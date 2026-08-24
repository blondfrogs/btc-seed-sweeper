#!/usr/bin/env python3
"""
sweeper.py — recover BTC from an old seed phrase and sweep it to a new address.

Everything sensitive (seed -> keys -> signing) happens locally in this process.
The only network calls are read-only balance/UTXO/fee lookups. This tool
NEVER broadcasts. It prints the raw signed transaction hex; you submit it
yourself (e.g. https://mempool.space/tx/push) when you are ready.

Air-gapped usage (recommended — the seed never touches an online machine):
    OFFLINE  python sweeper.py addresses               # seed -> addresses.json (public only)
    ONLINE   python sweeper.py fetch addresses.json    # -> utxos.json  (no seed needed)
             python sweeper.py fetch --addr 1abc... bc1q...   # or just type addresses
    OFFLINE  python sweeper.py sign utxos.json <new_address>  # seed + utxos -> raw tx hex

Test first (recommended): add --test to `sign` or `sweep` to send only 0.0001 BTC and
return the change to the old address; once it confirms, re-run fetch and do the real sweep.

One-machine usage:
    python sweeper.py scan                 # find funds
    python sweeper.py sweep <new_address>  # scan whole seed, sign, print raw tx hex
    python sweeper.py sweep <new_address> --addr <old_address>   # sweep one known address

Unusual wallet?  --path "m/0'/7'" --kind p2pkh   adds a custom derivation base path.
Only have private key(s)?  Paste WIF key(s) (5..., K..., L...) at the seed prompt instead.
"""
import argparse
import ctypes
import gc
import getpass
import json
import os
import re
import sys
import time
import unicodedata
from dataclasses import dataclass, field

import requests
from bip_utils import (
    Bip39MnemonicValidator, Bip39SeedGenerator, Bip32Slip10Secp256k1,
    P2PKHAddrEncoder, P2SHAddrEncoder, P2WPKHAddrEncoder, P2TRAddrEncoder, CoinsConf,
    ElectrumV2MnemonicValidator, ElectrumV2MnemonicTypes, ElectrumV2SeedGenerator,
    ElectrumV2Standard, ElectrumV2Segwit,
    ElectrumV1MnemonicValidator, ElectrumV1SeedGenerator, ElectrumV1,
)
from bitcoinutils.setup import setup as btc_setup
from bitcoinutils.keys import PrivateKey, P2wpkhAddress, P2shAddress, P2pkhAddress, P2trAddress
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_tx   # independent, spec-based signature verifier (same directory)  # noqa: E402

APIS = ["https://mempool.space/api", "https://blockstream.info/api"]
GAP_LIMIT = 20          # unused addresses in a row before we stop scanning a chain
MAX_ACCOUNTS = 10       # account discovery stops at the first unused account, or here
DUST = 546              # sats
btc_setup("mainnet")

# Never let a crash write process memory (and the seed) to disk (Unix only).
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
except Exception:
    pass


def wipe(buf):
    """Overwrite a bytearray in place with zeros."""
    if isinstance(buf, bytearray) and len(buf):
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


# ----------------------------------------------------------------------------- schemes

KINDS = ("p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr")

# Built-in derivation schemes. `base` is the path to the account node; "{a}" is the
# account number. Address chain (0 receive / 1 change) and index are appended.
# Electrum schemes have no BIP32 base path; they use bip_utils' Electrum classes.
SCHEMES = {
    "bip44":  dict(label="BIP44 legacy m/44'/0'/{a}'",     kind="p2pkh",       base="m/44'/0'/{a}'",
                   wallets="Coinomi, Mycelium, Exodus, Jaxx, Ledger/Trezor legacy, blockchain.com, Copay"),
    "bip49":  dict(label="BIP49 segwit m/49'/0'/{a}'",     kind="p2sh-p2wpkh", base="m/49'/0'/{a}'",
                   wallets="Coinomi, Mycelium, Ledger/Trezor, Samourai"),
    "bip84":  dict(label="BIP84 native m/84'/0'/{a}'",     kind="p2wpkh",      base="m/84'/0'/{a}'",
                   wallets="Coinomi, BlueWallet, Wasabi, Sparrow, Ledger/Trezor, Bitcoin Core"),
    "bip86":  dict(label="BIP86 taproot m/86'/0'/{a}'",    kind="p2tr",        base="m/86'/0'/{a}'",
                   wallets="Bitcoin Core, Sparrow, Ledger/Trezor (2021+)"),
    "bip32h": dict(label="BIP32 m/{a}'",                   kind="p2pkh",       base="m/{a}'",
                   wallets="MultiBit HD, Bread/BRD (legacy), Hive, Bitcoin Core pre-0.13 style"),
    "el2std": dict(label="Electrum v2 standard",           kind="p2pkh",       base=None),
    "el2sw":  dict(label="Electrum v2 segwit",             kind="p2wpkh",      base=None),
    "el1":    dict(label="Electrum v1 (pre-2014)",         kind="p2pkh",       base=None, uncompressed=True),
}
KIND_BY_PURPOSE = {"44": "p2pkh", "49": "p2sh-p2wpkh", "84": "p2wpkh", "86": "p2tr"}
INPUT_VBYTES = {"p2pkh": 148, "p2pkh-uncompressed": 180, "p2sh-p2wpkh": 91, "p2wpkh": 68, "p2tr": 58}
_P2PKH_VER = CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver")
_P2SH_VER = CoinsConf.BitcoinMainNet.ParamByKey("p2sh_net_ver")

_PATH_RE = re.compile(r"^m(/\d+'?)*$")


def custom_scheme_id(path, kind):
    path = path.strip().replace("h", "'").replace("H", "'")
    if not _PATH_RE.match(path):
        sys.exit(f"Bad derivation path {path!r}. Example: m/0'/7' or m/44'/0'/3'")
    if kind is None:
        purpose = path.split("/")[1].rstrip("'") if "/" in path else ""
        kind = KIND_BY_PURPOSE.get(purpose, "p2pkh")
    if kind not in KINDS:
        sys.exit(f"--kind must be one of {KINDS}")
    return f"custom:{path}:{kind}"


def scheme_info(scheme):
    """-> dict(label, kind, base, uncompressed, has_accounts) for builtin or custom ids."""
    if scheme.startswith("custom:"):
        _, path, kind = scheme.split(":", 2)
        return dict(label=f"custom {path}", kind=kind, base=path, uncompressed=False, has_accounts=False)
    if scheme.startswith("wif:"):
        kind = scheme[4:]
        return dict(label=f"WIF key ({kind})", kind=kind, base=None, uncompressed=None, has_accounts=False, wif=True)
    d = SCHEMES[scheme]
    return dict(label=d["label"], kind=d["kind"], base=d["base"],
                uncompressed=d.get("uncompressed", False), has_accounts=d["base"] is not None)


def path_str(scheme, account, chain, index):
    info = scheme_info(scheme)
    if info.get("wif"):
        return f"WIF key #{index + 1} ({info['kind']})"
    return f"{info['label'].replace('{a}', str(account))}/{chain}/{index}"


def electrum_normalize(text):
    """Electrum's normalize_text(): NFKD, lowercase, strip accents, collapse whitespace."""
    text = unicodedata.normalize("NFKD", text).lower()
    text = "".join(c for c in text if not unicodedata.combining(c))
    return " ".join(text.split())


_WIF_RE = re.compile(r"^(5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})$")
WIF_KINDS = ("p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr")


def looks_like_wif_list(text):
    toks = text.replace(",", " ").split()
    return bool(toks) and all(_WIF_RE.match(t) for t in toks)


def parse_wifs(text):
    """-> [(priv bytearray, compressed bool)]; exits on a bad key."""
    out = []
    for t in text.replace(",", " ").split():
        try:
            pk = PrivateKey(wif=t)
        except Exception:
            sys.exit(f"Invalid private key (bad WIF checksum?): {t[:6]}…")
        out.append((bytearray(pk.to_bytes()), pk.is_compressed() if hasattr(pk, "is_compressed") else t[0] in "KL"))
        del pk
    return out


# ----------------------------------------------------------------------------- data

@dataclass
class Coin:
    txid: str
    vout: int
    value: int            # sats
    address: str
    kind: str             # p2pkh | p2sh-p2wpkh | p2wpkh | p2tr
    priv: bytearray       # raw 32-byte private key; zeroed after signing
    path: str
    compressed: bool = True


@dataclass
class ScanResult:
    coins: list = field(default_factory=list)
    checked: int = 0

    @property
    def total(self):
        return sum(c.value for c in self.coins)


# ----------------------------------------------------------------------------- network (read-only)

def _get(path):
    """GET with retry/backoff, rotating between equivalent public Esplora APIs."""
    delay = 2
    for attempt in range(8):
        base = APIS[attempt % len(APIS)]
        try:
            r = requests.get(f"{base}{path}", timeout=30)
            if r.status_code == 429 or r.status_code >= 500:
                raise requests.HTTPError(f"{r.status_code} from {base}")
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError):
            if attempt == 7:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 30)


def get_utxos(address):
    return _get(f"/address/{address}/utxo")


def address_used(address):
    d = _get(f"/address/{address}")
    return (d["chain_stats"]["tx_count"] + d["mempool_stats"]["tx_count"]) > 0


def fee_rate():
    """Current half-hour fee rate in sat/vB, or None if it can't be fetched."""
    try:
        rate = int(_get("/v1/fees/recommended")["halfHourFee"])
        return rate if rate > 0 else None
    except Exception:
        return None


def check_fee_rate(rate):
    if not isinstance(rate, int) or isinstance(rate, bool) or rate <= 0:
        sys.exit(f"Fee rate must be a positive whole number of sat/vB (got {rate!r}). "
                 "Pass --fee-rate, e.g. --fee-rate 10.")
    return rate


def parse_amount(text):
    """'0.0001' (BTC) -> sats, exactly."""
    from decimal import Decimal, InvalidOperation
    try:
        sats = int(Decimal(text) * 100_000_000)
    except InvalidOperation:
        sys.exit(f"Bad amount {text!r}; give BTC like 0.0001")
    if sats <= DUST:
        sys.exit(f"Amount {text} BTC is below the dust limit ({DUST} sats).")
    return sats


TEST_AMOUNT_BTC = "0.0001"

# ----------------------------------------------------------------------------- derivation

def _electrum_v2_type(mnemonic):
    for t in (ElectrumV2MnemonicTypes.STANDARD, ElectrumV2MnemonicTypes.SEGWIT):
        if ElectrumV2MnemonicValidator(mnemonic_type=t).IsValid(mnemonic):
            return t
    return None


def seed_schemes(mnemonic, custom=()):
    """Which scheme ids could this secret (mnemonic or WIF list) belong to?"""
    if looks_like_wif_list(mnemonic):
        return ["wif:" + k for k in WIF_KINDS]
    out = []
    if Bip39MnemonicValidator().IsValid(mnemonic):
        out += ["bip44", "bip49", "bip84", "bip86", "bip32h"] + list(custom)
    t = _electrum_v2_type(mnemonic)
    if t == ElectrumV2MnemonicTypes.STANDARD:
        out.append("el2std")
    elif t == ElectrumV2MnemonicTypes.SEGWIT:
        out.append("el2sw")
    if ElectrumV1MnemonicValidator().IsValid(mnemonic):
        out.append("el1")
    if not out:
        sys.exit("Not a valid BIP39 / Electrum seed phrase or WIF private key. Check spelling/word order.")
    return out


class Roots:
    """Lazily derives per-(scheme, account) nodes. Holds the master key for the BIP39
    seed while alive; call .close() to drop it."""

    def __init__(self, mnemonic, passphrase, schemes, public_only=False):
        self.public_only = public_only
        self.master = None
        self.nodes = {}
        self.wifs = parse_wifs(mnemonic) if any(s.startswith("wif:") for s in schemes) else []
        if any(scheme_info(s)["base"] is not None for s in schemes):
            seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
            self.master = Bip32Slip10Secp256k1.FromSeed(seed)
            del seed
        if "el2std" in schemes or "el2sw" in schemes:
            seed = ElectrumV2SeedGenerator(mnemonic).Generate(electrum_normalize(passphrase))
            if "el2std" in schemes:
                self.nodes[("el2std", 0)] = ElectrumV2Standard.FromSeed(seed)
            if "el2sw" in schemes:
                self.nodes[("el2sw", 0)] = ElectrumV2Segwit.FromSeed(seed)
            del seed
        if "el1" in schemes:
            self.nodes[("el1", 0)] = ElectrumV1.FromSeed(ElectrumV1SeedGenerator(mnemonic).Generate())

    def node(self, scheme, account=0):
        info = scheme_info(scheme)
        if info["base"] is None:
            account = 0
        key = (scheme, account)
        if key not in self.nodes:
            if self.master is None:
                raise KeyError(scheme)
            n = self.master.DerivePath(info["base"].replace("{a}", str(account)))
            if self.public_only:
                n.ConvertToPublic()      # from here on, no private keys exist for this account
            self.nodes[key] = n
        return self.nodes[key]

    def size(self, scheme):
        """Number of addresses a scheme has per chain, or None if unbounded."""
        return len(self.wifs) if scheme.startswith("wif:") else None

    def compressed(self, scheme, index):
        if scheme.startswith("wif:"):
            return self.wifs[index][1]
        return not scheme_info(scheme)["uncompressed"]

    def derive(self, scheme, account, chain, index):
        """-> (address, priv bytearray or None). (None, None) past the end of a finite scheme
        or for an address type this key can't have (uncompressed keys are legacy-only)."""
        info = scheme_info(scheme)
        if info.get("wif"):
            if chain != 0 or index >= len(self.wifs):
                return None, None
            raw, compressed = self.wifs[index]
            if info["kind"] != "p2pkh" and not compressed:
                return None, None
            pk = PrivateKey(b=bytes(raw))
            pub = pk.get_public_key()
            del pk
            if info["kind"] == "p2pkh":
                addr = pub.get_address(compressed=compressed).to_string()
            elif info["kind"] == "p2sh-p2wpkh":
                addr = P2shAddress.from_script(pub.get_segwit_address().to_script_pub_key()).to_string()
            elif info["kind"] == "p2wpkh":
                addr = pub.get_segwit_address().to_string()
            else:
                addr = pub.get_taproot_address().to_string()
            return addr, (None if self.public_only else bytearray(raw))
        node = self.node(scheme, account)
        if info["base"] is None:                       # Electrum
            addr = node.GetAddress(chain, index)
            priv = None if self.public_only else bytearray(node.GetPrivateKey(chain, index).Raw().ToBytes())
            return addr, priv
        k = node.ChildKey(chain).ChildKey(index)
        pub = k.PublicKey().KeyObject()
        kind = info["kind"]
        if kind == "p2pkh":
            addr = P2PKHAddrEncoder.EncodeKey(pub, net_ver=_P2PKH_VER)
        elif kind == "p2sh-p2wpkh":
            addr = P2SHAddrEncoder.EncodeKey(pub, net_ver=_P2SH_VER)
        elif kind == "p2wpkh":
            addr = P2WPKHAddrEncoder.EncodeKey(pub, hrp="bc")
        else:
            addr = P2TRAddrEncoder.EncodeKey(pub, hrp="bc")
        priv = None if self.public_only else bytearray(k.PrivateKey().Raw().ToBytes())
        return addr, priv

    def close(self):
        self.master = None
        self.nodes.clear()
        for raw, _ in self.wifs:
            wipe(raw)
        self.wifs = []
        gc.collect()


def make_coin(u, addr, scheme, account, chain, index, priv, compressed):
    info = scheme_info(scheme)
    return Coin(u["txid"], u["vout"], u["value"], addr, info["kind"], priv,
                path_str(scheme, account, chain, index), compressed)


def list_addresses(mnemonic, passphrase, per_chain, accounts=1, custom=()):
    """Public info only, derived from account xpubs (no private keys created)."""
    schemes = seed_schemes(mnemonic, custom)
    roots = Roots(mnemonic, passphrase, schemes, public_only=True)
    out = []
    for scheme in schemes:
        n_acc = accounts if scheme_info(scheme)["has_accounts"] else 1
        for account in range(n_acc):
            for chain in (0, 1):
                n = per_chain if roots.size(scheme) is None else roots.size(scheme)
                for i in range(n):
                    addr, _ = roots.derive(scheme, account, chain, i)
                    if addr is None:
                        continue
                    out.append({"address": addr, "kind": scheme_info(scheme)["kind"], "scheme": scheme,
                                "account": account, "chain": chain, "index": i,
                                "path": path_str(scheme, account, chain, i)})
    roots.close()
    return out


def keys_for(mnemonic, passphrase, wanted, max_index=2000, accounts=1, custom=()):
    """wanted: {address: {scheme, account, chain, index} or None}.
    Returns {address: (kind, path, priv, compressed)}. Entries with a known location are
    derived directly; the rest are searched (all schemes, `accounts` accounts, max_index)."""
    schemes = seed_schemes(mnemonic, custom)
    roots = Roots(mnemonic, passphrase, schemes)
    found = {}

    def record(addr, scheme, account, chain, index, priv):
        info = scheme_info(scheme)
        found[addr] = (info["kind"], path_str(scheme, account, chain, index), priv, roots.compressed(scheme, index))

    # 1. exact derivations
    for addr, loc in wanted.items():
        if not loc:
            continue
        s = loc.get("scheme")
        if s not in schemes and not (s or "").startswith("custom:"):
            continue
        try:
            acc, ch, ix = int(loc.get("account", 0)), int(loc["chain"]), int(loc["index"])
            got, priv = roots.derive(s, acc, ch, ix)
        except Exception:
            continue
        if got is None:
            continue
        if got == addr:
            record(addr, s, acc, ch, ix, priv)
        else:
            wipe(priv)

    # 2. search for the rest
    remaining = set(wanted) - set(found)
    if remaining:
        for scheme in schemes:
            n_acc = accounts if scheme_info(scheme)["has_accounts"] else 1
            for account in range(n_acc):
                for chain in (0, 1):
                    for i in range(max_index if roots.size(scheme) is None else roots.size(scheme)):
                        if not remaining:
                            break
                        addr, priv = roots.derive(scheme, account, chain, i)
                        if addr is None:
                            continue
                        if addr in remaining:
                            record(addr, scheme, account, chain, i, priv)
                            remaining.discard(addr)
                        else:
                            wipe(priv)
    roots.close()
    if remaining:
        sys.exit("This seed does not control these addresses (wrong seed/passphrase, "
                 f"non-standard path, account beyond {accounts - 1}, or index beyond {max_index}"
                 " — see --path, --accounts, --max-index):\n  " + "\n  ".join(sorted(remaining)))
    return found


def normalize_addr_entries(entries):
    """Accept dicts or bare address strings; dedupe by address (keep richest entry)."""
    out = {}
    for x in entries:
        e = x if isinstance(x, dict) else {"address": x}
        if e["address"] not in out or len(e) > len(out[e["address"]]):
            out[e["address"]] = e
    return list(out.values())


def fetch_utxos(entries):
    """Online, no secrets. Carries scheme/account/chain/index through so `sign` needn't search."""
    coins = []
    for i, e in enumerate(entries):
        addr = e["address"]
        time.sleep(0.15)
        for u in get_utxos(addr):
            c = {"txid": u["txid"], "vout": u["vout"], "value": u["value"], "address": addr,
                 "confirmed": bool(u.get("status", {}).get("confirmed", True))}
            for k in ("scheme", "account", "chain", "index"):
                if k in e:
                    c[k] = e[k]
            coins.append(c)
        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{len(entries)} checked ...")
    return coins


def dedupe_utxos(utxos):
    """Drop duplicate (txid, vout) entries — a duplicate input makes the tx invalid."""
    seen, out = set(), []
    for u in utxos:
        key = (u["txid"], u["vout"])
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def coins_from_utxos(utxos, keys):
    return [Coin(u["txid"], u["vout"], u["value"], u["address"],
                 keys[u["address"]][0], keys[u["address"]][2], keys[u["address"]][1],
                 keys[u["address"]][3]) for u in utxos]


def scan(mnemonic, passphrase, max_accounts=MAX_ACCOUNTS, custom=()):
    """Walk every scheme with gap-limit address discovery and BIP44-style account
    discovery (stop at the first account with no used address)."""
    res = ScanResult()
    schemes = seed_schemes(mnemonic, custom)
    roots = Roots(mnemonic, passphrase, schemes)
    for scheme in schemes:
        info = scheme_info(scheme)
        n_acc = max_accounts if info["has_accounts"] else 1
        for account in range(n_acc):
            account_used = False
            for chain in (0, 1):
                label = info["label"].replace("{a}", str(account))
                print(f"  scanning {label} chain {chain} ...", end="", flush=True)
                gap, found, i = 0, 0, 0
                while gap < GAP_LIMIT:
                    addr, priv = roots.derive(scheme, account, chain, i)
                    if addr is None:
                        if roots.size(scheme) is not None and i >= roots.size(scheme):
                            break           # finite scheme (WIF keys): no more addresses
                        i += 1
                        continue
                    res.checked += 1
                    time.sleep(0.15)   # be polite to the public API
                    if not address_used(addr):
                        wipe(priv)      # unused address: forget its key immediately
                        gap += 1
                    else:
                        gap, account_used = 0, True
                        utxos = get_utxos(addr)
                        if not utxos:
                            wipe(priv)
                        for u in utxos:
                            res.coins.append(make_coin(u, addr, scheme, account, chain, i, priv,
                                                       roots.compressed(scheme, i)))
                            found += u["value"]
                    i += 1
                print(f" {found/1e8:.8f} BTC")
            if not account_used:
                break               # BIP44 account discovery: stop at first unused account
    roots.close()
    return res


# ----------------------------------------------------------------------------- transaction

def estimate_vbytes(coins, n_outputs=1):
    # overhead 11 + 43 per output (conservative) + per-input sizes
    return 11 + 43 * n_outputs + sum(INPUT_VBYTES["p2pkh-uncompressed" if (c.kind == "p2pkh" and not c.compressed)
                                                  else c.kind] for c in coins)


def select_inputs(coins, amount, rate):
    """Fewest inputs (largest first) covering amount + fee for a 2-output tx."""
    chosen = []
    for c in sorted(coins, key=lambda c: c.value, reverse=True):
        chosen.append(c)
        if sum(x.value for x in chosen) >= amount + estimate_vbytes(chosen, 2) * rate:
            return chosen
    total = sum(c.value for c in coins)
    sys.exit(f"Not enough funds: {total} sats available, need {amount} sats plus fee.")


def build_and_sign(coins, dest, rate, amount=None):
    """Sweep everything to dest, or (amount given) send `amount` sats and return the
    change to the address the first selected coin came from. Returns
    (tx, send, fee, vbytes, change, change_addr, coins_used)."""
    check_fee_rate(rate)
    change, change_addr = 0, None
    if amount is None:
        vb = estimate_vbytes(coins)
        fee = vb * rate
        total = sum(c.value for c in coins)
        send = total - fee
        if send <= DUST:
            sys.exit(f"After a {fee} sat fee nothing worth sending remains ({total} sats total).")
        outs = [TxOutput(send, _dest_script(dest))]
    else:
        coins = select_inputs(coins, amount, rate)
        total = sum(c.value for c in coins)
        send = amount
        vb = estimate_vbytes(coins, 2)
        fee = vb * rate
        change = total - send - fee
        change_addr = coins[0].address
        if change <= DUST:          # not worth a change output; give it to the miner
            fee += max(change, 0)
            change, change_addr = 0, None
            vb = estimate_vbytes(coins, 1)
        outs = [TxOutput(send, _dest_script(dest))]
        if change:
            outs.append(TxOutput(change, _dest_script(change_addr)))

    ins = [TxInput(c.txid, c.vout) for c in coins]
    has_segwit = any(c.kind != "p2pkh" for c in coins)
    tx = Transaction(ins, outs, has_segwit=has_segwit)
    # BIP341 (taproot) sighash commits to every input's scriptPubKey and amount.
    all_spks = [_dest_script(c.address) for c in coins]
    all_amounts = [c.value for c in coins]

    # Pass 1: compute every signature while ALL scriptSigs are still empty. The legacy
    # sighash must see other inputs' scriptSigs as empty, and the library does not clear
    # them for us, so nothing may be populated until every signature exists.
    sigs = []
    for i, c in enumerate(coins):
        pk = PrivateKey(b=bytes(c.priv))
        pub = pk.get_public_key()
        if c.kind == "p2pkh":
            spk = pub.get_address(compressed=c.compressed).to_script_pub_key()
            sigs.append((pk.sign_input(tx, i, spk), pub.to_hex(compressed=c.compressed), None))
        elif c.kind == "p2tr":
            sig = pk.sign_taproot_input(tx, i, all_spks, all_amounts)   # key path, tweaked
            sigs.append((sig, None, None))
        else:
            # BIP143: the script code for P2WPKH is the P2PKH-form script of the key hash,
            # NOT the P2WPKH scriptPubKey itself.
            script_code = pub.get_address().to_script_pub_key()
            redeem_hex = pub.get_segwit_address().to_script_pub_key().to_hex()
            sigs.append((pk.sign_segwit_input(tx, i, script_code, c.value), pub.to_hex(), redeem_hex))
        del pk
    # Pass 2: populate scriptSigs / witnesses.
    for i, (c, (sig, pub_hex, redeem_hex)) in enumerate(zip(coins, sigs)):
        if c.kind == "p2pkh":
            ins[i].script_sig = Script([sig, pub_hex])
            if has_segwit:
                tx.witnesses.append(TxWitnessInput([]))
        elif c.kind == "p2tr":
            tx.witnesses.append(TxWitnessInput([sig]))
        else:
            if c.kind == "p2sh-p2wpkh":
                ins[i].script_sig = Script([redeem_hex])
            tx.witnesses.append(TxWitnessInput([sig, pub_hex]))
    # Several coins may share one key buffer (same address): wipe once all are signed.
    for c in coins:
        wipe(c.priv)
    gc.collect()

    # Independent self-check: re-verify every signature with verify_tx (separate code,
    # spec-based sighash, libsecp256k1). Refuse to hand out hex that does not verify.
    prevouts = [{"script_pubkey": verify_tx.spk_for_address(c.address).hex(), "value": c.value}
                for c in coins]
    try:
        verify_tx.verify(tx.serialize(), prevouts)
    except Exception as e:
        sys.exit(f"INTERNAL ERROR: signed transaction failed independent verification ({e}). "
                 "Nothing was output. Please report this.")
    real_vb = verify_tx.vbytes(tx.serialize())
    if real_vb > vb:
        sys.exit(f"INTERNAL ERROR: fee estimate ({vb} vB) below actual size ({real_vb} vB).")
    return tx, send, fee, real_vb, change, change_addr, coins


def _dest_script(addr):
    try:
        if addr.startswith("bc1q"):
            return P2wpkhAddress(addr).to_script_pub_key()
        if addr.startswith("bc1p"):
            return P2trAddress(addr).to_script_pub_key()
        if addr.startswith("3"):
            return P2shAddress(addr).to_script_pub_key()
        if addr.startswith("1"):
            return P2pkhAddress(addr).to_script_pub_key()
    except ValueError:
        sys.exit(f"Address {addr!r} is malformed (bad checksum or typo). Aborting.")
    sys.exit("Address must be a mainnet 1..., 3..., bc1q... or bc1p... address.")


# ----------------------------------------------------------------------------- cli

def read_secret():
    print("Input is hidden. Paste/type your seed phrase (words separated by spaces),")
    print("or one or more private keys in WIF format (5..., K..., L...) separated by spaces.")
    raw = getpass.getpass("Seed phrase or private key(s): ").strip()
    if looks_like_wif_list(raw):
        return " ".join(raw.replace(",", " ").split()), ""      # WIF is case-sensitive; no passphrase
    m = " ".join(raw.lower().split())
    p = getpass.getpass("BIP39 passphrase (leave empty if you never set one): ")
    return m, p


def _amount_from_args(a):
    if getattr(a, "test", False) and a.amount:
        sys.exit("Use either --test or --amount, not both.")
    if getattr(a, "test", False):
        return parse_amount(TEST_AMOUNT_BTC)
    return parse_amount(a.amount) if a.amount else None


def _custom_from_args(a):
    paths = getattr(a, "path", None) or []
    return [custom_scheme_id(p, getattr(a, "kind", None)) for p in paths]


def confirm_destination(addr):
    _dest_script(addr)  # validate before asking for anything secret
    if input("Confirm destination address again (type it): ").strip() != addr:
        sys.exit("Addresses do not match. Aborting.")


def _print_result(tx, coins, dest, send, fee, vb, rate, change=0, change_addr=None, untouched=()):
    total = sum(c.value for c in coins)
    print("\n=== " + ("TEST / PARTIAL SEND SUMMARY" if change_addr or untouched else "SWEEP SUMMARY") + " ===")
    print(f"  inputs : {len(coins)}  ({total/1e8:.8f} BTC)")
    print(f"  to     : {dest}")
    print(f"  amount : {send/1e8:.8f} BTC")
    if change_addr:
        print(f"  change : {change/1e8:.8f} BTC  back to {change_addr} (your old address)")
    print(f"  fee    : {fee} sats  ({rate} sat/vB, ~{vb} vB)")
    print(f"  txid   : {tx.get_txid()}")
    if untouched:
        left = sum(c.value for c in untouched)
        print(f"  untouched: {len(untouched)} other coin(s), {left/1e8:.8f} BTC, still on the old addresses")
    if change_addr or untouched:
        print("\n  After this confirms, re-run `fetch` (the coins have changed) before the real sweep.")
    print("\nRaw signed transaction hex (NOT broadcast — this tool never submits):")
    print(tx.serialize())
    print("\nWhen ready, paste it at https://mempool.space/tx/push (or any node/explorer).")
    print(f"Then track it: https://mempool.space/tx/{tx.get_txid()}")


def cmd_addresses(a):
    custom = _custom_from_args(a)
    mnemonic, passphrase = read_secret()
    addrs = list_addresses(mnemonic, passphrase, a.per_chain, a.accounts, custom)
    del mnemonic, passphrase
    gc.collect()
    with open(a.out, "w") as fh:
        json.dump(addrs, fh, indent=1)
    print(f"Wrote {len(addrs)} public addresses to {a.out} (no keys). Take this file online.")


def cmd_fetch(a):
    entries = list(a.addr or [])
    if a.addresses_file:
        with open(a.addresses_file) as fh:
            entries += json.load(fh)
    entries = normalize_addr_entries(entries)
    if not entries:
        sys.exit("Give addresses.json or --addr ...")
    print(f"Fetching UTXOs for {len(entries)} addresses (read-only) ...")
    coins = dedupe_utxos(fetch_utxos(entries))
    rate = fee_rate()
    with open(a.out, "w") as fh:
        json.dump({"fee_rate": rate, "utxos": coins}, fh, indent=1)
    total = sum(c["value"] for c in coins)
    print(f"Found {len(coins)} coin(s), total {total/1e8:.8f} BTC.")
    for c in coins:
        print(f"  {c['value']/1e8:.8f}  {c['address']}" + ("" if c["confirmed"] else "  (UNCONFIRMED)"))
    if any(not c["confirmed"] for c in coins):
        print("Note: unconfirmed coins are included; wait for confirmation if you want to be safe.")
    if rate is None:
        print("WARNING: could not fetch the current fee rate. You must pass --fee-rate to `sign`.")
    else:
        print(f"Fee rate now {rate} sat/vB (saved for `sign`).")
    print(f"Wrote {a.out}. Take this file to the offline machine.")


def cmd_sign(a):
    confirm_destination(a.address)
    with open(a.utxos_file) as fh:
        data = json.load(fh)
    utxos = dedupe_utxos(data.get("utxos") or [])
    if not utxos:
        sys.exit("No UTXOs in file.")
    rate = check_fee_rate(a.fee_rate if a.fee_rate is not None else data.get("fee_rate"))
    amount = _amount_from_args(a)      # validate before asking for anything secret
    custom = _custom_from_args(a)
    wanted = {}
    for u in utxos:
        loc = {k: u[k] for k in ("scheme", "account", "chain", "index") if k in u}
        wanted[u["address"]] = loc if {"scheme", "chain", "index"} <= set(loc) else wanted.get(u["address"])
    mnemonic, passphrase = read_secret()
    keys = keys_for(mnemonic, passphrase, wanted, a.max_index, a.accounts, custom)
    del mnemonic, passphrase
    gc.collect()
    coins = coins_from_utxos(utxos, keys)
    del keys
    try:
        tx, send, fee, vb, change, change_addr, used = build_and_sign(coins, a.address, rate, amount)
        _print_result(tx, used, a.address, send, fee, vb, rate, change, change_addr,
                      untouched=[c for c in coins if c not in used])
        del tx
    finally:
        for c in coins:
            wipe(c.priv)
        del coins
        gc.collect()


def cmd_scan_or_sweep(a):
    amount = None
    custom = _custom_from_args(a)
    if a.cmd == "sweep":
        confirm_destination(a.address)
        amount = _amount_from_args(a)  # validate before asking for anything secret
    res = None
    try:
        if a.cmd == "sweep" and a.addr:
            # Known-address mode: look up coins first (no seed), then derive only those keys.
            entries = normalize_addr_entries(a.addr)
            print(f"Fetching UTXOs for {len(entries)} address(es) (read-only) ...")
            utxos = dedupe_utxos(fetch_utxos(entries))
            if not utxos:
                sys.exit("No coins found on the given address(es).")
            mnemonic, passphrase = read_secret()
            keys = keys_for(mnemonic, passphrase, {u["address"]: None for u in utxos},
                            a.max_index, a.accounts, custom)
            del mnemonic, passphrase
            gc.collect()
            res = ScanResult(coins=coins_from_utxos(utxos, keys), checked=len(entries))
            del keys
        else:
            mnemonic, passphrase = read_secret()
            print("\nScanning (read-only) ...")
            res = scan(mnemonic, passphrase, a.accounts, custom)
            del mnemonic, passphrase        # words no longer needed
            gc.collect()

        print(f"\nChecked {res.checked} addresses. Found {len(res.coins)} coin(s), total {res.total/1e8:.8f} BTC")
        for c in res.coins:
            print(f"  {c.value/1e8:.8f}  {c.address}  ({c.path})")
        if a.cmd == "scan" or not res.coins:
            return

        rate = a.fee_rate if a.fee_rate is not None else fee_rate()
        if rate is None:
            sys.exit("Could not fetch the current fee rate; re-run with --fee-rate N.")
        tx, send, fee, vb, change, change_addr, used = build_and_sign(res.coins, a.address, rate, amount)
        _print_result(tx, used, a.address, send, fee, vb, rate, change, change_addr,
                      untouched=[c for c in res.coins if c not in used])
        del tx
    finally:
        if res is not None:
            for c in res.coins:
                wipe(c.priv)
        gc.collect()


def _add_path_args(p):
    p.add_argument("--path", action="append", metavar="M/…",
                   help="extra custom derivation base path, e.g. \"m/0'/7'\" (repeatable)")
    p.add_argument("--kind", choices=KINDS, help="address type for --path (default: by purpose, else p2pkh)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="find funds only (needs seed + network)")
    p.add_argument("--accounts", type=int, default=MAX_ACCOUNTS,
                   help=f"max accounts to discover per scheme (default {MAX_ACCOUNTS}; stops at first unused)")
    _add_path_args(p)

    p = sub.add_parser("addresses", help="OFFLINE: seed -> public address list")
    p.add_argument("-o", "--out", default="addresses.json")
    p.add_argument("-n", "--per-chain", type=int, default=100, help="addresses per chain (default 100)")
    p.add_argument("--accounts", type=int, default=1, help="accounts per scheme to list (default 1 = account 0)")
    _add_path_args(p)

    p = sub.add_parser("fetch", help="ONLINE, no seed: addresses -> utxos.json")
    p.add_argument("addresses_file", nargs="?", help="addresses.json from the offline step")
    p.add_argument("--addr", nargs="+", help="or give addresses directly")
    p.add_argument("-o", "--out", default="utxos.json")

    p = sub.add_parser("sign", help="OFFLINE: seed + utxos.json -> raw tx hex")
    p.add_argument("utxos_file")
    p.add_argument("address", help="your NEW wallet's receive address")
    p.add_argument("--fee-rate", type=int, help="sat/vB (default: rate saved by fetch)")
    p.add_argument("--max-index", type=int, default=2000,
                   help="how far to search each chain for addresses without a saved path (default 2000)")
    p.add_argument("--accounts", type=int, default=1, help="accounts to search for unlocated addresses (default 1)")
    p.add_argument("--test", action="store_true",
                   help=f"TEST MODE: send only {TEST_AMOUNT_BTC} BTC, change goes back to the old address")
    p.add_argument("--amount", metavar="BTC", help="send only this much (e.g. 0.005) instead of everything")
    _add_path_args(p)

    p = sub.add_parser("sweep", help="build and sign a sweep; prints raw hex, never broadcasts")
    p.add_argument("address", help="your NEW wallet's receive address")
    p.add_argument("--fee-rate", type=int, help="sat/vB (default: current half-hour rate)")
    p.add_argument("--addr", nargs="+", metavar="OLD_ADDRESS",
                   help="sweep only these known address(es) instead of scanning the whole seed")
    p.add_argument("--max-index", type=int, default=2000, help="search depth for --addr (default 2000)")
    p.add_argument("--accounts", type=int, default=MAX_ACCOUNTS,
                   help=f"max accounts to discover / search (default {MAX_ACCOUNTS})")
    p.add_argument("--test", action="store_true",
                   help=f"TEST MODE: send only {TEST_AMOUNT_BTC} BTC, change goes back to the old address")
    p.add_argument("--amount", metavar="BTC", help="send only this much (e.g. 0.005) instead of everything")
    _add_path_args(p)

    a = ap.parse_args()
    {"addresses": cmd_addresses, "fetch": cmd_fetch, "sign": cmd_sign,
     "scan": cmd_scan_or_sweep, "sweep": cmd_scan_or_sweep}[a.cmd](a)


if __name__ == "__main__":
    main()
