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

One-machine usage:
    python sweeper.py scan                 # find funds
    python sweeper.py sweep <new_address>  # scan whole seed, sign, print raw tx hex
    python sweeper.py sweep <new_address> --addr <old_address>   # sweep one known address
"""
import argparse
import ctypes
import gc
import getpass
import json
import resource
import sys
import time
import unicodedata
from dataclasses import dataclass, field

import requests
from bip_utils import (
    Bip39MnemonicValidator, Bip39SeedGenerator,
    Bip44, Bip49, Bip84, Bip44Coins, Bip49Coins, Bip84Coins, Bip44Changes,
    ElectrumV2MnemonicValidator, ElectrumV2MnemonicTypes, ElectrumV2SeedGenerator,
    ElectrumV2Standard, ElectrumV2Segwit,
    ElectrumV1MnemonicValidator, ElectrumV1SeedGenerator, ElectrumV1,
)
from bitcoinutils.setup import setup as btc_setup
from bitcoinutils.keys import PrivateKey, P2wpkhAddress, P2shAddress, P2pkhAddress
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_tx   # independent, spec-based signature verifier (same directory)  # noqa: E402

APIS = ["https://mempool.space/api", "https://blockstream.info/api"]
GAP_LIMIT = 20          # unused addresses in a row before we stop scanning a chain
DUST = 546              # sats
btc_setup("mainnet")

# Never let a crash write process memory (and the seed) to disk.
try:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
except Exception:
    pass


def wipe(buf):
    """Overwrite a bytearray in place with zeros."""
    if isinstance(buf, bytearray) and len(buf):
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


# ----------------------------------------------------------------------------- schemes

# scheme id -> (label, input kind, pubkey compressed?)
SCHEMES = {
    "bip44":  ("BIP44 legacy m/44'/0'/0'",  "p2pkh",       True),
    "bip49":  ("BIP49 segwit m/49'/0'/0'",  "p2sh-p2wpkh", True),
    "bip84":  ("BIP84 native m/84'/0'/0'",  "p2wpkh",      True),
    "el2std": ("Electrum v2 standard",      "p2pkh",       True),
    "el2sw":  ("Electrum v2 segwit",        "p2wpkh",      True),
    "el1":    ("Electrum v1 (pre-2014)",    "p2pkh",       False),   # uncompressed keys
}
BIP_CLASSES = {"bip44": (Bip44, Bip44Coins.BITCOIN),
               "bip49": (Bip49, Bip49Coins.BITCOIN),
               "bip84": (Bip84, Bip84Coins.BITCOIN)}
INPUT_VBYTES = {"p2pkh": 148, "p2pkh-uncompressed": 180, "p2sh-p2wpkh": 91, "p2wpkh": 68}


def path_str(scheme, chain, index):
    return f"{SCHEMES[scheme][0]}/{chain}/{index}"


def electrum_normalize(text):
    """Electrum's normalize_text(): NFKD, lowercase, strip accents, collapse whitespace."""
    text = unicodedata.normalize("NFKD", text).lower()
    text = "".join(c for c in text if not unicodedata.combining(c))
    return " ".join(text.split())


# ----------------------------------------------------------------------------- data

@dataclass
class Coin:
    txid: str
    vout: int
    value: int            # sats
    address: str
    kind: str             # p2pkh | p2sh-p2wpkh | p2wpkh
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


# ----------------------------------------------------------------------------- derivation

def _electrum_v2_type(mnemonic):
    for t in (ElectrumV2MnemonicTypes.STANDARD, ElectrumV2MnemonicTypes.SEGWIT):
        if ElectrumV2MnemonicValidator(mnemonic_type=t).IsValid(mnemonic):
            return t
    return None


def seed_schemes(mnemonic):
    """Which scheme ids could this mnemonic belong to?"""
    out = []
    if Bip39MnemonicValidator().IsValid(mnemonic):
        out += ["bip44", "bip49", "bip84"]
    t = _electrum_v2_type(mnemonic)
    if t == ElectrumV2MnemonicTypes.STANDARD:
        out.append("el2std")
    elif t == ElectrumV2MnemonicTypes.SEGWIT:
        out.append("el2sw")
    if ElectrumV1MnemonicValidator().IsValid(mnemonic):
        out.append("el1")
    return out


def _roots(mnemonic, passphrase, schemes, public_only):
    """Per-scheme root objects. For BIP schemes with public_only, the root is the
    account xpub — no private key is ever derived on the public-only path."""
    roots = {}
    bip = [s for s in schemes if s in BIP_CLASSES]
    if bip:
        seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
        for s in bip:
            cls, coin = BIP_CLASSES[s]
            acct = cls.FromSeed(seed, coin).Purpose().Coin().Account(0)
            if public_only:
                acct = cls.FromExtendedKey(acct.PublicKey().ToExtended(), coin)
            roots[s] = acct
        del seed
    if "el2std" in schemes or "el2sw" in schemes:
        seed = ElectrumV2SeedGenerator(mnemonic).Generate(electrum_normalize(passphrase))
        if "el2std" in schemes:
            roots["el2std"] = ElectrumV2Standard.FromSeed(seed)
        if "el2sw" in schemes:
            roots["el2sw"] = ElectrumV2Segwit.FromSeed(seed)
        del seed
    if "el1" in schemes:
        roots["el1"] = ElectrumV1.FromSeed(ElectrumV1SeedGenerator(mnemonic).Generate())
    return roots


def _derive(root, scheme, chain, index, public_only):
    """-> (address, priv bytearray or None)"""
    if scheme in BIP_CLASSES:
        k = root.Change(Bip44Changes.CHAIN_INT if chain else Bip44Changes.CHAIN_EXT).AddressIndex(index)
        addr = k.PublicKey().ToAddress()
        priv = None if public_only else bytearray(k.PrivateKey().Raw().ToBytes())
    else:
        addr = root.GetAddress(chain, index)
        priv = None if public_only else bytearray(root.GetPrivateKey(chain, index).Raw().ToBytes())
    return addr, priv


def wallet_chains(mnemonic, passphrase, public_only=False):
    """Yield (scheme, chain, generator) for every chain this seed could have used.
    Generator yields (address, priv|None, kind, path, compressed) forever."""
    schemes = seed_schemes(mnemonic)
    if not schemes:
        sys.exit("Seed phrase is not a valid BIP39 or Electrum mnemonic. Check spelling/word order.")
    roots = _roots(mnemonic, passphrase, schemes, public_only)
    for scheme in schemes:
        label, kind, compressed = SCHEMES[scheme]
        for chain in (0, 1):
            def gen(root=roots[scheme], scheme=scheme, chain=chain, kind=kind, compressed=compressed):
                i = 0
                while True:
                    addr, priv = _derive(root, scheme, chain, i, public_only)
                    yield addr, priv, kind, path_str(scheme, chain, i), compressed
                    i += 1
            yield scheme, chain, gen()


def list_addresses(mnemonic, passphrase, per_chain):
    """Public info only, derived from xpubs where possible (no private keys created)."""
    out = []
    for scheme, chain, g in wallet_chains(mnemonic, passphrase, public_only=True):
        for i in range(per_chain):
            addr, _, kind, path, _ = next(g)
            out.append({"address": addr, "kind": kind, "scheme": scheme, "chain": chain,
                        "index": i, "path": path})
    return out


def keys_for(mnemonic, passphrase, wanted, max_index=2000):
    """wanted: {address: {scheme, chain, index} or None}.
    Returns {address: (kind, path, priv, compressed)}. Entries with a known
    scheme/chain/index are derived directly; the rest are searched up to max_index."""
    schemes = seed_schemes(mnemonic)
    if not schemes:
        sys.exit("Seed phrase is not a valid BIP39 or Electrum mnemonic. Check spelling/word order.")
    roots = _roots(mnemonic, passphrase, schemes, public_only=False)
    found = {}

    # 1. exact derivations
    for addr, loc in wanted.items():
        if loc and loc.get("scheme") in roots:
            s = loc["scheme"]
            got, priv = _derive(roots[s], s, int(loc["chain"]), int(loc["index"]), False)
            if got == addr:
                label, kind, compressed = SCHEMES[s]
                found[addr] = (kind, path_str(s, loc["chain"], loc["index"]), priv, compressed)
            else:
                wipe(priv)

    # 2. search for the rest
    remaining = set(wanted) - set(found)
    if remaining:
        for scheme in schemes:
            label, kind, compressed = SCHEMES[scheme]
            for chain in (0, 1):
                for i in range(max_index):
                    if not remaining:
                        break
                    addr, priv = _derive(roots[scheme], scheme, chain, i, False)
                    if addr in remaining:
                        found[addr] = (kind, path_str(scheme, chain, i), priv, compressed)
                        remaining.discard(addr)
                    else:
                        wipe(priv)
    if remaining:
        sys.exit("This seed does not control these addresses (wrong seed/passphrase, "
                 f"non-standard path, or index beyond {max_index} — try --max-index):\n  "
                 + "\n  ".join(sorted(remaining)))
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
    """Online, no secrets. Carries scheme/chain/index through so `sign` needn't search."""
    coins = []
    for i, e in enumerate(entries):
        addr = e["address"]
        time.sleep(0.15)
        for u in get_utxos(addr):
            c = {"txid": u["txid"], "vout": u["vout"], "value": u["value"], "address": addr,
                 "confirmed": bool(u.get("status", {}).get("confirmed", True))}
            for k in ("scheme", "chain", "index"):
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


def scan(mnemonic, passphrase):
    res = ScanResult()
    for scheme, chain, g in wallet_chains(mnemonic, passphrase):
        print(f"  scanning {SCHEMES[scheme][0]} chain {chain} ...", end="", flush=True)
        gap, found = 0, 0
        for addr, priv, kind, path, compressed in g:
            res.checked += 1
            time.sleep(0.15)   # be polite to the public API
            if not address_used(addr):
                wipe(priv)          # unused address: forget its key immediately
                gap += 1
                if gap >= GAP_LIMIT:
                    break
                continue
            gap = 0
            utxos = get_utxos(addr)
            if not utxos:
                wipe(priv)
            for u in utxos:
                res.coins.append(Coin(u["txid"], u["vout"], u["value"], addr, kind, priv, path, compressed))
                found += u["value"]
        print(f" {found/1e8:.8f} BTC")
    return res


# ----------------------------------------------------------------------------- transaction

def estimate_vbytes(coins):
    # overhead 11 + one output 43 + per-input sizes
    return 11 + 43 + sum(INPUT_VBYTES["p2pkh-uncompressed" if (c.kind == "p2pkh" and not c.compressed)
                                      else c.kind] for c in coins)


def build_and_sign(coins, dest, rate):
    check_fee_rate(rate)
    vb = estimate_vbytes(coins)
    fee = vb * rate
    total = sum(c.value for c in coins)
    send = total - fee
    if send <= DUST:
        sys.exit(f"After a {fee} sat fee nothing worth sending remains ({total} sats total).")

    ins = [TxInput(c.txid, c.vout) for c in coins]
    outs = [TxOutput(send, _dest_script(dest))]
    has_segwit = any(c.kind != "p2pkh" for c in coins)
    tx = Transaction(ins, outs, has_segwit=has_segwit)

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
    return tx, send, fee, real_vb


def _dest_script(addr):
    try:
        if addr.startswith("bc1q"):
            return P2wpkhAddress(addr).to_script_pub_key()
        if addr.startswith("3"):
            return P2shAddress(addr).to_script_pub_key()
        if addr.startswith("1"):
            return P2pkhAddress(addr).to_script_pub_key()
    except ValueError:
        sys.exit(f"Destination address {addr!r} is malformed (bad checksum or typo). Aborting.")
    sys.exit("Destination must be a mainnet 1..., 3..., or bc1q... address (taproot bc1p not supported).")


# ----------------------------------------------------------------------------- cli

def read_secret():
    print("Seed phrase input is hidden. Paste/type the words separated by spaces.")
    m = " ".join(getpass.getpass("Seed phrase: ").strip().lower().split())
    p = getpass.getpass("BIP39 passphrase (leave empty if you never set one): ")
    return m, p


def confirm_destination(addr):
    _dest_script(addr)  # validate before asking for anything secret
    if input("Confirm destination address again (type it): ").strip() != addr:
        sys.exit("Addresses do not match. Aborting.")


def _print_result(tx, coins, dest, send, fee, vb, rate):
    total = sum(c.value for c in coins)
    print("\n=== SWEEP SUMMARY ===")
    print(f"  inputs : {len(coins)}  ({total/1e8:.8f} BTC)")
    print(f"  to     : {dest}")
    print(f"  amount : {send/1e8:.8f} BTC")
    print(f"  fee    : {fee} sats  ({rate} sat/vB, ~{vb} vB)")
    print(f"  txid   : {tx.get_txid()}")
    print("\nRaw signed transaction hex (NOT broadcast — this tool never submits):")
    print(tx.serialize())
    print("\nWhen ready, paste it at https://mempool.space/tx/push (or any node/explorer).")
    print(f"Then track it: https://mempool.space/tx/{tx.get_txid()}")


def cmd_addresses(a):
    mnemonic, passphrase = read_secret()
    addrs = list_addresses(mnemonic, passphrase, a.per_chain)
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
    wanted = {}
    for u in utxos:
        loc = {k: u[k] for k in ("scheme", "chain", "index") if k in u}
        wanted[u["address"]] = loc if len(loc) == 3 else wanted.get(u["address"])
    mnemonic, passphrase = read_secret()
    keys = keys_for(mnemonic, passphrase, wanted, a.max_index)
    del mnemonic, passphrase
    gc.collect()
    coins = coins_from_utxos(utxos, keys)
    del keys
    try:
        tx, send, fee, vb = build_and_sign(coins, a.address, rate)
        _print_result(tx, coins, a.address, send, fee, vb, rate)
        del tx
    finally:
        for c in coins:
            wipe(c.priv)
        del coins
        gc.collect()


def cmd_scan_or_sweep(a):
    if a.cmd == "sweep":
        confirm_destination(a.address)
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
            keys = keys_for(mnemonic, passphrase, {u["address"]: None for u in utxos}, a.max_index)
            del mnemonic, passphrase
            gc.collect()
            res = ScanResult(coins=coins_from_utxos(utxos, keys), checked=len(entries))
            del keys
        else:
            mnemonic, passphrase = read_secret()
            print("\nScanning (read-only) ...")
            res = scan(mnemonic, passphrase)
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
        tx, send, fee, vb = build_and_sign(res.coins, a.address, rate)
        _print_result(tx, res.coins, a.address, send, fee, vb, rate)
        del tx
    finally:
        if res is not None:
            for c in res.coins:
                wipe(c.priv)
        gc.collect()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="find funds only (needs seed + network)")

    p = sub.add_parser("addresses", help="OFFLINE: seed -> public address list")
    p.add_argument("-o", "--out", default="addresses.json")
    p.add_argument("-n", "--per-chain", type=int, default=100, help="addresses per chain (default 100)")

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

    p = sub.add_parser("sweep", help="build and sign a sweep; prints raw hex, never broadcasts")
    p.add_argument("address", help="your NEW wallet's receive address")
    p.add_argument("--fee-rate", type=int, help="sat/vB (default: current half-hour rate)")
    p.add_argument("--addr", nargs="+", metavar="OLD_ADDRESS",
                   help="sweep only these known address(es) instead of scanning the whole seed")
    p.add_argument("--max-index", type=int, default=2000, help="search depth for --addr (default 2000)")

    a = ap.parse_args()
    {"addresses": cmd_addresses, "fetch": cmd_fetch, "sign": cmd_sign,
     "scan": cmd_scan_or_sweep, "sweep": cmd_scan_or_sweep}[a.cmd](a)


if __name__ == "__main__":
    main()
