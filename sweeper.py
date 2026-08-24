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
    python sweeper.py sweep <new_address>  # build + sign, print raw tx hex
"""
import argparse
import ctypes
import gc
import json
import getpass
import resource
import sys
import time
from dataclasses import dataclass, field

import requests
from bip_utils import (
    Bip39MnemonicValidator, Bip39SeedGenerator,
    Bip44, Bip49, Bip84, Bip44Coins, Bip49Coins, Bip84Coins, Bip44Changes,
    ElectrumV2MnemonicValidator, ElectrumV2SeedGenerator, ElectrumV2Standard, ElectrumV2Segwit,
    ElectrumV1MnemonicValidator, ElectrumV1SeedGenerator, ElectrumV1,
)
from bitcoinutils.setup import setup as btc_setup
from bitcoinutils.keys import PrivateKey, P2wpkhAddress, P2shAddress, P2pkhAddress
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script

APIS = ["https://mempool.space/api", "https://blockstream.info/api"]
API = APIS[0]
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

# ----------------------------------------------------------------------------- data

@dataclass
class Coin:
    txid: str
    vout: int
    value: int            # sats
    address: str
    kind: str             # p2pkh | p2sh-p2wpkh | p2wpkh
    priv: bytearray      # raw 32-byte private key; zeroed after signing
    path: str

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
        except (requests.RequestException, ValueError) as e:
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
    try:
        return requests.get(f"{API}/v1/fees/recommended", timeout=15).json()["halfHourFee"]
    except Exception:
        return 10

# ----------------------------------------------------------------------------- derivation

def wallet_candidates(mnemonic, passphrase):
    """Yield (label, chain_iterator) for every scheme the seed could have used."""
    if Bip39MnemonicValidator().IsValid(mnemonic):
        seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
        for label, cls, coin, kind in (
            ("BIP44 legacy  m/44'/0'/0'", Bip44, Bip44Coins.BITCOIN, "p2pkh"),
            ("BIP49 segwit  m/49'/0'/0'", Bip49, Bip49Coins.BITCOIN, "p2sh-p2wpkh"),
            ("BIP84 native  m/84'/0'/0'", Bip84, Bip84Coins.BITCOIN, "p2wpkh"),
        ):
            acct = cls.FromSeed(seed, coin).Purpose().Coin().Account(0)
            for change, cname in ((Bip44Changes.CHAIN_EXT, "0"), (Bip44Changes.CHAIN_INT, "1")):
                chain = acct.Change(change)
                def gen(chain=chain, label=label, cname=cname, kind=kind):
                    i = 0
                    while True:
                        k = chain.AddressIndex(i)
                        yield k.PublicKey().ToAddress(), bytearray(k.PrivateKey().Raw().ToBytes()), kind, f"{label}/{cname}/{i}"
                        i += 1
                yield f"{label} chain {cname}", gen()

    if ElectrumV2MnemonicValidator().IsValid(mnemonic):
        seed = ElectrumV2SeedGenerator(mnemonic).Generate(passphrase)
        for label, cls, kind in (("Electrum standard", ElectrumV2Standard, "p2pkh"),
                                 ("Electrum segwit", ElectrumV2Segwit, "p2wpkh")):
            try:
                w = cls.FromSeed(seed)
            except Exception:
                continue
            for cname in (0, 1):
                def gen(w=w, cname=cname, label=label, kind=kind):
                    i = 0
                    while True:
                        yield (w.GetAddress(cname, i), bytearray(w.GetPrivateKey(cname, i).Raw().ToBytes()),
                               kind, f"{label}/{cname}/{i}")
                        i += 1
                yield f"{label} chain {cname}", gen()

    if ElectrumV1MnemonicValidator().IsValid(mnemonic):
        w = ElectrumV1.FromSeed(ElectrumV1SeedGenerator(mnemonic).Generate())
        for cname in (0, 1):
            def gen(w=w, cname=cname):
                i = 0
                while True:
                    yield w.GetAddress(cname, i), bytearray(w.GetPrivateKey(cname, i).Raw().ToBytes()), "p2pkh", f"ElectrumV1/{cname}/{i}"
                    i += 1
            yield f"Electrum v1 (old) chain {cname}", gen()

def list_addresses(mnemonic, passphrase, per_chain):
    """Public info only: [{address, kind, path}] for the first per_chain of every chain."""
    out = []
    for label, chain in wallet_candidates(mnemonic, passphrase):
        for _ in range(per_chain):
            addr, priv, kind, path = next(chain)
            wipe(priv)
            out.append({"address": addr, "kind": kind, "path": path})
    return out

def dedupe_utxos(utxos):
    """Drop duplicate (txid, vout) entries — a duplicate input makes the tx invalid."""
    seen, out = set(), []
    for u in utxos:
        key = (u["txid"], u["vout"])
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out

def keys_for(mnemonic, passphrase, wanted):
    """Return {address: (kind, path, priv)} for the addresses in `wanted`, deriving
    only as far as needed. Any address the seed can't produce is reported."""
    wanted = set(wanted)
    found = {}
    limit = 2000
    schemes = list(wallet_candidates(mnemonic, passphrase))
    if not schemes:
        sys.exit("Seed phrase is not a valid BIP39 or Electrum mnemonic. Check spelling/word order.")
    for label, chain in schemes:
        for _ in range(limit):
            if not wanted - set(found):
                break
            addr, priv, kind, path = next(chain)
            if addr in wanted:
                found[addr] = (kind, path, priv)
            else:
                wipe(priv)
    missing = wanted - set(found)
    if missing:
        sys.exit("This seed does not control these addresses (wrong seed/passphrase, "
                 "or non-standard path):\n  " + "\n  ".join(sorted(missing)))
    return found

def fetch_utxos(addresses):
    """Online, no secrets: look up UTXOs for a list of {address, kind?, path?} dicts."""
    coins = []
    for i, a in enumerate(addresses):
        addr = a["address"] if isinstance(a, dict) else a
        time.sleep(0.15)
        for u in get_utxos(addr):
            coins.append({"txid": u["txid"], "vout": u["vout"], "value": u["value"], "address": addr,
                          "confirmed": bool(u.get("status", {}).get("confirmed", True))})
        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{len(addresses)} checked ...")
    return coins

def scan(mnemonic, passphrase):
    res = ScanResult()
    any_scheme = False
    for label, chain in wallet_candidates(mnemonic, passphrase):
        any_scheme = True
        print(f"  scanning {label} ...", end="", flush=True)
        gap, found = 0, 0
        for addr, priv, kind, path in chain:
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
                res.coins.append(Coin(u["txid"], u["vout"], u["value"], addr, kind, priv, path))
                found += u["value"]
        print(f" {found/1e8:.8f} BTC")
    if not any_scheme:
        sys.exit("Seed phrase is not a valid BIP39 or Electrum mnemonic. Check spelling/word order.")
    return res

# ----------------------------------------------------------------------------- transaction

def build_and_sign(coins, dest, rate):
    # conservative vbytes estimate: overhead 11 + outputs 43 + inputs (p2pkh 148, p2sh-p2wpkh 91, p2wpkh 68)
    vb = 11 + 43 + sum({"p2pkh": 148, "p2sh-p2wpkh": 91, "p2wpkh": 68}[c.kind] for c in coins)
    fee = vb * rate
    total = sum(c.value for c in coins)
    send = total - fee
    if send <= DUST:
        sys.exit(f"After a {fee} sat fee nothing worth sending remains ({total} sats total).")

    ins = [TxInput(c.txid, c.vout) for c in coins]
    outs = [TxOutput(send, _dest_script(dest))]
    has_segwit = any(c.kind != "p2pkh" for c in coins)
    tx = Transaction(ins, outs, has_segwit=has_segwit)

    for i, c in enumerate(coins):
        pk = PrivateKey(secret_exponent=int.from_bytes(bytes(c.priv), "big"))
        pub = pk.get_public_key()
        if c.kind == "p2pkh":
            sig = pk.sign_input(tx, i, pub.get_address().to_script_pub_key())
            ins[i].script_sig = Script([sig, pub.to_hex()])
            if has_segwit:
                tx.witnesses.append(TxWitnessInput([]))
        else:
            redeem = pub.get_segwit_address().to_script_pub_key()
            sig = pk.sign_segwit_input(tx, i, redeem, c.value)
            if c.kind == "p2sh-p2wpkh":
                ins[i].script_sig = Script([pub.get_segwit_address().to_script_pub_key().to_hex()])
            tx.witnesses.append(TxWitnessInput([sig, pub.to_hex()]))
        del pk
    # Several coins may share one key buffer (same address), so wipe only once
    # every input is signed.
    for c in coins:
        wipe(c.priv)
    gc.collect()
    return tx, send, fee, vb

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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan", help="find funds only (needs seed + network)")
    a1 = sub.add_parser("addresses", help="OFFLINE: seed -> public address list")
    a1.add_argument("-o", "--out", default="addresses.json")
    a1.add_argument("-n", "--per-chain", type=int, default=100, help="addresses per chain (default 100)")
    f = sub.add_parser("fetch", help="ONLINE, no seed: addresses -> utxos.json")
    f.add_argument("addresses_file", nargs="?", help="addresses.json from the offline step")
    f.add_argument("--addr", nargs="+", help="or give addresses directly")
    f.add_argument("-o", "--out", default="utxos.json")
    g = sub.add_parser("sign", help="OFFLINE: seed + utxos.json -> raw tx hex")
    g.add_argument("utxos_file")
    g.add_argument("address", help="your NEW wallet's receive address")
    g.add_argument("--fee-rate", type=int, help="sat/vB (default: rate saved by fetch)")
    s = sub.add_parser("sweep", help="build and sign a sweep; prints raw hex, never broadcasts")
    s.add_argument("address", help="your NEW wallet's receive address")
    s.add_argument("--fee-rate", type=int, help="sat/vB (default: current half-hour rate)")
    a = ap.parse_args()

    if a.cmd == "addresses":
        mnemonic, passphrase = read_secret()
        addrs = list_addresses(mnemonic, passphrase, a.per_chain)
        del mnemonic, passphrase
        gc.collect()
        with open(a.out, "w") as fh:
            json.dump(addrs, fh, indent=1)
        print(f"Wrote {len(addrs)} public addresses to {a.out} (no keys). Take this file online.")
        return

    if a.cmd == "fetch":
        addrs = [{"address": x} for x in (a.addr or [])]
        if a.addresses_file:
            with open(a.addresses_file) as fh:
                addrs += json.load(fh)
        addrs = list({x["address"]: x for x in addrs}.values())   # dedupe
        if not addrs:
            sys.exit("Give addresses.json or --addr ...")
        print(f"Fetching UTXOs for {len(addrs)} addresses (read-only) ...")
        coins = fetch_utxos(addrs)
        rate = fee_rate()
        with open(a.out, "w") as fh:
            json.dump({"fee_rate": rate, "utxos": coins}, fh, indent=1)
        total = sum(c["value"] for c in coins)
        print(f"Found {len(coins)} coin(s), total {total/1e8:.8f} BTC. Fee rate now {rate} sat/vB.")
        for c in coins:
            print(f"  {c['value']/1e8:.8f}  {c['address']}" + ("" if c["confirmed"] else "  (UNCONFIRMED)"))
        if any(not c["confirmed"] for c in coins):
            print("Note: unconfirmed coins are included; wait for confirmation if you want to be safe.")
        print(f"Wrote {a.out}. Take this file to the offline machine.")
        return

    if a.cmd == "sign":
        _dest_script(a.address)
        if input("Confirm destination address again (type it): ").strip() != a.address:
            sys.exit("Addresses do not match. Aborting.")
        with open(a.utxos_file) as fh:
            data = json.load(fh)
        if not data["utxos"]:
            sys.exit("No UTXOs in file.")
        mnemonic, passphrase = read_secret()
        utxos = dedupe_utxos(data["utxos"])
        keys = keys_for(mnemonic, passphrase, {u["address"] for u in utxos})
        del mnemonic, passphrase
        gc.collect()
        coins = [Coin(u["txid"], u["vout"], u["value"], u["address"],
                      keys[u["address"]][0], keys[u["address"]][2], keys[u["address"]][1])
                 for u in utxos]
        rate = a.fee_rate or data.get("fee_rate") or 10
        tx, send, fee, vb = build_and_sign(coins, a.address, rate)
        _print_result(tx, coins, a.address, send, fee, vb, rate)
        del coins, keys, tx
        gc.collect()
        return

    if a.cmd == "sweep":
        _dest_script(a.address)  # validate early, before asking for the seed
        confirm = input(f"Confirm destination address again (type it): ").strip()
        if confirm != a.address:
            sys.exit("Addresses do not match. Aborting.")

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

    rate = a.fee_rate or fee_rate()
    tx, send, fee, vb = build_and_sign(res.coins, a.address, rate)
    _print_result(tx, res.coins, a.address, send, fee, vb, rate)
    del res, tx
    gc.collect()

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

if __name__ == "__main__":
    main()
