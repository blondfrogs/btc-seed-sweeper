#!/usr/bin/env python3
"""
sweeper.py — recover BTC from an old seed phrase and sweep it to a new address.

Everything sensitive (seed -> keys -> signing) happens locally in this process.
The only network calls are read-only balance/UTXO lookups and the final
broadcast of the already-signed transaction (and only after you type YES).

Usage:
    python sweeper.py scan                 # find funds, no network writes
    python sweeper.py sweep <new_address>  # build + sign, show summary, ask, broadcast
    python sweeper.py sweep <new_address> --dry-run   # everything except broadcast
"""
import argparse
import getpass
import sys
import time
from dataclasses import dataclass, field

import requests
from bip_utils import (
    Bip39MnemonicValidator, Bip39SeedGenerator, Bip39Languages,
    Bip44, Bip49, Bip84, Bip44Coins, Bip49Coins, Bip84Coins, Bip44Changes,
    ElectrumV2MnemonicValidator, ElectrumV2SeedGenerator, ElectrumV2Standard, ElectrumV2Segwit,
    ElectrumV1MnemonicValidator, ElectrumV1SeedGenerator, ElectrumV1,
)
from bitcoinutils.setup import setup as btc_setup
from bitcoinutils.keys import PrivateKey, P2wpkhAddress, P2shAddress, P2pkhAddress
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis

APIS = ["https://mempool.space/api", "https://blockstream.info/api"]
API = APIS[0]
GAP_LIMIT = 20          # unused addresses in a row before we stop scanning a chain
DUST = 546              # sats
btc_setup("mainnet")

# ----------------------------------------------------------------------------- data

@dataclass
class Coin:
    txid: str
    vout: int
    value: int            # sats
    address: str
    kind: str             # p2pkh | p2sh-p2wpkh | p2wpkh
    wif: str
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

def broadcast(raw_hex):
    r = requests.post(f"{API}/tx", data=raw_hex, timeout=30)
    r.raise_for_status()
    return r.text.strip()

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
                        yield k.PublicKey().ToAddress(), k.PrivateKey().ToWif(), kind, f"{label}/{cname}/{i}"
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
                        yield (w.GetAddress(cname, i), w.GetPrivateKey(cname, i).ToWif(),
                               kind, f"{label}/{cname}/{i}")
                        i += 1
                yield f"{label} chain {cname}", gen()

    if ElectrumV1MnemonicValidator().IsValid(mnemonic):
        w = ElectrumV1.FromSeed(ElectrumV1SeedGenerator(mnemonic).Generate())
        for cname in (0, 1):
            def gen(w=w, cname=cname):
                i = 0
                while True:
                    yield w.GetAddress(cname, i), w.GetPrivateKey(cname, i).ToWif(), "p2pkh", f"ElectrumV1/{cname}/{i}"
                    i += 1
            yield f"Electrum v1 (old) chain {cname}", gen()

def scan(mnemonic, passphrase):
    res = ScanResult()
    any_scheme = False
    for label, chain in wallet_candidates(mnemonic, passphrase):
        any_scheme = True
        print(f"  scanning {label} ...", end="", flush=True)
        gap, found = 0, 0
        for addr, wif, kind, path in chain:
            res.checked += 1
            time.sleep(0.15)   # be polite to the public API
            if not address_used(addr):
                gap += 1
                if gap >= GAP_LIMIT:
                    break
                continue
            gap = 0
            for u in get_utxos(addr):
                res.coins.append(Coin(u["txid"], u["vout"], u["value"], addr, kind, wif, path))
                found += u["value"]
        print(f" {found/1e8:.8f} BTC")
    if not any_scheme:
        sys.exit("Seed phrase is not a valid BIP39 or Electrum mnemonic. Check spelling/word order.")
    return res

# ----------------------------------------------------------------------------- transaction

def build_and_sign(coins, dest, rate):
    n_in = len(coins)
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
        pk = PrivateKey(c.wif)
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
    return tx, send, fee, vb

def _dest_script(addr):
    if addr.startswith("bc1q"):
        return P2wpkhAddress(addr).to_script_pub_key()
    if addr.startswith("3"):
        return P2shAddress(addr).to_script_pub_key()
    if addr.startswith("1"):
        return P2pkhAddress(addr).to_script_pub_key()
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
    sub.add_parser("scan", help="find funds only")
    s = sub.add_parser("sweep", help="build, sign and broadcast a sweep")
    s.add_argument("address", help="your NEW wallet's receive address")
    s.add_argument("--dry-run", action="store_true", help="do everything except broadcast")
    s.add_argument("--fee-rate", type=int, help="sat/vB (default: current half-hour rate)")
    a = ap.parse_args()

    if a.cmd == "sweep":
        _dest_script(a.address)  # validate early, before asking for the seed
        confirm = input(f"Confirm destination address again (type it): ").strip()
        if confirm != a.address:
            sys.exit("Addresses do not match. Aborting.")

    mnemonic, passphrase = read_secret()
    print("\nScanning (read-only) ...")
    res = scan(mnemonic, passphrase)
    print(f"\nChecked {res.checked} addresses. Found {len(res.coins)} coin(s), total {res.total/1e8:.8f} BTC")
    for c in res.coins:
        print(f"  {c.value/1e8:.8f}  {c.address}  ({c.path})")
    if a.cmd == "scan" or not res.coins:
        return

    rate = a.fee_rate or fee_rate()
    tx, send, fee, vb = build_and_sign(res.coins, a.address, rate)
    raw = tx.serialize()
    print("\n=== SWEEP SUMMARY ===")
    print(f"  inputs : {len(res.coins)}  ({res.total/1e8:.8f} BTC)")
    print(f"  to     : {a.address}")
    print(f"  amount : {send/1e8:.8f} BTC")
    print(f"  fee    : {fee} sats  ({rate} sat/vB, ~{vb} vB)")
    print(f"  txid   : {tx.get_txid()}")
    print(f"\nRaw signed tx (you can broadcast this yourself anywhere):\n{raw}\n")
    if a.dry_run:
        print("--dry-run: not broadcasting.")
        return
    if input("Type YES to broadcast: ").strip() != "YES":
        print("Not broadcast.")
        return
    txid = broadcast(raw)
    print(f"Broadcast OK. Track it: https://mempool.space/tx/{txid}")

if __name__ == "__main__":
    main()
