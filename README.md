# btc-seed-sweeper

Recover bitcoin from an old wallet's seed phrase and move it to a new address — **without
ever putting the seed on an internet-connected computer, and without trusting this tool to
send anything.**

It derives your keys locally, builds and signs one transaction that sends the entire
balance to an address you choose, **independently re-verifies every signature** against a
from-spec implementation before showing you anything, and prints the signed transaction as
hex. **It never broadcasts.** You submit the hex yourself when you're ready.

---

## Table of contents

1. [How it works](#how-it-works)
2. [What you need](#what-you-need)
3. [Setup](#setup)
4. [Step-by-step: air-gapped sweep (recommended)](#step-by-step-air-gapped-sweep-recommended)
5. [Already know the address? Skip the scan](#already-know-the-address-skip-the-scan)
6. [One-machine mode (simpler, less safe)](#one-machine-mode-simpler-less-safe)
7. [Which wallets does it support?](#which-wallets-does-it-support)
8. [Troubleshooting](#troubleshooting)
9. [Security model](#security-model)
10. [Command reference](#command-reference)
11. [Verifying the dependencies yourself](#verifying-the-dependencies-yourself)

---

## How it works

```
 OFFLINE machine                 ONLINE machine                 OFFLINE machine
 ┌──────────────────┐            ┌──────────────────┐            ┌──────────────────┐
 │ seed phrase      │            │                  │            │ seed phrase      │
 │       ↓          │ addresses  │  look up UTXOs   │  utxos     │       ↓          │
 │ derive addresses ├───.json───▶│  + fee rate      ├───.json───▶│ sign transaction │
 │ (public only)    │            │  (no seed!)      │            │       ↓          │
 └──────────────────┘            └──────────────────┘            │  raw tx hex      │
                                                                 └────────┬─────────┘
                                          ONLINE: paste hex into          │
                                          mempool.space/tx/push  ◀────────┘
```

The only files that move between machines contain **public** data (addresses, transaction
IDs, amounts). The seed phrase is typed only on the offline machine, and the tool prints the
signed hex instead of sending it, so you get a final chance to review before anything moves.

---

## What you need

- **Your seed phrase** — 12 or 24 words (BIP39), or an Electrum seed. Plus the BIP39
  passphrase ("25th word") if you ever set one. Most people didn't.
- **A new wallet** with a receive address to sweep into. Any modern wallet works
  (Sparrow, Electrum, BlueWallet, a hardware wallet, …). Use a `bc1q…` address if offered.
- **Python 3.9 or newer** on each machine you'll use (`python3 --version` to check).
- For the air-gapped flow: **a second computer that you can keep offline**, and a USB stick
  (or a phone camera for QR / retyping — the files are small). A live-USB Linux boot of a
  laptop with Wi-Fi turned off is a good offline machine.

---

## Setup

Do this on **each** machine you'll use (the offline machine needs the packages installed
while it is still online, then disconnect):

```bash
git clone https://github.com/blondfrogs/btc-seed-sweeper.git
cd btc-seed-sweeper
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Dependency versions are pinned to the audited set (see
[Verifying the dependencies yourself](#verifying-the-dependencies-yourself)).

> **Tip:** everything below uses `.venv/bin/python sweeper.py …`. If you `source
> .venv/bin/activate` first you can just type `python sweeper.py …`.

---

## Step-by-step: air-gapped sweep (recommended)

### Step 0 — test your destination address

Before anything else, send a **tiny** amount (a few thousand sats) to your new wallet's
address from an exchange or another wallet, and confirm it shows up. This proves you
control the destination. Skipping this step is how people lose coins.

### Step 1 — OFFLINE: derive your addresses

On the offline machine, with networking disabled:

```bash
.venv/bin/python sweeper.py addresses
```

You'll be asked for the seed phrase (input is hidden) and the passphrase (press Enter if
you never set one). It writes `addresses.json` containing the first 100 addresses of every
derivation scheme it knows — **addresses only, no keys** (BIP39 addresses are derived from
the account *xpub*, so no per-address private key is even created). Example of what's inside:

```json
[{"address": "1LqBGSKuX5yY…", "kind": "p2pkh", "scheme": "bip44", "chain": 0, "index": 0,
  "path": "BIP44 legacy m/44'/0'/0'/0/0"}, …]
```

The `scheme/chain/index` fields let `sign` derive exactly the right key later instead of
searching for it, so use `addresses.json` rather than `--addr` when you can.

If the wallet was used heavily (more than ~100 addresses per chain), raise the count:
`--per-chain 300`.

> **Shortcut:** if you already know the funded addresses (e.g. from a block explorer or an
> old backup), you can skip this step entirely and pass them directly in Step 2. The seed
> is then entered only once, in Step 3.

### Step 2 — ONLINE: fetch the coins

Copy `addresses.json` to the online machine (USB stick is fine — it's public data). Then:

```bash
.venv/bin/python sweeper.py fetch addresses.json
```

or, without an address file:

```bash
.venv/bin/python sweeper.py fetch --addr 1YourOldAddr… bc1qAnotherOldAddr…
```

**No seed is asked for.** It queries mempool.space (falling back to blockstream.info),
prints what it found, and writes `utxos.json`:

```
Fetching UTXOs for 1200 addresses (read-only) ...
Found 2 coin(s), total 0.31500000 BTC.
  0.30000000  1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
  0.01500000  bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
Fee rate now 4 sat/vB (saved for `sign`).
Wrote utxos.json. Take this file to the offline machine.
```

If it prints `WARNING: could not fetch the current fee rate`, look up a sensible sat/vB on
https://mempool.space and pass it to `sign` with `--fee-rate`. Coins marked `(UNCONFIRMED)`
are included; wait for confirmation if you want to be safe.

If it reports **0 coins**, stop here and read [Troubleshooting](#troubleshooting).

### Step 3 — OFFLINE: sign

Copy `utxos.json` back to the offline machine. Then:

```bash
.venv/bin/python sweeper.py sign utxos.json bc1qYourNEWaddress…
```

It will:
1. Make you **retype the destination address** (guards against clipboard malware / typos).
2. Ask for the seed phrase and passphrase.
3. Re-derive only the keys needed, sign, **independently verify every signature**
   (see [Security model](#security-model)), and print a summary plus the raw hex:

```
=== SWEEP SUMMARY ===
  inputs : 2  (0.31500000 BTC)
  to     : bc1qYourNEWaddress…
  amount : 0.31498915 BTC
  fee    : 1085 sats  (4 sat/vB, ~271 vB)
  txid   : bda98328…

Raw signed transaction hex (NOT broadcast — this tool never submits):
02000000000102aaaa…
```

**Check the summary carefully.** The `to` address must be yours, and `amount + fee` should
equal the total. The fee rate comes from `utxos.json` (captured in Step 2); override with
`--fee-rate 20` if the network got busier since then. The fee is charged on the transaction's
*actual* size, not the estimate.

If an address in `utxos.json` has no `scheme/chain/index` (because you used `--addr`),
`sign` searches the first 2000 addresses of every chain for it. For a very heavily used
wallet, raise that with `--max-index 10000`.

### Step 4 — ONLINE: broadcast it yourself

Get the hex to an online device (retype it, QR it, or USB it — it's already signed and
contains no secrets) and paste it into any of:

- https://mempool.space/tx/push
- https://blockstream.info/tx/push
- your own node: `bitcoin-cli sendrawtransaction <hex>`

Then watch it confirm at `https://mempool.space/tx/<txid>`.

### Step 5 — clean up

Shut the offline machine **down** (not just close the terminal) to clear RAM. Delete
`addresses.json` / `utxos.json` if you like — they're public, but tidy.

---

## Already know the address? Skip the scan

If you know which old address holds the coins (from a block explorer, an old screenshot, a
backup…), you never need to generate an address list. The seed is used exactly once, to sign.

Air-gapped:
```bash
# online, no seed
.venv/bin/python sweeper.py fetch --addr 1YourOldAddr…
# offline
.venv/bin/python sweeper.py sign utxos.json bc1qYourNEWaddr…
```

One machine:
```bash
.venv/bin/python sweeper.py sweep bc1qYourNEWaddr… --addr 1YourOldAddr…
```

You can pass several old addresses after `--addr`. Coins on all of them go into one
transaction.

## One-machine mode (simpler, less safe)

If you accept having the seed on an online machine (e.g. small amount, trusted computer):

```bash
.venv/bin/python sweeper.py scan                     # find funds, nothing signed
.venv/bin/python sweeper.py sweep bc1qYourNEWaddr…   # sign and print hex
```

`scan` walks each derivation chain until it sees 20 unused addresses in a row (the standard
gap limit), so it finds everything the wallet ever used. `sweep` still never broadcasts.

---

## Which wallets does it support?

| Seed type | Scheme | Address style | Path scanned |
|---|---|---|---|
| BIP39 (12/24 words) | BIP44 legacy | `1…` | `m/44'/0'/0'/{0,1}/i` |
| BIP39 | BIP49 nested segwit | `3…` | `m/49'/0'/0'/{0,1}/i` |
| BIP39 | BIP84 native segwit | `bc1q…` | `m/84'/0'/0'/{0,1}/i` |
| Electrum v2 | standard | `1…` | Electrum's own |
| Electrum v2 | segwit | `bc1q…` | Electrum's own |
| Electrum v1 (pre-2014) | legacy, uncompressed keys | `1…` | Electrum's own |

That covers Electrum, Ledger, Trezor, Mycelium (recent), Samourai, Wasabi, BlueWallet,
Exodus, Coinomi, Trust Wallet, and most others. Receive **and** change chains are scanned.
Electrum seeds are detected by type (standard vs segwit) so only the matching chains are
walked, and Electrum passphrases are normalised the way Electrum does it (case, accents,
spacing); BIP39 passphrases are used verbatim, as BIP39 requires.

Not covered (yet): accounts other than 0, Taproot (`m/86'`), and wallets with unusual paths
(Multibit HD, early Bread/Mycelium, Bitcoin Core descriptor wallets, some Coinomi versions).
These are one-line additions in `wallet_candidates()` — open an issue with the wallet name.

**Bitcoin only.** The same seed may control other coins (LTC, ETH, BCH…) — this tool
neither touches nor sees them; they stay where they are.

---

## Troubleshooting

**"Seed phrase is not a valid BIP39 or Electrum mnemonic."**
A word is misspelled or out of order. Check each against the
[BIP39 word list](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt). Words
are lowercase and separated by single spaces; the tool normalises spacing for you.

**`fetch` / `scan` finds 0 BTC.**
- Did you set a BIP39 passphrase back then? Try again with it — a different passphrase
  gives a completely different wallet.
- Old wallet used more than 100 addresses? Re-run `addresses --per-chain 500`.
- The wallet software may use a non-standard path — tell us which wallet it was.
- Check one of the generated addresses on a block explorer. If the address *has* history
  but the tool shows nothing, the coins were already spent.

**"This seed does not control these addresses"** (during `sign`).
The addresses in `utxos.json` weren't derived from this seed/passphrase. Usually a typo in
the seed or a forgotten passphrase. If you used `--addr` on a heavily used wallet, the
address may simply be deeper than the default search — retry with `--max-index 10000`.

**"INTERNAL ERROR: signed transaction failed independent verification".**
The built-in verifier rejected the transaction the signer produced. Nothing was printed and
nothing is at risk; please open an issue with the (public) `utxos.json` and the error text.

**"429 Too Many Requests" / network errors.**
The public APIs rate-limit. The tool retries with backoff and alternates between two
providers; just let it run. Very large address lists take a few minutes.

**Transaction rejected when broadcasting.**
- "min relay fee not met": re-sign with `--fee-rate 10` or higher.
- "bad-txns-inputs-missingorspent": the coins were spent between `fetch` and broadcast, or
  `utxos.json` is stale. Re-run `fetch`.

**"No matching distribution found for requests==2.34.2".**
Your Python is older than 3.10. `requirements.txt` handles Python 3.9 automatically; if
you're on 3.8 or older, install a newer Python (3.9+ is required by `coincurve`).

**Windows users:** replace `.venv/bin/python` with `.venv\Scripts\python`.

---

## Security model

What this tool does to protect you:

- **Never broadcasts.** There is no code path that submits a transaction. You do that.
- **Seed never needs to be online.** `fetch` works from addresses alone.
- **Whole balance to one address you control** — no change output that could be stranded.
- **Destination is double-entered** and validated before the seed is requested.
- **Every signature is independently verified before output.** `verify_tx.py` is a
  separate, from-spec implementation of the legacy and BIP143 sighash algorithms (validated
  against the official BIP143 test vector) using libsecp256k1. `sweeper.py` runs it on every
  transaction it builds and refuses to print hex that doesn't pass — a signing bug can't
  reach you as a rejected broadcast. It also checks the fee estimate against the real size.
- **Fee rate is validated** (positive whole number) and never silently defaulted; if it
  couldn't be fetched you are told to supply one.
- **Memory hygiene (best effort):** private keys are held as mutable buffers and zeroed
  once they're no longer needed (including on the `scan`-only path and on errors); the
  seed is dropped after derivation; the `addresses` command never creates per-address
  private keys at all; core dumps are disabled so a crash can't write the seed to disk.
  Nothing secret is ever written to a file. See the caveat below.
- **Read-only network calls only** (address lookups, UTXO lists, fee estimate), and only
  in `scan`, `sweep`, and `fetch`. `addresses` and `sign` make no network calls at all.
- **Pinned, audited dependencies** — see below.

What it can't protect you from:

- **A compromised offline machine** (keylogger, malicious OS). Use a fresh live-USB boot.
- **Python's memory model.** The mnemonic string, the BIP39 seed bytes, and intermediate
  key objects inside the libraries are immutable and cannot be zeroed from Python; they
  stay in RAM (and potentially swap/hibernation files) until overwritten. Shutting the
  offline machine **down** afterwards is the real guarantee.
- **You sending to the wrong address.** Test the destination first (Step 0).

---

## Command reference

```
sweeper.py addresses [-o addresses.json] [-n PER_CHAIN]
    OFFLINE. Seed -> public address list. Default 100 addresses per chain.

sweeper.py fetch [addresses.json] [--addr A1 A2 ...] [-o utxos.json]
    ONLINE, no seed. Looks up UTXOs and current fee rate for the given addresses.

sweeper.py sign utxos.json NEW_ADDRESS [--fee-rate SAT_PER_VB] [--max-index N]
    OFFLINE. Seed + utxos -> signed, self-verified raw tx hex. Never broadcasts.

sweeper.py scan
    ONLINE + seed. Walks all derivation chains with a gap limit of 20 and reports balances.

sweeper.py sweep NEW_ADDRESS [--fee-rate SAT_PER_VB] [--addr OLD_ADDRESS ...] [--max-index N]
    ONLINE + seed. scan + sign in one go. With --addr, skips the scan and sweeps
    only the given address(es). Never broadcasts.
```

Destination address can be `1…`, `3…`, or `bc1q…` (mainnet). Taproot `bc1p…` is not
supported as a destination.

---

## Verifying the dependencies yourself

`requirements.txt` pins `bip_utils==2.12.2`, `bitcoin-utils==0.8.2`, `coincurve==21.0.0`
and `requests==2.34.2` (on Python 3.9, where 2.34 isn't available, it selects
`requests==2.32.5` instead — `requests` only does read-only HTTP lookups and never touches
keys).
These versions were audited by:

1. Re-downloading each wheel from PyPI and SHA-256-comparing **every installed file** against
   the wheel's RECORD (0 mismatches across 800+ files, including transitive deps
   `coincurve`, `pycryptodome`, `pynacl`, `ecdsa`).
2. Grepping every key-handling library for `socket`/`urllib`/`http`/`subprocess`/`exec`.
   The only hit is `bitcoinutils/proxy.py`, an optional Bitcoin Core RPC client that
   nothing imports.
3. Running derive + sign with all socket calls monkey-patched to throw — it completes,
   proving no dependency attempts a connection during key handling.
4. `pip-audit`: one advisory on `ecdsa` (Minerva timing attack) which requires an attacker
   timing many signatures on your machine; irrelevant for a single local signature.

To repeat the check: `pip install pip-audit && pip-audit`. Don't bump versions without
re-auditing.

## Running the tests

```bash
.venv/bin/python tests/test_all.py
```

The suite validates the verifier against the BIP143 spec vector, signs every supported
input type (BIP44/49/84, Electrum v2 standard/segwit, Electrum v1 uncompressed) from
throw-away test seeds and verifies them independently, and includes a negative test that
reproduces a real signing bug to prove the verifier catches it.

---

## License

MIT. Use at your own risk — read the summary before you broadcast.
