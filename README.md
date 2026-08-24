# btc-seed-sweeper

Recover bitcoin from an old wallet's seed phrase and move it to a new address — **without
ever putting the seed on an internet-connected computer, and without trusting this tool to
send anything.**

It's a single Python file. It derives your keys locally, builds and signs one transaction
that sends the entire balance to an address you choose, and prints the signed transaction
as hex. **It never broadcasts.** You submit the hex yourself when you're ready.

---

## Table of contents

1. [How it works](#how-it-works)
2. [What you need](#what-you-need)
3. [Setup](#setup)
4. [Step-by-step: air-gapped sweep (recommended)](#step-by-step-air-gapped-sweep-recommended)
5. [One-machine mode (simpler, less safe)](#one-machine-mode-simpler-less-safe)
6. [Which wallets does it support?](#which-wallets-does-it-support)
7. [Troubleshooting](#troubleshooting)
8. [Security model](#security-model)
9. [Command reference](#command-reference)
10. [Verifying the dependencies yourself](#verifying-the-dependencies-yourself)

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
- **Python 3.10+** on each machine you'll use.
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
derivation scheme it knows — **addresses only, no keys**. Example of what's inside:

```json
[{"address": "1LqBGSKuX5yY…", "kind": "p2pkh", "path": "BIP44 legacy m/44'/0'/0'/0/0"}, …]
```

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
Fetching UTXOs for 1800 addresses (read-only) ...
Found 2 coin(s), total 0.31500000 BTC. Fee rate now 4 sat/vB.
  0.30000000  1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
  0.01500000  bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
Wrote utxos.json. Take this file to the offline machine.
```

If it reports **0 coins**, stop here and read [Troubleshooting](#troubleshooting).

### Step 3 — OFFLINE: sign

Copy `utxos.json` back to the offline machine. Then:

```bash
.venv/bin/python sweeper.py sign utxos.json bc1qYourNEWaddress…
```

It will:
1. Make you **retype the destination address** (guards against clipboard malware / typos).
2. Ask for the seed phrase and passphrase.
3. Re-derive only the keys needed, sign, and print a summary plus the raw hex:

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
`--fee-rate 20` if the network got busier since then.

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
| Electrum v1 (pre-2014) | legacy | `1…` | Electrum's own |

That covers Electrum, Ledger, Trezor, Mycelium (recent), Samourai, Wasabi, BlueWallet,
Exodus, Coinomi, Trust Wallet, and most others. Receive **and** change chains are scanned.

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
the seed or a forgotten passphrase.

**"429 Too Many Requests" / network errors.**
The public APIs rate-limit. The tool retries with backoff and alternates between two
providers; just let it run. Very large address lists take a few minutes.

**Transaction rejected when broadcasting.**
- "min relay fee not met": re-sign with `--fee-rate 10` or higher.
- "bad-txns-inputs-missingorspent": the coins were spent between `fetch` and broadcast, or
  `utxos.json` is stale. Re-run `fetch`.

**Windows users:** replace `.venv/bin/python` with `.venv\Scripts\python`.

---

## Security model

What this tool does to protect you:

- **Never broadcasts.** There is no code path that submits a transaction. You do that.
- **Seed never needs to be online.** `fetch` works from addresses alone.
- **Whole balance to one address you control** — no change output that could be stranded.
- **Destination is double-entered** and validated before the seed is requested.
- **Memory hygiene:** private keys are held as mutable buffers and zeroed the moment
  they're no longer needed; the seed is dropped after derivation; core dumps are disabled
  so a crash can't write the seed to disk. Nothing secret is ever written to a file.
- **Read-only network calls only** (address lookups, UTXO lists, fee estimate), and only
  in `scan`, `sweep`, and `fetch`. `addresses` and `sign` make no network calls at all.
- **Pinned, audited dependencies** — see below.

What it can't protect you from:

- **A compromised offline machine** (keylogger, malicious OS). Use a fresh live-USB boot.
- **Python's memory model.** Immutable strings and library internals may leave copies in
  RAM. Shutting down the offline machine afterwards is the real guarantee.
- **You sending to the wrong address.** Test the destination first (Step 0).

---

## Command reference

```
sweeper.py addresses [-o addresses.json] [-n PER_CHAIN]
    OFFLINE. Seed -> public address list. Default 100 addresses per chain.

sweeper.py fetch [addresses.json] [--addr A1 A2 ...] [-o utxos.json]
    ONLINE, no seed. Looks up UTXOs and current fee rate for the given addresses.

sweeper.py sign utxos.json NEW_ADDRESS [--fee-rate SAT_PER_VB]
    OFFLINE. Seed + utxos -> signed raw tx hex. Never broadcasts.

sweeper.py scan
    ONLINE + seed. Walks all derivation chains with a gap limit of 20 and reports balances.

sweeper.py sweep NEW_ADDRESS [--fee-rate SAT_PER_VB]
    ONLINE + seed. scan + sign in one go. Never broadcasts.
```

Destination address can be `1…`, `3…`, or `bc1q…` (mainnet). Taproot `bc1p…` is not
supported as a destination.

---

## Verifying the dependencies yourself

`requirements.txt` pins `bip_utils==2.12.2`, `bitcoin-utils==0.8.2`, `requests==2.34.2`.
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

---

## License

MIT. Use at your own risk — read the summary before you broadcast.
