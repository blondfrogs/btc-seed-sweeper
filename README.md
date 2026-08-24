# BTC seed-phrase sweeper

Moves all BTC controlled by an old seed phrase to a new address. Keys never leave your machine.

## Setup
    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

## Air-gapped use (recommended — the seed never touches an online machine)

1. **Offline machine** — derive a public-only address list (no keys are written):
       python sweeper.py addresses            # -> addresses.json  (default 100 per chain)
2. **Online machine** — pull UTXOs and the current fee rate, no seed needed:
       python sweeper.py fetch addresses.json # -> utxos.json
   If you already know the funded addresses you can skip step 1 entirely:
       python sweeper.py fetch --addr 1abc... bc1q...
3. **Offline machine** — enter the seed, sign, get the raw hex:
       python sweeper.py sign utxos.json bc1q...yournewaddress
4. **This tool never broadcasts.** Carry the hex back online and paste it into
   https://mempool.space/tx/push (or your own node). Nothing moves until you do.

Move `addresses.json` / `utxos.json` between machines however you like (USB, QR, retyping) —
they contain only public data.

## One-machine use (simpler, less safe)
       python sweeper.py scan                      # find funds
       python sweeper.py sweep bc1q...newaddress   # sign, print raw hex

Supports BIP39 seeds (BIP44 legacy `1...`, BIP49 `3...`, BIP84 `bc1q...`, with optional passphrase)
and Electrum seeds (old v1 and v2 standard/segwit). Scans receive + change chains with a gap limit of 20.

## Safety notes
- Run on a clean, trusted machine, ideally offline until the scan step (balance lookup needs the network).
- Send a small test to your new address from elsewhere first to make sure you control it.
- `scan` finding 0 BTC does not mean the coins are gone — it may be an unusual derivation path;
  tell me what wallet software it was and I can add its path.
- The seed is only held in memory for the duration of the run; it is never written to disk.

## Dependency verification
Dependencies are pinned in `requirements.txt`. The audited versions (every installed file
SHA-256-matched against the PyPI wheel; no network code in any key-handling library) are
`bip_utils==2.12.2`, `bitcoin-utils==0.8.2`, `requests==2.34.2`. Re-check with `pip-audit` before use.

## Disclaimer
Use at your own risk. Always run `scan` first, review the summary, and test your destination address
before sweeping real funds. MIT licensed.

## Memory hygiene
- Core dumps are disabled at startup so a crash can't write the seed to disk.
- Private keys are held as mutable byte buffers and zeroed the moment they're no longer
  needed (unused addresses immediately; funded ones right after signing).
- The seed phrase and passphrase are dropped as soon as scanning finishes.
- Python can't guarantee erasure of every interpreter-internal copy, so for real safety
  run the sweep on a clean machine and shut it down (not just close the terminal) afterwards.
