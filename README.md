# BTC seed-phrase sweeper

Moves all BTC controlled by an old seed phrase to a new address. Keys never leave your machine.

## Setup
    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

## Use
1. Look first (read-only, nothing is signed or sent):
       .venv/bin/python sweeper.py scan
2. Build and sign the sweep — prints amount/fee/txid and the raw signed hex:
       .venv/bin/python sweeper.py sweep bc1q...yournewaddress
3. **This tool never broadcasts.** When you're ready, paste the hex into
   https://mempool.space/tx/push (or your own node). Nothing moves until you do.

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
