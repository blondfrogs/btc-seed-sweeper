#!/usr/bin/env bash
# setup.sh — (re)create .venv with a suitable Python (>= 3.10) and install pinned deps.
# If no suitable Python is installed, downloads a standalone Python 3.12 via `uv`
# (no admin rights needed). Safe to re-run; it replaces any existing .venv.
set -euo pipefail
cd "$(dirname "$0")"

MIN_MINOR=10
PY=""

ok_version() {   # is "$1" a python >= 3.10?
    "$1" -c "import sys; sys.exit(0 if sys.version_info >= (3, $MIN_MINOR) else 1)" 2>/dev/null
}

# 1. Look for an installed Python that is new enough (prefer newest).
for cand in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && ok_version "$cand"; then
        PY="$(command -v "$cand")"
        break
    fi
done

if [ -n "$PY" ]; then
    echo "Using $PY ($("$PY" --version))"
    rm -rf .venv
    "$PY" -m venv .venv
    .venv/bin/pip install -q --upgrade pip
    .venv/bin/pip install -q -r requirements.txt
else
    # 2. Nothing suitable installed: use uv to fetch a standalone Python 3.12.
    echo "No Python >= 3.$MIN_MINOR found on PATH. Fetching one with uv..."
    if ! command -v uv >/dev/null 2>&1; then
        if command -v pip3 >/dev/null 2>&1; then
            pip3 install --user -q uv
            export PATH="$HOME/.local/bin:$PATH"
        else
            curl -LsSf https://astral.sh/uv/install.sh | sh
            export PATH="$HOME/.local/bin:$PATH"
        fi
    fi
    rm -rf .venv
    uv venv -q --seed --python 3.12 .venv      # --seed: include pip in the venv
    .venv/bin/pip install -q -r requirements.txt
fi

echo
echo "Installed into .venv with $(.venv/bin/python --version):"
.venv/bin/pip list 2>/dev/null | grep -iE "^(bip.utils|bitcoin-utils|coincurve|requests) " || true
echo
echo "Running self-tests..."
.venv/bin/python tests/test_all.py 2>&1 | grep -v Warning | tail -1
echo
echo "Ready. Use:  .venv/bin/python sweeper.py --help"
