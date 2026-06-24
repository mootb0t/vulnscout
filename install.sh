#!/usr/bin/env bash
#
# vulnscout one-time installer — sets up a local virtualenv with the Python
# dependencies. External scanning tools (nmap, nuclei, ...) are NOT installed
# here; the in-app Modules screen (press `m`) has a one-click installer for
# those.
#
#   ./install.sh
#   ./run.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find a Python new enough for Textual >= 0.50 (needs >= 3.9; 3.11+ recommended).
PY=""
for c in python3.13 python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1; then
    if "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,9) else 1)' 2>/dev/null; then
      PY="$(command -v "$c")"; break
    fi
  fi
done

if [[ -z "$PY" ]]; then
  echo "install: no python3 >= 3.9 found. On macOS: brew install python@3.11" >&2
  exit 1
fi

echo "==> Using $("$PY" --version) at $PY"
echo "==> Creating virtualenv at $HERE/.venv"
"$PY" -m venv "$HERE/.venv"

echo "==> Installing Python dependencies"
"$HERE/.venv/bin/python" -m pip install --upgrade pip >/dev/null
"$HERE/.venv/bin/python" -m pip install -r "$HERE/requirements.txt"

echo
echo "Done. Launch with:  ./run.sh"
echo "Scanning tools (nmap, nuclei, ...) install from inside the app: press 'm'."
