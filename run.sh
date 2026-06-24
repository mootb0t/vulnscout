#!/usr/bin/env bash
#
# vulnscout launcher — run the TUI from anywhere, with the right Python.
#
#   ./run.sh
#
# The package is a Python *package* (run as `python -m vulnscout` from its
# parent directory). This script handles that for you: it finds a Python new
# enough for Textual, cd's to the parent dir, and runs the module.
#
# Override the interpreter with VULNSCOUT_PYTHON=/path/to/python ./run.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(dirname "$HERE")"
PKG="$(basename "$HERE")"

if [[ "$PKG" != "vulnscout" ]]; then
  echo "warning: this directory is named '$PKG', not 'vulnscout'." >&2
  echo "         Rename it to 'vulnscout' (e.g. after a ZIP download) so the" >&2
  echo "         package import works, then re-run ./run.sh" >&2
  exit 1
fi

has_textual() { "$1" -c 'import textual' >/dev/null 2>&1; }

# 1) Prefer a project-local virtualenv if install.sh created one.
PY=""
if [[ -x "$HERE/.venv/bin/python" ]] && has_textual "$HERE/.venv/bin/python"; then
  PY="$HERE/.venv/bin/python"
# 2) Honour an explicit override.
elif [[ -n "${VULNSCOUT_PYTHON:-}" ]] && has_textual "${VULNSCOUT_PYTHON}"; then
  PY="${VULNSCOUT_PYTHON}"
else
  # 3) Find any interpreter that can already import Textual.
  for c in python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 && has_textual "$c"; then
      PY="$(command -v "$c")"; break
    fi
  done
fi

if [[ -z "$PY" ]]; then
  echo "vulnscout: no Python with its dependencies installed was found." >&2
  echo "Run the one-time installer first:" >&2
  echo "    ./install.sh" >&2
  echo "or install deps manually into a Textual-capable Python (>= 3.9):" >&2
  echo "    python3.11 -m pip install -r \"$HERE/requirements.txt\"" >&2
  exit 1
fi

cd "$PARENT"
exec "$PY" -m "$PKG" "$@"
