"""vulnscout test suite (stdlib unittest — no extra deps).

Run from the directory that CONTAINS the vulnscout package:

    cd /path/to/Projects
    python3.11 -m unittest discover -t . -s vulnscout/tests -p "test_*.py"

These tests cover the pure, deterministic core (task registry contract,
fact store, severity derivation, parsers, privesc analyzers). They do not
import app.py, so textual is not required to run them.

Add or extend a test whenever you add a task, fact type, or privesc rule —
test_tasks.py is the contract guard that catches the silent breakages.
"""
