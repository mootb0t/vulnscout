"""vulnscout test suite (stdlib unittest — no extra deps).

Run from the directory that CONTAINS the vulnscout package:

    cd /path/to/Projects
    python3.11 -m unittest discover -t . -s vulnscout/tests -p "test_*.py"

These tests cover the pure, deterministic core (task registry contract,
fact store, severity derivation, parsers, privesc analyzers). They do not
import app.py, so textual is not required to run them.
"""
