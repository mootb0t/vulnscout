"""vulnscout — entry point.

TUI only. Run with:
    python -m vulnscout
"""

from __future__ import annotations

import sys

from .tools.toolcheck import check_tools


BANNER = r"""
        _                                    _
__   __| | _ __    ___   ___   ___  _   _  | |_
\ \ / /| || '_ \  / __| / __| / _ \| | | | | __|
 \ V / | || | | | \__ \| (__ | (_) | |_| | | |_
  \_/  |_||_| |_| |___/ \___| \___/ \__,_|  \__|

      fact-driven pentest scanner — v1.0
"""


GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
RESET = "\033[0m"


def startup_check() -> int:
    """Print the banner + tool availability summary. Returns # missing."""
    print(BANNER)
    print(
        f"  {DIM}Authorized testing only — see disclaimer in any exported "
        f"report.{RESET}\n"
    )
    statuses = check_tools()
    missing = 0
    width = max(len(s.name) for s in statuses)
    for s in statuses:
        if s.local_only:
            continue
        if s.available:
            print(f"  {GREEN}✓{RESET} {s.name:<{width}}   {DIM}{s.description}{RESET}")
        else:
            print(
                f"  {RED}✗{RESET} {s.name:<{width}}   "
                f"{YELLOW}→ {s.install_hint}{RESET}"
            )
            missing += 1
    print()
    if missing:
        print(
            f"  {YELLOW}{missing} tool(s) missing — they'll be skipped during "
            f"scans (the M screen has a one-click installer).{RESET}\n"
        )
    return missing


def main(argv=None) -> int:
    # No CLI args anymore — TUI only.
    from .app import VulnScoutApp
    startup_check()
    VulnScoutApp().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
