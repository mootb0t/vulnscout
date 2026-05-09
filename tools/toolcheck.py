"""Verify presence of every external tool we depend on.

Thin wrapper around `vulnscout.modules.MODULES` — the source of truth
for all tool metadata is the registry. This module exists to keep the
import path `from vulnscout.tools import is_available, check_tools`
short and clear from inside the phase runners.
"""

import shutil
from dataclasses import dataclass
from typing import List

from ..modules import MODULES, best_install_hint


@dataclass
class ToolStatus:
    name: str
    available: bool
    install_hint: str
    description: str
    category: str = "core"
    local_only: bool = False


def check_tools() -> List[ToolStatus]:
    """Return a ToolStatus for every registered module, reflecting PATH."""
    out: List[ToolStatus] = []
    for m in MODULES:
        path = shutil.which(m.name)
        out.append(
            ToolStatus(
                name=m.name,
                available=path is not None,
                install_hint=best_install_hint(m),
                description=m.description,
                category=m.category,
                local_only=m.local_only,
            )
        )
    return out


def is_available(name: str) -> bool:
    """Quick yes/no PATH lookup — used by phase runners to skip cleanly."""
    return shutil.which(name) is not None
