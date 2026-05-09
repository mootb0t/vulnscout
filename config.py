"""Persist user settings between sessions.

Settings live at ``~/.config/vulnscout/settings.json`` (XDG-style location
on macOS and Linux). The file is created on first save; missing or corrupt
files fall back to defaults silently rather than blocking startup.
"""

import json
import os
from pathlib import Path
from typing import Dict

from .opsec import SETTINGS_DEFAULTS as _OPSEC_DEFAULTS


# Hard-coded defaults — also used as the schema. Anything stored on disk
# that isn't in this dict is ignored on load (so renaming a key in code
# doesn't crash old config files).
DEFAULTS: Dict[str, str] = {
    "model":              "gemma3:3b",
    "profile":            "quick",
    "wordlist":           "",
    "templates":          "",
    "shodan_api_key":     "",     # for the Shodan CLI passive-OSINT module
    "hunter_api_key":     "",     # hunter.io domain email enumeration (free tier 25/month)
    "enable_local_tools": "",     # "1" to surface metasploit/john/hashcat
    # OPSEC toggles — see opsec.py for the canonical list and semantics.
    **_OPSEC_DEFAULTS,
}


def _config_path() -> Path:
    """Resolve the settings file path. Honors $XDG_CONFIG_HOME if set,
    otherwise uses ~/.config — works on both macOS and Linux."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "vulnscout" / "settings.json"


def load_settings() -> Dict[str, str]:
    """Read settings from disk, merged over defaults.

    Never raises — a missing or unreadable file returns defaults so the
    app always starts.
    """
    path = _config_path()
    settings = dict(DEFAULTS)
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            # Only copy known keys — avoids junk leaking in if the schema
            # changes between versions.
            for k in DEFAULTS:
                if k in data and isinstance(data[k], str):
                    settings[k] = data[k]
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return settings


def save_settings(settings: Dict[str, str]) -> bool:
    """Write settings atomically. Returns True on success.

    We write to a tempfile next to the target then rename, so a crash
    mid-write can't leave a half-written settings.json.
    """
    path = _config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Only persist known keys, normalised to strings.
        clean = {k: str(settings.get(k, DEFAULTS[k])) for k in DEFAULTS}
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w") as f:
            json.dump(clean, f, indent=2)
        os.replace(tmp, path)
        return True
    except OSError:
        return False
