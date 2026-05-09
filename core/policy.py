"""Policy — replaces the old Profile.

A policy declares:

  - which task ids are allowed (tag- and id-level)
  - intensity knobs (nmap flags, nuclei tags, wordlist tier, ...)
  - parallelism cap
  - per-task time budget
  - runtime warnings to surface in the TUI

Profiles only controlled HOW tools ran (flags), with the set of tools
hardcoded in each phase. Now the same Policy object filters the task
graph and provides per-task config.

Tasks read knobs via `policy.knob(task, name, default)` so each task
declares its own knob namespace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class Policy:
    key: str
    label: str
    description: str

    # --- Task selection ------------------------------------------------
    # Tag-level allowlist. Tasks that don't carry any of these tags are
    # excluded. Empty set = no tag filtering.
    allow_tags: Set[str] = field(default_factory=set)
    # Tag-level denylist. Anything tagged with one of these is excluded.
    deny_tags: Set[str] = field(default_factory=set)
    # Task-id-level overrides. allow takes precedence over deny.
    allow_ids: Set[str] = field(default_factory=set)
    deny_ids: Set[str] = field(default_factory=set)

    # --- Knobs ---------------------------------------------------------
    # Free-form per-task config. Tasks read via policy.knob("task.id", "name", default).
    # The intent is to keep each task's tunables in *its own* namespace
    # rather than the flat profile-fields blob the old design had.
    knobs: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # --- Scheduling ----------------------------------------------------
    max_parallel: int = 4
    # Per-task budget (seconds) — tasks that exceed are cancelled.
    # Per-task overrides via knob "timeout_s".
    default_timeout_s: float = 600.0

    # --- UI ------------------------------------------------------------
    runtime_warnings: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def task_allowed(self, task_id: str, tags: Set[str]) -> bool:
        """Decide whether a task with the given id+tags can run."""
        if task_id in self.allow_ids:
            return True
        if task_id in self.deny_ids:
            return False
        if self.allow_tags and not (tags & self.allow_tags):
            return False
        if self.deny_tags and (tags & self.deny_tags):
            return False
        return True

    def knob(self, task_id: str, name: str, default: Any = None) -> Any:
        """Read a per-task knob. Falls back to the policy-wide
        `_default` namespace, then to the supplied default."""
        ns = self.knobs.get(task_id) or {}
        if name in ns:
            return ns[name]
        ns = self.knobs.get("_default") or {}
        return ns.get(name, default)

    def timeout_for(self, task_id: str) -> float:
        return float(self.knob(task_id, "timeout_s", self.default_timeout_s))


# ---------------------------------------------------------------------------
# Built-in policies
# ---------------------------------------------------------------------------
#
# Five named policies (matching the old profile names + 'internal'). The
# point of policies is they're declarative — adding a new tool doesn't
# require touching every profile, and users can build custom policies in
# their config without code changes.


POLICIES: Dict[str, Policy] = {
    "quick": Policy(
        key="quick",
        label="Quick",
        description="Fast scan, top 1000 ports + version detection, minimal noise",
        deny_tags={"loud", "exploitation"},
        max_parallel=4,
        knobs={
            # -sV adds ~10s but is the only way searchsploit gets product
            # /version strings to query against. Without it, exploit-DB
            # hits never surface from nmap data.
            "nmap": {"args": ["--top-ports", "1000", "-sV", "-T4", "-Pn"]},
            # Broadened beyond just "cve" — misconfig + default-login +
            # exposed-panel produce findings most scans actually care about.
            "nuclei": {"tags": ["cve", "misconfig", "exposure",
                                "default-login", "exposed-panel"]},
            "_default": {"wordlist_tier": "common"},
            # theHarvester 4.x dropped google/bing — these are the engines
            # that still work without an API key.
            "theharvester": {"sources": ["crtsh", "hackertarget",
                                          "rapiddns", "duckduckgo",
                                          "otx", "certspotter"]},
        },
    ),
    "full": Policy(
        key="full",
        label="Full",
        description="Balanced: top 5000 ports, version detection, common vulns",
        deny_tags={"exploitation"},
        max_parallel=4,
        knobs={
            "nmap": {"args": ["--top-ports", "5000", "-sV", "-T4", "-Pn", "-O"]},
            "nuclei": {"tags": ["cve", "misconfig", "exposure",
                                "default-login", "exposed-panel",
                                "rce", "sqli", "lfi"]},
            "_default": {"wordlist_tier": "medium"},
            "theharvester": {"sources": ["crtsh", "hackertarget", "rapiddns",
                                          "duckduckgo", "otx", "certspotter",
                                          "dnsdumpster"]},
            "nikto": {"extra_args": ["-Tuning", "x", "-Cgidirs", "all"]},
        },
    ),
    "thorough": Policy(
        key="thorough",
        label="Thorough",
        description="All 65535 ports, every script. Slow.",
        deny_tags={"exploitation"},
        max_parallel=3,
        default_timeout_s=1800.0,
        knobs={
            "nmap": {"args": ["-p-", "-sV", "-T3", "-Pn", "-O", "--script", "vuln"]},
            "nuclei": {"tags": ["all"]},
            "_default": {"wordlist_tier": "big"},
            "theharvester": {"sources": ["crtsh", "hackertarget", "rapiddns",
                                          "duckduckgo", "otx", "certspotter",
                                          "dnsdumpster"]},
            "nikto": {"extra_args": ["-Tuning", "x", "-Cgidirs", "all"]},
        },
    ),
    "stealth": Policy(
        key="stealth",
        label="Stealth",
        description="IDS evasion, decoy scanning. Very slow.",
        deny_tags={"loud", "exploitation"},
        deny_ids={"nikto", "gobuster"},
        max_parallel=2,
        knobs={
            "nmap": {"args": ["-sS", "-T1", "-Pn", "--top-ports", "100",
                              "-D", "RND:10", "--randomize-hosts"]},
            "nuclei": {"tags": ["cve"]},
            "_default": {"wordlist_tier": "common"},
            "theharvester": {"sources": ["dnsdumpster", "crtsh",
                                          "hackertarget", "rapiddns"]},
        },
        runtime_warnings=[
            "Stealth — gobuster and nikto disabled to reduce noise",
            "Decoy IPs (-D RND:10) include real hosts whose IPs end up "
            "in target logs",
        ],
    ),
    "paranoid": Policy(
        key="paranoid",
        label="Paranoid",
        description="Extreme evasion, may take hours.",
        deny_tags={"loud", "exploitation", "fuzzing"},
        deny_ids={"nikto", "gobuster", "ffuf", "nuclei", "sqlmap"},
        max_parallel=1,
        default_timeout_s=3600.0,
        knobs={
            "nmap": {"args": ["-sS", "-T0", "-Pn", "--top-ports", "100",
                              "-D", "RND:5"]},
            "_default": {"wordlist_tier": "common"},
            "theharvester": {"sources": ["dnsdumpster", "crtsh", "hackertarget"]},
        },
        runtime_warnings=[
            "PARANOID — this scan may take hours. Hit Stop if unintended.",
            "-T0 paces probes ~5 minutes apart; a /24 takes many hours",
        ],
    ),
    "internal": Policy(
        key="internal",
        label="Internal / assume-breach",
        description=(
            "Internal-network engagement: skip public OSINT, full port "
            "range, AD-focused probes."
        ),
        deny_tags={"public-osint"},
        max_parallel=4,
        knobs={
            "nmap": {"args": ["-sS", "--top-ports", "10000", "-sV", "-T4",
                              "-Pn", "-O", "--script",
                              "default,vuln,smb-os-discovery,"
                              "smb2-security-mode,ldap-rootdse,"
                              "krb5-enum-users,ipp-info"]},
            "nuclei": {"tags": ["cve", "misconfig", "exposure",
                                "default-login", "exposed-panel", "rce"]},
            "_default": {"wordlist_tier": "medium"},
            "theharvester": {"sources": []},   # no public OSINT
            "nikto": {"extra_args": ["-Tuning", "x"]},
        },
        runtime_warnings=[
            "Internal — Phase-1 public-OSINT tasks are skipped; AD-focused "
            "follow-ups surface in engagement when AD ports are detected.",
        ],
    ),
}


POLICY_ORDER = ["quick", "full", "thorough", "stealth", "paranoid", "internal"]


def get_policy(key: str) -> Policy:
    return POLICIES.get(key, POLICIES["quick"])


# ---------------------------------------------------------------------------
# Common port classification (kept here so adding a port is one edit)
# ---------------------------------------------------------------------------

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8081}
HTTPS_PORTS = {443, 8443}
SMB_PORTS = {139, 445}
AD_PORTS = {88, 389, 636, 3268, 3269, 5985, 5986}
PRINTER_PORTS = {631, 9100}
