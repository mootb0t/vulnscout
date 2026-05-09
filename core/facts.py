"""Typed fact records emitted into the FactStore.

Every piece of intelligence learned during a scan is a Fact. Tasks consume
facts (via their `requires` set) and produce new facts. The fact log is
append-only and provenance-tracked: each Fact carries the id of the task
that emitted it and the ids of the parent facts that triggered it.

Why typed Facts instead of a dict-of-everything (the old `ScanState`):

  - Tasks declare which kinds they consume — the scheduler can statically
    plan the DAG and detect missing producers.
  - Provenance is for free. Asking "why did wpscan run?" walks `parents`
    back to the WhatWebTech fact that mentioned wordpress.
  - Reports synthesize from the fact log instead of stitching ad-hoc
    fields named `discovered_*` / `findings_phaseN`.
  - Adding a new fact type doesn't require touching every consumer — only
    the consumers that care opt in via `requires`.

Severity for findings is still derived deterministically (see severity.py).
The LLM never grades severity; it only summarises.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# Severity ranking used to sort findings in UI and reports.
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


_id_counter = itertools.count(1)


def _next_id() -> int:
    return next(_id_counter)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


@dataclass
class Fact:
    """One unit of intelligence in the scan.

    Subclasses add typed payload fields. All facts share:
      - kind     : registry-stable string (e.g. "port.open", "tech")
      - id       : monotonically-increasing int unique within a run
      - source   : the task name that produced this fact
      - parents  : ids of facts that triggered the producing task. Empty
                   for seed facts (Target).
      - ts       : wall-clock time the fact was created.
    """

    kind: str = ""
    id: int = field(default_factory=_next_id)
    source: str = ""
    parents: Tuple[int, ...] = ()
    ts: float = field(default_factory=time.time)

    def trace(self, store: "FactStoreLike") -> List["Fact"]:
        """Walk parents recursively. Useful for "why did this run?"."""
        seen: Dict[int, Fact] = {}
        stack: List[int] = list(self.parents)
        while stack:
            pid = stack.pop()
            if pid in seen:
                continue
            f = store.by_id(pid)
            if f is None:
                continue
            seen[pid] = f
            stack.extend(f.parents)
        return sorted(seen.values(), key=lambda f: f.id)


class FactStoreLike:
    """Minimal protocol used by Fact.trace — broken out so facts.py
    has no import cycle with store.py."""

    def by_id(self, fact_id: int) -> Optional[Fact]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Seed / target facts
# ---------------------------------------------------------------------------


@dataclass
class Target(Fact):
    """The seed fact for every scan. One per run.

    `target_type` is one of: "ip" / "cidr" / "domain" / "url"
    `domain` is the bare hostname extracted from URL targets, otherwise
    equal to target for ip/cidr.
    """

    kind: str = "target"
    target: str = ""
    target_type: str = "domain"
    domain: str = ""


# ---------------------------------------------------------------------------
# Network facts
# ---------------------------------------------------------------------------


@dataclass
class IPAddress(Fact):
    kind: str = "ip"
    address: str = ""


@dataclass
class HostUp(Fact):
    """A host that responded to discovery (masscan / naabu / nmap ping)."""

    kind: str = "host.up"
    host: str = ""


@dataclass
class Port(Fact):
    """An open port. Most-common consumed kind in the system."""

    kind: str = "port.open"
    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    service: str = ""        # nmap-detected service label (http, ssh, ...)
    product: str = ""        # software product (nginx, OpenSSH, ...)
    version: str = ""        # version string when banner-detectable

    @property
    def is_http(self) -> bool:
        return self.service in {"http", "https", "http-proxy"} or self.port in {
            80, 443, 8080, 8443, 8000, 8888, 8081
        }

    @property
    def is_https(self) -> bool:
        return self.service == "https" or self.port in {443, 8443}

    def url(self) -> str:
        scheme = "https" if self.is_https else "http"
        return f"{scheme}://{self.host}:{self.port}"


@dataclass
class OSGuess(Fact):
    kind: str = "os.guess"
    name: str = ""


# ---------------------------------------------------------------------------
# DNS / OSINT facts
# ---------------------------------------------------------------------------


@dataclass
class Subdomain(Fact):
    kind: str = "subdomain"
    name: str = ""


@dataclass
class WhoisInfo(Fact):
    kind: str = "whois"
    data: Dict[str, str] = field(default_factory=dict)


@dataclass
class IPInfo(Fact):
    kind: str = "ipinfo"
    data: Dict[str, str] = field(default_factory=dict)


@dataclass
class Email(Fact):
    kind: str = "email"
    address: str = ""
    found_via: str = ""   # "theharvester" | "hunter" | "file" | ...


@dataclass
class WaybackData(Fact):
    """Aggregate fact for a wayback sweep — total + interesting URLs."""

    kind: str = "wayback"
    total: int = 0
    interesting: List[str] = field(default_factory=list)


@dataclass
class GitHubData(Fact):
    kind: str = "github"
    total: int = 0
    secret_hits: int = 0


@dataclass
class InternetDB(Fact):
    """Shodan InternetDB hit for the target IP."""

    kind: str = "internetdb"
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReverseIP(Fact):
    """Other domains hosted on the same IP."""

    kind: str = "reverse_ip"
    domains: List[str] = field(default_factory=list)


@dataclass
class CrtSh(Fact):
    """Cert-transparency-derived subdomain set. Aggregate fact."""

    kind: str = "crtsh"
    certs: List[str] = field(default_factory=list)


@dataclass
class DNSSEC(Fact):
    kind: str = "dnssec"
    configured: Optional[bool] = None


# ---------------------------------------------------------------------------
# Web / fingerprint facts
# ---------------------------------------------------------------------------


@dataclass
class Tech(Fact):
    """A technology fingerprint (whatweb / httpx / nuclei tech-detect)."""

    kind: str = "tech"
    name: str = ""              # e.g. "WordPress", "Nginx", "PHP"
    version: str = ""           # may be empty
    on_url: str = ""            # the URL where it was observed


@dataclass
class WAF(Fact):
    kind: str = "waf"
    name: str = ""              # vendor name, or "" if none
    on_url: str = ""


@dataclass
class HTTPLive(Fact):
    """A confirmed-live HTTP(S) endpoint. httpx-style."""

    kind: str = "http.live"
    url: str = ""
    status: int = 0
    title: str = ""


@dataclass
class FormsDetected(Fact):
    """Site has forms — feeds sqlmap auto-trigger."""

    kind: str = "site.has_forms"
    url: str = ""


@dataclass
class WordPressDetected(Fact):
    """Site is WordPress — feeds wpscan auto-trigger."""

    kind: str = "site.is_wordpress"
    on_url: str = ""


# ---------------------------------------------------------------------------
# Vulnerability / finding facts
# ---------------------------------------------------------------------------


@dataclass
class Finding(Fact):
    """A user-facing finding. Drives the findings panel + the report.

    severity is one of CRITICAL / HIGH / MEDIUM / LOW / INFO, derived
    deterministically by the producing task (never the LLM).
    """

    kind: str = "finding"
    severity: str = "INFO"
    summary: str = ""           # one-sentence headline
    detail: str = ""            # longer paragraph (optional)
    tool: str = ""              # tool that produced it (nuclei, nikto, …)
    raw: str = ""               # raw output snippet (truncated)
    category: str = ""          # optional sub-header ("EXPOSURE", …)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity.upper(), 4)


@dataclass
class CVEHit(Fact):
    """A specific CVE referenced by some tool's output."""

    kind: str = "cve"
    cve: str = ""
    on: str = ""              # what it applies to ("nginx 1.18.0", ...)


@dataclass
class SearchsploitHit(Fact):
    kind: str = "searchsploit"
    title: str = ""
    edb_id: str = ""
    url: str = ""
    query: str = ""           # what fingerprint produced this hit
    cves: List[str] = field(default_factory=list)


@dataclass
class MSFModule(Fact):
    """A Metasploit module that targets a known CVE."""

    kind: str = "msf"
    cve: str = ""
    module: str = ""


# ---------------------------------------------------------------------------
# Loot / engagement facts
# ---------------------------------------------------------------------------


@dataclass
class DiscoveredUsername(Fact):
    kind: str = "loot.username"
    username: str = ""
    source_file: str = ""
    confidence: float = 0.5


@dataclass
class DiscoveredHash(Fact):
    kind: str = "loot.hash"
    user: str = ""
    hash_value: str = ""
    hash_type: str = ""       # ntlm | lm | nthash | ...


@dataclass
class DiscoveredCredential(Fact):
    """A secret string lifted from a fetched file (.env, config, ...).

    Value is stored verbatim — operators own the report. The TUI/report
    use truncated_value() for display.
    """

    kind: str = "loot.credential"
    label: str = ""
    value: str = ""
    source_file: str = ""
    line_context: str = ""
    is_critical: bool = False

    def truncated_value(self) -> str:
        """Display form: first 4 chars + asterisks."""
        v = self.value
        if not v:
            return ""
        if len(v) <= 4:
            return "****"
        return v[:4] + "*" * min(8, len(v) - 4)


@dataclass
class ConfirmedCred(Fact):
    """A credential confirmed by a successful login."""

    kind: str = "loot.confirmed_cred"
    user: str = ""
    password: str = ""
    service: str = ""         # ssh | smb | ftp | ...


@dataclass
class DiscoveredHost(Fact):
    """RFC1918 / link-local / *.internal host extracted from leaked files."""

    kind: str = "loot.host"
    host: str = ""


@dataclass
class VersionString(Fact):
    """Software version extracted from leaked files.

    Feeds a follow-up searchsploit pass — Phase 1 may have missed these
    because they live in package manifests rather than HTTP banners.
    """

    kind: str = "loot.version"
    text: str = ""
    source_file: str = ""


@dataclass
class FurtherPath(Fact):
    """URL path discovered in fetched file content; candidate for ffuf."""

    kind: str = "loot.path"
    path: str = ""
    source_file: str = ""


@dataclass
class GitExposed(Fact):
    """A `.git/` directory confirmed reachable on the target."""

    kind: str = "loot.git_exposed"
    url: str = ""


# ---------------------------------------------------------------------------
# Synthesis facts
# ---------------------------------------------------------------------------


@dataclass
class ScanSettled(Fact):
    """Emitted by the scheduler when the task queue has drained and no
    more tasks are running. Synthesis tasks (intel summary, analysis)
    trigger on this so they run with the full fact log available.

    The scheduler may emit this multiple times if a synthesis task
    queues new work — each emission is followed by another drain pass,
    and ScanFinished only goes out when no fact emitted during the
    settled phase produced new work.
    """

    kind: str = "scan.settled"


@dataclass
class IntelSummary(Fact):
    """Plain-text Phase-1 handoff block. One per scan."""

    kind: str = "intel.summary"
    text: str = ""


@dataclass
class Analysis(Fact):
    """Top-level LLM-synthesized analysis (3-section). One per scan."""

    kind: str = "analysis"
    text: str = ""


# ---------------------------------------------------------------------------
# Ergonomic kind constants
# ---------------------------------------------------------------------------
#
# Tasks declare requires={"port.open"} etc. Using string constants keeps
# the matching logic dead simple (set membership) without forcing every
# consumer to import the dataclass. Listed here for reference + IDE
# autocompletion.

K_TARGET            = "target"
K_IP                = "ip"
K_HOST_UP           = "host.up"
K_PORT              = "port.open"
K_OS                = "os.guess"
K_SUBDOMAIN         = "subdomain"
K_WHOIS             = "whois"
K_IPINFO            = "ipinfo"
K_EMAIL             = "email"
K_WAYBACK           = "wayback"
K_GITHUB            = "github"
K_INTERNETDB        = "internetdb"
K_REVERSE_IP        = "reverse_ip"
K_CRTSH             = "crtsh"
K_DNSSEC            = "dnssec"
K_TECH              = "tech"
K_WAF               = "waf"
K_HTTP_LIVE         = "http.live"
K_HAS_FORMS         = "site.has_forms"
K_IS_WORDPRESS      = "site.is_wordpress"
K_FINDING           = "finding"
K_CVE               = "cve"
K_SEARCHSPLOIT      = "searchsploit"
K_MSF               = "msf"
K_SCAN_SETTLED      = "scan.settled"
K_INTEL_SUMMARY     = "intel.summary"
K_ANALYSIS          = "analysis"
K_LOOT_USERNAME     = "loot.username"
K_LOOT_HASH         = "loot.hash"
K_LOOT_CREDENTIAL   = "loot.credential"
K_LOOT_CONFIRMED    = "loot.confirmed_cred"
K_LOOT_HOST         = "loot.host"
K_LOOT_VERSION      = "loot.version"
K_LOOT_PATH         = "loot.path"
K_LOOT_GIT          = "loot.git_exposed"
