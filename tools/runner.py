"""Subprocess orchestration shared across phases.

Public API:
  - PhaseEvent  : the only thing phase generators emit upward
  - ScanState   : everything we learn during a scan, carried across phases
  - ScanContext : ScanState + cancellation hooks + active subprocess refs
  - stream(...) : non-blocking subprocess line streamer
  - adapt_nmap_args(...) : privilege-aware flag rewriter
  - INSECURE_TLS_ENV : SSL-bypass env merged in for web-chain tools
  - running_as_root() : POSIX root check

This file deliberately doesn't know about LLMs, profiles, or specific
tool runners — those live in phases/. Keeping that boundary tight makes
it easy to test the streaming pipe in isolation.
"""

import asyncio
import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Optional, Set, Tuple

from ..opsec import OpsecSettings, apply_to_command, random_delay
from .parser import NmapPort


# ----------------------------------------------------------------------
# Events
# ----------------------------------------------------------------------


@dataclass
class PhaseEvent:
    """One unit of progress emitted by a phase generator.

    `kind` drives UI styling:
      - 'tool_start' : a tool kicked off (text = command line)
      - 'output'     : a line of streaming tool output
      - 'progress'   : nmap/masscan progress (carries percent + etc)
      - 'status'     : a high-level milestone
      - 'warning'    : something missing or degraded
      - 'finding'    : a structured Finding (carried in `finding`)
      - 'phase_done' : phase finished cleanly
    """

    kind: str
    text: str = ""
    tool: str = ""
    finding: Optional["Finding"] = None  # forward ref — resolved at runtime
    severity_hint: str = ""
    percent: float = 0.0
    etc: str = ""
    phase: int = 0  # which phase emitted this (1/2/3)


# ----------------------------------------------------------------------
# State
# ----------------------------------------------------------------------


@dataclass
class ScanState:
    """Snapshot of everything we learned during a scan. Survives across
    phases — Phase 2 reads what Phase 1 collected, Phase 3 reads both."""

    target: str
    target_type: str
    profile_key: str

    # Phase tracking — completed_phases is what gates the Run button.
    completed_phases: Set[int] = field(default_factory=set)
    phase_durations: Dict[int, float] = field(default_factory=dict)

    # ---- Phase 1 outputs ----
    nmap_xml: str = ""
    open_ports: List[NmapPort] = field(default_factory=list)
    os_guess: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    osint_emails: List[str] = field(default_factory=list)
    osint_hosts: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    waf: str = ""
    dnssec_configured: Optional[bool] = None
    live_hosts: List[str] = field(default_factory=list)  # masscan
    crtsh_certs: List[str] = field(default_factory=list)
    internetdb_data: dict = field(default_factory=dict)
    # Extended passive-intel collectors
    whois_data: Dict[str, str] = field(default_factory=dict)         # registrant/org/ns/dates
    ipinfo_data: Dict[str, str] = field(default_factory=dict)        # asn/org/city/country
    reverse_ip_domains: List[str] = field(default_factory=list)      # other domains on same IP
    hunter_emails: List[str] = field(default_factory=list)           # hunter.io results
    wayback_urls: List[str] = field(default_factory=list)            # interesting wayback URLs
    wayback_total: int = 0                                           # total archive count
    github_total: int = 0                                            # github code-search hits
    github_secret_hits: int = 0                                      # results mentioning secrets
    org_name: str = ""                                               # derived for social hints
    intel_summary: str = ""

    # ---- Phase 2 outputs ----
    cve_findings: List[str] = field(default_factory=list)
    has_wordpress: bool = False
    has_forms: bool = False
    msf_modules: List[Tuple[str, str]] = field(default_factory=list)  # (cve, module)
    # Structured searchsploit hits — each dict is
    # `{title, edb_id, url, query, severity, cves}`. Distinct from
    # `cve_findings` (CVEs only): hits without a CVE in the title still
    # land here so the engagement queue can surface manual-exploit
    # actions for every HIGH/CRITICAL exploit regardless of CVE coverage.
    searchsploit_hits: List[dict] = field(default_factory=list)
    screenshots_dir: str = ""

    # ---- Phase 3 output ----
    analysis_text: str = ""

    # ---- Phase 4 (Engagement) state ----
    # Usernames harvested from fetched file content (Phase 2). Stored as
    # `DiscoveredUsername(name, source_file, confidence)` tuples — see
    # `phases.engagement.DiscoveredUsername`. Confidence-weighted so the
    # cred-attack generator can prefer high-signal hits and the intel
    # summary can show provenance.
    discovered_usernames: List = field(default_factory=list)
    # NTLM-style hashes harvested from fetched files (Phase 2) — feeds the
    # pass-the-hash action. Each tuple is (user, hash, type) where `type`
    # is "ntlm" / "lm" / "nthash" depending on the SAM-line shape.
    discovered_hashes: List[Tuple[str, str, str]] = field(default_factory=list)
    # Confirmed credentials — populated by `_followups_from_output` when
    # a hydra hit is observed. Each tuple is (user, password, service)
    # where service is "ssh" | "smb" | "ftp" | etc. Drives the cred-flow
    # actions (kerberoast, BloodHound, secretsdump, wmiexec, post-exploit).
    confirmed_creds: List[Tuple[str, str, str]] = field(default_factory=list)
    # SSH probe outcome — gates SSH brute-force. None = probe hasn't run
    # (so we don't know what auth is supported and won't queue brute);
    # True = server accepts password auth (brute-force is viable);
    # False = pubkey-only or other non-passwordable auth (skip brute).
    ssh_password_auth_confirmed: Optional[bool] = None
    # When discovery confirmed a `/.git/` directory is exposed (HEAD or
    # config returned 200), the parent URL lands here so the gitleaks
    # action can clone+scan it. Empty string means nothing exposed yet.
    git_exposed_url: str = ""
    # Internal hosts / IPs surfaced from fetched file content (Phase 2
    # file discovery). RFC1918 + carrier-grade-NAT + link-local. Used
    # by the report and by future pivot-aware actions.
    discovered_hosts: List[str] = field(default_factory=list)
    # Email addresses from fetched files — distinct from osint_emails
    # which comes from theHarvester / hunter.io OSINT. Both feed the
    # cred-attack username generator (via local-part extraction).
    discovered_emails: List[str] = field(default_factory=list)
    # URL paths surfaced from fetched files (links, references in
    # configs / robots.txt / sitemap.xml). Queued for follow-up ffuf
    # passes; also visible in the report.
    further_paths: List[str] = field(default_factory=list)
    # Software version strings from fetched files (`Drupal 9.5.1`,
    # `Spring 5.3.20`, ...). Fed to searchsploit on the next Phase 2
    # CVE-cross-reference pass.
    version_strings: List[str] = field(default_factory=list)
    # Credentials / secrets harvested from fetched file content.
    # See `phases.engagement.DiscoveredCredential` — each entry holds
    # the raw value (never displayed verbatim), source file, the
    # matching line truncated to 80 chars, and an `is_critical` flag
    # for CRITICAL_PATTERNS (private keys, AWS keys, OAuth tokens, ...)
    # which forces the emitting Finding to CRITICAL.
    discovered_credentials: List = field(default_factory=list)
    # Action queue + execution timeline. Both are populated by Phase 4
    # interactively; nothing here runs without explicit user confirmation.
    engagement_actions: List = field(default_factory=list)   # List[EngagementAction]
    engagement_log: List = field(default_factory=list)       # List[EngagementLogEntry]

    # Findings bucket per phase — drives the collapsible UI sections.
    findings_phase1: List = field(default_factory=list)
    findings_phase2: List = field(default_factory=list)
    findings_phase3: List = field(default_factory=list)
    findings_phase4: List = field(default_factory=list)

    # Tool exec log (deduplicated) — used by the report.
    tools_run: List[str] = field(default_factory=list)

    # Temp files we created on behalf of engagement actions (e.g. user
    # lists for hydra). Cleaned up on Reset.
    engagement_tmpfiles: List[str] = field(default_factory=list)


@dataclass
class ScanContext:
    """Carried through every phase. Holds running subprocesses for the
    Stop button / quit-confirmation flow."""

    state: ScanState
    procs: List[asyncio.subprocess.Process] = field(default_factory=list)
    cancelled: bool = False

    # Optional settings the runner picks up. Nothing here changes
    # *what* runs — just where it looks.
    gobuster_wordlist: Optional[str] = None
    nuclei_templates_dir: Optional[str] = None
    enable_local_tools: bool = False
    hunter_api_key: str = ""
    # OPSEC knobs — applied centrally by stream(). Default is a no-op
    # (every toggle off) so existing call sites stay correct.
    opsec: OpsecSettings = field(default_factory=OpsecSettings)

    def cancel(self) -> None:
        """SIGKILL every active subprocess and flag the scan as cancelled."""
        self.cancelled = True
        for p in list(self.procs):
            if p.returncode is None:
                try:
                    p.kill()
                except ProcessLookupError:
                    pass


# ----------------------------------------------------------------------
# SSL bypass env
# ----------------------------------------------------------------------
#
# Pentest targets routinely use self-signed certificates — internal tools,
# dev environments, routers, older appliances. The web-chain tools default
# to strict cert verification and bail before doing useful work, so we
# inject env vars that disable verification at the language-runtime level.
#
# This is intentional and standard for pentest tooling: we're scanning
# systems the user owns or has authorization to test, not browsing the web.

INSECURE_TLS_ENV: Dict[str, str] = {
    "PERL_LWP_SSL_VERIFY_HOSTNAME": "0",   # Perl LWP::UserAgent (nikto)
    "PYTHONHTTPSVERIFY":            "0",   # Python stdlib urllib
    "REQUESTS_CA_BUNDLE":           "",    # Python requests (wafw00f)
    "CURL_CA_BUNDLE":               "",    # curl-based tools
    "SSL_CERT_FILE":                "",    # OpenSSL fallback
}


# ----------------------------------------------------------------------
# Subprocess streaming
# ----------------------------------------------------------------------


async def stream(
    ctx: ScanContext,
    tool: str,
    cmd: List[str],
    env_overrides: Optional[Dict[str, str]] = None,
) -> AsyncIterator[str]:
    """Spawn `cmd` and yield merged stdout/stderr lines as they arrive.

    `env_overrides` is merged on top of the current process environment —
    used for SSL-bypass + Shodan API key injection. Returns silently if
    cancelled or the binary disappears mid-flight.
    """
    if ctx.cancelled:
        return
    if tool not in ctx.state.tools_run:
        ctx.state.tools_run.append(tool)

    env = None
    if env_overrides:
        env = {**os.environ, **env_overrides}

    # Inter-tool delay — applied before launch so the throttle accounts
    # for any tor/proxychains setup time afterwards. Cancellation is
    # checked again post-sleep because a long delay can outlive a Stop.
    await random_delay(ctx.opsec)
    if ctx.cancelled:
        return

    cmd = apply_to_command(tool, list(cmd), ctx.opsec)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
    except FileNotFoundError:
        return

    ctx.procs.append(proc)
    try:
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            yield line.decode(errors="replace").rstrip()
            if ctx.cancelled:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                break
        await proc.wait()
    finally:
        if proc in ctx.procs:
            ctx.procs.remove(proc)


# ----------------------------------------------------------------------
# nmap arg adapter (privilege-aware)
# ----------------------------------------------------------------------


_NMAP_SCAN_TYPE_FLAGS = {"-sS", "-sT", "-sU", "-sA", "-sN", "-sF", "-sX", "-sY"}


def running_as_root() -> bool:
    """True iff effective UID 0. False on Windows or when probing fails."""
    try:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False


_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


def is_rfc1918(ip: str) -> bool:
    """True if the address is private/loopback/link-local (not a public internet IP)."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return False


def adapt_nmap_args(
    extra_args: List[str], is_root: bool, target_ip: str = ""
) -> Tuple[List[str], List[str]]:
    """Adjust profile-supplied nmap flags so the scan actually returns
    results on the current privilege level.

    Three concrete fixes:

      1. Insert `-Pn` if not present. nmap's default ICMP host discovery
         marks firewalled hosts as down and skips port scanning entirely.

      2. If not root, swap `-sS` for `-sT`. SYN scans need raw sockets;
         without root nmap aborts producing no results.

      3. If not root, drop `-O` (OS detection) and `-D ... ` (decoys).
         Both need raw sockets; including them unprivileged just produces
         warnings + slower scans without the intended effect.

    Returns (adapted_args, notes) where notes is a list of human-readable
    messages the caller surfaces to the live feed.
    """
    args = list(extra_args)
    notes: List[str] = []

    has_scan_type = any(a in _NMAP_SCAN_TYPE_FLAGS for a in args)

    is_external = bool(target_ip) and not is_rfc1918(target_ip)

    if not is_root:
        if "-sS" in args:
            args[args.index("-sS")] = "-sT"
            external_note = (
                f" (external target {target_ip})" if is_external else ""
            )
            notes.append(
                f"replaced -sS with -sT{external_note} — SYN scan needs raw "
                "sockets (root); TCP connect scan used instead"
            )
        elif not has_scan_type:
            args.insert(0, "-sT")
            if is_external:
                notes.append(
                    f"external target ({target_ip}), unprivileged — "
                    "inserting -sT (TCP connect); -sS would silently fail without root"
                )
            else:
                notes.append(
                    "running as unprivileged user, inserting -sT (TCP connect scan)"
                )

        if "-O" in args:
            args.remove("-O")
            notes.append("removed -O (OS detection) — requires sudo")

        if "-D" in args:
            idx = args.index("-D")
            if idx + 1 < len(args):
                del args[idx:idx + 2]
            else:
                del args[idx]
            notes.append("removed -D (decoy scan) — requires sudo for raw sockets")

        # External + unprivileged: TCP-connect scans through ISP NAT and
        # cloud egress paths get rate-limited at -T4/-T5; drop to -T3 so
        # the scan actually completes. --reason makes the difference
        # between filtered and closed visible in stdout/XML.
        if is_external:
            for fast in ("-T4", "-T5"):
                if fast in args:
                    args[args.index(fast)] = "-T3"
                    notes.append(
                        f"replaced {fast} with -T3 — external unprivileged "
                        "scans get rate-limited at -T4/-T5"
                    )
                    break
            if not any(a.startswith("-T") for a in args):
                args.insert(0, "-T3")
                notes.append(
                    "external unprivileged scan — added -T3 for reliability"
                )
            if "--host-timeout" not in args:
                args += ["--host-timeout", "120s"]
                notes.append(
                    "added --host-timeout 120s — caps per-host time on "
                    "unresponsive external hosts"
                )
            if "--reason" not in args:
                args.append("--reason")
                notes.append(
                    "added --reason — annotates each port with why nmap "
                    "decided open/filtered/closed"
                )
    else:
        if not has_scan_type:
            args.insert(0, "-sS")

    if "-Pn" not in args:
        args.append("-Pn")

    return args, notes


# ----------------------------------------------------------------------
# nmap progress-line parsing
# ----------------------------------------------------------------------
#
# nmap emits progress lines when run with `--stats-every`. We parse them
# in the runner so the UI gets a single ScanEvent kind per progress
# update without each phase having to re-implement the regex.

_NMAP_PROGRESS_RE = re.compile(r"About\s+([\d.]+)%\s+done;\s+ETC:\s+(\d+:\d+)")
_NMAP_STATS_RE = re.compile(r"^Stats:\s")


def parse_nmap_progress(line: str) -> Optional[Tuple[float, str]]:
    """Return (percent, etc) for a timing-progress line, else None."""
    m = _NMAP_PROGRESS_RE.search(line)
    if not m:
        return None
    try:
        return float(m.group(1)), m.group(2)
    except ValueError:
        return None


def is_nmap_stats_line(line: str) -> bool:
    """True for any nmap heartbeat/progress line (so we can dim them)."""
    return bool(_NMAP_STATS_RE.match(line)) or bool(_NMAP_PROGRESS_RE.search(line))
