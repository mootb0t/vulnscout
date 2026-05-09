"""Legacy ScanState materializer.

The redesigned scanner emits facts. Engagement (phases/engagement.py) is
~3400 lines of mature interactive logic that reads from the old ScanState
dataclass, and rewriting it for the new fact API would be enormous. This
module bridges the two:

  - subscribe to the FactStore
  - on every fact, update the matching ScanState fields
  - engagement consumes the materialized ScanState normally

Engagement's *writes* (confirmed creds added after a hydra hit, etc.)
also get echoed back into the FactStore via `echo_state_change()` so
the report and the LLM analysis still see them.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Tuple

from .facts import (
    Analysis, ConfirmedCred, CrtSh, DNSSEC, DiscoveredCredential,
    DiscoveredHash, DiscoveredHost, DiscoveredUsername, Email, Fact,
    Finding, FormsDetected, FurtherPath, GitExposed, GitHubData, IPAddress,
    IPInfo, InternetDB, IntelSummary, MSFModule, OSGuess, Port,
    ReverseIP, SearchsploitHit, Subdomain, Target, Tech, VersionString,
    WAF, WaybackData, WhoisInfo, WordPressDetected,
)
from .store import FactStore
from ..tools.parser import NmapPort
from ..tools.runner import ScanContext, ScanState

# llm.Finding is the legacy Finding shape engagement and the old report
# expected. Our new core.facts.Finding has the same logical fields but
# a different class — we map between them at materialize time.
from ..llm import Finding as LegacyFinding


def materialize(store: FactStore, profile_key: str = "quick") -> ScanState:
    """Project the entire fact log onto a fresh ScanState dataclass.

    Called once when the engagement screen opens. Engagement gets a
    static snapshot — subsequent fact emissions don't auto-flow into it.
    Use `attach_live_materializer` instead if you want a live view.
    """
    target = store.one("target")
    if target is None:
        return ScanState(target="", target_type="", profile_key=profile_key)

    state = ScanState(
        target=target.target,                  # type: ignore[attr-defined]
        target_type=target.target_type,        # type: ignore[attr-defined]
        profile_key=profile_key,
    )

    _populate_phase1(state, store)
    _populate_phase2(state, store)
    _populate_phase3(state, store)
    _populate_phase4_loot(state, store)
    return state


def _populate_phase1(state: ScanState, store: FactStore) -> None:
    state.ip_addresses = sorted({f.address for f in store.all_of(IPAddress) if f.address})
    state.open_ports = [
        NmapPort(host=p.host, port=p.port, protocol=p.protocol,
                 state="open", service=p.service, product=p.product,
                 version=p.version)
        for p in store.all_of(Port)
    ]
    osg = store.one("os.guess")
    state.os_guess = osg.name if osg else ""           # type: ignore[attr-defined]

    state.subdomains = sorted({s.name for s in store.all_of(Subdomain) if s.name})

    state.osint_emails = sorted({
        e.address for e in store.all_of(Email)
        if e.address and e.found_via != "hunter"
    })
    state.hunter_emails = sorted({
        e.address for e in store.all_of(Email)
        if e.address and e.found_via == "hunter"
    })

    state.technologies = sorted({
        f"{t.name}{(' ' + t.version) if t.version else ''}"
        for t in store.all_of(Tech) if t.name
    })

    waf = store.one("waf")
    state.waf = (waf.name if waf else "") or ""        # type: ignore[attr-defined]

    dnssec = store.one("dnssec")
    state.dnssec_configured = dnssec.configured if dnssec else None  # type: ignore[attr-defined]

    crt = store.one("crtsh")
    state.crtsh_certs = list(crt.certs) if crt else []  # type: ignore[attr-defined]

    idb = store.one("internetdb")
    state.internetdb_data = dict(idb.data) if idb else {}  # type: ignore[attr-defined]

    whois = store.one("whois")
    state.whois_data = dict(whois.data) if whois else {}   # type: ignore[attr-defined]

    ipinfo = store.one("ipinfo")
    state.ipinfo_data = dict(ipinfo.data) if ipinfo else {}  # type: ignore[attr-defined]

    rev = store.one("reverse_ip")
    state.reverse_ip_domains = list(rev.domains) if rev else []  # type: ignore[attr-defined]

    way = store.one("wayback")
    if way is not None:
        state.wayback_total = way.total                  # type: ignore[attr-defined]
        state.wayback_urls = list(way.interesting)       # type: ignore[attr-defined]

    gh = store.one("github")
    if gh is not None:
        state.github_total = gh.total                    # type: ignore[attr-defined]
        state.github_secret_hits = gh.secret_hits        # type: ignore[attr-defined]

    intel = store.one("intel.summary")
    state.intel_summary = intel.text if intel else ""    # type: ignore[attr-defined]


def _populate_phase2(state: ScanState, store: FactStore) -> None:
    from ..core.facts import CVEHit
    state.cve_findings = sorted({c.cve for c in store.all_of(CVEHit) if c.cve})

    # Searchsploit hits as the dict shape the old code expected.
    state.searchsploit_hits = [
        {
            "title": h.title, "edb_id": h.edb_id, "url": h.url,
            "query": h.query, "severity": "MEDIUM", "cves": list(h.cves),
        }
        for h in store.all_of(SearchsploitHit)
    ]

    # has_wordpress: explicit fact OR a Tech fact named 'wordpress'.
    # has_forms: explicit fact (from nikto / katana). Engagement uses these
    # to gate cred-attack actions, so be permissive about how the signal
    # arrives.
    state.has_wordpress = bool(store.has("site.is_wordpress")) or any(
        getattr(t, "name", "").lower() == "wordpress"
        for t in store.all_of(Tech)
    )
    state.has_forms = bool(store.has("site.has_forms"))
    state.msf_modules = [(m.cve, m.module) for m in store.all_of(MSFModule)]

    # Findings projection — split by their producing tool's "phase".
    # Phase-1 producers: the passive-osint + recon set; everything else
    # lands in Phase-2 (scanners). The old UI expected this split for
    # the collapsible sections; the new TUI uses the FactStore directly
    # but report.py still reads the legacy buckets.
    PHASE1_TOOLS = {
        "whois", "internetdb", "ipinfo", "crtsh", "reverse_ip", "hunter",
        "wayback", "github", "theharvester", "subfinder", "dnsrecon",
        "nmap", "masscan", "naabu", "httpx", "whatweb", "wafw00f",
    }
    state.findings_phase1 = []
    state.findings_phase2 = []
    from ..core.facts import Finding as NewFinding
    for f in store.all_of(NewFinding):
        legacy = LegacyFinding(
            severity=f.severity,
            summary=f.summary,
            detail=f.detail,
            tool=f.tool,
            raw=f.raw,
            phase=1 if f.tool in PHASE1_TOOLS else 2,
            category=f.category,
        )
        if legacy.phase == 1:
            state.findings_phase1.append(legacy)
        else:
            state.findings_phase2.append(legacy)

    # tools_run mirrors the old set — derive from the source attr.
    state.tools_run = sorted({f.source for f in store.log() if f.source})


def _populate_phase3(state: ScanState, store: FactStore) -> None:
    a = store.one("analysis")
    state.analysis_text = a.text if a else ""           # type: ignore[attr-defined]


def _populate_phase4_loot(state: ScanState, store: FactStore) -> None:
    state.discovered_usernames = list(store.all_of(DiscoveredUsername))
    state.discovered_hashes = [
        (h.user, h.hash_value, h.hash_type) for h in store.all_of(DiscoveredHash)
    ]
    state.confirmed_creds = [
        (c.user, c.password, c.service) for c in store.all_of(ConfirmedCred)
    ]
    state.discovered_credentials = list(store.all_of(DiscoveredCredential))
    state.discovered_hosts = sorted({h.host for h in store.all_of(DiscoveredHost) if h.host})
    state.discovered_emails = sorted({
        e.address for e in store.all_of(Email)
        if e.address and e.found_via == "file"
    })
    state.further_paths = sorted({p.path for p in store.all_of(FurtherPath) if p.path})
    state.version_strings = sorted({v.text for v in store.all_of(VersionString) if v.text})
    g = store.one("loot.git_exposed")
    state.git_exposed_url = g.url if g else ""          # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Engagement → fact echoing
# ---------------------------------------------------------------------------


async def echo_state_change(store: FactStore, state: ScanState,
                              previous: Dict[str, Any]) -> None:
    """Diff `state` vs `previous`, emit facts for new entries.

    Engagement modifies the state in place when an action confirms a
    credential, scrapes a hash, marks the SSH probe outcome. Call this
    after `await execute_action(...)` returns to keep the FactStore
    canonical for the report and the LLM analysis.

    `previous` is a snapshot taken before the action, e.g. via
    `snapshot_state(state)`.
    """
    prev_creds = set(previous.get("confirmed_creds", ()))
    for cred in state.confirmed_creds:
        if cred not in prev_creds:
            user, pw, svc = cred
            await store.emit(ConfirmedCred(
                user=user, password=pw, service=svc,
                source="engagement",
            ))

    prev_hashes = set(previous.get("discovered_hashes", ()))
    for h in state.discovered_hashes:
        if h not in prev_hashes:
            user, hv, ht = h
            await store.emit(DiscoveredHash(
                user=user, hash_value=hv, hash_type=ht,
                source="engagement",
            ))

    if (state.git_exposed_url
            and state.git_exposed_url != previous.get("git_exposed_url", "")):
        await store.emit(GitExposed(
            url=state.git_exposed_url, source="engagement",
        ))

    # Engagement-produced findings (legacy llm.Finding objects appended to
    # findings_phase4) → fact Findings, so post-exploitation results land in
    # the report and the findings view instead of being lost when the
    # engagement screen closes.
    prev_len = int(previous.get("findings_phase4_len", 0) or 0)
    for lf in state.findings_phase4[prev_len:]:
        await store.emit(Finding(
            severity=(getattr(lf, "severity", "") or "INFO").upper(),
            summary=getattr(lf, "summary", "") or "",
            detail=getattr(lf, "detail", "") or "",
            tool=getattr(lf, "tool", "") or "engagement",
            raw=getattr(lf, "raw", "") or "",
            category=getattr(lf, "category", "") or "",
            source="engagement",
        ))


def snapshot_state(state: ScanState) -> Dict[str, Any]:
    """Capture loot fields into hashable form for echo_state_change."""
    return {
        "confirmed_creds":      tuple(state.confirmed_creds),
        "discovered_hashes":    tuple(state.discovered_hashes),
        "git_exposed_url":      state.git_exposed_url,
        "findings_phase4_len":  len(state.findings_phase4),
    }
