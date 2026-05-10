"""LLM-assisted summarisers.

Two synthesisers:

  - intel_summary  : projects all Phase-1-equivalent facts into a single
                     plain-text block, the same format Phase 2/3 used to
                     consume. Deterministic — no LLM.
  - analysis       : feeds intel_summary + findings + loot to the LLM
                     for the three-section "attack angles / confirming
                     conditions / next steps" prose. Falls back to a
                     deterministic rollup when the LLM is unreachable.

Both run "once" with a soft trigger: the scheduler queues them on the
first findng/finding-ish fact, and they pull whatever the store knows
at run time. Since the scheduler keeps the loop alive while there's
running work, in practice they run after the bulk of tasks finish.
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

from ..core.facts import (
    Analysis, ConfirmedCred, CrtSh, DNSSEC, DiscoveredCredential, Email,
    Finding, GitHubData, IntelSummary, IPAddress, IPInfo, OSGuess, Port,
    ReverseIP, Subdomain, Tech, Target, WAF, WaybackData, WhoisInfo,
)
from ..core.tasks import Task, TaskCtx, register
from ..llm import LLMClient


# ---------------------------------------------------------------------------
# Intel summary (deterministic projection)
# ---------------------------------------------------------------------------


def _build_intel_text(store) -> str:
    """Reduce the fact store to the plain-text Phase-1 handoff block.

    Mirrors the format the old `tools.parser.format_intel_summary` produced
    so prompts and reports stay stable across the redesign.
    """
    target = store.one("target")
    if target is None:
        return ""
    tname = target.target

    ips = [f.address for f in store.all_of(IPAddress) if f.address]
    if ips:
        if len(ips) == 1:
            tname += f" ({ips[0]})"
        else:
            tname += f" ({', '.join(ips[:5])})"

    lines = [f"TARGET: {tname}"]

    os_guess = store.one("os.guess")
    lines.append(f"OS: {os_guess.name if os_guess else 'unknown'}")  # type: ignore[attr-defined]

    ports = store.all_of(Port)
    if ports:
        bits = []
        for p in ports:
            label = f"{p.port} ({p.service.upper() if p.service else 'unknown'})"
            if p.product:
                label = f"{p.port} ({p.service.upper() if p.service else ''} — {p.product}{(' ' + p.version) if p.version else ''})"
            bits.append(label)
        lines.append("OPEN PORTS: " + ", ".join(bits))
    else:
        lines.append("OPEN PORTS: none detected")

    subs = sorted({s.name for s in store.all_of(Subdomain) if s.name})
    if subs:
        sample = ", ".join(subs[:20])
        extra = f" (+{len(subs) - 20} more)" if len(subs) > 20 else ""
        lines.append(f"SUBDOMAINS: {sample}{extra}")
    else:
        lines.append("SUBDOMAINS: none found")

    techs = sorted({f"{t.name}{(' ' + t.version) if t.version else ''}"
                     for t in store.all_of(Tech) if t.name})
    lines.append("TECHNOLOGIES: " + (", ".join(techs) if techs else "unknown"))

    waf = store.one("waf")
    lines.append(f"WAF: {(waf.name if waf and waf.name else 'none detected')}")  # type: ignore[attr-defined]

    dnssec = store.one("dnssec")
    if dnssec is None:
        lines.append("DNSSEC: unknown")
    else:
        lines.append(f"DNSSEC: {'configured' if dnssec.configured else 'not configured'}")  # type: ignore[attr-defined]

    whois = store.one("whois")
    if whois is not None:
        bits = []
        for k in ("registrant", "org", "email", "created", "expires"):
            v = whois.data.get(k)  # type: ignore[attr-defined]
            if v:
                bits.append(f"{k}={v}")
        if bits:
            lines.append("WHOIS: " + ", ".join(bits))

    ipinfo = store.one("ipinfo")
    if ipinfo is not None:
        bits = []
        for k in ("asn", "org", "city", "country", "hostname"):
            v = ipinfo.data.get(k)  # type: ignore[attr-defined]
            if v:
                bits.append(f"{k}={v}")
        if bits:
            lines.append("IPINFO: " + ", ".join(bits))

    rev = store.one("reverse_ip")
    if rev is not None:
        n = len(rev.domains)  # type: ignore[attr-defined]
        if n:
            sample = ", ".join(rev.domains[:5])  # type: ignore[attr-defined]
            extra = f" (+{n - 5} more)" if n > 5 else ""
            lines.append(f"REVERSE IP: {n} other domain(s) — {sample}{extra}")

    hunter_emails = [e.address for e in store.all_of(Email) if e.found_via == "hunter"]
    if hunter_emails:
        sample = ", ".join(hunter_emails[:5])
        extra = f" (+{len(hunter_emails) - 5} more)" if len(hunter_emails) > 5 else ""
        lines.append(f"HUNTER.IO: {len(hunter_emails)} email(s) — {sample}{extra}")

    way = store.one("wayback")
    if way is not None:
        lines.append(
            f"WAYBACK: {way.total} historical URL(s), "  # type: ignore[attr-defined]
            f"{len(way.interesting)} potentially interesting"
        )

    gh = store.one("github")
    if gh is not None and gh.total:  # type: ignore[attr-defined]
        sec_note = (f" — {gh.secret_hits} mention secrets/keys/tokens"  # type: ignore[attr-defined]
                    if gh.secret_hits else "")
        lines.append(f"GITHUB: {gh.total} code result(s){sec_note}")

    return "\n".join(lines)


async def _run_intel_summary(ctx: TaskCtx) -> None:
    text = _build_intel_text(ctx.store)
    if not text.strip():
        return
    await ctx.emit(IntelSummary(text=text))


register(Task(
    id="intel_summary",
    label="intel summary",
    run=_run_intel_summary,
    # Triggers on scan.settled — by then every intel-class task has had a
    # chance to emit, so the projected text reflects the full picture.
    requires={"scan.settled"},
    produces={"intel.summary"},
    tags={"core"},
))


# ---------------------------------------------------------------------------
# Analysis (LLM)
# ---------------------------------------------------------------------------


def _findings_block(store) -> str:
    out = []
    for f in store.findings():
        out.append(f"[{f.severity}] {f.tool}: {f.summary}")  # type: ignore[attr-defined]
    return "\n".join(out)


def _loot_block(store) -> str:
    """Plain-text inventory of pivot data to feed the LLM.

    Verbatim values are kept — the operator owns the report. The TUI/MD
    renderer truncates for display, but the LLM needs the full strings
    so it can reason about which credential goes where.
    """
    bits: List[str] = []
    creds = store.all_of(ConfirmedCred)
    if creds:
        bits.append("Confirmed credentials:")
        for c in creds[:10]:
            bits.append(f"  - {c.user}:{c.password} ({c.service})")
    secs = [c for c in store.all_of(DiscoveredCredential) if c.is_critical]
    if secs:
        bits.append("Critical secrets discovered in fetched files:")
        for c in secs[:10]:
            bits.append(f"  - {c.label}: {c.value} (in {c.source_file})")
    from ..core.facts import (
        DiscoveredHost, DiscoveredHash, VersionString, FurtherPath,
        DiscoveredUsername,
    )
    hashes = store.all_of(DiscoveredHash)
    if hashes:
        bits.append("Hashes harvested:")
        for h in hashes[:10]:
            bits.append(f"  - {h.user}:{h.hash_value} ({h.hash_type})")
    hosts = store.all_of(DiscoveredHost)
    if hosts:
        bits.append("Internal hosts surfaced from leaked files:")
        for h in hosts[:15]:
            bits.append(f"  - {h.host}")
    versions = store.all_of(VersionString)
    if versions:
        bits.append("Software versions surfaced from leaked files:")
        for v in versions[:15]:
            bits.append(f"  - {v.text}")
    return "\n".join(bits)


async def _run_analysis(ctx: TaskCtx) -> None:
    intel = ctx.store.one("intel.summary")
    if intel is None:
        return
    intel_text = intel.text  # type: ignore[attr-defined]
    findings_text = _findings_block(ctx.store)
    loot_text = _loot_block(ctx.store)

    model = ctx.policy.knob("llm", "model", "gemma3:3b")
    client = LLMClient(model=model)
    text = await client.synthesize(
        intel_summary=intel_text,
        findings_block=findings_text or "(no structured findings)",
        loot_block=loot_text,
    )
    if not text:
        # Deterministic fallback — never silently skip; the user always
        # sees *something* in the analysis section.
        text = (
            "_LLM unavailable — listing findings sorted by severity._\n\n"
            + (findings_text or "(no findings)")
        )
    await ctx.emit(Analysis(text=text))


register(Task(
    id="analysis",
    label="LLM analysis",
    run=_run_analysis,
    requires={"intel.summary"},
    produces={"analysis"},
    tags={"core"},
))
