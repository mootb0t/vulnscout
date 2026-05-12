"""Textual TUI for vulnscout.

Layout
------
  ┌─ Header ─────────────────────────────────────────────┐
  │ Left (34 cols)            │ Right (flex)              │
  │  ─ target input            │  ─ live feed              │
  │  ─ target type radios      │  ─ findings (by severity) │
  │  ─ policy selector         │  ─ loot inventory         │
  │  ─ Run / Stop buttons      │  ─ tasks panel            │
  │  ─ progress bar            │                           │
  │  ─ status                  │                           │
  │  ─ identity panel          │                           │
  │  ─ tool indicators         │                           │
  └─ Footer ─────────────────────────────────────────────┘

Single Run button — the scheduler decides what to run when, in parallel.
Findings stream into a single severity-grouped panel; loot accumulates
in its own panel; the tasks panel is the live "what's running now"
view that replaces the old per-phase tabs.
"""

from __future__ import annotations

import asyncio
import time
from typing import List, Optional

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button, Checkbox, Collapsible, Footer, Header, Input, Label,
    ProgressBar, RadioButton, RadioSet, RichLog, Select, Static, TextArea,
)

from . import config, privesc, report
from .core.events import (
    Event, FactEmitted, ScanFinished, ScanStarted, Status as StatusEv,
    TaskFailed, TaskFinished, TaskOutput, TaskProgress, TaskSkipped,
    TaskStarted,
)
from .core.facts import (
    Analysis, ConfirmedCred, DiscoveredCredential, DiscoveredHash,
    DiscoveredHost, DiscoveredUsername, Email, Finding as FactFinding,
    FurtherPath, GitExposed, IntelSummary, MSFModule, Port,
    SearchsploitHit, Subdomain, Tech, VersionString,
)
from .core.orchestrator import Orchestrator
from .core.policy import POLICIES, POLICY_ORDER, get_policy
from .core.state_view import materialize, snapshot_state, echo_state_change
from .installer import (
    command_needs_sudo, ensure_install_paths, install_module, is_installable,
    sudo_authenticate,
)
from .llm import LLMClient, Finding as LegacyFinding
from .modules import CATEGORY_LABELS, CATEGORY_ORDER, MODULES, Module, get_module
from .opsec import (
    IdentityInfo, OpsecSettings, anonymization_warning, check_identity,
    is_proxychains_installed, is_tor_running, proxychains_install_hint,
    tor_install_hint,
)
from .phases.engagement import (
    CRITICAL_PHRASE, EngagementAction, build_action_queue,
    cleanup_tmpfiles, execute_action,
)
from .tools.parser import detect_target_type, validate_target
from .tools.runner import ScanContext, ScanState, running_as_root
from .tools.toolcheck import ToolStatus, check_tools


# ----------------------------------------------------------------------
# Shared styling helpers
# ----------------------------------------------------------------------


SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "bold yellow",
    "LOW":      "cyan",
    "INFO":     "dim white",
}

RISK_COLOR = {
    "PASSIVE":  "dim cyan",
    "LOW":      "cyan",
    "MEDIUM":   "bold yellow",
    "HIGH":     "red",
    "CRITICAL": "bold red",
}

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _escape(s: str) -> str:
    """Escape Rich markup so live tool output doesn't accidentally style itself."""
    return s.replace("[", r"\[")


def _quote(arg: str) -> str:
    """Shell-quote one argv token for *display* only — not for execution."""
    import shlex as _shlex
    return _shlex.quote(arg)


# ----------------------------------------------------------------------
# Sub-widgets
# ----------------------------------------------------------------------


class ScoutFox(Static):
    """Tiny animated ASCII fox peeking from the top-left corner."""

    FRAMES = (
        " /\\_/\\\n( o.o )",
        " /\\_/\\\n( -.- )",
        " /\\_/\\\n( o.> )",
        " /\\_/\\\n( o.o )",
        " /\\_/\\\n( <.o )",
    )

    def __init__(self, **kw) -> None:
        self._idx = 0
        super().__init__(self._markup(0), **kw)

    def on_mount(self) -> None:
        self.set_interval(0.9, self._tick)

    def _tick(self) -> None:
        self._idx = (self._idx + 1) % len(self.FRAMES)
        self.update(self._markup(self._idx))

    def _markup(self, idx: int) -> str:
        return f"[#e6a64c]{self.FRAMES[idx]}[/]"


class ToolCheckPanel(Static):
    """Compact green/red indicator block, one tool per line."""

    def update_tools(self, statuses: list[ToolStatus]) -> None:
        lines = []
        for s in statuses:
            if s.local_only:
                continue
            dot = "[#a6e22e]●[/]" if s.available else "[#f92672]●[/]"
            lines.append(f"{dot} {s.name}")
        self.update("\n".join(lines))


class IdentityPanel(Static):
    """Right-side panel summarising 'how do I look on the wire'."""

    def update_identity(self, info: Optional[IdentityInfo]) -> None:
        if info is None:
            self.update("[dim]identity: looking up…[/]")
            return
        bits = []
        if info.tor:
            bits.append("[#a6e22e]TOR[/]")
        if info.vpn:
            bits.append(f"[#a6e22e]VPN[/] [dim]({info.vpn_reason})[/]")
        ident_label = " · ".join(bits) if bits else "[#f92672]direct[/]"
        body = f"[b]Identity:[/] {ident_label}"
        if info.ip:
            body += f"\n  [dim]ip:[/] {info.ip}"
        if info.asn:
            body += f"\n  [dim]asn:[/] {info.asn[:60]}"
        if info.error and not info.ip:
            body += f"\n  [dim red]{info.error}[/]"
        self.update(body)


class FindingsList(Static):
    """Renders findings grouped by severity (CRITICAL → INFO).

    The old code split findings across four phase-specific lists; the new
    architecture has no phases, so we group purely by severity. Categories
    (e.g. "EXPOSURE" sub-section) still render under their own header
    inside each severity tier.
    """

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._findings: List[FactFinding] = []
        self._seen_ids: set = set()
        self._rerender()

    def add(self, f: FactFinding) -> None:
        # Dedup by fact id so a re-render or a fact replayed during
        # engagement doesn't double-add.
        if f.id in self._seen_ids:
            return
        self._seen_ids.add(f.id)
        self._findings.append(f)
        self._rerender()

    def clear(self) -> None:
        self._findings = []
        self._seen_ids = set()
        self._rerender()

    @property
    def count(self) -> int:
        return len(self._findings)

    def _rerender(self) -> None:
        if not self._findings:
            self.update("[dim]no findings yet — start a scan[/]")
            return
        blocks: List[str] = []
        for sev in SEVERITY_ORDER:
            tier = [f for f in self._findings if f.severity.upper() == sev]
            if not tier:
                continue
            color = SEVERITY_COLOR[sev]
            blocks.append(f"[{color}]── {sev}  ({len(tier)}) ──[/]")
            # Within a tier: group by category, then bare findings first.
            bare = [f for f in tier if not f.category]
            cats = sorted({f.category for f in tier if f.category})
            for f in bare:
                blocks.append(self._render_block(f))
            for cat in cats:
                blocks.append(f"  [b cyan]{_escape(cat)}[/]")
                for f in tier:
                    if f.category == cat:
                        blocks.append(self._render_block(f))
        self.update("\n\n".join(blocks))

    @staticmethod
    def _render_block(f: FactFinding) -> str:
        color = SEVERITY_COLOR.get(f.severity.upper(), "white")
        lines = [
            f"[{color}]{f.severity:<8}[/]  [dim]{f.tool:<14}[/]  "
            f"{_escape(f.summary)}"
        ]
        if f.detail and f.detail != f.summary:
            for sub in f.detail.splitlines()[:6]:
                lines.append(f"            [dim]{_escape(sub)}[/]")
            if len(f.detail.splitlines()) > 6:
                lines.append("            [dim]…[/]")
        return "\n".join(lines)


class LootList(Static):
    """Live loot inventory. Re-renders from the FactStore on each update."""

    def render_from_store(self, store) -> None:
        confirmed = store.all_of(ConfirmedCred)
        hashes = store.all_of(DiscoveredHash)
        creds = store.all_of(DiscoveredCredential)
        usernames = store.all_of(DiscoveredUsername)
        hosts = store.all_of(DiscoveredHost)
        versions = store.all_of(VersionString)
        paths = store.all_of(FurtherPath)
        git = store.one("loot.git_exposed")

        if not any([confirmed, hashes, creds, usernames, hosts,
                    versions, paths, git]):
            self.update("[dim]no loot yet[/]")
            return

        blocks: List[str] = []
        if confirmed:
            blocks.append(f"[bold red]Confirmed creds ({len(confirmed)})[/]")
            for c in confirmed[:6]:
                blocks.append(
                    f"  [b]{_escape(c.user)}[/]:[dim]{_escape(c.password)}[/] "
                    f"({c.service})"
                )
        if hashes:
            blocks.append(f"[red]Hashes ({len(hashes)})[/]")
            for h in hashes[:6]:
                v = h.hash_value if len(h.hash_value) <= 40 else h.hash_value[:36] + "…"
                blocks.append(f"  {_escape(h.user)}:{_escape(v)} ({h.hash_type})")
        if creds:
            crit = sum(1 for c in creds if c.is_critical)
            blocks.append(
                f"[bold red]Secrets ({len(creds)}, {crit} critical)[/]"
            )
            for c in creds[:6]:
                tag = f"[red]{c.label}[/]" if c.is_critical else c.label
                shown = c.value if c.is_critical else c.truncated_value()
                blocks.append(f"  {tag}: [dim]{_escape(shown)}[/]")
        if usernames:
            blocks.append(f"[yellow]Usernames ({len(usernames)})[/]")
            for u in sorted(usernames, key=lambda x: -float(x.confidence or 0))[:6]:
                blocks.append(f"  [b]{_escape(u.username)}[/] [dim]({u.confidence:.2f})[/]")
        if hosts:
            blocks.append(f"[cyan]Internal hosts ({len(hosts)})[/]")
            for h in hosts[:6]:
                blocks.append(f"  {_escape(h.host)}")
        if versions:
            blocks.append(f"[cyan]Versions ({len(versions)})[/]")
            for v in versions[:6]:
                blocks.append(f"  {_escape(v.text)}")
        if git:
            blocks.append(f"[bold red]Git exposed:[/] {_escape(git.url)}")
        if paths:
            blocks.append(f"[dim]Paths ({len(paths)}) — see report[/]")
        self.update("\n".join(blocks))


class TasksList(Static):
    """Live task lifecycle panel. Replaces the old phase tabs.

    Tracks: running (▶), done (✓), skipped (–), failed (✗). Order: most
    recently active at the top so the user sees what's happening now.
    """

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._states: dict = {}     # task_id -> (state, label, extra)
        self._order: List[str] = [] # most-recent-first
        self._rerender()

    def started(self, task_id: str, label: str) -> None:
        self._states[task_id] = ("running", label, "")
        self._touch(task_id)
        self._rerender()

    def finished(self, task_id: str, duration_s: float, facts: int) -> None:
        s = self._states.get(task_id)
        label = s[1] if s else task_id
        self._states[task_id] = (
            "done", label,
            f"{duration_s:.1f}s · {facts} fact(s)",
        )
        self._touch(task_id)
        self._rerender()

    def skipped(self, task_id: str, reason: str) -> None:
        s = self._states.get(task_id)
        label = s[1] if s else task_id
        self._states[task_id] = ("skipped", label, reason)
        self._touch(task_id)
        self._rerender()

    def failed(self, task_id: str, error: str) -> None:
        s = self._states.get(task_id)
        label = s[1] if s else task_id
        self._states[task_id] = ("failed", label, error)
        self._touch(task_id)
        self._rerender()

    def reset(self) -> None:
        self._states = {}
        self._order = []
        self._rerender()

    def _touch(self, task_id: str) -> None:
        if task_id in self._order:
            self._order.remove(task_id)
        self._order.insert(0, task_id)

    def _rerender(self) -> None:
        if not self._order:
            self.update("[dim]no tasks scheduled — start a scan[/]")
            return
        rows: List[str] = []
        # Running first, then everything else in recency order.
        running = [tid for tid in self._order
                    if self._states[tid][0] == "running"]
        rest = [tid for tid in self._order if tid not in running]
        for tid in running + rest:
            state, label, extra = self._states[tid]
            sigil, color = {
                "running": ("▶", "#66d9ef"),
                "done":    ("✓", "#a6e22e"),
                "skipped": ("–", "#6e7a8a"),
                "failed":  ("✗", "#f92672"),
            }.get(state, ("·", "white"))
            line = f"[{color}]{sigil}[/] {_escape(label)}"
            if extra:
                line += f" [dim]{_escape(extra)}[/]"
            rows.append(line)
        self.update("\n".join(rows))


# ----------------------------------------------------------------------
# Modal screens (preserved from prior version, lightly updated)
# ----------------------------------------------------------------------


class SettingsScreen(ModalScreen[Optional[dict]]):
    """General settings + OPSEC tab."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel", show=False)]

    def __init__(self, settings: dict, initial_tab: str = "general") -> None:
        super().__init__()
        self._settings = settings
        self._initial_tab = initial_tab if initial_tab in ("general", "opsec") else "general"

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="settings-box"):
            yield Label("[b]Settings[/b]")
            with Horizontal(id="settings-tabs"):
                yield Button("General", id="tab-general",
                             variant=("primary" if self._initial_tab == "general" else "default"))
                yield Button("OPSEC",   id="tab-opsec",
                             variant=("primary" if self._initial_tab == "opsec" else "default"))

            with Container(id="settings-pane-general",
                           classes=("hidden" if self._initial_tab != "general" else "")):
                yield Label("Ollama model:")
                yield Input(value=self._settings.get("model", ""), id="model")
                yield Label("Default policy:")
                yield Input(value=self._settings.get("profile", ""), id="profile")
                yield Label("Wordlist path (used by ffuf / gobuster):")
                yield Input(value=self._settings.get("wordlist", ""), id="wordlist")
                yield Label("Nuclei templates dir (blank = nuclei default):")
                yield Input(value=self._settings.get("templates", ""), id="templates")
                yield Label("Shodan API key (optional):")
                yield Input(value=self._settings.get("shodan_api_key", ""),
                            id="shodan_api_key", password=True)
                yield Label("Hunter.io API key (optional):")
                yield Input(value=self._settings.get("hunter_api_key", ""),
                            id="hunter_api_key", password=True)
                yield Label("Enable local-only tools (msf/john/hashcat — '1' = yes):")
                yield Input(value=self._settings.get("enable_local_tools", ""),
                            id="enable_local_tools")

            with Container(id="settings-pane-opsec",
                           classes=("hidden" if self._initial_tab != "opsec" else "")):
                yield from self._compose_opsec()

            with Container(classes="row"):
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    def _compose_opsec(self) -> ComposeResult:
        s = self._settings
        yield Label(
            "[b]OPSEC — operational security[/b]\n"
            "[dim]Stealth and Paranoid policies enable delays, UA randomization, "
            "source-port spoofing, and packet fragmentation automatically.[/]"
        )
        yield Checkbox(
            "Tor routing — wrap every tool in `torsocks`",
            value=s.get("opsec_tor") == "1", id="opsec_tor",
        )
        if not is_tor_running():
            yield Static(
                f"  [yellow]⚠ tor daemon not detected on 127.0.0.1:9050.[/]\n"
                f"  [dim]install: {tor_install_hint()}[/]",
                id="tor-hint",
            )
        yield Checkbox(
            "Proxychains — wrap every tool in `proxychains4 -q`",
            value=s.get("opsec_proxychains") == "1", id="opsec_proxychains",
        )
        if not is_proxychains_installed():
            yield Static(
                f"  [yellow]⚠ proxychains4 not installed.[/]\n"
                f"  [dim]install: {proxychains_install_hint()}[/]",
                id="pc-hint",
            )
        yield Checkbox(
            "Inter-tool delays (randomized seconds between tool runs)",
            value=s.get("opsec_delay_enabled") == "1", id="opsec_delay_enabled",
        )
        with Horizontal(classes="opsec-row"):
            yield Label("  min sec:", classes="opsec-inline-label")
            yield Input(value=s.get("opsec_delay_min", "5"),
                        id="opsec_delay_min", classes="opsec-numeric")
            yield Label("  max sec:", classes="opsec-inline-label")
            yield Input(value=s.get("opsec_delay_max", "30"),
                        id="opsec_delay_max", classes="opsec-numeric")
        yield Checkbox(
            "Randomize User-Agent (nikto / gobuster / ffuf / whatweb)",
            value=s.get("opsec_user_agent_random") == "1",
            id="opsec_user_agent_random",
        )
        yield Checkbox(
            "nmap source-port spoofing (--source-port 53)",
            value=s.get("opsec_nmap_source_port") == "1",
            id="opsec_nmap_source_port",
        )
        yield Checkbox(
            "nmap packet fragmentation (-f)",
            value=s.get("opsec_nmap_fragment") == "1",
            id="opsec_nmap_fragment",
        )

    @on(Button.Pressed, "#tab-general")
    def _show_general(self) -> None: self._switch_tab("general")

    @on(Button.Pressed, "#tab-opsec")
    def _show_opsec(self) -> None: self._switch_tab("opsec")

    def _switch_tab(self, which: str) -> None:
        for pane, btn in (("general", "tab-general"), ("opsec", "tab-opsec")):
            try:
                self.query_one(f"#settings-pane-{pane}").set_class(pane != which, "hidden")
                self.query_one(f"#{btn}", Button).variant = (
                    "primary" if pane == which else "default"
                )
            except Exception:
                pass

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        def _val(field: str) -> str:
            return self.query_one(f"#{field}", Input).value.strip()

        def _flag(field: str) -> str:
            return "1" if self.query_one(f"#{field}", Checkbox).value else "0"

        self.dismiss({
            "model":              _val("model"),
            "profile":            _val("profile"),
            "wordlist":           _val("wordlist"),
            "templates":          _val("templates"),
            "shodan_api_key":     _val("shodan_api_key"),
            "hunter_api_key":     _val("hunter_api_key"),
            "enable_local_tools": _val("enable_local_tools"),
            "opsec_tor":               _flag("opsec_tor"),
            "opsec_proxychains":       _flag("opsec_proxychains"),
            "opsec_delay_enabled":     _flag("opsec_delay_enabled"),
            "opsec_delay_min":         _val("opsec_delay_min") or "5",
            "opsec_delay_max":         _val("opsec_delay_max") or "30",
            "opsec_user_agent_random": _flag("opsec_user_agent_random"),
            "opsec_nmap_source_port":  _flag("opsec_nmap_source_port"),
            "opsec_nmap_fragment":     _flag("opsec_nmap_fragment"),
        })

    @on(Button.Pressed, "#cancel")
    def _cancel(self) -> None: self.dismiss(None)


class HelpScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("q", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help-box"):
            yield Label("[b]vulnscout — fact-driven scanner[/b]\n")
            yield Static(
                "[b cyan]How it works[/]\n"
                "  vulnscout has a tool registry (each tool is one Task) and\n"
                "  a fact store. Tasks declare what facts they need and what\n"
                "  facts they produce. The scheduler runs them in parallel\n"
                "  as their inputs become available.\n\n"
                "  The Target seed kicks off passive intel + nmap. As ports\n"
                "  appear, port-conditional tasks (sslscan, exposure probes)\n"
                "  schedule. As HTTP endpoints get confirmed, the web tools\n"
                "  fan out. Once everything settles, the LLM synthesises an\n"
                "  attack-angle analysis from the accumulated facts.\n"
            )
            yield Static(
                "[b cyan]Engagement (g)[/]\n"
                "  Interactive, post-scan: builds an action queue from the\n"
                "  facts collected (hydra SSH/SMB, default web creds, MSF\n"
                "  modules per CVE) and waits for per-action confirmation.\n"
                "  MEDIUM = single confirm, HIGH = double confirm,\n"
                "  CRITICAL = type a phrase. Every command is editable.\n"
            )
            yield Static(
                "[b cyan]Post-Exploitation (p)[/]\n"
                "  For when you're ON the box. An OS-aware enumeration\n"
                "  checklist + interesting-file list, plus a paste-and-\n"
                "  analyze box: paste `sudo -l`, a SUID list, `getcap`,\n"
                "  `uname -a`, `whoami /priv`, or a full linpeas/winpeas\n"
                "  dump and get ranked GTFOBins / kernel / capability\n"
                "  escalation leads. Advisory only — nothing is executed.\n"
            )
            yield Static("\n[b]Policies[/]")
            for k in POLICY_ORDER:
                p = POLICIES[k]
                yield Static(f"  [b]{p.label}[/] — {p.description}")
            yield Label("\n[dim]Press q or Esc to close[/]")


class FullAnalysisScreen(ModalScreen[None]):
    """Fullscreen scroller for the analysis text."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("q", "dismiss", "Close"),
        Binding("f", "dismiss", "Close"),
    ]

    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text or "(no analysis text available)"

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="full-analysis-box"):
            yield Label("[b cyan]Analysis (full)[/]")
            yield Static(_escape(self._text), id="full-analysis-text")
            yield Label("[dim]Press q, Esc, or f to close[/]")


class PrivescScreen(ModalScreen[None]):
    """Post-exploitation / privilege-escalation helper — 'you're IN the box'.

    Left: an OS-aware enumeration checklist + interesting-file list.
    Right: a paste-and-analyze box. Paste `sudo -l`, a SUID listing,
    `getcap`, `uname -a`, `whoami /priv`, or a whole linpeas/winpeas dump
    and get back ranked, copy-pasteable escalation leads (GTFOBins, kernel
    exploits, capabilities, Windows token abuse). Everything is advisory —
    vulnscout never runs any of it.
    """

    DEFAULT_CSS = """
    PrivescScreen { align: center middle; }
    #privesc-box {
        width: 92%; height: 92%;
        background: $surface; border: thick $accent; padding: 1 2;
    }
    #privesc-banner { height: auto; margin-bottom: 1; }
    #privesc-os-row { height: auto; margin-bottom: 1; }
    #privesc-os { layout: horizontal; height: auto; width: auto; }
    #privesc-panes { height: 1fr; }
    #privesc-ref {
        width: 2fr; height: 1fr; border-right: solid $panel; padding: 0 1 0 0;
    }
    #privesc-analyze { width: 3fr; height: 1fr; padding: 0 0 0 1; }
    #privesc-input { height: 10; border: tall $panel; margin-bottom: 1; }
    #privesc-results-scroll { height: 1fr; border: round $panel; padding: 0 1; }
    PrivescScreen .row { height: auto; }
    PrivescScreen .row Button { width: auto; margin-right: 2; }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("ctrl+r", "run_analyze", "Analyze"),
    ]

    _CONF_COLOR = {"high": "bold red", "medium": "yellow", "check": "cyan"}

    def __init__(self, os_hint: str = "linux", banner: str = "") -> None:
        super().__init__()
        self._os = "windows" if "win" in (os_hint or "").lower() else "linux"
        self._banner = banner

    def compose(self) -> ComposeResult:
        with Container(id="privesc-box"):
            yield Label(
                "[b cyan]Post-Exploitation — Privilege Escalation[/]   "
                "[dim]you're IN the box — enumerate, then escalate[/]"
            )
            if self._banner:
                yield Static(self._banner, id="privesc-banner")
            with Horizontal(id="privesc-os-row"):
                yield Label("Target OS:  ")
                with RadioSet(id="privesc-os"):
                    yield RadioButton("Linux", value=(self._os == "linux"),
                                      id="os-linux")
                    yield RadioButton("Windows", value=(self._os == "windows"),
                                      id="os-windows")
            with Horizontal(id="privesc-panes"):
                with VerticalScroll(id="privesc-ref"):
                    yield Static("", id="privesc-checklist")
                with Vertical(id="privesc-analyze"):
                    yield Label(
                        "[b]Paste tool output[/]  [dim]sudo -l · find -perm "
                        "-4000 · getcap · uname -a · whoami /priv · linpeas[/]"
                    )
                    yield TextArea(id="privesc-input")
                    with Horizontal(classes="row"):
                        yield Button("Analyze", id="privesc-run",
                                     variant="primary")
                        yield Button("Clear", id="privesc-clear")
                    with VerticalScroll(id="privesc-results-scroll"):
                        yield Static(
                            "[dim]Paste output above and press Analyze "
                            "(or Ctrl-R) for ranked escalation leads.[/]",
                            id="privesc-results",
                        )
            yield Static(
                "[dim]Esc=close · Ctrl-R=analyze · advisory only — "
                "vulnscout never runs these[/]"
            )

    def on_mount(self) -> None:
        self._render_checklist()

    def _render_checklist(self) -> None:
        os_name = self._os
        lines = [f"[b]Enumeration checklist — {os_name}[/]", ""]
        cur = None
        for step in privesc.enum_steps(os_name):
            if step.category != cur:
                cur = step.category
                lines.append(f"[b cyan]{cur}[/]")
            lines.append(f"  [#a6e22e]$[/] {_escape(step.command)}")
            lines.append(f"    [dim]{_escape(step.why)}[/]")
        lines += ["", "[b]Interesting files / loot[/]"]
        for path, why in privesc.interesting_files(os_name):
            lines.append(f"  [cyan]{_escape(path)}[/]")
            lines.append(f"    [dim]{_escape(why)}[/]")
        try:
            self.query_one("#privesc-checklist", Static).update("\n".join(lines))
        except Exception:
            pass

    @on(RadioSet.Changed, "#privesc-os")
    def _os_changed(self, ev: RadioSet.Changed) -> None:
        pressed = getattr(ev, "pressed", None)
        self._os = "windows" if (pressed and pressed.id == "os-windows") else "linux"
        self._render_checklist()

    @on(Button.Pressed, "#privesc-clear")
    def _clear(self) -> None:
        try:
            self.query_one("#privesc-input", TextArea).clear()
            self.query_one("#privesc-results", Static).update("[dim]cleared[/]")
        except Exception:
            pass

    @on(Button.Pressed, "#privesc-run")
    def _run_button(self) -> None:
        self.action_run_analyze()

    def action_run_analyze(self) -> None:
        results = self.query_one("#privesc-results", Static)
        text = self.query_one("#privesc-input", TextArea).text
        if not text.strip():
            results.update("[yellow]Nothing to analyze — paste some output first.[/]")
            return
        suggestions = privesc.analyze(text, self._os)
        if not suggestions:
            results.update(
                "[dim]No known escalation leads matched this output. Run "
                "linpeas/winpeas and paste the full dump, or inspect the "
                "interesting files manually.[/]"
            )
            return
        results.update(self._render_suggestions(suggestions))

    def _render_suggestions(self, suggestions: list) -> str:
        blocks = [
            f"[b]{len(suggestions)} escalation lead(s)[/]  "
            "[dim](ranked high → check)[/]", ""
        ]
        for s in suggestions:
            color = self._CONF_COLOR.get(s.confidence, "white")
            blocks.append(
                f"[{color}]● {s.confidence.upper()}[/]  [b]{_escape(s.title)}[/]  "
                f"[dim]{s.category}[/]"
            )
            if s.why:
                blocks.append(f"   [dim]{_escape(s.why)}[/]")
            blocks.append(f"   [#a6e22e]$[/] {_escape(s.command)}")
            if s.reference:
                blocks.append(f"   [dim]↳ {_escape(s.reference)}[/]")
            blocks.append("")
        return "\n".join(blocks)


# ----- Engagement-related modals (preserved verbatim from prior design) -----


class ActionCard(Container):
    DEFAULT_CSS = """
    ActionCard { height: auto; border: tall #1f2530; padding: 0 1;
                 margin-bottom: 1; }
    ActionCard.executing { border: tall #66d9ef; }
    ActionCard.completed { border: tall #a6e22e; }
    ActionCard.skipped, ActionCard.failed { border: tall #6e7a8a; }
    ActionCard > .row { layout: horizontal; height: auto; margin-top: 1; }
    ActionCard > .row Button { width: 1fr; margin-right: 1; }
    """

    class ActionRequest(Message):
        def __init__(self, action_id: str, kind: str) -> None:
            super().__init__()
            self.action_id = action_id
            self.kind = kind

    def __init__(self, action: EngagementAction) -> None:
        super().__init__(id=f"card-{action.id}")
        self.action_data = action
        import shutil as _sh
        self._tool_available = (action.required_tool == "echo") or (
            _sh.which(action.required_tool) is not None
        )

    def compose(self) -> ComposeResult:
        a = self.action_data
        risk_color = RISK_COLOR.get(a.risk, "white")
        cmd_str = " ".join(_quote(arg) for arg in a.command)
        tool_status = (
            f"[#a6e22e]✓[/] {a.required_tool}"
            if self._tool_available
            else f"[#f92672]✗[/] {a.required_tool} not installed"
        )
        new_chip = "[black on #e6db74] NEW [/]   " if a.is_new else ""
        yield Static(
            f"{new_chip}[b]{_escape(a.name)}[/]   "
            f"[{risk_color}]{a.risk}[/]   {tool_status}"
        )
        yield Static(f"[dim]{_escape(a.description)}[/]")
        if a.finding_ref:
            yield Static(f"[dim italic]triggered by: {_escape(a.finding_ref)}[/]")
        yield Static(f"[b cyan]$ {_escape(cmd_str)}[/]")
        yield Static(f"[dim]expected: {_escape(a.expected_output)}[/]")
        if a.summary:
            color = SEVERITY_COLOR.get("HIGH" if a.rc else "INFO", "white")
            yield Static(f"[{color}]result:[/] {_escape(a.summary)}")
        with Container(classes="row"):
            disabled = a.status != "pending"
            exec_disabled = disabled or (not self._tool_available and not a.manual_only)
            yield Button(
                "Execute" if not a.manual_only else "Manual",
                id=f"exec-{a.id}", variant="primary",
                disabled=exec_disabled,
            )
            yield Button("Skip", id=f"skip-{a.id}", disabled=disabled)
            yield Button("Explain", id=f"explain-{a.id}")
            yield Button("Edit Command", id=f"edit-{a.id}", disabled=disabled)

    @on(Button.Pressed)
    def _on_pressed(self, ev: Button.Pressed) -> None:
        bid = ev.button.id or ""
        for prefix, kind in (
            ("exec-", "execute"), ("skip-", "skip"),
            ("explain-", "explain"), ("edit-", "edit"),
        ):
            if bid.startswith(prefix):
                self.post_message(self.ActionRequest(self.action_data.id, kind))
                ev.stop()
                return


class ConfirmActionScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel", show=False)]

    def __init__(self, action: EngagementAction) -> None:
        super().__init__()
        self.action_data = action

    def compose(self) -> ComposeResult:
        a = self.action_data
        risk_color = RISK_COLOR.get(a.risk, "white")
        cmd_str = " ".join(_quote(arg) for arg in a.command)
        with Container(id="confirm-box"):
            yield Label(f"[b]Confirm action[/]   [{risk_color}]{a.risk}[/]")
            yield Static(f"[b]{_escape(a.name)}[/]")
            yield Static(f"[dim]{_escape(a.description)}[/]")
            yield Static(f"\n[b cyan]$ {_escape(cmd_str)}[/]")
            if a.rationale:
                yield Static(f"\n[dim]{_escape(a.rationale)}[/]")
            with Container(classes="row"):
                yield Button("Run", id="yes", variant="primary")
                yield Button("Cancel", id="no")

    @on(Button.Pressed, "#yes")
    def _yes(self) -> None: self.dismiss(True)

    @on(Button.Pressed, "#no")
    def _no(self) -> None: self.dismiss(False)


class DoubleConfirmActionScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel", show=False)]

    def __init__(self, action: EngagementAction) -> None:
        super().__init__()
        self.action_data = action
        self._step = 1

    def compose(self) -> ComposeResult:
        a = self.action_data
        risk_color = RISK_COLOR.get(a.risk, "white")
        cmd_str = " ".join(_quote(arg) for arg in a.command)
        with Container(id="confirm-box"):
            yield Label(f"[b]HIGH-risk action[/]   [{risk_color}]{a.risk}[/]")
            yield Static(f"[b]{_escape(a.name)}[/]")
            yield Static(f"[b cyan]$ {_escape(cmd_str)}[/]")
            yield Static(
                "\n[yellow]Impact: this is loud (logs/IDS), can lock "
                "accounts, may trip rate limits, and is hard to reverse. "
                "Make sure you have written authorization for the target.[/]"
            )
            if a.rationale:
                yield Static(f"\n[dim]{_escape(a.rationale)}[/]")
            yield Static("\n[dim]Step 1 of 2 — click Acknowledge to continue.[/]",
                         id="confirm-step")
            with Container(classes="row"):
                yield Button("Acknowledge", id="yes", variant="warning")
                yield Button("Cancel", id="no")

    @on(Button.Pressed, "#yes")
    def _yes(self) -> None:
        if self._step == 1:
            self._step = 2
            try:
                btn = self.query_one("#yes", Button)
                btn.label = "Run"
                btn.variant = "error"
                self.query_one("#confirm-step", Static).update(
                    "[red]Step 2 of 2 — final confirmation. Click Run to execute.[/]"
                )
            except Exception:
                self.dismiss(True)
            return
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def _no(self) -> None: self.dismiss(False)


class PhraseConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel", show=False)]

    def __init__(self, action: EngagementAction) -> None:
        super().__init__()
        self.action_data = action

    def compose(self) -> ComposeResult:
        a = self.action_data
        cmd_str = " ".join(_quote(arg) for arg in a.command)
        with Container(id="confirm-box"):
            yield Label("[bold red]CRITICAL ACTION[/]")
            yield Static(f"[b]{_escape(a.name)}[/]")
            yield Static(f"[b cyan]$ {_escape(cmd_str)}[/]")
            yield Static(
                "\n[red]This action can fully compromise the target — "
                "pop a shell, escalate privileges, or execute arbitrary "
                "code on the remote host. There is no clean undo.[/]"
            )
            if a.rationale:
                yield Static(f"\n[dim]{_escape(a.rationale)}[/]")
            yield Static(
                f"\n[b]To proceed, type[/] [yellow]{CRITICAL_PHRASE}[/] [b]below:[/]",
            )
            yield Input(placeholder=CRITICAL_PHRASE, id="phrase-input")
            with Container(classes="row"):
                yield Button("Run", id="yes", variant="error", disabled=True)
                yield Button("Cancel", id="no")

    @on(Input.Changed, "#phrase-input")
    def _on_change(self, ev: Input.Changed) -> None:
        try:
            self.query_one("#yes", Button).disabled = (
                ev.value.strip() != CRITICAL_PHRASE
            )
        except Exception:
            pass

    @on(Button.Pressed, "#yes")
    def _yes(self) -> None:
        if self.query_one("#phrase-input", Input).value.strip() == CRITICAL_PHRASE:
            self.dismiss(True)

    @on(Button.Pressed, "#no")
    def _no(self) -> None: self.dismiss(False)


class EditCommandScreen(ModalScreen[Optional[list]]):
    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel", show=False)]

    def __init__(self, action: EngagementAction) -> None:
        super().__init__()
        self.action_data = action

    def compose(self) -> ComposeResult:
        a = self.action_data
        joined = " ".join(_quote(arg) for arg in a.command)
        with Container(id="edit-box"):
            yield Label(f"[b]Edit command — {_escape(a.name)}[/]")
            yield Static(
                "[dim]Tokens are split by whitespace. Use single quotes to "
                "keep a value with spaces in one token.[/]"
            )
            yield Input(value=joined, id="edit-input")
            with Container(classes="row"):
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        import shlex as _shlex
        text = self.query_one("#edit-input", Input).value
        try:
            argv = _shlex.split(text)
        except ValueError:
            argv = text.split()
        if not argv:
            self.dismiss(None)
            return
        self.dismiss(argv)

    @on(Button.Pressed, "#cancel")
    def _cancel(self) -> None: self.dismiss(None)


class ExplainActionScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Close"),
                Binding("q", "dismiss", "Close")]

    def __init__(self, action: EngagementAction) -> None:
        super().__init__()
        self.action_data = action

    def compose(self) -> ComposeResult:
        a = self.action_data
        cmd_str = " ".join(_quote(arg) for arg in a.command)
        with VerticalScroll(id="explain-box"):
            yield Label(f"[b]{_escape(a.name)}[/]   [{RISK_COLOR.get(a.risk, 'white')}]{a.risk}[/]")
            yield Static(f"\n[dim]{_escape(a.description)}[/]")
            yield Static(f"\n[b]Command:[/]\n[cyan]$ {_escape(cmd_str)}[/]")
            yield Static(f"\n[b]Required tool:[/] {a.required_tool}")
            yield Static(f"\n[b]Expected output:[/]\n{_escape(a.expected_output)}")
            if a.rationale:
                yield Static(f"\n[b]Rationale:[/]\n{_escape(a.rationale)}")
            if a.finding_ref:
                yield Static(f"\n[dim]Triggered by:[/] {_escape(a.finding_ref)}")
            yield Label("\n[dim]Press q or Esc to close[/]")


class EngagementScreen(ModalScreen[None]):
    """Engagement UI — action queue (left) + execution output (right).

    Receives a synthesized ScanContext built from the FactStore (via
    `materialize`). The interactive logic in phases/engagement.py is
    unchanged — this screen only adapts the new architecture to it.
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("q", "dismiss", "Close"),
        Binding("r", "rebuild_queue", "Rebuild queue"),
    ]

    def __init__(
        self, ctx: ScanContext, llm: LLMClient, settings: dict,
        store=None,
    ) -> None:
        super().__init__()
        self._ctx = ctx
        self._llm = llm
        self._settings = settings
        self._store = store      # for echoing engagement state back as facts

    def compose(self) -> ComposeResult:
        with Container(id="engagement-box"):
            yield Label(
                "[b cyan]Engagement[/]   "
                "[dim]interactive exploitation guidance — every action requires "
                "explicit confirmation[/]"
            )
            with Horizontal(id="engagement-panes"):
                with VerticalScroll(id="engagement-queue-pane"):
                    yield Label("[b]Action Queue[/]")
                    yield Static(
                        "[dim]building queue from collected facts…[/]",
                        id="queue-status",
                    )
                    yield Container(id="queue-cards")
                with Vertical(id="engagement-output-pane"):
                    yield Label("[b]Execution Output[/]")
                    yield RichLog(
                        id="engagement-log", markup=True, wrap=True,
                        max_lines=10000,
                    )
            yield Static(
                "[dim]r=rebuild queue · q/Esc=close[/]",
                id="engagement-help",
            )

    async def on_mount(self) -> None:
        if not self._ctx.state.engagement_actions:
            self._ctx.state.engagement_actions = build_action_queue(
                self._ctx.state, self._settings,
            )
        await self._render_queue()
        log = self.query_one("#engagement-log", RichLog)
        if self._ctx.state.engagement_log:
            log.write(
                f"[dim]({len(self._ctx.state.engagement_log)} action(s) "
                "executed earlier this scan)[/]"
            )

    async def action_rebuild_queue(self) -> None:
        old = self._ctx.state.engagement_actions
        completed = [a for a in old if a.status != "pending"]
        fresh = build_action_queue(self._ctx.state, self._settings)
        old_refs = {a.finding_ref for a in old}
        existing_refs = {a.finding_ref for a in completed}
        added: list = []
        for a in fresh:
            if a.finding_ref in existing_refs:
                continue
            if a.finding_ref not in old_refs:
                a.is_new = True
            added.append(a)
        merged = completed + added
        self._ctx.state.engagement_actions = merged
        await self._render_queue()
        new_count = sum(1 for a in added if a.is_new)
        msg = f"[#a6e22e]✓[/] queue rebuilt"
        if new_count:
            msg += f" — [#e6db74]{new_count} new[/]"
        self.query_one("#engagement-log", RichLog).write(msg)

    _TIER_HEADER = {
        "PASSIVE":  ("── PASSIVE ──",  "#6e7a8a"),
        "LOW":      ("── LOW ──",      "#a6e22e"),
        "MEDIUM":   ("── MEDIUM ──",   "#e6db74"),
        "HIGH":     ("── HIGH ──",     "#f92672"),
        "CRITICAL": ("── CRITICAL ──", "bold red"),
    }

    async def _render_queue(self) -> None:
        cards = self.query_one("#queue-cards", Container)
        await cards.query("ActionCard, .tier-header").remove()
        actions = self._ctx.state.engagement_actions
        status = self.query_one("#queue-status", Static)
        if not actions:
            status.update(
                "[yellow]No actions surfaced.[/] [dim]The scan didn't produce "
                "usernames, web fingerprints, or CVEs that map to an action.[/]"
            )
            return
        pending = sum(1 for a in actions if a.status == "pending")
        new_count = sum(1 for a in actions if a.is_new)
        bits = [f"{pending} pending", f"{len(actions) - pending} settled"]
        if new_count:
            bits.insert(0, f"[#e6db74]{new_count} new[/]")
        bits.append("r=rebuild")
        status.update("[dim]" + " · ".join(bits) + "[/]")
        per_tier: dict = {}
        for a in actions:
            per_tier[a.risk] = per_tier.get(a.risk, 0) + 1
        seen_tiers: set = set()
        for a in actions:
            if a.risk not in seen_tiers:
                label, color = self._TIER_HEADER.get(
                    a.risk, (f"── {a.risk} ──", "#6e7a8a"),
                )
                cards.mount(Static(
                    f"[{color}]{label}[/]   "
                    f"[dim]{per_tier[a.risk]} action(s)[/]",
                    classes="tier-header",
                ))
                seen_tiers.add(a.risk)
            card = ActionCard(a)
            cards.mount(card)
            for cls in ("executing", "completed", "skipped", "failed"):
                if a.status == cls:
                    card.add_class(cls)

    @on(ActionCard.ActionRequest)
    async def _on_action_request(self, ev: ActionCard.ActionRequest) -> None:
        action = self._find_action(ev.action_id)
        if action is None:
            return
        if ev.kind == "explain":
            self.app.push_screen(ExplainActionScreen(action))
            return
        if ev.kind == "skip":
            action.status = "skipped"
            await self._render_queue()
            self.query_one("#engagement-log", RichLog).write(
                f"[dim]– skipped: {_escape(action.name)}[/]"
            )
            return
        if ev.kind == "edit":
            async def _saved(argv) -> None:
                if argv is None:
                    return
                action.command = list(argv)
                await self._render_queue()
                self.query_one("#engagement-log", RichLog).write(
                    f"[#a6e22e]✓[/] command edited for {_escape(action.name)}"
                )
            self.app.push_screen(EditCommandScreen(action), _saved)
            return
        if ev.kind == "execute":
            self._launch_execute(action)

    @work(exclusive=False)
    async def _launch_execute(self, action: EngagementAction) -> None:
        log = self.query_one("#engagement-log", RichLog)
        risk = action.risk.upper()
        risk_color = RISK_COLOR.get(action.risk, "white")
        log.write(
            f"\n[b cyan]▶[/] requested [{risk_color}]{action.risk}[/] "
            f"{_escape(action.name)} [dim]— awaiting confirmation[/]"
        )

        if action.manual_only or risk in ("PASSIVE", "LOW", "MEDIUM"):
            modal: ModalScreen = ConfirmActionScreen(action)
        elif risk == "HIGH":
            modal = DoubleConfirmActionScreen(action)
        elif risk == "CRITICAL":
            modal = PhraseConfirmScreen(action)
        else:
            modal = ConfirmActionScreen(action)

        try:
            approved = await self.app.push_screen_wait(modal)
        except Exception as e:
            log.write(f"[red]ERROR (confirm modal): {_escape(str(e))}[/]")
            return

        if not approved:
            log.write(f"[dim]– cancelled: {_escape(action.name)}[/]")
            return

        log.write(
            f"[b cyan]▶[/] [{risk_color}]{action.risk}[/] "
            f"{_escape(action.name)} [dim]— running[/]"
        )
        try:
            await self._render_queue()
        except Exception as e:
            log.write(f"[red]ERROR (queue render): {_escape(str(e))}[/]")

        prev_snap = snapshot_state(self._ctx.state)
        try:
            async for ev in execute_action(self._ctx, self._llm, action):
                if ev.kind == "tool_start":
                    log.write(f"[b cyan]$ {_escape(ev.text)}[/]")
                elif ev.kind == "output":
                    if ev.severity_hint == "dim":
                        log.write(f"[dim]{_escape(ev.text)}[/]")
                    else:
                        log.write(_escape(ev.text))
                elif ev.kind == "warning":
                    log.write(f"[yellow]⚠ {_escape(ev.text)}[/]")
                elif ev.kind == "finding" and ev.finding is not None:
                    color = SEVERITY_COLOR.get(ev.finding.severity.upper(), "white")
                    log.write(
                        f"[{color}]✦ [{ev.finding.severity}][/]  "
                        f"{_escape(ev.finding.summary)}"
                    )
        except Exception as e:
            log.write(f"[red]ERROR (execute): {_escape(str(e))}[/]")
        try:
            await self._render_queue()
        except Exception as e:
            log.write(f"[red]ERROR (post-render): {_escape(str(e))}[/]")
        # Echo any state changes (new confirmed creds, hashes, ...) back
        # into the FactStore so the report and analysis see them.
        if self._store is not None:
            try:
                await echo_state_change(self._store, self._ctx.state, prev_snap)
            except Exception:
                pass

    def _find_action(self, action_id: str) -> Optional[EngagementAction]:
        for a in self._ctx.state.engagement_actions:
            if a.id == action_id:
                return a
        return None


class ConfirmQuitScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel", show=False)]

    def compose(self) -> ComposeResult:
        with Container(id="q-box"):
            yield Label("[b]Quit?[/]\nA scan is running. Kill it and exit?")
            with Container(classes="row"):
                yield Button("Quit", id="yes", variant="error")
                yield Button("Cancel", id="no")

    @on(Button.Pressed, "#yes")
    def _yes(self) -> None: self.dismiss(True)

    @on(Button.Pressed, "#no")
    def _no(self) -> None: self.dismiss(False)


class ModuleRow(Container):
    DEFAULT_CSS = """
    ModuleRow { height: auto; layout: horizontal; padding: 0 0 0 2; }
    ModuleRow > Static { width: 1fr; height: auto; padding: 0 1 0 0; }
    ModuleRow > Button { width: 14; height: 1; min-height: 1; }
    """

    def __init__(self, status: ToolStatus, module: Optional[Module]) -> None:
        super().__init__()
        self.status = status
        self.module = module

    def compose(self) -> ComposeResult:
        s = self.status
        dot = "[#a6e22e]●[/]" if s.available else "[#f92672]●[/]"
        line = f"{dot} [b]{s.name}[/]  [dim]{s.description}[/]"
        if not s.available:
            line += f"\n      [yellow]install:[/] [dim]{s.install_hint}[/]"
        yield Static(line)
        if not s.available and self.module is not None and is_installable(self.module):
            # Textual widget ids only allow [A-Za-z0-9_-]. Tool names like
            # `impacket-ntlmrelayx.py` contain a dot — sanitize for the id
            # and stash the real name on the button so the click handler
            # can recover it without a brittle reverse mapping.
            safe_id = "install-" + _safe_id(s.name)
            btn = Button("Install", id=safe_id, variant="primary")
            btn.tool_name = s.name  # type: ignore[attr-defined]
            yield btn


def _safe_id(name: str) -> str:
    """Squash anything that isn't A-Za-z0-9_- into an underscore."""
    import re as _re
    return _re.sub(r"[^A-Za-z0-9_-]", "_", name)


class ModulesScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("q", "dismiss", "Close"),
        Binding("m", "dismiss", "Close"),
    ]

    def __init__(self, statuses: list[ToolStatus], show_local_only: bool) -> None:
        super().__init__()
        self._statuses = statuses
        self._show_local_only = show_local_only

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="modules-box"):
            yield Label(
                "[b]Modules[/b]  [dim]— external tools vulnscout integrates with[/]\n"
            )
            missing = self._installable_missing()
            if missing:
                needs_sudo = any(command_needs_sudo(m) for m in missing)
                with Horizontal(id="modules-actions"):
                    yield Button(f"Install All ({len(missing)})",
                                 id="install-all", variant="primary")
                    if needs_sudo:
                        yield Button("Install All + sudo",
                                     id="install-all-sudo", variant="warning")
                yield Static(
                    "[dim]Install All runs the right package manager for every "
                    "missing tool. " + (
                        "Some need root — “+ sudo” asks for your password once "
                        "and installs them all without leaving vulnscout.[/]"
                        if needs_sudo else
                        "Freshly installed tools turn ✓ without a restart.[/]"
                    )
                )
            by_cat: dict = {}
            for s in self._statuses:
                if s.local_only and not self._show_local_only:
                    continue
                by_cat.setdefault(s.category, []).append(s)

            for cat in CATEGORY_ORDER:
                rows = by_cat.get(cat, [])
                if not rows:
                    continue
                yield Static(f"\n[b cyan]{CATEGORY_LABELS.get(cat, cat)}[/]")
                for s in rows:
                    yield ModuleRow(s, get_module(s.name))

            if not self._show_local_only:
                yield Static(
                    "\n[dim]Exploitation tools (metasploit / john / hashcat) hidden.\n"
                    "Set enable_local_tools=1 in Settings to surface them.[/]"
                )
            yield Label("\n[dim]Press q, Esc, or m to close[/]")

    def _installable_missing(self) -> list:
        """Missing tools that have an automatable install path on this OS."""
        out = []
        for s in self._statuses:
            if s.available:
                continue
            if s.local_only and not self._show_local_only:
                continue
            m = get_module(s.name)
            if m is not None and is_installable(m):
                out.append(m)
        return out

    def _refresh_after(self, _result: Optional[bool] = None) -> None:
        # New binaries may land in ~/.local/bin or ~/go/bin — put those on
        # PATH, then re-check so the screen flips tools to ✓ without a restart.
        ensure_install_paths()
        self._statuses = check_tools()
        try:
            self.refresh(recompose=True)
        except TypeError:
            self.app.pop_screen()
            self.app.push_screen(ModulesScreen(check_tools(), self._show_local_only))

    def _install_all(self, sudo: bool) -> None:
        targets = self._installable_missing()
        if not targets:
            return
        if sudo:
            def _got_pw(pw: Optional[str]) -> None:
                if pw is None:        # cancelled
                    return
                self.app.push_screen(
                    InstallAllScreen(targets, sudo_password=pw), self._refresh_after)
            self.app.push_screen(SudoPasswordScreen(), _got_pw)
        else:
            self.app.push_screen(
                InstallAllScreen(targets, sudo_password=""), self._refresh_after)

    @on(Button.Pressed)
    def _on_install_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "install-all":
            event.stop()
            self._install_all(sudo=False)
            return
        if bid == "install-all-sudo":
            event.stop()
            self._install_all(sudo=True)
            return
        if not bid.startswith("install-"):
            return
        # Per-tool install. Prefer the real tool name stashed on the button —
        # the id is sanitized (dots → underscores) so it can't be reversed.
        name = getattr(event.button, "tool_name", None) or bid[len("install-"):]
        m = get_module(name)
        if m is None:
            return
        self.app.push_screen(InstallProgressScreen(m), self._refresh_after)


class InstallProgressScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "noop", "", show=False)]

    def __init__(self, module: Module) -> None:
        super().__init__()
        self.module = module
        self._success = False
        self._done = False

    def compose(self) -> ComposeResult:
        with Container(id="install-box"):
            yield Label(f"[b]Installing {self.module.label}[/]")
            yield Label(f"[dim]{self.module.description}[/]")
            yield RichLog(id="install-log", markup=True, wrap=True, max_lines=2000)
            with Container(classes="row"):
                yield Button("Close", id="install-close", disabled=True)

    def on_mount(self) -> None:
        self._run_install()

    def action_noop(self) -> None: pass

    @work(exclusive=True)
    async def _run_install(self) -> None:
        log = self.query_one("#install-log", RichLog)
        async for ev in install_module(self.module):
            if ev.kind == "cmd":
                log.write(f"[b cyan]{_escape(ev.text)}[/]")
            elif ev.kind == "output":
                log.write(_escape(ev.text))
            elif ev.kind == "error":
                log.write(f"[red]ERROR: {_escape(ev.text)}[/]")
            elif ev.kind == "done":
                self._success = ev.success
                color = "#a6e22e" if ev.success else "#f92672"
                sigil = "✓" if ev.success else "✗"
                log.write(f"[b {color}]{sigil} {_escape(ev.text)}[/]")
        self._done = True
        try:
            self.query_one("#install-close", Button).disabled = False
        except Exception:
            pass

    @on(Button.Pressed, "#install-close")
    def _close(self) -> None:
        if self._done:
            self.dismiss(self._success)


class SudoPasswordScreen(ModalScreen[Optional[str]]):
    """Collect the sudo password for a bulk install.

    Returns the password string on Continue, or None if cancelled. The
    value is used for this install run only — never written to disk or
    logged.
    """

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel", show=False)]

    def compose(self) -> ComposeResult:
        with Container(id="sudo-box"):
            yield Label("[b]Enter sudo password[/]")
            yield Static(
                "[dim]Needed to install system packages (apt / gem) as root. "
                "Entered once for this run — never stored, never logged. "
                "It's validated before anything installs.[/]"
            )
            yield Input(password=True, id="sudo-pw", placeholder="sudo password")
            with Container(classes="row"):
                yield Button("Continue", id="sudo-ok", variant="primary")
                yield Button("Cancel", id="sudo-cancel")

    def on_mount(self) -> None:
        self.query_one("#sudo-pw", Input).focus()

    @on(Input.Submitted, "#sudo-pw")
    def _on_submit(self) -> None:
        self._confirm()

    @on(Button.Pressed, "#sudo-ok")
    def _on_ok(self) -> None:
        self._confirm()

    def _confirm(self) -> None:
        self.dismiss(self.query_one("#sudo-pw", Input).value)

    @on(Button.Pressed, "#sudo-cancel")
    def _on_cancel(self) -> None:
        self.dismiss(None)


class InstallAllScreen(ModalScreen[bool]):
    """Install a list of modules sequentially, streaming progress.

    On close, the modules screen re-checks tool status (and PATH) so newly
    installed tools turn ✓ without restarting vulnscout. When a sudo
    password is supplied it's validated once up front, then reused for every
    root install in the run.
    """

    BINDINGS = [Binding("escape", "noop", "", show=False)]

    def __init__(self, modules: list, sudo_password: str = "") -> None:
        super().__init__()
        self._modules = list(modules)
        self._sudo_password = sudo_password
        self._done = False
        self._ok = 0
        self._fail = 0

    def compose(self) -> ComposeResult:
        with Container(id="install-box"):
            yield Label(f"[b]Install All — {len(self._modules)} module(s)[/]")
            yield Static("", id="install-all-status")
            yield RichLog(id="install-log", markup=True, wrap=True, max_lines=8000)
            with Container(classes="row"):
                yield Button("Close", id="install-close", disabled=True)

    def on_mount(self) -> None:
        self._run_all()

    def action_noop(self) -> None:
        pass

    @work(exclusive=True)
    async def _run_all(self) -> None:
        log = self.query_one("#install-log", RichLog)
        status = self.query_one("#install-all-status", Static)

        if self._sudo_password:
            log.write("[b cyan]authenticating sudo…[/]")
            ok, msg = await sudo_authenticate(self._sudo_password)
            if ok:
                log.write(f"[#a6e22e]✓ {_escape(msg)}[/]")
            else:
                log.write(f"[#f92672]✗ sudo: {_escape(msg)}[/]")
                log.write(
                    "[yellow]Aborting — re-open Modules and try again, "
                    "or use plain “Install All”.[/]"
                )
                self._finish()
                return

        total = len(self._modules)
        for i, m in enumerate(self._modules, 1):
            status.update(
                f"[dim]{i}/{total}  ·  [#a6e22e]{self._ok} ok[/]  ·  "
                f"[#f92672]{self._fail} failed[/][/]"
            )
            log.write(f"\n[b]▶ {i}/{total}  {_escape(m.label)}[/]  [dim]{_escape(m.name)}[/]")
            success = False
            async for ev in install_module(m, sudo_password=self._sudo_password):
                if ev.kind == "cmd":
                    log.write(f"[b cyan]{_escape(ev.text)}[/]")
                elif ev.kind == "output":
                    log.write(f"[dim]{_escape(ev.text)}[/]")
                elif ev.kind == "error":
                    log.write(f"[#f92672]ERROR: {_escape(ev.text)}[/]")
                elif ev.kind == "done":
                    success = ev.success
                    color = "#a6e22e" if ev.success else "#f92672"
                    sigil = "✓" if ev.success else "✗"
                    log.write(f"[b {color}]{sigil} {_escape(ev.text)}[/]")
            self._ok += int(success)
            self._fail += int(not success)

        status.update(
            f"[b]Done — [#a6e22e]{self._ok} installed[/], "
            f"[#f92672]{self._fail} failed[/] of {total}[/]"
        )
        log.write(
            f"\n[b]Finished:[/] [#a6e22e]{self._ok} installed[/], "
            f"[#f92672]{self._fail} failed[/]"
        )
        if self._fail and not self._sudo_password:
            log.write("[yellow]Some failures may need root — try “Install All + sudo”.[/]")
        self._finish()

    def _finish(self) -> None:
        self._done = True
        try:
            self.query_one("#install-close", Button).disabled = False
        except Exception:
            pass

    @on(Button.Pressed, "#install-close")
    def _close(self) -> None:
        if self._done:
            self.dismiss(True)


# ----------------------------------------------------------------------
# Main app
# ----------------------------------------------------------------------


class VulnScoutApp(App[None]):
    CSS_PATH = "app.tcss"

    BINDINGS = [
        Binding("s", "open_settings", "Settings"),
        Binding("o", "open_opsec", "OPSEC"),
        Binding("h", "open_help", "Help"),
        Binding("m", "open_modules", "Modules"),
        Binding("e", "export_report", "Export"),
        Binding("f", "open_full_analysis", "Full Analysis"),
        Binding("g", "open_engagement", "Engagement"),
        Binding("p", "open_privesc", "Post-Exploit"),
        Binding("q", "quit_app", "Quit"),
        Binding("ctrl+c", "quit_app", "Quit", show=False),
    ]

    scanning: reactive[bool] = reactive(False)

    def __init__(self) -> None:
        super().__init__()
        # Put pipx/go/brew bin dirs on PATH so tools installed via the
        # modules screen are visible to shutil.which without a restart.
        ensure_install_paths()
        self.tool_statuses = check_tools()
        self.settings = config.load_settings()
        self.llm = LLMClient(model=self.settings["model"])
        self.orch: Optional[Orchestrator] = None
        self._unsub_bus = None
        self._scan_started_at: float = 0.0
        self._identity: Optional[IdentityInfo] = None
        # Cached materialized state — refreshed on engagement open.
        self._engagement_ctx: Optional[ScanContext] = None

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="root"):
            with VerticalScroll(id="left"):
                yield ScoutFox(id="scout-fox")
                yield Label("[b]▍ vulnscout[/b]", id="brand")

                yield Label("Target")
                yield Input(
                    placeholder="10.0.0.1 / 10.0.0.0/24 / example.com / https://x",
                    id="target",
                )

                yield Label("Target type")
                with RadioSet(id="ttype"):
                    yield RadioButton("auto", value=True, id="auto")
                    yield RadioButton("ip", id="ip")
                    yield RadioButton("cidr", id="cidr")
                    yield RadioButton("domain", id="domain")
                    yield RadioButton("url", id="url")

                yield Label("Policy")
                default_policy = (
                    self.settings.get("profile")
                    if self.settings.get("profile") in POLICIES
                    else "quick"
                )
                yield Select(
                    [(POLICIES[k].label, k) for k in POLICY_ORDER],
                    value=default_policy,
                    id="profile",
                    allow_blank=False,
                )
                yield Static(
                    f"[dim]{POLICIES[default_policy].description}[/]",
                    id="profile-desc",
                )

                with Horizontal(id="actions"):
                    yield Button("Run", id="run", variant="primary")
                    yield Button("Stop", id="stop", variant="error", disabled=True)

                yield ProgressBar(
                    total=100, show_eta=False, show_percentage=False,
                    id="nmap-progress",
                )
                yield Static("", id="progress-text")

                yield Static("[dim]idle[/]", id="status")

                if not running_as_root():
                    yield Static(
                        "[dim yellow]running unprivileged — some nmap "
                        "scan types limited[/]",
                        id="sudo-banner",
                    )

                yield IdentityPanel(id="identity")

                yield Label("Tools")
                tp = ToolCheckPanel(id="tools")
                tp.update_tools(self.tool_statuses)
                yield tp

            with Vertical(id="right"):
                # Findings stay above the feed and get their own scroll —
                # severity-ordered, always visible. Loot + Tasks live in
                # collapsibles below the feed since they're chunkier.
                with VerticalScroll(id="findings-panel"):
                    yield Label("[b]Findings[/]  [dim](0)[/]", id="findings-title")
                    yield FindingsList(id="findings")
                yield RichLog(id="feed", markup=True, wrap=True, max_lines=5000)
                with VerticalScroll(id="bottom-panels"):
                    with Collapsible(title="Loot Inventory",
                                     id="loot-section", collapsed=True):
                        yield LootList(id="loot")
                    with Collapsible(title="Tasks",
                                     id="tasks-section", collapsed=False):
                        yield TasksList(id="tasks")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "vulnscout"
        self.sub_title = "fact-driven pentest scanner"
        feed = self.query_one("#feed", RichLog)
        feed.write(
            "[b cyan]vulnscout[/]  "
            "[dim]— press s for settings, h for help, m for modules, e to export[/]"
        )
        feed.write(
            "[dim]Use only on systems you own or have explicit written "
            "authorization to test.[/]"
        )
        if self.llm.available:
            feed.write(f"[#a6e22e]✓[/] ollama up — model: [b]{self.settings['model']}[/]")
        else:
            err = self.llm.last_error or "daemon not reachable"
            feed.write(
                f"[yellow]⚠  ollama unavailable — {_escape(err)}.[/] "
                "[dim]LLM analysis will fall back to a deterministic rollup.[/]"
            )
        missing = [s.name for s in self.tool_statuses
                   if not s.available and not s.local_only]
        if missing:
            feed.write(
                f"[yellow]⚠  missing tools (will be skipped):[/] {', '.join(missing[:8])}"
                + (f" (+{len(missing) - 8} more)" if len(missing) > 8 else "")
            )
        self._refresh_identity()

    # ------------------------------------------------------------------
    # Reactive watchers
    # ------------------------------------------------------------------

    def watch_scanning(self, _old: bool, _new: bool) -> None:
        try:
            run_btn = self.query_one("#run", Button)
            run_btn.disabled = _new
            # Once a scan has happened (orch is set), button reads
            # "Re-scan" so the user knows clicking it starts fresh.
            run_btn.label = (
                "Running…" if _new
                else ("Re-scan" if self.orch is not None else "Run")
            )
            self.query_one("#stop", Button).disabled = not _new
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Actions / keybindings
    # ------------------------------------------------------------------

    def action_open_settings(self) -> None:
        self._open_settings(initial_tab="general")

    def action_open_opsec(self) -> None:
        self._open_settings(initial_tab="opsec")

    def _open_settings(self, initial_tab: str = "general") -> None:
        def _save(values: Optional[dict]) -> None:
            if values is None:
                return
            self.settings.update(values)
            self.llm = LLMClient(model=self.settings["model"])
            self.llm.reset_probe()
            if self.settings.get("profile") in POLICIES:
                try:
                    self.query_one("#profile", Select).value = self.settings["profile"]
                except Exception:
                    pass
            persisted = config.save_settings(self.settings)
            self._log_info(
                f"settings saved (model={self.settings['model']}, "
                f"ollama={'up' if self.llm.available else 'down'}"
                f"{', persisted' if persisted else ', NOT persisted'})"
            )
            if not persisted:
                self._log_warn("couldn't write settings file — they'll reset next launch")
            if not self.llm.available and self.llm.last_error:
                self._log_warn(self.llm.last_error)
            self._refresh_identity()
        self.push_screen(SettingsScreen(self.settings, initial_tab=initial_tab), _save)

    def action_open_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_open_modules(self) -> None:
        ensure_install_paths()
        statuses = check_tools()
        show_local = self.settings.get("enable_local_tools") == "1"
        self.push_screen(ModulesScreen(statuses, show_local))

    def action_open_engagement(self) -> None:
        if self.orch is None:
            self._log_warn("run a scan first — engagement uses the collected facts")
            return
        # Materialize a fresh ScanState from the live FactStore. Engagement
        # mutates this snapshot during the session; echoes back via
        # echo_state_change after each action.
        state = materialize(self.orch.store, self.orch.policy.key)
        if not state.target:
            self._log_warn("scan hasn't produced a target fact yet")
            return
        # Build a synthetic ScanContext shape engagement.py expects.
        ctx = ScanContext(state=state, opsec=self.orch.opsec)
        self._engagement_ctx = ctx
        self.push_screen(
            EngagementScreen(ctx, self.llm, self.settings, store=self.orch.store)
        )

    def action_open_privesc(self) -> None:
        """Post-exploitation / privilege-escalation helper.

        Works with or without a finished scan — it's a reference + analyzer.
        When a scan exists we seed the OS toggle from the OSGuess fact and
        surface any confirmed creds so the operator knows how to get a shell
        before escalating.
        """
        os_hint = "linux"
        banner = ""
        if self.orch is not None:
            og = self.orch.store.one("os.guess")
            name = getattr(og, "name", "") if og else ""
            if name:
                os_hint = "windows" if "windows" in name.lower() else "linux"
                banner = f"[dim]scan-detected OS:[/] {_escape(name)}"
            creds = self.orch.store.all_of(ConfirmedCred)
            if creds:
                c = creds[0]
                banner += (("\n" if banner else "")
                           + f"[#a6e22e]✓ confirmed creds:[/] [b]{_escape(c.user)}[/]:"
                             f"[dim]{_escape(c.password)}[/] ({c.service}) — land a "
                             "shell with these, then escalate")
        self.push_screen(PrivescScreen(os_hint=os_hint, banner=banner))

    def action_open_full_analysis(self) -> None:
        if self.orch is None:
            self._log_warn("no analysis available yet — run a scan first")
            return
        a = self.orch.store.one("analysis")
        text = a.text if a else ""
        if not text:
            self._log_warn("no analysis produced yet")
            return
        self.push_screen(FullAnalysisScreen(text))

    def action_export_report(self) -> None:
        if self.orch is None:
            self._log_warn("nothing to export — run a scan first")
            return
        duration = time.time() - self._scan_started_at if self._scan_started_at else 0.0
        try:
            path = report.export_report(
                self.orch.store, duration,
                profile_key=self.orch.policy.key,
            )
            self._log_info(f"report exported → {path}")
        except Exception as e:
            self._log_warn(f"export failed: {e}")

    def _refresh_identity(self) -> None:
        try:
            self.query_one("#identity", IdentityPanel).update_identity(None)
        except Exception:
            pass
        self._probe_identity()

    @work(thread=True)
    def _probe_identity(self) -> None:
        info = check_identity()
        self.call_from_thread(self._set_identity, info)

    def _set_identity(self, info: IdentityInfo) -> None:
        self._identity = info
        try:
            self.query_one("#identity", IdentityPanel).update_identity(info)
        except Exception:
            pass

    @work
    async def action_quit_app(self) -> None:
        if self.scanning:
            confirm = await self.push_screen_wait(ConfirmQuitScreen())
            if not confirm:
                return
            if self.orch is not None:
                self.orch.cancel()
        self.exit()

    @on(Select.Changed, "#profile")
    def _on_profile_changed(self, event: Select.Changed) -> None:
        if event.value and event.value != Select.BLANK:
            try:
                desc = POLICIES[event.value].description
                self.query_one("#profile-desc", Static).update(f"[dim]{desc}[/]")
            except KeyError:
                pass

    @on(Button.Pressed, "#run")
    def _on_run(self) -> None:
        if self.scanning:
            return
        # If a previous scan finished, clicking Run again resets state and
        # starts a fresh one. There's no per-phase incremental run anymore.
        if self.orch is not None:
            self._reset_scan_state()

        target = self.query_one("#target", Input).value.strip()
        ok, err = validate_target(target)
        if not ok:
            self._log_warn(f"invalid target: {err}")
            return

        rs = self.query_one("#ttype", RadioSet)
        ttype_id = rs.pressed_button.id if rs.pressed_button else "auto"
        ttype = detect_target_type(target) if ttype_id == "auto" else ttype_id

        profile_value = self.query_one("#profile", Select).value
        policy_key = profile_value if isinstance(profile_value, str) else "quick"

        opsec = OpsecSettings.from_settings(self.settings)
        # Stealth/paranoid auto-enable certain knobs.
        if policy_key in ("stealth", "paranoid"):
            opsec = opsec.merged_with_profile(policy_key)

        self._announce_opsec(opsec, target, ttype)

        self.orch = Orchestrator(
            opsec, policy_key=policy_key,
            hunter_api_key=self.settings.get("hunter_api_key", ""),
            model=self.settings.get("model", "gemma3:3b"),
        )
        # Subscribe to events. Unsubscribed on scan finish.
        self._unsub_bus = self.orch.bus.subscribe(self._on_event)
        self._scan_started_at = time.time()
        self._run_scan(target, ttype)

    def _announce_opsec(
        self, opsec: OpsecSettings, target: str, ttype: str,
    ) -> None:
        import shutil as _shutil
        bits: list[str] = []
        if opsec.tor:
            bits.append("tor")
        if opsec.proxychains:
            bits.append("proxychains")
        if opsec.delay_enabled:
            bits.append(f"delays {opsec.delay_min:g}-{opsec.delay_max:g}s")
        if opsec.user_agent_random:
            bits.append("UA randomization")
        if opsec.nmap_source_port:
            bits.append("nmap --source-port 53")
        if opsec.nmap_fragment:
            bits.append("nmap -f")
        if bits:
            self._log_info("OPSEC active: " + ", ".join(bits))

        if opsec.tor and not _shutil.which("torsocks"):
            self._log_warn(
                "tor toggle is on but `torsocks` is not installed — "
                "traffic will go out un-wrapped"
            )
        if opsec.proxychains and not _shutil.which("proxychains4"):
            self._log_warn(
                "proxychains toggle is on but `proxychains4` is not installed — "
                "traffic will go out un-wrapped"
            )

        warn = anonymization_warning(target, ttype, opsec, self._identity)
        if warn:
            self._log_warn(warn)

    @on(Button.Pressed, "#stop")
    def _on_stop(self) -> None:
        if self.orch is not None and self.scanning:
            self.orch.cancel()
            self._log_warn("stop requested — killing child processes")

    # ------------------------------------------------------------------
    # Scan execution (orchestrator-driven)
    # ------------------------------------------------------------------

    @work(exclusive=True)
    async def _run_scan(self, target: str, target_type: str) -> None:
        assert self.orch is not None
        self.scanning = True
        self._reset_progress()
        self._set_status(f"running on {target} [{self.orch.policy.label}]")
        try:
            await self.orch.run(target=target, target_type=target_type)
        except asyncio.CancelledError:
            self._log_warn("scan cancelled")
            raise
        except Exception as e:
            self._log_warn(f"scan crashed: {e}")
        finally:
            self.scanning = False

    async def _on_event(self, ev: Event) -> None:
        """Single subscriber on the EventBus — dispatches to UI updates."""
        feed = self.query_one("#feed", RichLog)
        if isinstance(ev, ScanStarted):
            feed.write(f"[b cyan]▶ scan starting on {_escape(ev.target)}[/]")
        elif isinstance(ev, ScanFinished):
            note = "cancelled" if ev.cancelled else "complete"
            feed.write(
                f"[b #a6e22e]●[/] scan {note} in {ev.duration_s:.1f}s"
            )
            self._set_status(f"{note} in {ev.duration_s:.1f}s")
            # Re-label run button now that orch exists.
            try:
                self.query_one("#run", Button).label = "Re-scan"
            except Exception:
                pass
            # Update findings title with the post-scan summary so the
            # user can read the result at a glance.
            self._update_findings_title(post_scan=True)
        elif isinstance(ev, TaskStarted):
            tasks = self.query_one("#tasks", TasksList)
            tasks.started(ev.task, ev.label or ev.task)
            feed.write(f"[b cyan]▶ {ev.label or ev.task}[/]")
        elif isinstance(ev, TaskOutput):
            feed.write(f"[dim]{ev.task:<14}[/]  {_escape(ev.text)}")
        elif isinstance(ev, TaskProgress):
            self._update_progress(ev.percent, ev.etc)
        elif isinstance(ev, TaskFinished):
            tasks = self.query_one("#tasks", TasksList)
            tasks.finished(ev.task, ev.duration_s, ev.facts_emitted)
        elif isinstance(ev, TaskSkipped):
            tasks = self.query_one("#tasks", TasksList)
            tasks.skipped(ev.task, ev.reason)
        elif isinstance(ev, TaskFailed):
            tasks = self.query_one("#tasks", TasksList)
            tasks.failed(ev.task, ev.error)
            feed.write(f"[red]✗ {ev.task}: {_escape(ev.error)}[/]")
        elif isinstance(ev, StatusEv):
            sigil = {"warning": "⚠", "error": "✗"}.get(ev.severity, "i")
            color = {"warning": "yellow", "error": "red"}.get(ev.severity, "cyan")
            feed.write(f"[{color}]{sigil} {_escape(ev.text)}[/]")
        elif isinstance(ev, FactEmitted):
            await self._on_fact(ev.fact)

    async def _on_fact(self, f) -> None:
        """Render fact-emit events: findings into the panel, loot into
        the loot list, analysis into the feed."""
        feed = self.query_one("#feed", RichLog)
        if isinstance(f, FactFinding):
            try:
                self.query_one("#findings", FindingsList).add(f)
                self._update_findings_title()
            except Exception:
                pass
            color = SEVERITY_COLOR.get(f.severity.upper(), "white")
            feed.write(
                f"[{color}]✦ [{f.severity}][/]  [dim]{f.tool}[/] — "
                f"{_escape(f.summary)}"
            )
        elif isinstance(f, IntelSummary):
            feed.write(f"[#a6e22e]✓ intel summary built[/]")
        elif isinstance(f, Analysis):
            feed.write(f"[b #a6e22e]✓ analysis ready[/]  [dim](press f to view)[/]")
        elif f.kind in (
            "loot.confirmed_cred", "loot.hash", "loot.credential",
            "loot.username", "loot.host", "loot.version", "loot.path",
            "loot.git_exposed",
        ):
            try:
                if self.orch is not None:
                    self.query_one("#loot", LootList).render_from_store(self.orch.store)
            except Exception:
                pass

    def _update_findings_title(self, post_scan: bool = False) -> None:
        try:
            count = self.query_one("#findings", FindingsList).count
            base = f"[b]Findings[/]  [dim]({count})[/]"
            if post_scan and self.orch is not None:
                store = self.orch.store
                # Per-severity counts so the user reads the result at a glance.
                from .core.facts import Finding as _F
                sev_counts: dict = {}
                for f in store.all_of(_F):
                    s = f.severity.upper()
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                bits = []
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    if sev_counts.get(s):
                        color = SEVERITY_COLOR[s]
                        bits.append(f"[{color}]{sev_counts[s]} {s}[/]")
                ports = len(store.by_kind("port.open"))
                cves = len(store.by_kind("cve"))
                tail_bits = []
                if ports:
                    tail_bits.append(f"{ports} port(s)")
                if cves:
                    tail_bits.append(f"{cves} CVE(s)")
                tail = (
                    "  ·  " + " · ".join(tail_bits) if tail_bits else ""
                )
                if bits:
                    base += "   " + "  ".join(bits) + tail
                else:
                    base += "  [dim]— no findings produced[/]" + tail
            self.query_one("#findings-title", Label).update(base)
        except Exception:
            pass

    def _update_progress(self, percent: float, etc: str) -> None:
        try:
            self.query_one("#nmap-progress", ProgressBar).update(progress=percent)
            label = self.query_one("#progress-text", Static)
            if percent <= 0:
                label.update("")
            elif etc:
                label.update(f"[dim]{percent:.1f}% — ETC: {etc}[/]")
            else:
                label.update(f"[dim]{percent:.1f}%[/]")
        except Exception:
            pass

    def _reset_progress(self) -> None:
        self._update_progress(0.0, "")

    def _reset_scan_state(self) -> None:
        if self.orch is not None and self._engagement_ctx is not None:
            cleanup_tmpfiles(self._engagement_ctx.state)
        if self._unsub_bus:
            self._unsub_bus()
            self._unsub_bus = None
        self.orch = None
        self._engagement_ctx = None
        self._scan_started_at = 0.0
        try:
            self.query_one("#findings", FindingsList).clear()
            self.query_one("#loot", LootList).update("[dim]no loot yet[/]")
            self.query_one("#tasks", TasksList).reset()
        except Exception:
            pass
        self._reset_progress()
        self._set_status("idle")
        self.query_one("#feed", RichLog).clear()
        self._update_findings_title()

    # ------------------------------------------------------------------
    # Tiny logging helpers
    # ------------------------------------------------------------------

    def _log_info(self, msg: str) -> None:
        self.query_one("#feed", RichLog).write(f"[cyan]i[/] {_escape(msg)}")

    def _log_warn(self, msg: str) -> None:
        self.query_one("#feed", RichLog).write(f"[yellow]⚠[/] {_escape(msg)}")

    def _set_status(self, msg: str) -> None:
        self.query_one("#status", Static).update(f"[b]{_escape(msg)}[/]")
