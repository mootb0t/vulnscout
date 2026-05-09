"""Module registry — central source of truth for every external tool
vulnscout integrates with.

Each Module describes one binary, what it does, where it sits in the scan
flow, and how to install it. The registry powers:

  - the startup PATH check (toolcheck.py reads from here)
  - the modules screen (app.py shows status grouped by category)
  - the chain runner (scanner.py uses category + trigger metadata)
  - the one-click installer (installer.py picks the best command for
    the current platform from the install_* fields below)

Categories
----------
  core            — nmap, searchsploit, nuclei, ollama
  passive-osint   — no packets to target (shodan, theHarvester, subfinder, dnsrecon)
  network         — active host / port discovery (masscan, enum4linux)
  web             — web-stack inspection (whatweb..ffuf..sqlmap..wpscan)
  exploitation    — LOCAL ONLY, never bundled in public release
                    (metasploit suggestions, hashcat, john)

Install commands
----------------
Each install_* field carries the exact shell command for that package
manager — the installer parses it directly. Empty string means "this
package manager doesn't carry the tool". The installer falls through:

    macOS:  install_brew → install_pip → install_gem → install_go → install_curl
    Linux:  install_apt  → install_pip → install_gem → install_go → install_curl

Verified against Homebrew core / Debian apt / PyPI / RubyGems as of 2026.
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Module:
    name: str                       # binary name to look up in PATH
    label: str                      # display name in modules screen
    description: str                # one-line summary
    category: str                   # see module docstring
    install_brew: str = ""          # macOS Homebrew command, fully formed
    install_apt: str = ""           # Debian/Ubuntu apt command
    install_pip: str = ""           # Python tool — "pip install <pkg>" form
    install_gem: str = ""           # Ruby tool — "gem install <pkg>" form
    install_go: str = ""            # Go-binary fallback for Linux without apt
    install_curl: str = ""          # vendor install script (e.g. ollama)
    local_only: bool = False        # exploitation tools — gated behind a setting
    needs_api_key: bool = False     # surfaces a settings-modal prompt
    needs_sudo_apt: bool = True     # apt installs need sudo (vs go/pip --user)
    notes: str = ""                 # extra context shown in the modules screen


# Order roughly follows scan-chain phase + category, so the modules screen
# reads in execution order top-to-bottom.
MODULES: List[Module] = [
    # ---- passive osint (run first, no packets to target) ----
    Module(
        name="whois",
        label="whois",
        description="Domain registration / nameserver lookup — pure passive",
        category="passive-osint",
        # Pre-installed on macOS and most Linux distros, but list installs
        # for the rare environment that doesn't ship it.
        install_brew="brew install whois",
        install_apt="apt-get install -y whois",
        notes="Already present on most systems. No packets sent to target.",
    ),
    Module(
        name="waybackurls",
        label="waybackurls",
        description="Historical URLs from the Wayback Machine — passive",
        category="passive-osint",
        # No homebrew/apt package; Go install is the upstream route.
        install_go="go install github.com/tomnomnom/waybackurls@latest",
        notes="Surfaces admin/api/login/backup/config/upload paths from archive history.",
    ),
    Module(
        name="shodan",
        label="Shodan CLI",
        description="Passive lookup against Shodan's public index — no packets to target",
        category="passive-osint",
        # Shodan CLI is Python-only; no Homebrew or apt formula.
        install_pip="pip install shodan",
        needs_api_key=True,
        notes="Set Shodan API key in Settings (S) — without it, this module is skipped.",
    ),
    Module(
        name="theHarvester",
        label="theHarvester",
        description="Email / subdomain / host OSINT from public sources",
        category="passive-osint",
        install_brew="brew install theharvester",
        install_apt="apt-get install -y theharvester",
        install_pip="pip install theHarvester",
    ),
    Module(
        name="subfinder",
        label="subfinder",
        description="Passive subdomain enumeration",
        category="passive-osint",
        install_brew="brew install subfinder",
        install_apt="apt-get install -y subfinder",
        install_go="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    Module(
        name="dnsrecon",
        label="dnsrecon",
        description="DNS enumeration + zone transfer attempts",
        category="passive-osint",
        install_brew="brew install dnsrecon",
        install_apt="apt-get install -y dnsrecon",
        install_pip="pip install dnsrecon",
    ),

    # ---- network (active host/port discovery) ----
    Module(
        name="masscan",
        label="masscan",
        description="Fast host discovery for CIDR ranges; feeds live IPs to nmap",
        category="network",
        install_brew="brew install masscan",
        install_apt="apt-get install -y masscan",
        notes="CIDR targets only. Needs sudo for SYN sending.",
    ),
    Module(
        name="nmap",
        label="nmap",
        description="Network port + service scanner",
        category="core",
        install_brew="brew install nmap",
        install_apt="apt-get install -y nmap",
    ),
    Module(
        name="enum4linux",
        label="enum4linux",
        description="SMB share / user enumeration",
        category="network",
        # No homebrew core formula — enum4linux requires Samba binaries
        # (rpcclient, smbclient, nmblookup) that don't exist on macOS.
        install_apt="apt-get install -y enum4linux",
        notes="Linux only — depends on Samba binaries not available on macOS.",
    ),

    # ---- web ----
    Module(
        name="whatweb",
        label="whatweb",
        description="Web technology fingerprinter; output drives wpscan trigger",
        category="web",
        # No homebrew core formula — whatweb is a Ruby tool; gem is the
        # cross-platform install. apt covers standard Debian/Ubuntu/Kali.
        install_apt="apt-get install -y whatweb",
        install_gem="gem install whatweb",
    ),
    Module(
        name="wafw00f",
        label="wafw00f",
        description="Web Application Firewall detector",
        category="web",
        # No homebrew core formula — pip install is the canonical route on
        # macOS and the fallback on Linux when apt is unavailable.
        install_apt="apt-get install -y wafw00f",
        install_pip="pip install wafw00f",
    ),
    Module(
        name="gowitness",
        label="gowitness",
        description="Auto-screenshots all open HTTP/HTTPS services",
        category="web",
        # No homebrew core formula and no apt package; go install is the
        # canonical route on both macOS and Linux.
        install_go="go install github.com/sensepost/gowitness@latest",
        notes="Screenshots saved to ./reports/screenshots/<scan>/",
    ),
    Module(
        name="nikto",
        label="nikto",
        description="Web server vulnerability scanner",
        category="web",
        install_brew="brew install nikto",
        install_apt="apt-get install -y nikto",
    ),
    Module(
        name="ffuf",
        label="ffuf",
        description="Recursive directory fuzzer (primary, gobuster is fallback)",
        category="web",
        install_brew="brew install ffuf",
        install_apt="apt-get install -y ffuf",
        install_go="go install github.com/ffuf/ffuf/v2@latest",
    ),
    Module(
        name="gobuster",
        label="gobuster",
        description="Directory bruteforcer (fallback when ffuf is missing)",
        category="web",
        install_brew="brew install gobuster",
        install_apt="apt-get install -y gobuster",
        install_go="go install github.com/OJ/gobuster/v3@latest",
    ),
    Module(
        name="sqlmap",
        label="sqlmap",
        description="SQL injection scanner — passive detection only, no exploitation",
        category="web",
        install_brew="brew install sqlmap",
        install_apt="apt-get install -y sqlmap",
        install_pip="pip install sqlmap",
        notes="Triggers on URL targets or when nikto reports forms. --level=1 --risk=1.",
    ),
    Module(
        name="wpscan",
        label="wpscan",
        description="WordPress vulnerability scanner",
        category="web",
        # No homebrew formula. apt-get install wpscan only works on Kali/Parrot
        # — it is not in standard Debian/Ubuntu repos. gem is the canonical
        # install for both macOS and non-Kali Linux.
        install_gem="gem install wpscan",
        notes="Auto-runs only if whatweb's output mentions WordPress.",
    ),
    Module(
        name="sslscan",
        label="sslscan",
        description="TLS cipher and certificate audit",
        category="web",
        install_brew="brew install sslscan",
        install_apt="apt-get install -y sslscan",
    ),

    # ---- analysis core ----
    Module(
        name="searchsploit",
        label="searchsploit",
        description="Local exploit-db lookup (fed nmap XML directly)",
        category="core",
        install_brew="brew install exploitdb",
        install_apt="apt-get install -y exploitdb",
    ),
    Module(
        name="nuclei",
        label="nuclei",
        description="Template-based vulnerability scanner",
        category="core",
        install_brew="brew install nuclei",
        # No apt package upstream; fall through to go install on Linux.
        install_go="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    Module(
        name="ollama",
        label="ollama",
        description="Local LLM runtime — turns raw output into plain-english findings",
        category="core",
        install_brew="brew install ollama",
        # Linux: vendor install script is the only official route.
        install_curl="curl -fsSL https://ollama.com/install.sh | sh",
        notes="After install, run `ollama pull <model>` and start with `ollama serve`.",
    ),

    # ---- exploitation (LOCAL ONLY — gated behind enable_local_tools) ----
    Module(
        name="hydra",
        label="hydra",
        description="Network login brute-forcer — drives Phase 4 SSH/SMB actions",
        category="exploitation",
        install_brew="brew install hydra",
        install_apt="apt-get install -y hydra",
        local_only=True,
        notes="LOCAL ONLY. Phase 4 builds hydra commands but never runs "
              "them without explicit per-action confirmation.",
    ),
    Module(
        name="sshpass",
        label="sshpass",
        description="Non-interactive ssh password helper (Phase 4 follow-ups)",
        category="exploitation",
        install_brew="brew install hudochenkov/sshpass/sshpass",
        install_apt="apt-get install -y sshpass",
        local_only=True,
        notes="LOCAL ONLY. Used to log into a host with a credential hydra "
              "just confirmed. Note: macOS Homebrew core dropped sshpass; "
              "the hudochenkov tap is the maintained route.",
    ),
    Module(
        name="smbclient",
        label="smbclient",
        description="SMB client — Phase 4 share-listing follow-up",
        category="exploitation",
        install_brew="brew install samba",
        install_apt="apt-get install -y smbclient",
        local_only=True,
        notes="LOCAL ONLY. Part of the Samba suite; Phase 4 uses it to "
              "list shares with a credential hydra confirmed.",
    ),
    Module(
        name="msfconsole",
        label="metasploit",
        description="Cross-references CVEs against MSF module DB — suggestions only, "
                    "never auto-runs",
        category="exploitation",
        # macOS: cask, not formula. The bare `brew install metasploit` formula
        # was removed years ago — only the cask works now.
        # Linux: metasploit-framework is NOT in standard Debian/Ubuntu repos.
        # Kali/Parrot ship it pre-installed. For everything else, Rapid7's
        # vendor curl script is the only officially supported route.
        install_brew="brew install --cask metasploit",
        install_curl="curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash",
        local_only=True,
        notes="LOCAL ONLY. Lists which findings have ready-to-run MSF modules. "
              "Never executes anything automatically. "
              "On Kali/Parrot it's pre-installed; on other Linux the curl installer "
              "sets up Rapid7's repo and installs from there.",
    ),
    Module(
        name="hashcat",
        label="hashcat",
        description="GPU password cracker — manual trigger only, post-discovery",
        category="exploitation",
        install_brew="brew install hashcat",
        install_apt="apt-get install -y hashcat",
        local_only=True,
        notes="LOCAL ONLY. Auto-detects CUDA / Metal availability. Never auto-triggers.",
    ),
    Module(
        name="john",
        label="john the ripper",
        description="Password cracker — manual trigger only, post-discovery",
        category="exploitation",
        install_brew="brew install john-jumbo",
        install_apt="apt-get install -y john",
        local_only=True,
        notes="LOCAL ONLY. macOS gets john-jumbo (more formats). Never auto-triggers.",
    ),

    # ---- Modern recon (ProjectDiscovery family) ----
    Module(
        name="httpx",
        label="httpx",
        description="Live HTTP probe across host lists — replaces hand-rolled liveness checks",
        category="passive-osint",
        install_brew="brew install httpx",
        # ProjectDiscovery's httpx is published as `httpx` on Homebrew but the
        # binary collides with the Python httpx library. We rely on the
        # pentest tool being first in PATH; if a user has Python httpx
        # installed they'll need to re-order or alias.
        install_go="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        notes="ProjectDiscovery httpx (NOT the Python lib). Probes live HTTP/HTTPS, "
              "extracts titles, tech, status — feeds Phase 1 & 2.",
    ),
    Module(
        name="naabu",
        label="naabu",
        description="Fast SYN port scanner (ProjectDiscovery) — feeds nmap with live ports",
        category="network",
        install_brew="brew install naabu",
        install_go="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        notes="Lighter alternative to masscan for non-CIDR sweeps.",
    ),
    Module(
        name="katana",
        label="katana",
        description="Headless web crawler — discovers JS-rendered endpoints httpx/ffuf can't see",
        category="web",
        install_brew="brew install katana",
        install_go="go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        notes="Used in discovery to surface SPA / JS-only routes.",
    ),
    Module(
        name="dnsx",
        label="dnsx",
        description="Fast DNS resolver / brute — replaces dnsrecon for the bulk of discovery",
        category="passive-osint",
        install_brew="brew install dnsx",
        install_go="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    ),

    # ---- Modern AD / internal post-exploitation ----
    Module(
        name="nxc",
        label="netexec (nxc)",
        description="The modern AD swiss-army CLI — SMB/WinRM/LDAP/MSSQL/SSH spray, "
                    "share enum, kerberos, BloodHound. Replaces crackmapexec.",
        category="exploitation",
        install_pip="pipx install netexec",
        # No brew/apt formula yet (project is young, fast-moving).
        local_only=True,
        notes="LOCAL ONLY. Phase 4 builds nxc commands across SMB/WinRM/LDAP "
              "but never runs them without explicit per-action confirmation.",
    ),
    Module(
        name="certipy-ad",
        label="Certipy",
        description="Active Directory Certificate Services attack tool (ESC1-ESC13)",
        category="exploitation",
        install_pip="pipx install certipy-ad",
        local_only=True,
        notes="LOCAL ONLY. Phase 4 queues ADCS find/abuse actions when port 80/443 "
              "+ AD context detected.",
    ),
    Module(
        name="impacket-ntlmrelayx.py",
        label="ntlmrelayx",
        description="NTLM relay / coercion attack toolkit (impacket)",
        category="exploitation",
        install_pip="pipx install impacket",
        local_only=True,
        notes="LOCAL ONLY. Phase 4 hints at ntlmrelayx when SMB signing not "
              "required, or when Responder/mitm6 captures relay-able auth.",
    ),
    Module(
        name="responder",
        label="Responder",
        description="LLMNR/NBT-NS/MDNS poisoner — captures NetNTLMv2 on local networks",
        category="exploitation",
        install_apt="apt-get install -y responder",
        local_only=True,
        notes="LOCAL ONLY. Internal-engagement tool — only useful when you're "
              "on the same broadcast domain as the target.",
    ),
    Module(
        name="mitm6",
        label="mitm6",
        description="IPv6-DHCP / DNS poisoning to coerce auth in dual-stack networks",
        category="exploitation",
        install_pip="pipx install mitm6",
        local_only=True,
        notes="LOCAL ONLY. Pairs with ntlmrelayx for the canonical AD relay chain.",
    ),
    Module(
        name="evil-winrm",
        label="evil-winrm",
        description="Windows Remote Management shell with creds — fast WinRM access",
        category="exploitation",
        install_gem="gem install evil-winrm",
        local_only=True,
        notes="LOCAL ONLY. Auto-queued post-cred when port 5985/5986 confirmed open.",
    ),
    Module(
        name="kerbrute",
        label="kerbrute",
        description="Kerberos pre-auth user enumeration + password spraying",
        category="exploitation",
        install_go="go install github.com/ropnop/kerbrute@latest",
        local_only=True,
        notes="LOCAL ONLY. Less noisy than SMB / SSH brute on AD targets.",
    ),
    Module(
        name="bloodhound-python",
        label="bloodhound.py",
        description="BloodHound collector (Python) — builds AD attack graphs from creds",
        category="exploitation",
        install_pip="pipx install bloodhound",
        local_only=True,
        notes="LOCAL ONLY. Phase 4 queues a collection run when domain creds are confirmed.",
    ),
    Module(
        name="smbmap",
        label="smbmap",
        description="SMB share content walker — recursive listing, regex grep",
        category="exploitation",
        install_pip="pipx install smbmap",
        install_apt="apt-get install -y smbmap",
        local_only=True,
        notes="LOCAL ONLY. Auto-queued post-cred when SMB ports detected.",
    ),
    Module(
        name="linpeas.sh",
        label="linpeas",
        description="Linux privilege-escalation enumerator — runs after SSH login confirms creds",
        category="exploitation",
        # linpeas is distributed as a single shell script, not a package.
        # We treat its presence in PATH as the install signal; users
        # commonly drop it under ~/.local/bin or /usr/local/bin.
        install_curl="curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /usr/local/bin/linpeas.sh && chmod +x /usr/local/bin/linpeas.sh",
        local_only=True,
        notes="LOCAL ONLY. Distributed as a script, not a package — installer "
              "downloads the latest release. Phase 4 hints at piping into a "
              "confirmed SSH session.",
    ),

    # ---- Specialty / surface-specific tooling ----
    Module(
        name="mobsf",
        label="MobSF",
        description="Mobile Security Framework — APK/IPA static + dynamic analysis",
        category="exploitation",
        install_pip="pipx install mobsfscan",
        local_only=True,
        notes="LOCAL ONLY. mobsfscan is the headless static-analysis CLI — "
              "the full MobSF web UI is a separate Docker install.",
    ),
    Module(
        name="pret",
        label="PRET",
        description="Printer Exploitation Toolkit — IPP/PJL/PostScript on ports 631/9100",
        category="exploitation",
        # PRET is a python script (no formula); github clone or pipx via fork.
        install_pip="pipx install pret",
        local_only=True,
        notes="LOCAL ONLY. Phase 4 queues capture-print-job / shutdown-printer "
              "actions when port 9100 (raw print) or 631 (IPP) is open.",
    ),
]


# Categories listed in display order for the modules screen.
CATEGORY_ORDER = ("passive-osint", "network", "core", "web", "exploitation")
CATEGORY_LABELS = {
    "passive-osint": "Passive OSINT",
    "network":       "Network",
    "core":          "Core",
    "web":           "Web",
    "exploitation":  "Exploitation (local only)",
}


def get_module(name: str) -> Optional[Module]:
    """Look up a module by its binary name."""
    for m in MODULES:
        if m.name == name:
            return m
    return None


def best_install_hint(m: Module) -> str:
    """Pick the most likely install command for the user's platform — used
    for *display* in the startup screen and modules screen. The actual
    installer (installer.py) does its own platform-aware picking with
    fallbacks; this is just for the human-readable hint.
    """
    import sys
    if sys.platform == "darwin":
        for hint in (m.install_brew, m.install_pip, m.install_gem, m.install_curl):
            if hint:
                return hint
    if sys.platform.startswith("linux"):
        for hint in (m.install_apt, m.install_pip, m.install_gem,
                     m.install_go, m.install_curl):
            if hint:
                return hint
    # Fallback for unknown platforms
    for hint in (m.install_brew, m.install_apt, m.install_pip,
                 m.install_gem, m.install_go, m.install_curl):
        if hint:
            return hint
    return "(no install hint)"
