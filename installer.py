"""One-click installer for vulnscout modules.

Picks the best install command for the current platform from a Module's
install_* fields, runs it as a subprocess, and streams output as
InstallEvent objects so the UI can render progress live.

Platform preference
-------------------
  macOS  : brew → pipx → pip --user → gem → go install → curl-script
  Linux  : apt-get → pipx → pip --user → gem → go install → curl-script

`apt-get` is preferred over `apt` because it's stable for scripting (apt
prints a warning when used non-interactively). pipx is preferred over
pip because Python 3.12+ refuses `pip install` outside a venv (PEP 668)
unless you pass --break-system-packages.

Sudo handling
-------------
Linux installs that need root (apt-get, system gem) are prefixed with
sudo. Two modes:

  - no password  → `sudo -n` (non-interactive): succeeds only with
    passwordless or already-cached sudo, else fails with a clear error.
  - with password → `sudo -S -p ''`: the password is fed on the process's
    stdin. `sudo_authenticate()` validates+caches the password up front so
    the modules screen can install every root package in one run without
    the user leaving the TUI.

`ensure_install_paths()` adds the dirs package managers drop binaries into
(~/.local/bin, ~/go/bin, brew prefixes, ...) to PATH so a freshly
installed tool is visible to `shutil.which` WITHOUT restarting vulnscout.
"""

import asyncio
import os
import shlex
import shutil
import sys
from dataclasses import dataclass
from typing import AsyncIterator, List, Optional, Tuple

from .modules import Module


# ----------------------------------------------------------------------
# Events
# ----------------------------------------------------------------------


@dataclass
class InstallEvent:
    """One step of an in-progress install, surfaced to the UI."""

    kind: str           # 'cmd' | 'output' | 'done' | 'error'
    text: str = ""
    success: bool = False  # only meaningful for kind=='done'


# ----------------------------------------------------------------------
# Command picker
# ----------------------------------------------------------------------


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _with_sudo(cmd: List[str], password: str = "") -> List[str]:
    """Prefix sudo unless we're already root or sudo isn't on PATH.

    With a password we use `sudo -S -p ''` (read the secret from stdin,
    suppress the prompt) — install_module() feeds it on the process's
    stdin. Without one we use `sudo -n` (non-interactive), which only
    succeeds when the user already has passwordless or freshly-cached sudo.
    """
    if _is_root() or not shutil.which("sudo"):
        return cmd
    if password:
        return ["sudo", "-S", "-p", ""] + cmd
    return ["sudo", "-n"] + cmd


def _python_pkg(install_pip: str) -> str:
    """Extract the package name from a `pip install <pkg>` string."""
    parts = install_pip.split()
    return parts[-1] if parts else ""


def pick_install_command(
    m: Module, sudo_password: str = "",
) -> Tuple[Optional[List[str]], str]:
    """Return (argv, description) for the best install command.

    The argv is ready to pass to asyncio.create_subprocess_exec. When the
    command needs a shell (e.g. the ollama curl|sh script), argv[0] is
    "bash"/"sh" with the pipeline as a single argument.

    description is a short human-readable label like "via Homebrew" that
    the UI shows under the "Installing X..." header.

    Returns (None, reason) when no automatable path exists for this
    platform — e.g. the module only has a brew command but the user is
    on Linux without brew.
    """
    is_mac = sys.platform == "darwin"
    is_linux = sys.platform.startswith("linux")

    # ---- macOS: brew first ----
    if is_mac and m.install_brew and shutil.which("brew"):
        return shlex.split(m.install_brew), "via Homebrew"

    # ---- Linux: apt-get first ----
    if is_linux and m.install_apt and shutil.which("apt-get"):
        cmd = shlex.split(m.install_apt)
        if m.needs_sudo_apt:
            cmd = _with_sudo(cmd, sudo_password)
        return cmd, "via apt-get" if _is_root() else "via apt-get (sudo)"

    # ---- pipx (preferred) → pip3 --user → pip --user ----
    if m.install_pip:
        pkg = _python_pkg(m.install_pip)
        if pkg:
            if shutil.which("pipx"):
                return ["pipx", "install", pkg], "via pipx"
            if shutil.which("pip3"):
                return ["pip3", "install", "--user", pkg], "via pip3 --user"
            if shutil.which("pip"):
                return ["pip", "install", "--user", pkg], "via pip --user"

    # ---- gem ----
    if m.install_gem and shutil.which("gem"):
        cmd = shlex.split(m.install_gem)
        # On Linux, system Ruby's gem dir usually needs root; macOS
        # Homebrew Ruby's gem dir is user-writable.
        if is_linux and not _is_root():
            cmd = _with_sudo(cmd, sudo_password)
        return cmd, "via gem"

    # ---- go install (macOS + Linux fallback for tools without brew/apt) ----
    if m.install_go and shutil.which("go"):
        return shlex.split(m.install_go), "via go install"

    # ---- vendor curl script (e.g. ollama on Linux) ----
    if m.install_curl:
        # Pipe needs a shell. Wrap the whole pipeline in `sh -c` so the
        # subprocess call is a single argv that includes |.
        return ["sh", "-c", m.install_curl], "via vendor install script"

    # ---- Nothing worked ----
    if is_mac:
        return None, (
            f"no install path available — Homebrew not in PATH, "
            f"or {m.name} doesn't have a brew/pip/gem entry"
        )
    if is_linux:
        return None, (
            f"no install path available — apt-get/pipx/gem/go all unavailable, "
            f"or {m.name} doesn't expose one"
        )
    return None, "no install path available for this platform"


# ----------------------------------------------------------------------
# Async runner
# ----------------------------------------------------------------------


async def install_module(
    m: Module, sudo_password: str = "",
) -> AsyncIterator[InstallEvent]:
    """Run the install command for `m` and yield InstallEvent updates.

    Never raises — failures are surfaced as InstallEvent(kind='error') so
    the caller can render them without try/except wrappers. When
    `sudo_password` is supplied and the chosen command uses `sudo -S`, the
    password is fed on stdin.
    """
    cmd, desc = pick_install_command(m, sudo_password)
    if cmd is None:
        yield InstallEvent("error", text=desc)
        return

    # Don't echo the password — the argv never contains it (it goes on
    # stdin), but mask defensively in case a command form ever changed.
    yield InstallEvent("cmd", text=f"$ {' '.join(shlex.quote(p) for p in cmd)}")
    yield InstallEvent("output", text=f"[{desc}]")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as e:
        yield InstallEvent("error", text=f"binary not found: {cmd[0]} ({e})")
        return
    except Exception as e:
        yield InstallEvent("error", text=f"failed to start: {e}")
        return

    # Feed the sudo password if this command reads it from stdin, then close
    # stdin so anything else reading it gets EOF instead of hanging.
    if proc.stdin is not None:
        try:
            if sudo_password and "sudo" in cmd and "-S" in cmd:
                proc.stdin.write((sudo_password + "\n").encode())
                await proc.stdin.drain()
        except Exception:
            pass
        try:
            proc.stdin.close()
        except Exception:
            pass

    assert proc.stdout is not None
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        yield InstallEvent("output", text=line.decode(errors="replace").rstrip())

    rc = await proc.wait()
    success = rc == 0
    if success:
        yield InstallEvent("done", text=f"installed cleanly (exit 0)", success=True)
    else:
        # Common case: sudo -n with no cached creds → rc=1 and a useful stderr.
        yield InstallEvent(
            "done",
            text=f"failed with exit code {rc}",
            success=False,
        )


def is_installable(m: Module) -> bool:
    """True if at least one install path is available for this platform.

    Used by the modules screen to grey-out the Install button on tools
    that have no automatable install path on the current platform.
    """
    cmd, _ = pick_install_command(m)
    return cmd is not None


def command_needs_sudo(m: Module) -> bool:
    """Whether this module's chosen install command would use sudo.

    Lets the modules screen decide whether to even offer the
    "Install All + sudo" affordance (e.g. on macOS/brew it never does).
    """
    cmd, _ = pick_install_command(m)
    return bool(cmd) and "sudo" in cmd


async def sudo_authenticate(password: str) -> Tuple[bool, str]:
    """Validate `password` against sudo and cache the credential.

    Runs `sudo -S -k -p '' -v`: `-k` forces a fresh authentication (so a
    wrong password is rejected rather than silently using a cached ticket),
    `-S` reads the password from stdin, `-v` validates and refreshes the
    timestamp so subsequent `sudo -n` installs in this run don't re-prompt.

    Returns (ok, message). A no-op success when already root or when sudo
    isn't needed/available. Never raises.
    """
    if _is_root():
        return True, "already running as root — no sudo needed"
    if not shutil.which("sudo"):
        return False, "sudo not found on PATH"
    try:
        proc = await asyncio.create_subprocess_exec(
            "sudo", "-S", "-k", "-p", "", "-v",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await proc.communicate((password + "\n").encode())
    except Exception as e:  # noqa: BLE001
        return False, f"could not run sudo: {e}"
    if proc.returncode == 0:
        return True, "sudo credentials accepted"
    msg = (out or b"").decode(errors="replace").strip()
    last = msg.splitlines()[-1] if msg else ""
    return False, last or "incorrect password or sudo denied"


def ensure_install_paths() -> None:
    """Add the dirs package managers drop binaries into to PATH.

    pipx → ~/.local/bin, `go install` → ~/go/bin (or $GOPATH/bin), Homebrew
    → its prefix, cargo → ~/.cargo/bin. Appending these to os.environ['PATH']
    means a tool installed mid-session is found by shutil.which immediately,
    so the modules screen flips it to ✓ WITHOUT restarting vulnscout.

    Idempotent and safe to call repeatedly.
    """
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".local", "bin"),
        os.path.join(home, "go", "bin"),
        os.path.join(home, ".cargo", "bin"),
        os.path.join(home, ".rbenv", "shims"),
        "/opt/homebrew/bin", "/opt/homebrew/sbin",
        "/usr/local/bin", "/usr/local/sbin",
        "/home/linuxbrew/.linuxbrew/bin",
    ]
    gopath = os.environ.get("GOPATH")
    if gopath:
        candidates.append(os.path.join(gopath, "bin"))
    parts = os.environ.get("PATH", "").split(os.pathsep)
    seen = set(parts)
    added = [c for c in candidates if c not in seen and os.path.isdir(c)]
    if added:
        os.environ["PATH"] = os.pathsep.join(parts + added)
