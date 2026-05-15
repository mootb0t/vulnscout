"""Installer: platform command-picking, sudo prefixing, PATH refresh.

Platform is simulated with mock.patch so these run anywhere (the tests
don't actually install anything or call sudo).
"""

import os
import tempfile
import unittest
from unittest import mock

from vulnscout import installer as I
from vulnscout.modules import MODULES, Module


def _which(present):
    """Fake shutil.which: returns a path for binaries in `present`, else None."""
    return lambda b: ("/usr/bin/" + b) if b in present else None


def _apt_module():
    return Module(name="nmap", label="nmap", description="", category="core",
                  install_brew="brew install nmap",
                  install_apt="apt-get install -y nmap")


class PickCommandTest(unittest.TestCase):
    def test_macos_prefers_brew_without_sudo(self):
        with mock.patch.object(I.sys, "platform", "darwin"), \
             mock.patch.object(I.shutil, "which", _which({"brew"})), \
             mock.patch.object(I, "_is_root", lambda: False):
            cmd, _ = I.pick_install_command(_apt_module())
        self.assertEqual(cmd[0], "brew")
        self.assertNotIn("sudo", cmd)

    def test_linux_apt_uses_sudo_n_without_password(self):
        with mock.patch.object(I.sys, "platform", "linux"), \
             mock.patch.object(I.shutil, "which", _which({"apt-get", "sudo"})), \
             mock.patch.object(I, "_is_root", lambda: False):
            cmd, _ = I.pick_install_command(_apt_module())
        self.assertEqual(cmd[:2], ["sudo", "-n"])

    def test_linux_apt_uses_sudo_S_with_password(self):
        with mock.patch.object(I.sys, "platform", "linux"), \
             mock.patch.object(I.shutil, "which", _which({"apt-get", "sudo"})), \
             mock.patch.object(I, "_is_root", lambda: False):
            cmd, _ = I.pick_install_command(_apt_module(), sudo_password="pw")
        self.assertEqual(cmd[:4], ["sudo", "-S", "-p", ""])
        self.assertNotIn("pw", cmd)  # password is never in argv

    def test_root_never_uses_sudo(self):
        with mock.patch.object(I.sys, "platform", "linux"), \
             mock.patch.object(I.shutil, "which", _which({"apt-get", "sudo"})), \
             mock.patch.object(I, "_is_root", lambda: True):
            cmd, _ = I.pick_install_command(_apt_module(), sudo_password="pw")
        self.assertNotIn("sudo", cmd)

    def test_command_needs_sudo(self):
        m = _apt_module()
        with mock.patch.object(I.sys, "platform", "linux"), \
             mock.patch.object(I.shutil, "which", _which({"apt-get", "sudo"})), \
             mock.patch.object(I, "_is_root", lambda: False):
            self.assertTrue(I.command_needs_sudo(m))
        with mock.patch.object(I.sys, "platform", "darwin"), \
             mock.patch.object(I.shutil, "which", _which({"brew"})), \
             mock.patch.object(I, "_is_root", lambda: False):
            self.assertFalse(I.command_needs_sudo(m))


class RegistryCoverageTest(unittest.TestCase):
    def test_every_module_installable_on_some_platform(self):
        mac = _which({"brew", "pip3", "pipx", "gem", "go", "curl", "sudo"})
        lin = _which({"apt-get", "pip3", "pipx", "gem", "go", "curl", "sudo"})
        gaps = []
        for m in MODULES:
            with mock.patch.object(I.shutil, "which", mac), \
                 mock.patch.object(I.sys, "platform", "darwin"), \
                 mock.patch.object(I, "_is_root", lambda: False):
                mac_ok = I.is_installable(m)
            with mock.patch.object(I.shutil, "which", lin), \
                 mock.patch.object(I.sys, "platform", "linux"), \
                 mock.patch.object(I, "_is_root", lambda: False):
                lin_ok = I.is_installable(m)
            if not (mac_ok or lin_ok):
                gaps.append(m.name)
        self.assertEqual(gaps, [], f"no install path on any platform: {gaps}")

    def test_picked_commands_are_well_formed(self):
        lin = _which({"apt-get", "pip3", "pipx", "gem", "go", "curl", "sudo"})
        with mock.patch.object(I.shutil, "which", lin), \
             mock.patch.object(I.sys, "platform", "linux"), \
             mock.patch.object(I, "_is_root", lambda: False):
            for m in MODULES:
                cmd, desc = I.pick_install_command(m)
                self.assertIsInstance(cmd, list, m.name)
                self.assertTrue(cmd, m.name)
                self.assertTrue(all(isinstance(p, str) for p in cmd), m.name)
                self.assertIsInstance(desc, str)


class PathRefreshTest(unittest.TestCase):
    def test_ensure_install_paths_adds_existing_and_is_idempotent(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "bin"), exist_ok=True)
        old_path = os.environ.get("PATH", "")
        old_gopath = os.environ.get("GOPATH")
        try:
            os.environ["GOPATH"] = d
            I.ensure_install_paths()
            self.assertIn(os.path.join(d, "bin"),
                          os.environ["PATH"].split(os.pathsep))
            snapshot = os.environ["PATH"]
            I.ensure_install_paths()                  # second call: no change
            self.assertEqual(snapshot, os.environ["PATH"])
        finally:
            os.environ["PATH"] = old_path
            if old_gopath is None:
                os.environ.pop("GOPATH", None)
            else:
                os.environ["GOPATH"] = old_gopath

    def test_ensure_install_paths_skips_missing_dirs(self):
        old_path = os.environ.get("PATH", "")
        old_gopath = os.environ.get("GOPATH")
        try:
            os.environ["GOPATH"] = "/no/such/dir/vulnscout-test"
            I.ensure_install_paths()
            self.assertNotIn("/no/such/dir/vulnscout-test/bin",
                             os.environ["PATH"].split(os.pathsep))
        finally:
            os.environ["PATH"] = old_path
            if old_gopath is None:
                os.environ.pop("GOPATH", None)
            else:
                os.environ["GOPATH"] = old_gopath


if __name__ == "__main__":
    unittest.main()
