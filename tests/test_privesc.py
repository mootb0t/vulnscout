"""Privilege-escalation analyzers + knowledge base."""

import unittest

from vulnscout import privesc as P


class PrivescAnalyzerTest(unittest.TestCase):
    def _titles(self, suggestions):
        return [s.title for s in suggestions]

    # -- sudo -----------------------------------------------------------
    def test_sudo_gtfobins_binary(self):
        s = P.analyze_sudo("User www-data may run:\n    (root) NOPASSWD: /usr/bin/find")
        self.assertTrue(any("find" in t for t in self._titles(s)))
        self.assertTrue(all(x.category == "sudo" for x in s))
        self.assertTrue(any(x.confidence == "high" for x in s))

    def test_sudo_all_is_full_access(self):
        s = P.analyze_sudo("(ALL : ALL) ALL")
        self.assertTrue(any("Full sudo" in t for t in self._titles(s)))

    def test_sudo_ld_preload(self):
        s = P.analyze_sudo("env_keep+=LD_PRELOAD\n(root) /usr/sbin/apache2")
        self.assertTrue(any("LD_PRELOAD" in t for t in self._titles(s)))

    # -- suid -----------------------------------------------------------
    def test_suid_pkexec_gtfo_and_unusual(self):
        s = P.analyze_suid(
            "/usr/bin/pkexec\n/usr/bin/find\n/usr/bin/vim.basic\n/opt/weird_helper")
        titles = " ".join(self._titles(s))
        self.assertIn("PwnKit", titles)              # pkexec special-case
        self.assertIn("find", titles)                # GTFOBins suid
        self.assertIn("vim.basic", titles)           # de-versioned match
        self.assertTrue(any("Unusual" in t for t in self._titles(s)))

    def test_suid_command_adapts_to_real_binary_name(self):
        s = P.analyze_suid("/usr/bin/vim.basic")
        cmd = next(x.command for x in s if "vim.basic" in x.title)
        self.assertIn("vim.basic", cmd)

    def test_default_suid_not_flagged_unusual(self):
        s = P.analyze_suid("/usr/bin/passwd\n/usr/bin/su\n/usr/bin/mount")
        self.assertFalse(any("Unusual" in t for t in self._titles(s)))

    # -- capabilities ---------------------------------------------------
    def test_capabilities_setuid(self):
        s = P.analyze_capabilities("/usr/bin/python3.8 = cap_setuid+ep")
        self.assertEqual(len(s), 1)
        self.assertIn("setuid(0)", s[0].command)
        self.assertEqual(s[0].confidence, "high")

    def test_capabilities_dac_read(self):
        s = P.analyze_capabilities("/usr/bin/tac = cap_dac_read_search+ep")
        self.assertTrue(s and s[0].category == "capabilities")

    # -- kernel ---------------------------------------------------------
    def test_parse_kernel_version(self):
        self.assertEqual(P.parse_kernel_version("Linux x 5.15.0-generic"), (5, 15, 0))
        self.assertIsNone(P.parse_kernel_version("no version here"))

    def test_kernel_dirtycow(self):
        s = P.analyze_kernel("Linux box 4.4.0-21-generic #37-Ubuntu")
        self.assertTrue(any("DirtyCow" in x.title for x in s))

    def test_kernel_dirtypipe(self):
        s = P.analyze_kernel("5.10.0-8-amd64")
        self.assertTrue(any("DirtyPipe" in x.title for x in s))

    def test_kernel_modern_no_false_positive_but_has_catchall(self):
        s = P.analyze_kernel("6.5.0-15-generic")
        self.assertFalse(any("DirtyCow" in x.title for x in s))
        self.assertFalse(any("DirtyPipe" in x.title for x in s))
        self.assertTrue(any("Enumerate kernel" in x.title for x in s))

    # -- windows --------------------------------------------------------
    def test_windows_seimpersonate_potato(self):
        s = P.analyze_windows("SeImpersonatePrivilege   Impersonate a client   Enabled")
        self.assertTrue(any("Potato" in x.title for x in s))

    def test_windows_always_install_elevated(self):
        s = P.analyze_windows("AlwaysInstallElevated    REG_DWORD    0x1")
        self.assertTrue(any("AlwaysInstallElevated" in x.title for x in s))

    # -- merge / dedup --------------------------------------------------
    def test_analyze_merges_and_sorts_by_confidence(self):
        blob = "(root) NOPASSWD: /usr/bin/find\n/usr/bin/pkexec\nLinux 4.4.0-21-generic"
        s = P.analyze(blob, "linux")
        self.assertGreaterEqual(len(s), 3)
        ranks = [x.rank for x in s]
        self.assertEqual(ranks, sorted(ranks))  # high → check

    def test_analyze_dedupes(self):
        s = P.analyze("(root) NOPASSWD: /usr/bin/find\n/usr/bin/find", "linux")
        keys = [x.key() for x in s]
        self.assertEqual(len(keys), len(set(keys)))

    def test_analyze_windows_routes_on_os_hint(self):
        s = P.analyze("SeImpersonatePrivilege  Enabled", "windows")
        self.assertTrue(any(x.category == "windows" for x in s))

    # -- reference data -------------------------------------------------
    def test_reference_data_nonempty(self):
        self.assertTrue(P.enum_steps("linux"))
        self.assertTrue(P.enum_steps("windows"))
        self.assertTrue(P.interesting_files("linux"))
        self.assertTrue(P.interesting_files("windows"))
        self.assertIn("find", P.GTFOBINS)
        self.assertIn("suid", P.GTFOBINS["find"])


if __name__ == "__main__":
    unittest.main()
