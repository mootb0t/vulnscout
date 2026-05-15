"""Deterministic severity derivation (the LLM never grades severity)."""

import unittest

from vulnscout.tools.parser import derive_severity


class SeverityTest(unittest.TestCase):
    def test_nuclei_text_tags(self):
        self.assertEqual(derive_severity("nuclei", '"severity":"critical"'), "CRITICAL")
        self.assertEqual(derive_severity("nuclei", "[high] thing"), "HIGH")
        self.assertEqual(derive_severity("nuclei", "[medium] thing"), "MEDIUM")
        self.assertEqual(derive_severity("nuclei", "[low] thing"), "LOW")
        self.assertEqual(derive_severity("nuclei", "nothing notable"), "INFO")

    def test_nuclei_cvss_score_wins(self):
        crit = '{"info":{"classification":{"cvss-score":9.8}}}'
        med = '{"info":{"classification":{"cvss-score":5.0}}}'
        self.assertEqual(derive_severity("nuclei", crit), "CRITICAL")
        self.assertEqual(derive_severity("nuclei", med), "MEDIUM")

    def test_nikto_buckets(self):
        self.assertEqual(derive_severity("nikto", "Remote code execution found"), "CRITICAL")
        self.assertEqual(derive_severity("nikto", "SQL injection in id"), "HIGH")
        self.assertEqual(derive_severity("nikto", "directory traversal"), "HIGH")
        self.assertEqual(derive_severity("nikto", "missing header x-frame-options"), "LOW")

    def test_sslscan(self):
        self.assertEqual(derive_severity("sslscan", "SSLv3 enabled — POODLE"), "HIGH")
        self.assertEqual(derive_severity("sslscan", "TLSv1.2 supported"), "LOW")

    def test_sqlmap_negation_not_matched(self):
        self.assertEqual(derive_severity("sqlmap", "parameter id is vulnerable"), "HIGH")
        self.assertEqual(
            derive_severity("sqlmap", "all tested parameters do not appear to be injectable"),
            "INFO",
        )

    def test_searchsploit_rows(self):
        tbl = ("Exploit Title | Path\n"
               "------------- | ----\n"
               "Apache 2.4.49 Path Traversal | multiple/webapps/50383.sh\n")
        self.assertEqual(derive_severity("searchsploit", tbl), "MEDIUM")
        self.assertEqual(derive_severity("searchsploit", "no results"), "INFO")

    def test_gobuster_sensitive_paths(self):
        self.assertEqual(derive_severity("gobuster", "/.git/ (Status: 301)"), "HIGH")
        self.assertEqual(derive_severity("gobuster", "/images (Status: 301)"), "INFO")

    def test_unknown_tool_is_info(self):
        self.assertEqual(derive_severity("whatever", "blah"), "INFO")


if __name__ == "__main__":
    unittest.main()
