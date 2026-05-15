"""Target detection/validation + tool-output parsers."""

import unittest

from vulnscout.tools.parser import (
    detect_target_type, looks_like_xml, parse_nuclei_jsonl,
    parse_searchsploit_table, validate_target,
)


class ParserTest(unittest.TestCase):
    def test_detect_target_type(self):
        self.assertEqual(detect_target_type("1.2.3.4"), "ip")
        self.assertEqual(detect_target_type("10.0.0.0/24"), "cidr")
        self.assertEqual(detect_target_type("example.com"), "domain")
        self.assertEqual(detect_target_type("https://x.com/a"), "url")

    def test_validate_target(self):
        self.assertTrue(validate_target("1.2.3.4")[0])
        self.assertTrue(validate_target("example.com")[0])
        self.assertTrue(validate_target("https://x.com")[0])
        self.assertFalse(validate_target("")[0])
        self.assertFalse(validate_target("not a target!!")[0])
        self.assertFalse(validate_target("10.0.0.0/99")[0])

    def test_looks_like_xml(self):
        self.assertTrue(looks_like_xml("<?xml version='1.0'?>"))
        self.assertTrue(looks_like_xml("<nmaprun scanner='nmap'>"))
        self.assertFalse(looks_like_xml("just some text"))

    def test_parse_nuclei_jsonl_skips_junk(self):
        out = parse_nuclei_jsonl('{"a":1}\n\ngarbage line\n{"b":2}')
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["a"], 1)
        self.assertEqual(out[1]["b"], 2)

    def test_parse_searchsploit_table(self):
        tbl = (
            "Exploit Title                    | Path\n"
            "-------------------------------- | ----\n"
            "Apache 2.4.49 Path Traversal     | multiple/webapps/50383.sh\n"
            "Shellcodes: No Results\n"
        )
        rows = parse_searchsploit_table(tbl)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["edb_id"], "50383")
        self.assertIn("exploit-db.com/exploits/50383", rows[0]["url"])

    def test_parse_searchsploit_no_header_returns_empty(self):
        self.assertEqual(parse_searchsploit_table("random text\nno table here"), [])


if __name__ == "__main__":
    unittest.main()
