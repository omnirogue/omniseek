# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""HTML dossier, SARIF 2.1.0 and Markdown output."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import unittest

from helpers import EXAMPLES

from omniseek.model import load_document
from omniseek.render import render
from omniseek.render.markdown import COMMENT_LIMIT
from omniseek.verify import verify_document

HOSTILE = '<script>alert("x")</script>'


def sample(verified: bool = True) -> dict:
    document = load_document(str(EXAMPLES / "sample_findings.json"))
    if verified:
        document, _ = verify_document(document, str(EXAMPLES / "vulnerable_app"))
    return document


class HtmlTest(unittest.TestCase):
    def test_self_contained_with_csp_hash(self):
        page = render(sample(), "html")
        self.assertNotRegex(page, r"(src|href)=\"https?://")
        script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
        digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        self.assertIn(f"script-src 'sha256-{digest}'", page)

    def test_lens_tabs_badges_and_drawers(self):
        page = render(sample(), "html")
        for lens in ("architecture", "security", "performance", "product"):
            self.assertIn(f'data-lens="{lens}"', page)
        self.assertIn("ungrounded 0.00", page)
        self.assertIn("partial 0.50", page)
        self.assertIn('class="drawer"', page)
        self.assertIn("Remediation", page)

    def test_hostile_text_is_escaped(self):
        document = load_document(
            [{"title": HOSTILE, "lens": "security", "severity": "high", "description": HOSTILE,
              "citations": [{"path": HOSTILE, "start_line": 1, "end_line": 1, "snippet": HOSTILE}]}]
        )
        page = render(document, "html")
        self.assertNotIn(HOSTILE, page)
        self.assertIn("&lt;script&gt;", page)

    def test_empty_document(self):
        self.assertIn("No findings", render(load_document([]), "html"))


class SarifTest(unittest.TestCase):
    def test_structure(self):
        document = sample()
        sarif = json.loads(render(document, "sarif"))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(len(rules), len(set(rules)))
        self.assertEqual(len(run["results"]), len(document["findings"]))
        for result in run["results"]:
            self.assertEqual(rules[result["ruleIndex"]], result["ruleId"])
            self.assertIn(result["level"], ("error", "warning", "note"))
            location = result["locations"][0]["physicalLocation"]
            self.assertTrue(location["artifactLocation"]["uri"])
            self.assertGreaterEqual(location["region"]["startLine"], 1)

    def test_security_rules_carry_security_severity(self):
        sarif = json.loads(render(sample(), "sarif"))
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            if "security" in rule["properties"]["tags"]:
                self.assertIn("security-severity", rule["properties"])

    def test_repository_level_findings_are_anchored(self):
        document = load_document(
            [{"title": "No license", "lens": "product", "severity": "high",
              "citations": [{"kind": "absence", "globs": ["license*"]}]}]
        )
        result = json.loads(render(document, "sarif"))["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 1)


class MarkdownTest(unittest.TestCase):
    def test_summary_and_evidence(self):
        text = render(sample(), "md")
        self.assertIn("## OmniSeek report", text)
        self.assertIn("<details><summary>Evidence", text)
        self.assertIn("hallucinated", text)

    def test_stays_under_comment_limit(self):
        many = [
            {"title": f"finding {i}", "lens": "architecture", "severity": "low", "description": "x" * 2000,
             "citations": [{"path": "a.py", "start_line": i + 1, "end_line": i + 1, "snippet": "y" * 150}]}
            for i in range(200)
        ]
        text = render(load_document(many), "md")
        self.assertLess(len(text), COMMENT_LIMIT + 2000)
        self.assertIn("did not fit in one comment", text)


if __name__ == "__main__":
    unittest.main()
