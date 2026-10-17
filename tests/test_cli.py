# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""The command line: exit codes and files written."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest

from helpers import EXAMPLES

from omniseek.cli import EXIT_GATE, EXIT_OK, EXIT_USAGE, main

APP = str(EXAMPLES / "vulnerable_app")
SAMPLE = str(EXAMPLES / "sample_findings.json")


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name: str) -> str:
        return os.path.join(self.tmp.name, name)

    def test_scan_writes_every_format(self):
        code, _, err = run("scan", APP, "-o", self.path("f.json"), "--html", self.path("d.html"),
                           "--sarif", self.path("r.sarif"), "--md", self.path("r.md"))
        self.assertEqual(code, EXIT_OK, err)
        for name in ("f.json", "d.html", "r.sarif", "r.md"):
            self.assertGreater(os.path.getsize(self.path(name)), 100)
        self.assertIn("grounding 1.000", err)

    def test_scan_to_stdout_and_fail_on(self):
        code, out, _ = run("scan", APP, "--quiet")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)["schema"], "omniseek.findings/v1")
        code, _, err = run("scan", APP, "--quiet", "--fail-on", "high")
        self.assertEqual(code, EXIT_GATE, err)

    def test_verify_gate(self):
        code, out, _ = run("verify", SAMPLE, "--repo", APP)
        self.assertEqual(code, EXIT_GATE)
        self.assertIn("FLAGGED hallucinated", out)
        code, out, _ = run("verify", SAMPLE, "--repo", APP, "--min-score", "0.9", "--json", "-o", self.path("v.json"))
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)["citations_by_status"]["hallucinated"], 1)
        with open(self.path("v.json"), encoding="utf-8") as handle:
            annotated = json.load(handle)
        self.assertTrue(all("verification" in f for f in annotated["findings"]))

    def test_report_formats(self):
        for fmt in ("html", "md", "sarif"):
            code, _, err = run("report", SAMPLE, "--format", fmt, "-o", self.path(f"out.{fmt}"), "--verify-repo", APP)
            self.assertEqual(code, EXIT_OK, err)

    def test_cloud_sync_dry_run_sends_nothing(self):
        code, out, err = run("cloud-sync", SAMPLE, "--dry-run", "--no-snippets", "--api-url", "https://cloud.example.com")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("https://cloud.example.com/v1/omniseek/scans", err)
        self.assertEqual(json.loads(out)["schema"], "omniseek.cloud-sync/v1")

    def test_usage_errors(self):
        self.assertEqual(run("verify", self.path("missing.json"))[0], EXIT_USAGE)
        self.assertEqual(run("scan", self.path("nowhere"))[0], EXIT_USAGE)
        self.assertEqual(run("scan", APP, "--lenses", "vibes")[0], EXIT_USAGE)
        with open(self.path("bad.json"), "w", encoding="utf-8") as handle:
            handle.write('{"findings": [{"title": "x", "lens": "nope", "severity": "high"}]}')
        self.assertEqual(run("report", self.path("bad.json"))[0], EXIT_USAGE)

    def test_rules(self):
        code, out, _ = run("rules", "--json")
        self.assertEqual(code, EXIT_OK)
        self.assertGreater(len(json.loads(out)), 30)


if __name__ == "__main__":
    unittest.main()
