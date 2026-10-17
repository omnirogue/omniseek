# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""The citation and grounding verifier."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

from helpers import make_repo

from omniseek.model import load_document
from omniseek.verify import verify_document

SOURCE = "def login(user, password):\n    token = issue(user)\n    return token\n\n\ndef logout(user):\n    revoke(user)\n"


def finding(*citations: dict, title: str = "t") -> dict:
    return {"title": title, "lens": "security", "severity": "high", "citations": list(citations)}


def span(path: str, start, end, snippet=None, symbol=None) -> dict:
    citation = {"kind": "span", "path": path, "start_line": start, "end_line": end}
    if snippet is not None:
        citation["snippet"] = snippet
    if symbol is not None:
        citation["symbol"] = symbol
    return citation


class VerifierTest(unittest.TestCase):
    def setUp(self):
        self.repo = make_repo({"auth.py": SOURCE, "README.md": "# Demo\n"})

    def tearDown(self):
        self.repo.cleanup()

    def statuses(self, *citations: dict) -> list[str]:
        document = load_document([finding(*citations)])
        annotated, _ = verify_document(document, self.repo.name)
        return [c["status"] for c in annotated["findings"][0]["verification"]["citations"]]

    def test_verified_span_with_symbol_and_whitespace_differences(self):
        self.assertEqual(self.statuses(span("auth.py", 1, 3, "token   =  issue(user)", "login")), ["verified"])

    def test_drifted_quote_reports_actual_lines(self):
        document = load_document([finding(span("auth.py", 6, 7, "token = issue(user)"))])
        annotated, report = verify_document(document, self.repo.name)
        citation = annotated["findings"][0]["verification"]["citations"][0]
        self.assertEqual(citation["status"], "drifted")
        self.assertEqual(citation["actual_lines"], {"start_line": 2, "end_line": 2})
        self.assertEqual(report["grounding_score"], 0.5)

    def test_hallucinations(self):
        self.assertEqual(
            self.statuses(
                span("missing.py", 1, 2, "anything"),
                span("auth.py", 1, 3, "token = mint(user)"),
                span("auth.py", 1, 3, None, "authenticate"),
                span("auth.py", 40, 41),
            ),
            ["hallucinated"] * 4,
        )

    def test_invalid_citations(self):
        self.assertEqual(
            self.statuses(
                span("../outside.py", 1, 1, "x = 1"),
                span("/etc/hosts", 1, 1, "localhost"),
                span("auth.py", 0, 2, "def login"),
                span("auth.py", 3, 2, "def login"),
                span("auth.py", "one", 2, "def login"),
                {"kind": "teleport"},
            ),
            ["invalid"] * 6,
        )

    def test_unanchored_span(self):
        self.assertEqual(self.statuses(span("auth.py", 1, 2)), ["unanchored"])

    def test_absence(self):
        self.assertEqual(
            self.statuses(
                {"kind": "absence", "paths": ["LICENSE"], "globs": ["license.*"]},
                {"kind": "absence", "globs": ["readme*"]},
            ),
            ["verified", "hallucinated"],
        )

    def test_scores_and_missing_citations(self):
        document = load_document(
            [finding(span("auth.py", 1, 1, "def login(user, password):")), finding(title="no evidence")]
        )
        annotated, report = verify_document(document, self.repo.name)
        self.assertEqual([f["verification"]["status"] for f in annotated["findings"]], ["grounded", "missing_citation"])
        self.assertEqual(report["grounding_score"], 0.5)
        self.assertFalse(report["verified"])

    def test_empty_document_is_vacuously_grounded(self):
        _, report = verify_document(load_document([]), self.repo.name)
        self.assertEqual((report["grounding_score"], report["vacuous"]), (1.0, True))

    def test_citation_string_shorthand(self):
        document = load_document([{"title": "t", "lens": "product", "severity": "low", "citations": ["auth.py:6-7"]}])
        annotated, _ = verify_document(document, self.repo.name)
        self.assertEqual(annotated["findings"][0]["verification"]["citations"][0]["status"], "unanchored")

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_symlink_outside_the_repository_is_invalid(self):
        outside = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        outside.write("secret = 1\n")
        outside.close()
        self.addCleanup(os.unlink, outside.name)
        os.symlink(outside.name, os.path.join(self.repo.name, "link.py"))
        self.assertEqual(self.statuses(span("link.py", 1, 1, "secret = 1")), ["invalid"])


@unittest.skipIf(shutil.which("git") is None, "git is not installed")
class GitRevisionTest(unittest.TestCase):
    def test_verify_against_a_revision(self):
        repo = make_repo({"app.py": "def run():\n    return 1\n"})
        self.addCleanup(repo.cleanup)

        def git(*args):
            subprocess.run(["git", "-C", repo.name, *args], check=True, capture_output=True)

        git("init", "-q")
        git("-c", "user.name=t", "-c", "user.email=t@example.com", "add", "-A")
        git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init")
        with open(os.path.join(repo.name, "app.py"), "w", encoding="utf-8") as handle:
            handle.write("def run():\n    return 2\n")
        document = load_document([finding(span("app.py", 2, 2, "return 1"))])
        _, at_head = verify_document(document, repo.name, "HEAD")
        _, working = verify_document(document, repo.name)
        self.assertEqual(at_head["grounding_score"], 1.0)
        self.assertEqual(working["grounding_score"], 0.0)


if __name__ == "__main__":
    unittest.main()
