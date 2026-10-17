# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Bring-your-own-model scans and cloud-sync, against a local stub server (no network)."""

from __future__ import annotations

import json
import unittest

from helpers import EXAMPLES, EnvPatch, StubServer, fake_aws_key, make_repo

from omniseek import cloud
from omniseek.llm import LLMError, parse_findings, parse_model
from omniseek.model import load_document
from omniseek.scan import run_scan

GOOD = {
    "lens": "architecture", "severity": "medium", "confidence": "high",
    "title": "New database connection per lookup",
    "description": "find_user opens a connection on every call and never closes it.",
    "remediation": ["Reuse a pooled connection."],
    "citations": [{"path": "app.py", "start_line": 15, "end_line": 17,
                   "snippet": "conn = sqlite3.connect(DATABASE)", "symbol": "find_user"}],
}
INVENTED = {
    "lens": "security", "severity": "critical", "title": "Timing-unsafe token comparison",
    "description": "Invented.", "remediation": ["Use hmac.compare_digest."],
    "citations": [{"path": "auth/session.py", "start_line": 3, "end_line": 4, "snippet": "if token == stored:"}],
}
REPLY = json.dumps({"findings": [GOOD, INVENTED, {"lens": "vibes", "title": "x", "severity": "low"}]})


def provider_reply(path: str, body: dict) -> dict:
    if path.endswith("/chat/completions"):
        return {"choices": [{"message": {"content": REPLY}}]}
    if path.endswith("/v1/messages"):
        return {"content": [{"type": "text", "text": "```json\n" + REPLY + "\n```"}]}
    if ":generateContent" in path:
        return {"candidates": [{"content": {"parts": [{"text": REPLY}]}}]}
    return {"error": "unexpected path " + path}


class ByoModelTest(unittest.TestCase):
    def scan_with(self, spec: str, **env: str) -> tuple[dict, StubServer]:
        with StubServer(provider_reply) as stub:
            urls = {"OPENAI_BASE_URL": stub.url + "/v1", "ANTHROPIC_BASE_URL": stub.url,
                    "GEMINI_BASE_URL": stub.url + "/v1beta"}
            with EnvPatch(**urls, **env):
                document = run_scan(str(EXAMPLES / "vulnerable_app"), model=spec)
        return document, stub

    def check(self, document: dict) -> None:
        titles = {f["title"] for f in document["findings"]}
        self.assertIn(GOOD["title"], titles)
        self.assertNotIn(INVENTED["title"], titles)  # every citation hallucinated: dropped
        llm = document["analyzer"]["llm"]
        self.assertEqual((llm["findings_rejected_malformed"], llm["dropped_ungrounded"]), (1, 1))
        self.assertEqual(document["verification"]["grounding_score"], 1.0)

    def test_openai(self):
        document, stub = self.scan_with("openai/test-model", OPENAI_API_KEY="tk-openai")
        self.check(document)
        self.assertEqual(stub.requests[0]["headers"]["authorization"], "Bearer tk-openai")
        self.assertEqual(json.loads(stub.requests[0]["body"])["model"], "test-model")

    def test_anthropic(self):
        document, stub = self.scan_with("anthropic/test-model", ANTHROPIC_API_KEY="tk-anthro")
        self.check(document)
        self.assertEqual(stub.requests[0]["headers"]["x-api-key"], "tk-anthro")

    def test_gemini(self):
        document, stub = self.scan_with("gemini/test-model", GEMINI_API_KEY="tk-gemini", GOOGLE_API_KEY=None)
        self.check(document)
        self.assertIn("/models/test-model:generateContent", stub.requests[0]["path"])
        self.assertEqual(stub.requests[0]["headers"]["x-goog-api-key"], "tk-gemini")

    def test_secrets_are_redacted_before_sending(self):
        key = fake_aws_key()
        repo = make_repo({"main.py": f'KEY_ID = "{key}"\n\ndef main():\n    return KEY_ID\n', ".env": "TOKEN=abc\n"})
        with repo, StubServer(provider_reply) as stub:
            with EnvPatch(OPENAI_BASE_URL=stub.url + "/v1", OPENAI_API_KEY="k"):
                run_scan(repo.name, model="openai/m")
            body = stub.requests[0]["body"]
        sent = json.loads(body)["messages"][1]["content"]
        self.assertNotIn(key, body)
        self.assertIn('KEY_ID = "«redacted»"', sent)
        self.assertNotIn("TOKEN=abc", body)

    def test_missing_key_and_bad_spec(self):
        with EnvPatch(OPENAI_API_KEY=None):
            with self.assertRaises(LLMError):
                run_scan(str(EXAMPLES / "vulnerable_app"), model="openai/m")
        for spec in ("openai", "mystery/model", "/m"):
            with self.assertRaises(LLMError):
                parse_model(spec)

    def test_parse_findings_rejects_non_json(self):
        with self.assertRaises(LLMError):
            parse_findings("I could not find anything.", ["security"], "llm:x/y")


class CloudSyncTest(unittest.TestCase):
    def test_sync_sends_findings_not_paths(self):
        document = load_document(str(EXAMPLES / "sample_findings.json"))
        document["repo"]["root"] = "/private/local/path"
        with StubServer(lambda path, body: {"scan_id": "scan_1", "path": path}) as stub:
            with EnvPatch(OMNISI_API_KEY="tk-cloud", OMNISI_API_URL=None):
                reply = cloud.sync(document, api_url=stub.url, include_snippets=False)
            request = stub.requests[0]
        self.assertEqual(reply, {"scan_id": "scan_1", "path": "/v1/omniseek/scans"})
        self.assertEqual(request["headers"]["authorization"], "Bearer tk-cloud")
        self.assertIn("idempotency-key", request["headers"])
        body = json.loads(request["body"])
        self.assertEqual(body["schema"], cloud.PAYLOAD_SCHEMA)
        self.assertNotIn("/private/local/path", request["body"])
        self.assertTrue(all("snippet" not in c for f in body["findings"] for c in f["citations"]))

    def test_requires_token_and_https(self):
        document = load_document([])
        with EnvPatch(OMNISI_API_KEY=None):
            with self.assertRaises(cloud.CloudError):
                cloud.sync(document)
        with EnvPatch(OMNISI_API_KEY="k"):
            with self.assertRaises(cloud.CloudError):
                cloud.sync(document, api_url="http://cloud.example.com")


if __name__ == "__main__":
    unittest.main()
