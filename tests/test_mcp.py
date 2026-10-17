# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""The stdio MCP server, end to end through a subprocess."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

from helpers import EXAMPLES, ROOT


def call(messages: list, *roots: str) -> dict:
    args = [sys.executable, "-m", "omniseek.mcp_server"]
    for root in roots:
        args += ["--root", root]
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    stdin = "\n".join(m if isinstance(m, str) else json.dumps(m) for m in messages) + "\n"
    result = subprocess.run(args, input=stdin, capture_output=True, text=True, env=env, timeout=120, check=True)
    replies = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return {reply.get("id"): reply for reply in replies}


def request(request_id: int, method: str, params: dict | None = None) -> dict:
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def tool(request_id: int, name: str, arguments: dict) -> dict:
    return request(request_id, "tools/call", {"name": name, "arguments": arguments})


class McpTest(unittest.TestCase):
    def test_handshake_and_tools(self):
        replies = call(
            [
                request(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                          "clientInfo": {"name": "test", "version": "0"}}),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                request(2, "tools/list"),
                request(3, "ping"),
                request(4, "no/such/method"),
                "{not json",
            ],
            str(EXAMPLES),
        )
        self.assertEqual(replies[1]["result"]["protocolVersion"], "2025-06-18")
        names = [t["name"] for t in replies[2]["result"]["tools"]]
        self.assertEqual(names, ["omniseek_scan", "omniseek_verify_citations", "omniseek_render_dossier"])
        self.assertEqual(replies[3]["result"], {})
        self.assertEqual(replies[4]["error"]["code"], -32601)
        self.assertEqual(replies[None]["error"]["code"], -32700)

    def test_scan_verify_render(self):
        with tempfile.TemporaryDirectory() as out:
            replies = call(
                [
                    tool(1, "omniseek_scan", {"path": str(EXAMPLES / "vulnerable_app"), "min_severity": "high"}),
                    tool(2, "omniseek_verify_citations", {"findings_path": str(EXAMPLES / "sample_findings.json"),
                                                          "repo": str(EXAMPLES / "vulnerable_app")}),
                    tool(3, "omniseek_render_dossier", {"findings_path": str(EXAMPLES / "sample_findings.json"),
                                                        "format": "sarif", "output_path": os.path.join(out, "o.sarif")}),
                    tool(4, "omniseek_render_dossier", {"findings_path": str(EXAMPLES / "sample_findings.json"),
                                                        "format": "sarif", "output_path": os.path.join(out, "o.sarif")}),
                ],
                str(EXAMPLES),
                out,
            )
            scan = replies[1]["result"]["structuredContent"]
            self.assertTrue(scan["findings"])
            self.assertTrue(all(f["severity"] in ("critical", "high") for f in scan["findings"]))
            verify = replies[2]["result"]["structuredContent"]
            self.assertLess(verify["grounding_score"], 1.0)
            self.assertEqual({f["status"] for f in verify["flagged"]}, {"drifted", "hallucinated"})
            self.assertTrue(os.path.exists(os.path.join(out, "o.sarif")))
            self.assertTrue(replies[4]["result"]["isError"])  # refuses to overwrite

    def test_paths_outside_roots_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            replies = call([tool(1, "omniseek_scan", {"path": str(EXAMPLES)})], root)
        self.assertTrue(replies[1]["result"]["isError"])
        self.assertIn("outside the allowed roots", replies[1]["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
