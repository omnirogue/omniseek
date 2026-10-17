# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Shared test fixtures: temporary repositories and a local stub HTTP server."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def fake_aws_key() -> str:
    """Built at runtime so no credential-shaped literal is committed."""
    return "AKIA" + "QZ7X" * 4


def make_repo(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory(prefix="omniseek-test-")
    for rel, content in files.items():
        path = Path(tmp.name, rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp


class StubServer:
    """Answers POSTs with `reply(path, body) -> dict` and records every request."""

    def __init__(self, reply):
        self.requests: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                length = int(self.headers.get("content-length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                headers = {k.lower(): v for k, v in self.headers.items()}  # urllib capitalizes, httpx does not
                stub.requests.append({"path": self.path, "headers": headers, "body": body})
                payload = json.dumps(reply(self.path, json.loads(body))).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # silence
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class EnvPatch:
    def __init__(self, **values: str | None):
        self.values = values
        self.saved: dict[str, str | None] = {}

    def __enter__(self):
        for key, value in self.values.items():
            self.saved[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
