# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Minimal JSON-over-HTTPS client: httpx when installed (`omnirogue-omniseek[httpx]`), urllib otherwise."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504, 529})
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class HTTPError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def check_url(url: str) -> None:
    """Only HTTPS, or plain HTTP to this machine (for local model servers)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in LOCAL_HOSTS:
        return
    raise HTTPError(0, f"refusing to send data to {parts.scheme}://{parts.hostname or ''}: use https")


def _send(url: str, body: bytes, headers: dict[str, str], timeout: float) -> tuple[int, str]:
    try:
        import httpx  # type: ignore[import-not-found]
    except ImportError:
        httpx = None
    if httpx is not None:
        try:
            response = httpx.post(url, content=body, headers=headers, timeout=timeout)
        except httpx.HTTPError as exc:
            raise HTTPError(0, f"request to {urllib.parse.urlsplit(url).hostname} failed: {type(exc).__name__}") from exc
        return response.status_code, response.text
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - scheme checked above
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPError(0, f"request to {urllib.parse.urlsplit(url).hostname} failed: {exc}") from exc


def post_json(url: str, payload: dict, headers: dict[str, str], *, timeout: float = 180.0, retries: int = 2) -> dict:
    """POST JSON and return the decoded JSON reply. Error messages never include request headers."""
    check_url(url)
    body = json.dumps(payload).encode("utf-8")
    headers = {"content-type": "application/json", "user-agent": "omniseek", **headers}
    for attempt in range(retries + 1):
        status, text = _send(url, body, headers, timeout)
        if status in RETRY_STATUSES and attempt < retries:
            time.sleep(2 + attempt * 3)
            continue
        if status >= 400:
            raise HTTPError(status, f"HTTP {status} from {urllib.parse.urlsplit(url).hostname}: {text[:300]}")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise HTTPError(status, f"non-JSON reply from {urllib.parse.urlsplit(url).hostname}") from exc
    raise HTTPError(0, "unreachable")
