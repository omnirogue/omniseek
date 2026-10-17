# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""`omniseek cloud-sync`: the optional bridge to OmniSI Cloud.

Sends a findings document you already have (never the repository) to an
OmniSI Cloud workspace. The token is read from OMNISI_API_KEY only, so it never
appears in shell history or process listings. Nothing is sent without a token,
and `--dry-run` shows exactly what would be sent.

Payload (`omniseek.cloud-sync/v1`): client name and version, repository name
and commit (not the local path), analyzer settings, summary, verification
summary and the findings. `--no-snippets` strips quoted code and excerpts.

    POST {api_url}/v1/omniseek/scans
    Authorization: Bearer $OMNISI_API_KEY
    Idempotency-Key: sha256 of the payload
"""

from __future__ import annotations

import hashlib
import json
import os

from . import _http
from ._version import __version__

DEFAULT_API_URL = "https://api.omnirogue.com"
TOKEN_ENV = "OMNISI_API_KEY"
URL_ENV = "OMNISI_API_URL"
PAYLOAD_SCHEMA = "omniseek.cloud-sync/v1"


class CloudError(RuntimeError):
    pass


def _strip_code(finding: dict) -> dict:
    finding = dict(finding)
    finding["citations"] = [{k: v for k, v in c.items() if k != "snippet"} for c in finding.get("citations", [])]
    if isinstance(finding.get("verification"), dict):
        verification = dict(finding["verification"])
        verification["citations"] = [
            {k: v for k, v in c.items() if k != "excerpt"} for c in verification.get("citations", [])
        ]
        finding["verification"] = verification
    return finding


def build_payload(document: dict, *, include_snippets: bool = True) -> dict:
    repo = document.get("repo", {})
    findings = document.get("findings", [])
    if not include_snippets:
        findings = [_strip_code(f) for f in findings]
    return {
        "schema": PAYLOAD_SCHEMA,
        "client": {"name": "omniseek", "version": __version__},
        "repo": {"name": repo.get("name"), "commit": repo.get("commit"), "source": repo.get("source"),
                 "languages": repo.get("languages"), "files_scanned": repo.get("files_scanned")},
        "analyzer": document.get("analyzer", {}),
        "summary": document.get("summary", {}),
        "verification": document.get("verification"),
        "findings": findings,
    }


def endpoint(api_url: str | None) -> str:
    base = (api_url or os.environ.get(URL_ENV) or DEFAULT_API_URL).rstrip("/")
    return f"{base}/v1/omniseek/scans"


def sync(document: dict, *, api_url: str | None = None, include_snippets: bool = True, timeout: float = 60.0) -> dict:
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        raise CloudError(f"set {TOKEN_ENV} to an OmniSI Cloud API key (it is read from the environment only)")
    payload = build_payload(document, include_snippets=include_snippets)
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {
        "authorization": f"Bearer {token}",
        "idempotency-key": hashlib.sha256(body).hexdigest(),
    }
    try:
        return _http.post_json(endpoint(api_url), payload, headers, timeout=timeout)
    except _http.HTTPError as exc:
        raise CloudError(str(exc)) from exc
