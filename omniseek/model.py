# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""The findings document (`omniseek.findings/v1`) and helpers to build and load it.

A document is plain JSON:

    {
      "schema": "omniseek.findings/v1",
      "tool": {"name": "omniseek", "version": "0.1.0"},
      "generated_at": "2026-01-01T00:00:00Z",
      "repo": {"root": "...", "name": "...", "commit": "...", "files_scanned": 42},
      "analyzer": {"mode": "heuristic", "model": null, "lenses": [...]},
      "summary": {"total": 3, "by_severity": {...}, "by_lens": {...}},
      "findings": [ { finding }, ... ],
      "verification": { ... }            # added by `omniseek verify`
    }

A finding cites its evidence. A `span` citation names a file and an inclusive
1-based line range, the exact text it quotes (`snippet`) and optionally a
`symbol` that must appear there. An `absence` citation claims that none of the
listed paths or globs exist in the repository. Both kinds are checked by
`omniseek.verify`.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from ._version import __version__

FINDINGS_SCHEMA = "omniseek.findings/v1"
VERIFICATION_SCHEMA = "omniseek.verification/v1"
LENSES = ("architecture", "security", "performance", "product")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
CONFIDENCES = ("high", "medium", "low")

_LINE_RANGE = re.compile(r"^(?P<path>.+?):(?P<start>\d+)(?:-(?P<end>\d+))?$")


class FindingsError(ValueError):
    """The findings document is malformed."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def span(path: str, start_line: int, end_line: int, snippet: str, symbol: str | None = None) -> dict:
    citation: dict[str, Any] = {
        "kind": "span",
        "path": path,
        "start_line": int(start_line),
        "end_line": int(end_line),
        "snippet": snippet,
    }
    if symbol:
        citation["symbol"] = symbol
    return citation


def absence(paths: Iterable[str] = (), globs: Iterable[str] = (), note: str | None = None) -> dict:
    citation: dict[str, Any] = {"kind": "absence", "paths": list(paths), "globs": list(globs)}
    if note:
        citation["note"] = note
    return citation


def _citation_identity(citation: dict) -> str:
    if citation.get("kind") == "absence":
        return "absent:" + ",".join(sorted(citation.get("paths", []) + citation.get("globs", [])))
    snippet = " ".join(str(citation.get("snippet") or "").split())
    return f"{citation.get('path')}|{snippet}|{citation.get('symbol') or ''}"


def finding_id(rule_id: str, citations: list[dict]) -> str:
    """A stable id: the same rule on the same evidence keeps its id when lines move."""
    digest = hashlib.sha256(rule_id.encode("utf-8"))
    for citation in citations:
        digest.update(b"\0" + _citation_identity(citation).encode("utf-8"))
    return "OSK-" + digest.hexdigest()[:12].upper()


def make_finding(
    rule_id: str,
    lens: str,
    severity: str,
    title: str,
    description: str,
    remediation: Iterable[str],
    citations: list[dict],
    *,
    confidence: str = "medium",
    source: str = "heuristic",
    evidence: dict | None = None,
    tags: Iterable[str] = (),
) -> dict:
    if lens not in LENSES:
        raise ValueError(f"unknown lens {lens!r}")
    if severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity {severity!r}")
    finding: dict[str, Any] = {
        "id": finding_id(rule_id, citations),
        "rule_id": rule_id,
        "lens": lens,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "remediation": [step for step in remediation if step],
        "citations": citations,
        "source": source,
    }
    if evidence:
        finding["evidence"] = evidence
    if tags:
        finding["tags"] = sorted(set(tags))
    return finding


def _primary_location(finding: dict) -> tuple[str, int]:
    for citation in finding.get("citations", []):
        if citation.get("kind", "span") == "span":
            line = citation.get("start_line")
            return str(citation.get("path") or ""), line if isinstance(line, int) else 0
    return "", 0


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(f.get("severity"), len(SEVERITIES)),
            *_primary_location(f),
            f.get("rule_id", ""),
            f.get("id", ""),
        ),
    )


def dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for finding in findings:
        seen.setdefault(finding["id"], finding)
    return list(seen.values())


def summarize(findings: list[dict]) -> dict:
    by_severity = {name: 0 for name in SEVERITIES}
    by_lens = {name: 0 for name in LENSES}
    for finding in findings:
        if finding.get("severity") in by_severity:
            by_severity[finding["severity"]] += 1
        by_lens[finding.get("lens")] = by_lens.get(finding.get("lens"), 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_lens": by_lens}


def new_document(repo: dict, analyzer: dict, findings: list[dict]) -> dict:
    findings = sort_findings(dedupe_findings(findings))
    return {
        "schema": FINDINGS_SCHEMA,
        "tool": {"name": "omniseek", "version": __version__},
        "generated_at": utc_now(),
        "repo": repo,
        "analyzer": analyzer,
        "summary": summarize(findings),
        "findings": findings,
    }


def _normalize_citation(raw: Any) -> dict:
    """Accept the common shapes tools and models produce; never raise.

    Malformed citations are kept with what could be read, so the verifier can
    report them as invalid instead of the whole document being rejected.
    """
    if isinstance(raw, str):
        match = _LINE_RANGE.match(raw.strip())
        if not match:
            return {"kind": "span", "path": raw, "start_line": None, "end_line": None, "snippet": None}
        start = int(match["start"])
        return {
            "kind": "span",
            "path": match["path"],
            "start_line": start,
            "end_line": int(match["end"] or start),
            "snippet": None,
        }
    if not isinstance(raw, dict):
        return {"kind": "span", "path": None, "start_line": None, "end_line": None, "snippet": None}
    citation = dict(raw)
    if citation.get("kind") == "absence":
        citation["paths"] = [p for p in citation.get("paths") or [] if isinstance(p, str)]
        citation["globs"] = [g for g in citation.get("globs") or [] if isinstance(g, str)]
        return citation
    citation["kind"] = "span"
    if "path" not in citation and isinstance(citation.get("file"), str):
        citation["path"] = citation.pop("file")
    lines = citation.pop("lines", None)
    if isinstance(lines, str) and "start_line" not in citation:
        match = re.match(r"^\s*(\d+)\s*(?:-\s*(\d+))?\s*$", lines)
        if match:
            citation["start_line"] = int(match[1])
            citation["end_line"] = int(match[2] or match[1])
    for key in ("start_line", "end_line"):
        value = citation.get(key)
        if isinstance(value, str) and value.strip().isdigit():
            citation[key] = int(value)
    if citation.get("end_line") is None and isinstance(citation.get("start_line"), int):
        citation["end_line"] = citation["start_line"]
    citation.setdefault("path", None)
    citation.setdefault("start_line", None)
    citation.setdefault("snippet", None)
    return citation


def normalize_finding(raw: Any, index: int) -> dict:
    if not isinstance(raw, dict):
        raise FindingsError(f"findings[{index}] must be an object")
    finding = dict(raw)
    title = finding.get("title")
    if not isinstance(title, str) or not title.strip():
        raise FindingsError(f"findings[{index}] needs a non-empty title")
    lens = str(finding.get("lens") or "").strip().lower()
    if lens not in LENSES:
        raise FindingsError(f"findings[{index}] has unknown lens {finding.get('lens')!r} (use one of {', '.join(LENSES)})")
    severity = str(finding.get("severity") or "").strip().lower()
    if severity not in SEVERITY_RANK:
        raise FindingsError(
            f"findings[{index}] has unknown severity {finding.get('severity')!r} (use one of {', '.join(SEVERITIES)})"
        )
    finding["lens"], finding["severity"] = lens, severity
    citations = finding.get("citations")
    if citations is None:
        citations = []
    if not isinstance(citations, list):
        raise FindingsError(f"findings[{index}].citations must be a list")
    finding["citations"] = [_normalize_citation(c) for c in citations]
    remediation = finding.get("remediation") or []
    if isinstance(remediation, str):
        remediation = [remediation]
    finding["remediation"] = [str(step) for step in remediation if str(step).strip()]
    finding["description"] = str(finding.get("description") or "")
    finding.setdefault("rule_id", f"custom/{lens}")
    finding.setdefault("confidence", "medium")
    finding.setdefault("source", "external")
    if not isinstance(finding.get("id"), str) or not finding["id"]:
        finding["id"] = finding_id(finding["rule_id"], finding["citations"])
    return finding


def load_document(source: Any) -> dict:
    """Load a findings document from a path, JSON text or an already parsed object.

    A bare list of findings is wrapped in a document.
    """
    if isinstance(source, (dict, list)):
        data = source
    else:
        try:
            with open(source, encoding="utf-8") as handle:
                data = json.load(handle)
        except OSError as exc:
            raise FindingsError(f"cannot read {source}: {exc.strerror or exc}") from exc
        except json.JSONDecodeError as exc:
            raise FindingsError(f"{source} is not valid JSON: {exc}") from exc
    if isinstance(data, list):
        data = {"schema": FINDINGS_SCHEMA, "findings": data}
    if not isinstance(data, dict):
        raise FindingsError("a findings document must be a JSON object or a list of findings")
    schema = data.get("schema", FINDINGS_SCHEMA)
    if schema != FINDINGS_SCHEMA:
        raise FindingsError(f"unsupported schema {schema!r}; expected {FINDINGS_SCHEMA!r}")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise FindingsError("the document needs a 'findings' list")
    document = dict(data)
    document["schema"] = FINDINGS_SCHEMA
    document["findings"] = [normalize_finding(raw, i) for i, raw in enumerate(findings)]
    document.setdefault("tool", {"name": "omniseek", "version": __version__})
    document.setdefault("repo", {})
    document.setdefault("analyzer", {})
    document["summary"] = summarize(document["findings"])
    return document


def dump_json(data: Any, path: str | None) -> str:
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if path and path != "-":
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    return text
