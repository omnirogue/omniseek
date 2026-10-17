# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Citation and grounding verifier.

Checks every citation in a findings document against a local repository (the
working tree, or any git revision with `ref`) and scores how well each finding
is grounded. It runs no models and makes no network calls.

For a `span` citation it checks, in order:

1. the path is relative and stays inside the repository;
2. the file exists and is text;
3. the line range is well formed and inside the file;
4. the quoted `snippet` (whitespace-normalized) appears inside the cited lines;
5. the `symbol`, if given, appears as a whole identifier inside the cited lines.

For an `absence` citation it checks that none of the listed paths or globs exist.

Each citation gets a status and a score:

    verified      1.0  everything above holds
    drifted       0.5  the quote or symbol exists in the file, but at other lines
    unanchored    0.5  the range exists but nothing is quoted, so content cannot be checked
    hallucinated  0.0  the file, quote or symbol does not exist; or a claimed absence is present
    invalid       0.0  the citation is malformed or points outside the repository

A finding's `grounding_score` is the mean of its citation scores (0.0 without
citations). The document score is the mean over findings. Quote matching proves
provenance, not that the finding is correct: a verified citation shows the
evidence exists where the finding says it does.
"""

from __future__ import annotations

import bisect
import os
import re
from typing import Iterable

from .analyzers.patterns import redact
from .model import VERIFICATION_SCHEMA, utc_now
from .repo import (
    MAX_FILE_BYTES,
    _git,
    decode,
    is_safe_relpath,
    list_at_ref,
    matches_any,
    open_repo,
    read_at_ref,
    split_lines,
)

SCORES = {"verified": 1.0, "drifted": 0.5, "unanchored": 0.5, "hallucinated": 0.0, "invalid": 0.0}
EXCERPT_LINES = 15
VERIFY_MAX_BYTES = max(MAX_FILE_BYTES, 5_000_000)
MIN_SNIPPET_CHARS = 3


def _norm(text: str) -> str:
    return " ".join(text.split())


class WorkingTree:
    """Files as they are on disk. Symlinks that leave the root count as outside."""

    def __init__(self, root: str):
        self.root = os.path.realpath(root)
        if not os.path.isdir(self.root):
            raise FileNotFoundError(f"repository not found: {root}")
        self._repo = open_repo(self.root)
        self.label = "working-tree"
        self.commit = self._repo.commit
        self._cache: dict[str, object] = {}

    def files(self) -> list[str]:
        return self._repo.files

    def _real(self, rel: str) -> str | None:
        real = os.path.realpath(os.path.join(self.root, *rel.split("/")))
        if real != self.root and not real.startswith(self.root + os.sep):
            return None
        return real

    def inside(self, rel: str) -> bool:
        return self._real(rel) is not None

    def exists(self, rel: str) -> bool:
        real = self._real(rel)
        return real is not None and os.path.exists(real)

    def is_dir(self, rel: str) -> bool:
        real = self._real(rel)
        return real is not None and os.path.isdir(real)

    def lines(self, rel: str) -> list[str] | None | str:
        """Lines of a text file; None if missing; "binary" or "too-large" otherwise."""
        if rel in self._cache:
            return self._cache[rel]  # type: ignore[return-value]
        real = self._real(rel)
        result: list[str] | None | str = None
        if real is not None and os.path.isfile(real):
            if os.path.getsize(real) > VERIFY_MAX_BYTES:
                result = "too-large"
            else:
                with open(real, "rb") as handle:
                    text = decode(handle.read())
                result = "binary" if text is None else split_lines(text)
        self._cache[rel] = result
        return result


class GitRevision:
    """Files as committed at a git revision (branch, tag or SHA)."""

    def __init__(self, root: str, ref: str):
        self.root = os.path.realpath(root)
        names = list_at_ref(self.root, ref)
        if names is None:
            raise FileNotFoundError(f"cannot read git revision {ref!r} in {root}")
        resolved = _git(self.root, "rev-parse", ref)
        self.commit = resolved.stdout.decode().strip() if resolved and resolved.returncode == 0 else None
        self.label = ref
        self._ref = ref
        self._files = names
        self._set = set(names)
        self._cache: dict[str, object] = {}

    def files(self) -> list[str]:
        return self._files

    def inside(self, rel: str) -> bool:
        return True

    def exists(self, rel: str) -> bool:
        return rel in self._set or any(name.startswith(rel.rstrip("/") + "/") for name in self._files)

    def is_dir(self, rel: str) -> bool:
        return rel not in self._set and self.exists(rel)

    def lines(self, rel: str) -> list[str] | None | str:
        if rel not in self._cache:
            text = read_at_ref(self.root, self._ref, rel) if rel in self._set else None
            if text is None and rel in self._set:
                self._cache[rel] = "binary"
            else:
                self._cache[rel] = None if text is None else split_lines(text)
        return self._cache[rel]  # type: ignore[return-value]


def _locate(lines: list[str], needle: str, near: int) -> tuple[int, int] | None:
    """Where a normalized quote occurs in the file, as (start_line, end_line) nearest to `near`."""
    starts: list[int] = []
    numbers: list[int] = []
    parts: list[str] = []
    offset = 0
    for number, line in enumerate(lines, 1):
        normalized = _norm(line)
        if not normalized:
            continue
        starts.append(offset)
        numbers.append(number)
        parts.append(normalized)
        offset += len(normalized) + 1
    haystack = " ".join(parts)
    best: tuple[int, int] | None = None
    position = haystack.find(needle)
    tries = 0
    while position != -1 and tries < 1000:
        first = numbers[bisect.bisect_right(starts, position) - 1]
        last = numbers[bisect.bisect_right(starts, position + len(needle) - 1) - 1]
        if best is None or abs(first - near) < abs(best[0] - near):
            best = (first, last)
        position = haystack.find(needle, position + 1)
        tries += 1
    return best


def _excerpt(lines: list[str], start: int, end: int) -> list[dict]:
    """The cited lines as they are in the file (credential-looking values redacted)."""
    end = min(end, len(lines), start + EXCERPT_LINES - 1)
    return [{"line": n, "text": redact(lines[n - 1])[:300]} for n in range(start, end + 1)]


def _symbol_pattern(symbol: str) -> re.Pattern:
    return re.compile(r"(?<![\w$])" + re.escape(symbol) + r"(?![\w$])")


def _result(index: int, citation: dict, status: str, reason: str, **extra: object) -> dict:
    result = {
        "index": index,
        "kind": citation.get("kind", "span"),
        "status": status,
        "score": SCORES[status],
        "reason": reason,
    }
    if result["kind"] == "span":
        result.update(path=citation.get("path"), start_line=citation.get("start_line"), end_line=citation.get("end_line"))
    result.update(extra)
    return result


def _verify_absence(index: int, citation: dict, source) -> dict:
    paths = citation.get("paths") or []
    globs = citation.get("globs") or []
    if not paths and not globs:
        return _result(index, citation, "invalid", "absence citation lists no paths or globs")
    unsafe = [p for p in paths if not is_safe_relpath(p)]
    if unsafe:
        return _result(index, citation, "invalid", f"path {unsafe[0]!r} is not a relative path inside the repository")
    present = [p for p in paths if source.exists(p)]
    if globs:
        present += [f for f in source.files() if matches_any(f, globs)][:5]
    if present:
        return _result(index, citation, "hallucinated", f"claimed absent, but `{present[0]}` exists", found=present[:5])
    return _result(index, citation, "verified", "none of the listed paths or globs exist")


def _open_span(citation: dict, source) -> tuple[str, str] | list[str]:
    """The file's lines, or (status, reason) when the citation cannot be checked."""
    path = citation.get("path")
    start, end = citation.get("start_line"), citation.get("end_line")
    if not is_safe_relpath(path):
        return "invalid", "path must be relative and stay inside the repository"
    if not source.inside(path):
        return "invalid", "path resolves outside the repository (symlink)"
    if not all(isinstance(n, int) and not isinstance(n, bool) for n in (start, end)):
        return "invalid", "start_line and end_line must be integers"
    if start < 1 or end < start:
        return "invalid", f"line range {start}-{end} is not a valid 1-based inclusive range"
    lines = source.lines(path)
    if lines is None:
        return ("invalid", "path is a directory, not a file") if source.is_dir(path) else ("hallucinated", "file does not exist")
    if isinstance(lines, str):
        return "invalid", f"file is {lines.replace('-', ' ')} and cannot be quoted"
    return lines


def _quote_checks(
    lines: list[str], start: int, end: int, snippet: str, symbol: str | None
) -> tuple[dict, tuple[int, int] | None]:
    """Where the quote and symbol occur: in_span, elsewhere or not_found (and where, if elsewhere)."""
    in_range = end <= len(lines)
    window = "\n".join(lines[start - 1:end]) if in_range else ""
    checks: dict[str, object] = {"path": "ok", "range": "ok" if in_range else f"past end of file ({len(lines)} lines)"}
    actual: tuple[int, int] | None = None
    if snippet:
        if in_range and snippet in _norm(window):
            checks["snippet"] = "in_span"
        else:
            actual = _locate(lines, snippet, start)
            checks["snippet"] = "elsewhere" if actual else "not_found"
    if symbol:
        pattern = _symbol_pattern(symbol)
        if in_range and pattern.search(window):
            checks["symbol"] = "in_span"
        else:
            hit = next((n for n, line in enumerate(lines, 1) if pattern.search(line)), None)
            checks["symbol"] = "elsewhere" if hit else "not_found"
            if hit and actual is None:
                actual = (hit, hit)
    return checks, actual


def _verify_span(index: int, citation: dict, source) -> dict:
    opened = _open_span(citation, source)
    if isinstance(opened, tuple):
        return _result(index, citation, *opened)
    lines = opened
    start, end = citation["start_line"], citation["end_line"]
    snippet = _norm(citation["snippet"]) if isinstance(citation.get("snippet"), str) else ""
    snippet = snippet if len(snippet) >= MIN_SNIPPET_CHARS else ""
    symbol = citation.get("symbol").strip() if isinstance(citation.get("symbol"), str) else ""
    checks, actual = _quote_checks(lines, start, end, snippet, symbol or None)
    in_range = end <= len(lines)
    shown = actual or ((start, end) if in_range else None)
    extra: dict = {"checks": checks}
    if shown:
        extra["excerpt"] = _excerpt(lines, *shown)

    if checks.get("snippet") == "not_found":
        return _result(index, citation, "hallucinated", "quoted snippet does not appear anywhere in the file", **extra)
    if checks.get("symbol") == "not_found":
        return _result(index, citation, "hallucinated", f"symbol `{symbol}` does not appear in the file", **extra)
    if not snippet and not symbol:
        if not in_range:
            reason = f"lines {start}-{end} are past the end of the file ({len(lines)} lines)"
            return _result(index, citation, "hallucinated", reason, **extra)
        return _result(index, citation, "unanchored", "the range exists but nothing is quoted, so its content was not checked", **extra)
    if "elsewhere" in (checks.get("snippet"), checks.get("symbol")):
        where = ""
        if actual:
            extra["actual_lines"] = {"start_line": actual[0], "end_line": actual[1]}
            found = f"line {actual[0]}" if actual[0] == actual[1] else f"lines {actual[0]}-{actual[1]}"
            where = f" (found at {found})"
        return _result(index, citation, "drifted", f"the quoted evidence exists but outside lines {start}-{end}{where}", **extra)
    return _result(index, citation, "verified", "path, range, quote and symbol all check out", **extra)


def verify_citation(index: int, citation: object, source) -> dict:
    if not isinstance(citation, dict):
        return _result(index, {}, "invalid", "citation must be an object")
    kind = citation.get("kind", "span")
    if kind == "absence":
        return _verify_absence(index, citation, source)
    if kind != "span":
        return _result(index, citation, "invalid", f"unknown citation kind {kind!r}")
    return _verify_span(index, citation, source)


def verify_finding(finding: dict, source) -> dict:
    results = [verify_citation(i, c, source) for i, c in enumerate(finding.get("citations") or [])]
    if not results:
        return {"grounding_score": 0.0, "status": "missing_citation", "citations": []}
    score = round(sum(r["score"] for r in results) / len(results), 4)
    status = "grounded" if score == 1.0 else "ungrounded" if score == 0.0 else "partially_grounded"
    return {"grounding_score": score, "status": status, "citations": results}


def open_source(repo: str, ref: str | None = None):
    return GitRevision(repo, ref) if ref else WorkingTree(repo)


def verify_document(document: dict, repo: str, ref: str | None = None) -> tuple[dict, dict]:
    """Return (annotated document, verification report). The input is not modified."""
    source = open_source(repo, ref)
    annotated = dict(document)
    findings = []
    by_status = {status: 0 for status in SCORES}
    flagged = []
    for finding in document.get("findings", []):
        verification = verify_finding(finding, source)
        findings.append({**finding, "verification": verification})
        for citation in verification["citations"]:
            by_status[citation["status"]] += 1
            if citation["status"] in ("hallucinated", "invalid", "drifted"):
                flagged.append(
                    {
                        "finding_id": finding.get("id"),
                        "title": finding.get("title"),
                        "citation": citation["index"],
                        "status": citation["status"],
                        "reason": citation["reason"],
                        "path": citation.get("path"),
                        "start_line": citation.get("start_line"),
                        "end_line": citation.get("end_line"),
                    }
                )
        if verification["status"] == "missing_citation":
            flagged.append(
                {
                    "finding_id": finding.get("id"),
                    "title": finding.get("title"),
                    "citation": None,
                    "status": "missing_citation",
                    "reason": "the finding cites no evidence",
                }
            )
    scores = [f["verification"]["grounding_score"] for f in findings]
    statuses = [f["verification"]["status"] for f in findings]
    report = {
        "schema": VERIFICATION_SCHEMA,
        "verified_at": utc_now(),
        "repo": source.root,
        "ref": source.label,
        "commit": source.commit,
        "grounding_score": round(sum(scores) / len(scores), 4) if scores else 1.0,
        "vacuous": not scores,
        "verified": all(status == "grounded" for status in statuses),
        "findings_total": len(findings),
        "findings_grounded": statuses.count("grounded"),
        "findings_partially_grounded": statuses.count("partially_grounded"),
        "findings_ungrounded": statuses.count("ungrounded") + statuses.count("missing_citation"),
        "citations_total": sum(by_status.values()),
        "citations_by_status": by_status,
        "flagged": flagged,
    }
    annotated["findings"] = findings
    annotated["verification"] = {k: v for k, v in report.items() if k != "flagged"}
    return annotated, report


def drop_ungrounded(document: dict, keep_sources: Iterable[str] = ("heuristic",)) -> tuple[dict, int]:
    """Remove findings scored 0.0 (except from trusted sources). Returns (document, removed count)."""
    keep = set(keep_sources)
    kept = [
        f for f in document.get("findings", [])
        if f.get("source") in keep or f.get("verification", {}).get("grounding_score", 0.0) > 0.0
    ]
    removed = len(document.get("findings", [])) - len(kept)
    return {**document, "findings": kept}, removed
