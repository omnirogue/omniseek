# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Shared helpers for the heuristic analyzers."""

from __future__ import annotations

from collections import Counter

from ..model import absence, make_finding, span
from ..rules import RULES

PER_FILE_CAP = 5
PER_RULE_CAP = 60
SNIPPET_LIMIT = 200

CODE_LANGUAGES = frozenset(
    {
        "python", "javascript", "typescript", "go", "ruby", "php", "java", "kotlin", "csharp", "rust",
        "swift", "c", "cpp", "scala", "vue", "svelte", "shell",
    }
)
NON_PRODUCTION_PARTS = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "fixtures", "fixture", "examples", "example", "demo", "samples"}
)


def norm(text: str) -> str:
    return " ".join(text.split())


def snippet_of(line: str, limit: int = SNIPPET_LIMIT) -> str:
    """A quotable snippet: whitespace collapsed, cut to `limit` characters.

    A cut prefix of a whitespace-normalized line is still a substring of the
    normalized line, which is what the verifier compares.
    """
    return norm(line)[:limit].rstrip()


def is_non_production(path: str) -> bool:
    parts = path.lower().split("/")
    base = parts[-1]
    return (
        any(p in NON_PRODUCTION_PARTS for p in parts[:-1])
        or base.startswith("test_")
        or base.endswith(("_test.py", "_test.go", "_spec.rb"))
        or ".test." in base
        or ".spec." in base
    )


def line_span(
    path: str,
    lines: list[str],
    line_no: int,
    end_line: int | None = None,
    symbol: str | None = None,
    snippet: str | None = None,
    quote_line: int | None = None,
) -> dict:
    """A span citation over `line_no`..`end_line` (1-based, inclusive).

    It quotes `snippet` when given, otherwise line `quote_line` (default: the
    first line of the span).
    """
    if snippet is None:
        index = (quote_line or line_no) - 1
        snippet = snippet_of(lines[index]) if 0 <= index < len(lines) else ""
    return span(path, line_no, end_line or line_no, snippet, symbol)


class Emitter:
    """Collects findings for the selected lenses, with per-file and per-rule caps."""

    def __init__(self, lenses: list[str]):
        self.lenses = set(lenses)
        self.findings: list[dict] = []
        self._per_file: Counter = Counter()
        self._per_rule: Counter = Counter()
        self.capped: Counter = Counter()

    def wants(self, *lenses: str) -> bool:
        return any(lens in self.lenses for lens in lenses)

    def wants_rule(self, rule_id: str) -> bool:
        return RULES[rule_id].lens in self.lenses

    def add(
        self,
        rule_id: str,
        citations: list[dict],
        description: str,
        *,
        severity: str | None = None,
        confidence: str = "medium",
        evidence: dict | None = None,
        title: str | None = None,
        tags: tuple[str, ...] = (),
        cap_key: str | None = None,
    ) -> None:
        rule = RULES[rule_id]
        if rule.lens not in self.lenses:
            return
        if cap_key is None:
            cap_key = next((c["path"] for c in citations if c.get("kind") == "span"), "")
        if self._per_rule[rule_id] >= PER_RULE_CAP or self._per_file[(rule_id, cap_key)] >= PER_FILE_CAP:
            self.capped[rule_id] += 1
            return
        first_path = next((c["path"] for c in citations if c.get("kind") == "span"), None)
        if first_path and is_non_production(first_path):
            if rule.lens in ("architecture", "performance"):
                return  # test and example code is not held to production structure or speed
            if rule.lens == "security":
                confidence = "low"
                tags = tuple(tags) + ("non-production-path",)
        self._per_rule[rule_id] += 1
        self._per_file[(rule_id, cap_key)] += 1
        self.findings.append(
            make_finding(
                rule_id,
                rule.lens,
                severity or rule.severity,
                title or rule.title,
                description,
                rule.remediation,
                citations,
                confidence=confidence,
                evidence=evidence,
                tags=tags,
            )
        )


__all__ = [
    "CODE_LANGUAGES", "Emitter", "absence", "is_non_production", "line_span", "norm", "snippet_of", "span",
]
