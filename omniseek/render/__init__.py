# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Renderers for a findings document: HTML dossier, SARIF 2.1.0 and Markdown."""

from __future__ import annotations

FORMATS = ("html", "md", "sarif")


def grounding_of(finding: dict) -> float | None:
    verification = finding.get("verification")
    if isinstance(verification, dict) and isinstance(verification.get("grounding_score"), (int, float)):
        return float(verification["grounding_score"])
    return None


def grounding_label(score: float | None) -> tuple[str, str]:
    """(state, label): state is good, warning, critical or unknown."""
    if score is None:
        return "unknown", "not verified"
    if score >= 1.0:
        return "good", f"grounded {score:.2f}"
    if score > 0.0:
        return "warning", f"partial {score:.2f}"
    return "critical", f"ungrounded {score:.2f}"


def first_span(finding: dict) -> dict | None:
    return next((c for c in finding.get("citations", []) if c.get("kind", "span") == "span"), None)


def location(citation: dict | None) -> str:
    if not citation:
        return "repository"
    start, end = citation.get("start_line"), citation.get("end_line")
    if isinstance(start, int) and isinstance(end, int) and end != start:
        return f"{citation.get('path')}:{start}-{end}"
    if isinstance(start, int):
        return f"{citation.get('path')}:{start}"
    return str(citation.get("path"))


def render(document: dict, fmt: str) -> str:
    """Render a document; HTML and Markdown list findings most severe first."""
    if fmt in ("html", "md"):
        from ..model import sort_findings

        document = {**document, "findings": sort_findings(document.get("findings", []))}
    if fmt == "html":
        from .html import render_html

        return render_html(document)
    if fmt == "md":
        from .markdown import render_markdown

        return render_markdown(document)
    if fmt == "sarif":
        from .sarif import render_sarif

        return render_sarif(document)
    raise ValueError(f"unknown format {fmt!r}; use one of {', '.join(FORMATS)}")
