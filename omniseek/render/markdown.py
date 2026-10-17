# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""GitHub-flavored Markdown for pull-request comments and issues.

Output stays under GitHub's 65,536-character comment limit: when findings do
not fit, the lowest-severity ones are summarized in a closing note.
"""

from __future__ import annotations

from .._version import __version__
from ..model import LENSES, SEVERITIES
from . import first_span, grounding_label, grounding_of, location

COMMENT_LIMIT = 60_000
SEVERITY_ICONS = {"critical": "🛑", "high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪"}
GROUNDING_ICONS = {"good": "✅", "warning": "🟡", "critical": "❌", "unknown": "➖"}


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _inline(text: object) -> str:
    value = str(text).replace("`", "'")
    return f"`{value}`"


def _fence(lines: list[str]) -> str:
    body = "\n".join(lines)
    fence = "```"
    while fence in body:
        fence += "`"
    return f"{fence}\n{body}\n{fence}"


def _finding_block(finding: dict) -> str:
    state, label = grounding_label(grounding_of(finding))
    severity = finding.get("severity", "info")
    parts = [
        f"#### {SEVERITY_ICONS.get(severity, '')} {severity.upper()} · {_cell(finding.get('title', ''))}",
        "",
        f"**{finding.get('lens', '')}** · {_inline(location(first_span(finding)))} · "
        f"{GROUNDING_ICONS[state]} {label} · {_inline(finding.get('rule_id', ''))} · `{finding.get('id', '')}`",
        "",
    ]
    if finding.get("description"):
        parts += [finding["description"], ""]
    if finding.get("remediation"):
        parts += ["**Remediation**", ""] + [f"{i}. {step}" for i, step in enumerate(finding["remediation"], 1)] + [""]
    verification = {c["index"]: c for c in (finding.get("verification") or {}).get("citations", [])}
    evidence: list[str] = []
    for index, citation in enumerate(finding.get("citations", [])):
        check = verification.get(index)
        status = f" — {check['status']}: {check['reason']}" if check else ""
        if citation.get("kind") == "absence":
            targets = ", ".join(_inline(p) for p in (citation.get("paths") or []) + (citation.get("globs") or []))
            evidence.append(f"- absent: {targets}{status}")
            continue
        evidence.append(f"- {_inline(location(citation))}{status}")
        if check and check.get("excerpt"):
            evidence.append(_fence([f"{row['line']:>5}  {row['text']}" for row in check["excerpt"]]))
        elif citation.get("snippet"):
            evidence.append(_fence([str(citation["snippet"])]))
    if evidence:
        parts += [f"<details><summary>Evidence ({len(finding.get('citations', []))})</summary>", ""]
        parts += evidence + ["", "</details>", ""]
    return "\n".join(parts)


def render_markdown(document: dict) -> str:
    findings = document.get("findings", [])
    repo = document.get("repo", {})
    analyzer = document.get("analyzer", {})
    verification = document.get("verification") or {}
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES}
    lens_counts = {lens: sum(1 for f in findings if f.get("lens") == lens) for lens in LENSES}
    head = [f"## OmniSeek report · {_cell(repo.get('name') or 'repository')}", ""]
    meta = [f"{len(findings)} findings", f"{repo.get('files_scanned', '?')} files scanned"]
    if repo.get("commit"):
        meta.append(f"commit `{repo['commit'][:12]}`")
    meta.append(f"mode `{analyzer.get('mode', 'heuristic')}`" + (f" ({analyzer['model']})" if analyzer.get("model") else ""))
    if "grounding_score" in verification:
        state, _ = grounding_label(verification["grounding_score"])
        meta.append(f"grounding {GROUNDING_ICONS[state]} **{verification['grounding_score']:.2f}**")
    head += [" · ".join(meta), ""]
    head += [
        "| Severity | Count | | Lens | Count |",
        "| --- | ---: | --- | --- | ---: |",
    ]
    rows = max(len(SEVERITIES), len(LENSES))
    for i in range(rows):
        sev = f"{SEVERITY_ICONS[SEVERITIES[i]]} {SEVERITIES[i]} | {counts[SEVERITIES[i]]}" if i < len(SEVERITIES) else " | "
        lens = f"{LENSES[i]} | {lens_counts[LENSES[i]]}" if i < len(LENSES) else " | "
        head.append(f"| {sev} | | {lens} |")
    head.append("")
    if not findings:
        head.append("No findings. 🎉")
    body: list[str] = []
    size = sum(len(line) + 1 for line in head)
    omitted: list[dict] = []
    for finding in findings:
        block = _finding_block(finding)
        if size + len(block) > COMMENT_LIMIT:
            omitted.append(finding)
            continue
        body.append(block)
        size += len(block) + 1
    tail = []
    if omitted:
        left = ", ".join(
            f"{n} {s}" for s in SEVERITIES if (n := sum(1 for f in omitted if f.get("severity") == s))
        )
        tail.append(
            f"> {len(omitted)} more finding(s) did not fit in one comment ({left}). "
            "See the HTML dossier or SARIF output for all findings."
        )
    tail.append(f"\n<sub>Generated by [OmniSeek](https://github.com/omnirogue/omniseek) {__version__}. "
                "Heuristic and model findings can be wrong; check the cited lines before acting.</sub>")
    return "\n".join(head + body + tail) + "\n"
