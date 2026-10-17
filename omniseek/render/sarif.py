# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""SARIF 2.1.0 for GitHub code scanning (upload with github/codeql-action/upload-sarif).

Each finding becomes one result at its first span citation. Repository-level
findings (only `absence` citations) are anchored at line 1 of the README or
package manifest, because code scanning requires a file location.
"""

from __future__ import annotations

import hashlib
import json

from .._version import __version__
from ..rules import RULES
from . import first_span, grounding_of

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/omnirogue/omniseek"
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
PRECISION = {"high": "high", "medium": "medium", "low": "low"}
ANCHOR_FILES = ("README.md", "README.rst", "README", "pyproject.toml", "package.json", "go.mod", "Cargo.toml")


def _rule_descriptor(rule_id: str, finding: dict) -> dict:
    rule = RULES.get(rule_id)
    title = rule.title if rule else finding.get("title", rule_id)
    summary = rule.summary if rule else finding.get("description", "") or title
    remediation = list(rule.remediation) if rule else finding.get("remediation", [])
    severity = rule.severity if rule else finding.get("severity", "medium")
    lens = rule.lens if rule else finding.get("lens", "architecture")
    help_md = summary + ("\n\n**Remediation**\n\n" + "\n".join(f"- {step}" for step in remediation) if remediation else "")
    tags = [lens, "omniseek"] + (["security"] if lens == "security" else [])
    properties = {"tags": tags, "precision": PRECISION.get(finding.get("confidence", "medium"), "medium")}
    if lens == "security":
        properties["security-severity"] = SECURITY_SEVERITY[severity]
    return {
        "id": rule_id,
        "name": "".join(part.title() for part in rule_id.replace("/", "-").split("-")),
        "shortDescription": {"text": title},
        "fullDescription": {"text": summary},
        "help": {"text": summary + ("\n\n" + "\n".join(remediation) if remediation else ""), "markdown": help_md},
        "defaultConfiguration": {"level": LEVELS[severity]},
        "properties": properties,
    }


def _anchor(document: dict) -> str | None:
    files = set()
    for finding in document.get("findings", []):
        for citation in finding.get("citations", []):
            if citation.get("kind", "span") == "span" and citation.get("path"):
                files.add(citation["path"])
    for name in ANCHOR_FILES:
        if name in files:
            return name
    root_files = document.get("repo", {}).get("root_files") or []
    return next((name for name in ANCHOR_FILES if name in root_files), "README.md")


def _location(citation: dict) -> dict:
    region: dict = {}
    start, end = citation.get("start_line"), citation.get("end_line")
    if isinstance(start, int) and start >= 1:
        region["startLine"] = start
        if isinstance(end, int) and end >= start:
            region["endLine"] = end
    if citation.get("snippet"):
        region["snippet"] = {"text": citation["snippet"]}
    physical: dict = {"artifactLocation": {"uri": citation.get("path"), "uriBaseId": "%SRCROOT%"}}
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def render_sarif(document: dict) -> str:
    findings = document.get("findings", [])
    rule_ids: list[str] = []
    descriptors: list[dict] = []
    results = []
    anchor = _anchor(document)
    for finding in findings:
        rule_id = finding.get("rule_id") or f"custom/{finding.get('lens', 'architecture')}"
        if rule_id not in rule_ids:
            rule_ids.append(rule_id)
            descriptors.append(_rule_descriptor(rule_id, finding))
        spans = [c for c in finding.get("citations", []) if c.get("kind", "span") == "span" and c.get("path")]
        primary = first_span(finding)
        locations = [_location(primary)] if primary and primary.get("path") else []
        if not locations and anchor:
            locations = [{"physicalLocation": {"artifactLocation": {"uri": anchor, "uriBaseId": "%SRCROOT%"},
                                               "region": {"startLine": 1}}}]
        message = finding.get("title", "")
        if finding.get("description"):
            message += f": {finding['description']}"
        if finding.get("remediation"):
            message += " Fix: " + finding["remediation"][0]
        fingerprint = hashlib.sha256(f"{rule_id}|{finding.get('id')}".encode()).hexdigest()
        properties = {
            "lens": finding.get("lens"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "source": finding.get("source"),
            "omniseekId": finding.get("id"),
        }
        score = grounding_of(finding)
        if score is not None:
            properties["groundingScore"] = score
            properties["groundingStatus"] = finding["verification"].get("status")
        result = {
            "ruleId": rule_id,
            "ruleIndex": rule_ids.index(rule_id),
            "level": LEVELS.get(finding.get("severity"), "warning"),
            "message": {"text": message},
            "locations": locations,
            "partialFingerprints": {"omniseekFindingHash/v1": fingerprint},
            "properties": properties,
        }
        related = [_location(c) for c in spans[1:6]]
        if related:
            for number, item in enumerate(related, 1):
                item["id"] = number
            result["relatedLocations"] = related
        results.append(result)
    repo = document.get("repo", {})
    run: dict = {
        "tool": {
            "driver": {
                "name": "OmniSeek",
                "informationUri": INFORMATION_URI,
                "version": __version__,
                "semanticVersion": __version__,
                "rules": descriptors,
            }
        },
        "results": results,
        "columnKind": "unicodeCodePoints",
        "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The repository root that was scanned."}}},
    }
    if repo.get("commit"):
        run["properties"] = {"commit": repo["commit"]}
    sarif = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"
