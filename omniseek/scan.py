# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""`omniseek scan`: heuristics, an optional model pass, then citation verification."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile

from .analyzers import run_heuristics
from .llm import DEFAULT_MAX_CHARS, llm_findings
from .model import LENSES, new_document, sort_findings, summarize
from .repo import open_repo
from .rules import RULES
from .verify import drop_ungrounded, verify_document

REMOTE = re.compile(r"^(?:https://|ssh://|git://|git@[\w.-]+:)[^\s]+$")


class ScanError(RuntimeError):
    pass


def parse_lenses(value: str | list[str] | None) -> list[str]:
    if not value:
        return list(LENSES)
    items = value if isinstance(value, list) else value.split(",")
    lenses = [item.strip().lower() for item in items if item.strip()]
    unknown = [lens for lens in lenses if lens not in LENSES]
    if unknown:
        raise ScanError(f"unknown lens {unknown[0]!r}; choose from {', '.join(LENSES)}")
    return [lens for lens in LENSES if lens in lenses]


def resolve_target(target: str) -> tuple[str, str | None]:
    """A local directory, or a shallow clone of a git URL. Returns (path, url or None)."""
    if not REMOTE.match(target):
        return target, None
    if shutil.which("git") is None:
        raise ScanError("scanning a remote repository needs git on PATH")
    destination = tempfile.mkdtemp(prefix="omniseek-clone-")
    result = subprocess.run(
        ["git", "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never", "clone", "--depth", "1",
         "--quiet", "--", target, destination],
        capture_output=True,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        shutil.rmtree(destination, ignore_errors=True)
        detail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()[-1:] or ["clone failed"]
        raise ScanError(f"git clone failed: {detail[0]}")
    return destination, target


def run_scan(
    target: str,
    *,
    lenses: list[str] | None = None,
    model: str | None = None,
    verify: bool = True,
    keep_ungrounded: bool = False,
    max_context_chars: int = DEFAULT_MAX_CHARS,
    timeout: float = 180.0,
) -> dict:
    lenses = lenses or list(LENSES)
    path, remote = resolve_target(target)
    repo = open_repo(path)
    findings, stats = run_heuristics(repo, lenses)
    analyzer: dict = {"mode": "heuristic", "model": None, "lenses": lenses, "rules": len(RULES), "stats": stats}
    if model:
        proposed, meta = llm_findings(
            repo, lenses, model, sort_findings(findings), max_chars=max_context_chars, timeout=timeout
        )
        findings = findings + proposed
        analyzer.update(mode="heuristic+llm", model=model, llm=meta)
    summary = repo.summary()
    if remote:
        summary["source"] = remote
    document = new_document(summary, analyzer, findings)
    if verify or model:
        document, _ = verify_document(document, repo.root)
        if model and not keep_ungrounded:
            document, removed = drop_ungrounded(document)
            analyzer["llm"]["dropped_ungrounded"] = removed
            if removed:
                document, _ = verify_document({k: v for k, v in document.items() if k != "verification"}, repo.root)
    document["summary"] = summarize(document["findings"])
    return document
