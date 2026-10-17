# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""The deterministic multi-lens analyzer: same tree in, same findings out, no network."""

from __future__ import annotations

from ..repo import Repo
from . import patterns, product, python_ast, structure
from .base import Emitter


def run_heuristics(repo: Repo, lenses: list[str]) -> tuple[list[dict], dict]:
    """Every built-in rule for the selected lenses. Returns (findings, stats)."""
    emitter = Emitter(lenses)
    trees = python_ast.analyze(repo, emitter)
    patterns.analyze(repo, emitter)
    structure.analyze(repo, emitter, trees)
    product.analyze(repo, emitter)
    stats = {"python_files_parsed": len(trees), "capped": dict(sorted(emitter.capped.items()))}
    return emitter.findings, stats


__all__ = ["run_heuristics"]
