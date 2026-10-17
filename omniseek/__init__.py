# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""OmniSeek: citation-grounded, multi-lens codebase intelligence.

Scan a repository, verify that every cited line really exists, and export the
result as an HTML dossier, SARIF 2.1.0 or Markdown. The core runs on the
Python standard library alone.
"""

from ._version import __version__
from .model import FINDINGS_SCHEMA, LENSES, SEVERITIES

__all__ = ["__version__", "FINDINGS_SCHEMA", "LENSES", "SEVERITIES"]
