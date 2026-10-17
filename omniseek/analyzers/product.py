# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Product-readiness rules: documentation, licensing, tests, CI and package metadata.

Rules about something missing cite an `absence`: the exact paths or globs the
verifier re-checks to confirm nothing matches.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import urllib.parse

from ..model import absence
from ..repo import Repo, language_of, matches_any
from .base import CODE_LANGUAGES, Emitter, line_span

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10
    tomllib = None

README_GLOBS = ["readme", "readme.*"]
LICENSE_GLOBS = ["license", "license.*", "licence", "licence.*", "copying", "copying.*", "unlicense"]
SECURITY_GLOBS = ["security.md", "security.rst", "security.txt", ".github/security.md", "docs/security.md"]
CONTRIBUTING_GLOBS = ["contributing", "contributing.*", ".github/contributing.md", "docs/contributing.md"]
TEST_GLOBS = [
    "test/*", "tests/*", "*/test/*", "*/tests/*", "*__tests__/*", "spec/*", "*/spec/*",
    "test_*.py", "*/test_*.py", "*_test.py", "*_test.go", "*.test.*", "*.spec.*", "*test.java",
    "*tests.cs", "*_spec.rb", "*_test.rb", "*_test.exs",
]
CI_GLOBS = [
    ".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml", ".circleci/*", "azure-pipelines.yml",
    "jenkinsfile", ".buildkite/*", ".travis.yml", "bitbucket-pipelines.yml", ".drone.yml", ".woodpecker*",
]
QUICKSTART_HEADING = re.compile(
    r"\b(install|installation|quick ?start|getting started|usage|setup|set up|run|running|how to|build|develop|"
    r"example|examples|tutorial|use)\b",
    re.I,
)
MD_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
LOREM = re.compile(r"\blorem ipsum\b", re.I)
UI_LANGUAGES = frozenset({"html", "javascript", "typescript", "vue", "svelte", "markdown"})


def _present(repo: Repo, globs: list[str]) -> bool:
    return any(matches_any(p, globs) for p in repo.files)


def _source_count(repo: Repo) -> int:
    return sum(1 for p in repo.files if language_of(p) in CODE_LANGUAGES)


def _readme(repo: Repo) -> str | None:
    tops = sorted(p for p in repo.files if "/" not in p and matches_any(p, README_GLOBS))
    preferred = [p for p in tops if p.lower().endswith(".md")]
    return (preferred or tops or [None])[0]


def _declared_license(repo: Repo) -> str | None:
    if repo.has_file("package.json"):
        try:
            manifest = json.loads(repo.text("package.json") or "")
            if isinstance(manifest, dict) and isinstance(manifest.get("license"), str):
                return manifest["license"]
        except ValueError:
            pass
    if repo.has_file("pyproject.toml") and tomllib is not None:
        try:
            project = tomllib.loads(repo.text("pyproject.toml") or "").get("project", {})
        except (ValueError, tomllib.TOMLDecodeError):
            project = {}
        license_value = project.get("license")
        if isinstance(license_value, str):
            return license_value
        if isinstance(license_value, dict) and isinstance(license_value.get("text"), str):
            return license_value["text"]
    return None


def docs_and_policy(repo: Repo, emitter: Emitter) -> None:
    readme = _readme(repo)
    if readme is None:
        emitter.add(
            "product/missing-readme",
            [absence(globs=README_GLOBS, note="no README at the repository root")],
            "The repository root has no README.",
            confidence="high",
        )
    else:
        lines = repo.lines(readme) or []
        headings = [
            (n, line) for n, line in enumerate(lines, 1)
            if line.lstrip().startswith("#") or (n > 1 and re.fullmatch(r"\s*(=+|-+)\s*", line) and lines[n - 2].strip())
        ]
        heading_text = " ".join(
            line if line.lstrip().startswith("#") else lines[n - 2] for n, line in headings
        )
        if lines and not QUICKSTART_HEADING.search(heading_text):
            first = next((n for n, line in enumerate(lines, 1) if line.strip()), None)
            if first:
                emitter.add(
                    "product/readme-missing-quickstart",
                    [line_span(readme, lines, first)],
                    f"{readme} has {len(headings)} heading(s) and none covers installing, running or using the project.",
                    confidence="medium",
                )
    if not _present(repo, LICENSE_GLOBS):
        declared = _declared_license(repo)
        emitter.add(
            "product/missing-license",
            [absence(globs=LICENSE_GLOBS, note="no license file at the repository root")],
            "There is no LICENSE file."
            + (f" The package manifest declares `{declared}` but ships no license text." if declared else ""),
            severity="medium" if declared else "high",
            confidence="high",
        )
    if _source_count(repo) >= 5:
        if not _present(repo, SECURITY_GLOBS):
            emitter.add(
                "product/missing-security-policy",
                [absence(globs=SECURITY_GLOBS)],
                "There is no SECURITY.md telling researchers how to report a vulnerability.",
            )
        if not _present(repo, CONTRIBUTING_GLOBS):
            emitter.add(
                "product/missing-contributing",
                [absence(globs=CONTRIBUTING_GLOBS)],
                "There is no CONTRIBUTING guide.",
            )


def tests_and_ci(repo: Repo, emitter: Emitter) -> None:
    sources = _source_count(repo)
    if sources < 5:
        return
    if not _present(repo, TEST_GLOBS):
        emitter.add(
            "product/no-tests",
            [absence(globs=TEST_GLOBS, note="no file matches common test naming conventions")],
            f"{sources} source files and no test files.",
            confidence="medium",
        )
    if not _present(repo, CI_GLOBS):
        emitter.add(
            "product/no-ci",
            [absence(globs=CI_GLOBS)],
            "No CI configuration was found (GitHub Actions, GitLab CI, CircleCI, Azure Pipelines, Jenkins and others).",
        )


def _exists(repo: Repo, rel: str) -> bool:
    if repo.has_file(rel) or any(p.startswith(rel + "/") for p in repo.files):
        return True
    return os.path.exists(repo.abspath(rel))


def broken_links(repo: Repo, emitter: Emitter, limit: int = 25) -> None:
    reported = 0
    for path in repo.files:
        if language_of(path) != "markdown":
            continue
        lines = repo.lines(path) or []
        fenced = False
        for number, line in enumerate(lines, 1):
            if line.lstrip().startswith(("```", "~~~")):
                fenced = not fenced
                continue
            if fenced or len(line) > 2000:
                continue
            for match in MD_LINK.finditer(line):
                target = match.group(1)
                if re.match(r"^([a-z][a-z0-9+.-]*:|#|/|\{|\$)", target, re.I):
                    continue
                clean = urllib.parse.unquote(target.split("#", 1)[0].split("?", 1)[0])
                if not clean:
                    continue
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), clean))
                if resolved.startswith("..") or resolved == ".":
                    continue
                if _exists(repo, resolved):
                    continue
                emitter.add(
                    "product/broken-doc-link",
                    [line_span(path, lines, number, snippet=match.group(0)), absence(paths=[resolved])],
                    f"{path}:{number} links to `{target}`, but `{resolved}` does not exist.",
                    confidence="high",
                )
                reported += 1
                if reported >= limit:
                    return


def package_metadata(repo: Repo, emitter: Emitter) -> None:
    if repo.has_file("pyproject.toml") and tomllib is not None:
        text = repo.text("pyproject.toml") or ""
        try:
            project = tomllib.loads(text).get("project")
        except (ValueError, tomllib.TOMLDecodeError):
            project = None
        if isinstance(project, dict):
            missing = [key for key in ("description", "license") if not project.get(key)]
            lines = repo.lines("pyproject.toml") or []
            header = next((n for n, line in enumerate(lines, 1) if line.strip() == "[project]"), None)
            if missing and header:
                emitter.add(
                    "product/incomplete-package-metadata",
                    [line_span("pyproject.toml", lines, header)],
                    f"pyproject.toml [project] has no {' or '.join(missing)}.",
                )
    if repo.has_file("package.json"):
        try:
            manifest = json.loads(repo.text("package.json") or "")
        except ValueError:
            manifest = None
        if isinstance(manifest, dict) and manifest.get("private") is not True:
            missing = [key for key in ("description", "license") if not manifest.get(key)]
            lines = repo.lines("package.json") or []
            name_line = next((n for n, line in enumerate(lines, 1) if re.match(r'\s*"name"\s*:', line)), None)
            if missing and name_line:
                emitter.add(
                    "product/incomplete-package-metadata",
                    [line_span("package.json", lines, name_line)],
                    f"package.json is publishable (not private) but has no {' or '.join(missing)}.",
                )


def placeholder_content(repo: Repo, emitter: Emitter) -> None:
    for path in repo.files:
        if language_of(path) not in UI_LANGUAGES or "/test" in "/" + path.lower():
            continue
        lines = repo.lines(path) or []
        for number, line in enumerate(lines, 1):
            if len(line) < 2000 and LOREM.search(line):
                emitter.add(
                    "product/placeholder-content",
                    [line_span(path, lines, number)],
                    f"{path}:{number} still contains lorem ipsum placeholder text.",
                )
                break


def analyze(repo: Repo, emitter: Emitter) -> None:
    if not emitter.wants("product"):
        return
    docs_and_policy(repo, emitter)
    tests_and_ci(repo, emitter)
    broken_links(repo, emitter)
    package_metadata(repo, emitter)
    placeholder_content(repo, emitter)
