# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Read-only view of a local repository: which files exist and what they say.

Files come from `git ls-files` when the path is inside a git work tree (so
.gitignore is respected), otherwise from a directory walk that skips build
output and dependency folders. Symlinks are never followed, so nothing outside
the root is read. Patterns in an optional `.omniseekignore` file (one glob per
line, `#` comments) remove more paths.

Line numbering matches editors and git: lines are split on "\\n" only.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "bower_components", "__pycache__", ".venv", "venv",
        ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".eggs", "site-packages",
        "dist", "build", "target", ".next", ".nuxt", ".svelte-kit", "coverage", ".gradle",
        ".terraform", "vendor", ".cache", ".idea",
    }
)
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000

LANGUAGES = {
    ".py": "python", ".pyi": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
    ".cts": "typescript", ".go": "go", ".rb": "ruby", ".php": "php", ".java": "java", ".kt": "kotlin",
    ".cs": "csharp", ".rs": "rust", ".swift": "swift", ".c": "c", ".h": "c", ".cc": "cpp",
    ".cpp": "cpp", ".hpp": "cpp", ".scala": "scala", ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".sql": "sql", ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte",
    ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".json": "json", ".md": "markdown",
    ".tf": "terraform",
}
SPECIAL_FILES = {"dockerfile": "dockerfile", "makefile": "make", "jenkinsfile": "groovy"}


def language_of(path: str) -> str | None:
    base = os.path.basename(path).lower()
    if base in SPECIAL_FILES or base.startswith("dockerfile"):
        return SPECIAL_FILES.get(base, "dockerfile")
    return LANGUAGES.get(os.path.splitext(base)[1])


def split_lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def decode(data: bytes) -> str | None:
    """Text, or None for binary content (a NUL byte in the first 8 KiB)."""
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _git(root: str, *args: str, timeout: float = 30) -> subprocess.CompletedProcess | None:
    if shutil.which("git") is None:
        return None
    try:
        return subprocess.run(
            ["git", "-C", root, *args],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def is_safe_relpath(path: object) -> bool:
    """A relative POSIX path that stays inside the root (no absolute paths or `..`)."""
    if not isinstance(path, str) or not path or "\0" in path:
        return False
    if path.startswith(("/", "\\")) or (len(path) > 1 and path[1] == ":"):
        return False
    parts = path.replace("\\", "/").split("/")
    return ".." not in parts


def matches_any(path: str, globs: list[str]) -> bool:
    """Case-insensitive glob match on a relative path (`*` also crosses `/`)."""
    lowered = path.lower()
    return any(fnmatch.fnmatchcase(lowered, glob.lower()) for glob in globs)


def _load_ignore(root: str) -> list[str]:
    path = os.path.join(root, ".omniseekignore")
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []
    return [line.strip().rstrip("/") for line in lines if line.strip() and not line.lstrip().startswith("#")]


def _ignored(rel: str, patterns: list[str]) -> bool:
    if not patterns:
        return False
    parts = rel.split("/")
    candidates = ["/".join(parts[: i + 1]) for i in range(len(parts))] + parts
    return any(fnmatch.fnmatchcase(c, p) for p in patterns for c in candidates)


@dataclass
class Repo:
    root: str
    name: str
    files: list[str]
    is_git: bool = False
    commit: str | None = None
    truncated: bool = False
    max_file_bytes: int = MAX_FILE_BYTES
    _text: dict = field(default_factory=dict, repr=False)
    _lines: dict = field(default_factory=dict, repr=False)
    _file_set: frozenset = field(default=frozenset(), repr=False)

    def __post_init__(self) -> None:
        self._file_set = frozenset(self.files)

    # Contents -----------------------------------------------------------------
    def abspath(self, rel: str) -> str:
        return os.path.join(self.root, *rel.split("/"))

    def has_file(self, rel: str) -> bool:
        return rel in self._file_set

    def size(self, rel: str) -> int:
        try:
            return os.path.getsize(self.abspath(rel))
        except OSError:
            return -1

    def text(self, rel: str) -> str | None:
        """UTF-8 text of a listed file, or None if binary, too large or unreadable."""
        if rel in self._text:
            return self._text[rel]
        text = None
        if self.has_file(rel) and 0 <= self.size(rel) <= self.max_file_bytes:
            try:
                with open(self.abspath(rel), "rb") as handle:
                    text = decode(handle.read(self.max_file_bytes + 1))
            except OSError:
                text = None
        self._text[rel] = text
        return text

    def lines(self, rel: str) -> list[str] | None:
        if rel not in self._lines:
            text = self.text(rel)
            self._lines[rel] = None if text is None else split_lines(text)
        return self._lines[rel]

    def text_files(self, *languages: str) -> list[str]:
        wanted = set(languages)
        return [f for f in self.files if not wanted or language_of(f) in wanted]

    def languages(self) -> dict[str, int]:
        counts = Counter(language_of(f) for f in self.files)
        counts.pop(None, None)
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    # Git ----------------------------------------------------------------------
    def churn(self, max_commits: int = 1000, since: str = "1 year ago") -> Counter:
        """How many recent commits touched each file (empty outside git)."""
        if not self.is_git:
            return Counter()
        result = _git(
            self.root, "log", f"--since={since}", f"-n{max_commits}", "--format=", "--name-only", "--relative"
        )
        if result is None or result.returncode != 0:
            return Counter()
        names = result.stdout.decode("utf-8", errors="replace").splitlines()
        return Counter(name for name in names if name and name in self._file_set)

    def summary(self) -> dict:
        return {
            "root": self.root,
            "name": self.name,
            "commit": self.commit,
            "is_git": self.is_git,
            "files_scanned": len(self.files),
            "files_truncated": self.truncated,
            "root_files": [f for f in self.files if "/" not in f][:50],
            "languages": self.languages(),
        }


def _git_files(root: str) -> list[str] | None:
    result = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if result is None or result.returncode != 0:
        return None
    names = result.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return [n for n in names if n]


def _walk_files(root: str) -> list[str]:
    found: list[str] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in DEFAULT_EXCLUDED_DIRS and not d.endswith(".egg-info"))
        rel_dir = os.path.relpath(current, root)
        for name in sorted(files):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}".replace(os.sep, "/")
            found.append(rel)
        if len(found) > MAX_FILES * 2:
            break
    return found


def open_repo(path: str, *, max_files: int = MAX_FILES, max_file_bytes: int = MAX_FILE_BYTES) -> Repo:
    root = os.path.realpath(path)
    if not os.path.isdir(root):
        raise FileNotFoundError(f"not a directory: {path}")
    inside = _git(root, "rev-parse", "--is-inside-work-tree")
    is_git = bool(inside and inside.returncode == 0 and inside.stdout.strip() == b"true")
    names = _git_files(root) if is_git else None
    if names is None:
        is_git = False
        names = _walk_files(root)
    ignore = _load_ignore(root)
    files: list[str] = []
    for rel in sorted(set(names)):
        parts = rel.split("/")
        if any(p in DEFAULT_EXCLUDED_DIRS for p in parts[:-1]) or not is_safe_relpath(rel):
            continue
        if _ignored(rel, ignore):
            continue
        full = os.path.join(root, *parts)
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        files.append(rel)
    truncated = len(files) > max_files
    commit = None
    if is_git:
        head = _git(root, "rev-parse", "HEAD")
        if head is not None and head.returncode == 0:
            commit = head.stdout.decode().strip() or None
    return Repo(
        root=root,
        name=os.path.basename(root) or root,
        files=files[:max_files],
        is_git=is_git,
        commit=commit,
        truncated=truncated,
        max_file_bytes=max_file_bytes,
    )


def read_at_ref(root: str, ref: str, rel: str) -> str | None:
    """A file's text at a git revision, or None when it does not exist there."""
    result = _git(root, "show", f"{ref}:./{rel}")
    if result is None or result.returncode != 0:
        return None
    return decode(result.stdout)


def list_at_ref(root: str, ref: str) -> list[str] | None:
    result = _git(root, "ls-tree", "-r", "-z", "--name-only", "--full-tree", ref, "--", ".")
    if result is None or result.returncode != 0:
        return None
    prefix_result = _git(root, "rev-parse", "--show-prefix")
    prefix = prefix_result.stdout.decode().strip() if prefix_result and prefix_result.returncode == 0 else ""
    names = [n for n in result.stdout.decode("utf-8", errors="surrogateescape").split("\0") if n]
    return [n[len(prefix):] for n in names if n.startswith(prefix)]
