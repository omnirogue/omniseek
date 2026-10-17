# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Line-oriented rules: secrets, JavaScript/TypeScript, shell, CI, containers and dependencies.

Secret values are never copied into findings. A secret's citation quotes the
text before the value plus the value's first four characters (the public type
prefix for most providers), which is enough for the verifier to find the line.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter

from ..repo import Repo, language_of
from .base import CODE_LANGUAGES, Emitter, line_span, snippet_of

# Secrets ---------------------------------------------------------------------------------------
PROVIDER_SECRETS = [
    ("AWS access key id", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])")),
    ("API secret key", re.compile(r"(?<![A-Za-z0-9_-])sk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}")),
]
GENERIC_SECRET = re.compile(
    r"""(?i)\b([A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth[_-]?key|access[_-]?key))\b"""
    r"""["']?\s*[:=]\s*["']([^"'\s]{12,})["']"""
)
PLACEHOLDER_WORDS = (
    "example", "changeme", "change-me", "change_me", "your", "xxx", "placeholder", "dummy", "sample", "fake",
    "redacted", "****", "todo", "replace", "test", "secret", "password", "token", "<", "${", "{{", "%(", "$(",
)
SKIP_SECRET_FILES = re.compile(r"(\.lock|\.min\.js|\.map|\.svg|lock\.json|lock\.yaml|\.sum)$")
ENV_FILE = re.compile(r"^\.env(\.[\w-]+)?$")
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".tmpl")

# Code patterns -----------------------------------------------------------------------------------
JS_LANGS = frozenset({"javascript", "typescript", "vue", "svelte", "html"})
JS_EVAL = re.compile(r"(?<![\w.$])eval\s*\(\s*(?![\"'`][^\"'`$]*[\"'`]\s*\))|\bnew\s+Function\s*\(")
JS_EXEC = re.compile(r"\bexec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)")
JS_HTML_ASSIGN = re.compile(r"\.(?:inner|outer)HTML\s*\+?=\s*(.*)$")
JS_PLAIN_LITERAL = re.compile(r"""^(["'])[^"'`]*\1\s*;?\s*$|^`[^`$]*`\s*;?\s*$""")
JS_HTML_SINKS = re.compile(r"\bdangerouslySetInnerHTML\b|\bdocument\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\(")
JS_TLS = re.compile(r"\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0")
JS_ASYNC_FOREACH = re.compile(r"\.forEach\(\s*async\b")
JS_JSON_CLONE = re.compile(r"JSON\.parse\(\s*JSON\.stringify\(")
JS_DEEP_IMPORT = re.compile(r"""(?:from\s+|require\(\s*|import\s*\(\s*)["'](?:\.\./){4,}""")
CORS_ANY = re.compile(
    r"""Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|allow_origins\s*=\s*\[\s*["']\*["']"""
    r"""|\borigin\s*:\s*["']\*["']|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True"""
)
SELECT_STAR = re.compile(r"""["'`]\s*SELECT\s+\*\s+FROM\b""", re.I)
CHMOD_SHELL = re.compile(r"\bchmod\s+(?:-R\s+)?0?777\b")
CHMOD_CALL = re.compile(r"\bchmod(?:Sync)?\(\s*[^,]+,\s*0o?777\s*\)")
CURL_PIPE_SH = re.compile(r"\b(?:curl|wget)\b[^|#\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
SHELL_LIKE = frozenset({"shell", "dockerfile", "yaml", "make"})
COMMENT_PREFIXES = {
    "python": ("#",), "shell": ("#",), "yaml": ("#",), "dockerfile": ("#",), "make": ("#",), "ruby": ("#",),
    "toml": ("#",),
}
DEFAULT_COMMENT = ("//", "/*", "*", "#", "<!--")

# CI and containers -----------------------------------------------------------------------------
GHA_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([\w.-]+/[\w./-]+)@([\w./-]+)\s*(?:#.*)?$")
GHA_BRANCH_REFS = frozenset({"main", "master", "dev", "develop", "latest", "head", "trunk"})
GHA_UNTRUSTED = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits)"
    r"[\w.\[\]*]*\.(?:title|body|message|name|label|email|ref)|github\.head_ref)\s*\}\}"
)
GHA_RUN = re.compile(r"^(\s*)(?:-\s*)?run:\s*(.*)$")
GHA_HEAD_CHECKOUT = re.compile(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}")
DOCKER_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
DOCKER_USER = re.compile(r"^\s*USER\s+(\S+)", re.I)

# Dependencies ------------------------------------------------------------------------------------
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")
NPM_LOOSE = re.compile(r"^(\*|latest|x|)$|^(?:git\+)?https?://|^git(?:\+ssh)?://|^github:", re.I)


def redact(text: str) -> str:
    """Replace values that look like credentials with «redacted»."""
    for _, pattern in PROVIDER_SECRETS:
        text = pattern.sub("«redacted»", text)
    return GENERIC_SECRET.sub(lambda m: m.group(0).replace(m.group(2), "«redacted»"), text)


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _plausible_secret(value: str) -> bool:
    lowered = value.lower()
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return False
    if re.fullmatch(r"[A-Z0-9_]+", value) or re.fullmatch(r"[a-z_.]+", value):
        return False  # an environment variable name or a dotted setting name
    if "/" in value and "@" not in value and not re.search(r"[A-Za-z0-9+/]{30,}", value):
        return False  # a path or URL without credentials
    has_letters = re.search(r"[A-Za-z]", value) is not None
    has_digits = re.search(r"\d", value) is not None
    return has_letters and has_digits and _entropy(value) >= 3.0


def _secret_snippet(line: str, start: int) -> str:
    prefix = line[max(0, start - 60):start]
    return snippet_of(prefix + line[start:start + 4])


def _is_comment(line: str, language: str | None) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(COMMENT_PREFIXES.get(language or "", DEFAULT_COMMENT))


def scan_secrets(repo: Repo, emitter: Emitter) -> None:
    if not emitter.wants("security"):
        return
    for path in repo.files:
        base = os.path.basename(path)
        if ENV_FILE.match(base) and not base.endswith(ENV_TEMPLATE_SUFFIXES):
            lines = repo.lines(path) or []
            for number, line in enumerate(lines, 1):
                key, sep, _ = line.partition("=")
                if sep and key.strip() and not line.lstrip().startswith("#"):
                    emitter.add(
                        "security/committed-env-file",
                        [line_span(path, lines, number, snippet=snippet_of(key + "="))],
                        f"{path} is committed. It assigns `{key.strip()}` (value not shown) and possibly more.",
                    )
                    break
            continue
        if SKIP_SECRET_FILES.search(base):
            continue
        lines = repo.lines(path)
        if not lines:
            continue
        markdown = language_of(path) == "markdown"
        for number, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            for label, pattern in PROVIDER_SECRETS:
                match = pattern.search(line)
                if match and "EXAMPLE" not in match.group(0):
                    emitter.add(
                        "security/hardcoded-secret",
                        [line_span(path, lines, number, snippet=_secret_snippet(line, match.start()))],
                        f"{path}:{number} contains what looks like a {label} "
                        f"({len(match.group(0))} characters, value withheld).",
                        confidence="high",
                        evidence={"kind": label},
                    )
                    break
            else:
                if markdown:
                    continue
                match = GENERIC_SECRET.search(line)
                if match and _plausible_secret(match.group(2)):
                    emitter.add(
                        "security/hardcoded-secret",
                        [line_span(path, lines, number, snippet=_secret_snippet(line, match.start(2)), symbol=match.group(1))],
                        f"`{match.group(1)}` in {path}:{number} is assigned a literal "
                        f"{len(match.group(2))}-character value that looks like a credential (value withheld).",
                        confidence="medium",
                        evidence={"kind": "assignment"},
                    )


def _js_line(emitter: Emitter, path: str, lines: list[str], number: int, state: dict) -> None:
    line = lines[number - 1]

    def add(rule_id: str, description: str) -> None:
        emitter.add(rule_id, [line_span(path, lines, number)], description)

    if JS_EVAL.search(line):
        add("security/dangerous-eval", f"{path}:{number} evaluates a runtime string as code.")
    if state["child_process"] and JS_EXEC.search(line):
        add("security/shell-injection", f"{path}:{number} interpolates values into a shell command.")
    match = JS_HTML_ASSIGN.search(line)
    if match and not JS_PLAIN_LITERAL.match(match.group(1).strip()):
        add("security/xss-sink", f"{path}:{number} assigns computed markup to innerHTML/outerHTML.")
    elif JS_HTML_SINKS.search(line):
        add("security/xss-sink", f"{path}:{number} writes raw HTML.")
    if JS_TLS.search(line):
        add("security/tls-verification-disabled", f"{path}:{number} turns off TLS certificate checks.")
    if JS_ASYNC_FOREACH.search(line):
        add("performance/async-foreach", f"{path}:{number} passes an async callback to forEach.")
    if JS_JSON_CLONE.search(line):
        add("performance/json-deep-clone", f"{path}:{number} deep-clones through JSON.")
    if not state["deep_import"] and JS_DEEP_IMPORT.search(line):
        state["deep_import"] = True
        add("architecture/deep-relative-import", f"{path}:{number} imports across four or more parent directories.")


def _any_line(emitter: Emitter, path: str, lines: list[str], number: int, language: str, state: dict) -> None:
    line = lines[number - 1]
    cite = [line_span(path, lines, number)]
    if state["cors"] and CORS_ANY.search(line):
        emitter.add("security/permissive-cors", cite, f"{path}:{number} allows every origin.")
    if language in CODE_LANGUAGES and language != "shell" and SELECT_STAR.search(line):
        emitter.add("performance/select-star", cite, f"{path}:{number} selects every column.", confidence="low")
    if (CHMOD_SHELL if language in SHELL_LIKE else CHMOD_CALL).search(line):
        emitter.add("security/world-writable", cite, f"{path}:{number} makes a path world-writable.")
    if language in SHELL_LIKE and CURL_PIPE_SH.search(line):
        emitter.add("security/curl-pipe-shell", cite, f"{path}:{number} pipes a downloaded script into a shell.")


def scan_code_patterns(repo: Repo, emitter: Emitter) -> None:
    for path in repo.files:
        language = language_of(path)
        if language not in CODE_LANGUAGES and language not in JS_LANGS and language not in SHELL_LIKE:
            continue
        lines = repo.lines(path)
        if not lines:
            continue
        text = repo.text(path) or ""
        state = {
            "child_process": "child_process" in text,
            "cors": "cors" in text.lower() or "Access-Control" in text,
            "deep_import": False,
        }
        for number, line in enumerate(lines, 1):
            if len(line) > 1000 or _is_comment(line, language):
                continue
            if language in JS_LANGS:
                _js_line(emitter, path, lines, number, state)
            _any_line(emitter, path, lines, number, language, state)


def scan_workflows(repo: Repo, emitter: Emitter) -> None:
    if not emitter.wants("security"):
        return
    for path in repo.files:
        if not (path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))):
            continue
        lines = repo.lines(path) or []
        text = repo.text(path) or ""
        privileged = "pull_request_target" in text or "workflow_run" in text
        run_indent: int | None = None
        for number, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if run_indent is not None and stripped and indent <= run_indent:
                run_indent = None
            run = GHA_RUN.match(line)
            in_run = run_indent is not None
            if run:
                content = run.group(2).strip()
                if content[:1] in ("|", ">"):
                    run_indent = line.index("run:")
                in_run = True
            if in_run and GHA_UNTRUSTED.search(line):
                emitter.add(
                    "security/insecure-workflow",
                    [line_span(path, lines, number)],
                    f"{path}:{number} expands untrusted event text directly inside a run: script.",
                    confidence="high",
                )
            if privileged and GHA_HEAD_CHECKOUT.search(line):
                emitter.add(
                    "security/insecure-workflow",
                    [line_span(path, lines, number)],
                    f"{path}:{number} checks out pull-request code in a privileged (pull_request_target/workflow_run) workflow.",
                    confidence="medium",
                )
            uses = GHA_USES.match(line)
            if uses and uses.group(2).lower() in GHA_BRANCH_REFS:
                emitter.add(
                    "security/unpinned-action",
                    [line_span(path, lines, number)],
                    f"{path}:{number} runs `{uses.group(1)}` from the moving ref `{uses.group(2)}`.",
                )


def scan_dockerfiles(repo: Repo, emitter: Emitter) -> None:
    if not emitter.wants("security"):
        return
    for path in repo.files:
        if language_of(path) != "dockerfile":
            continue
        lines = repo.lines(path) or []
        stages: set[str] = set()
        last_from = None
        last_user = None
        for number, line in enumerate(lines, 1):
            match = DOCKER_FROM.match(line)
            if match:
                image, alias = match.group(1), match.group(2)
                last_from, last_user = number, None
                name = image.lower()
                if name not in stages and name != "scratch" and "$" not in image and "@sha256:" not in image:
                    tag = image.rsplit("/", 1)[-1].partition(":")[2]
                    if tag in ("", "latest"):
                        emitter.add(
                            "security/unpinned-base-image",
                            [line_span(path, lines, number)],
                            f"{path}:{number} builds FROM `{image}` without a fixed version.",
                        )
                if alias:
                    stages.add(alias.lower())
            user = DOCKER_USER.match(line)
            if user:
                last_user = (number, user.group(1))
        if last_from is None:
            continue
        if last_user is None:
            emitter.add(
                "security/container-runs-as-root",
                [line_span(path, lines, last_from)],
                f"The final stage of {path} (from line {last_from}) never sets USER, so it runs as root.",
                confidence="medium",
            )
        elif last_user[1].split(":")[0] in ("root", "0"):
            emitter.add(
                "security/container-runs-as-root",
                [line_span(path, lines, last_user[0])],
                f"{path}:{last_user[0]} switches the final stage to root.",
                confidence="high",
            )


def _requirements(repo: Repo, emitter: Emitter, path: str) -> None:
    lines = repo.lines(path) or []
    loose = []
    for number, line in enumerate(lines, 1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith(("-", "git+", "http:", "https:", "file:", ".")):
            continue
        match = REQ_LINE.match(stripped)
        if match and "==" not in match.group(3) and "@" not in stripped:
            loose.append(number)
    if loose:
        emitter.add(
            "security/unpinned-dependency",
            [line_span(path, lines, n) for n in loose[:5]],
            f"{path} lists {len(loose)} requirement(s) without an exact `==` version.",
            confidence="medium",
            evidence={"unpinned": len(loose)},
        )


def _package_json(repo: Repo, emitter: Emitter, path: str) -> None:
    try:
        manifest = json.loads(repo.text(path) or "")
    except ValueError:
        return
    if not isinstance(manifest, dict):
        return
    lines = repo.lines(path) or []
    loose: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = manifest.get(section)
        if isinstance(deps, dict):
            loose += [(d, v) for d, v in deps.items() if isinstance(v, str) and NPM_LOOSE.search(v.strip())]
    citations, names = [], []
    for dep, version in loose:
        needle, value = json.dumps(dep), json.dumps(version)
        number = next((n for n, line in enumerate(lines, 1) if needle in line and value in line), None)
        if number:
            citations.append(line_span(path, lines, number))
            names.append(f"{dep}@{version or '(empty)'}")
    if citations:
        more = f" and {len(names) - 5} more" if len(names) > 5 else ""
        emitter.add(
            "security/unpinned-dependency",
            citations[:5],
            f"{path} accepts any version of {', '.join(names[:5])}{more}.",
            severity="medium",
            confidence="high",
            evidence={"unpinned": len(names)},
        )


def scan_dependencies(repo: Repo, emitter: Emitter) -> None:
    if not emitter.wants("security"):
        return
    for path in repo.files:
        base = os.path.basename(path)
        if re.fullmatch(r"requirements[\w.-]*\.txt", base):
            _requirements(repo, emitter, path)
        elif base == "package.json":
            _package_json(repo, emitter, path)


def analyze(repo: Repo, emitter: Emitter) -> None:
    scan_secrets(repo, emitter)
    scan_code_patterns(repo, emitter)
    scan_workflows(repo, emitter)
    scan_dockerfiles(repo, emitter)
    scan_dependencies(repo, emitter)
