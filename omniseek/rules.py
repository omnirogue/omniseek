# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""The built-in heuristic rules: id, lens, default severity and guidance.

The SARIF exporter publishes this table as `tool.driver.rules`, and the
analyzers use it so every finding of a rule carries the same title and
remediation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    lens: str
    severity: str
    title: str
    summary: str
    remediation: tuple[str, ...]


_RULES = [
    # Security ------------------------------------------------------------------
    Rule(
        "security/hardcoded-secret", "security", "high", "Hardcoded credential",
        "A value that looks like a live credential is committed to the repository.",
        (
            "Revoke and rotate the credential now; assume it has been copied.",
            "Load it from an environment variable or a secret manager instead.",
            "Purge it from git history (git filter-repo) if the repository was ever shared.",
        ),
    ),
    Rule(
        "security/committed-env-file", "security", "high", "Environment file committed",
        "A .env file is tracked. These files usually hold credentials.",
        (
            "Remove the file from version control and add it to .gitignore.",
            "Commit a .env.example with placeholder values instead.",
            "Rotate any credential the file contained.",
        ),
    ),
    Rule(
        "security/dangerous-eval", "security", "high", "Dynamic code execution",
        "eval/exec (or new Function) runs strings as code; with any outside input this is remote code execution.",
        (
            "Replace eval with a parser for the expected format (json.loads, ast.literal_eval, a lookup table).",
            "If dynamic code is truly required, never pass it data that crosses a trust boundary.",
        ),
    ),
    Rule(
        "security/shell-injection", "security", "high", "Command built for a shell",
        "A command runs through a shell (shell=True, os.system, exec with interpolation), so crafted input can run extra commands.",
        (
            "Pass an argument list without a shell: subprocess.run([\"tool\", arg], check=True).",
            "Validate arguments against an allow-list; never interpolate them into a command string.",
        ),
    ),
    Rule(
        "security/unsafe-deserialization", "security", "high", "Unsafe deserialization",
        "pickle, marshal and yaml.load without a safe loader execute code embedded in the data they read.",
        (
            "Use a data-only format (JSON) for anything that crosses a trust boundary.",
            "For YAML use yaml.safe_load or Loader=yaml.SafeLoader.",
        ),
    ),
    Rule(
        "security/sql-string-building", "security", "high", "SQL built from strings",
        "A query is assembled with string formatting, which allows SQL injection when any part comes from input.",
        (
            "Use parameterized queries: cursor.execute(\"... WHERE id = %s\", (user_id,)).",
            "For dynamic identifiers, choose from an allow-list instead of formatting input in.",
        ),
    ),
    Rule(
        "security/tls-verification-disabled", "security", "medium", "TLS certificate verification disabled",
        "Certificate checks are turned off, so a network attacker can read and change the traffic.",
        (
            "Remove verify=False / rejectUnauthorized: false.",
            "For private CAs, point the client at the CA bundle instead of disabling verification.",
        ),
    ),
    Rule(
        "security/xss-sink", "security", "medium", "Raw HTML sink",
        "Markup is written with innerHTML, dangerouslySetInnerHTML or document.write; unescaped input becomes script.",
        (
            "Set textContent, or render through the framework's escaping.",
            "If HTML is required, sanitize it with a maintained sanitizer (for example DOMPurify).",
        ),
    ),
    Rule(
        "security/permissive-cors", "security", "medium", "CORS allows any origin",
        "Any website may call this API from a visitor's browser.",
        ("List the exact origins that need access.", "Never combine a wildcard origin with credentials."),
    ),
    Rule(
        "security/debug-enabled", "security", "medium", "Debug mode enabled in code",
        "Debug mode exposes stack traces, settings and sometimes an interactive console.",
        ("Read the debug flag from the environment and default it to off.",),
    ),
    Rule(
        "security/weak-hash", "security", "low", "MD5 or SHA-1 hash",
        "MD5 and SHA-1 are broken for collision resistance and unsuitable for passwords or signatures.",
        (
            "Use hashlib.sha256 (or blake2b) for integrity, and bcrypt/scrypt/argon2 for passwords.",
            "If the hash is not security-relevant, pass usedforsecurity=False to make that explicit.",
        ),
    ),
    Rule(
        "security/world-writable", "security", "medium", "World-writable permissions",
        "chmod 777 lets every local user and process modify the path.",
        ("Grant the narrowest mode that works (for example 755 for directories, 644 for files).",),
    ),
    Rule(
        "security/curl-pipe-shell", "security", "medium", "Remote script piped to a shell",
        "A downloaded script runs without an integrity check.",
        ("Download to a file, verify a pinned checksum or signature, then run it.",),
    ),
    Rule(
        "security/insecure-workflow", "security", "high", "Injectable CI workflow",
        "Untrusted pull-request or issue text reaches a privileged workflow step.",
        (
            "Pass untrusted values through env: and quote them as shell variables, never ${{ }} inside run:.",
            "Do not check out pull-request head code in pull_request_target workflows.",
        ),
    ),
    Rule(
        "security/unpinned-action", "security", "low", "GitHub Action pinned to a branch",
        "A third-party action is referenced by a moving branch, so its code can change under you.",
        ("Pin third-party actions to a full commit SHA and let Dependabot propose updates.",),
    ),
    Rule(
        "security/container-runs-as-root", "security", "medium", "Container runs as root",
        "The image never switches to an unprivileged USER.",
        ("Create a system user in the image and add USER <name> before the entrypoint.",),
    ),
    Rule(
        "security/unpinned-base-image", "security", "low", "Unpinned base image",
        "FROM uses :latest or no tag, so rebuilds silently change the base image.",
        ("Pin an explicit version tag, ideally with an @sha256 digest.",),
    ),
    Rule(
        "security/unpinned-dependency", "security", "low", "Unpinned dependency",
        "Dependencies without an exact version (or with '*'/'latest') make builds non-reproducible and widen the supply-chain window.",
        (
            "Pin exact versions in application manifests, or commit a lockfile.",
            "Let a bot (Dependabot, Renovate) propose upgrades as reviewable changes.",
        ),
    ),
    # Performance ----------------------------------------------------------------
    Rule(
        "performance/io-in-loop", "performance", "medium", "Network or database call inside a loop",
        "Each iteration waits for a round trip (the N+1 pattern).",
        (
            "Batch the work: one query with IN (...), a bulk API, or prefetching related rows.",
            "If calls must stay separate, run them concurrently with a bounded pool.",
        ),
    ),
    Rule(
        "performance/blocking-call-in-async", "performance", "medium", "Blocking call inside async code",
        "A synchronous sleep, HTTP request or subprocess call stalls the whole event loop.",
        (
            "Use the async equivalent (asyncio.sleep, an async HTTP client, asyncio.create_subprocess_exec).",
            "Or move the blocking call to a worker thread with asyncio.to_thread.",
        ),
    ),
    Rule(
        "performance/sequential-await", "performance", "low", "Awaits run one at a time in a loop",
        "Independent awaits inside a loop run sequentially.",
        ("Collect the coroutines and await them together (asyncio.gather or a TaskGroup) with a concurrency limit.",),
    ),
    Rule(
        "performance/async-foreach", "performance", "medium", "async callback passed to forEach",
        "Array.prototype.forEach ignores returned promises: the work is neither awaited nor bounded.",
        ("Use for...of with await, or await Promise.all(items.map(async ...)).",),
    ),
    Rule(
        "performance/json-deep-clone", "performance", "low", "Deep clone through JSON",
        "JSON.parse(JSON.stringify(x)) is slow and drops dates, maps and undefined values.",
        ("Use structuredClone(x).",),
    ),
    Rule(
        "performance/select-star", "performance", "low", "SELECT * in application code",
        "Fetching every column moves more data than needed and breaks when columns change.",
        ("Select the columns the code uses.",),
    ),
    # Architecture ---------------------------------------------------------------
    Rule(
        "architecture/large-file", "architecture", "low", "Very large source file",
        "Large files collect unrelated responsibilities and are hard to review and test.",
        ("Split the file along its responsibilities into smaller modules.",),
    ),
    Rule(
        "architecture/long-function", "architecture", "low", "Long function",
        "Long functions mix several responsibilities and resist testing.",
        ("Extract the separate steps into named helper functions with their own tests.",),
    ),
    Rule(
        "architecture/high-complexity", "architecture", "medium", "High cyclomatic complexity",
        "Many independent paths make the function hard to understand and to test exhaustively.",
        (
            "Replace nested conditionals with early returns or a dispatch table.",
            "Split the function and cover each branch with a test.",
        ),
    ),
    Rule(
        "architecture/import-cycle", "architecture", "medium", "Import cycle between modules",
        "Modules that import each other cannot be understood, tested or reused in isolation.",
        (
            "Move the shared types or helpers into a lower-level module both can import.",
            "Or invert the dependency with an interface passed in at runtime.",
        ),
    ),
    Rule(
        "architecture/churn-hotspot", "architecture", "medium", "Change hotspot",
        "A large file that changes very often: the likeliest place for new defects.",
        ("Add tests around the file before the next change, then split it along its change axes.",),
    ),
    Rule(
        "architecture/swallowed-exception", "architecture", "medium", "Exception silently swallowed",
        "An except block discards the error, hiding failures.",
        ("Catch the specific exception you expect, and log or re-raise everything else.",),
    ),
    Rule(
        "architecture/wildcard-import", "architecture", "low", "Wildcard import",
        "from x import * hides where names come from and couples modules implicitly.",
        ("Import the names you use explicitly.",),
    ),
    Rule(
        "architecture/deep-relative-import", "architecture", "low", "Deep relative import",
        "Imports climbing four or more directories signal blurred module boundaries.",
        ("Expose the module through a package entry point or a path alias.",),
    ),
    Rule(
        "architecture/todo-debt", "architecture", "info", "Concentrated TODO/FIXME debt",
        "Many TODO, FIXME or HACK markers in one file.",
        ("Turn the markers into tracked issues, then fix or delete them.",),
    ),
    # Product --------------------------------------------------------------------
    Rule(
        "product/missing-readme", "product", "high", "No README",
        "Nothing tells a newcomer what the project does or how to run it.",
        ("Add a README.md with a one-paragraph summary, install steps and a usage example.",),
    ),
    Rule(
        "product/readme-missing-quickstart", "product", "medium", "README has no install or usage section",
        "The README has no heading for installing, running or using the project.",
        ("Add an Install / Quickstart section with copy-pasteable commands.",),
    ),
    Rule(
        "product/broken-doc-link", "product", "medium", "Broken link in documentation",
        "A relative link points at a file that does not exist.",
        ("Fix the path or remove the link.",),
    ),
    Rule(
        "product/missing-license", "product", "high", "No license file",
        "Without a license nobody can legally reuse the code.",
        ("Add a LICENSE file with the full text of the license you chose.",),
    ),
    Rule(
        "product/missing-security-policy", "product", "low", "No security policy",
        "Researchers have no documented way to report a vulnerability privately.",
        ("Add SECURITY.md describing how to report issues (for example GitHub private vulnerability reporting).",),
    ),
    Rule(
        "product/missing-contributing", "product", "info", "No contributing guide",
        "Contributors do not know how to build, test or submit changes.",
        ("Add CONTRIBUTING.md with setup, test and pull-request steps.",),
    ),
    Rule(
        "product/no-tests", "product", "medium", "No automated tests",
        "The repository has source code but no test files.",
        ("Add a test suite for the main behaviors and run it in CI.",),
    ),
    Rule(
        "product/no-ci", "product", "low", "No continuous integration",
        "Nothing runs checks automatically on each change.",
        ("Add a CI workflow (for example .github/workflows/ci.yml) that runs the tests and linters.",),
    ),
    Rule(
        "product/incomplete-package-metadata", "product", "low", "Incomplete package metadata",
        "The package manifest lacks a description or license, which registries and users rely on.",
        ("Fill in description and license (and repository/homepage) in the manifest.",),
    ),
    Rule(
        "product/placeholder-content", "product", "low", "Placeholder content in user-facing files",
        "Lorem ipsum text is shipped in a user-facing file.",
        ("Replace the placeholder with real copy.",),
    ),
    # Model-generated findings -----------------------------------------------------
    Rule(
        "llm/architecture", "architecture", "medium", "Model finding (architecture)",
        "A finding proposed by the configured language model and checked by the citation verifier.",
        ("Review the cited lines and the suggested remediation.",),
    ),
    Rule(
        "llm/security", "security", "medium", "Model finding (security)",
        "A finding proposed by the configured language model and checked by the citation verifier.",
        ("Review the cited lines and the suggested remediation.",),
    ),
    Rule(
        "llm/performance", "performance", "medium", "Model finding (performance)",
        "A finding proposed by the configured language model and checked by the citation verifier.",
        ("Review the cited lines and the suggested remediation.",),
    ),
    Rule(
        "llm/product", "product", "medium", "Model finding (product)",
        "A finding proposed by the configured language model and checked by the citation verifier.",
        ("Review the cited lines and the suggested remediation.",),
    ),
]

RULES: dict[str, Rule] = {rule.id: rule for rule in _RULES}


def rule(rule_id: str) -> Rule:
    return RULES[rule_id]
