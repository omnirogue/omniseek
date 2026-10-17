# OmniSeek

**Citation-grounded codebase intelligence.** OmniSeek reviews a repository through four lenses (architecture, security, performance, product) and backs every finding with `file:line` evidence. Then it checks that evidence against your files, so a hallucinated line number or invented function cannot slip into the report.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

- **Runs anywhere, immediately.** Pure Python standard library: no compiler, no native wheels, no mandatory dependencies.
- **Deterministic by default.** More than 40 built-in rules, with Python rules evaluated on the syntax tree, so code inside strings and comments never matches. The same tree gives the same findings.
- **Bring your own model.** Add `--model anthropic/…`, `openai/…` or `gemini/…` and your own key for deeper, cross-file findings. Model findings are verified like everything else, and the ones whose citations do not exist are dropped.
- **Verifies anyone's claims.** `omniseek verify` checks any findings file (yours, another tool's, an AI assistant's) against the working tree or a git revision and scores it from 0.0 to 1.0.
- **Ships where you work.** A self-contained HTML dossier, SARIF 2.1.0 for GitHub code scanning, Markdown for pull requests, and an MCP server for Claude, Cursor and other assistants.

## 60-second quickstart

```bash
pipx install omnirogue-omniseek                # or: pip install omnirogue-omniseek

omniseek scan . --output findings.json --html dossier.html
omniseek verify findings.json --repo .
open dossier.html                                           # xdg-open on Linux
```

No install at all? From a checkout, `python3 -m omniseek scan .` works with any Python 3.10+.

> **Package name.** On PyPI this tool is `omnirogue-omniseek`; the command and the Python package are `omniseek`. The PyPI project called `omniseek` is unrelated. To install straight from this repository instead: `pipx install "git+https://github.com/omnirogue/omniseek"`.

Try it on the deliberately flawed demo app, including a findings file with planted hallucinations:

```bash
bash examples/run_demo.sh            # writes the dossier, SARIF and Markdown to a temp directory
```

## How it works

```
                      ┌──────────────────────── omniseek scan ─────────────────────────┐
  local dir           │  repo walker ──▶ heuristic lenses ──┐                          │
  or git URL ────────▶│  (git ls-files,  architecture       │                          │
                      │   .gitignore,    security           ├──▶ findings ──▶ verifier ├──▶ findings.json
                      │   no symlinks)   performance        │    + citations   (0.0-1.0)│      (omniseek.findings/v1)
                      │                  product            │                          │
                      │  optional: --model provider/model ──┘  redacted, line-numbered │
                      │            (your key; ungrounded findings dropped)             │
                      └────────────────────────────────────────────────────────────────┘
                                                   │
          ┌────────────────────┬───────────────────┼────────────────────┬─────────────────────┐
          ▼                    ▼                   ▼                    ▼                     ▼
  omniseek report       omniseek report     omniseek report     omniseek verify       omniseek cloud-sync
  --format html         --format sarif      --format md         any findings file     (optional, OmniSI Cloud)
  dark-mode dossier     GitHub code         PR comments         vs. working tree
                        scanning                                or a git revision

  omniseek-mcp: the same scan, verify and render as MCP tools (stdio, or streamable HTTP)
```

## Commands

| Command | What it does |
| --- | --- |
| `omniseek scan <path_or_git_url> [--lenses architecture,security,performance,product] [--model provider/model] [--output findings.json] [--html report.html] [--sarif out.sarif] [--md out.md] [--fail-on high]` | Scans a local directory, or shallow-clones an `https://`, `ssh://` or `git@` URL first. Findings go to `--output` (or stdout); the summary goes to stderr |
| `omniseek verify <findings.json> --repo <path> [--ref HEAD] [--min-score 1.0] [--output verified.json] [--json]` | Checks every citation; prints the grounding score and each flagged citation |
| `omniseek report <findings.json> --format html\|md\|sarif --output <file> [--verify-repo <path>]` | Renders a findings file; `--verify-repo` verifies first so the badges are current |
| `omniseek cloud-sync <findings.json> [--api-url https://api.omnirogue.com] [--no-snippets] [--dry-run]` | Optional: sends a findings file to OmniSI Cloud (needs `OMNISI_API_KEY`) |
| `omniseek rules [--lens security] [--json]` | Lists the built-in rules |

Exit codes: `0` success, `1` a gate failed (`--fail-on` severity or `--min-score`), `2` bad input or usage.

### Lenses

| Lens | Examples of what the built-in rules find |
| --- | --- |
| **security** | Hardcoded credentials (never copied into output), committed `.env` files, SQL built from strings (including through a variable), shell commands with `shell=True`/`os.system`, `eval`/`new Function`, pickle and unsafe YAML, disabled TLS verification, `innerHTML`/`dangerouslySetInnerHTML`, wildcard CORS, debug mode, injectable GitHub Actions, actions pinned to branches, root containers, `:latest` base images, unpinned dependencies |
| **performance** | HTTP or database calls inside loops (N+1), blocking calls in `async` code, sequential `await` in loops, `forEach(async …)`, JSON deep clones, `SELECT *` |
| **architecture** | Import cycles (Python and JS/TS), very large files, long and highly complex functions, change hotspots from git history, swallowed exceptions, wildcard imports, deep relative imports, TODO/FIXME debt |
| **product** | Missing README, license, security policy or contributing guide; README without install/usage; broken relative links in Markdown; no tests; no CI; incomplete package metadata; placeholder (lorem-ipsum) copy in user-facing files |

Test and example code is not held to the architecture and performance rules, and security findings there are marked low confidence. Add an `.omniseekignore` file (one glob per line) to skip more paths.

## The citation verifier

A finding is only as good as its evidence. Every finding carries citations:

```json
{
  "rule_id": "security/sql-string-building",
  "lens": "security",
  "severity": "high",
  "title": "SQL built from strings",
  "citations": [
    {"kind": "span", "path": "app.py", "start_line": 17, "end_line": 17,
     "snippet": "return conn.execute(f\"SELECT id, email FROM users WHERE name = '{name}'\").fetchone()",
     "symbol": "find_user"},
    {"kind": "absence", "globs": ["license", "license.*"]}
  ]
}
```

`omniseek verify` checks that the path stays inside the repository (no `..`, no absolute paths, no symlinks out), the file exists and is text, the line range is inside the file, the quoted snippet appears in exactly those lines (whitespace-insensitive), and the symbol appears there as a whole identifier. An `absence` citation is verified only if none of its paths or globs exist.

| Status | Score | Meaning |
| --- | --- | --- |
| `verified` | 1.0 | Path, range, quote and symbol all check out |
| `drifted` | 0.5 | The quote or symbol exists in the file, but at other lines (the actual lines are reported) |
| `unanchored` | 0.5 | The range exists but nothing was quoted, so the content could not be checked |
| `hallucinated` | 0.0 | The file, quote or symbol does not exist, or a claimed absence is present |
| `invalid` | 0.0 | Malformed, or points outside the repository |

A finding's `grounding_score` is the mean of its citation scores (0.0 when it cites nothing), and the document's score is the mean over findings. Verification proves provenance, not correctness: a verified citation shows the evidence exists where the finding says it does.

Shorthand citations such as `"app.py:15-17"` and `{"file": …, "lines": "15-17"}` are accepted, so you can verify output from other tools and assistants. Use `--ref <sha>` to verify against a commit instead of the working tree.

## Bring your own model

```bash
export ANTHROPIC_API_KEY=...                       # or OPENAI_API_KEY / GEMINI_API_KEY
omniseek scan . --model anthropic/claude-sonnet-5-5 --html dossier.html
omniseek scan . --model openai/<model-id>
omniseek scan . --model gemini/<model-id>
```

| Provider | Key | Endpoint override |
| --- | --- | --- |
| `openai/<model>` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` (any OpenAI-compatible server, including local ones on `http://localhost`) |
| `anthropic/<model>` | `ANTHROPIC_API_KEY` | `ANTHROPIC_BASE_URL` |
| `gemini/<model>` | `GEMINI_API_KEY` or `GOOGLE_API_KEY` | `GEMINI_BASE_URL` |

What is sent: a file list, the heuristic leads, and line-numbered excerpts (lead areas, entry points, configuration, then the largest source files) within `--max-context-chars` (default 120,000). `.env` files, key files and lockfiles are never sent, and values that look like credentials are replaced with `«redacted»` first. Keys are read from the environment only. Requests go over HTTPS (plain HTTP only to `localhost`). Install `omnirogue-omniseek[httpx]` to use httpx instead of urllib.

The model's findings are validated against the schema, then verified; findings with no valid citation are dropped unless you pass `--keep-ungrounded`.

## MCP server

`omniseek-mcp` exposes three tools: `omniseek_scan` (read-only, offline), `omniseek_verify_citations` (read-only) and `omniseek_render_dossier` (writes a file only when given `output_path`, and never overwrites without `overwrite: true`). Every path must be inside a `--root` directory (default: the working directory). Scans through MCP never call a model; your assistant already is one.

Claude Code:

```bash
claude mcp add omniseek -- omniseek-mcp --root /path/to/project
```

Claude Desktop, Cursor, OmniConsole and other clients that read an `mcpServers` file:

```json
{
  "mcpServers": {
    "omniseek": {
      "command": "omniseek-mcp",
      "args": ["--root", "/path/to/project"]
    }
  }
}
```

Without installing, use `"command": "python3", "args": ["-m", "omniseek.mcp_server", "--root", "/path/to/project"]` with `"env": {"PYTHONPATH": "/path/to/omniseek"}`.

Streamable HTTP (needs `pip install "omnirogue-omniseek[mcp]"`, works with MCP SDK 1.x and 2.x):

```bash
omniseek-mcp --transport streamable-http --root /path/to/project --port 8765   # http://127.0.0.1:8765/mcp
```

It binds to `127.0.0.1` and has no authentication of its own; put it behind your own authenticating proxy if you expose it.

## GitHub code scanning (SARIF)

Copy [`examples/github-action-sarif.yml`](examples/github-action-sarif.yml) to `.github/workflows/omniseek.yml`:

```yaml
name: omniseek
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install "omnirogue-omniseek==0.1.0"
      - run: omniseek scan . --output omniseek-findings.json --sarif omniseek.sarif --html omniseek-dossier.html --md omniseek.md
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: omniseek.sarif
          category: omniseek
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: omniseek-dossier
          path: omniseek-dossier.html
```

Results appear under **Security → Code scanning**. Security rules carry a `security-severity`, so GitHub ranks them as critical, high, medium or low. Add `--fail-on high` to the scan step to block merges on serious findings.

## OmniSeek open source vs. OmniSI Cloud

OmniSeek is the open-source core of OmniSI. OmniSI Cloud is a separate, proprietary service built on the OmniRogue Rust Engine. `cloud-sync` is the only bridge between them: it is optional, sends only a findings file you already have (never your repository), and nothing leaves your machine without `OMNISI_API_KEY`.

| | **OmniSeek** (this repository, Apache-2.0) | **OmniSI Cloud** (proprietary, OmniRogue Rust Engine) |
| --- | --- | --- |
| Where it runs | Your machine or CI, offline by default | Hosted service |
| Analysis | 40+ deterministic rules across 4 lenses, plus your own model | Parallel Rust ingestion of large monorepos and evidence packs; multi-stage model pipeline |
| Verification | Deterministic citation and grounding verifier | Cross-family adversarial verification: findings challenged by models from different labs |
| Memory | Stateless; one findings file per run | Organization memory: deduplicates findings across repositories and runs |
| Action | HTML, SARIF, Markdown, MCP | Turns a confirmed finding into a Decision your team approves, then executes the action exactly once |
| Models and keys | Bring your own (OpenAI, Anthropic, Gemini, OpenAI-compatible) | Managed |
| Price | Free | Commercial |
| Bridge | `omniseek cloud-sync findings.json` | Receives findings from OmniSeek |

```bash
export OMNISI_API_KEY=...
omniseek cloud-sync findings.json --dry-run     # see exactly what would be sent
omniseek cloud-sync findings.json --no-snippets # send without quoted code
```

`cloud-sync` posts `omniseek.cloud-sync/v1` JSON to `{api_url}/v1/omniseek/scans` with an idempotency key. The local repository path is never sent.

## Privacy and security

- `scan`, `verify` and `report` make no network calls. Only `--model`, `cloud-sync` and scanning a git URL do, and only to the endpoint you chose.
- Secret values are never copied into findings or reports: citations quote the text before the value plus its first four characters, and code excerpts are redacted.
- The HTML dossier is one file with no external requests. All content is escaped and the inline script is pinned by a Content-Security-Policy hash.
- The scanner never follows symlinks out of the repository, and the verifier rejects citations that escape it.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Findings schema

`omniseek.findings/v1`: `schema`, `tool`, `generated_at`, `repo` (`name`, `commit`, `files_scanned`, `languages`), `analyzer` (`mode`, `model`, `lenses`), `summary`, `findings[]` and, after verification, `verification` plus a `verification` block on each finding. Each finding has `id` (stable across line moves), `rule_id`, `lens`, `severity` (`critical`, `high`, `medium`, `low`, `info`), `confidence`, `title`, `description`, `remediation[]`, `citations[]` and `source` (`heuristic` or `llm:<provider>/<model>`). See [`examples/sample_findings.json`](examples/sample_findings.json).

## Development

```bash
python -m unittest discover -s tests        # no dependencies needed
python -m omniseek scan . --output /tmp/self.json && python -m omniseek verify /tmp/self.json --repo .
```

Tested on Linux and macOS with Python 3.10 to 3.13. See [CONTRIBUTING.md](CONTRIBUTING.md) to add a rule.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
