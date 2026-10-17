# Contributing to OmniSeek

Thanks for helping. OmniSeek is licensed under Apache-2.0, and contributions are accepted
under the same license (inbound = outbound).

## Setup

No dependencies are needed for the core or the tests:

```bash
git clone https://github.com/omnirogue/omniseek && cd omniseek
python -m unittest discover -s tests
python -m omniseek scan . --output /tmp/self.json && python -m omniseek verify /tmp/self.json --repo .
```

For the optional extras: `pip install -e ".[all]"`.

## Ground rules

- **Standard library only** in `omniseek/`. Optional integrations go behind an extra (`httpx`, `mcp`) and must degrade gracefully when it is missing.
- **Python 3.10+.** CI runs 3.10 to 3.13 on Linux and macOS.
- **Every source file starts with** `# SPDX-License-Identifier: Apache-2.0` (or `//` for JavaScript).
- **No secrets in fixtures.** Build credential-shaped test values at runtime (see `tests/helpers.py`), so no real-looking key is ever committed.
- **Findings must be verifiable.** Every citation a rule emits has to pass `omniseek verify` on the same tree; the tests check this for the demo app.

## Adding a heuristic rule

1. Add the rule's id, lens, default severity, title, summary and remediation to `omniseek/rules.py`.
2. Implement it in the matching analyzer: `analyzers/python_ast.py` (Python syntax tree), `analyzers/patterns.py` (line patterns for other languages, CI and containers), `analyzers/structure.py` (cross-file architecture) or `analyzers/product.py`.
3. Emit through `Emitter.add`, quoting the exact cited line with `line_span`. Never put a secret value in a snippet or description.
4. Add a test with one positive case and at least one look-alike that must not match.
5. Run the suite, and scan this repository to check the rule does not flood it with false positives.

## Pull requests

Keep changes focused, explain the user-visible effect, and say how you verified it. New
behaviour needs tests. Bug fixes should include a test that fails without the fix.
