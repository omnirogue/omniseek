# Changelog

## 0.1.0 (2026-10-16)

First public release, published on PyPI as `omnirogue-omniseek` (the command and the Python package are `omniseek`).

- `omniseek scan`: deterministic multi-lens analyzer (architecture, security, performance, product) with 40+ rules; Python rules run on the syntax tree. Optional bring-your-own-model pass for OpenAI, Anthropic and Gemini with secret redaction. Local directories or shallow-cloned git URLs.
- `omniseek verify`: citation and grounding verifier for any findings file, against the working tree or a git revision.
- `omniseek report`: self-contained HTML dossier, SARIF 2.1.0 and Markdown.
- `omniseek cloud-sync`: optional upload of a findings file to OmniSI Cloud.
- `omniseek-mcp`: MCP server over stdio (standard library) or streamable HTTP (`omnirogue-omniseek[mcp]`).
