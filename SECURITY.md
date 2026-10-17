# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open
[a private security advisory](https://github.com/omnirogue/omniseek/security/advisories/new)
on this repository. Do not open a public issue for a vulnerability.

Include the OmniSeek version (`omniseek --version`), the command or MCP tool call, and a
minimal repository or findings file that reproduces the problem. We aim to acknowledge
reports within three working days and to ship a fix or mitigation for confirmed issues
as quickly as their severity requires. We will credit you in the release notes unless
you ask us not to.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## What counts as a vulnerability

OmniSeek reads untrusted repositories and untrusted findings files, so these are in scope:

- Reading or writing outside the repository or the MCP `--root` directories (path traversal, symlink escapes).
- Code execution from a scanned repository, a findings file or a model reply.
- Script injection in the HTML dossier, or content that bypasses its Content-Security-Policy.
- A secret value from a scanned file appearing in findings, reports, model requests or cloud-sync payloads.
- Network requests that `scan`, `verify` or `report` make without `--model`, a git URL or `cloud-sync`, or any request to an endpoint other than the one configured.

Out of scope: findings that are wrong or missing (please open a normal issue), and the
behaviour of third-party model providers.

## Design notes

- Python rules parse code with `ast`; nothing from a scanned repository is imported or executed.
- Model and cloud credentials are read only from environment variables and never logged.
- HTTPS is required for every outbound request, except plain HTTP to `localhost`.
- The streamable-HTTP MCP transport has no authentication and binds to `127.0.0.1` by default.
