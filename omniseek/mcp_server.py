# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""OmniSeek as an MCP server.

The default transport is stdio: newline-delimited JSON-RPC 2.0 on stdin and
stdout, implemented with the standard library. `--transport streamable-http`
serves the same tools over HTTP with the official `mcp` SDK
(`pip install "omnirogue-omniseek[mcp]"`).

Tools:

    omniseek_scan              deterministic scan of a directory (read-only, offline)
    omniseek_verify_citations  check a findings document's citations against a repository
    omniseek_render_dossier    render findings as HTML, Markdown or SARIF (optionally to a file)

Every path a tool touches must be inside one of the `--root` directories
(default: the current directory). Scans through MCP never call a model or the
network: the calling assistant is already the model.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Callable

from ._version import __version__
from .model import LENSES, SEVERITIES, SEVERITY_RANK, FindingsError, load_document, summarize
from .render import FORMATS, render
from .scan import ScanError, parse_lenses, run_scan
from .verify import verify_document

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_INLINE_CHARS = 400_000

FINDINGS_INPUT = {
    "findings": {
        "description": "A findings document (as returned by omniseek_scan) or a list of findings.",
        "type": ["object", "array"],
    },
    "findings_path": {"description": "Path to a findings JSON file, instead of `findings`.", "type": "string"},
}

TOOLS = [
    {
        "name": "omniseek_scan",
        "title": "Scan a repository",
        "description": (
            "Deterministic multi-lens scan (architecture, security, performance, product) of a local directory. "
            "Every finding cites file:line evidence and comes back verified against the files. Offline and read-only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory to scan (default: the first root)."},
                "lenses": {"type": "array", "items": {"type": "string", "enum": list(LENSES)}},
                "min_severity": {"type": "string", "enum": list(SEVERITIES), "default": "info"},
                "max_findings": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False, "idempotentHint": True},
    },
    {
        "name": "omniseek_verify_citations",
        "title": "Verify citations",
        "description": (
            "Check that every cited file:start-end span, quoted snippet and symbol in a findings document exists in "
            "the repository (working tree or a git ref). Returns a 0.0-1.0 grounding score and flags drifted, "
            "hallucinated and invalid citations. Use it on findings you or another model wrote."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **FINDINGS_INPUT,
                "repo": {"type": "string", "description": "Repository directory (default: the first root)."},
                "ref": {"type": "string", "description": "Optional git revision to verify against."},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False, "idempotentHint": True},
    },
    {
        "name": "omniseek_render_dossier",
        "title": "Render a dossier",
        "description": (
            "Render findings as a self-contained dark-mode HTML dossier, GitHub SARIF 2.1.0 or Markdown. "
            "With output_path the result is written to that file (inside a root) and only its path is returned."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **FINDINGS_INPUT,
                "format": {"type": "string", "enum": list(FORMATS), "default": "html"},
                "output_path": {"type": "string", "description": "File to write; must not exist unless overwrite."},
                "overwrite": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
]


class ToolError(Exception):
    """A tool failed in a way the caller should see (reported with isError)."""


class Tools:
    def __init__(self, roots: list[str]):
        self.roots = [os.path.realpath(r) for r in roots] or [os.path.realpath(os.getcwd())]

    def confine(self, path: str | None, *, must_exist: bool = True) -> str:
        if path is None or path == "":
            return self.roots[0]
        if not isinstance(path, str):
            raise ToolError("paths must be strings")
        candidate = path if os.path.isabs(path) else os.path.join(self.roots[0], path)
        real = os.path.realpath(candidate)
        if not any(real == root or real.startswith(root + os.sep) for root in self.roots):
            raise ToolError(f"{path} is outside the allowed roots: {', '.join(self.roots)}")
        if must_exist and not os.path.exists(real):
            raise ToolError(f"{path} does not exist")
        return real

    def _document(self, args: dict) -> dict:
        try:
            if args.get("findings") is not None:
                return load_document(args["findings"])
            if args.get("findings_path"):
                return load_document(self.confine(args["findings_path"]))
        except FindingsError as exc:
            raise ToolError(str(exc)) from exc
        raise ToolError("pass `findings` or `findings_path`")

    def scan(self, args: dict) -> dict:
        root = self.confine(args.get("path"))
        if not os.path.isdir(root):
            raise ToolError(f"{args.get('path')} is not a directory")
        try:
            document = run_scan(root, lenses=parse_lenses(args.get("lenses")))
        except ScanError as exc:
            raise ToolError(str(exc)) from exc
        floor = SEVERITY_RANK.get(args.get("min_severity") or "info", len(SEVERITIES) - 1)
        limit = int(args.get("max_findings") or 50)
        kept = [f for f in document["findings"] if SEVERITY_RANK[f["severity"]] <= floor]
        document["truncated"] = max(0, len(kept) - limit)
        document["findings"] = kept[:limit]
        document["summary"] = summarize(document["findings"])
        return document

    def verify(self, args: dict) -> dict:
        document = self._document(args)
        repo = self.confine(args.get("repo"))
        try:
            annotated, report = verify_document(document, repo, args.get("ref") or None)
        except FileNotFoundError as exc:
            raise ToolError(str(exc)) from exc
        report["findings"] = [
            {"id": f.get("id"), "title": f.get("title"), **{k: f["verification"][k] for k in ("grounding_score", "status")}}
            for f in annotated["findings"]
        ]
        return report

    def render(self, args: dict) -> dict:
        document = self._document(args)
        fmt = args.get("format") or "html"
        if fmt not in FORMATS:
            raise ToolError(f"format must be one of {', '.join(FORMATS)}")
        content = render(document, fmt)
        output = args.get("output_path")
        if not output:
            if len(content) > MAX_INLINE_CHARS:
                raise ToolError("the rendered output is too large to return inline; pass output_path")
            return {"format": fmt, "content": content}
        target = self.confine(output, must_exist=False)
        if os.path.isdir(target):
            raise ToolError(f"{output} is a directory")
        if os.path.exists(target) and not args.get("overwrite"):
            raise ToolError(f"{output} exists; pass overwrite: true to replace it")
        if not os.path.isdir(os.path.dirname(target)):
            raise ToolError(f"the directory for {output} does not exist")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(content)
        return {"format": fmt, "output_path": target, "bytes": len(content.encode("utf-8"))}

    def dispatch(self) -> dict[str, Callable[[dict], dict]]:
        return {
            "omniseek_scan": self.scan,
            "omniseek_verify_citations": self.verify,
            "omniseek_render_dossier": self.render,
        }


class StdioServer:
    def __init__(self, tools: Tools):
        self.tools = tools

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    def _tool_result(self, name: str, args: dict) -> dict:
        handler = self.tools.dispatch()[name]
        try:
            result = handler(args)
        except ToolError as exc:
            return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        except Exception as exc:  # noqa: BLE001 - surface unexpected failures to the caller, keep serving
            return {"content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}], "isError": True}
        text = result["content"] if name == "omniseek_render_dossier" and "content" in result else json.dumps(result)
        return {"content": [{"type": "text", "text": text}], "structuredContent": result, "isError": False}

    def handle(self, message: Any) -> dict | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return self._error(message.get("id") if isinstance(message, dict) else None, -32600, "Invalid Request")
        method, request_id = message["method"], message.get("id")
        params = message.get("params") or {}
        if "id" not in message:  # a notification: never answered
            return None
        if method == "initialize":
            requested = params.get("protocolVersion") if isinstance(params, dict) else None
            version = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "omniseek", "title": "OmniSeek", "version": __version__},
                    "instructions": (
                        "Use omniseek_scan for a cited, multi-lens review of a repository, "
                        "omniseek_verify_citations to check any file:line claims before relying on them, "
                        "and omniseek_render_dossier to produce HTML, SARIF or Markdown."
                    ),
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
        if method == "tools/call":
            if not isinstance(params, dict) or params.get("name") not in self.tools.dispatch():
                return self._error(request_id, -32602, f"Unknown tool: {params.get('name') if isinstance(params, dict) else params}")
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                return self._error(request_id, -32602, "arguments must be an object")
            return {"jsonrpc": "2.0", "id": request_id, "result": self._tool_result(params["name"], args)}
        return self._error(request_id, -32601, f"Method not found: {method}")

    def serve(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                reply: Any = self._error(None, -32700, "Parse error")
            else:
                if isinstance(message, list):
                    replies = [r for r in (self.handle(m) for m in message) if r is not None]
                    reply = replies or None
                else:
                    reply = self.handle(message)
            if reply is not None:
                stdout.write(json.dumps(reply) + "\n")
                stdout.flush()


def serve_http(tools: Tools, host: str, port: int) -> None:  # pragma: no cover - needs the optional SDK
    try:
        from mcp.server.mcpserver import MCPServer  # mcp 2.x

        server = MCPServer("omniseek", version=__version__)

        def run() -> None:
            server.run(transport="streamable-http", host=host, port=port)
    except ImportError:
        try:
            from mcp.server.fastmcp import FastMCP  # mcp 1.x
        except ImportError:
            raise SystemExit('streamable-http needs the MCP SDK: pip install "omnirogue-omniseek[mcp]"') from None
        server = FastMCP("omniseek", host=host, port=port)

        def run() -> None:
            server.run(transport="streamable-http")
    descriptions = {tool["name"]: tool["description"] for tool in TOOLS}

    def call(name: str, args: dict) -> dict:
        try:
            return tools.dispatch()[name]({k: v for k, v in args.items() if v is not None})
        except ToolError as exc:
            raise ValueError(str(exc)) from exc

    @server.tool(name="omniseek_scan", description=descriptions["omniseek_scan"])
    def omniseek_scan(path: str | None = None, lenses: list[str] | None = None, min_severity: str = "info",
                      max_findings: int = 50) -> dict:
        return call("omniseek_scan", {"path": path, "lenses": lenses, "min_severity": min_severity,
                                      "max_findings": max_findings})

    @server.tool(name="omniseek_verify_citations", description=descriptions["omniseek_verify_citations"])
    def omniseek_verify_citations(findings: dict | list | None = None, findings_path: str | None = None,
                                  repo: str | None = None, ref: str | None = None) -> dict:
        return call("omniseek_verify_citations", {"findings": findings, "findings_path": findings_path,
                                                  "repo": repo, "ref": ref})

    @server.tool(name="omniseek_render_dossier", description=descriptions["omniseek_render_dossier"])
    def omniseek_render_dossier(findings: dict | list | None = None, findings_path: str | None = None,
                                format: str = "html", output_path: str | None = None, overwrite: bool = False) -> dict:
        return call("omniseek_render_dossier", {"findings": findings, "findings_path": findings_path, "format": format,
                                                "output_path": output_path, "overwrite": overwrite})

    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: serving without authentication on {host}:{port}", file=sys.stderr)
    run()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="omniseek-mcp", description="OmniSeek MCP server.")
    parser.add_argument("--root", action="append", default=[], help="Directory tools may read (repeatable; default: cwd).")
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1", help="streamable-http bind address (default 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8765, help="streamable-http port (default 8765).")
    parser.add_argument("--version", action="version", version=f"omniseek-mcp {__version__}")
    args = parser.parse_args(argv)
    for root in args.root:
        if not os.path.isdir(root):
            parser.error(f"--root {root} is not a directory")
    tools = Tools(args.root)
    if args.transport == "streamable-http":
        serve_http(tools, args.host, args.port)
        return 0
    try:
        StdioServer(tools).serve()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
