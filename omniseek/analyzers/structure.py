# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Architecture rules across files: size, change hotspots, import cycles and TODO debt."""

from __future__ import annotations

import ast
import posixpath
import re

from ..repo import Repo, language_of
from .base import CODE_LANGUAGES, Emitter, line_span

GENERATED = re.compile(r"(\.min\.js|_pb2\.py|_pb2_grpc\.py|\.pb\.go|\.generated\.\w+|\.g\.dart|\.d\.ts)$")
TODO = re.compile(r"(?:#|//|/\*|\*|<!--|--)\s*.*?\b(TODO|FIXME|HACK|XXX)\b")
JS_IMPORT = re.compile(
    r"""(?m)^[ \t]*(?:import|export)\s+(type\s+)?(?:[^;'"`]*?\s+from\s+)?["'](\.{1,2}/[^"']+)["']"""
)
JS_REQUIRE = re.compile(r"""\brequire\(\s*["'](\.{1,2}/[^"']+)["']\s*\)""")
JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte")
JS_SOURCE = frozenset({"javascript", "typescript", "vue", "svelte"})
MAX_CYCLE_CITATIONS = 8


def _last_text_line(lines: list[str]) -> int:
    for index in range(len(lines) - 1, -1, -1):
        if lines[index].strip():
            return index + 1
    return 0


def _source_files(repo: Repo) -> list[str]:
    return [p for p in repo.files if language_of(p) in CODE_LANGUAGES and not GENERATED.search(p)]


def large_files(repo: Repo, emitter: Emitter) -> None:
    if not emitter.wants("architecture"):
        return
    for path in _source_files(repo):
        lines = repo.lines(path)
        if not lines:
            continue
        count = len(lines)
        if count <= 800:
            continue
        last = _last_text_line(lines)
        emitter.add(
            "architecture/large-file",
            [line_span(path, lines, last)],
            f"{path} has {count:,} lines; the citation quotes line {last} to prove the length.",
            severity="medium" if count > 2000 else "low",
            evidence={"lines": count},
        )


def churn_hotspots(repo: Repo, emitter: Emitter, limit: int = 5) -> None:
    if not emitter.wants("architecture") or not repo.is_git:
        return
    churn = repo.churn()
    scored = []
    for path, commits in churn.items():
        if commits < 15 or language_of(path) not in CODE_LANGUAGES:
            continue
        lines = repo.lines(path)
        if lines and len(lines) >= 300:
            scored.append((commits * len(lines), path, commits, lines))
    for _, path, commits, lines in sorted(scored, reverse=True)[:limit]:
        last = _last_text_line(lines)
        emitter.add(
            "architecture/churn-hotspot",
            [line_span(path, lines, last)],
            f"{path} ({len(lines):,} lines) changed in {commits} commits over the last year.",
            evidence={"commits": commits, "lines": len(lines)},
        )


def todo_debt(repo: Repo, emitter: Emitter, limit: int = 5) -> None:
    if not emitter.wants("architecture"):
        return
    ranked = []
    for path in _source_files(repo):
        lines = repo.lines(path) or []
        hits = [n for n, line in enumerate(lines, 1) if len(line) < 500 and TODO.search(line)]
        if len(hits) >= 8:
            ranked.append((len(hits), path, hits, lines))
    for count, path, hits, lines in sorted(ranked, key=lambda r: (-r[0], r[1]))[:limit]:
        emitter.add(
            "architecture/todo-debt",
            [line_span(path, lines, n) for n in hits[:3]],
            f"{path} carries {count} TODO/FIXME/HACK markers.",
            evidence={"markers": count},
        )


# Import cycles -------------------------------------------------------------------------------------
def _python_modules(paths: list[str], file_set: set[str]) -> tuple[dict[str, str], dict[str, bool]]:
    """Map dotted module names to files; ambiguous names (two files, one name) are dropped."""
    modules: dict[str, str] = {}
    ambiguous: set[str] = set()
    is_package: dict[str, bool] = {}
    for path in paths:
        parts = path[:-3].split("/") if path.endswith(".py") else None
        if not parts:
            continue
        dirs = parts[:-1]
        top = len(dirs)
        while top > 0 and "/".join(dirs[:top]) + "/__init__.py" in file_set:
            top -= 1
        package_parts = dirs[top:]
        package = parts[-1] == "__init__"
        name = ".".join(package_parts if package else package_parts + [parts[-1]])
        if not name:
            continue
        if name in modules:
            ambiguous.add(name)
        modules[name] = path
        is_package[name] = package
    for name in ambiguous:
        modules.pop(name, None)
    return modules, is_package


def _is_type_checking(test: ast.AST) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _top_level_imports(tree: ast.AST) -> list[ast.AST]:
    found: list[ast.AST] = []
    try_nodes = tuple(t for t in (ast.Try, getattr(ast, "TryStar", None)) if t is not None)

    def walk(statements: list[ast.stmt]) -> None:
        for statement in statements:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                found.append(statement)
            elif isinstance(statement, ast.If):
                if not _is_type_checking(statement.test):
                    walk(statement.body)
                walk(statement.orelse)
            elif isinstance(statement, try_nodes):
                walk(statement.body)
                for handler in statement.handlers:
                    walk(handler.body)
                walk(statement.orelse)
                walk(statement.finalbody)
            elif isinstance(statement, ast.With):
                walk(statement.body)

    walk(getattr(tree, "body", []))
    return found


def python_import_graph(trees: dict[str, ast.AST], files: list[str]) -> dict[str, dict[str, int]]:
    """file -> {imported file -> line of the import}, for module-level imports inside the repo."""
    modules, is_package = _python_modules(list(trees), set(files))
    by_path = {path: name for name, path in modules.items()}
    graph: dict[str, dict[str, int]] = {}
    for path, tree in trees.items():
        name = by_path.get(path)
        if name is None:
            continue
        edges: dict[str, int] = {}

        def link(target: str | None, line: int) -> None:
            if target and target in modules and modules[target] != path:
                edges.setdefault(modules[target], line)

        for node in _top_level_imports(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    link(next((".".join(parts[:i]) for i in range(len(parts), 0, -1)
                               if ".".join(parts[:i]) in modules), None), node.lineno)
                continue
            if node.level:
                package = name if is_package.get(name) else name.rpartition(".")[0]
                parts = package.split(".") if package else []
                if node.level - 1 > len(parts):
                    continue
                base_parts = parts[: len(parts) - (node.level - 1)]
                base = ".".join(base_parts + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            for alias in node.names:
                submodule = f"{base}.{alias.name}" if base else alias.name
                link(submodule if submodule in modules else base, node.lineno)
        graph[path] = edges
    return graph


def _resolve_js(source: str, spec: str, file_set: set[str]) -> str | None:
    target = posixpath.normpath(posixpath.join(posixpath.dirname(source), spec))
    if target.startswith("../"):
        return None
    candidates = [target]
    stem, ext = posixpath.splitext(target)
    if ext in (".js", ".jsx", ".mjs", ".cjs"):
        candidates += [stem + e for e in (".ts", ".tsx", ".mts", ".cts")]
    candidates += [target + e for e in JS_EXTENSIONS]
    candidates += [f"{target}/index{e}" for e in JS_EXTENSIONS]
    return next((c for c in candidates if c in file_set), None)


def js_import_graph(repo: Repo) -> dict[str, dict[str, int]]:
    file_set = set(repo.files)
    graph: dict[str, dict[str, int]] = {}
    for path in repo.files:
        if language_of(path) not in JS_SOURCE or GENERATED.search(path):
            continue
        text = repo.text(path)
        if not text:
            continue
        edges: dict[str, int] = {}
        for match in JS_IMPORT.finditer(text):
            if match.group(1):  # `import type` is erased at compile time
                continue
            target = _resolve_js(path, match.group(2), file_set)
            if target and target != path:
                edges.setdefault(target, text.count("\n", 0, match.start(2)) + 1)
        for match in JS_REQUIRE.finditer(text):
            target = _resolve_js(path, match.group(1), file_set)
            if target and target != path:
                edges.setdefault(target, text.count("\n", 0, match.start(1)) + 1)
        if edges:
            graph[path] = edges
    return graph


def strongly_connected(graph: dict[str, dict[str, int]]) -> list[list[str]]:
    """Tarjan's algorithm, iterative; returns components with more than one node."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = 0
    for root in sorted(graph):
        if root in index:
            continue
        work = [(root, iter(sorted(graph.get(root, {}))))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(graph.get(child, {})))))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                if len(component) > 1:
                    components.append(sorted(component))
    return components


def _shortest_cycle(graph: dict[str, dict[str, int]], component: list[str]) -> list[str]:
    members = set(component)
    start = component[0]
    previous: dict[str, str] = {}
    queue = [start]
    seen = {start}
    while queue:
        node = queue.pop(0)
        for child in sorted(graph.get(node, {})):
            if child not in members:
                continue
            if child == start:
                path = [node]
                while path[-1] != start:
                    path.append(previous[path[-1]])
                return list(reversed(path)) + [start]
            if child not in seen:
                seen.add(child)
                previous[child] = node
                queue.append(child)
    return component + [start]


def import_cycles(repo: Repo, emitter: Emitter, trees: dict[str, ast.AST], limit: int = 10) -> None:
    if not emitter.wants("architecture"):
        return
    reported = 0
    for graph in (python_import_graph(trees, repo.files), js_import_graph(repo)):
        for component in strongly_connected(graph):
            if reported >= limit:
                return
            cycle = _shortest_cycle(graph, component)
            citations = []
            for source, target in list(zip(cycle, cycle[1:]))[:MAX_CYCLE_CITATIONS]:
                lines = repo.lines(source) or []
                line = graph[source].get(target)
                if line:
                    citations.append(line_span(source, lines, line))
            if not citations:
                continue
            reported += 1
            chain = " → ".join(cycle)
            emitter.add(
                "architecture/import-cycle",
                citations,
                f"{len(component)} modules import each other at load time: {chain}.",
                evidence={"modules": component},
                cap_key=component[0],
            )


def analyze(repo: Repo, emitter: Emitter, trees: dict[str, ast.AST]) -> None:
    large_files(repo, emitter)
    churn_hotspots(repo, emitter)
    todo_debt(repo, emitter)
    import_cycles(repo, emitter, trees)
