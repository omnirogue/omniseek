# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""Python rules evaluated on the syntax tree.

Working on the AST instead of text means code inside strings, comments and
docstrings never matches, and names are resolved through import aliases
(`import subprocess as sp` still counts as subprocess).
"""

from __future__ import annotations

import ast
import os
import re

from ..repo import Repo
from .base import Emitter, line_span

HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request"})
SHELL_CALLS = frozenset(
    {
        "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
        "subprocess.Popen",
    }
)
SHELL_STRING_CALLS = frozenset({"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"})
UNSAFE_LOADERS = frozenset(
    {
        "pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "_pickle.load", "_pickle.loads",
        "dill.load", "dill.loads", "marshal.load", "marshal.loads", "jsonpickle.decode", "yaml.unsafe_load",
        "pandas.read_pickle", "joblib.load",
    }
)
SAFE_YAML_LOADERS = ("SafeLoader", "CSafeLoader", "BaseLoader")
SQL_METHODS = frozenset(
    {"execute", "executescript", "exec_driver_sql", "raw", "query", "fetch", "fetchrow", "fetchval", "text"}
)
SQL_WORDS = re.compile(r"\b(select|insert\s+into|update|delete\s+from|create\s+table|drop\s+table|alter\s+table)\b", re.I)
BLOCKING_IN_ASYNC = frozenset(
    {
        "time.sleep", "urllib.request.urlopen", "subprocess.run", "subprocess.call", "subprocess.check_call",
        "subprocess.check_output", "os.system",
    }
)
ORM_METHODS = frozenset(
    {"get", "filter", "exclude", "create", "get_or_create", "update_or_create", "count", "exists", "first", "last"}
)
SETTINGS_FILE = re.compile(r"^(settings|production|prod|config|conf)[\w-]*\.py$")
MATCH_CASE = getattr(ast, "match_case", None)
TRY_NODES = tuple(t for t in (ast.Try, getattr(ast, "TryStar", None)) if t is not None)


def dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        inner = dotted(node.func)
        if inner:
            parts.append(inner + "()")
            return ".".join(reversed(parts))
    return None


def is_str_const(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _const_text(node: ast.AST) -> str:
    """The literal string parts of an expression."""
    return " ".join(n.value for n in ast.walk(node) if is_str_const(n))


def is_dynamic_string(node: ast.AST | None) -> bool:
    """An f-string with fields, `%`/`+` on a string, or `"...".format(...)`."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return any(is_str_const(side) or isinstance(side, ast.JoinedStr) for side in (node.left, node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return is_str_const(node.func.value)
    return False


def is_dynamic_sql(node: ast.AST | None) -> bool:
    return node is not None and is_dynamic_string(node) and bool(SQL_WORDS.search(_const_text(node)))


def _kw(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _is_const(node: ast.AST | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def complexity(fn: ast.AST) -> int:
    """McCabe-style complexity of one function, not counting nested functions or classes."""
    score = 1
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler)):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            score += 1 + len(node.ifs)
        elif MATCH_CASE is not None and isinstance(node, MATCH_CASE):
            score += 1
        stack.extend(ast.iter_child_nodes(node))
    return score


def import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


class _CallInfo:
    """A call node with its resolved names, shared by the per-rule checks."""

    __slots__ = ("node", "raw", "name", "attr", "first")

    def __init__(self, node: ast.Call, raw: str | None, name: str):
        self.node = node
        self.raw = raw
        self.name = name
        self.attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
        self.first = node.args[0] if node.args else None


class _Visitor(ast.NodeVisitor):
    def __init__(self, emitter: Emitter, path: str, lines: list[str], aliases: dict[str, str]):
        self.e = emitter
        self.path = path
        self.lines = lines
        self.aliases = aliases
        self.loop_depth = 0
        self.loops: list[ast.AST] = []
        self.functions: list[tuple[ast.AST, bool, dict]] = []  # (node, is_async, dynamic-SQL variables)
        self.reported_loops: set[int] = set()
        self.settings_file = bool(SETTINGS_FILE.match(os.path.basename(path)))

    # Helpers ------------------------------------------------------------------
    def qualify(self, name: str | None) -> str | None:
        if not name:
            return None
        head, _, rest = name.partition(".")
        if head in self.aliases:
            return self.aliases[head] + ("." + rest if rest else "")
        return name

    def cite(self, node: ast.AST, end: int | None = None, symbol: str | None = None) -> list[dict]:
        return [line_span(self.path, self.lines, node.lineno, end, symbol)]

    def where(self) -> str:
        for fn, _, _ in reversed(self.functions):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return f"`{fn.name}` in {self.path}"
        return self.path

    @property
    def in_async(self) -> bool:
        return bool(self.functions) and self.functions[-1][1]

    # Scopes -------------------------------------------------------------------
    def _function(self, node: ast.AST, is_async: bool) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._function_metrics(node)
        saved = self.loop_depth, self.loops
        self.loop_depth, self.loops = 0, []
        self.functions.append((node, is_async, {}))
        self.generic_visit(node)
        self.functions.pop()
        self.loop_depth, self.loops = saved

    def _function_metrics(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        end = getattr(node, "end_lineno", None) or node.lineno
        length = end - node.lineno + 1
        if length > 80 and self.e.wants_rule("architecture/long-function"):
            self.e.add(
                "architecture/long-function",
                self.cite(node, end, node.name),
                f"`{node.name}` in {self.path} spans {length} lines ({node.lineno}-{end}).",
                severity="medium" if length > 150 else "low",
                evidence={"lines": length},
            )
        score = complexity(node)
        if score > 20 and self.e.wants_rule("architecture/high-complexity"):
            self.e.add(
                "architecture/high-complexity",
                self.cite(node, end, node.name),
                f"`{node.name}` in {self.path} has cyclomatic complexity {score} (independent paths through the code).",
                severity="high" if score > 40 else "medium" if score > 30 else "low",
                evidence={"complexity": score},
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node, True)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._function(node, False)

    def _loop(self, node: ast.AST, before: list[ast.AST], body: list[ast.AST], after: list[ast.AST]) -> None:
        for child in before:
            self.visit(child)
        self.loop_depth += 1
        self.loops.append(node)
        for child in body:
            self.visit(child)
        self.loops.pop()
        self.loop_depth -= 1
        for child in after:
            self.visit(child)

    def visit_For(self, node: ast.For) -> None:
        self._loop(node, [node.iter, node.target], node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._loop(node, [node.iter, node.target], node.body, node.orelse)

    def visit_While(self, node: ast.While) -> None:
        self._loop(node, [], [node.test, *node.body], node.orelse)

    def _comprehension(self, node: ast.AST, elements: list[ast.AST]) -> None:
        generators = node.generators
        inner: list[ast.AST] = [generators[0].target, *generators[0].ifs]
        for generator in generators[1:]:
            inner += [generator.iter, generator.target, *generator.ifs]
        self._loop(node, [generators[0].iter], inner + elements, [])

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._comprehension(node, [node.elt])

    visit_SetComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._comprehension(node, [node.key, node.value])

    # Statements -----------------------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if (
            not self.functions
            and self.settings_file
            and "DEBUG" in targets
            and _is_const(node.value, True)
            and self.e.wants_rule("security/debug-enabled")
        ):
            self.e.add(
                "security/debug-enabled",
                self.cite(node, symbol="DEBUG"),
                f"{self.path} sets DEBUG = True at module level.",
            )
        if self.functions and len(targets) == 1 and is_dynamic_sql(node.value):
            self.functions[-1][2][targets[0]] = node
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names) and not self.path.endswith("__init__.py"):
            self.e.add(
                "architecture/wildcard-import",
                self.cite(node),
                f"{self.path} imports every public name from `{'.' * node.level}{node.module or ''}`.",
            )

    def _try(self, node: ast.AST) -> None:
        for handler in node.handlers:
            broad = handler.type is None or (
                isinstance(handler.type, ast.Name) and handler.type.id in ("Exception", "BaseException")
            )
            trivial = all(
                isinstance(stmt, (ast.Pass, ast.Continue))
                or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
                for stmt in handler.body
            )
            if broad and trivial:
                end = getattr(handler.body[-1], "end_lineno", None) or handler.lineno
                kind = "a bare `except:`" if handler.type is None else f"`except {handler.type.id}:`"
                self.e.add(
                    "architecture/swallowed-exception",
                    self.cite(handler, end),
                    f"{self.where()} catches {kind} and discards the error.",
                )
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self._try(node)

    visit_TryStar = visit_Try

    def visit_Await(self, node: ast.Await) -> None:
        if self.loops and self.in_async and isinstance(node.value, ast.Call):
            loop = self.loops[-1]
            target = self.qualify(dotted(node.value.func)) or ""
            if (
                id(loop) not in self.reported_loops
                and not isinstance(loop, ast.AsyncFor)
                and target not in ("asyncio.sleep", "anyio.sleep", "trio.sleep")
            ):
                self.reported_loops.add(id(loop))
                self.e.add(
                    "performance/sequential-await",
                    [line_span(self.path, self.lines, loop.lineno, node.lineno, quote_line=node.lineno)],
                    f"{self.where()} awaits `{target or 'a call'}` once per loop iteration, one after another.",
                    confidence="low",
                )
        self.generic_visit(node)

    # Calls ----------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        raw = dotted(node.func)
        call = _CallInfo(node, raw, self.qualify(raw) or "")
        for check in (
            self._check_eval, self._check_shell, self._check_deserialization, self._check_sql,
            self._check_tls, self._check_hash, self._check_debug, self._check_io,
        ):
            check(call)
        self.generic_visit(node)

    def _check_eval(self, call: _CallInfo) -> None:
        func, node = call.node.func, call.node
        if not (isinstance(func, ast.Name) and func.id in ("eval", "exec") and func.id not in self.aliases):
            return
        if node.args and not all(isinstance(a, ast.Constant) for a in node.args):
            self.e.add(
                "security/dangerous-eval",
                self.cite(node, symbol=func.id),
                f"{self.where()} passes a runtime value to `{func.id}()`.",
            )

    def _check_shell(self, call: _CallInfo) -> None:
        first = call.first
        if first is None or is_str_const(first):
            return
        if call.name in SHELL_CALLS and _is_const(_kw(call.node, "shell"), True):
            how = f"runs a computed command through a shell (`{call.raw}(..., shell=True)`)"
        elif call.name in SHELL_STRING_CALLS:
            how = f"passes a computed command string to `{call.raw}()`, which runs it through a shell"
        else:
            return
        self.e.add(
            "security/shell-injection",
            self.cite(call.node),
            f"{self.where()} {how}.",
            confidence="high" if is_dynamic_string(first) else "medium",
        )

    def _check_deserialization(self, call: _CallInfo) -> None:
        if call.name in UNSAFE_LOADERS or (call.name == "yaml.load" and not self._safe_yaml(call.node)):
            self.e.add(
                "security/unsafe-deserialization",
                self.cite(call.node),
                f"{self.where()} deserializes with `{call.raw}()`, which can execute code embedded in the data.",
            )

    def _check_sql(self, call: _CallInfo) -> None:
        first = call.first
        if first is None or not (call.attr in SQL_METHODS or call.name.endswith("sqlalchemy.text")):
            return
        if is_dynamic_sql(first):
            self.e.add(
                "security/sql-string-building",
                self.cite(call.node),
                f"{self.where()} formats values into the SQL passed to `{call.raw}()`.",
            )
            return
        if self.functions and isinstance(first, ast.Name):
            assigned = self.functions[-1][2].get(first.id)
            if assigned is not None:
                self.e.add(
                    "security/sql-string-building",
                    self.cite(assigned) + self.cite(call.node),
                    f"{self.where()} builds `{first.id}` with string formatting and passes it to `{call.raw}()`.",
                )

    def _check_tls(self, call: _CallInfo) -> None:
        if _is_const(_kw(call.node, "verify"), False) or call.name == "ssl._create_unverified_context":
            self.e.add(
                "security/tls-verification-disabled",
                self.cite(call.node),
                f"{self.where()} disables certificate verification in `{call.raw}()`.",
            )

    def _check_hash(self, call: _CallInfo) -> None:
        first = call.first
        weak = call.name in ("hashlib.md5", "hashlib.sha1") or (
            call.name == "hashlib.new" and is_str_const(first) and first.value.lower() in ("md5", "sha1")
        )
        if weak and not _is_const(_kw(call.node, "usedforsecurity"), False):
            self.e.add(
                "security/weak-hash",
                self.cite(call.node),
                f"{self.where()} uses `{call.raw}()` without usedforsecurity=False.",
                confidence="low",
            )

    def _check_debug(self, call: _CallInfo) -> None:
        if call.attr == "run" and _is_const(_kw(call.node, "debug"), True):
            self.e.add("security/debug-enabled", self.cite(call.node), f"{self.where()} starts the server with debug=True.")

    def _check_io(self, call: _CallInfo) -> None:
        if self.loop_depth and self._is_io(call.name, call.attr, call.raw):
            self.e.add(
                "performance/io-in-loop",
                self.cite(call.node),
                f"{self.where()} calls `{call.raw}()` inside a loop: one round trip per iteration.",
            )
        if self.in_async and (call.name in BLOCKING_IN_ASYNC or self._is_requests(call.name)):
            self.e.add(
                "performance/blocking-call-in-async",
                self.cite(call.node),
                f"{self.where()} is `async` but calls the blocking `{call.raw}()`.",
            )

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self.qualify(dotted(node)) == "ssl.CERT_NONE":
            self.e.add(
                "security/tls-verification-disabled",
                self.cite(node),
                f"{self.where()} uses ssl.CERT_NONE, which accepts any certificate.",
            )
        self.generic_visit(node)

    @staticmethod
    def _safe_yaml(node: ast.Call) -> bool:
        loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
        name = dotted(loader) if loader is not None else None
        return bool(name and name.endswith(SAFE_YAML_LOADERS))

    @staticmethod
    def _is_requests(name: str) -> bool:
        head, _, verb = name.rpartition(".")
        return head in ("requests", "httpx") and verb in HTTP_VERBS

    def _is_io(self, name: str, attr: str | None, raw: str | None) -> bool:
        if self._is_requests(name) or name == "urllib.request.urlopen":
            return True
        if attr == "execute":
            return True
        receiver = (raw or "").rsplit(".", 1)[0].lower()
        if attr in ORM_METHODS and ".objects" in "." + receiver:
            return True
        last = receiver.rsplit(".", 1)[-1]
        return attr in HTTP_VERBS and any(word in last for word in ("session", "client", "http"))


def parse(repo: Repo, path: str) -> ast.AST | None:
    text = repo.text(path)
    if text is None:
        return None
    try:
        return ast.parse(text, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def analyze(repo: Repo, emitter: Emitter) -> dict[str, ast.AST]:
    """Run every Python rule; return the parsed trees for the structure analyzers."""
    trees: dict[str, ast.AST] = {}
    for path in repo.text_files("python"):
        tree = parse(repo, path)
        if tree is None:
            continue
        trees[path] = tree
        lines = repo.lines(path) or []
        try:
            _Visitor(emitter, path, lines, import_aliases(tree)).visit(tree)
        except RecursionError:
            continue
    return trees
