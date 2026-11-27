"""Read what Python source declares, without importing or running any of it.

A file is parsed to a syntax tree and read as text. The reader follows a name to the
expression bound to it: a constant, an environment default, a formatted string, a
class attribute, a parameter default, a value imported from another module of the
project or returned by one of its functions. What it follows is bounded, and where
it cannot tell what a name stands for it records nothing for that name. An
identifier it reads is a declaration: the source says so, a run may say otherwise.

Recorded from a file that imports a known SDK: model identifiers given to a client,
a constructor or an agent; agents and the models, tools, MCP servers, sub-agents,
guardrails and memory their constructors name; tools declared by decorator, class,
wrapper, schema or reference; MCP servers started or reached from code; guardrails;
retrieval and memory stores; and the names of credential environment variables.
"""

from __future__ import annotations

import ast
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, TypeVar

from nexus_symbiote import limits
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.scanners.base import ScanResult, parse_python
from nexus_symbiote.scanners.source_python_tables import (
    AGENT_TOOL_METHODS,
    AGENT_WRAPPERS,
    AGENTS,
    AI_ROOTS,
    AI_SUBMODULES,
    APPROVAL_KEYWORDS,
    BEDROCK_GUARDRAIL_KEYS,
    BEDROCK_GUARDRAIL_VERSIONS,
    CLASS_METHODS,
    CLASS_PROVIDERS,
    CLI_MODEL_OPTIONS,
    CLIENT_KEYWORDS,
    CREDENTIAL_KEYWORDS,
    DATASET_LOADERS,
    DOCUMENT_LOADER_ROOTS,
    DOCUMENT_LOADER_SUFFIXES,
    DOCUMENT_LOADERS,
    DOCUMENT_PATH_KEYWORDS,
    EMBEDDING_ARGUMENTS,
    EMBEDDING_KEYWORDS,
    ENDPOINT_KEYWORDS,
    ENVIRONMENT_READS,
    FRAMEWORK_PROVIDERS,
    GUARDRAIL_CALLS,
    GUARDRAIL_DECORATORS,
    GUARDRAIL_WRAPPERS,
    HOSTED_AGENT_METHODS,
    HOSTED_TOOLS,
    MCP_MAP_KEYWORDS,
    MCP_MAPS,
    MCP_NESTED_KEYWORDS,
    MCP_ROOTS,
    MCP_SSE,
    MCP_STDIO,
    MCP_URL,
    MCP_WRAPPERS,
    MEMORY_BY_MODULE,
    MEMORY_STORES,
    MODEL_CONSTANT,
    MODEL_DICT_KEYS,
    MODEL_KEYWORDS,
    MODULE_PROVIDERS,
    OPTION_CONTROLS,
    POSITIONAL_MODELS,
    PROVIDER_SEGMENT_PARENTS,
    REPO_ID_CLASSES,
    SEGMENT_PROVIDERS,
    SETTINGS_BASES,
    STORE_IDENTITY_KEYWORDS,
    STORE_METHODS,
    TOOL_BASES,
    TOOL_BINDERS,
    TOOL_DECORATORS,
    TOOL_KEYWORDS,
    TOOL_NAME_KEYWORDS,
    TOOL_NODES,
    TOOL_WRAPPERS,
    VECTOR_STORES,
    WEIGHT_CLASSES,
    WEIGHT_ROOTS,
    AgentSpec,
)
from nexus_symbiote.scanners.source_references import (
    AgentRecord,
    Declarations,
    credential_name,
    declared_name,
    endpoint_origin,
    environment_name,
)

METHOD = "python-ast"
LOCAL = "<project>"
MAX_DEPTH = 12
MAX_CANDIDATES = 16
MAX_STRINGS = 8
# No identifier the collector records is this long, so longer text is part of none.
MAX_TEXT = 512
# How deep into a package a module of the project is looked for.
MAX_PACKAGES = 8
MAX_SERVER_ARGUMENTS = 256
MAX_STEPS = 2_000_000
MAX_NESTING = 48
UNRESOLVED = "${UNRESOLVED}"
_MODEL_CONSTANT = re.compile(MODEL_CONSTANT, re.IGNORECASE)
_MCP_SYMBOLS = MCP_STDIO | MCP_URL | MCP_WRAPPERS | MCP_MAPS
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_SCOPES = (*_FUNCTIONS, ast.ClassDef)
_DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_T = TypeVar("_T")


@dataclass(eq=False)
class Module:
    """One parsed file: its imports and what each scope binds."""

    path: str
    tree: ast.Module
    digest: str
    nodes: list[ast.AST] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)
    parents: dict[ast.AST, ast.AST] = field(default_factory=dict)
    bindings: dict[ast.AST | None, dict[str, list[ast.expr]]] = field(default_factory=dict)
    definitions: dict[ast.AST | None, dict[str, ast.AST]] = field(default_factory=dict)
    parameters: dict[ast.AST, dict[str, ast.arg]] = field(default_factory=dict)
    attributes: dict[ast.AST, dict[str, list[ast.expr]]] = field(default_factory=dict)


@dataclass(frozen=True, eq=False)
class _Value:
    module: Module
    node: ast.AST


def _split(origin: str) -> tuple[str, str, str | None]:
    """The module, symbol and class method an origin names."""
    parts = origin.split(".")
    if len(parts) >= 2 and parts[-1] in CLASS_METHODS:
        return ".".join(parts[:-2]), parts[-2], parts[-1]
    return ".".join(parts[:-1]), parts[-1], None


def _under(origin: str, prefix: str) -> bool:
    return origin == prefix or origin.startswith(prefix + ".")


def _row(origin: str | None, table: dict[tuple[str, str], _T]) -> _T | None:
    """The row of ``table`` for the constructor or function ``origin`` names."""
    if origin is None or "(" in origin or origin.startswith(LOCAL):
        return None
    module, symbol, method = _split(origin)
    names = [f"{symbol}.{method}", symbol, method] if method else [symbol]
    for name in names:
        for (prefix, wanted), row in table.items():
            if wanted in (name, "*") and _under(module, prefix):
                return row
    return None


def _keywords(call: ast.Call) -> dict[str, ast.expr]:
    return {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg is not None}


def _constant(node: ast.AST | None) -> object:
    return node.value if isinstance(node, ast.Constant) else None


def _ai_import(dotted: str) -> bool:
    root = dotted.split(".", 1)[0]
    if root not in AI_ROOTS:
        return False
    parts = AI_SUBMODULES.get(root)
    return parts is None or any(_under(dotted, part) for part in parts)


def provider_of(origin: str) -> str | None:
    """The provider the client, constructor or function behind ``origin`` talks to."""
    base = origin.split("()", 1)[0]
    module, symbol, _ = _split(base)
    named = CLASS_PROVIDERS.get(symbol)
    if named:
        return named
    segments = base.split(".")
    for index, segment in enumerate(segments[:-1]):
        if segment in PROVIDER_SEGMENT_PARENTS and segments[index + 1] in SEGMENT_PROVIDERS:
            return SEGMENT_PROVIDERS[segments[index + 1]]
    best = ""
    for prefix in MODULE_PROVIDERS:
        if _under(base, prefix) and len(prefix) > len(best):
            best = prefix
    return MODULE_PROVIDERS.get(best)


def framework_provider(origin: str) -> str | None:
    """The service the framework behind ``origin`` sends a bare identifier to."""
    base = origin.split("()", 1)[0]
    return next(
        (named for prefix, named in FRAMEWORK_PROVIDERS.items() if _under(base, prefix)), None
    )


def _loads_weights(origin: str) -> bool:
    base = origin.split("()", 1)[0]
    _, symbol, _ = _split(base)
    return symbol in WEIGHT_CLASSES or any(_under(base, root) for root in WEIGHT_ROOTS)


class PythonReader:
    """Reads the Python files of one project into a ``Declarations``."""

    def __init__(self, declarations: Declarations, result: ScanResult) -> None:
        self._found = declarations
        self._result = result
        self._sources: dict[str, bytes] = {}
        self._texts: dict[str, str] = {}
        self._modules: dict[str, Module | None] = {}
        self._analysed: list[Module] = []
        self._agents_by_call: dict[int, AgentRecord] = {}
        self._agent_calls: list[tuple[Module, ast.Call, AgentSpec, AgentRecord]] = []
        self._model_calls: dict[int, list[str]] = {}
        self._mcp_calls: dict[int, set[str]] = {}
        self._function_tools: dict[int, str | None] = {}
        self._guardrail_functions: dict[int, str | None] = {}
        self._candidates: set[str] = set()
        self._resolved: dict[tuple[str, str], str | None] = {}
        self._nesting = 0
        self._followed: dict[int, list[_Value]] = {}
        self._following: set[int] = set()
        self._origins: dict[int, str | None] = {}
        self._steps = 0
        self._exhausted: set[str] = set()
        self.known_files: frozenset[str] = frozenset()

    # -- files -------------------------------------------------------------------

    def add(self, path: str, content: bytes, text: str) -> None:
        """Offer one source file. Every file can be a module another imports from."""
        self._sources[path] = content
        self._texts[path] = text

    def add_cells(self, path: str, text: str) -> None:
        """Offer the code cells of a notebook as one module named by the notebook."""
        self._sources[path] = text.encode()
        self._texts[path] = text
        self._candidates.add(path)

    def read(self, candidates: set[str]) -> None:
        """Analyse the candidate files, in path order, then wire the agents they declare."""
        self._candidates |= candidates
        for path in sorted(self._candidates):
            module = self._load(path)
            if module is None or not self._imports_sdk(module):
                continue
            self._analysed.append(module)
            self._spend(module, self._register_agents)
        for module in self._analysed:
            self._spend(module, self._analyse)
        for module, call, spec, record in self._agent_calls:
            self._steps = self._allowance(module)
            self._wire(module, call, spec, record)
            self._overspent(module)

    @staticmethod
    def _allowance(module: Module) -> int:
        """The names one pass over a file may follow: linear in the file's size."""
        return min(MAX_STEPS, 10_000 + 50 * len(module.nodes))

    def _spend(self, module: Module, work: Callable[[Module], None]) -> None:
        self._steps = self._allowance(module)
        work(module)
        self._overspent(module)

    def _overspent(self, module: Module) -> None:
        if self._steps <= 0 and module.path not in self._exhausted:
            self._exhausted.add(module.path)
            self._found.gap(
                module.path,
                1,
                "Python source holds more name bindings than the collector follows; "
                "some declarations were not read",
            )

    def _load(self, path: str) -> Module | None:
        if path in self._modules:
            return self._modules[path]
        self._modules[path] = None
        text = self._texts.get(path)
        if text is None:
            return None
        try:
            tree = parse_python(text)
        except (SyntaxError, ValueError):
            if path in self._candidates:
                self._found.gap(path, 1, "Python source could not be parsed; not read")
            return None
        module = Module(path, tree, hash_bytes(self._sources[path]))
        if not self._index(module):
            if path in self._candidates:
                self._found.gap(
                    path,
                    1,
                    "Python source has more syntax nodes than the python-nodes limit; not read",
                )
            return None
        self._modules[path] = module
        return module

    def _index(self, module: Module) -> bool:
        bound = limits.current().python_nodes
        stack: list[ast.AST] = [module.tree]
        while stack:
            node = stack.pop()
            module.nodes.append(node)
            if len(module.nodes) > bound:
                return False
            children = list(ast.iter_child_nodes(node))
            for child in children:
                module.parents[child] = node
            stack.extend(reversed(children))
        package = PurePosixPath(module.path).parent.parts
        for node in module.nodes:
            self._bind(module, node, package)
        return True

    def _bind(self, module: Module, node: ast.AST, package: tuple[str, ...]) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                module.imports[bound] = alias.name if alias.asname else bound
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                kept = package[: len(package) - (node.level - 1)] if node.level > 1 else package
                base = ".".join([*kept, base] if base else kept)
            for alias in node.names:
                if alias.name != "*":
                    name = f"{base}.{alias.name}" if base else alias.name
                    module.imports[alias.asname or alias.name] = name
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                self._bind_target(module, target, node.value, node)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            if node.value is not None:
                self._bind_target(module, node.target, node.value, node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self._bind_target(module, item.optional_vars, item.context_expr, node)
        elif isinstance(node, _DEFINITIONS):
            scope = self._scope(module, node)
            module.definitions.setdefault(scope, {})[node.name] = node
        if isinstance(node, _FUNCTIONS):
            arguments = node.args
            positional = [*arguments.posonlyargs, *arguments.args]
            named = module.parameters.setdefault(node, {})
            for argument in (*positional, *arguments.kwonlyargs):
                named[argument.arg] = argument
            defaults = module.bindings.setdefault(node, {})
            for argument, default in zip(
                positional[len(positional) - len(arguments.defaults) :],
                arguments.defaults,
                strict=True,
            ):
                defaults.setdefault(argument.arg, []).append(default)
            for argument, optional in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
                if optional is not None:
                    defaults.setdefault(argument.arg, []).append(optional)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            # ``tools.append(x)`` and ``tools.extend(more)`` add to the list ``tools`` names.
            call = node.value
            function = call.func
            if (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.attr in {"append", "extend"}
                and len(call.args) == 1
            ):
                added = (
                    call.args[0]
                    if function.attr == "extend"
                    else ast.List(elts=[call.args[0]], ctx=ast.Load())
                )
                scope = self._scope(module, node)
                module.bindings.setdefault(scope, {}).setdefault(function.value.id, []).append(
                    added
                )

    def _bind_target(
        self, module: Module, target: ast.expr, value: ast.expr, statement: ast.AST
    ) -> None:
        scope = self._scope(module, statement)
        if isinstance(target, ast.Name):
            module.bindings.setdefault(scope, {}).setdefault(target.id, []).append(value)
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in {"self", "cls"}
        ):
            owner = self._class(module, statement)
            if owner is not None:
                module.attributes.setdefault(owner, {}).setdefault(target.attr, []).append(value)
        elif (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
        ):
            for part, bound in zip(target.elts, value.elts, strict=True):
                self._bind_target(module, part, bound, statement)

    def _scope(self, module: Module, node: ast.AST) -> ast.AST | None:
        current = module.parents.get(node)
        while current is not None and not isinstance(current, _SCOPES):
            current = module.parents.get(current)
        return current

    def _class(self, module: Module, node: ast.AST) -> ast.ClassDef | None:
        current = module.parents.get(node)
        while current is not None and not isinstance(current, ast.ClassDef):
            current = module.parents.get(current)
        return current

    def _imports_sdk(self, module: Module) -> bool:
        return any(
            _ai_import(dotted) and not self._in_project(dotted, module)
            for dotted in module.imports.values()
        )

    def _in_project(self, dotted: str, importer: Module) -> bool:
        """Whether a dotted name, or a package it lies in, is a module of the project."""
        parts = dotted.split(".", MAX_PACKAGES)[:MAX_PACKAGES]
        return any(
            self._project_file(".".join(parts[:count]), importer) is not None
            for count in range(len(parts), 0, -1)
        )

    def _project_file(self, dotted: str, importer: Module) -> str | None:
        """The project file a dotted module name resolves to from ``importer``, if any.

        A module is looked for beside the importing file, in each directory above it
        up to the project root, and in the usual source directories.
        """
        directory = importer.path.rpartition("/")[0]
        key = (dotted, directory)
        if key in self._resolved:
            return self._resolved[key]
        relative = dotted.replace(".", "/")
        bases: list[str] = []
        while directory:
            bases.append(directory + "/")
            directory = directory.rpartition("/")[0]
        bases.extend(("", "src/", "lib/", "app/"))
        found: str | None = None
        for base in bases:
            for candidate in (f"{base}{relative}.py", f"{base}{relative}/__init__.py"):
                if found is None and candidate in self._texts:
                    found = candidate
        self._resolved[key] = found
        return found

    def _project_module(self, dotted: str, importer: Module) -> Module | None:
        path = self._project_file(dotted, importer)
        return None if path is None else self._load(path)

    # -- names -------------------------------------------------------------------

    def _in_scope(self, module: Module, scope: ast.AST | None, name: str) -> list[_Value] | None:
        values = module.bindings.get(scope, {}).get(name, [])
        found = [_Value(module, value) for value in values]
        definition = module.definitions.get(scope, {}).get(name)
        if definition is not None:
            found.append(_Value(module, definition))
        if not found and scope is not None:
            parameter = module.parameters.get(scope, {}).get(name)
            if parameter is not None:
                found.append(_Value(module, parameter))
        return found or None

    def _lookup(self, module: Module, name: str, at: ast.AST) -> list[_Value] | None:
        """What ``name`` is bound to where ``at`` reads it; None when the file binds none."""
        scope = self._scope(module, at)
        nearest = True
        while True:
            if scope is None or nearest or not isinstance(scope, ast.ClassDef):
                found = self._in_scope(module, scope, name)
                if found is not None:
                    return found
            if scope is None:
                return None
            nearest = False
            scope = self._scope(module, scope)

    def _imported(self, module: Module, name: str, depth: int = 0) -> list[_Value] | None:
        """The values a name imported from another module of the project is bound to."""
        dotted = module.imports.get(name)
        if dotted is None or depth > MAX_DEPTH:
            return None
        head, _, symbol = dotted.rpartition(".")
        if not head:
            return None
        other = self._project_module(head, module)
        if other is None:
            return None
        found = self._in_scope(other, None, symbol)
        if found is not None:
            return found
        return self._imported(other, symbol, depth + 1)

    def _members(self, value: _Value, name: str, depth: int) -> list[_Value] | None:
        """The values of attribute ``name`` on what ``value`` is, when that can be read."""
        module, node = value.module, value.node
        if isinstance(node, ast.ClassDef):
            found = [
                _Value(module, bound) for bound in module.attributes.get(node, {}).get(name, [])
            ]
            found.extend(self._in_scope(module, node, name) or [])
            return found or None
        target: ast.AST | None = None
        if isinstance(node, ast.Call):
            target = node.func
        elif isinstance(node, ast.arg):
            target = node.annotation
        if target is None or depth > MAX_DEPTH:
            return None
        for owner in self._follow(module, target, depth + 1):
            if isinstance(owner.node, ast.ClassDef):
                return self._members(owner, name, depth + 1)
        return None

    def _attribute(self, module: Module, node: ast.Attribute, depth: int) -> list[_Value] | None:
        base = node.value
        if isinstance(base, ast.Name) and base.id in {"self", "cls"}:
            owner = self._class(module, node)
            if owner is not None:
                return self._members(_Value(module, owner), node.attr, depth)
            return None
        if isinstance(base, ast.Name) and self._lookup(module, base.id, base) is None:
            dotted = module.imports.get(base.id)
            other = None if dotted is None else self._project_module(dotted, module)
            if other is not None:
                return self._in_scope(other, None, node.attr) or self._imported(other, node.attr)
        if depth > MAX_DEPTH:
            return None
        for holder in self._follow(module, base, depth + 1):
            found = self._members(holder, node.attr, depth + 1)
            if found is not None:
                return found
        return None

    def _returns(self, module: Module, call: ast.Call, depth: int) -> list[_Value] | None:
        """The expressions a call of one of the project's own functions returns."""
        if depth > MAX_DEPTH:
            return None
        for target in self._follow(module, call.func, depth + 1):
            function = target.node
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            returned: list[_Value] = []
            stack: list[ast.AST] = list(function.body)
            while stack:
                node = stack.pop()
                if isinstance(node, _SCOPES):
                    continue
                if isinstance(node, ast.Return) and node.value is not None:
                    returned.append(_Value(target.module, node.value))
                stack.extend(ast.iter_child_nodes(node))
            return returned or None
        return None

    def _literal_item(self, module: Module, node: ast.Subscript, depth: int) -> list[_Value] | None:
        key = _constant(node.slice)
        for holder in self._follow(module, node.value, depth + 1):
            if not isinstance(holder.node, ast.Dict):
                continue
            values = [
                _Value(holder.module, value)
                for name, value in zip(holder.node.keys, holder.node.values, strict=True)
                if name is not None and (key is None or _constant(name) == key)
            ]
            if values:
                return values
        return None

    def _follow(self, module: Module, node: ast.AST, depth: int = 0) -> list[_Value]:
        """The expressions ``node`` stands for, each one the reader can follow no further."""
        key = id(node)
        known = self._followed.get(key)
        if known is not None:
            return known
        # A name bound in terms of itself, as in ``text = text.strip()``, is being
        # followed already: it stands for nothing more here. Each node is followed
        # once and its result kept, so such chains cost no more than their length.
        if key in self._following:
            return []
        out: list[_Value] = []
        if self._nesting >= MAX_NESTING:
            self._steps = 0
            return [_Value(module, node)]
        self._nesting += 1
        self._following.add(key)
        try:
            self._follow_into(_Value(module, node), out, set(), depth)
        finally:
            self._nesting -= 1
            self._following.discard(key)
        self._followed[key] = out
        return out

    def _follow_into(self, value: _Value, out: list[_Value], seen: set[int], depth: int) -> None:
        module, node = value.module, value.node
        if len(out) >= MAX_CANDIDATES or id(node) in seen:
            return
        seen.add(id(node))
        self._steps -= 1
        if depth > MAX_DEPTH or self._steps <= 0:
            out.append(value)
            return
        found: list[_Value] | None = None
        if isinstance(node, ast.Name):
            found = self._lookup(module, node.id, node)
            if found is None:
                found = self._imported(module, node.id)
        elif isinstance(node, ast.Attribute):
            found = self._attribute(module, node, depth)
        elif isinstance(node, (ast.Await, ast.NamedExpr, ast.Starred)):
            found = [_Value(module, node.value)]
        elif isinstance(node, ast.IfExp):
            found = [_Value(module, node.body), _Value(module, node.orelse)]
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            found = [_Value(module, operand) for operand in node.values]
        elif isinstance(node, ast.Subscript):
            found = self._literal_item(module, node, depth)
        elif isinstance(node, ast.Call):
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and function.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                item = ast.Subscript(value=function.value, slice=node.args[0], ctx=ast.Load())
                found = self._literal_item(module, item, depth)
                if (
                    found is None
                    and len(node.args) > 1
                    and not self._environment_read(module, node)
                ):
                    found = [_Value(module, node.args[1])]
            if found is None:
                found = self._returns(module, node, depth)
        if found is None:
            out.append(value)
            return
        for inner in found:
            self._follow_into(inner, out, seen, depth + 1)

    def origin(self, module: Module, node: ast.AST, depth: int = 0) -> str | None:
        """The dotted name of what ``node`` calls or names: ``openai.OpenAI().chat``."""
        key = id(node)
        if key not in self._origins:
            # Held as unknown while it is worked out, so a name bound in terms of
            # itself ends here, and each node is worked out once.
            self._origins[key] = None
            if self._nesting < MAX_NESTING:
                self._nesting += 1
                try:
                    self._origins[key] = self._origin(module, node, depth)
                finally:
                    self._nesting -= 1
            else:
                self._steps = 0
        return self._origins[key]

    def _origin(self, module: Module, node: ast.AST, depth: int) -> str | None:
        self._steps -= 1
        if depth > MAX_DEPTH or self._steps <= 0:
            return None
        if isinstance(node, ast.Name):
            found = self._lookup(module, node.id, node)
            if found is None:
                return self._import_origin(module, node.id, depth)
            origins = {self._value_origin(value, depth + 1) for value in found}
            return origins.pop() if len(origins) == 1 else None
        if isinstance(node, ast.Attribute):
            resolved = self._attribute(module, node, depth) if self._local_base(node) else None
            if resolved is not None:
                origins = {self._value_origin(value, depth + 1) for value in resolved}
                return origins.pop() if len(origins) == 1 else None
            base = self.origin(module, node.value, depth + 1)
            return None if base is None else f"{base}.{node.attr}"
        if isinstance(node, ast.Call):
            base = self.origin(module, node.func, depth + 1)
            return None if base is None else f"{base}()"
        if isinstance(node, ast.Await):
            return self.origin(module, node.value, depth + 1)
        return None

    @staticmethod
    def _local_base(node: ast.Attribute) -> bool:
        return isinstance(node.value, ast.Name)

    def _import_origin(self, module: Module, name: str, depth: int) -> str | None:
        dotted = module.imports.get(name)
        if dotted is None or depth > MAX_DEPTH:
            return None
        if self._project_file(dotted, module) is not None:
            return f"{LOCAL}.{dotted}"
        head, _, symbol = dotted.rpartition(".")
        other = self._project_module(head, module) if head else None
        if other is None:
            return dotted
        found = self._in_scope(other, None, symbol)
        if found is not None:
            origins = {self._value_origin(value, depth + 1) for value in found}
            return origins.pop() if len(origins) == 1 else None
        if symbol in other.imports:
            return self._import_origin(other, symbol, depth + 1)
        return f"{LOCAL}.{dotted}"

    def _value_origin(self, value: _Value, depth: int) -> str | None:
        node = value.node
        if isinstance(node, _DEFINITIONS):
            return f"{LOCAL}.{node.name}"
        if isinstance(node, ast.arg):
            if node.annotation is None:
                return None
            base = self.origin(value.module, node.annotation, depth + 1)
            return None if base is None else f"{base}()"
        if isinstance(node, (ast.Name, ast.Attribute, ast.Call, ast.Await)):
            return self.origin(value.module, node, depth + 1)
        return None

    # -- values ------------------------------------------------------------------

    def _environment_read(
        self, module: Module, node: ast.AST
    ) -> tuple[str, ast.expr | None] | None:
        """The variable an expression reads from the environment, and its default."""
        if isinstance(node, ast.Subscript):
            name = _constant(node.slice)
            if isinstance(name, str) and self.origin(module, node.value) == "os.environ":
                return name, None
            return None
        if not isinstance(node, ast.Call) or not node.args:
            return None
        name = _constant(node.args[0])
        if not isinstance(name, str) or self.origin(module, node.func) not in ENVIRONMENT_READS:
            return None
        default = node.args[1] if len(node.args) > 1 else _keywords(node).get("default")
        return name, default

    def strings(
        self, module: Module, node: ast.AST, depth: int = 0
    ) -> list[tuple[str, str | None]]:
        """The text values ``node`` can stand for, each with the variable that overrides it."""
        out: list[tuple[str, str | None]] = []
        for value in self._follow(module, node, depth):
            self._strings(value, out, depth)
        unique: list[tuple[str, str | None]] = []
        for item in out:
            if item not in unique:
                unique.append(item)
        return unique[:MAX_STRINGS]

    def _strings(self, value: _Value, out: list[tuple[str, str | None]], depth: int) -> None:
        module, node = value.module, value.node
        if depth > MAX_DEPTH:
            return
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and len(node.value) <= MAX_TEXT:
                out.append((node.value, None))
            return
        read = self._environment_read(module, node)
        if read is not None:
            name, default = read
            if default is not None:
                out.extend((text, name) for text, _ in self.strings(module, default, depth + 1))
            return
        parts: list[ast.AST] = []
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                parts.append(part.value if isinstance(part, ast.FormattedValue) else part)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            parts = [node.left, node.right]
        elif isinstance(node, ast.Call):
            function = node.func
            symbol = function.attr if isinstance(function, ast.Attribute) else None
            if isinstance(function, ast.Name):
                symbol = function.id
            default = _keywords(node).get("default") or (node.args[0] if node.args else None)
            if symbol in {"Field", "field", "str"} and default is not None:
                out.extend(self.strings(module, default, depth + 1))
            elif symbol == "strip" and isinstance(function, ast.Attribute):
                out.extend(self.strings(module, function.value, depth + 1))
            return
        if not parts:
            return
        built: list[tuple[str, str | None]] = [("", None)]
        for piece in parts:
            options = self.strings(module, piece, depth + 1)
            if not options:
                return
            # Joined text is bounded: a name joined to itself would otherwise double
            # at every binding it passes through.
            built = [
                (text + more, variable or other)
                for text, variable in built
                for more, other in options
                if len(text) + len(more) <= MAX_TEXT
            ][:MAX_STRINGS]
        out.extend(built)

    def _text(self, module: Module, node: ast.AST | None) -> str | None:
        """The one text value ``node`` stands for, when there is exactly one."""
        if node is None:
            return None
        found = {text for text, _ in self.strings(module, node)}
        return found.pop() if len(found) == 1 else None

    def _environment_names(self, module: Module, node: ast.AST | None) -> list[str]:
        """Each environment variable an expression reads, wherever in it the read is."""
        if node is None:
            return []
        names: list[str] = []
        stack: list[ast.AST] = [value.node for value in self._follow(module, node)]
        count = 0
        while stack and count < 256:
            current = stack.pop()
            count += 1
            read = self._environment_read(module, current)
            if read is not None and read[0] not in names:
                names.append(read[0])
            stack.extend(ast.iter_child_nodes(current))
        return names

    # -- passes ------------------------------------------------------------------

    def _register_agents(self, module: Module) -> None:
        for node in module.nodes:
            if not isinstance(node, ast.Call):
                continue
            origin = self.origin(module, node.func)
            if origin is None:
                continue
            spec = _row(origin, AGENTS)
            if spec is None:
                spec = next(
                    (
                        hosted
                        for method, hosted in HOSTED_AGENT_METHODS.items()
                        if origin.endswith(method) and provider_of(origin) == hosted.provider
                    ),
                    None,
                )
            if spec is None:
                continue
            location, name = self._agent_name(module, node, spec)
            if name is None:
                self._found.gap(
                    module.path,
                    node.lineno,
                    f"{spec.framework} agent declared without a name the collector can read; "
                    "not inventoried",
                )
                continue
            record = self._found.agent(
                location,
                node.lineno,
                name,
                framework=spec.framework,
                method=METHOD,
                digest=module.digest,
            )
            if record is None:
                continue
            record.locations.add((module.path, node.lineno))
            self._agents_by_call[id(node)] = record
            self._agent_calls.append((module, node, spec, record))

    def _binding(self, module: Module, call: ast.Call) -> str | None:
        """The name source gives the value of ``call``: a variable, an attribute or a function."""
        parent = module.parents.get(call)
        if isinstance(parent, ast.Await):
            parent = module.parents.get(parent)
        if isinstance(parent, (ast.Assign, ast.AnnAssign)):
            targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            if len(targets) == 1:
                target = targets[0]
                if isinstance(target, ast.Name):
                    return target.id
                if isinstance(target, ast.Attribute):
                    return target.attr
        if isinstance(parent, ast.Return):
            scope = self._scope(module, parent)
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return scope.name
        if isinstance(parent, ast.Dict):
            for key, value in zip(parent.keys, parent.values, strict=True):
                name = _constant(key)
                if value is call and isinstance(name, str):
                    return name
        if isinstance(parent, ast.withitem) and isinstance(parent.optional_vars, ast.Name):
            return parent.optional_vars.id
        return None

    def _agent_name(
        self, module: Module, call: ast.Call, spec: AgentSpec
    ) -> tuple[str, str | None]:
        """The file an agent belongs to and the name it is declared under.

        The name is the one its constructor gives it; without one, the name source
        binds the agent to: a variable, an attribute, a dictionary key or the function
        that returns it.
        """
        keywords = _keywords(call)
        candidates: list[ast.expr] = [keywords[key] for key in spec.name if key in keywords]
        if spec.name_position is not None and len(call.args) > spec.name_position:
            candidates.append(call.args[spec.name_position])
        for candidate in candidates:
            name = declared_name(self._text(module, candidate))
            if name is not None:
                return module.path, name
        configured = keywords.get("config")
        if spec.framework == "crewai" and isinstance(configured, ast.Subscript):
            key = _constant(configured.slice)
            if isinstance(key, str) and declared_name(key):
                return self._crew_file(module, call, "agents_config"), key
        return module.path, declared_name(self._binding(module, call))

    def _crew_file(self, module: Module, call: ast.Call, attribute: str) -> str:
        """The configuration file a CrewAI class names, when the project holds it."""
        owner = self._class(module, call)
        declared = "config/agents.yaml" if attribute == "agents_config" else "config/tasks.yaml"
        if owner is not None:
            values = self._members(_Value(module, owner), attribute, 0) or []
            for value in values:
                text = _constant(value.node)
                if isinstance(text, str):
                    declared = text
        path = (PurePosixPath(module.path).parent / declared).as_posix()
        return path if path in self.known_files else module.path

    def _analyse(self, module: Module) -> None:
        for node in module.nodes:
            if isinstance(node, ast.Call):
                self._call(module, node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function(module, node)
            elif isinstance(node, ast.ClassDef):
                self._class_definition(module, node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._named_constant(module, node)
            elif isinstance(node, ast.Dict):
                self._dictionary(module, node)
            elif isinstance(node, ast.Subscript):
                read = self._environment_read(module, node)
                if read is not None:
                    self._found.credential(read[0], module.path, node.lineno)

    def _call(self, module: Module, call: ast.Call) -> None:
        origin = self.origin(module, call.func)
        keywords = _keywords(call)
        read = self._environment_read(module, call)
        if read is not None:
            self._found.credential(read[0], module.path, call.lineno)
        self._models(module, call)
        if id(call) not in self._agents_by_call:
            for key in TOOL_KEYWORDS:
                if key in keywords:
                    self._tools(module, keywords[key], None)
        function = call.func
        if isinstance(function, ast.Attribute) and function.attr in TOOL_BINDERS and call.args:
            self._tools(module, call.args[0], None)
        for key in MCP_MAP_KEYWORDS:
            if key in keywords:
                self._server_map(module, keywords[key])
        self._approvals(module, call, keywords)
        if origin is None:
            return
        base = origin.split("()", 1)[0]
        _, symbol, _ = _split(base)
        if symbol in TOOL_NODES and call.args and "(" not in origin:
            self._tools(module, call.args[0], None)
        self._servers(module, call)
        self._guardrail_call(module, call, origin, keywords)
        self._store_call(module, call, origin, keywords)
        self._tool_wrapper(module, call, origin, None)
        self._option(module, call, origin, keywords)
        controls = _row(origin, OPTION_CONTROLS)
        if controls is not None:
            for key, kind in controls:
                if key in keywords:
                    self._found.guardrail(
                        module.path,
                        call.lineno,
                        key,
                        method=METHOD,
                        digest=module.digest,
                        guardrail_type=kind,
                        framework=base.split(".", 1)[0].replace("_", "-"),
                    )

    # -- models ------------------------------------------------------------------

    def _client_calls(self, module: Module, call: ast.Call) -> list[tuple[Module, ast.Call]]:
        """The call itself, the constructor of what it is called on, and clients given to it."""
        found: list[tuple[Module, ast.Call]] = [(module, call)]
        receiver: ast.AST = call.func
        while isinstance(receiver, ast.Attribute):
            receiver = receiver.value
        holders: list[ast.AST] = [receiver]
        keywords = _keywords(call)
        holders.extend(keywords[key] for key in CLIENT_KEYWORDS if key in keywords)
        for holder in holders:
            for value in self._follow(module, holder):
                if isinstance(value.node, ast.Call) and value.node is not call:
                    found.append((value.module, value.node))
                    nested = _keywords(value.node)
                    for key in CLIENT_KEYWORDS:
                        if key in nested:
                            found.extend(
                                (inner.module, inner.node)
                                for inner in self._follow(value.module, nested[key])
                                if isinstance(inner.node, ast.Call)
                            )
        return found[:MAX_CANDIDATES]

    def _client_settings(self, module: Module, call: ast.Call) -> tuple[str | None, list[str]]:
        """The endpoint a model call is sent to and the credential variables it is given."""
        endpoint: str | None = None
        credentials: list[str] = []
        for owner, client in self._client_calls(module, call):
            keywords = _keywords(client)
            for key in ENDPOINT_KEYWORDS:
                if endpoint is None and key in keywords:
                    for text, _ in self.strings(owner, keywords[key]):
                        endpoint = endpoint or endpoint_origin(text)
            for key in CREDENTIAL_KEYWORDS:
                if key in keywords:
                    for name in self._environment_names(owner, keywords[key]):
                        if credential_name(name) and name not in credentials:
                            credentials.append(name)
        return endpoint, credentials

    def _named_provider(self, module: Module, node: ast.AST) -> str | None:
        """The provider a ``provider=`` argument names; None when it cannot be read."""
        found: set[str | None] = set()
        for value in self._follow(module, node):
            current = value.node
            if isinstance(current, ast.Constant) and isinstance(current.value, str):
                found.add(SEGMENT_PROVIDERS.get(current.value.lower().replace("-", "_")))
            elif isinstance(current, ast.Call):
                origin = self.origin(value.module, current.func) or ""
                symbol = _split(origin.split("()", 1)[0])[1]
                found.add(
                    provider_of(origin)
                    or SEGMENT_PROVIDERS.get(symbol.removesuffix("Provider").lower())
                )
            else:
                found.add(None)
        return found.pop() if len(found) == 1 else None

    def _bedrock(self, module: Module, call: ast.Call) -> bool:
        for owner, client in self._client_calls(module, call):
            if not _under(self.origin(owner, client.func) or "", "boto3"):
                continue
            service = _constant(client.args[0]) if client.args else None
            service = service or _constant(_keywords(client).get("service_name"))
            if isinstance(service, str) and "bedrock" in service:
                return True
        return False

    def _models(self, module: Module, call: ast.Call) -> list[str]:
        """Record the model identifiers a call names; return their references."""
        cached = self._model_calls.get(id(call))
        if cached is not None:
            return cached
        refs: list[str] = []
        self._model_calls[id(call)] = refs
        origin = self.origin(module, call.func) or ""
        base = origin.split("()", 1)[0]
        _, symbol, _ = _split(base)
        keywords = _keywords(call)
        embedding = "embed" in origin.lower()
        found: list[tuple[ast.expr, bool]] = []
        for key in MODEL_KEYWORDS:
            if key not in keywords or (key == "repo_id" and symbol not in REPO_ID_CLASSES):
                continue
            found.append((keywords[key], embedding or key in EMBEDDING_KEYWORDS))
        if "llm" in keywords:
            found.append((keywords["llm"], False))
        position = _row(base, POSITIONAL_MODELS) if "(" not in origin else None
        if position is not None and len(call.args) > position and "model" not in keywords:
            found.append((call.args[position], embedding))
        if "id" in keywords and any(_under(base, root) for root in ("agno.models", "phi.model")):
            found.append((keywords["id"], False))
        if not found:
            return refs
        provider = provider_of(origin) if origin else None
        if "provider" in keywords:
            # A provider argument says where the call is sent, whatever the class is
            # named for: ``OpenAIChatModel(..., provider=DeepSeekProvider())``.
            provider = self._named_provider(module, keywords["provider"])
        if provider is None and self._bedrock(module, call):
            provider = "aws-bedrock"
        endpoint, credentials = self._client_settings(module, call)
        weights = bool(origin) and _loads_weights(origin)
        for expression, embeds in found:
            self._model_references(
                module,
                expression,
                refs,
                provider=provider,
                default_provider=framework_provider(origin) if origin else None,
                endpoint=endpoint,
                embedding=embeds,
                weights=weights,
                credentials=credentials,
            )
        return refs

    def _model_references(
        self,
        module: Module,
        expression: ast.AST,
        refs: list[str],
        *,
        provider: str | None,
        default_provider: str | None = None,
        endpoint: str | None = None,
        embedding: bool = False,
        weights: bool = False,
        credentials: list[str] | None = None,
        require_family: bool = False,
    ) -> None:
        values = self.strings(module, expression)
        line = getattr(expression, "lineno", 1)
        for text, variable in values:
            ref = self._found.model(
                text,
                module.path,
                line,
                method=METHOD,
                provider=provider,
                default_provider=default_provider,
                endpoint=endpoint,
                embedding=embedding,
                weights=weights,
                environment=variable,
                credentials=credentials or (),
                require_family=require_family,
            )
            if ref is not None and ref not in refs:
                refs.append(ref)
        if not values:
            for name in self._environment_names(module, expression)[:1]:
                if environment_name(name) and self._is_model_argument(module, expression):
                    self._found.unresolved_environment.setdefault(name, set()).add(
                        (module.path, line)
                    )

    def _is_model_argument(self, module: Module, expression: ast.AST) -> bool:
        """Whether an expression is an environment read and nothing else."""
        return any(
            self._environment_read(module, value.node) is not None
            for value in self._follow(module, expression)
        )

    def _model_objects(
        self, module: Module, node: ast.AST, default: str | None, depth: int = 0
    ) -> list[str]:
        """The model references an expression given as a model stands for.

        A model argument is an identifier, a client or model object whose constructor
        names one, such an object after ``bind_tools`` or a like method, or a
        configuration mapping that holds one. ``default`` is the service the
        framework sends a bare identifier to.
        """
        refs: list[str] = []
        if depth > MAX_DEPTH:
            return refs

        def add(found: list[str]) -> None:
            refs.extend(ref for ref in found if ref not in refs)

        for value in self._follow(module, node):
            current = value.node
            if isinstance(current, ast.Dict):
                for key, item in zip(current.keys, current.values, strict=True):
                    name = _constant(key)
                    if name in MODEL_DICT_KEYS:
                        self._model_references(
                            value.module, item, refs, provider=None, default_provider=default
                        )
                    elif name == "config_list":
                        add(self._model_objects(value.module, item, default, depth + 1))
            elif isinstance(current, (ast.List, ast.Tuple)):
                for element in current.elts[:MAX_CANDIDATES]:
                    add(self._model_objects(value.module, element, default, depth + 1))
            elif (
                isinstance(current, ast.Call)
                and self._environment_read(value.module, current) is None
            ):
                found = self._models(value.module, current)
                receiver = current.func
                if not found and isinstance(receiver, ast.Attribute):
                    found = self._model_objects(value.module, receiver.value, default, depth + 1)
                add(found)
            else:
                self._model_references(
                    value.module, current, refs, provider=None, default_provider=default
                )
        return refs

    def _named_constant(self, module: Module, node: ast.Assign | ast.AnnAssign) -> None:
        """A constant whose own name says it holds a model, when its value is of a known family."""
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if node.value is None or len(targets) != 1:
            return
        target = targets[0]
        name = target.id if isinstance(target, ast.Name) else None
        if isinstance(target, ast.Attribute):
            name = target.attr
        if name is None or _MODEL_CONSTANT.match(name) is None:
            return
        if isinstance(node.value, (ast.Call, ast.Name, ast.Attribute)) and not self.strings(
            module, node.value
        ):
            return
        self._model_references(
            module,
            node.value,
            [],
            provider=None,
            embedding="embed" in name.lower(),
            require_family=True,
        )

    def _dictionary(self, module: Module, node: ast.Dict) -> None:
        names = {
            key.value: value
            for key, value in zip(node.keys, node.values, strict=True)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        for key in MODEL_DICT_KEYS & names.keys():
            self._model_references(module, names[key], [], provider=None, require_family=True)
        for key in BEDROCK_GUARDRAIL_KEYS:
            if key in names:
                version = next(
                    (names[name] for name in BEDROCK_GUARDRAIL_VERSIONS if name in names), None
                )
                self._bedrock_guardrail(module, names[key], version)
        if _constant(names.get("type")) == "mcp" and "server_url" in names:
            self._hosted_server(module, node)

    def _option(
        self, module: Module, call: ast.Call, origin: str, keywords: dict[str, ast.expr]
    ) -> None:
        """A command-line option named for a model declares its default as one."""
        if not origin.endswith((".add_argument", "click.option", "typer.Option")):
            return
        flags = {_constant(argument) for argument in call.args}
        if not flags & CLI_MODEL_OPTIONS:
            return
        default = keywords.get("default")
        if default is None and origin.endswith("typer.Option") and call.args:
            default = call.args[0]
        if default is not None:
            self._model_references(module, default, [], provider=None, require_family=True)

    # -- tools -------------------------------------------------------------------

    def _decorators(
        self, module: Module, function: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[tuple[str, ast.expr]]:
        found: list[tuple[str, ast.expr]] = []
        for decorator in function.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            origin = self.origin(module, target)
            if origin is not None:
                found.append((origin, decorator))
        return found

    def _function_tool(
        self,
        module: Module,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        framework: str | None,
    ) -> str | None:
        """Record a function as a tool, under the name its decorator gives it, if any."""
        key = id(function)
        if key in self._function_tools:
            return self._function_tools[key]
        name: str | None = function.name
        for origin, decorator in self._decorators(module, function):
            declared = _row(origin, TOOL_DECORATORS)
            attribute = decorator.func if isinstance(decorator, ast.Call) else decorator
            registers = (
                isinstance(attribute, ast.Attribute) and attribute.attr in AGENT_TOOL_METHODS
            )
            if declared is None and not registers:
                continue
            framework = declared or framework
            if isinstance(decorator, ast.Call):
                options = _keywords(decorator)
                override = next(
                    (options[option] for option in TOOL_NAME_KEYWORDS if option in options), None
                )
                if override is None and decorator.args:
                    first = decorator.args[0]
                    override = first if isinstance(_constant(first), str) else None
                if override is not None:
                    name = declared_name(self._text(module, override))
        ref = None
        if name is None:
            self._found.gap(
                module.path, function.lineno, "tool declared with a name the collector cannot read"
            )
        else:
            ref = self._found.tool(
                module.path,
                function.lineno,
                name,
                method=METHOD,
                digest=module.digest,
                kind="function",
                framework=framework,
            )
        self._function_tools[key] = ref
        return ref

    def _function(self, module: Module, function: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for origin, decorator in self._decorators(module, function):
            if _row(origin, TOOL_DECORATORS) is not None:
                self._function_tool(module, function, None)
            kind = _row(origin, GUARDRAIL_DECORATORS)
            if kind is not None:
                self._guardrail_function(module, function, kind)
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and target.attr in AGENT_TOOL_METHODS:
                for value in self._follow(module, target.value):
                    owner = self._agents_by_call.get(id(value.node))
                    if owner is not None:
                        ref = self._function_tool(module, function, owner.framework)
                        if ref is not None:
                            owner.tools.add(ref)

    def _guardrail_function(
        self, module: Module, function: ast.FunctionDef | ast.AsyncFunctionDef, kind: str
    ) -> str | None:
        key = id(function)
        if key not in self._guardrail_functions:
            self._guardrail_functions[key] = self._found.guardrail(
                module.path,
                function.lineno,
                function.name,
                method=METHOD,
                digest=module.digest,
                guardrail_type=kind,
                framework="openai-agents",
            )
        return self._guardrail_functions[key]

    def _class_tool(
        self, module: Module, definition: ast.ClassDef, framework: str | None
    ) -> str | None:
        name: str | None = definition.name
        for statement in definition.body:
            targets: list[ast.expr] = []
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
            if any(isinstance(target, ast.Name) and target.id == "name" for target in targets):
                value = getattr(statement, "value", None)
                declared = declared_name(self._text(module, value))
                name = declared or name
        if name is None:
            return None
        return self._found.tool(
            module.path,
            definition.lineno,
            name,
            method=METHOD,
            digest=module.digest,
            kind="class",
            framework=framework,
        )

    def _tool_base(self, module: Module, definition: ast.ClassDef) -> str | None:
        for base in definition.bases:
            framework = _row(self.origin(module, base), TOOL_BASES)
            if framework is not None:
                return framework
        return None

    def _class_definition(self, module: Module, definition: ast.ClassDef) -> None:
        framework = self._tool_base(module, definition)
        if framework is not None:
            self._class_tool(module, definition, framework)
        bases = {(self.origin(module, base) or "").rsplit(".", 1)[-1] for base in definition.bases}
        if bases & SETTINGS_BASES:
            self._settings(module, definition)

    def _settings(self, module: Module, definition: ast.ClassDef) -> None:
        """A settings class reads each field from the environment variable of its name."""
        prefix = ""
        for statement in definition.body:
            holder: ast.AST = statement
            if isinstance(statement, ast.ClassDef) and statement.name == "Config":
                for inner in statement.body:
                    if isinstance(inner, ast.Assign) and any(
                        isinstance(target, ast.Name) and target.id == "env_prefix"
                        for target in inner.targets
                    ):
                        prefix = str(_constant(inner.value) or "")
            if isinstance(holder, ast.Assign) and isinstance(holder.value, ast.Call):
                configured = _constant(_keywords(holder.value).get("env_prefix"))
                if isinstance(configured, str):
                    prefix = configured
        for statement in definition.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                name = f"{prefix}{statement.target.id}".upper()
                self._found.credential(name, module.path, statement.lineno)

    def _tool_wrapper(
        self, module: Module, call: ast.Call, origin: str, agent: AgentRecord | None
    ) -> str | None:
        """A call that wraps a function, a class or a query engine as a named tool."""
        wrapper = _row(origin, TOOL_WRAPPERS)
        if wrapper is None:
            return None
        names, position = wrapper
        keywords = _keywords(call)
        target = next((keywords[name] for name in names if name in keywords), None)
        if target is None and position is not None and len(call.args) > position:
            target = call.args[position]
        name = declared_name(self._text(module, keywords.get("name")))
        metadata = keywords.get("metadata")
        if name is None and isinstance(metadata, ast.Call):
            name = declared_name(self._text(module, _keywords(metadata).get("name")))
        if name is None and target is not None:
            for value in self._follow(module, target):
                if isinstance(value.node, _DEFINITIONS):
                    name = value.node.name
        if name is None:
            return None
        return self._found.tool(
            module.path,
            call.lineno,
            name,
            method=METHOD,
            digest=module.digest,
            kind="function",
            framework=agent.framework if agent else origin.split(".", 1)[0].replace("_", "-"),
        )

    def _schema_tool(self, module: Module, node: ast.Dict) -> str | None:
        """A tool written as the JSON schema a model API takes."""
        names = {
            key.value: value
            for key, value in zip(node.keys, node.values, strict=True)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        kind = _constant(names.get("type"))
        if kind == "mcp" and "server_url" in names:
            return self._hosted_server(module, node)
        function = names.get("function")
        holder = names
        if isinstance(function, ast.Dict):
            holder = {
                key.value: value
                for key, value in zip(function.keys, function.values, strict=True)
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
        name = declared_name(self._text(module, holder.get("name")))
        schema = any(key in holder for key in ("parameters", "input_schema", "description"))
        if name is not None and (schema or isinstance(kind, str)):
            tool_kind = "schema" if schema or kind == "function" else "hosted"
            return self._found.tool(
                module.path, node.lineno, name, method=METHOD, digest=module.digest, kind=tool_kind
            )
        if isinstance(kind, str) and kind != "function" and declared_name(kind):
            for store in self._texts_of(module, names.get("vector_store_ids")):
                self._found.retrieval(
                    module.path,
                    node.lineno,
                    store,
                    method=METHOD,
                    digest=module.digest,
                    corpus_type="vector-store",
                    store="openai-vector-store",
                )
            return self._found.tool(
                module.path, node.lineno, kind, method=METHOD, digest=module.digest, kind="hosted"
            )
        return None

    def _texts_of(self, module: Module, node: ast.AST | None) -> list[str]:
        """The names a list of text values holds, each one exportable."""
        if node is None:
            return []
        found: list[str] = []
        for value in self._follow(module, node):
            elements = (
                value.node.elts if isinstance(value.node, (ast.List, ast.Tuple)) else [value.node]
            )
            for element in elements[:MAX_CANDIDATES]:
                name = declared_name(self._text(value.module, element))
                if name is not None and name not in found:
                    found.append(name)
        return found

    def _tools(
        self, module: Module, node: ast.AST, agent: AgentRecord | None, depth: int = 0
    ) -> set[str]:
        """Record what a tools argument holds; return the tool and server references."""
        refs: set[str] = set()
        if depth > MAX_DEPTH:
            return refs
        for value in self._follow(module, node):
            self._tool_value(value, refs, agent, depth)
        return refs

    def _tool_value(
        self, value: _Value, refs: set[str], agent: AgentRecord | None, depth: int
    ) -> None:
        module, node = value.module, value.node
        framework = agent.framework if agent else None
        ref: str | None = None
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for element in node.elts[:MAX_SERVER_ARGUMENTS]:
                refs |= self._tools(module, element, agent, depth + 1)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            refs |= self._tools(module, node.left, agent, depth + 1)
            refs |= self._tools(module, node.right, agent, depth + 1)
        elif isinstance(node, ast.Dict):
            ref = self._schema_tool(module, node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ref = self._function_tool(module, node, framework)
        elif isinstance(node, ast.ClassDef):
            ref = self._class_tool(module, node, self._tool_base(module, node) or framework)
        elif isinstance(node, ast.Call):
            ref = self._tool_call(module, node, refs, agent, depth)
        elif isinstance(node, (ast.Name, ast.Attribute)):
            origin = self.origin(module, node)
            if origin is not None and not origin.startswith(LOCAL) and "(" not in origin:
                ref = self._library_tool(module, node, origin, None, framework)
        elif isinstance(node, ast.Constant) and framework == "claude-agent-sdk":
            name = declared_name(node.value)
            if name is not None:
                ref = self._found.tool(
                    module.path,
                    node.lineno,
                    name,
                    method=METHOD,
                    digest=module.digest,
                    kind="builtin",
                    framework=framework,
                )
        if ref is not None:
            refs.add(ref)

    def _library_tool(
        self,
        module: Module,
        node: ast.AST,
        origin: str,
        named: ast.AST | None,
        framework: str | None,
    ) -> str | None:
        base = origin.split("()", 1)[0]
        _, symbol, _ = _split(base)
        name = declared_name(self._text(module, named)) or declared_name(symbol)
        if name is None:
            return None
        return self._found.tool(
            module.path,
            getattr(node, "lineno", 1),
            name,
            method=METHOD,
            digest=module.digest,
            kind="hosted" if symbol in HOSTED_TOOLS else "library",
            framework=framework,
            origin=base,
        )

    def _tool_call(
        self,
        module: Module,
        call: ast.Call,
        refs: set[str],
        agent: AgentRecord | None,
        depth: int,
    ) -> str | None:
        framework = agent.framework if agent else None
        declared = self._agents_by_call.get(id(call))
        if declared is not None:
            if agent is not None:
                agent.sub_agents.add(declared.ref)
            return None
        servers = self._servers(module, call)
        if servers:
            refs |= servers
            return None
        origin = self.origin(module, call.func)
        keywords = _keywords(call)
        function = call.func
        if isinstance(function, ast.Attribute) and function.attr != "as_tool":
            # Tools an MCP client object hands out are its servers' tools: the agent is
            # given the servers, and the client object itself is no tool.
            for holder in self._follow(module, function.value):
                if not isinstance(holder.node, ast.Call):
                    continue
                declared_servers = self._servers(holder.module, holder.node)
                held = self.origin(holder.module, holder.node.func) or ""
                if declared_servers or _split(held)[1] in _MCP_SYMBOLS:
                    refs |= declared_servers
                    return None
        if isinstance(function, ast.Attribute) and function.attr == "as_tool":
            owners = self._agent_refs(module, function.value)
            if agent is not None:
                agent.sub_agents |= owners
            name = declared_name(self._text(module, keywords.get("tool_name")))
            if name is None:
                return None
            return self._found.tool(
                module.path,
                call.lineno,
                name,
                method=METHOD,
                digest=module.digest,
                kind="agent",
                framework=framework,
            )
        if origin is None:
            return None
        wrapped = _row(origin, AGENT_WRAPPERS)
        if wrapped is not None:
            target = next((keywords[key] for key in wrapped if key in keywords), None)
            if target is None and call.args:
                target = call.args[0]
            if target is not None and agent is not None:
                agent.sub_agents |= self._agent_refs(module, target)
            return None
        ref = self._tool_wrapper(module, call, origin, agent)
        if ref is not None:
            return ref
        if origin.endswith(".load_tools") and call.args:
            for name in self._texts_of(module, call.args[0]):
                loaded = self._found.tool(
                    module.path,
                    call.lineno,
                    name,
                    method=METHOD,
                    digest=module.digest,
                    kind="library",
                    framework=framework,
                    origin=origin,
                )
                if loaded is not None:
                    refs.add(loaded)
            return None
        if origin.startswith(LOCAL):
            for target_value in self._follow(module, call.func):
                if isinstance(target_value.node, ast.ClassDef):
                    base = self._tool_base(target_value.module, target_value.node)
                    return self._class_tool(
                        target_value.module, target_value.node, base or framework
                    )
            return None
        for store in self._texts_of(module, keywords.get("vector_store_ids")):
            self._found.retrieval(
                module.path,
                call.lineno,
                store,
                method=METHOD,
                digest=module.digest,
                corpus_type="vector-store",
                store="openai-vector-store",
            )
        return self._library_tool(module, call, origin, keywords.get("name"), framework)

    # -- agents ------------------------------------------------------------------

    def _agent_refs(self, module: Module, node: ast.AST, depth: int = 0) -> set[str]:
        refs: set[str] = set()
        if depth > MAX_DEPTH:
            return refs
        for value in self._follow(module, node):
            current = value.node
            if isinstance(current, (ast.List, ast.Tuple, ast.Set)):
                for element in current.elts[:MAX_SERVER_ARGUMENTS]:
                    refs |= self._agent_refs(value.module, element, depth + 1)
            elif isinstance(current, ast.Dict):
                for element in current.values[:MAX_SERVER_ARGUMENTS]:
                    refs |= self._agent_refs(value.module, element, depth + 1)
            elif isinstance(current, ast.Call):
                record = self._agents_by_call.get(id(current))
                if record is not None:
                    refs.add(record.ref)
                    continue
                wrapped = _row(self.origin(value.module, current.func), AGENT_WRAPPERS)
                if wrapped is not None:
                    keywords = _keywords(current)
                    target = next((keywords[key] for key in wrapped if key in keywords), None)
                    if target is None and current.args:
                        target = current.args[0]
                    if target is not None:
                        refs |= self._agent_refs(value.module, target, depth + 1)
        return refs

    def _wire(self, module: Module, call: ast.Call, spec: AgentSpec, record: AgentRecord) -> None:
        """Follow the references an agent's constructor holds."""
        keywords = _keywords(call)
        origin = self.origin(module, call.func) or ""
        from_tools = origin.endswith(".from_tools")

        def arguments(names: tuple[str, ...], position: int | None) -> list[ast.expr]:
            found = [keywords[name] for name in names if name in keywords]
            if not found and position is not None and len(call.args) > position:
                found.append(call.args[position])
            return found

        for expression in arguments(spec.model, spec.model_position):
            record.models.update(self._model_objects(module, expression, spec.provider))
        tools_position = 0 if from_tools else spec.tools_position
        for expression in arguments(spec.tools, tools_position):
            for ref in self._tools(module, expression, record):
                record.tools.add(ref)
        for expression in arguments(spec.agents, None):
            record.sub_agents |= self._agent_refs(module, expression)
        for expression in arguments(spec.guardrails, None):
            record.guardrails |= self._guardrails(module, expression)
        for expression in arguments(spec.memory, None):
            record.memories |= self._stores(module, expression, memory=True)
        for expression in arguments(spec.data, None):
            record.data |= self._stores(module, expression, memory=False)
        if spec.framework == "claude-agent-sdk" and "tools" in keywords:
            record.tools |= self._tools(module, keywords["tools"], record)

    # -- MCP servers -------------------------------------------------------------

    def _server_text(self, module: Module, node: ast.AST) -> str:
        """A launch value as the MCP parser reads one: the text, or a placeholder."""
        text = self._text(module, node)
        if text is not None:
            return text
        names = self._environment_names(module, node)
        return f"${{{names[0]}}}" if names and environment_name(names[0]) else UNRESOLVED

    def _server_fields(
        self, module: Module, node: ast.Dict | ast.Call, config: dict[str, Any], depth: int
    ) -> None:
        """Read a launch declaration's literal fields into the form an MCP file has."""
        if depth > MAX_DEPTH:
            return
        if isinstance(node, ast.Dict):
            items = {
                key.value: value
                for key, value in zip(node.keys, node.values, strict=True)
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
        else:
            items = _keywords(node)
            self._mcp_calls.setdefault(id(node), set())
        for key in MCP_NESTED_KEYWORDS:
            if key in items:
                for value in self._follow(module, items[key]):
                    if isinstance(value.node, (ast.Dict, ast.Call)):
                        self._server_fields(value.module, value.node, config, depth + 1)
                        if isinstance(value.node, ast.Call):
                            self._server_symbol(value.module, value.node, config)
        for source, key in (("command", "command"), ("url", "url"), ("server_url", "url")):
            if source in items and key not in config:
                config[key] = self._server_text(module, items[source])
        for source in ("name", "server_label"):
            if source in items and "name" not in config:
                name = self._text(module, items[source])
                if name is not None:
                    config["name"] = name
        for source in ("transport", "type"):
            declared = _constant(items.get(source))
            if isinstance(declared, str) and "type" not in config:
                config["type"] = declared
        if "args" in items and "args" not in config:
            for value in self._follow(module, items["args"]):
                if isinstance(value.node, (ast.List, ast.Tuple)):
                    config["args"] = [
                        self._server_text(value.module, element)
                        for element in value.node.elts[:MAX_SERVER_ARGUMENTS]
                    ]
        for source in ("env", "headers"):
            if source in items and source not in config:
                for value in self._follow(module, items[source]):
                    if isinstance(value.node, ast.Dict):
                        config[source] = {
                            key.value: self._server_text(value.module, item)
                            for key, item in zip(value.node.keys, value.node.values, strict=True)
                            if isinstance(key, ast.Constant) and isinstance(key.value, str)
                        }

    def _server_symbol(self, module: Module, call: ast.Call, config: dict[str, Any]) -> str:
        origin = self.origin(module, call.func) or ""
        base = origin.split("()", 1)[0]
        _, symbol, method = _split(base)
        label = f"{symbol}.{method}" if method else symbol
        if label in MCP_SSE and "type" not in config:
            config["type"] = "sse"
        if call.args:
            first = call.args[0]
            if label in MCP_URL and "url" not in config:
                config["url"] = self._server_text(module, first)
            elif label in MCP_STDIO and "command" not in config:
                config["command"] = self._server_text(module, first)
                if len(call.args) > 1 and isinstance(call.args[1], (ast.List, ast.Tuple)):
                    config.setdefault(
                        "args",
                        [self._server_text(module, element) for element in call.args[1].elts],
                    )
        return label

    def _servers(self, module: Module, call: ast.Call) -> set[str]:
        """Record the MCP servers a call declares; return their references."""
        cached = self._mcp_calls.get(id(call))
        if cached is not None:
            return cached
        refs: set[str] = set()
        origin = self.origin(module, call.func)
        if origin is None or "(" in origin:
            return refs
        if not any(_under(origin, root) for root in MCP_ROOTS):
            return refs
        _, symbol, method = _split(origin)
        label = f"{symbol}.{method}" if method else symbol
        if label not in _MCP_SYMBOLS:
            return refs
        self._mcp_calls[id(call)] = refs
        if label in MCP_MAPS:
            if call.args:
                refs |= self._server_map(module, call.args[0])
            return refs
        config: dict[str, Any] = {}
        self._server_fields(module, call, config, 0)
        self._server_symbol(module, call, config)
        if not (config.get("command") or config.get("url")):
            for argument in [*call.args, *(_keywords(call).values())]:
                for owner, inner in self._inner_declarations(module, argument):
                    if isinstance(inner, ast.Call):
                        refs |= self._servers(owner, inner)
                        continue
                    literal: dict[str, Any] = {}
                    self._server_fields(owner, inner, literal, 0)
                    if literal.get("command") or literal.get("url"):
                        ref = self._declare_server(
                            owner, inner, literal, self._binding(module, call)
                        )
                        if ref is not None:
                            refs.add(ref)
            return refs
        if label == "MCPTools" and "args" not in config and " " in config.get("command", ""):
            try:
                words = shlex.split(config["command"])
            except ValueError:
                words = []
            if words:
                config["command"], config["args"] = words[0], words[1:]
        ref = self._declare_server(module, call, config, self._binding(module, call))
        if ref is not None:
            refs.add(ref)
        return refs

    def _inner_declarations(
        self, module: Module, node: ast.AST
    ) -> list[tuple[Module, ast.Call | ast.Dict]]:
        """The launch declarations an argument of a wrapping call holds."""
        found: list[tuple[Module, ast.Call | ast.Dict]] = []
        for value in self._follow(module, node):
            current = value.node
            if isinstance(current, ast.Lambda):
                current = current.body
            if isinstance(current, ast.Dict):
                found.append((value.module, current))
            elif isinstance(current, ast.Call):
                found.append((value.module, current))
                for argument in current.args[:4]:
                    for inner in self._follow(value.module, argument):
                        if isinstance(inner.node, ast.Call):
                            found.append((inner.module, inner.node))
        return found

    def _server_map(self, module: Module, node: ast.AST) -> set[str]:
        """Servers declared as a map from name to launch, or a list of named endpoints."""
        refs: set[str] = set()
        for value in self._follow(module, node):
            current = value.node
            entries: list[tuple[str | None, ast.AST]] = []
            if isinstance(current, ast.Dict):
                inner = {
                    key.value: item
                    for key, item in zip(current.keys, current.values, strict=True)
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                }
                if "mcpServers" in inner:
                    refs |= self._server_map(value.module, inner["mcpServers"])
                    continue
                entries = list(inner.items())
            elif isinstance(current, (ast.List, ast.Tuple)):
                entries = [(None, element) for element in current.elts]
            for name, entry in entries[:MAX_SERVER_ARGUMENTS]:
                for declared in self._follow(value.module, entry):
                    if isinstance(declared.node, ast.Call):
                        found = self._servers(declared.module, declared.node)
                        refs |= found
                        continue
                    if not isinstance(declared.node, ast.Dict):
                        continue
                    config: dict[str, Any] = {}
                    self._server_fields(declared.module, declared.node, config, 0)
                    if config.get("command") or config.get("url"):
                        if name is not None:
                            config["name"] = name
                        ref = self._declare_server(declared.module, declared.node, config, None)
                        if ref is not None:
                            refs.add(ref)
        return refs

    def _hosted_server(self, module: Module, node: ast.Dict) -> str | None:
        cached = self._mcp_calls.get(id(node))
        if cached is not None:
            return next(iter(cached), None)
        config: dict[str, Any] = {}
        self._server_fields(module, node, config, 0)
        config.pop("type", None)
        ref = self._declare_server(module, node, config, None)
        self._mcp_calls[id(node)] = {ref} if ref else set()
        return ref

    def _declare_server(
        self, module: Module, node: ast.AST, config: dict[str, Any], binding: str | None
    ) -> str | None:
        if config.get("command") == UNRESOLVED or config.get("url") == UNRESOLVED:
            self._found.gap(
                module.path,
                getattr(node, "lineno", 1),
                "MCP server declared with a launch the collector cannot read",
            )
            return None
        return self._found.declare_server(
            module.path, getattr(node, "lineno", 1), config, binding=binding, method=METHOD
        )

    # -- guardrails and stores ---------------------------------------------------

    def _guardrails(self, module: Module, node: ast.AST, depth: int = 0) -> set[str]:
        refs: set[str] = set()
        if depth > MAX_DEPTH:
            return refs
        for value in self._follow(module, node):
            current = value.node
            ref: str | None = None
            if isinstance(current, (ast.List, ast.Tuple, ast.Set)):
                for element in current.elts[:MAX_SERVER_ARGUMENTS]:
                    refs |= self._guardrails(value.module, element, depth + 1)
            elif isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                declared = "input-filter"
                for decorator, _ in self._decorators(value.module, current):
                    declared = _row(decorator, GUARDRAIL_DECORATORS) or declared
                ref = self._guardrail_function(value.module, current, declared)
            elif isinstance(current, ast.Call):
                origin = self.origin(value.module, current.func)
                kind = _row(origin, GUARDRAIL_WRAPPERS)
                keywords = _keywords(current)
                target = keywords.get("guardrail_function") or (
                    current.args[0] if current.args else None
                )
                if kind is not None and target is not None:
                    for function in self._follow(value.module, target):
                        if isinstance(function.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            ref = self._guardrail_function(function.module, function.node, kind)
                elif origin is not None:
                    ref = self._guardrail_call(value.module, current, origin, keywords)
            if ref is not None:
                refs.add(ref)
        return refs

    def _guardrail_call(
        self, module: Module, call: ast.Call, origin: str, keywords: dict[str, ast.expr]
    ) -> str | None:
        for key in BEDROCK_GUARDRAIL_KEYS:
            if key in keywords:
                version = next(
                    (keywords[name] for name in BEDROCK_GUARDRAIL_VERSIONS if name in keywords),
                    None,
                )
                self._bedrock_guardrail(module, keywords[key], version)
        if origin.endswith(("().use", "().use_many")) and _under(origin, "guardrails"):
            for argument in call.args:
                target = argument.func if isinstance(argument, ast.Call) else argument
                validator = self.origin(module, target)
                if validator is not None and _row(validator, GUARDRAIL_CALLS) is not None:
                    self._found.guardrail(
                        module.path,
                        argument.lineno,
                        validator.rsplit(".", 1)[-1],
                        method=METHOD,
                        digest=module.digest,
                        guardrail_type="validator",
                        framework="guardrails",
                    )
        row = _row(origin, GUARDRAIL_CALLS)
        if row is None:
            return None
        name, kind = row
        _, symbol, _ = _split(origin)
        return self._found.guardrail(
            module.path,
            call.lineno,
            name or symbol,
            method=METHOD,
            digest=module.digest,
            guardrail_type=kind,
            framework=origin.split(".", 1)[0].replace("_", "-"),
        )

    def _bedrock_guardrail(self, module: Module, node: ast.AST, version: ast.AST | None) -> None:
        name = declared_name(self._text(module, node))
        if name is not None:
            self._found.guardrail(
                module.path,
                getattr(node, "lineno", 1),
                name,
                method=METHOD,
                digest=module.digest,
                guardrail_type="policy",
                framework="aws-bedrock",
                version=self._text(module, version),
            )

    def _approvals(self, module: Module, call: ast.Call, keywords: dict[str, ast.expr]) -> None:
        for key, (kind, accepted) in APPROVAL_KEYWORDS.items():
            if key not in keywords:
                continue
            value = _constant(keywords[key])
            if accepted is not None and value not in accepted:
                continue
            if accepted is None and not isinstance(keywords[key], (ast.List, ast.Tuple, ast.Name)):
                continue
            self._found.guardrail(
                module.path,
                call.lineno,
                key,
                method=METHOD,
                digest=module.digest,
                guardrail_type=kind,
            )

    def _stores(self, module: Module, node: ast.AST, *, memory: bool, depth: int = 0) -> set[str]:
        refs: set[str] = set()
        if depth > MAX_DEPTH:
            return refs
        for value in self._follow(module, node):
            current = value.node
            if isinstance(current, (ast.List, ast.Tuple, ast.Set)):
                for element in current.elts[:MAX_SERVER_ARGUMENTS]:
                    refs |= self._stores(value.module, element, memory=memory, depth=depth + 1)
            elif isinstance(current, ast.Call):
                origin = self.origin(value.module, current.func)
                if origin is not None:
                    ref = self._store_call(value.module, current, origin, _keywords(current))
                    if ref is not None and ref.startswith("memory:") == memory:
                        refs.add(ref)
        return refs

    def _store_call(
        self, module: Module, call: ast.Call, origin: str, keywords: dict[str, ast.expr]
    ) -> str | None:
        base = origin.split("()", 1)[0]
        _, symbol, method = _split(base)
        direct = "(" not in origin
        trailing = origin.rsplit(".", 1)[-1]
        store = VECTOR_STORES.get(symbol) if direct else None
        if "(" in origin:
            for (root, opener), opened in STORE_METHODS.items():
                if trailing == opener and _under(base, root):
                    store = opened
        if store is not None:
            identity = next(
                (keywords[key] for key in STORE_IDENTITY_KEYWORDS if key in keywords), None
            )
            if identity is None and not direct and call.args:
                identity = call.args[0]
            named = declared_name(self._text(module, identity)) or store
            embedding = next(
                (keywords[key] for key in EMBEDDING_ARGUMENTS if key in keywords), None
            )
            if (
                embedding is None
                and method in {"from_documents", "from_texts"}
                and len(call.args) > 1
            ):
                embedding = call.args[1]
            models = [] if embedding is None else self._model_objects(module, embedding, None)
            return self._found.retrieval(
                module.path,
                call.lineno,
                named,
                method=METHOD,
                digest=module.digest,
                corpus_type="vector-store",
                store=store,
                embedding_model=models[0] if models else None,
            )
        if not direct:
            if origin.endswith(".fine_tuning.jobs.create") and "training_file" in keywords:
                name = declared_name(self._text(module, keywords["training_file"]))
                if name is not None:
                    return self._found.dataset(
                        module.path,
                        call.lineno,
                        name,
                        method=METHOD,
                        digest=module.digest,
                        dataset_type="fine-tuning",
                    )
            return None
        kind = MEMORY_STORES.get(symbol) or _row(base, MEMORY_BY_MODULE)
        if kind is not None and any(_under(base, root) for root in AI_ROOTS):
            return self._found.memory(
                module.path,
                call.lineno,
                symbol,
                method=METHOD,
                digest=module.digest,
                store_type=kind,
                framework=base.split(".", 1)[0].replace("_", "-"),
            )
        position = _row(base, DATASET_LOADERS)
        if position is not None and len(call.args) > position:
            name = declared_name(self._text(module, call.args[position]))
            if name is not None:
                return self._found.dataset(
                    module.path,
                    call.lineno,
                    name,
                    method=METHOD,
                    digest=module.digest,
                    loader=base,
                )
        loader = _row(base, DOCUMENT_LOADERS)
        if loader is None and symbol.endswith(DOCUMENT_LOADER_SUFFIXES):
            if any(_under(base, root) for root in DOCUMENT_LOADER_ROOTS):
                loader = DOCUMENT_PATH_KEYWORDS
        if loader is not None:
            source = next((keywords[key] for key in loader if key in keywords), None)
            if source is None and call.args:
                source = call.args[0]
            for text in self._document_sources(module, source):
                return self._found.retrieval(
                    module.path,
                    call.lineno,
                    text,
                    method=METHOD,
                    digest=module.digest,
                    corpus_type="documents",
                    store=symbol,
                )
        return None

    def _document_sources(self, module: Module, node: ast.AST | None) -> list[str]:
        if node is None:
            return []
        found: list[str] = []
        for value in self._follow(module, node):
            elements = (
                value.node.elts if isinstance(value.node, (ast.List, ast.Tuple)) else [value.node]
            )
            for element in elements[:MAX_CANDIDATES]:
                text = self._text(value.module, element)
                if text is None:
                    continue
                name = endpoint_origin(text) if "://" in text else declared_name(text)
                if name is not None and name not in found:
                    found.append(name)
        return found
