"""Read the model identifiers Python source gives an SDK, without importing or running it.

Only a file that imports a known SDK is analysed, and a project module named like one
is never taken for it. A model argument of a call into an SDK, or of a callee the
reader cannot name, is followed to a constant, an environment default, a formatted
string, a concatenation, text extended with ``+=`` or either side of a conditional:
through the names of its file and of the project modules it imports, the attributes of
``self``, of a module and of an object of a project class, the items of a literal
dictionary, and the values the project's own functions return. What a callee is comes
from the names, attributes and calls it is reached through, so a client made in the
file, a parameter annotated with an SDK class, a method handed to ``functools.partial``
and ``super()`` in a subclass of an SDK class are read; a call straight into another
library or a builtin is not. What the reader knows is there and cannot read, such as an
argument bound to a parameter, is a coverage gap, unless an SDK or another library
builds the object it holds, and so is a bound it reached. Each expression, and each
name in each scope, is worked out once, so the work is linear in the size of what is
read.
"""

from __future__ import annotations

import ast
import builtins
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TypeVar

from nexus_symbiote import limits
from nexus_symbiote.scanners.base import parse_python
from nexus_symbiote.scanners.source_python_tables import (
    AI_ROOTS,
    AI_SUBMODULES,
    CLASS_METHODS,
    EMBEDDING_KEYWORDS,
    ENVIRONMENT_READS,
    FORWARDERS,
    MODEL_KEYWORDS,
    POSITIONAL_MODELS,
    REPO_ID_CLASSES,
    TEXT_DEFAULTS,
    WEIGHT_CLASSES,
    WEIGHT_ROOTS,
)
from nexus_symbiote.scanners.source_references import (
    Declarations,
    environment_name,
    placeholder,
)

METHOD = "python-ast"
LOCAL = "<project>"
MAX_DEPTH = 12
# What a callee is, is followed this far: each step is one attribute, call or alias.
MAX_ORIGIN_DEPTH = 32
MAX_CANDIDATES = 16
MAX_STRINGS = 8
# No identifier is longer than 128 characters, so longer text is part of none.
MAX_TEXT = 256
MAX_STEPS = 2_000_000
# A dotted name longer than this is not followed: a short alias for a long name would
# otherwise cost the long name's length at every read.
MAX_ORIGIN = 256
# How far above the importing file, and how deep into a package, a module is looked for.
MAX_ANCESTORS = 32
MAX_PACKAGES = 8
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_SCOPES = (*_FUNCTIONS, ast.ClassDef, *_COMPREHENSIONS)
_DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_DISPLAYS: dict[type[ast.AST], str] = {
    ast.List: "list", ast.ListComp: "list", ast.Dict: "dict", ast.DictComp: "dict",
    ast.Set: "set", ast.SetComp: "set", ast.Tuple: "tuple", ast.JoinedStr: "str",
}  # fmt: skip
_TRANSFORMS: dict[str, Callable[[str], str]] = {
    "lower": str.lower, "strip": str.strip, "upper": str.upper,
}  # fmt: skip
_BUILTINS = frozenset(dir(builtins))
# Roots whose objects are not another library's: what they make may be text.
_NOT_LIBRARIES = frozenset({"builtins", *sys.stdlib_module_names})
_T = TypeVar("_T")
_K = TypeVar("_K")


@dataclass(eq=False)
class Module:
    """One parsed file: its imports, the scope of each node and what each scope binds."""

    path: str
    tree: ast.Module
    nodes: list[ast.AST] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)
    # The modules its import statements name, and the names they import from them.
    modules: set[str] = field(default_factory=set)
    members: set[str] = field(default_factory=set)
    scopes: dict[ast.AST, ast.AST | None] = field(default_factory=dict)
    # Names a scope declares ``global`` or ``nonlocal``, which bind in another scope.
    declared: dict[ast.AST | None, dict[str, str]] = field(default_factory=dict)
    bindings: dict[ast.AST | None, dict[str, list[ast.AST]]] = field(default_factory=dict)
    definitions: dict[ast.AST | None, dict[str, ast.AST]] = field(default_factory=dict)
    parameters: dict[ast.AST, dict[str, ast.arg]] = field(default_factory=dict)
    # What the methods of each class bind to an attribute of ``self`` or ``cls``.
    attributes: dict[ast.AST, dict[str, list[ast.AST]]] = field(default_factory=dict)


@dataclass(frozen=True, eq=False)
class _Value:
    module: Module
    node: ast.AST


_Scoped = tuple[int, str]


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


def _sdk(origin: str | None) -> bool:
    """Whether a callee whose origin is known is part of an SDK."""
    return origin is not None and _ai_import(origin.split("()", 1)[0])


def _library(origin: str | None) -> bool:
    """Whether an origin is another library's, outside the SDKs, the project and Python."""
    if origin is None or origin.startswith(LOCAL) or _sdk(origin):
        return False
    return not _python(origin)


def _python(origin: str | None) -> bool:
    """Whether an origin is a builtin's or the standard library's."""
    return origin is not None and origin.split(".", 1)[0].split("(", 1)[0] in _NOT_LIBRARIES


def _hops(node: ast.AST) -> int:
    """The attributes read on the way to a callee: one is a method, more a container."""
    count = 0
    while isinstance(node, ast.Attribute):
        node, count = node.value, count + 1
    return count


def _loads_weights(origin: str) -> bool:
    base = origin.split("()", 1)[0]
    _, symbol, _ = _split(base)
    return symbol in WEIGHT_CLASSES or any(_under(base, root) for root in WEIGHT_ROOTS)


def _scope_key(module: Module, scope: ast.AST | None, name: str) -> _Scoped:
    # A module's own scope is its tree, so the names of two modules never meet.
    return (id(module.tree if scope is None else scope), name)


class PythonReader:
    """Reads the Python files of one project into a ``Declarations``."""

    def __init__(
        self,
        declarations: Declarations,
        files: frozenset[str],
        load: Callable[[str], str | None] | None = None,
    ) -> None:
        """``files`` names every Python file of the project, read or not: a project
        module named like an SDK shadows it even when it is too large to read. ``load``
        gives the text of a module of the project that analysed code imports."""
        self._found = declarations
        self._files = files
        self._load_text = load
        self._texts: dict[str, str] = {}
        # Every module read, analysed or followed into, is kept for the whole scan.
        self._modules: dict[str, Module | None] = {}
        self._reasons: dict[str, str] = {}
        self._returns_of: dict[int, list[_Value]] = {}
        self._resolved: dict[tuple[str, str], str | None] = {}
        self._local: dict[tuple[str, str], bool] = {}
        # Kept for one file at a time, keyed by its syntax nodes.
        self._reads: dict[int, tuple[str, ast.expr | None] | None] = {}
        self._origins: dict[int, str | None] = {}
        self._named: dict[_Scoped, str | None] = {}
        self._scoped: dict[_Scoped, list[_Value] | None] = {}
        self._lookups: dict[_Scoped, tuple[_Scoped, list[_Value]] | None] = {}
        self._spelled: dict[int, list[tuple[str, str | None]]] = {}
        self._followed: dict[int, list[_Value]] = {}
        self._tables: dict[int, dict[object, list[ast.AST]]] = {}
        self._unread: set[tuple[int, int]] = set()
        self._given: set[tuple[int, int]] = set()
        self._steps = 0
        self._cut = False
        self._shallow = False

    # -- files -------------------------------------------------------------------

    def add(self, path: str, text: str) -> None:
        """Offer the text of one source file that imports an SDK."""
        self._texts[path] = text

    def read(self) -> None:
        """Analyse the offered files that import a known SDK, in path order."""
        for path in sorted(self._texts):
            self._cut = self._shallow = False
            module = self._module(path)
            if module is None:
                self._found.gap(path, 1, self._reasons[path])
                continue
            self._steps = self._allowance(module)
            if self._imports_sdk(module):
                self._analyse(module)
            elif self._steps > 0 and any(self._shadowed(name, module) for name in module.modules):
                self._found.gap(
                    path,
                    1,
                    "imports an SDK by a name that a module of the project also has; "
                    "not read as the SDK",
                )
            if self._cut or self._steps <= 0:
                self._found.gap(
                    path,
                    1,
                    "Python source binds more names or values than the collector follows; "
                    "some declarations were not read",
                )
            for table in (self._reads, self._origins, self._named, self._spelled):
                table.clear()
            self._returns_of.clear()
            self._followed.clear()
            self._tables.clear()
            self._scoped.clear()
            self._lookups.clear()

    @staticmethod
    def _allowance(module: Module) -> int:
        """The steps one pass over a file may take: linear in the file's size."""
        return min(MAX_STEPS, 10_000 + 50 * len(module.nodes))

    def _module(self, path: str) -> Module | None:
        """The parsed module at ``path``, read once whether it is analysed or followed into."""
        if path not in self._modules:
            text = self._texts.get(path)
            if text is None and self._load_text is not None:
                text = self._load_text(path)
            self._modules[path] = None if text is None else self._parse(path, text)
        return self._modules[path]

    def _parse(self, path: str, text: str) -> Module | None:
        try:
            tree = parse_python(text)
        except (SyntaxError, ValueError):
            self._reasons[path] = "Python source could not be parsed; not read"
            return None
        module = Module(path, tree)
        if not self._index(module):
            self._reasons[path] = (
                "Python source has more syntax nodes than the python-nodes limit; not read"
            )
            return None
        return module

    def _project_module(self, dotted: str, importer: Module) -> Module | None:
        path = self._project_file(dotted, importer.path.rpartition("/")[0])
        return None if path is None else self._module(path)

    def _index(self, module: Module) -> bool:
        bound = limits.current().python_nodes
        stack: list[tuple[ast.AST, ast.AST | None]] = [(module.tree, None)]
        while stack:
            node, scope = stack.pop()
            module.nodes.append(node)
            if len(module.nodes) > bound:
                return False
            module.scopes[node] = scope
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                kind = "global" if isinstance(node, ast.Global) else "nonlocal"
                module.declared.setdefault(scope, {}).update(dict.fromkeys(node.names, kind))
            inner = node if isinstance(node, _SCOPES) else scope
            stack.extend((child, inner) for child in reversed(list(ast.iter_child_nodes(node))))
        package = PurePosixPath(module.path).parent.parts
        for node in module.nodes:
            self._bind(module, node, package)
        return True

    def _bind(self, module: Module, node: ast.AST, package: tuple[str, ...]) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                module.modules.add(alias.name)
                self._bind_import(module, bound, alias.name if alias.asname else bound)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                kept = package[: len(package) - (node.level - 1)] if node.level > 1 else package
                base = ".".join([*kept, base] if base else kept)
            module.modules.add(base)
            for alias in node.names:
                if alias.name != "*":
                    name = f"{base}.{alias.name}" if base else alias.name
                    module.members.add(name)
                    self._bind_import(module, alias.asname or alias.name, name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                self._bind_target(module, target, node.value, node)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            if node.value is not None:
                self._bind_target(module, node.target, node.value, node)
        elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor, ast.comprehension)):
            self._bind_target(module, node.target, node, node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if isinstance(item.optional_vars, ast.Name):
                    self._bind_target(module, item.optional_vars, item.context_expr, node)
                elif item.optional_vars is not None:
                    self._bind_target(module, item.optional_vars, node, node)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            self._bind_name(module, node.name, node, module.scopes.get(node))
        elif isinstance(node, ast.MatchMapping) and node.rest:
            self._bind_name(module, node.rest, node, module.scopes.get(node))
        elif isinstance(node, _DEFINITIONS):
            module.definitions.setdefault(module.scopes.get(node), {})[node.name] = node
        if isinstance(node, _FUNCTIONS):
            arguments = node.args
            positional = [*arguments.posonlyargs, *arguments.args]
            named = module.parameters.setdefault(node, {})
            for argument in (*positional, *arguments.kwonlyargs):
                named[argument.arg] = argument
            for argument, default in zip(
                positional[len(positional) - len(arguments.defaults) :],
                arguments.defaults,
                strict=True,
            ):
                self._bind_name(module, argument.arg, default, node)
            for argument, optional in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
                if optional is not None:
                    self._bind_name(module, argument.arg, optional, node)

    def _bind_import(self, module: Module, bound: str, dotted: str) -> None:
        if len(dotted) <= MAX_ORIGIN:
            module.imports[bound] = dotted
        else:
            # Bound to nothing the reader follows, and not left as a name of the file.
            module.imports.pop(bound, None)
            self._cut = True

    def _bind_name(self, module: Module, name: str, value: ast.AST, scope: ast.AST | None) -> None:
        kind = module.declared.get(scope, {}).get(name)
        if kind == "global":
            scope = None
        elif kind == "nonlocal":
            scope = module.scopes.get(scope) if scope is not None else None
            while scope is not None and not isinstance(scope, _FUNCTIONS):
                scope = module.scopes.get(scope)
        module.bindings.setdefault(scope, {}).setdefault(name, []).append(value)

    def _bind_target(
        self, module: Module, target: ast.expr, value: ast.AST, statement: ast.AST
    ) -> None:
        """Bind the names of ``target``; one the reader cannot pair with a value is opaque."""
        if isinstance(target, ast.Name):
            scope = module.scopes.get(statement)
            if isinstance(statement, ast.NamedExpr):
                # An assignment expression in a comprehension binds in the scope around it.
                while isinstance(scope, _COMPREHENSIONS):
                    scope = module.scopes.get(scope)
            self._bind_name(module, target.id, value, scope)
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in ("self", "cls")
        ):
            owner = self._owner(module, target)
            if owner is not None:
                module.attributes.setdefault(owner, {}).setdefault(target.attr, []).append(value)
        elif isinstance(target, ast.Starred):
            self._bind_target(module, target.value, statement, statement)
        elif isinstance(target, (ast.Tuple, ast.List)):
            parts = value.elts if isinstance(value, (ast.Tuple, ast.List)) else None
            if (
                parts is None
                or len(parts) != len(target.elts)
                or any(isinstance(part, ast.Starred) for part in (*target.elts, *parts))
            ):
                parts = None
            for index, element in enumerate(target.elts):
                self._bind_target(
                    module, element, statement if parts is None else parts[index], statement
                )

    def _imports_sdk(self, module: Module) -> bool:
        return any(
            _ai_import(dotted) and not self._in_project(dotted, module)
            for dotted in (*module.modules, *module.members)
        )

    def _shadowed(self, dotted: str, module: Module) -> bool:
        """Whether an import of an SDK's name may load a project module instead.

        A module of the project at an import root shares the SDK's name. A deeper path
        that resolves only in the project, as ``agents.researcher`` may, is the project's.
        """
        directory = module.path.rpartition("/")[0]
        top = dotted.split(".", 1)[0]
        return (
            _ai_import(dotted)
            and self._project_file(top, directory) is not None
            and (dotted == top or self._project_file(dotted, directory) is None)
        )

    def _in_project(self, dotted: str, importer: Module) -> bool:
        """Whether a dotted name, or a package it lies in, is a module of the project."""
        directory = importer.path.rpartition("/")[0]
        key = (dotted, directory)
        known = self._local.get(key)
        if known is None:
            parts = dotted.split(".", MAX_PACKAGES)
            if len(parts) > MAX_PACKAGES:
                self._cut = True
            parts = parts[:MAX_PACKAGES]
            known = self._local[key] = any(
                self._project_file(".".join(parts[:count]), directory) is not None
                for count in range(len(parts), 0, -1)
            )
        return known

    def _project_file(self, dotted: str, directory: str) -> str | None:
        """The project file a dotted module name resolves to from ``directory``, if any:
        beside the importer, in each directory above it nearest first, at the root and
        in the usual source directories. A directory inside a package is no import root.
        Each place looked in is a step of the file's allowance."""
        key = (dotted, directory)
        if key in self._resolved:
            return self._resolved[key]
        relative = dotted.replace(".", "/")
        bases: list[str] = []
        searched = 0
        while directory and searched < MAX_ANCESTORS:
            searched += 1
            if f"{directory}/__init__.py" not in self._files:
                bases.append(directory + "/")
            directory = directory.rpartition("/")[0]
        if directory:
            self._cut = True
        bases.append("")
        bases.extend(
            root for root in ("src/", "lib/", "app/") if f"{root}__init__.py" not in self._files
        )
        self._steps -= len(bases)
        found: str | None = None
        for base in bases:
            for candidate in (f"{base}{relative}.py", f"{base}{relative}/__init__.py"):
                if found is None and candidate in self._files:
                    found = candidate
        self._resolved[key] = found
        return found

    # -- names -------------------------------------------------------------------

    def _once(self, table: dict[_K, _T], key: _K, pending: _T, work: Callable[[], _T]) -> _T:
        """``work()``, kept in ``table`` unless a depth bound cut it short, in which case
        the same work started nearer the top may get further. ``pending`` stands for the
        result while it is worked out, so work that comes back to the key ends there."""
        if key in table:
            return table[key]
        table[key] = pending
        outer, self._shallow = self._shallow, False
        found = work()
        if self._shallow:
            del table[key]
        else:
            table[key] = found
        self._shallow = self._shallow or outer
        return found

    def _in_scope(self, module: Module, scope: ast.AST | None, name: str) -> list[_Value] | None:
        key = _scope_key(module, scope, name)
        if key not in self._scoped:
            found = [
                _Value(module, value) for value in module.bindings.get(scope, {}).get(name, ())
            ]
            definition = module.definitions.get(scope, {}).get(name)
            if definition is not None:
                found.append(_Value(module, definition))
            parameter = None if scope is None else module.parameters.get(scope, {}).get(name)
            if parameter is not None:
                # A caller may pass any value, whatever the default and the body bind.
                found.append(_Value(module, parameter))
            self._scoped[key] = found or None
        return self._scoped[key]

    def _resolve(
        self, module: Module, name: str, at: ast.AST
    ) -> tuple[_Scoped, list[_Value]] | None:
        """The scope that binds ``name`` where ``at`` reads it, and what it binds there."""
        scope = module.scopes.get(at)
        key = _scope_key(module, scope, name)
        if key not in self._lookups:
            found = None
            nearest = True
            while True:
                self._steps -= 1
                if scope is None or nearest or not isinstance(scope, ast.ClassDef):
                    values = self._in_scope(module, scope, name)
                    if values is not None:
                        found = (_scope_key(module, scope, name), values)
                        break
                if scope is None:
                    break
                nearest, scope = False, module.scopes.get(scope)
            self._lookups[key] = found
        return self._lookups[key]

    def _follow(self, module: Module, node: ast.AST, depth: int = 0) -> list[_Value]:
        """The expressions ``node`` stands for, each one the reader can follow no further.

        Worked out once for each node, so following an attribute or a call, which follows
        what it is read from, costs no more than the file; a node followed again while it
        is being followed stands for nothing more.
        """

        def work() -> list[_Value]:
            found: list[_Value] = []
            self._follow_into(_Value(module, node), found, set(), depth)
            return found

        return self._once(self._followed, id(node), [], work)

    def _follow_into(self, value: _Value, out: list[_Value], seen: set[int], depth: int) -> None:
        module, node = value.module, value.node
        if id(node) in seen:
            return
        seen.add(id(node))
        self._steps -= 1
        if depth > MAX_DEPTH or self._steps <= 0:
            self._shallow = self._cut = True
            out.append(value)
            return
        found: Iterable[_Value] | None = None
        unknown = False
        if isinstance(node, ast.Name):
            resolved = self._resolve(module, node.id, node)
            found = self._imported(module, node.id) if resolved is None else resolved[1]
        elif isinstance(node, ast.Attribute):
            found = self._attribute(module, node, depth)
        elif isinstance(node, (ast.Subscript, ast.Call)) and not self._environment_read(
            module, node
        ):
            found, unknown = self._derived(module, node, depth)
        elif isinstance(node, (ast.Await, ast.NamedExpr, ast.Starred)):
            found = [_Value(module, node.value)]
        elif isinstance(node, ast.IfExp):
            found = [_Value(module, node.body), _Value(module, node.orelse)]
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            # Made as they are walked, so a wide expression costs its bound, not its width.
            found = (_Value(module, operand) for operand in node.values)
        if found is None or unknown:
            # What the reader cannot give stands for itself, beside what it can.
            out.append(value)
        if found is None:
            return
        for index, inner in enumerate(found):
            if len(out) >= MAX_CANDIDATES or index > MAX_CANDIDATES:
                # What is left is not walked: a wide expression or a name bound many
                # times, read at many places, would otherwise cost its width at each.
                self._cut = True
                return
            self._follow_into(inner, out, seen, depth + 1)

    def _imported(self, module: Module, name: str, depth: int = 0) -> list[_Value] | None:
        """What a name imported from another module of the project is bound to there."""
        dotted = module.imports.get(name)
        if dotted is None or depth > MAX_DEPTH or not self._in_project(dotted, module):
            return None
        head, _, symbol = dotted.rpartition(".")
        other = self._project_module(head, module) if head else None
        if other is None:
            return None
        self._steps -= 1
        return self._in_scope(other, None, symbol) or self._imported(other, symbol, depth + 1)

    def _owner(self, module: Module, node: ast.AST) -> ast.AST | None:
        """The class whose method, or a function within one, reads or binds ``node``."""
        scope = module.scopes.get(node)
        method = False
        while scope is not None:
            if isinstance(scope, ast.ClassDef) and method:
                return scope
            method = method or isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            scope = module.scopes.get(scope)
        return None

    def _members(self, module: Module, owner: ast.AST, name: str) -> list[_Value] | None:
        found = [_Value(module, value) for value in module.attributes.get(owner, {}).get(name, ())]
        found.extend(self._in_scope(module, owner, name) or ())
        return found or None

    def _attribute(self, module: Module, node: ast.Attribute, depth: int) -> list[_Value] | None:
        """What an attribute of ``self``, of a project module or of an object is bound to."""
        base = node.value
        if isinstance(base, ast.Name) and base.id in ("self", "cls"):
            owner = self._owner(module, node)
            return None if owner is None else self._members(module, owner, node.attr)
        if isinstance(base, ast.Name) and self._resolve(module, base.id, base) is None:
            dotted = module.imports.get(base.id)
            other = None if dotted is None else self._project_module(dotted, module)
            if other is None:
                return None
            return self._in_scope(other, None, node.attr) or self._imported(other, node.attr)
        if not (self.origin(module, base, depth + 1) or "").startswith(LOCAL):
            # Only an object the project defines has attributes the reader can find.
            return None
        found: list[_Value] = []
        for holder in self._follow(module, base, depth + 1):
            made = self._class_of(holder, depth)
            members = None if made is None else self._members(made.module, made.node, node.attr)
            if members is None:
                # One object the reader cannot tell the class of may hold anything.
                return None
            found.extend(members)
        return found or None

    def _class_of(self, value: _Value, depth: int) -> _Value | None:
        """The project class ``value`` is, or makes an object of, or is annotated with."""
        node = value.node
        if isinstance(node, ast.ClassDef):
            return value
        target = node.func if isinstance(node, ast.Call) else None
        if isinstance(node, ast.arg):
            target = node.annotation
        if target is None:
            return None
        classes = [
            found
            for found in self._follow(value.module, target, depth + 1)
            if isinstance(found.node, ast.ClassDef)
        ]
        return classes[0] if len(classes) == 1 else None

    def _derived(
        self, module: Module, node: ast.Subscript | ast.Call, depth: int
    ) -> tuple[list[_Value] | None, bool]:
        """What an item of a literal dictionary, or a call of a project function, gives.

        The flag says the expression may also stand for a value the reader cannot give:
        an item of what is not a literal dictionary, or a call of what it cannot read.
        """
        if isinstance(node, ast.Subscript):
            return self._items(module, node.value, _constant(node.slice), None, depth)
        function = node.func
        if isinstance(function, ast.Attribute) and function.attr == "get" and node.args:
            default = node.args[1] if len(node.args) > 1 else _keywords(node).get("default")
            if default is None:
                default = ast.Constant(None)
            key = _constant(node.args[0])
            return self._items(module, function.value, key, default, depth)
        if not (self.origin(module, function, depth + 1) or "").startswith(LOCAL):
            # Only a function the project defines returns what the reader can read.
            return None, True
        found: list[_Value] = []
        unknown = False
        for target in self._follow(module, function, depth + 1):
            if isinstance(target.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.extend(self._returned(target))
            elif isinstance(target.node, ast.Lambda):
                found.append(_Value(target.module, target.node.body))
            else:
                unknown = True
        return found or None, unknown

    def _items(
        self, module: Module, holder: ast.AST, key: object, default: ast.AST | None, depth: int
    ) -> tuple[list[_Value] | None, bool]:
        """What the literal dictionaries ``holder`` stands for hold under ``key``."""
        found: list[_Value] = []
        unknown = False
        fallback = [] if default is None else [_Value(module, default)]
        for value in self._follow(module, holder, depth + 1):
            table = value.node
            if not isinstance(key, str) or not isinstance(table, ast.Dict):
                unknown = True
                found.extend(fallback)
                continue
            entries = self._tables.get(id(table))
            if entries is None:
                # Indexed once, so reading many keys costs the dictionary's size once.
                entries = self._tables[id(table)] = {}
                for name, item in zip(table.keys, table.values, strict=True):
                    self._steps -= 1
                    entries.setdefault(_constant(name), []).append(item)
            items = [_Value(value.module, item) for item in entries.get(key, ())]
            # An entry it unpacks may hold the key too, or replace it.
            unknown = unknown or None in entries
            found.extend(items or fallback)
        return found or None, unknown

    def _returned(self, function: _Value) -> list[_Value]:
        """The expressions a function of the project returns, collected once."""
        key = id(function.node)
        if key not in self._returns_of:
            found: list[_Value] = []
            stack: list[ast.AST] = list(getattr(function.node, "body", ()))
            while stack:
                node = stack.pop()
                self._steps -= 1
                if isinstance(node, ast.Return) and node.value is not None:
                    found.append(_Value(function.module, node.value))
                if not isinstance(node, _SCOPES):
                    stack.extend(ast.iter_child_nodes(node))
            self._returns_of[key] = found
        return self._returns_of[key]

    def _single_origin(
        self, values: Iterable[_Value], depth: int, also: str | None = None
    ) -> str | None:
        # A binding to None says nothing about what the name calls.
        origins = {
            self._value_origin(value, depth + 1)
            for value in values
            if not (isinstance(value.node, ast.Constant) and value.node.value is None)
        }
        if also is not None:
            origins.add(also)
        return origins.pop() if len(origins) == 1 else None

    def origin(self, module: Module, node: ast.AST, depth: int = 0) -> str | None:
        """The dotted name of what ``node`` calls or names: ``openai.OpenAI().chat``."""
        key = id(node)
        if key in self._origins:
            return self._origins[key]
        if depth > MAX_ORIGIN_DEPTH or self._steps <= 0:
            self._shallow = self._cut = True
            return None
        self._steps -= 1

        def work() -> str | None:
            found = self._origin(module, node, depth)
            if found is not None and len(found) > MAX_ORIGIN:
                self._cut = True
                return None
            return found

        return self._once(self._origins, key, None, work)

    def _origin(self, module: Module, node: ast.AST, depth: int) -> str | None:
        if isinstance(node, ast.Name):
            return self._name_origin(module, node, depth)
        if isinstance(node, ast.Attribute):
            base = self.origin(module, node.value, depth + 1)
            own = isinstance(node.value, ast.Name) and node.value.id in ("self", "cls")
            if (base is None and own) or (base is not None and base.startswith(LOCAL)):
                members = self._attribute(module, node, depth)
                found = None if members is None else self._single_origin(members, depth)
                if found is not None:
                    return found
            return None if base is None else f"{base}.{node.attr}"
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name) and function.id == "super":
                owner = self._owner(module, node)
                if self._resolve(module, "super", function) is None and owner is not None:
                    # ``super()`` in a subclass is an object of the class it derives from.
                    bases = getattr(owner, "bases", ())
                    base = self.origin(module, bases[0], depth + 1) if bases else None
                    return None if base is None else f"{base}()"
            base = self.origin(module, function, depth + 1)
            if base is not None and base.startswith(LOCAL):
                # A project function that returns an SDK's object is that object.
                returned, unknown = self._derived(module, node, depth)
                found = None if not returned or unknown else self._single_origin(returned, depth)
                if found is not None:
                    return found
            return None if base is None else f"{base}()"
        if isinstance(node, ast.Await):
            return self.origin(module, node.value, depth + 1)
        if isinstance(node, ast.Constant):
            return None if node.value is None else f"builtins.{type(node.value).__name__}()"
        kind = _DISPLAYS.get(type(node))
        return None if kind is None else f"builtins.{kind}()"

    def _name_origin(self, module: Module, node: ast.Name, depth: int) -> str | None:
        resolved = self._resolve(module, node.id, node)
        if resolved is None:
            imported = self._imported(module, node.id)
            if imported is not None:
                return self._single_origin(imported, depth)
            found = self._import_origin(module, node.id)
            if found is None and node.id in _BUILTINS:
                return f"builtins.{node.id}"
            return found
        key, values = resolved
        # A module that binds an imported name too, as an optional import's fallback does,
        # may still hold what it imported.
        also = (
            self._import_origin(module, node.id)
            if key == _scope_key(module, None, node.id)
            else None
        )
        return self._once(self._named, key, None, lambda: self._single_origin(values, depth, also))

    def _import_origin(self, module: Module, name: str) -> str | None:
        """The dotted name an imported name stands for; a module of the project is marked."""
        dotted = module.imports.get(name)
        if dotted is None:
            return None
        return f"{LOCAL}.{dotted}" if self._in_project(dotted, module) else dotted

    def _value_origin(self, value: _Value, depth: int) -> str | None:
        node = value.node
        if isinstance(node, (*_DEFINITIONS, ast.Lambda)):
            return f"{LOCAL}.{getattr(node, 'name', '<lambda>')}"
        if isinstance(node, ast.arg):
            if node.annotation is None or isinstance(node.annotation, ast.Constant):
                return None
            base = self.origin(value.module, node.annotation, depth + 1)
            return None if base is None else f"{base}()"
        if isinstance(node, ast.expr):
            return self.origin(value.module, node, depth + 1)
        return None

    # -- values ------------------------------------------------------------------

    def _environment_read(
        self, module: Module, node: ast.AST
    ) -> tuple[str, ast.expr | None] | None:
        """The variable an expression reads from the environment, and its default."""
        key = id(node)
        if key not in self._reads:
            self._reads[key] = self._environment_read_of(module, node)
        return self._reads[key]

    def _environment_read_of(
        self, module: Module, node: ast.AST
    ) -> tuple[str, ast.expr | None] | None:
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
        unique: dict[tuple[str, str | None], None] = {}
        for value in self._follow(module, node, depth):
            for item in self._text(value, depth):
                unique[item] = None
                if len(unique) > MAX_STRINGS:
                    self._cut = True
                    return list(unique)[:MAX_STRINGS]
        return list(unique)

    def _text(self, value: _Value, depth: int) -> list[tuple[str, str | None]]:
        """The text one expression spells, read once however many names stand for it, so
        a name used twice in a concatenation costs one reading, not two. An expression
        read again while it is being read, as text built from itself is, spells no more."""

        def work() -> list[tuple[str, str | None]]:
            found: list[tuple[str, str | None]] = []
            self._strings(value, found, depth)
            return found

        return self._once(self._spelled, id(value.node), [], work)

    def _strings(self, value: _Value, out: list[tuple[str, str | None]], depth: int) -> None:
        module, node = value.module, value.node
        self._steps -= 1
        if depth > MAX_DEPTH or self._steps <= 0:
            self._shallow = self._cut = True
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
                if isinstance(part, ast.FormattedValue):
                    if part.conversion != -1 or part.format_spec is not None:
                        return
                    part = part.value
                parts.append(part)
        elif isinstance(node, (ast.BinOp, ast.AugAssign)) and isinstance(node.op, ast.Add):
            parts = (
                [node.left, node.right]
                if isinstance(node, ast.BinOp)
                else [node.target, node.value]
            )
        elif isinstance(node, ast.Call):
            self._call_text(module, node, out, depth)
            return
        if not parts:
            return
        built: list[tuple[str, str | None]] = [("", None)]
        for piece in parts:
            options = self.strings(module, piece, depth + 1)
            if not options or not built:
                return
            # Joined text is bounded: a name joined to itself would otherwise double
            # at every binding it passes through.
            joined = [
                (text + more, variable or other)
                for text, variable in built
                for more, other in options
                if len(text) + len(more) <= MAX_TEXT
            ]
            self._cut = self._cut or len(joined) > MAX_STRINGS
            built = joined[:MAX_STRINGS]
        out.extend(built)

    def _call_text(
        self, module: Module, node: ast.Call, out: list[tuple[str, str | None]], depth: int
    ) -> None:
        """The text a call gives back: a string method, or a field's or ``str``'s default."""
        function = node.func
        if isinstance(function, ast.Attribute) and function.attr in _TRANSFORMS:
            if not node.args and not node.keywords:
                change = _TRANSFORMS[function.attr]
                values = self.strings(module, function.value, depth + 1)
                out.extend((change(text), variable) for text, variable in values)
            return
        positional = TEXT_DEFAULTS.get(self.origin(module, function) or "")
        if positional is None:
            return
        default = _keywords(node).get("default")
        if default is None and positional and node.args:
            default = node.args[0]
        if default is not None:
            out.extend(self.strings(module, default, depth + 1))

    # -- models ------------------------------------------------------------------

    def _analyse(self, module: Module) -> None:
        for node in module.nodes:
            if isinstance(node, ast.Call):
                self._models(module, node)
        self._summarise(
            module, self._unread, "bound to a value the collector cannot read as a model"
        )
        self._summarise(
            module, self._given, "given to a callee the project defines, which is not followed"
        )

    def _summarise(self, module: Module, points: set[tuple[int, int]], what: str) -> None:
        if points:
            many = len(points)
            subject = "a model argument is" if many == 1 else f"{many} model arguments are"
            self._found.gap(module.path, min(points)[0], f"{subject} {what}; not inventoried")
            points.clear()

    def _project_callee(self, module: Module, function: ast.expr, origin: str | None) -> bool:
        """Whether a callee is a function or class the project defines, or a method of an
        object of a project class. What a project function returns may be an SDK's client,
        so a method of it is not: by convention a class is named in capitals."""
        if origin is None or not origin.startswith(LOCAL):
            return False
        made = origin[len(LOCAL) + 1 :].split("()", 1)
        if len(made) > 1:
            return made[0].rsplit(".", 1)[-1][:1].isupper()
        if isinstance(function, ast.Name) or "." not in made[0]:
            # A name, or a definition an attribute was followed to.
            return True
        base = function.value if isinstance(function, ast.Attribute) else None
        dotted = module.imports.get(base.id) if isinstance(base, ast.Name) else None
        directory = module.path.rpartition("/")[0]
        return dotted is not None and self._project_file(dotted, directory) is not None

    def _models(self, module: Module, call: ast.Call) -> None:
        """Record the literal model identifiers a call into an SDK, or an unknown callee, gives."""
        function, arguments = call.func, list(call.args)
        origin = self.origin(module, function)
        if origin in FORWARDERS and arguments:
            # ``partial(create, model=...)`` gives ``create`` what it is given.
            function, arguments = arguments[0], arguments[1:]
            origin = self.origin(module, function)
        local = self._project_callee(module, function, origin)
        if (_library(origin) or _python(origin)) and _hops(function) <= 1:
            # A function of another library or of Python, or a method of what one
            # returns: no model is given. A longer path may reach any object.
            return
        base = "" if origin is None else origin.split("()", 1)[0]
        _, symbol, _ = _split(base)
        keywords = _keywords(call)
        embedding = "embed" in (origin or "").lower()
        found: list[tuple[ast.expr, bool]] = []
        for key in MODEL_KEYWORDS:
            if key in keywords and (key != "repo_id" or symbol in REPO_ID_CLASSES):
                found.append((keywords[key], embedding or key in EMBEDDING_KEYWORDS))
        position = (
            _row(base, POSITIONAL_MODELS) if origin is not None and "(" not in origin else None
        )
        unread: list[ast.expr] = []
        if position is not None and len(arguments) > position and "model" not in keywords:
            if any(isinstance(argument, ast.Starred) for argument in arguments[: position + 1]):
                unread.append(arguments[0])
            else:
                found.append((arguments[position], embedding))
        if "id" in keywords and any(_under(base, root) for root in ("agno.models", "phi.model")):
            found.append((keywords["id"], False))
        if not any(key in keywords for key in MODEL_KEYWORDS):
            # What ``**options`` holds may be the model.
            unread.extend(keyword.value for keyword in call.keywords if keyword.arg is None)
        if local:
            self._given.update((value.lineno, value.col_offset) for value, _ in found)
            return
        self._unread.update((value.lineno, value.col_offset) for value in unread)
        weights = origin is not None and _loads_weights(origin)
        remote = weights and _constant(keywords.get("trust_remote_code")) is True
        for expression, embeds in found:
            self._model_references(
                module, expression, embedding=embeds, weights=weights, remote=remote
            )

    def _model_references(
        self,
        module: Module,
        expression: ast.expr,
        *,
        embedding: bool,
        weights: bool,
        remote: bool,
    ) -> None:
        """Record each identifier a model argument can hold, and count what it holds besides."""
        point = (expression.lineno, expression.col_offset)
        values = self._follow(module, expression)
        if not values:
            # A name bound only to itself stands for nothing the reader can give.
            self._unread.add(point)
        kept = 0
        for value in values:
            texts = self._text(value, 0)
            for text, variable in texts:
                kept += 1
                self._steps -= 1
                if kept > MAX_CANDIDATES:
                    self._cut = True
                    return
                ref = self._found.model(
                    text,
                    module.path,
                    point[0],
                    method=METHOD,
                    embedding=embedding,
                    weights=weights,
                    environment=variable,
                    remote_code=remote,
                )
                if ref is None and not placeholder(text):
                    self._unread.add(point)
            if not texts:
                self._unread_value(module, value, point)

    def _built(self, module: Module, node: ast.AST) -> bool:
        """Whether a value is an object an SDK or another library builds, not a name."""
        origin = self.origin(module, node)
        return _sdk(origin) or _library(origin)

    def _imported_leaf(self, value: _Value) -> bool:
        """Whether a value is a name, or an attribute of one, imported from a project module."""
        root = value.node
        while isinstance(root, ast.Attribute):
            root = root.value
        return (
            isinstance(value.node, (ast.Name, ast.Attribute))
            and isinstance(root, ast.Name)
            and root.id in value.module.imports
            and (self.origin(value.module, value.node) or "").startswith(f"{LOCAL}.")
        )

    def _unread_value(self, module: Module, value: _Value, point: tuple[int, int]) -> None:
        """Account for a value of a model argument that spells no text."""
        node = value.node
        read = self._environment_read(value.module, node)
        if read is not None and environment_name(read[0]):
            # A model that only the environment sets has no value here to record.
            self._found.unresolved_environment.setdefault(read[0], set()).add(
                (module.path, point[0])
            )
        elif self._imported_leaf(value):
            self._found.gap(
                module.path,
                point[0],
                "model argument is bound in another module of the project, which the "
                "collector could not follow; not inventoried",
            )
        elif not isinstance(node, ast.Constant) and not (
            # Whatever else spells no model is unread, unless it is a call by which an SDK
            # or another library builds an object, which is read where it is built.
            isinstance(node, ast.Call) and self._built(value.module, node)
        ):
            self._unread.add(point)
