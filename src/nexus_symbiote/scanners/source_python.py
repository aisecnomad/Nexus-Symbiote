"""Read the model identifiers Python source gives an SDK, without importing or running it.

Only a file that imports a known SDK is analysed, and a project module named like one
is never taken for it. A model identifier written as a literal argument of a call into
an SDK, or of a callee the reader cannot name, is recorded. What a callee is comes from
the names, attributes and calls it is reached through, so a client made in the file, a
parameter annotated with an SDK class, a method handed to ``functools.partial`` and
``super()`` in a subclass of an SDK class are read; a call straight into another
library or a builtin is not. A model argument that is neither a literal nor an object
an SDK or another library builds is a coverage gap, and so is one given to a callee the
project defines and a bound the reader reached. Each name in each scope is worked out
once, so the work is linear in the size of the file.
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
    FORWARDERS,
    MODEL_KEYWORDS,
    POSITIONAL_MODELS,
    REPO_ID_CLASSES,
    WEIGHT_CLASSES,
    WEIGHT_ROOTS,
)
from nexus_symbiote.scanners.source_references import Declarations, placeholder

METHOD = "python-ast"
LOCAL = "<project>"
# What a callee is, is followed this far: each step is one attribute, call or alias.
MAX_ORIGIN_DEPTH = 32
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

    def __init__(self, declarations: Declarations, files: frozenset[str]) -> None:
        """``files`` names every Python file of the project, read or not: a project
        module named like an SDK shadows it even when it is too large to read."""
        self._found = declarations
        self._files = files
        self._texts: dict[str, str] = {}
        self._resolved: dict[tuple[str, str], str | None] = {}
        self._local: dict[tuple[str, str], bool] = {}
        # Kept for one file at a time, keyed by its syntax nodes.
        self._origins: dict[int, str | None] = {}
        self._named: dict[_Scoped, str | None] = {}
        self._scoped: dict[_Scoped, list[_Value] | None] = {}
        self._lookups: dict[_Scoped, tuple[_Scoped, list[_Value]] | None] = {}
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
            module = self._load(path)
            if module is None:
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
            for table in (self._origins, self._named, self._scoped, self._lookups):
                table.clear()

    @staticmethod
    def _allowance(module: Module) -> int:
        """The steps one pass over a file may take: linear in the file's size."""
        return min(MAX_STEPS, 10_000 + 50 * len(module.nodes))

    def _load(self, path: str) -> Module | None:
        try:
            tree = parse_python(self._texts[path])
        except (SyntaxError, ValueError):
            self._found.gap(path, 1, "Python source could not be parsed; not read")
            return None
        module = Module(path, tree)
        if not self._index(module):
            self._found.gap(
                path,
                1,
                "Python source has more syntax nodes than the python-nodes limit; not read",
            )
            return None
        return module

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
            starred = filter(None, (arguments.vararg, arguments.kwarg))
            for argument in (*positional, *arguments.kwonlyargs, *starred):
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

    def _single_origin(self, values: Iterable[_Value], depth: int, also: str | None) -> str | None:
        # A binding to None says nothing about what the name calls.
        origins = {
            self._value_origin(value, depth + 1)
            for value in values
            if not (isinstance(value.node, ast.Constant) and value.node.value is None)
        }
        if also is not None:
            origins.add(also)
        return origins.pop() if len(origins) == 1 else None

    def _import_origin(self, module: Module, name: str) -> str | None:
        """The dotted name an imported name stands for; a module of the project is marked."""
        dotted = module.imports.get(name)
        if dotted is None:
            return None
        return f"{LOCAL}.{dotted}" if self._in_project(dotted, module) else dotted

    def _value_origin(self, value: _Value, depth: int) -> str | None:
        node = value.node
        if isinstance(node, _DEFINITIONS):
            return f"{LOCAL}.{node.name}"
        if isinstance(node, ast.arg):
            if node.annotation is None or isinstance(node.annotation, ast.Constant):
                return None
            base = self.origin(value.module, node.annotation, depth + 1)
            return None if base is None else f"{base}()"
        if isinstance(node, ast.expr):
            return self.origin(value.module, node, depth + 1)
        return None

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
        if isinstance(function, ast.Name):
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
        self, module: Module, expression: ast.expr, *, embedding: bool, weights: bool, remote: bool
    ) -> None:
        """Record a literal model argument; count one the collector cannot read."""
        point = (expression.lineno, expression.col_offset)
        if isinstance(expression, ast.Constant):
            text = expression.value
            if isinstance(text, str):
                ref = self._found.model(
                    text,
                    module.path,
                    point[0],
                    method=METHOD,
                    embedding=embedding,
                    weights=weights,
                    remote_code=remote,
                )
                if ref is None and not placeholder(text):
                    self._unread.add(point)
        elif self._imported_leaf(module, expression):
            self._found.gap(
                module.path,
                point[0],
                "model argument is bound in another module of the project, which the "
                "collector does not follow; not inventoried",
            )
        elif not self._built(module, expression):
            self._unread.add(point)

    def _built(self, module: Module, node: ast.AST) -> bool:
        """Whether a value is an object an SDK or another library makes. A name or an
        attribute of one, such as a library's default model, may hold text."""
        origin = self.origin(module, node)
        return origin is not None and origin.endswith("()") and (_sdk(origin) or _library(origin))

    def _imported_leaf(self, module: Module, node: ast.AST) -> bool:
        """Whether a value is a name, or an attribute of one, imported from a project module."""
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        return (
            isinstance(node, (ast.Name, ast.Attribute))
            and isinstance(root, ast.Name)
            and root.id in module.imports
            and (self.origin(module, node) or "").startswith(f"{LOCAL}.")
        )
