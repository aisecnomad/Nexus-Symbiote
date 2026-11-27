"""Read the model identifiers Python source gives an SDK, without importing or running it.

Only a file that imports a known SDK is analysed, and a project module named like one
is never taken for it. A model identifier written as a literal argument of a call into
an SDK, or of a callee the reader cannot name, is recorded, and so is one it is bound
to within the file: through names, conditionals, an environment variable's default,
joined text and string methods. What a callee is comes from the names, attributes and
calls it is reached through, so a client made in the file, a parameter annotated with
an SDK class, a method handed to ``functools.partial`` and ``super()`` in a subclass of
an SDK class are read; a call straight into another library or a builtin is not. What
a model argument holds besides text the reader can spell, unless it is an object an
SDK or another library builds, is a coverage gap, and so is a model argument given to
a callee the project defines and a bound the reader reached. Each name in each scope
is worked out once, so the work is linear in the size of the file.
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
    MODEL_CALLS,
    MODEL_KEYWORDS,
    POSITIONAL_MODELS,
    REPO_ID_CLASSES,
    WEIGHT_CLASSES,
    WEIGHT_ROOTS,
)
from nexus_symbiote.scanners.source_references import (
    Declarations,
    environment_name,
    model_identifier,
    placeholder,
)

METHOD = "python-ast"
LOCAL = "<project>"
# What a callee is, is followed this far: each step is one attribute, call or alias.
MAX_ORIGIN_DEPTH = 32
# A model argument is followed this far through names and conditionals, to at most so
# many values; joined text keeps at most so many texts of at most so many characters.
MAX_DEPTH = 12
MAX_CANDIDATES = 16
MAX_STRINGS = 16
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
_ANYTHING = frozenset({"builtins.object", "typing.Any", "typing_extensions.Any"})
_ACCESSORS = frozenset({"builtins.getattr", "typing.cast"})
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
    imported: dict[ast.alias, str] = field(default_factory=dict)
    # The modules its import statements name, and the names they import from them.
    modules: set[str] = field(default_factory=set)
    members: set[str] = field(default_factory=set)
    scopes: dict[ast.AST, ast.AST | None] = field(default_factory=dict)
    # Names a scope declares ``global`` or ``nonlocal``, which bind in another scope.
    declared: dict[ast.AST | None, dict[str, str]] = field(default_factory=dict)
    bindings: dict[ast.AST | None, dict[str, list[ast.AST]]] = field(default_factory=dict)
    definitions: dict[ast.AST | None, dict[str, ast.AST]] = field(default_factory=dict)
    parameters: dict[ast.AST, dict[str, ast.arg]] = field(default_factory=dict)
    # Names the file reads other than by spreading them into a call with ``**``.
    touched: set[str] = field(default_factory=set)
    spread: set[int] = field(default_factory=set)


@dataclass(frozen=True, eq=False)
class _Value:
    module: Module
    node: ast.AST
    # Environment variables that, when set, give the value in place of this one.
    variables: frozenset[str] = frozenset()


_Scoped = tuple[int, str]
# The texts an expression spells, each with the variables that may override it, and
# whether that is all it can hold.
_Text = tuple[str, frozenset[str]]
_Spelling = tuple[tuple[_Text, ...], bool]


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


def _model_call(function: ast.expr) -> bool:
    """Whether a callee is a bare name, or is reached through names SDK calls use."""
    if isinstance(function, ast.Name):
        return True
    while isinstance(function, ast.Attribute):
        if function.attr in MODEL_CALLS:
            return True
        function = function.value
    return False


def _loads_weights(origin: str) -> bool:
    base = origin.split("()", 1)[0]
    _, symbol, _ = _split(base)
    return symbol in WEIGHT_CLASSES or any(_under(base, root) for root in WEIGHT_ROOTS)


def _outside(node: ast.AST) -> list[ast.AST]:
    """What a function, class or comprehension evaluates in the scope around it."""
    if isinstance(node, _FUNCTIONS):
        arguments = node.args
        parts: list[ast.AST] = [*arguments.defaults, *filter(None, arguments.kw_defaults)]
        if not isinstance(node, ast.Lambda):
            every = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
            every += filter(None, (arguments.vararg, arguments.kwarg))
            parts += [*node.decorator_list, *filter(None, (a.annotation for a in every))]
            parts += filter(None, [node.returns])
        return parts
    if isinstance(node, ast.ClassDef):
        return [*node.decorator_list, *node.bases, *(keyword.value for keyword in node.keywords)]
    if isinstance(node, _COMPREHENSIONS):
        return [node.generators[0].iter]
    return []


def _falsy(node: ast.AST | None) -> bool:
    """Whether a default is absent or a constant that ``or`` passes over."""
    return node is None or (isinstance(node, ast.Constant) and not node.value)


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
        self._resolved: dict[tuple[str, str], tuple[str | None, bool]] = {}
        self._local: dict[tuple[str, str], tuple[bool, bool]] = {}
        # Kept for one file at a time, keyed by its syntax nodes.
        self._origins: dict[int, str | None] = {}
        self._named: dict[_Scoped, str | None] = {}
        self._scoped: dict[_Scoped, list[_Value] | None] = {}
        self._lookups: dict[_Scoped, tuple[_Scoped, list[_Value]] | None] = {}
        self._reads: dict[int, tuple[str, ast.expr | None] | None] = {}
        self._spelled: dict[int, _Spelling] = {}
        self._pending: set[int] = set()
        self._unread: set[tuple[int, int]] = set()
        self._given: set[tuple[int, int]] = set()
        self._steps = 0
        self._cut = False
        self._shallow = False

    def add(self, path: str, text: str) -> None:
        """Analyse one source file that may import a known SDK. Files are given in path
        order and one at a time, so no more than one is held."""
        self._cut = self._shallow = False
        module = self._load(path, text)
        if module is None:
            return
        self._steps = self._allowance(module)
        if self._imports_sdk(module):
            self._analyse(module)
        elif self._steps > 0 and any(
            self._shadowed(name, module) for name in (*module.modules, *module.members)
        ):
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
        tables = (self._origins, self._named, self._scoped, self._lookups, self._reads)
        for table in (*tables, self._spelled):
            table.clear()

    @staticmethod
    def _allowance(module: Module) -> int:
        """The steps one pass over a file may take: linear in the file's size."""
        return min(MAX_STEPS, 10_000 + 50 * len(module.nodes))

    def _load(self, path: str, text: str) -> Module | None:
        try:
            tree = parse_python(text)
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
        # Defaults, annotations, decorators, bases and a comprehension's first iterable
        # are evaluated in the scope around what they belong to.
        around: dict[int, ast.AST | None] = {}
        while stack:
            node, scope = stack.pop()
            scope = around.pop(id(node), scope)
            module.nodes.append(node)
            if len(module.nodes) > bound:
                return False
            module.scopes[node] = scope
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                kind = "global" if isinstance(node, ast.Global) else "nonlocal"
                module.declared.setdefault(scope, {}).update(dict.fromkeys(node.names, kind))
            elif isinstance(node, ast.Call):
                module.spread.update(
                    id(keyword.value) for keyword in node.keywords if keyword.arg is None
                )
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if id(node) not in module.spread:
                    module.touched.add(node.id)
            if isinstance(node, _SCOPES):
                around.update((id(part), scope) for part in _outside(node))
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
                self._bind_import(module, alias, bound, alias.name if alias.asname else bound)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level > len(package) + 1:
                # Past the top package the import fails, and binds nothing.
                return
            if node.level:
                kept = package[: len(package) - (node.level - 1)]
                base = ".".join([*kept, base] if base else kept)
            for alias in node.names:
                if alias.name == "*":
                    module.modules.add(base)
                else:
                    name = f"{base}.{alias.name}" if base else alias.name
                    module.members.add(name)
                    self._bind_import(module, alias, alias.asname or alias.name, name)
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

    def _bind_import(self, module: Module, alias: ast.alias, bound: str, dotted: str) -> None:
        if len(dotted) > MAX_ORIGIN:
            # Bound to nothing the reader follows, and not left as a name of the file.
            dotted, self._cut = "", True
        scope = module.scopes.get(alias)
        if scope is not None:
            module.imported[alias] = dotted
            self._bind_name(module, bound, alias, scope)
        elif dotted:
            module.imports[bound] = dotted
        else:
            module.imports.pop(bound, None)

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
        parts = dotted.split(".", MAX_PACKAGES)[:MAX_PACKAGES]
        return (
            _ai_import(dotted)
            and self._project_file(parts[0], directory) is not None
            and not any(
                self._project_file(".".join(parts[:count]), directory)
                for count in range(2, len(parts) + 1)
            )
        )

    def _in_project(self, dotted: str, importer: Module) -> bool:
        """Whether a dotted name, or a package it lies in, is a module of the project."""
        directory = importer.path.rpartition("/")[0]
        key = (dotted, directory)
        if key not in self._local:
            outer, self._cut = self._cut, False
            parts = dotted.split(".", MAX_PACKAGES)
            known = any(
                self._project_file(".".join(parts[:count]), directory) is not None
                for count in range(min(len(parts), MAX_PACKAGES), 0, -1)
            )
            # Kept with every bound reached on the way, so each file that asks hears of it.
            self._local[key] = (known, self._cut or len(parts) > MAX_PACKAGES)
            self._cut = outer
        known, cut = self._local[key]
        self._cut = self._cut or cut
        return known

    def _project_file(self, dotted: str, directory: str) -> str | None:
        """The project file a dotted module name resolves to from ``directory``, if any:
        beside the importer, in each directory above it nearest first, at the root and
        in the usual source directories. A directory inside a package is no import root.
        Each place looked in is a step of the file's allowance."""
        key = (dotted, directory)
        if key in self._resolved:
            found, cut = self._resolved[key]
            self._cut = self._cut or cut
            return found
        relative = dotted.replace(".", "/")
        bases: list[str] = []
        searched = 0
        while directory and searched < MAX_ANCESTORS:
            searched += 1
            if f"{directory}/__init__.py" not in self._files:
                bases.append(directory + "/")
            directory = directory.rpartition("/")[0]
        cut = bool(directory)
        self._cut = self._cut or cut
        bases.append("")
        bases.extend(
            root for root in ("src/", "lib/", "app/") if f"{root}__init__.py" not in self._files
        )
        self._steps -= len(bases)
        found = None
        for base in bases:
            for candidate in (f"{base}{relative}.py", f"{base}{relative}/__init__.py"):
                if found is None and candidate in self._files:
                    found = candidate
        self._resolved[key] = (found, cut)
        return found

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
            self._steps -= 1 + len(found)
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
            self._steps -= 1
            if isinstance(scope, ast.ClassDef) and method:
                return scope
            method = method or isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            scope = module.scopes.get(scope)
        return None

    def origin(self, module: Module, node: ast.AST, depth: int = 0) -> str | None:
        """The dotted name of what ``node`` calls or names: ``openai.OpenAI().chat``."""
        key = id(node)
        self._steps -= 1
        if key in self._origins:
            return self._origins[key]
        if depth > MAX_ORIGIN_DEPTH or self._steps <= 0:
            self._shallow = self._cut = True
            return None

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
                    # ``super()`` is an object of an SDK base, or else of the first.
                    bases = [
                        self.origin(module, base, depth + 1) for base in getattr(owner, "bases", ())
                    ]
                    base = next((made for made in bases if _sdk(made)), bases[0] if bases else None)
                    return None if base is None else f"{base}()"
            base = self.origin(module, function, depth + 1)
            if base is None or base in _ACCESSORS or _python(base) and base.endswith(".get"):
                # ``cast``, ``getattr`` and a container's ``get`` may give any object.
                return None
            return f"{base}()"
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

    def _single_origin(self, values: list[_Value], depth: int, also: str | None) -> str | None:
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
        return None if dotted is None else self._dotted_origin(module, dotted)

    def _dotted_origin(self, module: Module, dotted: str) -> str:
        return f"{LOCAL}.{dotted}" if self._in_project(dotted, module) else dotted

    def _value_origin(self, value: _Value, depth: int) -> str | None:
        node = value.node
        if isinstance(node, _DEFINITIONS):
            return f"{LOCAL}.{node.name}"
        if isinstance(node, ast.alias):
            dotted = value.module.imported.get(node)
            return self._dotted_origin(value.module, dotted) if dotted else None
        if isinstance(node, ast.arg):
            if node.annotation is None or isinstance(node.annotation, ast.Constant):
                return None
            base = self.origin(value.module, node.annotation, depth + 1)
            # ``Any``, ``object`` and a type stub's class say nothing of what an SDK makes.
            if base is None or base in _ANYTHING or base.startswith("mypy_boto3"):
                return None
            return f"{base}()"
        if isinstance(node, ast.expr):
            return self.origin(value.module, node, depth + 1)
        return None

    def _follow(self, module: Module, node: ast.AST, depth: int = 0) -> list[_Value]:
        """The expressions ``node`` can stand for, each one the reader follows no further."""
        found: list[_Value] = []
        self._follow_into(_Value(module, node), found, set(), depth)
        return found

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
        same = value.variables
        inner: Iterable[tuple[ast.AST, frozenset[str]]] | None = None
        if isinstance(node, ast.Name):
            resolved = self._resolve(module, node.id, node)
            inner = None if resolved is None else ((bound.node, same) for bound in resolved[1])
        elif isinstance(node, (ast.Await, ast.NamedExpr)):
            inner = [(node.value, same)]
        elif isinstance(node, ast.IfExp):
            inner = [(node.body, same), (node.orelse, same)]
        elif isinstance(node, ast.BoolOp):
            inner = self._operands(module, node, same)
        if inner is None:
            out.append(value)
            return
        for index, (part, variables) in enumerate(inner):
            if len(out) >= MAX_CANDIDATES or index > MAX_CANDIDATES:
                # What is left is not walked: a wide expression or a name bound many
                # times, read at many places, would otherwise cost its width at each.
                self._cut = True
                return
            self._follow_into(_Value(module, part, variables), out, seen, depth + 1)

    def _operands(
        self, module: Module, node: ast.BoolOp, variables: frozenset[str]
    ) -> Iterable[tuple[ast.AST, frozenset[str]]]:
        """The operands of ``a or b`` and ``a and b``, made as they are walked. In ``or``,
        a variable read with no default falls through to the operands after it when it is
        unset, so they are its default and the variable may override them."""
        last = len(node.values) - 1
        for index, operand in enumerate(node.values):
            name = None
            if isinstance(node.op, ast.Or) and index < last:
                name = self._unset_variable(module, operand)
            if name is None:
                yield operand, variables
            else:
                variables = variables | {name}

    def _unset_variable(self, module: Module, node: ast.AST) -> str | None:
        """The variable an operand reads, when the environment alone gives its value: a
        call with no default, made there or bound to a name the operand is."""
        reads: list[ast.AST] = [node]
        if isinstance(node, ast.Name):
            resolved = self._resolve(module, node.id, node)
            reads = [] if resolved is None else [bound.node for bound in resolved[1]]
        self._steps -= len(reads)
        names = set()
        for read in reads[: MAX_CANDIDATES + 1]:
            found = self._environment_read(module, read)
            if not isinstance(read, ast.Call) or found is None or not _falsy(found[1]):
                return None
            names.add(found[0])
        name = names.pop() if len(names) == 1 else None
        return name if environment_name(name) else None

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

    def _strings(self, module: Module, node: ast.AST, depth: int) -> _Spelling:
        """The texts ``node`` can stand for through names and conditionals, and whether
        that is all it can hold."""
        unique: dict[_Text, None] = {}
        whole = True
        for value in self._follow(module, node, depth):
            texts, complete = self._spell(value, depth)
            whole = whole and complete
            for item in texts:
                unique[item] = None
                if len(unique) > MAX_STRINGS:
                    self._cut = True
                    return tuple(unique)[:MAX_STRINGS], False
        return tuple(unique), whole

    def _spell(self, value: _Value, depth: int = 0) -> _Spelling:
        """What one expression spells, read once however many names stand for it. An
        expression read again while it is being read, as text built from itself is,
        spells nothing more there, and what was read meanwhile is not kept: the answer
        then does not depend on which name reading began at."""
        key = id(value.node)
        if key in self._pending:
            self._shallow = True
            return (), False
        known = self._spelled.get(key)
        if known is None:
            self._pending.add(key)
            outer, self._shallow = self._shallow, False
            known = self._spell_node(value.module, value.node, depth)
            self._pending.discard(key)
            if not self._shallow:
                self._spelled[key] = known
            self._shallow = self._shallow or outer
        texts, complete = known
        if value.variables:
            texts = tuple((text, variables | value.variables) for text, variables in texts)
        return texts, complete

    def _spell_node(self, module: Module, node: ast.AST, depth: int) -> _Spelling:
        self._steps -= 1
        if depth > MAX_DEPTH or self._steps <= 0:
            self._shallow = self._cut = True
            return (), False
        if isinstance(node, ast.Constant):
            if not isinstance(node.value, str):
                # None or a number: no model, and nothing the reader missed.
                return (), True
            return (
                (((node.value, frozenset()),), True) if len(node.value) <= MAX_TEXT else ((), False)
            )
        read = self._environment_read(module, node)
        if read is not None:
            name, default = read
            if default is None:
                return (), False
            texts, complete = self._strings(module, default, depth + 1)
            if environment_name(name) is None:
                # The variable that may override the default cannot be named.
                return texts, False
            return tuple((text, variables | {name}) for text, variables in texts), complete
        if isinstance(node, ast.JoinedStr):
            parts: list[ast.AST] = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    if part.conversion != -1 or part.format_spec is not None:
                        return (), False
                    part = part.value
                parts.append(part)
            return self._join(module, parts, depth)
        if isinstance(node, (ast.BinOp, ast.AugAssign)) and isinstance(node.op, ast.Add):
            if isinstance(node, ast.BinOp):
                return self._join(module, [node.left, node.right], depth)
            return self._join(module, [node.target, node.value], depth)
        if isinstance(node, ast.Call):
            return self._call_text(module, node, depth)
        return (), False

    def _join(self, module: Module, parts: list[ast.AST], depth: int) -> _Spelling:
        """The texts ``parts`` join to. They are bounded, and each joining is charged: a
        name joined to itself would otherwise double at every binding it passes."""
        built: list[_Text] = [("", frozenset())]
        whole = True
        for part in parts:
            options, complete = self._strings(module, part, depth + 1)
            whole = whole and complete
            self._steps -= len(built) * len(options)
            joined = [
                (text + more, variables | others)
                for text, variables in built
                for more, others in options
                if len(text) + len(more) <= MAX_TEXT
            ]
            whole = whole and len(joined) == len(built) * len(options)
            if not joined:
                return (), False
            if len(joined) > MAX_STRINGS:
                self._cut = True
            built = joined[:MAX_STRINGS]
        return tuple(built), whole

    def _call_text(self, module: Module, node: ast.Call, depth: int) -> _Spelling:
        """The text a string method or ``str()`` gives back."""
        function = node.func
        if isinstance(function, ast.Attribute) and function.attr in _TRANSFORMS:
            if node.args or node.keywords:
                return (), False
            change = _TRANSFORMS[function.attr]
            texts, complete = self._strings(module, function.value, depth + 1)
            # A token stays one whatever its case, so only text that could be recorded
            # as it is written is changed.
            kept = tuple(
                (change(text), variables)
                for text, variables in texts
                if model_identifier(text) is not None
            )
            return kept, complete and len(kept) == len(texts)
        if self.origin(module, function) == "builtins.str" and len(node.args) == 1:
            if not node.keywords:
                return self._strings(module, node.args[0], depth + 1)
        return (), False

    def _spread(self, module: Module, node: ast.expr) -> dict[str, ast.expr] | None:
        """The keywords ``**node`` gives, when it is a dict written out with text keys,
        there or bound once to a name the file reads only by spreading it: a dict read in
        any other way may be changed or handed on, so what it holds is not known."""
        held: ast.AST = node
        if isinstance(node, ast.Name):
            resolved = None if node.id in module.touched else self._resolve(module, node.id, node)
            if resolved is None or len(resolved[1]) != 1:
                return None
            held = resolved[1][0].node
        given: dict[str, ast.expr] = {}
        if isinstance(held, ast.Dict):
            for key, item in zip(held.keys, held.values, strict=True):
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    return None
                given[key.value] = item
        elif isinstance(held, ast.Call) and self.origin(module, held.func) == "builtins.dict":
            if held.args or any(keyword.arg is None for keyword in held.keywords):
                return None
            given = _keywords(held)
        else:
            return None
        self._steps -= len(given)
        return given

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
        parts = made[0].split(".")
        if isinstance(function, ast.Name) or len(parts) > 1 and parts[-2][:1].isupper():
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
        if not local and not _sdk(origin) and not _model_call(function):
            # Of an unknown object, a metrics label or a query's field is no model.
            return
        base = "" if origin is None else origin.split("()", 1)[0]
        _, symbol, _ = _split(base)
        keywords = _keywords(call)
        spread: list[ast.expr] = []
        for keyword in call.keywords:
            given = None if keyword.arg is not None else self._spread(module, keyword.value)
            if given is not None:
                for key, item in given.items():
                    keywords.setdefault(key, item)
            elif keyword.arg is None:
                spread.append(keyword.value)
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
            unread.extend(spread)
        if local:
            self._given.update((value.lineno, value.col_offset) for value, _ in found)
            return
        self._unread.update((value.lineno, value.col_offset) for value in unread)
        weights = origin is not None and _loads_weights(origin)
        flags = [keywords.get("trust_remote_code")]
        for options in (keywords.get("model_kwargs"), keywords.get("config_kwargs")):
            if isinstance(options, ast.Dict):
                flags += [
                    v
                    for k, v in zip(options.keys, options.values, strict=True)
                    if k is None or _constant(k) == "trust_remote_code"
                ]
        remote = weights and any(
            flag is not None and not (isinstance(flag, ast.Constant) and not flag.value)
            for flag in flags
        )
        for expression, embeds in found:
            self._model_references(
                module, expression, embedding=embeds, weights=weights, remote=remote
            )

    def _model_references(
        self, module: Module, expression: ast.expr, *, embedding: bool, weights: bool, remote: bool
    ) -> None:
        """Record each identifier a model argument can hold, and account for what else
        it can hold."""
        point = (expression.lineno, expression.col_offset)
        values = self._follow(module, expression)
        if not values:
            # A name bound only to itself stands for nothing the reader can give.
            self._unread.add(point)
        kept = 0
        for value in values:
            texts, complete = self._spell(value)
            for text, variables in texts:
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
                    remote_code=remote,
                    environment=variables,
                )
                if ref is None and not placeholder(text):
                    self._unread.add(point)
            if not complete:
                self._unread_value(value, point)

    def _unread_value(self, value: _Value, point: tuple[int, int]) -> None:
        """Account for what a value of a model argument holds besides the text read."""
        module, node = value.module, value.node
        read = self._environment_read(module, node)
        if read is not None and read[1] is None and environment_name(read[0]):
            # A model that only the environment sets has no value here to record.
            first = self._found.unresolved_environment.setdefault((module.path, read[0]), point[0])
            self._found.unresolved_environment[(module.path, read[0])] = min(first, point[0])
        elif self._imported_leaf(module, node):
            self._found.gap(
                module.path,
                point[0],
                "model argument is bound in another module of the project, which the "
                "collector does not follow; not inventoried",
            )
        elif not self._built(module, node):
            self._unread.add(point)

    def _built(self, module: Module, node: ast.AST) -> bool:
        """Whether a value is an object an SDK makes. What another library makes, such as
        configuration it reads, and a name or an attribute of one may hold text."""
        origin = self.origin(module, node)
        return origin is not None and origin.endswith("()") and _sdk(origin)

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
