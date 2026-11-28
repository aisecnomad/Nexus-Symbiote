"""Capabilities a source-declared tool body names, recorded only where they raise risk.

A tool the ``mcp`` collector records from a Python decorator or a TypeScript registration is
classified by the calls in its own body: process execution, network egress and whether it
sends data, filesystem writes and deletions, payment API writes and reads of secret-named
environment variables. Names resolve only through the file's imports, names
bound from them and builtins, by the language's scoping rules; nothing is executed or
imported. The classifier cannot show that a body does nothing else, so it records only what
raises risk, never ``read`` or ``read-only``, and a body past a bound records a coverage gap.
"""

from __future__ import annotations

import ast
import itertools
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from nexus_symbiote.core.enums import CapabilityClass, RiskSeverity, SideEffectProfile
from nexus_symbiote.core.models import CapabilityDeclaration, RiskAssessment
from nexus_symbiote.trifecta import SECRET_ENV_KEY_RE

if TYPE_CHECKING:
    from tree_sitter import Node

CATEGORY = "capability_scope"
EVIDENCE = "source-body-call-names"
MAX_BODY_NODES = 20_000
UNCLASSIFIED = "tool body too large or too ambiguous to classify its capabilities"

_RISK_CAPABILITIES = frozenset(
    {CapabilityClass.EXECUTE, CapabilityClass.WRITE, CapabilityClass.DESTRUCTIVE}
    | {CapabilityClass.PAYMENT, CapabilityClass.NETWORK, CapabilityClass.CREDENTIALS}
)

_PY_BUILTINS = frozenset({"eval", "exec", "open"})
_PY_EXECUTE = frozenset(
    {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}
    | {"subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput", "pty.spawn"}
    | {"os.system", "os.popen", "os.execl", "os.execle", "os.execlp", "os.execv", "os.execve"}
    | {"os.execvp", "os.execvpe", "os.spawnl", "os.spawnv", "os.spawnvp", "os.posix_spawn"}
    | {"os.posix_spawnp", "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec"}
    | {"eval", "exec", "builtins.eval", "builtins.exec", "os.execlpe", "os.spawnle", "os.spawnlp"}
    | {"os.spawnlpe", "os.spawnve", "os.spawnvpe"}
)
_PY_HTTP = frozenset({"requests", "httpx", "aiohttp", "urllib3"})
_PY_NETWORK = _PY_HTTP | frozenset(
    {"smtplib", "boto3", "botocore", "websocket", "websockets", "grpc"}
)
_SOCKET_NETWORK = frozenset(
    {"socket", "create_connection", "connect", "sendall", "send", "sendto", "getaddrinfo"}
)
_HTTP_WRITE = frozenset({"post", "put", "patch", "delete"})
_MAIL_WRITE = frozenset({"sendmail", "send_message"})
_PAYMENT_MODULES = frozenset({"stripe", "braintree", "adyen", "paypalrestsdk", "square"})
_PAYMENT_WRITE = frozenset(
    {"create", "capture", "confirm", "pay", "refund", "void", "sale", "submit_for_settlement"}
)
_PAYMENT_LOCAL = frozenset({"Webhook", "WebhookSignature", "error", "util", "oauth_error"})
_PAYMENT_RESOURCES = frozenset(
    {"Charge", "Refund", "PaymentIntent", "Payout", "Transfer", "Transaction", "Payment"}
)
# Distinctive on any receiver, such as a Path parameter.
_FS_WRITE = frozenset(
    {"write_text", "write_bytes", "makedirs", "mkdir", "copyfile", "copytree", "touch"}
)
_FS_DELETE = frozenset({"unlink", "rmtree", "rmdir"})
# Modules a resolved filesystem call has to come from; an unresolved receiver, such as a
# Path parameter, counts by the distinctive name alone.
_FS_MODULES = frozenset({"os", "shutil", "pathlib", "tempfile"})
# Ambiguous names, counted only as os.<name> or shutil.<name>.
_FS_MODULE_WRITE = frozenset({"remove", "rename", "replace", "copy", "copy2", "move"})
_FS_MODULE_DELETE = frozenset({"remove", "removedirs"})
_TS_EXECUTE = frozenset(
    {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"}
)
_TS_FS_WRITE = frozenset(
    {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "copyFile", "copyFileSync"}
    | {"rename", "renameSync", "mkdir", "mkdirSync", "createWriteStream"}
)
_TS_FS_DELETE = frozenset({"rm", "rmSync", "unlink", "unlinkSync", "rmdir", "rmdirSync"})
_TS_HTTP = frozenset({"axios", "node-fetch", "got", "undici", "ky", "http", "https"})
_TS_PAYMENT_RESOURCES = frozenset({"refunds", "charges", "paymentIntents", "payouts", "transfers"})
_TS_PAYMENT_WRITE = frozenset({"create", "confirm", "capture"})
_TS_GLOBALS = frozenset({"globalThis", "window", "global", "self"})
_TS_HTTP_SERVER = frozenset({"createServer", "Server", "listen", "STATUS_CODES"})
# A callee chain longer than this is not an API call; it names nothing, in constant time.
MAX_CHAIN = 16
_MODULE_HEAD = "\x00module:"


@dataclass
class ToolCapabilities:
    """What a tool body names that raises risk, and the findings it implies."""

    capabilities: list[CapabilityClass] = field(default_factory=list)
    profile: SideEffectProfile = SideEffectProfile.UNKNOWN
    risks: list[RiskAssessment] = field(default_factory=list)
    unclassified: bool = False

    @property
    def declaration(self) -> CapabilityDeclaration | None:
        """A declaration only for positive risk evidence; otherwise the tool stays unknown."""
        if not set(self.capabilities) & _RISK_CAPABILITIES:
            return None
        return CapabilityDeclaration(
            capabilities=self.capabilities, side_effect_profile=self.profile
        )


@dataclass
class _Observed:
    capabilities: set[CapabilityClass] = field(default_factory=set)
    writes: bool = False
    destructive: bool = False
    payment: bool = False
    execute: bool = False

    def add(self, *classes: CapabilityClass) -> None:
        self.capabilities.update(classes)

    def write(self, *classes: CapabilityClass) -> None:
        self.capabilities.update((CapabilityClass.WRITE, *classes))
        self.writes = True

    def delete(self, *classes: CapabilityClass) -> None:
        self.write(CapabilityClass.DESTRUCTIVE, *classes)
        self.destructive = True


def _finish(label: str, seen: _Observed) -> ToolCapabilities:
    risks: list[RiskAssessment] = []
    if seen.execute:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category=CATEGORY,
                detail=f"Tool '{label}' runs commands or evaluates code on the host.",
                recommendation="Confine the tool to an allow-list of commands and a sandbox.",
            )
        )
    if seen.payment:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category=CATEGORY,
                detail=f"Tool '{label}' performs a financial transaction.",
                recommendation="Require human approval and bound amounts for payment tools.",
            )
        )
    if seen.payment:
        profile = SideEffectProfile.FINANCIAL_TRANSACTION
    elif seen.destructive:
        profile = SideEffectProfile.DESTRUCTIVE
    elif seen.writes or seen.execute:
        profile = SideEffectProfile.STATE_MODIFYING
    else:
        profile = SideEffectProfile.UNKNOWN
    return ToolCapabilities(
        capabilities=sorted(seen.capabilities, key=lambda c: c.value), profile=profile, risks=risks
    )


def _secret_name(name: str) -> bool:
    return bool(name) and bool(SECRET_ENV_KEY_RE.search(name))


_PY_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_PY_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_PY_SCOPES = (*_PY_FUNCTIONS, ast.ClassDef, *_PY_COMPREHENSIONS)
_SCOPE_KINDS = {ast.ClassDef: "class", **dict.fromkeys(_PY_COMPREHENSIONS, "comprehension")}
# Distinct targets one name may have in one scope. Past it, a tool that reads the name is
# unclassified, so piling up bindings cannot crowd out the one that raises risk.
_MAX_TARGETS = 32

# A path a name may hold and whether it is reached through a call: after
# ``client = requests.Session()``, ``client`` is ``("requests.Session", True)``.
_Target = tuple[str, bool]


class _TooManyTargetsError(Exception):
    pass


@dataclass
class _Name:
    """Every target the bindings of one name in one scope give it."""

    targets: set[_Target] = field(default_factory=set)
    # Some binding names nothing: a parameter, a local function, a loop target and the like.
    unresolved: bool = False
    overflow: bool = False


@dataclass(eq=False)
class _Scope:
    kind: str  # "module", "function", "class" or "comprehension"
    parent: _Scope | None = None
    names: dict[str, _Name] = field(default_factory=dict)
    declared_global: set[str] = field(default_factory=set)
    declared_nonlocal: set[str] = field(default_factory=set)


class PythonScopes:
    """Every binding a module's names have, scope by scope, read as Python reads them: a name
    a function binds anywhere in its body is local to it, and a module-level name may hold
    any of its bindings or the builtin. Built in one pass per file; an assigned value is
    resolved against the bindings made before it."""

    def __init__(self, tree: ast.AST | None = None) -> None:
        self.module = _Scope("module")
        self._scopes: dict[ast.AST, _Scope] = {}
        # Stacked decorators can register one body under many names; it is read once.
        self.observed: dict[ast.AST, _Observed | None] = {}
        if tree is not None:
            self._fill(tree, self.module)

    def scope(self, function: ast.AST) -> _Scope:
        """The scope ``function`` opens, read now if it was not part of the tree."""
        if function not in self._scopes:
            self._fill(function, self.module)
        return self._scopes[function]

    def children(self, node: ast.AST, scope: _Scope) -> list[tuple[ast.AST, _Scope]]:
        """The child nodes of ``node``, each with the scope it is read in."""
        if not isinstance(node, _PY_SCOPES):
            return [(child, scope) for child in ast.iter_child_nodes(node)]
        if node not in self._scopes:
            self._fill(node, scope)
        inner = self._scopes[node]
        found: list[tuple[ast.AST, _Scope]] = []
        for name, value in ast.iter_fields(node):
            # Decorators, defaults, annotations and bases are read where the definition is.
            where = inner if isinstance(node, _PY_COMPREHENSIONS) or name == "body" else scope
            for child in value if isinstance(value, list) else [value]:
                if isinstance(child, ast.AST):
                    found.append((child, where))
        return found

    def resolve(self, scope: _Scope, dotted: str) -> tuple[list[_Target], bool]:
        """What ``dotted`` may name where ``scope`` reads it, and whether a binding names
        nothing; ``_TooManyTargetsError`` past the target bound."""
        head, _, rest = dotted.partition(".")
        entries, builtin = self._lookup(scope, head)
        builtin = builtin and head in _PY_BUILTINS
        targets = [(dotted, False)] if builtin else []
        unresolved = not entries and not builtin
        for entry in entries:
            if entry.overflow:
                raise _TooManyTargetsError
            unresolved = unresolved or entry.unresolved
            targets.extend(
                (f"{path}.{rest}" if rest else path, call) for path, call in entry.targets
            )
        return targets, unresolved

    def _lookup(self, scope: _Scope, name: str) -> tuple[list[_Name], bool]:
        """The bindings a read of ``name`` in ``scope`` may see, and whether a builtin may."""
        entries: list[_Name] = []
        current: _Scope | None = scope
        own = True  # A class body reads its own names; a scope nested in it does not.
        while current is not None:
            if name in current.declared_global and current is not self.module:
                current, own = self.module, False
                continue
            if name in current.declared_nonlocal:
                current, own = current.parent, False
                continue
            entry = current.names.get(name) if own or current.kind != "class" else None
            if entry is not None:
                entries.append(entry)
                if current.kind in {"function", "comprehension"}:
                    return entries, False
                if current.kind == "module":
                    return entries, True
            current, own = current.parent, False
        return entries, True

    def _fill(self, root: ast.AST, scope: _Scope) -> None:
        pending: list[tuple[ast.AST, _Scope]] = [(root, scope)]
        while pending:
            node, where = pending.pop()
            self._visit(node, where)
            pending.extend(reversed(self.children(node, where)))

    def _visit(self, node: ast.AST, scope: _Scope) -> None:
        """Record the bindings ``node`` makes in ``scope`` and open the scope it starts."""
        if isinstance(node, _PY_SCOPES):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                self._bind(scope, node.name, ())
            kind = _SCOPE_KINDS.get(type(node), "function")
            inner = self._scopes[node] = _Scope(kind, scope)
            if isinstance(node, _PY_FUNCTIONS):
                a = node.args
                for argument in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg):
                    if argument is not None:
                        self._bind(inner, argument.arg, ())
        elif isinstance(node, ast.Global):
            scope.declared_global.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            scope.declared_nonlocal.update(node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                path = alias.name if alias.asname else alias.name.split(".")[0]
                self._bind(scope, alias.asname or path, ((path, False),))
        elif isinstance(node, ast.ImportFrom):
            # A relative import binds the name to something outside the file: nothing.
            absolute = node.module is not None and node.level == 0
            for alias in node.names:
                if alias.name != "*":
                    path = f"{node.module}.{alias.name}"
                    self._bind(
                        scope, alias.asname or alias.name, ((path, False),) if absolute else ()
                    )
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                self._assign(scope, target, node.value)
        elif isinstance(
            node, ast.AnnAssign | ast.AugAssign | ast.For | ast.AsyncFor | ast.comprehension
        ):
            self._assign(
                scope, node.target, node.value if isinstance(node, ast.AnnAssign) else None
            )
        elif isinstance(node, ast.NamedExpr):
            # ``:=`` in a comprehension binds in the function or module around it.
            owner = scope
            while owner.kind == "comprehension" and owner.parent is not None:
                owner = owner.parent
            self._assign(owner, node.target, node.value, scope)
        elif isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                if item.optional_vars is not None:
                    self._assign(scope, item.optional_vars, item.context_expr)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                self._assign(scope, target, None)
        elif isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and node.name:
            self._bind(scope, node.name, ())
        elif isinstance(node, ast.MatchMapping) and node.rest:
            self._bind(scope, node.rest, ())

    def _assign(
        self,
        scope: _Scope,
        target: ast.AST,
        value: ast.expr | None,
        reads: _Scope | None = None,
    ) -> None:
        """Bind a name target to ``value``; each name an unpacking binds names nothing."""
        pending = [target]
        while pending:
            node = pending.pop()
            if isinstance(node, ast.Name):
                bound = self._value(reads or scope, value) if node is target else ()
                self._bind(scope, node.id, bound)
            elif isinstance(node, ast.Tuple | ast.List):
                pending.extend(node.elts)
            elif isinstance(node, ast.Starred):
                pending.append(node.value)

    def _value(self, scope: _Scope, value: ast.expr | None) -> tuple[_Target, ...] | None:
        """What assigning ``value`` binds: a call's result or another name for a target."""
        found = _chain_through(value) if value is not None else None
        if found is None:
            return ()
        dotted, through = found
        through = through or isinstance(value, ast.Call)
        try:
            targets, _ = self.resolve(scope, dotted)
        except _TooManyTargetsError:
            return None
        return tuple((path, through or call) for path, call in targets)

    def _bind(self, scope: _Scope, name: str, targets: tuple[_Target, ...] | None) -> None:
        if name in scope.declared_global:
            scope = self.module
        elif name in scope.declared_nonlocal:
            scope = self._enclosing(scope, name)
        entry = scope.names.setdefault(name, _Name())
        if targets is None:
            entry.overflow = True
        elif not targets:
            entry.unresolved = True
        for target in targets or ():
            if target not in entry.targets:
                if len(entry.targets) >= _MAX_TARGETS:
                    entry.overflow = True
                    return
                entry.targets.add(target)

    def _enclosing(self, scope: _Scope, name: str) -> _Scope:
        """The function scope a ``nonlocal`` name refers to."""
        nearest: _Scope | None = None
        current = scope.parent
        while current is not None and current.kind != "module":
            if current.kind != "class":
                nearest = nearest or current
                if name in current.names:
                    return current
            current = current.parent
        return nearest or self.module


def _chain(node: ast.AST) -> str | None:
    """``a.b.c`` for a name or attribute chain, reading through calls, without recursion."""
    found = _chain_through(node)
    return None if found is None else found[0]


def _chain_through(node: ast.AST) -> tuple[str, bool] | None:
    """The chain and whether it read through a call; None past ``MAX_CHAIN`` steps."""
    parts: list[str] = []
    through_call = False
    for _ in range(MAX_CHAIN):
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            through_call = True
            node = node.func
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts)), through_call
        elif parts:
            # A base that is not a name, such as ``(root / name)``, resolves to nothing.
            parts.append("?")
            return ".".join(reversed(parts)), through_call
        else:
            return None
    return None


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _open_mode(call: ast.Call, position: int) -> str | None:
    modes = list(call.args[position : position + 1]) + [
        k.value for k in call.keywords if k.arg == "mode"
    ]
    if not modes:
        return "r"
    return _literal(modes[0])


def classify_python(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    scopes: PythonScopes | None = None,
    label: str | None = None,
) -> ToolCapabilities:
    """Classify a Python tool body by the calls it names, never by its decorators."""
    scopes = scopes if scopes is not None else PythonScopes()
    if function not in scopes.observed:
        scopes.observed[function] = _observe_python(function, scopes)
    seen = scopes.observed[function]
    if seen is None:
        return ToolCapabilities(unclassified=True)
    return _finish(label or function.name, seen)


def _observe_python(
    function: ast.FunctionDef | ast.AsyncFunctionDef, scopes: PythonScopes
) -> _Observed | None:
    """What a body names that raises risk; None past a bound."""
    nodes: list[tuple[ast.AST, _Scope]] = []
    pending: list[tuple[ast.AST, _Scope]] = [
        (s, scopes.scope(function)) for s in reversed(function.body)
    ]
    while pending:
        node, scope = pending.pop()
        nodes.append((node, scope))
        if len(nodes) > MAX_BODY_NODES:
            return None
        pending.extend(reversed(scopes.children(node, scope)))
    seen = _Observed()
    try:
        for node, scope in nodes:
            _python_node(node, scope, scopes, seen)
    except _TooManyTargetsError:
        return None
    return seen


def _python_node(node: ast.AST, scope: _Scope, scopes: PythonScopes, seen: _Observed) -> None:
    if isinstance(node, ast.Subscript):
        environ = _chain(node.value)
        if environ is not None and any(
            path == "os.environ" for path, _ in scopes.resolve(scope, environ)[0]
        ):
            key = _literal(node.slice)
            if key is not None and _secret_name(key):
                seen.add(CapabilityClass.CREDENTIALS)
    if not isinstance(node, ast.Call):
        return
    found = _chain_through(node.func)
    if found is None:
        return
    written, through_call = found
    names, unresolved = scopes.resolve(scope, written)
    if unresolved:
        last = written.rsplit(".", 1)[-1]
        if last in _FS_WRITE:
            seen.write(CapabilityClass.FILESYSTEM)
        elif last in _FS_DELETE:
            seen.delete(CapabilityClass.FILESYSTEM)
    for name, via_call in names:
        _python_call(node, name, through_call or via_call, seen)


def _python_call(node: ast.Call, name: str, through_call: bool, seen: _Observed) -> None:
    """Classify one call against one target its callee may have."""
    parts = name.split(".")
    module = parts[0]
    last = parts[-1]
    # os.<name> or shutil.<name> itself, not a method of a value one of them returns.
    module_call = len(parts) == 2 and not through_call
    if name in _PY_EXECUTE:
        seen.add(CapabilityClass.EXECUTE)
        seen.execute = True
    if (
        (module in _PY_NETWORK and last[:1].islower())
        or name.startswith("urllib.request.")
        or (module == "socket" and last in _SOCKET_NETWORK)
    ):
        seen.add(CapabilityClass.NETWORK)
        if (module in _PY_HTTP and last in _HTTP_WRITE) or last in _MAIL_WRITE:
            seen.write()
    if (
        module in _PAYMENT_MODULES
        and len(parts) >= 2
        and not set(parts) & _PAYMENT_LOCAL
        and last[:1].islower()
    ):
        seen.add(CapabilityClass.NETWORK)
        if last in _PAYMENT_WRITE and (
            set(parts) & _PAYMENT_RESOURCES
            or ("Invoice" in parts and last == "pay")
            or (
                module == "stripe"
                and parts[-2] in {"charges", "refunds", "payment_intents", "payouts", "transfers"}
            )
            or (module == "stripe" and parts[-2] == "invoices" and last == "pay")
        ):
            seen.write(CapabilityClass.PAYMENT)
            seen.payment = True
    path_open = (
        name in {"pathlib.Path.open", "pathlib.PosixPath.open", "pathlib.WindowsPath.open"}
        and through_call
    )
    if name in {"open", "builtins.open", "io.open"} or path_open:
        mode = _open_mode(node, 0 if path_open else 1)
        if mode is None or any(flag in mode for flag in "wax+"):
            seen.add(CapabilityClass.FILESYSTEM)
            if mode is not None:
                seen.write()
    elif module in _FS_MODULES and last in _FS_WRITE:
        seen.write(CapabilityClass.FILESYSTEM)
    elif (module in _FS_MODULES and last in _FS_DELETE) or (
        module in {"os", "shutil"} and module_call and last in _FS_MODULE_DELETE
    ):
        seen.delete(CapabilityClass.FILESYSTEM)
    elif module in {"os", "shutil"} and module_call and last in _FS_MODULE_WRITE:
        seen.write(CapabilityClass.FILESYSTEM)
    if name in {"os.getenv", "os.environ.get"}:
        key_arg = next(iter(node.args), None) or next(
            (k.value for k in node.keywords if k.arg == "key"), None
        )
        key = _literal(key_arg)
        if key is not None and _secret_name(key):
            seen.add(CapabilityClass.CREDENTIALS)


def _ts_text(node: Node | None) -> str:
    return (node.text or b"").decode("utf-8", "replace") if node is not None else ""


def _ts_module(specifier: str) -> str:
    module = specifier.removeprefix("node:")
    return module.split("/", 1)[0] if not module.startswith("@") else module


Bindings = Mapping[str, tuple[tuple[str, str], ...]]


_Names = dict[str, dict[tuple[str, str], None]]  # Each name's bindings, in the order found.
_TS_FUNCTIONS = frozenset(
    {"function_declaration", "function_expression", "function", "arrow_function"}
    | {"method_definition", "generator_function", "generator_function_declaration"}
)
# Functions around a handler past this many leave it unclassified, which keeps a lookup's cost
# constant.
_MAX_SCOPES = 32
_TS_DECLARATIONS = frozenset(
    {"function_declaration", "class_declaration", "generator_function_declaration"}
)
_TS_BINDERS = frozenset({"variable_declarator", "assignment_expression"})


def _bind(names: _Names, name: str, binding: tuple[str, str]) -> None:
    names.setdefault(name, {})[binding] = None


class _View(Mapping[str, tuple[tuple[str, str], ...]]):
    """What names hold in one function: what it binds them to, over what the functions around
    it bind and then the module. A name the function binds otherwise, such as a parameter,
    hides the bindings around it."""

    def __init__(self, outer: _View | None, module: Bindings, depth: int = 0) -> None:
        self.outer, self.module, self.depth = outer, module, depth
        self.own: _Names = {}
        self.hidden: set[str] = set()

    def __getitem__(self, name: str) -> tuple[tuple[str, str], ...]:
        found: dict[tuple[str, str], None] = {}
        view: _View | None = self
        while view is not None:
            found.update(view.own.get(name, {}))
            if name in view.hidden:
                break
            view = view.outer
        else:
            found.update(dict.fromkeys(self.module.get(name, ())))
        if not found:
            raise KeyError(name)
        return tuple(found)

    def is_global(self, name: str) -> bool:
        view: _View | None = self
        while view is not None:
            if name in view.hidden or name in view.own:
                return False
            view = view.outer
        return name not in self.module

    def __iter__(self) -> Iterator[str]:
        names: set[str] = set(self.module)
        view: _View | None = self
        while view is not None:
            names.update(view.own)
            view = view.outer
        return iter(name for name in names if name in self)

    def __len__(self) -> int:
        return sum(1 for _ in self)


@dataclass
class TypeScriptNames:
    """What a file's names are bound to, by ``import``, ``require`` or a value taken from a
    bound name. The module's bindings reach every handler, and a function's only the
    handlers inside it, so one handler's names never reach another's."""

    module: dict[str, tuple[tuple[str, str], ...]]
    functions: dict[int, Node] = field(default_factory=dict)
    outer: dict[int, int | None] = field(default_factory=dict)  # Each function's enclosing one.
    declared: dict[int | None, list[Node]] = field(default_factory=dict)  # In source order.
    _views: dict[int | None, _View] = field(default_factory=dict)

    def view(self, function: int | None) -> _View:
        """What names hold in ``function``'s own scope, or the module's for None; past
        ``_MAX_SCOPES`` functions around it, ``_TooManyTargetsError``."""
        pending: list[int] = []
        current = function
        while current is not None and current not in self._views:
            pending.append(current)
            current = self.outer.get(current)
            if len(pending) > _MAX_SCOPES:
                raise _TooManyTargetsError
        if current is None and None not in self._views:
            self._views[None] = _View(None, self.module)
        for scope in reversed(pending):
            outer = self._views[self.outer.get(scope)]
            if outer.depth >= _MAX_SCOPES:
                raise _TooManyTargetsError
            node = self.functions[scope]
            self._views[scope] = _ts_scope(node, self.declared.get(scope, []), outer)
        return self._views[function]

    def handler(self, handler: Node, skip: frozenset[int]) -> _View:
        """What names hold in a handler: what the functions around it bind, and what every
        declarator in its body binds, nested ones too, except in another tool's handler."""
        declarators: list[Node] = []
        stack, visited = [handler], 0
        while stack:
            node = stack.pop()
            visited += 1
            if visited > MAX_BODY_NODES:
                raise _TooManyTargetsError
            if node.type in _TS_BINDERS:
                declarators.append(node)
            stack.extend(child for child in node.named_children if child.id not in skip)
        declarators.sort(key=lambda node: node.start_byte)
        return _ts_scope(handler, declarators, self.view(self.outer.get(handler.id)))


def typescript_imports(nodes: Iterable[Node]) -> TypeScriptNames:
    """Every (module, export or '') a name is bound to by ``import``, by ``require`` or by
    a value taken from a bound name, for the scope that binds it. ``nodes`` starts with the
    root. A second binding adds a candidate and never hides the first."""
    nodes = list(nodes)
    found = TypeScriptNames({})
    names: _Names = {}
    stack: list[tuple[Node, int | None]] = [(nodes[0], None)] if nodes else []
    while stack:
        node, function = stack.pop()
        if node.type == "import_statement":
            _bind_import(node, names)
        elif node.type in _TS_BINDERS:
            found.declared.setdefault(function, []).append(node)
        if node.type in _TS_FUNCTIONS:
            found.functions[node.id] = node
            found.outer[node.id] = function
            function = node.id
        stack.extend((child, function) for child in reversed(node.named_children))
    root = _View(None, {})
    top = _ts_top_declarations(nodes[0] if nodes else None, root.hidden)
    for declarator in found.declared.get(None, []):
        bound = _ts_declared(declarator, names)
        if not bound and declarator.id in top:
            root.hidden.update(_ts_bound_names(declarator.child_by_field_name("name")))
        for name, binding in bound:
            _bind(names, name, binding)
    root.module = found.module = {name: tuple(bindings) for name, bindings in names.items()}
    root.hidden.difference_update(found.module)
    found._views[None] = root
    return found


def _bind_import(node: Node, names: _Names) -> None:
    source = node.child_by_field_name("source")
    for clause in node.named_children:  # import cp = require("child_process")
        parts = clause.named_children if clause.type == "import_require_clause" else []
        if source is None and len(parts) == 2 and parts[0].type == "identifier":
            _bind(names, _ts_text(parts[0]), (_ts_module(_ts_text(parts[1]).strip("'\"`")), ""))
    if source is None:
        return
    module = _ts_module(_ts_text(source).strip("'\"`"))
    for clause in node.named_children:
        if clause.type != "import_clause":
            continue
        for part in clause.named_children:
            if part.type == "identifier":
                _bind(names, _ts_text(part), (module, ""))
            elif part.type == "namespace_import":
                for ident in part.named_children:
                    if ident.type == "identifier":
                        _bind(names, _ts_text(ident), (module, ""))
            elif part.type == "named_imports":
                for spec in part.named_children:
                    if spec.type != "import_specifier":
                        continue
                    imported = spec.child_by_field_name("name")
                    alias = spec.child_by_field_name("alias")
                    local = _ts_text(alias or imported)
                    _bind(names, local, (module, _ts_text(imported)))


def _ts_top_declarations(body: Node | None, hidden: set[str]) -> set[int]:
    """Collect names and variable declarators directly within this scope."""
    top: set[int] = set()
    for statement in (
        body.named_children
        if body is not None and body.type in {"statement_block", "program"}
        else []
    ):
        if statement.type == "export_statement":
            declaration = statement.child_by_field_name("declaration")
            if declaration is None:
                continue
            statement = declaration
        if statement.type in _TS_DECLARATIONS:
            declared = statement.child_by_field_name("name")
            if declared is not None:
                hidden.add(_ts_text(declared))
        elif statement.type in {"lexical_declaration", "variable_declaration"}:
            top.update(d.id for d in statement.named_children if d.type == "variable_declarator")
    return top


def _ts_scope(function: Node, declarators: list[Node], outer: _View) -> _View:
    """What names hold in a function. Its parameters, its own name and what its body declares
    at the top level otherwise than from a bound name hide the names around it; then each
    declarator, in source order, binds what its value holds."""
    view = _View(outer, outer.module, outer.depth + 1)
    view.hidden.update(_ts_parameters(function))
    if function.type in {"function_expression", "function", "generator_function"}:
        own = function.child_by_field_name("name")
        if own is not None:
            view.hidden.add(_ts_text(own))
    top = _ts_top_declarations(function.child_by_field_name("body"), view.hidden)
    for declarator in declarators:
        bound = _ts_declared(declarator, view)
        if not bound and declarator.id in top:
            view.hidden.update(_ts_bound_names(declarator.child_by_field_name("name")))
        for name, binding in bound:
            _bind(view.own, name, binding)
    return view


def _ts_declared(
    node: Node, names: Mapping[str, Iterable[tuple[str, str]]]
) -> list[tuple[str, tuple[str, str]]]:
    """What a declarator or an assignment binds its names to: a module it loads, as
    ``const run = require("child_process").execSync``, or what a value taken from a bound
    name holds. Destructuring binds each key, as ``const { execSync } = cp``."""
    assigned = node.type == "assignment_expression"
    target = node.child_by_field_name("left" if assigned else "name")
    value = _ts_unwrap(node.child_by_field_name("right" if assigned else "value"))
    if target is None or value is None:
        return []
    base: Node | None = value
    export = ""
    if value.type == "member_expression":
        export = _ts_text(value.child_by_field_name("property"))
        base = _ts_unwrap(value.child_by_field_name("object"))
    loaded = (
        _ts_loaded_module(base) if base is not None and base.type == "call_expression" else None
    )
    held = [(loaded, export)] if loaded is not None else _ts_derived(value, names)
    if target.type == "identifier":
        return [(_ts_text(target), binding) for binding in held]
    if target.type == "object_pattern":
        return [
            (local, (module, key))
            for module, held_export in held
            for local, key in _ts_destructured(target, held_export)
        ]
    return []


def _ts_destructured(pattern: Node, export: str) -> list[tuple[str, str]]:
    """The (local name, export) pairs destructuring a loaded module binds: a nested pattern
    binds its innermost key, as ``fs.promises.unlink`` acts as ``fs.unlink``."""
    found: list[tuple[str, str]] = []
    pending = [(pattern, export)]
    while pending:
        node, key = pending.pop()
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            name = _ts_text(node)
            found.append((name, name if node.type != "identifier" else key))
        elif node.type == "pair_pattern":
            value = node.child_by_field_name("value")
            if value is not None:
                pending.append((value, _ts_text(node.child_by_field_name("key")).strip("'\"`")))
        elif node.type in {"object_assignment_pattern", "assignment_pattern"}:
            left = node.child_by_field_name("left")
            if left is not None:
                pending.append((left, key))
        elif node.type == "rest_pattern":
            pending.extend((child, "") for child in node.named_children)
        elif node.type == "object_pattern":
            pending.extend((child, key) for child in node.named_children)
    return found


_TS_WRAPPED = frozenset(
    {"await_expression", "as_expression", "satisfies_expression", "non_null_expression"}
    | {"parenthesized_expression", "type_assertion"}
)


def _ts_unwrap(node: Node | None) -> Node | None:
    """The value under ``await``, a type assertion (``as``, ``satisfies``, ``<T>``, ``!``) or
    parentheses."""
    while node is not None and node.type in _TS_WRAPPED:
        children = node.named_children
        node = (
            (children[-1] if node.type == "type_assertion" else children[0]) if children else None
        )
    return node


# What calling an HTTP module returns that sends requests itself: a client or a request. A
# server, a response, headers, a form or an agent sends nothing.
_TS_HTTP_CLIENTS = {
    "axios": frozenset({"create", "Axios"}),
    "got": frozenset({"extend"}),
    "ky": frozenset({"create", "extend"}),
    "undici": frozenset({"Client", "Pool", "BalancedPool", "Agent", "ProxyAgent", "RetryAgent"}),
    "http": frozenset({"request", "get"}),
    "https": frozenset({"request", "get"}),
}


def _ts_derived(
    value: Node | None, names: Mapping[str, Iterable[tuple[str, str]]]
) -> list[tuple[str, str]]:
    """What a value taken from a bound name holds: another name for it, a member of it,
    ``promisify`` or ``.bind()`` of it, or what calling or constructing it returns, as in
    ``const run = cp.execSync``, ``const api = axios.create()`` or ``new Stripe(key)``. What
    calling an HTTP module returns holds it only when it is a client. Past ``_MAX_TARGETS``,
    one more binding is enough for a read of the name to be unclassified."""
    value = _ts_unwrap(value)
    called = value is not None and value.type in {"call_expression", "new_expression"}
    if called and value is not None:
        callee = value.child_by_field_name("function") or value.child_by_field_name("constructor")
        arguments = value.child_by_field_name("arguments")
        if _ts_chain(callee)[-1:] == ["promisify"]:
            value = arguments.named_children[0] if arguments and arguments.named_children else None
            called = False
        else:
            value = callee
    chain = _ts_chain(_ts_unwrap(value))
    if called and len(chain) > 1 and chain[-1] == "bind":  # ``f.bind(x)`` is ``f``
        chain, called = chain[:-1], False
    if not chain:
        return []
    head = chain[0]
    held = [(head.removeprefix(_MODULE_HEAD), "")] if head.startswith(_MODULE_HEAD) else []
    held = held or list(itertools.islice(names.get(head, ()), _MAX_TARGETS + 1))
    if not called:
        return held if len(chain) == 1 else [(module, chain[-1]) for module, _ in held]
    return [
        (module, export)
        for module, export in held
        if module not in _TS_HTTP
        or (chain[-1] if len(chain) > 1 else export) in _TS_HTTP_CLIENTS.get(module, ())
    ]


def _ts_loaded_module(call: Node) -> str | None:
    """The module a ``require("m")`` or ``import("m")`` call loads, or None."""
    callee = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    if callee is None or arguments is None or not arguments.named_children:
        return None
    loader = callee.type == "import" or (
        callee.type == "identifier" and _ts_text(callee) == "require"
    )
    first = arguments.named_children[0]
    if not loader or first.type != "string":
        return None
    return _ts_module(_ts_text(first).strip("'\"`"))


def _ts_chain(callee: Node | None) -> list[str]:
    """The names of a callee, outermost first, reading through calls, ``?.`` and ``(0, f)``;
    ``require("m").f`` starts with a module marker, and past ``MAX_CHAIN`` steps, nothing."""
    parts: list[str] = []
    node = callee
    steps = 0
    for _ in range(MAX_CHAIN * 8):
        if node is None:
            return []
        if node.type in {"member_expression", "subscript_expression", "call_expression"}:
            steps += 1
            if steps > MAX_CHAIN:
                return []
        if node.type in {"member_expression", "subscript_expression"}:
            prop = node.child_by_field_name("property") or node.child_by_field_name("index")
            parts.append(_ts_text(prop).strip("'\"`"))
            node = node.child_by_field_name("object")
        elif node.type == "call_expression":
            module = _ts_loaded_module(node)
            if module is not None:
                parts.append(_MODULE_HEAD + module)
                return list(reversed(parts))
            node = node.child_by_field_name("function")
        elif node.type in {"as_expression", "satisfies_expression"}:
            node = node.named_children[0] if node.named_children else None
        elif node.type in _TS_WRAPPED or node.type == "sequence_expression":
            node = node.named_children[-1] if node.named_children else None
        elif node.type in {"identifier", "this"}:
            parts.append(_ts_text(node))
            return list(reversed(parts))
        else:
            return []
    return []


def _ts_parameters(handler: Node) -> set[str]:
    """The names a handler's parameters bind, not their default values or types."""
    names: set[str] = set()
    parameters = handler.child_by_field_name("parameters") or handler.child_by_field_name(
        "parameter"
    )
    stack = [parameters] if parameters is not None else []
    while stack:
        node = stack.pop()
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            names.add(_ts_text(node))
        elif node.type in {"assignment_pattern", "object_assignment_pattern"}:
            left = node.child_by_field_name("left")
            if left is not None:
                stack.append(left)
        elif node.type in {"required_parameter", "optional_parameter"}:
            pattern = node.child_by_field_name("pattern")
            if pattern is not None:
                stack.append(pattern)
        elif node.type == "pair_pattern":
            value = node.child_by_field_name("value")
            if value is not None:
                stack.append(value)
        elif node.type != "type_annotation":
            stack.extend(node.named_children)
    return names


def _ts_method(options: Node | None) -> str:
    if options is None or options.type != "object":
        return ""
    for pair in options.named_children:
        if (
            pair.type == "pair"
            and _ts_text(pair.child_by_field_name("key")).strip("'\"") == "method"
        ):
            return _ts_text(pair.child_by_field_name("value")).strip("'\"`").upper()
    return ""


def _ts_property(node: Node) -> str:
    """The property ``a.b`` or ``a["b"]`` names, or '' for a computed one."""
    if node.type == "member_expression":
        return _ts_text(node.child_by_field_name("property"))
    index = node.child_by_field_name("index")
    return _ts_text(index).strip("'\"`") if index is not None and index.type == "string" else ""


def _ts_is_env(node: Node | None, bindings: _View) -> bool:
    """Whether ``node`` is ``process.env`` (or ``globalThis.process["env"]``), at constant depth."""
    if node is None or node.type not in {"member_expression", "subscript_expression"}:
        return False
    if _ts_property(node) != "env":
        return False
    obj = node.child_by_field_name("object")
    if obj is not None and obj.type == "identifier":
        name = _ts_text(obj)
        return (name == "process" and bindings.is_global(name)) or ("process", "") in bindings.get(
            name, ()
        )
    if obj is not None and obj.type in {"member_expression", "subscript_expression"}:
        base = obj.child_by_field_name("object")
        return (
            _ts_property(obj) == "process"
            and base is not None
            and base.type == "identifier"
            and _ts_text(base) in _TS_GLOBALS
            and bindings.is_global(_ts_text(base))
        )
    return False


def _ts_env_name(node: Node, bindings: _View) -> str | None:
    """The variable name of ``process.env.NAME`` or ``process.env["NAME"]``, else None."""
    if not _ts_is_env(node.child_by_field_name("object"), bindings):
        return None
    return _ts_property(node) or None


def _ts_bound_names(target: Node | None) -> list[str]:
    bound: list[str] = []
    pending = [target] if target is not None else []
    while pending:
        part = pending.pop()
        if part.type in {"identifier", "shorthand_property_identifier_pattern"}:
            bound.append(_ts_text(part))
        elif part.type in {"object_assignment_pattern", "assignment_pattern"}:
            left = part.child_by_field_name("left")
            if left is not None:
                pending.append(left)
            continue
        elif part.type == "pair_pattern":
            value = part.child_by_field_name("value")
            if value is not None:
                pending.append(value)
            continue
        pending.extend(part.named_children)
    return bound


def classify_typescript(
    handler: Node,
    names: TypeScriptNames,
    label: str,
    skip: frozenset[int] = frozenset(),
) -> ToolCapabilities:
    """Classify a handler by the calls in its syntax tree; ``skip`` holds other tools' ids."""
    seen = _Observed()
    parameters = frozenset(_ts_parameters(handler))
    try:
        imports = names.handler(handler, skip)
    except _TooManyTargetsError:
        return ToolCapabilities(unclassified=True)
    local = frozenset(imports.hidden)
    shadowed = parameters | local
    stack = [handler]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > MAX_BODY_NODES:
            return ToolCapabilities(unclassified=True)
        if node.type == "call_expression":
            try:
                _ts_call(node, imports, shadowed, parameters, seen)
            except _TooManyTargetsError:
                return ToolCapabilities(unclassified=True)
        elif node.type == "new_expression":
            constructor = _ts_chain(node.child_by_field_name("constructor"))
            if (
                constructor[-1:] == ["Function"]
                and (
                    len(constructor) == 1 or len(constructor) == 2 and constructor[0] in _TS_GLOBALS
                )
                and constructor[0] not in imports
                and constructor[0] not in shadowed
            ):
                seen.add(CapabilityClass.EXECUTE)
                seen.execute = True
        elif node.type in {"member_expression", "subscript_expression"}:
            name = _ts_env_name(node, imports)
            if name is not None and _secret_name(name):
                seen.add(CapabilityClass.CREDENTIALS)
        elif node.type == "variable_declarator":
            target, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if (
                target is not None
                and target.type == "object_pattern"
                and _ts_is_env(value, imports)
            ):
                for part in target.named_children:
                    key = (
                        part.child_by_field_name("key") or part.child_by_field_name("left") or part
                    )
                    if key.type in {
                        "property_identifier",
                        "shorthand_property_identifier_pattern",
                        "string",
                    } and _secret_name(_ts_text(key).strip("'\"")):
                        seen.add(CapabilityClass.CREDENTIALS)
        stack.extend(child for child in node.named_children if child.id not in skip)
    return _finish(label, seen)


def _ts_call(
    node: Node,
    imports: Bindings,
    shadowed: frozenset[str],
    parameters: frozenset[str],
    seen: _Observed,
) -> None:
    """Classify one call against every binding its head may have."""
    chain = _ts_chain(node.child_by_field_name("function"))
    if not chain:
        return
    head, last = chain[0], chain[-1]
    if head in _TS_GLOBALS and head not in shadowed and len(chain) > 1:
        chain, head = chain[1:], chain[1]
    candidates: tuple[tuple[str, str], ...]
    if head.startswith(_MODULE_HEAD):
        candidates = ((head.removeprefix(_MODULE_HEAD), ""),)
    else:
        candidates = imports.get(head, ())
    if len(candidates) > _MAX_TARGETS:
        raise _TooManyTargetsError
    unbound_global = not candidates and head not in shadowed
    arguments = node.child_by_field_name("arguments")
    values = (
        [child for child in arguments.named_children if child.type != "comment"]
        if arguments is not None and arguments.type == "arguments"
        else []
    )
    evaluates = unbound_global and head in {"eval", "Function"} and len(chain) == 1
    if evaluates:
        seen.add(CapabilityClass.EXECUTE)
        seen.execute = True
    if unbound_global and head == "fetch" and len(chain) == 1:
        seen.add(CapabilityClass.NETWORK)
        method = _ts_method(values[1]) if len(values) > 1 else ""
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            seen.write()
    for module, export in candidates:
        resolved = ([export] if export else []) + chain[1:]
        name = resolved[-1] if resolved else last
        if module == "child_process" and name in _TS_EXECUTE:
            seen.add(CapabilityClass.EXECUTE)
            seen.execute = True
        if module == "fs":
            if name in _TS_FS_DELETE:
                seen.delete(CapabilityClass.FILESYSTEM)
            elif name in _TS_FS_WRITE:
                seen.write(CapabilityClass.FILESYSTEM)
        if module in _TS_HTTP and name not in _TS_HTTP_SERVER:
            seen.add(CapabilityClass.NETWORK)
            method = _ts_method(values[1]) if len(values) > 1 else ""
            if method in {"POST", "PUT", "PATCH", "DELETE"} or name in _HTTP_WRITE:
                seen.write()
    stripe_bound = any(module == "stripe" for module, _ in candidates)
    if last in {"sendMail", "sendEmail"} and len(chain) > 1:
        seen.add(CapabilityClass.NETWORK)
        seen.write()
    # A receiver named stripe, such as ``this.stripe``, unless the chain starts at a parameter.
    named = any(part.lower() == "stripe" for part in chain[:-2]) and head not in parameters
    if (
        (stripe_bound or named)
        and len(chain) >= 3
        and chain[-2] in _TS_PAYMENT_RESOURCES
        and last in _TS_PAYMENT_WRITE
    ):
        seen.add(CapabilityClass.NETWORK)
        seen.write(CapabilityClass.PAYMENT)
        seen.payment = True
