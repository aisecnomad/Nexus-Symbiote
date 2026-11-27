"""Capabilities a source-declared tool body names, recorded only where they raise risk.

A tool the ``mcp`` collector records from a Python decorator or a TypeScript registration is
classified by the calls in its own body: process execution, network egress and whether it
sends data, filesystem writes and deletions, SQL statements, payment API writes and reads of
secret-named environment variables. Names are resolved only through the file's imports,
names bound from an imported call or name, and builtins, by the language's scoping rules: a
Python name a function binds anywhere in its body is local to it, so a parameter, a local
function or a loop target named like a module names nothing. Nothing is executed or
imported.

The classifier cannot show that a body does nothing else, because it does not follow
helpers, dynamic dispatch or other files. It therefore records only what raises risk and
never ``read`` or ``read-only``: a tool whose body names only reads, or nothing it knows,
keeps no declaration and stays unknown, which the trifecta and graph rules treat as not
safe. A body past the size bound is not classified and records a coverage gap.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from nexus_symbiote.core.enums import CapabilityClass, RiskSeverity, SideEffectProfile
from nexus_symbiote.core.models import CapabilityDeclaration, RiskAssessment
from nexus_symbiote.trifecta import _SECRET_ENV_KEY_RE

if TYPE_CHECKING:
    from tree_sitter import Node

CATEGORY = "capability_scope"
EVIDENCE = "source-body-call-names"
MAX_BODY_NODES = 20_000
UNCLASSIFIED = "tool body too large to classify its capabilities"

_RISK_CAPABILITIES = frozenset(
    {CapabilityClass.EXECUTE, CapabilityClass.WRITE, CapabilityClass.DESTRUCTIVE}
    | {CapabilityClass.PAYMENT, CapabilityClass.NETWORK, CapabilityClass.CREDENTIALS}
)

# ---- Python -------------------------------------------------------------------------------
_PY_BUILTINS = frozenset({"eval", "exec", "open"})
_PY_EXECUTE = frozenset(
    {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}
    | {"subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput", "pty.spawn"}
    | {"os.system", "os.popen", "os.execl", "os.execle", "os.execlp", "os.execv", "os.execve"}
    | {"os.execvp", "os.execvpe", "os.spawnl", "os.spawnv", "os.spawnvp", "os.posix_spawn"}
    | {"os.posix_spawnp", "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec"}
    | {"eval", "exec"}
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
_DB_MODULES = frozenset(
    {"sqlite3", "sqlalchemy", "psycopg", "psycopg2", "pymysql", "mysql", "asyncpg", "duckdb"}
)
_DB_RECEIVERS = frozenset({"cursor", "cur", "conn", "connection", "engine", "session", "db"})
_DB_EXECUTE = frozenset({"execute", "executemany", "executescript", "exec_driver_sql"})
_SQL_TEXT = frozenset({"sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text"})
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
# SQL operations count where a statement or subquery starts, and only with the clause they
# need, so prose that starts with the word, such as "update my profile", names nothing.
_SQL_WRITES = frozenset(
    {"INSERT", "REPLACE", "MERGE", "UPDATE", "ALTER", "CREATE", "GRANT", "REVOKE"}
)
_SQL_DESTRUCTIVE = frozenset({"DELETE", "DROP", "TRUNCATE"})
_SQL_OPERATIONS = _SQL_WRITES | _SQL_DESTRUCTIVE
_SQL_CLAUSE = {
    "INSERT": "INTO",
    "REPLACE": "INTO",
    "MERGE": "INTO",
    "UPDATE": "SET",
    "DELETE": "FROM",
}
_SQL_DDL = frozenset({"ALTER", "CREATE", "DROP"})
_SQL_OBJECTS = frozenset(
    {"TABLE", "VIEW", "INDEX", "DATABASE", "SCHEMA", "SEQUENCE", "FUNCTION", "PROCEDURE"}
    | {"TRIGGER", "TYPE", "USER", "ROLE", "EXTENSION", "MATERIALIZED", "UNIQUE", "TEMP"}
    | {"TEMPORARY", "OR", "IF", "GLOBAL", "LOCAL", "VIRTUAL", "UNLOGGED", "COLUMN"}
    | {"CONSTRAINT", "POLICY", "DOMAIN", "OWNED"}
)
# Words after which the next word still starts the statement.
_SQL_PREFIXES = frozenset({"EXPLAIN", "ANALYZE", "VERBOSE", "BEGIN", "DO"})
_SQL_WORD = re.compile(r"[^\W\d]\w*")

# ---- TypeScript ---------------------------------------------------------------------------
_TS_EXECUTE = frozenset(
    {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"}
)
_TS_FS_WRITE = frozenset(
    {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "copyFile", "copyFileSync"}
    | {"rename", "renameSync", "mkdir", "mkdirSync", "createWriteStream"}
)
_TS_FS_DELETE = frozenset({"rm", "rmSync", "unlink", "unlinkSync", "rmdir", "rmdirSync"})
_TS_HTTP = frozenset({"axios", "node-fetch", "got", "undici", "ky", "http", "https"})
_TS_SQL = frozenset(
    {"query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe", "queryRaw"}
)
_TS_PAYMENT_RESOURCES = frozenset({"refunds", "charges", "paymentIntents", "payouts", "transfers"})
_TS_PAYMENT_WRITE = frozenset({"create", "confirm", "capture"})
_TS_GLOBALS = frozenset({"globalThis", "window", "global", "self"})
_TS_HTTP_SERVER = frozenset({"createServer", "Server", "listen", "STATUS_CODES"})
# A callee chain longer than this is not an API call; it names nothing, in constant time.
MAX_CHAIN = 16
# Nodes read to decide whether one SQL argument uses a parameter; past it, assume it does.
_MAX_USE_NODES = 256
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
    raw_sql: bool = False
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
    if seen.raw_sql:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category=CATEGORY,
                detail=f"Tool '{label}' passes a caller-supplied statement to a database.",
                recommendation="Parameterize queries and restrict the tool to read-only access.",
            )
        )
    if seen.payment:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category=CATEGORY,
                detail=f"Tool '{label}' performs a financial transaction.",
                recommendation="Require human approval and bound amounts for payment tools.",
            )
        )
    if seen.payment:
        profile = SideEffectProfile.FINANCIAL_TRANSACTION
    elif seen.destructive or seen.raw_sql:
        profile = SideEffectProfile.DESTRUCTIVE
    elif seen.writes or seen.execute:
        profile = SideEffectProfile.STATE_MODIFYING
    else:
        profile = SideEffectProfile.UNKNOWN
    return ToolCapabilities(
        capabilities=sorted(seen.capabilities, key=lambda c: c.value), profile=profile, risks=risks
    )


def _secret_name(name: str) -> bool:
    return bool(name) and bool(_SECRET_ENV_KEY_RE.search(name))


def _sql_tokens(text: str) -> list[str]:
    """Upper-cased words and ``(``, ``)``, ``;`` outside literals, quoted names and comments."""
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char in "'\"`":
            # A doubled quote stays inside; an unterminated literal runs to the end.
            end = i + 1
            while (end := text.find(char, end)) >= 0 and text.startswith(char, end + 1):
                end += 2
            i = n if end < 0 else end + 1
        elif text.startswith("--", i):
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif char in "();":
            tokens.append(char)
            i += 1
        elif word := _SQL_WORD.match(text, i):
            tokens.append(word.group().upper())
            i = word.end()
        else:
            i += 1
    return tokens


def _sql_effect(text: str | None) -> str | None:
    """``destructive``, ``write`` or None: what the statements in ``text`` do.

    Words in literals, quoted names and comments count for nothing, and an operation counts
    only where a statement or a parenthesized subquery starts, with the clause it needs, so
    ``SELECT ... FOR UPDATE`` and ``ON DELETE CASCADE`` name nothing.
    """
    if not text:
        return None
    operations: set[str] = set()
    tokens = _sql_tokens(text)
    begin = 0
    for end in [*(k for k, part in enumerate(tokens) if part == ";"), len(tokens)]:
        statement, begin = tokens[begin:end], end + 1
        words = set(statement)
        common_table = bool(statement) and statement[0] == "WITH"
        start, depth = True, 0
        for k, word in enumerate(statement):
            if word == "(":
                start, depth = True, depth + 1
                continue
            if word == ")":
                depth = max(depth - 1, 0)
                start = common_table and depth == 0
                continue
            if start and word in _SQL_PREFIXES:
                continue
            if start and word in _SQL_OPERATIONS:
                clause = _SQL_CLAUSE.get(word)
                following = statement[k + 1] if k + 1 < len(statement) else ""
                if clause is not None:
                    shaped = clause in words
                else:
                    shaped = word not in _SQL_DDL or following in _SQL_OBJECTS
                if shaped:
                    operations.add(word)
                    if word == "ALTER" and "DROP" in words:
                        operations.add("DROP")
            start = False
    if operations & _SQL_DESTRUCTIVE:
        return "destructive"
    return "write" if operations else None


# ---- Python -------------------------------------------------------------------------------


_PY_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_PY_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_PY_SCOPES = (*_PY_FUNCTIONS, ast.ClassDef, *_PY_COMPREHENSIONS)
_SCOPE_KINDS = {ast.ClassDef: "class", **dict.fromkeys(_PY_COMPREHENSIONS, "comprehension")}
# Distinct targets one name may have in one scope. Past it, a tool that reads the name is
# unclassified, so piling up bindings cannot crowd out the one that raises risk.
_MAX_TARGETS = 32

# A path a name may hold and whether it is reached through a call: after
# ``conn = sqlite3.connect(db)``, ``conn`` is ``("sqlite3.connect", True)``.
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
    """Every binding a module's names have, scope by scope, read as Python reads them.

    A name a function binds anywhere in its own body (a parameter, an assignment, a loop,
    ``with`` or ``except`` target, an ``import``, a ``def`` or a ``class``) is local to it, so
    a read in that function sees only those bindings, never an import of the same name in
    the module or in another function. A module-level name may hold any of its bindings, or
    the builtin when none ran. Every binding is kept, so a second binding adds a target and
    never hides the first. Built in one pass per file; an assigned value is resolved against
    the bindings made before it.
    """

    def __init__(self, tree: ast.AST | None = None) -> None:
        self.module = _Scope("module")
        self._scopes: dict[ast.AST, _Scope] = {}
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
        """What ``dotted`` may name where ``scope`` reads it, and whether a binding names nothing.

        Raises ``_TooManyTargetsError`` when its head has more targets than the bound.
        """
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


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _PythonBody:
    """A tool's parameters and the values its body assigns, for the SQL it passes on."""

    def __init__(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        nodes: list[ast.AST],
        scopes: PythonScopes,
    ) -> None:
        self.scopes = scopes
        arguments = function.args
        self.parameters = {
            a.arg for a in arguments.posonlyargs + arguments.args + arguments.kwonlyargs
        }
        for extra in (arguments.vararg, arguments.kwarg):
            if extra is not None:
                self.parameters.add(extra.arg)
        self.values: dict[str, ast.expr] = {}
        for node in nodes:
            targets: list[tuple[ast.expr, ast.expr | None]] = []
            if isinstance(node, ast.Assign):
                targets = [(target, node.value) for target in node.targets]
            elif isinstance(node, ast.AnnAssign):
                targets = [(node.target, node.value)]
            elif isinstance(node, ast.With | ast.AsyncWith):
                targets = [(i.optional_vars, i.context_expr) for i in node.items if i.optional_vars]
            for target, value in targets:
                if isinstance(target, ast.Name) and value is not None:
                    self.values[target.id] = value

    def unwrap(self, node: ast.AST | None, scope: _Scope) -> ast.AST | None:
        """The text a SQLAlchemy ``text()`` wraps, through ``.bindparams()`` and the like."""
        base = node
        for _ in range(MAX_CHAIN):
            if not isinstance(base, ast.Call):
                return node
            chain = _chain(base.func)
            if chain is not None and any(
                path in _SQL_TEXT for path, _ in self.scopes.resolve(scope, chain)[0]
            ):
                return base.args[0] if base.args else None
            if not isinstance(base.func, ast.Attribute):
                return node
            base = base.func.value
        return node

    def caller_supplied(self, node: ast.AST | None, scope: _Scope, depth: int = 0) -> bool:
        """A statement that is a parameter, or text built from one."""
        if node is None:
            return False
        if isinstance(node, ast.Name):
            if node.id in self.parameters:
                return True
            value = self.unwrap(self.values.get(node.id), scope)
            return depth == 0 and value is not None and self.caller_supplied(value, scope, 1)
        if isinstance(node, ast.JoinedStr):
            interpolated = set().union(
                *(_names_in(p) for p in node.values if isinstance(p, ast.FormattedValue))
            )
            return bool(interpolated & self.parameters)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            return bool(_names_in(node) & self.parameters)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            arguments = [*node.args, *(k.value for k in node.keywords)]
            return bool(set().union(*(_names_in(a) for a in arguments)) & self.parameters)
        return False

    def statement_text(self, node: ast.AST | None, scope: _Scope) -> str | None:
        if isinstance(node, ast.Name) and node.id in self.values:
            node = self.unwrap(self.values[node.id], scope)
        return _literal(node)


def _open_mode(call: ast.Call) -> str | None:
    modes = list(call.args[1:2]) + [k.value for k in call.keywords if k.arg == "mode"]
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
    nodes: list[tuple[ast.AST, _Scope]] = []
    own = scopes.scope(function)
    pending: list[tuple[ast.AST, _Scope]] = [(s, own) for s in reversed(function.body)]
    while pending:
        node, scope = pending.pop()
        nodes.append((node, scope))
        if len(nodes) > MAX_BODY_NODES:
            return ToolCapabilities(unclassified=True)
        pending.extend(reversed(scopes.children(node, scope)))
    body = _PythonBody(function, [node for node, _ in nodes], scopes)
    seen = _Observed()
    try:
        for node, scope in nodes:
            _python_node(node, scope, scopes, body, seen)
    except _TooManyTargetsError:
        return ToolCapabilities(unclassified=True)
    return _finish(label or function.name, seen)


def _python_node(
    node: ast.AST, scope: _Scope, scopes: PythonScopes, body: _PythonBody, seen: _Observed
) -> None:
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
    receiver = written.split(".")[0] if "." in written else ""
    if unresolved:
        last = written.rsplit(".", 1)[-1]
        if last in _FS_WRITE:
            seen.write(CapabilityClass.FILESYSTEM)
        elif last in _FS_DELETE:
            seen.delete(CapabilityClass.FILESYSTEM)
        elif last in _DB_EXECUTE and receiver in _DB_RECEIVERS:
            _python_sql(node, scope, body, seen)
    for name, via_call in names:
        _python_call(node, scope, name, through_call or via_call, receiver, body, seen)


def _python_call(
    node: ast.Call,
    scope: _Scope,
    name: str,
    through_call: bool,
    receiver: str,
    body: _PythonBody,
    seen: _Observed,
) -> None:
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
    if module in _PAYMENT_MODULES and not set(parts) & _PAYMENT_LOCAL and last[:1].islower():
        seen.add(CapabilityClass.NETWORK)
        if last in _PAYMENT_WRITE and (
            set(parts) & _PAYMENT_RESOURCES or ("Invoice" in parts and last == "pay")
        ):
            seen.write(CapabilityClass.PAYMENT)
            seen.payment = True
    if name == "open":
        mode = _open_mode(node)
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
    # Building a statement, such as SQLAlchemy's ``text()``, is not running it.
    if last in _DB_EXECUTE and (module in _DB_MODULES or receiver in _DB_RECEIVERS):
        _python_sql(node, scope, body, seen)
    if name in {"os.getenv", "os.environ.get"}:
        key = _literal(node.args[0]) if node.args else None
        if key is not None and _secret_name(key):
            seen.add(CapabilityClass.CREDENTIALS)


def _python_sql(call: ast.Call, scope: _Scope, body: _PythonBody, seen: _Observed) -> None:
    statement = body.unwrap(call.args[0] if call.args else None, scope)
    if body.caller_supplied(statement, scope):
        seen.raw_sql = True
        seen.delete()
        return
    _sql_record(_sql_effect(body.statement_text(statement, scope)), seen)


def _sql_record(effect: str | None, seen: _Observed) -> None:
    if effect == "destructive":
        seen.delete()
    elif effect == "write":
        seen.write()


# ---- TypeScript ---------------------------------------------------------------------------


def _ts_text(node: Node | None) -> str:
    return (node.text or b"").decode("utf-8", "replace") if node is not None else ""


def _ts_module(specifier: str) -> str:
    module = specifier.removeprefix("node:")
    return module.split("/", 1)[0] if not module.startswith("@") else module


Bindings = Mapping[str, tuple[tuple[str, str], ...]]


def _bind(names: dict[str, list[tuple[str, str]]], name: str, binding: tuple[str, str]) -> None:
    known = names.setdefault(name, [])
    if binding not in known:
        known.append(binding)


def typescript_imports(nodes: Iterable[Node]) -> dict[str, tuple[tuple[str, str], ...]]:
    """Every (module, export or '') a name is bound to by ``import`` or ``require``.

    A name keeps every binding the file gives it, in any scope, so a second binding, such
    as an unused ``require`` of the same name elsewhere, adds a candidate and never hides
    the first.
    """
    nodes = list(nodes)
    names: dict[str, list[tuple[str, str]]] = {}
    for node in nodes:
        if node.type == "import_statement":
            source = node.child_by_field_name("source")
            if source is None:
                continue
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
        elif node.type == "variable_declarator":
            target = node.child_by_field_name("name")
            value = _ts_unwrap_await(node.child_by_field_name("value"))
            if target is None or value is None:
                continue
            export = ""
            if value.type == "member_expression":
                # const run = require("child_process").execSync
                export = _ts_text(value.child_by_field_name("property"))
                value = _ts_unwrap_await(value.child_by_field_name("object"))
            loaded = (
                _ts_loaded_module(value)
                if value is not None and value.type == "call_expression"
                else None
            )
            if loaded is None:
                continue
            if target.type == "identifier":
                _bind(names, _ts_text(target), (loaded, export))
            elif target.type == "object_pattern":
                for local, key in _ts_destructured(target, export):
                    _bind(names, local, (loaded, key))
    _bind_promisified(nodes, names)
    return {name: tuple(bindings) for name, bindings in names.items()}


def _ts_destructured(pattern: Node, export: str) -> list[tuple[str, str]]:
    """The (local name, export) pairs destructuring a loaded module binds.

    ``{ execSync: run = fallback }`` binds ``run`` to ``execSync``; a nested pattern binds
    to its innermost key, as ``fs.promises.unlink`` acts as ``fs.unlink``; ``...rest`` binds
    the module itself.
    """
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


def _ts_unwrap_await(node: Node | None) -> Node | None:
    while node is not None and node.type == "await_expression":
        node = node.named_children[0] if node.named_children else None
    return node


def _bind_promisified(nodes: Iterable[Node], names: dict[str, list[tuple[str, str]]]) -> None:
    """``const run = promisify(exec)`` runs what ``exec`` runs."""
    for node in nodes:
        if node.type != "variable_declarator":
            continue
        target, value = node.child_by_field_name("name"), node.child_by_field_name("value")
        if target is None or target.type != "identifier" or value is None:
            continue
        if value.type != "call_expression":
            continue
        callee = _ts_text(value.child_by_field_name("function"))
        arguments = value.child_by_field_name("arguments")
        if callee not in {"promisify", "util.promisify"} or arguments is None:
            continue
        first = arguments.named_children[0] if arguments.named_children else None
        if first is not None and first.type == "identifier" and _ts_text(first) in names:
            for binding in list(names[_ts_text(first)]):
                _bind(names, _ts_text(target), binding)


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
    """The names of a callee, outermost first, reading through calls, ``?.`` and ``(0, f)``.

    A chain loaded straight from a module, such as ``require("m").f``, starts with a
    module marker. A chain of more than ``MAX_CHAIN`` steps names nothing, so every node of
    a long chain costs constant time.
    """
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
        elif node.type in {
            "await_expression",
            "parenthesized_expression",
            "non_null_expression",
            "sequence_expression",
        }:
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


def _ts_uses(node: Node, parameters: set[str], *, assume: bool = True) -> bool:
    """Whether ``node`` reads a parameter; past ``_MAX_USE_NODES`` nodes, ``assume``."""
    if not parameters:
        return False
    stack = [node]
    budget = _MAX_USE_NODES
    while stack:
        budget -= 1
        if budget < 0:
            return assume
        current = stack.pop()
        if current.type in {"identifier", "shorthand_property_identifier"}:
            if _ts_text(current) in parameters:
                return True
        elif current.type == "member_expression":
            obj = current.child_by_field_name("object")
            if obj is not None:
                stack.append(obj)
            continue
        stack.extend(current.named_children)
    return False


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


def _ts_is_env(node: Node | None) -> bool:
    """Whether ``node`` is ``process.env`` (or ``globalThis.process["env"]``), at constant depth."""
    if node is None or node.type not in {"member_expression", "subscript_expression"}:
        return False
    if _ts_property(node) != "env":
        return False
    obj = node.child_by_field_name("object")
    if obj is not None and obj.type == "identifier":
        return _ts_text(obj) == "process"
    if obj is not None and obj.type in {"member_expression", "subscript_expression"}:
        base = obj.child_by_field_name("object")
        return (
            _ts_property(obj) == "process"
            and base is not None
            and base.type == "identifier"
            and _ts_text(base) in _TS_GLOBALS
        )
    return False


def _ts_env_name(node: Node) -> str | None:
    """The variable name of ``process.env.NAME`` or ``process.env["NAME"]``, else None."""
    if not _ts_is_env(node.child_by_field_name("object")):
        return None
    return _ts_property(node) or None


def _ts_import_binding(value: Node | None) -> bool:
    """Whether a declarator binds a module or a promisified export, as imports do."""
    value = _ts_unwrap_await(value)
    if value is not None and value.type == "member_expression":
        value = _ts_unwrap_await(value.child_by_field_name("object"))
    if value is None or value.type != "call_expression":
        return False
    callee = _ts_text(value.child_by_field_name("function"))
    return _ts_loaded_module(value) is not None or callee in {"promisify", "util.promisify"}


def _ts_locals(handler: Node, parameters: set[str], skip: frozenset[int]) -> set[str] | None:
    """Names the handler's body binds at its top level, which shadow imports and globals.

    Only a declaration directly in the body shadows, so a binding in a nested block or a
    dead branch cannot hide a call. A local bound from a parameter anywhere in the body,
    such as ``const { id } = args``, is added to ``parameters`` so SQL built from it is
    caller-supplied. None past the node bound.
    """
    names: set[str] = set()
    body = handler.child_by_field_name("body")
    if body is not None and body.type == "statement_block":
        for statement in body.named_children:
            if statement.type in {"function_declaration", "class_declaration"}:
                name = statement.child_by_field_name("name")
                if name is not None:
                    names.add(_ts_text(name))
            elif statement.type in {"lexical_declaration", "variable_declaration"}:
                for declarator in statement.named_children:
                    value = declarator.child_by_field_name("value")
                    if declarator.type == "variable_declarator" and not _ts_import_binding(value):
                        names.update(_ts_bound_names(declarator.child_by_field_name("name")))
    stack = [handler]
    visited = 0
    declarators: list[Node] = []
    while stack:
        node = stack.pop()
        visited += 1
        if visited > MAX_BODY_NODES:
            return None
        if node.type == "variable_declarator":
            declarators.append(node)
        stack.extend(child for child in node.named_children if child.id not in skip)
    for node in sorted(declarators, key=lambda n: n.start_byte):
        value = node.child_by_field_name("value")
        if value is not None and _ts_uses(value, parameters, assume=False):
            parameters.update(_ts_bound_names(node.child_by_field_name("name")))
    return names


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
    imports: Bindings,
    label: str,
    skip: frozenset[int] = frozenset(),
) -> ToolCapabilities:
    """Classify a TypeScript or JavaScript handler by the calls in its syntax tree.

    ``skip`` holds the ids of nested handlers that belong to other tools.
    """
    seen = _Observed()
    parameters = _ts_parameters(handler)
    local = _ts_locals(handler, parameters, skip)
    if local is None:
        return ToolCapabilities(unclassified=True)
    imports = {name: bound for name, bound in imports.items() if name not in local}
    shadowed = parameters | local
    stack = [handler]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > MAX_BODY_NODES:
            return ToolCapabilities(unclassified=True)
        if node.type == "call_expression":
            _ts_call(node, imports, shadowed, parameters, seen)
        elif node.type == "new_expression":
            constructor = _ts_chain(node.child_by_field_name("constructor"))
            if (
                constructor[-1:] == ["Function"]
                and (len(constructor) == 1 or constructor[0] in _TS_GLOBALS)
                and "Function" not in imports
                and "Function" not in local
            ):
                seen.add(CapabilityClass.EXECUTE)
                seen.execute = True
        elif node.type in {"member_expression", "subscript_expression"}:
            name = _ts_env_name(node)
            if name is not None and _secret_name(name):
                seen.add(CapabilityClass.CREDENTIALS)
        elif node.type == "variable_declarator":
            target, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if target is not None and target.type == "object_pattern" and _ts_is_env(value):
                for part in target.named_children:
                    if part.type == "shorthand_property_identifier_pattern" and _secret_name(
                        _ts_text(part)
                    ):
                        seen.add(CapabilityClass.CREDENTIALS)
        stack.extend(child for child in node.named_children if child.id not in skip)
    return _finish(label, seen)


def _ts_call(
    node: Node,
    imports: Bindings,
    shadowed: set[str],
    parameters: set[str],
    seen: _Observed,
) -> None:
    """Classify one call against every binding its head may have.

    ``shadowed`` holds the names the handler binds itself.
    """
    chain = _ts_chain(node.child_by_field_name("function"))
    if not chain:
        return
    head, last = chain[0], chain[-1]
    if head in _TS_GLOBALS and len(chain) > 1:
        chain, head = chain[1:], chain[1]
    candidates: tuple[tuple[str, str], ...]
    if head.startswith(_MODULE_HEAD):
        candidates = ((head.removeprefix(_MODULE_HEAD), ""),)
    else:
        candidates = () if head in shadowed else imports.get(head, ())
    unbound_global = not candidates and head not in shadowed
    arguments = node.child_by_field_name("arguments")
    values = (
        [child for child in arguments.named_children if child.type != "comment"]
        if arguments is not None and arguments.type == "arguments"
        else []
    )
    evaluates = unbound_global and head == "eval" and len(chain) == 1
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
    if (
        (stripe_bound or head.lower() == "stripe")
        and len(chain) >= 3
        and chain[-2] in _TS_PAYMENT_RESOURCES
        and last in _TS_PAYMENT_WRITE
    ):
        seen.add(CapabilityClass.NETWORK)
        seen.write(CapabilityClass.PAYMENT)
        seen.payment = True
    if last in _TS_SQL and len(chain) > 1 and values:
        statement = values[0]
        interpolated = statement.type == "template_string" and any(
            part.type == "template_substitution" and _ts_uses(part, parameters)
            for part in statement.named_children
        )
        passed = statement.type == "identifier" and _ts_text(statement) in parameters
        if interpolated or passed:
            seen.raw_sql = True
            seen.delete()
        else:
            _sql_record(_sql_effect(_ts_literal_text(statement)), seen)


def _ts_literal_text(node: Node) -> str | None:
    """The text of a string or template literal, each substitution read as ``?``."""
    if node.type not in {"string", "template_string"}:
        return None
    parts: list[str] = []
    for child in node.named_children:
        if child.type == "string_fragment":
            parts.append(_ts_text(child))
        elif child.type == "escape_sequence":
            escaped = _ts_text(child)
            parts.append("\n" if escaped in {"\\n", "\\r"} else escaped[1:2])
        elif child.type == "template_substitution":
            parts.append(" ? ")
    return "".join(parts)
