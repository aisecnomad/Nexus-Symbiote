"""Capabilities a source-declared tool body names, recorded only where they raise risk.

A tool the ``mcp`` collector records from a Python decorator or a TypeScript registration is
classified by the calls in its own body: process execution, network egress and whether it
sends data, filesystem writes and deletions, SQL statements, payment API writes and reads of
secret-named environment variables. Names resolve only through the file's imports, names
bound from them and builtins, by the language's scoping rules; nothing is executed or
imported. The classifier cannot show that a body does nothing else, so it records only what
raises risk, never ``read`` or ``read-only``, and a body past a bound records a coverage gap.
"""

from __future__ import annotations

import ast
import bisect
import itertools
import re
from collections.abc import Iterable, Mapping
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
_SQL_CLAUSE = {"INSERT": "INTO", "REPLACE": "INTO", "MERGE": "INTO", "UPDATE": "SET"}
_SQL_CLAUSE["DELETE"] = "FROM"
_SQL_DDL = frozenset({"ALTER", "CREATE", "DROP"})
_SQL_OBJECTS = frozenset(
    {"TABLE", "VIEW", "INDEX", "DATABASE", "SCHEMA", "SEQUENCE", "FUNCTION", "PROCEDURE"}
    | {"TRIGGER", "TYPE", "USER", "ROLE", "EXTENSION", "MATERIALIZED", "UNIQUE", "TEMP"}
    | {"TEMPORARY", "OR", "IF", "GLOBAL", "LOCAL", "VIRTUAL", "UNLOGGED", "COLUMN"}
    | {"CONSTRAINT", "POLICY", "DOMAIN", "OWNED", "FOREIGN", "TABLESPACE", "SERVER", "EVENT"}
    | {"RULE", "ROUTINE", "AGGREGATE", "PUBLICATION", "SUBSCRIPTION", "GROUP", "COLLATION"}
    | {"LANGUAGE", "STATISTICS", "LOGIN", "SYNONYM", "CLUSTERED", "NONCLUSTERED", "FULLTEXT"}
    | {"SPATIAL", "DEFINER", "SYSTEM", "DEFAULT", "OPERATOR", "CAST", "CONVERSION", "TEXT"}
)
# Words after which the next word still starts the statement.
_SQL_PREFIXES = frozenset({"EXPLAIN", "ANALYZE", "ANALYSE", "VERBOSE", "BEGIN", "DO"})
# ``$`` continues a name, so ``a$b$`` is an identifier, not a dollar quote.
_SQL_WORD = re.compile(r"[\w$]+")
# Where a database call takes its statement when it is not the first argument.
_SQL_ARGUMENTS = frozenset({"statement", "query", "sql", "operation"})
_SQL_DOLLAR = re.compile(r"\$(?:[^\W\d]\w*)?\$")
_SQL_RANK = {None: 0, "write": 1, "destructive": 2}
# A literal or quoted name, by its opening character and whether a backslash escapes: a
# doubled closing character stays inside, and an unterminated one runs to the end.
_SQL_QUOTED = {
    (q, e): re.compile(
        rf"{re.escape(q)}(?:[^{re.escape(c)}{chr(92) * 2 if e else ''}]++|{re.escape(c) * 2}"
        + (r"|\\." if e else "")
        + rf")*+{re.escape(c)}?",
        re.S,
    )
    for q, c in (("'", "'"), ('"', '"'), ("`", "`"), ("[", "]"))
    for e in (False, True)
}

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
    | {"prepare"}
)
# SQLite-family and pg-promise statement methods, too common to count on a name alone.
_TS_SQL_CLIENT = frozenset(
    {"exec", "run", "all", "get", "each", "none", "one", "many", "any", "result", "batch"}
    | {"oneOrNone", "manyOrNone"}
)
# Clients that are themselves a tag running its template, as postgres.js's ``sql`...```.
_TS_TAGGED = frozenset({"postgres", "@vercel/postgres", "@neondatabase/serverless"})
# Methods that run the template they tag, as Prisma's ``prisma.$executeRaw`...```.
_TS_SQL_TAGS = _TS_SQL | {"$executeRaw", "$queryRaw"}
# A receiver ``query`` or ``execute`` is SQL on: a client from one of these modules, or by name.
_TS_DB_MODULES = frozenset(
    {"pg", "mysql", "mysql2", "sqlite3", "better-sqlite3", "postgres", "@prisma/client", "knex"}
    | {"sequelize", "drizzle-orm", "mssql", "kysely", "typeorm", "@vercel/postgres", "oracledb"}
    | {"@neondatabase/serverless", "@libsql/client", "@planetscale/database", "pg-promise"}
    | {"bun:sqlite"}
)
_TS_DB_RECEIVERS = frozenset(
    {"db", "pool", "client", "conn", "connection", "sql", "knex", "prisma", "tx", "trx"}
    | {"sequelize", "database", "cursor"}
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
                severity=RiskSeverity.HIGH,
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
    return bool(name) and bool(SECRET_ENV_KEY_RE.search(name))


def _sql_tokens(text: str, escapes: bool = False) -> list[str]:
    """Upper-cased words and ``(``, ``)``, ``;`` outside literals, quoted names and comments.
    With ``escapes``, a backslash escapes the next character in a literal and ``[name]`` is a
    quoted name, as in MySQL, PostgreSQL ``E''`` strings, SQLite and T-SQL."""
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char in "'\"`" or (escapes and char == "["):
            quoted = _SQL_QUOTED[char, escapes].match(text, i)
            i = quoted.end() if quoted else n
        elif text.startswith("--", i):
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif char in "();":
            tokens.append(char)
            i += 1
        elif tag := _SQL_DOLLAR.match(text, i):
            # PostgreSQL dollar quoting; ``$1`` is a parameter, not a quote.
            end = text.find(tag.group(), tag.end())
            i = n if end < 0 else end + len(tag.group())
        elif word := _SQL_WORD.match(text, i):
            tokens.append(word.group().upper())
            i = word.end()
        else:
            i += 1
    return tokens


def _sql_effect(text: str | None) -> str | None:
    """``destructive``, ``write`` or None: what the statements in ``text`` do, read with and
    without backslash escapes, whichever does more. An operation counts where a statement or
    subquery starts, with the clause it needs."""
    if not text:
        return None
    # The two readings differ only where a backslash or a bracket can open or escape text.
    modes = (False, True) if "\\" in text or "[" in text else (False,)
    effects = {_sql_operations(_sql_tokens(text, escapes)) for escapes in modes}
    return max(effects, key=lambda effect: _SQL_RANK[effect])


def _sql_operations(tokens: list[str]) -> str | None:
    operations: set[str] = set()
    begin = 0
    for end in [*(k for k, part in enumerate(tokens) if part == ";"), len(tokens)]:
        statement, begin = tokens[begin:end], end + 1
        words = set(statement)
        # The last ANALYZE (or ANALYSE) option is the one that applies.
        analyze = max(
            (k for k, w in enumerate(statement) if w in {"ANALYZE", "ANALYSE"}), default=-1
        )
        if statement[:1] == ["EXPLAIN"] and (
            analyze < 0 or statement[analyze + 1 : analyze + 2] in (["FALSE"], ["OFF"], ["0"])
        ):
            continue  # A plan: the statement it describes does not run.
        # Per depth, whether a ")" back to it starts a statement again: after a WITH clause's
        # last CTE, nested or not, and after EXPLAIN's options.
        restarts = [statement[:1] in (["WITH"], ["EXPLAIN"])]
        start, skip = True, 0
        for k, word in enumerate(statement):
            if k < skip:
                continue
            if word == "(":
                start = True
                restarts.append(False)
                continue
            if word == ")":
                restarts.pop() if len(restarts) > 1 else None
                start = restarts[-1]
                continue
            if start and word == "WITH":
                restarts[-1] = True
            if start and word in {"SEARCH", "CYCLE"} and "SET" in statement[k:]:
                # A recursive query's SEARCH or CYCLE clause ends at SET <name> [USING <name>].
                skip = statement.index("SET", k) + 2
                skip += 2 if statement[skip : skip + 1] == ["USING"] else 0
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


_PY_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_PY_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_PY_SCOPES = (*_PY_FUNCTIONS, ast.ClassDef, *_PY_COMPREHENSIONS)
_PY_LOOPS = (ast.For, ast.AsyncFor, ast.While, *_PY_COMPREHENSIONS)
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


_Key = tuple[_Scope, str]
# Where a binding takes effect, the statement that always makes it (None for one that may
# not run, such as a loop target), the value it binds and the scope that value is read in.
_Binding = tuple[ast.AST, ast.AST | None, ast.AST | None, _Scope]
# Whether a statement may be caller-supplied, and the rank of what its text does.
_Value = tuple[bool, int]
# A name's bindings in its own frame, each with where it starts and ends and where the block
# that always runs it ends; their starts; and what its bindings elsewhere may give it.
_Placed = tuple[list[tuple[int, int, int, _Binding]], list[int], _Value]


def _join(a: _Value, b: _Value) -> _Value:
    return a[0] or b[0], max(a[1], b[1])


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
        # Each name's bindings with the values they bind, under the scope that owns the name.
        self.bindings: dict[_Key, list[_Binding]] = {}
        self._statements: dict[ast.AST | None, tuple[int, list[_Key]]] = {}
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
        owners, builtin = self.lookup(scope, head)
        builtin = builtin and head in _PY_BUILTINS
        targets = [(dotted, False)] if builtin else []
        unresolved = not owners and not builtin
        for entry in (owner.names[head] for owner in owners):
            if entry.overflow:
                raise _TooManyTargetsError
            unresolved = unresolved or entry.unresolved
            targets.extend(
                (f"{path}.{rest}" if rest else path, call) for path, call in entry.targets
            )
        return targets, unresolved

    def lookup(self, scope: _Scope, name: str) -> tuple[list[_Scope], bool]:
        """The scopes whose bindings a read of ``name`` in ``scope`` may see, and whether a
        builtin may."""
        owners: list[_Scope] = []
        current: _Scope | None = scope
        own = True  # A class body reads its own names; a scope nested in it does not.
        while current is not None:
            if name in current.declared_global and current is not self.module:
                current, own = self.module, False
                continue
            if name in current.declared_nonlocal:
                current, own = current.parent, False
                continue
            if name in current.names and (own or current.kind != "class"):
                owners.append(current)
                if current.kind in {"function", "comprehension"}:
                    return owners, False
                if current.kind == "module":
                    return owners, True
            current, own = current.parent, False
        return owners, True

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
                        self._bind(inner, argument.arg, (), (argument, None, None, inner))
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
                self._assign(scope, target, node.value, where=node, statement=node)
        elif isinstance(node, ast.AnnAssign | ast.AugAssign):
            # ``sql += text`` binds the old statement with ``text`` added.
            value = node if isinstance(node, ast.AugAssign) else node.value
            self._assign(scope, node.target, value, where=node, statement=node)
        elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
            self._assign(scope, node.target, node)
        elif isinstance(node, ast.NamedExpr):
            # ``:=`` in a comprehension binds in the function or module around it.
            owner = scope
            while owner.kind == "comprehension" and owner.parent is not None:
                owner = owner.parent
            self._assign(owner, node.target, node.value, scope, where=node)
        elif isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                if item.optional_vars is not None:
                    self._assign(scope, item.optional_vars, item.context_expr, statement=node)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                self._assign(scope, target, None)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self._bind(scope, node.name, ())
        elif isinstance(node, ast.Match):
            # A capture is part of the subject.
            for part in (p for case in node.cases for p in ast.walk(case.pattern)):
                for name in (getattr(part, "name", None), getattr(part, "rest", None)):
                    if name:
                        self._bind(scope, name, (), (part, None, node.subject, scope))

    def _assign(
        self,
        scope: _Scope,
        target: ast.AST,
        value: ast.AST | None,
        reads: _Scope | None = None,
        where: ast.AST | None = None,
        statement: ast.AST | None = None,
    ) -> None:
        """Bind a name target to ``value``; each name an unpacking binds names nothing, and
        holds its own item of a literal of the same length, or else any part of the value."""
        reads = reads or scope
        pending: list[tuple[ast.AST, ast.AST | None]] = [(target, value)]
        while pending:
            node, source = pending.pop()
            if isinstance(node, ast.Name):
                bound = self._value(reads, source) if node is target else ()
                binding = None if source is None else (where or node, statement, source, reads)
                self._bind(scope, node.id, bound, binding)
            elif isinstance(node, ast.Tuple | ast.List):
                items: list[ast.AST | None] = [source] * len(node.elts)
                if isinstance(source, ast.Tuple | ast.List) and len(source.elts) == len(node.elts):
                    if not any(isinstance(i, ast.Starred) for i in (*source.elts, *node.elts)):
                        items = [*source.elts]
                pending.extend(zip(node.elts, items, strict=True))
            elif isinstance(node, ast.Starred):
                pending.append((node.value, source))

    def _value(self, scope: _Scope, value: ast.AST | None) -> tuple[_Target, ...] | None:
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

    def _bind(
        self,
        scope: _Scope,
        name: str,
        targets: tuple[_Target, ...] | None,
        binding: _Binding | None = None,
    ) -> None:
        if name in scope.declared_global:
            scope = self.module
        elif name in scope.declared_nonlocal:
            scope = self._enclosing(scope, name)
        if binding is not None and self.bindings.setdefault((scope, name), [])[-1:] != [binding]:
            self.bindings[scope, name].append(binding)
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

    def statement(self, node: ast.AST | None, scope: _Scope) -> tuple[int, list[_Key]]:
        """The rank of the SQL text ``node`` may evaluate to, with each alternative read on
        its own and any other part as ``?``, and the names that text is taken from."""
        if node in self._statements:
            return self._statements[node]
        names: set[str] = set()
        runs: list[list[str]] = [[]]
        pending: list[ast.AST | None] = [node]
        while pending:
            part = pending.pop()
            if part is None:
                runs.append([])
            elif isinstance(part, ast.Constant):
                runs[-1].append(part.value if isinstance(part.value, str) else "?")
            elif isinstance(part, ast.Name | ast.FormattedValue):
                names.update(_names_in(part))
                runs[-1].append("?")
            elif isinstance(part, ast.JoinedStr):
                pending.extend(reversed(part.values))
            elif isinstance(part, ast.BinOp) and isinstance(part.op, ast.Add):
                pending += [part.right, part.left]
            elif isinstance(part, ast.BinOp) and isinstance(part.op, ast.Mod):
                names.update(_names_in(part.right))
                pending.append(part.left)
            elif isinstance(
                part, ast.Attribute | ast.Subscript | ast.Starred | ast.Await | ast.NamedExpr
            ):
                pending.append(part.value)
            elif isinstance(part, ast.Call) and (text := self._wrapped(part, scope)) is not None:
                pending.append(text)
            elif isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute):
                # A method of the statement, such as ``.strip()`` or ``.bindparams(...)``;
                # ``.format()`` and ``.join()`` also take their arguments into the text.
                if part.func.attr in {"format", "join"}:
                    names.update(*map(_names_in, (*part.args, *part.keywords)))
                pending.append(part.func.value)
            elif isinstance(part, ast.AugAssign):
                pending += [part.value, part.target]
            elif isinstance(part, ast.For | ast.AsyncFor | ast.comprehension):
                pending.append(part.iter)
            elif (items := _alternatives(part)) is not None:
                pending.append(None)
                for item in reversed(items):
                    pending += [item, None]
            else:
                runs[-1].append("?")
        rank = max(_SQL_RANK[_sql_effect("".join(run))] for run in runs)
        keys = [(owner, name) for name in names for owner in self.lookup(scope, name)[0]]
        self._statements[node] = rank, keys
        return rank, keys

    def _wrapped(self, call: ast.Call, scope: _Scope) -> ast.AST | None:
        """The statement a SQLAlchemy ``text()`` call wraps; None for any other call."""
        chain = _chain(call.func)
        if chain is None or not any(p in _SQL_TEXT for p, _ in self.resolve(scope, chain)[0]):
            return None
        return next(iter(call.args), None) or next(
            (k.value for k in call.keywords if k.arg == "text"), None
        )


def _alternatives(node: ast.AST) -> list[ast.expr] | None:
    """The values a statement may be one of: either side of a conditional or ``or``, or an
    item of the literal or comprehension it is taken from; None for anything else."""
    if isinstance(node, ast.IfExp):
        return [node.body, node.orelse]
    if isinstance(node, ast.BoolOp | ast.Dict):
        return node.values
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return node.elts
    if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
        return [node.value if isinstance(node, ast.DictComp) else node.elt]
    return None


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
        elif isinstance(node, ast.Await):
            node = node.value
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
    """A tool body by program point, so a statement is read from the bindings that can
    reach the call that runs it."""

    def __init__(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        nodes: list[tuple[ast.AST, _Scope, int, int, int]],
        outer: dict[int, int],
        scopes: PythonScopes,
    ) -> None:
        self.scopes, self.outer, self.at = scopes, outer, 0  # ``at``: the node being read.
        self.frames = [frame for *_, frame, _ in nodes]
        self.loops = [loop for *_, loop in nodes]
        self.frame_of = {scope: frame for _, scope, _, frame, _ in nodes}
        # Nodes are in source order, so each subtree ends where the next one not in it starts.
        self.ends = list(range(1, len(nodes) + 1))
        for index in range(len(nodes) - 1, -1, -1):
            if (parent := nodes[index][2]) >= 0:
                self.ends[parent] = max(self.ends[parent], self.ends[index])
        self.position = {node: index for index, (node, *_) in enumerate(nodes)}
        self.stops: dict[int, int] = {}
        for loop in outer:  # A loop repeats to the end of its body; an else runs once, after.
            body = getattr(nodes[loop][0], "body", None)
            self.stops[loop] = self.ends[self.position[body[-1]] if body else loop]
        self.last: dict[ast.AST, ast.AST] = dict.fromkeys(function.body, function.body[-1])
        for node, *_ in nodes:
            for _, value in ast.iter_fields(node):
                if isinstance(value, list) and value and isinstance(value[-1], ast.stmt):
                    self.last.update(dict.fromkeys(value, value[-1]))
        a = function.args
        every = (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg)
        self.arguments = {p for p in every if p is not None and p.arg not in {"self", "cls"}}
        self.summaries: dict[_Key, _Value] = {}
        self._placed: dict[_Key, _Placed] = {}
        self._contributions: dict[_Binding, _Value] = {}

    def evaluate(self, node: ast.AST | None, scope: _Scope) -> _Value:
        """What the statement ``node`` may be where the current node runs."""
        rank, keys = self.scopes.statement(node, scope)
        value: _Value = (False, rank)
        for key in keys:
            if self.frame_of.get(key[0]) == self.frames[self.at]:
                value = _join(value, self.reaching(key))
            else:
                value = _join(value, self.summary(key))
        return value

    def reaching(self, key: _Key) -> _Value:
        """What ``key`` may hold at the current node, which runs in the frame that binds it.
        A binding there that always runs before the node hides the earlier ones, and one
        later in a loop the node is in reaches it on the next pass; a binding made in another
        frame, such as a ``nonlocal`` write in a closure, may reach it anywhere."""
        placed, starts, value = self._place(key)
        if len(placed) > _MAX_TARGETS:  # Past the bound every binding counts, in constant time.
            return self.summary(key)
        at, kill = self.at, -1
        for latest in range(bisect.bisect_right(starts, at) - 1, -1, -1):
            index, end, block, binding = placed[latest]
            if end <= at:
                value = _join(value, self.contribution(binding))
                if at < block:
                    kill = index
                    break
        start, stop, loop = -1, -1, self.loops[at]
        while loop > kill:  # The outermost loop around the node that has no kill in it.
            start, stop, loop = loop, self.stops[loop], self.outer[loop]
        low, high = bisect.bisect_right(starts, start), bisect.bisect_left(starts, stop)
        for _, end, _, binding in placed[low:high]:
            if end > at:
                value = _join(value, self.contribution(binding))
        return value

    def _place(self, key: _Key) -> _Placed:
        if key not in self._placed:
            frame, other = self.frame_of[key[0]], (False, 0)
            placed: list[tuple[int, int, int, _Binding]] = []
            for binding in self.scopes.bindings.get(key, ()):
                where, statement = binding[0], binding[1]
                index = -1 if where in self.arguments else self.position.get(where, -2)
                if index == -1:
                    placed.append((-1, 0, len(self.ends), binding))
                elif index >= 0 and self.frames[index] == frame:
                    block = self.ends[self.position[self.last[statement]]] if statement else -1
                    placed.append((index, self.ends[index], block, binding))
                else:
                    other = _join(other, self.contribution(binding))
            placed.sort(key=lambda entry: entry[0])
            self._placed[key] = placed, [entry[0] for entry in placed], other
        return self._placed[key]

    def contribution(self, binding: _Binding) -> _Value:
        """What one binding may give its name: its own text and what it is built from."""
        if binding not in self._contributions:
            rank, keys = self.scopes.statement(binding[2], binding[3])
            value = (binding[0] in self.arguments, rank)
            for key in keys:
                value = _join(value, self.summary(key))
            self._contributions[binding] = value
        return self._contributions[binding]

    def summary(self, key: _Key) -> _Value:
        """What ``key`` may hold anywhere: every binding of it and of the names it is built
        from, solved for every name reached at once so that a cycle reads every value."""
        if key not in self.summaries:
            found: dict[_Key, _Value] = {}
            users: dict[_Key, set[_Key]] = {}
            pending = [key]
            while pending:
                current = pending.pop()
                if current in found or current in self.summaries:
                    continue
                found[current] = (False, 0)
                for where, _, source, reads in self.scopes.bindings.get(current, ()):
                    rank, keys = self.scopes.statement(source, reads)
                    found[current] = _join(found[current], (where in self.arguments, rank))
                    for ref in keys:
                        users.setdefault(ref, set()).add(current)
                        pending.append(ref)
            queue = list(users)
            while queue:
                ref = queue.pop()
                known = self.summaries[ref] if ref in self.summaries else found[ref]
                for user in users.get(ref, ()):
                    if (joined := _join(found[user], known)) != found[user]:
                        found[user] = joined
                        queue.append(user)
            self.summaries.update(found)
        return self.summaries[key]


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
    # Each node with its scope and, by index, its parent, the frame it runs in (the function
    # or generator around it, or -1 for the tool's own) and the innermost loop around it in
    # that frame; each loop with the next one out in its frame.
    nodes: list[tuple[ast.AST, _Scope, int, int, int]] = []
    outer: dict[int, int] = {}
    own = scopes.scope(function)
    pending: list[tuple[ast.AST, _Scope, int, int, int]]
    pending = [(s, own, -1, -1, -1) for s in reversed(function.body)]
    while pending:
        node, scope, _, frame, loop = entry = pending.pop()
        nodes.append(entry)
        if len(nodes) > MAX_BODY_NODES:
            return None
        here = len(nodes) - 1
        later = isinstance(node, (*_PY_FUNCTIONS, ast.GeneratorExp))  # Runs when called.
        repeats = isinstance(node, _PY_LOOPS)
        if repeats:
            outer[here] = -1 if later else loop
        once: set[ast.AST] = set()  # Parts of a loop that run once: an else, a for's iterable.
        if isinstance(node, ast.For | ast.AsyncFor | ast.While):
            once.update(node.orelse, [] if isinstance(node, ast.While) else [node.iter])
        for child, inner in reversed(scopes.children(node, scope)):
            if later and inner is not scope:
                pending.append((child, inner, here, here, here if repeats else -1))
            else:
                around = here if repeats and child not in once else loop
                pending.append((child, inner, here, frame, around))
    seen = _Observed()
    try:
        body = _PythonBody(function, nodes, outer, scopes)
        for index, (node, scope, *_) in enumerate(nodes):
            body.at = index
            _python_node(node, scope, scopes, body, seen)
    except _TooManyTargetsError:
        return None
    return seen


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
    for name, via_call in names:
        _python_call(node, name, through_call or via_call, seen)
    # Once per call, whatever targets the callee has: building a statement, such as with
    # SQLAlchemy's ``text()``, is not running it.
    if written.rsplit(".", 1)[-1] in _DB_EXECUTE and (
        receiver in _DB_RECEIVERS or any(n.split(".")[0] in _DB_MODULES for n, _ in names)
    ):
        _python_sql(node, scope, body, seen)


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
    if name in {"os.getenv", "os.environ.get"}:
        key = _literal(node.args[0]) if node.args else None
        if key is not None and _secret_name(key):
            seen.add(CapabilityClass.CREDENTIALS)


def _python_sql(call: ast.Call, scope: _Scope, body: _PythonBody, seen: _Observed) -> None:
    named = (k.value for k in call.keywords if k.arg in _SQL_ARGUMENTS)
    supplied, rank = body.evaluate(next(iter(call.args), None) or next(named, None), scope)
    if supplied:
        seen.raw_sql = True
        rank = 2
    _sql_record(rank, seen)


def _sql_record(rank: int, seen: _Observed) -> None:
    if rank == 2:
        seen.delete()
    elif rank == 1:
        seen.write()


def _ts_text(node: Node | None) -> str:
    return (node.text or b"").decode("utf-8", "replace") if node is not None else ""


def _ts_module(specifier: str) -> str:
    module = specifier.removeprefix("node:")
    return module.split("/", 1)[0] if not module.startswith("@") else module


Bindings = Mapping[str, tuple[tuple[str, str], ...]]


_Names = dict[str, dict[tuple[str, str], None]]  # Each name's bindings, in the order found.


def _bind(names: _Names, name: str, binding: tuple[str, str]) -> None:
    names.setdefault(name, {})[binding] = None


def typescript_imports(nodes: Iterable[Node]) -> dict[str, tuple[tuple[str, str], ...]]:
    """Every (module, export or '') a name is bound to by ``import`` or ``require``, in any
    scope, so a second binding adds a candidate and never hides the first."""
    nodes = list(nodes)
    names: _Names = {}
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
    _bind_derived(nodes, names)
    return {name: tuple(bindings) for name, bindings in names.items()}


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


def _ts_unwrap_await(node: Node | None) -> Node | None:
    while node is not None and node.type == "await_expression":
        node = node.named_children[0] if node.named_children else None
    return node


def _bind_derived(nodes: Iterable[Node], names: _Names) -> None:
    """A name bound from an imported name holds what that name holds, in source order."""
    for node in nodes:
        target = node.child_by_field_name("name") if node.type == "variable_declarator" else None
        if target is not None and target.type == "identifier":
            value = _ts_unwrap_await(node.child_by_field_name("value"))
            for binding in _ts_derived(value, names):
                _bind(names, _ts_text(target), binding)


def _ts_derived(
    value: Node | None, names: Mapping[str, Iterable[tuple[str, str]]]
) -> list[tuple[str, str]]:
    """What a value taken from an imported name holds: another name for it, a member of it,
    ``promisify`` of it, or what calling or constructing it returns, as in
    ``const run = cp.execSync``, ``const api = axios.create()`` or ``new Stripe(key)``. A
    server an http module creates is not a client. Past ``_MAX_TARGETS``, one more binding
    is enough for a read of the name to be unclassified."""
    called = value is not None and value.type in {"call_expression", "new_expression"}
    if called and value is not None:
        callee = value.child_by_field_name("function") or value.child_by_field_name("constructor")
        arguments = value.child_by_field_name("arguments")
        if _ts_text(callee) in {"promisify", "util.promisify"}:
            value = arguments.named_children[0] if arguments and arguments.named_children else None
            called = False
        else:
            value = callee
    chain = _ts_chain(value)
    if not chain or (called and chain[-1] in _TS_HTTP_SERVER):
        return []
    head = chain[0]
    held = [(head.removeprefix(_MODULE_HEAD), "")] if head.startswith(_MODULE_HEAD) else []
    held = held or list(itertools.islice(names.get(head, ()), _MAX_TARGETS + 1))
    if called or len(chain) == 1:
        return held
    return [(module, chain[-1]) for module, _ in held]


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


def _ts_import_binding(value: Node | None, imports: Bindings) -> bool:
    """Whether a declarator binds a module or a value taken from an import, as imports do."""
    value = _ts_unwrap_await(value)
    if _ts_derived(value, imports):
        return True
    if value is not None and value.type == "member_expression":
        value = _ts_unwrap_await(value.child_by_field_name("object"))
    return value is not None and value.type == "call_expression" and bool(_ts_loaded_module(value))


def _ts_locals(
    handler: Node, imports: Bindings, tainted: set[str], skip: frozenset[int]
) -> set[str] | None:
    """Names the body binds at its top level, which shadow imports; a name bound from a
    parameter anywhere is added to ``tainted``. None past the node bound."""
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
                    if declarator.type == "variable_declarator" and not _ts_import_binding(
                        value, imports
                    ):
                        names.update(_ts_bound_names(declarator.child_by_field_name("name")))
    stack = [handler]
    visited = 0
    flows: list[Node] = []
    reads: dict[str, list[int]] = {}
    while stack:
        node = stack.pop()
        visited += 1
        if visited > MAX_BODY_NODES:
            return None
        if node.type in _TS_READS:
            reads.setdefault(_ts_text(node), []).append(node.start_byte)
        elif node.type in _TS_FLOWS or node.type == "call_expression":
            flows.append(node)
        stack.extend(child for child in node.named_children if child.id not in skip)
    _ts_taint(flows, reads, tainted)
    return names


_TS_READS = frozenset({"identifier", "shorthand_property_identifier"})
_TS_FLOWS = {
    "variable_declarator": ("name", "value"),
    "assignment_expression": ("left", "right"),
    "augmented_assignment_expression": ("left", "right"),
    "for_in_statement": ("left", "right"),
}
_TS_CALLBACKS = frozenset({"arrow_function", "function_expression", "function"})
_TS_HOLDERS = frozenset(
    {"member_expression", "subscript_expression", "parenthesized_expression", "non_null_expression"}
)


def _ts_taint(flows: list[Node], reads: dict[str, list[int]], tainted: set[str]) -> None:
    """Add to ``tainted``, in source order, each name a flow binds from a value that reads a
    tainted name. Reads are found by their offsets, so a flow costs one bisection whatever
    the size of its value."""
    marked = sorted(offset for name in tainted for offset in reads.pop(name, ()))
    for node in sorted(flows, key=lambda flow: flow.start_byte):
        for bound, source in _ts_flows(node):
            if source is None:
                continue
            at = bisect.bisect_left(marked, source.start_byte)
            if at == len(marked) or marked[at] >= source.end_byte:
                continue
            for name in bound:
                if name not in tainted:
                    tainted.add(name)
                    for offset in reads.pop(name, ()):
                        bisect.insort(marked, offset)


def _ts_flows(node: Node) -> list[tuple[Iterable[str], Node | None]]:
    """Where a value flows into names: a declaration, an assignment, a ``for ... in`` or
    ``for ... of`` target, or the parameters of a callback given to a method of the value."""
    fields = _TS_FLOWS.get(node.type)
    if fields is not None:
        target, source = (node.child_by_field_name(field) for field in fields)
        return [(_ts_assigned(target), source)]
    callee, arguments = node.child_by_field_name("function"), node.child_by_field_name("arguments")
    if callee is None or callee.type != "member_expression" or arguments is None:
        return []
    receiver = callee.child_by_field_name("object")
    return [
        (_ts_parameters(callback), receiver)
        for callback in arguments.named_children
        if callback.type in _TS_CALLBACKS
    ]


def _ts_assigned(target: Node | None) -> list[str]:
    """The names a declaration or assignment binds; assigning to a member or item of a name
    binds that name."""
    while target is not None and target.type in _TS_HOLDERS:
        target = target.child_by_field_name("object") or target.named_child(0)
    return _ts_bound_names(target)


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
    """Classify a handler by the calls in its syntax tree; ``skip`` holds other tools' ids."""
    seen = _Observed()
    parameters = frozenset(_ts_parameters(handler))
    # _ts_locals adds names bound from a parameter anywhere in the body to ``tainted``, so
    # that SQL built from them is caller-supplied; only the handler's own parameters and
    # the names it binds at its top level shadow imports, and a name taken from one of
    # its parameters is not taken from an import.
    tainted = set(parameters)
    unshadowed = {name: b for name, b in imports.items() if name not in parameters}
    local = _ts_locals(handler, unshadowed, tainted, skip)
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
            try:
                _ts_call(node, imports, shadowed, parameters, seen, tainted)
            except _TooManyTargetsError:
                return ToolCapabilities(unclassified=True)
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
    shadowed: frozenset[str],
    parameters: frozenset[str],
    seen: _Observed,
    tainted: set[str],
) -> None:
    """Classify one call against every binding its head may have."""
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
    if len(candidates) > _MAX_TARGETS:
        raise _TooManyTargetsError
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
    # A receiver counts by its database module under any name, or by its own name, whatever
    # it is bound to: a pool is often imported from the project's own ``./db``. Prisma's
    # ``$``-prefixed raw methods exist on no other client.
    client = last.startswith("$") or any(module in _TS_DB_MODULES for module, _ in candidates)
    # In any case, as D1's ``env.DB``, and through a getter, as ``getPool().query(...)``.
    receiver_name = chain[-2].lower() if len(chain) > 1 else ""
    named = (
        receiver_name in _TS_DB_RECEIVERS or receiver_name.removeprefix("get") in _TS_DB_RECEIVERS
    )
    callee = node.child_by_field_name("function")
    receiver = callee.child_by_field_name("object") if callee is not None else None
    if arguments is not None and arguments.type == "template_string":
        # A tag that runs its template; the substitutions are bound parameters.
        if any(module in _TS_TAGGED for module, _ in candidates) or (
            len(chain) > 1 and last in _TS_SQL_TAGS and (client or named)
        ):
            _sql_record(_ts_statement(arguments, tainted, bound=True)[1], seen)
        return
    statement = values[0] if values else None
    if receiver is not None and receiver.type == "call_expression" and last in _TS_SQL:
        tag = receiver.child_by_field_name("arguments")
        if tag is not None and tag.type == "template_string":
            statement = receiver  # ``sql`...`.execute(db)`` runs the template
    prepared = "prepare" in chain[:-1]  # A prepared statement's arguments are bound values.
    if statement is None or prepared or len(chain) < 2:
        return
    if (last in _TS_SQL and (client or named)) or (last in _TS_SQL_CLIENT and client):
        supplied, rank = _ts_statement(statement, tainted)
        if supplied:
            seen.raw_sql = True
            rank = 2
        _sql_record(rank, seen)


def _ts_statement(node: Node, tainted: set[str], *, bound: bool = False) -> tuple[bool, int]:
    """Whether a statement may be caller-supplied, and the rank of its text: the parts of a
    concatenation, template or conditional, the object a member or item is read from, a
    method's receiver, the value of an assignment or comma expression and a query config's
    ``text``, ``sql`` or ``query``. A tagged template's substitutions are bound parameters;
    past ``_MAX_USE_NODES`` nodes, assume the worst."""
    supplied, budget = False, _MAX_USE_NODES * 4
    runs: list[list[str]] = [[]]
    pending: list[Node | None] = [node]
    while pending:
        budget -= 1
        if budget < 0:
            return True, 2
        part = pending.pop()
        kind = part.type if part is not None else ""
        if part is None:
            runs.append([])
        elif kind in {"string", "template_string"}:
            runs[-1].append(_ts_literal_text(part) or "")
            supplied = (
                supplied
                or not bound
                and any(
                    child.type == "template_substitution" and _ts_uses(child, tainted)
                    for child in part.named_children
                )
            )
        elif kind == "identifier":
            supplied = supplied or _ts_text(part) in tainted
            runs[-1].append("?")
        elif kind == "binary_expression" and _ts_text(part.child_by_field_name("operator")) == "+":
            pending += [part.child_by_field_name("right"), part.child_by_field_name("left")]
        elif kind in {"member_expression", "subscript_expression"}:
            pending.append(part.child_by_field_name("object"))
        elif kind == "call_expression":
            callee, arguments = (
                part.child_by_field_name("function"),
                part.child_by_field_name("arguments"),
            )
            if arguments is not None and arguments.type == "template_string":
                runs[-1].append(_ts_literal_text(arguments) or "")
            elif callee is not None and callee.type == "member_expression":
                if _ts_property(callee) in {"join", "concat"} and arguments is not None:
                    supplied = supplied or _ts_uses(arguments, tainted)
                pending.append(callee.child_by_field_name("object"))
            else:
                runs[-1].append("?")
        elif kind == "ternary_expression":
            pending += [None, part.child_by_field_name("alternative"), None]
            pending += [part.child_by_field_name("consequence"), None]
        elif kind == "array":
            pending.extend(reversed(part.named_children))
        elif kind == "object":
            for pair in part.named_children:
                key = _ts_text(pair.child_by_field_name("key")).strip("'\"`")
                if pair.type == "pair" and key in {"text", "sql", "query"}:
                    pending += [None, pair.child_by_field_name("value"), None]
        elif kind in _TS_WRAPPERS:
            pending.extend(part.named_children[:1])
        elif kind in {"assignment_expression", "sequence_expression"}:
            pending.extend(part.named_children[-1:])
        else:
            runs[-1].append("?")
    return supplied, max(_SQL_RANK[_sql_effect("".join(run))] for run in runs)


_TS_WRAPPERS = frozenset(
    {"parenthesized_expression", "as_expression", "satisfies_expression"}
    | {"non_null_expression", "await_expression", "type_assertion"}
)


def _ts_unescape(escaped: str) -> str:
    """What a JavaScript escape stands for: a control character as a space, ``\\xHH``
    and ``\\u`` forms as their character, a line continuation as nothing."""
    body = escaped[1:]
    if body[:1] in {"n", "r", "t", "v", "f", "b", "0"} and len(body) == 1:
        return " "
    if body[:1] in {"x", "u"}:
        digits = body[1:].strip("{}")
        try:
            return chr(int(digits, 16))
        except (ValueError, OverflowError):
            return "?"
    return "" if body in {"\n", "\r", "\r\n", "\u2028", "\u2029"} else body[:1]


def _ts_literal_text(node: Node) -> str | None:
    """The text of a string or template literal, each substitution read as ``?``."""
    if node.type not in {"string", "template_string"}:
        return None
    parts: list[str] = []
    for child in node.named_children:
        if child.type == "string_fragment":
            parts.append(_ts_text(child))
        elif child.type == "escape_sequence":
            parts.append(_ts_unescape(_ts_text(child)))
        elif child.type == "template_substitution":
            parts.append(" ? ")
    return "".join(parts)
