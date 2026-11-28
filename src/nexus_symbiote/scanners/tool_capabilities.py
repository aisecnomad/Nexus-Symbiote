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

_PY_BUILTINS = frozenset({"eval", "exec", "open", "str"})
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
_SQL_DELIMITERS = re.compile(r"""--|/\*|\*/|['"\r\n]""")
_SQL_LINE_END = re.compile(r"[\r\n]")
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
    | {"prepare", "$queryRaw", "$executeRaw"}
)
# What a prepared statement comes from; its other methods take bound values.
_TS_PREPARED = frozenset({"prepare", "PreparedStatement"})
# SQLite-family and pg-promise statement methods, too common to count on a name alone.
_TS_SQL_CLIENT = frozenset(
    {"exec", "run", "all", "get", "each", "none", "one", "many", "any", "result", "batch"}
    | {"oneOrNone", "manyOrNone"}
)
# Clients that are themselves a tag running its template, as postgres.js's ``sql`...```.
_TS_TAGGED = frozenset({"postgres", "@vercel/postgres", "@neondatabase/serverless"})
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
            line_end = _SQL_LINE_END.search(text, i + 2)
            i = line_end.end() if line_end else n
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
        last_set = next((k for k in reversed(range(len(statement))) if statement[k] == "SET"), -1)
        if statement[:1] == ["EXPLAIN"]:
            # ANALYZE inside the described query is an ordinary identifier.
            if statement[1:2] == ["("]:
                option_end = statement.index(")") if ")" in words else len(statement)
            else:
                option_end = next(
                    (
                        k
                        for k in range(1, len(statement))
                        if statement[k] not in {"ANALYZE", "ANALYSE", "VERBOSE"}
                    ),
                    len(statement),
                )
            analyze = next(
                (
                    k
                    for k in reversed(range(1, option_end))
                    if statement[k] in {"ANALYZE", "ANALYSE"}
                ),
                -1,
            )
            if analyze < 0 or statement[analyze + 1 : analyze + 2] in (["FALSE"], ["OFF"], ["0"]):
                continue
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
            if start and word in {"SEARCH", "CYCLE"} and k < last_set:
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
# The functions whose parameters a value may hold, one bit each, and the rank of its text.
_Held = tuple[int, int]
# A name's bindings in its own frame, each with where it starts and ends and where the block
# that always runs it ends; their starts; and what its bindings elsewhere may give it.
_Placed = tuple[list[tuple[int, int, int, _Binding]], list[int], _Value]


def _join(a: _Value, b: _Value) -> _Value:
    return a[0] or b[0], max(a[1], b[1])


def _hold(a: _Held, b: _Held) -> _Held:
    return a[0] | b[0], max(a[1], b[1])


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
        self._statements: dict[ast.AST | None, tuple[int, list[tuple[_Key, bool]]]] = {}
        # A function, and each parameter of it that may be caller input, to the function's bit;
        # what each name and binding may hold, solved once for every tool in the file.
        self.function_bits: dict[ast.AST, int] = {}
        self._parameter_bits: dict[ast.AST, int] = {}
        self._summaries: dict[_Key, _Held] = {}
        self._contributions: dict[_Binding, _Held] = {}
        self._first: set[ast.AST] = set()  # Generators whose iterable the enclosing scope reads.
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
            if isinstance(node, _PY_COMPREHENSIONS):
                self._first.add(node.generators[0])
            if isinstance(node, _PY_FUNCTIONS):
                a = node.args
                bit = self.function_bits[node] = 1 << len(self.function_bits)
                for argument in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg):
                    if argument is not None:
                        if argument.arg not in {"self", "cls"}:
                            self._parameter_bits[argument] = bit
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
            # A comprehension's first iterable is evaluated in the scope around it.
            outside = node in self._first and scope.parent is not None
            self._assign(scope, node.target, node, scope.parent if outside else None)
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

    def contribution(self, binding: _Binding) -> _Held:
        """What one binding may give its name: its own text and what it is built from."""
        if binding not in self._contributions:
            rank, keys = self.statement(binding[2], binding[3])
            held = self._parameter_bits.get(binding[0], 0), rank
            for key, ranked in keys:
                value = self.summary(key)
                held = _hold(held, value if ranked else (value[0], 0))
            self._contributions[binding] = held
        return self._contributions[binding]

    def summary(self, key: _Key) -> _Held:
        """What ``key`` may hold anywhere: every binding of it and of the names it is built
        from. Names built from each other hold one value, so each group of them is solved
        once, after the groups it is built from, and each reference is joined once."""
        if key in self._summaries:
            return self._summaries[key]
        order: dict[_Key, int] = {}
        low: dict[_Key, int] = {}
        place: dict[_Key, int] = {}  # Where a name sits on ``group``.
        held: dict[_Key, _Held] = {}
        refs: dict[_Key, list[tuple[_Key, bool]]] = {}
        group: list[_Key] = []
        frames = [(key, 0)]
        while frames:
            current, at = frames[-1]
            if at == 0:
                order[current] = low[current] = len(order)
                place[current] = len(group)
                group.append(current)
                value, found = (0, 0), []
                for where, _, source, reads in self.bindings.get(current, ()):
                    rank, keys = self.statement(source, reads)
                    value = _hold(value, (self._parameter_bits.get(where, 0), rank))
                    found.extend(keys)
                held[current], refs[current] = value, found
            if at < len(refs[current]):
                frames[-1] = (current, at + 1)
                ref, ranked = refs[current][at]
                if ref in self._summaries:
                    value = self._summaries[ref]
                    held[current] = _hold(held[current], value if ranked else (value[0], 0))
                elif ref not in order:
                    frames.append((ref, 0))
                else:  # Visited and not solved: part of the group being solved.
                    low[current] = min(low[current], order[ref])
                continue
            frames.pop()
            if low[current] == order[current]:
                start = place[current]
                value = (0, 0)
                for member in group[start:]:
                    value = _hold(value, held[member])
                self._summaries.update(dict.fromkeys(group[start:], value))
                del group[start:]
            if frames:
                parent, reached = frames[-1]
                if current in self._summaries:
                    value = self._summaries[current]
                    ranked = refs[parent][reached - 1][1]
                    held[parent] = _hold(held[parent], value if ranked else (value[0], 0))
                else:
                    low[parent] = min(low[parent], low[current])
        return self._summaries[key]

    def statement(self, node: ast.AST | None, scope: _Scope) -> tuple[int, list[tuple[_Key, bool]]]:
        """The rank of the SQL text ``node`` may evaluate to, with each alternative read on
        its own and any other part as ``?``, and the names that text is taken from, each with
        whether its own text counts: a name inside a quoted literal of the text is data. A
        comprehension's item is read in the comprehension."""
        if node in self._statements:
            return self._statements[node]
        names: dict[tuple[str, _Scope], bool] = {}
        runs: list[list[str]] = [[]]
        quote = ""  # The quote the text so far leaves open.
        pending: list[tuple[ast.AST | None, _Scope] | None] = [(node, scope)]
        while pending:
            entry = pending.pop()
            if entry is None:
                runs.append([])
                quote = ""
                continue
            part, where = entry
            if isinstance(part, ast.Constant):
                text = part.value if isinstance(part.value, str) else "?"
                runs[-1].append(text)
                for found in _SQL_DELIMITERS.finditer(text):
                    delimiter = found.group()
                    if quote == "--":
                        if delimiter in {"\r", "\n"}:
                            quote = ""
                    elif quote == "/*":
                        if delimiter == "*/":
                            quote = ""
                    elif quote:
                        if delimiter == quote:
                            quote = ""
                    elif delimiter in {"--", "/*", "'", '"'}:
                        quote = delimiter
            elif isinstance(part, ast.Name | ast.FormattedValue):
                for name in _names_in(part):
                    names[name, where] = names.get((name, where), False) or not quote
                runs[-1].append("?")
            elif isinstance(part, ast.JoinedStr):
                pending.extend((value, where) for value in reversed(part.values))
            elif isinstance(part, ast.BinOp) and isinstance(part.op, ast.Add):
                pending += [(part.right, where), (part.left, where)]
            elif isinstance(part, ast.BinOp) and isinstance(part.op, ast.Mod):
                for name in _names_in(part.right):
                    names[name, where] = True
                pending.append((part.left, where))
            elif isinstance(
                part, ast.Attribute | ast.Subscript | ast.Starred | ast.Await | ast.NamedExpr
            ):
                pending.append((part.value, where))
            elif isinstance(part, ast.Call) and (wrapped := self._wrapped(part, where)):
                pending.append((wrapped, where))
            elif isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute):
                # A method of the statement, such as ``.strip()`` or ``.bindparams(...)``;
                # ``.format()`` and ``.join()`` also take their arguments into the text.
                arguments: Iterable[ast.AST] = ()
                if part.func.attr in {"format", "join", "format_map"}:
                    arguments = (*part.args, *part.keywords)
                elif part.func.attr == "replace":
                    arguments = part.args[1:2]
                elif part.func.attr == "get" and len(part.args) >= 2:
                    # The lookup key only selects an entry. Its default can become the statement.
                    pending.extend([None, (part.args[1], where), None])
                for argument in arguments:
                    for name in _names_in(argument):
                        names[name, where] = True
                pending.append((part.func.value, where))
            elif isinstance(part, ast.AugAssign):
                pending += [(part.value, where), (part.target, where)]
            elif isinstance(part, ast.For | ast.AsyncFor | ast.comprehension):
                pending.append((part.iter, where))
            elif isinstance(part, _PY_COMPREHENSIONS):
                inner = self._scopes.get(part, where)
                item = part.value if isinstance(part, ast.DictComp) else part.elt
                pending += [None, (item, inner), None]
            elif part is not None and (items := _alternatives(part)) is not None:
                pending.append(None)
                for item in reversed(items):
                    pending += [(item, where), None]
            else:
                runs[-1].append("?")
        rank = max(_SQL_RANK[_sql_effect("".join(run))] for run in runs)
        keys = [
            ((owner, name), ranked)
            for (name, where), ranked in names.items()
            for owner in self.lookup(where, name)[0]
        ]
        self._statements[node] = rank, keys
        return rank, keys

    def _wrapped(self, call: ast.Call, scope: _Scope) -> ast.AST | None:
        """The statement passed to SQLAlchemy's text() or Python's str() conversion."""
        chain = _chain(call.func)
        if chain is None:
            return None
        for path, _ in self.resolve(scope, chain)[0]:
            if path in _SQL_TEXT or path in {"str", "builtins.str"}:
                keyword = "text" if path in _SQL_TEXT else "object"
                return next(iter(call.args), None) or next(
                    (k.value for k in call.keywords if k.arg == keyword), None
                )
        return None


def _alternatives(node: ast.AST) -> list[ast.expr] | None:
    """The values a statement may be one of: either side of a conditional or ``or``, or an
    item of the literal it is taken from; None for anything else."""
    if isinstance(node, ast.IfExp):
        return [node.body, node.orelse]
    if isinstance(node, ast.BoolOp | ast.Dict):
        return node.values
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return node.elts
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
    """The names a value put into a statement may take its text from: every name in it but
    the item it selects with, as ``field`` in ``ALLOWED[field]``, and a condition that only
    chooses between values."""
    names: set[str] = set()
    pending = [node]
    while pending:
        part = pending.pop()
        if isinstance(part, ast.Name):
            names.add(part.id)
        elif isinstance(part, ast.Subscript):
            pending.append(part.value)
        elif isinstance(part, ast.IfExp):
            pending += [part.body, part.orelse]
        elif not isinstance(part, ast.Compare):
            pending.extend(ast.iter_child_nodes(part))
    return names


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
        self.bit = scopes.function_bits.get(function, 0)
        self._placed: dict[_Key, _Placed] = {}
        self._made: dict[_Binding, _Value] = {}
        self._making: set[_Binding] = set()

    def evaluate(self, node: ast.AST | None, scope: _Scope) -> _Value:
        """What the statement ``node`` may be where the current node runs."""
        return self._read(node, scope, self.at)

    def _read(self, node: ast.AST | None, scope: _Scope, at: int) -> _Value:
        rank, keys = self.scopes.statement(node, scope)
        value: _Value = (False, rank)
        for key, ranked in keys:
            # A comprehension binds its targets before each item it makes, so they are read whole.
            same = key[0].kind != "comprehension" and self.frame_of.get(key[0]) == self.frames[at]
            found = self.reaching(key) if same else self.summary(key)
            value = _join(value, found if ranked else (found[0], 0))
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
        """What one binding may give its name, for this tool's parameters. One made in this
        body reads the names it is built from where it is made, as a call reads its
        statement; one made elsewhere, or past ``_MAX_TARGETS`` bindings being read inside
        each other, reads every binding of them."""
        made = self.position.get(binding[0], -1)
        if made < 0 or binding in self._making or len(self._making) >= _MAX_TARGETS:
            held, rank = self.scopes.contribution(binding)
            return bool(held & self.bit), rank
        if binding not in self._made:
            self._making.add(binding)
            at, self.at = self.at, made
            try:
                supplied, rank = self._read(binding[2], binding[3], made)
                self._made[binding] = supplied or binding[0] in self.arguments, rank
            finally:
                self.at = at
                self._making.discard(binding)
        return self._made[binding]

    def summary(self, key: _Key) -> _Value:
        """What ``key`` may hold anywhere, for this tool's parameters."""
        held, rank = self.scopes.summary(key)
        return bool(held & self.bit), rank


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
    method = written.rsplit(".", 1)[-1]
    asyncpg_fetch = method in {"fetch", "fetchrow", "fetchval"} and (
        receiver in {"conn", "connection", "pool", "db"}
        or any(n.startswith("asyncpg.") for n, _ in names)
    )
    if (
        asyncpg_fetch
        or method in _DB_EXECUTE
        and (receiver in _DB_RECEIVERS or any(n.split(".")[0] in _DB_MODULES for n, _ in names))
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
    """The package a specifier names, as ``@prisma/client`` for ``@prisma/client/edge``."""
    parts = specifier.removeprefix("node:").split("/")
    return "/".join(parts[:2]) if parts[0].startswith("@") else parts[0]


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
    made = chain[-1] if len(chain) > 1 else ""  # The method that made it, such as ``prepare``.
    return [
        (module, made or export)
        for module, export in held
        if module not in _TS_HTTP or (made or export) in _TS_HTTP_CLIENTS.get(module, ())
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


def _ts_tainted(handler: Node, tainted: set[str], skip: frozenset[int]) -> bool:
    """Add to ``tainted`` each name bound from a parameter anywhere in the body, so that SQL
    built from it is caller-supplied; False past the node bound."""
    stack = [handler]
    visited = 0
    flows: list[Node] = []
    reads: dict[str, list[int]] = {}
    while stack:
        node = stack.pop()
        visited += 1
        if visited > MAX_BODY_NODES:
            return False
        if node.type in _TS_READS:
            reads.setdefault(_ts_text(node), []).append(node.start_byte)
        elif node.type in _TS_FLOWS or node.type == "call_expression":
            flows.append(node)
        stack.extend(child for child in node.named_children if child.id not in skip)
    _ts_taint(flows, reads, tainted)
    return True


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
        # A falsy left operand of && cannot supply nonempty SQL text. Only the
        # right operand can become such a string, including through an alias.
        source = _ts_unwrap(source)
        while (
            source is not None
            and source.type == "binary_expression"
            and _ts_text(source.child_by_field_name("operator")) == "&&"
        ):
            source = _ts_unwrap(source.child_by_field_name("right"))
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
    tainted = set(parameters)
    if not _ts_tainted(handler, tainted, skip):
        return ToolCapabilities(unclassified=True)
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
    imports: _View,
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
            len(chain) > 1 and last in _TS_SQL and (client or named)
        ):
            _sql_record(_ts_statement(arguments, tainted, imports, bound=True)[1], seen)
        return
    statement = values[0] if values else None
    if receiver is not None and receiver.type == "call_expression" and last in _TS_SQL:
        tag = receiver.child_by_field_name("arguments")
        if tag is not None and tag.type == "template_string":
            statement = receiver  # ``sql`...`.execute(db)`` runs the template
    # A prepared statement's arguments are bound values, all but the statement it is given.
    prepared = last != "prepare" and (
        "prepare" in chain[:-1] or any(export in _TS_PREPARED for _, export in candidates)
    )
    if statement is None or prepared or len(chain) < 2:
        return
    if (last in _TS_SQL and (client or named)) or (last in _TS_SQL_CLIENT and client):
        supplied, rank = _ts_statement(statement, tainted, imports)
        if supplied:
            seen.raw_sql = True
            rank = 2
        _sql_record(rank, seen)


def _ts_statement(
    node: Node, tainted: set[str], bindings: _View, *, bound: bool = False
) -> tuple[bool, int]:
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
        elif kind in {"identifier", "shorthand_property_identifier"}:
            supplied = supplied or _ts_text(part) in tainted
            runs[-1].append("?")
        elif kind == "binary_expression":
            operator = _ts_text(part.child_by_field_name("operator"))
            if operator == "+":
                pending += [part.child_by_field_name("right"), part.child_by_field_name("left")]
            elif operator == "&&":
                pending.append(part.child_by_field_name("right"))
            elif operator in {"||", "??"}:
                pending += [
                    None,
                    part.child_by_field_name("right"),
                    None,
                    part.child_by_field_name("left"),
                    None,
                ]
            else:
                runs[-1].append("?")
        elif kind in {"member_expression", "subscript_expression"}:
            pending.append(part.child_by_field_name("object"))
        elif kind == "call_expression":
            callee, arguments = (
                part.child_by_field_name("function"),
                part.child_by_field_name("arguments"),
            )
            if arguments is not None and arguments.type == "template_string":
                runs[-1].append(_ts_literal_text(arguments) or "")
            elif (
                callee is not None
                and callee.type == "identifier"
                and _ts_text(callee) == "String"
                and bindings.is_global("String")
            ):
                if arguments is not None:
                    pending.extend(arguments.named_children[:1])
            elif callee is not None and callee.type == "member_expression":
                if arguments is not None:
                    method = _ts_property(callee)
                    if method in {"join", "concat"}:
                        supplied = supplied or _ts_uses(arguments, tainted)
                    elif method in {"replace", "replaceAll"}:
                        supplied = supplied or any(
                            _ts_uses(arg, tainted) for arg in arguments.named_children[1:2]
                        )
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
                elif pair.type == "shorthand_property_identifier" and _ts_text(pair) in {
                    "text",
                    "sql",
                    "query",
                }:
                    pending += [None, pair, None]
        elif kind in _TS_WRAPPERS:
            children = part.named_children
            pending.extend(children[-1:] if kind == "type_assertion" else children[:1])
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
    """What a JavaScript escape stands for: SQL line endings preserved, ``\\xHH``
    and ``\\u`` forms as their character, a line continuation as nothing."""
    body = escaped[1:]
    if body in {"n", "r"}:
        return "\n" if body == "n" else "\r"
    if body in {"t", "v", "f", "b", "0"}:
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
