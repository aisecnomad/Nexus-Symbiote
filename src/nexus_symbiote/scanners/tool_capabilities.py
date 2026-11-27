"""Capabilities and side effects a source-declared tool body names.

A tool declared in Python or TypeScript source is classified by the operations its body
names: process execution, network egress, filesystem reads and writes, SQL statements,
payment APIs and reads of secret-named environment variables. Only names in the body
count, never its decorators; nothing is executed or imported, a helper the body calls is
not followed, and a tool whose body names none of these keeps no declaration. The result
states what the code says, not what it does.

Names that ordinary code also uses for other things are counted only where they resolve
to the module that gives them the meaning: ``remove``, ``copy``, ``move`` and ``rename``
only on ``os`` or ``shutil``, ``get``/``put``/``patch`` only on an HTTP client, and
JavaScript ``exec`` only as ``child_process.exec`` or an imported function, so
``list.remove``, ``dict.get`` and ``RegExp.exec`` name no capability.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

from nexus_symbiote.core.enums import CapabilityClass, RiskSeverity, SideEffectProfile
from nexus_symbiote.core.models import CapabilityDeclaration, RiskAssessment

CATEGORY = "capability_scope"
# Past these bounds a body is not classified and the tool stays unknown.
MAX_BODY_NODES = 20_000
MAX_TYPESCRIPT_BODY = 65_536

_EXECUTE_CALLS = frozenset(
    {
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.spawnl",
        "os.spawnv",
        "os.posix_spawn",
        "pty.spawn",
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
        "eval",
        "exec",
        "builtins.eval",
        "builtins.exec",
    }
)
_EXECUTE_MODULES = frozenset({"subprocess", "pty"})
_HTTP_MODULES = frozenset({"requests", "httpx", "aiohttp", "urllib3"})
_NETWORK_MODULES = _HTTP_MODULES | frozenset(
    {"urllib", "socket", "smtplib", "boto3", "botocore", "websocket", "websockets", "grpc"}
)
_HTTP_WRITE = frozenset({"post", "put", "patch", "delete", "request"})
_NETWORK_WRITE_CALLS = frozenset({"sendmail", "send_message", "urlopen"})
_PAYMENT_MODULES = frozenset({"stripe", "paypalrestsdk", "braintree", "square", "adyen"})
_PAYMENT_READ = frozenset({"retrieve", "list", "search", "get"})
_DB_MODULES = frozenset(
    {"sqlite3", "sqlalchemy", "psycopg", "psycopg2", "pymysql", "mysql", "asyncpg", "duckdb"}
)
_DB_RECEIVERS = frozenset({"cursor", "cur", "conn", "connection", "engine", "session", "db"})
_DB_EXECUTE = frozenset({"execute", "executemany", "executescript", "exec_driver_sql"})
# Distinctive on any receiver: a Path or an os/shutil call.
_FILESYSTEM_WRITE = frozenset(
    {"write_text", "write_bytes", "unlink", "rmtree", "rmdir", "makedirs", "mkdir", "copyfile"}
)
# Ambiguous names, counted only on os or shutil.
_FILESYSTEM_WRITE_MODULE = frozenset({"remove", "rename", "replace", "copy", "copy2", "move"})
_FILESYSTEM_DELETE = frozenset({"unlink", "rmtree", "rmdir", "remove"})
_FILESYSTEM_READ = frozenset({"read_text", "read_bytes", "rglob", "listdir", "scandir", "walk"})
_FILESYSTEM_MODULES = frozenset({"os", "shutil"})
_SQL_WRITE = re.compile(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|COPY)\b", re.I)
_SQL_DESTRUCTIVE = re.compile(r"\b(DROP|DELETE|TRUNCATE)\b", re.I)
_SQL_ANY = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE)\b", re.I)
_SECRET_NAME = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH|PRIVATE|DSN|DATABASE_URL|_PAT)",
    re.I,
)

_TS_EXECUTE = re.compile(
    r"\b(?:execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\("
    r"|(?<![\w$.])exec\s*\("
    r"|\bchild_process\s*\.\s*exec\s*\("
    r"|(?<![\w$.])eval\s*\("
)
_TS_WRITE = re.compile(
    r"\b(?:writeFileSync|writeFile|appendFileSync|appendFile|rmSync|unlinkSync|mkdirSync"
    r"|copyFileSync|renameSync)\s*\("
    r"|\bfs(?:\.promises)?\s*\.\s*(?:rm|unlink|rename|copyFile|mkdir)\s*\("
)
_TS_DELETE = re.compile(
    r"\b(?:rmSync|unlinkSync)\s*\(|\bfs(?:\.promises)?\s*\.\s*(?:rm|unlink)\s*\("
)
_TS_READ = re.compile(r"\b(?:readFileSync|readFile|readdirSync|readdir)\s*\(")
_TS_NETWORK = re.compile(r"\b(?:fetch|axios|got|undici|http\.request|https\.request)\s*[.(]")
_TS_NETWORK_WRITE = re.compile(
    r"\bmethod\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]"
    r"|\baxios\s*\.\s*(?:post|put|patch|delete)\s*\("
    r"|\b(?:sendMail|sendEmail|send_email)\s*\("
)
_TS_PAYMENT = re.compile(
    r"\bstripe\s*\.\s*(?:refunds|charges|paymentIntents|payouts|transfers)\s*\.\s*create\s*\("
)
_TS_ENV = re.compile(
    r"\bprocess\.env(?:\.([A-Za-z_][\w]{0,63})|\[\s*['\"]([^'\"]{1,64})['\"]\s*\])"
)
_TS_SQL_INTERPOLATED = re.compile(
    r"\b(?:query|execute|raw|unsafe|exec)\s*\(\s*`[^`]{0,4096}?"
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`]{0,4096}?\$\{",
    re.I,
)


@dataclass
class ToolCapabilities:
    """What a tool body names: capability classes, a side-effect profile and findings."""

    capabilities: list[CapabilityClass] = field(default_factory=list)
    profile: SideEffectProfile = SideEffectProfile.UNKNOWN
    risks: list[RiskAssessment] = field(default_factory=list)

    @property
    def declaration(self) -> CapabilityDeclaration | None:
        """A declaration for a body that names something; None keeps the tool unknown."""
        if not self.capabilities:
            return None
        return CapabilityDeclaration(
            capabilities=self.capabilities, side_effect_profile=self.profile
        )


def import_map(tree: ast.AST) -> dict[str, str]:
    """Local names bound by absolute ``import`` statements, mapped to what they name."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    names[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    names[head] = head
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name != "*":
                    names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _dotted(node: ast.AST) -> str | None:
    """``a.b.c`` for a name or attribute chain, without recursion."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _body_nodes(function: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """Every node of the body, but not the decorators that register the tool."""
    for statement in function.body:
        yield from ast.walk(statement)


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _statement_text(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            for part in node.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
        )
    return None


def _caller_supplied(node: ast.AST | None, parameters: set[str]) -> bool:
    """A statement that is a parameter, or SQL text that interpolates one."""
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in parameters
    text = _statement_text(node)
    if isinstance(node, ast.JoinedStr):
        interpolated = set().union(
            *(_names_in(p) for p in node.values if isinstance(p, ast.FormattedValue))
        )
        return bool(interpolated & parameters) and bool(text and _SQL_ANY.search(text))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return bool(_names_in(node) & parameters)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return bool(set().union(*(_names_in(a) for a in node.args)) & parameters)
    return False


def _open_for_writing(call: ast.Call) -> bool:
    modes = list(call.args[1:2]) + [k.value for k in call.keywords if k.arg == "mode"]
    return any(
        isinstance(mode, ast.Constant)
        and isinstance(mode.value, str)
        and any(flag in mode.value for flag in "wax+")
        for mode in modes
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
    elif seen.capabilities:
        profile = SideEffectProfile.READ_ONLY
    else:
        profile = SideEffectProfile.UNKNOWN
    return ToolCapabilities(
        capabilities=sorted(seen.capabilities, key=lambda c: c.value),
        profile=profile,
        risks=risks,
    )


def _environment_read(name: str, call: ast.Call | None, node: ast.AST) -> str | None:
    """The literal variable name an environment read takes, '' when computed, else None."""
    key: ast.expr | None
    if isinstance(node, ast.Subscript) and name == "os.environ":
        key = node.slice
    elif call is not None and name in {"os.getenv", "os.environ.get"}:
        key = call.args[0] if call.args else None
    else:
        return None
    return key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else ""


def classify_python(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: Mapping[str, str],
    label: str | None = None,
) -> ToolCapabilities:
    """Classify a Python tool body by the calls it names, resolving import aliases."""
    seen = _Observed()
    arguments = function.args
    parameters = {a.arg for a in arguments.posonlyargs + arguments.args + arguments.kwonlyargs}
    if arguments.vararg is not None:
        parameters.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        parameters.add(arguments.kwarg.arg)
    nodes = []
    for node in _body_nodes(function):
        nodes.append(node)
        if len(nodes) > MAX_BODY_NODES:
            return ToolCapabilities()
    db_context = any(module.split(".")[0] in _DB_MODULES for module in imports.values())

    def resolve(dotted: str) -> str:
        head, _, rest = dotted.partition(".")
        origin = imports.get(head, head)
        return f"{origin}.{rest}" if rest else origin

    for node in nodes:
        if isinstance(node, ast.Subscript):
            target = _dotted(node.value)
            if target is not None:
                variable = _environment_read(resolve(target), None, node)
                if variable is not None and (variable == "" or _SECRET_NAME.search(variable)):
                    seen.add(CapabilityClass.CREDENTIALS)
        if not isinstance(node, ast.Call):
            continue
        written = _dotted(node.func)
        if written is None:
            continue
        name = resolve(written)
        module = name.split(".")[0]
        last = name.rsplit(".", 1)[-1]
        receiver = written.split(".")[0] if "." in written else ""
        if name in _EXECUTE_CALLS or module in _EXECUTE_MODULES:
            seen.add(CapabilityClass.EXECUTE)
            seen.execute = True
        if module in _NETWORK_MODULES or last in _NETWORK_WRITE_CALLS:
            seen.add(CapabilityClass.NETWORK)
            if (module in _HTTP_MODULES and last in _HTTP_WRITE) or last in {
                "sendmail",
                "send_message",
            }:
                seen.add(CapabilityClass.WRITE)
                seen.writes = True
        if module in _PAYMENT_MODULES:
            seen.add(CapabilityClass.PAYMENT, CapabilityClass.NETWORK)
            if last not in _PAYMENT_READ:
                seen.add(CapabilityClass.WRITE)
                seen.payment = True
        on_filesystem_module = module in _FILESYSTEM_MODULES
        if (
            last in _FILESYSTEM_WRITE
            or (on_filesystem_module and last in _FILESYSTEM_WRITE_MODULE)
            or (name == "open" and _open_for_writing(node))
        ):
            seen.add(CapabilityClass.FILESYSTEM, CapabilityClass.WRITE)
            seen.writes = True
            if last in _FILESYSTEM_DELETE and (on_filesystem_module or last != "remove"):
                seen.destructive = True
        elif last in _FILESYSTEM_READ or name in {"open", "glob.glob", "os.listdir"}:
            seen.add(CapabilityClass.FILESYSTEM, CapabilityClass.READ)
        is_database = last in _DB_EXECUTE and (
            db_context or receiver in _DB_RECEIVERS or module in _DB_MODULES
        )
        if is_database or name == "sqlalchemy.text":
            statement = node.args[0] if node.args else None
            if _caller_supplied(statement, parameters):
                seen.raw_sql = True
                seen.add(CapabilityClass.WRITE, CapabilityClass.DESTRUCTIVE)
            else:
                text = _statement_text(statement)
                if text is not None and _SQL_WRITE.search(text):
                    seen.add(CapabilityClass.WRITE)
                    seen.writes = True
                    if _SQL_DESTRUCTIVE.search(text):
                        seen.destructive = True
                elif text is not None and _SQL_ANY.search(text):
                    seen.add(CapabilityClass.READ)
        variable = _environment_read(name, node, node)
        if variable is not None and (variable == "" or _SECRET_NAME.search(variable)):
            seen.add(CapabilityClass.CREDENTIALS)
    return _finish(label or function.name, seen)


def classify_typescript(body: str, label: str) -> ToolCapabilities:
    """Classify a TypeScript or JavaScript handler body by the calls its text names."""
    if len(body) > MAX_TYPESCRIPT_BODY:
        return ToolCapabilities()
    seen = _Observed()
    if _TS_EXECUTE.search(body):
        seen.add(CapabilityClass.EXECUTE)
        seen.execute = True
    if _TS_WRITE.search(body):
        seen.add(CapabilityClass.FILESYSTEM, CapabilityClass.WRITE)
        seen.writes = True
        if _TS_DELETE.search(body):
            seen.destructive = True
    if _TS_READ.search(body):
        seen.add(CapabilityClass.FILESYSTEM, CapabilityClass.READ)
    if _TS_NETWORK.search(body) or _TS_NETWORK_WRITE.search(body):
        seen.add(CapabilityClass.NETWORK)
        if _TS_NETWORK_WRITE.search(body):
            seen.add(CapabilityClass.WRITE)
            seen.writes = True
    if _TS_PAYMENT.search(body):
        seen.add(CapabilityClass.PAYMENT, CapabilityClass.NETWORK, CapabilityClass.WRITE)
        seen.payment = True
    if _TS_SQL_INTERPOLATED.search(body):
        seen.raw_sql = True
        seen.add(CapabilityClass.WRITE, CapabilityClass.DESTRUCTIVE)
    for match in _TS_ENV.finditer(body):
        variable = match.group(1) or match.group(2) or ""
        if _SECRET_NAME.search(variable):
            seen.add(CapabilityClass.CREDENTIALS)
            break
    return _finish(label, seen)
