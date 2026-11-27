"""Capabilities a source-declared tool body names, recorded only where they raise risk.

A tool the ``mcp`` collector records from a Python decorator or a TypeScript registration is
classified by the calls in its own body: process execution, network egress and whether it
sends data, filesystem writes and deletions, SQL statements, payment API writes and reads of
secret-named environment variables. Names are resolved only through the file's imports,
bindings the body makes from an imported call, and builtins, so a parameter or a local
function named like a module names nothing. Nothing is executed or imported.

The classifier cannot show that a body does nothing else, because it does not follow
helpers, dynamic dispatch or other files. It therefore records only what raises risk and
never ``read`` or ``read-only``: a tool whose body names only reads, or nothing it knows,
keeps no declaration and stays unknown, which the trifecta and graph rules treat as not
safe. A body past the size bound is not classified and records a coverage gap.
"""

from __future__ import annotations

import ast
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
    {
        CapabilityClass.EXECUTE,
        CapabilityClass.WRITE,
        CapabilityClass.DESTRUCTIVE,
        CapabilityClass.PAYMENT,
        CapabilityClass.NETWORK,
        CapabilityClass.CREDENTIALS,
    }
)

# ---- Python -------------------------------------------------------------------------------
_PY_BUILTINS = frozenset({"eval", "exec", "open"})
_PY_EXECUTE = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.system",
        "os.popen",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.spawnl",
        "os.spawnv",
        "os.spawnvp",
        "os.posix_spawn",
        "os.posix_spawnp",
        "pty.spawn",
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
        "eval",
        "exec",
    }
)
_PY_HTTP = frozenset({"requests", "httpx", "aiohttp", "urllib3"})
_PY_NETWORK = _PY_HTTP | frozenset(
    {"urllib", "socket", "smtplib", "boto3", "botocore", "websocket", "websockets", "grpc"}
)
_HTTP_WRITE = frozenset({"post", "put", "patch", "delete"})
_MAIL_WRITE = frozenset({"sendmail", "send_message"})
_PAYMENT_MODULES = frozenset({"stripe", "braintree", "adyen", "paypalrestsdk", "square"})
_PAYMENT_WRITE = frozenset(
    {"create", "capture", "confirm", "pay", "refund", "void", "sale", "submit_for_settlement"}
)
_PAYMENT_LOCAL = frozenset({"Webhook", "WebhookSignature", "error", "util", "oauth_error"})
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
# Ambiguous names, counted only on os or shutil.
_FS_MODULE_WRITE = frozenset({"remove", "rename", "replace", "copy", "copy2", "move"})
_FS_MODULE_DELETE = frozenset({"remove", "removedirs"})
_SQL_WRITE_VERBS = ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "CREATE", "GRANT")
_SQL_DESTRUCTIVE_VERBS = ("DELETE", "DROP", "TRUNCATE")

# ---- TypeScript ---------------------------------------------------------------------------
_TS_EXECUTE = frozenset(
    {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"}
)
_TS_FS_WRITE = frozenset(
    {
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "copyFile",
        "copyFileSync",
        "rename",
        "renameSync",
        "mkdir",
        "mkdirSync",
        "createWriteStream",
    }
)
_TS_FS_DELETE = frozenset({"rm", "rmSync", "unlink", "unlinkSync", "rmdir", "rmdirSync"})
_TS_HTTP = frozenset({"axios", "node-fetch", "got", "undici", "ky", "http", "https"})
_TS_SQL = frozenset(
    {"query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe", "queryRaw"}
)
_TS_PAYMENT_RESOURCES = frozenset({"refunds", "charges", "paymentIntents", "payouts", "transfers"})
_TS_PAYMENT_WRITE = frozenset({"create", "confirm", "capture"})
_TS_GLOBALS = frozenset({"globalThis", "window", "global", "self"})


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


def _sql_verbs(text: str, verbs: Iterable[str]) -> bool:
    words = {word.strip("();,").upper() for word in text.split()}
    return any(verb in words for verb in verbs)


# ---- Python -------------------------------------------------------------------------------


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


def _chain(node: ast.AST) -> str | None:
    """``a.b.c`` for a name or attribute chain, reading through calls, without recursion."""
    parts: list[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        else:
            return None


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _PythonBody:
    def __init__(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        imports: Mapping[str, str],
        nodes: list[ast.AST],
    ) -> None:
        arguments = function.args
        self.parameters = {
            a.arg for a in arguments.posonlyargs + arguments.args + arguments.kwonlyargs
        }
        for extra in (arguments.vararg, arguments.kwarg):
            if extra is not None:
                self.parameters.add(extra.arg)
        self.imports = imports
        self.bound: dict[str, str | None] = {}
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
                if not isinstance(target, ast.Name) or value is None:
                    continue
                self.values[target.id] = value
                self.bound[target.id] = (
                    self.resolve(_chain(value)) if isinstance(value, ast.Call) else None
                )

    def resolve(self, dotted: str | None) -> str | None:
        """What a dotted name refers to, or None when it is not an import or a builtin."""
        if dotted is None:
            return None
        head, _, rest = dotted.partition(".")
        if head in self.bound:
            base = self.bound[head]
        elif head in self.parameters:
            base = None
        elif head in self.imports:
            base = self.imports[head]
        elif head in _PY_BUILTINS:
            base = head
        else:
            base = None
        if base is None:
            return None
        return f"{base}.{rest}" if rest else base

    def caller_supplied(self, node: ast.AST | None, depth: int = 0) -> bool:
        """A statement that is a parameter, or text built from one."""
        if node is None:
            return False
        if isinstance(node, ast.Name):
            if node.id in self.parameters:
                return True
            value = self.values.get(node.id)
            return depth == 0 and value is not None and self.caller_supplied(value, 1)
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

    def statement_text(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Name) and node.id in self.values:
            node = self.values[node.id]
        return _literal(node)


def _open_mode(call: ast.Call) -> str | None:
    modes = list(call.args[1:2]) + [k.value for k in call.keywords if k.arg == "mode"]
    if not modes:
        return "r"
    return _literal(modes[0])


def classify_python(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: Mapping[str, str],
    label: str | None = None,
) -> ToolCapabilities:
    """Classify a Python tool body by the calls it names, never by its decorators."""
    nodes: list[ast.AST] = []
    for statement in function.body:
        for node in ast.walk(statement):
            nodes.append(node)
            if len(nodes) > MAX_BODY_NODES:
                return ToolCapabilities(unclassified=True)
    body = _PythonBody(function, imports, nodes)
    seen = _Observed()
    for node in nodes:
        if isinstance(node, ast.Subscript) and body.resolve(_chain(node.value)) == "os.environ":
            key = _literal(node.slice)
            if key is not None and _secret_name(key):
                seen.add(CapabilityClass.CREDENTIALS)
        if not isinstance(node, ast.Call):
            continue
        written = _chain(node.func)
        if written is None:
            continue
        name = body.resolve(written)
        receiver = written.split(".")[0] if "." in written else ""
        last = written.rsplit(".", 1)[-1]
        if name is None:
            if last in _FS_WRITE:
                seen.write(CapabilityClass.FILESYSTEM)
            elif last in _FS_DELETE:
                seen.delete(CapabilityClass.FILESYSTEM)
            elif last in _DB_EXECUTE and receiver in _DB_RECEIVERS:
                _python_sql(node, body, seen)
            continue
        parts = name.split(".")
        module = parts[0]
        if name in _PY_EXECUTE:
            seen.add(CapabilityClass.EXECUTE)
            seen.execute = True
        if module in _PY_NETWORK and last[:1].islower():
            seen.add(CapabilityClass.NETWORK)
            if (module in _PY_HTTP and last in _HTTP_WRITE) or last in _MAIL_WRITE:
                seen.write()
        if module in _PAYMENT_MODULES and not set(parts) & _PAYMENT_LOCAL and last[:1].islower():
            seen.add(CapabilityClass.NETWORK)
            if last in _PAYMENT_WRITE:
                seen.write(CapabilityClass.PAYMENT)
                seen.payment = True
        if name == "open":
            mode = _open_mode(node)
            if mode is None or any(flag in mode for flag in "wax+"):
                seen.add(CapabilityClass.FILESYSTEM)
                if mode is not None:
                    seen.write()
        elif last in _FS_WRITE:
            seen.write(CapabilityClass.FILESYSTEM)
        elif last in _FS_DELETE or (module in {"os", "shutil"} and last in _FS_MODULE_DELETE):
            seen.delete(CapabilityClass.FILESYSTEM)
        elif module in {"os", "shutil"} and last in _FS_MODULE_WRITE:
            seen.write(CapabilityClass.FILESYSTEM)
        if name in _SQL_TEXT or (
            last in _DB_EXECUTE and (module in _DB_MODULES or receiver in _DB_RECEIVERS)
        ):
            _python_sql(node, body, seen)
        if name in {"os.getenv", "os.environ.get"}:
            key = _literal(node.args[0]) if node.args else None
            if key is not None and _secret_name(key):
                seen.add(CapabilityClass.CREDENTIALS)
    return _finish(label or function.name, seen)


def _python_sql(call: ast.Call, body: _PythonBody, seen: _Observed) -> None:
    statement = call.args[0] if call.args else None
    if body.caller_supplied(statement):
        seen.raw_sql = True
        seen.delete()
        return
    text = body.statement_text(statement)
    if text is None:
        return
    if _sql_verbs(text, _SQL_DESTRUCTIVE_VERBS):
        seen.delete()
    elif _sql_verbs(text, _SQL_WRITE_VERBS):
        seen.write()


# ---- TypeScript ---------------------------------------------------------------------------


def _ts_text(node: Node | None) -> str:
    return (node.text or b"").decode("utf-8", "replace") if node is not None else ""


def _ts_module(specifier: str) -> str:
    module = specifier.removeprefix("node:")
    return module.split("/", 1)[0] if not module.startswith("@") else module


def typescript_imports(nodes: Iterable[Node]) -> dict[str, tuple[str, str]]:
    """Local names bound by ``import`` or ``require``: name -> (module, export or '')."""
    names: dict[str, tuple[str, str]] = {}
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
                        names[_ts_text(part)] = (module, "")
                    elif part.type == "namespace_import":
                        for ident in part.named_children:
                            if ident.type == "identifier":
                                names[_ts_text(ident)] = (module, "")
                    elif part.type == "named_imports":
                        for spec in part.named_children:
                            if spec.type != "import_specifier":
                                continue
                            imported = spec.child_by_field_name("name")
                            alias = spec.child_by_field_name("alias")
                            local = _ts_text(alias or imported)
                            names[local] = (module, _ts_text(imported))
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            while value is not None and value.type == "await_expression":
                value = value.named_children[0] if value.named_children else None
            if value is None or value.type != "call_expression":
                continue
            callee = value.child_by_field_name("function")
            arguments = value.child_by_field_name("arguments")
            if _ts_text(callee) != "require" or arguments is None or not arguments.named_children:
                continue
            first = arguments.named_children[0]
            if first.type != "string":
                continue
            module = _ts_module(_ts_text(first).strip("'\"`"))
            target = node.child_by_field_name("name")
            if target is None:
                continue
            if target.type == "identifier":
                names[_ts_text(target)] = (module, "")
            elif target.type == "object_pattern":
                for part in target.named_children:
                    if part.type == "shorthand_property_identifier_pattern":
                        names[_ts_text(part)] = (module, _ts_text(part))
    return names


def _ts_chain(callee: Node | None) -> list[str]:
    """The names of a callee, outermost first, reading through calls and ``?.``."""
    parts: list[str] = []
    node = callee
    while node is not None:
        if node.type in {"member_expression", "subscript_expression"}:
            prop = node.child_by_field_name("property") or node.child_by_field_name("index")
            parts.append(_ts_text(prop).strip("'\"`"))
            node = node.child_by_field_name("object")
        elif node.type == "call_expression":
            node = node.child_by_field_name("function")
        elif node.type in {"parenthesized_expression", "non_null_expression"}:
            node = node.named_children[0] if node.named_children else None
        elif node.type in {"identifier", "this"}:
            parts.append(_ts_text(node))
            break
        else:
            return []
    return list(reversed(parts))


def _ts_parameters(handler: Node) -> set[str]:
    names: set[str] = set()
    parameters = handler.child_by_field_name("parameters") or handler.child_by_field_name(
        "parameter"
    )
    stack = [parameters] if parameters is not None else []
    while stack:
        node = stack.pop()
        if node.type in {
            "identifier",
            "shorthand_property_identifier_pattern",
            "shorthand_property_identifier",
        }:
            names.add(_ts_text(node))
        stack.extend(node.named_children)
    return names


def _ts_uses(node: Node, parameters: set[str]) -> bool:
    stack = [node]
    while stack:
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


def classify_typescript(
    handler: Node,
    imports: Mapping[str, tuple[str, str]],
    label: str,
    skip: frozenset[int] = frozenset(),
) -> ToolCapabilities:
    """Classify a TypeScript or JavaScript handler by the calls in its syntax tree.

    ``skip`` holds the ids of nested handlers that belong to other tools.
    """
    seen = _Observed()
    parameters = _ts_parameters(handler)
    stack = [handler]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > MAX_BODY_NODES:
            return ToolCapabilities(unclassified=True)
        if node.type == "call_expression":
            _ts_call(node, imports, parameters, seen)
        elif node.type == "new_expression":
            constructor = _ts_chain(node.child_by_field_name("constructor"))
            if (
                constructor[-1:] == ["Function"]
                and (len(constructor) == 1 or constructor[0] in _TS_GLOBALS)
                and "Function" not in imports
            ):
                seen.add(CapabilityClass.EXECUTE)
                seen.execute = True
        elif node.type in {"member_expression", "subscript_expression"}:
            chain = _ts_chain(node)
            if chain[:2] == ["process", "env"] and len(chain) == 3 and _secret_name(chain[2]):
                seen.add(CapabilityClass.CREDENTIALS)
        elif node.type == "variable_declarator":
            target, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if (
                target is not None
                and target.type == "object_pattern"
                and _ts_chain(value)
                == [
                    "process",
                    "env",
                ]
            ):
                for part in target.named_children:
                    if part.type == "shorthand_property_identifier_pattern" and _secret_name(
                        _ts_text(part)
                    ):
                        seen.add(CapabilityClass.CREDENTIALS)
        stack.extend(child for child in node.named_children if child.id not in skip)
    return _finish(label, seen)


def _ts_call(
    node: Node, imports: Mapping[str, tuple[str, str]], parameters: set[str], seen: _Observed
) -> None:
    chain = _ts_chain(node.child_by_field_name("function"))
    if not chain:
        return
    head, last = chain[0], chain[-1]
    if head in _TS_GLOBALS and len(chain) > 1:
        chain, head = chain[1:], chain[1]
    bound = imports.get(head) if head not in parameters else None
    module, export = bound if bound is not None else ("", "")
    resolved = ([export] if export else []) + chain[1:] if bound is not None else chain
    name = resolved[-1] if resolved else last
    arguments = node.child_by_field_name("arguments")
    values = (
        [child for child in arguments.named_children if child.type != "comment"]
        if arguments is not None and arguments.type == "arguments"
        else []
    )
    executes = module == "child_process" and name in _TS_EXECUTE
    evaluates = bound is None and head == "eval" and len(chain) == 1 and "eval" not in parameters
    if executes or evaluates:
        seen.add(CapabilityClass.EXECUTE)
        seen.execute = True
    if module == "fs":
        if name in _TS_FS_DELETE:
            seen.delete(CapabilityClass.FILESYSTEM)
        elif name in _TS_FS_WRITE:
            seen.write(CapabilityClass.FILESYSTEM)
    if (bound is None and head == "fetch" and len(chain) == 1) or module in _TS_HTTP:
        seen.add(CapabilityClass.NETWORK)
        method = _ts_method(values[1]) if len(values) > 1 else ""
        if method in {"POST", "PUT", "PATCH", "DELETE"} or (
            module in _TS_HTTP and name in _HTTP_WRITE
        ):
            seen.write()
    if last in {"sendMail", "sendEmail"} and len(chain) > 1:
        seen.add(CapabilityClass.NETWORK)
        seen.write()
    if (
        (module == "stripe" or head.lower() == "stripe")
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
