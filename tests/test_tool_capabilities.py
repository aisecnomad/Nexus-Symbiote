"""Source-declared tools carry the risk-raising capabilities their bodies name, nothing more.

The negative controls are the false positives an independent review reproduced on an
earlier head: ordinary names that share a capability name, unimported names, comments,
constants interpolated into SQL, and non-secret environment variables. A body is never
recorded as read-only, because the classifier cannot show that it writes nothing.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
import types
from dataclasses import replace
from pathlib import Path

import pytest

from nexus_symbiote import limits
from nexus_symbiote.core.enums import CapabilityClass, SideEffectProfile
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.tool_capabilities import (
    EVIDENCE,
    MAX_BODY_NODES,
    PythonScopes,
    ToolCapabilities,
    classify_python,
)

IMPORT = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
SERVER = "const server = new McpServer({name: 'demo', version: '1'});\n"
E = CapabilityClass


def _classify(source: str) -> ToolCapabilities:
    tree = ast.parse(source)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef))
    return classify_python(function, PythonScopes(tree))


def _tools(root: Path) -> dict[str, ToolComponent]:
    result = MCPScanner().scan(root)
    return {c.name: c for c in result.components if isinstance(c, ToolComponent)}


def _ts(tmp_path: Path, handler: str, header: str = "") -> ToolComponent:
    path = tmp_path / "src" / "server.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(IMPORT + header + SERVER + f'server.tool("t", {{}}, {handler});\n')
    return _tools(tmp_path)["t"]


def _caps(tool: ToolComponent) -> set[CapabilityClass]:
    return set(tool.capabilities.capabilities) if tool.capabilities else set()


# ---- Python: positive evidence ------------------------------------------------------------


def test_shell_execution_is_execute_and_a_high_finding() -> None:
    found = _classify(
        "import subprocess\n\ndef run_shell(command: str) -> str:\n"
        "    return subprocess.run(command, shell=True, capture_output=True).stdout\n"
    )
    assert E.EXECUTE in found.capabilities
    assert found.profile is SideEffectProfile.STATE_MODIFYING
    (risk,) = found.risks
    assert risk.severity.value == "high" and "runs commands" in risk.detail


def test_an_import_alias_resolves_to_its_module() -> None:
    found = _classify(
        "from subprocess import run as sh\n\ndef go(c: str) -> str:\n    return sh(c)\n"
    )
    assert E.EXECUTE in found.capabilities


def test_an_http_client_bound_in_the_body_sends_data() -> None:
    found = _classify(
        "import httpx\n\nasync def report(hook: str, rows: list) -> int:\n"
        "    async with httpx.AsyncClient() as client:\n"
        "        response = await client.post(hook, json=rows)\n"
        "    return response.status_code\n"
    )
    assert {E.NETWORK, E.WRITE} <= set(found.capabilities)
    assert found.profile is SideEffectProfile.STATE_MODIFYING
    session = _classify(
        "import requests\n\ndef drop(url: str) -> int:\n"
        "    return requests.Session().delete(url).status_code\n"
    )
    assert E.WRITE in session.capabilities


def test_sql_built_from_a_parameter_is_caller_supplied() -> None:
    for body in (
        "    sql = f'DELETE FROM {table}'\n    db.execute(sql)\n",
        "    db.execute('DELETE FROM t WHERE id = {tid}'.format(tid=table))\n",
        "    db.execute('DELETE FROM ' + table)\n",
        "    sqlite3.connect('x.db').execute(table)\n",
    ):
        found = _classify(f"import sqlite3\n\ndef purge(db, table: str) -> None:\n{body}")
        assert found.profile is SideEffectProfile.DESTRUCTIVE, body
        assert any("caller-supplied" in r.detail for r in found.risks), body


def test_a_parameterized_query_names_nothing_and_a_literal_delete_is_destructive() -> None:
    safe = _classify(
        "import sqlite3\n\ndef lookup(conn, tid: str) -> list:\n"
        "    return conn.execute('SELECT * FROM t WHERE id = ?', (tid,)).fetchall()\n"
    )
    assert safe.declaration is None and not safe.risks
    delete = _classify(
        "from sqlalchemy.sql import text\n\ndef clear(session) -> None:\n"
        "    session.execute(text('DELETE FROM sessions'))\n"
    )
    assert delete.profile is SideEffectProfile.DESTRUCTIVE and not delete.risks


def test_payment_writes_filesystem_deletes_and_secret_reads() -> None:
    found = _classify(
        "import os\nimport shutil\nimport stripe\nfrom pathlib import Path\n\n"
        "def refund(charge: str, path: str) -> str:\n"
        "    stripe.api_key = os.environ['STRIPE_SECRET_KEY']\n"
        "    stripe.Refund.create(charge=charge)\n"
        "    Path(path).unlink()\n"
        "    shutil.rmtree(path)\n"
        "    return 'ok'\n"
    )
    assert {E.PAYMENT, E.NETWORK, E.WRITE, E.DESTRUCTIVE, E.FILESYSTEM, E.CREDENTIALS} <= set(
        found.capabilities
    )
    assert found.profile is SideEffectProfile.FINANCIAL_TRANSACTION
    # A payment write is high, as a configured financial-transaction tool is.
    assert [r.severity.value for r in found.risks] == ["high"]


# ---- Python: never read-only, never from unresolved names ---------------------------------


def test_a_body_is_never_read_only_and_reads_alone_record_nothing() -> None:
    reads = _classify(
        "import requests\n\ndef fetch(url: str, path: str) -> str:\n"
        "    with open(path) as fh:\n        fh.read()\n"
        "    return requests.get(url).text\n"
    )
    assert reads.profile is not SideEffectProfile.READ_ONLY
    assert E.READ not in reads.capabilities
    assert set(reads.capabilities) == {E.NETWORK}
    mode = _classify("def save(path: str, mode: str) -> None:\n    open(path, mode).close()\n")
    assert mode.declaration is None


@pytest.mark.parametrize(
    "body",
    [
        "    items.remove(items[0])\n    settings.copy()\n    settings.get('level')\n",
        "    def square(x):\n        return x * x\n    return square(2)\n",
        "    stripe.Refund.create(charge='x')\n    requests.post('u')\n",
        "    raise subprocess.CalledProcessError(1, 'x')\n",
        "    executor.execute(job)\n",
        "    stripe_lib.Webhook.construct_event(payload, sig, secret)\n",
    ],
    ids=["builtins", "local-function", "parameters", "exception", "executor", "webhook"],
)
def test_unresolved_and_ordinary_names_count_for_nothing(body: str) -> None:
    found = _classify(
        "import subprocess\nimport sqlite3\nimport stripe as stripe_lib\n\n"
        "def tool(items, settings, stripe, requests, executor, job, payload, sig, secret):\n" + body
    )
    assert found.declaration is None and not found.risks, body


def test_only_secret_named_environment_variables_are_credentials() -> None:
    for plain in ("OUTPUT_PATH", "GIT_AUTHOR_NAME", "LOG_LEVEL"):
        found = _classify(f"import os\n\ndef v() -> str:\n    return os.environ['{plain}']\n")
        assert found.declaration is None, plain
    secret = _classify(
        "from os import getenv\n\ndef k() -> str:\n    return getenv('OPENAI_API_KEY')\n"
    )
    assert secret.capabilities == [E.CREDENTIALS]


def test_decorators_are_not_part_of_the_body() -> None:
    found = _classify(
        "import requests\n\n@requests.post('/x')\ndef tool(x: str) -> str:\n    return x\n"
    )
    assert found.declaration is None


def test_a_body_past_the_bound_is_unclassified_and_recorded_as_a_gap(tmp_path: Path) -> None:
    padding = "    _ = [" + "0, " * (MAX_BODY_NODES + 1) + "]\n"
    (tmp_path / "server.py").write_text(
        "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('t')\n\n"
        "@mcp.tool()\ndef run(cmd: str) -> str:\n"
        f'    """Run."""\n{padding}    return subprocess.check_output(cmd)\n'
    )
    result = MCPScanner().scan(tmp_path)
    (tool,) = [c for c in result.components if isinstance(c, ToolComponent)]
    assert tool.capabilities is None
    assert any("too large or too ambiguous to classify" in gap for gap in result.surfaces_excluded)


def test_python_mcp_tools_carry_capabilities_and_their_evidence(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import os\nimport subprocess\nfrom mcp.server.fastmcp import FastMCP\n\n"
        "mcp = FastMCP('tickets')\n\n"
        "@mcp.tool()\ndef purge(path: str) -> None:\n"
        '    """Delete a ticket file."""\n    os.remove(path)\n\n'
        "@mcp.tool()\ndef shell(command: str) -> str:\n"
        '    """Shell."""\n    return subprocess.check_output(command, shell=True).decode()\n\n'
        '@mcp.tool()\ndef greet(name: str) -> str:\n    """Say hi."""\n    return name\n'
    )
    tools = _tools(tmp_path)
    purge = tools["purge"]
    assert purge.capabilities is not None
    assert purge.capabilities.side_effect_profile is SideEffectProfile.DESTRUCTIVE
    assert purge.properties["capability_evidence"] == EVIDENCE
    assert not purge.risks, "a deletion alone sets the profile without a finding"
    shell = tools["shell"]
    assert E.EXECUTE in _caps(shell)
    assert any(r.category == "capability_scope" and r.severity.value == "high" for r in shell.risks)
    assert tools["greet"].capabilities is None
    assert "capability_evidence" not in tools["greet"].properties


def test_a_python_tool_that_runs_a_caller_statement_is_destructive_and_high(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import sqlite3\nfrom mcp.server.fastmcp import FastMCP\n\n"
        "mcp = FastMCP('tickets')\nengine = sqlite3.connect('t.db')\n\n"
        "@mcp.tool()\ndef run_sql(statement: str) -> list:\n"
        '    """Run SQL."""\n    return list(engine.execute(statement))\n'
    )
    run_sql = _tools(tmp_path)["run_sql"]
    assert run_sql.capabilities is not None
    assert run_sql.capabilities.side_effect_profile is SideEffectProfile.DESTRUCTIVE
    assert run_sql.properties["capability_evidence"] == EVIDENCE
    assert any(
        r.category == "capability_scope" and r.severity.value == "high" for r in run_sql.risks
    )


@pytest.mark.parametrize(
    ("body", "expected", "profile"),
    [
        ("    conn.execute('INSERT INTO t VALUES (1)')\n", {E.WRITE}, "state-modifying"),
        (
            "    stmt: str = 'DROP TABLE t'\n    conn.execute(stmt)\n",
            {E.WRITE, E.DESTRUCTIVE},
            "destructive",
        ),
    ],
    ids=["literal-insert", "annotated-local-drop"],
)
def test_python_sql_statement_forms(
    body: str, expected: set[CapabilityClass], profile: str
) -> None:
    found = _classify(f"def tool(conn):\n{body}")
    assert set(found.capabilities) == expected, body
    assert found.profile.value == profile, body


# ---- TypeScript ---------------------------------------------------------------------------


def test_typescript_child_process_fs_fetch_and_payment(tmp_path: Path) -> None:
    header = (
        'import { execSync } from "node:child_process";\n'
        'import * as fs from "fs";\n'
        'import Stripe from "stripe";\n'
        "const stripe = new Stripe(key);\n"
    )
    tool = _ts(
        tmp_path,
        "async ({ cmd, path, id }) => { execSync(cmd); fs.rmSync(path);"
        " await fetch(hook, { method: 'POST', body: '' });"
        " await stripe.refunds.create({ charge: id }); }",
        header,
    )
    assert {E.EXECUTE, E.FILESYSTEM, E.DESTRUCTIVE, E.NETWORK, E.WRITE, E.PAYMENT} <= _caps(tool)
    assert tool.capabilities is not None
    assert tool.capabilities.side_effect_profile is SideEffectProfile.FINANCIAL_TRANSACTION
    assert tool.properties["capability_evidence"] == EVIDENCE
    risks = [r for r in tool.risks if r.category == "capability_scope"]
    assert [r.severity.value for r in risks] == ["high", "high"], risks


def test_typescript_evaluation_and_secret_reads(tmp_path: Path) -> None:
    for handler in (
        "(c) => globalThis.eval(c)",
        "(c) => new Function(c)()",
        "(c) => eval(c)",
    ):
        assert E.EXECUTE in _caps(_ts(tmp_path / handler[:8].strip("() =>"), handler)), handler
    tool = _ts(tmp_path / "env", "() => { const { API_TOKEN } = process.env; return API_TOKEN; }")
    assert _caps(tool) == {E.CREDENTIALS}


@pytest.mark.parametrize(
    "handler",
    [
        "() => {\n  // never calls eval( or execSync(\n  return 'pong';\n}",
        "({ s }) => { const m = /a(b)/.exec(s); return m; }",
        "({ n }) => pool.spawn(n)",
        "({ r }) => gh.repos.fork(r)",
        "({ id }) => db.query(`SELECT * FROM ${TABLE} WHERE id = $1`, [id])",
        "({ id }) => db.query(SQL, [id])",
        "({ id }) => sql`SELECT * FROM t WHERE id = ${id}`",
        "() => process.env.LOG_LEVEL",
        "(stripe) => stripe.refunds.list()",
    ],
)
def test_typescript_negative_controls(tmp_path: Path, handler: str) -> None:
    tool = _ts(tmp_path, handler)
    assert tool.capabilities is None, handler
    assert not [r for r in tool.risks if r.category == "capability_scope"], handler


def test_typescript_sql_from_a_parameter_is_caller_supplied(tmp_path: Path) -> None:
    for name, handler in {
        "a": "({ id }) => db.query(`DELETE FROM t WHERE id = ${id}`)",
        "b": "({ statement }) => prisma.$queryRawUnsafe(statement)",
    }.items():
        tool = _ts(tmp_path / name, handler)
        assert any("caller-supplied" in r.detail for r in tool.risks), handler


def test_a_nested_registration_is_classified_by_its_own_handler_only(tmp_path: Path) -> None:
    path = tmp_path / "src" / "server.ts"
    path.parent.mkdir(parents=True)
    path.write_text(
        IMPORT
        + 'import { execSync, exec } from "child_process";\nimport * as fs from "fs";\n'
        + SERVER
        + 'server.tool("outer", {}, async () => {\n'
        + '  server.tool("inner", {}, async ({ cmd }) => execSync(cmd).toString());\n'
        + '  server.tool("argument", exec("id"), named);\n'
        + "  fs.writeFileSync('log.txt', 'ok');\n"
        + "});\n"
    )
    tools = _tools(tmp_path)
    assert {E.EXECUTE, E.WRITE} <= _caps(tools["outer"])
    assert E.EXECUTE in _caps(tools["inner"]) and E.WRITE not in _caps(tools["inner"])
    assert tools["argument"].capabilities is None


def test_a_handler_bound_elsewhere_stays_unknown(tmp_path: Path) -> None:
    tool = _ts(tmp_path, "handler", 'import { execSync } from "child_process";\n')
    assert tool.capabilities is None


# ---- Re-review of 0a81b273 ------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "    return os.getenv('NAME', '').replace('-', '_')\n",
        "    return os.environ.copy()\n",
        "    return os.path.join('x', name).replace('\\\\', '/')\n",
        "    return quote(name)\n",
        "    return socket.gethostname()\n",
        "    return redis.Redis().unlink(name)\n",
    ],
    ids=["getenv-replace", "environ-copy", "path-replace", "url-quote", "hostname", "redis"],
)
def test_values_returned_by_a_module_and_unrelated_modules_name_nothing(body: str) -> None:
    found = _classify(
        "import os\nimport socket\nimport redis\nfrom urllib.parse import quote\n\n"
        "def tool(name: str) -> object:\n" + body
    )
    assert found.declaration is None, body


def test_only_payment_resources_are_payments() -> None:
    customer = _classify(
        "import stripe\n\ndef c(e: str) -> object:\n    return stripe.Customer.create(email=e)\n"
    )
    assert customer.profile is not SideEffectProfile.FINANCIAL_TRANSACTION and not customer.risks
    assert customer.capabilities == [E.NETWORK]


@pytest.mark.parametrize(
    ("header", "handler"),
    [
        ("", "(c) => require('child_process').execSync(c)"),
        ("", "async (c) => { const { execSync } = await import('child_process'); execSync(c); }"),
        (
            'import { exec } from "child_process";\nimport { promisify } from "util";\nconst run = promisify(exec);\n',
            "(c) => run(c)",
        ),
        ("", "(c) => (0, eval)(c)"),
    ],
    ids=["inline-require", "dynamic-import", "promisify", "comma-eval"],
)
def test_typescript_loaded_and_wrapped_execution(tmp_path: Path, header: str, handler: str) -> None:
    assert E.EXECUTE in _caps(_ts(tmp_path, handler, header)), handler


def test_typescript_handler_bindings_shadow_imports(tmp_path: Path) -> None:
    shadow = _ts(
        tmp_path,
        "(c) => { const exec = (x) => x; const fetch = cache.get; exec(c); return fetch(c); }",
        'import { exec } from "child_process";\n',
    )
    assert shadow.capabilities is None


def test_typescript_names_bound_from_a_parameter_carry_taint(tmp_path: Path) -> None:
    tainted = _ts(
        tmp_path,
        "(args) => { const { id } = args; return db.query(`DELETE FROM t WHERE id = ${id}`); }",
    )
    assert any("caller-supplied" in r.detail for r in tainted.risks)


@pytest.mark.parametrize("kind", ["member", "call", "template"])
def test_long_chains_and_nested_templates_stay_linear(tmp_path: Path, kind: str) -> None:
    import time

    def handler(n: int) -> str:
        if kind == "member":
            return "async () => x" + ".a" * n
        if kind == "call":
            return "async () => x" + ".a()" * n
        inner = "1"
        for _ in range(n):
            inner = "db.query(`${" + inner + "}`)"
        return "async () => " + inner

    def cost(n: int) -> float:
        root = tmp_path / f"{kind}{n}"
        start = time.process_time()
        _ts(root, handler(n))
        return time.process_time() - start

    small, large = cost(500), cost(2000)
    assert large < max(small, 0.05) * 12, (small, large)


# ---- Remaining forms ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected", "profile"),
    [
        ("    path.write_text(data)\n", {E.FILESYSTEM, E.WRITE}, "state-modifying"),
        ("    path.unlink()\n", {E.FILESYSTEM, E.WRITE, E.DESTRUCTIVE}, "destructive"),
        ("    open(path, 'w').write(data)\n", {E.FILESYSTEM, E.WRITE}, "state-modifying"),
        ("    Path(path).write_text(data)\n", {E.FILESYSTEM, E.WRITE}, "state-modifying"),
        ("    os.rename(path, data)\n", {E.FILESYSTEM, E.WRITE}, "state-modifying"),
        ("    os.remove(path)\n", {E.FILESYSTEM, E.WRITE, E.DESTRUCTIVE}, "destructive"),
        (
            "    conn.execute(*args)\n    smtplib.SMTP('h').sendmail(a, b, data)\n",
            {E.NETWORK, E.WRITE, E.DESTRUCTIVE},
            "destructive",
        ),
    ],
)
def test_python_forms(body: str, expected: set[CapabilityClass], profile: str) -> None:
    found = _classify(
        "import os\nimport smtplib\nfrom pathlib import Path\n\n"
        f"def tool(path, data, conn, a, b, *args, **kwargs):\n{body}"
    )
    assert set(found.capabilities) == expected, body
    assert found.profile.value == profile, body


@pytest.mark.parametrize(
    ("header", "handler", "expected"),
    [
        ('import * as cp from "child_process";\n', "(c) => cp.spawn(c)", {E.EXECUTE}),
        ('import { execFile as run } from "child_process";\n', "(c) => run(c)", {E.EXECUTE}),
        ('const cp = require("child_process");\n', "(c) => cp.exec(c)", {E.EXECUTE}),
        (
            'const { writeFileSync } = require("fs");\n',
            "(p) => writeFileSync(p, 'x')",
            {E.FILESYSTEM, E.WRITE},
        ),
        ('import fs from "node:fs";\n', "(p) => fs.writeFileSync(p, 'x')", {E.FILESYSTEM, E.WRITE}),
        ('import axios from "axios";\n', "(u) => axios.post(u, {})", {E.NETWORK, E.WRITE}),
        ('import axios from "axios";\n', "(u) => axios.get(u)", {E.NETWORK}),
        ("", "(u) => fetch(u, { headers: {} })", {E.NETWORK}),
        ("", "(u) => fetch(u, opts)", {E.NETWORK}),
        ("", "(to) => mailer.sendMail({ to })", {E.NETWORK, E.WRITE}),
        ("", "() => process.env['GITHUB_TOKEN']", {E.CREDENTIALS}),
        ("", "() => process.env.STRIPE_SECRET_KEY", {E.CREDENTIALS}),
        ("", "() => { function fetch(u) { return u; } return fetch('x'); }", set()),
    ],
)
def test_typescript_forms(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass]
) -> None:
    assert _caps(_ts(tmp_path, handler, header)) == expected, handler


def test_typescript_parameter_use_past_its_bound_is_assumed(tmp_path: Path) -> None:
    template = "(id) => db.query(`DELETE FROM t WHERE x = ${ARGUMENT}`)"
    tool = _ts(tmp_path, template.replace("ARGUMENT", " + ".join(["k"] * 400)))
    assert any("caller-supplied" in r.detail for r in tool.risks)


def test_a_typescript_body_past_the_bound_records_a_gap(tmp_path: Path) -> None:
    path = tmp_path / "src" / "server.ts"
    path.parent.mkdir(parents=True)
    body = "; ".join(f"x{i}()" for i in range(7000))
    path.write_text(IMPORT + SERVER + f'server.tool("t", {{}}, async () => {{ {body}; }});\n')
    # The test default refuses a file this size; production allows far larger files.
    with limits.applied(replace(limits.DEFAULTS, ts_nodes=400_000)):
        result = MCPScanner().scan(tmp_path)
    (tool,) = [c for c in result.components if isinstance(c, ToolComponent)]
    assert tool.capabilities is None
    assert any("too large or too ambiguous to classify" in gap for gap in result.surfaces_excluded)


# ---- Final check of ca4c0f6b ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("from shutil import rmtree as nuke\n\ndef t(p):\n    nuke(p)\n", {E.DESTRUCTIVE}),
        ("from os import remove as rmf\n\ndef t(p):\n    rmf(p)\n", {E.DESTRUCTIVE}),
        ("from requests import post as send\n\ndef t(u):\n    send(u)\n", {E.WRITE}),
        ("ROOT = 1\n\ndef t(name):\n    (ROOT / name).unlink()\n", {E.DESTRUCTIVE}),
        ("import stripe\n\ndef t(i):\n    stripe.Invoice.pay(i)\n", {E.PAYMENT}),
    ],
    ids=["alias-rmtree", "alias-remove", "alias-post", "expression-receiver", "invoice-pay"],
)
def test_python_aliases_and_expression_receivers(
    source: str, expected: set[CapabilityClass]
) -> None:
    assert expected <= set(_classify(source).capabilities), source


def test_a_second_binding_of_a_name_cannot_hide_the_first(tmp_path: Path) -> None:
    path = tmp_path / "src" / "server.ts"
    path.parent.mkdir(parents=True)
    path.write_text(
        IMPORT
        + 'import { execSync } from "child_process";\n'
        + SERVER
        + 'server.tool("a", {}, (c) => execSync(c));\n'
        + 'server.tool("b", {}, (c) => { const { execSync } = require("./safe"); return execSync(c); });\n'
        + 'function unused() { const { execSync } = require("./noop"); return execSync; }\n'
    )
    tools = _tools(tmp_path)
    assert E.EXECUTE in _caps(tools["a"])
    assert E.EXECUTE in _caps(tools["b"])


@pytest.mark.parametrize(
    ("header", "handler", "expected"),
    [
        (
            'import { execSync } from "child_process";\n',
            "async ({ c }, _ = execSync) => execSync(c)",
            {E.EXECUTE},
        ),
        (
            'import { execSync } from "child_process";\n',
            "(c) => { if (c) { const execSync = 1; } return execSync(c); }",
            {E.EXECUTE},
        ),
        (
            "",
            '(c) => { const run = require("child_process").execSync; return run(c); }',
            {E.EXECUTE},
        ),
        ("", "() => globalThis.process.env.API_KEY", {E.CREDENTIALS}),
        ("", "() => process['env'].API_KEY", {E.CREDENTIALS}),
        ('import http from "http";\n', "() => http.createServer(handler)", set()),
        (
            'import { execSync } from "child_process";\n',
            "(c) => { if (c) { const execSync = c; } return execSync(c); }",
            {E.EXECUTE},
        ),
        (
            "",
            "({ u }) => { if (false) { const fetch = u; } return fetch(u, { method: 'POST' }); }",
            {E.NETWORK, E.WRITE},
        ),
    ],
    ids=[
        "default-value",
        "nested-block",
        "require-member",
        "global-process",
        "env-subscript",
        "server",
        "nested-block-from-parameter",
        "dead-branch-from-parameter",
    ],
)
def test_typescript_final_check_forms(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass]
) -> None:
    assert _caps(_ts(tmp_path, handler, header)) == expected, handler


def test_a_local_too_large_to_read_is_not_tainted(tmp_path: Path) -> None:
    columns = ", ".join(f"'c{i}'" for i in range(130))
    template = "(id) => { const cols = [COLUMNS]; return db.query(`SELECT ${cols.join(',')} FROM t`, [id]); }"
    tool = _ts(tmp_path, template.replace("COLUMNS", columns))
    assert not [r for r in tool.risks if r.category == "capability_scope"]


# ---- Review of 17cd06df: Python scoping and destructured TypeScript bindings ---------------


def _classify_named(source: str, name: str) -> ToolCapabilities:
    tree = ast.parse(source)
    function = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == name
    )
    return classify_python(function, PythonScopes(tree))


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "import subprocess as runner\n\ndef helper():\n    import math as runner\n"
            "    return runner.sqrt(9)\n\ndef tool(cmd):\n    return runner.run(cmd, shell=True)\n",
            {E.EXECUTE},
        ),
        (
            "from subprocess import run\n\ndef tool(cmd):\n    def inner():\n"
            "        run = lambda x: x\n        return run\n    return run(cmd)\n",
            {E.EXECUTE},
        ),
        (
            "from subprocess import run\n\ndef tool(x):\n    def run(v):\n        return v\n    return run(x)\n",
            set(),
        ),
        (
            "from subprocess import run\n\ndef tool(items):\n    for run in items:\n        run()\n",
            set(),
        ),
        ("from subprocess import run\n\ndef tool(fs):\n    return [run() for run in fs]\n", set()),
        (
            "from subprocess import run\n\ndef tool(cs):\n    return [run(c) for c in cs]\n",
            {E.EXECUTE},
        ),
        (
            "from subprocess import run\n\ndef tool(ctx):\n    with ctx() as run:\n        run()\n",
            set(),
        ),
        (
            "import subprocess\n\ndef tool(c):\n    run = subprocess.run\n    return run(c)\n",
            {E.EXECUTE},
        ),
        (
            "import subprocess\n\ndef register(mcp):\n    import shutil\n\n    @mcp.tool()\n"
            "    def tool(p):\n        shutil.rmtree(p)\n        return subprocess.run(p)\n",
            {E.EXECUTE, E.DESTRUCTIVE},
        ),
        (
            "import subprocess\n\nclass Tools:\n    subprocess = None\n\n"
            "    def tool(self, c):\n        return subprocess.run(c)\n",
            {E.EXECUTE},
        ),
        (
            "from subprocess import run\n\ndef tool(cmd):\n    class K:\n        if False:\n"
            "            run = None\n        out = run(cmd)\n    return K.out\n",
            {E.EXECUTE},
        ),
        (
            "import subprocess\nrunner = None\n\ndef tool(c):\n    global runner\n"
            "    runner = subprocess.run\n    return runner(c)\n",
            {E.EXECUTE},
        ),
        (
            "try:\n    from subprocess import run\nexcept ImportError:\n    run = None\n\n"
            "def tool(c):\n    return run(c)\n",
            {E.EXECUTE},
        ),
        (
            "from subprocess import run\nfrom math import prod as run\n\ndef tool(c):\n    return run(c)\n",
            {E.EXECUTE},
        ),
        ("from subprocess import run\n\ndef tool(c, run):\n    return run(c)\n", set()),
        (
            "from subprocess import run\nfrom .local import run\n\ndef tool(c):\n    return run(c)\n",
            {E.EXECUTE},
        ),
        ("from .local import run\n\ndef tool(c):\n    return run(c)\n", set()),
    ],
    ids=[
        "import-in-another-function",
        "binding-in-a-nested-function",
        "local-def",
        "loop-target",
        "comprehension-target",
        "comprehension-reads-the-import",
        "with-target",
        "local-alias",
        "enclosing-function-import",
        "class-names-are-not-method-locals",
        "class-body-falls-through",
        "global-declaration",
        "conditional-module-import",
        "every-module-binding-is-kept",
        "parameter",
        "relative-import-adds-nothing",
        "relative-import-alone",
    ],
)
def test_python_names_follow_python_scoping(source: str, expected: set[CapabilityClass]) -> None:
    found = _classify_named(source, "tool")
    assert expected <= set(found.capabilities), source
    if not expected:
        assert found.declaration is None and not found.risks, source


@pytest.mark.parametrize(
    "body",
    [
        "    if False:\n        from math import prod as run\n    return run(cmd)\n",
        "    if False:\n        run = lambda x: x\n    return run(cmd)\n",
    ],
    ids=["import", "assignment"],
)
def test_a_binding_in_a_branch_that_never_runs_makes_the_name_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    # Python makes ``run`` local to the whole function, so the call cannot reach the import.
    found = _classify_named(f"from subprocess import run\n\ndef tool(cmd):\n{body}", "tool")
    assert found.declaration is None and not found.risks
    stand_in = types.ModuleType("stand_in")
    stand_in.run = lambda command: command  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "stand_in", stand_in)
    path = tmp_path / "dead_branch.py"
    path.write_text(f"from stand_in import run\n\ndef tool(cmd):\n{body}")
    spec = importlib.util.spec_from_file_location("dead_branch", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(UnboundLocalError):
        module.tool("x")


def test_a_name_with_too_many_targets_is_unclassified(tmp_path: Path) -> None:
    imports = "".join(f"from m{i} import f as run\n" for i in range(40))
    source = imports + "from subprocess import run\n\ndef tool(c):\n    return run(c)\n"
    assert _classify_named(source, "tool").unclassified
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        + source.replace("def tool", "mcp = FastMCP('t')\n\n\n@mcp.tool()\ndef tool")
    )
    result = MCPScanner().scan(tmp_path)
    (tool,) = [c for c in result.components if isinstance(c, ToolComponent)]
    assert tool.capabilities is None
    assert any("tool: tool body too large" in gap for gap in result.surfaces_excluded)


def test_bindings_in_many_functions_do_not_leak_into_a_tool() -> None:
    helpers = "".join(
        f"def helper{i}():\n    import math as runner\n    runner = {i}\n    return runner\n\n"
        for i in range(2000)
    )
    source = f"import subprocess as runner\n\n{helpers}def tool(c):\n    return runner.run(c)\n"
    assert set(_classify_named(source, "tool").capabilities) == {E.EXECUTE}


@pytest.mark.parametrize(
    ("header", "handler", "expected"),
    [
        (
            "",
            '(c) => { const { execSync: runCmd } = require("child_process"); return runCmd(c); }',
            {E.EXECUTE},
        ),
        (
            "",
            '(p) => { const { unlink: delFile } = require("node:fs/promises"); return delFile(p); }',
            {E.FILESYSTEM, E.WRITE, E.DESTRUCTIVE},
        ),
        (
            "",
            'async (c) => { const { execSync: runCmd } = await import("child_process"); return runCmd(c); }',
            {E.EXECUTE},
        ),
        (
            'const { execSync: run = null } = require("child_process");\n',
            "(c) => run(c)",
            {E.EXECUTE},
        ),
        (
            'const { promises: { unlink: del } } = require("fs");\n',
            "(p) => del(p)",
            {E.FILESYSTEM, E.WRITE, E.DESTRUCTIVE},
        ),
        (
            'const { unlink } = require("fs").promises;\n',
            "(p) => unlink(p)",
            {E.FILESYSTEM, E.WRITE, E.DESTRUCTIVE},
        ),
        ('const { ...cp } = require("child_process");\n', "(c) => cp.exec(c)", {E.EXECUTE}),
        ('const { execSync: runCmd } = require("./safe");\n', "(c) => runCmd(c)", set()),
    ],
    ids=[
        "require-alias",
        "fs-promises-alias",
        "dynamic-import-alias",
        "alias-with-default",
        "nested-pattern",
        "require-member-pattern",
        "rest-pattern",
        "local-module",
    ],
)
def test_typescript_destructured_module_bindings(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass]
) -> None:
    assert _caps(_ts(tmp_path, handler, header)) == expected, handler


@pytest.mark.parametrize(
    ("body", "expected", "raw"),
    [
        ("    return text(q)\n", set(), False),
        ("    stmt = text(q)\n    return stmt\n", set(), False),
        ("    return session.execute(text(q))\n", {E.WRITE, E.DESTRUCTIVE}, True),
        (
            "    stmt = text(f'DELETE FROM t WHERE id = {q}')\n    return conn.execute(stmt)\n",
            {E.WRITE, E.DESTRUCTIVE},
            True,
        ),
        ("    return conn.execute(text(q).bindparams(a=1))\n", {E.WRITE, E.DESTRUCTIVE}, True),
        ("    return conn.execute(text('SELECT 1').bindparams(a=q))\n", set(), False),
        ("    return conn.execute('SELECT * FROM t -- DELETE later', (q,))\n", set(), False),
        (
            "    return conn.execute(\"SELECT * FROM t WHERE note = 'please DROP it'\")\n",
            set(),
            False,
        ),
        ("    return conn.execute('/* UPDATE */ SELECT * FROM t FOR UPDATE')\n", set(), False),
        ("    return conn.execute('SELECT 1; DROP TABLE t')\n", {E.WRITE, E.DESTRUCTIVE}, False),
        (
            "    return conn.execute('ALTER TABLE t DROP COLUMN c')\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
        (
            "    return conn.execute('CREATE TABLE t (id INT REFERENCES u ON DELETE CASCADE)')\n",
            {E.WRITE},
            False,
        ),
        (
            "    return conn.execute('WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d')\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
    ],
    ids=[
        "text-preview",
        "text-bound-and-returned",
        "text-executed",
        "text-of-an-f-string-executed",
        "text-bindparams-executed",
        "literal-text-bindparams",
        "comment-prose",
        "literal-prose",
        "lock-clause",
        "second-statement",
        "alter-drop",
        "referential-action",
        "data-modifying-cte",
    ],
)
def test_sql_is_read_as_statements_and_only_executed_sql_counts(
    body: str, expected: set[CapabilityClass], raw: bool
) -> None:
    found = _classify(f"from sqlalchemy import text\n\ndef tool(q, session, conn):\n{body}")
    assert set(found.capabilities) == expected, body
    assert any("caller-supplied" in r.detail for r in found.risks) is raw, body


@pytest.mark.parametrize(
    ("handler", "expected"),
    [
        ('(id) => db.query("UPDATE t SET seen = 1 WHERE id = $1", [id])', {E.WRITE}),
        ("() => db.query('DELETE FROM sessions')", {E.WRITE, E.DESTRUCTIVE}),
        ("(id) => db.query(`UPDATE t SET n = ${LIMIT} WHERE id = $1`, [id])", {E.WRITE}),
        ("() => db.query('SELECT * FROM t -- DELETE later')", set()),
        ("() => db.query(\"SELECT * FROM t WHERE note = 'please DROP it'\")", set()),
        ("(q) => index.query('Update my profile')", set()),
    ],
    ids=["update", "delete", "constant-substitution", "comment", "literal", "prose"],
)
def test_typescript_literal_sql_is_classified_by_its_statement(
    tmp_path: Path, handler: str, expected: set[CapabilityClass]
) -> None:
    tool = _ts(tmp_path, handler)
    assert _caps(tool) == expected, handler
    assert not [r for r in tool.risks if r.category == "capability_scope"], handler


@pytest.mark.parametrize(
    ("body", "expected", "raw"),
    [
        (
            "    sql = 'DELETE FROM t'\n    conn.execute(sql)\n    sql = 'SELECT 1'\n"
            "    return conn.execute(sql)\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
        (
            "    sql = f'DELETE FROM t WHERE n = {q}'\n    conn.execute(sql)\n    sql = 'SELECT 1'\n",
            {E.WRITE, E.DESTRUCTIVE},
            True,
        ),
        ("    sql = 'SELECT 1'\n    conn.execute(sql)\n    sql = 'DELETE FROM t'\n", set(), False),
        (
            "    if q:\n        sql = 'DELETE FROM t'\n    else:\n        sql = 'SELECT 1'\n"
            "    conn.execute(sql)\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
        (
            "    sql = 'SELECT 1'\n    for row in q:\n        conn.execute(sql)\n"
            "        sql = 'UPDATE t SET seen = 1'\n",
            {E.WRITE},
            False,
        ),
        ("    return conn.execute('EXPLAIN DELETE FROM t')\n", set(), False),
        ("    return conn.execute('EXPLAIN QUERY PLAN DELETE FROM t')\n", set(), False),
        (
            "    return conn.execute('EXPLAIN ANALYZE DELETE FROM t')\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
        (
            "    return conn.execute('EXPLAIN (ANALYZE, BUFFERS) UPDATE t SET a = 1')\n",
            {E.WRITE},
            False,
        ),
        (
            "    return conn.execute('SELECT $doc$ Use UPDATE t SET a = 1; DROP TABLE t $doc$')\n",
            set(),
            False,
        ),
        ("    return conn.execute('SELECT $$ (DELETE FROM t) $$')\n", set(), False),
        (
            "    return conn.execute('DELETE FROM t WHERE id = $1', (q,))\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
    ],
    ids=[
        "later-assignment",
        "later-assignment-of-caller-text",
        "assignment-after-the-call",
        "either-branch",
        "loop-carried",
        "explain",
        "explain-query-plan",
        "explain-analyze",
        "explain-options",
        "dollar-quoted",
        "empty-dollar-tag",
        "positional-parameter",
    ],
)
def test_sql_is_classified_at_the_call_as_it_runs(
    body: str, expected: set[CapabilityClass], raw: bool
) -> None:
    found = _classify(f"def tool(q, conn):\n{body}")
    assert set(found.capabilities) == expected, body
    assert any("caller-supplied" in r.detail for r in found.risks) is raw, body


@pytest.mark.parametrize(
    "handler",
    [
        "() => db.query('EXPLAIN UPDATE t SET a = 1')",
        "() => db.query('SELECT $$; DROP TABLE t $$')",
    ],
    ids=["explain", "dollar-quoted"],
)
def test_typescript_plans_and_quoted_sql_write_nothing(tmp_path: Path, handler: str) -> None:
    assert _caps(_ts(tmp_path, handler)) == set(), handler


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "import subprocess\n\ndef register():\n    run = subprocess.run\n\n"
            "    def tool(c):\n        nonlocal run\n        run = subprocess.call\n        return run(c)\n",
            {E.EXECUTE},
        ),
        (
            "from subprocess import run\n\ndef register():\n    run = print\n\n"
            "    def tool(c):\n        nonlocal run\n        return run(c)\n",
            set(),
        ),
        (
            "import subprocess\n\ndef tool(c):\n    if (run := subprocess.run):\n        return run(c)\n",
            {E.EXECUTE},
        ),
        (
            "import subprocess\n\ndef tool(cs):\n    [(run := subprocess.run) for _ in cs]\n    return run(cs)\n",
            {E.EXECUTE},
        ),
        (
            "from subprocess import run\n\ndef tool(c, lock):\n    with lock:\n        del run\n    return run(c)\n",
            set(),
        ),
        (
            "from subprocess import run\n\ndef tool(c):\n    try:\n        pass\n"
            "    except Exception as run:\n        pass\n    return run(c)\n",
            set(),
        ),
        (
            "from subprocess import run\n\ndef tool(c):\n    match c:\n        case {'a': 1, **run}:\n"
            "            pass\n        case [*rest] if rest:\n            pass\n    return run(c)\n",
            set(),
        ),
        (
            "from subprocess import run\n\ndef tool(c):\n    match c:\n        case str() as run:\n"
            "            pass\n    return run(c)\n",
            set(),
        ),
        (
            "from subprocess import run\n\ndef tool(c, pair):\n    run, *rest = pair\n    return run(c)\n",
            set(),
        ),
        (
            "from subprocess import run\n\ndef tool(c, pair):\n    *rest, run = pair\n    return run(c)\n",
            set(),
        ),
        (
            "from os import *\nimport subprocess\n\ndef tool(c):\n    return subprocess.run(c)\n",
            {E.EXECUTE},
        ),
        ("def tool(x):\n    x" + ".a" * 20 + ".unlink()\n", set()),
    ],
    ids=[
        "nonlocal-rebinding",
        "nonlocal-local-value",
        "walrus",
        "walrus-in-comprehension",
        "del",
        "except-target",
        "match-mapping-and-star",
        "match-as",
        "unpacking",
        "starred-unpacking",
        "star-import",
        "chain-past-the-bound",
    ],
)
def test_python_binding_forms(source: str, expected: set[CapabilityClass]) -> None:
    found = _classify_named(source, "tool")
    assert set(found.capabilities) == expected, source
    if not expected:
        assert found.declaration is None and not found.risks, source


def test_a_name_aliasing_one_with_too_many_targets_is_unclassified() -> None:
    imports = "".join(f"from m{i} import f as x\n" for i in range(40))
    source = imports + "run = x\n\ndef tool(c):\n    return run(c)\n"
    assert _classify_named(source, "tool").unclassified


def test_a_function_classified_without_its_module_scopes_still_reads_its_own() -> None:
    tree = ast.parse("def tool(c):\n    import subprocess\n    return subprocess.run(c)\n")
    function = tree.body[0]
    assert isinstance(function, ast.FunctionDef)
    assert set(classify_python(function).capabilities) == {E.EXECUTE}


def test_a_doubled_quote_stays_inside_its_literal() -> None:
    found = _classify(
        "def tool(conn):\n    conn.execute(\"INSERT INTO t VALUES ('it''s; DROP TABLE x')\")\n"
    )
    assert set(found.capabilities) == {E.WRITE}


def test_a_body_registered_under_many_names_is_read_once(tmp_path: Path) -> None:
    import time

    def cost(names: int) -> float:
        root = tmp_path / str(names)
        root.mkdir()
        (root / "server.py").write_text(
            "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('t')\n\n"
            + "".join(f"@mcp.tool(name='t{i}')\n" for i in range(names))
            + "def run(cmd: str) -> str:\n    _ = ["
            + "0, " * 7000
            + "]\n    return subprocess.check_output(cmd)\n"
        )
        start = time.process_time()
        tools = _tools(root)
        elapsed = time.process_time() - start
        assert len(tools) == names and all(E.EXECUTE in _caps(t) for t in tools.values())
        return elapsed

    small, large = cost(1), cost(200)
    assert large < max(small, 0.05) * 6, (small, large)


# ---- Reviews of d05e5cdc and 10b2125a: SQL at the call, database receivers ----------------


@pytest.mark.parametrize(
    ("body", "expected", "raw"),
    [
        (
            "    sql = 'DELETE FROM t'\n    sql = 'SELECT 1'\n    return conn.execute(sql)\n",
            set(),
            False,
        ),
        (
            "    sql = 'DELETE FROM t'\n    if q:\n        sql = 'SELECT 1'\n    return conn.execute(sql)\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
        (
            "    sql = 'DELETE FROM t'\n    sql = conn.execute(sql)\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
        (
            "    sql = 'SELECT 1'\n    for r in rows:\n        sql = 'SELECT 2'\n"
            "        conn.execute(sql)\n        sql = 'DELETE FROM t'\n",
            set(),
            False,
        ),
        (
            "    sql = 'SELECT 1'\n    def inner():\n        sql = 'DELETE FROM t'\n        return sql\n"
            "    return conn.execute(sql)\n",
            set(),
            False,
        ),
        (
            "    sql = 'DELETE FROM t'\n    def run():\n        conn.execute(sql)\n    run()\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
        (
            "    return session.execute(statement=text(f'DELETE FROM t WHERE id = {q}'))\n",
            {E.WRITE, E.DESTRUCTIVE},
            True,
        ),
        ("    return conn.execute(query='DROP TABLE t')\n", {E.WRITE, E.DESTRUCTIVE}, False),
        (
            "    return session.execute(text(text=f'DELETE FROM t WHERE id = {q}'))\n",
            {E.WRITE, E.DESTRUCTIVE},
            True,
        ),
        ("    return conn.execute('EXPLAIN (ANALYZE FALSE) DELETE FROM t')\n", set(), False),
        ("    return conn.execute('EXPLAIN (ANALYZE OFF, BUFFERS) DELETE FROM t')\n", set(), False),
        ("    return conn.execute('EXPLAIN (ANALYZE 0) DELETE FROM t')\n", set(), False),
        (
            "    return conn.execute('EXPLAIN (ANALYZE TRUE) DELETE FROM t')\n",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
    ],
    ids=[
        "definite-overwrite",
        "overwrite-in-a-branch",
        "assignment-of-the-call-result",
        "killed-inside-the-loop",
        "nested-scope-stays-there",
        "closure-reads-the-outer-value",
        "statement-keyword",
        "query-keyword",
        "text-keyword",
        "explain-analyze-false",
        "explain-analyze-off",
        "explain-analyze-zero",
        "explain-analyze-true",
    ],
)
def test_sql_values_follow_the_program_and_explain_options(
    body: str, expected: set[CapabilityClass], raw: bool
) -> None:
    found = _classify(f"from sqlalchemy import text\n\ndef tool(q, conn, session, rows):\n{body}")
    assert set(found.capabilities) == expected, body
    assert any("caller-supplied" in r.detail for r in found.risks) is raw, body


@pytest.mark.parametrize(
    ("header", "handler", "expected"),
    [
        ("", "async ({ query }) => searchClient.query(query)", set()),
        ("", "async (args) => handler.execute(args)", set()),
        ("", "async ({ v }) => index.query(v)", set()),
        ("", "async ({ q }) => graphql.query(q)", set()),
        ("", "async ({ sql }) => knex.raw(sql)", {E.WRITE, E.DESTRUCTIVE}),
        ("", "async ({ q }) => this.db.query(q)", {E.WRITE, E.DESTRUCTIVE}),
        ("", "async () => pool.query('DELETE FROM t')", {E.WRITE, E.DESTRUCTIVE}),
        ('import pg from "pg";\n', "async ({ q }) => pg.query(q)", {E.WRITE, E.DESTRUCTIVE}),
        ("", "async (stripe) => stripe.refunds.create({ charge: 'x' })", set()),
    ],
    ids=[
        "search-client",
        "handler",
        "vector-index",
        "graphql",
        "knex",
        "this-db",
        "pool-literal",
        "pg-import",
        "stripe-parameter",
    ],
)
def test_typescript_sql_needs_a_database_client(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass]
) -> None:
    assert _caps(_ts(tmp_path, handler, header)) == expected, handler


D, W, N = (
    SideEffectProfile.DESTRUCTIVE,
    SideEffectProfile.STATE_MODIFYING,
    SideEffectProfile.UNKNOWN,
)


@pytest.mark.parametrize(
    ("source", "profile", "raw"),
    [
        (
            "def tool(cur):\n    sql = 'SELECT 1'\n    def run():\n        cur.execute(sql)\n"
            "    sql = 'DROP TABLE users'\n    run()\n",
            D,
            False,
        ),
        (
            "def tool(cur):\n    sql = 'SELECT 1'\n    run = lambda: cur.execute(sql)\n"
            "    sql = 'DROP TABLE users'\n    run()\n",
            D,
            False,
        ),
        (
            "def tool(cur):\n    sql = 'SELECT 1'\n    rows = (cur.execute(sql) for _ in range(1))\n"
            "    sql = 'DROP TABLE users'\n    return list(rows)\n",
            D,
            False,
        ),
        (
            "def tool(cur, hard):\n    sql = 'SELECT 1'\n    def choose():\n        nonlocal sql\n"
            "        sql = 'DROP TABLE users'\n    if hard:\n        choose()\n    cur.execute(sql)\n",
            D,
            False,
        ),
        (
            "def tool(cur):\n    def setup():\n        global SQL\n        SQL = 'DROP TABLE users'\n"
            "    setup()\n    cur.execute(SQL)\n",
            D,
            False,
        ),
        (
            "def tool(cur):\n    sql = 'DROP TABLE users'\n    def inner():\n        nonlocal sql\n"
            "        cur.execute(sql)\n        sql = 'SELECT 1'\n    inner()\n",
            D,
            False,
        ),
        (
            "def tool(cur, batches):\n    for batch in batches:\n        sql = 'SELECT 1'\n"
            "        for row in batch:\n            cur.execute(sql, row)\n"
            "            sql = 'DELETE FROM t WHERE id = ?'\n",
            D,
            False,
        ),
        (
            "def tool(cur, ys, xs):\n    for y in ys:\n        def run():\n            sql = 'SELECT 1'\n"
            "            for x in xs:\n                cur.execute(sql)\n                sql = 'DROP TABLE t'\n"
            "        run()\n",
            D,
            False,
        ),
        (
            "def tool(cur, name):\n    sql = 'SELECT * FROM users WHERE 1 = 1'\n    if name:\n"
            "        sql += f\" AND name = '{name}'\"\n    cur.execute(sql)\n",
            D,
            True,
        ),
        (
            "def tool(cur):\n    sql = 'SELECT 1'\n    sql += '; DROP TABLE users'\n    cur.execute(sql)\n",
            D,
            False,
        ),
        (
            "def tool(cur, ident):\n    sql = 'DELETE FROM users'\n    sql = sql + ' WHERE id = ?'\n"
            "    cur.execute(sql, (ident,))\n",
            D,
            False,
        ),
        (
            "from sqlalchemy import text\ndef tool(conn, ident):\n"
            "    stmt = text('DELETE FROM users WHERE id = :i')\n    stmt = stmt.bindparams(i=ident)\n"
            "    conn.execute(stmt)\n",
            D,
            False,
        ),
        (
            "def tool(cur, statements):\n    for sql in statements:\n        cur.execute(sql)\n",
            D,
            True,
        ),
        (
            "def tool(cur, statements):\n    sql = 'SELECT 1'\n    for sql in statements:\n"
            "        cur.execute(sql)\n",
            D,
            True,
        ),
        (
            "def tool(cur, ident):\n    sql, params = 'DELETE FROM users WHERE id = ?', (ident,)\n"
            "    cur.execute(sql, params)\n",
            D,
            False,
        ),
        (
            "def tool(cur, ident):\n    sql, params = 'SELECT 1', ident\n    cur.execute(sql, params)\n",
            N,
            False,
        ),
        (
            "def tool(cur, table):\n    if (sql := f'DROP TABLE {table}'):\n        cur.execute(sql)\n",
            D,
            True,
        ),
        ("def tool(cur):\n    cur.execute(sql := 'DROP TABLE t')\n", D, False),
        (
            "def tool(cur, payload):\n    sql = 'SELECT 1'\n    match payload:\n"
            "        case {'sql': sql}:\n            cur.execute(sql)\n",
            D,
            True,
        ),
        ("def tool(cur):\n    [cur.execute(s) for s in ('DROP TABLE a',)]\n", D, False),
        (
            "DELETE_SQL = 'DELETE FROM notes WHERE id = ?'\ndef tool(conn, note_id):\n"
            "    conn.execute(DELETE_SQL, (note_id,))\n",
            D,
            False,
        ),
        (
            "TABLE = 'notes'\ndef tool(cur, note_id):\n"
            "    cur.execute(f'DELETE FROM {TABLE} WHERE id = ?', (note_id,))\n",
            D,
            False,
        ),
        (
            "def tool(cur, hard):\n    sql = 'DELETE FROM t' if hard else 'UPDATE t SET deleted = 1'\n"
            "    cur.execute(sql)\n",
            D,
            False,
        ),
        (
            "def tool(cur, hard):\n    sql = 'SELECT 1' if hard else 'UPDATE t SET deleted = 1'\n"
            "    cur.execute(sql)\n",
            W,
            False,
        ),
        ("def tool(cur):\n    cur.execute('DELETE FROM t ' + 'WHERE id = 1')\n", D, False),
        (
            "def tool(cur):\n    drop = 'DROP TABLE users'\n    sql = drop\n    cur.execute(sql)\n",
            D,
            False,
        ),
        (
            "from sqlalchemy import text\ndef tool(session):\n    sql = 'DELETE FROM users'\n"
            "    stmt = text(sql)\n    session.execute(stmt)\n",
            D,
            False,
        ),
        ("def tool(cur, req):\n    cur.execute(req.sql)\n", D, True),
        ("def tool(cur, args):\n    cur.execute(args['sql'])\n", D, True),
        ("def tool(cur, q):\n    cur.execute(q.strip())\n", D, True),
        (
            "def tool(cur, table):\n    t = table.strip()\n    cur.execute(f'SELECT * FROM {t}')\n",
            D,
            True,
        ),
        ("def tool(cur, q):\n    a = q\n    b = a\n    cur.execute(b)\n", D, True),
        ("def tool(cur, q):\n    sql = q or 'SELECT 1'\n    cur.execute(sql)\n", D, True),
        (
            "def tool(cur, cols):\n    cur.execute('SELECT ' + ', '.join(cols) + ' FROM t')\n",
            D,
            True,
        ),
        (
            "QUERIES = {'users': 'SELECT * FROM users'}\ndef tool(cur, name):\n"
            "    cur.execute(QUERIES[name])\n",
            N,
            False,
        ),
        (
            "QUERIES = {'purge': 'DELETE FROM t'}\ndef tool(cur, name):\n"
            "    cur.execute(QUERIES.get(name, 'SELECT 1'))\n",
            D,
            False,
        ),
        ("class T:\n    def tool(self, cur):\n        cur.execute(self.SQL)\n", N, False),
        (
            "import psycopg\nasync def tool(dsn):\n"
            "    aconn = await psycopg.AsyncConnection.connect(dsn)\n"
            "    await aconn.execute('DELETE FROM users')\n",
            D,
            False,
        ),
        (
            "def tool(cur):\n    sql = 'SELECT 1'\n    for row in cur.execute(sql):\n"
            "        sql = 'DROP TABLE users'\n",
            N,
            False,
        ),
        (
            "def tool(cur, xs):\n    sql = 'SELECT 1'\n    for x in xs:\n        cur.execute(sql)\n"
            "    else:\n        sql = 'DROP TABLE users'\n",
            N,
            False,
        ),
        (
            "def tool(cur):\n    sql = 'SELECT 1'\n    while cur.execute(sql):\n"
            "        sql = 'DROP TABLE users'\n",
            D,
            False,
        ),
        ("def tool(cur, sql):\n    sql = 'SELECT 1'\n    cur.execute(sql)\n", N, False),
        (
            "def tool(cur, sql, safe):\n    if safe:\n        sql = 'SELECT 1'\n    cur.execute(sql)\n",
            D,
            True,
        ),
        (
            "def tool(cur):\n    sql = 'DROP TABLE users'\n    class Q:\n        sql = 'SELECT 1'\n"
            "        def run(self):\n            cur.execute(sql)\n    Q().run()\n",
            D,
            False,
        ),
    ],
    ids=[
        "closure-defined-before-a-later-assignment",
        "lambda",
        "generator-expression",
        "nonlocal-write",
        "global-write",
        "nonlocal-read-before-its-reassignment",
        "inner-loop-reassignment",
        "inner-loop-in-a-function-in-a-loop",
        "augmented-f-string",
        "augmented-literal",
        "self-derived-concatenation",
        "self-derived-bindparams",
        "loop-target",
        "loop-target-after-a-literal",
        "tuple-unpacking",
        "tuple-unpacking-pairs-items",
        "walrus",
        "walrus-as-the-statement",
        "match-capture",
        "comprehension-target",
        "module-constant",
        "f-string-over-a-constant",
        "conditional-expression",
        "conditional-write",
        "concatenated-literals",
        "alias-of-a-literal",
        "text-of-a-variable",
        "attribute-of-a-parameter",
        "subscript-of-a-parameter",
        "method-of-a-parameter",
        "local-derived-from-a-parameter",
        "two-hop-alias",
        "or-default",
        "join-of-a-parameter",
        "allow-listed-query-by-key",
        "allow-listed-query-by-get",
        "self-attribute",
        "awaited-connection",
        "loop-iterable-runs-once",
        "loop-else-runs-once",
        "while-test-runs-each-pass",
        "parameter-overwritten",
        "parameter-kept-in-a-branch",
        "class-scope-is-skipped",
    ],
)
def test_a_statement_reaches_the_call_through_every_binding_and_frame(
    source: str, profile: SideEffectProfile, raw: bool
) -> None:
    found = _classify_named(source, "tool")
    assert found.profile is profile, source
    assert any("caller-supplied" in r.detail for r in found.risks) is raw, source


@pytest.mark.parametrize(("overwrites", "profile"), [(31, SideEffectProfile.UNKNOWN), (32, D)])
def test_past_the_bound_every_binding_of_a_statement_counts(
    overwrites: int, profile: SideEffectProfile
) -> None:
    lines = "    sql = 'SELECT 1'\n" * overwrites
    found = _classify(f"def tool(conn):\n    sql = 'DROP TABLE t'\n{lines}    conn.execute(sql)\n")
    assert found.profile is profile


@pytest.mark.parametrize(
    ("header", "handler", "raw"),
    [
        (
            'import { DataSource } from "typeorm";\nconst AppDataSource = new DataSource({});\n',
            "async ({ q }) => AppDataSource.query(q)",
            True,
        ),
        (
            'import { Pool } from "pg";\nconst pgPool = new Pool();\n',
            "async ({ q }) => pgPool.query(q)",
            True,
        ),
        (
            'import mysql from "mysql2";\nconst pool = mysql.createPool({});\nconst promised = pool.promise();\n',
            "async ({ q }) => promised.query(q)",
            True,
        ),
        ('const pg = require("knex")({ client: "pg" });\n', "async ({ q }) => pg.raw(q)", True),
        (
            'import sql from "mssql";\nconst pool = new sql.ConnectionPool("x");\n',
            "async ({ q }) => pool.request().query(q)",
            True,
        ),
        (
            'import { PrismaClient } from "@prisma/client";\nconst prismaClient = new PrismaClient();\n',
            "async ({ q }) => prismaClient.$queryRawUnsafe(q)",
            True,
        ),
        ("", "async function ({ q }) { return this.prismaService.$queryRawUnsafe(q); }", True),
        (
            'import { Client } from "@urql/core";\nconst client = new Client({});\n',
            "async ({ q }) => client.query(q)",
            True,
        ),
        ("", "async ({ q }) => client.query(q)", True),
        ('import { pool } from "./db";\n', "async ({ q }) => pool.query(q)", True),
        ('import { db } from "@/lib/db";\n', "async ({ q }) => db.query(q)", True),
        ('import { sql } from "@vercel/postgres";\n', "async ({ q }) => sql.query(q)", True),
        ('import { client } from "@acme/db";\n', "async ({ q }) => client.query(q)", True),
        (
            'import { createClient } from "@libsql/client";\nconst turso = createClient({});\n',
            "async ({ q }) => turso.execute(q)",
            True,
        ),
        ("", "async ({ q }) => searchClient.query(q)", False),
    ],
    ids=[
        "typeorm-data-source",
        "pg-pool-under-another-name",
        "mysql2-promise-pool",
        "called-knex-module",
        "mssql-request",
        "prisma-under-another-name",
        "prisma-raw-method-on-any-receiver",
        "another-sdk-client-named-client-counts",
        "unbound-client-by-name",
        "pool-from-a-local-module",
        "db-from-a-path-alias",
        "vercel-postgres",
        "client-from-a-wrapper-package",
        "libsql-client-under-another-name",
        "search-client-control",
    ],
)
def test_typescript_database_clients_resolve_through_derived_names(
    tmp_path: Path, header: str, handler: str, raw: bool
) -> None:
    tool = _ts(tmp_path, handler, header)
    assert any("caller-supplied" in r.detail for r in tool.risks) is raw


# ---- Review of 899c7384: names TypeScript takes from an import ----------------------------


@pytest.mark.parametrize(
    ("header", "handler", "expected"),
    [
        (
            'import * as cp from "child_process";\nconst run = cp.execSync;\n',
            "(c) => run(c)",
            {E.EXECUTE},
        ),
        (
            'import { exec } from "child_process";\nconst run = exec;\n',
            "(c) => run(c)",
            {E.EXECUTE},
        ),
        (
            'import cp from "child_process";\nimport { promisify } from "util";\n'
            "const run = promisify(cp.exec);\n",
            "async (c) => run(c)",
            {E.EXECUTE},
        ),
        (
            'import axios from "axios";\nconst api = axios.create({ baseURL: "https://x" });\n',
            "async (a) => api.post('/items', a)",
            {E.NETWORK, E.WRITE},
        ),
        (
            'import axios from "axios";\n',
            "async (a) => { const api = axios.create(); return api.post('/items', a); }",
            {E.NETWORK, E.WRITE},
        ),
        (
            'import Stripe from "stripe";\nconst payments = new Stripe("k");\n',
            "async ({ charge }) => payments.refunds.create({ charge })",
            {E.NETWORK, E.WRITE, E.PAYMENT},
        ),
        (
            'const pay = require("stripe")("k");\n',
            "async ({ charge }) => pay.refunds.create({ charge })",
            {E.NETWORK, E.WRITE, E.PAYMENT},
        ),
        (
            'import Stripe from "stripe";\n',
            "async function ({ charge }) { return this.stripe.refunds.create({ charge }); }",
            {E.NETWORK, E.WRITE, E.PAYMENT},
        ),
        (
            "",
            "async ({ charge }) => clients.stripe.refunds.create({ charge })",
            {E.NETWORK, E.WRITE, E.PAYMENT},
        ),
        ("", "async (args) => args.stripe.refunds.create({ charge: 'c' })", set()),
        (
            'import http from "http";\nconst srv = http.createServer(() => {});\n',
            "async () => { srv.close(); srv.on('x', () => {}); }",
            set(),
        ),
        (
            'import * as cp from "child_process";\n',
            "async (c) => { const child = cp.spawn('ls'); child.kill(); }",
            {E.EXECUTE},
        ),
        (
            'import { exec } from "child_process";\n',
            "(c) => { const exec = (x) => x; return exec(c); }",
            set(),
        ),
        (
            'import { exec } from "child_process";\n',
            "(exec) => { const run = exec; return run('x'); }",
            set(),
        ),
    ],
    ids=[
        "member-alias",
        "name-alias",
        "promisified-member",
        "created-client",
        "client-created-in-the-handler",
        "constructed-client",
        "called-module",
        "this-stripe",
        "property-stripe",
        "stripe-under-a-parameter",
        "server-is-not-a-client",
        "child-process-handle",
        "local-function-shadows",
        "alias-of-a-parameter-named-like-an-import",
    ],
)
def test_typescript_names_taken_from_an_import_hold_what_it_holds(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass]
) -> None:
    assert _caps(_ts(tmp_path, handler, header)) == expected


def test_a_typescript_name_with_too_many_bindings_is_unclassified(tmp_path: Path) -> None:
    imports = "".join(f'import {{ x }} from "m{i}";\n' for i in range(33))
    tool = _ts(tmp_path / "direct", "(c) => x(c)", imports)
    assert tool.capabilities is None
    derived = _ts(tmp_path / "derived", "(c) => y(c)", imports + "const y = x;\n")
    assert derived.capabilities is None
    root = tmp_path / "direct"
    assert any("too large or too ambiguous" in s for s in MCPScanner().scan(root).surfaces_excluded)
    at_the_bound = "".join(f'import {{ x }} from "m{i}";\n' for i in range(31))
    at_the_bound += 'import { exec as x } from "child_process";\n'
    assert _caps(_ts(tmp_path / "bound", "(c) => x(c)", at_the_bound)) == {E.EXECUTE}


# ---- Round-5 SQL reader findings ------------------------------------------------------------


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("EXPLAIN ANALYSE DELETE FROM t", {E.WRITE, E.DESTRUCTIVE}),
        ("explain (analyse) delete from t", {E.WRITE, E.DESTRUCTIVE}),
        ("EXPLAIN (ANALYSE TRUE) UPDATE t SET a = 1", {E.WRITE}),
        ("EXPLAIN (ANALYZE OFF, ANALYZE ON) DELETE FROM t", {E.WRITE, E.DESTRUCTIVE}),
        ("EXPLAIN (ANALYZE FALSE, ANALYZE) DELETE FROM t", {E.WRITE, E.DESTRUCTIVE}),
        ("EXPLAIN (ANALYZE, ANALYSE FALSE) DELETE FROM t", set()),
        ("SELECT a$b$c FROM t; DELETE FROM t", {E.WRITE, E.DESTRUCTIVE}),
        ("SELECT 1 AS a$x$; DELETE FROM t; SELECT 1 AS b$x$", {E.WRITE, E.DESTRUCTIVE}),
        ("SELECT $x$ DELETE FROM t $x$", set()),
        ("DELETE FROM t WHERE id = $1", {E.WRITE, E.DESTRUCTIVE}),
    ],
    ids=[
        "analyse-spelling",
        "analyse-option-lowercase",
        "analyse-true",
        "last-analyze-on",
        "last-analyze-bare",
        "last-analyse-false",
        "dollar-inside-a-name",
        "dollar-names-around-a-delete",
        "dollar-quote-control",
        "positional-parameter-control",
    ],
)
def test_sql_reader_spellings_and_dollar_names(
    statement: str, expected: set[CapabilityClass]
) -> None:
    found = _classify(f"def tool(conn):\n    conn.execute({statement!r})\n")
    assert set(found.capabilities) == expected, statement


@pytest.mark.parametrize(
    ("literal", "expected"),
    [
        ('"UPDATE accounts\\n\\tSET balance = 0\\n\\tWHERE id = 2"', {E.WRITE}),
        ('"DELETE\\tFROM t"', {E.WRITE, E.DESTRUCTIVE}),
        ('"SELECT 1;\\tDROP TABLE t"', {E.WRITE, E.DESTRUCTIVE}),
        ("`UPDATE t\\tSET a = 1`", {E.WRITE}),
        ('"\\u0044ELETE FROM t"', {E.WRITE, E.DESTRUCTIVE}),
        ('"SELECT \\x27; DROP TABLE t\\x27"', set()),
        ('"UPDATE t \\\nSET a = 1"', {E.WRITE}),
    ],
    ids=[
        "tab-indented",
        "tab-separated",
        "tab-after-semicolon",
        "template-tab",
        "unicode-escape",
        "hex-quote",
        "line-continuation",
    ],
)
def test_typescript_escapes_read_as_what_they_stand_for(
    tmp_path: Path, literal: str, expected: set[CapabilityClass]
) -> None:
    assert _caps(_ts(tmp_path, f"(id) => db.query({literal}, [id])")) == expected, literal


@pytest.mark.parametrize(
    ("statement", "rank"),
    [
        ("SELECT E'it\\'s'; DELETE FROM t", "destructive"),
        ("SELECT E'\\''; DELETE FROM t", "destructive"),
        ("SELECT 1 AS [it's]; DELETE FROM t", "destructive"),
        ("SELECT 'it\\'s'; DELETE FROM t", "destructive"),
        ("SELECT 'C:\\'; DELETE FROM t", "destructive"),
        ("SELECT 'it''s; DROP TABLE x'", None),
        ("SELECT a[1] FROM t", None),
        ("DROP FOREIGN TABLE ft", "destructive"),
        ("DROP SERVER s CASCADE", "destructive"),
        ("DROP EVENT TRIGGER et", "destructive"),
        ("CREATE CLUSTERED INDEX i ON t (a)", "write"),
        ("ALTER SYSTEM SET log_statement = 'none'", "write"),
        ("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO r", "write"),
        ("drop me a line", None),
        ("create a new account", None),
        (
            "WITH x AS (WITH y AS (SELECT 1) DELETE FROM t RETURNING *) SELECT * FROM x",
            "destructive",
        ),
        (
            "WITH x AS (WITH y AS (SELECT 1) UPDATE t SET a = 1 RETURNING *) SELECT * FROM x",
            "write",
        ),
        (
            "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) "
            "SEARCH DEPTH FIRST BY n SET ord DELETE FROM t WHERE id IN (SELECT n FROM r)",
            "destructive",
        ),
        (
            "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) "
            "CYCLE n SET is_cycle USING path DELETE FROM t",
            "destructive",
        ),
        ("WITH a AS (SELECT 1), b AS (SELECT 2) DELETE FROM t", "destructive"),
        ("SELECT * FROM t WHERE a IN (SELECT 1) AND b = 'UPDATE t SET x = 1'", None),
    ],
    ids=[
        "e-string-escaped-quote",
        "e-string-escaped-quote-only",
        "bracketed-name-with-a-quote",
        "backslash-escaped-quote",
        "standard-string-ending-in-a-backslash",
        "doubled-quote-control",
        "array-subscript-control",
        "drop-foreign-table",
        "drop-server",
        "drop-event-trigger",
        "create-clustered-index",
        "alter-system",
        "alter-default-privileges",
        "prose-drop",
        "prose-create",
        "nested-with-delete",
        "nested-with-update",
        "search-clause",
        "cycle-clause",
        "second-cte",
        "subquery-and-literal-control",
    ],
)
def test_sql_reader_quoting_objects_and_with_clauses(statement: str, rank: str | None) -> None:
    from nexus_symbiote.scanners.tool_capabilities import _sql_effect

    assert _sql_effect(statement) == rank, statement


# ---- Round-5 TypeScript statement and driver findings --------------------------------------

_PG = 'import { Pool } from "pg";\nconst pool = new Pool();\n'
_SQLITE = 'import Database from "better-sqlite3";\nconst db = new Database("f.db");\n'
_SQLITE3 = 'import sqlite3 from "sqlite3";\nconst db = new sqlite3.Database("f.db");\n'
_PGP = 'import pgp from "pg-promise";\nconst db = pgp()("url");\n'
_DELETES = {E.WRITE, E.DESTRUCTIVE}


@pytest.mark.parametrize(
    ("header", "handler", "expected", "raw"),
    [
        (_PG, 'async ({ id }) => pool.query("DELETE FROM t WHERE id = " + id)', _DELETES, True),
        (
            _PG,
            "async ({ name }) => pool.query('SELECT * FROM u WHERE n = ' + name)",
            _DELETES,
            True,
        ),
        (_PG, "async ({ table }) => pool.query('DELETE FROM ' + table)", _DELETES, True),
        (_PG, "async (args) => pool.query(args.sql)", _DELETES, True),
        (_PG, "async ({ q }) => pool.query(q as string)", _DELETES, True),
        (_PG, "async ({ q }) => pool.query(q!)", _DELETES, True),
        (_PG, "async ({ q }) => pool.query(q.trim())", _DELETES, True),
        (_PG, "async () => pool.query('DELETE FROM ' + 't')", _DELETES, False),
        (
            _PG,
            "async ({ hard }) => pool.query(hard ? 'DELETE FROM t' : 'SELECT 1')",
            _DELETES,
            False,
        ),
        (
            _PG + "const QUERIES = { a: 'SELECT 1' };\n",
            "async ({ name }) => pool.query(QUERIES[name])",
            set(),
            False,
        ),
        (_PG, "async ({ id }) => pool.query('DELETE FROM t WHERE id = $1', [id])", _DELETES, False),
        (
            _PG,
            "async ({ id }) => pool.query({ text: 'DELETE FROM t WHERE id = $1', values: [id] })",
            _DELETES,
            False,
        ),
        (_PG, "async ({ q }) => pool.query({ text: q, rowMode: 'array' })", _DELETES, True),
        (
            'import mysql from "mysql2";\nconst connection = mysql.createConnection({});\n',
            "async ({ q }) => connection.query({ sql: q, timeout: 40000 })",
            _DELETES,
            True,
        ),
        (_PG, "async (a) => { let q; return pool.query(q = a); }", _DELETES, True),
        (_PG, "async () => { let q; return pool.query(q = 'DELETE FROM t'); }", _DELETES, False),
        (_PG, "async (a) => pool.query((log(a), a))", _DELETES, True),
        (_PG, "async (a) => pool.query((log(a), 'SELECT 1'))", set(), False),
        ("", "async ({ q }) => searchClient.query(q)", set(), False),
    ],
    ids=[
        "concatenated-parameter",
        "concatenated-quoted-value",
        "concatenated-table",
        "member-of-a-parameter",
        "as-expression",
        "non-null-assertion",
        "method-of-a-parameter",
        "concatenated-literals",
        "conditional-literals",
        "allow-listed-statement",
        "parameterized-control",
        "config-text-literal",
        "config-text-parameter",
        "config-sql-parameter",
        "assignment-value",
        "assignment-literal",
        "comma-value",
        "comma-literal-control",
        "search-client-control",
    ],
)
def test_typescript_statement_forms(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass], raw: bool
) -> None:
    tool = _ts(tmp_path, handler, header)
    assert _caps(tool) == expected, handler
    assert any("caller-supplied" in r.detail for r in tool.risks) is raw, handler


@pytest.mark.parametrize(
    ("header", "handler", "expected", "raw"),
    [
        (
            'import postgres from "postgres";\nconst sql = postgres("url");\n',
            "async ({ id }) => sql`DELETE FROM t WHERE id = ${id}`",
            _DELETES,
            False,
        ),
        (
            'import { sql } from "@vercel/postgres";\n',
            "async ({ id }) => sql`INSERT INTO t VALUES (${id})`",
            {E.WRITE},
            False,
        ),
        (
            'import { neon } from "@neondatabase/serverless";\nconst sql = neon("url");\n',
            "async ({ id }) => sql`DELETE FROM t WHERE id = ${id}`",
            _DELETES,
            False,
        ),
        (
            'import { PrismaClient } from "@prisma/client";\nconst prisma = new PrismaClient();\n',
            "async ({ id }) => prisma.$executeRaw`DELETE FROM t WHERE id = ${id}`",
            _DELETES,
            False,
        ),
        (
            'import { sql } from "drizzle-orm";\nimport { drizzle } from "drizzle-orm/node-postgres";\n'
            'const db = drizzle("url");\n',
            "async ({ id }) => db.execute(sql`DELETE FROM t WHERE id = ${id}`)",
            _DELETES,
            False,
        ),
        (
            'import { sql } from "drizzle-orm";\n',
            "async ({ id }) => { const s = sql`DELETE FROM t WHERE id = ${id}`; return s; }",
            set(),
            False,
        ),
        (
            'import { sql } from "kysely";\n',
            "async ({ id }) => sql`DELETE FROM t WHERE id = ${id}`.execute(db)",
            _DELETES,
            False,
        ),
        (
            'import { gql } from "graphql-tag";\n',
            "async () => gql`query { users { id } }`",
            set(),
            False,
        ),
        (_SQLITE, "async ({ q }) => db.exec(q)", _DELETES, True),
        (_SQLITE, "async ({ q }) => db.prepare(q).run()", _DELETES, True),
        (
            _SQLITE,
            "async ({ id }) => db.prepare('DELETE FROM notes WHERE id = ?').run(id)",
            _DELETES,
            False,
        ),
        (_SQLITE3, "async ({ q }) => db.run(q)", _DELETES, True),
        (_SQLITE3, "async () => db.exec('DROP TABLE notes')", _DELETES, False),
        (
            "",
            "async ({ id }, env) => env.DB.prepare('DELETE FROM t WHERE id = ?').bind(id).run()",
            _DELETES,
            False,
        ),
        (_PGP, "async ({ id }) => db.none('DELETE FROM t WHERE id = $1', [id])", _DELETES, False),
        (_PGP, "async ({ q }) => db.any(q)", _DELETES, True),
        ("", "async ({ key }) => db.get(key)", set(), False),
        ("", "async ({ key }) => cache.get(key)", set(), False),
    ],
    ids=[
        "postgres-js-tag",
        "vercel-postgres-tag",
        "neon-tag",
        "prisma-execute-raw-tag",
        "drizzle-execute",
        "drizzle-builder-alone",
        "kysely-execute",
        "graphql-tag-control",
        "better-sqlite3-exec",
        "better-sqlite3-prepare-run",
        "better-sqlite3-prepared-literal",
        "sqlite3-run",
        "sqlite3-exec-literal",
        "d1-prepare-bind-run",
        "pg-promise-none",
        "pg-promise-any",
        "key-value-get-control",
        "map-get-control",
    ],
)
def test_typescript_tagged_templates_and_sqlite_family_drivers(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass], raw: bool
) -> None:
    tool = _ts(tmp_path, handler, header)
    assert _caps(tool) == expected, handler
    assert any("caller-supplied" in r.detail for r in tool.risks) is raw, handler


@pytest.mark.parametrize(
    ("handler", "raw"),
    [
        ("async ({ statements }) => { for (const s of statements) await pool.query(s); }", True),
        ("async ({ statements }) => { statements.forEach((s) => pool.query(s)); }", True),
        ("async ({ statements }) => statements.forEach(s => pool.query(s))", True),
        ("async (args) => { let q; q = args.sql; return pool.query(q); }", True),
        (
            "async ({ w }) => { let q = 'SELECT * FROM t WHERE '; q += w; return pool.query(q); }",
            True,
        ),
        (
            "async (args) => { const c = { text: '' }; c.text = args.sql; return pool.query(c); }",
            True,
        ),
        ("async (args) => { let q; ({ q } = args); return pool.query(q); }", True),
        ("async (args) => { for (const k in args) await pool.query(k); }", True),
        (
            "async ({ tables }) => { for (const t of tables) await pool.query(`DROP TABLE ${t}`); }",
            True,
        ),
        (
            "async ({ ids }) => Promise.all(ids.map((id) => pool.query(`DELETE FROM t WHERE id = ${id}`)))",
            True,
        ),
        (
            "async (args) => { const q = String(args.sql"
            + " + 0" * 300
            + "); return pool.query(q); }",
            True,
        ),
        (
            "async ({ ids }) => Promise.all(ids.map((id) => pool.query('DELETE FROM t WHERE id = $1', [id])))",
            False,
        ),
        (
            "async ({ ids }) => { const q = 'DELETE FROM t WHERE id = $1'; "
            "ids.forEach(id => pool.query(q, [id])); }",
            False,
        ),
        (
            "async ({ ids }) => { const q = 'DELETE FROM t'; ids.forEach((id = q) => pool.query(q)); }",
            False,
        ),
    ],
    ids=[
        "for-of-target",
        "callback-parameter",
        "unparenthesized-callback-parameter",
        "assignment",
        "augmented-assignment",
        "member-assignment",
        "destructuring-assignment",
        "for-in-key",
        "for-of-template",
        "map-callback-template",
        "value-past-the-walk-bound",
        "map-callback-parameterized-control",
        "callback-body-control",
        "callback-default-control",
    ],
)
def test_typescript_taint_flows_through_loops_callbacks_and_assignments(
    tmp_path: Path, handler: str, raw: bool
) -> None:
    tool = _ts(tmp_path, handler, _PG)
    assert any("caller-supplied" in r.detail for r in tool.risks) is raw, handler


@pytest.mark.parametrize(
    ("header", "handler", "raw"),
    [
        ("", "async ({ q }) => getPool().query(q)", True),
        ('import { getDb } from "./db";\n', "async ({ q }) => getDb().query(q)", True),
        ("", "async ({ q }) => (await getClient()).query(q)", True),
        ("", "async ({ q }) => getConnection().execute(q)", True),
        ("", "async ({ q }) => getUser().query(q)", False),
        ("", "async ({ q }) => getter.query(q)", False),
    ],
    ids=["getter", "getter-from-a-local-module", "awaited-getter", "connection-getter"]
    + ["other-getter-control", "get-prefix-alone-control"],
)
def test_typescript_a_getter_named_like_a_database_client_returns_one(
    tmp_path: Path, header: str, handler: str, raw: bool
) -> None:
    tool = _ts(tmp_path, handler, header)
    assert any("caller-supplied" in r.detail for r in tool.risks) is raw, handler


# ---- Verification of 62717237: the Python statement dataflow -----------------------------


def test_module_names_are_solved_once_for_every_tool_in_the_file() -> None:
    from tests.support import scaling_ratio

    def source(scale: int) -> ast.Module:
        tools, length = 40 * scale, 400 * scale
        head = "A0 = 'DROP TABLE t'\n" + "".join(f"A{i} = A{i - 1}\n" for i in range(1, length))
        body = "".join(f"def t{i}(cur):\n    cur.execute(A{length - 1})\n" for i in range(tools))
        return ast.parse(head + body)

    trees = {scale: source(scale) for scale in (1, 4)}

    def run(scale: int) -> None:
        scopes = PythonScopes(trees[scale])
        for node in trees[scale].body:
            if isinstance(node, ast.FunctionDef):
                assert classify_python(node, scopes).profile is SideEffectProfile.DESTRUCTIVE

    assert scaling_ratio(run) < 10


@pytest.mark.parametrize("order", ["reader-first", "writer-first"])
def test_a_parameter_written_to_a_global_is_caller_supplied_only_in_its_own_tool(
    order: str,
) -> None:
    tree = ast.parse(
        "SQL = 'DELETE FROM t'\n"
        "def write(cur, q):\n    global SQL\n    SQL = q\n    cur.execute(SQL)\n"
        "def read(cur):\n    cur.execute(SQL)\n"
    )
    scopes = PythonScopes(tree)
    write, read = (n for n in tree.body if isinstance(n, ast.FunctionDef))
    first, second = (read, write) if order == "reader-first" else (write, read)
    found = {f.name: classify_python(f, scopes) for f in (first, second)}
    assert any("caller-supplied" in r.detail for r in found["write"].risks)
    assert not any("caller-supplied" in r.detail for r in found["read"].risks)
    assert found["read"].profile is SideEffectProfile.DESTRUCTIVE


@pytest.mark.parametrize(
    ("source", "raw"),
    [
        (
            "ALLOWED = {'name': 'name', 'owner': 'owner_id'}\n"
            "def tool(conn, filters):\n    sql = 'SELECT * FROM t WHERE 1=1'\n"
            "    for key, value in filters.items():\n        if key in ALLOWED:\n"
            "            sql += f' AND {ALLOWED[key]} = ?'\n    return conn.execute(sql)\n",
            False,
        ),
        (
            "ALLOWED = {'name': 'name', 'owner': 'owner_id'}\n"
            "def tool(conn, field, value):\n"
            "    return conn.execute(f'SELECT * FROM t WHERE {ALLOWED[field]} = ?', (value,))\n",
            False,
        ),
        (
            "ALLOWED = {'name': 'name', 'owner': 'owner_id'}\n"
            "def tool(conn, field, value):\n"
            "    return conn.execute('SELECT * FROM t WHERE {} = ?'.format(ALLOWED[field]))\n",
            False,
        ),
        (
            "ALLOWED = {'name': 'name', 'owner': 'owner_id'}\n"
            "def tool(conn, field):\n"
            "    return conn.execute('SELECT * FROM t WHERE %s = 1' % ALLOWED[field])\n",
            False,
        ),
        (
            "def tool(conn, descending):\n"
            "    return conn.execute(f\"SELECT * FROM t ORDER BY a {'DESC' if descending else 'ASC'}\")\n",
            False,
        ),
        (
            "def tool(conn, name):\n    return conn.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n",
            True,
        ),
        (
            "def tool(conn, args):\n    return conn.execute(f'SELECT * FROM t WHERE n = {args[0]}')\n",
            True,
        ),
        (
            "def tool(conn, n):\n    return conn.execute(f'SELECT * FROM t WHERE n = {norm(n)}')\n",
            True,
        ),
        (
            "def tool(conn, d, col):\n    return conn.execute(f\"SELECT * FROM t ORDER BY {col if d else 'id'}\")\n",
            True,
        ),
    ],
    ids=[
        "allow-listed-field-after-augmented-assignment",
        "allow-listed-field",
        "allow-listed-format-argument",
        "allow-listed-percent-operand",
        "condition-that-only-chooses",
        "parameter-in-a-field-control",
        "item-of-a-parameter-control",
        "helper-over-a-parameter-control",
        "chosen-parameter-control",
    ],
)
def test_a_parameter_that_selects_an_allow_listed_fragment_is_not_caller_supplied(
    source: str, raw: bool
) -> None:
    tree = ast.parse(source)
    tool = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    found = classify_python(tool, PythonScopes(tree))
    assert any("caller-supplied" in r.detail for r in found.risks) is raw, source


# ---- Review of 03c57da0: the names a TypeScript scope binds -------------------------------

_EXEC = 'import { exec } from "child_process";\n'


@pytest.mark.parametrize(
    ("header", "handler", "expected"),
    [
        (_EXEC, "(exec) => { const a = exec; const run = a; return run('x'); }", set()),
        (_EXEC, "(exec) => { if (exec) { const run = exec; return run('x'); } }", set()),
        (_EXEC, "async (c) => { const exec = (x) => x; const run = exec; return run(c); }", set()),
        (
            'import fsp from "fs/promises";\n',
            "async (fsp) => { const store = fsp; const rm = store.rm; return rm('x'); }",
            set(),
        ),
        (
            'import Stripe from "stripe";\n',
            "async (a) => { class Stripe { refunds = { create: () => 0 }; } "
            "const p = new Stripe(); return p.refunds.create(a); }",
            set(),
        ),
        (_EXEC, "async function exec(c) { return c ? exec(null) : 0; }", set()),
        (_EXEC, "async (self) => self.exec('x')", set()),
        ("", "async (self) => self.stripe.refunds.create({ charge: 'c' })", set()),
        (_EXEC, "(c) => { const run = exec; return run(c); }", {E.EXECUTE}),
    ],
    ids=[
        "two-step-alias-of-a-parameter",
        "alias-of-a-parameter-in-a-block",
        "alias-of-a-local-function",
        "member-of-an-alias-of-a-parameter",
        "local-class-named-like-an-import",
        "handler-named-like-an-import",
        "parameter-named-like-a-global",
        "stripe-chain-from-a-parameter-named-like-a-global",
        "alias-of-the-import-control",
    ],
)
def test_a_typescript_name_the_handler_binds_hides_the_import_in_its_aliases(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass]
) -> None:
    assert _caps(_ts(tmp_path, handler, header)) == expected, handler


def _ts_file(tmp_path: Path, body: str) -> dict[str, ToolComponent]:
    path = tmp_path / "src" / "server.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(IMPORT + body.replace("__SERVER__", SERVER))
    return _tools(tmp_path)


def test_one_typescript_handlers_names_never_reach_another(tmp_path: Path) -> None:
    tools = _ts_file(
        tmp_path / "leak",
        _EXEC + "__SERVER__"
        'server.tool("a", {}, async (exec) => { const run = exec; return run("x"); });\n'
        'server.tool("b", {}, async ({ cmd }) => { if (cmd) { const run = (c) => c; '
        "return run(cmd); } });\n",
    )
    assert tools["a"].capabilities is None and tools["b"].capabilities is None
    tools = _ts_file(
        tmp_path / "union",
        'import axios from "axios";\nimport { Cache } from "./cache";\n__SERVER__'
        'server.tool("fetch", {}, async ({ url }) => { const client = axios.create(); '
        "return (await client.get(url)).data; });\n"
        'server.tool("evict", {}, async ({ key }) => { const client = new Cache(); '
        'await client.delete(key); return "ok"; });\n',
    )
    assert _caps(tools["fetch"]) == {E.NETWORK} and tools["evict"].capabilities is None
    many = "".join(f'import {{ C{i} }} from "sdk{i}";\n' for i in range(33))
    many += "__SERVER__" + "".join(
        f'server.tool("t{i}", {{}}, async (a) => {{ const client = new C{i}(); '
        "return client.call(a); });\n"
        for i in range(33)
    )
    root = tmp_path / "reused"
    path = root / "src" / "server.ts"
    path.parent.mkdir(parents=True)
    path.write_text(IMPORT + many.replace("__SERVER__", SERVER))
    result = MCPScanner().scan(root)
    assert not [s for s in result.surfaces_excluded if "too large or too ambiguous" in s]


def test_a_function_around_a_typescript_handler_lends_it_its_names(tmp_path: Path) -> None:
    tools = _ts_file(
        tmp_path / "lends",
        'import axios from "axios";\n__SERVER__'
        "function register() { const api = axios.create(); "
        'server.tool("t", {}, (u) => api.post(u, {})); }\nregister();\n',
    )
    assert _caps(tools["t"]) == {E.NETWORK, E.WRITE}
    tools = _ts_file(
        tmp_path / "shadows",
        _EXEC + "__SERVER__"
        'function register(exec) { server.tool("t", {}, (c) => { const run = exec; '
        "return run(c); }); }\n",
    )
    assert tools["t"].capabilities is None
    deep = "".join("(() => {" for _ in range(40)) + 'server.tool("t", {}, (c) => c);'
    deep += "})()" * 40 + ";\n"
    root = tmp_path / "deep"
    path = root / "src" / "server.ts"
    path.parent.mkdir(parents=True)
    path.write_text(IMPORT + SERVER + deep)
    assert any("too large or too ambiguous" in s for s in MCPScanner().scan(root).surfaces_excluded)


@pytest.mark.parametrize(
    ("header", "handler", "expected"),
    [
        (
            'import { createServer as createHttpServer } from "node:http";\n'
            "const httpServer = createHttpServer(() => {});\n",
            "async () => httpServer.address()",
            set(),
        ),
        (
            'import { Server as HttpServer } from "http";\nconst srv = new HttpServer();\n',
            "async () => srv.close()",
            set(),
        ),
        (
            'const { createServer: mk } = require("https");\nconst srv = mk({}, () => {});\n',
            "async () => srv.close()",
            set(),
        ),
        (
            'import http from "http";\n'
            'const srv = http.createServer(() => {}).on("error", () => {});\n',
            "async () => srv.close()",
            set(),
        ),
        (
            'import fetch, { Headers } from "node-fetch";\n',
            "async ({ url }) => { const h = new Headers(); h.delete('cookie'); "
            "return fetch(url, { headers: h }); }",
            {E.NETWORK},
        ),
        (
            'import { FormData } from "undici";\n',
            "async () => { const f = new FormData(); f.delete('k'); return 0; }",
            set(),
        ),
        (
            'import axios from "axios";\nconst cfg = await axios.get("https://x/cfg");\n',
            "async (k) => cfg.data.features.includes(k)",
            set(),
        ),
        (
            'import https from "https";\nconst agent = new https.Agent({ keepAlive: true });\n',
            "async () => agent.destroy()",
            set(),
        ),
        (
            'import { Client } from "undici";\nconst api = new Client("https://x");\n',
            "async (a) => api.request({ method: 'POST', path: '/', body: a })",
            {E.NETWORK},
        ),
        (
            'import axios from "axios";\nconst api = axios.create();\n',
            "async (a) => api.post('/x', a)",
            {E.NETWORK, E.WRITE},
        ),
    ],
    ids=[
        "aliased-create-server",
        "aliased-server-class",
        "destructured-create-server",
        "server-with-a-chained-listener",
        "headers-delete",
        "form-data-delete",
        "module-level-response",
        "https-agent",
        "undici-client-control",
        "axios-instance-control",
    ],
)
def test_only_a_client_an_http_module_returns_sends_requests(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass]
) -> None:
    assert _caps(_ts(tmp_path, handler, header)) == expected, handler


@pytest.mark.parametrize(
    ("header", "handler", "expected"),
    [
        (
            _EXEC + 'import { promisify } from "util";\n'
            "const run = promisify(exec) as (c: string) => Promise<unknown>;\n",
            "async (c) => run(c)",
            {E.EXECUTE},
        ),
        (
            'import axios from "axios";\nconst api = axios.create() as any;\n',
            "async (a) => api.post('/x', a)",
            {E.NETWORK, E.WRITE},
        ),
        (
            'import axios from "axios";\nconst api = axios.create() satisfies object;\n',
            "async (a) => api.post('/x', a)",
            {E.NETWORK, E.WRITE},
        ),
        (
            'import axios from "axios";\nconst api = <any>axios.create();\n',
            "async (a) => api.post('/x', a)",
            {E.NETWORK, E.WRITE},
        ),
        (
            'const cp = require("child_process") as typeof import("child_process");\n',
            "(c) => cp.execSync(c)",
            {E.EXECUTE},
        ),
        (
            'import * as cp from "child_process";\nconst { execSync } = cp;\n',
            "(c) => execSync(c)",
            {E.EXECUTE},
        ),
        (
            'import fs from "fs";\nconst { writeFile, unlink } = fs.promises;\n',
            "async (p) => { await writeFile(p, 'x'); await unlink(p); }",
            {E.FILESYSTEM, E.WRITE, E.DESTRUCTIVE},
        ),
        (
            'import axios from "axios";\nconst { post } = axios.create();\n',
            "async (a) => post('/x', a)",
            {E.NETWORK, E.WRITE},
        ),
        ('import cp = require("child_process");\n', "(c) => cp.execSync(c)", {E.EXECUTE}),
        (
            'import * as cp from "child_process";\nlet run: any;\nrun = cp.execSync;\n',
            "(c) => run(c)",
            {E.EXECUTE},
        ),
        (
            'import * as cp from "child_process";\nconst run = cp.exec.bind(cp);\n',
            "(c) => run(c)",
            {E.EXECUTE},
        ),
        (
            'import * as cp from "child_process";\n'
            'const run = require("util").promisify(cp.exec);\n',
            "async (c) => run(c)",
            {E.EXECUTE},
        ),
    ],
    ids=[
        "promisify-as-a-type",
        "client-as-any",
        "client-satisfies",
        "client-angle-assertion",
        "require-as-typeof-import",
        "destructured-namespace-import",
        "destructured-module-member",
        "destructured-client",
        "import-equals-require",
        "assigned-alias",
        "bound-method",
        "promisify-of-a-required-util",
    ],
)
def test_typescript_names_bound_through_assertions_destructuring_and_assignment(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass]
) -> None:
    assert _caps(_ts(tmp_path, handler, header)) == expected, handler


def test_a_typescript_member_of_a_name_bound_in_many_functions_stays_in_each(
    tmp_path: Path,
) -> None:
    many = "".join(
        f'function f{i}() {{ const x = require("m").e{i}; return x; }}\n' for i in range(34)
    )
    many += 'const x = require("child_process");\nconst run = x.execSync;\n'
    assert _caps(_ts(tmp_path, "(c) => run(c)", many)) == {E.EXECUTE}


# ---- Verification of 62717237: TypeScript statements and drivers ---------------------------


@pytest.mark.parametrize(
    ("header", "handler", "expected", "raw"),
    [
        (
            'import mysql from "mysql2/promise";\nconst conn = await mysql.createConnection({});\n',
            "async (values) => { const stmt = await conn.prepare('SELECT * FROM t WHERE id = ?'); "
            "return stmt.execute(values); }",
            set(),
            False,
        ),
        (
            'import mssql from "mssql";\nconst ps = new mssql.PreparedStatement();\n',
            "async (params) => { await ps.prepare('SELECT * FROM t WHERE id = @id'); "
            "return ps.execute(params); }",
            set(),
            False,
        ),
        (
            'import mssql from "mssql";\nconst ps = new mssql.PreparedStatement();\n',
            "async (params) => { await ps.prepare('DELETE FROM t WHERE id = @id'); "
            "return ps.execute(params); }",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
        (
            'import Database from "better-sqlite3";\nconst db = new Database("f.db");\n',
            "async ({ id }) => { const stmt = db.prepare('DELETE FROM t WHERE id = ?'); "
            "return stmt.run(id); }",
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
        (
            'import { Prisma } from "@prisma/client/edge";\n',
            "async ({ q }) => Prisma.raw(q)",
            {E.WRITE, E.DESTRUCTIVE},
            True,
        ),
        (
            'import { PrismaClient, Prisma } from "@prisma/client";\nconst prisma = new PrismaClient();\n',
            'async () => prisma.$executeRaw(Prisma.sql`DELETE FROM "Session"`)',
            {E.WRITE, E.DESTRUCTIVE},
            False,
        ),
    ],
    ids=[
        "mysql2-prepared-execute",
        "mssql-prepared-statement",
        "mssql-prepared-delete-control",
        "better-sqlite3-statement-held-in-a-name",
        "prisma-edge-entry",
        "prisma-execute-raw-of-a-sql-template",
    ],
)
def test_typescript_prepared_statements_and_package_entries(
    tmp_path: Path, header: str, handler: str, expected: set[CapabilityClass], raw: bool
) -> None:
    tool = _ts(tmp_path, handler, header)
    assert _caps(tool) == expected, handler
    assert any("caller-supplied" in r.detail for r in tool.risks) is raw, handler
