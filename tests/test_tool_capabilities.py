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
    assert [r.severity.value for r in found.risks] == ["medium"]


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
    assert any("too large to classify" in gap for gap in result.surfaces_excluded)


def test_python_mcp_tools_carry_capabilities_and_their_evidence(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import subprocess\nimport sqlite3\nfrom mcp.server.fastmcp import FastMCP\n\n"
        "mcp = FastMCP('tickets')\nengine = sqlite3.connect('t.db')\n\n"
        "@mcp.tool()\ndef run_sql(statement: str) -> list:\n"
        '    """Run SQL."""\n    return list(engine.execute(statement))\n\n'
        "@mcp.tool()\ndef shell(command: str) -> str:\n"
        '    """Shell."""\n    return subprocess.check_output(command, shell=True).decode()\n\n'
        '@mcp.tool()\ndef greet(name: str) -> str:\n    """Say hi."""\n    return name\n'
    )
    tools = _tools(tmp_path)
    run_sql = tools["run_sql"]
    assert run_sql.capabilities is not None
    assert run_sql.capabilities.side_effect_profile is SideEffectProfile.DESTRUCTIVE
    assert run_sql.properties["capability_evidence"] == EVIDENCE
    assert any(
        r.category == "capability_scope" and r.severity.value == "high" for r in run_sql.risks
    )
    assert E.EXECUTE in _caps(tools["shell"])
    assert tools["greet"].capabilities is None
    assert "capability_evidence" not in tools["greet"].properties


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
    assert {r.severity.value for r in tool.risks if r.category == "capability_scope"} == {
        "high",
        "medium",
    }


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


def test_typescript_handler_bindings_shadow_imports_and_carry_taint(tmp_path: Path) -> None:
    shadow = _ts(
        tmp_path / "shadow",
        "(c) => { const exec = (x) => x; const fetch = cache.get; exec(c); return fetch(c); }",
        'import { exec } from "child_process";\n',
    )
    assert shadow.capabilities is None
    tainted = _ts(
        tmp_path / "taint",
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
        ("    conn.execute('INSERT INTO t VALUES (1)')\n", {E.WRITE}, "state-modifying"),
        (
            "    stmt: str = 'DROP TABLE t'\n    conn.execute(stmt)\n",
            {E.WRITE, E.DESTRUCTIVE},
            "destructive",
        ),
        (
            "    conn.execute(*args)\n    smtplib.SMTP('h').sendmail(a, b, data)\n",
            {E.NETWORK, E.WRITE},
            "state-modifying",
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
    assert any("too large to classify" in gap for gap in result.surfaces_excluded)


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
    ],
    ids=[
        "default-value",
        "nested-block",
        "require-member",
        "global-process",
        "env-subscript",
        "server",
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
        ("    return conn.execute(\"SELECT * FROM t WHERE note = 'please DROP it'\")\n", set(), False),
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
