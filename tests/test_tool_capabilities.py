"""Source-declared tools carry the risk-raising capabilities their bodies name, nothing more.

The negative controls are the false positives an independent review reproduced on an
earlier head: ordinary names that share a capability name, unimported names, comments,
constants interpolated into SQL, and non-secret environment variables. A body is never
recorded as read-only, because the classifier cannot show that it writes nothing.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from nexus_symbiote.core.enums import CapabilityClass, SideEffectProfile
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.tool_capabilities import (
    EVIDENCE,
    MAX_BODY_NODES,
    ToolCapabilities,
    classify_python,
    import_map,
)

IMPORT = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
SERVER = "const server = new McpServer({name: 'demo', version: '1'});\n"
E = CapabilityClass


def _classify(source: str) -> ToolCapabilities:
    tree = ast.parse(source)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef))
    return classify_python(function, import_map(tree))


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
