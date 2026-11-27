"""Source-declared tools carry the capabilities their bodies name, and nothing more."""

from __future__ import annotations

import ast
from pathlib import Path

from nexus_symbiote.core.enums import CapabilityClass, SideEffectProfile
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.tool_capabilities import (
    ToolCapabilities,
    classify_python,
    classify_typescript,
    import_map,
)

IMPORT = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
SERVER = "const server = new McpServer({name: 'demo', version: '1'});\n"


def _classify(source: str) -> ToolCapabilities:
    tree = ast.parse(source)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef))
    return classify_python(function, import_map(tree))


def test_shell_execution_is_execute_and_a_high_finding() -> None:
    found = _classify(
        "import subprocess\n\n"
        "def run_shell(command: str) -> str:\n"
        "    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout\n"
    )
    assert CapabilityClass.EXECUTE in found.capabilities
    assert found.profile is SideEffectProfile.STATE_MODIFYING
    (risk,) = found.risks
    assert risk.severity.value == "high" and "runs commands" in risk.detail


def test_an_import_alias_resolves_to_its_module() -> None:
    found = _classify(
        "from subprocess import run as sh\n\ndef go(cmd: str) -> str:\n    return sh(cmd).stdout\n"
    )
    assert CapabilityClass.EXECUTE in found.capabilities


def test_a_caller_supplied_statement_is_destructive() -> None:
    found = _classify(
        "from sqlalchemy import text\n\n"
        "def run_sql(statement: str) -> list:\n"
        "    with engine.begin() as conn:\n"
        "        return list(conn.execute(text(statement)))\n"
    )
    assert found.profile is SideEffectProfile.DESTRUCTIVE
    assert any("caller-supplied" in r.detail for r in found.risks)


def test_a_literal_select_is_read_only() -> None:
    found = _classify(
        "def count(conn) -> int:\n    return conn.execute('SELECT count(*) FROM tickets').scalar()\n"
    )
    assert found.capabilities == [CapabilityClass.READ]
    assert found.profile is SideEffectProfile.READ_ONLY and not found.risks


def test_payment_file_write_network_and_environment() -> None:
    found = _classify(
        "import os\nimport requests\nimport stripe\n\n"
        "def refund(charge: str, path: str) -> str:\n"
        "    stripe.api_key = os.environ['STRIPE_KEY']\n"
        "    stripe.Refund.create(charge=charge)\n"
        "    with open(path, 'w') as fh:\n"
        "        fh.write('ok')\n"
        "    requests.post('https://hooks.example', json={})\n"
        "    return 'ok'\n"
    )
    assert set(found.capabilities) >= {
        CapabilityClass.PAYMENT,
        CapabilityClass.NETWORK,
        CapabilityClass.FILESYSTEM,
        CapabilityClass.WRITE,
        CapabilityClass.CREDENTIALS,
    }
    assert found.profile is SideEffectProfile.FINANCIAL_TRANSACTION
    assert [r.severity.value for r in found.risks] == ["medium"]


def test_a_body_that_names_nothing_keeps_no_declaration() -> None:
    found = _classify("def greet(name: str) -> str:\n    return f'hi {name}'\n")
    assert found.declaration is None and not found.risks
    assert found.profile is SideEffectProfile.UNKNOWN


def test_typescript_bodies() -> None:
    shell = classify_typescript("async ({ cmd }) => { return execSync(cmd).toString(); }", "run")
    assert CapabilityClass.EXECUTE in shell.capabilities
    assert shell.risks[0].severity.value == "high"
    write = classify_typescript("({ p, body }) => { writeFileSync(p, body); return 'ok'; }", "save")
    assert set(write.capabilities) == {CapabilityClass.FILESYSTEM, CapabilityClass.WRITE}
    assert write.profile is SideEffectProfile.STATE_MODIFYING
    net = classify_typescript(
        "async () => { const r = await fetch(url, { headers: { a: process.env.API_TOKEN } });"
        " return r.text(); }",
        "get",
    )
    assert set(net.capabilities) == {CapabilityClass.NETWORK, CapabilityClass.CREDENTIALS}
    assert net.profile is SideEffectProfile.READ_ONLY
    mail = classify_typescript("async ({ to }) => { await sendMail({ to }); }", "notify")
    assert mail.profile is SideEffectProfile.STATE_MODIFYING
    assert classify_typescript("() => 'pong'", "ping").declaration is None


def _tools(result: object) -> dict[str, ToolComponent]:
    return {
        c.name: c
        for c in result.components  # type: ignore[attr-defined]
        if isinstance(c, ToolComponent)
    }


def test_python_mcp_tools_carry_their_capabilities(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('tickets')\n\n"
        "@mcp.tool()\ndef run_sql(statement: str) -> list:\n"
        '    """Run SQL."""\n    return list(engine.execute(statement))\n\n'
        "@mcp.tool()\ndef shell(command: str) -> str:\n"
        '    """Shell."""\n    return subprocess.check_output(command, shell=True).decode()\n\n'
        '@mcp.tool()\ndef greet(name: str) -> str:\n    """Say hi."""\n    return name\n'
    )
    tools = _tools(MCPScanner().scan(tmp_path))
    run_sql = tools["run_sql"].capabilities
    assert run_sql is not None and run_sql.side_effect_profile is SideEffectProfile.DESTRUCTIVE
    assert any(
        r.category == "capability_scope" and r.severity.value == "high"
        for r in tools["run_sql"].risks
    )
    shell = tools["shell"].capabilities
    assert shell is not None and CapabilityClass.EXECUTE in shell.capabilities
    assert tools["greet"].capabilities is None
    assert not [r for r in tools["greet"].risks if r.category == "capability_scope"]


def test_typescript_registrations_carry_their_capabilities(tmp_path: Path) -> None:
    path = tmp_path / "src" / "server.ts"
    path.parent.mkdir(parents=True)
    path.write_text(
        IMPORT
        + SERVER
        + 'server.tool("run", {}, async ({ cmd }) => { return execSync(cmd).toString(); });\n'
        + 'server.registerTool("ping", {}, handler);\n'
    )
    tools = _tools(MCPScanner().scan(tmp_path))
    run = tools["run"].capabilities
    assert run is not None and CapabilityClass.EXECUTE in run.capabilities
    assert any(r.category == "capability_scope" for r in tools["run"].risks)
    assert tools["ping"].capabilities is None


def test_ordinary_names_that_share_a_capability_name_count_for_nothing() -> None:
    """Negative controls: list.remove, dict.copy, dict.get, queue.put and a decorator."""
    found = _classify(
        "import queue\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "@app.post('/x')\n"
        "def tidy(items: list, settings: dict, jobs: queue.Queue) -> dict:\n"
        "    items.remove(items[0])\n"
        "    snapshot = settings.copy()\n"
        "    level = settings.get('level')\n"
        "    jobs.put(level)\n"
        "    return snapshot\n"
    )
    assert found.declaration is None and not found.risks


def test_a_parameterized_query_is_not_caller_supplied_but_an_fstring_is() -> None:
    safe = _classify(
        "import sqlite3\n\n"
        "def lookup(conn, ticket_id: str) -> list:\n"
        "    return conn.execute('SELECT * FROM t WHERE id = ?', (ticket_id,)).fetchall()\n"
    )
    assert safe.profile is SideEffectProfile.READ_ONLY and not safe.risks
    injected = _classify(
        "import sqlite3\n\n"
        "def lookup(conn, ticket_id: str) -> list:\n"
        "    return conn.execute(f'SELECT * FROM t WHERE id = {ticket_id}').fetchall()\n"
    )
    assert injected.profile is SideEffectProfile.DESTRUCTIVE
    assert any("caller-supplied" in r.detail for r in injected.risks)


def test_execute_on_a_non_database_receiver_is_not_sql() -> None:
    found = _classify("def run(pool, task) -> object:\n    return pool.execute(task)\n")
    assert not found.risks


def test_only_secret_named_environment_reads_are_credentials() -> None:
    plain = _classify("import os\n\ndef level() -> str:\n    return os.environ['LOG_LEVEL']\n")
    assert plain.declaration is None
    secret = _classify(
        "from os import getenv\n\ndef key() -> str:\n    return getenv('OPENAI_API_KEY')\n"
    )
    assert secret.capabilities == [CapabilityClass.CREDENTIALS]


def test_a_regex_exec_is_not_process_execution() -> None:
    found = classify_typescript("({ s }) => { const m = /a(b)/.exec(s); return m?.[1]; }", "x")
    assert found.declaration is None
    child = classify_typescript("({ c }) => child_process.exec(c)", "y")
    assert CapabilityClass.EXECUTE in child.capabilities


def test_typescript_sql_is_caller_supplied_only_when_it_interpolates() -> None:
    constant = classify_typescript("({ id }) => db.query(SQL, [id])", "a")
    assert not constant.risks
    interpolated = classify_typescript(
        "({ id }) => db.query(`SELECT * FROM t WHERE id = ${id}`)", "b"
    )
    assert any("caller-supplied" in r.detail for r in interpolated.risks)


def test_a_deep_attribute_chain_and_an_oversized_body_are_bounded() -> None:
    chain = "x" + ".a" * 5000
    found = _classify(f"def deep(x) -> object:\n    return {chain}()\n")
    assert found.declaration is None
    assert classify_typescript("execSync(c);" * 10_000, "big").declaration is None


def test_a_nested_registration_is_classified_by_its_own_body_only(tmp_path: Path) -> None:
    path = tmp_path / "src" / "server.ts"
    path.parent.mkdir(parents=True)
    path.write_text(
        IMPORT
        + SERVER
        + 'server.tool("outer", {}, async () => {\n'
        + '  server.tool("inner", {}, async ({ cmd }) => execSync(cmd).toString());\n'
        + "  return writeFileSync('log.txt', 'ok');\n"
        + "});\n"
    )
    tools = _tools(MCPScanner().scan(tmp_path))
    outer, inner = tools["outer"].capabilities, tools["inner"].capabilities
    assert outer is not None and inner is not None
    assert CapabilityClass.EXECUTE not in outer.capabilities
    assert CapabilityClass.WRITE in outer.capabilities
    assert CapabilityClass.EXECUTE in inner.capabilities
    assert CapabilityClass.WRITE not in inner.capabilities
