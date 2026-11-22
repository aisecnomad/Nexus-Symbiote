"""Check import ambiguity and stdio compatibility using source text only."""

import pytest

from nexus_symbiote.scanners.mcp import MCPScanner

_PYTHON_SERVER = (
    "from mcp.server.fastmcp import FastMCP\n"
    "server = FastMCP('sample')\n"
    "@server.tool()\n"
    "def notes() -> str: return 'sample'\n"
)
_TS_SERVER = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'const server = new McpServer({name:"sample",version:"1.0"});\n'
)


@pytest.mark.parametrize(
    "annotation", ["Agent[FastMCP]", "Agent[list[FastMCP]]", "'FastMCP | Agent'"]
)
def test_sdk_annotation_keeps_server_sensitive_operands_visible(tmp_path, annotation):
    module = tmp_path / "library" / "agents"
    module.mkdir(parents=True)
    (module / "__init__.py").write_text("class Agent: pass\n")
    (tmp_path / "server.py").write_text(
        _PYTHON_SERVER + f"from agents import Agent\ndef configure(x: {annotation}): pass\n"
    )
    result = MCPScanner().scan(tmp_path)
    assert any(c.name == "notes" for c in result.components)
    assert any("unsupported Python MCP binding" in gap for gap in result.surfaces_excluded)


@pytest.mark.parametrize("regular", [True, False])
def test_qualified_sdk_import_stays_unresolved_with_either_checkout_layout(tmp_path, regular):
    agents = tmp_path / "agents"
    agents.mkdir()
    if regular:
        (agents / "__init__.py").write_text("")
    (agents / "tool.py").write_text("label = 'sample'\n")
    (tmp_path / "server.py").write_text(_PYTHON_SERVER + "import agents.tool\n")
    result = MCPScanner().scan(tmp_path)
    assert any(c.name == "notes" for c in result.components)
    gaps = [g for g in result.surfaces_excluded if "unresolved Python SDK tool import" in g]
    assert gaps


@pytest.mark.parametrize("entry", ["mcp.py", "server.py"])
def test_module_in_a_regular_package_retains_the_external_server(tmp_path, entry):
    package = tmp_path / "worker"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "mcp.py").write_text("label = 'sample'\n")
    (package / entry).write_text(_PYTHON_SERVER)
    result = MCPScanner().scan(tmp_path)
    assert {"sample", "notes"} <= {c.name for c in result.components}
    assert not result.surfaces_excluded


@pytest.mark.parametrize(
    ("assignment", "call", "gap"),
    [
        ("console.log = console.error;", 'console[level]("sample");', False),
        ("Math.random = () => 0.5;", "Math[op](2);", False),
        ("console.sample = 1;", 'console[level]("sample");', False),
        ("console.sample = configuredReporter;", 'console[level]("sample");', True),
        (
            "console.sample = configuredReporter; console.log = console.error;",
            'console[level]("sample");',
            True,
        ),
    ],
)
def test_stdio_reassignment_preserves_meaningful_coverage(tmp_path, assignment, call, gap):
    (tmp_path / "server.ts").write_text(_TS_SERVER + assignment + "\n" + call + "\n")
    result = MCPScanner().scan(tmp_path)
    assert any(c.name == "sample" for c in result.components)
    assert any("unresolved MCP registration receiver" in g for g in result.surfaces_excluded) is gap
