"""Keep SDK registration evidence distinct from ordinary source imports and types."""

import ast

import pytest

from nexus_symbiote import limits
from nexus_symbiote.scanners import ts_tools
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.python_tools import _annotation_names


def test_only_recognized_framework_generics_can_hide_type_arguments():
    tree = ast.parse(
        "from agents import ResultBuilder\n"
        "from mcp.server.fastmcp import Context, FastMCP\n"
        "def example(context: Context[None], result: ResultBuilder[FastMCP]): pass\n"
    )
    nodes = list(ast.walk(tree))
    annotations = _annotation_names(nodes)
    assert {node.id for node in annotations if isinstance(node, ast.Name)} == {"Context"}


def test_project_agents_module_is_not_an_external_sdk_import(tmp_path):
    local_agents = tmp_path / "agents"
    local_agents.mkdir()
    (local_agents / "__init__.py").write_text("")
    (local_agents / "research.py").write_text("def summary(): return 'notes'\n")
    (tmp_path / "server.py").write_text(
        "from agents.research import summary\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('docs')\n"
        "@server.tool()\n"
        "def notes() -> str: return summary()\n"
    )
    result = MCPScanner().scan(tmp_path)
    assert any(component.name == "notes" for component in result.components)
    assert not any("unresolved Python SDK tool import" in gap for gap in result.surfaces_excluded)


def test_agents_namespace_file_does_not_exempt_an_external_import(tmp_path):
    local_agents = tmp_path / "src" / "agents"
    local_agents.mkdir(parents=True)
    (local_agents / "research.py").write_text("label = 'notes'\n")
    (tmp_path / "server.py").write_text(
        "import agents\nfrom mcp.server.fastmcp import FastMCP\nserver = FastMCP('docs')\n"
    )
    result = MCPScanner().scan(tmp_path)
    assert any(component.name == "docs" for component in result.components)
    assert any("unresolved Python SDK tool import" in gap for gap in result.surfaces_excluded)


@pytest.mark.parametrize("entry", ["agents.py", "src/agents/__init__.py", "app/agents/agent.py"])
@pytest.mark.parametrize("annotation", ["Agent[FastMCP]", "'FastMCP | Agent'"])
def test_checkout_sdk_type_does_not_exempt_annotation_operations(tmp_path, entry, annotation):
    local_module = tmp_path / entry
    local_module.parent.mkdir(parents=True, exist_ok=True)
    local_module.write_text("class Agent: pass\n")
    server = tmp_path / ("app/server.py" if entry.startswith("app/") else "server.py")
    module = "agents.agent" if entry.endswith("agent.py") else "agents"
    server.write_text(
        f"from {module} import Agent\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('docs')\n"
        f"def inspect(value: {annotation}) -> None: pass\n"
    )
    result = MCPScanner().scan(tmp_path)
    assert any(component.name == "docs" for component in result.components)
    assert any("unsupported Python MCP binding" in gap for gap in result.surfaces_excluded)


def test_checkout_server_factory_is_not_collected_as_an_external_sdk(tmp_path):
    (tmp_path / "fastmcp.py").write_text("class FastMCP: pass\n")
    (tmp_path / "server.py").write_text("from fastmcp import FastMCP\nserver = FastMCP('docs')\n")
    result = MCPScanner().scan(tmp_path)
    assert not result.components
    assert any("may resolve to checkout code" in gap for gap in result.surfaces_excluded)


def test_sdk_message_and_tracing_imports_are_not_tool_registration(tmp_path):
    (tmp_path / "server.py").write_text(
        "from agents import gen_trace_id, set_tracing_disabled\n"
        "from agents.items import ToolCallItem\n"
        "from agents.tracing import trace\n"
        "from pydantic_ai.messages import ToolCallPart\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('docs')\n"
    )
    result = MCPScanner().scan(tmp_path)
    assert any(component.name == "docs" for component in result.components)
    assert not any("unresolved Python SDK tool import" in gap for gap in result.surfaces_excluded)


_TYPESCRIPT_SERVER = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'const server = new McpServer({ name: "docs", version: "1.0" });\n'
)


@pytest.mark.parametrize(
    "register",
    [
        'const alias = server; alias[method]("notes", callback);',
        'function attach(target: object) { target[method]("notes", callback); } attach(server);',
    ],
)
def test_computed_methods_on_possible_server_aliases_report_coverage_gap(tmp_path, register):
    (tmp_path / "server.ts").write_text(_TYPESCRIPT_SERVER + register)
    result = MCPScanner().scan(tmp_path)
    assert any("unresolved MCP registration receiver" in gap for gap in result.surfaces_excluded)


def test_computed_math_and_console_members_are_ordinary_builtins(tmp_path):
    (tmp_path / "server.ts").write_text(
        _TYPESCRIPT_SERVER + 'console[level]("ready"); Math[rounding](2);\n'
    )
    result = MCPScanner().scan(tmp_path)
    assert any(component.name == "docs" for component in result.components)
    assert not any(
        "unresolved MCP registration receiver" in gap for gap in result.surfaces_excluded
    )


@pytest.mark.parametrize(
    "declaration",
    [
        "console = configuration.reporter;",
        "globalThis.console = configuration.reporter;",
        "const console = configuration.reporter;",
    ],
)
def test_computed_console_on_a_local_receiver_keeps_coverage_gap(tmp_path, declaration):
    (tmp_path / "server.ts").write_text(
        _TYPESCRIPT_SERVER + declaration + 'console[level]("ready");\n'
    )
    result = MCPScanner().scan(tmp_path)
    assert any("unresolved MCP registration receiver" in gap for gap in result.surfaces_excluded)


def test_destructuring_function_properties_does_not_create_require_aliases():
    content = b"const {createRequire: make} = module; const {createRequire: {name}} = module;"
    tree = ts_tools._parse(content, False, 1.0)
    index = ts_tools._index(tree.root_node, limits.bound("ts-nodes"))
    assert ts_tools._creators(index) == {"createRequire", "make"}
