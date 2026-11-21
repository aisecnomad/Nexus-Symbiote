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


def test_destructuring_function_properties_does_not_create_require_aliases():
    content = b"const {createRequire: make} = module; const {createRequire: {name}} = module;"
    tree = ts_tools._parse(content, False, 1.0)
    index = ts_tools._index(tree.root_node, limits.bound("ts-nodes"))
    assert ts_tools._creators(index) == {"createRequire", "make"}
