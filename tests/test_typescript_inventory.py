"""Static TypeScript source evidence stays confined and does not imply descriptors."""

from dataclasses import replace
from pathlib import Path

import pytest

from nexus_symbiote import limits
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner

IMPORT = 'import { McpServer as Server } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
SERVER = "const server = new Server({name: 'demo', version: '1'});\n"


def _scan(tmp_path: Path, source: str):
    path = tmp_path / "src" / "server.ts"
    path.parent.mkdir(exist_ok=True)
    path.write_text(source)
    return MCPScanner().scan(tmp_path)


def _tools(result):
    return [c for c in result.components if isinstance(c, ToolComponent)]


def test_recursive_literal_registration_is_source_evidence(tmp_path):
    result = _scan(tmp_path, IMPORT + SERVER + 'server.registerTool("read_file", {}, handler);')
    assert not result.scan_failures
    tools = _tools(result)
    assert len(tools) == 1 and tools[0].name == "read_file"
    assert tools[0].assurance_level == AssuranceLevel.DECLARED
    assert tools[0].definition_hash is None and tools[0].input_schema is None
    assert tools[0].claims["tool_definition"].unknown_reason
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.tool_refs == [tools[0].bom_ref] and server.tool_count == 1
    assert server.properties["runtime_registration"] == "unknown"


@pytest.mark.parametrize("method", ["tool", "registerTool"])
@pytest.mark.parametrize("access", [".{}", '["{}"]', "['{}']", "[`{}`]"])
def test_legacy_and_current_registration_names(tmp_path, method, access):
    result = _scan(
        tmp_path, IMPORT + SERVER + f'server{access.format(method)}("read", {{}}, handler);'
    )
    assert [t.name for t in _tools(result)] == ["read"]


@pytest.mark.parametrize("index", ["methodName", "`register${methodName}`", r'"regis\x74erTool"'])
def test_computed_method_on_bound_server_marks_coverage_incomplete(tmp_path, index):
    source = IMPORT + SERVER + f'server[{index}]("hidden", {{}}, handler);\n'
    source += 'other[methodName](); server["registerPrompt"]("decoy", {}, handler);'
    result = _scan(tmp_path, source)
    assert not _tools(result)
    # A computed method on a receiver no binding names may reach the server too.
    assert [x for x in result.surfaces_excluded if "src/server.ts" in x] == [
        "src/server.ts:3 (unresolved MCP method name)",
        "src/server.ts:4 (unresolved MCP registration receiver)",
    ]


def test_bracket_registration_requires_a_bound_receiver(tmp_path):
    source = IMPORT + SERVER + 'function f(server) { server["tool"]("fake", handler); }'
    result = _scan(tmp_path, source)
    assert not _tools(result)
    assert any("unresolved MCP registration receiver" in x for x in result.surfaces_excluded)


def test_comments_strings_and_unrelated_imports_are_not_sdk_declarations(tmp_path):
    source = (
        '// import {McpServer} from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'const text = "McpServer registerTool";\n'
        'import {McpServer as Server} from "untrusted-package";\n'
        + SERVER
        + 'server.registerTool("read", {}, handler);'
    )
    assert not _tools(_scan(tmp_path, source))


def test_shadowed_constructor_parameter_is_not_sdk_server(tmp_path):
    result = _scan(
        tmp_path,
        IMPORT
        + 'function build(Server) { const server = new Server({}); server.tool("read", {}, handler); }',
    )
    assert not _tools(result)
    assert not any(isinstance(c, MCPServerComponent) for c in result.components)
    assert any("unresolved MCP registration receiver" in x for x in result.surfaces_excluded)


def test_shadowed_receiver_and_delayed_registration_stay_unknown(tmp_path):
    result = _scan(
        tmp_path,
        IMPORT + SERVER + 'function register(server) { server.tool("read", {}, handler); }',
    )
    assert not _tools(result)
    assert any("unresolved MCP registration receiver" in x for x in result.surfaces_excluded)


def test_dynamic_name_and_registration_before_definition_are_reported(tmp_path):
    result = _scan(
        tmp_path,
        IMPORT
        + 'server.tool("before", {}, handler);\n'
        + SERVER
        + "server.registerTool(runtimeName, {}, handler);",
    )
    assert not _tools(result)
    assert any("unresolved MCP tool name" in x for x in result.surfaces_excluded)
    assert any("registration scope or ordering" in x for x in result.surfaces_excluded)


def test_duplicate_names_and_invalid_syntax_fail_collection(tmp_path):
    result = _scan(
        tmp_path,
        IMPORT
        + SERVER
        + 'server.tool("read", {}, handler); server.tool("read", {}, otherHandler);',
    )
    assert len(_tools(result)) == 1
    assert any("duplicate MCP tool registration" in x for x in result.scan_failures)
    result = _scan(tmp_path, IMPORT + "const server=new Server({};")
    assert not _tools(result) and result.scan_failures


def test_symlink_source_is_not_read_or_executed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret"
    secret.write_text(IMPORT + SERVER + 'server.tool("CANARY", {}, handler);')
    project = tmp_path / "project"
    project.mkdir()
    (project / "server.ts").symlink_to(secret)
    result = MCPScanner().scan(project)
    assert not _tools(result) and result.scan_failures
    assert "CANARY" not in repr(result)


def test_configured_source_exclusion_is_observed(tmp_path):
    _scan(tmp_path, IMPORT + SERVER + 'server.tool("read", {}, handler);')
    scanner = MCPScanner()
    scanner.configure(exclude_paths=["src"])
    result = scanner.scan(tmp_path)
    assert not _tools(result)
    assert any("excluded by collection policy" in x for x in result.surfaces_excluded)


def test_source_byte_and_ast_limits_fail_without_partial_tools(tmp_path):
    result = _scan(tmp_path, IMPORT + SERVER + " " * limits.DEFAULTS.syntax_bytes)
    assert not _tools(result) and result.scan_failures
    with limits.applied(replace(limits.DEFAULTS, ts_nodes=10)):
        result = _scan(tmp_path, IMPORT + SERVER + 'server.tool("read", {}, handler);')
    assert not _tools(result) and result.scan_failures


def test_receiver_alias_is_reported(tmp_path):
    result = _scan(
        tmp_path, IMPORT + SERVER + 'const alias=server; alias.tool("read", {}, handler);'
    )
    assert not _tools(result)
    assert any("unresolved MCP registration receiver" in x for x in result.surfaces_excluded)


def test_factory_source_declarations_remain_static_and_shadow_aware(tmp_path):
    result = _scan(
        tmp_path,
        IMPORT
        + "export function factory() {"
        + SERVER
        + 'server.registerTool("read", {}, handler); }',
    )
    assert [t.name for t in _tools(result)] == ["read"]
    assert _tools(result)[0].definition_hash is None
    result = _scan(
        tmp_path,
        IMPORT
        + "export function factory() { const Server = Other;"
        + SERVER
        + 'server.registerTool("read", {}, handler); }',
    )
    assert not _tools(result)


def test_receiver_shadowing_in_block_does_not_use_outer_binding(tmp_path):
    result = _scan(
        tmp_path,
        IMPORT
        + SERVER
        + '{ const server = Other; server.tool("fake", {}, handler); }'
        + 'server.tool("real", {}, handler);',
    )
    assert [t.name for t in _tools(result)] == ["real"]
    assert any("unresolved MCP registration receiver" in x for x in result.surfaces_excluded)


def test_ambient_declarations_record_no_server_or_tool(tmp_path):
    result = _scan(
        tmp_path,
        IMPORT
        + SERVER
        + 'server.tool("read", {}, handler);\n'
        + "declare namespace Ambient {\n"
        + '  const ghost = new Server({}); ghost.tool("ghost", {}, handler);\n'
        + '  server.tool("phantom", {}, handler);\n}\n',
    )
    servers = [c.name for c in result.components if isinstance(c, MCPServerComponent)]
    assert servers == ["demo"] and [t.name for t in _tools(result)] == ["read"]


def test_method_names_bind_nothing_inside_the_method(tmp_path):
    result = _scan(
        tmp_path,
        IMPORT
        + "export const plugin = { Server() { const inner = new Server({}); return inner; } };\n"
        + SERVER
        + 'class Plugin { server() { server.tool("read", {}, handler); } }\n',
    )
    servers = [c for c in result.components if isinstance(c, MCPServerComponent)]
    assert sorted(server.name for server in servers) == ["demo", "inner"]
    assert [t.name for t in _tools(result)] == ["read"]
    assert not result.surfaces_excluded and not result.scan_failures


@pytest.mark.parametrize(
    "import_source",
    [
        'import type {McpServer as Server} from "@modelcontextprotocol/server";',
        'import {type McpServer as Server} from "@modelcontextprotocol/server";',
    ],
)
def test_type_only_import_is_not_runtime_constructor_evidence(tmp_path, import_source):
    assert not _tools(_scan(tmp_path, import_source + SERVER + 'server.tool("read", {}, handler);'))


def test_missing_parser_dependency_fails_only_relevant_source(tmp_path, monkeypatch):
    import builtins

    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "tree_sitter":
            raise ImportError("parser not installed")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    result = _scan(tmp_path, "const harmless=1;")
    assert not result.scan_failures
    result = _scan(tmp_path, IMPORT + SERVER + 'server.tool("read", {}, handler);')
    assert not _tools(result)
    assert any("parser dependency unavailable" in reason for reason in result.scan_failures)
