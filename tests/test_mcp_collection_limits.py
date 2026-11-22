"""One MCP configuration file cannot hold a scan for long or expand without bound."""

from __future__ import annotations

import json

import pytest

from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import (
    MAX_ENVIRONMENT,
    MAX_FILE_NODES,
    MAX_SERVERS_PER_FILE,
    MAX_TOOL_DEPTH,
    MAX_TOOL_NODES,
    MAX_TOOLS_PER_FILE,
    MCPScanner,
)
from tests.support import scaling_ratio


def scan(tmp_path, servers: dict):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    return MCPScanner().scan(tmp_path, config_only=True)


def test_server_count_limit_is_named(tmp_path):
    result = scan(tmp_path, {f"s{i}": {} for i in range(MAX_SERVERS_PER_FILE + 1)})
    assert result.scan_failures == [
        f".mcp.json: invalid server map or MCP server limit ({MAX_SERVERS_PER_FILE} per file) "
        "exceeded"
    ]
    assert not result.components


def test_tool_count_limit_per_file_is_named(tmp_path):
    tools = [{"name": f"t{i}"} for i in range(1000)]
    base_servers = MAX_TOOLS_PER_FILE // 1000 + 1
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        root.mkdir()
        servers = {f"s{i}": {"tools": tools} for i in range(base_servers * scale)}
        (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
        roots[scale] = root
    for scale in (1, 4):
        result = MCPScanner().scan(roots[scale], config_only=True)
        assert result.scan_failures == [
            f".mcp.json: MCP tool limit ({MAX_TOOLS_PER_FILE} per file) exceeded"
        ]
        assert not result.components
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale], config_only=True)) < 10


def test_environment_limit_is_named(tmp_path):
    env = {f"V{i}": "x" for i in range(MAX_ENVIRONMENT + 1)}
    result = scan(tmp_path, {"s": {"command": "node", "env": env}})
    assert result.scan_failures == [
        f".mcp.json: MCP server environment variable limit ({MAX_ENVIRONMENT}) exceeded"
    ]


@pytest.mark.parametrize("shape", ["deep", "wide"])
def test_tool_definition_budget_is_named(tmp_path, shape):
    if shape == "deep":
        schema: dict = {"type": "object"}
        for _ in range(MAX_TOOL_DEPTH + 1):
            schema = {"type": "object", "properties": {"x": schema}}
    else:
        schema = {"type": "object", "properties": {f"p{i}": {} for i in range(MAX_TOOL_NODES)}}
    result = scan(tmp_path, {"s": {"tools": [{"name": "t", "inputSchema": schema}]}})
    assert result.scan_failures == [
        f".mcp.json: MCP tool definition limit ({MAX_TOOL_NODES} nodes, {MAX_TOOL_DEPTH} levels) "
        "exceeded"
    ]


def test_file_descriptor_budget_is_named(tmp_path):
    annotations = {"a": [""] * (MAX_TOOL_NODES // 2)}
    tools = [{"name": f"t{i}", "annotations": annotations} for i in range(MAX_FILE_NODES // 9_000)]
    result = scan(tmp_path, {"s": {"tools": tools}})
    assert result.scan_failures == [
        f".mcp.json: MCP tool definition limit ({MAX_FILE_NODES} nodes per file) exceeded"
    ]


@pytest.mark.no_cover
def test_many_secret_values_times_many_strings_stays_fast(tmp_path):
    # The redaction cost was environment values times strings, with no bound on either.
    # Values are bounded now, so at the bound the cost grows with the strings alone;
    # scaling both measures their accepted product, whose ratio is about 6, not 4.
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        root.mkdir()
        env_count = MAX_ENVIRONMENT
        str_count = ((MAX_TOOL_NODES - 100) // 4) * scale
        env = {f"API_KEY_{i}": f"credential-value-{i:05d}" for i in range(env_count)}
        strings = [f"text {i} credential-value-00007 tail" for i in range(str_count)]
        tool = {"name": "t", "description": "d", "annotations": {"examples": strings}}
        (root / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"s": {"command": "node", "env": env, "tools": [tool]}}})
        )
        roots[scale] = root
    result = MCPScanner().scan(roots[4], config_only=True)
    assert not result.scan_failures
    recorded = next(c for c in result.components if isinstance(c, ToolComponent))
    assert "credential-value" not in json.dumps(recorded.annotations)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert "credential-value" not in server.model_dump_json()
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale], config_only=True)) < 10


def test_audit_redaction_blowup_shape_fails_fast_with_a_named_limit(tmp_path):
    # 0.1.0 sorted and applied every value for every string: about a minute for this
    # file, and hours at the 4 MiB limit. It now stops at the environment limit.
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        root.mkdir()
        env = {f"K{i}": f"v{i:05d}" for i in range(5_000 * scale)}
        tool = {"name": "t", "annotations": {"a": [f"s{i}" for i in range(3_750 * scale)]}}
        (root / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"s": {"command": "node", "env": env, "tools": [tool]}}})
        )
        roots[scale] = root
    for scale in (1, 4):
        result = MCPScanner().scan(roots[scale], config_only=True)
        assert result.scan_failures == [
            f".mcp.json: MCP server environment variable limit ({MAX_ENVIRONMENT}) exceeded"
        ]
        assert not any(
            isinstance(c, (MCPServerComponent, ToolComponent)) for c in result.components
        )
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale], config_only=True)) < 10
