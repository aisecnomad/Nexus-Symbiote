"""Check public risk attribution using inert findings and ordinary component names."""

import json
import re

import pytest
from click.testing import CliRunner

from nexus_symbiote import text_poisoning
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import AgentComponent, MCPServerComponent, ToolComponent


def _synthetic_hits(text, *, surface, is_tool_surface, where=""):
    if not is_tool_surface:
        return []
    return [
        text_poisoning.TextPoisoningHit(
            rule_id="TP-CONCEAL-003",
            category=text_poisoning.CATEGORY_TOOL_POISONING,
            severity=RiskSeverity.HIGH,
            byte_offset=match.start(),
            surface=surface,
            summary="Synthetic review finding",
            where=where,
        )
        for match in re.finditer(b"review marker", text.encode("utf-8", errors="surrogatepass"))
    ]


@pytest.mark.parametrize("field", ["description", "x-notes", "title"])
@pytest.mark.parametrize("shared", [True, False])
@pytest.mark.parametrize("path", [".mcp.json", ".cursor/mcp.json", "opencode.jsonc"])
def test_each_tool_declaration_keeps_its_own_finding_in_a_public_scan(
    tmp_path, monkeypatch, field, shared, path
):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    servers = {}
    for name in ("fetch", "time", "git", "memory", "sqlite"):
        tool = name if shared else name + "_tool"
        servers[name] = {
            "command": "uvx",
            "args": [f"mcp-server-{name}==1.0.0"],
            "tools": [{"name": tool, field: "review marker"}],
        }
        if path == "opencode.jsonc":
            servers[name]["command"] = ["uvx", *servers[name].pop("args")]
            servers[name]["type"] = "local"
    project = tmp_path / "project"
    config = project / path
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"mcp" if path == "opencode.jsonc" else "mcpServers": servers}))
    out = tmp_path / "bom.json"
    cli = CliRunner()
    scan = cli.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(out)])
    assert out.is_file(), scan.output
    bom = AIBOM.model_validate_json(out.read_text())
    found = {
        c.name
        for c in bom.components
        if isinstance(c, ToolComponent)
        and any(risk.category == text_poisoning.CATEGORY_TOOL_POISONING for risk in c.risks)
    }
    assert found == {name if shared else name + "_tool" for name in servers}
    assert all(
        not any(r.category == text_poisoning.CATEGORY_TOOL_POISONING for r in c.risks)
        for c in bom.components
        if isinstance(c, AgentComponent)
    )
    gate = cli.invoke(main, ["scan", "--check", "--no-project-policy", str(project)])
    assert gate.exit_code == 1 and "Scan gate failed" in gate.output, gate.output


@pytest.mark.parametrize("edge", ["tool", "server"])
def test_same_named_tools_under_different_declared_servers_use_the_server_ref(
    tmp_path, monkeypatch, edge
):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    path = "inventory.json"
    servers = [
        MCPServerComponent(name=name, bom_ref="server:" + name, source_path=path)
        for name in ("left", "right")
    ]
    tools = [
        ToolComponent(
            name="lookup",
            bom_ref="tool:" + server.name,
            mcp_server_ref=server.bom_ref if edge == "tool" else None,
            source_path=path,
        )
        for server in servers
    ]
    if edge == "server":
        for server, tool in zip(servers, tools, strict=True):
            server.tool_refs = [tool.bom_ref]
    src = {
        s.name: {
            "tools": [
                {"name": "lookup", "description": "review marker" if s.name == "right" else "plain"}
            ]
        }
        for s in servers
    }
    (tmp_path / path).write_text(json.dumps({"mcpServers": src}))
    root = AgentComponent(bom_ref="agent:repo", name="repo")
    text_poisoning.apply_text_poisoning_rules(AIBOM(components=[root, *servers, *tools]), tmp_path)
    assert not root.risks and not tools[0].risks and len(tools[1].risks) == 1


def test_unresolved_findings_remain_visible_without_a_library_diagnostics_list(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    file = "tools.json"
    (tmp_path / file).write_text(
        json.dumps(
            {
                "tools": [
                    {"name": "lookup", "description": "review marker"},
                    {"name": "lookup", "description": "review marker"},
                ]
            }
        )
    )
    tools = [
        ToolComponent(name="lookup", bom_ref="tool:" + name, source_path=file)
        for name in ("A", "B")
    ]
    bom = AIBOM(components=tools)
    assert text_poisoning.apply_text_poisoning_rules(bom, tmp_path) == 2
    risks = [r for tool in tools for r in tool.risks]
    assert len(risks) == 2 and all("unresolved" in r.detail.lower() for r in risks)


@pytest.mark.parametrize("format_name", ["yaml", "toml", "jsonc"])
def test_shared_names_keep_two_structured_declarations_and_one_independent_comment(
    tmp_path, monkeypatch, format_name
):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    file = "config." + format_name
    if format_name == "yaml":
        content = (
            'tools:\n  - name: lookup\n    description: "café review marker"\n'
            '  - name: lookup\n    description: "café review marker"\n'
            '  - name: distinct\n    # description: "café review marker"\n'
        )
    elif format_name == "toml":
        content = (
            '[[tools]]\nname="lookup"\ndescription="café review marker"\n' * 2
            + '[[tools]]\nname="distinct"\n# description="café review marker"\n'
        )
    else:
        content = (
            '{"tools":[{"name":"lookup","description":"café review marker"},'
            '{"name":"lookup","description":"café review marker"},'
            '{"name":"distinct" /* description: "café review marker" */}]}'
        )
    (tmp_path / file).write_text(content)
    root = AgentComponent(name="repo", bom_ref="agent:repo")
    tools = [
        ToolComponent(name=name, bom_ref=f"tool:{idx}", source_path=file)
        for idx, name in enumerate(("lookup", "lookup", "distinct"))
    ]
    added = text_poisoning.apply_text_poisoning_rules(AIBOM(components=[root, *tools]), tmp_path)
    assert added == 3
    assert len(root.risks) == 2 and all("unresolved" in r.detail for r in root.risks)
    assert not tools[0].risks and not tools[1].risks
    assert len(tools[2].risks) == 1


def test_server_metadata_stays_with_its_server_when_a_tool_shares_its_name(tmp_path, monkeypatch):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    path = "client.json"
    (tmp_path / path).write_text(
        json.dumps(
            {
                "servers": {
                    "example": {
                        "env": {"NOTES": "review marker"},
                        "tools": [{"name": "example", "description": "plain"}],
                    }
                }
            }
        )
    )
    root = AgentComponent(name="repo", bom_ref="agent:repo")
    server = MCPServerComponent(name="example", bom_ref="server:x", source_path=path)
    tool = ToolComponent(
        name="example", bom_ref="tool:x", source_path=path, mcp_server_ref=server.bom_ref
    )
    assert (
        text_poisoning.apply_text_poisoning_rules(AIBOM(components=[root, server, tool]), tmp_path)
        == 1
    )
    assert len(server.risks) == 1 and not root.risks and not tool.risks


def test_an_unrelated_tool_with_the_only_matching_name_does_not_acquire_a_server_edge(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    path = "inventory.json"
    (tmp_path / path).write_text(
        json.dumps(
            {
                "mcpServers": {
                    "left": {"tools": [{"name": "lookup", "title": "review marker"}]},
                    "right": {"tools": [{"name": "lookup", "title": "plain"}]},
                }
            }
        )
    )
    root = AgentComponent(name="repo", bom_ref="agent:repo")
    servers = [
        MCPServerComponent(name=n, bom_ref="server:" + n, source_path=path)
        for n in ("left", "right")
    ]
    tool = ToolComponent(
        name="lookup", bom_ref="tool:right", mcp_server_ref=servers[1].bom_ref, source_path=path
    )
    text_poisoning.apply_text_poisoning_rules(AIBOM(components=[root, *servers, tool]), tmp_path)
    assert not tool.risks and len(root.risks) == 1 and "unresolved" in root.risks[0].detail


def test_nested_schema_fields_keep_their_enclosing_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    file = "tools.json"
    description = {"tools": [{"name": "other", "title": "review marker"}]}
    (tmp_path / file).write_text(
        json.dumps(
            {
                "tools": [
                    {"name": "owner", "inputSchema": {"properties": description}},
                    {"name": "other"},
                ]
            }
        )
    )
    tools = [
        ToolComponent(name=n, bom_ref="tool:" + n, source_path=file) for n in ("owner", "other")
    ]
    text_poisoning.apply_text_poisoning_rules(AIBOM(components=tools), tmp_path)
    assert len(tools[0].risks) == 1 and not tools[1].risks
