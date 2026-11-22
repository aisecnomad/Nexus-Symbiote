"""blast-radius answers for packages and images, reports dependents, and stays linear."""

from __future__ import annotations

import json
import tracemalloc
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.models import (
    MAX_REFERENCE_CHARS,
    AgentComponent,
    MCPServerComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.graph import (
    INFERRED_AGENT_REF,
    MAX_GRAPH_ISSUES,
    assemble_repository_agent,
    blast_radius,
    validate_graph,
)


def _scanned(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("openai==1.30.0\n")
    (project / "Dockerfile").write_text("FROM ollama/ollama:0.3.0\n")
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/server-filesystem": "2025.8.21"}})
    )
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "files": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"],
                    }
                }
            }
        )
    )
    output = tmp_path / "bom.json"
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    return output


@pytest.mark.parametrize(
    "subject",
    [
        "registry:pypi/openai",
        "registry:docker/ollama/ollama:0.3.0",
        "registry:npm/@modelcontextprotocol/server-filesystem",
    ],
)
def test_a_compromised_package_or_image_reaches_the_repository_agent(tmp_path, subject):
    bom = AIBOM.load(_scanned(tmp_path))
    agent = next(c.bom_ref for c in bom.components if c.component_type.value == "agent")
    result = blast_radius(bom, subject)
    assert result["affected_agents"] == [agent]
    assert agent in result["dependent_components"]
    assert result["linked"] is True


def test_a_launcher_package_links_its_mcp_server(tmp_path):
    bom = AIBOM.load(_scanned(tmp_path))
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    target = "registry:npm/@modelcontextprotocol/server-filesystem"
    assert any(
        e.source_ref == server.bom_ref
        and e.target_ref == target
        and e.relationship == "registered-as"
        for e in bom.dependencies
    )
    assert server.bom_ref in blast_radius(bom, target)["dependent_components"]


@pytest.mark.parametrize(
    "image",
    [
        "ollama/ollama:0.3.0",
        "ghcr.io/github/github-mcp-server:1.0.0",
        "ghcr.io/github/github-mcp-server@sha256:" + "a" * 64,
    ],
)
def test_an_image_links_the_mcp_server_that_runs_it_on_any_registry(tmp_path, image):
    project = tmp_path / "project"
    project.mkdir()
    (project / "Dockerfile").write_text(f"FROM {image}\n")
    server = {"command": "docker", "args": ["run", "-i", "--rm", image]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"image": server}}))
    output = tmp_path / "bom.json"
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    assert CliRunner().invoke(main, args).exit_code == 0
    bom = AIBOM.load(output)
    (mcp,) = (c for c in bom.components if isinstance(c, MCPServerComponent))
    assert mcp.bom_ref in blast_radius(bom, f"registry:docker/{image}")["dependent_components"]


def test_cli_prints_dependents(tmp_path):
    output = _scanned(tmp_path)
    result = CliRunner().invoke(main, ["blast-radius", str(output), "registry:pypi/openai"])
    assert result.exit_code == 0, result.output
    assert f"Agents: {INFERRED_AGENT_REF}" in result.output
    assert f"Dependents: {INFERRED_AGENT_REF}" in result.output


def test_dependents_are_reported_without_any_agent():
    bom = AIBOM(
        components=[
            ToolComponent(bom_ref="s", name="s"),
            ToolComponent(bom_ref="t", name="t"),
        ],
        dependencies=[DependencyEdge(source_ref="s", target_ref="t", relationship="depends-on")],
    )
    result = blast_radius(bom, "t")
    assert result["affected_agents"] == []
    assert result["dependent_components"] == ["s"]


def test_an_unlinked_component_is_unknown_not_empty(tmp_path):
    bom = AIBOM(components=[RegistryEntryComponent(bom_ref="r", name="r")])
    result = blast_radius(bom, "r")
    assert result["linked"] is False
    assert any("reachability is unknown" in item for item in result["limitations"])
    bom.save(tmp_path / "bom.json")
    printed = CliRunner().invoke(main, ["blast-radius", str(tmp_path / "bom.json"), "r"])
    assert printed.exit_code == 0, printed.output
    assert (
        "Note: The component has no recorded relationships: reachability is unknown, not empty."
        in printed.output
    )


def test_several_agents_and_a_cycle():
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="a1", name="a1", sub_agent_refs=["a2"]),
            AgentComponent(bom_ref="a2", name="a2", sub_agent_refs=["a1"], tool_refs=["t"]),
            AgentComponent(bom_ref="a3", name="a3", tool_refs=["t"]),
            ToolComponent(bom_ref="t", name="t"),
            ToolComponent(bom_ref="u", name="u"),
        ]
    )
    result = blast_radius(bom, "t")
    assert result["affected_agents"] == ["a1", "a2", "a3"]
    assert result["reachable_components"] == ["a1", "a2", "a3", "t"]


def test_blast_radius_memory_is_linear_in_upstream_agents():
    # Before: one full forward walk per affected agent, all held at once.
    hub = AgentComponent(bom_ref="hub", name="hub", tool_refs=[f"t{i}" for i in range(1500)])
    agents = [
        AgentComponent(bom_ref=f"a{i}", name="a", sub_agent_refs=["hub"]) for i in range(1500)
    ]
    tools = [ToolComponent(bom_ref=f"t{i}", name="t") for i in range(1500)]
    bom = AIBOM(components=[hub, *agents, *tools])
    tracemalloc.start()
    try:
        result = blast_radius(bom, "t0")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(result["affected_agents"]) == 1501
    assert peak < 16 * 1024 * 1024


def test_graph_issues_are_bounded_and_identifiers_shortened():
    # The model caps bom_ref at MAX_REFERENCE_CHARS; *_refs entries are not capped.
    refs = [*(f"missing-{i}" for i in range(4999)), "m" * 100_000]
    agent = AgentComponent(bom_ref="a" * MAX_REFERENCE_CHARS, name="a", tool_refs=refs)
    issues = validate_graph(AIBOM(components=[agent]))
    assert len(issues) == MAX_GRAPH_ISSUES + 1
    assert issues[-1] == f"{5000 - MAX_GRAPH_ISSUES} further graph issues not shown"
    assert max(len(issue) for issue in issues) < 1000


def test_a_long_target_reference_is_shortened_in_graph_issues():
    agent = AgentComponent(bom_ref="a", name="a", tool_refs=["m" * 100_000, "n" * 100_000])
    issues = validate_graph(AIBOM(components=[agent]))
    assert len(issues) == 2
    assert all("mmmmmmmmmm" in issue or "nnnnnnnnnn" in issue for issue in issues)
    assert max(len(issue) for issue in issues) < 1000


def test_repeated_graph_issues_cannot_crowd_out_distinct_ones():
    repeated = ["missing-0"] * 500
    agent = AgentComponent(
        bom_ref="a", name="a", tool_refs=[*repeated, *(f"missing-{i}" for i in range(1, 150))]
    )
    issues = validate_graph(AIBOM(components=[agent]))
    assert len(set(issues[:-1])) == MAX_GRAPH_ISSUES
    assert issues[-1] == f"{150 - MAX_GRAPH_ISSUES} further graph issues not shown"


def test_assembly_does_not_search_the_inventory_per_tool(monkeypatch):
    calls = 0
    original = AIBOM.get_component

    def counted(self, ref):
        nonlocal calls
        calls += 1
        return original(self, ref)

    monkeypatch.setattr(AIBOM, "get_component", counted)
    bom = AIBOM()
    for server in range(200):
        bom.components.append(MCPServerComponent(bom_ref=f"s{server}", name="s"))
        for tool in range(50):
            bom.components.append(
                ToolComponent(bom_ref=f"s{server}/t{tool}", name="t", mcp_server_ref=f"s{server}")
            )
    assemble_repository_agent(bom, Path("/nonexistent-root-for-test"), failures=[])
    assert calls == 0
    assert sum(e.relationship == "provides-tool" for e in bom.dependencies) == 200 * 50


def test_shared_credential_surfaces_and_mcp_gateways_in_blast_radius():
    from nexus_symbiote.graph import MAX_SHARED_CREDENTIAL_HOLDERS, MAX_SHARED_CREDENTIAL_VARS

    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="agent:main", name="main", tool_refs=["server:gw"]),
            MCPServerComponent(
                bom_ref="server:gw",
                name="gateway",
                env={
                    "SHARED_API_TOKEN": "[redacted]",
                    "LOG_LEVEL": "info",
                    "[redacted-1]": "[redacted]",
                },
                properties={
                    "mcp_role": "gateway",
                    "upstream_server_refs": ["server:upstream"],
                },
            ),
            MCPServerComponent(
                bom_ref="server:upstream",
                name="upstream",
                env={
                    "SHARED_API_TOKEN": "[redacted]",
                    "LOG_LEVEL": "info",
                    "[redacted-1]": "[redacted]",
                },
            ),
        ]
    )
    result = blast_radius(bom, "server:upstream")
    assert result["affected_agents"] == ["agent:main"]
    assert "server:gw" in result["dependent_components"]
    assert result["mcp_gateways"] == ["server:gw"]
    assert result["shared_credential_surfaces"] == {
        "SHARED_API_TOKEN": ["server:gw", "server:upstream"]
    }

    many_env = {f"SERVICE_{idx:03d}_API_KEY": "[redacted]" for idx in range(500)}
    large_bom = AIBOM(
        components=[
            MCPServerComponent(bom_ref=f"server:{i:02d}", name=f"s{i}", env=dict(many_env))
            for i in range(50)
        ]
    )
    bounded = blast_radius(large_bom, "server:00")
    surfaces = bounded["shared_credential_surfaces"]
    assert len(surfaces) == MAX_SHARED_CREDENTIAL_VARS
    assert all(len(holders) == MAX_SHARED_CREDENTIAL_HOLDERS for holders in surfaces.values())
    assert any("shared_credential_surfaces" in item for item in bounded["limitations"])
