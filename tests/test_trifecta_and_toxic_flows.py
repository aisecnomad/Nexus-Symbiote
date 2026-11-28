"""Tests for lethal-trifecta, chained toxic-flow, and tool-shadowing analysis (Items 15 & 24)."""

from __future__ import annotations

import json
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    CapabilityClass,
    HumanInTheLoop,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.models import (
    AgentComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    IDEAgentComponent,
    MCPServerComponent,
    PromptComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.ide_agents import _SCOPED_TOOL_CLASSES
from nexus_symbiote.trifecta import (
    _IDE_GRANT_LEGS,
    EVIDENCE_LIMIT,
    analyze_trifecta,
    canonical_tool_name,
)
from tests.support import scaling_ratio


def _trifecta_bom(*, gated: bool = False, partial_gate: bool = False) -> AIBOM:
    """Build an agent with untrusted input, private data, and egress (plus gated twin)."""
    hitl_egress = HumanInTheLoop.REQUIRED if gated else HumanInTheLoop.NONE
    fetch_tool = ToolComponent(
        bom_ref="tool:web-fetch",
        name="web_fetch",
        mcp_server_ref="mcp:browser",
        description="Fetch arbitrary external web pages",
        source_path="mcp.json",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.READ],
            side_effect_profile=SideEffectProfile.READ_ONLY,
            # A URL fetcher is a way out as well as a way in, so the gated twin gates it too.
            human_in_the_loop=hitl_egress,
        ),
    )
    secret_tool = ToolComponent(
        bom_ref="tool:read-secrets",
        name="read_secret",
        mcp_server_ref="mcp:vault",
        description="Read local credentials and private files",
        source_path="mcp.json",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM, CapabilityClass.CREDENTIALS],
            filesystem_paths=["/etc/app/secrets"],
            human_in_the_loop=HumanInTheLoop.NONE,
        ),
    )
    egress_tool = ToolComponent(
        bom_ref="tool:send-webhook",
        name="send_webhook",
        mcp_server_ref="mcp:notify",
        description="Send outbound HTTP notifications",
        source_path="mcp.json",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE],
            egress_domains=["hooks.example.com"],
            side_effect_profile=SideEffectProfile.STATE_MODIFYING,
            human_in_the_loop=hitl_egress,
        ),
    )
    components = [fetch_tool, secret_tool, egress_tool]
    tool_refs = [fetch_tool.bom_ref, secret_tool.bom_ref, egress_tool.bom_ref]
    if partial_gate:
        second_egress = ToolComponent(
            bom_ref="tool:post-slack",
            name="post_slack",
            mcp_server_ref="mcp:notify",
            source_path="mcp.json",
            capabilities=CapabilityDeclaration(
                capabilities=[CapabilityClass.NETWORK],
                egress_domains=["slack.example.com"],
                human_in_the_loop=None,  # unknown -> fail closed
            ),
        )
        components.append(second_egress)
        tool_refs.append(second_egress.bom_ref)

    agent = AgentComponent(
        bom_ref="agent:support",
        name="support-agent",
        tool_refs=tool_refs,
        capabilities=CapabilityDeclaration(
            human_in_the_loop=HumanInTheLoop.REQUIRED if (gated and not partial_gate) else None,
        ),
    )
    return AIBOM(components=[agent, *components])


def test_lethal_trifecta_ungated_is_critical() -> None:
    report = analyze_trifecta(_trifecta_bom(gated=False))
    assert report.has_critical
    trifecta = [f for f in report.findings if f.kind == "lethal_trifecta"]
    assert len(trifecta) == 1
    assert trifecta[0].severity is RiskSeverity.CRITICAL
    assert set(trifecta[0].component_refs) == {
        "tool:web-fetch",
        "tool:read-secrets",
        "tool:send-webhook",
    }
    legs = {e["leg"] for e in trifecta[0].evidence}
    assert legs == {"untrusted_input", "private_data", "egress"}


def test_lethal_trifecta_gated_twin_stays_clean() -> None:
    report = analyze_trifecta(_trifecta_bom(gated=True), assume_declared_approvals=True)
    assert not report.has_critical
    assert [f for f in report.findings if f.kind == "lethal_trifecta"] == []
    assert [f for f in report.findings if f.kind == "toxic_flow"] == []


def test_lethal_trifecta_partial_gate_still_fails_closed() -> None:
    report = analyze_trifecta(
        _trifecta_bom(gated=True, partial_gate=True), assume_declared_approvals=True
    )
    assert report.has_critical
    trifecta = [f for f in report.findings if f.kind == "lethal_trifecta"]
    assert len(trifecta) == 1
    assert "tool:post-slack" in trifecta[0].component_refs
    assert analyze_trifecta(_trifecta_bom(gated=True, partial_gate=True)).has_critical


def test_explicit_none_on_egress_tool_overrides_agent_gate() -> None:
    bom = _trifecta_bom(gated=True)
    egress = next(c for c in bom.components if c.bom_ref == "tool:send-webhook")
    assert isinstance(egress, ToolComponent) and egress.capabilities is not None
    egress.capabilities.human_in_the_loop = HumanInTheLoop.NONE
    report = analyze_trifecta(bom)
    assert report.has_critical


def test_authorization_record_approval_gates_agent() -> None:
    bom = _trifecta_bom(gated=False)
    # Remove explicit NONE overrides on the egress tools so agent-level authorization governs.
    for ref in ("tool:send-webhook", "tool:web-fetch"):
        egress = next(c for c in bom.components if c.bom_ref == ref)
        assert isinstance(egress, ToolComponent) and egress.capabilities is not None
        egress.capabilities.human_in_the_loop = None
    agent = next(c for c in bom.components if isinstance(c, AgentComponent))
    agent.authorizations = [
        AuthorizationRecord(principal="user:alice", action="egress", approval_required=True)
    ]
    report = analyze_trifecta(bom, assume_declared_approvals=True)
    assert not report.has_critical


def test_real_scan_output_triggers_critical_trifecta(tmp_path: Path) -> None:
    """End-to-end: real `scan` on .mcp.json + .claude/settings.json fires critical trifecta."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fetch": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-fetch"],
                    },
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                    },
                    "slack": {"url": "https://mcp.slack.example.com/sse"},
                }
            }
        ),
        encoding="utf-8",
    )
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}),
        encoding="utf-8",
    )

    bom_path = tmp_path / "bom.json"
    runner = CliRunner()
    scan_res = runner.invoke(main, ["scan", str(tmp_path), "-o", str(bom_path)])
    assert scan_res.exit_code == 0

    res = runner.invoke(main, ["trifecta", str(bom_path)])
    assert res.exit_code == 1
    payload = json.loads(res.output)
    assert payload["severity_counts"]["critical"] >= 1
    trifecta_findings = [f for f in payload["findings"] if f["kind"] == "lethal_trifecta"]
    assert len(trifecta_findings) == 1
    legs = {e["leg"] for e in trifecta_findings[0]["evidence"]}
    assert legs == {"untrusted_input", "private_data", "egress"}


def test_real_scan_default_mode_with_allow_rules_does_not_clear_trifecta(tmp_path: Path) -> None:
    """Static defaultMode: default with allow rules must not silence a trifecta."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fetch": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-fetch"],
                    },
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                    },
                    "slack": {"url": "https://mcp.slack.example.com/sse"},
                }
            }
        ),
        encoding="utf-8",
    )
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {
                    "defaultMode": "default",
                    "allow": ["Bash(*)", "WebFetch(*)"],
                }
            }
        ),
        encoding="utf-8",
    )

    bom_path = tmp_path / "bom.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(tmp_path), "-o", str(bom_path)]).exit_code == 0
    res = runner.invoke(main, ["trifecta", str(bom_path)])
    assert res.exit_code == 1
    assert json.loads(res.output)["severity_counts"]["critical"] >= 1


def test_real_scan_benign_http_docs_and_time_server_with_tz_env_is_clean(tmp_path: Path) -> None:
    """Benign MCP env (TZ=UTC) beside an HTTP docs server must NOT trigger a false critical."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "docs": {"url": "https://docs.example.com/mcp"},
                    "time": {
                        "command": "npx",
                        "args": ["-y", "mcp-server-time"],
                        "env": {"TZ": "UTC", "LANG": "C.UTF-8"},
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    bom_path = tmp_path / "bom.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(tmp_path), "-o", str(bom_path)]).exit_code == 0
    res = runner.invoke(main, ["trifecta", str(bom_path)])
    assert res.exit_code == 0
    assert json.loads(res.output)["finding_count"] == 0


def test_real_scan_secret_env_beside_http_server_is_critical(tmp_path: Path) -> None:
    """Credential-named MCP env var beside a remote HTTP server fires critical."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "docs": {"url": "https://docs.example.com/mcp"},
                    "helper": {
                        "command": "npx",
                        "args": ["-y", "mcp-server-time"],
                        "env": {"OPENAI_API_KEY": "placeholder-value"},
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    bom_path = tmp_path / "bom.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(tmp_path), "-o", str(bom_path)]).exit_code == 0
    res = runner.invoke(main, ["trifecta", str(bom_path)])
    assert res.exit_code == 1
    assert json.loads(res.output)["severity_counts"]["critical"] == 1


def test_readonly_web_search_and_read_file_is_not_critical() -> None:
    """An agent with only web_search and read-only read_file has no egress/mutation leg."""
    web_search = ToolComponent(
        bom_ref="tool:web-search",
        name="web_search",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.READ],
            side_effect_profile=SideEffectProfile.READ_ONLY,
        ),
    )
    read_file = ToolComponent(
        bom_ref="tool:read-file",
        name="read_file",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM, CapabilityClass.READ],
            side_effect_profile=SideEffectProfile.READ_ONLY,
        ),
    )
    agent = AgentComponent(
        bom_ref="agent:researcher",
        name="researcher",
        tool_refs=["tool:web-search", "tool:read-file"],
    )
    report = analyze_trifecta(AIBOM(components=[agent, web_search, read_file]))
    assert not report.has_critical
    assert report.findings == ()


def test_hostile_inventory_properties_cannot_clear_trifecta() -> None:
    """Ad-hoc untrusted properties (requires_approval, approval_gate) cannot clear the gate."""
    bom = _trifecta_bom(gated=False)
    for comp in bom.components:
        comp.properties["requires_approval"] = True
        comp.properties["approval_gate"] = True
        comp.properties["human_in_the_loop"] = "required"
    report = analyze_trifecta(bom)
    assert report.has_critical


def test_ide_agent_gating_requires_verified_authorization_without_allow_rules() -> None:
    server = MCPServerComponent(
        bom_ref="mcp:remote",
        name="remote-mcp",
        endpoint_url="https://remote.example.com/mcp",
        env={"API_TOKEN": "[redacted]"},
    )
    ungated_ide = IDEAgentComponent(
        bom_ref="ide:claude-ungated",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="bypassPermissions",
    )
    unverified_default = IDEAgentComponent(
        bom_ref="ide:claude-default-static",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="default",
        assurance_level=AssuranceLevel.DECLARED,
        properties={"effective_authorization_verified": False},
    )
    default_with_allow = IDEAgentComponent(
        bom_ref="ide:claude-default-allow",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="default",
        assurance_level=AssuranceLevel.VERIFIED,
        properties={
            "effective_authorization_verified": True,
            "declared_permission_rule_counts": {"allow": 1, "ask": 0, "deny": 0},
        },
    )
    default_with_risk = IDEAgentComponent(
        bom_ref="ide:claude-default-risk",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="default",
        assurance_level=AssuranceLevel.VERIFIED,
        properties={
            "effective_authorization_verified": True,
            "declared_permission_rule_counts": {"allow": 0, "ask": 0, "deny": 0},
        },
        risks=[
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="permission_scope",
                detail="Unscoped tool allowance",
            )
        ],
    )
    verified_gated = IDEAgentComponent(
        bom_ref="ide:claude-verified",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="default",
        assurance_level=AssuranceLevel.VERIFIED,
        properties={
            "effective_authorization_verified": True,
            "declared_permission_rule_counts": {"allow": 0, "ask": 0, "deny": 0},
        },
    )

    assert analyze_trifecta(AIBOM(components=[ungated_ide, server])).has_critical
    assert analyze_trifecta(AIBOM(components=[unverified_default, server])).has_critical
    assert analyze_trifecta(AIBOM(components=[default_with_allow, server])).has_critical
    assert analyze_trifecta(AIBOM(components=[default_with_risk, server])).has_critical
    # No collector records verified effective authorization, so the untyped property that
    # claims it clears nothing either.
    assert analyze_trifecta(AIBOM(components=[verified_gated, server])).has_critical


def test_ide_agent_with_prompt_edge_still_covers_workspace_mcp_servers() -> None:
    """An IDE agent in bypassPermissions with a single edge to a prompt still catches MCP risks."""
    ide = IDEAgentComponent(
        bom_ref="ide:claude",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="bypassPermissions",
    )
    prompt = PromptComponent(bom_ref="prompt:claude-md", name="CLAUDE.md")
    server = MCPServerComponent(
        bom_ref="mcp:remote",
        name="remote-mcp",
        endpoint_url="https://remote.example.com/mcp",
        env={"API_TOKEN": "***"},
    )
    bom = AIBOM(
        components=[ide, prompt, server],
        dependencies=[
            DependencyEdge(
                source_ref="ide:claude",
                target_ref="prompt:claude-md",
                relationship="reads-instructions",
            )
        ],
    )
    report = analyze_trifecta(bom)
    assert report.has_critical


def test_empty_agent_cannot_hide_unlinked_tools() -> None:
    """An AgentComponent with no tool_refs must not drop unlinked tools from evaluation."""
    dummy = AgentComponent(bom_ref="agent:empty", name="empty", tool_refs=[])
    t_in = ToolComponent(bom_ref="tool:in", name="fetch_url")
    t_priv = ToolComponent(bom_ref="tool:priv", name="read_secret")
    t_out = ToolComponent(
        bom_ref="tool:out",
        name="post_slack",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE]
        ),
    )
    report = analyze_trifecta(AIBOM(components=[dummy, t_in, t_priv, t_out]))
    assert report.has_critical
    assert any(f.scope_ref == "inventory:unscoped" for f in report.findings)


@pytest.mark.parametrize(
    ("input_name", "private_name"),
    [
        ("fetch_url", "read_secret"),
        ("fetchUrl", "readSecrets"),
        ("WebFetch", "FileRead"),
        ("get_url", "cat_file"),
        ("f\u0435tch", "read_secret"),  # Cyrillic small letter ie
        ("f\u0435tchUrl", "r\u0435adSecrets"),
        ("fet\u03f2h", "read_secret"),  # Greek lunate sigma, which NFKC turns into a sigma
        ("fet\u1d04h", "read_secret"),
        ("fetch", "read_se\u1d04ret"),
        ("\u0192etch", "read_secret"),
        ("fetch", "re\u0251d_file"),
        ("fetch", "l\u0585ad_file"),
        ("fetch", "\u1d0fpen_file"),
    ],
)
def test_naming_evasion_variants_are_caught_without_capabilities(
    input_name: str,
    private_name: str,
) -> None:
    t_in = ToolComponent(bom_ref="tool:in", name=input_name)
    t_priv = ToolComponent(bom_ref="tool:priv", name=private_name)
    t_out = ToolComponent(
        bom_ref="tool:out",
        name="post_slack",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE]
        ),
    )
    report = analyze_trifecta(AIBOM(components=[t_in, t_priv, t_out]))
    assert report.has_critical
    trifecta = [f for f in report.findings if f.kind == "lethal_trifecta"]
    assert len(trifecta) == 1
    assert set(trifecta[0].component_refs) == {"tool:in", "tool:priv", "tool:out"}


def test_chained_toxic_flow_two_tools_is_one_finding() -> None:
    reader = ToolComponent(
        bom_ref="tool:read-customer-db",
        name="query_db",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM],
            filesystem_paths=["/var/data/customers.sqlite"],
        ),
    )
    sender = ToolComponent(
        bom_ref="tool:send-report",
        name="send_report",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK],
            egress_domains=["reports.example.org"],
        ),
    )
    bom = AIBOM(components=[reader, sender])
    report = analyze_trifecta(bom)
    toxic = [f for f in report.findings if f.kind == "toxic_flow"]
    assert len(toxic) == 1
    assert toxic[0].severity is RiskSeverity.HIGH
    assert set(toxic[0].component_refs) == {"tool:read-customer-db", "tool:send-report"}

    sender.capabilities = CapabilityDeclaration(
        capabilities=[CapabilityClass.NETWORK],
        egress_domains=["reports.example.org"],
        human_in_the_loop=HumanInTheLoop.REQUIRED,
    )
    clean_report = analyze_trifecta(bom, assume_declared_approvals=True)
    assert [f for f in clean_report.findings if f.kind == "toxic_flow"] == []


def test_tool_shadowing_detects_camelcase_zwsp_and_homoglyphs() -> None:
    trusted = ToolComponent(
        bom_ref="tool:internal-lookup",
        name="lookup_ticket",
        mcp_server_ref="mcp:internal",
        source_path="internal/mcp.json",
        trust_tier=TrustTier.INTERNAL_VERIFIED,
        assurance_level=AssuranceLevel.OBSERVED,
    )
    shadow_zwsp = ToolComponent(
        bom_ref="tool:thirdparty-zwsp",
        name="lookup\u200b-ticket",
        mcp_server_ref="mcp:thirdparty-1",
        source_path="thirdparty/mcp1.json",
        trust_tier=TrustTier.UNTRUSTED_PUBLIC,
    )
    shadow_camel = ToolComponent(
        bom_ref="tool:thirdparty-camel",
        name="lookupTicket",
        mcp_server_ref="mcp:thirdparty-2",
        source_path="thirdparty/mcp2.json",
        trust_tier=TrustTier.UNTRUSTED_PUBLIC,
    )
    shadow_cyrillic = ToolComponent(
        bom_ref="tool:thirdparty-cyrillic",
        name="l\u043e\u043ekup_ticket",  # Cyrillic small letter o
        mcp_server_ref="mcp:thirdparty-3",
        source_path="thirdparty/mcp3.json",
        trust_tier=TrustTier.UNTRUSTED_PUBLIC,
    )
    assert canonical_tool_name("lookupTicket") == "lookup_ticket"
    assert canonical_tool_name("l\u043e\u043ekup_ticket") == "lookup_ticket"

    report = analyze_trifecta(
        AIBOM(components=[trusted, shadow_zwsp, shadow_camel, shadow_cyrillic])
    )
    shadow_findings = [f for f in report.findings if f.kind == "tool_shadowing"]
    assert len(shadow_findings) == 1
    assert shadow_findings[0].severity is RiskSeverity.HIGH
    assert set(report.shadowed_refs) == {
        "tool:internal-lookup",
        "tool:thirdparty-zwsp",
        "tool:thirdparty-camel",
        "tool:thirdparty-cyrillic",
    }


def test_trifecta_linear_time_on_large_tool_set_and_agent_graphs() -> None:
    """2,000+2,000 tools, a 2,000-agent cycle, and an alternating-gate chain stay linear."""
    tool_boms = {
        scale: AIBOM(
            components=[
                ToolComponent(bom_ref=f"tool:priv-{i}", name=f"read_secret_{i}")
                for i in range(500 * scale)
            ]
            + [
                ToolComponent(
                    bom_ref=f"tool:sink-{i}",
                    name=f"send_report_{i}",
                    capabilities=CapabilityDeclaration(
                        capabilities=[CapabilityClass.NETWORK],
                        egress_domains=["reports.example.org"],
                    ),
                )
                for i in range(500 * scale)
            ]
        )
        for scale in (1, 4)
    }
    report_tools = analyze_trifecta(tool_boms[4])
    assert any(f.kind == "toxic_flow" for f in report_tools.findings)
    assert scaling_ratio(lambda scale: analyze_trifecta(tool_boms[scale])) < 10

    t_in = ToolComponent(bom_ref="tool:in", name="fetch_url")
    t_priv = ToolComponent(bom_ref="tool:priv", name="read_secret")
    t_out = ToolComponent(
        bom_ref="tool:out",
        name="post_slack",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE]
        ),
    )

    def _cycle_bom(count: int) -> AIBOM:
        cycle_agents = [
            AgentComponent(
                bom_ref=f"agent:c{i}",
                name=f"c{i}",
                sub_agent_refs=[f"agent:c{(i + 1) % count}"],
            )
            for i in range(count)
        ]
        cycle_agents[0].tool_refs = ["tool:in", "tool:priv", "tool:out"]
        return AIBOM(components=[*cycle_agents, t_in, t_priv, t_out])

    cycle_boms = {scale: _cycle_bom(500 * scale) for scale in (1, 4)}
    report_cycle = analyze_trifecta(cycle_boms[4])
    assert report_cycle.has_critical
    assert scaling_ratio(lambda scale: analyze_trifecta(cycle_boms[scale])) < 10

    def _chain_bom(count: int) -> AIBOM:
        chain_agents = [
            AgentComponent(
                bom_ref=f"agent:k{i}",
                name=f"k{i}",
                sub_agent_refs=[f"agent:k{i + 1}"] if i < count - 1 else [],
                capabilities=CapabilityDeclaration(
                    human_in_the_loop=HumanInTheLoop.REQUIRED if i % 2 == 0 else None
                ),
            )
            for i in range(count)
        ]
        chain_agents[-1].tool_refs = ["tool:in", "tool:priv", "tool:out"]
        return AIBOM(components=[*chain_agents, t_in, t_priv, t_out])

    chain_boms = {scale: _chain_bom(500 * scale) for scale in (1, 4)}
    report_chain = analyze_trifecta(chain_boms[4])
    assert report_chain.has_critical
    assert scaling_ratio(lambda scale: analyze_trifecta(chain_boms[scale])) < 10


def test_trifecta_cli_gate_and_determinism(tmp_path: Path) -> None:
    ungated_path = tmp_path / "ungated.json"
    gated_path = tmp_path / "gated.json"
    bom_ungated = _trifecta_bom(gated=False)
    bom_ungated.save(ungated_path)
    _trifecta_bom(gated=True).save(gated_path)

    runner = CliRunner()
    res_fail = runner.invoke(main, ["trifecta", str(ungated_path)])
    assert res_fail.exit_code == 1
    payload_1 = json.loads(res_fail.output)
    assert payload_1["severity_counts"]["critical"] == 1

    # Reversed component order must produce byte-identical JSON.
    reversed_path = tmp_path / "ungated_rev.json"
    AIBOM(components=list(reversed(bom_ungated.components))).save(reversed_path)
    res_rev = runner.invoke(main, ["trifecta", str(reversed_path)])
    assert res_rev.exit_code == 1
    assert res_rev.output == res_fail.output

    res_declared = runner.invoke(main, ["trifecta", str(gated_path)])
    assert res_declared.exit_code == 0, res_declared.output
    findings = json.loads(res_declared.output)["findings"]
    declared = next(f for f in findings if f["kind"] == "lethal_trifecta")
    assert declared["severity"] == "high"
    assert "enforcement is unverified" in declared["summary"]
    assert all(not entry["gated"] for entry in declared["evidence"])
    strict = runner.invoke(main, ["trifecta", str(gated_path), "--fail-on-finding"])
    assert strict.exit_code == 1


def _name_only_tools() -> list[ToolComponent]:
    return [
        ToolComponent(bom_ref="tool:in", name="web_search"),
        ToolComponent(bom_ref="tool:priv", name="read_secret"),
        ToolComponent(
            bom_ref="tool:out",
            name="post_slack",
            capabilities=CapabilityDeclaration(
                capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE]
            ),
        ),
    ]


def _critical_scopes(bom: AIBOM) -> set[str]:
    return {f.scope_ref for f in analyze_trifecta(bom).findings if f.kind == "lethal_trifecta"}


def test_legs_split_between_a_bound_ide_agent_and_unbound_servers_still_meet() -> None:
    """A bypass-mode IDE agent bound to one harmless server does not shed the others."""
    ide = IDEAgentComponent(
        bom_ref="ide:claude",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="bypassPermissions",
        mcp_server_refs=["mcp:time"],
    )
    servers = [
        MCPServerComponent(bom_ref="mcp:time", name="time", launcher_package="mcp-server-time"),
        MCPServerComponent(bom_ref="mcp:search", name="brave", launcher_package="brave-search"),
        MCPServerComponent(bom_ref="mcp:pg", name="postgres", launcher_package="pg-mcp"),
    ]
    assert _critical_scopes(AIBOM(components=servers)) == set()
    assert _critical_scopes(AIBOM(components=[ide, *servers])) == {"ide:claude"}


def test_decoy_agent_bound_to_one_leg_does_not_split_the_trifecta() -> None:
    decoy = AgentComponent(bom_ref="agent:decoy", name="decoy", tool_refs=["tool:in"])
    assert _critical_scopes(AIBOM(components=[decoy, *_name_only_tools()])) == {"agent:decoy"}
    # An agent that holds no leg adds nothing to the unbound pool's own finding.
    idle = AgentComponent(bom_ref="agent:idle", name="idle")
    assert _critical_scopes(AIBOM(components=[idle, *_name_only_tools()])) == {"inventory:unscoped"}


def test_url_fetchers_count_as_egress() -> None:
    """A tool or server that requests a URL of the model's choosing can carry data out."""
    fetch = MCPServerComponent(
        bom_ref="mcp:fetch", name="fetch", launcher_package="@modelcontextprotocol/server-fetch"
    )
    files = MCPServerComponent(
        bom_ref="mcp:fs",
        name="filesystem",
        launcher_package="@modelcontextprotocol/server-filesystem",
    )
    assert _critical_scopes(AIBOM(components=[fetch, files])) == {"inventory:root"}
    assert _critical_scopes(AIBOM(components=[files])) == set()

    reader = ToolComponent(bom_ref="tool:priv", name="read_secret")
    for name in ("fetch_url", "http_get", "browse"):
        declared = ToolComponent(
            bom_ref="tool:in",
            name=name,
            capabilities=CapabilityDeclaration(
                capabilities=[CapabilityClass.NETWORK, CapabilityClass.READ],
                side_effect_profile=SideEffectProfile.READ_ONLY,
            ),
        )
        assert analyze_trifecta(AIBOM(components=[declared, reader])).has_critical, name
        bare = ToolComponent(bom_ref="tool:in", name=name)
        assert analyze_trifecta(AIBOM(components=[bare, reader])).has_critical, name


def test_ungated_url_fetcher_beside_a_gated_webhook_is_critical() -> None:
    bom = _trifecta_bom(gated=True)
    fetch = next(c for c in bom.components if c.bom_ref == "tool:web-fetch")
    assert isinstance(fetch, ToolComponent) and fetch.capabilities is not None
    fetch.capabilities.human_in_the_loop = HumanInTheLoop.NONE
    assert analyze_trifecta(bom).has_critical


_NOW = datetime(2026, 6, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("records", "gated"),
    [
        ([{"action": "egress"}], True),
        ([{"action": "*", "resource_scope": "*"}], True),
        ([{"action": "egress", "expires_at": datetime(2026, 6, 2, tzinfo=UTC)}], True),
        ([{"action": "read-docs"}], False),
        ([{"action": "egress", "resource_scope": "hooks.example.com"}], False),
        ([{"action": "egress", "expires_at": datetime(2026, 5, 31, tzinfo=UTC)}], False),
        ([{"action": "egress", "expires_at": datetime(2026, 6, 2)}], False),  # noqa: DTZ001
        ([{"action": "egress"}, {"action": "deploy", "approval_required": False}], False),
        (
            [{"action": "egress"}, {"action": "x", "expires_at": datetime(2020, 1, 1, tzinfo=UTC)}],
            False,
        ),
    ],
)
def test_approval_record_gates_only_what_it_covers(
    records: list[dict[str, object]], gated: bool
) -> None:
    agent = AgentComponent(
        bom_ref="agent:a",
        name="a",
        tool_refs=["tool:in", "tool:priv", "tool:out"],
        authorizations=[
            AuthorizationRecord.model_validate(
                {"principal": "user:alice", "approval_required": True, **record}
            )
            for record in records
        ],
    )
    report = analyze_trifecta(
        AIBOM(components=[agent, *_name_only_tools()]), now=_NOW, assume_declared_approvals=True
    )
    assert report.has_critical is not gated
    observed = analyze_trifecta(AIBOM(components=[agent, *_name_only_tools()]), now=_NOW)
    severity = next(f.severity for f in observed.findings if f.kind == "lethal_trifecta")
    assert severity is (RiskSeverity.HIGH if gated else RiskSeverity.CRITICAL)


def test_untyped_verified_authorization_property_cannot_gate_an_ide_agent() -> None:
    server = MCPServerComponent(
        bom_ref="mcp:remote",
        name="remote-mcp",
        endpoint_url="https://remote.example.com/mcp",
        env={"API_TOKEN": "[redacted]"},
    )
    for ide_type, mode, properties in (
        ("claude-code", "default", {}),
        ("claude-code", "plan", {}),
        ("codex", None, {"approval_policy": "untrusted"}),
    ):
        ide = IDEAgentComponent(
            bom_ref="ide:agent",
            name=ide_type,
            ide_type=ide_type,
            permission_mode=mode,
            assurance_level=AssuranceLevel.VERIFIED,
            properties={"effective_authorization_verified": True, **properties},
        )
        assert analyze_trifecta(AIBOM(components=[ide, server])).has_critical, ide_type


def test_camel_case_split_is_linear_in_a_run_of_capitals() -> None:
    assert canonical_tool_name("HTTPServerURL") == "http_server_url"
    assert canonical_tool_name("getHTTPResponse2Json") == "get_http_response2_json"
    assert canonical_tool_name("A" * 50 + "b") == "a" * 49 + "_ab"
    assert scaling_ratio(lambda scale: canonical_tool_name("A" * (4000 * scale))) < 10
    assert scaling_ratio(lambda scale: canonical_tool_name("aB" * (2000 * scale))) < 10
    tool = [ToolComponent(bom_ref="tool:a", name="A" * 200_000)]
    assert analyze_trifecta(AIBOM(components=tool)).findings == ()


def _shared_hub(roots: int) -> AIBOM:
    """Many root agents over one hub agent whose tools hold every leg many times."""
    tools = [
        ToolComponent(bom_ref=f"tool:{kind}-{i:05}", name=f"{name}_{i}")
        for i in range(roots)
        for kind, name in (("in", "fetch_url"), ("priv", "read_secret"), ("out", "post_slack"))
    ]
    hub = AgentComponent(bom_ref="agent:hub", name="hub", tool_refs=[t.bom_ref for t in tools])
    agents = [
        AgentComponent(bom_ref=f"agent:root-{i:05}", name=f"r{i}", sub_agent_refs=["agent:hub"])
        for i in range(roots)
    ]
    return AIBOM(components=[*agents, hub, *tools])


def test_scope_construction_is_linear_in_agents_sharing_one_tool_surface() -> None:
    boms = {scale: _shared_hub(100 * scale) for scale in (1, 4)}
    assert scaling_ratio(lambda scale: analyze_trifecta(boms[scale])) < 10

    sizes = {}
    peaks = {}
    for scale, bom in boms.items():
        tracemalloc.start()
        report = analyze_trifecta(bom)
        sizes[scale] = len(json.dumps(report.to_dict()))
        peaks[scale] = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        trifectas = [f for f in report.findings if f.kind == "lethal_trifecta"]
        assert len(trifectas) == 100 * scale
        for finding in trifectas:
            for leg in ("untrusted_input", "private_data", "egress"):
                listed = [e["component_ref"] for e in finding.evidence if e["leg"] == leg]
                assert 0 < len(listed) <= EVIDENCE_LIMIT
                assert listed == sorted(listed)
            assert "at least" in finding.summary
    assert sizes[4] < 6 * sizes[1]
    assert peaks[4] < 6 * peaks[1]


def test_evidence_cap_keeps_every_leg_and_the_smallest_references() -> None:
    report = analyze_trifecta(_shared_hub(EVIDENCE_LIMIT + 5))
    finding = next(f for f in report.findings if f.scope_ref == "agent:root-00000")
    listed = [e["component_ref"] for e in finding.evidence if e["leg"] == "private_data"]
    assert listed == [f"tool:priv-{i:05}" for i in range(EVIDENCE_LIMIT)]
    small = analyze_trifecta(_shared_hub(2))
    assert all("at least" not in f.summary for f in small.findings)


def test_tool_description_text_from_collectors_feeds_the_untrusted_leg() -> None:
    described = ToolComponent(
        bom_ref="tool:in",
        name="lookup",
        description_text="Fetch external web pages, then summarize them.",
    )
    quiet = ToolComponent(bom_ref="tool:in", name="lookup", description_text="Adds two numbers.")
    rest = _name_only_tools()[1:]
    assert analyze_trifecta(AIBOM(components=[described, *rest])).has_critical
    assert not analyze_trifecta(AIBOM(components=[quiet, *rest])).has_critical


def _scan_and_analyze(root: Path, settings: dict[str, object], servers: dict[str, object]) -> int:
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    (root / ".claude").mkdir()
    (root / ".claude" / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    runner = CliRunner()
    bom_path = root / "bom.json"
    assert runner.invoke(main, ["scan", str(root), "-o", str(bom_path)]).exit_code == 0
    return runner.invoke(main, ["trifecta", str(bom_path)]).exit_code


@pytest.mark.parametrize(
    ("allow", "servers", "exit_code"),
    [
        # Every tool, with no narrowing, holds all three legs by itself.
        (["*"], {}, 1),
        # A read of everything is the private leg beside a server that fetches.
        (["Read(**)"], {"fetch": {"command": "npx", "args": ["-y", "mcp-server-fetch"]}}, 1),
        (["Read(./docs/**)"], {"fetch": {"command": "npx", "args": ["-y", "mcp-server-fetch"]}}, 0),
        (["WebFetch", "Read(//**)"], {}, 1),
        (["Bash(npm test)"], {"time": {"command": "npx", "args": ["-y", "mcp-server-time"]}}, 0),
        # A shell reads private files and sends them out, so it holds every leg.
        (["WebFetch", "Bash"], {}, 1),
        (["Bash(*)"], {}, 1),
    ],
)
def test_real_scan_ide_allow_rules_hold_the_legs_they_grant(
    tmp_path: Path, allow: list[str], servers: dict[str, object], exit_code: int
) -> None:
    settings = {"permissions": {"defaultMode": "default", "allow": allow}}
    assert _scan_and_analyze(tmp_path, settings, servers) == exit_code


@pytest.mark.parametrize(
    ("mode", "exit_code"), [("bypassPermissions", 1), ("acceptEdits", 0), ("default", 0)]
)
def test_real_scan_bypass_mode_holds_every_leg(tmp_path: Path, mode: str, exit_code: int) -> None:
    """Bypass mode runs Bash unprompted, so the agent is the private leg beside a fetch server."""
    settings = {"permissions": {"defaultMode": mode}}
    servers = {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}
    assert _scan_and_analyze(tmp_path, settings, servers) == exit_code


@pytest.mark.parametrize(
    ("approval", "sandbox", "critical"),
    [
        ("never", "danger-full-access", True),
        ("never", "workspace-write", False),
        ("on-request", "danger-full-access", False),
        ("never", ["danger-full-access"], False),
    ],
)
def test_codex_without_prompts_or_sandbox_holds_every_leg(
    approval: str, sandbox: object, critical: bool
) -> None:
    codex = IDEAgentComponent(
        bom_ref="ide:codex",
        name="codex",
        ide_type="codex",
        properties={"approval_policy": approval, "sandbox_mode": sandbox},
    )
    assert analyze_trifecta(AIBOM(components=[codex])).has_critical is critical


def test_every_allowance_class_the_collector_names_has_its_legs() -> None:
    """The collector's class names are the only record of the rules; a new one must be mapped."""
    assert set(_SCOPED_TOOL_CLASSES.values()) <= _IDE_GRANT_LEGS.keys()
    unknown = IDEAgentComponent(
        bom_ref="ide:claude",
        name="claude-code",
        ide_type="claude-code",
        risks=[
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="permission_scope",
                detail="IDE agent 'claude-code' declares unscoped tool allowances (new class).",
            )
        ],
    )
    assert analyze_trifecta(AIBOM(components=[unknown])).has_critical


def test_documentation_servers_named_for_a_platform_are_not_private_data() -> None:
    def remote(name: str) -> MCPServerComponent:
        return MCPServerComponent(
            bom_ref=f"mcp:{name}", name=name, endpoint_url=f"https://{name}.example.com/mcp"
        )

    assert not analyze_trifecta(
        AIBOM(components=[remote("aws-docs"), remote("react-docs")])
    ).has_critical
    packaged = MCPServerComponent(
        bom_ref="mcp:d",
        name="reference",
        launcher_package="awslabs.aws-documentation-mcp-server",
    )
    assert not analyze_trifecta(AIBOM(components=[packaged, remote("react-docs")])).has_critical
    # The platform itself, and a datastore whatever it is called, still count.
    for name in ("aws", "aws-api", "postgres-docs", "docs-s3"):
        bom = AIBOM(components=[remote(name), remote("react-docs")])
        assert analyze_trifecta(bom).has_critical, name


@pytest.mark.parametrize(
    ("name", "private"),
    [
        ("PGPASSWORD", True),
        ("MONGODB_URI", True),
        ("POSTGRES_URL", True),
        ("SUPABASE_SERVICE_ROLE_KEY", True),
        ("DATABASE_URL", True),
        ("MYSQL_PWD", True),
        ("GITHUB_TOKEN", True),
        ("APIKEY", True),
        ("DBPASSWD", True),
        ("TZ", False),
        ("NODE_ENV", False),
        ("LOG_LEVEL", False),
        ("API_BASE_URL", False),
        ("TOKENIZERS_PARALLELISM", False),
        ("KEYBOARD_LAYOUT", False),
        ("MYPG_URL", True),
        ("my-redis_uri", True),
        ("REDIS_CACHE_URL", False),
        ("DB" * 500 + "_URL", True),
        ("DB" * 500, False),
    ],
)
def test_secret_environment_names(name: str, private: bool) -> None:
    server = MCPServerComponent(
        bom_ref="mcp:s", name="thing", endpoint_url="https://x.example.com/mcp", env={name: "x"}
    )
    assert analyze_trifecta(AIBOM(components=[server])).has_critical is private


def test_secret_environment_name_scan_is_linear() -> None:
    """A long run of datastore names without a URL suffix must not rescan the run per name."""

    def analyze(scale: int) -> None:
        server = MCPServerComponent(
            bom_ref="mcp:s",
            name="thing",
            endpoint_url="https://x.example.com/mcp",
            env={"db" * (2000 * scale): "x", "pg_" * (1000 * scale): "x"},
        )
        analyze_trifecta(AIBOM(components=[server]))

    assert scaling_ratio(analyze) < 10


# The anchors are written \A and \Z (CodeQL misreads ^ and $ inside these alternations as
# unmatchable); these cases pin that both ends still bound a word, as ^ and $ did.
@pytest.mark.parametrize(
    ("name", "secret"),
    [
        ("KEY", True),
        ("TOKEN", True),
        ("API_KEY", True),
        ("KEY_ID", True),
        ("TOKEN\n", True),
        ("AWS_ACCESS_KEY_ID", True),
        ("anthropic_base_url", True),
        ("MONKEY", False),
        ("KEYRING", False),
        ("MY_AWS_ACCESS", False),
        ("TZ", False),
        ("NODE_ENV", False),
    ],
)
def test_secret_env_key_anchors_bound_a_word(name: str, secret: bool) -> None:
    from nexus_symbiote.trifecta import SECRET_ENV_KEY_RE

    assert bool(SECRET_ENV_KEY_RE.search(name)) is secret


def test_required_approvals_are_visible_on_unverified_flow_legs():
    report = analyze_trifecta(_trifecta_bom(gated=True))
    flow = next(f for f in report.findings if f.kind == "lethal_trifecta")
    assert any(leg["component_approval_declared"] for leg in flow.evidence)
    assert all(
        not leg["approval_enforcement_verified"] and not leg["gated"] for leg in flow.evidence
    )
