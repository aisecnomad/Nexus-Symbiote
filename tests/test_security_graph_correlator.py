"""Tests for unified security graph correlation and agent manifest identity/egress fields."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
)
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import (
    AgentComponent,
    CapabilityDeclaration,
    DataSourceComponent,
    MCPServerComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.graph import AgentDeclaration, assemble_repository_agent, blast_radius
from nexus_symbiote.security_graph import (
    SECURITY_GRAPH_SCHEMA,
    build_security_graph,
    render_security_graph_html,
    render_security_graph_json,
    render_security_graph_markdown,
    render_security_graph_mermaid,
)
from nexus_symbiote.vex_decisions import ExecutionEvidence, LoadedAdvisoryReport


def _sample_bom() -> AIBOM:
    bom = AIBOM()
    pkg = RegistryEntryComponent(
        bom_ref="pkg:npm/mcp-remote@0.1.15",
        name="mcp-remote",
        version="0.1.15",
        registry_type="npm",
        source_path="package-lock.json",
        properties={
            "advisories": [
                {
                    "id": "GHSA-6xpm-ggf7-wc3p",
                    "aliases": ["CVE-2025-6514"],
                    "severity": "critical",
                    "kev": True,
                    "epss": 0.91,
                }
            ]
        },
    )
    mcp = MCPServerComponent(
        bom_ref="mcp:server:remote-bridge",
        name="remote-bridge",
        command="npx",
        args=["mcp-remote@0.1.15"],
        launcher_package="npm:mcp-remote",
        source_path=".mcp.json",
        properties={"env_vars_referenced": ["OPENAI_API_KEY", "GITHUB_TOKEN"]},
    )
    tool = ToolComponent(
        bom_ref="tool:remote-bridge:send_report",
        name="send_report",
        mcp_server_ref="mcp:server:remote-bridge",
        source_path=".mcp.json",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE],
            side_effect_profile=SideEffectProfile.STATE_MODIFYING,
        ),
        risks=[
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="tool_description_poisoning",
                detail="Hidden directive in tool description.",
            )
        ],
    )
    db = DataSourceComponent(
        bom_ref="data:customer-db",
        name="customer-db",
        source_path="rag.yaml",
    )
    agent = AgentComponent(
        bom_ref="agent:support-bot",
        name="support-bot",
        tool_refs=["mcp:server:remote-bridge", "tool:remote-bridge:send_report"],
        data_refs=["data:customer-db"],
        properties={
            "declared_spiffe_id": "spiffe://prod.example.com/ns/ai/sa/support-bot",
            "declared_egress_domains": ["api.openai.com", "hooks.slack.com"],
            "declared_delegates_to": ["agent:billing-bot"],
        },
    )
    bom.components.extend([pkg, mcp, tool, db, agent])
    bom.add_dependency(
        DependencyEdge(
            source_ref="mcp:server:remote-bridge",
            target_ref="pkg:npm/mcp-remote@0.1.15",
            relationship="registered-as",
            assurance_level="declared",
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:support-bot",
            target_ref="mcp:server:remote-bridge",
            relationship="configured-with",
            assurance_level="declared",
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="mcp:server:remote-bridge",
            target_ref="tool:remote-bridge:send_report",
            relationship="provides-tool",
            assurance_level="declared",
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:support-bot",
            target_ref="data:customer-db",
            relationship="retrieves-from",
            assurance_level="declared",
        )
    )
    return bom


def test_agent_manifest_spiffe_egress_delegation_validation_and_blast_radius(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.yaml").write_text(
        "\n".join(
            [
                "id: acme:support",
                "name: support",
                "autonomy_level: L2-agent",
                "spiffe_id: spiffe://acme.example.com/ns/agents/sa/support",
                "egress_domains:",
                "  - API.OpenAI.com",
                "  - '*.slack.com'",
                "delegates_to:",
                "  - acme:billing",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    bom = AIBOM()
    agent = assemble_repository_agent(bom, tmp_path)
    assert (
        agent.properties["declared_spiffe_id"] == "spiffe://acme.example.com/ns/agents/sa/support"
    )
    assert agent.properties["declared_egress_domains"] == ["*.slack.com", "api.openai.com"]
    assert agent.properties["declared_delegates_to"] == ["acme:billing"]
    assert agent.claims["spiffe_id"].assurance is AssuranceLevel.DECLARED
    assert agent.claims["egress_domains"].assurance is AssuranceLevel.DECLARED
    assert agent.claims["delegates_to"].assurance is AssuranceLevel.DECLARED

    br = blast_radius(bom, agent.bom_ref)
    assert br["declared_workload_identities"] == ["spiffe://acme.example.com/ns/agents/sa/support"]
    assert br["declared_egress_domains"] == ["*.slack.com", "api.openai.com"]
    assert br["declared_delegations"] == ["acme:billing"]


def test_agent_manifest_rejects_invalid_spiffe_egress_and_credential_delegation() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AgentDeclaration(name="bad", spiffe_id="https://not-spiffe.example.com/sa")
    with pytest.raises(ValidationError):
        AgentDeclaration(name="bad", spiffe_id="spiffe://example.com/../escape")
    with pytest.raises(ValidationError):
        AgentDeclaration(name="bad", egress_domains=["https://user:pass@evil.example.com"])
    with pytest.raises(ValidationError):
        AgentDeclaration(name="bad", delegates_to=["ghp_1234567890abcdef1234567890abcdef1234"])


def test_build_security_graph_correlates_cve_package_mcp_agent_credentials_and_sinks() -> None:
    bom = _sample_bom()
    adv_report = LoadedAdvisoryReport(
        advisories=[
            {
                "advisory_id": "GHSA-6xpm-ggf7-wc3p",
                "component_ref": "pkg:npm/mcp-remote@0.1.15",
                "severity": "high",
                "kev": True,
                "epss": 0.95,
                "aliases": ["CVE-2025-6514"],
            }
        ],
        sha256="sha256:" + "a" * 64,
        coverage="complete",
        checked=1,
        skipped=0,
        excluded=0,
        errors=0,
    )
    trace = ExecutionEvidence(
        invoked_refs=frozenset({"agent:support-bot"}),
        declared_never_loaded_refs=frozenset(),
        unobserved_refs=frozenset(),
        shadowed_refs=frozenset(),
        sha256="sha256:" + "b" * 64,
    )
    report = build_security_graph(
        bom,
        advisory_report=adv_report,
        execution_evidence=trace,
        inventory_sha256="sha256:" + "c" * 64,
    )
    assert report.schema_version == SECURITY_GRAPH_SCHEMA
    assert report.kev_chain_count == 1
    assert report.chain_count >= 2

    adv_chain = next(c for c in report.chains if c.trigger_id == "GHSA-6xpm-ggf7-wc3p")
    assert adv_chain.severity == "critical"
    assert adv_chain.kev is True
    assert adv_chain.epss == 0.95
    assert adv_chain.affected_agents == ("agent:support-bot",)
    assert adv_chain.credential_names == ("GITHUB_TOKEN", "OPENAI_API_KEY")
    assert adv_chain.data_sinks == ("data:customer-db",)
    assert adv_chain.egress_domains == ("api.openai.com", "hooks.slack.com")
    assert adv_chain.workload_identities == ("spiffe://prod.example.com/ns/ai/sa/support-bot",)
    assert adv_chain.runtime_status == "reported:invoked"
    assert len(adv_chain.hops) >= 3

    # Verify all four renderers produce safe, deterministic outputs.
    assert json.loads(render_security_graph_json(report))["kev_chain_count"] == 1
    mermaid = render_security_graph_mermaid(report)
    assert mermaid.startswith("flowchart LR\n")
    assert "GHSA-6xpm-ggf7-wc3p" in mermaid
    markdown = render_security_graph_markdown(report)
    assert "Security Graph Correlation Report" in markdown
    assert "OPENAI_API_KEY" in markdown
    html_doc = render_security_graph_html(report)
    assert "Content-Security-Policy" in html_doc
    assert "default-src 'none'" in html_doc
    assert "<script" not in html_doc.lower()


def test_security_graph_cli_formats_and_ci_gates(tmp_path: Path) -> None:
    bom = _sample_bom()
    bom_path = tmp_path / "inventory.json"
    bom.save(bom_path)
    inv_sha = hash_bytes(bom_path.read_bytes())

    adv_path = tmp_path / "advisories.json"
    adv_path.write_text(
        json.dumps(
            {
                "inventory_sha256": inv_sha,
                "coverage": "complete",
                "complete": True,
                "dry_run": False,
                "components_checked": 1,
                "components_skipped": 0,
                "components_excluded": 0,
                "errors": [],
                "advisories": [
                    {
                        "advisory_id": "GHSA-6xpm-ggf7-wc3p",
                        "component_ref": "pkg:npm/mcp-remote@0.1.15",
                        "severity": "critical",
                        "kev": True,
                        "epss": 0.92,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    res = runner.invoke(
        main,
        ["security-graph", str(bom_path), "--advisories", str(adv_path), "--format", "json"],
    )
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["kev_chain_count"] == 1

    kev_gate = runner.invoke(
        main,
        [
            "security-graph",
            str(bom_path),
            "--advisories",
            str(adv_path),
            "--fail-on-kev",
        ],
    )
    assert kev_gate.exit_code == 1

    html_out = tmp_path / "graph.html"
    res_html = runner.invoke(
        main,
        ["security-graph", str(bom_path), "--format", "html", "-o", str(html_out)],
    )
    assert res_html.exit_code == 0, res_html.output
    assert "Content-Security-Policy" in html_out.read_text(encoding="utf-8")

    # HTML without -o fails cleanly with usage error.
    res_no_out = runner.invoke(main, ["security-graph", str(bom_path), "--format", "html"])
    assert res_no_out.exit_code == 2

    # blast-radius --advisories wires correlated chains cleanly.
    br_res = runner.invoke(
        main,
        [
            "blast-radius",
            str(bom_path),
            "pkg:npm/mcp-remote@0.1.15",
            "--advisories",
            str(adv_path),
            "--json-output",
        ],
    )
    assert br_res.exit_code == 0, br_res.output
    br_data = json.loads(br_res.output)
    assert len(br_data["correlated_chains"]) >= 1

    # Mermaid and Markdown formats succeed on empty BOM too.
    empty_path = tmp_path / "empty.json"
    AIBOM().save(empty_path)
    for fmt in ("mermaid", "markdown"):
        empty_res = runner.invoke(main, ["security-graph", str(empty_path), "--format", fmt])
        assert empty_res.exit_code == 0, empty_res.output


def test_security_graph_rejects_mismatched_advisory_digest(tmp_path: Path) -> None:
    bom_path = tmp_path / "inventory.json"
    _sample_bom().save(bom_path)
    bad_adv = tmp_path / "bad_adv.json"
    bad_adv.write_text(
        json.dumps(
            {
                "inventory_sha256": "sha256:" + "0" * 64,
                "coverage": "complete",
                "complete": True,
                "dry_run": False,
                "components_checked": 1,
                "components_skipped": 0,
                "components_excluded": 0,
                "errors": [],
                "advisories": [],
            }
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    res = runner.invoke(main, ["security-graph", str(bom_path), "--advisories", str(bad_adv)])
    assert res.exit_code != 0
    assert "does not match" in res.output


def test_security_graph_edge_cases_coverage_and_cli_errors(tmp_path: Path) -> None:
    import pytest

    from nexus_symbiote.core.models import (
        ClaimEvidence,
        IDEAgentComponent,
        MemoryStoreComponent,
    )
    from nexus_symbiote.security_graph import (
        _normalize_severity,
        _parse_epss,
        _parse_kev,
        _runtime_status_for_refs,
    )

    assert _normalize_severity(RiskSeverity.HIGH) == "high"
    assert _normalize_severity("moderate") == "medium"
    assert _normalize_severity(123) == "medium"
    assert _parse_epss(True) is None
    assert _parse_epss({"score": 0.42}) == 0.42
    assert _parse_epss("bad") is None
    assert _parse_kev({"cisa_kev": {"dateAdded": "2026-01-01"}}) is True
    assert _parse_kev({"kev": False}) is False

    ev = ExecutionEvidence(
        invoked_refs=frozenset({"a"}),
        declared_never_loaded_refs=frozenset({"b"}),
        unobserved_refs=frozenset({"c"}),
        shadowed_refs=frozenset({"s"}),
        sha256="sha256:" + "e" * 64,
    )
    assert _runtime_status_for_refs(["s"], ev) == "reported:shadowed"
    assert _runtime_status_for_refs(["b"], ev) == "reported:declared-never-loaded"
    assert _runtime_status_for_refs(["x"], ev) == "reported:unobserved"

    bom = _sample_bom()
    gateway = MCPServerComponent(
        bom_ref="mcp:gateway:edge",
        name="edge-gw",
        command="npx",
        args=["gw@1.0.0"],
        env={"STRIPE_SECRET_KEY": "${STRIPE_SECRET_KEY}"},
        claims={
            "config": ClaimEvidence(
                assurance=AssuranceLevel.DECLARED,
                method="mcp-config",
                scope="repository",
                locator="gw.json",
            )
        },
        properties={
            "mcp_role": "gateway",
            "upstream_server_refs": ["mcp:server:remote-bridge"],
            "advisories": [
                {"id": "CVE-2026-0001", "severity": "moderate", "epss": 0.2},
                {"id": "CVE-2026-0001", "severity": "high", "epss": 0.75, "kev": True},
                {"id": ""},
                "not-a-dict",
            ],
        },
    )
    mem = MemoryStoreComponent(
        bom_ref="mem:session",
        name="session-store",
        source_path="agent.yaml",
    )
    ide = IDEAgentComponent(
        bom_ref="ide:claude-code",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="bypassPermissions",
        source_path=".claude/settings.json",
    )
    bom.components.extend([gateway, mem, ide])
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:support-bot",
            target_ref="mcp:gateway:edge",
            relationship="configured-with",
            assurance_level="declared",
            conditions="static config",
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:support-bot",
            target_ref="mem:session",
            relationship="uses-memory",
            assurance_level="declared",
        )
    )

    adv_report = LoadedAdvisoryReport(
        advisories=[
            {
                "advisory_id": "CVE-2026-0001",
                "component_ref": "mcp:gateway:edge",
                "severity": "medium",
                "epss": 0.1,
            },
            {
                "advisory_id": "CVE-2026-9999",
                "component_ref": "pkg:missing@0.0.0",
                "severity": "high",
            },
        ],
        sha256="sha256:" + "d" * 64,
        coverage="complete",
        checked=2,
        skipped=0,
        excluded=0,
        errors=0,
    )
    report = build_security_graph(bom, advisory_report=adv_report, max_chains=2)
    assert report.chain_count == 2
    assert report.chains_omitted >= 1
    assert any("omitted" in lim for lim in report.limitations)
    assert "static config" in json.dumps(report.to_dict())

    bad_bom = AIBOM()
    bad_bom.add_dependency(
        DependencyEdge(source_ref="missing-a", target_ref="missing-b", relationship="depends-on")
    )
    with pytest.raises(ValueError, match="invalid graph"):
        build_security_graph(bad_bom)

    runner = CliRunner()
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{bad", encoding="utf-8")
    assert runner.invoke(main, ["security-graph", str(bad_file)]).exit_code != 0

    inv_dir = tmp_path / "inv"
    inv_dir.mkdir()
    bom_path = inv_dir / "full.json"
    bom.save(bom_path)
    inv_sha = hash_bytes(bom_path.read_bytes())
    assert runner.invoke(main, ["security-graph", str(bom_path), "--fail-on-chain"]).exit_code == 1

    trace_dir = tmp_path / "outside"
    trace_dir.mkdir()
    trace_file = trace_dir / "trace.json"
    trace_file.write_text(
        json.dumps(
            {
                "inventory_sha256": inv_sha,
                "reconciliation": {"matched": [{"inventory_ref": "agent:support-bot"}]},
            }
        ),
        encoding="utf-8",
    )
    assert (
        runner.invoke(
            main, ["security-graph", str(bom_path), "--trace-evidence", str(trace_file)]
        ).exit_code
        != 0
    )
    ok_trace = runner.invoke(
        main,
        [
            "security-graph",
            str(bom_path),
            "--trace-evidence",
            str(trace_file),
            "--allow-unsigned-trace-evidence",
        ],
    )
    assert ok_trace.exit_code == 0, ok_trace.output
    assert json.loads(ok_trace.output)["trace_evidence_sha256"] is not None

    bad_graph_payload = json.loads(bom.to_native_json())
    bad_graph_payload["dependencies"].append(
        {"source_ref": "missing-a", "target_ref": "missing-b", "relationship": "depends-on"}
    )
    bad_graph_path = tmp_path / "bad_graph.json"
    bad_graph_path.write_text(json.dumps(bad_graph_payload), encoding="utf-8")
    assert runner.invoke(main, ["security-graph", str(bad_graph_path)]).exit_code != 0


def test_security_graph_audit_regressions_kev_truncation_escaping_and_epss_zero() -> None:
    from nexus_symbiote.security_graph import _parse_epss

    # EPSS 0.0 inside a dict is preserved (not treated as falsy None) and non-recursive.
    assert _parse_epss({"score": 0.0}) == 0.0
    assert _parse_epss({"score": {"score": 0.5}}) is None

    # KEV chain cannot be hidden by max_chains=1 even when non-KEV critical risks exist,
    # and Mermaid/Markdown escape HTML/pipe characters cleanly.
    bom = _sample_bom()
    bom.components[0].risks.extend(
        [
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="known_vulnerability",
                detail="lower first",
            ),
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="known_vulnerability",
                detail="higher second",
            ),
        ]
    )
    bom.components[1].name = "srv|<img src=x onerror=alert(1)>"
    report = build_security_graph(bom, max_chains=1)
    assert report.kev_chain_count == 1
    assert report.chains[0].kev is True

    # Contiguous hop check: every consecutive hop shares an endpoint.
    for i in range(len(report.chains[0].hops) - 1):
        assert report.chains[0].hops[i].target_ref == report.chains[0].hops[i + 1].source_ref

    mermaid = render_security_graph_mermaid(report)
    assert "<img" not in mermaid
    md = render_security_graph_markdown(report)
    assert "<img" not in md
