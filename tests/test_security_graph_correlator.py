"""Tests for unified security graph correlation and agent manifest identity/egress fields."""

from __future__ import annotations

import json
from itertools import permutations
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


def test_unknown_advisory_severity_remains_unknown_in_the_report() -> None:
    component = MCPServerComponent(
        name="example",
        bom_ref="server:example",
        properties={
            "advisories": [
                {"id": "example-unscored", "severity": "unknown"},
                {"id": "example-scored", "severity": "info"},
            ]
        },
    )
    bom = AIBOM(components=[component])
    report = build_security_graph(bom)
    assert [(chain.trigger_id, chain.severity) for chain in report.chains] == [
        ("example-scored", "info"),
        ("example-unscored", "unknown"),
    ]
    assert report.to_dict()["severity_counts"] == {"info": 1, "unknown": 1}
    assert build_security_graph(bom, max_chains=1).chains_omitted == 1


def test_bridge_aliases_merge_across_sources_and_orders_with_component_isolation() -> None:
    cve = "CVE-2026-0001"
    ghsa = "GHSA-example"
    records = [
        {"id": cve, "severity": "unknown", "in_kev": True},
        {"id": ghsa, "severity": "high", "epss": 0.15},
        {"id": "OSV-example", "aliases": [ghsa, cve], "severity": "low", "epss": 0.85},
    ]
    primary = MCPServerComponent(name="example", bom_ref="server:example")
    other = MCPServerComponent(
        name="other",
        bom_ref="server:other",
        properties={"advisories": [{"id": cve, "severity": "low"}]},
    )
    bom = AIBOM(components=[primary, other])
    chain_ids = set()
    for order in permutations(records):
        for native_count in range(len(records) + 1):
            primary.properties["advisories"] = list(order[:native_count])
            receipt = LoadedAdvisoryReport(
                advisories=[
                    dict(row, component_ref=primary.bom_ref) for row in order[native_count:]
                ],
                sha256="sha256:" + "a" * 64,
                coverage="complete",
                checked=1,
                skipped=0,
                excluded=0,
                errors=0,
            )
            report = build_security_graph(bom, advisory_report=receipt)
            assert (report.chain_count, report.kev_chain_count, report.chains_omitted) == (2, 1, 0)
            linked, unrelated = report.chains
            chain_ids.add(linked.chain_id)
            assert (
                linked.subject_ref,
                linked.trigger_id,
                linked.severity,
                linked.kev,
                linked.epss,
            ) == (primary.bom_ref, cve, "high", True, 0.85)
            source = "advisory-report" if receipt.advisories else "inventory-property"
            assert linked.hops[0].evidence_method == source
            assert (
                unrelated.subject_ref,
                unrelated.trigger_id,
                unrelated.severity,
                unrelated.kev,
            ) == (other.bom_ref, cve, "low", False)
    assert len(chain_ids) == 1


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


def test_markdown_cells_keep_supplied_link_and_image_syntax_inert() -> None:
    from html.parser import HTMLParser

    import markdown_it

    samples = [
        ("https://docs.example.invalid/guide?a=1&b=2", "data:url-docs"),
        ("![x](https://beacon.example.invalid/p.png)", "data:[docs](https://example.invalid/)"),
        ("\\![y](https://beacon.example.invalid/q.png)", "data:a|b\\|c"),
        ("*bold* _italic_ ~del~ `code` &copy; &#65;", "data:`edge`"),
    ]
    bom = AIBOM()
    for index, (advisory_id, subject_ref) in enumerate(samples):
        bom.components.append(
            DataSourceComponent(
                name=f"docs-{index}",
                bom_ref=subject_ref,
                properties={"advisories": [{"id": advisory_id, "severity": "high"}]},
            )
        )
    md = render_security_graph_markdown(build_security_graph(bom))

    class _CellParser(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.rows: list[list[tuple[str, list[str]]]] = []
            self._row: list[tuple[str, list[str]]] | None = None
            self._in_td = False
            self._text: list[str] = []
            self._tags: list[str] = []

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag == "tr":
                self._row = []
            elif tag == "td":
                self._in_td = True
                self._text = []
                self._tags = []
            elif self._in_td:
                self._tags.append(tag)

        def handle_endtag(self, tag: str) -> None:
            if tag == "td" and self._row is not None:
                self._in_td = False
                self._row.append(("".join(self._text), list(self._tags)))
            elif tag == "tr" and self._row:
                self.rows.append(self._row)
                self._row = None

        def handle_data(self, data: str) -> None:
            if self._in_td:
                self._text.append(data)

    from nexus_symbiote.security_graph import _md_cell

    assert _md_cell("") == ""
    assert _md_cell(" ") == "` `"
    assert _md_cell(" x ") == "`  x  `"

    renderer = markdown_it.MarkdownIt("gfm-like", {"linkify": False})
    rendered_html = renderer.render(md)
    parser = _CellParser()
    parser.feed(rendered_html)

    assert len(parser.rows) == len(samples)
    by_trigger: dict[str, str] = {}
    for row in parser.rows:
        assert len(row) == 7
        trigger_text, trigger_tags = row[1]
        subject_text, subject_tags = row[2]
        # Only inert <code> wrappers are permitted; never <a>, <img>, <em>, <del>, etc.
        assert trigger_tags == ["code"]
        assert subject_tags == ["code"]
        by_trigger[trigger_text] = subject_text
    assert by_trigger == dict(samples)


def test_component_scoping_precedes_global_limit_and_counts_scoped_omissions(
    tmp_path: Path,
) -> None:
    bom = AIBOM()
    for ref, count, severity in (("local", 501, "low"), ("unrelated", 501, "critical")):
        bom.components.append(
            DataSourceComponent(
                name=ref,
                bom_ref=ref,
                properties={
                    "advisories": [{"id": f"{ref}-{i}", "severity": severity} for i in range(count)]
                },
            )
        )
    path = tmp_path / "inventory.json"
    bom.save(path)
    advisory = tmp_path / "advisories.json"
    advisory.write_text(
        json.dumps(
            {
                "inventory_sha256": hash_bytes(path.read_bytes()),
                "coverage": "complete",
                "complete": True,
                "dry_run": False,
                "components_checked": 2,
                "components_skipped": 0,
                "components_excluded": 0,
                "errors": [],
                "advisories": [],
            }
        )
    )
    result = CliRunner().invoke(
        main, ["blast-radius", str(path), "local", "--advisories", str(advisory), "--json-output"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert len(data["correlated_chains"]) == 500
    assert {c["subject_ref"] for c in data["correlated_chains"]} == {"local"}
    assert data["correlated_chains_omitted"] == 1
    assert data["correlation_traversal_complete"] is True
    assert any("1 lower-priority chain(s) omitted" in note for note in data["limitations"])


def test_runtime_intermediate_evidence_and_unrelated_negative_control() -> None:
    from dataclasses import replace

    bom = _sample_bom()
    trace = ExecutionEvidence(
        invoked_refs=frozenset({"mcp:server:remote-bridge"}),
        declared_never_loaded_refs=frozenset(),
        unobserved_refs=frozenset(),
        shadowed_refs=frozenset(),
        sha256="sha256:" + "e" * 64,
    )

    def advisory_chain(evidence: ExecutionEvidence):
        return next(
            chain
            for chain in build_security_graph(bom, execution_evidence=evidence).chains
            if chain.kev
        )

    chain = advisory_chain(trace)
    assert any(h.target_ref == "mcp:server:remote-bridge" for h in chain.hops[1:-1])
    assert chain.runtime_status == "reported:invoked"
    assert (
        advisory_chain(replace(trace, invoked_refs=frozenset({"other"}))).runtime_status
        == "reported:unobserved"
    )


def test_workload_declarations_are_safe_at_collection_and_import(tmp_path: Path) -> None:
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

    # Inert marker uses a recognizable provider prefix. No real credential is involved.
    sample = "ghp_" + "Example123" * 4
    fields = {
        "spiffe_id": f"spiffe://corp.example/workload/{sample}",
        "egress_domains": [f"sk-{'1234567890' * 3}.example.com"],
        "delegates_to": [f"team:{sample}"],
    }
    for field, value in fields.items():
        (tmp_path / "agent.yaml").write_text(json.dumps({"name": "team", field: value}))
        bom = AIBOM()
        failures: list[str] = []
        assembled = assemble_repository_agent(bom, tmp_path, failures=failures)
        assert failures
        assert f"declared_{field}" not in assembled.properties
        assert str(value) not in str(failures)
        marker = value if isinstance(value, str) else value[0]
        assert marker not in bom.to_native_json()
        assert marker not in json.dumps(CycloneDXGenerator().generate(bom))

    bom = _sample_bom()
    agent = next(comp for comp in bom.components if comp.bom_ref == "agent:support-bot")
    agent.properties.update({f"declared_{field}": value for field, value in fields.items()})
    graph = build_security_graph(bom)
    radius = blast_radius(bom, agent.bom_ref)
    assert not radius["declared_workload_identities"]
    assert not radius["declared_egress_domains"]
    assert not radius["declared_delegations"]
    assert not any(chain.workload_identities or chain.egress_domains for chain in graph.chains)
    assert sample not in render_security_graph_json(graph)


def test_subject_work_is_shared_and_traversal_limits_are_reported(monkeypatch) -> None:
    from nexus_symbiote import security_graph as graph

    bom = _sample_bom()
    ref = "pkg:npm/mcp-remote@0.1.15"
    bom.components[0].properties["advisories"].extend(
        {"id": f"example-{n}", "severity": "high"} for n in range(60)
    )
    paths = graph._WalkBudget.paths
    examined: list[int] = []

    def count(self, *args, **kwargs):
        before = self.remaining
        result = paths(self, *args, **kwargs)
        examined.append(before - self.remaining)
        return result

    monkeypatch.setattr(graph._WalkBudget, "paths", count)
    report = build_security_graph(bom, subject_refs={ref}, max_chains=1)
    assert len(examined) == 3
    assert report.traversal_complete
    assert report.chains_omitted == 60
    assert report.kev_chain_count == 1
    assert report.chains[0].kev
    for subject_limit, report_limit in ((2, 100), (100, 2)):
        examined.clear()
        monkeypatch.setattr(graph, "MAX_SUBJECT_EDGE_VISITS", subject_limit)
        monkeypatch.setattr(graph, "MAX_REPORT_EDGE_VISITS", report_limit)
        partial = build_security_graph(bom, subject_refs={ref}, max_chains=1)
        assert sum(examined) == min(subject_limit, report_limit)
        assert partial.to_dict()["traversal_complete"] is False
        assert partial.chains_omitted == 60
        assert partial.kev_chain_count == 1
        assert partial.chains[0].kev
        assert any("Traversal incomplete" in note for note in partial.limitations)
        assert "Partial view" in render_security_graph_mermaid(partial)


def test_component_identity_assurance_does_not_promote_static_reference_hops() -> None:
    from nexus_symbiote.core.models import ClaimEvidence

    pkg = RegistryEntryComponent(
        bom_ref="pkg:npm/observed-pkg@1.0.0",
        name="observed-pkg",
        version="1.0.0",
        registry_type="npm",
        assurance_level=AssuranceLevel.OBSERVED,
        source_path="package-lock.json",
        properties={"advisories": [{"id": "CVE-2026-4242", "severity": "high"}]},
    )
    server = MCPServerComponent(
        bom_ref="mcp:server:obs",
        name="obs-server",
        command="npx",
        args=["observed-pkg@1.0.0"],
        assurance_level=AssuranceLevel.OBSERVED,
        source_path=".mcp.json",
        claims={
            "identity": ClaimEvidence(
                assurance=AssuranceLevel.OBSERVED,
                method="file-digest",
                scope="repository",
                locator=".mcp.json",
            )
        },
        properties={"upstream_server_refs": ["mcp:server:upstream"]},
    )
    upstream = MCPServerComponent(
        bom_ref="mcp:server:upstream",
        name="upstream-server",
        command="npx",
        args=["upstream@1.0.0"],
        assurance_level=AssuranceLevel.OBSERVED,
        source_path=".mcp.json",
    )
    tool = ToolComponent(
        bom_ref="tool:obs:run",
        name="run",
        mcp_server_ref="mcp:server:obs",
        assurance_level=AssuranceLevel.OBSERVED,
        source_path=".mcp.json",
        claims={
            "tool_definition": ClaimEvidence(
                assurance=AssuranceLevel.OBSERVED,
                method="descriptor-digest",
                scope="repository",
                locator=".mcp.json",
            )
        },
        risks=[
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="tool_description_poisoning",
                detail="Hidden directive.",
            )
        ],
    )
    sink = DataSourceComponent(
        bom_ref="data:obs-sink",
        name="obs-sink",
        assurance_level=AssuranceLevel.OBSERVED,
        source_path="rag.yaml",
    )
    agent = AgentComponent(
        bom_ref="agent:obs-agent",
        name="obs-agent",
        assurance_level=AssuranceLevel.OBSERVED,
        tool_refs=["mcp:server:obs", "tool:obs:run"],
        data_refs=["data:obs-sink"],
        source_path="agent.yaml",
        claims={
            "identity": ClaimEvidence(
                assurance=AssuranceLevel.OBSERVED,
                method="file-digest",
                scope="repository",
                locator="agent.yaml",
            ),
            "data_refs": ClaimEvidence(
                assurance=AssuranceLevel.OBSERVED,
                method="relationship-evidence",
                scope="deployment",
                locator="trace.json",
            ),
        },
    )
    bom = AIBOM(components=[pkg, server, upstream, tool, sink, agent])
    bom.add_dependency(
        DependencyEdge(
            source_ref="mcp:server:obs",
            target_ref="pkg:npm/observed-pkg@1.0.0",
            relationship="registered-as",
            assurance_level="observed",
        )
    )

    report = build_security_graph(bom)
    adv_chain = next(c for c in report.chains if c.trigger_id == "CVE-2026-4242")
    by_method = {(h.evidence_method, h.relationship): h for h in adv_chain.hops}
    # Explicit DependencyEdge relationship assurance is preserved.
    assert by_method[("bom-dependency-edge", "reaches-via:registered-as")].assurance == "observed"
    # Static component-reference hop (tool_refs without a relationship claim) MUST stay declared
    # even though agent.assurance_level is OBSERVED.
    assert by_method[("component-reference", "reaches-via:tool_refs")].assurance == "declared"
    # Field-specific relationship claim on data_refs IS honored with its own locator.
    data_hop = by_method[("component-reference", "data_refs")]
    assert data_hop.assurance == "observed"
    assert data_hop.source_locator == "trace.json"

    # Finding trigger hop on an observed-identity tool stays declared, and static mcp_server_ref
    # / upstream_server_refs stay declared without relationship-specific claims.
    finding_chain = next(c for c in report.chains if c.trigger_kind == "finding")
    assert finding_chain.hops[0].assurance == "declared"
    for hop in finding_chain.hops:
        if hop.evidence_method in ("component-reference", "mcp-gateway-upstream") and (
            hop.relationship != "data_refs"
        ):
            assert hop.assurance == "declared"
