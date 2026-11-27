"""Tests for the assurance-tiered multi-hop security exposure graph and CLI."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    CapabilityClass,
    RiskSeverity,
    TrustTier,
)
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    ClaimEvidence,
    MCPServerComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.security_graph import (
    FORMAT,
    SecurityGraphError,
    correlate_security_graph,
    extract_credential_surfaces,
    render_security_graph_html,
)


def _build_demo_bom() -> AIBOM:
    pkg = RegistryEntryComponent(
        bom_ref="pkg:npm/@vendor/mcp-sql@1.2.0",
        name="@vendor/mcp-sql",
        version="1.2.0",
        registry_type="npm",
        package_url="pkg:npm/%40vendor/mcp-sql@1.2.0",
        source_path="package-lock.json",
        assurance_level=AssuranceLevel.OBSERVED,
        claims={
            "version": ClaimEvidence(
                assurance=AssuranceLevel.OBSERVED,
                method="npm-lockfile-v3",
                scope="file",
                collector="registry",
                locator="package-lock.json:42",
            )
        },
    )
    pkg_mismatch = RegistryEntryComponent(
        bom_ref="pkg:npm/other-mcp@2.0.0",
        name="other-mcp",
        version="2.0.0",
        registry_type="npm",
        package_url="pkg:npm/other-mcp@2.0.0",
        source_path="package-lock.json",
    )
    pkg_unpinned = RegistryEntryComponent(
        bom_ref="pkg:npm/floating-mcp",
        name="floating-mcp",
        version="latest",
        registry_type="npm",
        source_path="package.json",
    )
    mcp_srv = MCPServerComponent(
        bom_ref="mcp-server:sql-bridge",
        name="sql-bridge",
        version="1.2.0",
        version_pinned=True,
        transport="stdio",
        launcher_package="npm:@vendor/mcp-sql",
        package_url="pkg:npm/%40vendor/mcp-sql@1.2.0",
        source_path=".mcp.json",
        env={"POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}", "SAFE_LOCALE": "en_US"},
        properties={
            "header_names": ["X-Api-Key", "Accept"],
            "env_vars_referenced": ["GITHUB_TOKEN"],
            "declaration_line": 10,
        },
    )
    gateway_srv = MCPServerComponent(
        bom_ref="mcp-server:gateway",
        name="gateway",
        version="1.0.0",
        version_pinned=True,
        transport="sse",
        endpoint_url="https://mcp.example.com/sse",
        launcher_package="npm:other-mcp",
        source_path=".cursor/mcp.json",
        properties={
            "upstream_server_refs": ["mcp-server:sql-bridge"],
            "credential_env_vars": ["ANTHROPIC_API_KEY"],
        },
    )
    floating_srv = MCPServerComponent(
        bom_ref="mcp-server:floating",
        name="floating",
        version=None,
        version_pinned=None,
        transport="stdio",
        launcher_package="npm:floating-mcp",
        package_url="pkg:npm/floating-mcp@0.1.0",
        source_path=".mcp.json",
        properties={"headers": {"Authorization-Token": "REDACTED"}},
        risks=[
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="launch_context",
                detail="MCP launch uses unrestricted sandbox.",
            )
        ],
    )
    clean_exec_tool = ToolComponent(
        bom_ref="tool:run-query",
        name="run_query",
        description_text="Execute SQL statements against warehouse.",
        mcp_server_ref="mcp-server:sql-bridge",
        source_path=".mcp.json",
        trust_tier=TrustTier.INTERNAL_VERIFIED,
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.EXECUTE, CapabilityClass.NETWORK],
        ),
    )
    poisoned_tool = ToolComponent(
        bom_ref="tool:shadow-query",
        name="run_query",
        description_text="Shadowed and poisoned tool.",
        mcp_server_ref="mcp-server:floating",
        source_path=".cursor/mcp.json",
        trust_tier=TrustTier.UNTRUSTED_PUBLIC,
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM],
        ),
        risks=[
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="tool_description_poisoning",
                detail="Tool description contains hidden override tag.",
            )
        ],
    )
    rag = RAGSourceComponent(
        bom_ref="rag:customer-kb",
        name="customer-kb",
        corpus_type="vector-store",
        source_path="rag.yaml",
    )
    a2a_srv = A2AServerComponent(
        bom_ref="a2a-server:billing",
        name="billing-peer",
        endpoint_url="https://billing.example.com",
        authentication_required=True,
        properties={"authentication_schemes": ["OAuth2"]},
        source_path="agent-card.json",
    )
    a2a_cli = A2AClientComponent(
        bom_ref="a2a-client:caller",
        name="billing-caller",
        agent_card_url="https://billing.example.com",
        authentication_methods=["mTLS"],
    )
    agent = AgentComponent(
        bom_ref="agent:repo",
        name="triage-agent",
        workload_identity="spiffe://prod.example/ns/ai/sa/triage-workload",
        source_path="agent.yaml",
        tool_refs=[
            "mcp-server:gateway",
            "mcp-server:floating",
            "tool:run-query",
            "tool:shadow-query",
        ],
        data_refs=["rag:customer-kb"],
        authorizations=[
            AuthorizationRecord(
                principal="spiffe://prod.example/ns/ai/sa/triage",
                resource_scope="table:billing.invoices",
                action="read",
            )
        ],
    )
    bom = AIBOM(
        components=[
            pkg,
            pkg_mismatch,
            pkg_unpinned,
            mcp_srv,
            gateway_srv,
            floating_srv,
            clean_exec_tool,
            poisoned_tool,
            rag,
            a2a_srv,
            a2a_cli,
            agent,
        ],
        dependencies=[
            DependencyEdge(
                source_ref="mcp-server:sql-bridge",
                target_ref="pkg:npm/@vendor/mcp-sql@1.2.0",
                relationship="registered-as",
                assurance_level="declared",
                conditions="launcher package matches lockfile entry",
            ),
            DependencyEdge(
                source_ref="mcp-server:gateway",
                target_ref="pkg:npm/other-mcp@2.0.0",
                relationship="registered-as",
                assurance_level="declared",
            ),
            DependencyEdge(
                source_ref="mcp-server:floating",
                target_ref="pkg:npm/floating-mcp",
                relationship="registered-as",
                assurance_level="declared",
            ),
            DependencyEdge(
                source_ref="agent:repo",
                target_ref="a2a-server:billing",
                relationship="configured-with",
                assurance_level="declared",
            ),
            DependencyEdge(
                source_ref="agent:repo",
                target_ref="a2a-client:caller",
                relationship="configured-with",
                assurance_level="declared",
            ),
        ],
    )
    return bom


def _write_advisory_report(path: Path, inv_sha: str, *, complete: bool = True) -> None:
    report = {
        "components_checked": 2,
        "components_skipped": 0,
        "components_excluded": 0,
        "errors": [] if complete else ["timeout on registry"],
        "dry_run": False,
        "coverage": "complete" if complete else "partial",
        "complete": complete,
        "inventory_sha256": inv_sha,
        "advisories": [
            {
                "advisory_id": "GHSA-9999-aaaa-bbbb",
                "aliases": ["CVE-2026-4242"],
                "severity": "high",
                "in_kev": True,
                "kev_sources": ["CISA-KEV"],
                "epss_score": 0.91234,
                "component_ref": "pkg:npm/@vendor/mcp-sql@1.2.0",
                "package_url": "pkg:npm/%40vendor/mcp-sql@1.2.0",
            },
            {
                "advisory_id": "GHSA-9999-aaaa-bbbb",
                "aliases": ["OSV-2026-1"],
                "severity": "critical",
                "in_kev": False,
                "kev_sources": [],
                "epss_score": 0.95,
                "component_ref": "pkg:npm/@vendor/mcp-sql@1.2.0",
                "package_url": "pkg:npm/%40vendor/mcp-sql@1.2.0",
            },
        ],
    }
    path.write_text(json.dumps(report), encoding="utf-8")


def test_correlates_cve_kev_and_poisoned_tool_to_agent_credentials_and_data(tmp_path: Path) -> None:
    bom = _build_demo_bom()
    bom.components[1].properties["advisories"] = [
        {
            "id": "CVE-2026-7777",
            "aliases": ["GHSA-1111-2222-3333"],
            "severity": "medium",
            "in_kev": False,
            "epss_score": 0.12,
            "purl": "pkg:npm/other-mcp@2.0.0",
        }
    ]
    bom_file = tmp_path / "bom.json"
    bom.save(bom_file)
    inv_sha = hash_bytes(bom_file.read_bytes())

    adv_dir = tmp_path / "outside"
    adv_dir.mkdir()
    adv_file = adv_dir / "advisories.json"
    _write_advisory_report(adv_file, inv_sha)

    doc = correlate_security_graph(
        bom,
        inventory_sha256=inv_sha,
        advisories_path=adv_file,
        inventory_path=bom_file,
    )
    assert doc["format"] == FORMAT
    assert doc["summary"]["advisory_count"] == 2
    assert doc["summary"]["kev_advisory_count"] == 1
    assert doc["summary"]["poisoned_component_count"] == 1
    assert doc["summary"]["shadowed_tool_count"] >= 1

    # Verify version_agreement across exact-match, version-mismatch, and unpinned edges
    agreements = {
        (e["source_ref"], e["target_ref"]): e["version_agreement"]
        for e in doc["edges"]
        if e["relationship"] == "registered-as"
    }
    assert agreements[("mcp-server:sql-bridge", "pkg:npm/@vendor/mcp-sql@1.2.0")] == "exact-match"
    assert agreements[("mcp-server:gateway", "pkg:npm/other-mcp@2.0.0")] == "version-mismatch"
    assert agreements[("mcp-server:floating", "pkg:npm/floating-mcp")] == "unpinned"

    # Verify multi-hop CVE -> Package -> MCP Server -> Gateway -> Agent -> Credentials/Data/Tools
    kev_chains = [
        c for c in doc["exposure_chains"] if c["entry_ref"] == "advisory:GHSA-9999-aaaa-bbbb"
    ]
    assert len(kev_chains) == 1
    chain = kev_chains[0]
    assert chain["in_kev"] is True
    assert chain["severity"] == "critical"
    assert chain["epss_score"] == 0.95
    assert chain["package_refs"] == ["pkg:npm/@vendor/mcp-sql@1.2.0"]
    assert "mcp-server:sql-bridge" in chain["mcp_server_refs"]
    assert chain["agent_ref"] == "agent:repo"
    assert set(chain["reachable_credentials"]) >= {
        "env:ANTHROPIC_API_KEY",
        "env:GITHUB_TOKEN",
        "env:POSTGRES_PASSWORD",
        "mcp-header:X-Api-Key",
        "auth-scheme:OAuth2",
        "auth-scheme:mTLS",
        "principal:spiffe://prod.example/ns/ai/sa/triage",
    }
    assert "${POSTGRES_PASSWORD}" not in json.dumps(doc)
    assert chain["reachable_data_stores"] == ["rag:customer-kb"]
    assert "tool:run-query" in chain["reachable_high_risk_tools"]

    # Verify control-plane poisoning/shadowing chain also correlated
    cp_chains = [c for c in doc["exposure_chains"] if c["kind"] == "control_plane_exposure"]
    assert any(c["entry_ref"] == "tool:shadow-query" for c in cp_chains)

    # Verify CSP-pinned HTML rendering has matching SHA-256 hashes and no raw unescaped text
    html_text = render_security_graph_html(doc)
    assert "Content-Security-Policy" in html_text
    assert "GHSA-9999-aaaa-bbbb" in html_text
    style_body = html_text.split("<style>", 1)[1].split("</style>", 1)[0]
    script_body = html_text.split("<script>", 1)[1].split("</script>", 1)[0]
    for block in (style_body, script_body):
        b64 = hashlib.sha256(block.encode("utf-8")).digest()
        import base64

        assert base64.b64encode(b64).decode("ascii") in html_text


def test_security_graph_cli_modes_and_fail_closed_gates(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    bom = _build_demo_bom()
    bom_file = out_dir / "bom.json"
    bom.save(bom_file)
    inv_sha = hash_bytes(bom_file.read_bytes())

    adv_file = out_dir / "adv.json"
    _write_advisory_report(adv_file, inv_sha, complete=True)
    partial_adv = out_dir / "partial-adv.json"
    _write_advisory_report(partial_adv, inv_sha, complete=False)

    runner = CliRunner()

    # HTML without -o fails usage check
    res_no_out = runner.invoke(main, ["security-graph", str(bom_file), "--format", "html"])
    assert res_no_out.exit_code == 2

    # Partial advisories fail closed without --allow-partial-advisories
    res_partial = runner.invoke(
        main, ["security-graph", str(bom_file), "--advisories", str(partial_adv)]
    )
    assert res_partial.exit_code == 1
    assert "--allow-partial-advisories" in res_partial.output

    # Partial advisories succeed when explicitly accepted
    res_partial_ok = runner.invoke(
        main,
        [
            "security-graph",
            str(bom_file),
            "--advisories",
            str(partial_adv),
            "--allow-partial-advisories",
        ],
    )
    assert res_partial_ok.exit_code == 0, res_partial_ok.output
    assert json.loads(res_partial_ok.stdout)["coverage"]["advisory_status"] == "partial"

    # Advisory report placed inside --project-root is refused
    in_repo_adv = project / "adv.json"
    _write_advisory_report(in_repo_adv, inv_sha, complete=True)
    res_inside = runner.invoke(
        main,
        [
            "security-graph",
            str(bom_file),
            "--advisories",
            str(in_repo_adv),
            "--project-root",
            str(project),
        ],
    )
    assert res_inside.exit_code == 1

    # HTML output + --fail-on-kev exits 1 while writing valid HTML
    html_out = out_dir / "sec-graph.html"
    res_kev = runner.invoke(
        main,
        [
            "security-graph",
            str(bom_file),
            "--advisories",
            str(adv_file),
            "--project-root",
            str(project),
            "--format",
            "html",
            "-o",
            str(html_out),
            "--fail-on-kev",
        ],
    )
    assert res_kev.exit_code == 1
    assert html_out.is_file()
    assert "Security graph:" in res_kev.stderr

    # Usage validation for orphan flags
    assert (
        runner.invoke(
            main, ["security-graph", str(bom_file), "--allow-partial-advisories"]
        ).exit_code
        == 2
    )
    assert (
        runner.invoke(
            main, ["security-graph", str(bom_file), "--project-root", str(project)]
        ).exit_code
        == 2
    )


def test_security_graph_validation_errors_fail_closed() -> None:
    bom = _build_demo_bom()
    with pytest.raises(SecurityGraphError, match="max_nodes"):
        correlate_security_graph(bom, max_nodes=0)
    with pytest.raises(SecurityGraphError, match="exceeding --max-nodes"):
        correlate_security_graph(bom, max_nodes=2)

    # Dangling edge fails closed
    bad_bom = AIBOM(
        components=[AgentComponent(bom_ref="agent:a", name="a")],
        dependencies=[
            DependencyEdge(
                source_ref="agent:a", target_ref="missing:ref", relationship="depends-on"
            )
        ],
    )
    with pytest.raises(SecurityGraphError, match="Invalid inventory graph"):
        correlate_security_graph(bad_bom)

    # Malformed embedded advisory fields fail closed
    for bad_adv in (
        {"id": ""},
        {"id": "CVE-1", "aliases": "not-a-list"},
        {"id": "CVE-1", "aliases": ["bad,comma"]},
        {"id": "CVE-1", "in_kev": "yes"},
        {"id": "CVE-1", "kev_sources": [123]},
        {"id": "CVE-1", "epss_score": 1.5},
        {"id": "CVE-1", "epss_score": float("inf")},
    ):
        comp = RegistryEntryComponent(
            bom_ref="pkg:pypi/demo@1.0.0",
            name="demo",
            version="1.0.0",
            registry_type="pypi",
            properties={"advisories": [bad_adv]},
        )
        with pytest.raises(SecurityGraphError):
            correlate_security_graph(AIBOM(components=[comp]))

    # Unknown severity normalizes cleanly, missing advisory target is ignored, empty HTML renders
    ok_comp = RegistryEntryComponent(
        bom_ref="pkg:pypi/clean@1.0.0",
        name="clean",
        version=None,
        registry_type="pypi",
        claims={
            "name": ClaimEvidence(
                assurance=AssuranceLevel.DECLARED,
                method="requirements-txt",
                scope="file",
                collector="registry",
                locator="",
            )
        },
        properties={"advisories": [{"id": "CVE-2026-0001", "severity": "unusual"}]},
    )
    isolated_agent = AgentComponent(bom_ref="agent:iso", name="iso")
    clean_doc = correlate_security_graph(AIBOM(components=[ok_comp, isolated_agent]))
    assert clean_doc["summary"]["exposure_chain_count"] == 0
    empty_html = render_security_graph_html(clean_doc)
    assert "No correlated exposure chains recorded." in empty_html

    # Forward-compatible credential component surface extraction and edge cases
    dummy = AgentComponent(bom_ref="agent:x", name="OPENAI_API_KEY")
    assert extract_credential_surfaces(dummy) == ()

    unpinned_srv = MCPServerComponent(
        bom_ref="mcp-server:unpinned-explicit",
        name="unpinned-explicit",
        version_pinned=False,
        claims={
            "command": ClaimEvidence(
                assurance=AssuranceLevel.DECLARED,
                method="mcp-json",
                scope="file",
                collector="mcp",
                locator=".mcp.json:3",
            )
        },
    )
    unpinned_pkg = RegistryEntryComponent(
        bom_ref="pkg:npm/u@1.0.0", name="u", version="1.0.0", registry_type="npm"
    )
    edge_bom = AIBOM(
        components=[unpinned_srv, unpinned_pkg],
        dependencies=[
            DependencyEdge(
                source_ref="mcp-server:unpinned-explicit",
                target_ref="pkg:npm/u@1.0.0",
                relationship="registered-as",
            )
        ],
    )
    edge_doc = correlate_security_graph(edge_bom)
    assert edge_doc["edges"][0]["version_agreement"] == "unpinned"
    assert edge_doc["edges"][0]["evidence_method"] == "mcp-json"


def test_security_graph_cli_invalid_inventory_and_fail_on_chain(tmp_path: Path) -> None:
    runner = CliRunner()
    bad_file = tmp_path / "broken.json"
    bad_file.write_bytes(b"\xff\xfeinvalid")
    res_bad = runner.invoke(main, ["security-graph", str(bad_file)])
    assert res_bad.exit_code == 1
    assert "not a valid native AIBOM file" in res_bad.output

    bom = _build_demo_bom()
    bom_file = tmp_path / "bom.json"
    bom.save(bom_file)
    link_bom = tmp_path / "link_bom.json"
    link_bom.symlink_to(bom_file)
    res_link = runner.invoke(main, ["security-graph", str(link_bom)])
    assert res_link.exit_code == 1
    assert "not a valid native AIBOM file" in res_link.output
    res_chain = runner.invoke(main, ["security-graph", str(bom_file), "--fail-on-chain"])
    assert res_chain.exit_code == 1

    # Malformed UTF-8 / invalid JSON --advisories fails cleanly as SecurityGraphError (not internal crash)
    bad_adv_file = tmp_path / "bad_adv.json"
    bad_adv_file.write_bytes(b"\xff\xfe{not-json")
    res_bad_adv = runner.invoke(
        main, ["security-graph", str(bom_file), "--advisories", str(bad_adv_file)]
    )
    assert res_bad_adv.exit_code == 1
    assert "not valid strict UTF-8 JSON" in res_bad_adv.output

    # Standard Authorization/Cookie headers are captured, PEP 440 2-part versions match,
    # non-list properties.advisories fails closed, and mcp_server_ref propagates forward reach
    pep_pkg = RegistryEntryComponent(
        bom_ref="pkg:pypi/packaging@24.2",
        name="packaging",
        version="24.2",
        registry_type="pypi",
    )
    auth_srv = MCPServerComponent(
        bom_ref="mcp-server:auth-srv",
        name="auth-srv",
        version="24.2",
        version_pinned=True,
        properties={"header_names": ["Authorization", "Cookie"]},
    )
    ref_only_tool = ToolComponent(
        bom_ref="tool:exec-only",
        name="exec_only",
        mcp_server_ref="mcp-server:auth-srv",
        capabilities=CapabilityDeclaration(capabilities=[CapabilityClass.EXECUTE]),
        risks=[
            RiskAssessment(
                category="tool_description_poisoning",
                severity=RiskSeverity.HIGH,
                detail="poisoned",
            )
        ],
    )
    ag = AgentComponent(
        bom_ref="agent:pep",
        name="pep-agent",
    )
    pep_bom = AIBOM(
        components=[pep_pkg, auth_srv, ref_only_tool, ag],
        dependencies=[
            DependencyEdge(
                source_ref="mcp-server:auth-srv",
                target_ref="pkg:pypi/packaging@24.2",
                relationship="registered-as",
            ),
            DependencyEdge(
                source_ref="agent:pep",
                target_ref="mcp-server:auth-srv",
                relationship="configured-with",
            ),
        ],
    )
    pep_doc = correlate_security_graph(pep_bom)
    reg_edge = next(e for e in pep_doc["edges"] if e["relationship"] == "registered-as")
    assert reg_edge["version_agreement"] == "exact-match"
    assert pep_doc["exposure_chains"][0]["reachable_credentials"] == [
        "mcp-header:Authorization",
        "mcp-header:Cookie",
    ]
    assert pep_doc["exposure_chains"][0]["reachable_high_risk_tools"] == ["tool:exec-only"]

    bad_prop_pkg = RegistryEntryComponent(
        bom_ref="pkg:pypi/bad@1.0.0",
        name="bad",
        version="1.0.0",
        registry_type="pypi",
        properties={"advisories": "not-a-list"},
    )
    with pytest.raises(SecurityGraphError, match="list of objects"):
        correlate_security_graph(AIBOM(components=[bad_prop_pkg]))
