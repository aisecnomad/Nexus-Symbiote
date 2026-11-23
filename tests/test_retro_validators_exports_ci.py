"""Regression tests for Bundle H: validators, trace evidence, exports, advisories, and CI checks."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from packaging.version import Version

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import CITED_EVIDENCE_CLAIM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    ClaimEvidence,
    DataSourceComponent,
    IDEAgentComponent,
    MCPServerComponent,
    ModelComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.diff.differ import _semantic_value
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.vex import VEXGenerator
from nexus_symbiote.graph_view import build_view
from nexus_symbiote.offline_advisories import match_offline_advisories
from nexus_symbiote.spdx_profiles import _clean_rfc3339
from nexus_symbiote.trace_evidence import collect, sarif_document
from nexus_symbiote.utils.terminal import UNSAFE_TEXT, json_text
from nexus_symbiote.validators.completeness import COLLECTOR_OWNED_PROPERTIES, CompletenessValidator
from nexus_symbiote.validators.risk import component_content_digest
from nexus_symbiote.vex_decisions import (
    ExecutionEvidence,
    LoadedVEXDecisions,
    VEXDecisionEntry,
)
from scripts import check_locks, check_workflows
from tests.support import scaling_ratio

LIVE_OBSERVATION_KEYS = frozenset(
    {
        "observed_declaration_hash",
        "observed_declaration_hash_profile",
        "observed_identity_hash",
        "observed_identity_hash_profile",
        "observed_descriptor_hash",
        "observed_endpoint_hash",
        "displayed_descriptor_differs",
    }
)

# --- R-HIGH-21: component_content_digest across MCP/IDE/A2A/RAG components ---


def test_component_content_digest_binds_mcp_ide_a2a_rag_and_protects_model() -> None:
    mcp_static = MCPServerComponent(
        bom_ref="mcp:1",
        name="srv",
        properties={"static_config_hash": "sha256:" + "1" * 64},
    )
    assert component_content_digest(mcp_static) == "sha256:" + "1" * 64

    ide_settings = IDEAgentComponent(
        bom_ref="ide:1",
        name="claude-code",
        ide_type="claude-code",
        properties={
            "settings_hashes": {
                ".claude/settings.json": "sha256:" + "a" * 64,
                ".claude/settings.local.json": "sha256:" + "b" * 64,
            }
        },
    )
    digest_a = component_content_digest(ide_settings)
    assert digest_a is not None and digest_a.startswith("sha256:")
    ide_mutated = ide_settings.model_copy(
        update={
            "properties": {
                "settings_hashes": {
                    ".claude/settings.json": "sha256:" + "c" * 64,
                    ".claude/settings.local.json": "sha256:" + "b" * 64,
                }
            }
        }
    )
    assert component_content_digest(ide_mutated) != digest_a

    # Invalid settings_hashes shape returns None rather than hashing untrusted non-string values.
    ide_bad = IDEAgentComponent(
        bom_ref="ide:bad",
        name="claude-code",
        ide_type="claude-code",
        properties={"settings_hashes": {"a": 123}},
    )
    assert component_content_digest(ide_bad) is None

    a2a_srv = A2AServerComponent(
        bom_ref="a2a:1",
        name="agent",
        properties={"static_card_hash": "sha256:" + "2" * 64},
    )
    assert component_content_digest(a2a_srv) == "sha256:" + "2" * 64

    a2a_cli = A2AClientComponent(
        bom_ref="a2a-cli:1",
        name="client",
        properties={"static_value_binding": "hmac-sha256:" + "3" * 64},
    )
    assert component_content_digest(a2a_cli) == "hmac-sha256:" + "3" * 64

    rag = RAGSourceComponent(
        bom_ref="rag:1",
        name="docs",
        properties={"config_hash": "sha256:" + "4" * 64},
    )
    assert component_content_digest(rag) == "sha256:" + "4" * 64

    # ModelComponent must NOT fall back to supplier-controlled properties when hashes are absent.
    forged_model = ModelComponent(
        bom_ref="model:forged",
        name="forged.pkl",
        properties={"static_config_hash": "sha256:" + "9" * 64},
    )
    assert component_content_digest(forged_model) is None


# --- R-MED-01: trace_evidence checks ambiguous candidates ---


def test_trace_evidence_flags_mismatched_and_unreadable_ambiguous_candidates(
    tmp_path: Path,
) -> None:
    h1 = "sha256:" + "1" * 64
    h2 = "sha256:" + "2" * 64
    rogue_hash = "sha256:" + "f" * 64
    bom = AIBOM(
        components=[
            ToolComponent(bom_ref="tool:a", name="search", definition_hash=h1),
            ToolComponent(bom_ref="tool:b", name="search", definition_hash=h2),
            AgentComponent(
                bom_ref="agent:a",
                name="planner",
                workload_identity="spiffe://prod.example/a",
            ),
            AgentComponent(
                bom_ref="agent:b",
                name="planner",
                workload_identity="spiffe://prod.example/b",
            ),
            ToolComponent(bom_ref="tool:nodigest-a", name="ping"),
            ToolComponent(bom_ref="tool:nodigest-b", name="ping", definition_hash=h1),
        ]
    )
    trace_file = tmp_path / "trace.json"
    trace_file.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "runner"}}
                            ]
                        },
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "name": "execute_tool search",
                                        "startTimeUnixNano": "1700000000000000000",
                                        "endTimeUnixNano": "1700000000100000000",
                                        "attributes": [
                                            {
                                                "key": "gen_ai.operation.name",
                                                "value": {"stringValue": "execute_tool"},
                                            },
                                            {
                                                "key": "gen_ai.tool.name",
                                                "value": {"stringValue": "search"},
                                            },
                                            {
                                                "key": "gen_ai.tool.definition_hash",
                                                "value": {"stringValue": rogue_hash},
                                            },
                                        ],
                                    },
                                    {
                                        "name": "invoke_agent planner",
                                        "startTimeUnixNano": "1700000000000000000",
                                        "endTimeUnixNano": "1700000000100000000",
                                        "attributes": [
                                            {
                                                "key": "gen_ai.operation.name",
                                                "value": {"stringValue": "invoke_agent"},
                                            },
                                            {
                                                "key": "gen_ai.agent.name",
                                                "value": {"stringValue": "planner"},
                                            },
                                            {
                                                "key": "spiffe.id",
                                                "value": {
                                                    "stringValue": "spiffe://prod.example/rogue"
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "execute_tool ping",
                                        "startTimeUnixNano": "1700000000000000000",
                                        "endTimeUnixNano": "1700000000100000000",
                                        "attributes": [
                                            {
                                                "key": "gen_ai.operation.name",
                                                "value": {"stringValue": "execute_tool"},
                                            },
                                            {
                                                "key": "gen_ai.tool.name",
                                                "value": {"stringValue": "ping"},
                                            },
                                            {
                                                "key": "gen_ai.tool.definition_hash",
                                                "value": {"stringValue": h1},
                                            },
                                        ],
                                    },
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)
    doc = collect(bom_path, [trace_file], fail_on="undeclared")
    ambiguous = {entry["name"]: entry for entry in doc["reconciliation"]["ambiguous"]}
    assert ambiguous["search"]["definition_hash_matched"] is False
    assert ambiguous["search"]["span_count"] == 1
    assert ambiguous["planner"]["workload_identity_matched"] is False
    assert ambiguous["planner"]["span_count"] == 1
    # One candidate lacked a declared digest, so match is inconclusive (None), not false-positive.
    assert ambiguous["ping"]["definition_hash_matched"] is None

    assert doc["gate"]["passed"] is False
    assert any("2 reconciled items report" in reason for reason in doc["gate"]["reasons"])
    sarif = sarif_document(doc, "aibom.json")
    assert len(sarif["runs"][0]["results"]) == 2


def test_trace_evidence_passes_when_ambiguous_candidate_hash_and_id_match(
    tmp_path: Path,
) -> None:
    h1 = "sha256:" + "1" * 64
    h2 = "sha256:" + "2" * 64
    bom = AIBOM(
        components=[
            ToolComponent(bom_ref="tool:a", name="search", definition_hash=h1),
            ToolComponent(bom_ref="tool:b", name="search", definition_hash=h2),
            AgentComponent(
                bom_ref="agent:a",
                name="planner",
                workload_identity="spiffe://prod.example/a",
            ),
            AgentComponent(
                bom_ref="agent:b",
                name="planner",
                workload_identity="spiffe://prod.example/b",
            ),
        ]
    )
    trace_file = tmp_path / "trace.json"
    trace_file.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "runner"}}
                            ]
                        },
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "name": "execute_tool search",
                                        "startTimeUnixNano": "1700000000000000000",
                                        "endTimeUnixNano": "1700000000100000000",
                                        "attributes": [
                                            {
                                                "key": "gen_ai.operation.name",
                                                "value": {"stringValue": "execute_tool"},
                                            },
                                            {
                                                "key": "gen_ai.tool.name",
                                                "value": {"stringValue": "search"},
                                            },
                                            {
                                                "key": "gen_ai.tool.definition_hash",
                                                "value": {"stringValue": h2},
                                            },
                                        ],
                                    },
                                    {
                                        "name": "invoke_agent planner",
                                        "startTimeUnixNano": "1700000000000000000",
                                        "endTimeUnixNano": "1700000000100000000",
                                        "attributes": [
                                            {
                                                "key": "gen_ai.operation.name",
                                                "value": {"stringValue": "invoke_agent"},
                                            },
                                            {
                                                "key": "gen_ai.agent.name",
                                                "value": {"stringValue": "planner"},
                                            },
                                            {
                                                "key": "spiffe.id",
                                                "value": {"stringValue": "spiffe://prod.example/a"},
                                            },
                                        ],
                                    },
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)
    doc = collect(bom_path, [trace_file], fail_on="undeclared")
    ambiguous = {entry["name"]: entry for entry in doc["reconciliation"]["ambiguous"]}
    assert ambiguous["search"]["definition_hash_matched"] is True
    assert ambiguous["planner"]["workload_identity_matched"] is True
    assert doc["gate"]["passed"] is True


# --- R-MED-04: COLLECTOR_OWNED_PROPERTIES reconciliation rejection ---


def test_collector_owned_properties_rejects_supplier_forged_metadata(tmp_path: Path) -> None:
    expected_keys = {
        "named_format",
        "lockfile_sha256",
        "lockfile_record",
        "lockfile_integrity",
        "pinning_state",
        "artifact_verified",
        "settings_hashes",
        "source_values_bound",
        "rail_files",
        "config_file_hash",
    }
    assert expected_keys <= COLLECTOR_OWNED_PROPERTIES
    # Live observations are written by `verify-live --record`, never by a static
    # collection, so owning them would block every recorded inventory.
    assert not (LIVE_OBSERVATION_KEYS & COLLECTOR_OWNED_PROPERTIES)

    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Instructions\n", encoding="utf-8")
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    bom_path = tmp_path / "bom.json"
    res = CliRunner().invoke(
        main, ["scan", "--report-only", "--no-project-policy", str(project), "-o", str(bom_path)]
    )
    assert res.exit_code == 0, res.output
    bom = AIBOM.load(bom_path)
    prompt = bom.get_component("prompt:CLAUDE.md")
    assert prompt is not None
    prompt.properties["settings_hashes"] = {".claude/settings.json": "sha256:" + "0" * 64}
    report = CompletenessValidator().validate_against_project(bom, project)
    assert any("collector-owned properties" in issue.description for issue in report.issues)


# --- R-MED-09: CycloneDX _services auth filtering & bom-ref collision ---


def test_cyclonedx_services_filters_anonymous_auth_and_avoids_bom_ref_collisions() -> None:
    bom = AIBOM(
        components=[
            A2AClientComponent(
                bom_ref="a2a-anon",
                name="anon-client",
                agent_card_url="https://anon.example.test/.well-known/agent.json",
                authentication_methods=["none", "Anonymous"],
            ),
            A2AClientComponent(
                bom_ref="a2a-empty",
                name="empty-client",
                agent_card_url="https://empty.example.test/.well-known/agent.json",
                authentication_methods=[],
            ),
            A2AClientComponent(
                bom_ref="a2a-oauth",
                name="oauth-client",
                agent_card_url="https://oauth.example.test/.well-known/agent.json",
                authentication_methods=["none", "oauth2"],
            ),
            MCPServerComponent(
                bom_ref="srv",
                name="srv",
                endpoint_url="https://srv.example.test/mcp",
            ),
            # Existing component whose bom_ref collides with `service:srv` and `service:srv:1`
            ToolComponent(bom_ref="service:srv", name="collider-0"),
            ToolComponent(bom_ref="service:srv:1", name="collider-1"),
        ]
    )
    doc = CycloneDXGenerator(projection_version=3).generate(bom)
    by_name = {svc["name"]: svc for svc in doc["services"]}
    assert by_name["anon-client"]["authenticated"] is False
    assert by_name["empty-client"]["authenticated"] is False
    assert by_name["oauth-client"]["authenticated"] is True
    assert by_name["srv"]["bom-ref"] == "service:srv:2"
    all_refs = [c["bom-ref"] for c in doc["components"]] + [s["bom-ref"] for s in doc["services"]]
    assert len(all_refs) == len(set(all_refs))


# --- R-MED-10: SPDX RFC 3339 date validation & v4 declared fields ---


def test_spdx_rfc3339_validation_and_v4_declared_field_sanitization() -> None:
    assert _clean_rfc3339("2026-02-30") is None
    assert _clean_rfc3339("2026-02-30T12:00:00Z") is None
    assert _clean_rfc3339("2026-13-01T00:00:00Z") is None
    assert _clean_rfc3339("2026-05-01T10:30:00+02:00") == "2026-05-01T08:30:00Z"
    assert _clean_rfc3339("2026-05-01") == "2026-05-01T00:00:00Z"

    bom = AIBOM(
        components=[
            ModelComponent(
                bom_ref="model:m",
                name="m",
                properties={"declared_release_time": "2026-02-30T00:00:00Z"},
            ),
            DataSourceComponent(
                bom_ref="data:d",
                name="d",
                properties={
                    "declared_release_time": "not-a-timestamp",
                    "declared_availability": "notAnSpdxAvailabilityValue",
                },
            ),
            DataSourceComponent(
                bom_ref="data:good",
                name="good",
                properties={
                    "declared_release_time": "2026-05-01T02:00:00+02:00",
                    "declared_availability": "directDownload",
                },
            ),
        ]
    )
    gen = SPDXGenerator(projection_version=4)
    doc = gen.generate(bom)
    elems = {el["name"]: el for el in doc["@graph"] if "name" in el}
    assert "releaseTime" not in elems["m"]
    assert "releaseTime" not in elems["d"]
    assert "dataset_datasetAvailability" not in elems["d"]
    assert elems["good"]["releaseTime"] == "2026-05-01T00:00:00Z"
    assert elems["good"]["dataset_datasetAvailability"] == "directDownload"
    # Recovery succeeds cleanly on v4 export.
    recovered = SPDXGenerator.recover(doc)
    assert len(recovered.components) == 3


# --- R-MED-11: VEX advisory detail plain_text and executionOutcome with decisions ---


def test_vex_sanitizes_advisory_component_name_and_keeps_execution_outcome_with_decision() -> None:
    comp = RegistryEntryComponent(
        bom_ref="pkg:pypi:evil",
        name="evil\x1b[31m\u202epkg\n##[error]pwn",
        version="1.0.0",
        registry_type="pypi",
    )
    bom = AIBOM(components=[comp])
    inv_sha = "sha256:" + hashlib.sha256(bom.to_native_json().encode()).hexdigest()
    now = datetime(2026, 5, 1, tzinfo=UTC)
    expired = VEXDecisionEntry(
        id="CVE-2026-0001",
        component_ref=comp.bom_ref,
        state="not_affected",
        justification="code_not_reachable",
        detail="Reviewed",
        owner="sec-team",
        expires_at=datetime(2026, 4, 1, tzinfo=UTC),
        inventory_sha256=inv_sha,
        deployment_id="prod",
    )
    decisions = LoadedVEXDecisions(
        entries=(expired,),
        sha256="sha256:" + "a" * 64,
    )
    evidence = ExecutionEvidence(
        invoked_refs=frozenset({comp.bom_ref}),
        declared_never_loaded_refs=frozenset(),
        unobserved_refs=frozenset(),
        shadowed_refs=frozenset(),
        sha256="sha256:" + "b" * 64,
        attested=True,
    )
    vex = VEXGenerator(
        decisions=decisions,
        execution_evidence=evidence,
        advisories=[
            {
                "id": "CVE-2026-0001",
                "component_ref": comp.bom_ref,
                "severity": "high",
                "summary": "Vuln",
                "offline": True,
            }
        ],
        reference_time=now,
        inventory_sha256=inv_sha,
        deployment_id="prod",
    ).generate(bom)
    vuln = vex["vulnerabilities"][0]
    detail = vuln["analysis"]["detail"]
    assert "\x1b" not in detail
    assert "\u202e" not in detail
    assert "##[error]" not in detail
    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert props["nexus-symbiote:vexDecisionStatus"] == "expired-reverted"
    assert props["nexus-symbiote:executionOutcome"] == "invoked"


# --- R-LOW-01 & R-LOW-02: offline advisories per-ecosystem freshness and max EPSS ---


def test_offline_advisories_checks_per_ecosystem_freshness_and_max_epss(tmp_path: Path) -> None:
    db = tmp_path / "osv.json"
    db.write_text(
        json.dumps(
            [
                {
                    "id": "GHSA-pypi-0001",
                    "aliases": ["CVE-2026-1001", "CVE-2026-1002"],
                    "modified": "2026-04-28T00:00:00Z",
                    "summary": "Fresh PyPI record",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "openai"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                }
                            ],
                        }
                    ],
                },
                {
                    "id": "GHSA-npm-0001",
                    "modified": "2025-01-01T00:00:00Z",
                    "summary": "Stale npm record",
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "langchain"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                }
                            ],
                        }
                    ],
                },
            ]
        ),
        encoding="utf-8",
    )
    epss = tmp_path / "epss.csv"
    epss.write_text(
        "#model_version:v2025.03.14,score_date:2026-04-29T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2026-1001,0.12000,0.50000\n"
        "CVE-2026-1002,0.91000,0.99000\n",
        encoding="utf-8",
    )
    bom = AIBOM(
        components=[
            RegistryEntryComponent(
                bom_ref="pkg:pypi:openai",
                name="openai",
                version="1.0.0",
                registry_type="pypi",
                package_url="pkg:pypi/openai@1.0.0",
            ),
            RegistryEntryComponent(
                bom_ref="pkg:npm:langchain",
                name="langchain",
                version="1.0.0",
                registry_type="npm",
                package_url="pkg:npm/langchain@1.0.0",
            ),
        ]
    )
    now = datetime(2026, 5, 1, tzinfo=UTC)
    report, _prov = match_offline_advisories(
        bom, db_path=db, now=now, max_feed_age_days=14, epss_path=epss
    )
    # Global newest record is fresh (2026-04-28), yet stale npm sub-corpus MUST be flagged.
    assert any("offline advisory DB (npm)" in err for err in report.errors)
    assert not any("offline advisory DB (PyPI)" in err for err in report.errors)
    pypi_adv = next(a for a in report.advisories if a["package"] == "openai")
    assert pypi_adv["epss_score"] == 0.91
    assert pypi_adv["epss_percentile"] == 0.99


# --- R-MED-12: utils/terminal.py json_text escapes all 66 noncharacters ---


def test_json_text_escapes_all_unicode_noncharacters() -> None:
    nonchars = [chr(cp) for cp in range(0xFDD0, 0xFDF0)] + [
        chr((plane << 16) + tail) for plane in range(17) for tail in (0xFFFE, 0xFFFF)
    ]
    assert len(nonchars) == 66
    for ch in nonchars:
        assert UNSAFE_TEXT.search(ch) is not None
        encoded = json_text(json.dumps({"v": ch}, ensure_ascii=False))
        assert ch not in encoded
        assert json.loads(encoded)["v"] == ch


# --- R-MED-13: graph_view._edges includes upstream_server_refs ---


def test_graph_view_includes_gateway_upstream_server_refs() -> None:
    from nexus_symbiote.core.aibom import DependencyEdge

    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="agent:main", name="main"),
            MCPServerComponent(
                bom_ref="mcp:gw",
                name="gateway",
                properties={
                    "mcp_role": "gateway",
                    "upstream_server_refs": ["mcp:backend", "mcp:missing", 123],
                },
            ),
            MCPServerComponent(
                bom_ref="mcp:backend",
                name="backend",
                risks=[
                    RiskAssessment(
                        severity=RiskSeverity.HIGH,
                        category="credential_access",
                        detail="Backend accesses secrets",
                    )
                ],
            ),
        ],
        dependencies=[
            DependencyEdge(source_ref="agent:main", target_ref="mcp:gw", relationship="depends-on")
        ],
    )
    view = build_view(bom, max_nodes=100)
    idx_by_ref = {node.ref: node.index for node in view.nodes}
    assert any(
        edge.source == idx_by_ref["mcp:gw"]
        and edge.target == idx_by_ref["mcp:backend"]
        and edge.label == "upstream_server_refs"
        for edge in view.edges
    )


# --- R-LOW-04: differ.py colon-free cited evidence locator ---


def test_differ_semantic_value_preserves_colon_free_cited_evidence_locator() -> None:
    path = ("claims", CITED_EVIDENCE_CLAIM, "locator")
    assert _semantic_value("CLAUDE.md:42", path) == "CLAUDE.md"
    assert _semantic_value("CLAUDE.md", path) == "CLAUDE.md"
    assert _semantic_value("dir/file:name.md:10", path) == "dir/file:name.md"
    assert _semantic_value("dir/file:name.md", path) == "dir/file:name.md"
    # Verify claim object round-trip doesn't collapse distinct colon-free files.
    c1 = ClaimEvidence(method="cited", scope="repository", locator="A.md").model_dump(mode="json")
    c2 = ClaimEvidence(method="cited", scope="repository", locator="B.md").model_dump(mode="json")
    assert _semantic_value(c1, ("claims", CITED_EVIDENCE_CLAIM)) != _semantic_value(
        c2, ("claims", CITED_EVIDENCE_CLAIM)
    )


# --- R-LOW-06: SARIF _uri rejects backslash, NUL, and lone surrogates ---


def test_sarif_uri_rejects_backslash_nul_and_lone_surrogates(tmp_path: Path) -> None:
    gen = SARIFGenerator(tmp_path)
    assert gen._uri("src/app.py") == "src/app.py"
    assert gen._uri("..\\escape.py") is None
    assert gen._uri("src\\nested.py") is None
    assert gen._uri("src/null\x00byte.py") is None
    assert gen._uri("src/surrogate\ud800.py") is None


# --- R-MED-19(b, c): check_locks per-pin reachability & check_workflows env guards ---


def test_check_locks_catches_unreferenced_and_self_referencing_duplicate_pin() -> None:
    declared = {"click"}
    legit_pin = check_locks.Pin(
        name="click",
        version=Version("8.1.8"),
        marker=None,
        hashes=frozenset({"0" * 64}),
        via=frozenset({f"{check_locks.PROJECT} (pyproject.toml)"}),
    )
    injected_pin = check_locks.Pin(
        name="click",
        version=Version("9.9.9"),
        marker=None,
        hashes=frozenset({"1" * 64}),
        via=frozenset(),
    )
    self_ref_pin = check_locks.Pin(
        name="click",
        version=Version("9.9.8"),
        marker=None,
        hashes=frozenset({"2" * 64}),
        via=frozenset({"click"}),
    )
    lock = check_locks.Lock(
        path="requirements-ci.lock", pins={"click": [legit_pin, injected_pin, self_ref_pin]}
    )
    issues = check_locks._unreachable(lock, declared)
    assert len(issues) == 2
    assert any("click==9.9.9" in issue for issue in issues)
    assert any("click==9.9.8" in issue for issue in issues)


def test_clean_rfc3339_rejects_utc_overflow_and_cyclonedx_filters_noauth() -> None:
    from datetime import datetime, timedelta, timezone

    from nexus_symbiote.spdx_profiles import _clean_rfc3339

    assert _clean_rfc3339("9999-12-31T23:00:00-02:00") is None
    assert _clean_rfc3339("0001-01-01T00:00:00+02:00") is None
    overflow_dt = datetime(9999, 12, 31, 23, 0, tzinfo=timezone(timedelta(hours=-2)))
    assert _clean_rfc3339(overflow_dt) is None

    bom = AIBOM(
        components=[
            A2AClientComponent(
                bom_ref="a2a-client:noauth",
                name="noauth-client",
                agent_card_url="https://agent.example/card.json",
                authentication_methods=["noauth", "no-auth", "no_auth"],
            )
        ]
    )
    doc = CycloneDXGenerator(projection_version=3).generate(bom)
    assert doc["services"][0]["authenticated"] is False


def test_check_workflows_blocks_new_gate_env_vars_and_keeps_coverage_json() -> None:
    for var in (
        "COVERAGE_RCFILE",
        "COVERAGE_FILE",
        "COVERAGE_PROCESS_START",
        "COVERAGE_PROCESS_CONFIG",
        "COVERAGE_FORCE_CONFIG",
        "COVERAGE_CORE",
        "COVERAGE_RUN",
        "COVERAGE_DEBUG",
        "COV_CORE_CONFIG",
        "COV_CORE_DATAFILE",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        "VIRTUAL_ENV",
        "MYPYPATH",
        "NODE_OPTIONS",
        "NODE_PATH",
    ):
        assert check_workflows._unsafe_gate_env(var), var
    for prefix in ("PIP_", "UV_", "MYPY_", "RUFF_", "COVERAGE_", "COV_CORE_", "DYLD_"):
        assert prefix in check_workflows.UNSAFE_GATE_ENV_PREFIXES
    assert not check_workflows._unsafe_gate_env("COVERAGE_JSON")
    # Real repo workflows still pass cleanly.
    assert check_workflows.check(Path(".github/workflows/ci.yml")) == []


def test_component_content_digest_combines_co_present_bindings() -> None:
    mcp_a = MCPServerComponent(
        bom_ref="mcp:combo",
        name="srv",
        properties={
            "static_value_binding": "hmac-sha256:" + "1" * 64,
            "static_config_hash": "sha256:" + "a" * 64,
        },
    )
    mcp_b = mcp_a.model_copy(
        update={
            "properties": {
                "static_value_binding": "hmac-sha256:" + "1" * 64,
                "static_config_hash": "sha256:" + "b" * 64,
            }
        }
    )
    digest_a = component_content_digest(mcp_a)
    digest_b = component_content_digest(mcp_b)
    assert digest_a is not None and digest_a.startswith("sha256:")
    assert digest_b is not None and digest_a != digest_b


def test_collector_owned_includes_remaining_provenance_keys_and_differ_ascii_line_anchor() -> None:
    assert {
        "settings_hashes_profile",
        "requirement_hashes",
        "imports_digest",
    } <= COLLECTOR_OWNED_PROPERTIES
    assert "observed_endpoint_hash" not in COLLECTOR_OWNED_PROPERTIES

    path = ("claims", CITED_EVIDENCE_CLAIM, "locator")
    assert _semantic_value("CLAUDE.md:42", path) == "CLAUDE.md"
    assert _semantic_value("CLAUDE.md:42\n", path) == "CLAUDE.md:42\n"
    assert _semantic_value("CLAUDE.md:\u0661\u0662\u0663", path) == "CLAUDE.md:\u0661\u0662\u0663"

    gen = SARIFGenerator(root=Path("/repo"))
    assert gen._uri(Path("sub/file.py")) == "sub/file.py"
    assert gen._uri("..\\escape.py") is None


def test_recorded_live_observations_do_not_block_validate_against_project(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "proj"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"srv": {"command": "node", "args": ["server.js"]}}}),
        encoding="utf-8",
    )
    (project / "server.js").write_text("// server\n", encoding="utf-8")
    bom_path = tmp_path / "bom.json"
    res = CliRunner().invoke(
        main, ["scan", "--report-only", "--no-project-policy", str(project), "-o", str(bom_path)]
    )
    assert res.exit_code == 0, res.output
    bom = AIBOM.load(bom_path)
    baseline = CompletenessValidator().validate_against_project(bom, project)
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    # What `verify-live --record` writes onto the recorded server.
    server.properties.update(
        {
            "observed_declaration_hash": "sha256:" + "a" * 64,
            "observed_declaration_hash_profile": "mcp-declaration-v1",
            "observed_identity_hash": "sha256:" + "b" * 64,
            "observed_identity_hash_profile": "mcp-identity-v1",
            "observed_endpoint_hash": "sha256:" + "c" * 64,
        }
    )
    report = CompletenessValidator().validate_against_project(bom, project)
    assert not any("collector-owned properties" in issue.description for issue in report.issues)
    assert report.is_complete is baseline.is_complete


def test_ambiguous_runtime_checks_scale_linearly_with_shared_candidates(tmp_path: Path) -> None:
    """M items over one shared N-candidate list cost O(N + M), not O(N * M)."""

    def span(index: int) -> dict[str, Any]:
        return {
            "name": "chat m",
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000000100000000",
            "attributes": [
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "m"}},
                {"key": "gen_ai.provider.name", "value": {"stringValue": f"p{index}"}},
                {"key": "spiffe.id", "value": {"stringValue": f"spiffe://trust.example/w{index}"}},
            ],
        }

    def run(scale: int) -> None:
        size = 250 * scale
        bom = AIBOM(
            components=[
                ModelComponent(bom_ref=f"model:{i}", name="m", model_type="hosted")
                for i in range(size)
            ]
        )
        bom_path = tmp_path / f"aibom-{scale}.json"
        bom.save(bom_path)
        trace_file = tmp_path / f"trace-{scale}.json"
        trace_file.write_text(
            json.dumps(
                {
                    "resourceSpans": [
                        {
                            "resource": {"attributes": []},
                            "scopeSpans": [{"spans": [span(i) for i in range(size)]}],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        doc = collect(bom_path, [trace_file], fail_on="undeclared")
        assert len(doc["reconciliation"]["ambiguous"]) == size
        assert doc["reconciliation"]["ambiguous"][0]["workload_identity_matched"] is None

    assert scaling_ratio(run) < 10


def test_ambiguous_checks_summarize_identity_rich_candidates_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Agents with distinct identities are summarized once, not copied per trace item."""
    from nexus_symbiote import trace_evidence

    merges: list[int] = []
    merge = trace_evidence._merge_runtime

    def counted(summaries: Any) -> Any:
        merges.append(1)
        return merge(summaries)

    monkeypatch.setattr(trace_evidence, "_merge_runtime", counted)

    def run(scale: int) -> None:
        size = 200 * scale
        bom_path = tmp_path / f"aibom-rich-{scale}.json"
        AIBOM(
            components=[
                AgentComponent(
                    bom_ref=f"agent:{i}",
                    name="planner",
                    workload_identity=f"spiffe://prod.example/a{i}",
                )
                for i in range(size)
            ]
        ).save(bom_path)
        spans = [
            {
                "name": "invoke_agent planner",
                "startTimeUnixNano": "1700000000000000000",
                "endTimeUnixNano": "1700000000100000000",
                "attributes": [
                    {"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_agent"}},
                    {"key": "gen_ai.agent.id", "value": {"stringValue": f"x{i}"}},
                    {"key": "gen_ai.agent.name", "value": {"stringValue": "planner"}},
                    {"key": "spiffe.id", "value": {"stringValue": f"spiffe://rogue.example/{i}"}},
                ],
            }
            for i in range(size)
        ]
        trace_file = tmp_path / f"trace-rich-{scale}.json"
        trace_file.write_text(
            json.dumps(
                {
                    "resourceSpans": [
                        {"resource": {"attributes": []}, "scopeSpans": [{"spans": spans}]}
                    ]
                }
            ),
            encoding="utf-8",
        )
        doc = collect(bom_path, [trace_file], fail_on="undeclared")
        ambiguous = doc["reconciliation"]["ambiguous"]
        assert len(ambiguous) == size
        assert all(entry["workload_identity_matched"] is False for entry in ambiguous)

    assert scaling_ratio(run) < 10
    # Every item shares one candidate list, so no item copies its identities.
    assert not merges


def _trace_of(tmp_path: Path, spans: list[dict[str, Any]], name: str = "trace.json") -> Path:
    trace_file = tmp_path / name
    trace_file.write_text(
        json.dumps(
            {"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [{"spans": spans}]}]}
        ),
        encoding="utf-8",
    )
    return trace_file


def _span(attributes: dict[str, str]) -> dict[str, Any]:
    return {
        "name": "s",
        "startTimeUnixNano": "1700000000000000000",
        "endTimeUnixNano": "1700000000100000000",
        "attributes": [{"key": k, "value": {"stringValue": v}} for k, v in attributes.items()],
    }


def _split_candidate_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    """Serve every candidate list as two parts, as the ``Candidates`` type allows."""
    from nexus_symbiote import trace_evidence

    original = trace_evidence._Inventory.candidates
    halves: dict[int, tuple[list[Any], list[Any]]] = {}

    def split(self: Any, kind: str, values: Any) -> Any:
        parts = []
        for found, basis in original(self, kind, values):
            if len(found) < 2:
                parts.append((found, basis))
                continue
            # One stable pair of lists per original list, so repeated items share parts.
            first, second = halves.setdefault(id(found), (found[:1], found[1:]))
            parts.extend([(first, basis), (second, basis)])
        return parts

    monkeypatch.setattr(trace_evidence._Inventory, "candidates", split)


def test_ambiguous_checks_merge_candidates_split_across_lists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Identities and hashes from every part count; a part that omits one leaves it open."""
    _split_candidate_lists(monkeypatch)
    h1, h2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="agent:a", name="planner", workload_identity="spiffe://p/a"),
            AgentComponent(bom_ref="agent:b", name="planner", workload_identity="spiffe://p/b"),
            ToolComponent(bom_ref="tool:a", name="search", definition_hash=h1),
            ToolComponent(bom_ref="tool:b", name="search", definition_hash=h2),
            AgentComponent(bom_ref="agent:c", name="helper", workload_identity="spiffe://p/c"),
            AgentComponent(bom_ref="agent:d", name="helper"),
            ToolComponent(bom_ref="tool:c", name="ping", definition_hash=h1),
            ToolComponent(bom_ref="tool:d", name="ping"),
        ]
    )
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)
    agent = {"gen_ai.operation.name": "invoke_agent"}
    tool = {"gen_ai.operation.name": "execute_tool"}
    spans = [
        # The second part's identity and hash match: every part is consulted.
        _span({**agent, "gen_ai.agent.name": "planner", "spiffe.id": "spiffe://p/b"}),
        _span({**tool, "gen_ai.tool.name": "search", "gen_ai.tool.definition_hash": h2}),
        # One part declares nothing: the reported value cannot be confirmed.
        _span({**agent, "gen_ai.agent.name": "helper", "spiffe.id": "spiffe://p/c"}),
        _span({**tool, "gen_ai.tool.name": "ping", "gen_ai.tool.definition_hash": h1}),
    ]
    doc = collect(bom_path, [_trace_of(tmp_path, spans)], fail_on="undeclared")
    entries = {e["name"]: e for e in doc["reconciliation"]["ambiguous"]}
    assert entries["planner"]["workload_identity_matched"] is True
    assert entries["search"]["definition_hash_matched"] is True
    assert entries["helper"]["workload_identity_matched"] is None
    assert entries["ping"]["definition_hash_matched"] is None


def test_items_over_the_same_split_lists_reuse_one_merge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nexus_symbiote import trace_evidence

    _split_candidate_lists(monkeypatch)
    merges: list[int] = []
    merge = trace_evidence._merge_runtime

    def counted(summaries: Any) -> Any:
        merges.append(1)
        return merge(summaries)

    monkeypatch.setattr(trace_evidence, "_merge_runtime", counted)
    bom = AIBOM(
        components=[
            AgentComponent(
                bom_ref=f"agent:{i}", name="planner", workload_identity=f"spiffe://p/{i}"
            )
            for i in range(3)
        ]
    )
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)
    spans = [
        _span(
            {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.id": f"x{i}",
                "gen_ai.agent.name": "planner",
                "spiffe.id": "spiffe://p/2",
            }
        )
        for i in range(5)
    ]
    doc = collect(bom_path, [_trace_of(tmp_path, spans)], fail_on="undeclared")
    ambiguous = doc["reconciliation"]["ambiguous"]
    assert len(ambiguous) == 5
    assert all(entry["workload_identity_matched"] is True for entry in ambiguous)
    assert merges == [1]


def test_a_malformed_definition_hash_never_confirms_a_reported_hash(tmp_path: Path) -> None:
    good = "sha256:" + "1" * 64
    bom = AIBOM(
        components=[
            ToolComponent(bom_ref="tool:a", name="search", definition_hash="sha256:zz"),
            ToolComponent(bom_ref="tool:b", name="search", definition_hash="sha256:zz"),
        ]
    )
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)
    spans = [
        _span(
            {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "search",
                "gen_ai.tool.definition_hash": good,
            }
        )
    ]
    doc = collect(bom_path, [_trace_of(tmp_path, spans)], fail_on="undeclared")
    (entry,) = doc["reconciliation"]["ambiguous"]
    assert entry["definition_hash_matched"] is False


def test_an_inventory_without_a_content_digest_is_recorded_as_none() -> None:
    from nexus_symbiote.trace_evidence import _inventory_input

    recorded = _inventory_input(Path("aibom.json"), b"{}")
    assert recorded["content_digest"] is None
    assert recorded["size"] == 2
