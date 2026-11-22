"""Tests for CycloneDX projection 3, SPDX 3.0.1 AI/Dataset projection 4, ISO 22989, and agent.yaml 1.1."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from spdx_python_model import v3_0_1 as spdx

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel, AutonomyLevel, TrustTier
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    ClaimEvidence,
    CompletenessClaim,
    DataSourceComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    SkillPackageComponent,
    ToolComponent,
)
from nexus_symbiote.generators.cyclonedx import (
    PROJECTION,
    PROJECTION_V3_16,
    PROJECTION_V3_17,
    CycloneDXGenerator,
)
from nexus_symbiote.generators.spdx import PROJECTION as SPDX_V3
from nexus_symbiote.generators.spdx import PROJECTION_V4, SPDXGenerator
from nexus_symbiote.policy import PolicyError
from nexus_symbiote.spdx_profiles import (
    ISO_22989_AUTOMATION_TABLE,
    MAX_AGENT_YAML_BYTES,
    apply_agent_yaml_declarations,
    clean_license_identifier,
    normalize_spdx_dataset_type,
    resolve_automation_mapping,
    spdx_autonomy_presence,
)
from tests.support import scaling_ratio


def _rich_aibom() -> AIBOM:
    ts = datetime(2026, 11, 19, 0, 0, 0, tzinfo=UTC)
    agent = AgentComponent(
        bom_ref="agent:repo",
        name="customer-support-agent",
        version="1.2.0",
        supplier="Acme AI",
        autonomy_level=AutonomyLevel.L2_AGENT,
        source_path="agent.yaml",
        assurance_level=AssuranceLevel.OBSERVED,
        properties={
            "inferred_subject": True,
            "declared_license": "Apache-2.0",
            "declared_release_time": "2026-11-01T00:00:00Z",
            "declared_download_location": "https://example.com/agents/customer-support-1.2.0.tar.gz",
            "declared_domain": "customer-support",
            "declared_compliance": ["ISO/IEC 42001:2023"],
            "source_line": 12,
        },
    )
    base_model = ModelComponent(
        bom_ref="model:base",
        name="llama-3-8b",
        version="3.0.0",
        supplier="Meta",
        model_type="transformer",
        assurance_level=AssuranceLevel.OBSERVED,
        properties={
            "declared_license": "Apache-2.0",
            "declared_release_time": "2026-06-01T00:00:00Z",
            "declared_download_location": "https://huggingface.co/meta-llama/Llama-3-8B",
            "declared_domain": "text-generation",
        },
    )
    tuned_model = ModelComponent(
        bom_ref="model:tuned",
        name="support-llama-8b-ft",
        version="1.0.0",
        supplier="Acme AI",
        model_type="transformer",
        source_path="models/support.safetensors",
        hashes={"sha256": "a" * 64},
        signing_status="sigstore-signed",
        assurance_level=AssuranceLevel.VERIFIED,
        trust_tier=TrustTier.THIRD_PARTY_SIGNED,
        claims={
            "locator": ClaimEvidence(
                assurance=AssuranceLevel.OBSERVED,
                method="model-collector",
                scope="artifact",
                locator="models/support.safetensors:42",
            )
        },
        properties={
            "declared_license": "Apache-2.0",
            "declared_release_time": "2026-10-15T00:00:00Z",
            "declared_download_location": "https://example.com/models/support.safetensors",
            "declared_domain": "customer-support",
            "declared_limitations": "English ticket triage only.",
        },
    )
    dataset = DataSourceComponent(
        bom_ref="dataset:tickets",
        name="support-tickets-2026",
        version="2026.10",
        supplier="Acme Data",
        dataset_type="text",
        source_uri="https://example.com/datasets/support-tickets-2026.parquet",
        collection_date="2026-10-01T00:00:00Z",
        license="CC-BY-4.0",
        assurance_level=AssuranceLevel.DECLARED,
        properties={
            "declared_release_time": "2026-10-01T00:00:00Z",
            "declared_download_location": "https://example.com/datasets/support-tickets-2026.parquet",
            "declared_license": "CC-BY-4.0",
            "declared_availability": "directDownload",
            "declared_sensitive_pii": "no",
        },
    )
    mcp_srv = MCPServerComponent(
        bom_ref="mcp:docs",
        name="docs-mcp",
        version="2.1.0",
        transport="streamable-http",
        endpoint_url="https://mcp.example.com/v1",
        source_path=".mcp.json",
        version_pinned=True,
        assurance_level=AssuranceLevel.OBSERVED,
        claims={
            "endpoint": ClaimEvidence(
                assurance=AssuranceLevel.OBSERVED,
                method="mcp-collector",
                scope="endpoint",
                locator="https://mcp.example.com:8443",
            )
        },
    )
    tool = ToolComponent(
        bom_ref="tool:search_docs",
        name="search_docs",
        version="2.1.0",
        definition_hash="sha256:" + "b" * 64,
        assurance_level=AssuranceLevel.OBSERVED,
        properties={"hosted_tool_origin": "https://tools.example.com/v1"},
    )
    a2a_srv = A2AServerComponent(
        bom_ref="a2a:billing",
        name="billing-specialist",
        version="1.0.0",
        endpoint_url="https://a2a.example.com/billing",
        authentication_required=True,
        assurance_level=AssuranceLevel.OBSERVED,
        description="Billing A2A server",
    )
    a2a_cli = A2AClientComponent(
        bom_ref="a2a:client",
        name="billing-client",
        version="1.0.0",
        agent_card_url="https://a2a.example.com/.well-known/agent.json",
        authentication_methods=["oauth2"],
        assurance_level=AssuranceLevel.OBSERVED,
    )
    rag = RAGSourceComponent(
        bom_ref="rag:kb",
        name="kb-index",
        version="2026.10",
        supplier="Acme Data",
        corpus_type="vector-db",
        assurance_level=AssuranceLevel.OBSERVED,
        properties={
            "declared_release_time": "2026-10-01T00:00:00Z",
            "declared_download_location": "https://example.com/rag/kb-index",
            "declared_license": "CC-BY-4.0",
        },
    )
    skill = SkillPackageComponent(
        bom_ref="skill:triage",
        name="ticket-triage-skill",
        version="0.4.0",
        assurance_level=AssuranceLevel.OBSERVED,
    )
    prompt = PromptComponent(
        bom_ref="prompt:sys",
        name="system-prompt",
        content_hash="sha256:" + "c" * 64,
        assurance_level=AssuranceLevel.OBSERVED,
    )
    pkg = RegistryEntryComponent(
        bom_ref="pkg:openai",
        name="openai",
        version="1.52.0",
        registry_type="pypi",
        package_url="pkg:pypi/openai@1.52.0",
        assurance_level=AssuranceLevel.OBSERVED,
    )

    bom = AIBOM(
        components=[
            agent,
            base_model,
            tuned_model,
            dataset,
            mcp_srv,
            tool,
            a2a_srv,
            a2a_cli,
            rag,
            skill,
            prompt,
            pkg,
        ],
        dependencies=[
            DependencyEdge(
                source_ref="agent:repo", target_ref="model:tuned", relationship="uses-model"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="a2a:billing", relationship="delegates-to"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="rag:kb", relationship="retrieves-from"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="skill:triage", relationship="loads-skill"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="prompt:sys", relationship="configured-with"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="tool:search_docs", relationship="invokes"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="pkg:openai", relationship="depends-on"
            ),
            DependencyEdge(
                source_ref="mcp:docs", target_ref="tool:search_docs", relationship="provides-tool"
            ),
            DependencyEdge(
                source_ref="model:tuned", target_ref="dataset:tickets", relationship="trained-on"
            ),
            DependencyEdge(
                source_ref="model:tuned", target_ref="model:base", relationship="fine-tuned-from"
            ),
        ],
    )
    bom.metadata.timestamp = ts
    bom.metadata.authors = ["Platform Security Team"]
    bom.metadata.completeness = CompletenessClaim(
        scope="repository",
        collectors_requested=["mcp", "model"],
        collectors_completed=["mcp", "model"],
        scanner_status={"mcp": "complete", "model": "complete"},
    )
    return bom


def test_cyclonedx_projection_v3_standard_fields_schema_and_roundtrip() -> None:
    bom = _rich_aibom()
    doc_v2 = CycloneDXGenerator().generate(bom)
    assert any(
        p == {"name": "nexus-symbiote:projection", "value": PROJECTION}
        for p in doc_v2["metadata"]["properties"]
    )
    assert "services" not in doc_v2

    with pytest.raises(ValueError, match="projection_version must be 2 or 3"):
        CycloneDXGenerator(projection_version=99)
    with pytest.raises(ValueError, match="spec_version must be '1.6' or '1.7'"):
        CycloneDXGenerator(spec_version="1.5")
    with pytest.raises(ValueError, match="requires projection_version=3"):
        CycloneDXGenerator(projection_version=2, spec_version="1.6")

    for spec_ver, expected_marker, schema_ver in (
        ("1.7", PROJECTION_V3_17, SchemaVersion.V1_7),
        ("1.6", PROJECTION_V3_16, SchemaVersion.V1_6),
    ):
        gen = CycloneDXGenerator(projection_version=3, spec_version=spec_ver)
        raw_json = gen.generate_json(bom)
        validator = JsonStrictValidator(schema_ver)
        validation_errors = validator.validate_str(raw_json)
        assert validation_errors is None, f"CycloneDX {spec_ver} schema error: {validation_errors}"

        doc = json.loads(raw_json)
        assert any(
            p == {"name": "nexus-symbiote:projection", "value": expected_marker}
            for p in doc["metadata"]["properties"]
        )

        dep_pairs = {
            (row["ref"], target)
            for row in doc["dependencies"]
            for target in row.get("dependsOn", [])
        }
        assert len(dep_pairs) == 10

        service_urls = {ep for svc in doc["services"] for ep in svc["endpoints"]}
        assert "https://mcp.example.com/v1" in service_urls
        assert "https://a2a.example.com/billing" in service_urls
        assert "https://a2a.example.com/.well-known/agent.json" in service_urls
        assert "https://tools.example.com/v1" in service_urls

        tuned = next(c for c in doc["components"] if c["bom-ref"] == "model:tuned")
        assert tuned["evidence"]["occurrences"] == [
            {"location": "models/support.safetensors", "line": 42}
        ]
        assert tuned["licenses"] == [
            {"license": {"id": "Apache-2.0", "acknowledgement": "declared"}}
        ]
        assert tuned["pedigree"]["ancestors"] == [
            {"type": "machine-learning-model", "name": "llama-3-8b", "version": "3.0.0"}
        ]
        assert tuned["modelCard"]["modelParameters"]["datasets"] == [{"ref": "dataset:tickets"}]
        assert tuned["modelCard"]["modelParameters"]["task"] == "customer-support"
        assert tuned["modelCard"]["considerations"]["technicalLimitations"] == [
            "English ticket triage only."
        ]

        # URL port locator (https://mcp.example.com:8443) must NOT parse as line 8443.
        mcp_comp = next(c for c in doc["components"] if c["bom-ref"] == "mcp:docs")
        assert mcp_comp["evidence"]["occurrences"] == [{"location": ".mcp.json"}]

        recovered = CycloneDXGenerator.recover(doc)
        assert len(recovered.components) == len(bom.components)
        assert len(recovered.dependencies) == len(bom.dependencies)

        tampered = json.loads(raw_json)
        tampered["services"][0]["endpoints"] = ["https://evil.example.com/mcp"]
        with pytest.raises(ValueError, match="conflicts with the embedded native document"):
            CycloneDXGenerator.recover(tampered)


def test_spdx_projection_v4_typed_relationships_profiles_and_deserializer() -> None:
    bom = _rich_aibom()
    with pytest.raises(ValueError, match="projection_version must be 3 or 4"):
        SPDXGenerator(projection_version=5)
    with pytest.raises(ValueError, match="requires projection_version=4"):
        SPDXGenerator(projection_version=3, author="Jane")

    doc_v3 = SPDXGenerator(namespace="https://example.com/spdx").generate(bom)
    spdx_doc_v3 = next(item for item in doc_v3["@graph"] if item["type"] == "SpdxDocument")
    v3_props = {
        p["extension_cdxPropName"]: p["extension_cdxPropValue"]
        for p in spdx_doc_v3["extension"][0]["extension_cdxProperty"]
    }
    assert v3_props["nexus-symbiote:projection"] == SPDX_V3

    gen_v4 = SPDXGenerator(
        namespace="https://example.com/spdx", projection_version=4, author="Lead Reviewer"
    )
    raw_v4 = gen_v4.generate_json(bom)
    doc_v4 = json.loads(raw_v4)

    spdx_doc = next(item for item in doc_v4["@graph"] if item["type"] == "SpdxDocument")
    v4_props = {
        p["extension_cdxPropName"]: p["extension_cdxPropValue"]
        for p in spdx_doc["extension"][0]["extension_cdxProperty"]
    }
    assert v4_props["nexus-symbiote:projection"] == PROJECTION_V4
    assert "ai" in spdx_doc["profileConformance"]
    assert "dataset" in spdx_doc["profileConformance"]
    assert "simpleLicensing" in spdx_doc["profileConformance"]

    persons = {item["name"] for item in doc_v4["@graph"] if item["type"] == "Person"}
    assert persons == {"Platform Security Team", "Lead Reviewer"}

    by_name = {
        item["name"]: item["spdxId"]
        for item in doc_v4["@graph"]
        if "name" in item and "spdxId" in item
    }
    rels = [item for item in doc_v4["@graph"] if item["type"] == "Relationship"]
    rel_types = {item["relationshipType"] for item in rels}
    assert {
        "trainedOn",
        "descendantOf",
        "configures",
        "usesTool",
        "dependsOn",
        "other",
    } <= rel_types
    assert rel_types.isdisjoint({"delegatedTo", "hasInput", "hasProvidedDependency"})

    # Verify configures direction: system-prompt --configures--> customer-support-agent
    cfg_rel = next(r for r in rels if r["relationshipType"] == "configures")
    assert cfg_rel["from"] == by_name["system-prompt"]
    assert cfg_rel["to"] == [by_name["customer-support-agent"]]

    object_set = spdx.SHACLObjectSet()
    deserializer = spdx.JSONLDDeserializer()
    deserializer.read(io.StringIO(raw_v4), object_set)
    ai_pkgs = list(object_set.foreach_type(spdx.ai_AIPackage))
    ds_pkgs = list(object_set.foreach_type(spdx.dataset_DatasetPackage))
    assert len(ai_pkgs) == 3
    assert len(ds_pkgs) == 2

    recovered = SPDXGenerator.recover(doc_v4)
    assert len(recovered.components) == len(bom.components)

    incomplete_bom = _rich_aibom()
    for comp in incomplete_bom.components:
        comp.properties.pop("declared_release_time", None)
    doc_incomplete = gen_v4.generate(incomplete_bom)
    spdx_incomplete = next(
        item for item in doc_incomplete["@graph"] if item["type"] == "SpdxDocument"
    )
    assert "ai" not in spdx_incomplete["profileConformance"]


def test_observed_fields_and_autonomy_never_overridden_by_declarations(tmp_path: Path) -> None:
    """Verify High #1 and High #2: declarations never override observed autonomy or populate observed fields."""
    agent = AgentComponent(
        bom_ref="agent:repo",
        name="prod-agent",
        autonomy_level=AutonomyLevel.L2_AGENT,
        assurance_level=AssuranceLevel.OBSERVED,
        properties={"inferred_subject": True},
    )
    scanned_model = ModelComponent(
        bom_ref="model:models/intent-classifier.safetensors",
        name="models/intent-classifier.safetensors",
        model_type="safetensors",
        source_path="models/intent-classifier.safetensors",
        hashes={"sha256": "d" * 64},
        assurance_level=AssuranceLevel.OBSERVED,
    )
    bom = AIBOM(components=[agent, scanned_model])
    (tmp_path / "agent.yaml").write_text(
        """
schema_version: "1.1"
name: prod-agent
version: "9.9.9"
owner: Declared Corp
automation_level: no_automation
release_time: 2026-11-01
download_location: https://example.com/agents/prod.tar.gz?sig=secret-query-token
models:
  - name: models/intent-classifier.safetensors
    version: "7.7"
    supplier: OpenAI
    license: MIT
    release_time: 2026-11-01
    download_location: https://example.com/models/intent-classifier.safetensors
  - name: remote-declared-llm
    version: "4.1"
    supplier: VendorX
    license: Apache-2.0
    release_time: 2026-11-01T12:00:00Z
    download_location: https://example.com/models/remote-llm
""",
        encoding="utf-8",
    )
    notices = apply_agent_yaml_declarations(bom, tmp_path, relative_path="agent.yaml")
    assert any("autonomy_level conflict" in n for n in notices)

    # High #1: Observed L2_AGENT must still export ai_autonomyType == 'yes', never 'no'.
    assert spdx_autonomy_presence(agent) == "yes"
    assert agent.properties["declared_iso_22989_automation"] == "no_automation"
    assert "iso_22989_automation" not in agent.properties

    # High #2: Scanned OBSERVED model keeps version=None, supplier=None, assurance=OBSERVED;
    # declared values stay in declared_* with per-field declaration.* claims.
    assert scanned_model.version is None
    assert scanned_model.supplier is None
    assert scanned_model.assurance_level == AssuranceLevel.OBSERVED
    assert scanned_model.properties["declared_version"] == "7.7"
    assert scanned_model.properties["declared_supplier"] == "OpenAI"
    assert scanned_model.properties["declared_license"] == "MIT"
    assert scanned_model.claims["declaration.version"].assurance == AssuranceLevel.DECLARED
    assert scanned_model.claims["declaration.supplier"].assurance == AssuranceLevel.DECLARED
    assert scanned_model.claims["declaration.license"].assurance == AssuranceLevel.DECLARED

    # Declared-only model created by agent.yaml has DECLARED assurance and UNKNOWN trust tier.
    decl_model = next(c for c in bom.components if c.name == "remote-declared-llm")
    assert decl_model.assurance_level == AssuranceLevel.DECLARED
    assert decl_model.trust_tier == TrustTier.UNKNOWN
    assert decl_model.version == "4.1"
    assert decl_model.supplier == "VendorX"

    # Medium #7: Full download path preserved, query stripped, unquoted YAML date converted to RFC3339.
    assert (
        agent.properties["declared_download_location"] == "https://example.com/agents/prod.tar.gz"
    )
    assert agent.properties["declared_release_time"] == "2026-11-01T00:00:00Z"

    # SPDX export does NOT claim 'ai' profileConformance because observed model lacks observed version/supplier.
    spdx_doc = SPDXGenerator(projection_version=4).generate(bom)
    doc_node = next(n for n in spdx_doc["@graph"] if n["type"] == "SpdxDocument")
    assert "ai" not in doc_node["profileConformance"]
    model_node = next(
        n for n in spdx_doc["@graph"] if n.get("name") == "models/intent-classifier.safetensors"
    )
    assert "software_packageVersion" not in model_node
    assert "suppliedBy" not in model_node
    assert model_node.get("ai_autonomyType", True)
    agent_node = next(n for n in spdx_doc["@graph"] if n.get("name") == "prod-agent")
    assert agent_node["ai_autonomyType"] == "yes"


def test_secret_scrubbing_bounded_yaml_and_confinement_controls(tmp_path: Path) -> None:
    """Verify Medium #4, #5, #6, #9: secrets, malformed/deep/duplicate YAML, symlinks, traversal, limits, and overwrite."""
    bom_path = tmp_path / "inv.json"
    _rich_aibom().save(bom_path)
    proj = tmp_path / "proj"
    proj.mkdir()

    # Medium #4: AWS key in license and OpenAI-style key in owner must never appear in exports.
    aws_fixture = "AKIA" + "IOSFODNN7EXAMPLE"
    sk_fixture = "sk-" + "1234567890abcdefghijklmnop"
    assert clean_license_identifier(aws_fixture) is None
    (proj / "agent.yaml").write_text(
        f'schema_version: "1.0"\nowner: "{sk_fixture}"\nlicenses:\n  - "{aws_fixture}"\n'
        f'download_location: "https://user:pass@example.com/x"\n',
        encoding="utf-8",
    )
    for fmt in ("spdx", "cyclonedx"):
        res = CliRunner().invoke(
            main,
            [
                "export-standard",
                str(bom_path),
                "-f",
                fmt,
                "--project",
                str(proj),
                "--agent-yaml",
                "agent.yaml",
            ],
        )
        assert res.exit_code == 0, res.output
        assert aws_fixture not in res.output
        assert sk_fixture not in res.output
        assert "user:pass" not in res.output

    # Medium #5: Malformed YAML, deep nesting, duplicate keys, aliases, and unsupported schema_version fail closed.
    bad_payloads = [
        "owner: [unclosed\n",
        "owner: " + ("[" * 5000) + ("]" * 5000) + "\n",
        "owner: one\nowner: two\n",
        "a: &anchor {x: 1}\nb: *anchor\n",
        'schema_version: "0.1"\nowner: Acme\n',
        "- not-a-mapping\n",
    ]
    for idx, payload in enumerate(bad_payloads):
        bad_file = f"bad-{idx}.yaml"
        (proj / bad_file).write_text(payload, encoding="utf-8")
        res_bad = CliRunner().invoke(
            main,
            [
                "export-standard",
                str(bom_path),
                "-f",
                "spdx",
                "--project",
                str(proj),
                "--agent-yaml",
                bad_file,
            ],
        )
        assert res_bad.exit_code == 1
        assert "please report it" not in res_bad.output

    # Medium #6 & #9: CLI flag pairing, source overwrite refusal, --author on SPDX v3, --limit failure, traversal, symlink, >256 KiB.
    assert (
        CliRunner()
        .invoke(main, ["export-standard", str(bom_path), "-f", "spdx", "-o", str(bom_path)])
        .exit_code
        == 2
    )
    assert (
        CliRunner()
        .invoke(main, ["export-standard", str(bom_path), "-f", "spdx", "--project", str(proj)])
        .exit_code
        == 2
    )
    assert (
        CliRunner()
        .invoke(
            main, ["export-standard", str(bom_path), "-f", "spdx", "--agent-yaml", "agent.yaml"]
        )
        .exit_code
        == 2
    )
    assert (
        CliRunner()
        .invoke(
            main,
            [
                "export-standard",
                str(bom_path),
                "-f",
                "spdx",
                "--spdx-projection",
                "3",
                "--author",
                "Alice",
            ],
        )
        .exit_code
        == 2
    )
    assert (
        CliRunner()
        .invoke(
            main,
            [
                "export-standard",
                str(bom_path),
                "-f",
                "cyclonedx",
                "--spec-version",
                "1.6",
                "--cyclonedx-projection",
                "2",
            ],
        )
        .exit_code
        == 2
    )

    # --limit file-bytes=32 must fail closed (exit 1), never swallow read failure!
    (proj / "medium.yaml").write_text("owner: " + ("A" * 200) + "\n", encoding="utf-8")
    res_lim = CliRunner().invoke(
        main,
        [
            "--limit",
            "file-bytes=32",
            "export-standard",
            str(bom_path),
            "-f",
            "spdx",
            "--project",
            str(proj),
            "--agent-yaml",
            "medium.yaml",
        ],
    )
    assert res_lim.exit_code == 1

    # Path traversal, absolute path, symlink, and oversized >256 KiB file all fail closed.
    outside = tmp_path / "outside.yaml"
    outside.write_text("owner: Evil\n", encoding="utf-8")
    (proj / "escape.yaml").symlink_to(outside)
    (proj / "huge.yaml").write_bytes(b"owner: " + b"x" * (MAX_AGENT_YAML_BYTES + 10) + b"\n")

    for bad_arg in ("../outside.yaml", str(outside), "escape.yaml", "huge.yaml", "missing.yaml"):
        res_path = CliRunner().invoke(
            main,
            [
                "export-standard",
                str(bom_path),
                "-f",
                "spdx",
                "--project",
                str(proj),
                "--agent-yaml",
                bad_arg,
            ],
        )
        assert res_path.exit_code == 1

    # Explicit path helper checks (valid and oversized).
    valid_explicit = tmp_path / "explicit.yaml"
    valid_explicit.write_text("owner: ExplicitTeam\n", encoding="utf-8")
    b2 = _rich_aibom()
    apply_agent_yaml_declarations(b2, proj, explicit_path=valid_explicit)
    with pytest.raises(ValueError, match="exceeds maximum size limit"):
        apply_agent_yaml_declarations(b2, proj, explicit_path=proj / "huge.yaml")
    with pytest.raises(PolicyError):
        apply_agent_yaml_declarations(b2, proj, relative_path="bad-0.yaml")


def test_iso_22989_automation_table_and_linear_scaling(tmp_path: Path) -> None:
    assert len(ISO_22989_AUTOMATION_TABLE) == 6
    assert resolve_automation_mapping(None) is None
    assert resolve_automation_mapping(True) is None
    assert resolve_automation_mapping("unknown-level") is None
    assert resolve_automation_mapping("0") is not None
    assert normalize_spdx_dataset_type(None) == "noAssertion"
    assert normalize_spdx_dataset_type("audio") == "audio"
    assert normalize_spdx_dataset_type("evaluation") == "structured"
    assert normalize_spdx_dataset_type("custom-kind") == "other"

    mapped_l0 = resolve_automation_mapping("L0")
    assert mapped_l0 is not None and mapped_l0.spdx_autonomy_presence == "no"
    for level in (1, 2, 3, 4, 5):
        mapped = resolve_automation_mapping(level)
        assert mapped is not None and mapped.spdx_autonomy_presence == "yes"
    for level_str in ("L1", "L2", "L3", "L4"):
        mapped = resolve_automation_mapping(level_str)
        assert mapped is not None and mapped.spdx_autonomy_presence == "yes"

    # Medium #8: Verify CycloneDX projection 3 scales linearly on 1,500 models + 1,500 edges.
    def _build_bom(count: int) -> AIBOM:
        comps: list[Any] = [
            DataSourceComponent(
                bom_ref="ds:0", name="ds-0", assurance_level=AssuranceLevel.DECLARED
            )
        ]
        edges: list[DependencyEdge] = []
        for idx in range(count):
            ref = f"model:{idx}"
            comps.append(
                ModelComponent(
                    bom_ref=ref,
                    name=f"m-{idx}",
                    model_type="transformer",
                    assurance_level=AssuranceLevel.OBSERVED,
                )
            )
            edges.append(
                DependencyEdge(source_ref=ref, target_ref="ds:0", relationship="trained-on")
            )
        return AIBOM(components=comps, dependencies=edges)

    boms = {scale: _build_bom(375 * scale) for scale in (1, 4)}
    generator = CycloneDXGenerator(projection_version=3, spec_version="1.7")
    doc = generator._projection(boms[4])
    assert len(doc["components"]) == 1501
    assert scaling_ratio(lambda scale: generator._projection(boms[scale])) < 10

    # Verify CLI roundtrip with --agent-yaml and --author on SPDX v4.
    (tmp_path / "agent.yaml").write_text(
        """
name: customer-support-agent
version: "9.9.9"
owner: Different Owner
automation_level: full_automation
licenses:
  - Apache-2.0
data_usage: no-training-on-customer-inputs
compliance:
  - EU-AI-Act-Art-53
allowed_regions:
  - eu-west-1
datasets:
  - name: eval-golden-set
    version: "1.0"
    dataset_type: evaluation
    license: MIT
    download_location: https://example.com/eval.jsonl
    release_time: 2026-11-01
    availability: directDownload
    sensitive_personal_information: "no"
models:
  - name: support-llama-8b-ft
    version: "2.0.0"
    license: MIT
    training:
      description: LoRA fine-tune
      datasets:
        - eval-golden-set
""",
        encoding="utf-8",
    )
    bom_path = tmp_path / "aibom.json"
    _rich_aibom().save(bom_path)
    spdx_out = tmp_path / "out.spdx.json"
    res = CliRunner().invoke(
        main,
        [
            "export-standard",
            str(bom_path),
            "-f",
            "spdx",
            "--spdx-projection",
            "4",
            "--spdx-namespace",
            "https://example.com/ns",
            "--author",
            "Jane Doe",
            "--project",
            str(tmp_path),
            "--agent-yaml",
            "agent.yaml",
            "-o",
            str(spdx_out),
        ],
    )
    assert res.exit_code == 0, res.output
    spdx_doc = json.loads(spdx_out.read_text(encoding="utf-8"))
    person_names = {el["name"] for el in spdx_doc["@graph"] if el["type"] == "Person"}
    assert "Jane Doe" in person_names
    eval_node = next(el for el in spdx_doc["@graph"] if el.get("name") == "eval-golden-set")
    assert eval_node["software_downloadLocation"] == "https://example.com/eval.jsonl"
    assert eval_node["releaseTime"] == "2026-11-01T00:00:00Z"


def test_branch_coverage_for_profiles_and_export_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nexus_symbiote.spdx_profiles import _clean_rfc3339, _clean_url

    assert _clean_url("http://insecure.example.com/a") is None
    assert _clean_url("https://[::1") is None
    assert _clean_url("https://example.com/" + "AKIA" + "IOSFODNN7EXAMPLE") is None
    assert _clean_rfc3339(12345) is None
    assert _clean_rfc3339("2026-11-01") == "2026-11-01T00:00:00Z"

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    assert apply_agent_yaml_declarations(_rich_aibom(), empty_dir) == []

    # Agent with autonomy_level=None falls back to declared iso_22989_automation or noAssertion.
    ag = AgentComponent(
        bom_ref="agent:decl",
        name="decl-agent",
        autonomy_level=None,
        assurance_level=AssuranceLevel.DECLARED,
    )
    assert spdx_autonomy_presence(ag) == "noAssertion"
    ag.properties["iso_22989_automation"] = "assistance"
    assert spdx_autonomy_presence(ag) == "yes"

    # Existing DECLARED Agent, DataSource, and Model reconciliation + conflicts.
    ds = DataSourceComponent(
        bom_ref="ds:existing",
        name="existing-ds",
        version="1.0",
        license="Apache-2.0",
        assurance_level=AssuranceLevel.DECLARED,
    )
    mdl = ModelComponent(
        bom_ref="model:decl",
        name="decl-model",
        model_type="llm",
        assurance_level=AssuranceLevel.DECLARED,
        properties={"declared_license": "Apache-2.0"},
    )
    ds_blank = DataSourceComponent(
        bom_ref="ds:blank",
        name="blank-ds",
        assurance_level=AssuranceLevel.DECLARED,
    )
    ds_obs = DataSourceComponent(
        bom_ref="ds:obs",
        name="obs-ds",
        version="1.0",
        supplier="ObsOwner",
        license="MIT",
        assurance_level=AssuranceLevel.OBSERVED,
    )
    ag_preset = AgentComponent(
        bom_ref="agent:preset",
        name="preset-agent",
        version="0.9.0",
        supplier="DeclOwner",
        assurance_level=AssuranceLevel.OBSERVED,
        properties={"declared_license": "BSD-3-Clause"},
    )
    bom_decl = AIBOM(components=[ag, ag_preset, ds, ds_blank, ds_obs, mdl])
    (empty_dir / "agent.yml").write_text(
        """
owner: DeclOwner
licenses: Apache-2.0
version: "0.9.0"
automation_level: assistance
datasets:
  - 123
  - {}
  - name: existing-ds
    version: "2.0"
    supplier: DataOwner
    license: MIT
  - name: blank-ds
    license: MIT
  - name: obs-ds
    version: "1.0"
    supplier: ObsOwner
    license: MIT
models:
  - 123
  - {}
  - name: decl-model
    version: "1.1"
    supplier: ModelOwner
    license: MIT
    domain: nlp
    training:
      description: ""
      datasets:
        - unknown-ds
        - existing-ds
        - existing-ds
""",
        encoding="utf-8",
    )
    notices = apply_agent_yaml_declarations(bom_decl, empty_dir)
    assert ag.version == "0.9.0"
    assert ag.supplier == "DeclOwner"
    assert ag.properties["declared_license"] == "Apache-2.0"
    assert ds.supplier == "DataOwner"
    assert ds_blank.license == "MIT"
    assert mdl.version == "1.1"
    assert mdl.supplier == "ModelOwner"
    assert mdl.properties["declared_domain"] == "nlp"
    assert any("license conflict" in n for n in notices)

    bare_dir = tmp_path / "bare"
    bare_dir.mkdir()
    (bare_dir / "agent.yaml").write_text(
        "datasets:\n  - name: bare-ds\nmodels:\n  - name: bare-mdl\n",
        encoding="utf-8",
    )
    bare_bom = AIBOM()
    apply_agent_yaml_declarations(bare_bom, bare_dir)
    assert len(bare_bom.components) == 2

    # CLI error branches: non-native JSON, corrupt JSON, invalid --spdx-namespace, duplicate --author, symlink --project.
    non_native = tmp_path / "foreign.json"
    non_native.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6"}', encoding="utf-8")
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not-json", encoding="utf-8")
    assert (
        CliRunner().invoke(main, ["export-standard", str(non_native), "-f", "spdx"]).exit_code == 1
    )
    assert CliRunner().invoke(main, ["export-standard", str(corrupt), "-f", "spdx"]).exit_code == 1

    bom_path = tmp_path / "valid.json"
    _rich_aibom().save(bom_path)
    assert (
        CliRunner()
        .invoke(
            main,
            [
                "export-standard",
                str(bom_path),
                "-f",
                "spdx",
                "--spdx-namespace",
                "https://spdx.org/forbidden",
            ],
        )
        .exit_code
        == 1
    )
    res_cdx = CliRunner().invoke(
        main,
        [
            "export-standard",
            str(bom_path),
            "-f",
            "cyclonedx",
            "--author",
            "Dup Author",
            "--author",
            "Dup Author",
        ],
    )
    assert res_cdx.exit_code == 0

    # Symlink --project inside CWD prints note and succeeds; escaping CWD fails with exit 2.
    cwd_dir = tmp_path / "work"
    cwd_dir.mkdir()
    in_cwd_target = cwd_dir / "real_proj"
    in_cwd_target.mkdir()
    (in_cwd_target / "agent.yaml").write_text("owner: SymlinkTeam\n", encoding="utf-8")
    in_cwd_link = cwd_dir / "link_in"
    in_cwd_link.symlink_to(in_cwd_target)
    out_cwd_link = cwd_dir / "link_out"
    out_cwd_link.symlink_to(empty_dir)
    monkeypatch.chdir(cwd_dir)
    assert (
        CliRunner()
        .invoke(
            main,
            [
                "export-standard",
                str(bom_path),
                "-f",
                "cyclonedx",
                "--project",
                "link_in",
                "--agent-yaml",
                "agent.yaml",
            ],
        )
        .exit_code
        == 0
    )
    assert (
        CliRunner()
        .invoke(
            main,
            [
                "export-standard",
                str(bom_path),
                "-f",
                "cyclonedx",
                "--project",
                "link_out",
                "--agent-yaml",
                "agent.yml",
            ],
        )
        .exit_code
        == 2
    )
