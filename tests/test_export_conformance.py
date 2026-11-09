"""Standards and security semantics are tested with complete documents and independent consumers."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    IDEAgentComponent,
    MCPClientComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    ModelComponent,
    PromptComponent,
    RiskAssessment,
    ToolComponent,
    VerifiedExtensionComponent,
)
from nexus_symbiote.generators._common import native_document
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import validate_cyclonedx, validate_spdx


def fixture_bom() -> AIBOM:
    bom = AIBOM()
    bom.metadata.timestamp = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    bom.components = [
        AgentComponent(
            bom_ref="agent:main",
            name="main",
            authorizations=[
                AuthorizationRecord(principal="user:alice", action="send", approval_required=True),
            ],
        ),
        ToolComponent(
            bom_ref="tool:send",
            name="send",
            annotations={"destructiveHint": False},
            capabilities=CapabilityDeclaration(egress_domains=["internal.example"]),
            hashes={"sha256": "sha256:" + "ab" * 32},
        ),
        ModelComponent(
            bom_ref="model:one",
            name="one",
            supplier="Supplier with spaces",
            model_type="language-model",
        ),
        MemoryStoreComponent(bom_ref="memory:one", name="one", tenant_isolated=False),
        PromptComponent(bom_ref="prompt:one", name="one"),
        MCPServerComponent(bom_ref="server:one", name="one", version_pinned=False),
    ]
    bom.dependencies = [
        DependencyEdge(source_ref="agent:main", target_ref="tool:send", relationship="invokes"),
        DependencyEdge(source_ref="agent:main", target_ref="model:one", relationship="depends-on"),
    ]
    return bom


@pytest.mark.parametrize(
    "generator,validator",
    [(CycloneDXGenerator, validate_cyclonedx), (SPDXGenerator, validate_spdx)],
)
def test_complete_document_validates_and_is_deterministic(generator, validator):
    bom = fixture_bom()
    exporter = generator()
    document = exporter.generate(bom)
    assert validator(document) == []
    assert exporter.generate(bom) == document
    reordered = bom.model_copy(deep=True)
    reordered.components.reverse()
    reordered.dependencies.reverse()
    assert exporter.generate(reordered) == document


@pytest.mark.parametrize("generator", [CycloneDXGenerator, SPDXGenerator])
def test_authority_and_false_values_round_trip(generator):
    bom = fixture_bom()
    exporter = generator()
    first = exporter.generate(bom)
    recovered = exporter.recover(first)
    assert native_document(recovered) == native_document(bom)
    tool = bom.get_component("tool:send")
    agent = bom.get_component("agent:main")
    tool.capabilities.egress_domains = ["external.example"]
    agent.authorizations[0].approval_required = False
    second = exporter.generate(bom)
    assert second != first
    roundtrip = exporter.recover(second)
    assert roundtrip.get_component("agent:main").authorizations[0].approval_required is False
    assert roundtrip.get_component("tool:send").annotations["destructiveHint"] is False
    assert roundtrip.get_component("tool:send").capabilities.egress_domains == ["external.example"]
    report = exporter.generate_with_report(bom).loss_report
    assert report["nativeSemanticsComplete"] is False
    assert report["extensionRoundTripComplete"] is True
    assert report["admissionAuthority"] is False


def test_cdx_preserves_false_annotations_and_merges_adjacency():
    bom = fixture_bom()
    document = CycloneDXGenerator().generate(bom)
    assert len(document["dependencies"]) == 1
    props = next(c for c in document["components"] if c["bom-ref"] == "tool:send")["properties"]
    assert {p["name"]: p["value"] for p in props}[
        "nexus-symbiote:annotation.destructiveHint"
    ] == "False"
    assert "properties" not in document["dependencies"][0]


def test_spdx_references_are_resolved_and_qualified():
    document = SPDXGenerator().generate(fixture_bom())
    assert validate_spdx(document) == []
    assert any(n["type"] == "dataset_DatasetPackage" for n in document["@graph"])
    assert any(n.get("relationshipType") == "usesTool" for n in document["@graph"])
    document["@graph"][0]["element"].append("urn:missing")
    assert any("unresolved" in e for e in validate_spdx(document))


def test_spdx_aggregation_keeps_revisions_and_references_distinct():
    bom = fixture_bom()
    # A producer can update a BOM without changing its serial number or local references.
    bom.metadata.serial_number = "urn:uuid:be293054-64c2-494e-87f6-fceeaabe4a85"
    exporter = SPDXGenerator()
    graphs = []
    versions = ("1.2.3", "9.8.7")
    for version in versions:
        bom.get_component("tool:send").version = version
        graphs.append(exporter.generate(bom)["@graph"])

    combined = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [*graphs[0], *graphs[1]],
    }
    assert validate_spdx(combined) == []
    nodes = {node.get("spdxId", node.get("@id")): node for node in combined["@graph"]}
    assert len(nodes) == len(combined["@graph"])
    for graph, version in zip(graphs, versions, strict=True):
        document = graph[0]
        (root,) = document["rootElement"]
        (edge,) = (
            nodes[ref]
            for ref in document["element"]
            if nodes[ref].get("relationshipType") == "usesTool"
        )
        assert edge["from"] == root
        (tool,) = edge["to"]
        assert tool in document["element"]
        assert nodes[tool]["software_packageVersion"] == version
        assert nodes[tool]["creationInfo"] == document["creationInfo"]


def test_spdx_independent_consumer_round_trip():
    from spdx_python_model.bindings import v3_0_1 as spdx

    original = fixture_bom()
    document = SPDXGenerator().generate(original)
    objects = spdx.SHACLObjectSet()
    spdx.JSONLDDeserializer().read(io.BytesIO(json.dumps(document).encode()), objects)
    output = io.BytesIO()
    spdx.JSONLDSerializer().write(objects, output)
    consumed = json.loads(output.getvalue())
    assert validate_spdx(consumed) == []
    assert native_document(SPDXGenerator.recover(consumed)) == native_document(original)


def test_cdx_independent_consumer_round_trip():
    from cyclonedx.model.bom import Bom
    from cyclonedx.output.json import JsonV1Dot7

    original = fixture_bom()
    document = CycloneDXGenerator().generate(original)
    consumed = Bom.from_json(document)
    assert consumed is not None
    output = json.loads(JsonV1Dot7(consumed).output_as_string())
    assert validate_cyclonedx(output) == []
    assert native_document(CycloneDXGenerator.recover(output)) == native_document(original)


def test_cdx_partial_coverage_through_independent_consumer():
    """A reader cannot silently weaken incomplete coverage and still recover the BOM."""
    from cyclonedx.model.bom import Bom
    from cyclonedx.output.json import JsonV1Dot7

    from nexus_symbiote.core.models import CompletenessClaim

    original = fixture_bom()
    original.metadata.completeness = CompletenessClaim(scope="partial")
    document = CycloneDXGenerator().generate(original)
    assert document["compositions"] == [{"aggregate": "incomplete"}]
    consumed = Bom.from_json(document)
    assert consumed is not None
    output = json.loads(JsonV1Dot7(consumed).output_as_string())
    assert validate_cyclonedx(output) == []
    if output.get("compositions") == document["compositions"]:
        assert native_document(CycloneDXGenerator.recover(output)) == native_document(original)
    else:
        with pytest.raises(ValueError, match="projection conflicts"):
            CycloneDXGenerator.recover(output)


def test_spdx_partial_coverage_through_independent_consumer():
    from spdx_python_model.bindings import v3_0_1 as spdx

    from nexus_symbiote.core.models import CompletenessClaim

    original = fixture_bom()
    original.metadata.completeness = CompletenessClaim(scope="partial")
    document = SPDXGenerator().generate(original)
    objects = spdx.SHACLObjectSet()
    spdx.JSONLDDeserializer().read(io.BytesIO(json.dumps(document).encode()), objects)
    output = io.BytesIO()
    spdx.JSONLDSerializer().write(objects, output)
    consumed = json.loads(output.getvalue())
    assert validate_spdx(consumed) == []
    assert native_document(SPDXGenerator.recover(consumed)) == native_document(original)
    edges = [
        n
        for n in consumed["@graph"]
        if n.get("type") == "Relationship" and n.get("relationshipType") == "usesTool"
    ]
    assert edges and all(edge.get("completeness") == "incomplete" for edge in edges)


@pytest.mark.parametrize("generator", [CycloneDXGenerator, SPDXGenerator])
def test_invalid_hash_and_reference_fail_closed(generator):
    bom = fixture_bom()
    bom.components[1].hashes = {"sha256": "sha256:123"}
    with pytest.raises(ValueError, match="digest"):
        generator().generate(bom)
    bom = fixture_bom()
    bom.dependencies[0].target_ref = "tool:missing"
    with pytest.raises(ValueError, match="unknown"):
        generator().generate(bom)


def test_embedded_document_tamper_fails_digest_check():
    document = CycloneDXGenerator().generate(fixture_bom())
    props = document["metadata"]["properties"]
    native_property = next(p for p in props if p["name"] == "nexus-symbiote:document")
    native = json.loads(native_property["value"])
    native["components"][0]["name"] = "tampered"
    native_property["value"] = json.dumps(native)
    with pytest.raises(ValueError, match="digest mismatch"):
        CycloneDXGenerator.recover(document)


def test_sarif_has_stable_fingerprints_and_relative_encoded_paths(tmp_path: Path):
    bom = fixture_bom()
    tool = bom.get_component("tool:send")
    tool.source_path = str(tmp_path / "config with spaces.json")
    tool.risks = [
        RiskAssessment(severity=RiskSeverity.HIGH, category="unpinned", detail="Unpinned tool")
    ]
    exporter = SARIFGenerator(root=tmp_path)
    document = exporter.generate(bom)
    assert document == exporter.generate(bom)
    run = document["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"
    result = run["results"][0]
    assert result["partialFingerprints"]["nexus_symbiote/v1"]
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "config%20with%20spaces.json"
    )
    tool.source_path = "/outside/secret/config.json"
    assert "locations" not in exporter.generate(bom)["runs"][0]["results"][0]


def test_export_validation_is_offline(monkeypatch):
    import socket

    def denied(*args, **kwargs):
        raise AssertionError("export validation attempted network access")

    monkeypatch.setattr(socket.socket, "connect", denied)
    assert validate_cyclonedx(CycloneDXGenerator().generate(fixture_bom())) == []
    assert validate_spdx(SPDXGenerator().generate(fixture_bom())) == []


def test_invalid_input_documents_return_errors_instead_of_crashing():
    assert validate_cyclonedx({"components": [None]})
    assert validate_spdx({"@graph": [None]})


def test_sarif_loss_report_does_not_claim_inventory_round_trip():
    report = SARIFGenerator().generate_with_report(fixture_bom()).loss_report
    assert report["extensionRoundTripComplete"] is False
    assert report["items"][0]["preservedIn"] is None


@pytest.mark.parametrize("generator", [CycloneDXGenerator, SPDXGenerator])
def test_new_client_server_ide_and_extension_types_round_trip_without_trust_upgrade(generator):
    from nexus_symbiote.core.evidence import AuthorityClaim, DeploymentProfile, EvidenceRecord

    bom = fixture_bom()
    now = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    evidence = EvidenceRecord(
        source="iam:policy:42",
        collector="supplier-reported",
        collected_at=now,
        subject_digest="sha256:" + "a" * 64,
        verification_status="verified",
        verifier="supplier-verifier",
        verification_policy="supplier-policy",
        verified_at=now,
    )
    bom.get_component("agent:main").deployment_profile = DeploymentProfile(
        deployment_id="prod:agent:v1",
        environment="production",
        tenant="tenant:one",
        workload_identity="workload:one",
        authority=[
            AuthorityClaim(
                kind="effective",
                state="verified",
                principal="workload:one",
                action="read",
                resource="resource:one",
                evidence=[evidence],
            )
        ],
    )
    additions = [
        MCPClientComponent(bom_ref="client:mcp", name="mcp-client", server_refs=["server:one"]),
        A2AClientComponent(
            bom_ref="client:a2a", name="a2a-client", agent_card_url="https://example.com/card.json"
        ),
        A2AServerComponent(
            bom_ref="server:a2a",
            name="a2a-server",
            endpoint_url="https://example.com/a2a",
            authentication_required=False,
        ),
        IDEAgentComponent(bom_ref="ide:one", name="ide-agent", ide_type="claude-code"),
        VerifiedExtensionComponent(
            bom_ref="extension:one",
            name="claimed-verified-extension",
            publisher_verified=True,
            attestation_status="verified",
        ),
    ]
    for component in additions:
        bom.add_component(component)
    exporter = generator()
    result = exporter.generate_with_report(bom)
    restored = exporter.recover(result.document)
    assert native_document(restored) == native_document(bom)
    for component in additions:
        assert type(restored.get_component(component.bom_ref)) is type(component)
    assert (
        restored.get_component("agent:main").deployment_profile.authority[0].evidence[0].verifier
        == "supplier-verifier"
    )
    assert result.loss_report["admissionAuthority"] is False
    if generator is CycloneDXGenerator:
        extension = next(
            c for c in result.document["components"] if c["bom-ref"] == "extension:one"
        )
        assert extension["type"] == "library"
        properties = {p["name"]: p["value"] for p in extension["properties"]}
    else:
        extension = next(
            c for c in result.document["@graph"] if c.get("name") == "claimed-verified-extension"
        )
        assert extension["type"] == "software_Package"
        properties = {
            p["extension_cdxPropName"]: p["extension_cdxPropValue"]
            for p in extension["extension"][0]["extension_cdxProperty"]
        }
    assert properties["agentbom:kind"] == "verified-extension"
    assert properties["agentbom:claimsVerifiedByExporter"] == "false"


@pytest.mark.parametrize("generator", [CycloneDXGenerator, SPDXGenerator])
def test_security_field_loss_report_tracks_normalized_paths(generator):
    from nexus_symbiote.core.evidence import AuthorityClaim, DeploymentProfile
    from nexus_symbiote.core.models import CompletenessClaim
    from nexus_symbiote.generators._common import content_digest

    bom = fixture_bom()
    bom.metadata.completeness = CompletenessClaim(scope="partial")
    bom.get_component("agent:main").deployment_profile = DeploymentProfile(
        deployment_id="deployment:one",
        environment="production",
        authority=[AuthorityClaim(kind="effective", state="unknown", unknown_reason="no access")],
    )
    bom.dependencies[0].assurance_level = "observed"
    bom.dependencies[0].conditions = "conditional"
    result = generator().generate_with_report(bom)
    source = native_document(bom)
    report = result.loss_report
    assert report["sourceDigest"] == content_digest(source)
    assert report["itemCoverage"] == "selected-security-fields"
    assert report["nativeSemanticsComplete"] is False
    assert report["items"][0]["path"] == ""
    # Each JSON Pointer resolves in the exact sorted document named by sourceDigest.
    for item in report["items"]:
        value = source
        path = item["path"]
        if path:
            assert path.startswith("/")
            for token in path[1:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                value = value[int(token)] if isinstance(value, list) else value[token]
        assert value is not None
    paths = {item["path"] for item in report["items"]}
    assert "/metadata/completeness" in paths
    agent_index = next(
        i for i, c in enumerate(source["components"]) if c["bom_ref"] == "agent:main"
    )
    assert f"/components/{agent_index}/deployment_profile" in paths
    assert f"/components/{agent_index}/authorizations" in paths
    edge_index = next(i for i, e in enumerate(source["dependencies"]) if e.get("conditions"))
    assert f"/dependencies/{edge_index}/relationship" in paths
    assert f"/dependencies/{edge_index}/conditions" in paths
    assert f"/dependencies/{edge_index}/assurance_level" in paths
    # Reports name paths and limitations, not sensitive values.
    assert "deployment:one" not in json.dumps(report)
    assert "user:alice" not in json.dumps(report)
    assert native_document(generator.recover(result.document)) == source


@pytest.mark.parametrize("generator", [CycloneDXGenerator, SPDXGenerator])
def test_missing_native_extension_fails_closed(generator):
    document = generator().generate(fixture_bom())
    if generator is CycloneDXGenerator:
        properties = document["metadata"]["properties"]
        properties[:] = [p for p in properties if p["name"] != "nexus-symbiote:document"]
    else:
        doc = next(n for n in document["@graph"] if n["type"] == "SpdxDocument")
        properties = doc["extension"][0]["extension_cdxProperty"]
        properties[:] = [
            p for p in properties if p["extension_cdxPropName"] != "nexus-symbiote:document"
        ]
    with pytest.raises(ValueError, match="missing native document"):
        generator.recover(document)


@pytest.mark.parametrize("generator", [CycloneDXGenerator, SPDXGenerator])
def test_deployment_profile_survives_independent_consumer(generator):
    from nexus_symbiote.core.evidence import AuthorityClaim, DeploymentProfile

    original = fixture_bom()
    original.get_component("agent:main").deployment_profile = DeploymentProfile(
        deployment_id="deployment:one",
        environment="production",
        authority=[AuthorityClaim(kind="effective", state="unknown", unknown_reason="no access")],
    )
    document = generator().generate(original)
    if generator is CycloneDXGenerator:
        from cyclonedx.model.bom import Bom
        from cyclonedx.output.json import JsonV1Dot7

        output = json.loads(JsonV1Dot7(Bom.from_json(document)).output_as_string())
        assert validate_cyclonedx(output) == []
        properties = output["metadata"]["properties"]
        report_text = next(
            p["value"] for p in properties if p["name"] == "nexus-symbiote:lossReport"
        )
    else:
        from spdx_python_model.bindings import v3_0_1 as spdx

        objects = spdx.SHACLObjectSet()
        spdx.JSONLDDeserializer().read(io.BytesIO(json.dumps(document).encode()), objects)
        buffer = io.BytesIO()
        spdx.JSONLDSerializer().write(objects, buffer)
        output = json.loads(buffer.getvalue())
        assert validate_spdx(output) == []
        doc = next(n for n in output["@graph"] if n["type"] == "SpdxDocument")
        properties = doc["extension"][0]["extension_cdxProperty"]
        report_text = next(
            p["extension_cdxPropValue"]
            for p in properties
            if p["extension_cdxPropName"] == "nexus-symbiote:lossReport"
        )
    assert json.loads(report_text)["itemCoverage"] == "selected-security-fields"
    assert native_document(generator.recover(output)) == native_document(original)
