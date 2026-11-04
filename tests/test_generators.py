"""Tests for CycloneDX and SPDX generators."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.models import (
    AgentComponent,
    GuardrailComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    ModelComponent,
    PromptComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    SkillPackageComponent,
    ToolComponent,
)
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import validate_cyclonedx


def _sample_aibom() -> AIBOM:
    bom = AIBOM()
    bom.add_component(
        AgentComponent(
            bom_ref="agent:main",
            name="my-agent",
            framework="langchain",
            model_refs=["model:gpt-4o"],
            tool_refs=["tool:read_file"],
        )
    )
    bom.add_component(
        ModelComponent(
            bom_ref="model:gpt-4o",
            name="gpt-4o",
            provider="openai",
            serialization_format="api",
            signing_status="n/a",
        )
    )
    bom.add_component(
        ToolComponent(
            bom_ref="tool:read_file",
            name="read_file",
            description_text="Reads a file",
            definition_hash="sha256:abc123",
        )
    )
    bom.add_component(
        MCPServerComponent(
            bom_ref="mcp:fs",
            name="@modelcontextprotocol/server-filesystem",
            transport="stdio",
            tool_count=3,
            version_pinned=True,
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:main",
            target_ref="tool:read_file",
            relationship="invokes",
        )
    )
    return bom


class TestCycloneDXGenerator:
    def test_generate_structure(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.7"
        assert "serialNumber" in result
        assert len(result["components"]) == 4
        assert result["dependencies"] == []

    def test_component_types_mapped(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        types = {c["name"]: c["type"] for c in result["components"]}
        assert types["gpt-4o"] == "machine-learning-model"
        assert types["read_file"] == "library"
        assert types["@modelcontextprotocol/server-filesystem"] == "application"

    def test_extension_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        agent_comp = next(c for c in result["components"] if c["name"] == "my-agent")
        prop_names = {p["name"] for p in agent_comp.get("properties", [])}
        assert "nexus-symbiote:componentType" in prop_names
        assert "nexus-symbiote:autonomyLevel" in prop_names

    def test_model_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        model_comp = next(c for c in result["components"] if c["name"] == "gpt-4o")
        props = {p["name"]: p["value"] for p in model_comp.get("properties", [])}
        assert props.get("nexus-symbiote:provider") == "openai"

    def test_dependency_mapping(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        assert result["dependencies"] == []
        assert any(
            prop["name"] == "nexus-symbiote:dependency:relationship"
            and json.loads(prop["value"])
            == {"from": "agent:main", "to": "tool:read_file", "type": "invokes"}
            for prop in result["metadata"]["properties"]
        )

    def test_generate_json_valid(self):
        gen = CycloneDXGenerator()
        json_str = gen.generate_json(_sample_aibom())
        data = json.loads(json_str)
        assert data["bomFormat"] == "CycloneDX"

    def test_metadata_tools(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        tools = result["metadata"]["tools"]["components"]
        assert len(tools) == 1
        assert tools[0]["name"] == "nexus-symbiote"


class TestCycloneDXSchemaFormats:
    """These formats are checked where the cyclonedx extra is installed, as in CI.

    A core install leaves their checkers out; see test_format_checker_dependencies.
    """

    def test_export_rejects_a_timestamp_outside_rfc3339(self):
        bom = _sample_aibom()
        # Python allows UTC offsets with seconds; RFC 3339 date-time does not.
        bom.metadata.timestamp = datetime(2026, 11, 1, 12, tzinfo=timezone(timedelta(seconds=30)))
        with pytest.raises(ValueError, match=r"metadata/timestamp: .* is not a 'date-time'"):
            CycloneDXGenerator().generate(bom)

    def test_received_document_formats_are_enforced(self):
        document = CycloneDXGenerator().generate(_sample_aibom())
        document["metadata"]["timestamp"] = "not-a-timestamp"
        document["metadata"]["supplier"] = {"name": "Example", "url": ["https://exa mple.test/"]}
        assert validate_cyclonedx(document) == [
            "metadata/timestamp: 'not-a-timestamp' is not a 'date-time'",
            "metadata/supplier/url/0: 'https://exa mple.test/' is not a 'iri-reference'",
        ]
        with pytest.raises(ValueError, match="invalid cyclonedx export"):
            CycloneDXGenerator.recover(document)


class TestSPDXGenerator:
    def test_generate_structure(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        assert result["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
        graph = result["@graph"]
        doc = graph[0]
        assert doc["type"] == "SpdxDocument"
        assert next(e for e in graph if e["type"] == "CreationInfo")["specVersion"] == "3.0.1"

    def test_element_types(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        elements = result["@graph"][1:]
        types = {e["name"]: e["type"] for e in elements if "name" in e}
        assert types.get("gpt-4o") == "ai_AIPackage"
        assert types.get("read_file") == "software_Package"

    def test_spdx_ids_unique(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        ids = [e.get("spdxId", e.get("@id")) for e in result["@graph"]]
        assert len(ids) == len(set(ids))

    def test_extensions_present(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        elements = [e for e in result["@graph"][1:] if e.get("type") != "Relationship"]
        for elem in elements:
            if "extension" in elem:
                ext = elem["extension"][0]
                assert ext["type"] == "extension_CdxPropertiesExtension"
                assert "nexus-symbiote:component" in {
                    p["extension_cdxPropName"] for p in ext["extension_cdxProperty"]
                }

    def test_relationship_types(self):
        from nexus_symbiote.generators.spdx import NO_ASSERTION_LICENSE

        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        rels = [e for e in result["@graph"] if e.get("type") == "Relationship"]
        license_kinds = {"hasDeclaredLicense", "hasConcludedLicense"}
        dependencies = [rel for rel in rels if rel["relationshipType"] not in license_kinds]
        assert len(dependencies) == 1
        assert dependencies[0]["relationshipType"] == "usesTool"
        licensed_packages = [
            element
            for element in result["@graph"]
            if element.get("type") in {"ai_AIPackage", "dataset_DatasetPackage"}
        ]
        for package in licensed_packages:
            for kind in license_kinds:
                licensing = [
                    rel
                    for rel in rels
                    if rel["relationshipType"] == kind and rel["from"] == package["spdxId"]
                ]
                assert len(licensing) == 1
                assert licensing[0]["to"] == [NO_ASSERTION_LICENSE]

    def test_generate_json_valid(self):
        gen = SPDXGenerator()
        json_str = gen.generate_json(_sample_aibom())
        data = json.loads(json_str)
        assert "@context" in data


def _full_component_aibom() -> AIBOM:
    bom = AIBOM()
    bom.add_component(
        AgentComponent(
            bom_ref="agent:main",
            name="my-agent",
            framework="crewai",
            model_refs=["model:gpt-4o"],
            tool_refs=["tool:read_file"],
        )
    )
    bom.add_component(
        ModelComponent(
            bom_ref="model:gpt-4o",
            name="gpt-4o",
            provider="openai",
            model_type="foundation",
            serialization_format="safetensors",
            serialization_safety=SerializationSafety.SAFE,
            signing_status="sigstore-signed",
            trust_remote_code=True,
            version="4.0",
            supplier="OpenAI",
            description="Large language model",
            hashes={"sha256": "sha256:" + "ab" * 32},
        )
    )
    bom.add_component(
        ToolComponent(
            bom_ref="tool:read_file",
            name="read_file",
            description_text="Reads a file",
            definition_hash="sha256:abc123",
            annotations={"readOnlyHint": True, "openWorldHint": False},
        )
    )
    bom.add_component(
        MCPServerComponent(
            bom_ref="mcp:fs",
            name="filesystem",
            transport="stdio",
            tool_count=3,
            version_pinned=True,
            schema_hash="sha256:sch123",
        )
    )
    bom.add_component(
        PromptComponent(
            bom_ref="prompt:sys",
            name="system-prompt",
            prompt_type="system-prompt",
            content_hash="sha256:ppp",
        )
    )
    bom.add_component(
        GuardrailComponent(
            bom_ref="guard:filter",
            name="content-filter",
            guardrail_type="output-filter",
        )
    )
    bom.add_component(
        MemoryStoreComponent(
            bom_ref="mem:conv",
            name="conversation-store",
            store_type="conversation",
            tenant_isolated=True,
            encryption_at_rest=True,
        )
    )
    bom.add_component(
        RAGSourceComponent(
            bom_ref="rag:docs",
            name="docs-index",
            corpus_type="vector-store",
            embedding_model_name="text-embedding-3-small",
        )
    )
    bom.add_component(
        RegistryEntryComponent(
            bom_ref="reg:npm",
            name="npm-registry",
            registry_type="npm",
            publisher_verified=True,
        )
    )
    bom.add_component(
        SkillPackageComponent(
            bom_ref="skill:deploy",
            name="deploy-skill",
            skill_type="skill",
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:main",
            target_ref="model:gpt-4o",
            relationship="trained-on",
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:main",
            target_ref="tool:read_file",
            relationship="invokes",
        )
    )
    return bom


class TestCycloneDXGeneratorFull:
    def test_all_component_types_present(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        assert len(result["components"]) == 10

    def test_model_all_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        model_comp = next(c for c in result["components"] if c["name"] == "gpt-4o")
        props = {p["name"]: p["value"] for p in model_comp.get("properties", [])}
        assert props["nexus-symbiote:modelType"] == "foundation"
        assert props["nexus-symbiote:serializationFormat"] == "safetensors"
        assert props["nexus-symbiote:serializationSafety"] == "safe"
        assert props["nexus-symbiote:signingStatus"] == "sigstore-signed"
        assert props["nexus-symbiote:trustRemoteCode"] == "True"

    def test_model_version_and_supplier(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        model_comp = next(c for c in result["components"] if c["name"] == "gpt-4o")
        assert model_comp["version"] == "4.0"
        assert model_comp["supplier"]["name"] == "OpenAI"

    def test_model_hashes(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        model_comp = next(c for c in result["components"] if c["name"] == "gpt-4o")
        assert len(model_comp.get("hashes", [])) >= 1

    def test_agent_refs(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        agent_comp = next(c for c in result["components"] if c["name"] == "my-agent")
        props = {p["name"]: p["value"] for p in agent_comp.get("properties", [])}
        assert "nexus-symbiote:modelRef" in props
        assert "nexus-symbiote:toolRef" in props
        assert props["nexus-symbiote:framework"] == "crewai"

    def test_tool_annotation_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        tool_comp = next(c for c in result["components"] if c["name"] == "read_file")
        props = {p["name"]: p["value"] for p in tool_comp.get("properties", [])}
        assert "nexus-symbiote:annotation.readOnlyHint" in props

    def test_mcp_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        mcp_comp = next(c for c in result["components"] if c["name"] == "filesystem")
        props = {p["name"]: p["value"] for p in mcp_comp.get("properties", [])}
        assert props["nexus-symbiote:transport"] == "stdio"
        assert props["nexus-symbiote:toolCount"] == "3"
        assert props["nexus-symbiote:schemaHash"] == "sha256:sch123"

    def test_prompt_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        p = next(c for c in result["components"] if c["name"] == "system-prompt")
        props = {p["name"]: p["value"] for p in p.get("properties", [])}
        assert props["nexus-symbiote:promptType"] == "system-prompt"
        assert props["nexus-symbiote:contentHash"] == "sha256:ppp"

    def test_guardrail_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        g = next(c for c in result["components"] if c["name"] == "content-filter")
        props = {p["name"]: p["value"] for p in g.get("properties", [])}
        assert props["nexus-symbiote:guardrailType"] == "output-filter"

    def test_memory_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        m = next(c for c in result["components"] if c["name"] == "conversation-store")
        props = {p["name"]: p["value"] for p in m.get("properties", [])}
        assert props["nexus-symbiote:storeType"] == "conversation"
        assert props["nexus-symbiote:tenantIsolated"] == "True"
        assert props["nexus-symbiote:encryptionAtRest"] == "True"

    def test_rag_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        r = next(c for c in result["components"] if c["name"] == "docs-index")
        props = {p["name"]: p["value"] for p in r.get("properties", [])}
        assert props["nexus-symbiote:corpusType"] == "vector-store"
        assert props["nexus-symbiote:embeddingModel"] == "text-embedding-3-small"

    def test_registry_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        r = next(c for c in result["components"] if c["name"] == "npm-registry")
        props = {p["name"]: p["value"] for p in r.get("properties", [])}
        assert props["nexus-symbiote:registryType"] == "npm"
        assert props["nexus-symbiote:publisherVerified"] == "True"

    def test_skill_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        s = next(c for c in result["components"] if c["name"] == "deploy-skill")
        props = {p["name"]: p["value"] for p in s.get("properties", [])}
        assert props["nexus-symbiote:skillType"] == "skill"

    def test_multiple_dependency_types(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        assert result["dependencies"] == []
        recovered = CycloneDXGenerator.recover(result)
        assert {d.relationship for d in recovered.dependencies} == {"trained-on", "invokes"}

    def test_authors_in_metadata(self):
        bom = _full_component_aibom()
        bom.metadata.authors = ["Alice", "Bob"]
        gen = CycloneDXGenerator()
        result = gen.generate(bom)
        authors = result["metadata"]["authors"]
        assert len(authors) == 2
        assert authors[0]["name"] == "Alice"


class TestSPDXGeneratorFull:
    def test_all_element_types(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        graph = result["@graph"]
        types = {e.get("name"): e["type"] for e in graph if "name" in e}
        assert types["my-agent"] == "ai_AIPackage"
        assert types["conversation-store"] == "dataset_DatasetPackage"
        assert types["docs-index"] == "dataset_DatasetPackage"
        assert types["content-filter"] == "software_Package"

    def test_trained_on_relationship(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        rels = [e for e in result["@graph"] if e.get("type") == "Relationship"]
        rel_types = {r["relationshipType"] for r in rels}
        assert "trainedOn" in rel_types
        assert "usesTool" in rel_types

    def test_model_extensions(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        model = next(e for e in result["@graph"] if e.get("name") == "gpt-4o")
        ext = model["extension"][0]
        component = json.loads(ext["extension_cdxProperty"][0]["extension_cdxPropValue"])
        assert component["serialization_format"] == "safetensors"
        assert component["signing_status"] == "sigstore-signed"

    def test_supplier_mapped(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        model = next(e for e in result["@graph"] if e.get("name") == "gpt-4o")
        assert "suppliedBy" in model
        assert (
            next(e for e in result["@graph"] if e.get("spdxId") == model["suppliedBy"])["name"]
            == "OpenAI"
        )

    def test_hashes_mapped(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        model = next(e for e in result["@graph"] if e.get("name") == "gpt-4o")
        assert "verifiedUsing" in model
        assert model["verifiedUsing"][0]["type"] == "Hash"
