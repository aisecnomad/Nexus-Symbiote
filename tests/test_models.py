"""Tests for core domain models, enums, hashing, and AIBOM document."""

from __future__ import annotations

import json

import pytest

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge, prepare
from nexus_symbiote.core.enums import (
    AutonomyLevel,
    CapabilityClass,
    ComponentType,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import (
    canonical_json,
    extract_version_pin,
    hash_bytes,
    hash_canonical,
    hash_tool_definition,
)
from nexus_symbiote.core.models import (
    AgentComponent,
    AIBOMMetadata,
    AuthorizationRecord,
    CapabilityDeclaration,
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)


class TestEnums:
    def test_component_types_complete(self):
        assert len(ComponentType) >= 11

    def test_risk_severity_ordering(self):
        assert [severity.value for severity in RiskSeverity] == [
            "critical",
            "high",
            "medium",
            "low",
            "info",
        ]

    def test_serialization_safety_values(self):
        assert SerializationSafety.SAFE.value == "safe"
        assert SerializationSafety.UNSAFE_CODE_EXECUTION.value == "unsafe-code-execution"

    def test_trust_tier_values(self):
        assert TrustTier.INTERNAL_VERIFIED.value == "internal-verified"
        assert TrustTier.UNTRUSTED_PUBLIC.value == "untrusted-public"

    def test_autonomy_levels(self):
        assert AutonomyLevel.L0_CHATBOT.value == "L0-chatbot"
        assert AutonomyLevel.L4_FULLY_AUTONOMOUS.value == "L4-fully-autonomous"


class TestModels:
    def test_agent_component_defaults(self):
        agent = AgentComponent(bom_ref="agent:main", name="my-agent")
        assert agent.component_type == ComponentType.AGENT
        assert agent.autonomy_level is None
        assert agent.trust_tier == TrustTier.UNKNOWN

    def test_tool_component(self):
        tool = ToolComponent(
            bom_ref="tool:read_file",
            name="read_file",
            description_text="Reads a file from disk",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            definition_hash="sha256:abc123",
        )
        assert tool.component_type == ComponentType.TOOL
        assert tool.definition_hash == "sha256:abc123"

    def test_model_component_serialization_safety(self):
        model = ModelComponent(
            bom_ref="model:weights.pt",
            name="weights.pt",
            serialization_format="pytorch",
            serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
        )
        assert model.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION

    def test_mcp_server_component(self):
        mcp = MCPServerComponent(
            bom_ref="mcp:filesystem",
            name="@modelcontextprotocol/server-filesystem",
            transport="stdio",
            tool_count=5,
            version_pinned=True,
        )
        assert mcp.transport == "stdio"
        assert mcp.version_pinned is True

    def test_risk_assessment(self):
        risk = RiskAssessment(
            severity=RiskSeverity.CRITICAL,
            category="serialization_format",
            detail="Uses pickle",
            recommendation="Switch to SafeTensors",
        )
        assert risk.severity == RiskSeverity.CRITICAL

    def test_capability_declaration(self):
        cap = CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM, CapabilityClass.NETWORK],
            egress_domains=["api.example.com"],
        )
        assert len(cap.capabilities) == 2

    def test_authorization_record(self):
        auth = AuthorizationRecord(
            principal="admin@org.com",
            action="invoke",
            resource_scope="production",
            approval_required=True,
        )
        assert auth.approval_required is True

    def test_completeness_claim(self):
        claim = CompletenessClaim(
            scope="full-agent",
            surfaces_scanned=["mcp", "models"],
            surfaces_excluded=["rag"],
        )
        assert claim.scope == "full-agent"

    def test_metadata_defaults(self):
        meta = AIBOMMetadata()
        assert meta.spec_version == "1.2.0"
        assert meta.tool_name == "nexus-symbiote"

    def test_model_roundtrip(self):
        agent = AgentComponent(
            bom_ref="agent:test",
            name="test",
            framework="langchain",
            model_refs=["model:gpt-4o"],
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="test",
                    detail="test detail",
                )
            ],
        )
        data = agent.model_dump(mode="json", exclude_none=True)
        restored = AgentComponent.model_validate(data)
        assert restored.bom_ref == "agent:test"
        assert len(restored.risks) == 1


class TestHashing:
    def test_canonical_json_key_ordering(self):
        result = canonical_json({"b": 1, "a": 2})
        assert result == '{"a":2,"b":1}'

    def test_canonical_json_nested(self):
        result = canonical_json({"z": {"b": 1, "a": 2}, "a": "x"})
        assert result == '{"a":"x","z":{"a":2,"b":1}}'

    def test_canonical_json_string_escaping(self):
        result = canonical_json({"k": 'hello\nworld"!'})
        assert "\\n" in result
        assert '\\"' in result

    def test_canonical_json_null_handling(self):
        result = canonical_json({"a": None, "b": 1})
        assert '"a":null' in result

    def test_canonical_json_float(self):
        result = canonical_json({"v": 1.0})
        assert result == '{"v":1}'

    def test_canonical_json_nan(self):
        with pytest.raises(ValueError):
            canonical_json({"v": float("nan")})

    def test_hash_canonical_deterministic(self):
        h1 = hash_canonical({"b": 1, "a": 2})
        h2 = hash_canonical({"a": 2, "b": 1})
        assert h1 == h2

    def test_hash_canonical_format(self):
        h = hash_canonical({"x": 1})
        assert h.startswith("sha256:")
        assert len(h.split(":")[1]) == 64

    def test_hash_tool_definition(self):
        h = hash_tool_definition("read_file", "Reads a file", {"type": "object"})
        assert h.startswith("sha256:")

    def test_hash_tool_definition_sensitive_to_changes(self):
        h1 = hash_tool_definition("read_file", "Reads a file")
        h2 = hash_tool_definition("read_file", "Reads a file from disk")
        assert h1 != h2

    def test_hash_bytes(self):
        h = hash_bytes(b"hello world")
        assert h.startswith("sha256:")

    def test_extract_version_pin(self):
        assert extract_version_pin("@modelcontextprotocol/server-filesystem@1.2.3") == "1.2.3"
        assert extract_version_pin("package@latest") is None
        assert extract_version_pin("package:latest") is None


class TestAIBOM:
    def test_empty_aibom(self):
        bom = AIBOM()
        assert len(bom.components) == 0
        assert len(bom.dependencies) == 0

    def test_add_component(self):
        bom = AIBOM()
        tool = ToolComponent(bom_ref="tool:test", name="test")
        bom.add_component(tool)
        assert len(bom.components) == 1
        assert bom.get_component("tool:test") is not None

    def test_replace_component_is_explicit(self):
        bom = AIBOM()
        v1 = ToolComponent(bom_ref="tool:test", name="test-v1")
        v2 = ToolComponent(bom_ref="tool:test", name="test-v2")
        bom.add_component(v1)
        bom.replace_component(v2)
        assert len(bom.components) == 1
        assert bom.get_component("tool:test").name == "test-v2"

    def test_get_components_by_type(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(bom_ref="tool:a", name="a"))
        bom.add_component(ToolComponent(bom_ref="tool:b", name="b"))
        bom.add_component(ModelComponent(bom_ref="model:c", name="c"))
        tools = bom.get_components_by_type(ComponentType.TOOL)
        assert len(tools) == 2

    def test_add_dependency(self):
        bom = AIBOM()
        edge = DependencyEdge(
            source_ref="agent:main", target_ref="tool:read", relationship="invokes"
        )
        bom.add_dependency(edge)
        assert len(bom.dependencies) == 1

    def test_get_all_risks(self):
        bom = AIBOM()
        bom.add_component(
            ToolComponent(
                bom_ref="tool:test",
                name="test",
                risks=[
                    RiskAssessment(severity=RiskSeverity.HIGH, category="test", detail="d1"),
                    RiskAssessment(severity=RiskSeverity.LOW, category="test", detail="d2"),
                ],
            )
        )
        risks = bom.get_all_risks()
        assert len(risks) == 2

    def test_finalize_sets_tool_version_only(self):
        # ARCH-F1: finalize() must not stamp a wall-clock timestamp or a
        # random serial; both are export concerns owned by prepare().
        bom = AIBOM()
        bom.finalize()
        assert bom.metadata.tool_version is not None
        assert bom.metadata.timestamp is None
        assert bom.metadata.serial_number is None

    def test_prepare_derives_deterministic_serial(self):
        bom = AIBOM()
        prepare(bom)
        assert bom.metadata.serial_number is not None
        assert bom.metadata.serial_number.startswith("urn:uuid:")
        assert bom.metadata.timestamp is None

    def test_to_json_roundtrip(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(bom_ref="tool:x", name="x"))
        json_str = bom.to_json()
        data = json.loads(json_str)
        assert data["metadata"]["tool_name"] == "nexus-symbiote"
        assert len(data["components"]) == 1

    def test_save_and_load(self, tmp_path):
        bom = AIBOM()
        bom.add_component(ToolComponent(bom_ref="tool:x", name="x"))
        path = tmp_path / "test.aibom.json"
        bom.save(path)
        loaded = AIBOM.load(path)
        assert len(loaded.components) == 1
        assert loaded.get_component("tool:x").name == "x"

    def test_summary(self):
        bom = AIBOM()
        bom.add_component(
            ToolComponent(
                bom_ref="tool:x",
                name="x",
                risks=[RiskAssessment(severity=RiskSeverity.HIGH, category="test", detail="d")],
            )
        )
        s = bom.summary()
        assert s["total_components"] == 1
        assert s["total_risks"] == 1
        assert "high" in s["risk_breakdown"]

    def test_summary_is_json_like_the_summary_command(self):
        from datetime import UTC, datetime

        bom = AIBOM()
        bom.metadata.completeness = CompletenessClaim(
            scope="repository", timestamp=datetime(2026, 1, 1, tzinfo=UTC)
        )
        completeness = json.loads(json.dumps(bom.summary()))["completeness"]
        assert completeness["timestamp"] == "2026-01-01T00:00:00Z"


def test_value_descriptions_name_every_value_a_built_in_collector_emits():
    from nexus_symbiote.core.models import IDEAgentComponent, RegistryEntryComponent
    from nexus_symbiote.scanners.ide_agents import IDE_AGENT_CONFIGS

    ide = IDEAgentComponent.model_fields["ide_type"].description
    assert set(IDE_AGENT_CONFIGS) <= set(ide.split(", "))
    registry = RegistryEntryComponent.model_fields["registry_type"].description
    built_in = registry.split(" from built-in collectors")[0].replace(" or ", ", ").split(", ")
    assert set(built_in) == {"npm", "pypi", "docker-hub", "oci"}


def _emitted_transports() -> set[str]:
    from nexus_symbiote.scanners.mcp import _TRANSPORT_TYPES

    return set(_TRANSPORT_TYPES.values())


def _emitted_prompt_types() -> set[str]:
    from nexus_symbiote.scanners.prompt import (
        INSTRUCTION_DIRECTORIES,
        INSTRUCTION_FILES,
        NESTED_INSTRUCTION_NAMES,
    )

    tables = (INSTRUCTION_FILES, NESTED_INSTRUCTION_NAMES, INSTRUCTION_DIRECTORIES)
    return {kind for table in tables for kind in table.values()} | {"imported-instruction"}


@pytest.mark.parametrize(
    ("model", "field", "emitted"),
    [
        ("MCPServerComponent", "transport", _emitted_transports()),
        ("PromptComponent", "prompt_type", _emitted_prompt_types()),
        (
            "ModelComponent",
            "model_type",
            {"foundation", "adapter", "embedding", "quantized", "hosted"},
        ),
        ("SkillPackageComponent", "skill_type", {"skill", "skill-resource"}),
        ("VerifiedExtensionComponent", "extension_type", {"ide-extension"}),
    ],
    ids=["transport", "prompt_type", "model_type", "skill_type", "extension_type"],
)
def test_value_lists_name_every_value_a_collector_writes(model, field, emitted):
    from nexus_symbiote.core import models

    description = getattr(models, model).model_fields[field].description
    assert emitted <= set(description.split(", "))


def test_claim_descriptions_name_what_collection_records():
    from nexus_symbiote.core.models import DiscoveryVerification

    scope = CompletenessClaim.model_fields["scope"].description
    written = ("repository", "repository+shadowscan", "shadowscan-imported")
    assert all(f" {value}" in scope for value in (*written, "mcp-endpoint-observation"))
    assert "full-agent" not in scope
    fields = DiscoveryVerification.model_fields
    assert "metadata.timestamp" in fields["report_time"].description
    assert "shadowscan:repository" in fields["repository"].description
    assert "shadowscan:commit" in fields["commit"].description
    docstring = " ".join((DiscoveryVerification.__doc__ or "").split())
    assert "``not-applicable`` means no discovery report was imported" in docstring
