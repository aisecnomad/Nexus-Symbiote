"""CycloneDX 1.7 output generator.

Maps AgentBOM components to CycloneDX 1.7 JSON, extending the standard
with agent-specific property taxonomies under the nexus-symbiote: namespace.
"""

from __future__ import annotations

from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
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
from nexus_symbiote.generators._common import (
    claim_properties,
    component_property,
    document_properties,
    json_text,
    normalize_hash,
    prepare,
    recover_document,
    unordered_projection,
)
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.package_identifiers import (
    package_identifier,
    package_identifier_properties,
)
from nexus_symbiote.generators.validation import (
    require_inventory_limits,
    require_received_limits,
    require_valid,
)

COMPONENT_TYPE_MAP: dict[ComponentType, str] = {
    ComponentType.AGENT: "application",
    ComponentType.MODEL: "machine-learning-model",
    ComponentType.TOOL: "library",
    ComponentType.MCP_SERVER: "application",
    ComponentType.MCP_CLIENT: "application",
    ComponentType.A2A_CLIENT: "application",
    ComponentType.A2A_SERVER: "application",
    ComponentType.IDE_AGENT: "application",
    ComponentType.VERIFIED_EXTENSION: "library",
    ComponentType.PROMPT_TEMPLATE: "data",
    ComponentType.GUARDRAIL_POLICY: "library",
    ComponentType.MEMORY_STORE: "data",
    ComponentType.RAG_SOURCE: "data",
    ComponentType.DATA_SOURCE: "data",
    ComponentType.REGISTRY_ENTRY: "platform",
    ComponentType.SKILL_PACKAGE: "library",
}


class CycloneDXGenerator(Generator):
    format_name = "cyclonedx-1.7"

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        document = self._projection(aibom)
        require_valid(document, "cyclonedx")
        return document

    def _projection(self, aibom: AIBOM) -> dict[str, Any]:
        prepare(aibom)
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": aibom.metadata.version,
            "serialNumber": aibom.metadata.serial_number,
            "metadata": self._metadata(aibom),
            "components": [
                self._component(c) for c in sorted(aibom.components, key=lambda c: c.bom_ref)
            ],
            "dependencies": self._dependencies(aibom),
        }
        claim = aibom.metadata.completeness
        if claim and claim.source_report_digest:
            document["compositions"] = [{"aggregate": "incomplete"}]
        return document

    @staticmethod
    def _dependencies(aibom: AIBOM, *, historical: bool = False) -> list[dict[str, Any]]:
        adjacency: dict[str, set[str]] = {}
        for edge in aibom.dependencies:
            # The standard dependency graph cannot convey conditions, offered
            # capabilities, lineage or authority. Preserve those in the typed
            # extension only. The historical exporter flattened *every* edge.
            if historical or (edge.relationship == "depends-on" and not edge.conditions):
                adjacency.setdefault(edge.source_ref, set()).add(edge.target_ref)
        return [
            {"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(adjacency.items())
        ]

    @staticmethod
    def _public_view(document: dict[str, Any], native: AIBOM) -> dict[str, Any]:
        view = dict(document)
        # The upstream SDK supplies the schema hint and a ref-only row for each
        # component without emitted edges. Such a row declares that the component
        # has no dependencies, which a native depends-on edge contradicts even when
        # its conditions keep it out of the standard graph. Never discard targets.
        if view.get("$schema") == "http://cyclonedx.org/schema/bom-1.7.schema.json":
            del view["$schema"]
        view.setdefault("components", [])
        dependent = {
            edge.source_ref for edge in native.dependencies if edge.relationship == "depends-on"
        }
        independent = {component.bom_ref for component in native.components} - dependent
        rows = view.get("dependencies", [])
        if isinstance(rows, list):
            view["dependencies"] = [
                row
                for row in rows
                if not (
                    isinstance(row, dict)
                    and list(row) == ["ref"]
                    and isinstance(row["ref"], str)
                    and row["ref"] in independent
                )
            ]
        return view

    @classmethod
    def recover(
        cls, document: dict[str, Any], *, allow_legacy_relationships: bool = False
    ) -> AIBOM:
        """Require agreement with the embedded inventory; legacy mode checks the exact old graph."""
        require_received_limits(document, "cyclonedx")
        metadata = document.get("metadata", {})
        properties = metadata.get("properties", []) if isinstance(metadata, dict) else None
        if not isinstance(properties, list) or not all(
            isinstance(prop, dict)
            and isinstance(prop.get("name"), str)
            and isinstance(prop.get("value", ""), str)
            for prop in properties
        ):
            raise ValueError("invalid CycloneDX metadata properties")
        recovered = recover_document(properties)
        require_inventory_limits(recovered)
        exporter = cls()
        expected = exporter._projection(recovered)
        actual = cls._public_view(document, recovered)
        if allow_legacy_relationships and unordered_projection(
            actual["dependencies"]
        ) == unordered_projection(cls._dependencies(recovered, historical=True)):
            expected["dependencies"] = actual["dependencies"]
        if unordered_projection(actual) != unordered_projection(
            cls._public_view(expected, recovered)
        ):
            raise ValueError("CycloneDX projection conflicts with the embedded native document")
        # Costly schema validation runs only on what this generator emits for a
        # bounded inventory, never on arbitrary received content.
        require_valid(document, "cyclonedx")
        return recovered

    def _metadata(self, aibom: AIBOM) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "timestamp": (
                aibom.metadata.timestamp.isoformat() if aibom.metadata.timestamp else None
            ),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": aibom.metadata.tool_name,
                        "version": aibom.metadata.tool_version or "unknown",
                        "publisher": aibom.metadata.tool_vendor,
                    }
                ]
            },
        }
        if aibom.metadata.authors:
            meta["authors"] = [{"name": a} for a in aibom.metadata.authors]
        edges = sorted(
            {
                json_text(
                    {"from": edge.source_ref, "to": edge.target_ref, "type": edge.relationship}
                )
                for edge in aibom.dependencies
            }
        )
        meta["properties"] = [
            {"name": "nexus-symbiote:dependency:relationship", "value": edge} for edge in edges
        ] + document_properties(aibom, self.format_name)
        claim = aibom.metadata.completeness
        if claim and claim.source_report_digest:
            meta["properties"].extend(
                [
                    {
                        "name": "nexus-symbiote:discovery:reportSha256",
                        "value": claim.source_report_digest,
                    },
                    {
                        "name": "nexus-symbiote:discovery:sourceFormat",
                        "value": claim.source_report_format or "unknown",
                    },
                    {
                        "name": "nexus-symbiote:discovery:sourceStatus",
                        "value": claim.source_report_status or "unknown",
                    },
                    {
                        "name": "nexus-symbiote:discovery:unmappedCount",
                        "value": str(claim.source_unmapped_count),
                    },
                ]
            )
        return meta

    def _component(self, comp: AnyComponent) -> dict[str, Any]:
        cdx_type = COMPONENT_TYPE_MAP.get(comp.component_type, "library")
        result: dict[str, Any] = {
            "type": cdx_type,
            "bom-ref": comp.bom_ref,
            "name": comp.name,
        }
        if comp.version:
            result["version"] = comp.version
        if comp.supplier:
            result["supplier"] = {"name": comp.supplier}
        if comp.description:
            result["description"] = comp.description
        package = package_identifier(comp)
        if package.value is not None:
            result["purl"] = package.value
            if package.version is not None:
                result["version"] = package.version
        if comp.hashes:
            result["hashes"] = [
                {"alg": normalize_hash(alg, val)[0], "content": normalize_hash(alg, val)[1]}
                for alg, val in comp.hashes.items()
                if val
            ]

        props = self._extension_properties(comp)
        if props:
            result["properties"] = props

        return result

    def _extension_properties(self, comp: AnyComponent) -> list[dict[str, str]]:
        props: list[dict[str, str]] = []

        def _add(name: str, value: Any) -> None:
            if value is not None and value != "":
                props.append({"name": f"nexus-symbiote:{name}", "value": str(value)})

        _add("componentType", comp.component_type.value)
        _add("trustTier", comp.trust_tier.value)
        _add("assuranceLevel", comp.assurance_level.value)

        if isinstance(comp, AgentComponent):
            _add(
                "autonomyLevel",
                comp.autonomy_level.value if comp.autonomy_level is not None else "unknown",
            )
            _add("framework", comp.framework)
            for ref in comp.model_refs:
                _add("modelRef", ref)
            for ref in comp.tool_refs:
                _add("toolRef", ref)
        elif isinstance(comp, ModelComponent):
            _add("modelType", comp.model_type)
            _add("provider", comp.provider)
            _add("serializationFormat", comp.serialization_format)
            _add("serializationSafety", comp.serialization_safety.value)
            _add("signingStatus", comp.signing_status)
            _add("trustRemoteCode", comp.trust_remote_code)
        elif isinstance(comp, ToolComponent):
            _add("definitionHash", comp.definition_hash)
            _add("definitionHashVersion", comp.definition_hash_version)
            if comp.annotations:
                for k, v in comp.annotations.items():
                    _add(f"annotation.{k}", v)
        elif isinstance(comp, MCPServerComponent):
            _add("transport", comp.transport)
            _add("toolCount", comp.tool_count)
            _add("versionPinned", comp.version_pinned)
            _add("schemaHash", comp.schema_hash)
        elif isinstance(comp, PromptComponent):
            _add("promptType", comp.prompt_type)
            _add("contentHash", comp.content_hash)
        elif isinstance(comp, GuardrailComponent):
            _add("guardrailType", comp.guardrail_type)
        elif isinstance(comp, MemoryStoreComponent):
            _add("storeType", comp.store_type)
            _add("tenantIsolated", comp.tenant_isolated)
            _add("encryptionAtRest", comp.encryption_at_rest)
        elif isinstance(comp, RAGSourceComponent):
            _add("corpusType", comp.corpus_type)
            _add("embeddingModel", comp.embedding_model_name)
        elif isinstance(comp, RegistryEntryComponent):
            _add("registryType", comp.registry_type)
            _add("publisherVerified", comp.publisher_verified)
        elif isinstance(comp, SkillPackageComponent):
            _add("skillType", comp.skill_type)

        props.append(component_property(comp))
        props.extend(claim_properties(comp))
        props.extend(package_identifier_properties(comp))

        return props
