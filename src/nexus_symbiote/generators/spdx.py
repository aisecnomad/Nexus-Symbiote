"""Validated SPDX 3.0.1 projection with a digest-bound native document extension."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC
from typing import Any

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import AnyComponent, ModelComponent
from nexus_symbiote.generators._common import (
    NAMESPACE,
    claim_properties,
    component_property,
    content_digest,
    document_properties,
    json_text,
    native_document,
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

SPDX_TYPE_MAP = {
    ComponentType.AGENT: "ai_AIPackage",
    ComponentType.MODEL: "ai_AIPackage",
    ComponentType.PROMPT_TEMPLATE: "software_File",
    ComponentType.MEMORY_STORE: "dataset_DatasetPackage",
    ComponentType.RAG_SOURCE: "dataset_DatasetPackage",
    ComponentType.DATA_SOURCE: "dataset_DatasetPackage",
}


NO_ASSERTION_LICENSE = "https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _extension(properties: list[dict[str, str]]) -> list[dict[str, Any]]:
    return [
        {
            "type": "extension_CdxPropertiesExtension",
            "extension_cdxProperty": [
                {
                    "type": "extension_CdxPropertyEntry",
                    "extension_cdxPropName": prop["name"],
                    "extension_cdxPropValue": prop["value"],
                }
                for prop in properties
            ],
        }
    ]


@dataclass(frozen=True)
class _DocumentIds:
    document: str

    @property
    def creation(self) -> str:
        return self.document + "#creation"

    def element(self, kind: str, key: str) -> str:
        return f"{self.document}#{kind}-{uuid.uuid5(NAMESPACE, key)}"


class SPDXGenerator(Generator):
    format_name = "spdx-3.0.1"

    def __init__(self, namespace: str = "https://spdx.org/spdxdocs/nexus_symbiote") -> None:
        self._namespace = namespace.rstrip("/")

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        document = self._projection(aibom)
        require_valid(document, "spdx")
        return document

    def _projection(self, aibom: AIBOM) -> dict[str, Any]:
        prepare(aibom)
        # Native refs are BOM-local, and producers can reuse serial numbers across revisions.
        revision = content_digest(native_document(aibom)).removeprefix("sha256:")
        ids = _DocumentIds(f"{self._namespace}/document/{revision}")
        ci = ids.creation
        producer_id = ids.element("producer", aibom.metadata.tool_name)
        tool_id = ids.element("generator", aibom.metadata.tool_name)
        creator = {
            "type": "SoftwareAgent",
            "spdxId": producer_id,
            "creationInfo": ci,
            "name": aibom.metadata.tool_name,
        }
        generator = {
            "type": "Tool",
            "spdxId": tool_id,
            "creationInfo": ci,
            "name": aibom.metadata.tool_name,
            "summary": aibom.metadata.tool_version,
        }
        assert aibom.metadata.timestamp is not None
        try:
            created = aibom.metadata.timestamp.astimezone(UTC)
        except OverflowError as exc:
            raise ValueError("export timestamp cannot be represented in UTC") from exc
        creation = {
            "type": "CreationInfo",
            "@id": ci,
            "specVersion": "3.0.1",
            "created": created.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "createdBy": [producer_id],
            "createdUsing": [tool_id],
        }
        suppliers = {comp.supplier for comp in aibom.components if comp.supplier}
        parties = [
            {
                "type": "Organization",
                "spdxId": ids.element("supplier", name),
                "creationInfo": ci,
                "name": name,
            }
            for name in sorted(suppliers)
        ]
        components = [
            self._element(comp, ids) for comp in sorted(aibom.components, key=lambda c: c.bom_ref)
        ]
        edge_values = {
            json_text(edge.model_dump(mode="json", exclude_none=True)): edge
            for edge in aibom.dependencies
        }
        relationships = [self._relationship(edge_values[key], ids) for key in sorted(edge_values)]
        license_relationships = [
            {
                "type": "Relationship",
                "spdxId": ids.element("license-relationship", component["spdxId"] + ":" + kind),
                "creationInfo": ci,
                "relationshipType": kind,
                "from": component["spdxId"],
                "to": [NO_ASSERTION_LICENSE],
            }
            for component in components
            if component["type"] in {"ai_AIPackage", "dataset_DatasetPackage"}
            for kind in ("hasDeclaredLicense", "hasConcludedLicense")
        ]
        elements: list[dict[str, Any]] = [
            creator,
            generator,
            *parties,
            *components,
            *relationships,
            *license_relationships,
        ]
        doc = {
            "type": "SpdxDocument",
            "spdxId": ids.document,
            "creationInfo": ci,
            "name": "Nexus SymBiote AgentBOM " + str(aibom.metadata.serial_number),
            "element": [element["spdxId"] for element in elements],
            "rootElement": [
                ids.element("component", comp.bom_ref)
                for comp in sorted(aibom.components, key=lambda c: c.bom_ref)
                if comp.component_type == ComponentType.AGENT
            ],
            # The inventory does not collect all AI/Dataset-profile conformance evidence.
            "profileConformance": ["core", "software", "extension"],
            "extension": _extension(document_properties(aibom, self.format_name)),
        }
        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [doc, *elements, creation],
        }

    @staticmethod
    def _element(comp: AnyComponent, ids: _DocumentIds) -> dict[str, Any]:
        typ = SPDX_TYPE_MAP.get(comp.component_type, "software_Package")
        element: dict[str, Any] = {
            "type": typ,
            "spdxId": ids.element("component", comp.bom_ref),
            "creationInfo": ids.creation,
            "name": comp.name,
            "extension": _extension(
                [
                    component_property(comp),
                    *claim_properties(comp),
                    *package_identifier_properties(comp),
                ]
            ),
        }
        package = package_identifier(comp)
        if package.value is not None:
            element["externalIdentifier"] = [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "packageUrl",
                    "identifier": package.value,
                    "comment": "Declared package identity; not authenticated by the exporter.",
                }
            ]
            if typ != "software_File":
                element["software_packageUrl"] = package.value
        if typ != "software_File" and (package.version or comp.version):
            element["software_packageVersion"] = package.version or comp.version
        if comp.supplier:
            element["suppliedBy"] = ids.element("supplier", comp.supplier)
        if comp.description:
            element["description"] = comp.description
        if typ != "software_File":
            element["software_downloadLocation"] = "NOASSERTION"
        if typ == "ai_AIPackage":
            element.update(
                {
                    "software_primaryPurpose": "model"
                    if isinstance(comp, ModelComponent)
                    else "application",
                    "ai_autonomyType": "noAssertion",
                    "ai_informationAboutTraining": "Not supplied by the inventory producer.",
                    "ai_informationAboutApplication": comp.description
                    or "Not supplied by the inventory producer.",
                    "ai_limitation": "Inventory assertions do not establish model safety or authorization.",
                    "ai_useSensitivePersonalInformation": "noAssertion",
                }
            )
            if isinstance(comp, ModelComponent) and comp.model_type:
                element["ai_typeOfModel"] = [comp.model_type]
        elif typ == "dataset_DatasetPackage":
            element.update(
                {
                    "software_primaryPurpose": "data",
                    "dataset_datasetType": ["noAssertion"],
                    "dataset_hasSensitivePersonalInformation": "noAssertion",
                    "dataset_dataCollectionProcess": "Not supplied by the inventory producer.",
                    "dataset_intendedUse": "Not supplied by the inventory producer.",
                }
            )
        elif comp.component_type in {
            ComponentType.MCP_CLIENT,
            ComponentType.MCP_SERVER,
            ComponentType.A2A_CLIENT,
            ComponentType.A2A_SERVER,
            ComponentType.IDE_AGENT,
        }:
            element["software_primaryPurpose"] = "application"
        elif comp.component_type == ComponentType.VERIFIED_EXTENSION:
            element["software_primaryPurpose"] = "library"
        if comp.hashes:
            hashes = []
            for algorithm, value in sorted(comp.hashes.items()):
                name, digest = normalize_hash(algorithm, value)
                spdx_algorithm = (
                    name.lower().replace("-", "_")
                    if name.startswith("SHA3-")
                    else name.lower().replace("-", "")
                )
                hashes.append({"type": "Hash", "algorithm": spdx_algorithm, "hashValue": digest})
            element["verifiedUsing"] = hashes
        return element

    @staticmethod
    def _relationship(edge: DependencyEdge, ids: _DocumentIds) -> dict[str, Any]:
        mapping = {
            "invokes": "usesTool",
            "trained-on": "trainedOn",
            "depends-on": "dependsOn",
            "fine-tuned-from": "descendantOf",
            "quantized-from": "descendantOf",
            "merged-from": "descendantOf",
        }
        body = edge.model_dump(mode="json", exclude_none=True)
        return {
            "type": "Relationship",
            "spdxId": ids.element("relationship", content_digest(body)),
            "creationInfo": ids.creation,
            "relationshipType": mapping.get(edge.relationship, "other"),
            "from": ids.element("component", edge.source_ref),
            "to": [ids.element("component", edge.target_ref)],
            "extension": _extension(
                [{"name": "nexus-symbiote:relationship", "value": json_text(body)}]
            ),
        }

    @staticmethod
    def recover(document: dict[str, Any]) -> AIBOM:
        require_received_limits(document, "spdx")
        graph = document.get("@graph")
        if not isinstance(graph, list) or not all(isinstance(node, dict) for node in graph):
            raise ValueError("expected an SPDX graph of objects")
        docs = [node for node in graph if node.get("type") == "SpdxDocument"]
        if len(docs) != 1:
            raise ValueError("expected exactly one SPDX document")
        doc = docs[0]
        spdx_id = doc.get("spdxId")
        identifier = spdx_id if isinstance(spdx_id, str) else ""
        namespace, separator, _revision = identifier.rpartition("/document/")
        if not namespace or not separator:
            raise ValueError("unrecognized SPDX export document identifier")
        properties = [
            {"name": prop["extension_cdxPropName"], "value": prop.get("extension_cdxPropValue", "")}
            for extension in _list(doc.get("extension"))
            if isinstance(extension, dict)
            and extension.get("type") == "extension_CdxPropertiesExtension"
            for prop in _list(extension.get("extension_cdxProperty"))
            if isinstance(prop, dict) and "extension_cdxPropName" in prop
        ]
        if not all(isinstance(p["name"], str) and isinstance(p["value"], str) for p in properties):
            raise ValueError("invalid SPDX extension properties")
        recovered = recover_document(properties)
        require_inventory_limits(recovered)
        expected = SPDXGenerator(namespace)._projection(recovered)
        # A conforming JSON-LD consumer can omit an empty root element set.
        actual = {
            **document,
            "@graph": [
                {**node, "rootElement": node.get("rootElement", [])} if node is doc else node
                for node in graph
            ],
        }
        if unordered_projection(actual) != unordered_projection(expected):
            raise ValueError("SPDX projection conflicts with the embedded native document")
        # Costly schema validation runs only on what this generator emits for a
        # bounded inventory, never on arbitrary received content.
        require_valid(document, "spdx")
        return recovered
