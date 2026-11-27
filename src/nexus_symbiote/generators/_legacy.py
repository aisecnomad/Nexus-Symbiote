"""The 0.1.0 standard projection (version 1), kept only to recover exports written by it.

An export without a ``nexus-symbiote:projection`` marker was written by this projection.
Recovery requires agreement with it exactly, so this module must not change. The
shared helpers it calls are pinned by the 0.1.0 export fixtures under
``tests/fixtures/export-projection-0.1.0``. The package identifier rule is a copy of
the 0.1.0 one, because the current rule also checks the component's registry.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC
from typing import Any
from urllib.parse import parse_qsl, unquote

from packageurl import PackageURL
from packaging.specifiers import Specifier
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge, native_document, prepare
from nexus_symbiote.core.canonical import NAMESPACE, content_digest, json_text
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.hashing import extract_version_pin
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
    coverage_aggregate,
    native_components,
    normalize_hash,
)
from nexus_symbiote.generators.package_identifiers import PackageIdentifierProjection

CYCLONEDX_FORMAT = "cyclonedx-1.7"
SPDX_FORMAT = "spdx-3.0.1"
SPDX_NAMESPACE = "https://spdx.org/spdxdocs/nexus_symbiote"
NO_ASSERTION_LICENSE = "https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion"
MAX_CONDITION_COMMENT = 1024
COVERAGE_COMMENTS = {
    "incomplete": (
        "Collection coverage is incomplete: collectors were scoped or failed, surfaces "
        "were excluded, or discovery was imported. This document does not assert "
        "complete collection."
    ),
    "unknown": (
        "Collection coverage is unknown: static collection does not observe runtime, "
        "network or live tool surfaces. This document does not assert complete collection."
    ),
}
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
    ComponentType.CREDENTIAL: "data",
    ComponentType.REGISTRY_ENTRY: "platform",
    ComponentType.SKILL_PACKAGE: "library",
}
SPDX_TYPE_MAP = {
    ComponentType.AGENT: "ai_AIPackage",
    ComponentType.MODEL: "ai_AIPackage",
    ComponentType.PROMPT_TEMPLATE: "software_File",
    ComponentType.MEMORY_STORE: "dataset_DatasetPackage",
    ComponentType.RAG_SOURCE: "dataset_DatasetPackage",
    ComponentType.DATA_SOURCE: "dataset_DatasetPackage",
}


def package_identifier(component: AnyComponent) -> PackageIdentifierProjection:
    if not isinstance(component, RegistryEntryComponent) or component.package_url is None:
        return PackageIdentifierProjection(None, "unknown")
    value = component.package_url
    invalid = PackageIdentifierProjection(None, "unavailable-invalid")
    if (
        not value
        or len(value) > 2048
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
        or re.match(r"^pkg:[a-z][a-z0-9.+-]*/", value) is None
        or re.search(r"%(?![0-9A-Fa-f]{2})", value)
    ):
        return invalid
    try:
        decoded = unquote(value, errors="strict")
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in decoded):
            return invalid
        main, _, raw_fragment = value.partition("#")
        raw_path, _, raw_query = main.partition("?")
        path = unquote(raw_path, errors="strict")
        fragment = unquote(raw_fragment, errors="strict")
        segments = [*path.split("/"), *(fragment.split("/") if fragment else [])]
        if any(part in {"", ".", ".."} for part in segments):
            return invalid
        if raw_query:
            qualifiers = parse_qsl(
                raw_query, keep_blank_values=True, strict_parsing=True, errors="strict"
            )
            keys = [key.lower() for key, _ in qualifiers]
            if len(keys) != len(set(keys)) or any(not content for _, content in qualifiers):
                return invalid
        parsed = PackageURL.from_string(value)
        if not _agrees_with_component(parsed, component):
            return invalid
        return PackageIdentifierProjection(parsed.to_string(), "declared", parsed.version)
    except (ValueError, TypeError, UnicodeError):
        return invalid


def _agrees_with_component(package: PackageURL, component: RegistryEntryComponent) -> bool:
    if component.registry_type in {"pypi", "npm"} and package.type != component.registry_type:
        return False
    if package.type == "pypi":
        if (
            package.namespace
            or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", package.name) is None
            or canonicalize_name(package.name) != canonicalize_name(component.name)
        ):
            return False
        if package.version is not None:
            try:
                Version(package.version)
            except InvalidVersion:
                return False
        if component.version:
            declaration = component.version
            reference = declaration if declaration.startswith("==") else "package==" + declaration
            expected = extract_version_pin(reference, ecosystem="python")
            if expected is None or package.version is None:
                return False
            if declaration.startswith("==="):
                if not Specifier("===" + expected).contains(package.version, prereleases=True):
                    return False
            elif Version(expected) != Version(package.version):
                return False
    elif package.type == "npm":
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", package.name) is None or (
            package.namespace is not None
            and re.fullmatch(r"@[a-z0-9][a-z0-9._-]*", package.namespace) is None
        ):
            return False
        name = f"{package.namespace}/{package.name}" if package.namespace else package.name
        if name != component.name:
            return False
        if (
            package.version is not None
            and extract_version_pin(name + "@" + package.version, ecosystem="npm") is None
        ):
            return False
        if component.version:
            expected = extract_version_pin(name + "@" + component.version, ecosystem="npm")
            if expected is None or package.version != expected:
                return False
    return True


def package_identifier_properties(component: AnyComponent) -> list[dict[str, str]]:
    if not isinstance(component, RegistryEntryComponent):
        return []
    return [
        {
            "name": "nexus-symbiote:packageIdentifierProjection",
            "value": package_identifier(component).status,
        }
    ]


def loss_report(bom: AIBOM, target: str, document: dict[str, Any]) -> dict[str, Any]:
    preserves_native = target.startswith(("cyclonedx-", "spdx-"))
    items: list[dict[str, Any]] = [
        {
            "path": "",
            "reason": "agent authority, assurance, and coverage require the Nexus Symbiote extension"
            if preserves_native
            else "finding projection omits the complete source inventory",
            "preservedIn": "nexus-symbiote:document" if preserves_native else None,
            "severity": "info" if preserves_native else "warning",
        }
    ]
    if preserves_native:

        def add(path: str, reason: str) -> None:
            items.append(
                {
                    "path": path,
                    "reason": reason,
                    "preservedIn": "nexus-symbiote:document",
                    "severity": "warning",
                }
            )

        if document["metadata"].get("completeness") is not None:
            add(
                "/metadata/completeness",
                "Complete collection coverage and discovery provenance require the extension",
            )
        fields = (
            "deployment_profile",
            "authorizations",
            "capabilities",
            "claims",
            "trust_tier",
            "assurance_level",
        )
        for index, component in enumerate(document["components"]):
            for field in fields:
                if field in component and component[field] not in (None, [], {}):
                    add(
                        f"/components/{index}/{field}",
                        "Full agent-specific field semantics require the extension; "
                        "the standard projection may omit or normalize them",
                    )
        for index, edge in enumerate(document["dependencies"]):
            for field in ("relationship", "assurance_level", "conditions"):
                if edge.get(field) is not None:
                    add(
                        f"/dependencies/{index}/{field}",
                        "Complete relationship semantics require the extension; "
                        "the standard projection may omit or normalize them",
                    )
    identifier_losses = [
        {
            "path": f"/components/{index}/package_url",
            "reason": "declared package URL is invalid or conflicts with the component; standard identifier omitted",
            "preservedIn": "nexus-symbiote:document",
            "severity": "warning",
        }
        for index, component in enumerate(sorted(bom.components, key=lambda c: c.bom_ref))
        if preserves_native and package_identifier(component).status == "unavailable-invalid"
    ]
    return {
        "profile": "nexus-symbiote-export/v1",
        "target": target,
        "sourceDigest": content_digest(document),
        "nativeSemanticsComplete": False,
        "extensionRoundTripComplete": preserves_native,
        "admissionAuthority": False,
        "normalizations": [
            "component and dependency collections sorted for deterministic output",
            *(
                [
                    "valid declared package URLs canonicalized; standard package versions use their exact PURL version"
                ]
                if preserves_native
                else []
            ),
        ],
        "itemCoverage": "selected-security-fields" if preserves_native else "summary-only",
        "items": [*items, *identifier_losses],
    }


def document_properties(bom: AIBOM, target: str, document: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"name": "nexus-symbiote:document", "value": json_text(document)},
        {"name": "nexus-symbiote:documentDigest", "value": content_digest(document)},
        {
            "name": "nexus-symbiote:lossReport",
            "value": json_text(loss_report(bom, target, document)),
        },
    ]


def cyclonedx_projection(
    aibom: AIBOM, native: dict[str, Any] | None = None, *, historical: bool = False
) -> dict[str, Any]:
    prepare(aibom)
    native = native_document(aibom) if native is None else native
    components = native_components(native)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": aibom.metadata.version,
        "serialNumber": aibom.metadata.serial_number,
        "metadata": _cyclonedx_metadata(aibom, native, historical=historical),
        "components": [
            _cyclonedx_component(c, components[c.bom_ref])
            for c in sorted(aibom.components, key=lambda c: c.bom_ref)
        ],
        "dependencies": _cyclonedx_dependencies(aibom, historical=historical),
        "compositions": [{"aggregate": coverage_aggregate(aibom.metadata.completeness)}],
    }


def _cyclonedx_dependencies(aibom: AIBOM, *, historical: bool) -> list[dict[str, Any]]:
    adjacency: dict[str, set[str]] = {}
    for edge in aibom.dependencies:
        if historical or (edge.relationship == "depends-on" and not edge.conditions):
            adjacency.setdefault(edge.source_ref, set()).add(edge.target_ref)
    return [
        {"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(adjacency.items())
    ]


def _cyclonedx_metadata(
    aibom: AIBOM, native: dict[str, Any], *, historical: bool
) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "timestamp": (aibom.metadata.timestamp.isoformat() if aibom.metadata.timestamp else None),
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
                | ({"conditional": True} if edge.conditions and not historical else {})
            )
            for edge in aibom.dependencies
        }
    )
    meta["properties"] = [
        {"name": "nexus-symbiote:dependency:relationship", "value": edge} for edge in edges
    ] + document_properties(aibom, CYCLONEDX_FORMAT, native)
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


def _cyclonedx_component(comp: AnyComponent, native: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": COMPONENT_TYPE_MAP.get(comp.component_type, "library"),
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
    props = _cyclonedx_properties(comp, native)
    if props:
        result["properties"] = props
    return result


def _cyclonedx_properties(comp: AnyComponent, native: dict[str, Any]) -> list[dict[str, str]]:
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
    props.append(component_property(comp, native))
    props.extend(claim_properties(comp))
    props.extend(package_identifier_properties(comp))
    return props


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


def spdx_projection(
    aibom: AIBOM, namespace: str = SPDX_NAMESPACE, native: dict[str, Any] | None = None
) -> dict[str, Any]:
    prepare(aibom)
    native = native_document(aibom) if native is None else native
    revision = content_digest(native).removeprefix("sha256:")
    ids = _DocumentIds(f"{namespace.rstrip('/')}/document/{revision}")
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
    if aibom.metadata.timestamp is None:
        raise ValueError("export timestamps must be set")
    creation = {
        "type": "CreationInfo",
        "@id": ci,
        "specVersion": "3.0.1",
        "created": aibom.metadata.timestamp.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
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
    native_by_ref = native_components(native)
    components = [
        _spdx_element(comp, ids, native_by_ref[comp.bom_ref])
        for comp in sorted(aibom.components, key=lambda c: c.bom_ref)
    ]
    edge_values = {
        json_text(edge.model_dump(mode="json", exclude_none=True)): edge
        for edge in aibom.dependencies
    }
    coverage = coverage_aggregate(aibom.metadata.completeness)
    relationships = [
        _spdx_relationship(
            edge_values[key], ids, "incomplete" if coverage == "incomplete" else "noAssertion"
        )
        for key in sorted(edge_values)
    ]
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
        "profileConformance": ["core", "software", "extension"],
        "comment": COVERAGE_COMMENTS[coverage],
        "extension": _extension(document_properties(aibom, SPDX_FORMAT, native)),
    }
    return {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [doc, *elements, creation],
    }


def _spdx_element(comp: AnyComponent, ids: _DocumentIds, native: dict[str, Any]) -> dict[str, Any]:
    typ = SPDX_TYPE_MAP.get(comp.component_type, "software_Package")
    element: dict[str, Any] = {
        "type": typ,
        "spdxId": ids.element("component", comp.bom_ref),
        "creationInfo": ids.creation,
        "name": comp.name,
        "extension": _extension(
            [
                component_property(comp, native),
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


def _spdx_relationship(
    edge: DependencyEdge, ids: _DocumentIds, completeness: str
) -> dict[str, Any]:
    mapping = {
        "invokes": "usesTool",
        "trained-on": "trainedOn",
        "depends-on": "dependsOn",
        "fine-tuned-from": "descendantOf",
        "quantized-from": "descendantOf",
        "merged-from": "descendantOf",
    }
    body = edge.model_dump(mode="json", exclude_none=True)
    typed = mapping.get(edge.relationship)
    relationship = {
        "type": "Relationship",
        "spdxId": ids.element("relationship", content_digest(body)),
        "creationInfo": ids.creation,
        "relationshipType": "other" if edge.conditions or typed is None else typed,
        "from": ids.element("component", edge.source_ref),
        "to": [ids.element("component", edge.target_ref)],
        "completeness": completeness,
        "extension": _extension(
            [{"name": "nexus-symbiote:relationship", "value": json_text(body)}]
        ),
    }
    if edge.conditions:
        conditions = edge.conditions
        if len(conditions) > MAX_CONDITION_COMMENT:
            conditions = conditions[:MAX_CONDITION_COMMENT] + " [truncated]"
        relationship["comment"] = (
            f"Conditional native relationship '{edge.relationship}' (conditions: "
            f"{conditions}). Not an unconditional {typed or 'relationship'} assertion."
        )
    elif typed is None:
        relationship["comment"] = f"Native relationship '{edge.relationship}'."
    return relationship
