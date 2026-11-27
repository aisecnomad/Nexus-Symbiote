"""CycloneDX 1.7 output generator.

Maps AgentBOM components to CycloneDX 1.7 JSON, extending the standard with
agent-specific property taxonomies under the nexus-symbiote: and agentbom:
namespaces. docs/standard-exports.md describes the mapping and the property names.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from referencing.exceptions import Unresolvable

from nexus_symbiote.core.aibom import AIBOM, native_document, prepare
from nexus_symbiote.core.canonical import json_text
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
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
from nexus_symbiote.generators import _legacy
from nexus_symbiote.generators._common import (
    PROJECTION_PROPERTY,
    claim_properties,
    component_property,
    coverage_aggregate,
    declared_projection,
    document_properties,
    native_components,
    recover_native,
    repository_scan,
    repository_subject,
    requested_version,
    standard_hashes,
    standard_version,
    unordered_projection,
)
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.package_identifiers import (
    package_identifier,
    package_identifier_properties,
)
from nexus_symbiote.generators.validation import _is_iri_reference, _is_uri, require_valid

PROJECTION = "cyclonedx-1.7/2"
PROJECTION_V3_17 = "cyclonedx-1.7/3"
PROJECTION_V3_16 = "cyclonedx-1.6/3"
_V3_DIRECT_EDGES = frozenset(
    {
        "depends-on",
        "uses-model",
        "delegates-to",
        "retrieves-from",
        "loads-skill",
        "trained-on",
        "fine-tuned-from",
        "quantized-from",
        "merged-from",
        "invokes",
        "configured-with",
    }
)
_DERIVATION_EDGES = frozenset({"fine-tuned-from", "quantized-from", "merged-from"})
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
    ComponentType.REGISTRY_ENTRY: "library",
    ComponentType.SKILL_PACKAGE: "library",
}
# Package registries hold libraries; image registries hold containers. Any other
# registry keeps the neutral "library" type.
REGISTRY_COMPONENT_TYPES = {"docker-hub": "container", "docker": "container", "oci": "container"}


def component_type(comp: AnyComponent) -> str:
    if isinstance(comp, RegistryEntryComponent):
        return REGISTRY_COMPONENT_TYPES.get((comp.registry_type or "").lower(), "library")
    return COMPONENT_TYPE_MAP.get(comp.component_type, "library")


def property_value(value: Any) -> str:
    """JSON spelling for non-string values: ``true``, ``3``, ``{"a":1}``."""
    return value if isinstance(value, str) else json_text(value)


def standard_component(comp: AnyComponent) -> dict[str, Any]:
    """The standard fields of a component, shared with the VEX projection."""
    result: dict[str, Any] = {
        "type": component_type(comp),
        "bom-ref": comp.bom_ref,
        "name": comp.name,
    }
    version = standard_version(comp)
    if version:
        result["version"] = version
    package = package_identifier(comp)
    if package.value is not None:
        result["purl"] = package.value
    hashes = standard_hashes(comp)
    if hashes:
        result["hashes"] = [{"alg": name, "content": digest} for name, digest in hashes]
    return result


class CycloneDXGenerator(Generator):
    format_name = "cyclonedx-1.7"

    def __init__(self, *, projection_version: int = 2, spec_version: str = "1.7") -> None:
        if projection_version not in {2, 3}:
            raise ValueError("CycloneDX projection_version must be 2 or 3")
        if spec_version not in {"1.6", "1.7"}:
            raise ValueError("CycloneDX spec_version must be '1.6' or '1.7'")
        if spec_version == "1.6" and projection_version == 2:
            raise ValueError("CycloneDX 1.6 requires projection_version=3")
        self._projection_version = projection_version
        self._spec_version = spec_version
        self.format_name = f"cyclonedx-{spec_version}"

    @property
    def _projection_marker(self) -> str:
        if self._projection_version == 2:
            return PROJECTION
        return PROJECTION_V3_17 if self._spec_version == "1.7" else PROJECTION_V3_16

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        document = self._projection(aibom)
        if self._spec_version == "1.6":
            probe = dict(document, specVersion="1.7")
            require_valid(probe, "cyclonedx")
        else:
            require_valid(document, "cyclonedx")
        return document

    def _projection(
        self,
        aibom: AIBOM,
        native: dict[str, Any] | None = None,
        *,
        legacy_locations: bool = False,
    ) -> dict[str, Any]:
        prepare(aibom)
        native = native_document(aibom) if native is None else native
        components = native_components(native)
        subject = repository_subject(aibom)
        comp_by_ref: dict[str, AnyComponent] = {c.bom_ref: c for c in aibom.components}
        outgoing_by_source: dict[str, list[Any]] = {}
        for edge in aibom.dependencies:
            if not edge.conditions:
                outgoing_by_source.setdefault(edge.source_ref, []).append(edge)
        aggregate = coverage_aggregate(aibom.metadata.completeness)
        composition: dict[str, Any] = {"aggregate": aggregate}
        if subject is not None:
            composition |= {"assemblies": [subject.bom_ref], "dependencies": [subject.bom_ref]}
        document: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": self._spec_version,
            "version": aibom.metadata.version,
            "serialNumber": aibom.metadata.serial_number,
            "metadata": self._metadata(
                aibom,
                native,
                subject,
                comp_by_ref=comp_by_ref,
                outgoing_by_source=outgoing_by_source,
                legacy_locations=legacy_locations,
            ),
            "components": [
                self._component(
                    c,
                    components[c.bom_ref],
                    subject=subject,
                    comp_by_ref=comp_by_ref,
                    outgoing_edges=outgoing_by_source.get(c.bom_ref, ()),
                    legacy_locations=legacy_locations,
                )
                for c in sorted(aibom.components, key=lambda c: c.bom_ref)
                if c is not subject
            ],
            "dependencies": (
                self._dependencies_v3(aibom)
                if self._projection_version == 3
                else self._dependencies(aibom)
            ),
            "compositions": [composition],
        }
        if self._projection_version == 3:
            services = self._services(aibom)
            if services:
                document["services"] = services
        from nexus_symbiote.scan_advisories import cyclonedx_vulnerabilities

        vulnerabilities = cyclonedx_vulnerabilities(aibom)
        if vulnerabilities:
            document["vulnerabilities"] = vulnerabilities
        return document

    @staticmethod
    def _dependencies(aibom: AIBOM) -> list[dict[str, Any]]:
        """Only unconditional edges with dependency meaning enter the standard graph.

        ``depends-on`` keeps its direction. A tool requires the server that provides
        it, so ``provides-tool`` is the tool's dependency on its server. Conditions,
        invocation, lineage and authority stay in the extension.
        """
        adjacency: dict[str, set[str]] = {}
        for edge in aibom.dependencies:
            if edge.conditions:
                continue
            if edge.relationship == "depends-on":
                adjacency.setdefault(edge.source_ref, set()).add(edge.target_ref)
            elif edge.relationship == "provides-tool":
                adjacency.setdefault(edge.target_ref, set()).add(edge.source_ref)
        return [
            {"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(adjacency.items())
        ]

    @staticmethod
    def _dependencies_v3(aibom: AIBOM) -> list[dict[str, Any]]:
        """Projection 3 projects unconditional AI lineage, delegation, skill, retrieval, and model edges."""
        known = {c.bom_ref for c in aibom.components}
        adjacency: dict[str, set[str]] = {}
        for edge in aibom.dependencies:
            if edge.conditions:
                continue
            if edge.source_ref not in known or edge.target_ref not in known:
                continue
            if edge.relationship in _V3_DIRECT_EDGES:
                adjacency.setdefault(edge.source_ref, set()).add(edge.target_ref)
            elif edge.relationship == "provides-tool":
                adjacency.setdefault(edge.target_ref, set()).add(edge.source_ref)
        return [
            {"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(adjacency.items())
        ]

    @staticmethod
    def _service_endpoint(url: str) -> str | None:
        from nexus_symbiote.utils.secrets import holds_token_shape

        if not _is_iri_reference(url):
            return None
        try:
            parts = urlsplit(url)
        except ValueError:
            return None
        if not parts.scheme or not parts.netloc:
            return None if holds_token_shape(url, require_sk_boundary=True) else url
        hostport = parts.netloc.rpartition("@")[2]
        if not hostport:
            return None
        path = "" if holds_token_shape(parts.path, require_sk_boundary=True) else parts.path
        cleaned = urlunsplit((parts.scheme, hostport, path, "", ""))
        return cleaned if _is_iri_reference(cleaned) else None

    @staticmethod
    def _services(aibom: AIBOM) -> list[dict[str, Any]]:
        from nexus_symbiote.scanners.a2a import ANONYMOUS_AUTH_METHODS

        used_refs = {comp.bom_ref for comp in aibom.components}
        services: list[dict[str, Any]] = []
        for comp in sorted(aibom.components, key=lambda c: c.bom_ref):
            endpoints: list[str] = []
            authenticated: bool | None = None
            if isinstance(comp, MCPServerComponent) and comp.endpoint_url:
                sanitized = CycloneDXGenerator._service_endpoint(comp.endpoint_url)
                if sanitized is not None:
                    endpoints.append(sanitized)
            elif isinstance(comp, A2AServerComponent) and comp.endpoint_url:
                sanitized = CycloneDXGenerator._service_endpoint(comp.endpoint_url)
                if sanitized is not None:
                    endpoints.append(sanitized)
                authenticated = comp.authentication_required
            elif isinstance(comp, A2AClientComponent) and comp.agent_card_url:
                sanitized = CycloneDXGenerator._service_endpoint(comp.agent_card_url)
                if sanitized is not None:
                    endpoints.append(sanitized)
                # A client that declares no method is unauthenticated, as the collector's
                # finding says; only a non-anonymous method makes the service authenticated.
                authenticated = any(
                    isinstance(m, str) and m.strip().lower() not in ANONYMOUS_AUTH_METHODS
                    for m in comp.authentication_methods or ()
                )
            elif isinstance(comp.properties.get("hosted_tool_origin"), str):
                origin = comp.properties["hosted_tool_origin"]
                sanitized = CycloneDXGenerator._service_endpoint(origin)
                if sanitized is not None:
                    endpoints.append(sanitized)
            if not endpoints:
                continue
            service_ref = f"service:{comp.bom_ref}"
            if service_ref in used_refs:
                suffix = 1
                while f"service:{comp.bom_ref}:{suffix}" in used_refs:
                    suffix += 1
                service_ref = f"service:{comp.bom_ref}:{suffix}"
            used_refs.add(service_ref)
            entry: dict[str, Any] = {
                "bom-ref": service_ref,
                "name": comp.name,
                "endpoints": endpoints,
            }
            if authenticated is not None:
                entry["authenticated"] = authenticated
            if comp.description:
                entry["description"] = comp.description
            services.append(entry)
        return services

    @staticmethod
    def _public_view(document: dict[str, Any]) -> dict[str, Any]:
        view = dict(document)
        # The upstream SDK supplies the schema hint and an extra ref-only row
        # for known components without emitted edges. Never discard targets.
        if view.get("$schema") in {
            "http://cyclonedx.org/schema/bom-1.7.schema.json",
            "http://cyclonedx.org/schema/bom-1.6.schema.json",
        }:
            del view["$schema"]
        view.setdefault("components", [])
        view["dependencies"] = [
            edge for edge in view.get("dependencies", []) if set(edge) != {"ref"}
        ]
        return view

    @classmethod
    def _expected_view(cls, candidate: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
        view = cls._public_view(candidate)
        # Readers such as the upstream SDK drop the compositions array. Without one a
        # consumer sees no completeness assertion, which equals "unknown". Dropping
        # "incomplete" loses the public coverage warning, and any composition that
        # is present must match exactly, so both still conflict.
        if "compositions" not in document and [
            composition.get("aggregate") for composition in view.get("compositions", [])
        ] == ["unknown"]:
            del view["compositions"]
        # cyclonedx-python-lib also drops modelCard on read. Accept only the loss of
        # every modelCard, so an edited or partly removed card still conflicts.
        if not any("modelCard" in c for c in document.get("components", [])):
            view["components"] = [
                {k: v for k, v in c.items() if k != "modelCard"} for c in view["components"]
            ]
        return view

    @classmethod
    def recover(
        cls, document: dict[str, Any], *, allow_legacy_relationships: bool = False
    ) -> AIBOM:
        """Require agreement with the embedded inventory under the declared projection.

        A document without a projection marker was written by 0.1.0 and must match that
        projection. Legacy mode also accepts, for such a document only, the exact edge
        projection of the historical exporter as a whole: every edge in ``dependsOn``
        and no conditional flag. A mixture is rejected. Malformed input raises
        ValueError.
        """
        try:
            return cls._recover(document, allow_legacy_relationships)
        except (RecursionError, Unresolvable, KeyError, TypeError, AttributeError) as exc:
            raise ValueError("CycloneDX document cannot be recovered") from exc

    @classmethod
    def _recover(cls, document: dict[str, Any], allow_legacy_relationships: bool) -> AIBOM:
        properties = document.get("metadata", {}).get("properties", [])
        projection = declared_projection(properties)
        if projection == PROJECTION_V3_16 and document.get("specVersion") == "1.6":
            require_valid(dict(document, specVersion="1.7"), "cyclonedx")
        else:
            require_valid(document, "cyclonedx")
        recovered, native = recover_native(properties)
        candidates: Iterable[dict[str, Any]]
        if projection == PROJECTION:
            candidates = [
                cls(projection_version=2, spec_version="1.7")._projection(recovered, native)
            ]
        elif projection in {PROJECTION_V3_17, PROJECTION_V3_16}:
            version = "1.7" if projection == PROJECTION_V3_17 else "1.6"
            exporter = cls(projection_version=3, spec_version=version)
            candidates = (
                exporter._projection(recovered, native, legacy_locations=legacy)
                for legacy in (False, True)
            )
        elif projection is None:
            candidates = [
                _legacy.cyclonedx_projection(recovered, native, historical=historical)
                for historical in ((False, True) if allow_legacy_relationships else (False,))
            ]
        else:
            raise ValueError("unsupported CycloneDX projection version")
        actual = unordered_projection(cls._public_view(document))
        if not any(
            actual == unordered_projection(cls._expected_view(candidate, document))
            for candidate in candidates
        ):
            raise ValueError("CycloneDX projection conflicts with the embedded native document")
        return recovered

    def _metadata(
        self,
        aibom: AIBOM,
        native: dict[str, Any],
        subject: AnyComponent | None,
        *,
        comp_by_ref: dict[str, AnyComponent] | None = None,
        outgoing_by_source: dict[str, list[Any]] | None = None,
        legacy_locations: bool = False,
    ) -> dict[str, Any]:
        # The native BOM carries no wall-clock timestamp by default; omit
        # the field rather than emitting null, which the CycloneDX schema
        # rejects. An explicitly set observation timestamp is preserved.
        meta: dict[str, Any] = {}
        if aibom.metadata.timestamp is not None:
            meta["timestamp"] = aibom.metadata.timestamp.isoformat()
        meta["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": aibom.metadata.tool_name,
                    "version": aibom.metadata.tool_version or "unknown",
                    "publisher": aibom.metadata.tool_vendor,
                }
            ]
        }
        if aibom.metadata.authors:
            meta["authors"] = [{"name": a} for a in aibom.metadata.authors]
        if repository_scan(aibom):
            # Configuration read from a repository describes what is planned to run.
            meta["lifecycles"] = [{"phase": "pre-build"}]
        if subject is not None:
            meta["component"] = self._component(
                subject,
                native_components(native)[subject.bom_ref],
                subject=subject,
                comp_by_ref=comp_by_ref or {},
                outgoing_edges=(outgoing_by_source or {}).get(subject.bom_ref, ()),
                legacy_locations=legacy_locations,
            )
        edges = sorted(
            {
                json_text(
                    {"from": edge.source_ref, "to": edge.target_ref, "type": edge.relationship}
                    | ({"conditional": True} if edge.conditions else {})
                )
                for edge in aibom.dependencies
            }
        )
        meta["properties"] = [
            *({"name": "nexus-symbiote:dependency:relationship", "value": edge} for edge in edges),
            *document_properties(aibom, self.format_name, native),
            {"name": PROJECTION_PROPERTY, "value": self._projection_marker},
        ]
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

    @staticmethod
    def _source_line(comp: AnyComponent) -> int | None:
        raw = comp.properties.get("source_line")
        if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0:
            return raw
        for claim in comp.claims.values():
            locator = claim.locator or ""
            if "://" in locator:
                continue
            if ":" in locator:
                tail = locator.rsplit(":", 1)[1]
                if tail.isdigit() and int(tail) > 0:
                    return int(tail)
        return None

    def _component(
        self,
        comp: AnyComponent,
        native: dict[str, Any],
        *,
        subject: AnyComponent | None = None,
        comp_by_ref: dict[str, AnyComponent] | None = None,
        outgoing_edges: Any = (),
        legacy_locations: bool = False,
    ) -> dict[str, Any]:
        from nexus_symbiote.spdx_profiles import (
            _clean_url,
            _projected_download_location,
            clean_license_identifier,
            spdx_license_expression,
            spdx_license_ids,
        )

        result = standard_component(comp)
        if comp.supplier:
            result["supplier"] = {"name": comp.supplier}
        if comp.description:
            result["description"] = comp.description
        if comp.source_path:
            occurrence: dict[str, Any] = {"location": comp.source_path}
            if self._projection_version == 3:
                line_no = self._source_line(comp)
                if line_no is not None:
                    occurrence["line"] = line_no
            result["evidence"] = {"occurrences": [occurrence]}
        if self._projection_version == 3:
            observed_lic = clean_license_identifier(getattr(comp, "license", None))
            lic = observed_lic or clean_license_identifier(comp.properties.get("declared_license"))
            if lic:
                ack = {} if observed_lic else {"acknowledgement": "declared"}
                expr = spdx_license_expression(lic)
                if expr is None:
                    result["licenses"] = [{"license": {"name": lic} | ack}]
                elif expr in spdx_license_ids()[0]:
                    result["licenses"] = [{"license": {"id": expr} | ack}]
                else:
                    result["licenses"] = [{"expression": expr} | ack]
            # An observed URI may carry a query token, and a supplied inventory any declared
            # value, such as javascript: or a credentialed URL; the same cleaning applies.
            observed_dl = _clean_url(getattr(comp, "source_uri", None), legacy=legacy_locations)
            dl = observed_dl or _projected_download_location(
                comp.properties.get("declared_download_location"), legacy=legacy_locations
            )
            if isinstance(dl, str) and _is_uri(dl):
                ref = {"type": "distribution", "url": dl}
                result["externalReferences"] = [
                    ref if observed_dl else ref | {"comment": "declared by producer"}
                ]
            if isinstance(comp, ModelComponent) and comp_by_ref is not None:
                ancestors: list[dict[str, Any]] = []
                seen_ancestors: set[str] = set()
                for edge in sorted(outgoing_edges, key=lambda e: (e.relationship, e.target_ref)):
                    if (
                        edge.relationship not in _DERIVATION_EDGES
                        or edge.target_ref in seen_ancestors
                    ):
                        continue
                    anc = comp_by_ref.get(edge.target_ref)
                    if anc is None:
                        continue
                    seen_ancestors.add(edge.target_ref)
                    anc_obj: dict[str, Any] = {
                        "type": component_type(anc),
                        "name": anc.name,
                    }
                    if anc_ver := standard_version(anc):
                        anc_obj["version"] = anc_ver
                    ancestors.append(anc_obj)
                if ancestors:
                    result["pedigree"] = {"ancestors": ancestors}

                model_params: dict[str, Any] = {}
                domain = comp.properties.get("declared_domain")
                if isinstance(domain, str) and domain.strip():
                    model_params["task"] = domain.strip()
                if isinstance(comp.model_type, str) and comp.model_type.strip():
                    model_params["modelArchitecture"] = comp.model_type.strip()
                dataset_refs = sorted(
                    {
                        edge.target_ref
                        for edge in outgoing_edges
                        if edge.relationship == "trained-on"
                        and (ds := comp_by_ref.get(edge.target_ref)) is not None
                        and ds is not subject
                    }
                )
                if dataset_refs:
                    model_params["datasets"] = [{"ref": ref} for ref in dataset_refs]
                model_card: dict[str, Any] = {}
                if model_params:
                    model_card["modelParameters"] = model_params
                limitations = comp.properties.get("declared_limitations")
                if isinstance(limitations, str) and limitations.strip():
                    model_card["considerations"] = {"technicalLimitations": [limitations.strip()]}
                if model_card:
                    result["modelCard"] = model_card
        props = self._extension_properties(comp, native)
        if props:
            result["properties"] = props
        return result

    def _extension_properties(
        self, comp: AnyComponent, native: dict[str, Any]
    ) -> list[dict[str, str]]:
        props: list[dict[str, str]] = []

        def _add(name: str, value: Any) -> None:
            if value is not None and value != "":
                props.append({"name": f"nexus-symbiote:{name}", "value": property_value(value)})

        _add("componentType", comp.component_type.value)
        _add("trustTier", comp.trust_tier.value)
        _add("assuranceLevel", comp.assurance_level.value)
        _add("requestedVersion", requested_version(comp))

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
            for k, v in comp.annotations.items():
                _add(f"annotation.{k}", v)
        elif isinstance(comp, MCPServerComponent):
            _add("transport", comp.transport)
            # The native default of 0 also means "not observed"; only a count is exported.
            _add("toolCount", comp.tool_count or None)
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
