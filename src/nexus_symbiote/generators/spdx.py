"""Validated SPDX 3.0.1 projection with a digest-bound native document extension.

Profile conformance lists core, software and extension, plus expandedLicensing when
the document references SPDX's NoAssertionLicense individual. Models, agents and
data use the AI and Dataset classes, but the AI and Dataset profiles also require
properties an inventory does not collect (supplier, release time, version and
download location), so those profiles are not claimed. Unknown optional fields are
omitted rather than filled with placeholders.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote, urlsplit

from referencing.exceptions import Unresolvable

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge, native_document, prepare
from nexus_symbiote.core.canonical import NAMESPACE, content_digest, json_text
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import AgentComponent, AnyComponent, ModelComponent
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
    standard_hashes,
    standard_version,
    unordered_projection,
)
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.package_identifiers import (
    package_identifier,
    package_identifier_properties,
)
from nexus_symbiote.generators.validation import (
    _IRI_EXCLUDED,
    SPDX_COLLECTIONS,
    require_valid,
    spdx_errors,
)
from nexus_symbiote.utils.secrets import redact_text

PROJECTION = "spdx-3.0.1/3"
PROJECTION_V4 = "spdx-3.0.1/4"
PREVIOUS_PROJECTION = "spdx-3.0.1/2"
_AUTHOR_PROPERTY = "nexus-symbiote:spdx:author"
SPDX_TYPE_MAP = {
    ComponentType.AGENT: "ai_AIPackage",
    ComponentType.MODEL: "ai_AIPackage",
    ComponentType.PROMPT_TEMPLATE: "software_File",
    ComponentType.MEMORY_STORE: "dataset_DatasetPackage",
    ComponentType.RAG_SOURCE: "dataset_DatasetPackage",
    ComponentType.DATA_SOURCE: "dataset_DatasetPackage",
}
_MAPPING_V3 = {
    "invokes": "usesTool",
    "trained-on": "trainedOn",
    "depends-on": "dependsOn",
    "fine-tuned-from": "descendantOf",
    "quantized-from": "descendantOf",
    "merged-from": "descendantOf",
}
_MAPPING_V4 = {
    **_MAPPING_V3,
    "uses-model": "dependsOn",
    "loads-skill": "dependsOn",
    "configured-with": "configures",
    "produces": "generates",
}


# SPDX 3.0.1 defines this named individual for "no assertion" about a license.
NO_ASSERTION_LICENSE = "expandedlicensing_NoAssertionLicense"
MAX_CONDITION_COMMENT = 1024
# Projection 3 shows native text in relationship comments with this mapping: a tab
# becomes a space; C0 and C1 controls, line and paragraph separators, format and
# bidirectional characters, the other default-ignorable code points and the
# noncharacters U+FFFE and U+FFFF become U+FFFD; and a "##name[" CI log command
# introducer is broken. Recovery renders every comment again and compares it with the
# stored one, so the mapping is frozen with the projection instead of following
# utils.terminal.neutralize(), whose set grows as disguising characters are found:
# any change would make earlier projection 3 exports unrecoverable. A different
# rendering needs a new projection.
_COMMENT_UNSAFE = re.compile(
    r"[\x00-\x08\x0a-\x1f\x7f-\x9f\xad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891"
    r"\u08e2\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028\u2029\u202a-\u202e"
    r"\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\ufff9-\ufffb\ufffe\uffff"
    r"\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    r"\U000e0000-\U000e0fff]"
)
_COMMENT_LOG_COMMAND = re.compile(r"##(?=[A-Za-z]*\[)")
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
_NAMESPACE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^\s#?<>\"{}|\\^`]+")
_DEFAULT_DOCUMENT = re.compile(
    r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


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


def _comment_text(value: str) -> str:
    """Native text as projection 3 shows it in a relationship comment."""
    shown = _COMMENT_UNSAFE.sub("\ufffd", value.replace("\t", " "))
    return _COMMENT_LOG_COMMAND.sub("##\ufffd", shown)


def _validated_namespace(namespace: str) -> str:
    value = namespace.rstrip("/")
    invalid = "SPDX namespace must be an absolute IRI without a query or fragment"
    if len(value) > 2048 or _NAMESPACE.fullmatch(value) is None or _IRI_EXCLUDED.search(value):
        raise ValueError(invalid)
    # "spdx.org.", "spdx%2Eorg" and IDNA spellings such as "spdx\u3002org" name the
    # same host as "spdx.org".
    host = unquote(urlsplit(value).hostname or "")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(invalid) from exc
    host = host.lower().rstrip(".")
    if host == "spdx.org" or host.endswith(".spdx.org"):
        raise ValueError("SPDX namespace must be one the document creator controls")
    return value


def _document_namespace(spdx_id: str) -> str | None:
    """The namespace an export was written with, or None for the default identifier."""
    namespace, separator, revision = spdx_id.rpartition("/document/")
    if namespace and separator and revision:
        return namespace
    if _DEFAULT_DOCUMENT.fullmatch(spdx_id):
        return None
    raise ValueError("unrecognized SPDX export document identifier")


def _without_created(value: Any) -> Any:
    """Recursively drop ``created`` from SPDX ``CreationInfo`` elements only.

    When the embedded native document has no timestamp, ``CreationInfo.created``
    is render-time metadata, so it is the one value allowed to differ between an
    export and its recovery. A ``created`` key on any other element is content.
    """
    if isinstance(value, dict):
        creation_info = value.get("type") == "CreationInfo"
        return {
            key: _without_created(item)
            for key, item in value.items()
            if not (creation_info and key == "created")
        }
    if isinstance(value, list):
        return [_without_created(item) for item in value]
    return value


@dataclass(frozen=True)
class _DocumentIds:
    document: str

    @property
    def creation(self) -> str:
        return self.document + "#creation"

    def element(self, kind: str, key: str) -> str:
        return f"{self.document}#{kind}-{uuid.uuid5(NAMESPACE, key)}"


class SPDXGenerator(Generator):
    """SPDX 3.0.1 JSON-LD export.

    Element identifiers are scoped to one inventory revision. Pass ``namespace``, an
    absolute IRI the operator controls, to mint them under ``<namespace>/document/``;
    by default the document identifier is a ``urn:uuid`` derived from the revision.
    """

    format_name = "spdx-3.0.1"

    def __init__(
        self,
        namespace: str | None = None,
        *,
        projection_version: int = 3,
        author: str | None = None,
    ) -> None:
        if projection_version not in {3, 4}:
            raise ValueError("SPDX projection_version must be 3 or 4")
        if author is not None and projection_version < 4:
            raise ValueError("SPDX author option requires projection_version=4")
        self._namespace = None if namespace is None else _validated_namespace(namespace)
        self._projection_version = projection_version
        cleaned_author = (
            _comment_text(redact_text(author.strip()))[:200] if author and author.strip() else None
        )
        self._author = cleaned_author

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        document = self._projection(aibom)
        require_valid(document, "spdx")
        return document

    def _ids(self, revision: str) -> _DocumentIds:
        if self._namespace is None:
            return _DocumentIds(
                "urn:uuid:" + str(uuid.uuid5(NAMESPACE, "spdx-document:" + revision))
            )
        return _DocumentIds(f"{self._namespace}/document/{revision}")

    def _projection(
        self, aibom: AIBOM, native: dict[str, Any] | None = None, *, legacy_v2: bool = False
    ) -> dict[str, Any]:
        prepare(aibom)
        native = native_document(aibom) if native is None else native
        v4 = self._projection_version == 4 and not legacy_v2
        # Native refs are BOM-local, and producers can reuse serial numbers across revisions.
        ids = self._ids(content_digest(native).removeprefix("sha256:"))
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
        author_elements: list[dict[str, Any]] = []
        created_by = [producer_id]
        if v4:
            author_names = sorted(
                {
                    *([self._author] if self._author else []),
                    *(
                        _comment_text(redact_text(a.strip()))[:200]
                        for a in aibom.metadata.authors
                        if a.strip()
                    ),
                }
            )
            for author_name in author_names:
                aid = ids.element("author", author_name)
                author_elements.append(
                    {
                        "type": "Person",
                        "spdxId": aid,
                        "creationInfo": ci,
                        "name": author_name,
                    }
                )
                created_by.append(aid)

        # SPDX 3.0.1 requires CreationInfo.created. The native BOM carries no
        # wall-clock timestamp by default, so fall back to the export time.
        # This is the only wall-clock field in SPDX output: two exports of
        # the same inventory differ only here.
        created_at = aibom.metadata.timestamp or datetime.now(UTC)
        creation = {
            "type": "CreationInfo",
            "@id": ci,
            "specVersion": "3.0.1",
            "created": created_at.astimezone(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "createdBy": created_by,
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
        ordered = sorted(aibom.components, key=lambda c: c.bom_ref)
        components = [
            self._element(comp, ids, native_by_ref[comp.bom_ref], v4=v4) for comp in ordered
        ]
        comp_by_spdx_id = {ids.element("component", comp.bom_ref): comp for comp in ordered}
        edge_values = {
            json_text(edge.model_dump(mode="json", exclude_none=True)): edge
            for edge in aibom.dependencies
        }
        coverage = coverage_aggregate(aibom.metadata.completeness)
        relationships = [
            self._relationship(
                edge_values[key],
                ids,
                "incomplete" if coverage == "incomplete" else "noAssertion",
                neutralize_comments=not legacy_v2,
                v4=v4,
            )
            for key in sorted(edge_values)
        ]

        from nexus_symbiote.spdx_profiles import spdx_license_expression

        license_elements: dict[str, dict[str, Any]] = {}
        license_relationships: list[dict[str, Any]] = []
        used_no_assertion = False
        for component in components:
            if component["type"] not in {"ai_AIPackage", "dataset_DatasetPackage"}:
                continue
            src_comp = comp_by_spdx_id[component["spdxId"]]
            declared_lic: str | None = None
            if v4:
                raw_lic = getattr(src_comp, "license", None) or src_comp.properties.get(
                    "declared_license"
                )
                # Free text stays in the native extension; SPDX gets NoAssertion.
                declared_lic = spdx_license_expression(raw_lic)
            for kind in ("hasDeclaredLicense", "hasConcludedLicense"):
                if kind == "hasDeclaredLicense" and declared_lic:
                    lic_id = ids.element("license-expression", declared_lic)
                    license_elements.setdefault(
                        lic_id,
                        {
                            "type": "simplelicensing_LicenseExpression",
                            "spdxId": lic_id,
                            "creationInfo": ci,
                            "simplelicensing_licenseExpression": declared_lic,
                        },
                    )
                    target_lic = lic_id
                else:
                    target_lic = NO_ASSERTION_LICENSE
                    used_no_assertion = True
                license_relationships.append(
                    {
                        "type": "Relationship",
                        "spdxId": ids.element(
                            "license-relationship", component["spdxId"] + ":" + kind
                        ),
                        "creationInfo": ci,
                        "relationshipType": kind,
                        "from": component["spdxId"],
                        "to": [target_lic],
                    }
                )
                if target_lic != NO_ASSERTION_LICENSE and not getattr(src_comp, "license", None):
                    license_relationships[-1]["comment"] = "declared by producer"

        subject = repository_subject(aibom)
        members: list[dict[str, Any]] = [
            *parties,
            *(license_elements[k] for k in sorted(license_elements)),
            *components,
            *relationships,
            *license_relationships,
        ]
        sbom: dict[str, Any] = {
            "type": "software_Sbom",
            "spdxId": ids.element("sbom", "inventory"),
            "creationInfo": ci,
            "element": [member["spdxId"] for member in members],
            "rootElement": [
                ids.element("component", comp.bom_ref)
                for comp in ([subject] if subject is not None else ordered)
                if comp.component_type == ComponentType.AGENT
            ],
        }
        if repository_scan(aibom):
            sbom["software_sbomType"] = ["source"]
        elements: list[dict[str, Any]] = [creator, *author_elements, generator, *members, sbom]

        profiles = ["core", "software"]
        if v4:
            ai_pkgs = [c for c in components if c["type"] == "ai_AIPackage"]
            if ai_pkgs and all(
                all(
                    req in c
                    for req in (
                        "suppliedBy",
                        "releaseTime",
                        "software_packageVersion",
                        "software_downloadLocation",
                    )
                )
                for c in ai_pkgs
            ):
                profiles.append("ai")
            ds_pkgs = [c for c in components if c["type"] == "dataset_DatasetPackage"]
            if ds_pkgs and all(
                all(
                    req in c
                    for req in (
                        "suppliedBy",
                        "releaseTime",
                        "software_packageVersion",
                        "software_downloadLocation",
                    )
                )
                and c.get("dataset_datasetType") != ["noAssertion"]
                for c in ds_pkgs
            ):
                profiles.append("dataset")
            if license_elements:
                profiles.append("simpleLicensing")
        if used_no_assertion or (not v4 and license_relationships):
            profiles.append("expandedLicensing")
        profiles.append("extension")

        doc_props = [
            *document_properties(aibom, self.format_name, native),
            *(
                [{"name": _AUTHOR_PROPERTY, "value": self._author}]
                if v4 and self._author is not None
                else []
            ),
            {
                "name": PROJECTION_PROPERTY,
                "value": (
                    PREVIOUS_PROJECTION if legacy_v2 else (PROJECTION_V4 if v4 else PROJECTION)
                ),
            },
        ]
        doc = {
            "type": "SpdxDocument",
            "spdxId": ids.document,
            "creationInfo": ci,
            "name": "Nexus SymBiote AgentBOM " + str(aibom.metadata.serial_number),
            "element": [element["spdxId"] for element in elements],
            "rootElement": [sbom["spdxId"]],
            "profileConformance": profiles,
            "comment": COVERAGE_COMMENTS[coverage],
            "extension": _extension(doc_props),
        }
        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [doc, *elements, creation],
        }

    @staticmethod
    def _element(
        comp: AnyComponent,
        ids: _DocumentIds,
        native: dict[str, Any],
        *,
        v4: bool = False,
    ) -> dict[str, Any]:
        from nexus_symbiote.spdx_profiles import (
            _clean_url,
            normalize_spdx_dataset_type,
            spdx_autonomy_presence,
        )

        typ = SPDX_TYPE_MAP.get(comp.component_type, "software_Package")
        declared_fields: list[str] = []
        element: dict[str, Any] = {
            "type": typ,
            "spdxId": ids.element("component", comp.bom_ref),
            "creationInfo": ids.creation,
            "name": comp.name,
            # Projection 3 pins this key position; projection 4 refills it below.
            "extension": None,
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
        version = standard_version(comp)
        if typ != "software_File" and version:
            element["software_packageVersion"] = version
        if comp.supplier:
            element["suppliedBy"] = ids.element("supplier", comp.supplier)
        if comp.description:
            element["description"] = comp.description
        if typ == "ai_AIPackage":
            element["software_primaryPurpose"] = (
                "model" if isinstance(comp, ModelComponent) else "application"
            )
            if isinstance(comp, ModelComponent) and comp.model_type:
                element["ai_typeOfModel"] = [comp.model_type]
            if isinstance(comp, AgentComponent) and comp.description:
                element["ai_informationAboutApplication"] = comp.description
            if v4:
                presence = spdx_autonomy_presence(comp)
                if presence != "noAssertion":
                    element["ai_autonomyType"] = presence
                    if not (isinstance(comp, AgentComponent) and comp.autonomy_level is not None):
                        declared_fields.append("ai_autonomyType")
                rel_ts = comp.properties.get("declared_release_time")
                if isinstance(rel_ts, str) and rel_ts:
                    element["releaseTime"] = rel_ts
                    declared_fields.append("releaseTime")
                # A supplied inventory may declare any value; it is cleaned as agent.yaml's is.
                dl_loc = _clean_url(comp.properties.get("declared_download_location"))
                if dl_loc:
                    element["software_downloadLocation"] = dl_loc
                    declared_fields.append("software_downloadLocation")
                domain = comp.properties.get("declared_domain")
                if isinstance(domain, str) and domain:
                    element["ai_domain"] = [domain]
                    declared_fields.append("ai_domain")
                train_info = comp.properties.get("declared_training_info")
                if isinstance(train_info, str) and train_info:
                    element["ai_informationAboutTraining"] = train_info
                    declared_fields.append("ai_informationAboutTraining")
                compliance = comp.properties.get("declared_compliance")
                if (
                    isinstance(compliance, list)
                    and all(isinstance(x, str) for x in compliance)
                    and compliance
                ):
                    element["ai_standardCompliance"] = list(compliance)
                    declared_fields.append("ai_standardCompliance")
        elif typ == "dataset_DatasetPackage":
            element["software_primaryPurpose"] = "data"
            if v4:
                raw_ds_type = getattr(comp, "dataset_type", None) or getattr(
                    comp, "corpus_type", None
                )
                element["dataset_datasetType"] = [
                    normalize_spdx_dataset_type(
                        raw_ds_type if isinstance(raw_ds_type, str) else None
                    )
                ]
                rel_ts = comp.properties.get("declared_release_time")
                if isinstance(rel_ts, str) and rel_ts:
                    element["releaseTime"] = rel_ts
                    declared_fields.append("releaseTime")
                observed_loc = _clean_url(getattr(comp, "source_uri", None))
                dl_loc = observed_loc or _clean_url(
                    comp.properties.get("declared_download_location")
                )
                if isinstance(dl_loc, str) and dl_loc:
                    element["software_downloadLocation"] = dl_loc
                    if not observed_loc:
                        declared_fields.append("software_downloadLocation")
                avail = comp.properties.get("declared_availability")
                if isinstance(avail, str) and avail:
                    element["dataset_datasetAvailability"] = avail
                    declared_fields.append("dataset_datasetAvailability")
                pii = comp.properties.get("declared_sensitive_pii")
                if pii in {"yes", "no", "noAssertion"}:
                    element["dataset_hasSensitivePersonalInformation"] = pii
                    declared_fields.append("dataset_hasSensitivePersonalInformation")
            else:
                # The only property the Dataset class requires; the inventory has no type.
                element["dataset_datasetType"] = ["noAssertion"]
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
        ext_props = [
            component_property(comp, native),
            *claim_properties(comp),
            *package_identifier_properties(comp),
            *({"name": "nexus-symbiote:declaredField", "value": f} for f in declared_fields),
        ]
        element["extension"] = _extension(ext_props)
        hashes = standard_hashes(comp)
        if hashes:
            element["verifiedUsing"] = [
                {"type": "Hash", "algorithm": _spdx_algorithm(name), "hashValue": digest}
                for name, digest in hashes
            ]
        return element

    @staticmethod
    def _relationship(
        edge: DependencyEdge,
        ids: _DocumentIds,
        completeness: str,
        *,
        neutralize_comments: bool = True,
        v4: bool = False,
    ) -> dict[str, Any]:
        mapping = _MAPPING_V4 if v4 else _MAPPING_V3
        body = edge.model_dump(mode="json", exclude_none=True)
        typed = mapping.get(edge.relationship)
        from_ref = edge.source_ref
        to_ref = edge.target_ref
        # In SPDX 3.0.1, `from --configures--> to` means `from` is the configuration
        # applied to `to`, which is the inverse of native `agent --configured-with--> prompt`.
        if v4 and not edge.conditions and typed == "configures":
            from_ref, to_ref = edge.target_ref, edge.source_ref
        relationship = {
            "type": "Relationship",
            "spdxId": ids.element("relationship", content_digest(body)),
            "creationInfo": ids.creation,
            # A typed SPDX relationship is unconditional; standard-only consumers
            # never see the native condition, so match the CycloneDX graph rule.
            "relationshipType": "other" if edge.conditions or typed is None else typed,
            "from": ids.element("component", from_ref),
            "to": [ids.element("component", to_ref)],
            "completeness": completeness,
            "extension": _extension(
                [{"name": "nexus-symbiote:relationship", "value": json_text(body)}]
            ),
        }
        # Projection 2 rendered the original text. Retain that exact rendering
        # only for recovery; new exports declare projection 3 and neutralize it.
        shown_relationship = (
            _comment_text(edge.relationship) if neutralize_comments else edge.relationship
        )
        if edge.conditions:
            # SARIF and VEX neutralize inventory text in rendered messages; SPDX
            # comments are rendered by viewers the same way.
            conditions = _comment_text(edge.conditions) if neutralize_comments else edge.conditions
            if len(conditions) > MAX_CONDITION_COMMENT:
                conditions = conditions[:MAX_CONDITION_COMMENT] + " [truncated]"
            relationship["comment"] = (
                f"Conditional native relationship '{shown_relationship}' (conditions: "
                f"{conditions}). Not an unconditional {typed or 'relationship'} assertion."
            )
        elif typed is None:
            relationship["comment"] = f"Native relationship '{shown_relationship}'."
        return relationship

    @staticmethod
    def recover(document: dict[str, Any]) -> AIBOM:
        """Require agreement with the embedded inventory under the declared projection.

        A document without a projection marker was written by 0.1.0 and must match that
        projection. Malformed input raises ValueError.
        """
        try:
            return SPDXGenerator._recover(document)
        except (RecursionError, Unresolvable, KeyError, TypeError, AttributeError) as exc:
            raise ValueError("SPDX document cannot be recovered") from exc

    @staticmethod
    def _recover(document: dict[str, Any]) -> AIBOM:
        graph = document.get("@graph")
        docs = [
            node
            for node in (graph if isinstance(graph, list) else [])
            if isinstance(node, dict) and node.get("type") == "SpdxDocument"
        ]
        if len(docs) != 1:
            raise ValueError("expected exactly one SPDX document")
        doc = docs[0]
        properties = [
            {"name": prop["extension_cdxPropName"], "value": prop.get("extension_cdxPropValue", "")}
            for extension in doc.get("extension", [])
            if isinstance(extension, dict)
            and extension.get("type") == "extension_CdxPropertiesExtension"
            for prop in extension.get("extension_cdxProperty", [])
            if isinstance(prop, dict) and "extension_cdxPropName" in prop
        ]
        projection = declared_projection(properties)
        namespace = _document_namespace(doc["spdxId"])
        recovered, native = recover_native(properties)
        if projection == PROJECTION_V4:
            author_prop = next(
                (p["value"] for p in properties if p["name"] == _AUTHOR_PROPERTY),
                None,
            )
            expected = SPDXGenerator(
                namespace, projection_version=4, author=author_prop
            )._projection(recovered, native)
        elif projection in {PROJECTION, PREVIOUS_PROJECTION}:
            expected = SPDXGenerator(namespace)._projection(
                recovered, native, legacy_v2=projection == PREVIOUS_PROJECTION
            )
        elif projection is None and namespace is not None:
            expected = _legacy.spdx_projection(recovered, namespace, native)
        else:
            raise ValueError("unsupported SPDX projection version")
        # Without a native timestamp, CreationInfo.created is render-time
        # metadata and a re-projection at recovery time legitimately differs
        # only there. With one, the export must carry exactly that timestamp.
        actual, wanted = _public_view(document), _public_view(expected)
        if recovered.metadata.timestamp is None:
            actual, wanted = _without_created(actual), _without_created(wanted)
        if unordered_projection(actual) != unordered_projection(wanted):
            raise ValueError("SPDX projection conflicts with the embedded native document")
        # Only the flat reference topology emitted by a supported projection may
        # reach schema validation. Inline reference objects can make the general
        # SPDX schema revisit a tiny nested input an enormous number of times.
        errors = spdx_errors(
            document,
            legacy_license=_legacy.NO_ASSERTION_LICENSE if projection is None else None,
        )
        if errors:
            raise ValueError("invalid spdx export: " + "; ".join(errors[:10]))
        return recovered


def _public_view(document: dict[str, Any]) -> dict[str, Any]:
    # A conforming JSON-LD consumer can omit an empty root element set.
    return {
        **document,
        "@graph": [
            {**node, "rootElement": node.get("rootElement", [])}
            if isinstance(node, dict) and node.get("type") in SPDX_COLLECTIONS
            else node
            for node in document["@graph"]
        ],
    }


def _spdx_algorithm(name: str) -> str:
    """SPDX spells SHA3 digests with an underscore and the others without separators."""
    return (
        name.lower().replace("-", "_")
        if name.startswith("SHA3-")
        else name.lower().replace("-", "")
    )
