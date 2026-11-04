"""Shared export identity, extension preservation, and loss reporting."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import AnyComponent

NAMESPACE = uuid.UUID("ccaa2a43-8ba9-58e6-8f22-f8793a2039d5")
HASH_ALGORITHMS = {
    "md5": ("MD5", 32),
    "sha1": ("SHA-1", 40),
    "sha256": ("SHA-256", 64),
    "sha384": ("SHA-384", 96),
    "sha512": ("SHA-512", 128),
    "sha3256": ("SHA3-256", 64),
    "sha3384": ("SHA3-384", 96),
    "sha3512": ("SHA3-512", 128),
}


def json_text(value: Any) -> str:
    """Deterministic UTF-8 JSON representation; not a claim of RFC 8785 canonicalization."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def content_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json_text(value).encode("utf-8")).hexdigest()


def prepare(bom: AIBOM) -> AIBOM:
    """Fill missing export metadata once; never reset an existing observation timestamp."""
    if bom.metadata.timestamp is None:
        bom.metadata.timestamp = datetime.now(UTC)
    if bom.metadata.timestamp.tzinfo is None:
        raise ValueError("export timestamps must include a timezone")
    if bom.metadata.tool_version is None:
        bom.metadata.tool_version = __version__
    if bom.metadata.serial_number is None:
        body = native_document(bom)
        bom.metadata.serial_number = "urn:uuid:" + str(uuid.uuid5(NAMESPACE, content_digest(body)))
    ids = [c.bom_ref for c in bom.components]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate component references")
    known = set(ids)
    for edge in bom.dependencies:
        if edge.source_ref not in known or edge.target_ref not in known:
            raise ValueError("dependency references an unknown component")
    return bom


def native_document(bom: AIBOM) -> dict[str, Any]:
    document = bom.model_dump(mode="json", exclude_none=True)
    document["components"] = sorted(document["components"], key=lambda c: c["bom_ref"])
    document["dependencies"] = sorted(document["dependencies"], key=json_text)
    return document


def loss_report(bom: AIBOM, target: str) -> dict[str, Any]:
    from nexus_symbiote.generators.package_identifiers import package_identifier

    preserves_native = target.startswith(("cyclonedx-", "spdx-"))
    document = native_document(bom)
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
        # Paths refer to the sorted native document identified by sourceDigest.
        # Enumerate selected security-sensitive fields, not every loss.
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


def unordered_projection(value: Any) -> Any:
    """The arrays emitted by our standard projections are unordered collections.

    Native JSON in extension strings stays opaque, including ordered arguments
    and authority conditions. Sorting never drops duplicate entries or fields.
    """
    if isinstance(value, list):
        return sorted((unordered_projection(item) for item in value), key=json_text)
    if isinstance(value, dict):
        return {key: unordered_projection(item) for key, item in value.items()}
    return value


def document_properties(bom: AIBOM, target: str) -> list[dict[str, str]]:
    document = native_document(bom)
    return [
        {"name": "nexus-symbiote:document", "value": json_text(document)},
        {"name": "nexus-symbiote:documentDigest", "value": content_digest(document)},
        {"name": "nexus-symbiote:lossReport", "value": json_text(loss_report(bom, target))},
    ]


def component_property(comp: AnyComponent) -> dict[str, str]:
    return {
        "name": "nexus-symbiote:component",
        "value": json_text(comp.model_dump(mode="json", exclude_none=True)),
    }


def claim_properties(comp: AnyComponent) -> list[dict[str, str]]:
    return [
        {"name": "agentbom:kind", "value": comp.component_type.value},
        {"name": "agentbom:claimsVerifiedByExporter", "value": "false"},
    ]


def normalize_hash(algorithm: str, value: str) -> tuple[str, str]:
    key = algorithm.lower().replace("-", "").replace("_", "")
    if key not in HASH_ALGORITHMS:
        raise ValueError(f"unsupported hash algorithm: {algorithm}")
    name, length = HASH_ALGORITHMS[key]
    if ":" in value:
        prefix, value = value.split(":", 1)
        if prefix.lower().replace("-", "").replace("_", "") != key:
            raise ValueError("hash prefix disagrees with algorithm")
    if len(value) != length or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise ValueError(f"invalid {name} digest")
    return name, value.lower()


def recover_document(properties: list[dict[str, str]]) -> AIBOM:
    """Recover the native representation and check its digest, without authenticating its producer."""
    required = {
        "nexus-symbiote:document",
        "nexus-symbiote:documentDigest",
        "nexus-symbiote:lossReport",
    }
    native_properties = [p for p in properties if p["name"] in required]
    if any("value" not in p for p in native_properties):
        raise ValueError("missing native document property value")
    props = {p["name"]: p["value"] for p in native_properties}
    if len(props) != len(native_properties):
        raise ValueError("duplicate native document property names")
    if required.difference(props):
        raise ValueError("missing native document properties")
    from nexus_symbiote.generators.validation import parse_embedded_inventory

    document = parse_embedded_inventory(props["nexus-symbiote:document"])
    if props["nexus-symbiote:documentDigest"] != content_digest(document):
        raise ValueError("embedded native document digest mismatch")
    return AIBOM.model_validate(document)
