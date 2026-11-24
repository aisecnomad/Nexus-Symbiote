"""Shared export identity, extension preservation, and loss reporting."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Literal

from nexus_symbiote.core.aibom import (
    AIBOM,
    MAX_NATIVE_NESTING,
    _nested_deeper_than,
    native_document,
)
from nexus_symbiote.core.canonical import content_digest, json_text
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.hashing import extract_version_pin, parse_json_strict
from nexus_symbiote.core.models import AnyComponent, CompletenessClaim, RegistryEntryComponent
from nexus_symbiote.generators.package_identifiers import package_identifier
from nexus_symbiote.utils.confined import DEFAULT_EXCLUDES

# The confined collector never reads these trees, so excluding them again narrows nothing.
BUILTIN_EXCLUSIONS = frozenset({*DEFAULT_EXCLUDES, *(f"**/{name}" for name in DEFAULT_EXCLUDES)})
# The collector universe of the standard projections. A collector added later still
# narrows public coverage through the claim's scanner_status, which `scan` fills for
# every collector it knows; a frozen set keeps earlier exports recoverable.
PROJECTION_SCANNERS = frozenset(
    {"mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"}
)
PROJECTION_PROPERTY = "nexus-symbiote:projection"
REPOSITORY_AGENT_PREFIX = "agent:repository:"
NATIVE_DOCUMENT_LIMIT = 16 * 1024 * 1024
# CycloneDX 1.7 bounds component.version; a longer declaration stays in a property.
MAX_STANDARD_VERSION = 1024
HASH_ALGORITHMS = {
    "md5": ("MD5", 32),
    "sha1": ("SHA-1", 40),
    "sha256": ("SHA-256", 64),
    "sha384": ("SHA-384", 96),
    "sha512": ("SHA-512", 128),
    "sha3256": ("SHA3-256", 64),
    "sha3384": ("SHA3-384", 96),
    "sha3512": ("SHA3-512", 128),
    "blake2b256": ("BLAKE2b-256", 64),
    "blake2b384": ("BLAKE2b-384", 96),
    "blake2b512": ("BLAKE2b-512", 128),
    "blake3": ("BLAKE3", 64),
}
_SRI = re.compile(r"(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})")


def native_components(native: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {component["bom_ref"]: component for component in native["components"]}


def repository_subject(bom: AIBOM) -> AnyComponent | None:
    """The repository agent a scan assembles, which is what a scan's BOM describes."""
    agents = [
        component
        for component in bom.components
        if component.component_type == ComponentType.AGENT
        and component.bom_ref.startswith(REPOSITORY_AGENT_PREFIX)
    ]
    return agents[0] if len(agents) == 1 else None


def repository_scan(bom: AIBOM) -> bool:
    claim = bom.metadata.completeness
    return claim is not None and claim.scope.split("+", 1)[0] == "repository"


def standard_version(component: AnyComponent) -> str | None:
    """The version for standard version fields, at most 1024 characters long.

    A registry entry gets an exact version or nothing; any other kind keeps its
    declared version.
    """
    package = package_identifier(component)
    if package.version is not None:
        return package.version if len(package.version) <= MAX_STANDARD_VERSION else None
    version = component.version
    if not version or len(version) > MAX_STANDARD_VERSION:
        return None
    if not isinstance(component, RegistryEntryComponent):
        return version
    registry = (component.registry_type or "").lower()
    if registry == "pypi":
        return extract_version_pin(
            version if version.startswith("==") else "==" + version, ecosystem="python"
        )
    if registry == "npm":
        return extract_version_pin(f"{component.name}@{version}", ecosystem="npm")
    if registry in {"docker-hub", "docker", "oci"}:
        return extract_version_pin(f"{component.name}:{version}", ecosystem="oci")
    return extract_version_pin(version)


def requested_version(component: AnyComponent) -> str | None:
    """A declared version that standard version fields cannot carry, such as a range."""
    if component.version and standard_version(component) is None:
        return component.version
    return None


def _promoted_digests(component: AnyComponent) -> list[tuple[str, str]]:
    digests: list[tuple[str, str]] = []
    for field in ("content_hash", "index_snapshot_hash"):
        value = getattr(component, field, None)
        if isinstance(value, str) and ":" in value:
            try:
                digests.append(normalize_hash(value.split(":", 1)[0], value))
            except ValueError:
                continue
    integrity = (
        component.properties.get("lockfile_integrity")
        if isinstance(component, RegistryEntryComponent)
        else None
    )
    for token in integrity.split() if isinstance(integrity, str) else []:
        match = _SRI.fullmatch(token)
        if match is None:
            continue
        try:
            digests.append(
                normalize_hash(match[1], base64.b64decode(match[2], validate=True).hex())
            )
        except (ValueError, binascii.Error):
            continue
    return digests


def standard_hashes(component: AnyComponent) -> list[tuple[str, str]]:
    """Declared digests, then single-purpose digests that have a standard home.

    An instruction file's content digest, a RAG index snapshot digest, a dataset
    content digest and a lockfile integrity value are promoted only when the
    declared hashes lack that algorithm and the digest is well formed. Two
    different declared digests for one algorithm fail the export.
    """
    result: dict[str, str] = {}
    for algorithm, value in sorted(component.hashes.items()):
        name, digest = normalize_hash(algorithm, value)
        if result.setdefault(name, digest) != digest:
            raise ValueError(f"conflicting {name} digests")
    for name, digest in _promoted_digests(component):
        result.setdefault(name, digest)
    return sorted(result.items())


def loss_report(bom: AIBOM, target: str, native: dict[str, Any] | None = None) -> dict[str, Any]:
    preserves_native = target.startswith(("cyclonedx-", "spdx-"))
    document = native_document(bom) if native is None else native
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
        typed = {c.bom_ref: c for c in bom.components}
        for index, component in enumerate(document["components"]):
            for field in fields:
                if field in component and component[field] not in (None, [], {}):
                    add(
                        f"/components/{index}/{field}",
                        "Full agent-specific field semantics require the extension; "
                        "the standard projection may omit or normalize them",
                    )
            if component.get("risks"):
                add(
                    f"/components/{index}/risks",
                    "Risk findings are not standard inventory fields; SARIF and VEX "
                    "output project them separately",
                )
            model = typed.get(component["bom_ref"])
            if model is not None and requested_version(model) is not None:
                add(
                    f"/components/{index}/version",
                    "The declared version is not an exact version or is longer than "
                    "1024 characters, so standard version fields omit it",
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
            "reason": "declared package URL is invalid, unsupported or conflicts with the "
            "component; standard identifier omitted",
            "preservedIn": "nexus-symbiote:document",
            "severity": "warning",
        }
        for index, component in enumerate(sorted(bom.components, key=lambda c: c.bom_ref))
        if preserves_native and package_identifier(component).status == "unavailable-invalid"
    ]
    return {
        "profile": "nexus-symbiote-export/v2",
        "target": target,
        "sourceDigest": content_digest(document),
        "nativeSemanticsComplete": False,
        "extensionRoundTripComplete": preserves_native,
        "admissionAuthority": False,
        "normalizations": [
            "component and dependency collections sorted for deterministic output",
            *(
                [
                    "valid declared package URLs canonicalized",
                    (
                        "standard version fields carry exact versions of registry entries "
                        "and the declared versions of other kinds, up to 1024 characters"
                    ),
                ]
                if preserves_native
                else []
            ),
        ],
        "itemCoverage": "selected-security-fields" if preserves_native else "summary-only",
        "items": [*items, *identifier_losses],
    }


def coverage_aggregate(claim: CompletenessClaim | None) -> Literal["incomplete", "unknown"]:
    """Public coverage for standard-only consumers, which never see the native claim.

    Static collection never observes runtime, network or live tool surfaces, so
    the best result is "unknown" and an export never claims "complete".
    """
    if claim is None:
        return "unknown"
    requested = set(claim.collectors_requested)
    narrowed = (
        imports_discovery(claim)
        or bool(PROJECTION_SCANNERS - requested)
        or bool(requested - set(claim.collectors_completed))
        or any(state != "complete" for state in claim.scanner_status.values())
        or bool(claim.scan_failures or claim.surfaces_excluded)
        or not BUILTIN_EXCLUSIONS.issuperset(claim.exclusions)
    )
    return "incomplete" if narrowed else "unknown"


OMITTED_IMPORTED_FINDINGS = "nexus-symbiote:omittedImportedFindings"


def imported_discovery_component(component: AnyComponent) -> bool:
    """A finding-only export (SARIF, VEX) cannot carry imported coverage and provenance.

    Imported ShadowScan heuristics must not appear there as this tool's own findings,
    so those exports omit them and state how many were omitted.
    """
    return (
        component.properties.get("collection_mode") == "imported-unverified-report"
        or component.bom_ref.startswith("shadowscan:")
        or "discovery_report_entry" in component.claims
        or any(key.startswith("shadowscan:") for key in component.properties)
    )


def imports_discovery(claim: CompletenessClaim) -> bool:
    """Any imported-report marker counts, even without the digest the CLI always sets.

    The model does not tie these fields together. Every ``source_*`` field is compared
    with its default, so a field added later counts too.
    """
    return "shadowscan" in claim.scope.lower() or any(
        getattr(claim, name) != field.get_default(call_default_factory=True)
        for name, field in CompletenessClaim.model_fields.items()
        if name.startswith("source_")
    )


def unordered_projection(value: Any, *, _depth: int = 0) -> Any:
    """The arrays emitted by our standard projections are unordered collections.

    Native JSON in extension strings stays opaque, including ordered arguments
    and authority conditions. Sorting never drops duplicate entries or fields.
    """
    if _depth > MAX_NATIVE_NESTING:
        raise ValueError("projection is nested too deeply and cannot be recovered")
    if isinstance(value, list):
        return sorted(
            (unordered_projection(item, _depth=_depth + 1) for item in value), key=json_text
        )
    if isinstance(value, dict):
        return {key: unordered_projection(item, _depth=_depth + 1) for key, item in value.items()}
    return value


def document_properties(
    bom: AIBOM, target: str, native: dict[str, Any] | None = None
) -> list[dict[str, str]]:
    document = native_document(bom) if native is None else native
    if _nested_deeper_than(document, MAX_NATIVE_NESTING):
        raise ValueError("embedded native document is nested too deeply")
    encoded = json_text(document)
    if len(encoded.encode("utf-8")) > NATIVE_DOCUMENT_LIMIT:
        raise ValueError("embedded native document exceeds the byte limit")
    return [
        {"name": "nexus-symbiote:document", "value": encoded},
        {"name": "nexus-symbiote:documentDigest", "value": content_digest(document)},
        {
            "name": "nexus-symbiote:lossReport",
            "value": json_text(loss_report(bom, target, document)),
        },
    ]


def component_property(comp: AnyComponent, native: dict[str, Any] | None = None) -> dict[str, str]:
    value = comp.model_dump(mode="json", exclude_none=True) if native is None else native
    return {"name": "nexus-symbiote:component", "value": json_text(value)}


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


def declared_projection(properties: list[dict[str, Any]]) -> str | None:
    """The projection version a document declares; absent for 0.1.0 exports."""
    values = [p.get("value") for p in properties if p.get("name") == PROJECTION_PROPERTY]
    if len(values) > 1 or any(not isinstance(value, str) for value in values):
        raise ValueError("invalid projection version marker")
    return values[0] if values else None


def recover_native(properties: list[dict[str, Any]]) -> tuple[AIBOM, dict[str, Any]]:
    """Recover the native representation and its exact embedded document.

    The digest binds the embedded document, without authenticating its producer. The
    embedded text is parsed and validated like a native AgentBOM file: bounded in size
    and nesting, with duplicate keys and non-finite numbers rejected, and refused
    without quoting its values.
    """
    required = {
        "nexus-symbiote:document",
        "nexus-symbiote:documentDigest",
        "nexus-symbiote:lossReport",
    }
    native_properties = [p for p in properties if p["name"] in required]
    if any(not isinstance(p.get("value"), str) for p in native_properties):
        raise ValueError("missing native document property value")
    props = {p["name"]: p["value"] for p in native_properties}
    if len(props) != len(native_properties):
        raise ValueError("duplicate native document property names")
    if required.difference(props):
        raise ValueError("missing native document properties")
    try:
        document = parse_json_strict(
            props["nexus-symbiote:document"], max_bytes=NATIVE_DOCUMENT_LIMIT
        )
    except RecursionError as exc:
        raise ValueError("embedded native document is nested too deeply") from exc
    if _nested_deeper_than(document, MAX_NATIVE_NESTING):
        raise ValueError("embedded native document is nested too deeply")
    if not isinstance(document, dict):
        raise ValueError("embedded native document must be a JSON object")
    if props["nexus-symbiote:documentDigest"] != content_digest(document):
        raise ValueError("embedded native document digest mismatch")
    # As a native file is loaded: the refusal never quotes the document's values.
    return AIBOM.from_native(document), document
