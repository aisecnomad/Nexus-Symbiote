"""Offline validation against pinned official schemas and local graph constraints."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import TYPE_CHECKING, Any

from jsonschema import Draft7Validator, Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from nexus_symbiote.generators._spdx_dispatch import dispatched_spdx_schema

if TYPE_CHECKING:
    from nexus_symbiote.core.aibom import AIBOM

# Received exports are checked against these limits before schema validation, whose
# cost grows quadratically with CycloneDX components and dependency rows (uniqueItems)
# and by up to a few tenths of a second per SPDX graph entry.
MAX_RECEIVED_DEPTH = 32
MAX_RECEIVED_VALUES = 1_000_000
MAX_RECEIVED_COMPONENTS = 2_000
MAX_RECEIVED_SPDX_ELEMENTS = 1_000
MAX_RECEIVED_RELATIONSHIPS = 10_000


class VerificationLimitError(ValueError):
    """A received export is larger than verification accepts."""


def require_received_limits(document: Any, fmt: str) -> None:
    """Refuse an oversized received export before any costly or recursive check."""
    pending: list[tuple[Any, int]] = [(document, 1)]
    remaining = MAX_RECEIVED_VALUES
    while pending:
        value, depth = pending.pop()
        if isinstance(value, dict | list):
            remaining -= len(value)
            if depth > MAX_RECEIVED_DEPTH or remaining < 0:
                raise VerificationLimitError("export exceeds the verification limits")
            children = value.values() if isinstance(value, dict) else value
            pending.extend((child, depth + 1) for child in children)
    if not isinstance(document, dict):
        raise ValueError("export must be a JSON object")
    if fmt == "spdx":
        collections = [(document.get("@graph"), MAX_RECEIVED_SPDX_ELEMENTS)]
    else:
        collections = [
            (document.get("components"), MAX_RECEIVED_COMPONENTS),
            (document.get("dependencies"), MAX_RECEIVED_COMPONENTS),
        ]
    if any(isinstance(items, list) and len(items) > limit for items, limit in collections):
        raise VerificationLimitError("export exceeds the verification limits")


def require_inventory_limits(bom: AIBOM) -> None:
    """Bound the projection rebuilt from an embedded, unauthenticated inventory."""
    if (
        len(bom.components) > MAX_RECEIVED_COMPONENTS
        or len(bom.dependencies) > MAX_RECEIVED_RELATIONSHIPS
    ):
        raise VerificationLimitError("embedded inventory exceeds the verification limits")


def _schema(name: str) -> dict[str, Any]:
    schema = json.loads(
        files("nexus_symbiote.generators").joinpath("schemas/vendor/" + name).read_text()
    )
    if not isinstance(schema, dict):
        raise ValueError("vendored schema must be a JSON object")
    return schema


@lru_cache(maxsize=2)
def _validator(fmt: str) -> Any:
    if fmt == "spdx":
        return Draft202012Validator(
            dispatched_spdx_schema(_schema("spdx/spdx-json-schema-3.0.1.json")),
            format_checker=FormatChecker(),
        )
    main = _schema("cyclonedx/bom-1.7.schema.json")
    base = main["$id"]
    directory = base.rsplit("/", 1)[0] + "/"
    schemas = [(base, Resource.from_contents(main, default_specification=DRAFT7))]
    for name in ("jsf-0.82.schema.json", "spdx.schema.json"):
        resource = Resource.from_contents(
            _schema("cyclonedx/" + name), default_specification=DRAFT7
        )
        schemas.extend([(directory + name, resource), (name, resource)])
    return Draft7Validator(
        main, registry=Registry().with_resources(schemas), format_checker=FormatChecker()
    )


def validate_cyclonedx(document: dict[str, Any]) -> list[str]:
    errors = _schema_errors(document, "cyclonedx")
    if errors:
        return errors
    refs = [c["bom-ref"] for c in document.get("components", []) if "bom-ref" in c]
    if len(refs) != len(set(refs)):
        errors.append("duplicate CycloneDX bom-ref")
    known = set(refs)
    dep_refs: set[str] = set()
    for dependency in document.get("dependencies", []):
        ref = dependency.get("ref")
        if ref in dep_refs:
            errors.append("duplicate CycloneDX dependency ref")
        dep_refs.add(ref)
        for target in [ref, *dependency.get("dependsOn", []), *dependency.get("provides", [])]:
            if target not in known:
                errors.append(f"unresolved CycloneDX reference: {target}")
    return errors


def validate_spdx(document: dict[str, Any]) -> list[str]:
    errors = _schema_errors(document, "spdx")
    if errors:
        return errors
    graph = document.get("@graph", [])
    ids = [n.get("spdxId", n.get("@id")) for n in graph]
    if None in ids or len(ids) != len(set(ids)):
        errors.append("missing or duplicate SPDX graph identifier")
    known = set(ids)
    for node in graph:
        if node.get("type") == "SpdxDocument" and not set(node.get("rootElement", [])).issubset(
            node.get("element", [])
        ):
            errors.append("SPDX rootElement is not in document element collection")
        for field in (
            "creationInfo",
            "createdBy",
            "createdUsing",
            "suppliedBy",
            "element",
            "rootElement",
            "from",
            "to",
        ):
            values = node.get(field, [])
            values = values if isinstance(values, list) else [values]
            for value in values:
                # SPDX's predefined NoAssertion license is a vocabulary individual,
                # not an artifact that the exporting producer can redefine.
                standard_license = (
                    field == "to"
                    and node.get("relationshipType")
                    in {"hasDeclaredLicense", "hasConcludedLicense"}
                    and value == "https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion"
                )
                if isinstance(value, str) and value not in known and not standard_license:
                    errors.append(f"unresolved SPDX {field}: {value}")
    outgoing: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for node in graph:
        source, kind = node.get("from"), node.get("relationshipType")
        if node.get("type") == "Relationship" and isinstance(source, str) and isinstance(kind, str):
            outgoing.setdefault((source, kind), []).append(node)
    for package in graph:
        if package.get("type") not in {"ai_AIPackage", "dataset_DatasetPackage"}:
            continue
        for kind in ("hasDeclaredLicense", "hasConcludedLicense"):
            package_id = package.get("spdxId")
            relations = outgoing.get((package_id, kind), []) if isinstance(package_id, str) else []
            if len(relations) != 1 or len(relations[0].get("to", [])) != 1:
                errors.append(f"SPDX {package.get('spdxId')} requires exactly one {kind} target")
    return errors


def _schema_errors(document: dict[str, Any], fmt: str) -> list[str]:
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:180]}"
        for e in _validator(fmt).iter_errors(document)
    ]


def require_valid(document: dict[str, Any], fmt: str) -> None:
    errors = validate_spdx(document) if fmt == "spdx" else validate_cyclonedx(document)
    if errors:
        raise ValueError(f"invalid {fmt} export: " + "; ".join(errors[:10]))
