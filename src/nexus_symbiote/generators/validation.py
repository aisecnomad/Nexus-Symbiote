"""Offline validation against pinned official schemas and local graph constraints.

Array uniqueness uses a set instead of jsonschema's pairwise fallback for
unorderable items, and graph checks index each collection once. General schema
validation is not a resource sandbox: nested SPDX reference objects can amplify
work. Recovery restricts input to a supported projection before validating it.
Callers validating arbitrary documents must enforce external resource limits.
Format assertions use the checkers defined here, so the result does not depend on
which optional packages happen to be installed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import date, datetime
from functools import lru_cache
from importlib.resources import files
from typing import Any

from jsonschema import (
    Draft4Validator,
    Draft7Validator,
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)
from jsonschema import validators as jsonschema_validators
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT7

from nexus_symbiote.generators._spdx_dispatch import dispatched_spdx_schema

_VENDOR = "schemas/vendor/"
_CYCLONEDX_SUBSCHEMAS = (
    "cryptography-defs.schema.json",
    "jsf-0.82.schema.json",
    "spdx.schema.json",
)
SPDX_COLLECTIONS = frozenset({"SpdxDocument", "Bom", "Bundle", "software_Sbom"})
SARIF_LEVELS = frozenset({"none", "note", "warning", "error"})
# GitHub code scanning displays a result only with a location and keeps at most
# 25,000 results and 20 tags per rule.
SARIF_MAX_RULE_TAGS = 20


@lru_cache(maxsize=1)
def _provenance() -> dict[str, str]:
    manifest = json.loads(
        files("nexus_symbiote.generators")
        .joinpath(_VENDOR + "SOURCES.json")
        .read_text(encoding="utf-8")
    )
    return {record["file"]: record["sha256"] for record in manifest["files"]}


def _schema(name: str) -> dict[str, Any]:
    """Load a vendored schema only if its bytes still match the reviewed digest."""
    raw = files("nexus_symbiote.generators").joinpath(_VENDOR + name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != _provenance().get(name):
        raise ValueError("vendored schema does not match its recorded provenance digest")
    schema = json.loads(raw.decode("utf-8"))
    if not isinstance(schema, dict):
        raise ValueError("vendored schema must be a JSON object")
    return schema


def _identity(value: Any) -> Any:
    """A hashable key that is equal exactly when jsonschema calls two instances equal."""
    if value is True or value is False:
        return (0, value)
    if isinstance(value, str):
        return (1, value)
    if isinstance(value, int | float):
        return (2, value)
    if isinstance(value, list):
        return (3, tuple(_identity(item) for item in value))
    if isinstance(value, dict):
        return (4, frozenset((key, _identity(item)) for key, item in value.items()))
    return (5, value)


def _unique_items(
    validator: Any, unique: Any, instance: Any, schema: dict[str, Any]
) -> Iterator[ValidationError]:
    if not unique or not validator.is_type(instance, "array"):
        return
    seen: set[Any] = set()
    for item in instance:
        key = _identity(item)
        if key in seen:
            yield ValidationError("array has non-unique elements")
            return
        seen.add(key)


# The jsonschema stubs leave extend() unannotated.
_LinearDraft4 = jsonschema_validators.extend(  # type: ignore[no-untyped-call]
    Draft4Validator, {"uniqueItems": _unique_items}
)
_LinearDraft7 = jsonschema_validators.extend(  # type: ignore[no-untyped-call]
    Draft7Validator, {"uniqueItems": _unique_items}
)
_LinearDraft202012 = jsonschema_validators.extend(  # type: ignore[no-untyped-call]
    Draft202012Validator, {"uniqueItems": _unique_items}
)

# RFC 3339 digits are ASCII; without re.ASCII, \d also matches other scripts' digits.
_RFC3339 = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))",
    re.ASCII,
)
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}", re.ASCII)
_IRI_EXCLUDED = re.compile(r'[\x00-\x20\x7f-\x9f<>"{}|\\^`]|%(?![0-9A-Fa-f]{2})')
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def _is_date_time(instance: object) -> bool:
    if not isinstance(instance, str):
        return True
    match = _RFC3339.fullmatch(instance)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(match[index]) for index in range(1, 7))
    if match[7] is not None and (int(match[7]) > 23 or int(match[8]) > 59):
        return False
    try:
        # RFC 3339 allows a leap second; datetime does not represent one.
        datetime(year, month, day, hour, minute, min(second, 59))
    except ValueError:
        return False
    return second <= 60


def _is_date(instance: object) -> bool:
    if not isinstance(instance, str):
        return True
    if _DATE.fullmatch(instance) is None:
        return False
    try:
        date.fromisoformat(instance)
    except ValueError:
        return False
    return True


def _is_iri_reference(instance: object) -> bool:
    if not isinstance(instance, str):
        return True
    return _IRI_EXCLUDED.search(instance) is None and instance.count("#") <= 1


def _is_uri_reference(instance: object) -> bool:
    if not isinstance(instance, str):
        return True
    return instance.isascii() and _is_iri_reference(instance)


def _is_uri(instance: object) -> bool:
    if not isinstance(instance, str):
        return True
    return _SCHEME.match(instance) is not None and _is_uri_reference(instance)


def _is_email(instance: object) -> bool:
    return not isinstance(instance, str) or "@" in instance


FORMAT_CHECKS: dict[str, Callable[[object], bool]] = {
    "date": _is_date,
    "date-time": _is_date_time,
    "idn-email": _is_email,
    "iri-reference": _is_iri_reference,
    "uri": _is_uri,
    "uri-reference": _is_uri_reference,
}


def format_checker() -> FormatChecker:
    """The same format assertions in every installation, whatever extras are present."""
    checker = FormatChecker(formats=())
    for name, check in FORMAT_CHECKS.items():
        checker.checks(name)(check)
    return checker


@lru_cache(maxsize=3)
def _validator(fmt: str) -> Any:
    if fmt == "sarif":
        return _LinearDraft4(
            _schema("sarif/sarif-schema-2.1.0.json"),
            registry=Registry(),
            format_checker=format_checker(),
        )
    if fmt == "spdx":
        return _LinearDraft202012(
            dispatched_spdx_schema(_schema("spdx/spdx-json-schema-3.0.1.json")),
            registry=Registry(),
            format_checker=format_checker(),
        )
    main = _schema("cyclonedx/bom-1.7.schema.json")
    base = main["$id"]
    directory = base.rsplit("/", 1)[0] + "/"
    schemas = [(base, Resource.from_contents(main, default_specification=DRAFT7))]
    for name in _CYCLONEDX_SUBSCHEMAS:
        resource = Resource.from_contents(
            _schema("cyclonedx/" + name), default_specification=DRAFT7
        )
        schemas.extend([(directory + name, resource), (name, resource)])
    return _LinearDraft7(
        main, registry=Registry().with_resources(schemas), format_checker=format_checker()
    )


def _schema_errors(document: Any, fmt: str) -> list[str]:
    try:
        return [
            f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:180]}"
            for e in _validator(fmt).iter_errors(document)
        ]
    except Unresolvable:
        return ["$: a schema reference cannot be resolved"]
    except RecursionError:
        return ["$: the document is nested too deeply to validate"]


def _nested(items: Any, key: str) -> Iterator[dict[str, Any]]:
    stack = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    while stack:
        item = stack.pop()
        yield item
        children = item.get(key)
        if isinstance(children, list):
            stack.extend(child for child in children if isinstance(child, dict))


def _cyclonedx_refs(document: dict[str, Any]) -> list[str]:
    """Every bom-ref that a dependency or vulnerability may name, at any nesting level."""
    subject = document.get("metadata", {}).get("component")
    holders = [
        *_nested(document.get("components", []), "components"),
        *_nested([subject] if isinstance(subject, dict) else [], "components"),
        *_nested(document.get("services", []), "services"),
    ]
    return [item["bom-ref"] for item in holders if isinstance(item.get("bom-ref"), str)]


_BOM_LINK_ELEMENT = re.compile(
    r"urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*#.+",
    re.DOTALL,
)


def _is_bom_link(target: object) -> bool:
    return isinstance(target, str) and _BOM_LINK_ELEMENT.fullmatch(target) is not None


def validate_cyclonedx(document: dict[str, Any]) -> list[str]:
    errors = _schema_errors(document, "cyclonedx")
    if errors:
        return errors
    refs = _cyclonedx_refs(document)
    vulnerabilities = document.get("vulnerabilities", [])
    vulnerability_refs = [v["bom-ref"] for v in vulnerabilities if "bom-ref" in v]
    if any(count > 1 for count in Counter([*refs, *vulnerability_refs]).values()):
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
    for vulnerability in vulnerabilities:
        for affected in vulnerability.get("affects", []):
            target = affected.get("ref")
            if target not in known and not _is_bom_link(target):
                errors.append(f"unresolved CycloneDX reference: {target}")
    for composition in document.get("compositions", []):
        for target in [*composition.get("assemblies", []), *composition.get("dependencies", [])]:
            if target not in known and not _is_bom_link(target):
                errors.append(f"unresolved CycloneDX reference: {target}")
    return errors


@lru_cache(maxsize=1)
def spdx_named_individuals() -> frozenset[str]:
    """Elements SPDX 3.0.1 predefines, compact and expanded, from the vendored files."""
    schema = _schema("spdx/spdx-json-schema-3.0.1.json")
    compact = {
        alternative["const"]
        for alternative in schema["$defs"]["Element_derived"]["anyOf"]
        if isinstance(alternative, dict) and isinstance(alternative.get("const"), str)
    }
    context = _schema("spdx/spdx-context-3.0.1.jsonld")["@context"]
    expanded = {context[name] for name in compact if isinstance(context.get(name), str)}
    return frozenset(compact | expanded)


def validate_spdx(document: dict[str, Any]) -> list[str]:
    return spdx_errors(document)


def spdx_errors(document: dict[str, Any], *, legacy_license: str | None = None) -> list[str]:
    """SPDX schema and graph errors.

    ``legacy_license`` admits one more license-relationship target; recovery of
    0.1.0 exports, which used an IRI SPDX does not define, passes it.
    """
    errors = _schema_errors(document, "spdx")
    if errors:
        return errors
    graph = document.get("@graph", [])
    ids = [n.get("spdxId", n.get("@id")) for n in graph]
    if None in ids or len(ids) != len(set(ids)):
        errors.append("missing or duplicate SPDX graph identifier")
    known = set(ids)
    individuals = spdx_named_individuals()
    licenses: dict[tuple[Any, str], list[dict[str, Any]]] = {}
    for node in graph:
        if node.get("type") in SPDX_COLLECTIONS and not set(node.get("rootElement", [])).issubset(
            node.get("element", [])
        ):
            errors.append("SPDX rootElement is not in its element collection")
        kind = node.get("relationshipType")
        if node.get("type") == "Relationship" and kind in {
            "hasDeclaredLicense",
            "hasConcludedLicense",
        }:
            licenses.setdefault((node.get("from"), kind), []).append(node)
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
                legacy = (
                    value == legacy_license
                    and field == "to"
                    and kind in {"hasDeclaredLicense", "hasConcludedLicense"}
                )
                if (
                    isinstance(value, str)
                    and value not in known
                    and value not in individuals
                    and not legacy
                ):
                    errors.append(f"unresolved SPDX {field}: {value}")
    for package in graph:
        if package.get("type") not in {"ai_AIPackage", "dataset_DatasetPackage"}:
            continue
        for kind in ("hasDeclaredLicense", "hasConcludedLicense"):
            relations = licenses.get((package.get("spdxId"), kind), [])
            if len(relations) != 1 or len(relations[0].get("to", [])) != 1:
                errors.append(f"SPDX {package.get('spdxId')} requires exactly one {kind} target")
    return errors


def _text(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("text"), str) and bool(value["text"])


def _relative_reference(uri: Any) -> bool:
    if not isinstance(uri, str) or not uri or uri.startswith("/") or "\\" in uri:
        return False
    if _SCHEME.match(uri) or _IRI_EXCLUDED.search(uri):
        return False
    return ".." not in uri.split("/")


def _sarif_rule_errors(path: str, rule: Any) -> list[str]:
    if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or not rule["id"]:
        return [f"{path}/id: a rule needs a nonempty id"]
    errors = []
    for field in ("shortDescription", "fullDescription", "help"):
        if not _text(rule.get(field)):
            errors.append(f"{path}/{field}: plain text is required")
    if rule.get("defaultConfiguration", {}).get("level") not in SARIF_LEVELS:
        errors.append(f"{path}/defaultConfiguration/level: invalid level")
    properties = rule.get("properties", {})
    tags = properties.get("tags", [])
    if (
        not isinstance(tags, list)
        or not all(isinstance(tag, str) and tag for tag in tags)
        or len(set(tags)) != len(tags)
        or len(tags) > SARIF_MAX_RULE_TAGS
        or "security" not in tags
    ):
        errors.append(f"{path}/properties/tags: unique tags including 'security' are required")
    try:
        score = float(properties.get("security-severity", ""))
    except (TypeError, ValueError):
        score = -1.0
    if not 0.0 <= score <= 10.0:
        errors.append(f"{path}/properties/security-severity: a score from 0.0 to 10.0 is required")
    return errors


def _sarif_result_errors(path: str, result: Any, rules: dict[str, int]) -> list[str]:
    if not isinstance(result, dict):
        return [f"{path}: a result must be an object"]
    errors = []
    rule_id = result.get("ruleId")
    if rule_id not in rules or result.get("ruleIndex") != rules[rule_id]:
        errors.append(f"{path}/ruleId: the rule is not defined at ruleIndex")
    if result.get("level") not in SARIF_LEVELS:
        errors.append(f"{path}/level: invalid level")
    if not _text(result.get("message")):
        errors.append(f"{path}/message/text: plain text is required")
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        errors.append(f"{path}/locations: GitHub code scanning requires a location")
    else:
        for index, location in enumerate(locations):
            artifact = (
                location.get("physicalLocation", {}).get("artifactLocation", {})
                if isinstance(location, dict)
                else {}
            )
            if not _relative_reference(artifact.get("uri")) or not isinstance(
                artifact.get("uriBaseId"), str
            ):
                errors.append(f"{path}/locations/{index}: a relative uri with uriBaseId is needed")
    fingerprints = result.get("partialFingerprints")
    if (
        not isinstance(fingerprints, dict)
        or not isinstance(fingerprints.get("primaryLocationLineHash"), str)
        or not all(isinstance(value, str) for value in fingerprints.values())
    ):
        errors.append(f"{path}/partialFingerprints: primaryLocationLineHash is required")
    return errors


def validate_sarif(document: Any) -> list[str]:
    """OASIS SARIF 2.1.0 schema validation plus GitHub code scanning profile checks."""
    schema_errors = _schema_errors(document, "sarif")
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        return ["version: SARIF 2.1.0 is required", *schema_errors]
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        return ["runs: at least one run is required", *schema_errors]
    errors: list[str] = list(schema_errors)
    for run_index, run in enumerate(runs):
        path = f"runs/{run_index}"
        driver = run.get("tool", {}).get("driver") if isinstance(run, dict) else None
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
            errors.append(f"{path}/tool/driver/name: required")
            continue
        rules = driver.get("rules", [])
        if not isinstance(rules, list):
            errors.append(f"{path}/tool/driver/rules: must be an array")
            continue
        for index, rule in enumerate(rules):
            errors.extend(_sarif_rule_errors(f"{path}/tool/driver/rules/{index}", rule))
        indexes = {
            rule["id"]: index
            for index, rule in enumerate(rules)
            if isinstance(rule, dict) and isinstance(rule.get("id"), str)
        }
        if len(indexes) != len(rules):
            errors.append(f"{path}/tool/driver/rules: rule ids must be unique")
        results = run.get("results")
        if not isinstance(results, list):
            errors.append(f"{path}/results: must be an array")
            continue
        for index, result in enumerate(results):
            errors.extend(_sarif_result_errors(f"{path}/results/{index}", result, indexes))
        invocations = run.get("invocations")
        if not isinstance(invocations, list) or not invocations:
            errors.append(f"{path}/invocations: one invocation is required")
            continue
        for index, invocation in enumerate(invocations):
            if not isinstance(invocation, dict) or not isinstance(
                invocation.get("executionSuccessful"), bool
            ):
                errors.append(f"{path}/invocations/{index}/executionSuccessful: required")
                continue
            for number, notification in enumerate(invocation.get("toolExecutionNotifications", [])):
                if (
                    not isinstance(notification, dict)
                    or notification.get("level") not in SARIF_LEVELS
                    or not _text(notification.get("message"))
                ):
                    errors.append(
                        f"{path}/invocations/{index}/toolExecutionNotifications/{number}: "
                        "a level and plain text are required"
                    )
    return errors


_VALIDATORS: dict[str, Callable[[Any], list[str]]] = {
    "cyclonedx": validate_cyclonedx,
    "spdx": validate_spdx,
    "sarif": validate_sarif,
}


def require_valid(document: dict[str, Any], fmt: str) -> None:
    errors = _VALIDATORS[fmt](document)
    if errors:
        raise ValueError(f"invalid {fmt} export: " + "; ".join(errors[:10]))
