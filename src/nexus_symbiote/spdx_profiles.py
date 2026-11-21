"""SPDX 3.0.1 AI & Dataset profile helpers, ISO/IEC 22989 mapping, and agent.yaml 1.1 declarations."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Final
from urllib.parse import unquote, urlsplit, urlunsplit

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    AutonomyLevel,
    ComponentType,
    RiskSeverity,
    TrustTier,
)
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    ClaimEvidence,
    DataSourceComponent,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.policy import parse_yaml_mapping
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import REDACTED, redact_text, redact_url
from nexus_symbiote.utils.terminal import neutralize

MAX_AGENT_YAML_BYTES: Final[int] = 256 * 1024
MAX_AGENT_YAML_NODES: Final[int] = 4096
_SUPPORTED_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1.0", "1.1"})
_RFC3339_RE: Final[re.Pattern[str]] = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})",
    re.ASCII,
)
_SAFE_LICENSE_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9.()+\- ]{1,128}", re.ASCII)
_LICENSE_REF_RE: Final[re.Pattern[str]] = re.compile(r"LicenseRef-[A-Za-z0-9.-]+", re.ASCII)
# Printable ASCII only: a control, bidirectional or invisible character must arrive
# percent-encoded, so an export never carries one that a terminal or viewer acts on.
_SAFE_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:https|s3|gs|hf|oci)://[\x21\x23-\x26\x28-\x3b\x3d\x3f-\x5b\x5d-\x7e]+",
    re.ASCII,
)
_PREVIOUS_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:https|s3|gs|hf|oci)://[^\s<>\"'\\]+", re.ASCII
)
_ALLOWED_URL_SCHEMES: Final[frozenset[str]] = frozenset({"https", "s3", "gs", "hf", "oci"})
_SPDX_DATASET_TYPES: Final[frozenset[str]] = frozenset(
    {
        "audio",
        "categorical",
        "graph",
        "image",
        "noAssertion",
        "numeric",
        "other",
        "sensor",
        "structured",
        "syntactic",
        "text",
        "timeseries",
        "timestamp",
        "video",
    }
)
_SPDX_AVAILABILITY_TYPES: Final[frozenset[str]] = frozenset(
    {"clickthrough", "directDownload", "query", "registration", "scrapingScript"}
)


@dataclass(frozen=True)
class AutomationLevelMapping:
    """Canonical mapping across SymBiote L0..L4, ShadowScan 0..5, ISO/IEC 22989, and SPDX AI."""

    iso_name: str
    symbiote_level: AutonomyLevel
    shadowscan_level: int
    spdx_autonomy_presence: str


ISO_22989_AUTOMATION_TABLE: Final[tuple[AutomationLevelMapping, ...]] = (
    AutomationLevelMapping("no_automation", AutonomyLevel.L0_CHATBOT, 0, "no"),
    AutomationLevelMapping("assistance", AutonomyLevel.L1_COPILOT, 1, "yes"),
    AutomationLevelMapping("partial_automation", AutonomyLevel.L1_COPILOT, 2, "yes"),
    AutomationLevelMapping("conditional_automation", AutonomyLevel.L2_AGENT, 3, "yes"),
    AutomationLevelMapping("high_automation", AutonomyLevel.L3_AUTONOMOUS, 4, "yes"),
    AutomationLevelMapping("full_automation", AutonomyLevel.L4_FULLY_AUTONOMOUS, 5, "yes"),
)

_BY_SYMBIOTE: Final[dict[AutonomyLevel, AutomationLevelMapping]] = {
    # L1_COPILOT maps deterministically to partial_automation when reverse-mapped from SymBiote's 5-level enum.
    AutonomyLevel.L0_CHATBOT: ISO_22989_AUTOMATION_TABLE[0],
    AutonomyLevel.L1_COPILOT: ISO_22989_AUTOMATION_TABLE[2],
    AutonomyLevel.L2_AGENT: ISO_22989_AUTOMATION_TABLE[3],
    AutonomyLevel.L3_AUTONOMOUS: ISO_22989_AUTOMATION_TABLE[4],
    AutonomyLevel.L4_FULLY_AUTONOMOUS: ISO_22989_AUTOMATION_TABLE[5],
}
_BY_SHADOWSCAN: Final[dict[int, AutomationLevelMapping]] = {
    row.shadowscan_level: row for row in ISO_22989_AUTOMATION_TABLE
}
_BY_ISO_NAME: Final[dict[str, AutomationLevelMapping]] = {
    row.iso_name: row for row in ISO_22989_AUTOMATION_TABLE
}


def resolve_automation_mapping(
    value: AutonomyLevel | int | str | None,
) -> AutomationLevelMapping | None:
    """Resolve an ISO/IEC 22989, SymBiote L0..L4 / L0-chatbot..L4-fully-autonomous, or ShadowScan 0..5 level."""
    if value is None:
        return None
    if isinstance(value, AutonomyLevel):
        return _BY_SYMBIOTE.get(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return _BY_SHADOWSCAN.get(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned in _BY_ISO_NAME:
            return _BY_ISO_NAME[cleaned]
        upper = cleaned.upper()
        for level in AutonomyLevel:
            if level.value.upper() == upper or level.value.split("-", 1)[0].upper() == upper:
                return _BY_SYMBIOTE[level]
        if cleaned.isdigit():
            return _BY_SHADOWSCAN.get(int(cleaned))
    return None


def spdx_autonomy_presence(comp: AnyComponent) -> str:
    """Return SPDX 3.0.1 PresenceType ('yes', 'no', or 'noAssertion') for an AI component.

    Observed autonomy_level always takes precedence over producer declarations.
    """
    if isinstance(comp, AgentComponent) and comp.autonomy_level is not None:
        mapped = resolve_automation_mapping(comp.autonomy_level)
        if mapped is not None:
            return mapped.spdx_autonomy_presence
    declared_iso = comp.properties.get("iso_22989_automation")
    if isinstance(declared_iso, str):
        mapped = resolve_automation_mapping(declared_iso)
        if mapped is not None:
            return mapped.spdx_autonomy_presence
    return "noAssertion"


def normalize_spdx_dataset_type(raw: str | None) -> str:
    """Map native or producer dataset_type strings to valid SPDX 3.0.1 DatasetType values."""
    if not raw:
        return "noAssertion"
    cleaned = raw.strip()
    if cleaned in _SPDX_DATASET_TYPES:
        return cleaned
    lowered = cleaned.lower()
    alias_map = {
        "pre-training": "text",
        "fine-tuning": "text",
        "evaluation": "structured",
        "alignment": "text",
        "tabular": "structured",
    }
    return alias_map.get(lowered, "other")


def _clean_text(value: Any, *, max_len: int = 512) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    cleaned = neutralize(redact_text(value.strip()))
    return cleaned[:max_len] if cleaned else None


def _clean_url(value: Any, *, legacy: bool = False) -> str | None:
    """Sanitize a declared download URI, preserving safe paths while stripping query/fragment/credentials."""
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES or not parts.hostname or not parts.netloc:
        return None
    if parts.username or parts.password or "@" in parts.netloc:
        return None
    # A token-shaped host is a secret even though the path check below passes.
    if redact_url(candidate) == "[redacted-url]":
        return None
    if parts.path and REDACTED in redact_text(unquote(parts.path)):
        return None
    rebuilt = urlunsplit((scheme, parts.netloc, parts.path, "", ""))
    pattern = _PREVIOUS_URL_RE if legacy else _SAFE_URL_RE
    return rebuilt if pattern.fullmatch(rebuilt) else None


def _projected_download_location(value: Any, *, legacy: bool) -> str | None:
    # Recovery recreates previously written projections in memory for comparison.
    if legacy:
        return value if isinstance(value, str) and value else None
    return _clean_url(value)


def _declared_url(value: Any, owner: str, notices: list[str]) -> str | None:
    cleaned = _clean_url(value)
    if cleaned is None and isinstance(value, str) and value.strip():
        notices.append(f"{owner}: download_location refused (scheme, credentials or secret)")
    return cleaned


def _clean_rfc3339(value: Any) -> str | None:
    if isinstance(value, datetime):
        aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return aware.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return f"{value.isoformat()}T00:00:00Z"
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if len(candidate) == 10 and re.fullmatch(r"\d{4}-\d{2}-\d{2}", candidate, re.ASCII):
        candidate = f"{candidate}T00:00:00Z"
    return candidate if _RFC3339_RE.fullmatch(candidate) else None


def clean_license_identifier(value: Any) -> str | None:
    """Validate and secret-scrub a license identifier or SPDX expression."""
    if not isinstance(value, str) or not value.strip():
        return None
    redacted = neutralize(redact_text(value.strip()))
    if REDACTED in redacted:
        return None
    return redacted if _SAFE_LICENSE_RE.fullmatch(redacted) else None


@lru_cache(maxsize=1)
def spdx_license_ids() -> tuple[frozenset[str], frozenset[str]]:
    """(licence ids, exception ids) from the vendored, digest-checked CycloneDX enum.

    The enum lists sorted licence ids, then sorted exception ids; the one place
    the order restarts is the boundary, and anything else fails closed.
    """
    from nexus_symbiote.generators.validation import _schema

    ids = _schema("cyclonedx/spdx.schema.json")["enum"]
    (cut,) = [i for i in range(1, len(ids)) if ids[i].lower() < ids[i - 1].lower()]
    licences, exceptions = frozenset(ids[:cut]), frozenset(ids[cut:])
    # A reordered enum would silently swap or mix the sets: pin both ends of both runs.
    if (ids[0], ids[cut - 1], ids[cut], ids[-1]) != (
        "0BSD",
        "ZPL-2.1",
        "389-exception",
        "x11vnc-openssl-exception",
    ) or not ("MIT" in licences and "LLVM-exception" in exceptions):
        raise ValueError("vendored SPDX enum no longer lists licence ids before exception ids")
    return licences, exceptions


def spdx_license_expression(value: Any) -> str | None:
    """Return the value only if it parses as an SPDX license expression.

    or := and (OR and)*; and := with (AND with)*;
    with := '(' or ')' | simple [WITH exception-id]; simple := license-id ['+'] | LicenseRef-.
    """
    cleaned = clean_license_identifier(value)
    if cleaned is None:
        return None
    licences, exceptions = spdx_license_ids()
    tokens: list[str] = re.findall(r"[()]|[^\s()]+", cleaned)
    pos = 0

    def take() -> str | None:
        nonlocal pos
        pos += 1
        return tokens[pos - 1] if pos <= len(tokens) else None

    def accept(op: str) -> bool:
        if tokens[pos : pos + 1] == [op]:
            take()
            return True
        return False

    def disjunction() -> bool:
        return conjunction() and (not accept("OR") or disjunction())

    def conjunction() -> bool:
        return with_expr() and (not accept("AND") or conjunction())

    def with_expr() -> bool:
        tok = take()
        if tok == "(":
            return disjunction() and take() == ")"
        if tok is None:
            return False
        base = tok.removesuffix("+")
        if base in licences:
            ok = base == tok or not base.endswith(("+", "-only", "-or-later"))
        else:
            ok = base == tok and _LICENSE_REF_RE.fullmatch(tok) is not None
        return ok and (not accept("WITH") or take() in exceptions)

    return cleaned if disjunction() and pos == len(tokens) else None


def _conflict_risk(field_name: str, component_name: str, locator: str) -> RiskAssessment:
    locator = neutralize(locator)
    return RiskAssessment(
        severity=RiskSeverity.MEDIUM,
        category="declaration_conflict",
        detail=(
            f"Producer declaration in {locator} conflicts with collected '{field_name}' "
            f"on component '{neutralize(component_name)}'."
        ),
        recommendation=(
            f"Align {locator} with the repository's collected artifacts; producer declarations "
            "do not override observed collector evidence."
        ),
    )


def _type_conflict(
    holder: AnyComponent | None,
    declared: str,
    locator: str,
    notices: list[str],
    *,
    declaration_refs: set[str],
) -> bool:
    """Whether a collected component of another type holds the declared name.

    The declaration is then a conflict on the holder and is not applied.
    """
    if holder is None or holder.bom_ref in declaration_refs:
        return False
    holder.risks.append(_conflict_risk("component_type", holder.name, locator))
    notices.append(f"{holder.bom_ref}: {declared} name conflict with {locator}")
    return True


def _repeat_declaration(
    seen: dict[str, dict[str, Any]],
    name: str,
    entry: dict[str, Any],
    holder: AnyComponent | None,
    locator: str,
    notices: list[str],
) -> bool:
    if name not in seen:
        seen[name] = entry
        return False
    if seen[name] != entry and holder is not None:
        holder.risks.append(_conflict_risk("duplicate_declaration", name, locator))
        notices.append(f"{holder.bom_ref}: conflicting declaration repeated in {locator}")
    return True


def _record_claim(comp: AnyComponent, key: str, locator: str) -> None:
    comp.claims[f"declaration.{key}"] = ClaimEvidence(
        assurance=AssuranceLevel.DECLARED,
        method="agent-yaml-1.1",
        scope=key,
        locator=locator,
    )


def _apply_version_declaration(
    comp: AnyComponent, ver: str, locator: str, notices: list[str]
) -> None:
    if comp.version and comp.version != ver:
        comp.risks.append(_conflict_risk("version", comp.name, locator))
        notices.append(f"{comp.bom_ref}: version conflict with {locator}")
        return
    if comp.assurance_level == AssuranceLevel.DECLARED:
        if not comp.version:
            comp.version = ver
    elif not comp.version:
        comp.properties["declared_version"] = ver
    _record_claim(comp, "version", locator)


def _apply_supplier_declaration(
    comp: AnyComponent, sup: str, locator: str, notices: list[str]
) -> None:
    if comp.supplier and comp.supplier != sup:
        comp.risks.append(_conflict_risk("supplier", comp.name, locator))
        notices.append(f"{comp.bom_ref}: supplier conflict with {locator}")
        return
    if comp.assurance_level == AssuranceLevel.DECLARED:
        if not comp.supplier:
            comp.supplier = sup
    elif not comp.supplier:
        comp.properties["declared_supplier"] = sup
    _record_claim(comp, "supplier", locator)


def apply_agent_yaml_declarations(
    aibom: AIBOM,
    project_root: Path,
    *,
    explicit_path: Path | None = None,
    relative_path: str | None = None,
) -> list[str]:
    """Read producer declarations from agent.yaml 1.1 as DECLARED claims without overriding observed values.

    Returns neutralized diagnostic notices for any declaration conflicts detected.
    """
    failures: list[str] = []
    notices: list[str] = []
    raw_bytes: bytes | None = None
    locator = "agent.yaml"

    if explicit_path is not None:
        from nexus_symbiote.core.hashing import open_regular_file

        with open_regular_file(explicit_path) as handle:
            raw_bytes = handle.read(MAX_AGENT_YAML_BYTES + 1)
        if len(raw_bytes) > MAX_AGENT_YAML_BYTES:
            raise ValueError("agent.yaml exceeds maximum size limit (256 KiB)")
        locator = explicit_path.name
    else:
        candidates = (relative_path,) if relative_path is not None else ("agent.yaml", "agent.yml")
        with ConfinedCollection(project_root, failures) as files:
            for candidate in candidates:
                data = files.read_bytes(candidate, missing_ok=(relative_path is None))
                if data is not None:
                    if len(data) > MAX_AGENT_YAML_BYTES:
                        raise ValueError(f"{candidate} exceeds maximum size limit (256 KiB)")
                    raw_bytes = data
                    locator = candidate
                    break
        if failures:
            raise ValueError(
                f"cannot safely read {neutralize(relative_path or locator)} inside project root"
            )
        if relative_path is not None and raw_bytes is None:
            raise ValueError(f"cannot safely read {neutralize(relative_path)} inside project root")

    if raw_bytes is None:
        return notices

    parsed = parse_yaml_mapping(raw_bytes.decode("utf-8"), max_nodes=MAX_AGENT_YAML_NODES)
    if "schema_version" in parsed:
        schema_ver = parsed["schema_version"]
        if not isinstance(schema_ver, str) or schema_ver not in _SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError("unsupported agent.yaml schema_version")

    doc_digest = hash_bytes(raw_bytes)
    owner = _clean_text(parsed.get("owner"), max_len=200)
    data_usage = _clean_text(parsed.get("data_usage"), max_len=512)
    raw_compliance = parsed.get("compliance")
    compliance_list = (
        [c for item in raw_compliance if (c := _clean_text(item, max_len=128)) is not None]
        if isinstance(raw_compliance, list)
        else []
    )
    raw_regions = parsed.get("allowed_regions")
    allowed_regions = (
        [r for item in raw_regions if (r := _clean_text(item, max_len=64)) is not None]
        if isinstance(raw_regions, list)
        else []
    )
    raw_licenses = parsed.get("licenses")
    default_license = (
        clean_license_identifier(raw_licenses[0])
        if isinstance(raw_licenses, list) and raw_licenses
        else clean_license_identifier(raw_licenses)
    )
    iso_level = resolve_automation_mapping(parsed.get("automation_level"))

    for comp in aibom.components:
        if isinstance(comp, AgentComponent):
            if owner:
                _apply_supplier_declaration(comp, owner, locator, notices)
            if data_usage:
                comp.properties["declared_data_usage"] = data_usage
                _record_claim(comp, "data_usage", locator)
            if compliance_list:
                comp.properties["declared_compliance"] = compliance_list
                _record_claim(comp, "compliance", locator)
            if allowed_regions:
                comp.properties["allowed_regions"] = allowed_regions
                _record_claim(comp, "allowed_regions", locator)
            if default_license and "declared_license" not in comp.properties:
                comp.properties["declared_license"] = default_license
                _record_claim(comp, "license", locator)
            if iso_level is not None:
                if (
                    comp.autonomy_level is not None
                    and comp.autonomy_level != iso_level.symbiote_level
                ):
                    comp.risks.append(_conflict_risk("autonomy_level", comp.name, locator))
                    notices.append(f"{comp.bom_ref}: autonomy_level conflict with {locator}")
                    comp.properties["declared_iso_22989_automation"] = iso_level.iso_name
                else:
                    comp.properties["iso_22989_automation"] = iso_level.iso_name
                _record_claim(comp, "automation_level", locator)
            for extra_key in ("release_time", "download_location", "version"):
                raw_val = parsed.get(extra_key)
                if extra_key == "release_time" and (ts := _clean_rfc3339(raw_val)):
                    comp.properties.setdefault("declared_release_time", ts)
                    _record_claim(comp, "release_time", locator)
                elif extra_key == "download_location" and (
                    dl := _declared_url(raw_val, comp.bom_ref, notices)
                ):
                    comp.properties.setdefault("declared_download_location", dl)
                    _record_claim(comp, "download_location", locator)
                elif extra_key == "version" and (ver := _clean_text(raw_val, max_len=128)):
                    _apply_version_declaration(comp, ver, locator, notices)

    # Keyed by type too: a dataset declared under a collected model's name must not take
    # that model's slot, or a later conflicting model declaration skips the conflict check.
    by_key: dict[tuple[ComponentType, str], AnyComponent] = {
        (c.component_type, c.name): c for c in aibom.components
    }
    declaration_refs: set[str] = set()

    raw_datasets = parsed.get("datasets")
    dataset_refs_by_name: dict[str, str] = {}
    dataset_declarations: dict[str, dict[str, Any]] = {}
    if isinstance(raw_datasets, list):
        for entry in raw_datasets[:200]:
            if not isinstance(entry, dict):
                continue
            ds_name = _clean_text(entry.get("name"), max_len=200)
            if not ds_name:
                continue
            existing = by_key.get((ComponentType.DATA_SOURCE, ds_name))
            if existing is None and _type_conflict(
                by_key.get((ComponentType.MODEL, ds_name)),
                "dataset",
                locator,
                notices,
                declaration_refs=declaration_refs,
            ):
                continue
            if _repeat_declaration(
                dataset_declarations, ds_name, entry, existing, locator, notices
            ):
                continue
            ds_ver = _clean_text(entry.get("version"), max_len=128)
            ds_sup = _clean_text(entry.get("supplier"), max_len=200) or owner
            ds_lic = clean_license_identifier(entry.get("license")) or default_license
            raw_uri = entry.get("download_location") or entry.get("source_uri")
            ds_uri = _declared_url(raw_uri, f"dataset {ds_name}", notices)
            ds_rel = _clean_rfc3339(entry.get("release_time") or entry.get("collection_date"))
            ds_type = _clean_text(entry.get("dataset_type"), max_len=64)
            ds_avail = _clean_text(entry.get("availability"), max_len=64)
            ds_pii = entry.get("sensitive_personal_information")

            if isinstance(existing, DataSourceComponent):
                ds_comp = existing
                if ds_ver:
                    _apply_version_declaration(ds_comp, ds_ver, locator, notices)
                if ds_sup:
                    _apply_supplier_declaration(ds_comp, ds_sup, locator, notices)
                if ds_lic and ds_comp.license and ds_comp.license != ds_lic:
                    ds_comp.risks.append(_conflict_risk("license", ds_name, locator))
                    notices.append(f"{ds_comp.bom_ref}: license conflict with {locator}")
                    ds_lic = None
                comparison_uri = ds_uri or _clean_url(raw_uri, legacy=True)
                if comparison_uri and ds_comp.source_uri and ds_comp.source_uri != comparison_uri:
                    ds_comp.risks.append(_conflict_risk("source_uri", ds_name, locator))
                    notices.append(f"{ds_comp.bom_ref}: source_uri conflict with {locator}")
                    ds_uri = None
                if ds_lic and ds_comp.assurance_level == AssuranceLevel.DECLARED:
                    ds_comp.license = ds_comp.license or ds_lic
            else:
                digest_id = hashlib.sha256(ds_name.encode("utf-8")).hexdigest()[:16]
                ds_comp = DataSourceComponent(
                    bom_ref=f"dataset:declared:{digest_id}",
                    name=ds_name,
                    version=ds_ver,
                    supplier=ds_sup,
                    source_path=locator,
                    dataset_type=ds_type,
                    source_uri=ds_uri,
                    collection_date=ds_rel,
                    license=ds_lic,
                    assurance_level=AssuranceLevel.DECLARED,
                    trust_tier=TrustTier.UNKNOWN,
                )
                aibom.components.append(ds_comp)
                by_key[(ComponentType.DATA_SOURCE, ds_name)] = ds_comp
                declaration_refs.add(ds_comp.bom_ref)
                if ds_ver:
                    _record_claim(ds_comp, "version", locator)
                if ds_sup:
                    _record_claim(ds_comp, "supplier", locator)

            if ds_rel:
                ds_comp.properties["declared_release_time"] = ds_rel
                _record_claim(ds_comp, "release_time", locator)
            if ds_uri:
                ds_comp.properties["declared_download_location"] = ds_uri
                _record_claim(ds_comp, "download_location", locator)
            if ds_lic:
                ds_comp.properties["declared_license"] = ds_lic
                _record_claim(ds_comp, "license", locator)
            if ds_avail in _SPDX_AVAILABILITY_TYPES:
                ds_comp.properties["declared_availability"] = ds_avail
                _record_claim(ds_comp, "availability", locator)
            if isinstance(ds_pii, str) and ds_pii in {"yes", "no", "noAssertion"}:
                ds_comp.properties["declared_sensitive_pii"] = ds_pii
                _record_claim(ds_comp, "sensitive_personal_information", locator)
            ds_comp.properties["declaration_source_sha256"] = doc_digest
            _record_claim(ds_comp, "dataset", locator)
            dataset_refs_by_name[ds_name] = ds_comp.bom_ref

    raw_models = parsed.get("models")
    model_declarations: dict[str, dict[str, Any]] = {}
    edge_keys: set[tuple[str, str, str]] = {
        (e.source_ref, e.target_ref, e.relationship) for e in aibom.dependencies
    }
    if isinstance(raw_models, list):
        for entry in raw_models[:200]:
            if not isinstance(entry, dict):
                continue
            m_name = _clean_text(entry.get("name"), max_len=200)
            if not m_name:
                continue
            existing = by_key.get((ComponentType.MODEL, m_name))
            if existing is None and _type_conflict(
                by_key.get((ComponentType.DATA_SOURCE, m_name)),
                "model",
                locator,
                notices,
                declaration_refs=declaration_refs,
            ):
                continue
            if _repeat_declaration(model_declarations, m_name, entry, existing, locator, notices):
                continue
            m_ver = _clean_text(entry.get("version"), max_len=128)
            m_sup = _clean_text(entry.get("supplier"), max_len=200) or owner
            m_lic = clean_license_identifier(entry.get("license")) or default_license
            m_dl = _declared_url(entry.get("download_location"), f"model {m_name}", notices)
            m_rel = _clean_rfc3339(entry.get("release_time"))
            m_domain = _clean_text(entry.get("domain"), max_len=128)
            training = entry.get("training")

            if isinstance(existing, ModelComponent):
                m_comp = existing
                if m_ver:
                    _apply_version_declaration(m_comp, m_ver, locator, notices)
                if m_sup:
                    _apply_supplier_declaration(m_comp, m_sup, locator, notices)
            else:
                digest_id = hashlib.sha256(m_name.encode("utf-8")).hexdigest()[:16]
                m_comp = ModelComponent(
                    bom_ref=f"model:declared:{digest_id}",
                    name=m_name,
                    version=m_ver,
                    supplier=m_sup,
                    source_path=locator,
                    model_type=_clean_text(entry.get("model_type"), max_len=64) or "foundation",
                    assurance_level=AssuranceLevel.DECLARED,
                    trust_tier=TrustTier.UNKNOWN,
                )
                aibom.components.append(m_comp)
                by_key[(ComponentType.MODEL, m_name)] = m_comp
                declaration_refs.add(m_comp.bom_ref)
                if m_ver:
                    _record_claim(m_comp, "version", locator)
                if m_sup:
                    _record_claim(m_comp, "supplier", locator)

            if m_lic:
                prev_lic = m_comp.properties.get("declared_license")
                if isinstance(prev_lic, str) and prev_lic != m_lic:
                    m_comp.risks.append(_conflict_risk("license", m_name, locator))
                    notices.append(f"{m_comp.bom_ref}: license conflict with {locator}")
                else:
                    m_comp.properties["declared_license"] = m_lic
                    _record_claim(m_comp, "license", locator)
            if m_rel:
                m_comp.properties["declared_release_time"] = m_rel
                _record_claim(m_comp, "release_time", locator)
            if m_dl:
                m_comp.properties["declared_download_location"] = m_dl
                _record_claim(m_comp, "download_location", locator)
            if m_domain:
                m_comp.properties["declared_domain"] = m_domain
                _record_claim(m_comp, "domain", locator)
            if compliance_list:
                m_comp.properties.setdefault("declared_compliance", compliance_list)
                _record_claim(m_comp, "compliance", locator)
            if isinstance(training, dict):
                summary = _clean_text(training.get("description") or training.get("method"))
                if summary:
                    m_comp.properties["declared_training_info"] = summary
                    _record_claim(m_comp, "training", locator)
                ds_list = training.get("datasets")
                if isinstance(ds_list, list):
                    for ds_ref_name in ds_list[:50]:
                        clean_ds = _clean_text(ds_ref_name, max_len=200)
                        if clean_ds and clean_ds in dataset_refs_by_name:
                            key = (m_comp.bom_ref, dataset_refs_by_name[clean_ds], "trained-on")
                            if key not in edge_keys:
                                edge_keys.add(key)
                                aibom.dependencies.append(
                                    DependencyEdge(
                                        source_ref=m_comp.bom_ref,
                                        target_ref=key[1],
                                        relationship="trained-on",
                                        assurance_level="declared",
                                    )
                                )
            m_comp.properties["declaration_source_sha256"] = doc_digest
            _record_claim(m_comp, "model", locator)

    return notices
