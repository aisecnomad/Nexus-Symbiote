"""AIBOM diff engine — compares two AIBOMs to detect supply chain changes.

Critical for detecting rug-pull attacks, tool definition mutations,
unauthorized component additions and removals, trust tier downgrades and
coverage regressions.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.collection import CITED_EVIDENCE_CLAIM
from nexus_symbiote.core.enums import ComponentType, SerializationSafety, TrustTier
from nexus_symbiote.core.hashing import TOOL_DEFINITION_HASH_VERSION, canonical_json
from nexus_symbiote.core.models import (
    UNBOUND_VALUES_DETAIL,
    AnyComponent,
    CompletenessClaim,
    CredentialComponent,
    MCPServerComponent,
    check_spec_version,
)
from nexus_symbiote.utils.crypto import (
    VERIFIED_SIGNING_STATUSES,
    SigningStatus,
    component_evidence_refs,
)
from nexus_symbiote.utils.terminal import neutralize

SEVERITIES = ("info", "low", "medium", "high", "critical")


def _values_unbound(component: AnyComponent) -> bool:
    """True when this snapshot left values out of the keyed binding.

    The collector records that as a low completeness finding naming
    ``UNBOUND_VALUES_DETAIL``: MCP launch values, IDE settings values, RAG and A2A
    values, or the content of a prompt file whose digest is withheld. Prompt templates
    share one such finding, so a withheld digest without a binding counts too. Nothing
    else in the record changes when one of those values does, so diff cannot see the
    change and must not report the snapshots as equal.
    """
    if component.properties.get("static_value_binding"):
        return False
    if component.properties.get("content_hash_withheld"):
        return True
    return any(
        risk.category == "completeness" and UNBOUND_VALUES_DETAIL in risk.detail
        for risk in getattr(component, "risks", ())
    )


TRUST_TIER_ORDER = {
    TrustTier.INTERNAL_VERIFIED: 0,
    TrustTier.INTERNAL_UNVERIFIED: 1,
    TrustTier.THIRD_PARTY_SIGNED: 2,
    TrustTier.THIRD_PARTY_UNSIGNED: 3,
    TrustTier.UNTRUSTED_PUBLIC: 4,
    TrustTier.UNKNOWN: 5,
}


_SECURITY_FIELDS = {
    "component_type",
    "capabilities",
    "authorizations",
    "trust_remote_code",
    "assurance_level",
    "claims",
    "endpoint",
    "endpoint_url",
    "agent_card_url",
    "command",
    "args",
    "env",
    "transport",
    "autonomy_level",
    "workload_identity",
    "tenant",
    "deployment_id",
    "deployment_status",
    "deployment_profile",
    "signing_identity",
    "signing_key_reference",
    "publisher_verified",
    "publisher_identity",
    "attestation_status",
    "execution_isolation",
    "human_in_the_loop",
    "permission_mode",
    "authentication_required",
    "package_url",
    "provider",
    "registry_uri",
    "registry_source",
    "registry_type",
    "source_uri",
    "source_uris",
    "resolved_revision",
    "requested_alias",
    "tokenizer_hash",
    "chat_template_hash",
    "tensor_inventory_hash",
    "safetensors_header_hash",
    "index_snapshot_hash",
    "schema_hash",
    "config_hash",
    "write_authority",
    "tenant_isolated",
    "encryption_at_rest",
    "modification_authority",
    "authentication_methods",
    "version_pinned",
    "definition_hash_version",
    "supplier",
}
_SET_LISTS = {
    "capabilities",
    "oauth_scopes",
    "egress_domains",
    "filesystem_paths",
    "authorizations",
    "conditions",
    "evidence_refs",
    "source_uris",
    "supported_protocols",
    "authentication_methods",
    "skills_declared",
    "config_files",
    "authors",
    "surfaces_scanned",
    "surfaces_excluded",
    "scan_failures",
    "collectors_requested",
    "collectors_completed",
    "unobserved_surfaces",
    "exclusions",
    "source_unmapped_indexes",
}

# A removed record of these types can take away a tool, an instruction, a model or a
# control, or move configuration out of the collectors' reach.
_REMOVAL_HIGH_TYPES = frozenset(
    {
        ComponentType.MCP_SERVER,
        ComponentType.MCP_CLIENT,
        ComponentType.TOOL,
        ComponentType.MODEL,
        ComponentType.PROMPT_TEMPLATE,
        ComponentType.SKILL_PACKAGE,
        ComponentType.GUARDRAIL_POLICY,
        ComponentType.IDE_AGENT,
        ComponentType.VERIFIED_EXTENSION,
        ComponentType.A2A_CLIENT,
        ComponentType.A2A_SERVER,
    }
)
_EDGE_ADDED_HIGH = frozenset({"delegates-to", "acts-as-identity", "invokes"})
_EDGE_REMOVED_HIGH = frozenset({"uses-guardrail", "approved-under"})
# The dependency-array position is provenance, not content: reordering the source
# document must not look like a changed relationship.
_IMPORTED_EDGE_CONDITION = re.compile(
    r"Source-reported CycloneDX dependency; dependencies index [0-9]+; not independently verified"
)
_IMPORTED_EDGE_CONDITION_STABLE = "Source-reported CycloneDX dependency; not independently verified"

_FINDING_DIGEST = "shadowscan:finding-sha256"
_FINDING_INDEX = "shadowscan:finding-index"
_REPORT_DIGEST = "shadowscan:report-sha256"
_PROJECTION = "shadowscan:projection-profile"
_DECLARED_AUTONOMY = "declared_autonomy_level"

# A digest as collectors record one, anywhere inside a value: an algorithm-prefixed hex
# digest, or a Subresource Integrity value such as an npm lockfile's.
_DIGEST_VALUE = re.compile(
    r"sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128}"
    r"|sha(?:256|384|512)-[A-Za-z0-9+/]{43,86}={0,2}",
    re.IGNORECASE,
)
_DIGEST_NAME = re.compile(r"_(?:hash|hashes|digest|integrity|sha256)\Z", re.IGNORECASE)
_NAMED_PROPERTIES = 20
"""How many changed properties of one record a change names; the rest are counted."""
# Signing evidence from strongest to weakest. Any other status, such as
# signature-not-found, verification-failed or one this release does not know, is weakest.
_SIGNING_RANK = {
    **dict.fromkeys((*sorted(VERIFIED_SIGNING_STATUSES), "pgp-signed"), 0),
    SigningStatus.PARTIALLY_VERIFIED.value: 1,
    SigningStatus.SIGNATURE_PRESENT_UNVERIFIED.value: 2,
}
_WEAKEST_SIGNING = max(_SIGNING_RANK.values()) + 1
_STATUS_RANK = {"complete": 0, "partial": 1, "failed": 2, "unknown": 2}
_ASSURANCE_RANK = {"verified": 0, "observed": 1, "declared": 2}
_SOURCE_STATUS_RANK = {"complete": 0, "incomplete": 1, "unknown": 2}
_INFO_METADATA = frozenset({"tool_version"})
_LISTED = 5
_SHOWN = 200


def _severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _max_severity(severities: Iterable[str]) -> str:
    return max(severities, key=_severity_rank, default="info")


def _json_text(value: Any) -> str:
    """Compare as JSON values: `true` is not `1`, and key order never matters."""
    try:
        return canonical_json(value)
    except (TypeError, ValueError, OverflowError):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _readable_spec_version(version: object) -> bool:
    """The native format rule of ``core.models``, so the differ and the reader agree."""
    try:
        check_spec_version(version)
    except ValueError:
        return False
    return True


def _clip(value: object) -> str:
    text = str(value)
    return text if len(text) <= _SHOWN else text[: _SHOWN - 1] + "…"


def _listing(values: Iterable[str]) -> str:
    items = sorted(values)
    shown = "; ".join(_clip(item) for item in items[:_LISTED])
    return shown + (f"; and {len(items) - _LISTED} more" if len(items) > _LISTED else "")


def _incompleteness(claim: CompletenessClaim) -> list[str]:
    """What keeps a claim short of complete coverage of its own scope, by name."""
    found = []
    if claim.scan_failures:
        found.append(f"Scan failures: {_listing(claim.scan_failures)}.")
    if claim.surfaces_excluded:
        found.append(f"Coverage gaps: {_listing(claim.surfaces_excluded)}.")
    collectors = {
        name: state for name, state in claim.scanner_status.items() if state != "complete"
    }
    for name in claim.collectors_requested:
        if name not in claim.collectors_completed:
            collectors.setdefault(name, "not completed")
    if collectors:
        listed = _listing(f"{name} ({state})" for name, state in collectors.items())
        found.append(f"Collectors not complete: {listed}.")
    elif not claim.collectors_requested and not claim.scanner_status:
        found.append("No collector is recorded.")
    if claim.source_report_status not in (None, "complete"):
        found.append(f"ShadowScan source status: {claim.source_report_status}.")
    if claim.source_unmapped_count:
        found.append(f"ShadowScan entries left unmapped: {claim.source_unmapped_count}.")
    return found


def _semantic_value(value: Any, path: tuple[str, ...]) -> Any:
    """Ignore set ordering and fresh claim observation times, never arbitrary JSON arrays."""
    if (
        isinstance(value, str)
        and path[:2] == ("claims", CITED_EVIDENCE_CLAIM)
        and path[2:] in {("locator",), ("evidence_refs", "[]")}
    ):
        # A cited line moves with every edit above it; the cited file is what is compared.
        return re.sub(r":[0-9]+\Z", "", value)
    if isinstance(value, dict):
        return {
            key: _semantic_value(item, (*path, key))
            for key, item in sorted(value.items())
            if not (len(path) == 2 and path[0] == "claims" and key == "observed_at")
        }
    if isinstance(value, list):
        if len(path) == 3 and path[0] == "claims" and path[2] == "evidence_refs":
            # The operator policy file's digest says which run verified, not what.
            value = component_evidence_refs(value)
        items = [_semantic_value(item, (*path, "[]")) for item in value]
        opaque = any(
            part in {"properties", "input_schema", "annotations", "variable_schema"}
            for part in path
        )
        key = path[-1]
        if not opaque and key == "risks":
            # Risk scoring counts each occurrence, so preserve multiplicity.
            return sorted(_json_text(item) for item in items)
        if not opaque and (key in _SET_LISTS or key.endswith("_refs")):
            return sorted({_json_text(item) for item in items})
        return items
    return value


def _same(old: Any, new: Any, path: tuple[str, ...]) -> bool:
    return _json_text(_semantic_value(old, path)) == _json_text(_semantic_value(new, path))


def _signing_rank(status: object) -> int:
    if not isinstance(status, str):
        return _WEAKEST_SIGNING
    return _SIGNING_RANK.get(status, _WEAKEST_SIGNING)


def _property_texts(properties: dict[str, Any]) -> dict[str, str]:
    return {
        key: _json_text(_semantic_value(value, ("properties", key)))
        for key, value in properties.items()
    }


def _property_changes(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, str]]:
    """Name each changed property; changing or removing one that records a digest is high.

    Collectors keep companion weight files, custom code, settings files and lockfile
    integrity as digests in properties, so a swapped file shows only there.
    """
    before, after = _property_texts(old), _property_texts(new)
    changes: list[tuple[str, str, str]] = []
    for key in before.keys() | after.keys():
        old_text, new_text = before.get(key), after.get(key)
        if old_text == new_text:
            continue
        if old_text is None:
            changes.append(("medium", key, "added"))
            continue
        texts = (old_text,) if new_text is None else (old_text, new_text)
        digest = _DIGEST_NAME.search(key) is not None or any(
            _DIGEST_VALUE.search(text) is not None for text in texts
        )
        verb = "removed" if new_text is None else "changed"
        changes.append(("high" if digest else "medium", key, verb))
    changes.sort(key=lambda change: (-_severity_rank(change[0]), change[1]))
    named = [
        {"detail": f"properties.{_clip(key)} {verb}.", "severity": severity}
        for severity, key, verb in changes[:_NAMED_PROPERTIES]
    ]
    rest = [severity for severity, _, _ in changes[_NAMED_PROPERTIES:]]
    if rest:
        named.append(
            {"detail": f"properties: {len(rest)} more changed.", "severity": _max_severity(rest)}
        )
    return named


def _discovery_finding_drift(old_fields: dict[str, Any], new_fields: dict[str, Any]) -> bool | None:
    """Compare an imported finding by its content digest instead of its report's exact bytes.

    A rerun that only records new run times changes every component's exact report
    digest, and a finding inserted before others shifts their positional index. Returns
    None, leaving the fields untouched, when either side lacks a comparable finding
    digest, so legacy inventories keep the stricter comparison.
    """
    old_props, new_props = old_fields.get("properties"), new_fields.get("properties")
    if (
        not isinstance(old_props, dict)
        or not isinstance(new_props, dict)
        or not isinstance(old_props.get(_FINDING_DIGEST), str)
        or not isinstance(new_props.get(_FINDING_DIGEST), str)
        or old_props.get(_PROJECTION) != new_props.get(_PROJECTION)
    ):
        return None
    changed = bool(old_props[_FINDING_DIGEST] != new_props[_FINDING_DIGEST])
    for props in (old_props, new_props):
        props.pop(_FINDING_DIGEST)
        props.pop(_REPORT_DIGEST, None)
        props.pop(_FINDING_INDEX, None)
    return changed


def _edge_record(edge: DependencyEdge) -> dict[str, Any]:
    record = edge.model_dump(mode="json")
    if isinstance(record.get("conditions"), str) and _IMPORTED_EDGE_CONDITION.fullmatch(
        record["conditions"]
    ):
        record["conditions"] = _IMPORTED_EDGE_CONDITION_STABLE
    return record


def _edge_key(edge: DependencyEdge) -> str:
    return _json_text(_edge_record(edge))


def _carried_integrity(component: AnyComponent) -> bool:
    """Whether the record held evidence that would make a later change to it alert."""
    if component.hashes:
        return True
    if any(
        getattr(component, name, None)
        for name in ("content_hash", "definition_hash", "package_url", "schema_hash")
    ):
        return True
    if getattr(component, "version_pinned", None) is True:
        return True
    return any(key in component.properties for key in ("lockfile_integrity", "static_config_hash"))


def _records_absolute_paths(bom: AIBOM) -> bool:
    def absolute(value: str | None) -> bool:
        if not value:
            return False
        return value.startswith(("/", "\\\\")) or re.match(r"[A-Za-z]:[\\/]", value) is not None

    claim = bom.metadata.completeness
    return any(absolute(c.source_path) for c in bom.components) or (
        claim is not None and any(absolute(surface) for surface in claim.surfaces_scanned)
    )


@dataclass
class ComponentChange:
    bom_ref: str
    name: str
    change_type: str  # added, removed, modified
    component_type: str
    severity: str = "info"
    details: list[str] = field(default_factory=list)


@dataclass
class DependencyChange:
    source_ref: str
    target_ref: str
    relationship: str
    change_type: str  # added, removed
    assurance_level: str | None = None
    conditions: str | None = None
    severity: str = "medium"


@dataclass
class DiffReport:
    has_changes: bool = False
    components_added: list[ComponentChange] = field(default_factory=list)
    components_removed: list[ComponentChange] = field(default_factory=list)
    components_modified: list[ComponentChange] = field(default_factory=list)
    dependencies_added: list[DependencyChange] = field(default_factory=list)
    dependencies_removed: list[DependencyChange] = field(default_factory=list)
    security_alerts: list[dict[str, str]] = field(default_factory=list)
    metadata_changes: list[dict[str, str]] = field(default_factory=list)
    # Context about the comparison itself, such as gaps both snapshots share. Not changes.
    notes: list[dict[str, str]] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return (
            len(self.components_added)
            + len(self.components_removed)
            + len(self.components_modified)
            + len(self.dependencies_added)
            + len(self.dependencies_removed)
            + len(self.metadata_changes)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_changes": self.has_changes,
            "total_changes": self.total_changes,
            "components_added": [self._change_dict(c) for c in self.components_added],
            "components_removed": [self._change_dict(c) for c in self.components_removed],
            "components_modified": [self._change_dict(c) for c in self.components_modified],
            "dependencies_added": [self._edge_dict(d) for d in self.dependencies_added],
            "dependencies_removed": [self._edge_dict(d) for d in self.dependencies_removed],
            "security_alerts": self.security_alerts,
            "metadata_changes": self.metadata_changes,
            "notes": self.notes,
        }

    @staticmethod
    def _edge_dict(d: DependencyChange) -> dict[str, Any]:
        return {
            "source": d.source_ref,
            "target": d.target_ref,
            "relationship": d.relationship,
            "assurance_level": d.assurance_level,
            "conditions": d.conditions,
            "severity": d.severity,
        }

    def _change_dict(self, c: ComponentChange) -> dict[str, Any]:
        d: dict[str, Any] = {
            "bom_ref": c.bom_ref,
            "name": c.name,
            "type": c.component_type,
            "change": c.change_type,
            "severity": c.severity,
        }
        if c.details:
            d["details"] = c.details
        return d


class AIBOMDiffer:
    """Compares two AIBOMs and reports supply chain changes."""

    def diff(self, old: AIBOM, new: AIBOM) -> DiffReport:
        report = DiffReport()

        old_map = {c.bom_ref: c for c in old.components}
        new_map = {c.bom_ref: c for c in new.components}

        old_refs = set(old_map.keys())
        new_refs = set(new_map.keys())

        from nexus_symbiote.validators.risk import effective_component_risks

        for ref in sorted(new_refs - old_refs):
            comp = new_map[ref]
            added_severity = _max_severity(
                ("medium", *(r.severity.value for r in effective_component_risks(comp)))
            )
            change = ComponentChange(
                bom_ref=ref,
                name=comp.name,
                change_type="added",
                component_type=comp.component_type.value,
                severity=added_severity,
                details=[f"New {comp.component_type.value} component added."],
            )
            report.components_added.append(change)

        for ref in sorted(old_refs - new_refs):
            comp = old_map[ref]
            high = comp.component_type in _REMOVAL_HIGH_TYPES or _carried_integrity(comp)
            change = ComponentChange(
                bom_ref=ref,
                name=comp.name,
                change_type="removed",
                component_type=comp.component_type.value,
                severity="high" if high else "medium",
                details=[f"{comp.component_type.value} component removed."],
            )
            report.components_removed.append(change)

        for ref in sorted(old_refs & new_refs):
            modifications = self._compare_components(old_map[ref], new_map[ref])
            if modifications:
                severity = _max_severity(m.get("severity", "info") for m in modifications)
                change = ComponentChange(
                    bom_ref=ref,
                    name=new_map[ref].name,
                    change_type="modified",
                    component_type=new_map[ref].component_type.value,
                    severity=severity,
                    details=[m["detail"] for m in modifications],
                )
                report.components_modified.append(change)

        self._diff_metadata(old, new, report)
        self._diff_inputs(old, new, report)
        self._diff_dependencies(old, new, report, old_refs & new_refs)
        self._generate_security_alerts(report)
        self._settings_drift_alerts(old_map, new_map, old_refs & new_refs, report)

        report.has_changes = report.total_changes > 0
        return report

    def _compare_components(self, old: Any, new: Any) -> list[dict[str, str]]:
        modifications: list[dict[str, str]] = []

        if isinstance(old, MCPServerComponent) and isinstance(new, MCPServerComponent):
            for label, before, after in (
                ("endpoint", old.endpoint_url, new.endpoint_url),
                ("transport", old.transport, new.transport),
                ("launch command", old.command, new.command),
                ("launcher package", old.launcher_package, new.launcher_package),
            ):
                if before != after:
                    # External or legacy inventories may contain credentials in these fields.
                    modifications.append(
                        {
                            "detail": f"MCP server {label} changed. Review before execution.",
                            "severity": "critical",
                        }
                    )
            # Observed digests: the served tool set, and the instructions, prompts,
            # resource templates and other descriptor members a live observation binds.
            for label, before, after in (
                ("served tool set", old.schema_hash, new.schema_hash),
                (
                    "served instructions, prompts or resource templates",
                    old.properties.get("observed_declaration_hash"),
                    new.properties.get("observed_declaration_hash"),
                ),
            ):
                if before and (not after or before != after):
                    modifications.append(
                        {
                            "detail": f"MCP server {label} changed. Review before execution.",
                            "severity": "critical",
                        }
                    )
            binding = (
                "static_config_hash",
                "static_config_hash_profile",
                "static_value_binding",
                "static_value_binding_key_id",
                "static_value_binding_profile",
            )
            old_binding = tuple(old.properties.get(key) for key in binding)
            new_binding = tuple(new.properties.get(key) for key in binding)
            if old_binding != new_binding and (old_binding[0] or new_binding[0]):
                # These bindings are the only compared fields covering launcher
                # arguments, environment and endpoint paths, which exports redact.
                modifications.append(
                    {
                        "detail": (
                            "MCP server static source binding changed: launcher, arguments, "
                            "environment, endpoint or declared tools differ, or the binding key "
                            "changed. Review before execution."
                        ),
                        "severity": "critical",
                    }
                )
                if old_binding[0] == new_binding[0] and (
                    _values_unbound(old) or _values_unbound(new)
                ):
                    modifications.append(
                        {
                            "detail": (
                                "MCP server launch values are unbound in one snapshot; argument, "
                                "environment and endpoint-path drift is undetectable. Set "
                                "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY during both collections."
                            ),
                            "severity": "medium",
                        }
                    )
            elif _values_unbound(old) or _values_unbound(new):
                # Redacted arguments, environment values and endpoint paths are not in the
                # structural hash. Without the keyed binding a widened filesystem root
                # compares equal, so the comparison itself is the alert.
                modifications.append(
                    {
                        "detail": (
                            "MCP server launch values are unbound in one snapshot; argument, "
                            "environment and endpoint-path drift is undetectable. Set "
                            "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY during both collections."
                        ),
                        "severity": "medium",
                    }
                )

        elif _values_unbound(old) or _values_unbound(new):
            # The values themselves are left out of the record, so the alert names
            # none of them.
            modifications.append(
                {
                    "detail": (
                        "Values are unbound in one snapshot without the binding key; a change "
                        "to them is undetectable and no value is recorded. Set "
                        "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY during both collections."
                    ),
                    "severity": "medium",
                }
            )

        if old.trust_tier != new.trust_tier:
            old_rank = TRUST_TIER_ORDER.get(old.trust_tier, 5)
            new_rank = TRUST_TIER_ORDER.get(new.trust_tier, 5)
            if new_rank > old_rank:
                modifications.append(
                    {
                        "detail": (
                            f"Trust tier downgraded: "
                            f"{old.trust_tier.value} → {new.trust_tier.value}"
                        ),
                        "severity": "high",
                    }
                )
            else:
                # A snapshot is unsigned: a raised label is a claim to review, not evidence.
                modifications.append(
                    {
                        "detail": (
                            f"Trust tier upgraded: {old.trust_tier.value} → {new.trust_tier.value}"
                        ),
                        "severity": "medium",
                    }
                )

        if old.version != new.version:
            modifications.append(
                {
                    "detail": f"Version changed: {_clip(old.version)} → {_clip(new.version)}",
                    "severity": "medium",
                }
            )

        old_hash = getattr(old, "definition_hash", None)
        new_hash = getattr(new, "definition_hash", None)
        old_hash_version = getattr(old, "definition_hash_version", None)
        new_hash_version = getattr(new, "definition_hash_version", None)
        # Digests under one named profile are comparable even when it is not current; an
        # absent profile names no serializer, so two absent ones are not.
        comparable = old_hash_version == new_hash_version and new_hash_version is not None
        if old_hash and new_hash and old_hash != new_hash and comparable:
            modifications.append(
                {
                    "detail": "Tool definition hash changed — possible rug-pull attack.",
                    "severity": "critical",
                }
            )
        elif (
            old_hash
            and new_hash
            and (
                old_hash_version != TOOL_DEFINITION_HASH_VERSION
                or new_hash_version != TOOL_DEFINITION_HASH_VERSION
            )
        ):
            modifications.append(
                {
                    "detail": "Tool fingerprint versions are unknown or incompatible; re-collect and re-approve.",
                    "severity": "high",
                }
            )
        elif old_hash and not new_hash:
            modifications.append(
                {
                    "detail": "Tool definition hash missing — assurance regressed; content is unknown.",
                    "severity": "high",
                }
            )
        elif not old_hash and new_hash:
            # The first binding of content the baseline never pinned is itself a
            # reviewable change: nothing shows the content predates this revision.
            modifications.append(
                {
                    "detail": "Tool definition hash became available — first binding of "
                    "content the baseline never pinned.",
                    "severity": "medium",
                }
            )

        old_content = getattr(old, "content_hash", None)
        new_content = getattr(new, "content_hash", None)
        if old_content != new_content:
            modifications.append(
                {
                    "detail": "Content hash removed — content integrity is unknown."
                    if old_content and not new_content
                    else "Content hash changed."
                    if old_content
                    else "Content hash became available — first binding of content the "
                    "baseline never pinned.",
                    "severity": "high" if old_content else "medium",
                }
            )

        for hash_key in sorted(set(old.hashes.keys()) | set(new.hashes.keys())):
            old_h = old.hashes.get(hash_key)
            new_h = new.hashes.get(hash_key)
            if old_h != new_h:
                if old_h and not new_h:
                    outcome = "removed — integrity is unknown."
                elif old_h:
                    outcome = "changed."
                else:
                    outcome = (
                        "became available — first binding of content the baseline never pinned."
                    )
                modifications.append(
                    {
                        "detail": f"File hash ({_clip(hash_key)}) {outcome}",
                        "severity": "high" if old_h else "medium",
                    }
                )

        old_pinned = getattr(old, "version_pinned", None)
        new_pinned = getattr(new, "version_pinned", None)
        if old_pinned is True and new_pinned is not True:
            modifications.append(
                {
                    "detail": "Version pin removed — now floating or unknown.",
                    "severity": "high",
                }
            )

        old_safety = getattr(old, "serialization_safety", None)
        new_safety = getattr(new, "serialization_safety", None)
        if old_safety and new_safety and old_safety != new_safety:
            unsafe_target = new_safety in {
                SerializationSafety.UNSAFE_CODE_EXECUTION,
                SerializationSafety.UNSAFE_TEMPLATE_INJECTION,
            }
            modifications.append(
                {
                    "detail": f"Serialization safety changed: {old_safety.value} → {new_safety.value}",
                    "severity": "critical" if unsafe_target else "high",
                }
            )

        old_signing = getattr(old, "signing_status", None)
        new_signing = getattr(new, "signing_status", None)
        if old_signing != new_signing:
            # A snapshot is unsigned: only a stronger status is a claim to review at medium.
            raised = _signing_rank(new_signing) < _signing_rank(old_signing)
            modifications.append(
                {
                    "detail": f"Signing status changed: {_clip(old_signing)} → {_clip(new_signing)}",
                    "severity": "medium" if raised else "high",
                }
            )

        # Cover every remaining model field, rather than silently accepting a new
        # security field until somebody remembers to add a special-case comparison.
        handled = {
            "trust_tier",
            "version",
            "definition_hash",
            "content_hash",
            "hashes",
            "serialization_safety",
            "signing_status",
            "launcher_package",
            "risks",
        }
        # These special cases cover only some transitions; retain the generic
        # comparison for all other version/profile changes.
        if old_pinned is True and new_pinned is not True:
            handled.add("version_pinned")
        if old_hash or new_hash:
            handled.add("definition_hash_version")
        if (
            isinstance(old, CredentialComponent)
            and isinstance(new, CredentialComponent)
            and new.value_in_checkout
            and not old.value_in_checkout
        ):
            modifications.append(
                {
                    "detail": "A value for this credential is now committed in the checkout. "
                    "Remove it and rotate the credential.",
                    "severity": "high",
                }
            )
            handled.add("value_in_checkout")
        old_fields = old.model_dump(mode="json")
        new_fields = new.model_dump(mode="json")
        modifications.extend(self._risk_changes(old_fields["risks"], new_fields["risks"]))
        if _discovery_finding_drift(old_fields, new_fields):
            modifications.append(
                {
                    "detail": "ShadowScan finding content changed, including fields this "
                    "inventory does not project.",
                    "severity": "medium",
                }
            )
        old_props, new_props = old_fields.get("properties"), new_fields.get("properties")
        if isinstance(old_props, dict) and isinstance(new_props, dict):
            before = old_props.pop(_DECLARED_AUTONOMY, None)
            after = new_props.pop(_DECLARED_AUTONOMY, None)
            if not _same(before, after, ("properties", _DECLARED_AUTONOMY)):
                # The manifest's autonomy declaration is recorded as a property because
                # it is not an observation; a change is as consequential as the typed field.
                modifications.append(
                    {"detail": "Declared autonomy level changed.", "severity": "high"}
                )
            modifications.extend(_property_changes(old_props, new_props))
            handled.add("properties")
        for key in sorted((old_fields.keys() | new_fields.keys()) - handled):
            old_value = old_fields.get(key)
            new_value = new_fields.get(key)
            if _same(old_value, new_value, (key,)):
                continue
            severity = "medium"
            if (
                key in _SECURITY_FIELDS
                or key.endswith(("_ref", "_refs"))
                or _DIGEST_NAME.search(key) is not None
            ):
                severity = "high"
            if (key == "trust_remote_code" and new_value is True) or key in {
                "input_schema",
                "description_text",
                "annotations",
            }:
                severity = "critical"
            modifications.append({"detail": f"{key} changed.", "severity": severity})
        return modifications

    @staticmethod
    def _risk_changes(old_risks: list[Any], new_risks: list[Any]) -> list[dict[str, str]]:
        """Report added and removed findings with their own severity, not as one opaque change."""
        records = {_json_text(risk): risk for risk in (*old_risks, *new_risks)}
        before = Counter(_json_text(risk) for risk in old_risks)
        after = Counter(_json_text(risk) for risk in new_risks)

        def summary(found: Counter[str]) -> tuple[str, list[str]]:
            groups: Counter[tuple[str, str]] = Counter()
            for key, count in found.items():
                record = records[key]
                groups[(str(record.get("severity")), _clip(record.get("category")))] += count
            severities = [severity for severity, _ in groups]
            shown = ", ".join(
                f"{count} {severity} ({category})"
                for (severity, category), count in sorted(
                    groups.items(), key=lambda item: (-_severity_rank(item[0][0]), item[0][1])
                )
            )
            return shown, severities

        changes: list[dict[str, str]] = []
        added, removed = after - before, before - after
        if added:
            shown, severities = summary(added)
            changes.append(
                {
                    "detail": f"Risk findings added: {shown}.",
                    "severity": _max_severity(["medium", *severities]),
                }
            )
        if removed:
            shown, _ = summary(removed)
            changes.append({"detail": f"Risk findings removed: {shown}.", "severity": "medium"})
        return changes

    def _diff_metadata(self, old: AIBOM, new: AIBOM, report: DiffReport) -> None:
        old_metadata = old.metadata.model_dump(mode="json")
        new_metadata = new.metadata.model_dump(mode="json")
        for metadata in (old_metadata, new_metadata):
            # These identify a collection event, rather than its composition.
            metadata.pop("serial_number", None)
            metadata.pop("timestamp", None)
            metadata.pop("completeness", None)
        self._diff_completeness(old.metadata.completeness, new.metadata.completeness, report)
        for key in sorted(old_metadata.keys() | new_metadata.keys()):
            if _same(old_metadata.get(key), new_metadata.get(key), (key,)):
                continue
            if key in _INFO_METADATA:
                report.metadata_changes.append(
                    {
                        "field": key,
                        "severity": "info",
                        "detail": "The snapshots were written by different Nexus SymBiote "
                        "releases; a release can record evidence differently.",
                    }
                )
                continue
            severity = "high" if key == "spec_version" else "medium"
            change = {
                "field": key,
                "severity": severity,
                "detail": f"Snapshot metadata {key} changed.",
            }
            report.metadata_changes.append(change)
            report.security_alerts.append(
                {"severity": severity, "component": "metadata", "alert": change["detail"]}
            )

    def _diff_completeness(
        self,
        old: CompletenessClaim | None,
        new: CompletenessClaim | None,
        report: DiffReport,
    ) -> None:
        """Compare coverage field by field: a regression alerts and names what regressed."""

        def regression(name: str, detail: str) -> None:
            report.metadata_changes.append(
                {"field": f"completeness.{name}", "severity": "high", "detail": detail}
            )
            report.security_alerts.append(
                {"severity": "high", "component": "metadata", "alert": detail}
            )

        def improvement(name: str, detail: str) -> None:
            report.metadata_changes.append(
                {"field": f"completeness.{name}", "severity": "info", "detail": detail}
            )

        if old is None and new is None:
            report.notes.append(
                {
                    "field": "completeness",
                    "severity": "info",
                    "detail": "Neither snapshot carries a completeness claim, so coverage "
                    "cannot be compared.",
                }
            )
            return
        if new is None:
            regression(
                "claim", "The new snapshot carries no completeness claim; its coverage is unknown."
            )
            return
        if old is None:
            # Nothing shows the baseline had the same gaps, so any gap the new snapshot
            # records could have been introduced by the change under review.
            gaps = _incompleteness(new)
            if gaps:
                regression(
                    "claim",
                    "The baseline carries no completeness claim, so gaps in the new snapshot "
                    "cannot be shown to predate this change. " + " ".join(gaps),
                )
            else:
                improvement(
                    "claim",
                    "The baseline carries no completeness claim, so coverage changes cannot be "
                    "assessed against it; the new snapshot records complete coverage.",
                )
            return

        old_fields = old.model_dump(mode="json")
        new_fields = new.model_dump(mode="json")
        handled = {"timestamp"}

        handled.add("scope")
        if old.scope != new.scope:
            regression(
                "scope",
                f"Coverage scope changed from '{_clip(old.scope)}' to '{_clip(new.scope)}'.",
            )

        handled.add("scanner_status")
        for name in sorted(old.scanner_status.keys() | new.scanner_status.keys()):
            before, after = old.scanner_status.get(name), new.scanner_status.get(name)
            if before == after:
                continue
            label = f"scanner_status.{name}"
            if after is None:
                regression(
                    label, f"Collector '{_clip(name)}' is no longer recorded (was {_clip(before)})."
                )
            elif before is None:
                if after == "complete":
                    improvement(label, f"Collector '{_clip(name)}' is now recorded as complete.")
                else:
                    # The baseline recorded nothing for this collector, so nothing shows
                    # the gap the candidate now states predates the change under review.
                    regression(
                        label,
                        f"Collector '{_clip(name)}' is now recorded as {_clip(after)}; the "
                        "baseline does not show this gap predates the change.",
                    )
            elif _STATUS_RANK.get(after, 3) < _STATUS_RANK.get(before, 3):
                improvement(
                    label,
                    f"Collector '{_clip(name)}' coverage changed from {_clip(before)} to "
                    f"{_clip(after)}.",
                )
            else:
                regression(
                    label,
                    f"Collector '{_clip(name)}' coverage changed from {_clip(before)} to "
                    f"{_clip(after)}.",
                )

        # (field, whether an added entry is the regression, regression text, improvement text)
        for name, growth_regresses, worse, better in (
            ("collectors_requested", False, "Collectors no longer requested", "Collectors added"),
            (
                "collectors_completed",
                False,
                "Collectors no longer completed",
                "Collectors now completed",
            ),
            ("scan_failures", True, "New scan failures", "Scan failures no longer reported"),
            ("surfaces_excluded", True, "New coverage gaps", "Coverage gaps no longer reported"),
            ("exclusions", True, "New collection exclusions", "Collection exclusions removed"),
            (
                "unobserved_surfaces",
                True,
                "Surfaces newly recorded as unobserved",
                "Surfaces no longer recorded as unobserved",
            ),
        ):
            handled.add(name)
            # Multisets: a second identical gap or failure is a new one.
            before_items = Counter(str(item) for item in getattr(old, name))
            after_items = Counter(str(item) for item in getattr(new, name))
            added, removed = after_items - before_items, before_items - after_items
            lost, gained = (added, removed) if growth_regresses else (removed, added)
            if lost:
                regression(name, f"{worse}: {_listing(lost.elements())}.")
            if gained:
                improvement(name, f"{better}: {_listing(gained.elements())}.")

        handled.add("surfaces_scanned")
        scanned_before, scanned_after = set(old.surfaces_scanned), set(new.surfaces_scanned)
        lost_surfaces = scanned_before - scanned_after
        gained_surfaces = scanned_after - scanned_before
        if lost_surfaces:
            # A surface that is no longer scanned is narrowed coverage: components
            # found there can disappear without a removal alert of their own.
            noun = "surface" if len(lost_surfaces) == 1 else "surfaces"
            regression(
                "surfaces_scanned",
                f"{len(lost_surfaces)} scanned {noun} removed ({_listing(lost_surfaces)}): "
                "coverage narrowed; components found there are no longer compared.",
            )
        if gained_surfaces:
            noun = "surface" if len(gained_surfaces) == 1 else "surfaces"
            improvement(
                "surfaces_scanned",
                f"{len(gained_surfaces)} scanned {noun} added ({_listing(gained_surfaces)}). "
                "Components found there are compared separately.",
            )

        handled.add("assurance_level")
        if old.assurance_level != new.assurance_level:
            before_level, after_level = old.assurance_level.value, new.assurance_level.value
            message = f"Coverage assurance changed from {before_level} to {after_level}."
            if _ASSURANCE_RANK.get(after_level, 3) < _ASSURANCE_RANK.get(before_level, 3):
                improvement("assurance_level", message)
            else:
                regression("assurance_level", message)

        handled |= self._diff_source_report(old, new, regression, improvement)

        for name in sorted((old_fields.keys() | new_fields.keys()) - handled):
            if not _same(old_fields.get(name), new_fields.get(name), (name,)):
                regression(name, f"Completeness field {name} changed.")

        self._note_shared_gaps(old, new, report)

    @staticmethod
    def _diff_source_report(
        old: CompletenessClaim,
        new: CompletenessClaim,
        regression: Callable[[str, str], None],
        improvement: Callable[[str, str], None],
    ) -> set[str]:
        """Exact report bytes authenticate a report; its normalized content is what drifts."""
        content_comparable = (
            old.source_report_content_digest is not None
            and new.source_report_content_digest is not None
            and old.source_report_content_profile is not None
            and old.source_report_content_profile == new.source_report_content_profile
        )
        if content_comparable:
            if old.source_report_content_digest != new.source_report_content_digest:
                regression(
                    "source_report_content_digest",
                    "ShadowScan report content changed; review the report and the imported "
                    "components.",
                )
            elif old.source_report_digest != new.source_report_digest:
                improvement(
                    "source_report_digest",
                    "ShadowScan report regenerated; normalized content unchanged.",
                )
        elif old.source_report_digest != new.source_report_digest:
            if new.source_report_digest is None:
                regression("source_report_digest", "The ShadowScan report is no longer imported.")
            elif old.source_report_digest is None:
                regression("source_report_digest", "A ShadowScan report is now imported.")
            else:
                regression(
                    "source_report_digest",
                    "ShadowScan report bytes changed, and the snapshots carry no comparable "
                    "content digest.",
                )

        same_import_state = (old.source_report_digest is None) == (new.source_report_digest is None)
        if old.source_report_format != new.source_report_format:
            if None not in (old.source_report_format, new.source_report_format):
                message = (
                    f"ShadowScan report format changed from {old.source_report_format} to "
                    f"{new.source_report_format}."
                )
                if new.source_report_format == "shadowscan-json":
                    improvement("source_report_format", message)
                else:
                    regression("source_report_format", message)
            elif same_import_state:
                if new.source_report_format is None:
                    regression(
                        "source_report_format",
                        f"ShadowScan report format is no longer recorded (was {old.source_report_format}).",
                    )
                else:
                    improvement(
                        "source_report_format",
                        f"ShadowScan report format is now recorded as {new.source_report_format}.",
                    )

        before_status, after_status = old.source_report_status, new.source_report_status
        if before_status != after_status:
            if None not in (before_status, after_status):
                message = (
                    f"ShadowScan source status changed from {before_status} to {after_status}."
                )
                if _SOURCE_STATUS_RANK.get(str(after_status), 3) < _SOURCE_STATUS_RANK.get(
                    str(before_status), 3
                ):
                    improvement("source_report_status", message)
                else:
                    regression("source_report_status", message)
            elif same_import_state:
                if after_status is None:
                    regression(
                        "source_report_status",
                        f"ShadowScan source status is no longer recorded (was {before_status}).",
                    )
                elif after_status == "complete":
                    improvement(
                        "source_report_status",
                        "ShadowScan source status is now recorded as complete.",
                    )
                else:
                    regression(
                        "source_report_status",
                        f"ShadowScan source status is now {after_status} (was unrecorded).",
                    )

        if new.source_unmapped_count > old.source_unmapped_count:
            regression(
                "source_unmapped_count",
                f"ShadowScan entries left unmapped rose from {old.source_unmapped_count} to "
                f"{new.source_unmapped_count}.",
            )
        elif new.source_unmapped_count < old.source_unmapped_count:
            improvement(
                "source_unmapped_count",
                f"ShadowScan entries left unmapped fell from {old.source_unmapped_count} to "
                f"{new.source_unmapped_count}.",
            )
        elif sorted(old.source_unmapped_indexes) != sorted(new.source_unmapped_indexes):
            improvement(
                "source_unmapped_indexes",
                "Unmapped ShadowScan entries moved within the report; their number is unchanged.",
            )

        before_limits = Counter(old.source_projection_limitations or [])
        after_limits = Counter(new.source_projection_limitations or [])
        if after_limits - before_limits:
            regression(
                "source_projection_limitations",
                f"New ShadowScan projection limitations: {_listing((after_limits - before_limits).elements())}.",
            )
        if before_limits - after_limits:
            improvement(
                "source_projection_limitations",
                f"ShadowScan projection limitations no longer reported: "
                f"{_listing((before_limits - after_limits).elements())}.",
            )

        AIBOMDiffer._diff_discovery_verification(old, new, regression, improvement)

        if None not in (old.source_report_path, new.source_report_path) and (
            old.source_report_path != new.source_report_path
        ):
            # The location is where the import read the report, not its content, which the
            # report digests bind; a moved report is information, not drift.
            improvement(
                "source_report_path",
                f"ShadowScan report location changed from {_clip(old.source_report_path)} to "
                f"{_clip(new.source_report_path)}.",
            )
        return {
            "source_report_digest",
            "source_report_content_digest",
            "source_report_content_profile",
            "source_report_format",
            "source_report_status",
            "source_unmapped_count",
            "source_unmapped_indexes",
            "source_projection_limitations",
            "discovery_verification",
            "source_report_path",
        }

    @staticmethod
    def _diff_discovery_verification(
        old: CompletenessClaim,
        new: CompletenessClaim,
        regression: Callable[[str, str], None],
        improvement: Callable[[str, str], None],
    ) -> None:
        """Alert when signature verification is gained, lost or re-attributed.

        A baseline written before the record existed carries none: that reads as
        not-applicable, not as a change. Report digests and run times change on
        every rerun and the content digest is already compared above, so only the
        status and, for verified evidence, the signer binding are compared here.
        """
        before, after = old.discovery_verification, new.discovery_verification
        before_status = before.status if before is not None else "not-applicable"
        after_status = after.status if after is not None else "not-applicable"
        if before_status == "verified" and after_status != "verified":
            regression(
                "discovery_verification",
                "ShadowScan discovery evidence is no longer signature-verified.",
            )
        elif before_status != "verified" and after is not None and after.status == "verified":
            # The snapshot is unsigned, so the reviewer must see whose signature it claims.
            improvement(
                "discovery_verification",
                "ShadowScan discovery evidence is now signature-verified (signer "
                f"{_clip(after.signer_identity)}, issuer {_clip(after.issuer)}).",
            )
        elif (
            before is not None
            and after is not None
            and before_status == "verified"
            and (before.signer_identity, before.issuer) != (after.signer_identity, after.issuer)
        ):
            regression(
                "discovery_verification",
                "ShadowScan discovery evidence is now signed by a different identity or issuer.",
            )

    @staticmethod
    def _note_shared_gaps(
        old: CompletenessClaim, new: CompletenessClaim, report: DiffReport
    ) -> None:
        """Equal incompleteness is no drift, but the report must say the baseline had gaps."""
        collectors = [
            f"{_clip(name)} ({_clip(state)})"
            for name, state in sorted(new.scanner_status.items())
            if state != "complete" and old.scanner_status.get(name, "unknown") != "complete"
        ]
        failures = sum((Counter(old.scan_failures) & Counter(new.scan_failures)).values())
        gaps = sum((Counter(old.surfaces_excluded) & Counter(new.surfaces_excluded)).values())
        if not (collectors or failures or gaps):
            return
        parts = []
        if collectors:
            parts.append("collectors not complete in either: " + ", ".join(collectors))
        if failures:
            parts.append(f"{failures} scan failure(s) in both")
        if gaps:
            parts.append(f"{gaps} coverage gap(s) in both")
        report.notes.append(
            {
                "field": "completeness",
                "severity": "info",
                "detail": "Both snapshots are incomplete ("
                + "; ".join(parts)
                + "). The baseline was already incomplete; changes inside these gaps cannot "
                "be detected.",
            }
        )

    def _diff_inputs(self, old: AIBOM, new: AIBOM, report: DiffReport) -> None:
        """Inputs that other commands would refuse must not compare clean."""
        from nexus_symbiote.graph import validate_graph

        for label, bom in (("baseline", old), ("candidate", new)):
            if not _readable_spec_version(bom.metadata.spec_version):
                detail = (
                    f"The {label} snapshot uses a spec_version this release does not support; "
                    "the comparison can miss fields."
                )
                report.metadata_changes.append(
                    {"field": "spec_version", "severity": "high", "detail": detail}
                )
                report.security_alerts.append(
                    {"severity": "high", "component": "metadata", "alert": detail}
                )

        before, after = set(validate_graph(old)), set(validate_graph(new))
        if after - before:
            detail = (
                f"The candidate snapshot has {len(after - before)} new graph consistency "
                f"problem(s), such as dangling or mistyped references: {_listing(after - before)}."
            )
            report.metadata_changes.append({"field": "graph", "severity": "high", "detail": detail})
            report.security_alerts.append(
                {"severity": "high", "component": "metadata", "alert": detail}
            )
        if before - after:
            report.metadata_changes.append(
                {
                    "field": "graph",
                    "severity": "info",
                    "detail": f"Graph consistency problems of the baseline no longer present: "
                    f"{_listing(before - after)}.",
                }
            )
        if before & after:
            report.notes.append(
                {
                    "field": "graph",
                    "severity": "info",
                    "detail": f"Both snapshots have {len(before & after)} graph consistency "
                    "problem(s); neither is a valid inventory.",
                }
            )

        old_time, new_time = old.metadata.timestamp, new.metadata.timestamp
        if isinstance(old_time, datetime) and isinstance(new_time, datetime):
            try:
                reversed_order = old_time > new_time
            except TypeError:
                reversed_order = False
            if reversed_order:
                report.notes.append(
                    {
                        "field": "timestamp",
                        "severity": "info",
                        "detail": "The baseline (first argument) was recorded after the "
                        "candidate; check the argument order, since swapped snapshots show "
                        "additions as removals.",
                    }
                )
        if _records_absolute_paths(old) != _records_absolute_paths(new):
            report.notes.append(
                {
                    "field": "paths",
                    "severity": "info",
                    "detail": "One snapshot records absolute file paths, as release 0.1.0 "
                    "did, and the other root-relative paths, so location fields differ. "
                    "Re-create the baseline with this release from its reviewed commit.",
                }
            )

    def _diff_dependencies(
        self, old: AIBOM, new: AIBOM, report: DiffReport, retained: set[str]
    ) -> None:
        old_deps = {_edge_key(edge): edge for edge in old.dependencies}
        new_deps = {_edge_key(edge): edge for edge in new.dependencies}
        old_bindings = {(e.source_ref, e.target_ref, e.relationship) for e in old.dependencies}
        new_bindings = {(e.source_ref, e.target_ref, e.relationship) for e in new.dependencies}
        for key in sorted(new_deps.keys() - old_deps.keys()):
            edge = new_deps[key]
            report.dependencies_added.append(
                DependencyChange(
                    source_ref=edge.source_ref,
                    target_ref=edge.target_ref,
                    relationship=edge.relationship,
                    change_type="added",
                    assurance_level=edge.assurance_level,
                    conditions=edge.conditions,
                    severity="high" if edge.relationship in _EDGE_ADDED_HIGH else "medium",
                )
            )
        for key in sorted(old_deps.keys() - new_deps.keys()):
            edge = old_deps[key]
            report.dependencies_removed.append(
                DependencyChange(
                    source_ref=edge.source_ref,
                    target_ref=edge.target_ref,
                    relationship=edge.relationship,
                    change_type="removed",
                    assurance_level=edge.assurance_level,
                    conditions=edge.conditions,
                    severity="high" if edge.relationship in _EDGE_REMOVED_HIGH else "medium",
                )
            )
        modified: set[tuple[str, str, str]] = set()
        for change in (*report.dependencies_added, *report.dependencies_removed):
            binding = (change.source_ref, change.target_ref, change.relationship)
            if binding in old_bindings and binding in new_bindings:
                change.severity = "high"
                if binding in modified:
                    continue
                modified.add(binding)
                report.security_alerts.append(
                    {
                        "severity": "high",
                        "component": change.source_ref,
                        "alert": "Dependency assurance or conditions changed; review the full "
                        "edge records.",
                    }
                )
                continue
            # An edge to a component that was itself added or removed is covered by that
            # component's alert, unless the relationship grants or withdraws authority.
            explained = not {change.source_ref, change.target_ref} <= retained
            if explained and change.severity != "high":
                continue
            verb = "added" if change.change_type == "added" else "removed"
            report.security_alerts.append(
                {
                    "severity": change.severity,
                    "component": change.source_ref,
                    "alert": f"Relationship {verb}: '{_clip(change.source_ref)}' "
                    f"{change.relationship} '{_clip(change.target_ref)}'.",
                }
            )

    def _generate_security_alerts(self, report: DiffReport) -> None:
        # An in-place change is at least as consequential as an addition, which
        # always alerts: a change rated medium, such as a version bump, must still
        # fail the CI gate.
        for change in report.components_modified:
            if change.severity in {"medium", "high", "critical"}:
                report.security_alerts.append(
                    {
                        "severity": change.severity,
                        "component": change.bom_ref,
                        "alert": (
                            f"{change.severity.capitalize()} change in '{_clip(change.name)}': "
                            f"{'; '.join(change.details)}"
                        ),
                    }
                )

        for change in report.components_added:
            report.security_alerts.append(
                {
                    "severity": change.severity,
                    "component": change.bom_ref,
                    "alert": (
                        f"New component '{_clip(change.name)}' "
                        f"({change.component_type}) added to supply chain."
                    ),
                }
            )

        # A record that disappears is as reviewable as one that appears: it may have been
        # deleted, or moved where no collector reads it, taking its fingerprint along.
        for change in report.components_removed:
            report.security_alerts.append(
                {
                    "severity": change.severity,
                    "component": change.bom_ref,
                    "alert": (
                        f"Component '{_clip(change.name)}' ({change.component_type}) is no longer in "
                        "the inventory: confirm it was deleted, not moved out of collector scope."
                    ),
                }
            )

    def _settings_drift_alerts(
        self,
        old_map: dict[str, Any],
        new_map: dict[str, Any],
        retained: set[str],
        report: DiffReport,
    ) -> None:
        for ref in sorted(retained):
            raw_old = getattr(old_map[ref], "properties", None)
            raw_new = getattr(new_map[ref], "properties", None)
            old_props = raw_old if isinstance(raw_old, dict) else {}
            new_props = raw_new if isinstance(raw_new, dict) else {}
            comp_name = neutralize(_clip(getattr(new_map[ref], "name", ref)))

            def record_malformed(
                field_name: str, *, _ref: str = ref, _comp: str = comp_name
            ) -> None:
                report.security_alerts.append(
                    {
                        "severity": "high",
                        "component": _ref,
                        "alert_type": "malformed_settings_metadata",
                        "alert": neutralize(
                            f"malformed_settings_metadata: invalid '{field_name}' metadata in "
                            f"'{_comp}'; settings drift cannot be verified."
                        ),
                    }
                )

            old_deny, old_deny_ok = _string_set_prop(old_props, "deny_rules")
            new_deny, new_deny_ok = _string_set_prop(new_props, "deny_rules")
            if not old_deny_ok or not new_deny_ok:
                record_malformed("deny_rules")
            else:
                removed_deny = sorted(old_deny - new_deny)
                if removed_deny:
                    report.security_alerts.append(
                        {
                            "severity": "high",
                            "component": ref,
                            "alert_type": "deny_rule_removed",
                            "alert": neutralize(
                                f"deny_rule_removed: {_bounded_items_text(removed_deny)} "
                                f"removed from '{comp_name}'."
                            ),
                        }
                    )
                elif _truncated_tail_changed(
                    old_props, new_props, "deny_rules", detect_removal=True
                ):
                    report.security_alerts.append(
                        {
                            "severity": "high",
                            "component": ref,
                            "alert_type": "deny_rule_removed",
                            "alert": neutralize(
                                f"deny_rule_removed: truncated deny_rules changed or shrank in "
                                f"'{comp_name}'."
                            ),
                        }
                    )

            old_domains, old_dom_ok = _string_set_prop(old_props, "sandbox_allowed_domains")
            new_domains, new_dom_ok = _string_set_prop(new_props, "sandbox_allowed_domains")
            if not old_dom_ok or not new_dom_ok:
                record_malformed("sandbox_allowed_domains")
            else:
                added_domains = sorted(new_domains - old_domains)
                if added_domains:
                    report.security_alerts.append(
                        {
                            "severity": "high",
                            "component": ref,
                            "alert_type": "sandbox_egress_widened",
                            "alert": neutralize(
                                f"sandbox_egress_widened: allowedDomains added "
                                f"{_bounded_items_text(added_domains)} in '{comp_name}'."
                            ),
                        }
                    )
                elif _truncated_tail_changed(
                    old_props, new_props, "sandbox_allowed_domains", detect_removal=False
                ):
                    report.security_alerts.append(
                        {
                            "severity": "high",
                            "component": ref,
                            "alert_type": "sandbox_egress_widened",
                            "alert": neutralize(
                                f"sandbox_egress_widened: truncated allowedDomains expanded in "
                                f"'{comp_name}'."
                            ),
                        }
                    )

            old_act = old_props.get("activation")
            new_act = new_props.get("activation")
            if (old_act is not None and not isinstance(old_act, dict)) or (
                new_act is not None and not isinstance(new_act, dict)
            ):
                record_malformed("activation")
                continue
            if not isinstance(old_act, dict) or not isinstance(new_act, dict):
                continue
            for path, new_scope in sorted(new_act.items(), key=lambda kv: str(kv[0])):
                old_scope = old_act.get(path)
                if old_scope is None:
                    continue
                if (
                    not isinstance(path, str)
                    or not isinstance(old_scope, dict)
                    or not isinstance(new_scope, dict)
                ):
                    record_malformed("activation")
                    continue
                old_always = old_scope.get("always_apply")
                new_always = new_scope.get("always_apply")
                old_globs, old_gok = _string_set_prop(old_scope, "globs")
                new_globs, new_gok = _string_set_prop(new_scope, "globs")
                if (
                    (old_always is not None and not isinstance(old_always, bool))
                    or (new_always is not None and not isinstance(new_always, bool))
                    or not old_gok
                    or not new_gok
                ):
                    record_malformed("activation")
                    continue
                widened = (
                    (not old_always and bool(new_always))
                    or bool(new_globs - old_globs)
                    or _truncated_tail_changed(old_scope, new_scope, "globs", detect_removal=False)
                )
                if widened:
                    report.security_alerts.append(
                        {
                            "severity": "high",
                            "component": ref,
                            "alert_type": "scope_widened",
                            "alert": neutralize(
                                f"scope_widened: activation scope widened for '{_clip(path)}' "
                                f"in '{comp_name}'."
                            ),
                        }
                    )


def _string_set_prop(props: dict[str, Any], key: str) -> tuple[set[str], bool]:
    raw = props.get(key)
    if raw is None:
        return set(), True
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        return set(), False
    return set(raw), True


def _nonneg_int_prop(props: dict[str, Any], key: str) -> int | None:
    val = props.get(key)
    return val if type(val) is int and val >= 0 else None


def _bounded_items_text(items: list[str], limit: int = 5) -> str:
    shown = ", ".join(neutralize(_clip(item)) for item in items[:limit])
    return shown + (f" (and {len(items) - limit} more)" if len(items) > limit else "")


def _truncated_tail_changed(
    old_props: dict[str, Any],
    new_props: dict[str, Any],
    prefix: str,
    *,
    detect_removal: bool,
) -> bool:
    old_trunc = old_props.get(f"{prefix}_truncated") is True
    new_trunc = new_props.get(f"{prefix}_truncated") is True
    old_total = _nonneg_int_prop(old_props, f"{prefix}_total")
    new_total = _nonneg_int_prop(new_props, f"{prefix}_total")
    old_digest = old_props.get(f"{prefix}_digest")
    new_digest = new_props.get(f"{prefix}_digest")
    has_digests = isinstance(old_digest, str) and isinstance(new_digest, str)
    if detect_removal:
        if not old_trunc:
            return False
        if not new_trunc:
            return True
        if has_digests:
            return old_digest != new_digest
        return old_total is not None and new_total is not None and new_total < old_total
    if not new_trunc:
        return False
    if not old_trunc:
        return True
    if has_digests:
        return old_digest != new_digest
    return old_total is not None and new_total is not None and new_total > old_total
