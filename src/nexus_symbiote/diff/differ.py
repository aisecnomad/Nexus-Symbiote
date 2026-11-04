"""AIBOM diff engine — compares two AIBOMs to detect supply chain changes.

Critical for detecting rug-pull attacks, tool definition mutations,
unauthorized component additions, and trust tier downgrades.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import TrustTier
from nexus_symbiote.core.hashing import TOOL_DEFINITION_HASH_VERSION
from nexus_symbiote.core.models import A2AServerComponent, MCPServerComponent

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
    "publisher_verified",
    "publisher_identity",
    "attestation_status",
    "execution_isolation",
    "human_in_the_loop",
    "permission_mode",
    "authentication_required",
    "package_url",
    "registry_uri",
    "registry_source",
    "registry_type",
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


def _semantic_value(value: Any, path: tuple[str, ...]) -> Any:
    """Ignore set ordering and fresh claim observation times, never arbitrary JSON arrays."""
    if isinstance(value, dict):
        return {
            key: _semantic_value(item, (*path, key))
            for key, item in sorted(value.items())
            if not (len(path) == 2 and path[0] == "claims" and key == "observed_at")
        }
    if isinstance(value, list):
        items = [_semantic_value(item, (*path, "[]")) for item in value]
        opaque = any(
            part in {"properties", "input_schema", "annotations", "variable_schema"}
            for part in path
        )
        key = path[-1]
        if not opaque and key == "risks":
            # Risk scoring counts each occurrence, so preserve multiplicity.
            return sorted(json.dumps(item, sort_keys=True, separators=(",", ":")) for item in items)
        if not opaque and (key in _SET_LISTS or key.endswith("_refs")):
            return sorted(
                {json.dumps(item, sort_keys=True, separators=(",", ":")) for item in items}
            )
        return items
    return value


def _dependency_records(edges: list[DependencyEdge]) -> dict[tuple[str, str, str], Counter[str]]:
    records: dict[tuple[str, str, str], Counter[str]] = {}
    for edge in edges:
        binding = (edge.source_ref, edge.target_ref, edge.relationship)
        key = json.dumps(edge.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        records.setdefault(binding, Counter())[key] += 1
    return records


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
            "dependencies_added": [
                {
                    "source": d.source_ref,
                    "target": d.target_ref,
                    "relationship": d.relationship,
                    "assurance_level": d.assurance_level,
                    "conditions": d.conditions,
                }
                for d in self.dependencies_added
            ],
            "dependencies_removed": [
                {
                    "source": d.source_ref,
                    "target": d.target_ref,
                    "relationship": d.relationship,
                    "assurance_level": d.assurance_level,
                    "conditions": d.conditions,
                }
                for d in self.dependencies_removed
            ],
            "security_alerts": self.security_alerts,
            "metadata_changes": self.metadata_changes,
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

        for ref in sorted(new_refs - old_refs):
            comp = new_map[ref]
            change = ComponentChange(
                bom_ref=ref,
                name=comp.name,
                change_type="added",
                component_type=comp.component_type.value,
                severity="medium",
                details=[f"New {comp.component_type.value} component added."],
            )
            report.components_added.append(change)

        for ref in sorted(old_refs - new_refs):
            comp = old_map[ref]
            change = ComponentChange(
                bom_ref=ref,
                name=comp.name,
                change_type="removed",
                component_type=comp.component_type.value,
                severity="info",
                details=[f"{comp.component_type.value} component removed."],
            )
            report.components_removed.append(change)

        for ref in sorted(old_refs & new_refs):
            modifications = self._compare_components(old_map[ref], new_map[ref])
            if modifications:
                severity = max(
                    (m.get("severity", "info") for m in modifications),
                    key=lambda s: ["info", "low", "medium", "high", "critical"].index(s),
                )
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
        self._diff_dependencies(old, new, report)
        self._generate_security_alerts(report)

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
                modifications.append(
                    {
                        "detail": (
                            f"Trust tier upgraded: {old.trust_tier.value} → {new.trust_tier.value}"
                        ),
                        "severity": "info",
                    }
                )

        if old.version != new.version:
            modifications.append(
                {
                    "detail": f"Version changed: {old.version} → {new.version}",
                    "severity": "medium",
                }
            )

        old_hash = getattr(old, "definition_hash", None)
        new_hash = getattr(new, "definition_hash", None)
        old_hash_version = getattr(old, "definition_hash_version", None)
        new_hash_version = getattr(new, "definition_hash_version", None)
        if (
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
        elif old_hash and new_hash and old_hash != new_hash:
            modifications.append(
                {
                    "detail": "Tool definition hash changed — possible rug-pull attack.",
                    "severity": "critical",
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
            modifications.append(
                {"detail": "Tool definition hash became available.", "severity": "info"}
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
                    else "Content hash became available.",
                    "severity": "high" if old_content else "info",
                }
            )

        for hash_key in set(old.hashes.keys()) | set(new.hashes.keys()):
            old_h = old.hashes.get(hash_key)
            new_h = new.hashes.get(hash_key)
            if old_h != new_h:
                modifications.append(
                    {
                        "detail": f"File hash ({hash_key}) "
                        + (
                            "removed — integrity is unknown." if old_h and not new_h else "changed."
                        ),
                        "severity": "high" if old_h else "info",
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
            modifications.append(
                {
                    "detail": f"Serialization safety changed: {old_safety.value} → {new_safety.value}",
                    "severity": "high",
                }
            )

        old_signing = getattr(old, "signing_status", None)
        new_signing = getattr(new, "signing_status", None)
        if old_signing != new_signing:
            sev = "high" if old_signing in {"sigstore-signed", "pgp-signed"} else "info"
            modifications.append(
                {
                    "detail": f"Signing status changed: {old_signing} → {new_signing}",
                    "severity": sev,
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
        }
        # These special cases cover only some transitions; retain the generic
        # comparison for all other version/profile changes.
        if old_pinned is True and new_pinned is not True:
            handled.add("version_pinned")
        if old_hash or new_hash:
            handled.add("definition_hash_version")
        old_fields = old.model_dump(mode="json")
        new_fields = new.model_dump(mode="json")
        for key in sorted((old_fields.keys() | new_fields.keys()) - handled):
            old_value = old_fields.get(key)
            new_value = new_fields.get(key)
            if _semantic_value(old_value, (key,)) == _semantic_value(new_value, (key,)):
                continue
            severity = "medium"
            if key in _SECURITY_FIELDS or key.endswith("_refs") or key.endswith("_ref"):
                severity = "high"
            if (
                key == "properties"
                and isinstance(new, A2AServerComponent)
                and any(
                    old.properties.get(field) != new.properties.get(field)
                    for field in (
                        "supported_interfaces",
                        "security_requirements",
                        "skill_security_requirements",
                    )
                )
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

    def _diff_metadata(self, old: AIBOM, new: AIBOM, report: DiffReport) -> None:
        old_metadata = old.metadata.model_dump(mode="json")
        new_metadata = new.metadata.model_dump(mode="json")
        for metadata in (old_metadata, new_metadata):
            # These identify a collection event, rather than its composition.
            metadata.pop("serial_number", None)
            metadata.pop("timestamp", None)
            if metadata.get("completeness") is not None:
                metadata["completeness"].pop("timestamp", None)
        for key in sorted(old_metadata.keys() | new_metadata.keys()):
            if _semantic_value(old_metadata.get(key), (key,)) == _semantic_value(
                new_metadata.get(key), (key,)
            ):
                continue
            severity = "high" if key in {"completeness", "spec_version"} else "medium"
            change = {
                "field": key,
                "severity": severity,
                "detail": f"Snapshot metadata {key} changed.",
            }
            report.metadata_changes.append(change)
            report.security_alerts.append(
                {"severity": severity, "component": "metadata", "alert": change["detail"]}
            )

    def _diff_dependencies(self, old: AIBOM, new: AIBOM, report: DiffReport) -> None:
        old_records = _dependency_records(old.dependencies)
        new_records = _dependency_records(new.dependencies)
        for binding in sorted(old_records.keys() | new_records.keys()):
            before = old_records.get(binding, Counter())
            after = new_records.get(binding, Counter())
            if before == after:
                continue
            source, target, relationship = binding
            for kind, delta, changes in (
                ("added", after - before, report.dependencies_added),
                ("removed", before - after, report.dependencies_removed),
            ):
                for key, count in sorted(delta.items()):
                    edge = DependencyEdge.model_validate_json(key)
                    changes.extend(
                        DependencyChange(
                            source,
                            target,
                            relationship,
                            kind,
                            edge.assurance_level,
                            edge.conditions,
                        )
                        for _ in range(count)
                    )
            # Qualifiers and multiplicity belong to the binding. Keep one alert
            # and retain the complete added/removed records for the reviewer.
            if before and after:
                action = "changed assurance, conditions or record count"
            else:
                action = "added" if after else "removed"
            high = bool(before and after) or relationship in {
                "acts-as-identity",
                "approved-under",
                "delegates-to",
                "invokes",
                "uses-guardrail",
            }
            report.security_alerts.append(
                {
                    "severity": "high" if high else "medium",
                    "component": source,
                    "alert": f"Dependency {relationship} from '{source}' to '{target}' {action}.",
                }
            )

    def _generate_security_alerts(self, report: DiffReport) -> None:
        # An in-place change is at least as consequential as an addition, which
        # always alerts: a version bump, a swapped lockfile integrity value or a
        # replaced tool body is rated medium, and must still fail the CI gate.
        for change in report.components_modified:
            if change.severity in {"medium", "high", "critical"}:
                report.security_alerts.append(
                    {
                        "severity": change.severity,
                        "component": change.bom_ref,
                        "alert": (
                            f"{change.severity.capitalize()} change in '{change.name}': {'; '.join(change.details)}"
                        ),
                    }
                )

        for change in report.components_added:
            report.security_alerts.append(
                {
                    "severity": "medium",
                    "component": change.bom_ref,
                    "alert": (
                        f"New component '{change.name}' "
                        f"({change.component_type}) added to supply chain."
                    ),
                }
            )
