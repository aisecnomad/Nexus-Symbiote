"""Static attribution of expected format and fingerprint transitions across tool upgrades.

When an operator upgrades Nexus SymBiote across a documented profile change (for example
``0.1.0 -> 0.2.0`` or ``0.2.0 -> 0.3.0``) and passes ``diff --expect-upgrade FROM_VERSION``,
alerts caused *exclusively* by the documented serializer/profile transitions of that upgrade
are moved from ``security_alerts`` into ``tool_upgrade_changes``. Any component modification
that mixes an upgrade transition with genuine supply-chain drift (changed command, endpoint,
tool description, permissions, etc.) remains in ``security_alerts`` and fails the gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class UpgradeRule:
    """Known profile or schema transitions introduced after ``from_version``."""

    from_version: str
    detail_patterns: tuple[re.Pattern[str], ...]
    requires_profile_bump_for_binding: bool = True


_PROFILE_BUMP_RE = re.compile(
    r"^properties\.static_(?:config_hash_profile|value_binding_profile) (?:changed|added)\.$"
)

_STATIC_BINDING_MSG = (
    "MCP server static source binding changed: launcher, arguments, "
    "environment, endpoint or declared tools differ, or the binding key "
    "changed. Review before execution."
)

# 0.1.0 and 0.2.0 both wrote tool fingerprints as rfc8785-jcs-v2, the current profile, so no
# supported upgrade changes a fingerprint version. "Tool fingerprint versions are unknown or
# incompatible" therefore names a snapshot outside the documented transition, whose hash
# change can be a changed descriptor, and is never attributed.
SUPPORTED_UPGRADE_VERSIONS: dict[str, UpgradeRule] = {
    "0.1.0": UpgradeRule(
        from_version="0.1.0",
        detail_patterns=(
            _PROFILE_BUMP_RE,
            re.compile(r"^Risk finding category changed: transport_security -> local_process\.$"),
        ),
    ),
    "0.2.0": UpgradeRule(
        from_version="0.2.0",
        detail_patterns=(
            _PROFILE_BUMP_RE,
            re.compile(r"^properties\.(?:name_neutralized|serialization_evidence) added\.$"),
        ),
    ),
}

# An unsupported spec_version is never an upgrade transition: the comparison can miss fields.
_METADATA_UPGRADE_RE = re.compile(r"^(?:Native AIBOM format version|Tool version)\b")


def _all_details_expected(details: list[str], rule: UpgradeRule) -> bool:
    if not details:
        return False
    has_profile_bump = any(_PROFILE_BUMP_RE.match(d) for d in details)
    has_hash_change = any(d.startswith("properties.static_config_hash ") for d in details)
    for detail in details:
        if detail == _STATIC_BINDING_MSG:
            # Only attribute the static-binding notice when the profile version bumped
            # without any static_config_hash change; otherwise fail closed.
            if not has_profile_bump or has_hash_change:
                return False
            continue
        if not any(pattern.match(detail) for pattern in rule.detail_patterns):
            return False
    return True


def attribute_expected_upgrade(
    diff_document: dict[str, Any],
    from_version: str,
    *,
    baseline_tool_version: str | None = None,
) -> dict[str, Any]:
    """Partition ``security_alerts`` into active alerts vs expected tool-upgrade transitions."""
    rule = SUPPORTED_UPGRADE_VERSIONS.get(from_version)
    if rule is None:
        supported = ", ".join(sorted(SUPPORTED_UPGRADE_VERSIONS))
        raise ValueError(
            f"Unsupported --expect-upgrade version {from_version!r}; supported: {supported}"
        )
    if baseline_tool_version is not None and baseline_tool_version != from_version:
        raise ValueError(
            f"--expect-upgrade {from_version!r} does not match baseline tool_version "
            f"{baseline_tool_version!r}"
        )
    raw_alerts = diff_document.get("security_alerts")
    if not isinstance(raw_alerts, list):
        return {
            **diff_document,
            "expected_upgrade_from": from_version,
            "tool_upgrade_changes": [],
        }

    modified_by_ref: dict[str, list[str]] = {}
    for mod in diff_document.get("components_modified") or []:
        if isinstance(mod, dict) and isinstance(mod.get("bom_ref"), str):
            raw_details = mod.get("details")
            if isinstance(raw_details, list):
                modified_by_ref[mod["bom_ref"]] = [str(item) for item in raw_details]

    kept: list[dict[str, Any]] = []
    attributed: list[dict[str, Any]] = []
    for entry in raw_alerts:
        if not isinstance(entry, dict):
            continue
        comp_ref = str(entry.get("component", ""))
        alert_text = str(entry.get("alert") or entry.get("message") or "")
        is_expected = False
        if comp_ref == "metadata" and _METADATA_UPGRADE_RE.search(alert_text):
            is_expected = True
        elif comp_ref in modified_by_ref and (
            alert_text.startswith(("Medium change in ", "High change in ", "Critical change in "))
        ):
            is_expected = _all_details_expected(modified_by_ref[comp_ref], rule)
        if is_expected:
            attributed.append({**entry, "attributed_to_upgrade": from_version})
        else:
            kept.append(entry)
    return {
        **diff_document,
        "security_alerts": kept,
        "expected_upgrade_from": from_version,
        "tool_upgrade_changes": attributed,
    }
