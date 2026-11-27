"""Offline advisory matching inside ``scan``: known vulnerabilities as package findings.

The match runs the same bounded offline OSV matcher as ``advisories --offline-db`` and
records each hit on the package it affects: a ``known_vulnerability`` finding with the
advisory identifier, its aliases and the matcher's severity, and a structured entry under
``properties.advisories`` that the CycloneDX export projects as ``vulnerabilities``. The
bundle has to lie outside the scanned checkout, so that a repository cannot supply the
advisory data it is checked against. Nothing leaves the machine.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment

ADVISORY_CATEGORY = "known_vulnerability"
ADVISORY_PROPERTY = "advisories"
_SEVERITIES = {level.value for level in RiskSeverity}
_MAX_ALIASES = 8


def _severity(value: object) -> RiskSeverity:
    text = str(value).lower() if isinstance(value, str) else ""
    return RiskSeverity(text) if text in _SEVERITIES else RiskSeverity.MEDIUM


def _entry(advisory: dict[str, Any]) -> dict[str, Any]:
    aliases = advisory.get("aliases")
    kept: dict[str, Any] = {
        "id": str(advisory.get("id", "")),
        "aliases": sorted(str(a) for a in aliases)[:_MAX_ALIASES]
        if isinstance(aliases, list)
        else [],
        "severity": _severity(advisory.get("severity")).value,
        "package": str(advisory.get("package", "")),
        "version": str(advisory.get("version", "")),
        "ecosystem": str(advisory.get("ecosystem", "")),
        "source": "osv-offline",
    }
    for key in ("summary", "fixed_versions", "in_kev", "epss_score", "db_sha256"):
        value = advisory.get(key)
        if value not in (None, "", [], False):
            kept[key] = value
    return kept


def attach_offline_advisories(aibom: AIBOM, db_path: Path, root: Path) -> list[str]:
    """Match the inventory against ``db_path`` and record hits; returns collection failures."""
    from nexus_symbiote.offline_advisories import (
        DEFAULT_MAX_FEED_AGE_DAYS,
        match_offline_advisories,
    )

    resolved = db_path.resolve()
    if resolved == root.resolve() or resolved.is_relative_to(root.resolve()):
        return ["advisories: --advisory-db must lie outside the scanned project"]
    try:
        report, _provenance = match_offline_advisories(
            aibom,
            db_path=db_path,
            now=datetime.now(UTC),
            max_feed_age_days=DEFAULT_MAX_FEED_AGE_DAYS,
        )
    except (OSError, ValueError) as exc:
        return [f"advisories: offline bundle unusable: {exc}"]
    failures = [f"advisories: {error}" for error in report.errors[:16]]
    by_ref = {component.bom_ref: component for component in aibom.components}
    for advisory in report.advisories:
        component = by_ref.get(str(advisory.get("bom_ref") or advisory.get("component_ref")))
        risks = getattr(component, "risks", None)
        if component is None or not isinstance(risks, list):
            continue
        entry = _entry(advisory)
        recorded: list[dict[str, Any]] = component.properties.setdefault(ADVISORY_PROPERTY, [])
        if any(existing.get("id") == entry["id"] for existing in recorded):
            continue
        recorded.append(entry)
        names = ", ".join([entry["id"], *entry["aliases"]])
        summary = f" {entry['summary']}" if "summary" in entry else ""
        risks.append(
            RiskAssessment(
                severity=_severity(entry["severity"]),
                category=ADVISORY_CATEGORY,
                detail=(
                    f"{names} affects {entry['package']}@{entry['version']} "
                    f"({entry['ecosystem']}).{summary}"
                )[:1000],
                recommendation="Upgrade to a fixed release or record a VEX decision.",
                references=[f"https://osv.dev/vulnerability/{entry['id']}"],
            )
        )
    if report.components_checked and not report.advisories and not report.errors:
        return []
    return failures


def cyclonedx_vulnerabilities(aibom: AIBOM) -> list[dict[str, Any]]:
    """CycloneDX ``vulnerabilities`` entries for every recorded advisory, one per identifier."""
    merged: dict[str, dict[str, Any]] = {}
    for component in sorted(aibom.components, key=lambda c: c.bom_ref):
        entries = component.properties.get(ADVISORY_PROPERTY)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                continue
            record = merged.setdefault(
                entry["id"],
                {
                    "bom-ref": f"vulnerability:{entry['id']}",
                    "id": entry["id"],
                    "source": {
                        "name": "OSV",
                        "url": f"https://osv.dev/vulnerability/{entry['id']}",
                    },
                    "references": [
                        {"id": alias, "source": {"name": "OSV"}}
                        for alias in entry.get("aliases", [])
                        if isinstance(alias, str)
                    ],
                    "ratings": [{"severity": _severity(entry.get("severity")).value}],
                    "affects": [],
                },
            )
            if isinstance(entry.get("summary"), str) and "description" not in record:
                record["description"] = entry["summary"][:1000]
            if component.bom_ref not in {a["ref"] for a in record["affects"]}:
                record["affects"].append({"ref": component.bom_ref})
            if not record["references"]:
                del record["references"]
    return [merged[key] for key in sorted(merged)]
