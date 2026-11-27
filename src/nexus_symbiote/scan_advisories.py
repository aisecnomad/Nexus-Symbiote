"""Offline advisory matching inside ``scan``: known vulnerabilities as package findings.

The match runs the same bounded offline OSV matcher as ``advisories --offline-db`` and
records each hit on the package it affects: a ``known_vulnerability`` finding with the
advisory identifier, its aliases and the matcher's severity, and a structured entry under
``properties.advisories`` that the CycloneDX export projects as ``vulnerabilities``. Every
run also records a surface line with the bundle's digest and how many exact pins it checked,
so a clean inventory states what it was checked against. The bundle has to lie outside the
scanned checkout, so that a repository cannot supply the advisory data it is checked
against. Nothing leaves the machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment

ADVISORY_CATEGORY = "known_vulnerability"
ADVISORY_PROPERTY = "advisories"
UNKNOWN_SEVERITY_NOTE = "Severity is not stated in the advisory data; recorded as medium."
UNDECIDABLE_RANGE_NOTE = "The affected version range could not be decided; matched conservatively."
_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
_FINDING_SEVERITY = {
    "critical": RiskSeverity.CRITICAL,
    "high": RiskSeverity.HIGH,
    "medium": RiskSeverity.MEDIUM,
    "low": RiskSeverity.LOW,
}
_KEPT_FIELDS = (
    "summary",
    "fixed_versions",
    "matched_ids",
    "range_undecidable",
    "undecidable_bounds",
    "in_kev",
    "epss_score",
    "db_sha256",
)
_MAX_ALIASES = 16
_MAX_ERRORS = 16


@dataclass
class AdvisoryAttachment:
    """What ``scan`` records after a match: collection failures and the surface line."""

    failures: list[str] = field(default_factory=list)
    surface: str | None = None


def _matcher_severity(value: object) -> str:
    text = value.strip().lower() if isinstance(value, str) else ""
    if text == "moderate":
        text = "medium"
    return text if text in _RANK else "unknown"


def _finding_severity(matcher_severity: str) -> RiskSeverity:
    return _FINDING_SEVERITY.get(matcher_severity, RiskSeverity.MEDIUM)


def _entry(advisory: dict[str, Any]) -> dict[str, Any]:
    aliases = advisory.get("aliases")
    matcher_severity = _matcher_severity(advisory.get("severity"))
    kept: dict[str, Any] = {
        "id": str(advisory.get("id", "")),
        "aliases": sorted(str(a) for a in aliases)[:_MAX_ALIASES]
        if isinstance(aliases, list)
        else [],
        "matcher_severity": matcher_severity,
        "severity": _finding_severity(matcher_severity).value,
        "package": str(advisory.get("package", "")),
        "version": str(advisory.get("version", "")),
        "ecosystem": str(advisory.get("ecosystem", "")),
        "source": "osv-offline",
    }
    for key in _KEPT_FIELDS:
        value = advisory.get(key)
        if value not in (None, "", [], False):
            kept[key] = value
    return kept


def _surface(name: str, digest: str, checked: int, recorded: int, excluded: int) -> str:
    if checked == 0:
        coverage = f"no exact PyPI/npm pins to check, {excluded} excluded"
    else:
        coverage = (
            f"{checked} exact PyPI/npm pins checked, {recorded} advisories recorded, "
            f"{excluded} excluded"
        )
    return f"advisories: offline OSV bundle {name} sha256:{digest} ({coverage})"


def attach_offline_advisories(aibom: AIBOM, db_path: Path, root: Path) -> AdvisoryAttachment:
    """Match the inventory against ``db_path``; record hits, failures and the surface line."""
    from nexus_symbiote.offline_advisories import (
        DEFAULT_MAX_FEED_AGE_DAYS,
        match_offline_advisories,
    )

    resolved = db_path.resolve()
    if resolved == root.resolve() or resolved.is_relative_to(root.resolve()):
        return AdvisoryAttachment(
            ["advisories: --advisory-db must lie outside the scanned project"]
        )
    try:
        report, provenance = match_offline_advisories(
            aibom,
            db_path=db_path,
            now=datetime.now(UTC),
            max_feed_age_days=DEFAULT_MAX_FEED_AGE_DAYS,
        )
    except (OSError, ValueError) as exc:
        return AdvisoryAttachment([f"advisories: offline bundle unusable: {exc}"])
    failures = [f"advisories: {error}" for error in report.errors[:_MAX_ERRORS]]
    by_ref = {component.bom_ref: component for component in aibom.components}
    recorded_count = 0
    for advisory in report.advisories:
        component = by_ref.get(str(advisory.get("bom_ref") or advisory.get("component_ref")))
        risks = getattr(component, "risks", None)
        if component is None or not isinstance(risks, list):
            continue
        entry = _entry(advisory)
        recorded = component.properties.setdefault(ADVISORY_PROPERTY, [])
        if not isinstance(recorded, list):
            failures.append(f"advisories: {component.bom_ref}: properties.advisories is not a list")
            continue
        if any(isinstance(known, dict) and known.get("id") == entry["id"] for known in recorded):
            continue
        recorded.append(entry)
        recorded_count += 1
        names = ", ".join([entry["id"], *entry["aliases"]])
        notes: list[str] = []
        if isinstance(entry.get("summary"), str):
            notes.append(entry["summary"])
        if entry["matcher_severity"] == "unknown":
            notes.append(UNKNOWN_SEVERITY_NOTE)
        if entry.get("range_undecidable"):
            notes.append(UNDECIDABLE_RANGE_NOTE)
        detail = f"{names} affects {entry['package']}@{entry['version']} ({entry['ecosystem']})."
        risks.append(
            RiskAssessment(
                severity=_finding_severity(entry["matcher_severity"]),
                category=ADVISORY_CATEGORY,
                detail=" ".join([detail, *notes])[:1000],
                recommendation="Upgrade to a fixed release or record a VEX decision.",
                references=[f"https://osv.dev/vulnerability/{entry['id']}"],
            )
        )
    surface = _surface(
        db_path.name,
        str(provenance.get("db_sha256", "")),
        report.components_checked,
        recorded_count,
        report.components_excluded,
    )
    return AdvisoryAttachment(failures, surface)


def cyclonedx_vulnerabilities(aibom: AIBOM) -> list[dict[str, Any]]:
    """CycloneDX ``vulnerabilities``: one entry per advisory id across every affected package.

    The rating is the highest severity any affected package recorded, ``unknown`` when none
    states one; the aliases are the union; the description is the first summary.
    """
    hits: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for component in sorted(aibom.components, key=lambda c: c.bom_ref):
        entries = component.properties.get(ADVISORY_PROPERTY)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            identifier = entry.get("id") if isinstance(entry, dict) else None
            if isinstance(identifier, str) and identifier:
                hits.setdefault(identifier, []).append((component.bom_ref, entry))
    records: list[dict[str, Any]] = []
    for identifier in sorted(hits):
        affected = hits[identifier]
        rating = max(
            (_matcher_severity(e.get("matcher_severity", e.get("severity"))) for _, e in affected),
            key=_RANK.__getitem__,
        )
        aliases = sorted(
            {a for _, e in affected for a in e.get("aliases", []) if isinstance(a, str)}
        )[:_MAX_ALIASES]
        record: dict[str, Any] = {
            "bom-ref": f"vulnerability:{identifier}",
            "id": identifier,
            "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{identifier}"},
            "ratings": [{"severity": rating}],
            "affects": [{"ref": ref} for ref in sorted({ref for ref, _ in affected})],
        }
        if aliases:
            record["references"] = [{"id": alias, "source": {"name": "OSV"}} for alias in aliases]
        summary = next(
            (
                e["summary"]
                for _, e in affected
                if isinstance(e.get("summary"), str) and e["summary"]
            ),
            None,
        )
        if summary is not None:
            record["description"] = summary[:1000]
        records.append(record)
    return records
