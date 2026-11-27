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

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.canonical import json_text
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.core.models import MCPServerComponent, RiskAssessment

ADVISORY_CATEGORY = "known_vulnerability"
ADVISORY_PROPERTY = "advisories"
ADVISORY_SURFACE_PREFIX = "advisories: offline OSV bundle "
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
_ADVISORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}")
_FEED_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# Which registry declarations the inventory holds, widest first.
REGISTRY_PACKAGES = ("all-supported", "ai-catalog", "not-collected")


@dataclass
class AdvisoryAttachment:
    """Collection failures and evidence of what the offline matcher could check."""

    failures: list[str] = field(default_factory=list)
    surface: str | None = None
    unobserved_surface: str | None = None


def _matcher_severity(value: object) -> str:
    text = value.strip().lower() if isinstance(value, str) else ""
    if text == "moderate":
        text = "medium"
    return text if text in _RANK else "unknown"


def _finding_severity(matcher_severity: str) -> RiskSeverity:
    return _FINDING_SEVERITY.get(matcher_severity, RiskSeverity.MEDIUM)


def _aliases(value: object, identifier: str) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {
        alias for alias in value if isinstance(alias, str) and _ADVISORY_ID.fullmatch(alias)
    } - {identifier}


def _entry(advisory: dict[str, Any]) -> dict[str, Any]:
    identifier = str(advisory.get("id", ""))
    matcher_severity = _matcher_severity(advisory.get("severity"))
    kept: dict[str, Any] = {
        "id": identifier,
        "aliases": sorted(_aliases(advisory.get("aliases"), identifier))[:_MAX_ALIASES],
        "matcher_severity": matcher_severity,
        "severity": _finding_severity(matcher_severity).value,
        "package": str(advisory.get("package", "")),
        "version": str(advisory.get("version", "")),
        "ecosystem": str(advisory.get("ecosystem", "")),
        "source": "osv-offline",
    }
    for key in _KEPT_FIELDS:
        value = advisory.get(key)
        if value is not False and value not in (None, "", []):
            kept[key] = value
    return kept


def attach_offline_advisories(
    aibom: AIBOM,
    db_path: Path,
    root: Path,
    *,
    registry_packages: str,
    inventory_path: Path | None = None,
) -> AdvisoryAttachment:
    """Match the inventory against ``db_path``; record hits, failures and the surface line.

    ``registry_packages`` names the registry scope: coverage of a narrower one than every
    supported declaration is at most partial.
    """
    from nexus_symbiote.offline_advisories import (
        DEFAULT_MAX_FEED_AGE_DAYS,
        feed_in_input_repository,
        match_offline_advisories,
    )

    try:
        if db_path.is_symlink():
            return AdvisoryAttachment(["advisories: offline bundle must not be a symbolic link"])
        resolved = db_path.resolve(strict=True)
        if resolved.is_relative_to(root.resolve()):
            return AdvisoryAttachment(
                ["advisories: --advisory-db must lie outside the scanned project"]
            )
        inputs = (root,) if inventory_path is None else (root, inventory_path.resolve().parent)
        if feed_in_input_repository(resolved, *inputs):
            return AdvisoryAttachment(
                [
                    "advisories: --advisory-db must lie outside every git repository enclosing "
                    "the project, inventory or current directory"
                ]
            )
        report, provenance = match_offline_advisories(
            aibom,
            db_path=db_path,
            now=datetime.now(UTC),
            max_feed_age_days=DEFAULT_MAX_FEED_AGE_DAYS,
        )
    except (OSError, RuntimeError):
        return AdvisoryAttachment(["advisories: offline bundle could not be read"])
    except ValueError as exc:
        return AdvisoryAttachment([f"advisories: offline bundle unusable: {exc}"])
    failures = [f"advisories: {error}" for error in report.errors[:_MAX_ERRORS]]
    by_ref = {component.bom_ref: component for component in aibom.components}
    recorded_count = 0
    for advisory in report.advisories:
        component = by_ref.get(str(advisory.get("bom_ref") or advisory.get("component_ref")))
        risks = getattr(component, "risks", None)
        if component is None or not isinstance(risks, list):
            continue
        identifier = advisory.get("id")
        if not isinstance(identifier, str) or not _ADVISORY_ID.fullmatch(identifier):
            if len(failures) < _MAX_ERRORS:
                failures.append("advisories: matched advisory has an invalid identifier")
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
        uncertain = entry.get("range_undecidable") is True
        if uncertain:
            notes.append(UNDECIDABLE_RANGE_NOTE)
        verdict = "may affect" if uncertain else "affects"
        detail = f"{names} {verdict} {entry['package']}@{entry['version']} ({entry['ecosystem']})."
        risks.append(
            RiskAssessment(
                severity=_finding_severity(entry["matcher_severity"]),
                category=ADVISORY_CATEGORY,
                detail=" ".join([detail, *notes])[:1000],
                recommendation="Upgrade to a fixed release or record a VEX decision.",
                references=[f"https://osv.dev/vulnerability/{entry['id']}"],
            )
        )
    # Encode the receipt in the existing completeness claim without a native schema change.
    # Keep the receipt stable across checkouts and bind the contents rather than the path.
    # An MCP launcher package with no exact package URL is a package whose version is unknown.
    unidentified = sum(
        isinstance(component, MCPServerComponent)
        and component.package_url is None
        and (component.launcher_package or "").partition(":")[0] in {"npm", "pypi"}
        for component in aibom.components
    )
    narrowed = bool(failures or unidentified) or registry_packages != REGISTRY_PACKAGES[0]
    coverage = "partial" if report.coverage == "complete" and narrowed else report.coverage
    surface = ADVISORY_SURFACE_PREFIX + json_text(
        {
            "advisories_recorded": recorded_count,
            "components_checked": report.components_checked,
            "components_excluded": report.components_excluded,
            "components_skipped": report.components_skipped,
            "components_unidentified": unidentified,
            "coverage": coverage,
            "scope": "inventoried-pypi-and-npm",
            "registry_packages": registry_packages,
            "registry_lockfile_only_dependencies": "not-collected",
            "db_sha256": provenance["db_sha256"],
            "db_newest_record": provenance["db_newest_record"],
            "records_loaded": provenance["records_loaded"],
        }
    )
    if coverage == "none":
        return AdvisoryAttachment(failures, unobserved_surface=surface)
    return AdvisoryAttachment(failures, surface)


def parse_receipt(surface: str) -> dict[str, Any] | None:
    """The receipt a completeness surface line records, or None for any other line."""
    if not surface.startswith(ADVISORY_SURFACE_PREFIX + "{"):
        return None
    try:
        receipt = parse_json_strict(surface.removeprefix(ADVISORY_SURFACE_PREFIX), max_bytes=2048)
    except (ValueError, RecursionError):
        return None
    if not isinstance(receipt, dict):
        return None
    digest = receipt.get("db_sha256")
    if not isinstance(digest, str) or not _FEED_DIGEST.fullmatch(digest):
        return None
    return receipt


def advisory_receipts(aibom: AIBOM) -> dict[str, str]:
    """Return declared scan receipts and their feed digests for standards projection."""
    claim = aibom.metadata.completeness
    if claim is None:
        return {}
    receipts = {}
    for surface in (*claim.surfaces_scanned, *claim.unobserved_surfaces):
        receipt = parse_receipt(surface)
        if receipt is not None:
            receipts[surface.removeprefix(ADVISORY_SURFACE_PREFIX)] = receipt["db_sha256"]
    return receipts


def cyclonedx_vulnerabilities(aibom: AIBOM) -> list[dict[str, Any]]:
    """CycloneDX ``vulnerabilities``: one entry per advisory id across every affected package.

    The rating is the highest severity any affected package recorded, ``unknown`` when none
    states one; the aliases are the union; the description is the first summary.
    """
    feeds = set(advisory_receipts(aibom).values())
    if not feeds:
        return []
    hits: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    component_refs = {component.bom_ref for component in aibom.components}
    for component in sorted(aibom.components, key=lambda c: c.bom_ref):
        entries = component.properties.get(ADVISORY_PROPERTY)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("source") != "osv-offline":
                continue
            identifier = entry.get("id")
            digest = entry.get("db_sha256")
            if (
                isinstance(identifier, str)
                and _ADVISORY_ID.fullmatch(identifier)
                and isinstance(digest, str)
                and digest in feeds
            ):
                hits.setdefault(identifier, []).append((component.bom_ref, entry))
    records: list[dict[str, Any]] = []
    for identifier in sorted(hits):
        affected = hits[identifier]
        rating = max(
            (_matcher_severity(e.get("matcher_severity", e.get("severity"))) for _, e in affected),
            key=_RANK.__getitem__,
        )
        aliases = sorted(
            {alias for _, entry in affected for alias in _aliases(entry.get("aliases"), identifier)}
        )[:_MAX_ALIASES]
        record: dict[str, Any] = {
            "id": identifier,
            "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{identifier}"},
            "ratings": [{"severity": rating}],
            "affects": [{"ref": ref} for ref in sorted({ref for ref, _ in affected})],
        }
        vulnerability_ref = f"vulnerability:{identifier}"
        if vulnerability_ref not in component_refs:
            record["bom-ref"] = vulnerability_ref
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
