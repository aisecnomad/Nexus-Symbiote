"""Import untrusted Nexus-ShadowScan reports as *declared* discovery evidence.

No live collection, artifact execution, identity verification, or security
attestation occurs here. Report bytes remain a separate sensitive artifact.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.core.models import (
    AgentComponent,
    AIBOMMetadata,
    AnyComponent,
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.utils.confined import ConfinedCollection

MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 10_000
MAX_DEPENDENCIES = 10_000
PROJECTION_PROFILE = "nexus-symbiote/shadowscan-projection/v2"
_ALLOWED_SURFACES = frozenset(
    {"code", "identity", "gateway", "lowcode", "saas", "cloud", "endpoint", "network", "runtime"}
)


@dataclass
class ImportedReport:
    components: list[AnyComponent] = field(default_factory=list)
    dependencies: list[DependencyEdge] = field(default_factory=list)
    digest: str = ""
    source_format: str = ""
    source_status: str = "unknown"
    unmapped_count: int = 0
    unmapped_indexes: list[int] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_native_bom(self) -> AIBOM:
        """Reproduce a direct native import without promoting source assertions."""
        aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
        for component in self.components:
            aibom.add_component(component)
        for dependency in self.dependencies:
            aibom.add_dependency(dependency)
        aibom.metadata.completeness = CompletenessClaim(
            scope="shadowscan-imported",
            surfaces_scanned=["shadowscan:report"],
            surfaces_excluded=self.limitations,
            scan_failures=(
                []
                if self.source_status == "complete"
                else ["ShadowScan source report is incomplete or has unknown status"]
            ),
            scanner_status={"shadowscan": "partial"},
            source_report_digest=self.digest,
            source_report_format=self.source_format,
            source_report_status=self.source_status,
            source_unmapped_count=self.unmapped_count,
            source_unmapped_indexes=self.unmapped_indexes,
            assurance_level=AssuranceLevel.DECLARED,
            collectors_requested=["shadowscan"],
            collectors_completed=["shadowscan"],
            unobserved_surfaces=["runtime", "effective-identity", "effective-authorization"],
        )
        return aibom


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _incomplete_reasons(record: dict[str, Any]) -> dict[str, int]:
    reasons = record.get("incomplete_reasons", {})
    if not isinstance(reasons, dict) or any(
        type(count) is not int or count < 1 for count in reasons.values()
    ):
        raise ValueError("invalid ShadowScan incomplete reason counts")
    return reasons


def _risks(level: Any, shadow: Any) -> list[RiskAssessment]:
    findings: list[RiskAssessment] = []
    levels = {x.value: x for x in RiskSeverity}
    if isinstance(level, str) and level in levels:
        findings.append(
            RiskAssessment(
                severity=levels[level],
                category="shadowscan-heuristic",
                detail=f"ShadowScan heuristic risk: {level}; not an independently verified vulnerability.",
                recommendation="Review the original source evidence and verify under policy.",
            )
        )
    if shadow is True:
        findings.append(
            RiskAssessment(
                severity=RiskSeverity.INFO,
                category="shadowscan-inventory-unmatched",
                detail="ShadowScan reports no matching entry in its supplied inventory; authorization is not established.",
                recommendation="Verify inventory scope and reconcile the source finding.",
            )
        )
    return findings


def _make_component(
    kind: str,
    source_id: str,
    index: int,
    digest: str,
    surface: str | None,
    level: Any,
    shadow: Any,
    *,
    cdx_model: bool = False,
    cdx_mcp: bool = False,
    resource_type: Any = None,
) -> AnyComponent | None:
    # ShadowScan's endpoint connector emits an MCP tool as kind=mcp-server
    # and resource_type=mcp-tool. The latter is an observation type, not
    # proof that the tool is itself a server or linked to a particular server.
    # Conflicting claims are not projected as either kind.
    if resource_type == "mcp-tool" and (kind != "mcp-server" or cdx_model):
        return None
    is_mcp_tool = kind == "mcp-server" and resource_type == "mcp-tool"
    identity_hash = _short_hash(source_id)
    ref = "shadowscan:" + identity_hash
    props: dict[str, Any] = {
        "shadowscan:report-sha256": digest,
        "shadowscan:finding-index": index,
        "shadowscan:source-id-sha256": identity_hash,
        "collection_mode": "imported-unverified-report",
        "shadowscan:projection-profile": PROJECTION_PROFILE,
    }
    if surface in _ALLOWED_SURFACES:
        props["shadowscan:surface"] = surface
    if kind in {"agent", "mcp-server", "local-model", "model"}:
        props["shadowscan:kind"] = kind
    if isinstance(shadow, bool):
        props["shadowscan:inventory-unmatched"] = shadow
    risks = _risks(level, shadow)
    safe_kind = (
        "mcp-tool"
        if is_mcp_tool
        else kind
        if kind in {"agent", "mcp-server", "local-model", "model"}
        else "component"
    )
    common: dict[str, Any] = {
        "bom_ref": ref,
        "name": "ShadowScan " + safe_kind + " " + identity_hash[:12],
        "trust_tier": TrustTier.UNKNOWN,
        "assurance_level": AssuranceLevel.DECLARED,
        "properties": props,
        "risks": risks,
    }
    if is_mcp_tool:
        props["shadowscan:resource-type"] = "mcp-tool"
        return ToolComponent(**common)
    if kind == "mcp-server" or cdx_mcp:
        return MCPServerComponent(**common)
    if kind in {"local-model", "model"} or cdx_model:
        return ModelComponent(**common)
    if kind == "agent":
        return AgentComponent(autonomy_level=None, **common)
    return None


class ShadowScanImporter(Scanner):
    """Import supported ShadowScan JSON and CycloneDX observations conservatively."""

    name = "shadowscan"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(
            project_root,
            result,
            max_file_bytes=MAX_REPORT_BYTES,
            max_total_bytes=MAX_REPORT_BYTES,
        ) as files:
            for relative in (
                ".shadowscan/report.json",
                "shadowscan-report.json",
                "shadowscan.json",
            ):
                raw = files.read_bytes(relative, missing_ok=True)
                if raw is None:
                    continue
                try:
                    imported = self._import_bytes(raw)
                except (ValueError, TypeError, UnicodeError, RecursionError):
                    result.scan_failures.append("ShadowScan report could not be safely imported")
                    break
                result.components.extend(imported.components)
                result.dependencies.extend(imported.dependencies)
                result.source_report_digest = imported.digest
                result.source_report_format = imported.source_format
                result.source_report_status = imported.source_status
                result.source_unmapped_count = imported.unmapped_count
                result.source_unmapped_indexes = imported.unmapped_indexes
                result.surfaces_scanned.append("shadowscan:report")
                result.source_projection_limitations = list(imported.limitations)
                if imported.unmapped_count:
                    result.surfaces_excluded.append("ShadowScan report contains unmapped entries")
                if imported.source_format == "shadowscan-cyclonedx":
                    result.surfaces_excluded.append(
                        "ShadowScan CycloneDX source is a lossy projection"
                    )
                if imported.source_status != "complete":
                    result.scan_failures.append(
                        "ShadowScan source report is incomplete or has unknown status"
                    )
                break
        if (
            not result.source_report_digest
            and not result.scan_failures
            and not result.surfaces_excluded
        ):
            result.surfaces_scanned.append("shadowscan-report (no report found)")
        return result

    def import_report(self, report_path: Path) -> ImportedReport:
        """Import components together with mandatory coverage and provenance."""
        return self.read_report(report_path)

    def read_report(self, report_path: Path) -> ImportedReport:
        failures: list[str] = []
        with ConfinedCollection(
            report_path.parent,
            failures,
            max_file_bytes=MAX_REPORT_BYTES,
            max_total_bytes=MAX_REPORT_BYTES,
        ) as files:
            raw = files.read_bytes(report_path.name)
        if raw is None or failures:
            raise ValueError("ShadowScan report unavailable or outside safe read limits")
        return self._import_bytes(raw)

    def parse_report(self, text: str | bytes) -> ImportedReport:
        """Parse the exact bounded bytes used for digest and signature verification."""
        return self._import_bytes(text.encode("utf-8") if isinstance(text, str) else text)

    def _import_bytes(self, raw: bytes) -> ImportedReport:
        data = parse_json_strict(raw, max_bytes=MAX_REPORT_BYTES)
        if not isinstance(data, dict):
            raise ValueError("expected a ShadowScan report object")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if data.get("bomFormat") == "CycloneDX":
            result = self._from_cyclonedx(data, digest)
        else:
            result = self._from_native(data, digest)
        # Discovery is not a verified, complete BOM even when source scan is complete.
        result.limitations.append(
            "ShadowScan discovery is a source claim; artifact integrity and full BOM coverage are unverified"
        )
        result.limitations.append(
            "Names, detailed evidence, and unmapped relationships remain in the source report"
        )
        if result.unmapped_count:
            result.limitations.append(
                f"{result.unmapped_count} source entries were not mapped into BOM components"
            )
        return result

    @staticmethod
    def _native_complete(
        data: dict[str, Any], findings: list[Any], stats: list[Any], summary: dict[str, Any]
    ) -> bool:
        # The producer's summary describes the final, filtered findings. Connector
        # statistics can legitimately count observations before merging/filtering.
        if "total" in summary or "finding_identity_schema" in data:
            total = summary.get("total")
            if type(total) is not int or total != len(findings):
                raise ValueError("ShadowScan summary total disagrees with findings")
        complete = summary.get("complete") is True and bool(stats)
        if "status" in summary and summary["status"] != "complete":
            complete = False
        error_count = 0
        reason_counts: Counter[str] = Counter()
        for stat in stats:
            if (
                not isinstance(stat, dict)
                or not isinstance(stat.get("errors"), list)
                or not isinstance(stat.get("skipped"), bool)
                or not isinstance(stat.get("incomplete"), bool)
            ):
                raise ValueError("invalid ShadowScan connector statistics")
            error_count += len(stat["errors"])
            reason_counts.update(_incomplete_reasons(stat))
            if stat["errors"] or stat["skipped"] or stat["incomplete"]:
                complete = False
            omissions = stat.get("declared_omissions", 0)
            if not isinstance(omissions, int) or isinstance(omissions, bool) or omissions != 0:
                complete = False
        if "errors" in summary and (
            type(summary["errors"]) is not int or summary["errors"] != error_count
        ):
            raise ValueError("ShadowScan summary error count disagrees with connector statistics")
        if "incomplete_reasons" in summary and _incomplete_reasons(summary) != dict(reason_counts):
            raise ValueError(
                "ShadowScan summary incomplete reasons disagree with connector statistics"
            )
        for key in ("declared_omissions", "tolerated_gaps"):
            value = summary.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value != 0:
                complete = False
        return complete and not reason_counts

    @staticmethod
    def _project_native_findings(findings: list[Any], result: ImportedReport) -> None:
        ids: set[str] = set()
        for index, finding in enumerate(findings):
            if (
                not isinstance(finding, dict)
                or not isinstance(finding.get("id"), str)
                or not finding["id"]
                or len(finding["id"]) > 4096
            ):
                raise ValueError("invalid ShadowScan finding or identifier")
            source_id = finding["id"]
            if source_id in ids:
                raise ValueError("duplicate ShadowScan finding identifier")
            ids.add(source_id)
            kind, surface = finding.get("kind"), finding.get("surface")
            if not isinstance(kind, str) or not isinstance(surface, str):
                raise ValueError("invalid ShadowScan finding kind or surface")
            risk = finding.get("risk")
            level = risk.get("level") if isinstance(risk, dict) else None
            comp = _make_component(
                kind,
                source_id,
                index,
                result.digest,
                surface,
                level,
                finding.get("shadow"),
                resource_type=finding.get("resource_type"),
            )
            if comp is None:
                result.unmapped_count += 1
                result.unmapped_indexes.append(index)
            else:
                result.components.append(comp)

    @staticmethod
    def _check_native_breakdowns(summary: dict[str, Any], findings: list[Any]) -> None:
        for key, field_name in (("by_surface", "surface"), ("by_kind", "kind")):
            if key not in summary:
                continue
            counts = summary[key]
            if (
                not isinstance(counts, dict)
                or any(type(count) is not int for count in counts.values())
                or counts != dict(Counter(finding[field_name] for finding in findings))
            ):
                raise ValueError(f"ShadowScan summary {key} disagrees with findings")

    def _from_native(self, data: dict[str, Any], digest: str) -> ImportedReport:
        findings, stats, summary = data.get("findings"), data.get("stats"), data.get("summary")
        if (
            not isinstance(data.get("version"), str)
            or not isinstance(findings, list)
            or len(findings) > MAX_FINDINGS
        ):
            raise ValueError("invalid ShadowScan report envelope")
        if not isinstance(stats, list) or not isinstance(summary, dict):
            raise ValueError("ShadowScan report must include stats and summary")
        complete = self._native_complete(data, findings, stats, summary)
        result = ImportedReport(
            digest=digest,
            source_format="shadowscan-json",
            source_status="complete" if complete else "incomplete",
        )
        self._project_native_findings(findings, result)
        self._check_native_breakdowns(summary, findings)
        return result

    @staticmethod
    def _project_cyclonedx_dependencies(
        data: dict[str, Any], result: ImportedReport, mapped_refs: dict[str, str]
    ) -> None:
        """Retain bounded, source-reported edges without resolving external identities."""
        dependencies = data.get("dependencies", [])
        if not isinstance(dependencies, list) or len(dependencies) > MAX_DEPENDENCIES:
            raise ValueError("invalid or oversized CycloneDX dependency list")
        seen_sources: set[str] = set()
        total = 0
        omitted = 0
        for index, entry in enumerate(dependencies):
            if not isinstance(entry, dict):
                raise ValueError("invalid CycloneDX dependency")
            source, targets = entry.get("ref"), entry.get("dependsOn", [])
            if (
                not isinstance(source, str)
                or not source
                or len(source) > 4096
                or source in seen_sources
                or not isinstance(targets, list)
            ):
                raise ValueError("invalid or duplicate CycloneDX dependency source")
            seen_sources.add(source)
            total += len(targets)
            if total > MAX_DEPENDENCIES:
                raise ValueError("too many CycloneDX dependency edges")
            seen_targets: set[str] = set()
            for target in targets:
                if (
                    not isinstance(target, str)
                    or not target
                    or len(target) > 4096
                    or target in seen_targets
                ):
                    raise ValueError("invalid or duplicate CycloneDX dependency target")
                seen_targets.add(target)
                if source not in mapped_refs or target not in mapped_refs:
                    omitted += 1
                    continue
                result.dependencies.append(
                    DependencyEdge(
                        source_ref=mapped_refs[source],
                        target_ref=mapped_refs[target],
                        relationship="depends-on",
                        assurance_level="declared",
                        conditions=(
                            f"Source-reported CycloneDX dependency; report {result.digest}; "
                            f"dependencies index {index}; not independently verified"
                        ),
                    )
                )
        if omitted:
            result.limitations.append(
                f"{omitted} source dependency edges have unmapped endpoints and were not projected"
            )

    def _from_cyclonedx(self, data: dict[str, Any], digest: str) -> ImportedReport:
        meta = data.get("metadata")
        if data.get("specVersion") not in ("1.6", "1.7") or not isinstance(meta, dict):
            raise ValueError("unsupported ShadowScan CycloneDX envelope")
        props = _properties(meta.get("properties", []))
        status = props.get("shadowscan:scan:status")
        if status not in ("complete", "incomplete"):
            raise ValueError("CycloneDX document lacks ShadowScan scan status")
        result = ImportedReport(
            digest=digest, source_format="shadowscan-cyclonedx", source_status=status
        )
        compositions = data.get("compositions")
        if not isinstance(compositions, list) or not compositions:
            result.limitations.append("CycloneDX composition completeness is not reported")
        elif any(
            not isinstance(c, dict) or c.get("aggregate") not in {"unknown", "complete"}
            for c in compositions
        ):
            result.limitations.append("CycloneDX source declares incomplete composition")
        for key in (
            "shadowscan:bom:truncated-findings",
            "shadowscan:scan:credential-findings-excluded",
        ):
            if props.get(key) not in (None, "0"):
                result.limitations.append("CycloneDX source omits or truncates findings")
        # CycloneDX is a lossy projection of discovery; it cannot prove full report coverage.
        result.limitations.append(
            "CycloneDX source omits or summarizes discovery evidence and relationships"
        )
        ids: set[str] = set()
        mapped_refs: dict[str, str] = {}
        entries = []
        for key in ("components", "services"):
            items = data.get(key, [])
            if not isinstance(items, list):
                raise ValueError("invalid CycloneDX component list")
            entries.extend(items)
        if len(entries) > MAX_FINDINGS:
            raise ValueError("too many CycloneDX entries")
        for index, entry in enumerate(entries):
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("bom-ref"), str)
                or not entry["bom-ref"]
                or len(entry["bom-ref"]) > 4096
            ):
                raise ValueError("invalid CycloneDX entry")
            ref = entry["bom-ref"]
            if ref in ids:
                raise ValueError("duplicate CycloneDX bom-ref")
            ids.add(ref)
            p = _properties(entry.get("properties", []))
            kind = p.get("shadowscan:kind", "")
            shadow = {"true": True, "false": False}.get(p.get("shadowscan:shadow", ""))
            comp = _make_component(
                kind,
                ref,
                index,
                digest,
                p.get("shadowscan:surface"),
                p.get("shadowscan:heuristic-risk"),
                shadow,
                cdx_model=entry.get("type") == "machine-learning-model",
                cdx_mcp=entry.get("group") == "mcp-server",
                resource_type=p.get("shadowscan:resource-type"),
            )
            if comp is None:
                result.unmapped_count += 1
                result.unmapped_indexes.append(index)
            else:
                result.components.append(comp)
                mapped_refs[ref] = comp.bom_ref
        self._project_cyclonedx_dependencies(data, result, mapped_refs)
        return result


def _properties(value: Any) -> dict[str, str]:
    if not isinstance(value, list):
        raise ValueError("invalid CycloneDX properties")
    result: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("value"), str)
        ):
            raise ValueError("invalid CycloneDX property")
        name = item["name"]
        if name.startswith("shadowscan:"):
            if name in result:
                raise ValueError("duplicate ShadowScan property")
            result[name] = item["value"]
    return result
