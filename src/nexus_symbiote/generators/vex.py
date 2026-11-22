"""CycloneDX 1.7 findings in triage, retaining declared model-revision evidence.

The document has its own identity: a serial number derived from the inventory's,
the inventory's version, the inventory's timestamp when it records one, and the
producing tool. It names the inventory it describes with a BOM-Link external
reference, and its components carry the same types, versions, package URLs and
digests as the CycloneDX inventory export.

An applicable, unexpired operator decision can change the default ``in_triage`` state.
Trace outcomes are observations only. ``NEXUS-`` identifiers match no public database.
"""

from __future__ import annotations

import math
import re
import uuid
from datetime import datetime
from typing import Any

from nexus_symbiote.core.aibom import AIBOM, prepare
from nexus_symbiote.core.canonical import NAMESPACE, content_digest
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.generators._common import (
    OMITTED_IMPORTED_FINDINGS,
    imported_discovery_component,
)
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.cyclonedx import standard_component
from nexus_symbiote.generators.sarif import SEVERITY_ORDER, plain_text
from nexus_symbiote.generators.validation import require_valid
from nexus_symbiote.vex_decisions import (
    ExecutionEvidence,
    LoadedAdvisoryReport,
    LoadedVEXDecisions,
    resolve_reference_time,
)

_UNVERIFIED = "Inventory risk finding; exploitability and deployment impact are unverified."
_SERIAL = re.compile(
    r"urn:uuid:([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)
_CDX_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "none", "unknown"})
_SUPPRESSING_STATES = frozenset({"not_affected", "resolved", "false_positive"})


def _joined(values: list[Any], field: str) -> str:
    """Comma-join identifiers, refusing one that holds the delimiter and would read as two."""
    items = [value for value in values if isinstance(value, str)]
    if any("," in item for item in items):
        raise ValueError(f"Advisory {field} entries must not contain ','")
    return ",".join(items)


def finding_id(component_ref: str, category: str, detail: str) -> str:
    """Stable per component, category and finding text: ``NEXUS-`` and the SARIF fingerprint."""
    digest = content_digest(
        {"rule": f"nexus_symbiote/{category}", "component": component_ref, "detail": detail}
    )
    return "NEXUS-" + digest.split(":", 1)[1]


def _resolve_analysis(
    *,
    vuln_id: str,
    component_ref: str,
    default_detail: str,
    timestamp: str | None,
    decisions: LoadedVEXDecisions | None,
    execution_evidence: ExecutionEvidence | None,
    ref_time: datetime | None,
    props: dict[str, str],
    expired_warnings: list[str],
    inventory_sha256: str | None,
    deployment_id: str | None,
    advisory_complete: bool = True,
) -> dict[str, Any]:
    analysis: dict[str, Any] = {"state": "in_triage", "detail": default_detail}
    decision = decisions.lookup(vuln_id, component_ref) if decisions is not None else None
    if decision is not None:
        owner = plain_text(decision.owner)
        if (
            decision.expires_at is not None
            and ref_time is not None
            and decision.expires_at <= ref_time
        ):
            warning = (
                f"Expired operator VEX decision for {vuln_id} "
                f"(owner={owner}, expired_at={decision.expires_at.isoformat()}); "
                "reverted to in_triage."
            )
            expired_warnings.append(warning)
            analysis["detail"] = f"{warning} {default_detail}"
            props["nexus-symbiote:vexDecisionStatus"] = "expired-reverted"
            props["nexus-symbiote:vexDecisionOwner"] = owner
            props["nexus-symbiote:vexDecisionExpiredAt"] = decision.expires_at.isoformat()
        elif decision.state in _SUPPRESSING_STATES and (
            not advisory_complete
            or decision.component_ref != component_ref
            or decision.inventory_sha256 is None
            or decision.inventory_sha256 != inventory_sha256
            or decision.deployment_id is None
            or decision.deployment_id != deployment_id
        ):
            analysis["detail"] = (
                f"Operator decision is outside the inventory or deployment scope. {default_detail}"
            )
            props["nexus-symbiote:vexDecisionStatus"] = "scope-mismatch"
        else:
            analysis["state"] = decision.state
            if decision.justification is not None:
                analysis["justification"] = decision.justification
            analysis["detail"] = f"{plain_text(decision.detail)} (owner: {owner})"
            props["nexus-symbiote:vexDecisionStatus"] = "active"
            props["nexus-symbiote:vexDecisionOwner"] = owner
            if decision.expires_at is not None:
                props["nexus-symbiote:vexDecisionExpiresAt"] = decision.expires_at.isoformat()
    elif execution_evidence is not None:
        outcome = execution_evidence.outcome_for(component_ref)
        if outcome is not None:
            props["nexus-symbiote:executionOutcome"] = outcome
        if outcome == "declared-never-loaded":
            analysis["detail"] = (
                "Execution-bound (reported): component was declared but never loaded in "
                f"the observed runtime evidence. {default_detail}"
            )
            props["nexus-symbiote:suppressionBlocked"] = "true"
        elif outcome == "unobserved":
            analysis["detail"] = (
                "Execution-bound (reported): unobserved in runtime trace spans; absence of "
                f"telemetry does not prove unreachability. {default_detail}"
            )
        elif outcome == "invoked":
            analysis["detail"] = (
                "Execution-bound (reported): component was invoked in runtime trace evidence; "
                f"an invocation does not show that the finding is exploitable. {default_detail}"
            )
        elif outcome == "shadowed":
            analysis["detail"] = (
                "Execution-bound (reported): component is shadowed by another tool or server "
                f"definition; manual triage required. {default_detail}"
            )
    if timestamp:
        analysis["lastUpdated"] = timestamp
    return analysis


class VEXGenerator(Generator):
    """Project inventory findings without treating risk heuristics as vulnerabilities."""

    format_name = "vex-cyclonedx-1.7"

    def __init__(
        self,
        *,
        decisions: LoadedVEXDecisions | None = None,
        execution_evidence: ExecutionEvidence | None = None,
        advisories: list[dict[str, Any]] | None = None,
        advisory_report: LoadedAdvisoryReport | None = None,
        reference_time: datetime | None = None,
        inventory_sha256: str | None = None,
        deployment_id: str | None = None,
    ) -> None:
        self._decisions = decisions
        self._execution_evidence = execution_evidence
        if advisory_report is not None and advisories is not None:
            raise ValueError("Supply one advisory source")
        self._advisory_report = advisory_report
        self._advisories = (
            advisory_report.advisories if advisory_report is not None else advisories or []
        )
        self._reference_time = reference_time
        self._inventory_sha256 = inventory_sha256
        self._deployment_id = deployment_id

    def generate(self, bom: AIBOM) -> dict[str, Any]:
        from nexus_symbiote.validators.risk import effective_component_risks

        # The same content-derived serial as the inventory exports, so the BOM-Link
        # names the CycloneDX export of this inventory. prepare() derives the
        # serial from content (timestamps excluded); it is not wall-clock.
        prepare(bom)
        serial = str(bom.metadata.serial_number)
        stamp = bom.metadata.timestamp
        timestamp = stamp.isoformat() if stamp is not None else None
        ref_time = (
            resolve_reference_time(self._reference_time) if self._decisions is not None else None
        )
        decision_subject = self._inventory_sha256
        if (
            decision_subject is None
            and self._decisions is not None
            and self._deployment_id is not None
        ):
            decision_subject = hash_bytes(bom.to_native_json().encode("utf-8"))
        vulnerabilities: list[dict[str, Any]] = []
        components: list[dict[str, Any]] = []
        included_comp_refs: set[str] = set()
        seen: set[str] = set()
        expired_warnings: list[str] = []
        omitted = 0
        comp_by_ref = {comp.bom_ref: comp for comp in bom.components}

        for comp in sorted(bom.components, key=lambda c: c.bom_ref):
            risks = effective_component_risks(comp)
            if imported_discovery_component(comp):
                omitted += len(risks)
                continue
            if not risks:
                continue
            components.append(standard_component(comp))
            included_comp_refs.add(comp.bom_ref)
            for risk in sorted(risks, key=lambda r: (SEVERITY_ORDER[r.severity], r.category)):
                identifier = finding_id(comp.bom_ref, risk.category, risk.detail)
                if identifier in seen:
                    continue
                seen.add(identifier)
                props = {
                    "nexus-symbiote:category": risk.category,
                    "nexus-symbiote:assurance": "declared-inventory-finding",
                }
                if comp.hashes.get("sha256"):
                    props["nexus-symbiote:artifactDigest"] = comp.hashes["sha256"]
                if isinstance(comp, ModelComponent):
                    for key, value in {
                        "weightDigest": comp.hashes.get("sha256"),
                        "tensorMetadataDigest": comp.tensor_inventory_hash,
                        "adaptationEvent": comp.derivation_type,
                        "quantization": comp.quantization_method,
                        "baseModelRef": comp.base_model_ref,
                    }.items():
                        if value:
                            props["nexus-symbiote:" + key] = value
                recommendation = plain_text(risk.recommendation or "")
                default_detail = (
                    f"{_UNVERIFIED} {recommendation}" if recommendation else _UNVERIFIED
                )
                analysis = _resolve_analysis(
                    vuln_id=identifier,
                    component_ref=comp.bom_ref,
                    default_detail=default_detail,
                    timestamp=timestamp,
                    decisions=self._decisions,
                    execution_evidence=self._execution_evidence,
                    ref_time=ref_time,
                    props=props,
                    expired_warnings=expired_warnings,
                    inventory_sha256=decision_subject,
                    deployment_id=self._deployment_id,
                )
                vulnerabilities.append(
                    {
                        "bom-ref": "vulnerability:" + identifier,
                        "id": identifier,
                        "source": {"name": "Nexus SymBiote inventory findings"},
                        "description": plain_text(risk.detail),
                        "ratings": [{"severity": risk.severity.value}],
                        "analysis": analysis,
                        "affects": [{"ref": comp.bom_ref}],
                        "properties": [{"name": k, "value": v} for k, v in sorted(props.items())],
                    }
                )

        def _adv_key(entry: dict[str, Any]) -> tuple[str, str]:
            return (
                str(entry.get("component_ref") or entry.get("bom_ref") or ""),
                str(entry.get("advisory_id") or entry.get("id") or ""),
            )

        for adv in sorted(self._advisories, key=_adv_key):
            adv_id = adv.get("advisory_id") or adv.get("id")
            comp_ref = adv.get("component_ref") or adv.get("bom_ref")
            if not isinstance(adv_id, str) or not adv_id or not isinstance(comp_ref, str):
                continue
            adv_comp = comp_by_ref.get(comp_ref)
            if adv_comp is None or imported_discovery_component(adv_comp):
                continue
            dedup_key = f"{adv_id}::{comp_ref}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            if comp_ref not in included_comp_refs:
                components.append(standard_component(adv_comp))
                included_comp_refs.add(comp_ref)
            raw_sev = str(adv.get("severity", "unknown")).lower()
            sev = raw_sev if raw_sev in _CDX_SEVERITIES else "unknown"
            props = {
                "nexus-symbiote:assurance": (
                    "offline-advisory-match" if adv.get("offline") else "osv-advisory-match"
                ),
            }
            if isinstance(adv.get("aliases"), list) and adv["aliases"]:
                props["nexus-symbiote:aliases"] = _joined(adv["aliases"], "aliases")
            in_kev = adv.get("in_kev")
            if in_kev is None:
                in_kev = False
            elif not isinstance(in_kev, bool):
                # The string "false" is truthy: a coerced flag would invert KEV handling.
                raise ValueError("Advisory in_kev must be a JSON boolean")
            if in_kev:
                props["nexus-symbiote:inKev"] = "true"
                if isinstance(adv.get("kev_sources"), list) and adv["kev_sources"]:
                    props["nexus-symbiote:kevSources"] = _joined(adv["kev_sources"], "kev_sources")
            epss = adv.get("epss_score")
            if epss is not None:
                if isinstance(epss, bool) or not isinstance(epss, (int, float)):
                    raise ValueError("Advisory epss_score must be a JSON number")
                if not math.isfinite(epss):
                    raise ValueError("Advisory epss_score must be finite")
                props["nexus-symbiote:epssScore"] = f"{float(epss):.6f}"
            if adv.get("range_undecidable") is True:
                props["nexus-symbiote:rangeUndecidable"] = "true"
            summary = plain_text(
                str(adv.get("summary") or f"Advisory {adv_id} affecting {adv_comp.name}")
            )
            analysis = _resolve_analysis(
                vuln_id=adv_id,
                component_ref=comp_ref,
                default_detail=f"Advisory match for {adv_comp.name}; deployment impact unverified.",
                timestamp=timestamp,
                decisions=self._decisions,
                execution_evidence=self._execution_evidence,
                ref_time=ref_time,
                props=props,
                expired_warnings=expired_warnings,
                inventory_sha256=decision_subject,
                deployment_id=self._deployment_id,
                advisory_complete=self._advisory_report is None
                or self._advisory_report.coverage == "complete",
            )
            vulnerabilities.append(
                {
                    "bom-ref": f"advisory:{adv_id}:{comp_ref}",
                    "id": adv_id,
                    "source": {
                        "name": "Nexus SymBiote offline advisory match"
                        if adv.get("offline")
                        else "OSV"
                    },
                    "description": summary,
                    "ratings": [{"severity": sev}],
                    "analysis": analysis,
                    "affects": [{"ref": comp_ref}],
                    "properties": [{"name": k, "value": v} for k, v in sorted(props.items())],
                }
            )

        meta_props: list[dict[str, str]] = []
        if self._inventory_sha256:
            meta_props.append(
                {"name": "nexus-symbiote:inventorySha256", "value": self._inventory_sha256}
            )
        if self._deployment_id:
            meta_props.append({"name": "nexus-symbiote:deployment", "value": self._deployment_id})
        if (report := self._advisory_report) is not None:
            for name, report_value in (
                ("ReportSha256", report.sha256),
                ("Coverage", report.coverage),
                ("Checked", report.checked),
                ("Skipped", report.skipped),
                ("Excluded", report.excluded),
                ("Errors", report.errors),
            ):
                meta_props.append(
                    {"name": "nexus-symbiote:advisory" + name, "value": str(report_value)}
                )
        if omitted:
            meta_props.append({"name": OMITTED_IMPORTED_FINDINGS, "value": str(omitted)})
        if self._decisions is not None:
            meta_props.append(
                {"name": "nexus-symbiote:vexDecisionsSha256", "value": self._decisions.sha256}
            )
        if expired_warnings:
            meta_props.append(
                {"name": "nexus-symbiote:expiredVexDecisions", "value": str(len(expired_warnings))}
            )
        if self._execution_evidence is not None:
            evidence = self._execution_evidence
            meta_props.append(
                {
                    "name": "nexus-symbiote:traceAuthentication",
                    "value": "attested" if evidence.attested else "unsigned",
                }
            )
            if evidence.attestation_sha256:
                meta_props.append(
                    {
                        "name": "nexus-symbiote:traceAttestationSha256",
                        "value": evidence.attestation_sha256,
                    }
                )
            meta_props.append(
                {
                    "name": "nexus-symbiote:traceEvidenceSha256",
                    "value": self._execution_evidence.sha256,
                }
            )

        document: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": bom.metadata.version,
            "metadata": {
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": bom.metadata.tool_name,
                            "version": bom.metadata.tool_version or "unknown",
                            "publisher": bom.metadata.tool_vendor,
                        }
                    ]
                },
            },
            "components": components,
            "vulnerabilities": vulnerabilities,
        }
        if timestamp:
            document["metadata"]["timestamp"] = timestamp
        if meta_props:
            document["metadata"]["properties"] = meta_props
        inventory = _SERIAL.fullmatch(serial)
        if inventory is not None:
            document["externalReferences"] = [
                {
                    "type": "bom",
                    "url": f"urn:cdx:{inventory[1].lower()}/{bom.metadata.version}",
                    "comment": "The inventory whose findings this document lists",
                }
            ]
        document["serialNumber"] = "urn:uuid:" + str(
            uuid.uuid5(NAMESPACE, "nexus-symbiote/vex-content/v2:" + content_digest(document))
        )
        require_valid(document, "cyclonedx")
        return document
