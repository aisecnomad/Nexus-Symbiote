"""Risk scoring engine — aggregates per-component risks into an overall score."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import is_imported
from nexus_symbiote.core.coverage import CoverageStatus, assess_coverage
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.core.models import (
    NAMED_FORMAT_PROPERTY,
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AnyComponent,
    ComponentBase,
    CredentialComponent,
    IDEAgentComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RAGSourceComponent,
    RiskAssessment,
)
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.scanners.prompt import withholds_content_hash

if TYPE_CHECKING:
    from nexus_symbiote.policy import RiskPolicy, Suppression

REQUIRED_SCANNERS = BUILTIN_SCANNER_NAMES
MAX_REPORTED_COVERAGE_GAPS = 50
NO_LOCAL_EVIDENCE = "no agent manifest or supported local inventory evidence was found"

SEVERITY_WEIGHTS: dict[RiskSeverity, float] = {
    RiskSeverity.CRITICAL: 10.0,
    RiskSeverity.HIGH: 7.0,
    RiskSeverity.MEDIUM: 4.0,
    RiskSeverity.LOW: 1.0,
    RiskSeverity.INFO: 0.0,
}


def _declared_safetensors(component: ModelComponent) -> bool:
    """Whether the record gives SafeTensors as the format, or as the format that the file's
    name claims: the model collector records only the claim when no header established it."""
    declared = (component.serialization_format, component.properties.get(NAMED_FORMAT_PROPERTY))
    return any(
        isinstance(name, str) and name.lower() in {"safetensors", "safe-tensors"}
        for name in declared
    )


def _intrinsic_model_risks(component: ModelComponent) -> list[RiskAssessment]:
    """Derive risk from declared security facts even if findings were removed."""
    risks = list(component.risks)
    checks = (
        (
            component.serialization_safety
            in {
                SerializationSafety.UNSAFE_CODE_EXECUTION,
                SerializationSafety.UNSAFE_TEMPLATE_INJECTION,
            },
            RiskSeverity.CRITICAL,
            "serialization_format",
            "The declared model serialization or loader permits unsafe execution.",
        ),
        (
            component.trust_remote_code is True,
            RiskSeverity.CRITICAL,
            "code_execution",
            "The model configuration enables repository code execution.",
        ),
        (
            _declared_safetensors(component)
            and component.serialization_safety == SerializationSafety.UNKNOWN,
            RiskSeverity.HIGH,
            "invalid_safetensors",
            "The declared SafeTensors artifact has no corroborated structural safety.",
        ),
    )
    for applies, severity, category, detail in checks:
        if applies and not any(r.category == category and r.severity == severity for r in risks):
            risks.append(RiskAssessment(severity=severity, category=category, detail=detail))
    return risks


_CONTENT_DIGEST_FIELDS = ("content_hash", "definition_hash", "schema_hash", "config_hash")
_PROPERTY_BOUND_COMPONENT_TYPES = (
    MCPServerComponent,
    IDEAgentComponent,
    A2AServerComponent,
    A2AClientComponent,
    RAGSourceComponent,
)
_COMPONENT_BINDING_PROPERTIES = (
    "static_value_binding",
    "static_config_hash",
    "static_card_hash",
    "config_hash",
)


def component_content_digest(component: ComponentBase) -> str | None:
    """The unkeyed digest of the component's reviewed bytes, when a collector recorded one.

    Detail texts carry counts, not content, so without this a finding whose payload
    changed at the same count would keep its fingerprint.
    """
    for name in _CONTENT_DIGEST_FIELDS:
        value = getattr(component, name, None)
        if isinstance(value, str) and value:
            return value
    if isinstance(component, PromptComponent) and withholds_content_hash(component):
        # The keyed binding is the only record of the content; see ``content_unbound``.
        # Only the prompt collector withholds a digest: on any other record the flag is
        # supplied text, and a binding it carried would outlive a change of the bytes.
        binding = component.properties.get("static_value_binding")
        return binding if isinstance(binding, str) and binding else None
    sha = component.hashes.get("sha256")
    if sha:
        return sha
    if isinstance(component, _PROPERTY_BOUND_COMPONENT_TYPES):
        present: dict[str, Any] = {}
        for prop_key in _COMPONENT_BINDING_PROPERTIES:
            bound = component.properties.get(prop_key)
            if isinstance(bound, str) and bound:
                present[prop_key] = bound
        settings_hashes = component.properties.get("settings_hashes")
        if (
            isinstance(settings_hashes, dict)
            and settings_hashes
            and all(
                isinstance(k, str) and k and isinstance(v, str) and v
                for k, v in settings_hashes.items()
            )
        ):
            present["settings_hashes"] = settings_hashes
        if len(present) == 1:
            only = next(iter(present.values()))
            if isinstance(only, str):
                return only
            payload = json.dumps(only, sort_keys=True, separators=(",", ":"))
            return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if present:
            payload = json.dumps(present, sort_keys=True, separators=(",", ":"))
            return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return None


def content_unbound(component: ComponentBase) -> bool:
    """Whether the collector withheld the component's content digest and no keyed binding
    stands in for it, so no fingerprint can tie a finding to the reviewed bytes.

    A suppression of a finding on such a component would survive any change of its
    content, so it never applies: the entry is reported stale while the component still
    has a finding in that category, and unused otherwise.
    """
    return bool(component.properties.get("content_hash_withheld")) and (
        component_content_digest(component) is None
    )


def finding_fingerprint(
    component_ref: str,
    category: str,
    severity: RiskSeverity,
    detail: str,
    content: str | None = None,
) -> str:
    """The digest a suppression names, so it covers the finding as it was reviewed.

    The fields are hashed as ASCII JSON with sorted keys rather than RFC 8785 text:
    a detail can quote a lone surrogate from the checkout, which RFC 8785 cannot
    encode, and ASCII escaping keeps it distinct from any other string.
    """
    document = {
        "component_ref": component_ref,
        "category": category,
        "severity": severity.value,
        "detail": detail,
        "content": content,
    }
    text = json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _intrinsic_credential_risks(component: CredentialComponent) -> list[RiskAssessment]:
    """A value committed beside a credential reference is exposed, with or without a finding."""
    risks = list(component.risks)
    if component.value_in_checkout is True and not any(
        r.category == "credential_exposure" and r.severity == RiskSeverity.HIGH for r in risks
    ):
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="credential_exposure",
                detail="A value for this credential is committed in the checkout.",
                recommendation="Remove the value, rotate the credential and load it from a "
                "secret store.",
            )
        )
    return risks


def effective_component_risks(component: AnyComponent) -> list[RiskAssessment]:
    """Return declared risks together with intrinsic security-fact risks."""
    if isinstance(component, ModelComponent):
        return _intrinsic_model_risks(component)
    if isinstance(component, CredentialComponent):
        return _intrinsic_credential_risks(component)
    return list(getattr(component, "risks", []))


@dataclass
class RiskFinding:
    component_ref: str
    component_name: str
    severity: RiskSeverity
    category: str
    detail: str
    recommendation: str | None = None
    references: list[str] = field(default_factory=list)
    score: float = 0.0
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = finding_fingerprint(
                self.component_ref, self.category, self.severity, self.detail
            )


@dataclass
class SuppressedFinding:
    finding: RiskFinding
    suppression: Suppression


@dataclass
class StaleSuppression:
    """A suppression whose component and category still have a finding it no longer names."""

    suppression: Suppression
    current_fingerprints: list[str]


@dataclass
class RiskReport:
    overall_score: float = 0.0
    risk_level: str = "unknown"
    findings: list[RiskFinding] = field(default_factory=list)
    category_scores: dict[str, float] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)
    total_components: int = 0
    components_with_risks: int = 0
    gate_reasons: list[str] = field(default_factory=list)
    ignored_findings: int = 0
    warning_threshold_exceeded: bool = False
    coverage_status: str = "unknown"
    coverage_gaps: list[str] = field(default_factory=list)
    suppressed: list[SuppressedFinding] = field(default_factory=list)
    suppressions_expired: list[Suppression] = field(default_factory=list)
    suppressions_unused: list[Suppression] = field(default_factory=list)
    suppressions_stale: list[StaleSuppression] = field(default_factory=list)
    gate: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 2),
            "risk_level": self.risk_level,
            "coverage_status": self.coverage_status,
            "coverage_gaps": self.coverage_gaps,
            "gate_reasons": self.gate_reasons,
            "gate": self.gate,
            "ignored_findings": self.ignored_findings,
            "suppressed_findings": [
                {
                    "component_ref": item.finding.component_ref,
                    "component_name": item.finding.component_name,
                    "severity": item.finding.severity.value,
                    "category": item.finding.category,
                    "detail": item.finding.detail,
                    "fingerprint": item.finding.fingerprint,
                    "reason": item.suppression.reason,
                    "owner": item.suppression.owner,
                    "expires": item.suppression.expires.isoformat(),
                }
                for item in self.suppressed
            ],
            "suppressions_expired": [_suppression_dict(s) for s in self.suppressions_expired],
            "suppressions_unused": [_suppression_dict(s) for s in self.suppressions_unused],
            "suppressions_stale": [
                {
                    **_suppression_dict(item.suppression),
                    "current_fingerprints": item.current_fingerprints,
                }
                for item in self.suppressions_stale
            ],
            "warning_threshold_exceeded": self.warning_threshold_exceeded,
            "total_components": self.total_components,
            "components_with_risks": self.components_with_risks,
            "severity_counts": self.severity_counts,
            "category_scores": {k: round(v, 2) for k, v in self.category_scores.items()},
            "findings": [
                {
                    "component_ref": f.component_ref,
                    "component_name": f.component_name,
                    "severity": f.severity.value,
                    "category": f.category,
                    "detail": f.detail,
                    "recommendation": f.recommendation,
                    "score": round(f.score, 2),
                    "fingerprint": f.fingerprint,
                }
                for f in self.findings
            ],
        }


def _suppression_dict(suppression: Suppression) -> dict[str, str]:
    return {
        "component_ref": suppression.component_ref,
        "category": suppression.category,
        "fingerprint": suppression.fingerprint,
        "reason": suppression.reason,
        "owner": suppression.owner,
        "expires": suppression.expires.isoformat(),
    }


class RiskScorer:
    """Aggregates component-level risks into a scored report."""

    def __init__(
        self,
        severity_weights: dict[RiskSeverity, float] | None = None,
        fail_threshold: float = 50.0,
        warn_threshold: float = 25.0,
        ignore_categories: list[str] | None = None,
        fail_on_severity: str = "critical",
        suppressions: Sequence[Suppression] = (),
        today: date | None = None,
    ) -> None:
        if not math.isfinite(fail_threshold) or fail_threshold <= 0:
            raise ValueError("fail_threshold must be positive and finite")
        if not math.isfinite(warn_threshold) or warn_threshold < 0:
            raise ValueError("warn_threshold must be finite and nonnegative")
        # A partial map would silently weight the missing severities 0.0, so findings
        # at those severities could never trip the score threshold.
        if severity_weights is not None and set(severity_weights) != set(RiskSeverity):
            raise ValueError("severity_weights must assign a weight to every RiskSeverity")
        self.weights = dict(severity_weights) if severity_weights is not None else SEVERITY_WEIGHTS
        self.fail_threshold = fail_threshold
        self.warn_threshold = warn_threshold
        self.ignore_categories = set(ignore_categories or [])
        if fail_on_severity not in (*[s.value for s in RiskSeverity], "none"):
            raise ValueError("unknown fail_on_severity")
        self.fail_on_severity = fail_on_severity
        self.suppressions = list(suppressions)
        self.today = today

    @classmethod
    def from_policy(
        cls,
        policy: RiskPolicy,
        *,
        fail_threshold: float | None = None,
        fail_on_severity: str | None = None,
    ) -> RiskScorer:
        """A scorer for a loaded policy; explicit caller values replace the policy's."""
        return cls(
            fail_threshold=policy.fail_threshold if fail_threshold is None else fail_threshold,
            warn_threshold=policy.warn_threshold,
            ignore_categories=policy.ignore_categories,
            fail_on_severity=fail_on_severity or policy.fail_on_severity,
            suppressions=policy.suppressions,
        )

    def score(self, bom: AIBOM) -> RiskReport:
        report = RiskReport()
        report.total_components = len(bom.components)
        report.gate = {
            "fail_threshold": self.fail_threshold,
            "warn_threshold": self.warn_threshold,
            "fail_on_severity": self.fail_on_severity,
            "ignore_categories": sorted(self.ignore_categories),
            "suppressions": len(self.suppressions),
            # The score is the sum of finding weights. It is not capped at 100.
            "score_scale": "unbounded-sum",
        }
        coverage = bom.metadata.completeness
        assessment = assess_coverage(coverage)
        if assessment.status is CoverageStatus.PARTIAL:
            report.coverage_status = "partial"
        elif assessment.complete and bom.components:
            report.coverage_status = "reported"
        gaps = assessment.reasons()
        if assessment.complete and not bom.components:
            gaps.append("The inventory has no components.")
        report.coverage_gaps = gaps[:MAX_REPORTED_COVERAGE_GAPS]
        if len(gaps) > MAX_REPORTED_COVERAGE_GAPS:
            report.coverage_gaps.append(
                f"{len(gaps) - MAX_REPORTED_COVERAGE_GAPS} further coverage gaps omitted"
            )
        today = self.today or datetime.now(UTC).date()
        active = {(s.component_ref, s.category, s.fingerprint): s for s in self.suppressions}
        suppressed_pairs = {(s.component_ref, s.category) for s in self.suppressions}
        used: set[tuple[str, str, str]] = set()
        unmatched: dict[tuple[str, str], list[str]] = {}
        components_with_risks: set[str] = set()
        category_scores: dict[str, float] = {}

        for comp in bom.components:
            risks = effective_component_risks(comp)
            if not risks:
                continue
            content = component_content_digest(comp)
            unbound = content_unbound(comp)
            for risk in risks:
                if risk.category in self.ignore_categories:
                    report.ignored_findings += 1
                    continue
                sev = risk.severity
                weight = self.weights.get(sev, 0.0)

                finding = RiskFinding(
                    component_ref=comp.bom_ref,
                    component_name=comp.name,
                    severity=sev,
                    category=risk.category,
                    detail=risk.detail,
                    recommendation=risk.recommendation,
                    references=list(risk.references),
                    score=weight,
                    fingerprint=finding_fingerprint(
                        comp.bom_ref, risk.category, sev, risk.detail, content
                    ),
                )
                key = (comp.bom_ref, risk.category, finding.fingerprint)
                suppression = None if unbound else active.get(key)
                if suppression is not None:
                    used.add(key)
                    if suppression.expires >= today:
                        report.suppressed.append(SuppressedFinding(finding, suppression))
                        continue
                elif (comp.bom_ref, risk.category) in suppressed_pairs:
                    unmatched.setdefault((comp.bom_ref, risk.category), []).append(
                        finding.fingerprint
                    )
                components_with_risks.add(comp.bom_ref)
                report.findings.append(finding)

                sev_key = sev.value
                report.severity_counts[sev_key] = report.severity_counts.get(sev_key, 0) + 1
                category_scores[risk.category] = category_scores.get(risk.category, 0.0) + weight

        report.components_with_risks = len(components_with_risks)
        report.category_scores = category_scores
        report.overall_score = sum(f.score for f in report.findings)
        report.risk_level = (
            "unknown"
            if not report.findings and report.coverage_status != "reported"
            else self._classify(report.overall_score)
        )
        if report.severity_counts.get("critical", 0):
            report.risk_level = "critical"
        report.warning_threshold_exceeded = report.overall_score >= self.warn_threshold
        order = list(RiskSeverity)
        if self.fail_on_severity != "none":
            cutoff = order.index(RiskSeverity(self.fail_on_severity))
            if any(order.index(f.severity) <= cutoff for f in report.findings):
                report.gate_reasons.append(f"finding at or above {self.fail_on_severity}")
                if self.fail_on_severity == "critical":
                    report.risk_level = "critical"
        if report.overall_score >= self.fail_threshold:
            report.gate_reasons.append("aggregate score is at or above fail_threshold")
        if "invalid_safetensors" in category_scores:
            report.gate_reasons.append("SafeTensors structural safety is unverified")
        if report.coverage_status != "reported":
            report.gate_reasons.append("collection coverage is unknown or incomplete")
        if (
            coverage is not None
            and coverage.scope in {"repository", "repository+shadowscan"}
            and not any(
                not is_imported(c)
                and not (
                    isinstance(c, AgentComponent)
                    and c.properties.get("identity_source") == "repository-path"
                )
                for c in bom.components
            )
        ):
            report.gate_reasons.append(NO_LOCAL_EVIDENCE)
            if not report.findings:
                report.risk_level = "unknown"
        for suppression in self.suppressions:
            if suppression.expires < today:
                report.suppressions_expired.append(suppression)
                report.gate_reasons.append(
                    f"suppression of {suppression.category} on {suppression.component_ref} "
                    f"expired on {suppression.expires.isoformat()}"
                )
            elif (suppression.component_ref, suppression.category, suppression.fingerprint) in used:
                continue
            elif current := unmatched.get((suppression.component_ref, suppression.category)):
                report.suppressions_stale.append(StaleSuppression(suppression, sorted(current)))
            else:
                report.suppressions_unused.append(suppression)
        report.findings.sort(key=lambda f: self.weights.get(f.severity, 0.0), reverse=True)

        return report

    def _classify(self, score: float) -> str:
        if score >= self.fail_threshold:
            return "critical"
        if score >= self.warn_threshold:
            return "high"
        if score > 0:
            return "moderate"
        return "clean"

    def passes_gate(self, bom: AIBOM) -> tuple[bool, RiskReport]:
        report = self.score(bom)
        passed = not report.gate_reasons
        return passed, report
