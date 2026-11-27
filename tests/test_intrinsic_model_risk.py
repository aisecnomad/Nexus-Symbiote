"""Imported finding lists cannot erase security facts retained in an inventory."""

from __future__ import annotations

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import CompletenessClaim, ModelComponent, RiskAssessment
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.validators.risk import RiskScorer


def imported_model(**fields) -> AIBOM:
    component = ModelComponent(bom_ref="model:imported", name="imported", **fields)
    bom = AIBOM(components=[component])
    collectors = sorted(BUILTIN_SCANNER_NAMES)
    bom.metadata.completeness = CompletenessClaim(
        scope="repository",
        surfaces_scanned=["all"],
        scanner_status=dict.fromkeys(collectors, "complete"),
        collectors_requested=collectors,
        collectors_completed=collectors,
    )
    return AIBOM.model_validate(bom.model_dump(mode="json"))


@pytest.mark.parametrize(
    ("fields", "category", "severity"),
    [
        ({"serialization_safety": "unsafe-code-execution"}, "serialization_format", "critical"),
        ({"serialization_safety": "unsafe-template-injection"}, "serialization_format", "critical"),
        ({"trust_remote_code": True}, "code_execution", "critical"),
        (
            {"serialization_format": "safe-tensors", "serialization_safety": "unknown"},
            "invalid_safetensors",
            "high",
        ),
        (
            {"serialization_format": "safetensors", "serialization_safety": "unknown"},
            "invalid_safetensors",
            "high",
        ),
        # A file named as SafeTensors whose header did not establish the format.
        (
            {"properties": {"named_format": "safe-tensors"}, "serialization_safety": "unknown"},
            "invalid_safetensors",
            "high",
        ),
    ],
)
def test_stripping_imported_findings_does_not_clear_model_facts(fields, category, severity):
    bom = imported_model(**fields)
    passed, report = RiskScorer(fail_threshold=1000).passes_gate(bom)
    assert report.coverage_status == "reported"
    assert not passed
    assert any(f.category == category and f.severity.value == severity for f in report.findings)
    assert bom.components[0].risks == []


def test_intrinsic_findings_are_deduplicated_and_recomputed():
    bom = imported_model(trust_remote_code=True)
    bom.components[0].risks.append(
        RiskAssessment(
            severity=RiskSeverity.CRITICAL,
            category="code_execution",
            detail="Existing scanner finding",
        )
    )
    scorer = RiskScorer()
    first = scorer.score(bom)
    second = scorer.score(bom)
    assert first.to_dict() == second.to_dict()
    assert first.severity_counts == {"critical": 1}
    assert len(bom.components[0].risks) == 1


def test_lower_declared_severity_cannot_downgrade_intrinsic_critical_fact():
    bom = imported_model(trust_remote_code=True)
    bom.components[0].risks.append(
        RiskAssessment(severity=RiskSeverity.INFO, category="code_execution", detail="Harmless")
    )
    passed, report = RiskScorer(fail_threshold=1000).passes_gate(bom)
    assert not passed
    assert report.severity_counts["critical"] == 1


@pytest.mark.parametrize(
    "fields",
    [
        {"serialization_format": "safe-tensors", "serialization_safety": "safe"},
        {"trust_remote_code": False},
        {"provider": "hosted-provider", "requested_alias": "latest"},
        {"properties": {"named_format": "llama.cpp"}},
        {"properties": {"named_format": 7}},
    ],
)
def test_absent_security_facts_do_not_invent_these_findings(fields):
    passed, report = RiskScorer(fail_threshold=1000).passes_gate(imported_model(**fields))
    assert passed
    assert report.findings == []


def test_explicit_policy_controls_apply_to_intrinsic_risks():
    unsafe = imported_model(trust_remote_code=True)
    passed, report = RiskScorer(
        fail_threshold=1000, ignore_categories=["code_execution"]
    ).passes_gate(unsafe)
    assert passed and report.ignored_findings == 1
    assert RiskScorer(fail_threshold=1000, fail_on_severity="none").passes_gate(unsafe)[0]

    unverified = imported_model(serialization_format="safetensors")
    assert not RiskScorer(fail_threshold=1000, fail_on_severity="none").passes_gate(unverified)[0]
    passed, report = RiskScorer(
        fail_threshold=1000, ignore_categories=["invalid_safetensors"]
    ).passes_gate(unverified)
    assert passed and report.ignored_findings == 1
