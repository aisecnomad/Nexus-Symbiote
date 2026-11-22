"""Gate verdicts carry bounded, self-describing reasons, and documented settings are usable."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MAX_REFERENCE_CHARS, MCPServerComponent
from nexus_symbiote.graph import MAX_GRAPH_ISSUES, validate_graph
from nexus_symbiote.validators.completeness import MAX_REPORTED_ISSUES, CompletenessValidator
from tests.support import scaling_ratio


def test_one_long_reference_cannot_be_multiplied_into_every_graph_message():
    boms = {
        scale: AIBOM(
            components=[
                MCPServerComponent(
                    bom_ref="s" * MAX_REFERENCE_CHARS,
                    name="s",
                    tool_refs=[f"t{index}" for index in range(25_000 * scale)],
                )
            ]
        )
        for scale in (1, 4)
    }
    issues = validate_graph(boms[4])
    assert len(issues) == MAX_GRAPH_ISSUES + 1
    assert issues[-1] == f"{100_000 - MAX_GRAPH_ISSUES} further graph issues not shown"
    assert max(len(issue) for issue in issues) < 600
    report = CompletenessValidator().validate(boms[4])
    assert not report.is_complete and len(report.issues) <= MAX_REPORTED_ISSUES
    assert scaling_ratio(lambda scale: validate_graph(boms[scale])) < 10


def _scan(project: Path, target: Path) -> None:
    result = CliRunner().invoke(
        main, ["scan", "--no-project-policy", str(project), "-o", str(target)]
    )
    assert result.exit_code == 0, result.output


def test_minimum_observed_assurance_is_attainable_for_measured_inventories(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Read-only triage.")
    target = tmp_path / "bom.json"
    _scan(project, target)
    prompt = next(c for c in AIBOM.load(target).components if c.bom_ref == "prompt:CLAUDE.md")
    assert prompt.assurance_level.value == "observed"
    (project / ".nexus-symbiote.yaml").write_text("validate: {minimum_assurance_level: observed}\n")
    result = CliRunner().invoke(
        main,
        ["validate", str(target), "--project", str(project), "--accept-project-policy"],
    )
    assert result.exit_code == 0, result.output
    # A hosted-model alias is only a declaration; no collector observed or measured it.
    (project / "agent.yaml").write_text(
        "name: triage\ninstructions: [CLAUDE.md]\n"
        "models: {chat: {provider: example, requested_ref: latest}}\n"
    )
    _scan(project, target)
    result = CliRunner().invoke(
        main,
        ["validate", str(target), "--project", str(project), "--accept-project-policy"],
    )
    assert result.exit_code == 1
    assert "minimum observed assurance not attained (1 declared component)" in result.output


def test_risk_json_records_the_effective_gate_and_its_origin(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / ".nexus-symbiote.yaml").write_text("risk: {warn_threshold: 10}\n")
    target = tmp_path / "bom.json"
    _scan(project, target)
    args = [
        "risk",
        str(target),
        "--project",
        str(project),
        "--accept-project-policy",
        "--json-output",
    ]
    payload = json.loads(CliRunner().invoke(main, args).stdout)
    assert payload["gate"] == {
        "fail_threshold": 50.0,
        "warn_threshold": 10.0,
        "fail_on_severity": "critical",
        "ignore_categories": [],
        "suppressions": 0,
        "score_scale": "unbounded-sum",
        "fail_threshold_source": "built-in",
        "fail_on_severity_source": "built-in",
        "warn_threshold_source": "project policy",
        "ignore_categories_source": "built-in",
        "suppressions_source": "built-in",
    }
    overridden = json.loads(
        CliRunner()
        .invoke(main, [*args, "--threshold", "1000000", "--fail-on-severity", "none"])
        .stdout
    )
    assert overridden["gate"]["fail_threshold"] == 1000000.0
    assert overridden["gate"]["fail_threshold_source"] == "cli"
    assert overridden["gate"]["fail_on_severity"] == "none"
    assert overridden["gate"]["fail_on_severity_source"] == "cli"


@pytest.mark.parametrize(
    ("policy", "fail_source", "warn_threshold"),
    [
        ("validate: {minimum_assurance_level: observed}\n", "built-in", 25.0),
        ("risk: {fail_threshold: 20}\n", "project policy", 20.0),
    ],
)
def test_a_derived_warning_threshold_is_not_attributed_to_the_project_policy(
    tmp_path, policy, fail_source, warn_threshold
):
    from nexus_symbiote.policy import Policy

    assert Policy.model_validate({"risk": {"fail_threshold": 20.0}}).risk.model_fields_set == {
        "fail_threshold"
    }
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / ".nexus-symbiote.yaml").write_text(policy)
    target = tmp_path / "bom.json"
    _scan(project, target)
    args = [
        "risk",
        str(target),
        "--project",
        str(project),
        "--accept-project-policy",
        "--json-output",
    ]
    gate = json.loads(CliRunner().invoke(main, args).stdout)["gate"]
    assert gate["fail_threshold_source"] == fail_source
    assert gate["warn_threshold"] == warn_threshold
    assert gate["warn_threshold_source"] == "built-in"


def test_every_failing_gate_carries_a_reason(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    target = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", "--report-only", str(empty), "-o", str(target)])
    assert run.exit_code == 0, run.output
    risk = json.loads(CliRunner().invoke(main, ["risk", str(target), "--json-output"]).stdout)
    assert (
        "no agent manifest or supported local inventory evidence was found"
        in (risk["gate_reasons"])
    )
    doc = json.loads(target.read_text())
    doc["metadata"]["completeness"]["scan_failures"] = ["mcp: read refused"]
    target.write_text(json.dumps(doc))
    partial = json.loads(CliRunner().invoke(main, ["risk", str(target), "--json-output"]).stdout)
    assert "collection coverage is unknown or incomplete" in partial["gate_reasons"]
    assert partial["coverage_gaps"] == ["mcp: read refused"]
    validated = CliRunner().invoke(main, ["validate", str(target), "--no-project-policy"])
    assert "Basis: supplied-claims" in validated.output
    assert "No artifact hash or signature could be verified" in validated.output


def test_legacy_absolute_paths_explain_the_reconciliation_failure(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Read-only triage.")
    target = tmp_path / "bom.json"
    _scan(project, target)
    doc = json.loads(target.read_text())
    for component in doc["components"]:
        if component["bom_ref"] == "prompt:CLAUDE.md":
            component["source_path"] = "/elsewhere/checkout/CLAUDE.md"
    target.write_text(json.dumps(doc))
    # A current-format inventory that does not match was altered, not written by an
    # older version, so it gets no advice to re-collect.
    report = CompletenessValidator().validate_against_project(AIBOM.load(target), project)
    assert not report.is_complete and report.basis == "project-reconciliation-failed"
    assert not [issue for issue in report.issues if issue.surface == "format"]
    doc["metadata"]["spec_version"] = "1.0.0"
    target.write_text(json.dumps(doc))
    report = CompletenessValidator().validate_against_project(AIBOM.load(target), project)
    assert any(
        issue.severity == "info" and "absolute scan-host paths" in issue.description
        for issue in report.issues
    )
    legacy = CliRunner().invoke(
        main, ["validate", str(target), "--project", str(project), "--no-project-policy"]
    )
    assert legacy.exit_code == 1 and "re-collect it with this version" in legacy.output


def test_a_claim_listing_many_failures_is_summarized_consistently():
    from nexus_symbiote.core.coverage import MAX_LISTED_GAPS, assess_coverage
    from nexus_symbiote.core.models import CompletenessClaim
    from nexus_symbiote.validators.risk import RiskScorer

    # Distinct failures are listed up to the bound and then counted; one failure
    # recorded many times, as every collector that meets it records it, is one gap.
    claim = CompletenessClaim(
        scope="repository", scan_failures=[f"x{index}" for index in range(50_000)]
    )
    bom = AIBOM(metadata={"completeness": claim})
    reasons = assess_coverage(claim).reasons()
    assert len(reasons) < 2 * MAX_LISTED_GAPS
    assert f"{50_000 - MAX_LISTED_GAPS} further collection failures" in reasons
    repeated = CompletenessClaim(scope="repository", scan_failures=["x"] * 50_000)
    reasons = assess_coverage(repeated).reasons()
    assert reasons.count("x (recorded 50000 times)") == 1
    assert "x" not in reasons and not any("further collection failures" in r for r in reasons)
    report = CompletenessValidator().validate(bom)
    assert not report.is_complete and len(report.issues) < 2 * MAX_LISTED_GAPS
    assert RiskScorer().score(bom).coverage_status == "partial"
