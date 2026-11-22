import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import SCANNER_REGISTRY, main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import CompletenessClaim, ToolComponent
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.validators.completeness import CompletenessValidator


def test_failed_collector_produces_partial_output_and_nonzero(tmp_path, monkeypatch):
    class Broken:
        def scan(self, root):
            raise RuntimeError("unavailable")

    monkeypatch.setitem(SCANNER_REGISTRY, "broken", Broken)
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--scanner", "broken", "-o", str(output)]
    )
    assert result.exit_code != 0
    bom = AIBOM.load(output)
    assert bom.metadata.completeness.scope == "repository"
    assert bom.metadata.completeness.scanner_status["broken"] == "failed"
    assert bom.metadata.completeness.scan_failures
    assert not CompletenessValidator().validate(bom).is_complete


def test_unselected_scanners_remain_unknown(tmp_path):
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--scanner", "model", "-o", str(output)]
    )
    assert result.exit_code != 0
    bom = AIBOM.load(output)
    assert bom.metadata.completeness.scanner_status["model"] == "complete"
    assert not bom.metadata.completeness.surfaces_excluded
    assert bom.metadata.completeness.scanner_status["mcp"] == "unknown"
    assert not CompletenessValidator().validate(bom).is_complete


def test_component_collision_is_rejected_on_add_and_import():
    bom = AIBOM()
    bom.add_component(ToolComponent(bom_ref="tool:x", name="x"))
    with pytest.raises(ValueError, match="Duplicate"):
        bom.add_component(ToolComponent(bom_ref="tool:x", name="other"))
    component = bom.components[0].model_dump(mode="json")
    with pytest.raises(ValueError, match="Duplicate"):
        AIBOM.model_validate({"components": [component, component]})


def test_policy_with_typo_or_invalid_yaml_does_not_fall_back(tmp_path):
    (tmp_path / ".nexus-symbiote.yaml").write_text("scan:\n  scaners: [mcp]\n")
    ignored = tmp_path / "ignored.json"
    refused = CliRunner().invoke(main, ["scan", str(tmp_path), "--report-only", "-o", str(ignored)])
    assert refused.exit_code != 0
    assert "invalid policy" in refused.output
    assert not ignored.exists()
    skipped = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "--report-only", "-o", str(ignored)]
    )
    assert skipped.exit_code == 0
    assert ignored.is_file()
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--accept-project-policy", "-o", str(output)]
    )
    assert result.exit_code != 0
    assert "invalid policy" in result.output
    assert not output.exists()


def test_recorded_failure_cannot_be_complete():
    bom = AIBOM()
    bom.metadata.completeness = CompletenessClaim(
        scope="local-static-project",
        scanner_status={"model": "complete"},
        scan_failures=["read failed"],
    )
    assert not CompletenessValidator().validate(bom).is_complete


def test_imported_status_cannot_omit_required_scanners():
    bom = AIBOM()
    bom.metadata.completeness = CompletenessClaim(
        scope="local-static-project",
        scanner_status={"model": "complete"},
        surfaces_scanned=["model"],
    )
    result = CompletenessValidator().validate(bom)
    assert not result.is_complete
    assert any("Missing scanner coverage" in issue.description for issue in result.issues)


def test_imported_complete_status_cannot_hide_excluded_surfaces():
    bom = AIBOM()
    bom.metadata.completeness = CompletenessClaim(
        scope="local-static-project",
        scanner_status=dict.fromkeys(("model", "mcp", "prompt", "rag", "registry"), "complete"),
        surfaces_excluded=["prompts (not scanned)"],
    )
    assert not CompletenessValidator().validate(bom).is_complete


def _claims() -> list[CompletenessClaim]:
    everything = sorted(BUILTIN_SCANNER_NAMES)
    complete = {
        "scope": "repository",
        "surfaces_scanned": ["CLAUDE.md"],
        "scanner_status": dict.fromkeys(everything, "complete"),
        "collectors_requested": everything,
        "collectors_completed": everything,
    }
    return [
        CompletenessClaim(**complete),
        CompletenessClaim(**{**complete, "scan_failures": ["mcp: read refused"]}),
        CompletenessClaim(**{**complete, "surfaces_excluded": ["fixtures: excluded"]}),
        CompletenessClaim(**{**complete, "collectors_completed": everything[1:]}),
        CompletenessClaim(**{**complete, "collectors_requested": [], "collectors_completed": []}),
        CompletenessClaim(**{**complete, "scanner_status": {"mcp": "complete"}}),
        CompletenessClaim(**{**complete, "scanner_status": {}}),
        CompletenessClaim(**{**complete, "surfaces_scanned": []}),
        CompletenessClaim(
            **{**complete, "scanner_status": {**complete["scanner_status"], "rag": "partial"}}
        ),
    ]


@pytest.mark.parametrize("claim", _claims())
def test_validate_and_risk_share_one_coverage_verdict(claim):
    from nexus_symbiote.core.coverage import assess_coverage
    from nexus_symbiote.core.models import PromptComponent
    from nexus_symbiote.validators.risk import RiskScorer

    bom = AIBOM(components=[PromptComponent(bom_ref="prompt:CLAUDE.md", name="CLAUDE.md")])
    bom.metadata.completeness = claim
    verdict = assess_coverage(claim)
    completeness = CompletenessValidator().validate(bom)
    risk = RiskScorer().score(bom)
    assert completeness.coverage_status == verdict.status.value
    assert (risk.coverage_status == "reported") is verdict.complete
    assert (risk.coverage_status == "partial") is (verdict.status.value == "partial")
    coverage_errors = [
        issue.description
        for issue in completeness.issues
        if issue.severity == "error" and issue.surface != "graph"
    ]
    assert coverage_errors == verdict.reasons()
    assert risk.coverage_gaps == verdict.reasons()


def test_every_collector_list_matches_the_catalogue(monkeypatch):
    import importlib.util
    import sys
    from pathlib import Path

    from nexus_symbiote.scanners import ALL_SCANNERS

    assert {scanner.name for scanner in ALL_SCANNERS} == BUILTIN_SCANNER_NAMES
    spec = importlib.util.spec_from_file_location(
        "action_runner_catalogue", Path(__file__).parents[1] / "scripts" / "run_action.py"
    )
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, runner)
    spec.loader.exec_module(runner)
    assert set(runner.SCANNERS) == BUILTIN_SCANNER_NAMES
