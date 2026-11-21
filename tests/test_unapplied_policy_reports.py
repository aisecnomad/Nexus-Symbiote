"""A skipped checkout policy stays visible to people and automated gate consumers."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from tests.test_project_policy_ci_gate import _inventory, _project


@pytest.mark.parametrize("command", ["risk", "validate"])
@pytest.mark.parametrize("report_format", ["json", "markdown", "junit"])
def test_unapplied_checkout_policy_is_reported_separately_from_stdout(
    tmp_path, command, report_format
):
    project = _project(tmp_path / "project", "risk:\n  fail_threshold: 99\n")
    inventory = _inventory(tmp_path, project)
    args = [command, str(inventory), "--project", str(project), "--report-format", report_format]
    run = CliRunner().invoke(main, args)
    assert "was not applied" in run.stderr
    assert ".nexus-symbiote.yaml" in run.stderr
    assert "WARNING:" not in run.stdout
    if report_format == "json":
        document = json.loads(run.stdout)
        assert document["policy_source"] == "built-in"
        assert document["policy_unapplied"] == {
            "file": ".nexus-symbiote.yaml",
            "reason": "not-accepted",
        }
        opted_out = CliRunner().invoke(main, [*args, "--no-project-policy"])
        assert "policy_unapplied" not in json.loads(opted_out.stdout)
        assert "was not applied" not in opted_out.stderr


def test_baseline_ignores_relaxing_exclusions_without_consent(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".nexus-symbiote.yaml").write_text("scan: {exclude_paths: [vendor]}\n")
    (project / "AGENTS.md").write_text("Project instructions.\n")
    baselines = []
    for label, flags in [("implicit", []), ("explicit", ["--accept-project-policy"])]:
        path = tmp_path / f"{label}.json"
        run = CliRunner().invoke(main, ["baseline", str(project), "-o", str(path), *flags])
        assert run.exit_code == 0, run.output
        baselines.append(json.loads(path.read_text())["metadata"]["completeness"]["exclusions"])
    assert "vendor" not in baselines[0]
    assert "vendor" in baselines[1]


def test_json_shortcut_reports_ambiguous_policy_without_echoing_its_content(tmp_path):
    project = _project(tmp_path / "project", "risk:\n  fail_threshold: 99\n")
    inventory = _inventory(tmp_path, project)
    (project / ".nexus-symbiote.yml").write_text("untrusted policy contents")
    run = CliRunner().invoke(
        main, ["risk", str(inventory), "--project", str(project), "--json-output"]
    )
    assert json.loads(run.stdout)["policy_unapplied"] == {"reason": "invalid-or-ambiguous"}
    assert "was not applied" in run.stderr
    assert "untrusted policy contents" not in run.output
