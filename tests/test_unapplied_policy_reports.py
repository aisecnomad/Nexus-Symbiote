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


def test_mixed_checkout_keeps_the_tightening_without_accepting_relaxations(tmp_path):
    project = _project(
        tmp_path / "project",
        "validate: {minimum_assurance_level: observed}\nrisk: {fail_on_severity: none}\n",
    )
    inventory = _inventory(tmp_path, project)
    args = ["validate", str(inventory), "--project", str(project), "--report-format", "json"]
    implicit = CliRunner().invoke(main, args)
    assert json.loads(implicit.stdout)["policy_source"].startswith("project:")
    assert json.loads(implicit.stdout)["policy_unapplied"]["reason"] == "relaxations-not-accepted"
    explicit = CliRunner().invoke(main, [*args, "--accept-project-policy"])
    assert json.loads(explicit.stdout)["policy_source"].startswith("project:")


@pytest.mark.parametrize("command", ["risk", "validate"])
def test_tightening_checkout_policy_is_applied_in_machine_outputs(tmp_path, command):
    project = _project(
        tmp_path / "project",
        "validate: {minimum_assurance_level: observed}\nrisk: {fail_on_severity: high}\n",
    )
    inventory = _inventory(tmp_path, project)
    args = [command, str(inventory), "--project", str(project), "--report-format", "json"]
    implicit = CliRunner().invoke(main, args)
    explicit = CliRunner().invoke(main, [*args, "--accept-project-policy"])
    doc = json.loads(implicit.stdout)
    assert doc["policy_source"].startswith("project:")
    assert "policy_unapplied" not in doc
    assert implicit.exit_code == explicit.exit_code
    assert json.loads(explicit.stdout) == doc


def test_checkout_tightening_preserves_unspecified_operator_settings(tmp_path):
    from nexus_symbiote.cli import _policy_with_source
    from nexus_symbiote.policy import Policy

    project = _project(tmp_path / "project", "risk: {fail_on_severity: high}\n")
    operator = Policy.model_validate(
        {"risk": {"fail_threshold": 12}, "validate": {"minimum_assurance_level": "verified"}}
    )
    policy, source, _, unused = _policy_with_source(
        project, operator=operator, operator_digest="fixture"
    )
    assert source.startswith("operator:")
    assert unused is None
    assert policy.risk.fail_threshold == 12 and policy.risk.fail_on_severity == "high"
    assert policy.validation.minimum_assurance_level == "verified"

    (project / ".nexus-symbiote.yaml").write_text(
        "risk: {fail_threshold: 30, fail_on_severity: high}\n"
    )
    policy, _, _, unused = _policy_with_source(
        project, operator=operator, operator_digest="fixture"
    )
    assert policy.risk.fail_threshold == 12 and policy.risk.fail_on_severity == "high"
    assert policy.validation.minimum_assurance_level == "verified"
    assert unused is not None and unused["reason"] == "relaxations-not-accepted"


@pytest.mark.parametrize(
    ("command", "policy", "filename", "contents"),
    [
        ("risk", "risk: {fail_threshold: 1}", "requirements.txt", "openai>=1\n"),
        (
            "validate",
            "validate: {minimum_assurance_level: observed}",
            "agent.yaml",
            "name: triage\nmodels: {chat: {provider: example, requested_ref: latest}}\n",
        ),
    ],
)
def test_implicit_tightening_changes_the_exit_verdict(
    tmp_path, command, policy, filename, contents
):
    project = tmp_path / "project"
    project.mkdir()
    (project / filename).write_text(contents)
    (project / ".nexus-symbiote.yaml").write_text(policy)
    inventory = _inventory(tmp_path, project)
    args = [command, str(inventory), "--project", str(project), "--report-format", "json"]
    if command == "validate":
        # Hosted declarations have no local file digest. Isolate the assurance decision.
        args.append("--skip-integrity")
    ignored = CliRunner().invoke(main, [*args, "--no-project-policy"])
    strict = CliRunner().invoke(main, args)
    assert ignored.exit_code == 0, ignored.output
    assert strict.exit_code == 1, strict.output
    doc = json.loads(strict.stdout)
    if command == "risk":
        assert 1 <= doc["overall_score"] < 50
        assert doc["gate"]["fail_threshold"] == 1
    else:
        assert doc["assurance_errors"] == [
            "minimum observed assurance not attained (1 declared component)"
        ]


def test_explicit_checkout_removal_of_operator_exclusions_is_a_tightening(tmp_path):
    from nexus_symbiote.cli import _policy_with_source
    from nexus_symbiote.policy import Policy

    project = _project(tmp_path / "project", "scan: {exclude_paths: []}\n")
    operator = Policy.model_validate({"scan": {"exclude_paths": ["vendor"]}})
    effective, _, _, unused = _policy_with_source(
        project, operator=operator, operator_digest="fixture"
    )
    assert effective.scan.exclude_paths == [] and unused is None
