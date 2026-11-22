"""A checkout can request independent tightenings and relaxations in the same file."""

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import _policy_with_source, main
from nexus_symbiote.policy import Policy


@pytest.mark.parametrize(
    ("command", "operator"), [("scan", False), ("scan", True), ("baseline", False)]
)
def test_mixed_checkout_enforces_the_discovery_signature_through_public_commands(
    tmp_path, command, operator
):
    root = tmp_path / "project"
    discovery = root / ".shadowscan"
    discovery.mkdir(parents=True)
    fixture = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
    shutil.copyfile(fixture, discovery / "report.json")
    (root / "CLAUDE.md").write_text("Use local project instructions.\n")
    (root / ".nexus-symbiote.yaml").write_text(
        "validate: {require_discovery_signature: true}\nrisk: {fail_threshold: 90}\n"
    )
    args = [command, str(root)]
    out = tmp_path / "result.json"
    args += ["--check"] if command == "scan" else ["-o", str(out), "--allow-unsigned-discovery"]
    if operator:
        policy = tmp_path / "operator.json"
        policy.write_text(json.dumps({"risk": {"fail_threshold": 30}}))
        policy.chmod(0o600)
        args += ["--operator-policy", str(policy), "--allow-unsigned-operator-policy"]
    run = CliRunner().invoke(main, args)
    assert run.exit_code == 1, run.output
    if command == "baseline":
        assert "unverified imported discovery cannot be promoted" in run.output
        assert not out.exists()
    assert "relaxations" in run.stderr


def test_init_inherits_operator_category_decisions_but_an_explicit_empty_list_tightens(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    run = CliRunner().invoke(main, ["init", "--path", str(root)])
    assert run.exit_code == 0, run.output
    baseline = Policy.model_validate({"risk": {"ignore_categories": ["fixture-category"]}})

    def governing():
        return _policy_with_source(root, operator=baseline, operator_digest="fixture")[0]

    assert governing().risk.ignore_categories == ["fixture-category"]
    (root / ".nexus-symbiote.yaml").write_text("risk: {ignore_categories: []}\n")
    assert governing().risk.ignore_categories == []


def test_mixed_policy_reports_the_checkout_tightening_and_attributes_clamped_settings(tmp_path):
    (tmp_path / ".nexus-symbiote.yaml").write_text(
        "risk: {fail_threshold: 90, fail_on_severity: high}\n"
    )
    policy, source, _, unused = _policy_with_source(tmp_path)
    assert source.startswith("project:")
    assert policy.risk.fail_threshold == 50
    assert policy.risk.fail_on_severity == "high"
    assert unused == {"file": ".nexus-symbiote.yaml", "reason": "relaxations-not-accepted"}
    assert "fail_threshold" not in policy.risk.model_fields_set
