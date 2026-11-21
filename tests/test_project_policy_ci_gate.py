"""A project policy is applied only when the operator asks for it.

`scan`, `validate` and `risk` ignore `.nexus-symbiote.yaml` unless
`--accept-project-policy` is passed. `--no-project-policy` selects the built-in
policy and does not warn that a file was left unused. CI is not a reason to
apply or refuse the file: an unattended run that forgets the flag keeps the
built-in gates.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main

NOT_APPLIED = "was not applied"


def _project(root: Path, policy: str) -> Path:
    root.mkdir()
    (root / ".nexus-symbiote.yaml").write_text(policy)
    (root / "models").mkdir()
    (root / "models" / "classifier.pkl").write_bytes(b"\x80\x04N.")
    return root


def _inventory(tmp_path: Path, project: Path) -> Path:
    output = tmp_path / "inventory.json"
    run = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )
    assert run.exit_code == 0, run.output
    assert json.loads(output.read_text())["components"]
    return output


def test_a_project_policy_is_not_applied_unless_accepted(tmp_path: Path) -> None:
    project = _project(tmp_path / "project", "scan:\n  failure_mode: report-only\n")
    output = tmp_path / "out.json"
    # The pickle is critical. Report-only would exit 0; the built-in gate must not.
    held = CliRunner().invoke(main, ["scan", str(project), "-o", str(output)])
    assert held.exit_code == 1, held.output
    assert NOT_APPLIED in held.output
    assert "--accept-project-policy" in held.output
    recorded = CliRunner().invoke(main, ["scan", str(project), "--report-only", "-o", str(output)])
    assert recorded.exit_code == 0, recorded.output
    metadata = json.loads(output.read_text())["metadata"]
    assert not metadata.get("policy_weakened")
    assert metadata.get("policy_source", "built-in") == "built-in"
    accepted = CliRunner().invoke(
        main,
        ["scan", str(project), "--accept-project-policy", "-o", str(tmp_path / "accepted.json")],
    )
    assert accepted.exit_code == 0, accepted.output
    accepted_meta = json.loads((tmp_path / "accepted.json").read_text())["metadata"]
    assert accepted_meta.get("policy_weakened")


def test_unsafe_unused_policy_is_distinguished_from_an_incomplete_lookup(tmp_path: Path) -> None:
    project = tmp_path / "checkout cannot be listed"
    project.mkdir()
    (project / ".nexus-symbiote.yaml").symlink_to("unused.yaml")
    (project / "AGENTS.md").write_text("Use the configured tools.\n", encoding="utf-8")
    output = tmp_path / "inventory.json"

    run = CliRunner().invoke(main, ["scan", str(project), "--report-only", "-o", str(output)])

    assert run.exit_code == 0, run.output
    assert "was not applied because it is invalid or unsafe to read" in run.output
    assert output.exists()


def test_in_ci_a_project_policy_is_still_not_applied_without_the_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CI", "true")
    project = _project(tmp_path / "project", "scan:\n  failure_mode: report-only\n")
    output = tmp_path / "out.json"
    run = CliRunner().invoke(main, ["scan", str(project), "--report-only", "-o", str(output)])
    assert run.exit_code == 0, run.output
    assert NOT_APPLIED in run.output
    assert "looks like CI" not in run.output
    metadata = json.loads(output.read_text())["metadata"]
    assert not metadata.get("policy_weakened")


@pytest.mark.parametrize("flag", ["--accept-project-policy", "--no-project-policy"])
def test_an_explicit_choice_lets_scan_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    monkeypatch.setenv("CI", "true")
    project = _project(tmp_path / "project", "scan:\n  failure_mode: report-only\n")
    output = tmp_path / "out.json"
    run = CliRunner().invoke(main, ["scan", str(project), flag, "--report-only", "-o", str(output)])
    assert "looks like CI" not in run.output
    assert output.exists()
    weakened = json.loads(output.read_text())["metadata"].get("policy_weakened") or []
    assert bool(weakened) == (flag == "--accept-project-policy")
    if flag == "--no-project-policy":
        assert NOT_APPLIED not in run.output
    else:
        assert "weakens the built-in gates" in run.output


@pytest.mark.parametrize("command", ["validate", "risk"])
def test_validate_and_risk_ignore_a_project_policy_until_it_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    project = _project(tmp_path / "project", "risk:\n  fail_threshold: 1000000\n")
    inventory = _inventory(tmp_path, project)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    ignored = CliRunner().invoke(main, [command, str(inventory), "--project", str(project)])
    assert NOT_APPLIED in ignored.output
    assert "looks like CI" not in ignored.output
    accepted = CliRunner().invoke(
        main, [command, str(inventory), "--project", str(project), "--accept-project-policy"]
    )
    assert "WARNING: policy" in accepted.output
    assert "fail_threshold" in accepted.output


def test_a_stricter_project_policy_is_not_applied_without_the_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CI", "true")
    project = _project(tmp_path / "project", "risk:\n  fail_threshold: 20\n")
    output = tmp_path / "out.json"
    run = CliRunner().invoke(main, ["scan", str(project), "--report-only", "-o", str(output)])
    assert run.exit_code == 0, run.output
    assert NOT_APPLIED in run.output
    metadata = json.loads(output.read_text())["metadata"]
    assert metadata.get("policy_source", "built-in") == "built-in"
    accepted = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--report-only",
            "--accept-project-policy",
            "-o",
            str(tmp_path / "accepted.json"),
        ],
    )
    assert accepted.exit_code == 0, accepted.output
    accepted_meta = json.loads((tmp_path / "accepted.json").read_text())["metadata"]
    assert str(accepted_meta.get("policy_source", "")).startswith("project:")


def test_init_tells_the_operator_how_to_apply_the_created_policy(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["init", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".nexus-symbiote.yaml").is_file()
    assert "--accept-project-policy" in result.output
