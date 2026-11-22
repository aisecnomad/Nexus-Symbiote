"""Apply the named project's validation settings to both corroboration commands."""

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.policy import DEFAULT_EXCLUDE_PATHS
from nexus_symbiote.validators import completeness


@pytest.fixture
def project_scope(tmp_path, runner):
    project = tmp_path / "checkout"
    project.mkdir()
    (project / "AGENTS.md").write_text("Use sentence case for headings.\n", encoding="utf-8")
    (project / "drafts").mkdir()
    (project / "drafts" / "AGENTS.md").write_text("Keep notes short.\n", encoding="utf-8")
    path = tmp_path / "inventory.json"
    result = runner.invoke(main, ["scan", str(project), "-o", str(path)])
    assert result.exit_code == 0, result.output
    return runner, project, path


def _write_project_policy(project, text):
    (project / ".nexus-symbiote.yaml").write_text(text, encoding="utf-8")


def _commands(project, path):
    for command, options in (
        ("export-policy", ["--format", "json"]),
        ("crosswalk", ["--include-evidence-pack", "--format", "json"]),
    ):
        yield [command, str(path), "--project", str(project), *options]


def test_corroboration_uses_the_same_exclusions_as_validation(project_scope):
    runner, project, path = project_scope
    (project / "venv").mkdir()
    (project / "venv" / "AGENTS.md").write_text("Check vendored instructions.\n", encoding="utf-8")
    _write_project_policy(project, "scan:\n  exclude_paths: []\n")
    validate = runner.invoke(main, ["validate", str(path), "--project", str(project)])
    assert validate.exit_code == 1, validate.output
    for args in _commands(project, path):
        result = runner.invoke(main, args)
        assert result.exit_code == 1, result.output
        assert "failed completeness reconciliation" in result.stderr
        assert not result.stdout


def test_corroboration_rejects_extra_project_exclusions_locally(project_scope, monkeypatch):
    runner, project, path = project_scope
    _write_project_policy(project, "scan:\n  exclude_paths: [drafts]\n")
    monkeypatch.setattr("nexus_symbiote.policy_export.running_in_ci", lambda: False)
    for args in _commands(project, path):
        result = runner.invoke(main, args)
        assert result.exit_code == 1, result.output
        assert "weakens the built-in gates because" in result.stderr
        assert "in CI" not in result.stderr
        assert not result.stdout


def test_corroboration_enforces_project_discovery_verification(project_scope, monkeypatch):
    runner, project, path = project_scope
    _write_project_policy(project, "validate:\n  require_discovery_signature: true\n")
    checks = []

    def refuse(_inventory, root, _policies, *, exclude_paths):
        checks.append((root, tuple(exclude_paths)))
        return "failed", ["synthetic producer check failure"]

    monkeypatch.setattr(completeness, "discovery_producer_check", refuse)
    for args in _commands(project, path):
        result = runner.invoke(main, args)
        assert result.exit_code == 1, result.output
        assert "failed discovery producer verification" in result.stderr
        assert not result.stdout
    assert checks == [(project, DEFAULT_EXCLUDE_PATHS)] * 2


def test_corroboration_rejects_project_exclusions_that_weaken_ci(project_scope, monkeypatch):
    runner, project, path = project_scope
    _write_project_policy(project, "scan:\n  exclude_paths: [drafts]\n")
    monkeypatch.setenv("CI", "true")
    for args in _commands(project, path):
        result = runner.invoke(main, args)
        assert result.exit_code == 1, result.output
        assert "weakens the built-in gates in CI" in result.stderr
        assert not result.stdout


def test_corroboration_refuses_an_invalid_project_policy(project_scope):
    runner, project, path = project_scope
    _write_project_policy(project, "unexpected_setting: harmless example\n")
    for args in _commands(project, path):
        result = runner.invoke(main, args)
        assert result.exit_code == 1, result.output
        assert "could not load validation settings" in result.stderr
        assert "harmless example" not in result.output
        assert not result.stdout
