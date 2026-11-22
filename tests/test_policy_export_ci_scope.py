"""Corroboration applies the project settings that govern its own evidence."""

import pytest

from nexus_symbiote.cli import main
from tests import test_policy_export_project_settings as settings_cases

project_scope = settings_cases.project_scope


@pytest.mark.parametrize(
    "settings",
    [
        "risk:\n  fail_threshold: 90\n",
        "risk:\n  ignore_categories: [example]\n",
        "validate:\n  require_integrity: false\n",
        "scan:\n  failure_mode: report-only\n",
    ],
)
def test_ci_accepts_settings_outside_corroboration(project_scope, monkeypatch, settings):
    runner, project, path = project_scope
    settings_cases._write_project_policy(project, settings)
    monkeypatch.setenv("CI", "true")
    for args in settings_cases._commands(project, path):
        result = runner.invoke(main, args)
        assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    ("settings", "diagnostic"),
    [
        ("not_a_setting: ordinary example\n", "invalid or unsupported settings"),
        ("scan: [\n", "invalid YAML"),
    ],
)
def test_corroboration_reports_why_the_policy_was_refused(project_scope, settings, diagnostic):
    runner, project, path = project_scope
    settings_cases._write_project_policy(project, settings)
    for args in settings_cases._commands(project, path):
        result = runner.invoke(main, args)
        assert result.exit_code == 1
        assert diagnostic in result.stderr
        assert "ordinary example" not in result.output
        assert not result.stdout
