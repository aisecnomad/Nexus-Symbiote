"""Exercise project corroboration through both public evidence commands."""

import json
import struct

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.validators.completeness import CompletenessValidator
from tests.test_policy_export_project_settings import _commands, _write_project_policy


@pytest.fixture
def model_project(tmp_path, runner):
    project = tmp_path / "project"
    models = project / "models"
    models.mkdir(parents=True)
    model = models / "sample.safetensors"
    header = b'{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    header += b" " * (-len(header) % 8)
    model.write_bytes(struct.pack("<Q", len(header)) + header + struct.pack("<f", 1.0))
    inventory = tmp_path / "inventory.json"
    result = runner.invoke(main, ["scan", str(project), "-o", str(inventory)])
    assert result.exit_code == 0, result.output
    return project, inventory, model


def test_ci_refusal_names_the_policy_field_and_exclusion_count(runner, model_project, monkeypatch):
    project, inventory, _model = model_project
    _write_project_policy(project, "scan:\n  exclude_paths: ['node_modules/', 'absent']\n")
    monkeypatch.setenv("CI", "true")
    for args in _commands(project, inventory):
        result = runner.invoke(main, args)
        assert result.exit_code == 1, result.output
        assert "scan.exclude_paths" in result.stderr
        assert "2 additional" in result.stderr
        assert not result.stdout


def test_invalid_policy_key_has_a_bounded_single_line_diagnostic(runner, model_project):
    project, inventory, _model = model_project
    key = "example\n\x1bpolicy-field-" + "a" * 4_000
    _write_project_policy(project, f"? {json.dumps(key)}\n: sample value\n")
    for args in _commands(project, inventory):
        result = runner.invoke(main, args)
        assert result.exit_code == 1, result.output
        assert "invalid or unsupported settings" in result.stderr
        assert len(result.stderr.splitlines()) == 1
        assert "\x1b" not in result.stderr
        assert "sample value" not in result.stderr
        assert len(result.stderr) <= 1_100
        assert not result.stdout


def test_ci_checks_model_integrity_even_if_checkout_disables_it(runner, model_project, monkeypatch):
    project, inventory, model = model_project
    _write_project_policy(project, "validate:\n  require_integrity: false\n")
    monkeypatch.setenv("CI", "true")
    original = model.read_bytes()
    verify_completeness = CompletenessValidator.validate_against_project

    def change_model_after_reconciliation(self, *args, **kwargs):
        report = verify_completeness(self, *args, **kwargs)
        assert report.is_complete
        model.write_bytes(original[:-4] + struct.pack("<f", 2.0))
        return report

    for args in _commands(project, inventory):
        model.write_bytes(original)
        result = runner.invoke(main, args)
        assert result.exit_code == 0, result.output
        with monkeypatch.context() as patch:
            patch.setattr(
                CompletenessValidator, "validate_against_project", change_model_after_reconciliation
            )
            result = runner.invoke(main, args)
        assert result.exit_code == 1, result.output
        assert "failed integrity validation" in result.stderr
        assert not result.stdout
