"""Step summaries can be reused without mutating files read by the gate."""

import os

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main


@pytest.mark.parametrize("location", ["report.md", "ci/reports/summary.md"])
def test_validate_and_risk_append_to_the_same_project_report(tmp_path, location):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Consult the guide.\n")
    inventory = tmp_path / "inventory.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", str(project), "-o", str(inventory)])
    assert scan.exit_code == 0, scan.output
    summary = project / location
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text("Earlier report.\n")
    for gate in ("validate", "risk"):
        result = runner.invoke(
            main,
            [gate, str(inventory), "--project", str(project), "--step-summary", str(summary)],
        )
        assert result.exit_code == 0, result.output
    rendered = summary.read_text()
    assert rendered.startswith("Earlier report.\n")
    assert rendered.count("### Nexus SymBiote validate:") == 1
    assert rendered.count("### Nexus SymBiote risk:") == 1


def test_invalid_summary_is_a_controlled_output_error(tmp_path):
    from nexus_symbiote.core.aibom import AIBOM

    inventory = tmp_path / "inventory.json"
    AIBOM().save(inventory)
    result = CliRunner().invoke(main, ["validate", str(inventory), "--step-summary", "notes\0file"])
    assert result.exit_code == 1
    assert "output" in result.output.lower() and "internal error" not in result.output.lower()


def test_gate_keeps_an_imported_project_report_intact(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Read @report.md\n")
    summary = project / "report.md"
    original = b"Project reference.\n"
    summary.write_bytes(original)
    inventory = tmp_path / "inventory.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(project), "-o", str(inventory)]).exit_code == 0
    for gate in ("validate", "risk"):
        result = runner.invoke(
            main,
            [gate, str(inventory), "--project", str(project), "--step-summary", str(summary)],
        )
        assert result.exit_code == 2 and "--step-summary" in result.output
        assert summary.read_bytes() == original


def test_existing_hard_linked_report_is_unchanged(tmp_path):
    from nexus_symbiote.core.aibom import AIBOM

    inventory = tmp_path / "inventory.json"
    AIBOM().save(inventory)
    project = tmp_path / "project"
    project.mkdir()
    summary = project / "report.md"
    summary.write_text("Earlier report.\n")
    os.link(summary, tmp_path / "other.md")
    result = CliRunner().invoke(
        main,
        ["validate", str(inventory), "--project", str(project), "--step-summary", str(summary)],
    )
    assert result.exit_code in {1, 2}
    assert summary.read_text() == "Earlier report.\n"
