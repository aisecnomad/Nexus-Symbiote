"""A project policy that picks another export format changes what ``scan -o`` writes.

Every setting that changes reported results is listed under ``policy_weakened`` and
warned about, so a checkout cannot silently replace the native inventory a workflow
expects with a SARIF or CycloneDX document under the same file name.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.policy import Policy, weakened_settings


def test_a_non_native_default_format_is_a_weakened_setting() -> None:
    relaxed = Policy.model_validate({"output": {"default_format": "cyclonedx"}})
    assert weakened_settings(relaxed) == ["output.default_format=cyclonedx"]
    assert weakened_settings(Policy.model_validate({"output": {"default_format": "json"}})) == []


def test_scan_warns_when_the_project_policy_selects_another_format(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".nexus-symbiote.yaml").write_text('output:\n  default_format: "cyclonedx"\n')
    output = tmp_path / "inventory.json"
    run = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--report-only",
            "--accept-project-policy",
            "-o",
            str(output),
        ],
        catch_exceptions=False,
    )
    assert run.exit_code == 0, run.output
    assert "weakens the built-in gates" in run.output
    assert "output.default_format=cyclonedx" in run.output
    assert json.loads(output.read_text())["bomFormat"] == "CycloneDX"
