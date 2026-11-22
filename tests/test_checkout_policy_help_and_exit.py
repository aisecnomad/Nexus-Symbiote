"""Public consent help agrees with checkout policy enforcement and exit modes."""

import pytest

from nexus_symbiote.cli import main


@pytest.mark.parametrize("command", ["scan", "risk", "validate", "baseline"])
def test_accept_policy_help_explains_mixed_settings(runner, command):
    help_text = runner.invoke(main, [command, "--help"])
    assert help_text.exit_code == 0
    words = " ".join(help_text.output.split())
    assert "Tightening settings apply automatically" in words
    assert "including in mixed policies" in words
    if command == "baseline":
        assert "built-in gates still check the staged inventory" in words
    else:
        assert "Operator policy always sets the minimum" in words


@pytest.mark.parametrize("command", ["scan", "validate", "risk"])
@pytest.mark.parametrize(("mode", "expected"), [(None, 1), ("--detailed-exit-codes", 4)])
def test_invalid_checkout_policy_exit_mode(runner, tmp_path, command, mode, expected):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Project notes.\n")
    inventory = tmp_path / "inventory.json"
    first = runner.invoke(main, ["scan", str(project), "-o", str(inventory)])
    assert first.exit_code == 0, first.output
    (project / ".nexus-symbiote.yaml").write_text("unrecognized_setting: value\n")
    args = (
        [str(project), "--check"]
        if command == "scan"
        else [str(inventory), "--project", str(project)]
    )
    result = runner.invoke(main, [command, *args, *([mode] if mode else [])])
    assert result.exit_code == expected, result.output
    assert "invalid policy" in result.output
