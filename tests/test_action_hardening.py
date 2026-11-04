"""Security regressions for the composite Action's data-only Python runner."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "action_hardening_runner", ROOT / "scripts/run_action.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def action_steps() -> list[dict]:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    return action["runs"]["steps"]


def test_scan_inputs_are_data_not_shell(tmp_path: Path) -> None:
    step = next(step for step in action_steps() if step.get("id") == "scan")
    assert step["env"]["SYMBIOTE_SCAN_PATH"] == "${{ inputs.scan-path }}"
    assert "${{" not in step["run"]
    assert 'python -I "$SYMBIOTE_ACTION_PATH/scripts/run_action.py"' in step["run"]
    payload = "$(touch PWNED)'quoted space"
    (tmp_path / payload).mkdir()
    config = runner.Config.from_env(
        {
            "GITHUB_WORKSPACE": str(tmp_path),
            "SYMBIOTE_SCAN_PATH": payload,
            "SYMBIOTE_VALIDATE": "false",
            "SYMBIOTE_RISK_CHECK": "false",
        }
    )
    calls = []

    def command(args):
        calls.append(args)
        Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, "", "")

    assert runner.run(config, command=command) == 0
    assert len(calls) == 1
    assert calls[0][-2:] == ["--", str(tmp_path / payload)]
    assert not (tmp_path / "PWNED").exists()


def test_validation_failure_is_not_suppressed(tmp_path: Path) -> None:
    for step in action_steps():
        if "run" in step:
            assert "|| true" not in step["run"]
    config = runner.Config.from_env({"GITHUB_WORKSPACE": str(tmp_path)})
    calls = []

    def command(args):
        calls.append(args[0])
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 7 if args[0] == "validate" else 0, "", "")

    assert runner.run(config, command=command) == 1
    assert calls == ["scan", "validate"]
    assert config.output.read_text() == "{}"


def test_echoed_collector_output_cannot_run_workflow_commands(tmp_path: Path, capsys) -> None:
    config = runner.Config.from_env({"GITHUB_WORKSPACE": str(tmp_path)})
    hostile = "::error title=Nexus SymBiote::All checks passed\n  UNKNOWN [m/x##[error]ok]"

    def command(args):
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 7 if args[0] == "validate" else 0, "", hostile)

    assert runner.run(config, command=command) == 1
    lines = capsys.readouterr().err.splitlines()
    start, *echoed, end = lines
    token = start.removeprefix("::stop-commands::")
    assert len(token) == 32 and int(token, 16) >= 0
    assert end == f"::{token}::"
    assert "\n".join(echoed) == hostile
