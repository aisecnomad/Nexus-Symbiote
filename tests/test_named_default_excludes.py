"""Accepting checkout metadata leaves other occupied default names visible."""

import json
import subprocess
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.mcp import MCPScanner
from scripts import run_action


def test_action_scans_checkout_metadata_without_accepting_dependencies(tmp_path: Path) -> None:
    project = tmp_path / "checkout"
    metadata = project / ".git"
    metadata.mkdir(parents=True)
    (metadata / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (project / "AGENTS.md").write_text("Review the reports.\n", encoding="utf-8")
    action = yaml.safe_load((Path(__file__).parents[1] / "action.yml").read_text())
    config = run_action.Config.from_env(
        {
            "GITHUB_WORKSPACE": str(project),
            "SYMBIOTE_OUTPUT_FILE": "agentbom.json",
            "SYMBIOTE_ACCEPT_DEFAULT_EXCLUDES": action["inputs"]["accept-default-excludes"][
                "default"
            ],
        }
    )
    calls: list[list[str]] = []

    def command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        result = CliRunner().invoke(main, args)
        return subprocess.CompletedProcess(args, result.exit_code, result.stdout, result.stderr)

    assert run_action.run(config, command=command) == 0
    assert {args[0] for args in calls} == {"scan", "validate", "risk"}
    assert all("--accept-default-exclude=root:.git" in args for args in calls)
    inventory = project / "agentbom.json"
    claim = json.loads(inventory.read_text())["metadata"]["completeness"]
    assert ".git" in claim["exclusions"]
    assert "accepted default exclusion: .git" in claim["unobserved_surfaces"]
    assert not claim["surfaces_excluded"]
    inventory.unlink()

    dependency = project / "node_modules"
    dependency.mkdir()
    (dependency / "package.json").write_text("{}\n", encoding="utf-8")
    assert run_action.run(config, command=command) == 1
    claim = json.loads(inventory.read_text())["metadata"]["completeness"]
    assert claim["surfaces_excluded"] == ["node_modules: default collection exclude; not collected"]


def test_repeated_names_record_only_occupied_accepted_names(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Review the reports.\n", encoding="utf-8")
    (project / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
    (project / "Node_Modules").mkdir()
    (project / "Node_Modules" / "sample.txt").touch()
    (project / "venv").mkdir()
    inventory = tmp_path / "baseline.json"
    flags = [
        "--accept-default-exclude",
        ".git",
        "--accept-default-exclude",
        "node_modules",
        "--accept-default-exclude",
        "venv",
    ]
    runner = CliRunner()
    result = runner.invoke(main, ["baseline", str(project), "-o", str(inventory), *flags])
    assert result.exit_code == 0, result.output
    document = json.loads(inventory.read_text())
    unobserved = document["metadata"]["completeness"]["unobserved_surfaces"]
    assert sorted(s for s in unobserved if s.startswith("accepted default exclusion:")) == [
        "accepted default exclusion: .git",
        "accepted default exclusion: node_modules",
    ]
    unobserved.remove("accepted default exclusion: .git")
    inventory.write_text(json.dumps(document))
    checked = runner.invoke(main, ["validate", str(inventory), "--project", str(project), *flags])
    assert checked.exit_code != 0
    assert "accepted default exclusion: .git" in checked.output


def test_a_named_acceptance_keeps_the_agent_directory_gap_for_a_scoped_scan(tmp_path: Path) -> None:
    hidden = tmp_path / ".claude" / "skills" / ".git"
    hidden.mkdir(parents=True)
    (hidden / "HEAD").touch()
    scanner = MCPScanner()
    scanner.configure(accept_default_excludes=frozenset({".git"}))
    result = scanner.scan(tmp_path)
    assert any("inside an agent configuration directory" in gap for gap in result.surfaces_excluded)
    assert not result.accepted_default_names


def test_action_input_and_cli_reject_unknown_names(tmp_path: Path) -> None:
    inputs = {"GITHUB_WORKSPACE": str(tmp_path), "SYMBIOTE_ACCEPT_DEFAULT_EXCLUDES": "false"}
    assert run_action.Config.from_env(inputs).accept_default_excludes is False
    with pytest.raises(run_action.InputError, match="built-in exclusions"):
        run_action.Config.from_env({**inputs, "SYMBIOTE_ACCEPT_DEFAULT_EXCLUDES": "build"})
    assert (
        CliRunner()
        .invoke(main, ["scan", str(tmp_path), "--accept-default-exclude", "build"])
        .exit_code
        == 2
    )
    action = yaml.safe_load((Path(__file__).parents[1] / "action.yml").read_text())
    assert action["inputs"]["accept-default-excludes"]["default"] == "root:.git"
    assert any(
        step.get("env", {}).get("SYMBIOTE_ACCEPT_DEFAULT_EXCLUDES")
        == "${{ inputs.accept-default-excludes }}"
        for step in action["runs"]["steps"]
    )
