"""A reviewed checkout may omit its Git metadata and only the occupied paths it recorded."""

import json
import shutil
import subprocess

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.mcp import MCPScanner
from scripts import verify_staged_policy


@pytest.mark.parametrize("kind", ["nested", "folded", "ordinary", "linked-head", "gitfile", "link"])
def test_git_acceptance_requires_exact_root_metadata(tmp_path, kind):
    entry = {"nested": "src/.git", "folded": ".g\u200dit"}.get(kind, ".git")
    path = tmp_path / entry
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "gitfile":
        path.write_text("ordinary checkout file\n")
    elif kind == "link":
        (tmp_path / "ordinary").write_text("gitdir: elsewhere\n")
        path.symlink_to(tmp_path / "ordinary")
    else:
        path.mkdir()
        if kind == "linked-head":
            (tmp_path / "ordinary").write_text("ref: refs/heads/main\n")
            (path / "HEAD").symlink_to(tmp_path / "ordinary")
        else:
            (path / ("notes.txt" if kind == "ordinary" else "HEAD")).write_text("project notes\n")
    scanner = MCPScanner()
    scanner.configure(accept_default_excludes=(".git",))
    result = scanner.scan(tmp_path)
    assert result.surfaces_excluded, kind
    assert not result.accepted_default_names


@pytest.mark.parametrize("added", ["node_modules", "client/node_modules"])
@pytest.mark.parametrize("command", ["validate", "risk"])
def test_new_occupied_path_requires_a_new_record(tmp_path, added, command):
    project = tmp_path / "project"
    existing = project / "old" / "node_modules"
    existing.mkdir(parents=True)
    (existing / "package.json").write_text("{}")
    (project / "AGENTS.md").write_text("Review the reports.\n")
    inventory = tmp_path / "baseline.json"
    flags = ["--no-project-policy", "--accept-default-exclude=node_modules"]
    runner = CliRunner()
    recorded = runner.invoke(main, ["scan", str(project), "-o", str(inventory), *flags])
    assert recorded.exit_code == 0, recorded.output
    args = [command, str(inventory), "--project", str(project), *flags, "--json-output"]
    clean = runner.invoke(main, args)
    assert clean.exit_code == 0, clean.output
    added_path = project / added
    added_path.mkdir(parents=True)
    (added_path / "package.json").write_text("{}")
    changed = runner.invoke(main, args)
    assert changed.exit_code == 1, changed.output
    assert added in json.dumps(json.loads(changed.stdout))


def test_real_git_checkout_works_in_staged_policy_and_keeps_dependency_gaps(tmp_path):
    project = tmp_path / "checkout"
    project.mkdir()
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "--quiet", str(project)], check=True, timeout=10)  # noqa: S603
    (project / "AGENTS.md").write_text("Review the reports.\n")
    operator = tmp_path / "policy.yaml"
    operator.write_text("version: '1.0'\n")
    code, text = verify_staged_policy.run_staged_gate(project, operator, allow_unsigned=True)
    assert code == 0, text
    dependency = project / "node_modules"
    dependency.mkdir()
    (dependency / "package.json").write_text("{}")
    failed, text = verify_staged_policy.run_staged_gate(project, operator, allow_unsigned=True)
    assert failed == 1 and "node_modules" in text


@pytest.mark.parametrize("head", ["ref: refs/heads/topic\r\n", "a" * 40, "b" * 64])
def test_root_symbolic_or_detached_head_is_recognized(tmp_path, head):
    directory = tmp_path / ".git"
    directory.mkdir()
    (directory / "HEAD").write_bytes(head.encode())
    scanner = MCPScanner()
    scanner.configure(accept_default_excludes=(".git",))
    result = scanner.scan(tmp_path)
    assert result.accepted_default_exclusions == [".git"]
    assert not result.surfaces_excluded


def test_staged_gate_can_explicitly_refuse_root_git_metadata(tmp_path):
    project = tmp_path / "checkout"
    project.mkdir()
    (project / "AGENTS.md").write_text("Review the reports.\n")
    (project / ".git").write_text("gitdir: ../outside-this-checkout\n")
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: '1.0'\n")
    args = [
        "--project",
        str(project),
        "--operator-policy",
        str(policy),
        "--allow-unsigned-operator-policy",
    ]
    assert verify_staged_policy.main(args) == 0
    assert verify_staged_policy.main([*args, "--no-accept-default-excludes"]) == 1
    assert verify_staged_policy.main([*args, "--accept-default-exclude", "venv"]) == 1
    assert (
        verify_staged_policy.main(
            [*args, "--accept-default-exclude", ".git", "--accept-default-exclude", "venv"]
        )
        == 0
    )
