"""Exercise the published hook entries from an initialized Git checkout."""

import shlex
import shutil
import subprocess
from pathlib import Path

import yaml
from click.testing import CliRunner

from nexus_symbiote.cli import main


def test_published_hooks_accept_git_and_keep_dependency_gaps(tmp_path, monkeypatch):
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "--quiet", str(tmp_path)], check=True, timeout=30)  # noqa: S603
    (tmp_path / "AGENTS.md").write_text("Keep receipts.\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    hooks = yaml.safe_load((Path(__file__).parents[1] / ".pre-commit-hooks.yaml").read_text())
    runner = CliRunner()
    for hook in hooks:
        program, *args = shlex.split(hook["entry"])
        assert program == "nexus-symbiote"
        result = runner.invoke(main, args)
        assert result.exit_code == 0, (hook["id"], result.output)

    dependency = tmp_path / "node_modules"
    dependency.mkdir()
    (dependency / "README.md").write_text("A dependency.\n", encoding="utf-8")
    for hook in hooks:
        result = runner.invoke(main, shlex.split(hook["entry"])[1:])
        assert result.exit_code == 1, (hook["id"], result.output)
        assert "node_modules" in result.output
