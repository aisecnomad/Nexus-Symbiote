"""Reconciliation and drift retain accepted paths beyond both listing limits."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.utils import confined


@pytest.mark.parametrize("bound", ["MAX_LISTED_FAILURES", "MAX_LISTED_FAILURE_CHARACTERS"])
def test_moving_an_unlisted_accepted_directory_changes_the_receipt(tmp_path, monkeypatch, bound):
    monkeypatch.setattr(confined, bound, 2 if bound == "MAX_LISTED_FAILURES" else 40)
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "AGENTS.md").write_text("Read the project notes.\n")
    for name in ("aa", "bb", "cc", "dd", "ee", "ff"):
        path = root / name / "node_modules"
        path.mkdir(parents=True)
        (path / "notes.txt").write_text("Sample.\n")
    runner = CliRunner()
    flags = ["--no-project-policy", "--accept-default-exclude=node_modules"]
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    scan = ["scan", str(root), *flags]
    assert runner.invoke(main, [*scan, "-o", str(old)]).exit_code == 0

    def reconcile(command):
        return runner.invoke(
            main, [command, str(old), "--project", str(root), *flags, "--json-output"]
        )

    for command in ("validate", "risk"):
        unchanged = reconcile(command)
        assert unchanged.exit_code == 0, unchanged.output
    (root / "ff").rename(root / "zz")
    for command in ("validate", "risk"):
        moved = reconcile(command)
        assert moved.exit_code == 1, moved.output
        assert "accepted default exclusion" in moved.output
    assert runner.invoke(main, [*scan, "-o", str(new)]).exit_code == 0
    before = json.loads(old.read_text())["metadata"]["completeness"]
    after = json.loads(new.read_text())["metadata"]["completeness"]
    assert before["unobserved_surfaces"] != after["unobserved_surfaces"]
    drift = runner.invoke(main, ["diff", str(old), str(new), "--fail-on-alert"])
    assert drift.exit_code == 1, drift.output
