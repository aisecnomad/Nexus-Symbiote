"""A non-empty default exclude is a coverage gap until the operator accepts it."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.base import Scanner
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.utils.confined import ConfinedCollection

GAP = "node_modules: default collection exclude; not collected"


def test_agent_tree_excludes_are_reported_even_without_the_prompt_scanner(tmp_path: Path) -> None:
    excluded = tmp_path / ".claude" / "skills" / "node_modules"
    excluded.mkdir(parents=True)
    (excluded / "README.md").write_text("Fixture\n", encoding="utf-8")
    expected = (
        ".claude/skills/node_modules: default-excluded name inside an agent configuration "
        "directory; not collected"
    )

    for scanner in (MCPScanner(), PromptScanner()):
        result = scanner.scan(tmp_path)
        assert list(result.surfaces_excluded) == [expected]


def test_an_empty_default_exclude_is_not_a_gap(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "README.md").write_text("hello\n")
    gaps: list[str] = []
    with ConfinedCollection(tmp_path, [], gaps) as files:
        assert list(files.iter_files()) == [Path("README.md")]
    assert gaps == []


def test_a_nonempty_default_exclude_is_a_gap_until_accepted(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.json").write_text("{}\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / "README.md").write_text("hello\n")
    gaps: list[str] = []
    with ConfinedCollection(tmp_path, [], gaps) as files:
        assert list(files.iter_files()) == [Path("README.md")]
    assert GAP in gaps
    assert any(item.startswith(".git:") for item in gaps)
    accepted: list[str] = []
    with ConfinedCollection(tmp_path, [], accepted, accept_default_excludes=True) as files:
        assert list(files.iter_files()) == [Path("README.md")]
    assert accepted == []


def test_a_default_excluded_file_and_symlink_are_gaps(tmp_path: Path) -> None:
    (tmp_path / "venv").write_text("not a directory\n")
    (tmp_path / ".venv").symlink_to("venv")
    gaps: list[str] = []
    with ConfinedCollection(tmp_path, [], gaps) as files:
        assert list(files.iter_files()) == []
    assert "venv: default collection exclude; not collected" in gaps
    assert ".venv: default collection exclude; not collected" in gaps


def test_scan_fails_closed_and_the_flag_clears_the_collection_gap(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "node_modules").mkdir()
    (project / "node_modules" / "left.json").write_text("{}\n")
    (project / "AGENTS.md").write_text("Keep receipts.\n")
    runner = CliRunner()
    refused = runner.invoke(
        main, ["scan", str(project), "--report-only", "-o", str(tmp_path / "refused.json")]
    )
    assert refused.exit_code == 0, refused.output
    document = json.loads((tmp_path / "refused.json").read_text())
    assert GAP in document["metadata"]["completeness"]["surfaces_excluded"]
    accepted = runner.invoke(
        main,
        [
            "scan",
            str(project),
            "--report-only",
            "--accept-default-excludes",
            "-o",
            str(tmp_path / "accepted.json"),
        ],
    )
    assert accepted.exit_code == 0, accepted.output
    cleared = json.loads((tmp_path / "accepted.json").read_text())
    assert GAP not in cleared["metadata"]["completeness"]["surfaces_excluded"]


def test_validate_recollection_sees_the_same_flag(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "node_modules").mkdir()
    (project / "node_modules" / "left.json").write_text("{}\n")
    (project / "AGENTS.md").write_text("Keep receipts.\n")
    inventory = tmp_path / "bom.json"
    runner = CliRunner()
    scanned = runner.invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "--accept-default-excludes",
            "-o",
            str(inventory),
        ],
    )
    assert scanned.exit_code == 0, scanned.output
    refused = runner.invoke(
        main, ["validate", str(inventory), "--project", str(project), "--no-project-policy"]
    )
    assert refused.exit_code != 0
    assert "default collection exclude" in refused.output
    accepted = runner.invoke(
        main,
        [
            "validate",
            str(inventory),
            "--project",
            str(project),
            "--no-project-policy",
            "--accept-default-excludes",
            "--skip-integrity",
        ],
    )
    assert "default collection exclude" not in accepted.output


def test_scanner_configure_threads_the_flag(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.json").write_text("{}\n")
    scanner = MCPScanner()
    assert isinstance(scanner, Scanner)
    refused = scanner.scan(tmp_path)
    assert any("default collection exclude" in gap for gap in refused.surfaces_excluded)
    scanner.configure(accept_default_excludes=True)
    accepted = scanner.scan(tmp_path)
    assert not any("default collection exclude" in gap for gap in accepted.surfaces_excluded)
