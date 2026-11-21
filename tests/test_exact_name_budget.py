"""Exact-spelling fallback listings share the collection's entry budget."""

import json
import os
import unicodedata
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.utils.confined import ConfinedCollection

_SPENT = "entries limit of 20 exceeded"


def _tree(root, count=20):
    (root / "CLAUDE.md").write_text("instructions")
    (root / "claude.MD").write_text("variant")
    for index in range(count):
        (root / f"filler-{index}").touch()


def _variant_tree(root, count=20):
    _tree(root, count)
    if (root / "CLAUDE.md").read_text() != "instructions":
        pytest.skip("needs a case-sensitive file system to hold both spellings")


@pytest.mark.parametrize("operation", ["read", "metadata", "directory"])
def test_exact_spelling_fails_closed_before_caching_an_oversized_directory(tmp_path, operation):
    _tree(tmp_path)
    (tmp_path / "123").mkdir()
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=10) as files:
        if operation == "read":
            assert files.read_text("CLAUDE.md") is None
        elif operation == "metadata":
            assert files.regular_file("CLAUDE.md") is None
        else:
            assert not files.is_directory("123")
        assert not files._exact_names
        assert files.root_entries() == []
        assert list(files.iter_files()) == []
    assert any("entries limit of 10 exceeded" in failure for failure in failures)


def test_cached_exact_names_are_not_charged_again(tmp_path):
    _variant_tree(tmp_path, count=1)
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=3) as files:
        assert files.read_text("CLAUDE.md") == "instructions"
        assert files.read_text("CLAUDE.md") == "instructions"
        assert files._entry_budget == [0]
        assert len(next(iter(files._exact_names.values()))[1]) == 3
    assert not failures


def test_exact_name_listing_and_walk_spend_the_same_budget(tmp_path):
    _variant_tree(tmp_path, count=1)
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=5) as files:
        assert files.read_text("CLAUDE.md") == "instructions"
        assert list(files.iter_files()) == []
    assert any("entries limit of 5 exceeded" in failure for failure in failures)


def test_changed_directory_cannot_reuse_or_replace_its_bounded_cache(tmp_path):
    _variant_tree(tmp_path, count=1)
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=5) as files:
        assert files.read_text("CLAUDE.md") == "instructions"
        (tmp_path / "new-a").mkdir()
        for name in ("new-b", "new-c"):
            (tmp_path / name).touch()
        assert files.read_text("CLAUDE.md") is None
        assert all(len(names) <= 3 for _, names in files._exact_names.values())
    assert any("entries limit of 5 exceeded" in failure for failure in failures)


@pytest.mark.parametrize("changed_field", ["st_size", "st_nlink"])
def test_same_tick_size_or_nlink_change_invalidates_exact_name_cache(
    tmp_path, monkeypatch, changed_field
):
    _variant_tree(tmp_path, count=1)
    failures = []
    real_fstat = os.fstat
    root_identity = (tmp_path.stat().st_dev, tmp_path.stat().st_ino)
    frozen_root_stat = None
    mutate_field = False

    def fake_fstat(fd: int) -> os.stat_result:
        nonlocal frozen_root_stat
        info = real_fstat(fd)
        if (info.st_dev, info.st_ino) != root_identity:
            return info
        if frozen_root_stat is None:
            frozen_root_stat = info
            return info
        if not mutate_field:
            return frozen_root_stat
        values = list(frozen_root_stat)
        if changed_field == "st_size":
            values[6] = frozen_root_stat.st_size + 39
        else:
            values[3] = frozen_root_stat.st_nlink + 1
        return os.stat_result(
            values,
            {
                "st_atime_ns": frozen_root_stat.st_atime_ns,
                "st_mtime_ns": frozen_root_stat.st_mtime_ns,
                "st_ctime_ns": frozen_root_stat.st_ctime_ns,
            },
        )

    monkeypatch.setattr(os, "fstat", fake_fstat)
    with ConfinedCollection(tmp_path, failures, max_entries=5) as files:
        assert files.read_text("CLAUDE.md") == "instructions"
        for name in ("new-a", "new-b", "new-c"):
            (tmp_path / name).touch()
        mutate_field = True
        assert files.read_text("CLAUDE.md") is None
        assert all(len(names) <= 3 for _, names in files._exact_names.values())
    assert any("entries limit of 5 exceeded" in failure for failure in failures)


def test_non_ascii_exact_name_is_also_bounded(tmp_path):
    _tree(tmp_path)
    (tmp_path / "café").write_text("instructions")
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=10) as files:
        assert files.read_text(Path("café")) is None
        assert not files._exact_names
    assert any("entries limit of 10 exceeded" in failure for failure in failures)


def _spent_tree(root: Path) -> None:
    (root / "0bulk").mkdir()
    for index in range(30):
        (root / "0bulk" / f"f{index}").write_text("x")
    # "123" has no other case, so checking its exact spelling lists the root.
    (root / "123").write_text("target")
    (root / "1link").symlink_to("123")


def test_symlink_met_after_the_entry_budget_is_spent_ends_the_walk(tmp_path):
    _spent_tree(tmp_path)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=20) as files:
        assert list(files.iter_files()) == [Path("123")]
    assert [failure.split(";")[0] for failure in failures] == [f"0bulk: {_SPENT}"]


def _listed_variant_tree(root: Path) -> None:
    composed = unicodedata.normalize("NFC", "café")
    decomposed = unicodedata.normalize("NFD", "café")
    # "1" has no other case, so opening it lists the directory that holds it.
    (root / composed / "1").mkdir(parents=True)
    (root / composed / "1" / "present.json").write_text("{}")
    try:
        (root / decomposed / "1").mkdir(parents=True)
    except FileExistsError:
        # The file system folds Unicode normalization, as APFS does.
        pytest.skip("file system rejects the name")
    (root / "bulk").mkdir()
    for index in range(30):
        (root / "bulk" / f"f{index}").write_text("x")


@pytest.mark.parametrize("operation", ["read_json", "case_variants"])
def test_case_variant_search_after_the_entry_budget_is_spent_ends_quietly(tmp_path, operation):
    _listed_variant_tree(tmp_path)
    prefix = Path(unicodedata.normalize("NFC", "café"), "1")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=20) as files:
        assert files.read_json(prefix / "present.json") == {}
        assert list(files.iter_files("bulk")) == []
        assert [failure.split(";")[0] for failure in failures] == [f"bulk: {_SPENT}"]
        if operation == "read_json":
            assert files.read_json(prefix / "missing.json", missing_ok=True) is None
        else:
            assert files.case_variants(prefix / "missing.json") == []
    assert [failure.split(";")[0] for failure in failures] == [f"bulk: {_SPENT}"]


def test_scan_keeps_what_collectors_found_once_the_entry_budget_is_spent(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"server": {"command": "node", "args": ["x.js"]}}})
    )
    _spent_tree(project)
    sensitive = not (project / ".MCP.JSON").exists()
    output = tmp_path / "inventory.json"
    result = CliRunner().invoke(
        main,
        ["--limit", "entries=20", "scan", str(project), "--no-project-policy", "-o", str(output)],
    )
    assert result.exit_code == 1
    assert "scanner-input-error" not in result.output
    inventory = json.loads(output.read_text())
    failures = inventory["metadata"]["completeness"]["scan_failures"]
    spent = {f"0bulk: {_SPENT}; raise it with --limit entries=N"}
    if sensitive:
        assert failures and set(failures) == spent
        assert "server" in {component["name"] for component in inventory["components"]}
    else:
        # A case-insensitive file system confirms the exact spelling only by listing the
        # directory, which the spent budget refuses, so the file is a named failure.
        assert failures and set(failures) == {
            *spent,
            f".mcp.json: {_SPENT}; raise it with --limit entries=N",
        }
