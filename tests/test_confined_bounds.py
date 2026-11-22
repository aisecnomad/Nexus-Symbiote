"""The confined reader's bounds: named failures, shared budgets, odd names and operator paths."""

from __future__ import annotations

import errno
import os
import tracemalloc
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import open_regular_file, pathname_identity
from nexus_symbiote.limits import Bound
from nexus_symbiote.scanners.base import ScanResult, source_collection_bytes
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.utils.confined import (
    MAX_LISTED_FAILURE_CHARACTERS,
    MAX_LISTED_FAILURES,
    ConfinedCollection,
)
from tests.support import scaling_ratio


def _refused_link(link: Path, target: Path) -> None:
    # In-root links to regular files and directories are followed; an absolute target
    # is a per-entry failure, which these tests need in large numbers.
    os.symlink(str(target), link)


REFUSED = "symlink target is absolute"


def _undecodable(directory: Path, raw: bytes, content: bytes = b"x = 1\n") -> Path:
    path = directory / os.fsdecode(raw)
    try:
        path.write_bytes(content)
    except (OSError, UnicodeEncodeError):
        pytest.skip("file system rejects names that are not UTF-8")
    return path


def test_depth_limit_is_a_named_failure(tmp_path):
    deep = tmp_path.joinpath(*(f"d{level}" for level in range(5)))
    deep.mkdir(parents=True)
    (deep / "hidden.txt").write_text("deep")
    (tmp_path / "top.txt").write_text("top")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_depth=3) as files:
        assert list(files.iter_files()) == [Path("top.txt")]
    assert failures == [
        "d0/d1/d2/d3: depth limit of 3 exceeded; this limit is fixed for this input"
    ]
    failures = []
    with (
        limits.applied(replace(limits.DEFAULTS, depth=3)),
        ConfinedCollection(tmp_path, failures) as files,
    ):
        list(files.iter_files())
    assert failures == ["d0/d1/d2/d3: depth limit of 3 exceeded; raise it with --limit depth=N"]


def test_entry_budget_is_shared_by_every_listing_of_one_collection(tmp_path):
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        for index in range(3):
            (tmp_path / name / f"{index}.txt").write_text("")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=5) as files:
        assert len(list(files.iter_files("a"))) == 3
        assert list(files.iter_files("b")) == []
    assert failures == ["b: entries limit of 5 exceeded; this limit is fixed for this input"]


def test_an_exhausted_entry_budget_is_reported_once(tmp_path):
    for name in ("a", "b", "c", "d"):
        (tmp_path / name).mkdir()
        for index in range(3):
            (tmp_path / name / f"{index}.txt").write_text("")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=8) as files:
        found = list(files.iter_files())
        assert files.root_entries() == []
    assert found == [Path("a/0.txt"), Path("a/1.txt"), Path("a/2.txt")]
    assert failures == ["b: entries limit of 8 exceeded; this limit is fixed for this input"]


def test_root_listing_is_charged_to_the_entry_budget(tmp_path):
    for index in range(5):
        (tmp_path / f"{index}.txt").write_text("")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=4) as files:
        assert files.root_entries() == []
    assert failures == [".: entries limit of 4 exceeded; this limit is fixed for this input"]
    with ConfinedCollection(tmp_path, [], max_entries=5) as files:
        assert files.root_entries() == [f"{index}.txt" for index in range(5)]
        assert list(files.iter_files()) == []


def test_size_failures_name_the_limit_and_never_quote_content(tmp_path):
    (tmp_path / "big.json").write_text('{"token": "CANARY-SECRET-0123456789"}')
    (tmp_path / "small.txt").write_text("1234")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_file_bytes=16, max_total_bytes=6) as files:
        assert files.read_json("big.json") is None
        assert files.read_text("small.txt") == "1234"
        assert files.hash_file("small.txt") is None
    assert failures == [
        "big.json: file-bytes limit of 16 bytes exceeded; this limit is fixed for this input",
        "small.txt: total-bytes limit of 6 bytes exceeded; this limit is fixed for this input",
    ]
    failures = []
    configured = replace(limits.DEFAULTS, file_bytes=16)
    with limits.applied(configured), ConfinedCollection(tmp_path, failures) as files:
        assert files.read_bytes("big.json") is None
        with pytest.raises(OSError), files.open_regular("big.json"):
            pass
    assert failures == [
        "big.json: file-bytes limit of 16 bytes exceeded; raise it with --limit file-bytes=N"
    ]
    assert "CANARY" not in repr(failures)


def test_stream_budget_names_the_bound_that_stopped_it(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"x" * 64)
    failures: list[str] = []
    budget = Bound(32, "model-total-bytes")
    with (
        ConfinedCollection(tmp_path, failures, max_total_bytes=budget) as files,
        pytest.raises(ValueError),
        files.open_regular("a.bin", max_bytes=128) as stream,
    ):
        while stream.read(16):
            pass
    assert failures == [
        "a.bin: model-total-bytes limit of 32 bytes exceeded; "
        "raise it with --limit model-total-bytes=N"
    ]


def test_a_stream_reads_again_only_what_it_read_and_charges_it_once(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"0123456789")
    failures: list[str] = []
    with (
        ConfinedCollection(tmp_path, failures, max_total_bytes=6) as files,
        files.open_regular("a.bin") as stream,
    ):
        assert stream.read(6) == b"012345"
        assert stream.reread(2, 4) == b"2345"
        assert stream.reread(0, 6) == b"012345"
        with pytest.raises(ValueError, match="already read"):
            stream.reread(4, 3)
        with pytest.raises(ValueError, match="already read"):
            stream.reread(-1, 1)
    assert failures == []


def test_a_file_that_does_not_fit_leaves_the_byte_budget_to_files_that_do(tmp_path):
    # The mcp and a2a source searches stop at the first refused file once the budget
    # is spent, so a file refused for its size must not mark it spent.
    for name, size in (("a", 8), ("b", 5), ("c", 1), ("d", 4)):
        (tmp_path / name).write_bytes(b"x" * size)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_total_bytes=10) as files:
        assert files.read_bytes("a") == b"x" * 8
        assert files.read_bytes("b") is None
        assert files.hash_file("b") is None
        assert not files.bytes_exhausted
        assert files.read_bytes("c") == b"x"
        with pytest.raises(ValueError), files.open_regular("d") as stream:
            stream.read(16)
        assert files.bytes_exhausted
        assert files.read_bytes("c") is None
    assert failures == [
        f"{name}: total-bytes limit of 10 bytes exceeded; this limit is fixed for this input"
        for name in ("b", "d", "c")
    ]


def test_overflowing_json_numbers_are_invalid_json(tmp_path):
    (tmp_path / "x.json").write_text('{"maximum": 1e400}')
    (tmp_path / "y.json").write_text('{"minimum": -1E999, "ok": 1e-400}')
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json("x.json") is None
        assert files.read_json("y.json") is None
    assert failures == [
        "x.json: invalid JSON or duplicate keys",
        "y.json: invalid JSON or duplicate keys",
    ]
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"s": {"tools": [{"name": "t", "inputSchema": {"maximum": 1e400}}]}}}'
    )
    assert MCPScanner().scan(tmp_path).scan_failures == [
        ".mcp.json: invalid JSON or duplicate keys"
    ]


def test_undecodable_and_unparsable_files_are_listed_once_under_the_root_relative_path(
    tmp_path,
):
    (tmp_path / "bad.txt").write_bytes(b"\xff")
    (tmp_path / "bad.json").write_text("{")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        for name in ("bad.txt", "bad.json"):
            for spelling in (name, f"./{name}", tmp_path / name):
                assert files.read_json(spelling) is None
    assert failures == ["bad.txt: invalid UTF-8", "bad.json: invalid JSON or duplicate keys"]


def test_policy_exclusion_checks_do_not_grow_with_the_number_of_entries(tmp_path):
    # Files and exclusions grow together, so checking each file against every
    # exclusion grows with the square of the size.
    roots = {}
    for scale in (1, 4):
        roots[scale] = tmp_path / f"scale-{scale}"
        (roots[scale] / "x000123").mkdir(parents=True)
        (roots[scale] / "x000123" / "hidden.py").write_text("")
        for index in range(75 * scale):
            (roots[scale] / f"f{index}.py").write_text("")

    def walk(scale: int) -> tuple[list[Path], list[str]]:
        surfaces: list[str] = []
        exclusions = [f"x{index:06d}" for index in range(5_000 * scale)]
        with ConfinedCollection(roots[scale], [], surfaces, exclude_paths=exclusions) as files:
            return list(files.iter_files()), surfaces

    assert scaling_ratio(walk) < 10
    found, surfaces = walk(4)
    assert len(found) == 300
    assert surfaces == ["x000123: excluded by collection policy"]


def test_a_walk_records_tens_of_thousands_of_messages_in_linear_time(tmp_path):
    # Checking each new message against the list made 95,000 symlinks a 70 s walk.
    count = 50_000
    names: dict[int, list[str]] = {}
    roots = {}
    for scale in (1, 4):
        roots[scale] = tmp_path / f"scale-{scale}"
        roots[scale].mkdir()
        (roots[scale] / "target").write_text("x")
        names[scale] = [f"l{index:05d}" for index in range(count // 4 * scale)]
        for name in names[scale]:
            _refused_link(roots[scale] / name, roots[scale] / "target")

    def refused(scale: int) -> list[str]:
        failures: list[str] = []
        with ConfinedCollection(roots[scale], failures) as files:
            assert list(files.iter_files()) == [Path("target")]
        return failures

    def excluded(scale: int) -> list[str]:
        exclusions: list[str] = []
        with ConfinedCollection(roots[scale], [], exclusions, exclude_paths=names[scale]) as files:
            assert list(files.iter_files()) == [Path("target")]
        return exclusions

    assert scaling_ratio(refused) < 10
    failures = refused(4)
    assert len(failures) == MAX_LISTED_FAILURES + 1
    assert failures[-1] == f"l01000: {REFUSED} (and {count - 1_001} more not listed)"
    assert scaling_ratio(excluded) < 10
    # Each exclusion names a path of the operator's policy, so their text is bounded already.
    assert len(excluded(4)) == count


def test_failures_past_the_listing_bounds_are_summarized_by_reason(tmp_path):
    (tmp_path / "target").write_text("x")
    for index in range(MAX_LISTED_FAILURES + 20):
        _refused_link(tmp_path / f"l{index:05d}", tmp_path / "target")
    os.mkfifo(tmp_path / "pipe")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        list(files.iter_files())
        with files.bounded_failures():
            assert files.read_bytes("missing.json") is None
            assert files.read_bytes("other.json") is None
        assert files.read_bytes("outside.json") is None
    assert failures[: MAX_LISTED_FAILURES + 1] == [
        *(f"l{index:05d}: {REFUSED}" for index in range(MAX_LISTED_FAILURES)),
        f"l{MAX_LISTED_FAILURES:05d}: {REFUSED} (and 19 more not listed)",
    ]
    # Every reason is still recorded, and failures outside a bounded block are listed.
    assert failures[MAX_LISTED_FAILURES + 1 :] == [
        "pipe: nonregular file excluded",
        "missing.json: file unavailable during collection (and 1 more not listed)",
        "outside.json: file unavailable during collection",
    ]


def test_long_paths_are_listed_only_up_to_the_character_bound(tmp_path):
    (tmp_path / "target").write_text("x")
    for index in range(2_000):
        _refused_link(tmp_path / (f"l{index:04d}" + "x" * 240), tmp_path / "target")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        list(files.iter_files())
    assert sum(len(failure) for failure in failures[:-1]) <= MAX_LISTED_FAILURE_CHARACTERS
    assert len(failures) < 300
    assert failures[-1].endswith("more not listed)")


def test_every_walk_that_meets_a_failure_still_adds_one(tmp_path):
    # Collectors compare the failure count before and after a walk to learn whether
    # the listing they got is complete; that must hold past the listing bound.
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "target").write_text("x")
    (tmp_path / "b" / "target").write_text("x")
    for index in range(MAX_LISTED_FAILURES + 5):
        _refused_link(tmp_path / "a" / f"l{index:05d}", tmp_path / "a" / "target")
    _refused_link(tmp_path / "b" / "link", tmp_path / "b" / "target")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert list(files.iter_files("a")) == [Path("a/target")]
        before = len(failures)
        assert list(files.iter_files("b")) == [Path("b/target")]
        assert len(failures) == before + 1
    assert failures[-2:] == [
        f"a/l{MAX_LISTED_FAILURES:05d}: {REFUSED} (and 4 more not listed)",
        f"b/link: {REFUSED}",
    ]


def test_a_tree_of_failing_entries_still_yields_an_inventory_that_loads(tmp_path):
    # Every walking collector failed once per symlink: 20,000 long names made a 23 MB
    # inventory that validate, risk and diff refused to read.
    project = tmp_path / "project"
    project.mkdir()
    (project / "target").write_text("x")
    for index in range(20_000):
        _refused_link(project / (f"l{index:05d}" + "x" * 195), project / "target")
    output = tmp_path / "out.json"
    runner = CliRunner()
    scan = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    assert runner.invoke(main, scan).exit_code == 0
    assert output.stat().st_size < 2 * limits.MIB
    claim = AIBOM.load(output).metadata.completeness
    assert claim is not None
    summaries = [failure for failure in claim.scan_failures if "more not listed" in failure]
    assert summaries
    assert all(f": {REFUSED} (and " in failure for failure in summaries)
    result = runner.invoke(main, ["validate", str(output)])
    assert "not a valid native AIBOM file" not in result.output


def test_every_failure_a_collection_records_is_listed_within_the_bounds(tmp_path):
    # Only walks and bounded blocks were bounded: one read after another listed them all.
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        for index in range(MAX_LISTED_FAILURES + 20):
            assert files.read_bytes(f"m{index:05d}.json") is None
    assert len(failures) == MAX_LISTED_FAILURES + 1
    assert failures[-1] == (
        f"m{MAX_LISTED_FAILURES:05d}.json: file unavailable during collection "
        "(and 19 more not listed)"
    )


def test_case_variants_past_the_bounds_are_summed_up_in_one_line(tmp_path):
    # The reason names the path that was asked for, so one line per reason was one
    # line per variant.
    count = MAX_LISTED_FAILURES + 20
    for index in range(count):
        (tmp_path / f"d{index:05d}").mkdir()
        (tmp_path / f"d{index:05d}" / "Settings.json").write_text("{}")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        for index in range(count):
            assert files.read_bytes(f"d{index:05d}/settings.json", missing_ok=True) is None
    listed, summary = failures[:-1], failures[-1]
    assert sum(map(len, listed)) <= MAX_LISTED_FAILURE_CHARACTERS
    first = len(listed)
    assert summary == (
        f"d{first:05d}/Settings.json: case variant of d{first:05d}/settings.json is the "
        "active file on case-insensitive file systems and is not inventoried "
        f"(and {count - first - 1} more not listed)"
    )


def test_a_summary_names_at_most_64_reasons_and_counts_the_rest(tmp_path):
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        for index in range(MAX_LISTED_FAILURES):
            files._fail(f"f{index}", "listed")
        for reason in range(70):
            for index in range(2):
                files._fail(f"r{reason}-{index}", f"reason {reason}")
    assert len(failures) == MAX_LISTED_FAILURES + 65
    assert failures[MAX_LISTED_FAILURES:] == [
        *(f"r{reason}-0: reason {reason} (and 1 more not listed)" for reason in range(64)),
        "12 more failures for 6 other reasons not listed",
    ]


def test_failures_past_the_bounds_are_counted_not_kept(tmp_path):
    def retained(count: int) -> int:
        failures: list[str] = []
        tracemalloc.start()
        try:
            with ConfinedCollection(tmp_path, failures) as files:
                start = tracemalloc.get_traced_memory()[0]
                for index in range(count):
                    files._fail("x" * 200 + str(index), "failed")
                return tracemalloc.get_traced_memory()[0] - start
        finally:
            tracemalloc.stop()

    # Twice the failures past the bounds keep no more memory than the first half.
    assert retained(10_000) < retained(5_000) + 64 * 1024


def test_records_a_collector_appends_are_listed_within_the_bounds():
    result = ScanResult(scanner_name="x", scan_failures=["a: failed", "b: failed"])
    for index in range(MAX_LISTED_FAILURES + 10):
        result.scan_failures.append(f"f{index:05d}: failed")
        result.surfaces_excluded.append(f"g{index:05d}: not inventoried")
    result.scan_failures += ["late: failed"]
    result.scan_failures.extend(["later: failed"])
    assert len(result.scan_failures) == MAX_LISTED_FAILURES + 1
    assert result.scan_failures[:2] == ["a: failed", "b: failed"]
    assert result.scan_failures[-1] == "f00998: failed (and 13 more failures not listed)"
    assert len(result.surfaces_excluded) == MAX_LISTED_FAILURES + 1
    assert result.surfaces_excluded[-1] == (
        "g01000: not inventoried (and 9 more excluded surfaces not listed)"
    )
    kind = type(result.scan_failures)
    result.make_portable(Path("/checkout"))
    assert type(result.scan_failures) is kind
    result.scan_failures.append("after: failed")
    assert result.scan_failures[-1] == "f00998: failed (and 14 more failures not listed)"
    long = ScanResult(scanner_name="x", surfaces_excluded=["y" * 70_000, "z: gap"])
    assert long.surfaces_excluded == ["y" * 70_000 + " (and 1 more excluded surface not listed)"]


def test_a_collection_sums_up_its_own_failures_before_the_line_that_counts_the_rest(tmp_path):
    result = ScanResult(scanner_name="x")
    with ConfinedCollection(tmp_path, result.scan_failures, result.surfaces_excluded) as files:
        for index in range(MAX_LISTED_FAILURES + 5):
            assert files.read_bytes(f"m{index:05d}") is None
        result.scan_failures.append("direct: failed")
        result.scan_failures.append("again: failed")
    assert len(result.scan_failures) == MAX_LISTED_FAILURES + 2
    assert result.scan_failures[-2:] == [
        f"m{MAX_LISTED_FAILURES:05d}: file unavailable during collection (and 4 more not listed)",
        "direct: failed (and 1 more failure not listed)",
    ]


def test_a_collection_that_also_searches_source_states_both_limits():
    configured = replace(limits.DEFAULTS, total_bytes=2 * limits.KIB, source_scan_bytes=limits.KIB)
    with limits.applied(configured):
        bound = source_collection_bytes()
    assert bound.value == 3 * limits.KIB
    assert bound.exceeded() == (
        "total-bytes limit of 2 KiB (plus 1 KiB source-scan-bytes for source search) "
        "exceeded; raise it with --limit total-bytes=N"
    )


def test_messages_are_recorded_once_even_when_the_caller_appends_too(tmp_path):
    failures = ["missing: file unavailable during collection"]
    with ConfinedCollection(tmp_path, failures) as files:
        failures.append("later: file unavailable during collection")
        assert files.read_bytes("missing") is None
        assert files.read_bytes("later") is None
        assert files.read_bytes("other") is None
        assert files.read_bytes("other") is None
    assert failures == [
        "missing: file unavailable during collection",
        "later: file unavailable during collection",
        "other: file unavailable during collection",
    ]


def test_a_failed_stream_read_is_recorded(tmp_path, monkeypatch):
    (tmp_path / "a.bin").write_bytes(b"x" * 10)
    failures: list[str] = []
    read = os.read
    with ConfinedCollection(tmp_path, failures) as files, files.open_regular("a.bin") as stream:
        broken = stream.fileno()

        def failing(fd: int, size: int) -> bytes:
            if fd == broken:
                raise OSError(errno.EIO, "I/O error")
            return read(fd, size)

        monkeypatch.setattr(os, "read", failing)
        with pytest.raises(OSError):
            stream.read(4)
    assert failures == ["a.bin: stream read failed (I/O error)"]


def test_an_undecodable_name_is_a_failure_and_the_inventory_still_loads(tmp_path):
    project = tmp_path / "project"
    (project / "models").mkdir(parents=True)
    (project / ".claude" / "skills").mkdir(parents=True)
    (project / "AGENTS.md").write_text("Keep receipts.")
    _undecodable(project, b"tool\xff.py", b"import chromadb\n")
    _undecodable(project / "models", b"m\xff.pkl")
    _undecodable(project / ".claude" / "skills", b"s\xfe.md", b"skill")
    expected = {
        "tool\\xff.py: name is not valid UTF-8; not collected",
        "models/m\\xff.pkl: name is not valid UTF-8; not collected",
        ".claude/skills/s\\xfe.md: name is not valid UTF-8; not collected",
    }
    for scanner in (RAGScanner, ModelScanner, MCPScanner):
        result = scanner().scan(project)
        assert set(result.scan_failures) == expected
        assert not any("\\udc" in repr(component) for component in result.components)
    # The prompt collector walks the whole tree for nested instruction files.
    assert set(PromptScanner().scan(project).scan_failures) == expected
    output = tmp_path / "out.json"
    runner = CliRunner()
    scan = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    assert runner.invoke(main, scan).exit_code == 0
    bom = AIBOM.load(output)
    assert "tool\\xff.py: name is not valid UTF-8; not collected" in (
        bom.metadata.completeness.scan_failures if bom.metadata.completeness else []
    )
    result = runner.invoke(main, ["validate", str(output)])
    assert "not a valid native AIBOM file" not in result.output


def test_operator_roots_walk_dot_dot_through_the_real_parent(tmp_path):
    real = tmp_path / "real"
    (real / "project").mkdir(parents=True)
    (real / "project" / "file.txt").write_text("inside")
    (tmp_path / "other").mkdir()
    (tmp_path / "project").mkdir()
    (tmp_path / "project" / "file.txt").write_text("lexical twin")
    (tmp_path / "link").symlink_to(tmp_path / "other", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path / "link" / ".." / "project", failures) as files:
        assert files.read_text("file.txt") is None
    assert ".: root unavailable or contains a symlink" in failures
    with ConfinedCollection(real / "project" / ".." / "project", []) as files:
        assert files.read_text("file.txt") == "inside"
    assert pathname_identity(tmp_path / "link" / ".." / "project" / "file.txt") is None
    with pytest.raises(OSError):
        open_regular_file(tmp_path / "link" / ".." / "project" / "file.txt")
    with open_regular_file(real / "project" / ".." / "project" / "file.txt") as stream:
        assert stream.read() == b"inside"


def test_project_paths_with_a_symlinked_component_are_resolved_like_scan(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "model.bin").write_bytes(b"data")
    (tmp_path / "alias").symlink_to(project, target_is_directory=True)
    import hashlib

    digest = "sha256:" + hashlib.sha256(b"data").hexdigest()
    result = CliRunner().invoke(
        main,
        ["verify-artifact", "model.bin", "--project", str(tmp_path / "alias"), "--sha256", digest],
    )
    assert result.exit_code == 0, result.output


def test_a_null_document_and_an_unwalkable_directory_name_are_named_as_such(tmp_path):
    (tmp_path / "x.json").write_text("null")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json("x.json") is None
        assert list(files.iter_files("../x")) == []
        assert list(files.iter_files("a\x00b")) == []
    unwalkable = "directory is outside collection root or not a plain relative path"
    assert failures == [
        "x.json: JSON document is null",
        f"../x: {unwalkable}",
        f"a\x00b: {unwalkable}",
    ]


@pytest.mark.parametrize("outside", ["../outside", "/etc", "a/../../b", "/"])
def test_an_exclusion_outside_the_root_invalidates_the_policy_and_collects_nothing(
    tmp_path, outside
):
    (tmp_path / "kept.json").write_text("{}")
    failures: list[str] = []
    exclusions: list[str] = []
    with ConfinedCollection(tmp_path, failures, exclusions, exclude_paths=[outside]) as files:
        assert list(files.iter_files()) == []
        assert files.read_bytes("kept.json", missing_ok=True) is None
    assert failures[0] == ".: excluded path is outside collection root"
    assert exclusions == []


def test_an_exclusion_outside_the_root_fails_the_scan_gate(tmp_path, monkeypatch):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"a": {"command": "x"}}}')

    class Escaping(MCPScanner):
        def configure(self, exclude_paths=(), *, accept_default_excludes=False):
            super().configure([*exclude_paths, "../outside"])

    monkeypatch.setattr("nexus_symbiote.cli._get_scanners", lambda: {"mcp": Escaping})
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "--scanner", "mcp", "-o", str(output)]
    )
    assert result.exit_code == 1, result.output
    assert "Scan gate failed" in result.output
    assert "collection: .: excluded path is outside collection root" in result.output
    assert not any(c.bom_ref.startswith("mcp:") for c in AIBOM.load(output).components)
