"""The confined reader follows one in-root symlink lexically and reports case variants."""

from __future__ import annotations

import itertools
import json
import os
from pathlib import Path

import pytest

from nexus_symbiote.scanners.base import parse_python
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.utils.confined import (
    CollectionError,
    ConfinedCollection,
    _lexical_target,
    fold_name,
)
from tests.support import scaling_ratio


def _collect(root: Path) -> tuple[list[Path], list[str]]:
    failures: list[str] = []
    with ConfinedCollection(root, failures) as files:
        walked = list(files.iter_files())
    return walked, failures


def test_walk_yields_file_links_and_skips_directory_links_inside_the_root(tmp_path):
    (tmp_path / "docs" / "v2").mkdir(parents=True)
    (tmp_path / "docs" / "v2" / "guide.md").write_text("guide")
    (tmp_path / "AGENTS.md").write_text("agents")
    (tmp_path / "CLAUDE.md").symlink_to("AGENTS.md")
    (tmp_path / "docs" / "latest").symlink_to("v2", target_is_directory=True)
    (tmp_path / "docs" / "v2" / "home").symlink_to("../../AGENTS.md")
    (tmp_path / "self").symlink_to(".", target_is_directory=True)
    walked, failures = _collect(tmp_path)
    assert failures == []
    assert [path.as_posix() for path in walked] == [
        "AGENTS.md",
        "CLAUDE.md",
        "docs/v2/guide.md",
        "docs/v2/home",
    ]


@pytest.mark.parametrize(
    ("make", "reason"),
    [
        (lambda root, out: (root / "x").symlink_to(out), "symlink target is absolute"),
        (lambda root, out: (root / "x").symlink_to("../outside"), "symlink target is outside"),
        (lambda root, out: (root / "x").symlink_to("missing"), "symlink target is unavailable"),
        (lambda root, out: (root / "x").symlink_to("chain"), "symlink target is another symlink"),
        (
            lambda root, out: (root / "x").symlink_to("node_modules/pkg.json"),
            "symlink target is excluded from collection",
        ),
        (lambda root, out: (root / "x").symlink_to("fifo"), "not a regular file or directory"),
        (lambda root, out: (root / "x").symlink_to("d/../a"), "not a plain relative path"),
    ],
)
def test_other_symlinks_in_a_walk_are_failures(tmp_path, make, reason):
    root = tmp_path / "root"
    (root / "node_modules").mkdir(parents=True)
    (root / "node_modules" / "pkg.json").write_text("{}")
    (root / "d").mkdir()
    (root / "a").write_text("a")
    (root / "chain").symlink_to("a")
    os.mkfifo(root / "fifo")
    (tmp_path / "outside").write_text("CANARY")
    make(root, tmp_path / "outside")
    _, failures = _collect(root)
    assert any(failure.startswith("x: ") and reason in failure for failure in failures)


def test_fixed_read_follows_one_in_root_link_and_names_its_target(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "mcp.json").write_text('{"mcpServers": {}}')
    (tmp_path / ".mcp.json").symlink_to("config/mcp.json")
    (tmp_path / ".claude").symlink_to("config", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json(".mcp.json") == {"mcpServers": {}}
        assert files.link_target(".mcp.json") == "config/mcp.json"
        assert files.read_json(".claude/mcp.json") == {"mcpServers": {}}
        assert files.link_target(".claude/mcp.json") == "config/mcp.json"
        assert files.in_root_target(".mcp.json") == Path("config/mcp.json")
        assert files.is_directory(".claude")
        assert [path.as_posix() for path in files.iter_files(".claude")] == ["config/mcp.json"]
    assert failures == []


def test_read_through_a_link_into_a_further_link_is_refused(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "f.json").write_text("{}")
    (tmp_path / "hop").symlink_to("real", target_is_directory=True)
    (tmp_path / "entry.json").symlink_to("hop/f.json")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json("entry.json") is None
        assert files.in_root_target("entry.json") is None
    assert failures == [
        "entry.json: symlink target is or passes through another symlink or a non-directory"
    ]


def test_a_link_whose_target_passes_through_a_file_says_so(tmp_path):
    (tmp_path / "a").write_text("x")
    (tmp_path / "x.md").symlink_to("a/b.md")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_bytes("x.md") is None
    assert failures == [
        "x.md: symlink target is or passes through another symlink or a non-directory"
    ]
    # No POSIX system lets a symlink be created with empty text; refuse it as empty.
    with pytest.raises(CollectionError, match="^symlink target is empty$"):
        _lexical_target(Path(), "")


def test_missing_fixed_path_reports_its_case_variants(tmp_path):
    (tmp_path / ".Claude").mkdir()
    (tmp_path / ".Claude" / "Settings.json").write_text("{}")
    (tmp_path / "Agents.md").write_text("x")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json(".claude/settings.json", missing_ok=True) is None
        assert files.read_text("AGENTS.md", missing_ok=True, variants_read={"Agents.md"}) is None
        assert files.read_text("README.md", missing_ok=True) is None
        assert files.case_variants("agents.md") == [Path("Agents.md")]
    assert failures == [
        ".Claude/Settings.json: case variant of .claude/settings.json is the active file on "
        "case-insensitive file systems and is not inventoried"
    ]


def test_missing_directory_reports_its_case_variants(tmp_path):
    (tmp_path / ".cursor" / "Rules").mkdir(parents=True)
    (tmp_path / ".cursor" / "Rules" / "a.mdc").write_text("x")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert list(files.iter_files(".cursor/rules")) == []
    assert [failure.split(":")[0] for failure in failures] == [".cursor/Rules"]


def test_exact_name_is_read_and_reports_coexisting_variant_unless_read(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("upper")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_text("CLAUDE.md", missing_ok=True) == "upper"
    assert failures == []

    lower = tmp_path / "claude.md"
    variant_name = "claude.md" if not lower.exists() else "CLAUDE.md."
    (tmp_path / variant_name).write_text("lower")

    failures = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_text("CLAUDE.md", missing_ok=True) == "upper"
    assert [failure.split(":")[0] for failure in failures] == [variant_name]

    failures = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert (
            files.read_text("CLAUDE.md", missing_ok=True, variants_read={variant_name}) == "upper"
        )
    assert failures == []


def test_names_fold_as_case_insensitive_file_systems_compare_them():
    assert fold_name("CLAUDE.md") == fold_name("claude.md")
    assert fold_name("caf\u00e9.md") == fold_name("cafe\u0301.md")
    assert fold_name("agent.json.") == fold_name("agent.json")
    assert fold_name("a\u200db") == fold_name("ab")
    assert fold_name("agent.json") != fold_name("agent-card.json")


@pytest.mark.parametrize(
    "source", ["x = " + "-" * 100_000 + "1\n", "if a:\n    pass\n" + "elif a:\n    pass\n" * 20_000]
)
def test_parser_resource_failures_become_value_errors(source):
    with pytest.raises(ValueError):
        parse_python(source)


def test_byte_order_mark_is_accepted_like_cpython():
    assert parse_python("\ufeffimport chromadb\n").body


def test_deeply_nested_source_does_not_discard_other_collector_results(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"notes": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}})
    )
    (tmp_path / "x.py").write_text("# mcp\nx = " + "-" * 100_000 + "1\n")
    mcp = MCPScanner().scan(tmp_path)
    assert any(component.name == "notes" for component in mcp.components)
    assert any("x.py" in failure for failure in mcp.scan_failures)


def test_missing_file_below_a_linked_directory_is_absent_not_a_failure(tmp_path):
    (tmp_path / "shared").mkdir()
    (tmp_path / ".claude").symlink_to("shared", target_is_directory=True)
    (tmp_path / ".cursor").symlink_to("gone", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json(".claude/settings.local.json", missing_ok=True) is None
        assert list(files.iter_files(".claude/commands")) == []
        assert files.read_json(".cursor/mcp.json", missing_ok=True) is None
    assert failures == [".cursor/mcp.json: symlink target is unavailable"]


def _linked_claude(root: Path) -> Path:
    """`.claude -> config/claude`, the layout where a host opens variants through the link."""
    target = root / "config" / "claude"
    target.mkdir(parents=True)
    (root / ".claude").symlink_to("config/claude", target_is_directory=True)
    return target


def test_case_variant_below_an_in_root_directory_link_is_reported(tmp_path):
    target = _linked_claude(tmp_path)
    (target / "Settings.json").write_text("{}")
    (target / "Rules").mkdir()
    (target / "Rules" / "a.md").write_text("x")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json(".claude/settings.json", missing_ok=True) is None
        assert list(files.iter_files(".claude/rules")) == []
        assert files.case_variants(".claude/settings.json") == [Path(".claude/Settings.json")]
    assert failures == [
        (
            ".claude/Settings.json: case variant of .claude/settings.json is the active file on "
            "case-insensitive file systems and is not inventoried"
        ),
        (
            ".claude/Rules: case variant of .claude/rules is the active file on "
            "case-insensitive file systems and is not inventoried"
        ),
    ]


def test_case_variant_search_follows_one_link_only(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "Settings.json").write_text("{}")
    (tmp_path / "hop").symlink_to("real", target_is_directory=True)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "claude").symlink_to("../hop", target_is_directory=True)
    (tmp_path / ".claude").symlink_to("config/claude", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.case_variants(".claude/settings.json") == []
        assert files.read_json(".claude/settings.json", missing_ok=True) is None
    assert failures == [
        ".claude/settings.json: symlink target is or passes through another symlink "
        "or a non-directory"
    ]


def test_case_variant_search_spends_a_bounded_budget(tmp_path):
    for top in range(10):
        for below in range(10):
            (tmp_path / ("A" + "." * top) / ("B" + "." * below)).mkdir(parents=True)

    def run(scale: int) -> list[str]:
        failures: list[str] = []
        with ConfinedCollection(tmp_path, failures, max_entries=300) as files:
            for index in range(500 * scale):
                assert files.read_bytes(f"a/b/x{index}.md", missing_ok=True) is None
        return failures

    failures = run(4)
    assert failures and all(
        f.endswith(": entries limit of 300 exceeded; this limit is fixed for this input")
        for f in failures
    )
    assert scaling_ratio(run) < 10


def test_path_with_a_nul_character_is_a_refused_read_not_an_error(tmp_path):
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_bytes("a\x00b.md", missing_ok=True) is None
        assert files.is_directory("a\x00b") is False
        assert files.in_root_target("a\x00b.md") is None
        assert list(files.iter_files("a\x00b")) == []
    assert failures


def test_symlink_to_a_target_beyond_the_depth_limit_is_refused(tmp_path):
    # The default depth is 64, so the target sits beyond it and within a raised limit.
    deep = Path(*["d"] * 70)
    (tmp_path / deep).mkdir(parents=True)
    (tmp_path / deep / "f.md").write_text("x")
    (tmp_path / "link.md").symlink_to(deep / "f.md")
    (tmp_path / "linkdir").symlink_to(deep, target_is_directory=True)
    with ConfinedCollection(tmp_path, [], max_depth=128) as files:
        walked = [path.as_posix() for path in files.iter_files()]
    assert "link.md" in walked
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_bytes("link.md") is None
        assert files.read_bytes("linkdir/f.md") is None
        list(files.iter_files("."))
    too_deep = (
        "symlink target is too deep; depth limit of 64 exceeded; raise it with --limit depth=N"
    )
    assert f"link.md: {too_deep}" in failures
    assert f"linkdir/f.md: {too_deep}" in failures


@pytest.mark.parametrize("text", [".", "./"])
def test_names_below_a_link_to_the_root_are_refused_not_searched_in_the_root(tmp_path, text):
    (tmp_path / "Settings.json").write_text('{"permissions": {"defaultMode": "bypassPermissions"}}')
    (tmp_path / "Rules").mkdir()
    (tmp_path / "Rules" / "evil.md").write_text("x")
    (tmp_path / "Copilot-Instructions.md").write_text("x")
    (tmp_path / ".claude").symlink_to(text, target_is_directory=True)
    (tmp_path / ".github").symlink_to(text, target_is_directory=True)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / ".cursor").symlink_to("..", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json(".claude/settings.json", missing_ok=True) is None
        assert list(files.iter_files(".claude/rules")) == []
        assert files.read_text(".github/copilot-instructions.md", missing_ok=True) is None
        assert files.read_json("pkg/.cursor/hooks.json", missing_ok=True) is None
    assert failures == [
        ".claude/settings.json: symlink target is the collection root",
        ".claude/rules: symlink target is the collection root",
        ".github/copilot-instructions.md: symlink target is the collection root",
        "pkg/.cursor/hooks.json: symlink target is the collection root",
    ]


def _same_folding_names(count: int, base: str = "a") -> list[str]:
    """Names that fold to ``base`` (case, trailing dots and spaces), without ``base``."""
    names: list[str] = []
    length = 0
    upper = base.upper()
    while len(names) < count:
        for suffix in itertools.product(". ", repeat=length):
            name = upper + "".join(suffix)
            if name != base and len(names) < count:
                names.append(name)
        length += 1
    return names


def test_lookups_beside_thousands_of_same_folding_directories_stay_fast(tmp_path):
    for name in _same_folding_names(2000):
        (tmp_path / name).mkdir()
        (tmp_path / name / "keep").write_text("")

    def run(scale: int) -> list[str]:
        failures: list[str] = []
        with ConfinedCollection(tmp_path, failures) as files:
            for index in range(500 * scale):
                assert files.read_bytes(f"a/m{index}.md", missing_ok=True) is None
        return failures

    failures = run(4)
    assert failures == [
        "a: more than 16 names in its directory differ from it only by case or "
        "normalisation and are not checked"
    ]
    assert scaling_ratio(run) < 10


def test_a_spent_variant_budget_is_one_failure_and_ends_every_later_search(tmp_path):
    for top in _same_folding_names(16):
        for below in _same_folding_names(16, "b"):
            (tmp_path / top / below).mkdir(parents=True)

    def run(scale: int) -> list[str]:
        failures: list[str] = []
        with ConfinedCollection(tmp_path, failures, max_entries=1000) as files:
            for index in range(500 * scale):
                assert files.read_bytes(f"a/b/x{index}.md", missing_ok=True) is None
            assert files.case_variants("a/b") == []
        return failures

    failures = run(4)
    assert len(failures) == 1 and failures[0].endswith(
        ": entries limit of 1000 exceeded; this limit is fixed for this input"
    )
    assert scaling_ratio(run) < 10


@pytest.mark.parametrize("fillers", [3, 0])
def test_a_variant_budget_spent_exactly_fails_the_next_search(tmp_path, fillers):
    # Listing the root costs its entries and itself: 5 of 5 with three fillers, or
    # 2 of 2 with B.md alone. The search that spends it all misses nothing, but
    # every later one is refused and must say so.
    (tmp_path / "B.md").write_text("x")
    for index in range(fillers):
        (tmp_path / f"f{index}").write_text("x")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=fillers + 2) as files:
        assert files.read_bytes("a.md", missing_ok=True) is None
        assert failures == []
        assert files.read_bytes("b.md", missing_ok=True) is None
        assert files.case_variants("c.md") == []
    assert failures == [
        f"b.md: entries limit of {fillers + 2} exceeded; this limit is fixed for this input"
    ]


def test_failures_recorded_once_beside_those_the_caller_appends(tmp_path):
    failures = ["x.md: file unavailable during collection"]
    with ConfinedCollection(tmp_path, failures) as files:
        files.read_bytes("x.md")
        failures.append("y.md: file unavailable during collection")
        files.read_bytes("y.md")
        files.read_bytes("z.md")
        files.read_bytes("z.md")
    assert failures == [
        "x.md: file unavailable during collection",
        "y.md: file unavailable during collection",
        "z.md: file unavailable during collection",
    ]


def test_directory_walk_follows_a_link_out_of_it_once_under_the_target_name(tmp_path):
    (tmp_path / "vendor" / "pdf").mkdir(parents=True)
    (tmp_path / "vendor" / "pdf" / "SKILL.md").write_text("x")
    skills = tmp_path / ".claude" / "skills"
    (skills / "own").mkdir(parents=True)
    (skills / "own" / "SKILL.md").write_text("x")
    (skills / "pdf").symlink_to("../../vendor/pdf", target_is_directory=True)
    (skills / "pdf-again").symlink_to("../../vendor/pdf", target_is_directory=True)
    (skills / "mine").symlink_to("own", target_is_directory=True)
    (skills / "vendor").symlink_to("../../vendor", target_is_directory=True)
    failures: list[str] = []
    links: list[Path] = []
    with ConfinedCollection(tmp_path, failures) as files:
        walked = [
            path.as_posix() for path in files.iter_files(".claude/skills", directory_links=links)
        ]
        whole = [path.as_posix() for path in files.iter_files()]
    assert failures == []
    assert walked == [".claude/skills/own/SKILL.md", "vendor/pdf/SKILL.md"]
    assert [link.name for link in links] == ["mine", "pdf", "pdf-again", "vendor"]
    assert whole == [".claude/skills/own/SKILL.md", "vendor/pdf/SKILL.md"]


def test_directory_walk_refuses_a_link_to_the_root_or_to_a_directory_holding_it(tmp_path):
    skills = tmp_path / ".claude" / "skills"
    skills.mkdir(parents=True)
    (skills / "SKILL.md").write_text("x")
    (skills / "all").symlink_to("../..", target_is_directory=True)
    (skills / "up").symlink_to("..", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert [path.as_posix() for path in files.iter_files(".claude/skills")] == [
            ".claude/skills/SKILL.md"
        ]
        assert [path.as_posix() for path in files.iter_files()] == [".claude/skills/SKILL.md"]
    assert failures == [
        ".claude/skills/all: symlink target is the collection root",
        ".claude/skills/up: symlink target holds the walked directory",
    ]


NOT_UTF8 = "symlink target name is not valid UTF-8; not collected"


def test_a_link_to_a_name_that_is_not_utf8_is_refused_wherever_it_is_met(tmp_path):
    # Followed, its target's lone surrogates reached link targets, walked paths and
    # failure messages, which an inventory cannot hold.
    raw = os.fsencode(tmp_path)
    try:
        os.makedirs(raw + b"/\xffdir")
        for name in (b"/\xffdir/f.md", b"/\xfe.md"):
            with open(raw + name, "wb") as stream:
                stream.write(b"x")
    except (OSError, UnicodeEncodeError):
        pytest.skip("file system rejects names that are not UTF-8")
    os.mkfifo(raw + b"/\xffdir/pipe")
    os.symlink(b"\xfe.md", raw + b"/file.md")
    os.symlink(b"\xffdir", raw + b"/dir")
    os.mkdir(raw + b"/a")
    os.symlink(b"../\xffdir", raw + b"/a/.claude")
    failures: list[str] = []
    links: list[Path] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_bytes("file.md") is None
        assert files.link_target("file.md") is None
        assert files.read_bytes("dir/f.md") is None
        assert files.regular_file("dir/f.md") is None
        assert not files.is_directory("dir")
        assert list(files.iter_files("dir")) == []
        assert files.read_bytes("a/.claude/settings.json", missing_ok=True) is None
        assert files.case_variants("a/.claude/Settings.json") == []
        assert list(files.iter_files(directory_links=links)) == []
    assert links == []
    assert failures == [
        f"file.md: {NOT_UTF8}",
        f"dir/f.md: {NOT_UTF8}",
        f"dir: {NOT_UTF8}",
        f"a/.claude/settings.json: {NOT_UTF8}",
        f"a/.claude: {NOT_UTF8}",
        "\\xfe.md: name is not valid UTF-8; not collected",
        "\\xffdir: name is not valid UTF-8; not collected",
    ]


def test_a_case_variant_is_reported_once_however_many_paths_lead_to_it(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "Settings.json").write_text("{}")
    second = (
        "SETTINGS.JSON" if not (tmp_path / "t" / "SETTINGS.JSON").exists() else "Settings.json."
    )
    (tmp_path / "t" / second).write_text("{}")
    for index in range(3):
        (tmp_path / f"p{index}").mkdir()
        (tmp_path / f"p{index}" / ".claude").symlink_to("../t", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        for index in range(3):
            path = f"p{index}/.claude/settings.json"
            assert files.read_bytes(path, missing_ok=True) is None
            assert sorted(files.case_variants(path)) == sorted(
                [
                    Path(f"p{index}/.claude/{second}"),
                    Path(f"p{index}/.claude/Settings.json"),
                ]
            )
        files.report_case_variant("t/Settings.json", "t/settings.json")
        files.report_case_variant("q/.claude/Settings.json", "q/.claude/settings.json")
    variant = "is the active file on case-insensitive file systems and is not inventoried"
    assert sorted(failures) == sorted(
        [
            f"p0/.claude/{second}: case variant of p0/.claude/settings.json {variant}",
            f"p0/.claude/Settings.json: case variant of p0/.claude/settings.json {variant}",
            f"q/.claude/Settings.json: case variant of q/.claude/settings.json {variant}",
        ]
    )


def test_entry_link_reads_an_excluded_link_without_following_it(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".venv").mkdir()
    (tmp_path / "node_modules").symlink_to(".claude", target_is_directory=True)
    (tmp_path / "venv").symlink_to(tmp_path / ".claude", target_is_directory=True)
    (tmp_path / ".git").symlink_to("..", target_is_directory=True)
    (tmp_path / "self").symlink_to(".", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.excluded("node_modules")
        assert files.entry_link("node_modules") == Path(".claude")
        assert files.entry_link("self") == Path()
        assert files.entry_link(".venv") is None
        assert files.entry_link("missing") is None
        for refused in ("venv", ".git"):
            with pytest.raises(CollectionError):
                files.entry_link(refused)
        with pytest.raises(CollectionError):
            files.entry_link("node_modules/inner")
    assert failures == []


def test_entry_link_enforces_depth_bound_and_reports_non_directory_parent(tmp_path):
    (tmp_path / "file.txt").write_text("x", encoding="utf-8")
    (tmp_path / "deep").symlink_to("a/b/c/d/e", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_depth=2) as files:
        with pytest.raises(CollectionError, match="not a directory"):
            files.entry_link("file.txt/child")
        with pytest.raises(CollectionError, match="too deep"):
            files.entry_link("deep")
    assert failures == []
