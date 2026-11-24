"""The pull-request size cap counts product changes and ignores the test trees."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.support import load_script

checker = load_script("check_pull_request_size")


def test_tests_and_binaries_are_not_counted() -> None:
    listing = "\n".join(
        [
            "10\t2\tsrc/nexus_symbiote/cli.py",
            "1000\t0\ttests/test_cli.py",
            "3\t1\tbenchmarks/case.json",
            "-\t-\tdocs/assets/banner.jpg",
            "-\t-\ttests/fixtures/model.bin",
            "4\t0\tREADME.md",
        ]
    )
    assert checker.changed_lines(listing) == 16


def test_the_command_fails_above_the_limit(tmp_path: Path, capsys) -> None:
    listing = tmp_path / "numstat.txt"
    listing.write_text("1600\t0\tsrc/nexus_symbiote/cli.py\n")
    assert checker.main(["--numstat-file", str(listing), "--limit", "1500"]) == 1
    assert "1600" in capsys.readouterr().out


def test_a_binary_change_outside_the_expected_trees_cannot_be_measured(
    tmp_path: Path, capsys
) -> None:
    listing = tmp_path / "numstat.txt"
    listing.write_text("-\t-\tsrc/nexus_symbiote/cli.py\n")
    assert checker.main(["--numstat-file", str(listing)]) == 1
    assert "cannot be measured" in capsys.readouterr().out


def _git(root: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(root), *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "PATH": "/usr/bin:/bin",
        },
    ).stdout


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.invalid")
    _git(root, "config", "user.name", "t")
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src" / "a.py").write_text("x = 1\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return root


def test_a_pull_requests_own_gitattributes_cannot_hide_its_changes(
    repository: Path, monkeypatch, capsys
) -> None:
    # `src/** -diff` would report every source change as binary, and so as zero lines.
    base = _git(repository, "rev-parse", "HEAD").strip()
    (repository / ".gitattributes").write_text("src/** -diff\n")
    (repository / "src" / "a.py").write_text("".join(f"x{i} = {i}\n" for i in range(40)))
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "change")
    monkeypatch.chdir(repository)
    assert checker.main(["--base", base, "--limit", "20"]) == 1
    assert "42 lines" in capsys.readouterr().out


def test_the_merge_commits_first_parent_counts_only_the_pull_request(
    repository: Path, monkeypatch, capsys
) -> None:
    # CI measures the merge commit against its first parent. The base branch can move
    # while the job waits for a runner: against the moved tip, the commits merged since
    # would count as the pull request's own.
    _git(repository, "checkout", "-q", "-b", "feature")
    (repository / "src" / "b.py").write_text("".join(f"b{i} = {i}\n" for i in range(10)))
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "pull request")
    _git(repository, "checkout", "-q", "main")
    _git(repository, "merge", "-q", "--no-ff", "-m", "merge", "feature")
    merge = _git(repository, "rev-parse", "HEAD").strip()
    _git(repository, "checkout", "-q", "-b", "moved", "HEAD^1")
    (repository / "src" / "c.py").write_text("".join(f"c{i} = {i}\n" for i in range(90)))
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "merged meanwhile")
    moved = _git(repository, "rev-parse", "HEAD").strip()
    _git(repository, "checkout", "-q", "--detach", merge)
    monkeypatch.chdir(repository)
    assert checker.main(["--base", f"{merge}^1", "--limit", "20"]) == 0
    assert "10 lines" in capsys.readouterr().out
    assert checker.main(["--base", moved, "--limit", "20"]) == 1
    assert "100 lines" in capsys.readouterr().out


def test_a_move_out_of_tests_counts_at_its_destination(
    repository: Path, monkeypatch, capsys
) -> None:
    (repository / "tests" / "big.py").write_text("".join(f"y{i} = {i}\n" for i in range(40)))
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "tests")
    base = _git(repository, "rev-parse", "HEAD").strip()
    _git(repository, "mv", "tests/big.py", "src/big.py")
    _git(repository, "commit", "-q", "-m", "move")
    monkeypatch.chdir(repository)
    assert checker.main(["--base", base, "--limit", "20"]) == 1
    assert "40 lines" in capsys.readouterr().out


def test_a_file_the_base_marks_minus_diff_is_counted_not_refused(
    repository: Path, monkeypatch, capsys
) -> None:
    # The vendored schemas are `-diff` in the base, so numstat reports them as binary;
    # a schema update must be measured as text rather than fail the gate.
    (repository / ".gitattributes").write_text("src/vendor/*.json -diff\n")
    (repository / "src" / "vendor").mkdir()
    (repository / "src" / "vendor" / "s.json").write_text("{}\n")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "schema")
    base = _git(repository, "rev-parse", "HEAD").strip()
    (repository / "src" / "vendor" / "s.json").write_text("{\n" + "1,\n" * 30 + "}\n")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "bump")
    monkeypatch.chdir(repository)
    assert checker.main(["--base", base, "--limit", "20"]) == 1
    assert "33 lines" in capsys.readouterr().out


def test_binary_content_the_base_does_not_mark_still_cannot_be_measured(
    repository: Path, monkeypatch, capsys
) -> None:
    base = _git(repository, "rev-parse", "HEAD").strip()
    (repository / "src" / "blob.dat").write_bytes(b"\0\1\2" * 10)
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "blob")
    monkeypatch.chdir(repository)
    assert checker.main(["--base", base]) == 1
    assert "cannot be measured" in capsys.readouterr().out


@pytest.mark.parametrize("content", [b"\0\1\2" * 2000, b"\xff\xfe" * 2000])
def test_binary_content_in_a_type_the_base_marks_binary_cannot_be_measured(
    repository: Path, monkeypatch, capsys, content: bytes
) -> None:
    # `*.png binary` unsets diff, so the base marks it -diff; content with a NUL byte or
    # that is not UTF-8 is still binary, and counting its newlines would pass any blob.
    (repository / ".gitattributes").write_text("*.png binary\n")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "attributes")
    base = _git(repository, "rev-parse", "HEAD").strip()
    (repository / "src" / "logo.png").write_bytes(content)
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "blob")
    monkeypatch.chdir(repository)
    assert checker.main(["--base", base]) == 1
    assert "cannot be measured" in capsys.readouterr().out


def test_an_image_the_base_marks_binary_in_an_expected_tree_is_not_counted(
    repository: Path, monkeypatch, capsys
) -> None:
    (repository / ".gitattributes").write_text("*.png binary\n")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "attributes")
    base = _git(repository, "rev-parse", "HEAD").strip()
    (repository / "docs" / "assets").mkdir(parents=True)
    (repository / "docs" / "assets" / "logo.png").write_bytes(b"\0\1\2" * 2000)
    (repository / "tests" / "fixture.png").write_bytes(b"\xff\n" * 2000)
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "images")
    monkeypatch.chdir(repository)
    assert checker.main(["--base", base]) == 0
    assert "0 lines" in capsys.readouterr().out


def test_a_binary_fixture_with_a_non_ascii_path_under_tests_is_not_counted(
    repository: Path, monkeypatch, capsys
) -> None:
    # core.quotePath would print "tests/fixtur\303\251.bin", which no longer starts tests/.
    base = _git(repository, "rev-parse", "HEAD").strip()
    (repository / "tests" / "fixturé.bin").write_bytes(b"\0\1\2" * 10)
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "fixture")
    monkeypatch.chdir(repository)
    assert checker.main(["--base", base]) == 0
    assert "0 lines" in capsys.readouterr().out


def test_a_run_from_a_subdirectory_still_refuses_binary_content(
    repository: Path, monkeypatch, capsys
) -> None:
    # numstat prints root-relative paths; read from a subdirectory, the blob lookups and
    # pathspecs found nothing and counted a binary .png as zero lines.
    (repository / ".gitattributes").write_text("*.png binary\n")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "attributes")
    base = _git(repository, "rev-parse", "HEAD").strip()
    (repository / "src" / "sub").mkdir(parents=True)
    (repository / "src" / "sub" / "y.png").write_bytes(b"\0\1\2" * 2000)
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "blob")
    monkeypatch.chdir(repository / "src" / "sub")
    assert checker.main(["--base", base]) == 1
    assert "cannot be measured" in capsys.readouterr().out


def test_default_limit_is_pinned_to_1500() -> None:
    assert checker.DEFAULT_LIMIT == 1500


def test_non_steering_doc_deletions_are_exempt_while_additions_and_steering_count() -> None:
    listing = "\n".join(
        [
            "0\t3054\tdocs/audits/closed-pr-review-2026-11-02.json",
            "120\t2542\tdocs/known-limitations.md",
            "80\t1071\tROADMAP.md",
            "0\t5\tSHADOWSCAN_INTEGRATION.md",
            "10\t30\tCLAUDE.md",
            "5\t15\tSECURITY.md",
            "4\t6\tdocs/evil.py",
        ]
    )
    # Counted: 120 (known-limitations added) + 80 (ROADMAP added) + 40 (CLAUDE.md) + 20 (SECURITY.md) + 10 (docs/evil.py) = 270
    assert checker.changed_lines(listing) == 270
