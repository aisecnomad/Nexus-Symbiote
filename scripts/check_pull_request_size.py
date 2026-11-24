"""Fail a pull request that changes more than the cap outside tests and benchmarks.

The count is insertions plus deletions across code, workflows, configuration, and agent
steering files. ``tests/`` and ``benchmarks/`` are excluded so a regression suite can be
large, and deleted lines in non-steering documentation (``docs/``, ``CHANGELOG.md``,
``ROADMAP.md``, ``SHADOWSCAN_INTEGRATION.md``) are excluded so retiring historical notes
or condensing prose is not penalized while every added documentation line still counts.
A binary file, which git reports as ``-``, is not counted in a tree where binaries are
expected, and fails the check anywhere else, since its change cannot be measured. Run it
in CI against the pull request's base, or pass ``--numstat-file`` for a review of a saved
``git diff --numstat`` listing.

The pull request controls its own ``.gitattributes``, which would let ``src/** -diff``
report every source change as binary, so git reads attributes from the base instead;
renames are not detected, so a move out of ``tests/`` counts at its destination. A file
the base marks ``-diff``, such as a vendored schema, is counted as text when both
sides are UTF-8 without a NUL byte; binary content anywhere else outside the expected
trees still fails, whatever its attributes. Paths are read NUL-separated and
unquoted, so a non-ASCII path keeps its prefix.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

SKIP_PREFIXES = ("tests/", "benchmarks/")
DOC_DELETION_EXEMPT_FILES = frozenset({"CHANGELOG.md", "ROADMAP.md", "SHADOWSCAN_INTEGRATION.md"})
# Trees whose binary files, such as images and model fixtures, are expected.
BINARY_PREFIXES = (*SKIP_PREFIXES, "docs/assets/", "examples/")
DEFAULT_LIMIT = 1500


class UnmeasuredChangeError(ValueError):
    """A binary change outside the trees where binaries are expected."""


Row = tuple[str, str, str]


def _exempt_deletions(path: str) -> bool:
    """Whether deleted lines in path are non-steering documentation reductions."""
    return path in DOC_DELETION_EXEMPT_FILES or (
        path.startswith("docs/") and path.endswith((".md", ".json"))
    )


def _rows(numstat: str) -> list[Row]:
    rows = []
    for line in numstat.splitlines():
        if line.strip():
            added, deleted, path = line.split("\t", 2)
            rows.append((added, deleted, path))
    return rows


def changed_lines(
    numstat: str | list[Row], *, skip_prefixes: tuple[str, ...] = SKIP_PREFIXES
) -> int:
    """Sum insertions and deletions, skipping test trees, binary rows, and pure doc deletions."""
    total = 0
    for added, deleted, path in _rows(numstat) if isinstance(numstat, str) else numstat:
        if path.startswith(skip_prefixes):
            continue
        if added == "-" or deleted == "-":
            if not path.startswith(BINARY_PREFIXES):
                raise UnmeasuredChangeError(
                    f"binary change outside {', '.join(BINARY_PREFIXES)}: {path!r}"
                )
            continue
        total += int(added) + (0 if _exempt_deletions(path) else int(deleted))
    return total


def _top_level() -> str:
    """The working tree's top: numstat prints root-relative paths, and every pathspec and
    tree lookup must read them from there, whatever directory the script starts in."""
    result = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--show-toplevel"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _git(base: str, *args: str) -> bytes:
    """Output of a git command that reads attributes from the base and prints raw paths."""
    result = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "core.quotePath=false",
            "--literal-pathspecs",
            f"--attr-source={base}",
            *args,
        ],
        check=False,
        capture_output=True,
        cwd=_top_level(),
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr.decode(errors="replace").strip() or "git failed")
    return result.stdout


def _fields(output: bytes) -> list[str]:
    return output.decode("utf-8", "surrogateescape").split("\0")[:-1]


def _require_text(base: str, path: str) -> None:
    """Refuse a -diff file whose content is binary: its newline count says nothing."""
    for revision in (base, "HEAD"):
        if not _git(base, "ls-tree", "-z", revision, "--", path):
            continue
        content = _git(base, "cat-file", "blob", f"{revision}:{path}")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = "\0"
        if "\0" in text:
            raise UnmeasuredChangeError(f"binary content in a -diff file: {path!r}")


def _text_row(base: str, path: str) -> Row:
    """A -diff file's numstat as text: numstat keeps it binary even with --text."""
    _require_text(base, path)
    patch = _git(
        base,
        "diff",
        "--text",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "-U0",
        base,
        "HEAD",
        "--",
        path,
    )
    added = deleted = 0
    in_hunk = False
    for line in patch.split(b"\n"):
        if line.startswith(b"diff --git "):
            in_hunk = False
        elif line.startswith(b"@@"):
            in_hunk = True
        elif in_hunk and line.startswith(b"+"):
            added += 1
        elif in_hunk and line.startswith(b"-"):
            deleted += 1
    return str(added), str(deleted), path


def _from_git(base: str) -> list[Row]:
    rows: list[Row] = []
    for record in _fields(_git(base, "diff", "--numstat", "-z", "--no-renames", base, "HEAD")):
        added, deleted, path = record.split("\t", 2)
        rows.append((added, deleted, path))
    binary = [
        path
        for added, deleted, path in rows
        if "-" in (added, deleted) and not path.startswith(BINARY_PREFIXES)
    ]
    if not binary:
        return rows
    # Only the base's attributes are trusted: a pull request cannot mark its own binary
    # content -diff to have it measured as text.
    fields = _fields(_git(base, "check-attr", "-z", "diff", "--", *binary))
    undiffed = {fields[i] for i in range(0, len(fields), 3) if fields[i + 2] == "unset"}
    return [_text_row(base, row[2]) if row[2] in undiffed else row for row in rows]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="Git ref to diff HEAD against, such as origin/main")
    parser.add_argument("--numstat-file", type=Path, help="A saved git diff --numstat listing")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    args = parser.parse_args(argv)
    if (args.base is None) == (args.numstat_file is None):
        parser.error("pass exactly one of --base and --numstat-file")
    try:
        listing: str | list[Row] = (
            args.numstat_file.read_text(encoding="utf-8")
            if args.numstat_file
            else _from_git(args.base)
        )
        total = changed_lines(listing)
    except UnmeasuredChangeError as exc:
        print(f"pull request size cannot be measured: {exc}")
        return 1
    print(f"pull request changes {total} lines outside tests/ and benchmarks/ (limit {args.limit})")
    return 1 if total > args.limit else 0


if __name__ == "__main__":
    raise SystemExit(main())
