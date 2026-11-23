"""Muse F-370-1: a default-excluded directory does not make the MCP source walk incomplete.

``pkg/srv.py`` serves its tools through the Python SDK beside ``pkg/mcp.py``, a passive
helper named for the SDK's import root. The import resolves past the helper only while
the walk is complete, so an ordinary checkout, whose occupied ``.git`` is a default
exclude, dropped the server's tools. A default-excluded entry is reported as a gap and
handed to the search as unvisited instead; an explicit exclusion still fails closed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.utils.confined import ConfinedCollection

_GAP = "pkg/srv.py: Python SDK import may resolve to checkout code"
_GIT_GAP = ".git: default collection exclude; not collected"
_POLICY_GAP = "other_excluded: excluded by collection policy"
_EVERY_TOOL = ["ping", "pong", "real", "top"]
_WITHOUT_HELPER = ["pong", "top"]


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _server(name: str, tool: str) -> str:
    return (
        "from mcp.server.fastmcp import FastMCP\n"
        f"app = FastMCP({name!r})\n"
        "@app.tool()\n"
        f"def {tool}() -> str:\n"
        "    return 'pong'\n"
    )


def _checkout(root: Path, *, git: bool = False, helper: str = "HELPER = 1\n") -> None:
    """``real``/``ping`` need the helper read as passive; ``top``/``pong`` need no helper."""
    _write(root, "pkg/__init__.py", "")
    _write(root, "pkg/mcp.py", helper)
    _write(root, "pkg/srv.py", _server("real", "ping"))
    _write(root, "top.py", _server("top", "pong"))
    if git:
        _write(root, ".git/HEAD", "ref: refs/heads/main\n")


def _names(result: ScanResult) -> list[str]:
    assert not result.scan_failures
    return sorted(component.name for component in result.components)


def test_git_metadata_keeps_the_walk_complete(tmp_path: Path) -> None:
    clean, with_git = tmp_path / "clean", tmp_path / "with_git"
    _checkout(clean)
    _checkout(with_git, git=True)
    assert _names(MCPScanner().scan(clean)) == _EVERY_TOOL

    result = MCPScanner().scan(with_git)
    assert _names(result) == _EVERY_TOOL
    assert result.surfaces_excluded == [_GIT_GAP]


def test_an_explicit_exclusion_leaves_the_walk_incomplete(tmp_path: Path) -> None:
    _checkout(tmp_path, git=True)
    _write(tmp_path, "other_excluded/x.py", "x = 1\n")
    scanner = MCPScanner()
    scanner.configure(exclude_paths=("other_excluded",))
    result = scanner.scan(tmp_path)
    assert _names(result) == _WITHOUT_HELPER
    assert result.surfaces_excluded == [_GIT_GAP, _POLICY_GAP, _GAP]


@pytest.mark.parametrize("cache", ["__pycache__", "__PYCACHE__", "__pycache__."])
def test_a_bytecode_cache_beside_the_helper_still_fails_closed(tmp_path: Path, cache: str) -> None:
    # A case-insensitive file system opens each spelling as the cache Python loads from.
    _checkout(tmp_path, git=True)
    _write(tmp_path, f"pkg/{cache}/mcp.cpython-312.pyc", "bytecode")
    result = MCPScanner().scan(tmp_path)
    assert _names(result) == _WITHOUT_HELPER
    assert _GAP in result.surfaces_excluded


@pytest.mark.parametrize(
    "sibling",
    [
        "pkg/venv/__init__.py",
        "pkg/VENV/__init__.py",
        "venv/__init__.py",
        "pkg/mcp/.git/HEAD",
        "pkg/mcp/venv/pyvenv.cfg",
    ],
)
def test_an_unvisited_sibling_keeps_the_helper_uncertain(tmp_path: Path, sibling: str) -> None:
    # ``venv`` is both a default exclude and a standard module, so a checkout copy in a
    # search root can shadow what the helper imports; an excluded entry under a
    # directory named for the SDK leaves that package's contents unread.
    _checkout(tmp_path, git=True, helper="import logging\nHELPER = 1\n")
    _write(tmp_path, sibling, "server = object()\n")
    result = MCPScanner().scan(tmp_path)
    assert _names(result) == _WITHOUT_HELPER
    assert _GAP in result.surfaces_excluded


def test_the_listed_exclusions_are_classified_without_a_collection_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(ConfinedCollection, "policy_exclusions_recorded", raising=False)
    _checkout(tmp_path, git=True)
    assert _names(MCPScanner().scan(tmp_path)) == _EVERY_TOOL

    _write(tmp_path, "other_excluded/x.py", "x = 1\n")
    scanner = MCPScanner()
    scanner.configure(exclude_paths=("other_excluded",))
    assert _names(scanner.scan(tmp_path)) == _WITHOUT_HELPER


@pytest.mark.parametrize(("recorded", "expected"), [(0, _EVERY_TOOL), (1, _WITHOUT_HELPER)])
def test_a_collection_count_of_policy_exclusions_is_read_instead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorded: int, expected: list[str]
) -> None:
    monkeypatch.setattr(
        ConfinedCollection,
        "policy_exclusions_recorded",
        property(lambda self: recorded),
        raising=False,
    )
    _checkout(tmp_path, git=True)
    assert _names(MCPScanner().scan(tmp_path)) == expected
