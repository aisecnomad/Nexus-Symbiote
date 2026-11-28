"""An A2A agent card built in Python is a gap however its module is sized, encoded or spelled.

The SDK search streams each module under the source budget, so no size short of that
budget hides a card. It searches the text Python reads: decoded as the module's encoding
declaration says, with identifiers compared in NFKC form, as Python compares them.
"""

from __future__ import annotations

import json
import tracemalloc
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.limits import Bound
from nexus_symbiote.scanners import a2a
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.utils import confined

BUILT = "A2A agent card built in Python code is not inventoried"
SOURCE_UNREAD = "source file is larger than the file-bytes limit; not read"
UNPARSED = (
    "Python source that names AgentCard could not be parsed; "
    "an agent card it builds is not inventoried"
)
UNFOLLOWED = (
    "Python source encoding declaration could not be followed; "
    "an agent card it builds is not inventoried"
)
HINTS = (b"a2a", b"A2AClient", b"AgentCard")
CARD_MODULE = (
    "from a2a.server.apps import A2AStarletteApplication\n"
    "from a2a.types import AgentCard\n"
    "card = AgentCard(name='payments', url='http://evil.example/a2a', version='1.0.0', skills=[])\n"
    "app = A2AStarletteApplication(agent_card=card, http_handler=None)\n"
)


def _wide(text: str) -> str:
    """``text`` in fullwidth forms, which NFKC folds back to ASCII."""
    return "".join(chr(ord(character) + 0xFEE0) for character in text)


def _spelled(package: str, card: str) -> str:
    return (
        f"from {package}.types import {card}\n"
        f"card = {card}(name='payments', url='http://evil.example/agent', skills=[])\n"
    )


FULLWIDTH_MODULE = _spelled(_wide("a2a"), _wide("AgentCard"))


def _padded(content: bytes, size: int) -> bytes:
    """``content`` followed by one comment line that brings it to exactly ``size`` bytes."""
    padded = content + b"# " + b"x" * (size - len(content) - 3) + b"\n"
    assert len(padded) == size
    return padded


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _project(root: Path) -> Path:
    root.mkdir()
    (root / "CLAUDE.md").write_text("# Project\n\nBenign instructions.\n")
    return root


def _scan(project: Path, output: Path, *prefix: str):
    return CliRunner().invoke(
        main, [*prefix, "scan", str(project), "--no-project-policy", "-o", str(output)]
    )


def _completeness(output: Path) -> dict:
    completeness: dict = json.loads(output.read_text())["metadata"]["completeness"]
    return completeness


@pytest.mark.parametrize(
    "relative", ["agent_server.py", "src/agent_server.py", "services/pay/agent_server.py"]
)
def test_card_module_one_byte_past_file_bytes_fails_every_gate(tmp_path, relative):
    # One byte past file-bytes, the module was skipped silently and every gate passed.
    project = _project(tmp_path / "project")
    before = tmp_path / "before.json"
    assert _scan(project, before).exit_code == 0
    _write(project / relative, _padded(CARD_MODULE.encode(), limits.DEFAULTS.file_bytes + 1))
    after = tmp_path / "after.json"
    scan = _scan(project, after)
    assert scan.exit_code == 1, scan.output
    completeness = _completeness(after)
    # The source collector cannot tell what a file it did not read holds either.
    assert completeness["surfaces_excluded"] == sorted(
        [f"{relative}: {UNPARSED}", f"{relative}: {SOURCE_UNREAD}"]
    )
    assert completeness["scanner_status"]["a2a"] == "partial"
    assert completeness["scanner_status"]["source"] == "partial"
    diff = CliRunner().invoke(main, ["diff", str(before), str(after), "--fail-on-alert"])
    assert diff.exit_code == 1, diff.output
    validate = CliRunner().invoke(
        main, ["validate", "--no-project-policy", str(after), "--project", str(project)]
    )
    assert validate.exit_code == 1, validate.output


def test_lowered_file_bytes_never_hides_a_card_module(tmp_path):
    # Lowering a limit can only add failures; it used to remove this gap.
    project = _project(tmp_path / "project")
    _write(project / "agent_server.py", _padded(CARD_MODULE.encode(), 100_000))
    output = tmp_path / "bom.json"
    run = _scan(project, output, "--limit", "file-bytes=64KiB")
    assert run.exit_code == 1, run.output
    completeness = _completeness(output)
    assert completeness["surfaces_excluded"] == sorted(
        [f"agent_server.py: {BUILT}", f"agent_server.py: {SOURCE_UNREAD}"]
    )
    assert completeness["scanner_status"]["a2a"] == "partial"


def test_fullwidth_card_module_fails_the_scan_and_drift_gates(tmp_path):
    project = _project(tmp_path / "project")
    before = tmp_path / "before.json"
    assert _scan(project, before).exit_code == 0
    _write(project / "server.py", FULLWIDTH_MODULE.encode())
    after = tmp_path / "after.json"
    scan = _scan(project, after)
    assert scan.exit_code == 1, scan.output
    assert _completeness(after)["surfaces_excluded"] == [f"server.py: {BUILT}"]
    diff = CliRunner().invoke(main, ["diff", str(before), str(after), "--fail-on-alert"])
    assert diff.exit_code == 1, diff.output


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(FULLWIDTH_MODULE.encode(), id="fullwidth"),
        pytest.param(_spelled("\u00aa2\u00aa", "AgentC\u00aard").encode(), id="ordinal-letter"),
        pytest.param(
            _spelled("\U0001d41a2\U0001d41a", "\U0001d400gentCard").encode(), id="math-bold"
        ),
        pytest.param(
            b"# -*- coding: latin-1 -*-\n"
            + _spelled("\u00aa2\u00aa", "AgentC\u00aard").encode("latin-1"),
            id="declared-latin-1",
        ),
        pytest.param(
            b"# coding: shift_jis\n" + FULLWIDTH_MODULE.encode("shift_jis"),
            id="declared-shift-jis",
        ),
        pytest.param(
            b"# coding: gb18030\n"
            + _spelled("\U0001d41a2\U0001d41a", "\U0001d400gentCard").encode("gb18030"),
            id="declared-gb18030",
        ),
    ],
)
def test_compatibility_spellings_are_read_as_python_reads_them(tmp_path, content):
    # Python folds each identifier to NFKC, so these import and build a2a.types.AgentCard
    # although no hint appears in their bytes.
    assert not any(hint in content for hint in HINTS)
    _write(tmp_path / "server.py", content)
    result = A2AScanner().scan(tmp_path)
    assert result.surfaces_excluded == [f"server.py: {BUILT}"]
    assert not result.scan_failures
    assert [component.bom_ref for component in result.components] == ["a2a-server:code-detected"]


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(
            b"# coding: utf-7\nfrom +AGE-2a.types import +AEE-gentCard\n"
            b"card = +AEE-gentCard(name='payments', url='http://evil.example/agent')\n",
            id="utf-7",
        ),
        pytest.param(
            b"# coding: unicode_escape\nfrom \\x61\\x32\\x61.types import \\x41gentCard\n"
            b"card = \\x41gentCard(name='payments', url='http://evil.example/agent')\n",
            id="unicode-escape",
        ),
    ],
)
def test_encoding_the_search_cannot_follow_is_a_gap(tmp_path, content):
    # Python decodes these to an AgentCard import and call; the search cannot read them.
    assert not any(hint in content for hint in HINTS)
    _write(tmp_path / "server.py", content)
    result = A2AScanner().scan(tmp_path)
    assert result.surfaces_excluded == [f"server.py: {UNFOLLOWED}"]
    assert not result.scan_failures


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(
            "# -*- coding: utf-8 -*-\nGREETING = 'héllo 世界 \U0001f600'\n".encode(),
            id="utf-8",
        ),
        pytest.param(b"\xef\xbb\xbfNAME = 'caf\xc3\xa9'\n", id="byte-order-mark"),
        pytest.param(b"# -*- coding: cp1252 -*-\nNAME = 'caf\xe9 \x80'\n", id="declared-cp1252"),
        pytest.param(
            b"# coding: shift_jis\nNAME = '" + "日本".encode("shift_jis") + b"'\n",
            id="declared-shift-jis",
        ),
        pytest.param(b"NAME = 'caf\xe9'\n", id="not-utf-8"),
    ],
)
def test_ordinary_non_ascii_modules_are_silent(tmp_path, content):
    _write(tmp_path / "pkg" / "names.py", content)
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    assert not result.components


def test_module_in_a_declared_encoding_is_parsed_as_python_reads_it(tmp_path):
    # Read as UTF-8, the byte 0xe9 made this module unparsable and its import unseen.
    _write(
        tmp_path / "client.py",
        b"# -*- coding: latin-1 -*-\nfrom a2a.client import A2AClient\nNAME = 'caf\xe9'\n",
    )
    result = A2AScanner().scan(tmp_path)
    assert [component.bom_ref for component in result.components] == ["a2a-client:code-detected"]
    assert not result.surfaces_excluded and not result.scan_failures


@pytest.mark.parametrize(
    ("character", "extra", "expected"),
    [("x", 0, BUILT), ("x", 1, UNPARSED), ("\U0001d400", 0, BUILT), ("\U0001d400", 1, UNPARSED)],
)
def test_parsed_window_is_counted_in_characters(tmp_path, character, extra, expected):
    # 262,144 characters are parsed even when each takes four bytes; one more is a gap.
    count = 262_144 - len(CARD_MODULE) - len("# \n") + extra
    _write(tmp_path / "server.py", f"{CARD_MODULE}# {character * count}\n".encode())
    result = A2AScanner().scan(tmp_path)
    assert result.surfaces_excluded == [f"server.py: {expected}"]


@pytest.mark.parametrize(
    "card",
    [
        pytest.param(CARD_MODULE, id="ascii"),
        pytest.param(FULLWIDTH_MODULE, id="fullwidth"),
        pytest.param(_spelled("a2a", "Agent" + _wide("Card")), id="partly-fullwidth"),
    ],
)
def test_card_at_the_end_of_a_large_module_is_a_gap(tmp_path, card):
    filler = b"VALUES = [\n" + b"    1234567,\n" * 400_000 + b"]\n"
    _write(tmp_path / "pkg" / "server.py", filler + card.encode())
    result = A2AScanner().scan(tmp_path)
    assert result.surfaces_excluded == [f"pkg/server.py: {UNPARSED}"]
    assert not result.scan_failures


@pytest.mark.parametrize(
    "filler",
    [
        pytest.param("    1234567,\n", id="ascii"),
        pytest.param("    '\u7ffb\u8a33\u30c7\u30fc\u30bf',\n", id="cjk"),
        pytest.param("    '\uff11\uff12\uff13\u2460\ufb01',\n", id="compatibility-forms"),
    ],
)
def test_large_generated_module_without_a_card_is_silent(tmp_path, filler):
    # A module far beyond the parsed window, even one that imports the SDK, is no gap
    # unless it names AgentCard.
    body = "import a2a\nVALUES = [\n" + filler * (5_000_000 // len(filler.encode())) + "]\n"
    _write(tmp_path / "generated.py", body.encode())
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    assert not result.components


@pytest.mark.parametrize("card", [CARD_MODULE, FULLWIDTH_MODULE], ids=["ascii", "fullwidth"])
@pytest.mark.parametrize(("head", "expected"), [(None, BUILT), (64, UNPARSED)])
def test_hint_split_across_reads_is_found(tmp_path, monkeypatch, card, head, expected):
    # Five-byte reads split every hint, and every fullwidth letter, at some offset.
    monkeypatch.setattr(a2a, "_CHUNK_BYTES", 5)
    if head is not None:
        monkeypatch.setattr(a2a, "_HEAD_BYTES", head)
    for offset in range(16):
        root = tmp_path / str(offset)
        _write(root / "server.py", f"x = 1  # {'p' * offset}\n{card}".encode())
        result = A2AScanner().scan(root)
        assert result.surfaces_excluded == [f"server.py: {expected}"], offset
        assert not result.scan_failures


def test_lowered_total_bytes_never_reads_as_complete(tmp_path):
    # The search's own byte limit refused the card module and nothing was recorded.
    for index in range(7):
        _write(tmp_path / f"module_{index}.py", b"#" * 511 + b"\n")
    _write(tmp_path / "zz_card.py", _padded(CARD_MODULE.encode(), 2048))
    settings = replace(limits.DEFAULTS, total_bytes=limits.KIB, source_scan_bytes=4 * limits.KIB)
    with limits.applied(settings):
        result = A2AScanner().scan(tmp_path)
    recorded = result.scan_failures + result.surfaces_excluded
    assert [entry.split(": ", 1)[0] for entry in recorded] == ["zz_card.py"]


def test_module_larger_than_the_source_budget_is_a_named_failure(tmp_path):
    _write(tmp_path / "server.py", _padded(CARD_MODULE.encode(), 100_000))
    budget = 64 * limits.KIB
    settings = replace(limits.DEFAULTS, file_bytes=32 * limits.KIB, source_scan_bytes=budget)
    with limits.applied(settings):
        result = A2AScanner().scan(tmp_path)
    assert result.scan_failures == [f"server.py: {Bound(budget, 'source-scan-bytes').exceeded()}"]


def test_module_that_changes_during_the_read_is_a_named_failure(tmp_path, monkeypatch):
    module = tmp_path / "server.py"
    _write(module, CARD_MODULE.encode())
    original = confined._BoundedReader.read
    appended: list[bool] = []

    def read_then_append(self, size=-1):
        data = original(self, size)
        if data and not appended:
            appended.append(True)
            with module.open("ab") as handle:
                handle.write(b"# appended during the read\n")
        return data

    monkeypatch.setattr(confined._BoundedReader, "read", read_then_append)
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures == ["server.py: file changed during collection"]


def test_search_memory_does_not_grow_with_module_size(tmp_path):
    # Text not in NFKC form is folded a slice at a time, and U+FDFA expands to eighteen
    # characters, so a whole-file read or fold would grow with the module.
    peaks = []
    line = ("    '" + "x" * 32 + "\ufdfa" * 4 + "',\n").encode()
    for size in (2 * limits.MIB, 8 * limits.MIB):
        root = tmp_path / str(size)
        _write(root / "table.py", b"VALUES = [\n" + line * (size // len(line)) + b"]\n")
        tracemalloc.start()
        try:
            result = A2AScanner().scan(root)
            peaks.append(tracemalloc.get_traced_memory()[1])
        finally:
            tracemalloc.stop()
        assert not result.scan_failures and not result.surfaces_excluded
    assert peaks[1] < peaks[0] + limits.MIB, peaks
