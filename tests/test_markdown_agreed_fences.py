"""Fenced examples shared by both supported HTML readings stay examples."""

import pytest

from nexus_symbiote.scanners.prompt import PromptScanner
from tests.test_instruction_diff import _classes, _write


@pytest.mark.parametrize("tag", ["<search>Notes</search>", "<pre\u00a0x>\n</pre>"])
def test_fenced_home_example_has_no_scope_gap_when_both_readers_agree(tmp_path, tag):
    _write(tmp_path, "CLAUDE.md", f"{tag}\n\n```text\nSee @~/example/notes.md\n```\n")
    assert not PromptScanner().scan(tmp_path).surfaces_excluded


def test_html_that_still_contains_the_example_keeps_the_scope_gap(tmp_path):
    _write(tmp_path, "CLAUDE.md", "<pre\u00a0x>\n\n```text\nSee @~/example/notes.md\n```\n")
    assert any(
        "outside the project root" in gap
        for gap in PromptScanner().scan(tmp_path).surfaces_excluded
    )


def test_new_example_is_excluded_in_both_diff_readings(tmp_path):
    base, head = tmp_path / "before", tmp_path / "after"
    common = "<search>Notes</search>\n\n"
    _write(base, "CLAUDE.md", common)
    _write(head, "CLAUDE.md", common + "```text\nRead @sample.md\n```\n")
    assert "import_added" not in _classes(base, head)
