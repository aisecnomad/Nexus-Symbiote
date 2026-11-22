"""A Markdown example cannot hide a change to the instructions that follow it."""

import pytest

from nexus_symbiote.scanners.prompt import PromptScanner, _comment_is_instruction
from tests.test_instruction_diff import _classes, _write

FOOTNOTE = "Setup\n[^1]: see the guide\n===\n\n"
HTML = "<search>Find project notes</search>\n\n"


@pytest.mark.parametrize("earlier", ["Press <kbd>Tab</kbd>.", '[guide](notes.md "Guide")'])
def test_multiline_code_boundary_preserves_import_after_footnote(tmp_path, earlier):
    name = "chapter`.md"
    (tmp_path / name).write_text("Project notes.\n")
    (tmp_path / "CLAUDE.md").write_text(
        FOOTNOTE + earlier + "\n\nRead the `project\nguide`@" + name + "\n\n> Note.\n"
    )
    result = PromptScanner().scan(tmp_path)
    assert "prompt:import:" + name in {c.bom_ref for c in result.components}


def test_footnote_ambiguity_keeps_the_outside_root_coverage_gap(tmp_path):
    (tmp_path / "CLAUDE.md").write_text(
        FOOTNOTE + "Press <kbd>Tab</kbd>.\n\nRead the `project\nguide`@../notes.md\n\n> Note.\n"
    )
    assert any(
        "outside the project root" in s for s in PromptScanner().scan(tmp_path).surfaces_excluded
    )


@pytest.mark.parametrize("punctuation", ["!", "?"])
def test_later_verb_punctuation_preserves_following_instruction(punctuation):
    assert _comment_is_instruction(
        f"To run checks, e.g. lint, just run{punctuation} Next: ./example.sh"
    )


@pytest.mark.parametrize("prefix", [HTML, FOOTNOTE])
@pytest.mark.parametrize("example", ["```\nRead @notes.md\n```\n", "    Read @notes.md\n"])
def test_example_does_not_mask_a_new_import_in_prose(tmp_path, prefix, example):
    base, head = tmp_path / "base", tmp_path / "head"
    text = prefix + example
    for root in (base, head):
        _write(root, "notes.md", "Project notes.\n")
    _write(base, "CLAUDE.md", text)
    _write(head, "CLAUDE.md", text + "\nSee @notes.md\n")
    assert _classes(base, head).count("import_added") == 1


@pytest.mark.parametrize("end", ["\n", "\r"])
def test_footnote_grant_is_preserved_on_supported_line_endings(tmp_path, end):
    base, head = tmp_path / "base", tmp_path / "head"
    _write(base, "CLAUDE.md", FOOTNOTE.replace("\n", end).encode())
    _write(head, "CLAUDE.md", (FOOTNOTE + "> allowed-tools: Read\n").replace("\n", end).encode())
    assert "tool_grant_changed" in _classes(base, head)


@pytest.mark.parametrize("end", ["\n", "\r"])
def test_fenced_grant_does_not_mask_a_new_grant_in_prose(tmp_path, end):
    base, head = tmp_path / "base", tmp_path / "head"
    text = FOOTNOTE + "```\nallowed-tools: Read\n```\n"
    _write(base, "CLAUDE.md", text.replace("\n", end).encode())
    _write(head, "CLAUDE.md", (text + "\n> allowed-tools: Read\n").replace("\n", end).encode())
    assert "tool_grant_changed" in _classes(base, head)
