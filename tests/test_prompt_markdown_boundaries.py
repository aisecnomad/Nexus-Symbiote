"""Security classifications across Markdown block and sentence boundaries."""

import pytest

from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.scanners.prompt import (
    PromptScanner,
    _comment_is_instruction,
    detect_hidden_markup,
)
from tests.support import scaling_ratio


@pytest.mark.parametrize(
    "memory",
    [
        "<search>Notes\n\n>@chapter.md\n>@../outside.md",
        "Notes\n[^1]: footnote\n---\n\n>@chapter.md\n>@../outside.md",
        "See `one`@chapter.md and `two`@../outside.md\n\n<pre\u00a0x",
    ],
)
def test_ambiguous_markdown_keeps_imported_text_and_scope_gaps(tmp_path, memory):
    (tmp_path / "CLAUDE.md").write_text(memory)
    (tmp_path / "chapter.md").write_text("Ordinary project documentation.")
    result = PromptScanner().scan(tmp_path)
    assert any(c.bom_ref == "prompt:import:chapter.md" for c in result.components)
    assert any("outside the project root" in gap for gap in result.surfaces_excluded)


@pytest.mark.parametrize("abbreviation", ["e.g.", "i.e."])
@pytest.mark.parametrize("example", ["1. python --version", "$python"])
def test_each_run_in_one_sentence_is_classified(abbreviation, example):
    text = f"<!-- run the checks, {abbreviation} run {example} -->"
    (finding,) = detect_hidden_markup(text, "CLAUDE.md")
    assert finding.severity == RiskSeverity.HIGH


def test_formatting_a_long_environment_value_does_not_hide_the_command():
    value = "ordinary" * 120
    assert _comment_is_instruction(f"run MODE={value} python --version")


def test_scanning_assignment_words_grows_with_text_length():
    notes = {scale: "run:a=" * (900 * scale) for scale in (1, 4)}
    assert scaling_ratio(lambda scale: _comment_is_instruction(notes[scale])) < 10
