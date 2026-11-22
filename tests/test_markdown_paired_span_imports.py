"""Compare inert project documentation when code span boundaries move."""

import pytest

from nexus_symbiote.instruction_diff import diff_instruction_trees
from nexus_symbiote.scanners.prompt import PromptScanner
from tests.test_markdown_prose_imports import DEEP_QUOTE, HTML, LAZY_QUOTE, SETEXT


def _project(root, text):
    root.mkdir()
    for name in ("one", "two", "guide", "chapter`title`"):
        (root / (name + ".md")).write_text("Project notes.\n")
    (root / "chapter").write_text("Rendered title.\n")
    (root / "CLAUDE.md").write_text(text)


@pytest.mark.parametrize("width", [2, 3, 4])
@pytest.mark.parametrize("inner", ["`n`@label", "`n`@label and `m`@other"])
def test_blank_line_makes_a_reference_inside_a_multiline_span_visible(tmp_path, width, inner):
    fence = "`" * width
    before = "`end`@one.md " + fence + "example\n@two.md\nRun " + inner + fence + " to check.\n"
    after = before.replace("@two.md\n", "@two.md\n\n")
    old, new = tmp_path / "before", tmp_path / "after"
    _project(old, before)
    _project(new, after)
    for root, present in ((old, False), (new, True)):
        refs = {c.bom_ref for c in PromptScanner().scan(root).components}
        assert ("prompt:import:two.md" in refs) is present
        assert "prompt:import:one.md" in refs
    changes = diff_instruction_trees(old, new)["changes"]
    assert any(c["class"] == "import_added" and "two.md" in c["summary"] for c in changes)


@pytest.mark.parametrize("prefix", ["", HTML, SETEXT, LAZY_QUOTE, DEEP_QUOTE])
def test_raw_html_does_not_promote_a_code_like_delimiter(tmp_path, prefix):
    old, new = tmp_path / "before", tmp_path / "after"
    _project(old, prefix + "<div>\nnotes\n</div>\n")
    _project(new, prefix + "<div>\nnotes\n`n`@guide.md\n</div>\n")
    refs = {c.bom_ref for c in PromptScanner().scan(new).components}
    assert "prompt:import:guide.md" not in refs
    changes = diff_instruction_trees(old, new)["changes"]
    assert not any(c["class"] == "import_added" and "guide.md" in c["summary"] for c in changes)


@pytest.mark.parametrize("prefix", ["", HTML, SETEXT, LAZY_QUOTE])
def test_real_prose_after_a_raw_html_block_still_uses_both_filename_readings(tmp_path, prefix):
    _project(tmp_path / "docs", prefix + "<div>\nraw\n\nRead `n`@chapter`title`.md\n")
    refs = {c.bom_ref for c in PromptScanner().scan(tmp_path / "docs").components}
    assert {"prompt:import:chapter`title`.md", "prompt:import:chapter"} <= refs
