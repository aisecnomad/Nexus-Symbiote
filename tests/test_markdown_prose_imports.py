"""Inventory and compare ordinary, in-project Markdown references."""

import pytest

from nexus_symbiote.instruction_diff import diff_instruction_trees
from nexus_symbiote.scanners.prompt import PromptScanner


def _project(root, rules):
    root.mkdir(exist_ok=True)
    (root / "guide.md").write_text("Project documentation.\n", encoding="utf-8")
    (root / "CLAUDE.md").write_text(rules, encoding="utf-8")


HTML = "<search>notes</search>\n\n"
SETEXT = "[^n]: notes\n---\n\n"
LAZY_QUOTE = "> diagrams\n    notes\n\n"
DEEP_QUOTE = ">" * 70 + " design notes\n\n"


@pytest.mark.parametrize("prefix", ["", HTML, SETEXT, LAZY_QUOTE, DEEP_QUOTE])
@pytest.mark.parametrize(
    "prose",
    [
        "A lone `\n\n`begin\nend`@guide.md",
        "- A lone `\n- `begin\n  end`@guide.md",
        "[chapter]: ./index.md\nRead `example`@guide.md",
        "See [public][chapter] and `example`@guide.md",
        "Use <span title='`'>this</span> and `example`@guide.md",
    ],
)
def test_scan_and_diff_observe_in_project_prose(tmp_path, prefix, prose):
    before, after = tmp_path / "before", tmp_path / "after"
    text = prefix + prose + "\n"
    _project(before, text.replace("@guide.md", ""))
    _project(after, text)
    refs = {component.bom_ref for component in PromptScanner().scan(after).components}
    assert "prompt:import:guide.md" in refs
    changes = diff_instruction_trees(before, after)["changes"]
    assert sum(c["class"] == "import_added" and "guide.md" in c["summary"] for c in changes) == 1


@pytest.mark.parametrize("trigger", [HTML, SETEXT, LAZY_QUOTE])
@pytest.mark.parametrize("example", ["Use x`@guide.md` here.", "请使用`@guide.md`作为例子。"])
def test_unpaired_backtick_in_other_item_keeps_examples_literal(tmp_path, trigger, example):
    before, after = tmp_path / "before", tmp_path / "after"
    _project(before, trigger + "- A lone `\n")
    _project(after, trigger + "- A lone `\n- " + example + "\n")
    result = PromptScanner().scan(after)
    assert not result.surfaces_excluded
    assert not any(c.bom_ref.startswith("prompt:import:") for c in result.components)
    assert "import_added" not in {
        c["class"] for c in diff_instruction_trees(before, after)["changes"]
    }


@pytest.mark.parametrize("trigger", ["", HTML, SETEXT, LAZY_QUOTE])
def test_blank_line_promoting_html_example_to_prose_is_an_import_change(tmp_path, trigger):
    before, after = tmp_path / "before", tmp_path / "after"
    _project(before, trigger + "<div>\nRead @guide.md\nSee @guide.md\n")
    _project(after, trigger + "<div>\nRead @guide.md\n\nSee @guide.md\n")
    changes = diff_instruction_trees(before, after)["changes"]
    assert sum(c["class"] == "import_added" for c in changes) == 1


@pytest.mark.parametrize("base_prefix", [HTML, SETEXT])
@pytest.mark.parametrize("head_prefix", [LAZY_QUOTE, DEEP_QUOTE])
def test_changed_ambiguity_preserves_a_new_prose_reference(tmp_path, base_prefix, head_prefix):
    before, after = tmp_path / "before", tmp_path / "after"
    example = "```text\nSee @guide.md\n```\n"
    _project(before, base_prefix + example)
    _project(after, head_prefix + example + "\nSee @guide.md\n")
    assert "import_added" in {c["class"] for c in diff_instruction_trees(before, after)["changes"]}


def test_unchanged_prose_across_a_blank_line_has_no_new_import(tmp_path):
    before, after = tmp_path / "before", tmp_path / "after"
    _project(before, LAZY_QUOTE + "Notes\nSee @guide.md\n")
    _project(after, LAZY_QUOTE + "Notes\n\nSee @guide.md\n")
    assert "import_added" not in {
        c["class"] for c in diff_instruction_trees(before, after)["changes"]
    }
