"""Distinguish an inline path example from a project import after a code span."""

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.prompt import PromptScanner


@pytest.mark.parametrize("trigger", ["<search>notes</search>", "[^note]: notes\n---"])
@pytest.mark.parametrize(
    "example",
    [
        "请使用`@/components`作为路径别名。",
        "Use x`@/components` here.",
        "Use x``@/components`` here.",
        "Use x`@/components here.",
    ],
)
def test_prose_attached_alias_is_not_an_import(tmp_path, trigger, example):
    (tmp_path / "CLAUDE.md").write_text(trigger + "\n\n" + example + "\n", encoding="utf-8")
    result = PromptScanner().scan(tmp_path)
    assert not result.surfaces_excluded
    gate = CliRunner().invoke(main, ["scan", str(tmp_path), "--check", "--no-project-policy"])
    assert gate.exit_code == 0, gate.output


@pytest.mark.parametrize("container", ["", "> ", "- "])
def test_import_after_an_actual_closing_run_is_retained(tmp_path, container):
    (tmp_path / "notes.md").write_text("Ordinary project notes.\n")
    (tmp_path / "CLAUDE.md").write_text(
        f"<search>notes</search>\n\n{container}`begin\n{container}end`@notes.md\n"
    )
    result = PromptScanner().scan(tmp_path)
    assert any(c.bom_ref == "prompt:import:notes.md" for c in result.components)


@pytest.mark.parametrize("between", ["\n\n", "\n>\n", "\n\n```text\nexample\n```\n\n"])
def test_unmatched_opener_in_a_separate_block_cannot_promote_an_alias(tmp_path, between):
    (tmp_path / "CLAUDE.md").write_text(
        "<search>notes</search>\n\n> `begin" + between + "> Use x`@/components` here.\n"
    )
    result = PromptScanner().scan(tmp_path)
    assert not result.surfaces_excluded
