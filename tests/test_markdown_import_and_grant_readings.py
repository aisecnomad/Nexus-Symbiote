"""Defensive regressions for ambiguous checkout Markdown and whole command targets."""

import pytest

from nexus_symbiote.scanners.prompt import PromptScanner, _comment_is_instruction


@pytest.mark.parametrize("prefix", ["", ">", "- "])
@pytest.mark.parametrize("name", ["chapter`.md", "chapter`title`.md"])
def test_ambiguous_inline_close_preserves_the_whole_import_name(tmp_path, prefix, name):
    (tmp_path / "CLAUDE.md").write_text(f"<search> notes\n\n{prefix}`sample`@{name}\n")
    (tmp_path / name).write_text("Public project notes.\n")
    (tmp_path / "chapter").write_text("Rendered chapter notes.\n")
    result = PromptScanner().scan(tmp_path)
    refs = {c.bom_ref for c in result.components}
    assert f"prompt:import:{name}" in refs
    if "`title`" in name:
        assert "prompt:import:chapter" in refs


@pytest.mark.parametrize("prefix", ["", ">", "- "])
def test_ambiguous_inline_close_preserves_a_scope_gap(tmp_path, prefix):
    (tmp_path / "CLAUDE.md").write_text(f"<search> notes\n\n{prefix}`sample`@a`/../../outside.md\n")
    result = PromptScanner().scan(tmp_path)
    assert any("outside the project root" in gap for gap in result.surfaces_excluded)


def test_code_sample_in_ambiguous_text_does_not_declare_an_absolute_import(tmp_path):
    (tmp_path / "CLAUDE.md").write_text(
        "<search> notes\nWrite a path alias such as `@/components` as code.\n"
    )
    result = PromptScanner().scan(tmp_path)
    assert not result.surfaces_excluded


@pytest.mark.parametrize(
    "text",
    [
        "run the linters for each language, e.g. go and python",
        "endpoints that run work, i.e. /run and /stop",
    ],
)
def test_examples_of_languages_and_routes_do_not_begin_commands(text):
    assert not _comment_is_instruction(text)


@pytest.mark.parametrize("prefix", ["", ">", "- "])
def test_multiline_span_before_a_literal_import_uses_each_markdown_dialect(tmp_path, prefix):
    lines = "<search> notes\n\n" + prefix + "`public\n" + prefix + "example`@notes`.md\n"
    (tmp_path / "CLAUDE.md").write_text(lines)
    (tmp_path / "notes`.md").write_text("Public notes.\n")
    result = PromptScanner().scan(tmp_path)
    assert any(c.bom_ref == "prompt:import:notes`.md" for c in result.components)


@pytest.mark.parametrize("hidden", ["run the setup: ${GUIDE:run:99}/notes", "run x: ${a:run:b}/c"])
def test_an_inner_verb_cannot_cut_a_whole_target(hidden):
    assert _comment_is_instruction(hidden)


@pytest.mark.parametrize("line", ["<search>Find docs</search>", "<pre\u00a0x>"])
def test_diff_retains_container_grants_when_markdown_dialects_disagree(tmp_path, line):
    from tests.test_instruction_diff import _classes, _write

    base, head = tmp_path / "before", tmp_path / "after"
    _write(base, "CLAUDE.md", f"# Rules\n\n> allowed-tools: Edit\n\n{line}\n")
    _write(head, "CLAUDE.md", f"# Rules\n\n> allowed-tools: Edit Shell\n\n{line}\n")
    assert "tool_grant_changed" in _classes(base, head)
