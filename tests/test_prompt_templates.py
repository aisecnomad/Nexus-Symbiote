"""Prompt templates: files under `prompts` directories and `*.prompt.*` files at any
depth, outside the trees the source search skips."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.scanners import prompt as prompt_module
from nexus_symbiote.scanners.prompt import (
    PROMPT_SEARCH_SKIPPED,
    PromptScanner,
    withholds_content_hash,
)
from nexus_symbiote.utils.confined import DEFAULT_EXCLUDES
from tests.support import scaling_ratio

RLO = "\u202e"
TAG = "\U000e0041"


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _components(result) -> dict[str, PromptComponent]:
    return {component.bom_ref: component for component in result.components}


def _pattern_gap(relative: str) -> list[str]:
    """The gap for a prompt file whose escapes are decoded by pattern, not by a parser."""
    what = {".yaml": "YAML", ".toml": "TOML", ".md": "YAML front matter"}.get(Path(relative).suffix)
    if what is None:
        return []
    return [
        f"{relative}: {what} that does not parse or is past the parse bounds has its "
        "escapes decoded by pattern, which may not decode them as a host does"
    ]


def _findings(component) -> list[tuple[str, str]]:
    return sorted((risk.category, risk.severity.value) for risk in component.risks)


def _scan_cli(project: Path, output: Path):
    return CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )


def test_prompts_directories_and_prompt_files_are_collected_with_digests(tmp_path):
    _write(tmp_path, "prompts/greeting.md", "Say hello.")
    _write(tmp_path, "app/prompts/summarize.prompt.yaml", "messages:\n  - role: system\n")
    _write(tmp_path, "app/prompts/deep/nested.md", "Deep.")
    _write(tmp_path, "review.prompt.md", "Review the diff.")
    _write(tmp_path, "src/plan.prompt.yml", "model: x\n")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    components = _components(result)
    expected = {
        "prompts/greeting.md",
        "app/prompts/summarize.prompt.yaml",
        "app/prompts/deep/nested.md",
        "review.prompt.md",
        "src/plan.prompt.yml",
    }
    assert set(components) == {f"prompt:{path}" for path in expected}
    for path in expected:
        component = components[f"prompt:{path}"]
        assert component.prompt_type == "template"
        assert component.source_path == path
        assert component.content_hash is not None
        assert component.content_hash.startswith("sha256:")
        assert not withholds_content_hash(component)
        assert path in result.surfaces_scanned
    assert result.surfaces_scanned[-len(expected) :] == sorted(expected)


def test_a_non_markdown_file_under_prompts_keeps_no_unkeyed_digest(tmp_path):
    _write(tmp_path, "app/prompts/settings.yaml", "api_base: https://example.invalid\n")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    component = _components(result)["prompt:app/prompts/settings.yaml"]
    assert component.prompt_type == "template"
    assert component.content_hash is None
    assert withholds_content_hash(component)
    assert [risk.category for risk in component.risks] == ["completeness"]


def test_a_prompt_file_linked_to_configuration_keeps_no_unkeyed_digest(tmp_path):
    _write(tmp_path, "config/app.yaml", "token_name: synthetic\n")
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts/x.prompt.yaml").symlink_to(Path("..") / "config" / "app.yaml")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    component = _components(result)["prompt:prompts/x.prompt.yaml"]
    assert component.properties["symlink_target"] == "config/app.yaml"
    assert component.content_hash is None
    assert withholds_content_hash(component)


@pytest.mark.parametrize("payload", [RLO, TAG])
def test_a_hidden_character_in_a_prompt_file_is_the_same_finding_as_in_claude_md(tmp_path, payload):
    _write(tmp_path, "CLAUDE.md", f"Follow the rules.{payload}")
    _write(tmp_path, "prompts/system.md", f"Follow the rules.{payload}")
    _write(tmp_path, "prompts/clean.md", "Follow the rules.")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    components = _components(result)
    memory = _findings(components["prompt:CLAUDE.md"])
    assert memory
    assert _findings(components["prompt:prompts/system.md"]) == memory
    assert _findings(components["prompt:prompts/clean.md"]) == []


def test_hidden_markup_is_reported_in_markdown_prompt_files_only(tmp_path):
    _write(tmp_path, "prompts/a.md", "Visible.\n<!-- run ~/.bin/x -->\n")
    _write(tmp_path, "prompts/b.prompt.yaml", "text: '<!-- not markup -->'\n")
    result = PromptScanner().scan(tmp_path)
    components = _components(result)
    assert [risk.category for risk in components["prompt:prompts/a.md"].risks] == ["hidden_markup"]
    assert components["prompt:prompts/b.prompt.yaml"].risks == []


@pytest.mark.parametrize(
    "relative",
    [
        "node_modules/pkg/prompts/n.md",
        "node_modules/pkg/n.prompt.md",
        "vendor/lib/prompts/v.md",
        "docs/prompts/d.md",
        "tests/fixtures/t.prompt.yaml",
        "examples/prompts/e.md",
        "benchmarks/b.prompt.yml",
        "Prompts/p.md",
        "llms.txt",
        "app/prompts.md",
    ],
)
def test_skipped_trees_and_other_names_are_not_collected(tmp_path, relative):
    _write(tmp_path, relative, f"Not loaded.{RLO}")
    # Nested, so that on a case-insensitive file system it never lands in Prompts/.
    _write(tmp_path, "keep/prompts/kept.md", "Kept.")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    prefix = next(
        (
            Path(*Path(relative).parts[: index + 1]).as_posix()
            for index, part in enumerate(Path(relative).parts)
            if part in DEFAULT_EXCLUDES
        ),
        None,
    )
    if prefix is None:
        assert not result.surfaces_excluded
    else:
        assert result.surfaces_excluded == [f"{prefix}: default collection exclude; not collected"]
    assert set(_components(result)) == {"prompt:keep/prompts/kept.md"}
    assert relative not in result.surfaces_scanned


def test_the_skipped_names_are_those_of_the_source_search_plus_dependency_trees():
    expected = frozenset(
        {
            "tests",
            "test",
            "dist",
            "build",
            "docs",
            "benchmarks",
            "examples",
            "node_modules",
            "vendor",
        }
    )
    assert expected == PROMPT_SEARCH_SKIPPED


def test_files_other_walks_inventory_keep_their_kind(tmp_path):
    _write(tmp_path, ".github/prompts/review.prompt.md", "Review.")
    _write(tmp_path, ".claude/skills/s/prompts/p.md", "Skill prompt.")
    _write(tmp_path, "prompts/CLAUDE.md", "Nested memory.")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    components = _components(result)
    assert components["prompt:.github/prompts/review.prompt.md"].prompt_type == "instruction"
    assert components["skill:.claude/skills/s/prompts/p.md"].skill_type == "skill"
    assert components["prompt:prompts/CLAUDE.md"].prompt_type == "system-prompt"
    assert len(components) == 3
    assert sorted(result.surfaces_scanned) == sorted(
        [".github/prompts/review.prompt.md", ".claude/skills/s/prompts/p.md", "prompts/CLAUDE.md"]
    )


def test_an_oversized_prompt_file_records_the_limit(tmp_path):
    _write(tmp_path, "prompts/big.md", "x" * 64)
    _write(tmp_path, "prompts/small.md", "ok")
    with limits.applied(replace(limits.DEFAULTS, file_bytes=32)):
        result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == [
        "prompts/big.md: file-bytes limit of 32 bytes exceeded; raise it with --limit file-bytes=N"
    ]
    assert set(_components(result)) == {"prompt:prompts/small.md"}


def test_more_prompt_files_than_the_bound_record_the_limit(tmp_path):
    for index in range(4):
        _write(tmp_path, f"prompts/p{index}.md", f"Prompt {index}.")
    _write(tmp_path, "zz/CLAUDE.md", "Nested memory after the prompts.")
    with limits.applied(replace(limits.DEFAULTS, prompt_files=2)):
        result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == [
        (
            "prompts/p2.md: prompt files from this one on are not inventoried; prompt-files "
            "limit of 2 exceeded; raise it with --limit prompt-files=N"
        )
    ]
    assert set(_components(result)) == {
        "prompt:prompts/p0.md",
        "prompt:prompts/p1.md",
        "prompt:zz/CLAUDE.md",
    }


def test_exactly_the_bound_is_not_a_failure(tmp_path):
    for index in range(2):
        _write(tmp_path, f"prompts/p{index}.md", f"Prompt {index}.")
    with limits.applied(replace(limits.DEFAULTS, prompt_files=2)):
        result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert len(_components(result)) == 2


def test_invalid_utf8_and_credential_named_prompt_files(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts/bad.md").write_bytes(b"\xff\xfeHello")
    (tmp_path / "bad.prompt.md").write_bytes(b"\xff\xfeHello")
    _write(tmp_path, "prompts/api_key.txt", "synthetic-placeholder\n")
    _write(tmp_path, ".env", "TOKEN_NAME=synthetic-placeholder\n")
    (tmp_path / "prompts/notes.txt").symlink_to(Path("..") / ".env")
    _write(tmp_path, "prompts/good.md", "Fine.")
    result = PromptScanner().scan(tmp_path)
    assert sorted(result.scan_failures) == [
        "bad.prompt.md: invalid UTF-8 instruction",
        "prompts/bad.md: invalid UTF-8 instruction",
    ]
    assert sorted(result.surfaces_excluded) == [
        "prompts/api_key.txt: its name says it holds credentials; not read or inventoried",
        (
            "prompts/notes.txt: a symlink leads to .env, whose name says it holds credentials; "
            "not read or inventoried"
        ),
    ]
    assert set(_components(result)) == {"prompt:prompts/good.md"}


def test_files_under_prompts_that_are_not_text_are_not_read(tmp_path):
    _write(tmp_path, "app/prompts/system.md", "System.")
    _write(tmp_path, "app/prompts/__init__.py", "SYSTEM = 'x'\n")
    (tmp_path / "app/prompts/flow.png").write_bytes(b"\x89PNG\r\n\x1a\n\xff" * 64)
    (tmp_path / "app/prompts/.DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1\xff")
    (tmp_path / "app/prompts/key.pem").write_text("not a key\n")
    with limits.applied(replace(limits.DEFAULTS, file_bytes=128)):
        result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    assert set(_components(result)) == {"prompt:app/prompts/system.md"}
    assert result.surfaces_scanned[-1] == "app/prompts/system.md"
    assert not any("flow.png" in line or "DS_Store" in line for line in result.surfaces_scanned)


@pytest.mark.parametrize(
    ("relative", "link", "target", "expected"),
    [
        ("prompts/style", ".cursor/rules", "../prompts", ("rules-file", ".cursor/rules")),
        (
            "prompts/review.prompt.md",
            ".github/prompts",
            "../prompts",
            ("instruction", ".github/prompts"),
        ),
    ],
)
def test_a_rule_or_prompt_directory_linked_to_prompts_keeps_its_kind(
    tmp_path, relative, link, target, expected
):
    _write(tmp_path, relative, "Be terse.")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / link).symlink_to(target)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    (component,) = result.components
    assert (component.prompt_type, component.properties.get("instruction_directory")) == expected
    assert component.content_hash is not None
    assert not withholds_content_hash(component)
    assert [risk.category for risk in component.risks] == []
    assert result.surfaces_scanned.count(relative) == 1


@pytest.mark.parametrize(
    ("link", "target"),
    [(".claude/commands", "../prompts"), (".claude/skills/shared", "../../prompts")],
)
def test_a_skill_or_command_directory_linked_to_prompts_keeps_its_kind(tmp_path, link, target):
    _write(tmp_path, "prompts/review.md", "Review.")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / link).symlink_to(target)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert [component.bom_ref for component in result.components] == ["skill:prompts/review.md"]
    assert result.surfaces_scanned == ["prompts/review.md"]


def test_an_imported_prompt_file_keeps_the_identity_of_an_import(tmp_path):
    _write(tmp_path, "CLAUDE.md", "Use @prompts/system.md for the tone.")
    _write(tmp_path, "prompts/system.md", "Also read @extra.txt.")
    _write(tmp_path, "prompts/extra.txt", "Extra.")
    _write(tmp_path, "prompts/other.md", "Not imported.")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    components = _components(result)
    assert {ref: component.prompt_type for ref, component in components.items()} == {
        "prompt:CLAUDE.md": "system-prompt",
        "prompt:import:prompts/system.md": "imported-instruction",
        "prompt:import:prompts/extra.txt": "imported-instruction",
        "prompt:prompts/other.md": "template",
    }
    assert components["prompt:CLAUDE.md"].properties["imports"] == ["prompts/system.md"]
    system = components["prompt:import:prompts/system.md"]
    assert system.properties["imported_by"] == ["CLAUDE.md"]
    assert system.properties["imports"] == ["prompts/extra.txt"]
    extra = components["prompt:import:prompts/extra.txt"]
    assert extra.properties["imported_by"] == ["prompts/system.md"]
    assert [path for path in result.surfaces_scanned if path.startswith("prompts/")] == [
        "prompts/system.md",
        "prompts/extra.txt",
        "prompts/other.md",
    ]


def test_two_runs_are_byte_identical_and_portable(tmp_path):
    for root in (tmp_path / "one", tmp_path / "two" / "nested"):
        _write(root, "prompts/b.md", "Second.")
        _write(root, "prompts/a.md", "First.")
        _write(root, "app/prompts/c.prompt.yaml", "model: x\n")
        _write(root, "d.prompt.md", "Root.")
    first = PromptScanner().scan(tmp_path / "one")
    second = PromptScanner().scan(tmp_path / "two" / "nested")
    assert first.components == second.components
    assert first.surfaces_scanned == second.surfaces_scanned
    assert str(tmp_path) not in repr(first)
    outputs = [tmp_path / "first.json", tmp_path / "second.json"]
    for output in outputs:
        run = _scan_cli(tmp_path / "one", output)
        assert run.exit_code == 0, run.output
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    assert b"prompts/a.md" in outputs[0].read_bytes()


ESCAPED_TAGS = "\\udb40\\udc49\\udb40\\udc47"


@pytest.mark.parametrize(
    ("relative", "escaped", "raw"),
    [
        (
            "prompts/a.json",
            '{"system": "Hi ' + ESCAPED_TAGS + '"}',
            '{"system": "Hi ' + TAG * 2 + '"}',
        ),
        ("prompts/a.json", '["\\u202eHi"]', f'["{RLO}Hi"]'),
        ("prompts/a.yaml", 'system: "Hi \\U000E0041\\U000E0041"\n', f"system: Hi {TAG * 2}\n"),
        ("prompts/a.yml", '- "Hi \\udb40\\udc41"\n', f"- Hi {TAG}\n"),
        (
            "app/x.prompt.yml",
            'messages:\n  - content: "\\u202e"\n',
            f"messages:\n  - content: {RLO}\n",
        ),
        ("prompts/a.toml", 'system = "Hi \\U000E0041"\n', f'system = "Hi {TAG}"\n'),
    ],
)
def test_escaped_hidden_characters_are_the_same_finding_as_raw_ones(
    tmp_path, relative, escaped, raw
):
    findings = []
    for name, text in (("escaped", escaped), ("raw", raw)):
        _write(tmp_path / name, relative, text)
        result = PromptScanner().scan(tmp_path / name)
        assert not result.scan_failures
        assert not result.surfaces_excluded
        (component,) = result.components
        findings.append([risk for risk in component.risks if risk.category != "completeness"])
    assert findings[0] == findings[1]
    assert {risk.severity.value for risk in findings[0]} == {"critical"}


def test_a_character_written_raw_in_a_string_counts_once(tmp_path):
    _write(tmp_path, "prompts/a.json", '{"system": "Hi ' + TAG + '", "user": "\\n"}')
    result = PromptScanner().scan(tmp_path)
    (component,) = result.components
    (risk,) = [risk for risk in component.risks if risk.category == "tag_characters"]
    assert "contains 1 deprecated Unicode tag characters" in risk.detail


@pytest.mark.parametrize(
    ("relative", "text"),
    [
        ("prompts/a.json", '{"system": "Caf\\u00e9\\n\\t\\"quoted\\""}'),
        ("prompts/a.yaml", 'system: "Caf\\u00e9\\n"\nother: [1, 2]\n'),
        ("prompts/a.toml", 'system = "Caf\\u00e9\\n"\n'),
        ("prompts/a.md", "Escapes such as \\u202e are text in Markdown.\n"),
        ("prompts/a.json", '{"system": "{{ user | default(\'x\') }}", }'),
    ],
)
def test_escaped_ordinary_text_and_unparsed_files_without_escapes_are_clean(
    tmp_path, relative, text
):
    _write(tmp_path, relative, text)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    (component,) = result.components
    assert [risk.category for risk in component.risks if risk.category != "completeness"] == []


@pytest.mark.parametrize(
    ("relative", "text"),
    [
        ("prompts/a.json", '{"s": "x", "s": "a\\u202eb"}'),
        ("prompts/a.json", '{"id": 123456789012345678901234567890, "s": "a\\u202eb"}'),
        ("prompts/a.json", '{"t": "\\ud800", "s": "a\\u202eb"}'),
        ("prompts/a.json", '{"t": NaN, "s": "a\\u202eb"}'),
        ("prompts/a.json", '// a comment\n{"s": "a\\u202eb", }'),
        ("prompts/a.yaml", 's: "a\\u202eb\nother: ['),
        ("prompts/a.toml", 's = "x"\ns = "a\\u202eb"\n'),
        ("prompts/a.toml", 's = "a\\xadb"\n'),
    ],
)
def test_a_file_a_strict_reader_refuses_still_has_its_escapes_decoded(tmp_path, relative, text):
    _write(tmp_path, relative, text)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    # JSON is always decoded by pattern; YAML or TOML only when it does not parse.
    assert result.surfaces_excluded == _pattern_gap(relative)
    (component,) = result.components
    assert component.prompt_type == "template"
    assert {"bidi_override", "invisible_characters"} & {risk.category for risk in component.risks}


@pytest.mark.parametrize("bound", ["_MAX_YAML_EVENTS", "_MAX_PARSED_CHARACTERS"])
def test_yaml_past_the_parse_bounds_is_decoded_by_pattern(tmp_path, monkeypatch, bound):
    padding = "".join(f"k{i}: 1\n" for i in range(20))
    _write(tmp_path / "escaped", "prompts/a.yaml", padding + 'z: "a\\u202eb"\n')
    # A pattern also decodes an escape in a single-quoted scalar, which YAML keeps as text.
    _write(tmp_path / "literal", "prompts/a.yaml", "z: 'a\\u202eb'\n")
    before = {
        name: PromptScanner().scan(tmp_path / name).components[0] for name in ("escaped", "literal")
    }
    monkeypatch.setattr(prompt_module, bound, 4)
    after = {
        name: PromptScanner().scan(tmp_path / name).components[0] for name in ("escaped", "literal")
    }
    assert "bidi_override" in {risk.category for risk in before["escaped"].risks}
    assert "bidi_override" not in {risk.category for risk in before["literal"].risks}
    for component in after.values():
        assert "bidi_override" in {risk.category for risk in component.risks}


@pytest.mark.parametrize(
    "text",
    [
        '{"id": 12345678901234567890, "s": "line\\nnext"}',
        '// a comment\n{"s": "line\\nnext"}',
        '["\\ud83d\\udc68\\u200d\\ud83d\\udc69"]',
        '["\\\\u202e \\\\d+"]',
        '\ufeff{"s": "line\\nnext"}',
    ],
)
def test_ordinary_json_a_strict_reader_refuses_is_clean(tmp_path, text):
    _write(tmp_path, "prompts/a.json", text)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    (component,) = result.components
    assert [risk.category for risk in component.risks if risk.category != "completeness"] == []


@pytest.mark.parametrize(
    ("relative", "text"),
    [
        ("prompts/a.json", '{"\\udb40\\udc49": 1}'),
        ("prompts/a.toml", '"\\U000E0049" = 1\n'),
        ("prompts/a.json", '\ufeff{"s": "\\udb40\\udc49"}'),
        ("app/x.prompt.md", '---\ndescription: "\\U000E0049"\n---\nBody.\n'),
        ("prompts/a.md", '---\ndescription: "\\U000E0049\n---\nBody.\n'),
    ],
)
def test_escapes_in_keys_after_a_bom_and_in_front_matter_are_decoded(tmp_path, relative, text):
    _write(tmp_path, relative, text)
    result = PromptScanner().scan(tmp_path)
    # The unclosed quote in the last case's front matter does not parse.
    unparsed = relative == "prompts/a.md"
    assert result.surfaces_excluded == (_pattern_gap(relative) if unparsed else [])
    (component,) = result.components
    assert ("tag_characters", "critical") in _findings(component)
    assert "invisible_characters" not in {risk.category for risk in component.risks}


FLOW_TRIP = "# " + "[" * 65 + "\n"
SPLIT_ESCAPES = 'system: "Hi \\udb40\\\n  \\udc49\\udb40\\\n  \\udc47"\n'


@pytest.mark.parametrize(
    ("relative", "text", "parsed"),
    [
        ("prompts/a.yaml", SPLIT_ESCAPES, True),
        ("prompts/a.yaml", FLOW_TRIP + SPLIT_ESCAPES, False),
        ("prompts/a.md", f"---\n{FLOW_TRIP}{SPLIT_ESCAPES}---\nBody.\n", False),
        # The repeated key keeps TOML from parsing.
        ("prompts/a.toml", 's = """Hi \\udb40\\\n   \\udc49"""\ns = 1\n', False),
    ],
)
def test_an_escape_continued_on_the_next_line_is_joined(tmp_path, relative, text, parsed):
    # A line-ending backslash continues the string; a pattern that kept it split the pair.
    _write(tmp_path, relative, text)
    result = PromptScanner().scan(tmp_path)
    (component,) = result.components
    assert ("tag_characters", "critical") in _findings(component)
    assert result.surfaces_excluded == ([] if parsed else _pattern_gap(relative))


@pytest.mark.parametrize(
    "relative", ["CLAUDE.md", ".claude/rules/a.md", ".claude/skills/n/SKILL.md"]
)
@pytest.mark.parametrize("opener", ["---", "---yaml", "--- yaml"])
def test_escapes_in_the_front_matter_of_an_instruction_file_are_decoded(tmp_path, relative, opener):
    findings = []
    for name, description in (("escaped", '"Hi \\U000E0049\\U000E0047"'), ("raw", "Hi " + TAG)):
        _write(tmp_path / name, relative, f"{opener}\nname: n\ndescription: {description}\n---\n")
        result = PromptScanner().scan(tmp_path / name)
        assert not result.surfaces_excluded and not result.scan_failures
        (component,) = [c for c in result.components if c.source_path == relative]
        findings.append(_findings(component))
    assert findings[0] == findings[1]
    assert ("tag_characters", "critical") in findings[0]


def test_escapes_in_a_markdown_body_are_text(tmp_path):
    _write(tmp_path, "app/x.prompt.md", '---\ndescription: "plain"\n---\nWrite "\\u202e".\n')
    result = PromptScanner().scan(tmp_path)
    (component,) = result.components
    assert _findings(component) == []


def test_an_escaped_line_separator_is_the_finding_a_raw_one_is(tmp_path):
    findings = []
    for name, text in (("escaped", '["x\\u2028y"]'), ("raw", '["x\u2028y"]')):
        _write(tmp_path / name, "prompts/a.json", text)
        (component,) = PromptScanner().scan(tmp_path / name).components
        findings.append([risk for risk in component.risks if risk.category != "completeness"])
    assert findings[0] == findings[1]
    assert [(risk.category, risk.severity.value) for risk in findings[0]] == [
        ("line_separators", "low")
    ]


@pytest.mark.parametrize(
    ("link", "target", "alias", "directory"),
    [
        ("app/prompts", "../data", "app/prompts/system.md", "data"),
        ("prompts/shared", "../data", "prompts/shared/system.md", "data"),
        ("agent", "examples/agent", "agent/prompts/system.md", "examples/agent"),
        ("agent", "tests/agent", "agent/prompts/system.md", "tests/agent"),
    ],
)
def test_a_directory_symlink_to_files_no_walk_inventories_is_a_gap(
    tmp_path, link, target, alias, directory
):
    held = alias.removeprefix(link).lstrip("/")
    _write(tmp_path, f"{directory}/{held}", f"Hello.{TAG}")
    _write(tmp_path, "prompts/clean.md", "Clean.")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / link).symlink_to(target)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert result.surfaces_excluded == [
        (
            f"{link}: directory symlink to {directory}; prompt templates under it, such as "
            f"{alias}, are not inventoried, because the walk reads their files only under "
            f"{directory}, where they are not prompt templates"
        )
    ]
    assert set(_components(result)) == {"prompt:prompts/clean.md"}


@pytest.mark.parametrize(
    ("link", "target", "directory", "inventoried"),
    [
        ("app/data", "../data", "data", set()),
        ("docs/prompts", "../data", "data", set()),
        (".github/prompts", "../data", "data", {"prompt:data/system.md"}),
        ("svc/prompts", "../prompts", "prompts", {"prompt:prompts/system.md"}),
        ("app/prompts", "../other/prompts", "other/prompts", {"prompt:other/prompts/system.md"}),
        ("prompts/rules", "../.claude/rules", ".claude/rules", {"prompt:.claude/rules/system.md"}),
    ],
)
def test_other_directory_symlinks_are_not_prompt_gaps(
    tmp_path, link, target, directory, inventoried
):
    _write(tmp_path, f"{directory}/system.md", "Hello.")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / link).symlink_to(target)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not any("prompt templates" in gap for gap in result.surfaces_excluded)
    assert set(_components(result)) == inventoried


@pytest.mark.parametrize("relative", ["prompts/a.md", ".claude/rules/a.md", "x.prompt.md"])
def test_invalid_utf8_under_prompts_is_the_failure_it_is_in_a_rule_directory(tmp_path, relative):
    (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / relative).write_bytes(b"Hello \xff\xfe")
    _write(tmp_path / "twin", relative, "Hello \u00e9")
    result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == [f"{relative}: invalid UTF-8 instruction"]
    assert not result.surfaces_excluded
    twin = PromptScanner().scan(tmp_path / "twin")
    assert not twin.scan_failures
    assert [component.source_path for component in twin.components] == [relative]


@pytest.mark.parametrize(
    ("relative", "named"),
    [
        ("pkg/prompts/claude.md", "pkg/prompts/CLAUDE.md"),
        ("prompts/Agents.md", "prompts/AGENTS.md"),
    ],
)
def test_a_case_variant_of_an_instruction_name_under_prompts_stays_a_failure(
    tmp_path, relative, named
):
    _write(tmp_path, relative, "Hello.")
    _write(tmp_path, "pkg/prompts/system.md", "Hello.")
    result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == [
        (
            f"{relative}: case variant of {named} is the active file on case-insensitive file "
            "systems and is not inventoried"
        )
    ]
    assert set(_components(result)) == {"prompt:pkg/prompts/system.md"}


def test_a_character_written_raw_in_a_string_counts_once_for_each_kind(tmp_path):
    _write(tmp_path, "prompts/a.json", '{"a": "' + "\u200b" * 3 + '\\n"}')
    (component,) = PromptScanner().scan(tmp_path).components
    (risk,) = [risk for risk in component.risks if risk.category == "invisible_characters"]
    assert "ZERO WIDTH SPACE (U+200B) x3" in risk.detail


def test_an_import_through_a_directory_symlink_is_one_component(tmp_path):
    _write(tmp_path, "CLAUDE.md", "Use @alias/a.md.")
    _write(tmp_path, "prompts/a.md", "Hello.")
    (tmp_path / "alias").symlink_to("prompts")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert set(_components(result)) == {"prompt:CLAUDE.md", "prompt:import:alias/a.md"}


def test_an_import_that_is_not_utf8_is_one_failure(tmp_path):
    _write(tmp_path, "CLAUDE.md", "Use @prompts/a.md.")
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts/a.md").write_bytes(b"Hello \xff\xfe")
    result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == ["prompts/a.md: invalid UTF-8 instruction"]


@pytest.mark.parametrize(
    ("memory", "links"),
    [("@app/prompts/x.json", []), ("@alias/x.json", [("alias", "app/prompts")])],
)
def test_an_imported_prompt_template_keeps_its_escape_check(tmp_path, memory, links):
    _write(tmp_path, "CLAUDE.md", memory)
    _write(tmp_path, "app/prompts/x.json", '{"a": "\\udb40\\udc49"}')
    for link, target in links:
        (tmp_path / link).symlink_to(target)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    (imported,) = [c for c in result.components if c.prompt_type == "imported-instruction"]
    assert ("tag_characters", "critical") in _findings(imported)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("a.yaml", lambda size: "[" * size + "\\"),
        ("a.yml", lambda size: "{" * size + "\\"),
        ("a.md", lambda size: "---\nk: " + "[" * size + "\\\n---\nBody.\n"),
        ("b.yaml", lambda size: ("[" * 63 + '"' + "]" * 63 + '",') * (size // 130) + "\\"),
        (
            "b.md",
            lambda size: (
                "---\nk: " + ("[" * 63 + '"' + "]" * 63 + '",') * (size // 130) + "\\\n---\nBody.\n"
            ),
        ),
    ],
)
def test_deeply_nested_yaml_is_decoded_by_pattern_in_linear_time(tmp_path, name, text):
    roots = {}
    for scale in (1, 4):
        root = tmp_path / str(scale)
        for index in range(10):
            _write(root, f"prompts/{index}{name}", text(5_000 * scale))
        roots[scale] = root

    def run(scale: int) -> None:
        result = PromptScanner().scan(roots[scale])
        assert len(result.components) == 10
        assert not result.scan_failures

    assert scaling_ratio(run) < 8


@pytest.mark.parametrize("depth", [64, 1_000, 2_000])
def test_closed_nested_yaml_keeps_its_escape_check(tmp_path, depth):
    _write(tmp_path, "prompts/a.yaml", "k: " + "[" * depth + '"\\U000E0049"' + "]" * depth + "\n")
    (component,) = PromptScanner().scan(tmp_path).components
    assert ("tag_characters", "critical") in _findings(component)


def test_a_library_of_unbound_templates_is_one_finding(tmp_path):
    for index in range(15):
        _write(
            tmp_path, f"prompts/tpl_{index:02d}.j2", f"Summarize {{{{ text }}}} in style {index}."
        )
    _write(tmp_path, "prompts/readme.md", "Templates.")
    result = PromptScanner().scan(tmp_path)
    risks = [risk for component in result.components for risk in component.risks]
    (risk,) = risks
    assert (risk.category, risk.severity.value) == ("completeness", "low")
    assert risk.detail.startswith("15 prompt templates have values not bound in this inventory")
    assert "'prompts/tpl_11.j2' and 3 more." in risk.detail
    assert "tpl_12" not in risk.detail
    assert _components(result)["prompt:prompts/tpl_00.j2"].risks == [risk]
    assert [c.source_path for c in result.components if not withholds_content_hash(c)] == [
        "prompts/readme.md"
    ]


def test_a_changed_template_without_its_own_finding_is_unbound_in_diff(tmp_path):
    from nexus_symbiote.diff import differ

    _write(tmp_path, "prompts/a.j2", "A {{ x }}")
    _write(tmp_path, "prompts/b.j2", "B {{ x }}")
    component = _components(PromptScanner().scan(tmp_path))["prompt:prompts/b.j2"]
    assert not component.risks
    assert differ._values_unbound(component)


def test_cli_passes_a_project_with_fifty_templates(tmp_path):
    project = tmp_path / "project"
    _write(project, "CLAUDE.md", "Follow the house style.")
    for index in range(1, 51):
        _write(
            project, f"prompts/tpl_{index:02d}.j2", f"Summarize {{{{ text }}}} in style {index}."
        )
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert run.exit_code == 0, run.output
    assert "Scan gate passed" in run.output
    bom = json.loads(output.read_text())
    risks = [risk for component in bom["components"] for risk in component.get("risks", [])]
    assert [(risk["category"], risk["severity"]) for risk in risks] == [("completeness", "low")]
    assert "50 prompt templates" in risks[0]["detail"]
    assert "and 38 more." in risks[0]["detail"]


@pytest.mark.parametrize(
    ("relative", "content", "reason"),
    [
        (
            "support/prompts/credentials_help.txt",
            b"Help.",
            (
                "excluded: support/prompts/credentials_help.txt: its name says it holds "
                "credentials; not read or inventoried"
            ),
        ),
        (
            "prompts/a.txt",
            "Hello prompt".encode("utf-16"),
            "collection: prompts/a.txt: invalid UTF-8 instruction",
        ),
    ],
)
def test_cli_fails_a_project_whose_prompts_cannot_be_read(tmp_path, relative, content, reason):
    project = tmp_path / "project"
    _write(project, "CLAUDE.md", "Follow the house style.")
    (project / relative).parent.mkdir(parents=True)
    (project / relative).write_bytes(content)
    run = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert run.exit_code == 1, run.output
    assert "collection coverage is unknown or incomplete" in run.output
    assert reason in run.output


def test_templates_are_read_after_skills_keep_their_budget(tmp_path):
    _write(tmp_path, ".claude/skills/pdf/SKILL.md", "---\nname: pdf\n---\nUse it.\n")
    _write(tmp_path, "prompts/a.txt", "x" * 40_000)
    _write(tmp_path, "prompts/b.txt", "x" * 25_520)
    with limits.applied(limits.resolve(["file-bytes=64KiB", "total-bytes=64KiB"], {})):
        result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == [
        "prompts/b.txt: total-bytes limit of 64 KiB exceeded; raise it with --limit total-bytes=N"
    ]
    assert set(_components(result)) == {
        "skill:.claude/skills/pdf/SKILL.md",
        "prompt:prompts/a.txt",
    }


def test_an_imported_credential_name_under_prompts_is_excluded_once(tmp_path):
    _write(tmp_path, "CLAUDE.md", "See @prompts/api_key.txt.")
    _write(tmp_path, "prompts/api_key.txt", "synthetic-placeholder\n")
    result = PromptScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        (
            "prompts/api_key.txt: imported by CLAUDE.md but its name says it holds credentials; "
            "not read or inventoried"
        )
    ]


def _quoted_closers(depth: int) -> str:
    """YAML nested ``depth`` flow collections deep whose brackets, counting the closing
    ones in a quoted string, nest only 40 deep."""
    return (
        "k: "
        + "[" * 40
        + '"'
        + "]" * 40
        + '", '
        + "[" * (depth - 40)
        + "'C:\\Logs'"
        + "]" * depth
        + "\n"
    )


@pytest.mark.parametrize(
    ("relative", "text", "decoded_by_pattern"),
    [
        ("prompts/a.yaml", "k: " + "[" * 64 + "'C:\\Logs'" + "]" * 64 + "\n", False),
        ("prompts/a.yaml", "k: " + "[" * 65 + "'C:\\Logs'" + "]" * 65 + "\n", True),
        ("prompts/a.yaml", "k: " + "{a: " * 65 + "'C:\\Logs'" + "}" * 65 + "\n", True),
        ("prompts/a.yaml", _quoted_closers(64), False),
        ("prompts/a.yaml", _quoted_closers(65), True),
        ("prompts/a.toml", "k = " + "[" * 100 + "'C:\\Logs'" + "]" * 100 + "\n", False),
    ],
)
def test_yaml_nested_past_the_flow_bound_is_decoded_by_pattern(
    tmp_path, relative, text, decoded_by_pattern
):
    _write(tmp_path, relative, text)
    (component,) = PromptScanner().scan(tmp_path).components
    assert (("line_separators", "low") in _findings(component)) is decoded_by_pattern


@pytest.mark.parametrize(
    "text",
    [
        "# " + "]" * 100 + "\nk: " + "[" * 100 + "\\",
        "k: " + "[" * 100 + '"\\\\"' + "\n# " + "]" * 99 + "[\n",
        "{" * 100 + "\\",
    ],
)
def test_flow_depth_is_the_deepest_nesting(text):
    assert prompt_module._flow_depth(text) == 100


def test_templates_bound_by_the_operator_key_carry_no_finding(tmp_path, monkeypatch):
    from nexus_symbiote.scanners.source_binding import SOURCE_BINDING_KEY_ENV

    _write(tmp_path, "prompts/a.j2", "A {{ x }}")
    _write(tmp_path, "prompts/b.j2", "B {{ x }}")
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "prompt-template-key-" + "0123456789abcdef" * 2)
    components = PromptScanner().scan(tmp_path).components
    assert len(components) == 2
    assert all("static_value_binding" in c.properties for c in components)
    assert all(withholds_content_hash(c) and not c.risks for c in components)
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV)
    unkeyed = PromptScanner().scan(tmp_path).components
    assert [len(c.risks) for c in unkeyed] == [1, 0]


def test_templates_recorded_before_the_bound_keep_their_finding(tmp_path):
    for index in range(3):
        _write(tmp_path, f"prompts/t{index}.j2", f"T{index} {{{{ x }}}}")
    with limits.applied(replace(limits.DEFAULTS, prompt_files=2)):
        result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == [
        (
            "prompts/t2.j2: prompt files from this one on are not inventoried; prompt-files "
            "limit of 2 exceeded; raise it with --limit prompt-files=N"
        )
    ]
    (risk,) = [risk for component in result.components for risk in component.risks]
    assert risk.detail.startswith("2 prompt templates have values not bound")
    assert risk.detail.endswith(": 'prompts/t0.j2', 'prompts/t1.j2'.")


@pytest.mark.parametrize(
    ("count", "start", "end"),
    [
        (1, "1 prompt template has values not bound", ": 'prompts/t00.j2'."),
        (12, "12 prompt templates have values not bound", ", 'prompts/t11.j2'."),
    ],
)
def test_the_shared_finding_names_every_template_up_to_twelve(tmp_path, count, start, end):
    for index in range(count):
        _write(tmp_path, f"prompts/t{index:02d}.j2", f"T{index} {{{{ x }}}}")
    (risk,) = [r for c in PromptScanner().scan(tmp_path).components for r in c.risks]
    assert risk.detail.startswith(start)
    assert risk.detail.endswith(end)


@pytest.mark.parametrize(
    ("link", "target", "link_text"),
    [
        ("prompts/notes.txt", ".env", "../.env"),
        ("prompts/notes.md", "prompts/credentials.txt", "credentials.txt"),
    ],
)
def test_an_import_through_a_symlink_to_a_credential_file_is_excluded_once(
    tmp_path, link, target, link_text
):
    _write(tmp_path, "CLAUDE.md", f"See @{link}.")
    _write(tmp_path, target, "A=1\n")
    (tmp_path / "prompts").mkdir(exist_ok=True)
    (tmp_path / link).symlink_to(link_text)
    result = PromptScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        (
            f"{link}: imported by CLAUDE.md but a symlink leads to {target}, whose name says "
            "it holds "
            "credentials; not read or inventoried"
        )
    ]
