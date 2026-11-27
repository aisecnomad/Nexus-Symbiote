"""Vendor-shaped literals in collected source are findings, and the value is not."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import IMPORTED_MODE
from nexus_symbiote.core.models import MCPServerComponent, PromptComponent
from nexus_symbiote.literal_credentials import MAX_LITERALS, apply_literal_credential_findings
from nexus_symbiote.scanners.mcp_credentials import normalize_credential

_TOKEN = "sk-proj-" + "a1b2c3d4e5f6g7h8i9j0"
_EXAMPLE = "sk-proj-" + ("example" * 4)


def _server(path: str, ref: str = "mcp:one") -> MCPServerComponent:
    return MCPServerComponent(bom_ref=ref, name="srv", source_path=path)


def test_a_vendor_shape_in_source_is_a_fingerprint_finding(tmp_path: Path) -> None:
    (tmp_path / "agent").mkdir()
    (tmp_path / "agent" / "app.py").write_text(
        f'client = OpenAI(api_key="{_TOKEN}")\n', encoding="utf-8"
    )
    server = _server("agent/app.py")
    added = apply_literal_credential_findings(AIBOM(components=[server]), tmp_path)
    assert added == 1
    [risk] = server.risks
    assert risk.category == "credential_exposure"
    assert risk.severity.value == "high"
    assert risk.detail.startswith(
        "agent/app.py:1: a vendor token shape is committed (value unbound)."
    )
    assert _TOKEN not in risk.detail
    assert _TOKEN not in (risk.recommendation or "")


def test_a_placeholder_shape_and_a_config_file_raise_nothing(tmp_path: Path) -> None:
    (tmp_path / "docs.md").write_text(f"example key {_EXAMPLE}\n", encoding="utf-8")
    (tmp_path / "mcp.json").write_text('{"env": {"TOKEN": "' + _TOKEN + '"}}\n', encoding="utf-8")
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={_TOKEN}\n", encoding="utf-8")
    docs = PromptComponent(bom_ref="prompt:docs", name="docs", source_path="docs.md")
    config = _server("mcp.json", "mcp:cfg")
    env = _server(".env", "mcp:env")
    added = apply_literal_credential_findings(AIBOM(components=[docs, config, env]), tmp_path)
    assert added == 0
    assert docs.risks == []
    assert config.risks == []
    assert env.risks == []


def test_a_dockerfile_env_literal_is_reported_once_for_two_owners(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(f"ENV HF_TOKEN={_TOKEN}\n", encoding="utf-8")
    first = _server("Dockerfile", "reg:b")
    second = _server("Dockerfile", "reg:a")
    added = apply_literal_credential_findings(AIBOM(components=[first, second]), tmp_path)
    assert added == 1
    assert first.risks == []
    assert len(second.risks) == 1
    assert _TOKEN not in second.risks[0].detail


def test_too_many_shapes_fail_closed_and_add_no_finding(tmp_path: Path) -> None:
    lines = "\n".join(f'TOKEN_{i} = "{_TOKEN[:-2]}{i:02d}"' for i in range(MAX_LITERALS + 1))
    (tmp_path / "app.py").write_text(lines + "\n", encoding="utf-8")
    server = _server("app.py")
    failures: list[str] = []
    added = apply_literal_credential_findings(
        AIBOM(components=[server]), tmp_path, failures=failures
    )
    assert added == 0
    assert server.risks == []
    assert failures == [
        f"app.py: more than {MAX_LITERALS} vendor token shapes in one file; not collected"
    ]
    assert _TOKEN[:12] not in " ".join(failures)


def test_a_non_utf8_file_is_a_failure_and_not_a_guess(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_bytes(b"\xff" + _TOKEN.encode())
    server = _server("app.py")
    failures: list[str] = []
    added = apply_literal_credential_findings(
        AIBOM(components=[server]), tmp_path, failures=failures
    )
    assert added == 0
    assert server.risks == []
    assert failures == ["app.py: literal credentials were not read (not UTF-8)"]


def test_one_window_stops_matching_at_the_findings_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nexus_symbiote import literal_credentials

    monkeypatch.setattr(literal_credentials, "MAX_LITERALS", 1)
    normalizations = 0

    def counted(value: str) -> str:
        nonlocal normalizations
        normalizations += 1
        return normalize_credential(value)

    monkeypatch.setattr(literal_credentials, "normalize_credential", counted)
    tokens = [_TOKEN, _TOKEN, _TOKEN + "1", _TOKEN + "2"]
    (tmp_path / "app.py").write_text(" ".join(tokens), encoding="utf-8")
    server = _server("app.py")
    failures: list[str] = []
    assert (
        apply_literal_credential_findings(AIBOM(components=[server]), tmp_path, failures=failures)
        == 0
    )
    assert len(failures) == 1 and server.risks == []
    # Two occurrences of the first spelling consume one slot. The third
    # occurrence exceeds the budget, so the fourth is never normalized.
    assert normalizations == 3


@pytest.mark.parametrize("mark", ["\u200b", "\ufe0e", "\u00a0"])
def test_a_mark_or_space_inside_a_token_is_still_a_finding(tmp_path: Path, mark: str) -> None:
    marked = "sk-proj-a1b2" + mark + "c3d4e5f6g7h8i9j0"
    (tmp_path / "app.py").write_text(f'key = "{marked}"\n', encoding="utf-8")
    server = _server("app.py")
    assert apply_literal_credential_findings(AIBOM(components=[server]), tmp_path) == 1
    detail = server.risks[0].detail
    assert marked not in detail
    assert mark not in detail
    assert "app.py:1:" in detail


@pytest.mark.parametrize(
    "text",
    [
        'key = "sk-proj-a1b2c3d4" \\\n"e5f6g7h8i9j0"\n',
        'key = "sk-proj-" +\n"a1b2c3d4e5f6g7h8i9j0"\n',
        'key = "sk-proj-a1b2c3d4\ne5f6g7h8i9j0"\n',
    ],
)
def test_a_token_split_across_lines_is_one_finding(tmp_path: Path, text: str) -> None:
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    server = _server("app.py")
    assert apply_literal_credential_findings(AIBOM(components=[server]), tmp_path) == 1
    detail = server.risks[0].detail
    assert "sk-proj-" not in detail
    assert "app.py:1:" in detail


def test_a_token_cut_off_by_the_join_cap_fails_closed(tmp_path: Path) -> None:
    from nexus_symbiote.literal_credentials import _JOIN_LINES

    lines = ['key = "'] + ["pad"] * (_JOIN_LINES - 2) + ["sk-proj-"]
    lines.append('a1b2c3d4e5f6g7h8i9j0"')
    (tmp_path / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    server = _server("app.py")
    failures: list[str] = []
    added = apply_literal_credential_findings(
        AIBOM(components=[server]), tmp_path, failures=failures
    )
    assert added == 0
    assert server.risks == []
    assert any("not collected" in failure for failure in failures)
    assert "sk-proj-" not in " ".join(failures)


def test_scan_reports_a_skill_literal_without_copying_it(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "project"
    skill = project / ".claude" / "skills" / "ship"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(f"# ship\n\nexport KEY={_TOKEN}\n", encoding="utf-8")
    out = tmp_path / "out.json"
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert _TOKEN not in text
    assert _TOKEN not in result.output
    assert "credential_exposure" in text
    assert "SKILL.md:3:" in text
    assert "value unbound" in text


def test_a_token_in_prose_is_a_finding(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        f'export KEY="{_TOKEN}"\nOr paste the deploy token {_TOKEN} when asked.\n',
        encoding="utf-8",
    )
    skill = PromptComponent(bom_ref="skill:ship", name="ship", source_path="SKILL.md")
    added = apply_literal_credential_findings(AIBOM(components=[skill]), tmp_path)
    assert added == 2
    rendered = " ".join(risk.detail for risk in skill.risks)
    assert "SKILL.md:1:" in rendered
    assert "SKILL.md:2:" in rendered
    assert _TOKEN not in rendered
    assert "sha256:" not in rendered


def test_a_single_quoted_break_is_not_joined(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("key = 'sk-proj-a1b2c3d4'\n'e5f6g7h8i9j0'\n", encoding="utf-8")
    server = _server("app.py")
    assert apply_literal_credential_findings(AIBOM(components=[server]), tmp_path) == 0


def test_a_keyed_binding_is_not_an_unkeyed_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "k" * 32)
    (tmp_path / "app.py").write_text(f'key = "{_TOKEN}"\n', encoding="utf-8")
    server = _server("app.py")
    assert apply_literal_credential_findings(AIBOM(components=[server]), tmp_path) == 1
    detail = server.risks[0].detail
    assert "hmac-sha256:" in detail
    assert "key_id=" in detail
    assert _TOKEN not in detail
    assert hashlib.sha256(normalize_credential(_TOKEN).encode("utf-8")).hexdigest() not in detail


def test_deleting_the_finding_fails_project_reconciliation(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "project"
    skill = project / ".claude" / "skills" / "ship"
    skill.mkdir(parents=True)
    (project / "CLAUDE.md").write_text("Be helpful.\n", encoding="utf-8")
    (skill / "SKILL.md").write_text(f"# ship\n\nexport KEY={_TOKEN}\n", encoding="utf-8")
    out = tmp_path / "out.json"
    runner = CliRunner()
    scanned = runner.invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(out)]
    )
    assert scanned.exit_code == 0, scanned.output
    assert _TOKEN not in out.read_text(encoding="utf-8")
    kept = runner.invoke(
        main, ["validate", "--no-project-policy", str(out), "--project", str(project)]
    )
    assert kept.exit_code == 0, kept.output
    bom = AIBOM.load(out)
    for component in bom.components:
        component.risks = [
            risk for risk in component.risks if risk.category != "credential_exposure"
        ]
    bom.save(out)
    removed = runner.invoke(
        main, ["validate", "--no-project-policy", str(out), "--project", str(project)]
    )
    assert removed.exit_code != 0, removed.output
    assert "mismatched" in removed.output.lower()
    gated = runner.invoke(
        main, ["risk", "--no-project-policy", str(out), "--project", str(project)]
    )
    assert gated.exit_code != 0, gated.output


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_repeated_shapes_in_one_window_keep_their_physical_lines(
    tmp_path: Path, newline: str
) -> None:
    # NFKC expands the ligature and removes the format mark from the view
    # before the vendor prefixes. U+2028 does not advance a physical source line.
    parts = ['notes = "ﬀ\u200b\u2028start', f"first {_TOKEN}", f'second {_TOKEN}"']
    (tmp_path / "app.py").write_bytes(newline.join(parts).encode())
    server = _server("app.py")
    assert apply_literal_credential_findings(AIBOM(components=[server]), tmp_path) == 2
    assert [risk.detail.split(": ", 1)[0] for risk in server.risks] == ["app.py:2", "app.py:3"]


@pytest.mark.parametrize("join", [" +\n", " \\\n"])
def test_match_start_survives_joins_and_internal_whitespace(tmp_path: Path, join: str) -> None:
    text = f'header = "ﬀ\u200b" {join}" note: sk-proj-a1b2 c3d4e5f6g7h8i9j0"\n'
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    server = _server("app.py")
    assert apply_literal_credential_findings(AIBOM(components=[server]), tmp_path) == 1
    assert server.risks[0].detail.startswith("app.py:2:")


def test_scan_and_sarif_locate_a_match_on_the_continuation_line(tmp_path: Path) -> None:
    import json

    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "project"
    skill = project / ".claude" / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(f'# Notes\n\ntext = "start\nexample: {_TOKEN}"\n')
    runner = CliRunner()
    for fmt in ("native", "sarif"):
        output = tmp_path / f"result-{fmt}.json"
        args = ["scan", str(project), "--report-only", "--no-project-policy", "-o", str(output)]
        if fmt == "sarif":
            args += ["-f", "sarif"]
        result = runner.invoke(main, args)
        assert result.exit_code == 0, result.output
        document = output.read_text(encoding="utf-8")
        assert _TOKEN not in document
        if fmt == "native":
            messages = [
                risk.detail
                for component in AIBOM.load(output).components
                for risk in component.risks
                if risk.category == "credential_exposure"
            ]
        else:
            messages = [
                item["message"]["text"]
                for item in json.loads(document)["runs"][0]["results"]
                if item["ruleId"] == "nexus_symbiote/credential_exposure/high"
            ]
        assert len(messages) == 1
        assert messages[0].startswith(".claude/skills/demo/SKILL.md:4:")


def test_an_imported_citation_is_not_a_local_source(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(f"demo = '{_TOKEN}'", encoding="utf-8")
    server = _server("app.py")
    server.properties["collection_mode"] = IMPORTED_MODE
    assert apply_literal_credential_findings(AIBOM(components=[server]), tmp_path) == 0


def test_ordinary_source_alias_is_collected(tmp_path: Path) -> None:
    (tmp_path / "impl.py").write_text(f"demo = '{_TOKEN}'", encoding="utf-8")
    (tmp_path / "app.py").symlink_to("impl.py")
    server = _server("app.py")
    assert apply_literal_credential_findings(AIBOM(components=[server]), tmp_path) == 1
    assert server.risks[0].detail.startswith("app.py:1")


def test_credential_store_target_is_an_explicit_coverage_exclusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "sample.txt").write_text("ordinary fixture text", encoding="utf-8")
    (tmp_path / "app.py").symlink_to("secrets/sample.txt")
    observed = (tmp_path / "secrets" / "sample.txt").stat()
    read = os.read

    def check_before_read(fd: int, length: int) -> bytes:
        opened = os.fstat(fd)
        assert (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        return read(fd, length)

    monkeypatch.setattr(os, "read", check_before_read)
    exclusions: list[str] = []
    server = _server("app.py")
    assert (
        apply_literal_credential_findings(
            AIBOM(components=[server]), tmp_path, exclusions=exclusions
        )
        == 0
    )
    assert len(exclusions) == 1 and "not read" in exclusions[0]
    assert not server.risks


def test_prefix_documentation_does_not_join_words_into_a_token(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "The ghp_ prefix identifies personal access tokens used by developers.\n"
        "The sk-proj- prefix identifies project keys in this documentation.\n"
        "The sk-ant-api03- prefix identifies Anthropic credentials in this documentation.\n"
    )
    skill = PromptComponent(bom_ref="skill:guide", name="guide", source_path="SKILL.md")
    assert apply_literal_credential_findings(AIBOM(components=[skill]), tmp_path) == 0


def test_only_the_final_word_can_cross_the_continuation_boundary() -> None:
    from nexus_symbiote.literal_credentials import _cut_off_token

    assert not _cut_off_token("Prefix glossary: ghp_ and sk-proj- are examples.")
    assert _cut_off_token("Prefix glossary: ghp_ and sk-proj-")


def test_a_long_next_line_is_inspected_as_a_separate_window() -> None:
    from nexus_symbiote.literal_credentials import _JOIN_CHARS, _literal_windows

    long_line = "a" * _JOIN_CHARS
    windows = list(_literal_windows('description = "first\n' + long_line))
    assert [window[0] for window in windows] == [1, 2]
    assert windows[0][3]
    assert windows[1][1] == long_line
