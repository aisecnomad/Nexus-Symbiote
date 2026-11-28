"""Mixed-script words and hidden characters in collected source, without the text."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import IMPORTED_MODE
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import MCPServerComponent, RiskAssessment
from nexus_symbiote.source_unicode import MAX_FINDINGS, apply_source_unicode_findings

_HOMOGLYPH = "def s\u0435nd_email():\n    return None\n"
_BIDI = 'name = "fetch\u202e_url"\n'
_ZERO_WIDTH = 'note = "Fetch\u200b a URL"\n'
_EMOJI = "label = 'ship \U0001f468\u200d\U0001f4bb'\n"


def _server(path: str) -> MCPServerComponent:
    return MCPServerComponent(bom_ref="mcp:one", name="srv", source_path=path)


def _categories(server: MCPServerComponent) -> set[str]:
    return {risk.category for risk in server.risks}


def test_a_homoglyph_a_bidi_override_and_a_zero_width_are_flagged(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(_HOMOGLYPH + _BIDI + _ZERO_WIDTH, encoding="utf-8")
    server = _server("agent.py")
    added = apply_source_unicode_findings(AIBOM(components=[server]), tmp_path)
    assert added == 3
    assert _categories(server) == {"identifier_characters", "bidi_override", "invisible_characters"}
    rendered = " ".join(risk.detail for risk in server.risks)
    assert "\u0435" not in rendered
    assert "\u202e" not in rendered
    assert "\u200b" not in rendered
    assert "agent.py:1 mixes the Cyrillic, Latin scripts" in rendered
    assert "U+202E" in rendered
    assert "U+200B" in rendered
    assert "sha256:" not in rendered


def test_an_emoji_joiner_and_ascii_raise_nothing(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def send_email():\n    return None\n" + _EMOJI, encoding="utf-8"
    )
    server = _server("app.py")
    assert apply_source_unicode_findings(AIBOM(components=[server]), tmp_path) == 0
    assert server.risks == []


def test_a_name_already_neutralized_is_not_reported_again(tmp_path: Path) -> None:
    line = "s\u0435nd_email"
    (tmp_path / "app.py").write_text(line + "\n", encoding="utf-8")
    server = MCPServerComponent(
        bom_ref="mcp:one",
        name=line,
        source_path="app.py",
        risks=[
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="identifier_characters",
                detail="already recorded",
            )
        ],
    )
    assert apply_source_unicode_findings(AIBOM(components=[server]), tmp_path) == 0
    assert len(server.risks) == 1


def test_too_many_disguised_lines_fail_closed(tmp_path: Path) -> None:
    text = "".join(f"name_{i} = 'fetch\u202e_{i}'\n" for i in range(MAX_FINDINGS + 1))
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    server = _server("app.py")
    failures: list[str] = []
    added = apply_source_unicode_findings(AIBOM(components=[server]), tmp_path, failures=failures)
    assert added == 0
    assert server.risks == []
    assert failures == [f"app.py: more than {MAX_FINDINGS} source Unicode findings; not collected"]
    assert "\u202e" not in " ".join(failures)


def test_an_instruction_file_is_not_read_here(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text(_BIDI, encoding="utf-8")
    prompt_like = _server("CLAUDE.md")
    assert apply_source_unicode_findings(AIBOM(components=[prompt_like]), tmp_path) == 0


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("agent.py", '# Measure Δt in μs.\n"""Scientific notes: σ_max and μs."""\nΔt = 5\n'),
        ("agent.ts", "// Measure Δt in μs.\nconst unit = `μs`;\nconst Δt = 5;\n"),
        ("agent.jsx", "/* Δt in μs */\nconst label = <div>μs</div>;\nconst Δt = 5;\n"),
    ],
)
def test_only_identifier_tokens_contribute_mixed_scripts(
    tmp_path: Path, filename: str, source: str
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")
    server = _server(filename)
    assert apply_source_unicode_findings(AIBOM(components=[server]), tmp_path) == 1
    assert server.risks[0].detail == f"{filename}:3 mixes the Greek, Latin scripts."


def test_source_parser_refusal_stays_visible_without_disclosing_source(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('"""unfinished Δt', encoding="utf-8")
    failures: list[str] = []
    apply_source_unicode_findings(
        AIBOM(components=[_server("app.py")]), tmp_path, failures=failures
    )
    assert failures == ["app.py: source identifiers could not be read"]


def test_both_project_gates_corroborate_an_observed_identifier(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "server.py").write_text(
        'from mcp.server.fastmcp import FastMCP\nserver = FastMCP("science")\nΔt = 1\n',
        encoding="utf-8",
    )
    target = tmp_path / "bom.json"
    runner = CliRunner()
    scan = runner.invoke(
        main, ["scan", "--report-only", "--no-project-policy", str(project), "-o", str(target)]
    )
    assert scan.exit_code == 0, scan.output
    assert any(
        risk.detail == "server.py:3 mixes the Greek, Latin scripts."
        for component in AIBOM.load(target).components
        for risk in component.risks
    )
    common = [str(target), "--project", str(project), "--no-project-policy", "--json-output"]
    for command in ("validate", "risk"):
        result = runner.invoke(main, [command, *common])
        assert json.loads(result.stdout)["assessment_basis"] == "project-reconciled", result.output

    # A new scientific variable on a different line makes the saved observation stale.
    with (project / "server.py").open("a", encoding="utf-8") as source:
        source.write("Δt_other = 2\n")
    for command in ("validate", "risk"):
        result = runner.invoke(main, [command, *common])
        report = json.loads(result.stdout)
        assert result.exit_code == 1, result.output
        assert report["assessment_basis"] == "project-reconciliation-failed", result.output


def test_an_imported_source_citation_does_not_select_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("Δt = 1", encoding="utf-8")
    server = _server("app.py")
    server.properties["collection_mode"] = IMPORTED_MODE
    assert apply_source_unicode_findings(AIBOM(components=[server]), tmp_path) == 0


def test_identifier_analysis_uses_the_operator_syntax_budget(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("Δt = 1", encoding="utf-8")
    failures: list[str] = []
    with limits.applied(limits.resolve(["syntax-bytes=4"], {})):
        assert (
            apply_source_unicode_findings(
                AIBOM(components=[_server("app.py")]), tmp_path, failures=failures
            )
            == 0
        )
    assert len(failures) == 1 and "syntax-bytes" in failures[0]


def test_ordinary_source_alias_is_collected(tmp_path: Path) -> None:
    (tmp_path / "impl.py").write_text("Δt = 1", encoding="utf-8")
    (tmp_path / "app.py").symlink_to("impl.py")
    server = _server("app.py")
    assert apply_source_unicode_findings(AIBOM(components=[server]), tmp_path) == 1
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
        apply_source_unicode_findings(AIBOM(components=[server]), tmp_path, exclusions=exclusions)
        == 0
    )
    assert len(exclusions) == 1 and "not read" in exclusions[0]
    assert not server.risks


def test_ascii_js_escape_is_interpreted_only_in_identifier_nodes(tmp_path: Path) -> None:
    (tmp_path / "agent.js").write_text(r'const comment = "x\u0435";' + "\n" + r"let x\u0435 = 1;")
    server = _server("agent.js")
    assert apply_source_unicode_findings(AIBOM(components=[server]), tmp_path) == 1
    assert server.risks[0].detail == "agent.js:2 mixes the Cyrillic, Latin scripts."


def test_repeated_rtl_marks_keep_their_count_and_other_findings(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(("# مرحبا\u200f\n" * 40) + _BIDI)
    server = _server("agent.py")
    failures: list[str] = []
    assert (
        apply_source_unicode_findings(AIBOM(components=[server]), tmp_path, failures=failures) == 2
    )
    assert failures == []
    assert _categories(server) == {"directional_marks", "bidi_override"}
    assert any(
        "U+200F) x40" in risk.detail and "agent.py:1" in risk.detail for risk in server.risks
    )
