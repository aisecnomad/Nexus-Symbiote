"""Mixed-script words and hidden characters in collected source, without the text."""

from __future__ import annotations

from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM
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
    (tmp_path / "agent.ts").write_text(_HOMOGLYPH + _BIDI + _ZERO_WIDTH, encoding="utf-8")
    server = _server("agent.ts")
    added = apply_source_unicode_findings(AIBOM(components=[server]), tmp_path)
    assert added == 3
    assert _categories(server) == {"identifier_characters", "bidi_override", "invisible_characters"}
    rendered = " ".join(risk.detail for risk in server.risks)
    assert "\u0435" not in rendered
    assert "\u202e" not in rendered
    assert "\u200b" not in rendered
    assert "agent.ts:1 mixes the Cyrillic, Latin scripts" in rendered
    assert "U+202E" in rendered
    assert "U+200B" in rendered
    assert "sha256:" in rendered


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
    assert failures == [f"app.py: more than {MAX_FINDINGS} disguised source lines; not collected"]
    assert "\u202e" not in " ".join(failures)


def test_an_instruction_file_is_not_read_here(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text(_BIDI, encoding="utf-8")
    prompt_like = _server("CLAUDE.md")
    assert apply_source_unicode_findings(AIBOM(components=[prompt_like]), tmp_path) == 0
