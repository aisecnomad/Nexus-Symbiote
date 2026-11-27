"""Vendor-shaped literals in collected source are findings, and the value is not."""

from __future__ import annotations

from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent, PromptComponent
from nexus_symbiote.literal_credentials import MAX_LITERALS, apply_literal_credential_findings

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
    assert risk.detail.startswith("agent/app.py:1: a vendor token shape is committed (sha256:")
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
