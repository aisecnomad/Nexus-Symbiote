"""`.env` findings name the key and vendor. They do not name or hash the value."""

from __future__ import annotations

from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.credential_allowlist import bind_credential_allowlist, load_credential_allowlist
from nexus_symbiote.env_credentials import MAX_ENV_LINES, apply_env_credential_findings

_SAMPLE = "sk-proj-thisisfake0123456789ab"


def _bom(tmp_path: Path, name: str = "notes.md") -> PromptComponent:
    (tmp_path / name).write_text("notes\n", encoding="utf-8")
    return PromptComponent(bom_ref="prompt:notes", name="notes", source_path=name)


def test_an_env_assignment_names_the_key_and_vendor_not_the_value(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        f'# comment\n\nexport OPENAI_API_KEY="{_SAMPLE}"\nPORT=3000\n',
        encoding="utf-8",
    )
    notes = _bom(tmp_path)
    added = apply_env_credential_findings(AIBOM(components=[notes]), tmp_path)
    assert added == 2
    rendered = " ".join(risk.detail for risk in notes.risks)
    assert ".env:3: OPENAI_API_KEY holds an openai credential." in rendered
    assert ".env:4: PORT holds an unspecified credential." in rendered
    assert _SAMPLE not in rendered
    assert "sha256:" not in rendered


def test_a_template_uses_the_vendor_shape_digest(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(f"OPENAI_API_KEY={_SAMPLE}\n", encoding="utf-8")
    (tmp_path / ".env.sample").write_text("PORT=1\n", encoding="utf-8")
    notes = _bom(tmp_path)
    added = apply_env_credential_findings(AIBOM(components=[notes]), tmp_path)
    assert added == 1
    detail = notes.risks[0].detail
    assert detail.startswith(".env.example:1: a vendor token shape is committed (value unbound).")
    assert _SAMPLE not in detail


def test_a_mark_inside_the_value_still_names_the_vendor(tmp_path: Path) -> None:
    marked = "sk-proj-thisis" + "\u200b" + "fake0123456789ab"
    (tmp_path / "svc" / ".env").parent.mkdir()
    (tmp_path / "svc" / ".env").write_text(f"OPENAI_API_KEY={marked}\n", encoding="utf-8")
    notes = _bom(tmp_path)
    added = apply_env_credential_findings(AIBOM(components=[notes]), tmp_path)
    assert added == 1
    assert notes.risks[0].detail == "svc/.env:1: OPENAI_API_KEY holds an openai credential."
    assert marked not in notes.risks[0].detail
    assert "\u200b" not in notes.risks[0].detail


def test_a_non_utf8_env_and_a_huge_env_fail_closed(tmp_path: Path) -> None:
    (tmp_path / ".env").write_bytes(b"\xff" + _SAMPLE.encode())
    notes = _bom(tmp_path)
    failures: list[str] = []
    assert (
        apply_env_credential_findings(AIBOM(components=[notes]), tmp_path, failures=failures) == 0
    )
    assert notes.risks == []
    assert failures == [".env: env credentials were not read (not UTF-8)"]
    assert _SAMPLE not in failures[0]

    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / ".env").write_text("A=1\n" * (MAX_ENV_LINES + 1), encoding="utf-8")
    failures.clear()
    assert (
        apply_env_credential_findings(AIBOM(components=[notes]), tmp_path, failures=failures) == 0
    )
    assert any("line bound" in failure for failure in failures)
    assert _SAMPLE not in " ".join(failures)


def test_a_path_allowlist_suppresses_the_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={_SAMPLE}\n", encoding="utf-8")
    (tmp_path / ".nexus-symbiote-credential-allowlist.yaml").write_text(
        'allow:\n  - path: ".env"\n    reason: "Local fixture."\n',
        encoding="utf-8",
    )
    allowlist, error = load_credential_allowlist(tmp_path)
    assert error is None
    notes = _bom(tmp_path)
    with bind_credential_allowlist(allowlist):
        added = apply_env_credential_findings(AIBOM(components=[notes]), tmp_path)
    assert added == 0
    assert notes.risks == []
