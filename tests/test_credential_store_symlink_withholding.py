"""Adversarial regression tests for PR #347 credential-store symlinks and direct credential rails."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.rag import RAGScanner


@pytest.mark.parametrize(
    ("store_dir", "store_file"),
    [
        (".kube", "config"),
        (".docker", "config.json"),
        (".aws", "config"),
        (".vault", "token"),
    ],
)
def test_guardrail_config_symlink_into_credential_store_is_withheld(
    tmp_path: Path, store_dir: str, store_file: str
) -> None:
    store = tmp_path / store_dir
    store.mkdir()
    (store / store_file).write_text("sensitive-token-material\n", encoding="utf-8")
    nemo = tmp_path / "nemo"
    nemo.mkdir()
    (nemo / "safe.co").write_text("define flow safe\n  bot say 'ok'\n", encoding="utf-8")
    (nemo / "config.yml").symlink_to(Path("..") / store_dir / store_file)

    result = RAGScanner().scan(tmp_path)
    assert not result.components
    assert any("nemo/config.yml" in entry for entry in result.surfaces_excluded)


def test_a2a_card_symlink_into_credential_store_is_withheld(tmp_path: Path) -> None:
    store = tmp_path / ".docker"
    store.mkdir()
    (store / "config.json").write_text('{"auths": {"reg": {"auth": "dGVzdA=="}}}', encoding="utf-8")
    (tmp_path / "agent.json").symlink_to(Path(".docker/config.json"))

    result = A2AScanner().scan(tmp_path)
    assert not result.components
    assert any("agent.json" in entry for entry in result.surfaces_excluded)


@pytest.mark.parametrize("rail_name", ["secrets.co", "credentials.co", ".secrets.co"])
def test_direct_regular_credential_named_colang_rail_is_withheld(
    tmp_path: Path, rail_name: str
) -> None:
    nemo = tmp_path / "nemo"
    nemo.mkdir()
    (nemo / "config.yml").write_text("models:\n  - type: main\n    engine: openai\n")
    (nemo / rail_name).write_text("define flow secret\n  bot say 'super-secret-value'\n")
    (nemo / "safe.co").write_text("define flow safe\n  bot say 'hello'\n")

    result = RAGScanner().scan(tmp_path)
    assert len(result.components) == 1
    rail_files = result.components[0].properties.get("rail_files", {})
    assert rail_name not in rail_files
    assert "safe.co" in rail_files
    assert any(rail_name in entry for entry in result.surfaces_excluded)
