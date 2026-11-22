"""Adversarial regression tests for PR #327 scheme operands, refused secrets, and command drift."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.scanners.mcp import MCPScanner
from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure


@pytest.mark.parametrize(
    ("setting", "secret"),
    [
        ("--env=API_TOKEN=Bearer", "--aB3cD4eF=1234"),
        ("--env=API_TOKEN=Bearer", "--aB3c-dE5fGhIjKl="),
        ("--auth=token", "--aB3c-dE5fGhIjKl="),
        ("--env=API_TOKEN=Bearer", "k9X2mP7qR4=v1"),
        ("--env=API_TOKEN=Bearer", "k9X2mP7qR4=2025"),
        ("--env=API_TOKEN=Bearer", "k9X2mP7qR4=true"),
        ("--auth=token", "--ProductionApiSecretBearerTokenValue"),
        ("--auth=token", "--cobalt-falcon-harbor-quartz-velvet-cipher"),
    ],
)
def test_scheme_operand_credentials_stay_redacted(
    tmp_path: Path, setting: str, secret: str
) -> None:
    result, inventory = _scan(
        tmp_path,
        {"source": {"command": "node", "args": [setting, secret]}, "sibling": _echo(secret)},
    )
    assert has_exposure(result)
    assert all(secret not in doc for doc in exports(inventory))


@pytest.mark.parametrize(
    ("extra_config", "expected_failure"),
    [
        ({"mcpServerCommand": "node --api-key 'ZqSEx7Wv3Lp9Rk2Tm5Yn'"}, "not plain words"),
        ({"mcpServerCommand": ["node", "--api-key", "ZqSEx7Wv3Lp9Rk2Tm5Yn"]}, "invalid MCP server"),
        (
            {
                "mcpServerCommand": "node --api-key ZqSEx7Wv3Lp9Rk2Tm5Yn",
                "mcp": {"serverCommand": "node --version"},
            },
            "more than one setting",
        ),
    ],
)
def test_refused_gemini_server_command_scrubs_secrets_from_siblings(
    tmp_path: Path, extra_config: dict[str, object], expected_failure: str
) -> None:
    value = "ZqSEx7Wv3Lp9Rk2Tm5Yn"
    gemini = tmp_path / ".gemini"
    gemini.mkdir()
    (gemini / "settings.json").write_text(
        json.dumps(
            {
                **extra_config,
                "mcpServers": {"sibling": _echo(value)},
            }
        ),
        encoding="utf-8",
    )
    result = MCPScanner().scan(tmp_path)
    assert any(expected_failure in f for f in result.scan_failures)
    dumped = json.dumps([c.model_dump(mode="json") for c in result.components])
    assert value not in dumped
