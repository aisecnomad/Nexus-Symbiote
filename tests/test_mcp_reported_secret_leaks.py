"""Secrets reported against the merged MCP scrubbing change stay out of exports.

Each case is a value that is not a vendor-token shape, repeated in a sibling tool
description. Output redaction of ``ghp_`` tokens is not what withholds it: the
collector has to have read the value. Commands use only synthetic sentinels.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner

SECRET = "HunteR2-Sentinel-99xx"  # noqa: S105 - synthetic sentinel
DOLLAR = "Hunte$r2Hunter2Sentinel"  # noqa: S105 - a literal whose text contains "$"
PEM = b"-----BEGIN PRIVATE KEY-----\n" + b"\xfb\xef" * 40 + b"\n-----END PRIVATE KEY-----\n"
URLSAFE = base64.urlsafe_b64encode(PEM).decode()
STANDARD = base64.b64encode(PEM).decode()
MARKED = STANDARD[:30] + "\u200e" + STANDARD[30:]


def _scan(tmp_path: Path, relative: str, document: dict) -> str:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    result = MCPScanner().scan(tmp_path)
    return json.dumps(
        [component.model_dump(mode="json") for component in result.components],
        ensure_ascii=False,
    ) + "\n".join(result.scan_failures)


def _sibling(secret: str) -> dict:
    return {
        "command": "npx",
        "args": ["-y", "ok@1.0.0"],
        "tools": [{"name": "echo", "description": f"repeat {secret} please"}],
    }


def _mcp(tmp_path: Path, bad: dict, secret: str) -> str:
    return _scan(
        tmp_path,
        ".mcp.json",
        {"mcpServers": {"bad": bad, "ok": _sibling(secret)}},
    )


def test_one_thousand_and_one_arguments_still_withhold_their_password(tmp_path: Path) -> None:
    bad = {"command": "npx", "args": ["--password", SECRET, *["pad"] * 999]}
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


def test_urlsafe_base64_private_key_is_withheld(tmp_path: Path) -> None:
    assert STANDARD != URLSAFE
    bad = {"command": "npx", "args": ["-y", "x@1"], "env": {"SERVICE_CONFIG": URLSAFE}}
    assert URLSAFE not in _mcp(tmp_path, bad, URLSAFE)


def test_a_shell_default_containing_a_dollar_is_withheld(tmp_path: Path) -> None:
    bad = {
        "command": "npx",
        "args": ["-y", "x@1"],
        "env": {"API_TOKEN": "${UNUSED:-" + DOLLAR + "}"},
    }
    assert DOLLAR not in _mcp(tmp_path, bad, DOLLAR)


def test_a_shell_default_that_is_only_a_reference_stays(tmp_path: Path) -> None:
    text = _mcp(
        tmp_path,
        {
            "command": "npx",
            "args": ["-y", "x@1"],
            "env": {"API_TOKEN": "${UNUSED:-$OTHER}"},
        },
        "$OTHER",
    )
    assert "$OTHER" in text


@pytest.mark.parametrize(
    "args",
    [
        ["/c", "set API_TOKEN " + SECRET],
        ["/c", "set", "API_TOKEN", SECRET],
        ["/c", "setx API_TOKEN " + SECRET],
        ["/c", "setx", "API_TOKEN", SECRET],
    ],
)
def test_set_and_setx_without_equals_withhold_the_value(tmp_path: Path, args: list[str]) -> None:
    assert SECRET not in _mcp(tmp_path, {"command": "cmd", "args": args}, SECRET)


def test_a_zed_command_field_other_than_env_is_withheld(tmp_path: Path) -> None:
    document = {
        "context_servers": {
            "bad": {"command": {"path": "npx", "args": ["-y", "x@1"], "apiKey": SECRET}},
            "ok": _sibling(SECRET),
        }
    }
    assert SECRET not in _scan(tmp_path, ".zed/settings.json", document)


def test_a_three_element_env_list_withholds_its_value(tmp_path: Path) -> None:
    bad = {"command": "npx", "args": ["-y", "x@1"], "env": ["API_TOKEN", SECRET, "1"]}
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


def test_a_top_level_api_key_is_withheld(tmp_path: Path) -> None:
    bad = {"command": "npx", "args": ["-y", "x@1"], "apiKey": SECRET}
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


@pytest.mark.parametrize(
    "args",
    [
        ["-y", "x@1", "--header", "Authorization: Bearer --tls " + SECRET],
        ["-y", "x@1", "--auth", "bearer", "--tls", SECRET],
    ],
)
def test_bearer_with_a_flag_before_the_token_is_withheld(tmp_path: Path, args: list[str]) -> None:
    assert SECRET not in _mcp(tmp_path, {"command": "npx", "args": args}, SECRET)


def test_a_left_to_right_mark_inside_base64_does_not_hide_the_key(tmp_path: Path) -> None:
    bad = {"command": "npx", "args": ["-y", "x@1"], "env": {"SERVICE_CONFIG": MARKED}}
    exported = _mcp(tmp_path, bad, MARKED)
    assert MARKED not in exported
    assert MARKED.replace("\u200e", "") not in exported


def test_whitespace_only_command_changes_the_static_config_hash(tmp_path: Path) -> None:
    def digest(command: str) -> str:
        text = _scan(
            tmp_path / command.encode().hex(),
            ".mcp.json",
            {"mcpServers": {"s": {"command": command, "args": ["-y", "x@1"]}}},
        )
        payload = json.loads(text)
        server = next(
            item for item in payload if "static_config_hash" in item.get("properties", {})
        )
        return server["properties"]["static_config_hash"]

    plain = digest("npx")
    assert digest("npx ") != plain
    assert digest(" npx") != plain
    assert digest("npx\t") != plain
    assert digest("npx ") != digest(" npx")


@pytest.mark.parametrize(
    "bad",
    [
        {"command": "npx", "args": ["x@1", "--password", SECRET], "tools": 1},
        {"command": "npx", "args": ["x@1"], "auth": {"token": SECRET}, "tools": 1},
        {
            "command": "npx",
            "args": ["x@1"],
            "url": "https://user:" + SECRET + "@example.invalid/mcp",
            "tools": 1,
        },
        {
            "url": "https://example.invalid/mcp",
            "headers": [{"name": "Authorization", "val": "Bearer " + SECRET}],
        },
    ],
)
def test_already_closed_refusal_paths_still_withhold_the_secret(tmp_path: Path, bad: dict) -> None:
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


def test_server_component_is_still_recorded_for_a_padded_command(tmp_path: Path) -> None:
    text = _scan(
        tmp_path,
        ".mcp.json",
        {"mcpServers": {"s": {"command": "npx ", "args": ["-y", "x@1"]}}},
    )
    server = next(
        item for item in json.loads(text) if "static_config_hash" in item.get("properties", {})
    )
    assert MCPServerComponent.model_validate(server).command == "npx"
