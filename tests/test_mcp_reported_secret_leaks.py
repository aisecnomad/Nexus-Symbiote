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


def test_flags_between_a_scheme_and_its_token_are_all_skipped(tmp_path: Path) -> None:
    bad = {
        "command": "npx",
        "args": ["-y", "x@1", "--auth", "bearer", "--tls", "--insecure", SECRET],
    }
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


def test_an_env_list_of_any_length_withholds_its_value(tmp_path: Path) -> None:
    bad = {
        "command": "npx",
        "args": ["-y", "x@1"],
        "env": ["API_TOKEN", SECRET, "1", "extra"],
    }
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


@pytest.mark.parametrize("mark", ["\u200b", "\u202e"])
def test_a_password_mark_does_not_hide_the_unmarked_token(tmp_path: Path, mark: str) -> None:
    marked = SECRET[:8] + mark + SECRET[8:]
    bad = {"command": "npx", "args": ["-y", "x@1", "--password", marked]}
    assert marked not in _mcp(tmp_path, bad, SECRET)
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


def test_password_decoys_past_the_position_cap_do_not_publish_the_real_secret(
    tmp_path: Path,
) -> None:
    args: list[str] = []
    for index in range(70):
        args.extend(["--password", f"DecoySecret{index:04d}Xx"])
    args.extend(["--password", SECRET])
    args.extend(["pad"] * (1001 - len(args)))
    assert len(args) > 1000
    assert SECRET not in _mcp(tmp_path, {"command": "npx", "args": args}, SECRET)


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
    assert digest("npx\u00a0") != plain
    assert digest("npx\u200b") != plain


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


@pytest.mark.parametrize(
    ("first", "second", "expected_command"),
    [
        (" ghp_" + "a1B2" * 9 + " ", " ghp_" + "c3D4" * 9 + " ", "[redacted-command]"),
        ("ghp_" + "a1B2" * 9 + "\u200b", "ghp_" + "c3D4" * 9 + "\u200b", "[redacted-command]"),
        (
            "/opt/ghp_" + "a1B2" * 9 + "/npx ",
            "/opt/ghp_" + "c3D4" * 9 + "/npx ",
            "npx",
        ),
    ],
)
def test_padded_secret_or_path_command_does_not_leak_into_unkeyed_hash(
    tmp_path: Path, first: str, second: str, expected_command: str
) -> None:
    def digest(sub: str, command: str) -> str:
        text = _scan(
            tmp_path / sub,
            ".mcp.json",
            {"mcpServers": {"s": {"command": command, "args": ["-y", "x@1"]}}},
        )
        server = next(
            item for item in json.loads(text) if "static_config_hash" in item.get("properties", {})
        )
        assert server["command"] == expected_command
        return server["properties"]["static_config_hash"]

    assert digest("a", first) == digest("b", second)


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("setx", ["API_TOKEN", SECRET]),
        ("setx", ["/M", "API_TOKEN", SECRET]),
        ("C:\\Windows\\System32\\setx.exe", ["/M", "API_TOKEN", SECRET]),
        ("cmd", ["/c", f"setx /M API_TOKEN {SECRET}"]),
        ("cmd", ["/c", "setx", "/M", "API_TOKEN", SECRET]),
    ],
)
def test_setx_command_and_machine_flag_withhold_credential(
    tmp_path: Path, command: str, args: list[str]
) -> None:
    bad = {"command": command, "args": args}
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


def test_scheme_flag_operands_rejects_hyphenated_words_in_linear_time() -> None:
    from nexus_symbiote.scanners.mcp import _scheme_flag_operands
    from tests.support import scaling_ratio

    assert _scheme_flag_operands(f"Bearer-foo {SECRET}") == []
    assert _scheme_flag_operands(f"X-Bearer --tls {SECRET}") == []
    assert _scheme_flag_operands("Bearer-" * 4_000 + f" {SECRET}") == []
    ratio = scaling_ratio(
        lambda scale: _scheme_flag_operands("Bearer-" * (500 * scale) + f" {SECRET}")
    )
    assert ratio < 10.0


@pytest.mark.parametrize("scheme", ["DPoP", "HOBA"])
def test_dpop_and_hoba_scheme_flags_withhold_credential(tmp_path: Path, scheme: str) -> None:
    bad = {
        "command": "npx",
        "args": ["-y", "x@1", "--header", f"Authorization: {scheme} --tls {SECRET}"],
    }
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


@pytest.mark.parametrize(
    ("command", "head_args"),
    [
        ("cmd", ["/c", "set", "API_TOKEN", SECRET]),
        ("cmd", ["/c", "setx", "API_TOKEN", SECRET]),
        ("curl", ["-u", f"user:{SECRET}"]),
    ],
)
def test_overflow_args_withhold_set_setx_and_fetcher_credentials(
    tmp_path: Path, command: str, head_args: list[str]
) -> None:
    args = [*head_args, *(["pad"] * 1_000)]
    bad = {"command": command, "args": args}
    assert SECRET not in _mcp(tmp_path, bad, SECRET)


def test_setx_withholds_base64_padded_secret(tmp_path: Path) -> None:
    padded_value = "dG9rZW4xMjM0NTY3ODkw=="
    bad = {"command": "cmd", "args": ["/c", "setx", "API_TOKEN", padded_value]}
    assert padded_value not in _mcp(tmp_path, bad, padded_value)
