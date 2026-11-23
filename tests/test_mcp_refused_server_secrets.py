"""Values of a refused or malformed MCP server stay out of exports (#208 merge review)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanners.mcp import MCPScanner, _diagnostic_values

STRIPE = "zq9XwV2rT7pL4mN8kJ3h"
USERINFO = "Pw9xK2mV7qL4"
INLINE = "Tk3jH8wQ5zR1"
WORDS = "correcthorsewalrus"


def _scan(root: Path, servers: dict[str, object]) -> str:
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(root)
    return AIBOM(components=result.components).model_dump_json() + "\n".join(
        [*result.scan_failures, *result.surfaces_excluded]
    )


def test_a_refused_servers_env_is_scrubbed_from_its_siblings(tmp_path: Path) -> None:
    shown = _scan(
        tmp_path,
        {
            "billing": {"command": "node", "args": "billing.js", "env": {"STRIPE_API_KEY": STRIPE}},
            f"echo-{STRIPE}": {
                "command": "node",
                "args": ["docs.js"],
                "tools": [
                    {"name": "lookup", "description": f"uses {STRIPE}", "inputSchema": {}},
                ],
            },
        },
    )
    assert STRIPE not in shown


def test_a_failure_names_its_server_without_its_own_url_or_inline_values(
    tmp_path: Path,
) -> None:
    shown = _scan(
        tmp_path,
        {
            f"url-{USERINFO}": {
                "type": "http",
                "url": f"https://user:{USERINFO}@mcp.example.com/mcp",
                "tools": [{"name": 5}],
            },
            f"npx-{INLINE}": {
                "command": "npx",
                "args": ["-y", "cross-env", f"API_TOKEN={INLINE}", "node", "x.js"],
                "tools": [{"name": 5}],
            },
        },
    )
    assert USERINFO not in shown and INLINE not in shown
    assert "invalid tool definition for server 'url-***'" in shown


def test_a_large_tool_list_does_not_use_up_the_walk_before_the_url(tmp_path: Path) -> None:
    tools: list[object] = [{"name": 5}]
    tools.extend(
        {"name": f"t{index}", "inputSchema": {"properties": {f"p{n}": {} for n in range(20)}}}
        for index in range(300)
    )
    shown = _scan(
        tmp_path,
        {
            f"url-{WORDS}": {
                "type": "http",
                "url": f"https://user:{WORDS}@mcp.example.com/mcp",
                "tools": tools,
            },
        },
    )
    assert WORDS not in shown
    assert "invalid tool definition for server 'url-***'" in shown


def test_a_large_unknown_field_withholds_the_failing_servers_name(tmp_path: Path) -> None:
    shown = _scan(
        tmp_path,
        {
            f"url-{WORDS}": _failing(
                {
                    "type": "http",
                    "url": "https://mcp.example.com/mcp",
                    "metadata": {f"k{index}": "v" for index in range(5000)},
                }
            ),
        },
    )
    assert WORDS not in shown
    assert "invalid tool definition for server '[withheld]'" in shown


def test_launch_fields_too_large_to_walk_are_refused() -> None:
    # The parser's argument limit refuses such a server first; the walk fails closed too.
    assert _diagnostic_values({"args": [f"API_TOKEN={WORDS}", *(["x"] * 5000)]}) is None


def test_a_short_user_name_is_not_scrubbed_from_names_but_a_short_password_is(
    tmp_path: Path,
) -> None:
    shown = _scan(
        tmp_path,
        {
            "git-mirror-hunter2": {
                "type": "http",
                "url": "https://git:hunter2@mcp.example.com/mcp",
                "tools": [{"name": 5}],
            },
        },
    )
    assert "hunter2" not in shown
    assert "invalid tool definition for server 'git-mirror-***'" in shown


def test_a_long_user_name_is_scrubbed_from_a_failing_servers_name(tmp_path: Path) -> None:
    shown = _scan(
        tmp_path,
        {
            f"mirror-{USERINFO}": {
                "type": "http",
                "url": f"https://{USERINFO}@mcp.example.com/mcp",
                "tools": [{"name": 5}],
            },
        },
    )
    assert USERINFO not in shown
    assert "invalid tool definition for server 'mirror-***'" in shown


def _failing(config: dict[str, object]) -> dict[str, object]:
    return {**config, "tools": [{"name": 5}]}


@pytest.mark.parametrize(
    "config",
    [
        {"command": "node", "env": {"DATABASE_URL": f"postgres://svc:{WORDS}@db.example.com/app"}},
        {
            "type": "http",
            "url": "https://mcp.example.com/mcp",
            "headers": {"X-Up": f"https://s:{WORDS}@u.example"},
        },
        {
            "type": "http",
            "url": "https://mcp.example.com/mcp",
            "http_headers": {"X-Up": f"https://s:{WORDS}@u.example"},
        },
        {
            "type": "http",
            "url": "https://mcp.example.com/mcp",
            "auth": {"tokenUrl": f"https://c:{WORDS}@auth.example/t"},
        },
        {"type": "http", "url": "https://mcp.example.com/mcp", "oauth": {"clientSecret": WORDS}},
        {"command": "node", "dev": {"debug": {"url": f"https://d:{WORDS}@dbg.example"}}},
        {
            "command": "npx",
            "args": ["-y", "mcp-remote", f"--url=https://user:{WORDS}@mcp.example.com/mcp"],
        },
        {
            "command": "sh",
            "args": ["-c", f"exec mcp-remote https://user:{WORDS}@mcp.example.com/mcp"],
        },
        {"command": "docker", "args": ["run", f"--env=API_TOKEN={WORDS}", "image"]},
        {"type": "http", "url": f"https://user:{WORDS}@mcp.example.com\\@x.example/mcp"},
        {"type": "http", "url": "https://mcp.example.com/mcp", "proxy": f"https://p:{WORDS}@px"},
    ],
)
def test_a_failing_servers_name_never_shows_a_credential_its_fields_hold(
    tmp_path: Path, config: dict[str, object]
) -> None:
    shown = _scan(tmp_path, {f"srv-{WORDS}": _failing(config)})
    assert WORDS not in shown
    assert "invalid tool definition for server 'srv-***'" in shown


def test_a_percent_encoded_password_is_scrubbed_as_decoded(tmp_path: Path) -> None:
    shown = _scan(
        tmp_path,
        {
            "pe-correct-horse-walrus": _failing(
                {"type": "http", "url": "https://u:correct%2Dhorse%2Dwalrus@mcp.example.com/mcp"}
            ),
        },
    )
    assert "correct-horse-walrus" not in shown
    assert "invalid tool definition for server 'pe-***'" in shown


def test_a_field_too_large_to_walk_withholds_the_failing_servers_name(tmp_path: Path) -> None:
    # `uri` is walked but not validated, so it can hold more than the walk reads.
    shown = _scan(
        tmp_path,
        {
            f"srv-{WORDS}": _failing(
                {"type": "http", "url": "https://mcp.example.com/mcp", "uri": [["x"] * 5000]}
            ),
        },
    )
    assert WORDS not in shown
    assert "invalid tool definition for server '[withheld]'" in shown


OAUTH = "ZqOAx7Wv3Lp9Rk2Tm5Yn"
URL_PASSWORD = "ZqURx7Wv3Lp9Rk2Tm5Yn"  # noqa: S105 - synthetic sentinel
ARGUMENT = "ZqARx7Wv3Lp9Rk2Tm5Yn"
SETTING = "ZqSEx7Wv3Lp9Rk2Tm5Yn"


def _echo(*values: str) -> dict[str, object]:
    description = "Uses " + " and ".join(values)
    tool = {"name": "t", "description": description, "inputSchema": {"type": "object"}}
    return {"command": "node", "args": ["srv.js"], "tools": [tool]}


def _scan_file(root: Path, relative: str, data: object) -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    result = MCPScanner().scan(root)
    return AIBOM(components=result.components).model_dump_json() + "\n".join(
        [*result.scan_failures, *result.surfaces_excluded]
    )


def test_a_refused_servers_auth_url_and_arguments_are_scrubbed_from_its_siblings(
    tmp_path: Path,
) -> None:
    refused = {
        "command": "node",
        "url": f"https://u:{URL_PASSWORD}@mcp.example.com/mcp",
        "oauth": {"clientSecret": OAUTH},
        "args": ["--api-key", ARGUMENT, 1],
    }
    shown = _scan(tmp_path, {"a": refused, "b": _echo(OAUTH, URL_PASSWORD, ARGUMENT)})
    assert ".mcp.json: invalid server configuration" in shown
    assert [value for value in (OAUTH, URL_PASSWORD, ARGUMENT) if value in shown] == []


def test_a_refused_zed_servers_settings_are_scrubbed_from_its_siblings(tmp_path: Path) -> None:
    refused = {"command": "node", "args": [1], "settings": {"api_key": SETTING}}
    data = {"context_servers": {"a": refused, "b": _echo(SETTING)}}
    shown = _scan_file(tmp_path, ".zed/settings.json", data)
    assert "invalid server configuration" in shown
    assert SETTING not in shown


def test_a_server_discarded_as_a_duplicate_is_scrubbed_from_its_siblings(tmp_path: Path) -> None:
    data = {
        "mcpServers": {"x": {"command": "node", "args": ["a.js"]}, "b": _echo(SETTING)},
        "servers": {"x": {"command": "node", "env": {"API_TOKEN": SETTING}}},
    }
    shown = _scan_file(tmp_path, ".mcp.json", data)
    assert "MCP server declared under more than one server map" in shown
    assert SETTING not in shown


def test_a_gemini_server_replaced_by_the_server_command_is_scrubbed(tmp_path: Path) -> None:
    servers = {"mcp": {"command": "node", "env": {"API_TOKEN": SETTING}}, "b": _echo(SETTING)}
    data = {"mcpServerCommand": "node m.js", "mcpServers": servers}
    shown = _scan_file(tmp_path, ".gemini/settings.json", data)
    assert "Uses ***" in shown or "Uses [" in shown
    assert SETTING not in shown


SPLIT_SCHEME = "Qm7vX2pL9sT4wB8nR3kJ6hY5cD1fG0zA"


@pytest.mark.parametrize(
    "launch",
    [
        # The scheme word ends the assignment; the credential is the next launch word.
        {
            "command": "cmd",
            "args": ["/c", "set", "AUTH_TYPE=Digest", SPLIT_SCHEME, "&&", "node", "s.js"],
        },
        {
            "command": "cmd",
            "args": ["/c", "set", "HEADER=Bearer", SPLIT_SCHEME, "&&", "node", "s.js"],
        },
        {
            "command": "cmd",
            "args": ["/c", "set", "PROXY_HEADER=Negotiate", SPLIT_SCHEME, "&&", "node", "s.js"],
        },
        {"command": "cmd", "args": ["/c", f"set X_HEADER=Basic {SPLIT_SCHEME}&& node s.js"]},
        {
            "command": "npx",
            "args": ["mcp-remote", "--env", "CUSTOM_HEADER=AWS4-HMAC-SHA256", SPLIT_SCHEME],
        },
        {"command": "sh", "args": ["-c", f"API_TOKEN=Bearer {SPLIT_SCHEME} node s.js"]},
    ],
)
def test_a_split_scheme_credential_is_scrubbed_from_an_echoing_sibling(
    tmp_path: Path, launch: dict[str, object]
) -> None:
    """A credential after a scheme word in a secret-like assignment never reaches the exports,
    whatever the finding classifier makes of the assignment's name."""
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
    from nexus_symbiote.generators.spdx import SPDXGenerator

    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"launch": launch, "echo": _echo(SPLIT_SCHEME)}})
    )
    result = MCPScanner().scan(tmp_path)
    bom = AIBOM(components=result.components)
    shown = bom.model_dump_json() + "\n".join([*result.scan_failures, *result.surfaces_excluded])
    assert SPLIT_SCHEME not in shown
    assert SPLIT_SCHEME not in json.dumps(CycloneDXGenerator().generate(bom))
    assert SPLIT_SCHEME not in json.dumps(SPDXGenerator().generate(bom))
