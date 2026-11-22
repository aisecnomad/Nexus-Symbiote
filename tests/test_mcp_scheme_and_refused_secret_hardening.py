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
        ("--token-source=token", "ZqSEx7Wv3Lp9Rk2Tm5Yn"),
        ("--token-format=token", "ProductionApiSecretBearerTokenValue"),
        ("--auth-source=token", "ZqSEx7Wv3Lp9Rk2Tm5Yn"),
        ("--oauth-profile=token", "--cobalt-falcon-harbor-quartz-velvet-cipher"),
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


def test_shell_default_after_scheme_assignment_is_redacted(tmp_path: Path) -> None:
    marker = "RealDefaultValue123"
    result, inventory = _scan(
        tmp_path,
        {
            "source": {
                "command": "node",
                "args": ["--env=API_TOKEN=Bearer", f"${{API_TOKEN:-{marker}}}"],
            },
            "sibling": _echo(marker),
        },
    )
    assert has_exposure(result)
    assert all(marker not in doc for doc in exports(inventory))


def test_zed_and_opencode_displaced_refused_secrets_scrub_siblings(tmp_path: Path) -> None:
    outer_marker = "ZqOuter9Xk2Lm4Np7Qr8"
    inner_marker = "ZqInner5Wv3Jk8Mt2Py6"
    zed = tmp_path / "zed"
    (zed / ".zed").mkdir(parents=True)
    (zed / ".zed" / "settings.json").write_text(
        json.dumps(
            {
                "context_servers": {
                    "refused": {
                        "env": {"API_TOKEN": outer_marker},
                        "command": {"path": "node", "env": {"API_TOKEN": inner_marker}},
                    },
                    "sibling": _echo(f"{outer_marker} {inner_marker}"),
                }
            }
        ),
        encoding="utf-8",
    )
    zed_result = MCPScanner().scan(zed)
    zed_dumped = json.dumps([c.model_dump(mode="json") for c in zed_result.components])
    assert outer_marker not in zed_dumped and inner_marker not in zed_dumped

    opencode = tmp_path / "opencode"
    opencode.mkdir()
    (opencode / "opencode.json").write_text(
        json.dumps(
            {
                "mcp": {
                    "refused": {
                        "type": "local",
                        "command": ["node", "--api-key", inner_marker],
                        "args": ["--api-key", outer_marker],
                    },
                    "sibling": {
                        "type": "local",
                        "command": ["node", "srv.js"],
                        "tools": [{"name": "t", "description": f"{outer_marker} {inner_marker}"}],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    oc_result = MCPScanner().scan(opencode)
    oc_dumped = json.dumps([c.model_dump(mode="json") for c in oc_result.components])
    assert outer_marker not in oc_dumped and inner_marker not in oc_dumped


def test_malformed_list_and_semicolon_query_secrets_scrub_siblings(tmp_path: Path) -> None:
    list_marker = "ZqList7Kp2Rm9Xw4Vn6"
    ref_marker = "ZqRef4Ht8Lm2Qp5Vx9"
    query_marker = "ZqQuery3Bn6Jk8Ty2Mw"
    phrase_marker = "correct horse battery staple"
    result, inventory = _scan(
        tmp_path,
        {
            "bad_list": ["node", "--api-key", list_marker],
            "bad_env": {
                "command": "node",
                "env": [["DB_PASSWORD", phrase_marker], f"${{API_TOKEN:-{ref_marker}}}"],
            },
            "bad_url": {
                "url": f"https://mcp.example.com/sse?a=1;api_key={query_marker}",
                "args": "not-a-list",
            },
            "sibling": _echo(f"{list_marker} {ref_marker} {query_marker} {phrase_marker}"),
        },
    )
    for doc in exports(inventory):
        for marker in (list_marker, ref_marker, query_marker, phrase_marker):
            assert marker not in doc


def test_rewrapped_key_literals_resists_constant_prefix_dos_and_padding_variants(
    tmp_path: Path,
) -> None:
    import base64
    import textwrap

    from nexus_symbiote.scanners.mcp_credentials import rewrapped_key_literals

    # Constant PKCS#8 base64 prefix repeated 120x must not blow the comparison budget.
    pem = "-----BEGIN PRIVATE KEY-----\n" + ("A" * 64 + "\n") * 25 + "-----END PRIVATE KEY-----\n"
    encoded = base64.b64encode(pem.encode()).decode()
    prefix = encoded[:16]
    decoy = (prefix * 120) + " tail"
    unpadded = encoded.rstrip("=")
    bom_wrapped = "\ufeff".join(textwrap.wrap(unpadded, 19))
    found = set(rewrapped_key_literals({"decoy": decoy, "copy": bom_wrapped}, [encoded]))
    assert bom_wrapped in found

    # Wrapped base64 private key inside oauth must also scrub differently wrapped copies.
    gcp = json.dumps({"type": "service_account", "private_key": "public-synthetic-fixture-key-42"})
    gcp_b64 = base64.b64encode(gcp.encode()).decode()
    wrapped_64 = "\n".join(textwrap.wrap(gcp_b64, 24))
    wrapped_17 = "\r\n".join(textwrap.wrap(gcp_b64.rstrip("="), 17))
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"url": "https://mcp.example.com", "oauth": {"privateKey": wrapped_64}},
            "sibling": _echo(wrapped_17),
        },
    )
    assert not any("comparison limit" in f for f in result.scan_failures)
    assert all(gcp_b64[16:40] not in doc for doc in exports(inventory))


def test_multiple_endpoints_and_control_char_urls_are_unbound(tmp_path: Path) -> None:
    from nexus_symbiote.core.models import UNBOUND_VALUES_DETAIL

    result, _ = _scan(
        tmp_path,
        {
            "multi": {
                "url": "https://safe.example.com",
                "httpUrl": "https://other.example.com",
            },
            "ctrl": {"url": "https://mcp\t.example.com\n"},
        },
    )
    by_name = {c.name: c for c in result.components}
    for name in ("multi", "ctrl"):
        risks = [r.detail for r in by_name[name].risks if UNBOUND_VALUES_DETAIL in r.detail]
        assert any("endpoint" in detail for detail in risks)
    assert by_name["ctrl"].endpoint_url == "[redacted]"


def test_non_assignment_digest_selector_keeps_public_package_spec(tmp_path: Path) -> None:
    result, inventory = _scan(
        tmp_path,
        {
            "source": {
                "command": "npx",
                "args": ["--auth=digest", "@example/mcp-server@1.0.0"],
            },
            "sibling": _echo("@example/mcp-server@1.0.0"),
        },
    )
    assert "@example/mcp-server@1.0.0" in inventory.to_json()
    assert not has_exposure(result)


@pytest.mark.parametrize(
    "selector",
    [
        "--auth-type=bearer",
        "--auth=token",
        "--auth-mode=basic",
        "--authentication=bearer",
        "--auth-header=bearer",
        "--token-source=token",
        "--env=AUTH_TYPE=Bearer",
    ],
)
@pytest.mark.parametrize(
    "public_arg",
    [
        "--no-http2",
        "--http2-only",
        "--ipv4-only",
        "--oauth2-pkce",
        "--tls13-only",
        "--s3-bucket",
        "--utf8-mode",
        "--sha256-verify",
        "--k8s-context",
        "--no_http2",
        "--enableTLS",
        "--disableSSL",
        "--allowHTTP2",
        "--noHTTP2",
        "--enableMTLS",
        "--useJSON",
        "--enableMCP",
        "--allowSSE",
        "--disableCORS",
        "--enableIPv4",
        "--TLSMode",
        "--HTTPProxy",
        "--model=claude-sonnet-4-20250514",
        "--tenant-id=18ac72c8-1813-4200-9ff1-a800cbcda102",
        "--workspace=team-alpha-2025",
        "--no-http2=true",
        "--enableTLS=true",
        "--env=NODE_ENV=production",
        "--enable-automatic-updates=",
        "MODEL=claude-sonnet-4-20250514",
        "TENANT_ID=18ac72c8-1813-4200-9ff1-a800cbcda102",
        "PORT=8080",
        "Workspace10",
        "WorkspaceV10",
        "OpenAPI3.1",
        "OAuth2.1",
    ],
)
def test_mode_selector_keeps_benign_cli_options_switches_and_labels_public(
    tmp_path: Path, selector: str, public_arg: str
) -> None:
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "node", "args": [selector, public_arg]},
            "sibling": _echo(public_arg),
        },
    )
    assert not has_exposure(result)
    assert all(public_arg in doc for doc in exports(inventory))


@pytest.mark.parametrize(
    ("selector", "following", "hidden_literal"),
    [
        (
            "--auth-type=bearer",
            "--api-key=ZqSEx7Wv3Lp9Rk2Tm5Yn",
            "ZqSEx7Wv3Lp9Rk2Tm5Yn",
        ),
        (
            "--auth-type=bearer",
            "--env=API_TOKEN=ZqSEx7Wv3Lp9Rk2Tm5Yn",
            "ZqSEx7Wv3Lp9Rk2Tm5Yn",
        ),
        (
            "--auth-type=bearer",
            "--model=ghp_k9X2mP7qR4wZ8vL3nB6tY1cF5hJ0dS2uE4gK",
            "ghp_k9X2mP7qR4wZ8vL3nB6tY1cF5hJ0dS2uE4gK",
        ),
        (
            "--auth-type=bearer",
            "--model=${API_TOKEN:-RealDefaultMarker847}",
            "RealDefaultMarker847",
        ),
        ("--auth-type=bearer", "--aB3cD4eF=8492", "--aB3cD4eF=8492"),
        ("--auth-type=bearer", "--x9k2m8p4q7r1=val", "--x9k2m8p4q7r1=val"),
        ("--auth-type=bearer", "--x=ZqSEx7Wv3Lp9Rk2Tm5Yn", "--x=ZqSEx7Wv3Lp9Rk2Tm5Yn"),
        (
            "--auth-type=bearer",
            "--enable-automatic-updates==",
            "--enable-automatic-updates==",
        ),
        ("--auth-type=bearer", "--xqtrkm849wznvb", "--xqtrkm849wznvb"),
        ("--auth-type=bearer", "--xqtr84-wznv92", "--xqtr84-wznv92"),
        ("--auth-type=bearer", "--token-849271", "--token-849271"),
        ("--auth-type=bearer", "--xqtrKWZNpmvb", "--xqtrKWZNpmvb"),
        ("--auth-type=bearer", "--XKJQPWZRMNVB", "--XKJQPWZRMNVB"),
        (
            "--auth-type=bearer",
            "--cobalt-falcon-harbor-quartz-velvet-cipher=1",
            "--cobalt-falcon-harbor-quartz-velvet-cipher=1",
        ),
        (
            "--auth-type=bearer",
            "MODEL=a9f2c8d4-e5b6a7c8-d9e0f1a2",
            "MODEL=a9f2c8d4-e5b6a7c8-d9e0f1a2",
        ),
        (
            "--auth-type=bearer",
            "MODEL=claude-4-83749261",
            "MODEL=claude-4-83749261",
        ),
        (
            "--auth-type=bearer",
            "MODEL=a-b-c-d-e-f-20250514",
            "MODEL=a-b-c-d-e-f-20250514",
        ),
        (
            "--auth-type=bearer",
            "MODEL=superlongsegmentname-4-20250514",
            "MODEL=superlongsegmentname-4-20250514",
        ),
        ("--auth-type=bearer", "--qzx__wvn_kpm", "--qzx__wvn_kpm"),
        ("--auth-type=bearer", "--a-http2-b", "--a-http2-b"),
        (
            "--auth-type=bearer",
            "FOO=deadbeef84927163a5c4e2",
            "FOO=deadbeef84927163a5c4e2",
        ),
        (
            "--auth-type=bearer",
            "AB=deadbeef84927163a5c4e2",
            "AB=deadbeef84927163a5c4e2",
        ),
        (
            "--auth-type=bearer",
            "API_KEY=18ac72c8-1813-4200-9ff1-a800cbcda102",
            "18ac72c8-1813-4200-9ff1-a800cbcda102",
        ),
        ("--auth-type=bearer", "Workspace8492", "Workspace8492"),
        ("--auth-type=bearer", "claude-4-83749261", "claude-4-83749261"),
        ("--env=API_TOKEN=Bearer", "--no-http2", "--no-http2"),
        ("--env=API_TOKEN=Bearer", "--enableTLS", "--enableTLS"),
        ("--env=API_TOKEN=Bearer", "Workspace10", "Workspace10"),
    ],
)
def test_mode_selector_refactor_keeps_adversarial_secrets_redacted(
    tmp_path: Path, selector: str, following: str, hidden_literal: str
) -> None:
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "node", "args": [selector, following]},
            "sibling": _echo(hidden_literal),
        },
    )
    assert has_exposure(result)
    assert all(hidden_literal not in doc for doc in exports(inventory))


@pytest.mark.parametrize("operand", ["--no-http2", "--enableTLS", "Workspace10"])
def test_cmd_set_still_redacts_benign_looking_operands(tmp_path: Path, operand: str) -> None:
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "cmd", "args": ["/c", f"set AUTH_TYPE=Bearer {operand}"]},
            "sibling": _echo(operand),
        },
    )
    assert has_exposure(result)
    assert all(operand not in doc for doc in exports(inventory))


def test_short_empty_option_after_mode_selector_stays_public(tmp_path: Path) -> None:
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "node", "args": ["--auth-type=bearer", "--empty="]},
            "sibling": _echo("--empty="),
        },
    )
    assert not has_exposure(result)
    assert all("--empty=" in doc for doc in exports(inventory))
