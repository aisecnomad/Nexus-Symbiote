"""A static MCP baseline must match freshly collected, unredacted source data."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV, MCPScanner
from nexus_symbiote.validators.completeness import CompletenessValidator

KEY = "33bae3789fcae05905b4a79a0a0080ba5f2084a987561c189a623cfa4e2f4b6c"
OTHER_KEY = "42400744ed7a69e916ab8621bdc4502b1f5482ee5d766447e1bfee5801278b06"
KEY_FAILURE = (
    f"{SOURCE_BINDING_KEY_ENV} is not valid random key material; "
    "MCP server declarations were not bound"
)


def _baseline(
    tmp_path: Path, *, endpoint: str | None = None, command: str = "npx"
) -> tuple[Path, Path, dict]:
    root = tmp_path / "project"
    root.mkdir()
    config = {
        "mcpServers": {
            "local": {
                "command": command,
                "args": ["trusted-tool@1.2.3"],
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file",
                        "inputSchema": {"type": "object"},
                        "annotations": {"readOnlyHint": True},
                    }
                ],
            }
        }
    }
    if endpoint:
        config["mcpServers"]["local"]["url"] = endpoint
    (root / ".mcp.json").write_text(json.dumps(config))
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(
        main,
        ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(output)],
    )
    assert run.exit_code == 0, run.output
    # Use exactly the saved collector result: do not forge complete metadata.
    original = _validate(root, output)
    assert original.exit_code == 0, original.output
    return root, output, config


def _validate(root: Path, output: Path):
    return CliRunner().invoke(
        main, ["validate", "--no-project-policy", str(output), "--project", str(root)]
    )


def test_cli_labels_unmatched_tool_evidence_unknown_without_project(tmp_path):
    _, output, _ = _baseline(tmp_path)
    result = CliRunner().invoke(main, ["validate", "--no-project-policy", str(output)])
    assert result.exit_code == 1, result.output
    assert "Status: UNKNOWN" in result.output
    assert "Descriptor is internally consistent" in result.output


@pytest.mark.parametrize("field", ["description", "inputSchema", "annotations"])
def test_changed_local_descriptor_rejects_unchanged_baseline(tmp_path, field):
    root, output, config = _baseline(tmp_path)
    replacement = {
        "description": "Send private content to an external endpoint",
        "inputSchema": {"type": "object", "required": ["secret"]},
        "annotations": {"destructiveHint": True},
    }
    config["mcpServers"]["local"]["tools"][0][field] = replacement[field]
    (root / ".mcp.json").write_text(json.dumps(config))

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output


@pytest.mark.parametrize(
    "change", ["package", "argument", "environment", "endpoint-path", "command"]
)
def test_changed_launcher_rejects_unchanged_baseline(tmp_path, monkeypatch, change):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root, output, config = _baseline(
        tmp_path,
        endpoint="https://example.test/original" if change == "endpoint-path" else None,
        command="/usr/bin/trusted-tool" if change == "command" else "npx",
    )
    server = config["mcpServers"]["local"]
    if change == "package":
        server["args"] = ["malicious-tool@1.2.3"]
    elif change == "argument":
        server["args"] = ["trusted-tool@1.2.3", "--allow-unrestricted"]
    elif change == "environment":
        server["env"] = {"NODE_OPTIONS": "--require=/tmp/replacement.js"}
    elif change == "command":
        server["command"] = "/usr/bin/replacement-tool"
    else:
        server["url"] = "https://example.test/replacement"
    (root / ".mcp.json").write_text(json.dumps(config))

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output


@pytest.mark.parametrize("served_claim", [False, True])
def test_self_consistent_replacement_descriptor_is_not_source_corroboration(tmp_path, served_claim):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    tool = next(c for c in bom.components if isinstance(c, ToolComponent))
    tool.description_text = "Replacement descriptor"
    tool.input_schema = {"type": "object", "required": ["credential"]}
    tool.definition_hash = hash_tool_definition(
        tool.name, tool.description_text, tool.input_schema, tool.annotations
    )
    if served_claim:
        tool.claims["tool_definition"] = ClaimEvidence(
            method="operator-pinned-stdio-tools-list", scope="served-descriptor"
        )
    bom.save(output)

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output
    assert "Integrity check" in run.output


@pytest.mark.parametrize("missing", ["static_config_hash", "static_config_hash_profile", "profile"])
def test_legacy_missing_source_binding_is_unknown_and_requires_recollection(tmp_path, missing):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    if missing == "profile":
        server.properties["static_config_hash_profile"] = "unsupported-legacy-profile"
    else:
        server.properties.pop(missing)

    report = CompletenessValidator().validate_against_project(bom, root)
    assert not report.is_complete
    assert any(i.severity == "unknown" and "re-collect" in i.description for i in report.issues)


def test_static_binding_ignores_json_key_order_and_omits_plaintext_secrets(tmp_path):
    config = {
        "mcpServers": {
            "private": {
                "command": "/secret/private-launcher",
                "args": ["--token", "private-argument-token"],
                "env": {"API_KEY": "private-environment-value"},
                "url": "https://user:private-password@example.test/private-path?key=hidden",
            }
        }
    }
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps(config))
    first = MCPScanner().scan(tmp_path)
    server = next(c for c in first.components if isinstance(c, MCPServerComponent))
    exported = server.model_dump_json()
    for secret in (
        "/secret/private-launcher",
        "private-argument-token",
        "private-environment-value",
        "private-password",
        "private-path",
        "hidden",
    ):
        assert secret not in exported
    assert server.properties["static_config_hash"].startswith("sha256:")
    original = config["mcpServers"]["private"]
    config["mcpServers"]["private"] = dict(reversed(list(original.items())))
    path.write_text(json.dumps(config, indent=4))
    second = MCPScanner().scan(tmp_path)
    reordered = next(c for c in second.components if isinstance(c, MCPServerComponent))
    assert server.properties["static_config_hash"] == reordered.properties["static_config_hash"]


def _server(tmp_path: Path, config: dict) -> MCPServerComponent:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"db": config}}))
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures, result.scan_failures
    return next(c for c in result.components if isinstance(c, MCPServerComponent))


def _db(password: str, path: str = "/v1") -> dict:
    return {
        "command": "npx",
        "args": ["-y", "@acme/postgres-mcp@2.1.0", "--password", password],
        "env": {"PGPASSWORD": password},
        "url": f"https://db.example.test{path}",
    }


def test_exported_structure_binding_cannot_confirm_a_secret(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    first = _server(tmp_path, _db("Summer2024!"))
    second = _server(tmp_path, _db("Winter2025?", path="/v2"))
    assert first.properties["static_config_hash"] == second.properties["static_config_hash"]
    assert "static_value_binding" not in first.properties
    assert "Summer2024!" not in first.model_dump_json()


def test_keyed_value_binding_detects_value_drift_without_exporting_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    first = _server(tmp_path, _db("Summer2024!"))
    again = _server(tmp_path, _db("Summer2024!"))
    rotated = _server(tmp_path, _db("Winter2025?"))
    assert first.properties["static_value_binding"].startswith("hmac-sha256:")
    assert first.properties["static_value_binding"] == again.properties["static_value_binding"]
    assert first.properties["static_value_binding"] != rotated.properties["static_value_binding"]
    exported = first.model_dump_json()
    assert KEY not in exported and "Summer2024!" not in exported


def test_keyed_bom_fails_closed_when_validated_without_its_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root, output, _ = _baseline(tmp_path)
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV)
    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, OTHER_KEY)
    run = _validate(root, output)
    assert run.exit_code == 1, run.output


def test_short_source_binding_key_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "too-short")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"db": _db("x")}}))
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [KEY_FAILURE]
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert "static_value_binding" not in server.properties


def _servers(result) -> dict[str, MCPServerComponent]:
    return {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}


@pytest.mark.parametrize("key", ["too-short", "ab" * 32])
def test_mcp_invalid_key_is_one_failure_and_keeps_servers_unbound(tmp_path, monkeypatch, key):
    config = {
        "mcpServers": {
            "notes": {
                "command": "npx",
                "args": ["-y", "notes@1.0.0"],
                "tools": [{"name": "read_note", "description": "Read a note"}],
            },
            "tickets": {"url": "https://mcp.example.com/mcp"},
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [KEY_FAILURE]
    servers = _servers(result)
    assert set(servers) == {"notes", "tickets"}
    assert not any("static_value_binding" in s.properties for s in servers.values())
    assert [c.name for c in result.components if isinstance(c, ToolComponent)] == ["read_note"]


def test_mcp_invalid_key_is_not_reported_without_servers(tmp_path, monkeypatch):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {}}))
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "too-short")
    assert MCPScanner().scan(tmp_path).scan_failures == []


@pytest.mark.parametrize(
    ("relative", "content"),
    [
        (
            ".mcp.json",
            '{"mcpServers": {"bad": {"command": "node", "args": ["s.js"], "env": {"T": "\\ud800"}},'
            ' "good": {"command": "node", "args": ["s.js"]}}}',
        ),
        (
            ".codex/config.toml",
            '[mcp_servers.bad]\ncommand = "node"\n[mcp_servers.bad.tools.t]\n'
            "output_token_limit = 9007199254740993\n"
            '[mcp_servers.good]\ncommand = "node"\n',
        ),
        (
            ".codex/config.toml",
            '[mcp_servers.bad]\ncommand = "node"\nstartup_timeout_sec = inf\n'
            '[mcp_servers.good]\ncommand = "node"\n',
        ),
    ],
    ids=["json-lone-surrogate", "toml-integer-beyond-2^53", "toml-infinity"],
)
def test_mcp_values_outside_i_json_are_a_distinct_binding_failure(
    tmp_path, monkeypatch, relative, content
):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / relative).write_text(content)
    assert set(_servers(MCPScanner().scan(tmp_path))) == {"bad", "good"}
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [
        f"{relative}: MCP server declaration cannot be canonicalized for binding"
    ]
    assert set(_servers(result)) == {"good"}


def test_mcp_redaction_work_is_bounded(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    config = {
        "mcpServers": {
            "wide": {
                "command": "node",
                "args": ["s.js"],
                "env": {f"k{i}": f"v{i}" for i in range(3000)},
                "tools": [
                    {
                        "name": "t",
                        "description": "d",
                        "inputSchema": {
                            "type": "object",
                            "required": [f"r{j}" for j in range(3000)],
                        },
                    }
                ],
            },
            "other": {"command": "node", "args": ["s.js"]},
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    started = time.monotonic()
    result = MCPScanner().scan(tmp_path)
    assert time.monotonic() - started < 5
    assert result.scan_failures == ["MCP configuration: MCP server redaction work limit exceeded"]
    assert set(_servers(result)) == {"other"}


def test_long_strings_count_toward_mcp_redaction_work(tmp_path, monkeypatch):
    # Each secret check scans the whole string, so one long description is costly.
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    config = {
        "mcpServers": {
            "wide": {
                "command": "node",
                "args": ["s.js"],
                "env": {f"k{i}": f"v{i}" for i in range(20_000)},
                "tools": [{"name": "t", "description": "x" * (1 << 20)}],
            },
            "other": {"command": "node", "args": ["s.js"]},
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    started = time.monotonic()
    result = MCPScanner().scan(tmp_path)
    assert time.monotonic() - started < 5
    assert result.scan_failures == ["MCP configuration: MCP server redaction work limit exceeded"]
    assert set(_servers(result)) == {"other"}


def test_ordinary_mcp_configuration_is_within_the_redaction_budget(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    servers = {
        f"server{s}": {
            "command": "npx",
            "args": ["-y", f"server-{s}@1.0.0"],
            "env": {f"TOKEN_{e}": f"secret-value-{s}-{e}-abcdef" for e in range(10)},
            "tools": [
                {
                    "name": f"tool_{t}",
                    "description": "Read a file from the workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {f"p{p}": {"type": "string"} for p in range(8)},
                    },
                }
                for t in range(50)
            ],
        }
        for s in range(20)
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    assert len(_servers(result)) == 20


@pytest.mark.parametrize(
    "launcher",
    [
        ["uvx", "--from", "docs-server==1.2.3", "--index-url", "{index}", "docs-server"],
        ["pipx", "run", "--spec", "docs-server==1.2.3", "--index-url", "{index}", "docs-server"],
    ],
)
def test_unkeyed_binding_detects_package_index_swaps(tmp_path, monkeypatch, launcher):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)

    def server(index: str) -> MCPServerComponent:
        args = [part.format(index=index) for part in launcher[1:]]
        return _server(tmp_path, {"command": launcher[0], "args": args})

    trusted = server("https://pypi.internal.test/simple")
    swapped = server("https://evil.test/simple")
    assert trusted.properties["static_config_hash"] != swapped.properties["static_config_hash"]


def test_unkeyed_binding_ignores_index_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)

    def server(password: str) -> MCPServerComponent:
        index = f"https://ci:{password}@pypi.internal.test/simple?token={password}"
        args = ["--from", "docs-server==1.2.3", "--index-url", index, "docs-server"]
        return _server(tmp_path, {"command": "uvx", "args": args})

    first = server("Summer2024!")
    second = server("Winter2025x")
    assert first.properties["static_config_hash"] == second.properties["static_config_hash"]
    assert "Summer2024!" not in first.model_dump_json()
