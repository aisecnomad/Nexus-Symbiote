"""A split credential and an unrelated CLI option have different export behavior."""

import hashlib
import json

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import UNBOUND_VALUES_DETAIL, MCPServerComponent
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.scanners.mcp import MCPScanner
from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure

PUBLIC_DIGEST = hashlib.sha256(b"public generated operand fixture").hexdigest()
LETTERS = "".join(chr(97 + int(digit, 16)) for digit in PUBLIC_DIGEST[:20])
DIGITS = str(int(PUBLIC_DIGEST[:15], 16))


@pytest.mark.parametrize(
    "operand",
    [
        "--" + LETTERS.upper(),
        "--" + LETTERS.capitalize(),
        "--" + LETTERS[:6] + "_" + LETTERS[6:],
        "--part=" + PUBLIC_DIGEST[:20],
        "+" + DIGITS,
        DIGITS[:8] + "." + DIGITS[8:],
    ],
)
@pytest.mark.parametrize("layout", ["array", "shell-text", "cmd-text"])
def test_secret_assignment_operands_stay_out_of_exports(tmp_path, operand, layout):
    if layout == "array":
        command, args = "node", ["--env=API_TOKEN=Bearer", operand]
    elif layout == "shell-text":
        command, args = "sh", ["-c", "node notes.js --env=API_TOKEN=Bearer " + operand]
    else:
        command, args = "cmd", ["/c", "set API_TOKEN=Bearer " + operand]
    result, inventory = _scan(
        tmp_path, {"reader": {"command": command, "args": args}, "notes": _echo(operand)}
    )
    assert has_exposure(result)
    assert all(
        operand not in text
        for text in (*exports(inventory), json.dumps(SARIFGenerator().generate(inventory)))
    )


@pytest.mark.parametrize(
    ("assignment", "next_arg"),
    [
        ("--auth-type=bearer", "--transport"),
        ("--auth=bearer", "--stateless"),
        ("--auth-type=bearer", "PORT=8080"),
        ("AUTH_MODE=token", "--privileged"),
        ("--output-format=token", "OpenAPI3"),
        ("--token-source=token", "WorkspaceV2"),
        ("--kind=token", "OpenAPI3"),
        ("--token-format=token", "OpenAPI3"),
    ],
)
def test_ordinary_cli_options_remain_visible(tmp_path, assignment, next_arg):
    result, inventory = _scan(
        tmp_path,
        {"reader": {"command": "node", "args": [assignment, next_arg]}, "notes": _echo(next_arg)},
    )
    assert not has_exposure(result)
    assert all(next_arg in text for text in exports(inventory))


@pytest.mark.parametrize("field", ["headers", "auth", "oauth", "http_headers", "named-session"])
@pytest.mark.parametrize("package", ["mcp-server-fetch", "document-reader-tools"])
def test_refused_metadata_keeps_public_sibling_launch_identity(tmp_path, field, package):
    entry = (
        {"name": "X-Session", "value": package} if field == "named-session" else {"value": package}
    )
    key = "headers" if field == "named-session" else field
    refused = {"command": "node", "args": [0], key: [entry]}
    result, inventory = _scan(
        tmp_path, {"invalid": refused, "reader": {"command": "uvx", "args": [package]}}
    )
    assert result.scan_failures
    server = next(
        c for c in inventory.components if isinstance(c, MCPServerComponent) and c.name == "reader"
    )
    assert package in server.model_dump_json()
    assert not any(UNBOUND_VALUES_DETAIL in r.detail for r in server.risks)


def test_nested_refused_credential_field_protects_a_sibling(tmp_path):
    value = PUBLIC_DIGEST[:28]
    refused = {"command": "node", "args": [0], "env": {"API_KEY": {"v": value}}}
    result, inventory = _scan(tmp_path, {"invalid": refused, "reader": _echo(value)})
    assert result.scan_failures
    assert all(value not in text for text in exports(inventory))


@pytest.mark.parametrize(
    ("path", "field"),
    [
        (".cursor/mcp.json", "mcpServers"),
        (".vscode/mcp.json", "servers"),
        (".gemini/settings.json", "mcpServers"),
        (".zed/settings.json", "context_servers"),
        (".codex/config.toml", "mcp_servers"),
    ],
)
def test_client_configs_preserve_the_same_scheme_evidence(tmp_path, path, field):
    marker = "--" + LETTERS.upper()
    args = ["--env=API_TOKEN=Bearer", marker]
    source = tmp_path / path
    source.parent.mkdir()
    if source.suffix == ".toml":
        text = f'[{field}.reader]\ncommand="node"\nargs={json.dumps(args)}\n'
    else:
        text = json.dumps({field: {"reader": {"command": "node", "args": args}}})
    source.write_text(text)
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    assert has_exposure(result)
    assert all(marker not in document for document in exports(AIBOM(components=result.components)))
