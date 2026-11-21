"""Redaction invariants shared by sibling records and inventory formats."""

import base64
import hashlib
import json
import textwrap
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import UNBOUND_VALUES_DETAIL, MCPServerComponent
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.scanners.mcp import MCPScanner


def _scan(root: Path, servers: dict):
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    result = MCPScanner().scan(root)
    return result, AIBOM(components=result.components)


def _echo(text: str) -> dict:
    return {
        "command": "node",
        "tools": [{"name": "lookup", "description": f"Fixture echo: {text}"}],
    }


@pytest.mark.parametrize("columns", [64, 76])
@pytest.mark.parametrize("padding", ["\n", "\u00a0", "\u2028"])
def test_encoded_key_redaction_survives_formatting_in_sibling_exports(tmp_path, columns, padding):
    # The schema marker exercises the decoder without creating or storing any key material.
    public_document = json.dumps({"private_key": "This is public example text. " * 4})
    encoded = base64.b64encode(public_document.encode()).decode()
    wrapped = "\n".join(textwrap.wrap(encoded, columns))
    value = padding + wrapped + padding
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "node", "env": {"SERVICE_CONFIG": value}},
            "sibling": _echo(f"{value} | {wrapped} | {encoded}"),
        },
    )
    assert not result.scan_failures
    assert any(
        risk.category == "credential_exposure" and risk.severity == RiskSeverity.HIGH
        for component in result.components
        for risk in component.risks
    )
    for exported in (
        inventory.model_dump_json(),
        json.dumps(CycloneDXGenerator().generate(inventory)),
        json.dumps(SPDXGenerator().generate(inventory)),
    ):
        assert "Fixture echo:" in exported
        assert encoded[:40] not in exported


@pytest.mark.parametrize("field", ["args", "command", "auth", "oauth", "env", "headers", None])
def test_malformed_field_cannot_publish_its_literal_in_a_sibling(tmp_path, field):
    public_id = hashlib.sha256(b"public scanner regression fixture").hexdigest()[:24]
    fields = {
        "args": f"--api-key {public_id}",
        "command": [f"API_KEY={public_id}"],
        "auth": public_id,
        "oauth": public_id,
        "env": [f"API_KEY={public_id}"],
        "headers": [f"X-Api-Key: {public_id}"],
    }
    invalid = {field: fields[field]} if field is not None else [f"API_KEY={public_id}"]
    result, inventory = _scan(tmp_path, {"invalid": invalid, "sibling": _echo(public_id)})
    assert any("invalid server configuration" in failure for failure in result.scan_failures)
    shown = inventory.model_dump_json()
    assert "Fixture echo:" in shown
    assert public_id not in shown


def test_scheme_selector_and_port_are_distinct_options(tmp_path):
    result, inventory = _scan(
        tmp_path, {"local": {"command": "npx", "args": ["--auth=bearer", "--port=8080"]}}
    )
    assert not result.scan_failures
    assert not any(
        r.category == "credential_exposure" for c in inventory.components for r in c.risks
    )


def test_command_normalized_for_display_is_marked_unbound(tmp_path):
    result, inventory = _scan(tmp_path, {"local": {"command": "mcpserver\u00a0"}})
    assert not result.scan_failures
    server = next(c for c in inventory.components if isinstance(c, MCPServerComponent))
    assert any(
        UNBOUND_VALUES_DETAIL in risk.detail and "command" in risk.detail for risk in server.risks
    )


@pytest.mark.parametrize("assignment,prefix", [("BOT=Bot", ""), ("--env=API_TOKEN=Bearer", "-X")])
def test_scheme_arguments_protect_their_literal_in_siblings(tmp_path, assignment, prefix):
    public_id = prefix + hashlib.sha256(b"public protocol test").hexdigest()[:32]
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "node", "args": [assignment, public_id]},
            "sibling": _echo(public_id),
        },
    )
    assert any(r.category == "credential_exposure" for c in result.components for r in c.risks)
    assert public_id not in inventory.model_dump_json()


@pytest.mark.parametrize("bad_shape", ["arguments", "entry", "environment"])
def test_invalid_public_fields_preserve_a_sibling_package_identity(tmp_path, bad_shape):
    package = "@fixtures/public-tool@1.2.3"
    cases = {
        "arguments": {"command": "npx", "args": ["-y", package, 42]},
        "entry": ["npx", "-y", package],
        "environment": {"command": "node", "env": [f"public-label-{n}" for n in range(4200)]},
    }
    result, _ = _scan(
        tmp_path,
        {"valid": {"command": "npx", "args": ["-y", package]}, "invalid": cases[bad_shape]},
    )
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.package_url == "pkg:npm/%40fixtures/public-tool@1.2.3"


@pytest.mark.parametrize("width,separator", [(76, "\n"), (43, "\r\n")])
def test_same_key_in_a_sibling_with_a_different_line_width(tmp_path, width, separator):
    sample = json.dumps({"private_key": "Public example text only. " * 10})
    encoded = base64.b64encode(sample.encode()).decode()
    source = "\n".join(textwrap.wrap(encoded, 64))
    sibling = separator.join(textwrap.wrap(encoded, width))
    result, inventory = _scan(
        tmp_path,
        {"src": {"command": "node", "env": {"SERVICE_CONFIG": source}}, "copy": _echo(sibling)},
    )
    assert not result.scan_failures
    for rendered in (
        inventory.model_dump_json(),
        json.dumps(CycloneDXGenerator().generate(inventory)),
        json.dumps(SPDXGenerator().generate(inventory)),
    ):
        assert "Fixture echo:" in rendered
        assert encoded[:35] not in rendered


def test_ordinary_ascii_command_padding_preserves_binding(tmp_path):
    _, inventory = _scan(tmp_path, {"local": {"command": "npx "}})
    server = next(c for c in inventory.components if isinstance(c, MCPServerComponent))
    assert not any(
        UNBOUND_VALUES_DETAIL in r.detail and "command" in r.detail for r in server.risks
    )
