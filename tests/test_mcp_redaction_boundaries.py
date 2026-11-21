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
