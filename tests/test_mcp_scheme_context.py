"""Check typed authentication operands and public selectors in static inventory exports."""

import hashlib
import json

import pytest

from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from tests.test_mcp_redaction_boundaries import _echo, _scan


def exports(inventory):
    return (
        inventory.to_json(),
        json.dumps(CycloneDXGenerator().generate(inventory)),
        json.dumps(SPDXGenerator().generate(inventory)),
    )


def has_exposure(result):
    return any(
        risk.category == "credential_exposure" and risk.severity == "high"
        for component in result.components
        for risk in component.risks
    )


DIGEST = hashlib.sha256(b"public generated scanner fixture").hexdigest()
NUMBER = str(int(DIGEST[:16], 16))
DASH_WORD = "--" + "".join(chr(97 + int(c, 16)) for c in DIGEST[:24])


@pytest.mark.parametrize(
    ("name", "operand"),
    [
        ("AUTH_TYPE", DIGEST[:28]),
        ("authMode", DIGEST[:28]),
        ("TYPE", DIGEST[:28]),
        ("CONN", NUMBER),
        ("API_TOKEN", DASH_WORD),
        ("API_TOKEN", "part=" + DIGEST[:22]),
    ],
)
def test_authentication_operands_are_withheld_across_exports(tmp_path, name, operand):
    source = {"command": "node", "args": [f"--env={name}=Bearer", operand]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(operand)})
    assert has_exposure(result)
    assert all(operand not in document for document in exports(inventory))


@pytest.mark.parametrize(
    ("selector", "public"),
    [
        ("--format", "OpenAPI3"),
        ("--source", "18ac72c8-1813-4200-9ff1-a800cbcda102"),
        ("PROFILE", "WorkspaceV2"),
    ],
)
def test_public_selection_does_not_redact_a_sibling_description(tmp_path, selector, public):
    config = {"command": "node", "args": [selector + "=token", public]}
    result, inventory = _scan(tmp_path, {"source": config, "sibling": _echo(public)})
    assert not has_exposure(result)
    assert all(public in document for document in exports(inventory))


@pytest.mark.parametrize(
    "field", ["oauth", "auth", "headers", "named-header", "env-authz", "env-auth"]
)
def test_refused_credential_fields_protect_sibling_exports(tmp_path, field):
    marker = DIGEST[:28]
    value = {"value": marker}
    if field == "named-header":
        extra = {"headers": [{"name": "CONN", **value}]}
    elif field.startswith("env-"):
        extra = {"env": {field[4:].upper(): value}}
    else:
        extra = {field: [value]}
    bad = {"command": "node", "args": [0], **extra}
    result, inventory = _scan(tmp_path, {"refused": bad, "sibling": _echo(marker)})
    assert result.scan_failures and inventory.components
    assert all(marker not in document for document in exports(inventory))
