"""Preserve credential context in malformed declarative fields and avoid flagging locators."""

import hashlib
import json

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanners.mcp import MCPScanner, _assignment_word_hits, _malformed_values
from tests.test_mcp_redaction_boundaries import _echo, _scan


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("AUTH_TYPE", "example.test/public/tool:v1.0"),
        ("AUTH_SCHEME", "--port=8080"),
        ("--auth", "./config/server.json"),
        ("--auth", "http://localhost:8080/mcp"),
        ("DISPLAY_MODE", "public-choice-1234"),
    ],
)
def test_scheme_settings_and_public_locators_do_not_report_a_credential(field, value):
    assert not _assignment_word_hits(field + "=bearer", value)


@pytest.mark.parametrize(
    "label",
    [
        "AUTH_HEADER",
        "AUTHORIZATION_HEADER",
        "BEARER_HEADER",
        "OAUTH",
        "AUTHENTICATION",
        "BOT",
        "SERVICE_AUTHORIZATION",
    ],
)
def test_header_carrying_assignments_retain_real_scheme_evidence(label):
    marker = hashlib.sha256(b"public mock header value").hexdigest()[:32]
    assert any(value == marker for _, value in _assignment_word_hits(label + "=Bearer", marker))


@pytest.mark.parametrize("layout", ["pair", "named", "nested", "pw", "argv", "opencode"])
def test_malformed_field_context_protects_a_public_marker_in_the_sibling(tmp_path, layout):
    marker = hashlib.sha256(b"public mock field value").hexdigest()[:32]
    cases = {
        "pair": {"env": [["API_TOKEN", marker]]},
        "named": {"headers": [{"name": "Authorization", "value": marker}]},
        "nested": {"env": {"API_TOKEN": {"value": marker}}},
        "pw": {"env": {"entry": {"pw": marker}}},
        "argv": {"command": ["node", "--pat", marker]},
    }
    if layout == "opencode":
        bad = {"type": "local", "command": ["node", 5, "--api-key=" + marker]}
        good = {"type": "local", "command": ["node"], "tools": _echo(marker)["tools"]}
        (tmp_path / "opencode.json").write_text(json.dumps({"mcp": {"bad": bad, "good": good}}))
        result = MCPScanner().scan(tmp_path)
        inventory = AIBOM(components=result.components)
    else:
        result, inventory = _scan(
            tmp_path, {"bad": {"command": "node", **cases[layout]}, "good": _echo(marker)}
        )
    assert result.scan_failures and inventory.components
    assert marker not in inventory.to_json()


def test_nested_name_value_pairs_are_visited_once():
    value = hashlib.sha256(b"public mock leaf").hexdigest()[:32]
    nested = value
    for _ in range(100):
        nested = ["API_TOKEN", nested]
    assert list(_malformed_values(nested)).count(value) == 1
