"""Parenthesized tool patterns only apply where the client used literal-name fallback."""

import pytest

from tests.test_steering_mcp_names import _surfaces


@pytest.mark.parametrize(
    ("name", "rule", "denied"),
    [
        ("filesystem", "mcp__filesystem(*)", False),
        ("filesystem", "mcp__filesystem__*(*)", False),
        ("filesystem", "mcp__filesystem__*", True),
        ("filesystem", "mcp__filesystem", True),
        ("my__srv", "mcp__my__srv", False),
        ("my__srv", "mcp__my", True),
        ("__filesystem", "mcp____filesystem", False),
    ],
)
def test_a_whole_server_denial_must_be_valid_for_every_tool(tmp_path, name, rule, denied):
    (surface,) = _surfaces(tmp_path, [name], {"defaultMode": "bypassPermissions", "deny": [rule]})
    assert surface["deny_covered"] is denied
    assert surface["writable"] is not denied


@pytest.mark.parametrize(
    ("name", "rule", "writable"),
    [
        ("filesystem", "mcp__filesystem__write_file(*)", False),
        ("filesystem", "mcp__filesystem__write_file", True),
        ("__filesystem", "mcp____filesystem__write_file(*)", True),
    ],
)
def test_only_the_literal_fallback_accepts_an_unconditional_call_suffix(
    tmp_path, name, rule, writable
):
    (surface,) = _surfaces(tmp_path, [name], {"defaultMode": "default", "allow": [rule]})
    assert surface["writable"] is writable
