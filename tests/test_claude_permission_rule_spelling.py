"""The static approval verdict follows Claude's spelling and wildcard rules."""

import pytest

from tests.test_steering_mcp_names import _surfaces


@pytest.mark.parametrize("padding", [" ", "\t", "\n", "\u3000"])
@pytest.mark.parametrize("side", ["left", "right"])
@pytest.mark.parametrize("decision", ["allow", "deny"])
def test_a_padded_rule_does_not_change_the_approval_mode(tmp_path, padding, side, decision):
    rule = "mcp__filesystem"
    padded = padding + rule if side == "left" else rule + padding
    mode = "bypassPermissions" if decision == "deny" else "default"
    (surface,) = _surfaces(tmp_path, ["filesystem"], {"defaultMode": mode, decision: [padded]})
    assert surface["approval_status"] == ("preapproved" if decision == "deny" else "prompting")
    assert not surface["deny_covered"]


@pytest.mark.parametrize(
    "rule,expected",
    [
        ("mcp__filesystem", "preapproved"),
        ("mcp__filesystem__write*", "preapproved"),
        ("mcp__filesystem__*file", "preapproved"),
        ("mcp__filesystem__*", "preapproved"),
        ("mcp__filesystem*", "prompting"),
        ("mcp__*", "prompting"),
        ("mcp__files*", "prompting"),
        ("mcp__other*", "prompting"),
        ("mcp__filesystem2*", "prompting"),
        ("m*", "prompting"),
        ("*", "prompting"),
        ("*__write_file", "prompting"),
        ("mcp__*__write_file", "prompting"),
        ("mcp__*__write_file(condition)", "prompting"),
        ("mcp__filesystem__write_file(condition)", "prompting"),
    ],
)
def test_allow_globs_apply_only_in_the_tool_position(tmp_path, rule, expected):
    (surface,) = _surfaces(tmp_path, ["filesystem"], {"defaultMode": "default", "allow": [rule]})
    assert surface["approval_status"] == expected


@pytest.mark.parametrize(
    "name,prefix",
    [
        ("claude.ai filesystem.", "claude_ai_filesystem"),
        ("claude.ai Filesystem (repo)", "claude_ai_Filesystem_repo"),
    ],
)
def test_managed_connector_allow_uses_the_runtime_namespace(tmp_path, name, prefix):
    perms = {"defaultMode": "default", "allow": [f"mcp__{prefix}__write_file"]}
    (surface,) = _surfaces(tmp_path, [name], perms)
    assert surface["approval_status"] == "preapproved"


@pytest.mark.parametrize(
    "rule",
    ["mcp__claude_ai_filesystem_", " mcp__claude_ai_filesystem", "mcp__claude_ai_filesystem\t"],
)
def test_only_the_whole_managed_connector_namespace_can_be_denied(tmp_path, rule):
    (surface,) = _surfaces(
        tmp_path, ["claude.ai filesystem."], {"defaultMode": "bypassPermissions", "deny": [rule]}
    )
    assert not surface["deny_covered"] and surface["writable"]


@pytest.mark.parametrize("name", ["reports__v2", "reports_"])
@pytest.mark.parametrize("suffix,status", [("", "prompting"), ("__*", "preapproved")])
def test_ambiguous_server_names_use_their_whole_qualified_address(tmp_path, name, suffix, status):
    (surface,) = _surfaces(
        tmp_path, [name], {"defaultMode": "default", "allow": ["mcp__" + name + suffix]}
    )
    assert surface["approval_status"] == status
