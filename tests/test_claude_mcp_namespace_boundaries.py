"""Static MCP permission coverage at namespace boundaries."""

import pytest

from tests.test_steering_mcp_names import _surfaces


@pytest.mark.parametrize("name", ["__filesystem", "..filesystem", "  filesystem", "📁filesystem"])
@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        ("", False),
        ("write_file", True),
        ("write_file(*)", True),
        ("write*", False),
        ("write_file(example)", False),
    ],
)
def test_leading_double_underscore_names_take_literal_tool_allows(tmp_path, name, tool, expected):
    perms = {"defaultMode": "default", "allow": ["mcp____filesystem__" + tool]}
    (surface,) = _surfaces(tmp_path, [name], perms)
    assert surface["writable"] is expected


@pytest.mark.parametrize(
    ("name", "deny", "covered"),
    [
        ("my-fs", "*", True),
        ("my-fs", "mcp__*", True),
        ("my-fs", "mcp__my-fs*", True),
        ("my-fs", "mcp__my-fs__write*", False),
        ("my-fs", "mcp__my-fs2*", False),
        ("my-fs", " mcp__my-fs*", False),
        ("my-fs", "mcp__my-fs* ", False),
        ("fs_", "mcp__fs", True),
        ("my__srv", "mcp__my", True),
        ("__filesystem", "mcp__", False),
    ],
)
def test_only_a_deny_covering_all_tool_names_clears_the_surface(tmp_path, name, deny, covered):
    perms = {"defaultMode": "bypassPermissions", "deny": [deny]}
    (surface,) = _surfaces(tmp_path, [name], perms)
    assert surface["deny_covered"] is covered
    assert surface["writable"] is (not covered)
