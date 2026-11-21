"""Compare Claude permission rules with the tool address derived from an MCP server name."""

import json

import pytest

from nexus_symbiote.control_plane_audit import audit_project_control_plane


def _surfaces(project, names, permissions):
    servers = {name: {"command": "node", "args": ["server-filesystem", "."]} for name in names}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    settings = project / ".claude"
    settings.mkdir()
    (settings / "settings.json").write_text(json.dumps({"permissions": permissions}))
    return audit_project_control_plane(project).steering_surfaces


@pytest.mark.parametrize(
    "name,tool_id",
    [
        ("files.repo", "files_repo"),
        ("files repo", "files_repo"),
        ("files@repo", "files_repo"),
        ("files\U0001f4c1repo", "files__repo"),
    ],
)
def test_normalized_mcp_tool_address_counts_as_preapproved(tmp_path, name, tool_id):
    perms = {"defaultMode": "default", "allow": [f"mcp__{tool_id}__write_file"]}
    (surface,) = _surfaces(tmp_path, [name], perms)
    assert surface["writable"] and surface["approval_status"] == "preapproved"


@pytest.mark.parametrize(
    "rule,covered",
    [
        ("mcp__files_repo", True),
        ("mcp__files_repo__*", True),
        ("mcp__files.repo", False),
        ("mcp__files_repo__write_file", False),
    ],
)
def test_only_a_whole_runtime_namespace_can_establish_deny_coverage(tmp_path, rule, covered):
    perms = {"defaultMode": "bypassPermissions", "deny": [rule]}
    (surface,) = _surfaces(tmp_path, ["files.repo"], perms)
    assert surface["deny_covered"] is covered
    assert surface["writable"] is (not covered)


def test_an_allowance_covers_each_server_sharing_the_same_tool_namespace(tmp_path):
    perms = {"defaultMode": "default", "allow": ["mcp__files_repo__write_file"]}
    surfaces = _surfaces(tmp_path, ["files.repo", "files_repo"], perms)
    assert len(surfaces) == 2
    assert all(surface["writable"] for surface in surfaces)


@pytest.mark.parametrize(
    "rule", ["mcp__filesystem*", "mcp__*", "mcp__files*", "mcp__filesystem__write*", "m*"]
)
def test_prefix_globs_cover_the_runtime_tool_namespace(tmp_path, rule):
    (surface,) = _surfaces(tmp_path, ["filesystem"], {"defaultMode": "default", "allow": [rule]})
    assert surface["approval_status"] == "preapproved"


@pytest.mark.parametrize(
    "rule,expected",
    [
        ("mcp__other*", "prompting"),
        ("mcp__filesystem2*", "prompting"),
        ("mcp__*__write_file", "preapproved"),
        ("*__write_file", "preapproved"),
        ("mcp__*__write_file(condition)", "unverified"),
    ],
)
def test_only_intersecting_unresolved_globs_leave_approval_unknown(tmp_path, rule, expected):
    (surface,) = _surfaces(tmp_path, ["filesystem"], {"defaultMode": "default", "allow": [rule]})
    assert surface["approval_status"] == expected


@pytest.mark.parametrize(
    "name,normalized",
    [
        ("claude.ai filesystem.", "claude_ai_filesystem"),
        ("claude.ai Filesystem (repo)", "claude_ai_Filesystem_repo"),
    ],
)
def test_managed_connector_names_follow_the_client_namespace(tmp_path, name, normalized):
    perms = {"defaultMode": "default", "allow": [f"mcp__{normalized}__write_file"]}
    (surface,) = _surfaces(tmp_path, [name], perms)
    assert surface["approval_status"] == "preapproved"


def test_extra_underscore_cannot_grant_deny_coverage_for_a_managed_connector(tmp_path):
    (surface,) = _surfaces(
        tmp_path,
        ["claude.ai filesystem."],
        {"defaultMode": "bypassPermissions", "deny": ["mcp__claude_ai_filesystem_"]},
    )
    assert not surface["deny_covered"] and surface["writable"]
