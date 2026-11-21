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
