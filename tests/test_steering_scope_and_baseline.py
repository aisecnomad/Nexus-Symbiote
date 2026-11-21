"""CLI steering, host-scoped rules and incomplete baselines."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.control_plane_audit import audit_project_control_plane
from tests.test_control_plane_audit import _fs_project, _write


@pytest.mark.parametrize(
    ("mode", "allow", "status"),
    [
        (None, [], "unverified"),
        ("default", [], "prompting"),
        ("plan", [], "prompting"),
        ("default", ["mcp__fs"], "preapproved"),
        ("plan", ["mcp__fs__*"], "preapproved"),
        ("default", ["mcp__fs__write_file"], "preapproved"),
        ("default", ["mcp__fs_backup__write_file"], "prompting"),
    ],
)
def test_steering_distinguishes_prompting_from_preapproval(
    tmp_path: Path, mode: str | None, allow: list[str], status: str
) -> None:
    _fs_project(tmp_path, [], ["."])
    _write(
        tmp_path / ".claude/settings.json",
        json.dumps({"permissions": {"defaultMode": mode, "allow": allow}}),
    )
    summary = audit_project_control_plane(tmp_path)
    [surface] = summary.steering_surfaces
    assert surface["approval_status"] == status
    assert surface["writable"] == (status == "preapproved")
    assert summary.gaps == []

    args = ["audit-control-plane", str(tmp_path)]
    default = CliRunner().invoke(main, args)
    assert default.exit_code == (1 if status == "preapproved" else 0), default.output
    if status == "unverified":
        strict = CliRunner().invoke(main, [*args, "--fail-on-severity", "medium"])
        assert strict.exit_code == 1, strict.output
        assert "steering_surface_unverified" in strict.output


def test_steering_rules_are_host_scoped_and_allow_arguments_stay_private(tmp_path):
    marker = "filesystem-private-fixture"
    _write(
        tmp_path / ".claude/settings.json",
        json.dumps({"permissions": {"deny": ["mcp__filesystem__*"], "allow": [marker]}}),
    )
    _write(
        tmp_path / ".cursor/mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "custom-filesystem",
                        "args": [".", "--read-only-hint"],
                        "readOnly": "false",
                        "autoApprove": True,
                    }
                }
            }
        ),
    )
    _write(
        tmp_path / ".mcp.json",
        json.dumps({"mcpServers": {"filesystem": {"command": "custom-filesystem", "args": ["."]}}}),
    )
    summary = audit_project_control_plane(tmp_path)
    surfaces = {s["source_file"]: s for s in summary.steering_surfaces}
    assert surfaces[".cursor/mcp.json"]["writable"]
    assert surfaces[".mcp.json"]["deny_covered"]
    assert marker not in json.dumps(summary.to_dict())


def test_partial_or_wrong_shape_claims_and_baselines_are_visible(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    baseline = tmp_path / "baseline"
    _write(baseline / ".mcp.json", "[]")
    claims = tmp_path / "claims.json"
    claims.write_bytes(b"{}" + b" " * 4_194_304)
    report = audit_project_control_plane(project, baseline_root=baseline, claims_path=claims)
    assert any("baseline:" in gap for gap in report.gaps)
    assert any("claims" in gap for gap in report.gaps)


@pytest.mark.parametrize("config", [".cursor/mcp.json", ".vscode/mcp.json", "mcp.json"])
def test_claude_mode_cannot_preapprove_a_server_owned_by_another_client(tmp_path, config):
    _write(
        tmp_path / ".claude/settings.json",
        json.dumps({"permissions": {"defaultMode": "acceptEdits"}}),
    )
    _write(
        tmp_path / config,
        json.dumps({"mcpServers": {"filesystem": {"command": "example", "args": ["."]}}}),
    )
    summary = audit_project_control_plane(tmp_path)
    (surface,) = summary.steering_surfaces
    assert surface["approval_status"] == "unverified" and not surface["writable"]
    assert any(item["category"] == "steering_surface_unverified" for item in summary.findings)
