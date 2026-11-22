"""Adversarial regression tests for PR #330 local settings overrides on steering surfaces."""

from __future__ import annotations

import json
from pathlib import Path

from nexus_symbiote.control_plane_audit import audit_project_control_plane


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_local_settings_deny_cannot_suppress_committed_writable_steering_surface(
    tmp_path: Path,
) -> None:
    _write_json(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
                }
            }
        },
    )
    _write_json(
        tmp_path / ".claude/settings.json",
        {"permissions": {"defaultMode": "bypassPermissions"}},
    )
    _write_json(
        tmp_path / ".claude/settings.local.json",
        {"permissions": {"deny": ["mcp__*"]}},
    )

    summary = audit_project_control_plane(tmp_path)
    (surface,) = summary.steering_surfaces
    assert surface["deny_covered"] is False
    assert surface["writable"] is True
    assert any(f["category"] == "steering_surface_writable" for f in summary.findings)


def test_local_settings_default_mode_cannot_suppress_unverified_steering_surface(
    tmp_path: Path,
) -> None:
    _write_json(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
                }
            }
        },
    )
    _write_json(
        tmp_path / ".claude/settings.local.json",
        {"permissions": {"defaultMode": "default"}},
    )

    summary = audit_project_control_plane(tmp_path)
    (surface,) = summary.steering_surfaces
    assert surface["approval_status"] == "unverified"
    assert any(f["category"] == "steering_surface_unverified" for f in summary.findings)
