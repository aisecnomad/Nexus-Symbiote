"""Read synthetic permission declarations without starting an MCP server."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote import control_plane_audit
from nexus_symbiote.cli import main
from tests.test_steering_mcp_names import _surfaces


@pytest.mark.parametrize(
    ("name", "rule", "covered"),
    [
        ("reports", "m*", False),
        ("reports", "mc*", False),
        ("reports", "mcp*", False),
        ("reports", "Mcp*", False),
        ("reports", "mcp__*", True),
        ("reports", "*(*)", True),
        ("reports", "mcp_*(*)", True),
        ("reports", "mcp*(*)", False),
        ("reports", "mcp__reports(*)", False),
        ("reports_", "mcp__reports_", True),
        ("my__reports", "mcp__my__reports", True),
        ("__reports", "mcp____reports", True),
        ("__reports", "mcp____reports(*)", True),
        ("reports", "mcp__*__*", True),
        ("reports", "*__*", True),
        ("reports", "*ports__*", True),
        ("reports", "mcp__reports__**", True),
        ("reports", "mcp__*__list*", False),
        ("reports", "*ports__detail*", False),
        ("reports", "mcp__reports__*suffix", False),
        ("logs", "*ports__*", False),
        ("a__b__c", "mcp__a__b", False),
        ("reports", "MCP__reports", False),
        ("Reports", "mcp__reports", False),
        ("", "mcp__", False),
        ("reports", "mcp__reports(foo)", False),
        ("__reports", "mcp____reports(foo)", False),
        ("reports", "mcp__*(*)", False),
    ],
)
def test_only_a_valid_whole_namespace_deny_covers_a_write_capable_server(
    tmp_path, name, rule, covered
):
    (surface,) = _surfaces(tmp_path, [name], {"defaultMode": "acceptEdits", "deny": [rule]})
    assert surface["deny_covered"] is covered
    assert surface["approval_status"] == ("denied" if covered else "preapproved")
    assert surface["writable"] is (not covered)


@pytest.mark.parametrize(("rule", "status"), [("mc*", 1), ("mcp__*__*", 0)])
def test_public_gate_reports_the_same_permission_decision(tmp_path, rule, status):
    _surfaces(tmp_path, ["reports"], {"defaultMode": "acceptEdits", "deny": [rule]})
    gate = CliRunner().invoke(
        main,
        ["audit-control-plane", str(tmp_path), "--json-output", "--fail-on-severity", "critical"],
    )
    assert gate.exit_code == status, gate.output
    categories = {item["category"] for item in json.loads(gate.stdout)["security_flags"]}
    assert ("steering_surface_writable" in categories) == bool(status)


def test_unfinished_glob_comparison_preserves_evidence_and_exact_matches(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane_audit, "_CLAUDE_DENY_GLOB_WORK", 0)
    surfaces = _surfaces(
        tmp_path,
        ["reports", "logs"],
        {"defaultMode": "acceptEdits", "deny": ["*ports__*", "mcp__logs"]},
    )
    assert {s["server_name"]: s["approval_status"] for s in surfaces} == {
        "reports": "preapproved",
        "logs": "denied",
    }
    summary = control_plane_audit.audit_project_control_plane(tmp_path)
    assert any("wildcard comparison limit" in gap for gap in summary.gaps)
