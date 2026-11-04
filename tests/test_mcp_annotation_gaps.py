"""A tool's own annotations can raise its side-effect profile, never lower it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import SideEffectProfile
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner

DESTRUCTIVE_TOOL = {
    "name": "delete_all_files",
    "description": "Deletes every file in the workspace",
}
SELF_DECLARED_SAFE = {"readOnlyHint": True, "destructiveHint": False}


def write_project(project: Path, tool: dict) -> None:
    server = {"command": "npx", "args": ["-y", "pkg@1.2.3"], "tools": [tool]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))


def scan_tool(project: Path, name: str, annotations: dict) -> ToolComponent:
    write_project(project, {"name": name, "description": "", "annotations": annotations})
    result = MCPScanner().scan(project)
    assert not result.scan_failures
    return next(c for c in result.components if isinstance(c, ToolComponent))


def profile(tool: ToolComponent) -> SideEffectProfile:
    assert tool.capabilities is not None
    return tool.capabilities.side_effect_profile


@pytest.mark.parametrize(
    "name,annotations,expected",
    [
        ("delete_all_files", SELF_DECLARED_SAFE, SideEffectProfile.DESTRUCTIVE),
        ("delete_all_files", {"readOnlyHint": True}, SideEffectProfile.DESTRUCTIVE),
        ("drop_table", {"readOnlyHint": 1}, SideEffectProfile.DESTRUCTIVE),
        ("create_issue", SELF_DECLARED_SAFE, SideEffectProfile.STATE_MODIFYING),
        ("frobnicate", SELF_DECLARED_SAFE, SideEffectProfile.UNKNOWN),
        ("read_file", SELF_DECLARED_SAFE, SideEffectProfile.READ_ONLY),
    ],
)
def test_self_declared_hints_never_lower_the_inferred_profile(
    tmp_path, name, annotations, expected
):
    assert profile(scan_tool(tmp_path, name, annotations)) == expected


@pytest.mark.parametrize(
    "name,annotations",
    [
        ("read_file", {"destructiveHint": True}),
        ("frobnicate", {"destructiveHint": True}),
        ("create_issue", {"readOnlyHint": True, "destructiveHint": True}),
    ],
)
def test_declared_destructive_hint_still_raises_the_profile(tmp_path, name, annotations):
    tool = scan_tool(tmp_path, name, annotations)
    assert profile(tool) == SideEffectProfile.DESTRUCTIVE
    assert any(r.category == "capability_scope" for r in tool.risks)


def test_read_only_hint_keeps_the_destructive_finding(tmp_path):
    plain = scan_tool(tmp_path, "delete_all_files", {})
    hinted = scan_tool(tmp_path, "delete_all_files", SELF_DECLARED_SAFE)
    assert [(r.severity.value, r.category, r.detail) for r in hinted.risks] == [
        (r.severity.value, r.category, r.detail) for r in plain.risks
    ]
    assert ("high", "capability_scope") in {(r.severity.value, r.category) for r in hinted.risks}
    assert hinted.annotations == SELF_DECLARED_SAFE


def test_read_only_hint_does_not_lower_the_risk_score(tmp_path):
    runner = CliRunner()
    scores = {}
    for label, tool in (
        ("plain", DESTRUCTIVE_TOOL),
        ("hinted", {**DESTRUCTIVE_TOOL, "annotations": SELF_DECLARED_SAFE}),
    ):
        project = tmp_path / label
        project.mkdir()
        write_project(project, tool)
        bom = tmp_path / f"{label}.json"
        scan = runner.invoke(
            main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(bom)]
        )
        assert scan.exit_code == 0, scan.output
        risk = runner.invoke(
            main,
            ["risk", str(bom), "--project", str(project), "--no-project-policy", "--json-output"],
        )
        report = json.loads(risk.stdout)
        assert report["assessment_basis"] == "project-reconciled"
        scores[label] = report["overall_score"]
    assert scores == {"plain": 11.0, "hinted": 11.0}
