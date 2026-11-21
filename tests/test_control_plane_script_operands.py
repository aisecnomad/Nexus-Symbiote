"""Repository binding and reporting regressions for the control-plane auditor."""

import hashlib
import json
from pathlib import Path

import pytest

from nexus_symbiote.control_plane_audit import audit_project_control_plane
from tests.test_registry_free_text_redaction import TOKEN


def write(root: Path, name: str, content: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.mark.parametrize(
    ("command", "target", "decoy"),
    [
        (["node", "@hooks/report.js"], "@hooks/report.js", None),
        (["python3", "@service/main.py"], "@service/main.py", None),
        (["npx", "tsx", "hooks/report.ts"], "hooks/report.ts", "tsx"),
        (["uvx", "python", "hooks/report"], "hooks/report", "python"),
        (["npx", "-p", "tsx", "tsx", "hooks/report.ts"], "hooks/report.ts", "tsx"),
        (["uvx", "--from", "toolkit", "python", "hooks/report"], "hooks/report", "toolkit"),
    ],
)
@pytest.mark.parametrize("surface", ["hook", "server"])
def test_bound_target_is_the_execution_operand(
    tmp_path: Path, command: list[str], target: str, decoy: str | None, surface: str
) -> None:
    base, current = tmp_path / "before", tmp_path / "after"
    for root, body in ((base, "previous\n"), (current, "current\n")):
        if surface == "hook":
            write(root, ".claude/hooks.json", json.dumps({"hooks": {"Start": [" ".join(command)]}}))
        else:
            server = {"command": command[0], "args": command[1:]}
            write(root, ".mcp.json", json.dumps({"mcpServers": {"example": server}}))
        if decoy:
            write(root, decoy, "unrelated\n")
        write(root, target, body)

    audit = audit_project_control_plane(current, baseline_root=base)
    targets = audit.hook_targets if surface == "hook" else audit.launcher_targets
    assert [(item["target_path"], item["launch_target_sha256"]) for item in targets] == [
        (target, hashlib.sha256(b"current\n").hexdigest())
    ]
    assert [alert["root_cause"] for alert in audit.reach_alerts] == ["launch_target_changed"]
    assert not audit.gaps


def test_missing_extensionless_runner_script_is_reported(tmp_path: Path) -> None:
    hooks = {"hooks": {"Start": ["npx tsx hooks/report"]}}
    write(tmp_path, ".claude/hooks.json", json.dumps(hooks))
    audit = audit_project_control_plane(tmp_path)
    assert any(f["category"] == "hook_target_missing" for f in audit.findings)


@pytest.mark.parametrize("create_readme", [True, False])
def test_package_directory_operand_is_not_a_script(tmp_path: Path, create_readme: bool) -> None:
    (tmp_path / "docs").mkdir()
    if create_readme:
        write(tmp_path, "docs/readme.md", "Public documentation\n")
    server = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "./docs"]}
    write(tmp_path, ".mcp.json", json.dumps({"mcpServers": {"docs": server}}))
    audit = audit_project_control_plane(tmp_path)
    assert not audit.launcher_targets
    assert not audit.gaps
    assert not any(f["category"] == "hook_target_missing" for f in audit.findings)


@pytest.mark.parametrize(
    ("command", "gap"),
    [
        ("npx tsx ./reports", "directory entry point is unresolved"),
        ("npx --unknown-runner-option tsx ./main.ts", "unrecognized package-runner options"),
    ],
)
def test_ambiguous_execution_is_visible(tmp_path: Path, command: str, gap: str) -> None:
    write(tmp_path, "reports/index.ts", "// Local report\n")
    write(tmp_path, ".claude/hooks.json", json.dumps({"hooks": {"Start": [command]}}))
    audit = audit_project_control_plane(tmp_path)
    assert any(gap in item for item in audit.gaps)


def test_same_claims_apply_to_both_snapshots(tmp_path: Path) -> None:
    base, current = tmp_path / "before", tmp_path / "after"
    base.mkdir()
    claims = tmp_path / "claims.json"
    write(tmp_path, claims.name, json.dumps({"identities": [{"id": "external-reviewer"}]}))
    write(current, "agent.yaml", "identities:\n  - id: repository-worker\n")
    audit = audit_project_control_plane(current, claims_path=claims, baseline_root=base)
    assert [
        a["changed_ref"] for a in audit.reach_alerts if a["root_cause"] == "identity_added"
    ] == ["agent-control:repository-worker"]
    assert not audit_project_control_plane(
        current, claims_path=claims, baseline_root=current
    ).reach_alerts


def test_hook_event_redaction_reaches_every_export(tmp_path: Path) -> None:
    base, current = tmp_path / "before", tmp_path / "after"
    base.mkdir()
    write(current, ".claude/hooks.json", json.dumps({"hooks": {TOKEN: ["node ./report.js"]}}))
    write(current, "report.js", "// Local report\n")
    audit = audit_project_control_plane(current, baseline_root=base)
    assert any(a["root_cause"] == "hook_command_changed" for a in audit.reach_alerts)
    assert TOKEN not in json.dumps(audit.to_dict())
    assert TOKEN not in audit.bom.model_dump_json()
