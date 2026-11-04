"""Codex merges project layers table by table, and only along a directory's ancestors."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import IDEAgentComponent, MCPClientComponent, MCPServerComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import MCPScanner

UNPROMPTED = "Codex declares workspace writes with no interactive escalation prompts."
ROOT = ".codex/config.toml"
WEB = "packages/web/.codex/config.toml"
SERVER = '[mcp_servers.fs]\ncommand = "npx"\nargs = ["-y", "fs-server@1.2.3"]\n'
GRANULAR = (
    "[approval_policy.granular]\nsandbox_approval = true\nrules = true\nmcp_elicitations = true\n"
)


def write_layer(root: Path, value: str, directory: str = ".") -> None:
    folder = root / directory / ".codex"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.toml").write_text(value)


def codex(result: ScanResult) -> IDEAgentComponent:
    return next(
        c for c in result.components if isinstance(c, IDEAgentComponent) and c.name == "codex"
    )


def servers(root: Path, result: ScanResult) -> dict[str, MCPServerComponent]:
    return {
        Path(c.source_path).relative_to(root).as_posix(): c
        for c in result.components
        if isinstance(c, MCPServerComponent)
    }


def test_nested_layer_overrides_fields_of_a_root_server(tmp_path: Path) -> None:
    write_layer(
        tmp_path,
        SERVER + 'env = { API_TOKEN = "CANARY_ROOT_ENV" }\n'
        '[mcp_servers.fs.tools.delete_file]\napproval_mode = "prompt"\n',
    )
    write_layer(
        tmp_path,
        '[mcp_servers.fs]\nenabled = false\ndefault_tools_approval_mode = "prompt"\n'
        '[mcp_servers.fs.tools.delete_file]\napproval_mode = "approve"\n',
        "packages/web",
    )
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    found = servers(tmp_path, result)
    assert set(found) == {ROOT, WEB}
    root, web = found[ROOT], found[WEB]
    assert root.properties["declared_enabled"] is True
    assert root.properties["tool_approval_modes"] == {"delete_file": "prompt"}
    assert "codex_merged_layers" not in root.properties
    # The package scope runs the root's launcher with the package's overrides.
    assert web.command == "npx" and web.version == "1.2.3" and web.version_pinned is True
    assert web.env == {"API_TOKEN": "***"}
    assert web.properties["declared_enabled"] is False
    assert web.properties["default_tools_approval_mode"] == "prompt"
    assert web.properties["tool_approval_modes"] == {"delete_file": "approve"}
    assert web.properties["codex_merged_layers"] == [ROOT, WEB]
    assert root.properties["static_config_hash"] != web.properties["static_config_hash"]
    assert "CANARY_ROOT_ENV" not in repr(result)
    client = next(c for c in result.components if isinstance(c, MCPClientComponent))
    assert client.server_refs == sorted({root.bom_ref, web.bom_ref})


@pytest.mark.parametrize(
    ("layers", "failure"),
    [
        # A sibling's declaration never reaches another directory's scope.
        ({"a": SERVER, "b": "[mcp_servers.fs]\nenabled = false\n"}, "b/.codex/config.toml"),
        # The merged server declares both transports, which Codex rejects.
        (
            {".": SERVER, "packages/web": '[mcp_servers.fs]\nurl = "https://example.test/mcp"\n'},
            WEB,
        ),
        # A table replaces a value of another type, so nothing is inherited.
        ({".": "mcp_servers = []\n", "packages/web": "[mcp_servers.fs]\nenabled = false\n"}, WEB),
    ],
)
def test_merged_server_must_be_valid(tmp_path: Path, layers: dict[str, str], failure: str) -> None:
    for directory, body in layers.items():
        write_layer(tmp_path, body, directory)
    result = MCPScanner().scan(tmp_path)
    assert f"{failure}: invalid server configuration" in result.scan_failures
    assert failure not in servers(tmp_path, result)


def test_nested_layer_overrides_one_granular_prompt(tmp_path: Path) -> None:
    write_layer(tmp_path, 'sandbox_mode = "workspace-write"\n' + GRANULAR)
    write_layer(tmp_path, "[approval_policy.granular]\nmcp_elicitations = false\n", "packages/web")
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    agent = codex(result)
    assert agent.properties["nested_config_layers"] == {
        WEB: {"approval_policy": {"granular": {"mcp_elicitations": False}}}
    }
    assert not agent.risks


def test_merged_granular_policy_decides_the_package_scope(tmp_path: Path) -> None:
    write_layer(
        tmp_path,
        'sandbox_mode = "workspace-write"\n'
        + GRANULAR.replace("mcp_elicitations = true", "mcp_elicitations = false"),
    )
    write_layer(
        tmp_path, "[approval_policy.granular]\nsandbox_approval = false\nrules = false\n", "sub"
    )
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    # Only the merged policy in sub/ rejects every prompt; the root still allows two.
    assert {(risk.severity, risk.detail) for risk in codex(result).risks} == {
        (RiskSeverity.MEDIUM, UNPROMPTED)
    }


@pytest.mark.parametrize("root", ["", 'approval_policy = "never"\n'])
def test_partial_granular_policy_needs_an_inherited_table(tmp_path: Path, root: str) -> None:
    write_layer(tmp_path, 'sandbox_mode = "read-only"\n' + root)
    write_layer(tmp_path, "[approval_policy.granular]\nmcp_elicitations = false\n", "packages/web")
    result = IDEAgentScanner().scan(tmp_path)
    assert result.scan_failures == [f"{WEB}: invalid granular approval policy"]


def test_empty_approval_table_merges_as_no_change(tmp_path: Path) -> None:
    write_layer(tmp_path, GRANULAR)
    write_layer(tmp_path, "[approval_policy]\n", "packages/web")
    assert not IDEAgentScanner().scan(tmp_path).scan_failures
    # Without an inherited policy, an empty table is not a policy Codex accepts.
    write_layer(tmp_path, "[approval_policy]\n")
    assert IDEAgentScanner().scan(tmp_path).scan_failures == [
        f"{ROOT}: unsupported declared approval policy",
        f"{WEB}: unsupported declared approval policy",
    ]


def test_sibling_layers_do_not_share_a_scope(tmp_path: Path) -> None:
    write_layer(tmp_path, 'sandbox_mode = "workspace-write"\n')
    write_layer(tmp_path, 'sandbox_mode = "read-only"\n', "a")
    write_layer(tmp_path, 'approval_policy = "never"\n', "b")
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    # b/ inherits workspace-write from the root, not read-only from its sibling a/.
    assert {(risk.severity, risk.detail) for risk in codex(result).risks} == {
        (RiskSeverity.MEDIUM, UNPROMPTED)
    }


def test_profile_declared_in_a_sibling_is_undefined(tmp_path: Path) -> None:
    write_layer(tmp_path, '[permissions.wide]\nextends = ":workspace"\n', "a")
    write_layer(tmp_path, 'default_permissions = "wide"\n', "b")
    result = IDEAgentScanner().scan(tmp_path)
    assert result.scan_failures == ["b/.codex/config.toml: unsupported declared permission profile"]


@pytest.mark.parametrize(
    ("root", "package"),
    [
        (SERVER, "[mcp_servers.fs]\nenabled = false\n"),
        (SERVER, '[mcp_servers.fs]\ndefault_tools_approval_mode = "prompt"\n'),
        (GRANULAR, "[approval_policy.granular]\nmcp_elicitations = false\n"),
    ],
)
def test_partial_overrides_pass_the_scan_gate(tmp_path: Path, root: str, package: str) -> None:
    project = tmp_path / "project"
    write_layer(project, root)
    write_layer(project, package, "packages/web")
    (project / "AGENTS.md").write_text("Be careful.")
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert run.exit_code == 0, run.output
    assert json.loads(output.read_text())["metadata"]["completeness"]["scan_failures"] == []
