"""A launcher named by path or with a Windows suffix keeps its pinning findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner

UNPINNED = {
    "npx": ["-y", "some-mcp-server@latest"],
    "bunx": ["some-mcp-server"],
    "uvx": ["some-mcp-server"],
    "pipx": ["run", "some-mcp-server"],
    "docker": ["run", "registry.test/team/server:latest"],
}
IDENTITY = {
    "npx": "npm:some-mcp-server",
    "bunx": "npm:some-mcp-server",
    "uvx": "pypi:some-mcp-server",
    "pipx": "pypi:some-mcp-server",
    "docker": "oci:registry.test/team/server",
}


def write_project(project: Path, command: str, args: list[str]) -> None:
    server = {"command": command, "args": args}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))


def scan_server(project: Path, command: str, args: list[str]) -> MCPServerComponent:
    write_project(project, command, args)
    result = MCPScanner().scan(project)
    assert not result.scan_failures
    return next(c for c in result.components if isinstance(c, MCPServerComponent))


def findings(server: MCPServerComponent) -> set[tuple[str, str]]:
    return {(risk.severity.value, risk.category) for risk in server.risks}


@pytest.mark.parametrize(
    "command,launcher",
    [
        ("npx.cmd", "npx"),
        ("NPX.CMD", "npx"),
        ("npx.exe", "npx"),
        ("bunx.exe", "bunx"),
        ("uvx.exe", "uvx"),
        ("pipx.bat", "pipx"),
        ("docker.exe", "docker"),
        ("Npx.Ps1", "npx"),
    ],
)
def test_windows_suffix_keeps_classification_and_identity(tmp_path, command, launcher):
    server = scan_server(tmp_path, command, UNPINNED[launcher])
    assert ("high", "version_pinning") in findings(server)
    assert server.version_pinned is False
    # A bare name is resolved from PATH exactly like the plain launcher name.
    assert server.launcher_package == IDENTITY[launcher]
    assert server.properties["launcher"] == launcher
    assert server.properties["launcher_path_qualified"] is False


@pytest.mark.parametrize(
    "command,launcher",
    [
        ("/usr/local/bin/npx", "npx"),
        ("./node_modules/.bin/npx", "npx"),
        ("C:\\private-dir\\npx.ps1", "npx"),
        ("C:/private-dir/npx.CMD", "npx"),
        ("C:npx.cmd", "npx"),
        ("/opt/private-dir/uvx", "uvx"),
        ("D:\\private-dir\\uvx.exe", "uvx"),
        ("/opt/private-dir/bunx", "bunx"),
        ("/opt/private-dir/pipx", "pipx"),
        ("/usr/local/bin/docker", "docker"),
    ],
)
def test_path_qualified_launcher_is_classified_without_registry_identity(
    tmp_path, command, launcher
):
    server = scan_server(tmp_path, command, UNPINNED[launcher])
    assert ("high", "version_pinning") in findings(server)
    assert server.version_pinned is False
    # The explicit path can name any executable, so no registry package is claimed.
    assert server.launcher_package is None
    assert server.properties["launcher"] == launcher
    assert server.properties["launcher_path_qualified"] is True
    assert server.command == "[redacted-command]"
    assert "private-dir" not in server.model_dump_json()


@pytest.mark.parametrize(
    "command,args,version",
    [
        ("/usr/local/bin/npx", ["-y", "pkg@1.2.3"], "1.2.3"),
        ("C:\\private-dir\\uvx.exe", ["pkg==1.2.3"], "1.2.3"),
        ("npx.cmd", ["-y", "pkg@1.2.3"], "1.2.3"),
    ],
)
def test_normalized_launcher_records_exact_pins(tmp_path, command, args, version):
    server = scan_server(tmp_path, command, args)
    assert server.version == version
    assert server.version_pinned is True
    assert ("high", "version_pinning") not in findings(server)


def test_plain_launcher_output_is_unchanged(tmp_path):
    server = scan_server(tmp_path, "npx", UNPINNED["npx"])
    assert server.command == "npx"
    assert server.launcher_package == "npm:some-mcp-server"
    assert "launcher" not in server.properties
    assert "launcher_path_qualified" not in server.properties


@pytest.mark.parametrize("command", ["/opt/private-dir/server", "server.exe", "npx-helper"])
def test_other_commands_are_not_launchers(tmp_path, command):
    server = scan_server(tmp_path, command, ["-y", "some-mcp-server@latest"])
    assert server.version_pinned is None
    assert ("high", "version_pinning") not in findings(server)
    assert "launcher" not in server.properties


def test_path_qualified_launcher_scores_like_the_bare_launcher(tmp_path):
    runner = CliRunner()
    scores = {}
    for name, command in (("bare", "npx"), ("path", "/usr/local/bin/npx")):
        project = tmp_path / name
        project.mkdir()
        write_project(project, command, UNPINNED["npx"])
        bom = tmp_path / f"{name}.json"
        scan = runner.invoke(
            main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(bom)]
        )
        assert scan.exit_code == 0, scan.output
        risk = runner.invoke(
            main,
            [
                "risk",
                str(bom),
                "--project",
                str(project),
                "--no-project-policy",
                "--json-output",
            ],
        )
        report = json.loads(risk.stdout)
        assert report["assessment_basis"] == "project-reconciled"
        scores[name] = report["overall_score"]
    assert scores == {"bare": 11.0, "path": 11.0}
