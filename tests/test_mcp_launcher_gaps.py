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
        (
            "docker.exe",
            ["run", "-i", "--rm", "registry.test/team/server@sha256:" + "a" * 64],
            "sha256:" + "a" * 64,
        ),
        ("docker.exe", ["run", "-i", "--rm", "registry.test/team/server:1.2.3"], "1.2.3"),
    ],
)
def test_normalized_launcher_records_exact_pins(tmp_path, command, args, version):
    server = scan_server(tmp_path, command, args)
    assert server.version == version
    assert server.version_pinned is True
    assert ("high", "version_pinning") not in findings(server)


@pytest.mark.parametrize(
    "command,args",
    [
        (
            "pipx.exe",
            [
                "run",
                "--spec",
                "some-mcp-server",
                "--index-url",
                "https://evil.example/simple",
                "srv",
            ],
        ),
        (
            "uvx.exe",
            ["--from", "some-mcp-server", "--index-url", "https://evil.example/simple", "srv"],
        ),
    ],
)
def test_suffixed_launcher_with_alternate_index_has_no_identity(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.launcher_package is None


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


ENV_NAME = "GITHUB_PERSONAL_ACCESS_TOKEN"


@pytest.mark.parametrize(
    "command,args,identity",
    [
        (
            "docker",
            ["run", "-i", "--rm", "-e", ENV_NAME, "ghcr.io/github/github-mcp-server"],
            "oci:ghcr.io/github/github-mcp-server",
        ),
        (
            "docker",
            ["run", "--env=X=1", "-v", "/srv:/srv", "--init", "registry.test/team/server"],
            "oci:registry.test/team/server",
        ),
        ("npx", ["-y", "--package=some-mcp-server@latest", "srv"], "npm:some-mcp-server"),
        ("npx", ["-p", "some-mcp-server@latest", "srv"], "npm:some-mcp-server"),
        ("npx", ["--quiet", "some-mcp-server@latest"], "npm:some-mcp-server"),
        ("npx", ["-y", "--", "some-mcp-server@latest"], "npm:some-mcp-server"),
    ],
)
def test_package_after_value_option_keeps_pinning_finding(tmp_path, command, args, identity):
    server = scan_server(tmp_path, command, args)
    assert ("high", "version_pinning") in findings(server)
    assert server.version_pinned is False
    assert server.launcher_package == identity


def test_option_values_are_skipped_without_being_recorded(tmp_path):
    secret = "ghp_" + "Z" * 36
    args = ["run", "-i", "--rm", "-e", f"{ENV_NAME}={secret}", "ghcr.io/github/github-mcp-server"]
    server = scan_server(tmp_path, "docker", args)
    assert server.launcher_package == "oci:ghcr.io/github/github-mcp-server"
    dump = server.model_dump_json()
    assert secret not in dump
    assert ENV_NAME not in dump


def test_pinned_image_after_environment_option_has_no_finding(tmp_path):
    digest = "sha256:" + "b" * 64
    args = ["run", "-i", "--rm", "-e", ENV_NAME, f"ghcr.io/github/github-mcp-server@{digest}"]
    server = scan_server(tmp_path, "docker", args)
    assert server.version == digest
    assert server.version_pinned is True
    assert ("high", "version_pinning") not in findings(server)


@pytest.mark.parametrize(
    "command,args",
    [
        ("npx", ["--registry", "https://registry.test/", "some-mcp-server@1.2.3"]),
        ("npx", ["-p", "a@1.0.0", "-p", "b@latest", "srv"]),
        ("uvx", []),
        ("docker", ["run", "--platform", "linux/amd64", "registry.test/team/server:1.2.3"]),
        ("docker", ["--debug", "run", "registry.test/team/server:latest"]),
        ("docker", ["-H", "tcp://registry.test", "run", "-i", "registry.test/team/server"]),
        ("docker", ["container", "run", "registry.test/team/server:latest"]),
        ("docker", ["--context", "registry.test", "container", "run", "registry.test/x"]),
    ],
)
def test_undetermined_package_reference_is_a_finding(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.version_pinned is None
    assert server.launcher_package is None
    pinning = [risk for risk in server.risks if risk.category == "version_pinning"]
    assert [risk.severity.value for risk in pinning] == ["high"]
    assert "could not be determined" in pinning[0].detail
    assert "registry.test" not in server.model_dump_json()


@pytest.mark.parametrize(
    "args",
    [
        ["compose", "up"],
        ["pull", "registry.test/team/server:latest"],
        ["--debug", "compose", "run", "server"],
        ["-H", "tcp://registry.test", "version"],
        [],
    ],
)
def test_docker_command_that_starts_no_container_has_no_finding(tmp_path, args):
    server = scan_server(tmp_path, "docker", args)
    assert server.launcher_package is None
    assert [risk for risk in server.risks if risk.category == "version_pinning"] == []
