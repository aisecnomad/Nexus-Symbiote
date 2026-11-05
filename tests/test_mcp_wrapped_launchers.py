"""A launcher started through a shell, cmd, PowerShell or env keeps its pinning findings."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner


def scan_server(
    project: Path, command: str, args: list[str], env: dict[str, str] | None = None
) -> MCPServerComponent:
    server: dict[str, object] = {"command": command, "args": args}
    if env:
        server["env"] = env
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    result = MCPScanner().scan(project)
    assert not result.scan_failures
    return next(c for c in result.components if isinstance(c, MCPServerComponent))


def pinning(server: MCPServerComponent) -> list[str]:
    return [risk.detail for risk in server.risks if risk.category == "version_pinning"]


def encoded(line: str) -> str:
    return base64.b64encode(line.encode("utf-16-le")).decode()


@pytest.mark.parametrize(
    "command,args,launcher,wrapper,identity",
    [
        ("sh", ["-c", "npx -y some-mcp-server@latest"], "npx", "sh", "npm:some-mcp-server"),
        ("bash", ["-lc", "npx some-mcp-server"], "npx", "bash", "npm:some-mcp-server"),
        ("bash", ["-ec", "exec npx -y some-mcp-server"], "npx", "bash", "npm:some-mcp-server"),
        (
            "zsh",
            ["-o", "errexit", "-c", "uvx some-mcp-server"],
            "uvx",
            "zsh",
            "pypi:some-mcp-server",
        ),
        (
            "bash",
            ["--norc", "-c", "-x", "bunx some-mcp-server"],
            "bunx",
            "bash",
            "npm:some-mcp-server",
        ),
        (
            "sh",
            ["-c", "FOO=1 pipx run some-mcp-server", "name"],
            "pipx",
            "sh",
            "pypi:some-mcp-server",
        ),
        ("sh", ["-c", "'npx' \"some-mcp-server@latest\""], "npx", "sh", "npm:some-mcp-server"),
        (
            "dash",
            ["-c", "docker run -i --rm -e TOKEN registry.test/team/server:latest"],
            "docker",
            "dash",
            "oci:registry.test/team/server",
        ),
        ("cmd", ["/c", "npx", "-y", "some-mcp-server@latest"], "npx", "cmd", "npm:some-mcp-server"),
        ("cmd.exe", ["/C", "npx -y some-mcp-server"], "npx", "cmd", "npm:some-mcp-server"),
        (
            "CMD.EXE",
            ["/d", "/s", "/c", "npx.cmd some-mcp-server"],
            "npx",
            "cmd",
            "npm:some-mcp-server",
        ),
        ("cmd", ["/K", "uvx", "some-mcp-server"], "uvx", "cmd", "pypi:some-mcp-server"),
        ("cmd", ["/c", "@npx", "some-mcp-server"], "npx", "cmd", "npm:some-mcp-server"),
        (
            "powershell",
            ["-Command", "npx -y some-mcp-server"],
            "npx",
            "powershell",
            "npm:some-mcp-server",
        ),
        ("pwsh", ["-c", "npx", "some-mcp-server@latest"], "npx", "pwsh", "npm:some-mcp-server"),
        (
            "powershell.exe",
            ["-NoProfile", "-ExecutionPolicy", "Bypass", "-command", "npx 'some-mcp-server'"],
            "npx",
            "powershell",
            "npm:some-mcp-server",
        ),
        ("powershell", ["npx", "some-mcp-server"], "npx", "powershell", "npm:some-mcp-server"),
        (
            "pwsh",
            ["-NoLogo", "-EncodedCommand", encoded("npx -y some-mcp-server@latest")],
            "npx",
            "pwsh",
            "npm:some-mcp-server",
        ),
        (
            "env",
            ["FOO=1", "npx", "-y", "some-mcp-server@latest"],
            "npx",
            "env",
            "npm:some-mcp-server",
        ),
        (
            "env",
            ["-i", "-u", "HOME", "--", "uvx", "some-mcp-server"],
            "uvx",
            "env",
            "pypi:some-mcp-server",
        ),
        ("env", ["-S", "npx -y some-mcp-server@latest"], "npx", "env", "npm:some-mcp-server"),
        ("env", ["-S", "FOO=1 npx", "some-mcp-server"], "npx", "env", "npm:some-mcp-server"),
        ("env", ["--split-string=npx some-mcp-server"], "npx", "env", "npm:some-mcp-server"),
        ("sh", ["-c", "env A=1 npx some-mcp-server"], "npx", "sh", "npm:some-mcp-server"),
        (
            "cmd",
            ["/c", "env", "A=1", "npx", "some-mcp-server"],
            "npx",
            "cmd",
            "npm:some-mcp-server",
        ),
    ],
)
def test_wrapped_unpinned_launcher_is_a_finding(
    tmp_path, command, args, launcher, wrapper, identity
):
    server = scan_server(tmp_path, command, args)
    assert server.version_pinned is False
    assert any("unpinned package reference" in detail for detail in pinning(server))
    assert server.launcher_package == identity
    assert server.properties["launcher"] == launcher
    assert server.properties["launcher_wrapper"] == wrapper
    assert server.properties["launcher_path_qualified"] is False


@pytest.mark.parametrize(
    "command,args,version",
    [
        ("sh", ["-c", "npx -y some-mcp-server@1.2.3"], "1.2.3"),
        ("cmd", ["/c", "uvx", "some-mcp-server==1.2.3"], "1.2.3"),
        ("pwsh", ["-Command", "npx some-mcp-server@1.2.3"], "1.2.3"),
        ("env", ["A=1", "docker", "run", "-i", "registry.test/team/server:1.2.3"], "1.2.3"),
    ],
)
def test_wrapped_pinned_launcher_records_its_version(tmp_path, command, args, version):
    server = scan_server(tmp_path, command, args)
    assert server.version == version
    assert server.version_pinned is True
    assert pinning(server) == []


@pytest.mark.parametrize(
    "command,args",
    [
        ("/bin/sh", ["-c", "npx some-mcp-server@latest"]),
        ("/usr/bin/env", ["npx", "some-mcp-server@latest"]),
        ("sh", ["-c", "/opt/private-dir/npx some-mcp-server@latest"]),
    ],
)
def test_path_in_wrapper_chain_withholds_registry_identity(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.version_pinned is False
    assert pinning(server)
    assert server.launcher_package is None
    assert server.properties["launcher"] == "npx"
    assert server.properties["launcher_path_qualified"] is True
    assert "private-dir" not in server.model_dump_json()


@pytest.mark.parametrize(
    "command,args",
    [
        ("sh", ["-c", "npx some-mcp-server@1.2.3 | tee log"]),
        ("sh", ["-c", "npx some-mcp-server@1.2.3 && npx other-server"]),
        ("bash", ["-c", "cd /srv; npx some-mcp-server@1.2.3"]),
        ("sh", ["-c", "npx some-mcp-server@1.2.3\nnpx other-server"]),
        ("sh", ["-c", "npx $(cat pkg.txt)"]),
        ("sh", ["-c", "npx `cat pkg.txt`"]),
        ("sh", ["-c", "npx $PKG"]),
        ("sh", ["-c", "npx some-mcp-server@${VERSION}"]),
        ("sh", ["-c", "npx some-mcp-server@{1.2.3,latest}"]),
        ("sh", ["-c", "npx some-mcp-server@1.2.3 > log"]),
        ("sh", ["-c", "nohup npx some-mcp-server@1.2.3"]),
        ("sh", ["-c", "npx 'unterminated"]),
        ("bash", ["--unknown-option", "-c", "npx some-mcp-server@1.2.3"]),
        ("cmd", ["/c", "npx some-mcp-server@1.2.3 & calc"]),
        ("cmd", ["/c", "npx", "%PKG%"]),
        ("cmd", ["/c", '"npx some-mcp-server@1.2.3"']),
        ("cmd", ["/x", "/c", "npx some-mcp-server@1.2.3"]),
        ("pwsh", ["-c", "npx some-mcp-server@1.2.3; calc"]),
        ("pwsh", ["-c", "npx $env:PKG"]),
        ("pwsh", ["-c", "& npx some-mcp-server@1.2.3"]),
        ("pwsh", ["-EncodedCommand", encoded("npx $env:PKG")]),
        ("env", ["--frobnicate", "npx", "some-mcp-server@1.2.3"]),
        ("env", ["-S", "npx $PKG"]),
        ("env", ["env"] * 6 + ["npx", "some-mcp-server@1.2.3"]),
        # Readable but too long to tokenize within the bound.
        ("sh", ["-c", "npx some-mcp-server@1.2.3" + " x" * 3000]),
        ("sh", ["-c", "docker run $IMAGE"]),
    ],
)
def test_unreadable_wrapped_line_is_an_undetermined_finding(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.version_pinned is None
    assert server.launcher_package is None
    details = pinning(server)
    assert len(details) == 1
    assert "could not be determined" in details[0]
    assert server.properties["launcher_wrapper"]


@pytest.mark.parametrize(
    "command,args",
    [
        ("sh", ["-c", "node server.js"]),
        ("bash", ["run-server.sh"]),
        ("bash", ["-lc", "python -m my_server --port 3000"]),
        ("sh", ["-c", "node $HOME/server.js"]),
        ("sh", []),
        ("cmd", ["/c", "python", "-m", "my_server"]),
        ("cmd", ["/d"]),
        ("pwsh", ["-File", "server.ps1"]),
        ("pwsh", ["server.ps1"]),
        ("pwsh", ["-Command", "-"]),
        ("env", ["FOO=1", "node", "server.js"]),
        ("env", []),
    ],
)
def test_wrapper_without_a_package_launcher_has_no_pinning_finding(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.version_pinned is None
    assert pinning(server) == []
    assert "launcher" not in server.properties


def test_wrapped_docker_command_that_starts_no_container_has_no_finding(tmp_path):
    server = scan_server(tmp_path, "sh", ["-c", "docker compose up"])
    assert pinning(server) == []
    assert server.properties["launcher"] == "docker"


SECRET = "ghp_" + "Q" * 36


@pytest.mark.parametrize(
    "command,args",
    [
        ("sh", ["-c", f"GITHUB_TOKEN={SECRET} npx -y some-mcp-server@1.2.3"]),
        ("sh", ["-c", f"docker run -i -e GITHUB_TOKEN={SECRET} ghcr.io/github/github-mcp-server"]),
        ("cmd", ["/c", "npx", "--registry", f"https://u:{SECRET}@registry.test/", "srv"]),
        ("env", [f"GITHUB_TOKEN={SECRET}", "npx", "some-mcp-server"]),
        ("sh", ["-c", f"npx some-mcp-server --token {SECRET} | cat"]),
        ("pwsh", ["-c", f"npx some-mcp-server --token {SECRET}; calc"]),
    ],
)
def test_wrapped_line_is_never_exported(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    dump = server.model_dump_json()
    assert SECRET not in dump
    assert "GITHUB_TOKEN" not in dump
    assert "registry.test" not in dump
    assert server.command == "[redacted-command]"
    assert set(server.args) == {"***"}


def test_secret_in_package_position_withholds_identity(tmp_path):
    secret = "s3cr3t-registry-token"  # noqa: S105 - test fixture
    server = scan_server(tmp_path, "sh", ["-c", f"npx {secret}"], env={"TOKEN": secret})
    assert server.launcher_package is None
    assert secret not in server.model_dump_json()
