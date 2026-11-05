"""A launcher started through a shell, cmd, PowerShell or env keeps its pinning findings."""

from __future__ import annotations

import base64
import json
import time
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


def test_many_env_assignments_after_double_dash_resolve_in_linear_time():
    from nexus_symbiote.scanners.mcp import _resolve_launch

    started = time.perf_counter()
    launch = _resolve_launch("env", ["--", *["A=1"] * 200_000, "npx", "some-mcp-server"])
    # Quadratic stripping took about 30 seconds here; linear stripping takes well under one.
    assert time.perf_counter() - started < 10
    assert launch.launcher == "npx"
    assert launch.args == ["some-mcp-server"]


@pytest.mark.parametrize(
    "command,args",
    [
        ("pwsh", ["/c", "npx -y some-mcp-server@latest"]),
        ("pwsh", ["/Command", "npx -y some-mcp-server@latest"]),
        ("pwsh", ["\u2013c", "npx -y some-mcp-server@latest"]),
        ("pwsh", ["\u2014Command", "npx -y some-mcp-server@latest"]),
        ("pwsh", ["\u2015\u2015command", "npx -y some-mcp-server@latest"]),
        ("pwsh", ["-NoProfile", "/c", "npx -y some-mcp-server@latest"]),
        ("pwsh.exe", ["/c", "npx -y some-mcp-server@latest"]),
        ("powershell", ["/NoProfile", "/Command", "npx -y some-mcp-server@latest"]),
        ("pwsh", ["/EncodedCommand", encoded("npx -y some-mcp-server@latest")]),
        ("bash", ["--rcfile", "rc", "-c", "npx some-mcp-server@latest"]),
    ],
)
def test_wrapper_option_spellings_are_read(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.version_pinned is False
    assert any("unpinned package reference" in detail for detail in pinning(server))
    assert server.launcher_package == "npm:some-mcp-server"
    assert server.properties["launcher_wrapper"] in {"pwsh", "powershell", "bash"}


ENCODED = encoded("npx -y some-mcp-server@latest")


@pytest.mark.parametrize(
    "value",
    [
        ENCODED[:8] + " " + ENCODED[8:],
        ENCODED[:8] + "\r\n" + ENCODED[8:] + "\t",
    ],
)
def test_encoded_command_ignores_whitespace_like_dotnet(tmp_path, value):
    server = scan_server(tmp_path, "pwsh", ["-EncodedCommand", value])
    assert server.launcher_package == "npm:some-mcp-server"
    assert any("unpinned package reference" in detail for detail in pinning(server))


@pytest.mark.parametrize(
    "command,args",
    [
        ("pwsh", ["-EncodedCommand", encoded("npx -y some-mcp-server@latest" + " " * 6200)]),
        ("pwsh", ["-EncodedCommand", encoded(" " * 9000 + "npx -y some-mcp-server@1.2.3")]),
        ("pwsh", ["-EncodedCommand", ENCODED[:-4] + "!!" + ENCODED[-4:]]),
        ("sh", ["-c", "n\\px -y some-mcp-server@latest"]),
        ("sh", ["-c", 'n"p"x -y some-mcp-server@latest; true']),
        ("sh", ["-c", "np[x] -y some-mcp-server@latest"]),
        ("cmd", ["/c", "n^px -y some-mcp-server@latest"]),
        ("powershell", ["-c", "n`px -y some-mcp-server@latest"]),
        ("sh", ["-c", "nohup sh -c 'npx -y some-mcp-server@latest'"]),
        ("bash", ["-c", "timeout 3600 bash -c 'npx some-mcp-server@latest'"]),
        ("cmd", ["/c", "installer=x", "npx", "-y", "some-mcp-server@1.2.3"]),
        ("pwsh", ["-c", "helper=x npx some-mcp-server@1.2.3"]),
        ("pwsh", ["-c", "npx some-mcp-server@1.2.3 @splat"]),
        ("env", ["-S", "A=1", "-S", "npx some-mcp-server@latest"]),
        ("nohup", ["npx", "-y", "some-mcp-server@latest"]),
        ("busybox", ["sh", "-c", "npx -y some-mcp-server@latest"]),
        ("timeout", ["3600", "npx", "some-mcp-server@1.2.3"]),
        ("dotenv", ["--", "npx", "some-mcp-server@1.2.3"]),
    ],
)
def test_obscured_wrapped_launcher_is_an_undetermined_finding(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.version_pinned is None
    assert server.launcher_package is None
    details = pinning(server)
    assert len(details) == 1
    assert "could not be determined" in details[0]
    assert server.properties["launcher"] == "npx"
    assert server.properties["launcher_wrapper"]


@pytest.mark.parametrize(
    "command,args",
    [
        ("fish", ["-c", "npx -y some-mcp-server@latest"]),
        ("mksh", ["-c", "npx -y some-mcp-server@latest"]),
        ("yash", ["-c", "npx -y some-mcp-server@latest"]),
    ],
)
def test_more_posix_shells_are_wrappers(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.launcher_package == "npm:some-mcp-server"
    assert any("unpinned package reference" in detail for detail in pinning(server))
    assert server.properties["launcher_wrapper"] == command


SCOPED = "@modelcontextprotocol/server-filesystem@1.2.3"


@pytest.mark.parametrize(
    "command,args",
    [
        ("pwsh", ["-Command", f"npx -y '{SCOPED}' C:\\data"]),
        ("powershell", ["-Command", "npx", "-y", f'"{SCOPED}"']),
    ],
)
def test_quoted_scoped_package_under_powershell_is_pinned(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.version_pinned is True
    assert server.version == "1.2.3"
    assert server.launcher_package == "npm:@modelcontextprotocol/server-filesystem"
    assert pinning(server) == []


@pytest.mark.parametrize(
    "command,args",
    [
        ("bash", ["-lc", "python -m my_server --runtime docker"]),
        ("sh", ["-c", "node /opt/docker"]),
        ("sh", ["-c", "node /srv/docker/server.js > /tmp/mcp.log"]),
        ("python", ["-m", "my_server", "--runtime", "docker"]),
        ("pwsh", ["-File", "npx.ps1"]),
        ("pwsh", ["npx", "some-mcp-server@latest"]),
        ("bash", ["--rcfile", "npx", "-c", "node s.js"]),
    ],
)
def test_launcher_name_outside_command_position_has_no_finding(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert pinning(server) == []
    assert "launcher" not in server.properties


@pytest.mark.parametrize(
    "line",
    [
        "uvx --from pkg==1.0 --index-url {} tool",
        "uvx --from pkg==1.0 --index-url {} tool; true",
    ],
)
def test_wrapped_package_source_is_bound_by_static_config_hash(tmp_path, line):
    def static_hash(url: str) -> str:
        server = scan_server(tmp_path, "sh", ["-c", line.format(url)])
        return str(server.properties["static_config_hash"])

    assert static_hash("https://pypi.org/simple") != static_hash("https://evil.example/simple")


def test_direct_launcher_static_config_hash_is_unchanged(tmp_path):
    server = scan_server(
        tmp_path, "uvx", ["--from", "pkg==1.0", "--index-url", "https://pypi.org/simple", "tool"]
    )
    assert server.properties["static_config_hash"] == DIRECT_UVX_HASH


DIRECT_UVX_HASH = "sha256:44f413734097e44466f14476b0780df5cc51c60ac86b4e255139db2a0e854bb7"


def test_unknown_program_before_launcher_is_not_exported(tmp_path):
    server = scan_server(tmp_path, "/opt/private-dir/runner", ["npx", "some-mcp-server@1.2.3"])
    assert "could not be determined" in pinning(server)[0]
    assert server.properties["launcher_wrapper"] == "[redacted-command]"
    assert "private-dir" not in server.model_dump_json()


@pytest.mark.parametrize(
    "command,args",
    [
        ("sh", ["-c", "$TOOL some-mcp-server@latest"]),
        ("sh", ["-c", "${RUNNER} x"]),
        ("sh", ["-c", '"$(command -v runner)" some-mcp-server']),
        ("sh", ["-c", "`cat tool.txt` some-mcp-server"]),
        ("sh", ["-c", "${TOOL:-/opt/bin/runner} some-mcp-server"]),
        ("bash", ["-lc", "cd /srv && $TOOL some-mcp-server"]),
        ("bash", ["-c", "FOO=1 exec $TOOL some-mcp-server"]),
        ("sh", ["-c", "nohup $TOOL some-mcp-server"]),
        ("sh", ["-c", "/opt/bin/$TOOL some-mcp-server"]),
        ("sh", ["-c", "run* some-mcp-server"]),
        ("sh", ["-c", "x=$(cat tool.txt); $x some-mcp-server"]),
        ("cmd", ["/c", "%LAUNCHER% some-mcp-server"]),
        ("cmd", ["/c", "@%LAUNCHER%", "some-mcp-server"]),
        ("cmd", ["/v:on", "/c", "!LAUNCHER! some-mcp-server"]),
        ("pwsh", ["-c", "$env:LAUNCHER some-mcp-server"]),
        ("pwsh", ["-c", "& $tool some-mcp-server"]),
        ("pwsh", ["-c", "& (Get-Command runner).Source some-mcp-server"]),
        ("powershell", ["-EncodedCommand", encoded("$env:LAUNCHER some-mcp-server")]),
        ("env", ["${TOOL}", "some-mcp-server"]),
        ("env", ["-S", "$TOOL some-mcp-server"]),
        ("sh", ["-c", "</dev/null $TOOL some-mcp-server"]),
        ("sh", ["-c", "2>/tmp/err $TOOL some-mcp-server"]),
        ("sh", ["-c", "> /tmp/log $TOOL some-mcp-server"]),
        ("sh", ["-c", 'eval "$TOOL some-mcp-server"']),
        ("sh", ["-c", "eval $LAUNCH"]),
        ("sh", ["-c", "env $TOOL some-mcp-server"]),
        ("sh", ["-c", "env -i PATH=$PATH $TOOL some-mcp-server"]),
        ("sh", ["-c", "env -u HOME $TOOL some-mcp-server"]),
        ("sh", ["-c", "exec -a name $TOOL some-mcp-server"]),
        ("sh", ["-c", "exec >>$LOG 2>&1; $TOOL some-mcp-server"]),
        ("bash", ["-c", "builtin exec $TOOL some-mcp-server"]),
        ("bash", ["-c", "coproc $TOOL some-mcp-server"]),
        ("bash", ["-c", "coproc srv { $TOOL some-mcp-server; }"]),
        ("bash", ["-c", "function f { $TOOL some-mcp-server; }; f"]),
        ("sh", ["-c", 'sh -c "$LAUNCH"']),
        ("sh", ["-c", "bash -ec $LAUNCH"]),
        ("bash", ["-c", '. "$ENV_SCRIPT"']),
        ("bash", ["-c", "source $ENV_SCRIPT"]),
        ("sh", ["-c", 'timeout "$SECS" $TOOL some-mcp-server']),
        ("cmd", ["/c", 'start "" %LAUNCHER% some-mcp-server']),
        ("cmd", ["/c", 'start /b /wait "" %LAUNCHER% some-mcp-server']),
        ("cmd", ["/c", "start /d C:\\srv %LAUNCHER% some-mcp-server"]),
        ("cmd", ["/c", "if 1==1 %LAUNCHER% some-mcp-server"]),
        ("cmd", ["/c", "if /i not %A% == b %LAUNCHER% some-mcp-server"]),
        ("cmd", ["/c", "if defined LAUNCHER %LAUNCHER% some-mcp-server"]),
        ("cmd", ["/c", "if exist x.txt (%LAUNCHER% some-mcp-server)"]),
        ("cmd", ["/c", "for /f %i in ('where runner') do %i some-mcp-server"]),
        ("cmd", ["/c", "for %%T in (a) do @%%~fT some-mcp-server"]),
        ("cmd", ["/c", ">nul %LAUNCHER% some-mcp-server"]),
        ("pwsh", ["-c", 'iex "$env:LAUNCHER some-mcp-server"']),
        ("pwsh", ["-c", "Invoke-Expression $env:LAUNCHER"]),
        ("pwsh", ["-c", "Invoke-Expression (Get-Content launch.txt)"]),
        ("pwsh", ["-c", "Start-Process $env:LAUNCHER -ArgumentList some-mcp-server"]),
        ("pwsh", ["-c", "Start-Process -FilePath $env:LAUNCHER some-mcp-server"]),
        ("pwsh", ["-c", "Start-Process -NoNewWindow -Wait $env:LAUNCHER"]),
        ("pwsh", ["-c", "saps -WorkingDirectory C:\\srv -f:$env:LAUNCHER"]),
        ("pwsh", ["-c", "$PSStyle.OutputRendering = 'PlainText'; & $env:LAUNCHER x"]),
    ],
)
def test_computed_command_in_wrapped_line_is_an_undetermined_finding(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert server.version_pinned is None
    assert server.launcher_package is None
    details = pinning(server)
    assert len(details) == 1
    assert "could not be determined" in details[0]
    assert server.properties["launcher"] == "[computed]"
    assert server.properties["launcher_wrapper"] == command
    dump = server.model_dump_json()
    assert "some-mcp-server" not in dump
    assert "LAUNCHER" not in dump
    assert "TOOL" not in dump


@pytest.mark.parametrize(
    "command,args,wrapper",
    [
        ("$NPX", ["some-mcp-server"], None),
        ("${NPX}", ["some-mcp-server"], None),
        ("${env:NPX}", ["some-mcp-server"], None),
        ("%NPX%", ["some-mcp-server"], None),
        ("/opt/${TOOL}", ["some-mcp-server"], None),
        ("nohup", ["${TOOL}", "some-mcp-server"], "nohup"),
        ("timeout", ["30", "${TOOL}", "some-mcp-server"], "timeout"),
    ],
)
def test_computed_configured_command_is_an_undetermined_finding(tmp_path, command, args, wrapper):
    server = scan_server(tmp_path, command, args)
    details = pinning(server)
    assert len(details) == 1
    assert "could not be determined" in details[0]
    assert server.launcher_package is None
    assert server.properties["launcher"] == "[computed]"
    assert server.properties.get("launcher_wrapper") == wrapper
    assert "NPX" not in server.model_dump_json()


@pytest.mark.parametrize(
    "command,args",
    [
        ("sh", ["-c", "node server.js --port $PORT"]),
        ("sh", ["-c", "$HOME/bin/my-server --port 3000"]),
        ("sh", ["-c", '"$HOME/.local/bin/my-server"']),
        ("sh", ["-c", 'exec node "$@"']),
        ("bash", ["-c", 'cd "$DIR" && node server.js']),
        ("bash", ["-c", "PORT=$((BASE + 1)) node server.js"]),
        ("sh", ["-c", 'echo "$(date)" > /tmp/started; node server.js']),
        ("sh", ["-c", "{ node server.js; } 2>&1"]),
        ("sh", ["-c", "'$TOOL' --port 3000"]),
        ("sh", ["-c", "for f in *.js; do node $f; done"]),
        ("cmd", ["/c", '"%ProgramFiles%\\nodejs\\node.exe" server.js']),
        ("cmd", ["/c", "node server.js --port %PORT%"]),
        ("pwsh", ["-c", "$port = 3000; node server.js --port $port"]),
        ("pwsh", ["-c", "$env:PORT = '3000'; node server.js"]),
        ("pwsh", ["-c", '& "$env:ProgramFiles\\nodejs\\node.exe" server.js']),
        ("${HOME}/bin/my-server", ["--port", "3000"]),
        ("node", ["${HOME}/server.js"]),
        ("env", ["PORT=${PORT}", "node", "server.js"]),
        ("nohup", ["node", "${HOME}/server.js"]),
        ("sh", ["-c", "exec >>$LOG 2>&1; node server.js"]),
        ("sh", ["-c", 'exec 2>"$LOGFILE"; exec node server.js']),
        ("sh", ["-c", 'exec 2>>"$LOG"; node server.js']),
        ("sh", ["-c", ">$LOG node server.js"]),
        ("sh", ["-c", "node server.js 2>>$LOG"]),
        ("bash", ["-c", "node server.js &>$LOG"]),
        ("sh", ["-c", 'timeout "$TIMEOUT" node server.js']),
        ("sh", ["-c", "taskset $MASK node server.js"]),
        ("timeout", ["${TIMEOUT}", "node", "server.js"]),
        ("chrt", ["${PRIO}", "node", "server.js"]),
        ("bash", ["-c", '. "$HOME/.nvm/nvm.sh"; nvm use 20; node server.js']),
        ("sh", ["-c", 'sh -c "node $DIR/server.js"']),
        ("sh", ["-c", "env PORT=$PORT node server.js"]),
        ("cmd", ["/c", "if defined PORT node server.js --port %PORT%"]),
        ("cmd", ["/c", "for %i in (%FILES%) do node %~fi"]),
        ("cmd", ["/c", 'start "%TITLE%" node server.js']),
        ("pwsh", ["-c", "$PSStyle.OutputRendering = 'PlainText'; node server.js"]),
        ("pwsh", ["-c", "$PSDefaultParameterValues['*:Encoding'] = 'utf8'; node server.js"]),
        (
            "powershell",
            [
                "-Command",
                "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
                "$host.UI.RawUI.WindowTitle = 'mcp'; node server.js",
            ],
        ),
        ("pwsh", ["-c", "Start-Process -FilePath node -ArgumentList $env:ARGS"]),
        ("pwsh", ["-c", "iex 'Write-Output ready'; node server.js"]),
    ],
)
def test_literal_command_with_expanded_arguments_has_no_finding(tmp_path, command, args):
    server = scan_server(tmp_path, command, args)
    assert pinning(server) == []
    assert "launcher" not in server.properties


@pytest.mark.parametrize(
    "command,args",
    [
        ("sh", ["-c", "$" * 200_000 + "/"]),
        ("sh", ["-c", "exec " + "$" * 200_000 + "/"]),
        ("cmd", ["/c", "%a" * 100_000 + "\\"]),
        ("cmd", ["/c", "!a" * 100_000 + "\\"]),
        ("pwsh", ["-c", "$" * 200_000 + "\\"]),
        ("$" * 200_000 + "/", []),
        ("%a" * 100_000 + "/", []),
        ("nohup", ["$" * 200_000 + "/"]),
        ("sh", ["-c", "env -i " * 100_000 + "node"]),
        ("cmd", ["/c", "if not " * 100_000 + "node"]),
        ("cmd", ["/c", "start /b " * 100_000 + "node"]),
    ],
)
def test_long_computed_word_is_classified_in_linear_time(tmp_path, command, args):
    started = time.monotonic()
    scan_server(tmp_path, command, args)
    assert time.monotonic() - started < 3
