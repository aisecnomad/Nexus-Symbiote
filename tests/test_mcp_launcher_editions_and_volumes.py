"""Static manifest classification across launcher editions and volume substitutions."""

import hashlib
import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.mcp_launch import analyze


@pytest.mark.parametrize("program", ["powershell", "PowerShell.exe"])
@pytest.mark.parametrize(
    "prefix",
    [
        ["-CustomPipeName", "sample"],
        ["-WorkingDirectory", "sample"],
        ["-wo", "sample"],
        ["-cwa", "sample"],
        ["-CommandWithArgs", "sample"],
    ],
)
def test_windows_powershell_does_not_skip_modern_parameters(tmp_path, program, prefix):
    args = ["-NoProfile", *prefix, "-Command", "Write-Output sample"]
    assert analyze(program, args).unknown is not None
    manifest = {"mcpServers": {"sample": {"command": program, "args": args}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(manifest))
    gate = CliRunner().invoke(main, ["scan", str(tmp_path), "--check", "--no-project-policy"])
    assert gate.exit_code == 1, gate.output
    assert "PowerShell" in gate.output


@pytest.mark.parametrize("program", ["powershell.exe", "pwsh"])
def test_shared_powershell_switches_retain_a_benign_command(program):
    result = analyze(program, ["-NoProfile", "-Command", "Write-Output sample"])
    assert result.unknown is None and result.executable == "write-output"


def test_modern_powershell_can_still_consume_a_pipe_name():
    result = analyze("pwsh", ["-CustomPipeName", "sample", "-Command", "Write-Output sample"])
    assert result.unknown is None and result.executable == "write-output"


@pytest.mark.parametrize(
    "option", ["-cwa", "-CommandWithArgs", "-RemoveWorkingDirectoryTrailingCharacter"]
)
def test_platform_or_version_specific_switches_do_not_establish_a_command(option):
    result = analyze("pwsh", [option, "-Command", "Write-Output sample"])
    assert result.unknown is not None


@pytest.mark.parametrize(
    ("source", "flag"),
    [
        ("${BASE:-/sample}/podman.sock", "runtime_socket_mount"),
        ("${extensionInstallFolder:example.fixture}/containerd.sock", "runtime_socket_mount"),
        ("${DATA:-/etc}", "broad_host_mount"),
        ("${DATA:-/}", "host_root_mount"),
        ("${workspaceFolder:sample}/", None),
        ("${extensionInstallFolder:example.fixture}/", None),
        ("${DATA:-/sample}/assets", None),
    ],
)
def test_volume_sources_are_scored_from_inert_manifest_text(tmp_path, source, flag):
    image = "example.invalid/fixture/tool@sha256:" + hashlib.sha256(b"test image").hexdigest()
    args = ["run", "--rm", "-i", "-v", source + ":/sample-data:ro", image]
    classified = analyze("docker", args)
    if flag is None:
        assert not {"runtime_socket_mount", "broad_host_mount", "host_root_mount"}.intersection(
            classified.context
        )
        return
    assert classified.context.get(flag)
    manifest = {"mcpServers": {"sample": {"command": "docker", "args": args}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(manifest))
    inventory = tmp_path / "out.json"
    runner = CliRunner()
    scanned = runner.invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(inventory)]
    )
    assert scanned.exit_code == 0, scanned.output
    severity = "medium" if flag == "broad_host_mount" else "high"
    gate = runner.invoke(main, ["risk", str(inventory), "--fail-on-severity", severity])
    assert gate.exit_code == 1, gate.output
    assert f"{severity} sample [launch_context]" in gate.output


def test_an_unrecognized_leading_source_substitution_records_a_coverage_gap():
    declaration = ["run", "-v", "${resource:sample}/assets:/data:ro", "example.invalid/test:v1"]
    result = analyze("docker", declaration)
    assert result.unknown and "volume source" in result.unknown


def test_long_mount_form_also_checks_a_literal_default():
    args = ["run", "--mount", "type=bind,src=${DATA:-/etc},target=/data", "example.invalid/test:v1"]
    assert analyze("docker", args).context.get("broad_host_mount")
