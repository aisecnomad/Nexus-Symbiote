"""Classify format options from inert manifests without starting an interpreter."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.mcp_launch import analyze


@pytest.mark.parametrize("option", ["-if", "-OF"])
@pytest.mark.parametrize(
    "program",
    ["powershell", "PowerShell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"],
)
def test_legacy_unverified_format_alias_keeps_manifest_gate_closed(tmp_path, program, option):
    args = ["-NoProfile", option, "Text", "-Command", "Write-Output sample"]
    assert analyze(program, args).unknown is not None
    manifest = {"mcpServers": {"sample": {"command": program, "args": args}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(manifest))
    check = CliRunner().invoke(main, ["scan", str(tmp_path), "--check", "--no-project-policy"])
    assert check.exit_code == 1, check.output
    assert "PowerShell" in check.output


@pytest.mark.parametrize(
    ("program", "option"),
    [
        ("powershell.exe", "-InputFormat"),
        ("powershell", "-OutputFormat"),
        ("pwsh", "-if"),
        ("pwsh.exe", "-of"),
    ],
)
def test_supported_format_spelling_keeps_benign_command(program, option):
    parsed = analyze(program, [option, "Text", "-Command", "Write-Output sample"])
    assert parsed.unknown is None and parsed.executable == "write-output"
