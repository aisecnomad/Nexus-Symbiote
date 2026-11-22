"""Runtime context reported from launcher declarations, without executing a launcher."""

import json

import pytest

from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.mcp_launch import analyze


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("python3-dbg", ["-c", "print(1)"]),
        ("python3.13-dbg", ["-c", "print(1)"]),
        ("python3.13d", ["-c", "print(1)"]),
        ("lua", ["-e", "print(1)"]),
        ("Rscript", ["-e", "print(1)"]),
        ("osascript", ["-e", "return 1"]),
        ("pwsh", ["-Command", "Invoke-Expression", "1"]),
        ("pwsh", ["-Command", "iex", "1"]),
    ],
)
def test_inline_expressions_do_not_establish_a_program_identity(command, args):
    launch = analyze(command, args)
    assert launch.unknown is not None and "inline" in launch.unknown


@pytest.mark.parametrize(
    ("driver", "source", "host_mount"),
    [("local", "/dev/example", True), ("local", ":/share", False), ("remote", "/data", False)],
)
def test_only_local_absolute_volume_devices_establish_a_host_mount(driver, source, host_mount):
    mount = f"type=volume,volume-driver={driver},volume-opt=device={source},target=/data"
    image = "example@sha256:" + "a" * 64
    launch = analyze("docker", ["run", "--mount", mount, image])
    assert bool(launch.context.get("host_mounts")) is host_mount


def test_registry_and_settings_reports_share_the_selected_scope(tmp_path):
    server = {"command": "npx", "args": ["-y", "@acme/files-mcp@1.0.0"]}
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": server}}))
    (tmp_path / ".npmrc").write_text(
        "scope=@docs\n@docs:registry=https://registry.example/\n"
        "@unused:registry=https://unused.example/\n"
    )
    result = MCPScanner().scan(tmp_path)
    (component,) = [c for c in result.components if isinstance(c, MCPServerComponent)]
    assert (
        ".npmrc:@docs:registry=https://registry.example" in component.properties["package_sources"]
    )
    assert ".npmrc:@docs:registry" in component.properties["resolver_settings"]
    assert ".npmrc:@unused:registry" not in component.properties["resolver_settings"]
