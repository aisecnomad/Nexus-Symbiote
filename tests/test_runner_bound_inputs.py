"""Coverage and digest evidence from inert package-runner declarations."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.control_plane_audit import audit_project_control_plane


def _declare(root, argv, surface="hook"):
    root.mkdir(exist_ok=True)
    if surface == "hook":
        folder = root / ".claude"
        folder.mkdir(exist_ok=True)
        (folder / "settings.json").write_text(
            json.dumps({"hooks": {"PreToolUse": [{"command": " ".join(argv)}]}})
        )
    else:
        (root / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"example": {"command": argv[0], "args": argv[1:]}}})
        )


@pytest.mark.parametrize("surface", ["hook", "mcp"])
@pytest.mark.parametrize(
    "options",
    [
        ["-r", "./pre.cjs"],
        ["--require=./pre.cjs"],
        ["--import", "./pre.cjs"],
        ["--loader=./pre.cjs"],
        ["-r./pre.cjs"],
    ],
)
def test_a_changed_preload_is_bound_alongside_the_entry_script(tmp_path, surface, options):
    for name in ("before", "after"):
        root = tmp_path / name
        _declare(root, ["npx", "tsx", *options, "./app.ts"], surface)
        (root / "pre.cjs").write_text("// ordinary " + name)
        (root / "app.ts").write_text("// stable example")
    summary = audit_project_control_plane(tmp_path / "after", baseline_root=tmp_path / "before")
    targets = summary.hook_targets if surface == "hook" else summary.launcher_targets
    assert {row["target_path"] for row in targets} == {"app.ts", "pre.cjs"}
    assert any(row["root_cause"] == "launch_target_changed" for row in summary.reach_alerts)


@pytest.mark.parametrize(
    "argv",
    [
        ["npx", "tsx", "$PWD/sample.ts"],
        ["uvx", "python", "~/sample.py"],
        ["npx", "tsx", "./directory"],
        ["uvx", "python", "./alias"],
        ["uvx", "--from", "./directory", "entry"],
        ["npx", "-p", "./directory", "entry"],
        ["npx", "-p./directory", "entry"],
        ["npx", "file:./directory"],
        ["npx", "."],
        ["npx", "tsx", "--import", "sample-module", "./app.ts"],
    ],
)
def test_unestablished_entry_or_preload_is_a_coverage_gap(tmp_path, argv):
    _declare(tmp_path, argv)
    (tmp_path / "directory").mkdir()
    (tmp_path / "alias").symlink_to("directory", target_is_directory=True)
    (tmp_path / "app.ts").write_text("// stable")
    summary = audit_project_control_plane(tmp_path)
    assert summary.gaps
    gate = CliRunner().invoke(main, ["audit-control-plane", str(tmp_path)])
    assert gate.exit_code == 1, gate.output


@pytest.mark.parametrize("suffix", ["mts", "cts", "tsx", "jsx"])
def test_an_unlisted_at_prefixed_script_is_still_reported(tmp_path, suffix):
    _declare(tmp_path, ["npx", "tsx", "@samples/note." + suffix])
    summary = audit_project_control_plane(tmp_path)
    assert summary.gaps or any(f["category"] == "hook_target_missing" for f in summary.findings)


@pytest.mark.parametrize(
    "argv",
    [
        ["uvx", "sample-server", "--db-path", "data.db"],
        ["uvx", "sample-server", "data.db"],
        ["npx", "sample-server", "--config", "parameters.yaml"],
        ["npx", "sample-server", "--sample-data", "./parameters.yaml"],
        ["npx", "@modelcontextprotocol/server-filesystem", "./node_modules"],
        ["npx", "@modelcontextprotocol/server-filesystem", "./.venv"],
    ],
)
def test_data_operands_and_reference_server_roots_are_not_script_inputs(tmp_path, argv):
    _declare(tmp_path, argv, "mcp")
    (tmp_path / "data.db").write_text("ordinary data")
    (tmp_path / "parameters.yaml").write_text("rows: 1")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / ".venv").mkdir()
    summary = audit_project_control_plane(tmp_path)
    assert not summary.launcher_targets and not summary.gaps


@pytest.mark.parametrize("command", [["npx", "tsx"], ["node"]])
def test_multiple_preloads_are_deduplicated_without_replacing_the_primary(tmp_path, command):
    args = [*command, "--import=./one.mjs", "-r", "./two.cjs", "-r./two.cjs", "./app.js"]
    _declare(tmp_path, args, "mcp")
    for path in ("one.mjs", "two.cjs", "app.js"):
        (tmp_path / path).write_text("// " + path)
    summary = audit_project_control_plane(tmp_path)
    assert [row["target_path"] for row in summary.launcher_targets] == [
        "app.js",
        "one.mjs",
        "two.cjs",
    ]
    server = next(component for component in summary.bom.components if component.name == "example")
    assert server.properties["launch_target"] == summary.launcher_targets[0]["launch_target_sha256"]
