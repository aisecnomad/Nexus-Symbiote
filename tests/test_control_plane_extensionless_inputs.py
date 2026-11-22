"""Static launch binding for extensionless files, dependency imports and data directories."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.control_plane_audit import audit_project_control_plane
from tests.test_runner_bound_inputs import _declare


@pytest.mark.parametrize("option", ["--inspect", "--experimental-strip-types", "--future-option"])
@pytest.mark.parametrize("operand", ["hooks/note", "note"])
def test_runtime_options_keep_extensionless_project_file_visible(tmp_path, option, operand):
    for root in (tmp_path / "before", tmp_path / "after"):
        _declare(root, ["npx", "tsx", option, operand])
        target = root / operand
        target.parent.mkdir(exist_ok=True, parents=True)
        target.write_text("# " + root.name + "\n")
    result = audit_project_control_plane(tmp_path / "after", baseline_root=tmp_path / "before")
    if option == "--future-option":
        assert any("option arity" in gap for gap in result.gaps)
    else:
        assert any(t["target_path"] == operand for t in result.hook_targets)
        assert any(a["root_cause"] == "launch_target_changed" for a in result.reach_alerts)


@pytest.mark.parametrize("surface", ["hook", "mcp"])
def test_extensionless_scoped_script_through_a_directory_link(tmp_path, surface):
    _declare(tmp_path, ["npx", "tsx", "@sample/note"], surface)
    real = tmp_path / "notes"
    real.mkdir()
    (real / "note").write_text("# ordinary inert file\n")
    (tmp_path / "@sample").symlink_to("notes", target_is_directory=True)
    result = audit_project_control_plane(tmp_path)
    targets = result.hook_targets if surface == "hook" else result.launcher_targets
    assert any(t["target_path"] == "@sample/note" for t in targets) or result.gaps


@pytest.mark.parametrize(
    ("program", "prefix", "option", "specifier"),
    [
        ("node", [], "-r", "dotenv/config"),
        ("node", [], "--import", "tsx"),
        ("node", [], "--loader", "ts-node/esm"),
        ("npx", ["tsx"], "--import", "sample-module"),
        ("npx", ["tsx"], "--require", "@sample/config/options"),
    ],
)
def test_registry_module_preloads_leave_the_project_entry_bound(
    tmp_path, program, prefix, option, specifier
):
    _declare(tmp_path, [program, *prefix, option, specifier, "./app.js"], "mcp")
    (tmp_path / "app.js").write_text("// ordinary application")
    result = audit_project_control_plane(tmp_path)
    assert [t["target_path"] for t in result.launcher_targets] == ["app.js"]
    assert not result.gaps
    gate = CliRunner().invoke(main, ["audit-control-plane", str(tmp_path)])
    assert gate.exit_code == 0, gate.output


@pytest.mark.parametrize(
    "specifier", ["../note.mjs", "file:../note.mjs", "$MODE/note", "@scope", "pkg/../note"]
)
def test_an_unresolved_preload_keeps_a_gap(tmp_path, specifier):
    _declare(tmp_path, ["node", "--import", specifier, "./app.js"], "mcp")
    (tmp_path / "app.js").write_text("// ordinary application")
    result = audit_project_control_plane(tmp_path)
    assert any("preload target is unresolved" in gap for gap in result.gaps)


@pytest.mark.parametrize("package", ["@cyanheads/filesystem-mcp", "sample-data-server@1.0.0"])
def test_directory_argument_of_a_registry_application_is_data(tmp_path, package):
    _declare(tmp_path, ["npx", "-y", package, "./data"], "mcp")
    (tmp_path / "data").mkdir()
    (tmp_path / "data/note.txt").write_text("public notes")
    result = audit_project_control_plane(tmp_path)
    assert not result.gaps and not result.launcher_targets


@pytest.mark.parametrize("package", ["tsx", "ts-node", "@babel/node"])
def test_directory_argument_of_a_script_runner_still_needs_an_entry(tmp_path, package):
    _declare(tmp_path, ["npx", package, "./data"], "mcp")
    (tmp_path / "data").mkdir()
    result = audit_project_control_plane(tmp_path)
    assert any("directory entry point" in gap for gap in result.gaps)


@pytest.mark.parametrize(
    ("manifest", "expect_gap"),
    [
        ({"name": "sample", "exports": {"./setup": "./setup.mjs"}}, True),
        ({"dependencies": {"sample": "file:./packages/sample"}}, True),
        ({"workspaces": ["packages/*"]}, True),
        ({"name": "unrelated", "dependencies": {"sample": "^1.0.0"}}, False),
    ],
)
def test_checkout_package_bindings_are_not_assumed_external(tmp_path, manifest, expect_gap):
    _declare(tmp_path, ["node", "--import", "sample/setup", "./app.js"], "mcp")
    (tmp_path / "package.json").write_text(json.dumps(manifest))
    (tmp_path / "app.js").write_text("// ordinary application")
    result = audit_project_control_plane(tmp_path)
    assert any("preload target is unresolved" in gap for gap in result.gaps) is expect_gap
    assert [t["target_path"] for t in result.launcher_targets] == ["app.js"]
