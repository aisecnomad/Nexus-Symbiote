"""Adversarial contract tests for the composite Action's actual runner."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SPEC = importlib.util.spec_from_file_location(
    "action_runner", Path(__file__).parents[1] / "scripts" / "run_action.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def configuration(tmp_path: Path, **inputs: str):
    return runner.Config.from_env({"GITHUB_WORKSPACE": str(tmp_path), **inputs})


@pytest.mark.parametrize("payload", ["$(touch PWNED)", "quote'and\"space", "--scanner=none"])
def test_path_input_is_one_literal_argument_and_collection_runs_once(tmp_path, payload):
    (tmp_path / payload).mkdir()
    config = configuration(tmp_path, SYMBIOTE_SCAN_PATH=payload, SYMBIOTE_SARIF="true")
    calls = []
    exports = []

    def command(args):
        calls.append(args)
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, '{"overall_score": 0}', "")

    def export(native, output, fmt):
        exports.append((native.read_text(), fmt))
        output.write_text("evidence")

    assert runner.run(config, command=command, export=export) == 0
    assert [c[0] for c in calls] == ["scan", "validate", "risk"]
    assert calls[0][-2:] == ["--", str(tmp_path / payload)]
    assert exports == [("{}", "json"), ("{}", "sarif")]
    assert not (tmp_path / "PWNED").exists()


def test_command_runner_never_uses_shell(monkeypatch):
    captured = {}

    def invoke(args, **kwargs):
        captured.update(args=args, kwargs=kwargs)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner.subprocess, "run", invoke)
    runner._run(["scan", "$(touch PWNED)"])
    assert captured["args"] == [
        sys.executable,
        "-I",
        "-m",
        "nexus_symbiote",
        "scan",
        "$(touch PWNED)",
    ]
    assert captured["kwargs"].get("shell", False) is False


@pytest.mark.parametrize("status", [1, 7])
def test_validation_failure_fails_action_and_preserves_export(tmp_path, status):
    config = configuration(tmp_path)
    calls = []

    def command(args):
        calls.append(args[0])
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(
            args, status if args[0] == "validate" else 0, "", "failed"
        )

    outputs = tmp_path / "outputs"
    assert runner.run(config, command=command, outputs=outputs) == 1
    assert calls == ["scan", "validate"]
    assert config.output.exists()
    assert "aibom_path=" in outputs.read_text()


@pytest.mark.parametrize("report", ["{}", '{"overall_score": "0"}', '{"overall_score": NaN}'])
def test_malformed_risk_report_never_becomes_zero_score(tmp_path, report):
    config = configuration(tmp_path, SYMBIOTE_VALIDATE="false")

    def command(args):
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, report, "")

    with pytest.raises(ValueError):
        runner.run(config, command=command)


@pytest.mark.parametrize(
    "key,value",
    [
        ("SYMBIOTE_FORMAT", "json; echo injected"),
        ("SYMBIOTE_SCANNERS", "mcp,$(whoami)"),
        ("SYMBIOTE_SCANNERS", "mcp,mcp"),
        ("SYMBIOTE_VALIDATE", "yes"),
        ("SYMBIOTE_RISK_THRESHOLD", "NaN"),
        ("SYMBIOTE_RISK_THRESHOLD", "-1"),
        ("SYMBIOTE_RISK_THRESHOLD", "101"),
        ("SYMBIOTE_OUTPUT_FILE", "../outside"),
        ("SYMBIOTE_OUTPUT_FILE", "*"),
        ("SYMBIOTE_OUTPUT_FILE", "[a-z]"),
        ("SYMBIOTE_OUTPUT_FILE", "!exclude"),
        ("SYMBIOTE_OUTPUT_FILE", "artifact\ninjected=value"),
    ],
)
def test_invalid_input_fails_before_collection(tmp_path, key, value):
    with pytest.raises(ValueError):
        configuration(tmp_path, **{key: value})


def test_output_symlink_outside_workspace_is_refused(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "escape").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        configuration(workspace, SYMBIOTE_OUTPUT_FILE="escape/result")


def test_action_expressions_are_never_embedded_in_shell_source():
    action = yaml.safe_load((Path(__file__).parents[1] / "action.yml").read_text())
    for step in action["runs"]["steps"]:
        if "run" in step:
            assert "${{" not in step["run"]
            assert "|| true" not in step["run"]
    install = next(
        s for s in action["runs"]["steps"] if s.get("name") == "Install reviewed Action source"
    )
    assert '"$SYMBIOTE_ACTION_PATH"' in install["run"]


def test_workflow_pins_structure_and_release_privilege_separation():
    checker_spec = importlib.util.spec_from_file_location(
        "workflow_checker", Path(__file__).parents[1] / "scripts" / "check_workflows.py"
    )
    assert checker_spec is not None and checker_spec.loader is not None
    checker = importlib.util.module_from_spec(checker_spec)
    checker_spec.loader.exec_module(checker)
    root = Path(__file__).parents[1]
    workflows = root / ".github/workflows"
    for path in [root / "action.yml", *workflows.glob("*.yml"), *workflows.glob("*.yaml")]:
        assert checker.check(path) == []
    release = yaml.safe_load((root / ".github/workflows/release.yml").read_text())
    events = release.get("on", release.get(True))
    assert set(events) == {"workflow_dispatch"}
    publish_input = events["workflow_dispatch"]["inputs"]["publish"]
    assert publish_input["type"] == "choice"
    assert publish_input["options"] == ["none", "testpypi", "pypi"]
    assert publish_input["default"] == "none"
    jobs = release["jobs"]
    assert jobs["build"]["permissions"] == {"contents": "read", "actions": "read"}
    build_steps = jobs["build"]["steps"]
    build_commands = [step.get("run", "") for step in build_steps]
    assert any("--require-hashes -r requirements-ci.lock" in command for command in build_commands)
    build = next(s for s in build_steps if s.get("run") == "python -m build --no-isolation")
    assert build["working-directory"].endswith("/release-source")
    assert any("git archive" in command for command in build_commands)

    def index(predicate):
        return next(i for i, step in enumerate(build_steps) if predicate(step))

    upload = index(lambda s: s.get("name") == "Upload distributions")
    # The attested bytes are uploaded before anything runs tests, writes evidence
    # or installs packages into the evidence environment.
    assert upload < index(lambda s: s.get("run") == "python -m pytest")
    assert upload < index(lambda s: "evidence/" in s.get("run", ""))
    assert upload < index(lambda s: 'release-smoke/bin/python" -m pip install' in s.get("run", ""))
    assert jobs["publish"]["environment"]["name"] == "${{ inputs.publish }}"
    assert jobs["publish"]["if"].startswith("inputs.publish != 'none'")
    publish_step = next(s for s in jobs["publish"]["steps"] if "pypi-publish" in s["uses"])
    assert "test.pypi.org/legacy/" in publish_step["with"]["repository-url"]
    assert "upload.pypi.org/legacy/" in publish_step["with"]["repository-url"]
    assert set(jobs["publish"]["needs"]) == {"build", "attest", "verify"}
    assert jobs["publish"]["permissions"] == {"id-token": "write"}
    assert "id-token" not in jobs["verify"]["permissions"]
    for name in ["compatibility", "attest", "verify", "publish"]:
        downloads = [s for s in jobs[name]["steps"] if "download-artifact" in s.get("uses", "")]
        assert downloads
        assert all(s["with"]["digest-mismatch"] == "error" for s in downloads)
    for name in ["attest", "publish"]:
        assert all("run" not in step for step in jobs[name]["steps"])


def test_release_floating_dependencies_cannot_replace_attestation_or_publication_inputs():
    path = Path(__file__).parents[1] / ".github/workflows/release.yml"
    jobs = yaml.safe_load(path.read_text())["jobs"]
    build = jobs["build"]
    compatibility = jobs["compatibility"]
    assert compatibility["needs"] == "build"
    assert compatibility["permissions"] == {}
    assert "outputs" not in compatibility
    assert set(jobs["attest"]["needs"]) == {"build", "compatibility"}

    for step in build["steps"]:
        for command in step.get("run", "").splitlines():
            if "pip install" in command:
                assert "--require-hashes" in command or "--no-deps" in command
    assert any("pip install dist/*.whl" in step.get("run", "") for step in compatibility["steps"])

    for output, step_id in [("distributions_id", "distributions"), ("evidence_id", "evidence")]:
        assert build["outputs"][output] == "${{ steps." + step_id + ".outputs.artifact-id }}"
        upload = next(s for s in build["steps"] if s.get("id") == step_id)
        assert upload["uses"].startswith("actions/upload-artifact@")
        assert upload["with"]["if-no-files-found"] == "error"

    for job, paths in [
        ("compatibility", ["dist"]),
        ("attest", ["dist", "evidence"]),
        ("publish", ["dist"]),
    ]:
        downloads = [
            s["with"]
            for s in jobs[job]["steps"]
            if s.get("uses", "").startswith("actions/download-artifact@")
        ]
        assert [d["path"] for d in downloads] == paths
        for download in downloads:
            output = "distributions_id" if download["path"] == "dist" else "evidence_id"
            # The pinned downloader selects *all* artifacts for an empty ID.
            assert (
                download["artifact-ids"] == "${{ needs.build.outputs." + output + " || 'missing' }}"
            )


@pytest.mark.parametrize("validate", [True, False])
def test_real_entry_point_ignores_untrusted_python_path_and_policy(tmp_path, validate):
    project = tmp_path / "$(touch PWNED)'quoted space"
    project.mkdir()
    package_root = tmp_path / "stub"
    package = package_root / "nexus_symbiote"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "__main__.py").write_text(
        "from pathlib import Path\nPath('PWNED').write_text('shadowed')\n"
    )
    (package_root / "sitecustomize.py").write_text(
        "from pathlib import Path\nPath('PWNED').write_text('startup')\n"
    )
    (project / ".nexus-symbiote.yaml").write_text(
        "scan:\n  scanners: [prompt]\nvalidate:\n  require_completeness: false\n  require_integrity: false\n"
    )
    (project / "CLAUDE.md").write_text("Review issues with read-only tools.\n")
    (project / "model.pkl").write_bytes(b"unsafe-format-fixture")
    env = {
        **os.environ,
        "GITHUB_WORKSPACE": str(tmp_path),
        "SYMBIOTE_SCAN_PATH": project.name,
        "SYMBIOTE_SCANNERS": "",
        "SYMBIOTE_FORMAT": "json",
        "SYMBIOTE_VALIDATE": str(validate).lower(),
        "SYMBIOTE_RISK_CHECK": "false",
        "SYMBIOTE_RISK_THRESHOLD": "50",
        "SYMBIOTE_SARIF": "false",
        "SYMBIOTE_OUTPUT_FILE": "result.json",
        "GITHUB_OUTPUT": str(tmp_path / "action-outputs"),
        "PYTHONPATH": str(package_root),
    }
    entry = Path(__file__).parents[1] / "scripts" / "run_action.py"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(entry)], cwd=tmp_path, env=env, capture_output=True, check=False
    )
    assert result.returncode == (1 if validate else 0)
    assert not (tmp_path / "PWNED").exists()
    models = [
        c
        for c in json.loads((tmp_path / "result.json").read_text())["components"]
        if c["component_type"] == "model"
    ]
    assert [c["serialization_safety"] for c in models] == ["unsafe-code-execution"]


@pytest.mark.parametrize("extension", ["yml", "yaml"])
def test_workflow_checker_main_rejects_unsafe_workflows_under_either_extension(
    tmp_path, monkeypatch, extension
):
    spec = importlib.util.spec_from_file_location(
        "workflow_checker_main", Path(__file__).parents[1] / "scripts" / "check_workflows.py"
    )
    assert spec is not None and spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    root = Path(__file__).parents[1]
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / "action.yml").write_text((root / "action.yml").read_text())
    workflow = tmp_path / ".github/workflows" / f"untrusted.{extension}"
    workflow.write_text(
        "on: pull_request\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo ${{ github.head_ref }}\n"
    )
    monkeypatch.chdir(tmp_path)
    assert checker.main() == 1
    workflow.write_text(
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 5\n"
        "    steps:\n"
        "      - run: echo safe\n"
    )
    assert checker.main() == 0


def workflow_checker():
    spec = importlib.util.spec_from_file_location(
        "workflow_checker_policy", Path(__file__).parents[1] / "scripts" / "check_workflows.py"
    )
    assert spec is not None and spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    return checker


SAFE_WORKFLOW = """\
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: echo safe
"""
SCRIPT_ACTION = "actions/github-script@" + "0" * 40
TRIGGERS = "only push, pull_request, schedule and workflow_dispatch triggers are allowed"
PERMISSIONS = "top-level permissions must be an explicit read-only mapping"
TIMEOUT = "test must set a positive integer timeout-minutes"
RUNNER = "test must run on GitHub-hosted runner labels"
CREDENTIALS = "actions/checkout must set persist-credentials: false"
ENVIRONMENT_FILE = "untrusted context must not reach GITHUB_ENV or GITHUB_PATH"


@pytest.mark.parametrize(
    ("old", "new", "error"),
    [
        ("on: pull_request", "on: [push, pull_request_target]", TRIGGERS),
        ("on: pull_request", "on:\n  workflow_run:\n    workflows: [CI]", TRIGGERS),
        ("on: pull_request", "on: issue_comment", TRIGGERS),
        ("permissions:\n  contents: read\n", "", PERMISSIONS),
        ("permissions:\n  contents: read\n", "permissions: write-all\n", PERMISSIONS),
        ("contents: read", "contents: write", PERMISSIONS),
        ("    timeout-minutes: 5\n", "", TIMEOUT),
        ("    timeout-minutes: 5\n", "    timeout-minutes: '${{ inputs.minutes }}'\n", TIMEOUT),
        ("runs-on: ubuntu-latest", "runs-on: [self-hosted, linux]", RUNNER),
        # A self-hosted runner can be selected by a custom label alone.
        ("runs-on: ubuntu-latest", "runs-on: gpu-builder", RUNNER),
        ("        with:\n          persist-credentials: false\n", "", CREDENTIALS),
        ("persist-credentials: false", "persist-credentials: true", CREDENTIALS),
        (
            "      - run: echo safe\n",
            f"      - uses: {SCRIPT_ACTION}\n"
            "        with:\n"
            "          script: console.log('${{ github.event.issue.title }}')\n",
            "pass expressions through env, never script source",
        ),
        (
            "      - run: echo safe\n",
            "      - env:\n"
            "          TITLE: ${{ github.event.pull_request.title }}\n"
            '        run: echo "TITLE=$TITLE" >> "$GITHUB_ENV"\n',
            ENVIRONMENT_FILE,
        ),
        (
            "    steps:\n",
            "    env:\n"
            "      BRANCH: ${{ github.head_ref }}\n"
            "    steps:\n"
            '      - run: echo "$BRANCH" >> "$GITHUB_PATH"\n',
            ENVIRONMENT_FILE,
        ),
    ],
)
def test_workflow_checker_rejects_privileged_unbounded_or_injectable_jobs(
    tmp_path, old, new, error
):
    checker = workflow_checker()
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(SAFE_WORKFLOW)
    assert checker.check(workflow) == []
    assert old in SAFE_WORKFLOW
    workflow.write_text(SAFE_WORKFLOW.replace(old, new, 1))
    assert checker.check(workflow) == [f"{workflow}: {error}"]


def test_workflow_checker_rejects_action_inputs_reaching_environment_files(tmp_path):
    checker = workflow_checker()
    action = yaml.safe_load((Path(__file__).parents[1] / "action.yml").read_text())
    path = tmp_path / "action.yml"
    path.write_text(yaml.safe_dump(action))
    assert checker.check(path) == []
    install = next(s for s in action["runs"]["steps"] if "GITHUB_PATH" in s.get("run", ""))
    install["env"]["SYMBIOTE_VENV_HINT"] = "${{ inputs.scan-path }}"
    path.write_text(yaml.safe_dump(action))
    assert checker.check(path) == [f"{path}: {ENVIRONMENT_FILE}"]
