"""Regression tests for repository hygiene, lockfile, workflow, and tag-ruleset gate hardenings."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

from tests.support import ROOT, load_script

workflows_checker = load_script("check_workflows")
locks_checker = load_script("check_locks")
hygiene_checker = load_script("check_repository_hygiene")
controls_checker = load_script("check_repository_controls")


@pytest.mark.parametrize(
    "bad_flag",
    [
        "--deselect=tests/test_security.py",
        "--ignore=tests",
        "--ignore-glob=tests/*.py",
        "-p no:timeout",
        "-pno:timeout",
        "--plugin=evil",
        "-o python_files=none.py",
        "-opython_files=none.py",
        "--override-ini=addopts=--collect-only",
        "-o",
    ],
)
def test_c207_01_workflow_gate_rejects_test_skipping_pytest_flags(bad_flag: str) -> None:
    parts = bad_flag.split()
    gate = workflows_checker._Gate(
        "python",
        ["-m", "pytest", "--strict-skips", *parts],
        [],
    )
    assert gate.runs("python -m pytest") is False
    assert gate.runs("--strict-skips") is False


def test_c207_01_workflow_gate_allows_timeout_ini_overrides_and_non_pytest_flags() -> None:
    pytest_gate = workflows_checker._Gate(
        "python",
        [
            "-m",
            "pytest",
            "-n",
            "auto",
            "--dist",
            "worksteal",
            "--strict-skips",
            "-o",
            "test_timeout=120",
            "-o",
            "faulthandler_timeout=115",
        ],
        [],
    )
    assert pytest_gate.runs("python -m pytest") is True
    assert pytest_gate.runs("--strict-skips") is True

    cli_gate = workflows_checker._Gate(
        "python",
        ["-m", "nexus_symbiote", "scan", ".", "-o", "out.json"],
        [],
    )
    assert cli_gate.runs("-m nexus_symbiote") is True


def test_c207_01_verified_ci_step_is_pinned_in_reviewed_gate_steps(tmp_path: Path) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    workflow["jobs"]["verified"]["steps"][0]["run"] = (
        "python -c 'import sys; failed = []; sys.exit(bool(failed))'\n"
    )
    target = tmp_path / "ci.yml"
    target.write_text(yaml.safe_dump(workflow), encoding="utf-8")
    errors = workflows_checker.check(target)
    assert any(
        "verified runs sys.exit(bool(failed)) other than in its reviewed step" in err
        for err in errors
    ), errors


def test_eba4b73b_locks_checker_forbids_uv_sources_offline_and_passes_no_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (
        "pyproject.toml",
        "requirements-ci.lock",
        "requirements-action.lock",
        "requirements-floor.lock",
    ):
        (tmp_path / name).write_text((ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
    with (tmp_path / "pyproject.toml").open("a", encoding="utf-8") as handle:
        handle.write('\n[tool.uv.sources]\nrequests = { index = "https://evil.invalid/simple" }\n')
    issues = locks_checker.check(tmp_path)
    assert any("[tool.uv.sources] is forbidden" in issue for issue in issues), issues

    source_text = (ROOT / "scripts/check_locks.py").read_text(encoding="utf-8")
    assert '"--no-sources"' in source_text


def test_e156_01_repository_hygiene_flags_u0085_next_line(tmp_path: Path) -> None:
    assert hygiene_checker._hidden("\u0085") is True
    doc = tmp_path / "README.md"
    doc.write_text("Visible heading\u0085hidden continuation\n", encoding="utf-8")
    issues = hygiene_checker.hidden_character_issues(tmp_path, [Path("README.md")])
    assert len(issues) == 1
    assert "U+0085" in issues[0]


def test_b169_01_standalone_tag_creation_ruleset_without_bypass_actors_fails() -> None:
    immutability = {
        "id": 1,
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
        "rules": [{"type": "update"}, {"type": "deletion"}],
        "bypass_actors": [],
        "current_user_can_bypass": "never",
    }
    deadlocked_creation = {
        "id": 2,
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
        "rules": [{"type": "creation"}],
        "bypass_actors": [],
        "current_user_can_bypass": "never",
    }
    errors, _ = controls_checker.evaluate_tag_rulesets([immutability, deadlocked_creation])
    assert any("blocking all v* tag creation" in err for err in errors), errors

    authorized_creation = {
        **deadlocked_creation,
        "bypass_actors": [{"actor_id": 1, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
    }
    ok_errors, ok_notices = controls_checker.evaluate_tag_rulesets(
        [immutability, authorized_creation]
    )
    assert ok_errors == []
    assert ok_notices == []


def test_d304_01_offline_invariant_and_auxiliary_workflows_parallelize_and_align_timeouts() -> None:
    ini = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    options = ini["tool"]["pytest"]["ini_options"]
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    deps = yaml.safe_load((ROOT / ".github/workflows/dependencies.yml").read_text(encoding="utf-8"))
    rel = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))

    offline_runs = [
        s["run"]
        for s in ci["jobs"]["offline-invariant"]["steps"]
        if "-m pytest" in s.get("run", "")
    ]
    assert len(offline_runs) == 1
    limit = re.search(r"-o test_timeout=(\d+)", offline_runs[0])
    dump = re.search(r"-o faulthandler_timeout=(\d+)", offline_runs[0])
    test_timeout = int(limit.group(1) if limit else options["test_timeout"])
    faulthandler = int(dump.group(1) if dump else options["faulthandler_timeout"])
    assert 0.9 * test_timeout <= faulthandler <= test_timeout

    newest_runs = [
        s["run"] for s in deps["jobs"]["newest"]["steps"] if "pytest" in s.get("run", "")
    ]
    assert len(newest_runs) == 1 and "-n auto --dist worksteal" in newest_runs[0]

    release_runs = [s["run"] for s in rel["jobs"]["build"]["steps"] if "pytest" in s.get("run", "")]
    assert len(release_runs) == 1 and "-n auto --dist worksteal" in release_runs[0]
