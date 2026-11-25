"""scripts/check_workflows.py: pins, local actions, privilege and hollowed gates."""

from __future__ import annotations

import re
import shutil

import pytest
import yaml

from tests.support import ROOT, load_script

checker = load_script("check_workflows")
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
SAFE = f"""on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: {CHECKOUT}
        with:
          persist-credentials: false
      - run: echo safe
"""


@pytest.fixture
def repository(tmp_path, monkeypatch):
    (tmp_path / ".github/workflows").mkdir(parents=True)
    shutil.copyfile(ROOT / "action.yml", tmp_path / "action.yml")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run_checker(repository, workflow, capsys):
    (repository / ".github/workflows/untrusted.yml").write_text(workflow)
    status = checker.main()
    return status, capsys.readouterr().out


def test_the_repository_workflows_and_action_pass(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    assert checker.main() == 0, capsys.readouterr().out


def test_a_tree_without_workflows_fails_instead_of_passing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert checker.main() == 1
    assert "no workflow found" in capsys.readouterr().out


@pytest.mark.parametrize(
    "script",
    [
        'PY=python3\nPY+=" -c pass"\n$PY scripts/check_locks.py',
        "PY=python3\nPY[0]=echo\n$PY scripts/check_locks.py",
    ],
)
def test_appending_to_or_indexing_a_command_variable_forgets_its_value(tmp_path, script):
    errors = workflow_errors(tmp_path, "ci.yml", run_locks(script))
    assert any(NOT_A_GATE in error for error in errors), errors


def test_a_here_document_before_the_command_name_is_read(tmp_path):
    script = "<<EOF cat\nnotes\nEOF\npython scripts/check_locks.py"
    assert workflow_errors(tmp_path, "ci.yml", run_locks(script)) == []


def test_a_reviewed_workflow_passes(repository, capsys):
    assert run_checker(repository, SAFE, capsys) == (0, "")


@pytest.mark.parametrize(
    "change,message",
    [
        (("on: pull_request", "on: pull_request_target"), "triggers must be among"),
        (("on: pull_request", "on: [workflow_run]"), "triggers must be among"),
        (("permissions:\n  contents: read\n", ""), "top-level permissions"),
        (("  contents: read", "  contents: write"), "top-level permissions"),
        (("    timeout-minutes: 5\n", ""), "timeout-minutes"),
        (
            ("          persist-credentials: false\n", "          fetch-depth: 0\n"),
            "persist-credentials",
        ),
        (("# v7.0.1", ""), "full version comment"),
        (("# v7.0.1", "# v6.0.0"), "older than its floor"),
        (("echo safe", "echo ${{ github.head_ref }}"), "never shell source"),
    ],
)
def test_privileged_triggers_write_tokens_and_unbounded_jobs_are_rejected(
    repository, capsys, change, message
):
    old, new = change
    assert old in SAFE
    status, output = run_checker(repository, SAFE.replace(old, new, 1), capsys)
    assert status == 1
    assert message in output


def test_one_commit_cannot_carry_two_version_labels(repository, capsys):
    workflow = SAFE + f"      - uses: {CHECKOUT.replace('v7.0.1', 'v7.0.9')}\n"
    status, output = run_checker(repository, workflow, capsys)
    assert status == 1 and "is labelled" in output


def test_a_pin_the_version_check_cannot_read_is_rejected(repository, capsys):
    pin = CHECKOUT.split(" #", 1)[0]
    workflow = SAFE + f"      - {{uses: {pin}, with: {{persist-credentials: false}}}}\n"
    status, output = run_checker(repository, workflow, capsys)
    assert status == 1 and "write each pinned uses on a line of its own" in output


def test_a_local_action_is_checked_like_any_other(repository, capsys):
    action = repository / ".github/actions/setup"
    action.mkdir(parents=True)
    (action / "action.yml").write_text(
        "name: setup\nruns:\n  using: composite\n  steps:\n"
        "    - uses: some-org/some-action@main\n"
        "    - run: echo ${{ github.event.pull_request.title }}\n      shell: bash\n"
    )
    workflow = SAFE + "      - uses: ./.github/actions/setup\n"
    status, output = run_checker(repository, workflow, capsys)
    assert status == 1
    assert "pinned to a commit: some-org/some-action@main" in output
    assert "never shell source" in output


def test_a_missing_local_action_is_rejected(repository, capsys):
    status, output = run_checker(repository, SAFE + "      - uses: ./tools/absent\n", capsys)
    assert status == 1 and "does not exist" in output


def ci_workflow():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())


@pytest.mark.parametrize(
    "job,command",
    [
        ("dependency-audit", "scripts/check_dependency_advisories.py"),
        ("codeql", "scripts/check_codeql_sarif.py"),
        ("floor", "requirements-floor.lock"),
        ("test", "--strict-skips"),
        ("macos", "--strict-skips"),
        ("quality", "scripts/check_locks.py"),
        ("action", "sys.exit(bool(failures))"),
        ("action-annotations", "symbiote-injected-annotation"),
        ("action-annotations", "set-output"),
        ("verified", "sys.exit(bool(failed))"),
        ("offline-invariant", "requirements-ci.lock"),
        ("offline-invariant", "unshare --net"),
        ("distribution", "scripts/check_image.py"),
    ],
)
def test_a_gate_job_hollowed_out_under_its_name_is_rejected(tmp_path, job, command):
    workflow = ci_workflow()
    for step in workflow["jobs"][job]["steps"]:
        if command in step.get("run", ""):
            step["run"] = "true"
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any(f"{job} no longer runs {command}" in error for error in checker.check(path))


@pytest.mark.parametrize(
    "job,command",
    [
        ("build", "--strict-skips"),
        ("build", "scripts/check_image.py"),
        ("build", "scripts/image_base_updates.py"),
        ("verify", "gh attestation verify"),
        ("image", "scripts/check_image.py"),
        ("image-verify", "gh attestation verify"),
    ],
)
def test_a_release_gate_hollowed_out_under_its_name_is_rejected(tmp_path, job, command):
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    for step in workflow["jobs"][job]["steps"]:
        if command in step.get("run", ""):
            step["run"] = step["run"].replace(command, "true")
    path = tmp_path / "release.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any(f"{job} no longer runs {command}" in error for error in checker.check(path))


def test_a_workflow_named_like_an_action_is_still_checked_as_a_workflow(repository, capsys):
    (repository / ".github/workflows/action.yml").write_text(
        SAFE.replace("on: pull_request", "on: pull_request_target")
    )
    status = checker.main()
    assert status == 1
    assert "triggers must be among" in capsys.readouterr().out


def workflow_errors(tmp_path, name, change):
    """The checker's errors for the repository's workflow `name` after `change` edits it."""
    workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
    change(workflow["jobs"])
    path = tmp_path / name
    path.write_text(yaml.safe_dump(workflow))
    return checker.check(path)


def step_running(job, command):
    return next(step for step in job["steps"] if command in step.get("run", step.get("uses", "")))


def condition(job, command, value):
    def change(jobs):
        step_running(jobs[job], command)["if"] = value

    return change


@pytest.mark.parametrize(
    "name,job,command,value",
    [
        ("ci.yml", "test", "python -m pytest", False),
        ("ci.yml", "quality", "mypy src/nexus_symbiote scripts", "false"),
        ("ci.yml", "quality", "scripts/check_workflows.py", "${{ false }}"),
        ("ci.yml", "coverage", "scripts/check_coverage.py", "github.event_name == 'never'"),
        ("ci.yml", "codeql", "github/codeql-action/init@", False),
        ("ci.yml", "action", "sys.exit(bool(failures))", False),
        ("ci.yml", "action-annotations", "symbiote-injected-annotation", "failure()"),
        (
            "release.yml",
            "build",
            "scripts/check_repository_controls.py",
            "inputs.publish == 'never'",
        ),
        # The preflight's reviewed condition does not carry over to another gate.
        ("release.yml", "build", "python -m pytest", "inputs.publish != 'none'"),
        # The image is rehearsed in every release run, not only in one that publishes.
        ("release.yml", "build", "scripts/check_image.py", "inputs.publish != 'none'"),
        ("release.yml", "image", "scripts/check_image.py", "inputs.publish == 'testpypi'"),
        ("release.yml", "compatibility", "scripts/check_installed_wheel.py", False),
        ("release.yml", "verify", "gh attestation verify", False),
        ("ci.yml", "verified", "sys.exit(bool(failed))", False),
    ],
)
def test_a_gate_step_that_a_condition_can_skip_is_rejected(tmp_path, name, job, command, value):
    errors = workflow_errors(tmp_path, name, condition(job, command, value))
    assert any(f"{job} may skip {command}" in error for error in errors), errors


@pytest.mark.parametrize(
    "name,job,value",
    [
        ("ci.yml", "quality", False),
        ("ci.yml", "test", "github.event_name == 'push'"),
        ("ci.yml", "action-annotations", "success() && false"),
        ("release.yml", "build", "github.ref == 'refs/heads/release'"),
        ("release.yml", "image", "inputs.publish == 'pypi'"),
        ("release.yml", "compatibility", "${{ false }}"),
    ],
)
def test_a_required_job_that_a_condition_can_skip_is_rejected(tmp_path, name, job, value):
    def change(jobs):
        jobs[job]["if"] = value

    errors = workflow_errors(tmp_path, name, change)
    assert any(f"required job {job} may be skipped" in error for error in errors), errors


@pytest.mark.parametrize("value", ["success()", "always()", "${{ always() }}", " ${{success()}} "])
def test_a_gate_may_run_on_success_or_always(tmp_path, value):
    def change(jobs):
        for job, command in (("test", "python -m pytest"), ("codeql", "init@")):
            step_running(jobs[job], command)["if"] = value
        jobs["quality"]["if"] = value

    assert workflow_errors(tmp_path, "ci.yml", change) == []


def edit_run(job, command, old, new):
    def change(jobs):
        step = step_running(jobs[job], command)
        assert old in step["run"]
        step["run"] = step["run"].replace(old, new, 1)

    return change


TEST_STEP = 'tee "$PYTEST_LOG"\n'
# A here-string is not a here-document: the next line still runs as a command.
HERE_STRING = "cat <<<EOF\nmypy src/nexus_symbiote scripts || true\nEOF"


@pytest.mark.parametrize(
    "name,job,command,old,new",
    [
        ("release.yml", "build", "python -m pytest", "--strict-skips", "--strict-skips || true"),
        ("release.yml", "build", "python -m pytest", "--strict-skips", "--strict-skips ||true"),
        ("release.yml", "build", "python -m pytest", "--strict-skips", "--strict-skips \\\n|| :"),
        ("release.yml", "build", "python -m pytest", "--strict-skips", "--strict-skips ||\n true"),
        ("ci.yml", "test", "python -m pytest", TEST_STEP, 'tee "$PYTEST_LOG" || true\n'),
        ("ci.yml", "test", "python -m pytest", TEST_STEP, 'tee "$PYTEST_LOG" &\n'),
        ("ci.yml", "quality", "mypy src", "mypy src/nexus_symbiote scripts", HERE_STRING),
        ("ci.yml", "test", "python -m pytest", "\n  '\n", "\n  ' || exit 0\n"),
        ("ci.yml", "quality", "mypy src/nexus_symbiote scripts", "scripts", "scripts || :"),
        ("ci.yml", "quality", "scripts/check_locks.py", ".py", ".py; true"),
        ("ci.yml", "quality", "scripts/check_workflows.py", ".py", ".py || /usr/bin/true"),
        ("ci.yml", "distribution", "python -m build --no-isolation", "isolation", "isolation &"),
        ("ci.yml", "action-annotations", "gh api --paginate", '/check-runs"\n', '/check-runs" &\n'),
        ("ci.yml", "action", "sys.exit(bool(failures))", "<<'PY'", "<<'PY' || true"),
        ("release.yml", "build", "check_repository_controls", '"$PUBLISH"', '"$PUBLISH" || echo'),
        ("release.yml", "build", "check_image.py", "packages.json", "packages.json || true"),
        ("release.yml", "image", "check_image.py", '"$GITHUB_OUTPUT"', '"$GITHUB_OUTPUT" || :'),
        ("ci.yml", "distribution", "scripts/check_image.py", "dist", "dist || true"),
    ],
)
def test_a_gate_command_whose_status_is_discarded_is_rejected(
    tmp_path, name, job, command, old, new
):
    errors = workflow_errors(tmp_path, name, edit_run(job, command, old, new))
    assert any(f"{job} discards the exit status of" in error for error in errors), errors


@pytest.mark.parametrize(
    "job,command,old,new",
    [
        ("quality", "mypy src", "mypy", "pip cache purge || true\nmypy"),
        ("quality", "mypy src", "scripts", "scripts || exit 1"),
        ("quality", "mypy src", "scripts", "scripts || { echo 'mypy failed'; exit 1; }"),
        ("action", "$EVIDENCE/hostile.json", "set -euo", "echo 'a & b || true' >&2\nset -euo"),
        ("action-annotations", "gh api", '/jobs"', '/jobs?per_page=100&filter=latest"'),
        ("quality", "check_locks", ".py", '.py --title "Locks & pins"'),
    ],
)
def test_status_handling_that_keeps_the_gate_is_accepted(tmp_path, job, command, old, new):
    assert workflow_errors(tmp_path, "ci.yml", edit_run(job, command, old, new)) == []


@pytest.mark.parametrize(
    "old,new",
    [
        ("mypy src/nexus_symbiote scripts", "true # mypy src/nexus_symbiote scripts"),
        ("mypy src/nexus_symbiote scripts", "# mypy src/nexus_symbiote scripts\ntrue"),
        ("mypy src/nexus_symbiote scripts", "true;# mypy src/nexus_symbiote scripts"),
    ],
)
def test_a_gate_command_left_only_in_a_comment_is_rejected(tmp_path, old, new):
    errors = workflow_errors(tmp_path, "ci.yml", edit_run("quality", "mypy", old, new))
    assert any("quality no longer runs mypy src/nexus_symbiote scripts" in e for e in errors)


def test_the_annotation_check_fails_on_the_runners_legacy_command_warning(tmp_path):
    # The Action pre-seeds its outputs in GITHUB_OUTPUT, so a set-output that the runner
    # executed changes nothing; the deprecation warning it annotates is the only trace.
    step = step_running(ci_workflow()["jobs"]["action-annotations"], "gh api --paginate")
    pattern = re.compile(re.search(r"grep -Ei '([^']+)'", step["run"])[1], re.IGNORECASE)
    deprecated = (
        "The `{}` command is deprecated and will be disabled soon. Please upgrade to using"
        " Environment Files."
    )
    assert pattern.search(deprecated.format("set-output"))
    assert pattern.search(deprecated.format("save-state"))
    assert pattern.search("Warning ##[warning]symbiote-injected-annotation.pkl")
    assert not pattern.search(" Process completed with exit code 1.")
    reverted = edit_run(
        "action-annotations",
        "gh api --paginate",
        "grep -Ei 'symbiote-injected-annotation|set-output|save-state'",
        "grep -F 'symbiote-injected-annotation'",
    )
    errors = workflow_errors(tmp_path, "ci.yml", reverted)
    assert any("action-annotations no longer runs set-output" in error for error in errors)


def test_a_gating_job_cannot_continue_on_error(tmp_path):
    workflow = ci_workflow()
    workflow["jobs"]["codeql"]["steps"][-2]["continue-on-error"] = True
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("continue on error" in error for error in checker.check(path))


def test_dropping_a_verification_job_from_verified_ci_is_rejected(tmp_path):
    workflow = ci_workflow()
    workflow["jobs"]["verified"]["needs"].remove("floor")
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("Verified CI" in error for error in checker.check(path))


def test_the_offline_invariant_job_is_a_prerequisite_of_verified_ci(tmp_path):
    workflow = ci_workflow()
    verified = workflow["jobs"]["verified"]
    assert "offline-invariant" in verified["needs"]
    expected = re.search(r"^expected = (\{.*\})$", verified["steps"][0]["run"], re.M)
    assert expected is not None
    assert set(yaml.safe_load(expected[1])) == set(verified["needs"])
    assert not (ROOT / ".github/workflows/offline-invariant.yml").exists()

    verified["needs"].remove("offline-invariant")
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("Verified CI must always aggregate" in error for error in checker.check(path))

    del workflow["jobs"]["offline-invariant"]
    path.write_text(yaml.safe_dump(workflow))
    errors = checker.check(path)
    assert any("required job offline-invariant is missing" in error for error in errors)
    assert any("Verified CI must always aggregate" in error for error in errors)


@pytest.mark.parametrize(
    "old,new",
    [
        ('"$OFFLINE_PYTHON" -m pytest', 'true || "$OFFLINE_PYTHON" -m pytest'),
        ("unshare --net bash", "unshare --net --help bash"),
        ("unshare --net bash", "bash"),
        ("--strict-skips ", ""),
        ("errno.ENETUNREACH", "errno.ETIMEDOUT"),
        ("--preserve-env=CI,", "--preserve-env="),
        ('| tee "$PYTEST_LOG"', '| tee "$PYTEST_LOG" || true'),
    ],
)
def test_the_offline_invariant_step_is_held_to_its_reviewed_text(tmp_path, old, new):
    errors = workflow_errors(
        tmp_path, "ci.yml", edit_run("offline-invariant", "-m pytest", old, new)
    )
    assert any("offline-invariant" in e for e in errors), errors


def test_the_offline_invariant_environment_is_held_to_its_reviewed_value(tmp_path):
    def change(jobs):
        step_running(jobs["offline-invariant"], "unshare --net")["env"]["EXTRA"] = "1"

    errors = workflow_errors(tmp_path, "ci.yml", change)
    assert any("runs unshare --net other than in its reviewed step" in e for e in errors), errors


def test_removing_the_action_jobs_with_their_verified_ci_entries_is_rejected(tmp_path):
    workflow = ci_workflow()
    for job in ("action", "action-annotations"):
        del workflow["jobs"][job]
        workflow["jobs"]["verified"]["needs"].remove(job)
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    errors = checker.check(path)
    assert any("Verified CI must always aggregate" in error for error in errors)
    assert any("required job action is missing" in error for error in errors)


@pytest.mark.parametrize(
    "permissions",
    [
        "    permissions:\n      contents: write\n",
        "    permissions:\n      contents: read\n      pull-requests: write\n",
        "    permissions:\n      id-token: write\n",
        "    permissions: write-all\n",
        "    permissions:\n      contents: admin\n",
    ],
)
def test_a_job_cannot_grant_itself_a_write_token(repository, capsys, permissions):
    workflow = SAFE.replace("    timeout-minutes: 5\n", "    timeout-minutes: 5\n" + permissions)
    status, output = run_checker(repository, workflow, capsys)
    assert status == 1
    assert "test may hold write permissions only for nothing" in output


def test_a_write_scope_stays_with_the_job_reviewed_for_it(tmp_path):
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    path = tmp_path / "release.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert not any("write permissions" in error for error in checker.check(path))
    # The build job runs the test suite; it must never hold the publishing token.
    workflow["jobs"]["build"]["permissions"]["id-token"] = "write"
    path.write_text(yaml.safe_dump(workflow))
    assert any(
        "build may hold write permissions only for nothing" in error
        for error in checker.check(path)
    )


SCHEDULED = """on:
  schedule:
    - cron: "17 5 * * *"
    - cron: "43 4 * * 2"
permissions:
  contents: read
concurrency:
  group: {group}
  cancel-in-progress: {cancel}
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: echo safe
"""


@pytest.mark.parametrize(
    "group,cancel,rejected",
    [
        ("scheduled-${{ github.ref }}", "true", True),
        (
            "scheduled-${{ github.ref }}-${{ github.event.schedule || github.event_name }}",
            "true",
            False,
        ),
        ("scheduled-${{ github.ref }}", "false", False),
    ],
)
def test_one_schedule_cannot_cancel_another(repository, capsys, group, cancel, rejected):
    status, output = run_checker(repository, SCHEDULED.format(group=group, cancel=cancel), capsys)
    assert (status, "github.event.schedule" in output) == (int(rejected), rejected)
    single = SCHEDULED.replace('    - cron: "43 4 * * 2"\n', "")
    assert run_checker(repository, single.format(group=group, cancel=cancel), capsys)[0] == 0


def test_a_step_may_continue_on_error_only_when_its_outcome_is_checked(tmp_path):
    workflow = ci_workflow()
    steps = workflow["jobs"]["codeql"]["steps"]
    steps[-2].update({"id": "probe", "continue-on-error": True})
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("continue on error" in error for error in checker.check(path))
    steps.append(
        {
            "name": "The probe must have failed",
            "env": {"OUTCOME": "${{ steps.probe.outcome }}"},
            "run": 'test "$OUTCOME" = failure',
        }
    )
    path.write_text(yaml.safe_dump(workflow))
    assert not any("continue on error" in error for error in checker.check(path))
    workflow["jobs"]["codeql"]["continue-on-error"] = True
    path.write_text(yaml.safe_dump(workflow))
    assert any("continue on error" in error for error in checker.check(path))


@pytest.mark.parametrize(
    "value,swallowed",
    [
        (False, True),
        ("failure()", True),
        ("always()", False),
        ("steps.probe.outcome != 'failure'", False),
    ],
)
def test_the_step_that_checks_an_outcome_must_run(tmp_path, value, swallowed):
    workflow = ci_workflow()
    steps = workflow["jobs"]["codeql"]["steps"]
    steps[-2].update({"id": "probe", "continue-on-error": True})
    steps.append(
        {
            "name": "The probe must have failed",
            "if": value,
            "env": {"OUTCOME": "${{ steps.probe.outcome }}"},
            "run": 'test "$OUTCOME" = failure',
        }
    )
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("continue on error" in error for error in checker.check(path)) is swallowed


def test_the_action_jobs_outcome_assertions_must_run(tmp_path):
    errors = workflow_errors(
        tmp_path, "ci.yml", condition("action", "sys.exit(bool(failures))", False)
    )
    assert any("action must not continue on error" in error for error in errors), errors


def test_a_later_steps_name_does_not_read_an_outcome(tmp_path):
    workflow = ci_workflow()
    steps = workflow["jobs"]["codeql"]["steps"]
    steps[-2].update({"id": "probe", "continue-on-error": True})
    steps.append({"name": "Report (steps.probe.outcome)", "run": "true"})
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("codeql must not continue on error" in error for error in checker.check(path))


@pytest.mark.parametrize(
    "name,job,command",
    [
        ("ci.yml", "test", "python -m pytest"),
        ("ci.yml", "quality", "ruff check src tests scripts"),
        ("release.yml", "verify", "gh attestation verify"),
    ],
)
def test_a_gate_in_a_step_that_continues_on_error_does_not_count(tmp_path, name, job, command):
    # A later step reads the outcome, so the step may continue on error, but its gate's
    # failure would no longer fail the job.
    def change(jobs):
        steps = jobs[job]["steps"]
        step = step_running(jobs[job], command)
        step.update({"id": "gate", "continue-on-error": True})
        steps.insert(
            steps.index(step) + 1,
            {"env": {"OUTCOME": "${{ steps.gate.outcome }}"}, "run": 'echo "$OUTCOME"'},
        )

    errors = workflow_errors(tmp_path, name, change)
    assert f"{job} runs {command} only in a step that continues on error" in "\n".join(errors)
    assert not any("must not continue on error" in error for error in errors), errors


def run_locks(script, **step_changes):
    """Replace the quality job's lock check with `script` and the step settings given."""

    def change(jobs):
        step = step_running(jobs["quality"], "scripts/check_locks.py")
        step["run"] = script
        step.update(step_changes)

    return change


NOT_A_GATE = "quality does not run scripts/check_locks.py as a command of its own"
LOCKS = "python scripts/check_locks.py"


@pytest.mark.parametrize(
    "script",
    [
        f"{LOCKS} && echo ok\necho done",
        f"set +e\n{LOCKS}\necho done",
        f"set +o errexit\n{LOCKS}\necho done",
        f"if {LOCKS}; then :; fi",
        f"if\n{LOCKS}\nthen :\nfi",
        f"while {LOCKS}; do break; done",
        f"! {LOCKS}",
        f"echo '{LOCKS}'",
        f'echo "{LOCKS}"',
        f"echo {LOCKS}",
        f"{LOCKS} &\nwait",
        f"{LOCKS} | cat",
        f"{{ {LOCKS}; }}\necho done",
        f"( {LOCKS} )\necho done",
        f"{LOCKS} || if false; then exit 1; fi",
        f"cd tests/fixtures\n{LOCKS}",
        f"exit 0\n{LOCKS}",
        f"trap 'exit 0' EXIT\n{LOCKS}",
        f"python() {{ :; }}\n{LOCKS}",
        f"eval 'python() {{ :; }}'\n{LOCKS}",
        f'tool=echo\n"$tool" {LOCKS.removeprefix("python ")}',
        "python -c 'print(1)' scripts/check_locks.py",
        "python -m json.tool scripts/check_locks.py",
        f"bash -ec 'set +e; {LOCKS}; true'",
        f"bash -c '{LOCKS}'\ntrue",
        f"case x in *) {LOCKS};; esac",
        f"echo $'\\'\n{LOCKS}\n' #'",
        f'cat <<EO"F"\nEO\n{LOCKS}\nEOF',
        f"x=$(cat <<'EOF'\n)\n{LOCKS}\n(\nEOF\n)",
        f"x=$(: # )\n{LOCKS}\n)",
        f"builtin set +e\n{LOCKS}\necho done",
        f"builtin -- set +e\n{LOCKS}\necho done",
        f"builtin -- exit 0\n{LOCKS}",
        'PY=python3\nbuiltin -- declare PY=echo\n"$PY" scripts/check_locks.py',
        f"command set +e\n{LOCKS}\necho done",
        f"command -p set +e\n{LOCKS}\necho done",
        f"time set +e\n{LOCKS}\necho done",
        f"shopt -u -o errexit\n{LOCKS}\necho done",
        f"shopt -uo errexit\n{LOCKS}\necho done",
        f"x=\n${{x}}set +e\n{LOCKS}\necho done",
        f"$(echo set) +e\n{LOCKS}\necho done",
        f"set -n\n{LOCKS}",
        f"set -o noexec\n{LOCKS}",
        f"builtin exit 0\n{LOCKS}",
        f"builtin cd /\n{LOCKS}",
        f"builtin trap 'exit 0' EXIT\n{LOCKS}",
        f"hash -p /bin/true python\n{LOCKS}",
        f"enable -n set\nset +e\n{LOCKS}",
        'PY=python3\nexport PY=echo\n"$PY" scripts/check_locks.py',
        'PY=python3\ndeclare PY=echo\n"$PY" scripts/check_locks.py',
        'PY=python3\nbuiltin declare PY=echo\n"$PY" scripts/check_locks.py',
        'PY=python3\nfor PY in echo; do :; done\n"$PY" scripts/check_locks.py',
        'PY=python3\nif true; then for PY in echo; do :; done; fi\n"$PY" scripts/check_locks.py',
        'PY=python3\nread -r PY <<< echo\n"$PY" scripts/check_locks.py',
        'PY=python3\nprintf -v PY echo\n"$PY" scripts/check_locks.py',
        f'x=\n: "${{x:=set}}"\n$x +e\n{LOCKS}\necho done',
        "python -X scripts/check_locks.py -c pass",
        "python -W scripts/check_locks.py -c pass",
        "python -uX scripts/check_locks.py -c pass",
        "python -uc scripts/check_locks.py",
        "python --version scripts/check_locks.py",
        f"bash -n -c '{LOCKS}'",
        f"{LOCKS} || exit 256",
        f"exit 256\n{LOCKS}",
        f"exit 0256\n{LOCKS}",
        "python -V scripts/check_locks.py",
        "python -h scripts/check_locks.py",
        "python -? scripts/check_locks.py",
        "python -i scripts/check_locks.py",
        f"timeout --help {LOCKS}",
        f"timeout --version 5m {LOCKS}",
        f"bash --version -e -c '{LOCKS}'",
        f"bash --help -ec '{LOCKS}'",
        f"bash -D -e -c '{LOCKS}'",
        f"shopt -s -o noexec\n{LOCKS}",
        f"shopt -so noexec\n{LOCKS}",
        f"set -t\n{LOCKS}",
        f"set -o onecmd\n{LOCKS}",
        f"OPTS=+e\nset $OPTS\n{LOCKS}\necho done",
        f"x=e\nset +$x\n{LOCKS}\necho done",
        f"n=errexit\nset +o $n\n{LOCKS}\necho done",
        f"{{set,+e}}\n{LOCKS}\necho done",
        f"{{exit,0}}\n{LOCKS}",
    ],
)
def test_a_gate_command_that_does_not_stand_alone_is_rejected(tmp_path, script):
    errors = workflow_errors(tmp_path, "ci.yml", run_locks(script))
    assert any(NOT_A_GATE in error for error in errors), errors


@pytest.mark.parametrize(
    "script,changes",
    [
        (f"set -euo pipefail\n{LOCKS} | cat", {}),
        (f"{LOCKS} | cat", {"shell": "bash"}),
        (f"set +e\necho preparing\nset -e\n{LOCKS}", {}),
        (f"{LOCKS} || exit 3", {}),
        ('PY=python3\n"$PY" -I scripts/check_locks.py --strict', {}),
        (f"bash --noprofile --norc -e -o pipefail -c '\n  {LOCKS} | tee log\n'", {}),
        (f"timeout 5m {LOCKS}", {}),
        (f"timeout --signal=INT --kill-after=30s 12m {LOCKS}", {}),
        (f"timeout -k 5 -s TERM --preserve-status 5m {LOCKS}", {}),
        (f"{LOCKS} || exit 257", {}),
        (f"if true; then echo ok; fi\n{LOCKS}", {}),
        (f"{LOCKS}", {"shell": "bash --noprofile --norc -eo pipefail {0}"}),
        (f"echo $'it\\'s'\n{LOCKS}", {}),
        (f'cat <<"EOF" >notes\n{LOCKS}\nEOF\n{LOCKS}', {}),
        (f"x=$(cat <<'EOF'\n)\nEOF\n)\n{LOCKS}", {}),
        (f"command -v python\nbuiltin echo ok\n{LOCKS}", {}),
        (f"shopt -s -o errexit\nshopt -o\n{LOCKS}", {}),
        (f'"$RUNNER_TEMP/bin/tool" --check\n{LOCKS}', {}),
        ('PY=python3\nprintf "%s\\n" "$PY"\n"$PY" scripts/check_locks.py', {}),
        ("python -X dev -W error -Xutf8 scripts/check_locks.py", {}),
        ("python -I --check-hash-based-pycs never -- scripts/check_locks.py", {}),
    ],
)
def test_a_gate_command_that_stands_alone_is_accepted(tmp_path, script, changes):
    assert workflow_errors(tmp_path, "ci.yml", run_locks(script, **changes)) == []


@pytest.mark.parametrize("shell", ["cat {0}", "true {0}", "sh {0}", "bash +e {0}", "pwsh", 0])
def test_a_gate_step_in_an_unreviewed_shell_is_rejected(tmp_path, shell):
    def change(jobs):
        step_running(jobs["test"], "python -m pytest")["shell"] = shell

    errors = workflow_errors(tmp_path, "ci.yml", change)
    assert any(f"test runs its gate under the step shell {shell!r}" in e for e in errors), errors


@pytest.mark.parametrize("level", ["workflow", "job"])
@pytest.mark.parametrize(
    "defaults,message",
    [
        ({"run": {"shell": "true {0}"}}, "under the {} defaults shell 'true {{0}}'"),
        ({"run": {"working-directory": "tests"}}, "in the {} defaults directory 'tests'"),
        ({"run": "bash"}, "under the {} defaults shell 'unreadable'"),
    ],
)
def test_run_defaults_cannot_change_how_a_gate_runs(tmp_path, level, defaults, message):
    workflow = ci_workflow()
    (workflow if level == "workflow" else workflow["jobs"]["quality"])["defaults"] = defaults
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    expected = f"quality runs its gate {message.format(level)}"
    assert any(expected in error for error in checker.check(path)), expected


def test_a_gate_step_cannot_move_to_another_directory(tmp_path):
    errors = workflow_errors(
        tmp_path, "ci.yml", run_locks(LOCKS, **{"working-directory": "tests/fixtures"})
    )
    assert any("quality runs its gate in the step directory 'tests/fixtures'" in e for e in errors)


@pytest.mark.parametrize(
    "script,runs",
    [
        (
            'out=`date`\necho "$(printf "%s)" "a b")" ${HOME:-x}\nfiles=(a "b c")\n'
            f"exec >log 2>&1\n{LOCKS} &>out <<-EOF\n\tbody\n\tEOF",
            True,
        ),
        (f"for f in a b; do echo $f; done\nuntil true; do :; done\n{LOCKS}", True),
        (f"cat <<<word\nif true; then :; elif false; then :; else :; fi\n{LOCKS}", True),
        (f"echo 'unterminated\n{LOCKS}", False),
        (f'echo "unterminated\n{LOCKS}', False),
        (f"echo $(unbalanced\n{LOCKS}", False),
        (f"echo `unterminated\n{LOCKS}", False),
        (f"{LOCKS} >", False),
        (f"cat <<EOF\n{LOCKS}", False),
        (f"cat <<$X\n{LOCKS}\n$X", False),
        (f"if true; then\n{LOCKS}", False),
        (f"for f; :\n{LOCKS}", False),
        (f"; ;\n&& {LOCKS}", False),
    ],
)
def test_the_gate_reader_follows_quoting_expansions_and_redirections(script, runs):
    gates = checker._gates(script, True, False)
    assert any(gate.runs("scripts/check_locks.py") for gate in gates) is runs


@pytest.mark.parametrize("variable", ["SHELLOPTS", "BASHOPTS", "PS4", "ENV", "PATH"])
@pytest.mark.parametrize("scope", ["workflow", "job", "step"])
def test_a_shell_variable_that_hollows_a_gate_is_unsafe_gate_environment(tmp_path, variable, scope):
    # bash imports SHELLOPTS at startup: noexec parses every later script and exits 0.
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    value = {"SHELLOPTS": "noexec", "BASHOPTS": "extdebug", "PS4": "$(id)", "ENV": "x"}.get(
        variable, "stubs:/usr/bin"
    )
    target = {
        "workflow": workflow,
        "job": workflow["jobs"]["quality"],
        "step": step_running(workflow["jobs"]["quality"], "scripts/check_workflows.py"),
    }[scope]
    target.setdefault("env", {})[variable] = value
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    errors = checker.check(path)
    assert any(f"sets unsafe gate environment in {scope} env" in e for e in errors), errors


@pytest.mark.parametrize(
    "write",
    ['echo SHELLOPTS=noexec >> "$GITHUB_ENV"', 'echo stubs >> "${GITHUB_PATH}"'],
)
def test_a_job_environment_write_ahead_of_a_gate_is_rejected(tmp_path, write):
    def change(jobs):
        jobs["quality"]["steps"].insert(1, {"run": write})

    errors = workflow_errors(tmp_path, "ci.yml", change)
    assert any("writes the job environment through $GITHUB_ENV" in e for e in errors), errors


def test_the_pull_request_size_step_is_a_protected_gate(tmp_path):
    errors = workflow_errors(
        tmp_path,
        "ci.yml",
        edit_run(
            "quality",
            "scripts/check_pull_request_size.py",
            '"$MERGE_SHA^1"',
            '"$MERGE_SHA^1" || true',
        ),
    )
    assert any(
        "discards the exit status of scripts/check_pull_request_size.py" in e for e in errors
    )
    assert workflow_errors(
        tmp_path,
        "ci.yml",
        condition("quality", "scripts/check_pull_request_size.py", "github.event_name == 'never'"),
    )


@pytest.mark.parametrize(
    "write",
    [
        'echo SHELLOPTS=noexec >> "$(printenv GITHUB_ENV)"',
        'v=GITHUB_ENV; echo SHELLOPTS=noexec >> "${!v}"',
        "python -c \"import os; open(os.environ['GITHUB_PATH'], 'a').write('stubs')\"",
    ],
)
def test_naming_the_job_environment_files_ahead_of_a_gate_is_rejected(tmp_path, write):
    # A tripwire: the bare name catches indirect writes, not every way to reach the file.
    def change(jobs):
        jobs["quality"]["steps"].insert(1, {"run": write})

    errors = workflow_errors(tmp_path, "ci.yml", change)
    assert any("writes the job environment through $GITHUB_ENV" in e for e in errors), errors


@pytest.mark.parametrize(
    "old,new",
    [
        ('"$MERGE_SHA^1"', '"$MERGE_SHA^1" --limit 99999999'),
        ('--base "$MERGE_SHA^1"', "--base HEAD"),
        ('--base "$MERGE_SHA^1"', "--numstat-file /dev/null"),
        # The base branch's current tip, which moves while the job waits for a runner.
        ('--base "$MERGE_SHA^1"', '--base "origin/main"'),
    ],
)
def test_the_pull_request_size_arguments_are_pinned(tmp_path, old, new):
    errors = workflow_errors(
        tmp_path, "ci.yml", edit_run("quality", "scripts/check_pull_request_size.py", old, new)
    )
    assert any("scripts/check_pull_request_size.py other than" in e for e in errors), errors


def test_the_pull_request_size_base_comes_from_the_merge_commit(tmp_path):
    def change(jobs):
        step_running(jobs["quality"], "scripts/check_pull_request_size.py")["env"] = {
            "MERGE_SHA": "${{ github.event.pull_request.head.sha }}"
        }

    errors = workflow_errors(tmp_path, "ci.yml", change)
    assert any("scripts/check_pull_request_size.py other than" in e for e in errors), errors


@pytest.mark.parametrize(
    "variable,command",
    [
        ("BASH_FUNC_python%%", "scripts/check_locks.py"),
        ("PYTHONUSERBASE", "scripts/check_locks.py"),
        ("PYTHONSAFEPATH", "scripts/check_workflows.py"),
        ("GIT_DIR", "scripts/check_pull_request_size.py"),
        ("HOME", "scripts/check_locks.py"),
        ("XDG_CONFIG_HOME", "scripts/check_pull_request_size.py"),
        ("XDG_DATA_HOME", "scripts/check_workflows.py"),
        ("A-B", "scripts/check_locks.py"),
    ],
)
def test_a_variable_family_that_hollows_a_gate_is_unsafe_gate_environment(
    tmp_path, variable, command
):
    def change(jobs):
        step_running(jobs["quality"], command).setdefault("env", {})[variable] = "() { true; }"

    errors = workflow_errors(tmp_path, "ci.yml", change)
    assert any("sets unsafe gate environment in step env" in e for e in errors), errors


@pytest.mark.parametrize("language", ["python", "actions"])
def test_the_codeql_workflow_analyzes_python_and_actions(tmp_path, language):
    def change(jobs):
        matrix = jobs["analyze"]["strategy"]["matrix"]
        matrix["language"] = [item for item in matrix["language"] if item != language]

    errors = workflow_errors(tmp_path, "codeql.yml", change)
    assert any(f"analyze must analyze {language} with CodeQL" in e for e in errors), errors


@pytest.mark.parametrize("event", ["pull_request", "push", "schedule"])
def test_the_codeql_workflow_runs_on_pull_requests_and_main(tmp_path, event):
    # Code scanning holds a merge until the pull request has a result for every CodeQL
    # configuration main holds; a workflow that uploads on main only would block them all.
    workflow = yaml.safe_load((ROOT / ".github/workflows/codeql.yml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    del triggers[event]
    path = tmp_path / "codeql.yml"
    path.write_text(yaml.safe_dump(workflow))
    errors = checker.check(path)
    assert any(f"must run on {event}" in e for e in errors), errors


@pytest.mark.parametrize(
    ("name", "job", "variable", "value"),
    [
        ("ci.yml", "codeql", "SARIF_PATH", "/dev/null"),
        ("codeql.yml", "analyze", "SARIF_PATH", "/dev/null"),
    ],
)
def test_the_codeql_policy_reads_the_analysis_it_gates(tmp_path, name, job, variable, value):
    def change(jobs):
        step_running(jobs[job], "scripts/check_codeql_sarif.py")["env"][variable] = value

    errors = workflow_errors(tmp_path, name, change)
    assert any("scripts/check_codeql_sarif.py other than" in e for e in errors), errors


def without_step(job, command):
    def change(jobs):
        jobs[job]["steps"].remove(step_running(jobs[job], command))

    return change


def setting(job, key, value, command=None):
    def change(jobs):
        (jobs[job] if command is None else step_running(jobs[job], command))[key] = value

    return change


@pytest.mark.parametrize(
    ("name", "change", "message"),
    [
        (
            "codeql.yml",
            without_step("analyze", "scripts/check_codeql_sarif.py"),
            "analyze no longer runs scripts/check_codeql_sarif.py in its reviewed step",
        ),
        (
            "ci.yml",
            without_step("codeql", "scripts/check_codeql_sarif.py"),
            "codeql no longer runs scripts/check_codeql_sarif.py in its reviewed step",
        ),
        (
            "codeql.yml",
            without_step("analyze", "github/codeql-action/analyze@"),
            "analyze no longer runs github/codeql-action/analyze@",
        ),
        (
            "codeql.yml",
            without_step("analyze", "github/codeql-action/init@"),
            "analyze no longer runs github/codeql-action/init@",
        ),
        (
            "codeql.yml",
            setting("analyze", "continue-on-error", True),
            "analyze must not continue on error in a gating workflow",
        ),
        (
            "codeql.yml",
            setting("analyze", "continue-on-error", True, "scripts/check_codeql_sarif.py"),
            "analyze runs scripts/check_codeql_sarif.py only in a step that continues on error",
        ),
        (
            "codeql.yml",
            setting("analyze", "if", False, "scripts/check_codeql_sarif.py"),
            "analyze may skip scripts/check_codeql_sarif.py",
        ),
        ("codeql.yml", setting("analyze", "if", "false"), "required job analyze may be skipped"),
    ],
    ids=[
        "codeql-no-policy",
        "ci-no-policy",
        "no-analyze",
        "no-init",
        "job-continues",
        "policy-continues",
        "policy-skipped",
        "job-skipped",
    ],
)
def test_the_codeql_workflow_is_a_gate_that_cannot_be_hollowed_out(tmp_path, name, change, message):
    errors = workflow_errors(tmp_path, name, change)
    assert any(message in e for e in errors), errors


@pytest.mark.parametrize("field", ["container", "services"])
def test_a_gate_job_cannot_run_in_a_job_container(tmp_path, field):
    def change(jobs):
        jobs["quality"][field] = (
            "ghcr.io/example/python:latest" if field == "container" else {"db": {"image": "x"}}
        )

    errors = workflow_errors(tmp_path, "ci.yml", change)
    assert any("must not run its gates in a job container" in e for e in errors), errors


@pytest.mark.parametrize("runner", ["ubuntu-24.04", "${{ matrix.os }}", ["macos-15"]])
def test_the_macos_suite_cannot_move_to_another_runner(tmp_path, runner):
    def change(jobs):
        jobs["macos"]["runs-on"] = runner

    errors = workflow_errors(tmp_path, "ci.yml", change)
    assert any("macos must run on a macos- runner" in e for e in errors), errors


def test_the_image_push_holds_no_oidc_token(tmp_path):
    def change(jobs):
        jobs["image"]["permissions"]["id-token"] = "write"

    errors = workflow_errors(tmp_path, "release.yml", change)
    assert any("image may hold write permissions only for packages" in e for e in errors)
