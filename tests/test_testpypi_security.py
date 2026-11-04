"""Test-index publication must preserve the release verification boundary."""

import runpy
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def release():
    return yaml.safe_load((WORKFLOWS / "release.yml").read_text())


def commands(job):
    return "\n".join(step.get("run", "") for step in job["steps"])


def test_only_the_release_workflow_can_publish_to_a_package_index():
    workflows = [*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]
    publishers = sorted(
        path.name for path in workflows if "pypa/gh-action-pypi-publish@" in path.read_text()
    )
    assert publishers == ["release.yml"]


def test_testpypi_publication_requires_the_same_source_and_wheel_gates():
    build = release()["jobs"]["build"]
    preflight = next(
        (s for s in build["steps"] if "check_repository_controls.py" in s.get("run", "")), None
    )
    assert preflight is not None, "TestPyPI publication must verify exact-source CI"
    assert preflight["if"] == "inputs.publish != 'none'"
    assert '--sha "$GITHUB_SHA"' in preflight["run"]
    assert preflight["env"]["GH_TOKEN"] == "${{ github.token }}"  # noqa: S105 - expression, not a credential
    assert build["permissions"] == {"contents": "read", "actions": "read"}
    source = commands(build)
    assert "--require-hashes -r requirements-ci.lock" in source
    assert "python scripts/check_security_regressions.py" in source
    assert "python -m build --no-isolation" in source
    assert "python -I scripts/check_wheel_security.py dist/*.whl" in source
    assert "--no-index --no-deps --force-reinstall dist/*.whl" in source
    assert source.index("check_repository_controls.py") < source.index("python -m build")


def test_built_wheel_runs_every_a2a_card_regression():
    cases = runpy.run_path(str(ROOT / "scripts" / "check_wheel_security.py"))["CASES"]
    assert {"test_a2a_source_binding.py", "test_a2a_v1_cards.py"} <= set(cases)


def test_testpypi_is_opt_in_main_only_and_keeps_oidc_away_from_source_execution():
    doc = release()
    events = doc.get("on", doc.get(True))
    assert set(events) == {"workflow_dispatch"}
    publish_input = events["workflow_dispatch"]["inputs"]["publish"]
    assert publish_input["type"] == "choice"
    assert publish_input["default"] == "none"
    jobs = doc["jobs"]
    assert jobs["build"]["if"] == "github.ref == 'refs/heads/main'"
    publish = jobs["publish"]
    assert publish["if"] == "inputs.publish != 'none' && github.ref == 'refs/heads/main'"
    assert publish["environment"]["name"] == "${{ inputs.publish }}"
    assert publish["environment"]["url"] == (
        "${{ inputs.publish == 'testpypi' && 'https://test.pypi.org/p/nexus-symbiote'"
        " || 'https://pypi.org/p/nexus-symbiote' }}"
    )
    assert publish["permissions"] == {"id-token": "write"}
    assert set(publish["needs"]) == {"build", "attest", "verify"}
    assert not any("run" in step for step in publish["steps"])
    assert not any("checkout" in step.get("uses", "") for step in publish["steps"])
    upload = next(
        s for s in publish["steps"] if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@")
    )
    assert upload["with"]["repository-url"] == (
        "${{ inputs.publish == 'testpypi' && 'https://test.pypi.org/legacy/'"
        " || 'https://upload.pypi.org/legacy/' }}"
    )
    assert upload["with"]["attestations"] is True


def test_evidence_is_derived_only_from_the_uploaded_distribution_bytes():
    steps = release()["jobs"]["build"]["steps"]
    runs = [step.get("run", "") for step in steps]
    staged = next(i for i, run in enumerate(runs) if "distributions.sha256" in run)
    upload = next(i for i, step in enumerate(steps) if step.get("name") == "Upload distributions")
    recheck = next(
        i for i, run in enumerate(runs) if '-c "$RUNNER_TEMP/distributions.sha256"' in run
    )
    assert staged < upload < recheck
    assert runs[recheck].index("distributions.sha256") < runs[recheck].index("evidence.py prepare")
