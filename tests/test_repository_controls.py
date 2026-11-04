from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.error import HTTPError

import pytest
import yaml

spec = importlib.util.spec_from_file_location(
    "repository_controls", Path(__file__).parents[1] / "scripts/check_repository_controls.py"
)
assert spec and spec.loader
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


def branch():
    return {
        "protected": True,
        "protection": {
            "enabled": True,
            "required_status_checks": {
                "enforcement_level": "everyone",
                "contexts": ["Verified CI"],
                "checks": [{"context": "Verified CI", "app_id": 15368}],
            },
        },
    }


def test_required_verified_ci_applies_to_everyone():
    assert controls.evaluate(branch()) == []
    metadata = branch()
    metadata["protection"]["required_status_checks"]["contexts"] = []
    metadata["protection"]["required_status_checks"]["checks"] = [
        {"context": "Verified CI", "app_id": 15368}
    ]
    assert controls.evaluate(metadata) == []


@pytest.mark.parametrize("metadata", [None, {}, {"protected": False}, {"protected": 1}])
def test_unknown_or_disabled_protection_fails(metadata):
    assert controls.evaluate(metadata)


def test_checks_cannot_be_bypassed_by_administrator():
    metadata = branch()
    metadata["protection"]["required_status_checks"]["enforcement_level"] = "non_admins"
    assert controls.evaluate(metadata)


def test_missing_aggregate_context_fails_even_with_other_green_checks():
    metadata = branch()
    metadata["protection"]["required_status_checks"]["contexts"] = ["quality", "Tests Python 3.12"]
    metadata["protection"]["required_status_checks"]["checks"] = []
    assert controls.evaluate(metadata)


@pytest.mark.parametrize("key,value", [("contexts", "Verified CI"), ("checks", [None])])
def test_malformed_check_metadata_fails(key, value):
    metadata = branch()
    metadata["protection"]["required_status_checks"][key] = value
    assert controls.evaluate(metadata)


def test_no_network_request_without_credentials():
    with pytest.raises(ValueError, match="token"):
        controls.fetch_branch("Hunzee-VC/Nexus-Symbiote", "main", "")


def test_no_arbitrary_network_origin():
    with pytest.raises(ValueError, match="owner/name"):
        controls.fetch_branch("https://evil.example", "main", "unused")


@pytest.mark.parametrize(
    "checks", [[], [{"context": "Verified CI"}], [{"context": "Verified CI", "app_id": 1}]]
)
def test_unbound_or_impostor_check_source_cannot_supply_required_verification(checks):
    metadata = branch()
    metadata["protection"]["required_status_checks"]["checks"] = checks
    assert controls.evaluate(metadata)


def environment(name="pypi"):
    return {
        "name": name,
        "can_admins_bypass": True,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [{"type": "User", "reviewer": {"login": "maintainer"}}],
            },
            {"type": "branch_policy"},
        ],
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
    }


MAIN_ONLY = {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}


def test_reviewed_environment_deploying_only_from_main_is_accepted():
    assert controls.evaluate_environment(environment(), MAIN_ONLY, name="pypi", branch="main") == []
    # Policies created before tag policies existed carry no type and name a branch.
    untyped = {"total_count": 1, "branch_policies": [{"id": 1, "name": "main"}]}
    assert controls.evaluate_environment(environment(), untyped, name="pypi", branch="main") == []


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "other-environment",
        "no-reviewers",
        "empty-reviewers",
        "self-review",
        "malformed-rules",
        "missing-rules",
        "any-branch",
        "protected-branches",
        "unlisted-policies",
        "other-branch",
        "extra-branch",
        "tag-pattern",
        "truncated-policies",
        "malformed-policy",
    ],
)
def test_unreviewed_or_unrestricted_publication_environment_fails(change):
    metadata, policies = environment(), MAIN_ONLY
    reviews = metadata["protection_rules"][0]
    if change == "missing":
        metadata = None
    elif change == "other-environment":
        metadata = environment("testpypi")
    elif change == "no-reviewers":
        metadata["protection_rules"] = [{"type": "branch_policy"}]
    elif change == "empty-reviewers":
        reviews["reviewers"] = []
    elif change == "self-review":
        reviews["prevent_self_review"] = False
    elif change == "malformed-rules":
        metadata["protection_rules"] = [None]
    elif change == "missing-rules":
        del metadata["protection_rules"]
    elif change == "any-branch":
        metadata["deployment_branch_policy"] = None
    elif change == "protected-branches":
        # Any branch protected later, not only main, could then deploy.
        metadata["deployment_branch_policy"] = {
            "protected_branches": True,
            "custom_branch_policies": False,
        }
        policies = None
    elif change == "unlisted-policies":
        policies = None
    elif change == "other-branch":
        policies = {"total_count": 1, "branch_policies": [{"name": "release/*", "type": "branch"}]}
    elif change == "extra-branch":
        policies = {
            "total_count": 2,
            "branch_policies": [
                {"name": "main", "type": "branch"},
                {"name": "feature/*", "type": "branch"},
            ],
        }
    elif change == "tag-pattern":
        policies = {"total_count": 1, "branch_policies": [{"name": "main", "type": "tag"}]}
    elif change == "truncated-policies":
        policies = {"total_count": 2, "branch_policies": [{"name": "main", "type": "branch"}]}
    else:
        policies = {"total_count": 2, "branch_policies": [{"name": "main", "type": "branch"}, None]}
    assert controls.evaluate_environment(metadata, policies, name="pypi", branch="main")


def test_only_publication_environments_are_queried():
    with pytest.raises(ValueError, match="environment"):
        controls.fetch_environment("Hunzee-VC/Nexus-Symbiote", "production", "token")


@pytest.mark.parametrize("status", [404, 403])
def test_missing_environment_blocks_publication(monkeypatch, status):
    def fetch(repo, path, token):
        raise HTTPError("https://api.github.com/" + path, status, "error", None, None)

    monkeypatch.setattr(controls, "_fetch", fetch)
    if status == 404:
        # GitHub would otherwise create the environment, unprotected, on first use.
        assert controls.fetch_environment("owner/repo", "pypi", "token") == (None, None)
        assert controls.evaluate_environment(None, None, name="pypi", branch="main") == [
            "publication environment pypi is not configured"
        ]
    else:
        with pytest.raises(HTTPError):
            controls.fetch_environment("owner/repo", "pypi", "token")


@pytest.mark.parametrize("protected", [True, False])
def test_publication_preflight_requires_the_dispatched_environment(monkeypatch, capsys, protected):
    sha = "a" * 40
    run = {
        "id": 7,
        "run_attempt": 1,
        "head_sha": sha,
        "head_branch": "main",
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "head_repository": {"full_name": "owner/repo"},
        "status": "completed",
        "conclusion": "success",
    }
    jobs = [
        {
            "name": name,
            "run_id": 7,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
        }
        for name in sorted(controls.REQUIRED_CI_JOBS)
    ]
    configured = environment("testpypi")
    if not protected:
        configured["protection_rules"] = []
    responses = {
        "branches/main": {**branch(), "commit": {"sha": sha}},
        "actions/workflows/ci.yml/runs": {"workflow_runs": [run]},
        "actions/runs/7/jobs": {"total_count": len(jobs), "jobs": jobs},
        "environments/testpypi/deployment-branch-policies": MAIN_ONLY,
        "environments/testpypi": configured,
    }
    requested = []

    def fetch(repo, path, token):
        requested.append(path)
        assert repo == "owner/repo" and token == "token"  # noqa: S105 - test value
        return next(value for key, value in responses.items() if path.startswith(key))

    monkeypatch.setattr(controls, "_fetch", fetch)
    monkeypatch.setenv("GH_TOKEN", "token")
    argv = ["check", "--repo", "owner/repo", "--sha", sha]
    monkeypatch.setattr("sys.argv", argv)
    assert controls.main() == 0
    assert not any(path.startswith("environments/") for path in requested)
    monkeypatch.setattr("sys.argv", [*argv, "--environment", "testpypi"])
    assert controls.main() == (0 if protected else 1)
    assert "environments/testpypi" in requested
    assert ("testpypi environment must require" in capsys.readouterr().err) is not protected


def test_release_preflight_checks_the_environment_it_publishes_to():
    release = yaml.safe_load(
        (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    )
    preflight = next(
        step
        for step in release["jobs"]["build"]["steps"]
        if "check_repository_controls.py" in step.get("run", "")
    )
    assert preflight["env"]["PUBLISH_ENVIRONMENT"] == "${{ inputs.publish }}"
    assert '--environment "$PUBLISH_ENVIRONMENT"' in preflight["run"]
    assert preflight["if"] == "inputs.publish != 'none'"
    publish_input = release.get("on", release.get(True))["workflow_dispatch"]["inputs"]["publish"]
    assert set(publish_input["options"]) - {"none"} == controls.PUBLICATION_ENVIRONMENTS
