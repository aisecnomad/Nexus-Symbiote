"""Require enforced checks and successful workflow evidence for the published SHA.

Only read repository metadata. Administrative configuration is a separate
operator action; a checked-in policy file does not protect a GitHub branch.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

REQUIRED_CHECKS = frozenset({"Verified CI"})
GITHUB_ACTIONS_APP_ID = 15368
REQUIRED_CI_JOBS = frozenset({"Verified CI", "CodeQL policy", "Dependency advisories"})
CI_WORKFLOW = ".github/workflows/ci.yml"
MAX_RESPONSE_BYTES = 1024 * 1024
# Each index's trusted publisher accepts this repository's release workflow and its
# environment from any ref, so the environment's reviewers and branch policy are what
# stop a modified copy of the workflow on another branch from publishing.
PUBLICATION_ENVIRONMENTS = frozenset({"pypi", "testpypi"})


def evaluate(metadata: Any, required: frozenset[str] = REQUIRED_CHECKS) -> list[str]:
    """Require positively reported protection; missing or malformed data fails."""
    if not isinstance(metadata, dict) or metadata.get("protected") is not True:
        return ["branch protection is not positively reported as enabled"]
    protection = metadata.get("protection")
    if not isinstance(protection, dict) or protection.get("enabled") is not True:
        return ["branch protection metadata is unavailable or disabled"]
    status = protection.get("required_status_checks")
    if not isinstance(status, dict):
        return ["required status-check metadata is unavailable"]
    errors = []
    if status.get("enforcement_level") != "everyone":
        errors.append("required checks must apply to administrators as well as contributors")
    contexts = status.get("contexts", [])
    checks = status.get("checks", [])
    if (
        not isinstance(contexts, list)
        or any(not isinstance(c, str) for c in contexts)
        or not isinstance(checks, list)
        or any(not isinstance(c, dict) or not isinstance(c.get("context"), str) for c in checks)
    ):
        return [*errors, "required status-check metadata is malformed"]
    present = set(contexts) | {c["context"] for c in checks}
    missing = required - present
    if missing:
        errors.append("missing enforced required checks: " + ", ".join(sorted(missing)))
    bound = {
        c["context"]
        for c in checks
        if type(c.get("app_id")) is int and c["app_id"] == GITHUB_ACTIONS_APP_ID
    }
    if required - bound:
        errors.append("required checks must be bound to the GitHub Actions app")
    return errors


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
    ) -> None:
        # Never forward an authentication header to a redirect destination.
        return None


def _fetch(repo: str, path: str, token: str) -> Any:
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) is None:
        raise ValueError("repository must be owner/name")
    if not token or any(c in token for c in "\r\n"):
        raise ValueError("a GitHub token with repository contents-read access is required")
    request = Request(
        f"https://api.github.com/repos/{repo}/{path}",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "nexus-symbiote-repository-controls",
        },
    )
    with build_opener(_NoRedirect()).open(request, timeout=15) as response:  # noqa: S310 - fixed HTTPS API origin
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("GitHub branch response exceeds the size limit")
    return json.loads(raw)


def fetch_branch(repo: str, branch: str, token: str) -> Any:
    if not branch or any(ord(c) < 32 for c in branch):
        raise ValueError("branch name is invalid")
    return _fetch(repo, f"branches/{quote(branch, safe='')}", token)


def _valid_sha(value: str) -> bool:
    return re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is not None


def evaluate_revision(metadata: Any, sha: str) -> list[str]:
    if not _valid_sha(sha):
        return ["an exact source commit SHA is required"]
    commit = metadata.get("commit") if isinstance(metadata, dict) else None
    if not isinstance(commit, dict) or commit.get("sha") != sha:
        return ["source SHA does not match the live branch head"]
    return []


def fetch_verification(repo: str, sha: str, token: str) -> tuple[Any, Any]:
    if not _valid_sha(sha):
        raise ValueError("an exact source commit SHA is required")
    # The file-specific endpoint prevents an unrelated workflow from supplying
    # an identically named check. Inspect the newest run, including queued runs;
    # an older successful attempt must not hide a later failure or pending run.
    response = _fetch(repo, f"actions/workflows/ci.yml/runs?head_sha={sha}&per_page=1", token)
    runs = response.get("workflow_runs") if isinstance(response, dict) else None
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        return None, None
    run = runs[0]
    run_id = run.get("id")
    if type(run_id) is not int or run_id <= 0:
        return run, None
    jobs = _fetch(repo, f"actions/runs/{run_id}/jobs?filter=latest&per_page=100", token)
    return run, jobs


def evaluate_verification(
    run: Any, response: Any, *, repo: str, branch: str, sha: str
) -> list[str]:
    if not isinstance(run, dict):
        return ["CI workflow evidence is unavailable for the source SHA"]
    source = run.get("head_repository")
    attempt = run.get("run_attempt")
    if (
        type(run.get("id")) is not int
        or run["id"] <= 0
        or type(attempt) is not int
        or attempt <= 0
        or run.get("head_sha") != sha
        or run.get("head_branch") != branch
        or run.get("path") != CI_WORKFLOW
        or run.get("event") not in {"push", "workflow_dispatch"}
        or not isinstance(source, dict)
        or not isinstance(source.get("full_name"), str)
        or source["full_name"].lower() != repo.lower()
    ):
        return ["CI evidence does not identify the expected repository, workflow and source"]
    errors = []
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        errors.append("the latest CI workflow run has not succeeded for the source SHA")
    jobs = response.get("jobs") if isinstance(response, dict) else None
    total = response.get("total_count") if isinstance(response, dict) else None
    if (
        not isinstance(jobs, list)
        or not jobs
        or type(total) is not int
        or total != len(jobs)
        or any(not isinstance(job, dict) for job in jobs)
    ):
        return [*errors, "CI job evidence is missing, incomplete or malformed"]
    for name in sorted(REQUIRED_CI_JOBS):
        matching = [job for job in jobs if job.get("name") == name]
        if len(matching) != 1 or any(
            job.get("run_id") != run["id"]
            or type(job.get("run_id")) is not int
            or job.get("run_attempt") != attempt
            or type(job.get("run_attempt")) is not int
            or job.get("status") != "completed"
            or job.get("conclusion") != "success"
            for job in matching
        ):
            errors.append(name + " did not succeed in the latest workflow attempt")
    return errors


def fetch_environment(repo: str, name: str, token: str) -> tuple[Any, Any]:
    if name not in PUBLICATION_ENVIRONMENTS:
        raise ValueError("unsupported publication environment")
    try:
        environment = _fetch(repo, f"environments/{name}", token)
    except HTTPError as error:
        if error.code != 404:
            raise
        # GitHub would create a missing environment, unprotected, on first use.
        error.close()
        return None, None
    policy = environment.get("deployment_branch_policy") if isinstance(environment, dict) else None
    if isinstance(policy, dict) and policy.get("custom_branch_policies") is True:
        listed = _fetch(repo, f"environments/{name}/deployment-branch-policies?per_page=100", token)
        return environment, listed
    return environment, None


def evaluate_environment(environment: Any, policies: Any, *, name: str, branch: str) -> list[str]:
    """Require a reviewer other than the dispatcher and deployments from the branch alone."""
    if not isinstance(environment, dict) or environment.get("name") != name:
        return [f"publication environment {name} is not configured"]
    rules = environment.get("protection_rules")
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        return [f"{name} environment protection metadata is malformed"]
    errors = []
    reviews = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    if (
        len(reviews) != 1
        or not isinstance(reviews[0].get("reviewers"), list)
        or not reviews[0]["reviewers"]
        or reviews[0].get("prevent_self_review") is not True
    ):
        errors.append(f"{name} environment must require a reviewer other than the dispatcher")
    policy = environment.get("deployment_branch_policy")
    listed = policies.get("branch_policies") if isinstance(policies, dict) else None
    total = policies.get("total_count") if isinstance(policies, dict) else None
    if (
        not isinstance(policy, dict)
        or policy.get("protected_branches") is not False
        or policy.get("custom_branch_policies") is not True
        or not isinstance(listed, list)
        or type(total) is not int
        or total != len(listed)
        # A policy without a type predates tag policies and names a branch.
        or [
            (p.get("name"), p.get("type", "branch")) if isinstance(p, dict) else None
            for p in listed
        ]
        != [(branch, "branch")]
    ):
        errors.append(f"{name} environment must allow deployments from {branch} alone")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--branch", default="main")
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--environment", choices=sorted(PUBLICATION_ENVIRONMENTS))
    args = parser.parse_args()
    try:
        if not _valid_sha(args.sha):
            raise ValueError("an exact source commit SHA is required")
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
        metadata = fetch_branch(args.repo, args.branch, token)
        errors = [*evaluate(metadata), *evaluate_revision(metadata, args.sha)]
        if not errors:
            run, jobs = fetch_verification(args.repo, args.sha, token)
            errors.extend(
                evaluate_verification(run, jobs, repo=args.repo, branch=args.branch, sha=args.sha)
            )
        if args.environment is not None:
            environment, policies = fetch_environment(args.repo, args.environment, token)
            errors.extend(
                evaluate_environment(
                    environment, policies, name=args.environment, branch=args.branch
                )
            )
    except (HTTPError, URLError, OSError, ValueError, RecursionError):
        # Do not include response bodies, headers or credential-bearing error text.
        print(
            "Repository controls could not be verified from GitHub; publication is blocked.",
            file=sys.stderr,
        )
        return 2
    for error in errors:
        print("Repository controls: " + error, file=sys.stderr)
    if errors:
        return 1
    scope = f" and the reviewed {args.environment} environment" if args.environment else ""
    print(
        "Repository controls verified: protected branch and successful CI for the exact "
        f"source{scope}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
