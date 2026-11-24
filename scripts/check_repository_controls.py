"""Require enforced checks, successful workflow evidence and release prerequisites.

Read-only. For the published SHA it requires branch protection, the newest trusted CI run
to have succeeded, and, with ``--publish``, the release-tag ruleset and the index
environment's protection. Publishing to PyPI also requires the commit to have been on the
branch for 24 hours, as its trusted CI runs show (``SOAK_OVERRIDE`` with a stated reason
waives that for an urgent fix), and the signed release tag to point at it. Only an
administrator's token can see who may bypass the ruleset: the workflow reports that it
could not, and ``--verify-bypass-actors``, for the administrator's own run, fails unless
the list is readable and empty and GitHub reports that the token cannot bypass it either.
Administrative configuration is a separate operator action; a checked-in policy file does
not protect a GitHub branch.
"""

from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import re
import ssl
import sys
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

REQUIRED_CHECKS = frozenset({"Verified CI"})
GITHUB_ACTIONS_APP_ID = 15368
REQUIRED_CI_JOBS = frozenset({"Verified CI", "CodeQL policy", "Dependency advisories"})
CI_WORKFLOW = ".github/workflows/ci.yml"
MAX_RESPONSE_BYTES = 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]
RUNS_PER_PAGE = 100
SOAK = timedelta(hours=24)
CLOCK_SKEW = timedelta(minutes=5)
MIN_OVERRIDE_REASON = 20
TAG_PATTERN = "refs/tags/v*"
TRUSTED_EVENTS = frozenset({"push", "workflow_dispatch"})
SIGNER_ENV = "ALLOWED_RELEASE_TAG_SIGNERS"


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


def _tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _strict_json(raw: bytes) -> Any:
    def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in items:
            if key in obj:
                raise ValueError("duplicate JSON key in GitHub API response")
            obj[key] = value
        return obj

    def _invalid_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant in GitHub API response: {value}")

    def _finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON number in GitHub API response")
        return number

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=_invalid_constant,
        parse_float=_finite_float,
    )


def _fetch(repo: str, path: str, token: str) -> Any:
    if re.fullmatch(r"(?!\.\.?/)[A-Za-z0-9_.-]+/(?!\.\.?$)[A-Za-z0-9_.-]+", repo) is None:
        raise ValueError("repository must be owner/name")
    if not token or any(c in token for c in "\r\n\x00"):
        raise ValueError(
            "a GitHub token with repository contents-read and Actions-read access is required"
        )
    request = Request(
        f"https://api.github.com/repos/{repo}/{path}",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "nexus-symbiote-repository-controls",
        },
    )
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=_tls_context()), _NoRedirect())
    with opener.open(request, timeout=15) as response:  # noqa: S310 - fixed HTTPS API origin
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("GitHub response exceeds the size limit")
    return _strict_json(raw)


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


def _trusted(run: Any, *, repo: str, branch: str, sha: str) -> bool:
    if not isinstance(run, dict):
        return False
    source = run.get("head_repository")
    return (
        type(run.get("id")) is int
        and run["id"] > 0
        and run.get("head_sha") == sha
        and run.get("head_branch") == branch
        and run.get("path") == CI_WORKFLOW
        and run.get("event") in TRUSTED_EVENTS
        and isinstance(source, dict)
        and isinstance(source.get("full_name"), str)
        and source["full_name"].lower() == repo.lower()
    )


def fetch_runs(repo: str, sha: str, token: str) -> list[Any] | None:
    """Every run of ci.yml for the SHA, or None when the list is malformed or truncated."""
    if not _valid_sha(sha):
        raise ValueError("an exact source commit SHA is required")
    response = _fetch(
        repo, f"actions/workflows/ci.yml/runs?head_sha={sha}&per_page={RUNS_PER_PAGE}", token
    )
    runs = response.get("workflow_runs") if isinstance(response, dict) else None
    total = response.get("total_count") if isinstance(response, dict) else None
    if not isinstance(runs, list) or type(total) is not int or total != len(runs):
        return None
    return runs


def newest_trusted_run(runs: list[Any], *, repo: str, branch: str, sha: str) -> Any:
    """The newest push or dispatch run of ci.yml on the branch in this repository.

    Runs from pull requests, forks and other branches can share the SHA and be newer; they
    are not evidence and must not displace the trusted run. A newer trusted run, pending or
    failed, still wins over an older success.
    """
    trusted = [run for run in runs if _trusted(run, repo=repo, branch=branch, sha=sha)]
    return max(trusted, key=lambda run: run["id"], default=None)


def fetch_verification(repo: str, sha: str, token: str, branch: str = "main") -> tuple[Any, Any]:
    # The file-specific endpoint prevents an unrelated workflow from supplying
    # an identically named check.
    runs = fetch_runs(repo, sha, token)
    if runs is None:
        return None, None
    run = newest_trusted_run(runs, repo=repo, branch=branch, sha=sha)
    if run is None:
        return None, None
    jobs = _fetch(repo, f"actions/runs/{run['id']}/jobs?filter=latest&per_page=100", token)
    return run, jobs


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def landed_at(
    metadata: Any, runs: list[Any], *, repo: str, branch: str, sha: str
) -> datetime | None:
    """When the SHA reached the branch, or None when no push run of it shows that.

    The commit time is whatever the committer's clock said, so the landing is the later of
    that and the first push run, which GitHub creates as the commit lands. A dispatch names
    its ref only by name, which a tag can share with the branch, so it cannot show that the
    commit was on the branch: a commit pushed with "[skip ci]" has no landing time.
    """
    commit = metadata.get("commit") if isinstance(metadata, dict) else None
    details = commit.get("commit") if isinstance(commit, dict) else None
    committer = details.get("committer") if isinstance(details, dict) else None
    committed = _timestamp(committer.get("date")) if isinstance(committer, dict) else None
    if committed is None:
        return None
    pushes: list[datetime] = []
    for run in runs:
        if _trusted(run, repo=repo, branch=branch, sha=sha):
            created = _timestamp(run.get("created_at"))
            if created is None:
                return None
            if run["event"] == "push":
                pushes.append(created)
    first = min(pushes, default=None)
    return None if first is None else max(committed, first)


def override_reason(override: str) -> str:
    """The stated reason, reduced to plain prose so that it cannot steer the runner's log."""
    return re.sub(r"[^A-Za-z0-9 .,;:()'/-]", "", override).strip()


def evaluate_soak(landed: datetime | None, now: datetime, override: str) -> list[str]:
    """Publishing to PyPI waits 24 hours after the release commit lands, unless explained."""
    reason = override_reason(override)
    if reason:
        if len(reason) < MIN_OVERRIDE_REASON:
            return ["a soak override must state its reason in at least 20 characters"]
        return []
    if landed is None:
        return ["the time the release commit reached the branch is unavailable"]
    if landed > now + CLOCK_SKEW:
        return ["the release commit time is in the future"]
    if now - landed < SOAK:
        hours = (now - landed).total_seconds() / 3600
        return [
            f"the release commit reached the branch {hours:.1f} hours ago; PyPI publication"
            " waits 24 hours (set soak_override with a reason for an urgent fix)"
        ]
    return []


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
        or run.get("event") not in TRUSTED_EVENTS
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


def fetch_tag_rulesets(repo: str, token: str) -> list[Any]:
    listing = _fetch(repo, "rulesets?targets=tag&per_page=100", token)
    if not isinstance(listing, list):
        raise ValueError("ruleset listing is malformed")
    return [
        _fetch(repo, f"rulesets/{entry['id']}", token)
        for entry in listing
        if isinstance(entry, dict)
        and entry.get("target") == "tag"
        and entry.get("enforcement") == "active"
        and type(entry.get("id")) is int
    ]


def _covers_release_tags(ruleset: Any) -> bool:
    """Active tag ruleset covering every v* tag without exclusions."""
    if (
        not isinstance(ruleset, dict)
        or ruleset.get("target") != "tag"
        or ruleset.get("enforcement") != "active"
    ):
        return False
    conditions = ruleset.get("conditions")
    names = conditions.get("ref_name") if isinstance(conditions, dict) else None
    include = names.get("include") if isinstance(names, dict) else None
    exclude = names.get("exclude", []) if isinstance(names, dict) else None
    if not isinstance(include, list) or exclude:
        return False
    return TAG_PATTERN in include or "~ALL" in include


def _guards_release_tags(ruleset: Any) -> bool:
    """Active, covering every v* tag and blocking updates and deletions."""
    if not _covers_release_tags(ruleset):
        return False
    rules = ruleset.get("rules")
    types = (
        {r.get("type") for r in rules if isinstance(r, dict)} if isinstance(rules, list) else set()
    )
    return {"update", "deletion"} <= types


def evaluate_tag_rulesets(
    rulesets: list[Any], *, verify_bypass_actors: bool = False
) -> tuple[list[str], list[str]]:
    """Errors and notices for the ruleset that must stop v* tags from moving or vanishing.

    No one may bypass it, the checking token included. GitHub returns ``bypass_actors`` only
    to a caller that may edit the ruleset, which means an administrator; the release
    workflow's token never sees it. ``current_user_can_bypass`` says whether the caller
    itself may. A missing or null value of either is unknown, never empty or "never": the
    workflow reports it, and the administrator's check (``verify_bypass_actors``) fails on it.
    """
    for ruleset in rulesets:
        if not _covers_release_tags(ruleset):
            continue
        rules = ruleset.get("rules")
        has_creation = isinstance(rules, list) and any(
            rule.get("type") == "creation" for rule in rules if isinstance(rule, dict)
        )
        if not has_creation:
            continue
        if _guards_release_tags(ruleset):
            return [
                "release-tag creation must use a separate creation-only ruleset with an"
                " authorized creator; the no-bypass immutability ruleset must allow creation"
            ], []
        if ruleset.get("bypass_actors") == []:
            return [
                "release-tag creation ruleset has no bypass actors, blocking all v* tag creation"
            ], []
    unknown_actors = unknown_caller = False
    for ruleset in rulesets:
        if not _guards_release_tags(ruleset):
            continue
        actors = ruleset.get("bypass_actors")
        caller = ruleset.get("current_user_can_bypass")
        if actors not in (None, []) or caller not in (None, "never"):
            continue
        if actors == [] and caller == "never":
            return [], []
        unknown_actors = unknown_actors or actors is None
        unknown_caller = unknown_caller or caller is None
    gaps: list[tuple[str, str]] = []
    if unknown_caller:
        gaps.append(
            (
                "GitHub did not report whether this token may bypass the release-tag ruleset",
                "GitHub did not report whether this token may bypass the release-tag ruleset;"
                " the administrator check (--verify-bypass-actors) shows whether anyone may",
            )
        )
    if unknown_actors:
        gaps.append(
            (
                "this token cannot read who may bypass the release-tag ruleset; run the check"
                " with a repository administrator's token",
                "the release-tag ruleset's bypass actors are visible only to administrators, so"
                " this token could not check them; the administrator check"
                " (--verify-bypass-actors) does",
            )
        )
    if not gaps:
        return [
            "no active ruleset without bypass stops refs/tags/v* from being moved or deleted"
        ], []
    if verify_bypass_actors:
        return [error for error, _ in gaps], []
    return [], [notice for _, notice in gaps]


def fetch_environment(repo: str, name: str, token: str) -> tuple[Any, Any]:
    environment = _fetch(repo, f"environments/{quote(name, safe='')}", token)
    policy = environment.get("deployment_branch_policy") if isinstance(environment, dict) else None
    policies = None
    if isinstance(policy, dict) and policy.get("custom_branch_policies") is True:
        policies = _fetch(
            repo,
            f"environments/{quote(name, safe='')}/deployment-branch-policies?per_page=100",
            token,
        )
    return environment, policies


def evaluate_environment(environment: Any, policies: Any, *, name: str, branch: str) -> list[str]:
    """The publishing environment must need a reviewer, admit no bypass and only the branch."""
    if not isinstance(environment, dict) or environment.get("name") != name:
        return [f"the {name} environment is unavailable"]
    errors = []
    if environment.get("can_admins_bypass") is not False:
        errors.append(f"administrators can bypass the {name} environment's protection rules")
    rules = environment.get("protection_rules")
    if not isinstance(rules, list) or not any(
        isinstance(rule, dict)
        and rule.get("type") == "required_reviewers"
        and isinstance(rule.get("reviewers"), list)
        and rule["reviewers"]
        for rule in rules
    ):
        errors.append(f"the {name} environment requires no reviewer")
    policy = environment.get("deployment_branch_policy")
    entries = policies.get("branch_policies") if isinstance(policies, dict) else None
    total = policies.get("total_count") if isinstance(policies, dict) else None
    if not isinstance(policy, dict):
        errors.append(f"the {name} environment accepts deployments from any branch")
    elif (
        # "Protected branches" admits every branch with a protection rule, not only this one.
        policy.get("custom_branch_policies") is not True
        or not isinstance(entries, list)
        or type(total) is not int
        or total != len(entries)
        or len(entries) != 1
        or not isinstance(entries[0], dict)
        or entries[0].get("name") != branch
        or entries[0].get("type", "branch") != "branch"
    ):
        errors.append(f"the {name} environment accepts deployments from refs other than {branch}")
    return errors


def project_version(root: Path = ROOT) -> str:
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    if not isinstance(version, str) or re.fullmatch(r"[0-9A-Za-z.+!-]{1,64}", version) is None:
        raise ValueError("project version is malformed")
    return version


def fetch_release_tag(repo: str, version: str, token: str) -> tuple[Any, Any]:
    try:
        ref = _fetch(repo, f"git/ref/tags/{quote('v' + version, safe='')}", token)
    except HTTPError as error:
        if error.code == 404:
            return None, None
        raise
    target = ref.get("object") if isinstance(ref, dict) else None
    tag = None
    if (
        isinstance(target, dict)
        and target.get("type") == "tag"
        and _valid_sha(target.get("sha", ""))
    ):
        tag = _fetch(repo, f"git/tags/{target['sha']}", token)
    return ref, tag


def _allowed_tag_signers(raw: str | None = None) -> frozenset[str]:
    source = os.environ.get(SIGNER_ENV, "") if raw is None else raw
    return frozenset(item.strip().lower() for item in source.split(",") if item.strip())


def evaluate_release_tag(
    ref: Any,
    tag: Any,
    *,
    version: str,
    sha: str,
    allowed_signers: frozenset[str] | None = None,
) -> list[str]:
    """The signed, annotated v<version> tag must already point at the commit being published."""
    name = f"v{version}"
    target = ref.get("object") if isinstance(ref, dict) else None
    if (
        not isinstance(ref, dict)
        or ref.get("ref") != f"refs/tags/{name}"
        or not isinstance(target, dict)
        or target.get("type") != "tag"
    ):
        return [f"push the signed, annotated tag {name} for the source commit before publishing"]
    commit = tag.get("object") if isinstance(tag, dict) else None
    if (
        not isinstance(tag, dict)
        or tag.get("tag") != name
        or not isinstance(commit, dict)
        or commit.get("type") != "commit"
        or commit.get("sha") != sha
    ):
        return [f"the release tag {name} does not point at the source commit"]
    verification = tag.get("verification")
    if not isinstance(verification, dict) or verification.get("verified") is not True:
        return [f"GitHub does not report a verified signature on the release tag {name}"]
    if allowed_signers is None:
        raw_signers = os.environ.get(SIGNER_ENV, "")
        signers = _allowed_tag_signers(raw_signers)
        if raw_signers != "" and not signers:
            return [f"{SIGNER_ENV} is set but names no allowed tag signer"]
    else:
        signers = allowed_signers
    if signers:
        tagger = tag.get("tagger")
        raw_email = tagger.get("email") if isinstance(tagger, dict) else None
        email = raw_email.strip().lower() if isinstance(raw_email, str) else ""
        if not email or email not in signers:
            return [f"the release tag {name} was not created by an allowed tag signer"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--branch", default="main")
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument(
        "--publish", choices=["testpypi", "pypi"], help="also check this index's prerequisites"
    )
    parser.add_argument(
        "--verify-bypass-actors",
        action="store_true",
        help="fail unless the release-tag ruleset's bypass list is readable and empty;"
        " needs a repository administrator's token",
    )
    args = parser.parse_args()
    if args.verify_bypass_actors and not args.publish:
        parser.error("--verify-bypass-actors needs --publish")
    notices: list[str] = []
    waiver: str | None = None
    try:
        if not _valid_sha(args.sha):
            raise ValueError("an exact source commit SHA is required")
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
        metadata = fetch_branch(args.repo, args.branch, token)
        errors = [*evaluate(metadata), *evaluate_revision(metadata, args.sha)]
        if not errors:
            run, jobs = fetch_verification(args.repo, args.sha, token, args.branch)
            errors.extend(
                evaluate_verification(run, jobs, repo=args.repo, branch=args.branch, sha=args.sha)
            )
        if not errors and args.publish:
            ruleset_errors, notices = evaluate_tag_rulesets(
                fetch_tag_rulesets(args.repo, token),
                verify_bypass_actors=args.verify_bypass_actors,
            )
            errors.extend(ruleset_errors)
            environment, policies = fetch_environment(args.repo, args.publish, token)
            errors.extend(
                evaluate_environment(environment, policies, name=args.publish, branch=args.branch)
            )
        if not errors and args.publish == "pypi":
            # A truncated or malformed listing leaves the landing time unknown; the commit
            # date alone is whatever the committer's clock said.
            runs = fetch_runs(args.repo, args.sha, token)
            landed = (
                None
                if runs is None
                else landed_at(metadata, runs, repo=args.repo, branch=args.branch, sha=args.sha)
            )
            override = os.environ.get("SOAK_OVERRIDE", "")
            soak_errors = evaluate_soak(landed, datetime.now(UTC), override)
            errors.extend(soak_errors)
            waiver = override_reason(override) if not soak_errors else None
            if waiver and not errors:
                print(f"Soak period waived by the publishing maintainer: {waiver}")
                notices.append(f"the 24-hour soak was waived: {waiver}")
            version = project_version()
            ref, tag = fetch_release_tag(args.repo, version, token)
            errors.extend(evaluate_release_tag(ref, tag, version=version, sha=args.sha))
    except (
        HTTPError,
        URLError,
        http.client.HTTPException,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RecursionError,
    ):
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
    for notice in notices:
        print("Repository controls notice: " + notice)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if notices and summary:
        # The run page is what the maintainer sees at the environment approval.
        try:
            with open(summary, "a", encoding="utf-8") as stream:
                stream.write("".join(f"- Repository controls notice: {n}\n" for n in notices))
        except OSError:
            print("The notices could not be added to the job summary.", file=sys.stderr)
    checked = "protected branch and successful CI for the exact source"
    if args.publish:
        checked += f", the release-tag ruleset and the {args.publish} environment"
    if args.publish == "pypi":
        soak = "the stated soak waiver" if waiver else "the 24-hour soak"
        checked += f", {soak} and the signed release tag"
    print(f"Repository controls verified: {checked}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
