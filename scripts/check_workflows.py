"""Reject mutable Action references, injectable shell and over-privileged workflows."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

# Events such as pull_request_target, workflow_run or issue_comment run with the base
# repository's token and secrets while handling content an outside contributor controls.
# None of this project's workflows needs them; allow only the events it uses.
ALLOWED_EVENTS = frozenset({"push", "pull_request", "schedule", "workflow_dispatch"})
# A self-hosted runner can be selected by a custom label alone, so accept only the
# image labels of GitHub-hosted runners.
HOSTED_RUNNER = re.compile(r"(?:ubuntu|windows|macos)-[0-9a-z.-]+")
# Contexts a pull request author or Action caller controls. A step that copies them
# into GITHUB_ENV or GITHUB_PATH could set variables or executables for later steps.
UNTRUSTED_CONTEXT = re.compile(r"\$\{\{[^}]*\b(?:github\.event\.|github\.head_ref|inputs\.)")
ENVIRONMENT_FILES = re.compile(r"\bGITHUB_(?:ENV|PATH)\b")


def _events(document: dict[Any, Any]) -> set[str]:
    events = document.get("on", document.get(True))
    if isinstance(events, str):
        return {events}
    if isinstance(events, (list, dict)):
        return {str(event) for event in events}
    return set()


def _job_errors(path: Path, name: str, job: dict[str, Any]) -> list[str]:
    errors = []
    timeout = job.get("timeout-minutes")
    if type(timeout) is not int or timeout <= 0:
        errors.append(f"{path}: {name} must set a positive integer timeout-minutes")
    runners = job.get("runs-on")
    runners = [runners] if isinstance(runners, str) else runners
    if (
        not isinstance(runners, list)
        or not runners
        or any(
            not isinstance(label, str) or not HOSTED_RUNNER.fullmatch(label) for label in runners
        )
    ):
        errors.append(f"{path}: {name} must run on GitHub-hosted runner labels")
    return errors


def _step_errors(path: Path, step: dict[str, Any], scope: str) -> list[str]:
    errors = []
    uses = step.get("uses")
    configured = step.get("with")
    settings: dict[str, Any] = configured if isinstance(configured, dict) else {}
    if isinstance(uses, str) and uses.startswith("actions/checkout@"):
        if settings.get("persist-credentials") not in {False, "false"}:
            errors.append(f"{path}: actions/checkout must set persist-credentials: false")
    if isinstance(uses, str) and uses.startswith("actions/github-script@"):
        if "${{" in str(settings.get("script", "")):
            errors.append(f"{path}: pass expressions through env, never script source")
    run = step.get("run")
    if isinstance(run, str) and ENVIRONMENT_FILES.search(run):
        if UNTRUSTED_CONTEXT.search(scope + str(step.get("env", ""))):
            errors.append(f"{path}: untrusted context must not reach GITHUB_ENV or GITHUB_PATH")
    return errors


def check(path: Path) -> list[str]:
    errors: list[str] = []
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return [f"{path}: expected a mapping"]
    if path.name == "action.yml":
        runs = document.get("runs")
        steps = runs.get("steps") if isinstance(runs, dict) else None
        for step in steps if isinstance(steps, list) else []:
            if isinstance(step, dict):
                errors.extend(_step_errors(path, step, ""))
    else:
        if _events(document) - ALLOWED_EVENTS:
            errors.append(
                f"{path}: only push, pull_request, schedule and workflow_dispatch triggers are allowed"
            )
        permissions = document.get("permissions")
        if not isinstance(permissions, dict) or any(
            value not in {"read", "none"} for value in permissions.values()
        ):
            errors.append(f"{path}: top-level permissions must be an explicit read-only mapping")
        # PyYAML's YAML 1.1 resolver interprets the GitHub key `on` as True.
        allowed = {
            "name",
            "run-name",
            "on",
            True,
            "permissions",
            "concurrency",
            "env",
            "defaults",
            "jobs",
        }
        if document.keys() - allowed:
            errors.append(f"{path}: unsupported workflow top-level fields")
        jobs = document.get("jobs", {})
        if not isinstance(jobs, dict) or not jobs:
            errors.append(f"{path}: workflow must define jobs")
        else:
            for name, job in jobs.items():
                if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
                    errors.append(f"{path}: {name} must define steps")
                    continue
                needs = job.get("needs", [])
                needs = [needs] if isinstance(needs, str) else needs
                if not isinstance(needs, list) or set(needs) - jobs.keys():
                    errors.append(f"{path}: {name} references unknown prerequisites")
                errors.extend(_job_errors(path, name, job))
                scope = str(document.get("env", "")) + str(job.get("env", ""))
                for step in job["steps"]:
                    if isinstance(step, dict):
                        errors.extend(_step_errors(path, step, scope))
            if path.name == "ci.yml":
                verified = jobs.get("verified", {})
                required = {
                    "test",
                    "coverage",
                    "quality",
                    "distribution",
                    "security-regressions",
                    "dependency-audit",
                    "codeql",
                }
                if (
                    not isinstance(verified, dict)
                    or verified.get("name") != "Verified CI"
                    or verified.get("if") != "always()"
                    or not isinstance(verified.get("needs"), list)
                    or not required <= jobs.keys()
                    or set(verified.get("needs", [])) != jobs.keys() - {"verified"}
                ):
                    errors.append(
                        f"{path}: Verified CI must always aggregate every verification job"
                    )

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "uses" and isinstance(child, str) and not child.startswith("./"):
                    if not re.fullmatch(r"[^@]+@[0-9a-f]{40}", child):
                        errors.append(f"{path}: Action must be pinned to a commit: {child}")
                if key == "run" and isinstance(child, str) and "${{" in child:
                    errors.append(f"{path}: pass expressions through env, never shell source")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(document)
    return errors


def main() -> int:
    errors = [
        error
        # GitHub runs workflows with either extension; checking only one would let
        # an unpinned or shell-injecting workflow through under the other.
        for path in [
            Path("action.yml"),
            *sorted(Path(".github/workflows").glob("*.yml")),
            *sorted(Path(".github/workflows").glob("*.yaml")),
        ]
        for error in check(path)
    ]
    for error in errors:
        print(error)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
