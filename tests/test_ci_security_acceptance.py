"""Adversarial acceptance cases for incomplete advisory, CodeQL and test-session evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from nexus_symbiote.scanners.live_mcp import HTTPReply

ROOT = Path(__file__).resolve().parents[1]


def script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


advisories = script("check_dependency_advisories")
codeql = script("check_codeql_sarif")
release_checksums = script("release_checksums")


class Transport:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.queries = []

    def request(self, endpoint, body, headers, *, timeout, max_bytes):
        assert endpoint == "https://api.osv.dev/v1/querybatch"
        assert 0 < timeout <= 20
        self.queries.append(json.loads(body)["queries"])
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return HTTPReply(200, {}, json.dumps(response).encode())


PACKAGES = [{"name": "requests", "version": "2.19.0"}]


def test_dependency_policy_follows_pages_without_losing_an_earlier_advisory():
    transport = Transport(
        {"results": [{"vulns": [{"id": "GHSA-example"}], "next_page_token": "second"}]},
        {"results": [{}]},
    )
    report = advisories.audit(PACKAGES, transport=transport)
    assert report["complete"] is True and report["passed"] is False
    assert report["advisories"] == [{**PACKAGES[0], "advisory_id": "GHSA-example"}]
    assert transport.queries[1][0] == {**transport.queries[0][0], "page_token": "second"}


@pytest.mark.parametrize(
    "responses",
    [
        ({"results": []},),
        ({"results": [{}], "error": {"message": "unknown query failure"}},),
        ({"results": [{"error": "unavailable"}]},),
        ({"results": [{"vulns": None}]},),
        ({"results": [{"vulns": [{"id": ""}]}]},),
        ({"results": [{"next_page_token": 1}]},),
        ({"results": [{"next_page_token": "cycle"}]}, {"results": [{"next_page_token": "cycle"}]}),
        (OSError("remote failure"),),
    ],
)
def test_dependency_policy_never_approves_incomplete_or_malformed_lookup(responses):
    report = advisories.audit(PACKAGES, transport=Transport(*responses))
    assert report["complete"] is False and report["passed"] is False
    assert report["errors"]


def test_dependency_policy_checks_every_batch_with_the_exact_version():
    packages = [{"name": f"package-{i}", "version": "1.0"} for i in range(101)]
    transport = Transport({"results": [{} for _ in range(100)]}, {"results": [{}]})
    report = advisories.audit(packages, transport=transport)
    assert report["complete"] and report["passed"]
    assert [len(batch) for batch in transport.queries] == [100, 1]
    assert transport.queries[-1] == [
        {"package": {"ecosystem": "PyPI", "name": "package-100"}, "version": "1.0"}
    ]


HASH = "--hash=sha256:" + "0" * 64


def test_locked_inventory_includes_pins_for_other_interpreters_and_platforms(tmp_path):
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "# generated\n"
        "\n"
        "Annotated_Types==0.8.0 \\\n"
        f"    {HASH} \\\n"
        f"    {HASH}\n"
        "    # via pydantic\n"
        "zipp==4.1.2 ; python_full_version < '3.12' \\\n"
        f"    {HASH}\n"
        "colorama==0.4.6 ; sys_platform == 'win32'\n"
        # pip strips indentation, so it installs an indented pin like any other.
        f"  indented==2.0 {HASH}\n"
    )
    assert advisories.locked_packages((lock,)) == [
        {"name": "annotated-types", "version": "0.8.0"},
        {"name": "colorama", "version": "0.4.6"},
        {"name": "indented", "version": "2.0"},
        {"name": "zipp", "version": "4.1.2"},
    ]


@pytest.mark.parametrize(
    "entry",
    [
        "loose>=1.0",
        "wildcard==1.*",
        "bounded==1.0,<2",
        "extra[socks]==1.0",
        "arbitrary===1.0",
        "-r other-requirements.txt",
        "--extra-index-url https://packages.example.invalid/simple",
        # pip strips indentation before it reads an entry, so indenting hides nothing.
        "  loose>=1.0",
        "\t-r other-requirements.txt",
        "  --extra-index-url https://packages.example.invalid/simple",
        # A hash line that continues no entry is an option line; pip follows the rest.
        f"    {HASH} -r other-requirements.txt",
        f"    {HASH} --extra-index-url https://packages.example.invalid/simple",
        # Only a line holding one whole SHA-256 digest is skipped as a hash.
        "    --hash=sha256:00",
    ],
)
def test_lock_entries_that_are_not_exact_pins_fail_the_audit(tmp_path, entry):
    lock = tmp_path / "requirements.lock"
    lock.write_text(f"good==1.0 \\\n    {HASH}\n    # via something\n")
    assert advisories.locked_packages((lock,)) == [{"name": "good", "version": "1.0"}]
    lock.write_text(lock.read_text() + entry + "\n")
    with pytest.raises(ValueError, match="exact pin"):
        advisories.locked_packages((lock,))


def test_reviewed_locks_cover_pins_the_audit_interpreter_does_not_install():
    pins = [
        line
        for path in advisories.LOCK_FILES
        for line in path.read_text().splitlines()
        if line[:1].isalnum()
    ]
    locked = advisories.locked_packages(advisories.LOCK_FILES)
    names = {package["name"] for package in locked}
    assert len(locked) == len({line.split(" ", 1)[0].lower() for line in pins})
    # Python 3.11 backports and Windows-only packages are installed elsewhere.
    for name in ("zipp", "importlib-metadata", "backports-tarfile", "colorama", "pywin32-ctypes"):
        assert name in names
    installed = [{"name": "pip", "version": "26.3"}, {"name": "zipp", "version": "0.1"}]
    merged = {(p["name"], p["version"]) for p in advisories.inventory(installed, locked)}
    assert merged == {("pip", "26.3"), ("zipp", "0.1")} | {
        (p["name"], p["version"]) for p in locked
    }


def test_dependency_cli_audits_installed_and_locked_identities(monkeypatch, tmp_path):
    audited = []

    def audit(packages, *, transport=None):
        audited.extend(packages)
        return {"complete": True, "passed": True, "advisories": [], "errors": []}

    monkeypatch.setattr(advisories, "audit", audit)
    monkeypatch.setattr("sys.argv", ["check", "--out", str(tmp_path / "report.json")])
    assert advisories.main() == 0
    names = {package["name"] for package in audited}
    assert {"pip", "zipp", "importlib-metadata"} <= names
    assert "nexus-symbiote" not in names


def test_scheduled_advisory_audit_repeats_the_ci_audit_outside_publication_evidence():
    workflows = ROOT / ".github" / "workflows"
    scheduled = yaml.safe_load((workflows / "dependency-audit.yml").read_text())
    ci = yaml.safe_load((workflows / "ci.yml").read_text())
    assert set(scheduled.get("on", scheduled.get(True))) == {"schedule", "workflow_dispatch"}
    assert scheduled["permissions"] == {"contents": "read"}
    # The publication preflight reads the newest ci.yml run for the release commit and
    # accepts only push and manual runs, so the schedule must not move into ci.yml.
    assert "schedule" not in ci.get("on", ci.get(True))

    def steps(job):
        normalized = []
        for step in job["steps"]:
            step = copy.deepcopy(step)
            if "uses" in step:
                # Dependabot moves the action pins of both workflows together.
                step["uses"] = step["uses"].split("@", 1)[0]
                step.get("with", {}).pop("name", None)
            normalized.append(step)
        return normalized

    assert steps(scheduled["jobs"]["dependency-audit"]) == steps(ci["jobs"]["dependency-audit"])


def test_session_guard_refuses_a_package_imported_from_another_checkout(monkeypatch, tmp_path):
    # A virtual environment shared by several worktrees holds one editable install;
    # the guard in another worktree's conftest must not accept it as its own source.
    other = tmp_path / "other-worktree"
    (other / "src" / "nexus_symbiote").mkdir(parents=True)
    (other / "src" / "nexus_symbiote" / "__init__.py").write_text("")
    (other / "tests").mkdir()
    shutil.copyfile(ROOT / "tests" / "conftest.py", other / "tests" / "conftest.py")
    spec = importlib.util.spec_from_file_location("other_conftest", other / "tests/conftest.py")
    assert spec and spec.loader
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    monkeypatch.setattr(guard, "_regular_install", lambda: None)
    with pytest.raises(pytest.UsageError, match="neither this checkout's"):
        guard.pytest_sessionstart(None)
    # A regular install, as when a built wheel is tested, is accepted from any checkout.
    imported = importlib.util.find_spec("nexus_symbiote")
    assert imported and imported.origin
    monkeypatch.setattr(guard, "_regular_install", lambda: os.path.realpath(imported.origin))
    guard.pytest_sessionstart(None)


def test_unreadable_lock_fails_the_dependency_cli_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(advisories, "LOCK_FILES", (tmp_path / "missing.lock",))
    monkeypatch.setattr("sys.argv", ["check", "--out", str(tmp_path / "report.json")])
    assert advisories.main() == 1
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["passed"] is False and report["complete"] is False


def sarif(score="7.5"):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/example",
                                "properties": {"tags": ["security"], "security-severity": score},
                            }
                        ],
                    }
                },
                "results": [{"ruleId": "py/example"}],
                "versionControlProvenance": [{"revisionId": "a" * 40}],
            }
        ],
    }


@pytest.mark.parametrize("score", ["7.0", "9.8", "10"])
def test_codeql_analysis_success_does_not_approve_high_critical_or_suppressed_findings(score):
    document = sarif(score)
    document["runs"][0]["results"][0].update(
        baselineState="unchanged", suppressions=[{"kind": "external", "status": "accepted"}]
    )
    report = codeql.evaluate(document, "a" * 40)
    assert report["complete"] is True and report["passed"] is False
    assert report["blocking_findings"]


def test_codeql_policy_accepts_no_high_security_findings_and_standard_extension_rules():
    document = sarif("6.9")
    driver = document["runs"][0]["tool"]["driver"]
    document["runs"][0]["tool"]["extensions"] = [{"rules": driver.pop("rules")}]
    assert codeql.evaluate(document, "a" * 40)["passed"]
    document["runs"][0]["results"] = []
    assert codeql.evaluate(document, "a" * 40)["passed"]


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "no-results",
        "no-runs",
        "unknown-rule",
        "failed-invocation",
        "no-severity",
        "invalid-severity",
    ],
)
def test_codeql_policy_denies_ambiguous_incomplete_or_wrong_revision_evidence(change):
    document = copy.deepcopy(sarif())
    run = document["runs"][0]
    if change == "source":
        run["versionControlProvenance"][0]["revisionId"] = "b" * 40
    elif change == "no-results":
        del run["results"]
    elif change == "no-runs":
        document["runs"] = []
    elif change == "unknown-rule":
        run["results"][0]["ruleId"] = "py/unknown"
    elif change == "failed-invocation":
        run["invocations"] = [{"executionSuccessful": False}]
    elif change == "no-severity":
        del run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    else:
        run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = "NaN"
    with pytest.raises(ValueError):
        codeql.evaluate(document, "a" * 40)


def test_codeql_cli_denies_a_pr_head_sha_when_checkout_is_the_merge_commit(monkeypatch, tmp_path):
    path = tmp_path / "python.sarif"
    path.write_text(json.dumps(sarif()))
    output = tmp_path / "report.json"
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setattr(codeql.subprocess, "check_output", lambda *_args, **_kw: "b" * 40)
    monkeypatch.setattr("sys.argv", ["check_codeql_sarif", str(path), "--out", str(output)])
    assert codeql.main() == 1
    assert json.loads(output.read_text())["complete"] is False


def test_candidate_checksums_bind_the_exact_source_and_evidence(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "candidate.whl").write_bytes(b"reviewable candidate")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "dependency-advisories.json").write_text('{"passed": true}')
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setattr(
        release_checksums.subprocess, "check_output", lambda *_args, **_kw: "a" * 40
    )
    monkeypatch.setattr(release_checksums.subprocess, "run", lambda *_args, **_kw: None)
    release_checksums.main()
    source = json.loads((tmp_path / "evidence" / "source-revision.json").read_text())
    assert source["source_sha"] == "a" * 40
    manifest = (tmp_path / "evidence" / "SHA256SUMS").read_text()
    assert "dist/candidate.whl" in manifest
    assert "evidence/source-revision.json" in manifest
    assert "evidence/dependency-advisories.json" in manifest
    monkeypatch.setattr(
        release_checksums.subprocess, "check_output", lambda *_args, **_kw: "b" * 40
    )
    with pytest.raises(ValueError, match="exact commit"):
        release_checksums.main()
