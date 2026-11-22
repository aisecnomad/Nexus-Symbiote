"""Adversarial acceptance cases for incomplete advisory and CodeQL evidence."""

from __future__ import annotations

import copy
import json
from datetime import date, timedelta

import pytest

from nexus_symbiote.scanners.live_mcp import HTTPReply
from tests.support import ROOT, load_script

advisories = load_script("check_dependency_advisories")
codeql = load_script("check_codeql_sarif")
release_checksums = load_script("release_checksums")
locks = load_script("check_locks")


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


def test_the_lock_inventory_includes_pins_for_other_pythons_and_platforms():
    packages = advisories.lock_inventory([ROOT / "requirements-ci.lock"])
    pinned = {(p["name"], p["version"]) for p in packages}
    ci = locks.read_lock(ROOT, "requirements-ci.lock")
    conditional = {
        (pin.name, str(pin.version)) for pins in ci.pins.values() for pin in pins if pin.marker
    }
    # importlib-metadata and zipp apply only below Python 3.12, colorama only on Windows:
    # the Python 3.12 Linux audit job never installs them, yet they must be queried.
    assert {"importlib-metadata", "zipp", "colorama"} <= {name for name, _ in conditional}
    assert conditional <= pinned
    action = locks.read_lock(ROOT, "requirements-action.lock")
    union = advisories.lock_inventory(
        [ROOT / "requirements-ci.lock", ROOT / "requirements-action.lock"]
    )
    assert {(p.name, str(p.version)) for ps in action.pins.values() for p in ps} <= {
        (p["name"], p["version"]) for p in union
    }


def report(*found):
    return {
        "complete": True,
        "passed": not found,
        "errors": [],
        "packages": [{"name": "requests", "version": "2.19.0"}],
        "advisories": [
            {"name": name, "version": version, "advisory_id": advisory}
            for name, version, advisory in found
        ],
    }


def waiver(**changes):
    return {
        "advisory_id": "GHSA-aaaa-bbbb-cccc",
        "package": "requests",
        "version": "2.19.0",
        "reason": "Not reachable: the Action never sends credentials through requests.",
        "expires": (date.today() + timedelta(days=30)).isoformat(),
        **changes,
    }


def test_a_reviewed_waiver_accepts_exactly_one_advisory_and_is_recorded(tmp_path):
    path = tmp_path / "waivers.json"
    path.write_text(json.dumps({"waivers": [waiver()]}))
    accepted = advisories.load_waivers(path, date.today())
    result = report(
        ("requests", "2.19.0", "GHSA-aaaa-bbbb-cccc"), ("requests", "2.19.0", "GHSA-other")
    )
    advisories.apply_waivers(result, accepted)
    assert result["passed"] is False
    assert [a["advisory_id"] for a in result["advisories"]] == ["GHSA-other"]
    assert [a["advisory_id"] for a in result["waived"]] == ["GHSA-aaaa-bbbb-cccc"]
    single = report(("requests", "2.19.0", "GHSA-aaaa-bbbb-cccc"))
    advisories.apply_waivers(single, accepted)
    assert single["passed"] is True and single["waived"][0]["reason"]


@pytest.mark.parametrize(
    "changes",
    [
        {"expires": -1},
        {"expires": 91},
        {"reason": "accepted"},
        {"version": None},
        {"extra": "field"},
    ],
)
def test_an_expired_open_ended_or_unexplained_waiver_is_rejected(tmp_path, changes):
    # Expiry offsets are applied to the same day the check uses, so the case does not
    # change meaning when collection and the test run fall on either side of midnight.
    today = date.today()
    if isinstance(changes.get("expires"), int):
        changes = {**changes, "expires": (today + timedelta(days=changes["expires"])).isoformat()}
    path = tmp_path / "waivers.json"
    path.write_text(json.dumps({"waivers": [waiver(**changes)]}))
    with pytest.raises(ValueError):
        advisories.load_waivers(path, today)


def test_an_unused_waiver_fails_so_stale_exceptions_are_removed():
    result = report()
    advisories.apply_waivers(result, [waiver()])
    assert result["passed"] is False
    assert "unused" in result["errors"][0]
    # A waiver for a version another inventory pins, such as the floor lock's, is not stale.
    other = report()
    other["packages"] = [{"name": "requests", "version": "2.0.0"}]
    advisories.apply_waivers(other, [waiver()])
    assert other["passed"] is True


def test_a_waiver_for_another_version_does_not_hide_the_advisory():
    result = report(("requests", "2.20.0", "GHSA-aaaa-bbbb-cccc"))
    advisories.apply_waivers(result, [waiver()])
    assert result["passed"] is False and result["advisories"]


def test_the_committed_waiver_file_is_valid():
    waivers = advisories.load_waivers(
        ROOT / "config/dependency-advisory-waivers.json", date.today()
    )
    assert isinstance(waivers, list)


def test_a_rejected_waiver_file_fails_the_gate_with_its_reason(tmp_path, monkeypatch, capsys):
    path = tmp_path / "waivers.json"
    path.write_text(json.dumps({"waivers": [waiver(reason="ok")]}))
    monkeypatch.setattr(advisories, "audit", lambda packages: report())
    monkeypatch.setattr(advisories, "installed_packages", lambda: [])
    out = tmp_path / "report.json"
    status = advisories.main(
        [
            "--lock",
            str(ROOT / "requirements-action.lock"),
            "--waivers",
            str(path),
            "--out",
            str(out),
        ]
    )
    assert status == 1
    assert "gives no reason" in capsys.readouterr().out
    assert json.loads(out.read_text())["passed"] is False


def test_unlocked_runner_tools_are_reported_but_not_audited(tmp_path, monkeypatch):
    audited = []

    def audit(packages):
        audited.extend(packages)
        return report()

    monkeypatch.setattr(advisories, "audit", audit)
    monkeypatch.setattr(
        advisories, "installed_packages", lambda: [{"name": "pip", "version": "99.0"}]
    )
    out = tmp_path / "report.json"
    missing = tmp_path / "no-waivers.json"
    status = advisories.main(
        [
            "--lock",
            str(ROOT / "requirements-action.lock"),
            "--waivers",
            str(missing),
            "--out",
            str(out),
        ]
    )
    written = json.loads(out.read_text())
    assert status == 0
    assert written["unlocked_installed"] == [{"name": "pip", "version": "99.0"}]
    assert {"name": "pip", "version": "99.0"} not in audited


def test_a_failure_to_list_runner_tools_keeps_the_finished_audit(tmp_path, monkeypatch):
    monkeypatch.setattr(advisories, "audit", lambda packages: report())

    def unreadable():
        raise OSError("site-packages is unreadable")

    monkeypatch.setattr(advisories, "installed_packages", unreadable)
    out = tmp_path / "report.json"
    status = advisories.main(
        [
            "--lock",
            str(ROOT / "requirements-action.lock"),
            "--waivers",
            str(tmp_path / "no-waivers.json"),
            "--out",
            str(out),
        ]
    )
    written = json.loads(out.read_text())
    assert status == 1
    assert written["errors"] == ["installed distributions outside the locks unavailable"]
    assert "advisories" in written and written["passed"] is False


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
                "invocations": [{"executionSuccessful": True}],
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
        "no-invocations",
        "empty-invocations",
        "empty-provenance",
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
    elif change == "no-invocations":
        del run["invocations"]
    elif change == "empty-invocations":
        run["invocations"] = []
    elif change == "empty-provenance":
        run["versionControlProvenance"] = []
    elif change == "no-severity":
        del run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    else:
        run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = "NaN"
    with pytest.raises(ValueError):
        codeql.evaluate(document, "a" * 40)


def test_codeql_policy_accepts_a_run_without_source_provenance():
    # The CodeQL CLI does not write versionControlProvenance by default; the CLI entry point
    # binds the analysis to the checkout instead.
    document = sarif("6.9")
    del document["runs"][0]["versionControlProvenance"]
    assert codeql.evaluate(document, "a" * 40)["passed"]


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
