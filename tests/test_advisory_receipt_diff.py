"""diff compares offline advisory receipts by meaning, not as scanned-surface strings."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.offline_advisories import load_offline_advisory_db


def _feed(path: Path, *identifiers: str) -> Path:
    modified = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [
        {
            "id": identifier,
            "modified": modified,
            "affected": [{"package": {"ecosystem": "PyPI", "name": "pillow"}, "versions": ["1.0"]}],
        }
        for identifier in identifiers
    ]
    path.write_text(json.dumps(records), encoding="utf-8")
    return path


def _scan(project: Path, output: Path, *options: str) -> Path:
    result = CliRunner().invoke(
        main,
        ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output), *options],
    )
    assert result.exit_code == 0, result.output
    return output


def _diff(old: Path, new: Path) -> tuple[int, dict]:
    result = CliRunner().invoke(main, ["diff", str(old), str(new), "--json-output"])
    return result.exit_code, json.loads(result.stdout)


def _project(tmp_path: Path, requirements: str) -> Path:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    (project / "requirements.txt").write_text(requirements, encoding="utf-8")
    return project


def test_a_refreshed_feed_is_a_note_that_names_both_digests(tmp_path: Path) -> None:
    project = _project(tmp_path, "langchain==0.3.27\npillow==9.0.0\n")
    monday = _feed(tmp_path / "monday" / "osv.json", "PYSEC-1")
    tuesday = _feed(tmp_path / "tuesday" / "osv.json", "PYSEC-1", "PYSEC-2")
    options = ("--all-packages", "--advisory-db")
    old = _scan(project, tmp_path / "old.json", *options, str(monday))
    new = _scan(project, tmp_path / "new.json", *options, str(tuesday))
    code, report = _diff(old, new)
    assert code == 0, report
    assert report["security_alerts"] == []
    (change,) = report["metadata_changes"]
    assert change["severity"] == "info"
    for feed in (monday, tuesday):
        assert load_offline_advisory_db(feed)[1] in change["detail"]


def test_an_added_pin_does_not_narrow_advisory_coverage(tmp_path: Path) -> None:
    feed = _feed(tmp_path / "operator" / "osv.json", "PYSEC-1")
    options = ("--all-packages", "--advisory-db", str(feed))
    project = _project(tmp_path, "langchain==0.3.27\n")
    old = _scan(project, tmp_path / "old.json", *options)
    _project(tmp_path, "langchain==0.3.27\nrequests==2.31.0\n")
    new = _scan(project, tmp_path / "new.json", *options)
    _, report = _diff(old, new)
    assert [alert["severity"] for alert in report["security_alerts"]] == ["medium"]
    assert "requests" in report["security_alerts"][0]["alert"]


def test_narrowed_advisory_coverage_alerts(tmp_path: Path) -> None:
    feed = _feed(tmp_path / "operator" / "osv.json", "PYSEC-1")
    options = ("--all-packages", "--advisory-db", str(feed))
    project = _project(tmp_path, "langchain==0.3.27\nrequests==2.31.0\n")
    baseline = _scan(project, tmp_path / "baseline.json", *options)

    _project(tmp_path, "langchain==0.3.27\n")
    fewer = _scan(project, tmp_path / "fewer.json", *options)
    _, report = _diff(baseline, fewer)
    assert any(
        "advisory coverage narrowed" in alert["alert"]
        and "components_checked 2 → 1" in alert["alert"]
        for alert in report["security_alerts"]
        if alert["severity"] == "high"
    ), report["security_alerts"]

    _project(tmp_path, "langchain==0.3.27\nrequests==2.31.0\nflask>=2\n")
    partial = _scan(project, tmp_path / "partial.json", *options)
    _, report = _diff(baseline, partial)
    assert any(
        "advisory coverage narrowed" in alert["alert"]
        and "coverage complete → partial" in alert["alert"]
        for alert in report["security_alerts"]
    ), report["security_alerts"]

    _project(tmp_path, "langchain==0.3.27\nrequests==2.31.0\n")
    unchecked = _scan(project, tmp_path / "unchecked.json", "--all-packages")
    code, report = _diff(baseline, unchecked)
    assert code == 1
    assert any(
        "offline advisory matching is no longer recorded" in alert["alert"].lower()
        for alert in report["security_alerts"]
    ), report["security_alerts"]
