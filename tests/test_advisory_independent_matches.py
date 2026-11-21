"""Evidence that establishes a version match survives an unreadable sibling range."""

import json
from pathlib import Path

import pytest

from tests.test_offline_advisories import (
    _bom_with_package,
    _transformers_record,
    match_offline_advisories,
)


@pytest.mark.parametrize("source", ["versions", "earlier range", "later range"])
def test_a_known_hit_is_reported_alongside_a_feed_error(tmp_path: Path, source: str) -> None:
    good = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0"}]}
    malformed = {"type": "ECOSYSTEM", "events": [{"fixed": "2.0"}]}
    ranges = [malformed]
    versions = []
    if source == "versions":
        versions = ["4.35.0"]
    else:
        ranges.insert(0 if source == "earlier range" else 1, good)
    path = tmp_path / "feed.json"
    path.write_text(json.dumps([_transformers_record(versions=versions, ranges=ranges)]))
    report, _ = match_offline_advisories(_bom_with_package(), db_path=path)
    assert not report.complete
    assert len(report.advisories) == 1
    assert len(report.errors) == 1
    assert "no introduced event" in report.errors[0]


@pytest.mark.parametrize("raw_type", ["git", "gıt"])
def test_only_the_osv_git_enum_is_skipped(tmp_path: Path, raw_type: str) -> None:
    bad = {"type": raw_type, "events": [{"introduced": "0"}]}
    path = tmp_path / "feed.json"
    path.write_text(json.dumps([_transformers_record(ranges=[bad])]))
    report, _ = match_offline_advisories(_bom_with_package(), db_path=path)
    assert not report.complete
    assert len(report.errors) == 1
    assert "range type is not supported" in report.errors[0]
