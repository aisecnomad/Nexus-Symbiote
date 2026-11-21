"""Offline advisory matching: indexed cost, the advisory-matches budget, and equivalence.

The indexed matcher must report exactly what pairwise matching reported: the same matches,
fixed versions and undecidable bounds for every block, and the same error for every block
it cannot decide. The reference below is the pairwise matcher this module replaced, as of
37b3cfce (unparsable upper bounds flag a match, and stop parsable ones excluding a version
in the interval event order puts them in; limits exclude only a version at or above all of
them; malformed blocks, an unparsable ``introduced`` and an unparsable queried version are
errors), kept as the oracle. It differs from that matcher in its names and in the three
rules of #303: a run of consecutive ``introduced`` events owns the bounds after it together,
and a range of a type OSV does not define, or with no ``introduced``, is an error.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from typing import Any

import pytest
from click.testing import CliRunner
from packaging.version import InvalidVersion, Version

import nexus_symbiote.offline_advisories as offline
from nexus_symbiote import limits
from nexus_symbiote.advisories import package_identity
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import RegistryEntryComponent
from tests.support import scaling_ratio

# #296 rates the feed's age against the caller's clock. These tests date every record
# now, so a feed-age error never stands in for the matching behaviour under test.
NOW = datetime.now(UTC)
MODIFIED = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
_match_offline_advisories = partial(offline.match_offline_advisories, now=NOW)


def _reference_compare(ecosystem: str, left: str, right: str) -> int | None:
    if ecosystem == "PyPI":
        try:
            lv, rv = Version(left), Version(right)
        except InvalidVersion:
            return None
        return -1 if lv < rv else (1 if lv > rv else 0)
    if ecosystem == "npm":
        lk, rk = offline._semver_key(left), offline._semver_key(right)
        if lk is None or rk is None:
            return None
        return -1 if lk < rk else (1 if lk > rk else 0)
    return None


def _reference_range_matches(
    ecosystem: str, version: str, rng: dict[str, Any]
) -> tuple[bool, list[str], list[str]]:
    """Evaluate one OSV range: (in range, fixed versions above it, unparsable upper bounds).

    The queried version and every ``introduced`` must parse; another event that does not
    leaves the version possibly affected, and is reported. It is out of range below its
    ``introduced``, at or above every ``limit`` when all parse and none is "*" (a version
    below any limit is in range), or past a parsable bound of an interval with none unparsable.
    """
    raw_type = rng.get("type")
    if raw_type is not None:
        if isinstance(raw_type, str) and raw_type.isascii() and raw_type.lower() == "git":
            return False, [], []
        if (
            not isinstance(raw_type, str)
            or not raw_type.isascii()
            or raw_type.lower() not in {"ecosystem", "semver"}
        ):
            raise ValueError("OSV range type is not supported")
    events = rng.get("events")
    if not isinstance(events, list):
        raise ValueError("OSV range events are not a list")

    def cmp(left: str, right: str) -> int:
        if (result := _reference_compare(ecosystem, left, right)) is None:
            raise ValueError("OSV range version cannot be compared")
        return result

    has_zero_intro = False
    found: dict[str, list[str]] = {"introduced": [], "fixed": [], "last_affected": [], "limit": []}
    ordered: list[tuple[str, str]] = []
    for ev in events:
        kind, raw = next(iter(ev.items())) if isinstance(ev, dict) and len(ev) == 1 else ("", "")
        if kind == "introduced" and raw in ("0", 0) and not isinstance(raw, bool):
            has_zero_intro = True
            ordered.append((kind, "0"))
        elif kind in found and isinstance(raw, str) and raw.strip():
            found[kind].append(raw.strip())
            ordered.append((kind, raw.strip()))
        else:
            raise ValueError("OSV range event cannot be parsed")
    intros, fixed_versions, last_affected, limits = found.values()
    if not has_zero_intro and not intros:
        raise ValueError("OSV range has no introduced event")

    cmp(version, version)
    best_intro: str | None = None
    found_intro = has_zero_intro
    for intro in intros:
        if cmp(intro, version) > 0:
            continue
        found_intro = True
        if best_intro is None or cmp(intro, best_intro) > 0:
            best_intro = intro
    if not found_intro:
        return False, [], []

    bounds = (*fixed_versions, *last_affected, *(lim for lim in limits if lim != "*"))
    unparsed = [b for b in bounds if _reference_compare(ecosystem, b, b) is None]

    def ends_after_intro(bound: str) -> bool:
        decided = not open_interval and bound not in unparsed
        return decided and (best_intro is None or cmp(best_intro, bound) <= 0)

    run: list[str] = []  # the consecutive introduced events an event follows; empty before any
    bounded = False  # a fixed or last_affected has followed the run
    open_interval = False  # an unparsable bound may close the version's interval
    for kind, value in ordered:
        if kind == "introduced":
            run, bounded = ([value], False) if bounded else ([*run, value], False)
            continue
        if kind == "limit":
            continue
        bounded = True
        held = not run or any(cmp(owner, best_intro or "0") == 0 for owner in run)
        open_interval |= held and value in unparsed
    if (
        all(x != "*" and x not in unparsed and cmp(version, x) >= 0 for x in limits or ["*"])
        or any(ends_after_intro(fix) and cmp(fix, version) <= 0 for fix in fixed_versions)
        or any(ends_after_intro(last) and cmp(last, version) < 0 for last in last_affected)
    ):
        return False, [], []
    fixed_above = [fix for fix in fixed_versions if fix not in unparsed and cmp(fix, version) > 0]
    return True, fixed_above, [bound[:64] for bound in unparsed]


def _reference_matches_affected_version(
    affected: dict[str, Any], ecosystem: str, version: str
) -> tuple[bool, list[str], list[str], str | None]:
    """Evaluate each range independently; keep a settled match alongside the first error."""
    raw_versions, raw_ranges = affected.get("versions", []), affected.get("ranges", [])
    if not isinstance(raw_versions, list) or not isinstance(raw_ranges, list):
        return False, [], [], "OSV affected versions or ranges are not a list"
    listed = any(
        isinstance(ver, str)
        and (ver == version or _reference_compare(ecosystem, version, ver) == 0)
        for ver in raw_versions
    )
    hits = []
    reason = None
    for rng in raw_ranges:
        try:
            matched, fixes, bounds = _reference_range_matches(
                ecosystem, version, rng if isinstance(rng, dict) else {}
            )
        except ValueError as exc:
            reason = reason or str(exc)
            continue
        if matched:
            hits.append((fixes, bounds))
    if reason is not None:
        hits = [(fixes, bounds) for fixes, bounds in hits if not bounds]
    fixes = sorted({fix for found, _ in hits for fix in found})
    settled = listed or any(not bounds for _, bounds in hits)
    bounds = [] if settled else sorted({bound for _, items in hits for bound in items})
    return listed or bool(hits), fixes, bounds, reason


_Block = tuple[str, list[str], list[str]]


def _reference_blocks(
    blocks: list[tuple[str, dict[str, Any]]], ecosystem: str, version: str
) -> tuple[list[_Block], list[tuple[str, str]], list[str | None]]:
    """Pairwise matching of one version: each matching block's record id, fixed versions and
    undecidable bounds, each undecided block's reason, both in order, and every block's
    reason (None when decided).
    """
    found: list[_Block] = []
    undecided: list[tuple[str, str]] = []
    outcomes: list[str | None] = []
    for record_id, affected in blocks:
        hit, fixed, bounds, reason = _reference_matches_affected_version(
            affected, ecosystem, version
        )
        outcomes.append(reason)
        if reason is not None:
            undecided.append((record_id, reason))
        if hit:
            found.append((record_id, fixed, bounds))
    return found, undecided, outcomes


def _indexed_blocks(
    matcher: offline._PackageMatcher, version: str, budget: offline._MatchBudget
) -> tuple[list[_Block], list[tuple[str, str]]]:
    found, failed = matcher.matches(version, budget)
    return (
        [(adv.record_id, fixed, bounds) for adv, fixed, bounds in found],
        [(adv.record_id, reason) for adv, reason in failed],
    )


_VERSIONS = {
    "PyPI": [
        *(f"{major}.{minor}" for major in range(4) for minor in range(4)),
        *("1.0.0", "1.2.0rc1", "1.2.0.dev3", "1.2.post1", "1!0.5", "2.0a1", "v2.1", " 1.3 "),
        *("01.2", "1.0.0.0", "3.0+local", "2.0-alpha.1", "not-a-version", "1.x", "", "0"),
    ],
    "npm": [
        *(
            f"{major}.{minor}.{patch}"
            for major in range(3)
            for minor in range(3)
            for patch in (0, 4)
        ),
        *("1", "1.2", "v2.1.0", "1.2.3-alpha.1", "1.2.3-alpha.beta", "1.2.3-1", "1.2.3-rc.10"),
        *("1.2.3+build", " 2.0.0 ", "01.2.3", "1.0.0.0", "1!0.5", "not-a-version", "1.x", "", "0"),
    ],
}
# Event versions are mostly ones the ecosystem parses, so most ranges can be decided and
# the ones that cannot are each about one unparseable version, whose effect depends on
# which comparisons the component version leads evaluation to make.
_PARSEABLE = {
    eco: [v for v in vs if offline._version_key(eco, v) is not None]
    for eco, vs in _VERSIONS.items()
}
# Bounds no ecosystem parses, two of them alike in their first 64 characters, so a cut
# report of both is one bound.
_UNPARSEABLE = {
    eco: [
        *(v for v in vs if v.strip() and offline._version_key(eco, v) is None),
        *("2.6.0-NA!", "z" * 70 + "#", "z" * 70 + "$"),
    ]
    for eco, vs in _VERSIONS.items()
}
# Each event shape pairwise matching refuses: several keys, no key, not an object, an unknown key, a
# value that is not a non-empty string, and the integers and booleans "0" must not admit.
_MALFORMED_EVENTS: list[object] = [
    {"introduced": "1.0", "fixed": "2.0"},
    {"fixed": "1.0", "limit": "2.0"},
    {},
    "event",
    None,
    ["introduced", "0"],
    {"withdrawn": "1.0"},
    {"fixed": 3},
    {"last_affected": None},
    {"limit": "  "},
    {"introduced": ""},
    {"introduced": True},
    {"introduced": False},
    {"introduced": 5},
    {"introduced": "0", "limit": "*"},
]


def _random_event(rng: random.Random, ecosystem: str) -> object:
    pool = _UNPARSEABLE if rng.random() < 0.04 else _PARSEABLE
    version = rng.choice(pool[ecosystem])
    roll = rng.random()
    if roll < 0.30:
        return {"introduced": rng.choice([version, version, version, "0", "0", 0, 0.0])}
    if roll < 0.58:
        return {"fixed": version}
    if roll < 0.73:
        return {"last_affected": version}
    if roll < 0.83:
        return {"limit": rng.choice([version, version, "*", " * "])}
    if roll < 0.97:
        return {"introduced": version}
    return rng.choice(_MALFORMED_EVENTS)


def _random_block(rng: random.Random, ecosystem: str) -> dict[str, Any]:
    versions = _VERSIONS[ecosystem]
    block: dict[str, Any] = {}
    if rng.random() < 0.4:
        block["versions"] = [rng.choice([*versions, 7, None]) for _ in range(rng.randint(0, 4))]
    if rng.random() < 0.03:
        block["versions"] = rng.choice(["1.0", None, {"1.0": True}])
    if rng.random() < 0.9:
        ranges: list[object] = []
        for _ in range(rng.randint(0, 3)):
            roll = rng.random()
            events: list[object] = (
                [{"introduced": "0"}, *rng.choice([[], [{"limit": "*"}]])]
                if roll < 0.08
                else [_random_event(rng, ecosystem) for _ in range(rng.randint(0, 6))]
            )
            if 0.08 <= roll < 0.2:
                # One version that cannot be compared, among ones that can: an error as an
                # introduced, otherwise a bound that parsable ones may or may not overrule.
                kind = rng.choice(["introduced", "fixed", "last_affected", "limit"])
                bad = {kind: rng.choice(_UNPARSEABLE[ecosystem])}
                events.insert(rng.randint(0, len(events)), bad)
            elif 0.2 <= roll < 0.3:
                # Two ordered intervals, an unparsable bound among one's parsable bounds or
                # before both (the PYSEC-2024-264 shape): it keeps only its own one open.
                cuts = sorted(
                    rng.sample(_PARSEABLE[ecosystem], 4),
                    key=lambda text: offline._version_key(ecosystem, text),
                )
                events = [{"introduced": rng.choice([cuts[0], "0"])}, {"fixed": cuts[1]}]
                events += [{"introduced": cuts[2]}, {"last_affected": cuts[3]}]
                bad = {rng.choice(["fixed", "last_affected"]): rng.choice(_UNPARSEABLE[ecosystem])}
                events.insert(rng.randint(0, len(events)), bad)
            elif 0.3 <= roll < 0.4:
                # Several limits: a version below any of them is in range, and a "*" or an
                # unparsable one keeps every version in range (the latter flagged).
                pool = [*_PARSEABLE[ecosystem], "*", " * ", *_UNPARSEABLE[ecosystem][:2]]
                events = [{"introduced": rng.choice([*_PARSEABLE[ecosystem], "0"])}]
                events += [{"limit": rng.choice(pool)} for _ in range(rng.randint(2, 3))]
                events += [{"fixed": rng.choice(_PARSEABLE[ecosystem])}] * rng.randint(0, 1)
                rng.shuffle(events)
            entry: dict[str, Any] = {"events": events}
            kind = rng.choice(["ECOSYSTEM", "SEMVER", "semver", None, None, "GIT", 7])
            if kind is not None:
                entry["type"] = kind
            if rng.random() < 0.04:
                entry["events"] = rng.choice([None, "events", {"introduced": "0"}])
            if rng.random() < 0.02:
                del entry["events"]
            ranges.append(entry if rng.random() < 0.96 else rng.choice(["range", 7, None, []]))
        block["ranges"] = (
            ranges if rng.random() < 0.97 else rng.choice([{"type": "ECOSYSTEM"}, "ranges", None])
        )
    return block


def _advisory(record_id: str) -> offline._ParsedAdvisory:
    return offline._ParsedAdvisory(record_id, (), "", "unknown", ())


@pytest.mark.parametrize("ecosystem", ["PyPI", "npm"])
def test_the_indexed_matcher_reports_what_pairwise_matching_reported(ecosystem):
    rng = random.Random(273)  # noqa: S311 - a reproducible corpus, not a secret
    versions = _VERSIONS[ecosystem]
    budget = offline._MatchBudget(10**9)
    counts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    for _ in range(600):
        blocks = [
            (f"GHSA-{rng.randint(0, 5)}", _random_block(rng, ecosystem))
            for _ in range(rng.randint(1, 8))
        ]
        matcher = offline._PackageMatcher(
            ecosystem, [(_advisory(record_id), block) for record_id, block in blocks], budget
        )
        flagged_or_not: list[set[bool]] = [set() for _ in blocks]
        for version in versions:
            expected, expected_undecided, _ = _reference_blocks(blocks, ecosystem, version)
            found, undecided = _indexed_blocks(matcher, version, budget)
            assert found == expected, (ecosystem, version, blocks)
            assert undecided == expected_undecided, (ecosystem, version, blocks)
            reasons.update(reason for _, reason in expected_undecided)
            parsed = offline._version_key(ecosystem, version) is not None
            counts["matched" if expected else "unmatched"] += 1
            counts["matched and undecided"] += bool(expected) and bool(expected_undecided)
            counts["with fixes"] += any(fixed for _, fixed, _ in expected)
            counts["flagged blocks"] += sum(bool(bounds) for *_, bounds in expected)
            counts["long bounds cut"] += any(
                len(bound) == 64 for *_, bounds in expected for bound in bounds
            )
            counts["unparsed version matched"] += bool(expected) and not parsed
            if parsed:
                hits = {record: bool(bounds) for record, _, bounds in expected}
                for seen, (record, _) in zip(flagged_or_not, blocks, strict=True):
                    if record in hits:
                        seen.add(hits[record])
        # A record flagged for some versions and decided for others: the parsable bounds
        # and listings that overrule an unparsable one are what the index must reproduce.
        counts["flag varies by version"] += sum(seen == {True, False} for seen in flagged_or_not)
    assert min(counts["matched"], counts["unmatched"]) > 2_000
    assert counts["matched and undecided"] > 500
    assert counts["with fixes"] > 500
    assert counts["flagged blocks"] > 1_000
    assert counts["long bounds cut"] > 50
    assert counts["unparsed version matched"] > 20
    assert counts["flag varies by version"] > 50
    assert min(reasons.values()) > 300
    assert set(reasons) == {
        "OSV affected versions or ranges are not a list",
        "OSV range events are not a list",
        "OSV range event cannot be parsed",
        "OSV range has no introduced event",
        "OSV range type is not supported",
        "OSV range version cannot be compared",
    }


def test_flags_and_errors_follow_the_pairwise_rules_on_a_worked_example():
    compared, not_a_list = "OSV range version cannot be compared", "OSV range events are not a list"
    blocks = [
        # An unparsable fix: a flagged match once the version reaches the introduced.
        ("GHSA-1", {"ranges": [{"events": [{"introduced": "2.0"}, {"fixed": "nope!"}]}]}),
        # A parsable version reaches the second range; one that does not parse stops first.
        (
            "GHSA-2",
            {
                "ranges": [
                    {"events": [{"introduced": "0"}, {"limit": "1.0"}, {"limit": "x!"}]},
                    {"events": "bad"},
                ]
            },
        ),
        # The unparsable bound shares the fix's interval, so the fix excludes nothing and
        # the match is flagged; the listing decides 2.5, so that match is not.
        (
            "GHSA-3",
            {
                "versions": ["2.5"],
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "2.0"}, {"last_affected": "j!"}]}
                ],
            },
        ),
        # Only the identical string lists a version that does not parse.
        ("GHSA-4", {"versions": ["not-a-version"]}),
        # An unparsable introduced is an error for every version.
        ("GHSA-5", {"ranges": [{"events": [{"introduced": "bad!"}]}]}),
        # Event order puts the unparsable bound in the interval from 0, not the one from 1.0.
        (
            "GHSA-6",
            {
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"last_affected": "j2!"},
                            {"introduced": "1.0"},
                            {"fixed": "2.0"},
                        ]
                    }
                ]
            },
        ),
    ]
    budget = offline._MatchBudget(10**6)
    matcher = offline._PackageMatcher(
        "PyPI", [(_advisory(record_id), block) for record_id, block in blocks], budget
    )
    always = [("GHSA-2", not_a_list), ("GHSA-5", compared)]
    expected = {
        "0.5": ([("GHSA-3", ["2.0"], ["j!"]), ("GHSA-6", ["2.0"], ["j2!"])], always),
        "1.5": ([("GHSA-3", ["2.0"], ["j!"]), ("GHSA-6", ["2.0"], ["j2!"])], always),
        "2.5": ([("GHSA-1", [], ["nope!"]), ("GHSA-3", [], [])], always),
        "not-a-version": (
            [("GHSA-4", [], [])],
            [
                *(("GHSA-1", compared), ("GHSA-2", compared), ("GHSA-3", compared)),
                *(("GHSA-5", compared), ("GHSA-6", compared)),
            ],
        ),
    }
    for version, (found, undecided) in expected.items():
        assert _reference_blocks(blocks, "PyPI", version)[:2] == (found, undecided)
        assert _indexed_blocks(matcher, version, budget) == (found, undecided)


def _component(name: str, version: str, kind: str = "pypi") -> RegistryEntryComponent:
    return RegistryEntryComponent(
        bom_ref=f"pkg:{kind}:{name}@{version}",
        name=name,
        version=version,
        registry_type=kind,
        package_url=f"pkg:{kind}/{name}@{version}",
    )


# The default cap lists the first errors; without one, every error must match too.
@pytest.mark.parametrize("cap", [offline.MAX_OFFLINE_ERRORS, 10**9])
def test_a_random_bundle_gives_the_report_pairwise_matching_gave(tmp_path, monkeypatch, cap):
    monkeypatch.setattr(offline, "MAX_OFFLINE_ERRORS", cap)
    rng = random.Random(20)  # noqa: S311 - a reproducible corpus, not a secret
    pinned = {
        "pypi": [v for v in _VERSIONS["PyPI"] if v == v.strip() and v[:1].isdigit()],
        "npm": [v for v in _VERSIONS["npm"] if v.count(".") == 2 and v[:1].isdigit()],
    }
    names = [f"package-{index}" for index in range(12)]
    records = []
    for index in range(300):
        kind = rng.choice(["pypi", "npm"])
        ecosystem = "PyPI" if kind == "pypi" else "npm"
        affected = []
        for _ in range(rng.randint(1, 3)):
            block = _random_block(rng, ecosystem)
            block["package"] = {
                "ecosystem": rng.choice([ecosystem, ecosystem.lower()]),
                "name": rng.choice(names),
            }
            affected.append(block)
        records.append(
            {
                "id": f"GHSA-{index:04d}",
                "aliases": [f"CVE-2026-{rng.randint(0, 150):04d}"] if rng.random() < 0.5 else [],
                "summary": f"summary {index}",
                "modified": MODIFIED,
                "affected": affected,
            }
        )
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(records), encoding="utf-8")
    components = []
    for kind, versions in pinned.items():
        for name in names:
            for version in versions:
                component = _component(name, version, kind)
                try:
                    package_identity(component)
                except ValueError:
                    continue
                components.append(component)

    report, _ = _match_offline_advisories(AIBOM(components=components), db_path=db_file)

    assert report.components_checked == len(components) > 400
    parsed = offline._parse_osv_records(records)
    expected = []
    errors = []
    # The record merge, alias deduplication and error cap of pairwise matching at 37b3cfce.
    unlisted_errors = 0
    for component in sorted(components, key=lambda item: item.bom_ref):
        ecosystem = "PyPI" if component.registry_type == "pypi" else "npm"
        matched_by_adv: dict[str, tuple[offline._ParsedAdvisory, list[str], list[str]]] = {}
        for adv in parsed:
            for block in adv.affected:
                package = block["package"]
                if (package["ecosystem"].lower(), package["name"]) != (
                    component.registry_type,
                    component.name,
                ):
                    continue
                is_match, fixed, undecided, reason = _reference_matches_affected_version(
                    block, ecosystem, component.version
                )
                if reason is not None:
                    unlisted_errors += len(errors) >= offline.MAX_OFFLINE_ERRORS
                    if len(errors) < offline.MAX_OFFLINE_ERRORS:
                        errors.append(
                            f"{component.bom_ref}: offline advisory {adv.record_id}: {reason}"
                        )
                if is_match:
                    hit = matched_by_adv.setdefault(adv.record_id, (adv, [], list(undecided)))
                    hit[1].extend(fixed)
                    hit[2][:] = [*hit[2], *undecided] if hit[2] and undecided else []
        raw_matches = [(a, sorted(set(f)), sorted(set(u))) for a, f, u in matched_by_adv.values()]
        for entry in offline._deduplicate_matches(raw_matches):
            expected.append({**entry, "component_ref": component.bom_ref})
    if unlisted_errors:
        errors.append(f"{unlisted_errors} more offline advisory errors are not listed")
    keys = ("component_ref", "id", "aliases", "matched_ids", "summary", "fixed_versions")
    flags = ("range_undecidable", "undecidable_bounds")
    assert [{key: entry.get(key) for key in (*keys, *flags)} for entry in report.advisories] == [
        {key: entry.get(key) for key in (*keys, *flags)} for entry in expected
    ]
    assert report.errors == errors
    assert report.complete is False
    assert len(expected) > 1_000
    assert len(errors) + unlisted_errors > 1_000
    assert bool(unlisted_errors) is (cap < 10**9)
    assert sum(bool(entry["fixed_versions"]) for entry in expected) > 100
    assert sum("range_undecidable" in entry for entry in expected) > 100


def _range_record(index: int, events: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "id": f"GHSA-{index:06d}",
        "modified": MODIFIED,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "victim"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
        **extra,
    }


def test_advisories_that_do_not_match_cost_no_comparison_per_component(tmp_path):
    inputs = {}
    for scale in (1, 4):
        db_file = tmp_path / f"osv-{scale}.json"
        db_file.write_text(
            json.dumps(
                [
                    _range_record(
                        index, [{"introduced": f"9000.{index}.0"}, {"fixed": f"9000.{index}.5"}]
                    )
                    for index in range(2_500 * scale)
                ]
            ),
            encoding="utf-8",
        )
        bom = AIBOM(components=[_component("victim", f"1.{i}.0") for i in range(60 * scale)])
        inputs[scale] = (bom, db_file)

    def run(scale: int) -> None:
        bom, db_file = inputs[scale]
        report, _ = _match_offline_advisories(bom, db_path=db_file)
        assert report.complete is True
        assert report.components_checked == 60 * scale
        assert report.advisories == []

    assert scaling_ratio(run) < 10


def _matching_inputs(tmp_path, components: int, advisories: int):
    db_file = tmp_path / "osv.json"
    db_file.write_text(
        json.dumps(
            [
                _range_record(index, [{"introduced": "0"}], aliases=["CVE-2026-0001"])
                for index in range(advisories)
            ]
        ),
        encoding="utf-8",
    )
    return AIBOM(components=[_component("victim", f"1.{i}.0") for i in range(components)]), db_file


def test_matches_beyond_the_budget_stop_with_one_error(tmp_path):
    bom, db_file = _matching_inputs(tmp_path, components=5, advisories=4)

    with limits.applied(replace(limits.DEFAULTS, advisory_matches=20)):
        report, _ = _match_offline_advisories(bom, db_path=db_file)
    assert report.complete is True
    assert len(report.advisories) == 5
    assert all(len(entry["matched_ids"]) == 4 for entry in report.advisories)

    with limits.applied(replace(limits.DEFAULTS, advisory_matches=19)):
        report, _ = _match_offline_advisories(bom, db_path=db_file)
    assert report.errors == [
        "Offline advisory matching stopped: advisory-matches limit of 19 exceeded; "
        "raise it with --limit advisory-matches=N"
    ]
    assert report.complete is False
    assert len(report.advisories) == 4
    assert report.components_checked == 5


def test_the_budget_is_an_operator_limit_and_the_command_exits_1(tmp_path):
    bom, db_file = _matching_inputs(tmp_path, components=5, advisories=4)
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)
    arguments = ["advisories", str(bom_path), "--offline-db", str(db_file)]
    runner = CliRunner()

    stopped = runner.invoke(main, ["--limit", "advisory-matches=19", *arguments])
    assert stopped.exit_code == 1
    payload = json.loads(stopped.output)
    assert payload["complete"] is False
    assert len(payload["errors"]) == 1
    assert "advisory-matches limit of 19 exceeded" in payload["errors"][0]

    complete = json.loads(runner.invoke(main, arguments).output)
    assert complete["complete"] is True
    assert len(complete["advisories"]) == 5
    assert limits.DEFAULTS.advisory_matches == 2_000_000


def test_an_undated_feed_still_fails_the_indexed_command(tmp_path):
    bom, db_file = _matching_inputs(tmp_path, components=5, advisories=4)
    records = json.loads(db_file.read_text(encoding="utf-8"))
    db_file.write_text(
        json.dumps([{k: v for k, v in r.items() if k != "modified"} for r in records]),
        encoding="utf-8",
    )
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)

    result = CliRunner().invoke(main, ["advisories", str(bom_path), "--offline-db", str(db_file)])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["complete"] is False
    assert len(payload["advisories"]) == 5
    assert any("carries no record 'modified' or 'published' date" in e for e in payload["errors"])


def test_errors_past_the_report_cap_spend_no_budget(tmp_path):
    db_file = tmp_path / "osv.json"
    db_file.write_text(
        json.dumps([_range_record(index, [{"introduced": "bad!"}]) for index in range(400)]),
        encoding="utf-8",
    )
    bom = AIBOM(components=[_component("victim", f"1.{i}.0") for i in range(50)])

    with limits.applied(replace(limits.DEFAULTS, advisory_matches=1)):
        report, _ = _match_offline_advisories(bom, db_path=db_file)
    assert report.components_checked == 50
    assert len(report.errors) == offline.MAX_OFFLINE_ERRORS + 1
    assert report.errors[0] == (
        "pkg:pypi:victim@1.0.0: offline advisory GHSA-000000: OSV range version cannot be compared"
    )
    assert report.errors[-1] == "19900 more offline advisory errors are not listed"
    assert report.complete is False


def test_a_range_with_many_events_spends_the_budget_before_it_is_evaluated(tmp_path):
    events = [
        {"introduced": f"5.{index}.0"} if index % 2 == 0 else {"fixed": f"5.{index}.0"}
        for index in range(400)
    ]
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([_range_record(0, events)]), encoding="utf-8")
    bom = AIBOM(components=[_component("victim", "5.10.3"), _component("victim", "5.11.3")])

    report, _ = _match_offline_advisories(bom, db_path=db_file)
    assert report.complete is True
    assert [entry["version"] for entry in report.advisories] == ["5.10.3"]
    assert report.advisories[0]["fixed_versions"] == sorted(
        f"5.{index}.0" for index in range(11, 400, 2)
    )

    with limits.applied(replace(limits.DEFAULTS, advisory_matches=1_000)):
        report, _ = _match_offline_advisories(bom, db_path=db_file)
    assert report.advisories == []
    assert len(report.errors) == 1
    assert report.complete is False


def test_runs_of_introduced_that_own_unparsable_bounds_cost_what_the_budget_charges():
    """A range is charged the square of its events, so evaluating it may cost no more.

    The shape: one run of ``introduced`` events that owns many unparsable bounds, then a
    second run the queried versions fall in. Asking each owned bound for each member of
    its run, at each position, is cubic (a ratio near 64 at 4x) for a quadratic charge.
    """

    def run(scale: int) -> None:
        size = 150 * scale
        events: list[dict[str, str]] = [{"introduced": f"1.{i}"} for i in range(size)]
        events += [{"fixed": f"junk{i}!"} for i in range(size)]
        events += [{"introduced": f"2.{i}"} for i in range(size)]
        budget = offline._MatchBudget(10**9)
        matcher = offline._PackageMatcher(
            "PyPI", [(_advisory("GHSA-run"), {"ranges": [{"events": events}]})], budget
        )
        for version in ("1.5", "2.5"):
            found, undecided = _indexed_blocks(matcher, version, budget)
            assert [record for record, _, _ in found] == ["GHSA-run"]
            assert undecided == []

    assert scaling_ratio(run) < 32
