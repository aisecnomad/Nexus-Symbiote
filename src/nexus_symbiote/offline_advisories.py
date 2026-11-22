"""Offline advisory matching with provenance, alias deduplication, and KEV/EPSS enrichment.

Matches exact pinned PyPI and npm packages in an AgentBOM against an operator-supplied
OSV bundle (a JSON file or a flat directory of them) without network I/O. Files are
opened without following symlinks and bounded in size. A bundle or catalog that is empty
or wrongly shaped is refused, and a package whose ecosystem the bundle holds no record
for is an error, so neither can pass as a complete result with no advisories. Each feed's
own date (never a file time, which a checkout sets) is recorded, and a feed that is undated,
older than the operator's limit or dated in the future is an error, so a stale answer is
not complete either.
"""

from __future__ import annotations

import csv
import hashlib
import io
import math
import os
import re
from bisect import bisect_left
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from nexus_symbiote import __version__, limits
from nexus_symbiote.advisories import (
    MAX_ADVISORIES,
    AdvisoryReport,
    _excluded,
    _in_scope,
    _normalize,
    _origin_exclusion,
    mcp_package_identity,
    package_identity,
)
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict
from nexus_symbiote.core.models import MCPServerComponent, RegistryEntryComponent

MAX_DB_BYTES = 32 * 1024 * 1024
MAX_DB_FILES = 10_000
MAX_DB_RECORDS = 100_000
MAX_CATALOG_BYTES = 16 * 1024 * 1024
MAX_OFFLINE_COMPONENTS = 50_000
MAX_OFFLINE_ERRORS = 100
DEFAULT_MAX_FEED_AGE_DAYS = 30
MAX_FEED_AGE_DAYS = 36_500
_FUTURE_TOLERANCE = timedelta(days=1)
_FEED_DATE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}))?"
)

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_SUPPORTED_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})
# OSV's other range type. Its events are commits, which no package version compares with.
_UNMATCHED_RANGE_TYPES = frozenset({"GIT"})
# Steps of evaluating a range, or of filtering its fixes, that cost about what one match does.
_CHEAP_STEPS = 32
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


@dataclass(frozen=True)
class _ParsedAdvisory:
    record_id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    affected: tuple[dict[str, Any], ...]
    dated: datetime | None = None


@dataclass(frozen=True)
class _KEVEntry:
    source: str
    date_added: str | None


@dataclass(frozen=True)
class _EPSSEntry:
    score: float
    percentile: float | None


def _read_bounded_bytes(path: Path, max_bytes: int, label: str) -> bytes:
    with open_regular_file(path) as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{label} exceeds maximum size of {max_bytes} bytes")
    return data


def _parse_feed_date(raw: object, label: str) -> datetime | None:
    """Parse a date a feed states about itself: None when absent, an error when malformed."""
    if raw is None:
        return None
    try:
        if not isinstance(raw, str) or _FEED_DATE_RE.fullmatch(raw) is None:
            raise ValueError
        parsed = datetime.fromisoformat(raw)
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC)
    except (ValueError, OverflowError):
        raise ValueError(f"{label} is not an RFC 3339 date or date-time") from None


def _feed_age_error(
    label: str, noun: str, dated: datetime | None, now: datetime, limit: int
) -> str | None:
    if dated is None:
        field = "record 'modified' or 'published' date" if noun == "newest record" else noun
        return f"{label} carries no {field}, so its age is unknown; limit {limit} days"
    if dated - now > _FUTURE_TOLERANCE:
        return f"{label} {noun} {dated:%Y-%m-%d} is in the future"
    age = (now.date() - dated.date()).days
    if age > limit:
        return f"{label} is {age} days old ({noun} {dated:%Y-%m-%d}); limit {limit}"
    return None


def _iso(dated: datetime | None) -> str | None:
    return None if dated is None else dated.isoformat()


def _semver_key(raw: str) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]] | None:
    match = _SEMVER_RE.fullmatch(raw.strip())
    if match is None:
        return None
    major, minor, patch = int(match[1]), int(match[2] or 0), int(match[3] or 0)
    pre = match[4].split(".") if match[4] else []
    parts = tuple((0, int(tok)) if tok.isdigit() else (1, tok) for tok in pre)
    return (major, minor, patch, 0 if parts else 1, parts)


def _version_key(ecosystem: str, raw: str) -> Any | None:
    if ecosystem == "PyPI":
        try:
            return Version(raw)
        except InvalidVersion:
            return None
    return _semver_key(raw) if ecosystem == "npm" else None


def _parse_epss_unit(raw: object, field_name: str) -> float:
    """Validate that an EPSS score or percentile is a finite float in [0.0, 1.0]."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raw = "nan"
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or not (0.0 <= value <= 1.0):
        raise ValueError(f"EPSS {field_name} must be a finite number in [0, 1]")
    return value


def _extract_severity(record: dict[str, Any]) -> str:
    db_spec = record.get("database_specific")
    candidates = [
        db_spec.get("severity") if isinstance(db_spec, dict) else None,
        record.get("severity"),
    ]
    for raw in candidates:
        if isinstance(raw, str):
            norm = "medium" if raw.strip().lower() == "moderate" else raw.strip().lower()
            if norm in _SEVERITY_ORDER:
                return norm
    return "unknown"


def _parse_osv_records(payload: object) -> list[_ParsedAdvisory]:
    items: object = payload
    if isinstance(payload, dict):
        wrapper = next((k for k in ("advisories", "vulnerabilities") if k in payload), None)
        items = [payload] if wrapper is None else payload[wrapper]
    if not isinstance(items, list):
        raise ValueError("Offline advisory DB must be an OSV record or an array of OSV records")

    parsed: list[_ParsedAdvisory] = []
    for item in items:
        rec_id = item.get("id") if isinstance(item, dict) else None
        if not isinstance(rec_id, str) or not rec_id.strip():
            raise ValueError("Offline advisory DB entry is not an OSV record with an 'id'")
        if item.get("withdrawn"):
            continue
        raw_aliases = item.get("aliases")
        aliases = (
            tuple(sorted({a.strip() for a in raw_aliases if isinstance(a, str) and a.strip()}))
            if isinstance(raw_aliases, list)
            else ()
        )
        raw_summary = item.get("summary")
        summary = raw_summary.strip() if isinstance(raw_summary, str) else ""
        affected = item.get("affected", [])
        if not isinstance(affected, list) or not all(isinstance(a, dict) for a in affected):
            raise ValueError(
                f"Offline advisory DB record {rec_id.strip()} has malformed 'affected'"
            )
        raw_dated = item.get("modified")
        dated = _parse_feed_date(
            item.get("published") if raw_dated is None else raw_dated,
            "Offline advisory DB record 'modified' or 'published'",
        )
        parsed.append(
            _ParsedAdvisory(
                rec_id.strip(), aliases, summary, _extract_severity(item), (*affected,), dated
            )
        )
    return parsed


def load_offline_advisory_db(path: Path) -> tuple[list[_ParsedAdvisory], str]:
    """Load bounded offline OSV records from a JSON file or directory, returning (records, sha256)."""
    if path.is_symlink():
        raise ValueError("Offline advisory DB path must not be a symbolic link")
    if path.is_dir():
        records: list[_ParsedAdvisory] = []
        total_bytes = 0
        manifest_lines: list[str] = []
        # Bound directory iteration itself, including entries that are not advisory files.
        with os.scandir(path) as listing:
            entries: list[os.DirEntry[str]] = []
            for entry in listing:
                if len(entries) == MAX_DB_FILES:
                    raise ValueError(
                        f"Offline advisory DB exceeds {MAX_DB_FILES} directory entries"
                    )
                entries.append(entry)
        for entry in sorted(entries, key=lambda e: e.name):
            if entry.is_dir():
                raise ValueError("Offline advisory DB directory must not contain subdirectories")
            if not entry.name.endswith(".json"):
                continue
            if entry.is_symlink():
                raise ValueError("Offline advisory DB directory must not contain symbolic links")
            data = _read_bounded_bytes(Path(entry.path), MAX_DB_BYTES - total_bytes, entry.name)
            total_bytes += len(data)
            manifest_lines.append(f"{entry.name}:{hash_bytes(data)}")
            payload = parse_json_strict(data.decode("utf-8"), max_bytes=MAX_DB_BYTES)
            records.extend(_parse_osv_records(payload))
            if len(records) > MAX_DB_RECORDS:
                raise ValueError(f"Offline advisory DB exceeds {MAX_DB_RECORDS} records")
        digest = "sha256:" + hashlib.sha256("\n".join(manifest_lines).encode("utf-8")).hexdigest()
    else:
        data = _read_bounded_bytes(path, MAX_DB_BYTES, "Offline advisory DB")
        records = _parse_osv_records(
            parse_json_strict(data.decode("utf-8"), max_bytes=MAX_DB_BYTES)
        )
        digest = hash_bytes(data)
    if not records:
        raise ValueError("Offline advisory DB holds no advisory records")
    if len(records) > MAX_DB_RECORDS:
        raise ValueError(f"Offline advisory DB exceeds {MAX_DB_RECORDS} records")
    # Matches merge by id, so a different record could drop another's aliases and KEV status.
    # Copies that differ only in their date (two exports of one record) are one record, with
    # the latest date; any other difference, a stale copy stamped later included, is refused.
    by_id: dict[str, _ParsedAdvisory] = {}
    for rec in records:
        kept = by_id.setdefault(rec.record_id, rec)
        if replace(kept, dated=None) != replace(rec, dated=None):
            raise ValueError(f"Offline advisory DB holds two different records {rec.record_id}")
        if rec.dated is not None and (kept.dated is None or rec.dated > kept.dated):
            by_id[rec.record_id] = rec
    return list(by_id.values()), digest


def load_kev_catalog(path: Path) -> tuple[dict[str, list[_KEVEntry]], str, datetime | None]:
    """Load an offline CISA or ENISA KEV JSON catalog, with the ``dateReleased`` it states."""
    data = _read_bounded_bytes(path, MAX_CATALOG_BYTES, "KEV catalog")
    payload = parse_json_strict(data.decode("utf-8"), max_bytes=MAX_CATALOG_BYTES)
    if not isinstance(payload, dict):
        raise ValueError("KEV catalog must be a JSON object")
    default_source = payload.get("source")
    if not isinstance(default_source, str) or not default_source.strip():
        default_source = (
            "enisa-kev" if "enisa" in str(payload.get("title", "")).lower() else "cisa-kev"
        )
    raw_entries = payload.get("vulnerabilities", payload.get("entries"))
    if not isinstance(raw_entries, list):
        raise ValueError("KEV catalog must hold a 'vulnerabilities' or 'entries' array")

    index: dict[str, list[_KEVEntry]] = {}
    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        raw_id = entry.get("cveID") or entry.get("id") or entry.get("cve")
        if not isinstance(raw_id, str) or not raw_id.strip():
            continue
        src = entry.get("source")
        src_name = src.strip() if isinstance(src, str) and src.strip() else default_source
        date_added = entry.get("dateAdded") or entry.get("date_added")
        index.setdefault(raw_id.strip().upper(), []).append(
            _KEVEntry(src_name, date_added.strip() if isinstance(date_added, str) else None)
        )
    if not index:
        raise ValueError("KEV catalog holds no entries")
    released = _parse_feed_date(payload.get("dateReleased"), "KEV catalog 'dateReleased'")
    return index, hash_bytes(data), released


def _epss_csv_score_date(text: str) -> datetime | None:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            break
        for part in stripped.lstrip("#").split(","):
            key, found, value = part.partition(":")
            if found and key.strip() == "score_date":
                return _parse_feed_date(value.strip(), "EPSS catalog 'score_date'")
    return None


def load_epss_catalog(path: Path) -> tuple[dict[str, _EPSSEntry], str, datetime | None]:
    """Load an offline EPSS CSV or JSON catalog with strict finite [0, 1] validation."""
    data = _read_bounded_bytes(path, MAX_CATALOG_BYTES, "EPSS catalog")
    text = data.decode("utf-8")
    index: dict[str, _EPSSEntry] = {}
    if text.lstrip().startswith(("{", "[")):
        payload = parse_json_strict(text, max_bytes=MAX_CATALOG_BYTES)
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ValueError("EPSS JSON catalog must be an object with a 'data' array")
        scored = _parse_feed_date(payload.get("score_date"), "EPSS catalog 'score_date'")
        for row in payload["data"]:
            if not isinstance(row, dict):
                continue
            cve, epss, pct = row.get("cve"), row.get("epss"), row.get("percentile")
            if not isinstance(cve, str) or not cve.strip() or epss is None:
                continue
            index[cve.strip().upper()] = _EPSSEntry(
                _parse_epss_unit(epss, "score"),
                _parse_epss_unit(pct, "percentile") if pct is not None else None,
            )
    else:
        scored = _epss_csv_score_date(text)
        rows = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        for row in csv.DictReader(io.StringIO("\n".join(rows))):
            cve, epss, pct = row.get("cve"), row.get("epss"), row.get("percentile")
            if not cve or not cve.strip() or not epss or not epss.strip():
                continue
            index[cve.strip().upper()] = _EPSSEntry(
                _parse_epss_unit(epss.strip(), "score"),
                _parse_epss_unit(pct.strip(), "percentile") if pct and pct.strip() else None,
            )
    if not index:
        raise ValueError("EPSS catalog holds no entries")
    return index, hash_bytes(data), scored


class _MatchBudgetError(Exception):
    pass


class _MatchBudget:
    def __init__(self, units: int) -> None:
        self.left = units

    def spend(self, units: int) -> None:
        self.left -= units
        if self.left < 0:
            raise _MatchBudgetError


_UNCOMPARABLE = "OSV range version cannot be compared"


@dataclass(frozen=True)
class _Range:
    """One OSV range; a version is a string until its package is ranked, then a position.

    A ranked bound the ecosystem cannot parse is None, and ``unparsed`` holds the reported
    form (cut to 64 characters) of each such ``fixed``, ``last_affected`` or ``limit``.
    ``owners`` holds each run of consecutive ``introduced`` events ("0" for the zero one; empty
    before the first) with the ``fixed`` and ``last_affected`` events that follow it: the run
    opens one interval, whichever of its events comes first. Once ranked, it holds only the
    positions of the runs that own an unparsable bound (None for the empty run), and
    ``origin`` is the position of "0".
    """

    zero_intro: bool
    intros: tuple[Any, ...]
    fixes: tuple[tuple[Any, str], ...]
    last_affected: tuple[Any, ...]
    limits: tuple[Any, ...]
    owners: tuple[Any, ...] = ()
    unparsed: tuple[str, ...] = ()
    origin: Any = None

    def versions(self) -> tuple[Any, ...]:
        return (*self.intros, *(fix for fix, _ in self.fixes), *self.last_affected, *self.limits)


def _read_range(rng: dict[str, Any]) -> _Range | None:
    """Read one range's events; None for a GIT range, ``ValueError`` if it cannot be read.

    A type OSV does not define, and events with no ``introduced``, are errors: either would
    otherwise make a damaged or unsupported record read as "not affected".
    """
    raw_type = rng.get("type")
    if raw_type is not None:
        # Older feeds use mixed case. Unicode lookalikes are distinct range types.
        kind_of_range = raw_type.upper() if isinstance(raw_type, str) and raw_type.isascii() else ""
        if kind_of_range in _UNMATCHED_RANGE_TYPES:
            return None
        if kind_of_range not in _SUPPORTED_RANGE_TYPES:
            raise ValueError("OSV range type is not supported")
    events = rng.get("events")
    if not isinstance(events, list):
        raise ValueError("OSV range events are not a list")

    has_zero_intro = False
    found: dict[str, list[str]] = {"introduced": [], "fixed": [], "last_affected": [], "limit": []}
    group: tuple[list[str], list[str]] = ([], [])
    groups = [group]
    for ev in events:
        kind, raw = next(iter(ev.items())) if isinstance(ev, dict) and len(ev) == 1 else ("", "")
        if kind == "introduced" and raw in ("0", 0) and not isinstance(raw, bool):
            has_zero_intro, text = True, "0"
        elif kind in found and isinstance(raw, str) and raw.strip():
            text = raw.strip()
            found[kind].append(text)
        else:
            raise ValueError("OSV range event cannot be parsed")
        if kind == "introduced":
            if group[1]:
                group = ([], [])
                groups.append(group)
            group[0].append(text)
        elif kind != "limit":
            group[1].append(text)
    intros, fixed_versions, last_affected, limits = found.values()
    if not has_zero_intro and not intros:
        raise ValueError("OSV range has no introduced event")
    # A "*" limit bounds nothing: it is kept, ranked as None, so limits cannot exclude a
    # version, and it is never reported.
    return _Range(
        has_zero_intro,
        tuple(intros),
        tuple((fix, fix) for fix in fixed_versions),
        tuple(last_affected),
        tuple(limits),
        tuple((tuple(run), tuple(bounds)) for run, bounds in groups if bounds),
    )


def _in_range(version: int, rng: _Range) -> bool:
    """Decide one ranked OSV range for a parsed version (order-independent per OSV spec).

    Every ``introduced`` parses here; a block naming one that does not is an error before
    any range of it is evaluated. An upper bound that does not parse (None) excludes no
    version, so a range that only it could have ended still matches, reported undecided;
    while one follows the run of ``introduced`` events that holds the version's own, no
    ``fixed`` or ``last_affected`` excludes the version either. Limits exclude it only when
    it is at or above every one of them, all parsable and none "*" (OSV: a version below any
    limit is in range).
    """
    best_intro: int | None = None
    found_intro = rng.zero_intro
    for intro in rng.intros:
        if intro > version:
            continue
        found_intro = True
        if best_intro is None or intro > best_intro:
            best_intro = intro
    if not found_intro:
        return False
    start = rng.origin if best_intro is None else best_intro
    open_interval = any(owner is None or owner == start for owner in rng.owners)

    def ends_after_intro(bound: int | None) -> bool:
        if open_interval or bound is None:
            return False
        return best_intro is None or best_intro <= bound

    return not (
        (bool(rng.limits) and all(lim is not None and version >= lim for lim in rng.limits))
        or any(ends_after_intro(fix) and fix <= version for fix, _ in rng.fixes)
        or any(ends_after_intro(last) and last < version for last in rng.last_affected)
    )


# A block's evidence for one version: (block, matching range, or None for a listed version).
_Hit = tuple[int, _Range | None]


class _PackageMatcher:
    """Every affected block of one package, indexed by the versions it matches.

    Whether a range matches depends on a version only through how it compares with the
    range's own parsable events. The distinct versions a package's ranges name are ranked:
    one has the odd position ``2 * rank + 1``, and the versions between two neighbours share
    the even position between them. ``_in_range`` runs once per position a range can tell
    apart, and each run of matching positions is stored in a segment tree, so a component
    version costs one bisection plus the blocks that match it, however many do not.

    A block that cannot be decided is an error, never a miss, and which blocks those are
    depends on the version only through whether it parses: a malformed block or range, or a
    range with an unparsable ``introduced``, for a version that parses; any range of a
    matched type, for one that does not. So each block's error, the first that evaluating
    its ranges in order meets, is found once per package for each of the two cases.
    """

    def __init__(
        self,
        ecosystem: str,
        blocks: list[tuple[_ParsedAdvisory, dict[str, Any]]],
        budget: _MatchBudget,
    ) -> None:
        self._ecosystem = ecosystem
        self._advisories = [adv for adv, _ in blocks]
        self._listed: dict[Any, list[int]] = {}
        self._listed_text: dict[str, list[int]] = {}
        self._nodes: dict[int, list[_Hit]] = {}
        failed_parsed: list[tuple[int, str]] = []
        failed_unparsed_blocks: list[tuple[int, str]] = []

        ranges: list[tuple[int, _Range]] = []
        for number, (_, affected) in enumerate(blocks):
            raw_versions, raw_ranges = affected.get("versions", []), affected.get("ranges", [])
            if not isinstance(raw_versions, list) or not isinstance(raw_ranges, list):
                reason = "OSV affected versions or ranges are not a list"
                failed_parsed.append((number, reason))
                failed_unparsed_blocks.append((number, reason))
                continue
            for ver in raw_versions:
                if not isinstance(ver, str):
                    continue
                if (key := _version_key(ecosystem, ver)) is None:
                    # Only the identical string equals a version the ecosystem cannot parse.
                    self._listed_text.setdefault(ver, []).append(number)
                else:
                    self._listed.setdefault(key, []).append(number)
            failed: str | None = None
            failed_unparsed: str | None = None
            readable: list[_Range] = []
            for raw_range in raw_ranges:
                try:
                    rng = _read_range(raw_range if isinstance(raw_range, dict) else {})
                except ValueError as exc:
                    failed = failed or str(exc)
                    failed_unparsed = failed_unparsed or str(exc)
                    continue
                if rng is None:
                    continue
                failed_unparsed = failed_unparsed or _UNCOMPARABLE
                if any(_version_key(ecosystem, intro) is None for intro in rng.intros):
                    failed = failed or _UNCOMPARABLE
                    continue
                readable.append(rng)
            if failed is not None:
                failed_parsed.append((number, failed))
            for rng in readable:
                budget.spend((len(rng.versions()) + 1) ** 2 // _CHEAP_STEPS)
                ranges.append((number, rng))
            if failed_unparsed is not None:
                failed_unparsed_blocks.append((number, failed_unparsed))
        # Kept whole so a component costs nothing per error past the ones the report lists.
        self._errors = {
            parses: (
                frozenset(number for number, _ in failed),
                tuple((self._advisories[number], reason) for number, reason in failed),
            )
            for parses, failed in ((True, failed_parsed), (False, failed_unparsed_blocks))
        }

        texts = {text for _, rng in ranges for text in rng.versions()}
        if any(rng.owners for _, rng in ranges):
            texts.add("0")  # the version a zero introduced, which owns bounds, starts at
        keys = {text: _version_key(ecosystem, text) for text in texts}
        self._keys = sorted({key for key in keys.values() if key is not None})
        position = {key: 2 * rank + 1 for rank, key in enumerate(self._keys)}
        self._leaves = 2 * len(self._keys) + 1

        def at(text: str) -> int | None:
            return None if (key := keys[text]) is None else position[key]

        for number, raw in ranges:
            bounds = (*(fix for fix, _ in raw.fixes), *raw.last_affected, *raw.limits)
            rng = _Range(
                raw.zero_intro,
                tuple(at(text) for text in raw.intros),
                tuple((at(text), text) for text, _ in raw.fixes),
                tuple(at(text) for text in raw.last_affected),
                tuple(at(text) for text in raw.limits),
                owners=tuple(
                    {
                        owner
                        for run, owned in raw.owners
                        if any(keys[bound] is None for bound in owned)
                        for owner in ([at(intro) for intro in run] or [None])
                    }
                ),
                unparsed=tuple(text[:64] for text in bounds if keys[text] is None and text != "*"),
                origin=at("0") if raw.owners else None,
            )
            start: int | None = None
            low = 0
            for named in (*sorted({p for p in rng.versions() if p is not None}), self._leaves):
                for probe in (low, named)[: 1 if named == self._leaves else 2]:
                    if _in_range(probe, rng):
                        start = probe if start is None else start
                    elif start is not None:
                        self._store(start, probe - 1, (number, rng))
                        start = None
                low = named + 1
            if start is not None:
                self._store(start, self._leaves - 1, (number, rng))

    def _store(self, first: int, last: int, entry: _Hit) -> None:
        low, high = first + self._leaves, last + self._leaves + 1
        while low < high:
            if low & 1:
                self._nodes.setdefault(low, []).append(entry)
                low += 1
            if high & 1:
                high -= 1
                self._nodes.setdefault(high, []).append(entry)
            low >>= 1
            high >>= 1

    def matches(
        self, version: str, budget: _MatchBudget
    ) -> tuple[
        list[tuple[_ParsedAdvisory, list[str], list[str]]], tuple[tuple[_ParsedAdvisory, str], ...]
    ]:
        """Each matching block's advisory, fixes above ``version`` and undecided bounds (empty
        once a listing or a range without one decides it), then each block that cannot be
        decided for it with the reason; both in bundle order. The second is shared between
        calls, so a caller lists the errors it reports without building the rest.
        """
        key = _version_key(self._ecosystem, version)
        position = -1
        if key is None:
            hits: list[_Hit] = [(number, None) for number in self._listed_text.get(version, ())]
        else:
            rank = bisect_left(self._keys, key)
            exact = rank < len(self._keys) and self._keys[rank] == key
            position = 2 * rank + 1 if exact else 2 * rank
            hits = [(number, None) for number in self._listed.get(key, ())]
            node = position + self._leaves
            while node:
                hits.extend(self._nodes.get(node, ()))
                node >>= 1
        undecidable, failed = self._errors[key is not None]
        blocks: dict[int, tuple[list[str], list[str], list[bool]]] = {}
        for number, rng in sorted(hits, key=lambda hit: hit[0]):
            fixes = () if rng is None else rng.fixes
            budget.spend(1 + len(fixes) // _CHEAP_STEPS)
            # Exact listings and readable ranges establish a hit independently of a
            # malformed sibling. Preserve the feed error even when coverage is partial.
            if number in undecidable and rng is not None and rng.unparsed:
                continue
            fixed, bounds, decided = blocks.setdefault(number, ([], [], [False]))
            fixed.extend(text for at, text in fixes if at is not None and at > position)
            if rng is None or not rng.unparsed:
                decided[0] = True
            else:
                bounds.extend(rng.unparsed)
        found = [
            (
                self._advisories[number],
                sorted(set(fixed)),
                [] if decided[0] else sorted(set(bounds)),
            )
            for number, (fixed, bounds, decided) in sorted(blocks.items())
        ]
        return found, failed


def _build_package_index(
    records: list[_ParsedAdvisory],
) -> dict[tuple[str, str], list[tuple[_ParsedAdvisory, dict[str, Any]]]]:
    """Index OSV affected blocks by ``(ecosystem.lower(), normalized_name)`` for O(1) lookup."""
    index: dict[tuple[str, str], list[tuple[_ParsedAdvisory, dict[str, Any]]]] = {}
    for adv in records:
        for aff in adv.affected:
            pkg = aff.get("package")
            if not isinstance(pkg, dict):
                continue
            pkg_eco, pkg_name = pkg.get("ecosystem"), pkg.get("name")
            if not isinstance(pkg_eco, str) or not isinstance(pkg_name, str):
                continue
            eco_lower = pkg_eco.strip().lower()
            if eco_lower in {"pypi", "npm"}:
                key = (eco_lower, _normalize(eco_lower, pkg_name.strip()))
                index.setdefault(key, []).append((adv, aff))
    return index


def _deduplicate_matches(
    matches: list[tuple[_ParsedAdvisory, list[str], list[str]]],
) -> list[dict[str, Any]]:
    """Collapse alias pairs into one canonical advisory entry via union-find."""
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        while parent.get(node, node) != node:
            parent[node] = parent.get(parent[node], parent[node])
            node = parent[node]
        return node

    for adv, *_ in matches:
        ids = [adv.record_id, *adv.aliases]
        for ident in ids:
            parent.setdefault(ident, ident)
        for ident in ids[1:]:
            ra, rb = find(ids[0]), find(ident)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

    grouped: dict[str, list[tuple[_ParsedAdvisory, list[str], list[str]]]] = {}
    for match in matches:
        grouped.setdefault(find(match[0].record_id), []).append(match)

    merged: list[dict[str, Any]] = []
    for items in grouped.values():
        advs = [adv for adv, *_ in items]
        all_ids = {ident for adv in advs for ident in (adv.record_id, *adv.aliases)}
        summaries = sorted({adv.summary for adv in advs if adv.summary})
        best_severity = min((adv.severity for adv in advs), key=_SEVERITY_ORDER.__getitem__)
        bounds = sorted({b for *_, u in items for b in u})[:16] if all(u for *_, u in items) else []
        cves = sorted(i for i in all_ids if i.upper().startswith("CVE-"))
        primary_id = cves[0] if cves else sorted(all_ids)[0]
        merged.append(
            {
                "id": primary_id,
                "advisory_id": primary_id,
                "aliases": sorted(i for i in all_ids if i != primary_id),
                "matched_ids": sorted({adv.record_id for adv in advs}),
                "severity": best_severity,
                "base_severity": best_severity,
                "summary": summaries[0] if summaries else "",
                "fixed_versions": sorted({fix for _, fixed, _ in items for fix in fixed}),
                **({"range_undecidable": True, "undecidable_bounds": bounds} if bounds else {}),
            }
        )
    merged.sort(key=lambda entry: entry["id"])
    return merged


def match_offline_advisories(
    bom: AIBOM,
    *,
    db_path: Path,
    kev_paths: Iterable[Path] = (),
    epss_path: Path | None = None,
    exclude: Iterable[str] = (),
    exclude_private_origins: bool = False,
    inventory_sha256: str | None = None,
    now: datetime,
    max_feed_age_days: int = DEFAULT_MAX_FEED_AGE_DAYS,
) -> tuple[AdvisoryReport, dict[str, Any]]:
    """Match pinned packages in ``bom`` against an offline OSV DB with KEV/EPSS enrichment.

    ``now`` is the caller's clock. A feed whose own date is missing, more than
    ``max_feed_age_days`` before it, or more than a day after it adds an error, so the
    report is not complete.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if type(max_feed_age_days) is not int or not 1 <= max_feed_age_days <= MAX_FEED_AGE_DAYS:
        raise ValueError(f"max_feed_age_days must be an integer from 1 to {MAX_FEED_AGE_DAYS}")
    now = now.astimezone(UTC)
    patterns = list(exclude)
    if any(not isinstance(p, str) or not p or len(p) > 256 for p in patterns):
        raise ValueError("exclusion patterns must be 1 to 256 characters")
    if any("*" in p[:-1] for p in patterns):
        raise ValueError("an exclusion pattern may hold '*' only as its last character")

    records, db_digest = load_offline_advisory_db(db_path)
    pkg_index = _build_package_index(records)
    covered = {ecosystem for ecosystem, _ in pkg_index}
    db_dated = max((adv.dated for adv in records if adv.dated is not None), default=None)
    feed_errors = [
        _feed_age_error("offline advisory DB", "newest record", db_dated, now, max_feed_age_days)
    ]

    kev_index: dict[str, list[_KEVEntry]] = {}
    kev_provenance: list[dict[str, Any]] = []
    for kpath in kev_paths:
        k_idx, k_digest, released = load_kev_catalog(kpath)
        kev_provenance.append(
            {
                "path": kpath.name,
                "sha256": k_digest,
                "entries": len(k_idx),
                "date_released": _iso(released),
            }
        )
        feed_errors.append(
            _feed_age_error(
                f"KEV catalog {kpath.name}", "dateReleased", released, now, max_feed_age_days
            )
        )
        for key, entries in k_idx.items():
            kev_index.setdefault(key, []).extend(entries)

    epss_index: dict[str, _EPSSEntry] = {}
    epss_provenance: dict[str, Any] | None = None
    if epss_path is not None:
        epss_index, digest, scored = load_epss_catalog(epss_path)
        epss_provenance = {
            "path": epss_path.name,
            "sha256": digest,
            "entries": len(epss_index),
            "score_date": _iso(scored),
        }
        feed_errors.append(
            _feed_age_error(
                f"EPSS catalog {epss_path.name}", "score_date", scored, now, max_feed_age_days
            )
        )

    provenance: dict[str, Any] = {
        "offline": True,
        "db_sha256": db_digest,
        "records_loaded": len(records),
        "db_newest_record": _iso(db_dated),
        "max_feed_age_days": max_feed_age_days,
        "feed_age_evaluated_at": now.isoformat(),
        "kev_catalogs": kev_provenance,
        "epss_catalog": epss_provenance,
    }
    report = AdvisoryReport(
        tool_version=__version__, inventory_sha256=inventory_sha256, dry_run=False
    )
    report.errors.extend(error for error in feed_errors if error is not None)

    targets: list[tuple[str, str, str, str]] = []
    for comp in sorted(bom.components, key=lambda c: c.bom_ref):
        kind = _in_scope(comp)
        if kind is None:
            continue
        if not kind:
            report.components_skipped += 1
            report.skipped.append(
                {"component_ref": comp.bom_ref, "reason": "ecosystem is not queried"}
            )
            continue
        try:
            if isinstance(comp, RegistryEntryComponent):
                eco, name, version = package_identity(comp)
            elif isinstance(comp, MCPServerComponent):
                eco, name, version = mcp_package_identity(comp)
            else:
                continue
        except (ValueError, TypeError, UnicodeError):
            report.errors.append(f"{comp.bom_ref}: exact package identity unavailable")
            continue
        reason = (
            "excluded by the operator"
            if _excluded(kind, name, patterns)
            else _origin_exclusion(comp, kind)
            if exclude_private_origins
            else None
        )
        if reason is not None:
            report.components_excluded += 1
            report.excluded.append({"component_ref": comp.bom_ref, "reason": reason})
            continue
        if eco.lower() not in covered:
            report.errors.append(f"{comp.bom_ref}: offline advisory DB holds no {eco} records")
            continue
        targets.append((comp.bom_ref, eco, name, version))

    if len(targets) > MAX_OFFLINE_COMPONENTS:
        report.errors.append(
            f"Package component limit exceeded ({len(targets)} > {MAX_OFFLINE_COMPONENTS})"
        )
        return report, provenance

    unlisted_errors = 0
    bound = limits.bound("advisory-matches")
    budget = _MatchBudget(bound.value)
    matchers: dict[tuple[str, str], _PackageMatcher] = {}
    for bom_ref, eco, name, version in targets:
        report.components_checked += 1
        report.queries.append(
            {"component_ref": bom_ref, "ecosystem": eco, "name": name, "version": version}
        )
        matched_by_adv: dict[str, tuple[_ParsedAdvisory, list[str], list[str]]] = {}
        package = (eco.lower(), name)
        try:
            if package not in matchers:
                matchers[package] = _PackageMatcher(eco, pkg_index.get(package, []), budget)
            found, failed = matchers[package].matches(version, budget)
        except _MatchBudgetError:
            if unlisted_errors:
                report.errors.append(
                    f"{unlisted_errors} more offline advisory errors are not listed"
                )
            report.errors.append(f"Offline advisory matching stopped: {bound.exceeded()}")
            return report, provenance
        listed = max(0, min(len(failed), MAX_OFFLINE_ERRORS - len(report.errors)))
        for adv, reason in failed[:listed]:
            report.errors.append(f"{bom_ref}: offline advisory {adv.record_id}: {reason}")
        unlisted_errors += len(failed) - listed
        for adv, fixed, undecided in found:
            hit = matched_by_adv.setdefault(adv.record_id, (adv, [], list(undecided)))
            hit[1].extend(fixed)
            hit[2][:] = [*hit[2], *undecided] if hit[2] and undecided else []
        raw_matches = [(a, sorted(set(f)), sorted(set(u))) for a, f, u in matched_by_adv.values()]
        for entry in _deduplicate_matches(raw_matches):
            if len(report.advisories) >= MAX_ADVISORIES:
                report.errors.append(f"Advisory report limit reached ({MAX_ADVISORIES})")
                return report, provenance
            lookup_ids = [entry["id"].upper(), *(a.upper() for a in entry["aliases"])]
            kev_hits = [hit for lid in lookup_ids for hit in kev_index.get(lid, ())]
            entry["in_kev"] = bool(kev_hits)
            if kev_hits:
                sources = sorted({h.source for h in kev_hits})
                dates = sorted(h.date_added for h in kev_hits if h.date_added)
                entry["kev_sources"] = sources
                if dates:
                    entry["kev_date_added"] = dates[0]
                if entry["severity"] != "critical":
                    entry["severity"] = "critical"
                    entry["severity_elevated_by"] = sources[0]
            for lid in lookup_ids:
                if (epss_hit := epss_index.get(lid)) is not None:
                    entry["epss_score"] = epss_hit.score
                    if epss_hit.percentile is not None:
                        entry["epss_percentile"] = epss_hit.percentile
                    break
            entry.update(
                {
                    "component_ref": bom_ref,
                    "bom_ref": bom_ref,
                    "ecosystem": eco,
                    "package": name,
                    "version": version,
                    "offline": True,
                    "db_sha256": db_digest,
                }
            )
            report.advisories.append(entry)
    if unlisted_errors:
        report.errors.append(f"{unlisted_errors} more offline advisory errors are not listed")
    return report, provenance
