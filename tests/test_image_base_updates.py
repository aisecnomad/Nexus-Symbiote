"""scripts/image_base_updates.py: which Debian fixes the image's base packages are behind."""

from __future__ import annotations

import http.client
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from nexus_symbiote.scanners.live_mcp import HTTPReply
from tests.support import load_script

updates = load_script("image_base_updates")


@pytest.fixture(autouse=True)
def pauses(monkeypatch):
    """The pause before a retry is recorded, not waited for; only the script's clock changes."""
    taken: list[float] = []
    clock = SimpleNamespace(monotonic=time.monotonic, sleep=taken.append)
    monkeypatch.setattr(updates, "time", clock)
    return taken


BASE = "python:3.12.16-slim-trixie@sha256:" + "5e" * 32
PACKAGES = [
    {"source": "adduser", "version": "3.152", "binaries": ["adduser"]},
    {"source": "glibc", "version": "2.41-12+deb13u4", "binaries": ["libc-bin", "libc6"]},
    {"source": "zlib", "version": "1:1.3.dfsg+really1.3.1-1", "binaries": ["zlib1g"]},
]
ZLIB_FIX = "1:1.3.dfsg+really1.3.1-1+deb13u1"


def affected(name: str, release: str, fixed: str | None = None) -> dict:
    """One `affected` entry as OSV's Debian records carry it."""
    events = [{"introduced": "0"}, *([] if fixed is None else [{"fixed": fixed}])]
    return {
        "package": {"name": name, "ecosystem": f"Debian:{release}"},
        "ranges": [{"type": "ECOSYSTEM", "events": events}],
        "versions": ["1"],
    }


# Shaped like OSV's answers on 2026-11-25 for the base the 0.2.0 image was built on.
ANSWERS = {
    "adduser": {},
    "glibc": {
        "vulns": [
            {"id": "DEBIAN-CVE-2010-4756", "affected": [affected("glibc", "13")]},
            {
                "id": "DEBIAN-CVE-2026-5435",
                "affected": [
                    affected("glibc", "12"),
                    affected("glibc", "13", "2.41-12+deb13u5"),
                    affected("glibc", "14", "2.42-3"),
                ],
            },
        ]
    },
    "zlib": {
        "vulns": [
            {
                "id": "DEBIAN-CVE-2026-27171",
                "affected": [affected("zlib", "12"), affected("zlib", "13", ZLIB_FIX)],
            },
            {"id": "DSA-6613-1", "affected": [affected("zlib", "13", ZLIB_FIX)]},
        ]
    },
}


class Transport:
    def __init__(self, answers=None, status: int = 200):
        self.answers = ANSWERS if answers is None else answers
        self.status = status
        self.queries: list[dict] = []

    def request(self, endpoint, body, headers, *, timeout, max_bytes):
        assert endpoint == "https://api.osv.dev/v1/query"
        assert max_bytes == updates.MAX_RESPONSE_BYTES and 0 < timeout <= 20
        query = json.loads(body)
        self.queries.append(query)
        answer = self.answers[query["package"]["name"]]
        if isinstance(answer, list):
            answer = answer[len([q for q in self.queries if q["package"] == query["package"]]) - 1]
        return HTTPReply(
            self.status, {}, answer if isinstance(answer, bytes) else json.dumps(answer).encode()
        )


def test_a_fixed_version_in_this_release_is_pending_and_any_other_advisory_is_not():
    transport = Transport()
    report = updates.lookup(BASE, "Debian:13", PACKAGES, transport=transport)
    assert [q["package"] | {"version": q["version"]} for q in transport.queries] == [
        {"ecosystem": "Debian:13", "name": p["source"], "version": p["version"]} for p in PACKAGES
    ]
    assert report["complete"] is True and report["errors"] == []
    assert (report["base"], report["ecosystem"], report["packages"]) == (BASE, "Debian:13", 3)
    assert report["pending"] == [
        {
            "source": "glibc",
            "version": "2.41-12+deb13u4",
            "fixed": ["2.41-12+deb13u5"],
            "advisories": ["DEBIAN-CVE-2026-5435"],
        },
        {
            "source": "zlib",
            "version": "1:1.3.dfsg+really1.3.1-1",
            "fixed": [ZLIB_FIX],
            "advisories": ["DEBIAN-CVE-2026-27171", "DSA-6613-1"],
        },
    ]
    # A fix in another Debian release, or none, is not an update this base is behind.
    assert report["without_fix"] == [
        {"source": "glibc", "version": "2.41-12+deb13u4", "advisories": ["DEBIAN-CVE-2010-4756"]}
    ]
    # Markdown for the job summary: a blank line on each side of the list, or the closing
    # sentence would render inside its last item; versions as code, or GitHub would strike
    # through the text between two of Debian's tildes.
    assert updates.summary(report) == [
        f"Base image `{BASE}` (Debian:13): 2 of 3 source packages are behind a fix in that"
        " release.",
        "",
        "- `glibc` `2.41-12+deb13u4` is fixed in `2.41-12+deb13u5` (DEBIAN-CVE-2026-5435)",
        f"- `zlib` `1:1.3.dfsg+really1.3.1-1` is fixed in `{ZLIB_FIX}`"
        " (DEBIAN-CVE-2026-27171, DSA-6613-1)",
        "",
        "1 more advisories have no fixed version in Debian:13.",
    ]
    nothing_pending = updates.lookup(BASE, "Debian:13", PACKAGES[:1], transport=Transport())
    assert updates.summary(nothing_pending)[1:] == [
        "",
        "0 more advisories have no fixed version in Debian:13.",
    ]


def test_a_fix_recorded_for_another_package_of_the_advisory_is_not_this_package_s_fix():
    # As OSV records the gcc advisories: one record, several source packages per release.
    shared = {
        "id": "DEBIAN-CVE-2026-102010",
        "affected": [
            affected("gcc-13", "13", "13.3.0-13+deb13u1"),
            affected("gcc-14", "13"),
            affected("gcc-14", "14", "14.3.0-1"),
        ],
    }
    packages = [{"source": "gcc-14", "version": "14.2.0-19", "binaries": ["libgcc-s1"]}]
    transport = Transport({"gcc-14": {"vulns": [shared]}})
    report = updates.lookup(BASE, "Debian:13", packages, transport=transport)
    assert report["pending"] == []
    assert report["without_fix"] == [
        {"source": "gcc-14", "version": "14.2.0-19", "advisories": ["DEBIAN-CVE-2026-102010"]}
    ]


def test_every_page_of_a_package_is_read_and_a_repeated_page_is_refused():
    first = {"vulns": [{"id": "DSA-1-1", "affected": []}], "next_page_token": "next"}
    second = {"vulns": [{"id": "DSA-2-1", "affected": [affected("zlib", "13", ZLIB_FIX)]}]}
    transport = Transport({"zlib": [first, second]})
    report = updates.lookup(BASE, "Debian:13", PACKAGES[2:], transport=transport)
    assert [q.get("page_token") for q in transport.queries] == [None, "next"]
    assert report["pending"][0]["advisories"] == ["DSA-2-1"]
    assert report["without_fix"][0]["advisories"] == ["DSA-1-1"]
    looping = Transport({"zlib": [first, first, first]})
    assert updates.lookup(BASE, "Debian:13", PACKAGES[2:], transport=looping)["complete"] is False
    oversized = Transport({"zlib": {"next_page_token": "t" * 2049}})
    report = updates.lookup(BASE, "Debian:13", PACKAGES[2:], transport=oversized)
    assert report["complete"] is False and len(oversized.queries) == 1
    endless = Transport(
        {"zlib": [{"next_page_token": f"page-{n}"} for n in range(updates.MAX_PAGES + 1)]}
    )
    report = updates.lookup(BASE, "Debian:13", PACKAGES[2:], transport=endless)
    assert report["complete"] is False and len(endless.queries) == updates.MAX_PAGES


@pytest.mark.parametrize(
    "answer",
    [
        b"not json",
        b"[]",
        {"code": 3, "message": "Invalid query"},
        {"vulns": "none"},
        {"vulns": [{"affected": []}]},
        {"vulns": [{"id": "DSA-1\n::error::x", "affected": []}]},
        {"vulns": [{"id": "DSA-1", "affected": [affected("zlib", "13", "1.0\n::warning::x")]}]},
        {"vulns": [{"id": "DSA-1", "affected": [affected("zlib", "13", "")]}]},
        {"vulns": [], "next_page_token": 7},
    ],
)
def test_a_reply_that_is_not_the_documented_shape_leaves_the_record_incomplete(answer):
    report = updates.lookup(BASE, "Debian:13", PACKAGES[2:], transport=Transport({"zlib": answer}))
    assert report["complete"] is False
    # The error names the package and the kind of failure, in plain characters only.
    [error] = report["errors"]
    assert error.startswith("OSV lookup of the image's base packages is incomplete at zlib: ")
    assert updates.re.fullmatch(r"[A-Za-z0-9 .,()'?:-]+", error)


class Flaky(Transport):
    """Fails the first `failures` requests, by status or by a dropped connection."""

    def __init__(self, failures: int, error: Exception | None = None):
        super().__init__()
        self.failures, self.error, self.sent = failures, error, 0

    def request(self, endpoint, body, headers, *, timeout, max_bytes):
        self.sent += 1
        if self.sent <= self.failures:
            if self.error is not None:
                raise self.error
            return HTTPReply(503, {}, b"")
        return super().request(endpoint, body, headers, timeout=timeout, max_bytes=max_bytes)


@pytest.mark.parametrize(
    "error",
    [
        None,
        OSError("connection reset"),
        ValueError("deadline"),
        http.client.IncompleteRead(b"partial"),
    ],
)
def test_a_request_that_fails_is_sent_once_more_after_a_pause_and_no_further(error, pauses):
    once = Flaky(1, error)
    report = updates.lookup(BASE, "Debian:13", PACKAGES, transport=once)
    assert report["complete"] is True and len(report["pending"]) == 2
    assert once.sent == len(PACKAGES) + 1
    assert pauses == [updates.RETRY_PAUSE_SECONDS]
    twice = Flaky(2, error)
    report = updates.lookup(BASE, "Debian:13", PACKAGES, transport=twice)
    assert report["complete"] is False and twice.sent == 2
    # Which package, and whether the service failed or its reply was refused.
    kind = type(error).__name__ if error is not None else "ValueError"
    assert report["errors"][0].startswith(
        f"OSV lookup of the image's base packages is incomplete at adduser: {kind}: "
    )


def test_an_http_error_a_refused_connection_or_a_spent_deadline_is_incomplete(monkeypatch):
    failed = updates.lookup(BASE, "Debian:13", PACKAGES, transport=Transport(status=503))
    assert failed["complete"] is False

    class Refusing:
        def request(self, *args, **kwargs):
            raise OSError("network is unreachable")

    assert updates.lookup(BASE, "Debian:13", PACKAGES, transport=Refusing())["complete"] is False
    monkeypatch.setattr(updates, "TOTAL_TIMEOUT_SECONDS", 0)
    transport = Transport()
    assert updates.lookup(BASE, "Debian:13", PACKAGES, transport=transport)["complete"] is False
    assert transport.queries == []


def inventory(tmp_path: Path, **changes) -> Path:
    document = {
        "schema_version": 1,
        "image": "nexus-symbiote:0.2.0",
        "base": BASE,
        "os": {"id": "debian", "version_id": "13"},
        "packages": PACKAGES,
        **changes,
    }
    path = tmp_path / "image-packages.json"
    path.write_text(json.dumps(document))
    return path


def test_the_inventory_names_the_base_the_release_and_each_source_package(tmp_path):
    assert updates.load_inventory(inventory(tmp_path)) == (BASE, "Debian:13", PACKAGES)


@pytest.mark.parametrize(
    "changes",
    [
        {"os": {"id": "alpine", "version_id": "3"}},
        {"os": {"id": "debian", "version_id": "13\n"}},
        {"os": "debian"},
        {"base": "python:3.12 ::error::x"},
        {"base": None},
        {"packages": []},
        {"packages": [{"source": f"p{n}", "version": "1"} for n in range(2001)]},
        {"packages": "glibc"},
        {"packages": [PACKAGES[0], PACKAGES[0]]},
        {"packages": [{"source": "glibc", "version": "2.41\n::error::x"}]},
        {"packages": [{"source": "Glibc", "version": "2.41"}]},
        {"packages": [{"source": "glibc"}]},
        {"packages": ["glibc"]},
    ],
)
def test_an_inventory_that_is_not_what_the_image_check_writes_is_refused(tmp_path, changes):
    with pytest.raises(ValueError):
        updates.load_inventory(inventory(tmp_path, **changes))


def test_the_record_is_written_and_summarized_and_pending_updates_do_not_fail(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(updates, "PinnedHTTPTransport", Transport)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    out = tmp_path / "evidence" / "image-base-updates.json"
    assert updates.main([str(inventory(tmp_path)), "--out", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["complete"] is True and len(report["pending"]) == 2
    assert report["source_sha"] == "a" * 40
    printed = capsys.readouterr().out
    assert "2 of 3 source packages are behind a fix" in printed
    assert (tmp_path / "summary.md").read_text() == "## Image base updates\n\n" + printed


def test_an_incomplete_lookup_or_an_unreadable_inventory_fails_and_says_so(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(updates, "PinnedHTTPTransport", lambda: Transport(status=500))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    out = tmp_path / "image-base-updates.json"
    assert updates.main([str(inventory(tmp_path)), "--out", str(out)]) == 1
    assert json.loads(out.read_text())["complete"] is False
    assert "incomplete" in capsys.readouterr().out
    assert updates.main([str(tmp_path / "absent.json"), "--out", str(out)]) == 1
    assert json.loads(out.read_text()) == {
        "complete": False,
        "errors": ["the image inventory is unavailable or invalid"],
    }
    assert not (tmp_path / "summary.md").exists()
