"""Tests for offline OSV advisory matching, alias deduplication, and KEV/EPSS enrichment (Item 20 & X6)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import partial

import pytest
from click.testing import CliRunner

from nexus_symbiote import offline_advisories
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import ClaimEvidence, RegistryEntryComponent
from nexus_symbiote.offline_advisories import load_epss_catalog, load_kev_catalog
from tests.support import scaling_ratio

NOW = datetime(2026, 11, 20, tzinfo=UTC)
MODIFIED = "2026-11-15T00:00:00Z"
match_offline_advisories = partial(offline_advisories.match_offline_advisories, now=NOW)


def _bom_with_package(
    *,
    name: str = "transformers",
    version: str | None = "4.35.0",
    registry_type: str = "pypi",
    purl: str | None = None,
    registry_uri: str | None = None,
    claims: dict[str, ClaimEvidence] | None = None,
) -> AIBOM:
    pkg_url = (
        purl
        if purl is not None
        else (
            f"pkg:{registry_type}/{name}@{version}"
            if version is not None
            else f"pkg:{registry_type}/{name}"
        )
    )
    comp = RegistryEntryComponent(
        bom_ref=f"pkg:{registry_type}:{name}@{version or 'unpinned'}",
        name=name,
        version=version,
        registry_type=registry_type,
        package_url=pkg_url,
        registry_uri=registry_uri,
        claims=claims or {},
    )
    return AIBOM(components=[comp])


def _sample_osv_bundle() -> dict:
    # Planted alias pair: CVE-2024-99999 and GHSA-aaaa-bbbb-cccc refer to each other.
    return {
        "advisories": [
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "modified": MODIFIED,
                "aliases": ["CVE-2024-99999"],
                "summary": "Unsafe deserialization in transformers checkpoint loader",
                "database_specific": {"severity": "MEDIUM"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "transformers"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "4.0.0"}, {"fixed": "4.48.0"}],
                            }
                        ],
                    }
                ],
            },
            {
                "id": "CVE-2024-99999",
                "aliases": ["GHSA-aaaa-bbbb-cccc"],
                "summary": "Unsafe deserialization in transformers checkpoint loader",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "transformers"},
                        "versions": ["4.35.0"],
                    }
                ],
            },
            {
                "id": "GHSA-npm-1111-2222",
                "summary": "Prototype pollution in mcp-helper",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "@acme/mcp-helper"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}],
                            }
                        ],
                    }
                ],
            },
        ]
    }


def test_offline_advisories_matches_transformers_and_deduplicates_alias_pair(tmp_path):
    db_file = tmp_path / "osv-bundle.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")

    # Positive fixture: vulnerable transformers==4.35.0 matched offline; alias pair appears once.
    report, provenance = match_offline_advisories(_bom_with_package(), db_path=db_file)
    assert provenance["offline"] is True
    assert provenance["db_sha256"].startswith("sha256:")
    assert report.complete is True
    assert len(report.advisories) == 1
    adv = report.advisories[0]
    assert adv["id"] == "CVE-2024-99999"
    assert adv["advisory_id"] == "CVE-2024-99999"
    assert adv["component_ref"] == "pkg:pypi:transformers@4.35.0"
    assert adv["aliases"] == ["GHSA-aaaa-bbbb-cccc"]
    assert adv["matched_ids"] == ["CVE-2024-99999", "GHSA-aaaa-bbbb-cccc"]
    assert adv["severity"] == "high"
    assert adv["fixed_versions"] == ["4.48.0"]
    assert adv["offline"] is True

    # Benign twin: fixed version transformers==4.48.0 produces 0 advisories.
    clean_report, _ = match_offline_advisories(_bom_with_package(version="4.48.0"), db_path=db_file)
    assert clean_report.complete is True
    assert clean_report.advisories == []


def test_offline_advisories_kev_elevates_severity_and_epss_enriches(tmp_path):
    db_dir = tmp_path / "osv-dir"
    db_dir.mkdir()
    (db_dir / "transformers.json").write_text(
        json.dumps(
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2024-99999"],
                "summary": "Transformers vulnerability",
                "database_specific": {"severity": "MEDIUM"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "transformers"},
                        "versions": ["4.35.0"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    kev_file = tmp_path / "cisa-kev.json"
    kev_file.write_text(
        json.dumps(
            {
                "title": "CISA Catalog of Known Exploited Vulnerabilities",
                "vulnerabilities": [{"cveID": "CVE-2024-99999", "dateAdded": "2026-03-01"}],
            }
        ),
        encoding="utf-8",
    )
    epss_file = tmp_path / "epss.csv"
    epss_file.write_text(
        "#model_version:v2026.01,score_date:2026-11-01\n"
        "cve,epss,percentile\n"
        "CVE-2024-99999,0.91234,0.99450\n",
        encoding="utf-8",
    )

    report, provenance = match_offline_advisories(
        _bom_with_package(),
        db_path=db_dir,
        kev_paths=(kev_file,),
        epss_path=epss_file,
    )
    assert len(report.advisories) == 1
    adv = report.advisories[0]
    assert adv["in_kev"] is True
    assert adv["kev_sources"] == ["cisa-kev"]
    assert adv["kev_date_added"] == "2026-03-01"
    assert adv["base_severity"] == "medium"
    assert adv["severity"] == "critical"
    assert adv["severity_elevated_by"] == "cisa-kev"
    assert adv["epss_score"] == pytest.approx(0.91234)
    assert adv["epss_percentile"] == pytest.approx(0.99450)
    assert len(provenance["kev_catalogs"]) == 1
    assert provenance["epss_catalog"] is not None


def test_offline_advisories_refuse_two_different_records_with_one_id(tmp_path):
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-99999"}]}), "utf-8")
    record = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2024-99999"],
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "transformers"}, "versions": ["4.35.0"]}
        ],
    }
    db_dir = tmp_path / "osv"
    db_dir.mkdir()
    (db_dir / "b.json").write_text(json.dumps(record), encoding="utf-8")
    # An identical copy, as two ecosystem exports hold, is one record.
    (db_dir / "c.json").write_text(json.dumps(record), encoding="utf-8")
    report, _ = match_offline_advisories(_bom_with_package(), db_path=db_dir, kev_paths=(kev_file,))
    assert [(a["id"], a["severity"]) for a in report.advisories] == [("CVE-2024-99999", "critical")]

    # A copy without the alias, read first, would otherwise drop the KEV elevation.
    (db_dir / "a.json").write_text(json.dumps({**record, "aliases": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="two different records GHSA-aaaa-bbbb-cccc"):
        match_offline_advisories(_bom_with_package(), db_path=db_dir, kev_paths=(kev_file,))


def test_offline_advisories_order_independent_range_events_and_bounds(tmp_path):
    """Out-of-order OSV events [introduced 0, introduced 4.0, fixed 3.0, fixed 5.0] match 4.35.0."""
    db_file = tmp_path / "osv-unordered.json"
    db_file.write_text(
        json.dumps(
            {
                "advisories": [
                    {
                        "id": "CVE-2026-00001",
                        "modified": MODIFIED,
                        "summary": "Multi-branch range in unsorted event order",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "transformers"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {"introduced": "0"},
                                            {"introduced": "4.0"},
                                            {"fixed": "3.0"},
                                            {"fixed": "5.0"},
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    hit, _ = match_offline_advisories(_bom_with_package(version="4.35.0"), db_path=db_file)
    assert hit.complete is True
    assert len(hit.advisories) == 1
    assert hit.advisories[0]["fixed_versions"] == ["5.0"]

    # Between fixed 3.0 and re-introduced 4.0 -> clean.
    gap, _ = match_offline_advisories(_bom_with_package(version="3.5.0"), db_path=db_file)
    assert gap.advisories == []

    # Below first fix (2.5.0) -> vulnerable.
    early, _ = match_offline_advisories(_bom_with_package(version="2.5.0"), db_path=db_file)
    assert len(early.advisories) == 1

    # At second fix (5.0.0) -> clean.
    fixed, _ = match_offline_advisories(_bom_with_package(version="5.0.0"), db_path=db_file)
    assert fixed.advisories == []


def test_offline_advisories_partial_npm_semver_int_zero_and_range_edge_cases(tmp_path):
    """Covers partial npm SemVer ("1", "1.0", "2.0"), int introduced: 0, bool rejection, GIT, limit, last_affected, withdrawn."""
    db_file = tmp_path / "osv-edge.json"
    db_file.write_text(
        json.dumps(
            {
                "advisories": [
                    {
                        "id": "GHSA-npm-partial",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "mcp-partial"},
                                "ranges": [
                                    {
                                        "type": "SEMVER",
                                        "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "id": "GHSA-npm-major-only",
                        "database_specific": {"severity": "MEDIUM"},
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "mcp-major"},
                                "ranges": [
                                    {
                                        "type": "SEMVER",
                                        "events": [{"introduced": "1"}, {"limit": "2.0"}],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "id": "GHSA-int-zero",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "mcp-zero"},
                                "ranges": [
                                    {
                                        "type": "SEMVER",
                                        "events": [{"introduced": 0}, {"last_affected": "0.5.0"}],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "id": "GHSA-bool-not-zero",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "mcp-bool"},
                                "ranges": [{"type": "SEMVER", "events": [{"introduced": False}]}],
                            }
                        ],
                    },
                    {
                        "id": "GHSA-git-ignored",
                        "database_specific": {"severity": "CRITICAL"},
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "mcp-git"},
                                "ranges": [
                                    {
                                        "type": "GIT",
                                        "events": [{"introduced": "0"}, {"fixed": "deadbeef"}],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "id": "GHSA-withdrawn-skip",
                        "withdrawn": "2026-01-15T00:00:00Z",
                        "database_specific": {"severity": "CRITICAL"},
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "mcp-withdrawn"},
                                "versions": ["1.0.0"],
                            }
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    # Partial npm SemVer: introduced "1.0" matches 1.5.0; fixed "2.0" closes 2.0.0.
    r1, _ = match_offline_advisories(
        _bom_with_package(name="mcp-partial", version="1.5.0", registry_type="npm"),
        db_path=db_file,
    )
    assert [a["id"] for a in r1.advisories] == ["GHSA-npm-partial"]
    r1_fixed, _ = match_offline_advisories(
        _bom_with_package(name="mcp-partial", version="2.0.0", registry_type="npm"),
        db_path=db_file,
    )
    assert r1_fixed.advisories == []

    # Major-only "1" with exclusive limit "2.0".
    r2, _ = match_offline_advisories(
        _bom_with_package(name="mcp-major", version="1.9.9", registry_type="npm"),
        db_path=db_file,
    )
    assert [a["id"] for a in r2.advisories] == ["GHSA-npm-major-only"]
    r2_lim, _ = match_offline_advisories(
        _bom_with_package(name="mcp-major", version="2.0.0", registry_type="npm"),
        db_path=db_file,
    )
    assert r2_lim.advisories == []

    # Integer introduced: 0 + inclusive last_affected: 0.5.0.
    r3, _ = match_offline_advisories(
        _bom_with_package(name="mcp-zero", version="0.5.0", registry_type="npm"),
        db_path=db_file,
    )
    assert [a["id"] for a in r3.advisories] == ["GHSA-int-zero"]
    r3_after, _ = match_offline_advisories(
        _bom_with_package(name="mcp-zero", version="0.5.1", registry_type="npm"),
        db_path=db_file,
    )
    assert r3_after.advisories == []

    # Boolean False is NOT integer 0; GIT ranges and withdrawn records produce 0 matches.
    for pkg_name in ("mcp-bool", "mcp-git", "mcp-withdrawn"):
        clean, _ = match_offline_advisories(
            _bom_with_package(name=pkg_name, version="1.0.0", registry_type="npm"),
            db_path=db_file,
        )
        assert clean.advisories == [], pkg_name


def test_offline_advisories_pypi_prereleases_and_epochs(tmp_path):
    db_file = tmp_path / "osv-pep440.json"
    db_file.write_text(
        json.dumps(
            {
                "advisories": [
                    {
                        "id": "CVE-2026-44001",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "torch"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "1.0.0a1"}, {"fixed": "1.0.0"}],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "id": "CVE-2026-44002",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "epochpkg"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": "1!1.0.0"}],
                                    }
                                ],
                            }
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    rc_hit, _ = match_offline_advisories(
        _bom_with_package(name="torch", version="1.0.0rc1"), db_path=db_file
    )
    assert [a["id"] for a in rc_hit.advisories] == ["CVE-2026-44001"]
    final_clean, _ = match_offline_advisories(
        _bom_with_package(name="torch", version="1.0.0"), db_path=db_file
    )
    assert final_clean.advisories == []

    pre_epoch, _ = match_offline_advisories(
        _bom_with_package(name="epochpkg", version="9.0.0"), db_path=db_file
    )
    assert [a["id"] for a in pre_epoch.advisories] == ["CVE-2026-44002"]
    post_epoch, _ = match_offline_advisories(
        _bom_with_package(name="epochpkg", version="1!1.0.0"), db_path=db_file
    )
    assert post_epoch.advisories == []


def test_offline_advisories_unpinned_package_marks_incomplete_and_exits_1(tmp_path):
    bom_path = tmp_path / "unpinned.json"
    _bom_with_package(name="requests", version=None, purl="pkg:pypi/requests").save(bom_path)
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(main, ["advisories", str(bom_path), "--offline-db", str(db_file)])
    assert res.exit_code == 1
    payload = json.loads(res.output)
    assert payload["complete"] is False
    assert any("exact package identity unavailable" in err for err in payload["errors"])


def test_offline_advisories_over_4mb_db_and_over_500_packages_linear_speed(tmp_path):
    """DB >4 MiB parses without hitting the 4 MiB default parser cap, and 1,000x20,000 matching stays linear."""
    records = [
        {
            "id": f"GHSA-bulk-{i:05d}",
            "summary": "x" * 160,
            "database_specific": {"severity": "LOW"},
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": f"other-pkg-{i:05d}"},
                    "versions": ["1.0.0"],
                }
            ],
        }
        for i in range(18_000)
    ]
    records.append(
        {
            "id": "CVE-2026-88888",
            "modified": MODIFIED,
            "summary": "Planted target match",
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "pkg-00500"},
                    "versions": ["1.0.0"],
                }
            ],
        }
    )
    db_file = tmp_path / "large-osv.json"
    db_text = json.dumps({"advisories": records})
    assert len(db_text.encode("utf-8")) > 4 * 1024 * 1024
    db_file.write_text(db_text, encoding="utf-8")

    comps = [
        RegistryEntryComponent(
            bom_ref=f"pkg:pypi:pkg-{i:05d}@1.0.0",
            name=f"pkg-{i:05d}",
            version="1.0.0",
            registry_type="pypi",
            package_url=f"pkg:pypi/pkg-{i:05d}@1.0.0",
        )
        for i in range(1_000)
    ]
    bom = AIBOM(components=comps)

    report, _ = match_offline_advisories(bom, db_path=db_file)

    assert report.complete is True
    assert report.components_checked == 1_000
    assert [a["id"] for a in report.advisories] == ["CVE-2026-88888"]

    # A wall-clock bound failed under coverage tracing (6.1 s against 5 s on main f0404849).
    # Comparing two sizes on one machine cancels the runner and the tracer: growing the
    # packages and the advisories 4x each costs about 4x when matching is indexed by
    # package, and about 16x when every package is compared with every advisory.
    sized = {}
    for scale in (1, 4):
        scaled_db = tmp_path / f"scaled-osv-{scale}.json"
        scaled_db.write_text(json.dumps({"advisories": records[: 4_500 * scale]}), encoding="utf-8")
        sized[scale] = (AIBOM(components=comps[: 250 * scale]), scaled_db)

    def run(scale: int) -> None:
        scaled_bom, scaled_db = sized[scale]
        scaled, _ = match_offline_advisories(scaled_bom, db_path=scaled_db)
        assert scaled.components_checked == 250 * scale

    assert scaling_ratio(run) < 10


@pytest.mark.parametrize(
    "bad_epss",
    [
        "cve,epss,percentile\nCVE-2024-99999,nan,0.5\n",
        "cve,epss,percentile\nCVE-2024-99999,inf,0.5\n",
        "cve,epss,percentile\nCVE-2024-99999,-0.01,0.5\n",
        "cve,epss,percentile\nCVE-2024-99999,1.01,0.5\n",
        json.dumps({"data": [{"cve": "CVE-2024-99999", "epss": [1]}]}),
        json.dumps({"data": [{"cve": "CVE-2024-99999", "epss": True}]}),
    ],
)
def test_offline_advisories_rejects_hostile_epss_values(tmp_path, bad_epss):
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")
    epss_file = tmp_path / "bad_epss.dat"
    epss_file.write_text(bad_epss, encoding="utf-8")

    with pytest.raises(ValueError, match="finite number"):
        match_offline_advisories(_bom_with_package(), db_path=db_file, epss_path=epss_file)


def test_offline_advisories_exclude_validation_and_private_origins(tmp_path):
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")

    # Wildcard not at end must be rejected just like live mode.
    with pytest.raises(ValueError, match="last character"):
        match_offline_advisories(_bom_with_package(), db_path=db_file, exclude=("trans*mers",))

    # --exclude-private-origins withholds packages lacking lockfile-backed public origin.
    bom_unrecorded = _bom_with_package()
    rep_excl, _ = match_offline_advisories(
        bom_unrecorded, db_path=db_file, exclude_private_origins=True
    )
    assert rep_excl.components_excluded == 1
    assert rep_excl.components_checked == 0

    bom_public = _bom_with_package(
        registry_uri="https://pypi.org",
        claims={
            "package_resolution": ClaimEvidence(
                assurance=AssuranceLevel.DECLARED,
                method="lockfile",
                scope="uv.lock",
            )
        },
    )
    rep_pub, _ = match_offline_advisories(bom_public, db_path=db_file, exclude_private_origins=True)
    assert rep_pub.components_checked == 1
    assert len(rep_pub.advisories) == 1


def test_offline_advisories_npm_semver_and_symlink_rejection(tmp_path):
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")

    bom_npm = _bom_with_package(
        name="@acme/mcp-helper",
        version="1.1.5",
        registry_type="npm",
        purl="pkg:npm/%40acme/mcp-helper@1.1.5",
    )
    report, _ = match_offline_advisories(bom_npm, db_path=db_file)
    assert len(report.advisories) == 1
    assert report.advisories[0]["id"] == "GHSA-npm-1111-2222"

    # Symlink offline DB must be refused.
    link = tmp_path / "symlink-db.json"
    link.symlink_to(db_file)
    with pytest.raises(ValueError, match="symbolic link"):
        match_offline_advisories(bom_npm, db_path=link)


def test_advisories_cli_offline_mode_and_help_exit_codes(tmp_path):
    bom_path = tmp_path / "aibom.json"
    _bom_with_package().save(bom_path)
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")

    runner = CliRunner()
    help_res = runner.invoke(main, ["advisories", "--help"])
    assert help_res.exit_code == 0
    assert "Exits 1" in help_res.output

    res = runner.invoke(main, ["advisories", str(bom_path), "--offline-db", str(db_file)])
    assert res.exit_code == 1
    payload = json.loads(res.output)
    assert payload["sent_to_osv"] == "nothing (offline advisory bundle)"
    assert payload["provenance"]["offline"] is True
    assert len(payload["advisories"]) == 1

    # --kev without --offline-db fails cleanly.
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    res_bad = runner.invoke(main, ["advisories", str(bom_path), "--kev", str(kev_file)])
    assert res_bad.exit_code != 0
    assert "--offline-db" in res_bad.output


def _pypi_record(record_id: str = "GHSA-cccc-dddd-eeee") -> dict:
    return {
        "id": record_id,
        "modified": MODIFIED,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "transformers"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    }


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"advisories": []},
        {"vulns": [_pypi_record()]},
        {"advisories": {"GHSA-cccc-dddd-eeee": _pypi_record()}},
        [_pypi_record(), "GHSA-cccc-dddd-eeee"],
        [_pypi_record(), {"affected": []}],
        [{**_pypi_record(), "withdrawn": "2024-01-01T00:00:00Z"}],
    ],
    ids=[
        "empty",
        "empty-wrapper",
        "unknown-wrapper",
        "mapping",
        "non-object",
        "no-id",
        "withdrawn",
    ],
)
def test_offline_advisories_refuse_an_empty_or_wrongly_shaped_database(tmp_path, payload):
    bom_path = tmp_path / "aibom.json"
    _bom_with_package().save(bom_path)
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Offline advisory DB"):
        match_offline_advisories(_bom_with_package(), db_path=db_file)

    res = CliRunner().invoke(main, ["advisories", str(bom_path), "--offline-db", str(db_file)])
    assert res.exit_code == 1
    assert "Offline advisory DB" in res.output
    assert '"complete"' not in res.output


def test_offline_advisories_refuse_an_empty_or_nested_database_directory(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "README.txt").write_text("no records here", encoding="utf-8")
    with pytest.raises(ValueError, match="holds no advisory records"):
        match_offline_advisories(_bom_with_package(), db_path=empty)

    nested = tmp_path / "nested"
    (nested / "PyPI").mkdir(parents=True)
    (nested / "PyPI" / "a.json").write_text(json.dumps(_pypi_record()), encoding="utf-8")
    with pytest.raises(ValueError, match="subdirectories"):
        match_offline_advisories(_bom_with_package(), db_path=nested)

    # A top-level record does not excuse the records a subdirectory would hide.
    (nested / "top.json").write_text(json.dumps(_pypi_record()), encoding="utf-8")
    with pytest.raises(ValueError, match="subdirectories"):
        match_offline_advisories(_bom_with_package(), db_path=nested)


def test_offline_feed_bounds_directory_entries_before_sorting(tmp_path, monkeypatch):
    monkeypatch.setattr(offline_advisories, "MAX_DB_FILES", 2)
    for filename in ("first.txt", "second.txt", "third.txt"):
        (tmp_path / filename).touch()
    with pytest.raises(ValueError, match="2 directory entries"):
        offline_advisories.load_offline_advisory_db(tmp_path)


def test_offline_advisories_database_without_the_queried_ecosystem_is_incomplete(tmp_path):
    db_file = tmp_path / "pypi-only.json"
    db_file.write_text(json.dumps([_pypi_record()]), encoding="utf-8")
    npm = _bom_with_package(name="left-pad", version="1.3.0", registry_type="npm")
    bom = AIBOM(components=[*_bom_with_package().components, *npm.components])

    report, _ = match_offline_advisories(bom, db_path=db_file)
    assert report.components_checked == 1
    assert [adv["package"] for adv in report.advisories] == ["transformers"]
    assert report.complete is False
    assert report.errors == ["pkg:npm:left-pad@1.3.0: offline advisory DB holds no npm records"]

    only_npm, _ = match_offline_advisories(npm, db_path=db_file)
    assert only_npm.components_checked == 0
    assert only_npm.coverage == "none"
    assert only_npm.complete is False

    bom_path = tmp_path / "npm.json"
    npm.save(bom_path)
    res = CliRunner().invoke(main, ["advisories", str(bom_path), "--offline-db", str(db_file)])
    assert res.exit_code == 1
    assert json.loads(res.output)["complete"] is False


@pytest.mark.parametrize(
    "payload",
    [{}, {"catalog": []}, {"vulnerabilities": []}, {"vulnerabilities": [{"notes": "no id"}]}],
)
def test_offline_advisories_refuse_a_kev_catalog_without_entries(tmp_path, payload):
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="KEV catalog"):
        load_kev_catalog(kev_file)


@pytest.mark.parametrize(
    "text",
    [
        json.dumps([{"cve": "CVE-2024-99999", "epss": 0.5}]),
        json.dumps({"data": []}),
        "#model_version:v2025.03.14\ncve,epss,percentile\n",
        "",
    ],
    ids=["json-array", "empty-data", "header-only", "empty-file"],
)
def test_offline_advisories_refuse_an_epss_catalog_without_entries(tmp_path, text):
    epss_file = tmp_path / "epss"
    epss_file.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="EPSS"):
        load_epss_catalog(epss_file)


def test_offline_advisories_provenance_counts_catalog_entries(tmp_path):
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(
        json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-99999"}, {"cveID": "CVE-2024-1"}]}),
        encoding="utf-8",
    )
    epss_file = tmp_path / "epss.csv"
    epss_file.write_text("cve,epss,percentile\nCVE-2024-99999,0.5,0.9\n", encoding="utf-8")

    _, provenance = match_offline_advisories(
        _bom_with_package(), db_path=db_file, kev_paths=[kev_file], epss_path=epss_file
    )
    assert provenance["records_loaded"] == 3
    assert provenance["kev_catalogs"][0]["entries"] == 2
    assert provenance["epss_catalog"]["entries"] == 1


def test_offline_advisories_stop_matching_at_the_report_limit(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus_symbiote.offline_advisories.MAX_ADVISORIES", 3)
    db_file = tmp_path / "osv.json"
    db_file.write_text(
        json.dumps([_pypi_record(f"GHSA-{index:04d}-dddd-eeee") for index in range(2)]),
        encoding="utf-8",
    )
    bom = AIBOM(
        components=[
            component
            for minor in range(5)
            for component in _bom_with_package(version=f"4.{minor}.0").components
        ]
    )

    report, _ = match_offline_advisories(bom, db_path=db_file)
    assert len(report.advisories) == 3
    assert report.errors == ["Advisory report limit reached (3)"]
    assert report.components_checked == 2
    assert report.complete is False


def _transformers_record(record_id: str = "GHSA-bad0-bad0-bad0", **affected: object) -> dict:
    package = {"package": {"ecosystem": "PyPI", "name": "transformers"}}
    return {"id": record_id, "modified": MODIFIED, "affected": [{**package, **affected}]}


_FIXED_BEFORE_4 = _transformers_record(
    "GHSA-good-good-good",
    ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}],
)


@pytest.mark.parametrize(
    "bad",
    [
        _transformers_record(ranges="bad"),
        _transformers_record(versions="4.35.0"),
        _transformers_record(ranges=["bad"]),
        _transformers_record(ranges=[{"type": "ECOSYSTEM", "events": "bad"}]),
        _transformers_record(
            ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "not a version!"}]}]
        ),
        _transformers_record(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": False}]}]),
        _transformers_record(
            ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": 5}]}]
        ),
        _transformers_record(
            ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0", "fixed": "5"}]}]
        ),
        _transformers_record(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {}]}]),
        _transformers_record(ranges=[{"type": "CALVER", "events": [{"introduced": "0"}]}]),
        _transformers_record(ranges=[{"type": 7, "events": [{"introduced": "0"}]}]),
        _transformers_record(ranges=[{"type": "ECOSYSTEM", "events": [{"fixed": "5.0"}]}]),
        _transformers_record(ranges=[{"type": "ECOSYSTEM", "events": []}]),
    ],
    ids=[
        "ranges-not-list",
        "versions-not-list",
        "range-not-object",
        "events-not-list",
        "introduced-not-version",
        "introduced-bool",
        "fixed-not-string",
        "two-keys-in-event",
        "event-without-key",
        "range-type-unknown",
        "range-type-not-string",
        "events-without-introduced",
        "events-empty",
    ],
)
def test_offline_advisories_unevaluable_record_for_the_package_is_incomplete(tmp_path, bad):
    bom_path = tmp_path / "aibom.json"
    _bom_with_package().save(bom_path)
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([_FIXED_BEFORE_4, bad]), encoding="utf-8")

    report, _ = match_offline_advisories(_bom_with_package(), db_path=db_file)
    assert report.advisories == []
    assert report.complete is False
    assert len(report.errors) == 1
    assert report.errors[0].startswith("pkg:pypi:transformers@4.35.0: offline advisory GHSA-bad0")

    res = CliRunner().invoke(main, ["advisories", str(bom_path), "--offline-db", str(db_file)])
    assert res.exit_code == 1
    assert json.loads(res.output)["complete"] is False


def test_offline_advisories_refuse_a_record_whose_affected_is_not_a_list_of_objects(tmp_path):
    bom_path = tmp_path / "aibom.json"
    _bom_with_package().save(bom_path)
    db_file = tmp_path / "osv.json"
    for affected in ("oops", ["oops", *_FIXED_BEFORE_4["affected"]]):
        bad = {"id": "GHSA-bad0-bad0-bad0", "affected": affected}
        db_file.write_text(json.dumps([_FIXED_BEFORE_4, bad]), encoding="utf-8")
        with pytest.raises(ValueError, match="GHSA-bad0-bad0-bad0 has malformed 'affected'"):
            match_offline_advisories(_bom_with_package(), db_path=db_file)
        res = CliRunner().invoke(main, ["advisories", str(bom_path), "--offline-db", str(db_file)])
        assert res.exit_code == 1
        assert '"complete"' not in res.output


def test_offline_advisories_unevaluable_record_elsewhere_keeps_other_matches_complete(tmp_path):
    other = _transformers_record(ranges="bad")
    other["affected"][0]["package"]["name"] = "torch"
    vulnerable = _transformers_record(
        "GHSA-vuln-vuln-vuln",
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "4.0"}, {"fixed": "4.48.0"}]}],
    )
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([_FIXED_BEFORE_4, other, vulnerable]), encoding="utf-8")

    report, _ = match_offline_advisories(_bom_with_package(), db_path=db_file)
    assert report.complete is True
    assert report.errors == []
    assert [(a["id"], a["fixed_versions"]) for a in report.advisories] == [
        ("GHSA-vuln-vuln-vuln", ["4.48.0"])
    ]

    torch = _bom_with_package(name="torch", version="2.0.0")
    both = AIBOM(components=[*_bom_with_package().components, *torch.components])
    mixed, _ = match_offline_advisories(both, db_path=db_file)
    assert [a["component_ref"] for a in mixed.advisories] == ["pkg:pypi:transformers@4.35.0"]
    assert mixed.errors == [
        "pkg:pypi:torch@2.0.0: offline advisory GHSA-bad0-bad0-bad0: "
        "OSV affected versions or ranges are not a list"
    ]


def _torch_record(*last_affected: str, versions: list[str] | None = None) -> dict:
    """The PYSEC-2025-193 shape: from 0 to a ``last_affected`` PEP 440 cannot parse."""
    ranges = [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": last}]}
        for last in last_affected
    ]
    affected = {"package": {"ecosystem": "PyPI", "name": "torch"}, "ranges": ranges}
    return {
        "id": "PYSEC-2025-193",
        "modified": MODIFIED,
        "affected": [{**affected, "versions": versions or []}],
    }


@pytest.mark.parametrize("version", ["2.5.1", "2.7.0"])
def test_offline_advisories_unparsable_upper_bound_is_a_flagged_match(tmp_path, version):
    bom = _bom_with_package(name="torch", version=version)
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([_torch_record("2.6.0-NA", "2.6.0-cu124")]), encoding="utf-8")

    report, _ = match_offline_advisories(bom, db_path=db_file)
    assert report.complete is True
    assert report.errors == []
    assert [
        (a["id"], a["range_undecidable"], a["undecidable_bounds"]) for a in report.advisories
    ] == [("PYSEC-2025-193", True, ["2.6.0-NA", "2.6.0-cu124"])]

    # The fixture's fixed date must not age out of the CLI's real-clock feed limit.
    arguments = ["advisories", str(bom_path), "--offline-db", str(db_file)]
    res = CliRunner().invoke(main, [*arguments, "--max-feed-age-days", "36500"])
    assert res.exit_code == 1
    assert json.loads(res.output)["complete"] is True


def test_offline_advisories_exact_listing_decides_before_unparsable_bounds(tmp_path):
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([_torch_record("2.6.0-NA", versions=["2.5.1"])]), "utf-8")
    listed, _ = match_offline_advisories(
        _bom_with_package(name="torch", version="2.5.1"), db_path=db_file
    )
    assert [a["id"] for a in listed.advisories] == ["PYSEC-2025-193"]
    assert "range_undecidable" not in listed.advisories[0]
    unlisted, _ = match_offline_advisories(
        _bom_with_package(name="torch", version="2.7.0"), db_path=db_file
    )
    assert unlisted.advisories[0]["undecidable_bounds"] == ["2.6.0-NA"]


@pytest.mark.parametrize(
    ("events", "version", "bounds"),
    [
        # The unparsable bound may close the interval after 2.0, so the fix decides nothing.
        ([{"introduced": "0"}, {"fixed": "2.0"}, {"last_affected": "junk!"}], "2.5", ["junk!"]),
        ([{"fixed": "junk!"}, {"introduced": "0"}, {"fixed": "2.0"}], "2.5", ["junk!"]),
        # Event order puts the unparsable bound in the interval before 2.0's.
        (
            [{"introduced": "0"}, {"last_affected": "junk!"}, {"introduced": "2.0"}]
            + [{"fixed": "3.0"}],
            "3.5",
            None,
        ),
        ([{"introduced": "0"}, {"limit": "2.0"}, {"fixed": "junk!"}], "2.5", None),
        ([{"introduced": "3.0"}, {"last_affected": "junk!"}], "2.5", None),
        ([{"introduced": "0"}, {"fixed": "2.0"}, {"last_affected": "junk!"}], "1.5", ["junk!"]),
        ([{"introduced": "1.0"}, {"limit": "junk!"}], "2.5", ["junk!"]),
        ([{"introduced": "0"}, {"fixed": "x" * 100}], "2.5", ["x" * 64]),
        # Two introduced events with no bound between them open one interval, in either order.
        (
            [{"introduced": "1.0"}, {"introduced": "0"}, {"last_affected": "junk!"}]
            + [{"fixed": "2.0"}],
            "2.5",
            ["junk!"],
        ),
        (
            [{"introduced": "0"}, {"introduced": "1.0"}, {"last_affected": "junk!"}]
            + [{"fixed": "2.0"}],
            "2.5",
            ["junk!"],
        ),
        # A limit is not an interval bound, so it does not split the run either.
        (
            [{"introduced": "1.0"}, {"limit": "9.0"}, {"introduced": "0"}]
            + [{"last_affected": "junk!"}, {"fixed": "2.0"}],
            "2.5",
            ["junk!"],
        ),
        # A bound between them does: the unparsable one belongs to the later interval only.
        (
            [{"introduced": "1.0"}, {"fixed": "2.0"}, {"introduced": "0"}]
            + [{"last_affected": "junk!"}],
            "2.5",
            None,
        ),
    ],
    ids=[
        "fixed-in-undecidable-interval",
        "unordered-bound",
        "other-interval",
        "limit-excludes",
        "below-introduced",
        "fixed-above",
        "limit",
        "long",
        "introduced-run-later-first",
        "introduced-run-zero-first",
        "introduced-run-across-limit",
        "introduced-split-by-bound",
    ],
)
def test_offline_advisories_parsable_bounds_decide_before_unparsable_ones(
    tmp_path, events, version, bounds
):
    db_file = tmp_path / "osv.json"
    record = _transformers_record(ranges=[{"type": "ECOSYSTEM", "events": events}])
    db_file.write_text(json.dumps([record]), encoding="utf-8")
    report, _ = match_offline_advisories(_bom_with_package(version=version), db_path=db_file)
    assert report.complete is True
    assert [a["undecidable_bounds"] for a in report.advisories] == ([bounds] if bounds else [])


@pytest.mark.parametrize("version", ["2.8.4", "2.9.0"])
def test_offline_advisories_unparsable_last_affected_beside_parsable_ones_flags(tmp_path, version):
    """The PYSEC-2024-264 shape: 2.9.0-NA may be the last affected, so 2.9.0rc3 ends nothing."""
    last = ["2.9.0-NA", "2.9.0-beta1", "2.9.0-beta2", "2.9.0-rc1", "2.9.0-rc2", "2.9.0-rc3"]
    events = [{"introduced": "0"}, *({"last_affected": v} for v in last)]
    record = _transformers_record(
        "PYSEC-2024-264", ranges=[{"type": "ECOSYSTEM", "events": events}]
    )
    record["affected"][0]["package"]["name"] = "apache-airflow"
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([record]), encoding="utf-8")
    bom = _bom_with_package(name="apache-airflow", version=version)

    report, _ = match_offline_advisories(bom, db_path=db_file)
    assert report.complete is True
    assert [
        (a["id"], a["range_undecidable"], a["undecidable_bounds"]) for a in report.advisories
    ] == [("PYSEC-2024-264", True, ["2.9.0-NA"])]


@pytest.mark.parametrize(
    ("limits", "found"),
    [
        (["2.0", "5.0"], [("GHSA-bad0-bad0-bad0", None)]),
        (["2.0", "*"], [("GHSA-bad0-bad0-bad0", None)]),
        (["2.0", "junk!"], [("GHSA-bad0-bad0-bad0", ["junk!"])]),
        (["2.0"], []),
    ],
    ids=["below-another-limit", "star-limit", "unparsable-limit", "at-or-above-every-limit"],
)
def test_offline_advisories_a_version_below_any_limit_is_in_range(tmp_path, limits, found):
    """OSV limits: a version is in range below any of them, and "*" bounds nothing."""
    events = [{"introduced": "0"}, *({"limit": limit} for limit in limits)]
    db_file = tmp_path / "osv.json"
    record = _transformers_record(ranges=[{"type": "ECOSYSTEM", "events": events}])
    db_file.write_text(json.dumps([record]), encoding="utf-8")
    report, _ = match_offline_advisories(_bom_with_package(version="3.0"), db_path=db_file)
    assert report.complete is True
    assert [(a["id"], a.get("undecidable_bounds")) for a in report.advisories] == found


def test_offline_advisories_bound_the_errors_from_malformed_records(tmp_path):
    bad = [_transformers_record(f"GHSA-bad0-bad0-{i:04d}", ranges="bad") for i in range(1000)]
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(bad), encoding="utf-8")
    pins = [_bom_with_package(version=f"4.{minor}.0").components[0] for minor in range(100)]

    report, _ = match_offline_advisories(AIBOM(components=pins), db_path=db_file)
    assert report.components_checked == 100
    assert report.complete is False
    assert len(report.errors) == 101
    assert report.errors[-1] == "99900 more offline advisory errors are not listed"

    AIBOM(components=pins).save(bom_path := tmp_path / "aibom.json")
    res = CliRunner().invoke(main, ["advisories", str(bom_path), "--offline-db", str(db_file)])
    assert res.exit_code == 1
    assert len(json.loads(res.output)["errors"]) == 101


@pytest.mark.parametrize(
    "intros",
    [[{"introduced": "1.0"}, {"introduced": "0"}], [{"introduced": "0"}, {"introduced": "1.0"}]],
    ids=["later-introduced-first", "zero-first"],
)
def test_offline_advisories_consecutive_introduced_events_own_one_interval(tmp_path, intros):
    """A bound follows every introduced of the run before it, so event order cannot decide.

    With a single owner, [introduced 1.0, introduced 0, last_affected junk!, fixed 2.0] gave
    the unparsable bound to 0 alone, so fixed 2.0 excluded 2.5 and the record did not match,
    while the swapped order flagged it.
    """
    events = [*intros, {"last_affected": "junk!"}, {"fixed": "2.0"}]
    record = _transformers_record(ranges=[{"type": "ECOSYSTEM", "events": events}])
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([record]), encoding="utf-8")
    report, _ = match_offline_advisories(_bom_with_package(version="2.5"), db_path=db_file)
    assert report.complete is True
    assert [a["undecidable_bounds"] for a in report.advisories] == [["junk!"]]

    # A bound between the two introduced events splits them into two owners again.
    split = [intros[0], {"fixed": "0.5"}, intros[1], {"last_affected": "junk!"}, {"fixed": "2.0"}]
    record = _transformers_record(ranges=[{"type": "ECOSYSTEM", "events": split}])
    db_file.write_text(json.dumps([record]), encoding="utf-8")
    report, _ = match_offline_advisories(_bom_with_package(version="2.5"), db_path=db_file)
    expected = [["junk!"]] if intros[1] == {"introduced": "1.0"} else []
    assert [a["undecidable_bounds"] for a in report.advisories] == expected


@pytest.mark.parametrize(
    ("rng", "reason"),
    [
        ({"type": "FOO", "events": [{"introduced": "0"}]}, "OSV range type is not supported"),
        ({"type": 7, "events": [{"introduced": "0"}]}, "OSV range type is not supported"),
        ({"type": "ECOSYSTEM", "events": [{"fixed": "2.0"}]}, "OSV range has no introduced event"),
        ({"type": "ECOSYSTEM", "events": []}, "OSV range has no introduced event"),
        ({"events": [{"limit": "*"}]}, "OSV range has no introduced event"),
    ],
    ids=["unknown-type", "non-string-type", "fixed-only", "no-events", "limit-only"],
)
def test_offline_advisories_report_ranges_that_would_quietly_mean_not_affected(
    tmp_path, rng, reason
):
    """A range type OSV does not define, or a range with no introduced, is an error, not a miss."""
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([_transformers_record(ranges=[rng])]), encoding="utf-8")
    report, _ = match_offline_advisories(_bom_with_package(), db_path=db_file)
    assert report.advisories == []
    assert report.complete is False
    assert report.errors == [
        f"pkg:pypi:transformers@4.35.0: offline advisory GHSA-bad0-bad0-bad0: {reason}"
    ]


def test_offline_advisories_git_range_beside_an_ecosystem_range_is_not_an_error(tmp_path):
    """OSV records commonly pair a GIT range with the ECOSYSTEM one; only the latter is matched."""
    git = {"type": "GIT", "repo": "https://example.com/r.git", "events": [{"introduced": "0"}]}
    eco = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0"}]}
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([_transformers_record(ranges=[git, eco])]), encoding="utf-8")
    report, _ = match_offline_advisories(_bom_with_package(), db_path=db_file)
    assert report.complete is True
    assert report.errors == []
    assert [a["fixed_versions"] for a in report.advisories] == [["5.0"]]
