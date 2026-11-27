"""Scan-time offline advisories, the all-packages registry mode and CycloneDX vulnerabilities."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.validation import validate_cyclonedx
from nexus_symbiote.offline_advisories import load_offline_advisory_db
from nexus_symbiote.scan_advisories import ADVISORY_SURFACE_PREFIX
from nexus_symbiote.scanners.registry import AllPackagesRegistryScanner, RegistryScanner


def _project(root: Path) -> Path:
    project = root / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("langchain==0.3.27\npillow==9.0.0\n")
    return project


def _bundle(root: Path) -> Path:
    bundle = root / "osv-bundle"
    bundle.mkdir()
    recent = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = {
        "id": "PYSEC-2022-TEST1",
        "aliases": ["CVE-2022-22817"],
        "summary": "Pillow before 9.0.1 allows evaluation of arbitrary expressions.",
        "modified": recent,
        "published": "2022-01-10T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pillow", "purl": "pkg:pypi/pillow"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0.1"}]}
                ],
            }
        ],
        "database_specific": {"severity": "HIGH"},
    }
    (bundle / "PYSEC-2022-TEST1.json").write_text(json.dumps(record))
    return bundle


def test_all_packages_registry_inventories_non_ai_pins(tmp_path: Path) -> None:
    project = _project(tmp_path)
    catalog_only = {c.name for c in RegistryScanner().scan(project).components}
    everything = {c.name for c in AllPackagesRegistryScanner().scan(project).components}
    assert "pillow" not in catalog_only and "langchain" in catalog_only
    assert {"pillow", "langchain"} <= everything


def test_scan_records_offline_advisories_and_exports_cyclonedx_vulnerabilities(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    bundle = _bundle(tmp_path)
    out = tmp_path / "inventory.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "--all-packages",
            "--advisory-db",
            str(bundle),
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    bom = AIBOM.load(out)
    (pillow,) = [c for c in bom.components if c.name == "pillow"]
    (finding,) = [r for r in pillow.risks if r.category == "known_vulnerability"]
    assert "PYSEC-2022-TEST1" in finding.detail and "CVE-2022-22817" in finding.detail
    assert finding.severity.value == "high"
    (advisory,) = pillow.properties["advisories"]
    assert {advisory["id"], *advisory["aliases"]} == {"PYSEC-2022-TEST1", "CVE-2022-22817"}
    document = CycloneDXGenerator().generate(bom)
    (vulnerability,) = document["vulnerabilities"]
    assert vulnerability["id"] == advisory["id"]
    assert vulnerability["affects"] == [{"ref": pillow.bom_ref}]
    assert vulnerability["ratings"] == [{"severity": "high"}]
    assert any(
        f.startswith("advisories: offline OSV bundle")
        for f in bom.metadata.completeness.surfaces_scanned
    )  # type: ignore[union-attr]


def test_a_bundle_inside_the_scanned_project_is_refused(tmp_path: Path) -> None:
    project = _project(tmp_path)
    inside = project / "bundle"
    inside.mkdir()
    (inside / "x.json").write_text("[]")
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "--advisory-db",
            str(inside),
        ],
    )
    assert result.exit_code == 0
    assert "must lie outside the scanned project" in result.output


def _record(
    identifier: str,
    packages: list[tuple[str, str]],
    *,
    severity: str | None = "HIGH",
    aliases: list[str] | None = None,
    summary: str = "A planted test advisory.",
    age_days: int = 1,
) -> dict[str, object]:
    modified = (datetime.now(UTC) - timedelta(days=age_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record: dict[str, object] = {
        "id": identifier,
        "aliases": aliases or [],
        "summary": summary,
        "modified": modified,
        "published": "2022-01-10T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": name, "purl": f"pkg:pypi/{name}"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}
                ],
            }
            for name, fixed in packages
        ],
    }
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    return record


def _write_bundle(root: Path, records: list[dict[str, object]], name: str = "bundle") -> Path:
    bundle = root / name
    bundle.mkdir()
    for index, record in enumerate(records):
        (bundle / f"record-{index}.json").write_text(json.dumps(record))
    return bundle


def _scan(project: Path, bundle: Path, out: Path, *extra: str) -> AIBOM:
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "--all-packages",
            "--advisory-db",
            str(bundle),
            "-o",
            str(out),
            *extra,
        ],
    )
    assert result.exit_code == 0, result.output
    return AIBOM.load(out)


def _claim(bom: AIBOM):  # noqa: ANN202
    claim = bom.metadata.completeness
    assert claim is not None
    return claim


def test_one_advisory_across_two_pins_exports_one_vulnerability(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("pillow==9.0.0\nnumpy==1.21.0\n")
    # Two records that share a CVE alias are reported under that CVE for both packages.
    bundle = _write_bundle(
        tmp_path,
        [
            _record("PYSEC-A", [("pillow", "9.0.1")], severity="LOW", aliases=["CVE-2099-0001"]),
            _record(
                "GHSA-B", [("numpy", "1.22.0")], severity="CRITICAL", aliases=["CVE-2099-0001"]
            ),
        ],
    )
    bom = _scan(project, bundle, tmp_path / "inventory.json")
    document = CycloneDXGenerator().generate(bom)
    assert validate_cyclonedx(document) == []
    (vulnerability,) = document["vulnerabilities"]
    refs = {c.bom_ref for c in bom.components if c.name in {"pillow", "numpy"}}
    assert vulnerability["id"] == "CVE-2099-0001"
    assert {a["ref"] for a in vulnerability["affects"]} == refs
    assert vulnerability["ratings"] == [{"severity": "critical"}]
    assert [r["id"] for r in vulnerability["references"]] == ["GHSA-B", "PYSEC-A"]
    aliasless = _write_bundle(
        tmp_path, [_record("PYSEC-ALIASLESS", [("pillow", "9.0.1"), ("numpy", "1.22.0")])], "two"
    )
    bom = _scan(project, aliasless, tmp_path / "inventory-2.json")
    document = CycloneDXGenerator().generate(bom)
    assert validate_cyclonedx(document) == []
    (vulnerability,) = document["vulnerabilities"]
    assert "references" not in vulnerability and len(vulnerability["affects"]) == 2


def test_an_unstated_severity_is_recorded_as_medium_and_exported_as_unknown(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    bundle = _write_bundle(tmp_path, [_record("PYSEC-NOSEV", [("pillow", "9.0.1")], severity=None)])
    bom = _scan(project, bundle, tmp_path / "inventory.json")
    (pillow,) = [c for c in bom.components if c.name == "pillow"]
    (finding,) = [r for r in pillow.risks if r.category == "known_vulnerability"]
    assert finding.severity.value == "medium"
    assert "Severity is not stated in the advisory data" in finding.detail
    (entry,) = pillow.properties["advisories"]
    assert entry["matcher_severity"] == "unknown" and entry["severity"] == "medium"
    document = CycloneDXGenerator().generate(bom)
    assert validate_cyclonedx(document) == []
    assert document["vulnerabilities"][0]["ratings"] == [{"severity": "unknown"}]


def test_every_run_records_the_bundle_digest_and_the_targets_checked(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, [_record("PYSEC-OTHER", [("pillow", "9.0.1")])])
    _, feed_digest = load_offline_advisory_db(bundle)
    floating = tmp_path / "floating"
    floating.mkdir()
    (floating / "requirements.txt").write_text("requests>=2.0\n")
    claim = _claim(_scan(floating, bundle, tmp_path / "floating.json"))
    (surface,) = [s for s in claim.unobserved_surfaces if s.startswith(ADVISORY_SURFACE_PREFIX)]
    receipt = json.loads(surface.removeprefix(ADVISORY_SURFACE_PREFIX))
    assert receipt["db_sha256"] == feed_digest
    assert receipt["coverage"] == "none" and receipt["components_checked"] == 0
    assert any(f.startswith("advisories:") for f in claim.scan_failures)
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "requirements.txt").write_text("requests==2.31.0\n")
    claim = _claim(_scan(clean, bundle, tmp_path / "clean.json"))
    (surface,) = [s for s in claim.surfaces_scanned if s.startswith(ADVISORY_SURFACE_PREFIX)]
    receipt = json.loads(surface.removeprefix(ADVISORY_SURFACE_PREFIX))
    assert receipt["db_sha256"] == feed_digest
    assert receipt["coverage"] == "complete" and receipt["components_checked"] == 1
    assert receipt["advisories_recorded"] == 0 and not claim.scan_failures
    other = _write_bundle(tmp_path, [_record("PYSEC-ELSE", [("pillow", "9.0.2")])], "other")
    again = _claim(_scan(clean, other, tmp_path / "clean-2.json"))
    assert again.surfaces_scanned != claim.surfaces_scanned


def test_a_stale_bundle_is_a_collection_failure_with_its_surface_recorded(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    bundle = _write_bundle(tmp_path, [_record("PYSEC-OLD", [("pillow", "9.0.1")], age_days=400)])
    claim = _claim(_scan(project, bundle, tmp_path / "inventory.json"))
    assert any(f.startswith("advisories:") for f in claim.scan_failures)
    assert any(s.startswith("advisories: offline OSV bundle") for s in claim.surfaces_scanned)


def test_an_all_packages_scan_reconciles_against_its_unchanged_checkout(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("langchain==0.3.27\nrequests==2.31.0\n")
    out = tmp_path / "inventory.json"
    scanned = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "--all-packages",
            "-o",
            str(out),
        ],
    )
    assert scanned.exit_code == 0, scanned.output
    bom = AIBOM.load(out)
    flags = {
        c.name: c.properties.get("ai_catalog")
        for c in bom.components
        if c.name in {"langchain", "requests"}
    }
    assert flags == {"langchain": True, "requests": False}
    validated = CliRunner().invoke(
        main,
        ["validate", str(out), "--project", str(project), "--all-packages", "--no-project-policy"],
    )
    assert "no matching local evidence" not in validated.output, validated.output
    assert "project-reconciliation-failed" not in validated.output, validated.output


def test_all_packages_without_the_registry_collector_warns(tmp_path: Path) -> None:
    project = _project(tmp_path)
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "--all-packages",
            "--scanner",
            "mcp",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "--all-packages has no effect" in (result.stderr or "") + result.output


def test_the_catalog_predicate_is_unchanged_in_all_packages_mode() -> None:
    assert AllPackagesRegistryScanner._is_ai_package("requests") is False
    assert AllPackagesRegistryScanner._inventoried("requests") is True
    assert RegistryScanner._inventoried("requests") is False
    assert RegistryScanner._inventoried("langchain") is True


def test_a_cvss_v3_vector_sets_the_severity_from_its_base_score(tmp_path: Path) -> None:
    project = _project(tmp_path)
    record = _record("CVE-2099-9999", [("pillow", "9.0.1")], severity=None)
    record["severity"] = [
        {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    ]
    bom = _scan(project, _write_bundle(tmp_path, [record]), tmp_path / "inventory.json")
    (pillow,) = [c for c in bom.components if c.name == "pillow"]
    (finding,) = [r for r in pillow.risks if r.category == "known_vulnerability"]
    assert finding.severity.value == "critical"
    assert "Severity is not stated" not in finding.detail
    (vulnerability,) = CycloneDXGenerator().generate(bom)["vulnerabilities"]
    assert vulnerability["ratings"] == [{"severity": "critical"}]


def test_vex_lists_a_recorded_advisory_once_under_its_bom_id(tmp_path: Path) -> None:
    from nexus_symbiote.core.hashing import hash_bytes

    project, operator, out = (tmp_path / name for name in ("project", "operator", "out"))
    for directory in (project, operator, out):
        directory.mkdir()
    (project / "requirements.txt").write_text("pillow==9.0.0\n")
    feed = operator / "osv.json"
    feed.write_text(
        json.dumps([_record("PYSEC-F5-1", [("pillow", "9.0.1")], aliases=["CVE-2099-55"])])
    )
    inventory, report = out / "inventory.json", operator / "advisories.json"
    bom = _scan(project, feed, inventory)
    (bom_vulnerability,) = CycloneDXGenerator().generate(bom)["vulnerabilities"]
    runner = CliRunner()
    runner.invoke(
        main, ["advisories", str(inventory), "--offline-db", str(feed), "-o", str(report)]
    )
    decision = {
        "id": bom_vulnerability["id"],
        "component_ref": "registry:pypi/pillow",
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "The decoder is never imported.",
        "owner": "security@example.invalid",
        "expires_at": "2030-01-01T00:00:00Z",
        "inventory_sha256": hash_bytes(inventory.read_bytes()),
        "deployment_id": "prod",
    }
    decisions = operator / "decisions.json"
    decisions.write_text(json.dumps({"version": 1, "decisions": [decision]}))
    for linked in (["--advisories", str(report)], []):
        vex = out / "vex.json"
        result = runner.invoke(
            main,
            [
                "vex",
                str(inventory),
                *linked,
                "--decisions",
                str(decisions),
                "--project-root",
                str(project),
                "--deployment-id",
                "prod",
                "-o",
                str(vex),
            ],
        )
        assert result.exit_code == 0, result.output
        listed = [
            (entry["id"], entry["analysis"]["state"])
            for entry in json.loads(vex.read_text())["vulnerabilities"]
            if entry["affects"] == [{"ref": "registry:pypi/pillow"}]
        ]
        assert listed == [(bom_vulnerability["id"], "not_affected")], linked
