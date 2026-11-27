"""Coverage and provenance for an explicitly selected offline advisory bundle."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.canonical import json_text
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import AIBOMMetadata, CompletenessClaim, RegistryEntryComponent
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.scan_advisories import ADVISORY_SURFACE_PREFIX


def _clean_bundle(path: Path, identifier: str = "SYNTHETIC-OSV-1") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "id": identifier,
        "modified": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "other-fixture"}, "versions": ["1"]}
        ],
    }
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _scan(project: Path, feed: Path, output: Path, *, fmt: str = "json") -> dict:
    response = CliRunner().invoke(
        main,
        [
            "--offline",
            "scan",
            str(project),
            "--all-packages",
            "--advisory-db",
            str(feed),
            "-f",
            fmt,
            "-o",
            str(output),
        ],
    )
    assert response.exit_code == 0, response.output
    return json.loads(output.read_text(encoding="utf-8"))


def _receipt(document: dict, field: str) -> dict:
    claim = document["metadata"]["completeness"]
    (receipt,) = (row for row in claim[field] if row.startswith(ADVISORY_SURFACE_PREFIX))
    return json.loads(receipt.removeprefix(ADVISORY_SURFACE_PREFIX))


def test_receipt_scopes_complete_coverage_to_inventoried_packages(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manifest = {"name": "project", "dependencies": {"direct-package": "1.0.0"}}
    (project / "package.json").write_text(json.dumps(manifest))
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": manifest,
            "node_modules/direct-package": {
                "version": "1.0.0",
                "dependencies": {"transitive-package": "2.0.0"},
            },
            "node_modules/transitive-package": {"version": "2.0.0"},
        },
    }
    (project / "package-lock.json").write_text(json.dumps(lock))
    feed = tmp_path / "advisory.json"
    feed.write_text(
        json.dumps(
            {
                "id": "SYNTHETIC-NPM-1",
                "modified": datetime.now(UTC).isoformat(),
                "affected": [
                    {"package": {"ecosystem": "npm", "name": name}, "versions": [version]}
                    for name, version in (
                        ("direct-package", "1.0.0"),
                        ("transitive-package", "2.0.0"),
                    )
                ],
            }
        )
    )
    native = _scan(project, feed, tmp_path / "inventory.json")
    packages = [entry for entry in native["components"] if entry.get("registry_type") == "npm"]
    assert [package["name"] for package in packages] == ["direct-package"]
    assert packages[0]["properties"]["advisories"][0]["id"] == "SYNTHETIC-NPM-1"
    receipt = _receipt(native, "surfaces_scanned")
    assert receipt["coverage"] == "complete"
    assert receipt["components_checked"] == receipt["advisories_recorded"] == 1
    assert receipt["scope"] == "inventoried-pypi-and-npm"
    assert receipt["registry_lockfile_only_dependencies"] == "not-collected"


def test_clean_reports_bind_feed_bytes_without_its_path(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("synthetic-package==1\n", encoding="utf-8")
    left = _clean_bundle(tmp_path / "operator-a" / "operator-filename.json")
    right = _clean_bundle(tmp_path / "operator-b" / left.name, "SYNTHETIC-OSV-2")
    one = _scan(project, left, tmp_path / "one.json")
    two = _scan(project, right, tmp_path / "two.json")
    first = _receipt(one, "surfaces_scanned")
    second = _receipt(two, "surfaces_scanned")
    assert first["coverage"] == second["coverage"] == "complete"
    assert first["components_checked"] == second["components_checked"] == 1
    assert first["db_sha256"] == hash_bytes(left.read_bytes())
    assert second["db_sha256"] == hash_bytes(right.read_bytes())
    assert first["db_sha256"] != second["db_sha256"]
    assert left.name not in json.dumps(one)
    assert not any(row.get("properties", {}).get("advisories") for row in one["components"])


@pytest.mark.parametrize("requirements", ["", "synthetic-package==1\n"])
def test_advisory_coverage_round_trips_to_cyclonedx(tmp_path: Path, requirements: str) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "review.prompt.md").write_text("Review the change.\n", encoding="utf-8")
    if requirements:
        (project / "requirements.txt").write_text(requirements, encoding="utf-8")
    feed = _clean_bundle(tmp_path / "operator" / "bundle.json")
    native = _scan(project, feed, tmp_path / "native.json")
    applicable_field = "surfaces_scanned" if requirements else "unobserved_surfaces"
    expected = _receipt(native, applicable_field)
    assert expected["coverage"] == ("complete" if requirements else "none")
    assert expected["components_checked"] == int(bool(requirements))
    assert expected["db_sha256"] == hash_bytes(feed.read_bytes())
    if not requirements:
        assert not any(
            surface.startswith(ADVISORY_SURFACE_PREFIX)
            for surface in native["metadata"]["completeness"]["surfaces_scanned"]
        )
    cdx = _scan(project, feed, tmp_path / "cdx.json", fmt="cyclonedx")
    (property_,) = (
        row
        for row in cdx["metadata"]["properties"]
        if row["name"] == "nexus-symbiote:advisories:collection"
    )
    assert json.loads(property_["value"]) == expected
    assert not cdx.get("vulnerabilities")
    assert _receipt(CycloneDXGenerator().recover(cdx).to_dict(), applicable_field) == expected


@pytest.mark.parametrize("aliases", [None, "unexpected-string", [False, ""]])
def test_cyclonedx_ignores_invalid_aliases_from_native_extensions(
    tmp_path: Path, aliases: object
) -> None:
    digest = hash_bytes(b"synthetic advisory bundle")
    package = RegistryEntryComponent(
        bom_ref="vulnerability:SYNTHETIC-OSV-1",
        name="synthetic-package",
        properties={
            "advisories": [
                {
                    "id": "SYNTHETIC-OSV-1",
                    "aliases": aliases,
                    "source": "osv-offline",
                    "db_sha256": digest,
                },
                {"id": "invalid/identifier", "source": "osv-offline", "db_sha256": digest},
            ]
        },
    )
    receipt = ADVISORY_SURFACE_PREFIX + json_text({"coverage": "complete", "db_sha256": digest})
    metadata = AIBOMMetadata(
        completeness=CompletenessClaim(scope="repository", surfaces_scanned=[receipt])
    )
    path = tmp_path / "native.json"
    path.write_text(
        json.dumps(AIBOM(components=[package], metadata=metadata).to_dict()), encoding="utf-8"
    )

    output = tmp_path / "cdx.json"
    result = CliRunner().invoke(
        main, ["export-standard", str(path), "--format", "cyclonedx", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    (finding,) = json.loads(output.read_text(encoding="utf-8"))["vulnerabilities"]
    assert "references" not in finding
    assert "bom-ref" not in finding
    assert finding["affects"] == [{"ref": package.bom_ref}]


def test_unrelated_advisory_extension_keeps_legacy_cyclonedx_projection() -> None:
    package = RegistryEntryComponent(
        bom_ref="registry:pypi/synthetic-pkg",
        name="synthetic-pkg",
        properties={"advisories": [{"id": "CUSTOM-1", "source": "custom"}]},
    )
    bom = AIBOM(components=[package])
    exporter = CycloneDXGenerator()
    document = exporter.generate(bom)
    assert "vulnerabilities" not in document
    assert exporter.recover(document).components[0].properties == package.properties


def test_advisory_bundle_parent_symlink_is_refused(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("synthetic-package==1\n", encoding="utf-8")
    feed = _clean_bundle(tmp_path / "operator" / "feed.json")
    redirected = tmp_path / "redirected"
    redirected.symlink_to(feed.parent, target_is_directory=True)
    output = tmp_path / "native.json"
    response = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--all-packages",
            "--advisory-db",
            str(redirected / feed.name),
            "-o",
            str(output),
        ],
    )
    assert response.exit_code == 1, response.output
    claim = json.loads(output.read_text(encoding="utf-8"))["metadata"]["completeness"]
    assert any(failure.startswith("advisories:") for failure in claim["scan_failures"])
    assert not any(
        surface.startswith(ADVISORY_SURFACE_PREFIX) for surface in claim["surfaces_scanned"]
    )
