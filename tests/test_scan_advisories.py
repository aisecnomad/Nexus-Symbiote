"""Scan-time offline advisories, the all-packages registry mode and CycloneDX vulnerabilities."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import A2AServerComponent, CapabilityDeclaration
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
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
