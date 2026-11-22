"""Follow-ups to ARCH-F1: report locations, SPDX ``created`` and verification drift."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.aibom import AIBOM, prepare
from nexus_symbiote.core.models import (
    AgentComponent,
    CompletenessClaim,
    DiscoveryVerification,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.generators.spdx import SPDXGenerator, _without_created
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

REPORT = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
DIGEST = "sha256:" + "ab" * 32


def _bom(claim: CompletenessClaim | None = None) -> AIBOM:
    bom = AIBOM()
    bom.add_component(AgentComponent(bom_ref="agent:main", name="main"))
    bom.metadata.completeness = claim
    return bom


def test_import_without_a_root_records_only_the_file_name(tmp_path: Path) -> None:
    report = tmp_path / "operator" / "secret-dir" / "report.json"
    report.parent.mkdir(parents=True)
    shutil.copyfile(REPORT, report)
    imported = ShadowScanImporter().read_report(report)
    assert imported.source_path == "report.json"
    claim = imported.to_native_bom().metadata.completeness
    assert claim is not None
    assert claim.source_report_path == "report.json"
    assert str(tmp_path) not in imported.to_native_bom().to_json()


def test_import_under_a_root_records_a_relative_posix_path(tmp_path: Path) -> None:
    report = tmp_path / "project" / "reports" / "shadowscan.json"
    report.parent.mkdir(parents=True)
    shutil.copyfile(REPORT, report)
    imported = ShadowScanImporter().read_report(report, tmp_path / "project")
    assert imported.source_path == "reports/shadowscan.json"
    outside = ShadowScanImporter().read_report(report, tmp_path / "elsewhere")
    assert outside.source_path == "shadowscan.json"


def test_serial_ignores_the_report_location() -> None:
    here = _bom(CompletenessClaim(scope="shadowscan-imported", source_report_path="a.json"))
    there = _bom(CompletenessClaim(scope="shadowscan-imported", source_report_path="other/b.json"))
    prepare(here)
    prepare(there)
    assert here.metadata.serial_number == there.metadata.serial_number


def _creation_nodes(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [node for node in document["@graph"] if node.get("type") == "CreationInfo"]


def test_spdx_recovery_requires_the_native_timestamp() -> None:
    bom = _bom()
    bom.metadata.timestamp = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    document = json.loads(SPDXGenerator().generate_json(bom))
    SPDXGenerator.recover(json.loads(json.dumps(document)))
    for node in _creation_nodes(document):
        node["created"] = "2030-01-01T00:00:00Z"
    with pytest.raises(ValueError, match="conflicts with the embedded native document"):
        SPDXGenerator.recover(document)


def test_spdx_recovery_without_a_native_timestamp_ignores_only_creation_info() -> None:
    document = json.loads(SPDXGenerator().generate_json(_bom()))
    for node in _creation_nodes(document):
        node["created"] = "2030-01-01T00:00:00Z"
    SPDXGenerator.recover(json.loads(json.dumps(document)))
    tool = {"type": "Tool", "created": "2030-01-01T00:00:00Z"}
    assert _without_created({"@graph": [tool]}) == {"@graph": [tool]}
    for node in document["@graph"]:
        if node.get("type") == "Tool":
            node["name"] = "another-generator"
    with pytest.raises(ValueError, match="conflicts with the embedded native document"):
        SPDXGenerator.recover(document)


def _claim(record: DiscoveryVerification | None, path: str | None = None) -> CompletenessClaim:
    return CompletenessClaim(
        scope="repository", discovery_verification=record, source_report_path=path
    )


def _verification_changes(old: CompletenessClaim, new: CompletenessClaim) -> list[str]:
    report = AIBOMDiffer().diff(_bom(old), _bom(new))
    alerts = [alert["alert"] for alert in report.security_alerts]
    assert not any("Completeness field" in alert for alert in alerts)
    return [
        f"{change['severity']}:{change['detail']}"
        for change in report.metadata_changes
        if change["field"]
        in ("completeness.discovery_verification", "completeness.source_report_path")
    ]


def test_baseline_without_a_record_is_not_a_verification_change() -> None:
    not_applicable = DiscoveryVerification(status="not-applicable")
    assert _verification_changes(_claim(None), _claim(not_applicable)) == []
    unverified = DiscoveryVerification(status="unverified", report_digest=DIGEST)
    assert _verification_changes(_claim(None), _claim(unverified, "r.json")) == []


def test_losing_verification_alerts() -> None:
    verified = DiscoveryVerification(
        status="verified",
        method="sigstore",
        report_digest=DIGEST,
        signer_identity="https://example.test/signer",
        issuer="https://issuer.example.test",
    )
    unverified = DiscoveryVerification(status="unverified", report_digest=DIGEST)
    lost = "high:ShadowScan discovery evidence is no longer signature-verified."
    assert _verification_changes(_claim(verified), _claim(unverified)) == [lost]
    assert _verification_changes(_claim(verified), _claim(None)) == [lost]
    gained = (
        "info:ShadowScan discovery evidence is now signature-verified (signer "
        "https://example.test/signer, issuer https://issuer.example.test)."
    )
    assert _verification_changes(_claim(None), _claim(verified)) == [gained]
    resigned = verified.model_copy(update={"signer_identity": "https://example.test/other"})
    assert _verification_changes(_claim(verified), _claim(resigned)) == [
        "high:ShadowScan discovery evidence is now signed by a different identity or issuer."
    ]
    rerun = verified.model_copy(update={"report_digest": "sha256:" + "cd" * 32})
    assert _verification_changes(_claim(verified), _claim(rerun)) == []
