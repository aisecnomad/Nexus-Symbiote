"""ShadowScan import: source claims remain untrusted and loss is visible."""

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, TrustTier
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
from nexus_symbiote.validators.completeness import CompletenessValidator
from nexus_symbiote.validators.risk import RiskScorer


def _report():
    return {
        "version": "0.1.4",
        "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
        "stats": [
            {
                "connector": "code.filesystem",
                "errors": [],
                "skipped": False,
                "incomplete": False,
                "declared_omissions": 0,
            }
        ],
        "findings": [
            {
                "id": "agent-CANARY",
                "kind": "agent",
                "surface": "code",
                "title": "CANARY",
                "resource": "CANARY",
                "evidence": [{"snippet": "CANARY"}],
                "risk": {"level": "high"},
                "shadow": True,
            },
            {
                "id": "server",
                "kind": "mcp-server",
                "surface": "endpoint",
                "metadata": {"url": "https://x/CANARY"},
                "risk": {"level": "critical"},
            },
            {"id": "process", "kind": "runtime-process", "surface": "runtime", "title": "CANARY"},
        ],
    }


def test_native_import_has_source_digest_loss_and_no_raw_secrets(tmp_path):
    path = tmp_path / "report.json"
    raw = json.dumps(_report()).encode()
    path.write_bytes(raw)
    imported = ShadowScanImporter().read_report(path)
    assert imported.digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert imported.source_status == "complete"
    assert imported.unmapped_count == 1 and imported.unmapped_indexes == [2]
    assert len(imported.components) == 2
    assert "CANARY" not in repr(imported)
    agent = next(c for c in imported.components if c.component_type == ComponentType.AGENT)
    assert agent.autonomy_level is None
    assert (
        agent.assurance_level == AssuranceLevel.DECLARED and agent.trust_tier == TrustTier.UNKNOWN
    )
    assert not agent.source_path


def test_cli_bom_preserves_uncertainty_and_confines_sensitive_data(tmp_path):
    path, out = tmp_path / "report.json", tmp_path / "bom.json"
    path.write_text(json.dumps(_report()))
    result = CliRunner().invoke(
        main, ["import-shadowscan", str(path), "-o", str(out), "--report-only"]
    )
    assert result.exit_code == 0, result.output
    assert "CANARY" not in out.read_text()
    bom = AIBOM.load(out)
    claim = bom.metadata.completeness
    assert claim.source_unmapped_indexes == [2]
    assert claim.scanner_status == {"shadowscan": "partial"}
    assert not CompletenessValidator().validate(bom).is_complete
    assert not RiskScorer().passes_gate(bom)[0]
    cdx = CycloneDXGenerator().generate(bom)
    assert cdx["compositions"][0]["aggregate"] == "incomplete"
    assert any(
        p["name"] == "nexus-symbiote:discovery:reportSha256" for p in cdx["metadata"]["properties"]
    )
    assert "CANARY" not in json.dumps(cdx)


def test_incomplete_source_writes_partial_bom_and_fails(tmp_path):
    report = _report()
    report["stats"][0]["incomplete"] = True
    path, out = tmp_path / "report.json", tmp_path / "bom.json"
    path.write_text(json.dumps(report))
    result = CliRunner().invoke(main, ["import-shadowscan", str(path), "-o", str(out)])
    assert result.exit_code != 0 and out.exists()
    claim = AIBOM.load(out).metadata.completeness
    assert claim.source_report_status == "incomplete" and claim.scan_failures


def test_baseline_rejects_contradictory_shadowscan_diagnostics(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Review the release.")
    source = project / "shadowscan.json"
    fixture = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
    report = json.loads(fixture.read_bytes())
    source.write_text(json.dumps(report))
    runner = CliRunner()
    assert (
        runner.invoke(main, ["baseline", str(project), "-o", str(tmp_path / "good")]).exit_code == 0
    )
    report["summary"].update(errors=99, incomplete_reasons={"permission-denied": 99})
    source.write_text(json.dumps(report))
    baseline = tmp_path / "bad"
    assert runner.invoke(main, ["baseline", str(project), "-o", str(baseline)]).exit_code == 1
    assert not baseline.exists()
    direct = tmp_path / "direct"
    result = runner.invoke(
        main, ["import-shadowscan", str(source), "-o", str(direct), "--report-only"]
    )
    assert result.exit_code == 1 and not direct.exists()


@pytest.mark.parametrize(
    ("scope", "field", "value"),
    [
        ("summary", "errors", True),
        ("summary", "errors", -1),
        ("summary", "errors", "0"),
        ("summary", "incomplete_reasons", []),
        ("summary", "incomplete_reasons", {"timeout": False}),
        ("summary", "incomplete_reasons", {"timeout": -1}),
        ("stats", "incomplete_reasons", None),
        ("stats", "incomplete_reasons", {"timeout": "1"}),
    ],
)
def test_malformed_shadowscan_diagnostics_cannot_establish_coverage(scope, field, value):
    report = _report()
    (report["summary"] if scope == "summary" else report["stats"][0])[field] = value
    with pytest.raises(ValueError):
        ShadowScanImporter().parse_report(json.dumps(report))


def test_incomplete_reasons_and_error_totals_match_connectors_and_retain_provenance():
    report = _report()
    status = {"errors": ["diagnostic"], "incomplete": True, "incomplete_reasons": {"timeout": 1}}
    report["stats"][0].update(status)
    report["stats"].append({**status, "skipped": False})
    report["summary"].update(
        complete=False, status="incomplete", errors=2, incomplete_reasons={"timeout": 2}
    )
    raw = json.dumps(report).encode()
    bom = ShadowScanImporter().parse_report(raw).to_native_bom()
    assert bom.metadata.completeness.source_report_status == "incomplete"
    assert (
        bom.metadata.completeness.source_report_digest
        == "sha256:" + hashlib.sha256(raw).hexdigest()
    )
    assert all(component.assurance_level == AssuranceLevel.DECLARED for component in bom.components)
    report["summary"]["incomplete_reasons"] = {"other": 2}
    with pytest.raises(ValueError):
        ShadowScanImporter().parse_report(json.dumps(report))


def test_connector_reasons_prevent_complete_status_even_without_summary_diagnostics():
    report = _report()
    report["stats"][0]["incomplete_reasons"] = {"timeout": 1}
    assert ShadowScanImporter().parse_report(json.dumps(report)).source_status == "incomplete"


def test_source_cannot_be_overwritten(tmp_path):
    path = tmp_path / "report.json"
    original = json.dumps(_report())
    path.write_text(original)
    result = CliRunner().invoke(main, ["import-shadowscan", str(path), "-o", str(path)])
    assert result.exit_code != 0 and path.read_text() == original


def test_verify_discovery_checks_exact_bytes_without_claiming_authenticity(tmp_path):
    report, bom = tmp_path / "report.json", tmp_path / "bom.json"
    report.write_text(json.dumps(_report()))
    runner = CliRunner()
    assert (
        runner.invoke(
            main, ["import-shadowscan", str(report), "-o", str(bom), "--report-only"]
        ).exit_code
        == 0
    )
    result = runner.invoke(main, ["verify-discovery", str(bom), str(report)])
    assert result.exit_code == 0
    assert "Source identity, signature, and truth were not verified" in result.output
    report.write_text(report.read_text() + " ")
    result = runner.invoke(main, ["verify-discovery", str(bom), str(report)])
    assert result.exit_code != 0 and "digest mismatch" in result.output


def test_verify_discovery_rejects_missing_digest(tmp_path):
    report, bom = tmp_path / "report.json", tmp_path / "bom.json"
    report.write_text(json.dumps(_report()))
    bom.write_text(AIBOM().to_json())
    result = CliRunner().invoke(main, ["verify-discovery", str(bom), str(report)])
    assert result.exit_code != 0 and "valid ShadowScan report digest" in result.output


def test_verify_artifact_checks_confined_bytes(tmp_path):
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"test artifact")
    digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    runner = CliRunner()
    result = runner.invoke(
        main, ["verify-artifact", "model.bin", "--project", str(tmp_path), "--sha256", digest]
    )
    assert result.exit_code == 0
    assert "Signer, artifact safety, and deployment binding were not verified" in result.output
    artifact.write_bytes(b"changed")
    result = runner.invoke(
        main, ["verify-artifact", "model.bin", "--project", str(tmp_path), "--sha256", digest]
    )
    assert result.exit_code != 0 and "digest mismatch" in result.output
    result = runner.invoke(
        main, ["verify-artifact", "../outside", "--project", str(tmp_path), "--sha256", digest]
    )
    assert result.exit_code != 0


def test_verify_artifact_signature_policy_is_required(tmp_path, monkeypatch):
    from nexus_symbiote.utils.crypto import VerificationResult

    artifact, bundle = tmp_path / "model.bin", tmp_path / "bundle.json"
    artifact.write_bytes(b"artifact")
    bundle.write_text("{}")
    digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    args = [
        "verify-artifact",
        "model.bin",
        "--project",
        str(tmp_path),
        "--sha256",
        digest,
        "--bundle",
        str(bundle),
    ]
    runner = CliRunner()
    assert runner.invoke(main, args).exit_code != 0
    calls = []

    def verify(actual_digest, content, identity, issuer):
        calls.append((actual_digest, content, identity, issuer))
        return VerificationResult(True)

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_digest", verify)
    result = runner.invoke(main, args + ["--signer-identity", "signer", "--issuer", "issuer"])
    assert result.exit_code == 0 and calls == [(digest, b"{}", "signer", "issuer")]
    assert "does not establish artifact safety" in result.output


@pytest.mark.parametrize("fmt", ["sarif"])
def test_lossy_outputs_fail_closed(tmp_path, fmt):
    path, out = tmp_path / "report.json", tmp_path / "bom.json"
    path.write_text(json.dumps(_report()))
    result = CliRunner().invoke(main, ["import-shadowscan", str(path), "-f", fmt, "-o", str(out)])
    assert result.exit_code != 0 and not out.exists()
    assert "cannot preserve imported discovery coverage" in result.output


@pytest.mark.parametrize("content", ['{"version":"a","version":"b"}', '{"x":NaN}', "[]"])
def test_bad_or_duplicate_json_is_rejected(tmp_path, content):
    path = tmp_path / "report.json"
    path.write_text(content)
    with pytest.raises(ValueError):
        ShadowScanImporter().read_report(path)


def test_duplicate_ids_rejected(tmp_path):
    report = _report()
    report["findings"][1]["id"] = report["findings"][0]["id"]
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="duplicate"):
        ShadowScanImporter().read_report(path)


def test_cyclonedx_services_and_unknown_composition_are_not_ignored(tmp_path):
    report = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"properties": [{"name": "shadowscan:scan:status", "value": "complete"}]},
        "components": [],
        "services": [{"bom-ref": "ss-service", "group": "mcp-server", "name": "CANARY"}],
        "compositions": [{"aggregate": "unknown"}, {"aggregate": "incomplete"}],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    imported = ShadowScanImporter().read_report(path)
    assert imported.source_status == "complete"
    assert any("incomplete composition" in item for item in imported.limitations)
    assert imported.components[0].component_type == ComponentType.MCP_SERVER
    assert "CANARY" not in repr(imported)


def test_conventional_scan_carries_source_fingerprint(tmp_path):
    directory = tmp_path / ".shadowscan"
    directory.mkdir()
    path, out = directory / "report.json", tmp_path / "bom.json"
    path.write_text(json.dumps(_report()))
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--scanner", "shadowscan", "-o", str(out), "--report-only"]
    )
    assert result.exit_code == 0, result.output
    claim = AIBOM.load(out).metadata.completeness
    assert claim.source_report_digest == "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    assert claim.scanner_status["shadowscan"] == "partial"


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_portable_import_preserves_native_coverage_and_provenance(tmp_path, fmt):
    from nexus_symbiote.generators.spdx import SPDXGenerator

    source, output = tmp_path / "report.json", tmp_path / "export.json"
    raw = json.dumps(_report(), ensure_ascii=False, indent=2).replace("\n", "\r\n").encode()
    source.write_bytes(raw)
    result = CliRunner().invoke(
        main,
        [
            "import-shadowscan",
            str(source),
            "-f",
            fmt,
            "-o",
            str(output),
            "--report-only",
        ],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(output.read_text())
    generator = CycloneDXGenerator if fmt == "cyclonedx" else SPDXGenerator
    recovered = generator.recover(document)
    claim = recovered.metadata.completeness
    assert claim.source_report_digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert claim.source_unmapped_indexes == [2]
    assert claim.scanner_status == {"shadowscan": "partial"}
    assert claim.surfaces_excluded
    if fmt == "cyclonedx":
        assert document["compositions"] == [{"aggregate": "incomplete"}]


def test_bare_findings_do_not_claim_report_coverage(tmp_path):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(_report()["findings"]))
    with pytest.raises(ValueError, match="report object"):
        ShadowScanImporter().read_report(source)


def test_imported_findings_do_not_create_local_artifact_or_dependency_claims(tmp_path):
    source = tmp_path / "shadowscan.json"
    source.write_text(json.dumps(_report()))
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--scanner",
            "shadowscan",
            "-o",
            str(out),
            "--report-only",
        ],
    )
    assert result.exit_code == 0, result.output
    bom = AIBOM.load(out)
    imported = [c for c in bom.components if c.bom_ref.startswith("shadowscan:")]
    assert imported
    for component in imported:
        assert "repository_presence" not in component.claims
        assert component.claims["discovery_report_entry"].assurance == AssuranceLevel.DECLARED
        assert not component.source_path
    imported_refs = {c.bom_ref for c in imported}
    assert not any(e.target_ref in imported_refs for e in bom.dependencies)


def test_complete_source_import_cannot_pass_inventory_gate(tmp_path):
    source, output = tmp_path / "report.json", tmp_path / "bom.json"
    source.write_text(json.dumps(_report()))
    result = CliRunner().invoke(main, ["import-shadowscan", str(source), "-o", str(output)])
    assert result.exit_code != 0
    assert output.exists()
    assert not RiskScorer().passes_gate(AIBOM.load(output))[0]


@pytest.mark.parametrize("use_parent", [False, True])
def test_import_ignores_supplier_policy(tmp_path, use_parent):
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    report = incoming / "report.json"
    report.write_text(json.dumps(_report()))
    policy_dir = tmp_path if use_parent else incoming
    (policy_dir / ".nexus-symbiote.yaml").write_text("scan: {failure_mode: report-only}\n")
    runner = CliRunner()
    output = tmp_path / "gated.json"
    args = ["import-shadowscan", str(report), "-o"]
    gated = runner.invoke(main, [*args, str(output)])
    assert gated.exit_code == 1 and "Imported claims" in gated.output
    exploratory = tmp_path / "exploratory.json"
    result = runner.invoke(main, [*args, str(exploratory), "--report-only"])
    assert result.exit_code == 0, result.output
    for path in (output, exploratory):
        inventory = AIBOM.load(path)
        assert RiskScorer().score(inventory).severity_counts["critical"] > 0


def test_verify_direct_projection_rejects_copied_digest_and_ignored_fields(tmp_path):
    report, target = tmp_path / "report.json", tmp_path / "bom.json"
    # Include CRLF so a reader normalizing newlines would fail the digest check.
    report.write_bytes(json.dumps(_report(), indent=2).replace("\n", "\r\n").encode())
    runner = CliRunner()
    assert (
        runner.invoke(
            main, ["import-shadowscan", str(report), "-o", str(target), "--report-only"]
        ).exit_code
        == 0
    )
    original = target.read_text()
    args = ["verify-discovery", str(target), str(report), "--projection"]
    assert runner.invoke(main, args).exit_code == 0
    for change in ("component", "coverage", "relationship", "unknown"):
        doc = json.loads(original)
        if change == "component":
            doc["components"][0]["assurance_level"] = "observed"
        elif change == "coverage":
            doc["metadata"]["completeness"]["source_unmapped_count"] = 0
        elif change == "relationship":
            ref = doc["components"][0]["bom_ref"]
            doc["dependencies"].append(
                {"source_ref": ref, "target_ref": ref, "relationship": "approved-under"}
            )
        else:
            doc["components"][0]["permission_granted"] = True
        target.write_text(json.dumps(doc))
        failed = runner.invoke(main, args)
        assert failed.exit_code != 0, change


def test_report_signer_is_external_policy_and_applies_to_exact_report(tmp_path, monkeypatch):
    from nexus_symbiote.utils.crypto import VerificationResult

    report, target, bundle = (tmp_path / n for n in ("report.json", "bom.json", "bundle.json"))
    report.write_text(json.dumps(_report()))
    expected = "sha256:" + hashlib.sha256(report.read_bytes()).hexdigest()
    bundle.write_bytes(b"test-bundle")
    runner = CliRunner()
    assert (
        runner.invoke(
            main, ["import-shadowscan", str(report), "-o", str(target), "--report-only"]
        ).exit_code
        == 0
    )
    cmd = ["verify-discovery", str(target), str(report)]
    for partial in (
        ["--bundle", str(bundle)],
        ["--issuer", "authority"],
        ["--signer-identity", "operator"],
    ):
        assert runner.invoke(main, cmd + partial).exit_code != 0

    calls = []

    def check(digest, payload, signer, issuer):
        calls.append((digest, payload, signer, issuer))
        return VerificationResult(calls[-1] == (expected, b"test-bundle", "operator", "authority"))

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_digest", check)
    signed = cmd + [
        "--bundle",
        str(bundle),
        "--signer-identity",
        "operator",
        "--issuer",
        "authority",
    ]
    assert runner.invoke(main, signed).exit_code == 0 and len(calls) == 1
    assert runner.invoke(main, signed[:-1] + ["wrong-issuer"]).exit_code != 0
    assert (
        runner.invoke(main, [("someone-else" if v == "operator" else v) for v in signed]).exit_code
        != 0
    )
    doc = json.loads(target.read_text())
    doc["components"] = []
    target.write_text(json.dumps(doc))
    assert runner.invoke(main, signed).exit_code != 0 and len(calls) == 3


def test_offline_production_sigstore_policy_on_upstream_release_fixture():
    from pathlib import Path

    pytest.importorskip("sigstore")
    from nexus_symbiote.utils.crypto import verify_sigstore_digest

    # Official sigstore-python release fixture. The expected identity and digest
    # below are independent policy inputs, never extracted from the bundle.
    path = Path(__file__).parent / "fixtures/sigstore-python/bundle_v3_github.whl.sigstore"
    digest = "sha256:c4e92e9ecc828bef2aa7dba1de8ac983511f7532a0df11c770d39099a25cf201"
    signer = (
        "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
    )
    issuer = "https://token.actions.githubusercontent.com"
    data = path.read_bytes()
    assert verify_sigstore_digest(digest, data, signer, issuer).verified
    assert not verify_sigstore_digest(digest, data, "wrong-identity", issuer).verified
    assert not verify_sigstore_digest(digest, data, signer, "https://wrong.invalid").verified
    assert not verify_sigstore_digest("sha256:" + "0" * 64, data, signer, issuer).verified


def test_spdx_ai_and_dataset_license_relationship_cardinality():
    from nexus_symbiote.core.models import ModelComponent, RAGSourceComponent
    from nexus_symbiote.generators.spdx import NO_ASSERTION_LICENSE, SPDXGenerator

    bom = AIBOM(
        components=[
            ModelComponent(bom_ref="model:m", name="model"),
            RAGSourceComponent(bom_ref="data:d", name="data"),
        ]
    )
    graph = SPDXGenerator().generate(bom)["@graph"]
    packages = [n for n in graph if n["type"] in {"ai_AIPackage", "dataset_DatasetPackage"}]
    assert len(packages) == 2
    for package in packages:
        for kind in ("hasDeclaredLicense", "hasConcludedLicense"):
            matches = [
                n
                for n in graph
                if n.get("from") == package["spdxId"] and n.get("relationshipType") == kind
            ]
            assert len(matches) == 1
            assert matches[0]["to"] == [NO_ASSERTION_LICENSE]


def test_spdx_license_validation_rejects_omitted_duplicate_or_forged_target():
    import copy

    from nexus_symbiote.core.models import ModelComponent
    from nexus_symbiote.generators.spdx import SPDXGenerator
    from nexus_symbiote.generators.validation import validate_spdx

    document = SPDXGenerator().generate(AIBOM(components=[ModelComponent(bom_ref="m", name="m")]))
    index = next(
        i
        for i, n in enumerate(document["@graph"])
        if n.get("relationshipType") == "hasDeclaredLicense"
    )
    missing = copy.deepcopy(document)
    relation = missing["@graph"].pop(index)
    missing["@graph"][0]["element"].remove(relation["spdxId"])
    assert any("requires exactly one" in e for e in validate_spdx(missing))
    forged = copy.deepcopy(document)
    forged["@graph"][index]["to"] = ["https://malicious.invalid/license"]
    assert any("unresolved" in e for e in validate_spdx(forged))
    duplicate = copy.deepcopy(document)
    relation = copy.deepcopy(duplicate["@graph"][index])
    relation["spdxId"] += "/duplicate"
    duplicate["@graph"].append(relation)
    duplicate["@graph"][0]["element"].append(relation["spdxId"])
    assert any("requires exactly one" in e for e in validate_spdx(duplicate))
