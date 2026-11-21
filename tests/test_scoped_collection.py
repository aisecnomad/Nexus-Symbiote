"""End-to-end static coverage and imported-evidence gates."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, TrustTier
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.validators.risk import RiskScorer

# Unmodified JSON from "shadowscan code <repo> --format json" on a synthetic
# LangChain project with an MCP server, using Nexus-ShadowScan 1a821e5763e9.
REPORT = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"


@pytest.mark.parametrize("report_only", [False, True])
def test_empty_repository_has_no_local_baseline_subject(tmp_path, report_only):
    root = tmp_path / "empty"
    root.mkdir()
    if report_only:
        shutil.copyfile(REPORT, root / "shadowscan.json")
    snapshot = tmp_path / "snapshot.json"
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(root), "-o", str(snapshot)])
    assert result.exit_code == 1, result.output
    bom = AIBOM.load(snapshot)
    assert set(bom.metadata.completeness.scanner_status.values()) == {"complete"}
    passed, risk = RiskScorer().passes_gate(bom)
    assert not passed
    assert "no agent manifest or supported local inventory evidence was found" in risk.gate_reasons
    baseline = tmp_path / "baseline.json"
    assert runner.invoke(main, ["baseline", str(root), "-o", str(baseline)]).exit_code == 1
    assert not baseline.exists()


def test_default_baseline_with_no_external_report(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()
    (root / "agent.yaml").write_text("name: Demo\ninstructions: [CLAUDE.md]\n")
    (root / "CLAUDE.md").write_text("Use the configured tools.")
    output = tmp_path / "baseline.json"
    runner = CliRunner()
    result = runner.invoke(main, ["baseline", str(root), "-o", str(output)])
    assert result.exit_code == 0, result.output
    claim = AIBOM.load(output).metadata.completeness
    assert claim.scope == "repository"
    assert not claim.scan_failures and not claim.surfaces_excluded
    assert set(claim.scanner_status.values()) == {"complete"}
    assert "shadowscan-report (no report found)" in claim.surfaces_scanned
    assert {"**/.git", "**/venv", "**/.venv"} <= set(claim.exclusions)
    assert "runtime" in claim.unobserved_surfaces
    result = runner.invoke(main, ["validate", str(output), "--project", str(root)])
    assert result.exit_code == 0, result.output


def test_scoped_model_baseline_does_not_verify_an_unsigned_artifact(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    header = b'{"weight":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}'
    header += b" " * (-len(header) % 8)
    model = root / "weights.safetensors"
    model.write_bytes(len(header).to_bytes(8, "little") + header + b"abcd")
    output = tmp_path / "baseline.json"
    runner = CliRunner()
    result = runner.invoke(main, ["baseline", str(root), "-o", str(output)])
    assert result.exit_code == 0, result.output
    result = runner.invoke(main, ["validate", str(output), "--project", str(root)])
    assert result.exit_code == 1, result.output
    assert "No trusted artifact-bound signer policy" in result.output


def test_complete_producer_report_preserves_partial_projection(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "agent.yaml").write_text("name: Local agent\ninstructions: [protocol.txt]\n")
    (root / "protocol.txt").write_text("Use the declared tools.")
    report = root / "shadowscan.json"
    shutil.copyfile(REPORT, report)
    runner = CliRunner()
    output = tmp_path / "baseline.json"
    result = runner.invoke(main, ["baseline", str(root), "-o", str(output)])
    assert result.exit_code == 0, result.output
    bom = AIBOM.load(output)
    claim = bom.metadata.completeness
    assert claim.scope == "repository+shadowscan"
    assert claim.scanner_status["shadowscan"] == "complete"
    assert claim.source_report_digest == "sha256:" + hashlib.sha256(report.read_bytes()).hexdigest()
    assert claim.source_report_status == "complete" and not claim.source_unmapped_count
    assert claim.source_projection_limitations
    verified = runner.invoke(
        main,
        [
            "validate",
            str(output),
            "--project",
            str(root),
            "--no-project-policy",
            "--allow-unsigned-discovery",
        ],
    )
    assert verified.exit_code == 0, verified.output
    assets = [c for c in bom.components if c.bom_ref.startswith("shadowscan:")]
    assert len(assets) == 2
    assert all(c.assurance_level == AssuranceLevel.DECLARED for c in assets)
    assert all(c.trust_tier == TrustTier.UNKNOWN for c in assets)
    assert not any(e.target_ref in {c.bom_ref for c in assets} for e in bom.dependencies)
    exported = CycloneDXGenerator().generate(bom)
    assert [c["aggregate"] for c in exported["compositions"]] == ["incomplete"]
    assert CycloneDXGenerator.recover(exported).metadata.completeness == claim
    direct = tmp_path / "direct.json"
    result = runner.invoke(main, ["import-shadowscan", str(report), "-o", str(direct)])
    assert result.exit_code == 1, result.output
    assert AIBOM.load(direct).metadata.completeness.scanner_status == {"shadowscan": "partial"}


@pytest.mark.parametrize("gap", ["incomplete", "unmapped", "cyclonedx", "custom-exclusion"])
def test_repository_baseline_refuses_actual_collection_gaps(tmp_path, gap):
    root = tmp_path / "project"
    root.mkdir()
    (root / "agent.yaml").write_text("name: Local agent\ninstructions: [protocol.txt]\n")
    (root / "protocol.txt").write_text("Use the declared tools.")
    raw = json.loads(REPORT.read_bytes())
    report = root / "shadowscan.json"
    report.write_text(json.dumps(raw))
    runner = CliRunner()
    control = tmp_path / "control.json"
    result = runner.invoke(main, ["baseline", str(root), "-o", str(control)])
    assert result.exit_code == 0, result.output
    claim = AIBOM.load(control).metadata.completeness
    assert not claim.scan_failures and not claim.surfaces_excluded
    if gap == "incomplete":
        raw["stats"][0]["incomplete"] = True
    elif gap == "unmapped":
        raw["findings"][0]["kind"] = "runtime-process"
        raw["summary"]["by_kind"] = {"runtime-process": 1, "agent": 1}
    elif gap == "cyclonedx":
        raw = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"properties": [{"name": "shadowscan:scan:status", "value": "complete"}]},
        }
    else:
        (root / ".nexus-symbiote.yaml").write_text("scan: {exclude_paths: [hidden]}")
        (root / "hidden").mkdir()
        (root / "hidden/weights.pkl").write_bytes(b"unexamined")
    report.write_text(json.dumps(raw))
    observed = tmp_path / "observed.json"
    accept = ["--accept-project-policy"] if gap == "custom-exclusion" else []
    result = runner.invoke(main, ["scan", str(root), "--report-only", "-o", str(observed), *accept])
    assert result.exit_code == 0, result.output
    bom = AIBOM.load(observed)
    claim = bom.metadata.completeness
    passed, risk = RiskScorer().passes_gate(bom)
    assert not passed
    assert (
        "no agent manifest or supported local inventory evidence was found" not in risk.gate_reasons
    )
    if gap == "incomplete":
        assert claim.source_report_status == "incomplete"
        assert "ShadowScan source report is incomplete or has unknown status" in claim.scan_failures
    elif gap == "unmapped":
        assert claim.source_unmapped_count == 1
        assert claim.source_unmapped_indexes == [0]
        assert (
            "ShadowScan report contains unmapped entries: runtime-process"
            in claim.surfaces_excluded
        )
    elif gap == "cyclonedx":
        assert "ShadowScan CycloneDX source is a lossy projection" in claim.surfaces_excluded
    else:
        assert "hidden" in claim.exclusions
        assert "hidden: excluded by collection policy" in claim.surfaces_excluded
    if gap != "incomplete":
        assert claim.source_report_status == "complete"
        assert not claim.scan_failures
    destination = tmp_path / "baseline.json"
    result = runner.invoke(main, ["baseline", str(root), "-o", str(destination), *accept])
    assert result.exit_code == 1, result.output
    assert not destination.exists()
