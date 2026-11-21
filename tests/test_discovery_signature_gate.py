"""CI can require that a merged BOM's ShadowScan evidence comes from a signed report.

The gate never trusts the BOM: it re-reads the report beneath the project root,
requires the recorded exact-byte digest, and verifies the operator-selected
Sigstore bundle over those bytes.
"""

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.policy import Policy
from nexus_symbiote.utils.crypto import SIGSTORE_MISSING, VerificationResult
from nexus_symbiote.validators.completeness import (
    discovery_producer_check,
    discovery_producer_problems,
)

FIXTURES = Path(__file__).parent / "fixtures"
REPORT = FIXTURES / "shadowscan/code-report-0.1.4.json"
UPSTREAM_BUNDLE = FIXTURES / "sigstore-python/bundle_v3_github.whl.sigstore"
IDENTITY = "https://github.com/acme/discovery/.github/workflows/scan.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
GATED = "validate: {require_integrity: false, require_discovery_signature: true}\n"
UNGATED = "validate: {require_integrity: false}\n"
# Only the producer check guards the evidence when the gated project switches completeness off.
UNCHECKED = (
    "validate: {require_completeness: false, require_integrity: false,"
    " require_discovery_signature: true}\n"
)


def _project(tmp_path: Path, policy: str) -> tuple[Path, Path]:
    project, bom = tmp_path / "proj", tmp_path / "bom.json"
    (project / ".shadowscan").mkdir(parents=True)
    shutil.copy(REPORT, project / ".shadowscan/report.json")
    (project / ".shadowscan/report.sigstore.json").write_text("{}")
    # risk --project needs a local subject besides the imported discovery evidence.
    server = {"command": "npx", "args": ["-y", "@acme/payments-mcp@1.2.3"]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"payments": server}}))
    CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(bom)])
    assert bom.is_file()
    (project / ".nexus-symbiote.yaml").write_text(policy)
    return project, bom


def _signers(
    tmp_path: Path, identity: str = IDENTITY, artifact: str = ".shadowscan/report.json"
) -> Path:
    path = tmp_path / "signers.json"
    record = {
        "artifact_path": artifact,
        "bundle_path": ".shadowscan/report.sigstore.json",
        "expected_identity": identity,
        "expected_issuer": ISSUER,
    }
    path.write_text(json.dumps({"version": 1, "artifacts": [record]}))
    return path


def _verifier(monkeypatch, **overrides):
    calls = []

    def verify(artifact, bundle, identity, issuer):
        calls.append((artifact, bundle, identity, issuer))
        digest = "sha256:" + hashlib.sha256(Path(artifact).read_bytes()).hexdigest()
        fields = {
            "verified": True,
            "identity": identity,
            "issuer": issuer,
            "details": {"artifact_digest": digest},
        }
        return VerificationResult(**{**fields, **overrides})

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_bundle", verify)
    return calls


def _validate(bom: Path, project: Path, *extra: str):
    return CliRunner().invoke(
        main,
        [
            "validate",
            str(bom),
            "--project",
            str(project),
            "--accept-project-policy",
            *extra,
        ],
    )


def test_required_signature_without_an_operator_entry_fails_validate_and_risk(tmp_path):
    project, bom = _project(tmp_path, GATED)
    result = _validate(bom, project)
    assert result.exit_code == 1
    assert "Discovery producer check" in result.output
    assert "No operator signature policy entry names the ShadowScan report" in result.output
    risk = CliRunner().invoke(
        main,
        [
            "risk",
            str(bom),
            "--project",
            str(project),
            "--accept-project-policy",
            "--json-output",
        ],
    )
    assert risk.exit_code == 1
    reasons = json.loads(risk.stdout)["gate_reasons"]
    assert any("No operator signature policy entry names" in reason for reason in reasons)


def test_without_the_requirement_validation_is_unchanged(tmp_path, monkeypatch):
    calls = _verifier(monkeypatch)
    project, bom = _project(tmp_path, UNGATED)
    # The BOM's evidence is unverified at import, so the unsigned gate needs
    # the explicit acceptance here; what this test owns is that no producer
    # check runs without the requirement.
    result = _validate(bom, project, "--allow-unsigned-discovery")
    assert result.exit_code == 0, result.output
    assert "Discovery producer check" not in result.output and calls == []


def test_signed_report_passes_and_binds_the_exact_recorded_bytes(tmp_path, monkeypatch):
    calls = _verifier(monkeypatch)
    project, bom = _project(tmp_path, GATED)
    result = _validate(bom, project, "--signature-policy", str(_signers(tmp_path)))
    assert result.exit_code == 0, result.output
    assert "Discovery producer check" in result.output
    report = (project / ".shadowscan/report.json").resolve()
    assert [(Path(a).resolve(), Path(b).name, i, s) for a, b, i, s in calls] == [
        (report, "report.sigstore.json", IDENTITY, ISSUER)
    ]
    risk = CliRunner().invoke(
        main,
        ["risk", str(bom), "--project", str(project), "--json-output"]
        + ["--signature-policy", str(_signers(tmp_path))],
    )
    assert json.loads(risk.stdout)["assessment_basis"] == "project-reconciled"


def test_an_operator_entry_for_the_report_requires_its_signer_without_the_flag(
    tmp_path, monkeypatch
):
    _verifier(monkeypatch, verified=False, error="Sigstore artifact verification failed")
    project, bom = _project(tmp_path, UNGATED)
    result = _validate(bom, project, "--signature-policy", str(_signers(tmp_path)))
    assert result.exit_code == 1
    assert "ShadowScan report signature or signer policy verification failed" in result.output


@pytest.mark.parametrize(
    "overrides",
    [
        {"verified": False, "error": "Sigstore artifact verification failed"},
        {"identity": "https://github.com/attacker/fork/.github/workflows/x.yml@refs/heads/main"},
        {"issuer": "https://issuer.attacker.test"},
        {"details": {"artifact_digest": "sha256:" + "0" * 64}},
        {"details": None},
    ],
)
def test_a_signature_over_other_bytes_or_by_another_signer_fails(tmp_path, monkeypatch, overrides):
    _verifier(monkeypatch, **overrides)
    project, bom = _project(tmp_path, GATED)
    result = _validate(bom, project, "--signature-policy", str(_signers(tmp_path)))
    assert result.exit_code == 1
    assert "ShadowScan report signature or signer policy verification failed" in result.output


def test_real_offline_verification_rejects_a_bundle_for_other_bytes(tmp_path):
    pytest.importorskip("sigstore")
    project, bom = _project(tmp_path, GATED)
    shutil.copy(UPSTREAM_BUNDLE, project / ".shadowscan/report.sigstore.json")
    signer = (
        "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
    )
    result = _validate(bom, project, "--signature-policy", str(_signers(tmp_path, signer)))
    assert result.exit_code == 1
    assert "ShadowScan report signature or signer policy verification failed" in result.output


def test_report_changed_after_scan_fails_before_the_signature_check(tmp_path, monkeypatch):
    calls = _verifier(monkeypatch)
    project, bom = _project(tmp_path, GATED)
    report = project / ".shadowscan/report.json"
    report.write_text(report.read_text().replace("00:09:37", "00:10:00"))
    result = _validate(bom, project, "--signature-policy", str(_signers(tmp_path)))
    assert result.exit_code == 1 and calls == []
    assert "Local discovery report differs from the recorded digest." in result.output


def test_discovery_evidence_needs_a_recorded_digest(tmp_path):
    project, bom = _project(tmp_path, GATED)
    doc = json.loads(bom.read_text())
    doc["metadata"]["completeness"]["source_report_digest"] = None
    stripped = AIBOM.model_validate(doc)
    assert discovery_producer_problems(stripped, project, []) == [
        "ShadowScan evidence has no recorded report digest to authenticate."
    ]
    doc["components"] = [c for c in doc["components"] if not c["bom_ref"].startswith("shadowscan:")]
    doc["metadata"]["completeness"].update(
        scope="repository", source_report_format=None, source_report_status=None
    )
    # Stripping every discovery marker cannot turn the check into a vacuous pass.
    assert discovery_producer_problems(AIBOM.model_validate(doc), project, []) == [
        "The inventory omits the ShadowScan report present beneath the project root."
    ]
    (project / ".shadowscan/report.json").unlink()
    assert discovery_producer_check(AIBOM.model_validate(doc), project, []) == (
        "not-applicable",
        [],
    )


def test_the_policy_flag_is_strict_and_off_by_default():
    assert Policy().validation.require_discovery_signature is False
    assert Policy.model_validate({"validate": {"require_discovery_signature": True}})
    with pytest.raises(ValueError):
        Policy.model_validate({"validate": {"require_discovery_signature": "true"}})


def _discovered(doc: dict, component_type: str) -> dict:
    return next(
        c
        for c in doc["components"]
        if c["bom_ref"].startswith("shadowscan:") and c["component_type"] == component_type
    )


def _clear_server_risks(doc: dict) -> None:
    _discovered(doc, "mcp-server")["risks"] = []


def _drop_discovered_agent(doc: dict) -> None:
    agent = _discovered(doc, "agent")["bom_ref"]
    doc["components"] = [c for c in doc["components"] if c["bom_ref"] != agent]
    doc["dependencies"] = [
        e for e in doc["dependencies"] if agent not in (e["source_ref"], e["target_ref"])
    ]


@pytest.mark.parametrize("edit", [_clear_server_risks, _drop_discovered_agent])
def test_the_signed_report_binds_the_evidence_when_completeness_is_off(tmp_path, monkeypatch, edit):
    calls = _verifier(monkeypatch)
    project, bom = _project(tmp_path, UNCHECKED)
    signers = str(_signers(tmp_path))
    assert _validate(bom, project, "--signature-policy", signers).exit_code == 0
    doc = json.loads(bom.read_text())
    edit(doc)
    bom.write_text(json.dumps(doc))
    result = _validate(bom, project, "--signature-policy", signers)
    assert result.exit_code == 1 and len(calls) == 2
    assert "ShadowScan evidence differs from the projection of the signed report." in result.output


def test_a_report_removed_after_the_scan_cannot_be_authenticated(tmp_path, monkeypatch):
    calls = _verifier(monkeypatch)
    project, bom = _project(tmp_path, UNCHECKED)
    (project / ".shadowscan/report.json").unlink()
    result = _validate(bom, project)
    assert result.exit_code == 1 and calls == []
    assert "No readable ShadowScan report beneath the project root to authenticate." in (
        result.output
    )


def test_a_missing_sigstore_extra_fails_with_its_install_hint(tmp_path, monkeypatch):
    _verifier(monkeypatch, verified=False, error=SIGSTORE_MISSING, details=None)
    project, bom = _project(tmp_path, GATED)
    result = _validate(bom, project, "--signature-policy", str(_signers(tmp_path)))
    assert result.exit_code == 1
    assert SIGSTORE_MISSING in result.output
    assert "signer policy verification failed" not in result.output


def test_an_entry_naming_the_report_file_by_another_link_still_requires_its_signer(
    tmp_path, monkeypatch
):
    project, bom = _project(tmp_path, GATED)
    os.link(project / ".shadowscan/report.json", project / ".shadowscan/alias.json")
    signers = str(_signers(tmp_path, artifact=".shadowscan/alias.json"))
    calls = _verifier(monkeypatch)
    result = _validate(bom, project, "--signature-policy", signers)
    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    (project / ".nexus-symbiote.yaml").write_text(UNGATED)
    calls = _verifier(monkeypatch, verified=False, error="Sigstore artifact verification failed")
    result = _validate(bom, project, "--signature-policy", signers)
    assert result.exit_code == 1 and len(calls) == 1
    assert "ShadowScan report signature or signer policy verification failed" in result.output


def test_an_entry_naming_the_report_file_in_another_spelling_is_refused(tmp_path, monkeypatch):
    # Where file names fold case this spelling reaches the report; a confined read
    # still requires the spelling the directory holds, so the result is the same on
    # every file system.
    project, bom = _project(tmp_path, GATED)
    signers = str(_signers(tmp_path, artifact=".shadowscan/REPORT.json"))
    calls = _verifier(monkeypatch)
    result = _validate(bom, project, "--signature-policy", signers)
    assert result.exit_code == 1 and calls == []
    assert "Policy artifact or bundle is unavailable beneath the project root" in result.output


def _strip_discovery(doc: dict) -> None:
    imported = {c["bom_ref"] for c in doc["components"] if c["bom_ref"].startswith("shadowscan:")}
    doc["components"] = [c for c in doc["components"] if c["bom_ref"] not in imported]
    doc["dependencies"] = [
        e for e in doc["dependencies"] if not {e["source_ref"], e["target_ref"]} & imported
    ]
    doc["metadata"]["completeness"].update(
        scope="repository",
        source_report_digest=None,
        source_report_content_digest=None,
        source_report_content_profile=None,
        source_report_format=None,
        source_report_status=None,
        source_projection_limitations=None,
    )


def test_removing_all_discovery_evidence_fails_the_producer_check(tmp_path, monkeypatch):
    _verifier(monkeypatch)
    project, bom = _project(tmp_path, UNCHECKED)
    signers = str(_signers(tmp_path))
    doc = json.loads(bom.read_text())
    _strip_discovery(doc)
    bom.write_text(json.dumps(doc))
    result = _validate(bom, project, "--signature-policy", signers)
    assert result.exit_code == 1, result.output
    assert "omits the ShadowScan report that the operator signature policy names" in result.output


def test_operator_flag_requires_the_signature_when_the_project_policy_is_ignored(tmp_path):
    project, bom = _project(tmp_path, UNGATED)
    plain = _validate(bom, project, "--no-project-policy")
    assert "Discovery producer check" not in plain.output
    assert "Discovery producer: not verified (unsigned evidence accepted)" in plain.output
    required = _validate(bom, project, "--no-project-policy", "--require-discovery-signature")
    assert required.exit_code == 1
    assert "No operator signature policy entry names the ShadowScan report" in required.output
    risk = CliRunner().invoke(
        main,
        ["risk", str(bom), "--project", str(project), "--no-project-policy", "--json-output"],
    )
    assert json.loads(risk.stdout)["discovery_producer"] == "not-verified"
    text = CliRunner().invoke(
        main, ["risk", str(bom), "--project", str(project), "--no-project-policy"]
    )
    assert "Discovery producer: not verified (unsigned evidence accepted)" in text.output
    gated = CliRunner().invoke(
        main,
        [
            "risk",
            str(bom),
            "--project",
            str(project),
            "--no-project-policy",
            "--json-output",
            "--require-discovery-signature",
        ],
    )
    assert gated.exit_code == 1
    assert json.loads(gated.stdout)["discovery_producer"] == "failed"
    unscoped = CliRunner().invoke(main, ["validate", str(bom), "--require-discovery-signature"])
    assert unscoped.exit_code == 2 and "requires --project" in unscoped.output


def test_signed_report_reports_a_verified_producer(tmp_path, monkeypatch):
    _verifier(monkeypatch)
    project, bom = _project(tmp_path, UNGATED)
    risk = CliRunner().invoke(
        main,
        ["risk", str(bom), "--project", str(project), "--no-project-policy", "--json-output"]
        + ["--signature-policy", str(_signers(tmp_path))],
    )
    assert json.loads(risk.stdout)["discovery_producer"] == "verified"


def test_a_failed_producer_check_does_not_relabel_a_passed_reconciliation(tmp_path):
    project, bom = _project(tmp_path, GATED)
    args = [
        "risk",
        str(bom),
        "--project",
        str(project),
        "--accept-project-policy",
        "--json-output",
    ]
    document = json.loads(CliRunner().invoke(main, args).stdout)
    assert document["assessment_basis"] == "project-reconciled"
    assert document["overall_score"] is None and document["passed"] is False
    assert document["coverage_status"] != "unreconciled"
    text = CliRunner().invoke(main, args[:-1]).output
    assert "Project reconciliation failed" not in text
    assert "No operator signature policy entry names" in text
