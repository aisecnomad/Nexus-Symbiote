"""Operator configuration cannot escape the scanned project's trust boundary."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.signature_policy import SignaturePolicyError, load_signature_policies
from nexus_symbiote.validators.integrity import IntegrityValidator
from tests.test_integrity_security import write_safetensors


@pytest.fixture
def policy_inputs(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "model.bin").write_bytes(b"artifact")
    (project / "model.sigstore").write_text("unverified bundle")
    record = {
        "artifact_path": "model.bin",
        "bundle_path": "model.sigstore",
        "expected_identity": "publisher@example.test",
        "expected_issuer": "https://issuer.example.test",
    }
    policy = tmp_path / "operator-policy.json"
    policy.write_text(json.dumps({"version": 1, "artifacts": [record]}))
    return project, policy, record


def write_records(policy, records, **extra):
    policy.write_text(json.dumps({"version": 1, "artifacts": records, **extra}))


def test_explicit_operator_policy_outside_project_loads_without_trusting_bundle(policy_inputs):
    project, policy, record = policy_inputs
    loaded = load_signature_policies(policy, project)
    assert len(loaded) == 1
    assert loaded[0].artifact_path == project / "model.bin"
    assert loaded[0].bundle_path == project / "model.sigstore"
    assert loaded[0].expected_identity == record["expected_identity"]
    assert loaded[0].expected_issuer == record["expected_issuer"]
    # Ambient repository content does not override the selected operator file.
    (project / ".nexus-symbiote.yaml").write_text("untrusted: true")
    assert load_signature_policies(policy, project) == loaded


@pytest.mark.parametrize(
    "change", ["extra_record", "missing", "blank", "wrong_type", "extra_root", "empty", "version"]
)
def test_unknown_missing_or_invalid_fields_fail_closed(policy_inputs, change):
    project, policy, record = policy_inputs
    if change == "extra_record":
        record["allow_any_signer"] = True
    elif change == "missing":
        del record["expected_issuer"]
    elif change == "blank":
        record["expected_identity"] = " "
    elif change == "wrong_type":
        record["artifact_path"] = 123
    if change == "extra_root":
        write_records(policy, [record], allow_any=True)
    elif change == "empty":
        write_records(policy, [])
    elif change == "version":
        write_records(policy, [record], version=True)
    else:
        write_records(policy, [record])
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(policy, project)


def test_duplicate_artifact_paths_and_json_keys_are_rejected(policy_inputs):
    project, policy, record = policy_inputs
    write_records(policy, [record, {**record, "artifact_path": "./model.bin"}])
    with pytest.raises(SignaturePolicyError, match="Duplicate artifact"):
        load_signature_policies(policy, project)
    policy.write_text('{"version":1,"version":1,"artifacts":[]}')
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(policy, project)


@pytest.mark.parametrize("field", ["artifact_path", "bundle_path"])
@pytest.mark.parametrize(
    "value",
    ["../outside", "/etc/passwd", "C:\\outside", "..\\outside", ".", "https://example.test/model"],
)
def test_artifact_and_bundle_references_cannot_escape_project(policy_inputs, field, value):
    project, policy, record = policy_inputs
    record[field] = value
    write_records(policy, [record])
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(policy, project)


@pytest.mark.parametrize("field", ["artifact_path", "bundle_path"])
def test_symlinked_artifacts_and_bundles_are_rejected(policy_inputs, tmp_path, field):
    project, policy, record = policy_inputs
    outside = tmp_path / "outside"
    outside.write_bytes(b"private")
    (project / "linked").symlink_to(outside)
    record[field] = "linked"
    write_records(policy, [record])
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(policy, project)


def test_symlinked_parent_directory_and_operator_policy_are_rejected(policy_inputs, tmp_path):
    project, policy, record = policy_inputs
    external = tmp_path / "external"
    external.mkdir()
    (external / "model.bin").write_bytes(b"private")
    (project / "models").symlink_to(external, target_is_directory=True)
    record["artifact_path"] = "models/model.bin"
    write_records(policy, [record])
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(policy, project)
    linked_policy = tmp_path / "selected-link.json"
    linked_policy.symlink_to(policy)
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(linked_policy, project)


@pytest.mark.parametrize(
    "issuer",
    [
        "http://issuer.example.test",
        "https://user:password@example.test",
        "https://issuer.example.test?token=secret",
        "issuer",
    ],
)
def test_oidc_issuer_cannot_embed_credentials_or_use_ambiguous_url(policy_inputs, issuer):
    project, policy, record = policy_inputs
    record["expected_issuer"] = issuer
    write_records(policy, [record])
    with pytest.raises(SignaturePolicyError) as caught:
        load_signature_policies(policy, project)
    if "://" in issuer:
        assert issuer not in str(caught.value)
    assert "password" not in str(caught.value)
    assert "secret" not in str(caught.value)


def test_size_limit_and_missing_files_are_explicit_errors(policy_inputs, monkeypatch):
    project, policy, record = policy_inputs
    monkeypatch.setattr("nexus_symbiote.signature_policy.MAX_POLICY_BYTES", 8)
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(policy, project)
    monkeypatch.setattr("nexus_symbiote.signature_policy.MAX_POLICY_BYTES", 4 * 1024 * 1024)
    (project / "model.bin").unlink()
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(policy, project)


def test_unmatched_explicit_subject_fails_each_project_gate(policy_inputs, tmp_path):
    project, policy, record = policy_inputs
    (project / "model.bin").rename(project / "weights.unrecognized")
    write_records(policy, [{**record, "artifact_path": "weights.unrecognized"}])
    (project / "CLAUDE.md").write_text("Use the reviewed tools.")
    runner = CliRunner()
    original = tmp_path / "original.json"
    scan = ["scan", str(project), "--no-project-policy"]
    assert runner.invoke(main, [*scan, "-o", str(original)]).exit_code == 0
    checked = tmp_path / "checked.json"
    explicit = ["--signature-policy", str(policy)]
    failure = "Signature policy artifact #1 did not match a collected model"
    result = runner.invoke(main, [*scan, *explicit, "-o", str(checked)])
    assert result.exit_code == 1
    coverage = AIBOM.load(checked).metadata.completeness
    assert coverage is not None and coverage.scanner_status["model"] == "failed"
    assert failure in coverage.scan_failures
    # Use the original inventory so each project gate must rediscover the omission.
    against_project = [str(original), "--project", str(project), "--no-project-policy", *explicit]
    result = runner.invoke(main, ["validate", *against_project])
    assert result.exit_code == 1 and failure in result.output
    result = runner.invoke(main, ["risk", *against_project, "--json-output"])
    assert result.exit_code == 1
    assessment = json.loads(result.output)
    assert assessment["assessment_basis"] == "project-reconciliation-failed"
    assert any(failure in reason for reason in assessment["gate_reasons"])


def test_policy_entries_are_accounted_individually(policy_inputs):
    project, policy, record = policy_inputs
    (project / "weights.unrecognized").write_bytes(b"second artifact")
    write_records(policy, [record, {**record, "artifact_path": "weights.unrecognized"}])
    policies = load_signature_policies(policy, project)
    local = ModelScanner(policies).scan(project)
    failure = "Signature policy artifact #2 did not match a collected model"
    assert local.scan_failures == [
        "model.bin: explicit signature policy verification failed",
        failure,
    ]
    report = IntegrityValidator(policies).validate(AIBOM(components=local.components), project)
    assert report.signatures_checked == 1 and report.signatures_verified == 0
    assert [
        issue.detail for issue in report.issues if issue.category == "unmatched_signature_policy"
    ] == [failure]
    assert any(issue.category == "signature_verification_failed" for issue in report.issues)


def test_failed_signature_on_valid_safetensors_blocks_scan_and_risk(policy_inputs, tmp_path):
    project, policy, record = policy_inputs
    (project / "model.bin").unlink()
    write_safetensors(project / "model.safetensors")
    write_records(policy, [{**record, "artifact_path": "model.safetensors"}])
    runner = CliRunner()
    checked = tmp_path / "checked.json"
    explicit = ["--signature-policy", str(policy), "--no-project-policy"]
    scan = ["scan", str(project), *explicit, "-o", str(checked)]
    assert runner.invoke(main, scan).exit_code == 1
    assert runner.invoke(main, [*scan, "--report-only"]).exit_code == 0
    bom = AIBOM.load(checked)
    failure = "model.safetensors: explicit signature policy verification failed"
    coverage = bom.metadata.completeness
    assert coverage is not None and coverage.scanner_status["model"] == "failed"
    assert failure in coverage.scan_failures
    model = next(c for c in bom.components if c.component_type.value == "model")
    assert (
        model.serialization_safety.value == "safe" and model.signing_status == "verification-failed"
    )
    # Remove the stored failure to ensure risk rechecks the explicit policy itself.
    coverage.scan_failures.clear()
    coverage.scanner_status["model"] = "complete"
    coverage.collectors_completed.append("model")
    bom.save(checked)
    result = runner.invoke(
        main, ["risk", str(checked), "--project", str(project), *explicit, "--json-output"]
    )
    assert result.exit_code == 1
    assessment = json.loads(result.output)
    assert assessment["assessment_basis"] == "project-reconciliation-failed"
    assert any(failure in reason for reason in assessment["gate_reasons"])


def test_explicit_policy_cannot_be_silently_disabled(policy_inputs, tmp_path):
    project, policy, _ = policy_inputs
    runner = CliRunner()
    explicit = ["--signature-policy", str(policy)]
    result = runner.invoke(
        main, ["scan", str(project), "--scanner", "prompt", "--report-only", *explicit]
    )
    assert result.exit_code != 0 and "requires the model scanner" in result.output
    (project / ".nexus-symbiote.yaml").write_text("validate: {require_integrity: false}")
    bom = tmp_path / "bom.json"
    AIBOM().save(bom)
    result = runner.invoke(main, ["validate", str(bom), "--project", str(project), *explicit])
    assert result.exit_code != 0 and "requires integrity validation" in result.output
