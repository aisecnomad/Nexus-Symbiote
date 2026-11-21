"""Operator configuration cannot escape the scanned project's trust boundary."""

from __future__ import annotations

import json

import pytest

from nexus_symbiote.signature_policy import SignaturePolicyError, load_signature_policies


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


@pytest.mark.parametrize("marker", ["directory", "file"])
def test_a_policy_in_the_repository_that_holds_the_project_is_refused(tmp_path, marker):
    # A pull request can edit any file of the repository, not only the scanned directory.
    repository = tmp_path / "repository"
    project = repository / "services" / "agent"
    project.mkdir(parents=True)
    (project / "model.bin").write_bytes(b"artifact")
    if marker == "directory":
        (repository / ".git").mkdir()
    else:
        # A worktree or submodule checkout holds a .git file.
        (repository / ".git").write_text("gitdir: elsewhere\n")
    record = {"kind": "digest-pin", "artifact_path": "model.bin", "expected_sha256": "0" * 64}
    document = json.dumps({"version": 2, "artifacts": [record]})
    inside = repository / "ci" / "signers.json"
    inside.parent.mkdir()
    inside.write_text(document)
    with pytest.raises(SignaturePolicyError, match="outside every repository that holds it"):
        load_signature_policies(inside, project)
    # Another name for the repository directory does not hide it.
    alias = tmp_path / "alias"
    alias.symlink_to(repository, target_is_directory=True)
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(alias / "ci" / "signers.json", project)
    outside = tmp_path / "signers.json"
    outside.write_text(document)
    assert len(load_signature_policies(outside, project).digest_pins) == 1


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


@pytest.mark.parametrize(
    ("version", "artifacts", "reason"),
    [
        (1, ["model.bin"], "Each signature policy artifact must be an object"),
        (
            2,
            [{"kind": "digest-pin", "artifact_path": "model.bin", "expected_sha256": 7}],
            "expected_sha256 must be a SHA-256 digest",
        ),
        (
            2,
            [{"kind": "digest-pin", "artifact_path": "model.bin", "expected_sha256": None}],
            "A digest pin requires expected_sha256",
        ),
    ],
)
def test_malformed_entries_fail_closed_with_their_reason(policy_inputs, version, artifacts, reason):
    project, policy, _ = policy_inputs
    policy.write_text(json.dumps({"version": version, "artifacts": artifacts}))
    with pytest.raises(SignaturePolicyError, match=reason):
        load_signature_policies(policy, project)


def test_a_missing_project_root_is_an_explicit_error(policy_inputs, tmp_path):
    _, policy, _ = policy_inputs
    with pytest.raises(SignaturePolicyError, match="Project root is unavailable"):
        load_signature_policies(policy, tmp_path / "no-such-project")


def test_version_2_supports_openssf_model_signing_dsse_and_rekor_witnesses(policy_inputs):
    project, policy, record = policy_inputs
    v2_record = {
        **record,
        "kind": "openssf-model-signing-dsse",
        "rekor_root_hash": "sha256:" + "ab" * 32,
        "minimum_rekor_tree_size": 1024,
    }
    policy.write_text(json.dumps({"version": 2, "artifacts": [v2_record]}))
    loaded = load_signature_policies(policy, project)
    assert len(loaded) == 1
    entry = loaded[0]
    assert entry.allow_oms_dsse is True
    assert entry.rekor_root_hash == "sha256:" + "ab" * 32
    assert entry.minimum_rekor_tree_size == 1024

    for bad_field, bad_val, match in [
        ("rekor_root_hash", "not-a-digest", "rekor_root_hash must be a SHA-256 digest"),
        ("rekor_root_hash", None, "rekor_root_hash must be a SHA-256 digest"),
        ("minimum_rekor_tree_size", 0, "minimum_rekor_tree_size must be a positive integer"),
        ("minimum_rekor_tree_size", True, "minimum_rekor_tree_size must be a positive integer"),
        ("minimum_rekor_tree_size", None, "minimum_rekor_tree_size must be a positive integer"),
    ]:
        policy.write_text(
            json.dumps({"version": 2, "artifacts": [{**v2_record, bad_field: bad_val}]})
        )
        with pytest.raises(SignaturePolicyError, match=match):
            load_signature_policies(policy, project)
