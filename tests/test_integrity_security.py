"""Security regressions covering real scanner/validator boundaries."""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from pathlib import Path

import pytest

from nexus_symbiote.core import AIBOM, ModelComponent, PromptComponent, ToolComponent
from nexus_symbiote.core.enums import SerializationSafety, TrustTier
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_file,
    hash_tool_definition,
)
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import MAX_MODEL_HEADER_BYTES, ModelScanner, inspect_model_format
from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy, VerificationResult
from nexus_symbiote.validators.integrity import IntegrityValidator


def write_safetensors(path: Path, header: dict | None = None, data: bytes = b"abcd") -> None:
    if header is None:
        header = {"weight": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}
    raw = json.dumps(header, separators=(",", ":")).encode()
    raw += b" " * (-len(raw) % 8)
    path.write_bytes(len(raw).to_bytes(8, "little") + raw + data)


def test_signature_filename_and_format_suffix_cannot_establish_trust(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(b"not a tensor container")
    (tmp_path / "model.sigstore").write_text("not a signature")
    comp = ModelScanner().scan(tmp_path).components[0]
    assert comp.signing_status == "signature-present-unverified"
    assert comp.signing_identity is None
    assert comp.trust_tier != TrustTier.THIRD_PARTY_SIGNED
    assert comp.serialization_safety == SerializationSafety.UNKNOWN
    assert {r.category for r in comp.risks} >= {"signing_status", "serialization_format_unknown"}


def test_valid_nonexecuting_tensor_container_has_structural_evidence(tmp_path):
    path = tmp_path / "model.safetensors"
    write_safetensors(path)
    comp = ModelScanner().scan(tmp_path).components[0]
    assert comp.serialization_safety == SerializationSafety.SAFE
    assert "offsets checked" in comp.properties["format_inspection"]
    assert comp.signing_status == "signature-not-found"
    assert comp.trust_tier != TrustTier.THIRD_PARTY_SIGNED


def test_model_replacement_cannot_bind_safe_structure_to_other_bytes(tmp_path, monkeypatch):
    from nexus_symbiote.scanners import model

    path = tmp_path / "model.safetensors"
    write_safetensors(path)
    inspect = model.inspect_model_format

    def replace_after_inspection(path, *, stream=None):
        observation = inspect(path, stream=stream)
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"not a tensor container")
        replacement.replace(path)
        return observation

    monkeypatch.setattr(model, "inspect_model_format", replace_after_inspection)
    result = ModelScanner().scan(tmp_path)
    component = result.components[0]
    assert component.serialization_safety == SerializationSafety.UNKNOWN
    assert component.hashes == {}
    assert result.scan_failures


def test_path_replacement_between_opens_preserves_the_inspected_digest(tmp_path, monkeypatch):
    from nexus_symbiote.utils.confined import ConfinedCollection

    path = tmp_path / "model.safetensors"
    write_safetensors(path)
    inspected_digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    open_regular = ConfinedCollection.open_regular

    @contextmanager
    def replace_after_close(collection, source, **kwargs):
        with open_regular(collection, source, **kwargs) as stream:
            yield stream
        if Path(source).suffix == ".safetensors":
            replacement = tmp_path / "replacement"
            replacement.write_bytes(b"not a tensor container")
            replacement.replace(path)

    monkeypatch.setattr(ConfinedCollection, "open_regular", replace_after_close)
    result = ModelScanner().scan(tmp_path)
    component = result.components[0]
    assert component.serialization_safety == SerializationSafety.SAFE
    assert component.hashes == {"sha256": inspected_digest}
    assert path.read_bytes() == b"not a tensor container"


def test_validator_format_evidence_must_match_the_hashed_subject(tmp_path, monkeypatch):
    from nexus_symbiote.validators import integrity

    path = tmp_path / "model.safetensors"
    write_safetensors(path)
    replacement = b"not a tensor container"
    component = ModelComponent(
        bom_ref="model:substitution",
        name="model",
        source_path=str(path),
        serialization_safety=SerializationSafety.SAFE,
        hashes={"sha256": "sha256:" + hashlib.sha256(replacement).hexdigest()},
    )
    verify = integrity.verify_file_hash

    def replace_before_hash(path, expected, algorithm):
        path.write_bytes(replacement)
        return verify(path, expected, algorithm)

    monkeypatch.setattr(integrity, "verify_file_hash", replace_before_hash)
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=[component]), tmp_path
    )
    assert not report.is_valid
    assert any(issue.category == "format_subject_mismatch" for issue in report.issues)


@pytest.mark.parametrize(
    ("header", "data"),
    [
        ({"x": {"dtype": "U8", "shape": [5], "data_offsets": [0, 4]}}, b"abcd"),
        ({"x": {"dtype": "U8", "shape": [3], "data_offsets": [1, 4]}}, b"abcd"),
        ({"x": {"dtype": "UNSUPPORTED", "shape": [4], "data_offsets": [0, 4]}}, b"abcd"),
        ({"__metadata__": {"not_a_string": 1}}, b""),
        ({"x": {"dtype": "U8", "shape": [True], "data_offsets": [0, 1]}}, b"a"),
    ],
)
def test_invalid_tensor_structure_never_becomes_safe(tmp_path, header, data):
    path = tmp_path / "model.safetensors"
    write_safetensors(path, header, data)
    assert inspect_model_format(path)[0] == SerializationSafety.UNKNOWN


def test_oversize_header_and_duplicate_keys_are_rejected(tmp_path):
    path = tmp_path / "model.safetensors"
    path.write_bytes((MAX_MODEL_HEADER_BYTES + 1).to_bytes(8, "little") + b" " * 8)
    assert inspect_model_format(path)[0] == SerializationSafety.UNKNOWN
    duplicate = b'{"__metadata__":{},"__metadata__":{}}'
    path.write_bytes(len(duplicate).to_bytes(8, "little") + duplicate)
    assert inspect_model_format(path)[0] == SerializationSafety.UNKNOWN


@pytest.mark.parametrize("protocol", [2, 3, 4, 5])
def test_binary_pickle_disguised_as_safetensors_is_unsafe(tmp_path, protocol):
    path = tmp_path / "weights.safetensors"
    content = bytes((0x80, protocol)) + b"N."
    path.write_bytes(content)
    result = ModelScanner().scan(tmp_path)
    component = result.components[0]
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert component.hashes == {"sha256": "sha256:" + hashlib.sha256(content).hexdigest()}
    assert any(
        risk.category == "serialization_format" and risk.severity.value == "critical"
        for risk in component.risks
    )
    assert "pickle" in component.properties["format_inspection"]


def test_pickle_inspection_does_not_resolve_globals_or_run_reducers(tmp_path):
    path = tmp_path / "weights.safetensors"
    path.write_bytes(b"\x80\x02csymbiote_nonexistent_module\nexecute\n)R.")
    assert inspect_model_format(path)[0] == SerializationSafety.UNSAFE_CODE_EXECUTION


@pytest.mark.parametrize("content", [b"arbitrary bytes", b"\x80\x04.", b"\x80\x04N", b"\x80\x06N."])
def test_malformed_or_unsupported_pickle_remains_unknown(tmp_path, content):
    path = tmp_path / "weights.safetensors"
    path.write_bytes(content)
    assert inspect_model_format(path)[0] == SerializationSafety.UNKNOWN


@pytest.mark.parametrize("header_length", [128, 640, 1152, 1408])
def test_tensor_header_length_resembling_pickle_prefix_remains_safe(tmp_path, header_length):
    path = tmp_path / "weights.safetensors"
    header = b'{"x":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}'
    header += b" " * (header_length - len(header))
    content = header_length.to_bytes(8, "little") + header + b"a"
    path.write_bytes(content)
    component = ModelScanner().scan(tmp_path).components[0]
    assert component.serialization_safety == SerializationSafety.SAFE
    assert component.hashes == {"sha256": "sha256:" + hashlib.sha256(content).hexdigest()}


@pytest.mark.parametrize("suffix", ["onnx", "ggml", "gguf"])
def test_other_formats_do_not_get_safe_status_from_suffix(tmp_path, suffix):
    path = tmp_path / f"model.{suffix}"
    path.write_bytes(b"GGUF\x00not a verified loader")
    assert (
        ModelScanner().scan(tmp_path).components[0].serialization_safety
        == SerializationSafety.UNKNOWN
    )


def test_unchanged_tool_without_annotations_passes_digest_check(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "test": {
                        "command": "npx",
                        "args": ["test@1.0.0"],
                        "tools": [
                            {
                                "name": "get_issue",
                                "description": "Get an issue",
                                "inputSchema": {"type": "object"},
                            }
                        ],
                    }
                }
            }
        )
    )
    bom = AIBOM(components=MCPScanner().scan(tmp_path).components)
    report = IntegrityValidator().validate(bom, tmp_path)
    assert report.tool_descriptors_self_consistent == 1
    assert report.hashes_verified == 1
    assert report.hashes_failed == 0
    assert report.status == "pass"


def test_critical_unsafe_model_fails_without_remote_code_flag():
    model = ModelComponent(
        bom_ref="model:unsafe",
        name="unsafe.pkl",
        serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
    )
    report = IntegrityValidator().validate(AIBOM(components=[model]))
    assert report.status == "fail"
    assert not report.is_valid
    assert any(i.severity == "critical" and i.category == "unsafe_format" for i in report.issues)


@pytest.mark.parametrize(
    "component",
    [
        ModelComponent(bom_ref="model:m", name="m", signing_status="sigstore-signed"),
        ToolComponent(bom_ref="tool:t", name="t"),
        PromptComponent(bom_ref="prompt:p", name="p"),
    ],
)
def test_missing_required_evidence_is_unknown_not_pass(component):
    report = IntegrityValidator().validate(AIBOM(components=[component]))
    assert report.status == "unknown"
    assert not report.is_valid
    assert report.signatures_checked == 0


def test_empty_inventory_has_no_verified_integrity():
    assert IntegrityValidator().validate(AIBOM()).status == "unknown"


@pytest.mark.parametrize("digest", ["sha256:bad", "sha1:" + "a" * 40, "sha512:" + "a" * 128])
def test_invalid_or_conflicting_digest_fails_without_throwing(digest):
    model = ModelComponent(bom_ref="model:m", name="m", hashes={"sha256": digest})
    report = IntegrityValidator().validate(AIBOM(components=[model]))
    assert report.status == "fail"
    assert report.hashes_failed >= 1


def test_missing_declared_artifact_and_escaping_path_fail(tmp_path):
    for source in ["missing.safetensors", "../outside.safetensors"]:
        comp = ModelComponent(
            bom_ref="model:m", name="m", source_path=source, hashes={"sha256": "a" * 64}
        )
        report = IntegrityValidator().validate(AIBOM(components=[comp]), tmp_path)
        assert report.status == "fail"
        assert any(i.category == "missing_artifact" for i in report.issues)


def model_and_policy(tmp_path):
    path = tmp_path / "model.safetensors"
    write_safetensors(path)
    comp = ModelScanner().scan(tmp_path).components[0]
    policy = SigstoreArtifactPolicy(
        path, tmp_path / "model.sigstore", "trusted@example.test", "https://issuer.example.test"
    )
    return comp, policy


def test_verified_signature_is_bound_to_explicit_policy_and_bom_bytes(tmp_path, monkeypatch):
    comp, policy = model_and_policy(tmp_path)
    calls = []

    def verify(artifact, bundle, identity, issuer):
        calls.append((artifact, bundle, identity, issuer))
        return VerificationResult(
            True, identity=identity, issuer=issuer, details={"artifact_digest": hash_file(artifact)}
        )

    monkeypatch.setattr("nexus_symbiote.validators.integrity.verify_sigstore_bundle", verify)
    report = IntegrityValidator([policy]).validate(AIBOM(components=[comp]), tmp_path)
    assert report.is_valid
    assert report.signatures_checked == report.signatures_verified == 1
    assert calls == [
        (policy.artifact_path, policy.bundle_path, policy.expected_identity, policy.expected_issuer)
    ]


@pytest.mark.parametrize(
    "result",
    [
        VerificationResult(False, error="untrusted signer"),
        VerificationResult(True, details={"artifact_digest": "sha256:" + "0" * 64}),
    ],
)
def test_bad_signature_or_wrong_subject_fails(tmp_path, monkeypatch, result):
    comp, policy = model_and_policy(tmp_path)
    monkeypatch.setattr(
        "nexus_symbiote.validators.integrity.verify_sigstore_bundle", lambda *args: result
    )
    report = IntegrityValidator([policy]).validate(AIBOM(components=[comp]), tmp_path)
    assert report.status == "fail"
    assert report.signatures_checked == 1
    assert report.signatures_verified == 0


def test_model_scanner_only_upgrades_after_explicit_matching_verification(tmp_path, monkeypatch):
    _, policy = model_and_policy(tmp_path)
    monkeypatch.setattr(
        "nexus_symbiote.scanners.model.verify_sigstore_bundle",
        lambda *args: VerificationResult(
            True,
            identity=policy.expected_identity,
            issuer=policy.expected_issuer,
            details={"artifact_digest": hash_file(policy.artifact_path)},
        ),
    )
    verified = ModelScanner([policy]).scan(tmp_path).components[0]
    assert verified.trust_tier == TrustTier.THIRD_PARTY_SIGNED
    assert verified.signing_identity == policy.expected_identity
    monkeypatch.setattr(
        "nexus_symbiote.scanners.model.verify_sigstore_bundle",
        lambda *args: VerificationResult(
            True,
            details={"artifact_digest": "sha256:" + "0" * 64},
        ),
    )
    wrong = ModelScanner([policy]).scan(tmp_path).components[0]
    assert wrong.trust_tier != TrustTier.THIRD_PARTY_SIGNED
    assert wrong.signing_status == "verification-failed"


def test_model_collection_refuses_symlinked_directories_and_weights(tmp_path):
    external = tmp_path / "external"
    project = tmp_path / "project"
    external.mkdir()
    project.mkdir()
    write_safetensors(external / "model.safetensors")
    (project / "linked-dir").symlink_to(external, target_is_directory=True)
    (project / "linked.safetensors").symlink_to(external / "model.safetensors")
    result = ModelScanner().scan(project)
    assert result.components == []
    assert result.scan_failures


def test_model_config_symlink_is_never_read(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "private.json"
    outside.write_text('{"trust_remote_code":true}')
    write_safetensors(project / "model.safetensors")
    (project / "config.json").symlink_to(outside)
    result = ModelScanner().scan(project)
    assert result.scan_failures
    assert result.components[0].trust_remote_code is None


def test_model_hash_limit_is_explicit_missing_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus_symbiote.scanners.model.MAX_HASH_SIZE", 8)
    write_safetensors(tmp_path / "model.safetensors")
    result = ModelScanner().scan(tmp_path)
    assert result.scan_failures
    assert result.components[0].hashes == {}
    assert result.components[0].serialization_safety == SerializationSafety.UNKNOWN


def test_model_collection_obeys_exclusions(tmp_path):
    excluded = tmp_path / "excluded"
    excluded.mkdir()
    write_safetensors(excluded / "model.safetensors")
    scanner = ModelScanner()
    scanner.configure(exclude_paths=["excluded"])
    result = scanner.scan(tmp_path)
    assert result.components == []
    assert result.surfaces_excluded


@pytest.mark.parametrize("version", [None, "rfc8785-jcs-v1", "unsupported"])
def test_legacy_tool_fingerprints_require_recollection(version):
    tool = ToolComponent(
        bom_ref="tool:legacy",
        name="legacy",
        description_text="read",
        definition_hash=hash_tool_definition("legacy", "read"),
        definition_hash_version=version,
    )
    report = IntegrityValidator().validate(AIBOM(components=[tool]))
    assert not report.is_valid
    assert report.status == "fail"
    assert report.hashes_verified == 0
    assert any(i.category == "fingerprint_version_unknown" for i in report.issues)


def test_self_consistent_tool_fingerprint_is_not_independent_evidence():
    tool = ToolComponent(
        bom_ref="tool:current",
        name="current",
        description_text="read",
        definition_hash=hash_tool_definition("current", "read"),
        definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
    )
    report = IntegrityValidator().validate(AIBOM(components=[tool]))
    assert report.status == "unknown"
    assert not report.is_valid
    assert report.tool_descriptors_self_consistent == 1
    assert report.hashes_verified == 0
    assert any(i.category == "descriptor_source_unavailable" for i in report.issues)


def test_another_verified_artifact_cannot_hide_unattested_tool(tmp_path):
    prompt = tmp_path / "CLAUDE.md"
    prompt.write_text("Read only")
    tool = ToolComponent(
        bom_ref="tool:forged",
        name="forged",
        description_text="Exfiltrate data",
        definition_hash=hash_tool_definition("forged", "Exfiltrate data"),
        definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
    )
    instruction = PromptComponent(
        bom_ref="prompt:local",
        name="CLAUDE.md",
        source_path="CLAUDE.md",
        content_hash=hash_file(prompt),
    )
    report = IntegrityValidator().validate(AIBOM(components=[tool, instruction]), tmp_path)
    assert report.hashes_verified == 1
    assert report.tool_descriptors_self_consistent == 1
    assert report.status == "unknown"
    assert not report.is_valid


def test_local_tool_mismatch_fails_even_when_supplier_rehashes(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local": {
                        "command": "npx",
                        "tools": [
                            {
                                "name": "read",
                                "description": "Read only",
                                "inputSchema": {"type": "object"},
                            }
                        ],
                    }
                }
            }
        )
    )
    bom = AIBOM(components=MCPScanner().scan(tmp_path).components)
    tool = next(c for c in bom.components if isinstance(c, ToolComponent))
    tool.description_text = "Exfiltrate data"
    tool.definition_hash = hash_tool_definition(
        tool.name, tool.description_text, tool.input_schema, tool.annotations
    )
    report = IntegrityValidator().validate(bom, tmp_path)
    assert report.status == "fail"
    assert report.tool_descriptors_self_consistent == 1
    assert report.hashes_verified == 0
    assert any(i.category == "hash_mismatch" for i in report.issues)


def test_redacted_descriptor_is_not_counted_as_internally_consistent():
    # Only the displayed view can be recomputed; the original digest stays unchecked.
    tool = ToolComponent(
        bom_ref="tool:redacted",
        name="redacted",
        description_text="[REDACTED]",
        redacted_definition_hash=hash_tool_definition("redacted", "[REDACTED]"),
        definition_hash="sha256:" + "0" * 64,
        definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
    )
    report = IntegrityValidator().validate(AIBOM(components=[tool]))
    assert report.status == "unknown"
    assert report.tool_descriptors_self_consistent == 0
    assert report.hashes_verified == 0
    (issue,) = report.issues
    assert issue.category == "descriptor_source_unavailable"
    assert issue.severity == "unknown"
    assert issue.detail == (
        "Redacted representation matches; original descriptor requires matching source evidence"
    )


def test_validate_prints_no_workflow_command_from_a_supplied_bom_ref(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    ref = "tool:x\n::error::forged\r::warning::forged\u2028::notice::forged\x85##[error]forged"
    tool = ToolComponent(
        bom_ref=ref,
        name="x",
        description_text="d",
        definition_hash=hash_tool_definition("x", "d"),
        definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
    )
    path = tmp_path / "supplied.aibom.json"
    AIBOM(components=[tool]).save(path)
    result = CliRunner().invoke(main, ["validate", "--no-project-policy", str(path)])
    assert result.exit_code == 1, result.output
    lines = result.output.splitlines()
    assert any(line.startswith("  UNKNOWN [tool:x") for line in lines), result.output
    # The runner trims leading whitespace before "::" and finds "##[" anywhere.
    for line in lines:
        assert not line.lstrip().startswith("::"), line
        assert "##[" not in line, line
