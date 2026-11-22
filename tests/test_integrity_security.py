"""Security regressions covering real scanner/validator boundaries."""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from nexus_symbiote import limits
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

    def replace_after_inspection(inspected, **options):
        # The collector passes root-relative paths; replace the scanned file itself.
        observation = inspect(inspected, **options)
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
    digest = integrity._ArtifactDigests.digest

    def replace_before_hash(self, path, algorithm):
        path.write_bytes(replacement)
        return digest(self, path, algorithm)

    monkeypatch.setattr(integrity._ArtifactDigests, "digest", replace_before_hash)
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
    oversize = b"{" + b" " * MAX_MODEL_HEADER_BYTES + b"}"
    path.write_bytes(len(oversize).to_bytes(8, "little") + oversize)
    assert inspect_model_format(path) == (
        SerializationSafety.UNKNOWN,
        "SafeTensors header exceeds the inspection limit",
    )
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
    assert report.hashes_verified == 1
    assert report.hashes_failed == 0
    assert report.status == "pass"
    # Without the project, the descriptor only agrees with its own recorded digest.
    unbound = IntegrityValidator().validate(bom)
    assert unbound.hashes_verified == 0 and unbound.status == "unknown"


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


def test_model_hash_limit_is_explicit_missing_evidence(tmp_path):
    write_safetensors(tmp_path / "model.safetensors")
    with limits.applied(replace(limits.DEFAULTS, model_bytes=8)):
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


def test_current_version_tool_fingerprint_is_only_self_consistent_without_local_evidence():
    tool = ToolComponent(
        bom_ref="tool:current",
        name="current",
        description_text="read",
        definition_hash=hash_tool_definition("current", "read"),
        definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
    )
    report = IntegrityValidator().validate(AIBOM(components=[tool]))
    assert not report.is_valid and report.status == "unknown"
    assert report.hashes_verified == 0 and report.hashes_failed == 0
    assert [i.category for i in report.issues] == ["descriptor_source_unavailable"]


def test_supplementary_served_descriptor_cannot_turn_project_integrity_green(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "project"
    project.mkdir()
    server = {"command": "npx", "args": ["-y", "pinned-mcp@1.2.3"]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"pinned": server}}))
    target = tmp_path / "bom.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", "--report-only", str(project), "-o", str(target)])
    assert scan.exit_code == 0, scan.output
    args = ["validate", str(target), "--project", str(project), "--no-project-policy"]
    honest = runner.invoke(main, args)
    assert honest.exit_code == 1
    assert "No artifact hash or signature could be verified" in honest.output
    doc = json.loads(target.read_text())
    doc["components"].append(
        {
            "bom_ref": "tool:fabricated",
            "component_type": "tool",
            "name": "fabricated",
            "description_text": "d",
            "definition_hash": hash_tool_definition("fabricated", "d"),
            "definition_hash_version": TOOL_DEFINITION_HASH_VERSION,
            "claims": {
                "tool_definition": {
                    "method": "operator-pinned-stdio-tools-list",
                    "scope": "served-descriptor",
                    "assurance": "observed",
                }
            },
        }
    )
    target.write_text(json.dumps(doc))
    supplemented = runner.invoke(main, args)
    assert supplemented.exit_code == 1, supplemented.output
    assert "Hashes verified: 0" in supplemented.output


def _prompts_naming_one_file(tmp_path: Path, count: int) -> tuple[AIBOM, bytes]:
    content = b"Shared instructions.\n" * 1000
    (tmp_path / "shared.md").write_bytes(content)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    prompts = [
        PromptComponent(
            bom_ref=f"prompt:{index}",
            name="shared.md",
            source_path="shared.md",
            content_hash=digest,
        )
        for index in range(count)
    ]
    return AIBOM(components=prompts), content


def test_many_components_naming_one_artifact_read_it_once(tmp_path):
    bom, content = _prompts_naming_one_file(tmp_path, 1000)
    report = IntegrityValidator().validate(bom, tmp_path)
    assert report.status == "pass" and report.hashes_verified == 1000
    assert report.bytes_charged == len(content)


def test_case_variant_digest_keys_are_one_algorithm_and_one_read(tmp_path):
    write_safetensors(tmp_path / "model.safetensors")
    content = (tmp_path / "model.safetensors").read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    model = ModelComponent(
        bom_ref="model:m",
        name="m",
        source_path="model.safetensors",
        hashes={"sha256": digest, "SHA256": digest, "Sha256": digest},
    )
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=[model]), tmp_path
    )
    assert report.status == "fail"
    duplicates = [i for i in report.issues if "more than once" in i.detail]
    assert len(duplicates) == 2 and report.hashes_verified == 1
    assert {i.severity for i in duplicates} == {"error"}


def test_validation_byte_budget_fails_closed_with_a_reason(tmp_path):
    bom, content = _prompts_naming_one_file(tmp_path, 1)
    (tmp_path / "other.md").write_bytes(content)
    other = PromptComponent(
        bom_ref="prompt:other",
        name="other.md",
        source_path="other.md",
        content_hash=bom.components[0].content_hash,
    )
    bom.components.append(other)
    report = IntegrityValidator(byte_budget=len(content)).validate(bom, tmp_path)
    assert report.status == "unknown" and report.hashes_verified == 1
    (issue,) = [i for i in report.issues if i.category == "validation_budget_exhausted"]
    assert issue.component_ref == "prompt:other" and issue.severity == "unknown"


def test_repeated_models_are_inspected_once_and_fail_as_duplicates(tmp_path, monkeypatch):
    from nexus_symbiote.scanners import model

    path = tmp_path / "model.safetensors"
    write_safetensors(path, data=b"abcd" * 1024)
    size = path.stat().st_size
    inspected: list[Path] = []
    real_inspect = model.observe_model_artifact

    def inspect(artifact, **kwargs):
        inspected.append(artifact)
        return real_inspect(artifact, **kwargs)

    monkeypatch.setattr(model, "observe_model_artifact", inspect)
    models = [
        ModelComponent(bom_ref=f"model:{i}", name="m", source_path="model.safetensors")
        for i in range(50)
    ]
    report = IntegrityValidator(byte_budget=10 * size).validate(AIBOM(components=models), tmp_path)
    duplicates = [i for i in report.issues if i.category == "duplicate_artifact"]
    assert len(inspected) == 1 and report.bytes_charged == size
    assert len(duplicates) == 49 and {i.severity for i in duplicates} == {"error"}
    assert "model:0" not in {i.component_ref for i in duplicates}
    assert not [i for i in report.issues if i.category == "validation_budget_exhausted"]
    assert report.status == "fail"


def test_hosted_model_declarations_sharing_one_manifest_are_not_duplicates(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Read-only triage.")
    (project / "agent.yaml").write_text(
        "name: triage\ninstructions: [CLAUDE.md]\nmodels:\n"
        "  chat: {provider: example, requested_ref: latest}\n"
        "  embed: {provider: example, requested_ref: embed-v2}\n"
    )
    target = tmp_path / "bom.json"
    scan = CliRunner().invoke(
        main, ["scan", "--no-project-policy", str(project), "-o", str(target)]
    )
    assert scan.exit_code == 0, scan.output
    bom = AIBOM.load(target)
    hosted = [c for c in bom.components if isinstance(c, ModelComponent)]
    assert len(hosted) == 2 and {c.source_path for c in hosted} == {"agent.yaml"}
    report = IntegrityValidator().validate(bom, project)
    assert report.status == "unknown"
    assert not [i for i in report.issues if i.category == "duplicate_artifact"]


def _signed_weights(tmp_path: Path, bundle_bytes: bytes) -> tuple[Path, SigstoreArtifactPolicy]:
    weights = tmp_path / "weights"
    weights.mkdir()
    path = weights / "model.safetensors"
    write_safetensors(path)
    bundle = tmp_path / "model.sigstore"
    bundle.write_bytes(bundle_bytes)
    policy = SigstoreArtifactPolicy(
        path, bundle, "trusted@example.test", "https://issuer.example.test"
    )
    return path, policy


def test_one_signed_artifact_is_inspected_and_verified_once_however_it_is_named(
    tmp_path, monkeypatch
):
    from nexus_symbiote.scanners import model
    from nexus_symbiote.validators import integrity

    path, policy = _signed_weights(tmp_path, b"{" + b" " * 65536 + b"}")
    (tmp_path / "alias").symlink_to(path.parent, target_is_directory=True)
    verified: list[Path] = []
    inspected: list[Path] = []
    real_inspect = model.observe_model_artifact

    def verify(artifact, bundle, identity, issuer):
        verified.append(artifact)
        return VerificationResult(
            True, identity=identity, issuer=issuer, details={"artifact_digest": hash_file(artifact)}
        )

    def inspect(artifact, **kwargs):
        inspected.append(artifact)
        return real_inspect(artifact, **kwargs)

    monkeypatch.setattr(integrity, "verify_sigstore_bundle", verify)
    monkeypatch.setattr(model, "observe_model_artifact", inspect)
    spellings = [
        "weights/model.safetensors",
        "./weights/model.safetensors",
        "weights//model.safetensors",
        str(path),
        "alias/model.safetensors",
    ]
    models = [
        ModelComponent(
            bom_ref=f"model:{i}",
            name="m",
            source_path=spellings[i % len(spellings)],
            hashes={"sha256": hash_file(path)},
        )
        for i in range(1000)
    ]
    report = IntegrityValidator([policy]).validate(AIBOM(components=models), tmp_path)
    assert len(verified) == 1 and len(inspected) == 1
    assert report.signatures_checked == report.signatures_verified == 1
    duplicates = [i for i in report.issues if i.category == "duplicate_artifact"]
    assert len(duplicates) == 999 and report.status == "fail"
    size = path.stat().st_size
    bundle = policy.bundle_path.stat().st_size
    # Inspection, the verifier's own hash pass and the digest check each read the
    # weights once; the bundle and a fixed amount of verification work are charged too.
    assert report.bytes_charged == 3 * size + bundle + integrity.SIGNATURE_VERIFICATION_COST


def test_signature_verification_work_draws_on_the_validation_budget(tmp_path, monkeypatch):
    from nexus_symbiote.validators import integrity

    path, policy = _signed_weights(tmp_path, b"{}")
    calls: list[Path] = []
    monkeypatch.setattr(integrity, "verify_sigstore_bundle", lambda *args: calls.append(args[0]))
    model = ModelComponent(
        bom_ref="model:m",
        name="m",
        source_path="weights/model.safetensors",
        hashes={"sha256": hash_file(path)},
    )
    validator = IntegrityValidator([policy], byte_budget=integrity.SIGNATURE_VERIFICATION_COST)
    report = validator.validate(AIBOM(components=[model]), tmp_path)
    (issue,) = [i for i in report.issues if i.category == "validation_budget_exhausted"]
    assert issue.severity == "unknown" and not calls
    assert f"{integrity.SIGNATURE_VERIFICATION_COST:,} bytes" in issue.detail
    assert report.status == "unknown"


def test_a_digest_pin_is_charged_for_the_reads_it_needs_and_no_verification(tmp_path):
    from nexus_symbiote.utils.crypto import DigestPinPolicy, SignaturePolicySet

    path, _ = _signed_weights(tmp_path, b"{}")
    pin = DigestPinPolicy(path, hash_file(path))
    model = ModelComponent(
        bom_ref="model:m",
        name="m",
        source_path="weights/model.safetensors",
        hashes={"sha256": hash_file(path)},
    )
    validator = IntegrityValidator(SignaturePolicySet(digest_pins=[pin]))
    report = validator.validate(AIBOM(components=[model]), tmp_path)
    assert report.status == "pass" and report.signatures_checked == 0
    # The model check's observation and the digest check each read the weights once;
    # a pin is compared with the observed digest, so no bundle or verification work.
    assert report.bytes_charged == 2 * path.stat().st_size


def test_paths_the_readers_refuse_are_never_charged_to_the_budget(tmp_path):
    project = tmp_path / "project"
    (project / "real").mkdir(parents=True)
    outside = tmp_path / "outside.safetensors"
    write_safetensors(outside, data=b"\0" * 2_000_000)
    write_safetensors(project / "real" / "model.safetensors", data=b"\0" * 2_000_000)
    (project / "linked").symlink_to(project / "real", target_is_directory=True)
    for source in (str(outside), "linked/model.safetensors"):
        model = ModelComponent(bom_ref="model:m", name="m", source_path=source)
        report = IntegrityValidator(byte_budget=1_000_000).validate(
            AIBOM(components=[model]), project
        )
        assert report.bytes_charged == 0, source
        assert not [i for i in report.issues if i.category == "validation_budget_exhausted"]
        assert report.status != "pass"
    escaped = IntegrityValidator(byte_budget=1_000_000).validate(
        AIBOM(components=[ModelComponent(bom_ref="model:m", name="m", source_path=str(outside))]),
        project,
    )
    assert [i.category for i in escaped.issues if i.severity == "error"] == ["missing_artifact"]


def test_bound_imports_downgrade_only_evidence_the_import_could_not_carry(tmp_path):
    # A format without a structural validator: its unknown verdict is not a gap in
    # evidence the import could fill, so it still blocks.
    (tmp_path / "weights.h5").write_bytes(b"\0" * 64)
    imported = ModelComponent(
        bom_ref="shadowscan:m",
        name="m",
        source_path="weights.h5",
        properties={"collection_mode": "imported-unverified-report"},
    )
    report = IntegrityValidator().validate(
        AIBOM(components=[imported]), tmp_path, bound_imports=frozenset({"shadowscan:m"})
    )
    severities = {issue.category: issue.severity for issue in report.issues}
    assert severities["format_unverified"] == "unknown"
    assert severities["unverified_signature"] == "info"
    assert severities["missing_hash"] == "info"
    assert report.status == "unknown"


def test_bound_imports_keep_the_observed_unsafe_verdict_without_a_recorded_digest(tmp_path):
    # The import records no digest; the verdict comes from the local bytes all the same.
    (tmp_path / "weights.bin").write_bytes(b"\x80\x04N.")
    imported = ModelComponent(
        bom_ref="shadowscan:m",
        name="m",
        source_path="weights.bin",
        properties={"collection_mode": "imported-unverified-report"},
    )
    report = IntegrityValidator().validate(
        AIBOM(components=[imported]), tmp_path, bound_imports=frozenset({"shadowscan:m"})
    )
    severities = {issue.category: issue.severity for issue in report.issues}
    assert severities["unsafe_format"] == "critical"
    assert severities["format_unverified"] == "unknown"
    assert "format_subject_mismatch" not in severities
    assert report.status == "fail"


def test_issue_lists_are_bounded_but_the_verdict_counts_every_issue():
    from nexus_symbiote.validators.integrity import MAX_REPORTED_ISSUES

    tools = [ToolComponent(bom_ref=f"tool:{i}", name="t") for i in range(MAX_REPORTED_ISSUES)]
    tools.append(
        ToolComponent(
            bom_ref="tool:bad",
            name="bad",
            description_text="d",
            definition_hash="sha256:" + "0" * 64,
            definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
        )
    )
    report = IntegrityValidator().validate(AIBOM(components=tools))
    assert len(report.issues) == MAX_REPORTED_ISSUES and report.issues_omitted == 1
    assert report.status == "fail" and report.issues[0].component_ref == "tool:bad"
    assert report.to_dict()["issues_omitted"] == 1


def test_imported_model_and_tool_claims_are_judged_as_imported_after_reconciliation(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "project"
    (project / ".shadowscan").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("Use the configured tools.")
    report = {
        "version": "0.1.4",
        "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
        "stats": [{"errors": [], "skipped": False, "incomplete": False}],
        "findings": [
            {"id": "m1", "kind": "local-model", "surface": "endpoint"},
            {"id": "t1", "kind": "mcp-server", "resource_type": "mcp-tool", "surface": "code"},
        ],
    }
    (project / ".shadowscan/report.json").write_text(json.dumps(report))
    target = tmp_path / "bom.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", "--no-project-policy", str(project), "-o", str(target)])
    assert scan.exit_code == 0, scan.output
    bom = AIBOM.load(target)
    imported = {c.component_type.value for c in bom.components if c.bom_ref.startswith("shadow")}
    assert imported == {"model", "tool"}
    args = ["validate", str(target), "--project", str(project), "--no-project-policy"]
    reconciled = runner.invoke(main, args)
    assert reconciled.exit_code == 0, reconciled.output
    assert "Imported discovery claim without local evidence" in reconciled.output
    unreconciled = IntegrityValidator().validate(bom, project)
    assert unreconciled.status == "unknown"
    # A component merely labelled as imported is never exempt: only reconciliation binds it.
    forged = bom.model_copy(deep=True)
    model = next(c for c in forged.components if c.component_type.value == "model")
    model.serialization_safety = SerializationSafety.UNSAFE_CODE_EXECUTION
    target.write_text(forged.to_json())
    assert runner.invoke(main, args).exit_code == 1


def test_mcp_plus_instruction_file_passes_validate_project_while_mcp_only_remains_unknown(
    tmp_path,
):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "project"
    project.mkdir()
    server = {"command": "npx", "args": ["-y", "pinned-mcp@1.2.3"]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"pinned": server}}))
    runner = CliRunner()
    binding_env = {"NEXUS_SYMBIOTE_SOURCE_BINDING_KEY": "k" * 32}
    mcp_only_bom = tmp_path / "mcp-only.json"
    assert (
        runner.invoke(
            main,
            ["scan", "--report-only", "--no-project-policy", str(project), "-o", str(mcp_only_bom)],
            env=binding_env,
        ).exit_code
        == 0
    )
    mcp_only_val = runner.invoke(
        main,
        [
            "validate",
            str(mcp_only_bom),
            "--project",
            str(project),
            "--no-project-policy",
            "--json-output",
        ],
        env=binding_env,
    )
    assert mcp_only_val.exit_code == 1
    assert json.loads(mcp_only_val.stdout)["integrity"]["status"] == "unknown"

    # Adding an instruction file provides verifiable static artifact hash evidence and
    # allows validate --project to pass, matching docs/known-limitations.md.
    (project / "CLAUDE.md").write_text("Follow the repository instructions.\n")
    with_prompt_bom = tmp_path / "with-prompt.json"
    assert (
        runner.invoke(
            main,
            [
                "scan",
                "--report-only",
                "--no-project-policy",
                str(project),
                "-o",
                str(with_prompt_bom),
            ],
            env=binding_env,
        ).exit_code
        == 0
    )
    with_prompt_val = runner.invoke(
        main,
        [
            "validate",
            str(with_prompt_bom),
            "--project",
            str(project),
            "--no-project-policy",
            "--json-output",
        ],
        env=binding_env,
    )
    assert with_prompt_val.exit_code == 0, with_prompt_val.output
    report = json.loads(with_prompt_val.stdout)["integrity"]
    assert report["status"] == "pass"
    assert report["hashes_verified"] == 1


@pytest.mark.parametrize("filename", ["model.h5", "model.tflite", "model.mlmodel", "model.pte"])
def test_operator_digest_pin_does_not_bypass_format_unverified_on_non_safetensors_models(
    tmp_path, filename
):
    from nexus_symbiote.utils.crypto import DigestPinPolicy

    project = tmp_path / "project"
    project.mkdir()
    artifact = project / filename
    payload = b"non-inspected-weights-payload-bytes"
    artifact.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    comp = ModelComponent(
        bom_ref=f"model:{filename}",
        name=filename,
        source_path=filename,
        hashes={"sha256": f"sha256:{digest}"},
        serialization_safety=SerializationSafety.UNKNOWN,
    )
    unpinned = IntegrityValidator().validate(AIBOM(components=[comp]), project)
    assert unpinned.status == "unknown"

    pinned = IntegrityValidator(
        [DigestPinPolicy(artifact_path=artifact, expected_sha256=digest)]
    ).validate(AIBOM(components=[comp]), project)
    assert pinned.status == "unknown"
    assert not pinned.is_valid
    assert any(issue.category == "format_unverified" for issue in pinned.issues)
