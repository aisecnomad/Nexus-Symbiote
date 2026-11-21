"""Model collection binds every file a loader reads, and only operator policy verifies it."""

from __future__ import annotations

import functools
import hashlib
import json
import os
import pickle
import shutil
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import merge_collected
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety, TrustTier
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners import model as model_collector
from nexus_symbiote.scanners.model import ModelPackages, ModelScanner, inspect_model_format
from nexus_symbiote.signature_policy import SignaturePolicyError, load_signature_policies
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.crypto import (
    SIGSTORE_MISSING,
    DigestPinPolicy,
    SigstoreArtifactPolicy,
    VerificationResult,
)
from nexus_symbiote.validators.completeness import (
    CompletenessValidator,
    discovery_producer_problems,
)
from nexus_symbiote.validators.integrity import IntegrityValidator
from nexus_symbiote.validators.risk import RiskScorer
from tests.support import scaling_ratio


def write_safetensors(path: Path, data: bytes = b"abcd") -> None:
    header = {"w": {"dtype": "U8", "shape": [len(data)], "data_offsets": [0, len(data)]}}
    raw = json.dumps(header, separators=(",", ":")).encode()
    raw += b" " * (-len(raw) % 8)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(len(raw).to_bytes(8, "little") + raw + data)


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def scanned(scanner: ModelScanner, root: Path) -> AIBOM:
    """Model components as ``scan`` records them, with the collection claim reconciliation expects."""
    collected: dict[str, Any] = {}
    for component in scanner.scan(root).components:
        merge_collected(collected, component, scanner.name, None)
    return AIBOM(components=list(collected.values()))


# Minimal protobuf encoding for ONNX ModelProto fixtures.
def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        low, value = value & 0x7F, value >> 7
        out.append(low | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _field(number: int, payload: bytes | int) -> bytes:
    if isinstance(payload, int):
        return _varint(number << 3) + _varint(payload)
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def _entry(key: str, value: str) -> bytes:
    return _field(1, key.encode()) + _field(2, value.encode())


def onnx_tensor(name: str, location: str | None = None, *, external: bool = True) -> bytes:
    body = _field(1, 4) + _field(2, 1) + _field(8, name.encode())
    if location is None:
        return body + _field(9, b"\0" * 16)
    body += _field(13, _entry("location", location)) + _field(13, _entry("offset", "0"))
    return body + (_field(14, 1) if external else b"")


def onnx_model(*tensors: bytes, metadata: tuple[tuple[str, str], ...] = ()) -> bytes:
    graph = _field(2, b"graph") + b"".join(_field(5, tensor) for tensor in tensors)
    document = _field(1, 8) + _field(7, graph)
    return document + b"".join(_field(14, _entry(key, value)) for key, value in metadata)


def gguf_string(text: str) -> bytes:
    raw = text.encode()
    return len(raw).to_bytes(8, "little") + raw


def gguf(template: str | None = None, *, architecture: str = "llama") -> bytes:
    tokens = (8).to_bytes(4, "little") + (3).to_bytes(8, "little")
    tokens += b"".join(gguf_string(token) for token in ("<s>", "a", "b"))
    entries = [
        ("general.architecture", 8, gguf_string(architecture)),
        ("tokenizer.ggml.tokens", 9, tokens),
        ("general.file_type", 4, (15).to_bytes(4, "little")),
    ]
    if template is not None:
        entries.append(("tokenizer.chat_template", 8, gguf_string(template)))
    header = b"GGUF" + (3).to_bytes(4, "little") + (0).to_bytes(8, "little")
    header += len(entries).to_bytes(8, "little")
    for key, kind, value in entries:
        header += gguf_string(key) + kind.to_bytes(4, "little") + value
    return header + b"\0" * 32


def write_policy(directory: Path, records: list[dict], version: int = 2) -> Path:
    path = directory / "signers.json"
    path.write_text(json.dumps({"version": version, "artifacts": records}))
    return path


def pin(project: Path, relative: str) -> dict:
    return {
        "kind": "digest-pin",
        "artifact_path": relative,
        "expected_sha256": sha256(project / relative),
    }


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    return root


# Root-relative references --------------------------------------------------------


def test_model_records_are_root_relative_and_independent_of_checkout_location(tmp_path):
    first = tmp_path / "agent"
    write_safetensors(first / "model.safetensors")
    write_safetensors(first / "nested" / "deeper" / "weights.safetensors")
    (first / "nested" / "deeper" / "config.json").write_text('{"model_type": "x"}')
    second = tmp_path / "agent-ci"
    shutil.copytree(first, second)
    collected = ModelScanner().scan(first)
    moved = ModelScanner().scan(second)
    assert [c.model_dump(mode="json") for c in collected.components] == [
        c.model_dump(mode="json") for c in moved.components
    ]
    assert collected.surfaces_scanned == moved.surfaces_scanned
    refs = {c.bom_ref: c for c in collected.components}
    assert set(refs) == {"model:model.safetensors", "model:nested/deeper/weights.safetensors"}
    assert refs["model:model.safetensors"].source_path == "model.safetensors"
    assert (
        refs["model:nested/deeper/weights.safetensors"].name == "nested/deeper/weights.safetensors"
    )
    text = json.dumps([c.model_dump(mode="json") for c in collected.components])
    assert str(tmp_path) not in text + json.dumps(collected.surfaces_scanned)


def test_same_named_models_in_same_named_directories_are_distinct(project):
    for run in ("run1", "run2"):
        write_safetensors(project / run / "checkpoint-500" / "model.safetensors", run.encode())
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    assert sorted(c.bom_ref for c in result.components) == [
        "model:run1/checkpoint-500/model.safetensors",
        "model:run2/checkpoint-500/model.safetensors",
    ]
    bom = project.parent / "bom.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(bom)]
    )
    assert scanned.exit_code == 0, scanned.output
    assert "conflicting duplicate component" not in bom.read_text()


def test_failure_messages_name_root_relative_paths(project):
    write_safetensors(project / "models" / "big.safetensors")
    with limits.applied(replace(limits.DEFAULTS, model_bytes=8)):
        result = ModelScanner().scan(project)
    assert result.scan_failures
    assert all(str(project) not in failure for failure in result.scan_failures)
    assert any(failure.startswith("models/big.safetensors: ") for failure in result.scan_failures)


def test_inventory_from_another_location_reconciles(tmp_path):
    supplier = tmp_path / "supplier"
    write_safetensors(supplier / "models" / "m.safetensors")
    bom = scanned(ModelScanner(), supplier)
    consumer = tmp_path / "consumer"
    shutil.copytree(supplier, consumer)
    report = CompletenessValidator().validate_against_project(bom, consumer)
    assert not [issue for issue in report.issues if "model" in issue.surface]


def test_agent_manifest_model_path_matches_collected_models(tmp_path, project):
    (project / "instructions.md").write_text("Read-only triage instructions.\n")
    write_safetensors(project / "models" / "weights.safetensors")
    (project / "agent.yaml").write_text(
        "id: acme:triager\nname: triager\nversion: '1.0'\npurpose: Security triage\n"
        "owner: security\nframework: custom\ninstructions: [instructions.md]\n"
        "models:\n  local:\n    path: models\n"
    )
    bom = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(bom)]
    )
    assert result.exit_code == 0, result.output
    components = json.loads(bom.read_text())["components"]
    (agent,) = [c for c in components if c["component_type"] == "agent"]
    assert "model:models/weights.safetensors" in agent["model_refs"]


# Multi-file weights ---------------------------------------------------------------


def test_onnx_external_data_is_bound_and_a_swap_fails_integrity(project):
    graph = project / "export" / "model.onnx"
    graph.parent.mkdir()
    graph.write_bytes(onnx_model(onnx_tensor("w", "model.onnx_data"), onnx_tensor("b")))
    weights = graph.with_name("model.onnx_data")
    weights.write_bytes(b"reviewed weights")
    before = ModelScanner().scan(project)
    assert not before.scan_failures
    (component,) = before.components
    assert component.properties["weight_files"] == [
        {"path": "export/model.onnx_data", "sha256": sha256(weights)}
    ]
    assert "export/model.onnx_data" in before.surfaces_scanned
    weights.write_bytes(b"backdoored weights")
    after = ModelScanner().scan(project).components[0]
    assert after.properties["weight_files"] != component.properties["weight_files"]
    assert after.hashes == component.hashes
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=[component]), project
    )
    assert report.status == "fail"
    assert any(issue.category == "weight_files_mismatch" for issue in report.issues)


@pytest.mark.parametrize("location", ["../outside.bin", "/etc/passwd", "missing.bin", "a\\b"])
def test_onnx_external_data_outside_or_missing_is_a_failure(project, location):
    (project / "model.onnx").write_bytes(onnx_model(onnx_tensor("w", location)))
    result = ModelScanner().scan(project)
    assert result.scan_failures == [
        "model.onnx: ONNX external data reference is missing or outside the model directory"
    ]


def test_onnx_location_of_an_embedded_tensor_is_not_external(project):
    (project / "model.onnx").write_bytes(onnx_model(onnx_tensor("w", "x.bin", external=False)))
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    assert "weight_files" not in result.components[0].properties


def test_onnx_location_keys_outside_parsed_fields_fail_closed(project):
    hidden = _field(99, _field(13, _entry("location", "model.onnx_data")))
    (project / "model.onnx").write_bytes(onnx_model(onnx_tensor("w")) + hidden)
    (project / "model.onnx_data").write_bytes(b"weights")
    result = ModelScanner().scan(project)
    assert result.scan_failures == [
        "model.onnx: ONNX file holds an external-data key outside the parsed graph; "
        "external weight files are unknown"
    ]
    metadata = onnx_model(onnx_tensor("w"), metadata=(("location", "Paris"),))
    (project / "model.onnx").write_bytes(metadata)
    assert not ModelScanner().scan(project).scan_failures


def test_one_inspection_budget_bounds_all_files_of_a_scan(project, monkeypatch):
    monkeypatch.setattr("nexus_symbiote.utils.model_formats.MAX_INSPECTION_UNITS", 60)
    for name in ("a", "b"):
        (project / name).mkdir()
        tensors = [onnx_tensor(f"w{i}", "data.bin") for i in range(4)]
        (project / name / "model.onnx").write_bytes(onnx_model(*tensors))
        (project / name / "data.bin").write_bytes(b"weights")
    (project / "c").mkdir()
    (project / "c" / "model.onnx").write_bytes(
        onnx_model(*[onnx_tensor(f"t{i}") for i in range(9)])
    )
    result = ModelScanner().scan(project)
    assert result.scan_failures == [
        "b/model.onnx: ONNX graph exceeds the inspection limits; external weight files are unknown"
    ]
    weights = {c.bom_ref: c.properties.get("weight_files") for c in result.components}
    assert weights["model:a/model.onnx"] is not None
    assert weights["model:c/model.onnx"] is None


@pytest.mark.parametrize(
    ("content", "failed"),
    [
        (b"model bytes", False),
        (b"\x7f\x7f\x0a\x08location", True),
        (b"\x0a\x88\x00location\x00", True),
        # Not even a key encoding: an unreadable file fails on the bytes alone.
        (b"\x7f doc: location", True),
    ],
)
def test_unparseable_onnx_fails_only_when_it_names_external_data(project, content, failed):
    (project / "model.onnx").write_bytes(content)
    result = ModelScanner().scan(project)
    assert bool(result.scan_failures) is failed
    assert result.components[0].serialization_safety == SerializationSafety.UNKNOWN


def test_savedmodel_variables_and_assets_are_bound(project):
    export = project / "export"
    (export / "variables").mkdir(parents=True)
    (export / "assets").mkdir()
    (export / "saved_model.pb").write_bytes(b"\x08\x01")
    data = export / "variables" / "variables.data-00000-of-00001"
    data.write_bytes(b"reviewed")
    (export / "variables" / "variables.index").write_bytes(b"index")
    (export / "assets" / "vocab.txt").write_text("a\n")
    (export / "fingerprint.pb").write_bytes(b"f")
    (export / "README.md").write_text("not a weight file")
    component = ModelScanner().scan(project).components[0]
    assert [item["path"] for item in component.properties["weight_files"]] == [
        "export/assets/vocab.txt",
        "export/fingerprint.pb",
        "export/variables/variables.data-00000-of-00001",
        "export/variables/variables.index",
    ]
    data.write_bytes(b"backdoor")
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=[component]), project
    )
    assert any(issue.category == "weight_files_mismatch" for issue in report.issues)


def test_a_linked_savedmodel_directory_binds_its_files_and_fails_closed(tmp_path, project):
    # A loader reads export/variables/* through the link; the walk lists shared/* only.
    (project / "export").mkdir()
    (project / "shared").mkdir()
    (project / "export" / "saved_model.pb").write_bytes(b"\x08\x01")
    (project / "shared" / "variables.index").write_bytes(b"index")
    (project / "shared" / "variables.data-00000-of-00001").write_bytes(b"reviewed")
    (project / "export" / "variables").symlink_to("../shared", target_is_directory=True)
    policies = load_signature_policies(
        write_policy(tmp_path, [pin(project, "export/saved_model.pb")]), project
    )
    result = ModelScanner(policies).scan(project)
    refused = "hash refused (symlink, nonregular file or I/O error)"
    assert result.scan_failures == [
        f"export/variables/variables.data-00000-of-00001: {refused}",
        f"export/variables/variables.index: {refused}",
    ]
    (component,) = result.components
    assert component.signing_status == "partially-verified"
    assert component.trust_tier == TrustTier.UNKNOWN
    package = ModelPackages(project.resolve()).observe(Path("export/saved_model.pb"))
    assert [path.as_posix() for path, _ in package.weight_files] == [
        "export/saved_model.pb",
        "export/variables/variables.data-00000-of-00001",
        "export/variables/variables.index",
    ]
    assert not package.complete


@pytest.mark.parametrize("name", ["Variables/variables.index", "Fingerprint.pb"])
def test_a_case_variant_of_a_savedmodel_name_is_a_failure(project, name):
    export = project / "export"
    (export / name).parent.mkdir(parents=True, exist_ok=True)
    (export / "saved_model.pb").write_bytes(b"\x08\x01")
    (export / name).write_bytes(b"weights")
    variant = name.partition("/")[0]
    result = ModelScanner().scan(project)
    assert result.scan_failures == [
        f"export/{variant}: case variant of export/{variant.lower()} is the active file on "
        "case-insensitive file systems and is not inventoried"
    ]
    assert not ModelPackages(project.resolve()).observe(Path("export/saved_model.pb")).complete


def test_savedmodel_files_are_listed_once_for_every_model_in_a_directory(project, monkeypatch):
    export = project / "export"
    (export / "variables").mkdir(parents=True)
    (export / "variables" / "variables.index").write_bytes(b"index")
    (export / "saved_model.pb").write_bytes(b"\x08\x01")
    (export / "saved_model.pbtxt").write_text("meta_graphs {}\n")
    variables = Path("export/variables")
    listings: list[Path] = []
    below = model_collector.ModelTree.below

    def counted(tree: model_collector.ModelTree, directory: Path) -> list[Path]:
        if directory == variables:
            listings.append(directory)
        return below(tree, directory)

    monkeypatch.setattr(model_collector.ModelTree, "below", counted)
    components = ModelScanner().scan(project).components
    assert [c.properties["weight_files"][0]["path"] for c in components] == [
        "export/variables/variables.index"
    ] * 2
    assert listings == [variables]
    listings.clear()
    packages = ModelPackages(project.resolve())
    for component in components:
        assert packages.observe(Path(component.name)).complete
    assert listings == [variables]


def test_shard_index_is_bound_to_every_shard_it_lists(project):
    model = project / "llm"
    write_safetensors(model / "model-00001-of-00002.safetensors", b"aa")
    write_safetensors(model / "model-00002-of-00002.safetensors", b"bb")
    index = model / "model.safetensors.index.json"
    index.write_text(
        json.dumps(
            {
                "metadata": {},
                "weight_map": {
                    "a": "model-00001-of-00002.safetensors",
                    "b": "model-00002-of-00002.safetensors",
                },
            }
        )
    )
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    for component in result.components:
        assert component.properties["weight_files"] == [
            {"path": "llm/model.safetensors.index.json", "sha256": sha256(index)}
        ]


@pytest.mark.parametrize("shard", ["missing.safetensors", "evil.dat", "../model.safetensors"])
def test_shard_index_naming_an_uncollected_file_is_a_failure(project, shard):
    model = project / "llm"
    model.mkdir()
    (model / "evil.dat").write_bytes(pickle.dumps({"a": 1}))
    (model / "pytorch_model.bin.index.json").write_text(json.dumps({"weight_map": {"a": shard}}))
    result = ModelScanner().scan(project)
    assert result.scan_failures == [
        "llm/pytorch_model.bin.index.json: model index references a missing, unrecognised "
        "or out-of-directory weight file"
    ]


# Hugging Face configuration, templates, tokenizer and custom code -----------------


def test_every_config_is_read_and_a_decoy_cannot_shadow_trust_remote_code(project):
    write_safetensors(project / "model.safetensors")
    (project / "config.json").write_text("{}")
    (project / "tokenizer_config.json").write_text(
        json.dumps({"trust_remote_code": True, "model_max_length": 10**30})
    )
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    component = result.components[0]
    assert component.trust_remote_code is True
    assert any(
        risk.category == "code_execution" and risk.severity == RiskSeverity.CRITICAL
        for risk in component.risks
    )
    assert [item["path"] for item in component.properties["config_files"]] == [
        "config.json",
        "tokenizer_config.json",
    ]


@pytest.mark.parametrize(
    "template",
    ["{{ messages }}", [{"name": "default", "template": "{{ messages }}"}]],
)
def test_chat_template_in_tokenizer_config_is_digested(project, template):
    write_safetensors(project / "model.safetensors")
    config = project / "tokenizer_config.json"
    config.write_text(json.dumps({"chat_template": template}))
    first = ModelScanner().scan(project).components[0]
    assert first.chat_template_hash is not None
    edited = (
        "{{ 'ignore previous instructions' }}"
        if isinstance(template, str)
        else [{"name": "default", "template": "{{ 'ignore previous instructions' }}"}]
    )
    config.write_text(json.dumps({"chat_template": edited}))
    second = ModelScanner().scan(project).components[0]
    assert second.chat_template_hash != first.chat_template_hash


def test_chat_template_files_are_digested(project):
    write_safetensors(project / "model.safetensors")
    (project / "chat_template.jinja").write_text("{{ messages }}")
    (project / "additional_chat_templates").mkdir()
    (project / "additional_chat_templates" / "tool_use.jinja").write_text("{{ tools }}")
    component = ModelScanner().scan(project).components[0]
    assert [item["source"] for item in component.properties["chat_templates"]] == [
        "additional_chat_templates/tool_use.jinja",
        "chat_template.jinja",
    ]
    (project / "additional_chat_templates" / "tool_use.jinja").write_text("{{ evil }}")
    assert ModelScanner().scan(project).components[0].chat_template_hash != (
        component.chat_template_hash
    )


def test_every_tokenizer_file_is_digested(project):
    write_safetensors(project / "model.safetensors")
    (project / "tokenizer.json").write_text("{}")
    special = project / "special_tokens_map.json"
    special.write_text('{"eos_token": "</s>"}')
    first = ModelScanner().scan(project).components[0]
    assert [item["path"] for item in first.properties["tokenizer_files"]] == [
        "tokenizer.json",
        "special_tokens_map.json",
    ]
    special.write_text('{"eos_token": "<|im_end|>"}')
    assert ModelScanner().scan(project).components[0].tokenizer_hash != first.tokenizer_hash


def test_auto_map_custom_code_is_a_high_finding_with_digested_modules(project):
    write_safetensors(project / "model.safetensors")
    (project / "config.json").write_text(
        json.dumps({"auto_map": {"AutoModel": "modeling_x.XModel"}})
    )
    module = project / "modeling_x.py"
    module.write_text("import os\n")
    component = ModelScanner().scan(project).components[0]
    assert component.trust_remote_code is None
    (risk,) = [risk for risk in component.risks if risk.category == "custom_code"]
    assert risk.severity == RiskSeverity.HIGH
    assert "another repository" not in risk.detail
    assert component.properties["custom_code"] == {
        "declared_in": ["config.json"],
        "references": ["modeling_x.XModel"],
        "cross_repository": False,
        "python_files": [{"path": "modeling_x.py", "sha256": sha256(module)}],
    }
    module.write_text("import os\nos.system('id')\n")
    edited = ModelScanner().scan(project).components[0]
    assert edited.properties["custom_code"] != component.properties["custom_code"]


def test_cross_repository_auto_map_is_named_in_the_finding(project):
    write_safetensors(project / "model.safetensors")
    (project / "tokenizer_config.json").write_text(
        json.dumps({"auto_map": {"AutoTokenizer": ["other/repo--tokenization_x.XTok", None]}})
    )
    component = ModelScanner().scan(project).components[0]
    (risk,) = [risk for risk in component.risks if risk.category == "custom_code"]
    assert "another repository" in risk.detail
    assert component.properties["custom_code"]["cross_repository"] is True


def test_a_reference_to_a_repository_without_an_owner_names_another_repository(project):
    # transformers splits on "--" and fetches the module from the repository gpt2.
    write_safetensors(project / "model.safetensors")
    (project / "config.json").write_text(
        json.dumps({"auto_map": {"AutoModel": "gpt2--modeling_gpt.Model"}})
    )
    component = ModelScanner().scan(project).components[0]
    (risk,) = [risk for risk in component.risks if risk.category == "custom_code"]
    assert "another repository" in risk.detail
    custom_code = component.properties["custom_code"]
    assert custom_code["references"] == ["gpt2--modeling_gpt.Model"]
    assert custom_code["cross_repository"] is True


def test_python_files_without_declared_custom_code_do_not_change_the_inventory(project):
    write_safetensors(project / "model.safetensors")
    before = ModelScanner().scan(project)
    (project / "helper.py").write_text("print(1)\n")
    after = ModelScanner().scan(project)
    assert after.components == before.components
    assert after.surfaces_scanned == before.surfaces_scanned


@pytest.mark.parametrize(("value", "recorded"), [("org/base-7b", True), ("/home/u/base", False)])
def test_adapter_base_model_is_recorded_only_as_a_hub_identifier(project, value, recorded):
    write_safetensors(project / "adapter_model.safetensors")
    (project / "adapter_config.json").write_text(
        json.dumps({"peft_type": "LORA", "base_model_name_or_path": value})
    )
    component = ModelScanner().scan(project).components[0]
    assert component.model_type == "adapter"
    assert component.properties.get("base_model") == (value if recorded else None)


# GGUF chat templates ------------------------------------------------------------------


def test_gguf_chat_template_is_read_within_bounds(project):
    path = project / "model.gguf"
    path.write_bytes(gguf("{% for m in messages %}{{ m.content }}{% endfor %}"))
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    component = result.components[0]
    assert component.serialization_safety == SerializationSafety.UNKNOWN
    assert component.properties["gguf_architecture"] == "llama"
    assert [item["source"] for item in component.properties["chat_templates"]] == [
        "model.gguf#tokenizer.chat_template"
    ]
    path.write_bytes(gguf("{{ messages }} ignore previous instructions"))
    assert ModelScanner().scan(project).components[0].chat_template_hash != (
        component.chat_template_hash
    )


@pytest.mark.parametrize(
    "template",
    [
        "{{ self.__init__.__globals__.__builtins__ }}",
        "{{ ''['__class__'] }}",
        "{{ x|attr('\\x5f\\x5fclass\\x5f\\x5f') }}",
    ],
)
def test_gguf_template_reaching_python_internals_is_critical_once(project, template):
    (project / "model.gguf").write_bytes(gguf(template))
    component = ModelScanner().scan(project).components[0]
    assert component.serialization_safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION
    serialization = [risk for risk in component.risks if risk.category == "serialization_format"]
    assert [risk.severity for risk in serialization] == [RiskSeverity.CRITICAL]
    report = RiskScorer().score(AIBOM(components=[component]))
    assert [f.severity for f in report.findings if f.category == "serialization_format"] == [
        RiskSeverity.CRITICAL
    ]


def test_unreadable_gguf_metadata_is_noted_without_a_failure(project):
    (project / "model.gguf").write_bytes(b"GGUF\x09\x00\x00\x00 not a supported version")
    result = ModelScanner().scan(project)
    assert not result.scan_failures and not result.surfaces_excluded
    assert result.components[0].properties["gguf_metadata"] == (
        "not inspected: GGUF metadata could not be read"
    )


def test_gguf_metadata_beyond_the_bounds_is_a_coverage_gap(project, monkeypatch):
    # A sandbox-escape template behind more metadata than the bounds allow.
    monkeypatch.setattr("nexus_symbiote.utils.model_formats.MAX_INSPECTION_UNITS", 2)
    (project / "model.gguf").write_bytes(gguf("{{ x.__class__ }}"))
    result = ModelScanner().scan(project)
    assert result.surfaces_excluded == [
        "model.gguf: GGUF chat templates not inspected: GGUF metadata exceeds the inspection limits"
    ]
    assert result.components[0].serialization_safety == SerializationSafety.UNKNOWN


# Format detection ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["checkpoint.pth.tar", "model.pkl.gz", "model.dill", "weights.pck"]
)
def test_common_pickle_names_are_inventoried_as_code_executing(project, name):
    (project / name).write_bytes(pickle.dumps({"weights": [0.0]}))
    (component,) = ModelScanner().scan(project).components
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION


@pytest.mark.parametrize("protocol", [0, 1])
def test_text_protocol_pickle_behind_another_suffix_is_unsafe(project, protocol):
    (project / "model.onnx").write_bytes(pickle.dumps({"weights": [0.0]}, protocol=protocol))
    component = ModelScanner().scan(project).components[0]
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert "text-protocol pickle" in component.properties["format_inspection"]


def test_a_malformed_pickle_behind_another_suffix_is_unknown(project):
    # NEWOBJ pops the MARK's object, so pickletools.dis pops past the stack at APPENDS.
    (project / "model.onnx").write_bytes(b"\x80\x02(K\x01\x81e.")
    write_safetensors(project / "model.safetensors")
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    assert [c.serialization_safety for c in result.components] == [
        SerializationSafety.UNKNOWN,
        SerializationSafety.SAFE,
    ]
    assert ModelPackages(project).observe(Path("model.onnx")).complete


def test_torch_zip_checkpoint_behind_another_suffix_is_unsafe(project):
    with zipfile.ZipFile(project / "model.gguf", "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"weights": [0.0]}))
        archive.writestr("archive/version", "3")
    component = ModelScanner().scan(project).components[0]
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION


def _critical_serialization_finding(component) -> bool:
    return any(
        risk.category == "serialization_format" and risk.severity == RiskSeverity.CRITICAL
        for risk in component.risks
    )


def test_torch_zip_with_the_pickle_after_another_member_is_unsafe(project):
    # torch.save may write archive/version first; the central directory still lists data.pkl.
    with zipfile.ZipFile(project / "model.onnx", "w") as archive:
        archive.writestr("archive/version", "3")
        archive.writestr("archive/data.pkl", pickle.dumps({"weights": [0.0]}))
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    component = result.components[0]
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert "ZIP archive" in component.properties["format_inspection"]
    assert _critical_serialization_finding(component)


def test_a_zip_with_many_members_before_the_pickle_is_unsafe(project):
    with zipfile.ZipFile(project / "model.safetensors", "w") as archive:
        for index in range(3000):
            archive.writestr(f"archive/data/{index}", b"\0" * 8)
        archive.writestr("archive/data.pkl", pickle.dumps({"weights": [0.0]}))
    component = ModelScanner().scan(project).components[0]
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION


def test_a_zip_without_a_pickle_member_behind_another_suffix_stays_unknown(project):
    with zipfile.ZipFile(project / "model.onnx", "w") as archive:
        archive.writestr("archive/version", "3")
        archive.writestr("archive/data/0", b"\0" * 8)
    result = ModelScanner().scan(project)
    component = result.components[0]
    assert component.serialization_safety == SerializationSafety.UNKNOWN
    assert "lists no pickle member" in component.properties["format_inspection"]
    assert not result.scan_failures
    with zipfile.ZipFile(project / "model.gguf", "w") as archive:
        archive.writestr("archive/version", "3")
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    gguf = next(c for c in result.components if c.name.endswith("model.gguf"))
    assert gguf.serialization_safety == SerializationSafety.UNKNOWN
    assert gguf.properties["gguf_metadata"] == "not inspected: the file is a ZIP archive"


def test_a_padded_binary_pickle_behind_another_suffix_is_unsafe(project):
    # More than 4,096 well-formed opcodes before GLOBAL os.system and REDUCE.
    payload = b"\x80\x04" + b"N0" * 2100 + b"cos\nsystem\n(S'id'\ntR."
    (project / "model.onnx").write_bytes(payload)
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    component = result.components[0]
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert "binary pickle" in component.properties["format_inspection"]
    assert _critical_serialization_finding(component)


def test_a_pickle_longer_than_the_inspected_sample_is_unsafe(project):
    from nexus_symbiote.scanners.model import MAX_PICKLE_INSPECTION_BYTES

    payload = b"\x80\x04" + b"N0" * MAX_PICKLE_INSPECTION_BYTES + b"cos\nsystem\n(S'id'\ntR."
    (project / "model.gguf").write_bytes(payload)
    component = ModelScanner().scan(project).components[0]
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION


def test_a_plain_onnx_file_stays_unknown(project):
    (project / "model.onnx").write_bytes(onnx_model(onnx_tensor("w")))
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    assert result.components[0].serialization_safety == SerializationSafety.UNKNOWN


def test_keras_archive_is_not_mistaken_for_a_pickle(project):
    with zipfile.ZipFile(project / "model.keras", "w") as archive:
        archive.writestr("metadata.json", "{}")
        archive.writestr("config.json", "{}")
    assert ModelScanner().scan(project).components[0].serialization_safety == (
        SerializationSafety.UNKNOWN
    )


def test_unreadable_pickle_keeps_its_code_executing_rating(project):
    (project / "model.pkl").write_bytes(pickle.dumps(list(range(100))))
    with limits.applied(replace(limits.DEFAULTS, model_bytes=8)):
        result = ModelScanner().scan(project)
    assert result.scan_failures
    component = result.components[0]
    assert component.hashes == {}
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert any(risk.severity == RiskSeverity.CRITICAL for risk in component.risks)


@pytest.mark.parametrize("name", ["model.tflite", "model.mlmodel", "program.pte"])
def test_other_model_formats_are_inventoried_as_unknown(project, name):
    (project / name).write_bytes(b"\x18\x00\x00\x00TFL3")
    component = ModelScanner().scan(project).components[0]
    assert component.serialization_safety == SerializationSafety.UNKNOWN


# SafeTensors: one validator -------------------------------------------------------------


def test_utf16_safetensors_header_is_not_safe(project):
    header = json.dumps({"w": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}})
    raw = header.encode("utf-16-le")
    path = project / "model.safetensors"
    path.write_bytes(len(raw).to_bytes(8, "little") + raw + b"a")
    assert raw.startswith(b"{")
    assert inspect_model_format(path)[0] == SerializationSafety.UNKNOWN


def test_scan_and_validate_agree_on_a_zero_element_tensor(project):
    header = {"t": {"dtype": "U8", "shape": [0, 6_000_000_000], "data_offsets": [0, 0]}}
    raw = json.dumps(header, separators=(",", ":")).encode()
    (project / "model.safetensors").write_bytes(len(raw).to_bytes(8, "little") + raw)
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    (component,) = result.components
    assert component.serialization_safety == SerializationSafety.SAFE
    assert component.tensor_inventory_hash is not None
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=[component]), project
    )
    assert report.status == "pass", report.to_dict()


def test_oversized_safetensors_header_has_its_own_explanation(project):
    from nexus_symbiote.scanners.model import MAX_MODEL_HEADER_BYTES

    raw = b"{" + b" " * MAX_MODEL_HEADER_BYTES + b"}"
    path = project / "model.safetensors"
    path.write_bytes(len(raw).to_bytes(8, "little") + raw)
    assert inspect_model_format(path) == (
        SerializationSafety.UNKNOWN,
        "SafeTensors header exceeds the inspection limit",
    )


# Operator signature policy: kinds, location and evidence -------------------------------


def test_version_two_digest_pin_verifies_a_model_and_records_evidence(tmp_path, project):
    write_safetensors(project / "models" / "m.safetensors")
    policy = write_policy(tmp_path, [pin(project, "models/m.safetensors")])
    policies = load_signature_policies(policy, project)
    assert list(policies) == [] and len(policies.digest_pins) == 1
    result = ModelScanner(policies).scan(project)
    assert not result.scan_failures
    (component,) = result.components
    assert component.signing_status == "digest-pinned"
    assert component.trust_tier == TrustTier.INTERNAL_VERIFIED
    assert not any(risk.category == "signing_status" for risk in component.risks)
    evidence = component.claims["signing_status"]
    assert evidence.method == "digest-pin"
    assert evidence.assurance.value == "verified"
    assert f"policy:{sha256(policy)}" in evidence.evidence_refs
    assert (
        f"digest-pin:models/m.safetensors@{sha256(project / 'models/m.safetensors')}"
        in evidence.evidence_refs
    )
    report = IntegrityValidator(policies).validate(AIBOM(components=[component]), project)
    assert report.status == "pass", report.to_dict()


def test_a_digest_pin_rejects_other_bytes(tmp_path, project):
    path = project / "m.safetensors"
    write_safetensors(path)
    policies = load_signature_policies(
        write_policy(tmp_path, [pin(project, "m.safetensors")]), project
    )
    write_safetensors(path, b"evil")
    component = ModelScanner(policies).scan(project).components[0]
    assert component.signing_status == "verification-failed"
    assert component.claims["signing_status"].unknown_reason == (
        "m.safetensors: Artifact differs from the operator digest pin"
    )
    report = IntegrityValidator(policies).validate(AIBOM(components=[component]), project)
    assert any(issue.category == "signature_verification_failed" for issue in report.issues)


def _verified(policy_identity: str, issuer: str):
    def verify(artifact, bundle, identity, expected_issuer):
        return VerificationResult(
            True,
            identity=identity,
            issuer=expected_issuer,
            details={"artifact_digest": sha256(artifact), "bundle_digest": "sha256:" + "b" * 64},
        )

    return verify


def test_same_signer_substitution_fails_with_an_expected_digest(tmp_path, project, monkeypatch):
    path = project / "m.safetensors"
    write_safetensors(path)
    (project / "m.safetensors.sigstore").write_text("{}")
    record = {
        "kind": "sigstore-message-signature",
        "artifact_path": "m.safetensors",
        "bundle_path": "m.safetensors.sigstore",
        "expected_identity": "release@example.test",
        "expected_issuer": "https://issuer.example.test",
        "expected_sha256": sha256(path),
    }
    policies = load_signature_policies(write_policy(tmp_path, [record]), project)
    verify = _verified("release@example.test", "https://issuer.example.test")
    monkeypatch.setattr("nexus_symbiote.scanners.model.verify_sigstore_bundle", verify)
    signed = ModelScanner(policies).scan(project).components[0]
    assert signed.signing_status == "sigstore-signed"
    assert signed.trust_tier == TrustTier.THIRD_PARTY_SIGNED
    refs = signed.claims["signing_status"].evidence_refs
    assert "issuer:https://issuer.example.test" in refs
    assert "bundle:m.safetensors.sigstore@sha256:" + "b" * 64 in refs
    # An older release signed by the same identity verifies, but not against the pin.
    write_safetensors(path, b"old!")
    substituted = ModelScanner(policies).scan(project).components[0]
    assert substituted.signing_status == "verification-failed"
    assert substituted.claims["signing_status"].unknown_reason == (
        "m.safetensors: Signed artifact differs from the operator digest pin"
    )


def test_every_weight_file_must_be_covered(tmp_path, project):
    graph = project / "model.onnx"
    graph.write_bytes(onnx_model(onnx_tensor("w", "model.onnx_data")))
    (project / "model.onnx_data").write_bytes(b"weights")
    policies = load_signature_policies(
        write_policy(tmp_path, [pin(project, "model.onnx")]), project
    )
    component = ModelScanner(policies).scan(project).components[0]
    assert component.signing_status == "partially-verified"
    report = IntegrityValidator(policies).validate(AIBOM(components=[component]), project)
    assert any(
        issue.detail == "No trusted signer policy entry covers weight file model.onnx_data"
        for issue in report.issues
    )
    both = write_policy(tmp_path, [pin(project, "model.onnx"), pin(project, "model.onnx_data")])
    covered = ModelScanner(load_signature_policies(both, project)).scan(project)
    assert covered.components[0].signing_status == "digest-pinned"


def test_missing_sigstore_install_is_its_own_status_and_failure(project, monkeypatch):
    write_safetensors(project / "m.safetensors")
    policy = SigstoreArtifactPolicy(
        project / "m.safetensors", project / "m.sigstore", "id@example.test", "https://i.test"
    )
    monkeypatch.setattr(
        "nexus_symbiote.scanners.model.verify_sigstore_bundle",
        lambda *args: VerificationResult(False, error=SIGSTORE_MISSING),
    )
    result = ModelScanner([policy]).scan(project)
    assert result.components[0].signing_status == "verification-unavailable"
    assert result.scan_failures == [f"m.safetensors: {SIGSTORE_MISSING}"]


def test_unused_policy_entries_are_collection_failures(tmp_path, project):
    write_safetensors(project / "m.safetensors")
    (project / "tokenizer.json").write_text("{}")
    policy = write_policy(tmp_path, [pin(project, "m.safetensors"), pin(project, "tokenizer.json")])
    result = ModelScanner(load_signature_policies(policy, project)).scan(project)
    assert result.scan_failures == [
        "tokenizer.json: signature policy entry names no collected model weight file"
    ]


def test_a_signature_entry_for_the_discovery_report_is_not_unused(tmp_path, project):
    (project / ".shadowscan").mkdir()
    (project / ".shadowscan" / "report.json").write_text("{}")
    (project / ".shadowscan" / "report.json.sigstore").write_text("{}")
    record = {
        "artifact_path": ".shadowscan/report.json",
        "bundle_path": ".shadowscan/report.json.sigstore",
        "expected_identity": "discovery@example.test",
        "expected_issuer": "https://issuer.example.test",
    }
    policies = load_signature_policies(write_policy(tmp_path, [record], version=1), project)
    assert not ModelScanner(policies).scan(project).scan_failures
    pinned = write_policy(tmp_path, [pin(project, ".shadowscan/report.json")])
    assert ModelScanner(load_signature_policies(pinned, project)).scan(project).scan_failures == [
        ".shadowscan/report.json: the ShadowScan report needs a sigstore-message-signature "
        "entry; a digest pin does not authenticate its producer"
    ]


def test_an_entry_for_a_report_location_the_importer_skips_is_unused(tmp_path, project):
    # The importer reads the first report location that exists, never this one.
    (project / ".shadowscan").mkdir()
    (project / ".shadowscan" / "report.json").write_text("{}")
    (project / "shadowscan.json").write_text("{}")
    (project / "shadowscan.json.sigstore").write_text("{}")
    record = {
        "artifact_path": "shadowscan.json",
        "bundle_path": "shadowscan.json.sigstore",
        "expected_identity": "discovery@example.test",
        "expected_issuer": "https://issuer.example.test",
    }
    policies = load_signature_policies(write_policy(tmp_path, [record], version=1), project)
    assert ModelScanner(policies).scan(project).scan_failures == [
        "shadowscan.json: signature policy entry names a ShadowScan report location that "
        "the importer does not read"
    ]


def test_a_supplied_unsigned_inventory_is_corroborated_by_a_new_pin(tmp_path, project):
    write_safetensors(project / "models" / "m.safetensors")
    bom = scanned(ModelScanner(), project)
    policies = load_signature_policies(
        write_policy(tmp_path, [pin(project, "models/m.safetensors")]), project
    )
    report = CompletenessValidator().validate_against_project(
        bom, project, signature_policies=policies
    )
    assert not [issue for issue in report.issues if issue.surface.startswith("model:")]
    # The supplier recorded less than the operator's policy verified; it claimed nothing.
    assert not [claim for claim in report.supplier_claims if claim.subject.startswith("model:")]
    assert IntegrityValidator(policies).validate(bom, project).status == "pass"
    asserted = bom.model_copy(deep=True)
    asserted.components[0].signing_identity = "release@example.test"
    claims = CompletenessValidator().validate_against_project(
        asserted, project, signature_policies=policies
    )
    assert [(c.subject, c.kind, c.detail) for c in claims.supplier_claims] == [
        ("model:models/m.safetensors", "field", "signing_identity")
    ]


@pytest.mark.parametrize(
    "record",
    [
        {"kind": "openssf-model-signing", "artifact_path": "m.safetensors"},
        {"kind": "digest-pin", "artifact_path": "m.safetensors"},
        {"kind": "digest-pin", "artifact_path": "m.safetensors", "expected_sha256": "sha256:00"},
        {
            "kind": "digest-pin",
            "artifact_path": "m.safetensors",
            "expected_sha256": "a" * 64,
            "allow_any": True,
        },
        {"artifact_path": "m.safetensors", "expected_sha256": "a" * 64},
    ],
)
def test_version_two_entries_are_strict(tmp_path, project, record):
    write_safetensors(project / "m.safetensors")
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(write_policy(tmp_path, [record]), project)


def test_version_one_policies_stay_valid(tmp_path, project):
    write_safetensors(project / "m.safetensors")
    (project / "m.sigstore").write_text("{}")
    record = {
        "artifact_path": "m.safetensors",
        "bundle_path": "m.sigstore",
        "expected_identity": "id@example.test",
        "expected_issuer": "https://issuer.example.test",
    }
    (loaded,) = load_signature_policies(write_policy(tmp_path, [record], version=1), project)
    assert loaded.expected_sha256 is None
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(write_policy(tmp_path, [{**record, "kind": "x"}], 1), project)


def test_policies_inside_the_project_or_hard_linked_are_refused(tmp_path, project):
    write_safetensors(project / "m.safetensors")
    inside = write_policy(project, [pin(project, "m.safetensors")])
    with pytest.raises(SignaturePolicyError, match="outside the scanned project"):
        load_signature_policies(inside, project)
    outside = tmp_path / "linked.json"
    os.link(inside, outside)
    with pytest.raises(SignaturePolicyError, match="hard links"):
        load_signature_policies(outside, project)


def test_a_symlinked_project_path_loads_like_its_target(tmp_path, project):
    write_safetensors(project / "m.safetensors")
    link = tmp_path / "link"
    link.symlink_to(project, target_is_directory=True)
    policy = write_policy(tmp_path, [pin(project, "m.safetensors")])
    (entry,) = load_signature_policies(policy, link).digest_pins
    assert entry.artifact_path == project.resolve() / "m.safetensors"


def test_another_name_for_the_same_artifact_is_a_duplicate(tmp_path, project):
    write_safetensors(project / "m.safetensors")
    os.link(project / "m.safetensors", project / "alias.safetensors")
    policy = write_policy(
        tmp_path, [pin(project, "m.safetensors"), pin(project, "alias.safetensors")]
    )
    with pytest.raises(SignaturePolicyError, match="Duplicate artifact"):
        load_signature_policies(policy, project)


def test_cli_scan_validate_and_baseline_accept_a_pin_policy(tmp_path, project):
    write_safetensors(project / "models" / "m.safetensors")
    policy = write_policy(tmp_path, [pin(project, "models/m.safetensors")])
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    args = ["--no-project-policy", "--signature-policy", str(policy)]
    scanned = runner.invoke(main, ["scan", str(project), "-o", str(bom), *args])
    assert scanned.exit_code == 0, scanned.output
    link = tmp_path / "link"
    link.symlink_to(project, target_is_directory=True)
    validated = runner.invoke(main, ["validate", str(bom), "--project", str(link), *args])
    assert validated.exit_code == 0, validated.output
    baseline = tmp_path / "baseline.json"
    staged = runner.invoke(
        main,
        ["baseline", str(project), "-o", str(baseline), "--signature-policy", str(policy)],
    )
    assert staged.exit_code == 0, staged.output
    components = json.loads(baseline.read_text())["components"]
    (model,) = [c for c in components if c["component_type"] == "model"]
    assert model["signing_status"] == "digest-pinned"


def test_cli_refuses_a_policy_inside_the_project(project):
    write_safetensors(project / "m.safetensors")
    policy = write_policy(project, [pin(project, "m.safetensors")])
    result = CliRunner().invoke(main, ["scan", str(project), "--signature-policy", str(policy)])
    assert result.exit_code != 0
    assert "outside the scanned project" in result.output


def test_digest_pins_need_no_sigstore_install(tmp_path, project, monkeypatch):
    import sys

    write_safetensors(project / "m.safetensors")
    policies = load_signature_policies(
        write_policy(tmp_path, [pin(project, "m.safetensors")]), project
    )
    for module in ("sigstore", "sigstore.verify", "sigstore.models", "sigstore_models"):
        monkeypatch.setitem(sys.modules, module, None)
    assert ModelScanner(policies).scan(project).components[0].signing_status == "digest-pinned"
    assert isinstance(policies.digest_pins[0], DigestPinPolicy)


# Scale ----------------------------------------------------------------------------------


def test_many_model_directories_scan_in_linear_time(project):
    roots = {}
    for scale in (1, 4):
        roots[scale] = project / f"scale-{scale}"
        for index in range(375 * scale):
            directory = roots[scale] / f"d{index:04d}"
            directory.mkdir(parents=True)
            (directory / "m.ggml").write_bytes(b"x")
    assert scaling_ratio(lambda scale: ModelScanner().scan(roots[scale])) < 10
    assert len(ModelScanner().scan(roots[4]).components) == 1500


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ('{"weight_map": {"a": "x"}, "weight_map": {}}', "invalid JSON or duplicate keys"),
        (
            '{"weight_map": ["model.safetensors"]}',
            "model index must map tensor names to weight files",
        ),
        ('{"weight_map": {"a": 1}}', "model index must map tensor names to weight files"),
    ],
)
def test_malformed_shard_index_is_a_failure(project, content, reason):
    write_safetensors(project / "model.safetensors")
    (project / "model.safetensors.index.json").write_text(content)
    result = ModelScanner().scan(project)
    assert result.scan_failures == [f"model.safetensors.index.json: {reason}"]


@pytest.mark.parametrize(
    ("config", "reason"),
    [
        ('{"model_type": "x", "model_type": "y"}', "invalid JSON or duplicate keys"),
        ('{"rope_theta": NaN}', "invalid JSON or duplicate keys"),
        ('{"chat_template": 42}', "chat_template must be a string or a list of named templates"),
        (
            '{"chat_template": [{"name": "x"}]}',
            "chat_template must be a string or a list of named templates",
        ),
    ],
)
def test_malformed_configuration_is_a_failure_with_a_fixed_reason(project, config, reason):
    write_safetensors(project / "model.safetensors")
    (project / "tokenizer_config.json").write_text(config)
    result = ModelScanner().scan(project)
    assert result.scan_failures == [f"tokenizer_config.json: {reason}"]
    assert result.components[0].properties["config_files"][0]["path"] == "tokenizer_config.json"


def test_custom_pipelines_declare_custom_code(project):
    write_safetensors(project / "model.safetensors")
    (project / "config.json").write_text(
        json.dumps({"custom_pipelines": {"text-generation": {"impl": "pipeline_x.XPipeline"}}})
    )
    (project / "pipeline_x.py").write_text("print(1)\n")
    component = ModelScanner().scan(project).components[0]
    assert component.properties["custom_code"]["references"] == ["pipeline_x.XPipeline"]
    assert any(risk.category == "custom_code" for risk in component.risks)


def test_a_pinned_file_that_cannot_be_hashed_fails_verification(tmp_path, project):
    write_safetensors(project / "m.safetensors")
    policies = load_signature_policies(
        write_policy(tmp_path, [pin(project, "m.safetensors")]), project
    )
    with limits.applied(replace(limits.DEFAULTS, model_bytes=8)):
        result = ModelScanner(policies).scan(project)
    component = result.components[0]
    assert component.signing_status == "verification-failed"
    assert component.claims["signing_status"].unknown_reason == (
        "m.safetensors: Artifact could not be hashed through the confined reader"
    )


# Validation observes each file once, within one budget ---------------------------------


def _calls(monkeypatch, name: str) -> list[Path]:
    """Record the root-relative path of every call to one ConfinedCollection method."""
    calls: list[Path] = []
    original = getattr(ConfinedCollection, name)

    def record(self, path=".", *args, **kwargs):
        calls.append(Path(path))
        return original(self, path, *args, **kwargs)

    monkeypatch.setattr(ConfinedCollection, name, record)
    return calls


def test_validation_walks_a_directory_once_for_all_its_models(project, monkeypatch):
    names = [f"m{index:04d}.ggml" for index in range(1500)]
    for name in names:
        (project / name).write_bytes(b"x")
    bom = AIBOM(components=ModelScanner().scan(project).components)
    walks = _calls(monkeypatch, "iter_files")
    opened = _calls(monkeypatch, "open_regular")
    report = IntegrityValidator(require_model_signatures=False).validate(bom, project)
    assert report.components_checked == 1500
    assert walks == [Path(".")]
    assert sorted(opened) == [Path(name) for name in names]


def test_models_sharing_external_data_read_it_once_per_validation(project, monkeypatch):
    shared = project / "shared.data"
    shared.write_bytes(b"w" * 4096)
    for index in range(100):
        graph = onnx_model(onnx_tensor("w", "shared.data"))
        (project / f"g{index:03d}.onnx").write_bytes(graph)
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    hashed = _calls(monkeypatch, "hash_file")
    opened = _calls(monkeypatch, "open_regular")
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=result.components), project
    )
    assert not [issue for issue in report.issues if issue.category.startswith("weight_files")]
    assert (hashed + opened).count(Path("shared.data")) == 1


def test_tensor_metadata_is_checked_from_the_same_observation(project, monkeypatch):
    write_safetensors(project / "m.safetensors")
    bom = AIBOM(components=ModelScanner().scan(project).components)
    opened = _calls(monkeypatch, "open_regular")
    report = IntegrityValidator(require_model_signatures=False).validate(bom, project)
    assert opened == [Path("m.safetensors")]
    assert not [i for i in report.issues if i.category == "tensor_metadata_unverified"]


def test_validation_reads_stop_at_one_byte_budget(project, monkeypatch):
    write_safetensors(project / "a.safetensors")
    write_safetensors(project / "b.safetensors")
    bom = AIBOM(components=ModelScanner().scan(project).components)
    budget = (project / "a.safetensors").stat().st_size + 1
    monkeypatch.setattr(
        "nexus_symbiote.validators.integrity.ModelPackages",
        functools.partial(ModelPackages, byte_budget=budget),
    )
    report = IntegrityValidator(require_model_signatures=False).validate(bom, project)
    exhausted = [i for i in report.issues if i.category == "validation_budget_exhausted"]
    assert [(i.component_ref, i.severity) for i in exhausted] == [
        ("model:b.safetensors", "unknown")
    ]
    assert report.status != "pass"


def test_a_shared_signed_weight_file_is_verified_once(tmp_path, project, monkeypatch):
    (project / "shared.data").write_bytes(b"weights")
    (project / "shared.data.sigstore").write_text("{}")
    for index in range(20):
        graph = onnx_model(onnx_tensor("w", "shared.data"))
        (project / f"g{index:02d}.onnx").write_bytes(graph)
    record = {
        "kind": "sigstore-message-signature",
        "artifact_path": "shared.data",
        "bundle_path": "shared.data.sigstore",
        "expected_identity": "release@example.test",
        "expected_issuer": "https://issuer.example.test",
    }
    policies = load_signature_policies(write_policy(tmp_path, [record]), project)
    calls = []

    def verify(artifact, bundle, identity, issuer):
        calls.append(Path(artifact))
        details = {"artifact_digest": sha256(Path(artifact))}
        return VerificationResult(True, identity=identity, issuer=issuer, details=details)

    monkeypatch.setattr("nexus_symbiote.scanners.model.verify_sigstore_bundle", verify)
    monkeypatch.setattr("nexus_symbiote.validators.integrity.verify_sigstore_bundle", verify)
    result = ModelScanner(policies).scan(project)
    assert not result.scan_failures
    assert {c.signing_status for c in result.components} == {"partially-verified"}
    assert len(calls) == 1
    report = IntegrityValidator(policies).validate(AIBOM(components=result.components), project)
    assert report.signatures_verified == 20
    assert len(calls) == 2


def test_validation_rereads_shard_indexes_and_bound_files(project, monkeypatch):
    model = project / "llm"
    write_safetensors(model / "model-00001-of-00002.safetensors", b"aa")
    write_safetensors(model / "model-00002-of-00002.safetensors", b"bb")
    shards = {"a": "model-00001-of-00002.safetensors", "b": "model-00002-of-00002.safetensors"}
    index = model / "model.safetensors.index.json"
    index.write_text(json.dumps({"weight_map": shards}))
    bom = AIBOM(components=ModelScanner().scan(project).components)
    opened = _calls(monkeypatch, "open_regular")
    clean = IntegrityValidator(require_model_signatures=False).validate(bom, project)
    assert not [i for i in clean.issues if i.category.startswith("weight_files")]
    # Both shards bind the index; the validation reads it once.
    assert opened.count(Path("llm/model.safetensors.index.json")) == 1
    index.write_text(json.dumps({"weight_map": shards, "metadata": {"total_size": 4}}))
    changed = IntegrityValidator(require_model_signatures=False).validate(bom, project)
    assert {i.component_ref for i in changed.issues if i.category == "weight_files_mismatch"} == {
        "model:llm/model-00001-of-00002.safetensors",
        "model:llm/model-00002-of-00002.safetensors",
    }
    index.unlink()
    index.symlink_to(model / "model-00001-of-00002.safetensors")
    unreadable = IntegrityValidator(require_model_signatures=False).validate(bom, project)
    assert any(i.category == "weight_files_unverified" for i in unreadable.issues)


def test_a_bound_file_that_cannot_be_read_leaves_the_model_unverified(project):
    graph = project / "model.onnx"
    graph.write_bytes(onnx_model(onnx_tensor("w", "model.onnx_data")))
    (project / "model.onnx_data").write_bytes(b"weights")
    bom = AIBOM(components=ModelScanner().scan(project).components)
    (project / "model.onnx_data").unlink()
    (project / "model.onnx_data").mkdir()
    report = IntegrityValidator(require_model_signatures=False).validate(bom, project)
    categories = {issue.category for issue in report.issues}
    assert {"weight_files_unverified", "weight_files_mismatch"} <= categories


# Report entries, policy digests and the policy location --------------------------------

REPORT = Path(__file__).parent / "fixtures" / "shadowscan" / "code-report-0.1.4.json"


def _discovery_project(tmp_path: Path) -> tuple[Path, Path]:
    project, bom = tmp_path / "proj", tmp_path / "bom.json"
    (project / ".shadowscan").mkdir(parents=True)
    shutil.copy(REPORT, project / ".shadowscan" / "report.json")
    (project / ".shadowscan" / "report.sigstore.json").write_text("{}")
    server = {"command": "npx", "args": ["-y", "@acme/payments-mcp@1.2.3"]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"payments": server}}))
    CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(bom)])
    assert bom.is_file()
    return project, bom


def _report_policy(tmp_path: Path, expected_sha256: str) -> Path:
    record = {
        "kind": "sigstore-message-signature",
        "artifact_path": ".shadowscan/report.json",
        "bundle_path": ".shadowscan/report.sigstore.json",
        "expected_identity": "https://github.com/acme/discovery/.github/workflows/scan.yml@main",
        "expected_issuer": "https://token.actions.githubusercontent.com",
        "expected_sha256": expected_sha256,
    }
    return write_policy(tmp_path, [record])


def test_a_pinned_discovery_report_must_match_its_pin(tmp_path, monkeypatch):
    project, bom = _discovery_project(tmp_path)

    def verify(artifact, bundle, identity, issuer):
        details = {"artifact_digest": sha256(Path(artifact))}
        return VerificationResult(True, identity=identity, issuer=issuer, details=details)

    # A valid signature from the expected signer, over an older or another report.
    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_bundle", verify)
    other = _report_policy(tmp_path, "sha256:" + "0" * 64)
    assert discovery_producer_problems(
        AIBOM.load(bom), project, load_signature_policies(other, project)
    ) == ["ShadowScan report differs from the operator's expected_sha256 pin."]
    (project / ".nexus-symbiote.yaml").write_text("validate: {require_integrity: false}\n")
    args = ["validate", str(bom), "--project", str(project), "--signature-policy"]
    refused = CliRunner().invoke(main, [*args, str(other)])
    assert refused.exit_code == 1
    assert "differs from the operator's expected_sha256 pin" in refused.output
    exact = _report_policy(tmp_path, sha256(project / ".shadowscan" / "report.json"))
    accepted = CliRunner().invoke(main, [*args, str(exact)])
    assert accepted.exit_code == 0, accepted.output


def test_equivalent_policies_with_other_bytes_reconcile_and_raise_no_drift(tmp_path, project):
    write_safetensors(project / "models" / "m.safetensors")
    write_safetensors(project / "models" / "n.safetensors", b"efgh")
    entry = pin(project, "models/m.safetensors")
    supplier = tmp_path / "supplier.json"
    supplier.write_text(json.dumps({"version": 2, "artifacts": [entry]}))
    # Same entry, other bytes, and one more entry for another model.
    consumer = tmp_path / "consumer.json"
    records = [entry, pin(project, "models/n.safetensors")]
    consumer.write_text(json.dumps({"version": 2, "artifacts": records}, indent=2))
    supplied = scanned(ModelScanner(load_signature_policies(supplier, project)), project)
    policies = load_signature_policies(consumer, project)
    report = CompletenessValidator().validate_against_project(
        supplied, project, signature_policies=policies
    )
    assert not [issue for issue in report.issues if issue.surface.startswith("model:")]
    recollected = scanned(ModelScanner(policies), project)
    changed = {
        change.bom_ref for change in AIBOMDiffer().diff(supplied, recollected).components_modified
    }
    assert changed == {"model:models/n.safetensors"}


def test_cli_consumer_validates_a_supplier_inventory_under_its_own_policy(tmp_path, project):
    write_safetensors(project / "models" / "m.safetensors")
    entry = pin(project, "models/m.safetensors")
    supplier = tmp_path / "supplier.json"
    supplier.write_text(json.dumps({"version": 2, "artifacts": [entry]}))
    consumer = tmp_path / "consumer.json"
    consumer.write_text(json.dumps({"version": 2, "artifacts": [entry]}, indent=2))
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    flags = ["--no-project-policy", "--signature-policy"]
    scanned = runner.invoke(main, ["scan", str(project), "-o", str(bom), *flags, str(supplier)])
    assert scanned.exit_code == 0, scanned.output
    checked = runner.invoke(
        main, ["validate", str(bom), "--project", str(project), *flags, str(consumer)]
    )
    assert checked.exit_code == 0, checked.output


def test_a_policy_reached_through_another_name_for_the_project_is_refused(
    tmp_path, project, monkeypatch
):
    # A case variant or a bind mount names the project's directory without
    # matching it lexically; its device and inode still match.
    write_safetensors(project / "m.safetensors")
    alias = tmp_path / "alias"
    alias.mkdir()
    policy = write_policy(alias, [pin(project, "m.safetensors")])
    real = os.stat(project)

    def identity(path):
        info = os.stat(path)
        if Path(path) == alias:
            return real.st_dev, real.st_ino
        return info.st_dev, info.st_ino

    monkeypatch.setattr("nexus_symbiote.signature_policy._identity", identity)
    with pytest.raises(SignaturePolicyError, match="outside the scanned project"):
        load_signature_policies(policy, project)


def test_validate_reports_unused_entries_when_completeness_is_skipped(tmp_path, project):
    write_safetensors(project / "m.safetensors")
    (project / "tokenizer.json").write_text("{}")
    policy = write_policy(tmp_path, [pin(project, "m.safetensors"), pin(project, "tokenizer.json")])
    bom = AIBOM(components=ModelScanner().scan(project).components)
    report = IntegrityValidator(load_signature_policies(policy, project)).validate(bom, project)
    unused = [i for i in report.issues if i.category == "unused_policy_entry"]
    assert [(i.component_ref, i.detail, i.severity) for i in unused] == [
        (
            "signature-policy",
            "tokenizer.json: signature policy entry names no collected model weight file",
            "error",
        )
    ]
    path = tmp_path / "bom.json"
    path.write_text(bom.to_json())
    (project / ".nexus-symbiote.yaml").write_text("validate: {require_completeness: false}\n")
    result = CliRunner().invoke(
        main,
        ["validate", str(path), "--project", str(project), "--signature-policy", str(policy)],
    )
    assert result.exit_code == 1
    assert "tokenizer.json: signature policy entry names no collected model weight file" in (
        result.output
    )


@pytest.mark.parametrize("budget", ["artifact", "bindings"])
def test_entries_of_a_model_the_budget_left_unchecked_are_not_unused(
    tmp_path, project, monkeypatch, budget
):
    export = project / "export"
    (export / "variables").mkdir(parents=True)
    (export / "saved_model.pb").write_bytes(b"\x08\x01")
    (export / "variables" / "variables.data-00000-of-00001").write_bytes(b"reviewed")
    (export / "variables" / "variables.index").write_bytes(b"index")
    (project / "notes.txt").write_text("not a weight file")
    names = [
        "export/saved_model.pb",
        "export/variables/variables.data-00000-of-00001",
        "export/variables/variables.index",
        "notes.txt",
    ]
    policy = write_policy(tmp_path, [pin(project, name) for name in names])
    policies = load_signature_policies(policy, project)
    bom = AIBOM(components=ModelScanner(policies).scan(project).components)
    if budget == "bindings":
        monkeypatch.setattr(
            "nexus_symbiote.validators.integrity.ModelPackages",
            functools.partial(ModelPackages, binding_budget=0),
        )
    validator = IntegrityValidator(policies, byte_budget=1 if budget == "artifact" else None)
    report = validator.validate(bom, project)
    assert any(i.category == "validation_budget_exhausted" for i in report.issues)
    unused = [i.detail for i in report.issues if i.category == "unused_policy_entry"]
    assert unused == ["notes.txt: signature policy entry names no collected model weight file"]


# ONNX keys in every encoding a protobuf runtime accepts --------------------------------


def test_an_overlong_external_data_key_tag_fails_closed(project):
    # protobuf C++ keeps the low 32 bits of a tag: 8A 80 80 80 10 is field 1, wire type 2.
    key = bytes([0x8A, 0x80, 0x80, 0x80, 0x10]) + b"\x08location"
    tensor = _field(1, 4) + _field(2, 1) + _field(8, b"w")
    tensor += _field(13, key + _field(2, b"model.onnx_data")) + _field(14, 1)
    (project / "model.onnx").write_bytes(_field(1, 8) + _field(7, _field(5, tensor)))
    (project / "model.onnx_data").write_bytes(b"weights")
    result = ModelScanner().scan(project)
    assert result.scan_failures == [
        "model.onnx: ONNX graph could not be parsed; external weight files are unknown"
    ]


def test_tensors_and_values_named_location_are_not_external_data(project):
    value = _field(11, _field(1, b"location"))
    node = _field(1, _field(1, b"location") + _field(4, b"Relu"))
    (project / "model.onnx").write_bytes(_field(1, 8) + _field(7, value + node))
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    assert "weight_files" not in result.components[0].properties


@pytest.mark.parametrize(
    "data_location",
    [
        # EXTERNAL with bit 32 set: protobuf reads an enum as int32.
        _varint(14 << 3) + bytes([0x81, 0x80, 0x80, 0x80, 0x10]),
        # EXTERNAL, then values ONNX's closed enum does not define, which protobuf
        # keeps as unknown fields.
        _field(14, 1) + _field(14, 2),
        _field(14, 1) + _varint(14 << 3) + b"\xff" * 9 + b"\x01",
    ],
)
def test_external_data_in_any_data_location_encoding_protobuf_reads_is_bound(
    tmp_path, project, data_location
):
    tensor = _field(1, 4) + _field(2, 1) + _field(8, b"w")
    tensor += _field(13, _entry("location", "model.onnx_data")) + data_location
    (project / "model.onnx").write_bytes(_field(1, 8) + _field(7, _field(5, tensor)))
    weights = project / "model.onnx_data"
    weights.write_bytes(b"reviewed weights")
    policy = write_policy(tmp_path, [pin(project, "model.onnx")])
    result = ModelScanner(load_signature_policies(policy, project)).scan(project)
    assert not result.scan_failures
    (component,) = result.components
    assert component.properties["weight_files"] == [
        {"path": "model.onnx_data", "sha256": sha256(weights)}
    ]
    # The pin covers the graph only, so the model is not verified as a whole.
    assert component.signing_status == "partially-verified"
    weights.write_bytes(b"swapped weights!")
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=[component]), project
    )
    assert any(issue.category == "weight_files_mismatch" for issue in report.issues)


# Files bound to many models ------------------------------------------------------------


def _shards_and_indexes(directory: Path, shards: int, indexes: int) -> list[str]:
    """``shards`` model files and ``indexes`` identical shard indexes listing every one."""
    directory.mkdir(parents=True)
    names = [f"s{number:05d}.ggml" for number in range(shards)]
    for name in names:
        (directory / name).write_bytes(b"")
    document = json.dumps({"weight_map": {f"t{i}": name for i, name in enumerate(names)}})
    for number in range(indexes):
        (directory / f"model.ggml.index.{number:02d}.json").write_text(document)
    return names


def test_a_directory_with_more_shard_indexes_than_the_limit_binds_none(project):
    limit = model_collector.MAX_SHARD_INDEXES
    model = project / "llm"
    _shards_and_indexes(model, 3, limit + 1)
    result = ModelScanner().scan(project)
    assert result.scan_failures == [f"llm: {model_collector.TOO_MANY_INDEXES}"]
    assert all("weight_files" not in c.properties for c in result.components)
    assert not [surface for surface in result.surfaces_scanned if ".index." in surface]
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=result.components), project
    )
    unverified = {i.component_ref for i in report.issues if i.category == "weight_files_unverified"}
    assert unverified == {c.bom_ref for c in result.components}
    (model / f"model.ggml.index.{limit:02d}.json").unlink()
    bound = ModelScanner().scan(project)
    assert not bound.scan_failures
    assert {len(c.properties["weight_files"]) for c in bound.components} == {limit}


def test_shards_listed_by_many_indexes_are_bound_within_one_budget(project, monkeypatch):
    # Identical indexes are one blob in a repository, so N shards and K indexes that
    # each list every shard would cost N x K bindings in scan, validate and risk.
    # The budget is twice the operator's entries limit, lowered here to keep the tree small.
    lowered = replace(limits.DEFAULTS, entries=20_000)
    limit = 2 * lowered.entries
    assert 2 * limits.DEFAULTS.entries == model_collector.MAX_WEIGHT_FILE_BINDINGS
    indexes = model_collector.MAX_SHARD_INDEXES
    _shards_and_indexes(project / "llm", limit // (2 * indexes) + 100, indexes)
    with limits.applied(lowered):
        result = ModelScanner().scan(project)
    pairs = sum(len(c.properties.get("weight_files", [])) for c in result.components)
    assert 0 < pairs <= limit
    (failure,) = result.scan_failures
    assert failure.endswith(model_collector.BINDINGS_EXHAUSTED)
    # Every issue stays listed, so each refused model can be named; the verdict
    # counts all issues either way.
    monkeypatch.setattr("nexus_symbiote.validators.integrity.MAX_REPORTED_ISSUES", 10**6)
    with limits.applied(lowered):
        report = IntegrityValidator(require_model_signatures=False).validate(
            AIBOM(components=result.components), project
        )
    assert report.status != "pass"
    exhausted = {i.component_ref for i in report.issues if i.category.endswith("budget_exhausted")}
    assert exhausted == {c.bom_ref for c in result.components if "weight_files" not in c.properties}


def test_validation_charges_bindings_to_one_budget_and_binds_each_model_once(project, monkeypatch):
    names = _shards_and_indexes(project / "llm", 3, 2)
    components = ModelScanner().scan(project).components
    # Two indexes of three entries, then two bindings for each of two shards.
    monkeypatch.setattr(
        "nexus_symbiote.validators.integrity.ModelPackages",
        functools.partial(ModelPackages, binding_budget=2 * 3 + 2 * 2),
    )
    # A model listed twice is bound once.
    again = components[0].model_copy(update={"bom_ref": "model:again"})
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=[*components, again]), project
    )
    exhausted = {i.component_ref for i in report.issues if i.category.endswith("budget_exhausted")}
    assert exhausted == {f"model:llm/{names[2]}"}
    assert report.status != "pass"


def test_weight_files_are_matched_to_policy_entries_without_resolving_each(project, monkeypatch):
    write_safetensors(project / "m.safetensors")
    (project / "m.data").write_bytes(b"weights")
    weight_files = [(Path(name), sha256(project / name)) for name in ("m.safetensors", "m.data")]
    policies = {
        (project / name).resolve(): DigestPinPolicy(project / name, digest)
        for name, digest in ((path.as_posix(), digest) for path, digest in weight_files)
    }

    def refuse(self, strict=False):
        raise AssertionError("a weight file path was resolved again")

    monkeypatch.setattr(Path, "resolve", refuse)
    verification = model_collector.verify_weight_files(
        weight_files, project, policies, verify=model_collector.verify_sigstore_bundle
    )
    assert verification.status is not None
    assert verification.status.value == "digest-pinned"
    assert verification.pins_verified == 2


def test_directory_digests_recorded_on_every_model_are_bounded(project):
    # Each model records its directory's digests, so one configuration with many
    # chat templates beside N models would otherwise be recorded N times. The budget
    # is twice the operator's entries limit, lowered here to keep the file small.
    lowered = replace(limits.DEFAULTS, entries=20_000)
    limit = 2 * lowered.entries
    assert 2 * limits.DEFAULTS.entries == model_collector.MAX_SHARED_DIGESTS
    templates = [{"name": str(i), "template": ""} for i in range(limit // 2)]
    (project / "tokenizer_config.json").write_text(json.dumps({"chat_template": templates}))
    for name in ("a.ggml", "b.ggml", "c.ggml"):
        (project / name).write_bytes(b"")
    with limits.applied(lowered):
        result = ModelScanner().scan(project)
    assert result.scan_failures == [f"b.ggml: {model_collector.SHARED_DIGESTS_EXHAUSTED}"]
    first, *rest = result.components
    assert len(first.properties["chat_templates"]) == limit // 2
    assert first.chat_template_hash is not None
    for component in rest:
        assert {"config_files", "chat_templates"}.isdisjoint(component.properties)
        assert component.chat_template_hash is None


def test_validation_keeps_no_chat_template_of_the_files_it_observes(project):
    (project / "model.gguf").write_bytes(gguf("{{ messages }}"))
    scanned = ModelScanner().scan(project).components[0]
    assert scanned.properties["chat_templates"]
    observation = ModelPackages(project).observe(Path("model.gguf")).observation
    assert observation is not None
    assert observation.chat_templates == ()
    assert observation.digest == scanned.hashes["sha256"]


def test_the_native_schema_names_every_signing_status_the_collector_emits():
    from nexus_symbiote.core.models import ModelComponent
    from nexus_symbiote.utils.crypto import SigningStatus

    description = ModelComponent.model_fields["signing_status"].description or ""
    assert [status.value for status in SigningStatus if status.value not in description] == []


def _length_delimited(field: int, payload: bytes) -> bytes:
    return bytes([(field << 3) | 2, len(payload)]) + payload


def _onnx_with_external_data(location: bytes) -> bytes:
    entry = _length_delimited(1, b"location") + _length_delimited(2, location)
    tensor = _length_delimited(13, entry) + bytes([14 << 3, 1])
    return _length_delimited(7, _length_delimited(5, tensor))


_BOUND_LAYOUTS = {
    "onnx-external-data": (
        "models/checkpoint",
        {"models/model.onnx": _onnx_with_external_data(b"checkpoint")},
    ),
    "savedmodel-variables": ("models/variables/blob", {"models/saved_model.pb": b"\x08\x01"}),
}


@pytest.mark.parametrize("layout", _BOUND_LAYOUTS.values(), ids=_BOUND_LAYOUTS)
def test_a_pickle_bound_to_a_model_keeps_its_own_critical_component(
    project: Path, layout: tuple[str, dict[str, bytes]]
) -> None:
    # Audit 2026-11-16 S4-05: a file a model binds was only hashed, so a pickle bound as
    # ONNX external data or SavedModel variables lost the rating it has on its own.
    bound, parents = layout
    payload = b"\x80\x02cbuiltins\nexec\n(X\x01\x00\x00\x001tR."
    (project / bound).parent.mkdir(parents=True, exist_ok=True)
    (project / bound).write_bytes(payload)
    for relative, content in parents.items():
        (project / relative).write_bytes(content)
    result = ModelScanner().scan(project)
    assert not result.scan_failures, result.scan_failures
    found = {c.source_path: c for c in result.components}
    (parent,) = parents
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    assert found[parent].properties["weight_files"] == [{"path": bound, "sha256": digest}]
    assert found[bound].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert found[bound].hashes == {"sha256": digest}
    assert any(r.severity is RiskSeverity.CRITICAL for r in found[bound].risks)
    assert sorted(result.surfaces_scanned).count(bound) == 1


def test_a_bound_file_that_holds_no_payload_is_only_a_weight_file(project: Path) -> None:
    (project / "models").mkdir()
    (project / "models/checkpoint").write_bytes(b"\x00\x01" * 64)
    (project / "models/model.onnx").write_bytes(_onnx_with_external_data(b"checkpoint"))
    result = ModelScanner().scan(project)
    assert not result.scan_failures, result.scan_failures
    assert [c.source_path for c in result.components] == ["models/model.onnx"]


def test_a_pinned_model_is_not_verified_once_the_binding_budget_refuses_it(project: Path) -> None:
    # Audit 2026-11-16 S4-06: after the budget refused its bindings, a model was verified
    # on its main file alone, as digest-pinned, though its external data differs from its pin.
    (project / "a").mkdir()
    (project / "b").mkdir()
    (project / "b/model.onnx").write_bytes(_onnx_with_external_data(b"weights.data"))
    (project / "b/weights.data").write_bytes(b"pinned bytes")
    pins = [
        DigestPinPolicy(project / p, sha256(project / p))
        for p in ("b/model.onnx", "b/weights.data")
    ]
    (project / "b/weights.data").write_bytes(b"swapped bytes")
    index = {"weight_map": {f"t{i}": f"missing-{i}.safetensors" for i in range(25)}}
    (project / "a/model.safetensors.index.json").write_text(json.dumps(index))
    with limits.applied(replace(limits.DEFAULTS, entries=10)):
        result = ModelScanner(digest_pins=pins).scan(project)
    assert any(f.endswith(model_collector.BINDINGS_EXHAUSTED) for f in result.scan_failures)
    (component,) = [c for c in result.components if c.source_path == "b/model.onnx"]
    assert "weight_files" not in component.properties
    assert component.signing_status == "partially-verified"
    assert component.trust_tier is TrustTier.UNKNOWN
    (evidence,) = component.claims.values()
    assert evidence.assurance.value != "verified"
    assert model_collector.BINDINGS_EXHAUSTED in (evidence.unknown_reason or "")


def test_a_pinned_shard_is_not_verified_once_the_budget_refuses_its_index(project: Path) -> None:
    # A refused index binds none of its shards, and a shard then charges nothing, so it
    # was verified alone although its pinned index, which decides what loads, differs.
    (project / "c").mkdir()
    shard = project / "c/model-00001-of-00001.safetensors"
    header = json.dumps({"t0": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    shard.write_bytes(len(header).to_bytes(8, "little") + header + b"\0\0\0\0")
    index = project / "c/model.safetensors.index.json"
    index.write_text(json.dumps({"weight_map": {"t0": shard.name}}))
    pins = [DigestPinPolicy(path, sha256(path)) for path in (shard, index)]
    weight_map = {"t0": shard.name, **{f"t{i}": f"missing-{i}.safetensors" for i in range(1, 25)}}
    index.write_text(json.dumps({"weight_map": weight_map}))
    with limits.applied(replace(limits.DEFAULTS, entries=10)):
        result = ModelScanner(digest_pins=pins).scan(project)
    assert any(f.endswith(model_collector.BINDINGS_EXHAUSTED) for f in result.scan_failures)
    (component,) = [c for c in result.components if c.source_path == "c/" + shard.name]
    assert component.signing_status == "partially-verified"
    assert component.trust_tier is TrustTier.UNKNOWN
    (evidence,) = component.claims.values()
    assert evidence.assurance.value != "verified"
    assert model_collector.BINDINGS_EXHAUSTED in (evidence.unknown_reason or "")


@pytest.mark.parametrize(
    "variant",
    [
        "duplicate-keys",
        "list-weight-map",
        "too-many-indexes",
        "oversized",
        "missing-shard",
        "outside-shard",
        "empty-weight-map",
    ],
)
def test_a_pinned_shard_is_not_verified_when_its_index_cannot_be_bound(
    project: Path, variant: str
) -> None:
    # An index that cannot be read or parsed, one of too many, or one that names none of
    # the collected weight files binds none of its shards; the shard was then verified
    # alone although its pinned index, which decides what loads, differs from its pin.
    (project / "c").mkdir()
    shard = project / "c/model-00001-of-00001.safetensors"
    header = json.dumps({"t0": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    shard.write_bytes(len(header).to_bytes(8, "little") + header + b"\0\0\0\0")
    index = project / "c/model.safetensors.index.json"
    index.write_text(json.dumps({"weight_map": {"t0": shard.name}}))
    pins = [DigestPinPolicy(path, sha256(path)) for path in (shard, index)]
    if variant == "duplicate-keys":
        entry = json.dumps({"t0": shard.name})[1:-1]
        index.write_text(f'{{"weight_map": {{{entry}, {entry}}}}}')
    elif variant == "list-weight-map":
        index.write_text(json.dumps({"weight_map": [shard.name]}))
    elif variant == "too-many-indexes":
        index.write_text(json.dumps({"weight_map": {"t0": shard.name, "t1": shard.name}}))
        for number in range(model_collector.MAX_SHARD_INDEXES):
            (project / f"c/m{number}.safetensors.index.json").write_text('{"weight_map": {}}')
    elif variant == "oversized":
        index.write_text(json.dumps({"weight_map": {"t0": shard.name}, "pad": "x" * 512}))
    elif variant == "outside-shard":
        (project / shard.name).write_bytes(shard.read_bytes())
        index.write_text(json.dumps({"weight_map": {"t0": "../" + shard.name}}))
    elif variant == "missing-shard":
        index.write_text(json.dumps({"weight_map": {"t0": "nothere.safetensors"}}))
    else:
        index.write_text(json.dumps({"weight_map": {}}))
    bound = replace(limits.DEFAULTS, file_bytes=256) if variant == "oversized" else limits.DEFAULTS
    with limits.applied(bound):
        result = ModelScanner(digest_pins=pins).scan(project)
    assert result.scan_failures
    (component,) = [c for c in result.components if c.source_path == "c/" + shard.name]
    assert component.signing_status == "partially-verified"
    assert component.trust_tier is TrustTier.UNKNOWN
    (evidence,) = component.claims.values()
    assert evidence.assurance.value != "verified"
    assert model_collector.INDEX_UNBOUND in (evidence.unknown_reason or "")


def test_a_pinned_shard_with_a_bound_index_stays_verified(project: Path) -> None:
    (project / "c").mkdir()
    shard = project / "c/model-00001-of-00001.safetensors"
    header = json.dumps({"t0": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    shard.write_bytes(len(header).to_bytes(8, "little") + header + b"\0\0\0\0")
    index = project / "c/model.safetensors.index.json"
    index.write_text(json.dumps({"weight_map": {"t0": shard.name}}))
    pins = [DigestPinPolicy(path, sha256(path)) for path in (shard, index)]
    result = ModelScanner(digest_pins=pins).scan(project)
    assert not result.scan_failures, result.scan_failures
    (component,) = [c for c in result.components if c.source_path == "c/" + shard.name]
    assert component.signing_status == "digest-pinned"
    assert component.trust_tier is TrustTier.INTERNAL_VERIFIED


def test_tensor_metadata_is_checked_at_the_artifact_an_in_root_link_names(project, monkeypatch):
    (project / "weights").mkdir()
    write_safetensors(project / "weights" / "real.safetensors")
    (project / "model.safetensors").symlink_to("weights/real.safetensors")
    collected = [
        component
        for component in ModelScanner().scan(project).components
        if component.source_path == "weights/real.safetensors"
    ]
    # The link's own path names the same bytes, as the model check locates them.
    linked = collected[0].model_copy(update={"source_path": "model.safetensors"})
    opened = _calls(monkeypatch, "open_regular")
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=[linked]), project
    )
    assert opened == [Path("weights/real.safetensors")]
    assert not [i for i in report.issues if i.category == "tensor_metadata_unverified"]
    assert report.hashes_failed == 0
