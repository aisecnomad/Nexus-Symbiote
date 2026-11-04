"""Common model formats are inventoried and never silently treated as clean."""

from __future__ import annotations

import json
import pickle
import warnings
import zipfile
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.scanners.model import ModelScanner, model_format
from nexus_symbiote.validators.integrity import IntegrityValidator

INERT_PICKLE = pickle.dumps({"weights": [0.0, 1.0]}, protocol=4)
HDF5 = b"\x89HDF\r\n\x1a\n"


def _scan(project: Path) -> dict[str, tuple[SerializationSafety, set[tuple[RiskSeverity, str]]]]:
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    return {
        Path(component.name).name: (
            component.serialization_safety,
            {(risk.severity, risk.category) for risk in component.risks},
        )
        for component in result.components
    }


@pytest.mark.parametrize("name", ["lightning.ckpt", "paddle.pdparams"])
def test_pickle_based_checkpoints_are_rated_code_executing(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(INERT_PICKLE)
    safety, risks = _scan(tmp_path)[name]
    assert safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert (RiskSeverity.CRITICAL, "serialization_format") in risks


@pytest.mark.parametrize("name", ["legacy.h5", "legacy.hdf5", "model.keras", "saved_model.pb"])
def test_formats_without_a_validator_are_reported_unknown(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    if name.endswith(".keras"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("config.json", "{}")
    else:
        # Keras weights without a model configuration: no code-carrying construct.
        path.write_bytes(HDF5 + b"\0" * 32 + b"keras_version" + b"\0" * 32)
    safety, risks = _scan(tmp_path)[name]
    assert safety == SerializationSafety.UNKNOWN
    assert (RiskSeverity.HIGH, "serialization_format_unknown") in risks


def test_generic_protobuf_files_are_not_models(tmp_path: Path) -> None:
    (tmp_path / "descriptor.pb").write_bytes(b"\x08\x01")
    assert model_format(tmp_path / "descriptor.pb") is None
    assert model_format(tmp_path / "SAVED_MODEL.PB") == ("pb", "tensorflow-savedmodel")
    assert _scan(tmp_path) == {}


def _keras_archive(path: Path, config: object, *extra: tuple[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive, warnings.catch_warnings():
        warnings.filterwarnings("ignore", "Duplicate name", UserWarning)
        archive.writestr("metadata.json", "{}")
        archive.writestr("config.json", json.dumps(config))
        for name, data in extra:
            archive.writestr(name, data)


DENSE = {"module": "keras.layers", "class_name": "Dense", "config": {"units": 1}}


@pytest.mark.parametrize(
    "layer",
    [
        {"module": "keras.layers", "class_name": "Lambda", "config": {"function": {}}},
        {"module": "builtins", "class_name": "function", "config": "exec"},
    ],
)
def test_keras_archive_with_code_bearing_config_is_code_executing(tmp_path: Path, layer) -> None:
    config = {"module": "keras", "class_name": "Sequential", "config": {"layers": [DENSE, layer]}}
    _keras_archive(tmp_path / "model.keras", config)
    safety, risks = _scan(tmp_path)["model.keras"]
    assert safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert (RiskSeverity.CRITICAL, "serialization_format") in risks


@pytest.mark.parametrize(
    "extra",
    [
        [("archive/data.pkl", INERT_PICKLE)],
        # zipfile, like Keras, opens the last of two members with the same name.
        [("config.json", json.dumps({"class_name": "Lambda"}).encode())],
    ],
)
def test_keras_archive_with_pickle_or_ambiguous_member_is_code_executing(
    tmp_path: Path, extra
) -> None:
    _keras_archive(tmp_path / "model.keras", {"class_name": "Sequential"}, *extra)
    assert _scan(tmp_path)["model.keras"][0] == SerializationSafety.UNSAFE_CODE_EXECUTION


def test_keras_extension_layers_are_not_rated_code_executing(tmp_path: Path) -> None:
    backbone = {
        "module": "keras_hub.src.models.bert.bert_backbone",
        "class_name": "BertBackbone",
        "registered_name": "keras_hub>BertBackbone",
        "config": {"vocabulary_size": 8},
    }
    _keras_archive(tmp_path / "model.keras", {"class_name": "Functional", "config": backbone})
    assert _scan(tmp_path)["model.keras"][0] == SerializationSafety.UNKNOWN


@pytest.mark.parametrize("content", [b"not a zip", b"PK\x03\x04" + b"\0" * 26])
def test_malformed_keras_archive_is_unknown(tmp_path: Path, content: bytes) -> None:
    (tmp_path / "model.keras").write_bytes(content)
    assert _scan(tmp_path)["model.keras"][0] == SerializationSafety.UNKNOWN


@pytest.mark.parametrize("suffix", [".h5", ".hdf5"])
def test_keras_hdf5_model_configuration_is_unknown_with_loader_evidence(
    tmp_path: Path, suffix: str
) -> None:
    # The model_config attribute name is far from the start of the file.
    (tmp_path / f"model{suffix}").write_bytes(HDF5 + b"\0" * 200_000 + b"model_config" + b"\0")
    (component,) = ModelScanner().scan(tmp_path).components
    assert component.serialization_safety == SerializationSafety.UNKNOWN
    assert "CVE-2025-9905" in component.properties["format_inspection"]


def test_hdf5_without_keras_markers_stays_inventoried_as_unknown(tmp_path: Path) -> None:
    # A marker can be hidden from a byte search, so absence is never proof of data.
    (tmp_path / "train.h5").write_bytes(HDF5 + b"\0" * 64 + b"dataset")
    (component,) = ModelScanner().scan(tmp_path).components
    assert component.serialization_safety == SerializationSafety.UNKNOWN
    assert "without Keras model configuration" in component.properties["format_inspection"]


def test_non_hdf5_bytes_under_an_hdf5_name_stay_inventoried(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(pickle.dumps({"weights": [0.0]}, protocol=0))
    assert _scan(tmp_path)["model.h5"][0] == SerializationSafety.UNKNOWN


def test_versioned_layouts_do_not_collide(tmp_path: Path) -> None:
    for model in ("encoder", "decoder"):
        version = tmp_path / "serving" / model / "1"
        version.mkdir(parents=True)
        (version / "saved_model.pb").write_bytes(b"\x08\x01")
    for run in ("version_0", "version_1"):
        checkpoints = tmp_path / "lightning_logs" / run / "checkpoints"
        checkpoints.mkdir(parents=True)
        (checkpoints / "last.ckpt").write_bytes(INERT_PICKLE)
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    assert sorted(component.bom_ref for component in result.components) == [
        "model:lightning_logs/version_0/checkpoints/last.ckpt",
        "model:lightning_logs/version_1/checkpoints/last.ckpt",
        "model:serving/decoder/1/saved_model.pb",
        "model:serving/encoder/1/saved_model.pb",
    ]


@pytest.mark.parametrize(
    "name", ["finalized_model.sav", "model.dill", "model.pkl.gz", "model.joblib.xz", ".ckpt"]
)
def test_more_pickle_names_are_rated_code_executing(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(INERT_PICKLE)
    result = ModelScanner().scan(tmp_path)
    (component,) = result.components
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION


def test_integrity_model_inspection_is_bound_to_the_pathname(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "model.keras").write_bytes(b"not a zip")
    bom = AIBOM(components=ModelScanner().scan(tmp_path).components)
    monkeypatch.setattr(
        "nexus_symbiote.validators.integrity.pathname_identity", lambda path: (0, 0)
    )
    report = IntegrityValidator().validate(bom, tmp_path)
    assert any(
        issue.category == "format_unverified" and "could not be bound" in issue.detail
        for issue in report.issues
    )


def test_integrity_validation_inspects_keras_configuration(tmp_path: Path) -> None:
    config = {"class_name": "Sequential", "config": {"layers": [DENSE, {"class_name": "Lambda"}]}}
    # Pad the archive so the buffered stream's read-ahead spans the central directory.
    _keras_archive(tmp_path / "model.keras", config, ("model.weights.h5", b"\0" * 300_000))
    bom = AIBOM(components=ModelScanner().scan(tmp_path).components)
    (component,) = bom.components
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    report = IntegrityValidator().validate(bom, tmp_path)
    assert any(
        issue.category == "unsafe_format" and "Lambda layer" in issue.detail
        for issue in report.issues
    )
