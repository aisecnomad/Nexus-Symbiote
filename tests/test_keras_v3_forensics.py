"""Tests for bounded Keras v3 ZIP archive Lambda and custom-callable forensics."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.scanners.model import (
    MAX_KERAS_CONFIG_BYTES,
    MAX_KERAS_CONFIG_DEPTH,
    ZIP_KERAS_CODE_EXECUTION,
    ZIP_MEMBER_UNREAD,
    ZIP_WITHOUT_PICKLE,
    ModelScanner,
    inspect_model_format,
)
from nexus_symbiote.utils.model_formats import InspectionBudget


def _write_keras_zip(
    path: Path,
    config: dict[str, object] | str | bytes,
    *,
    member_name: str = "config.json",
    compression: int = zipfile.ZIP_DEFLATED,
) -> Path:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        if isinstance(config, bytes):
            payload = config
        elif isinstance(config, str):
            payload = config.encode("utf-8")
        else:
            payload = json.dumps(config).encode("utf-8")
        archive.writestr(member_name, payload)
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
    return path


def test_benign_keras_v3_archive_is_not_flagged_as_code_execution(tmp_path: Path) -> None:
    config = {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "Dense",
                    "config": {"units": 32, "activation": "relu"},
                }
            ],
        },
    }
    model_path = _write_keras_zip(tmp_path / "clean.keras", config)
    safety, explanation = inspect_model_format(model_path)
    assert safety is SerializationSafety.UNKNOWN
    assert explanation == ZIP_WITHOUT_PICKLE


def test_keras_v3_lambda_layer_is_flagged_as_unsafe_code_execution(tmp_path: Path) -> None:
    config = {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "Lambda",
                    "config": {
                        "name": "evil_lambda",
                        "function": {
                            "class_name": "__lambda__",
                            "config": {"code": "4wEAAAAAAAAAAQAAAA=="},
                        },
                    },
                }
            ]
        },
    }
    model_path = _write_keras_zip(tmp_path / "lambda.keras", config)
    safety, explanation = inspect_model_format(model_path)
    assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert explanation == ZIP_KERAS_CODE_EXECUTION

    result = ModelScanner().scan(tmp_path)
    assert len(result.components) == 1
    comp = result.components[0]
    assert comp.serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert any(
        risk.severity is RiskSeverity.CRITICAL and risk.category == "serialization_format"
        for risk in comp.risks
    )


@pytest.mark.parametrize("module_name", ["os", "subprocess", "builtins", "posix.path", "importlib"])
def test_keras_v3_dangerous_module_deserialization_flagged(
    tmp_path: Path, module_name: str
) -> None:
    config = {
        "module": "keras",
        "class_name": "Functional",
        "config": {
            "layers": [
                {
                    "module": module_name,
                    "class_name": "system",
                    "registered_name": "system",
                    "config": {"command": "id"},
                }
            ]
        },
    }
    model_path = _write_keras_zip(tmp_path / "cve_2025_1550.keras", config)
    safety, explanation = inspect_model_format(model_path)
    assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert explanation == ZIP_KERAS_CODE_EXECUTION


def test_keras_v3_tf_op_lambda_with_function_flagged(tmp_path: Path) -> None:
    config = {
        "module": "keras.layers.core.tf_op_layer",
        "class_name": "TFOpLambda",
        "config": {"name": "op", "function": "os.system"},
    }
    model_path = _write_keras_zip(
        tmp_path / "tf_op.keras", config, member_name="nested/config.json"
    )
    safety, explanation = inspect_model_format(model_path)
    assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert explanation == ZIP_KERAS_CODE_EXECUTION


def test_renamed_keras_lambda_archive_under_models_dir_caught_by_content(tmp_path: Path) -> None:
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    config = {"module": "keras.layers", "class_name": "Lambda", "config": {}}
    _write_keras_zip(models_dir / "disguised.dat", config)
    result = ModelScanner().scan(tmp_path)
    assert len(result.components) == 1
    assert result.components[0].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert result.components[0].serialization_format == "zip-archive"


def test_keras_oversized_config_fails_closed_as_unread(tmp_path: Path) -> None:
    # A small deflated blob expanding past MAX_KERAS_CONFIG_BYTES must fail closed
    # to ZIP_MEMBER_UNREAD rather than being skipped as clean.
    huge = b'{"padding":"' + (b"a" * (MAX_KERAS_CONFIG_BYTES + 1024)) + b'"}'
    model_path = _write_keras_zip(tmp_path / "bomb.keras", huge)
    safety, explanation = inspect_model_format(model_path)
    assert safety is SerializationSafety.UNKNOWN
    assert explanation == ZIP_MEMBER_UNREAD


def test_keras_deeply_nested_config_fails_closed_as_unread(tmp_path: Path) -> None:
    depth = MAX_KERAS_CONFIG_DEPTH + 5
    payload = ("[" * depth) + "0" + ("]" * depth)
    model_path = _write_keras_zip(tmp_path / "deep.keras", payload)
    safety, explanation = inspect_model_format(model_path)
    assert safety is SerializationSafety.UNKNOWN
    assert explanation == ZIP_MEMBER_UNREAD


def test_keras_budget_exhaustion_fails_closed_as_unread(tmp_path: Path) -> None:
    config = {"module": "keras", "class_name": "Sequential", "config": {"layers": []}}
    model_path = _write_keras_zip(tmp_path / "budget.keras", config)
    tight_budget = InspectionBudget(4)
    safety, explanation = inspect_model_format(model_path, budget=tight_budget)
    assert safety is SerializationSafety.UNKNOWN
    assert explanation == ZIP_MEMBER_UNREAD


def test_keras_non_json_or_empty_config_does_not_crash(tmp_path: Path) -> None:
    empty_path = _write_keras_zip(tmp_path / "empty.keras", b"")
    assert inspect_model_format(empty_path) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)

    non_utf8 = _write_keras_zip(tmp_path / "bin_cfg.keras", b"\xff\xfe\xfd")
    assert inspect_model_format(non_utf8) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)

    bad_json = _write_keras_zip(tmp_path / "bad_json.keras", "{not-json")
    assert inspect_model_format(bad_json) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16-le", "utf-16-be", "utf-32-le"])
def test_keras_bom_and_utf16_utf32_config_json_still_detected(
    tmp_path: Path, encoding: str
) -> None:
    config = {"module": "keras.layers", "class_name": "Lambda", "config": {}}
    encoded = json.dumps(config).encode(encoding)
    model_path = _write_keras_zip(tmp_path / f"enc_{encoding}.keras", encoded)
    safety, explanation = inspect_model_format(model_path)
    assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert explanation == ZIP_KERAS_CODE_EXECUTION


def test_keras_infozip_unicode_path_0x7075_disguised_config_json_detected(
    tmp_path: Path,
) -> None:
    import struct
    import zlib

    # Store malicious config under benign central-directory name "benign.txt" with a
    # valid CRC32 Info-ZIP 0x7075 Unicode Path extra field renaming it to "config.json".
    config = json.dumps({"module": "keras.layers", "class_name": "Lambda", "config": {}}).encode()
    stored_name = b"benign.txt"
    unicode_name = b"config.json"
    upath_payload = struct.pack("<BI", 1, zlib.crc32(stored_name)) + unicode_name
    upath_extra = struct.pack("<HH", 0x7075, len(upath_payload)) + upath_payload

    info = zipfile.ZipInfo(stored_name.decode("ascii"))
    info.extra = upath_extra
    model_path = tmp_path / "unicode_path.keras"
    with zipfile.ZipFile(model_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(info, config)

    safety, explanation = inspect_model_format(model_path)
    assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert explanation == ZIP_KERAS_CODE_EXECUTION
