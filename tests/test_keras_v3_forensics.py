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


@pytest.mark.parametrize(
    "layer",
    [
        {"module": "builtins", "class_name": "function", "config": "relu"},
        {
            "module": "keras.layers.core.tf_op_layer",
            "class_name": "TFOpLambda",
            "config": {"name": "op", "function": "math.add"},
        },
    ],
)
def test_standard_keras_functions_are_not_arbitrary_code(tmp_path: Path, layer: dict) -> None:
    config = {"module": "keras", "class_name": "Functional", "config": {"layers": [layer]}}
    archive = _write_keras_zip(tmp_path / "standard.keras", config)
    assert inspect_model_format(archive) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)


@pytest.mark.parametrize(
    ("module", "function", "expected"),
    [
        ("builtins", "mean_squared_error", ZIP_WITHOUT_PICKLE),
        ("builtins", "categorical_accuracy", ZIP_WITHOUT_PICKLE),
        ("keras.losses", "mean_absolute_error", ZIP_WITHOUT_PICKLE),
        ("keras.losses", "cosine_similarity", ZIP_WITHOUT_PICKLE),
        ("keras.metrics", "binary_accuracy", ZIP_WITHOUT_PICKLE),
        ("keras.metrics", "pearson_correlation", ZIP_WITHOUT_PICKLE),
        ("keras.metrics", "mean_squared_error", ZIP_WITHOUT_PICKLE),
        ("keras.metrics", "relu", ZIP_MEMBER_UNREAD),
        ("keras.losses", "local_workshop_loss", ZIP_MEMBER_UNREAD),
    ],
)
def test_keras_compile_function_descriptors(
    tmp_path: Path, module: str, function: str, expected: str
) -> None:
    descriptor = {
        "module": module,
        "class_name": "function",
        "config": function,
        "registered_name": "function" if module == "builtins" else function,
    }
    config = {
        "module": "keras",
        "class_name": "Sequential",
        "config": {"layers": []},
        "compile_config": {"metrics": [descriptor]},
    }
    archive = _write_keras_zip(tmp_path / "compiled.keras", config)
    assert inspect_model_format(archive) == (SerializationSafety.UNKNOWN, expected)


@pytest.mark.parametrize("suffix", [".keras", ".npz"])
def test_nested_application_assets_are_not_model_descriptors(tmp_path: Path, suffix: str) -> None:
    archive = tmp_path / f"model{suffix}"
    with zipfile.ZipFile(archive, "w") as bundle:
        if suffix == ".keras":
            bundle.writestr(
                "config.json", '{"module":"keras","class_name":"Sequential","config":{"layers":[]}}'
            )
        bundle.writestr(
            "assets/config.json", '{"module":"builtins","class_name":"str","config":{}}'
        )
    assert inspect_model_format(archive) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"module": "keras", "class_name": "Sequential"},
        [],
        {
            "module": "keras",
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": None, "config": {}}]},
        },
        {"module": "example_definitions", "class_name": "function", "config": "an_ordinary_name"},
    ],
)
def test_incomplete_model_descriptor_is_unread(tmp_path: Path, config: object) -> None:
    archive = _write_keras_zip(tmp_path / "incomplete.keras", json.dumps(config))
    assert inspect_model_format(archive) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


def test_keras_descriptor_must_be_present_in_named_model(tmp_path: Path) -> None:
    archive = tmp_path / "missing.keras"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("assets/readme.txt", "example asset")
    assert inspect_model_format(archive) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


@pytest.mark.parametrize(
    "settings",
    [
        {"display_units": "meters", "description": "sample"},
        {"module": "builtins", "class_name": "str", "config": {}},
        {
            "class_name": "DisplayScale",
            "config": {"label_type": {"module": "builtins", "class_name": "str", "config": {}}},
        },
    ],
)
def test_generic_zip_may_contain_root_application_settings(tmp_path: Path, settings: dict) -> None:
    archive = tmp_path / "numeric.npz"
    # NumPy format 1.0, one unsigned byte, with a 16-byte-aligned data offset.
    header = b"{'descr': '|u1', 'fortran_order': False, 'shape': (1,), }".ljust(69) + b"\n"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "levels.npy",
            b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + b"\x02",
        )
        bundle.writestr("config.json", json.dumps(settings))
        bundle.writestr("metadata.json", '{"units":"meters"}')
    assert inspect_model_format(archive) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)


def test_renamed_custom_model_with_keras_archive_layout_is_inspected(tmp_path: Path) -> None:
    archive = tmp_path / "snapshot.npz"
    config = {"module": "workshop.models", "class_name": "Forecast", "config": None}
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("config.json", json.dumps(config))
        bundle.writestr("metadata.json", '{"keras_version":"3.9.2"}')
        bundle.writestr("model.weights.npz", b"")
    assert inspect_model_format(archive) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


@pytest.mark.parametrize("capacity", [0, 4, None, 128])
def test_descriptor_read_reserves_its_output_budget_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capacity: int | None
) -> None:
    from nexus_symbiote.scanners import model

    payload = b'{"class_name":"Sequential","config":{"layers":[]}}'
    units = len(payload) if capacity is None else capacity
    archive = _write_keras_zip(tmp_path / "budgeted.keras", payload)
    with zipfile.ZipFile(archive) as bundle:
        info = bundle.getinfo("config.json")
        boundary = bundle.getinfo("metadata.json").header_offset
    member = model._ZipMember(
        b"config.json", info.compress_type, info.compress_size, info.header_offset
    )
    budget = InspectionBudget(units)
    original = model._MemberData.read
    requests = []

    def checked_read(reader: model._MemberData, size: int) -> bytes:
        requests.append(size)
        assert budget.remaining == units - size
        return original(reader, size)

    monkeypatch.setattr(model._MemberData, "read", checked_read)
    with archive.open("rb") as stream:
        verdict = model._member_holds_keras_code(stream, member, boundary, budget, required=True)
    assert requests == ([units] if units else [])
    assert verdict is (False if units >= len(payload) else None)
    assert budget.remaining == max(0, units - len(payload))


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
    assert inspect_model_format(empty_path) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)

    non_utf8 = _write_keras_zip(tmp_path / "bin_cfg.keras", b"\xff\xfe\xfd")
    assert inspect_model_format(non_utf8) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)

    bad_json = _write_keras_zip(tmp_path / "bad_json.keras", "{not-json")
    assert inspect_model_format(bad_json) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


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
