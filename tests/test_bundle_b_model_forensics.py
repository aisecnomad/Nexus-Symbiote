"""Regression tests for Bundle B model and archive forensics hardening.

Covers:
- R-CRIT-01: CPython C-unpickler NUL truncation in protocol-0 GET/PUT (and FLOAT overflow).
- R-HIGH-01: Chained duplicate 0x0001 ZIP64 extra fields matching CPython zipfile._decodeExtra.
- R-HIGH-02: BINFLOAT-prefixed pickle disguised as .safetensors bypassing tensor_candidate.
- R-MED-16: Jinja2 {% raw %}...{% endraw %} blocks blinding _joined_literal_marker.
"""

from __future__ import annotations

import hashlib
import io
import pickle
import struct
import zipfile
from typing import TYPE_CHECKING

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.scanners.model import (
    ModelScanner,
    _zip64_location,
    inspect_model_format,
    observe_model_artifact,
)
from nexus_symbiote.utils.model_formats import template_escape_markers
from nexus_symbiote.utils.pickle_load import Budget, load_segment
from tests.support import scaling_ratio

if TYPE_CHECKING:
    from pathlib import Path


def _build_npy_object_array() -> bytes:
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    pad = 16 - ((10 + len(header) + 1) % 16)
    header_padded = header + b" " * pad + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header_padded)) + header_padded + b"N."


def _build_duplicate_zip64_npz(member_name: bytes, member_data: bytes) -> bytes:
    """Build a valid ZIP where a first 0x0001 extra keeps sentinels and a second supplies offsets."""
    crc = zipfile.crc32(member_data) & 0xFFFFFFFF
    size = len(member_data)
    local_header = (
        b"PK\x03\x04"
        + struct.pack("<HHHHHIIIHH", 45, 0, 0, 0, 0, crc, size, size, len(member_name), 0)
        + member_name
        + member_data
    )
    cd_offset = len(local_header)
    first_z64 = struct.pack("<HHQQQ", 0x0001, 24, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    second_z64 = struct.pack("<HHQQQ", 0x0001, 24, size, size, 0)
    extra = first_z64 + second_z64
    central_header = (
        b"PK\x01\x02"
        + struct.pack(
            "<HHHHHHIIIHHHHHII",
            45,
            45,
            0,
            0,
            0,
            0,
            crc,
            0xFFFFFFFF,
            0xFFFFFFFF,
            len(member_name),
            len(extra),
            0,
            0,
            0,
            0,
            0xFFFFFFFF,
        )
        + member_name
        + extra
    )
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(central_header), cd_offset, 0)
    return local_header + central_header + eocd


def test_pickle_get_put_nul_truncation_matches_cpython_c_unpickler() -> None:
    benign_payload = b"K0p0\x00bypass\n0g0\x00also\n."
    assert pickle.loads(benign_payload) == 48  # noqa: S301 - inert integer literal
    c_benign = load_segment(benign_payload, len(benign_payload), 0, "c", Budget(4096, 64))
    py_benign = load_segment(benign_payload, len(benign_payload), 0, "py", Budget(4096, 64))
    assert c_benign.outcome == "stop"
    assert py_benign.outcome == "error"

    exec_payload = b"K0p0\x00bypass\n0g0\x00also\n0cos\nsystem\n(S'id'\ntR."
    c_exec = load_segment(exec_payload, len(exec_payload), 0, "c", Budget(4096, 64))
    py_exec = load_segment(exec_payload, len(exec_payload), 0, "py", Budget(4096, 64))
    assert c_exec.outcome == "called"
    assert py_exec.outcome == "error"


def test_pickle_memo_bounds_and_float_overflow_nul_suffix() -> None:
    huge_put = b"K0p18446744073709551616\n."
    assert load_segment(huge_put, len(huge_put), 0, "c", Budget(4096, 64)).outcome == "error"
    assert load_segment(huge_put, len(huge_put), 0, "py", Budget(4096, 64)).outcome == "stop"

    neg_put = b"K0p-1\n."
    assert load_segment(neg_put, len(neg_put), 0, "c", Budget(4096, 64)).outcome == "error"
    assert load_segment(neg_put, len(neg_put), 0, "py", Budget(4096, 64)).outcome == "error"

    overflow_float = b"F1e999\x00inf\n."
    assert load_segment(overflow_float, len(overflow_float), 0, "c", Budget(4096, 64)).outcome == (
        "error"
    )

    real_inf = b"Finf\x00junk\n."
    assert load_segment(real_inf, len(real_inf), 0, "c", Budget(4096, 64)).outcome == "stop"


@pytest.mark.parametrize(
    "rel_path", ["models/weights.dat", "models/checkpoint", "models/direct.pkl"]
)
def test_model_scanner_catches_nul_truncated_put_get_pickle_regardless_of_extension(
    tmp_path: Path, rel_path: str
) -> None:
    target = tmp_path / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"K0p0\x00bypass\n0g0\x00also\n0cos\nsystem\n(S'id'\ntR.")

    result = ModelScanner().scan(tmp_path)
    matched = [c for c in result.components if c.source_path == rel_path]
    assert len(matched) == 1
    assert matched[0].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert any(
        r.category == "serialization_format" and r.severity is RiskSeverity.CRITICAL
        for r in matched[0].risks
    )


def test_duplicate_zip64_extra_field_object_array_is_rated_critical(tmp_path: Path) -> None:
    npy = _build_npy_object_array()
    archive = _build_duplicate_zip64_npz(b"arr_0.npy", npy)

    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        assert zf.read("arr_0.npy") == npy

    npz_path = tmp_path / "weights.npz"
    npz_path.write_bytes(archive)
    safety, _ = inspect_model_format(npz_path)
    assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION

    result = ModelScanner().scan(tmp_path)
    matched = [c for c in result.components if c.source_path == "weights.npz"]
    assert len(matched) == 1
    assert any(
        r.category == "serialization_format" and r.severity is RiskSeverity.CRITICAL
        for r in matched[0].risks
    )


def test_zip64_location_rejects_truncated_zip64_extra_field() -> None:
    truncated = struct.pack("<HH", 0x0001, 24) + b"\x00" * 16
    assert _zip64_location(truncated, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF) is None


def test_binfloat_pickle_disguised_as_safetensors_is_critical_with_exact_digest(
    tmp_path: Path,
) -> None:
    # BINFLOAT 0.0 starts with b"G\x00\x00\x00\x00\x00\x00\x00" whose 8-byte little-endian
    # integer is 71, triggering SafeTensors tensor_candidate on files >= 79 bytes.
    payload = b"G" + b"\x00" * 8 + b"0cos\nsystem\n(S'echo " + b"A" * 64 + b"'\ntR."
    assert len(payload) >= 79
    assert int.from_bytes(payload[:8], "little") == 71

    path = tmp_path / "model.safetensors"
    path.write_bytes(payload)

    safety, _ = inspect_model_format(path)
    assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION

    with open_regular_file(path) as stream:
        obs = observe_model_artifact(path, stream=stream)
    assert obs.safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert obs.digest == f"sha256:{hashlib.sha256(payload).hexdigest()}"

    result = ModelScanner().scan(tmp_path)
    matched = [c for c in result.components if c.source_path == "model.safetensors"]
    assert len(matched) == 1
    assert any(
        r.category == "serialization_format" and r.severity is RiskSeverity.CRITICAL
        for r in matched[0].risks
    )


def test_safetensors_valid_and_malformed_non_pickle_preserve_verdicts(tmp_path: Path) -> None:
    header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    valid = struct.pack("<Q", len(header)) + header + b"\x00" * 4
    valid_path = tmp_path / "good.safetensors"
    valid_path.write_bytes(valid)
    assert inspect_model_format(valid_path)[0] is SerializationSafety.SAFE

    bad_header = b"{not json at all!"
    malformed = struct.pack("<Q", len(bad_header)) + bad_header + b"\x00" * 16
    bad_path = tmp_path / "broken.safetensors"
    bad_path.write_bytes(malformed)
    safety, explanation = inspect_model_format(bad_path)
    assert safety is SerializationSafety.UNKNOWN
    assert "Malformed or unsupported SafeTensors" in explanation


@pytest.mark.parametrize(
    "template",
    [
        b'{% raw %}{#{% endraw %}{{ "_" ~ "_class_" ~ "_" }}',
        b'{% raw %}{{ \'{% endraw %}{{ "_" ~ "_class_" ~ "_" }}',
        b'{%- raw -%}{# unclosed comment {%- endraw -%}{{ "_" + "_globals_" + "_" }}',
        b'{%+ raw +%}{% if "{%+ endraw +%}{{ "_" ~ "_subclasses_" ~ "_" }}',
        b'{% raw %}{% raw %}{% endraw %}{{ "_" ~ "_builtins_" ~ "_" }}',
    ],
)
def test_jinja_raw_block_cannot_blind_joined_literal_marker(template: bytes) -> None:
    assert template_escape_markers(template) is True


@pytest.mark.parametrize(
    "template",
    [
        b'{% raw %}{{ "_" ~ "_class_" ~ "_" }}{% endraw %}{{ "hello" }}',
        b'{%- raw -%}{{ "_" ~ "_class_" ~ "_" }}{%- endraw -%}',
        b'{% raw %}{{ "_" ~ "_class_" ~ "_" }}',
    ],
)
def test_jinja_raw_block_literal_text_does_not_false_positive(template: bytes) -> None:
    assert template_escape_markers(template) is False


def test_jinja_raw_block_scanning_stays_linear() -> None:
    def run(scale: int) -> bool:
        chunk = b'{% raw %}{# unclosed " {% endraw %}' * (400 * scale)
        return template_escape_markers(chunk + b'{{ "plain" }}')

    assert scaling_ratio(run) < 10
