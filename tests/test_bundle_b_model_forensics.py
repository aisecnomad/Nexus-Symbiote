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
import sys
import zipfile
from typing import TYPE_CHECKING

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.scanners.model import (
    ModelScanner,
    _PrefixedStream,
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
        b'{%+ raw %}{% if "{%+ endraw -%}{{ "_" ~ "_subclasses_" ~ "_" }}',
        b'{% raw %}{% raw %}{% endraw %}{{ "_" ~ "_builtins_" ~ "_" }}',
        # Jinja2 3.1 ends a raw block at "+%}" too (TOKEN_RAW_BEGIN's end rule).
        b'{% raw %}hello{% endraw +%}{{ a["_" ~ "_class_" ~ "_"] }}',
        b'{% set x = ({1: {2: 3}}, a["_" ~ "_class_" ~ "_"]) %}',
        # A "}}" that closes nested dict braces does not end the tag: Jinja's lexer
        # matches a tag's end only while brackets balance.
        b'{{ ({1: {2: 3}}, a["_" ~ "_class_" ~ "_"]) }}',
        b'{{ {1: {2: 3}} and "{% raw %}" }}{{ a["_" ~ "_class_" ~ "_"] }}',
        b'{{ {1: 2}}}{{ a["_" ~ "_class_" ~ "_"] }}',
        # A ")" skipped between two joined pieces still closes its "(": the tag ends at
        # its "}}" and the apostrophe after it is text, not the start of a string.
        b'{{ ("x") ~ "y" }} Don\'t {{ a["_" ~ "_class_" ~ "_"] }}',
        b"{{ ('<|' + message['role'] + '|>') + '\\n' }} Don't "
        + b'{{ cycler["_" ~ "_init_" ~ "_"]["_" ~ "_globals_" ~ "_"] }}',
        # Jinja2 3.x ends this raw block at "+%}", 2.x only at the later "{% endraw %}",
        # which makes the payload a live tag: both readings are checked.
        b'{% raw %}X{% endraw +%}{# {% endraw %}{{ a["_" ~ "_class_" ~ "_"] }} #}',
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
        b'{% raw %}{{ "_" ~ "_class_" ~ "_" }}{% endraw +%}{{ "hello" }}',
        b'{{ {1: {2: 3}} }}"_" ~ "_class_" ~ "_"',
    ],
)
def test_jinja_raw_block_literal_text_does_not_false_positive(template: bytes) -> None:
    assert template_escape_markers(template) is False


@pytest.mark.parametrize(
    "payload",
    [
        b"cos\x00x\ngetpid\n)R.",
        b"cos\x00/\ngetpid\n)R.",
        b"\x80\x04\x8c\x04os\x00x\x8c\x06getpid\x93)R.",
    ],
)
def test_frozen_importer_nul_truncated_module_name_is_detected(
    tmp_path: Path, payload: bytes
) -> None:
    if sys.version_info < (3, 13):
        # CPython 3.11-3.12 FrozenImporter C-string strcmp executes NUL-truncated names.
        assert pickle.loads(payload) > 0  # noqa: S301 - inert os.getpid()
    for flavor in ("c", "py"):
        seg = load_segment(payload, len(payload), 0, flavor, Budget(4096, 64))
        assert seg.outcome == "called"
    weights = tmp_path / "weights.dat"
    weights.write_bytes(payload)
    result = ModelScanner().scan(tmp_path)
    matched = [c for c in result.components if c.source_path == "weights.dat"]
    assert len(matched) == 1
    assert matched[0].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION


def test_valid_safetensors_and_executable_pickle_polyglot_is_rated_critical(
    tmp_path: Path,
) -> None:
    header_len = (28 << 8) | 0x43  # SHORT_BINBYTES len 28
    prefix = struct.pack("<Q", header_len)
    chunk = bytearray(b'{"__metadata__":{"a":"')
    json_tail = b'"},"w":{"dtype":"F32","shape":[16],"data_offsets":[0,64]}}'
    k = len(json_tail) + 10
    target = header_len - 2 - k
    chunk.append(ord("0"))
    while target - len(chunk) > 128:
        chunk.extend(b"C" + bytes([125]) + b"a" * 125 + b"0")
    s = target - len(chunk) - 3
    chunk.extend(b"C" + bytes([s]) + b"a" * s + b"0")
    chunk.extend(b"C" + bytes([k]) + b"b" * (k - len(json_tail)) + json_tail)
    tensor_data = b"0cos\ngetpid\n)R.".ljust(64, b"\x00")
    polyglot = prefix + bytes(chunk) + tensor_data
    assert pickle.loads(polyglot) > 0  # noqa: S301 - inert os.getpid()

    path = tmp_path / "polyglot.safetensors"
    path.write_bytes(polyglot)
    safety, _ = inspect_model_format(path)
    assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION

    with open_regular_file(path) as stream:
        obs = observe_model_artifact(path, stream=stream)
    assert obs.safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert obs.digest == f"sha256:{hashlib.sha256(polyglot).hexdigest()}"


def test_prefixed_stream_read_all_and_zero_preserve_bytes() -> None:
    stream = _PrefixedStream(b"hello", io.BytesIO(b"world"))
    assert stream.read(0) == b""
    assert stream.read(-1) == b"helloworld"
    assert stream.read() == b""

    chunked = _PrefixedStream(b"hello", io.BytesIO(b"world"))
    assert chunked.read(3) == b"hel"
    assert chunked.read() == b"loworld"


def test_jinja_raw_block_scanning_stays_linear() -> None:
    def run(scale: int) -> bool:
        chunk = b'{% raw %}{# unclosed " {% endraw %}' * (400 * scale)
        return template_escape_markers(chunk + b'{{ "plain" }}')

    assert scaling_ratio(run) < 10


def test_c_unpickler_int_with_leading_zeros_past_the_int_digit_limit_is_followed(
    tmp_path: Path,
) -> None:
    # strtol reads any number of leading zeros; int() refuses more than 4,300 digits.
    zeros = b"0" * (sys.get_int_max_str_digits() + 1)
    payload = b"I" + zeros + b"\n0cos\ngetpid\n)R."
    assert pickle.loads(payload) > 0  # noqa: S301 - inert os.getpid()
    segment = load_segment(payload, len(payload), 0, "c", Budget(65536, 64))
    assert segment.outcome == "called"

    # Past what a C long holds, strtol overflows and PyLong_FromString reads the digits:
    # under the default limit it refuses them, under no limit it reads them and the call
    # runs, so the walk goes on as the loader with no limit does ("int-digits").
    overflowing = b"I" + b"1" * (sys.get_int_max_str_digits() + 1) + b"\n0cos\ngetpid\n)R."
    with pytest.raises(ValueError):
        pickle.loads(overflowing)  # noqa: S301 - refused before any call
    overflowed = load_segment(overflowing, len(overflowing), 0, "c", Budget(65536, 64))
    assert overflowed.outcome == "called"
    assert "int-digits" in overflowed.differs

    for rel_path in ("models/weights.dat", "models/direct.pkl"):
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    result = ModelScanner().scan(tmp_path)
    for rel_path in ("models/weights.dat", "models/direct.pkl"):
        matched = [c for c in result.components if c.source_path == rel_path]
        assert len(matched) == 1, rel_path
        assert matched[0].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION


def test_hashing_reader_never_asks_for_more_than_the_limit() -> None:
    from dataclasses import replace

    from nexus_symbiote import limits
    from nexus_symbiote.scanners.model import _HashingModelReader

    requested: list[int] = []

    class _Recording(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            requested.append(-1 if size is None else size)
            return super().read(size)

    with limits.applied(replace(limits.DEFAULTS, model_bytes=16)):
        reader = _HashingModelReader(_Recording(b"A" * 64))
    with pytest.raises(OSError, match="hash byte limit"):
        reader.read(-1)
    assert requested == [17]


_DIGIT_CALLS = {
    "int": b"I" + b"1" * 5000 + b"\n0cos\ngetpid\n)R.",
    "long": b"L" + b"1" * 5000 + b"L\n0cos\ngetpid\n)R.",
    "get": b"K0p0\n0g" + b"0" * 5000 + b"\n0cos\ngetpid\n)R.",
    "put": b"K0p" + b"0" * 5000 + b"\n0cos\ngetpid\n)R.",
}


@pytest.mark.parametrize("payload", _DIGIT_CALLS.values(), ids=_DIGIT_CALLS)
def test_text_integers_are_read_whatever_the_int_digit_limit(payload: bytes) -> None:
    # A loader run with int_max_str_digits=0 reads every one of these and calls getpid.
    import subprocess

    loaded = subprocess.run(
        [
            sys.executable,
            "-I",
            "-X",
            "int_max_str_digits=0",
            "-c",
            "import pickle, sys; pickle.loads(sys.stdin.buffer.read()); print('loaded')",
        ],
        input=payload,
        capture_output=True,
        check=False,
    )
    assert loaded.stdout.strip() == b"loaded"
    for flavor in ("c", "py"):
        segment = load_segment(payload, len(payload), 0, flavor, Budget(65536, 64))
        assert segment.outcome == "called", flavor
        assert "int-digits" in segment.differs


def test_a_memo_index_past_a_c_long_still_fails_the_c_unpickler() -> None:
    index = b"1" + b"0" * 5000
    payload = b"K0p" + index + b"\n0cos\ngetpid\n)R."
    assert load_segment(payload, len(payload), 0, "c", Budget(65536, 64)).outcome == "error"
    boundary = b"K0p9223372036854775807\n0g9223372036854775807\n."
    assert load_segment(boundary, len(boundary), 0, "c", Budget(4096, 64)).outcome == "stop"
    over = b"K0p9223372036854775808\n."
    assert load_segment(over, len(over), 0, "c", Budget(4096, 64)).outcome == "error"
