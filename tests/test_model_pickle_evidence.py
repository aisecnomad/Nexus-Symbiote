"""A pickle-family name is rated by its inspected content, not by the name alone."""

from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import os
import pickle
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.models import CompletenessClaim, ModelComponent
from nexus_symbiote.scanners.model import (
    MAX_MODEL_HEADER_BYTES,
    MAX_PICKLE_INSPECTION_BYTES,
    NUMPY_OBJECT_ARRAY,
    PICKLE_NAME_EMPTY,
    PICKLE_NAME_GGUF,
    PICKLE_NAME_UNEVIDENCED,
    PICKLE_NAME_UNREADABLE,
    PICKLE_NAME_WRAPPED,
    ZIP_DIRECTORY_UNREAD,
    ZIP_PICKLE_MEMBER,
    ZIP_WITHOUT_PICKLE,
    ModelScanner,
    inspect_model_format,
    model_format,
)
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.validators.risk import RiskScorer

UNSAFE = SerializationSafety.UNSAFE_CODE_EXECUTION
UNKNOWN = SerializationSafety.UNKNOWN
UNHASHED = "Potential code-executing loader format (artifact could not be hashed)"
LOADER = "Potential code-executing loader format ({})"
# A synthetic pickle that calls builtins.eval on a constant; it is never loaded here.
EVAL_PICKLE = b"cbuiltins\neval\n(S'1'\ntR."
HOSTILE_TEMPLATE = "{{ self.__init__.__globals__.__builtins__ }}"
BENIGN_TEMPLATE = "{{ messages[0].content }}"


def _npy_object_array() -> bytes:
    text = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    text += " " * (-(10 + 2 + len(text) + 1) % 64) + "\n"
    return b"\x93NUMPY\x01\x00" + len(text).to_bytes(2, "little") + text.encode() + b"\x00" * 8


def _torch_zip(member: str = "archive/data.pkl") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(member, pickle.dumps({"weight": [0.0]}, protocol=2))
        archive.writestr("archive/version", b"3\n")
    return buffer.getvalue()


def _gguf(template: str) -> bytes:
    """A version 3 GGUF file with an architecture key and one chat template."""

    def string(text: str) -> bytes:
        raw = text.encode()
        return len(raw).to_bytes(8, "little") + raw

    entries = [
        ("general.architecture", string("llama")),
        ("tokenizer.chat_template", string(template)),
    ]
    header = b"GGUF" + (3).to_bytes(4, "little") + (0).to_bytes(8, "little")
    header += len(entries).to_bytes(8, "little")
    for key, value in entries:
        header += string(key) + (8).to_bytes(4, "little") + value
    return header + b"\0" * 32


def _tar(member: str, data: bytes, *more: str, form: int = tarfile.USTAR_FORMAT) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=form) as archive:
        for name in (member, *more):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _checksummed(block: bytearray, offset: int = 0) -> None:
    header = block[offset : offset + 512]
    header[148:156] = b" " * 8
    block[offset + 148 : offset + 156] = b"%06o\0 " % sum(header)


def _v7(archive: bytes, name: bytes | None = None, typeflag: bytes | None = None) -> bytes:
    """``archive`` as a pre-POSIX tar: no ustar magic, each header's checksum recomputed."""
    data = bytearray(archive)
    offset = 0
    while any(data[offset : offset + 512]):
        size = int(data[offset + 124 : offset + 136].split(b"\0")[0] or b"0", 8)
        data[offset + 257 : offset + 263] = bytes(6)
        if offset == 0 and name is not None:
            data[0:100] = name.ljust(100, b"\0")
        if offset == 0 and typeflag is not None:
            data[156:157] = typeflag
        _checksummed(data, offset)
        offset += 512 + -(-size // 512) * 512
    return bytes(data)


def _base256_checksum(archive: bytes) -> bytes:
    """``archive`` with its first header's checksum in a positive base-256 field."""
    data = bytearray(archive)
    data[148:156] = b"\x80" + (256 + sum(data[:148]) + sum(data[156:512])).to_bytes(7, "big")
    return bytes(data)


def _space_checksum(archive: bytes) -> bytes:
    """``archive`` with an all-space checksum field, which tarfile reads as 0.

    High bytes in the owner names, which no loader reads, bring the signed checksum to 0.
    """
    data = bytearray(archive)
    data[148:156] = b" " * 8
    excess = 256 + sum(data[:148]) + sum(data[156:512])
    high = b"\x80" * (excess // 128) + bytes([256 - excess % 128] if excess % 128 else [])
    data[265 : 265 + len(high)] = high
    return bytes(data)


def _lzma_alone(dictionary: int, header: dict[int, bytes] | None = None) -> bytes:
    """``EVAL_PICKLE`` in an LZMA-alone stream, with header bytes patched at their offsets."""
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dictionary}]
    data = bytearray(lzma.compress(EVAL_PICKLE, format=lzma.FORMAT_ALONE, filters=filters))
    for offset, value in (header or {}).items():
        data[offset : offset + len(value)] = value
    return bytes(data)


def _lzma_payload(payload: bytes) -> bytes:
    """What an LZMA-alone stream decodes to, whichever liblzma this Python links.

    The encoder ends every stream with an end marker. A liblzma before 5.4, such as the
    one in python.org's macOS build, refuses that marker after a known size, which later
    releases, and the loaders that link them, accept; the same stream with the size
    unknown then shows what they read.
    """
    try:
        return lzma.decompress(payload, format=lzma.FORMAT_ALONE)
    except lzma.LZMAError:
        if payload[5:13] == b"\xff" * 8:
            raise
        unknown_size = payload[:5] + b"\xff" * 8 + payload[13:]
        return lzma.decompress(unknown_size, format=lzma.FORMAT_ALONE)


def _oversized_directory_zip() -> bytes:
    """A torch-style archive whose pickle member sits behind a directory past the bound."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/version", b"3\n")
        filler = 3000
        for index in range(MAX_MODEL_HEADER_BYTES // filler + 1):
            archive.writestr(f"archive/{index:04d}".ljust(filler, "x"), b"")
        archive.writestr("archive/data.pkl", EVAL_PICKLE)
    return buffer.getvalue()


def _scan(root: Path) -> tuple[dict[str, ModelComponent], list[str]]:
    result = ModelScanner().scan(root)
    found = {
        component.source_path or "": component
        for component in result.components
        if isinstance(component, ModelComponent)
    }
    return found, [str(failure) for failure in result.scan_failures]


def _severities(component: ModelComponent) -> set[tuple[str, str]]:
    return {(risk.category, risk.severity.value) for risk in component.risks}


def _gate(components: list[ModelComponent]) -> tuple[bool, set[tuple[str, str]]]:
    bom = AIBOM(components=list(components))
    collectors = ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"]
    bom.metadata.completeness = CompletenessClaim(
        scope="repository",
        surfaces_scanned=["all"],
        scanner_status=dict.fromkeys(collectors, "complete"),
        collectors_requested=collectors,
        collectors_completed=collectors,
    )
    passed, report = RiskScorer().passes_gate(bom)
    assert report.coverage_status == "reported"
    return passed, {(finding.category, finding.severity.value) for finding in report.findings}


def test_a_zero_filled_bin_is_unknown_with_a_high_finding_and_passes_the_gate(
    tmp_path: Path,
) -> None:
    (tmp_path / "data" / "raw").mkdir(parents=True)
    (tmp_path / "data" / "raw" / "embeddings.bin").write_bytes(
        b"\0" * (2 * MAX_PICKLE_INSPECTION_BYTES + 7)
    )
    found, failures = _scan(tmp_path)
    assert failures == []
    component = found["data/raw/embeddings.bin"]
    assert component.serialization_safety is UNKNOWN
    assert component.serialization_format == "pytorch-legacy"
    assert component.properties["format_inspection"] == PICKLE_NAME_UNEVIDENCED
    assert component.hashes["sha256"].startswith("sha256:")
    severities = _severities(component)
    assert ("serialization_format_unknown", "high") in severities
    assert not any(severity == "critical" for _, severity in severities)
    passed, findings = _gate([component])
    # The risk validator keeps the collector's high finding and adds no critical one.
    assert ("serialization_format_unknown", "high") in findings
    assert ("serialization_format", "critical") not in findings
    assert passed


@pytest.mark.parametrize("protocol", [0, 2, 4])
@pytest.mark.parametrize("suffix", [".pkl", ".pt", ".bin", ".pth.tar"])
def test_a_pickle_stream_under_a_pickle_family_name_is_critical(
    tmp_path: Path, protocol: int, suffix: str
) -> None:
    (tmp_path / f"model{suffix}").write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol))
    found, failures = _scan(tmp_path)
    assert failures == []
    component = found[f"model{suffix}"]
    assert component.serialization_safety is UNSAFE
    kind = "binary" if protocol else "text-protocol"
    assert component.properties["format_inspection"] == (
        f"Recognized {kind} pickle opcode stream; object loading can execute code"
    )
    assert ("serialization_format", "critical") in _severities(component)
    assert not _gate([component])[0]


def test_a_torch_zip_archive_with_a_pickle_member_is_critical(tmp_path: Path) -> None:
    (tmp_path / "model.pt").write_bytes(_torch_zip())
    (tmp_path / "pytorch_model.bin").write_bytes(_torch_zip("data.pkl"))
    found, failures = _scan(tmp_path)
    assert failures == []
    for name in ("model.pt", "pytorch_model.bin"):
        assert found[name].serialization_safety is UNSAFE, name
        assert found[name].properties["format_inspection"] == ZIP_PICKLE_MEMBER, name
        assert ("serialization_format", "critical") in _severities(found[name]), name


@pytest.mark.parametrize(
    ("payload", "detail"),
    [
        (b"N0" * (2 * MAX_PICKLE_INSPECTION_BYTES) + b".", "names no callable before the"),
        (b"cos\nsystem\n" + b"N0" * (2 * MAX_PICKLE_INSPECTION_BYTES) + b".", "resolves an"),
    ],
    ids=["padded-before-the-bound", "name-padded-before-the-bound"],
)
def test_a_pickle_the_bounds_leave_unrated_is_critical_under_a_pickle_family_name(
    tmp_path: Path, payload: bytes, detail: str
) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "padded.pkl").write_bytes(payload)
    (tmp_path / "models" / "padded").write_bytes(payload)
    found, failures = _scan(tmp_path)
    assert failures == []
    named = found["models/padded.pkl"]
    assert named.serialization_safety is UNSAFE
    evidence = named.properties["format_inspection"]
    assert evidence.startswith("Potential code-executing loader format (pickle opcode stream")
    assert detail in evidence
    assert "no bounded structural validator" not in evidence
    assert ("serialization_format", "critical") in _severities(named)
    # The same bytes found by content, which no name rates, keep the bounded verdict.
    by_content = found["models/padded"]
    assert by_content.serialization_safety is UNKNOWN
    assert by_content.properties["format_inspection"].endswith(
        "no bounded structural validator for this format/loader"
    )
    assert detail in by_content.properties["format_inspection"]


def test_a_zip_archive_without_a_pickle_member_under_a_pickle_family_name_is_unknown(
    tmp_path: Path,
) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("weights.safetensors", b"\0" * 32)
    (tmp_path / "bundle.pt").write_bytes(buffer.getvalue())
    found, failures = _scan(tmp_path)
    assert failures == []
    component = found["bundle.pt"]
    assert component.serialization_safety is UNKNOWN
    assert component.properties["format_inspection"] == ZIP_WITHOUT_PICKLE
    assert ("serialization_format_unknown", "high") in _severities(component)


def test_a_zip_directory_past_the_bound_keeps_the_critical_rating_under_a_pickle_name(
    tmp_path: Path,
) -> None:
    archive = _oversized_directory_zip()
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist()[0] == "archive/version"
        assert opened.namelist()[-1] == "archive/data.pkl"
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "model.pt").write_bytes(archive)
    (tmp_path / "models" / "archive").write_bytes(archive)
    found, failures = _scan(tmp_path)
    assert failures == []
    named = found["models/model.pt"]
    assert named.serialization_safety is UNSAFE
    assert named.properties["format_inspection"] == LOADER.format(
        "ZIP archive whose directory is malformed or over the inspection limit"
    )
    assert ("serialization_format", "critical") in _severities(named)
    # The same bytes found by content, which no name rates, keep the bounded verdict.
    by_content = found["models/archive"]
    assert by_content.serialization_safety is UNKNOWN
    assert by_content.properties["format_inspection"] == ZIP_DIRECTORY_UNREAD


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("m.pkl.gz", gzip.compress(EVAL_PICKLE, mtime=0)),
        ("m.pkl.bz2", bz2.compress(EVAL_PICKLE)),
        ("m.pkl.xz", lzma.compress(EVAL_PICKLE)),
        ("m.pkl.lzma", lzma.compress(EVAL_PICKLE, format=lzma.FORMAT_ALONE)),
        ("m.pkl.tar", _tar("data.pkl", EVAL_PICKLE)),
        ("m.joblib", zlib.compress(EVAL_PICKLE)),
        ("m.joblib.gz", gzip.compress(EVAL_PICKLE, mtime=0)),
        ("m.pkl", gzip.compress(EVAL_PICKLE, mtime=0)),
        ("legacy.pt", _tar("pickle", EVAL_PICKLE)),
        ("m.pkl.zst", b"\x28\xb5\x2f\xfd" + b"\0" * 32),
        ("m.joblib", b"\x04\x22\x4d\x18" + b"\0" * 32),
        ("m.pkl", b"ZF0x" + zlib.compress(EVAL_PICKLE)),
        ("m.pkl.gz", b"\0" * 64),
    ],
    ids=[
        "gzip-suffix",
        "bz2-suffix",
        "xz-suffix",
        "lzma-alone-suffix",
        "tar-suffix",
        "zlib-joblib",
        "gzip-joblib",
        "gzip-magic-under-pkl",
        "ustar-magic-under-pt",
        "zstd-suffix",
        "lz4-magic-under-joblib",
        "joblib-legacy-zfile",
        "wrapper-suffix-alone",
    ],
)
def test_a_compressed_or_archived_pickle_family_file_is_critical(
    tmp_path: Path, name: str, payload: bytes
) -> None:
    (tmp_path / name).write_bytes(payload)
    assert inspect_model_format(tmp_path / name) == (UNSAFE, PICKLE_NAME_WRAPPED)
    found, failures = _scan(tmp_path)
    assert failures == []
    assert found[name].serialization_safety is UNSAFE
    assert found[name].properties["format_inspection"] == PICKLE_NAME_WRAPPED
    assert ("serialization_format", "critical") in _severities(found[name])
    assert not _gate([found[name]])[0]


@pytest.mark.parametrize(
    "payload",
    [
        b"\0" * 512,
        b"\x1f" + b"\0" * 511,
        b"\0" * 257 + b"ustaX" + b"\0" * 250,
        b"GGU" + b"\0" * 509,
        b"gguf" + b"\0" * 508,
    ],
    ids=["zeros", "half-gzip-magic", "near-ustar", "partial-gguf-magic", "lowercase-gguf-magic"],
)
def test_bytes_with_no_wrapper_magic_under_a_plain_pickle_name_stay_unknown(
    tmp_path: Path, payload: bytes
) -> None:
    (tmp_path / "embeddings.bin").write_bytes(payload)
    assert inspect_model_format(tmp_path / "embeddings.bin") == (UNKNOWN, PICKLE_NAME_UNEVIDENCED)


LZMA_LOADED = {
    "lzma-4k-joblib": ("m.joblib", _lzma_alone(4096)),
    "lzma-32k-joblib": ("m.joblib", _lzma_alone(32768)),
    "lzma-4k-pkl": ("m.pkl", _lzma_alone(4096)),
    "lzma-32k-pkl": ("m.pkl", _lzma_alone(32768)),
    "lzma-48k-bin": ("m.bin", _lzma_alone(49152)),
    "lzma-64k-joblib": ("m.joblib", _lzma_alone(65536)),
    "lzma-8m-pkl": ("m.pkl", _lzma_alone(8 << 20)),
    "lzma-256-byte-dictionary-joblib": ("m.joblib", _lzma_alone(4096, {1: b"\x00\x01\x00\x00"})),
    "lzma-zero-dictionary-joblib": ("m.joblib", _lzma_alone(4096, {1: bytes(4)})),
    "lzma-known-size-pkl": (
        "m.pkl",
        _lzma_alone(4096, {5: len(EVAL_PICKLE).to_bytes(8, "little")}),
    ),
}
TAR_LOADED = {
    "v7-storages-pt": ("legacy.pt", _v7(_tar("storages", EVAL_PICKLE, "pickle"))),
    "v7-pickle-ckpt": ("legacy.ckpt", _v7(_tar("pickle", EVAL_PICKLE))),
    "ustar-storages-pt": ("legacy.pt", _tar("storages", EVAL_PICKLE, "pickle")),
    "gnu-storages-pt": ("legacy.pt", _tar("storages", EVAL_PICKLE, form=tarfile.GNU_FORMAT)),
    "pax-pickle-ckpt": ("legacy.ckpt", _tar("pickle", EVAL_PICKLE, form=tarfile.PAX_FORMAT)),
    "v7-empty-first-name-pt": ("legacy.pt", _v7(_tar("x", EVAL_PICKLE, "pickle"), name=b"")),
    "v7-unknown-first-type-pt": ("legacy.pt", _v7(_tar("x", EVAL_PICKLE, "pickle"), typeflag=b"Z")),
    "v7-base-256-checksum-pt": ("legacy.pt", _base256_checksum(_v7(_tar("storages", EVAL_PICKLE)))),
    "v7-space-checksum-pt": ("legacy.pt", _space_checksum(_v7(_tar("storages", EVAL_PICKLE)))),
}


@pytest.mark.parametrize(
    ("name", "payload"),
    [*LZMA_LOADED.values(), *TAR_LOADED.values()],
    ids=[*LZMA_LOADED, *TAR_LOADED],
)
def test_an_lzma_alone_or_tar_stream_without_its_usual_magic_is_critical(
    tmp_path: Path, name: str, payload: bytes
) -> None:
    # joblib opens any LZMA-alone stream that starts 5d 00, whatever its dictionary, and
    # torch.load's legacy path opens any tar archive tarfile reads, ustar or V7.
    if payload.startswith(b"\x5d\x00"):
        assert _lzma_payload(payload) == EVAL_PICKLE
    else:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            assert {"storages", "pickle"} & set(archive.getnames())
    (tmp_path / name).write_bytes(payload)
    assert inspect_model_format(tmp_path / name) == (UNSAFE, PICKLE_NAME_WRAPPED)
    found, failures = _scan(tmp_path)
    assert failures == []
    assert found[name].properties["format_inspection"] == PICKLE_NAME_WRAPPED
    passed, findings = _gate([found[name]])
    assert ("serialization_format", "critical") in findings
    assert not passed


def _wrong_checksum() -> bytes:
    data = bytearray(_v7(_tar("storages", EVAL_PICKLE)))
    data[148:154] = b"%06o" % (int(data[148:154], 8) + 1)
    return bytes(data)


def _empty_name_block() -> bytes:
    block = bytearray(512)
    block[156:157] = b"0"
    _checksummed(block)
    return bytes(block)


@pytest.mark.parametrize(
    "payload",
    [
        _lzma_alone(4096, {0: b"\x00"}),
        _lzma_alone(4096, {0: b"\x5e"}),
        _lzma_alone(4096, {1: b"\x10\x00\x00\x00"}),
        _lzma_alone(4096, {5: (1 << 63).to_bytes(8, "little")}),
        _lzma_alone(4096, {5: bytes(7) + b"\xff"}),
        _lzma_alone(4096, {13: b"\x01"}),
        _lzma_alone(4096)[:13],
        b"\0" * 512,
        _wrong_checksum(),
        _wrong_checksum()[:511],
    ],
    ids=[
        "lzma-properties-zero",
        "lzma-properties-other-than-joblibs",
        "lzma-dictionary-not-a-multiple-of-256",
        "lzma-size-neither-unknown-nor-below-2-63",
        "lzma-size-with-only-its-top-byte-all-ones",
        "lzma-range-coder-first-byte-not-zero",
        "lzma-header-cut-before-the-range-coder",
        "zeros",
        "tar-wrong-checksum",
        "tar-short-of-a-block",
    ],
)
def test_near_lzma_alone_and_tar_headers_under_a_pickle_name_stay_unknown(
    tmp_path: Path, payload: bytes
) -> None:
    (tmp_path / "m.pkl").write_bytes(payload)
    assert inspect_model_format(tmp_path / "m.pkl") == (UNKNOWN, PICKLE_NAME_UNEVIDENCED)


def test_a_tar_block_with_a_valid_checksum_and_no_name_is_read_as_a_header(
    tmp_path: Path,
) -> None:
    # tarfile reads a block with a matching checksum and number fields as a header whatever
    # its name, and lists the members after an unnamed one, so the name is no evidence.
    payload = _empty_name_block() + _tar("pickle", EVAL_PICKLE)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        assert archive.getnames() == ["", "pickle"]
    (tmp_path / "legacy.pt").write_bytes(payload)
    assert inspect_model_format(tmp_path / "legacy.pt") == (UNSAFE, PICKLE_NAME_WRAPPED)


TAR_NUMBER_FIELDS = {
    "mode": slice(100, 108),
    "uid": slice(108, 116),
    "gid": slice(116, 124),
    "size": slice(124, 136),
    "mtime": slice(136, 148),
    "devmajor": slice(329, 337),
    "devminor": slice(337, 345),
}


@pytest.mark.parametrize("field", TAR_NUMBER_FIELDS.values(), ids=list(TAR_NUMBER_FIELDS))
def test_a_checksummed_block_whose_number_field_tarfile_rejects_is_no_tar_header(
    tmp_path: Path, field: slice
) -> None:
    # A raw array of small integers can sum to its own checksum field; tarfile still
    # rejects the block when a number field is not octal or base-256.
    data = bytearray(_v7(_tar("storages", EVAL_PICKLE)))
    data[field.start : field.start + 2] = b"9\0"
    _checksummed(data)
    with pytest.raises(tarfile.ReadError), tarfile.open(fileobj=io.BytesIO(bytes(data))):
        pass
    (tmp_path / "legacy.pt").write_bytes(bytes(data))
    assert inspect_model_format(tmp_path / "legacy.pt") == (UNKNOWN, PICKLE_NAME_UNEVIDENCED)


def test_the_ustar_magic_keeps_the_wrapped_rating_with_a_wrong_checksum(tmp_path: Path) -> None:
    # tarfile rejects this block, but the ustar magic was a wrapper before the checksum
    # check existed, and the rating stays at least that wide.
    data = bytearray(_tar("storages", EVAL_PICKLE))
    data[148:154] = b"%06o" % (int(data[148:154], 8) + 1)
    with pytest.raises(tarfile.ReadError), tarfile.open(fileobj=io.BytesIO(bytes(data))):
        pass
    (tmp_path / "legacy.pt").write_bytes(bytes(data))
    assert inspect_model_format(tmp_path / "legacy.pt") == (UNSAFE, PICKLE_NAME_WRAPPED)


@pytest.mark.parametrize("suffix", [".bin", ".pt", ".pkl"])
@pytest.mark.parametrize("template", [HOSTILE_TEMPLATE, BENIGN_TEMPLATE], ids=["hostile", "benign"])
def test_gguf_content_under_a_pickle_family_name_keeps_the_critical_rating(
    tmp_path: Path, suffix: str, template: str
) -> None:
    # llama.cpp opens a model by its magic, so a GGUF file is loadable under any name,
    # and its chat template is inspected only under a .gguf name: the rating stays what
    # the name gave it before, critical, instead of dropping to unknown.
    (tmp_path / "models").mkdir()
    path = tmp_path / "models" / f"ggml-model-q4_0{suffix}"
    path.write_bytes(_gguf(template))
    assert inspect_model_format(path) == (UNSAFE, PICKLE_NAME_GGUF)
    found, failures = _scan(tmp_path)
    assert failures == []
    component = found[f"models/ggml-model-q4_0{suffix}"]
    assert component.serialization_safety is UNSAFE
    assert component.properties["format_inspection"] == PICKLE_NAME_GGUF
    assert ("serialization_format", "critical") in _severities(component)
    passed, findings = _gate([component])
    assert ("serialization_format", "critical") in findings
    assert not passed


def test_gguf_content_under_a_wrapper_suffix_is_rated_by_the_wrapper_first(tmp_path: Path) -> None:
    path = tmp_path / "ggml-model.pth.tar"
    path.write_bytes(_gguf(BENIGN_TEMPLATE))
    assert inspect_model_format(path) == (UNSAFE, PICKLE_NAME_WRAPPED)


def test_gguf_content_past_the_head_bound_keeps_the_gguf_evidence(tmp_path: Path) -> None:
    path = tmp_path / "ggml-model.bin"
    path.write_bytes(_gguf(BENIGN_TEMPLATE) + b"\0" * (MAX_PICKLE_INSPECTION_BYTES + 1))
    assert inspect_model_format(path) == (UNSAFE, PICKLE_NAME_GGUF)


def _safetensors() -> bytes:
    header = json.dumps({"w": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}).encode()
    return len(header).to_bytes(8, "little") + header + b"\0" * 4


def test_safetensors_content_under_a_pickle_family_name_beside_a_hostile_template(
    tmp_path: Path,
) -> None:
    # The directory template adds its critical finding under either name and fails the
    # gate; under a pickle-family name the rating stays unknown, as the template check
    # lifts only a safe rating (docs/security-model.md), while .safetensors is rated by
    # the template.
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "chat_template.jinja").write_text(HOSTILE_TEMPLATE)
    (tmp_path / "models" / "model.bin").write_bytes(_safetensors())
    (tmp_path / "models" / "model.safetensors").write_bytes(_safetensors())
    found, failures = _scan(tmp_path)
    assert failures == []
    renamed = found["models/model.bin"]
    assert renamed.serialization_safety is UNKNOWN
    assert renamed.properties["format_inspection"] == PICKLE_NAME_UNEVIDENCED
    severities = _severities(renamed)
    assert ("serialization_format", "critical") in severities
    assert ("serialization_format_unknown", "high") in severities
    passed, findings = _gate([renamed])
    assert ("serialization_format", "critical") in findings
    assert not passed
    own = found["models/model.safetensors"]
    assert own.serialization_safety is SerializationSafety.UNSAFE_TEMPLATE_INJECTION


def test_the_same_gguf_bytes_are_rated_by_their_template_under_their_own_name(
    tmp_path: Path,
) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "escape.gguf").write_bytes(_gguf(HOSTILE_TEMPLATE))
    (tmp_path / "models" / "plain.gguf").write_bytes(_gguf(BENIGN_TEMPLATE))
    found, failures = _scan(tmp_path)
    assert failures == []
    escape = found["models/escape.gguf"].serialization_safety
    assert escape is SerializationSafety.UNSAFE_TEMPLATE_INJECTION
    assert found["models/plain.gguf"].serialization_safety is UNKNOWN


def test_an_object_dtype_array_is_critical_under_any_name(tmp_path: Path) -> None:
    (tmp_path / "objects.npy").write_bytes(_npy_object_array())
    (tmp_path / "objects.pkl").write_bytes(_npy_object_array())
    found, failures = _scan(tmp_path)
    assert failures == []
    for name in ("objects.npy", "objects.pkl"):
        assert found[name].serialization_safety is UNSAFE, name
        assert found[name].properties["format_inspection"] == NUMPY_OBJECT_ARRAY, name
        assert ("serialization_format", "critical") in _severities(found[name]), name


def test_an_empty_pickle_family_file_is_unknown_with_a_high_finding(tmp_path: Path) -> None:
    (tmp_path / "empty.pkl").write_bytes(b"")
    found, failures = _scan(tmp_path)
    assert failures == []
    component = found["empty.pkl"]
    assert component.serialization_safety is UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_NAME_EMPTY
    severities = _severities(component)
    assert ("serialization_format_unknown", "high") in severities
    assert not any(severity == "critical" for _, severity in severities)
    assert inspect_model_format(tmp_path / "empty.pkl") == (UNKNOWN, PICKLE_NAME_EMPTY)


def test_an_unreadable_pickle_family_file_keeps_the_critical_rating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "weights.pt"
    target.write_bytes(b"\0" * 64)
    if os.geteuid() == 0:
        # Root reads a mode-000 file; the confined open is refused for it instead.
        open_regular = ConfinedCollection.open_regular

        def refused(self: ConfinedCollection, path: Path, *args: object, **kwargs: object):
            if path.name == target.name:
                raise PermissionError(13, "Permission denied", str(path))
            return open_regular(self, path, *args, **kwargs)

        monkeypatch.setattr(ConfinedCollection, "open_regular", refused)
    else:
        target.chmod(0)
    try:
        found, failures = _scan(tmp_path)
    finally:
        target.chmod(0o600)
    assert any("weights.pt" in failure for failure in failures), failures
    component = found["weights.pt"]
    assert component.serialization_safety is UNSAFE
    assert component.hashes == {}
    assert component.properties["format_inspection"] == UNHASHED
    assert ("serialization_format", "critical") in _severities(component)


def test_a_read_that_fails_during_inspection_keeps_the_critical_rating(tmp_path: Path) -> None:
    class _Broken(io.BytesIO):
        def fileno(self) -> int:
            raise OSError(5, "Input/output error")

    assert inspect_model_format(tmp_path / "weights.pt", stream=_Broken(b"\0" * 64)) == (
        UNSAFE,
        PICKLE_NAME_UNREADABLE,
    )
    assert inspect_model_format(tmp_path / "missing.pkl") == (UNSAFE, PICKLE_NAME_UNREADABLE)
    assert inspect_model_format(tmp_path / "missing.h5")[0] is UNKNOWN


def test_the_safetensors_path_is_untouched(tmp_path: Path) -> None:
    header = b'{"t":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    (tmp_path / "model.safetensors").write_bytes(
        len(header).to_bytes(8, "little") + header + b"\0" * 4
    )
    (tmp_path / "empty.safetensors").write_bytes(b"")
    found, failures = _scan(tmp_path)
    assert failures == []
    assert found["model.safetensors"].serialization_safety is SerializationSafety.SAFE
    assert found["empty.safetensors"].serialization_safety is UNKNOWN
    assert found["empty.safetensors"].properties["format_inspection"] != PICKLE_NAME_EMPTY


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"N" + b"\xff" * 40, (UNKNOWN, PICKLE_NAME_UNEVIDENCED)),
        (
            b"(" * 300,
            (
                UNSAFE,
                LOADER.format(
                    "pickle opcode stream that names no callable before the inspection limits"
                ),
            ),
        ),
        (b"\x80\x05\x95" + b"\xff" * 8, (UNKNOWN, PICKLE_NAME_UNEVIDENCED)),
        (
            b"\x80\x04N." + b"junk" * 10,
            (UNSAFE, "Recognized binary pickle opcode stream; object loading can execute code"),
        ),
        (
            b"PK\x03\x04" + b"\0" * 60,
            (
                UNSAFE,
                LOADER.format(
                    "ZIP archive whose directory is malformed or over the inspection limit"
                ),
            ),
        ),
        (b"\x93NUMPY\x01\x00\xff\xff" + b"x" * 40, (UNKNOWN, PICKLE_NAME_UNEVIDENCED)),
        (b"\x93NUMPY\x01\x00\x10\x00{'descr': '<f8',\n", (UNKNOWN, PICKLE_NAME_UNEVIDENCED)),
        ("é".encode("latin-1") * 20, (UNKNOWN, PICKLE_NAME_UNEVIDENCED)),
    ],
    ids=[
        "text-opcode-then-garbage",
        "marks",
        "truncated-frame",
        "stop-then-tail",
        "zip-stub",
        "numpy-header-over-size",
        "numpy-header-truncated",
        "non-ascii-no-opcode",
    ],
)
def test_hostile_pickle_family_content_is_rated_without_raising(
    tmp_path: Path, payload: bytes, expected: tuple[SerializationSafety, str]
) -> None:
    (tmp_path / "hostile.pkl").write_bytes(payload)
    safety, evidence = inspect_model_format(tmp_path / "hostile.pkl")
    assert (safety, evidence) == expected
    found, failures = _scan(tmp_path)
    assert failures == []
    assert found["hostile.pkl"].serialization_safety is safety
    assert found["hostile.pkl"].properties["format_inspection"] == evidence


def test_inspection_stays_within_the_pickle_bound(tmp_path: Path) -> None:
    class _Counting(io.FileIO):
        read_bytes = 0

        def read(self, size: int | None = -1) -> bytes:
            data = super().read(size)
            self.read_bytes += len(data)
            return data

    # An opcode byte starts the file, so the sample is read; nothing past the bound is.
    padded = tmp_path / "padded.pkl"
    padded.write_bytes(b"N" + b"\0" * (4 * MAX_PICKLE_INSPECTION_BYTES))
    with _Counting(padded, "rb") as stream:
        safety, _ = inspect_model_format(padded, stream=stream)
        assert safety is UNKNOWN
        assert stream.read_bytes <= MAX_PICKLE_INSPECTION_BYTES


def test_two_scans_of_the_same_tree_are_byte_identical(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "embeddings.bin").write_bytes(b"\0" * (MAX_PICKLE_INSPECTION_BYTES + 1))
    (tmp_path / "empty.pkl").write_bytes(b"")
    (tmp_path / "model.pkl").write_bytes(pickle.dumps([1, 2], protocol=4))
    (tmp_path / "model.pt").write_bytes(_torch_zip())
    (tmp_path / "objects.pth").write_bytes(_npy_object_array())
    (tmp_path / "padded.pkl").write_bytes(b"N0" * (2 * MAX_PICKLE_INSPECTION_BYTES) + b".")
    first = AIBOM(components=ModelScanner().scan(tmp_path).components).model_dump_json()
    second = AIBOM(components=ModelScanner().scan(tmp_path).components).model_dump_json()
    assert first == second
    assert first.count('"serialization_safety":"unknown"') == 2
    assert first.count('"serialization_safety":"unsafe-code-execution"') == 4


def test_a_pickle_family_name_is_still_a_model_format(tmp_path: Path) -> None:
    assert model_format(tmp_path / "a.pkl") == ("pickle", "pickle")
    assert model_format(tmp_path / "b.bin") == ("bin", "pytorch-legacy")
    for name in ("c.pth.tar", "d.pkl.gz"):
        assert model_format(tmp_path / name) == ("pickle", "pickle-archive"), name
