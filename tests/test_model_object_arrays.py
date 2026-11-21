"""NumPy object-dtype arrays are recognized by their header, alone or as any ZIP member."""

from __future__ import annotations

import base64
import hashlib
import io
import pickle
import random
import struct
import zipfile
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.scanners import model
from nexus_symbiote.scanners.model import (
    MAX_PICKLE_INSPECTION_BYTES,
    NUMPY_HEADER_UNREAD,
    NUMPY_OBJECT_ARRAY,
    ZIP_DIRECTORY_UNREAD,
    ZIP_MEMBER_UNREAD,
    ZIP_OBJECT_ARRAY,
    ZIP_PICKLE_MEMBER,
    ZIP_WITHOUT_PICKLE,
    ModelScanner,
    inspect_model_format,
)
from nexus_symbiote.utils import model_formats

UNSAFE = SerializationSafety.UNSAFE_CODE_EXECUTION
NOT_RECOGNIZED = (
    SerializationSafety.UNKNOWN,
    "No bounded structural validator for this format/loader",
)


def _npy(
    descr: str,
    *,
    version: int = 1,
    lead: int = 0,
    padding: int = 0,
    shape: str = "(1,)",
    minor: int = 0,
) -> bytes:
    """An array file with ``descr`` written as Python literal text, as NumPy writes it."""
    text = "{" + " " * lead + f"'descr': {descr}, 'fortran_order': False, 'shape': {shape}, }}"
    width = 2 if version == 1 else 4
    text += " " * (padding + (-(10 + width + len(text) + padding) % 64)) + "\n"
    encoded = text.encode("utf-8" if version == 3 else "latin-1")
    return (
        b"\x93NUMPY"
        + bytes([version, minor])
        + len(encoded).to_bytes(width, "little")
        + encoded
        + pickle.dumps(["payload"], protocol=2)
    )


def _zip(members: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def _inspect(tmp_path: Path, content: bytes, name: str = "model.onnx") -> tuple[object, str]:
    path = tmp_path / name
    path.write_bytes(content)
    return inspect_model_format(path)


@pytest.mark.parametrize(
    ("descr", "options"),
    [
        ("'|O'", {}),
        ("'O'", {"version": 2}),
        ("'<O8'", {"version": 3}),
        ("'object'", {}),
        ("'i4,(2,3)O'", {}),
        ("'(2,)O'", {}),
        ("[('a', '<i4'), ('b', '|O')]", {}),
        ("[('n', [('m', [('deep', '|O')])])]", {}),
        ("[('s', '|O', (2,))]", {}),
        ("[(('title', 'name'), '|O')]", {}),
        ("[('café', '|O')]", {"version": 3}),
        # The descr after 2 KiB of whitespace, which a literal reader skips.
        ("'|O'", {"lead": 2048}),
        # Python 2 wrote a long integer with an L; np.load still reads that header.
        ("'|O'", {"shape": "(1L,)"}),
        ("'|O'", {"version": 2, "shape": "(2L, 3L)"}),
    ],
)
def test_an_object_dtype_is_found_however_the_header_spells_it(
    tmp_path: Path, descr: str, options: dict[str, Any]
) -> None:
    assert _inspect(tmp_path, _npy(descr, **options)) == (UNSAFE, NUMPY_OBJECT_ARRAY)


@pytest.mark.parametrize(
    ("descr", "options"),
    [
        ("'<f8'", {}),
        ("'M8[ns]'", {}),
        # Field names are not types, whatever they spell.
        ("[('O', '<f8'), ('|O', '<i4'), ('object', 'u1')]", {}),
        ("[('n', [('O', '<f4')])]", {}),
        ("[(('O', 'O'), '<f8')]", {}),
        # np.load refuses a minor version other than 0 and a malformed header.
        ("'|O'", {"minor": 1}),
        ("'|O' + 'x'", {}),
    ],
)
def test_a_numeric_dtype_is_not_an_object_array(
    tmp_path: Path, descr: str, options: dict[str, Any]
) -> None:
    assert _inspect(tmp_path, _npy(descr, **options)) == NOT_RECOGNIZED


def test_an_array_header_is_read_to_the_largest_a_version_1_header_holds(
    tmp_path: Path,
) -> None:
    longest = _npy("'|O'", lead=65_535 - 200)
    assert 65_000 < int.from_bytes(longest[8:10], "little") <= MAX_PICKLE_INSPECTION_BYTES
    assert _inspect(tmp_path, longest) == (UNSAFE, NUMPY_OBJECT_ARRAY)
    longer = _npy("'|O'", version=2, lead=MAX_PICKLE_INSPECTION_BYTES)
    assert int.from_bytes(longer[8:12], "little") > MAX_PICKLE_INSPECTION_BYTES
    assert _inspect(tmp_path, longer) == (SerializationSafety.UNKNOWN, NUMPY_HEADER_UNREAD)


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_every_member_of_an_archive_is_checked_for_an_object_array(
    tmp_path: Path, compression: int
) -> None:
    numbers = _npy("'<f8'", shape="(9000,)") + b"\0" * 72_000
    found = _inspect(
        tmp_path, _zip([("numbers.npy", numbers), ("objects.npy", _npy("'|O'"))], compression)
    )
    assert found == (UNSAFE, ZIP_OBJECT_ARRAY)
    # np.load reads any member that starts with the NumPy magic, whatever its name.
    renamed = _zip([("version", b"3"), ("payload", _npy("[('a', '|O')]"))], compression)
    assert _inspect(tmp_path, renamed) == (UNSAFE, ZIP_OBJECT_ARRAY)
    plain = _zip([("numbers.npy", numbers), ("more.npy", _npy("[('O', '<f8')]"))], compression)
    assert _inspect(tmp_path, plain) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)


def test_a_zip64_directory_locates_every_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A low ZIP64 limit makes zipfile write each offset and size in ZIP64 fields.
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 16)
    archive = _zip([(f"n{index}.npy", _npy("'<f8'")) for index in range(3)] + [("o", _npy("'O'"))])
    assert b"PK\x06\x06" in archive
    assert _inspect(tmp_path, archive) == (UNSAFE, ZIP_OBJECT_ARRAY)


@pytest.mark.parametrize("compression", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_a_member_compressed_by_another_method_is_not_left_unrated(
    tmp_path: Path, compression: int
) -> None:
    archive = _zip([("objects.npy", _npy("'|O'"))], compression)
    assert _inspect(tmp_path, archive) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


def test_overlapping_members_are_not_read_twice(tmp_path: Path) -> None:
    archive = bytearray(_zip([("a.npy", _npy("'<f8'")), ("b.npy", _npy("'<f8'"))]))
    # Point the second directory entry at the first member's local header.
    second = archive.index(b"PK\x01\x02", archive.index(b"PK\x01\x02") + 4)
    archive[second + 42 : second + 46] = (0).to_bytes(4, "little")
    assert _inspect(tmp_path, bytes(archive)) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


def test_a_member_whose_array_header_is_over_the_bound_is_not_left_unrated(
    tmp_path: Path,
) -> None:
    archive = _zip([("a.npy", _npy("'<f8'", version=2, lead=MAX_PICKLE_INSPECTION_BYTES))])
    assert _inspect(tmp_path, archive) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


def test_invalid_raw_deflate_is_not_an_array(tmp_path: Path) -> None:
    archive = bytearray(_zip([("objects.npy", _npy("'|O'"))], zipfile.ZIP_DEFLATED))
    data = 30 + int.from_bytes(archive[26:28], "little") + int.from_bytes(archive[28:30], "little")
    # Block type 3 is reserved: zipfile cannot inflate the member, so np.load cannot read it.
    archive[data] = 0x07
    assert _inspect(tmp_path, bytes(archive)) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)


def test_a_pickle_family_member_after_another_is_unsafe_under_a_model_name(
    tmp_path: Path,
) -> None:
    for member in ("weights/data.pickle", "archive/data.pkl.gz", "nested/model.pt"):
        archive = _zip([("archive/version", b"3"), (member, pickle.dumps({"w": [0.0]}))])
        assert _inspect(tmp_path, archive, "model.gguf") == (UNSAFE, ZIP_PICKLE_MEMBER)


def test_an_object_array_under_a_model_name_is_a_critical_component(tmp_path: Path) -> None:
    (tmp_path / "model.onnx").write_bytes(_zip([("arr_0.npy", _npy("'|O'"))]))
    (tmp_path / "weights.h5").write_bytes(_npy("[('a', '<i4'), ('b', '|O')]"))
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    assert {c.name: c.serialization_safety for c in result.components} == {
        "model.onnx": UNSAFE,
        "weights.h5": UNSAFE,
    }
    for component in result.components:
        assert any(
            risk.severity is RiskSeverity.CRITICAL and risk.category == "serialization_format"
            for risk in component.risks
        )


def test_array_headers_spend_the_inspection_budget_one_scan_shares(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed: list[int] = []
    declares = model._declares_object

    def counted(header: bytes, major: int) -> bool:
        parsed.append(len(header))
        return declares(header, major)

    monkeypatch.setattr(model, "_declares_object", counted)
    monkeypatch.setattr(model_formats, "MAX_INSPECTION_UNITS", 200_000)
    # Each 60 KiB header inflates from about a hundred bytes.
    padded = _npy("'<f8'", version=2, lead=60_000)
    archive = _zip([(f"m{index}.npy", padded) for index in range(40)], zipfile.ZIP_DEFLATED)
    assert len(archive) < 40 * 1024
    (tmp_path / "arrays.npz").write_bytes(archive)
    (tmp_path / "first.npy").write_bytes(_npy("'|O'", lead=60_000))
    (tmp_path / "second.npy").write_bytes(_npy("'|O'", lead=60_000))
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    assert sum(parsed) <= 200_000
    assert {c.name: c.properties["format_inspection"] for c in result.components} == {
        "arrays.npz": ZIP_MEMBER_UNREAD,
        "first.npy": NUMPY_HEADER_UNREAD,
        "second.npy": NUMPY_HEADER_UNREAD,
    }


def test_a_header_that_claims_more_than_it_holds_costs_only_what_it_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(model_formats, "MAX_INSPECTION_UNITS", 4_096)
    claim = b"\x93NUMPY\x02\x00" + MAX_PICKLE_INSPECTION_BYTES.to_bytes(4, "little") + b"{}"
    for index in range(100):
        (tmp_path / f"short{index:03d}.npy").write_bytes(claim)
    (tmp_path / "zz.npy").write_bytes(_npy("'|O'"))
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    assert {c.name: c.serialization_safety for c in result.components} == {"zz.npy": UNSAFE}


# Audit 2026-11-16 S4-01: zipfile, which np.load uses, finds the central directory where
# its end record says it ends, not at the offset it stores, and reads a ZIP64 record
# whenever a locator precedes the end record. A decoy directory one reader takes must not
# hide the members another reader lists.


def _local(name: bytes, data: bytes, extra: bytes = b"") -> bytes:
    crc = zipfile.crc32(data)
    fields = (0x04034B50, 20, 0, 0, 0, 0, crc, len(data), len(data), len(name), len(extra))
    return struct.pack("<IHHHHHIIIHH", *fields) + name + extra + data


def _central(
    name: bytes, data: bytes, offset: int, comment: bytes = b"", extra: bytes = b""
) -> bytes:
    crc = zipfile.crc32(data)
    fields = (0x02014B50, 20, 20, 0, 0, 0, 0, crc, len(data), len(data), len(name), len(extra))
    tail = (len(comment), 0, 0, 0, offset)
    return struct.pack("<IHHHHHHIIIHHHHHII", *fields, *tail) + name + extra + comment


def _end(count: int, size: int, offset: int) -> bytes:
    return struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, count, count, size, offset, 0)


def _concatenated_decoy(decoy: tuple[bytes, bytes], real: tuple[bytes, bytes]) -> bytes:
    """The end record stores the offset of a decoy directory; zipfile reads the directory
    of the same size that ends at the end record, and moves its member's offset."""
    real_local = _local(*real)
    padding = max(0, len(real_local) - len(_local(*decoy)))
    decoy = (decoy[0], decoy[1] + b" " * padding)
    first = _local(*decoy)
    size = len(_central(*real, 0))
    listed = _central(*decoy, 0)
    listed = _central(*decoy, 0, b"c" * (size - len(listed)))
    shift = size + len(real_local)
    real_cd = _central(*real, len(first) + size - shift)
    return first + listed + real_local + real_cd + _end(1, size, len(first))


def _zip64_decoy(decoy: tuple[bytes, bytes], real: tuple[bytes, bytes]) -> bytes:
    """The classic end record names a decoy directory; a ZIP64 locator and record name
    the real one, which zipfile reads although no classic field is saturated."""
    first = _local(*decoy)
    listed = _central(*decoy, 0)
    real_at = len(first) + len(listed)
    real_local = _local(*real)
    real_cd = _central(*real, real_at)
    record_at = real_at + len(real_local) + len(real_cd)
    directory_at = real_at + len(real_local)
    record = struct.pack(
        "<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1, len(real_cd), directory_at
    )
    locator = struct.pack("<IIQI", 0x07064B50, 0, record_at, 1)
    tail = _end(1, len(listed), len(first))
    return first + listed + real_local + real_cd + record + locator + tail


_PICKLE = b"cbuiltins\nexec\n(S'import builtins; builtins.HIT=1'\ntR."
_DECOYS = {
    "concatenated-pickle": (_concatenated_decoy, (b"archive/version", b"3\n"), b"archive/data.pkl"),
    "concatenated-array": (_concatenated_decoy, (b"numbers.npy", _npy("'<f8'")), b"objects.npy"),
    "zip64-pickle": (_zip64_decoy, (b"archive/version", b"3\n"), b"archive/data.pkl"),
    "zip64-array": (_zip64_decoy, (b"numbers.npy", _npy("'<f8'")), b"objects.npy"),
}


@pytest.mark.parametrize("case", _DECOYS.values(), ids=_DECOYS)
def test_a_decoy_directory_does_not_hide_what_zipfile_lists(
    tmp_path: Path, case: tuple[Any, tuple[bytes, bytes], bytes]
) -> None:
    build, decoy, real_name = case
    pickled = real_name.endswith(b".pkl")
    payload = _PICKLE if pickled else _npy("'|O'")
    archive = build(decoy, (real_name, payload))
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == [real_name.decode()]
        assert opened.read(real_name.decode()) == payload
    expected = ZIP_PICKLE_MEMBER if pickled else ZIP_OBJECT_ARRAY
    (tmp_path / "models").mkdir()
    relatives = ["models/archive", "arrays.npz", "archive.dat", "model.onnx"]
    for relative in relatives:
        (tmp_path / relative).write_bytes(archive)
        assert inspect_model_format(tmp_path / relative) == (UNSAFE, expected), relative
    found = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert {r: found[r].serialization_safety for r in relatives} == dict.fromkeys(relatives, UNSAFE)


def _zip64_extensible_decoy(
    decoy: tuple[bytes, bytes], real: tuple[bytes, bytes], padding: int
) -> bytes:
    """The locator stores the offset of a ZIP64 record naming the real directory, whose
    size counts ``padding``, a decoy directory and a decoy record as extensible data.
    zipfile from Python 3.13 reads the record at the locator's offset; a reader that takes
    the record right before the locator lists only the decoy."""
    first = _local(*decoy)
    real_local = _local(*real)
    real_cd = _central(*decoy, 0) + _central(*real, len(first))
    directory_at = len(first) + len(real_local)
    record_at = directory_at + len(real_cd)
    decoy_cd = _central(*decoy, 0)
    decoy_at = record_at + 56 + padding
    extensible = padding + len(decoy_cd) + 56
    record = struct.pack(
        "<IQHHIIQQQQ", 0x06064B50, 44 + extensible, 45, 45, 0, 0, 2, 2, len(real_cd), directory_at
    )
    decoy_record = struct.pack(
        "<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1, len(decoy_cd), decoy_at
    )
    locator = struct.pack("<IIQI", 0x07064B50, 0, record_at, 1)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    head = first + real_local + real_cd + record
    return head + b"\0" * padding + decoy_cd + decoy_record + locator + end


_INERT_PICKLE = pickle.dumps({"weights": [1, 2, 3]}, protocol=2)


@pytest.mark.parametrize("large", [False, True], ids=["record-in-tail", "record-before-tail"])
@pytest.mark.parametrize("pickled", [False, True], ids=["array", "pickle"])
def test_a_zip64_record_before_the_retained_tail_is_not_hidden_by_a_decoy(
    tmp_path: Path, large: bool, pickled: bool
) -> None:
    # Audit P1-H2: a locator offset before the retained tail was dropped, and the decoy
    # record before the locator listed only a harmless member, so an object array was not
    # inventoried and a .pt fell from critical to high. What that record lists is unread.
    decoy = (b"archive/version", b"3\n") if pickled else (b"numbers.npy", _npy("'<f8'"))
    real = (b"archive/data.pkl", _INERT_PICKLE) if pickled else (b"objects.npy", _npy("'|O'"))
    padding = 2 * model._ZIP_TAIL_BYTES if large else 4096
    archive = _zip64_extensible_decoy(decoy, real, padding)
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == [decoy[0].decode(), real[0].decode()]
    expected = (
        (SerializationSafety.UNKNOWN, ZIP_DIRECTORY_UNREAD)
        if large
        else (UNSAFE, ZIP_PICKLE_MEMBER if pickled else ZIP_OBJECT_ARRAY)
    )
    (tmp_path / "models").mkdir()
    relatives = ["models/archive", "arrays.npz", "model.pt"]
    for relative in relatives:
        (tmp_path / relative).write_bytes(archive)
    assert inspect_model_format(tmp_path / "models/archive") == expected
    found = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert set(relatives) <= set(found)
    assert found["model.pt"].serialization_safety == UNSAFE
    assert found["models/archive"].properties["format_inspection"] in expected


def _zip64_in_first_name(real: tuple[bytes, bytes]) -> bytes:
    """A small archive whose first local header's name holds the real member, its
    directory, a ZIP64 record and the locator, followed by a classic end record naming an
    empty directory. zipfile and miniz read the locator just before the end record."""
    member = _local(*real)
    directory_at = 30 + len(member)
    directory = _central(*real, 30)
    record_at = directory_at + len(directory)
    record = struct.pack(
        "<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1, len(directory), directory_at
    )
    locator = struct.pack("<IIQI", 0x07064B50, 0, record_at, 1)
    name = member + directory + record + locator
    first = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, 0, 0, 0, len(name), 0)
    return first + name + _end(0, 0, 30 + len(name))


@pytest.mark.parametrize("pickled", [False, True], ids=["array", "pickle"])
def test_a_zip64_locator_inside_the_first_header_is_read(tmp_path: Path, pickled: bool) -> None:
    # The first local header and its name were read before the directory search and not
    # kept, so a locator there was never seen: the decoy end record listed nothing, an
    # object array in a 375-byte .npz was not inventoried, and a .pt fell to high.
    real = (b"archive/data.pkl", _INERT_PICKLE) if pickled else (b"objects.npy", _npy("'|O'"))
    archive = _zip64_in_first_name(real)
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == [real[0].decode()]
        assert opened.read(real[0].decode()) == real[1]
    expected = (UNSAFE, ZIP_PICKLE_MEMBER if pickled else ZIP_OBJECT_ARRAY)
    (tmp_path / "models").mkdir()
    relatives = ["models/archive", "arrays.npz", "archive.dat", "model.pt"]
    for relative in relatives:
        (tmp_path / relative).write_bytes(archive)
        assert inspect_model_format(tmp_path / relative) == expected, relative
    found = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert {r: found[r].serialization_safety for r in relatives} == dict.fromkeys(relatives, UNSAFE)


def test_a_locator_outside_the_held_bytes_is_unread() -> None:
    # A contract of _zip_directory for a caller that holds only the end of an archive:
    # the scanner keeps every byte it read, so it does not reach this itself. A locator
    # that would lie before what is held is not decided, whatever the end record names.
    archive = _zip64_in_first_name((b"objects.npy", _npy("'|O'")))
    stream = io.BytesIO(archive)
    stream.seek(len(archive) - 22)
    assert model._zip_directory(stream, len(archive) - 22, len(archive)) is None


def _zip64_record_after_locator(decoy: tuple[bytes, bytes], real: tuple[bytes, bytes]) -> bytes:
    """The classic end record names a decoy directory; the locator stores the offset of a
    ZIP64 record kept in the end record's comment, after the locator, naming the real
    directory. zipfile refuses the archive; miniz reads the record there."""
    first = _local(*decoy)
    real_local = _local(*real)
    real_cd = _central(*decoy, 0) + _central(*real, len(first))
    real_at = len(first) + len(real_local)
    decoy_cd = _central(*decoy, 0)
    decoy_at = real_at + len(real_cd)
    end_at = decoy_at + len(decoy_cd) + 20
    record = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 2, 2, len(real_cd), real_at)
    locator = struct.pack("<IIQI", 0x07064B50, 0, end_at + 22, 1)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(decoy_cd), decoy_at, len(record))
    return first + real_local + real_cd + decoy_cd + locator + end + record


@pytest.mark.parametrize("pickled", [False, True], ids=["array", "pickle"])
def test_a_zip64_record_after_the_locator_is_read_as_miniz_reads_it(
    tmp_path: Path, pickled: bool
) -> None:
    # A record at the locator's offset was taken only before the locator, so this one was
    # dropped and the decoy listed only archive/version; torch.load's miniz unpickles
    # data.pkl from the directory the record names.
    decoy = (b"archive/version", b"3\n") if pickled else (b"numbers.npy", _npy("'<f8'"))
    real = (b"archive/data.pkl", _INERT_PICKLE) if pickled else (b"objects.npy", _npy("'|O'"))
    archive = _zip64_record_after_locator(decoy, real)
    with pytest.raises(zipfile.BadZipFile):
        zipfile.ZipFile(io.BytesIO(archive))
    expected = (UNSAFE, ZIP_PICKLE_MEMBER if pickled else ZIP_OBJECT_ARRAY)
    (tmp_path / "models").mkdir()
    relatives = ["models/archive", "archive.dat", "model.pt"]
    for relative in relatives:
        (tmp_path / relative).write_bytes(archive)
        assert inspect_model_format(tmp_path / relative) == expected, relative
    found = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert {r: found[r].serialization_safety for r in relatives} == dict.fromkeys(relatives, UNSAFE)


def _directory_past_its_end_record(real: tuple[bytes, bytes]) -> bytes:
    """The classic record stores the real directory's offset with a size that runs past
    the end record into its comment. zipfile reads the directory of that size ending at
    the end record, a decoy entry whose comment absorbs the real entries; miniz reads the
    stored offset, bounded only by the archive's size."""
    version = (b"archive/version", b"3\n")
    head = _local(*version) + _local(*real)
    real_cd = _central(*version, 0) + _central(*real, len(_local(*version)))
    probe_size = len(_central(*version, 0))
    stored = len(head) + probe_size
    size = probe_size + len(real_cd)
    decoy = _central(*version, probe_size, comment=real_cd)
    assert len(decoy) == size
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 2, 2, size, stored, probe_size)
    return head + decoy[:probe_size] + real_cd + end + b"\0" * probe_size


@pytest.mark.parametrize("pickled", [False, True], ids=["array", "pickle"])
def test_a_directory_that_runs_past_its_end_record_is_unread(tmp_path: Path, pickled: bool) -> None:
    # Only zipfile's decoy reading was kept, so the archive was rated as listing no
    # pickle; no writer produces this layout, and the stored reading miniz takes lists
    # the real member, so what the archive holds is not decided.
    real = (b"archive/data.pkl", _INERT_PICKLE) if pickled else (b"objects.npy", _npy("'|O'"))
    archive = _directory_past_its_end_record(real)
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == ["archive/version"]
    (tmp_path / "models").mkdir()
    relatives = ["models/archive", "archive.dat"]
    for relative in relatives:
        (tmp_path / relative).write_bytes(archive)
        assert inspect_model_format(tmp_path / relative) == (
            SerializationSafety.UNKNOWN,
            ZIP_DIRECTORY_UNREAD,
        ), relative
    found = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert {r: found[r].properties["format_inspection"] for r in relatives} == dict.fromkeys(
        relatives, ZIP_DIRECTORY_UNREAD
    )


def _locator_naming_offset_zero(real: tuple[bytes, bytes], padding: int) -> bytes:
    """An ordinary archive whose last directory entry's comment is a ZIP64 locator storing
    offset 0, where no record lies. zipfile without the CVE-2025-8291 fix finds no record
    and reads the classic directory, which lists the real member."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("notes.txt", b"\0" * (8 + padding))
        info = zipfile.ZipInfo(real[0].decode())
        info.comment = struct.pack("<IIQI", 0x07064B50, 0, 0, 1)
        archive.writestr(info, real[1])
    return buffer.getvalue()


@pytest.mark.parametrize("large", [False, True], ids=["held-whole", "past-the-tail"])
@pytest.mark.parametrize("pickled", [False, True], ids=["array", "pickle"])
def test_a_locator_naming_no_held_record_does_not_hide_the_classic_directory(
    tmp_path: Path, large: bool, pickled: bool
) -> None:
    # The locator's offset lay before the bytes held, so the archive was rated as a
    # directory not read, unknown and high, although the classic directory lists a pickle
    # or object array: a 20-byte comment let a critical .npz, .keras or .onnx pass.
    real = (b"evil.pkl", _PICKLE) if pickled else (b"objects.npy", _npy("'|O'"))
    padding = 2 * model._ZIP_TAIL_BYTES if large else 0
    archive = _locator_naming_offset_zero(real, padding)
    expected = (UNSAFE, ZIP_PICKLE_MEMBER if pickled else ZIP_OBJECT_ARRAY)
    (tmp_path / "models").mkdir()
    relatives = ["models/archive", "arrays.npz", "model.keras", "model.onnx", "model.pt"]
    for relative in relatives:
        (tmp_path / relative).write_bytes(archive)
        assert inspect_model_format(tmp_path / relative) == expected, relative


# The second review's reproducer of the gate bypass, as found: two stored members, the
# second model/data.pkl, and that entry's comment shaped like a ZIP64 locator at offset 0.
_DECOY_LOCATOR_288 = base64.b64decode(
    "UEsDBBQAAAAAAAAAAAB9DhbaAwAAAAMAAAARAAAAa2VyYXNfbWV0YWRhdGEucGJvawpQSwMEFAAAAAAAAAAAAG2k"
    "rIcdAAAAHQAAAA4AAABtb2RlbC9kYXRhLnBrbGNfX2J1aWx0aW5fXwpldmFsCihTJzErMScKdFIuUEsBAhQAFAAA"
    "AAAAAAAAAH0OFtoDAAAAAwAAABEAAAAAAAAAAAAAAAAAAAAAAGtlcmFzX21ldGFkYXRhLnBiUEsBAhQAFAAAAAAA"
    "AAAAAG2krIcdAAAAHQAAAA4AAAAUAAAAAAAAAAAAMgAAAG1vZGVsL2RhdGEucGtsUEsGBwAAAAAAAAAAAAAAAAEA"
    "AABQSwUGAAAAAAIAAgCPAAAAewAAAAAA"
)


@pytest.mark.parametrize("name", ["m.keras", "m.npz", "m.onnx", "m.pt"])
def test_the_reported_decoy_locator_archive_is_critical(tmp_path: Path, name: str) -> None:
    assert hashlib.sha256(_DECOY_LOCATOR_288).hexdigest() == (
        "1f9a167fbc9e88fa10ffd3b23a94786fcd0c220dec9606325b46878de453acb5"
    )
    (tmp_path / name).write_bytes(_DECOY_LOCATOR_288)
    assert inspect_model_format(tmp_path / name) == (UNSAFE, ZIP_PICKLE_MEMBER)
    found = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert found[name].serialization_safety == UNSAFE


def _cut_out(members: list[tuple[str, bytes]], prefix: int = 19) -> bytes:
    """An archive written after ``prefix`` bytes, with absolute offsets, then cut out of
    that file: every stored offset is ``prefix`` bytes too large. zipfile still lists it."""
    buffer = io.BytesIO()
    buffer.write(b"#" * prefix)
    with zipfile.ZipFile(buffer, "a") as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()[prefix:]


@pytest.mark.parametrize("dangerous", [True, False], ids=["object-array", "harmless"])
def test_an_archive_cut_out_of_a_larger_file_keeps_its_rating(
    tmp_path: Path, dangerous: bool
) -> None:
    # A stored directory offset that starts no directory entry is not one that runs past
    # its end record: zipfile's reading of the archive decides, as it did before.
    second = _npy("'|O'") if dangerous else _npy("'<f8'")
    archive = _cut_out([("weights.npy", _npy("'<f8'")), ("meta.npy", second)])
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == ["weights.npy", "meta.npy"]
    expected = (
        (UNSAFE, ZIP_OBJECT_ARRAY)
        if dangerous
        else (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)
    )
    assert _inspect(tmp_path, archive, "arrays.npz") == expected


def test_an_empty_archive_after_another_is_read_as_its_loaders_read_it(tmp_path: Path) -> None:
    # The last end record names an empty directory, which zipfile and miniz list.
    archive = _zip([("weights.npy", _npy("'<f8'"))]) + _zip([])
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == []
    assert _inspect(tmp_path, archive, "arrays.npz") == (
        SerializationSafety.UNKNOWN,
        ZIP_WITHOUT_PICKLE,
    )


def _saturated_with_record_after_locator(real: tuple[bytes, bytes]) -> bytes:
    """A classic record with saturated counts names the real directory; the locator, in
    the last entry's comment, stores the offset of a ZIP64 record kept in the end record's
    comment that names a decoy. No record lies before the locator, so zipfile without the
    CVE-2025-8291 fix reads the classic record."""
    decoy = (b"numbers.npy", _npy("'<f8'"))
    first_local, real_local = _local(*decoy), _local(*real)
    decoy_cd = _central(*decoy, 0)
    decoy_at = len(first_local) + len(real_local)
    real_at = decoy_at + len(decoy_cd)
    listed = _central(*decoy, 0)
    padding = b"x" * 80
    sized = _central(*real, len(first_local), padding + b"\0" * 20)
    end_at = real_at + len(listed) + len(sized)
    locator = struct.pack("<IIQI", 0x07064B50, 0, end_at + 22, 1)
    real_cd = listed + _central(*real, len(first_local), padding + locator)
    record = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1, len(decoy_cd), decoy_at)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF, len(real_cd), real_at, 56)
    return first_local + real_local + decoy_cd + real_cd + end + record


@pytest.mark.parametrize("pickled", [False, True], ids=["array", "pickle"])
def test_a_saturated_classic_record_is_kept_where_a_reader_falls_back_to_it(
    tmp_path: Path, pickled: bool
) -> None:
    # Only the record after the locator was found, and the saturated classic record was
    # dropped for it, although a reader that looks before the locator finds no record and
    # reads the classic one, which lists the real member.
    real = (b"evil.pkl", _INERT_PICKLE) if pickled else (b"objects.npy", _npy("'|O'"))
    archive = _saturated_with_record_after_locator(real)
    expected = (UNSAFE, ZIP_PICKLE_MEMBER if pickled else ZIP_OBJECT_ARRAY)
    (tmp_path / "models").mkdir()
    relatives = ["models/archive", "arrays.npz", "model.pt"]
    for relative in relatives:
        (tmp_path / relative).write_bytes(archive)
        assert inspect_model_format(tmp_path / relative) == expected, relative


def _saturated_count_with_record_before_locator_only() -> bytes:
    """65,535 entries, so the classic counts saturate, list archive/data.pkl; a ZIP64
    record before the locator names a decoy, and the locator's offset holds no record.
    miniz, which torch.load uses, reads the classic directory and lists data.pkl."""
    version = (b"archive/version", b"3\n")
    real = (b"archive/data.pkl", _INERT_PICKLE)
    head = _local(*version) + _local(*real)
    filler = _central(b"f", b"", 0)
    entries = [_central(*version, 0), _central(*real, len(_local(*version)))]
    real_cd = b"".join(entries) + filler * (0xFFFF - len(entries))
    real_at = len(head)
    decoy_cd = _central(*version, 0)
    decoy_at = real_at + len(real_cd)
    record_at = decoy_at + len(decoy_cd)
    record = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1, len(decoy_cd), decoy_at)
    locator = struct.pack("<IIQI", 0x07064B50, 0, decoy_at, 1)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF, len(real_cd), real_at, 0)
    assert record_at + 56 + 20 == len(head + real_cd + decoy_cd + record + locator)
    return head + real_cd + decoy_cd + record + locator + end


def test_a_saturated_count_is_unread_when_the_locator_names_no_record(tmp_path: Path) -> None:
    # The record before the locator named a decoy, and the saturated classic record was
    # dropped for it; miniz reads the classic one, whose directory is past the bound.
    archive = _saturated_count_with_record_before_locator_only()
    (tmp_path / "models").mkdir()
    for relative in ["models/archive", "weights.dat"]:
        (tmp_path / relative).write_bytes(archive)
        assert inspect_model_format(tmp_path / relative) == (
            SerializationSafety.UNKNOWN,
            ZIP_DIRECTORY_UNREAD,
        ), relative
    (tmp_path / "model.pt").write_bytes(archive)
    found = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert found["model.pt"].serialization_safety == UNSAFE
    assert found["weights.dat"].properties["format_inspection"] == ZIP_DIRECTORY_UNREAD


def _overlong_name(archive: bytes, extra: int) -> bytes:
    """The last directory entry's name length set past the directory by ``extra`` bytes.

    ``zipfile`` reads the directory into a buffer of its stated size and cuts the name
    there, so it still lists the member by its name.
    """
    entry = len(archive) - 22 - _little_end_size(archive)
    name_length = int.from_bytes(archive[entry + 28 : entry + 30], "little")
    longer = min(0xFFFF, name_length + extra)
    return archive[: entry + 28] + longer.to_bytes(2, "little") + archive[entry + 30 :]


def _little_end_size(archive: bytes) -> int:
    return int.from_bytes(archive[-22 + 12 : -22 + 16], "little")


@pytest.mark.parametrize("extra", [0xFFFF, 10], ids=["past-the-end", "into-the-end-record"])
@pytest.mark.parametrize("pickled", [True, False], ids=["pickle", "array"])
def test_a_name_that_runs_past_the_directory_does_not_hide_its_member(
    tmp_path: Path, extra: int, pickled: bool
) -> None:
    # A decoy at the stored offset parsed while the directory zipfile reads, whose last
    # name runs past it, did not, and was dropped: np.load still unpickled the member.
    real_name = b"archive/data.pkl" if pickled else b"objects.npy"
    decoy = (b"archive/version", b"3\n") if pickled else (b"numbers.npy", _npy("'<f8'"))
    payload = _PICKLE if pickled else _npy("'|O'")
    archive = _overlong_name(_concatenated_decoy(decoy, (real_name, payload)), extra)
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == [real_name.decode()]
        assert opened.read(real_name.decode()) == payload
    expected = (UNSAFE, ZIP_PICKLE_MEMBER if pickled else ZIP_OBJECT_ARRAY)
    (tmp_path / "models").mkdir()
    relatives = ["models/archive", "arrays.npz", "model.onnx"]
    for relative in relatives:
        (tmp_path / relative).write_bytes(archive)
        assert inspect_model_format(tmp_path / relative) == expected, relative
    found = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert {r: found[r].serialization_safety for r in relatives} == dict.fromkeys(relatives, UNSAFE)


def test_a_name_cut_at_the_directory_end_lists_a_harmless_member_as_harmless(
    tmp_path: Path,
) -> None:
    archive = _overlong_name(
        _concatenated_decoy((b"a.npy", _npy("'<f8'")), (b"b.npy", _npy("'<f8'"))), 0xFFFF
    )
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == ["b.npy"]
    assert _inspect(tmp_path, archive, "arrays.npz")[1] == ZIP_WITHOUT_PICKLE


def _counts_hold_an_end_signature(archive: bytes) -> bytes:
    """The end record's entry counts set to the bytes ``PK\\x05\\x06``, which ``zipfile``
    never reads: it takes the last 22 bytes as the end record first."""
    end = len(archive) - 22
    return archive[: end + 8] + b"PK\x05\x06" + archive[end + 12 :]


@pytest.mark.parametrize("pickled", [True, False], ids=["pickle", "array"])
def test_an_end_record_is_located_as_zipfile_locates_it(tmp_path: Path, pickled: bool) -> None:
    member = ("archive/data.pkl", _PICKLE) if pickled else ("objects.npy", _npy("'|O'"))
    archive = _counts_hold_an_end_signature(_zip([("numbers.npy", _npy("'<f8'")), member]))
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == ["numbers.npy", member[0]]
    expected = (UNSAFE, ZIP_PICKLE_MEMBER if pickled else ZIP_OBJECT_ARRAY)
    (tmp_path / "models").mkdir()
    for relative in ("models/archive", "arrays.npz", "model.onnx"):
        (tmp_path / relative).write_bytes(archive)
        assert inspect_model_format(tmp_path / relative) == expected, relative
    harmless = _counts_hold_an_end_signature(_zip([("numbers.npy", _npy("'<f8'"))]))
    assert _inspect(tmp_path, harmless, "arrays.npz")[1] == ZIP_WITHOUT_PICKLE


def test_an_archive_that_starts_with_an_end_record_is_read_as_np_load_reads_it(
    tmp_path: Path,
) -> None:
    # np.load hands zipfile a file that starts with PK\x05\x06, as an empty archive does.
    archive = b"PK\x05\x06" + b"\x00" * 18 + _zip([("objects.npy", _npy("'|O'"))])
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == ["objects.npy"]
    assert _inspect(tmp_path, archive, "arrays.npz") == (UNSAFE, ZIP_OBJECT_ARRAY)
    assert _inspect(tmp_path, archive) == (UNSAFE, ZIP_OBJECT_ARRAY)
    pickled = b"PK\x05\x06" + b"\x00" * 18 + _zip([("x.pkl", _PICKLE)])
    assert _inspect(tmp_path, pickled, "arrays.npz") == (UNSAFE, ZIP_PICKLE_MEMBER)


def test_a_pickle_member_named_past_a_nul_is_unsafe(tmp_path: Path) -> None:
    # zipfile cuts a member name at its first NUL, so a loader opens x.pkl.
    first = _local(b"numbers.npy", _npy("'<f8'"))
    hidden = _local(b"x.pkl\0y", _PICKLE)
    directory = _central(b"numbers.npy", _npy("'<f8'"), 0) + _central(
        b"x.pkl\0y", _PICKLE, len(first)
    )
    archive = first + hidden + directory + _end(2, len(directory), len(first) + len(hidden))
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == ["numbers.npy", "x.pkl"]
    assert _inspect(tmp_path, archive, "arrays.npz") == (UNSAFE, ZIP_PICKLE_MEMBER)
    assert not model._pickle_member(b"x.txt\0y.npy")


def _unicode_path(shown: bytes, name: bytes, *, version: int = 1, crc: int | None = None) -> bytes:
    """An Info-ZIP Unicode Path extra field (0x7075) that renames ``shown`` to ``name``."""
    body = struct.pack("<BL", version, zipfile.crc32(shown) if crc is None else crc) + name
    return struct.pack("<HH", 0x7075, len(body)) + body


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        (_unicode_path(b"x.npy", b"x.pkl"), (UNSAFE, ZIP_PICKLE_MEMBER)),
        (_unicode_path(b"x.npy", b"x.pkl\0y"), (UNSAFE, ZIP_PICKLE_MEMBER)),
        (
            _unicode_path(b"x.npy", b"x.pkl", crc=0),
            (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE),
        ),
        (
            _unicode_path(b"x.npy", b"x.pkl", version=2),
            (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE),
        ),
        (_unicode_path(b"x.npy", b"y.npy"), (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)),
    ],
    ids=["renamed", "renamed-past-nul", "crc-mismatch", "other-version", "harmless-rename"],
)
def test_a_pickle_member_renamed_by_a_unicode_path_field_is_unsafe(
    tmp_path: Path, field: bytes, expected: tuple[SerializationSafety, str]
) -> None:
    # zipfile (3.12 and later) lists a member under the name a version-1 Unicode Path
    # field gives when its CRC matches the stored name, so a loader opens x.pkl.
    first = _local(b"numbers.npy", _npy("'<f8'"))
    hidden = _local(b"x.npy", _PICKLE, field)
    directory = _central(b"numbers.npy", _npy("'<f8'"), 0) + _central(
        b"x.npy", _PICKLE, len(first), extra=field
    )
    archive = first + hidden + directory + _end(2, len(directory), len(first) + len(hidden))
    for name in ("arrays.npz", "model.onnx"):
        assert _inspect(tmp_path, archive, name) == expected


@pytest.mark.parametrize("starts", [True, False], ids=["entry-signature", "no-signature"])
def test_a_directory_that_starts_but_cannot_be_read_hides_behind_no_decoy(starts: bool) -> None:
    # The end record stores the offset of a harmless decoy; the directory of the same
    # size that ends at the end record starts with an entry signature, but its second
    # entry is cut short. What it lists is not decided, so the decoy's reading alone does
    # not rate the archive. A directory without the signature is one no reader takes,
    # and the decoy is read.
    decoy = _local(b"a.npy", _npy("'<f8'"))
    listed = _central(b"a.npy", _npy("'<f8'"), 0)
    other = (b"PK\x01\x02" if starts else b"\0" * 4) + b"\0" * (len(listed) - 4)
    archive = decoy + listed + other + _end(1, len(listed), len(decoy))
    directory = model._zip_directory(io.BytesIO(archive), 0, len(archive))
    assert directory is not None
    readings, undecided = directory
    assert [m.name for members, _ in readings for m in members] == [b"a.npy"]
    assert undecided is starts


@pytest.mark.parametrize("comment", [b"", b"saved by np.savez"], ids=["bare", "commented"])
def test_an_empty_archive_is_read_not_left_unread(tmp_path: Path, comment: bytes) -> None:
    # np.savez() with no arrays writes only an end record, at offset 0.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.comment = comment
    empty = buffer.getvalue()
    assert empty.startswith(b"PK\x05\x06")
    with zipfile.ZipFile(io.BytesIO(empty)) as opened:
        assert opened.namelist() == []
    for name in ("arrays.npz", "model.onnx"):
        assert _inspect(tmp_path, empty, name) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)


def test_a_directory_past_the_bound_is_unread_whatever_a_decoy_lists(tmp_path: Path) -> None:
    # The end record stores the offset of a directory listing a pickle, more than the
    # bound before the end; the directory zipfile reads, which ends at the end record,
    # is a decoy. What the far one lists is not decided, so the archive stays unread.
    real = (b"archive/data.pkl", _PICKLE)
    decoy = (b"archive/version", b"3\n")
    first = _local(b"README", b"x")
    real_local = _local(*real)
    size = len(_central(*real, len(first)))
    padding = b"\x00" * (2 * model._ZIP_TAIL_BYTES)
    decoy_at = len(first) + len(real_local) + size + len(padding)
    decoy_local = _local(*decoy)
    stored = len(first) + len(real_local)
    shift = decoy_at + len(decoy_local) - stored
    listed = _central(*decoy, decoy_at - shift)
    listed = _central(*decoy, decoy_at - shift, b"c" * (size - len(listed)))
    head = first + real_local + _central(*real, len(first))
    archive = head + padding + decoy_local + listed + _end(1, size, stored)
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.namelist() == ["archive/version"]
    (tmp_path / "models").mkdir()
    (tmp_path / "models/archive").write_bytes(archive)
    unread = (SerializationSafety.UNKNOWN, ZIP_DIRECTORY_UNREAD)
    assert inspect_model_format(tmp_path / "models/archive") == unread
    found = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert found["models/archive"].properties["format_inspection"] == ZIP_DIRECTORY_UNREAD


def _mutated(rng: random.Random) -> bytes:
    names = [f"m{index}.npy" for index in range(rng.randrange(1, 4))]
    archive = _zip([(name, _npy("'<f8'")) for name in names])
    choice = rng.randrange(4)
    if choice == 0:
        archive = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64))) + archive
    elif choice == 1:
        archive = _concatenated_decoy((b"a.npy", _npy("'<f8'")), (b"b.npy", _npy("'<f8'")))
    elif choice == 2:
        archive = _zip64_decoy((b"a.npy", _npy("'<f8'")), (b"b.npy", _npy("'<f8'")))
    if rng.randrange(4) == 0:
        archive = _overlong_name(archive, rng.choice([1, 10, 0xFFFF]))
    end = archive.rfind(b"PK\x05\x06")
    for _ in range(rng.randrange(3)):
        at = rng.randrange(max(0, end - 96), len(archive))
        archive = archive[:at] + bytes([rng.randrange(256)]) + archive[at + 1 :]
    return archive


def test_the_scanner_lists_every_member_zipfile_lists() -> None:
    rng = random.Random(20261116)  # noqa: S311 - a reproducible corpus, not a secret
    compared = 0
    for _ in range(400):
        archive = _mutated(rng)
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as opened:
                listed = {name.encode("cp437") for name in opened.namelist()}
        except (zipfile.BadZipFile, ValueError, OSError, UnicodeError, NotImplementedError):
            continue
        directory = model._zip_directory(io.BytesIO(archive), 0, len(archive))
        # A directory not decided is rated unknown unless a reading lists a dangerous
        # member; when every directory is decided, the readings list every member.
        if directory is not None and not directory[1]:
            readings = directory[0]
            compared += 1
            # zipfile cuts a name at its first NUL.
            names = {m.name.split(b"\0")[0] for members, _ in readings for m in members}
            assert listed <= names, archive
    assert compared > 100
