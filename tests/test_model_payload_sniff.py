"""Pickle and object-dtype NumPy payloads are found by content, not only by suffix."""

from __future__ import annotations

import io
import os
import pickle
import pickletools
import random
import struct
import subprocess
import sys
import zipfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO, cast

import pytest

from nexus_symbiote import limits
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.scanners.model import (
    MAX_PICKLE_INSPECTION_BYTES,
    MAX_PICKLE_MARKS,
    MAX_PICKLE_OPCODES,
    NUMPY_HEADER_UNREAD,
    NUMPY_OBJECT_ARRAY,
    PICKLE_FRAME_TAIL,
    PICKLE_NAME_UNCALLED,
    PICKLE_NAME_UNEVIDENCED,
    PICKLE_UNREAD,
    ZIP_DIRECTORY_UNREAD,
    ZIP_MEMBER_UNREAD,
    ZIP_OBJECT_ARRAY,
    ZIP_PICKLE_MEMBER,
    ModelScanner,
)
from nexus_symbiote.utils import pickle_load
from nexus_symbiote.validators.integrity import IntegrityValidator
from tests.support import scaling_ratio

UNSAFE = SerializationSafety.UNSAFE_CODE_EXECUTION
BINARY_PICKLE = "Recognized binary pickle opcode stream; object loading can execute code"


class _Boom:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, ("1+1",))


def _reduce_pickle(*tail: object) -> bytes:
    return pickle.dumps([_Boom(), *tail], protocol=4)


def _npy(descr: str, *, version: int = 1, lead: int = 0) -> bytes:
    text = "{" + " " * lead + f"'descr': '{descr}', 'fortran_order': False, 'shape': (1,), }}"
    width = 2 if version == 1 else 4
    text += " " * (-(10 + width + len(text) + 1) % 64) + "\n"
    return (
        b"\x93NUMPY"
        + bytes([version, 0])
        + len(text).to_bytes(width, "little")
        + text.encode()
        + b"\x00" * 8
    )


def _zip(members: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def _components(root: Path) -> dict[str, object]:
    result = ModelScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    return {component.source_path or "": component for component in result.components}


def _component(root: Path, relative: str):
    return _components(root).get(relative)


def _critical(component) -> bool:
    return any(
        risk.severity is RiskSeverity.CRITICAL and risk.category == "serialization_format"
        for risk in component.risks
    )


def test_renamed_pickle_and_object_arrays_are_critical(tmp_path: Path) -> None:
    payload = _reduce_pickle()
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights").write_bytes(payload)
    (tmp_path / "models" / "model.dat").write_bytes(payload)
    (tmp_path / "tensors").mkdir()
    (tmp_path / "tensors" / "objects.npy").write_bytes(_npy("|O"))
    (tmp_path / "tensors" / "numbers.npy").write_bytes(_npy("<f8"))
    (tmp_path / "checkpoints").mkdir()
    (tmp_path / "checkpoints" / "bundle.bin.not").write_bytes(_zip([("weights/data.pkl", payload)]))

    found = _components(tmp_path)
    assert "tensors/numbers.npy" not in found
    for relative in (
        "models/weights",
        "models/model.dat",
        "tensors/objects.npy",
        "checkpoints/bundle.bin.not",
    ):
        component = found[relative]
        assert component.serialization_safety is UNSAFE
        assert _critical(component)
    assert "1+1" not in found["models/weights"].model_dump_json()
    # The rating carries the same evidence as a file under a model name.
    assert found["models/weights"].properties["format_inspection"] == BINARY_PICKLE
    assert found["tensors/objects.npy"].properties["format_inspection"] == NUMPY_OBJECT_ARRAY
    archive = found["checkpoints/bundle.bin.not"]
    assert archive.properties["format_inspection"] == ZIP_PICKLE_MEMBER
    assert archive.serialization_format == "zip-archive"


def test_a_suffix_list_file_is_unknown_without_a_recognized_stream(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"not a pickle")
    component = _component(tmp_path, "model.pkl")
    assert component is not None
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_NAME_UNEVIDENCED
    assert not _critical(component)
    assert any(
        risk.severity is RiskSeverity.HIGH and risk.category == "serialization_format_unknown"
        for risk in component.risks
    )


def test_a_pickle_longer_or_shorter_than_the_sample_is_found_by_the_shared_recognizer(
    tmp_path: Path,
) -> None:
    (tmp_path / "models").mkdir()
    long = _reduce_pickle(b"x" * 117_000)
    assert len(long) > MAX_PICKLE_INSPECTION_BYTES
    (tmp_path / "models" / "long").write_bytes(long)
    # Cut short after more than 16 well-formed opcodes, as a loader still runs them.
    truncated = _reduce_pickle(*range(40))
    (tmp_path / "models" / "truncated").write_bytes(truncated[:-12])
    noise = random.Random(152).randbytes(5000)  # noqa: S311 - fixed test data, not a secret
    (tmp_path / "models" / "random").write_bytes(noise)
    (tmp_path / "models" / "notes").write_bytes(b"(a parenthesised note, not a pickle)\n" * 50)

    found = _components(tmp_path)
    assert sorted(found) == ["models/long", "models/truncated"]
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert component.properties["format_inspection"] == BINARY_PICKLE


def test_a_zip_is_rated_from_the_directory_at_its_end(tmp_path: Path) -> None:
    payload = _reduce_pickle()
    (tmp_path / "models").mkdir()
    # torch.save may write a member longer than any prefix before data.pkl.
    (tmp_path / "models" / "archive").write_bytes(
        _zip([("archive/version", b"3" * 100_000), ("archive/data.pkl", payload)])
    )
    (tmp_path / "models" / "renamed.dat").write_bytes(
        _zip([("version", b"1"), ("weights/data.pickle", payload)])
    )
    (tmp_path / "models" / "notes.dat").write_bytes(
        _zip([("version", b"1"), ("README.txt", b"numbers only")])
    )

    found = _components(tmp_path)
    assert sorted(found) == ["models/archive", "models/renamed.dat"]
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert component.properties["format_inspection"] == ZIP_PICKLE_MEMBER


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_npz_object_arrays_are_inventoried_wherever_they_sit(
    tmp_path: Path, compression: int
) -> None:
    numbers = _npy("<f8") + b"\x00" * 70_000
    (tmp_path / "late.npz").write_bytes(
        _zip([("numbers.npy", numbers), ("objects.npy", _npy("|O"))], compression)
    )
    (tmp_path / "numbers.npz").write_bytes(_zip([("numbers.npy", numbers)], compression))

    found = _components(tmp_path)
    assert sorted(found) == ["late.npz"]
    assert found["late.npz"].serialization_safety is UNSAFE
    assert found["late.npz"].properties["format_inspection"] == ZIP_OBJECT_ARRAY
    assert _critical(found["late.npz"])


def test_npz_with_a_compressed_member_first_is_inventoried(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("numbers.npy", _npy("<f8"), compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("objects.npy", _npy("|O"), compress_type=zipfile.ZIP_STORED)
    (tmp_path / "arrays.npz").write_bytes(buffer.getvalue())
    component = _component(tmp_path, "arrays.npz")
    assert component is not None
    assert component.serialization_safety is UNSAFE


def test_content_left_unread_at_a_bound_is_inventoried_as_unknown(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "padded.npy").write_bytes(
        _npy("|O", version=2, lead=MAX_PICKLE_INSPECTION_BYTES)
    )
    (tmp_path / "models" / "lzma.npz").write_bytes(
        _zip([("objects.npy", _npy("|O"))], zipfile.ZIP_LZMA)
    )
    whole = _zip([("version", b"3"), ("archive/data.pkl", _reduce_pickle())])
    (tmp_path / "models" / "cut").write_bytes(whole[: whole.index(b"PK\x01\x02")])

    found = _components(tmp_path)
    assert {
        path: component.properties["format_inspection"] for path, component in found.items()
    } == {
        "models/padded.npy": NUMPY_HEADER_UNREAD,
        "models/lzma.npz": ZIP_MEMBER_UNREAD,
        "models/cut": ZIP_DIRECTORY_UNREAD,
    }
    for component in found.values():
        assert component.serialization_safety is SerializationSafety.UNKNOWN
        assert any(risk.category == "serialization_format_unknown" for risk in component.risks)


def test_each_byte_of_a_model_directory_is_charged_once(tmp_path: Path) -> None:
    models = tmp_path / "models"
    models.mkdir()
    (models / "weights").write_bytes(_reduce_pickle(b"y" * 40_000))
    for index in range(20):
        (models / f"notes{index}.txt").write_bytes(b"T" + b"e" * 4_999)
    (models / "config.json").write_text('{"model_type": "demo"}')
    (models / "tokenizer.json").write_text('{"version": "1.0"}')
    total = sum(path.stat().st_size for path in models.iterdir())
    with limits.applied(replace(limits.DEFAULTS, model_total_bytes=total)):
        component = _component(tmp_path, "models/weights")
    assert component is not None
    assert component.serialization_safety is UNSAFE
    assert component.hashes["sha256"].startswith("sha256:")
    assert [entry["path"] for entry in component.properties["config_files"]] == [
        "models/config.json"
    ]


def test_a_model_directory_file_is_not_a_content_candidate(tmp_path: Path) -> None:
    models = tmp_path / "models"
    models.mkdir()
    for name in ("config.json", "vocab.txt", "chat_template.jinja", "loader.py"):
        (models / name).write_bytes(_reduce_pickle())
    assert _components(tmp_path) == {}


def test_validation_observes_a_content_artifact_as_the_scan_did(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights").write_bytes(_reduce_pickle())
    (tmp_path / "arrays.npz").write_bytes(_zip([("arr_0.npy", _npy("|O"))]))
    bom = AIBOM(components=ModelScanner().scan(tmp_path).components)
    report = IntegrityValidator(require_model_signatures=False).validate(bom, tmp_path)
    issues = {(issue.component_ref, issue.category) for issue in report.issues}
    for reference in ("model:models/weights", "model:arrays.npz"):
        assert (reference, "unsafe_format") in issues
        assert (reference, "format_subject_mismatch") not in issues
        assert (reference, "format_claim_mismatch") not in issues


@pytest.mark.parametrize("member", [".pkl", "archive/.pkl", "archive/..pkl", "DATA.PKL"])
@pytest.mark.parametrize("name", ["model.gguf", "model.onnx", "models/archive"])
def test_a_pickle_member_named_only_by_its_suffix_is_critical(
    tmp_path: Path, member: str, name: str
) -> None:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_zip([("archive/version", b"3"), (member, _reduce_pickle())]))
    component = _component(tmp_path, name)
    assert component is not None and component.serialization_safety is UNSAFE
    assert component.properties["format_inspection"] == ZIP_PICKLE_MEMBER


def _without_zip64(archive: bytes, member: bytes) -> bytes:
    """``archive`` with ``member``'s central entry claiming 0xFFFFFFFF bytes, no ZIP64 field."""
    entry = archive.index(b"PK\x01\x02")
    while archive[entry + 46 : entry + 46 + len(member)] != member:
        entry = archive.index(b"PK\x01\x02", entry + 4)
    return archive[: entry + 24] + b"\xff\xff\xff\xff" + archive[entry + 28 :]


def test_a_later_entry_without_its_zip64_field_does_not_hide_a_pickle(tmp_path: Path) -> None:
    archive = _without_zip64(
        _zip([("archive/data.pkl", _reduce_pickle()), ("archive/version", b"3")]),
        b"archive/version",
    )
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        assert opened.read("archive/data.pkl")  # the loader still reads the pickle
    (tmp_path / "model.onnx").write_bytes(archive)
    component = _component(tmp_path, "model.onnx")
    assert component is not None and component.serialization_safety is UNSAFE


def _short_zip64(archive: bytes, member: bytes) -> bytes:
    """``archive`` with ``member``'s central entry claiming 0xFFFFFFFF compressed bytes and
    carrying a ZIP64 field too short to hold them, which ``zipfile`` refuses as corrupt."""
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        infos = opened.infolist()
    rebuilt = io.BytesIO()
    with zipfile.ZipFile(rebuilt, "w") as out:
        for info in infos:
            copy = zipfile.ZipInfo(info.filename, info.date_time)
            if info.filename.encode() == member:
                copy.extra = b"\x01\x00\x00\x00"
            with zipfile.ZipFile(io.BytesIO(archive)) as opened:
                out.writestr(copy, opened.read(info.filename))
    data = rebuilt.getvalue()
    entry = data.index(b"PK\x01\x02")
    while data[entry + 46 : entry + 46 + len(member)] != member:
        entry = data.index(b"PK\x01\x02", entry + 4)
    return data[: entry + 20] + b"\xff\xff\xff\xff" + data[entry + 24 :]


@pytest.mark.parametrize("unreadable", [b"archive/readme.txt", b"archive/data.pkl"])
def test_an_entry_whose_zip64_field_is_too_short_does_not_hide_a_pickle(
    tmp_path: Path, unreadable: bytes
) -> None:
    # The first member is not the pickle, so only the central directory names it. The
    # short field is on an entry listed before the pickle, or on the pickle's own entry.
    archive = _short_zip64(
        _zip(
            [
                ("archive/version", b"3"),
                ("archive/readme.txt", b"hi"),
                ("archive/data.pkl", _reduce_pickle()),
            ]
        ),
        unreadable,
    )
    with pytest.raises(zipfile.BadZipFile):
        zipfile.ZipFile(io.BytesIO(archive)).infolist()
    (tmp_path / "model.onnx").write_bytes(archive)
    component = _component(tmp_path, "model.onnx")
    assert component is not None and component.serialization_safety is UNSAFE
    assert component.properties["format_inspection"] == ZIP_PICKLE_MEMBER
    assert _critical(component)


def test_an_unlocated_entry_without_a_pickle_leaves_the_archive_unrated(tmp_path: Path) -> None:
    archive = _short_zip64(
        _zip([("arr_0.npy", _npy("<f4")), ("arr_1.npy", _npy("<f4"))]), b"arr_0.npy"
    )
    (tmp_path / "arrays.npz").write_bytes(archive)
    component = _component(tmp_path, "arrays.npz")
    assert component is not None and component.serialization_safety is not UNSAFE
    assert component.properties["format_inspection"] == ZIP_DIRECTORY_UNREAD
    assert not _critical(component)


def test_a_later_entry_whose_name_runs_past_the_file_does_not_hide_a_pickle(
    tmp_path: Path,
) -> None:
    # The first member is not the pickle, so only the central directory names it.
    archive = _zip(
        [("archive/version", b"3"), ("archive/data.pkl", _reduce_pickle()), ("archive/x", b"")]
    )
    entry = archive.rindex(b"PK\x01\x02")
    archive = archive[: entry + 28] + b"\xff\xff" + archive[entry + 30 :]
    (tmp_path / "model.onnx").write_bytes(archive)
    component = _component(tmp_path, "model.onnx")
    assert component is not None and component.serialization_safety is UNSAFE
    assert component.properties["format_inspection"] == ZIP_PICKLE_MEMBER


@pytest.mark.parametrize(
    "text",
    [
        b"N.B. these weights are converted by convert.py\n",
        b"cached/\nlogs/\n.",
        b"logs/*\n.env\n",
    ],
)
def test_text_under_a_model_directory_is_not_read_as_a_pickle(tmp_path: Path, text: bytes) -> None:
    (tmp_path / "checkpoints").mkdir()
    (tmp_path / "checkpoints" / ".gitignore").write_bytes(text)
    assert _component(tmp_path, "checkpoints/.gitignore") is None


def test_text_that_reads_as_an_importable_global_is_unknown(tmp_path: Path) -> None:
    # `pickle.load` imports a module named `heckpoint*` when a file `heckpoint*.py` is on
    # its path, and the module's __getattr__ may answer `*.pth`, so this is a GLOBAL
    # returned at STOP. A module name that may hold any character a file name may is
    # the price of not missing `cev-il\nrun\n)R.` beside a committed `ev-il.py`.
    (tmp_path / "checkpoints").mkdir()
    (tmp_path / "checkpoints" / ".gitignore").write_bytes(b"checkpoint*\n*.pth\n.DS_Store\n")
    component = _component(tmp_path, "checkpoints/.gitignore")
    assert component is not None
    assert component.serialization_safety is SerializationSafety.UNKNOWN


@pytest.mark.parametrize(
    "data",
    [
        b"cev-il\nrun\n)R.",
        b"cevil x\nrun\n)R.",
        b"\x80\x02cev-il\nrun\n)R.",
        b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x8c\x05ev-il\x8c\x03run\x93)R.",
    ],
    ids=["global-dash", "global-space", "proto-2", "stack-global"],
)
def test_a_pickle_that_imports_a_module_with_any_file_name_is_critical(
    tmp_path: Path, data: bytes
) -> None:
    # find_class imports the module first, and importlib imports `ev-il.py` or
    # `evil x.py` beside the loader, which runs that file.
    module = (
        data.split(b"\x8c\x05")[1][:5]
        if b"\x93" in data
        else data.split(b"c", 1)[1].split(b"\n")[0]
    )
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / (module.decode() + ".py")).write_text("open('IMPORTED', 'w').write('yes')\nrun = len\n")
    (lab / "w.bin").write_bytes(data)
    subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import pickle; pickle.load(open('w.bin', 'rb'))"],
        cwd=lab,
        capture_output=True,
        env={"PYTHONPATH": str(lab), "PATH": os.defpath},
        check=False,
        timeout=60,
    )
    assert (lab / "IMPORTED").exists()
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights").write_bytes(data)
    component = _component(tmp_path, "models/weights")
    assert component is not None and component.serialization_safety is UNSAFE


def test_a_text_pickle_that_names_an_importable_global_is_critical(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "payload").write_bytes(b'cos\nsystem\n(S"id"\ntR.')
    component = _component(tmp_path, "models/payload")
    assert component is not None and component.serialization_safety is UNSAFE


# MARK, NONE, then DUP and TUPLE2 at each level: a tuple whose two items are the tuple
# below, so the paths through the pickle's 40 levels number 2**40, then FROZENSET hashes it.
_SHARED_TUPLES = b"(N" + b"2\x86" * 40 + b"\x91."


def test_a_frozenset_of_shared_tuples_is_rated_in_linear_time(tmp_path: Path) -> None:
    # Each level holds the one below twice, so a walk that does not share them is
    # exponential in the depth; at the largest depth that is 2**40 visits.
    roots = {}
    for scale in (1, 4):
        roots[scale] = tmp_path / f"scale-{scale}"
        (roots[scale] / "models").mkdir(parents=True)
        (roots[scale] / "models" / "shared").write_bytes(b"(N" + b"2\x86" * (10 * scale) + b"\x91.")
    assert scaling_ratio(lambda scale: _components(roots[scale])) < 10
    assert (roots[4] / "models" / "shared").read_bytes() == _SHARED_TUPLES
    assert _component(roots[4], "models/shared") is None


def test_a_resolved_object_below_shared_tuples_is_still_hashed(tmp_path: Path) -> None:
    # hash() reaches the resolved object at the bottom first, which runs its __hash__.
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "shared").write_bytes(b"(cos\nsystem\n" + _SHARED_TUPLES[2:])
    component = _component(tmp_path, "models/shared")
    assert component is not None and component.serialization_safety is UNSAFE


def test_an_unhashable_item_below_shared_tuples_stops_the_load_first(tmp_path: Path) -> None:
    # An empty list before the resolved object: hash() fails on it before reaching it.
    shared = b"(]cos\nsystem\n\x86" + b"2\x86" * 40 + b"\x91."
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "shared").write_bytes(shared)
    component = _component(tmp_path, "models/shared")
    assert component is None or component.serialization_safety is not UNSAFE


def test_a_deeply_nested_first_pickle_does_not_hide_the_next(tmp_path: Path) -> None:
    # CPython hashes 1,200 nested tuples and reads on; the next pickle calls code.
    deep = b"(N" + b"\x85" * 1200 + b"\x91."
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "deep").write_bytes(deep + _reduce_pickle())
    component = _component(tmp_path, "models/deep")
    assert component is not None and component.serialization_safety is UNSAFE


# Opcodes through which unpickling resolves or calls an object.
_CODE_OPCODES = {
    "GLOBAL",
    "STACK_GLOBAL",
    "INST",
    "OBJ",
    "REDUCE",
    "NEWOBJ",
    "NEWOBJ_EX",
    "BUILD",
    "EXT1",
    "EXT2",
    "EXT4",
}


def _names_a_callable(data: bytes) -> bool:
    names: set[str] = set()
    stream = io.BytesIO(data[:MAX_PICKLE_INSPECTION_BYTES])
    try:
        # A loader can read the pickles that follow a STOP, so every one of them counts.
        while stream.tell() < len(stream.getbuffer()):
            for opcode, _, _ in pickletools.genops(stream):
                names.add(opcode.name)
    except (ValueError, UnicodeError, OverflowError, RecursionError, IndexError):
        # Malformed or truncated bytes end the walk; the opcodes read before them count.
        pass
    return bool(names & _CODE_OPCODES)


def test_text_that_reads_as_a_harmless_pickle_is_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    # "N." is NONE then STOP, "Mar." BININT2 then STOP: well-formed, but they run nothing.
    (tmp_path / "models" / "NOTES.txt").write_bytes(b"N.B. retrain after the next release\n")
    (tmp_path / "samples.dat").write_bytes((11854).to_bytes(2, "little") + bytes(range(64)))
    (tmp_path / "service.dat").write_bytes(b"Mar. 3 12:00:01 service started\n")
    assert _components(tmp_path) == {}
    # A name on the pickle suffix list is still rated by the name.
    (tmp_path / "models" / "notes.pkl").write_bytes(b"N.B.")
    assert _components(tmp_path)["models/notes.pkl"].serialization_safety is UNSAFE


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_a_pickle_that_reaches_code_is_critical_by_content_at_every_protocol(
    tmp_path: Path, protocol: int
) -> None:
    payload = pickle.dumps(_Boom(), protocol=protocol)
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights").write_bytes(payload)
    (tmp_path / "state.dat").write_bytes(payload)
    (tmp_path / "bundle.npz").write_bytes(_zip([("arr_0.npy", _npy("|O")), ("x.pkl", payload)]))
    found = _components(tmp_path)
    assert sorted(found) == ["bundle.npz", "models/weights", "state.dat"]
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


def test_random_files_are_never_critical_without_an_opcode_that_reaches_code(
    tmp_path: Path,
) -> None:
    rng = random.Random(1520)  # noqa: S311 - fixed test data, not a secret
    starts = [b"N.", b"Mar.", b"I12\n.", b"(l.", b"].", b"}.", b"K\x07.", b"\x80\x02N."]
    (tmp_path / "models").mkdir()
    written: dict[str, bytes] = {}
    for index in range(240):
        kind = index % 4
        if kind == 0:
            data = rng.choice(starts) + bytes(rng.choices(range(32, 127), k=rng.randrange(200)))
        elif kind == 1:
            data = rng.choice(starts) + rng.randbytes(rng.randrange(400))
        elif kind == 2:
            data = bytes([0x80, rng.randrange(2, 6)]) + rng.randbytes(rng.randrange(400))
        else:
            data = b"".join(
                rng.randrange(-(2**15), 2**15).to_bytes(2, "little", signed=True)
                for _ in range(rng.randrange(1, 100))
            )
        relative = f"models/file{index}.txt" if index % 2 else f"data{index}.dat"
        (tmp_path / relative).write_bytes(data)
        written[relative] = data
    for relative, component in _components(tmp_path).items():
        if _critical(component):
            assert _names_a_callable(written[relative]), relative


class _LargeBuffer:
    """Reduces as NumPy does at protocol 5: a callable, then the array's bytes in-band."""

    def __reduce_ex__(self, protocol: object) -> tuple[object, tuple[object]]:
        return (eval, (pickle.PickleBuffer(bytearray(MAX_PICKLE_INSPECTION_BYTES + 4096)),))


def test_a_protocol_5_pickle_of_a_large_buffer_is_unknown_by_content(tmp_path: Path) -> None:
    payload = pickle.dumps(_LargeBuffer(), protocol=5)
    names = [opcode.name for opcode, _, _ in pickletools.genops(payload)]
    # The bytes run past the inspection bound after the name, before the call.
    assert names.index("STACK_GLOBAL") < names.index("BYTEARRAY8") < names.index("REDUCE")
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "array").write_bytes(payload)
    (tmp_path / "array.dat").write_bytes(payload)
    (tmp_path / "array.pt").write_bytes(payload)
    found = _components(tmp_path)
    assert sorted(found) == ["array.dat", "array.pt", "models/array"]
    for relative in ("array.dat", "models/array"):
        assert found[relative].serialization_safety is SerializationSafety.UNKNOWN
        assert found[relative].properties["format_inspection"] == PICKLE_NAME_UNCALLED
    # The pickle a bound left unrated is pickle evidence under a pickle-family name.
    assert found["array.pt"].serialization_safety is UNSAFE
    assert found["array.pt"].properties["format_inspection"] == (
        "Potential code-executing loader format (pickle opcode stream that resolves an "
        "importable name and, within the inspection limits, never uses it)"
    )


def test_a_binary_pickle_with_no_callable_before_the_bound_is_unknown(tmp_path: Path) -> None:
    filler = b"N0" * 20 + b"\x8e" + (MAX_PICKLE_INSPECTION_BYTES).to_bytes(8, "little")
    payload = b"\x80\x04" + filler + b"x" * MAX_PICKLE_INSPECTION_BYTES
    payload += pickle.dumps(_Boom(), protocol=4)[2:]
    (tmp_path / "padded.dat").write_bytes(payload)
    # The same opcodes cut short before the bound run nothing: not a payload.
    (tmp_path / "short.dat").write_bytes(b"\x80\x04" + filler + b"x" * 100)
    found = _components(tmp_path)
    assert sorted(found) == ["padded.dat"]
    component = found["padded.dat"]
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_UNREAD
    assert any(risk.category == "serialization_format_unknown" for risk in component.risks)
    bom = AIBOM(components=list(found.values()))
    report = IntegrityValidator(require_model_signatures=False).validate(bom, tmp_path)
    categories = {issue.category for issue in report.issues}
    assert "format_claim_mismatch" not in categories
    assert "format_subject_mismatch" not in categories


def _legacy_torch(main: object) -> bytes:
    """``torch.save``'s legacy layout: three header pickles, then the main pickle."""
    sys_info = {
        "protocol_version": 1001,
        "little_endian": True,
        "type_sizes": {"short": 2, "int": 4, "long": 4},
    }
    header = [0x1950A86A20F9469CFC6C, 1001, sys_info]
    return b"".join(pickle.dumps(part, protocol=2) for part in [*header, main])


def test_a_pickle_after_harmless_pickles_is_critical_by_content(tmp_path: Path) -> None:
    legacy = _legacy_torch(_Boom())
    # torch's _legacy_load unpickles the three header pickles, then the main one.
    stream = io.BytesIO(legacy)
    for _ in range(3):
        pickle.load(stream)  # noqa: S301 - the test's own bytes
    assert pickle.Unpickler(stream).load() == 2  # noqa: S301 - _Boom evaluates 1+1
    (tmp_path / "models").mkdir()
    files = {
        "models/pytorch_model": legacy,
        "weights.dat": legacy,
        "w.npy": legacy,
        "models/m2": b"\x80\x04N." + pickle.dumps(_Boom(), protocol=4),
        "models/m3": b"N." + pickle.dumps(_Boom(), protocol=0),
        "models/m4": b"N.N.(l." + pickle.dumps(_Boom(), protocol=1),
    }
    for relative, data in files.items():
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == sorted(files)
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


def test_harmless_pickles_in_a_row_are_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "header").write_bytes(_legacy_torch([1, 2, 3]))
    (tmp_path / "pairs.dat").write_bytes(b"N.N.\x80\x04N.")
    (tmp_path / "trailer.dat").write_bytes(b"N.\x80\x09 not a pickle")
    assert _components(tmp_path) == {}


def test_a_pickle_past_the_bound_after_a_harmless_one_is_unknown(tmp_path: Path) -> None:
    filler = b"\x80\x04\x8e" + (MAX_PICKLE_INSPECTION_BYTES).to_bytes(8, "little")
    payload = b"\x80\x04N." + filler + b"x" * MAX_PICKLE_INSPECTION_BYTES + b"."
    payload += pickle.dumps(_Boom(), protocol=4)
    (tmp_path / "padded.dat").write_bytes(payload)
    component = _components(tmp_path)["padded.dat"]
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_UNREAD


def _padded_legacy_torch(protocol: int, *, by_opcodes: bool) -> bytes:
    """Legacy ``torch.save`` bytes whose ``sys_info`` pickle runs past an inspection bound."""
    sys_info: dict[str, object] = {"protocol_version": 1001, "little_endian": True}
    if by_opcodes:
        sys_info.update({f"k{index}": index for index in range(MAX_PICKLE_OPCODES)})
    else:
        sys_info["note"] = "x" * MAX_PICKLE_INSPECTION_BYTES
    header = [0x1950A86A20F9469CFC6C, 1001, sys_info]
    parts = [pickle.dumps(part, protocol=protocol) for part in header]
    return b"".join([*parts, pickle.dumps(_Boom(), protocol=protocol)])


@pytest.mark.parametrize("protocol", [0, 2])
@pytest.mark.parametrize("by_opcodes", [True, False], ids=["opcodes", "bytes"])
def test_a_padded_header_pickle_after_a_stop_is_unknown(
    tmp_path: Path, protocol: int, by_opcodes: bool
) -> None:
    legacy = _padded_legacy_torch(protocol, by_opcodes=by_opcodes)
    stream = io.BytesIO(legacy)
    for _ in range(3):
        pickle.load(stream)  # noqa: S301 - the test's own bytes
    assert pickle.Unpickler(stream).load() == 2  # noqa: S301 - _Boom evaluates 1+1
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "pytorch_model").write_bytes(legacy)
    (tmp_path / "weights.dat").write_bytes(legacy)
    found = _components(tmp_path)
    assert sorted(found) == ["models/pytorch_model", "weights.dat"]
    for component in found.values():
        assert component.serialization_safety is SerializationSafety.UNKNOWN
        assert component.properties["format_inspection"] == PICKLE_UNREAD


def test_text_cut_short_without_an_earlier_stop_is_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    # After a STOP, a text segment that fails short of the bound, or ends with the file.
    (tmp_path / "models" / "notes").write_bytes(b"N.(I1\nnot a pickle at all\n")
    (tmp_path / "tail.dat").write_bytes(b"N.(I1\nI2\n")
    assert _components(tmp_path) == {}


# builtins.len('x'): an inert call that pickle.load reaches past harmless padding.
_INERT_CALL = b"cbuiltins\nlen\n(S'x'\ntR."
_PADDING = b"N0" * (MAX_PICKLE_OPCODES // 2 + 1)  # NONE, POP: past the opcode budget
_LONG_STRING = b"S'" + b"a" * MAX_PICKLE_INSPECTION_BYTES + b"'\n0"  # STRING, POP
# Text-protocol pickles at the start of a file that run past the opcode or MARK budget,
# or past the 64 KiB sample, before the loader's behaviour is decided.
_PAST_A_BOUND = {
    "opcodes": (_PADDING + _INERT_CALL, PICKLE_UNREAD),
    "marks": (b"(" * (MAX_PICKLE_MARKS + 1) + _INERT_CALL, PICKLE_UNREAD),
    "named": (_INERT_CALL[:14] + _PADDING + _INERT_CALL[14:], PICKLE_NAME_UNCALLED),
    "no-call": (b"(" + b"I1\n" * MAX_PICKLE_OPCODES, PICKLE_UNREAD),
    "sample": (_LONG_STRING + _INERT_CALL, PICKLE_UNREAD),
    "sample-named": (_INERT_CALL[:14] + _LONG_STRING + _INERT_CALL[14:], PICKLE_NAME_UNCALLED),
    "sample-no-call": (b"(S'" + b"x" * MAX_PICKLE_INSPECTION_BYTES + b"'\n", PICKLE_UNREAD),
}


@pytest.mark.parametrize(
    ("data", "explanation"), list(_PAST_A_BOUND.values()), ids=list(_PAST_A_BOUND)
)
def test_a_text_pickle_past_a_bound_is_unknown_by_content(
    tmp_path: Path, data: bytes, explanation: str
) -> None:
    if data.endswith(_INERT_CALL[14:]):
        # pickle.load reads past the padding and calls what the pickle resolved.
        assert _oracle(data, tmp_path / "oracle.bin") == (True, True)
    root = tmp_path / "project"
    (root / "models").mkdir(parents=True)
    (root / "models" / "weights").write_bytes(data)
    (root / "weights.dat").write_bytes(data)
    found = _components(root)
    assert sorted(found) == ["models/weights", "weights.dat"]
    for component in found.values():
        assert component.serialization_safety is SerializationSafety.UNKNOWN
        assert component.properties["format_inspection"] == explanation
        assert any(risk.category == "serialization_format_unknown" for risk in component.risks)


@pytest.mark.parametrize("flavor", pickle_load.FLAVORS)
@pytest.mark.parametrize(
    ("sample", "size", "outcome"),
    [
        # A count past the end of the file: truncated, or EOF after a short read.
        (b"The weights", 1000, "error"),
        (b"T\x00\x01\x00\x00ab", 200, "error"),
        # A count that ends inside the file but past the sample.
        (b"T\x00\x01\x00\x00ab", 70_000, "unread"),
        # A line past the sample: undecided while what it shows may still parse.
        (b"S'abc", 1000, "unread"),
        (b"SIMPLE  =    T", 1000, "error"),
        (b"I12", 1000, "unread"),
        (b"I 12  ", 1000, "unread"),
        (b"I12 and more", 1000, "error"),
        (b"Infinity and beyond", 1000, "error"),
        (b"F-inf", 1000, "unread"),
        (b"cos\nsys", 1000, "unread"),
        (b"cos path\nsys", 1000, "unread"),  # only the module line shows
        # The module is imported before the name is looked up, and a module named
        # `ev-il` imports, so only text that is not UTF-8 fails a GLOBAL line early.
        (b"cos\nsys tem", 1000, "unread"),
        (b"cev-", 1000, "unread"),
        (b"cos\n\xff", 1000, "error"),
        (b"Pabc", 1000, "unread"),
        (b"Pab\xe9", 1000, "error"),
        (b"Vanything at all", 1000, "unread"),
    ],
)
def test_a_read_past_the_sample_is_decided_where_the_loaders_are(
    flavor: pickle_load.Flavor, sample: bytes, size: int, outcome: str
) -> None:
    budget = pickle_load.Budget(MAX_PICKLE_OPCODES, MAX_PICKLE_MARKS)
    assert pickle_load.load_segment(sample, size, 0, flavor, budget).outcome == outcome


def test_long_text_past_the_sample_is_not_inventoried(tmp_path: Path) -> None:
    line = b"The weights in this directory were converted from the original checkpoint.\n"
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "README").write_bytes(line * 3000)
    (tmp_path / "models" / "header.fits").write_bytes(b"SIMPLE  =    T" + b" " * 200_000)
    (tmp_path / "models" / "notes").write_bytes(b"Infinity and beyond " * 10_000)
    (tmp_path / "samples.dat").write_bytes(b"Index of runs, " * 10_000)
    assert all(
        len(path.read_bytes()) > MAX_PICKLE_INSPECTION_BYTES for path in tmp_path.rglob("*.*")
    )
    assert _components(tmp_path) == {}


def _frame_stop(tail: bytes) -> bytes:
    """A FRAME holding ``N.`` then ``tail``: a STOP with bytes left in its frame."""
    body = b"N." + tail
    return b"\x95" + len(body).to_bytes(8, "little") + body


def test_each_place_a_pickle_resumes_is_read_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The C unpickler resumes after a STOP inside a frame both at the frame's end and
    # right after the STOP, and from there "N." reaches the same frame end: each such
    # frame doubles the walks of everything after it. Read once each, the budget lasts
    # to the call that a buffered file's C unpickler reaches after the first STOP.
    data = _frame_stop(_INERT_CALL) + _frame_stop(b"N.") * 12
    assert _oracle(data, tmp_path / "oracle.bin")[1]
    walks: dict[tuple[str, int], int] = {}
    load_segments = pickle_load.load_segments

    def counted(
        sample: bytes, size: int, start: int, flavor: pickle_load.Flavor, budget: pickle_load.Budget
    ) -> object:
        walks[flavor, start] = walks.get((flavor, start), 0) + 1
        return load_segments(sample, size, start, flavor, budget)

    monkeypatch.setattr(pickle_load, "load_segments", counted)
    root = tmp_path / "project"
    root.mkdir()
    (root / "weights.dat").write_bytes(data)
    component = _components(root)["weights.dat"]
    assert component.serialization_safety is UNSAFE
    assert max(walks.values()) == 1


@pytest.mark.parametrize("relative", ["models/weights", "model.onnx"])
def test_a_content_check_that_cannot_read_is_not_called_safetensors(
    tmp_path: Path, relative: str
) -> None:
    from nexus_symbiote.scanners.model import INSPECTION_FAILED, inspect_model_format

    path = tmp_path / relative
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(_PADDING + _INERT_CALL)

    class _FailsAfterPrefix:
        """A stream whose reads fail once the eight-byte prefix is read."""

        def __init__(self, raw: io.BufferedReader) -> None:
            self.raw = raw

        def fileno(self) -> int:
            return self.raw.fileno()

        def read(self, size: int = -1) -> bytes:
            if self.raw.tell():
                raise OSError("read error")
            return self.raw.read(size)

    with path.open("rb") as raw:
        stream = cast(BinaryIO, _FailsAfterPrefix(raw))
        assert inspect_model_format(path, stream=stream) == (
            SerializationSafety.UNKNOWN,
            INSPECTION_FAILED,
        )
    # A SafeTensors file whose header does not parse keeps the SafeTensors label.
    tensors = tmp_path / "model.safetensors"
    tensors.write_bytes((20).to_bytes(8, "little") + b"{not a json header}!")
    assert inspect_model_format(tensors) == (
        SerializationSafety.UNKNOWN,
        "Malformed or unsupported SafeTensors structure",
    )


# A text-protocol and a binary pickle that call exec and end with no STOP: pickle.load
# runs the REDUCE, then fails at what follows.
_TEXT_CALL = b"c__builtin__\nexec\n(S'import builtins; builtins.HIT=1'\ntR"
_BINARY_CALL = b"\x80\x02c__builtin__\nexec\nX\x1f\x00\x00\x00import builtins; builtins.HIT=1\x85R"


def _header(protocol: int) -> bytes:
    parts = [0x1950A86A20F9469CFC6C, 1001, {"protocol_version": 1001}]
    return b"".join(pickle.dumps(part, protocol=protocol) for part in parts)


def _runs_exec(data: bytes) -> bool:
    import builtins

    builtins.HIT = 0  # type: ignore[attr-defined]
    stream = io.BytesIO(data)
    try:
        for _ in range(8):
            pickle.load(stream)  # noqa: S301 - the test's own bytes
    except Exception:  # noqa: BLE001, S110 - the loader fails after the call
        pass
    hit = getattr(builtins, "HIT", 0)
    del builtins.HIT  # type: ignore[attr-defined]
    return hit == 1


_CUT_SHORT_AFTER_A_STOP = {
    "text-eof": b"N." + _TEXT_CALL,
    "text-invalid-opcode": b"N." + _TEXT_CALL + b"\xff\xff",
    "text-stack-underflow": b"N." + _TEXT_CALL + b"00000.",
    "text-header-eof": _header(0) + _TEXT_CALL,
    "text-header-invalid-opcode": _header(0) + _TEXT_CALL + b"\xff",
    "binary-header-eof": _header(2) + _BINARY_CALL,
    "binary-header-invalid-opcode": _header(2) + _BINARY_CALL + b"\xff",
    "binary-eof": b"N." + _BINARY_CALL,
}


@pytest.mark.parametrize("data", _CUT_SHORT_AFTER_A_STOP.values(), ids=_CUT_SHORT_AFTER_A_STOP)
def test_a_call_after_a_stop_that_fails_later_is_critical(tmp_path: Path, data: bytes) -> None:
    assert _runs_exec(data)
    (tmp_path / "models").mkdir()
    files = ["models/pytorch_model", "legacy.dat", "w.npy", "models/m.pt", "m.pkl", "m.onnx"]
    for relative in files:
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == sorted(files)
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_a_reduce_pickle_with_no_stop_is_critical_under_a_model_name(
    tmp_path: Path, protocol: int
) -> None:
    data = pickle.dumps(_Boom(), protocol=protocol)[:-1]
    for name, tail in {"eof": b"", "invalid": b"\xff", "underflow": b"00000."}.items():
        (tmp_path / f"{name}.onnx").write_bytes(data + tail)
        (tmp_path / f"{name}.after.dat").write_bytes(b"N." + data + tail)
    found = _components(tmp_path)
    assert len(found) == 6
    assert all(component.serialization_safety is UNSAFE for component in found.values())


def test_a_binary_call_with_no_stop_is_critical_by_content(tmp_path: Path) -> None:
    assert _runs_exec(_BINARY_CALL)
    (tmp_path / "w.dat").write_bytes(_BINARY_CALL)
    assert _components(tmp_path)["w.dat"].serialization_safety is UNSAFE


def test_text_that_reads_as_a_name_without_a_call_is_not_critical(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    # Alone, a text-protocol call cut short is as likely prose.
    (tmp_path / "models" / "readme").write_bytes(b"config\nvalues\nbuild\n")
    (tmp_path / "text.dat").write_bytes(_TEXT_CALL[:-1])
    # After a STOP: words that are no module name, or no call after the name.
    (tmp_path / "models" / "notes").write_bytes(b"N.c see notes\nfor details\nb")
    (tmp_path / "log.dat").write_bytes(b"N.bad\n")
    (tmp_path / "list.dat").write_bytes(b"N.]\x83\x94\xf3\x81<")
    (tmp_path / "stack.dat").write_bytes(b"\x80\x02N.J\xcaW\x22\x16\x93T\xb1")
    assert _components(tmp_path) == {}


def test_a_name_after_a_stop_with_no_call_before_a_flaw_is_not_inventoried(
    tmp_path: Path,
) -> None:
    # pickle.load stops at the byte that is no opcode, or at the end, before any call.
    (tmp_path / "named.dat").write_bytes(b"N.cos\nsystem\n\xff")
    (tmp_path / "ended.dat").write_bytes(b"N.cos\nsystem\n")
    assert _components(tmp_path) == {}


def test_a_name_after_a_stop_cut_short_by_the_bound_is_unknown(tmp_path: Path) -> None:
    data = b"N.cos\nsystem\nS'" + b"a" * MAX_PICKLE_INSPECTION_BYTES + b"'\n\x85R."
    # The call comes after the inspected sample.
    assert data.index(b"R.") > MAX_PICKLE_INSPECTION_BYTES
    (tmp_path / "named.dat").write_bytes(data)
    component = _components(tmp_path)["named.dat"]
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_NAME_UNCALLED


# A STACK_GLOBAL call of exec, and a GLOBAL one, that pickle.load runs.
_STACK_CALL = b"\x8c\x08builtins\x8c\x04exec\x93\x8c\x13builtins.HIT=1;None\x85R."
_GLOBAL_CALL = b"cbuiltins\nexec\n\x8c\x13builtins.HIT=1;None\x85R."

# After a STOP, the next pickle may start with any opcode, not only PROTO 2 to 5 or
# a byte that starts common text-protocol pickles.
_ANY_OPCODE_AFTER_A_STOP = {
    "header-short-binunicode": _header(2) + _STACK_CALL,
    "header-frame": _header(2) + b"\x95" + len(_STACK_CALL).to_bytes(8, "little") + _STACK_CALL,
    "header-proto-1": _header(2) + b"\x80\x01" + _GLOBAL_CALL,
    "header-proto-0": _header(2) + b"\x80\x00" + _GLOBAL_CALL,
    "none-short-binunicode": b"N." + _STACK_CALL,
    "none-newtrue-pop": b"N.\x880" + _GLOBAL_CALL,
    "none-empty-set-pop": b"N.\x8f0" + _GLOBAL_CALL,
}


@pytest.mark.parametrize("data", _ANY_OPCODE_AFTER_A_STOP.values(), ids=_ANY_OPCODE_AFTER_A_STOP)
def test_a_call_after_a_stop_is_critical_whatever_opcode_starts_it(
    tmp_path: Path, data: bytes
) -> None:
    assert _runs_exec(data)
    (tmp_path / "models").mkdir()
    files = ["models/x", "x.dat", "x.npy", "legacy.tar.dat"]
    for relative in files:
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == sorted(files)
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


def test_bytes_after_a_stop_that_start_no_opcode_are_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "invalid.dat").write_bytes(b"N.\xff" + _GLOBAL_CALL)
    (tmp_path / "protocol.dat").write_bytes(b"N.\x80\x06" + _GLOBAL_CALL)
    assert _components(tmp_path) == {}


# Text that reads as a name after a STOP and then an opcode that calls, with nothing on
# the stack for it to call: pickle.load fails at a stack underflow and calls nothing.
_UNCALLED_TEXT = {
    "paths.dat": b"VERSION\n.cache\nlogs\noutputs\n",
    "models/notes.txt": b"N.cache\nbuild\nbin\n",
    "models/llama/MANIFEST": b"Vendored paths:\n.cache\nbuild\nREADME.md\n",
    "models/.gitignore": b"VERSION\n.cache\nbuild\nbin\n",
    "models/.gitignore2": b"Vocabulary files kept out of git\n.cache\ntokenizer\noutputs/\nruns/\n",
    "models/cache-build": b"VERSION\n.cache\nbuild\n",
    "models/calls-none": b"N.cos\nsystem\nN)R.",
    "models/obj-without-mark": b"N.cos\nsystem\no.",
}


def _calls_anything(data: bytes) -> bool:
    called: list[str] = []

    class _Record:
        def __init__(self, *_: object) -> None:
            called.append("init")

        def __call__(self, *_: object) -> None:
            called.append("call")

        def __setstate__(self, _: object) -> None:
            called.append("setstate")

    class _Unpickler(pickle.Unpickler):
        def find_class(self, module: str, name: str) -> type:
            return _Record

    stream = io.BytesIO(data)
    for _ in range(8):
        try:
            _Unpickler(stream).load()
        except Exception:  # noqa: BLE001 - the stream fails where pickle.load does
            break
    return bool(called)


def test_a_name_with_no_operands_for_its_call_is_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "models" / "llama").mkdir(parents=True)
    for relative, data in _UNCALLED_TEXT.items():
        assert not _calls_anything(data)
        (tmp_path / relative).write_bytes(data)
    assert _components(tmp_path) == {}


@pytest.mark.parametrize(
    "data",
    [
        b"N.(cos\nsystem\nNo.",
        b"N.cos\nsystem\n)\x81.",
        b"N.cos\nsystem\np0\n0g0\n)R.",
        b"N.(cos\nsystem\nN\x85R.",
    ],
    ids=["obj", "newobj", "memo", "inside-a-mark"],
)
def test_a_call_with_its_operands_after_a_stop_is_critical(tmp_path: Path, data: bytes) -> None:
    (tmp_path / "call.dat").write_bytes(data)
    assert _components(tmp_path)["call.dat"].serialization_safety is UNSAFE


def _short(text: bytes) -> bytes:
    return b"\x8c" + bytes([len(text)]) + text


# STACK_GLOBAL takes the two strings on the stack, whatever opcodes come between them
# and it: protocols 2 and 3 memoize each string with BINPUT.
_MEMOIZED_STACK_CALL = (
    _short(b"builtins") + b"q\x00" + _short(b"exec") + b"q\x01\x93" + _short(b"builtins.HIT=1")
)
_STACK_CALL_AFTER_A_GAP = {
    "binput-invalid-opcode": b"N." + _MEMOIZED_STACK_CALL + b"\x85R\xff",
    "binput-eof": b"N." + _MEMOIZED_STACK_CALL + b"\x85R",
    "proto-4-binput-invalid-opcode": b"N.\x80\x04" + _MEMOIZED_STACK_CALL + b"\x85R\xff",
    "header-proto-2-binput": _header(2) + b"\x80\x02" + _MEMOIZED_STACK_CALL + b"\x85R\xff",
    "header-binput-eof": _header(2) + _MEMOIZED_STACK_CALL + b"\x85R",
    "newtrue-pop": b"N."
    + _short(b"builtins")
    + _short(b"exec")
    + b"\x880\x93"
    + _short(b"builtins.HIT=1")
    + b"\x85R\xff",
    "unicode-newtrue-pop": b"N.Vbuiltins\nVexec\n\x880\x93" + _short(b"builtins.HIT=1") + b"\x85R",
    "first-proto-4-binput": b"\x80\x04" + _MEMOIZED_STACK_CALL + b"\x85R\xff",
}


@pytest.mark.parametrize("data", _STACK_CALL_AFTER_A_GAP.values(), ids=_STACK_CALL_AFTER_A_GAP)
def test_a_stack_global_is_named_by_the_strings_on_the_stack(tmp_path: Path, data: bytes) -> None:
    assert _runs_exec(data)
    (tmp_path / "models").mkdir()
    files = ["models/x", "x.dat", "x.npy", "w.bin"]
    for relative in files:
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == sorted(files)
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


def _finds_a_class(data: bytes) -> bool:
    found: list[str] = []

    class _Unpickler(pickle.Unpickler):
        def find_class(self, module: str, name: str) -> type:
            found.append(f"{module}.{name}")
            return object

    stream = io.BytesIO(data)
    for _ in range(8):
        try:
            _Unpickler(stream).load()
        except Exception:  # noqa: BLE001 - the stream fails where pickle.load does
            break
    return bool(found)


# Text whose name-shaped lines come only after a stack underflow, where pickle.load stops.
_NAMED_PAST_AN_UNDERFLOW = {
    "models/.gitignore": b"VERSION\n.build\ncheckpoints\nlogs\n",
    "paths.dat": b"VERSION\n.build\ncheckpoints\nlogs\n",
    "models/build-notes": b"N.build\na\nbuild\nos\n",
    "dirs.dat": b"N.build\nbin\ncache\nos\nsystem\n",
}


def test_a_name_past_a_stack_underflow_is_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    for relative, data in _NAMED_PAST_AN_UNDERFLOW.items():
        assert not _finds_a_class(data)
        (tmp_path / relative).write_bytes(data)
    assert _components(tmp_path) == {}


def _frame(body: bytes) -> bytes:
    return b"\x95" + len(body).to_bytes(8, "little") + body


_TEXT_EXEC = b"cbuiltins\nexec\n(S'import builtins; builtins.HIT=1'\ntR."
_SYS_INFO = pickle.dumps({"protocol_version": 1001}, protocol=4)[11:]

# A harmless pickle whose STOP falls inside a FRAME with bytes after it: an unpickler
# reading io.BytesIO or an unbuffered file resumes after the frame, one reading with
# peek after the STOP.
_FRAME_TAIL_THEN_CALL = {
    "invalid-opcode": b"\x80\x04" + _frame(b"N.\xff\xff") + b"\x80\x04" + _STACK_CALL,
    "invalid-opcode-text": b"\x80\x04" + _frame(b"N.\xff") + _TEXT_EXEC,
    "proto-9": b"\x80\x04" + _frame(b"N.\x80\x09") + b"\x80\x04" + _STACK_CALL,
    "harmless-opcodes": b"\x80\x04" + _frame(b"K\x01.\x00\x00\x00") + _TEXT_EXEC,
    "torch-legacy": pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
    + pickle.dumps(1001, protocol=2)
    + b"\x80\x04"
    + _frame(_SYS_INFO + b"\xff")
    + b"\x80\x02"
    + _STACK_CALL,
}


@pytest.mark.parametrize("data", _FRAME_TAIL_THEN_CALL.values(), ids=_FRAME_TAIL_THEN_CALL)
def test_a_call_after_a_frame_with_a_tail_is_critical(tmp_path: Path, data: bytes) -> None:
    assert _runs_exec(data)
    (tmp_path / "models").mkdir()
    files = ["models/x", "x.dat", "x.npy"]
    for relative in files:
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == sorted(files)
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


def test_a_frame_with_bytes_after_its_stop_is_unknown(tmp_path: Path) -> None:
    (tmp_path / "tail.dat").write_bytes(b"\x80\x04" + _frame(b"N.\xff"))
    component = _components(tmp_path)["tail.dat"]
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_FRAME_TAIL


def test_a_frame_that_ends_at_its_stop_is_read_as_before(tmp_path: Path) -> None:
    (tmp_path / "header.dat").write_bytes(pickle.dumps({"protocol_version": 1001}, protocol=4))
    (tmp_path / "pair.dat").write_bytes(pickle.dumps(1, protocol=4) + pickle.dumps(2, protocol=4))
    assert _components(tmp_path) == {}


# A harmless pickle, then one whose BUILD sets no state, padded past each inspection
# bound, with a call of exec beyond it.
_PAYLOAD_PAST_A_BOUND = b"cbuiltins\nexec\n(S'import builtins;builtins.HIT=1'\ntR."
_PADDED_PAST_A_BOUND = {
    "opcodes": b"N." + b"NNb" + b"N0" * 3000 + _PAYLOAD_PAST_A_BOUND,
    "marks": b"N." + b"NNb" + b"(0" * 70 + _PAYLOAD_PAST_A_BOUND,
    "bytes": b"N." + b"NNb0S'" + b"a" * 70000 + b"'\n0" + _PAYLOAD_PAST_A_BOUND,
    "torch-header": _header(2) + b"NNb" + b"N0" * 3000 + _PAYLOAD_PAST_A_BOUND,
}


@pytest.mark.parametrize("data", _PADDED_PAST_A_BOUND.values(), ids=_PADDED_PAST_A_BOUND)
def test_a_pickle_after_a_stop_that_a_bound_cuts_short_is_unknown(
    tmp_path: Path, data: bytes
) -> None:
    assert _runs_exec(data)
    (tmp_path / "models").mkdir()
    files = ["models/x", "x.dat", "x.npy", "legacy.tar.dat"]
    for relative in files:
        (tmp_path / relative).write_bytes(data)
    (tmp_path / "x.pt").write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == sorted([*files, "x.pt"])
    for relative in files:
        assert found[relative].serialization_safety is SerializationSafety.UNKNOWN
        assert found[relative].properties["format_inspection"] == PICKLE_UNREAD
    assert found["x.pt"].serialization_safety is UNSAFE


@pytest.mark.parametrize(
    "data",
    [
        b"VERSION\n.h\ncache\nlogs\nREADME.md\n",
        b"N.g0\ncos\nsystem\n(S'id'\ntR.",
        b"N.j\x07\x00\x00\x00cos\nsystem\n)R.",
        b"N.cos\nsystem\nq\x01h\x02)R.",
    ],
    ids=["text", "get", "long-binget", "other-slot"],
)
def test_a_memo_slot_never_stored_ends_the_pickle(tmp_path: Path, data: bytes) -> None:
    # pickle.load raises "Memo value not found" at the read, before anything after it.
    assert not _calls_anything(data)
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "x").write_bytes(data)
    (tmp_path / "x.dat").write_bytes(data)
    assert _components(tmp_path) == {}


def test_a_memo_slot_that_was_stored_is_read_back(tmp_path: Path) -> None:
    data = b"N.cos\nsystem\nq\x050h\x05(S'id'\ntR."
    assert _calls_anything(data)
    (tmp_path / "x.dat").write_bytes(data)
    assert _components(tmp_path)["x.dat"].serialization_safety is UNSAFE


# An oracle for the property tests below: pickle.load in a loop, by the C and the
# pure-Python unpicklers, with find_class returning a class that records each way it is
# used instead of importing anything (called, __new__, __setstate__, item assignment,
# append, extend, add, hashing, iteration, truth, __index__ and keys()), and
# persistent_load torch's legacy one: the object a ("module", obj, ...) id carries, else
# an inert object. find_class fails only for a module that no finder can name, as the
# import of it does; any other module may be a file of that name.


class _Log:
    def __init__(self) -> None:
        self.resolved = False
        self.called = False


def _recording(log: _Log) -> type:
    def record(*_: object, **__: object) -> object:
        log.called = True
        return None

    def used(result: object) -> Callable[..., object]:
        def method(*_: object, **__: object) -> object:
            log.called = True
            return result

        return method

    class Meta(type):
        def __call__(cls, *_: object, **__: object) -> object:
            log.called = True
            return object.__new__(cls)

        __setitem__ = __getitem__ = append = extend = add = used(None)
        __hash__ = __index__ = __len__ = used(0)
        __bool__ = used(True)
        __iter__ = keys = used(iter(()))

    def new(cls: type, *_: object, **__: object) -> object:
        log.called = True
        return object.__new__(cls)

    return Meta("Recorded", (), {"__new__": new, "__setstate__": record, "__slots__": ()})


def _unpickler(base: type) -> type:
    class Recording(base):  # type: ignore[misc, valid-type]
        log: _Log

        def find_class(self, module: str, name: str) -> type:
            self.log.resolved = True
            if pickle_load._unimportable(module):
                raise ImportError(module)
            return _recording(self.log)

        def persistent_load(self, saved: object) -> object:
            # torch.load's legacy persistent_load returns the object a "module" id
            # carries, and otherwise a storage: an object that runs nothing it is given.
            if isinstance(saved, tuple) and len(saved) > 1 and saved[0] in ("module", b"module"):
                return saved[1]
            return object()

    if hasattr(base, "dispatch"):
        # The pure-Python unpickler allocates and zero-fills a BYTEARRAY8 of the declared
        # length before reading it. Linux refuses 39 TiB at once with MemoryError; macOS
        # grants it and the zero fill runs until the runner kills the test process. A
        # length past the end of the data ends the pickle in an error either way, so it
        # is refused before anything is allocated.
        def load_bytearray8(self: Recording) -> None:
            (length,) = struct.unpack("<Q", self.read(8))
            if length > self.size:
                raise pickle.UnpicklingError("pickle data was truncated")
            buffer = bytearray(length)
            self.readinto(buffer)
            self.append(buffer)

        def init(self: Recording, file: BinaryIO, **options: object) -> None:
            base.__init__(self, file, **options)
            view = getattr(file, "getbuffer", None)
            self.size = len(view()) if view is not None else sys.maxsize

        Recording.__init__ = init  # type: ignore[method-assign]
        Recording.dispatch = {**base.dispatch, pickle.BYTEARRAY8[0]: load_bytearray8}

    return Recording


_UNPICKLERS = {"c": _unpickler(pickle.Unpickler), "py": _unpickler(pickle._Unpickler)}  # type: ignore[attr-defined]


def _oracle_walk(
    flavor: str, stream: io.BufferedIOBase | io.BytesIO, size: int, encoding: str = "ASCII"
) -> list:
    walk: list[tuple[str, bool, int | None]] = []
    for _ in range(32):
        log = _Log()
        if stream.tell() >= size:
            walk.append(("error", False, None))
            break
        unpickler = _UNPICKLERS[flavor](stream, encoding=encoding)
        unpickler.log = log
        try:
            unpickler.load()
        except Exception:  # noqa: BLE001 - pickle.load stops at any exception
            walk.append(("called" if log.called else "error", log.resolved, None))
            break
        if log.called:
            walk.append(("called", log.resolved, None))
            break
        walk.append(("stop", log.resolved, stream.tell()))
    return walk


def _machine_walks(flavor: pickle_load.Flavor, data: bytes) -> list[tuple[list, int | None]]:
    """Each walk the interpreter may take, with the index of its first step that some
    supported CPython takes differently (``pickle_load.VERSION_DIFFERENCES``)."""
    budget = pickle_load.Budget(10**6, 10**6)
    walks: list[tuple[list, int | None]] = []

    def walk(start: int, steps: list, differs: int | None) -> None:
        if len(steps) == 32:
            walks.append((steps, differs))
            return
        for segment in pickle_load.load_segments(data, len(data), start, flavor, budget):
            first = len(steps) if differs is None and segment.differs else differs
            if segment.outcome != "stop":
                outcome = segment.outcome if segment.certain else "maybe-called"
                walks.append(([*steps, (outcome, segment.resolved, None)], first))
            else:
                after = segment.resumes[0]
                walk(after, [*steps, ("stop", segment.resolved, after)], first)

    walk(0, [], None)
    return walks


def _covers(machine: list, differs: int, oracle: list) -> bool:
    """Whether a walk is at least as permissive as the unpickler's from its first step
    that some supported version takes differently: the same steps before it, and a call
    after it if the unpickler calls there."""
    if machine[:differs] != oracle[:differs]:
        return False
    called = ("called", "maybe-called")
    return not any(step[0] == "called" for step in oracle[differs:]) or any(
        step[0] in called for step in machine[differs:]
    )


def _agrees(flavor: pickle_load.Flavor, data: bytes, oracle: list) -> bool:
    """The interpreter follows the unpickler where every version reads alike, and covers
    it where versions differ."""
    walks = _machine_walks(flavor, data)
    if len(walks) == 1 and walks[0][1] is None:
        return _follows(walks[0][0], oracle)
    return any(differs is not None and _covers(steps, differs, oracle) for steps, differs in walks)


def _follows(machine: list, oracle: list) -> bool:
    """Whether the interpreter's walk is the unpickler's.

    Where the interpreter assumes a call that only a resolved object of another type
    than the recording class would reach (a tuple of arguments, a dict of slots, a
    buffer, a str), the unpickler may stop or go on there: the steps before must match
    and that one must have reached find_class.
    """
    if machine and machine[-1][0] == "maybe-called":
        count = len(machine) - 1
        return machine[:count] == oracle[:count] and len(oracle) > count and oracle[count][1]
    return machine == oracle


_SNIPPETS = [
    *(b"N", b"\x88", b"\x89", b"I1\n", b"I01\n", b"I017\n", b"I 5\n", b"L5L\n", b"F1.5\n"),
    *(b"F 1\n", b"K\x07", b"M\x01\x02", b"J\x01\x00\x00\x00", b"G?\xf0\x00\x00\x00\x00\x00\x00"),
    *(b"S'x'\n", b"Sx\n", b"Vhi\n", b"U\x02ab", b"X\x01\x00\x00\x00x", b"\x8c\x01s", b"C\x03abc"),
    *(b"B\x01\x00\x00\x00z", b"\x96\x02\x00\x00\x00\x00\x00\x00\x00ab", b"T\x01\x00\x00\x00\xe9"),
    *(b"(", b")", b"]", b"}", b"\x8f", b"t", b"l", b"d", b"\x85", b"\x86", b"\x87", b"a", b"e"),
    *(b"s", b"u", b"\x90", b"\x91", b"0", b"1", b"2", b"p0\n", b"g0\n", b"q\x01", b"h\x01"),
    *(b"r\x02\x00\x00\x00", b"j\x02\x00\x00\x00", b"\x94", b"R", b"o", b"b", b"\x81", b"\x92"),
    *(b"\x93", b"Q", b"P1\n", b"\x98", b".", b".", b"cos\nsystem\n", b"cbuiltins\nexec\n"),
    *(b"ca b\nc\n", b"c\n\n", b"\x8c\x08builtins\x8c\x04exec", b"ios\nsystem\n", b"\x80\x02"),
    *(b"\x80\x04", b"\x82\x01", b"\xff", b"\x8c\x02os\x8c\x06system", b"NNb", b"N}b", b"N)b"),
    *(b"cbuiltins\n__dict__\n", b"\x8c\x08builtins\x8c\x08__dict__\x93", b"(S'k'\nS'v'\n"),
    *(b"U\x01\xe9", b"S'\xc3\xa9'\n", b"(S'module'\ncos\nsystem\nNNtQ", b"U\x01m"),
]


def _generated(seed: int, count: int) -> list[bytes]:
    rng = random.Random(seed)  # noqa: S311 - a reproducible corpus, not a secret
    samples = []
    for _ in range(count):
        parts = [rng.choice(_SNIPPETS) for _ in range(rng.randrange(1, 24))]
        if rng.random() < 0.3:
            cut = rng.randrange(len(parts) + 1)
            body = b"".join(parts[:cut])
            # A frame of its body, or one byte longer or shorter than it.
            length = len(body) + rng.choice([0, 0, 1, -1])
            parts = [b"\x95" + max(0, length).to_bytes(8, "little") + body, *parts[cut:]]
        data = rng.choice([b"", b"N.", b"\x80\x02N.", _header(2)]) + b"".join(parts)
        if rng.random() < 0.2 and data:
            index = rng.randrange(len(data))
            data = data[:index] + bytes([rng.randrange(256)]) + data[index + 1 :]
        samples.append(data)
    return samples


_PUSHED = [
    *(b"N", b"K\x01", b"S'k'\n", b"\x8c\x01k", b")", b"]", b"}", b"\x8f", b"(", b"(", b"\x88"),
    *(b"cos\nsystem\n", b"cbuiltins\n__dict__\n", b"\x8c\x02os\x8c\x06system\x93", b"h\x00"),
    *(b"\x96\x01\x00\x00\x00\x00\x00\x00\x00a", b"C\x01a", b"I300\n", b"2"),
    *(b"(S'k'\nS'v'\nd", b"N}\x86", b"(K\x01K\x02d", b"Vos\n", b"g0\n", b"j\x00\x00\x00\x00"),
    *(b"(ios\nsystem\n", b"ca b\nc\n", b"\x8c\x01k\x85", b"P1\n", b"\x89", b"F1.5\n"),
]
_USES = [
    *(b"s", b"u", b"a", b"e", b"\x90", b"\x91", b"d", b"l", b"t", b"\x85", b"\x86", b"R"),
    *(b"o", b"b", b"\x81", b"\x92", b"0", b"1", b"\x98", b"\x93", b"Q", b"q\x00", b"\x94"),
    *(b"\x87", b"p0\n", b"r\x00\x00\x00\x00", b"\x82\x01", b"\xff"),
]


def _structured(seed: int, count: int) -> list[bytes]:
    """Pickles of values pushed and then used: names resolved and then called, set
    items on, appended to, hashed, iterated, built or handed to type checks."""
    rng = random.Random(seed)  # noqa: S311 - a reproducible corpus, not a secret
    samples = []
    for _ in range(count):
        segments = []
        for _ in range(rng.choice([1, 1, 2])):
            parts = [rng.choice([b"", b"\x80\x02", b"\x80\x04"])]
            for _ in range(rng.randrange(1, 10)):
                parts.append(rng.choice(_PUSHED if rng.random() < 0.6 else _USES))
            parts.append(b"." if rng.random() < 0.8 else b"")
            segments.append(b"".join(parts))
        samples.append(b"".join(segments))
    return samples


_PROPERTY_SAMPLES = _generated(152, 1500) + _structured(152, 1500)


@pytest.mark.parametrize("flavor", pickle_load.FLAVORS)
def test_the_interpreter_ends_each_pickle_where_the_unpickler_does(flavor: str) -> None:
    mismatched = [
        data
        for data in _PROPERTY_SAMPLES
        if not _agrees(
            flavor,  # type: ignore[arg-type]
            data,
            _oracle_walk(flavor, io.BytesIO(data), len(data)),
        )
    ]
    assert not mismatched, mismatched[:5]


_Z7 = b"\x00" * 7
_BYTEARRAY = b"\x96\x01" + _Z7 + b"a"
# Each opcode's corner where the C and pure-Python unpicklers part, or fail.
_EDGES = [
    *(b"}]Ns.", b"(]\x91.", b"(Nd.", b"(NNd.", b"I017\n.", b"I 5\n.", b"I1_0\n.", b"F1e400\n."),
    *(b"Finf\n.", b"F1_0\n.", b"F 1\n.", b"T\x01\x00\x00\x00a.", b"T\xff\xff\xff\xff."),
    *(b"\x8d\x01" + _Z7 + b"a.", _BYTEARRAY + b"\x98.", b"C\x01a\x98.", b"N\x98."),
    *(b"](NeK\x00Ns.", b"]K\x00Ns.", _BYTEARRAY + b"K\x00K\x05s.", _BYTEARRAY + b"K\x00M,\x01s."),
    *(b")K\x00Ns.", b"}(u.", b"}(Nu.", b"}(NNu.", b"N(u.", b"](e.", b"N(e.", b"](NNe."),
    *(_BYTEARRAY + b"(K\x01e.", _BYTEARRAY + b"(M,\x01e.", b"\x8f(N\x90.", b"\x8f(]\x90."),
    *(b"N(\x90.", b"(\x91(N\x90.", b"\x8f(\x90.", b"\x84\x01\x00\x00\x00.", b"(o.", b"N(o."),
    *(b"cos\nsystem\n}b.", b"N(NNtb.", b"N(N}tb.", b"N(N(K\x01K\x02dtb.", b"N(}Ntb.", b"Np-1\n."),
    *(b"cos\nsystem\n)}\x92.", b"cos\nsystem\n)(K\x01Nd\x92.", b"cos\nsystem\n)(Vk\nNd\x92."),
    *(b"cos\nsystem\n]R.", b"cos\nsystem\nNR.", b"Va b\nVc\n\x93.", b"Vos\nVsystem\n\x93)R."),
    *(b"N)\x81.", b"cos\nsystem\nN\x81.", b"\x95\x0a" + _Z7 + _frame(b"N") + b".", b"N\x88b."),
    *(b"P1\n)R.", b"NQ}b.", b"(iA\nB\n.", b"iA\nB\n.", b"(iA\nB", b"cA\n", b"c\n\n."),
    *(_frame(b"I12") + b"\n.", _frame(b"J\x01") + b"\x00\x00\x00.", b"\x95\x0a" + _Z7 + b"N."),
    *(b"\x80\x06N.", b"(0N.", b"1", b"N2\x86.", b"\x87.", b"(\x85.", b"\x97.", b"I\n."),
    *(b"\x95" + b"\xff" * 8, b"\x8b\x01\x00\x00\x00\x05.", b"\x8b\xff\xff\xff\xff."),
    *(b"\x8fK\x00Ns.", b"Ncos\nsystem\nb."),
    # What find_class returned, handed to each opcode that uses it.
    *(b"(K\x01\x85Nd.", b"(]\x85Nd.", b"(cos\nsystem\n\x85Nd.", b"((\x91Nd.", b"NNQb."),
    *(b"]Vk\nNs.", b"]cos\nsystem\nNs.", b"cos\nsystem\n(\x90.", b"cos\nsystem\n(N\x90."),
    *(b"cos\nsystem\ncos\nsystem\nR.", b"Ncos\nsystem\nR.", b"cos\nsystem\n)cos\nsystem\n\x92."),
    *(b"cos\nsystem\ncos\nsystem\n\x81.", b"N(Ncos\nsystem\ntb.", b"N(cos\nsystem\nNtb."),
    *(b"cos\nsystem\n\x98.", b"cos\nsystem\nQ.", b"Vos\ncos\nsystem\n\x93.", b"K\x01cos\nx\n\x93."),
    *(b"\x96\x01" + _Z7 + b"acos\nsystem\na.", b"cos\nsystem\n(e.", b"]cos\nsystem\n(K\x01u."),
]


@pytest.mark.parametrize("flavor", pickle_load.FLAVORS)
def test_the_interpreter_follows_each_unpickler_at_its_corners(flavor: str) -> None:
    for data in _EDGES:
        walk = _oracle_walk(flavor, io.BytesIO(data), len(data))
        assert _agrees(flavor, data, walk), data  # type: ignore[arg-type]


def _oracle(data: bytes, path: Path) -> tuple[bool, bool]:
    """Whether a loader resolves, and whether it calls, anything from ``data``.

    io.BytesIO for both unpicklers, and a buffered file, which the C unpickler peeks
    in: after a STOP inside a frame it resumes right after the STOP.
    """
    path.write_bytes(data)
    walks = [
        _oracle_walk(flavor, io.BytesIO(data), len(data), encoding)
        for flavor in _UNPICKLERS
        # torch.load passes "utf-8", np.load and pandas "latin1" (audit 2026-11-16 S4-02).
        for encoding in ("ASCII", "utf-8", "latin1", "bytes")
    ]
    with path.open("rb") as stream:
        walks.append(_oracle_walk("c", stream, len(data)))
    steps = [step for walk in walks for step in walk]
    return any(step[1] for step in steps), any(step[0] == "called" for step in steps)


def _differs(data: bytes) -> bool:
    """Whether a walk of either flavor, at any start the scanner reads, takes a step
    that some supported version takes differently."""
    for flavor in pickle_load.FLAVORS:
        budget = pickle_load.Budget(10**6, 10**6)
        pending, seen = [0], set()
        while pending:
            start = pending.pop()
            if start in seen:
                continue
            seen.add(start)
            for segment in pickle_load.load_segments(data, len(data), start, flavor, budget):
                if segment.differs:
                    return True
                pending.extend(segment.resumes)
    return False


def test_content_ratings_follow_what_the_unpicklers_do(tmp_path: Path) -> None:
    from nexus_symbiote.scanners.model import inspect_model_format

    (tmp_path / "models").mkdir()
    missed, flagged = [], []
    for data in _PROPERTY_SAMPLES:
        resolved, called = _oracle(data, tmp_path / "oracle.bin")
        for relative in ("models/x", "x.dat"):
            path = tmp_path / relative
            path.write_bytes(data)
            safety, explanation = inspect_model_format(path)
            critical = safety is UNSAFE
            if called and not critical:
                missed.append((data, relative, explanation))
            if critical and not resolved and not _differs(data):
                # Where versions differ, a call that another version reaches is rated.
                flagged.append((data, relative))
    assert not missed, missed[:5]
    assert not flagged, flagged[:5]


def _frame4(body: bytes) -> bytes:
    return b"\x80\x04\x95" + len(body).to_bytes(8, "little") + body


# A resolved object that the loader changes without calling it: builtins.__dict__["len"]
# = os.system, os.environ["LD_PRELOAD"] = ..., sys.path.append(...), sys.modules.update.
_STATE_CHANGES = {
    "dict-setitem": b"cbuiltins\n__dict__\nS'len'\ncos\nsystem\ns.",
    "dict-setitem-proto4": _frame4(
        b"\x8c\x08builtins\x8c\x08__dict__\x93\x8c\x03len\x8c\x02os\x8c\x06system\x93s."
    ),
    "environ-setitem": b"cos\nenviron\nS'LD_PRELOAD'\nS'/tmp/x.so'\ns.",
    "path-append": b"csys\npath\nS'/tmp/evil'\na.",
    "path-appends": b"csys\npath\n(S'/tmp/evil'\ne.",
    "modules-setitems": b"csys\nmodules\n(S'json'\ncos\nsystem\nu.",
    "set-additems": b"\x80\x04\x8c\x01m\x8c\x01s\x93(K\x01\x90.",
    "after-a-stop": b"N.cbuiltins\n__dict__\nS'len'\ncos\nsystem\ns.",
    "legacy-torch": _legacy_torch(None)[: -len(pickle.dumps(None, protocol=2))]
    + b"cbuiltins\n__dict__\nS'len'\ncos\nsystem\ns.",
    "hashed-key": b"(cos\nsystem\nNd.",
}


def _changes_what_it_resolved(data: bytes) -> bool:
    """Whether a real unpickler changes the object find_class returned, in a loop."""
    target: dict[str, object] = {}

    class _Target(list):  # type: ignore[type-arg]
        def __setitem__(self, key: object, value: object) -> None:
            target[str(key)] = value

        def add(self, item: object) -> None:
            target["added"] = item

        def __hash__(self) -> int:
            target["hashed"] = True
            return 0

        def __eq__(self, other: object) -> bool:
            return list.__eq__(self, other)

    resolved = _Target()

    class _Unpickler(pickle.Unpickler):
        def find_class(self, module: str, name: str) -> object:
            return resolved

    stream = io.BytesIO(data)
    for _ in range(8):
        try:
            _Unpickler(stream).load()
        except Exception:  # noqa: BLE001 - the stream fails where pickle.load does
            break
    return bool(target) or bool(len(resolved))


@pytest.mark.parametrize("data", _STATE_CHANGES.values(), ids=_STATE_CHANGES)
def test_a_pickle_that_changes_what_it_resolved_is_critical(tmp_path: Path, data: bytes) -> None:
    from nexus_symbiote.scanners.model import inspect_model_format

    # No REDUCE, OBJ, INST, NEWOBJ or BUILD: SETITEM(S), APPEND(S) and ADDITEMS on the
    # resolved object, or hashing it, run its methods all the same.
    assert _changes_what_it_resolved(data)
    relatives = ["models/x", "x.dat", "x.npy", "legacy.tar.dat"]
    (tmp_path / "models").mkdir()
    for relative in relatives:
        (tmp_path / relative).write_bytes(data)
        assert inspect_model_format(tmp_path / relative)[0] is UNSAFE, relative
    found = _components(tmp_path)
    assert {
        relative: found[relative].serialization_safety for relative in relatives
    } == dict.fromkeys(relatives, UNSAFE)


_RETURNS_A_NAME = {
    "text": b"cos\nsystem\n.",
    "proto4": _frame4(b"\x8c\x02os\x8c\x06system\x93."),
    "proto2-flaw": b"\x80\x02cos\nsystem\n\xff",
    "after-a-stop": b"N.cos\nsystem\n.",
    "popped": b"N.cos\nsystem\n0N.",
    "memoized": b"N.cos\nsystem\np0\n.",
}


@pytest.mark.parametrize("data", _RETURNS_A_NAME.values(), ids=_RETURNS_A_NAME)
def test_a_pickle_that_only_resolves_a_name_is_unknown(tmp_path: Path, data: bytes) -> None:
    # pickle.load imports the name and returns it, or stops, without using it.
    assert not _calls_anything(data)
    (tmp_path / "x.dat").write_bytes(data)
    component = _components(tmp_path)["x.dat"]
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_NAME_UNCALLED


def test_every_opcode_is_interpreted() -> None:
    # Any other byte is an invalid load key, where pickle.load stops.
    codes = {opcode.code.encode("latin-1")[0] for opcode in pickletools.opcodes}
    assert set(pickle_load._DISPATCH) == codes


# A call that only some supported CPython reaches, whatever version runs the scan,
# with the VERSION_DIFFERENCES entry it relies on.
_ONE_VERSION_CALLS = {
    # Base 10 from 3.14 only; both unpicklers fail '08' in base 0.
    "int-base-10": (b"I08\n0cos\nsystem\n)R.", "int-base"),
    "long-base-10": (b"L08L\n0cos\nsystem\n)R.", "int-base"),
    # Base 0 up to 3.13 only.
    "int-base-0": (b"I0x1f\n0cos\nsystem\n)R.", "int-base"),
    "long-base-0": (b"L0x1f\n0cos\nsystem\n)R.", "int-base"),
    # The C unpickler reads on past a frame's end before 3.13: from where it stands,
    # from a buffered file, or from the frame's end, from io.BytesIO.
    "frame-read-on": (_frame(b"I12") + b"\n0cos\nsystem\n)R.", "frame-bounds"),
    "frame-read-at-its-end": (_frame(b"Ix") + b"5\n0cos\nsystem\n)R.", "frame-bounds"),
    "frame-in-a-frame": (b"\x95\x0a" + _Z7 + _frame(b"N") + b"0cos\nsystem\n)R.", "frame-bounds"),
}


@pytest.mark.parametrize("data, difference", _ONE_VERSION_CALLS.values(), ids=_ONE_VERSION_CALLS)
def test_a_call_that_one_supported_version_reaches_is_critical(
    tmp_path: Path, data: bytes, difference: str
) -> None:
    assert difference in pickle_load.VERSION_DIFFERENCES
    differs = {
        key
        for flavor in pickle_load.FLAVORS
        for segment in pickle_load.load_segments(
            data, len(data), 0, flavor, pickle_load.Budget(10**6, 10**6)
        )
        for key in segment.differs
    }
    assert difference in differs
    (tmp_path / "models").mkdir()
    for relative in ("models/x", "x.dat"):
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == ["models/x", "x.dat"]
    assert all(component.serialization_safety is UNSAFE for component in found.values())


def test_a_reading_every_version_shares_reports_no_difference() -> None:
    for data in (b"I17\n.", b"L17L\n.", b"I00\n.", _frame(b"I12\n") + b".", b"I 5\n."):
        for flavor in pickle_load.FLAVORS:
            budget = pickle_load.Budget(10**6, 10**6)
            (segment,) = pickle_load.load_segments(data, len(data), 0, flavor, budget)
            assert segment.outcome == "stop", (data, flavor)
            assert not segment.differs, (data, flavor)


@pytest.mark.parametrize("module", [b"ev-il", b"e x", b"ev\xc3\xa9il"])
def test_a_global_cut_by_the_sample_that_may_import_is_unknown(
    tmp_path: Path, module: bytes
) -> None:
    # The module line starts three bytes before the sample ends. The unpicklers import
    # the module before they look the name up, and importlib imports `ev-il.py` too, so
    # a visible character that no identifier has does not make the load fail.
    start = MAX_PICKLE_INSPECTION_BYTES - 3
    data = b"S'" + b"a" * (start - 6) + b"'\n0" + b"c" + module + b"\nrun\n)R."
    assert data.index(module) == start
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / (module.decode() + ".py")).write_text("open('IMPORTED', 'w').write('yes')\nrun = len\n")
    (lab / "w.bin").write_bytes(data)
    subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import pickle; pickle.load(open('w.bin', 'rb'))"],
        cwd=lab,
        capture_output=True,
        env={"PYTHONPATH": str(lab), "PATH": os.defpath},
        check=False,
        timeout=60,
    )
    assert (lab / "IMPORTED").exists()
    root = tmp_path / "project"
    (root / "models").mkdir(parents=True)
    (root / "models" / "weights").write_bytes(data)
    found = _components(root)
    assert sorted(found) == ["models/weights"]
    assert found["models/weights"].serialization_safety is SerializationSafety.UNKNOWN


# Audit 2026-11-16 S4-02: STRING, BINSTRING and SHORT_BINSTRING decode by the loader's
# encoding. pickle.load's default "ASCII" stops at a byte over 0x7f, but torch.load
# passes "utf-8" and np.load(encoding="latin1") and pandas.read_pickle "latin1", and
# those go on to the call.
_CALL = b"cbuiltins\nexec\n(S'import builtins; builtins.HIT=1'\ntR."
_ENCODED_STRINGS = {
    "short-binstring-utf8": b"U\x02\xc3\xa90" + _CALL,
    "binstring-utf8": b"T\x02\x00\x00\x00\xc3\xa90" + _CALL,
    "string-utf8": b"S'\xc3\xa9'\n0" + _CALL,
    "short-binstring-latin1": b"U\x01\xff0" + _CALL,
    "proto2-short-binstring": b"\x80\x02U\x02\xc3\xa90" + _CALL,
    # Under encoding="bytes" the string is bytes, which READONLY_BUFFER takes.
    "readonly-buffer": b"\x80\x05U\x01m\x980" + _CALL,
}


def _runs_with(data: bytes, encoding: str) -> bool:
    called: list[object] = []

    class _Unpickler(pickle.Unpickler):
        def find_class(self, module: str, name: str) -> object:
            return lambda *args: called.append(args)

    try:
        _Unpickler(io.BytesIO(data), encoding=encoding).load()
    except Exception:  # noqa: BLE001, S110 - pickle.load stops at any exception
        pass
    return bool(called)


@pytest.mark.parametrize("data", _ENCODED_STRINGS.values(), ids=_ENCODED_STRINGS)
def test_a_call_after_a_string_another_encoding_reads_is_critical(
    tmp_path: Path, data: bytes
) -> None:
    assert not _runs_with(data, "ASCII")
    assert any(_runs_with(data, encoding) for encoding in ("utf-8", "latin1", "bytes"))
    differs = {
        key
        for flavor in pickle_load.FLAVORS
        for segment in pickle_load.load_segments(
            data, len(data), 0, flavor, pickle_load.Budget(10**6, 10**6)
        )
        for key in segment.differs
    }
    assert "string-encoding" in differs
    assert "string-encoding" in pickle_load.VERSION_DIFFERENCES
    (tmp_path / "models").mkdir()
    for relative in ("models/x", "x.dat"):
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert {relative: found[relative].serialization_safety for relative in found} == {
        "models/x": UNSAFE,
        "x.dat": UNSAFE,
    }


# Audit 2026-11-16 S4-03: torch's legacy persistent_load returns the object that a
# ("module", obj, source_file, source) id carries when the source fields are empty, so
# a BINPERSID of such a tuple puts what GLOBAL resolved back on the stack.
_PERSISTENT_MAIN = b"(S'module'\ncbuiltins\nexec\nNNtQ(S'import builtins; builtins.HIT=1'\ntR."


def _legacy_persistent_load(saved: object) -> object:
    assert isinstance(saved, tuple)
    if saved[0] == "module":
        return saved[1]
    raise RuntimeError(saved[0])


def _torch_legacy_runs(data: bytes) -> bool:
    called: list[object] = []

    class _Unpickler(pickle.Unpickler):
        def find_class(self, module: str, name: str) -> object:
            return lambda *args: called.append(args)

    stream = io.BytesIO(data)
    try:
        for _ in range(3):
            _Unpickler(stream, encoding="utf-8").load()
        unpickler = _Unpickler(stream, encoding="utf-8")
        unpickler.persistent_load = _legacy_persistent_load  # type: ignore[assignment]
        unpickler.load()
    except Exception:  # noqa: BLE001, S110 - torch.load stops at any exception
        pass
    return bool(called)


_PERSISTENT_CALLS = {
    "text-main": _legacy_torch(None)[: -len(pickle.dumps(None, protocol=2))] + _PERSISTENT_MAIN,
    "binary-main": _legacy_torch(None)[: -len(pickle.dumps(None, protocol=2))]
    + b"\x80\x02"
    + _PERSISTENT_MAIN,
}


@pytest.mark.parametrize("data", _PERSISTENT_CALLS.values(), ids=_PERSISTENT_CALLS)
def test_an_object_torch_persistent_load_returns_is_used_as_resolved(
    tmp_path: Path, data: bytes
) -> None:
    assert _torch_legacy_runs(data)
    (tmp_path / "checkpoints").mkdir()
    for relative in ("checkpoints/x", "x.dat"):
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert {relative: found[relative].serialization_safety for relative in found} == {
        "checkpoints/x": UNSAFE,
        "x.dat": UNSAFE,
    }


def test_a_storage_id_stays_inert() -> None:
    # Any other id is a storage, which runs nothing: a REDUCE of it fails.
    data = b"(S'storage'\ncbuiltins\nexec\nNNtQ)R."
    for flavor in pickle_load.FLAVORS:
        (segment,) = pickle_load.load_segments(
            data, len(data), 0, flavor, pickle_load.Budget(10**6, 10**6)
        )
        assert segment.outcome == "error", flavor
