"""Compression suffixes that joblib and pandas choose by name keep a pickle in the inventory."""

from __future__ import annotations

import gzip
import io
import lzma
import pickle
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.scanners.model import ModelScanner


class _Payload:
    def __reduce__(self) -> tuple[object, tuple[str]]:  # harmless: the scanner never unpickles
        return (len, ("x",))


RAW = pickle.dumps(_Payload(), protocol=4)


def _tar() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("frame.pkl")
        info.size = len(RAW)
        archive.addfile(info, io.BytesIO(RAW))
    return buffer.getvalue()


def _zip(member: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(member, data)
    return buffer.getvalue()


CASES: dict[str, Callable[[], bytes]] = {
    "clf.joblib.z": lambda: zlib.compress(RAW),
    "clf.pkl.z": lambda: zlib.compress(RAW),
    "clf.joblib.lz4": lambda: b"\x04\x22\x4d\x18\x64\x40\xa7" + RAW,
    "frame.pkl.zip": lambda: _zip("frame.pkl", RAW),
    "frame.pkl.tar.gz": lambda: gzip.compress(_tar()),
    "frame.pkl.tar.xz": lambda: lzma.compress(_tar()),
    "nested/dir/My.Model.PKL.Tar.BZ2": lambda: gzip.compress(_tar()),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_compressed_pickle_outside_a_model_directory_is_inventoried_as_code_executing(
    tmp_path: Path, name: str
) -> None:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(CASES[name]())
    models = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert list(models) == [name]
    assert models[name].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION


@pytest.mark.parametrize(
    "name",
    [
        "notes.txt.gz",
        "data.csv.zip",
        "site.zip",
        "release.tar.gz",
        "logs.tar.z",
        "a.b.c.pkl.x",
        # Two wrappers is the most a loader unwraps by name.
        "frame.pkl.tar.gz.z",
    ],
)
def test_wrapped_names_without_a_pickle_family_suffix_are_not_inventoried(
    tmp_path: Path, name: str
) -> None:
    (tmp_path / name).write_bytes(gzip.compress(b"plain text"))
    assert not ModelScanner().scan(tmp_path).components


@pytest.mark.parametrize(
    "member", ["frame.pkl.z", "clf.joblib.lz4", "frame.pkl.zip", "x.pkl.tar.gz"]
)
def test_a_zip_member_under_a_loader_compression_name_is_a_pickle_member(
    tmp_path: Path, member: str
) -> None:
    (tmp_path / "bundle.npz").write_bytes(_zip(member, b"not a pickle"))
    components = ModelScanner().scan(tmp_path).components
    assert [c.source_path for c in components] == ["bundle.npz"]
    assert components[0].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION


@pytest.mark.parametrize("member", ["notes.txt.zip", "site.tar.gz", "frame.pkl.tar.gz.z"])
def test_a_zip_member_without_a_pickle_family_name_stays_uninventoried(
    tmp_path: Path, member: str
) -> None:
    (tmp_path / "bundle.npz").write_bytes(_zip(member, b"not a pickle"))
    assert not ModelScanner().scan(tmp_path).components


@pytest.mark.parametrize("name", ["fn.cloudpickle", "fn.cloudpickle.gz"])
def test_a_cloudpickle_name_is_pickle_family_and_rated_by_content(
    tmp_path: Path, name: str
) -> None:
    data = gzip.compress(RAW) if name.endswith(".gz") else RAW
    (tmp_path / name).write_bytes(data)
    (tmp_path / "inert.cloudpickle").write_bytes(b"\0" * 64)
    models = {c.source_path: c for c in ModelScanner().scan(tmp_path).components}
    assert models[name].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    # No pickle evidence in the content: unknown, not code-executing by name alone.
    assert models["inert.cloudpickle"].serialization_safety is SerializationSafety.UNKNOWN
