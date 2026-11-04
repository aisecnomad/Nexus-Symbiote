"""Adversarial tests for BOM-supplied artifact paths."""

import hashlib
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import ModelComponent, PromptComponent
from nexus_symbiote.utils import confined, crypto
from nexus_symbiote.utils.confined import (
    ConfinedCollection,
    descriptor_binding,
    hash_confined_file,
)
from nexus_symbiote.validators.integrity import IntegrityValidator


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def validate_path(root: Path, path: str, expected: str):
    bom = AIBOM()
    bom.add_component(
        PromptComponent(
            bom_ref="prompt:test", name="prompt", source_path=path, content_hash=expected
        )
    )
    return IntegrityValidator().validate(bom, root)


def test_relative_and_absolute_paths_within_root(tmp_path: Path) -> None:
    f = tmp_path / "model.bin"
    f.write_bytes(b"model")
    for path in ("model.bin", str(f)):
        report = validate_path(tmp_path, path, digest(b"model"))
        assert report.is_valid
        assert report.hashes_verified == 1


def test_parent_absolute_and_symlink_escape_fail(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"external-canary")
    (root / "link").symlink_to(outside)
    (root / "parent-link").symlink_to(tmp_path, target_is_directory=True)
    for path in ("../outside", str(outside), "link", "parent-link/outside", "missing"):
        report = validate_path(root, path, digest(b"external-canary"))
        assert not report.is_valid
        assert report.hashes_failed == 1
        assert digest(b"external-canary") not in str(report.to_dict())


def test_missing_project_or_source_fails_verification(tmp_path: Path) -> None:
    bom = AIBOM()
    bom.add_component(
        ModelComponent(bom_ref="model:test", name="model", hashes={"sha256": digest(b"data")})
    )
    for root in (None, tmp_path):
        result = IntegrityValidator().validate(bom, root)
        assert not result.is_valid
        assert result.hashes_failed == 1


def test_prompt_missing_file_fails_verification(tmp_path: Path) -> None:
    bom = AIBOM()
    bom.add_component(
        PromptComponent(
            bom_ref="prompt:1", name="prompt", source_path="missing", content_hash=digest(b"prompt")
        )
    )
    result = IntegrityValidator().validate(bom, tmp_path)
    assert not result.is_valid
    assert result.hashes_failed == 1


def test_hash_limit_and_algorithm_are_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "model.bin").write_bytes(b"data")
    monkeypatch.setattr("nexus_symbiote.utils.confined.MAX_HASH_BYTES", 3)
    with pytest.raises(OSError):
        hash_confined_file(tmp_path, "model.bin")
    with pytest.raises(OSError):
        hash_confined_file(tmp_path, "model.bin", "md5")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO required")
def test_fifo_rejected_without_blocking(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(OSError):
        hash_confined_file(tmp_path, "pipe")


def test_descriptor_binding_detects_rename_over_without_timestamp_change(tmp_path):
    """A rename-over inside one coarse timestamp tick must still change the binding."""
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"original")
    fd = os.open(target, os.O_RDONLY)
    try:
        before = os.fstat(fd)
        replacement = tmp_path / "replacement.bin"
        replacement.write_bytes(b"replaced")
        # Pin the replacement's timestamps to the original so size/mtime/ctime
        # alone cannot distinguish the two inodes.
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        replacement.replace(target)
        after = os.fstat(fd)
        assert after.st_nlink == 0
        assert descriptor_binding(before) != descriptor_binding(after)
        # Pathname-based observation now sees different bytes than the descriptor.
        assert target.read_bytes() == b"replaced"
        assert os.read(fd, 16) == b"original"
    finally:
        os.close(fd)


def test_descriptor_binding_tracks_link_count(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"data")
    before = os.stat(target)
    (tmp_path / "link.bin").hardlink_to(target)
    assert descriptor_binding(before) != descriptor_binding(os.stat(target))


def test_path_replacement_during_confined_read_is_refused(tmp_path: Path) -> None:
    (tmp_path / "model.bin").write_bytes(b"original")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement")
    failures: list[str] = []
    with (
        ConfinedCollection(tmp_path, failures) as files,
        pytest.raises(OSError, match="changed during collection"),
        files.open_regular("model.bin") as stream,
    ):
        stream.read(64)
        replacement.replace(tmp_path / "model.bin")
    assert failures


def test_path_identity_tracks_the_object_not_its_timestamps(tmp_path: Path) -> None:
    target = tmp_path / "model.safetensors"
    target.write_bytes(b"original")
    with ConfinedCollection(tmp_path, []) as files:
        before = files.path_identity(target)
        assert before is not None
        assert before == files.path_identity("model.safetensors")
        target.write_bytes(b"edited!!")
        target.touch()
        assert files.path_identity(target) == before


def test_path_identity_observes_replacement_and_removal(tmp_path: Path) -> None:
    target = tmp_path / "model.safetensors"
    target.write_bytes(b"original")
    with ConfinedCollection(tmp_path, []) as files:
        before = files.path_identity(target)
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"not a tensor container")
        replacement.replace(target)
        assert files.path_identity(target) not in (None, before)
        target.unlink()
        assert files.path_identity(target) is None


def test_path_identity_refuses_outside_missing_and_symlinked_paths(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "real.bin").write_bytes(b"x")
    (root / "link.bin").symlink_to(root / "real.bin")
    with ConfinedCollection(root, []) as files:
        assert files.path_identity("../outside") is None
        assert files.path_identity(tmp_path) is None
        assert files.path_identity("missing.bin") is None
        assert files.path_identity("link.bin") != files.path_identity("real.bin")


@pytest.fixture
def unchanging_descriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Model a filesystem whose replaced inode is never unlinked or restamped.

    On overlayfs, renaming a file over one that lives in a lower layer leaves
    the open descriptor's link count, size and timestamps untouched, so only
    the pathname's identity can reveal the swap.
    """
    monkeypatch.setattr(confined, "descriptor_binding", lambda info: ())
    monkeypatch.setattr(crypto, "descriptor_binding", lambda info: ())


def _swap_on_first_read(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    real_read = os.read
    swapped = False

    def read(fd: int, size: int) -> bytes:
        nonlocal swapped
        if not swapped:
            swapped = True
            replacement = target.with_name("replacement")
            replacement.write_bytes(b"replaced bytes")
            replacement.replace(target)
        return real_read(fd, size)

    monkeypatch.setattr(os, "read", read)


@pytest.mark.usefixtures("unchanging_descriptor")
@pytest.mark.parametrize("operation", ["read_bytes", "hash_file"])
def test_pathname_must_still_name_the_descriptor_after_a_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    target = tmp_path / "config.json"
    target.write_bytes(b'{"servers": {}}')
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        _swap_on_first_read(monkeypatch, target)
        assert getattr(files, operation)("config.json") is None
    assert failures


@pytest.mark.usefixtures("unchanging_descriptor")
def test_stream_refuses_a_swap_the_descriptor_cannot_see(tmp_path: Path) -> None:
    (tmp_path / "model.bin").write_bytes(b"original")
    failures: list[str] = []
    with (
        ConfinedCollection(tmp_path, failures) as files,
        pytest.raises(OSError, match="changed during collection"),
        files.open_regular("model.bin") as stream,
    ):
        stream.read(64)
        (tmp_path / "replacement").write_bytes(b"replacement")
        (tmp_path / "replacement").replace(tmp_path / "model.bin")
    assert failures


@pytest.mark.usefixtures("unchanging_descriptor")
def test_stream_refuses_an_a_b_a_swap(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"A")
    target.rename(tmp_path / "saved")
    target.write_bytes(b"B")
    failures: list[str] = []
    with (
        ConfinedCollection(tmp_path, failures) as files,
        pytest.raises(OSError, match="changed during collection"),
        files.open_regular("model.bin") as stream,
    ):
        assert stream.read(8) == b"B"
        (tmp_path / "saved").replace(target)
    assert failures


@pytest.mark.usefixtures("unchanging_descriptor")
def test_signed_artifact_hash_refuses_a_swapped_pathname(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"original")
    assert crypto.compute_file_hash(target) == digest(b"original")
    real_open = crypto.open_regular_file

    def open_then_swap(path: Path):  # type: ignore[no-untyped-def]
        stream = real_open(path)
        (tmp_path / "replacement").write_bytes(b"replacement")
        (tmp_path / "replacement").replace(target)
        return stream

    monkeypatch.setattr(crypto, "open_regular_file", open_then_swap)
    assert crypto.compute_file_hash(target) is None


def test_non_utf8_file_names_are_not_collected(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    try:
        name = os.path.join(os.fsencode(project), b"agent\xff.py")
        with open(name, "w") as stream:
            stream.write("from mcp import ClientSession\n")
    except OSError:
        pytest.skip("filesystem rejects file names that are not valid UTF-8")
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "--scanner",
            "mcp",
            "-o",
            str(output),
        ],
    )
    assert run.exit_code == 0, run.output
    completeness = AIBOM.load(output).metadata.completeness
    assert completeness is not None
    assert ".: file name is not valid UTF-8" in completeness.scan_failures
