"""Adversarial tests for BOM-supplied artifact paths."""

import hashlib
import os
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import file_invariance
from nexus_symbiote.core.models import ModelComponent, PromptComponent
from nexus_symbiote.utils.confined import ConfinedCollection, hash_confined_file
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


def test_file_invariance_tracks_link_count(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"data")
    before = os.stat(target)
    (tmp_path / "link.bin").hardlink_to(target)
    after = os.stat(target)
    # The link count is the first member of the invariance tuple: a rename-over
    # drops it even on filesystems that do not refresh change time.
    assert file_invariance(before)[0] != file_invariance(after)[0]
    assert file_invariance(before) != file_invariance(after)


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
        # Swap the pathname while the pinned descriptor is still open.
        replacement.replace(tmp_path / "model.bin")
    assert failures
