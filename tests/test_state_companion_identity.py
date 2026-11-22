import os

import pytest

from nexus_symbiote.runtime import AuthorizationError, StateStore


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_an_inert_hardlinked_companion_is_refused_before_open(tmp_path, suffix):
    path = tmp_path / "state.sqlite"
    StateStore.initialize(path)
    other = tmp_path / "empty-fixture"
    other.write_bytes(b"")
    os.link(other, path.with_name(path.name + suffix))
    with pytest.raises(AuthorizationError, match="journal") as refused:
        StateStore(path)
    assert refused.value.reason == "state-invalid"


@pytest.mark.parametrize("mode", [0o620, 0o602])
def test_an_empty_companion_writable_by_others_is_refused(tmp_path, mode):
    path = tmp_path / "state.sqlite"
    StateStore.initialize(path)
    companion = path.with_name(path.name + "-journal")
    companion.write_bytes(b"")
    companion.chmod(mode)
    with pytest.raises(AuthorizationError, match="journal") as refused:
        StateStore(path)
    assert refused.value.reason == "state-invalid"
