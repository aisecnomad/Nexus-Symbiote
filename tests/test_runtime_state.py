"""The state store never mistakes lost or replaced state for first use."""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from datetime import UTC, datetime, timedelta

import pytest

from nexus_symbiote.runtime import (
    NONCE_RETENTION,
    AuthorizationError,
    StateStore,
    TrustStatus,
    digest,
)
from tests.test_runtime_authorization import NOW, fixture, invoke


def test_missing_state_file_is_refused_and_not_created(tmp_path):
    path = tmp_path / "state.sqlite"
    with pytest.raises(AuthorizationError, match="initialize") as missing:
        StateStore(path)
    assert missing.value.reason == "state-missing"
    assert not path.exists()


def test_initialize_creates_an_owner_only_store_and_refuses_an_existing_file(tmp_path):
    path = tmp_path / "private" / "state.sqlite"
    previous = os.umask(0)
    try:
        store = StateStore.initialize(path)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert len(store.store_id) == 32
    assert StateStore(path).store_id == store.store_id
    assert StateStore.initialize(tmp_path / "other.sqlite").store_id != store.store_id
    with pytest.raises(AuthorizationError, match="already exists") as exists:
        StateStore.initialize(path)
    assert exists.value.reason == "state-invalid"


@pytest.mark.parametrize("kind", ["symlink", "directory", "empty", "foreign"])
def test_unsafe_or_uninitialized_paths_are_refused(tmp_path, kind):
    path = tmp_path / "state.sqlite"
    if kind == "symlink":
        StateStore.initialize(tmp_path / "real.sqlite")
        path.symlink_to(tmp_path / "real.sqlite")
    elif kind == "directory":
        path.mkdir()
    elif kind == "empty":
        path.touch()
    else:
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE unrelated (x)")
    expected, message = {
        "symlink": ("state-invalid", "symlink"),
        "directory": ("state-invalid", "regular file"),
        "empty": ("state-missing", "not initialized"),
        "foreign": ("state-missing", "not initialized"),
    }[kind]
    with pytest.raises(AuthorizationError, match=message) as refused:
        StateStore(path)
    assert refused.value.reason == expected


def test_symlinked_path_is_refused_by_initialize_too(tmp_path):
    (tmp_path / "target").mkdir()
    link = tmp_path / "state.sqlite"
    link.symlink_to(tmp_path / "target" / "state.sqlite")
    with pytest.raises(AuthorizationError) as refused:
        StateStore.initialize(link)
    assert refused.value.reason == "state-invalid"
    assert not (tmp_path / "target" / "state.sqlite").exists()


def test_state_removed_while_running_denies_instead_of_starting_empty(tmp_path):
    values = list(fixture(tmp_path))
    assert invoke(values) == "executed"
    (tmp_path / "state.sqlite").unlink()
    values[5] = values[5].model_copy(update={"nonce": "f" * 32})
    with pytest.raises(AuthorizationError) as unavailable:
        invoke(values)
    assert unavailable.value.reason == "state-unavailable"
    assert not (tmp_path / "state.sqlite").exists()
    assert len(values[-1]) == 1


def test_opening_restricts_a_group_readable_store(tmp_path):
    path = tmp_path / "state.sqlite"
    StateStore.initialize(path)
    path.chmod(0o644)
    StateStore(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_expired_nonces_are_pruned_from_the_store_clock(tmp_path):
    store = StateStore.initialize(tmp_path / "state.sqlite")
    clock = NOW
    store.record(
        (),
        "early-nonce-000000",
        tenant="acme",
        not_after=clock - NONCE_RETENTION - timedelta(seconds=1),
        now=clock,
    )
    store.record(
        (),
        "recent-nonce-00000",
        tenant="acme",
        not_after=clock - NONCE_RETENTION + timedelta(days=1),
        now=clock,
    )
    with sqlite3.connect(tmp_path / "state.sqlite") as db:
        db.execute("INSERT INTO tenant_nonces(tenant, nonce) VALUES ('acme', 'legacy-row-0000000')")
    store.record(
        (),
        "later-nonce-000000",
        tenant="acme",
        not_after=clock + timedelta(minutes=5),
        now=clock,
    )
    with sqlite3.connect(tmp_path / "state.sqlite") as db:
        kept = {row[0] for row in db.execute("SELECT nonce FROM tenant_nonces")}
    assert kept == {"recent-nonce-00000", "legacy-row-0000000", "later-nonce-000000"}


def test_a_presented_expiry_cannot_prune_another_tenants_nonce(tmp_path):
    store = StateStore.initialize(tmp_path / "state.sqlite")
    clock = NOW
    store.record(
        (),
        "other-tenant-nonce",
        tenant="other",
        not_after=clock - timedelta(days=1),
        now=clock,
    )
    store.record(
        (),
        "presented-nonce-000",
        tenant="acme",
        not_after=clock + timedelta(minutes=5),
        now=clock,
    )
    with pytest.raises(AuthorizationError, match="5 minutes ahead") as refused:
        store.record(
            (),
            "future-nonce-00000",
            tenant="acme",
            not_after=clock + timedelta(minutes=6),
            now=clock,
        )
    assert refused.value.reason == "approval-lifetime-exceeds-policy"
    with sqlite3.connect(tmp_path / "state.sqlite") as db:
        kept = {row[0] for row in db.execute("SELECT nonce FROM tenant_nonces")}
    assert kept == {"other-tenant-nonce", "presented-nonce-000"}


@pytest.mark.parametrize(
    "not_after",
    [
        lambda: datetime.now(UTC) - NONCE_RETENTION - timedelta(minutes=1),
        lambda: NOW + timedelta(minutes=4),
    ],
    ids=["stale-expiry", "caller-on-an-old-clock"],
)
def test_a_nonce_recorded_without_a_clock_cannot_be_replayed(tmp_path, not_after):
    # The prune ran from the wall clock after the insert, so an expiry more than the
    # retention window behind it deleted the row just written and the same nonce was
    # accepted again.
    store = StateStore.initialize(tmp_path / "state.sqlite")
    expiry = not_after()
    store.record((), "stale-nonce-000000", tenant="acme", not_after=expiry)
    with pytest.raises(AuthorizationError) as replayed:
        store.record((), "stale-nonce-000000", tenant="acme", not_after=expiry)
    assert replayed.value.reason == "approval-replayed"


def test_representing_the_recorded_trust_status_takes_no_write_lock(tmp_path):
    values = fixture(tmp_path)
    gateway, status = values[0], values[4]
    signers = {"a" * 64}
    gateway.state.accept_trust_status(status, signers)
    with sqlite3.connect(tmp_path / "state.sqlite", isolation_level=None) as holder:
        holder.execute("BEGIN IMMEDIATE")
        try:
            started = time.monotonic()
            head = gateway.state.accept_trust_status(status, signers)
            assert time.monotonic() - started < 5
        finally:
            holder.execute("ROLLBACK")
    assert head == ("trust:acme", 1, digest(status.model_dump(mode="json")))


def test_snapshot_heads_advance_only_through_snapshot_scopes(tmp_path):
    store = StateStore.initialize(tmp_path / "state.sqlite")
    with pytest.raises(AuthorizationError) as refused:
        store.advance_snapshot("trust:acme", 99, "sha256:" + "0" * 64)
    assert refused.value.reason == "configuration-invalid"


def test_older_or_forked_heads_are_refused_without_the_write_lock(tmp_path):
    store = StateStore.initialize(tmp_path / "state.sqlite")
    scope = "snapshot:" + digest(["acme", "prod", "agent:triage"])
    store.advance_snapshot(scope, 2, "sha256:" + "2" * 64)
    status = TrustStatus(
        tenant="acme", serial=2, not_before=NOW, not_after=NOW + timedelta(minutes=5)
    )
    signers = {"a" * 64}
    store.accept_trust_status(status, signers)
    attempts = [
        (lambda: store.advance_snapshot(scope, 1, "sha256:" + "1" * 64), "snapshot-superseded"),
        (lambda: store.advance_snapshot(scope, 2, "sha256:" + "3" * 64), "snapshot-fork"),
        (
            lambda: store.accept_trust_status(status.model_copy(update={"serial": 1}), signers),
            "trust-rollback",
        ),
        (
            lambda: store.accept_trust_status(
                status.model_copy(update={"not_after": NOW + timedelta(minutes=6)}), signers
            ),
            "trust-fork",
        ),
    ]
    with sqlite3.connect(tmp_path / "state.sqlite", isolation_level=None) as holder:
        holder.execute("BEGIN IMMEDIATE")
        try:
            for attempt, expected in attempts:
                started = time.monotonic()
                with pytest.raises(AuthorizationError) as refused:
                    attempt()
                assert refused.value.reason == expected
                assert time.monotonic() - started < 5
        finally:
            holder.execute("ROLLBACK")
