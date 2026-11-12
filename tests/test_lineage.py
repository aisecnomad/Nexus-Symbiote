from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.lineage import DataVersion, HostedModelIdentity, LineageIndex
from nexus_symbiote.runtime import HostedModelAttestation, digest, key_id, sign_contract

NOW = datetime.now(UTC)
HASH = "sha256:" + "a" * 64


def version(name, kind="source", parents=(), **changes):
    return DataVersion(
        id=name,
        kind=kind,
        tenant="acme",
        content_digest=HASH,
        parents=parents,
        acl_revision="v1",
        allowed_principals=("reader",),
        **changes,
    )


def test_withdrawal_invalidates_all_descendants():
    index = LineageIndex(
        "acme",
        (
            version("source"),
            version("chunk", "chunk", ("source",)),
            version("index", "index", ("chunk",)),
            version("memory", "memory", ("index",), writer="agent"),
        ),
    )
    record = index.retrieve(
        ("memory",),
        principal="reader",
        acl_revision="v1",
        observed_at=NOW,
        read_watermark="commit:4",
    )
    assert record.source_versions == ("memory",) and record.source_digests == (HASH,)
    assert set(index.withdraw("source")) == {"source", "chunk", "index", "memory"}
    with pytest.raises(PermissionError):
        index.retrieve(
            ("memory",),
            principal="reader",
            acl_revision="v1",
            observed_at=NOW,
            read_watermark="commit:5",
        )


def test_acl_revocation_applies_through_derived_records():
    index = LineageIndex("acme", (version("source"), version("chunk", "chunk", ("source",))))
    index.update_acl("source", revision="v2", principals=())
    with pytest.raises(PermissionError):
        index.retrieve(
            ("chunk",),
            principal="reader",
            acl_revision="v1",
            observed_at=NOW,
            read_watermark="commit:2",
        )


def test_cross_tenant_and_missing_ancestry_rejected():
    with pytest.raises(ValueError):
        LineageIndex("other", (version("source"),))
    with pytest.raises(ValueError):
        LineageIndex("acme", (version("chunk", "chunk", ("missing",)),))


def test_alias_is_not_cryptographically_pinned_and_attestation_must_verify():
    identity = HostedModelIdentity(
        provider="provider",
        endpoint="https://models.example.test",
        requested_alias="latest",
        observed_at=NOW,
    )
    assert not identity.immutable_identity_established
    key = Ed25519PrivateKey.generate()
    statement = HostedModelAttestation(
        provider=identity.provider,
        endpoint=identity.endpoint,
        requested_alias="latest",
        resolved_revision="rev123",
        not_before=NOW - timedelta(seconds=1),
        not_after=NOW + timedelta(hours=1),
    )
    envelope = sign_contract(statement, "model", (key,))
    claimed = HostedModelIdentity(
        **{
            **identity.model_dump(),
            "identity_assurance": "provider-attested",
            "revision": "rev123",
            "evidence_digest": digest(envelope.model_dump(mode="json", by_alias=True)),
        }
    )
    assert not claimed.immutable_identity_established
    claimed.verify_attestation(envelope, {key_id(key.public_key()): key.public_key()}, now=NOW)
    assert claimed.immutable_identity_established
    assert not claimed.identity_is_verified(now=statement.not_before - timedelta(microseconds=1))
    assert not claimed.identity_is_verified(now=NOW - timedelta(microseconds=1))
    assert claimed.identity_is_verified(now=NOW)
    assert claimed.identity_is_verified(now=statement.not_after - timedelta(microseconds=1))
    assert not claimed.identity_is_verified(now=statement.not_after)
    assert not claimed.model_copy(update={"revision": "rev999"}).immutable_identity_established
    assert not claimed.identity_is_verified(now=NOW + timedelta(hours=2))
    restored = HostedModelIdentity.model_validate(claimed.model_dump(mode="json"))
    assert not restored.immutable_identity_established
    with pytest.raises(ValueError):
        claimed.verify_attestation(envelope, {}, now=NOW)
    assert not claimed.immutable_identity_established


def test_cached_hosted_identity_respects_default_clock(monkeypatch):
    import nexus_symbiote.lineage as lineage

    future = NOW + timedelta(days=1)
    key = Ed25519PrivateKey.generate()
    statement = HostedModelAttestation(
        provider="provider",
        endpoint="https://models.example.test",
        requested_alias="latest",
        resolved_revision="rev123",
        not_before=future - timedelta(seconds=1),
        not_after=future + timedelta(hours=1),
    )
    envelope = sign_contract(statement, "model", (key,))
    identity = HostedModelIdentity(
        provider=statement.provider,
        endpoint=statement.endpoint,
        requested_alias=statement.requested_alias,
        revision=statement.resolved_revision,
        identity_assurance="provider-attested",
        evidence_digest=digest(envelope.model_dump(mode="json", by_alias=True)),
        observed_at=future,
    )
    identity.verify_attestation(envelope, {key_id(key.public_key()): key.public_key()}, now=future)

    class RolledBackClock:
        @staticmethod
        def now(tz):
            return NOW

    monkeypatch.setattr(lineage, "datetime", RolledBackClock)
    assert not identity.identity_is_verified()
    assert not identity.immutable_identity_established
