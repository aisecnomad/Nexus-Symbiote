"""Identity and data-lineage evidence without inferring unavailable guarantees."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, PrivateAttr, model_validator

from nexus_symbiote.runtime import (
    Contract,
    Envelope,
    HostedModelAttestation,
    _window,
    digest,
    verify_contract,
)


class HostedModelIdentity(Contract):
    provider: str
    endpoint: str
    requested_alias: str
    revision: str | None = None
    identity_assurance: Literal["alias-only", "provider-reported", "provider-attested"] = (
        "alias-only"
    )
    evidence_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    observed_at: datetime
    _verified_digest: str | None = PrivateAttr(default=None)
    _verified_until: datetime | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def evidence_requirements(self) -> HostedModelIdentity:
        if self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.identity_assurance != "alias-only" and not self.revision:
            raise ValueError("a reported/attested identity requires a revision")
        if self.identity_assurance == "provider-attested" and not self.evidence_digest:
            raise ValueError("attestation claim requires evidence digest")
        return self

    @property
    def immutable_identity_established(self) -> bool:
        return self.identity_is_verified()

    def identity_is_verified(self, *, now: datetime | None = None) -> bool:
        timestamp = now or datetime.now(UTC)
        return bool(
            timestamp.utcoffset() is not None
            and self.identity_assurance == "provider-attested"
            and self._verified_digest == digest(self.model_dump(mode="json"))
            and self._verified_until is not None
            # Verification binds the observation inside the signed validity window.
            # Cached evidence cannot establish an identity before that observation,
            # including when the clock moves backwards after verification.
            and self.observed_at <= timestamp < self._verified_until
        )

    def verify_attestation(
        self, envelope: Envelope, trusted_keys: Mapping[str, Ed25519PublicKey], *, now: datetime
    ) -> None:
        self._verified_digest = None
        self._verified_until = None
        contract, _ = verify_contract(envelope, "model", trusted_keys)
        if not isinstance(contract, HostedModelAttestation):
            raise ValueError("expected hosted-model attestation")
        _window(contract, now, timedelta(hours=24))
        if not contract.not_before <= self.observed_at <= now:
            raise ValueError("observation is outside the attested window or in the future")
        expected = (self.provider, self.endpoint, self.requested_alias, self.revision)
        actual = (
            contract.provider,
            contract.endpoint,
            contract.requested_alias,
            contract.resolved_revision,
        )
        if (
            actual != expected
            or digest(envelope.model_dump(mode="json", by_alias=True)) != self.evidence_digest
        ):
            raise ValueError("hosted-model attestation subject mismatch")
        if self.identity_assurance == "provider-attested":
            self._verified_digest = digest(self.model_dump(mode="json"))
            self._verified_until = contract.not_after


class DataVersion(Contract):
    id: str
    tenant: str
    kind: Literal["source", "chunk", "index", "cache", "memory"]
    content_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    parents: tuple[str, ...] = ()
    transformation_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    embedding_revision: str | None = None
    acl_revision: str
    allowed_principals: tuple[str, ...]
    writer: str | None = None
    withdrawn: bool = False


class RetrievalRecord(Contract):
    tenant: str
    principal: str
    observed_at: datetime
    source_versions: tuple[str, ...]
    source_digests: tuple[str, ...]
    acl_revisions: tuple[str, ...]
    read_watermark: str


class LineageIndex:
    """Tenant-local immutable version graph with cascading source withdrawal."""

    def __init__(self, tenant: str, versions: tuple[DataVersion, ...] = ()) -> None:
        self.tenant = tenant
        self.versions: dict[str, DataVersion] = {}
        pending = list(versions)
        while pending:
            available = [v for v in pending if all(p in self.versions for p in v.parents)]
            if not available:
                raise ValueError("lineage contains missing parents or a cycle")
            for value in available:
                self.add(value)
                pending.remove(value)

    def add(self, value: DataVersion) -> None:
        if value.tenant != self.tenant or value.id in self.versions:
            raise ValueError("cross-tenant or duplicate lineage version")
        if value.id in value.parents or any(p not in self.versions for p in value.parents):
            raise ValueError("missing or cyclic parent")
        if value.kind != "source" and not value.parents:
            raise ValueError("derived records require parent evidence")
        if any(self.versions[p].withdrawn for p in value.parents):
            raise ValueError("cannot derive from withdrawn records")
        self.versions[value.id] = value

    def withdraw(self, source_id: str) -> tuple[str, ...]:
        if source_id not in self.versions:
            raise KeyError(source_id)
        queue = deque([source_id])
        affected: set[str] = set()
        while queue:
            current = queue.popleft()
            if current in affected:
                continue
            affected.add(current)
            self.versions[current] = self.versions[current].model_copy(update={"withdrawn": True})
            queue.extend(v.id for v in self.versions.values() if current in v.parents)
        return tuple(sorted(affected))

    def update_acl(self, version: str, *, revision: str, principals: tuple[str, ...]) -> None:
        current = self.versions[version]
        self.versions[version] = current.model_copy(
            update={"acl_revision": revision, "allowed_principals": principals}
        )

    def retrieve(
        self,
        ids: tuple[str, ...],
        *,
        principal: str,
        acl_revision: str,
        observed_at: datetime,
        read_watermark: str,
    ) -> RetrievalRecord:
        if observed_at.utcoffset() is None:
            raise ValueError("retrieval time must be timezone-aware")
        selected = [self.versions[i] for i in ids]
        for value in selected:
            self._authorize_ancestry(value.id, principal, acl_revision, set())
        return RetrievalRecord(
            tenant=self.tenant,
            principal=principal,
            observed_at=observed_at,
            source_versions=ids,
            source_digests=tuple(v.content_digest for v in selected),
            acl_revisions=tuple(v.acl_revision for v in selected),
            read_watermark=read_watermark,
        )

    def _authorize_ancestry(self, version: str, principal: str, acl: str, seen: set[str]) -> None:
        if version in seen:
            return
        seen.add(version)
        value = self.versions[version]
        if (
            value.withdrawn
            or principal not in value.allowed_principals
            or value.acl_revision != acl
        ):
            raise PermissionError("withdrawn, unauthorized, or stale ACL evidence")
        for parent in value.parents:
            self._authorize_ancestry(parent, principal, acl, seen)
