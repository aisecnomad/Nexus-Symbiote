"""Signed, operation-bound authorization for integrations that mediate tool calls.

The adapter must authenticate the workload and obtain the served descriptor from
the actual endpoint. This module authorizes only calls routed through its gateway;
it does not sandbox a process or establish the truth of provider declarations.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Generic, Literal, TypeVar

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from nexus_symbiote.runtime_validation import (
    MAX_ARGUMENT_BYTES,
    MAX_SCHEMA_BYTES,
    ValidationBudgetError,
    check_json_budget,
    validate_arguments,
)

PAYLOAD_TYPE: Literal["application/vnd.in-toto+json"] = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
# These predicate types are signed into attestations and checked by verifiers. They keep
# the original namespace on purpose, even after the repository moved. Changing them is a
# versioned wire-format decision, not a rename.
PREDICATES = {
    "snapshot": "https://github.com/aisecnomad/nexus-symbiote/attestation/approved-snapshot/v1",
    "approval": "https://github.com/aisecnomad/nexus-symbiote/attestation/action-approval/v1",
    "trust": "https://github.com/aisecnomad/nexus-symbiote/attestation/trust-status/v1",
    "model": "https://github.com/aisecnomad/nexus-symbiote/attestation/hosted-model/v1",
}
T = TypeVar("T")


class AuthorizationError(ValueError):
    """The operation lacks complete, valid authorization evidence."""


def canonical_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise AuthorizationError("value is outside the canonical JSON domain") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def strict_json(raw: str | bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise AuthorizationError("duplicate JSON key")
            out[key] = value
        return out

    def invalid(_: str) -> Any:
        raise AuthorizationError("nonfinite JSON value")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    canonical_bytes(value)
    return value


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class ValidWindow(Contract):
    not_before: datetime
    not_after: datetime

    @field_validator("not_before", "not_after")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def ordered(self) -> ValidWindow:
        if self.not_before >= self.not_after:
            raise ValueError("not_after must follow not_before")
        return self


class ToolGrant(Contract):
    definition_profile: Literal["rfc8785-jcs-v2"] = "rfc8785-jcs-v2"
    server_id: str = Field(min_length=1)
    endpoint_identity: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    definition_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    actions: tuple[str, ...] = Field(min_length=1)
    resources: tuple[str, ...] = Field(min_length=1)
    require_approval: bool = True


class ApprovedSnapshot(ValidWindow):
    version: Literal["1"] = "1"
    kind: Literal["approved"] = "approved"
    agent_id: str = Field(min_length=1)
    deployment_id: str = Field(min_length=1)
    tenant: str = Field(min_length=1)
    workload_identity: str = Field(min_length=1)
    serial: int = Field(gt=0)
    bom_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tools: tuple[ToolGrant, ...]

    @model_validator(mode="after")
    def unique_tools(self) -> ApprovedSnapshot:
        keys = [(g.server_id, g.tool_name) for g in self.tools]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate tool grants")
        return self


class TrustStatus(ValidWindow):
    version: Literal["1"] = "1"
    tenant: str = Field(min_length=1)
    serial: int = Field(gt=0)
    revoked_snapshots: tuple[str, ...] = ()
    revoked_tools: tuple[str, ...] = ()
    revoked_endpoints: tuple[str, ...] = ()
    revoked_signers: tuple[str, ...] = ()


class ExecutionContext(Contract):
    agent_id: str
    deployment_id: str
    tenant: str
    workload_identity: str
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class HostedModelAttestation(ValidWindow):
    provider: str
    endpoint: str
    requested_alias: str
    resolved_revision: str = Field(min_length=1)


class ToolCall(Contract):
    server_id: str
    tool_name: str
    action: str
    resource: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ServedTool(Contract):
    endpoint_identity: str
    definition: dict[str, Any]


class ActionApproval(ValidWindow):
    version: Literal["1"] = "1"
    snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    context_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    request_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    nonce: str = Field(min_length=16, max_length=256)
    actor: str = Field(min_length=1)


class EnvelopeSignature(Contract):
    key_id: str = Field(alias="keyid")
    signature: str = Field(alias="sig")


class Envelope(Contract):
    payload_type: Literal["application/vnd.in-toto+json"] = Field(
        default=PAYLOAD_TYPE, alias="payloadType"
    )
    payload: str = Field(max_length=24 * 1024 * 1024)
    signatures: tuple[EnvelopeSignature, ...] = Field(max_length=32)


def key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(raw).hexdigest()


def _pae(payload: bytes) -> bytes:
    kind = PAYLOAD_TYPE.encode()
    return b" ".join(
        [b"DSSEv1", str(len(kind)).encode(), kind, str(len(payload)).encode(), payload]
    )


def sign_contract(
    contract: ApprovedSnapshot | ActionApproval | TrustStatus | HostedModelAttestation,
    kind: Literal["snapshot", "approval", "trust", "model"],
    keys: tuple[Ed25519PrivateKey, ...],
) -> Envelope:
    expected = {
        "snapshot": ApprovedSnapshot,
        "approval": ActionApproval,
        "trust": TrustStatus,
        "model": HostedModelAttestation,
    }[kind]
    if not isinstance(contract, expected) or not keys:
        raise AuthorizationError("contract type and nonempty signing keys must match purpose")
    body = contract.model_dump(mode="json")
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATES[kind],
        "subject": [{"name": kind, "digest": {"sha256": digest(body).split(":", 1)[1]}}],
        "predicate": body,
    }
    payload = canonical_bytes(statement)
    signatures = tuple(
        EnvelopeSignature(
            key_id=key_id(k.public_key()),
            signature=base64.b64encode(k.sign(_pae(payload))).decode(),
        )
        for k in keys
    )
    return Envelope(payload=base64.b64encode(payload).decode(), signatures=signatures)


def verify_contract(
    envelope: Envelope,
    kind: Literal["snapshot", "approval", "trust", "model"],
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    threshold: int = 1,
) -> tuple[ApprovedSnapshot | ActionApproval | TrustStatus | HostedModelAttestation, set[str]]:
    _validate_threshold(threshold)
    if not trusted_keys:
        raise AuthorizationError("positive threshold and purpose-specific trusted keys required")
    try:
        payload = base64.b64decode(envelope.payload, validate=True)
        if len(payload) > 16 * 1024 * 1024:
            raise AuthorizationError("statement exceeds limit")
        accepted: set[str] = set()
        for signature in envelope.signatures:
            public = trusted_keys.get(signature.key_id)
            if public is None or key_id(public) != signature.key_id:
                continue
            try:
                public.verify(base64.b64decode(signature.signature, validate=True), _pae(payload))
                accepted.add(signature.key_id)
            except InvalidSignature:
                continue
        if len(accepted) < threshold:
            raise AuthorizationError("insufficient distinct trusted signers")
        statement = strict_json(payload)
        if not isinstance(statement, dict) or set(statement) != {
            "_type",
            "predicateType",
            "subject",
            "predicate",
        }:
            raise AuthorizationError("invalid in-toto statement")
        if statement["_type"] != STATEMENT_TYPE or statement["predicateType"] != PREDICATES[kind]:
            raise AuthorizationError("statement purpose mismatch")
        contract: ApprovedSnapshot | ActionApproval | TrustStatus | HostedModelAttestation
        if kind == "snapshot":
            contract = ApprovedSnapshot.model_validate(statement["predicate"])
        elif kind == "approval":
            contract = ActionApproval.model_validate(statement["predicate"])
        elif kind == "trust":
            contract = TrustStatus.model_validate(statement["predicate"])
        else:
            contract = HostedModelAttestation.model_validate(statement["predicate"])
        subject = [
            {"name": kind, "digest": {"sha256": digest(statement["predicate"]).split(":", 1)[1]}}
        ]
        if statement["subject"] != subject:
            raise AuthorizationError("subject digest mismatch")
        return contract, accepted
    except ValidationError as exc:
        # Field names only: the text would otherwise echo issuer-authored values to
        # whoever reads the library error, which the CLI already avoids.
        raise AuthorizationError(_validation_message(exc)) from exc
    except (ValueError, TypeError, KeyError) as exc:
        raise AuthorizationError(str(exc)) from exc


def _validation_message(exc: ValidationError) -> str:
    known = {
        name
        for model in (ApprovedSnapshot, ActionApproval, TrustStatus, HostedModelAttestation)
        for name in model.model_fields
    }
    invalid = set()
    for error in exc.errors(include_input=False, include_context=False, include_url=False):
        location = error["loc"]
        head = location[0] if location else None
        invalid.add(head if isinstance(head, str) and head in known else "unsupported field")
    return "contract validation failed; review fields: " + ", ".join(sorted(invalid))


def _validate_threshold(threshold: int) -> None:
    # Envelope admits at most 32 signatures. Reject bool and coercible values so
    # an operator's quorum policy has one unambiguous, achievable meaning.
    if type(threshold) is not int or not 1 <= threshold <= 32:
        raise AuthorizationError("quorum threshold must be an integer between 1 and 32")


def _validate_key_quorum(threshold: int, trusted_keys: Mapping[str, Ed25519PublicKey]) -> None:
    authorized = {
        identifier for identifier, public in trusted_keys.items() if identifier == key_id(public)
    }
    # An empty ring with the default threshold remains a disabled purpose, as
    # before. It can never verify a contract; an explicit larger quorum is a
    # configuration error. Aliases for the same key do not create more signers.
    if (trusted_keys or threshold > 1) and threshold > len(authorized):
        raise AuthorizationError("quorum threshold exceeds distinct authorized signing keys")


def _window(contract: ValidWindow, now: datetime, maximum: timedelta) -> None:
    if now.utcoffset() is None:
        raise AuthorizationError("verification time must include timezone")
    if not contract.not_before <= now < contract.not_after:
        raise AuthorizationError("contract is future-dated or expired")
    if contract.not_after - contract.not_before > maximum:
        raise AuthorizationError("contract validity exceeds local policy")


def _validate_arguments(schema: Any, arguments: dict[str, Any]) -> None:
    try:
        validate_arguments(schema, arguments)
    except ValidationBudgetError as exc:
        raise AuthorizationError("tool arguments or offline input schema are invalid") from exc


class StateStore:
    """Durable check-and-record state; the operator must protect the database path."""

    def __init__(self, path: Path) -> None:
        if path.is_symlink():
            raise AuthorizationError("state database cannot be a symlink")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self._transaction() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS heads (scope TEXT PRIMARY KEY, serial INTEGER NOT NULL, digest TEXT NOT NULL)"
            )
            if "revoked_signers" not in {
                row[1] for row in connection.execute("PRAGMA table_info(heads)")
            }:
                connection.execute("ALTER TABLE heads ADD COLUMN revoked_signers TEXT")
            connection.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY)")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS tenant_nonces "
                "(tenant TEXT NOT NULL, nonce TEXT NOT NULL, PRIMARY KEY (tenant, nonce))"
            )
        path.chmod(0o600)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path, timeout=10, isolation_level=None)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            yield db

    def restore_trust_status(self, status: TrustStatus) -> None:
        """Restore issuer eligibility only for the exact digest already accepted by this store."""
        with self._transaction() as db:
            restored = db.execute(
                "UPDATE heads SET revoked_signers=? WHERE scope=? AND serial=? AND digest=?",
                (
                    json.dumps(status.revoked_signers),
                    "trust:" + status.tenant,
                    status.serial,
                    digest(status.model_dump(mode="json")),
                ),
            )
            if restored.rowcount != 1:
                raise AuthorizationError("archived trust status does not match the recorded head")

    def accept_trust_status(
        self, status: TrustStatus, verified_signers: set[str]
    ) -> tuple[str, int, str]:
        """Atomically authenticate a transition against the preceding tenant trust state."""
        scope = "trust:" + status.tenant
        head = (scope, status.serial, digest(status.model_dump(mode="json")))
        if not verified_signers or verified_signers.intersection(status.revoked_signers):
            raise AuthorizationError("trust status requires unrevoked signers")
        with self._transaction() as db:
            old = db.execute(
                "SELECT serial, digest, revoked_signers FROM heads WHERE scope=?", (scope,)
            ).fetchone()
            if old:
                if status.serial < old[0] or (status.serial == old[0] and head[2] != old[1]):
                    raise AuthorizationError("trust-status rollback/fork")
                if old[2] is None:
                    if head[1:] != old[:2]:
                        raise AuthorizationError(
                            "restore the recorded trust status before advancing"
                        )
                elif verified_signers.intersection(json.loads(old[2])):
                    raise AuthorizationError("previously revoked trust-status signer")
            db.execute(
                "INSERT OR REPLACE INTO heads(scope,serial,digest,revoked_signers) VALUES (?,?,?,?)",
                (*head, json.dumps(status.revoked_signers)),
            )
        return head

    def record(
        self,
        heads: tuple[tuple[str, int, str], ...],
        nonce: str | None = None,
        *,
        tenant: str | None = None,
        check_time: Callable[[], None] | None = None,
    ) -> None:
        with self._transaction() as db:
            for scope, serial, value in heads:
                old = db.execute(
                    "SELECT serial, digest FROM heads WHERE scope=?", (scope,)
                ).fetchone()
                if scope.startswith("trust:"):
                    # Only accept_trust_status may advance this head or change issuer eligibility.
                    if old != (serial, value):
                        raise AuthorizationError(
                            "trust-status rollback/fork or missing trust state"
                        )
                    continue
                if old and (serial < old[0] or (serial == old[0] and value != old[1])):
                    raise AuthorizationError("snapshot or trust-status rollback/fork")
                db.execute(
                    "INSERT OR REPLACE INTO heads(scope,serial,digest) VALUES (?,?,?)",
                    (scope, serial, value),
                )
            if nonce is not None:
                # Rows consumed before nonces were tenant-scoped stay consumed for every
                # tenant, so an upgrade can never resurrect a used nonce.
                legacy = db.execute("SELECT 1 FROM nonces WHERE nonce=?", (nonce,)).fetchone()
                try:
                    if legacy is not None:
                        raise sqlite3.IntegrityError("legacy nonce")
                    if tenant is None:
                        db.execute("INSERT INTO nonces(nonce) VALUES (?)", (nonce,))
                    else:
                        db.execute(
                            "INSERT INTO tenant_nonces(tenant, nonce) VALUES (?, ?)",
                            (tenant, nonce),
                        )
                except sqlite3.IntegrityError as exc:
                    raise AuthorizationError("approval nonce has already been used") from exc
            if check_time is not None:
                # The write lock may have taken longer than the remaining approval lifetime.
                check_time()


class ReferenceGateway(Generic[T]):
    """Authorize and execute one call through authenticated, operator-owned adapters."""

    def __init__(
        self,
        *,
        snapshot_keys: Mapping[str, Ed25519PublicKey],
        approval_keys: Mapping[str, Ed25519PublicKey],
        trust_keys: Mapping[str, Ed25519PublicKey],
        state: StateStore,
        authenticate: Callable[[], ExecutionContext],
        describe: Callable[[str, str], ServedTool],
        resolve_scope: Callable[[ToolCall], tuple[str, str]],
        execute: Callable[[ToolCall], T],
        approval_actors: Mapping[str, str] | None = None,
        clock: Callable[[], datetime] | None = None,
        snapshot_threshold: int = 1,
        approval_threshold: int = 1,
        trust_threshold: int = 1,
    ) -> None:
        for threshold, keys in (
            (snapshot_threshold, snapshot_keys),
            (approval_threshold, approval_keys),
            (trust_threshold, trust_keys),
        ):
            _validate_threshold(threshold)
            _validate_key_quorum(threshold, keys)
        self.snapshot_keys = dict(snapshot_keys)
        self.approval_keys = dict(approval_keys)
        self.trust_keys = dict(trust_keys)
        self.snapshot_threshold = snapshot_threshold
        self.approval_threshold = approval_threshold
        self.trust_threshold = trust_threshold
        self.state = state
        self.authenticate = authenticate
        self.describe = describe
        self.resolve_scope = resolve_scope
        self.execute = execute
        self.approval_actors = dict(approval_actors or {})
        self.clock = clock or (lambda: datetime.now(UTC))

    def invoke(
        self,
        call: ToolCall,
        *,
        snapshot: Envelope,
        trust: Envelope,
        bom: Mapping[str, Any],
        approval: Envelope | None = None,
    ) -> T:
        from nexus_symbiote.core.hashing import hash_tool_definition

        try:
            check_json_budget(call.arguments, maximum=MAX_ARGUMENT_BYTES)
            call = ToolCall.model_validate(
                strict_json(canonical_bytes(call.model_dump(mode="json")))
            )
        except (ValidationBudgetError, RecursionError) as exc:
            raise AuthorizationError("tool arguments exceed the supported JSON budget") from exc
        timestamp = self.clock()
        context = self.authenticate()
        statuses, trust_signers = verify_contract(
            trust, "trust", self.trust_keys, threshold=self.trust_threshold
        )
        if not isinstance(statuses, TrustStatus):
            raise AuthorizationError("unexpected contract")
        _window(statuses, timestamp, timedelta(hours=1))
        if statuses.tenant != context.tenant:
            raise AuthorizationError("trust status tenant mismatch")
        trust_head = self.state.accept_trust_status(statuses, trust_signers)
        approved, snapshot_signers = verify_contract(
            snapshot, "snapshot", self.snapshot_keys, threshold=self.snapshot_threshold
        )
        if not isinstance(approved, ApprovedSnapshot):
            raise AuthorizationError("unexpected snapshot")
        _window(approved, timestamp, timedelta(hours=24))
        expected = ExecutionContext(
            **{name: getattr(approved, name) for name in ExecutionContext.model_fields}
        )
        if context != expected or statuses.tenant != context.tenant:
            raise AuthorizationError("workload, deployment, tenant, or policy mismatch")
        snapshot_digest = digest(approved.model_dump(mode="json"))
        if digest(dict(bom)) != approved.bom_digest:
            raise AuthorizationError("companion BOM does not match approved digest")
        if snapshot_digest in statuses.revoked_snapshots:
            raise AuthorizationError("snapshot is revoked")
        if (snapshot_signers | trust_signers) & set(statuses.revoked_signers):
            raise AuthorizationError("signer is revoked")
        # Pydantic's frozen models do not freeze nested dictionaries. Give the
        # resolver an independent request so it cannot retain a reference to the
        # authorized arguments and change them later, after approval is checked.
        request_bytes = canonical_bytes(call.model_dump(mode="json"))
        scope_call = ToolCall.model_validate(strict_json(request_bytes))
        effective_action, effective_resource = self.resolve_scope(scope_call)
        if canonical_bytes(scope_call.model_dump(mode="json")) != request_bytes:
            raise AuthorizationError("scope resolver modified the request")
        if (effective_action, effective_resource) != (call.action, call.resource):
            raise AuthorizationError("operation labels do not match the actual tool arguments")
        grant = next(
            (
                g
                for g in approved.tools
                if (g.server_id, g.tool_name) == (call.server_id, call.tool_name)
            ),
            None,
        )
        if (
            grant is None
            or call.action not in grant.actions
            or call.resource not in grant.resources
        ):
            raise AuthorizationError("action/resource is outside approved capability")
        served = self.describe(call.server_id, call.tool_name)
        definition = served.definition
        if (
            definition.get("name") != call.tool_name
            or served.endpoint_identity != grant.endpoint_identity
        ):
            raise AuthorizationError("served tool name or authenticated endpoint changed")
        unsupported = set(definition) - {"name", "description", "inputSchema", "annotations"}
        if unsupported:
            raise AuthorizationError("descriptor uses fields unsupported by digest profile v1")
        try:
            check_json_budget(definition, maximum=MAX_SCHEMA_BYTES)
        except ValidationBudgetError as exc:
            raise AuthorizationError("served descriptor exceeds the supported JSON budget") from exc
        actual = hash_tool_definition(
            call.tool_name,
            definition.get("description", ""),
            definition.get("inputSchema"),
            definition.get("annotations"),
        )
        if actual != grant.definition_digest:
            raise AuthorizationError("served descriptor changed since approval")
        if (
            actual in statuses.revoked_tools
            or served.endpoint_identity in statuses.revoked_endpoints
        ):
            raise AuthorizationError("tool or endpoint is revoked")
        nonce = None
        consent: ActionApproval | None = None
        if grant.require_approval:
            if approval is None:
                raise AuthorizationError("operation-bound approval required")
            verified_approval, signers = verify_contract(
                approval, "approval", self.approval_keys, threshold=self.approval_threshold
            )
            if not isinstance(verified_approval, ActionApproval):
                raise AuthorizationError("unexpected approval")
            consent = verified_approval
            _window(consent, timestamp, timedelta(minutes=5))
            if signers & set(statuses.revoked_signers):
                raise AuthorizationError("approver is revoked")
            if any(self.approval_actors.get(signer) != consent.actor for signer in signers):
                raise AuthorizationError(
                    "approval actor is not bound to its authorized signing key"
                )
            if (consent.snapshot_digest, consent.context_digest, consent.request_digest) != (
                snapshot_digest,
                digest(context.model_dump(mode="json")),
                digest(call.model_dump(mode="json")),
            ):
                raise AuthorizationError("approval does not cover this operation")
            nonce = consent.nonce
        _validate_arguments(definition.get("inputSchema"), call.arguments)
        if self.authenticate() != context:
            raise AuthorizationError("execution identity changed during authorization")

        def check_time() -> None:
            final_time = self.clock()
            _window(approved, final_time, timedelta(hours=24))
            _window(statuses, final_time, timedelta(hours=1))
            if consent is not None:
                _window(consent, final_time, timedelta(minutes=5))

        self.state.record(
            (
                (
                    "snapshot:" + digest([context.tenant, context.deployment_id, context.agent_id]),
                    approved.serial,
                    snapshot_digest,
                ),
                trust_head,
            ),
            nonce,
            tenant=context.tenant,
            check_time=check_time,
        )
        return self.execute(call)
