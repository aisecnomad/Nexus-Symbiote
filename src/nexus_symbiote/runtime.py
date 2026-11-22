"""Signed, operation-bound authorization for integrations that mediate tool calls.

The adapter must authenticate the workload and obtain the served descriptor from
the actual endpoint. This module authorizes only calls routed through its gateway;
it does not sandbox a process or establish the truth of provider declarations.
docs/runtime-contract-reference.md specifies the wire format, the order of checks
and every reason code.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import stat
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Generic, Literal, NoReturn, Protocol, TypeVar, cast

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from nexus_symbiote.runtime_validation import (
    MAX_ARGUMENT_BYTES,
    MAX_SAFE_INTEGER,
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
Kind = Literal["snapshot", "approval", "trust", "model"]
Purpose = Literal["snapshot", "approval", "trust", "model", "contract"]
MAX_LIFETIMES: dict[str, timedelta] = {
    "snapshot": timedelta(hours=24),
    "trust": timedelta(hours=1),
    "approval": timedelta(minutes=5),
    "model": timedelta(hours=24),
}
MAX_STATEMENT_BYTES = 1024 * 1024
MAX_PAYLOAD_CHARACTERS = 4 * ((MAX_STATEMENT_BYTES + 2) // 3)
MAX_SIGNATURES = 32
# DSSE key IDs are hints. A signature without a known key ID is tried against each
# ring key, so the total number of verifications per envelope is capped.
MAX_SIGNATURE_ATTEMPTS = 64
MAX_BOM_BYTES = 16 * 1024 * 1024
MAX_BOM_NODES = 1_000_000
MAX_BOM_DEPTH = 64
NONCE_RETENTION = timedelta(days=7)
DIGEST_PROFILE = "rfc8785-jcs-v2"
DESCRIPTOR_FIELDS = (
    "name",
    "description",
    "inputSchema",
    "annotations",
    "title",
    "outputSchema",
    "_meta",
)
T = TypeVar("T")
U = TypeVar("U")

REASONS: dict[str, str] = {
    "denied": "authorization evidence is incomplete or invalid",
    "configuration-invalid": "gateway, signer or quorum configuration is invalid",
    "json-invalid": "input is not strict JSON",
    "json-not-object": "input must be a JSON object",
    "json-out-of-domain": "value is outside the canonical JSON domain",
    "json-budget-exceeded": "JSON exceeds the supported size or complexity",
    "json-number-out-of-range": "JSON contains an integer outside the I-JSON range",
    "envelope-invalid": "signed envelope is malformed",
    "statement-too-large": "signed statement exceeds the size limit",
    "signers-insufficient": "too few distinct trusted signers",
    "signers-out-of-scope": "too few signers are authorized for this tenant, deployment, agent "
    "or tool",
    "statement-invalid": "payload is not a valid in-toto statement",
    "statement-purpose-mismatch": "statement was signed for another purpose",
    "contract-invalid": "contract does not validate",
    "contract-not-canonical": "contract is not in canonical form",
    "subject-mismatch": "statement subject does not match its predicate",
    "snapshot-not-yet-valid": "snapshot is not yet valid",
    "snapshot-expired": "snapshot has expired",
    "snapshot-lifetime-exceeds-policy": "snapshot validity exceeds 24 hours",
    "trust-not-yet-valid": "trust status is not yet valid",
    "trust-expired": "trust status has expired",
    "trust-lifetime-exceeds-policy": "trust status validity exceeds 1 hour",
    "approval-not-yet-valid": "approval is not yet valid",
    "approval-expired": "approval has expired",
    "approval-lifetime-exceeds-policy": "approval validity exceeds 5 minutes",
    "model-not-yet-valid": "hosted-model attestation is not yet valid",
    "model-expired": "hosted-model attestation has expired",
    "model-lifetime-exceeds-policy": "hosted-model attestation validity exceeds 24 hours",
    "contract-not-yet-valid": "contract is not yet valid",
    "contract-expired": "contract has expired",
    "contract-lifetime-exceeds-policy": "contract validity exceeds local policy",
    "trust-tenant-mismatch": "trust status is for another tenant",
    "trust-signer-revoked": "a trust-status signer is revoked",
    "trust-rollback": "trust status is older than the recorded one",
    "trust-fork": "another trust status with this serial was recorded",
    "trust-restore-required": "restore the recorded trust status before advancing",
    "trust-superseded": "a newer trust status was recorded during authorization",
    "context-mismatch": "workload, deployment, tenant, agent or policy differs from the snapshot",
    "snapshot-revoked": "snapshot is revoked",
    "signer-revoked": "a snapshot signer is revoked",
    "snapshot-superseded": "a newer snapshot is recorded for this agent",
    "snapshot-fork": "another snapshot with this serial was recorded for this agent",
    "bom-required": "snapshot verification requires its companion BOM",
    "bom-mismatch": "companion BOM does not match the approved digest",
    "bom-too-large": "companion BOM exceeds the supported JSON budget",
    "arguments-too-large": "tool arguments exceed the supported JSON budget",
    "arguments-number-out-of-range": "tool arguments contain an integer outside the I-JSON range",
    "arguments-not-json": "tool call is outside the canonical JSON domain",
    "resolver-modified-request": "scope resolver modified the request",
    "scope-mismatch": "operation labels do not match the actual tool arguments",
    "tool-not-granted": "snapshot does not grant this tool",
    "capability-denied": "action or resource is outside the approved capability",
    "tool-revoked": "tool definition is revoked",
    "endpoint-revoked": "endpoint is revoked",
    "endpoint-mismatch": "authenticated endpoint differs from the grant",
    "descriptor-name-mismatch": "served tool name differs from the requested tool",
    "descriptor-unsupported": "served descriptor has fields outside the digest profile",
    "descriptor-too-large": "served descriptor exceeds the supported JSON budget",
    "descriptor-not-json": "served descriptor is outside the canonical JSON domain",
    "descriptor-changed": "served descriptor changed since approval",
    "approval-required": "operation requires a signed approval",
    "approver-revoked": "an approval signer is revoked",
    "approval-actor-unbound": "approval actor is not bound to its signing keys",
    "approval-quorum-not-met": "approval needs more distinct approvers",
    "approval-snapshot-mismatch": "approval was given for another snapshot",
    "approval-context-mismatch": "approval was given for another execution context",
    "approval-request-mismatch": "approval was given for another request",
    "approval-replayed": "approval nonce has already been used",
    "arguments-invalid": "tool arguments do not satisfy the input schema",
    "schema-invalid": "input schema is invalid, unsupported or not resolvable offline",
    "validation-capacity": "schema validation capacity is exhausted; retry later",
    "validation-timeout": "schema validation timed out; retry later",
    "validation-unavailable": "schema validation worker is unavailable",
    "validation-failed": "schema validation failed or exceeded its budget",
    "identity-changed": "execution identity changed during authorization",
    "state-missing": "state database does not exist or is not initialized",
    "state-invalid": "state database path is unsafe or already exists",
    "state-unavailable": "state database is unavailable or locked",
    "adapter-error": "an adapter raised an exception other than AuthorizationError",
}


class AuthorizationError(ValueError):
    """The operation lacks complete, valid authorization evidence.

    ``reason`` is a stable code from REASONS; the message text may change.
    """

    def __init__(self, message: str, *, reason: str = "denied") -> None:
        super().__init__(message)
        self.reason = reason


def canonical_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise AuthorizationError(
            "value is outside the canonical JSON domain", reason="json-out-of-domain"
        ) from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


MAX_STRICT_JSON_DEPTH = 256


def _deeper_than(value: Any, limit: int) -> bool:
    """Whether arrays and objects nest more than ``limit`` levels, checked without recursion."""
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if isinstance(item, dict | list):
            if depth > limit:
                return True
            children = item.values() if isinstance(item, dict) else item
            pending.extend((child, depth + 1) for child in children)
    return False


def strict_json(raw: str | bytes) -> Any:
    from nexus_symbiote.core.hashing import json_nesting_exceeds

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise AuthorizationError("duplicate JSON key", reason="json-invalid")
            out[key] = value
        return out

    def invalid(_: str) -> Any:
        raise AuthorizationError("nonfinite JSON value", reason="json-invalid")

    try:
        # json.loads would detect UTF-16 and UTF-32 in bytes and skip a byte-order mark,
        # so a signed statement could take several encodings; only UTF-8 is accepted.
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        if text.startswith("\ufeff"):
            raise ValueError("byte-order mark")
        if json_nesting_exceeds(text, MAX_STRICT_JSON_DEPTH):
            raise AuthorizationError("input nests too deeply", reason="json-invalid")
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)
    except AuthorizationError:
        raise
    except (ValueError, RecursionError) as exc:
        raise AuthorizationError("input is not strict JSON", reason="json-invalid") from exc
    # Interpreters differ in how deep json.loads recurses before it fails (3.14 parses
    # 100,000 levels), so the bound is explicit rather than the interpreter's.
    if _deeper_than(value, MAX_STRICT_JSON_DEPTH):
        raise AuthorizationError("input nests too deeply", reason="json-invalid")
    canonical_bytes(value)
    return value


# Revocation entries are compared verbatim, so a malformed one would be ignored silently.
Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
KeyId = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_LAUNCHER_IDENTITY = re.compile(r"stdio\+launcher:sha256:[0-9a-f]{64}")
_URL_IDENTITY = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.-]*)://"
    r"(?P<host>[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?|\[[0-9a-f:.]+\])"
    r"(?::(?P<port>[1-9][0-9]{0,4}))?"
    r"(?P<path>(?:/(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-F]{2})*)*)"
)
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _ipv6_text(value: int) -> str:
    """Write an IPv6 address as RFC 5952 hexadecimal text, the first longest zero run as ::.

    ``str(IPv6Address)`` prints IPv4-mapped addresses differently across Python
    patch releases, so a grant signed on one interpreter could fail on another.
    """
    groups = [value >> shift & 0xFFFF for shift in range(112, -1, -16)]
    best = size = 0
    start: int | None = None
    for index, group in enumerate([*groups, 1]):
        if group == 0 and start is None:
            start = index
        elif group != 0 and start is not None:
            if index - start > size:
                best, size = start, index - start
            start = None
    text = [f"{group:x}" for group in groups]
    if size < 2:
        return ":".join(text)
    return ":".join(text[:best]) + "::" + ":".join(text[best + size :])


def _canonical_host(host: str) -> bool:
    """Accept an IP literal only in its one spelling."""
    if host.startswith("["):
        try:
            address = int(ipaddress.IPv6Address(host[1:-1]))
        except ValueError:
            return False
        # IPv4-mapped and IPv4-compatible addresses are other spellings of IPv4 ones.
        if address >> 32 == 0xFFFF or 1 < address < 2**32:
            return False
        return f"[{_ipv6_text(address)}]" == host
    # URL parsers read a host whose last label is a number as an IPv4 address, in
    # forms such as 2130706433, 127.1 or 0x7f.0.0.1.
    if _NUMERIC_LABEL.fullmatch(host.rsplit(".", 1)[-1]):
        try:
            return str(ipaddress.IPv4Address(host)) == host
        except ValueError:
            return False
    return True


def _endpoint_identity(value: str) -> str:
    """Accept one spelling per endpoint so a revocation entry cannot silently miss."""
    if _LAUNCHER_IDENTITY.fullmatch(value):
        return value
    match = _URL_IDENTITY.fullmatch(value)
    if match is None:
        raise ValueError("endpoint identity is not a launcher pin or canonical URL")
    port, path = match["port"], match["path"]
    if (
        not _canonical_host(match["host"])
        or (port is not None and (int(port) > 65535 or int(port) == _DEFAULT_PORTS.get(match[1])))
        or path == "/"
        or any(segment in {".", ".."} for segment in path.split("/"))
        or any(chr(int(code, 16)) in _UNRESERVED for code in re.findall("%(..)", path))
    ):
        raise ValueError("endpoint identity is not in canonical form")
    return value


EndpointIdentity = Annotated[str, AfterValidator(_endpoint_identity)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


def _aware(value: datetime) -> datetime:
    if value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    try:
        return value.astimezone(UTC)
    except OverflowError as exc:
        # Pydantic reports only ValueError and AssertionError as validation errors.
        raise ValueError("timestamp is out of range in UTC") from exc


class ValidWindow(Contract):
    not_before: datetime
    not_after: datetime

    @field_validator("not_before", "not_after")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        return _aware(value)

    @model_validator(mode="after")
    def ordered(self) -> ValidWindow:
        if self.not_before >= self.not_after:
            raise PydanticCustomError("validity_window", "not_after must follow not_before")
        return self


class ToolGrant(Contract):
    definition_profile: Literal["rfc8785-jcs-v2"] = "rfc8785-jcs-v2"
    server_id: str = Field(min_length=1)
    endpoint_identity: EndpointIdentity
    tool_name: str = Field(min_length=1)
    definition_digest: Sha256Digest
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
    serial: int = Field(gt=0, le=MAX_SAFE_INTEGER)
    bom_digest: Sha256Digest
    policy_digest: Sha256Digest
    tools: tuple[ToolGrant, ...]

    @model_validator(mode="after")
    def unique_tools(self) -> ApprovedSnapshot:
        keys = [(g.server_id, g.tool_name) for g in self.tools]
        if len(keys) != len(set(keys)):
            raise PydanticCustomError("duplicate_tool_grants", "duplicate tool grants")
        return self


class TrustStatus(ValidWindow):
    version: Literal["1"] = "1"
    tenant: str = Field(min_length=1)
    serial: int = Field(gt=0, le=MAX_SAFE_INTEGER)
    revoked_snapshots: tuple[Sha256Digest, ...] = ()
    revoked_tools: tuple[Sha256Digest, ...] = ()
    revoked_endpoints: tuple[EndpointIdentity, ...] = ()
    revoked_signers: tuple[KeyId, ...] = ()


class ExecutionContext(Contract):
    agent_id: str
    deployment_id: str
    tenant: str
    workload_identity: str
    policy_digest: Sha256Digest


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
    snapshot_digest: Sha256Digest
    context_digest: Sha256Digest
    request_digest: Sha256Digest
    nonce: str = Field(min_length=16, max_length=256)
    actor: str = Field(min_length=1)


AnyContract = ApprovedSnapshot | ActionApproval | TrustStatus | HostedModelAttestation
CONTRACTS: dict[str, type[AnyContract]] = {
    "snapshot": ApprovedSnapshot,
    "approval": ActionApproval,
    "trust": TrustStatus,
    "model": HostedModelAttestation,
}
C = TypeVar("C", ApprovedSnapshot, ActionApproval, TrustStatus, HostedModelAttestation)
_URLSAFE = str.maketrans("-_", "+/")


def _canonical_base64(value: str) -> str:
    """Accept canonical standard or URL-safe base64, as DSSE allows; return standard."""
    standard = value.translate(_URLSAFE)
    if standard != value and ("+" in value or "/" in value):
        raise ValueError("base64 mixes the standard and URL-safe alphabets")
    try:
        raw = base64.b64decode(standard, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("value is not base64") from exc
    # Non-canonical padding bits would give one signed payload several encodings.
    if base64.b64encode(raw).decode("ascii") != standard:
        raise ValueError("base64 encoding is not canonical")
    return standard


class EnvelopeSignature(Contract):
    key_id: str | None = Field(default=None, alias="keyid", max_length=256)
    signature: str = Field(alias="sig", min_length=1, max_length=4096)

    @field_validator("signature")
    @classmethod
    def canonical_signature(cls, value: str) -> str:
        return _canonical_base64(value)


class Envelope(Contract):
    payload_type: Literal["application/vnd.in-toto+json"] = Field(
        default=PAYLOAD_TYPE, alias="payloadType"
    )
    payload: str = Field(max_length=MAX_PAYLOAD_CHARACTERS)
    signatures: tuple[EnvelopeSignature, ...] = Field(max_length=MAX_SIGNATURES)

    @field_validator("payload")
    @classmethod
    def canonical_payload(cls, value: str) -> str:
        return _canonical_base64(value)


class SignerScope(Contract):
    """Limit what one signing key may authorize; an omitted field leaves it unrestricted.

    A trust status covers a whole tenant, so a key restricted to deployments, agents
    or tools does not count towards a trust-status quorum.
    """

    tenants: frozenset[str] | None = None
    deployments: frozenset[str] | None = None
    agents: frozenset[str] | None = None
    tools: frozenset[tuple[str, str]] | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None

    @field_validator("not_before", "not_after")
    @classmethod
    def aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _aware(value)

    @model_validator(mode="after")
    def ordered(self) -> SignerScope:
        if (
            self.not_before is not None
            and self.not_after is not None
            and self.not_before >= self.not_after
        ):
            raise PydanticCustomError("validity_window", "not_after must follow not_before")
        return self

    def permits(
        self,
        *,
        at: datetime,
        tenant: str,
        deployment: str | None,
        agent: str | None,
        tools: Iterable[tuple[str, str]],
    ) -> bool:
        if (self.not_before is not None and at < self.not_before) or (
            self.not_after is not None and at >= self.not_after
        ):
            return False
        if self.tenants is not None and tenant not in self.tenants:
            return False
        if deployment is None:
            return self.deployments is None and self.agents is None and self.tools is None
        return (
            (self.deployments is None or deployment in self.deployments)
            and (self.agents is None or agent in self.agents)
            and (self.tools is None or all(tool in self.tools for tool in tools))
        )


class ContractSigner(Protocol):
    """An Ed25519 signer. A KMS, HSM or agent-held key can implement this."""

    def sign(self, data: bytes) -> bytes:
        """The Ed25519 signature over ``data``."""

    def public_key(self) -> Ed25519PublicKey:
        """The public key that verifies this signer's signatures."""


@dataclass(frozen=True)
class Decision:
    """One authorization outcome for an audit trail.

    It holds digests, serials, signer key IDs and the request labels, never argument
    values. ``server_id``, ``tool_name``, ``action`` and ``resource`` come from the
    caller; treat them as untrusted text. For an admitted call the signer fields name
    the keys that counted toward each threshold; a call denied after the snapshot's
    signatures were verified names every key whose signature verified.
    """

    admitted: bool
    reason: str
    time: datetime
    server_id: str
    tool_name: str
    action: str
    resource: str
    store_id: str | None = None
    request_digest: str | None = None
    tenant: str | None = None
    deployment_id: str | None = None
    agent_id: str | None = None
    workload_identity: str | None = None
    trust_serial: int | None = None
    trust_digest: str | None = None
    snapshot_serial: int | None = None
    snapshot_digest: str | None = None
    approval_digest: str | None = None
    approval_actor: str | None = None
    trust_signers: tuple[str, ...] = ()
    snapshot_signers: tuple[str, ...] = ()
    approval_signers: tuple[str, ...] = ()


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
    contract: AnyContract,
    kind: Kind,
    keys: Sequence[ContractSigner],
) -> Envelope:
    expected = CONTRACTS[kind]
    if not isinstance(contract, expected) or not keys or len(keys) > MAX_SIGNATURES:
        raise AuthorizationError(
            "contract type and 1 to 32 signing keys must match purpose",
            reason="configuration-invalid",
        )
    # model_copy(update=...) and model_construct skip validation. Re-validate, and refuse
    # a contract that differs from its canonical form instead of normalizing it: the
    # signer's digest of the object it holds must be the digest the envelope binds,
    # which revocation and approval use.
    held = contract.model_dump(mode="json")
    try:
        body = expected.model_validate(held).model_dump(mode="json")
    except ValidationError as exc:
        raise AuthorizationError(
            "contract does not validate and cannot be signed", reason="contract-invalid"
        ) from exc
    if digest(body) != digest(held):
        raise AuthorizationError(
            "contract is not in canonical form and cannot be signed",
            reason="contract-not-canonical",
        )
    if contract.not_after - contract.not_before > MAX_LIFETIMES[kind]:
        raise AuthorizationError(
            "contract validity exceeds the maximum lifetime for its purpose and can never verify",
            reason=f"{kind}-lifetime-exceeds-policy",
        )
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATES[kind],
        "subject": [{"name": kind, "digest": {"sha256": digest(body).split(":", 1)[1]}}],
        "predicate": body,
    }
    payload = canonical_bytes(statement)
    if len(payload) > MAX_STATEMENT_BYTES:
        raise AuthorizationError("statement exceeds limit", reason="statement-too-large")
    message = _pae(payload)
    signatures = []
    for signer in keys:
        public = signer.public_key()
        raw = signer.sign(message)
        try:
            if not isinstance(public, Ed25519PublicKey):
                raise InvalidSignature
            public.verify(raw, message)
        except InvalidSignature as exc:
            raise AuthorizationError(
                "signer did not return a valid Ed25519 signature", reason="configuration-invalid"
            ) from exc
        signatures.append(
            EnvelopeSignature(key_id=key_id(public), signature=base64.b64encode(raw).decode())
        )
    return Envelope(payload=base64.b64encode(payload).decode(), signatures=tuple(signatures))


def _accepted_signers(
    envelope: Envelope, payload: bytes, trusted_keys: Mapping[str, Ed25519PublicKey]
) -> set[str]:
    ring = {name: public for name, public in trusted_keys.items() if key_id(public) == name}
    message = _pae(payload)
    accepted: set[str] = set()
    attempts = 0
    for signature in envelope.signatures:
        try:
            raw = base64.b64decode(signature.signature, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) != 64:
            continue
        hint = signature.key_id or ""
        for name in [hint] if hint in ring else sorted(ring):
            if name in accepted:
                continue
            if attempts >= MAX_SIGNATURE_ATTEMPTS:
                return accepted
            attempts += 1
            try:
                ring[name].verify(raw, message)
            except InvalidSignature:
                continue
            accepted.add(name)
            break
    return accepted


def verify_contract(
    envelope: Envelope,
    kind: Kind,
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    threshold: int = 1,
) -> tuple[AnyContract, set[str]]:
    _validate_threshold(threshold)
    if not trusted_keys:
        raise AuthorizationError(
            "purpose-specific trusted keys required",
            reason="configuration-invalid",
        )
    try:
        payload = base64.b64decode(envelope.payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuthorizationError(
            "envelope payload is not base64", reason="envelope-invalid"
        ) from exc
    if len(payload) > MAX_STATEMENT_BYTES:
        raise AuthorizationError("statement exceeds limit", reason="statement-too-large")
    accepted = _accepted_signers(envelope, payload, trusted_keys)
    if len(accepted) < threshold:
        raise AuthorizationError(
            "insufficient distinct trusted signers", reason="signers-insufficient"
        )
    try:
        statement = strict_json(payload)
    except AuthorizationError as exc:
        raise AuthorizationError("invalid in-toto statement", reason="statement-invalid") from exc
    if not isinstance(statement, dict) or set(statement) != {
        "_type",
        "predicateType",
        "subject",
        "predicate",
    }:
        raise AuthorizationError("invalid in-toto statement", reason="statement-invalid")
    if statement["_type"] != STATEMENT_TYPE or statement["predicateType"] != PREDICATES[kind]:
        raise AuthorizationError("statement purpose mismatch", reason="statement-purpose-mismatch")
    try:
        contract = CONTRACTS[kind].model_validate(statement["predicate"])
    except ValidationError as exc:
        # Field names only: the text would otherwise echo issuer-authored values to
        # whoever reads the library error, which the CLI already avoids.
        raise AuthorizationError(
            "contract validation failed; review fields: " + validation_fields(exc),
            reason="contract-invalid",
        ) from exc
    # One contract must have one digest: revocation and approval bind to the
    # canonical form, so a predicate encoded differently by another signer
    # would otherwise verify under a subject digest nothing can revoke.
    predicate_digest = digest(statement["predicate"])
    if predicate_digest != digest(contract.model_dump(mode="json")):
        raise AuthorizationError(
            "predicate is not in canonical contract form", reason="contract-not-canonical"
        )
    if statement["subject"] != [
        {"name": kind, "digest": {"sha256": predicate_digest.split(":", 1)[1]}}
    ]:
        raise AuthorizationError("subject digest mismatch", reason="subject-mismatch")
    return contract, accepted


def _verified(
    envelope: Envelope,
    kind: Kind,
    model: type[C],
    keys: Mapping[str, Ed25519PublicKey],
    threshold: int,
) -> tuple[C, set[str]]:
    contract, signers = verify_contract(envelope, kind, keys, threshold=threshold)
    if not isinstance(contract, model):
        raise AuthorizationError("unexpected contract", reason="statement-purpose-mismatch")
    return contract, signers


_RULES = {
    "validity_window": "contract rule: validity window",
    "duplicate_tool_grants": "contract rule: duplicate tool grant",
    "model_type": "input is not a JSON object",
}


def _field_names() -> frozenset[str]:
    names: set[str] = set()
    for model in (
        ApprovedSnapshot,
        ToolGrant,
        TrustStatus,
        ActionApproval,
        HostedModelAttestation,
        ExecutionContext,
        ToolCall,
        Envelope,
        EnvelopeSignature,
    ):
        for name, info in model.model_fields.items():
            names.add(name)
            if info.alias:
                names.add(info.alias)
    return frozenset(names)


def validation_fields(exc: ValidationError) -> str:
    """Name the invalid fields and contract rules without echoing any input value."""
    known = _field_names()
    invalid = set()
    for error in exc.errors(include_input=False, include_context=False, include_url=False):
        location = error["loc"]
        if not location:
            invalid.add(_RULES.get(error["type"], "contract rule"))
            continue
        parts: list[str] = []
        for part in location:
            if isinstance(part, int):
                continue
            if part not in known:
                parts.append("unsupported field")
                break
            parts.append(part)
        invalid.add(".".join(parts) or "unsupported field")
    return ", ".join(sorted(invalid))


def _validate_threshold(threshold: int) -> None:
    # Envelope admits at most 32 signatures. Reject bool and coercible values so
    # an operator's quorum policy has one unambiguous, achievable meaning.
    if type(threshold) is not int or not 1 <= threshold <= MAX_SIGNATURES:
        raise AuthorizationError(
            "quorum threshold must be an integer between 1 and 32",
            reason="configuration-invalid",
        )


def _validate_key_quorum(threshold: int, trusted_keys: Mapping[str, Ed25519PublicKey]) -> None:
    authorized = {
        identifier for identifier, public in trusted_keys.items() if identifier == key_id(public)
    }
    # An empty ring with the default threshold remains a disabled purpose, as
    # before. It can never verify a contract; an explicit larger quorum is a
    # configuration error. Aliases for the same key do not create more signers.
    if (trusted_keys or threshold > 1) and threshold > len(authorized):
        raise AuthorizationError(
            "quorum threshold exceeds distinct authorized signing keys",
            reason="configuration-invalid",
        )


def _window(
    contract: ValidWindow, now: datetime, maximum: timedelta, purpose: Purpose = "contract"
) -> None:
    if now.utcoffset() is None:
        raise AuthorizationError(
            "verification time must include timezone", reason="configuration-invalid"
        )
    if contract.not_after - contract.not_before > maximum:
        raise AuthorizationError(
            "contract validity exceeds local policy", reason=f"{purpose}-lifetime-exceeds-policy"
        )
    if now < contract.not_before:
        raise AuthorizationError("contract is not yet valid", reason=f"{purpose}-not-yet-valid")
    if now >= contract.not_after:
        raise AuthorizationError("contract has expired", reason=f"{purpose}-expired")


_VALIDATION_MESSAGES = {
    "arguments-invalid": "tool arguments do not satisfy the offline input schema",
    "schema-invalid": "offline input schema is invalid, unsupported or not resolvable offline",
    "validation-capacity": "offline input schema validation capacity is exhausted; retry later",
    "validation-timeout": "offline input schema validation timed out; retry later",
    "validation-unavailable": "offline input schema worker is unavailable",
    "validation-failed": "offline input schema validation failed or exceeded its budget",
}


def _validate_arguments(schema: Any, arguments: dict[str, Any]) -> None:
    try:
        validate_arguments(schema, arguments)
    except ValidationBudgetError as exc:
        reason = exc.reason if exc.reason in _VALIDATION_MESSAGES else "validation-failed"
        raise AuthorizationError(_VALIDATION_MESSAGES[reason], reason=reason) from exc


def tool_definition_digest(definition: Mapping[str, Any]) -> str:
    """Digest a served MCP tool descriptor under profile rfc8785-jcs-v2.

    The digest is the inventory's tool fingerprint, ``hash_tool_definition``:
    name, description (default ""), inputSchema when present, annotations (absent
    and empty are equal), and title, outputSchema and _meta only when present and
    not null, read with ``tool_definition_extensions``. A descriptor with any
    other field, or a title that is not a string or an outputSchema or _meta that
    is not an object, is refused instead of being hashed without it.
    """
    from nexus_symbiote.core.hashing import hash_tool_definition, tool_definition_extensions

    if set(definition) - set(DESCRIPTOR_FIELDS):
        raise AuthorizationError(
            f"descriptor uses fields unsupported by digest profile {DIGEST_PROFILE}",
            reason="descriptor-unsupported",
        )
    name = definition.get("name")
    if not isinstance(name, str) or not name:
        raise AuthorizationError(
            "served descriptor has no tool name", reason="descriptor-name-mismatch"
        )
    try:
        check_json_budget(dict(definition), maximum=MAX_SCHEMA_BYTES)
    except ValidationBudgetError as exc:
        if exc.reason == "json-budget-exceeded":
            raise AuthorizationError(
                "served descriptor exceeds the supported JSON budget",
                reason="descriptor-too-large",
            ) from exc
        raise AuthorizationError(
            "served descriptor is outside the canonical JSON domain",
            reason="descriptor-not-json",
        ) from exc
    description = definition.get("description", "")
    input_schema, annotations = definition.get("inputSchema"), definition.get("annotations")
    try:
        # The preimage equates an absent, null and empty annotations object, so another
        # falsy value, such as false or [], would otherwise digest as no annotations.
        if (
            (description is not None and not isinstance(description, str))
            or (input_schema is not None and not isinstance(input_schema, dict))
            or (annotations is not None and not isinstance(annotations, dict))
        ):
            raise ValueError("invalid tool fields")
        extensions = tool_definition_extensions(definition)
    except ValueError as exc:
        raise AuthorizationError(
            f"descriptor field types are unsupported by digest profile {DIGEST_PROFILE}",
            reason="descriptor-unsupported",
        ) from exc
    try:
        # A null description keeps the digest it always had, which the inventory computes too.
        return hash_tool_definition(
            name, definition.get("description", ""), input_schema, annotations, **extensions
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise AuthorizationError(
            "served descriptor is outside the canonical JSON domain",
            reason="descriptor-not-json",
        ) from exc


def _json_copy(value: Any) -> Any:
    """Copy JSON data without sharing containers, keeping key order and number spelling."""
    return json.loads(json.dumps(value, allow_nan=False))


def _check_arguments(arguments: dict[str, Any]) -> None:
    try:
        check_json_budget(arguments, maximum=MAX_ARGUMENT_BYTES, strict_integral_floats=True)
    except ValidationBudgetError as exc:
        if exc.reason == "json-number-out-of-range":
            raise AuthorizationError(
                "tool arguments contain an integer outside the I-JSON range of +/-(2**53 - 1); "
                "pass it as a string",
                reason="arguments-number-out-of-range",
            ) from exc
        if exc.reason == "json-invalid":
            raise AuthorizationError(
                "tool call is outside the canonical JSON domain", reason="arguments-not-json"
            ) from exc
        raise AuthorizationError(
            "tool arguments exceed the supported JSON budget", reason="arguments-too-large"
        ) from exc


def _isolated_call(call: ToolCall) -> tuple[ToolCall, bytes]:
    """Copy the call so no caller or adapter reference can change it, and canonicalize it.

    The copy keeps the arguments as sent (key order, 1.0 versus 1). The request
    digest is computed over the RFC 8785 form, in which those are equal.
    """
    _check_arguments(call.arguments)
    try:
        isolated = ToolCall.model_validate(_json_copy(call.model_dump(mode="json")))
        return isolated, canonical_bytes(isolated.model_dump(mode="json"))
    except (ValueError, TypeError, RuntimeError) as exc:
        raise AuthorizationError(
            "tool call is outside the canonical JSON domain", reason="arguments-not-json"
        ) from exc


def _canonical_call(request_bytes: bytes) -> ToolCall:
    """Parse the RFC 8785 form of a call, which a canonical gateway checks and executes.

    RFC 8785 writes integral numbers below 1e21 as integers, so a float of 2**53 or
    more becomes an integer outside I-JSON whose value can differ from the float's:
    2.0**60 is written 1152921504606847000. Such arguments are refused.
    """
    call = ToolCall.model_validate(json.loads(request_bytes))
    _check_arguments(call.arguments)
    return call


def contract_digest(contract: AnyContract | ExecutionContext) -> str:
    """Return the digest that revocation lists and approvals use for a contract or context."""
    return digest(contract.model_dump(mode="json"))


def request_digest(call: ToolCall) -> str:
    """Return the digest an approval binds for exactly this tool call."""
    return "sha256:" + hashlib.sha256(_isolated_call(call)[1]).hexdigest()


def bom_digest(bom: Mapping[str, Any]) -> str:
    """Return the companion-BOM digest a snapshot binds, within the BOM budget."""
    try:
        document = dict(bom)
    except (TypeError, ValueError) as exc:
        raise AuthorizationError(
            "companion BOM must be a JSON object", reason="bom-mismatch"
        ) from exc
    try:
        check_json_budget(
            document, maximum=MAX_BOM_BYTES, max_depth=MAX_BOM_DEPTH, max_nodes=MAX_BOM_NODES
        )
        return digest(document)
    except ValidationBudgetError as exc:
        if exc.reason == "json-budget-exceeded":
            raise AuthorizationError(
                "companion BOM exceeds the supported JSON budget", reason="bom-too-large"
            ) from exc
        raise AuthorizationError(
            "companion BOM does not match approved digest", reason="bom-mismatch"
        ) from exc
    except AuthorizationError as exc:
        raise AuthorizationError(
            "companion BOM does not match approved digest", reason="bom-mismatch"
        ) from exc


def _snapshot_scope(snapshot: ApprovedSnapshot) -> str:
    return "snapshot:" + digest([snapshot.tenant, snapshot.deployment_id, snapshot.agent_id])


def _refuse_shared_directory(info: os.stat_result) -> None:
    if info.st_mode & 0o002:
        raise AuthorizationError(
            "state database directory cannot be world-writable", reason="state-invalid"
        )
    # The sticky exception is compatible with stores shared by a trusted group.
    # A companion check cannot reserve an absent name for a later SQLite open.
    if info.st_mode & 0o020 and not info.st_mode & stat.S_ISVTX:
        raise AuthorizationError(
            "state database directory cannot be group-writable without the sticky bit",
            reason="state-invalid",
        )


def _refuse_planted_companions(parent_fd: int, name: str, uid: int | None) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            info = os.stat(name + suffix, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AuthorizationError(
                "state database journal cannot be inspected", reason="state-invalid"
            ) from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (uid is not None and info.st_uid != uid)
            or info.st_mode & 0o022
        ):
            raise AuthorizationError(
                "state database journal must be a singly linked regular file owned by the "
                "current user and writable only by its owner",
                reason="state-invalid",
            )


def _secure_existing(path: Path) -> tuple[int, int]:
    from nexus_symbiote.core.hashing import open_directory_nofollow

    uid = getattr(os, "geteuid", lambda: None)()
    try:
        parent_fd = open_directory_nofollow(path.parent)
    except FileNotFoundError as exc:
        raise AuthorizationError(
            "state database does not exist; create it once with StateStore.initialize",
            reason="state-missing",
        ) from exc
    except OSError as exc:
        raise AuthorizationError(
            "state database parent directory cannot be a symlink or unavailable",
            reason="state-invalid",
        ) from exc
    try:
        parent_info = os.fstat(parent_fd)
        if uid is not None and parent_info.st_uid != uid:
            raise AuthorizationError(
                "state database directory must be owned by the current user",
                reason="state-invalid",
            )
        _refuse_shared_directory(parent_info)
        _refuse_planted_companions(parent_fd, path.name, uid)
        try:
            info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise AuthorizationError(
                "state database does not exist; create it once with StateStore.initialize",
                reason="state-missing",
            ) from exc
        except OSError as exc:
            raise AuthorizationError(
                "state database cannot be inspected", reason="state-invalid"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise AuthorizationError("state database cannot be a symlink", reason="state-invalid")
        if not stat.S_ISREG(info.st_mode):
            raise AuthorizationError(
                "state database must be a regular file", reason="state-invalid"
            )
        if info.st_nlink != 1:
            raise AuthorizationError(
                "state database cannot have other hard links", reason="state-invalid"
            )
        if uid is not None and info.st_uid != uid:
            raise AuthorizationError(
                "state database must be owned by the current user", reason="state-invalid"
            )
        if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            try:
                fd = os.open(
                    path.name,
                    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=parent_fd,
                )
                try:
                    os.fchmod(fd, 0o600)
                finally:
                    os.close(fd)
            except OSError as exc:
                raise AuthorizationError(
                    "state database permissions cannot be restricted", reason="state-invalid"
                ) from exc
        return (info.st_dev, info.st_ino)
    finally:
        os.close(parent_fd)


def _migrate(db: sqlite3.Connection) -> None:
    db.execute(
        "CREATE TABLE IF NOT EXISTS heads "
        "(scope TEXT PRIMARY KEY, serial INTEGER NOT NULL, digest TEXT NOT NULL)"
    )
    if "revoked_signers" not in {row[1] for row in db.execute("PRAGMA table_info(heads)")}:
        db.execute("ALTER TABLE heads ADD COLUMN revoked_signers TEXT")
    db.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY)")
    db.execute(
        "CREATE TABLE IF NOT EXISTS tenant_nonces "
        "(tenant TEXT NOT NULL, nonce TEXT NOT NULL, PRIMARY KEY (tenant, nonce))"
    )
    if "not_after" not in {row[1] for row in db.execute("PRAGMA table_info(tenant_nonces)")}:
        db.execute("ALTER TABLE tenant_nonces ADD COLUMN not_after INTEGER")
    db.execute("CREATE INDEX IF NOT EXISTS tenant_nonces_by_nonce ON tenant_nonces (nonce)")
    db.execute("CREATE INDEX IF NOT EXISTS tenant_nonces_by_expiry ON tenant_nonces (not_after)")
    db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('store_id', ?)", (secrets.token_hex(16),)
    )


def _is_recorded(old: Sequence[Any] | None, serial: int, value: str) -> bool:
    """Whether a snapshot head is already recorded; refuse an older or forked one."""
    if old is None or serial > old[0]:
        return False
    if serial < old[0]:
        raise AuthorizationError(
            "snapshot is superseded by a newer recorded snapshot",
            reason="snapshot-superseded",
        )
    if value != old[1]:
        raise AuthorizationError(
            "snapshot fork: another snapshot has this serial",
            reason="snapshot-fork",
        )
    return True


def _advance(db: sqlite3.Connection, scope: str, serial: int, value: str) -> None:
    old = db.execute("SELECT serial, digest FROM heads WHERE scope=?", (scope,)).fetchone()
    if not _is_recorded(old, serial, value):
        db.execute(
            "INSERT OR REPLACE INTO heads(scope,serial,digest) VALUES (?,?,?)",
            (scope, serial, value),
        )


class StateStore:
    """Durable check-and-record state shared by every gateway that opens this file.

    One-use approvals and snapshot and trust-status rollback protection hold per
    state file: gateways that do not share the file do not see each other's state.
    Create the file once with ``StateStore.initialize``. Opening a missing or
    uninitialised file is refused, so lost state is never mistaken for first use.
    The operator must protect the database path.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._inode = _secure_existing(self.path)
        with self._transaction() as db:
            tables = {
                row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if "heads" not in tables:
                raise AuthorizationError(
                    "state database is not initialized; create it with StateStore.initialize",
                    reason="state-missing",
                )
            _migrate(db)
            self.store_id: str = db.execute(
                "SELECT value FROM meta WHERE key='store_id'"
            ).fetchone()[0]

    @classmethod
    def initialize(cls, path: Path) -> StateStore:
        """Create a new, empty state database; refuse to replace an existing file."""
        from nexus_symbiote.core.hashing import open_directory_nofollow

        path = Path(path)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        uid = getattr(os, "geteuid", lambda: None)()
        try:
            missing: list[Path] = []
            probe = Path(os.path.abspath(path)).parent
            while not os.path.lexists(probe):
                missing.append(probe)
                if probe == probe.parent:
                    break
                probe = probe.parent
            dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            for component in reversed(missing):
                created = False
                try:
                    os.mkdir(component, 0o700)
                    created = True
                except FileExistsError:
                    # Another process created this ancestor directory concurrently; open_directory_nofollow verifies it below.
                    pass
                if created:
                    comp_fd = os.open(component, dir_flags)
                    try:
                        comp_info = os.fstat(comp_fd)
                        if uid is not None and comp_info.st_uid != uid:
                            raise AuthorizationError(
                                "state database directory must be owned by the current user",
                                reason="state-invalid",
                            )
                        os.fchmod(comp_fd, 0o700)
                    finally:
                        os.close(comp_fd)
            parent_fd = open_directory_nofollow(path.parent)
            try:
                parent_info = os.fstat(parent_fd)
                if uid is not None and parent_info.st_uid != uid:
                    raise AuthorizationError(
                        "state database directory must be owned by the current user",
                        reason="state-invalid",
                    )
                _refuse_shared_directory(parent_info)
                _refuse_planted_companions(parent_fd, path.name, uid)
                os.close(os.open(path.name, flags, 0o600, dir_fd=parent_fd))
            finally:
                os.close(parent_fd)
        except AuthorizationError:
            raise
        except FileExistsError as exc:
            raise AuthorizationError(
                "state database already exists; open it instead of initializing it",
                reason="state-invalid",
            ) from exc
        except OSError as exc:
            raise AuthorizationError(
                "state database could not be created", reason="state-invalid"
            ) from exc
        try:
            with closing(_connect(path)) as db:
                db.execute("BEGIN IMMEDIATE")
                _migrate(db)
                db.execute("COMMIT")
        except BaseException as exc:
            # Remove what this call created, so that initializing again is possible.
            for suffix in ("", "-journal", "-wal", "-shm"):
                with suppress(OSError):
                    os.unlink(f"{path}{suffix}")
            if isinstance(exc, sqlite3.Error):
                raise AuthorizationError(
                    "state database could not be initialized", reason="state-unavailable"
                ) from exc
            raise
        return cls(path)

    def _check_path_binding(self) -> None:
        from nexus_symbiote.core.hashing import open_directory_nofollow

        expected_inode = getattr(self, "_inode", None)
        if expected_inode is None:
            return
        uid = getattr(os, "geteuid", lambda: None)()
        abs_path = Path(os.path.abspath(self.path))
        try:
            parent_fd = open_directory_nofollow(self.path.parent)
        except FileNotFoundError as exc:
            if any(os.path.islink(parent) for parent in abs_path.parents):
                raise AuthorizationError(
                    "state database cannot be a symlink", reason="state-invalid"
                ) from None
            raise AuthorizationError(
                "state database identity changed; open the replacement store explicitly",
                reason="state-unavailable",
            ) from exc
        except OSError as exc:
            raise AuthorizationError(
                "state database parent directory cannot be a symlink or unavailable",
                reason="state-invalid",
            ) from exc
        try:
            parent_info = os.fstat(parent_fd)
            if uid is not None and parent_info.st_uid != uid:
                raise AuthorizationError(
                    "state database directory must be owned by the current user",
                    reason="state-invalid",
                )
            _refuse_shared_directory(parent_info)
            _refuse_planted_companions(parent_fd, self.path.name, uid)
            try:
                info = os.stat(self.path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise AuthorizationError(
                    "state database identity changed; open the replacement store explicitly",
                    reason="state-unavailable",
                ) from exc
            except OSError as exc:
                raise AuthorizationError(
                    "state database cannot be inspected", reason="state-invalid"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                raise AuthorizationError(
                    "state database cannot be a symlink", reason="state-invalid"
                )
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or (uid is not None and info.st_uid != uid)
                or (info.st_dev, info.st_ino) != expected_inode
            ):
                raise AuthorizationError(
                    "state database identity changed; open the replacement store explicitly",
                    reason="state-invalid",
                )
        finally:
            os.close(parent_fd)

    def _verify_store_id(self, db: sqlite3.Connection) -> None:
        expected = getattr(self, "store_id", None)
        if expected is None:
            return
        row = db.execute("SELECT value FROM meta WHERE key='store_id'").fetchone()
        if row is None or row[0] != expected:
            raise AuthorizationError(
                "state database identity changed; open the replacement store explicitly",
                reason="state-invalid",
            )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._check_path_binding()
        try:
            with closing(_connect(self.path)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                self._check_path_binding()
                self._verify_store_id(db)
                yield db
        except sqlite3.Error as exc:
            raise AuthorizationError(
                "state database is unavailable or locked", reason="state-unavailable"
            ) from exc

    def _head(self, scope: str) -> tuple[Any, ...] | None:
        self._check_path_binding()
        try:
            with closing(_connect(self.path)) as db:
                self._check_path_binding()
                self._verify_store_id(db)
                row = db.execute(
                    "SELECT serial, digest, revoked_signers FROM heads WHERE scope=?", (scope,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise AuthorizationError(
                "state database is unavailable or locked", reason="state-unavailable"
            ) from exc
        return cast("tuple[Any, ...] | None", row)

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
                raise AuthorizationError(
                    "archived trust status does not match the recorded head",
                    reason="trust-restore-required",
                )

    def accept_trust_status(
        self,
        status: TrustStatus,
        verified_signers: set[str],
        *,
        threshold: int = 1,
        check_time: Callable[[], set[str]] | None = None,
    ) -> tuple[str, int, str]:
        """Atomically authenticate a transition against the preceding tenant trust state."""
        _validate_threshold(threshold)
        scope = "trust:" + status.tenant
        head = (scope, status.serial, digest(status.model_dump(mode="json")))
        revoked = json.dumps(status.revoked_signers)
        eligible = verified_signers - set(status.revoked_signers)
        if len(eligible) < threshold:
            raise AuthorizationError(
                "trust status requires unrevoked signers", reason="trust-signer-revoked"
            )
        # Re-presenting the recorded status changes nothing, and a recorded status
        # only moves forward, so an older or forked one is refused from the read.
        # Neither takes the store-wide write lock.
        current = self._head(scope)
        if current == (status.serial, head[2], revoked):
            return head
        if current is not None and status.serial < current[0]:
            raise AuthorizationError("trust-status rollback", reason="trust-rollback")
        if current is not None and status.serial == current[0] and head[2] != current[1]:
            raise AuthorizationError("trust-status fork", reason="trust-fork")
        with self._transaction() as db:
            old = db.execute(
                "SELECT serial, digest, revoked_signers FROM heads WHERE scope=?", (scope,)
            ).fetchone()
            if old:
                if status.serial < old[0]:
                    raise AuthorizationError("trust-status rollback", reason="trust-rollback")
                if status.serial == old[0] and head[2] != old[1]:
                    raise AuthorizationError("trust-status fork", reason="trust-fork")
                if old[2] is None:
                    if head[1:] != old[:2]:
                        raise AuthorizationError(
                            "restore the recorded trust status before advancing",
                            reason="trust-restore-required",
                        )
                elif len(eligible - set(json.loads(old[2]))) < threshold:
                    raise AuthorizationError(
                        "previously revoked trust-status signer", reason="trust-signer-revoked"
                    )
            if check_time is not None:
                # Scope expiry and the previous status's revocations must be
                # applied to the same signers, not to two different quorums.
                current_signers = check_time() & eligible
                previous_revocations = set(json.loads(old[2])) if old and old[2] else set()
                if len(current_signers - previous_revocations) < threshold:
                    raise AuthorizationError(
                        "too few current trust signers remain eligible",
                        reason="trust-signer-revoked",
                    )
            db.execute(
                "INSERT OR REPLACE INTO heads(scope,serial,digest,revoked_signers) VALUES (?,?,?,?)",
                (*head, revoked),
            )
        return head

    def advance_snapshot(
        self,
        scope: str,
        serial: int,
        value: str,
        *,
        trust_head: tuple[str, int, str] | None = None,
        check_time: Callable[[], None] | None = None,
    ) -> None:
        """Record a verified snapshot as current for its agent, retiring lower serials."""
        if not scope.startswith("snapshot:"):
            raise AuthorizationError(
                "only snapshot heads advance here", reason="configuration-invalid"
            )
        # Heads only move forward, so a recorded, superseded or forked snapshot is
        # settled by a read, without the store-wide write lock.
        if _is_recorded(self._head(scope), serial, value) and trust_head is None:
            return
        with self._transaction() as db:
            if trust_head is not None:
                trust_scope, trust_serial, trust_digest = trust_head
                old = db.execute(
                    "SELECT serial, digest FROM heads WHERE scope=?", (trust_scope,)
                ).fetchone()
                if not trust_scope.startswith("trust:") or old != (trust_serial, trust_digest):
                    raise AuthorizationError(
                        "trust status changed before snapshot admission", reason="trust-superseded"
                    )
            if check_time is not None:
                check_time()
            _advance(db, scope, serial, value)

    def record(
        self,
        heads: tuple[tuple[str, int, str], ...],
        nonce: str | None = None,
        *,
        tenant: str | None = None,
        not_after: datetime | None = None,
        check_time: Callable[[], None] | None = None,
        now: datetime | None = None,
    ) -> None:
        # The presented expiry must not choose which rows are deleted. A caller of
        # record() can name an expiry; the retention watermark is this clock, and an
        # approval nonce may not claim an expiry further ahead than its lifetime.
        clock = datetime.now(UTC) if now is None else now
        if not_after is not None and not_after > clock + MAX_LIFETIMES["approval"]:
            raise AuthorizationError(
                "approval expiry is more than 5 minutes ahead",
                reason="approval-lifetime-exceeds-policy",
            )
        with self._transaction() as db:
            for scope, serial, value in heads:
                if scope.startswith("trust:"):
                    # Only accept_trust_status may advance this head or change issuer eligibility.
                    old = db.execute(
                        "SELECT serial, digest FROM heads WHERE scope=?", (scope,)
                    ).fetchone()
                    if old != (serial, value):
                        raise AuthorizationError(
                            "trust-status rollback/fork or missing trust state",
                            reason="trust-superseded",
                        )
                    continue
                _advance(db, scope, serial, value)
            if nonce is not None:
                # Rows consumed before nonces were tenant-scoped stay consumed for every
                # tenant, so an upgrade can never resurrect a used nonce. A use without a
                # tenant is store-wide, so it conflicts with every tenant's earlier use.
                legacy = db.execute("SELECT 1 FROM nonces WHERE nonce=?", (nonce,)).fetchone()
                if legacy is None and tenant is None:
                    legacy = db.execute(
                        "SELECT 1 FROM tenant_nonces WHERE nonce=?", (nonce,)
                    ).fetchone()
                expires = None if not_after is None else int(not_after.timestamp())
                try:
                    if legacy is not None:
                        raise sqlite3.IntegrityError("legacy nonce")
                    if tenant is None:
                        db.execute("INSERT INTO nonces(nonce) VALUES (?)", (nonce,))
                    else:
                        db.execute(
                            "INSERT INTO tenant_nonces(tenant, nonce, not_after) VALUES (?, ?, ?)",
                            (tenant, nonce, expires),
                        )
                except sqlite3.IntegrityError as exc:
                    raise AuthorizationError(
                        "approval nonce has already been used", reason="approval-replayed"
                    ) from exc
                if expires is not None:
                    # Keep a used nonce until it is older than the retention window
                    # measured from this clock, not from the expiry just presented.
                    # A far-future expiry would otherwise delete another tenant's
                    # nonce that is still inside the window. The row just inserted
                    # always survives, so a stale expiry cannot be recorded twice.
                    # Rows with no expiry stay: SQL does not treat NULL as less than
                    # the cutoff.
                    watermark = min(int(clock.timestamp()), expires)
                    cutoff = watermark - int(NONCE_RETENTION.total_seconds())
                    db.execute(
                        "DELETE FROM tenant_nonces WHERE not_after < ?",
                        (cutoff,),
                    )
            if check_time is not None:
                # The write lock may have taken longer than the remaining approval lifetime.
                check_time()


def _connect(path: Path) -> sqlite3.Connection:
    # mode=rw never creates the file, so a database removed while a gateway runs is
    # an error instead of a silently empty store.
    uri = Path(os.path.abspath(path)).as_uri() + "?mode=rw"
    return sqlite3.connect(uri, uri=True, timeout=10, isolation_level=None)


def _validate_rings(
    rings: Sequence[tuple[str, Mapping[str, Ed25519PublicKey]]],
    scopes: Mapping[str, SignerScope],
    allow_shared_keys: bool,
) -> None:
    purposes: dict[str, set[str]] = {}
    for purpose, keys in rings:
        for public in keys.values():
            purposes.setdefault(key_id(public), set()).add(purpose)
    if not allow_shared_keys and any(len(found) > 1 for found in purposes.values()):
        raise AuthorizationError(
            "a signing key appears in more than one purpose ring; use one key per purpose "
            "or pass allow_shared_keys=True",
            reason="configuration-invalid",
        )
    if set(scopes) - set(purposes):
        raise AuthorizationError(
            "a signer scope names a key that is in no ring", reason="configuration-invalid"
        )


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
        signer_scopes: Mapping[str, SignerScope] | None = None,
        allow_shared_keys: bool = False,
        on_decision: Callable[[Decision], None] | None = None,
        canonical_arguments: bool = True,
    ) -> None:
        for threshold, keys in (
            (snapshot_threshold, snapshot_keys),
            (approval_threshold, approval_keys),
            (trust_threshold, trust_keys),
        ):
            _validate_threshold(threshold)
            _validate_key_quorum(threshold, keys)
        _validate_rings(
            (("snapshot", snapshot_keys), ("approval", approval_keys), ("trust", trust_keys)),
            signer_scopes or {},
            allow_shared_keys,
        )
        actors = dict(approval_actors or {})
        if any(not isinstance(actor, str) or not actor.strip() for actor in actors.values()):
            raise AuthorizationError(
                "approval actor names must be nonempty strings",
                reason="configuration-invalid",
            )
        approvers = {
            actors.get(name) for name, public in approval_keys.items() if key_id(public) == name
        }
        if approval_threshold > len(approvers - {None}) and (
            approval_threshold > 1 or (approval_actors is not None and bool(approval_keys))
        ):
            raise AuthorizationError(
                "approval quorum exceeds the number of distinct approvers",
                reason="configuration-invalid",
            )
        self.snapshot_keys = dict(snapshot_keys)
        self.approval_keys = dict(approval_keys)
        self.trust_keys = dict(trust_keys)
        self.snapshot_threshold = snapshot_threshold
        self.approval_threshold = approval_threshold
        self.trust_threshold = trust_threshold
        self.state = state
        self.authenticate = authenticate
        self.describe = describe
        self._prepare: Callable[[Mapping[str, Any]], None] | None = None
        self.resolve_scope = resolve_scope
        self.execute = execute
        self.approval_actors = actors
        self.clock = clock or (lambda: datetime.now(UTC))
        self.signer_scopes = dict(signer_scopes or {})
        self.allow_shared_keys = allow_shared_keys
        self.on_decision = on_decision
        self.canonical_arguments = canonical_arguments

    @staticmethod
    def registrar(
        *,
        snapshot_keys: Mapping[str, Ed25519PublicKey],
        trust_keys: Mapping[str, Ed25519PublicKey],
        state: StateStore,
        approval_keys: Mapping[str, Ed25519PublicKey] | None = None,
        snapshot_threshold: int = 1,
        trust_threshold: int = 1,
        signer_scopes: Mapping[str, SignerScope] | None = None,
        allow_shared_keys: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> ReferenceGateway[NoReturn]:
        """Return a gateway that only registers snapshots, for an issuance pipeline.

        It needs no adapters, and ``invoke`` on it is refused. Give it the rings,
        quorums and signer scopes of the gateways that share ``state``;
        ``approval_keys`` is only checked, so one scope map can serve both.
        """

        def no_adapter(*_: object) -> NoReturn:
            raise AuthorizationError(
                "this gateway only registers snapshots", reason="configuration-invalid"
            )

        return ReferenceGateway(
            snapshot_keys=snapshot_keys,
            approval_keys=approval_keys or {},
            trust_keys=trust_keys,
            state=state,
            authenticate=no_adapter,
            describe=no_adapter,
            resolve_scope=no_adapter,
            execute=no_adapter,
            clock=clock,
            snapshot_threshold=snapshot_threshold,
            trust_threshold=trust_threshold,
            signer_scopes=signer_scopes,
            allow_shared_keys=allow_shared_keys,
        )

    def bind_adapters(
        self,
        *,
        describe: Callable[[str, str], ServedTool],
        execute: Callable[[ToolCall], U],
        prepare: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> ReferenceGateway[U]:
        """Bind adapters and optional preparation before recording the approval."""
        bound = cast("ReferenceGateway[U]", copy.copy(self))
        bound.describe = describe
        bound.execute = execute
        bound._prepare = prepare
        return bound

    def check_validation_worker(self) -> None:
        """Run one trivial schema validation; call it at start-up or from a readiness probe."""
        _validate_arguments({"type": "object"}, {})

    def register_snapshot(self, snapshot: Envelope, *, trust: Envelope) -> ApprovedSnapshot:
        """Make a newly issued snapshot current for its agent without invoking a tool.

        The snapshot and trust status are checked as ``invoke`` checks them, except
        the workload context and companion BOM. Lower serials for the same tenant,
        deployment and agent are denied from then on by every gateway that shares
        this state file.
        """
        timestamp = self.clock()
        approved, signers = self._verify_snapshot(snapshot, timestamp)
        statuses, trust_signers, trust_head = self._accept_trust(trust, approved.tenant, timestamp)
        self._admit_snapshot(approved, signers, statuses, trust_signers, trust_head, timestamp)
        return approved

    def invoke(
        self,
        call: ToolCall,
        *,
        snapshot: Envelope,
        trust: Envelope,
        bom: Mapping[str, Any],
        approval: Envelope | None = None,
    ) -> T:
        timestamp = self.clock()
        facts: dict[str, Any] = {
            "time": timestamp,
            "server_id": call.server_id,
            "tool_name": call.tool_name,
            "action": call.action,
            "resource": call.resource,
            "store_id": getattr(self.state, "store_id", None),
        }
        try:
            admitted = self._authorize(
                call,
                snapshot=snapshot,
                trust=trust,
                bom=bom,
                approval=approval,
                timestamp=timestamp,
                facts=facts,
            )
        except AuthorizationError as exc:
            self._decide(facts, exc.reason)
            raise
        except Exception:
            self._decide(facts, "adapter-error")
            raise
        self._decide(facts, "admitted")
        return self.execute(admitted)

    def _decide(self, facts: dict[str, Any], reason: str) -> None:
        if self.on_decision is not None:
            self.on_decision(Decision(admitted=reason == "admitted", reason=reason, **facts))

    def _scoped(
        self,
        signers: set[str],
        threshold: int,
        at: datetime,
        *,
        tenant: str,
        deployment: str | None = None,
        agent: str | None = None,
        tools: Sequence[tuple[str, str]] = (),
    ) -> set[str]:
        allowed = {
            signer
            for signer in signers
            if signer not in self.signer_scopes
            or self.signer_scopes[signer].permits(
                at=at, tenant=tenant, deployment=deployment, agent=agent, tools=tools
            )
        }
        if len(allowed) < threshold:
            raise AuthorizationError(
                "too few signers are authorized for this tenant, deployment, agent or tool",
                reason="signers-out-of-scope",
            )
        return allowed

    def _accept_trust(
        self, trust: Envelope, tenant: str, timestamp: datetime
    ) -> tuple[TrustStatus, set[str], tuple[str, int, str]]:
        statuses, signers = _verified(
            trust, "trust", TrustStatus, self.trust_keys, self.trust_threshold
        )
        _window(statuses, timestamp, MAX_LIFETIMES["trust"], "trust")
        if statuses.tenant != tenant:
            raise AuthorizationError("trust status tenant mismatch", reason="trust-tenant-mismatch")
        unrevoked = signers - set(statuses.revoked_signers)
        if len(unrevoked) < self.trust_threshold:
            raise AuthorizationError(
                "trust status requires unrevoked signers", reason="trust-signer-revoked"
            )
        scoped = self._scoped(unrevoked, self.trust_threshold, timestamp, tenant=tenant)

        def check_time() -> set[str]:
            now = self.clock()
            _window(statuses, now, MAX_LIFETIMES["trust"], "trust")
            return self._scoped(scoped, self.trust_threshold, now, tenant=tenant)

        return (
            statuses,
            scoped,
            self.state.accept_trust_status(
                statuses, scoped, threshold=self.trust_threshold, check_time=check_time
            ),
        )

    def _verify_snapshot(
        self, snapshot: Envelope, timestamp: datetime
    ) -> tuple[ApprovedSnapshot, set[str]]:
        approved, signers = _verified(
            snapshot, "snapshot", ApprovedSnapshot, self.snapshot_keys, self.snapshot_threshold
        )
        _window(approved, timestamp, MAX_LIFETIMES["snapshot"], "snapshot")
        return approved, signers

    def _admit_snapshot(
        self,
        approved: ApprovedSnapshot,
        signers: set[str],
        statuses: TrustStatus,
        trust_signers: set[str],
        trust_head: tuple[str, int, str],
        timestamp: datetime,
    ) -> tuple[str, set[str]]:
        """Admit a verified snapshot: its digest and the signers that count toward it.

        The trust signers were checked for revocation when the trust status was accepted.
        """
        snapshot_digest = digest(approved.model_dump(mode="json"))
        if snapshot_digest in statuses.revoked_snapshots:
            raise AuthorizationError("snapshot is revoked", reason="snapshot-revoked")
        unrevoked_snapshot = signers - set(statuses.revoked_signers)
        if len(unrevoked_snapshot) < self.snapshot_threshold:
            raise AuthorizationError("a snapshot signer is revoked", reason="signer-revoked")
        counted = self._scoped(
            unrevoked_snapshot,
            self.snapshot_threshold,
            timestamp,
            tenant=approved.tenant,
            deployment=approved.deployment_id,
            agent=approved.agent_id,
            tools=[(grant.server_id, grant.tool_name) for grant in approved.tools],
        )

        # A newer authentic snapshot retires older ones as soon as it is seen, even
        # when the call that presented it is denied later.
        def check_time() -> None:
            now = self.clock()
            _window(statuses, now, MAX_LIFETIMES["trust"], "trust")
            _window(approved, now, MAX_LIFETIMES["snapshot"], "snapshot")
            self._scoped(trust_signers, self.trust_threshold, now, tenant=approved.tenant)
            self._scoped(
                unrevoked_snapshot,
                self.snapshot_threshold,
                now,
                tenant=approved.tenant,
                deployment=approved.deployment_id,
                agent=approved.agent_id,
                tools=[(grant.server_id, grant.tool_name) for grant in approved.tools],
            )

        self.state.advance_snapshot(
            _snapshot_scope(approved),
            approved.serial,
            snapshot_digest,
            trust_head=trust_head,
            check_time=check_time,
        )
        return snapshot_digest, counted

    def _authorize(
        self,
        call: ToolCall,
        *,
        snapshot: Envelope,
        trust: Envelope,
        bom: Mapping[str, Any],
        approval: Envelope | None,
        timestamp: datetime,
        facts: dict[str, Any],
    ) -> ToolCall:
        call, request_bytes = _isolated_call(call)
        request_digest = "sha256:" + hashlib.sha256(request_bytes).hexdigest()
        facts["request_digest"] = request_digest
        if self.canonical_arguments:
            # The scope resolver and the schema check then judge exactly the form the
            # executor receives and the request digest binds.
            call = _canonical_call(request_bytes)
        context = self.authenticate()
        facts.update(
            tenant=context.tenant,
            deployment_id=context.deployment_id,
            agent_id=context.agent_id,
            workload_identity=context.workload_identity,
        )
        statuses, trust_signers, trust_head = self._accept_trust(trust, context.tenant, timestamp)
        facts.update(
            trust_serial=statuses.serial,
            trust_digest=trust_head[2],
            trust_signers=tuple(sorted(trust_signers)),
        )
        approved, snapshot_signers = self._verify_snapshot(snapshot, timestamp)
        facts.update(
            snapshot_serial=approved.serial, snapshot_signers=tuple(sorted(snapshot_signers))
        )
        expected = ExecutionContext(
            **{name: getattr(approved, name) for name in ExecutionContext.model_fields}
        )
        if context != expected:
            raise AuthorizationError(
                "workload, deployment, tenant, agent or policy mismatch", reason="context-mismatch"
            )
        snapshot_digest, counted = self._admit_snapshot(
            approved, snapshot_signers, statuses, trust_signers, trust_head, timestamp
        )
        facts.update(snapshot_digest=snapshot_digest, snapshot_signers=tuple(sorted(counted)))
        if bom_digest(bom) != approved.bom_digest:
            raise AuthorizationError(
                "companion BOM does not match approved digest", reason="bom-mismatch"
            )
        # Pydantic's frozen models do not freeze nested dictionaries. Give the
        # resolver an independent request so it cannot retain a reference to the
        # authorized arguments and change them later, after approval is checked.
        scope_call = ToolCall.model_validate(_json_copy(call.model_dump(mode="json")))
        effective = self.resolve_scope(scope_call)
        try:
            unchanged = canonical_bytes(scope_call.model_dump(mode="json")) == request_bytes
        except ValueError:
            unchanged = False
        if not unchanged:
            raise AuthorizationError(
                "scope resolver modified the request", reason="resolver-modified-request"
            )
        if effective != (call.action, call.resource):
            raise AuthorizationError(
                "operation labels do not match the actual tool arguments", reason="scope-mismatch"
            )
        grant = next(
            (
                g
                for g in approved.tools
                if (g.server_id, g.tool_name) == (call.server_id, call.tool_name)
            ),
            None,
        )
        if grant is None:
            raise AuthorizationError(
                "tool is outside approved capability: the snapshot does not grant it",
                reason="tool-not-granted",
            )
        if call.action not in grant.actions or call.resource not in grant.resources:
            raise AuthorizationError(
                "action/resource is outside approved capability", reason="capability-denied"
            )
        if grant.definition_digest in statuses.revoked_tools:
            raise AuthorizationError("tool is revoked", reason="tool-revoked")
        if grant.endpoint_identity in statuses.revoked_endpoints:
            raise AuthorizationError("endpoint is revoked", reason="endpoint-revoked")
        served = self.describe(call.server_id, call.tool_name)
        if served.endpoint_identity != grant.endpoint_identity:
            raise AuthorizationError(
                "authenticated endpoint differs from the approved grant",
                reason="endpoint-mismatch",
            )
        try:
            check_json_budget(served.definition, maximum=MAX_SCHEMA_BYTES)
            definition = _json_copy(served.definition)
        except ValidationBudgetError as exc:
            reason = (
                "descriptor-too-large"
                if exc.reason == "json-budget-exceeded"
                else "descriptor-not-json"
            )
            raise AuthorizationError(
                "served descriptor is outside the supported JSON budget", reason=reason
            ) from exc
        except (ValueError, TypeError, RuntimeError, RecursionError) as exc:
            raise AuthorizationError(
                "served descriptor cannot be copied within its JSON budget",
                reason="descriptor-not-json",
            ) from exc
        if definition.get("name") != call.tool_name:
            raise AuthorizationError(
                "served tool name differs from the requested tool",
                reason="descriptor-name-mismatch",
            )
        if tool_definition_digest(definition) != grant.definition_digest:
            raise AuthorizationError(
                "served descriptor changed since approval", reason="descriptor-changed"
            )
        consent: ActionApproval | None = None
        approval_signers: set[str] = set()
        if grant.require_approval:
            consent, approval_signers = self._check_approval(
                approval,
                statuses=statuses,
                snapshot_digest=snapshot_digest,
                context=context,
                call=call,
                request_digest=request_digest,
                timestamp=timestamp,
                facts=facts,
            )
        _validate_arguments(definition.get("inputSchema"), call.arguments)
        if self._prepare is not None:
            self._prepare(definition)
        if self.authenticate() != context:
            raise AuthorizationError(
                "execution identity changed during authorization", reason="identity-changed"
            )

        def check_time() -> None:
            final_time = self.clock()
            _window(approved, final_time, MAX_LIFETIMES["snapshot"], "snapshot")
            _window(statuses, final_time, MAX_LIFETIMES["trust"], "trust")
            self._scoped(trust_signers, self.trust_threshold, final_time, tenant=context.tenant)
            self._scoped(
                counted,
                self.snapshot_threshold,
                final_time,
                tenant=context.tenant,
                deployment=context.deployment_id,
                agent=context.agent_id,
                tools=[(g.server_id, g.tool_name) for g in approved.tools],
            )
            if consent is not None:
                _window(consent, final_time, MAX_LIFETIMES["approval"], "approval")
                scoped = self._scoped(
                    approval_signers,
                    self.approval_threshold,
                    final_time,
                    tenant=context.tenant,
                    deployment=context.deployment_id,
                    agent=context.agent_id,
                    tools=[(call.server_id, call.tool_name)],
                )
                self._approval_quorum(consent, scoped)

        self.state.record(
            ((_snapshot_scope(approved), approved.serial, snapshot_digest), trust_head),
            None if consent is None else consent.nonce,
            tenant=context.tenant,
            not_after=None if consent is None else consent.not_after,
            check_time=check_time,
            now=timestamp,
        )
        return call

    def _approval_quorum(self, consent: ActionApproval, scoped: set[str]) -> dict[str, str]:
        # The quorum counts people, not keys: two keys enrolled for one approver
        # are one approval, and the named actor must be one of the signers.
        bound = {
            signer: self.approval_actors[signer]
            for signer in scoped
            if self.approval_actors.get(signer) is not None
        }
        actors = set(bound.values())
        if len(bound) < self.approval_threshold or consent.actor not in actors:
            raise AuthorizationError(
                "approval actor is not bound to its authorized signing key",
                reason="approval-actor-unbound",
            )
        if len(actors) < self.approval_threshold:
            raise AuthorizationError(
                "approval quorum requires distinct approvers", reason="approval-quorum-not-met"
            )
        return bound

    def _check_approval(
        self,
        approval: Envelope | None,
        *,
        statuses: TrustStatus,
        snapshot_digest: str,
        context: ExecutionContext,
        call: ToolCall,
        request_digest: str,
        timestamp: datetime,
        facts: dict[str, Any],
    ) -> tuple[ActionApproval, set[str]]:
        if approval is None:
            raise AuthorizationError(
                "operation-bound approval required", reason="approval-required"
            )
        consent, signers = _verified(
            approval, "approval", ActionApproval, self.approval_keys, self.approval_threshold
        )
        facts.update(
            approval_digest=digest(consent.model_dump(mode="json")),
            approval_actor=consent.actor,
            approval_signers=tuple(sorted(signers)),
        )
        _window(consent, timestamp, MAX_LIFETIMES["approval"], "approval")
        unrevoked = signers - set(statuses.revoked_signers)
        if len(unrevoked) < self.approval_threshold:
            raise AuthorizationError("approver is revoked", reason="approver-revoked")
        scoped = self._scoped(
            unrevoked,
            self.approval_threshold,
            timestamp,
            tenant=context.tenant,
            deployment=context.deployment_id,
            agent=context.agent_id,
            tools=[(call.server_id, call.tool_name)],
        )
        bound = self._approval_quorum(consent, scoped)
        facts["approval_signers"] = tuple(sorted(bound))
        if consent.snapshot_digest != snapshot_digest:
            raise AuthorizationError(
                "approval does not cover this operation: it names another snapshot",
                reason="approval-snapshot-mismatch",
            )
        if consent.context_digest != digest(context.model_dump(mode="json")):
            raise AuthorizationError(
                "approval does not cover this operation: it names another execution context",
                reason="approval-context-mismatch",
            )
        if consent.request_digest != request_digest:
            raise AuthorizationError(
                "approval does not cover this operation: it names another request",
                reason="approval-request-mismatch",
            )
        return consent, unrevoked
