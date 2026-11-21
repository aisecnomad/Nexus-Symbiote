"""Signed attestations that bind a purpose to the exact bytes of one file, usually an inventory.

An attestation is a DSSE envelope whose payload is an in-toto Statement v1. Its single
subject is the file: an informational name and the SHA-256 of the file's exact bytes,
which is the binding. Its predicate records why the key holders signed: they produced
the file (``generated``) or reviewed it as a baseline (``reviewed``); when they signed,
by their own clock; an optional source revision they claim; and, when the file is a
native inventory this build reads, its format version and its run-independent content
digest (``nexus_symbiote.core.content_digest``), so a later collection of the same
content can be checked against a reviewed one.

Verification establishes that enough distinct trusted keys signed this statement, for
this purpose, over these bytes or this content. It does not establish that an inventory
is complete, accurate or safe, that it is the newest one the key holders signed, or who
holds a key. Signing is an explicit operator step; nothing here signs a scan result on
its own.

The envelope, the pre-authentication encoding, key IDs and the order of checks are
those of the runtime contracts (``nexus_symbiote.runtime``): signatures are verified
before the payload is parsed. The statement differs: its subject is a file, not a
contract digest. ``PREDICATE_TYPE`` is new and uses the repository's canonical
namespace; the runtime predicate types keep their original namespace on purpose.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, get_args

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from nexus_symbiote.core.aibom import AIBOM, MAX_NATIVE_BYTES
from nexus_symbiote.core.content_digest import INVENTORY_CONTENT_PROFILE, inventory_content_digest
from nexus_symbiote.core.hashing import hash_bytes, parse_json_strict
from nexus_symbiote.runtime import (
    MAX_SIGNATURES,
    MAX_STATEMENT_BYTES,
    STATEMENT_TYPE,
    AuthorizationError,
    ContractSigner,
    Envelope,
    EnvelopeSignature,
    _accepted_signers,
    _aware,
    _pae,
    canonical_bytes,
    digest,
    key_id,
    strict_json,
)
from nexus_symbiote.utils.terminal import neutralize

PREDICATE_TYPE = "https://github.com/Hunzee-VC/Nexus-Symbiote/attestation/inventory/v1"
NATIVE_FORMAT = "nexus-symbiote-aibom"
Purpose = Literal["generated", "reviewed", "policy"]
SubjectFormat = Literal["nexus-symbiote-aibom", "other"]
Match = Literal["bytes", "content"]
MAX_SUBJECT_NAME_CHARACTERS = 255
# Whether a file is a native inventory must follow from its bytes alone. Parsing and
# hashing recurse, so without an explicit bound the interpreter's recursion limit and
# the caller's stack would decide for a deeply nested file.
MAX_NATIVE_DEPTH = 256
# A complete envelope holds at most a 1 MiB statement in base64 and 32 signatures.
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_SUBJECT_BYTES = 64 * 1024 * 1024
CLOCK_SKEW = timedelta(minutes=5)

REASONS: dict[str, str] = {
    "configuration-invalid": "signers, trusted keys, threshold, purpose, match mode or age "
    "limit are invalid",
    "input-unreadable": "an input file is not a readable regular file reached without "
    "symbolic links",
    "input-too-large": "an input file exceeds its size limit",
    "key-invalid": "a key or passphrase file was refused",
    "envelope-invalid": "signed envelope is malformed",
    "statement-too-large": "signed statement exceeds the size limit",
    "signers-insufficient": "too few distinct trusted signers",
    "statement-invalid": "payload is not a valid inventory attestation statement",
    "statement-purpose-mismatch": "statement is not an inventory attestation",
    "predicate-invalid": "attestation predicate does not validate",
    "predicate-not-canonical": "attestation predicate is not in canonical form",
    "subject-mismatch": "file does not match the attested subject",
    "subject-not-inventory": "file is not a native inventory this build reads",
    "purpose-mismatch": "attestation was signed for another purpose",
    "attestation-not-yet-valid": "attestation is dated more than 5 minutes after the current time",
    "attestation-expired": "attestation is older than the maximum age",
    "content-digest-unavailable": "attestation records no content digest, so only the attested "
    "bytes can match",
}

_ENVELOPE_MEMBERS = frozenset({"payloadType", "payload", "signatures"})
_SIGNATURE_MEMBERS = frozenset({"keyid", "sig"})
_STATEMENT_MEMBERS = frozenset({"_type", "subject", "predicateType", "predicate"})
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_SURROGATE = re.compile("[\ud800-\udfff]")


class AttestationError(ValueError):
    """An attestation cannot be made or does not verify.

    ``reason`` is a stable code from REASONS and the message is its fixed text, which
    never contains envelope, key or file content.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(REASONS[reason])
        self.reason = reason


class InventoryPredicate(BaseModel):
    """The predicate of an inventory attestation, in the one form that verifies."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    purpose: Purpose
    signed_at: datetime
    subject_format: SubjectFormat
    spec_version: (
        Annotated[
            StrictStr,
            Field(pattern=r"^(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,5})$"),
        ]
        | None
    ) = None
    content_digest: Annotated[StrictStr, Field(pattern=r"^sha256:[0-9a-f]{64}$")] | None = None
    content_profile: Literal["nexus-symbiote/inventory-content/v1"] | None = None
    source_revision: (
        Annotated[StrictStr, Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")] | None
    ) = None

    @field_validator("signed_at")
    @classmethod
    def whole_seconds(cls, value: datetime) -> datetime:
        value = _aware(value)
        if value.microsecond:
            raise ValueError("signed_at must be a whole second")
        return value

    @model_validator(mode="after")
    def native_fields(self) -> InventoryPredicate:
        present = {
            value is not None
            for value in (self.spec_version, self.content_digest, self.content_profile)
        }
        if present != {self.subject_format == NATIVE_FORMAT}:
            raise PydanticCustomError(
                "native_fields",
                "spec_version, content_digest and content_profile are present exactly for "
                "a native inventory",
            )
        return self


@dataclass(frozen=True)
class VerifiedAttestation:
    """The facts a verified attestation establishes about one file.

    ``subject_sha256`` is the digest of the bytes verified and ``attested_sha256`` the
    one the statement records; they differ only when ``match`` is ``content``.
    """

    predicate: InventoryPredicate
    signers: tuple[str, ...]
    match: Match
    subject_sha256: str
    attested_sha256: str


def subject_name(name: str) -> str:
    """The informational subject name for a file name, as other tools may print it.

    Characters that can rewrite or disguise terminal and CI output are replaced, a
    "##name[" log command is broken as ``neutralize`` breaks it, lone surrogates from a
    name that is not UTF-8 are replaced, and the result is cut to 255 characters.
    """
    return _SURROGATE.sub("\ufffd", neutralize(name))[:MAX_SUBJECT_NAME_CHARACTERS]


def _nested_deeper_than(value: object, limit: int) -> bool:
    """Whether arrays and objects nest more than ``limit`` levels.

    Checked without recursion and with one iterator per open level, so memory grows
    with the depth, not with the number of values.
    """
    pending: list[Iterator[object]] = [iter((value,))]
    while pending:
        for item in pending[-1]:
            if isinstance(item, dict | list):
                if len(pending) > limit:
                    return True
                if item:
                    pending.append(iter(item.values() if isinstance(item, dict) else item))
                    break
        else:
            pending.pop()
    return False


def _native_facts(subject: bytes) -> tuple[str, str] | None:
    """The format version and content digest of a native inventory this build reads.

    The nesting is bounded lexically before ``json.loads`` and again on the parsed value
    before the strict parse and the content digest, which both serialize recursively.
    """
    from nexus_symbiote.core.hashing import MAX_JSON_NESTING, json_nesting_exceeds

    if len(subject) > MAX_NATIVE_BYTES:
        return None
    try:
        text = subject.decode("utf-8")
        if json_nesting_exceeds(text, MAX_JSON_NESTING):
            return None
        if _nested_deeper_than(json.loads(text), MAX_NATIVE_DEPTH):
            return None
        document = parse_json_strict(text, max_bytes=MAX_NATIVE_BYTES)
        if not isinstance(document, dict):
            return None
        content = inventory_content_digest(document)
        bom = AIBOM.from_native(document)
    except (ValueError, RecursionError):
        return None
    return bom.metadata.spec_version, content


def build_statement(
    subject: bytes,
    *,
    name: str,
    purpose: Purpose,
    signed_at: datetime,
    source_revision: str | None = None,
) -> dict[str, Any]:
    """The statement that attests ``subject`` for ``purpose``, ready for ``sign_statement``.

    ``signed_at`` must carry a timezone and be a whole second. The content digest is
    recorded when ``subject`` is a native inventory this build reads; ``name`` is
    informational and passes through ``subject_name``.
    """
    shown = subject_name(name)
    if not shown:
        raise AttestationError("statement-invalid")
    facts = _native_facts(subject)
    fields: dict[str, Any] = {
        "version": "1",
        "purpose": purpose,
        "signed_at": signed_at,
        "subject_format": "other" if facts is None else NATIVE_FORMAT,
        "source_revision": source_revision,
    }
    if facts is not None:
        fields.update(
            spec_version=facts[0],
            content_digest=facts[1],
            content_profile=INVENTORY_CONTENT_PROFILE,
        )
    try:
        predicate = InventoryPredicate.model_validate(fields)
    except ValidationError:
        raise AttestationError("predicate-invalid") from None
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": shown, "digest": {"sha256": _sha256_hex(subject)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate.model_dump(mode="json", exclude_none=True),
    }


def _sha256_hex(data: bytes) -> str:
    return hash_bytes(data).removeprefix("sha256:")


def _payload_value(payload: bytes) -> Any:
    try:
        return strict_json(payload.decode("utf-8"))
    except (UnicodeError, AuthorizationError):
        raise AttestationError("statement-invalid") from None


def _subject_digest(subject: object) -> str:
    """The SHA-256 of the statement's one subject, which must be as this module writes it."""
    if not isinstance(subject, list) or len(subject) != 1:
        raise AttestationError("statement-invalid")
    entry = subject[0]
    if not isinstance(entry, dict) or set(entry) != {"name", "digest"}:
        raise AttestationError("statement-invalid")
    name, digests = entry["name"], entry["digest"]
    if not isinstance(name, str) or not name or subject_name(name) != name:
        raise AttestationError("statement-invalid")
    if not isinstance(digests, dict) or set(digests) != {"sha256"}:
        raise AttestationError("statement-invalid")
    value = digests["sha256"]
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        raise AttestationError("statement-invalid")
    return value


def _statement(value: object) -> tuple[InventoryPredicate, str]:
    """Check a parsed statement; return its predicate and its subject's SHA-256."""
    if not isinstance(value, dict) or set(value) != _STATEMENT_MEMBERS:
        raise AttestationError("statement-invalid")
    if value["_type"] != STATEMENT_TYPE or value["predicateType"] != PREDICATE_TYPE:
        raise AttestationError("statement-purpose-mismatch")
    try:
        predicate = InventoryPredicate.model_validate(value["predicate"])
    except ValidationError:
        raise AttestationError("predicate-invalid") from None
    # One attestation has one predicate encoding: another spelling of the same time,
    # an explicit null or a number in place of a timestamp is refused, not normalized.
    if digest(value["predicate"]) != digest(predicate.model_dump(mode="json", exclude_none=True)):
        raise AttestationError("predicate-not-canonical")
    return predicate, _subject_digest(value["subject"])


def _signing_keys(
    signers: Sequence[ContractSigner],
) -> list[tuple[str, ContractSigner, Ed25519PublicKey]]:
    if not 1 <= len(signers) <= MAX_SIGNATURES:
        raise AttestationError("configuration-invalid")
    keys = []
    for signer in signers:
        public = signer.public_key()
        if not isinstance(public, Ed25519PublicKey):
            raise AttestationError("configuration-invalid")
        keys.append((key_id(public), signer, public))
    if len({name for name, _, _ in keys}) != len(keys):
        raise AttestationError("configuration-invalid")
    return sorted(keys, key=lambda entry: entry[0])


def sign_statement(statement: dict[str, Any], signers: Sequence[ContractSigner]) -> Envelope:
    """Sign the RFC 8785 form of ``statement`` with each of 1 to 32 distinct Ed25519 keys.

    The statement must pass every check that verification applies to it, so nothing is
    signed that could never verify. Each returned signature is verified before use, and
    signatures are ordered by key ID, so the envelope does not depend on signer order.
    """
    keys = _signing_keys(signers)
    try:
        payload = canonical_bytes(statement)
    except AuthorizationError:
        raise AttestationError("statement-invalid") from None
    if len(payload) > MAX_STATEMENT_BYTES:
        raise AttestationError("statement-too-large")
    _statement(_payload_value(payload))
    message = _pae(payload)
    signatures = []
    for name, signer, public in keys:
        raw = signer.sign(message)
        try:
            public.verify(raw, message)
        except (InvalidSignature, TypeError, ValueError):
            raise AttestationError("configuration-invalid") from None
        signatures.append(
            EnvelopeSignature(key_id=name, signature=base64.b64encode(raw).decode("ascii"))
        )
    return Envelope(payload=base64.b64encode(payload).decode("ascii"), signatures=tuple(signatures))


def parse_envelope(raw: bytes) -> Envelope:
    """Read a DSSE envelope that uses exactly the DSSE member names, as strict UTF-8 JSON."""
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise AttestationError("envelope-invalid")
    try:
        document = strict_json(raw.decode("utf-8"))
    except (UnicodeError, AuthorizationError):
        raise AttestationError("envelope-invalid") from None
    signatures = document.get("signatures") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or set(document) != _ENVELOPE_MEMBERS
        or not isinstance(signatures, list)
        or not all(
            isinstance(entry, dict) and "sig" in entry and set(entry) <= _SIGNATURE_MEMBERS
            for entry in signatures
        )
    ):
        raise AttestationError("envelope-invalid")
    try:
        return Envelope.model_validate(document)
    except ValidationError:
        raise AttestationError("envelope-invalid") from None


def _verification_time(
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    purpose: str,
    threshold: int,
    match: str,
    max_age: timedelta | None,
    now: datetime | None,
) -> datetime:
    """Refuse a configuration that is ambiguous or could never verify; return the time."""
    when = datetime.now(UTC) if now is None else now
    if (
        purpose not in get_args(Purpose)
        or match not in get_args(Match)
        or type(threshold) is not int
        or not 1 <= threshold <= MAX_SIGNATURES
        or threshold > len(trusted_keys)
        or not all(
            isinstance(public, Ed25519PublicKey) and key_id(public) == name
            for name, public in trusted_keys.items()
        )
        or (max_age is not None and (type(max_age) is not timedelta or max_age <= timedelta()))
        or not isinstance(when, datetime)
        or when.utcoffset() is None
    ):
        raise AttestationError("configuration-invalid")
    return when


def _same_content(predicate: InventoryPredicate, facts: tuple[str, str] | None) -> None:
    if facts is None:
        raise AttestationError("subject-not-inventory")
    spec_version, content = facts
    if spec_version != predicate.spec_version or not hmac.compare_digest(
        content, predicate.content_digest or ""
    ):
        raise AttestationError("subject-mismatch")


def verify_attestation(
    envelope: Envelope,
    subject: bytes,
    *,
    trusted_keys: Mapping[str, Ed25519PublicKey],
    purpose: Purpose,
    threshold: int = 1,
    match: Match = "bytes",
    max_age: timedelta | None = None,
    now: datetime | None = None,
) -> VerifiedAttestation:
    """Verify that trusted keys attested ``subject`` for ``purpose``; raise AttestationError.

    ``trusted_keys`` maps each key ID to its key; at least ``threshold`` distinct ones must
    have signed. With ``match="bytes"`` the subject must be the attested file; with
    ``"content"`` it must be a native inventory with the attested content digest. An
    attestation signed more than 5 minutes after ``now`` (default: the current time) is
    refused, and with ``max_age`` one signed longer ago than that.
    """
    when = _verification_time(
        trusted_keys, purpose=purpose, threshold=threshold, match=match, max_age=max_age, now=now
    )
    try:
        payload = base64.b64decode(envelope.payload, validate=True)
    except (binascii.Error, ValueError):
        raise AttestationError("envelope-invalid") from None
    if len(payload) > MAX_STATEMENT_BYTES:
        raise AttestationError("statement-too-large")
    accepted = _accepted_signers(envelope, payload, trusted_keys)
    if len(accepted) < threshold:
        raise AttestationError("signers-insufficient")
    predicate, attested = _statement(_payload_value(payload))
    actual = _sha256_hex(subject)
    if match == "bytes":
        if not hmac.compare_digest(actual, attested):
            raise AttestationError("subject-mismatch")
    elif predicate.content_digest is None:
        raise AttestationError("content-digest-unavailable")
    else:
        _same_content(predicate, _native_facts(subject))
    if predicate.purpose != purpose:
        raise AttestationError("purpose-mismatch")
    if predicate.signed_at - when > CLOCK_SKEW:
        raise AttestationError("attestation-not-yet-valid")
    if max_age is not None and when - predicate.signed_at > max_age:
        raise AttestationError("attestation-expired")
    if match == "bytes" and predicate.subject_format == NATIVE_FORMAT:
        _same_content(predicate, _native_facts(subject))
    return VerifiedAttestation(
        predicate=predicate,
        signers=tuple(sorted(accepted)),
        match=match,
        subject_sha256=actual,
        attested_sha256=attested,
    )
