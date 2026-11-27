"""Inventory attestations: known-answer vectors, every refusal and the configuration rules.

Envelopes for tampered statements are signed here with a DSSE pre-authentication encoding
written out independently of the library, so each refusal is reached with signatures that
trusted keys really made.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from nexus_symbiote import attestation
from nexus_symbiote.attestation import (
    MAX_ENVELOPE_BYTES,
    MAX_NATIVE_DEPTH,
    PREDICATE_TYPE,
    REASONS,
    AttestationError,
    build_statement,
    parse_envelope,
    sign_statement,
    subject_name,
    verify_attestation,
)
from nexus_symbiote.core.aibom import AIBOM, MAX_NATIVE_BYTES
from nexus_symbiote.core.content_digest import INVENTORY_CONTENT_PROFILE
from nexus_symbiote.runtime import (
    MAX_STATEMENT_BYTES,
    PREDICATES,
    Envelope,
    EnvelopeSignature,
    key_id,
)
from tests.support import scaling_ratio

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads(
    (ROOT / "tests" / "vectors" / "attestation" / "inventory-v1.json").read_text(encoding="utf-8")
)
TEST_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTORS["key"]["seed_hex"]))
SIGNED_AT = datetime(2026, 11, 12, 10, 0, tzinfo=UTC)
NOW = SIGNED_AT + timedelta(hours=1)
NATIVE = AIBOM().to_json().encode()
OTHER = b'{"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1}\n'
REVISION = "0123456789abcdef0123456789abcdef01234567"
A, B, C = (Ed25519PrivateKey.generate() for _ in range(3))


def ring(*keys):
    return {key_id(key.public_key()): key.public_key() for key in keys}


def pae(payload: bytes) -> bytes:
    return b"DSSEv1 28 application/vnd.in-toto+json %d %s" % (len(payload), payload)


def envelope_over(payload: bytes, *keys, hint: str | None = "") -> Envelope:
    """Sign exact payload bytes; hint "" names each signing key, None omits the key ID."""
    signatures = tuple(
        EnvelopeSignature(
            key_id=key_id(key.public_key()) if hint == "" else hint,
            signature=base64.b64encode(key.sign(pae(payload))).decode(),
        )
        for key in keys
    )
    return Envelope(payload=base64.b64encode(payload).decode(), signatures=signatures)


def signed(statement, *keys) -> Envelope:
    return envelope_over(rfc8785.dumps(statement), *(keys or (A,)))


def statement(subject=NATIVE, *, purpose="reviewed", signed_at=SIGNED_AT, **extra):
    return build_statement(
        subject, name="reviewed.json", purpose=purpose, signed_at=signed_at, **extra
    )


def verify(envelope, subject=NATIVE, *, keys=(A,), purpose="reviewed", **options):
    options.setdefault("now", NOW)
    return verify_attestation(
        envelope, subject, trusted_keys=ring(*keys), purpose=purpose, **options
    )


def refused(reason, call, *args, **kwargs):
    with pytest.raises(AttestationError) as raised:
        call(*args, **kwargs)
    assert raised.value.reason == reason
    # The message is the fixed text for the code, never input.
    assert str(raised.value) == REASONS[reason]
    return raised.value


# Known-answer vectors


def test_vector_key_is_the_published_runtime_test_key():
    runtime = json.loads((ROOT / "tests" / "vectors" / "runtime" / "contracts.json").read_text())
    assert VECTORS["key"] == runtime["key"]
    assert key_id(TEST_KEY.public_key()) == VECTORS["key"]["key_id"]
    assert VECTORS["predicate_type"] == PREDICATE_TYPE
    assert [
        vector["statement"]["predicate"]["subject_format"] for vector in VECTORS["attestations"]
    ] == [
        "nexus-symbiote-aibom",
        "other",
    ]


@pytest.mark.parametrize("vector", VECTORS["attestations"], ids=lambda vector: vector["name"])
def test_vector_statement_and_envelope_are_reproduced_byte_for_byte(vector):
    built = build_statement(
        vector["subject_text"].encode(),
        name=vector["subject_name"],
        purpose=vector["purpose"],
        signed_at=datetime.fromisoformat(vector["signed_at"]),
        source_revision=vector.get("source_revision"),
    )
    assert built == vector["statement"]
    envelope = sign_statement(built, [TEST_KEY])
    assert envelope.model_dump(mode="json", by_alias=True) == vector["envelope"]


def independent_content_digest(text: str) -> str:
    document = json.loads(text)
    for name in ("serial_number", "timestamp"):
        del document["metadata"][name]
    for component in document["components"]:
        for claim in component.get("claims", {}).values():
            del claim["observed_at"]
    return "sha256:" + hashlib.sha256(rfc8785.dumps(document)).hexdigest()


@pytest.mark.parametrize("vector", VECTORS["attestations"], ids=lambda vector: vector["name"])
def test_vector_envelope_verifies_independently_and_in_the_library(vector):
    wire = vector["envelope"]
    assert set(wire) == {"payloadType", "payload", "signatures"}
    assert wire["payloadType"] == "application/vnd.in-toto+json"
    payload = base64.b64decode(wire["payload"], validate=True)
    assert payload == rfc8785.dumps(vector["statement"])
    [signature] = wire["signatures"]
    assert signature["keyid"] == VECTORS["key"]["key_id"]
    public = serialization.load_pem_public_key(VECTORS["key"]["public_key_pem"].encode())
    public.verify(base64.b64decode(signature["sig"], validate=True), pae(payload))
    subject_bytes = vector["subject_text"].encode()
    expected = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": vector["subject_name"],
                "digest": {"sha256": hashlib.sha256(subject_bytes).hexdigest()},
            }
        ],
        "predicateType": "https://github.com/Hunzee-VC/Nexus-Symbiote/attestation/inventory/v1",
        "predicate": {
            "version": "1",
            "purpose": vector["purpose"],
            "signed_at": vector["signed_at"],
            "subject_format": vector["statement"]["predicate"]["subject_format"],
        },
    }
    if expected["predicate"]["subject_format"] == "nexus-symbiote-aibom":
        expected["predicate"] |= {
            "spec_version": "1.1.0",
            "content_digest": independent_content_digest(vector["subject_text"]),
            "content_profile": "nexus-symbiote/inventory-content/v1",
        }
    if "source_revision" in vector:
        expected["predicate"]["source_revision"] = vector["source_revision"]
    assert vector["statement"] == expected
    verified = verify_attestation(
        parse_envelope(json.dumps(wire).encode()),
        subject_bytes,
        trusted_keys=ring(TEST_KEY),
        purpose=vector["purpose"],
        now=NOW,
    )
    assert verified.signers == (VECTORS["key"]["key_id"],)
    assert (
        verified.subject_sha256
        == verified.attested_sha256
        == hashlib.sha256(subject_bytes).hexdigest()
    )


def test_content_profile_literal_is_the_profile_the_digest_module_computes():
    field = attestation.InventoryPredicate.model_fields["content_profile"]
    assert INVENTORY_CONTENT_PROFILE in repr(field.annotation)
    assert statement()["predicate"]["content_profile"] == INVENTORY_CONTENT_PROFILE


# Round trips


def test_native_inventory_round_trip_records_its_format_and_content_digest():
    built = statement(source_revision=REVISION)
    predicate = built["predicate"]
    assert predicate["subject_format"] == "nexus-symbiote-aibom"
    assert predicate["spec_version"] == "1.2.0"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", predicate["content_digest"])
    verified = verify(sign_statement(built, [A]))
    assert verified.predicate.source_revision == REVISION
    assert verified.signers == (key_id(A.public_key()),)
    assert verified.match == "bytes"
    assert verified.subject_sha256 == hashlib.sha256(NATIVE).hexdigest()


def test_other_file_round_trip_has_no_content_fields():
    built = statement(OTHER, purpose="generated")
    assert set(built["predicate"]) == {"version", "purpose", "signed_at", "subject_format"}
    assert built["predicate"]["subject_format"] == "other"
    verified = verify(sign_statement(built, [A]), OTHER, purpose="generated")
    assert verified.predicate.content_digest is None


def test_content_match_accepts_another_collection_of_the_same_content():
    # Another collection of the same content that records when it was collected.
    collected = AIBOM()
    collected.metadata.timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    later = collected.to_json().encode()
    assert later != NATIVE
    envelope = sign_statement(statement(), [A])
    refused("subject-mismatch", verify, envelope, later)
    verified = verify(envelope, later, match="content")
    assert verified.match == "content"
    assert verified.subject_sha256 == hashlib.sha256(later).hexdigest()
    assert verified.attested_sha256 == hashlib.sha256(NATIVE).hexdigest()


def test_threshold_two_of_three_counts_distinct_trusted_signers():
    envelope = sign_statement(statement(), [A, B])
    verified = verify(envelope, keys=(A, B, C), threshold=2)
    assert verified.signers == tuple(sorted(key_id(key.public_key()) for key in (A, B)))
    refused("signers-insufficient", verify, envelope, keys=(A, B, C), threshold=3)


def test_signature_order_follows_key_ids_not_signer_order():
    built = statement()
    first, second = sign_statement(built, [A, B]), sign_statement(built, [B, A])
    assert first == second
    names = [signature.key_id for signature in first.signatures]
    assert names == sorted(names)


# Signatures


def test_untrusted_wrong_and_missing_signatures_are_refused():
    built = statement()
    refused("signers-insufficient", verify, signed(built, B))
    refused("signers-insufficient", verify, signed(built, A), keys=(A, B), threshold=2)
    refused("signers-insufficient", verify, Envelope(payload=signed(built).payload, signatures=()))
    twice = signed(built, A, A)
    assert len(twice.signatures) == 2
    refused("signers-insufficient", verify, twice, keys=(A, B), threshold=2)


def test_key_id_hint_naming_another_trusted_key_is_not_tried_against_the_others():
    built = statement()
    envelope = envelope_over(rfc8785.dumps(built), A, hint=key_id(B.public_key()))
    refused("signers-insufficient", verify, envelope, keys=(A, B))
    for hint in (None, "kms-key-7", "f" * 64):
        unknown = envelope_over(rfc8785.dumps(built), A, hint=hint)
        assert verify(unknown, keys=(B, A)).signers == (key_id(A.public_key()),)


def test_reencoded_payload_without_a_new_signature_is_refused():
    envelope = signed(statement())
    pretty = json.dumps(json.loads(base64.b64decode(envelope.payload)), indent=2).encode()
    forged = Envelope(payload=base64.b64encode(pretty).decode(), signatures=envelope.signatures)
    refused("signers-insufficient", verify, forged)


def test_a_duplicate_member_in_an_otherwise_valid_statement_is_refused():
    valid = statement()
    body = rfc8785.dumps(valid)
    duplicated = body[:-1] + b',"predicate":' + rfc8785.dumps(valid["predicate"]) + b"}"
    assert verify(envelope_over(body, A))
    with pytest.raises(AttestationError):
        verify(envelope_over(duplicated, A))
    wire = signed(valid).model_dump(mode="json", by_alias=True)
    text = json.dumps(wire)
    raw = text[:-1] + ', "payload": ' + json.dumps(wire["payload"]) + "}"
    refused("envelope-invalid", parse_envelope, raw.encode())


def test_trusted_signers_may_serialize_the_statement_differently():
    pretty = json.dumps(statement(), indent=2, sort_keys=False).encode()
    assert pretty != rfc8785.dumps(statement())
    assert verify(envelope_over(pretty, A)).signers == (key_id(A.public_key()),)


def test_url_safe_base64_is_accepted_only_in_canonical_form():
    built = build_statement(NATIVE, name="a???.json", purpose="reviewed", signed_at=SIGNED_AT)
    wire = signed(built).model_dump(mode="json", by_alias=True)
    payload = base64.b64decode(wire["payload"])
    raw = base64.b64decode(wire["signatures"][0]["sig"])
    assert "/" in wire["payload"]
    wire["payload"] = base64.urlsafe_b64encode(payload).decode()
    assert "/" not in wire["payload"]
    wire["signatures"][0]["sig"] = base64.urlsafe_b64encode(raw).decode()
    assert verify(parse_envelope(json.dumps(wire).encode())).signers == (key_id(A.public_key()),)
    for noncanonical in ("QR==", "Q+-=", wire["payload"] + "\n"):
        value = dict(wire, payload=noncanonical)
        refused("envelope-invalid", parse_envelope, json.dumps(value).encode())
    signature = wire["signatures"][0]["sig"]
    assert signature.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    bits = signature[:-3] + alphabet[alphabet.index(signature[-3]) ^ 1] + "=="
    assert base64.urlsafe_b64decode(bits) == raw
    for noncanonical in (signature[:-2], bits):
        value = dict(wire, signatures=[{"keyid": None, "sig": noncanonical}])
        refused("envelope-invalid", parse_envelope, json.dumps(value).encode())


def test_envelope_built_without_validation_is_still_checked():
    unchecked = Envelope.model_construct(payload="not base64!", signatures=())
    refused("envelope-invalid", verify, unchecked)


def test_wrong_length_signatures_are_ignored():
    built = statement()
    short = EnvelopeSignature(
        key_id=key_id(A.public_key()), signature=base64.b64encode(bytes(63)).decode()
    )
    envelope = Envelope(payload=signed(built).payload, signatures=(short,))
    refused("signers-insufficient", verify, envelope)


# Statement and predicate


def mutated(change):
    value = copy.deepcopy(statement(source_revision=REVISION))
    change(value)
    return value


def set_predicate(**fields):
    def change(value):
        value["predicate"].update(fields)
        for name, field in fields.items():
            if field is None:
                del value["predicate"][name]

    return change


def other_with(**fields):
    def change(value):
        for name in ("spec_version", "content_digest", "content_profile"):
            del value["predicate"][name]
        value["predicate"]["subject_format"] = "other"
        value["predicate"].update(fields)

    return change


STATEMENT_REFUSALS = {
    "extra statement member": ("statement-invalid", lambda v: v.update(extra=1)),
    "missing statement member": ("statement-invalid", lambda v: v.pop("predicateType")),
    "statement type changed": (
        "statement-purpose-mismatch",
        lambda v: v.update(_type="https://in-toto.io/Statement/v0.1"),
    ),
    "runtime predicate type": (
        "statement-purpose-mismatch",
        lambda v: v.update(predicateType=PREDICATES["snapshot"]),
    ),
    "two subjects": ("statement-invalid", lambda v: v["subject"].append(v["subject"][0])),
    "no subject": ("statement-invalid", lambda v: v.update(subject=[])),
    "subject is an object": ("statement-invalid", lambda v: v.update(subject=v["subject"][0])),
    "extra subject member": ("statement-invalid", lambda v: v["subject"][0].update(uri="x")),
    "uppercase digest": (
        "statement-invalid",
        lambda v: v["subject"][0]["digest"].update(
            sha256=v["subject"][0]["digest"]["sha256"].upper()
        ),
    ),
    "short digest": (
        "statement-invalid",
        lambda v: v["subject"][0]["digest"].update(sha256=v["subject"][0]["digest"]["sha256"][:63]),
    ),
    "sha512 beside sha256": (
        "statement-invalid",
        lambda v: v["subject"][0]["digest"].update(sha512="0" * 128),
    ),
    "sha512 only": (
        "statement-invalid",
        lambda v: v["subject"][0].update(digest={"sha512": "0" * 128}),
    ),
    "digest is a string": ("statement-invalid", lambda v: v["subject"][0].update(digest="0" * 64)),
    "control character in name": (
        "statement-invalid",
        lambda v: v["subject"][0].update(name="a\x1b[31m"),
    ),
    "bidi character in name": (
        "statement-invalid",
        lambda v: v["subject"][0].update(name="a\u202eb"),
    ),
    "log command in name": (
        "statement-invalid",
        lambda v: v["subject"][0].update(name="a##[error]b"),
    ),
    "empty name": ("statement-invalid", lambda v: v["subject"][0].update(name="")),
    "name too long": ("statement-invalid", lambda v: v["subject"][0].update(name="n" * 256)),
    "name not a string": ("statement-invalid", lambda v: v["subject"][0].update(name=7)),
    "predicate not an object": ("predicate-invalid", lambda v: v.update(predicate=[])),
    "unknown predicate field": ("predicate-invalid", set_predicate(reviewer="alice")),
    "predicate version 2": ("predicate-invalid", set_predicate(version="2")),
    "predicate version as number": ("predicate-invalid", set_predicate(version=1)),
    "unknown purpose": ("predicate-invalid", set_predicate(purpose="approved")),
    "missing purpose": ("predicate-invalid", set_predicate(purpose=None)),
    "content digest with other format": (
        "predicate-invalid",
        other_with(content_digest="sha256:" + "0" * 64),
    ),
    "spec version with other format": ("predicate-invalid", other_with(spec_version="1.1.0")),
    "native without content digest": ("predicate-invalid", set_predicate(content_digest=None)),
    "native without profile": ("predicate-invalid", set_predicate(content_profile=None)),
    "unknown content profile": ("predicate-invalid", set_predicate(content_profile="other/v1")),
    "uppercase content digest": (
        "predicate-invalid",
        set_predicate(content_digest="sha256:" + "A" * 64),
    ),
    "malformed spec version": ("predicate-invalid", set_predicate(spec_version="01.1.0")),
    "uppercase source revision": (
        "predicate-invalid",
        set_predicate(source_revision=REVISION.upper()),
    ),
    "short source revision": ("predicate-invalid", set_predicate(source_revision=REVISION[:39])),
    "fractional seconds": ("predicate-invalid", set_predicate(signed_at="2026-11-12T10:00:00.5Z")),
    "timestamp without zone": ("predicate-invalid", set_predicate(signed_at="2026-11-12T10:00:00")),
    "timestamp not a time": ("predicate-invalid", set_predicate(signed_at="yesterday")),
    "offset instead of Z": (
        "predicate-not-canonical",
        set_predicate(signed_at="2026-11-12T10:00:00+00:00"),
    ),
    "other zone, same instant": (
        "predicate-not-canonical",
        set_predicate(signed_at="2026-11-12T11:00:00+01:00"),
    ),
    "zero fraction": (
        "predicate-not-canonical",
        set_predicate(signed_at="2026-11-12T10:00:00.000Z"),
    ),
    "unix time number": ("predicate-not-canonical", set_predicate(signed_at=1794477600)),
    "explicit null": (
        "predicate-not-canonical",
        lambda v: v["predicate"].update(source_revision=None),
    ),
}


@pytest.mark.parametrize("case", sorted(STATEMENT_REFUSALS))
def test_statement_and_predicate_refusals(case):
    reason, change = STATEMENT_REFUSALS[case]
    value = mutated(change)
    refused(reason, verify, signed(value))
    # The signer refuses whatever verification would refuse.
    refused(reason, sign_statement, value, [A])


def test_unix_time_vector_is_the_same_instant():
    assert datetime.fromtimestamp(1794477600, UTC) == SIGNED_AT


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b'{"_type": 1, "_type": 2}',
        b"[" * 100_000 + b"]" * 100_000,
        b'{"a": NaN}',
        b'{"a": "\\ud800"}',
        b"\xef\xbb\xbf{}",
        json.dumps({"_type": "x"}).encode("utf-16"),
        b"\xff",
    ],
    ids=[
        "not json",
        "duplicate key",
        "deep",
        "nan",
        "lone surrogate",
        "bom",
        "utf-16",
        "not utf-8",
    ],
)
def test_payload_that_is_not_strict_utf8_json_is_refused(payload):
    refused("statement-invalid", verify, envelope_over(payload, A))


def test_statement_size_is_limited_when_signing_and_verifying():
    refused("statement-too-large", verify, envelope_over(b" " * (MAX_STATEMENT_BYTES + 1), A))
    oversized = statement()
    oversized["predicate"] = {"padding": "x" * MAX_STATEMENT_BYTES}
    refused("statement-too-large", sign_statement, oversized, [A])


# Subject, purpose and time


def test_one_flipped_byte_fails_the_byte_match():
    envelope = signed(statement())
    flipped = bytearray(NATIVE)
    flipped[len(flipped) // 2] ^= 1
    refused("subject-mismatch", verify, envelope, bytes(flipped))
    refused("subject-mismatch", verify, envelope, NATIVE + b"\n")


def test_content_match_refusals():
    refused("content-digest-unavailable", verify, signed(statement(OTHER)), OTHER, match="content")
    envelope = signed(statement())
    refused("subject-not-inventory", verify, envelope, OTHER, match="content")
    refused("subject-not-inventory", verify, envelope, b"\xff", match="content")
    changed = AIBOM()
    changed.metadata.authors.append("someone")
    refused("subject-mismatch", verify, envelope, changed.to_json().encode(), match="content")


def test_native_claims_are_recomputed_from_the_attested_bytes():
    claims_other_content = mutated(set_predicate(content_digest="sha256:" + "0" * 64))
    refused("subject-mismatch", verify, signed(claims_other_content))
    claims_other_version = mutated(set_predicate(spec_version="1.0.0"))
    refused("subject-mismatch", verify, signed(claims_other_version))
    not_native = statement(OTHER)
    not_native["predicate"] |= statement()["predicate"]
    refused("subject-not-inventory", verify, signed(not_native), OTHER)


def test_other_attestation_of_a_native_file_verifies_without_content_claims():
    built = statement()
    for name in ("spec_version", "content_digest", "content_profile"):
        del built["predicate"][name]
    built["predicate"]["subject_format"] = "other"
    verified = verify(signed(built))
    assert verified.predicate.subject_format == "other"
    refused("content-digest-unavailable", verify, signed(built), match="content")


def test_purpose_must_match():
    envelope = signed(statement(purpose="generated"))
    refused("purpose-mismatch", verify, envelope, purpose="reviewed")
    assert verify(envelope, purpose="generated").predicate.purpose == "generated"


def test_time_checks_allow_five_minutes_of_skew_and_an_optional_maximum_age():
    envelope = signed(statement())
    assert verify(envelope, now=SIGNED_AT - timedelta(minutes=5))
    refused(
        "attestation-not-yet-valid",
        verify,
        envelope,
        now=SIGNED_AT - timedelta(minutes=5, seconds=1),
    )
    assert verify(envelope, now=SIGNED_AT + timedelta(days=90), max_age=timedelta(days=90))
    refused(
        "attestation-expired",
        verify,
        envelope,
        now=SIGNED_AT + timedelta(days=90, seconds=1),
        max_age=timedelta(days=90),
    )
    assert verify(envelope, now=SIGNED_AT + timedelta(days=36500))
    later = datetime.now(UTC) + timedelta(hours=1)
    refused(
        "attestation-not-yet-valid",
        verify_attestation,
        signed(statement(signed_at=later.replace(microsecond=0))),
        NATIVE,
        trusted_keys=ring(A),
        purpose="reviewed",
    )


def test_verification_time_may_be_given_in_any_zone():
    envelope = signed(statement())
    eastern = timezone(timedelta(hours=-5))
    assert verify(envelope, now=NOW.astimezone(eastern))


# Configuration


@pytest.mark.parametrize(
    "options",
    [
        {"keys": ()},
        {"threshold": 0},
        {"threshold": 33},
        {"threshold": True},
        {"threshold": 2.0},
        {"threshold": 2},
        {"purpose": "approved"},
        {"match": "digest"},
        {"max_age": timedelta()},
        {"max_age": timedelta(days=-1)},
        {"max_age": 90},
        {"now": datetime(2026, 11, 12, 11, 0)},
        {"now": "2026-11-12T11:00:00Z"},
    ],
    ids=repr,
)
def test_invalid_configuration_is_refused_before_the_envelope_is_read(options):
    garbage = Envelope.model_construct(payload="!", signatures=())
    refused("configuration-invalid", verify, garbage, **options)


def test_ring_entries_must_be_ed25519_keys_named_by_their_key_id():
    envelope = signed(statement())
    public = A.public_key()
    for trusted in (
        {"alias": public},
        {key_id(public): B.public_key()},
        {key_id(public): generate_private_key(SECP256R1()).public_key()},
    ):
        refused(
            "configuration-invalid",
            verify_attestation,
            envelope,
            NATIVE,
            trusted_keys=trusted,
            purpose="reviewed",
            now=NOW,
        )


class ExternalSigner:
    """A signer whose key never enters this process as a key object, like a KMS."""

    def __init__(self, key, *, broken=False, public=None):
        self._key, self.broken, self._public = key, broken, public

    def sign(self, data: bytes) -> bytes:
        return bytes(64) if self.broken else self._key.sign(data)

    def public_key(self):
        return self._public or self._key.public_key()


def test_signer_configuration_is_checked():
    built = statement()
    assert verify(sign_statement(built, [ExternalSigner(A)]))
    refused("configuration-invalid", sign_statement, built, [])
    many = [Ed25519PrivateKey.generate() for _ in range(33)]
    refused("configuration-invalid", sign_statement, built, many)
    refused("configuration-invalid", sign_statement, built, [A, ExternalSigner(A)])
    refused("configuration-invalid", sign_statement, built, [ExternalSigner(A, broken=True)])
    refused(
        "configuration-invalid", sign_statement, built, [ExternalSigner(A, public=B.public_key())]
    )
    ecdsa = generate_private_key(SECP256R1())
    refused("configuration-invalid", sign_statement, built, [ExternalSigner(ecdsa)])
    refused("statement-invalid", sign_statement, {**built, "subject": {1, 2}}, [A])
    refused(
        "statement-invalid",
        sign_statement,
        {**built, "subject": [{"name": "x", "digest": {"sha256": float("nan")}}]},
        [A],
    )


# Building a statement


def test_subject_names_are_neutralized_and_bounded():
    assert subject_name("a\x1b[31m\u202eb\nc") == "a\ufffd[31m\ufffdb\ufffdc"
    assert subject_name("x##[error]y::error::z") == "x##\ufffd[error]y::error::z"
    assert subject_name("bad\udcffname") == "bad\ufffdname"
    assert subject_name("n" * 300) == "n" * 255
    long = "##" + "[" * 300
    assert subject_name(subject_name(long)) == subject_name(long)
    built = build_statement(
        OTHER, name="evil\x1b\u202e##[error]\udcff.json", purpose="generated", signed_at=SIGNED_AT
    )
    assert built["subject"][0]["name"] == "evil\ufffd\ufffd##\ufffd[error]\ufffd.json"
    assert verify(signed(built), OTHER, purpose="generated")


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        ({"name": ""}, "statement-invalid"),
        ({"purpose": "approved"}, "predicate-invalid"),
        ({"signed_at": datetime(2026, 11, 12, 10, 0)}, "predicate-invalid"),
        ({"signed_at": SIGNED_AT.replace(microsecond=1)}, "predicate-invalid"),
        ({"source_revision": "HEAD"}, "predicate-invalid"),
        ({"source_revision": REVISION[:-1] + "G"}, "predicate-invalid"),
    ],
)
def test_build_statement_refuses_invalid_arguments(arguments, reason):
    values = {"name": "x.json", "purpose": "reviewed", "signed_at": SIGNED_AT} | arguments
    refused(reason, build_statement, NATIVE, **values)


def test_signing_time_in_another_zone_is_recorded_in_utc():
    eleven = SIGNED_AT.astimezone(timezone(timedelta(hours=1)))
    assert statement(signed_at=eleven)["predicate"]["signed_at"] == "2026-11-12T10:00:00Z"
    assert statement(source_revision="a" * 64)["predicate"]["source_revision"] == "a" * 64


@pytest.mark.parametrize(
    ("subject", "native"),
    [
        (NATIVE, True),
        (b'{"metadata": {}, "components": []}', True),
        (b"{}", False),
        (b'{"metadata": {}}', False),
        (b'{"components": []}', True),
        (b'{"metadata": {"spec_version": "9.0.0"}, "components": []}', False),
        (b'{"metadata": {}, "components": [], "extra": 1}', False),
        (b'{"metadata": {}, "components": [], "components": []}', False),
        (b"[]", False),
        (b"\xff", False),
        (b"", False),
        (b" " * (16 * 1024 * 1024 - 33) + b'{"metadata": {}, "components": []}', False),
    ],
    ids=[
        "native",
        "undeclared 1.0",
        "empty object",
        "no components",
        "no metadata",
        "unsupported version",
        "unknown field",
        "duplicate key",
        "array",
        "not utf-8",
        "empty",
        "over 16 MiB",
    ],
)
def test_subject_format_is_decided_from_the_bytes(subject, native):
    predicate = build_statement(subject, name="s", purpose="generated", signed_at=SIGNED_AT)[
        "predicate"
    ]
    assert (predicate["subject_format"] == "nexus-symbiote-aibom") is native
    if native:
        assert predicate["spec_version"] in {"1.0.0", "1.1.0", "1.2.0"}


def depth(value: object) -> int:
    """How deep arrays and objects nest, counted level by level."""
    levels, frontier = 0, [value]
    while containers := [item for item in frontier if isinstance(item, dict | list)]:
        levels += 1
        frontier = [
            child
            for item in containers
            for child in (item.values() if isinstance(item, dict) else item)
        ]
    return levels


def nested(levels: int) -> bytes:
    """The vector's native inventory with arrays and objects nested exactly ``levels`` deep."""
    document = json.loads(VECTORS["attestations"][0]["subject_text"])
    chain: dict[str, object] = {}
    for _ in range(levels - 4):
        chain = {"a": chain}
    document["components"][0]["properties"] = chain
    assert depth(document) == levels
    AIBOM.model_validate(document)
    return json.dumps(document).encode()


@pytest.mark.parametrize("levels", [MAX_NATIVE_DEPTH, MAX_NATIVE_DEPTH + 1])
def test_native_subject_nesting_has_an_explicit_bound(levels):
    subject = nested(levels)
    native = levels <= MAX_NATIVE_DEPTH
    built = statement(subject)
    assert (built["predicate"]["subject_format"] == "nexus-symbiote-aibom") is native
    envelope = signed(built)
    assert verify(envelope, subject).predicate == attestation.InventoryPredicate.model_validate(
        built["predicate"]
    )
    if native:
        assert verify(envelope, subject, match="content").predicate.content_digest
    else:
        refused("content-digest-unavailable", verify, envelope, subject, match="content")


def test_subject_nested_past_any_interpreter_limit_is_other():
    document = json.loads(VECTORS["attestations"][0]["subject_text"])
    document["components"][0]["properties"] = "NESTED"
    nesting = '{"a":' * 100_000 + "{}" + "}" * 100_000
    subject = json.dumps(document).replace('"NESTED"', nesting).encode()
    built = statement(subject)
    assert built["predicate"]["subject_format"] == "other"
    assert verify(signed(built), subject).predicate.subject_format == "other"


def at_stack_depth(frames: int, call):
    """Run ``call`` with ``frames`` more Python frames on the stack."""
    return call() if frames == 0 else at_stack_depth(frames - 1, call)


@pytest.mark.parametrize("levels", [MAX_NATIVE_DEPTH, MAX_NATIVE_DEPTH + 1, 600])
def test_native_classification_does_not_depend_on_the_callers_stack(levels):
    subject = nested(levels)
    shallow = statement(subject)
    assert at_stack_depth(400, lambda: statement(subject)) == shallow
    native = levels <= MAX_NATIVE_DEPTH
    assert (shallow["predicate"]["subject_format"] == "nexus-symbiote-aibom") is native
    # What one caller signed, a caller deeper in its stack verifies, recomputation included.
    envelope = signed(shallow)
    verified = at_stack_depth(400, lambda: verify(envelope, subject))
    assert verified.predicate.subject_format == shallow["predicate"]["subject_format"]


# Envelope parsing


def wire():
    return signed(statement()).model_dump(mode="json", by_alias=True)


@pytest.mark.parametrize(
    "change",
    [
        lambda w: w.update(payloadType="application/json"),
        lambda w: w.pop("payloadType"),
        lambda w: w.update(payload_type=w.pop("payloadType")),
        lambda w: w.update(extra=1),
        lambda w: w.update(signatures={}),
        lambda w: w.update(signatures=["sig"]),
        lambda w: w["signatures"][0].update(key_id=w["signatures"][0].pop("keyid")),
        lambda w: w["signatures"][0].update(signature=w["signatures"][0].pop("sig")),
        lambda w: w["signatures"][0].update(cert="x"),
        lambda w: w["signatures"][0].update(keyid=7),
        lambda w: w.update(payload=w["payload"] + "\n"),
        lambda w: w.update(payload=w["payload"].replace("=", "")),
        lambda w: w.update(signatures=w["signatures"] * 33),
    ],
    ids=[
        "payload type",
        "no payload type",
        "python name",
        "extra member",
        "signatures object",
        "signature string",
        "key_id name",
        "signature name",
        "extra signature member",
        "numeric keyid",
        "line break",
        "unpadded",
        "33 signatures",
    ],
)
def test_envelope_must_use_exactly_the_dsse_members(change):
    value = wire()
    change(value)
    refused("envelope-invalid", parse_envelope, json.dumps(value).encode())


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b"not json",
        b'{"payload": "", "payload": ""}',
        "{}".encode("utf-16"),
        b"\xef\xbb\xbf{}",
        b" " * (MAX_ENVELOPE_BYTES + 1),
    ],
    ids=["array", "not json", "duplicate member", "utf-16", "bom", "oversized"],
)
def test_envelope_must_be_bounded_strict_utf8_json(raw):
    refused("envelope-invalid", parse_envelope, raw)


def test_parsed_envelope_with_a_null_key_id_is_tried_against_each_key():
    value = wire()
    value["signatures"][0]["keyid"] = None
    assert verify(parse_envelope(json.dumps(value).encode()), keys=(B, A))
    del value["signatures"][0]["keyid"]
    assert verify(parse_envelope(json.dumps(value).encode()), keys=(B, A))


# Arbitrary input


JSON = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(-(2**60), 2**60)
    | st.sampled_from([0.5, -1.0, 1e300])
    | st.text(max_size=12)
    | st.sampled_from(["2026-11-12T10:00:00Z", "1.1.0", "reviewed", "other", "sha256:" + "0" * 64]),
    lambda children: (
        st.lists(children, max_size=3)
        | st.dictionaries(
            st.sampled_from([*attestation.InventoryPredicate.model_fields, "keyid", "sig", "x"]),
            children,
            max_size=4,
        )
    ),
    max_leaves=12,
)
ENVELOPE_LIKE = st.fixed_dictionaries(
    {
        "payloadType": JSON | st.just("application/vnd.in-toto+json"),
        "payload": JSON,
        "signatures": JSON,
    }
)


@settings(max_examples=300, deadline=None)
@given(
    st.one_of(
        st.binary(max_size=64),
        JSON.map(json.dumps).map(str.encode),
        ENVELOPE_LIKE.map(json.dumps).map(str.encode),
    )
)
def test_any_envelope_input_parses_or_is_refused_with_a_reason(raw):
    try:
        envelope = parse_envelope(raw)
    except AttestationError as refusal:
        assert refusal.reason == "envelope-invalid"
        return
    with pytest.raises(AttestationError):
        verify(envelope)


@settings(max_examples=300, deadline=None)
@given(st.one_of(st.binary(max_size=64), JSON.map(json.dumps).map(str.encode)))
def test_any_signed_payload_is_refused_with_a_reason(payload):
    with pytest.raises(AttestationError):
        verify(envelope_over(payload, A))


@settings(max_examples=300, deadline=None)
@given(
    st.dictionaries(
        st.sampled_from(sorted(attestation.InventoryPredicate.model_fields)), JSON, max_size=8
    )
)
def test_any_signed_predicate_verifies_or_is_refused_with_a_reason(fields):
    value = statement(source_revision=REVISION)
    value["predicate"] = {**value["predicate"], **fields}
    try:
        verified = verify(envelope_over(json.dumps(value).encode(), A))
    except AttestationError:
        return
    else:
        assert verified.predicate.model_dump(mode="json", exclude_none=True) == value["predicate"]


# Bounded work and documentation


def test_content_verification_time_grows_linearly_with_the_inventory():
    native = json.loads(VECTORS["attestations"][0]["subject_text"])
    [component] = native["components"]

    def inventory(count: int) -> bytes:
        document = copy.deepcopy(native)
        document["components"] = [
            {**component, "bom_ref": f"prompt:p{index}.md", "name": f"p{index}.md"}
            for index in range(count)
        ]
        return json.dumps(document).encode()

    subjects = {scale: inventory(500 * scale) for scale in (1, 4)}
    envelopes = {scale: signed(statement(subjects[scale])) for scale in (1, 4)}
    for scale in (1, 4):
        assert verify(envelopes[scale], subjects[scale], match="content").predicate.content_digest

    def run(scale: int) -> object:
        return verify(envelopes[scale], subjects[scale], match="content")

    assert scaling_ratio(run) < 10


def test_classification_time_grows_linearly_with_values_nested_to_the_bound():
    document = json.loads(VECTORS["attestations"][0]["subject_text"])
    chain: dict[str, object] = {}
    for _ in range(MAX_NATIVE_DEPTH - 6):
        chain = {"a": chain}

    def subject(count: int) -> bytes:
        document["components"][0]["properties"] = {"chains": [chain] * count}
        assert depth(document) == MAX_NATIVE_DEPTH
        return json.dumps(document).encode()

    subjects = {scale: subject(20 * scale) for scale in (1, 4)}
    for scale in (1, 4):
        assert statement(subjects[scale])["predicate"]["subject_format"] == "nexus-symbiote-aibom"

    def run(scale: int) -> object:
        return statement(subjects[scale])

    assert scaling_ratio(run) < 10


DOCUMENT = (ROOT / "docs" / "inventory-attestation.md").read_text(encoding="utf-8")


def test_documented_native_rule_names_its_bounds():
    flat = " ".join(DOCUMENT.split())
    assert f"at most {MAX_NATIVE_BYTES // (1024 * 1024)} MiB, with arrays and objects" in flat
    assert f"nested at most {MAX_NATIVE_DEPTH} levels deep" in flat


def test_documented_native_rule_reads_a_missing_metadata_as_empty():
    flat = " ".join(DOCUMENT.split())
    assert "that has a `components` list and validates as a native inventory" in flat
    assert "a missing `metadata` is read as an empty object" in flat
    without, empty = (
        build_statement(subject, name="s", purpose="generated", signed_at=SIGNED_AT)["predicate"]
        for subject in (b'{"components": []}', b'{"metadata": {}, "components": []}')
    )
    assert without["subject_format"] == "nexus-symbiote-aibom"
    assert without["content_digest"] == empty["content_digest"]


def test_reason_table_documents_exactly_the_codes():
    section = DOCUMENT.split("## Reason codes", 1)[1].split("\n## ", 1)[0]
    assert set(re.findall(r"^\| `([a-z-]+)` \|", section, re.M)) == set(REASONS)


def test_reason_codes_used_in_the_source_are_registered():
    source = "".join(
        (ROOT / "src" / "nexus_symbiote" / name).read_text(encoding="utf-8")
        for name in ("attestation.py", "attestation_cli.py")
    )
    used = set(re.findall(r'AttestationError\("([a-z-]+)"\)', source))
    used |= set(re.findall(r'_failure\(\s*(?:operation|"[a-z]+"),\s*"([a-z-]+)"', source))
    assert used == set(REASONS)
