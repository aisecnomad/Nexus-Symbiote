"""Tamper-evident hash-chained runtime receipts, Merkle commitments, and output hygiene.

Provides an opt-in ``on_decision`` sink (``ReceiptChainSink``) for ``ReferenceGateway``
that records secret-free authorization decisions as RFC 8785 JCS hash-chained JSONL
receipts with optional Ed25519 signatures and domain-separated SHA-256 Merkle roots,
plus an offline verifier (``verify_receipt_chain``) and an adapter helper
(``sanitize_tool_output``) for redacting credentials and flagging indirect prompt
injection in tool responses.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

from nexus_symbiote.core.hashing import (
    descriptor_binding,
    open_directory_nofollow,
    open_regular_file,
)
from nexus_symbiote.runtime import (
    REASONS,
    AuthorizationError,
    Contract,
    ContractSigner,
    Decision,
    KeyId,
    Sha256Digest,
    canonical_bytes,
    key_id,
    strict_json,
)
from nexus_symbiote.text_poisoning import TextPoisoningHit, scan_text_block
from nexus_symbiote.utils.secrets import redact_text

RECEIPT_SCHEMA_VERSION: Literal["nexus-symbiote/runtime-receipt/v1"] = (
    "nexus-symbiote/runtime-receipt/v1"
)
GENESIS_HASH = "sha256:" + "0" * 64
EMPTY_MERKLE_ROOT = "sha256:" + hashlib.sha256(b"").hexdigest()
_RECEIPT_SIGNING_PREFIX = b"nexus-symbiote/runtime-receipt/v1\n"
_MERKLE_LEAF_PREFIX = b"\x00"
_MERKLE_NODE_PREFIX = b"\x01"
MAX_RECEIPT_FILE_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_LINE_BYTES = 128 * 1024
MAX_RECEIPTS = 250_000
MAX_VERIFICATION_ERRORS = 64
_LABELS_WITHHELD = "[withheld]"


class ReceiptError(ValueError):
    """Raised when a runtime receipt chain is malformed, unsafe, or tampered."""


class ExecutionReceipt(Contract):
    """One tamper-evident, secret-free authorization receipt."""

    schema_version: Literal["nexus-symbiote/runtime-receipt/v1"] = RECEIPT_SCHEMA_VERSION
    seq: int = Field(ge=0)
    prev_hash: Sha256Digest
    receipt_hash: Sha256Digest
    admitted: bool
    reason: str = Field(min_length=1, max_length=128)
    time: str = Field(min_length=1, max_length=64)
    server_id: str
    tool_name: str
    action: str
    resource: str
    store_id: str | None = None
    request_digest: Sha256Digest | None = None
    tenant: str | None = None
    deployment_id: str | None = None
    agent_id: str | None = None
    workload_identity: str | None = None
    trust_serial: int | None = None
    trust_digest: Sha256Digest | None = None
    snapshot_serial: int | None = None
    snapshot_digest: Sha256Digest | None = None
    approval_digest: Sha256Digest | None = None
    approval_actor: str | None = None
    trust_signers: tuple[KeyId, ...] = ()
    snapshot_signers: tuple[KeyId, ...] = ()
    approval_signers: tuple[KeyId, ...] = ()
    signer_key_id: KeyId | None = None
    signature: str | None = Field(default=None, max_length=1024)


@dataclass(frozen=True)
class ReceiptVerificationResult:
    """Summary of offline receipt chain verification."""

    verified: bool
    count: int
    first_hash: str | None
    last_hash: str | None
    merkle_root: str
    signed_count: int
    signers: tuple[str, ...]
    errors: tuple[str, ...] = ()
    presented_signers: tuple[str, ...] = ()
    verified_signature_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "count": self.count,
            "first_hash": self.first_hash,
            "last_hash": self.last_hash,
            "merkle_root": self.merkle_root,
            "signed_count": self.signed_count,
            "signers": list(self.signers),
            "presented_signers": list(self.presented_signers),
            "verified_signature_count": self.verified_signature_count,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class ToolOutputScanResult:
    """Result of sanitizing and inspecting an adapter's tool response text."""

    sanitized_text: str
    redacted: bool
    poisoning_hits: tuple[TextPoisoningHit, ...]

    @property
    def flagged(self) -> bool:
        return bool(self.poisoning_hits)


def _receipt_body(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        k: v for k, v in payload.items() if k not in {"receipt_hash", "signer_key_id", "signature"}
    }


def compute_receipt_hash(body: Mapping[str, Any]) -> str:
    """Compute the canonical RFC 8785 JCS SHA-256 hash of a receipt body."""
    return "sha256:" + hashlib.sha256(canonical_bytes(dict(body))).hexdigest()


def compute_merkle_root(hashes: Sequence[str]) -> str:
    """Compute an RFC 6962 domain-separated SHA-256 Merkle root over receipt hashes.

    Unpaired odd nodes are promoted unchanged (never duplicated) so appending a
    duplicate tail cannot produce a second-preimage collision (CVE-2012-2459).
    """
    if not hashes:
        return EMPTY_MERKLE_ROOT
    level = [hashlib.sha256(_MERKLE_LEAF_PREFIX + item.encode("utf-8")).digest() for item in hashes]
    while len(level) > 1:
        next_level: list[bytes] = []
        for idx in range(0, len(level), 2):
            if idx + 1 < len(level):
                next_level.append(
                    hashlib.sha256(_MERKLE_NODE_PREFIX + level[idx] + level[idx + 1]).digest()
                )
            else:
                next_level.append(level[idx])
        level = next_level
    return "sha256:" + level[0].hex()


def _signing_message(body: Mapping[str, Any]) -> bytes:
    return _RECEIPT_SIGNING_PREFIX + canonical_bytes(dict(body))


def _check_safe_log_file(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise ReceiptError("receipt log must be a regular file")
    if info.st_nlink != 1:
        raise ReceiptError("receipt log must have one link")
    if os.name == "posix":
        if info.st_uid != os.geteuid():
            raise ReceiptError("receipt log must be owned by the current user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ReceiptError("receipt log must not be accessible to group or others (0600)")


def _lock_receipt_file(fd: int, *, shared: bool) -> None:
    try:
        import fcntl
    except ImportError as exc:
        raise OSError("receipt locking requires POSIX advisory locks") from exc
    fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)


@contextmanager
def _locked_log(path: Path) -> Iterator[BinaryIO]:
    """Hold a writer lock on the same private file used to inspect and append the chain."""
    parent = open_directory_nofollow(path.parent)
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(path.name, flags, 0o600, dir_fd=parent)
        with os.fdopen(fd, "r+b", buffering=0) as stream:
            _check_safe_log_file(os.fstat(fd))
            _lock_receipt_file(fd, shared=False)
            opened = os.fstat(fd)
            _check_safe_log_file(opened)
            if not os.path.samestat(
                opened, os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            ):
                raise ReceiptError("receipt log changed before append")
            yield stream
            if not os.path.samestat(
                opened, os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            ):
                raise ReceiptError("receipt log changed during append")
    finally:
        os.close(parent)


class ReceiptChainSink:
    """Append-only ``0600`` hash-chained JSONL sink compatible with ``ReferenceGateway.on_decision``."""

    def __init__(
        self,
        path: Path,
        *,
        signer: ContractSigner | None = None,
        trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> None:
        self.path = path.absolute()
        self.signer = signer
        self._hashes: list[str] = []
        self._last_hash = GENESIS_HASH
        self._next_seq = 0
        self._ring = dict(trusted_keys or {})
        if signer is not None:
            public = signer.public_key()
            if trusted_keys is not None and (
                key_id(public) not in trusted_keys
                or any(key_id(pub) != kid for kid, pub in trusted_keys.items())
            ):
                raise ReceiptError("receipt signer is not trusted by the supplied ring")
            self._ring[key_id(public)] = public
        elif trusted_keys is not None:
            raise ReceiptError("a trusted receipt writer requires a signer")
        self._stamp: tuple[int, ...] | None = None
        with _locked_log(self.path) as stream:
            self._refresh(stream)

    def _refresh(self, stream: BinaryIO) -> None:
        stamp = descriptor_binding(os.fstat(stream.fileno()))
        if self._stamp == stamp:
            return
        stream.seek(0)
        result, hashes = _verify_stream(
            stream, self._ring or None, self.signer is not None, None, allow_empty=True
        )
        if not result.verified:
            raise ReceiptError("cannot resume receipt chain: " + "; ".join(result.errors))
        if result.signed_count and self.signer is None:
            raise ReceiptError("resuming a signed chain requires a trusted signer")
        if self._next_seq and (
            result.count < self._next_seq or hashes[self._next_seq - 1] != self._last_hash
        ):
            raise ReceiptError("receipt log no longer contains this writer's committed prefix")
        self._hashes = hashes
        self._next_seq = result.count
        self._last_hash = result.last_hash or GENESIS_HASH
        self._stamp = stamp

    @property
    def count(self) -> int:
        return self._next_seq

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def merkle_root(self) -> str:
        return compute_merkle_root(self._hashes)

    def __call__(self, decision: Decision) -> ExecutionReceipt:
        return self.record(decision)

    def record(self, decision: Decision) -> ExecutionReceipt:
        with _locked_log(self.path) as stream:
            self._refresh(stream)
            return self._append(stream, decision)

    def _append(self, stream: BinaryIO, decision: Decision) -> ExecutionReceipt:
        if self._next_seq >= MAX_RECEIPTS:
            raise ReceiptError("receipt log exceeds its record limit")
        body: dict[str, Any] = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "seq": self._next_seq,
            "prev_hash": self._last_hash,
            "admitted": decision.admitted,
            "reason": decision.reason
            if decision.reason in REASONS or decision.reason == "admitted"
            else "denied",
            "time": decision.time.isoformat(),
            "server_id": _LABELS_WITHHELD,
            "tool_name": _LABELS_WITHHELD,
            "action": _LABELS_WITHHELD,
            "resource": _LABELS_WITHHELD,
            "store_id": _LABELS_WITHHELD if decision.store_id is not None else None,
            "request_digest": decision.request_digest,
            "tenant": _LABELS_WITHHELD if decision.tenant is not None else None,
            "deployment_id": _LABELS_WITHHELD if decision.deployment_id is not None else None,
            "agent_id": _LABELS_WITHHELD if decision.agent_id is not None else None,
            "workload_identity": _LABELS_WITHHELD
            if decision.workload_identity is not None
            else None,
            "trust_serial": decision.trust_serial,
            "trust_digest": decision.trust_digest,
            "snapshot_serial": decision.snapshot_serial,
            "snapshot_digest": decision.snapshot_digest,
            "approval_digest": decision.approval_digest,
            "approval_actor": _LABELS_WITHHELD if decision.approval_actor is not None else None,
            "trust_signers": list(decision.trust_signers),
            "snapshot_signers": list(decision.snapshot_signers),
            "approval_signers": list(decision.approval_signers),
        }
        receipt_hash = compute_receipt_hash(body)
        signer_kid: str | None = None
        signature_b64: str | None = None
        if self.signer is not None:
            public = self.signer.public_key()
            signer_kid = key_id(public)
            if signer_kid not in self._ring:
                raise ReceiptError("current receipt signer is not trusted by the configured ring")
            msg = _signing_message(body)
            raw_sig = self.signer.sign(msg)
            public.verify(raw_sig, msg)
            signature_b64 = base64.b64encode(raw_sig).decode("ascii")

        envelope = {
            **body,
            "receipt_hash": receipt_hash,
            "signer_key_id": signer_kid,
            "signature": signature_b64,
        }
        encoded = (json.dumps(envelope, separators=(",", ":"), sort_keys=True) + "\n").encode(
            "utf-8"
        )
        if len(encoded) > MAX_RECEIPT_LINE_BYTES:
            raise ReceiptError("serialized receipt exceeds maximum line byte limit")
        receipt = ExecutionReceipt.model_validate_json(encoded, strict=True)
        fd = stream.fileno()
        size = os.fstat(fd).st_size
        if size + len(encoded) > MAX_RECEIPT_FILE_BYTES:
            raise ReceiptError("receipt log exceeds its byte limit")
        try:
            if stream.write(encoded) != len(encoded):
                raise ReceiptError("incomplete receipt write")
            stream.flush()
            os.fsync(fd)
        except BaseException:
            self._stamp = None
            os.ftruncate(fd, size)
            os.fsync(fd)
            raise
        self._stamp = descriptor_binding(os.fstat(fd))
        self._hashes.append(receipt_hash)
        self._last_hash = receipt_hash
        self._next_seq += 1
        return receipt


def _failed(reason: str) -> ReceiptVerificationResult:
    return ReceiptVerificationResult(False, 0, None, None, EMPTY_MERKLE_ROOT, 0, (), (reason,))


def _verify_stream(
    stream: BinaryIO,
    trusted_keys: Mapping[str, Ed25519PublicKey] | None,
    require_signatures: bool,
    expected_merkle_root: str | None,
    *,
    allow_empty: bool = False,
) -> tuple[ReceiptVerificationResult, list[str]]:
    before = os.fstat(stream.fileno())
    if before.st_size > MAX_RECEIPT_FILE_BYTES:
        return _failed("receipt log exceeds maximum size limit"), []
    ring = dict(trusted_keys or {})
    if (require_signatures or trusted_keys is not None) and (
        not ring or any(key_id(pub) != kid for kid, pub in ring.items())
    ):
        return _failed("signature verification requires a valid trusted Ed25519 key ring"), []

    errors: list[str] = []
    omitted = 0

    def error(message: str) -> None:
        nonlocal omitted
        if len(errors) < MAX_VERIFICATION_ERRORS:
            errors.append(message)
        else:
            omitted += 1

    hashes: list[str] = []
    presented: set[str] = set()
    authenticated: set[str] = set()
    signed_count = verified_count = total = count = 0
    previous = GENESIS_HASH
    while line := stream.readline(MAX_RECEIPT_LINE_BYTES + 1):
        total += len(line)
        if total > MAX_RECEIPT_FILE_BYTES:
            return _failed("receipt log exceeds maximum size limit"), []
        if len(line) > MAX_RECEIPT_LINE_BYTES:
            error("line exceeds maximum byte limit")
            break
        if not line.endswith(b"\n"):
            error("final receipt line is missing its newline")
            break
        if not line.strip():
            continue
        if count >= MAX_RECEIPTS:
            error(f"receipt log exceeds {MAX_RECEIPTS} entries")
            break
        index = count
        count += 1
        try:
            obj = strict_json(line)
            if not isinstance(obj, dict) or set(obj) != ExecutionReceipt.model_fields.keys():
                raise ReceiptError("v1 receipt fields are missing or unknown")
            # Strict JSON mode accepts JSON arrays for tuples, but never coerces
            # strings or numbers into other JSON types. Sign the original wire body.
            receipt = ExecutionReceipt.model_validate_json(line, strict=True)
        except (AuthorizationError, ValueError) as exc:
            error(f"entry {index}: malformed receipt ({type(exc).__name__})")
            continue

        if receipt.seq != index:
            error(f"entry {index}: expected seq {index}, got {receipt.seq}")
        if receipt.prev_hash != previous:
            error(f"entry {index}: prev_hash mismatch (chain broken)")
        body = _receipt_body(obj)
        if compute_receipt_hash(body) != receipt.receipt_hash:
            error(f"entry {index}: receipt_hash mismatch (tampered payload)")
        previous = receipt.receipt_hash
        hashes.append(previous)

        kid, signature = receipt.signer_key_id, receipt.signature
        if kid is None and signature is None:
            if require_signatures or ring:
                error(f"entry {index}: missing required Ed25519 signature")
            continue
        if kid is None or signature is None:
            error(f"entry {index}: incomplete signature fields")
            continue
        signed_count += 1
        presented.add(kid)
        try:
            sig_bytes = base64.b64decode(signature, validate=True)
            if len(sig_bytes) != 64 or base64.b64encode(sig_bytes).decode("ascii") != signature:
                raise ValueError("incorrect Ed25519 signature encoding")
            if ring:
                if kid not in ring:
                    error(f"entry {index}: signer key is not in trusted ring")
                    continue
                ring[kid].verify(sig_bytes, _signing_message(body))
                verified_count += 1
                authenticated.add(kid)
        except (binascii.Error, ValueError, InvalidSignature):
            error(f"entry {index}: invalid Ed25519 signature")

    if not allow_empty and not count:
        error("receipt log is empty")
    if descriptor_binding(before) != descriptor_binding(os.fstat(stream.fileno())):
        error("receipt log changed during verification")
    root = compute_merkle_root(hashes)
    if expected_merkle_root is not None and root != expected_merkle_root:
        error("merkle_root does not match --expected-merkle-root")
    if omitted:
        errors.append(f"{omitted} further verification error(s) omitted")
    return ReceiptVerificationResult(
        verified=not errors,
        count=len(hashes),
        first_hash=hashes[0] if hashes else None,
        last_hash=hashes[-1] if hashes else None,
        merkle_root=root,
        signed_count=signed_count,
        signers=tuple(sorted(authenticated)),
        errors=tuple(errors),
        presented_signers=tuple(sorted(presented)),
        verified_signature_count=verified_count,
    ), hashes


def verify_receipt_chain(
    path: Path,
    *,
    trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
    require_signatures: bool = False,
    expected_merkle_root: str | None = None,
) -> ReceiptVerificationResult:
    """Check v1 wire hashes and any requested key-ring or Merkle-root assurance."""
    try:
        with open_regular_file(path) as stream:
            _lock_receipt_file(stream.fileno(), shared=True)
            result, _ = _verify_stream(
                stream, trusted_keys, require_signatures, expected_merkle_root
            )
            return result
    except OSError:
        return _failed("receipt log could not be read safely")


def sanitize_tool_output(text: str, *, source_name: str = "tool-output") -> ToolOutputScanResult:
    """Redact credential patterns and flag indirect prompt injection in tool output text."""
    sanitized = redact_text(text)
    hits = tuple(scan_text_block(text, surface=source_name, is_tool_surface=True))
    return ToolOutputScanResult(
        sanitized_text=sanitized,
        redacted=sanitized != text,
        poisoning_hits=hits,
    )
