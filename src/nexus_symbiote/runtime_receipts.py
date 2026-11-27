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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

from nexus_symbiote.core.hashing import open_directory_nofollow, open_regular_file
from nexus_symbiote.runtime import (
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
_RECEIPT_SIGNING_PREFIX = b"nexus-symbiote/runtime-receipt/v1\n"
_MERKLE_LEAF_PREFIX = b"\x00"
_MERKLE_NODE_PREFIX = b"\x01"
MAX_RECEIPT_FILE_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_LINE_BYTES = 128 * 1024
MAX_RECEIPTS = 250_000
MAX_VERIFICATION_ERRORS = 64
_MAX_LABEL_CHARS = 1024


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
    trust_signers: tuple[str, ...] = ()
    snapshot_signers: tuple[str, ...] = ()
    approval_signers: tuple[str, ...] = ()
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "count": self.count,
            "first_hash": self.first_hash,
            "last_hash": self.last_hash,
            "merkle_root": self.merkle_root,
            "signed_count": self.signed_count,
            "signers": list(self.signers),
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
        return GENESIS_HASH
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
    if os.name == "posix":
        if info.st_uid != os.geteuid():
            raise ReceiptError("receipt log must be owned by the current user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ReceiptError("receipt log must not be accessible to group or others (0600)")


def _open_append_0600(path: Path) -> int:
    target = path.absolute()
    parent_path = target.parent
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = open_directory_nofollow(parent_path)
    try:
        fd = os.open(target.name, flags, 0o600, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        info = os.fstat(fd)
        _check_safe_log_file(info)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _clip_label(value: str) -> str:
    if len(value) <= _MAX_LABEL_CHARS:
        return value
    digest_tail = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{value[: _MAX_LABEL_CHARS - 25]}...[sha256:{digest_tail}]"


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
        if os.path.lexists(self.path):
            resume_keys = trusted_keys
            if resume_keys is None and signer is not None:
                pub = signer.public_key()
                resume_keys = {key_id(pub): pub}
            existing, hashes = _verify_receipt_chain_with_hashes(
                self.path,
                trusted_keys=resume_keys,
                require_signatures=signer is not None,
                allow_empty=True,
                check_owner_0600=True,
            )
            if not existing.verified:
                raise ReceiptError(
                    "refusing to append to tampered receipt chain: " + "; ".join(existing.errors)
                )
            self._hashes = hashes
            self._next_seq = existing.count
            self._last_hash = existing.last_hash or GENESIS_HASH

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
        body: dict[str, Any] = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "seq": self._next_seq,
            "prev_hash": self._last_hash,
            "admitted": decision.admitted,
            "reason": _clip_label(decision.reason)[:128],
            "time": decision.time.isoformat(),
            "server_id": _clip_label(decision.server_id),
            "tool_name": _clip_label(decision.tool_name),
            "action": _clip_label(decision.action),
            "resource": _clip_label(decision.resource),
            "store_id": decision.store_id,
            "request_digest": decision.request_digest,
            "tenant": decision.tenant,
            "deployment_id": decision.deployment_id,
            "agent_id": decision.agent_id,
            "workload_identity": decision.workload_identity,
            "trust_serial": decision.trust_serial,
            "trust_digest": decision.trust_digest,
            "snapshot_serial": decision.snapshot_serial,
            "snapshot_digest": decision.snapshot_digest,
            "approval_digest": decision.approval_digest,
            "approval_actor": decision.approval_actor,
            "trust_signers": list(decision.trust_signers),
            "snapshot_signers": list(decision.snapshot_signers),
            "approval_signers": list(decision.approval_signers),
        }
        receipt_hash = compute_receipt_hash(body)
        signer_kid: str | None = None
        signature_b64: str | None = None
        if self.signer is not None:
            public = self.signer.public_key()
            msg = _signing_message(body)
            raw_sig = self.signer.sign(msg)
            public.verify(raw_sig, msg)
            signer_kid = key_id(public)
            signature_b64 = base64.b64encode(raw_sig).decode("ascii")

        receipt = ExecutionReceipt(
            **body,
            receipt_hash=receipt_hash,
            signer_key_id=signer_kid,
            signature=signature_b64,
        )
        encoded = (
            json.dumps(receipt.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")
        if len(encoded) > MAX_RECEIPT_LINE_BYTES:
            raise ReceiptError("serialized receipt exceeds maximum line byte limit")
        fd = _open_append_0600(self.path)
        with os.fdopen(fd, "ab") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        self._hashes.append(receipt_hash)
        self._last_hash = receipt_hash
        self._next_seq += 1
        return receipt


def _verify_receipt_chain_with_hashes(
    path: Path,
    *,
    trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
    require_signatures: bool = False,
    expected_merkle_root: str | None = None,
    allow_empty: bool = False,
    check_owner_0600: bool = False,
) -> tuple[ReceiptVerificationResult, list[str]]:
    """Single-open fail-closed verifier returning both result and verified receipt hashes."""
    errors: list[str] = []
    omitted_errors = 0

    def add_error(message: str) -> None:
        nonlocal omitted_errors
        if len(errors) < MAX_VERIFICATION_ERRORS:
            errors.append(message)
        else:
            omitted_errors += 1

    ring = (
        {kid: pub for kid, pub in trusted_keys.items() if key_id(pub) == kid}
        if trusted_keys
        else {}
    )
    if (require_signatures or trusted_keys is not None) and not ring:
        return (
            ReceiptVerificationResult(
                verified=False,
                count=0,
                first_hash=None,
                last_hash=None,
                merkle_root=GENESIS_HASH,
                signed_count=0,
                signers=(),
                errors=("signature verification requires at least one trusted Ed25519 public key",),
            ),
            [],
        )

    hashes: list[str] = []
    signers: set[str] = set()
    signed_count = 0

    try:
        with open_regular_file(path) as handle:
            info = os.fstat(handle.fileno())
            if check_owner_0600:
                _check_safe_log_file(info)
            if info.st_size > MAX_RECEIPT_FILE_BYTES:
                return (
                    ReceiptVerificationResult(
                        verified=False,
                        count=0,
                        first_hash=None,
                        last_hash=None,
                        merkle_root=GENESIS_HASH,
                        signed_count=0,
                        signers=(),
                        errors=("receipt log exceeds maximum size limit",),
                    ),
                    [],
                )
            raw = handle.read(MAX_RECEIPT_FILE_BYTES + 1)
    except ReceiptError as exc:
        return (
            ReceiptVerificationResult(
                verified=False,
                count=0,
                first_hash=None,
                last_hash=None,
                merkle_root=GENESIS_HASH,
                signed_count=0,
                signers=(),
                errors=(str(exc),),
            ),
            [],
        )
    except OSError:
        return (
            ReceiptVerificationResult(
                verified=False,
                count=0,
                first_hash=None,
                last_hash=None,
                merkle_root=GENESIS_HASH,
                signed_count=0,
                signers=(),
                errors=("receipt log could not be read safely",),
            ),
            [],
        )

    if len(raw) > MAX_RECEIPT_FILE_BYTES:
        return (
            ReceiptVerificationResult(
                verified=False,
                count=0,
                first_hash=None,
                last_hash=None,
                merkle_root=GENESIS_HASH,
                signed_count=0,
                signers=(),
                errors=("receipt log exceeds maximum size limit",),
            ),
            [],
        )

    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        if allow_empty:
            return (
                ReceiptVerificationResult(
                    verified=True,
                    count=0,
                    first_hash=None,
                    last_hash=None,
                    merkle_root=GENESIS_HASH,
                    signed_count=0,
                    signers=(),
                    errors=(),
                ),
                [],
            )
        return (
            ReceiptVerificationResult(
                verified=False,
                count=0,
                first_hash=None,
                last_hash=None,
                merkle_root=GENESIS_HASH,
                signed_count=0,
                signers=(),
                errors=("receipt log is empty",),
            ),
            [],
        )
    if len(lines) > MAX_RECEIPTS:
        return (
            ReceiptVerificationResult(
                verified=False,
                count=0,
                first_hash=None,
                last_hash=None,
                merkle_root=GENESIS_HASH,
                signed_count=0,
                signers=(),
                errors=(f"receipt log exceeds {MAX_RECEIPTS} entries",),
            ),
            [],
        )

    expected_prev = GENESIS_HASH
    for idx, line in enumerate(lines):
        if len(line) > MAX_RECEIPT_LINE_BYTES:
            add_error(f"entry {idx}: line exceeds maximum byte limit")
            continue
        try:
            obj = strict_json(line)
            if not isinstance(obj, dict):
                raise ReceiptError("entry is not a JSON object")
            receipt = ExecutionReceipt.model_validate(obj)
        except (AuthorizationError, ReceiptError, ValueError) as exc:
            add_error(f"entry {idx}: malformed receipt ({type(exc).__name__})")
            continue

        if receipt.seq != idx:
            add_error(f"entry {idx}: expected seq {idx}, got {receipt.seq}")
        if receipt.prev_hash != expected_prev:
            add_error(f"entry {idx}: prev_hash mismatch (chain broken)")

        body = _receipt_body(receipt.model_dump(mode="json"))
        computed = compute_receipt_hash(body)
        if receipt.receipt_hash != computed:
            add_error(f"entry {idx}: receipt_hash mismatch (tampered payload)")

        if receipt.signature is not None or receipt.signer_key_id is not None:
            if receipt.signature is None or receipt.signer_key_id is None:
                add_error(f"entry {idx}: incomplete signature fields")
            else:
                signed_count += 1
                signers.add(receipt.signer_key_id)
                if ring:
                    pub = ring.get(receipt.signer_key_id)
                    if pub is None:
                        add_error(f"entry {idx}: signer key is not in trusted ring")
                    else:
                        try:
                            sig_bytes = base64.b64decode(receipt.signature, validate=True)
                            pub.verify(sig_bytes, _signing_message(body))
                        except (binascii.Error, ValueError, InvalidSignature):
                            add_error(f"entry {idx}: invalid Ed25519 signature")
        elif require_signatures or ring:
            add_error(f"entry {idx}: missing required Ed25519 signature")

        hashes.append(receipt.receipt_hash)
        expected_prev = receipt.receipt_hash

    root = compute_merkle_root(hashes)
    if expected_merkle_root is not None and root != expected_merkle_root:
        add_error("merkle_root does not match --expected-merkle-root")
    if omitted_errors:
        errors.append(f"{omitted_errors} further verification error(s) omitted")

    return (
        ReceiptVerificationResult(
            verified=not errors,
            count=len(hashes),
            first_hash=hashes[0] if hashes else None,
            last_hash=hashes[-1] if hashes else None,
            merkle_root=root,
            signed_count=signed_count,
            signers=tuple(sorted(signers)),
            errors=tuple(errors),
        ),
        hashes,
    )


def verify_receipt_chain(
    path: Path,
    *,
    trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
    require_signatures: bool = False,
    expected_merkle_root: str | None = None,
) -> ReceiptVerificationResult:
    """Verify an offline runtime receipt JSONL chain, failing closed on any tamper."""
    result, _ = _verify_receipt_chain_with_hashes(
        path,
        trusted_keys=trusted_keys,
        require_signatures=require_signatures,
        expected_merkle_root=expected_merkle_root,
    )
    return result


def sanitize_tool_output(text: str, *, source_name: str = "tool-output") -> ToolOutputScanResult:
    """Redact credential patterns and flag indirect prompt injection in tool output text."""
    sanitized = redact_text(text)
    hits = tuple(scan_text_block(text, surface=source_name, is_tool_surface=True))
    return ToolOutputScanResult(
        sanitized_text=sanitized,
        redacted=sanitized != text,
        poisoning_hits=hits,
    )
