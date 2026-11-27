"""Tamper-evident hash-chained execution receipts and 0600 JSONL observation sink.

Implements ``ROADMAP 1.4`` reference-gateway observation sinks:
- ``ReceiptSink`` plugs directly into ``ReferenceGateway(..., on_decision=sink)`` and writes
  newline-delimited RFC 8785 canonical receipt records to a private ``0600`` regular file.
- Every receipt binds ``prev_receipt_sha256``, ``seq``, canonical UTC timestamp, decision
  outcome/reason, redacted and neutralized request labels, contract digests, and signer key IDs—
  never tool argument values or secrets.
- Supports optional Ed25519 per-receipt signatures and RFC 6962 domain-separated SHA-256
  Merkle roots, verified offline by ``verify_receipt_log`` and ``runtime verify-receipts``.
"""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexus_symbiote.core.hashing import open_directory_nofollow, open_regular_file
from nexus_symbiote.runtime import Decision, canonical_bytes, key_id, strict_json
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import neutralize

RECEIPT_FORMAT = "nexus-symbiote/runtime-receipt/v1"
GENESIS_HASH = "sha256:" + "0" * 64
DOMAIN_PREFIX = b"nexus-symbiote/runtime-receipt/v1\x00"
MAX_RECEIPT_LOG_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_LINE_BYTES = 256 * 1024
MAX_RECEIPT_ENTRIES = 200_000
MAX_SIGNATURE_ATTEMPTS = 64
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_SPIFFE_ID_RE = re.compile(r"^spiffe://[A-Za-z0-9.-]{1,128}(?:/[A-Za-z0-9._-]{1,128}){0,16}$")


class ReceiptVerificationError(ValueError):
    """Raised when a runtime receipt log is unsafe, malformed, tampered, or unverified."""

    def __init__(self, message: str, *, reason: str = "receipt-invalid") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class VerifiedReceiptLog:
    """Summary returned by offline receipt-chain verification."""

    entry_count: int
    admitted_count: int
    denied_count: int
    head_receipt_sha256: str
    merkle_root: str
    signers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": True,
            "format": RECEIPT_FORMAT,
            "entry_count": self.entry_count,
            "admitted_count": self.admitted_count,
            "denied_count": self.denied_count,
            "head_receipt_sha256": self.head_receipt_sha256,
            "merkle_root": self.merkle_root,
            "signers": list(self.signers),
        }


def _utc_timestamp(moment: datetime) -> str:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ReceiptVerificationError(
            "receipt timestamp must be timezone-aware", reason="receipt-invalid"
        )
    utc = moment.astimezone(UTC)
    if utc.microsecond:
        return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def _scrub_label(value: str, limit: int = 256) -> str:
    if _SPIFFE_ID_RE.fullmatch(value):
        cleaned = neutralize(value)
    else:
        cleaned = neutralize(redact_text(value))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def _scrub_optional(value: str | None, limit: int = 256) -> str | None:
    if value is None:
        return None
    return _scrub_label(value, limit)


def merkle_root(receipt_digests: Sequence[str]) -> str:
    """Compute an RFC 6962 domain-separated SHA-256 Merkle root over ``sha256:<hex>`` leaves."""
    if not receipt_digests:
        return "sha256:" + hashlib.sha256(b"").hexdigest()
    level: list[bytes] = []
    for item in receipt_digests:
        if not isinstance(item, str) or not _SHA256_RE.fullmatch(item):
            raise ReceiptVerificationError(
                "invalid leaf digest in Merkle tree", reason="receipt-invalid"
            )
        level.append(hashlib.sha256(b"\x00" + bytes.fromhex(item[7:])).digest())
    while len(level) > 1:
        nxt: list[bytes] = []
        for idx in range(0, len(level), 2):
            if idx + 1 < len(level):
                nxt.append(hashlib.sha256(b"\x01" + level[idx] + level[idx + 1]).digest())
            else:
                nxt.append(level[idx])
        level = nxt
    return "sha256:" + level[0].hex()


def _receipt_core_body(
    decision: Decision,
    *,
    seq: int,
    prev_receipt_sha256: str,
) -> dict[str, Any]:
    return {
        "format": RECEIPT_FORMAT,
        "seq": seq,
        "prev_receipt_sha256": prev_receipt_sha256,
        "timestamp": _utc_timestamp(decision.time),
        "admitted": decision.admitted,
        "reason": _scrub_label(decision.reason, 128),
        "server_id": _scrub_label(decision.server_id, 256),
        "tool_name": _scrub_label(decision.tool_name, 256),
        "action": _scrub_label(decision.action, 128),
        "resource": _scrub_label(decision.resource, 512),
        "store_id": _scrub_optional(decision.store_id),
        "request_digest": decision.request_digest,
        "tenant": _scrub_optional(decision.tenant),
        "deployment_id": _scrub_optional(decision.deployment_id),
        "agent_id": _scrub_optional(decision.agent_id),
        "workload_identity": _scrub_optional(decision.workload_identity),
        "trust_serial": decision.trust_serial,
        "trust_digest": decision.trust_digest,
        "snapshot_serial": decision.snapshot_serial,
        "snapshot_digest": decision.snapshot_digest,
        "approval_digest": decision.approval_digest,
        "approval_actor": _scrub_optional(decision.approval_actor),
        "trust_signers": list(decision.trust_signers),
        "snapshot_signers": list(decision.snapshot_signers),
        "approval_signers": list(decision.approval_signers),
    }


def _open_private_append(path: Path) -> tuple[int, os.stat_result]:
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise ReceiptVerificationError(
            "descriptor-relative no-follow file access is unavailable",
            reason="receipt-io-error",
        )
    path = Path(path)
    if not path.name or path.name in {".", ".."}:
        raise ReceiptVerificationError(
            "receipt sink path must name a file", reason="receipt-io-error"
        )
    try:
        parent_fd = open_directory_nofollow(path.parent)
    except OSError as exc:
        raise ReceiptVerificationError(
            "receipt sink parent must be an existing non-symlink directory",
            reason="receipt-io-error",
        ) from exc
    uid = getattr(os, "geteuid", lambda: None)()
    try:
        parent_st = os.fstat(parent_fd)
        parent_mode = stat.S_IMODE(parent_st.st_mode)
        if parent_mode & 0o002 or ((parent_mode & 0o020) and not (parent_mode & stat.S_ISVTX)):
            raise ReceiptVerificationError(
                "receipt sink parent directory must not be writable by untrusted users",
                reason="receipt-io-error",
            )
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_APPEND
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            fd = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ReceiptVerificationError(
                    "receipt sink path may not be a symbolic link", reason="receipt-io-error"
                ) from exc
            raise ReceiptVerificationError(
                "receipt sink file could not be opened safely", reason="receipt-io-error"
            ) from exc
    finally:
        os.close(parent_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise ReceiptVerificationError(
                "receipt sink must be a single-link regular file", reason="receipt-io-error"
            )
        if uid is not None and st.st_uid != uid:
            raise ReceiptVerificationError(
                "receipt sink must be owned by the current user", reason="receipt-io-error"
            )
        if st.st_mode & 0o077:
            os.fchmod(fd, 0o600)
            st = os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def _pread_exact(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(fd, size - offset, offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


class ReceiptSink:
    """Append-only ``0600`` JSONL observation sink for ``ReferenceGateway(on_decision=...)``."""

    def __init__(
        self,
        path: Path,
        *,
        signing_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.path = Path(path)
        self._signing_key = signing_key
        self._signer_id = key_id(signing_key.public_key()) if signing_key is not None else None
        self._seq = 0
        self._head = GENESIS_HASH
        self._digests: list[str] = []

        fd, st = _open_private_append(self.path)
        try:
            size = st.st_size
            if size > MAX_RECEIPT_LOG_BYTES:
                raise ReceiptVerificationError(
                    "existing receipt log exceeds maximum size", reason="receipt-too-large"
                )
            self._inode = (st.st_dev, st.st_ino)
            self._byte_size = size
            if size > 0:
                raw = _pread_exact(fd, size)
                resume_ring = (
                    {self._signer_id: signing_key.public_key()}
                    if signing_key is not None and self._signer_id is not None
                    else {}
                )
                verified, digests = _verify_raw_lines(
                    raw,
                    trusted_ring=resume_ring,
                    require_signatures=signing_key is not None,
                    threshold=1,
                )
                self._seq = verified.entry_count
                self._head = verified.head_receipt_sha256
                self._digests = digests
        finally:
            os.close(fd)

    @property
    def entry_count(self) -> int:
        return self._seq

    @property
    def head_receipt_sha256(self) -> str:
        return self._head

    def current_merkle_root(self) -> str:
        return merkle_root(self._digests)

    def __call__(self, decision: Decision) -> dict[str, Any]:
        return self.record(decision)

    def record(self, decision: Decision) -> dict[str, Any]:
        """Append one hash-chained (and optionally Ed25519-signed) receipt record."""
        if self._seq >= MAX_RECEIPT_ENTRIES:
            raise ReceiptVerificationError(
                "receipt log reached maximum entry count", reason="receipt-too-large"
            )
        body = _receipt_core_body(decision, seq=self._seq, prev_receipt_sha256=self._head)
        canon = canonical_bytes(body)
        receipt_sha = "sha256:" + hashlib.sha256(canon).hexdigest()
        envelope: dict[str, Any] = {
            **body,
            "receipt_sha256": receipt_sha,
        }
        if self._signing_key is not None and self._signer_id is not None:
            sig = self._signing_key.sign(DOMAIN_PREFIX + canon)
            envelope["signatures"] = [
                {
                    "keyid": self._signer_id,
                    "sig": base64.b64encode(sig).decode("ascii"),
                }
            ]
        line = json.dumps(envelope, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
        if len(line) > MAX_RECEIPT_LINE_BYTES:
            raise ReceiptVerificationError(
                "serialized receipt entry exceeds maximum line size", reason="receipt-too-large"
            )
        if self._byte_size + len(line) > MAX_RECEIPT_LOG_BYTES:
            raise ReceiptVerificationError(
                "receipt log would exceed maximum byte budget", reason="receipt-too-large"
            )
        fd, st = _open_private_append(self.path)
        try:
            if (st.st_dev, st.st_ino) != self._inode or st.st_size != self._byte_size:
                raise ReceiptVerificationError(
                    "receipt sink file changed unexpectedly on disk",
                    reason="receipt-chain-broken",
                )
            view = memoryview(line)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self._byte_size += len(line)
        self._seq += 1
        self._head = receipt_sha
        self._digests.append(receipt_sha)
        return envelope


def _parse_signature_items(raw_sigs: Any) -> list[tuple[str | None, bytes]]:
    if not isinstance(raw_sigs, list) or not raw_sigs or len(raw_sigs) > 32:
        raise ReceiptVerificationError(
            "receipt entry lacks a valid signatures array", reason="signers-insufficient"
        )
    parsed: list[tuple[str | None, bytes]] = []
    for item in raw_sigs:
        if not isinstance(item, Mapping) or set(item) - {"keyid", "sig"} or "sig" not in item:
            raise ReceiptVerificationError(
                "malformed receipt signature object", reason="receipt-invalid"
            )
        sig_b64 = item.get("sig")
        hint = item.get("keyid")
        if not isinstance(sig_b64, str) or (
            hint is not None and (not isinstance(hint, str) or not _KEY_ID_RE.fullmatch(hint))
        ):
            raise ReceiptVerificationError(
                "malformed receipt signature fields", reason="receipt-invalid"
            )
        try:
            sig_bytes = base64.b64decode(sig_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ReceiptVerificationError(
                "receipt signature is not valid base64", reason="receipt-invalid"
            ) from exc
        if len(sig_bytes) != 64:
            raise ReceiptVerificationError(
                "receipt signature must be 64 Ed25519 bytes", reason="receipt-invalid"
            )
        parsed.append((hint, sig_bytes))
    return parsed


def _verify_signatures(
    entry: Mapping[str, Any],
    canon_body: bytes,
    trusted_ring: Mapping[str, Ed25519PublicKey],
    threshold: int,
) -> set[str]:
    parsed = _parse_signature_items(entry.get("signatures"))
    matched: set[str] = set()
    message = DOMAIN_PREFIX + canon_body
    attempts = 0
    ordered_ring = sorted(trusted_ring.items())
    for hint, sig_bytes in parsed:
        if hint is not None:
            pub = trusted_ring.get(hint)
            if pub is None or hint in matched:
                continue
            candidates: list[tuple[str, Ed25519PublicKey]] = [(hint, pub)]
        else:
            candidates = [(kid, pub) for kid, pub in ordered_ring if kid not in matched]
        for kid, pub in candidates:
            if attempts >= MAX_SIGNATURE_ATTEMPTS:
                break
            attempts += 1
            try:
                pub.verify(sig_bytes, message)
            except InvalidSignature:
                continue
            matched.add(kid)
            break
    if len(matched) < threshold:
        raise ReceiptVerificationError(
            "insufficient trusted receipt signatures", reason="signers-insufficient"
        )
    return matched


def _validate_core_schema(entry: Mapping[str, Any], expected_seq: int) -> None:
    for str_field in ("timestamp", "reason", "server_id", "tool_name", "action", "resource"):
        if not isinstance(entry.get(str_field), str):
            raise ReceiptVerificationError(
                f"receipt field {str_field} invalid at seq {expected_seq}",
                reason="receipt-invalid",
            )
    for signer_field in ("trust_signers", "snapshot_signers", "approval_signers"):
        val = entry.get(signer_field)
        if val is not None and (
            not isinstance(val, list) or not all(isinstance(s, str) for s in val)
        ):
            raise ReceiptVerificationError(
                f"receipt field {signer_field} invalid at seq {expected_seq}",
                reason="receipt-invalid",
            )


def _verify_raw_lines(
    raw: bytes,
    *,
    trusted_ring: Mapping[str, Ed25519PublicKey],
    require_signatures: bool,
    threshold: int = 1,
    expected_merkle_root: str | None = None,
) -> tuple[VerifiedReceiptLog, list[str]]:
    if not raw or not raw.endswith(b"\n"):
        raise ReceiptVerificationError(
            "receipt log must be non-empty LF-terminated JSONL",
            reason="receipt-invalid",
        )
    lines = raw[:-1].split(b"\n")
    if not lines or len(lines) > MAX_RECEIPT_ENTRIES:
        raise ReceiptVerificationError(
            "receipt log is empty or exceeds entry limit", reason="receipt-invalid"
        )

    expected_prev = GENESIS_HASH
    digests: list[str] = []
    admitted_count = 0
    denied_count = 0
    observed_signers: set[str] = set()

    for expected_seq, line in enumerate(lines):
        if not line or len(line) > MAX_RECEIPT_LINE_BYTES or b"\r" in line:
            raise ReceiptVerificationError(
                f"receipt line {expected_seq} is empty, contains CR, or exceeds size limit",
                reason="receipt-invalid",
            )
        try:
            entry = strict_json(line)
        except Exception as exc:
            raise ReceiptVerificationError(
                f"receipt line {expected_seq} is not strict JSON", reason="receipt-invalid"
            ) from exc
        if not isinstance(entry, dict) or entry.get("format") != RECEIPT_FORMAT:
            raise ReceiptVerificationError(
                f"receipt line {expected_seq} does not match {RECEIPT_FORMAT}",
                reason="receipt-invalid",
            )
        if type(entry.get("seq")) is not int or entry["seq"] != expected_seq:
            raise ReceiptVerificationError(
                f"receipt sequence gap or reorder at index {expected_seq}",
                reason="receipt-chain-broken",
            )
        prev = entry.get("prev_receipt_sha256")
        if not isinstance(prev, str) or not hmac.compare_digest(prev, expected_prev):
            raise ReceiptVerificationError(
                f"receipt prev_receipt_sha256 mismatch at seq {expected_seq}",
                reason="receipt-chain-broken",
            )
        recorded_sha = entry.get("receipt_sha256")
        if not isinstance(recorded_sha, str) or not _SHA256_RE.fullmatch(recorded_sha):
            raise ReceiptVerificationError(
                f"receipt_sha256 malformed at seq {expected_seq}",
                reason="receipt-invalid",
            )
        if type(entry.get("admitted")) is not bool:
            raise ReceiptVerificationError(
                f"receipt outcome fields invalid at seq {expected_seq}",
                reason="receipt-invalid",
            )
        _validate_core_schema(entry, expected_seq)
        if "signatures" in entry and not (require_signatures or trusted_ring):
            _parse_signature_items(entry["signatures"])

        core = {k: v for k, v in entry.items() if k not in {"receipt_sha256", "signatures"}}
        canon_body = canonical_bytes(core)
        computed_sha = "sha256:" + hashlib.sha256(canon_body).hexdigest()
        if not hmac.compare_digest(recorded_sha, computed_sha):
            raise ReceiptVerificationError(
                f"receipt_sha256 digest mismatch at seq {expected_seq}",
                reason="receipt-tampered",
            )
        if require_signatures or trusted_ring:
            observed_signers |= _verify_signatures(entry, canon_body, trusted_ring, threshold)

        if entry["admitted"]:
            admitted_count += 1
        else:
            denied_count += 1
        expected_prev = computed_sha
        digests.append(computed_sha)

    computed_root = merkle_root(digests)
    if expected_merkle_root is not None:
        if not _SHA256_RE.fullmatch(expected_merkle_root):
            raise ReceiptVerificationError(
                "expected Merkle root must be sha256:<64 lowercase hex>",
                reason="receipt-invalid",
            )
        if not hmac.compare_digest(computed_root, expected_merkle_root):
            raise ReceiptVerificationError(
                "receipt log Merkle root does not match expected root",
                reason="receipt-merkle-mismatch",
            )

    return (
        VerifiedReceiptLog(
            entry_count=len(digests),
            admitted_count=admitted_count,
            denied_count=denied_count,
            head_receipt_sha256=expected_prev,
            merkle_root=computed_root,
            signers=tuple(sorted(observed_signers)),
        ),
        digests,
    )


def verify_receipt_log(
    path: Path,
    *,
    trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
    threshold: int = 1,
    require_signatures: bool = False,
    expected_merkle_root: str | None = None,
) -> VerifiedReceiptLog:
    """Verify a JSONL runtime receipt chain offline without following symlinks."""
    keys = dict(trusted_keys or {})
    if threshold < 1 or threshold > 32:
        raise ReceiptVerificationError(
            "signature threshold must be between 1 and 32", reason="configuration-invalid"
        )
    if threshold > 1 and not keys:
        raise ReceiptVerificationError(
            "threshold > 1 requires trusted public keys", reason="configuration-invalid"
        )
    if require_signatures and not keys:
        raise ReceiptVerificationError(
            "--require-signatures requires at least one trusted public key",
            reason="configuration-invalid",
        )
    ring = {kid: pub for kid, pub in keys.items() if key_id(pub) == kid}
    if keys and threshold > len(ring):
        raise ReceiptVerificationError(
            "signature threshold exceeds valid trusted key ring", reason="configuration-invalid"
        )
    try:
        with open_regular_file(path) as handle:
            raw = handle.read(MAX_RECEIPT_LOG_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise ReceiptVerificationError(
            "receipt log must be a readable regular file without symlinks",
            reason="receipt-io-error",
        ) from exc
    if len(raw) > MAX_RECEIPT_LOG_BYTES:
        raise ReceiptVerificationError(
            "receipt log exceeds maximum size limit", reason="receipt-too-large"
        )
    verified, _ = _verify_raw_lines(
        raw,
        trusted_ring=ring,
        require_signatures=require_signatures,
        threshold=threshold,
        expected_merkle_root=expected_merkle_root,
    )
    return verified
