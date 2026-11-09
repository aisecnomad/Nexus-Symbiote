"""Artifact-bound integrity verification under an explicit signer trust policy."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nexus_symbiote.core.hashing import (
    descriptor_binding,
    normalize_digest,
    open_regular_file,
    pathname_identity,
)

MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_SIGNED_ARTIFACT_BYTES = 5 * 1024 * 1024 * 1024
MAX_DISCOVERY_STATEMENT_BYTES = 64 * 1024
# A fixed message, so callers can report it instead of a generic signature failure.
SIGSTORE_MISSING = "sigstore package not installed; install nexus-symbiote[sigstore]"


@dataclass(frozen=True)
class DiscoveryContextPolicy:
    """Operator-supplied expectations for a signed discovery statement."""

    statement_path: Path
    bundle_path: Path
    repository: str
    revision: str
    scope: str
    producer_version: str
    max_age_seconds: int


@dataclass(frozen=True)
class SigstoreArtifactPolicy:
    """Trusted caller input, never inferred from a BOM or adjacent signature file.

    This policy authorizes verification of one artifact with one exact identity
    and OIDC issuer. It does not grant execution authority to the artifact.
    """

    artifact_path: Path
    bundle_path: Path
    expected_identity: str
    expected_issuer: str
    discovery_context: DiscoveryContextPolicy | None = None

    def __post_init__(self) -> None:
        if not self.expected_identity.strip() or not self.expected_issuer.strip():
            raise ValueError("Both an expected signer identity and OIDC issuer are required")


@dataclass
class VerificationResult:
    """Outcome of a signature or hash verification."""

    verified: bool
    identity: str | None = None
    issuer: str | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


def verify_file_hash(
    path: Path,
    expected_hash: str,
    algorithm: str | None = None,
) -> VerificationResult:
    """Verify a regular file against a well-formed SHA-2 digest."""
    try:
        algorithm, expected_digest = normalize_digest(expected_hash, algorithm)
    except ValueError as exc:
        return VerificationResult(verified=False, error=str(exc))
    actual = compute_file_hash(path, algorithm)
    if actual is None:
        return VerificationResult(verified=False, error="Failed to read a regular artifact file")
    actual_digest = actual.split(":", 1)[1]
    if hmac.compare_digest(actual_digest, expected_digest):
        return VerificationResult(
            verified=True,
            details={"algorithm": algorithm, "digest": actual_digest},
        )
    return VerificationResult(
        verified=False,
        error="Hash mismatch against the expected artifact digest",
        details={"algorithm": algorithm, "expected": expected_digest, "actual": actual_digest},
    )


def verify_sigstore_digest(
    digest_hex: str,
    bundle_json: bytes,
    expected_identity: str,
    expected_issuer: str,
) -> VerificationResult:
    """Verify a caller-inspected SHA-256 subject without a network refresh.

    The caller must bind this digest to the inspected artifact. This function
    verifies a raw artifact signature, not an arbitrary DSSE predicate's subject.
    """
    if (
        not expected_identity
        or not expected_identity.strip()
        or not expected_issuer
        or not expected_issuer.strip()
    ):
        return VerificationResult(
            False, error="Expected signer identity and OIDC issuer are both required"
        )
    try:
        _, digest = normalize_digest(digest_hex, "sha256")
        if len(bundle_json) > MAX_BUNDLE_BYTES:
            raise ValueError("bundle byte limit exceeded")
        from sigstore.hashes import Hashed
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
        from sigstore_models.common.v1 import HashAlgorithm

        bundle = Bundle.from_json(bundle_json)
        policy = Identity(identity=expected_identity, issuer=expected_issuer)
        verifier = Verifier.production(offline=True)
        verifier.verify_artifact(
            Hashed(algorithm=HashAlgorithm.SHA2_256, digest=bytes.fromhex(digest)), bundle, policy
        )
        return VerificationResult(
            True,
            identity=expected_identity,
            issuer=expected_issuer,
            details={
                "artifact_digest": f"sha256:{digest}",
                "bundle_digest": f"sha256:{hashlib.sha256(bundle_json).hexdigest()}",
                "method": "sigstore-python.verify_artifact",
            },
        )
    except ImportError:
        return VerificationResult(False, error=SIGSTORE_MISSING)
    except Exception as exc:
        return VerificationResult(
            False, error=f"Sigstore artifact verification failed ({type(exc).__name__})"
        )


def verify_sigstore_bundle(
    artifact_path: Path,
    bundle_path: Path,
    expected_identity: str | None = None,
    expected_issuer: str | None = None,
) -> VerificationResult:
    """Verify an exact local artifact under an explicitly selected signer policy.

    Inputs are bounded, regular files with no symlink traversal. Streaming hash
    verification uses the supported public Sigstore 3.x API and offline trust
    material. Missing trust material fails; no network refresh is initiated.
    """
    if (
        not expected_identity
        or not expected_identity.strip()
        or not expected_issuer
        or not expected_issuer.strip()
    ):
        return VerificationResult(
            False, error="Expected signer identity and OIDC issuer are both required"
        )
    try:
        with open_regular_file(bundle_path) as stream:
            bundle_bytes = stream.read(MAX_BUNDLE_BYTES + 1)
        if len(bundle_bytes) > MAX_BUNDLE_BYTES:
            return VerificationResult(False, error="Sigstore bundle exceeds byte limit")
        digest = compute_file_hash(artifact_path, "sha256")
        if digest is None:
            return VerificationResult(
                False, error="Artifact is unavailable, changed, or exceeds verification limit"
            )
        return verify_sigstore_digest(digest, bundle_bytes, expected_identity, expected_issuer)
    except (OSError, ValueError):
        return VerificationResult(
            False, error="Signature verification inputs could not be read safely"
        )


def compute_file_hash(path: Path, algorithm: str = "sha256") -> str | None:
    """Compute a file's SHA-2 digest, returning None when it cannot be checked."""
    try:
        algorithm = algorithm.lower()
        normalize_digest("0" * hashlib.new(algorithm).digest_size * 2, algorithm)
        h = hashlib.new(algorithm)
        total = 0
        with open_regular_file(path) as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > MAX_SIGNED_ARTIFACT_BYTES:
                return None
            while chunk := stream.read(8192):
                total += len(chunk)
                if total > MAX_SIGNED_ARTIFACT_BYTES:
                    return None
                h.update(chunk)
            after = os.fstat(stream.fileno())
            if descriptor_binding(before) != descriptor_binding(after) or pathname_identity(
                path
            ) != (after.st_dev, after.st_ino):
                return None
        return f"{algorithm}:{h.hexdigest()}"
    except (OSError, ValueError):
        return None


def verify_hash_consistency(hashes: dict[str, str], path: Path) -> list[VerificationResult]:
    """Verify each digest, rejecting conflicting key/prefix algorithms."""
    return [verify_file_hash(path, expected, algo) for algo, expected in hashes.items()]
