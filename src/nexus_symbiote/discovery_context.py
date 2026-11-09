"""Verify an operator-scoped, signed statement about one discovery report."""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.crypto import MAX_DISCOVERY_STATEMENT_BYTES, SigstoreArtifactPolicy

_FIELDS = frozenset(
    {
        "version",
        "report_sha256",
        "repository",
        "revision",
        "scope",
        "producer_version",
        "produced_at",
    }
)
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")


def discovery_context_problems(
    root: Path, policy: SigstoreArtifactPolicy, report_digest: str, *, now: datetime | None = None
) -> list[str]:
    """Authenticate statement bytes before checking its report, subject and age.

    This verifies a producer claim, not that the producer ran an accurate scan.
    The caller must separately authenticate and reconcile the report itself.
    """
    from nexus_symbiote.utils.crypto import SIGSTORE_MISSING, verify_sigstore_bundle

    context = policy.discovery_context
    if context is None:
        return []
    failures: list[str] = []
    try:
        with ConfinedCollection(
            root, failures, max_file_bytes=MAX_DISCOVERY_STATEMENT_BYTES
        ) as files:
            raw = files.read_bytes(context.statement_path.relative_to(files.root))
        if raw is None or failures:
            raise ValueError
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        verified = verify_sigstore_bundle(
            context.statement_path,
            context.bundle_path,
            policy.expected_identity,
            policy.expected_issuer,
        )
        if verified.error == SIGSTORE_MISSING:
            return [SIGSTORE_MISSING]
        if not (
            verified.verified
            and verified.identity == policy.expected_identity
            and verified.issuer == policy.expected_issuer
            and verified.details
            and hmac.compare_digest(str(verified.details.get("artifact_digest", "")), digest)
        ):
            return ["Discovery statement signature or signer policy verification failed."]
        statement: Any = parse_json_strict(raw, max_bytes=MAX_DISCOVERY_STATEMENT_BYTES)
        if not isinstance(statement, dict) or set(statement) != _FIELDS:
            raise ValueError
        if type(statement["version"]) is not int or statement["version"] != 1:
            raise ValueError
        if not all(isinstance(statement[key], str) for key in _FIELDS - {"version"}):
            raise ValueError
        if not hmac.compare_digest(statement["report_sha256"], report_digest):
            return ["Discovery statement does not bind the recorded report digest."]
        if any(
            statement[key] != getattr(context, key)
            for key in ("repository", "revision", "scope", "producer_version")
        ):
            return [
                "Discovery statement subject, scope or producer version differs from operator policy."
            ]
        produced = statement["produced_at"]
        if not _TIMESTAMP.fullmatch(produced):
            raise ValueError
        issued = datetime.fromisoformat(produced[:-1] + "+00:00")
        current = now if now is not None else datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError
        age = (current - issued).total_seconds()
        if age < 0 or age > context.max_age_seconds:
            return ["Discovery statement is future-dated or outside the allowed age."]
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        return ["Discovery statement is unavailable or malformed."]
    return []
