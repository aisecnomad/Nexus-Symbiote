"""Load explicitly selected operator signature policies without discovery.

JSON shape: {"version": 1, "artifacts": [{"artifact_path": "models/model.bin",
"bundle_path": "models/model.sigstore", "expected_identity": "publisher@example.test",
"expected_issuer": "https://issuer.example.test"}]}.

The operator policy may live outside the inspected project. Artifact and bundle
references are forward-slash paths beneath the supplied project root. Loading a
policy neither verifies a signature nor authorizes artifact execution.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.crypto import (
    MAX_BUNDLE_BYTES,
    MAX_SIGNED_ARTIFACT_BYTES,
    SigstoreArtifactPolicy,
)

MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_POLICY_ARTIFACTS = 1000
_FIELDS = frozenset({"artifact_path", "bundle_path", "expected_identity", "expected_issuer"})


class SignaturePolicyError(ValueError):
    """The selected policy cannot be used safely; messages omit input values."""


def unmatched_policy_entries(
    policies: Iterable[SigstoreArtifactPolicy], checked_policies: set[SigstoreArtifactPolicy]
) -> list[str]:
    """Identify every unchecked artifact by its one-based position in the operator policy."""
    return [
        f"Signature policy artifact #{index} did not match a collected model"
        for index, policy in enumerate(policies, start=1)
        if policy not in checked_policies
    ]


def _required_string(record: dict[str, Any], field: str) -> str:
    value = record[field]
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise SignaturePolicyError(f"Signature policy {field} must be a nonempty clean string")
    return value


def _relative_path(value: str) -> Path:
    path = Path(value)
    if (
        not path.parts
        or path.is_absolute()
        or PureWindowsPath(value).drive
        or "\\" in value
        or ".." in path.parts
        or "://" in value
    ):
        raise SignaturePolicyError(
            "Signature policy paths must be relative beneath the project root"
        )
    return path


def load_signature_policies(policy_path: Path, project_root: Path) -> list[SigstoreArtifactPolicy]:
    """Read one bounded strict JSON policy selected by the trusted operator.

    Each artifact has one policy. Unknown fields, duplicate object keys, duplicate
    artifact paths, missing files and symlinks are rejected. No ambient policy,
    repository configuration, signer hint or adjacent signature is trusted.
    """
    try:
        with open_regular_file(policy_path) as stream:
            if os.fstat(stream.fileno()).st_size > MAX_POLICY_BYTES:
                raise SignaturePolicyError("Signature policy exceeds the byte limit")
            raw = stream.read(MAX_POLICY_BYTES + 1)
        document = parse_json_strict(raw, max_bytes=MAX_POLICY_BYTES)
    except (OSError, ValueError, RecursionError):
        raise SignaturePolicyError(
            "Selected signature policy is unavailable or invalid strict JSON"
        ) from None
    if not isinstance(document, dict) or set(document) != {"version", "artifacts"}:
        raise SignaturePolicyError("Signature policy requires only version and artifacts fields")
    if type(document["version"]) is not int or document["version"] != 1:
        raise SignaturePolicyError("Unsupported signature policy version")
    records = document["artifacts"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_POLICY_ARTIFACTS:
        raise SignaturePolicyError("Signature policy requires a bounded nonempty artifacts list")
    policies: list[SigstoreArtifactPolicy] = []
    seen: set[Path] = set()
    failures: list[str] = []
    with ConfinedCollection(project_root, failures) as files:
        for record in records:
            if not isinstance(record, dict) or set(record) != _FIELDS:
                raise SignaturePolicyError(
                    "Each artifact requires exactly the four signature policy fields"
                )
            artifact = _relative_path(_required_string(record, "artifact_path"))
            bundle = _relative_path(_required_string(record, "bundle_path"))
            identity = _required_string(record, "expected_identity")
            issuer = _required_string(record, "expected_issuer")
            try:
                parsed_issuer = urlsplit(issuer)
                if (
                    parsed_issuer.scheme != "https"
                    or not parsed_issuer.hostname
                    or parsed_issuer.username is not None
                    or parsed_issuer.password is not None
                    or parsed_issuer.query
                    or parsed_issuer.fragment
                ):
                    raise ValueError
            except ValueError:
                raise SignaturePolicyError(
                    "Expected OIDC issuer must be an HTTPS issuer URL without credentials"
                ) from None
            if artifact in seen:
                raise SignaturePolicyError("Duplicate artifact in signature policy")
            seen.add(artifact)
            try:
                # Open only to validate root containment, file kind and bounds.
                # Artifact bytes and signature authenticity are checked later.
                with files.open_regular(artifact, max_bytes=MAX_SIGNED_ARTIFACT_BYTES):
                    pass
                with files.open_regular(bundle, max_bytes=MAX_BUNDLE_BYTES):
                    pass
            except (OSError, ValueError):
                raise SignaturePolicyError(
                    "Policy artifact or bundle is unavailable beneath the project root"
                ) from None
            policies.append(
                SigstoreArtifactPolicy(files.root / artifact, files.root / bundle, identity, issuer)
            )
    if failures:
        raise SignaturePolicyError("Signature policy references could not be safely inspected")
    return policies
