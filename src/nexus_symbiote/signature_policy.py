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
import re
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.crypto import (
    MAX_BUNDLE_BYTES,
    MAX_DISCOVERY_STATEMENT_BYTES,
    MAX_SIGNED_ARTIFACT_BYTES,
    DiscoveryContextPolicy,
    SigstoreArtifactPolicy,
)

MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_POLICY_ARTIFACTS = 1000
_FIELDS = frozenset({"artifact_path", "bundle_path", "expected_identity", "expected_issuer"})
_CONTEXT_FIELDS = frozenset(
    {
        "statement_path",
        "bundle_path",
        "repository",
        "revision",
        "scope",
        "producer_version",
        "max_age_seconds",
    }
)


class SignaturePolicyError(ValueError):
    """The selected policy cannot be used safely; messages omit input values."""


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
    seen_identities: set[tuple[int, int]] = set()
    failures: list[str] = []
    with ConfinedCollection(project_root, failures) as files:
        for record in records:
            if not isinstance(record, dict) or set(record) not in (
                _FIELDS,
                _FIELDS | {"discovery_context"},
            ):
                raise SignaturePolicyError(
                    "Each artifact requires the four signature policy fields and optional discovery_context"
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
            context = None
            if "discovery_context" in record:
                item = record["discovery_context"]
                if not isinstance(item, dict) or set(item) != _CONTEXT_FIELDS:
                    raise SignaturePolicyError("Discovery context requires all expected fields")
                age = item["max_age_seconds"]
                if type(age) is not int or not 1 <= age <= 604800:
                    raise SignaturePolicyError(
                        "Discovery context max_age_seconds must be 1 to 604800"
                    )
                statement = _relative_path(_required_string(item, "statement_path"))
                statement_bundle = _relative_path(_required_string(item, "bundle_path"))
                context = DiscoveryContextPolicy(
                    files.root / statement,
                    files.root / statement_bundle,
                    _required_string(item, "repository"),
                    _required_string(item, "revision"),
                    _required_string(item, "scope"),
                    _required_string(item, "producer_version"),
                    age,
                )
                if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", context.revision):
                    raise SignaturePolicyError(
                        "Discovery revision must be a full lowercase commit digest"
                    )
            try:
                # Open only to validate root containment, file kind and bounds.
                # Artifact bytes and signature authenticity are checked later.
                with files.open_regular(artifact, max_bytes=MAX_SIGNED_ARTIFACT_BYTES):
                    pass
                with files.open_regular(bundle, max_bytes=MAX_BUNDLE_BYTES):
                    pass
                if context is not None:
                    with files.open_regular(statement, max_bytes=MAX_DISCOVERY_STATEMENT_BYTES):
                        pass
                    with files.open_regular(statement_bundle, max_bytes=MAX_BUNDLE_BYTES):
                        pass
            except (OSError, ValueError):
                raise SignaturePolicyError(
                    "Policy artifact or bundle is unavailable beneath the project root"
                ) from None
            artifact_id = files.path_identity(artifact)
            if artifact_id is None or artifact_id in seen_identities:
                raise SignaturePolicyError("Duplicate or unavailable signature policy artifact")
            seen_identities.add(artifact_id)
            if context is not None:
                from nexus_symbiote.scanners.shadowscan import REPORT_PATHS

                report_ids = [files.path_identity(path) for path in REPORT_PATHS]
                first_report_id = next(
                    (identity for identity in report_ids if identity is not None), None
                )
                if artifact_id != first_report_id:
                    raise SignaturePolicyError(
                        "Discovery context must name the report selected by the ShadowScan collector"
                    )
            policies.append(
                SigstoreArtifactPolicy(
                    files.root / artifact, files.root / bundle, identity, issuer, context
                )
            )
    if failures:
        raise SignaturePolicyError("Signature policy references could not be safely inspected")
    return policies
