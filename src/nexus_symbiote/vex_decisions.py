"""Operator VEX decisions, execution-bound trace outcomes, and advisory report loading.

Enforces CycloneDX 1.7 VEX security invariants:
- Operator VEX decisions, trusted keys, and trace evidence are regular files (no symlinks
  or hard-linked policy files) stored outside the scanned project and enclosing git trees.
- Non-``in_triage`` decisions require ``owner`` and timezone-aware ``expires_at``, evaluated
  against wall-clock UTC time (never inventory timestamps or ``SOURCE_DATE_EPOCH``). Duplicate
  ``(id, component_ref)`` entries are refused.
- Trace evidence requires a verified Ed25519 DSSE attestation by default (unless
  ``allow_unsigned=True``), verifies ``inventory_sha256``, reads real ``trace-diff`` output
  (``reconciliation.matched``/``unobserved`` via ``inventory_ref``), and separates
  ``unobserved`` telemetry from ``declared_never_loaded``.
"""

from __future__ import annotations

import hmac
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from nexus_symbiote.core.hashing import (
    hash_bytes,
    open_directory_nofollow,
    open_regular_file,
    parse_json_strict,
)
from nexus_symbiote.policy import parse_yaml_mapping
from nexus_symbiote.utils.crypto import _trusted_ancestor_uids
from nexus_symbiote.utils.terminal import UNSAFE_TEXT

MAX_DECISIONS_BYTES = 4 * 1024 * 1024
MAX_DECISIONS = 5_000
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
# Format characters that ordinary text needs: ZWNJ and ZWJ (Persian, Indic scripts, emoji
# sequences), variation selectors (emoji presentation) and the soft hyphen. Output
# neutralization replaces them; every other character UNSAFE_TEXT matches is refused.
_ORDINARY_FORMAT_CHARACTERS = re.compile(r"[\xad\u200c\u200d\ufe00-\ufe0f\U000e0100-\U000e01ef]")

VEXState = Literal["not_affected", "exploitable", "resolved", "false_positive", "in_triage"]
VEXJustification = Literal[
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
]


class VEXDecisionError(ValueError):
    """Raised when an operator VEX decision, trace evidence, or advisory file is unsafe or invalid."""


class VEXDecisionEntry(BaseModel):
    """One operator-authored triage decision for a finding or advisory."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=256)
    component_ref: str | None = Field(default=None, max_length=1024)
    state: VEXState
    justification: VEXJustification | None = None
    detail: str = Field(min_length=1, max_length=2048)
    owner: str = Field(min_length=1, max_length=256)
    expires_at: datetime | None = None
    inventory_sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    deployment_id: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("id", "detail", "owner", "deployment_id")
    @classmethod
    def _clean_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value.strip()
            or "\t" in value
            or UNSAFE_TEXT.search(_ORDINARY_FORMAT_CHARACTERS.sub("", value))
        ):
            raise ValueError(
                "must be a non-empty string without control, bidirectional or invisible characters"
            )
        return value.strip()

    @field_validator("expires_at")
    @classmethod
    def _require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("expires_at must include an explicit UTC or timezone offset")
        try:
            return value.astimezone(UTC)
        except OverflowError:
            raise ValueError("expires_at must be within the supported UTC range") from None

    @model_validator(mode="after")
    def _validate_policy_rules(self) -> VEXDecisionEntry:
        if self.state != "in_triage" and self.expires_at is None:
            raise ValueError("non-in_triage VEX decisions must specify expires_at")
        if self.justification is not None and self.state != "not_affected":
            raise ValueError("justification is only valid when state is 'not_affected'")
        return self


class VEXDecisionSet(BaseModel):
    """Versioned container for operator VEX decisions."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    decisions: list[VEXDecisionEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_unique_targets(self) -> VEXDecisionSet:
        seen: set[tuple[str, str | None]] = set()
        for entry in self.decisions:
            key = (entry.id, entry.component_ref)
            if key in seen:
                raise ValueError("duplicate VEX decision")
            seen.add(key)
        return self


@dataclass(frozen=True)
class LoadedVEXDecisions:
    """Validated operator VEX decisions with file digest provenance."""

    entries: tuple[VEXDecisionEntry, ...]
    sha256: str

    def lookup(self, vuln_id: str, component_ref: str) -> VEXDecisionEntry | None:
        """Return component-scoped decision first, then global."""
        global_match: VEXDecisionEntry | None = None
        for entry in self.entries:
            if entry.id != vuln_id:
                continue
            if entry.component_ref == component_ref:
                return entry
            if entry.component_ref is None and global_match is None:
                global_match = entry
        return global_match


@dataclass(frozen=True)
class ExecutionEvidence:
    """Execution-bound component classification derived from runtime trace evidence."""

    invoked_refs: frozenset[str]
    declared_never_loaded_refs: frozenset[str]
    unobserved_refs: frozenset[str]
    shadowed_refs: frozenset[str]
    sha256: str
    attested: bool = False
    attestation_sha256: str | None = None

    def outcome_for(self, component_ref: str) -> str | None:
        """Return 'shadowed', 'invoked', 'declared-never-loaded', 'unobserved', or None."""
        if component_ref in self.shadowed_refs:
            return "shadowed"
        if component_ref in self.invoked_refs:
            return "invoked"
        if component_ref in self.declared_never_loaded_refs:
            return "declared-never-loaded"
        if component_ref in self.unobserved_refs:
            return "unobserved"
        return None


def resolve_reference_time(explicit_now: datetime | None = None) -> datetime:
    """Resolve expiry reference time using explicit test clock or current UTC wall clock."""
    if explicit_now is not None:
        if explicit_now.tzinfo is None:
            raise VEXDecisionError("Reference time must be timezone-aware")
        return explicit_now.astimezone(UTC)
    return datetime.now(UTC)


def _repository_roots(path: Path) -> list[Path]:
    return [candidate for candidate in (path, *path.parents) if os.path.lexists(candidate / ".git")]


def _safe_stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except OSError:
        return None


def _ensure_outside_project(
    file_path: Path,
    project_root: Path | None,
    *,
    inventory_path: Path | None = None,
    forbid_inventory_dir: bool = False,
    label: str = "Operator VEX decisions file",
) -> None:
    resolved_file = file_path.resolve()
    untrusted: list[Path] = []
    if project_root is not None:
        resolved_root = project_root.resolve()
        untrusted.append(resolved_root)
        untrusted.extend(_repository_roots(resolved_root))
    if inventory_path is not None:
        inv_dir = inventory_path.resolve().parent
        untrusted.extend(_repository_roots(inv_dir))
        if forbid_inventory_dir:
            untrusted.append(inv_dir)
    untrusted.extend(_repository_roots(Path.cwd().resolve()))

    msg = f"{label} must live outside the scanned project and enclosing git repositories"
    if any(resolved_file.is_relative_to(root) for root in untrusted):
        raise VEXDecisionError(msg)
    if os.name == "posix" and untrusted:
        untrusted_ids = {
            (st.st_dev, st.st_ino) for root in untrusted if (st := _safe_stat(root)) is not None
        }
        if any(
            (st.st_dev, st.st_ino) in untrusted_ids
            for parent in resolved_file.parents
            if (st := _safe_stat(parent)) is not None
        ):
            raise VEXDecisionError(msg)


def _check_operator_directory(path: Path, trusted: set[int]) -> None:
    # Walk top down. A writable directory is safe for traversal only if its
    # trusted owner enforces sticky protection on the next, also checked entry.
    absolute = path.absolute()
    if ".." in absolute.parts:
        raise VEXDecisionError("Operator material must use a path without parent traversal")
    for directory in reversed(absolute.parents):
        try:
            fd = open_directory_nofollow(directory)
        except PermissionError:
            # Earlier ancestors passed the trust checks. A traverse-only entry can
            # still be inspected without following it or opening it for reading.
            info = directory.lstat()
            owner_trusted = stat.S_ISDIR(info.st_mode) and info.st_uid in trusted
        else:
            try:
                info = os.fstat(fd)
                owner_trusted = info.st_uid in trusted
                if (
                    not owner_trusted
                    and directory == Path(absolute.anchor)
                    and len(absolute.parts) > 2
                ):
                    # An unprivileged writer cannot rename a direct mount under
                    # a read-only namespace root with an unmapped UID.
                    owner_trusted = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY) and (
                        os.stat(absolute.parts[1], dir_fd=fd, follow_symlinks=False).st_dev
                        != info.st_dev
                    )
            finally:
                os.close(fd)
        if not owner_trusted or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise VEXDecisionError("Operator material has a writable or untrusted ancestor")


def _read_regular_bytes(
    path: Path, max_bytes: int, label: str, *, single_link: bool = False
) -> bytes:
    try:
        trusted = (
            _trusted_ancestor_uids(os.geteuid())
            if single_link and hasattr(os, "geteuid")
            else set()
        )
        if single_link:
            if not trusted:
                raise VEXDecisionError("Cannot establish ownership of operator material")
            _check_operator_directory(path, trusted)
        with open_regular_file(path) as handle:
            if single_link:
                info = os.fstat(handle.fileno())
                if info.st_nlink != 1:
                    raise VEXDecisionError(f"{label} must not have additional hard links")
                if info.st_uid not in trusted or info.st_mode & 0o022:
                    raise VEXDecisionError(
                        f"{label} has an untrusted owner or is group/world writable"
                    )
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        raise VEXDecisionError(f"Cannot safely read {label.lower()}: {exc}") from exc
    if len(raw) > max_bytes:
        raise VEXDecisionError(f"{label} exceeds {max_bytes} bytes")
    return raw


def load_vex_decisions(
    path: Path,
    *,
    project_root: Path | None = None,
    inventory_path: Path | None = None,
) -> LoadedVEXDecisions:
    """Load and validate an operator-owned VEX decisions YAML or JSON file."""
    _ensure_outside_project(
        path,
        project_root,
        inventory_path=inventory_path,
        forbid_inventory_dir=True,
        label="Operator VEX decisions file",
    )
    raw = _read_regular_bytes(path, MAX_DECISIONS_BYTES, "VEX decisions file", single_link=True)
    try:
        text = raw.decode("utf-8")
        # Aliases expand into repeated validation work, and a repeated key (a second
        # ``state:``) would silently replace the first: both are refused.
        payload: Any = (
            parse_json_strict(text, max_bytes=MAX_DECISIONS_BYTES)
            if path.suffix.lower() == ".json" or text.lstrip().startswith("{")
            else parse_yaml_mapping(text, max_nodes=100_000)
        )
    except (ValueError, RecursionError) as exc:
        raise VEXDecisionError("Invalid VEX decisions syntax or complexity") from exc
    if not isinstance(payload, dict):
        raise VEXDecisionError(
            "VEX decisions file must be a mapping with 'version' and 'decisions'"
        )
    if isinstance(payload.get("decisions"), list) and len(payload["decisions"]) > MAX_DECISIONS:
        raise VEXDecisionError(f"VEX decisions file exceeds {MAX_DECISIONS} entries")
    try:
        model = VEXDecisionSet.model_validate(payload)
    except ValidationError as exc:
        duplicate = any(
            e["msg"] == "Value error, duplicate VEX decision"
            for e in exc.errors(include_input=False)
        )
        raise VEXDecisionError(
            "duplicate VEX decision" if duplicate else "Invalid VEX decisions schema"
        ) from exc
    return LoadedVEXDecisions(entries=tuple(model.decisions), sha256=hash_bytes(raw))


def _load_trusted_keys(key_paths: Sequence[Path]) -> dict[str, Ed25519PublicKey]:
    from nexus_symbiote.runtime import key_id

    ring: dict[str, Ed25519PublicKey] = {}
    for key_path in key_paths:
        raw = _read_regular_bytes(key_path, MAX_KEY_BYTES, "Trusted key file", single_link=True)
        try:
            public = serialization.load_pem_public_key(raw)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise VEXDecisionError("Trusted key could not be loaded as Ed25519 PEM") from exc
        if not isinstance(public, Ed25519PublicKey):
            raise VEXDecisionError("Only Ed25519 public keys are supported")
        ring[key_id(public)] = public
    return ring


def _verify_trace_attestation(
    trace_bytes: bytes,
    attestation_path: Path,
    trusted_key_paths: Sequence[Path],
    *,
    project_root: Path | None,
    inventory_path: Path | None,
) -> str:
    from nexus_symbiote.attestation import (
        MAX_ENVELOPE_BYTES,
        AttestationError,
        parse_envelope,
        verify_attestation,
    )

    if not trusted_key_paths:
        raise VEXDecisionError("--trace-attestation requires at least one --trusted-key")
    for kpath in trusted_key_paths:
        _ensure_outside_project(
            kpath,
            project_root,
            inventory_path=inventory_path,
            forbid_inventory_dir=True,
            label="Trusted key file",
        )
    env_bytes = _read_regular_bytes(attestation_path, MAX_ENVELOPE_BYTES, "Trace attestation")
    ring = _load_trusted_keys(trusted_key_paths)
    try:
        verify_attestation(
            parse_envelope(env_bytes),
            trace_bytes,
            trusted_keys=ring,
            purpose="generated",
            match="bytes",
        )
    except AttestationError as exc:
        raise VEXDecisionError(f"Trace evidence attestation verification failed: {exc}") from exc
    return hash_bytes(env_bytes)


def _extract_refs(items: object) -> set[str]:
    refs: set[str] = set()
    if not isinstance(items, list):
        return refs
    for item in items:
        if isinstance(item, str) and item.strip():
            refs.add(item.strip())
        elif isinstance(item, dict):
            for key in ("inventory_ref", "bom_ref", "component_ref", "ref"):
                val = item.get(key)
                if isinstance(val, str) and val.strip():
                    refs.add(val.strip())
                    break
    return refs


def _trace_inventory_sha256(payload: dict[str, Any]) -> str | None:
    top = payload.get("inventory_sha256")
    if isinstance(top, str) and top.strip():
        return top.strip()
    inputs = payload.get("inputs")
    inv = inputs.get("inventory") if isinstance(inputs, dict) else None
    sha = inv.get("sha256") if isinstance(inv, dict) else None
    return sha.strip() if isinstance(sha, str) and sha.strip() else None


def load_execution_evidence(
    path: Path,
    *,
    project_root: Path | None = None,
    inventory_path: Path | None = None,
    expected_inventory_sha256: str | None = None,
    attestation_path: Path | None = None,
    trusted_key_paths: Sequence[Path] = (),
    allow_unsigned: bool = False,
) -> ExecutionEvidence:
    """Load execution-bound trace evidence from a ``trace-diff`` or execution-evidence JSON report."""
    if attestation_path is None and not allow_unsigned:
        raise VEXDecisionError(
            "Trace evidence requires --trace-attestation with --trusted-key "
            "(or explicit --allow-unsigned-trace-evidence)"
        )
    _ensure_outside_project(
        path,
        project_root,
        inventory_path=inventory_path,
        forbid_inventory_dir=attestation_path is None,
        label="Trace evidence file",
    )
    raw = _read_regular_bytes(path, MAX_REPORT_BYTES, "Trace evidence file")
    attestation_digest = None
    if attestation_path is not None:
        attestation_digest = _verify_trace_attestation(
            raw,
            attestation_path,
            trusted_key_paths,
            project_root=project_root,
            inventory_path=inventory_path,
        )

    payload = parse_json_strict(raw.decode("utf-8"), max_bytes=MAX_REPORT_BYTES)
    if not isinstance(payload, dict):
        raise VEXDecisionError("Trace evidence file must be a JSON object")

    recorded_sha = _trace_inventory_sha256(payload)
    if expected_inventory_sha256 is not None:
        if recorded_sha is None:
            raise VEXDecisionError("Trace evidence is missing inventory_sha256 binding")
        if not hmac.compare_digest(recorded_sha, expected_inventory_sha256):
            raise VEXDecisionError(
                "Trace evidence inventory_sha256 does not match the supplied AIBOM"
            )

    rec_map = payload["reconciliation"] if isinstance(payload.get("reconciliation"), dict) else {}
    invoked = (
        _extract_refs(payload.get("invoked"))
        | _extract_refs(payload.get("matched"))
        | _extract_refs(rec_map.get("matched"))
    )
    declared_never_loaded = _extract_refs(payload.get("declared_never_loaded"))
    unobserved = _extract_refs(payload.get("unobserved")) | _extract_refs(rec_map.get("unobserved"))
    shadowed = (
        _extract_refs(payload.get("shadowed"))
        | _extract_refs(payload.get("shadowed_refs"))
        | _extract_refs(rec_map.get("shadowed"))
    )
    return ExecutionEvidence(
        invoked_refs=frozenset(invoked),
        declared_never_loaded_refs=frozenset(declared_never_loaded - invoked - shadowed),
        unobserved_refs=frozenset(unobserved - invoked - shadowed - declared_never_loaded),
        shadowed_refs=frozenset(shadowed),
        sha256=hash_bytes(raw),
        attested=attestation_digest is not None,
        attestation_sha256=attestation_digest,
    )


@dataclass(frozen=True)
class LoadedAdvisoryReport:
    advisories: list[dict[str, Any]]
    sha256: str
    coverage: str
    checked: int
    skipped: int
    excluded: int
    errors: int


def load_advisory_report(
    path: Path,
    *,
    expected_inventory_sha256: str | None = None,
    allow_partial: bool = False,
) -> LoadedAdvisoryReport:
    """Load an advisory report JSON produced by ``advisories`` (live or offline)."""
    raw = _read_regular_bytes(path, MAX_REPORT_BYTES, "Advisory report")
    payload = parse_json_strict(raw.decode("utf-8"), max_bytes=MAX_REPORT_BYTES)
    if not isinstance(payload, dict) or not isinstance(payload.get("advisories"), list):
        raise VEXDecisionError("Advisory report must be a JSON object with an 'advisories' array")
    recorded_sha = payload.get("inventory_sha256")
    if expected_inventory_sha256 is not None:
        if not isinstance(recorded_sha, str) or not recorded_sha.strip():
            raise VEXDecisionError("Advisory report is missing inventory_sha256 binding")
        if not hmac.compare_digest(recorded_sha.strip(), expected_inventory_sha256):
            raise VEXDecisionError(
                "Advisory report inventory_sha256 does not match the supplied AIBOM"
            )

    def counter(name: str) -> int:
        value = payload.get("components_" + name)
        if type(value) is not int or value < 0:
            raise VEXDecisionError("Advisory report lacks valid coverage counters")
        return value

    checked, skipped, excluded = (counter(k) for k in ("checked", "skipped", "excluded"))
    errors = payload.get("errors")
    dry_run = payload.get("dry_run")
    if (
        not isinstance(errors, list)
        or not all(isinstance(e, str) for e in errors)
        or type(dry_run) is not bool
    ):
        raise VEXDecisionError("Advisory report lacks valid coverage counters")
    coverage = "none" if dry_run or not checked else "partial" if errors else "complete"
    if payload.get("coverage") != coverage or payload.get("complete") is not (
        coverage == "complete"
    ):
        raise VEXDecisionError("Advisory report coverage is inconsistent")
    if coverage != "complete" and not allow_partial:
        raise VEXDecisionError("Incomplete advisory coverage requires --allow-partial-advisories")
    advisories = payload["advisories"]
    if not all(
        isinstance(a, dict)
        and isinstance(a.get("advisory_id") or a.get("id"), str)
        and isinstance(a.get("component_ref") or a.get("bom_ref"), str)
        for a in advisories
    ):
        raise VEXDecisionError("Malformed advisory report entry")
    return LoadedAdvisoryReport(
        advisories, hash_bytes(raw), coverage, checked, skipped, excluded, len(errors)
    )
