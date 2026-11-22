"""Runtime authorization policy export and corroborated compliance evidence packs.

Kept separate from ``cli.py`` and the thin command wrappers so subcommand modules never
import ``cli.py`` and every corroboration path shares one boundary check.
"""

from __future__ import annotations

import functools
import json
import os
import re
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import click

from nexus_symbiote import attestation
from nexus_symbiote.attestation import MAX_SUBJECT_BYTES
from nexus_symbiote.attestation_cli import _load_trusted_public
from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.core.enums import AssuranceLevel, SerializationSafety
from nexus_symbiote.core.hashing import hash_bytes, normalize_digest
from nexus_symbiote.core.inventory_digests import inventory_digests
from nexus_symbiote.core.models import MCPServerComponent, ModelComponent, ToolComponent
from nexus_symbiote.graph import validate_graph
from nexus_symbiote.policy import (
    PolicyError,
    additional_exclusions,
    resolved_project_policy,
    running_in_ci,
)
from nexus_symbiote.runtime import key_id
from nexus_symbiote.runtime_cli import (
    _check_key_placement,
    _InputTooLargeError,
    _KeyFileError,
    _read,
    _refuse_source_overwrite,
)
from nexus_symbiote.utils.crypto import VERIFIED_SIGNING_STATUSES
from nexus_symbiote.utils.terminal import echo_line, json_text, neutralize, write_cli_output

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy

_POLICY_FORMATS = frozenset({"cedar", "rego", "json"})
_UNVERIFIED_SEVERITIES = frozenset({"critical", "error", "unknown"})
_MAX_POLICY_DIAGNOSTIC_CHARS = 1024


def resolve_project_root(value: str | Path, *, label: str) -> Path:
    """Resolve a project directory, refusing relative symlinks that escape ``cwd``."""
    requested = Path(value)
    resolved = requested.resolve()
    if Path(os.path.normpath(requested.absolute())) == resolved:
        return resolved
    if (
        not requested.is_absolute()
        and ".." not in requested.parts
        and not resolved.is_relative_to(Path.cwd().resolve())
    ):
        raise click.BadParameter(
            f"{value} leads outside the current directory through a symbolic link; "
            f"name the directory it resolves to, {resolved}, to collect that directory",
            param_hint=label,
        )
    echo_line(
        "Note: ", label, " ", value, " resolves through a symbolic link to ", resolved, err=True
    )
    return resolved


def require_binding_key() -> None:
    """Validate ``NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`` length when set."""
    from nexus_symbiote.scanners.mcp import _MIN_SOURCE_BINDING_KEY_LENGTH, SOURCE_BINDING_KEY_ENV

    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if key and len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise click.UsageError(
            f"{SOURCE_BINDING_KEY_ENV} must contain at least "
            f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
        )


def load_signer_policies(path: Path | None, project: Path) -> list[SigstoreArtifactPolicy]:
    """Load an explicit operator signer policy JSON outside ``project``."""
    from nexus_symbiote.signature_policy import load_signature_policies

    if path is None:
        return []
    try:
        return load_signature_policies(path, project)
    except ValueError as exc:
        raise click.ClickException(neutralize(exc)) from None


def verify_file_attestation(
    subject_path: Path,
    envelope_path: Path,
    *,
    trusted_keys: tuple[Path, ...],
    purpose: attestation.Purpose,
    project: Path | None = None,
    inventory: Path | None = None,
    subject_bytes: bytes | None = None,
    failure_prefix: str = "attestation verification failed",
) -> attestation.VerifiedAttestation:
    """Verify a DSSE inventory attestation envelope against ``subject_path``."""
    roles = {
        "SUBJECT": subject_path,
        "ENVELOPE": envelope_path,
        "PROJECT": project,
        "INVENTORY": inventory,
    }
    named = {role: path for role, path in roles.items() if path is not None}
    inputs, holders = tuple(named.values()), ", ".join(named)
    _check_key_placement(trusted_keys, inputs, option="--trusted-key", holders=holders)

    def _read_role(role: str, loader: functools.partial[Any]) -> Any:
        try:
            return loader()
        except _KeyFileError as exc:
            raise click.ClickException(f"{failure_prefix}: {exc} (key-invalid)") from None
        except _InputTooLargeError:
            raise click.ClickException(
                f"{failure_prefix}: the {role} exceeds its size limit (input-too-large)"
            ) from None
        except OSError:
            raise click.ClickException(
                f"{failure_prefix}: the {role} is not a readable regular file reached without "
                "symbolic links (input-unreadable)"
            ) from None

    ring: dict[str, Ed25519PublicKey] = {}
    for key_path in trusted_keys:
        pub = cast(
            "Ed25519PublicKey",
            _read_role("trusted key file", functools.partial(_load_trusted_public, key_path)),
        )
        ring[key_id(pub)] = pub
    raw_env = cast(
        bytes,
        _read_role(
            "envelope file",
            functools.partial(_read, envelope_path, attestation.MAX_ENVELOPE_BYTES),
        ),
    )
    if subject_bytes is not None:
        if len(subject_bytes) > MAX_SUBJECT_BYTES:
            raise click.ClickException(
                f"{failure_prefix}: the subject file exceeds its size limit (input-too-large)"
            )
        data = subject_bytes
    else:
        data = cast(
            bytes,
            _read_role("subject file", functools.partial(_read, subject_path, MAX_SUBJECT_BYTES)),
        )
    try:
        verified = attestation.verify_attestation(
            attestation.parse_envelope(raw_env),
            data,
            trusted_keys=ring,
            purpose=purpose,
            threshold=1,
            match="bytes",
        )
    except attestation.AttestationError as exc:
        raise click.ClickException(f"{failure_prefix}: {exc} ({exc.reason})") from None
    return replace(verified, envelope_digest=hash_bytes(raw_env))


def corroborate_against_project(
    bom: AIBOM,
    project: Path,
    signature_policy: Path | None = None,
) -> tuple[str, frozenset[str], frozenset[str]]:
    """Reconcile and integrity-check ``bom`` in the named project's scan scope."""
    from nexus_symbiote.validators.completeness import (
        CompletenessValidator,
        discovery_producer_check,
        discovery_signature_required,
    )
    from nexus_symbiote.validators.integrity import IntegrityValidator

    root = resolve_project_root(project, label="--project")
    require_binding_key()
    sig_policies = load_signer_policies(signature_policy, root)
    try:
        policy, _ = resolved_project_policy(root)
    except PolicyError as exc:
        message = neutralize(f"could not load validation settings for --project: {exc}")
        if len(message) > _MAX_POLICY_DIAGNOSTIC_CHARS:
            message = message[: _MAX_POLICY_DIAGNOSTIC_CHARS - 3] + "..."
        raise click.ClickException(message) from exc
    if extra_paths := additional_exclusions(policy.scan):
        entries = "entry" if len(extra_paths) == 1 else "entries"
        where = " in CI" if running_in_ci() else ""
        raise click.ClickException(
            f"the project policy weakens the built-in gates{where} because "
            f"scan.exclude_paths contains {len(extra_paths)} additional {entries}"
        )
    excluded = policy.scan.exclude_paths
    c_report = CompletenessValidator().validate_against_project(
        bom, root, exclude_paths=excluded, signature_policies=sig_policies
    )
    if not c_report.is_complete:
        raise click.ClickException("inventory failed completeness reconciliation against --project")
    i_report = IntegrityValidator(signature_policies=sig_policies).validate(
        bom, root, exclude_paths=excluded, bound_imports=c_report.bound_imports
    )
    if i_report.status == "fail" or bool(i_report.omitted_severities & _UNVERIFIED_SEVERITIES):
        raise click.ClickException("inventory failed integrity validation against --project")
    if discovery_signature_required(
        policy.validation.require_discovery_signature, root, sig_policies
    ):
        _status, problems = discovery_producer_check(
            bom, root, sig_policies, exclude_paths=excluded
        )
        if problems:
            raise click.ClickException(
                "inventory failed discovery producer verification against --project"
            )
    unverified_refs = frozenset(
        issue.component_ref for issue in i_report.issues if issue.severity in _UNVERIFIED_SEVERITIES
    )
    from nexus_symbiote.utils.crypto import policy_entries

    has_policy = bool(policy_entries(sig_policies))
    corroborated_models = frozenset(
        c.bom_ref
        for c in bom.components
        if isinstance(c, ModelComponent)
        and has_policy
        and c.signing_status in VERIFIED_SIGNING_STATUSES
        and c.bom_ref not in unverified_refs
    )
    return c_report.basis, corroborated_models, unverified_refs


def _valid_sha256(value: str | None, *, prefixed: bool) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        alg, dig = normalize_digest(value, "sha256")
    except ValueError:
        return None
    return f"{alg}:{dig}" if prefixed else dig


def _cedar_str(value: str) -> str:
    """Format ``value`` as a valid Cedar string literal with control/CI characters escaped."""
    ado_brackets = {m.end() - 1 for m in re.finditer(r"##[A-Za-z0-9_.-]*\[", value)}
    parts = ['"']
    for idx, ch in enumerate(value):
        code = ord(ch)
        if idx in ado_brackets:
            parts.append("\\u{5b}")
        elif ch == "\\":
            parts.append("\\\\")
        elif ch == '"':
            parts.append('\\"')
        elif ch == "\n":
            parts.append("\\n")
        elif ch == "\r":
            parts.append("\\r")
        elif ch == "\t":
            parts.append("\\t")
        elif ch == "\0":
            parts.append("\\0")
        elif code < 0x20 or code >= 0x7F:
            parts.append(f"\\u{{{code:x}}}")
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def render_authorization_policy(
    bom: AIBOM,
    policy_format: str = "cedar",
    *,
    verified_only: bool = True,
    corroborated_model_refs: frozenset[str] | set[str] | None = None,
    unverified_refs: frozenset[str] | set[str] = frozenset(),
) -> str:
    """Render a deterministic Cedar, Rego v1, or JSON authorization policy from an inventory."""
    if policy_format not in _POLICY_FORMATS:
        raise ValueError(f"unsupported policy format: {policy_format}")
    graph_issues = validate_graph(bom)
    if graph_issues:
        raise ValueError("invalid graph: " + "; ".join(graph_issues))

    allowed_assurance = {AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED}
    tools = []
    for c in sorted(bom.components, key=lambda x: x.bom_ref):
        if not isinstance(c, ToolComponent):
            continue
        defn_hash = _valid_sha256(c.definition_hash, prefixed=True)
        if defn_hash is None:
            continue
        if verified_only and (
            c.assurance_level not in allowed_assurance
            or c.bom_ref in unverified_refs
            or (c.mcp_server_ref is not None and c.mcp_server_ref in unverified_refs)
        ):
            continue
        tools.append(
            {
                "bom_ref": c.bom_ref,
                "name": c.name,
                "mcp_server_ref": c.mcp_server_ref,
                "definition_hash": defn_hash,
            }
        )
    servers = [
        {
            "bom_ref": c.bom_ref,
            "name": c.name,
            "transport": c.transport,
            "version_pinned": c.version_pinned,
            "mcp_role": c.properties.get("mcp_role", "server"),
        }
        for c in sorted(bom.components, key=lambda x: x.bom_ref)
        if isinstance(c, MCPServerComponent)
        and (
            not verified_only
            or (
                c.version_pinned is True
                and c.assurance_level in allowed_assurance
                and c.bom_ref not in unverified_refs
            )
        )
    ]
    models = []
    for c in sorted(bom.components, key=lambda x: x.bom_ref):
        if not isinstance(c, ModelComponent):
            continue
        model_sha = _valid_sha256(c.hashes.get("sha256"), prefixed=False)
        if model_sha is None:
            continue
        if c.serialization_safety is not SerializationSafety.SAFE or c.trust_remote_code is True:
            continue
        if verified_only:
            if c.signing_status not in VERIFIED_SIGNING_STATUSES or c.bom_ref in unverified_refs:
                continue
            if c.bom_ref not in (corroborated_model_refs or ()):
                continue
        models.append(
            {
                "bom_ref": c.bom_ref,
                "name": c.name,
                "sha256": model_sha,
                "signing_status": c.signing_status,
            }
        )
    bundle = {
        "format": "nexus-symbiote/authorization-policy/v1",
        "serial_number": bom.metadata.serial_number,
        "verified_only": verified_only,
        "allowed_tools": tools,
        "allowed_mcp_servers": servers,
        "allowed_models": models,
    }
    if policy_format == "json":
        return json.dumps(bundle, indent=2)
    if policy_format == "rego":
        return (
            "package nexus_symbiote.authz\n\nimport rego.v1\n\n"
            "default allow_tool := false\ndefault allow_model := false\n\n"
            f"allowed_tools := {json.dumps({t['bom_ref']: t['definition_hash'] for t in tools}, sort_keys=True)}\n"
            f"allowed_models := {json.dumps({m['bom_ref']: m['sha256'] for m in models}, sort_keys=True)}\n\n"
            "allow_tool if {\n"
            "  expected := allowed_tools[input.tool_ref]\n"
            "  input.definition_hash == expected\n"
            "}\n\n"
            "allow_model if {\n"
            "  expected := allowed_models[input.model_ref]\n"
            "  input.sha256 == expected\n"
            "}\n"
        )
    lines = ["// Nexus SymBiote generated default-deny Cedar policy (v1)"]
    for t in tools:
        lines.append(
            f'permit (principal, action == NexusSymbiote::Action::"InvokeTool", '
            f"resource == NexusSymbiote::Tool::{_cedar_str(str(t['bom_ref']))}) when {{\n"
            f"  context.definition_hash == {_cedar_str(str(t['definition_hash']))}\n}};"
        )
    for m in models:
        lines.append(
            f'permit (principal, action == NexusSymbiote::Action::"UseModel", '
            f"resource == NexusSymbiote::Model::{_cedar_str(str(m['bom_ref']))}) when {{\n"
            f"  context.sha256 == {_cedar_str(str(m['sha256']))}\n}};"
        )
    return "\n".join(lines) + "\n"


def run_export_policy(
    inventory: Path,
    *,
    policy_format: str,
    verified_only: bool,
    project: Path | None,
    signature_policy: Path | None,
    attestation_envelope: Path | None,
    trusted_keys: tuple[Path, ...],
    output: Path | None,
) -> None:
    """Execute the ``export-policy`` CLI workflow."""
    if signature_policy is not None and project is None:
        raise click.UsageError("--signature-policy requires --project")
    if trusted_keys and attestation_envelope is None:
        raise click.UsageError("--trusted-key requires --require-attestation")
    if attestation_envelope is not None and not trusted_keys:
        raise click.UsageError("--require-attestation requires at least one --trusted-key")
    if verified_only and project is None and attestation_envelope is None:
        raise click.UsageError(
            "--verified-only requires --project or --require-attestation with --trusted-key; "
            "pass --include-declared to export uncorroborated inventory claims"
        )
    _refuse_source_overwrite(output, inventory)
    try:
        bom, raw_bytes = AIBOM.load_with_bytes(inventory)
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(inventory)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc
    graph_issues = validate_graph(bom)
    if graph_issues:
        raise click.ClickException(
            "invalid graph: " + "; ".join(neutralize(issue) for issue in graph_issues)
        )
    if attestation_envelope is not None:
        verify_file_attestation(
            inventory,
            attestation_envelope,
            trusted_keys=trusted_keys,
            purpose="reviewed",
            project=project,
            subject_bytes=raw_bytes,
        )
    # A reviewed attestation vouches for the file, not for a model's digest or signature:
    # only --project with --signature-policy corroborates a model permit.
    corroborated_models: frozenset[str] = frozenset()
    unverified_refs: frozenset[str] = frozenset()
    if project is not None:
        _basis, corroborated_models, unverified_refs = corroborate_against_project(
            bom, project, signature_policy
        )
    text = render_authorization_policy(
        bom,
        policy_format,
        verified_only=verified_only,
        corroborated_model_refs=corroborated_models,
        unverified_refs=unverified_refs,
    )
    if output is not None:
        write_cli_output(output, text)
        return
    if policy_format in {"json", "rego"}:
        click.echo(json_text(text), nl=policy_format == "json")
    else:
        click.echo(text, nl=False)


def build_evidence_pack(
    raw_bytes: bytes,
    bom: AIBOM,
    *,
    project: Path | None = None,
    signature_policy: Path | None = None,
) -> dict[str, Any]:
    """Build the compliance evidence pack for ``crosswalk --include-evidence-pack``."""
    digests = inventory_digests(raw_bytes)
    declared_signed_models = [
        {
            "bom_ref": c.bom_ref,
            "name": c.name,
            "sha256": model_sha,
            "signing_status": c.signing_status,
        }
        for c in sorted(bom.components, key=lambda x: x.bom_ref)
        if isinstance(c, ModelComponent)
        and c.signing_status in VERIFIED_SIGNING_STATUSES
        and c.serialization_safety is SerializationSafety.SAFE
        and c.trust_remote_code is not True
        and (model_sha := _valid_sha256(c.hashes.get("sha256"), prefixed=False)) is not None
    ]
    verification_basis = "unverified-supplied-bom"
    verified_models: list[dict[str, Any]] = []
    if project is not None:
        verification_basis, corroborated_refs, _unverified = corroborate_against_project(
            bom, project, signature_policy
        )
        verified_models = [
            entry for entry in declared_signed_models if entry["bom_ref"] in corroborated_refs
        ]

    return {
        "verification_basis": verification_basis,
        "inventory_digests": {
            "file_sha256": digests.file_sha256,
            "canonical_digest": digests.canonical_digest,
            "content_digest": digests.content_digest,
        },
        "component_counts": bom.summary()["component_types"],
        "verified_models": verified_models,
        "declared_signed_models": declared_signed_models,
        "pinned_mcp_servers": [
            {
                "bom_ref": c.bom_ref,
                "name": c.name,
                "transport": c.transport,
                "launcher_package": c.launcher_package,
            }
            for c in sorted(bom.components, key=lambda x: x.bom_ref)
            if isinstance(c, MCPServerComponent) and c.version_pinned is True
        ],
        "fingerprinted_tools": [
            {"bom_ref": c.bom_ref, "name": c.name, "definition_hash": defn_hash}
            for c in sorted(bom.components, key=lambda x: x.bom_ref)
            if isinstance(c, ToolComponent)
            and (defn_hash := _valid_sha256(c.definition_hash, prefixed=True)) is not None
        ],
    }
