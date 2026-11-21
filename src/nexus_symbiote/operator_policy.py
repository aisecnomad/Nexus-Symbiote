"""Signed operator policy loading outside the checkout, monotonic narrowing, and gate formats."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from xml.sax.saxutils import escape as xml_escape

from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.policy import (
    MAX_POLICY_YAML_NODES,
    Policy,
    PolicyError,
    RiskPolicy,
    ScanPolicy,
    ValidatePolicy,
    parse_yaml_mapping,
)
from nexus_symbiote.signature_policy import _identity, _repository_roots
from nexus_symbiote.utils.terminal import neutralize

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_OPERATOR_POLICY_BYTES = 1024 * 1024
GateReportFormat = Literal["text", "json", "markdown", "junit"]
EXIT_PASSED, EXIT_USAGE_ERROR, EXIT_GATE_FAILED, EXIT_COLLECTION_FAILED = 0, 2, 3, 4
_SEVERITY_STRICTNESS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "none": 5}
_ASSURANCE_STRICTNESS = {"declared": 0, "observed": 1, "verified": 2}
_MARKDOWN_PUNCTUATION = re.compile(r"([!-/:-@\[-`{-~])")
_WORKFLOW_COMMAND = re.compile(r"(?:::|##\[)")


class OperatorPolicyError(PolicyError):
    """The selected operator policy failed placement, integrity, or schema checks."""


class OperatorPolicyAttestationError(OperatorPolicyError):
    """Cryptographic verification of the operator policy envelope failed."""


@dataclass(frozen=True)
class LoadedOperatorPolicy:
    """Verified operator policy with its byte digest and any verified DSSE signer key IDs."""

    policy: Policy
    digest: str
    signers: tuple[str, ...] = ()


def _read_confined_operator_policy(policy_path: Path, root: Path | None) -> tuple[bytes, str]:
    inside_msg = (
        "Operator policy must be provisioned outside the scanned project and outside "
        "every repository that holds it"
    )
    untrusted: list[Path] = []
    if root is not None:
        resolved_root = root.resolve()
        untrusted.extend([resolved_root, *_repository_roots(resolved_root)])
    untrusted.extend(_repository_roots(Path.cwd().resolve()))
    resolved_policy = policy_path.resolve()
    if any(resolved_policy.is_relative_to(directory) for directory in untrusted):
        raise OperatorPolicyError(inside_msg)

    from nexus_symbiote.utils.crypto import _trust_anchor_error, _trusted_ancestor_uids

    uid = getattr(os, "geteuid", lambda: None)()
    trusted_uids = _trusted_ancestor_uids(uid) if uid is not None else set()
    try:
        with open_regular_file(policy_path) as stream:
            info = os.fstat(stream.fileno())
            if info.st_size > MAX_OPERATOR_POLICY_BYTES:
                raise OperatorPolicyError("Operator policy exceeds the 1 MiB byte limit")
            if info.st_nlink != 1:
                raise OperatorPolicyError("Operator policy must not have other hard links")
            if uid is not None and info.st_uid not in trusted_uids:
                raise OperatorPolicyError("Operator policy must be owned by the current user")
            if info.st_mode & 0o002:
                raise OperatorPolicyError(
                    "Operator policy and its directory must not be world-writable"
                )
            if (reason := _trust_anchor_error(policy_path, info)) is not None:
                raise OperatorPolicyError(f"Operator policy {reason}")
            raw = stream.read(MAX_OPERATOR_POLICY_BYTES + 1)
            if len(raw) > MAX_OPERATOR_POLICY_BYTES:
                raise OperatorPolicyError("Operator policy exceeds the 1 MiB byte limit")
            ancestors = {_identity(parent) for parent in Path(os.path.abspath(policy_path)).parents}
    except OperatorPolicyError:
        raise
    except OSError as exc:
        raise OperatorPolicyError("Selected operator policy cannot be safely read") from exc

    if untrusted:
        try:
            untrusted_inodes = {_identity(directory) for directory in untrusted}
        except OSError as exc:
            raise OperatorPolicyError("Target root is unavailable") from exc
        if ancestors & untrusted_inodes:
            raise OperatorPolicyError(inside_msg)
    return raw, "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_policy_attestation(
    raw_policy: bytes,
    policy_path: Path,
    root: Path | None,
    envelope_path: Path,
    trusted_keys: tuple[Path, ...],
    *,
    threshold: int = 1,
    max_age_days: int | None = 90,
) -> tuple[str, ...]:
    from datetime import timedelta

    import click
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from nexus_symbiote.attestation import AttestationError, parse_envelope, verify_attestation
    from nexus_symbiote.attestation_cli import _load_trusted_public
    from nexus_symbiote.runtime import key_id
    from nexus_symbiote.runtime_cli import (
        _check_key_placement,
        _InputTooLargeError,
        _KeyFileError,
    )

    if not trusted_keys:
        raise OperatorPolicyError(
            "--operator-policy-attestation requires at least one --operator-policy-key"
        )
    if max_age_days is not None and max_age_days < 0:
        raise OperatorPolicyError("--operator-policy-max-age-days must be >= 0")
    raw_envelope, _ = _read_confined_operator_policy(envelope_path, root)
    try:
        _check_key_placement(
            trusted_keys,
            (policy_path, envelope_path, *(() if root is None else (root,))),
            option="--operator-policy-key",
            holders="PROJECT, OPERATOR_POLICY, ENVELOPE",
        )
        ring: dict[str, Ed25519PublicKey] = {}
        for key_path in trusted_keys:
            pub = _load_trusted_public(key_path)
            if not isinstance(pub, Ed25519PublicKey):
                raise _KeyFileError("only Ed25519 public keys are supported")
            ring[key_id(pub)] = pub
        parsed_env = parse_envelope(raw_envelope)
    except AttestationError as exc:
        raise OperatorPolicyAttestationError(
            f"Operator policy attestation verification failed: {neutralize(exc)}"
        ) from exc
    except (
        OperatorPolicyError,
        click.ClickException,
        _KeyFileError,
        _InputTooLargeError,
        OSError,
        ValueError,
    ) as exc:
        raise OperatorPolicyError(
            f"Operator policy key or envelope cannot be loaded: {neutralize(exc)}"
        ) from exc

    try:
        verified = verify_attestation(
            parsed_env,
            raw_policy,
            trusted_keys=ring,
            purpose="policy",
            threshold=threshold,
            match="bytes",
            max_age=timedelta(days=max_age_days) if max_age_days else None,
        )
    except AttestationError as exc:
        raise OperatorPolicyAttestationError(
            f"Operator policy attestation verification failed: {neutralize(exc)}"
        ) from exc
    return verified.signers


def load_operator_policy(
    policy_path: Path,
    root: Path | None,
    *,
    envelope_path: Path | None = None,
    trusted_keys: tuple[Path, ...] = (),
    threshold: int = 1,
    allow_unsigned: bool = False,
    max_age_days: int | None = 90,
) -> LoadedOperatorPolicy:
    """Load and verify a signed operator policy outside the target checkout."""
    from pydantic import ValidationError

    if trusted_keys and envelope_path is None:
        raise OperatorPolicyError("--operator-policy-key requires --operator-policy-attestation")
    if envelope_path is not None and not trusted_keys:
        raise OperatorPolicyError(
            "--operator-policy-attestation requires at least one --operator-policy-key"
        )
    if allow_unsigned and (envelope_path is not None or trusted_keys):
        raise OperatorPolicyError(
            "--allow-unsigned-operator-policy cannot be combined with "
            "--operator-policy-attestation or --operator-policy-key"
        )
    raw, policy_digest = _read_confined_operator_policy(policy_path, root)
    if envelope_path is None and not allow_unsigned:
        raise OperatorPolicyAttestationError(
            "--operator-policy requires --operator-policy-attestation and "
            "--operator-policy-key (or pass --allow-unsigned-operator-policy explicitly)"
        )
    signers: tuple[str, ...] = ()
    if envelope_path is not None:
        signers = _verify_policy_attestation(
            raw,
            policy_path,
            root,
            envelope_path,
            trusted_keys,
            threshold=threshold,
            max_age_days=max_age_days,
        )
    try:
        mapping = parse_yaml_mapping(raw.decode("utf-8"), max_nodes=MAX_POLICY_YAML_NODES)
        parsed = Policy.model_validate(mapping)
    except (UnicodeError, PolicyError, ValidationError) as exc:
        raise OperatorPolicyError("Selected operator policy is invalid YAML or schema") from exc
    return LoadedOperatorPolicy(policy=parsed, digest=policy_digest, signers=signers)


def append_step_summary(path: Path, rendered: str) -> None:
    """Append Markdown to an explicitly selected regular file without following symlinks."""
    import errno as _errno

    from nexus_symbiote.utils.files import OutputRefusedError, _parent, _relative
    from nexus_symbiote.utils.terminal import output_failure, refuse_dash_output

    refuse_dash_output(path)
    target = path.absolute()
    root = Path(target.anchor)
    try:
        relative = _relative(root, target, allow_parent=True)
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise OSError("Secure output requires descriptor-relative no-symlink file operations")
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        with _parent(root, relative, create_parents=False) as parent:
            fd = os.open(relative.name, flags, 0o600, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise OutputRefusedError(_errno.EINVAL, "output must be a regular file")
                prefix = b""
                if info.st_size > 0:
                    last_byte = os.pread(fd, 1, info.st_size - 1)
                    if last_byte != b"\n":
                        prefix = b"\n"
                payload = prefix + rendered.encode("utf-8")
                view = memoryview(payload)
                written = 0
                while written < len(view):
                    written += os.write(fd, view[written:])
            finally:
                os.close(fd)
    except (OSError, ValueError) as exc:
        raise output_failure(exc) from exc


def narrow_policy(operator: Policy, project: Policy | None) -> tuple[Policy, list[str]]:
    """Combine operator and project policies so the project policy can only tighten gates."""
    if project is None:
        return operator, []

    clamped: list[str] = []

    # 1. Scan section: project cannot drop operator-required scanners, add exclusions,
    # or relax error mode to report-only.
    op_scanners = list(operator.scan.scanners)
    missing_scanners = [s for s in op_scanners if s not in project.scan.scanners]
    if missing_scanners:
        clamped.append("scan.scanners (kept operator collectors)")
    extra_scanners = [s for s in project.scan.scanners if s not in op_scanners]
    effective_scanners = [*op_scanners, *extra_scanners]

    op_excludes = set(operator.scan.exclude_paths)
    extra_excludes = [p for p in project.scan.exclude_paths if p not in op_excludes]
    if extra_excludes:
        clamped.append("scan.exclude_paths (refused extra project exclusions)")
    # Excluding fewer paths only widens collection, so a project may narrow to none; one
    # that does not set the list keeps the operator's.
    if "exclude_paths" in project.scan.model_fields_set:
        effective_excludes = [
            p for p in operator.scan.exclude_paths if p in set(project.scan.exclude_paths)
        ]
    else:
        effective_excludes = list(operator.scan.exclude_paths)

    if operator.scan.failure_mode == "error" and project.scan.failure_mode == "report-only":
        clamped.append("scan.failure_mode=error (clamped project report-only)")
        effective_failure_mode: Literal["error", "report-only"] = "error"
    else:
        effective_failure_mode = (
            "error"
            if "error" in (operator.scan.failure_mode, project.scan.failure_mode)
            else "report-only"
        )

    # 2. Validation section: booleans OR together; assurance takes stricter rank.
    req_comp = operator.validation.require_completeness or project.validation.require_completeness
    if operator.validation.require_completeness and not project.validation.require_completeness:
        clamped.append("validate.require_completeness=true")
    req_int = operator.validation.require_integrity or project.validation.require_integrity
    if operator.validation.require_integrity and not project.validation.require_integrity:
        clamped.append("validate.require_integrity=true")
    req_disc = (
        operator.validation.require_discovery_signature
        or project.validation.require_discovery_signature
    )
    if (
        operator.validation.require_discovery_signature
        and not project.validation.require_discovery_signature
    ):
        clamped.append("validate.require_discovery_signature=true")

    op_assure = operator.validation.minimum_assurance_level
    proj_assure = project.validation.minimum_assurance_level
    if _ASSURANCE_STRICTNESS[proj_assure] < _ASSURANCE_STRICTNESS[op_assure]:
        clamped.append(f"validate.minimum_assurance_level={op_assure}")
        effective_assurance = op_assure
    else:
        effective_assurance = proj_assure

    # 3. Risk section: fail_threshold takes min, fail_on_severity takes stricter,
    # ignore_categories and suppressions take intersection with operator's allowlist.
    if project.risk.fail_threshold > operator.risk.fail_threshold:
        clamped.append(f"risk.fail_threshold={operator.risk.fail_threshold!r}")
    effective_fail = min(operator.risk.fail_threshold, project.risk.fail_threshold)

    if project.risk.warn_threshold > operator.risk.warn_threshold:
        clamped.append(f"risk.warn_threshold={min(operator.risk.warn_threshold, effective_fail)!r}")
    effective_warn = min(operator.risk.warn_threshold, project.risk.warn_threshold, effective_fail)

    op_sev = operator.risk.fail_on_severity
    proj_sev = project.risk.fail_on_severity
    if _SEVERITY_STRICTNESS[proj_sev] > _SEVERITY_STRICTNESS[op_sev]:
        clamped.append(f"risk.fail_on_severity={op_sev}")
        effective_sev = op_sev
    else:
        effective_sev = proj_sev

    op_ignored = set(operator.risk.ignore_categories)
    extra_ignored = [c for c in project.risk.ignore_categories if c not in op_ignored]
    if extra_ignored:
        clamped.append("risk.ignore_categories (refused unapproved category ignores)")
    effective_ignored = [
        c for c in operator.risk.ignore_categories if c in set(project.risk.ignore_categories)
    ]

    op_supp_keys = {
        (s.component_ref, s.category, s.fingerprint): s for s in operator.risk.suppressions
    }
    proj_supp_keys = {
        (s.component_ref, s.category, s.fingerprint) for s in project.risk.suppressions
    }
    unapproved_supps = proj_supp_keys - set(op_supp_keys)
    if unapproved_supps:
        clamped.append(f"risk.suppressions (refused {len(unapproved_supps)} checkout suppressions)")
    effective_suppressions = list(operator.risk.suppressions)

    narrowed = Policy(
        version="1.0",
        scan=ScanPolicy(
            scanners=effective_scanners,
            exclude_paths=effective_excludes,
            failure_mode=effective_failure_mode,
        ),
        risk=RiskPolicy(
            fail_threshold=effective_fail,
            warn_threshold=effective_warn,
            fail_on_severity=effective_sev,
            ignore_categories=effective_ignored,
            suppressions=effective_suppressions,
        ),
        validate=ValidatePolicy(
            require_completeness=req_comp,
            require_integrity=req_int,
            minimum_assurance_level=effective_assurance,
            require_discovery_signature=req_disc,
        ),
        output=operator.output,
    )
    return narrowed, clamped


def inert_markdown_cell(value: object) -> str:
    """Render untrusted inventory text so Markdown and GitHub workflow commands stay inert."""
    cleaned = neutralize(value)
    cleaned = _WORKFLOW_COMMAND.sub(lambda m: "\\".join(m.group(0)), cleaned)
    return _MARKDOWN_PUNCTUATION.sub(r"\\\1", cleaned)


def _gate_reasons(document: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for key in ("gate_reasons", "assurance_errors", "graph_issues", "clamped_project_settings"):
        items = document.get(key)
        if isinstance(items, list):
            reasons.extend(str(item) for item in items)
    for section_name in ("completeness", "integrity"):
        section = document.get(section_name)
        if isinstance(section, dict) and section.get("status") in ("fail", "unknown"):
            issues = section.get("issues")
            if isinstance(issues, list) and issues:
                for issue in issues[:10]:
                    if isinstance(issue, dict):
                        detail = (
                            issue.get("description")
                            or issue.get("detail")
                            or issue.get("message")
                            or str(issue)
                        )
                        reasons.append(f"{section_name}: {detail}")
                    else:
                        reasons.append(f"{section_name}: {issue}")
            else:
                reasons.append(f"{section_name}: {section.get('status')}")
    producer = document.get("discovery_producer")
    if isinstance(producer, dict) and isinstance(producer.get("problems"), list):
        reasons.extend(f"discovery_producer: {problem}" for problem in producer["problems"][:10])
    if document.get("unsigned_discovery"):
        reasons.append(str(document["unsigned_discovery"]))
    alerts = document.get("security_alerts")
    if isinstance(alerts, list):
        for alert in alerts[:25]:
            if isinstance(alert, dict):
                msg = alert.get("alert") or alert.get("message", "")
                reasons.append(f"{alert.get('severity', 'alert')}: {msg}")
    return reasons


def render_gate_markdown(gate_name: str, document: dict[str, Any]) -> str:
    """Render a deterministic, injection-safe Markdown summary suitable for GITHUB_STEP_SUMMARY."""
    passed = bool(document.get("passed", not document.get("security_alerts")))
    verdict = "passed" if passed else "failed"
    lines = [
        f"### Nexus SymBiote {inert_markdown_cell(gate_name)}: {verdict}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Verdict | {verdict} |",
    ]
    if "policy_source" in document:
        lines.append(f"| Policy source | {inert_markdown_cell(document['policy_source'])} |")
    if document.get("operator_policy_digest"):
        lines.append(
            f"| Operator policy digest | {inert_markdown_cell(document['operator_policy_digest'])} |"
        )
    if document.get("operator_policy_signers"):
        signers = ", ".join(map(str, document["operator_policy_signers"]))
        lines.append(f"| Operator policy signers | {inert_markdown_cell(signers)} |")
    if "overall_score" in document and document["overall_score"] is not None:
        lines.append(f"| Risk score | {inert_markdown_cell(document['overall_score'])} |")
    reasons = _gate_reasons(document)
    if reasons:
        lines.append("")
        lines.append("#### Reasons")
        for reason in reasons[:25]:
            lines.append(f"- {inert_markdown_cell(reason)}")
    return "\n".join(lines) + "\n"


def render_gate_junit(gate_name: str, document: dict[str, Any]) -> str:
    """Render a deterministic, XML-escaped JUnit report for CI test-summary consumers."""
    passed = bool(document.get("passed", not document.get("security_alerts")))
    safe_gate = xml_escape(neutralize(gate_name), {'"': "&quot;", "'": "&apos;"})
    reasons = [neutralize(r) for r in _gate_reasons(document)]
    if not passed and not reasons:
        reasons.append(f"{neutralize(gate_name)} gate failed")
    failures = 0 if passed else 1
    body = ""
    if not passed:
        joined = xml_escape("; ".join(reasons[:25]), {'"': "&quot;", "'": "&apos;"})
        body = f'<failure message="{joined}">{joined}</failure>'
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<testsuite name="nexus-symbiote.{safe_gate}" tests="1" failures="{failures}">'
        f'<testcase classname="nexus_symbiote.gates" name="{safe_gate}">{body}</testcase>'
        "</testsuite>\n"
    )
