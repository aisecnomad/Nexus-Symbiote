"""Commands that attest the exact bytes of a file and verify those attestations.

Signing is an explicit operator step with keys the operator holds; no command signs a
scan result on its own. Verification takes operator-supplied public keys and refuses one
kept where the change under review could have written it: inside a git working tree that
holds the subject, the envelope or the current directory. That catches misplacement; it
does not authenticate a key.
"""

from __future__ import annotations

import functools
import json
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypeVar, cast

import click
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nexus_symbiote.attestation import MAX_SUBJECT_BYTES
from nexus_symbiote.runtime_cli import (
    _check_key_placement,
    _InputTooLargeError,
    _KeyFileError,
    _load_private,
    _passphrase,
    _read,
    _refuse_source_overwrite,
)
from nexus_symbiote.utils.terminal import echo_line, json_text, write_cli_output

MAX_AGE_DAYS = 36500
_PURPOSES = ["generated", "reviewed", "policy"]
_REVISION = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
T = TypeVar("T")


class _AttestationFailure(click.ClickException):
    def __init__(self, operation: str, reason: str, detail: str) -> None:
        super().__init__(f"attestation {operation} failed: {detail} ({reason})")
        self.reason = reason
        self.detail = detail


class _AttestationGateError(_AttestationFailure):
    exit_code = 3


def _failure(operation: str, reason: str, detail: str) -> _AttestationFailure:
    if operation == "verification" and reason not in {
        "key-invalid",
        "input-too-large",
        "input-unreadable",
    }:
        return _AttestationGateError(operation, reason, detail)
    return _AttestationFailure(operation, reason, detail)


def _load(operation: str, role: str, load: Callable[[], T]) -> T:
    """Run one bounded, no-follow file read; a refusal names the file's role, never content."""
    try:
        return load()
    except _KeyFileError as exc:
        raise _failure(operation, "key-invalid", str(exc)) from None
    except _InputTooLargeError:
        raise _failure(operation, "input-too-large", f"the {role} exceeds its size limit") from None
    except OSError:
        raise _failure(
            operation,
            "input-unreadable",
            f"the {role} is not a readable regular file reached without symbolic links",
        ) from None


def _revision(_ctx: click.Context, _param: click.Parameter, value: str | None) -> str | None:
    if value is not None and not _REVISION.fullmatch(value):
        raise click.BadParameter("use a git commit ID of 40 or 64 lowercase hexadecimal characters")
    return value


def _check_trust_anchors(keys: tuple[Path, ...], inputs: tuple[Path, ...]) -> None:
    _check_key_placement(keys, inputs, option="--trusted-key", holders="SUBJECT, ENVELOPE")


@click.command("attest")
@click.argument("subject", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--key",
    "keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Ed25519 private key PEM that you own and that gives group and others no permission; repeat for each signer.",
)
@click.option(
    "--purpose",
    type=click.Choice(_PURPOSES),
    required=True,
    help="generated: you produced SUBJECT; reviewed: you reviewed SUBJECT as a baseline; policy: you approved SUBJECT as an operator policy.",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    required=True,
    help="Envelope file to create with mode 0600; must not exist.",
)
@click.option(
    "--passphrase-file",
    type=click.Path(path_type=Path),
    help="Passphrase for encrypted private keys, on the first line of this file, "
    "which you own and which gives group and others no permission.",
)
@click.option(
    "--source-revision",
    callback=_revision,
    help="Git commit ID SUBJECT was produced from, 40 or 64 lowercase hexadecimal "
    "characters; recorded as your claim and never checked.",
)
def attest(
    subject: Path,
    keys: tuple[Path, ...],
    purpose: str,
    out: Path,
    passphrase_file: Path | None,
    source_revision: str | None,
) -> None:
    """Sign the exact bytes of SUBJECT for one purpose; an explicit operator step.

    The attestation binds the SHA-256 of SUBJECT and, for a native inventory this build
    reads, its content digest. It records who signed and why, not that the file is
    accurate, complete or safe.
    """
    from nexus_symbiote.attestation import (
        AttestationError,
        Purpose,
        build_statement,
        sign_statement,
    )
    from nexus_symbiote.runtime import key_id

    _refuse_source_overwrite(out, subject)
    passphrase = _load(
        "signing", "passphrase file", functools.partial(_passphrase, passphrase_file)
    )
    signers = [
        _load("signing", "signing key file", functools.partial(_load_private, path, passphrase))
        for path in keys
    ]
    names = [key_id(signer.public_key()) for signer in signers]
    if len(set(names)) != len(names):
        raise click.BadParameter("each --key must be a different signing key", param_hint="'--key'")
    data = _load("signing", "subject file", functools.partial(_read, subject, MAX_SUBJECT_BYTES))
    try:
        statement = build_statement(
            data,
            name=subject.name,
            purpose=cast(Purpose, purpose),
            signed_at=datetime.now(UTC).replace(microsecond=0),
            source_revision=source_revision,
        )
        envelope = sign_statement(statement, signers)
    except AttestationError as exc:
        raise _failure("signing", exc.reason, str(exc)) from None
    text = json.dumps(envelope.model_dump(mode="json", by_alias=True), indent=2) + "\n"
    write_cli_output(out, text, overwrite=False)
    predicate = statement["predicate"]
    result = {
        "out": str(out),
        "subject_sha256": statement["subject"][0]["digest"]["sha256"],
        "subject_format": predicate["subject_format"],
        **(
            {"content_digest": predicate["content_digest"]} if "content_digest" in predicate else {}
        ),
        "purpose": purpose,
        "signers": sorted(names),
        "signed": True,
    }
    click.echo(json_text(json.dumps(result)))


def _load_trusted_public(path: Path) -> Ed25519PublicKey:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization

    from nexus_symbiote.core.hashing import open_regular_file, pathname_identity
    from nexus_symbiote.runtime_cli import MAX_KEY_BYTES
    from nexus_symbiote.utils.crypto import _trust_anchor_error, _trusted_ancestor_uids

    uid = getattr(os, "geteuid", lambda: None)()
    trusted_uids = _trusted_ancestor_uids(uid) if uid is not None else set()
    with open_regular_file(path) as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read(MAX_KEY_BYTES + 1)
        if (
            info.st_nlink != 1
            or (uid is not None and info.st_uid not in trusted_uids)
            or (info.st_mode & 0o002)
            or pathname_identity(path) != (info.st_dev, info.st_ino)
        ):
            raise _KeyFileError("trusted key file failed ownership, permission, or link checks")
        if (reason := _trust_anchor_error(path, info)) is not None:
            raise _KeyFileError(f"trusted key file {reason}")
    if len(raw) > MAX_KEY_BYTES:
        raise _InputTooLargeError
    try:
        public = serialization.load_pem_public_key(raw)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise _KeyFileError("public key could not be loaded") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise _KeyFileError("only Ed25519 public keys are supported")
    return public


def _subject_bytes(subject: Path, preloaded: bytes | None) -> bytes:
    if preloaded is None:
        return _read(subject, MAX_SUBJECT_BYTES)
    if len(preloaded) > MAX_SUBJECT_BYTES:
        raise _InputTooLargeError
    return preloaded


def _verify_core(
    subject: Path,
    envelope: Path,
    *,
    trusted_keys: tuple[Path, ...],
    purpose: str,
    threshold: int,
    match: str,
    max_age_days: int | None,
    subject_bytes: bytes | None = None,
) -> tuple[object, dict[str, object]]:

    from nexus_symbiote import attestation
    from nexus_symbiote.runtime import key_id

    ring: dict[str, Ed25519PublicKey] = {}
    for path in trusted_keys:
        public = _load(
            "verification", "trusted key file", functools.partial(_load_trusted_public, path)
        )
        ring[key_id(public)] = public
    if threshold > len(ring):
        raise click.BadParameter(
            f"must be at most the number of distinct trusted keys ({len(ring)})",
            param_hint="'--threshold'",
        )
    raw = _load(
        "verification",
        "envelope file",
        functools.partial(_read, envelope, attestation.MAX_ENVELOPE_BYTES),
    )
    data = _load(
        "verification",
        "subject file",
        functools.partial(_subject_bytes, subject, subject_bytes),
    )
    try:
        verified = attestation.verify_attestation(
            attestation.parse_envelope(raw),
            data,
            trusted_keys=ring,
            purpose=cast(attestation.Purpose, purpose),
            threshold=threshold,
            match=cast(attestation.Match, match),
            max_age=None if max_age_days is None else timedelta(days=max_age_days),
        )
    except attestation.AttestationError as exc:
        raise _failure("verification", exc.reason, str(exc)) from None
    predicate = verified.predicate
    facts: dict[str, object] = {
        "attestation_verified": True,
        "purpose": predicate.purpose,
        "signers": list(verified.signers),
        "match": verified.match,
        "subject_sha256": verified.subject_sha256,
        "attested_sha256": verified.attested_sha256,
        "subject_format": predicate.subject_format,
        **predicate.model_dump(
            mode="json",
            include={"spec_version", "content_digest", "content_profile"},
            exclude_none=True,
        ),
        "signed_at": predicate.model_dump(mode="json")["signed_at"],
        **predicate.model_dump(mode="json", include={"source_revision"}, exclude_none=True),
    }
    return verified, facts


@click.command("verify-attestation")
@click.argument("subject", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("envelope", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--trusted-key",
    "trusted_keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Trusted Ed25519 public key PEM; repeat to build the ring. It must lie outside every "
    "git working tree that holds SUBJECT, ENVELOPE or the current directory, which catches "
    "misplacement but does not authenticate the key.",
)
@click.option(
    "--purpose",
    type=click.Choice(_PURPOSES),
    required=True,
    help="Purpose the attestation must have been signed for. Any trusted key can sign either "
    "purpose, so trust only keys that may sign for this one.",
)
@click.option(
    "--threshold",
    type=click.IntRange(min=1, max=32),
    default=1,
    help="Minimum number of distinct trusted keys that must have signed, at most the "
    "number of distinct trusted keys (default: 1).",
)
@click.option(
    "--match",
    "match",
    type=click.Choice(["bytes", "content"]),
    default="bytes",
    help="bytes (default): SUBJECT is the attested file. content: SUBJECT is a native "
    "inventory with the attested content digest, such as a later collection of the "
    "same content.",
)
@click.option(
    "--max-age-days",
    type=click.IntRange(min=1, max=MAX_AGE_DAYS),
    help="Refuse an attestation signed more than this many days ago.",
)
@click.option("--json-output", is_flag=True, help="Print the verified facts as JSON.")
def verify_attestation(
    subject: Path,
    envelope: Path,
    trusted_keys: tuple[Path, ...],
    purpose: str,
    threshold: int,
    match: str,
    max_age_days: int | None,
    json_output: bool,
) -> None:
    """Verify that trusted keys attested SUBJECT for a purpose; exit 1 when they did not.

    A verified attestation establishes who signed which bytes or content for which
    purpose and when, by the signer's clock. It does not establish that SUBJECT is
    accurate, complete or safe, or that it is the newest file the signers attested.
    """
    from nexus_symbiote import attestation

    _check_trust_anchors(trusted_keys, (subject, envelope))
    raw_verified, facts = _verify_core(
        subject,
        envelope,
        trusted_keys=trusted_keys,
        purpose=purpose,
        threshold=threshold,
        match=match,
        max_age_days=max_age_days,
    )
    verified = cast(attestation.VerifiedAttestation, raw_verified)
    predicate = verified.predicate
    if json_output:
        click.echo(json_text(json.dumps(facts, indent=2)))
        return
    count = len(verified.signers)
    echo_line(
        "Attestation verified: ",
        f"purpose {predicate.purpose}, {count} trusted key{'' if count == 1 else 's'}. It "
        "does not establish that the file is accurate, complete or safe.",
    )
    for name in verified.signers:
        echo_line("Signer key ID: ", name)
    echo_line("Subject SHA-256: ", verified.subject_sha256)
    if verified.match == "content":
        echo_line("Match: content; the attested file's SHA-256 is ", verified.attested_sha256)
    else:
        echo_line("Match: bytes")
    if predicate.content_digest is None:
        echo_line("Subject format: ", predicate.subject_format, " (no content digest)")
    else:
        echo_line("Subject format: ", predicate.subject_format, " ", predicate.spec_version)
        echo_line(
            "Content digest: ", predicate.content_digest, " (", predicate.content_profile, ")"
        )
    echo_line("Signed at (signer's clock): ", facts["signed_at"])
    if predicate.source_revision is not None:
        echo_line("Source revision claimed by the signer, not checked: ", predicate.source_revision)


def verify_gate_attestation(
    subject: Path,
    envelope: Path,
    *,
    trusted_keys: tuple[Path, ...],
    purpose: str = "reviewed",
    threshold: int = 1,
    match: str = "bytes",
    max_age_days: int | None = None,
    project: Path | None = None,
    subject_bytes: bytes | None = None,
) -> dict[str, object]:
    """Verify an attestation for a gate command and return structured verification facts."""
    inputs = (subject, envelope) if project is None else (subject, envelope, project)
    holders = "SUBJECT, ENVELOPE" if project is None else "SUBJECT, ENVELOPE or --project"
    try:
        _check_key_placement(trusted_keys, inputs, option="--trusted-key", holders=holders)
        _, facts = _verify_core(
            subject,
            envelope,
            trusted_keys=trusted_keys,
            purpose=purpose,
            threshold=threshold,
            match=match,
            max_age_days=max_age_days,
            subject_bytes=subject_bytes,
        )
    except _AttestationFailure as exc:
        return {
            "verified": False,
            "status": "fail",
            "reason": exc.reason,
            "detail": exc.detail,
            "signers": [],
        }
    except click.BadParameter as exc:
        return {
            "verified": False,
            "status": "fail",
            "reason": "configuration-invalid",
            "detail": exc.message,
            "signers": [],
        }
    except click.ClickException as exc:
        return {
            "verified": False,
            "status": "fail",
            "reason": "key-invalid",
            "detail": exc.format_message(),
            "signers": [],
        }
    return {
        "verified": True,
        "status": "pass",
        **{k: v for k, v in facts.items() if k != "attestation_verified"},
    }


def register_attestation_commands(main: click.Group) -> None:
    main.add_command(attest)
    main.add_command(verify_attestation)
