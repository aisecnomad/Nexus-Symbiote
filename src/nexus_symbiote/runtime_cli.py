"""Explicit signing and contract verification commands; no implicit admission."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import click
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.runtime import (
    ActionApproval,
    ApprovedSnapshot,
    Envelope,
    HostedModelAttestation,
    TrustStatus,
    _window,
    digest,
    key_id,
    sign_contract,
    strict_json,
    verify_contract,
)
from nexus_symbiote.utils.terminal import inert_json

Purpose = Literal["snapshot", "approval", "trust", "model"]


def _safe_error(exc: Exception, operation: Literal["signing", "verification"]) -> str:
    """Describe an operator error without echoing contract values or extra keys."""
    if isinstance(exc, ValidationError):
        fields = {
            field
            for model in (
                ApprovedSnapshot,
                ActionApproval,
                TrustStatus,
                HostedModelAttestation,
                Envelope,
            )
            for field in model.model_fields
        }
        fields.add("payloadType")
        invalid = set()
        for error in exc.errors(include_input=False, include_context=False, include_url=False):
            location = error["loc"]
            field = location[0] if location else None
            invalid.add(
                field if isinstance(field, str) and field in fields else "unsupported field"
            )
        locations = ", ".join(sorted(invalid))
        return f"runtime input validation failed; review fields: {locations} (runtime-input-error)"
    if isinstance(exc, OSError):
        return f"runtime {operation} files could not be accessed safely (runtime-io-error)"
    return (
        f"runtime {operation} failed; review the selected contract, Ed25519 keys, "
        "signer policy and validity (runtime-contract-error)"
    )


def _read(path: Path, maximum: int = 24 * 1024 * 1024) -> bytes:
    with open_regular_file(path) as stream:
        if os.fstat(stream.fileno()).st_size > maximum:
            raise click.ClickException("input exceeds size limit")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise click.ClickException("input exceeds size limit")
    return raw


def _write_new(path: Path, content: bytes, mode: int = 0o600) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "wb") as stream:
        stream.write(content)


@click.group("runtime")
def runtime_group() -> None:
    """Sign and verify purpose-specific contracts for mediated tool integrations."""


@runtime_group.command("keygen")
@click.option(
    "--private-key",
    type=click.Path(path_type=Path),
    required=True,
    help="New PEM private key file, created with mode 0600; must not exist.",
)
@click.option(
    "--public-key",
    type=click.Path(path_type=Path),
    required=True,
    help="New PEM public key file, created with mode 0600; must not exist.",
)
def keygen(private_key: Path, public_key: Path) -> None:
    """Create an Ed25519 key pair without overwriting existing files."""
    if private_key.exists() or public_key.exists() or private_key == public_key:
        raise click.ClickException("choose distinct, nonexistent key paths")
    key = Ed25519PrivateKey.generate()
    _write_new(
        private_key,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _write_new(
        public_key,
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )
    click.echo(json.dumps({"key_id": key_id(key.public_key())}))


@runtime_group.command("sign")
@click.argument("contract_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind",
    type=click.Choice(["snapshot", "approval", "trust", "model"]),
    required=True,
    help="Contract purpose; a signature is valid only for this purpose.",
)
@click.option(
    "--key",
    "keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Ed25519 private key PEM; repeat for multiple signers.",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    required=True,
    help="Signed envelope file to create; must not exist.",
)
def sign(contract_path: Path, kind: str, keys: tuple[Path, ...], out: Path) -> None:
    """Sign an explicit contract; signatures do not establish unmeasured facts."""
    try:
        raw = strict_json(_read(contract_path))
        contract: ApprovedSnapshot | ActionApproval | TrustStatus | HostedModelAttestation
        if kind == "snapshot":
            contract = ApprovedSnapshot.model_validate(raw)
        elif kind == "approval":
            contract = ActionApproval.model_validate(raw)
        elif kind == "trust":
            contract = TrustStatus.model_validate(raw)
        else:
            contract = HostedModelAttestation.model_validate(raw)
        loaded = []
        for path in keys:
            private = serialization.load_pem_private_key(_read(path, 65536), password=None)
            if not isinstance(private, Ed25519PrivateKey):
                raise ValueError("only Ed25519 signing keys are supported")
            loaded.append(private)
        envelope = sign_contract(contract, cast(Purpose, kind), tuple(loaded))
        _write_new(
            out,
            (json.dumps(envelope.model_dump(mode="json", by_alias=True), indent=2) + "\n").encode(),
        )
        click.echo(json.dumps({"out": str(out), "predicate": kind, "signed": True}))
    except (ValueError, OSError) as exc:
        raise click.ClickException(_safe_error(exc, "signing")) from None


@runtime_group.command("verify")
@click.argument("envelope_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind",
    type=click.Choice(["snapshot", "approval", "trust", "model"]),
    required=True,
    help="Expected contract purpose; a contract signed for another purpose is rejected.",
)
@click.option(
    "--public-key",
    "keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Trusted Ed25519 public key PEM; repeat to build the trusted key ring.",
)
@click.option(
    "--threshold",
    type=click.IntRange(min=1),
    default=1,
    help="Minimum number of distinct trusted signatures (default: 1).",
)
@click.option(
    "--bom",
    type=click.Path(exists=True, path_type=Path),
    help="The exact companion BOM; required for snapshot contracts.",
)
def verify(
    envelope_path: Path, kind: str, keys: tuple[Path, ...], threshold: int, bom: Path | None
) -> None:
    """Verify purpose, signer, subject and time; invocation uses ReferenceGateway."""
    try:
        ring = {}
        for path in keys:
            public = serialization.load_pem_public_key(_read(path, 65536))
            if not isinstance(public, Ed25519PublicKey):
                raise ValueError("expected Ed25519 public key")
            ring[key_id(public)] = public
        envelope = Envelope.model_validate(strict_json(_read(envelope_path)))
        contract, accepted = verify_contract(
            envelope, cast(Purpose, kind), ring, threshold=threshold
        )
        maximum = (
            timedelta(minutes=5)
            if kind == "approval"
            else timedelta(hours=1 if kind == "trust" else 24)
        )
        _window(contract, datetime.now(UTC), maximum)
        if isinstance(contract, ApprovedSnapshot):
            if bom is None or digest(strict_json(_read(bom))) != contract.bom_digest:
                raise ValueError("snapshot verification requires its exact companion BOM")
        result: dict[str, Any] = {
            "contract_verified": True,
            "kind": kind,
            "accepted_signers": sorted(accepted),
            "invocation_authorized": False,
        }
        click.echo(inert_json(json.dumps(result, indent=2)))
    except (ValueError, OSError) as exc:
        raise click.ClickException(_safe_error(exc, "verification")) from None


def register_runtime_commands(main: click.Group) -> None:
    main.add_command(runtime_group)
