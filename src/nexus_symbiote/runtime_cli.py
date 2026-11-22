"""Explicit signing and contract verification commands; no implicit admission."""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import click
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.runtime import (
    CONTRACTS,
    MAX_LIFETIMES,
    REASONS,
    ApprovedSnapshot,
    AuthorizationError,
    Envelope,
    ExecutionContext,
    Kind,
    ReferenceGateway,
    SignerScope,
    StateStore,
    ToolCall,
    _window,
    bom_digest,
    contract_digest,
    key_id,
    request_digest,
    sign_contract,
    strict_json,
    tool_definition_digest,
    validation_fields,
    verify_contract,
)
from nexus_symbiote.utils.files import _parent, _relative
from nexus_symbiote.utils.terminal import json_text

MAX_KEY_BYTES = 65536
MAX_INPUT_BYTES = 24 * 1024 * 1024
MAX_PASSPHRASE_FILE_BYTES = 4096
# OpenSSL refuses longer PEM passphrases.
MAX_PASSPHRASE_BYTES = 1023
_CONTRACT_KINDS = ["snapshot", "approval", "trust", "model"]
_KEY_ID = re.compile(r"[0-9a-f]{64}")
_DIGEST_KINDS = [*_CONTRACT_KINDS, "context", "request", "tool", "bom"]


class _KeyFileError(Exception):
    """A key or passphrase file was refused; the message is fixed text, never file content."""


class _InputTooLargeError(Exception):
    """An input file exceeds its size limit."""


class _RingError(Exception):
    """Rings and scopes do not fit together; the message holds fixed text and key IDs only."""


_HANDLED = (
    ValueError,
    TypeError,
    RecursionError,
    OSError,
    UnsupportedAlgorithm,
    _KeyFileError,
    _InputTooLargeError,
    _RingError,
)


def _safe_error(exc: BaseException, operation: str) -> str:
    """Describe an operator error without echoing contract values or extra keys."""
    if isinstance(exc, ValidationError):
        fields = validation_fields(exc)
        return f"runtime input validation failed; review fields: {fields} (runtime-input-error)"
    if isinstance(exc, AuthorizationError):
        description = REASONS.get(exc.reason, REASONS["denied"])
        return f"runtime {operation} failed: {description} ({exc.reason})"
    if isinstance(exc, _KeyFileError):
        return f"runtime {operation} failed: {exc} (runtime-key-error)"
    if isinstance(exc, _InputTooLargeError):
        return f"runtime {operation} input exceeds its size limit (runtime-input-too-large)"
    if isinstance(exc, _RingError):
        return f"runtime {operation} failed: {exc} (configuration-invalid)"
    if isinstance(exc, OSError):
        return f"runtime {operation} files could not be accessed safely (runtime-io-error)"
    if isinstance(exc, RecursionError):
        return f"runtime {operation} input is nested too deeply (runtime-input-error)"
    return (
        f"runtime {operation} failed; review the selected contract, Ed25519 keys, "
        "signer policy and validity (runtime-contract-error)"
    )


def _read(path: Path, maximum: int = MAX_INPUT_BYTES, *, owner_only: str = "") -> bytes:
    """Read a bounded regular file.

    With ``owner_only``, refuse a file that the effective user does not own or that its
    group or others can access.
    """
    with open_regular_file(path) as stream:
        info = os.fstat(stream.fileno())
        if owner_only and os.name == "posix":
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise _KeyFileError(f"{owner_only} must not be accessible to group or others")
            # Mode bits alone do not say whose file this is: run as root, an
            # attacker-owned 0600 file in a shared directory would pass.
            if info.st_uid != os.geteuid():
                raise _KeyFileError(f"{owner_only} must be owned by the user running the command")
        if info.st_size > maximum:
            raise _InputTooLargeError
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise _InputTooLargeError
    return raw


def _json_object(path: Path) -> dict[str, Any]:
    document = strict_json(_read(path))
    if not isinstance(document, dict):
        raise AuthorizationError("input must be a JSON object", reason="json-not-object")
    return document


def _ring(paths: tuple[Path, ...]) -> dict[str, Ed25519PublicKey]:
    ring = {}
    for path in paths:
        public = _load_public(path)
        ring[key_id(public)] = public
    return ring


def _working_trees(directories: Iterable[Path]) -> list[Path]:
    """Every directory at or above these that holds a ``.git`` entry, nested ones included."""
    found: list[Path] = []
    for directory in directories:
        for candidate in (directory, *directory.parents):
            if candidate not in found and os.path.lexists(candidate / ".git"):
                found.append(candidate)
    return found


def _identity(path: Path) -> tuple[int, int]:
    info = os.stat(path)
    return info.st_dev, info.st_ino


def _verify_outside_checkout(
    target: Path, untrusted_roots: tuple[Path, ...], *, label: str
) -> None:
    try:
        resolved_roots = [p.resolve() for p in untrusted_roots]
        search_starts = [
            *(p if p.is_dir() else p.parent for p in resolved_roots),
            Path.cwd().resolve(),
        ]
        trees = _working_trees(search_starts)
        forbidden_dirs = [
            *trees,
            *(p for p in resolved_roots if p.is_dir() and p not in trees),
        ]
        forbidden_ids = {_identity(d) for d in forbidden_dirs}
        resolved_target = target.resolve()
        ancestor_ids = {_identity(parent) for parent in resolved_target.parents}
        if any(resolved_target.is_relative_to(d) for d in forbidden_dirs) or bool(
            ancestor_ids & forbidden_ids
        ):
            raise click.UsageError(
                f"{label} must lie outside the target checkout and every git working tree "
                "that holds the checkout or the current directory"
            )
        if os.stat(resolved_target).st_nlink != 1:
            raise click.UsageError(f"{label} must not have multiple hard links")
    except click.UsageError:
        raise
    except (OSError, RuntimeError):
        raise click.UsageError(f"{label} cannot be inspected safely") from None


def _check_key_placement(
    keys: tuple[Path, ...], inputs: tuple[Path, ...], *, option: str, holders: str
) -> None:
    """Refuse a trusted key that a change to a working tree or untrusted root could supply.

    This catches misplacement, such as a key committed beside the contracts or inside
    the project directory it is to judge; it does not authenticate the key.
    """
    try:
        resolved_inputs = [path.resolve() for path in inputs]
        dir_inputs = [p for p in resolved_inputs if p.is_dir()]
        search_starts = [
            *(p if p.is_dir() else p.parent for p in resolved_inputs),
            Path.cwd().resolve(),
        ]
        trees = _working_trees(search_starts)
        untrusted_dirs = [*trees, *(d for d in dir_inputs if d not in trees)]
        untrusted = {_identity(d) for d in untrusted_dirs}
        for key in keys:
            resolved = key.resolve()
            # Device and inode also find the tree directory itself under a name the path
            # text misses, such as a case variant or a bind mount of the tree. A mount of
            # a directory or file inside a tree gives the key another location: not found.
            ancestors = {_identity(parent) for parent in resolved.parents}
            if any(resolved.is_relative_to(d) for d in untrusted_dirs) or ancestors & untrusted:
                raise click.UsageError(
                    f"a {option} file must lie outside every git working tree that holds "
                    f"{holders} or the current directory, and outside {holders}; "
                    "this catches misplacement, it does not authenticate the key"
                )
            if os.stat(resolved).st_nlink != 1:
                raise click.UsageError(
                    f"a {option} file must not have other hard links: another name for it "
                    "could lie inside such a working tree"
                )
    except (OSError, RuntimeError):
        raise click.UsageError(f"the location of a {option} file cannot be inspected") from None


def _check_rings(
    rings: dict[str, dict[str, Ed25519PublicKey]], scopes: dict[str, Any], allow_shared_keys: bool
) -> None:
    """Name the key behind a ring or scope error that the library reports without it."""
    if not allow_shared_keys:
        for name in sorted(set().union(*rings.values())):
            purposes = [purpose for purpose, ring in rings.items() if name in ring]
            if len(purposes) > 1:
                raise _RingError(
                    f"key {name} is in the {' and '.join(purposes)} rings; use one key per "
                    "purpose, or pass --allow-shared-keys if the gateways allow shared keys"
                )
    for name in sorted(scopes):
        if not any(name in ring for ring in rings.values()):
            # Only a key ID is echoed; any other scope name is input and stays unprinted.
            shown = f"key {name}" if _KEY_ID.fullmatch(name) else "an entry that is not a key ID"
            raise _RingError(
                f"--signer-scopes names {shown}, which is not a --snapshot-key, --trust-key "
                "or --approval-key"
            )


def _path_exists_or_symlink(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def _write_new(path: Path, content: bytes, mode: int = 0o600) -> None:
    """Create ``path``; when the write or close fails, remove the file this call created."""
    target = path.absolute()
    root = Path(target.anchor)
    relative = _relative(root, target, allow_parent=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with _parent(root, relative, create_parents=False) as parent:
        fd = os.open(relative.name, flags, mode, dir_fd=parent)
        created = os.fstat(fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
        except BaseException:
            # A partial key or envelope would block every retry; a file that has
            # replaced this one since it was created is left alone.
            with contextlib.suppress(OSError):
                current = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
                if os.path.samestat(current, created):
                    os.unlink(relative.name, dir_fd=parent)
            raise


def _unlink_created(path: Path) -> None:
    target = path.absolute()
    root = Path(target.anchor)
    try:
        relative = _relative(root, target, allow_parent=True)
        with _parent(root, relative, create_parents=False) as parent:
            info = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISREG(info.st_mode):
                os.unlink(relative.name, dir_fd=parent)
    except (OSError, ValueError):
        # Best-effort cleanup: the caller re-raises the failure that led here.
        pass


def _passphrase(path: Path | None) -> bytes | None:
    if path is None:
        return None
    raw = _read(path, MAX_PASSPHRASE_FILE_BYTES, owner_only="passphrase file")
    lines = raw.splitlines()
    if not lines or not lines[0]:
        raise _KeyFileError("passphrase file is empty")
    if len(lines[0]) > MAX_PASSPHRASE_BYTES:
        raise _KeyFileError(f"passphrase must be at most {MAX_PASSPHRASE_BYTES} bytes")
    return lines[0]


def _load_private(path: Path, passphrase: bytes | None) -> Ed25519PrivateKey:
    pem = _read(path, MAX_KEY_BYTES, owner_only="private key file")
    encrypted = pem.lstrip().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    if encrypted and passphrase is None:
        raise _KeyFileError("private key is encrypted; pass --passphrase-file")
    try:
        private = serialization.load_pem_private_key(
            pem, password=passphrase if encrypted else None
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise _KeyFileError(
            "private key could not be loaded; check the file and passphrase"
        ) from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise _KeyFileError("only Ed25519 signing keys are supported")
    return private


def _load_public(path: Path) -> Ed25519PublicKey:
    try:
        public = serialization.load_pem_public_key(_read(path, MAX_KEY_BYTES))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise _KeyFileError("public key could not be loaded") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise _KeyFileError("only Ed25519 public keys are supported")
    return public


def _refuse_source_overwrite(output: Path | None, source: Path) -> None:
    from nexus_symbiote.utils.terminal import output_failure

    if output is None:
        return
    try:
        # Path text alone misses a second name for the same file (a hard link, a bind
        # mount or a case variant), so an existing output is also compared by identity.
        same = output.resolve() == source.resolve() or (
            output.exists() and os.path.samefile(output, source)
        )
    except (OSError, RuntimeError) as exc:
        raise output_failure(exc) from exc
    if same:
        raise click.BadParameter("output must not overwrite the source inventory")


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
@click.option(
    "--passphrase-file",
    type=click.Path(path_type=Path),
    help="Encrypt the private key with the passphrase on the first line of this file, "
    "which you own and which gives group and others no permission.",
)
def keygen(private_key: Path, public_key: Path, passphrase_file: Path | None) -> None:
    """Create an Ed25519 key pair without overwriting existing files.

    Use one key pair per purpose: snapshot, approval and trust rings must not share keys.
    """
    try:
        if (
            _path_exists_or_symlink(private_key)
            or _path_exists_or_symlink(public_key)
            or private_key.absolute() == public_key.absolute()
        ):
            raise _KeyFileError("choose distinct, nonexistent key paths")
        passphrase = _passphrase(passphrase_file)
        key = Ed25519PrivateKey.generate()
        encryption: serialization.KeySerializationEncryption = (
            serialization.NoEncryption()
            if passphrase is None
            else serialization.BestAvailableEncryption(passphrase)
        )
        # Serialize both keys first, so a refused passphrase writes neither file.
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )
        _write_new(public_key, public_pem)
        try:
            _write_new(private_key, private_pem)
        except BaseException:
            _unlink_created(public_key)
            raise
        result = {"key_id": key_id(key.public_key()), "encrypted": passphrase is not None}
        click.echo(json_text(json.dumps(result)))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "key generation")) from None


@runtime_group.command("sign")
@click.argument("contract_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind",
    type=click.Choice(_CONTRACT_KINDS),
    required=True,
    help="Contract purpose; a signature is valid only for this purpose.",
)
@click.option(
    "--key",
    "keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Ed25519 private key PEM that you own and only you can access; "
    "repeat for multiple signers.",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    required=True,
    help="Signed envelope file to create; must not exist.",
)
@click.option(
    "--passphrase-file",
    type=click.Path(path_type=Path),
    help="Passphrase for encrypted private keys, on the first line of this file, "
    "which you own and which gives group and others no permission.",
)
def sign(
    contract_path: Path,
    kind: str,
    keys: tuple[Path, ...],
    out: Path,
    passphrase_file: Path | None,
) -> None:
    """Sign an explicit contract; signatures do not establish unmeasured facts.

    A contract that could never verify, because its validity window is longer than
    its purpose allows or has already ended, is refused. Prints the contract digest
    that approvals and revocation lists use.
    """
    purpose = cast(Kind, kind)
    try:
        contract = CONTRACTS[purpose].model_validate(_json_object(contract_path))
        if contract.not_after - contract.not_before > MAX_LIFETIMES[purpose]:
            raise AuthorizationError(
                "contract validity exceeds its purpose's maximum lifetime",
                reason=f"{purpose}-lifetime-exceeds-policy",
            )
        if contract.not_after <= datetime.now(UTC):
            raise AuthorizationError("contract has expired", reason=f"{purpose}-expired")
        passphrase = _passphrase(passphrase_file)
        loaded = tuple(_load_private(path, passphrase) for path in keys)
        envelope = sign_contract(contract, purpose, loaded)
        _write_new(
            out,
            (json.dumps(envelope.model_dump(mode="json", by_alias=True), indent=2) + "\n").encode(),
        )
        result = {
            "out": str(out),
            "predicate": kind,
            "digest": contract_digest(contract),
            "signers": sorted({key_id(private.public_key()) for private in loaded}),
            "signed": True,
        }
        click.echo(json_text(json.dumps(result)))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "signing")) from None


@runtime_group.command("verify")
@click.argument("envelope_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind",
    type=click.Choice(_CONTRACT_KINDS),
    required=True,
    help="Expected contract purpose; a contract signed for another purpose is rejected.",
)
@click.option(
    "--public-key",
    "keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Trusted Ed25519 public key PEM; repeat to build the trusted key ring. It must lie "
    "outside every git working tree that holds ENVELOPE_PATH, the --bom file or the current "
    "directory, which catches misplacement but does not authenticate the key.",
)
@click.option(
    "--threshold",
    type=click.IntRange(min=1, max=32),
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
    """Verify purpose, signer, subject and time; invocation uses ReferenceGateway.

    Revocation, signer scopes, approver identities and an approval's bindings are
    checked only by the gateway.
    """
    purpose = cast(Kind, kind)
    inputs = (envelope_path,) if bom is None else (envelope_path, bom)
    _check_key_placement(
        keys, inputs, option="--public-key", holders="ENVELOPE_PATH, the --bom file"
    )
    try:
        ring = _ring(keys)
        envelope = Envelope.model_validate(_json_object(envelope_path))
        contract, accepted = verify_contract(envelope, purpose, ring, threshold=threshold)
        _window(contract, datetime.now(UTC), MAX_LIFETIMES[purpose], purpose)
        if isinstance(contract, ApprovedSnapshot):
            if bom is None:
                raise AuthorizationError(
                    "snapshot verification requires its exact companion BOM",
                    reason="bom-required",
                )
            if bom_digest(_json_object(bom)) != contract.bom_digest:
                raise AuthorizationError(
                    "companion BOM does not match approved digest", reason="bom-mismatch"
                )
        result: dict[str, Any] = {
            "contract_verified": True,
            "kind": kind,
            "digest": contract_digest(contract),
            "accepted_signers": sorted(accepted),
            "invocation_authorized": False,
        }
        click.echo(json_text(json.dumps(result, indent=2)))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "verification")) from None


@runtime_group.command("digest")
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind",
    type=click.Choice(_DIGEST_KINDS),
    required=True,
    help="What the file holds: an unsigned contract, an execution context, a tool call, "
    "a served tool descriptor or a companion BOM.",
)
def digest_command(input_path: Path, kind: str) -> None:
    """Print the canonical digest that contracts, approvals and revocations bind.

    It verifies nothing and works for contracts that are not yet valid or expired.
    """
    try:
        document = _json_object(input_path)
        if kind in CONTRACTS:
            value = contract_digest(CONTRACTS[kind].model_validate(document))
        elif kind == "context":
            value = contract_digest(ExecutionContext.model_validate(document))
        elif kind == "request":
            value = request_digest(ToolCall.model_validate(document))
        elif kind == "tool":
            value = tool_definition_digest(document)
        else:
            value = bom_digest(document)
        click.echo(json_text(json.dumps({"kind": kind, "digest": value})))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "digest")) from None


@runtime_group.command("key-id")
@click.argument("public_key", type=click.Path(exists=True, path_type=Path))
def key_id_command(public_key: Path) -> None:
    """Print the key ID that envelopes, key rings and revocation lists use."""
    try:
        click.echo(json_text(json.dumps({"key_id": key_id(_load_public(public_key))})))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "key ID")) from None


@runtime_group.command("register")
@click.argument("snapshot_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--trust",
    "trust_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Signed, currently valid trust status for the snapshot's tenant.",
)
@click.option(
    "--state",
    type=click.Path(path_type=Path),
    required=True,
    help="Initialized state database that the gateways share.",
)
@click.option(
    "--snapshot-key",
    "snapshot_keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Trusted snapshot-signing public key PEM; repeat to build the ring.",
)
@click.option(
    "--trust-key",
    "trust_keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Trusted trust-status public key PEM; repeat to build the ring.",
)
@click.option(
    "--approval-key",
    "approval_keys",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Approval public key PEM the gateways trust; repeat for each. Only checked, so "
    "the gateways' signer scope map can be passed unchanged.",
)
@click.option(
    "--snapshot-threshold",
    type=click.IntRange(min=1, max=32),
    default=1,
    help="Minimum number of distinct snapshot signers (default: 1).",
)
@click.option(
    "--trust-threshold",
    type=click.IntRange(min=1, max=32),
    default=1,
    help="Minimum number of distinct trust-status signers (default: 1).",
)
@click.option(
    "--signer-scopes",
    type=click.Path(exists=True, path_type=Path),
    help="JSON object mapping key IDs to the signer scopes the gateways use.",
)
@click.option(
    "--allow-shared-keys",
    is_flag=True,
    help="Accept a key in more than one ring, as gateways built with allow_shared_keys=True do.",
)
def register(
    snapshot_path: Path,
    trust_path: Path,
    state: Path,
    snapshot_keys: tuple[Path, ...],
    trust_keys: tuple[Path, ...],
    approval_keys: tuple[Path, ...],
    snapshot_threshold: int,
    trust_threshold: int,
    signer_scopes: Path | None,
    allow_shared_keys: bool,
) -> None:
    """Make a newly issued snapshot current; gateways sharing the store deny older serials.

    The snapshot and trust status are checked as the gateway checks them, except the
    workload context and the companion BOM. Pass the rings, quorums, signer scopes
    and shared-key setting the gateways use; approval keys are only checked against
    the scope map. Every key file must lie outside every git working tree that holds
    SNAPSHOT_PATH, a --trust, --state or --signer-scopes file, or the current directory.
    """
    inputs = (
        snapshot_path,
        trust_path,
        state,
        *(() if signer_scopes is None else (signer_scopes,)),
    )
    for option, ring_keys in (
        ("--snapshot-key", snapshot_keys),
        ("--trust-key", trust_keys),
        ("--approval-key", approval_keys),
    ):
        _check_key_placement(
            ring_keys,
            inputs,
            option=option,
            holders="SNAPSHOT_PATH, a --trust, --state or --signer-scopes file,",
        )
    try:
        scopes = (
            {}
            if signer_scopes is None
            else {
                name: SignerScope.model_validate(scope)
                for name, scope in _json_object(signer_scopes).items()
            }
        )
        rings = {
            "snapshot": _ring(snapshot_keys),
            "trust": _ring(trust_keys),
            "approval": _ring(approval_keys),
        }
        _check_rings(rings, scopes, allow_shared_keys)
        registrar = ReferenceGateway.registrar(
            snapshot_keys=rings["snapshot"],
            trust_keys=rings["trust"],
            approval_keys=rings["approval"],
            state=StateStore(state),
            snapshot_threshold=snapshot_threshold,
            trust_threshold=trust_threshold,
            signer_scopes=scopes,
            allow_shared_keys=allow_shared_keys,
        )
        snapshot = registrar.register_snapshot(
            Envelope.model_validate(_json_object(snapshot_path)),
            trust=Envelope.model_validate(_json_object(trust_path)),
        )
        result = {
            "registered": True,
            "tenant": snapshot.tenant,
            "deployment_id": snapshot.deployment_id,
            "agent_id": snapshot.agent_id,
            "serial": snapshot.serial,
            "digest": contract_digest(snapshot),
        }
        click.echo(json_text(json.dumps(result)))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "registration")) from None


def register_runtime_commands(main: click.Group) -> None:
    main.add_command(runtime_group)
