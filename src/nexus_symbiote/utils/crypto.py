"""Artifact-bound integrity verification under an explicit signer trust policy."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nexus_symbiote.core.hashing import (
    descriptor_binding,
    normalize_digest,
    open_directory_nofollow,
    open_regular_file,
    pathname_identity,
)

if TYPE_CHECKING:
    from sigstore.models import TrustedRoot

    from nexus_symbiote.core.models import ClaimEvidence

MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_TRUST_ROOT_BYTES = 4 * 1024 * 1024
MAX_SIGNED_ARTIFACT_BYTES = 5 * 1024 * 1024 * 1024
# A fixed message, so callers can report it instead of a generic signature failure.
SIGSTORE_MISSING = "sigstore package not installed; install nexus-symbiote[sigstore]"
DSSE_UNSUPPORTED = (
    "Bundle carries a DSSE envelope (an OpenSSF Model Signing signature or an attestation); "
    "only Sigstore message-signature bundles are verified"
)


class SigningStatus(str, Enum):
    """What the model collector established about a model's weight files."""

    SIGSTORE_SIGNED = "sigstore-signed"
    DIGEST_PINNED = "digest-pinned"
    PARTIALLY_VERIFIED = "partially-verified"
    VERIFICATION_FAILED = "verification-failed"
    VERIFICATION_UNAVAILABLE = "verification-unavailable"
    SIGNATURE_PRESENT_UNVERIFIED = "signature-present-unverified"
    SIGNATURE_NOT_FOUND = "signature-not-found"


VERIFIED_SIGNING_STATUSES = frozenset(
    {SigningStatus.SIGSTORE_SIGNED.value, SigningStatus.DIGEST_PINNED.value}
)
# The claim on a model component that records how its signing status was established.
SIGNING_EVIDENCE_CLAIM = "signing_status"
# An evidence reference that names the digest of the operator policy file a run used.
POLICY_REF_PREFIX = "policy:"


def component_evidence_refs(refs: Iterable[Any]) -> list[Any]:
    """``refs`` without policy-file digests, to compare one component across runs.

    The digest identifies the run's policy file, not the component: equivalent
    policies with other bytes, or one more entry for another artifact, must not
    make the same verified component look changed or mismatched.
    """
    return [ref for ref in refs if not (isinstance(ref, str) and ref.startswith(POLICY_REF_PREFIX))]


def comparable_claim(claim: ClaimEvidence) -> dict[str, Any]:
    """A claim as two runs compare it: without its observation time or policy-file digest."""
    dumped = claim.model_dump(exclude={"observed_at"})
    dumped["evidence_refs"] = component_evidence_refs(dumped["evidence_refs"])
    return dumped


def _sha256(value: str | None) -> str | None:
    if value is None:
        return None
    algorithm, digest = normalize_digest(value, "sha256")
    return f"{algorithm}:{digest}"


# Explicit Sigstore trust-root override. A flag value wins over the environment;
# when neither is set, the sigstore-python TUF cache is used after the private
# cache check and single read in _read_sigstore_cache.
TRUST_ROOT_ENV = "NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT"
TRUST_ROOT_SHA256_ENV = "NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256"


@dataclass(frozen=True)
class SigstoreArtifactPolicy:
    """Trusted caller input, never inferred from a BOM or adjacent signature file.

    This policy authorizes verification of one artifact with one exact identity
    and OIDC issuer, and with ``expected_sha256`` also pins its exact bytes, so
    another artifact signed by the same identity cannot take its place. It does
    not grant execution authority to the artifact.
    """

    artifact_path: Path
    bundle_path: Path
    expected_identity: str
    expected_issuer: str
    expected_sha256: str | None = None
    policy_digest: str | None = None
    allow_oms_dsse: bool = False
    rekor_root_hash: str | None = None
    minimum_rekor_tree_size: int | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.expected_identity, str)
            or not self.expected_identity.strip()
            or not isinstance(self.expected_issuer, str)
            or not self.expected_issuer.strip()
        ):
            raise ValueError("Both an expected signer identity and OIDC issuer are required")
        if type(self.allow_oms_dsse) is not bool:
            raise ValueError("allow_oms_dsse must be a boolean")
        if self.expected_sha256 is not None and not isinstance(self.expected_sha256, str):
            raise ValueError("expected_sha256 must be a string")
        if self.rekor_root_hash is not None and not isinstance(self.rekor_root_hash, str):
            raise ValueError("rekor_root_hash must be a string")
        object.__setattr__(self, "expected_sha256", _sha256(self.expected_sha256))
        object.__setattr__(self, "rekor_root_hash", _sha256(self.rekor_root_hash))
        if self.minimum_rekor_tree_size is not None and (
            type(self.minimum_rekor_tree_size) is not int or self.minimum_rekor_tree_size < 1
        ):
            raise ValueError("minimum_rekor_tree_size must be a positive integer")


@dataclass(frozen=True)
class DigestPinPolicy:
    """An operator-pinned SHA-256 for one artifact; the operator is the trust root."""

    artifact_path: Path
    expected_sha256: str
    policy_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_sha256", _sha256(self.expected_sha256))


ArtifactPolicy = SigstoreArtifactPolicy | DigestPinPolicy


class SignaturePolicySet(list[SigstoreArtifactPolicy]):
    """The Sigstore entries of one operator policy, plus its digest pins and digest.

    It is a list of the Sigstore entries so every consumer that verifies
    signatures keeps working; consumers that accept digest pins read
    ``digest_pins`` as well.
    """

    def __init__(
        self,
        signatures: Iterable[SigstoreArtifactPolicy] = (),
        digest_pins: Iterable[DigestPinPolicy] = (),
        *,
        digest: str | None = None,
    ) -> None:
        super().__init__(signatures)
        self.digest_pins: tuple[DigestPinPolicy, ...] = tuple(digest_pins)
        self.digest = digest


def policy_entries(
    signature_policies: Iterable[SigstoreArtifactPolicy],
    digest_pins: Iterable[DigestPinPolicy] = (),
) -> list[ArtifactPolicy]:
    """Every entry of a policy set or plain sequence, rejecting duplicate artifacts."""
    entries: list[ArtifactPolicy] = [*signature_policies, *digest_pins]
    if isinstance(signature_policies, SignaturePolicySet):
        entries.extend(signature_policies.digest_pins)
    if len({entry.artifact_path.resolve() for entry in entries}) != len(entries):
        raise ValueError("Duplicate artifact signature policies")
    return entries


@dataclass
class VerificationResult:
    """Outcome of a signature or hash verification."""

    verified: bool
    identity: str | None = None
    issuer: str | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


def _current_uid() -> int | None:
    """Current user id, or None on platforms without user ids."""
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        uid: int = geteuid()
        return uid
    return None


# What an operator can do about a shared cache entry, and about a shared explicit root.
_CACHE_REMEDY = (
    "point XDG_CACHE_HOME at a directory you own, or use an explicit trust root "
    f"({TRUST_ROOT_ENV} or --trust-root)"
)
_EXPLICIT_REMEDY = (
    f"or pin the trust root's SHA-256 ({TRUST_ROOT_SHA256_ENV} or --trust-root-sha256)"
)


def _owner_error(info: os.stat_result, path: Path, *, what: str) -> str | None:
    """Return an error when a trust entry is not owned by the current user."""
    uid = _current_uid()
    if uid is not None and info.st_uid != uid:
        return f"{what} {path} is not owned by the current user"
    return None


def _private_dir_error(path: Path, *, what: str, remedy: str) -> str | None:
    """Return an error unless a path is a user-owned private directory, not a symlink."""
    try:
        info = os.lstat(path)
    except OSError:
        return f"{what} {path} cannot be inspected"
    return _private_dir_info_error(info, path, what=what, remedy=remedy)


def _private_dir_info_error(
    info: os.stat_result, path: Path, *, what: str, remedy: str
) -> str | None:
    if stat.S_ISLNK(info.st_mode):
        return f"{what} {path} must not be a symlink"
    if not stat.S_ISDIR(info.st_mode):
        return f"{what} {path} is not a directory"
    if (error := _owner_error(info, path, what=what)) is not None:
        return error
    if info.st_mode & 0o022:
        return f"{what} {path} is group/world-writable; make it private, {remedy}"
    return None


_SEEDED_ROOT_SIDECAR = ".trusted_root.seeded.sha256"


def _private_file_info_error(
    info: os.stat_result, parent_mode: int | None, path: Path, *, what: str, remedy: str
) -> str | None:
    """Return an error unless a trust file is user-owned, unlinked elsewhere, and private.

    A group/world-writable file is accepted only when its parent directory
    keeps everyone else from traversing to it: sigstore-python seeds
    trusted_root.json with the ambient umask, so under umask 002/007 the file
    is group-writable and only the private directory (mode 0700, as
    _check_sigstore_cache_dirs creates) protects it.
    """
    if (error := _owner_error(info, path, what=what)) is not None:
        return error
    if info.st_nlink != 1:
        return f"{what} {path} must not have other hard links; {remedy}"
    if info.st_mode & 0o022:
        if parent_mode is None or parent_mode & 0o011:
            return (
                f"{what} {path} is group/world-writable and its directory lets "
                f"others reach it; make the file private, make its directory private, {remedy}"
            )
    return None


# Every valid uid; (uid_t)-1 is reserved. The initial user namespace maps exactly this.
_FULL_UID_RANGE = 4_294_967_295
_DEFAULT_OVERFLOW_UID = 65534


def _read_uid_map() -> str | None:
    """This process's ``/proc/self/uid_map``, or ``None`` where it cannot be read."""
    try:
        return Path("/proc/self/uid_map").read_text(encoding="utf-8")
    except OSError:
        return None


def _overflow_uid() -> int:
    """The uid the kernel shows for an owner unmapped in this user namespace."""
    try:
        value = int(Path("/proc/sys/kernel/overflowuid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return _DEFAULT_OVERFLOW_UID
    return value if 0 <= value < _FULL_UID_RANGE else _DEFAULT_OVERFLOW_UID


def _parse_uid_map(text: str) -> list[tuple[int, int]] | None:
    """``(first inside uid, count)`` per ``uid_map`` line, or ``None`` if malformed."""
    ranges: list[tuple[int, int]] = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 3 or not all(field.isascii() and field.isdigit() for field in fields):
            return None
        ranges.append((int(fields[0]), int(fields[2])))
    return ranges


def _trusted_ancestor_uids(uid: int) -> set[int]:
    """Owners trusted above an unpinned trust root or a signature policy.

    The caller's effective uid, and uid 0 when this user namespace maps it. In a
    user namespace that does not map every uid, the kernel shows every unmapped
    owner, host root and other host users alike, as the overflow uid, so that uid
    is never trusted there, not even when it is the caller's own. Where the map
    cannot be read on Linux a partial namespace cannot be ruled out and the
    overflow uid is not trusted either; elsewhere there are no user namespaces.
    """
    text = _read_uid_map()
    ranges = None if text is None else _parse_uid_map(text)
    if ranges is None:
        if not sys.platform.startswith("linux"):
            return {0, uid}
        return {0, uid} - {_overflow_uid()}
    allowed = {uid}
    if any(first <= 0 < first + count for first, count in ranges):
        allowed.add(0)
    if sum(count for _first, count in ranges) < _FULL_UID_RANGE:
        allowed.discard(_overflow_uid())
    return allowed


def _absolute_through_root_links(path: Path) -> Path:
    """``path`` made absolute, with macOS's standard ``/var``-style root links resolved."""
    absolute = Path(os.path.abspath(path))
    parts = list(absolute.parts)
    if (
        sys.platform == "darwin"
        and len(parts) > 1
        and parts[0] == "/"
        and parts[1] in {"var", "tmp", "etc"}
    ):
        link_path = f"/{parts[1]}"
        with contextlib.suppress(OSError):
            if os.path.islink(link_path) and os.readlink(link_path) == f"private/{parts[1]}":
                absolute = Path("/", "private", *parts[1:])
    return absolute


def _check_trusted_ancestors(
    directory: Path,
    trusted_uids: set[int] | None,
    *,
    include_self: bool = True,
    verify_fd: bool = True,
    open_dir: Callable[[Path], int] = open_directory_nofollow,
    anchor_path: Path | None = None,
) -> tuple[str, Path] | None:
    """Inspect ``directory`` and its ancestors up to the root for symlink, owner, or write risks.

    Returns ``None`` when every checked ancestor is safe, or ``(reason, failing_path)`` where
    ``reason`` is one of ``"uninspectable"``, ``"symlink"``, ``"not_dir"``, ``"untrusted_owner"``,
    or ``"writable"``.
    """
    abs_dir = _absolute_through_root_links(directory)
    abs_subject = _absolute_through_root_links(anchor_path) if anchor_path is not None else abs_dir
    chain = (abs_dir, *abs_dir.parents) if include_self else tuple(abs_dir.parents)
    walk = tuple(reversed(chain)) if verify_fd else chain
    for ancestor in walk:
        try:
            linfo = os.lstat(ancestor)
        except OSError:
            return "uninspectable", ancestor
        if stat.S_ISLNK(linfo.st_mode):
            return "symlink", ancestor
        if not stat.S_ISDIR(linfo.st_mode):
            return "not_dir", ancestor
        is_mount_anchor = ancestor == Path(abs_subject.anchor) and len(abs_subject.parts) > 2
        if not verify_fd:
            info = linfo
            owner_trusted = trusted_uids is None or info.st_uid in trusted_uids
        else:
            if (
                trusted_uids is not None
                and not is_mount_anchor
                and linfo.st_uid not in trusted_uids
            ):
                return "untrusted_owner", ancestor
            if (linfo.st_mode & 0o022) and not (linfo.st_mode & stat.S_ISVTX):
                return "writable", ancestor
            try:
                fd = open_dir(ancestor)
            except PermissionError:
                # Earlier ancestors passed trust checks; a traverse-only entry can
                # still be inspected without following it or opening it for reading.
                info = linfo
                owner_trusted = trusted_uids is None or info.st_uid in trusted_uids
            except OSError:
                return "uninspectable", ancestor
            else:
                try:
                    info = os.fstat(fd)
                    owner_trusted = trusted_uids is None or info.st_uid in trusted_uids
                    if not owner_trusted and is_mount_anchor:
                        # An unprivileged writer cannot rename a direct mount under
                        # a read-only namespace root with an unmapped UID.
                        owner_trusted = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY) and (
                            os.stat(abs_subject.parts[1], dir_fd=fd, follow_symlinks=False).st_dev
                            != info.st_dev
                        )
                except OSError:
                    return "uninspectable", ancestor
                finally:
                    os.close(fd)
        if not owner_trusted:
            return "untrusted_owner", ancestor
        if (info.st_mode & 0o022) and not (info.st_mode & stat.S_ISVTX):
            return "writable", ancestor
    return None


def _ancestor_error(directory: Path, *, dir_what: str, remedy: str) -> str | None:
    """Reject non-sticky group/world-writable or foreign non-root ancestors above an unpinned root."""
    uid = _current_uid()
    trusted_uids = _trusted_ancestor_uids(uid) if uid is not None else None
    failure = _check_trusted_ancestors(directory, trusted_uids, include_self=False, verify_fd=False)
    if failure is None:
        return None
    reason, ancestor = failure
    if reason == "uninspectable":
        return f"{dir_what} {ancestor} cannot be inspected"
    if reason == "symlink":
        return f"{dir_what} {ancestor} must not be a symlink"
    if reason in {"not_dir", "untrusted_owner"}:
        return f"{dir_what} {ancestor} is not owned by the current user"
    return f"{dir_what} {ancestor} is group- or world-writable without sticky protection; {remedy}"


def _trust_anchor_error(path: Path, info: os.stat_result | None) -> str | None:
    """Why someone other than the caller or root could replace a trust anchor, or ``None``.

    ``info`` is the ``fstat`` of the anchor as opened without following symlinks, so the
    file judged is the file read. When preparing a temporary anchor, pass its parent
    directory and ``None`` to check that directory and its ancestors. Whoever can
    write a directory above the anchor can
    rename the directory below it away and put another anchor in its place, so every
    ancestor up to the file system root must be a real directory owned by the caller or
    root that its group and others cannot write unless it is sticky. Ancestors are
    checked after the open: replacing one needs write access to the directory above it,
    which this walk then refuses. The reason is fixed text that never names the path.
    """
    uid = _current_uid()
    if uid is None:
        return None
    trusted_uids = _trusted_ancestor_uids(uid)
    if info is not None:
        if info.st_uid not in trusted_uids:
            return "must be owned by the current user or root"
        if info.st_mode & 0o022:
            return "must not be group- or world-writable"
    directory = path if info is None else path.parent
    failure = _check_trusted_ancestors(
        directory,
        trusted_uids,
        include_self=True,
        verify_fd=True,
        anchor_path=path,
    )
    if failure is None:
        return None
    reason, _ancestor = failure
    if reason == "uninspectable":
        return "must lie in directories that can be inspected"
    return (
        "must lie in directories, up to the file system root, that are owned by "
        "the current user or root and are not group- or world-writable unless sticky"
    )


def _sigstore_cache_targets_dir() -> Path:
    """Resolve the TUF targets directory exactly as sigstore-python does.

    sigstore-python exposes no public API for this path, so this uses the same
    resolver its TrustUpdater uses. If that private API moves, verification
    fails closed instead of checking the wrong directory.
    """
    from sigstore._internal.tuf import DEFAULT_TUF_URL, _get_dirs

    _metadata_dir, targets_dir = _get_dirs(DEFAULT_TUF_URL)
    return targets_dir


def _check_sigstore_cache_dirs() -> tuple[Path | None, str | None]:
    """Ensure the offline TUF cache directories are private, creating them mode 0700.

    Offline, sigstore-python reads ``trusted_root.json`` from its user cache
    without verifying it, so anyone who can write to the cache (or rename a
    component above it) chooses the accepted certificate authorities and
    transparency logs. This checks the TUF targets directory and every ancestor
    up to the Sigstore cache directory and fails closed on any symlink, foreign
    owner, or group/world write bit; ``_read_sigstore_cache`` checks the file.
    The ownership and mode of the cache home above the Sigstore directory, which
    other applications share, are not checked; on a shared machine point
    XDG_CACHE_HOME at a private directory instead. The cache is then opened
    without following symlinks, so no directory on its path may be one.

    Returns (targets_dir, error); exactly one of them is set.
    """
    try:
        import platformdirs

        targets_dir = _sigstore_cache_targets_dir()
        sigstore_dir = Path(platformdirs.user_cache_dir("sigstore-python", "sigstore"))
    except Exception:
        return None, "Cannot resolve the Sigstore trust-root cache location"
    missing: list[Path] = []
    probe = targets_dir
    while not probe.exists():
        missing.append(probe)
        if probe == probe.parent:
            break
        probe = probe.parent
    for component in reversed(missing):
        try:
            os.mkdir(component, 0o700)
        except FileExistsError:
            continue  # Created concurrently; the chain check below vets it.
        except OSError:
            return None, f"Cannot create the private Sigstore trust-root cache at {component}"
    current = targets_dir
    while True:
        error = _private_dir_error(
            current, what="Sigstore trust-root cache directory", remedy=_CACHE_REMEDY
        )
        if error is not None:
            return None, error
        if current == sigstore_dir:
            break
        if sigstore_dir not in current.parents:
            return None, (
                "Sigstore trust-root cache "
                f"{targets_dir} is outside the Sigstore cache directory {sigstore_dir}"
            )
        current = current.parent
    return targets_dir, None


def _read_sigstore_cache() -> tuple[Path | None, bytes | None, str | None]:
    """Check the offline TUF cache and read its trusted root once.

    After the directory chain passes ``_check_sigstore_cache_dirs``, a missing
    ``trusted_root.json`` is seeded mode 0600 from the root embedded in
    sigstore-python, as sigstore-python itself would. The file is then opened
    once without following symlinks, must be user-owned and not group/world
    writable where anyone else can reach it (a file sigstore-python seeded
    under a group-writable umask is accepted only inside a private directory),
    judged by fstat on that descriptor and its directory's, and read. The
    caller must build the verifier from the returned bytes and never let
    sigstore-python re-read the path, which a process running as the same user
    could replace in between.

    Returns (trusted_root_path, content, error); the error is set alone on failure.
    """
    targets_dir, error = _check_sigstore_cache_dirs()
    if error is not None or targets_dir is None:
        return None, None, error or "Sigstore trust-root cache could not be checked"
    trusted_root = targets_dir / "trusted_root.json"
    error = _seed_sigstore_cache(trusted_root)
    if error is not None:
        return None, None, error
    content, error = _read_checked_trust_root(
        trusted_root,
        private=True,
        what="Sigstore trusted root",
        dir_what="Sigstore trust-root cache directory",
        remedy=_CACHE_REMEDY,
    )
    if content is None:
        return None, None, error or f"Sigstore trusted root {trusted_root} cannot be inspected"
    content = _refresh_seeded_sigstore_cache(trusted_root, content)
    return trusted_root, content, None


def _write_raw_nofollow(dir_fd: int, name: str, payload: bytes) -> None:
    """Write ``payload`` to ``name`` in ``dir_fd`` via raw OS calls without os.fdopen."""
    cloexec = getattr(os, "O_CLOEXEC", 0)
    temp_name = f".{name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | cloexec
    fd = os.open(temp_name, flags, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(temp_name, dir_fd=dir_fd)
        raise
    os.close(fd)
    try:
        os.replace(temp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name, dir_fd=dir_fd)
        raise


def _refresh_seeded_sigstore_cache(trusted_root: Path, content: bytes) -> bytes:
    """Refresh an unmodified previously seeded cache root when sigstore-python upgrades."""
    try:
        from sigstore._internal.tuf import DEFAULT_TUF_URL
        from sigstore._utils import read_embedded

        embedded = read_embedded("trusted_root.json", DEFAULT_TUF_URL)
    except Exception:
        return content
    if content == embedded:
        return content
    cloexec = getattr(os, "O_CLOEXEC", 0)
    try:
        dir_fd = open_directory_nofollow(trusted_root.parent)
    except OSError:
        return content
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | cloexec
        sidecar_fd = os.open(_SEEDED_ROOT_SIDECAR, flags, dir_fd=dir_fd)
        try:
            info = os.fstat(sidecar_fd)
            uid = _current_uid()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or (uid is not None and info.st_uid != uid)
                or info.st_size > 128
            ):
                return content
            recorded = os.read(sidecar_fd, 129).strip().decode("ascii")
        finally:
            os.close(sidecar_fd)
        current_digest = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(recorded, current_digest):
            return content
        new_digest = hashlib.sha256(embedded).hexdigest().encode("ascii")
        _write_raw_nofollow(dir_fd, trusted_root.name, embedded)
        _write_raw_nofollow(dir_fd, _SEEDED_ROOT_SIDECAR, new_digest)
        return embedded
    except (OSError, UnicodeDecodeError):
        return content
    finally:
        os.close(dir_fd)


def _seed_sigstore_cache(trusted_root: Path) -> str | None:
    """Create a missing cached trusted root from sigstore-python's embedded copy.

    The file is created exclusively and without following symlinks, so an
    existing entry of any kind is left in place for the checked read to vet. A
    file that could not be written whole, including when closing it fails, is
    removed, so a later run does not read a truncated root.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    failure = f"Cannot seed the Sigstore trusted root {trusted_root}"
    try:
        dir_fd = open_directory_nofollow(trusted_root.parent)
    except OSError:
        return (
            f"Cannot open the Sigstore trust-root cache directory {trusted_root.parent} "
            "without following symlinks; no directory on its path may be a symlink"
        )
    try:
        try:
            fd = os.open(trusted_root.name, flags, 0o600, dir_fd=dir_fd)
        except FileExistsError:
            return None
        try:
            with os.fdopen(fd, "wb") as stream:
                from sigstore._internal.tuf import DEFAULT_TUF_URL
                from sigstore._utils import read_embedded

                embedded = read_embedded("trusted_root.json", DEFAULT_TUF_URL)
                stream.write(embedded)
        except Exception:
            os.unlink(trusted_root.name, dir_fd=dir_fd)
            return failure
        with contextlib.suppress(OSError):
            digest_bytes = hashlib.sha256(embedded).hexdigest().encode("ascii")
            _write_raw_nofollow(dir_fd, _SEEDED_ROOT_SIDECAR, digest_bytes)
    except OSError:
        return failure
    finally:
        os.close(dir_fd)
    return None


def _read_explicit_trust_root(
    trust_root: str | Path | None, expected_sha256: str | None
) -> tuple[Path | None, bytes | None, str | None, str | None]:
    """Resolve an explicit trust root from a flag value or the environment and read it once.

    A flag value wins over ``NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT``. The path
    names a ``trusted_root.json`` file, or a directory holding one. With a
    pinned SHA-256 (flag or ``NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256``)
    the file bytes must match it; without one, the file and its parent
    directory must be user-owned and private. The file is opened once without
    following symlinks, the checks run against that descriptor, and the bytes
    returned are exactly the bytes checked, so the caller must load the trust
    root from them and never re-open the path.

    Returns (path, content, source, error); source is "flag" or "environment".
    """
    raw = trust_root
    source = "flag"
    if raw is None:
        raw = os.environ.get(TRUST_ROOT_ENV) or None
        source = "environment"
    digest = expected_sha256
    if digest is None:
        digest = os.environ.get(TRUST_ROOT_SHA256_ENV) or None
    if raw is None:
        if digest is not None:
            return (
                None,
                None,
                None,
                "A pinned Sigstore trust-root SHA-256 was supplied without a trust root; "
                f"set {TRUST_ROOT_ENV} or pass --trust-root",
            )
        return None, None, None, None
    path = Path(raw)
    if path.is_dir():
        path = path / "trusted_root.json"
    expected: str | None = None
    if digest is not None:
        try:
            _algorithm, expected = normalize_digest(digest, "sha256")
        except ValueError:
            return (
                None,
                None,
                None,
                "Pinned Sigstore trust-root SHA-256 must be sha256:<64 lowercase hex characters>",
            )
    content, error = _read_checked_trust_root(
        path, private=expected is None, check_ancestors=expected is None
    )
    if content is None:
        return None, None, None, error
    if expected is not None and not hmac.compare_digest(
        hashlib.sha256(content).hexdigest(), expected
    ):
        return None, None, None, "Explicit Sigstore trust root does not match the pinned SHA-256"
    return path, content, source, None


def _read_checked_trust_root(
    path: Path,
    *,
    private: bool,
    check_ancestors: bool = False,
    what: str = "Explicit Sigstore trust root",
    dir_what: str = "Explicit Sigstore trust-root directory",
    remedy: str = _EXPLICIT_REMEDY,
) -> tuple[bytes | None, str | None]:
    """Read a trust-root file once through a no-follow descriptor, bounded.

    With ``private``, the file and its parent directory must be user-owned and
    private, judged by fstat on the very descriptors the bytes come from.
    """
    try:
        dir_fd = open_directory_nofollow(path.parent)
    except OSError:
        fallback = (
            _private_dir_error(path.parent, what=dir_what, remedy=remedy) if private else None
        )
        return None, fallback or f"{what} {path} cannot be inspected"
    try:
        try:
            linked = os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            return None, f"{what} {path} cannot be inspected"
        if stat.S_ISLNK(linked.st_mode):
            return None, f"{what} {path} must not be a symlink"
        if not stat.S_ISREG(linked.st_mode):
            return None, f"{what} {path} is not a regular file"
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path.name, flags, dir_fd=dir_fd)
        except OSError:
            return None, f"{what} {path} cannot be inspected"
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return None, f"{what} {path} is not a regular file"
            if private:
                dir_info = os.fstat(dir_fd)
                error = _private_file_info_error(
                    info, dir_info.st_mode, path, what=what, remedy=remedy
                )
                if error is None:
                    error = _private_dir_info_error(
                        dir_info, path.parent, what=dir_what, remedy=remedy
                    )
                if error is None and check_ancestors:
                    error = _ancestor_error(path.parent, dir_what=dir_what, remedy=remedy)
                if error is not None:
                    return None, error
            if info.st_size > MAX_TRUST_ROOT_BYTES:
                return None, f"{what} {path} exceeds the {MAX_TRUST_ROOT_BYTES}-byte limit"
            content = stream.read(MAX_TRUST_ROOT_BYTES + 1)
            if len(content) > MAX_TRUST_ROOT_BYTES:
                return None, f"{what} {path} exceeds the {MAX_TRUST_ROOT_BYTES}-byte limit"
            return content, None
    except OSError:
        return None, f"{what} {path} cannot be inspected"
    finally:
        os.close(dir_fd)


def _trusted_root_from_bytes(content: bytes) -> TrustedRoot:
    """Build a sigstore TrustedRoot from bytes already read, as ``from_file`` does by path."""
    from sigstore.models import TrustedRoot
    from sigstore_models.trustroot import v1 as trustroot_v1

    return TrustedRoot(trustroot_v1.TrustedRoot.from_json(content))


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


def _carries_dsse_envelope(bundle_json: bytes) -> bool:
    from nexus_symbiote.core.hashing import MAX_JSON_NESTING, json_nesting_exceeds

    try:
        decoded = bundle_json.decode("utf-8")
        if json_nesting_exceeds(decoded, MAX_JSON_NESTING):
            return False
        document = json.loads(decoded)
    except (ValueError, RecursionError):
        return False
    return isinstance(document, dict) and (
        "dsseEnvelope" in document or "dsse_envelope" in document
    )


OMS_PREDICATE_TYPES = frozenset(
    {
        "https://model_signing/signature/v1.0",
        "https://github.com/ossf/model-signing/signature/v1.0",
        "https://openssf.org/model-signing/signature/v1.0",
    }
)


def _extract_rekor_checkpoint_details(bundle: Any) -> tuple[dict[str, Any], str | None]:
    """Validate and extract Rekor inclusion-proof checkpoint fields from a verified Sigstore bundle.

    sigstore-python verifies the checkpoint signature and Merkle inclusion proof,
    but does not bind ``inclusion_proof.tree_size`` or ``inclusion_proof.log_index``
    to the signed checkpoint note's decimal tree size line. Enforcing exact agreement
    between the signed note (tree size and root hash) and the inclusion proof fields
    prevents bit-shifted ``logIndex`` / ``treeSize`` forgery.
    """
    import base64
    import binascii

    try:
        entry = getattr(bundle, "log_entry", None)
        inner = getattr(entry, "_inner", None)
        proof = getattr(inner, "inclusion_proof", None)
        if proof is None:
            return {}, None
        log_index = getattr(proof, "log_index", None)
        tree_size = getattr(proof, "tree_size", None)
        root_hash = getattr(proof, "root_hash", None)
        checkpoint = getattr(proof, "checkpoint", None)
        envelope = getattr(checkpoint, "envelope", None)
        if (
            type(log_index) is not int
            or type(tree_size) is not int
            or tree_size < 1
            or not isinstance(root_hash, (bytes, bytearray))
            or len(root_hash) != 32
            or not isinstance(envelope, str)
        ):
            return {}, "Rekor inclusion proof is missing required checkpoint fields"
        note_body, sep, sig_block = envelope.partition("\n\n")
        if sep != "\n\n" or not sig_block.strip():
            return {}, "Rekor checkpoint envelope is missing its signature block"
        lines = note_body.split("\n")
        if len(lines) < 3:
            return {}, "Rekor checkpoint note body has fewer than three lines"
        origin = lines[0]
        size_line = lines[1]
        root_b64 = lines[2]
        if (
            not origin.strip()
            or origin != origin.strip()
            or not size_line.isascii()
            or not size_line.isdigit()
            or size_line.startswith("0")
        ):
            return {}, "Rekor checkpoint note header or tree size is malformed"
        signed_tree_size = int(size_line)
        try:
            signed_root = base64.b64decode(root_b64, validate=True)
        except (binascii.Error, ValueError):
            return {}, "Rekor checkpoint note root hash is not valid base64"
        if len(signed_root) != 32 or not hmac.compare_digest(signed_root, bytes(root_hash)):
            return {}, "Rekor checkpoint note root hash does not match inclusion proof root hash"
        if tree_size != signed_tree_size or not (0 <= log_index < signed_tree_size):
            return (
                {},
                "Rekor inclusion proof tree size or log index does not match signed checkpoint",
            )
        return (
            {
                "rekor_log_index": log_index,
                "rekor_tree_size": signed_tree_size,
                "rekor_root_hash": f"sha256:{signed_root.hex()}",
                "rekor_checkpoint_origin": origin,
            },
            None,
        )
    except Exception:
        return {}, "Rekor inclusion proof checkpoint could not be parsed"


def _verify_rekor_witness(
    rekor_details: dict[str, Any],
    *,
    rekor_root_hash: str | None = None,
    minimum_rekor_tree_size: int | None = None,
) -> str | None:
    """Verify the bundle's Rekor checkpoint against an operator-witnessed root hash or minimum tree size."""
    if rekor_root_hash is None and minimum_rekor_tree_size is None:
        return None
    if minimum_rekor_tree_size is not None:
        if type(minimum_rekor_tree_size) is not int or minimum_rekor_tree_size < 1:
            return "Minimum Rekor tree size must be a positive integer"
        actual_size = rekor_details.get("rekor_tree_size")
        if type(actual_size) is not int or actual_size < minimum_rekor_tree_size:
            return "Rekor checkpoint tree size is smaller than the policy minimum"
    if rekor_root_hash is not None:
        if not isinstance(rekor_root_hash, str):
            return "Expected Rekor root hash must be a valid SHA-256 digest"
        try:
            _alg, expected_hex = normalize_digest(rekor_root_hash, "sha256")
        except ValueError:
            return "Expected Rekor root hash must be a valid SHA-256 digest"
        actual_root = rekor_details.get("rekor_root_hash")
        if not isinstance(actual_root, str) or not hmac.compare_digest(
            actual_root, f"sha256:{expected_hex}"
        ):
            return "Rekor checkpoint root hash does not match the witnessed root hash"
    return None


def _clean_oms_resource_name(raw_name: Any) -> str | None:
    from pathlib import PurePosixPath

    if not isinstance(raw_name, str) or not raw_name or len(raw_name) > 1024:
        return None
    if raw_name.startswith("/") or "\\" in raw_name or any(ord(c) < 0x20 for c in raw_name):
        return None
    parts = PurePosixPath(raw_name).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    return "/".join(parts)


def _verify_oms_statement(
    payload_type: str,
    payload_bytes: bytes,
    expected_digest_hex: str,
    *,
    artifact_name: str | None = None,
) -> str | None:
    """Verify an OpenSSF Model Signing v1.0 in-toto statement against a per-file SHA-256.

    In OpenSSF Model Signing v1.0, ``subject[].digest.sha256`` is a manifest root
    digest over serialized per-file digests, NEVER a raw weight file's digest.
    Per-file digests live in ``predicate.resources[]`` and must match both the
    inspected artifact's name and its SHA-256.
    """
    from pathlib import PurePosixPath

    from nexus_symbiote.core.hashing import parse_json_strict

    if payload_type != "application/vnd.in-toto+json":
        return "OpenSSF Model Signing DSSE payloadType must be application/vnd.in-toto+json"
    try:
        statement = parse_json_strict(payload_bytes, max_bytes=MAX_BUNDLE_BYTES)
    except (ValueError, RecursionError):
        return "OpenSSF Model Signing DSSE payload is not valid strict JSON"
    if not isinstance(statement, dict):
        return "OpenSSF Model Signing DSSE statement must be a JSON object"
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        return "OpenSSF Model Signing DSSE statement requires in-toto Statement/v1"
    predicate_type = statement.get("predicateType")
    if not isinstance(predicate_type, str) or predicate_type not in OMS_PREDICATE_TYPES:
        return "Unsupported OpenSSF Model Signing predicateType"
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not 1 <= len(subjects) <= 64:
        return "OpenSSF Model Signing statement requires a bounded nonempty subject list"
    for subject in subjects:
        if not isinstance(subject, dict):
            return "OpenSSF Model Signing subject entry must be an object"
        subj_name = subject.get("name")
        digest_map = subject.get("digest")
        if (
            not isinstance(subj_name, str)
            or not subj_name.strip()
            or not isinstance(digest_map, dict)
            or not isinstance(digest_map.get("sha256"), str)
        ):
            return "OpenSSF Model Signing subject entry requires name and sha256 digest"
        try:
            normalize_digest(digest_map["sha256"], "sha256")
        except ValueError:
            return "OpenSSF Model Signing subject carries a malformed sha256 digest"
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return "OpenSSF Model Signing statement requires a predicate object"
    resources = predicate.get("resources")
    if not isinstance(resources, list) or not 1 <= len(resources) <= 1024:
        return "OpenSSF Model Signing predicate requires a bounded nonempty resources list"
    parsed_resources: list[tuple[str, str]] = []
    seen_names: set[str] = set()
    for resource in resources:
        if not isinstance(resource, dict):
            return "OpenSSF Model Signing resource entry must be an object"
        clean_name = _clean_oms_resource_name(resource.get("name"))
        alg = resource.get("algorithm")
        raw_digest = resource.get("digest")
        if clean_name is None or alg != "sha256" or not isinstance(raw_digest, str):
            return "OpenSSF Model Signing resource entry requires clean name, sha256 algorithm, and digest"
        if clean_name in seen_names:
            return "OpenSSF Model Signing predicate lists duplicate resource names"
        try:
            _alg, res_hex = normalize_digest(raw_digest, "sha256")
        except ValueError:
            return "OpenSSF Model Signing resource carries a malformed sha256 digest"
        seen_names.add(clean_name)
        parsed_resources.append((clean_name, res_hex))

    if artifact_name is not None:
        normalized = artifact_name
        while normalized.startswith("./"):
            normalized = normalized[2:]
        target = _clean_oms_resource_name(normalized)
        if target is None:
            return "Artifact name is invalid for OpenSSF Model Signing resource matching"
        exact = [res_hex for res_name, res_hex in parsed_resources if res_name == target]
        if len(exact) == 1:
            matched_hex = exact[0]
        else:
            target_base = PurePosixPath(target).name
            by_base = [
                res_hex
                for res_name, res_hex in parsed_resources
                if PurePosixPath(res_name).name == target_base
            ]
            if not by_base:
                return "OpenSSF Model Signing manifest does not list the inspected artifact"
            if len(by_base) > 1:
                return "OpenSSF Model Signing manifest has multiple resources with this filename"
            matched_hex = by_base[0]
    else:
        if len(parsed_resources) != 1:
            return "OpenSSF Model Signing multi-resource manifest requires an artifact name"
        matched_hex = parsed_resources[0][1]

    if not hmac.compare_digest(matched_hex, expected_digest_hex):
        return "OpenSSF Model Signing resource digest does not match the inspected artifact digest"
    return None


def verify_sigstore_digest(
    digest_hex: str,
    bundle_json: bytes,
    expected_identity: str,
    expected_issuer: str,
    *,
    trust_root: str | Path | None = None,
    trust_root_sha256: str | None = None,
    allow_oms_dsse: bool = False,
    rekor_root_hash: str | None = None,
    minimum_rekor_tree_size: int | None = None,
    artifact_name: str | None = None,
) -> VerificationResult:
    """Verify a caller-inspected SHA-256 subject without a network refresh.

    The caller must bind this digest to the inspected artifact. By default this
    function verifies a message signature over the artifact digest and refuses a
    DSSE envelope with ``DSSE_UNSUPPORTED``. When ``allow_oms_dsse=True``, it
    verifies an OpenSSF Model Signing DSSE in-toto Statement/v1 bundle binding
    the artifact in ``predicate.resources``.
    """
    if (
        not isinstance(expected_identity, str)
        or not expected_identity.strip()
        or not isinstance(expected_issuer, str)
        or not expected_issuer.strip()
    ):
        return VerificationResult(
            False, error="Expected signer identity and OIDC issuer are both required"
        )
    if type(allow_oms_dsse) is not bool:
        return VerificationResult(False, error="allow_oms_dsse must be a boolean")
    if rekor_root_hash is not None and not isinstance(rekor_root_hash, str):
        return VerificationResult(
            False, error="Expected Rekor root hash must be a valid SHA-256 digest"
        )
    if minimum_rekor_tree_size is not None and (
        type(minimum_rekor_tree_size) is not int or minimum_rekor_tree_size < 1
    ):
        return VerificationResult(False, error="Minimum Rekor tree size must be a positive integer")
    override_path, override_content, override_source, override_error = _read_explicit_trust_root(
        trust_root, trust_root_sha256
    )
    if override_error is not None:
        return VerificationResult(False, error=override_error)
    try:
        _, digest = normalize_digest(digest_hex, "sha256")
        if len(bundle_json) > MAX_BUNDLE_BYTES:
            return VerificationResult(False, error="Sigstore bundle exceeds byte limit")
        from nexus_symbiote.core.hashing import MAX_JSON_NESTING, json_nesting_exceeds

        if json_nesting_exceeds(bundle_json.decode("utf-8"), MAX_JSON_NESTING):
            raise ValueError("bundle JSON nesting limit exceeded")
        is_dsse = _carries_dsse_envelope(bundle_json)
        if is_dsse and not allow_oms_dsse:
            return VerificationResult(False, error=DSSE_UNSUPPORTED)
        if allow_oms_dsse and not is_dsse:
            return VerificationResult(
                False,
                error="OpenSSF Model Signing policy requires a DSSE Sigstore bundle",
            )
        from sigstore.hashes import Hashed
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
        from sigstore_models.common.v1 import HashAlgorithm

        bundle = Bundle.from_json(bundle_json)
        policy = Identity(identity=expected_identity, issuer=expected_issuer)
        if override_path is not None and override_content is not None:
            trust_root_path = override_path
            trust_root_source = override_source or "explicit"
            verifier = Verifier(trusted_root=_trusted_root_from_bytes(override_content))
        else:
            cached_path, cached_content, cache_error = _read_sigstore_cache()
            if cache_error is not None or cached_path is None or cached_content is None:
                return VerificationResult(
                    False,
                    error=cache_error or "Sigstore trust-root cache could not be checked",
                    details={"trust_root_path": None},
                )
            trust_root_path = cached_path
            trust_root_source = "cache"
            verifier = Verifier(trusted_root=_trusted_root_from_bytes(cached_content))
        if allow_oms_dsse:
            payload_type, payload_bytes = verifier.verify_dsse(bundle, policy)
            oms_error = _verify_oms_statement(
                payload_type, payload_bytes, digest, artifact_name=artifact_name
            )
            if oms_error is not None:
                return VerificationResult(False, error=oms_error)
            method = "sigstore-python.verify_dsse"
        else:
            verifier.verify_artifact(
                Hashed(algorithm=HashAlgorithm.SHA2_256, digest=bytes.fromhex(digest)),
                bundle,
                policy,
            )
            method = "sigstore-python.verify_artifact"
        rekor_details, checkpoint_error = _extract_rekor_checkpoint_details(bundle)
        if checkpoint_error is not None:
            return VerificationResult(False, error=checkpoint_error)
        witness_error = _verify_rekor_witness(
            rekor_details,
            rekor_root_hash=rekor_root_hash,
            minimum_rekor_tree_size=minimum_rekor_tree_size,
        )
        if witness_error is not None:
            return VerificationResult(False, error=witness_error)
        return VerificationResult(
            True,
            identity=expected_identity,
            issuer=expected_issuer,
            details={
                "artifact_digest": f"sha256:{digest}",
                "bundle_digest": f"sha256:{hashlib.sha256(bundle_json).hexdigest()}",
                "method": method,
                "trust_root_path": str(trust_root_path),
                "trust_root_source": trust_root_source,
                **rekor_details,
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
    *,
    trust_root: str | Path | None = None,
    trust_root_sha256: str | None = None,
    allow_oms_dsse: bool = False,
    rekor_root_hash: str | None = None,
    minimum_rekor_tree_size: int | None = None,
    artifact_name: str | None = None,
) -> VerificationResult:
    """Verify an exact local artifact under an explicitly selected signer policy."""
    if (
        not isinstance(expected_identity, str)
        or not expected_identity.strip()
        or not isinstance(expected_issuer, str)
        or not expected_issuer.strip()
    ):
        return VerificationResult(
            False, error="Expected signer identity and OIDC issuer are both required"
        )
    if type(allow_oms_dsse) is not bool:
        return VerificationResult(False, error="allow_oms_dsse must be a boolean")
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
        extra_kwargs: dict[str, Any] = {}
        if allow_oms_dsse or rekor_root_hash is not None or minimum_rekor_tree_size is not None:
            resolved_name = artifact_name
            if allow_oms_dsse and resolved_name is None:
                artifact_p = Path(artifact_path)
                bundle_dir = Path(bundle_path).parent
                try:
                    resolved_name = (
                        artifact_p.resolve().relative_to(bundle_dir.resolve()).as_posix()
                    )
                except (OSError, ValueError):
                    resolved_name = (
                        artifact_p.as_posix()
                        if not artifact_p.is_absolute() and ".." not in artifact_p.parts
                        else artifact_p.name
                    )
            extra_kwargs = {
                "allow_oms_dsse": allow_oms_dsse,
                "rekor_root_hash": rekor_root_hash,
                "minimum_rekor_tree_size": minimum_rekor_tree_size,
                **({"artifact_name": resolved_name} if allow_oms_dsse else {}),
            }
        return verify_sigstore_digest(
            digest,
            bundle_bytes,
            expected_identity,
            expected_issuer,
            trust_root=trust_root,
            trust_root_sha256=trust_root_sha256,
            **extra_kwargs,
        )
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
