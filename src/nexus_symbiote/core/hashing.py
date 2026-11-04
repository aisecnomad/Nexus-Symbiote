"""Canonical hashing for AgentBOM components.

Implements RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic
hashing of tool definitions, prompt templates, and other mutable artifacts.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import itertools
import json
import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO, Literal

import rfc8785
from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version


def canonical_json(data: Any) -> str:
    """Serialize strict I-JSON with RFC 8785, rejecting ambiguous inputs.

    Nonfinite numbers, out-of-range integers, lone surrogates and unsupported
    Python values fail instead of being coerced into a different JSON value.
    """
    return rfc8785.dumps(data).decode("utf-8")


SOURCE_BINDING_KEY_ENV = "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY"
_HEX_KEY = re.compile(r"(?:[0-9a-fA-F]{2})+")
# Every BOM exports the key identifier, and a binding over a public card is computed from
# known input, so each lets anyone holding a BOM test key guesses offline. Stretching the
# key makes every guess cost this derivation instead of one HMAC; a guessable key stays
# guessable, only slower.
_KEY_DERIVATION_SALT = b"nexus-symbiote/source-binding-key/v1"
_KEY_DERIVATION_ITERATIONS = 600_000
_KEY_ID_LABEL = b"nexus-symbiote/source-binding-key-id"


class SourceBindingKeyError(ValueError):
    """The operator key is not random key material. The message never contains the key."""


class SourceBindingValueError(ValueError):
    """A declaration contains values that RFC 8785 cannot canonicalize for binding."""


def _evidently_not_random(material: bytes) -> bool:
    """Return whether key bytes are too short, low-diversity, textual or patterned.

    Passing proves nothing about entropy: the hash of a passphrase passes. Together the
    rules reject fewer than one random 32-byte key in a billion.
    """
    if len(material) < 32 or len(set(material)) < 20:
        return True
    try:
        text = material.decode("utf-8")
    except UnicodeDecodeError:
        pass
    else:
        if all(char.isprintable() or char.isspace() for char in text):
            return True  # encoded text, such as a passphrase
    blocks = [material[index : index + 8] for index in range(len(material) - 7)]
    steps = [(after - before) % 256 for before, after in itertools.pairwise(material)]
    # A repeated 8-byte block, or 8 bytes that change by a constant step like a counter.
    return len(set(blocks)) < len(blocks) or any(
        len(set(steps[index : index + 7])) == 1 for index in range(len(steps) - 6)
    )


def source_binding_key() -> bytes | None:
    """Return the decoded operator key, or ``None`` when values are not bound.

    Only hexadecimal keys of at least 32 bytes are accepted, so a passphrase cannot be
    used as typed. The format check rejects encoded text and evident patterns but cannot
    recognize every non-random key, such as a hash of a passphrase.
    """
    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if not key:
        return None
    material = bytes.fromhex(key) if _HEX_KEY.fullmatch(key) else b""
    if _evidently_not_random(material):
        raise SourceBindingKeyError(
            f"{SOURCE_BINDING_KEY_ENV} must be random key material: at least 64 hexadecimal "
            "characters from a random generator; never a passphrase, text or a pattern"
        )
    return material


@functools.lru_cache(maxsize=8)
def _stretched_key(material: bytes) -> bytes:
    """Derive the binding key once per process and key with PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", material, _KEY_DERIVATION_SALT, _KEY_DERIVATION_ITERATIONS)


def bind_source_values(config: dict[str, Any], *, profile: str) -> tuple[str, str] | None:
    """Bind private source values without exporting a digest usable to guess secrets."""
    material = source_binding_key()
    if material is None:
        return None
    try:
        message = canonical_json({"profile": profile, "configuration": config})
    except (TypeError, ValueError, RecursionError):
        raise SourceBindingValueError("declaration cannot be canonicalized for binding") from None
    key = _stretched_key(material)
    mac = hmac.new(key, message.encode("utf-8"), "sha256").hexdigest()
    key_id = hmac.new(key, _KEY_ID_LABEL, "sha256").hexdigest()
    return "hmac-sha256:" + mac, key_id[:32]


def parse_json_strict(
    text: str | bytes,
    *,
    max_bytes: int = 4 * 1024 * 1024,
    check: Callable[[Any], None] | None = None,
) -> Any:
    """Parse bounded I-JSON, rejecting duplicate keys and invalid numbers.

    ``check`` runs on the parsed value before the slower I-JSON check, so a caller
    can refuse a value that is too large for it without paying for that check.
    """
    if len(text if isinstance(text, bytes) else text.encode("utf-8")) > max_bytes:
        raise ValueError("JSON exceeds the configured byte limit")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON object key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"Nonfinite JSON number: {value}")

    result = json.loads(text, object_pairs_hook=object_pairs, parse_constant=reject_constant)
    if check is not None:
        check(result)
    canonical_json(result)
    return result


# v2 normalizes omitted/empty MCP annotations. Older fingerprints require
# collection and approval under the current contract; never silently relabel them.
TOOL_DEFINITION_HASH_VERSION = "rfc8785-jcs-v2"

SECURE_HASH_ALGORITHMS = {"sha256": 64, "sha384": 96, "sha512": 128}


def normalize_digest(expected_hash: str, algorithm: str | None = None) -> tuple[str, str]:
    """Validate a security digest and reconcile its optional algorithm prefix."""
    if ":" in expected_hash:
        prefix, digest = expected_hash.split(":", 1)
        if algorithm is not None and prefix.lower() != algorithm.lower():
            raise ValueError("Digest algorithm prefix disagrees with its field")
        algorithm = prefix.lower()
    else:
        digest = expected_hash
        algorithm = (algorithm or "sha256").lower()
    length = SECURE_HASH_ALGORITHMS.get(algorithm)
    if length is None:
        raise ValueError(f"Unsupported security hash algorithm: {algorithm}")
    if len(digest) != length or re.fullmatch(r"[a-fA-F0-9]+", digest) is None:
        raise ValueError(f"Malformed {algorithm} digest")
    return algorithm, digest.lower()


def descriptor_binding(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return the open-descriptor evidence that must stay fixed across one observation.

    Size, mtime and ctime alone cannot detect a rename-over: when the replacement
    lands within the same coarse-grained kernel timestamp tick, the unlinked
    inode's ctime equals its previous value. The link count of the inode behind
    the descriptor drops to zero on unlink, so it is compared as well, together
    with the device and inode identity. A replaced inode that is never unlinked,
    such as a file in an overlayfs lower layer, keeps all of these values; only
    the pathname's current identity (``pathname_identity``) reveals that swap.
    """
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_parent_no_follow(absolute: Path) -> int:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise OSError("Descriptor-relative no-follow file access is unavailable")
    parent_fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
    except BaseException:
        os.close(parent_fd)
        raise
    return parent_fd


def pathname_identity(path: Path) -> tuple[int, int] | None:
    """Return the device and inode that ``path`` resolves to now, or ``None``.

    Resolution matches ``open_regular_file``: no symlink is followed in any
    component. Compare the result with the open descriptor's identity after a
    read to prove the pathname still names the bytes that were read.
    """
    absolute = Path(os.path.abspath(path))
    try:
        parent_fd = _open_parent_no_follow(absolute)
        try:
            info = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(parent_fd)
    except OSError:
        return None
    return (info.st_dev, info.st_ino)


def open_regular_file(path: Path) -> BinaryIO:
    """Open a regular file without following any symlink or blocking on a FIFO.

    Descriptor-relative traversal also protects the parent path from symlink
    replacement between a check and the final open. Fail closed on platforms
    without the required no-follow APIs.
    """
    absolute = Path(os.path.abspath(path))
    parent_fd = _open_parent_no_follow(absolute)
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(absolute.name, flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("Artifact is not a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def hash_canonical(data: dict[str, Any], algorithm: str = "sha256") -> str:
    """Hash a dict using JCS canonicalization and the specified algorithm."""
    canon = canonical_json(data)
    h = hashlib.new(algorithm)
    h.update(canon.encode("utf-8"))
    return f"{algorithm}:{h.hexdigest()}"


def hash_tool_definition(
    name: str,
    description: str,
    input_schema: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
) -> str:
    """Hash v2 model-visible metadata, normalizing omitted annotations to {}.

    Callers carry TOOL_DEFINITION_HASH_VERSION beside the digest. Comparing to an
    authenticated approved baseline detects metadata drift; this fingerprint does
    not establish publisher identity or constrain a tool's implementation.
    """
    definition: dict[str, Any] = {
        "name": name,
        "description": description,
    }
    if input_schema is not None:
        definition["inputSchema"] = input_schema
    # Missing and empty MCP annotations have the same defined digest contract.
    # A producer and consumer must not disagree because the model fills defaults.
    definition["annotations"] = annotations or {}
    return hash_canonical(definition)


def hash_file(path: Path, algorithm: str = "sha256") -> str | None:
    """Hash a file's contents. Returns None if the file does not exist."""
    if not path.is_file():
        return None
    h = hashlib.new(algorithm)
    with open_regular_file(path) as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return f"{algorithm}:{h.hexdigest()}"


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Hash raw bytes."""
    h = hashlib.new(algorithm)
    h.update(data)
    return f"{algorithm}:{h.hexdigest()}"


_NPM_NAME = r"(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*"
_NUMERIC = r"(?:0|[1-9][0-9]*)"
_PRERELEASE = rf"(?:{_NUMERIC}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_SEMVER = re.compile(
    rf"{_NUMERIC}\.{_NUMERIC}\.{_NUMERIC}"
    rf"(?:-{_PRERELEASE}(?:\.{_PRERELEASE})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_NPM_PIN = re.compile(rf"({_NPM_NAME})@(.+)")
_OCI_NAME = r"(?:[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?/)?[a-z0-9][a-z0-9._/-]*"
_OCI_DIGEST = re.compile(rf"{_OCI_NAME}@sha256:([0-9a-fA-F]{{64}})")
_OCI_TAG = re.compile(rf"{_OCI_NAME}:([A-Za-z0-9_][A-Za-z0-9_.-]{{0,127}})")


def _python_version_pin(reference: str) -> str | None:
    try:
        requirement = Requirement(
            "package" + reference if reference.startswith("==") else reference
        )
    except InvalidRequirement:
        return None
    constraints = list(requirement.specifier)
    if requirement.url or requirement.marker or len(constraints) != 1:
        return None
    constraint = constraints[0]
    if constraint.operator not in {"==", "==="} or "*" in constraint.version:
        return None
    try:
        version = Version(constraint.version)
    except InvalidVersion:
        return None
    if not constraint.contains(version, prereleases=True):
        return None
    return constraint.version


def _oci_version_pin(reference: str) -> str | None:
    immutable = _OCI_DIGEST.fullmatch(reference)
    if immutable:
        return "sha256:" + immutable.group(1).lower()
    tagged = _OCI_TAG.fullmatch(reference)
    if tagged is None:
        return None
    version = tagged.group(1)
    if _SEMVER.fullmatch(version):
        return version
    try:
        Version(version)
    except InvalidVersion:
        return None
    return version


def extract_version_pin(
    reference: str, *, ecosystem: Literal["python", "npm", "oci"] | None = None
) -> str | None:
    """Extract an exact declared version, never artifact authenticity.

    Python requires one finite PEP 440 equality specifier. npm requires a full
    SemVer; OCI accepts a version tag or a complete SHA-256 content digest.
    Mixed constraints, wildcard/range expressions, URLs and markers stay unknown.
    Supplying the launcher's ecosystem prevents ambiguous bare strings from
    being treated as package pins. Bare SemVer remains a compatibility input.
    """
    value = reference.strip()
    if not value or len(value) > 2048 or any(c in value for c in "\r\n\x00"):
        return None
    if ecosystem == "python" or (ecosystem is None and "==" in value):
        return _python_version_pin(value)
    if any(c.isspace() or c in "|,;" for c in value) or "://" in value:
        return None
    if ecosystem in {None, "oci"}:
        version = _oci_version_pin(value)
        if version is not None:
            return version
    if ecosystem in {None, "npm"}:
        package = _NPM_PIN.fullmatch(value)
        if package and _SEMVER.fullmatch(package.group(2)):
            return package.group(2)
    if ecosystem is None and _SEMVER.fullmatch(value):
        return value
    return None
