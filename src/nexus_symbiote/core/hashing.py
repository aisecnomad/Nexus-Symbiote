"""Canonical hashing for AgentBOM components.

Implements RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic
hashing of tool definitions, prompt templates, and other mutable artifacts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from contextvars import ContextVar
from pathlib import Path
from typing import Any, BinaryIO, Literal, TypedDict

import rfc8785
from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version


def canonical_json(data: Any) -> str:
    """Serialize strict I-JSON with RFC 8785, rejecting ambiguous inputs.

    Nonfinite numbers, out-of-range integers, lone surrogates and unsupported
    Python values fail instead of being coerced into a different JSON value.
    """
    return rfc8785.dumps(data).decode("utf-8")


_BOM_PREFIXES = (
    b"\xef\xbb\xbf",
    b"\xff\xfe\x00\x00",
    b"\x00\x00\xfe\xff",
    b"\xff\xfe",
    b"\xfe\xff",
)


MAX_JSON_NESTING = 850


def json_nesting_exceeds(text: str, limit: int = MAX_JSON_NESTING) -> bool:
    """Return whether JSON container nesting exceeds ``limit`` without recursing."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > limit:
                return True
        elif char in "}]" and depth > 0:
            depth -= 1
    return False


def parse_json_strict(text: str | bytes, *, max_bytes: int = 4 * 1024 * 1024) -> Any:
    """Parse bounded UTF-8 I-JSON, rejecting BOMs, duplicate keys and invalid numbers."""
    if isinstance(text, bytes):
        if len(text) > max_bytes:
            raise ValueError("JSON exceeds the configured byte limit")
        if text.startswith(_BOM_PREFIXES):
            raise ValueError("Byte-order marks are not permitted in strict I-JSON")
        decoded = text.decode("utf-8")
    elif isinstance(text, str):
        if text.startswith("\ufeff"):
            raise ValueError("Byte-order marks are not permitted in strict I-JSON")
        if len(text.encode("utf-8")) > max_bytes:
            raise ValueError("JSON exceeds the configured byte limit")
        decoded = text
    else:
        raise TypeError("JSON input must be str or bytes")

    if json_nesting_exceeds(decoded, MAX_JSON_NESTING):
        raise RecursionError("JSON nesting exceeds the configured depth limit")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON object key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"Nonfinite JSON number: {value}")

    result = json.loads(decoded, object_pairs_hook=object_pairs, parse_constant=reject_constant)
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


gate_input_files: ContextVar[set[tuple[int, int]] | None] = ContextVar(
    "gate_input_files", default=None
)


def stat_input_file(fd: int) -> os.stat_result:
    """Remember the opened input's identity while a gate is preparing an output."""
    info = os.fstat(fd)
    inputs = gate_input_files.get()
    if inputs is not None and stat.S_ISREG(info.st_mode):
        inputs.add((info.st_dev, info.st_ino))
    return info


def descriptor_binding(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return the open-descriptor evidence that must stay fixed across one observation.

    Size and mtime alone cannot detect a rename-over: when the replacement
    lands within the same coarse-grained kernel timestamp tick, the unlinked
    inode's mtime equals its previous value. The link count of the inode behind
    the descriptor drops to zero on unlink, so it is compared as well, together
    with the device and inode identity. A replaced inode that is never unlinked,
    such as a file in an overlayfs lower layer, keeps all of these values; only
    the pathname's current identity (``pathname_identity``) reveals that swap.

    Ctime also detects in-place, same-length writes followed by restoring mtime.
    A ctime-only difference cannot establish that a change was harmless metadata:
    invalidate cached digests and refuse a changed observation. A later stable
    observation can succeed, but must read and charge its bytes again.
    """
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _unnormalized_absolute(path: Path) -> Path:
    # os.path.abspath would collapse "link/.." textually and name a different file
    # than the kernel opens; each ".." is walked instead, through the real parent.
    return path if path.is_absolute() else Path.cwd() / path


def open_directory_nofollow(directory: Path) -> int:
    """Open a directory without following symlinks in the target path.

    Walks from the filesystem anchor using ``O_NOFOLLOW`` descriptors, allowing
    traverse-only (execute-without-read) system ancestor directories after
    verifying via ``lstat`` that each ancestor is a real directory (or a
    standard macOS root firmlink/symlink to ``/private/{var,tmp,etc}``). A ``..``
    component is opened through the real parent, as the kernel resolves it, so
    ``link/..`` fails closed instead of naming the directory that holds the link.
    """
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise OSError("Descriptor-relative no-follow file access is unavailable")
    absolute = _unnormalized_absolute(Path(directory))
    parts = list(absolute.parts)
    if (
        sys.platform == "darwin"
        and len(parts) >= 2
        and parts[0] == "/"
        and parts[1] in {"var", "tmp", "etc"}
    ):
        link_path = f"/{parts[1]}"
        if os.path.islink(link_path) and os.readlink(link_path) == f"private/{parts[1]}":
            parts = ["/", "private", *parts[1:]]

    cloexec = getattr(os, "O_CLOEXEC", 0)
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec
    o_path = getattr(os, "O_PATH", 0)
    path_flags = (o_path | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec) if o_path else 0
    current_fd: int | None = None
    prefix = Path(parts[0])
    try:
        for index, part in enumerate(parts):
            if index > 0:
                prefix = prefix / part
            is_last = index == len(parts) - 1
            if current_fd is not None:
                try:
                    next_fd = os.open(part, dir_flags, dir_fd=current_fd)
                    os.close(current_fd)
                    current_fd = next_fd
                    continue
                except PermissionError:
                    if is_last:
                        raise
                    if path_flags:
                        try:
                            next_fd = os.open(part, path_flags, dir_fd=current_fd)
                            os.close(current_fd)
                            current_fd = next_fd
                            continue
                        except PermissionError:
                            # Expected when O_PATH open is also denied; fall back to validated lstat below.
                            pass
                    os.close(current_fd)
                    current_fd = None
                    st = os.lstat(prefix)
                    if not stat.S_ISDIR(st.st_mode):
                        raise OSError(f"Not a directory: {prefix}") from None
                    continue

            st = os.lstat(prefix)
            if not stat.S_ISDIR(st.st_mode):
                raise OSError(f"Not a directory: {prefix}")
            try:
                fd = os.open(prefix, dir_flags)
            except PermissionError:
                if is_last:
                    raise
                if not path_flags:
                    continue
                try:
                    fd = os.open(prefix, path_flags)
                except PermissionError:
                    continue
            try:
                opened_st = os.fstat(fd)
                if not stat.S_ISDIR(opened_st.st_mode) or (
                    opened_st.st_dev,
                    opened_st.st_ino,
                ) != (st.st_dev, st.st_ino):
                    raise OSError(f"Directory changed during open: {prefix}")
            except BaseException:
                os.close(fd)
                raise
            current_fd = fd

        if current_fd is None:
            raise OSError(f"Unable to open directory: {directory}")
        return current_fd
    except BaseException:
        if current_fd is not None:
            os.close(current_fd)
        raise


def _open_parent_no_follow(absolute: Path) -> int:
    return open_directory_nofollow(absolute.parent)


def pathname_identity(path: Path) -> tuple[int, int] | None:
    """Return the device and inode that ``path`` resolves to now, or ``None``.

    Resolution matches ``open_regular_file``: no symlink is followed in any
    component. Compare the result with the open descriptor's identity after a
    read to prove the pathname still names the bytes that were read.
    """
    absolute = _unnormalized_absolute(Path(path))
    try:
        parent_fd = _open_parent_no_follow(absolute)
        try:
            info = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(parent_fd)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return (info.st_dev, info.st_ino)


def open_regular_file(path: Path) -> BinaryIO:
    """Open a regular file without following any symlink or blocking on a FIFO.

    Descriptor-relative traversal also protects the parent path from symlink
    replacement between a check and the final open. Fail closed on platforms
    without the required no-follow APIs.
    """
    absolute = _unnormalized_absolute(Path(path))
    parent_fd = _open_parent_no_follow(absolute)
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(absolute.name, flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        if not stat.S_ISREG(stat_input_file(fd).st_mode):
            raise OSError("Artifact is not a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _require_secure_algorithm(algorithm: str) -> str:
    normalized = algorithm.lower()
    if normalized not in SECURE_HASH_ALGORITHMS:
        raise ValueError(f"Unsupported security hash algorithm: {algorithm}")
    return normalized


def hash_canonical(data: dict[str, Any], algorithm: str = "sha256") -> str:
    """Hash a dict using JCS canonicalization and the specified algorithm."""
    algorithm = _require_secure_algorithm(algorithm)
    canon = canonical_json(data)
    h = hashlib.new(algorithm)
    h.update(canon.encode("utf-8"))
    return f"{algorithm}:{h.hexdigest()}"


class ToolDefinitionExtensions(TypedDict):
    title: str | None
    output_schema: dict[str, Any] | None
    meta: dict[str, Any] | None


def tool_definition_extensions(descriptor: Mapping[str, Any]) -> ToolDefinitionExtensions:
    """Read the optional MCP descriptor members that ``hash_tool_definition`` binds."""
    title, output_schema, meta = (descriptor.get(key) for key in ("title", "outputSchema", "_meta"))
    if (
        (title is not None and not isinstance(title, str))
        or (output_schema is not None and not isinstance(output_schema, dict))
        or (meta is not None and not isinstance(meta, dict))
    ):
        raise ValueError("invalid tool fields")
    return {"title": title, "output_schema": output_schema, "meta": meta}


def hash_tool_definition(
    name: str,
    description: str,
    input_schema: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
    *,
    title: str | None = None,
    output_schema: dict[str, Any] | None = None,
    meta: dict[str, Any] | None = None,
) -> str:
    """Hash v2 model-visible metadata, normalizing omitted annotations to {}.

    ``title``, ``outputSchema`` and ``_meta`` enter the definition only when they
    are not None, so a definition without them keeps the digest it always had.
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
    if title is not None:
        definition["title"] = title
    if output_schema is not None:
        definition["outputSchema"] = output_schema
    if meta is not None:
        definition["_meta"] = meta
    return hash_canonical(definition)


def hash_file(path: Path, algorithm: str = "sha256") -> str | None:
    """Hash a regular file's contents, read without following a symbolic link.

    Returns None when ``path``, or a directory on the way to it, does not exist. Any
    other failure raises ``OSError``, including a symbolic link, whatever it points to,
    and anything that is not a regular file.
    """
    algorithm = _require_secure_algorithm(algorithm)
    h = hashlib.new(algorithm)
    try:
        stream = open_regular_file(path)
    except FileNotFoundError:
        return None
    with stream as f:
        before = os.fstat(f.fileno())
        while chunk := f.read(8192):
            h.update(chunk)
        after = os.fstat(f.fileno())
        if descriptor_binding(before) != descriptor_binding(after) or pathname_identity(path) != (
            after.st_dev,
            after.st_ino,
        ):
            raise OSError("File changed during hashing")
    return f"{algorithm}:{h.hexdigest()}"


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Hash raw bytes."""
    algorithm = _require_secure_algorithm(algorithm)
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
_OCI_TAG_CHARS = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
_OCI_DIGEST = re.compile(rf"{_OCI_NAME}(?::{_OCI_TAG_CHARS})?@sha256:([0-9a-fA-F]{{64}})")
_OCI_COLON_DIGEST = re.compile(rf"{_OCI_NAME}:sha256:([0-9a-fA-F]{{64}})")
_OCI_TAG = re.compile(rf"{_OCI_NAME}:({_OCI_TAG_CHARS})")


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
    immutable = _OCI_DIGEST.fullmatch(reference) or _OCI_COLON_DIGEST.fullmatch(reference)
    if immutable:
        return "sha256:" + immutable.group(1).lower()
    tagged = _OCI_TAG.fullmatch(reference)
    if tagged is None:
        return None
    version = tagged.group(1)
    if _SEMVER.fullmatch(version):
        return version
    if "." not in version:
        return None
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
