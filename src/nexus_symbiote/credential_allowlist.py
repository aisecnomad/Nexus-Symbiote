"""Explicit allowlist for vendor-shaped credential findings.

``.nexus-symbiote.yaml`` refuses unknown keys, so this list is its own file at the
scan root: ``.nexus-symbiote-credential-allowlist.yaml``. Absence suppresses
nothing. A broken file suppresses nothing and is a collection failure. Each entry
is one SHA-256 fingerprint or one path glob, and a reason. ``--no-project-policy``
does not load it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nexus_symbiote import limits
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import normalize_credential

ALLOWLIST_NAMES = (
    ".nexus-symbiote-credential-allowlist.yaml",
    ".nexus-symbiote-credential-allowlist.yml",
)
_MAX_ENTRIES = 256
_MAX_BYTES = 64 * 1024
_MAX_REASON = 200
_MAX_PATTERN = 200
_MAX_PATTERN_PARTS = 32
_MAX_PATH_PARTS = 64
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")

_ALLOW: ContextVar[CredentialAllowlist | None] = ContextVar("ns_credential_allowlist", default=None)
_PATH: ContextVar[str] = ContextVar("ns_credential_allowlist_path", default="")


class AllowlistError(ValueError):
    """The allowlist exists and cannot be applied without hiding findings."""


class AllowEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fingerprint: str | None = None
    path: str | None = None
    reason: str = Field(min_length=1, max_length=_MAX_REASON)

    @model_validator(mode="after")
    def one_target(self) -> AllowEntry:
        if (self.fingerprint is None) == (self.path is None):
            raise ValueError("an entry needs a fingerprint or a path, and not both")
        if "\n" in self.reason or "\r" in self.reason:
            raise ValueError("reason must be one line")
        if not self.reason.strip():
            raise ValueError("reason must say why the entry is allowed")
        if self.fingerprint is not None and _FINGERPRINT.fullmatch(self.fingerprint) is None:
            raise ValueError("fingerprint must be 64 lowercase hex digits")
        if self.path is not None:
            _check_glob(self.path)
        return self


class CredentialAllowlist(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    allow: list[AllowEntry] = Field(default_factory=list, max_length=_MAX_ENTRIES)

    def suppresses(self, rel_path: str, digest: str) -> bool:
        for entry in self.allow:
            if entry.fingerprint is not None and entry.fingerprint == digest:
                return True
            if entry.path is not None and path_glob_matches(entry.path, rel_path):
                return True
        return False


def _check_glob(pattern: str) -> None:
    if (
        not pattern
        or len(pattern) > _MAX_PATTERN
        or "\\" in pattern
        or pattern.startswith("/")
        or "\x00" in pattern
    ):
        raise ValueError("path glob must be a relative pattern")
    parts = pattern.split("/")
    if len(parts) > _MAX_PATTERN_PARTS or any(part == ".." or part == "" for part in parts):
        raise ValueError("path glob must be a relative pattern")
    if set(pattern) <= set("*?/"):
        # Only wildcards: the entry would silence the detector for every file it reaches.
        raise ValueError("path glob must name a file or directory")


def path_glob_matches(pattern: str, path: str) -> bool:
    """Whether a bounded ``*`` / ``**`` glob matches a relative POSIX path."""
    pat = pattern.split("/")
    segs = PurePosixPath(path).as_posix().split("/")
    if len(pat) > _MAX_PATTERN_PARTS or len(segs) > _MAX_PATH_PARTS:
        return False
    width = len(segs) + 1
    matched = [False] * width
    matched[0] = True
    for part in pat:
        nxt = [False] * width
        if part == "**":
            seen = False
            for index, flag in enumerate(matched):
                seen = seen or flag
                nxt[index] = seen
        else:
            # fnmatch bounds wildcard backtracking. Only * and ? are special here.
            pattern = part.replace("[", "[[]")
            for index, flag in enumerate(matched[:-1]):
                if flag and fnmatchcase(segs[index], pattern):
                    nxt[index + 1] = True
        matched = nxt
    return matched[-1]


def load_credential_allowlist(
    root: Path,
    *,
    exclude_paths: Iterable[str | Path] = (),
) -> tuple[CredentialAllowlist, str | None]:
    """Read the allowlist. A missing file suppresses nothing and is not a failure."""
    failures: list[str] = []
    raw = None
    try:
        with ConfinedCollection(
            root,
            failures,
            [],
            exclude_paths=exclude_paths,
            max_file_bytes=min(_MAX_BYTES, limits.current().file_bytes),
        ) as files:
            if any(files.case_variants(name) for name in ALLOWLIST_NAMES):
                return CredentialAllowlist(), (
                    "credential allowlist: unexpected filename case; nothing is suppressed"
                )
            present = [name for name in ALLOWLIST_NAMES if files.entry_exists(name)]
            if len(present) > 1:
                return CredentialAllowlist(), (
                    "credential allowlist: both .yaml and .yml are present; nothing is suppressed"
                )
            if present:
                raw = files.read_bytes(
                    present[0], missing_ok=True, report_coexisting_variants=False
                )
            elif not failures:
                return CredentialAllowlist(), None
    except (OSError, ValueError):
        # A failed close also invalidates bytes returned by a successful read.
        raw = None
    if failures:
        return CredentialAllowlist(), f"credential allowlist: {failures[0]}"
    if raw is None:
        return (
            CredentialAllowlist(),
            "credential allowlist: file could not be read; nothing is suppressed",
        )
    try:
        text = raw.decode("utf-8")
        parsed: Any = parse_yaml_mapping(text, max_nodes=4096)
        loaded = CredentialAllowlist.model_validate(parsed)
    except (PolicyError, UnicodeDecodeError, ValueError):
        return CredentialAllowlist(), (
            "credential allowlist: file is not a valid allowlist; nothing is suppressed"
        )
    return loaded, None


@contextmanager
def bind_credential_allowlist(allowlist: CredentialAllowlist | None) -> Iterator[None]:
    token = _ALLOW.set(allowlist)
    try:
        yield
    finally:
        _ALLOW.reset(token)


@contextmanager
def bind_credential_path(path: str) -> Iterator[None]:
    token = _PATH.set(path)
    try:
        yield
    finally:
        _PATH.reset(token)


def credential_suppressed(literal: str, *, rel_path: str | None = None) -> bool:
    """Whether the active allowlist names this token or the file that holds it."""
    allow = _ALLOW.get()
    if allow is None or not allow.allow:
        return False
    digest = hashlib.sha256(normalize_credential(literal).encode("utf-8")).hexdigest()
    return allow.suppresses(_PATH.get() if rel_path is None else rel_path, digest)
