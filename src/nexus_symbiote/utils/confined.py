"""Bounded local collection with descriptor-relative, no-symlink reads.

This is an offline collector boundary, not a process sandbox. It requires POSIX
``dir_fd`` and ``O_NOFOLLOW`` support and fails closed where unavailable.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, cast

from nexus_symbiote.core.hashing import file_invariance

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_DEPTH = 32
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_HASH_BYTES = 5 * 1024 * 1024 * 1024
DEFAULT_EXCLUDES = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})


class CollectionError(ValueError):
    """A collection input exceeded the supported safe boundary."""


def hash_confined_file(root: Path, source_path: str | Path, algorithm: str = "sha256") -> str:
    """Compatibility hash API for a BOM-supplied path beneath a caller root."""
    if algorithm not in {"sha256", "sha384", "sha512"}:
        raise OSError("unsupported security hash algorithm")
    try:
        with (
            ConfinedCollection(root, [], max_total_bytes=MAX_HASH_BYTES) as files,
            files.open_regular(source_path, max_bytes=MAX_HASH_BYTES) as stream,
        ):
            digest = hashlib.new(algorithm)
            while chunk := stream.read(65536):
                digest.update(chunk)
            return f"{algorithm}:{digest.hexdigest()}"
    except (CollectionError, ValueError) as exc:
        raise OSError("confined artifact hash refused") from exc


class _BoundedReader(io.RawIOBase):
    """Explicit-size reads only; enforce both stream and collection budgets."""

    def __init__(self, fd: int, owner: ConfinedCollection, path: Path, limit: int) -> None:
        self._fd = fd
        self._owner = owner
        self._path = path
        self._limit = limit
        self._read = 0

    def readable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._fd

    def read(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("read of closed collection stream")
        if not 0 <= size <= MAX_FILE_BYTES:
            raise CollectionError("explicit bounded read size required")
        raw = os.read(self._fd, min(size, self._limit + 1 - self._read))
        self._read += len(raw)
        self._owner._bytes_read += len(raw)
        if self._read > self._limit or self._owner._bytes_read > self._owner.max_total_bytes:
            self._owner._fail(self._path, "stream byte limit exceeded")
            raise CollectionError("stream byte limit exceeded")
        return raw

    def close(self) -> None:
        if not self.closed:
            os.close(self._fd)
        super().close()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionError("duplicate JSON key")
        result[key] = value
    return result


class ConfinedCollection:
    """Read regular files beneath a pinned root without following symlinks.

    Limits cover individual file bytes, directory entries over the complete walk,
    and directory depth. A directory exceeding the entry budget is not partially
    returned. Within those bounds traversal is lexical and deterministic.
    """

    def __init__(
        self,
        root: Path,
        failures: list[str],
        exclusions: list[str] | None = None,
        *,
        exclude_paths: Iterable[str | Path] = (),
        max_file_bytes: int = MAX_FILE_BYTES,
        max_entries: int = MAX_ENTRIES,
        max_depth: int = MAX_DEPTH,
        max_total_bytes: int = MAX_TOTAL_BYTES,
    ) -> None:
        self.root = Path(os.path.abspath(root))
        self.failures = failures
        self.exclusions = exclusions if exclusions is not None else []
        self.max_file_bytes = max_file_bytes
        self.max_entries = max_entries
        self.max_depth = max_depth
        self.max_total_bytes = max_total_bytes
        self._bytes_read = 0
        self._entry_budget = [max_entries]
        self._root_fd: int | None = None
        self._excluded: list[Path] = []
        self._invalid_policy = False
        for value in exclude_paths:
            path = Path(value)
            candidate = path if path.is_absolute() else self.root / path
            candidate = Path(os.path.abspath(candidate))
            try:
                candidate.relative_to(self.root)
            except ValueError:
                self._fail(".", "excluded path is outside collection root")
                self._invalid_policy = True
                continue
            self._excluded.append(candidate)

    def __enter__(self) -> ConfinedCollection:
        if self._invalid_policy:
            return self
        if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
            self._fail(".", "no-follow descriptor-relative collection unsupported")
            return self
        current: int | None = None
        try:
            current = os.open(self.root.anchor, os.O_RDONLY | os.O_DIRECTORY)
            for part in self.root.parts[1:]:
                next_fd = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current
                )
                os.close(current)
                current = next_fd
            self._root_fd = current
        except OSError:
            if current is not None:
                os.close(current)
            self._fail(".", "root unavailable or contains a symlink")
        return self

    def __exit__(self, *args: object) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def _fail(self, path: str | Path, reason: str) -> None:
        message = f"{path!s}: {reason}"
        if message not in self.failures:
            self.failures.append(message)

    def _relative(self, path: str | Path) -> Path:
        candidate = Path(path)
        if candidate.is_absolute():
            try:
                candidate = candidate.relative_to(self.root)
            except ValueError as exc:
                raise CollectionError("path is outside collection root") from exc
        if ".." in candidate.parts:
            raise CollectionError("parent traversal is not allowed")
        return candidate

    def excluded(self, path: str | Path) -> bool:
        relative = self._relative(path)
        absolute = self.root / relative
        # Dependency caches, virtual environments and Git internals are outside
        # the documented static scope. The BOM records these patterns. Any
        # further omission within that scope is a blocking coverage gap.
        if any(part in DEFAULT_EXCLUDES for part in relative.parts):
            return True
        denied = any(absolute == value or value in absolute.parents for value in self._excluded)
        if denied:
            message = f"{relative}: excluded by collection policy"
            if message not in self.exclusions:
                self.exclusions.append(message)
        return denied

    def _open_parent(self, relative: Path) -> int:
        if self._root_fd is None:
            raise CollectionError("collection root unavailable")
        fd = os.dup(self._root_fd)
        try:
            for part in relative.parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read_bytes(self, path: str | Path, *, missing_ok: bool = False) -> bytes | None:
        relative: Path | str = str(path)
        try:
            relative = self._relative(path)
            if self.excluded(relative):
                return None
            if not relative.parts:
                raise CollectionError("expected a regular file")
            parent = self._open_parent(relative)
            try:
                fd = os.open(
                    relative.name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent,
                )
            finally:
                os.close(parent)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise CollectionError("not a regular file")
                if before.st_size > self.max_file_bytes:
                    raise CollectionError("file byte limit exceeded")
                if before.st_size > self.max_total_bytes - self._bytes_read:
                    raise CollectionError("total byte limit exceeded")
                chunks: list[bytes] = []
                length = 0
                while length <= self.max_file_bytes:
                    chunk = os.read(fd, min(65536, self.max_file_bytes + 1 - length))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    length += len(chunk)
                    self._bytes_read += len(chunk)
                    if self._bytes_read > self.max_total_bytes:
                        raise CollectionError("total byte limit exceeded")
                if length > self.max_file_bytes:
                    raise CollectionError("file byte limit exceeded")
                after = os.fstat(fd)
                if file_invariance(before) != file_invariance(after):
                    raise CollectionError("file changed during collection")
                return b"".join(chunks)
            finally:
                os.close(fd)
        except FileNotFoundError:
            if not missing_ok:
                self._fail(relative, "file unavailable during collection")
        except (OSError, CollectionError):
            # Do not echo exception payloads: malformed input may contain secrets.
            self._fail(relative, "read refused (symlink, nonregular file, limit, or I/O error)")
        return None

    def read_text(self, path: str | Path, *, missing_ok: bool = False) -> str | None:
        raw = self.read_bytes(path, missing_ok=missing_ok)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            self._fail(path, "invalid UTF-8")
            return None

    @contextmanager
    def open_regular(self, path: str | Path, *, max_bytes: int | None = None) -> Iterator[BinaryIO]:
        """Yield a confined regular stream or raise OSError after recording failure.

        ``max_bytes`` bounds the artifact size and bytes read; reads require an
        explicit chunk size (at most four MiB). Collection-wide budget still
        applies. The trusted consumer must not bypass read() with fileno().
        """
        relative = self._relative(path)
        limit = self.max_file_bytes if max_bytes is None else max_bytes
        try:
            if self.excluded(relative) or not relative.parts:
                raise CollectionError("file excluded by policy")
            parent = self._open_parent(relative)
            try:
                fd = os.open(
                    relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
                )
            finally:
                os.close(parent)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                    raise CollectionError("nonregular file or byte limit exceeded")
            except BaseException:
                os.close(fd)
                raise
        except (OSError, CollectionError) as exc:
            self._fail(relative, "stream refused (symlink, nonregular file, limit, or I/O error)")
            raise OSError("confined stream unavailable") from exc
        stream = _BoundedReader(fd, self, relative, limit)
        try:
            yield cast(BinaryIO, stream)
            after = os.fstat(fd)
            if file_invariance(before) != file_invariance(after):
                self._fail(relative, "file changed during collection")
                raise OSError("artifact changed during collection")
        finally:
            stream.close()

    def path_identity(self, path: str | Path) -> tuple[int, int] | None:
        """Device and inode pair a confined pathname currently resolves to.

        The pair is a content handle: unchanged by atime/mtime/ctime updates,
        changed whenever the pathname is renamed, removed, or replaced by any
        other object (including a symlink, whose reported inode is the link
        itself and cannot match a stream opened with O_NOFOLLOW). Compare the
        pair before and after a bounded read to prove the name kept resolving
        to the same object. This is portable across filesystems; the
        invariance tuple checks on an owned descriptor additionally detect
        in-place mutation and link-count drops.

        ``None`` means the pathname is unavailable, excluded by policy, or
        outside the collection boundary. A ``None`` before-to-after pair must
        be treated as inspection failure, never as a match.
        """
        try:
            relative = self._relative(path)
            if self.excluded(relative) or not relative.parts:
                return None
            parent = self._open_parent(relative)
            try:
                info = os.stat(
                    relative.name,
                    dir_fd=parent,
                    follow_symlinks=False,
                )
            finally:
                os.close(parent)
        except (OSError, CollectionError):
            return None
        return (info.st_dev, info.st_ino)

    def hash_file(self, path: str | Path, *, max_bytes: int | None = None) -> str | None:
        """Stream SHA-256 beneath the root, with explicit individual/total bounds.

        Model collectors can choose a larger per-file limit while retaining the
        collection-wide byte budget. No artifact is deserialized or imported.
        """
        relative: Path | str = str(path)
        try:
            relative = self._relative(path)
            if self.excluded(relative):
                return None
            parent = self._open_parent(relative)
            try:
                fd = os.open(
                    relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
                )
            finally:
                os.close(parent)
            try:
                before = os.fstat(fd)
                limit = self.max_file_bytes if max_bytes is None else max_bytes
                if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                    raise CollectionError("nonregular file or byte limit exceeded")
                if before.st_size > self.max_total_bytes - self._bytes_read:
                    raise CollectionError("total byte limit exceeded")
                digest = hashlib.sha256()
                length = 0
                while length <= limit:
                    chunk = os.read(fd, min(65536, limit + 1 - length))
                    if not chunk:
                        break
                    length += len(chunk)
                    self._bytes_read += len(chunk)
                    if length > limit or self._bytes_read > self.max_total_bytes:
                        raise CollectionError("byte limit exceeded")
                    digest.update(chunk)
                after = os.fstat(fd)
                if file_invariance(before) != file_invariance(after):
                    raise CollectionError("file changed during collection")
                return "sha256:" + digest.hexdigest()
            finally:
                os.close(fd)
        except (OSError, CollectionError):
            self._fail(relative, "hash refused (symlink, nonregular file, limit, or I/O error)")
            return None

    def read_json(self, path: str | Path, *, missing_ok: bool = False) -> Any:
        content = self.read_text(path, missing_ok=missing_ok)
        if content is None:
            return None
        try:
            value = json.loads(
                content,
                object_pairs_hook=_unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(CollectionError("nonfinite JSON")),
            )
            if value is None:
                raise CollectionError("null configuration")
            return value
        except (ValueError, RecursionError):
            self._fail(path, "invalid JSON or duplicate keys")
            return None

    def iter_files(self, directory: str | Path = ".") -> Iterator[Path]:
        """Yield root-relative file paths, never following directory symlinks."""
        try:
            relative = self._relative(directory)
        except CollectionError:
            self._fail(directory, "directory is outside collection root")
            return
        if self.excluded(relative) or self._root_fd is None:
            return
        fd = os.dup(self._root_fd)
        try:
            for part in relative.parts:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            yield from self._walk(fd, relative, 0, self._entry_budget)
        except FileNotFoundError:
            return
        except OSError:
            self._fail(relative, "directory unavailable or contains a symlink")
        finally:
            os.close(fd)

    def _walk(
        self, directory_fd: int, relative: Path, depth: int, budget: list[int]
    ) -> Iterator[Path]:
        if depth > self.max_depth:
            self._fail(relative, "directory depth limit exceeded")
            return
        entries: list[str] = []
        try:
            with os.scandir(directory_fd) as stream:
                for entry in stream:
                    if len(entries) >= budget[0]:
                        self._fail(relative, "directory entry limit exceeded")
                        budget[0] = 0
                        return
                    entries.append(entry.name)
            budget[0] -= len(entries)
            for name in sorted(entries):
                child = relative / name
                if self.excluded(child):
                    continue
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    self._fail(child, "symlink excluded")
                elif stat.S_ISDIR(metadata.st_mode):
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                    try:
                        yield from self._walk(child_fd, child, depth + 1, budget)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(metadata.st_mode):
                    yield child
                else:
                    self._fail(child, "nonregular file excluded")
        except OSError:
            self._fail(relative, "directory changed or could not be read")
