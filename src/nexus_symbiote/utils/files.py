"""Descriptor-based I/O for files in an explicitly selected directory."""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
import sys
from collections.abc import Iterator
from pathlib import Path

from nexus_symbiote.core.hashing import open_directory_nofollow


class OutputRefusedError(OSError):
    """The destination is one the output rules never replace."""


def _relative(root: Path, path: Path, *, allow_parent: bool = False) -> Path:
    relative = path.relative_to(root) if path.is_absolute() else path
    if (
        not relative.parts
        or relative.anchor
        or relative.name in ("", "..")
        or (".." in relative.parts and not allow_parent)
    ):
        raise ValueError("Expected a file beneath the selected directory")
    return relative


@contextlib.contextmanager
def _parent(root: Path, relative: Path, create_parents: bool) -> Iterator[int]:
    cloexec = getattr(os, "O_CLOEXEC", 0)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec
    o_path = getattr(os, "O_PATH", 0)
    path_flags = (o_path | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec) if o_path else 0
    parent: int | None = open_directory_nofollow(root)
    prefix = root
    dir_parts = relative.parts[:-1]
    try:
        for index, part in enumerate(dir_parts):
            is_last = index == len(dir_parts) - 1
            if (
                index == 0
                and root == Path(root.anchor)
                and sys.platform == "darwin"
                and part in {"var", "tmp", "etc"}
                and os.path.islink(f"/{part}")
                and os.readlink(f"/{part}") == f"private/{part}"
            ):
                assert parent is not None
                priv = os.open("private", flags, dir_fd=parent)
                os.close(parent)
                parent = priv
                prefix = prefix / "private"
            prefix = prefix / part
            if parent is not None:
                try:
                    # ".." of a directory opened without following links is its real
                    # parent, so this reaches exactly what the kernel resolves.
                    child = os.open(part, flags, dir_fd=parent)
                except PermissionError:
                    if path_flags:
                        child = os.open(part, path_flags, dir_fd=parent)
                    elif is_last:
                        raise
                    else:
                        os.close(parent)
                        parent = None
                        if not stat.S_ISDIR(os.lstat(prefix).st_mode):
                            raise OSError(errno.ENOTDIR, f"Not a directory: {prefix}") from None
                        continue
                except FileNotFoundError:
                    if not create_parents:
                        raise
                    os.mkdir(part, mode=0o700, dir_fd=parent)
                    child = os.open(part, flags, dir_fd=parent)
                os.close(parent)
                parent = child
                continue
            try:
                parent = os.open(prefix, flags)
            except FileNotFoundError:
                if not create_parents:
                    raise
                os.mkdir(prefix, mode=0o700)
                parent = os.open(prefix, flags)
            except PermissionError:
                if is_last or not stat.S_ISDIR(os.lstat(prefix).st_mode):
                    raise
        assert parent is not None
        yield parent
    finally:
        if parent is not None:
            os.close(parent)


def create_staging_file(path: Path, prefix: str) -> Path:
    """Create an empty private file beside an explicitly selected output, by its path.

    The directory is reached as ``write_output_file`` reaches it, without following a
    link, so a linked directory is refused before anything is created in its target.
    """
    path = path.absolute()
    root = Path(path.anchor)
    relative = _relative(root, path, allow_parent=True)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("Secure output requires descriptor-relative no-symlink file operations")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    with _parent(root, relative, create_parents=False) as parent:
        name = f"{prefix}{secrets.token_hex(16)}.tmp"
        os.close(os.open(name, flags, 0o600, dir_fd=parent))
    return path.parent / name


def write_output_file(
    path: Path,
    data: str,
    *,
    root: Path | None = None,
    create_parents: bool = False,
    overwrite: bool = True,
) -> None:
    """Replace the destination atomically without writing through an existing link."""
    if root is None:
        # An explicitly selected output may lie anywhere, but never traverse a link.
        path = path.absolute()
        root = Path(path.anchor)
        relative = _relative(root, path, allow_parent=True)
    else:
        relative = _relative(root, path)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("Secure output requires descriptor-relative no-symlink file operations")
    with _parent(root, relative, create_parents) as parent:
        # A link is replaced, never followed, but a device, FIFO, socket or directory,
        # named directly or through that link, is never replaced by a report.
        for follow in (False, True):
            try:
                mode = os.stat(relative.name, dir_fd=parent, follow_symlinks=follow).st_mode
            except FileNotFoundError:
                break
            except OSError:
                if follow:
                    # A link whose target cannot be reached is itself replaced.
                    break
                raise
            if not (stat.S_ISREG(mode) or (stat.S_ISLNK(mode) and not follow)):
                raise OutputRefusedError(errno.EINVAL, "output must be a regular file")
        temp = f".nexus-symbiote-{secrets.token_hex(16)}.tmp"
        open_flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(temp, open_flags, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if overwrite:
                os.replace(temp, relative.name, src_dir_fd=parent, dst_dir_fd=parent)
            else:
                try:
                    os.link(
                        temp,
                        relative.name,
                        src_dir_fd=parent,
                        dst_dir_fd=parent,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    if exc.errno not in {
                        errno.EPERM,
                        errno.EOPNOTSUPP,
                        getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
                    }:
                        raise
                    out_fd = os.open(relative.name, open_flags, 0o600, dir_fd=parent)
                    try:
                        with os.fdopen(out_fd, "w", encoding="utf-8") as direct:
                            direct.write(data)
                            direct.flush()
                            os.fsync(direct.fileno())
                    except BaseException:
                        with contextlib.suppress(OSError):
                            os.unlink(relative.name, dir_fd=parent)
                        raise
        finally:
            # After a rename the name is gone; in a directory that forbids removal
            # (append-only) the temporary file stays. Neither replaces the outcome.
            with contextlib.suppress(OSError):
                os.unlink(temp, dir_fd=parent)
