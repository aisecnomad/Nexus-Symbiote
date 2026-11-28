#!/usr/bin/env python3
"""Materialize the agent BOM regression fixture from ``corpus.json``.

The fixture is a synthetic customer-support agent monorepo with 109 labelled components in
ten categories and ten decoys (see ``ground_truth.json``). It is stored as data and written
out on demand, as AIBOM-Bench is, so the repository tracks no dependency manifest that pins
the deliberately vulnerable packages the fixture plants, and no file a dependency scanner or
an editor would treat as live configuration.

    python benchmarks/agent-bom-fixture/build_fixture.py --out /tmp/agent-bom-fixture

The output directory must not exist, and its parent must be one no one else can change: a
directory the operator owns that only the operator can write to, or a sticky directory
owned by root or the operator, such as ``/tmp``. The
builder opens that parent without following a symbolic link, creates the output under it
with mode 0700, and creates every directory and file relative to descriptors it opened,
without following symbolic links, without replacing an existing entry, and setting each
file's mode on its open descriptor. A path therefore cannot leave the output directory even
if another process changes the tree while the builder runs. Every file is checked against the SHA-256
the corpus records before anything is written, so the same corpus always produces
byte-identical files. Nothing is executed: the pickle is an inert dictionary and every
credential is a public synthetic sentinel.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus.json"
MAX_FILES = 512
MAX_FILE_BYTES = 1 << 20


class CorpusError(ValueError):
    """The corpus is malformed or a file does not match its recorded digest."""


def _relative(path: object) -> PurePosixPath:
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        raise CorpusError(f"invalid corpus path: {path!r}")
    relative = PurePosixPath(path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in path.split("/")):
        raise CorpusError(f"corpus path escapes the output directory: {path!r}")
    return relative


def load(corpus: Path = CORPUS) -> list[tuple[PurePosixPath, bytes, int]]:
    """Every (path, bytes, mode) of the corpus, each checked against its SHA-256."""
    document = json.loads(corpus.read_text(encoding="utf-8"))
    files = document.get("files") if isinstance(document, dict) else None
    if not isinstance(files, list) or not 0 < len(files) <= MAX_FILES:
        raise CorpusError("corpus.json must hold a non-empty 'files' list")
    entries: list[tuple[PurePosixPath, bytes, int]] = []
    seen: set[PurePosixPath] = set()
    for record in files:
        if not isinstance(record, dict):
            raise CorpusError("corpus entry is not an object")
        relative = _relative(record.get("path"))
        if relative in seen:
            raise CorpusError(f"duplicate corpus path: {relative}")
        seen.add(relative)
        content = record.get("content")
        encoding = record.get("encoding")
        if not isinstance(content, str):
            raise CorpusError(f"{relative}: content is not a string")
        if encoding == "utf-8":
            data = content.encode("utf-8")
        elif encoding == "base64":
            data = base64.b64decode(content, validate=True)
        else:
            raise CorpusError(f"{relative}: unknown encoding {encoding!r}")
        if len(data) > MAX_FILE_BYTES:
            raise CorpusError(f"{relative}: larger than {MAX_FILE_BYTES} bytes")
        digest = hashlib.sha256(data).hexdigest()
        if record.get("sha256") != digest:
            raise CorpusError(f"{relative}: SHA-256 mismatch")
        mode = record.get("mode", 0o644)
        if mode not in (0o644, 0o755):
            raise CorpusError(f"{relative}: unsupported mode {mode!r}")
        entries.append((relative, data, mode))
    for relative, _, _ in entries:
        if any(parent in seen for parent in relative.parents):
            raise CorpusError(f"{relative}: a parent path is also a corpus file")
    return entries


_DIRECTORY = (
    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)
_FILE = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _trusted_parent(descriptor: int, parent: Path) -> None:
    """Refuse a parent another user could change.

    Safe is a sticky directory owned by root or the operator, such as ``/tmp``, where no
    one else can replace an entry, or a directory the operator owns that no one else can
    write to.
    """
    info = os.fstat(descriptor)
    sticky = bool(info.st_mode & stat.S_ISVTX) and info.st_uid in {0, os.geteuid()}
    private = info.st_uid == os.geteuid() and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    if not (sticky or private):
        raise CorpusError(f"{parent} must be yours and writable only by you, or a sticky directory")


def _write(directory: int, parts: tuple[str, ...], data: bytes, mode: int) -> None:
    """Write ``data`` at ``parts`` under ``directory`` without following symbolic links."""
    if len(parts) == 1:
        with os.fdopen(os.open(parts[0], _FILE, 0o600, dir_fd=directory), "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
        return
    # An earlier file may have created the directory; O_NOFOLLOW below still refuses a link.
    with contextlib.suppress(FileExistsError):
        os.mkdir(parts[0], 0o755, dir_fd=directory)
    child = os.open(parts[0], _DIRECTORY, dir_fd=directory)
    try:
        _write(child, parts[1:], data, mode)
    finally:
        os.close(child)


def build(out: Path, corpus: Path = CORPUS) -> list[PurePosixPath]:
    """Write the corpus under a new directory ``out`` and return the relative paths written."""
    entries = load(corpus)
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise CorpusError("this platform cannot write without following symbolic links")
    if out.name in {"", ".", ".."}:
        raise CorpusError(f"{out} does not name a new directory")
    parent_path = out.parent if str(out.parent) else Path(".")
    try:
        parent = os.open(parent_path, _DIRECTORY)
    except OSError as exc:
        raise CorpusError(f"{parent_path} cannot be opened as a directory: {exc}") from None
    try:
        _trusted_parent(parent, parent_path)
        try:
            os.mkdir(out.name, 0o700, dir_fd=parent)
        except FileExistsError:
            raise CorpusError(f"{out} already exists; give a new output directory") from None
        root = os.open(out.name, _DIRECTORY, dir_fd=parent)
        try:
            for relative, data, mode in entries:
                _write(root, relative.parts, data, mode)
        finally:
            os.close(root)
    finally:
        os.close(parent)
    return [relative for relative, _, _ in entries]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    args = parser.parse_args(argv)
    try:
        written = build(args.out)
    except (CorpusError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {len(written)} files to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
