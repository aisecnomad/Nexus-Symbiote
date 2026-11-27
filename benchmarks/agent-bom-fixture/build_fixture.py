#!/usr/bin/env python3
"""Materialize the agent BOM regression fixture from ``corpus.json``.

The fixture is a synthetic customer-support agent monorepo with 109 labelled components in
ten categories and ten decoys (see ``ground_truth.json``). It is stored as data and written
out on demand, as AIBOM-Bench is, so the repository tracks no dependency manifest that pins
the deliberately vulnerable packages the fixture plants, and no file a dependency scanner or
an editor would treat as live configuration.

    python benchmarks/agent-bom-fixture/build_fixture.py --out /tmp/agent-bom-fixture

The output directory must not exist or must be empty. Every file is checked against the
SHA-256 the corpus records before the command succeeds, so the same corpus always produces
byte-identical files. Nothing is executed: the pickle is an inert dictionary and every
credential is a public synthetic sentinel.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
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
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
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
    return entries


def build(out: Path, corpus: Path = CORPUS) -> list[PurePosixPath]:
    """Write the corpus under ``out`` and return the relative paths written."""
    entries = load(corpus)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise CorpusError(f"{out} exists and is not an empty directory")
    out.mkdir(parents=True, exist_ok=True)
    root = out.resolve()
    for relative, data, mode in entries:
        target = root.joinpath(*relative.parts)
        if not target.resolve().is_relative_to(root):
            raise CorpusError(f"{relative}: resolves outside the output directory")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(mode)
    return [relative for relative, _, _ in entries]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="empty or new output directory")
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
