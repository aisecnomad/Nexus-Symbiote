"""Collect what a project's own source declares about the models it uses.

The other collectors read the files a coding agent or an MCP client reads. This one
reads the application: the model identifiers its Python code gives an SDK.

Everything it records is a declaration at declared assurance, with the file and line
it was read from. Nothing is imported, executed or contacted: a file is parsed to a
syntax tree. What the reader could not resolve is a coverage gap, never silence, and a
file it does not understand declares nothing it can record.

Tests, documentation, examples, benchmarks and build output are not read, as the MCP
source search does not read them, and a link is read only when the file it reaches is
not one of these. A file named as one that holds credentials is read like any other:
the collector exports no value but a model identifier that passes the export checks.
"""

from __future__ import annotations

import io
import tokenize
from pathlib import Path, PurePosixPath

from nexus_symbiote import limits
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    SourceBudget,
    source_collection_bytes,
)
from nexus_symbiote.scanners.source_python import PythonReader
from nexus_symbiote.scanners.source_python_tables import SDK_IMPORT
from nexus_symbiote.scanners.source_references import Declarations
from nexus_symbiote.utils.confined import ConfinedCollection

SKIPPED_DIRECTORIES = frozenset(
    {"tests", "test", "__tests__", "dist", "build", "docs", "benchmarks", "examples"}
)
SURFACE = "source: declarations in application source (static)"
SKIPPED_SURFACE = "source: tests, documentation, examples, benchmarks and build output are not read"
_PYTHON_TESTS = ("test_", "conftest.py")


def _skipped(path: PurePosixPath) -> bool:
    """Whether a path is a test, documentation, an example, a benchmark or build output."""
    if SKIPPED_DIRECTORIES.intersection(path.parts[:-1]):
        return True
    return path.name.startswith(_PYTHON_TESTS) or path.name.endswith("_test.py")


def eligible(path: PurePosixPath) -> bool:
    """Whether the collector reads a file at this path, by its name and directories."""
    return path.suffix.lower() == ".py" and not _skipped(path)


def _decoded(raw: bytes) -> str | None:
    """Source text as Python reads it: the encoding its first lines declare, else UTF-8."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        return raw.decode(encoding)
    except (SyntaxError, LookupError, UnicodeDecodeError):
        return None


class SourceScanner(Scanner):
    """Declarations in application source: the model identifiers code gives an SDK."""

    name = "source"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        found = Declarations(result)
        selected: list[Path] = []
        modules: set[str] = set()
        with self._collection(project_root, result) as files:
            for path in files.iter_files():
                if path.suffix.lower() == ".py":
                    modules.add(path.as_posix())
                if eligible(PurePosixPath(path.as_posix())):
                    selected.append(path)
            python = PythonReader(found, frozenset(modules))
            self._read(files.root, sorted(selected), result, python)
        python.read()
        found.close()
        result.components.extend(found.components())
        result.surfaces_scanned.append(SURFACE)
        result.surfaces_scanned.append(SKIPPED_SURFACE)
        return result

    def _read(
        self, root: Path, selected: list[Path], result: ScanResult, python: PythonReader
    ) -> None:
        """Hand each selected file that imports an SDK to the reader, within the source budget.

        Files are read apart from the collection, whose failures are not kept. A file
        that cannot be opened or read, or one that imports an SDK and is too large to
        parse or cannot be decoded, is a named gap.
        """
        budget = SourceBudget("source declarations", result)
        syntax = limits.current().syntax_bytes
        with ConfinedCollection(
            root, [], exclude_paths=self._exclude_paths, max_total_bytes=source_collection_bytes()
        ) as heuristic:
            for path in selected:
                if budget.exhausted:
                    break
                location = path.as_posix()
                found = heuristic.regular_file(path)
                if found is None:
                    if heuristic.entry_exists(path):
                        result.surfaces_excluded.append(
                            f"{location}: source file could not be read; not read"
                        )
                    continue
                if _skipped(PurePosixPath(found[0].as_posix())):
                    # A link reaches a test, documentation or build output.
                    continue
                large = found[1] > heuristic.max_file_bytes
                raw = None if large else heuristic.read_bytes(path)
                followed = heuristic.link_target(path)
                if followed is not None and _skipped(PurePosixPath(followed)):
                    # The link changed after it was checked.
                    continue
                if raw is None:
                    # Whether it imports an SDK is unknown, so it is a gap, not silence.
                    reason = "is larger than the file-bytes limit" if large else "could not be read"
                    result.surfaces_excluded.append(f"{location}: source file {reason}; not read")
                    continue
                if not budget.admit(len(raw), path) or not SDK_IMPORT.search(raw):
                    continue
                if len(raw) > syntax:
                    result.surfaces_excluded.append(
                        f"{location}: source file is larger than the syntax-bytes limit; "
                        "declarations in it were not read"
                    )
                    continue
                text = _decoded(raw)
                if text is None:
                    result.surfaces_excluded.append(
                        f"{location}: source file cannot be decoded as its encoding declares; "
                        "declarations in it were not read"
                    )
                    continue
                python.add(location, text)
