"""Collect the model identifiers a project's own Python code gives an SDK.

Nothing is imported, executed or contacted, and each record is a declaration with the
file and line it was read from. What the reader knows is there and cannot read is a
coverage gap; ``docs/collectors.md`` says which files are read and what is a gap.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path, PurePosixPath

from nexus_symbiote import limits
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    SourceBudget,
    source_collection_bytes,
)
from nexus_symbiote.scanners.mcp_sources import (
    _INVALID_DECLARED,
    _INVALID_UTF8,
    _python_text,
    _UnreadableError,
)
from nexus_symbiote.scanners.source_python import PythonReader
from nexus_symbiote.scanners.source_python_tables import SDK_IMPORT, SDK_WORD
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


def _names_sdk(text: str) -> bool:
    """Whether an import statement may name an SDK once Python folds identifiers to NFKC,
    a slice at a time to bound each character's expansion, where its name alone counts."""
    if SDK_IMPORT.search(text):
        return True
    if text.isascii() or unicodedata.is_normalized("NFKC", text):
        return False
    slices = range(0, len(text), 4096)
    return any(
        SDK_WORD.search(unicodedata.normalize("NFKC", text[at : at + 4160])) for at in slices
    )


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
        found.close()
        result.components.extend(found.components())
        result.surfaces_scanned.append(SURFACE)
        result.surfaces_scanned.append(SKIPPED_SURFACE)
        return result

    def _read(
        self, root: Path, selected: list[Path], result: ScanResult, python: PythonReader
    ) -> None:
        """Hand each selected file that names an SDK to the reader, within the source budget.
        Files are read apart from the collection, whose failures are not kept: a file that
        cannot be opened, read or decoded as Python decodes it, a link to a file the collector
        does not read and one that names an SDK and is too large to parse are each a gap."""
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
                target = PurePosixPath(found[0].as_posix())
                large = found[1] > heuristic.max_file_bytes
                raw = None if large or _skipped(target) else heuristic.read_bytes(path)
                followed = heuristic.link_target(path)
                if _skipped(target) or (followed is not None and _skipped(PurePosixPath(followed))):
                    # What the application runs may hide in a test or build output.
                    result.surfaces_excluded.append(
                        f"{location}: source file links to a file the collector does not "
                        "read; not read"
                    )
                    continue
                if raw is None:
                    # Whether it imports an SDK is unknown, so it is a gap, not silence.
                    reason = "is larger than the file-bytes limit" if large else "could not be read"
                    result.surfaces_excluded.append(f"{location}: source file {reason}; not read")
                    continue
                if not budget.admit(len(raw), path):
                    continue
                try:
                    text = _python_text(raw)
                except _UnreadableError as error:
                    # Text Python cannot decode does not run, unless its codec is one
                    # this reader does not follow; then what it names is unknown.
                    invalid = error.args[0] in (_INVALID_UTF8, _INVALID_DECLARED)
                    if not invalid or _names_sdk(raw.decode("latin-1")):
                        result.surfaces_excluded.append(
                            f"{location}: source file cannot be decoded as its encoding "
                            "declares; declarations in it were not read"
                        )
                    continue
                if not _names_sdk(text):
                    continue
                if len(raw) > syntax:
                    result.surfaces_excluded.append(
                        f"{location}: source file is larger than the syntax-bytes limit; "
                        "declarations in it were not read"
                    )
                    continue
                python.add(location, text)
