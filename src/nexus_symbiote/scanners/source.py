"""Collect what a project's own source declares about the models it uses.

The other collectors read the files a coding agent or an MCP client reads. This one
reads the application: the model identifiers its Python code gives an SDK.

Everything it records is a declaration at declared assurance, with the file and line
it was read from. Nothing is imported, executed or contacted: a file is parsed to a
syntax tree. What the reader could not resolve is a coverage gap, never silence, and a
file it does not understand declares nothing it can record.

Tests, documentation, examples, benchmarks and build output are not read, as the MCP
source search does not read them. A file named as one that holds credentials is not
read either, and a link is read only when the file it reaches is one this collector
reads.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from nexus_symbiote import limits
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    SourceBudget,
    source_collection_bytes,
)
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.source_python import PythonReader
from nexus_symbiote.scanners.source_python_tables import AI_MARKERS
from nexus_symbiote.scanners.source_references import Declarations
from nexus_symbiote.utils.confined import ConfinedCollection

SKIPPED_DIRECTORIES = frozenset(
    {"tests", "test", "__tests__", "dist", "build", "docs", "benchmarks", "examples"}
)
SURFACE = "source: declarations in application source (static)"
SKIPPED_SURFACE = "source: tests, documentation, examples, benchmarks and build output are not read"
_PYTHON_TESTS = ("test_", "conftest.py")


def eligible(path: PurePosixPath) -> bool:
    """Whether the collector reads a file at this path, by its name and directories."""
    if SKIPPED_DIRECTORIES.intersection(path.parts[:-1]) or path.suffix.lower() != ".py":
        return False
    return not (path.name.startswith(_PYTHON_TESTS) or path.name.endswith("_test.py"))


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
        """Hand each selected file that names an SDK to the reader, within the source budget.

        Files are read apart from the collection, whose failures are not kept. A file
        that cannot be read, or that names an SDK and is too large to parse or is not
        UTF-8, is a named gap.
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
                found = None if credential_shaped(location) else heuristic.regular_file(path)
                if found is None:
                    continue
                target = found[0].as_posix()
                if credential_shaped(target) or not eligible(PurePosixPath(target)):
                    # A link reaches a file named for credentials, a test or another kind.
                    continue
                large = found[1] > heuristic.max_file_bytes
                raw = None if large else heuristic.read_bytes(path)
                if raw is None:
                    # Whether it names an SDK is unknown, so it is a gap, not silence.
                    reason = "is larger than the file-bytes limit" if large else "could not be read"
                    result.surfaces_excluded.append(f"{location}: source file {reason}; not read")
                    continue
                if not budget.admit(len(raw), path):
                    continue
                if not any(marker in raw for marker in AI_MARKERS):
                    continue
                if len(raw) > syntax:
                    result.surfaces_excluded.append(
                        f"{location}: source file is larger than the syntax-bytes limit; "
                        "declarations in it were not read"
                    )
                    continue
                try:
                    python.add(location, raw.decode("utf-8"))
                except UnicodeDecodeError:
                    result.surfaces_excluded.append(
                        f"{location}: source file is not UTF-8; declarations in it were not read"
                    )
