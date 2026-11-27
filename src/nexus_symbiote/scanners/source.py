"""Collect what a project's own source and configuration declare about its agents.

The other collectors read the files a coding agent or an MCP client reads. This one
reads the application: the models its code asks for, the agents it constructs and
what each is given, its tools, the MCP servers it starts or reaches, its guardrails,
its memory and retrieval stores, and the names of the credential variables it reads.

Everything it records is a declaration at declared assurance, with the file and line
it was read from. Nothing is imported, executed or contacted: Python is parsed to a
syntax tree, TypeScript and JavaScript with the grammar the MCP source collector
uses, and data files with the bounded static readers. What a reader could not
resolve is a coverage gap, never silence, and a file it does not understand declares
nothing it can record.

Tests, documentation, examples, benchmarks and build output are not read, as the MCP
source search does not read them. A file named as one that holds credentials is not
read either; an environment file is read for its variable names only, never a value.
A configuration file another collector reads is left to that collector: the settings
directories of coding agents and editors, MCP client files, retrieval and guardrail
configuration, and A2A agent cards.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from nexus_symbiote import limits
from nexus_symbiote.scanners.a2a import A2A_CONFIG_FILES, AGENT_CARD_NAMES
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    SourceBudget,
    source_collection_bytes,
)
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.mcp import MCP_DIALECTS
from nexus_symbiote.scanners.rag import GUARDRAIL_CONFIG_FILES, RAG_CONFIG_PATTERNS
from nexus_symbiote.scanners.source_clike import CLIKE_SUFFIXES, ClikeReader
from nexus_symbiote.scanners.source_config import (
    ConfigReader,
    is_environment_file,
    notebook_code,
)
from nexus_symbiote.scanners.source_config import reads as reads_configuration
from nexus_symbiote.scanners.source_python import PythonReader
from nexus_symbiote.scanners.source_python_tables import AI_MARKERS
from nexus_symbiote.scanners.source_references import Declarations
from nexus_symbiote.scanners.source_script import SCRIPT_MARKERS, ScriptReader
from nexus_symbiote.scanners.ts_tools import NOT_SOURCE_NAMES, SCRIPT_SUFFIXES
from nexus_symbiote.utils.confined import ConfinedCollection

SKIPPED_DIRECTORIES = frozenset(
    {"tests", "test", "__tests__", "dist", "build", "docs", "benchmarks", "examples"}
)
SURFACE = "source: declarations in application source and configuration (static)"
SKIPPED_SURFACE = "source: tests, documentation, examples, benchmarks and build output are not read"
_PYTHON_TESTS = ("test_", "conftest.py")
NOTEBOOK_SUFFIX = ".ipynb"
# Configuration another collector reads, by file name.
COLLECTED_ELSEWHERE = frozenset(
    {
        *RAG_CONFIG_PATTERNS,
        *GUARDRAIL_CONFIG_FILES,
        *A2A_CONFIG_FILES,
        *AGENT_CARD_NAMES,
        *(dialect.path for dialect in MCP_DIALECTS if "/" not in dialect.path),
    }
)


def eligible(path: PurePosixPath) -> bool:
    """Whether the collector reads a file at this path, by its name and directories."""
    if SKIPPED_DIRECTORIES.intersection(path.parts[:-1]):
        return False
    name, suffix = path.name, path.suffix.lower()
    if suffix == ".py":
        return not (name.startswith(_PYTHON_TESTS) or name.endswith("_test.py"))
    if suffix in SCRIPT_SUFFIXES:
        return not name.endswith(NOT_SOURCE_NAMES)
    if suffix in CLIKE_SUFFIXES or suffix == NOTEBOOK_SUFFIX:
        return True
    if is_environment_file(name):
        return True
    # A dot-directory holds the settings of a tool, which that tool's collector reads.
    if name in COLLECTED_ELSEWHERE or any(part.startswith(".") for part in path.parts[:-1]):
        return False
    return reads_configuration(path)


class SourceScanner(Scanner):
    """Declarations in application source: models, agents, tools, servers and stores."""

    name = "source"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        found = Declarations(result)
        python = PythonReader(found, result)
        script = ScriptReader(found)
        clike = ClikeReader(found)
        configuration = ConfigReader(found)
        selected: list[Path] = []
        known: set[str] = set()
        with self._collection(project_root, result) as files:
            for path in files.iter_files():
                known.add(path.as_posix())
                if eligible(PurePosixPath(path.as_posix())):
                    selected.append(path)
            python.known_files = frozenset(known)
            candidates = self._read(
                files.root, sorted(selected), result, python, script, clike, configuration
            )
        python.read(candidates)
        found.close()
        result.components.extend(found.components())
        result.credential_names = found.credential_names()
        result.credential_references = found.credential_references()
        result.surfaces_scanned.append(SURFACE)
        result.surfaces_scanned.append(SKIPPED_SURFACE)
        return result

    def _read(
        self,
        root: Path,
        selected: list[Path],
        result: ScanResult,
        python: PythonReader,
        script: ScriptReader,
        clike: ClikeReader,
        configuration: ConfigReader,
    ) -> set[str]:
        """Hand each selected file to its reader, within the source budget.

        Returns the Python files that name an SDK, which are analysed once every file
        is known, because one module reads constants from another.


        Files are read apart from the collection, whose failures are not kept: a file
        that is too large or unreadable declares nothing this collector can record.
        One that names an SDK and is too large to parse is a named gap.
        """
        candidates: set[str] = set()
        budget = SourceBudget("source declarations", result)
        syntax = limits.current().syntax_bytes
        with ConfinedCollection(
            root, [], exclude_paths=self._exclude_paths, max_total_bytes=source_collection_bytes()
        ) as heuristic:
            for path in selected:
                if budget.exhausted:
                    break
                location = path.as_posix()
                suffix = path.suffix.lower()
                names_only = is_environment_file(path.name)
                if credential_shaped(location) and not names_only:
                    continue
                raw = heuristic.read_bytes(path)
                if raw is None or not budget.admit(len(raw), path):
                    continue
                code = suffix == ".py" or suffix in SCRIPT_SUFFIXES or suffix in CLIKE_SUFFIXES
                if code and len(raw) > syntax:
                    markers = AI_MARKERS if suffix == ".py" else SCRIPT_MARKERS
                    if any(marker in raw for marker in markers):
                        result.surfaces_excluded.append(
                            f"{location}: source file is larger than the syntax-bytes limit; "
                            "declarations in it were not read"
                        )
                    continue
                if suffix == ".py":
                    try:
                        text = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    python.add(location, raw, text)
                    if any(marker in raw for marker in AI_MARKERS):
                        candidates.add(location)
                elif suffix == NOTEBOOK_SUFFIX:
                    cells = notebook_code(raw)
                    if cells is not None and any(m.decode() in cells for m in AI_MARKERS):
                        python.add_cells(location, cells)
                elif suffix in SCRIPT_SUFFIXES:
                    script.read(location, raw)
                elif suffix in CLIKE_SUFFIXES:
                    clike.read(location, raw)
                else:
                    configuration.read(location, raw)
        return candidates
