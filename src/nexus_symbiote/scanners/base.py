"""Abstract scanner interface for discovering agent supply chain components."""

from __future__ import annotations

import re
import stat
import tomllib
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.aibom import DependencyEdge
from nexus_symbiote.core.models import AnyComponent
from nexus_symbiote.utils.confined import ConfinedCollection

MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_MODEL_BYTES = 1024 * 1024 * 1024
# tomllib is pure Python: its cost grows quadratically with the parts of one
# dotted key or table header, and every input byte is slow. These bounds keep a
# hostile agent configuration file to well under a second of parsing.
MAX_TOML_BYTES = 256 * 1024
MAX_TOML_LINE_DOTS = 16
MAX_TOML_NESTING = 32
_TOML_SIGNIFICANT = re.compile(r"[\n#\"'.\[\]{}]")
_TOML_BASIC_STRING = re.compile(r'[\n"\\]')


def toml_exceeds_limits(text: str) -> bool:
    """Bound the dotted-key parts and nesting tomllib would process, in linear time.

    Keys never span lines, so the unquoted dots on one line bound the parts of
    any key on it. A malformed prefix is refused by tomllib before it is reached.
    """
    if len(text.encode("utf-8", "surrogatepass")) > MAX_TOML_BYTES:
        return True
    dots = depth = 0
    position = 0
    while match := _TOML_SIGNIFICANT.search(text, position):
        char, start = match.group(), match.start()
        position = start + 1
        if char == "\n":
            dots = 0
        elif char == ".":
            dots += 1
            if dots > MAX_TOML_LINE_DOTS:
                return True
        elif char in "[{":
            depth += 1
            if depth > MAX_TOML_NESTING:
                return True
        elif char in "]}":
            depth = max(depth - 1, 0)
        else:
            if char == "#":
                end = text.find("\n", start)
            elif text.startswith(char * 3, start):
                end = _toml_multiline_end(text, start + 3, char)
            elif char == "'":
                end = text.find("'", position)
            else:
                end = _toml_basic_end(text, position)
            end = len(text) if end < 0 else end
            if text.find("\n", start, end) >= 0:
                dots = 0
            position = end if char == "#" else end + 1
    return False


def _toml_basic_end(text: str, position: int) -> int:
    while match := _TOML_BASIC_STRING.search(text, position):
        if match.group() == "\\":
            position = match.end() + 1
            continue
        return match.start()
    return -1


def _toml_multiline_end(text: str, position: int, quote: str) -> int:
    while (end := text.find(quote * 3, position)) >= 0:
        escapes = len(text[position:end]) - len(text[position:end].rstrip("\\"))
        if quote == '"' and escapes % 2:
            position = end + 1
            continue
        # Like tomllib, take up to two further quotes as string content.
        extra = 0
        while extra < 2 and text.startswith(quote, end + 3 + extra):
            extra += 1
        return end + 2 + extra
    return -1


# At most this many files are read for one documented name, such as CLAUDE.md.
MAX_CASE_VARIANTS = 8
# HFS+ ignores these code points when it compares names (see git's core.protectHFS).
_HFS_IGNORED = dict.fromkeys(
    [0x200C, 0x200D, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x206A, 0x2070), 0xFEFF]
)


def folded_name(path: str) -> str:
    """Fold a name so spellings that default macOS and Windows file systems treat as one match."""
    return path.translate(_HFS_IGNORED).upper().casefold()


def case_variants(
    files: ConfinedCollection,
    name: str,
    failures: list[str],
    *,
    directory: bool = False,
    listings: dict[str, dict[str, int]] | None = None,
) -> list[str]:
    """Paths that a case-insensitive file system opens as a documented name; exact name first.

    Agents open fixed names by path join, so the default macOS and Windows file systems
    open .MCP.json as .mcp.json, and .Claude/Skills as .claude/skills. A case-sensitive
    file system can hold several such paths; all are returned, up to MAX_CASE_VARIANTS
    at each level, because which one an agent reads there depends on where it runs.
    With `directory`, the name is a directory; otherwise entries of every kind are returned,
    so that a directory or symlink under a file name is read and refused. `listings` shares
    directory listings
    between calls, so that each directory is listed at most once.
    """
    listings = {} if listings is None else listings

    def entries(parent: str) -> dict[str, int]:
        if parent not in listings:
            listings[parent] = files.list_entries(parent or ".")
        return listings[parent]

    *directories, leaf = name.split("/")
    parents = [""]
    for depth, part in enumerate(directories, 1):
        parents = _first_variants(
            [
                f"{parent}{entry}/"
                for parent in parents
                for entry, kind in entries(parent).items()
                # A symlinked directory is listed so that reading it fails closed.
                if kind in (stat.S_IFDIR, stat.S_IFLNK) and folded_name(entry) == folded_name(part)
            ],
            "/".join(directories[:depth]) + "/",
            "directories",
            failures,
        )
    return _first_variants(
        [
            f"{parent}{entry}"
            for parent in parents
            for entry, kind in entries(parent).items()
            # Every kind is kept for a file name, so a directory there fails its read.
            if (not directory or kind in (stat.S_IFDIR, stat.S_IFLNK))
            and folded_name(entry) == folded_name(leaf)
        ],
        name,
        "directories" if directory else "files",
        failures,
    )


def _first_variants(paths: list[str], name: str, kind: str, failures: list[str]) -> list[str]:
    paths.sort(key=lambda path: (path != name, path))
    message = f"{name}: more than {MAX_CASE_VARIANTS} {kind} open as {name}; the rest not read"
    # Documented names share directories such as .claude/, so one bound can be hit repeatedly.
    if len(paths) > MAX_CASE_VARIANTS and message not in failures:
        failures.append(message)
    return paths[:MAX_CASE_VARIANTS]


def read_regular_text(path: Path, *, max_bytes: int = MAX_CONFIG_BYTES) -> str:
    """Legacy explicit-file reader, bounded and no-follow for all path parts."""
    with ConfinedCollection(
        path.parent, [], max_file_bytes=max_bytes, max_total_bytes=max_bytes
    ) as files:
        content = files.read_text(path.name)
    if content is None:
        raise OSError("bounded regular-file read refused")
    return content


def hash_regular_file(path: Path, *, max_bytes: int = MAX_MODEL_BYTES) -> str:
    """Legacy explicit-file hash; automatic scans use their project-root boundary."""
    with ConfinedCollection(path.parent, [], max_total_bytes=max_bytes) as files:
        digest = files.hash_file(path.name, max_bytes=max_bytes)
    if digest is None:
        raise OSError("bounded regular-file hash refused")
    return digest


def exportable(component: AnyComponent) -> bool:
    """Whether every export can encode a component's text as UTF-8.

    Collectors read JSON escapes and YAML as Python strings, which may hold lone
    surrogates. Pydantic raises PydanticSerializationError, a ValueError, for them.
    """
    try:
        component.model_dump_json()
    except ValueError:
        return False
    return True


def sanitized_origin(value: str) -> str:
    """Omit paths as well as userinfo, queries and fragments from URL output."""
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname:
            return "[redacted]"
        host = parsed.hostname
        host = f"[{host}]" if ":" in host else host
        port = parsed.port
        return f"{parsed.scheme.lower()}://{host}" + (f":{port}" if port is not None else "")
    except ValueError:
        return "[redacted]"


@dataclass
class ScanResult:
    """The output of a single scanner pass."""

    scanner_name: str
    components: list[AnyComponent] = field(default_factory=list)
    dependencies: list[DependencyEdge] = field(default_factory=list)
    surfaces_scanned: list[str] = field(default_factory=list)
    surfaces_excluded: list[str] = field(default_factory=list)
    scan_failures: list[str] = field(default_factory=list)
    source_report_digest: str | None = None
    source_report_format: str | None = None
    source_report_status: str | None = None
    source_projection_limitations: list[str] | None = None
    source_unmapped_count: int = 0
    source_unmapped_indexes: list[int] = field(default_factory=list)


class Scanner(ABC):
    """Base class for all component scanners."""

    name: str = "base"
    _exclude_paths: tuple[str | Path, ...] = ()
    _files: ConfinedCollection | None = None

    def configure(self, exclude_paths: Iterable[str | Path] = ()) -> None:
        """Set root-relative or absolute collection exclusions before ``scan``."""
        self._exclude_paths = tuple(exclude_paths)

    @contextmanager
    def _collection(
        self, root: Path, result: ScanResult, **limits: Any
    ) -> Iterator[ConfinedCollection]:
        with ConfinedCollection(
            root,
            result.scan_failures,
            result.surfaces_excluded,
            exclude_paths=self._exclude_paths,
            **limits,
        ) as files:
            self._files = files
            try:
                yield files
            finally:
                self._files = None

    @abstractmethod
    def scan(self, project_root: Path) -> ScanResult:
        """Scan a project directory and return discovered components."""

    def _safe_read_json(self, path: Path) -> dict[str, Any] | list[Any] | None:
        # Compatibility for scanner helpers; scans should open a _collection so
        # every failure is retained on the ScanResult and the project root pinned.
        if self._files is not None:
            data = self._files.read_json(path)
        else:
            with ConfinedCollection(path.parent, []) as files:
                data = files.read_json(path.name)
        return data if isinstance(data, (dict, list)) else None

    def _read_mapping(
        self, path: Path, result: ScanResult, *, missing_ok: bool = True
    ) -> dict[str, Any] | None:
        """Read a bounded static JSON/YAML/TOML mapping and retain parse failures."""
        if self._files is None:
            raise RuntimeError("_read_mapping called outside a _collection context")
        if path.suffix.lower() == ".json":
            data = self._files.read_json(path, missing_ok=missing_ok)
        elif path.suffix.lower() == ".toml":
            text = self._files.read_text(path, missing_ok=missing_ok)
            if text is None:
                return None
            try:
                label = path.relative_to(self._files.root).as_posix()
            except ValueError:
                label = path.name
            if toml_exceeds_limits(text):
                result.scan_failures.append(f"{label}: TOML size or structure limit exceeded")
                return None
            try:
                data = tomllib.loads(text)
            except (ValueError, RecursionError):
                result.scan_failures.append(f"{label}: TOML mapping parse failed")
                return None
        else:
            text = self._files.read_text(path, missing_ok=missing_ok)
            if text is None:
                return None
            try:
                import yaml
            except ImportError:
                result.scan_failures.append(f"{path.name}: YAML parser unavailable")
                return None
            from nexus_symbiote.policy import parse_yaml_mapping

            try:
                for index, token in enumerate(yaml.scan(text)):
                    if index >= 20_000 or isinstance(
                        token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)
                    ):
                        raise ValueError("unsupported YAML graph")
                data = parse_yaml_mapping(text)
            except (ValueError, RecursionError, yaml.YAMLError):
                result.scan_failures.append(
                    f"{path.name}: YAML mapping parse failed or unsupported"
                )
                return None
        if data is None:
            return None
        if not isinstance(data, dict):
            result.scan_failures.append(f"{path.name}: expected a mapping")
            return None
        return data
