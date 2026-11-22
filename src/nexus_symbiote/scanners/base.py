"""Abstract scanner interface for discovering agent supply chain components."""

from __future__ import annotations

import ast
import os
import re
import warnings
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote import limits
from nexus_symbiote.core.aibom import DependencyEdge
from nexus_symbiote.core.identifiers import neutral_text
from nexus_symbiote.core.models import (
    AnyComponent,
    DiscoveryVerification,
    MCPClientComponent,
)
from nexus_symbiote.limits import Bound
from nexus_symbiote.utils.confined import BoundedRecords, ConfinedCollection
from nexus_symbiote.utils.secrets import holds_token_shape, redact_text

MAX_CONFIG_BYTES = 4 * 1024 * 1024
YAML_TOKEN_LIMIT = 20_000
MAX_MODEL_BYTES = 1024 * 1024 * 1024
# The default only: a source budget reads the operator's source-scan-bytes limit.
MAX_SOURCE_BYTES = limits.DEFAULTS.source_scan_bytes
MAX_SERVER_NAME_CHARS = 128
_SERVER_NAME = re.compile(r"(?=.*[A-Za-z0-9])[A-Za-z0-9_.-]+(?: [A-Za-z0-9_.-]+)*")
_NAME_CHARACTERS = re.compile(r"[A-Za-z0-9_. -]+")


def read_regular_text(path: Path, *, max_bytes: int = MAX_CONFIG_BYTES) -> str:
    """Legacy explicit-file reader, bounded and no-follow for all path parts."""
    with ConfinedCollection(
        path.parent, [], max_file_bytes=max_bytes, max_total_bytes=max_bytes
    ) as files:
        content = files.read_text(path.name)
        # A collection reads through a symlink to a file beside it; this reader does not.
        if files.link_target(path.name) is not None:
            content = None
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


def sanitized_origin(value: str) -> str:
    """Omit paths as well as userinfo, queries and fragments from URL output."""
    from nexus_symbiote.utils.secrets import TOKEN_SHAPE

    try:
        parsed = urlsplit(value)
        raw_host = parsed.netloc.rpartition("@")[2]
        if (
            not parsed.scheme
            or not parsed.hostname
            or "\\" in parsed.netloc
            or TOKEN_SHAPE.search(raw_host)
        ):
            return "[redacted]"
        host = parsed.hostname
        host = f"[{host}]" if ":" in host else host
        port = parsed.port
        return f"{parsed.scheme.lower()}://{host}" + (f":{port}" if port is not None else "")
    except ValueError:
        return "[redacted]"


def parse_python(source: str) -> ast.Module:
    """Parse scanned source without printing compiler warnings, which quote its raw bytes.

    A UTF-8 byte-order mark is accepted, as CPython accepts it in a source file. The
    parser reports deeply nested source as MemoryError, RecursionError or OverflowError;
    each becomes ValueError, so callers record a failure for the file instead of losing
    the whole collector.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            return ast.parse(source.removeprefix("\ufeff"))
        except (MemoryError, RecursionError, OverflowError):
            raise ValueError("Python source too complex to parse") from None


class KnownValues:
    """Values the scan read from configuration that a server name declared in source
    must not hold, such as a credential with no token shape.

    Only a value of name characters, at most ``MAX_SERVER_NAME_CHARS`` long, can be
    part of a declared name, so no other is kept. A name is tested against the values
    of each length by the cheaper of two reads, every value of that length or every
    part of the name that long, so a test costs at most the square of the name's
    length however many values a project's files hold. After ``refuse``, which stands
    for a file whose values could not all be read, every name holds one.
    """

    __slots__ = ("_by_length", "_refused")

    def __init__(self, values: Iterable[str] = ()) -> None:
        self._by_length: dict[int, set[str]] = {}
        self._refused = False
        self.add(values)

    def add(self, values: Iterable[str]) -> None:
        for value in values:
            if len(value) <= MAX_SERVER_NAME_CHARS and _NAME_CHARACTERS.fullmatch(value):
                self._by_length.setdefault(len(value), set()).add(value)

    def refuse(self) -> None:
        self._refused = True

    def held_by(self, name: str) -> bool:
        if self._refused:
            return True
        size = len(name)
        for length, values in self._by_length.items():
            starts = size - length + 1
            if starts < 1:
                continue
            if len(values) <= starts:
                if any(value in name for value in values):
                    return True
            elif any(name[start : start + length] in values for start in range(starts)):
                return True
        return False


def declared_server_name(literal: object, known: KnownValues | None = None) -> str | None:
    """The name a server constructor declares as a literal, when it is in the supported form.

    A source collector names a server by this literal, the name clients see, and by
    its binding otherwise, as it does when redaction would change the literal or the
    literal holds one of the ``known`` values.
    """
    if not isinstance(literal, str) or len(literal) > MAX_SERVER_NAME_CHARS:
        return None
    if _SERVER_NAME.fullmatch(literal) is None:
        return None
    if known is not None and known.held_by(literal):
        return None
    # Every shape the identifier reading of redact_text finds, the plain one finds too; a
    # shape glued to a prefix, which redaction leaves alone, keeps the binding as well.
    if redact_text(literal) != literal or holds_token_shape(literal):
        return None
    return literal


def project_relative(root: Path) -> Callable[[str], str]:
    """Map a location inside ``root`` to project-relative POSIX text; others stay as given.

    The one rule for paths in an inventory: collection applies it before recording,
    and readers apply it to records an earlier release wrote with absolute paths.
    """
    base = os.path.abspath(root)
    prefix = base.rstrip(os.sep) + os.sep

    def relative(value: str) -> str:
        if value == base:
            return "."
        if not value.startswith(prefix):
            return value
        return value[len(prefix) :].replace(os.sep, "/")

    return relative


@dataclass
class ScanResult:
    """The output of a single scanner pass.

    Its failures and excluded surfaces are listed within the listing bounds, past
    which they are counted, so a collector that records one for every file it meets
    still yields an inventory that loads.
    """

    scanner_name: str
    components: list[AnyComponent] = field(default_factory=list)
    dependencies: list[DependencyEdge] = field(default_factory=list)
    surfaces_scanned: list[str] = field(default_factory=list)
    surfaces_excluded: list[str] = field(default_factory=list)
    accepted_default_exclusions: list[str] = field(
        default_factory=lambda: BoundedRecords(noun="accepted default exclusion", bind_omitted=True)
    )
    scan_failures: list[str] = field(default_factory=list)
    source_report_digest: str | None = None
    source_report_content_digest: str | None = None
    source_report_content_profile: str | None = None
    source_report_path: str | None = None
    source_report_format: str | None = None
    source_report_status: str | None = None
    source_projection_limitations: list[str] | None = None
    source_unmapped_count: int = 0
    source_unmapped_indexes: list[int] = field(default_factory=list)
    discovery_verification: DiscoveryVerification | None = None
    accepted_default_names: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not isinstance(self.scan_failures, BoundedRecords):
            self.scan_failures = BoundedRecords(self.scan_failures)
        if not isinstance(self.surfaces_excluded, BoundedRecords):
            self.surfaces_excluded = BoundedRecords(self.surfaces_excluded, noun="excluded surface")

    def make_portable(self, root: Path) -> None:
        """Record locations inside the project rather than where it was checked out.

        A checkout path is not a property of the project: recorded, it made the
        same tree collected in CI differ from its baseline on every component.
        """
        relative = project_relative(root)
        for component in self.components:
            if component.source_path is not None:
                component.source_path = relative(component.source_path)
            if isinstance(component, MCPClientComponent) and component.config_path is not None:
                component.config_path = relative(component.config_path)
            for key in ("config_paths", "source_paths"):
                values = component.properties.get(key)
                if isinstance(values, list):
                    component.properties[key] = [
                        relative(value) if isinstance(value, str) else value for value in values
                    ]
        self.surfaces_scanned[:] = [relative(record) for record in self.surfaces_scanned]
        # Coverage reasons quote checkout text, such as a server name, and are exported.
        for records in (
            self.surfaces_excluded,
            self.scan_failures,
            self.accepted_default_exclusions,
        ):
            records[:] = [neutral_text(relative(record)) for record in records]


class SourceBudget:
    """Bound the source text a collector reads while it looks for references.

    A file count says nothing about cost and made ordinary projects fail, so the
    bound is the text read: the operator's ``source-scan-bytes`` limit, for each
    collector that searches source. What does not fit is one named coverage gap,
    which names the first file not read in full, the limit and how to raise it.
    """

    def __init__(self, label: str, result: ScanResult, limit: int | None = None) -> None:
        self._label = label
        self._result = result
        value = limits.current().source_scan_bytes if limit is None else limit
        self.bound = Bound(value, "source-scan-bytes")
        self._remaining = value
        self.exhausted = False

    def admit(self, size: int, path: str | Path | None = None) -> bool:
        """Charge ``size`` bytes read from ``path``; False once they do not fit."""
        if self.exhausted:
            return False
        self._remaining -= size
        if self._remaining < 0:
            self.exhausted = True
            where = "" if path is None else f"{Path(path).as_posix()}: "
            self._result.scan_failures.append(
                f"{where}{self._label} exceed the combined size limit: the rest were not "
                "read; " + self.bound.exceeded()
            )
        return not self.exhausted


def source_collection_bytes() -> Bound:
    """The byte limit of a collection that also searches source text.

    Source text is charged to the collection as well, so its limit is the operator's
    ``total-bytes`` plus ``source-scan-bytes``, and every read of the collection counts
    against that sum. A failure states both values as the operator set them.
    """
    settings = limits.current()
    total, source = settings.total_bytes, settings.source_scan_bytes
    shown = (
        f"{limits.format_value('total-bytes', total)} (plus "
        f"{limits.format_value('source-scan-bytes', source)} source-scan-bytes for source search)"
    )
    return Bound(total + source, "total-bytes", shown=shown)


class Scanner(ABC):
    """Base class for all component scanners."""

    name: str = "base"
    _exclude_paths: tuple[str | Path, ...] = ()
    _accept_default_excludes: bool | tuple[str, ...] = False
    _files: ConfinedCollection | None = None

    def configure(
        self,
        exclude_paths: Iterable[str | Path] = (),
        *,
        accept_default_excludes: bool | tuple[str, ...] = False,
    ) -> None:
        """Set root-relative or absolute collection exclusions before ``scan``."""
        self._exclude_paths = tuple(exclude_paths)
        self._accept_default_excludes = accept_default_excludes

    @contextmanager
    def _collection(
        self, root: Path, result: ScanResult, **bounds: Any
    ) -> Iterator[ConfinedCollection]:
        with ConfinedCollection(
            root,
            result.scan_failures,
            result.surfaces_excluded,
            exclude_paths=self._exclude_paths,
            accept_default_excludes=self._accept_default_excludes,
            accepted_default_exclusions=result.accepted_default_exclusions,
            **bounds,
        ) as files:
            self._files = files
            try:
                yield files
            finally:
                result.accepted_default_names.update(files.accepted_default_names)
                self._files = None

    @abstractmethod
    def scan(self, project_root: Path) -> ScanResult:
        """Scan a project directory and return discovered components."""

    @staticmethod
    def _parse_yaml_mapping(
        path: Path,
        text: str,
        result: ScanResult,
        *,
        inert_without: frozenset[str] | None = None,
    ) -> dict[str, Any] | None:
        """Parse ``text`` read from ``path`` as a bounded static YAML mapping.

        Anchors, aliases and tags are refused, as is more than ``YAML_TOKEN_LIMIT``
        tokens. With ``inert_without``, a document with no content, or one with an
        anchor, alias or tag but no scalar equal to any of those names, is an empty
        mapping: it cannot declare a key of that name, so it is never composed.
        """
        try:
            import yaml
        except ImportError:
            result.scan_failures.append(f"{path.as_posix()}: YAML parser unavailable")
            return None
        from nexus_symbiote.policy import parse_yaml_mapping

        frame = (
            yaml.StreamStartToken,
            yaml.StreamEndToken,
            yaml.DocumentStartToken,
            yaml.DocumentEndToken,
        )
        try:
            graph = named = content = False
            for index, token in enumerate(yaml.scan(text)):
                if index >= YAML_TOKEN_LIMIT:
                    raise ValueError("YAML token limit exceeded")
                if isinstance(token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)):
                    if inert_without is None:
                        raise ValueError("unsupported YAML graph")
                    graph = True
                elif isinstance(token, yaml.ScalarToken):
                    named = named or (inert_without is not None and token.value in inert_without)
                if not isinstance(token, frame):
                    content = True
            if inert_without is not None and (not content or (graph and not named)):
                return {}
            if graph:
                raise ValueError("unsupported YAML graph")
            data = parse_yaml_mapping(text)
        except (ValueError, RecursionError, OverflowError, IndexError, yaml.YAMLError):
            result.scan_failures.append(
                f"{path.as_posix()}: YAML mapping parse failed or unsupported"
            )
            return None
        return data

    def _read_mapping(
        self, path: Path, result: ScanResult, *, missing_ok: bool = True
    ) -> dict[str, Any] | None:
        """Read a bounded static JSON/YAML mapping and retain parse failures."""
        if self._files is None:
            raise RuntimeError("_read_mapping called outside a _collection context")
        if path.suffix.lower() == ".json":
            data = self._files.read_json(path, missing_ok=missing_ok)
        else:
            text = self._files.read_text(path, missing_ok=missing_ok)
            if text is None:
                return None
            return self._parse_yaml_mapping(path, text, result)
        if data is None:
            return None
        if not isinstance(data, dict):
            result.scan_failures.append(f"{path.as_posix()}: expected a mapping")
            return None
        return data
