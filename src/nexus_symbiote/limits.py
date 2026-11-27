"""Operator-set bounds on what one command collects from a checkout.

Every bound fails closed: a collector that reaches one records a scan failure
naming the limit, its value, the root-relative path where it was reached and how
to raise it, so the gates fail. Changing a limit moves where collection stops; it
never decides whether a stop is reported. Limits come only from the operator,
through the ``--limit NAME=VALUE`` root option and the ``NEXUS_SYMBIOTE_LIMITS``
environment variable. Nothing in the scanned checkout, its policy file included,
can change them.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace

ENV_VAR = "NEXUS_SYMBIOTE_LIMITS"
OPTION = "--limit"

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
TIB = 1024 * GIB

_SUFFIXES = {"kib": KIB, "mib": MIB, "gib": GIB}
_VALUE = re.compile(r"([0-9]{1,20})[ \t]*([KkMmGg][Ii][Bb])?")


class LimitError(ValueError):
    """A limit setting is malformed, unknown, repeated or out of range."""


@dataclass(frozen=True)
class LimitSpec:
    """One operator-settable limit: its name, unit, accepted range and meaning."""

    name: str
    unit: str
    maximum: int
    summary: str

    @property
    def attribute(self) -> str:
        return self.name.replace("-", "_")


SPECS: dict[str, LimitSpec] = {
    spec.name: spec
    for spec in (
        LimitSpec(
            "file-bytes",
            "bytes",
            GIB,
            "Size of one file a collector reads into memory: configuration, "
            "manifests, instructions and candidate source files.",
        ),
        LimitSpec(
            "total-bytes",
            "bytes",
            64 * GIB,
            "Bytes one collector reads in total, except model weights; the mcp, a2a, rag "
            "and source collectors, which also search source, may read source-scan-bytes more, "
            "which alone bounds the files a ShadowScan report cites.",
        ),
        LimitSpec(
            "entries",
            "count",
            10_000_000,
            "Directory entries listed by walks and exact-name checks in one collection; "
            "also the independent bound on project-policy discovery.",
        ),
        LimitSpec(
            "depth",
            "count",
            256,
            "Directory nesting below the project root that a walk descends into.",
        ),
        LimitSpec(
            "model-bytes",
            "bytes",
            TIB,
            "Size of one model weight or tokenizer file that is inspected and hashed.",
        ),
        LimitSpec(
            "model-total-bytes",
            "bytes",
            16 * TIB,
            "Bytes the model collector reads in total, weights included.",
        ),
        LimitSpec(
            "source-scan-bytes",
            "bytes",
            64 * GIB,
            "Bytes of Python, TypeScript and JavaScript source one collector reads while "
            "it looks for references: the mcp collector's SDK and tool references, the "
            "a2a collector's SDK references, the rag collector's vector-store imports and "
            "the source collector's model identifiers; "
            "also the files of any type that a ShadowScan report cites.",
        ),
        LimitSpec(
            "syntax-bytes",
            "bytes",
            64 * MIB,
            "Size of one source file the mcp or source collector parses: a file with an "
            "MCP SDK, agent framework or other SDK reference.",
        ),
        LimitSpec(
            "ts-nodes",
            "count",
            10_000_000,
            "Syntax nodes in one TypeScript or JavaScript file the mcp collector parses.",
        ),
        LimitSpec(
            "python-nodes",
            "count",
            10_000_000,
            "Syntax nodes in one Python file the mcp or source collector parses.",
        ),
        LimitSpec(
            "import-lookups",
            "count",
            1_000_000,
            "Memory and context files whose @path imports the prompt collector follows, "
            "and distinct import targets it looks up, in one collection.",
        ),
        LimitSpec(
            "prompt-files",
            "count",
            1_000_000,
            "Text files under prompts directories, and *.prompt.md, *.prompt.yaml and "
            "*.prompt.yml files, that the prompt collector records in one collection.",
        ),
        LimitSpec(
            "advisory-matches",
            "count",
            1_000_000_000,
            "Advisory records `advisories --offline-db` matches to package versions in one "
            "run, before aliases merge; evaluating a range with many events counts too.",
        ),
    )
}


@dataclass(frozen=True)
class CollectionLimits:
    """The limits one command collects under; defaults apply unless the operator sets one."""

    file_bytes: int = 4 * MIB
    total_bytes: int = 32 * MIB
    entries: int = 100_000
    depth: int = 64
    model_bytes: int = 64 * GIB
    model_total_bytes: int = 256 * GIB
    source_scan_bytes: int = 64 * MIB
    syntax_bytes: int = 256 * KIB
    ts_nodes: int = 20_000
    python_nodes: int = 200_000
    import_lookups: int = 5_000
    prompt_files: int = 5_000
    advisory_matches: int = 2_000_000

    def value(self, name: str) -> int:
        value: int = getattr(self, SPECS[name].attribute)
        return value


DEFAULTS = CollectionLimits()


def format_value(name: str, value: int) -> str:
    """Render a limit value the way an operator would write it."""
    spec = SPECS.get(name)
    if spec is None or spec.unit != "bytes":
        return str(value)
    for suffix, size in (("GiB", GIB), ("MiB", MIB), ("KiB", KIB)):
        if value >= size and value % size == 0:
            return f"{value // size} {suffix}"
    return f"{value} byte" if value == 1 else f"{value} bytes"


@dataclass(frozen=True)
class Bound:
    """A bound one collection enforces, and whether the operator can raise it.

    ``shown`` states the value in a failure when the bound adds another limit to the
    named one, so that the failure gives the numbers the operator set.
    """

    value: int
    name: str
    configurable: bool = True
    shown: str | None = None

    def exceeded(self) -> str:
        shown = format_value(self.name, self.value) if self.shown is None else self.shown
        if self.configurable:
            return f"{self.name} limit of {shown} exceeded; raise it with {OPTION} {self.name}=N"
        return f"{self.name} limit of {shown} exceeded; this limit is fixed for this input"


def _parse_value(spec: LimitSpec, text: str) -> int:
    match = _VALUE.fullmatch(text.strip())
    if match is None or (match.group(2) and spec.unit != "bytes"):
        expected = (
            "a whole number of bytes, optionally followed by KiB, MiB or GiB"
            if spec.unit == "bytes"
            else "a whole number"
        )
        raise LimitError(f"{spec.name} needs {expected}")
    value = int(match.group(1)) * _SUFFIXES.get((match.group(2) or "").lower(), 1)
    if not 1 <= value <= spec.maximum:
        raise LimitError(
            f"{spec.name} must be between 1 and {format_value(spec.name, spec.maximum)}"
        )
    return value


def parse_setting(text: str) -> tuple[str, int]:
    """Parse one ``NAME=VALUE`` setting; error messages never repeat what was supplied."""
    name, separator, value = text.partition("=")
    name = name.strip().lower().replace("_", "-")
    if not separator:
        raise LimitError(
            f"limit settings take the form NAME=VALUE, for example {OPTION} entries=200000"
        )
    spec = SPECS.get(name)
    if spec is None:
        close = difflib.get_close_matches(name, SPECS, n=1)
        hint = f"; did you mean {close[0]}?" if close else "."
        raise LimitError(f"unknown limit name{hint} Known limits: " + ", ".join(SPECS))
    return name, _parse_value(spec, value)


def _settings(items: Iterable[str], source: str) -> dict[str, int]:
    settings: dict[str, int] = {}
    for item in items:
        if not item.strip():
            continue
        name, value = parse_setting(item)
        if name in settings:
            raise LimitError(f"{name} is set more than once in {source}")
        settings[name] = value
    return settings


def resolve(options: Iterable[str], environ: Mapping[str, str]) -> CollectionLimits:
    """Combine the environment and ``--limit`` options; an option wins for its name."""
    settings = _settings(environ.get(ENV_VAR, "").split(","), ENV_VAR)
    settings.update(_settings(options, OPTION))
    return replace(DEFAULTS, **{SPECS[name].attribute: value for name, value in settings.items()})


_current: ContextVar[CollectionLimits] = ContextVar(
    "nexus_symbiote_collection_limits", default=DEFAULTS
)


def current() -> CollectionLimits:
    """The limits in force for this context; collectors read them when they run."""
    return _current.get()


def bound(name: str) -> Bound:
    """The operator-settable bound ``name`` as currently in force."""
    return Bound(current().value(name), name)


@contextmanager
def applied(limits: CollectionLimits) -> Iterator[CollectionLimits]:
    """Use ``limits`` for the duration of one command, then restore the previous ones."""
    token = _current.set(limits)
    try:
        yield limits
    finally:
        _current.reset(token)
