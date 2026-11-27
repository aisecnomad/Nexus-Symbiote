"""Vocabulary and records of the source collector: what an identifier must look like to
be recorded, and the accumulator that turns the readers' records into components, each a
declaration with the file and line it was read from.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from nexus_symbiote.core.collection import SOURCE_REFERENCE_MODE
from nexus_symbiote.core.enums import AssuranceLevel, TrustTier
from nexus_symbiote.core.models import AnyComponent, ClaimEvidence, ModelComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.model import MODEL_EXTENSIONS, NAMED_MODEL_FILES
from nexus_symbiote.utils.secrets import holds_token_shape, redact_text

COLLECTOR = "source"
REFERENCE_CLAIM = "source_reference"
MAX_EVIDENCE_LOCATIONS = 16
MAX_RECORDS = 5_000

_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{1,127}")
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,63}")
_RUN = re.compile(r"[A-Za-z0-9]{24,}")
# A long run of hex or of base64 with no separator, or user information before an
# ``@``: what a key, a token or a connection string looks like, and no model's name.
_SECRET_SHAPED = re.compile(
    r"[0-9A-Fa-f]{32}|[0-9A-Fa-f-]{48}|^[A-Za-z0-9+/]{40,}={0,2}$|^[^@:/]+:[^@/]+@(?![0-9]+$)"
)
# A model pinned by its version's digest, which is a hash, not a key.
_PINNED = re.compile(r"[\w.-]+/[\w.-]+:[0-9a-f]{64}")
# A path on this or another host, after a routing prefix or none: a drive with a path, a
# share, the root or a home directory. No identifier holds ``//``.
_ABSOLUTE = re.compile(r"(?:^|[:/@])(?:[A-Za-z]:(?=[^:]*[\\/])|\\\\|/|~)")
# Words a model argument holds that name no model on purpose.
_NOT_A_MODEL = frozenset(
    {
        "auto", "default", "dummy", "fake", "false", "mock", "model", "model-id", "model-name",
        "model_id", "model_name", "my-model", "none", "null", "str", "string", "test", "true",
        "your-model",
    }
)  # fmt: skip
# A model argument that ends like this names a file, which the model collector reads.
_FILE_SUFFIXES = (
    *MODEL_EXTENSIONS,
    *NAMED_MODEL_FILES,
    *[".json", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"],
)
_EMBEDDING = re.compile(
    r"(?i)(?:embed|bge-|e5-|gte-|minilm|mpnet|gecko|arctic-embed|voyage-|jina-|rerank)"
)


def unchanged_by_redaction(text: str) -> bool:
    """Whether exported ``text`` would be the text as written: no token shape in it."""
    return redact_text(text) == text and not holds_token_shape(text)


def model_identifier(literal: object) -> str | None:
    """``literal`` when it can be recorded as a model identifier, else None."""
    if not isinstance(literal, str):
        return None
    text = literal.strip()
    if _MODEL_ID.fullmatch(text) is None or not any(c.isalpha() for c in text):
        return None
    lowered = text.lower()
    if lowered in _NOT_A_MODEL or lowered.endswith(_FILE_SUFFIXES) or "://" in text:
        return None
    if text.startswith(("./", "../")) or _ABSOLUTE.search(text):
        return None
    if _SECRET_SHAPED.search(text) and not _PINNED.fullmatch(text):
        return None
    return text if unchanged_by_redaction(text) else None


def placeholder(text: str) -> bool:
    """Whether a model argument's text names no hosted model and is no gap: a word such as
    ``default``, or a path or weight file in the project, which the model collector reads."""
    text = text.strip()
    local = text.startswith(("./", "../", ".\\", "..\\")) or text.lower().endswith(_FILE_SUFFIXES)
    return not text or text.lower() in _NOT_A_MODEL or local and not _ABSOLUTE.search(text)


def model_kind(name: str, *, embedding: bool = False) -> str | None:
    if name.startswith("ft:"):
        return "fine-tuned"
    if embedding or _EMBEDDING.search(name):
        return "embedding"
    return None


@functools.lru_cache(maxsize=4096)
def environment_name(name: object) -> str | None:
    """``name`` when it can be exported as the name of an environment variable: one shaped
    like a key, a long run of hex or of letters and digits not all in capitals, is not."""
    if not isinstance(name, str) or not _ENVIRONMENT_NAME.fullmatch(name):
        return None
    keylike = _SECRET_SHAPED.search(name) or any(not run.isupper() for run in _RUN.findall(name))
    return None if keylike or not unchanged_by_redaction(name) else name


def model_ref(name: str) -> str:
    return f"model:source:{quote(name, safe='._:@+-')}"


@dataclass
class _Model:
    name: str
    locations: set[tuple[str, int]] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)
    environment: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    remote_code: bool = False
    count: int = 0


def _evidence(locations: Iterable[tuple[str, int]]) -> list[str]:
    return [f"{path}:{line}" for path, line in sorted(locations)[:MAX_EVIDENCE_LOCATIONS]]


class Declarations:
    """What the readers found: a model is one component for the project, however many files
    name it, and ``components`` lists them in an order that depends only on what was read."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        self._models: dict[str, _Model] = {}
        self._written: dict[str, str | None] = {}
        self._gaps: set[str] = set()
        self._full = False
        self._path = ""
        self._lines: set[tuple[str, int]] = set()
        # Where each file first reads a variable that alone sets a model, with no value.
        self.unresolved_environment: dict[tuple[str, str], int] = {}

    def gap(self, path: str, line: int, reason: str) -> None:
        text = f"{path}:{line}: {reason}"
        if text not in self._gaps:
            self._gaps.add(text)
            self.result.surfaces_excluded.append(text)

    def model(
        self,
        literal: object,
        path: str,
        line: int,
        *,
        method: str,
        embedding: bool = False,
        remote_code: bool = False,
        environment: Iterable[str] = (),
    ) -> str | None:
        """Record one reference to a model; ``remote_code`` says its call lets it run its
        code, and ``environment`` names the variables that, when set, give another model."""
        if not isinstance(literal, str):
            return None
        if literal not in self._written:
            # Each text is judged once: a file may give the same text at every call. One
            # longer than any identifier is not kept, so the memory does not grow with it.
            if len(self._written) >= MAX_RECORDS:
                self._written.clear()
            self._written[literal] = model_identifier(literal)
        name = self._written[literal] if len(literal) <= 256 else self._written.pop(literal)
        if name is None:
            return None
        record = self._models.get(name)
        if record is None:
            if len(self._models) >= MAX_RECORDS:
                if not self._full:
                    self._full = True
                    self.result.scan_failures.append(
                        f"source: more than {MAX_RECORDS} model identifiers; the rest were not "
                        "recorded"
                    )
                return None
            record = self._models[name] = _Model(name)
        if path != self._path:
            self._path, self._lines = path, set()
        if (name, line) not in self._lines:
            # A place repeats only within its file, which is read whole before the next.
            self._lines.add((name, line))
            record.count += 1
            record.locations.add((path, line))
            if len(record.locations) > MAX_EVIDENCE_LOCATIONS:
                record.locations.discard(max(record.locations))
        record.methods.add(method)
        kind = model_kind(name, embedding=embedding)
        if kind:
            record.kinds.add(kind)
        record.remote_code = record.remote_code or remote_code
        # Each name was checked where it was read; one is checked again once for a model.
        record.environment.update(
            filter(environment_name, frozenset(environment) - record.environment)
        )
        return model_ref(name)

    def close(self) -> None:
        """Name each model that only an environment variable sets, once for each file that
        reads it so: a value another read gives does not stand for this one."""
        for (path, name), line in sorted(self.unresolved_environment.items()):
            self.gap(path, line, f"model set only by environment variable {name}; not inventoried")

    def components(self) -> list[AnyComponent]:
        built: list[AnyComponent] = []
        for name in sorted(self._models):
            model = self._models[name]
            listed = _evidence(model.locations)
            first = min(model.locations)
            method = sorted(model.methods)[0]
            properties: dict[str, Any] = {
                "collection_mode": SOURCE_REFERENCE_MODE,
                "method": method,
                "declaration_line": first[1],
                "reference_path": first[0],
            }
            if model.count > MAX_EVIDENCE_LOCATIONS:
                properties["references_unlisted"] = model.count - MAX_EVIDENCE_LOCATIONS
            if model.environment:
                properties["environment_variables"] = sorted(model.environment)
            kind = "fine-tuned" if "fine-tuned" in model.kinds else min(model.kinds, default=None)
            built.append(
                ModelComponent(
                    bom_ref=model_ref(name),
                    name=name,
                    model_type=kind,
                    trust_tier=TrustTier.UNKNOWN,
                    assurance_level=AssuranceLevel.DECLARED,
                    # Code that lets a model run its own code says so; it is no bare name.
                    trust_remote_code=True if model.remote_code else None,
                    properties=properties,
                    claims={
                        REFERENCE_CLAIM: ClaimEvidence(
                            assurance=AssuranceLevel.DECLARED,
                            method=method,
                            scope="repository",
                            collector=COLLECTOR,
                            locator=listed[0],
                            evidence_refs=listed if len(listed) > 1 else [],
                        )
                    },
                )
            )
        return built
