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
# A long run of hex or base64, or user information before an ``@``: a key's shape, no name's.
_SECRET_SHAPED = re.compile(
    r"[0-9A-Fa-f]{32}|[0-9A-Fa-f-]{48}|(?:^|:)[A-Za-z0-9+/]{40,}={0,2}$"
    r"|(?:^|/)[^@:/]+:[^@/]+@(?![0-9]+$)"
)
# A model pinned by its version's digest, which is a hash, not a key.
_PINNED = re.compile(r"[\w.-]+/[\w.-]+:[0-9a-f]{64}")
# A host path, after a route or none: a drive with a path, a share, the root, a home or ``//``.
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
# The routing prefix a model router reads off an identifier, and its provider, named as
# OpenTelemetry's ``gen_ai.provider.name`` names it where it names one.
ROUTES: dict[str, str] = {
    "anthropic": "anthropic", "azure": "azure.ai.openai", "azure_ai": "azure.ai.inference",
    "azure_openai": "azure.ai.openai", "bedrock": "aws.bedrock", "bedrock_converse": "aws.bedrock",
    "cerebras": "cerebras", "cohere": "cohere", "cohere_chat": "cohere", "deepseek": "deepseek",
    "fireworks": "fireworks", "fireworks_ai": "fireworks", "gemini": "gcp.gemini",
    "google-gla": "gcp.gemini", "google-vertex": "gcp.vertex_ai", "google_anthropic_vertex":
    "gcp.vertex_ai", "google_genai": "gcp.gemini", "google_vertexai": "gcp.vertex_ai",
    "grok": "x_ai", "groq": "groq", "huggingface": "huggingface", "ibm": "ibm.watsonx.ai",
    "mistral": "mistral_ai", "mistralai": "mistral_ai", "nvidia_nim": "nvidia", "ollama": "ollama",
    "ollama_chat": "ollama", "openai": "openai", "openai-chat": "openai",
    "openai-responses": "openai", "openrouter": "openrouter", "perplexity": "perplexity",
    "replicate": "replicate", "sagemaker": "aws.sagemaker", "together": "together",
    "together_ai": "together", "vertex_ai": "gcp.vertex_ai", "watsonx": "ibm.watsonx.ai",
    "xai": "x_ai",
}  # fmt: skip
# Routing prefixes that are also the owner of weights on a model hub, with the names
# that owner publishes there: such an identifier is the owner and the name together.
_HUB_OWNED: dict[str, re.Pattern[str]] = {
    "mistralai": re.compile(""),
    "openai": re.compile(
        r"(?i)(?:whisper-(?:tiny|base|small|medium|large)|clip|gpt2|gpt-oss|shap-e|jukebox)"
    ),
}
# Providers that serve a model from weights on the machine, so no hosted service is named.
LOCAL_PROVIDERS = frozenset({"ollama"})


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
    """Whether a model argument's text is no model and no gap: a placeholder or a project file."""
    text = text.strip()
    local = text.startswith(("./", "../", ".\\", "..\\")) or text.lower().endswith(_FILE_SUFFIXES)
    return not text or text.lower() in _NOT_A_MODEL or local and not _ABSOLUTE.search(text)


def split_route(literal: str, separators: str = "/:") -> tuple[str, str | None]:
    """The model identifier and the provider a routing prefix on ``literal`` names:
    ``openai/gpt-4o`` and ``anthropic:claude-sonnet-4-5`` are a route and an identifier.
    Only a call that routes by prefix reads it so, by its own separators and only as
    written: a router's prefixes are lower case, so ``Groq/`` is an owner on a model hub.
    A route before what is no identifier gives no name."""
    for separator in separators:
        prefix, found, rest = literal.partition(separator)
        provider = ROUTES.get(prefix) if found else None
        owned = _HUB_OWNED.get(prefix) if separator == "/" else None
        if provider is None or owned is not None and owned.match(rest):
            continue
        if prefix == "bedrock":
            # LiteLLM's ``converse/`` and ``invoke/`` choose Bedrock's API, not a model.
            rest = rest.removeprefix("converse/").removeprefix("invoke/")
        elif prefix == "huggingface" and rest.count("/") > 1:
            # Before a hub's owner/name, a provider that serves it for Hugging Face.
            rest = rest.split("/", 1)[1]
        return (rest, provider) if model_identifier(rest) is not None else ("", provider)
    return literal, None


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


def model_ref(name: str, provider: str | None = None) -> str:
    # One name routed to two providers may be two models, as an opaque deployment is.
    qualifier = f"?provider={quote(provider, safe='-')}" if provider else ""
    return f"model:source:{quote(name, safe='._:@+-')}{qualifier}"


@dataclass
class _Model:
    name: str
    locations: set[tuple[str, int]] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)
    aliases: set[str] = field(default_factory=set)
    environment: set[str] = field(default_factory=set)
    environment_unlisted: bool = False
    methods: set[str] = field(default_factory=set)
    remote_code: bool = False
    count: int = 0


def _evidence(locations: Iterable[tuple[str, int]]) -> list[str]:
    return [f"{path}:{line}" for path, line in sorted(locations)[:MAX_EVIDENCE_LOCATIONS]]


class Declarations:
    """What the readers found: one component for each model, in an order fixed by what was read."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        self._models: dict[tuple[str, str | None], _Model] = {}
        self._written: dict[str, str | None] = {}
        self._routed: dict[tuple[str, str], tuple[str, str | None]] = {}
        self._gaps: set[str] = set()
        self._full = False
        self._path = ""
        self._lines: set[tuple[tuple[str, str | None], int]] = set()
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
        routes: str = "",
        remote_code: bool = False,
        environment: Iterable[str] = (),
    ) -> str | None:
        """Record one reference to a model. ``routes`` holds the separators by which the call
        reads a routing prefix on the identifier, which then names the provider, so the model
        is one component for each provider it is routed to; ``remote_code`` says its call
        lets it run its code, and ``environment`` names the variables that, when set, give
        another model."""
        if not isinstance(literal, str):
            return None
        if literal not in self._written:
            # Each text is judged once, and one longer than any identifier is not kept.
            if len(self._written) >= MAX_RECORDS:
                self._written.clear()
            self._written[literal] = model_identifier(literal)
        written = self._written[literal] if len(literal) <= 256 else self._written.pop(literal)
        if written is None:
            return None
        if (written, routes) not in self._routed:
            # Each split is worked out once, as each text is judged once.
            if len(self._routed) >= MAX_RECORDS:
                self._routed.clear()
            self._routed[(written, routes)] = split_route(written, routes)
        name, routed = self._routed[(written, routes)]
        if not name:
            # A route this call reads, before what can be no model's name.
            return None
        key = (name, routed)
        record = self._models.get(key)
        if record is None:
            if len(self._models) >= MAX_RECORDS:
                if not self._full:
                    self._full = True
                    self.result.scan_failures.append(
                        f"source: more than {MAX_RECORDS} model identifiers; the rest were not "
                        "recorded"
                    )
                return None
            record = self._models[key] = _Model(name)
        if path != self._path:
            self._path, self._lines = path, set()
        if (key, line) not in self._lines:
            # A place repeats only within its file, which is read whole before the next.
            self._lines.add((key, line))
            record.count += 1
            record.locations.add((path, line))
            if len(record.locations) > MAX_EVIDENCE_LOCATIONS:
                record.locations.discard(max(record.locations))
        record.methods.add(method)
        kind = model_kind(name, embedding=embedding)
        if kind:
            record.kinds.add(kind)
        if written != name:
            record.aliases.add(written)
        record.remote_code = record.remote_code or remote_code
        # Each name was checked where it was read; one is checked again once for a model.
        record.environment.update(
            filter(environment_name, frozenset(environment) - record.environment)
        )
        if len(record.environment) > MAX_EVIDENCE_LOCATIONS:
            # The first names in order are kept, as the first places are.
            record.environment = set(sorted(record.environment)[:MAX_EVIDENCE_LOCATIONS])
            record.environment_unlisted = True
        return model_ref(name, routed)

    def close(self) -> None:
        """Name each model that only an environment variable sets, once for each file that
        reads it so: a value another read gives does not stand for this one."""
        for (path, name), line in sorted(self.unresolved_environment.items()):
            self.gap(path, line, f"model set only by environment variable {name}; not inventoried")

    def components(self) -> list[AnyComponent]:
        built: list[AnyComponent] = []
        for name, provider in sorted(self._models, key=lambda key: (key[0], key[1] or "")):
            model = self._models[(name, provider)]
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
            if len(model.aliases) > 1:
                properties["requested_aliases"] = sorted(model.aliases)
            if model.environment_unlisted:
                properties["environment_variables_unlisted"] = True
            kind = "fine-tuned" if "fine-tuned" in model.kinds else min(model.kinds, default=None)
            if kind is None and provider is not None and provider not in LOCAL_PROVIDERS:
                kind = "hosted"
            built.append(
                ModelComponent(
                    bom_ref=model_ref(name, provider),
                    name=name,
                    model_type=kind,
                    provider=provider,
                    requested_alias=next(iter(model.aliases)) if len(model.aliases) == 1 else None,
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
