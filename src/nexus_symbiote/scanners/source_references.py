"""Vocabulary and records of the source collector.

The source collector reads what application source declares. Every record is a
declaration read from a file, never an observation of a running system, so each is
recorded at declared assurance with the file and line it was read from, and what a
reader could not resolve is a named coverage gap.

This module holds what the readers share: what an identifier must look like to be
recorded, the routing prefixes a model router reads off the front of one, and the
accumulator that turns the readers' records into components.
"""

from __future__ import annotations

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
# A long run of hex or of base64 with no separator, or user information before an
# ``@``: what a key, a token or a connection string looks like, and no model's name.
_SECRET_SHAPED = re.compile(r"[0-9A-Fa-f]{32,}|[A-Za-z0-9+/]{40,}={0,2}|[^@:/]+:[^@/]*@.+")
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
# The routing prefix a model router reads off the front of an identifier, and the
# provider it routes to.
ROUTES: dict[str, str] = {
    "anthropic": "anthropic", "azure": "azure-openai", "azure_ai": "azure-ai",
    "bedrock": "aws-bedrock", "bedrock_converse": "aws-bedrock", "cerebras": "cerebras",
    "cohere": "cohere", "cohere_chat": "cohere", "deepseek": "deepseek", "fireworks": "fireworks",
    "fireworks_ai": "fireworks", "gemini": "google", "google-gla": "google",
    "google-vertex": "google-vertex-ai", "google_genai": "google",
    "google_vertexai": "google-vertex-ai", "groq": "groq", "huggingface": "huggingface",
    "mistral": "mistral", "mistralai": "mistral", "nvidia_nim": "nvidia", "ollama": "ollama",
    "ollama_chat": "ollama", "openai": "openai", "openrouter": "openrouter",
    "perplexity": "perplexity", "replicate": "replicate", "sagemaker": "aws-sagemaker",
    "together": "together", "together_ai": "together", "vertex_ai": "google-vertex-ai",
    "watsonx": "ibm-watsonx", "xai": "xai",
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
LOCAL_PROVIDERS = frozenset({"huggingface", "ollama"})


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
    if text.startswith(("./", "../", "/", "~")) or not unchanged_by_redaction(text):
        return None
    if _SECRET_SHAPED.fullmatch(text):
        return None
    return text


def placeholder(text: str) -> bool:
    """Whether a model argument's text names no model on purpose, such as ``default``."""
    return not text.strip() or text.strip().lower() in _NOT_A_MODEL


def split_route(literal: str, *, weights: bool = False) -> tuple[str, str | None]:
    """The model identifier and the provider a routing prefix on ``literal`` names.

    ``openai/gpt-4o`` and ``anthropic:claude-sonnet-4-5`` are a route and an
    identifier. An identifier read by a library that loads weights, which
    ``weights`` says, is never split: there the part before the slash is the owner.
    """
    if weights:
        return literal, None
    for separator in ("/", ":"):
        prefix, found, rest = literal.partition(separator)
        if not found or not rest:
            continue
        provider = ROUTES.get(prefix.lower())
        if provider is None:
            continue
        owned = _HUB_OWNED.get(prefix.lower()) if separator == "/" else None
        if owned is not None and owned.match(rest):
            continue
        if model_identifier(rest) is None:
            continue
        return rest, provider
    return literal, None


def model_kind(name: str, *, embedding: bool = False) -> str | None:
    if name.startswith("ft:"):
        return "fine-tuned"
    if embedding or _EMBEDDING.search(name):
        return "embedding"
    return None


def environment_name(name: object) -> str | None:
    if isinstance(name, str) and _ENVIRONMENT_NAME.fullmatch(name) and unchanged_by_redaction(name):
        return name
    return None


def model_ref(name: str) -> str:
    return f"model:source:{quote(name, safe='._:@+-')}"


@dataclass
class _Model:
    name: str
    locations: set[tuple[str, int]] = field(default_factory=set)
    providers: set[str] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)
    aliases: set[str] = field(default_factory=set)
    environment: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    remote_code: bool = False


def _evidence(locations: Iterable[tuple[str, int]]) -> list[str]:
    return [f"{path}:{line}" for path, line in sorted(locations)[:MAX_EVIDENCE_LOCATIONS]]


class Declarations:
    """What the readers found, keyed so that a second sighting adds evidence, not a twin.

    A model is one component for the project, whatever the number of files that name
    it. ``components`` returns the records in an order that depends only on what was
    read.
    """

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        self._models: dict[str, _Model] = {}
        self._written: dict[str, str | None] = {}
        self.unresolved_environment: dict[str, set[tuple[str, int]]] = {}
        self._environment: set[str] = set()
        self._gaps: set[str] = set()
        self._full = False

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
        weights: bool = False,
        environment: str | None = None,
        remote_code: bool = False,
    ) -> str | None:
        """Record one reference to a model and return its component reference.

        A provider is recorded only when a routing prefix on the identifier names it.
        ``remote_code`` says the call that loads it lets the model run its own code.
        """
        if not isinstance(literal, str):
            return None
        if literal not in self._written:
            # Each text is judged once: a file may give the same text at every call.
            if len(self._written) >= MAX_RECORDS:
                self._written.clear()
            self._written[literal] = model_identifier(literal)
        written = self._written[literal]
        if written is None:
            return None
        name, routed = split_route(written, weights=weights)
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
        record.locations.add((path, line))
        record.methods.add(method)
        if routed:
            record.providers.add(routed)
        kind = model_kind(name, embedding=embedding)
        if kind:
            record.kinds.add(kind)
        if written != name:
            record.aliases.add(written)
        if environment and environment_name(environment):
            record.environment.add(environment)
            self._environment.add(environment)
        record.remote_code = record.remote_code or remote_code
        return model_ref(name)

    def close(self) -> None:
        """Name each model that only an environment variable sets, with no value in the project."""
        for name in sorted(self.unresolved_environment):
            if name in self._environment:
                continue
            path, line = min(self.unresolved_environment[name])
            self.gap(
                path,
                line,
                f"model set by environment variable {name}, which no file of the project "
                "gives a value; not inventoried",
            )

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
            if len(model.locations) > MAX_EVIDENCE_LOCATIONS:
                properties["references_unlisted"] = len(model.locations) - MAX_EVIDENCE_LOCATIONS
            if len(model.providers) > 1:
                properties["providers"] = sorted(model.providers)
            if len(model.aliases) > 1:
                properties["requested_aliases"] = sorted(model.aliases)
            if model.environment:
                properties["environment_variables"] = sorted(model.environment)
            provider = next(iter(model.providers)) if len(model.providers) == 1 else None
            kind = (
                "fine-tuned"
                if "fine-tuned" in model.kinds
                else "embedding"
                if "embedding" in model.kinds
                else "hosted"
                if provider is not None and provider not in LOCAL_PROVIDERS
                else None
            )
            built.append(
                ModelComponent(
                    bom_ref=model_ref(name),
                    name=name,
                    model_type=kind,
                    provider=provider,
                    requested_alias=(
                        next(iter(model.aliases)) if len(model.aliases) == 1 else None
                    ),
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
