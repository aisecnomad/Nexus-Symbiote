"""Vocabulary and records of the source collector.

The source collector reads what application source declares: hosted model
identifiers, agents and what they are given, tools, MCP servers started or reached
from code, guardrails, memory and retrieval stores, and the names of credential
environment variables. Every record is a declaration read from a file. None is an
observation of a running system, so each is recorded at declared assurance with the
file and line it was read from, and what a reader could not resolve is a named
coverage gap.

This module holds what the readers share: which modules and packages belong to which
provider, what an identifier must look like to be recorded, and the accumulator that
turns the readers' records into components.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

from nexus_symbiote.core.enums import AssuranceLevel, TrustTier
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    ClaimEvidence,
    DataSourceComponent,
    GuardrailComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    ModelComponent,
    RAGSourceComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.base import ScanResult, sanitized_origin
from nexus_symbiote.utils.secrets import holds_token_shape, redact_text

COLLECTOR = "source"
REFERENCE_MODE = "static-source-reference"
DECLARATION_MODE = "static-source-declaration"
REFERENCE_CLAIM = "source_reference"
DECLARATION_CLAIM = "source_declaration"
CREDENTIAL_PROPERTY = "credential_environment_names"
MAX_EVIDENCE_LOCATIONS = 16
MAX_RECORDS = 5_000
MAX_NAME_CHARS = 128

_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{1,127}")
_DECLARED_NAME = re.compile(r"(?=.*[A-Za-z0-9])[A-Za-z0-9_][A-Za-z0-9_ .:/()&'+-]{0,127}")
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,63}")
_CREDENTIAL_WORD = re.compile(
    r"(?:^|_)(?:API_?KEY|APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIALS?|ACCESS_KEY|"
    r"SECRET_KEY|PRIVATE_KEY|AUTH|PAT|KEY|DSN|CONNECTION_STRING)(?:_|$)"
)
# Words a model argument holds that name no model.
_NOT_A_MODEL = frozenset(
    {
        "auto",
        "default",
        "dummy",
        "fake",
        "false",
        "mock",
        "model",
        "model-id",
        "model-name",
        "model_id",
        "model_name",
        "my-model",
        "none",
        "null",
        "str",
        "string",
        "test",
        "true",
        "your-model",
    }
)
# A model argument that ends like this names a file, which the model collector reads.
_FILE_SUFFIXES = (
    ".bin",
    ".ckpt",
    ".gguf",
    ".h5",
    ".joblib",
    ".json",
    ".md",
    ".onnx",
    ".pkl",
    ".pt",
    ".pth",
    ".py",
    ".safetensors",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
)
# Identifiers of the model families a hosted or local runtime serves. An identifier
# read from a place that does not itself say "this is a model", such as a
# configuration key or a constant, is recorded only when it belongs to one.
_FAMILY = re.compile(
    r"(?i)^(?:"
    r"(?:chat)?gpt-|o[134](?:-|$)|text-embedding-|text-davinci|text-moderation|omni-moderation|"
    r"whisper|dall-e|tts-|gpt-image|davinci|babbage|computer-use|codex-|"
    r"claude|gemini|gemma|palm-|text-bison|chat-bison|textembedding-gecko|text-multilingual|"
    r"imagen|veo-|learnlm|"
    r"llama|codellama|meta-llama|mistral|mixtral|codestral|pixtral|ministral|magistral|"
    r"devstral|open-mistral|open-mixtral|command(?:-|$)|embed-(?:english|multilingual|v)|"
    r"rerank-|c4ai-|deepseek|qwen|qwq|phi-?[1-9]|grok-|sonar|pplx-|nova-|titan|"
    r"amazon\.|anthropic\.|meta\.|cohere\.|mistral\.|ai21\.|stability\.|deepseek\.|writer\.|"
    r"(?:us|eu|apac|global)\.(?:amazon|anthropic|meta|cohere|mistral|deepseek|writer)\.|"
    r"nomic-embed|bge-|all-minilm|all-mpnet|e5-|gte-|mxbai-|snowflake-arctic|voyage-|jina-|"
    r"granite|shieldgemma|llava|starcoder|wizardlm|vicuna|zephyr|solar-|glm-|kimi-|moonshot-|"
    r"yi-|ernie|hermes|dolphin|tinyllama|smollm|orca-|neural-chat|stable-diffusion|sdxl|flux|"
    r"ft:|accounts/fireworks/models/|models/(?:gemini|gemma|text-embedding|embedding)|"
    r"tunedmodels/"
    r")"
)
# The vendor whose service an identifier's family is served by, and the services of
# other names that serve the same family.
_VENDOR_FAMILIES: tuple[tuple[re.Pattern[str], frozenset[str]], ...] = (
    (
        re.compile(
            r"(?i)^(?:(?:chat)?gpt-|o[134](?:-|$)|text-embedding-|text-davinci|whisper|dall-e|"
            r"tts-|gpt-image|omni-moderation|text-moderation|davinci|babbage|codex-|computer-use)"
        ),
        frozenset({"openai", "azure-openai", "openrouter"}),
    ),
    (
        re.compile(r"(?i)^claude"),
        frozenset({"anthropic", "aws-bedrock", "google-vertex-ai", "openrouter"}),
    ),
    (
        re.compile(r"(?i)^(?:models/)?(?:gemini|text-bison|chat-bison|textembedding-gecko|imagen)"),
        frozenset({"google", "google-vertex-ai", "openrouter"}),
    ),
    (re.compile(r"(?i)^grok-"), frozenset({"xai", "openrouter"})),
    (re.compile(r"(?i)^(?:sonar|pplx-)"), frozenset({"perplexity", "openrouter"})),
    (
        re.compile(r"(?i)^(?:command(?:-|$)|embed-(?:english|multilingual|v)|rerank-)"),
        frozenset({"cohere", "aws-bedrock", "openrouter"}),
    ),
)
_HUB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")
_HUB_OWNERS = frozenset(
    {
        "baai",
        "bigcode",
        "cohere",
        "cohereforai",
        "cross-encoder",
        "deepseek-ai",
        "facebook",
        "google",
        "google-bert",
        "huggingfaceh4",
        "huggingfacetb",
        "ibm-granite",
        "intfloat",
        "jinaai",
        "meta-llama",
        "microsoft",
        "mistralai",
        "mixedbread-ai",
        "nomic-ai",
        "nvidia",
        "openai",
        "protectai",
        "qwen",
        "sentence-transformers",
        "snowflake",
        "stabilityai",
        "thebloke",
        "thenlper",
        "tiiuae",
        "unsloth",
    }
)
_SAFETY_CLASSIFIER = re.compile(
    r"(?i)(?:llama-?guard|prompt-?guard|shieldgemma|granite-guardian|text-moderation|"
    r"omni-moderation|deberta-v3-base-prompt-injection|wildguard|nemoguard)"
)
_EMBEDDING = re.compile(
    r"(?i)(?:embed|bge-|e5-|gte-|minilm|mpnet|gecko|arctic-embed|voyage-|jina-|rerank)"
)
# The routing prefix a model router reads off the front of an identifier.
ROUTES: dict[str, str] = {
    "anthropic": "anthropic",
    "azure": "azure-openai",
    "azure_ai": "azure-ai",
    "bedrock": "aws-bedrock",
    "bedrock_converse": "aws-bedrock",
    "cerebras": "cerebras",
    "cohere": "cohere",
    "cohere_chat": "cohere",
    "deepseek": "deepseek",
    "fireworks": "fireworks",
    "fireworks_ai": "fireworks",
    "gemini": "google",
    "google-gla": "google",
    "google-vertex": "google-vertex-ai",
    "google_genai": "google",
    "google_vertexai": "google-vertex-ai",
    "groq": "groq",
    "huggingface": "huggingface",
    "mistral": "mistral",
    "mistralai": "mistral",
    "nvidia_nim": "nvidia",
    "ollama": "ollama",
    "ollama_chat": "ollama",
    "openai": "openai",
    "openrouter": "openrouter",
    "perplexity": "perplexity",
    "replicate": "replicate",
    "sagemaker": "aws-sagemaker",
    "together": "together",
    "together_ai": "together",
    "vertex_ai": "google-vertex-ai",
    "watsonx": "ibm-watsonx",
    "xai": "xai",
}
# Routing prefixes that are also the owner of weights on a model hub, with the names
# that owner publishes there: such an identifier is the owner and the name together.
_HUB_OWNED: dict[str, re.Pattern[str]] = {
    "mistralai": re.compile(""),
    "openai": re.compile(
        r"(?i)(?:whisper-(?:tiny|base|small|medium|large)|clip|gpt2|gpt-oss|shap-e|jukebox)"
    ),
}
_HOSTS: tuple[tuple[str, str], ...] = (
    ("api.openai.com", "openai"),
    (".openai.azure.com", "azure-openai"),
    (".cognitiveservices.azure.com", "azure-openai"),
    (".services.ai.azure.com", "azure-ai"),
    ("api.anthropic.com", "anthropic"),
    ("generativelanguage.googleapis.com", "google"),
    ("aiplatform.googleapis.com", "google-vertex-ai"),
    ("api.groq.com", "groq"),
    ("api.mistral.ai", "mistral"),
    ("api.cohere.com", "cohere"),
    ("api.cohere.ai", "cohere"),
    ("api.together.xyz", "together"),
    ("api.together.ai", "together"),
    ("openrouter.ai", "openrouter"),
    ("api.deepseek.com", "deepseek"),
    ("api.x.ai", "xai"),
    ("api.perplexity.ai", "perplexity"),
    ("api.fireworks.ai", "fireworks"),
    ("integrate.api.nvidia.com", "nvidia"),
    ("api.cerebras.ai", "cerebras"),
    ("api.replicate.com", "replicate"),
    ("api-inference.huggingface.co", "huggingface"),
    ("router.huggingface.co", "huggingface"),
    (".amazonaws.com", "aws-bedrock"),
)
_LOCAL_RUNTIME_PORTS = {11434: "ollama"}
# Providers that serve a model from weights on the machine, so no hosted service is named.
LOCAL_PROVIDERS = frozenset({"huggingface", "ollama"})
_UNSAFE = "[redacted]"


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
    return text


def known_family(name: str) -> bool:
    """Whether ``name`` is an identifier of a known model family, by its own text."""
    if _FAMILY.match(name):
        return True
    prefix, separator, rest = name.partition("/")
    if separator and prefix.lower() in ROUTES and _FAMILY.match(rest):
        return True
    prefix, separator, rest = name.partition(":")
    if separator and prefix.lower() in ROUTES and _FAMILY.match(rest):
        return True
    if _HUB_ID.fullmatch(name):
        owner, _, model = name.partition("/")
        return owner.lower() in _HUB_OWNERS or bool(_FAMILY.match(model))
    return False


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


def serves(provider: str, name: str) -> bool:
    """Whether ``provider`` is a service known to serve the family ``name`` belongs to.

    True for a family no vendor is known for: the answer is only used to withhold a
    framework's default service from an identifier that plainly belongs elsewhere.
    """
    for family, services in _VENDOR_FAMILIES:
        if family.match(name):
            return provider in services
    return True


def model_kind(name: str, *, embedding: bool = False) -> str | None:
    if name.startswith("ft:"):
        return "fine-tuned"
    if embedding or _EMBEDDING.search(name):
        return "embedding"
    return None


def safety_classifier(name: str) -> bool:
    return _SAFETY_CLASSIFIER.search(name) is not None


def endpoint_origin(value: object) -> str | None:
    """The scheme, host and port of an endpoint, or None when it cannot be exported."""
    if not isinstance(value, str) or len(value) > 2048 or "://" not in value:
        return None
    origin = sanitized_origin(value.strip())
    return None if origin == _UNSAFE else origin


def provider_of_endpoint(origin: str | None) -> str | None:
    if origin is None:
        return None
    try:
        parsed = urlsplit(origin)
        host, port = (parsed.hostname or "").lower(), parsed.port
    except ValueError:
        return None
    for suffix, provider in _HOSTS:
        if host == suffix or (suffix.startswith(".") and host.endswith(suffix)):
            return provider
    if host in {"localhost", "127.0.0.1", "::1", "host.docker.internal", "ollama"}:
        return _LOCAL_RUNTIME_PORTS.get(port or 0)
    return None


def credential_name(name: object) -> str | None:
    """``name`` when it is an environment variable named as a credential is named."""
    if not isinstance(name, str) or _ENVIRONMENT_NAME.fullmatch(name) is None:
        return None
    if _CREDENTIAL_WORD.search(name.upper()) is None or not unchanged_by_redaction(name):
        return None
    return name


def environment_name(name: object) -> str | None:
    if isinstance(name, str) and _ENVIRONMENT_NAME.fullmatch(name) and unchanged_by_redaction(name):
        return name
    return None


def declared_name(literal: object) -> str | None:
    """``literal`` when it can be exported as the name a declaration gives a component."""
    if not isinstance(literal, str):
        return None
    text = " ".join(literal.split())
    if _DECLARED_NAME.fullmatch(text) is None or not unchanged_by_redaction(text):
        return None
    return text


def _ref(kind: str, path: str, name: str) -> str:
    return f"{kind}:source:{quote(path, safe='')}/{quote(name, safe='')}"


def model_ref(name: str) -> str:
    return f"model:source:{quote(name, safe='._:@+-')}"


@dataclass
class _Model:
    name: str
    locations: set[tuple[str, int]] = field(default_factory=set)
    providers: set[str] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)
    aliases: set[str] = field(default_factory=set)
    environment: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    credentials: set[str] = field(default_factory=set)


@dataclass
class AgentRecord:
    """An agent a file declares, and the references its declaration holds."""

    ref: str
    path: str
    line: int
    name: str
    framework: str | None
    method: str
    digest: str | None
    models: set[str] = field(default_factory=set)
    tools: set[str] = field(default_factory=set)
    sub_agents: set[str] = field(default_factory=set)
    guardrails: set[str] = field(default_factory=set)
    memories: set[str] = field(default_factory=set)
    data: set[str] = field(default_factory=set)
    locations: set[tuple[str, int]] = field(default_factory=set)


@dataclass
class _Item:
    """A tool, guardrail, memory store, retrieval source or dataset a file declares."""

    ref: str
    path: str
    line: int
    name: str
    method: str
    digest: str | None
    properties: dict[str, Any] = field(default_factory=dict)
    fields: dict[str, Any] = field(default_factory=dict)


def _evidence(locations: Iterable[tuple[str, int]]) -> list[str]:
    return [f"{path}:{line}" for path, line in sorted(locations)[:MAX_EVIDENCE_LOCATIONS]]


class Declarations:
    """What the readers found, keyed so that a second sighting adds evidence, not a twin.

    A model is one component for the project, whatever the number of files that name
    it. Everything else belongs to the file that declares it. ``components`` returns
    them in an order that depends only on what was read.
    """

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        self._models: dict[str, _Model] = {}
        self._agents: dict[str, AgentRecord] = {}
        self._tools: dict[str, _Item] = {}
        self._guardrails: dict[str, _Item] = {}
        self._memories: dict[str, _Item] = {}
        self._sources: dict[str, _Item] = {}
        self._datasets: dict[str, _Item] = {}
        self._servers: dict[str, MCPServerComponent] = {}
        self._server_tools: list[ToolComponent] = []
        self.credentials: dict[str, set[tuple[str, int]]] = {}
        self._pending_credentials: dict[str, set[tuple[str, int]]] = {}
        self.references: dict[str, set[tuple[str, int]]] = {}
        self.unresolved_environment: dict[str, set[tuple[str, int]]] = {}
        self._environment: set[str] = set()
        self._parser: Any = None
        self._gaps: set[str] = set()
        self._full = False

    # -- records -----------------------------------------------------------------

    def _room(self, records: dict[str, Any]) -> bool:
        if len(records) < MAX_RECORDS:
            return True
        if not self._full:
            self._full = True
            self.result.scan_failures.append(
                f"source: more than {MAX_RECORDS} declarations of one kind; the rest were not "
                "recorded"
            )
        return False

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
        provider: str | None = None,
        default_provider: str | None = None,
        endpoint: str | None = None,
        embedding: bool = False,
        weights: bool = False,
        environment: str | None = None,
        credentials: Iterable[str] = (),
        require_family: bool = False,
    ) -> str | None:
        """Record one reference to a model and return its component reference.

        The provider recorded is, in order, the one the endpoint's host names, the
        one a routing prefix names, and ``provider``, which the client or constructor
        names. ``default_provider`` is where a framework sends a bare identifier; it
        is recorded only when nothing else names one and it serves that family.
        """
        written = model_identifier(literal)
        if written is None:
            return None
        name, routed = split_route(written, weights=weights)
        if require_family and not (known_family(written) or known_family(name)):
            return None
        record = self._models.get(name)
        if record is None:
            if not self._room(self._models):
                return None
            record = self._models[name] = _Model(name)
        record.locations.add((path, line))
        record.methods.add(method)
        origin = endpoint_origin(endpoint)
        named = provider_of_endpoint(origin) or routed or provider
        if named is None and default_provider and origin is None:
            named = default_provider if serves(default_provider, name) else None
        if named:
            record.providers.add(named)
        if origin:
            record.endpoints.add(origin)
        kind = model_kind(name, embedding=embedding)
        if kind:
            record.kinds.add(kind)
        if written != name:
            record.aliases.add(written)
        if environment and environment_name(environment):
            record.environment.add(environment)
            self._environment.add(environment)
        for credential in credentials:
            if credential_name(credential):
                record.credentials.add(credential)
        ref = model_ref(name)
        if safety_classifier(name):
            self.guardrail(
                path,
                line,
                name,
                method=method,
                digest=None,
                guardrail_type="classifier",
                model=ref,
            )
        return ref

    def agent(
        self,
        path: str,
        line: int,
        name: str,
        *,
        framework: str | None,
        method: str,
        digest: str | None,
    ) -> AgentRecord | None:
        ref = _ref("agent", path, name)
        record = self._agents.get(ref)
        if record is None:
            if not self._room(self._agents):
                return None
            record = self._agents[ref] = AgentRecord(
                ref, path, line, name, framework, method, digest
            )
        elif record.framework is None:
            record.framework = framework
        record.locations.add((path, line))
        return record

    def agent_ref(self, path: str, name: str) -> str | None:
        ref = _ref("agent", path, name)
        return ref if ref in self._agents else None

    def _item(
        self,
        records: dict[str, _Item],
        kind: str,
        path: str,
        line: int,
        name: str,
        method: str,
        digest: str | None,
    ) -> _Item | None:
        ref = _ref(kind, path, name)
        record = records.get(ref)
        if record is None:
            if not self._room(records):
                return None
            record = records[ref] = _Item(ref, path, line, name, method, digest)
        return record

    def tool(
        self,
        path: str,
        line: int,
        name: str,
        *,
        method: str,
        digest: str | None,
        kind: str,
        framework: str | None = None,
        origin: str | None = None,
    ) -> str | None:
        """Record a tool: a function, a library or hosted tool, a class or a schema."""
        record = self._item(self._tools, "tool", path, line, name, method, digest)
        if record is None:
            return None
        record.properties.setdefault("tool_kind", kind)
        if framework:
            record.properties.setdefault("framework", framework)
        if origin and unchanged_by_redaction(origin):
            record.properties.setdefault("origin", origin)
        return record.ref

    def guardrail(
        self,
        path: str,
        line: int,
        name: str,
        *,
        method: str,
        digest: str | None,
        guardrail_type: str,
        framework: str | None = None,
        model: str | None = None,
        version: str | None = None,
    ) -> str | None:
        record = self._item(self._guardrails, "guardrail", path, line, name, method, digest)
        if record is None:
            return None
        record.fields.setdefault("guardrail_type", guardrail_type)
        if model:
            record.fields.setdefault("model_ref", model)
        if version and unchanged_by_redaction(version):
            record.fields.setdefault("policy_version", version)
        if framework:
            record.properties.setdefault("framework", framework)
        return record.ref

    def memory(
        self,
        path: str,
        line: int,
        name: str,
        *,
        method: str,
        digest: str | None,
        store_type: str,
        framework: str | None = None,
    ) -> str | None:
        record = self._item(self._memories, "memory", path, line, name, method, digest)
        if record is None:
            return None
        record.fields.setdefault("store_type", store_type)
        if framework:
            record.properties.setdefault("framework", framework)
        return record.ref

    def retrieval(
        self,
        path: str,
        line: int,
        name: str,
        *,
        method: str,
        digest: str | None,
        corpus_type: str,
        store: str | None = None,
        embedding_model: str | None = None,
    ) -> str | None:
        record = self._item(self._sources, "rag", path, line, name, method, digest)
        if record is None:
            return None
        record.fields.setdefault("corpus_type", corpus_type)
        if store:
            record.properties.setdefault("store", store)
        if embedding_model:
            record.fields.setdefault("embedding_model_ref", embedding_model)
        return record.ref

    def dataset(
        self,
        path: str,
        line: int,
        name: str,
        *,
        method: str,
        digest: str | None,
        dataset_type: str | None = None,
        loader: str | None = None,
    ) -> str | None:
        record = self._item(self._datasets, "data", path, line, name, method, digest)
        if record is None:
            return None
        if dataset_type:
            record.fields.setdefault("dataset_type", dataset_type)
        if loader:
            record.properties.setdefault("loader", loader)
        return record.ref

    def server(
        self, component: MCPServerComponent, tools: list[ToolComponent], line: int, method: str
    ) -> str | None:
        """Keep a server the MCP collector's own parser read from a literal declaration."""
        if component.bom_ref in self._servers:
            return component.bom_ref
        if not self._room(self._servers):
            return None
        component.properties["collection_mode"] = DECLARATION_MODE
        component.properties["method"] = method
        component.properties["declaration_line"] = line
        component.claims[DECLARATION_CLAIM] = ClaimEvidence(
            assurance=AssuranceLevel.DECLARED,
            method=method,
            scope="repository",
            collector=COLLECTOR,
            locator=f"{component.source_path}:{line}",
        )
        self._servers[component.bom_ref] = component
        self._server_tools.extend(tools)
        return component.bom_ref

    def declare_server(
        self,
        path: str,
        line: int,
        config: dict[str, Any],
        *,
        binding: str | None,
        method: str,
    ) -> str | None:
        """Hand a literal launch or endpoint declaration to the MCP collector's parser.

        ``config`` is in the form an MCP client file gives a server. The parser reads
        the launcher's own grammar and exports no argument, environment or header
        value. The server is named as declared; without a name, by its launcher
        package, by what source binds it to, or by the host it is reached at.
        """
        from nexus_symbiote.scanners.mcp import McpDialect, MCPScanner

        declared = config.pop("name", None)
        transport = config.get("type")
        if isinstance(transport, str):
            config["type"] = transport.replace("_", "-")
        if self._parser is None:
            self._parser = MCPScanner()
        dialect = McpDialect(path, "json", ("mcpServers",))
        name = declared_name(declared)
        try:
            if name is None:
                scratch = ScanResult(scanner_name=COLLECTOR)
                probe, _ = self._parser._parse_server(
                    "server", dict(config), dialect, None, scratch
                )
                package = (probe.launcher_package or "").rsplit(":", 1)[-1].rsplit("/", 1)[-1]
                host = (probe.endpoint_url or "").split("://", 1)[-1].split(":", 1)[0]
                name = (
                    declared_name(package)
                    or declared_name(binding)
                    or declared_name(None if host == _UNSAFE else host)
                )
            if name is None:
                self.gap(
                    path,
                    line,
                    "MCP server declared without a name the collector can read; not inventoried",
                )
                return None
            component, tools = self._parser._parse_server(name, config, dialect, None, self.result)
        except (TypeError, ValueError, AttributeError, KeyError):
            self.gap(
                path,
                line,
                "MCP server declaration is not in a form the collector reads; not inventoried",
            )
            return None
        return self.server(component, tools, line, method)

    def credential_reference(self, name: object, path: str, line: int) -> None:
        """Record a stored credential a workflow refers to by the name of its kind."""
        if (
            isinstance(name, str)
            and _ENVIRONMENT_NAME.fullmatch(name)
            and unchanged_by_redaction(name)
            and (name in self.references or len(self.references) < MAX_RECORDS)
        ):
            self.references.setdefault(name, set()).add((path, line))

    def credential(self, name: object, path: str, line: int, *, pending: bool = False) -> None:
        """Record a credential environment variable by name.

        A ``pending`` name was read from an environment or deployment file. It is kept
        only when the project also declares an AI component, so that the variables of
        an unrelated service are not presented as an agent's credentials.
        """
        accepted = credential_name(name)
        if accepted is None:
            return
        records = self._pending_credentials if pending else self.credentials
        if accepted in records or len(records) < MAX_RECORDS:
            records.setdefault(accepted, set()).add((path, line))

    # -- output ------------------------------------------------------------------

    def empty(self) -> bool:
        return not (
            self._models
            or self._agents
            or self._tools
            or self._guardrails
            or self._memories
            or self._sources
            or self._datasets
            or self._servers
        )

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

    def credential_references(self) -> dict[str, list[str]]:
        return {name: _evidence(self.references[name]) for name in sorted(self.references)}

    def credential_names(self) -> dict[str, list[str]]:
        merged = {name: set(found) for name, found in self.credentials.items()}
        if not self.empty():
            for name, found in self._pending_credentials.items():
                merged.setdefault(name, set()).update(found)
        return {name: _evidence(merged[name]) for name in sorted(merged)}

    def _claim(
        self, claim: str, method: str, locations: Iterable[tuple[str, int]]
    ) -> ClaimEvidence:
        listed = _evidence(locations)
        return ClaimEvidence(
            assurance=AssuranceLevel.DECLARED,
            method=method,
            scope="repository",
            collector=COLLECTOR,
            locator=listed[0],
            evidence_refs=listed if len(listed) > 1 else [],
        )

    def _declared(self, record: _Item) -> dict[str, Any]:
        properties: dict[str, Any] = {
            "collection_mode": DECLARATION_MODE,
            "method": record.method,
            "declaration_line": record.line,
        }
        if record.digest:
            properties["source_sha256"] = record.digest
        properties.update(record.properties)
        return {
            "bom_ref": record.ref,
            "name": record.name,
            "source_path": record.path,
            "trust_tier": TrustTier.UNKNOWN,
            "assurance_level": AssuranceLevel.DECLARED,
            "properties": properties,
            "claims": {
                DECLARATION_CLAIM: self._claim(
                    DECLARATION_CLAIM, record.method, [(record.path, record.line)]
                )
            },
            **record.fields,
        }

    def components(self) -> list[AnyComponent]:
        built: list[AnyComponent] = []
        known_models = {model_ref(name) for name in self._models}
        for name in sorted(self._models):
            model = self._models[name]
            first = min(model.locations)
            properties: dict[str, Any] = {
                "collection_mode": REFERENCE_MODE,
                "method": sorted(model.methods)[0],
                "declaration_line": first[1],
                "reference_path": first[0],
            }
            if len(model.locations) > MAX_EVIDENCE_LOCATIONS:
                properties["references_unlisted"] = len(model.locations) - MAX_EVIDENCE_LOCATIONS
            if len(model.providers) > 1:
                properties["providers"] = sorted(model.providers)
            if len(model.endpoints) > 1:
                properties["endpoints"] = sorted(model.endpoints)
            if len(model.aliases) > 1:
                properties["requested_aliases"] = sorted(model.aliases)
            if model.environment:
                properties["environment_variables"] = sorted(model.environment)
            if model.credentials:
                properties[CREDENTIAL_PROPERTY] = sorted(model.credentials)
            provider = next(iter(model.providers)) if len(model.providers) == 1 else None
            kinds = model.kinds
            kind = (
                "fine-tuned"
                if "fine-tuned" in kinds
                else "embedding"
                if "embedding" in kinds
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
                    endpoint=next(iter(model.endpoints)) if len(model.endpoints) == 1 else None,
                    requested_alias=(
                        next(iter(model.aliases)) if len(model.aliases) == 1 else None
                    ),
                    trust_tier=TrustTier.UNKNOWN,
                    assurance_level=AssuranceLevel.DECLARED,
                    properties=properties,
                    claims={
                        REFERENCE_CLAIM: self._claim(
                            REFERENCE_CLAIM, sorted(model.methods)[0], model.locations
                        )
                    },
                )
            )
        for ref in sorted(self._tools):
            built.append(ToolComponent(**self._declared(self._tools[ref])))
        for ref in sorted(self._guardrails):
            record = self._guardrails[ref]
            if record.fields.get("model_ref") not in known_models:
                record.fields.pop("model_ref", None)
            built.append(GuardrailComponent(**self._declared(record)))
        for ref in sorted(self._memories):
            built.append(MemoryStoreComponent(**self._declared(self._memories[ref])))
        for ref in sorted(self._sources):
            record = self._sources[ref]
            if record.fields.get("embedding_model_ref") not in known_models:
                record.fields.pop("embedding_model_ref", None)
            built.append(RAGSourceComponent(**self._declared(record)))
        for ref in sorted(self._datasets):
            built.append(DataSourceComponent(**self._declared(self._datasets[ref])))
        for ref in sorted(self._servers):
            built.append(self._servers[ref])
        built.extend(sorted(self._server_tools, key=lambda tool: tool.bom_ref))
        known = {component.bom_ref for component in built} | set(self._agents)
        for ref in sorted(self._agents):
            agent = self._agents[ref]
            properties = {
                "collection_mode": DECLARATION_MODE,
                "method": agent.method,
                "declaration_line": agent.line,
                "runtime_use": "unknown",
            }
            if agent.digest:
                properties["source_sha256"] = agent.digest
            built.append(
                AgentComponent(
                    bom_ref=ref,
                    name=agent.name,
                    framework=agent.framework,
                    source_path=agent.path,
                    deployment_status="unknown",
                    trust_tier=TrustTier.UNKNOWN,
                    assurance_level=AssuranceLevel.DECLARED,
                    model_refs=sorted(agent.models & known),
                    tool_refs=sorted(agent.tools & known),
                    sub_agent_refs=sorted((agent.sub_agents & known) - {ref}),
                    guardrail_refs=sorted(agent.guardrails & known),
                    memory_refs=sorted(agent.memories & known),
                    data_refs=sorted(agent.data & known),
                    properties=properties,
                    claims={
                        DECLARATION_CLAIM: self._claim(
                            DECLARATION_CLAIM, agent.method, agent.locations
                        ),
                        "deployment": ClaimEvidence(
                            method="not-collected",
                            scope="runtime",
                            unknown_reason="A source declaration does not show a running agent",
                        ),
                    },
                )
            )
        return built
