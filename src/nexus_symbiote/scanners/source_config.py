"""Read what configuration, deployment and workflow files declare.

These files are data. Each is parsed with the bounded static readers the other
collectors use and never evaluated. A file this reader cannot parse declares nothing
it can record, and is not a failure.

Read here: environment templates and the variable names of environment files;
container and deployment manifests (Dockerfile, Compose, Kubernetes); Ollama
Modelfiles; agent framework configuration (CrewAI agents, LiteLLM model lists,
LangGraph deployments); n8n workflows; tool definitions written as function schemas;
and, in any YAML, JSON, TOML or properties file, a key that names a model whose value
is an identifier of a known model family.

An environment file that is not a template is read for its variable names only.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.hashing import MAX_JSON_NESTING, hash_bytes, json_nesting_exceeds
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.source_python_tables import SEGMENT_PROVIDERS
from nexus_symbiote.scanners.source_references import (
    AgentRecord,
    Declarations,
    declared_name,
    endpoint_origin,
    environment_name,
)
from nexus_symbiote.utils.toml import loads as load_toml

MAX_NODES = 20_000
MAX_DEPTH = 32
MAX_DOCUMENTS = 64
MAX_LINES = 20_000
DATA_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".toml", ".properties"})
_ENV_TEMPLATE = (".example", ".sample", ".template", ".dist", ".defaults")
_MODEL_VARIABLE = re.compile(
    r"(?:^|_)(?:MODEL|LLM|DEPLOYMENT)(?:_(?:NAME|ID))?$|(?:^|_)(?:MODEL|LLM)_[A-Z0-9_]+$"
)
_MODEL_KEYS = frozenset(
    {
        "basemodel",
        "chatmodel",
        "defaultmodel",
        "deployment",
        "deploymentname",
        "embeddingmodel",
        "embedmodel",
        "fallbackmodel",
        "llm",
        "llmmodel",
        "model",
        "modelid",
        "modelname",
    }
)
_MODEL_LIST_KEYS = frozenset({"fallbackmodels", "fallbacks", "models", "providers"})
_ENDPOINT_KEYS = frozenset({"apibase", "baseurl", "endpoint", "apiendpoint", "azureendpoint"})
_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_DOCKER_ENV = re.compile(r"^\s*(?:ENV|ARG)\s+(.*)$", re.IGNORECASE)
_DOCKER_PAIR = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S*)")
_OLLAMA_PULL = re.compile(r"\bollama\s+(?:pull|run)\s+([A-Za-z0-9][A-Za-z0-9._:/-]{1,127})")
_MODELFILE_FROM = re.compile(r"^\s*FROM\s+(\S+)\s*$", re.IGNORECASE)
_OS_ENVIRON = re.compile(r"^os\.environ/([A-Za-z_][A-Za-z0-9_]*)$")
_DOCUMENT_BREAK = re.compile(r"(?m)^---[ \t]*(?:#.*)?$")
# Dependency manifests and lock files: the registry collector reads these, and a
# ``model`` key in one names no hosted model.
_NOT_CONFIGURATION = frozenset(
    {
        "agent.yaml",
        "composer.json",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "tsconfig.json",
        "yarn.lock",
    }
)
_N8N_PROVIDERS = {
    "anthropic": "anthropic",
    "awsbedrock": "aws-bedrock",
    "azureopenai": "azure-openai",
    "cohere": "cohere",
    "deepseek": "deepseek",
    "googlegemini": "google",
    "googlevertex": "google-vertex-ai",
    "groq": "groq",
    "huggingfaceinference": "huggingface",
    "mistralcloud": "mistral",
    "ollama": "ollama",
    "openai": "openai",
    "openrouter": "openrouter",
    "xaigrok": "xai",
}
_N8N_MODEL_PARAMETERS = ("model", "modelName", "modelId")
_N8N_STORE_PARAMETERS = (
    "pineconeIndex",
    "qdrantCollection",
    "collectionName",
    "tableName",
    "indexName",
    "memoryKey",
)
_N8N_LINKS = {
    "ai_languageModel": "models",
    "ai_tool": "tools",
    "ai_memory": "memories",
    "ai_vectorStore": "data",
    "ai_retriever": "data",
}


def _fold(key: object) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower()) if isinstance(key, str) else ""


def _unquoted(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text.split(" #", 1)[0].strip()


def is_environment_file(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(".env") or lowered.endswith(".env") or ".env." in lowered


def is_environment_template(name: str) -> bool:
    return is_environment_file(name) and name.lower().endswith(_ENV_TEMPLATE)


def is_container_file(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in {"dockerfile", "containerfile"}
        or lowered.startswith("dockerfile.")
        or lowered.endswith(".dockerfile")
    )


def is_modelfile(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered == "modelfile" or lowered.startswith("modelfile.") or lowered.endswith(".modelfile")
    )


def reads(path: PurePosixPath) -> bool:
    """Whether this reader has a rule for a file of this name."""
    name = path.name
    return (
        is_environment_file(name)
        or is_container_file(name)
        or is_modelfile(name)
        or (path.suffix.lower() in DATA_SUFFIXES and name.lower() not in _NOT_CONFIGURATION)
    )


class ConfigReader:
    """Reads one data file at a time into a ``Declarations``."""

    def __init__(self, declarations: Declarations) -> None:
        self._found = declarations

    def read(self, path: str, content: bytes) -> None:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return
        name = PurePosixPath(path).name
        suffix = PurePosixPath(path).suffix.lower()
        if is_environment_file(name):
            self._environment_file(path, text, values=is_environment_template(name))
        elif is_container_file(name):
            self._container_file(path, text)
        elif is_modelfile(name):
            self._modelfile(path, text)
        elif suffix == ".properties":
            self._properties(path, text)
        elif suffix in DATA_SUFFIXES:
            digest = hash_bytes(content)
            for document in self._documents(path, text, suffix):
                self._document(path, text, document, digest)

    # -- line-oriented files -----------------------------------------------------

    def _variable(self, path: str, line: int, name: str, value: str | None, method: str) -> None:
        if not environment_name(name):
            return
        self._found.credential(name, path, line, pending=True)
        if value and _MODEL_VARIABLE.search(name.upper()):
            self._found.model(
                value,
                path,
                line,
                method=method,
                environment=name,
                embedding="EMBED" in name.upper(),
                require_family=True,
            )

    def _environment_file(self, path: str, text: str, *, values: bool) -> None:
        for number, line in enumerate(text.splitlines()[:MAX_LINES], start=1):
            match = _ASSIGNMENT.match(line)
            if match is None or line.lstrip().startswith("#"):
                continue
            value = _unquoted(match.group(2)) if values else None
            self._variable(path, number, match.group(1), value, "environment-file")

    def _container_file(self, path: str, text: str) -> None:
        for number, line in enumerate(text.splitlines()[:MAX_LINES], start=1):
            pulled = _OLLAMA_PULL.search(line)
            if pulled is not None and not line.lstrip().startswith("#"):
                self._found.model(
                    pulled.group(1), path, number, method="container-file", provider="ollama"
                )
            match = _DOCKER_ENV.match(line)
            if match is None:
                continue
            body = match.group(1)
            pairs = _DOCKER_PAIR.findall(body)
            if not pairs:
                name, _, value = body.strip().partition(" ")
                pairs = [(name, value)]
            for name, value in pairs:
                self._variable(path, number, name, _unquoted(value), "container-file")

    def _modelfile(self, path: str, text: str) -> None:
        for number, line in enumerate(text.splitlines()[:MAX_LINES], start=1):
            match = _MODELFILE_FROM.match(line)
            if match is not None:
                self._found.model(
                    match.group(1), path, number, method="modelfile", provider="ollama"
                )

    def _properties(self, path: str, text: str) -> None:
        for number, line in enumerate(text.splitlines()[:MAX_LINES], start=1):
            key, separator, value = line.partition("=")
            parts = key.strip().split(".")
            if not separator or line.lstrip().startswith(("#", "!")):
                continue
            if _fold(parts[-1]) in _MODEL_KEYS:
                provider = next(
                    (
                        SEGMENT_PROVIDERS[part]
                        for part in reversed(parts)
                        if part in SEGMENT_PROVIDERS
                    ),
                    None,
                )
                self._found.model(
                    _unquoted(value),
                    path,
                    number,
                    method="config-key",
                    provider=provider,
                    embedding="embedding" in parts,
                    require_family=True,
                )

    # -- structured files --------------------------------------------------------

    def _documents(self, path: str, text: str, suffix: str) -> list[Any]:
        if suffix == ".json":
            try:
                if json_nesting_exceeds(text, MAX_JSON_NESTING):
                    return []
                return [json.loads(text)]
            except (ValueError, RecursionError):
                return []
        if suffix == ".toml":
            try:
                return [load_toml(text)]
            except (ValueError, RecursionError, TypeError):
                return []
        documents: list[Any] = []
        for part in _DOCUMENT_BREAK.split(text)[:MAX_DOCUMENTS]:
            if not part.strip():
                continue
            scratch = ScanResult(scanner_name="source")
            parsed = Scanner._parse_yaml_mapping(Path(path), part, scratch)
            if parsed is not None:
                documents.append(parsed)
        return documents

    @staticmethod
    def _line(text: str, needle: object) -> int:
        if not isinstance(needle, str) or not needle:
            return 1
        position = text.find(needle)
        return 1 if position < 0 else text.count("\n", 0, position) + 1

    def _document(self, path: str, text: str, document: Any, digest: str) -> None:
        if isinstance(document, dict):
            if self._workflow(path, text, document, digest):
                return
            self._crew_agents(path, text, document, digest)
            self._model_list(path, text, document)
            self._deployment(path, text, document)
            if PurePosixPath(path).name == "langgraph.json":
                self._graphs(path, text, document, digest)
        self._schemas(path, text, document, digest)
        self._model_keys(path, text, document)

    def _walk(self, document: Any) -> Iterator[tuple[tuple[str, ...], dict[str, Any]]]:
        """Each mapping of a document with the keys that lead to it, within the bounds."""
        stack: list[tuple[tuple[str, ...], Any]] = [((), document)]
        seen = 0
        while stack and seen < MAX_NODES:
            keys, node = stack.pop()
            seen += 1
            if len(keys) > MAX_DEPTH:
                continue
            if isinstance(node, dict):
                yield keys, node
                for key in sorted(node, key=str, reverse=True):
                    stack.append(((*keys, str(key)), node[key]))
            elif isinstance(node, list):
                for item in reversed(node[:MAX_NODES]):
                    stack.append((keys, item))

    def _model_keys(self, path: str, text: str, document: Any) -> None:
        for keys, mapping in self._walk(document):
            provider = next(
                (SEGMENT_PROVIDERS[key] for key in reversed(keys) if key in SEGMENT_PROVIDERS),
                None,
            )
            named = mapping.get("provider")
            if isinstance(named, str):
                provider = SEGMENT_PROVIDERS.get(named.lower(), provider)
            endpoint = next(
                (
                    value
                    for key, value in mapping.items()
                    if _fold(key) in _ENDPOINT_KEYS and endpoint_origin(value)
                ),
                None,
            )
            for key, value in mapping.items():
                folded = _fold(key)
                values: list[object] = []
                if folded in _MODEL_KEYS:
                    values = [value]
                elif folded in _MODEL_LIST_KEYS and isinstance(value, list):
                    values = [
                        item.get("id") if isinstance(item, dict) else item for item in value[:64]
                    ]
                for item in values:
                    if isinstance(item, str):
                        self._found.model(
                            item,
                            path,
                            self._line(text, item),
                            method="config-key",
                            provider=provider,
                            endpoint=endpoint,
                            embedding="embed" in folded,
                            require_family=True,
                        )

    def _crew_agents(self, path: str, text: str, document: dict[str, Any], digest: str) -> None:
        """A CrewAI agents file: each key names an agent that has a role and a goal."""
        entries = {
            key: value
            for key, value in document.items()
            if isinstance(key, str)
            and isinstance(value, dict)
            and "role" in value
            and ("goal" in value or "backstory" in value)
        }
        if not entries or len(entries) != len(document):
            return
        for key in sorted(entries):
            name = declared_name(key)
            if name is None:
                continue
            agent = self._found.agent(
                path,
                self._line(text, f"{key}:"),
                name,
                framework="crewai",
                method="yaml-config",
                digest=digest,
            )
            model = entries[key].get("llm")
            if agent is not None and isinstance(model, str):
                ref = self._found.model(model, path, self._line(text, model), method="yaml-config")
                if ref is not None:
                    agent.models.add(ref)

    def _model_list(self, path: str, text: str, document: dict[str, Any]) -> None:
        """A LiteLLM proxy configuration: the models it routes and the keys it reads."""
        entries = document.get("model_list")
        if not isinstance(entries, list):
            return
        for entry in entries[:MAX_NODES]:
            parameters = entry.get("litellm_params") if isinstance(entry, dict) else None
            if not isinstance(parameters, dict):
                continue
            model = parameters.get("model")
            key = parameters.get("api_key")
            match = _OS_ENVIRON.match(key) if isinstance(key, str) else None
            credentials = [match.group(1)] if match else []
            for name in credentials:
                self._found.credential(name, path, self._line(text, name))
            if isinstance(model, str):
                self._found.model(
                    model,
                    path,
                    self._line(text, model),
                    method="config-key",
                    endpoint=parameters.get("api_base"),
                    credentials=credentials,
                )

    def _graphs(self, path: str, text: str, document: dict[str, Any], digest: str) -> None:
        graphs = document.get("graphs")
        if not isinstance(graphs, dict):
            return
        for key in sorted(graphs, key=str):
            name = declared_name(key)
            if name is not None:
                self._found.agent(
                    path,
                    self._line(text, f'"{key}"'),
                    name,
                    framework="langgraph",
                    method="config-key",
                    digest=digest,
                )

    def _deployment(self, path: str, text: str, document: dict[str, Any]) -> None:
        """Environment a Compose service or a Kubernetes workload is started with."""
        services = document.get("services")
        compose = isinstance(services, dict) and any(
            isinstance(service, dict) and ("image" in service or "build" in service)
            for service in services.values()
        )
        kubernetes = isinstance(document.get("kind"), str) and "apiVersion" in document
        if not compose and not kubernetes:
            return
        for keys, mapping in self._walk(document):
            environment = mapping.get("environment") if compose else None
            pairs: list[tuple[object, object]] = []
            if isinstance(environment, dict):
                pairs = list(environment.items())
            elif isinstance(environment, list):
                for item in environment:
                    if isinstance(item, str):
                        name, _, value = item.partition("=")
                        pairs.append((name, value or None))
            if kubernetes:
                entries = mapping.get("env")
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict):
                            pairs.append((entry.get("name"), entry.get("value")))
                if keys == ("data",) and document.get("kind") == "ConfigMap":
                    pairs.extend(mapping.items())
            for variable, given in pairs:
                if isinstance(variable, str):
                    text_value = given if isinstance(given, str) else None
                    if text_value is not None and text_value.startswith("${"):
                        text_value = text_value.partition(":-")[2].rstrip("}") or None
                    self._variable(
                        path,
                        self._line(text, variable),
                        variable,
                        text_value,
                        "deployment-manifest",
                    )

    def _schemas(self, path: str, text: str, document: Any, digest: str) -> None:
        """A file that holds tools written as the function schemas a model API takes."""
        entries = document if isinstance(document, list) else [document]
        if isinstance(document, dict) and isinstance(document.get("tools"), list):
            entries = document["tools"]
        for entry in entries[:MAX_NODES]:
            if not isinstance(entry, dict):
                continue
            holder = entry.get("function") if entry.get("type") == "function" else entry
            if not isinstance(holder, dict):
                continue
            schema = holder.get("parameters") or holder.get("input_schema")
            name = declared_name(holder.get("name"))
            if (
                name is not None
                and isinstance(schema, dict)
                and schema.get("type") == "object"
                and isinstance(holder.get("description"), str)
            ):
                self._found.tool(
                    path,
                    self._line(text, f'"{name}"'),
                    name,
                    method="json-schema",
                    digest=digest,
                    kind="schema",
                )

    # -- n8n workflows -----------------------------------------------------------

    @staticmethod
    def _parameter(parameters: dict[str, Any], names: tuple[str, ...]) -> str | None:
        for name in names:
            value = parameters.get(name)
            if isinstance(value, dict):
                value = value.get("value")
            if isinstance(value, str) and value and not value.startswith("="):
                return value
        return None

    def _workflow(self, path: str, text: str, document: dict[str, Any], digest: str) -> bool:
        nodes, connections = document.get("nodes"), document.get("connections")
        if not isinstance(nodes, list) or not isinstance(connections, dict):
            return False
        typed = [
            node
            for node in nodes[:MAX_NODES]
            if isinstance(node, dict)
            and isinstance(node.get("type"), str)
            and isinstance(node.get("name"), str)
        ]
        if not any("n8n-nodes" in node["type"] for node in typed):
            return False
        method = "n8n-workflow"
        agents: dict[str, AgentRecord] = {}
        provided: dict[str, tuple[str, str]] = {}
        tool_sources = {
            source
            for source, outputs in connections.items()
            if isinstance(outputs, dict) and "ai_tool" in outputs
        }
        for node in typed:
            name = declared_name(node["name"])
            kind = node["type"].rsplit(".", 1)[-1]
            folded = kind.lower()
            parameters = node.get("parameters")
            parameters = parameters if isinstance(parameters, dict) else {}
            line = self._line(text, f'"{node["name"]}"')
            references = node.get("credentials")
            if isinstance(references, dict):
                for reference in references:
                    self._found.credential_reference(reference, path, line)
            if name is None:
                continue
            ref: str | None = None
            if folded.startswith(("lmchat", "lm", "embeddings")) and "langchain" in node["type"]:
                service = (
                    folded.removeprefix("lmchat").removeprefix("lm").removeprefix("embeddings")
                )
                model = self._parameter(parameters, _N8N_MODEL_PARAMETERS)
                if model is not None:
                    ref = self._found.model(
                        model,
                        path,
                        line,
                        method=method,
                        provider=_N8N_PROVIDERS.get(service),
                        embedding=folded.startswith("embeddings"),
                    )
                if ref is not None:
                    provided[node["name"]] = ("models", ref)
            elif folded == "agent" or folded.endswith("agent"):
                agent = self._found.agent(
                    path, line, name, framework="n8n", method=method, digest=digest
                )
                if agent is not None:
                    agents[node["name"]] = agent
            elif folded == "mcpclienttool":
                endpoint = self._parameter(parameters, ("sseEndpoint", "endpointUrl", "url"))
                if endpoint is not None:
                    ref = self._found.declare_server(
                        path, line, {"name": name, "url": endpoint}, binding=None, method=method
                    )
                if ref is not None:
                    provided[node["name"]] = ("tools", ref)
            elif folded.startswith("tool") or node["name"] in tool_sources:
                ref = self._found.tool(
                    path, line, name, method=method, digest=digest, kind="workflow-node"
                )
                if ref is not None:
                    provided[node["name"]] = ("tools", ref)
            elif folded.startswith("memory"):
                ref = self._found.memory(
                    path, line, name, method=method, digest=digest, store_type="conversation"
                )
                if ref is not None:
                    provided[node["name"]] = ("memories", ref)
            elif folded.startswith("vectorstore"):
                store = folded.removeprefix("vectorstore")
                identity = declared_name(self._parameter(parameters, _N8N_STORE_PARAMETERS))
                ref = self._found.retrieval(
                    path,
                    line,
                    identity or name,
                    method=method,
                    digest=digest,
                    corpus_type="vector-store",
                    store=store or None,
                )
                if ref is not None:
                    provided[node["name"]] = ("data", ref)
            elif "openai" in folded or "anthropic" in folded or "gemini" in folded:
                model = self._parameter(parameters, _N8N_MODEL_PARAMETERS)
                if model is not None:
                    self._found.model(model, path, line, method=method, require_family=True)
        for source in sorted(connections, key=str):
            outputs = connections[source]
            if source not in provided or not isinstance(outputs, dict):
                continue
            field, ref = provided[source]
            for link, expected in _N8N_LINKS.items():
                if expected != field:
                    continue
                for target in self._targets(outputs.get(link)):
                    agent = agents.get(target)
                    if agent is not None:
                        getattr(agent, field).add(ref)
        return True

    @staticmethod
    def _targets(outputs: object) -> list[str]:
        found: list[str] = []
        stack: list[object] = [outputs]
        while stack and len(found) < MAX_NODES:
            node = stack.pop()
            if isinstance(node, list):
                stack.extend(node[:MAX_NODES])
            elif isinstance(node, dict) and isinstance(node.get("node"), str):
                found.append(node["node"])
        return found


def notebook_code(content: bytes) -> str | None:
    """The code cells of a Jupyter notebook as one Python source text, or None.

    Cell magics and shell escapes are not Python and are replaced by blank lines, so a
    line number counts the lines of the notebook's code cells in order.
    """
    try:
        text = content.decode("utf-8")
        if json_nesting_exceeds(text, MAX_JSON_NESTING):
            return None
        document = json.loads(text)
    except (ValueError, RecursionError):
        return None
    cells = document.get("cells") if isinstance(document, dict) else None
    if not isinstance(cells, list):
        return None
    lines: list[str] = []
    for cell in cells[:MAX_NODES]:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        source = cell.get("source")
        if isinstance(source, list):
            source = "".join(part for part in source if isinstance(part, str))
        if not isinstance(source, str):
            continue
        for line in source.splitlines():
            lines.append("" if line.lstrip().startswith(("%", "!")) else line)
        lines.append("")
    return "\n".join(lines) if lines else None
