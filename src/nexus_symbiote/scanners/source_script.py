"""Read what TypeScript and JavaScript source declares, without running any of it.

A file is parsed with the grammar the MCP source collector uses, under the same
bounds on size, syntax nodes and parse time. Names are followed within the file: an
identifier to the one expression bound to it, an environment read to its default, a
template or a concatenation to its text. A name the file binds more than once, or
binds to something the reader does not follow, stands for nothing it records.

Recorded from a file that imports a known package: model identifiers given to a
provider function, a client or a constructor; agents and what their options name;
tools declared by helper, class, schema or reference; MCP servers started or
reached from code; memory and retrieval stores; and the names of credential
environment variables.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from nexus_symbiote import limits
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.scanners.source_python_tables import HOSTED_TOOLS, MEMORY_STORES, VECTOR_STORES
from nexus_symbiote.scanners.source_references import (
    AgentRecord,
    Declarations,
    credential_name,
    declared_name,
    endpoint_origin,
    environment_name,
)
from nexus_symbiote.scanners.ts_tools import (
    _JSX,
    MAX_PARSE_SECONDS,
    UTF16_BYTE_ORDER_MARKS,
    _nodes,
    _parse,
    _string_value,
    _value,
    source_text,
)

if TYPE_CHECKING:
    from tree_sitter import Node

METHOD = "typescript-syntax"
MAX_DEPTH = 10
MAX_ITEMS = 256
UNRESOLVED = "${UNRESOLVED}"

# The provider a package's clients and provider functions talk to.
PACKAGE_PROVIDERS: dict[str, str] = {
    "@ai-sdk/amazon-bedrock": "aws-bedrock",
    "@ai-sdk/anthropic": "anthropic",
    "@ai-sdk/azure": "azure-openai",
    "@ai-sdk/cerebras": "cerebras",
    "@ai-sdk/cohere": "cohere",
    "@ai-sdk/deepseek": "deepseek",
    "@ai-sdk/fireworks": "fireworks",
    "@ai-sdk/google": "google",
    "@ai-sdk/google-vertex": "google-vertex-ai",
    "@ai-sdk/groq": "groq",
    "@ai-sdk/mistral": "mistral",
    "@ai-sdk/openai": "openai",
    "@ai-sdk/perplexity": "perplexity",
    "@ai-sdk/togetherai": "together",
    "@ai-sdk/xai": "xai",
    "@anthropic-ai/bedrock-sdk": "aws-bedrock",
    "@anthropic-ai/sdk": "anthropic",
    "@anthropic-ai/vertex-sdk": "google-vertex-ai",
    "@aws-sdk/client-bedrock-runtime": "aws-bedrock",
    "@google/genai": "google",
    "@google/generative-ai": "google",
    "@huggingface/inference": "huggingface",
    "@langchain/anthropic": "anthropic",
    "@langchain/aws": "aws-bedrock",
    "@langchain/cohere": "cohere",
    "@langchain/google-genai": "google",
    "@langchain/google-vertexai": "google-vertex-ai",
    "@langchain/groq": "groq",
    "@langchain/mistralai": "mistral",
    "@langchain/ollama": "ollama",
    "@langchain/openai": "openai",
    "@mistralai/mistralai": "mistral",
    "@openrouter/ai-sdk-provider": "openrouter",
    "cohere-ai": "cohere",
    "groq-sdk": "groq",
    "ollama": "ollama",
    "ollama-ai-provider": "ollama",
    "openai": "openai",
    "together-ai": "together",
}
# Client classes whose service differs from their package's.
SYMBOL_PROVIDERS: dict[str, str] = {
    "AzureChatOpenAI": "azure-openai",
    "AzureOpenAI": "azure-openai",
    "AzureOpenAIEmbeddings": "azure-openai",
}
# Packages whose default export or named exports are provider functions: a call with
# an identifier as its first argument names a model of that provider.
PROVIDER_FUNCTION_PREFIXES = ("@ai-sdk/", "@openrouter/ai-sdk-provider", "ollama-ai-provider")
AGENT_PACKAGES: dict[str, str] = {
    "@anthropic-ai/claude-agent-sdk": "claude-agent-sdk",
    "@google/adk": "google-adk",
    "@inngest/agent-kit": "agentkit",
    "@langchain/langgraph": "langgraph",
    "@mastra/core": "mastra",
    "@openai/agents": "openai-agents",
    "@openai/agents-realtime": "openai-agents",
    "@strands-agents/sdk": "strands",
    "@voltagent/core": "voltagent",
    "ai": "ai-sdk",
    "langchain": "langchain",
    "llamaindex": "llamaindex",
}
AGENT_SYMBOLS = frozenset(
    {
        "Agent",
        "Experimental_Agent",
        "LlmAgent",
        "RealtimeAgent",
        "ToolLoopAgent",
        "createAgent",
        "createReactAgent",
    }
)
FRAMEWORK_PROVIDERS = {"openai-agents": "openai", "google-adk": "google"}
TOOL_HELPERS = frozenset(
    {
        "DynamicStructuredTool",
        "DynamicTool",
        "betaZodTool",
        "createTool",
        "dynamicTool",
        "tool",
        "zodFunction",
    }
)
TOOL_PACKAGES = (
    "@anthropic-ai/sdk",
    "@langchain/core",
    "@mastra/core",
    "@openai/agents",
    "@voltagent/core",
    "ai",
    "langchain",
    "llamaindex",
    "openai",
)
MODEL_PROPERTIES = frozenset(
    {
        "azureOpenAIApiDeploymentName",
        "deployment",
        "deploymentName",
        "embeddingModel",
        "model",
        "modelId",
        "modelName",
    }
)
MODEL_HOLDERS = ("model", "llm", "chatModel")
ENDPOINT_PROPERTIES = ("baseURL", "baseUrl", "basePath", "endpoint", "azureOpenAIEndpoint")
MCP_PACKAGES = (
    "@ai-sdk/mcp",
    "@langchain/mcp-adapters",
    "@mastra/mcp",
    "@modelcontextprotocol/",
    "@openai/agents",
    "ai",
    "mcp-use",
)
MCP_STDIO = frozenset({"Experimental_StdioMCPTransport", "MCPServerStdio", "StdioClientTransport"})
MCP_URL = frozenset(
    {
        "MCPServerSSE",
        "MCPServerStreamableHttp",
        "SSEClientTransport",
        "StreamableHTTPClientTransport",
        "WebSocketClientTransport",
        "hostedMcpTool",
    }
)
MCP_SSE = frozenset({"MCPServerSSE", "SSEClientTransport"})
MCP_MAPS = frozenset({"MCPClient", "MCPConfiguration", "MultiServerMCPClient"})
MCP_MAP_PROPERTIES = ("mcpServers", "servers")
MCP_CLIENTS = frozenset({"createMCPClient", "experimental_createMCPClient"})
SCRIPT_STORES: dict[str, str] = {
    **VECTOR_STORES,
    "FaissStore": "faiss",
    "HNSWLib": "hnswlib",
    "LibSQLVector": "libsql",
    "MemoryVectorStore": "in-memory",
    "PgVector": "pgvector",
    "PineconeStore": "pinecone",
    "PineconeVector": "pinecone",
    "WeaviateStore": "weaviate",
}
SCRIPT_MEMORY: dict[str, str] = {
    **MEMORY_STORES,
    "BufferMemory": "conversation",
    "BufferWindowMemory": "conversation",
    "Memory": "conversation",
}
STORE_IDENTITIES = ("collectionName", "indexName", "tableName", "namespace")
SCRIPT_MARKERS = tuple(
    sorted(
        {
            name.encode()
            for name in (
                *PACKAGE_PROVIDERS,
                *AGENT_PACKAGES,
                "@modelcontextprotocol/",
                "@langchain/",
                "@mastra/",
                "@ai-sdk/",
            )
            if name not in {"ai", "openai", "ollama", "langchain"}
        }
        | {b'"ai"', b"'ai'", b"openai", b"ollama", b"langchain"}
    )
)
_WRAPPERS = frozenset(
    {
        "as_expression",
        "await_expression",
        "non_null_expression",
        "parenthesized_expression",
        "satisfies_expression",
        "type_assertion",
    }
)
_ENVIRONMENT_OBJECTS = frozenset({"process.env", "import.meta.env", "Bun.env"})
_MODEL_CONSTANT_WORDS = ("MODEL", "LLM", "DEPLOYMENT")


@dataclass
class _File:
    path: str
    digest: str
    imports: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    bindings: dict[str, list[Node]] = field(default_factory=dict)
    parents: dict[int, Node] = field(default_factory=dict)
    nodes: list[Node] = field(default_factory=list)


def _field(node: Node | None, name: str) -> Node | None:
    return None if node is None else node.child_by_field_name(name)


def _line(node: Node) -> int:
    return int(node.start_point.row) + 1


def _package(specifier: str, packages: tuple[str, ...] | dict[str, Any]) -> str | None:
    """The entry of ``packages`` a module specifier names, itself or a path into it."""
    best: str | None = None
    for name in packages:
        exact = specifier == name or specifier.startswith(name + "/")
        if (exact or (name.endswith("/") and specifier.startswith(name))) and (
            best is None or len(name) > len(best)
        ):
            best = name
    return best


class ScriptReader:
    """Reads one TypeScript or JavaScript file at a time into a ``Declarations``."""

    def __init__(self, declarations: Declarations) -> None:
        self._found = declarations
        self._agents: dict[int, AgentRecord] = {}
        self._tools: dict[int, str | None] = {}
        self._servers: dict[int, set[str]] = {}

    def read(self, path: str, content: bytes) -> None:
        if not any(marker in content for marker in SCRIPT_MARKERS):
            return
        try:
            text = source_text(content)
            source = content if content[:2] not in UTF16_BYTE_ORDER_MARKS else text.encode()
            scale = max(1.0, limits.current().syntax_bytes / limits.DEFAULTS.syntax_bytes)
            suffix = PurePosixPath(path).suffix.lower()
            tree = _parse(source, _JSX.get(suffix, False), MAX_PARSE_SECONDS * scale)
            file = _File(path, hash_bytes(content))
            file.nodes = list(_nodes(tree.root_node, limits.bound("ts-nodes")))
        except ImportError:
            self._found.gap(path, 1, "TypeScript parser unavailable; source not read")
            return
        except ValueError:
            self._found.gap(
                path, 1, "source could not be parsed within the collector's bounds; not read"
            )
            return
        self._agents, self._tools, self._servers = {}, {}, {}
        self._index(file)
        if not self._imports_sdk(file):
            return
        for node in file.nodes:
            if node.type in {"call_expression", "new_expression"}:
                self._register_agent(file, node)
        for node in file.nodes:
            self._visit(file, node)
        for node in file.nodes:
            record = self._agents.get(node.id)
            if record is not None:
                self._wire(file, node, record)

    # -- names -------------------------------------------------------------------

    def _index(self, file: _File) -> None:
        for node in file.nodes:
            for child in node.named_children:
                file.parents[child.id] = node
            if node.type == "import_statement":
                self._import(file, node)
            elif node.type == "variable_declarator":
                name, value = _field(node, "name"), _field(node, "value")
                if name is None or value is None:
                    continue
                if name.type == "identifier":
                    file.bindings.setdefault(_value(name), []).append(value)
                    self._require(file, _value(name), None, value)
                elif name.type == "object_pattern":
                    for part in name.named_children:
                        if part.type == "shorthand_property_identifier_pattern":
                            self._require(file, _value(part), _value(part), value)
                        elif part.type == "pair_pattern":
                            key, bound = _field(part, "key"), _field(part, "value")
                            if key is not None and bound is not None:
                                self._require(file, _value(bound), _value(key), value)
            elif node.type == "function_declaration":
                name = _field(node, "name")
                if name is not None:
                    file.bindings.setdefault(_value(name), []).append(node)

    def _require(self, file: _File, bound: str, symbol: str | None, value: Node) -> None:
        if value.type != "call_expression" or _value(_field(value, "function")) != "require":
            return
        arguments = _field(value, "arguments")
        specifier = _string_value(arguments.named_children[0]) if arguments else None
        if specifier is not None and arguments is not None and len(arguments.named_children) == 1:
            file.imports[bound] = (specifier, symbol)

    def _import(self, file: _File, node: Node) -> None:
        specifier = _string_value(_field(node, "source"))
        if specifier is None:
            return
        for clause in node.named_children:
            if clause.type != "import_clause":
                continue
            for part in clause.named_children:
                if part.type == "identifier":
                    file.imports[_value(part)] = (specifier, None)
                elif part.type == "namespace_import":
                    for bound in part.named_children:
                        file.imports[_value(bound)] = (specifier, "*")
                elif part.type == "named_imports":
                    for item in part.named_children:
                        name, alias = _field(item, "name"), _field(item, "alias")
                        if name is not None:
                            file.imports[_value(alias or name)] = (specifier, _value(name))

    def _imports_sdk(self, file: _File) -> bool:
        packages = (*PACKAGE_PROVIDERS, *AGENT_PACKAGES, *MCP_PACKAGES, "@langchain/", "@mastra/")
        return any(_package(specifier, packages) for specifier, _ in file.imports.values())

    def _unwrap(self, node: Node | None) -> Node | None:
        steps = 0
        while node is not None and node.type in _WRAPPERS and steps < MAX_DEPTH:
            node = node.named_children[0] if node.named_children else None
            steps += 1
        return node

    def _follow(self, file: _File, node: Node | None, depth: int = 0) -> list[Node]:
        """The expressions ``node`` stands for, each one followed as far as the file binds it."""
        node = self._unwrap(node)
        if node is None or depth > MAX_DEPTH:
            return []
        if node.type == "identifier":
            name = _value(node)
            values = file.bindings.get(name, [])
            if len(values) == 1 and name not in file.imports:
                return self._follow(file, values[0], depth + 1)
            return [node]
        if node.type == "ternary_expression":
            return [
                *self._follow(file, _field(node, "consequence"), depth + 1),
                *self._follow(file, _field(node, "alternative"), depth + 1),
            ]
        return [node]

    def _environment(self, node: Node | None) -> str | None:
        """The variable a ``process.env`` read names."""
        node = self._unwrap(node)
        if node is None:
            return None
        if node.type == "member_expression":
            if _value(_field(node, "object")) in _ENVIRONMENT_OBJECTS:
                return environment_name(_value(_field(node, "property")))
        if node.type == "subscript_expression":
            if _value(_field(node, "object")) in _ENVIRONMENT_OBJECTS:
                return environment_name(_string_value(_field(node, "index")))
        if node.type == "call_expression" and _value(_field(node, "function")) == "Deno.env.get":
            arguments = _field(node, "arguments")
            if arguments is not None and arguments.named_children:
                return environment_name(_string_value(arguments.named_children[0]))
        return None

    def _texts(
        self, file: _File, node: Node | None, depth: int = 0
    ) -> list[tuple[str, str | None]]:
        """The text values ``node`` can stand for, each with the variable that overrides it."""
        found: list[tuple[str, str | None]] = []
        if depth > MAX_DEPTH:
            return found
        for value in self._follow(file, node, depth):
            literal = _string_value(value)
            if literal is not None:
                found.append((literal, None))
            elif value.type == "binary_expression":
                operator = _value(_field(value, "operator"))
                left, right = _field(value, "left"), _field(value, "right")
                if operator in {"??", "||"}:
                    variable = self._environment(left)
                    found.extend(
                        (text, variable or other)
                        for text, other in self._texts(file, right, depth + 1)
                    )
                    if variable is None:
                        found.extend(self._texts(file, left, depth + 1))
                elif operator == "+":
                    found.extend(
                        (first + second, variable or other)
                        for first, variable in self._texts(file, left, depth + 1)
                        for second, other in self._texts(file, right, depth + 1)
                    )
            elif value.type == "template_string":
                built: list[tuple[str, str | None]] = [("", None)]
                for part in value.named_children:
                    if part.type == "template_substitution":
                        options = self._texts(
                            file,
                            part.named_children[0] if part.named_children else None,
                            depth + 1,
                        )
                    else:
                        options = [(_value(part), None)] if part.type == "string_fragment" else []
                    built = [
                        (text + more, variable or other)
                        for text, variable in built
                        for more, other in options
                    ][:8]
                found.extend(built)
        return found[:8]

    def _text(self, file: _File, node: Node | None) -> str | None:
        found = {text for text, _ in self._texts(file, node)}
        return found.pop() if len(found) == 1 else None

    def _origin(self, file: _File, node: Node | None, depth: int = 0) -> tuple[str, str] | None:
        """The package and the dotted symbol path a callee or constructor comes from."""
        node = self._unwrap(node)
        if node is None or depth > MAX_DEPTH:
            return None
        if node.type == "identifier":
            name = _value(node)
            imported = file.imports.get(name)
            if imported is not None:
                specifier, symbol = imported
                return specifier, "" if symbol in (None, "*") else str(symbol)
            values = file.bindings.get(name, [])
            if len(values) == 1:
                return self._origin(file, values[0], depth + 1)
            return None
        if node.type == "member_expression":
            base = self._origin(file, _field(node, "object"), depth + 1)
            if base is None:
                return None
            name = _value(_field(node, "property"))
            return base[0], f"{base[1]}.{name}" if base[1] else name
        if node.type in {"call_expression", "new_expression"}:
            callee = _field(node, "function") or _field(node, "constructor")
            return self._origin(file, callee, depth + 1)
        return None

    def _callee(self, file: _File, node: Node) -> tuple[str, str] | None:
        return self._origin(file, _field(node, "function") or _field(node, "constructor"))

    @staticmethod
    def _arguments(node: Node) -> list[Node]:
        arguments = _field(node, "arguments")
        return [] if arguments is None else list(arguments.named_children)

    def _properties(self, file: _File, node: Node | None) -> dict[str, Node]:
        """The properties of the object literal ``node`` stands for, by name."""
        found: dict[str, Node] = {}
        for value in self._follow(file, node):
            if value.type != "object":
                continue
            for part in value.named_children[:MAX_ITEMS]:
                if part.type == "pair":
                    key, bound = _field(part, "key"), _field(part, "value")
                    name = _string_value(key) if key is not None and key.type == "string" else None
                    name = name or (_value(key) if key is not None else None)
                    if name and bound is not None:
                        found.setdefault(name, bound)
                elif part.type == "shorthand_property_identifier":
                    found.setdefault(_value(part), part)
        return found

    def _elements(self, file: _File, node: Node | None) -> list[tuple[str | None, Node]]:
        """The members of an array or an object literal, an object's with their keys."""
        found: list[tuple[str | None, Node]] = []
        for value in self._follow(file, node):
            if value.type == "array":
                for element in value.named_children[:MAX_ITEMS]:
                    inner = (
                        element.named_children[0] if element.type == "spread_element" else element
                    )
                    if element.type == "spread_element":
                        found.extend(self._elements(file, inner))
                    else:
                        found.append((None, inner))
            elif value.type == "object":
                found.extend(self._properties(file, value).items())
            else:
                found.append((None, value))
        return found[:MAX_ITEMS]

    def _binding(self, file: _File, node: Node) -> str | None:
        parent = file.parents.get(node.id)
        steps = 0
        while parent is not None and parent.type in _WRAPPERS and steps < MAX_DEPTH:
            parent = file.parents.get(parent.id)
            steps += 1
        if parent is None:
            return None
        if parent.type == "variable_declarator":
            name = _field(parent, "name")
            return _value(name) if name is not None and name.type == "identifier" else None
        if parent.type == "pair":
            key = _field(parent, "key")
            return _string_value(key) or _value(key) if key is not None else None
        if parent.type == "assignment_expression":
            left = _field(parent, "left")
            if left is not None and left.type == "member_expression":
                return _value(_field(left, "property"))
            return _value(left) if left is not None and left.type == "identifier" else None
        return None

    # -- passes ------------------------------------------------------------------

    def _register_agent(self, file: _File, node: Node) -> None:
        origin = self._callee(file, node)
        if origin is None:
            return
        package = _package(origin[0], AGENT_PACKAGES)
        symbol = origin[1].rsplit(".", 1)[-1]
        if package is None or symbol not in AGENT_SYMBOLS or "." in origin[1].rstrip("."):
            return
        arguments = self._arguments(node)
        options = self._properties(file, arguments[0]) if arguments else {}
        name = declared_name(self._text(file, options.get("name") or options.get("id")))
        name = name or declared_name(self._binding(file, node))
        framework = AGENT_PACKAGES[package]
        if name is None:
            self._found.gap(
                file.path,
                _line(node),
                f"{framework} agent declared without a name the collector can read; "
                "not inventoried",
            )
            return
        record = self._found.agent(
            file.path, _line(node), name, framework=framework, method=METHOD, digest=file.digest
        )
        if record is not None:
            self._agents[node.id] = record

    def _visit(self, file: _File, node: Node) -> None:
        variable = self._environment(node)
        if variable is not None:
            self._found.credential(variable, file.path, _line(node))
        if node.type in {"call_expression", "new_expression"}:
            self._model_call(file, node)
            self._server(file, node)
            self._store(file, node)
            if node.id not in self._agents:
                arguments = self._arguments(node)
                options = self._properties(file, arguments[0]) if arguments else {}
                if "tools" in options:
                    self._tool_list(file, options["tools"], None)
                self._tool(file, node, None, None)
        elif node.type == "pair":
            self._model_property(file, node)
        elif node.type == "variable_declarator":
            self._constant(file, node)

    # -- models ------------------------------------------------------------------

    def _provider(self, origin: tuple[str, str] | None) -> str | None:
        if origin is None:
            return None
        for part in origin[1].split("."):
            if part in SYMBOL_PROVIDERS:
                return SYMBOL_PROVIDERS[part]
        package = _package(origin[0], PACKAGE_PROVIDERS)
        return None if package is None else PACKAGE_PROVIDERS[package]

    def _client_options(self, file: _File, node: Node) -> tuple[str | None, list[str]]:
        """The endpoint and credential variables given to the client a call is made on."""
        endpoint: str | None = None
        credentials: list[str] = []
        holders: list[Node] = [node]
        current = self._unwrap(_field(node, "function") or _field(node, "constructor"))
        steps = 0
        while current is not None and steps < MAX_DEPTH:
            steps += 1
            if current.type == "member_expression":
                current = self._unwrap(_field(current, "object"))
            elif current.type == "identifier":
                values = file.bindings.get(_value(current), [])
                current = values[0] if len(values) == 1 else None
            else:
                if current.type in {"call_expression", "new_expression"}:
                    holders.append(current)
                break
        for holder in holders:
            arguments = self._arguments(holder)
            options = self._properties(file, arguments[0]) if arguments else {}
            for key in ENDPOINT_PROPERTIES:
                if endpoint is None and key in options:
                    endpoint = next(
                        (
                            origin
                            for text, _ in self._texts(file, options[key])
                            if (origin := endpoint_origin(text))
                        ),
                        None,
                    )
            for key in ("apiKey", "authToken", "token"):
                variable = self._environment(options.get(key))
                if variable and credential_name(variable) and variable not in credentials:
                    credentials.append(variable)
        return endpoint, credentials

    def _record_models(
        self,
        file: _File,
        node: Node | None,
        *,
        provider: str | None,
        default_provider: str | None = None,
        endpoint: str | None = None,
        embedding: bool = False,
        credentials: list[str] | None = None,
        require_family: bool = False,
    ) -> list[str]:
        refs: list[str] = []
        if node is None:
            return refs
        for text, variable in self._texts(file, node):
            ref = self._found.model(
                text,
                file.path,
                _line(node),
                method=METHOD,
                provider=provider,
                default_provider=default_provider,
                endpoint=endpoint,
                embedding=embedding,
                environment=variable,
                credentials=credentials or (),
                require_family=require_family,
            )
            if ref is not None and ref not in refs:
                refs.append(ref)
        if not refs:
            variable = self._environment(node)
            if variable is not None:
                self._found.unresolved_environment.setdefault(variable, set()).add(
                    (file.path, _line(node))
                )
        return refs

    def _model_call(self, file: _File, node: Node) -> list[str]:
        """A provider function called with an identifier: ``openai("gpt-4o")``."""
        origin = self._callee(file, node)
        if origin is None or node.type != "call_expression":
            return []
        if not origin[0].startswith(PROVIDER_FUNCTION_PREFIXES):
            return []
        arguments = self._arguments(node)
        if not arguments:
            return []
        endpoint, credentials = self._client_options(file, node)
        return self._record_models(
            file,
            arguments[0],
            provider=self._provider(origin),
            endpoint=endpoint,
            embedding="embedding" in origin[1].lower(),
            credentials=credentials,
        )

    def _model_property(self, file: _File, pair: Node) -> None:
        """An option named for a model, in the arguments of a call into a known package."""
        key = _field(pair, "key")
        name = (_string_value(key) or _value(key)) if key is not None else ""
        if name not in MODEL_PROPERTIES:
            return
        call = self._enclosing_call(file, pair)
        origin = None if call is None else self._callee(file, call)
        value = self._unwrap(_field(pair, "value"))
        if value is None or value.type in {"call_expression", "new_expression"}:
            return
        endpoint, credentials = (None, []) if call is None else self._client_options(file, call)
        framework = (
            AGENT_PACKAGES.get(_package(origin[0], AGENT_PACKAGES) or "") if origin else None
        )
        self._record_models(
            file,
            value,
            provider=self._provider(origin),
            default_provider=FRAMEWORK_PROVIDERS.get(framework or ""),
            endpoint=endpoint,
            embedding="embed" in name.lower() or (origin is not None and "mbed" in origin[1]),
            credentials=credentials,
            require_family=origin is None,
        )

    def _enclosing_call(self, file: _File, node: Node) -> Node | None:
        current = file.parents.get(node.id)
        steps = 0
        while current is not None and steps < 6:
            if current.type in {"call_expression", "new_expression"}:
                return current
            if current.type not in {"object", "arguments", "pair", "array", *_WRAPPERS}:
                return None
            current = file.parents.get(current.id)
            steps += 1
        return None

    def _constant(self, file: _File, node: Node) -> None:
        name = _field(node, "name")
        if name is None or name.type != "identifier":
            return
        words = _value(name).upper().replace("-", "_")
        if not any(word in words for word in _MODEL_CONSTANT_WORDS):
            return
        value = self._unwrap(_field(node, "value"))
        if value is None or value.type in {"call_expression", "new_expression", "object"}:
            return
        self._record_models(
            file, value, provider=None, embedding="EMBED" in words, require_family=True
        )

    def _models(self, file: _File, node: Node | None, default: str | None) -> list[str]:
        """The model references an agent's model option stands for."""
        refs: list[str] = []
        for value in self._follow(file, node):
            if value.type == "call_expression":
                found = self._model_call(file, value)
                if not found:
                    receiver = self._unwrap(_field(value, "function"))
                    if receiver is not None and receiver.type == "member_expression":
                        found = self._models(file, _field(receiver, "object"), default)
                refs.extend(found)
            elif value.type == "new_expression":
                arguments = self._arguments(value)
                options = self._properties(file, arguments[0]) if arguments else {}
                origin = self._callee(file, value)
                endpoint, credentials = self._client_options(file, value)
                for key in MODEL_PROPERTIES & options.keys():
                    refs.extend(
                        self._record_models(
                            file,
                            options[key],
                            provider=self._provider(origin),
                            endpoint=endpoint,
                            credentials=credentials,
                        )
                    )
            else:
                refs.extend(
                    self._record_models(file, value, provider=None, default_provider=default)
                )
        return refs

    # -- tools -------------------------------------------------------------------

    def _tool(
        self, file: _File, node: Node, key: str | None, agent: AgentRecord | None
    ) -> str | None:
        """A tool made by a helper or a class of a known package."""
        if node.id in self._tools:
            return self._tools[node.id]
        origin = self._callee(file, node)
        if origin is None or _package(origin[0], TOOL_PACKAGES) is None:
            return None
        symbol = origin[1].rsplit(".", 1)[-1]
        arguments = self._arguments(node)
        ref: str | None = None
        if symbol in TOOL_HELPERS:
            options: dict[str, Node] = {}
            for argument in arguments[:2]:
                options = {**self._properties(file, argument), **options}
            name = declared_name(self._text(file, options.get("name") or options.get("id")))
            name = name or declared_name(key) or declared_name(self._binding(file, node))
            if name is not None:
                ref = self._found.tool(
                    file.path,
                    _line(node),
                    name,
                    method=METHOD,
                    digest=file.digest,
                    kind="function",
                    framework=agent.framework if agent else None,
                )
        elif symbol.endswith("Tool") and symbol[:1].islower() or symbol in HOSTED_TOOLS:
            name = declared_name(symbol)
            for store in arguments[:1]:
                identity = declared_name(self._text(file, store))
                if identity is not None and symbol == "fileSearchTool":
                    self._found.retrieval(
                        file.path,
                        _line(node),
                        identity,
                        method=METHOD,
                        digest=file.digest,
                        corpus_type="vector-store",
                        store="openai-vector-store",
                    )
            if name is not None and symbol != "hostedMcpTool":
                ref = self._found.tool(
                    file.path,
                    _line(node),
                    name,
                    method=METHOD,
                    digest=file.digest,
                    kind="hosted",
                    framework=agent.framework if agent else None,
                    origin=origin[0],
                )
        self._tools[node.id] = ref
        return ref

    def _schema_tool(self, file: _File, node: Node) -> str | None:
        properties = self._properties(file, node)
        holder = properties
        if "function" in properties:
            holder = self._properties(file, properties["function"]) or properties
        name = declared_name(self._text(file, holder.get("name")))
        described = any(key in holder for key in ("parameters", "input_schema", "description"))
        if name is None or not described:
            return None
        return self._found.tool(
            file.path, _line(node), name, method=METHOD, digest=file.digest, kind="schema"
        )

    def _tool_list(self, file: _File, node: Node | None, agent: AgentRecord | None) -> set[str]:
        refs: set[str] = set()
        for key, element in self._elements(file, node):
            for value in self._follow(file, element):
                ref: str | None = None
                if value.type in {"call_expression", "new_expression"}:
                    servers = self._server(file, value)
                    if servers:
                        refs |= servers
                        continue
                    sub_agent = self._agents.get(value.id)
                    if sub_agent is not None and agent is not None:
                        agent.sub_agents.add(sub_agent.ref)
                        continue
                    callee = self._unwrap(_field(value, "function"))
                    if (
                        callee is not None
                        and callee.type == "member_expression"
                        and _value(_field(callee, "property")) == "asTool"
                    ):
                        if agent is not None:
                            agent.sub_agents |= self._agent_refs(file, _field(callee, "object"))
                        arguments = self._arguments(value)
                        options = self._properties(file, arguments[0]) if arguments else {}
                        name = declared_name(self._text(file, options.get("toolName")))
                        if name is not None:
                            ref = self._found.tool(
                                file.path,
                                _line(value),
                                name,
                                method=METHOD,
                                digest=file.digest,
                                kind="agent",
                            )
                    else:
                        binding = self._binding(file, value)
                        ref = self._tool(file, value, key or binding, agent)
                elif value.type == "object":
                    ref = self._schema_tool(file, value)
                elif value.type == "identifier":
                    imported = file.imports.get(_value(value))
                    name = declared_name(_value(value))
                    if imported is not None and name is not None:
                        ref = self._found.tool(
                            file.path,
                            _line(value),
                            name,
                            method=METHOD,
                            digest=file.digest,
                            kind="library",
                            origin=imported[0],
                        )
                    elif name is not None and _value(value) in file.bindings:
                        declared = file.bindings[_value(value)][0]
                        if declared.type == "function_declaration":
                            ref = self._found.tool(
                                file.path,
                                _line(declared),
                                name,
                                method=METHOD,
                                digest=file.digest,
                                kind="function",
                            )
                if ref is not None:
                    refs.add(ref)
        return refs

    # -- agents ------------------------------------------------------------------

    def _agent_refs(self, file: _File, node: Node | None) -> set[str]:
        refs: set[str] = set()
        for _, element in self._elements(file, node):
            for value in self._follow(file, element):
                record = self._agents.get(value.id)
                if record is not None:
                    refs.add(record.ref)
                elif value.type == "call_expression":
                    for argument in self._arguments(value)[:1]:
                        refs |= self._agent_refs(file, argument)
        return refs

    def _wire(self, file: _File, node: Node, record: AgentRecord) -> None:
        arguments = self._arguments(node)
        options = self._properties(file, arguments[0]) if arguments else {}
        default = FRAMEWORK_PROVIDERS.get(record.framework or "")
        for key in MODEL_HOLDERS:
            if key in options:
                record.models.update(self._models(file, options[key], default))
        if "tools" in options:
            record.tools |= self._tool_list(file, options["tools"], record)
        for key in ("mcpServers", "mcpTools"):
            if key in options:
                record.tools |= self._tool_list(file, options[key], record)
        for key in ("handoffs", "subAgents", "agents"):
            if key in options:
                record.sub_agents |= self._agent_refs(file, options[key])
        for key, kind in (
            ("inputGuardrails", "input-filter"),
            ("outputGuardrails", "output-filter"),
        ):
            for _, element in self._elements(file, options.get(key)):
                for value in self._follow(file, element):
                    name = declared_name(
                        self._text(file, self._properties(file, value).get("name"))
                    )
                    name = name or declared_name(
                        _value(element) if element.type == "identifier" else None
                    )
                    if name is not None:
                        ref = self._found.guardrail(
                            file.path,
                            _line(value),
                            name,
                            method=METHOD,
                            digest=file.digest,
                            guardrail_type=kind,
                            framework=record.framework,
                        )
                        if ref is not None:
                            record.guardrails.add(ref)
        for key in ("memory", "checkpointer", "checkpointSaver"):
            for value in self._follow(file, options.get(key)):
                ref = self._store(file, value)
                if ref is not None and ref.startswith("memory:"):
                    record.memories.add(ref)

    # -- MCP servers and stores --------------------------------------------------

    def _launch_text(self, file: _File, node: Node) -> str:
        text = self._text(file, node)
        if text is not None:
            return text
        variable = self._environment(node)
        return f"${{{variable}}}" if variable else UNRESOLVED

    def _launch(self, file: _File, options: dict[str, Node]) -> dict[str, Any]:
        config: dict[str, Any] = {}
        for source, key in (("command", "command"), ("url", "url"), ("serverUrl", "url")):
            if source in options and key not in config:
                value = self._unwrap(options[source])
                if value is not None and value.type == "new_expression":
                    arguments = self._arguments(value)
                    value = arguments[0] if arguments else None
                if value is not None:
                    config[key] = self._launch_text(file, value)
        full = self._text(file, options.get("fullCommand"))
        if full and "command" not in config:
            words = full.split()
            if words:
                config["command"], config["args"] = words[0], words[1:]
        for source in ("name", "serverLabel"):
            name = self._text(file, options.get(source))
            if name is not None and "name" not in config:
                config["name"] = name
        kind = self._text(file, options.get("type") or options.get("transport"))
        if kind is not None:
            config["type"] = kind
        if "args" in options and "args" not in config:
            config["args"] = [
                self._launch_text(file, element)
                for _, element in self._elements(file, options["args"])
            ]
        for source in ("env", "headers"):
            if source in options:
                config[source] = {
                    key: self._launch_text(file, value)
                    for key, value in self._properties(file, options[source]).items()
                }
        return config

    def _declare(
        self, file: _File, node: Node, config: dict[str, Any], binding: str | None
    ) -> str | None:
        if config.get("command") == UNRESOLVED or config.get("url") == UNRESOLVED:
            self._found.gap(
                file.path,
                _line(node),
                "MCP server declared with a launch the collector cannot read",
            )
            return None
        return self._found.declare_server(
            file.path, _line(node), config, binding=binding, method=METHOD
        )

    def _server_map(self, file: _File, node: Node | None) -> set[str]:
        refs: set[str] = set()
        entries = self._properties(file, node)
        for nested in MCP_MAP_PROPERTIES:
            if nested in entries:
                return self._server_map(file, entries[nested])
        for name, entry in entries.items():
            for value in self._follow(file, entry):
                if value.type in {"call_expression", "new_expression"}:
                    refs |= self._server(file, value)
                    continue
                config = self._launch(file, self._properties(file, value))
                if config.get("command") or config.get("url"):
                    config["name"] = name
                    ref = self._declare(file, value, config, None)
                    if ref is not None:
                        refs.add(ref)
        return refs

    def _server(self, file: _File, node: Node) -> set[str]:
        """Record the MCP servers a call or constructor declares; return their references."""
        if node.id in self._servers:
            return self._servers[node.id]
        refs: set[str] = set()
        origin = self._callee(file, node)
        if origin is None or _package(origin[0], MCP_PACKAGES) is None:
            return refs
        symbol = origin[1].rsplit(".", 1)[-1]
        arguments = self._arguments(node)
        if symbol not in MCP_STDIO | MCP_URL | MCP_MAPS | MCP_CLIENTS:
            options = self._properties(file, arguments[0]) if arguments else {}
            holder = self._properties(file, options.get("options")) or options
            if "mcpServers" in holder and origin[0].startswith("@anthropic-ai/claude-agent-sdk"):
                refs |= self._server_map(file, holder["mcpServers"])
                self._servers[node.id] = refs
            return refs
        self._servers[node.id] = refs
        if not arguments:
            return refs
        if symbol in MCP_MAPS:
            refs |= self._server_map(file, arguments[0])
            return refs
        if symbol in MCP_CLIENTS:
            transport = self._properties(file, arguments[0]).get("transport")
            for value in self._follow(file, transport):
                if value.type in {"call_expression", "new_expression"}:
                    refs |= self._server(file, value)
                else:
                    config = self._launch(file, self._properties(file, value))
                    if config.get("command") or config.get("url"):
                        ref = self._declare(file, value, config, self._binding(file, node))
                        if ref is not None:
                            refs.add(ref)
            return refs
        first = self._unwrap(arguments[0])
        config = self._launch(file, self._properties(file, first))
        if "url" not in config and symbol in MCP_URL and first is not None:
            target = first
            if first.type == "new_expression":
                inner = self._arguments(first)
                target = inner[0] if inner else first
            if target.type != "object":
                config["url"] = self._launch_text(file, target)
        if symbol in MCP_SSE:
            config.setdefault("type", "sse")
        if config.get("command") or config.get("url"):
            ref = self._declare(file, node, config, self._binding(file, node))
            if ref is not None:
                refs.add(ref)
        return refs

    def _store(self, file: _File, node: Node) -> str | None:
        if node.type != "new_expression":
            return None
        origin = self._callee(file, node)
        if origin is None:
            return None
        symbol = origin[1].rsplit(".", 1)[-1]
        arguments = self._arguments(node)
        options: dict[str, Node] = {}
        for argument in arguments[:2]:
            options = {**self._properties(file, argument), **options}
        if symbol in SCRIPT_STORES:
            identity = next((options[key] for key in STORE_IDENTITIES if key in options), None)
            name = declared_name(self._text(file, identity)) or SCRIPT_STORES[symbol]
            return self._found.retrieval(
                file.path,
                _line(node),
                name,
                method=METHOD,
                digest=file.digest,
                corpus_type="vector-store",
                store=SCRIPT_STORES[symbol],
            )
        if symbol in SCRIPT_MEMORY and origin[0].startswith(
            ("@langchain/", "@mastra/", "langchain")
        ):
            return self._found.memory(
                file.path,
                _line(node),
                symbol,
                method=METHOD,
                digest=file.digest,
                store_type=SCRIPT_MEMORY[symbol],
            )
        return None
