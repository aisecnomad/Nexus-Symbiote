"""Agents, models, tools, MCP servers and credentials that TypeScript and JavaScript declare.

Reads calls whose callee is imported from a known agent framework: the Vercel AI SDK and
its provider packages, Mastra, the OpenAI Agents SDK, LangChain.js and LangGraph.js.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from nexus_symbiote import limits
from nexus_symbiote.core.enums import TrustTier
from nexus_symbiote.core.models import AgentComponent, ToolComponent
from nexus_symbiote.scanners import ts_tools
from nexus_symbiote.scanners.code_inventory import (
    _ENV_NAME,
    Builder,
    _scope,
    mcp_component,
    model_component,
    plausible_model,
)
from nexus_symbiote.scanners.mcp_credentials import credential_name

if TYPE_CHECKING:
    from tree_sitter import Node

MAX_NODES = 400_000
AI_SDK_PROVIDERS = {
    "@ai-sdk/openai": "openai",
    "@ai-sdk/anthropic": "anthropic",
    "@ai-sdk/google": "google",
    "@ai-sdk/google-vertex": "google-vertex",
    "@ai-sdk/amazon-bedrock": "aws-bedrock",
    "@ai-sdk/azure": "azure-openai",
    "@ai-sdk/mistral": "mistral",
    "@ai-sdk/groq": "groq",
    "@ai-sdk/cohere": "cohere",
    "@ai-sdk/xai": "xai",
    "@ai-sdk/deepseek": "deepseek",
    "ollama-ai-provider": "ollama",
    "@openrouter/ai-sdk-provider": "openrouter",
}
LANGCHAIN_MODELS = {
    ("@langchain/openai", "ChatOpenAI"): ("openai", "hosted"),
    ("@langchain/openai", "AzureChatOpenAI"): ("azure-openai", "hosted"),
    ("@langchain/openai", "OpenAIEmbeddings"): ("openai", "embedding"),
    ("@langchain/anthropic", "ChatAnthropic"): ("anthropic", "hosted"),
    ("@langchain/google-genai", "ChatGoogleGenerativeAI"): ("google", "hosted"),
    ("@langchain/google-vertexai", "ChatVertexAI"): ("google-vertex", "hosted"),
    ("@langchain/aws", "ChatBedrockConverse"): ("aws-bedrock", "hosted"),
    ("@langchain/ollama", "ChatOllama"): ("ollama", "hosted"),
    ("@langchain/mistralai", "ChatMistralAI"): ("mistral", "hosted"),
    ("@langchain/groq", "ChatGroq"): ("groq", "hosted"),
}
AGENT_CTORS = {
    ("@mastra/core/agent", "Agent"): "mastra",
    ("@mastra/core", "Agent"): "mastra",
    ("@openai/agents", "Agent"): "openai-agents",
    ("@openai/agents-core", "Agent"): "openai-agents",
    ("@langchain/langgraph/prebuilt", "createReactAgent"): "langgraph",
    ("langchain", "createAgent"): "langchain",
    ("@voltagent/core", "Agent"): "voltagent",
}
TOOL_FACTORIES = {
    ("ai", "tool"): "key",
    ("@mastra/core/tools", "createTool"): "id",
    ("@mastra/core", "createTool"): "id",
    ("@openai/agents", "tool"): "name",
    ("@langchain/core/tools", "tool"): "name",
    ("@langchain/core/tools", "DynamicStructuredTool"): "name",
    ("@langchain/core/tools", "DynamicTool"): "name",
}
LOOP_CALLS = {"generateText", "streamText", "generateObject", "streamObject"}
MCP_CTORS = {
    ("@openai/agents", "MCPServerStdio"),
    ("@openai/agents", "MCPServerStreamableHttp"),
    ("@openai/agents", "MCPServerSSE"),
    ("@mastra/mcp", "MCPClient"),
    ("@mastra/mcp", "MCPConfiguration"),
}


def _text(node: Node | None) -> str:
    return ts_tools._value(node)


def _string(node: Node | None) -> str | None:
    return ts_tools._string_value(node)


class TypeScriptSource:
    def __init__(self, path: str, root: Node, builder: Builder) -> None:
        self.path = path
        self.root = root
        self.b = builder
        self.imports: dict[str, tuple[str, str]] = {}
        self.values: dict[str, Node] = {}
        self.refs: dict[str, str] = {}
        self.nodes = list(self._walk(root))

    def _walk(self, root: Node) -> Iterator[Node]:
        stack = [root]
        count = 0
        while stack and count < MAX_NODES:
            node = stack.pop()
            count += 1
            yield node
            stack.extend(reversed(node.named_children))

    def index(self) -> None:
        for node in self.nodes:
            if node.type == "import_statement":
                source = _string(node.child_by_field_name("source"))
                if source is None:
                    continue
                for clause in node.named_children:
                    if clause.type != "import_clause":
                        continue
                    for part in clause.named_children:
                        if part.type == "identifier":
                            self.imports[_text(part)] = (source, "default")
                        elif part.type == "named_imports":
                            for spec in part.named_children:
                                if spec.type != "import_specifier":
                                    continue
                                imported = _text(spec.child_by_field_name("name"))
                                alias = spec.child_by_field_name("alias")
                                self.imports[_text(alias) if alias is not None else imported] = (
                                    source,
                                    imported,
                                )
                        elif part.type == "namespace_import":
                            for ident in part.named_children:
                                self.imports[_text(ident)] = (source, "*")
            elif node.type == "variable_declarator":
                name = node.child_by_field_name("name")
                value = node.child_by_field_name("value")
                if name is not None and name.type == "identifier" and value is not None:
                    self.values[_text(name)] = value

    def callee(self, node: Node) -> tuple[str, str] | None:
        target = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if target is None:
            return None
        if target.type == "identifier":
            return self.imports.get(_text(target))
        if target.type == "member_expression":
            obj = target.child_by_field_name("object")
            prop = target.child_by_field_name("property")
            if obj is not None and obj.type == "identifier" and prop is not None:
                found = self.imports.get(_text(obj))
                if found is not None:
                    return found[0], _text(prop)
        return None

    def args(self, node: Node) -> list[Node]:
        arguments = node.child_by_field_name("arguments")
        return list(arguments.named_children) if arguments is not None else []

    def prop(self, obj: Node | None, key: str) -> Node | None:
        if obj is None:
            return None
        if obj.type == "identifier" and _text(obj) in self.values:
            obj = self.values[_text(obj)]
        if obj.type != "object":
            return None
        for child in obj.named_children:
            if child.type == "pair":
                name = child.child_by_field_name("key")
                label = _string(name) if name is not None and name.type == "string" else _text(name)
                if label == key:
                    return child.child_by_field_name("value")
            elif child.type == "shorthand_property_identifier" and _text(child) == key:
                return child
        return None

    def entries(self, obj: Node | None) -> list[tuple[str, Node]]:
        if obj is None:
            return []
        if obj.type == "identifier" and _text(obj) in self.values:
            obj = self.values[_text(obj)]
        found: list[tuple[str, Node]] = []
        if obj.type == "object":
            for child in obj.named_children:
                if child.type == "pair":
                    key = child.child_by_field_name("key")
                    value = child.child_by_field_name("value")
                    label = _string(key) if key is not None and key.type == "string" else _text(key)
                    if label and value is not None:
                        found.append((label, value))
                elif child.type == "shorthand_property_identifier":
                    found.append((_text(child), child))
        elif obj.type == "array":
            for child in obj.named_children:
                found.append((_text(child) if child.type == "identifier" else "", child))
        return found

    def resolve(self, node: Node | None, depth: int = 0) -> Node | None:
        if node is None or depth > 4:
            return node
        if (
            node.type in {"identifier", "shorthand_property_identifier"}
            and _text(node) in self.values
        ):
            return self.resolve(self.values[_text(node)], depth + 1)
        if node.type in {
            "await_expression",
            "parenthesized_expression",
            "as_expression",
            "satisfies_expression",
        }:
            inner = node.named_children[0] if node.named_children else None
            return self.resolve(inner, depth + 1)
        return node

    def string_value(self, node: Node | None) -> str | None:
        node = self.resolve(node)
        return _string(node)

    def line(self, node: Node) -> int:
        return int(node.start_point[0]) + 1

    # ---- components

    def model(self, node: Node | None) -> str | None:
        node = self.resolve(node)
        if node is None:
            return None
        if node.type in {"call_expression", "new_expression"}:
            found = self.callee(node)
            if found is None:
                return None
            module, name = found
            provider = AI_SDK_PROVIDERS.get(module)
            if provider is not None:
                args = self.args(node)
                value = self.string_value(args[0]) if args else None
                if value and plausible_model(value, hub=True):
                    kind = (
                        "embedding"
                        if name.lower().startswith(("embedding", "textembedding"))
                        else "hosted"
                    )
                    return model_component(
                        self.b, value, provider, kind, self.path, self.line(node)
                    )
            mapped = LANGCHAIN_MODELS.get((module, name))
            if mapped is not None:
                args = self.args(node)
                options = args[0] if args else None
                value = self.string_value(
                    self.prop(options, "model") or self.prop(options, "modelName")
                )
                if value and plausible_model(value):
                    return model_component(
                        self.b, value, mapped[0], mapped[1], self.path, self.line(node)
                    )
            if module in {"@openai/agents", "@openai/agents-extensions"} and name == "aisdk":
                args = self.args(node)
                return self.model(args[0]) if args else None
            return None
        value = _string(node)
        if value and plausible_model(value):
            return model_component(self.b, value, None, "hosted", self.path, self.line(node))
        return None

    def tool(self, key: str, node: Node | None) -> str | None:
        resolved = self.resolve(node)
        if resolved is None:
            return None
        if resolved.type in {"call_expression", "new_expression"}:
            found = self.callee(resolved)
            kind = TOOL_FACTORIES.get(found) if found is not None else None
            if kind is None:
                return None
            args = self.args(resolved)
            options = args[-1] if args else None
            name: str | None = key if kind == "key" else self.string_value(self.prop(options, kind))
            name = (
                name
                or key
                or (_text(node) if node is not None and node.type == "identifier" else "")
            )
            if not name:
                return None
            description = self.string_value(self.prop(options, "description"))
            return self.b.add(
                ToolComponent(
                    bom_ref=f"tool:code:{_scope(PurePosixPath(self.path))}/{quote(name, safe='')}",
                    name=name,
                    description_text=description[:300] if description else None,
                    source_path=self.path,
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                    properties={
                        "collection_mode": "static-source",
                        "declared_at": f"{self.path}:{self.line(resolved)}",
                    },
                )
            )
        return None

    def agent(self, node: Node, framework: str, variable: str | None) -> str:
        args = self.args(node)
        options = args[0] if args else None
        name = (
            self.string_value(self.prop(options, "name"))
            or variable
            or f"{framework} agent at line {self.line(node)}"
        )
        ref = self.b.add(
            AgentComponent(
                bom_ref=f"agent:code:{_scope(PurePosixPath(self.path))}/{quote(name, safe='')}",
                name=name,
                framework=framework,
                source_path=self.path,
                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                properties={
                    "collection_mode": "static-source",
                    "declared_at": f"{self.path}:{self.line(node)}",
                    **({"variable": variable} if variable and variable != name else {}),
                },
            )
        )
        stored = self.b.components[ref]
        assert isinstance(stored, AgentComponent)
        if variable:
            self.refs[variable] = ref
        model = self.model(self.prop(options, "model") or self.prop(options, "llm"))
        if model:
            stored.model_refs.append(model)
            self.b.edge(ref, model, "uses-model")
        for key, value in self.entries(self.prop(options, "tools")):
            tool = self.tool(key, value)
            if tool is None and value.type in {"identifier", "shorthand_property_identifier"}:
                tool = self.tool(_text(value), self.values.get(_text(value)))
            if tool:
                stored.tool_refs.append(tool)
                self.b.edge(ref, tool, "invokes")
        for _, value in self.entries(self.prop(options, "handoffs")):
            target = self.refs.get(_text(value))
            if target:
                stored.sub_agent_refs.append(target)
                self.b.edge(ref, target, "delegates-to")
        for _, value in self.entries(self.prop(options, "mcpServers")):
            server = self.refs.get(_text(value))
            if server:
                stored.tool_refs.append(server)
                self.b.edge(ref, server, "invokes")
        return ref

    def mcp(self, node: Node, module: str, name: str, variable: str | None) -> None:
        args = self.args(node)
        options = args[0] if args else None
        if name in {"MCPClient", "MCPConfiguration"}:
            for label, server in self.entries(self.prop(options, "servers")):
                self._server(label, server, node)
            return
        own_label = self.string_value(self.prop(options, "name"))
        ref = self._server(own_label, options, node)
        if ref and variable:
            self.refs[variable] = ref

    def _server(self, label: str | None, options: Node | None, node: Node) -> str | None:
        command = self.string_value(self.prop(options, "command"))
        full = self.string_value(self.prop(options, "fullCommand"))
        args: list[str] = []
        if full and not command:
            words = full.split()
            command, args = (words[0], words[1:]) if words else (None, [])
        for _, value in self.entries(self.prop(options, "args")):
            text = _string(value)
            if text is not None:
                args.append(text)
        url_node = self.resolve(self.prop(options, "url"))
        url = _string(url_node)
        if url is None and url_node is not None and url_node.type == "new_expression":
            inner = self.args(url_node)
            url = _string(inner[0]) if inner else None
        env = [
            key for key, _ in self.entries(self.prop(options, "env")) if _ENV_NAME.fullmatch(key)
        ]
        return mcp_component(
            self.b,
            name=label,
            command=command,
            args=args,
            url=url,
            env=env,
            path=self.path,
            line=self.line(node),
        )

    def credentials(self) -> None:
        for node in self.nodes:
            if node.type not in {"member_expression", "subscript_expression"}:
                continue
            obj = node.child_by_field_name("object")
            if (
                obj is None
                or obj.type != "member_expression"
                or _text(obj).replace(" ", "") != "process.env"
            ):
                continue
            if node.type == "member_expression":
                name = _text(node.child_by_field_name("property"))
            else:
                name = _string(node.child_by_field_name("index")) or ""
            if _ENV_NAME.fullmatch(name) and credential_name(name):
                self.b.credential(name, "environment-variable")

    def collect(self) -> None:
        self.index()
        declared: dict[int, str] = {}
        for name, value in self.values.items():
            declared[value.id] = name
        for node in self.nodes:
            if node.type not in {"call_expression", "new_expression"}:
                continue
            found = self.callee(node)
            if found is None:
                continue
            variable = declared.get(node.id)
            if found in MCP_CTORS:
                self.mcp(node, found[0], found[1], variable)
        for node in self.nodes:
            if node.type not in {"call_expression", "new_expression"}:
                continue
            found = self.callee(node)
            if found is None:
                continue
            variable = declared.get(node.id)
            framework = AGENT_CTORS.get(found)
            if framework is not None:
                self.agent(node, framework, variable)
            elif found[0] == "ai" and found[1] in LOOP_CALLS:
                args = self.args(node)
                options = args[0] if args else None
                self.model(self.prop(options, "model"))
                for key, value in self.entries(self.prop(options, "tools")):
                    self.tool(key, value)
            elif found in TOOL_FACTORIES and TOOL_FACTORIES[found] != "key":
                self.tool(variable or "", node)
            elif found[0] in AI_SDK_PROVIDERS or found in LANGCHAIN_MODELS:
                self.model(node)
        self.credentials()


def collect(builder: Builder, path: str, text: str) -> str | None:
    """Read one TypeScript or JavaScript file; return why it could not be parsed."""
    source = text.encode("utf-8")
    scale = max(1.0, limits.current().syntax_bytes / limits.DEFAULTS.syntax_bytes)
    suffix = PurePosixPath(path).suffix
    try:
        tree: Any = ts_tools._parse(
            source, ts_tools._JSX.get(suffix, False), ts_tools.MAX_PARSE_SECONDS * 4 * scale
        )
    except (ValueError, ImportError, RuntimeError) as exc:
        return str(exc) or type(exc).__name__
    TypeScriptSource(path, tree.root_node, builder).collect()
    return None
