"""Agents, hosted models, tools, MCP servers and credentials that application code declares.

Configuration collectors record what a client launches. This collector reads what the
application itself constructs with an agent framework: each agent, the model it calls,
the tools and MCP servers it is given, the agents it hands off to, and the credentials
it authenticates with. Credentials are recorded by name; a value is never read into the
inventory, and one committed beside its name is reported as a risk.

Only calls that resolve to an import from a known framework module are read, so names
that merely look like agents, models or tools elsewhere in a checkout are not recorded.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import yaml

from nexus_symbiote import limits
from nexus_symbiote.core.aibom import DependencyEdge, Relationship
from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import (
    MODEL_REFERENCE,
    A2AClientComponent,
    AgentComponent,
    AnyComponent,
    CredentialComponent,
    DataSourceComponent,
    GuardrailComponent,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners import mcp_launch
from nexus_symbiote.scanners.base import (
    YAML_TOKEN_LIMIT,
    Scanner,
    ScanResult,
    SourceBudget,
    parse_python,
    sanitized_origin,
    source_collection_bytes,
)
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.mcp_credentials import credential_name
from nexus_symbiote.scanners.ts_tools import NOT_SOURCE_NAMES, SKIPPED_DIRECTORIES
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import REDACTED, holds_token_shape

COLLECTOR = "code"
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,127}")

# Hosted model identifiers by family. Read only where a framework call takes a model.
MODEL_ID = re.compile(
    r"""(?ix)^(
      (?:gpt|chatgpt)-[\w.:-]+ | o[1-9](?:-[\w.]+)* | text-embedding-[\w.-]+ | codex-[\w.-]+
      | omni-moderation[\w.-]* | dall-e-\d | whisper-\d | tts-\d[\w.-]* | gpt-image-[\w.-]+
      | claude-[\w.:@-]+ | (?:anthropic|amazon|meta|mistral|cohere|ai21|deepseek|qwen|writer|us|eu|apac)
        \.[\w.:-]+
      | gemini-[\w.:-]+ | gemma[\w.:-]* | (?:text|chat)-bison[\w@.-]* | text-embedding-\d+[\w@.-]*
      | (?:llama|codellama|mistral|mixtral|ministral|codestral|magistral|qwen|qwq|phi|deepseek|command
        |grok|jamba|nemotron|granite|olmo|falcon|smollm|kimi|glm|sonar)[\w.:/-]*
    )$""",
)
HUB_ID = re.compile(r"^[A-Za-z0-9][\w.-]{0,95}/[A-Za-z0-9][\w.-]{0,95}$")
_PROVIDER_PREFIXES = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google": "google",
    "google-gla": "google",
    "google-vertex": "google-vertex",
    "gemini": "google",
    "vertex_ai": "google-vertex",
    "bedrock": "aws-bedrock",
    "azure": "azure-openai",
    "groq": "groq",
    "mistral": "mistral",
    "cohere": "cohere",
    "ollama": "ollama",
    "ollama_chat": "ollama",
    "huggingface": "huggingface",
    "openrouter": "openrouter",
    "together_ai": "together",
    "deepseek": "deepseek",
    "xai": "xai",
}


def provider_of(model: str) -> str | None:
    """The provider a hosted model identifier names, from its prefix or its family."""
    low = model.lower()
    if re.match(
        r"^(gpt|chatgpt|o[1-9]|text-embedding|codex|omni-moderation|dall-e|whisper|tts)", low
    ):
        return "openai"
    if low.startswith("claude"):
        return "anthropic"
    if low.startswith(("gemini", "gemma", "text-bison", "chat-bison")):
        return "google"
    if re.match(r"^(anthropic|amazon|meta|mistral|cohere|ai21|us|eu|apac)\.", low):
        return "aws-bedrock"
    if low.startswith(("mistral", "mixtral", "ministral", "codestral", "magistral")):
        return "mistral"
    if low.startswith("command"):
        return "cohere"
    if low.startswith("grok"):
        return "xai"
    if low.startswith("deepseek"):
        return "deepseek"
    return None


def split_model(value: str) -> tuple[str | None, str]:
    """``provider:model`` and ``provider/model`` spellings, as (provider, model)."""
    for sep in (":", "/"):
        head, found, tail = value.partition(sep)
        if found and head.lower() in _PROVIDER_PREFIXES and tail:
            return _PROVIDER_PREFIXES[head.lower()], tail
    return None, value


def plausible_model(value: str, *, hub: bool = False) -> bool:
    if not value or len(value) > 160 or any(ch.isspace() for ch in value):
        return False
    _, bare = split_model(value)
    if MODEL_ID.match(bare):
        return True
    return hub and (
        HUB_ID.match(bare) is not None or re.fullmatch(r"[\w.-]{2,96}", bare) is not None
    )


# ------------------------------------------------------------------ framework tables


@dataclass(frozen=True)
class ModelCtor:
    modules: tuple[str, ...]
    provider: str | None
    kind: str = "hosted"
    keys: tuple[str, ...] = ("model", "model_name")
    positional: int | None = None


@dataclass(frozen=True)
class AgentCtor:
    modules: tuple[str, ...]
    framework: str
    name_keys: tuple[str, ...] = ("name",)
    name_pos: int | None = None
    model_keys: tuple[str, ...] = ("model", "llm")
    model_pos: int | None = None
    tools_keys: tuple[str, ...] = ("tools",)
    tools_pos: int | None = None
    sub_keys: tuple[str, ...] = ()
    mcp_keys: tuple[str, ...] = ()
    guard_keys: tuple[str, ...] = ()
    prompt_keys: tuple[str, ...] = ("instructions", "system_prompt", "prompt", "instruction")
    remote: bool = False


def _mc(
    modules: tuple[str, ...], provider: str | None, kind: str = "hosted", **kw: Any
) -> ModelCtor:
    return ModelCtor(modules, provider, kind, **kw)


MODEL_CTORS: dict[str, tuple[ModelCtor, ...]] = {
    "ChatOpenAI": (_mc(("langchain_openai", "langchain_community.chat_models"), "openai"),),
    "AzureChatOpenAI": (
        _mc(
            ("langchain_openai",),
            "azure-openai",
            keys=("azure_deployment", "deployment_name", "model"),
        ),
    ),
    "OpenAIEmbeddings": (
        _mc(("langchain_openai", "langchain_community.embeddings"), "openai", "embedding"),
    ),
    "AzureOpenAIEmbeddings": (
        _mc(("langchain_openai",), "azure-openai", "embedding", keys=("azure_deployment", "model")),
    ),
    "ChatAnthropic": (_mc(("langchain_anthropic",), "anthropic"),),
    "ChatGoogleGenerativeAI": (_mc(("langchain_google_genai",), "google"),),
    "GoogleGenerativeAIEmbeddings": (_mc(("langchain_google_genai",), "google", "embedding"),),
    "ChatVertexAI": (_mc(("langchain_google_vertexai",), "google-vertex"),),
    "VertexAIEmbeddings": (_mc(("langchain_google_vertexai",), "google-vertex", "embedding"),),
    "ChatBedrock": (_mc(("langchain_aws",), "aws-bedrock", keys=("model_id", "model")),),
    "ChatBedrockConverse": (_mc(("langchain_aws",), "aws-bedrock", keys=("model", "model_id")),),
    "BedrockEmbeddings": (_mc(("langchain_aws",), "aws-bedrock", "embedding", keys=("model_id",)),),
    "ChatOllama": (_mc(("langchain_ollama", "langchain_community.chat_models"), "ollama"),),
    "OllamaLLM": (_mc(("langchain_ollama",), "ollama"),),
    "OllamaEmbeddings": (
        _mc(("langchain_ollama", "langchain_community.embeddings"), "ollama", "embedding"),
    ),
    "ChatMistralAI": (_mc(("langchain_mistralai",), "mistral"),),
    "ChatGroq": (_mc(("langchain_groq",), "groq"),),
    "ChatCohere": (_mc(("langchain_cohere",), "cohere"),),
    "HuggingFaceEmbeddings": (
        _mc(
            ("langchain_huggingface", "langchain_community.embeddings"),
            "huggingface",
            "embedding",
            keys=("model_name", "model"),
        ),
    ),
    "init_chat_model": (
        _mc(("langchain.chat_models", "langchain"), None, keys=("model",), positional=0),
    ),
    "LLM": (_mc(("crewai",), None, keys=("model",), positional=0),),
    "OpenAI": (_mc(("llama_index.llms.openai",), "openai"),),
    "Anthropic": (_mc(("llama_index.llms.anthropic",), "anthropic"),),
    "BedrockConverse": (_mc(("llama_index.llms.bedrock_converse",), "aws-bedrock"),),
    "Bedrock": (_mc(("llama_index.llms.bedrock",), "aws-bedrock"),),
    "Ollama": (_mc(("llama_index.llms.ollama",), "ollama"),),
    "Gemini": (_mc(("llama_index.llms.gemini",), "google"),),
    "GoogleGenAI": (_mc(("llama_index.llms.google_genai",), "google"),),
    "AzureOpenAI": (
        _mc(("llama_index.llms.azure_openai",), "azure-openai", keys=("engine", "model")),
    ),
    "OpenAIEmbedding": (_mc(("llama_index.embeddings.openai",), "openai", "embedding"),),
    "HuggingFaceEmbedding": (
        _mc(("llama_index.embeddings.huggingface",), "huggingface", "embedding"),
    ),
    "OpenAIChatCompletionClient": (_mc(("autogen_ext.models.openai",), "openai"),),
    "AzureOpenAIChatCompletionClient": (
        _mc(("autogen_ext.models.openai",), "azure-openai", keys=("azure_deployment", "model")),
    ),
    "AnthropicChatCompletionClient": (_mc(("autogen_ext.models.anthropic",), "anthropic"),),
    "OllamaChatCompletionClient": (_mc(("autogen_ext.models.ollama",), "ollama"),),
    "InferenceClientModel": (
        _mc(("smolagents",), "huggingface", keys=("model_id",), positional=0),
    ),
    "HfApiModel": (_mc(("smolagents",), "huggingface", keys=("model_id",), positional=0),),
    "LiteLLMModel": (_mc(("smolagents",), None, keys=("model_id",), positional=0),),
    "OpenAIServerModel": (_mc(("smolagents",), "openai", keys=("model_id",), positional=0),),
    "TransformersModel": (
        _mc(("smolagents",), "huggingface", "hub", keys=("model_id",), positional=0),
    ),
    "OpenAIModel": (
        _mc(("pydantic_ai.models.openai",), "openai", keys=("model_name",), positional=0),
        _mc(("strands.models.openai",), "openai", keys=("model_id",)),
    ),
    "OpenAIChatModel": (
        _mc(("pydantic_ai.models.openai",), "openai", keys=("model_name",), positional=0),
    ),
    "OpenAIResponsesModel": (
        _mc(("pydantic_ai.models.openai",), "openai", keys=("model_name",), positional=0),
    ),
    "AnthropicModel": (
        _mc(("pydantic_ai.models.anthropic",), "anthropic", keys=("model_name",), positional=0),
        _mc(("strands.models.anthropic",), "anthropic", keys=("model_id",)),
    ),
    "GeminiModel": (
        _mc(("pydantic_ai.models.gemini",), "google", keys=("model_name",), positional=0),
    ),
    "GoogleModel": (
        _mc(("pydantic_ai.models.google",), "google", keys=("model_name",), positional=0),
    ),
    "BedrockConverseModel": (
        _mc(("pydantic_ai.models.bedrock",), "aws-bedrock", keys=("model_name",), positional=0),
    ),
    "BedrockModel": (
        _mc(("strands.models", "strands.models.bedrock"), "aws-bedrock", keys=("model_id",)),
    ),
    "LiteLlm": (_mc(("google.adk.models.lite_llm", "google.adk.models"), None, keys=("model",)),),
    "OpenAIChatCompletion": (
        _mc(("semantic_kernel.connectors.ai.open_ai",), "openai", keys=("ai_model_id",)),
    ),
    "AzureChatCompletion": (
        _mc(
            ("semantic_kernel.connectors.ai.open_ai",),
            "azure-openai",
            keys=("deployment_name", "ai_model_id"),
        ),
    ),
    "OpenAIChatGenerator": (
        _mc(("haystack.components.generators.chat",), "openai", keys=("model",)),
    ),
    "SentenceTransformer": (
        _mc(
            ("sentence_transformers",),
            "huggingface",
            "embedding",
            keys=("model_name_or_path",),
            positional=0,
        ),
    ),
    "pipeline": (_mc(("transformers",), "huggingface", "hub", keys=("model",)),),
}
_HUB_LOADERS = ("transformers", "peft", "diffusers", "sentence_transformers", "optimum")
_CLIENT_SDKS = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google.genai": "google",
    "google.generativeai": "google",
    "litellm": None,
    "mistralai": "mistral",
    "groq": "groq",
    "cohere": "cohere",
    "ollama": "ollama",
}
_CLIENT_CALLS = {
    "create",
    "parse",
    "stream",
    "generate_content",
    "completion",
    "acompletion",
    "chat",
    "generate",
}


def _ac(modules: tuple[str, ...], framework: str, **kw: Any) -> AgentCtor:
    return AgentCtor(modules, framework, **kw)


AGENT_CTORS: dict[str, tuple[AgentCtor, ...]] = {
    "create_react_agent": (
        _ac(("langgraph.prebuilt",), "langgraph", model_pos=0, tools_pos=1),
        _ac(("langchain.agents",), "langchain", model_keys=("llm",), model_pos=0, tools_pos=1),
    ),
    "create_agent": (_ac(("langchain.agents",), "langchain", model_pos=0, tools_pos=1),),
    "create_tool_calling_agent": (
        _ac(("langchain.agents",), "langchain", model_keys=("llm",), model_pos=0, tools_pos=1),
    ),
    "create_openai_tools_agent": (
        _ac(("langchain.agents",), "langchain", model_keys=("llm",), model_pos=0, tools_pos=1),
    ),
    "create_openai_functions_agent": (
        _ac(("langchain.agents",), "langchain", model_keys=("llm",), model_pos=0, tools_pos=1),
    ),
    "create_structured_chat_agent": (
        _ac(("langchain.agents",), "langchain", model_keys=("llm",), model_pos=0, tools_pos=1),
    ),
    "AgentExecutor": (_ac(("langchain.agents",), "langchain", model_keys=()),),
    "Agent": (
        _ac(("crewai",), "crewai", name_keys=("role",), model_keys=("llm",)),
        _ac(
            ("agents",),
            "openai-agents",
            sub_keys=("handoffs",),
            mcp_keys=("mcp_servers",),
            guard_keys=("input_guardrails", "output_guardrails"),
        ),
        _ac(("google.adk.agents", "google.adk"), "google-adk", sub_keys=("sub_agents",)),
        _ac(("pydantic_ai",), "pydantic-ai", model_pos=0, mcp_keys=("toolsets", "mcp_servers")),
        _ac(("strands",), "strands"),
        _ac(("haystack.components.agents",), "haystack", model_keys=("chat_generator",)),
    ),
    "LlmAgent": (_ac(("google.adk.agents", "google.adk"), "google-adk", sub_keys=("sub_agents",)),),
    "SequentialAgent": (
        _ac(("google.adk.agents",), "google-adk", model_keys=(), sub_keys=("sub_agents",)),
    ),
    "ParallelAgent": (
        _ac(("google.adk.agents",), "google-adk", model_keys=(), sub_keys=("sub_agents",)),
    ),
    "LoopAgent": (
        _ac(("google.adk.agents",), "google-adk", model_keys=(), sub_keys=("sub_agents",)),
    ),
    "RemoteA2aAgent": (
        _ac(("google.adk.agents.remote_a2a_agent", "google.adk.agents"), "google-adk", remote=True),
    ),
    "FunctionAgent": (
        _ac(("llama_index.core.agent.workflow", "llama_index.core.agent"), "llamaindex"),
    ),
    "ReActAgent": (
        _ac(("llama_index.core.agent.workflow", "llama_index.core.agent"), "llamaindex"),
    ),
    "CodeActAgent": (
        _ac(("llama_index.core.agent.workflow", "llama_index.core.agent"), "llamaindex"),
    ),
    "AgentWorkflow": (
        _ac(
            ("llama_index.core.agent.workflow",), "llamaindex", model_keys=(), sub_keys=("agents",)
        ),
    ),
    "AssistantAgent": (
        _ac(
            ("autogen_agentchat.agents",),
            "autogen",
            name_pos=0,
            model_keys=("model_client",),
            sub_keys=("handoffs",),
            mcp_keys=("workbench",),
            prompt_keys=("system_message",),
        ),
    ),
    "CodeAgent": (_ac(("smolagents",), "smolagents", sub_keys=("managed_agents",)),),
    "ToolCallingAgent": (_ac(("smolagents",), "smolagents", sub_keys=("managed_agents",)),),
    "ChatCompletionAgent": (
        _ac(
            ("semantic_kernel.agents",),
            "semantic-kernel",
            model_keys=("service",),
            tools_keys=("plugins",),
        ),
    ),
}

TOOL_MODULES = (
    "crewai_tools",
    "langchain_community.tools",
    "langchain_tavily",
    "langchain_google_community",
    "google.adk.tools",
    "smolagents",
    "agents",
    "llama_index.tools",
)
TOOL_FACTORIES = {
    "QueryEngineTool.from_defaults",
    "QueryEngineTool",
    "FunctionTool.from_defaults",
    "FunctionTool",
    "StructuredTool.from_function",
    "Tool.from_function",
    "Tool",
}
_HOSTED_AGENT_TOOLS = {
    "WebSearchTool",
    "FileSearchTool",
    "ComputerTool",
    "CodeInterpreterTool",
    "ImageGenerationTool",
}
DECORATOR_TOOLS = {
    ("langchain_core.tools", "tool"),
    ("langchain.tools", "tool"),
    ("crewai.tools", "tool"),
    ("agents", "function_tool"),
    ("agents.tool", "function_tool"),
    ("smolagents", "tool"),
    ("smolagents.tools", "tool"),
    ("langchain_core.tools.convert", "tool"),
    ("crewai.tools.base_tool", "tool"),
}
OWN_DECORATOR_TOOLS = {("strands", "tool"), ("pydantic_ai", "Tool")}

MCP_CTORS: dict[str, tuple[str, ...]] = {
    "MCPServerStdio": ("agents.mcp", "pydantic_ai.mcp"),
    "MCPServerSse": ("agents.mcp",),
    "MCPServerStreamableHttp": ("agents.mcp",),
    "MCPServerHTTP": ("pydantic_ai.mcp",),
    "MCPServerSSE": ("pydantic_ai.mcp",),
    "MCPServerStreamableHTTP": ("pydantic_ai.mcp",),
    "MCPToolset": (
        "google.adk.tools.mcp_tool",
        "google.adk.tools.mcp_tool.mcp_toolset",
        "google.adk.tools",
    ),
    "McpWorkbench": ("autogen_ext.tools.mcp",),
    "StdioServerParams": ("autogen_ext.tools.mcp",),
    "SseServerParams": ("autogen_ext.tools.mcp",),
    "StdioServerParameters": ("mcp", "mcp.client.stdio"),
    "BasicMCPClient": ("llama_index.tools.mcp",),
}
_MCP_PARAM_KEYS = ("connection_params", "server_params", "params")

GUARD_CTORS = {
    "Guard": ("guardrails",),
    "RailsConfig.from_path": ("nemoguardrails",),
    "LLMRails": ("nemoguardrails",),
}
DATASET_CALLS = {"load_dataset": ("datasets",)}

_DANGEROUS_CALLS = {
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("os", "system"),
    ("os", "popen"),
}


def _module_ok(module: str, modules: Iterable[str]) -> bool:
    return any(module == m or module.startswith(m + ".") for m in modules)


# ------------------------------------------------------------------ inventory builder


@dataclass
class Builder:
    """Collects one scan's components with stable references and typed edges."""

    result: ScanResult
    components: dict[str, AnyComponent] = field(default_factory=dict)
    edges: set[tuple[str, str, str]] = field(default_factory=set)
    conditions: dict[tuple[str, str, str], str] = field(default_factory=dict)
    touched: int = 0

    def add(self, component: AnyComponent) -> str:
        self.touched += 1
        existing = self.components.get(component.bom_ref)
        if existing is None:
            self.components[component.bom_ref] = component
            return component.bom_ref
        risks = getattr(component, "risks", None)
        if isinstance(risks, list) and hasattr(existing, "risks"):
            known = {(r.category, r.detail) for r in existing.risks}
            existing.risks.extend(r for r in risks if (r.category, r.detail) not in known)
        return existing.bom_ref

    def edge(
        self, source: str, target: str, relationship: Relationship, condition: str | None = None
    ) -> None:
        if source and target and source != target:
            key = (source, target, relationship)
            self.edges.add(key)
            self.touched += 1
            if condition and key not in self.conditions:
                self.conditions[key] = condition

    def credential(self, name: str, kind: str, *, committed: bool = False, where: str = "") -> str:
        ref = self.add(
            CredentialComponent(
                bom_ref=f"credential:{name}",
                name=name,
                credential_kind=(
                    "workflow-credential"
                    if kind == "workflow-credential"
                    else "environment-variable"
                ),
                trust_tier=TrustTier.UNKNOWN,
            )
        )
        comp = self.components[ref]
        assert isinstance(comp, CredentialComponent)
        comp.properties.setdefault("reference_kinds", [])
        if kind not in comp.properties["reference_kinds"]:
            comp.properties["reference_kinds"].append(kind)
        if committed:
            comp.value_in_checkout = True
            detail = f"A value for {name} is committed in {where}; the value was not recorded"
            if all(r.detail != detail for r in comp.risks):
                comp.risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.HIGH,
                        category="credential_exposure",
                        detail=detail,
                        recommendation="Remove the value from the checkout, rotate it, and load it from a secret store",
                    )
                )
        return ref

    def literal_credential(self, owner: str, parameter: str, path: str, line: int) -> None:
        """A credential-shaped literal passed as ``parameter``; only where it is is recorded."""
        ref = self.add(
            CredentialComponent(
                bom_ref=f"credential:literal:{_scope(PurePosixPath(path))}/{quote(parameter, safe='')}",
                name=parameter,
                credential_kind="source-literal",
                value_in_checkout=True,
                source_path=path,
                trust_tier=TrustTier.UNKNOWN,
                properties={"declared_at": f"{path}:{line}"},
                risks=[
                    RiskAssessment(
                        severity=RiskSeverity.HIGH,
                        category="credential_exposure",
                        detail=(
                            f"A token-shaped {parameter} literal is passed at {path}:{line}; "
                            "the value was not recorded"
                        ),
                        recommendation=(
                            "Remove the value from the source, rotate it, and load it from a "
                            "secret store"
                        ),
                    )
                ],
            )
        )
        self.edge(owner, ref, "acts-as-identity", f"literal in {path}")

    def finish(self) -> None:
        for component in self.components.values():
            if isinstance(component, CredentialComponent) and component.value_in_checkout is None:
                component.value_in_checkout = False
            self.result.components.append(component)
        for source, target, relationship in sorted(self.edges):
            if source in self.components and target in self.components:
                self.result.dependencies.append(
                    DependencyEdge(
                        source_ref=source,
                        target_ref=target,
                        relationship=relationship,
                        assurance_level="declared",
                        conditions=self.conditions.get((source, target, relationship)),
                    )
                )


def _scope(path: PurePosixPath | Path) -> str:
    return quote(path.as_posix(), safe="")


def model_component(
    builder: Builder,
    raw: str,
    provider: str | None,
    kind: str,
    path: str,
    line: int,
    framework: str | None = None,
) -> str:
    prefix_provider, name = split_model(raw)
    provider = prefix_provider or provider or provider_of(name)
    if kind == "hub" or (provider == "huggingface" and HUB_ID.match(name)):
        ref, reference = f"model:hub:{name}", "hub"
        model_type = "embedding" if kind == "embedding" else "foundation"
    else:
        ref, reference = f"model:hosted:{provider or 'unknown'}:{name}", "hosted"
        model_type = "embedding" if kind == "embedding" else "hosted"
    properties: dict[str, Any] = {
        "collection_mode": "static-source",
        "first_seen": f"{path}:{line}",
        MODEL_REFERENCE: reference,
    }
    if framework:
        properties["framework"] = framework
    return builder.add(
        ModelComponent(
            bom_ref=ref,
            name=name,
            model_type=model_type,
            provider=provider,
            requested_alias=raw,
            source_path=path,
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            properties=properties,
        )
    )


def mcp_component(
    builder: Builder,
    *,
    name: str | None,
    command: str | None,
    args: list[str],
    url: str | None,
    env: Iterable[str],
    path: str,
    line: int,
) -> str | None:
    package_name: str | None = None
    version: str | None = None
    launcher: str | None = None
    purl: str | None = None
    pinned: bool | None = None
    if command:
        try:
            launch = mcp_launch.analyze(command, list(args))
        except (ValueError, RecursionError):
            launch = None
        if launch is not None and launch.packages:
            pkg = launch.packages[0]
            package_name, version, pinned = pkg.name, pkg.version, pkg.pinned
            if package_name:
                launcher = f"{pkg.ecosystem}:{package_name}"
                purl = package_url(pkg.ecosystem, package_name, version)
    transport = "stdio" if command else ("http" if url else None)
    label = name or (package_name.rsplit("/", 1)[-1] if package_name else None)
    if label is None and url:
        label = sanitized_origin(url)
    if not label:
        return None
    endpoint = sanitized_origin(url) if url else None
    return builder.add(
        MCPServerComponent(
            bom_ref=f"mcp-server:code:{_scope(PurePosixPath(path))}/{quote(label, safe='')}",
            name=label,
            version=version,
            transport=transport,
            command=mcp_launch.normalize_command(command) if command else None,
            launcher_package=launcher,
            package_url=purl,
            args=[REDACTED for _ in args],
            env=dict.fromkeys(sorted(env), REDACTED),
            endpoint_url=endpoint,
            version_pinned=pinned,
            source_path=path,
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            properties={"collection_mode": "static-source", "declared_at": f"{path}:{line}"},
        )
    )


def package_url(ecosystem: str, name: str, version: str | None) -> str | None:
    kinds = {
        "npm": "npm",
        "pypi": "pypi",
        "python": "pypi",
        "oci": "oci",
        "docker": "docker",
        "go": "golang",
    }
    kind = kinds.get(ecosystem.lower())
    if kind is None:
        return None
    if kind == "npm":
        body = quote(name, safe="/")
    elif kind == "pypi":
        body = re.sub(r"[-_.]+", "-", name).lower()
    else:
        body = quote(name, safe="/")
    return f"pkg:{kind}/{body}" + (f"@{quote(version, safe='')}" if version else "")


# ------------------------------------------------------------------ python source


@dataclass
class _Call:
    module: str
    qual: str
    node: ast.Call


class PythonSource:
    """One parsed Python file and the framework calls it makes."""

    def __init__(
        self,
        path: str,
        tree: ast.Module,
        nodes: list[ast.AST],
        builder: Builder,
        local: frozenset[str] = frozenset(),
    ) -> None:
        self.path = path
        self.tree = tree
        self.nodes = nodes
        self.b = builder
        # Top-level names the checkout itself provides to this file: such an import is
        # project code, whatever framework shares its name (an ``agents`` package).
        self.local = local
        self.imports: dict[str, tuple[str, str | None]] = {}
        self.assigns: dict[str, ast.expr] = {}
        self.target_of: dict[int, str] = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.parent: dict[int, ast.AST] = {}
        self.agent_refs: dict[int, str] = {}
        self.var_refs: dict[str, str] = {}
        self._shell: dict[int, bool] = {}
        self._index()

    # ---- indexing

    def _index(self) -> None:
        for node in self.nodes:
            for child in ast.iter_child_nodes(node):
                self.parent[id(child)] = node
            if isinstance(node, ast.ImportFrom) and node.module and not node.level:
                if node.module.split(".", 1)[0] in self.local:
                    continue
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = (node.module, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in self.local:
                        continue
                    local = alias.asname or alias.name.split(".")[0]
                    self.imports[local] = (
                        alias.name if alias.asname else alias.name.split(".")[0],
                        None,
                    )
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                self._bind(node.targets[0], node.value)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                self._bind(node.target, node.value)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        self._bind(item.optional_vars, item.context_expr)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)

    def _bind(self, target: ast.expr, value: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self.assigns[target.id] = value
            self.target_of[id(value)] = target.id
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
        ):
            self.target_of[id(value)] = target.attr

    # ---- resolution helpers

    def origin(self, func: ast.expr) -> tuple[str, str] | None:
        parts: list[str] = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name) or node.id not in self.imports:
            return None
        module, name = self.imports[node.id]
        parts.reverse()
        if name is None:
            if not parts:
                return None
            return module, ".".join(parts)
        return module, ".".join([name, *parts])

    def string(self, node: ast.expr | None, depth: int = 0) -> str | None:
        if node is None or depth > 4:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self.assigns:
            return self.string(self.assigns[node.id], depth + 1)
        if isinstance(node, ast.Call):
            env = self.env_read(node)
            if env is not None and len(node.args) > 1:
                return self.string(node.args[1], depth + 1)
            for kw in node.keywords:
                if kw.arg == "default":
                    return self.string(kw.value, depth + 1)
        return None

    def strings(self, node: ast.expr | None) -> list[str]:
        if isinstance(node, ast.Name) and node.id in self.assigns:
            node = self.assigns[node.id]
        if isinstance(node, (ast.List, ast.Tuple)):
            return [s for s in (self.string(e) for e in node.elts) if s is not None]
        return []

    def env_read(self, node: ast.AST) -> str | None:
        """The variable name in os.environ[...], os.environ.get(...), os.getenv(...)."""
        if isinstance(node, ast.Subscript):
            base = self.origin(node.value) if isinstance(node.value, ast.Attribute) else None
            named = isinstance(node.value, ast.Name) and self.imports.get(node.value.id) == (
                "os",
                "environ",
            )
            if base == ("os", "environ") or named:
                key = node.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    return key.value
            return None
        if isinstance(node, ast.Call) and node.args:
            found = self.origin(node.func)
            if found in {("os", "getenv"), ("os", "environ.get"), ("os", "getenv")} or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and self.imports.get(node.func.value.id) == ("os", "environ")
            ):
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    return first.value
        return None

    def kw(self, call: ast.Call, keys: Iterable[str]) -> ast.expr | None:
        wanted = tuple(keys)
        for key in wanted:
            for item in call.keywords:
                if item.arg == key:
                    return item.value
        return None

    def calls(self) -> Iterator[_Call]:
        for node in self.nodes:
            if isinstance(node, ast.Call):
                found = self.origin(node.func)
                if found is not None:
                    yield _Call(found[0], found[1], node)

    def line(self, node: ast.AST) -> int:
        return getattr(node, "lineno", 1)

    def enclosing_call(self, node: ast.AST) -> ast.Call | None:
        current = self.parent.get(id(node))
        while current is not None:
            if isinstance(current, ast.Call):
                return current
            current = self.parent.get(id(current))
        return None

    # ---- components

    def model(
        self, node: ast.expr | None, provider: str | None = None, *, depth: int = 0
    ) -> str | None:
        if node is None or depth > 4:
            return None
        if isinstance(node, ast.Name) and node.id in self.var_refs:
            return self.var_refs[node.id]
        if isinstance(node, ast.Name) and node.id in self.assigns:
            return self.model(self.assigns[node.id], provider, depth=depth + 1)
        if isinstance(node, ast.Call):
            found = self.origin(node.func)
            if found is not None:
                ref = self.model_call(_Call(found[0], found[1], node))
                if ref:
                    return ref
            return None
        value = self.string(node)
        if value is not None and plausible_model(value):
            return model_component(self.b, value, provider, "hosted", self.path, self.line(node))
        return None

    def model_call(self, call: _Call) -> str | None:
        last = call.qual.rsplit(".", 1)[-1]
        if last == "from_pretrained" and _module_ok(call.module, _HUB_LOADERS):
            arg = (
                call.node.args[0]
                if call.node.args
                else self.kw(call.node, ("pretrained_model_name_or_path",))
            )
            value = self.string(arg)
            if value and plausible_model(value, hub=True) and "/" in value:
                return model_component(
                    self.b, value, "huggingface", "hub", self.path, self.line(call.node)
                )
            return None
        for ctor in MODEL_CTORS.get(call.qual, ()):
            if not _module_ok(call.module, ctor.modules):
                continue
            value_node = self.kw(call.node, ctor.keys)
            if (
                value_node is None
                and ctor.positional is not None
                and len(call.node.args) > ctor.positional
            ):
                value_node = call.node.args[ctor.positional]
            value = self.string(value_node)
            hub = ctor.kind in {"hub", "embedding"} and ctor.provider == "huggingface"
            if value and plausible_model(value, hub=hub):
                ref = model_component(
                    self.b, value, ctor.provider, ctor.kind, self.path, self.line(call.node)
                )
                self.var_refs.setdefault(self.target_of.get(id(call.node), ""), ref)
                self._link_credentials(call.node, ref)
                return ref
        return None

    def client_models(self) -> None:
        sdks = {
            provider
            for module, _ in self.imports.values()
            for sdk, provider in _CLIENT_SDKS.items()
            if module == sdk or module.startswith(sdk + ".")
        }
        if not sdks:
            return
        for node in self.nodes:
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr not in _CLIENT_CALLS:
                continue
            value = self.string(self.kw(node, ("model",)))
            if value and plausible_model(value):
                provider = next(iter(sdks)) if len(sdks) == 1 else None
                model_component(self.b, value, provider, "hosted", self.path, self.line(node))

    def tool(self, element: ast.expr, owner: str | None) -> list[str]:
        """References of the tools one list element names; sub-agents become edges."""
        refs: list[str] = []
        if isinstance(element, ast.Name):
            name = element.id
            if name in self.var_refs and self.var_refs[name].startswith(("agent:", "a2a-client:")):
                if owner:
                    self.b.edge(owner, self.var_refs[name], "delegates-to")
                return refs
            if name in self.functions:
                fn = self.functions[name]
                decorated = self._decorator_tool(fn)
                if decorated is not None:
                    refs.append(decorated)
                    return refs
                refs.append(self._own_tool(name, fn, fn.lineno))
                return refs
            if name in self.assigns and isinstance(self.assigns[name], ast.Call):
                return self.tool(self.assigns[name], owner)
            imported = self.imports.get(name)
            if imported is not None and _module_ok(imported[0], TOOL_MODULES):
                refs.append(self._own_tool(imported[1] or name, None, self.line(element)))
            return refs
        if isinstance(element, ast.Call):
            found = self.origin(element.func)
            if found is None:
                return refs
            module, qual = found
            last = qual.split(".")[0]
            if qual in {"AgentTool"} or (
                qual == "AgentTool" and _module_ok(module, ("google.adk.tools",))
            ):
                agent = self.kw(element, ("agent",)) or (element.args[0] if element.args else None)
                if isinstance(agent, ast.Name) and agent.id in self.var_refs and owner:
                    self.b.edge(owner, self.var_refs[agent.id], "delegates-to")
                return refs
            if last in MCP_CTORS and any(_module_ok(module, (m,)) for m in MCP_CTORS[last]):
                server = self.mcp(element)
                if server and owner:
                    self.b.edge(owner, server, "invokes")
                return refs
            if qual in TOOL_FACTORIES or any(
                qual.startswith(f + ".") for f in ("QueryEngineTool", "FunctionTool")
            ):
                name_node = self.kw(element, ("name",))
                label = self.string(name_node)
                if label is None:
                    named = self.kw(element, ("fn", "func")) or (
                        element.args[0] if element.args else None
                    )
                    if isinstance(named, ast.Name):
                        label = named.id
                if label:
                    refs.append(self._own_tool(label, None, self.line(element)))
                    self._tool_targets(element, refs[-1])
                return refs
            if _module_ok(module, TOOL_MODULES) or last in _HOSTED_AGENT_TOOLS:
                refs.append(self._own_tool(last, None, self.line(element)))
        return refs

    def _tool_targets(self, call: ast.Call, tool_ref: str) -> None:
        engine = self.kw(call, ("query_engine",))
        if isinstance(engine, ast.Call) and isinstance(engine.func, ast.Attribute):
            base = engine.func.value
            if isinstance(base, ast.Name) and base.id in self.var_refs:
                self.b.edge(tool_ref, self.var_refs[base.id], "retrieves-from")

    def _decorator_tool(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        for deco in fn.decorator_list:
            target = deco.func if isinstance(deco, ast.Call) else deco
            found = self.origin(target)
            if found is None:
                continue
            if found in DECORATOR_TOOLS:
                name = fn.name
                if isinstance(deco, ast.Call):
                    explicit = (
                        self.string(deco.args[0])
                        if deco.args
                        else self.string(self.kw(deco, ("name", "name_override")))
                    )
                    name = explicit or name
                return f"tool:python:{quote(self.path, safe='')}/{name}"
            if found in OWN_DECORATOR_TOOLS:
                return self._own_tool(fn.name, fn, fn.lineno)
        return None

    def _own_tool(
        self, name: str, fn: ast.FunctionDef | ast.AsyncFunctionDef | None, line: int
    ) -> str:
        description = ast.get_docstring(fn) if fn is not None else None
        ref = f"tool:code:{_scope(PurePosixPath(self.path))}/{quote(name, safe='')}"
        risks: list[RiskAssessment] = []
        if fn is not None and self._executes_shell(fn):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="capability_scope",
                    detail=f"Tool {name} runs operating-system commands (subprocess or os.system)",
                    recommendation="Restrict the command set, avoid shell=True, and require approval",
                )
            )
        return self.b.add(
            ToolComponent(
                bom_ref=ref,
                name=name,
                description_text=(description or "").strip().splitlines()[0][:300]
                if description
                else None,
                source_path=self.path,
                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                risks=risks,
                properties={
                    "collection_mode": "static-source",
                    "declared_at": f"{self.path}:{line}",
                },
            )
        )

    def _executes_shell(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        # Each function body is walked once, however many agents are given the tool.
        known = self._shell.get(id(fn))
        if known is None:
            known = self._shell[id(fn)] = any(
                isinstance(node, ast.Call)
                and (found := self.origin(node.func)) is not None
                and (found[0].split(".")[0], found[1]) in _DANGEROUS_CALLS
                for node in ast.walk(fn)
            )
        return known

    def mcp(self, call: ast.Call) -> str | None:
        found = self.origin(call.func)
        qual = found[1] if found else ""
        name = self.string(self.kw(call, ("name",)))
        params = self.kw(call, _MCP_PARAM_KEYS)
        if isinstance(params, ast.Name) and params.id in self.assigns:
            params = self.assigns[params.id]
        command: str | None = None
        args: list[str] = []
        url: str | None = None
        env: set[str] = set()
        if isinstance(params, ast.Dict):
            fields = {
                self.string(k): v
                for k, v in zip(params.keys, params.values, strict=True)
                if k is not None
            }
            command = self.string(fields.get("command"))
            args = self.strings(fields.get("args"))
            url = self.string(fields.get("url"))
            env |= self._dict_credentials(fields.get("env"))
            env |= self._dict_credentials(fields.get("headers"))
        elif isinstance(params, ast.Call):
            return self.mcp_from_params(params, name)
        else:
            command = self.string(self.kw(call, ("command",))) or (
                self.string(call.args[0])
                if call.args and qual.startswith("MCPServerStdio")
                else None
            )
            args = self.strings(self.kw(call, ("args",)))
            url = self.string(self.kw(call, ("url",)))
            env |= self._dict_credentials(self.kw(call, ("env",)))
            env |= self._dict_credentials(self.kw(call, ("headers",)))
        ref = mcp_component(
            self.b,
            name=name,
            command=command,
            args=args,
            url=url,
            env=env,
            path=self.path,
            line=self.line(call),
        )
        if ref is not None:
            self.var_refs.setdefault(self.target_of.get(id(call), ""), ref)
            for cred in sorted(env):
                if credential_name(cred):
                    self.b.edge(
                        ref, self.b.credential(cred, "environment-variable"), "acts-as-identity"
                    )
        return ref

    def mcp_from_params(self, params: ast.Call, name: str | None) -> str | None:
        command = self.string(self.kw(params, ("command",)))
        args = self.strings(self.kw(params, ("args",)))
        url = self.string(self.kw(params, ("url",)))
        env = self._dict_credentials(self.kw(params, ("env", "headers")))
        server_params = self.kw(params, ("server_params",))
        if isinstance(server_params, ast.Call):
            return self.mcp_from_params(server_params, name)
        return mcp_component(
            self.b,
            name=name,
            command=command,
            args=args,
            url=url,
            env=env,
            path=self.path,
            line=self.line(params),
        )

    def _dict_credentials(self, node: ast.expr | None) -> set[str]:
        names: set[str] = set()
        if isinstance(node, ast.Name) and node.id in self.assigns:
            node = self.assigns[node.id]
        if not isinstance(node, ast.Dict):
            return names
        for key, value in zip(node.keys, node.values, strict=True):
            for sub in ast.walk(value):
                env = self.env_read(sub)
                if env and _ENV_NAME.fullmatch(env):
                    names.add(env)
            key_text = self.string(key) if key is not None else None
            if key_text and _ENV_NAME.fullmatch(key_text) and credential_name(key_text):
                names.add(key_text)
        return names

    def multi_server_client(self, call: ast.Call, owner: str | None) -> list[str]:
        refs: list[str] = []
        config = call.args[0] if call.args else self.kw(call, ("connections",))
        if isinstance(config, ast.Name) and config.id in self.assigns:
            config = self.assigns[config.id]
        if not isinstance(config, ast.Dict):
            return refs
        for key, value in zip(config.keys, config.values, strict=True):
            name = self.string(key) if key is not None else None
            if not name or not isinstance(value, ast.Dict):
                continue
            fields = {
                self.string(k): v
                for k, v in zip(value.keys, value.values, strict=True)
                if k is not None
            }
            env = self._dict_credentials(fields.get("env")) | self._dict_credentials(
                fields.get("headers")
            )
            ref = mcp_component(
                self.b,
                name=name,
                command=self.string(fields.get("command")),
                args=self.strings(fields.get("args")),
                url=self.string(fields.get("url")),
                env=env,
                path=self.path,
                line=self.line(value),
            )
            if ref:
                refs.append(ref)
                for cred in sorted(env):
                    if credential_name(cred):
                        self.b.edge(
                            ref, self.b.credential(cred, "environment-variable"), "acts-as-identity"
                        )
        return refs

    def identity(
        self, call: _Call, ctor: AgentCtor, crew_roles: dict[str, dict[str, Any]]
    ) -> tuple[str, str, str | None, str | None]:
        """The agent's name, reference, variable and crew configuration key."""
        node = call.node
        variable = self.target_of.get(id(node))
        name = self.string(self.kw(node, ctor.name_keys))
        if name is None and ctor.name_pos is not None and len(node.args) > ctor.name_pos:
            name = self.string(node.args[ctor.name_pos])
        config_key: str | None = None
        config = self.kw(node, ("config",))
        if isinstance(config, ast.Subscript) and isinstance(config.slice, ast.Constant):
            config_key = config.slice.value if isinstance(config.slice.value, str) else None
        if name is None and config_key is not None:
            role = crew_roles.get(config_key, {}).get("role")
            name = role.strip() if isinstance(role, str) and role.strip() else config_key
        if (
            name is None
            and ctor.framework == "crewai"
            and isinstance(self.parent.get(id(node)), ast.Return)
        ):
            function = self._enclosing_function(node)
            name = function.name if function is not None else None
        name = name or variable
        if not name:
            name = f"{ctor.framework} agent at line {self.line(node)}"
        kind = "a2a-client" if ctor.remote else "agent"
        ref = f"{kind}:code:{_scope(PurePosixPath(self.path))}/{quote(name, safe='')}"
        return name, ref, variable, config_key

    def register(self, call: _Call, ctor: AgentCtor, crew_roles: dict[str, dict[str, Any]]) -> None:
        _, ref, variable, _ = self.identity(call, ctor, crew_roles)
        if variable:
            self.var_refs.setdefault(variable, ref)
        self.agent_refs.setdefault(id(call.node), ref)

    def agent(
        self, call: _Call, ctor: AgentCtor, crew_roles: dict[str, dict[str, Any]]
    ) -> str | None:
        node = call.node
        name, _, variable, config_key = self.identity(call, ctor, crew_roles)
        if ctor.remote:
            card = self.string(self.kw(node, ("agent_card",)))
            ref = self.b.add(
                A2AClientComponent(
                    bom_ref=f"a2a-client:code:{_scope(PurePosixPath(self.path))}/{quote(name, safe='')}",
                    name=name,
                    agent_card_url=sanitized_origin(card) if card and "://" in card else None,
                    supported_protocols=["a2a"],
                    source_path=self.path,
                    trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                    properties={
                        "collection_mode": "static-source",
                        "framework": ctor.framework,
                        "declared_at": f"{self.path}:{self.line(node)}",
                    },
                )
            )
            if variable:
                self.var_refs[variable] = ref
            return ref
        ref = f"agent:code:{_scope(PurePosixPath(self.path))}/{quote(name, safe='')}"
        agent = AgentComponent(
            bom_ref=ref,
            name=name,
            framework=ctor.framework,
            source_path=self.path,
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            properties={
                "collection_mode": "static-source",
                "declared_at": f"{self.path}:{self.line(node)}",
                **({"variable": variable} if variable and variable != name else {}),
            },
        )
        ref = self.b.add(agent)
        stored = self.b.components[ref]
        assert isinstance(stored, AgentComponent)
        if variable:
            self.var_refs[variable] = ref
        self.agent_refs[id(node)] = ref
        model_node = self.kw(node, ctor.model_keys) if ctor.model_keys else None
        if model_node is None and ctor.model_pos is not None and len(node.args) > ctor.model_pos:
            model_node = node.args[ctor.model_pos]
        if model_node is None and config_key is not None:
            llm = crew_roles.get(config_key, {}).get("llm")
            if isinstance(llm, str) and plausible_model(llm):
                model_ref: str | None = model_component(
                    self.b, llm, None, "hosted", self.path, self.line(node)
                )
            else:
                model_ref = None
        else:
            model_ref = self.model(model_node)
        if model_ref:
            stored.model_refs.append(model_ref)
            self.b.edge(ref, model_ref, "uses-model")
        tools_node = self.kw(node, ctor.tools_keys)
        if tools_node is None and ctor.tools_pos is not None and len(node.args) > ctor.tools_pos:
            tools_node = node.args[ctor.tools_pos]
        for element in self._elements(tools_node):
            for tool_ref in self.tool(element, ref):
                if tool_ref not in stored.tool_refs:
                    stored.tool_refs.append(tool_ref)
                if tool_ref in self.b.components:
                    self.b.edge(ref, tool_ref, "invokes")
            if isinstance(element, ast.Call):
                found = self.origin(element.func)
                if found and found[1] == "MultiServerMCPClient":
                    for server in self.multi_server_client(element, ref):
                        self.b.edge(ref, server, "invokes")
        for element in self._elements(self.kw(node, ctor.sub_keys) if ctor.sub_keys else None):
            target = self._agent_ref(element)
            if target and target != ref:
                if target not in stored.sub_agent_refs:
                    stored.sub_agent_refs.append(target)
                self.b.edge(ref, target, "delegates-to")
        for element in self._elements(self.kw(node, ctor.mcp_keys) if ctor.mcp_keys else None):
            server_ref = self._server_ref(element)
            if server_ref:
                if server_ref not in stored.tool_refs:
                    stored.tool_refs.append(server_ref)
                self.b.edge(ref, server_ref, "invokes")
        for element in self._elements(self.kw(node, ctor.guard_keys) if ctor.guard_keys else None):
            guard = self._guardrail(element)
            if guard:
                stored.guardrail_refs.append(guard)
                self.b.edge(ref, guard, "uses-guardrail")
        shell = any(
            r.startswith("tool:code:") and self._tool_has_risk(r) for r in stored.tool_refs
        ) or any(
            isinstance(e, ast.Name)
            and e.id in self.functions
            and self._decorator_tool(self.functions[e.id])
            and self._executes_shell(self.functions[e.id])
            for e in self._elements(tools_node)
        )
        detail = f"Agent {name} can run operating-system commands through a tool"
        if shell and all(r.detail != detail for r in stored.risks):
            stored.risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="capability_scope",
                    detail=detail,
                    recommendation="Gate command execution behind approval or remove the tool",
                )
            )
        return ref

    def _agent_ref(self, element: ast.expr) -> str | None:
        if isinstance(element, ast.Call) and element.args:
            element = element.args[0]
        if isinstance(element, ast.Name):
            ref = self.var_refs.get(element.id)
            if ref and ref.startswith(("agent:", "a2a-client:")):
                return ref
            value = self.assigns.get(element.id)
            if isinstance(value, ast.Call):
                return self.agent_refs.get(id(value))
        return None

    def _tool_has_risk(self, ref: str) -> bool:
        comp = self.b.components.get(ref)
        return isinstance(comp, ToolComponent) and bool(comp.risks)

    def _enclosing_function(self, node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        current = self.parent.get(id(node))
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = self.parent.get(id(current))
        return None

    def _elements(self, node: ast.expr | None) -> list[ast.expr]:
        if (
            isinstance(node, ast.Name)
            and node.id in self.assigns
            and isinstance(self.assigns[node.id], (ast.List, ast.Tuple))
        ):
            node = self.assigns[node.id]
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return [e for e in node.elts if not isinstance(e, ast.Starred)]
        if isinstance(node, ast.Dict):
            return [v for v in node.values if v is not None]
        if node is not None:
            return [node]
        return []

    def _server_ref(self, element: ast.expr) -> str | None:
        if isinstance(element, ast.Name):
            if element.id in self.var_refs and self.var_refs[element.id].startswith("mcp-server:"):
                return self.var_refs[element.id]
            if element.id in self.assigns and isinstance(self.assigns[element.id], ast.Call):
                return self.mcp(self.assigns[element.id])  # type: ignore[arg-type]
            return None
        if isinstance(element, ast.Call):
            return self.mcp(element)
        return None

    def _guardrail(self, element: ast.expr) -> str | None:
        if isinstance(element, ast.Name):
            name = element.id
        elif isinstance(element, ast.Call) and isinstance(element.func, ast.Name):
            name = element.func.id
        else:
            return None
        return self.b.add(
            GuardrailComponent(
                bom_ref=f"guardrail:code:{_scope(PurePosixPath(self.path))}/{quote(name, safe='')}",
                name=name,
                guardrail_type="agent-guardrail",
                source_path=self.path,
                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                properties={"collection_mode": "static-source"},
            )
        )

    def guards(self) -> None:
        for call in self.calls():
            last = call.qual
            modules = GUARD_CTORS.get(last)
            if modules is None or not _module_ok(call.module, modules):
                continue
            name = (
                self.string(self.kw(call.node, ("name",)))
                or self.target_of.get(id(call.node))
                or "guard"
            )
            validators = []
            parent = self.parent.get(id(call.node))
            outer = self.parent.get(id(parent)) if parent is not None else None
            if isinstance(outer, ast.Call):
                for arg in outer.args:
                    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                        validators.append(arg.func.id)
            self.b.add(
                GuardrailComponent(
                    bom_ref=f"guardrail:code:{_scope(PurePosixPath(self.path))}/{quote(name, safe='')}",
                    name=name,
                    guardrail_type=call.module.split(".")[0],
                    source_path=self.path,
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                    properties={
                        "collection_mode": "static-source",
                        **({"validators": validators} if validators else {}),
                    },
                )
            )

    def datasets(self) -> None:
        for call in self.calls():
            modules = DATASET_CALLS.get(call.qual)
            if modules is None or not _module_ok(call.module, modules):
                continue
            arg = call.node.args[0] if call.node.args else self.kw(call.node, ("path",))
            value = self.string(arg)
            if not value or not re.fullmatch(r"[\w.-]{1,96}(/[\w.-]{1,96})?", value):
                continue
            self.b.add(
                DataSourceComponent(
                    bom_ref=f"data:hub:{value}",
                    name=value,
                    dataset_type="huggingface-dataset",
                    source_uri=f"https://huggingface.co/datasets/{value}" if "/" in value else None,
                    source_path=self.path,
                    trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                    properties={"collection_mode": "static-source"},
                )
            )

    def credentials(self) -> None:
        for node in self.nodes:
            name = self.env_read(node)
            if not name or not _ENV_NAME.fullmatch(name) or not credential_name(name):
                continue
            ref = self.b.credential(name, "environment-variable")
            call = self.enclosing_call(node)
            owner = None
            while call is not None and owner is None:
                owner = self.agent_refs.get(id(call)) or self._call_component(call)
                call = self.enclosing_call(call)
            if owner:
                self.b.edge(
                    owner, ref, "acts-as-identity", f"read from the environment in {self.path}"
                )

    def _call_component(self, call: ast.Call) -> str | None:
        target = self.target_of.get(id(call))
        if target and target in self.var_refs:
            return self.var_refs[target]
        return None

    def _link_credentials(self, call: ast.Call, ref: str) -> None:
        for sub in ast.walk(call):
            name = self.env_read(sub)
            if name and _ENV_NAME.fullmatch(name) and credential_name(name):
                self.b.edge(
                    ref, self.b.credential(name, "environment-variable"), "acts-as-identity"
                )
        for keyword in call.keywords:
            value = keyword.value
            if (
                keyword.arg
                and credential_name(keyword.arg.upper())
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and holds_token_shape(value.value)
            ):
                self.b.literal_credential(ref, keyword.arg, self.path, self.line(keyword))

    # ---- driver

    def collect(self, crew_roles: dict[str, dict[str, Any]]) -> None:
        for call in self.calls():
            self.model_call(call)
        for call in self.calls():
            last = call.qual
            if last in MCP_CTORS and _module_ok(call.module, MCP_CTORS[last]):
                self.mcp(call.node)
        executors: list[_Call] = []
        agents: list[tuple[_Call, AgentCtor]] = []
        for call in self.calls():
            for ctor in AGENT_CTORS.get(call.qual, ()):
                if not _module_ok(call.module, ctor.modules):
                    continue
                if call.qual == "AgentExecutor":
                    executors.append(call)
                else:
                    agents.append((call, ctor))
                break
        for call, ctor in agents:
            self.register(call, ctor, crew_roles)
        for call, ctor in agents:
            self.agent(call, ctor, crew_roles)
        for call in executors:
            inner = self.kw(call.node, ("agent",))
            if isinstance(inner, ast.Name) and inner.id in self.var_refs:
                ref = self.var_refs[inner.id]
                stored = self.b.components.get(ref)
                variable = self.target_of.get(id(call.node))
                if isinstance(stored, AgentComponent) and variable:
                    stored.properties.setdefault("executor", variable)
                for element in self._elements(self.kw(call.node, ("tools",))):
                    for tool_ref in self.tool(element, ref):
                        if isinstance(stored, AgentComponent) and tool_ref not in stored.tool_refs:
                            stored.tool_refs.append(tool_ref)
                        if tool_ref in self.b.components:
                            self.b.edge(ref, tool_ref, "invokes")
            else:
                self.agent(call, AGENT_CTORS["AgentExecutor"][0], crew_roles)
        self.client_models()
        self.guards()
        self.datasets()
        self.credentials()


# ------------------------------------------------------------------ configuration files


def dotenv_credentials(builder: Builder, path: str, text: str) -> None:
    """Names a checked-in ``.env`` template lists; a ``.env`` file itself is never read."""
    for raw in text.splitlines()[:5000]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not _ENV_NAME.fullmatch(key) or not credential_name(key):
            continue
        value = value.strip().strip("'\"")
        builder.credential(key, "dotenv-key", committed=holds_token_shape(value), where=path)


YAML_REFUSED = "YAML mapping parse failed or unsupported"
JSON_REFUSED = "invalid JSON or duplicate keys"


def static_yaml(text: str) -> list[Any] | None:
    """The documents of ``text`` as plain data, or None when they cannot be read.

    YAML is read as the other collectors read it: anchors, aliases and tags are refused,
    and so is more than ``YAML_TOKEN_LIMIT`` tokens, so what is composed is bounded by the
    text.
    """
    from nexus_symbiote.policy import bounded_flow_loader

    loader = bounded_flow_loader()
    graph = (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)
    try:
        for index, token in enumerate(yaml.scan(text, Loader=loader)):
            if index >= YAML_TOKEN_LIMIT or isinstance(token, graph):
                return None
        return list(yaml.load_all(text, Loader=loader))
    except (ValueError, RecursionError, OverflowError, IndexError, yaml.YAMLError):
        return None


def _one_document(text: str) -> Any:
    documents = static_yaml(text)
    return documents[0] if documents is not None and len(documents) == 1 else None


def json_document(text: str) -> Any:
    """``text`` as JSON within the shared nesting bound, or None."""
    from nexus_symbiote.core.hashing import MAX_JSON_NESTING, json_nesting_exceeds

    if json_nesting_exceeds(text, MAX_JSON_NESTING):
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def crew_role_index(texts: dict[str, str], gaps: dict[str, str]) -> dict[str, dict[str, Any]]:
    roles: dict[str, dict[str, Any]] = {}
    for path, text in texts.items():
        if PurePosixPath(path).name not in {"agents.yaml", "agents.yml"}:
            continue
        documents = static_yaml(text)
        if documents is None:
            gaps[path] = YAML_REFUSED
            continue
        data = documents[0] if len(documents) == 1 else None
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(key, str) and isinstance(value, dict) and "role" in value:
                    roles[key] = value
    return roles


_PLACEHOLDER = re.compile(r"\$\{([A-Z][A-Z0-9_]{2,127})(?::[^}]*)?\}")


def spring_config(builder: Builder, path: str, text: str) -> None:
    """Spring AI ``spring.ai.<provider>...model`` settings and ``${NAME}`` credentials."""
    models: list[tuple[str, str]] = []
    if path.endswith((".yml", ".yaml")):
        for data in static_yaml(text) or ():
            ai = (
                data.get("spring", {}).get("ai")
                if isinstance(data, dict) and isinstance(data.get("spring"), dict)
                else None
            )
            if isinstance(ai, dict):
                for provider, settings in ai.items():
                    for value in _walk_values(settings, "model"):
                        models.append((str(provider), value))
    else:
        for line in text.splitlines():
            match = re.match(r"[ \t]*spring\.ai\.([\w-]+)\.[\w.-]*model[ \t]*[=:][ \t]*(\S+)", line)
            if match:
                models.append((match.group(1), match.group(2)))
    if not models and "spring.ai" not in text and "\n  ai:" not in text:
        return
    for provider, value in models:
        if plausible_model(value):
            mapped = {
                "openai": "openai",
                "anthropic": "anthropic",
                "azure": "azure-openai",
                "bedrock": "aws-bedrock",
                "vertex": "google-vertex",
                "ollama": "ollama",
                "mistralai": "mistral",
            }.get(provider, provider)
            ref = model_component(builder, value, mapped, "hosted", path, 1, framework="spring-ai")
            for name in _PLACEHOLDER.findall(text):
                if credential_name(name):
                    builder.edge(
                        ref,
                        builder.credential(name, "config-placeholder"),
                        "acts-as-identity",
                        f"placeholder in {path}",
                    )


def _walk_values(node: Any, key: str) -> Iterator[str]:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, str):
                yield v
            else:
                yield from _walk_values(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_values(item, key)


def nemo_config(builder: Builder, path: str, data: Any) -> None:
    """The models a NeMo Guardrails configuration runs; the guardrail itself is the rag record."""
    if (
        not isinstance(data, dict)
        or "rails" not in data
        or not isinstance(data.get("models"), list)
    ):
        return
    folder = PurePosixPath(path).parent.as_posix()
    for entry in data["models"]:
        if (
            isinstance(entry, dict)
            and isinstance(entry.get("model"), str)
            and plausible_model(entry["model"])
        ):
            engine = entry.get("engine")
            ref = model_component(
                builder,
                entry["model"],
                engine if isinstance(engine, str) else None,
                "hosted",
                path,
                1,
            )
            builder.components[ref].properties.setdefault(
                "used_by_guardrail", f"nemo-guardrails:{folder}"
            )


def n8n_workflow(builder: Builder, path: str, data: Any) -> None:
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list):
        return
    nodes = [n for n in data["nodes"] if isinstance(n, dict) and isinstance(n.get("type"), str)]
    if not any(
        n["type"].startswith(("@n8n/n8n-nodes-langchain.", "n8n-nodes-base.")) for n in nodes
    ):
        return
    workflow = str(data.get("name") or PurePosixPath(path).stem)
    refs: dict[str, str] = {}
    scope = _scope(PurePosixPath(path))
    for n in nodes:
        kind = n["type"].rsplit(".", 1)[-1]
        name = str(n.get("name") or kind)
        raw_params = n.get("parameters")
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        if not n["type"].startswith("@n8n/n8n-nodes-langchain."):
            if kind == "webhook" and str(params.get("authentication", "none")) == "none":
                refs[f"webhook:{name}"] = name
            continue
        if kind == "agent" or kind.endswith("Agent"):
            refs[name] = builder.add(
                AgentComponent(
                    bom_ref=f"agent:n8n:{scope}/{quote(name, safe='')}",
                    name=name,
                    framework="n8n",
                    source_path=path,
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                    properties={
                        "collection_mode": "static-config",
                        "workflow": workflow,
                        "node_type": n["type"],
                    },
                )
            )
        elif kind.startswith("lmChat") or kind.startswith("lm") or kind.startswith("embeddings"):
            model = params.get("model")
            value = model.get("value") if isinstance(model, dict) else model
            if isinstance(value, str) and plausible_model(value):
                provider = (
                    kind.removeprefix("lmChat")
                    .removeprefix("lm")
                    .removeprefix("embeddings")
                    .lower()
                    or None
                )
                refs[name] = model_component(
                    builder,
                    value,
                    provider,
                    "embedding" if kind.startswith("embeddings") else "hosted",
                    path,
                    1,
                    "n8n",
                )
        elif kind == "mcpClientTool":
            url = params.get("sseEndpoint") or params.get("endpointUrl")
            ref = mcp_component(
                builder,
                name=name,
                command=None,
                args=[],
                url=url if isinstance(url, str) else None,
                env=(),
                path=path,
                line=1,
            )
            if ref:
                refs[name] = ref
        elif kind.startswith("tool"):
            refs[name] = builder.add(
                ToolComponent(
                    bom_ref=f"tool:n8n:{scope}/{quote(name, safe='')}",
                    name=name,
                    description_text=str(
                        params.get("toolDescription") or params.get("description") or ""
                    )[:300]
                    or None,
                    source_path=path,
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                    properties={"collection_mode": "static-config", "node_type": n["type"]},
                )
            )
        credentials = n.get("credentials")
        if isinstance(credentials, dict) and name in refs:
            for cred in credentials.values():
                label = cred.get("name") if isinstance(cred, dict) else None
                if isinstance(label, str) and label:
                    builder.edge(
                        refs[name],
                        builder.credential(label, "workflow-credential"),
                        "acts-as-identity",
                    )
    raw_connections = data.get("connections")
    connections: dict[str, Any] = raw_connections if isinstance(raw_connections, dict) else {}
    relation: dict[str, Relationship] = {
        "ai_languageModel": "uses-model",
        "ai_tool": "invokes",
        "ai_memory": "uses-memory",
    }
    for source, outputs in connections.items():
        if not isinstance(outputs, dict):
            continue
        for kind, groups in outputs.items():
            for group in groups if isinstance(groups, list) else []:
                for target in group if isinstance(group, list) else []:
                    dest = target.get("node") if isinstance(target, dict) else None
                    if source in refs and dest in refs and kind in relation:
                        builder.edge(refs[dest], refs[source], relation[kind])
                    if f"webhook:{source}" in refs and dest in refs:
                        agent = builder.components.get(refs[dest])
                        if isinstance(agent, AgentComponent):
                            detail = f"Agent {dest} is triggered by webhook {source}, which requires no authentication"
                            if all(r.detail != detail for r in agent.risks):
                                agent.risks.append(
                                    RiskAssessment(
                                        severity=RiskSeverity.MEDIUM,
                                        category="authentication",
                                        detail=detail,
                                        recommendation="Require header or basic authentication on the webhook",
                                    )
                                )


def subagent_definition(builder: Builder, path: str, text: str) -> str | None:
    """Claude Code and Copilot subagent definitions: front matter with a name.

    Returns why front matter that is present could not be read.
    """
    match = re.match(r"---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", text, re.S)
    if not match:
        return None
    documents = static_yaml(match.group(1))
    if documents is None:
        return YAML_REFUSED
    front = documents[0] if len(documents) == 1 else None
    if not isinstance(front, dict):
        return None
    name = front.get("name") if isinstance(front.get("name"), str) else PurePosixPath(path).stem
    framework = "github-copilot" if "/.github/" in f"/{path}" else "claude-code"
    tools = front.get("tools")
    builder.add(
        AgentComponent(
            bom_ref=f"agent:subagent:{_scope(PurePosixPath(path))}",
            name=str(name),
            framework=framework,
            prompt_refs=[f"prompt:{path}"],
            source_path=path,
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            description=str(front.get("description"))[:500] if front.get("description") else None,
            properties={
                "collection_mode": "static-config",
                "definition": "subagent",
                **({"model_alias": str(front["model"])} if front.get("model") else {}),
                **({"tools_declared": str(tools)[:500]} if tools else {}),
            },
        )
    )
    return None


# ------------------------------------------------------------------ infrastructure


AI_IMAGES = {
    "vllm/vllm-openai": "model-server",
    "ollama/ollama": "model-server",
    "ghcr.io/huggingface/text-generation-inference": "model-server",
    "nvcr.io/nvidia/tritonserver": "model-server",
    "ghcr.io/ggerganov/llama.cpp": "model-server",
    "ghcr.io/ggml-org/llama.cpp": "model-server",
    "localai/localai": "model-server",
    "ghcr.io/open-webui/open-webui": "ai-gateway",
    "ghcr.io/berriai/litellm": "ai-gateway",
    "qdrant/qdrant": "vector-store",
    "chromadb/chroma": "vector-store",
    "semitechnologies/weaviate": "vector-store",
    "milvusdb/milvus": "vector-store",
    "pgvector/pgvector": "vector-store",
    "ankane/pgvector": "vector-store",
}


def ai_image(image: str) -> str | None:
    """The image name, when ``image`` is a known AI serving image; images are the registry's."""
    name = image.partition("@")[0]
    if ":" in name.rsplit("/", 1)[-1]:
        name = name.rpartition(":")[0]
    name = name.removeprefix("docker.io/").removeprefix("library/")
    return name if name in AI_IMAGES else None


def dockerfile(builder: Builder, path: str, text: str) -> None:
    """The model an AI serving image is started with. The image itself is a registry record."""
    image: str | None = None
    for line in text.splitlines():
        match = re.match(r"[ \t]*FROM[ \t]+(?:--platform=\S+[ \t]+)?(\S+)", line, re.I)
        if match:
            image = ai_image(match.group(1)) or image
    if image is None:
        return
    for match in re.finditer(r'["\s]--model["\s]*[,=\s]\s*"?([\w./:-]+)"?', text):
        if plausible_model(match.group(1), hub=True):
            ref = model_component(
                builder,
                match.group(1),
                "huggingface" if "/" in match.group(1) else None,
                "hub" if "/" in match.group(1) else "hosted",
                path,
                1,
            )
            builder.components[ref].properties.setdefault(
                "served_by", f"{AI_IMAGES[image]}/{image}"
            )


_TERRAFORM_KINDS = frozenset(
    {
        "aws_bedrockagent_agent",
        "azurerm_cognitive_deployment",
        "google_vertex_ai_endpoint",
        "google_vertex_ai_index",
        "aws_bedrockagent_knowledge_base",
    }
)
_HCL_ATTRIBUTE = re.compile(r'^[ \t]*([\w-]+)[ \t]*=[ \t]*"([^"\n]*)"', re.M)


def terraform(builder: Builder, path: str, text: str) -> None:
    for match in re.finditer(r'\bresource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', text):
        kind, label = match.group(1), match.group(2)
        if kind not in _TERRAFORM_KINDS:
            continue
        body = _hcl_block(text, match.end() - 1)
        attrs = dict(_HCL_ATTRIBUTE.findall(body))
        if kind == "aws_bedrockagent_agent":
            name = attrs.get("agent_name") or label
            agent = builder.add(
                AgentComponent(
                    bom_ref=f"agent:terraform:{_scope(PurePosixPath(path))}/{quote(label, safe='')}",
                    name=name,
                    framework="aws-bedrock-agents",
                    deployment_status="declared",
                    source_path=path,
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                    properties={
                        "collection_mode": "static-config",
                        "terraform_resource": f"{kind}.{label}",
                    },
                )
            )
            model = attrs.get("foundation_model")
            if model and plausible_model(model):
                builder.edge(
                    agent,
                    model_component(builder, model, "aws-bedrock", "hosted", path, 1),
                    "uses-model",
                )
        elif kind == "azurerm_cognitive_deployment":
            model_block = re.search(r"\bmodel\s*\{([^}]*)\}", body)
            fields = dict(_HCL_ATTRIBUTE.findall(model_block.group(1))) if model_block else {}
            name = fields.get("name")
            if name and plausible_model(name):
                ref = model_component(builder, name, "azure-openai", "hosted", path, 1)
                comp = builder.components[ref]
                if fields.get("version"):
                    comp.properties["model_version"] = fields["version"]
                if attrs.get("name"):
                    comp.properties["deployment_name"] = attrs["name"]
        elif kind in {
            "google_vertex_ai_endpoint",
            "google_vertex_ai_index",
            "aws_bedrockagent_knowledge_base",
        }:
            builder.add(
                RegistryEntryComponent(
                    bom_ref=f"cloud:{kind}:{label}",
                    name=attrs.get("display_name") or attrs.get("name") or label,
                    registry_type=kind.split("_", 1)[0],
                    source_path=path,
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                    properties={
                        "collection_mode": "static-config",
                        "terraform_resource": f"{kind}.{label}",
                    },
                )
            )


def _hcl_block(text: str, start: int) -> str:
    depth = 0
    for index in range(start, min(len(text), start + 20_000)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index]
    return text[start + 1 :]


_KIND_INFERENCE = re.compile(r"(?m)^kind:[ \t]*[\"']?InferenceService\b")
_METADATA_NAME = re.compile(
    r"(?m)^metadata:[ \t]*\n(?:[ \t]+[^\n]*\n){0,64}?[ \t]+name:[ \t]*[\"']?([\w.-]{1,253})"
)


def kserve(builder: Builder, path: str, text: str) -> None:
    """KServe ``InferenceService`` documents, read by line, and the hub models they serve."""
    for document in re.split(r"(?m)^---[ \t]*$", text):
        if not _KIND_INFERENCE.search(document):
            continue
        found = _METADATA_NAME.search(document)
        name = found.group(1) if found else "inference-service"
        for match in re.finditer(r"--model_id=([\w./-]+)|hf://([\w./-]+)", document):
            value = match.group(1) or match.group(2)
            if value and HUB_ID.match(value):
                ref = model_component(builder, value, "huggingface", "hub", path, 1)
                comp = builder.components[ref]
                comp.properties.setdefault("served_by", f"kserve/{name}")


# ------------------------------------------------------------------ scanner


_TS_SUFFIXES = frozenset({".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs"})
_POLYGLOT_MARKERS = {
    ".java": (b"org.springframework.ai",),
    ".kt": (b"org.springframework.ai",),
    ".go": (b"github.com/tmc/langchaingo",),
    ".cs": (b"Microsoft.SemanticKernel",),
}
SOURCE_SUFFIXES = frozenset({".py", *_TS_SUFFIXES, *_POLYGLOT_MARKERS})
_TS_MARKERS = (
    b"@ai-sdk/",
    b"@mastra/",
    b"@openai/agents",
    b"@langchain/",
    b"@voltagent/",
    b'from "ai"',
    b"from 'ai'",
)
_IMAGE_MARKERS = tuple(sorted({image.rsplit("/", 1)[-1].encode() for image in AI_IMAGES}))
_TERRAFORM_MARKERS = tuple(sorted({kind.encode() for kind in _TERRAFORM_KINDS}))
_SPRING_NAMES = frozenset({"application.yml", "application.yaml", "application.properties"})
_CREW_NAMES = frozenset({"agents.yaml", "agents.yml"})
_NEMO_NAMES = frozenset({"config.yml", "config.yaml"})
_ENV_TEMPLATE_SUFFIXES = frozenset({".example", ".sample", ".template"})
_SUBAGENT_DIRECTORIES = frozenset({(".claude", "agents"), (".github", "agents")})
NO_FINDINGS = "code (no framework agents, models or AI configuration found)"


def _python_markers() -> tuple[bytes, ...]:
    modules: set[str] = {*TOOL_MODULES, *_HUB_LOADERS, *_CLIENT_SDKS}
    for model_ctors in MODEL_CTORS.values():
        for model_ctor in model_ctors:
            modules.update(model_ctor.modules)
    for agent_ctors in AGENT_CTORS.values():
        for agent_ctor in agent_ctors:
            modules.update(agent_ctor.modules)
    for named in (*MCP_CTORS.values(), *GUARD_CTORS.values(), *DATASET_CALLS.values()):
        modules.update(named)
    modules.update(module for module, _ in DECORATOR_TOOLS | OWN_DECORATOR_TOOLS)
    return tuple(sorted({module.split(".", 1)[0].encode() for module in modules}))


PYTHON_MARKERS = _python_markers()


def markers_for(path: PurePosixPath) -> tuple[bytes, ...] | None:
    """The bytes that make a file worth reading here, or None when it is never read.

    Directories the source searches skip (tests, examples, builds) and files named as
    holding credentials, a ``.env`` file among them, are never read.
    """
    if SKIPPED_DIRECTORIES.intersection(path.parts[:-1]) or credential_shaped(path.as_posix()):
        return None
    name, suffix = path.name, path.suffix
    if suffix == ".py":
        return PYTHON_MARKERS
    if suffix in _TS_SUFFIXES:
        return None if name.endswith(NOT_SOURCE_NAMES) or ".min." in name else _TS_MARKERS
    if suffix in _POLYGLOT_MARKERS:
        return _POLYGLOT_MARKERS[suffix]
    if name in _SPRING_NAMES:
        return (b"spring",)
    if name in {"Dockerfile", "Containerfile"} or name.endswith(".Dockerfile"):
        return _IMAGE_MARKERS
    if suffix == ".tf":
        return _TERRAFORM_MARKERS
    if suffix == ".md":
        return (b"---",) if tuple(path.parts[-3:-1]) in _SUBAGENT_DIRECTORIES else None
    if name.startswith(".env.") and suffix in _ENV_TEMPLATE_SUFFIXES:
        return (b"=",)
    if suffix == ".json":
        return (b"n8n-nodes",)
    if suffix in {".yaml", ".yml"}:
        found = [b"InferenceService"]
        if name in _CREW_NAMES:
            found.append(b"role")
        if name in _NEMO_NAMES:
            found.append(b"rails")
        return tuple(found)
    return None


_PY_DECLARATION = re.compile(
    rb"(?m)^[ \t]*(?:from|import)[ \t]+(?:"
    + b"|".join(re.escape(marker) for marker in PYTHON_MARKERS)
    + rb")(?![\w])"
)
_NEMO_DECLARATION = re.compile(rb"(?m)^rails[ \t]*:")
_CREW_DECLARATION = re.compile(rb"(?m)^[ \t]+role[ \t]*:")
_SPRING_DECLARATION = re.compile(rb"spring\.ai\.|(?m:^[ \t]+ai[ \t]*:)")


def declares(path: PurePosixPath, raw: bytes) -> bool:
    """Whether a file holds a declaration this collector reads, so failing to read it is a gap.

    A recognised declaration is a framework import line, an AI SDK package specifier, an
    n8n workflow, a NeMo ``rails`` configuration, a CrewAI role, a Spring AI setting or a
    subagent definition. Surfaces read by line (Dockerfiles, compose files, KServe,
    Terraform and ``.env`` templates) cannot fail to parse.
    """
    name, suffix = path.name, path.suffix
    if suffix == ".py":
        return _PY_DECLARATION.search(raw) is not None
    if suffix in _TS_SUFFIXES:
        return any(marker in raw for marker in _TS_MARKERS)
    if suffix in _POLYGLOT_MARKERS:
        return any(marker in raw for marker in _POLYGLOT_MARKERS[suffix])
    if suffix == ".json":
        return b"n8n-nodes" in raw
    if suffix == ".md":
        return True
    if name in _NEMO_NAMES:
        return _NEMO_DECLARATION.search(raw) is not None
    if name in _CREW_NAMES:
        return _CREW_DECLARATION.search(raw) is not None
    if name in _SPRING_NAMES and suffix != ".properties":
        return b"spring" in raw and _SPRING_DECLARATION.search(raw) is not None
    return False


class CodeInventoryScanner(Scanner):
    """Collects framework agents and their wiring from source and AI configuration.

    A file is read only when it holds one of its surface's markers. One that holds a
    recognised declaration (see ``declares``) but is too large, not text in its encoding,
    unparsable or over ``python-nodes`` is a named collection failure, worded as the
    ``mcp`` source search words it so the gate groups the two collectors' records. Any
    other unreadable file declares nothing. The text read is bounded by the source
    budget. Only files that declared something are listed as scanned, so code that
    declares nothing an agent uses leaves the inventory unchanged.
    """

    name = COLLECTOR
    _modules: dict[str, set[str]] = {}
    _packages: set[str] = set()

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        modules: dict[str, set[str]] = {}
        packages: set[str] = set()
        builder = Builder(result)
        scanned: list[str] = []
        with self._collection(project_root, result) as files:
            candidates: list[tuple[Path, tuple[bytes, ...]]] = []
            for path in files.iter_files():
                posix = PurePosixPath(path.as_posix())
                if posix.name == "__init__.py" and len(posix.parts) > 1:
                    modules.setdefault(posix.parent.parent.as_posix(), set()).add(posix.parent.name)
                    packages.add(posix.parent.as_posix())
                elif posix.suffix == ".py":
                    modules.setdefault(posix.parent.as_posix(), set()).add(posix.stem)
                found = markers_for(posix)
                if found is not None:
                    candidates.append((path, found))
            self._modules = modules
            self._packages = packages
            gaps: dict[str, str] = {}
            texts, declared = self._read(project_root, candidates, result, gaps)
            crew_roles = crew_role_index(texts, gaps)
            python_nodes = limits.bound("python-nodes")
            for rel, text in texts.items():
                before = builder.touched
                try:
                    gap = self._collect_one(
                        builder, rel, PurePosixPath(rel), text, python_nodes, crew_roles
                    )
                except (ValueError, RecursionError, KeyError, TypeError) as exc:
                    gap = f"code inventory could not read the file ({type(exc).__name__})"
                    declared.add(rel)
                if gap is not None and rel in declared:
                    gaps.setdefault(rel, gap)
                if builder.touched != before:
                    scanned.append(rel)
            # Every declaration can fail, so past the listing bound the collection sums
            # the failures up by reason, as the mcp source search does.
            with files.bounded_failures():
                for rel, reason in gaps.items():
                    files._fail(rel, reason)
        builder.finish()
        result.surfaces_scanned.extend(scanned or [NO_FINDINGS])
        return result

    def _read(
        self,
        root: Path,
        candidates: list[tuple[Path, tuple[bytes, ...]]],
        result: ScanResult,
        gaps: dict[str, str],
    ) -> tuple[dict[str, str], set[str]]:
        """The text of each candidate that holds one of its markers, within the budget."""
        from nexus_symbiote.scanners.mcp_sources import _python_text, _UnreadableError

        texts: dict[str, str] = {}
        declared: set[str] = set()
        budget = SourceBudget("code inventory sources", result)
        syntax_bytes = limits.bound("syntax-bytes")
        with ConfinedCollection(
            root, [], exclude_paths=self._exclude_paths, max_total_bytes=source_collection_bytes()
        ) as heuristic:
            for path, found in candidates:
                raw = heuristic.read_bytes(path, missing_ok=True)
                if raw is None:
                    continue
                if not budget.admit(len(raw), path):
                    break
                if not any(marker in raw for marker in found):
                    continue
                rel = path.as_posix()
                if declares(PurePosixPath(rel), raw):
                    declared.add(rel)
                if path.suffix in SOURCE_SUFFIXES and len(raw) > syntax_bytes.value:
                    if rel in declared:
                        gaps[rel] = syntax_bytes.exceeded()
                    continue
                try:
                    texts[rel] = _python_text(raw) if path.suffix == ".py" else raw.decode("utf-8")
                except (_UnreadableError, UnicodeDecodeError) as exc:
                    if rel in declared:
                        gaps[rel] = (
                            str(exc) if isinstance(exc, _UnreadableError) else "invalid UTF-8"
                        )
        return texts, declared

    def _collect_one(
        self,
        builder: Builder,
        rel: str,
        path: PurePosixPath,
        text: str,
        python_nodes: limits.Bound,
        crew_roles: dict[str, dict[str, Any]],
    ) -> str | None:
        """Read one file into the builder; return why a declaration could not be read."""
        from nexus_symbiote.scanners import code_inventory_polyglot, code_inventory_ts

        name, suffix = path.name, path.suffix
        if suffix == ".py":
            try:
                tree = parse_python(text)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                return "invalid Python syntax"
            nodes = list(islice(ast.walk(tree), python_nodes.value + 1))
            if len(nodes) > python_nodes.value:
                return python_nodes.exceeded()
            # What an absolute import finds in the checkout: the root and ``src``, which
            # are on the import path, and a script's own directory unless it is a package.
            directory = path.parent.as_posix()
            roots = (".", "src") if directory in self._packages else (".", "src", directory)
            local = frozenset(
                name
                for where in roots
                for name in self._modules.get(where, ())
                if not (where == directory and name == path.stem)
            )
            PythonSource(rel, tree, nodes, builder, local).collect(crew_roles)
        elif suffix in _TS_SUFFIXES:
            return code_inventory_ts.collect(builder, rel, text)
        elif suffix in _POLYGLOT_MARKERS:
            code_inventory_polyglot.collect(builder, rel, text)
        elif name.startswith(".env."):
            dotenv_credentials(builder, rel, text)
        elif name in _SPRING_NAMES:
            if suffix != ".properties" and static_yaml(text) is None:
                return YAML_REFUSED
            spring_config(builder, rel, text)
        elif name in {"Dockerfile", "Containerfile"} or name.endswith(".Dockerfile"):
            dockerfile(builder, rel, text)
        elif suffix == ".tf":
            terraform(builder, rel, text)
        elif suffix == ".md":
            return subagent_definition(builder, rel, text)
        elif suffix == ".json":
            data = json_document(text)
            if data is None:
                return JSON_REFUSED
            n8n_workflow(builder, rel, data)
        elif suffix in {".yaml", ".yml"}:
            kserve(builder, rel, text)
            if name in _NEMO_NAMES:
                documents = static_yaml(text)
                if documents is None:
                    return YAML_REFUSED
                if len(documents) == 1:
                    nemo_config(builder, rel, documents[0])
        return None
