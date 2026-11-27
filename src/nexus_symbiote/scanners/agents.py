"""Framework-level agent assembly collected from source and workflow definitions.

Records the agents a checkout constructs with an agent SDK, the models they call, the
tools they bind, the credentials they read (by environment variable name only) and the
datasets they load, as literal declarations in source: no scanned code runs, and only
identifiers, root-relative paths and line numbers are recorded. Supported in Python:
LangGraph, CrewAI, the OpenAI Agents SDK, the Claude Agent SDK, Google ADK, Pydantic AI,
AutoGen and smolagents, plus model identifiers passed to a known AI SDK. Supported in
TypeScript and JavaScript: the Vercel AI SDK and provider SDK model literals. n8n workflow
exports, LiteLLM routing files, Ollama Modelfiles, Codex and Continue settings contribute
agents and model references from configuration.

An import whose first module is a package or module of the checkout is checkout code,
not the SDK of the same name, and declares nothing here. Test sources (``tests/``,
``test_*.py``, ``*.test.ts`` and the like) are not deployed inventory and are not read.
A model identifier is recorded only when a known AI SDK is imported in the same file, and
only when it is a literal; names bound elsewhere are a gap, not a guess.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from nexus_symbiote import limits
from nexus_symbiote.core.aibom import DependencyEdge
from nexus_symbiote.core.enums import (
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    CapabilityDeclaration,
    DataSourceComponent,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    SourceBudget,
    parse_python,
    sanitized_origin,
    source_collection_bytes,
)
from nexus_symbiote.utils.confined import ConfinedCollection

if TYPE_CHECKING:
    from tree_sitter import Node

COLLECTION_MODE = "static-source-declaration"
REFERENCE_COLLECTION_MODE = "static-source-reference"
"""A model named by an identifier in source or configuration: there is no local artifact."""
_MAX_PYTHON_CHARACTERS = 4 * 1024 * 1024
_MAX_WORKFLOW_BYTES = 4 * 1024 * 1024
_MAX_REFERENCES = 16
_MAX_NAME = 128

# First import module -> framework label, and the class or function names that build an
# agent under it. ``agents`` is the OpenAI Agents SDK only when one of its own names is
# imported, since the module name is generic.
_AGENT_FRAMEWORKS: dict[str, str] = {
    "langgraph": "langgraph",
    "crewai": "crewai",
    "agents": "openai-agents",
    "claude_agent_sdk": "claude-agent-sdk",
    "google.adk": "google-adk",
    "pydantic_ai": "pydantic-ai",
    "autogen_agentchat": "autogen",
    "autogen": "autogen",
    "smolagents": "smolagents",
}
_AGENT_BUILDERS: dict[str, frozenset[str]] = {
    "langgraph": frozenset({"StateGraph", "create_react_agent", "create_agent"}),
    "crewai": frozenset({"Agent"}),
    "openai-agents": frozenset({"Agent"}),
    "claude-agent-sdk": frozenset({"ClaudeAgentOptions", "ClaudeSDKClient"}),
    "google-adk": frozenset({"LlmAgent", "Agent", "SequentialAgent", "ParallelAgent", "LoopAgent"}),
    "pydantic-ai": frozenset({"Agent"}),
    "autogen": frozenset({"AssistantAgent", "UserProxyAgent", "ConversableAgent"}),
    "smolagents": frozenset({"CodeAgent", "ToolCallingAgent"}),
}
_OPENAI_AGENTS_NAMES = frozenset(
    {
        "Agent",
        "Runner",
        "function_tool",
        "WebSearchTool",
        "FileSearchTool",
        "CodeInterpreterTool",
        "ComputerTool",
        "HostedMCPTool",
        "MCPServerStdio",
        "MCPServerSse",
        "MCPServerStreamableHttp",
    }
)
# Imports whose presence makes a literal ``model=`` argument a model reference.
_MODEL_SDK_ROOTS = frozenset(
    {
        "openai",
        "anthropic",
        "litellm",
        "boto3",
        "langchain",
        "langchain_openai",
        "langchain_anthropic",
        "langchain_google_genai",
        "langchain_google_vertexai",
        "langchain_aws",
        "langchain_community",
        "langchain_core",
        "langchain_ollama",
        "langchain_mistralai",
        "langchain_groq",
        "google",
        "mistralai",
        "cohere",
        "groq",
        "together",
        "ollama",
        "transformers",
        "sentence_transformers",
        "vertexai",
        "huggingface_hub",
        "datasets",
        *_AGENT_FRAMEWORKS,
    }
)
_MODEL_KEYWORDS = frozenset(
    {"model", "model_name", "model_id", "modelId", "deployment_name", "azure_deployment", "llm"}
)
# Constructors whose first positional string argument is a model identifier.
_POSITIONAL_MODEL_CALLS: dict[str, str] = {
    "SentenceTransformer": "huggingface",
    "CrossEncoder": "huggingface",
    "init_chat_model": "",
    "Agent": "pydantic-ai",
}
_EMBEDDING_MARKERS = ("embedding", "embed", "minilm", "e5-", "bge-", "cross-encoder", "rerank")
_FROM_PRETRAINED = "from_pretrained"
_PROVIDER_CLASSES: dict[str, str] = {
    "ChatOpenAI": "openai",
    "OpenAI": "openai",
    "AsyncOpenAI": "openai",
    "OpenAIEmbeddings": "openai",
    "AzureChatOpenAI": "azure-openai",
    "AzureOpenAI": "azure-openai",
    "AzureOpenAIEmbeddings": "azure-openai",
    "ChatAnthropic": "anthropic",
    "Anthropic": "anthropic",
    "AsyncAnthropic": "anthropic",
    "ChatGoogleGenerativeAI": "google",
    "ChatVertexAI": "google",
    "GenerativeModel": "google",
    "ChatBedrock": "aws-bedrock",
    "ChatBedrockConverse": "aws-bedrock",
    "BedrockEmbeddings": "aws-bedrock",
    "ChatOllama": "ollama",
    "OllamaLLM": "ollama",
    "ChatMistralAI": "mistral",
    "ChatGroq": "groq",
    "ChatCohere": "cohere",
    "LLM": "",
    "LlmAgent": "",
}
_PREFIX_PROVIDERS: dict[str, str] = {
    "azure": "azure-openai",
    "bedrock": "aws-bedrock",
    "anthropic": "anthropic",
    "openai": "openai",
    "gemini": "google",
    "google": "google",
    "vertex_ai": "google",
    "ollama": "ollama",
    "mistral": "mistral",
    "groq": "groq",
    "cohere": "cohere",
    "huggingface": "huggingface",
    "together_ai": "together",
}
_MODEL_FAMILIES: tuple[tuple[str, str], ...] = (
    ("gpt-", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("text-embedding-", "openai"),
    ("claude-", "anthropic"),
    ("gemini-", "google"),
    ("llama", "meta"),
    ("mistral", "mistral"),
    ("mixtral", "mistral"),
    ("command-", "cohere"),
    ("anthropic.claude", "aws-bedrock"),
    ("amazon.", "aws-bedrock"),
)
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{1,127}$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_PLACEHOLDER = re.compile(r"[<>{}$ ]|^your[-_]|^example|^xxx|^todo|^changeme", re.IGNORECASE)
_TEST_DIRECTORIES = frozenset({"tests", "test", "__tests__", "spec", "specs", "testing"})
_SKIPPED_DIRECTORIES = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "site-packages",
        "__pycache__",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
    }
)
_TOOL_DECORATORS = frozenset({"tool", "function_tool", "tool_plain", "kernel_function"})
_TOOL_LIST_KEYWORDS = frozenset({"tools", "allowed_tools"})
_PROMPT_KEYWORDS = frozenset(
    {"instructions", "instruction", "system_prompt", "system_message", "backstory", "prompt"}
)
_PERMISSION_KEYWORDS = frozenset({"permission_mode", "approval_policy", "human_input_mode"})
_UNSAFE_PERMISSION_VALUES = frozenset(
    {"bypasspermissions", "never", "danger-full-access", "dontask", "acceptedits"}
)
_BUILTIN_TOOL_MODULES: dict[str, str] = {
    "google.adk.tools": "google-adk",
    "agents": "openai-agents",
    "crewai_tools": "crewai",
    "langchain_community.tools": "langchain",
    "smolagents": "smolagents",
}
_BUILTIN_TOOL_CAPABILITIES: dict[str, tuple[CapabilityClass, ...]] = {
    "google_search": (CapabilityClass.NETWORK, CapabilityClass.READ),
    "WebSearchTool": (CapabilityClass.NETWORK, CapabilityClass.READ),
    "SerperDevTool": (CapabilityClass.NETWORK, CapabilityClass.READ),
    "FileReadTool": (CapabilityClass.FILESYSTEM, CapabilityClass.READ),
    "FileWriterTool": (CapabilityClass.FILESYSTEM, CapabilityClass.WRITE),
    "DirectoryReadTool": (CapabilityClass.FILESYSTEM, CapabilityClass.READ),
    "CodeInterpreterTool": (CapabilityClass.EXECUTE,),
    "built_in_code_execution": (CapabilityClass.EXECUTE,),
    "ComputerTool": (CapabilityClass.EXECUTE, CapabilityClass.FILESYSTEM),
    "ShellTool": (CapabilityClass.EXECUTE,),
    "Bash": (CapabilityClass.EXECUTE,),
    "Write": (CapabilityClass.FILESYSTEM, CapabilityClass.WRITE),
    "Edit": (CapabilityClass.FILESYSTEM, CapabilityClass.WRITE),
    "MultiEdit": (CapabilityClass.FILESYSTEM, CapabilityClass.WRITE),
    "NotebookEdit": (CapabilityClass.FILESYSTEM, CapabilityClass.WRITE),
    "Read": (CapabilityClass.FILESYSTEM, CapabilityClass.READ),
    "Glob": (CapabilityClass.FILESYSTEM, CapabilityClass.READ),
    "Grep": (CapabilityClass.FILESYSTEM, CapabilityClass.READ),
    "WebFetch": (CapabilityClass.NETWORK, CapabilityClass.READ),
    "WebSearch": (CapabilityClass.NETWORK, CapabilityClass.READ),
}
_EXECUTE_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.Popen",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execvp",
        "os.spawnl",
        "pty.spawn",
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
        "eval",
        "exec",
    }
)
_NETWORK_ROOTS = frozenset(
    {"requests", "httpx", "urllib", "aiohttp", "socket", "smtplib", "boto3", "websocket", "grpc"}
)
_PAYMENT_ROOTS = frozenset({"stripe", "paypalrestsdk", "braintree", "square", "adyen"})
_FILESYSTEM_WRITE = frozenset(
    {
        "write_text",
        "write_bytes",
        "unlink",
        "rmtree",
        "remove",
        "rmdir",
        "makedirs",
        "mkdir",
        "rename",
        "copyfile",
        "copy",
        "move",
    }
)
_FILESYSTEM_READ = frozenset({"read_text", "read_bytes", "glob", "rglob", "listdir", "scandir"})
_SQL_WRITE = re.compile(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|COPY)\b", re.I)
_SQL_READ = re.compile(r"\bSELECT\b", re.I)
_DB_EXECUTE = frozenset({"execute", "executemany", "exec_driver_sql"})
_ENV_READ = frozenset({"os.environ", "os.getenv", "environ"})

_TS_SUFFIXES = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"})
_TS_AGENT_CALLS = frozenset({"generateText", "streamText", "generateObject", "streamObject"})
_TS_PROVIDER_FUNCTIONS: dict[str, str] = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google",
    "azure": "azure-openai",
    "bedrock": "aws-bedrock",
    "mistral": "mistral",
    "groq": "groq",
    "ollama": "ollama",
    "cohere": "cohere",
    "createAnthropic": "anthropic",
    "createOpenAI": "openai",
    "createGoogleGenerativeAI": "google",
}
_TS_ENV = re.compile(
    r"process\.env(?:\.([A-Z][A-Z0-9_]{2,63})|\[\s*['\"]([A-Z][A-Z0-9_]{2,63})['\"]\s*\])"
)
_TS_EXECUTE = re.compile(r"\b(?:execSync|exec|spawn|spawnSync|execFile|execFileSync)\s*\(")
_TS_WRITE = re.compile(
    r"\b(?:writeFileSync|writeFile|appendFileSync|appendFile|rmSync|unlinkSync|mkdirSync)\s*\("
)
_TS_READ = re.compile(r"\b(?:readFileSync|readFile|readdirSync|readdir)\s*\(")
_TS_NETWORK = re.compile(
    r"\b(?:fetch|axios|got|undici|http\.request|https\.request|sendMail)\s*[.(]"
)
_TS_SDK_MODULES = frozenset(
    {"ai", "@ai-sdk/anthropic", "@ai-sdk/openai", "@ai-sdk/google", "@anthropic-ai/sdk", "openai"}
)

_N8N_AGENT_TYPES = (".agent", ".openAiAssistant", ".chainLlm", ".chainSummarization")
_N8N_MODEL_TYPES = (".lmChat", ".lmOpenAi", ".lmOllama", ".lmCohere", ".lmAnthropic", ".embeddings")
_N8N_PROVIDERS: dict[str, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "googlegemini": "google",
    "googlevertex": "google",
    "ollama": "ollama",
    "mistralcloud": "mistral",
    "groq": "groq",
    "cohere": "cohere",
    "azureopenai": "azure-openai",
    "awsbedrock": "aws-bedrock",
}


def _is_test_path(path: Path) -> bool:
    parts = set(path.parts[:-1])
    if parts & _TEST_DIRECTORIES:
        return True
    name = path.name
    return (
        name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.tsx", ".test.js", ".spec.ts", ".spec.js"))
        or name == "conftest.py"
    )


def _skipped(path: Path) -> bool:
    return bool(set(path.parts[:-1]) & _SKIPPED_DIRECTORIES) or _is_test_path(path)


def _reference_text(value: str) -> str:
    return quote(value, safe="")


def _plausible_model_id(value: str) -> bool:
    if not _MODEL_ID.match(value) or _PLACEHOLDER.search(value):
        return False
    if _ENV_NAME.match(value):
        return False
    return any(ch.isalpha() for ch in value) and any(ch.isdigit() or ch in "-/.:" for ch in value)


def _provider_for(model: str, hint: str) -> tuple[str, str]:
    """Split ``prefix/model`` and ``prefix:model`` routes and name the provider."""
    name = model
    provider = hint
    if model.lower().startswith("accounts/fireworks/models/"):
        # A Fireworks route carries the account path in the identifier itself.
        return model, provider or "fireworks"
    for separator in ("/", ":"):
        head, sep, rest = model.partition(separator)
        if sep and head.lower() in _PREFIX_PROVIDERS and rest:
            provider = provider or _PREFIX_PROVIDERS[head.lower()]
            name = rest
            break
    if not provider:
        lowered = name.lower()
        for prefix, family in _MODEL_FAMILIES:
            if lowered.startswith(prefix):
                provider = family
                break
    if not provider and "/" in name:
        provider = "huggingface"
    return name, provider or "unknown"


def _model_kind(name: str, provider: str) -> str:
    lowered = name.lower()
    if any(marker in lowered for marker in _EMBEDDING_MARKERS):
        return "embedding"
    if provider in {"huggingface", "ollama", "meta"} or lowered.endswith((".safetensors", ".gguf")):
        return "local"
    return "hosted"


@dataclass
class _ModelReference:
    name: str
    provider: str
    path: str
    line: int
    api: str


@dataclass
class _ToolDeclaration:
    name: str
    path: str
    line: int
    binding: str
    framework: str
    capabilities: list[CapabilityClass] = field(default_factory=list)
    side_effect: SideEffectProfile = SideEffectProfile.UNKNOWN
    risks: list[RiskAssessment] = field(default_factory=list)
    description: str | None = None


@dataclass
class _AgentDeclaration:
    name: str
    framework: str
    path: str
    line: int
    builder: str
    models: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    prompt_sources: list[str] = field(default_factory=list)
    mcp_servers: list[str] = field(default_factory=list)
    permission_mode: str | None = None
    credentials: list[str] = field(default_factory=list)
    datasets: list[str] = field(default_factory=list)


@dataclass
class _ModuleFindings:
    """What one source file declares."""

    path: str
    digest: str
    frameworks: set[str] = field(default_factory=set)
    agents: list[_AgentDeclaration] = field(default_factory=list)
    models: list[_ModelReference] = field(default_factory=list)
    tools: list[_ToolDeclaration] = field(default_factory=list)
    credentials: set[str] = field(default_factory=set)
    datasets: list[tuple[str, str, str | None, int]] = field(default_factory=list)


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted(node.value)
        return None if head is None else f"{head}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return None


def _string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword(call: ast.Call, names: Iterable[str]) -> ast.expr | None:
    wanted = set(names)
    for keyword in call.keywords:
        if keyword.arg in wanted:
            return keyword.value
    return None


def _list_items(node: ast.AST | None) -> list[ast.expr]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return list(node.elts)
    return []


class _Module:
    """One parsed Python source and the module-level names it binds."""

    def __init__(self, tree: ast.Module, path: Path, local_modules: frozenset[str]) -> None:
        self.tree = tree
        self.path = path
        self.bindings: dict[str, ast.expr] = {}
        self.imports: dict[str, tuple[str, str]] = {}  # local name -> (module, member)
        self.import_roots: set[str] = set()
        self.frameworks: set[str] = set()
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.local_modules = local_modules
        for node in tree.body:
            self._collect(node)

    def _collect(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in self.local_modules:
                    continue
                self.import_roots.add(root)
                self.imports[alias.asname or root] = (alias.name, "")
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            root = node.module.split(".", 1)[0]
            if root in self.local_modules:
                return
            self.import_roots.add(root)
            names = {alias.name for alias in node.names}
            if root == "agents" and not names & _OPENAI_AGENTS_NAMES:
                return
            for alias in node.names:
                self.imports[alias.asname or alias.name] = (node.module, alias.name)
            framework = _framework_for(node.module)
            if framework:
                self.frameworks.add(framework)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.bindings[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            self.bindings[node.target.id] = node.value
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.functions[node.name] = node

    def resolve(self, node: ast.expr | None, depth: int = 0) -> ast.expr | None:
        """Follow module-level name bindings to the expression they name."""
        if isinstance(node, ast.Name) and depth < 4:
            bound = self.bindings.get(node.id)
            if bound is not None:
                return self.resolve(bound, depth + 1)
        return node

    def framework_of(self, call: ast.Call) -> tuple[str, str] | None:
        """The framework and builder name when ``call`` constructs an agent."""
        name = _dotted(call.func)
        if name is None:
            return None
        base = name.split(".")[-1]
        head = name.split(".")[0]
        module, member = self.imports.get(head, ("", ""))
        framework = _framework_for(module) if module else None
        if framework is None or framework not in self.frameworks:
            return None
        builder = member or base
        if builder not in _AGENT_BUILDERS.get(framework, frozenset()):
            return None
        return framework, builder

    def origin(self, name: str) -> tuple[str, str]:
        head = name.split(".")[0]
        return self.imports.get(head, ("", ""))


def _framework_for(module: str) -> str | None:
    """The agent framework ``module`` belongs to, by its longest matching prefix."""
    best: tuple[int, str] | None = None
    for prefix, label in _AGENT_FRAMEWORKS.items():
        if (module == prefix or module.startswith(prefix + ".")) and (
            best is None or len(prefix) > best[0]
        ):
            best = (len(prefix), label)
    return None if best is None else best[1]


def _function_capabilities(
    function: ast.FunctionDef | ast.AsyncFunctionDef, module: _Module
) -> tuple[list[CapabilityClass], SideEffectProfile, list[RiskAssessment], bool]:
    """Classify a tool body by the operations it names; returns (caps, profile, risks, env)."""
    capabilities: set[CapabilityClass] = set()
    risks: list[RiskAssessment] = []
    reads_env = False
    destructive = payment = raw_sql = False
    parameters = {arg.arg for arg in function.args.args + function.args.kwonlyargs}
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func) or ""
        root = name.split(".")[0]
        last = name.split(".")[-1]
        origin_module = module.origin(root)[0].split(".", 1)[0] if root else ""
        roots = {root, origin_module}
        if name in _EXECUTE_CALLS or (root in {"subprocess", "pty"}):
            capabilities.add(CapabilityClass.EXECUTE)
        if roots & _NETWORK_ROOTS or last in {"post", "get", "put", "patch", "urlopen", "sendmail"}:
            capabilities.add(CapabilityClass.NETWORK)
        if roots & _PAYMENT_ROOTS:
            capabilities.update((CapabilityClass.PAYMENT, CapabilityClass.NETWORK))
            payment = True
        if last in _FILESYSTEM_WRITE or (
            name == "open"
            and any(
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and any(flag in arg.value for flag in "wax+")
                for arg in list(node.args[1:2])
                + [k.value for k in node.keywords if k.arg == "mode"]
            )
        ):
            capabilities.update((CapabilityClass.FILESYSTEM, CapabilityClass.WRITE))
            if last in {"unlink", "rmtree", "remove", "rmdir"}:
                destructive = True
        elif last in _FILESYSTEM_READ or name == "open":
            capabilities.update((CapabilityClass.FILESYSTEM, CapabilityClass.READ))
        if last in _DB_EXECUTE or last == "text":
            statement = node.args[0] if node.args else None
            literal = _string(statement)
            if literal is not None:
                if _SQL_WRITE.search(literal):
                    capabilities.add(CapabilityClass.WRITE)
                    if re.search(r"\b(DROP|DELETE|TRUNCATE)\b", literal, re.I):
                        destructive = True
                elif _SQL_READ.search(literal):
                    capabilities.add(CapabilityClass.READ)
            elif isinstance(statement, ast.Name) and statement.id in parameters:
                raw_sql = True
                capabilities.update((CapabilityClass.WRITE, CapabilityClass.DESTRUCTIVE))
        if name in _ENV_READ or name.startswith(("os.environ", "os.getenv")):
            reads_env = True
            capabilities.add(CapabilityClass.CREDENTIALS)
    for node in ast.walk(function):
        if isinstance(node, ast.Subscript) and _dotted(node.value) in {"os.environ", "environ"}:
            reads_env = True
            capabilities.add(CapabilityClass.CREDENTIALS)
    label = function.name
    if CapabilityClass.EXECUTE in capabilities:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="capability_scope",
                detail=f"Tool '{label}' runs commands or evaluates code on the host.",
                recommendation="Confine the tool to an allow-list of commands and a sandbox.",
            )
        )
    if raw_sql:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="capability_scope",
                detail=f"Tool '{label}' passes a caller-supplied statement to a database.",
                recommendation="Parameterize queries and restrict the tool to read-only access.",
            )
        )
    if payment:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="capability_scope",
                detail=f"Tool '{label}' performs a financial transaction.",
                recommendation="Require human approval and bound amounts for payment tools.",
            )
        )
    if payment:
        profile = SideEffectProfile.FINANCIAL_TRANSACTION
    elif destructive or raw_sql:
        profile = SideEffectProfile.DESTRUCTIVE
    elif CapabilityClass.WRITE in capabilities or CapabilityClass.EXECUTE in capabilities:
        profile = SideEffectProfile.STATE_MODIFYING
    elif capabilities:
        profile = SideEffectProfile.READ_ONLY
    else:
        profile = SideEffectProfile.UNKNOWN
    return sorted(capabilities, key=lambda c: c.value), profile, risks, reads_env


def _env_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and _dotted(node.value) in _ENV_READ:
            value = _string(node.slice)
            if value and _ENV_NAME.match(value):
                names.add(value)
        elif isinstance(node, ast.Call):
            name = _dotted(node.func) or ""
            if name in {"os.getenv", "os.environ.get", "environ.get", "getenv"} and node.args:
                value = _string(node.args[0])
                if value and _ENV_NAME.match(value):
                    names.add(value)
    return names


class _PythonAnalysis:
    """Collect declarations from one parsed Python module."""

    def __init__(self, module: _Module, findings: _ModuleFindings) -> None:
        self.module = module
        self.findings = findings
        self.tool_names: dict[str, _ToolDeclaration] = {}
        self.model_sdk = bool(module.import_roots & _MODEL_SDK_ROOTS)

    def run(self) -> None:
        module = self.module
        self.findings.frameworks = set(module.frameworks)
        self.findings.credentials = _env_names(module.tree)
        for name, function in module.functions.items():
            decorator = self._tool_decorator(function)
            if decorator is not None:
                self._declare_function_tool(name, function, decorator)
        if self.model_sdk:
            for node in ast.walk(module.tree):
                if isinstance(node, ast.Call):
                    self._model_literals(node)
                    self._dataset(node)
        for statement in module.tree.body:
            self._agent_statement(statement)
        for agent in self.findings.agents:
            agent.credentials = sorted(self.findings.credentials)

    def _tool_decorator(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        for decorator in function.decorator_list:
            name = _dotted(decorator) or ""
            last = name.split(".")[-1]
            if last in _TOOL_DECORATORS:
                head = name.split(".")[0]
                module, _ = self.module.origin(head)
                if head in self.module.bindings or head in self.module.imports or module:
                    return name
                if last == "tool" and len(name.split(".")) > 1:
                    return name
        return None

    def _declare_function_tool(
        self, name: str, function: ast.FunctionDef | ast.AsyncFunctionDef, decorator: str
    ) -> None:
        capabilities, profile, risks, _ = _function_capabilities(function, self.module)
        head = decorator.split(".")[0]
        module, _member = self.module.origin(head)
        framework = (_framework_for(module) or "") if module else ""
        if not framework and head in self.module.bindings:
            framework = next(iter(self.module.frameworks), "")
        if not framework and module.startswith("langchain"):
            framework = "langchain"
        docstring = ast.get_docstring(function)
        tool = _ToolDeclaration(
            name=name,
            path=self.findings.path,
            line=function.lineno,
            binding="decorator",
            framework=framework or module.split(".", 1)[0] or "python",
            capabilities=capabilities,
            side_effect=profile,
            risks=risks,
            description=docstring.strip().splitlines()[0][:200] if docstring else None,
        )
        self.tool_names[name] = tool
        self.findings.tools.append(tool)

    def _model_literals(self, call: ast.Call) -> None:
        name = _dotted(call.func) or ""
        base = name.split(".")[-1]
        hint = _PROVIDER_CLASSES.get(base, "")
        if base == _FROM_PRETRAINED and call.args:
            literal = _string(self.module.resolve(call.args[0]))
            self._add_model(literal, "huggingface", call.lineno, name)
            return
        positional = _POSITIONAL_MODEL_CALLS.get(base)
        if positional is not None and call.args:
            module, _ = self.module.origin(name.split(".")[0])
            if base != "Agent" or module.startswith("pydantic_ai"):
                literal = _string(self.module.resolve(call.args[0]))
                self._add_model(literal, positional, call.lineno, name)
        for keyword in call.keywords:
            if keyword.arg in _MODEL_KEYWORDS:
                literal = _string(self.module.resolve(keyword.value))
                self._add_model(literal, hint, call.lineno, name)

    def _add_model(self, literal: str | None, hint: str, line: int, api: str) -> None:
        if literal is None or not _plausible_model_id(literal):
            return
        provider_hint = "" if hint in {"pydantic-ai"} else hint
        model, provider = _provider_for(literal, provider_hint)
        if provider == "huggingface" and "/" not in model and hint != "huggingface":
            return
        self.findings.models.append(
            _ModelReference(model, provider, self.findings.path, line, api.split(".")[-1])
        )

    def _dataset(self, call: ast.Call) -> None:
        name = _dotted(call.func) or ""
        if name.split(".")[-1] != "load_dataset" or not call.args:
            return
        dataset = _string(call.args[0])
        if dataset is None or _PLACEHOLDER.search(dataset):
            return
        files = _keyword(call, ("data_files",))
        locator = _string(files)
        if locator is None and isinstance(files, (ast.List, ast.Tuple)):
            locator = next((v for v in (_string(e) for e in files.elts) if v), None)
        if dataset in {"json", "csv", "parquet", "text", "arrow"}:
            if locator is None:
                return
            self.findings.datasets.append((locator, "local-files", locator, call.lineno))
        else:
            self.findings.datasets.append((dataset, "huggingface", f"hf:{dataset}", call.lineno))

    def _agent_statement(self, statement: ast.stmt) -> None:
        assigned: str | None = None
        value: ast.expr | None = None
        if isinstance(statement, ast.Assign) and isinstance(statement.targets[0], ast.Name):
            assigned, value = statement.targets[0].id, statement.value
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            assigned, value = statement.target.id, statement.value
        elif isinstance(statement, ast.Expr):
            value = statement.value
        if not isinstance(value, ast.Call):
            return
        found = self.module.framework_of(value)
        if found is None:
            # ``graph.compile()`` names the LangGraph agent that a StateGraph builds.
            if (
                isinstance(value.func, ast.Attribute)
                and value.func.attr == "compile"
                and assigned is not None
            ):
                builder = self.module.resolve(value.func.value)
                if isinstance(builder, ast.Call) and self.module.framework_of(builder) == (
                    "langgraph",
                    "StateGraph",
                ):
                    self._declare_agent(assigned, "langgraph", "StateGraph", builder, value.lineno)
            return
        framework, builder_name = found
        if framework == "langgraph" and builder_name == "StateGraph":
            return  # recorded when compiled
        self._declare_agent(assigned, framework, builder_name, value, value.lineno)

    def _declare_agent(
        self, assigned: str | None, framework: str, builder: str, call: ast.Call, line: int
    ) -> None:
        literal_name = _string(_keyword(call, ("name", "role")))
        if builder in {"ClaudeAgentOptions", "ClaudeSDKClient"}:
            assigned = None
        name = literal_name or assigned or Path(self.findings.path).stem
        agent = _AgentDeclaration(
            name=name[:_MAX_NAME],
            framework=framework,
            path=self.findings.path,
            line=line,
            builder=builder,
        )
        model_node = self.module.resolve(_keyword(call, ("model", "llm", "model_name")))
        if model_node is None and framework == "pydantic-ai" and call.args:
            model_node = call.args[0]
        self._bind_model(agent, model_node, call)
        if not agent.models:
            self._bind_module_models(agent)
        for keyword_name in _TOOL_LIST_KEYWORDS:
            for item in _list_items(self.module.resolve(_keyword(call, (keyword_name,)))):
                self._bind_tool(agent, item, framework, keyword_name)
        self._bind_graph_tools(agent, framework)
        prompt = _keyword(call, _PROMPT_KEYWORDS)
        if prompt is not None:
            agent.prompt_sources.append(self._prompt_source(prompt))
        servers = self.module.resolve(_keyword(call, ("mcp_servers",)))
        if isinstance(servers, ast.Dict):
            agent.mcp_servers = [k for k in (_string(key) for key in servers.keys) if k]
        elif servers is not None:
            agent.mcp_servers = [n for n in (_dotted(item) for item in _list_items(servers)) if n]
        permission = _string(_keyword(call, _PERMISSION_KEYWORDS))
        if permission is not None:
            agent.permission_mode = permission
        self.findings.agents.append(agent)

    def _bind_model(self, agent: _AgentDeclaration, node: ast.expr | None, call: ast.Call) -> None:
        literal = _string(node)
        if literal is not None and _plausible_model_id(literal):
            hint = (
                "" if agent.framework == "pydantic-ai" else _PROVIDER_CLASSES.get(agent.builder, "")
            )
            model, provider = _provider_for(literal, hint)
            agent.models.append(f"{provider}/{model}")
            self.findings.models.append(
                _ModelReference(model, provider, self.findings.path, call.lineno, agent.builder)
            )
            return
        if isinstance(node, ast.Call):
            base = (_dotted(node.func) or "").split(".")[-1]
            hint = _PROVIDER_CLASSES.get(base, "")
            value = _string(_keyword(node, _MODEL_KEYWORDS))
            if value is None and node.args and base in _POSITIONAL_MODEL_CALLS:
                value = _string(node.args[0])
            if value is not None and _plausible_model_id(value):
                model, provider = _provider_for(value, hint)
                agent.models.append(f"{provider}/{model}")

    def _bind_module_models(self, agent: _AgentDeclaration) -> None:
        """A graph or client built without a model argument uses the module's model client."""
        for value in self.module.bindings.values():
            if not isinstance(value, ast.Call):
                continue
            base = (_dotted(value.func) or "").split(".")[-1]
            if base not in _PROVIDER_CLASSES or base in {"LLM", "LlmAgent"}:
                continue
            literal = _string(self.module.resolve(_keyword(value, _MODEL_KEYWORDS)))
            if literal is not None and _plausible_model_id(literal):
                model, provider = _provider_for(literal, _PROVIDER_CLASSES[base])
                if _model_kind(model, provider) != "embedding":
                    agent.models.append(f"{provider}/{model}")

    def _bind_tool(
        self, agent: _AgentDeclaration, item: ast.expr, framework: str, keyword_name: str
    ) -> None:
        literal = _string(item)
        if literal is not None:
            if keyword_name == "allowed_tools" and literal and len(literal) <= _MAX_NAME:
                self._builtin_tool(agent, literal, framework, "allowed-tools")
            return
        name = _dotted(item)
        if name is None:
            return
        base = name.split(".")[-1]
        if base in self.tool_names:
            agent.tools.append(base)
            return
        if base in self.module.functions:
            function = self.module.functions[base]
            capabilities, profile, risks, _ = _function_capabilities(function, self.module)
            docstring = ast.get_docstring(function)
            tool = _ToolDeclaration(
                name=base,
                path=self.findings.path,
                line=function.lineno,
                binding="agent-tools-list",
                framework=framework,
                capabilities=capabilities,
                side_effect=profile,
                risks=risks,
                description=docstring.strip().splitlines()[0][:200] if docstring else None,
            )
            self.tool_names[base] = tool
            self.findings.tools.append(tool)
            agent.tools.append(base)
            return
        bound = self.module.resolve(item)
        callee = _dotted(bound.func) if isinstance(bound, ast.Call) else name
        if callee is None:
            return
        class_name = callee.split(".")[-1]
        module, _ = self.module.origin(callee.split(".")[0])
        tool_framework = next(
            (label for prefix, label in _BUILTIN_TOOL_MODULES.items() if module.startswith(prefix)),
            "",
        )
        if tool_framework or class_name in _BUILTIN_TOOL_CAPABILITIES:
            self._builtin_tool(agent, class_name, tool_framework or framework, "agent-tools-list")

    def _builtin_tool(
        self, agent: _AgentDeclaration, name: str, framework: str, binding: str
    ) -> None:
        if name in self.tool_names:
            agent.tools.append(name)
            return
        capabilities = list(_BUILTIN_TOOL_CAPABILITIES.get(name, ()))
        if name.startswith("mcp__") or name.lower().startswith("mcp:"):
            return  # MCP tools are the MCP collector's subject
        profile = (
            SideEffectProfile.STATE_MODIFYING
            if CapabilityClass.WRITE in capabilities or CapabilityClass.EXECUTE in capabilities
            else SideEffectProfile.READ_ONLY
            if capabilities
            else SideEffectProfile.UNKNOWN
        )
        risks: list[RiskAssessment] = []
        if CapabilityClass.EXECUTE in capabilities:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="capability_scope",
                    detail=f"Built-in tool '{name}' runs commands or code for the agent.",
                    recommendation="Restrict the tool with an allow-list or remove it.",
                )
            )
        tool = _ToolDeclaration(
            name=name,
            path=self.findings.path,
            line=agent.line,
            binding=binding,
            framework=framework,
            capabilities=capabilities,
            side_effect=profile,
            risks=risks,
        )
        self.tool_names[name] = tool
        self.findings.tools.append(tool)
        agent.tools.append(name)

    def _bind_graph_tools(self, agent: _AgentDeclaration, framework: str) -> None:
        if framework != "langgraph":
            return
        for node in ast.walk(self.module.tree):
            if not isinstance(node, ast.Call):
                continue
            callee = _dotted(node.func) or ""
            if callee.split(".")[-1] in {"ToolNode", "bind_tools", "create_react_agent"}:
                source = _keyword(node, ("tools",))
                if source is None and node.args:
                    source = node.args[0 if callee.split(".")[-1] != "create_react_agent" else 1]
                for item in _list_items(self.module.resolve(source)):
                    self._bind_tool(agent, item, framework, "tools")

    def _prompt_source(self, node: ast.expr) -> str:
        literal = _string(node)
        if literal is not None:
            return "inline:sha256:" + hash_bytes(literal.encode("utf-8"))[:16]
        resolved = self.module.resolve(node)
        if resolved is None:
            return "module-loaded"
        for inner in ast.walk(resolved):
            value = _string(inner)
            if value and ("/" in value or value.endswith((".md", ".txt", ".yaml", ".jinja2"))):
                return f"file:{value}"[:_MAX_NAME]
        return "module-loaded"


class _TypeScriptAnalysis:
    """Vercel AI SDK agents, provider model literals, tools and env names in one file."""

    def __init__(self, root: Node, source: bytes, findings: _ModuleFindings) -> None:
        self.root = root
        self.source = source
        self.findings = findings

    def text(self, node: Node | None) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode("utf-8", "replace")

    def run(self, limit: limits.Bound) -> None:
        text = self.text(self.root)
        imports = set(re.findall(r"""from\s+['"]([^'"]+)['"]""", text)) | set(
            re.findall(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", text)
        )
        if not imports & _TS_SDK_MODULES and not any(m.startswith("@ai-sdk/") for m in imports):
            return
        self.findings.frameworks.add("vercel-ai-sdk" if "ai" in imports else "provider-sdk")
        for env_match in _TS_ENV.finditer(text):
            self.findings.credentials.add(env_match.group(1) or env_match.group(2))
        count = 0
        pending = [self.root]
        while pending:
            node = pending.pop()
            count += 1
            if count > limit.value:
                raise ValueError(limit.exceeded())
            if node.type == "call_expression":
                self._call(node)
            pending.extend(reversed(node.named_children))

    def _call(self, node: Node) -> None:
        function = node.child_by_field_name("function")
        callee = self.text(function)
        base = callee.split(".")[-1]
        line = node.start_point[0] + 1
        arguments = node.child_by_field_name("arguments")
        if base in _TS_AGENT_CALLS and arguments is not None:
            self._agent(node, arguments, base, line)
        elif base in _TS_PROVIDER_FUNCTIONS and arguments is not None:
            literal = self._first_string(arguments)
            if literal:
                self._model(literal, _TS_PROVIDER_FUNCTIONS[base], line, base)
        elif base == "create" and arguments is not None:
            model = self._object_property(arguments, "model")
            literal = self._string_literal(model)
            if literal:
                provider = "anthropic" if "messages" in callee else "openai"
                self._model(literal, provider, line, callee)

    def _agent(self, node: Node, arguments: Node, call: str, line: int) -> None:
        enclosing = node.parent
        name = Path(self.findings.path).stem
        while enclosing is not None:
            if enclosing.type in {"function_declaration", "method_definition"}:
                declared = enclosing.child_by_field_name("name")
                if declared is not None:
                    name = f"{name}.{self.text(declared)}"
                break
            enclosing = enclosing.parent
        agent = _AgentDeclaration(
            name=name[:_MAX_NAME],
            framework="vercel-ai-sdk",
            path=self.findings.path,
            line=line,
            builder=call,
            credentials=sorted(self.findings.credentials),
        )
        model = self._object_property(arguments, "model")
        if model is not None and model.type == "call_expression":
            callee = self.text(model.child_by_field_name("function")).split(".")[-1]
            literal = self._first_string(model.child_by_field_name("arguments"))
            provider = _TS_PROVIDER_FUNCTIONS.get(callee, "")
            if literal and _plausible_model_id(literal):
                resolved, provider = _provider_for(literal, provider)
                agent.models.append(f"{provider}/{resolved}")
                self.findings.models.append(
                    _ModelReference(resolved, provider, self.findings.path, line, callee)
                )
        elif model is not None:
            literal = self._string_literal(model)
            if literal and _plausible_model_id(literal):
                resolved, provider = _provider_for(literal, "")
                agent.models.append(f"{provider}/{resolved}")
                self.findings.models.append(
                    _ModelReference(resolved, provider, self.findings.path, line, call)
                )
        system = self._object_property(arguments, "system")
        if system is not None:
            literal = self._string_literal(system)
            agent.prompt_sources.append(
                "inline:sha256:" + hash_bytes(literal.encode("utf-8"))[:16]
                if literal is not None
                else "module-loaded"
            )
        tools = self._object_property(arguments, "tools")
        if tools is not None and tools.type == "object":
            for pair in tools.named_children:
                if pair.type != "pair":
                    continue
                key = self.text(pair.child_by_field_name("key")).strip("'\"`")
                value = pair.child_by_field_name("value")
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key) or value is None:
                    continue
                agent.tools.append(key)
                self.findings.tools.append(self._tool(key, value, pair.start_point[0] + 1))
        self.findings.agents.append(agent)

    def _tool(self, name: str, value: Node, line: int) -> _ToolDeclaration:
        body = self.text(value)
        capabilities: set[CapabilityClass] = set()
        risks: list[RiskAssessment] = []
        if _TS_EXECUTE.search(body):
            capabilities.add(CapabilityClass.EXECUTE)
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="capability_scope",
                    detail=f"Tool '{name}' runs commands on the host.",
                    recommendation="Confine the tool to an allow-list of commands and a sandbox.",
                )
            )
        if _TS_WRITE.search(body):
            capabilities.update((CapabilityClass.FILESYSTEM, CapabilityClass.WRITE))
        elif _TS_READ.search(body):
            capabilities.update((CapabilityClass.FILESYSTEM, CapabilityClass.READ))
        if _TS_NETWORK.search(body):
            capabilities.add(CapabilityClass.NETWORK)
        if _TS_ENV.search(body):
            capabilities.add(CapabilityClass.CREDENTIALS)
        if CapabilityClass.WRITE in capabilities or CapabilityClass.EXECUTE in capabilities:
            profile = SideEffectProfile.STATE_MODIFYING
        elif capabilities:
            profile = SideEffectProfile.READ_ONLY
        else:
            profile = SideEffectProfile.UNKNOWN
        description = re.search(r"""description\s*:\s*(['"`])(.*?)\1""", body, re.S)
        return _ToolDeclaration(
            name=name,
            path=self.findings.path,
            line=line,
            binding="agent-tools-object",
            framework="vercel-ai-sdk",
            capabilities=sorted(capabilities, key=lambda c: c.value),
            side_effect=profile,
            risks=risks,
            description=description.group(2)[:200] if description else None,
        )

    def _model(self, literal: str, provider: str, line: int, api: str) -> None:
        if not _plausible_model_id(literal):
            return
        model, resolved = _provider_for(literal, provider)
        self.findings.models.append(
            _ModelReference(model, resolved, self.findings.path, line, api.split(".")[-1])
        )

    def _first_string(self, arguments: Node | None) -> str | None:
        if arguments is None:
            return None
        for child in arguments.named_children:
            literal = self._string_literal(child)
            if literal is not None:
                return literal
            if child.type == "object":
                return None
        return None

    def _string_literal(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type in {"string", "template_string"}:
            if node.type == "template_string" and "${" in self.text(node):
                return None
            return self.text(node).strip("'\"`")
        return None

    def _object_property(self, arguments: Node, key: str) -> Node | None:
        for child in arguments.named_children:
            if child.type != "object":
                continue
            for pair in child.named_children:
                if (
                    pair.type == "pair"
                    and self.text(pair.child_by_field_name("key")).strip("'\"`") == key
                ):
                    return pair.child_by_field_name("value")
        return None


class AgentScanner(Scanner):
    """Framework agents, their models, tools, credentials and datasets from source."""

    name = "agents"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        modules: list[_ModuleFindings] = []
        with self._collection(project_root, result) as files:
            python_sources: list[Path] = []
            ts_sources: list[Path] = []
            json_sources: list[Path] = []
            config_sources: list[Path] = []
            for path in files.iter_files():
                if _skipped(path):
                    continue
                suffix = path.suffix.lower()
                if suffix == ".py":
                    python_sources.append(path)
                elif suffix in _TS_SUFFIXES and ".d.ts" not in path.name:
                    ts_sources.append(path)
                elif suffix == ".json":
                    json_sources.append(path)
                elif self._config_candidate(path):
                    config_sources.append(path)
            local_modules = self._local_modules(files)
            budget = SourceBudget("agent source files", result)
            limit = source_collection_bytes()
            with ConfinedCollection(
                files.root, [], exclude_paths=self._exclude_paths, max_total_bytes=limit
            ) as sources:
                for path in sorted(python_sources):
                    found = self._python(sources, path, budget, local_modules, result)
                    if found is not None:
                        modules.append(found)
                for path in sorted(ts_sources):
                    found = self._typescript(sources, path, budget, result)
                    if found is not None:
                        modules.append(found)
                for path in sorted(json_sources):
                    found = self._workflow(sources, path, budget, result)
                    if found is not None:
                        modules.append(found)
                for path in sorted(config_sources):
                    found = self._config(sources, path, budget, result)
                    if found is not None:
                        modules.append(found)
        self._emit(modules, result)
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("agents (no agent framework declarations found)")
        return result

    @staticmethod
    def _config_candidate(path: Path) -> bool:
        name = path.name.lower()
        posix = path.as_posix()
        return (
            name == "modelfile"
            or name.endswith(".modelfile")
            or ("litellm" in name and name.endswith((".yaml", ".yml")))
            or posix in {".codex/config.toml", ".continue/config.yaml", ".continue/config.yml"}
        )

    @staticmethod
    def _local_modules(files: ConfinedCollection) -> frozenset[str]:
        names: set[str] = set()
        for entry in files.root_entries():
            if entry.endswith(".py"):
                names.add(entry[:-3])
            elif files.is_directory(entry) and files.entry_exists(Path(entry) / "__init__.py"):
                names.add(entry)
        if files.is_directory("src"):
            for source in files.iter_files("src"):
                if len(source.parts) == 3 and source.name == "__init__.py":
                    names.add(source.parts[1])
                elif len(source.parts) == 2 and source.suffix == ".py":
                    names.add(source.stem)
        return frozenset(names)

    def _read(
        self,
        sources: ConfinedCollection,
        path: Path,
        budget: SourceBudget,
        markers: Iterable[bytes],
    ) -> bytes | None:
        if budget.exhausted:
            return None
        raw = sources.read_bytes(path)
        if raw is None or not budget.admit(len(raw), path):
            return None
        if not any(marker in raw for marker in markers):
            return None
        return raw

    def _python(
        self,
        sources: ConfinedCollection,
        path: Path,
        budget: SourceBudget,
        local_modules: frozenset[str],
        result: ScanResult,
    ) -> _ModuleFindings | None:
        markers = [root.encode() for root in sorted(_MODEL_SDK_ROOTS)] + [b"environ", b"getenv"]
        raw = self._read(sources, path, budget, markers)
        if raw is None:
            return None
        try:
            content = raw.decode("utf-8")
            if len(content) > _MAX_PYTHON_CHARACTERS:
                return None
            tree = parse_python(content)
        except (SyntaxError, ValueError, UnicodeDecodeError):
            return None
        bound = limits.bound("python-nodes")
        count = sum(1 for _ in ast.walk(tree))
        if count > bound.value:
            result.scan_failures.append(f"{path.as_posix()}: {bound.exceeded()}")
            return None
        module = _Module(tree, path, local_modules)
        if not module.import_roots & _MODEL_SDK_ROOTS and not module.frameworks:
            return None
        findings = _ModuleFindings(path=path.as_posix(), digest="sha256:" + hash_bytes(raw))
        _PythonAnalysis(module, findings).run()
        if findings.agents or findings.models or findings.tools or findings.datasets:
            result.surfaces_scanned.append(path.as_posix())
            return findings
        return None

    def _typescript(
        self, sources: ConfinedCollection, path: Path, budget: SourceBudget, result: ScanResult
    ) -> _ModuleFindings | None:
        raw = self._read(
            sources,
            path,
            budget,
            [
                b"@ai-sdk/",
                b"from 'ai'",
                b'from "ai"',
                b"@anthropic-ai/sdk",
                b"from 'openai'",
                b'from "openai"',
            ],
        )
        if raw is None:
            return None
        try:
            from tree_sitter import Language, Parser
            from tree_sitter_typescript import language_tsx, language_typescript
        except ImportError:
            result.scan_failures.append(f"{path.as_posix()}: TypeScript grammar unavailable")
            return None
        jsx = path.suffix.lower() in {".tsx", ".jsx", ".js", ".mjs", ".cjs"}
        parser = Parser(Language(language_tsx() if jsx else language_typescript()))
        tree = parser.parse(raw)
        findings = _ModuleFindings(path=path.as_posix(), digest="sha256:" + hash_bytes(raw))
        try:
            _TypeScriptAnalysis(tree.root_node, raw, findings).run(limits.bound("ts-nodes"))
        except ValueError as exc:
            result.scan_failures.append(f"{path.as_posix()}: {exc}")
            return None
        if findings.agents or findings.models or findings.tools:
            result.surfaces_scanned.append(path.as_posix())
            return findings
        return None

    def _workflow(
        self, sources: ConfinedCollection, path: Path, budget: SourceBudget, result: ScanResult
    ) -> _ModuleFindings | None:
        raw = self._read(sources, path, budget, [b"n8n-nodes-"])
        if raw is None or len(raw) > _MAX_WORKFLOW_BYTES:
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict) or not isinstance(data.get("nodes"), list):
            return None
        nodes = [n for n in data["nodes"] if isinstance(n, dict) and isinstance(n.get("type"), str)]
        if not any("n8n-nodes-" in n["type"] for n in nodes):
            return None
        findings = _ModuleFindings(path=path.as_posix(), digest="sha256:" + hash_bytes(raw))
        findings.frameworks.add("n8n")
        raw_connections = data.get("connections")
        connections: dict[str, Any] = raw_connections if isinstance(raw_connections, dict) else {}
        feeds: dict[str, set[str]] = {}
        for source_name, by_type in connections.items():
            if not isinstance(by_type, dict):
                continue
            for _kind, lists in by_type.items():
                if not isinstance(lists, list):
                    continue
                for group in lists:
                    for target in group if isinstance(group, list) else []:
                        if isinstance(target, dict) and isinstance(target.get("node"), str):
                            feeds.setdefault(target["node"], set()).add(str(source_name))
        models: dict[str, str] = {}
        tools: dict[str, _ToolDeclaration] = {}
        credentials: set[str] = set()
        agents: list[tuple[str, dict[str, Any]]] = []
        for node in nodes:
            kind = node["type"]
            label = str(node.get("name") or kind.rsplit(".", 1)[-1])[:_MAX_NAME]
            raw_parameters = node.get("parameters")
            parameters: dict[str, Any] = raw_parameters if isinstance(raw_parameters, dict) else {}
            creds = node.get("credentials")
            if isinstance(creds, dict):
                credentials.update(str(key) for key in creds if isinstance(key, str))
            if kind.endswith(_N8N_AGENT_TYPES):
                agents.append((label, parameters))
            elif any(marker in kind for marker in _N8N_MODEL_TYPES):
                model = parameters.get("model")
                if isinstance(model, dict):
                    model = model.get("value")
                if not isinstance(model, str):
                    options = parameters.get("options")
                    model = options.get("model") if isinstance(options, dict) else None
                suffix = kind.rsplit(".", 1)[-1].lower()
                provider = next(
                    (p for key, p in _N8N_PROVIDERS.items() if key in suffix), "unknown"
                )
                if isinstance(model, str) and _plausible_model_id(model):
                    resolved, provider = _provider_for(model, provider)
                    models[label] = f"{provider}/{resolved}"
                    findings.models.append(
                        _ModelReference(
                            resolved, provider, findings.path, 0, kind.rsplit(".", 1)[-1]
                        )
                    )
            elif kind.endswith("Tool") or ".tool" in kind.lower():
                tool = _ToolDeclaration(
                    name=label, path=findings.path, line=0, binding="workflow-node", framework="n8n"
                )
                endpoint = parameters.get("sseEndpoint") or parameters.get("endpointUrl")
                if isinstance(endpoint, str) and endpoint.startswith(("http://", "https://")):
                    tool.capabilities.append(CapabilityClass.NETWORK)
                    tool.description = f"MCP client endpoint {sanitized_origin(endpoint)}"
                tools[label] = tool
                findings.tools.append(tool)
        for label, _parameters in agents:
            agent = _AgentDeclaration(
                name=label, framework="n8n", path=findings.path, line=0, builder="workflow-node"
            )
            upstream = feeds.get(label, set())
            agent.models = [models[n] for n in sorted(upstream) if n in models] or sorted(
                models.values()
            )[:1]
            agent.tools = [n for n in sorted(upstream) if n in tools] or (
                sorted(tools) if len(agents) == 1 else []
            )
            agent.credentials = sorted(credentials)
            findings.agents.append(agent)
        findings.credentials = credentials
        if findings.agents or findings.models or findings.tools:
            result.surfaces_scanned.append(path.as_posix())
            return findings
        return None

    def _config(
        self, sources: ConfinedCollection, path: Path, budget: SourceBudget, result: ScanResult
    ) -> _ModuleFindings | None:
        raw = self._read(sources, path, budget, [b""])
        if raw is None:
            return None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        findings = _ModuleFindings(path=path.as_posix(), digest="sha256:" + hash_bytes(raw))
        name = path.name.lower()
        posix = path.as_posix()
        if name == "modelfile" or name.endswith(".modelfile"):
            for number, line in enumerate(text.splitlines(), 1):
                words = line.split()
                if len(words) >= 2 and words[0].upper() == "FROM" and _plausible_model_id(words[1]):
                    findings.models.append(
                        _ModelReference(words[1], "ollama", findings.path, number, "Modelfile")
                    )
        elif posix == ".codex/config.toml":
            from nexus_symbiote.utils import toml as bounded_toml

            try:
                data = bounded_toml.loads(text)
            except ValueError:
                result.scan_failures.append(f"{posix}: TOML parse failed")
                return None
            model = data.get("model") if isinstance(data, dict) else None
            if isinstance(model, str) and _plausible_model_id(model):
                resolved, provider = _provider_for(model, "openai")
                findings.models.append(_ModelReference(resolved, provider, posix, 1, "codex"))
        else:
            mapping = self._parse_yaml_mapping(path, text, result)
            if not mapping:
                return None
            entries = mapping.get("model_list") if "litellm" in name else mapping.get("models")
            for entry in entries if isinstance(entries, list) else []:
                if not isinstance(entry, dict):
                    continue
                params = entry.get("litellm_params") if "litellm" in name else entry
                if not isinstance(params, dict):
                    continue
                model = params.get("model")
                if isinstance(model, str) and _plausible_model_id(model):
                    hint = str(params.get("provider") or "")
                    resolved, provider = _provider_for(model, _PREFIX_PROVIDERS.get(hint, hint))
                    api = "litellm" if "litellm" in name else "continue"
                    findings.models.append(_ModelReference(resolved, provider, posix, 0, api))
        if findings.models:
            result.surfaces_scanned.append(posix)
            return findings
        return None

    def _emit(self, modules: list[_ModuleFindings], result: ScanResult) -> None:
        model_refs: dict[str, ModelComponent] = {}
        components: list[AnyComponent] = []
        edges: list[DependencyEdge] = []
        for module in modules:
            for reference in module.models:
                key = f"{reference.provider}/{reference.name}"
                ref = f"model:reference:{reference.provider}/{_reference_text(reference.name)}"
                component = model_refs.get(key)
                if component is None:
                    component = ModelComponent(
                        bom_ref=ref,
                        name=reference.name,
                        provider=reference.provider,
                        model_type=_model_kind(reference.name, reference.provider),
                        requested_alias=reference.name,
                        source_path=reference.path,
                        trust_tier=(
                            TrustTier.THIRD_PARTY_UNSIGNED
                            if reference.provider != "unknown"
                            else TrustTier.UNKNOWN
                        ),
                        properties={
                            "collection_mode": REFERENCE_COLLECTION_MODE,
                            "references": [],
                            "credential_env_vars": [],
                        },
                    )
                    model_refs[key] = component
                    components.append(component)
                references = component.properties["references"]
                if len(references) < _MAX_REFERENCES:
                    entry = {"path": reference.path, "line": reference.line, "api": reference.api}
                    if entry not in references:
                        references.append(entry)
                known = set(component.properties["credential_env_vars"])
                component.properties["credential_env_vars"] = sorted(known | module.credentials)
        tool_refs: dict[tuple[str, str], str] = {}
        for module in modules:
            for tool in module.tools:
                ref = f"tool:agent-code:{_reference_text(module.path)}/{_reference_text(tool.name)}"
                if (module.path, tool.name) in tool_refs:
                    continue
                tool_refs[(module.path, tool.name)] = ref
                capabilities = (
                    CapabilityDeclaration(
                        capabilities=tool.capabilities, side_effect_profile=tool.side_effect
                    )
                    if tool.capabilities or tool.side_effect != SideEffectProfile.UNKNOWN
                    else None
                )
                components.append(
                    ToolComponent(
                        bom_ref=ref,
                        name=tool.name,
                        description_text=tool.description,
                        source_path=module.path,
                        trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        capabilities=capabilities,
                        risks=tool.risks,
                        properties={
                            "collection_mode": COLLECTION_MODE,
                            "method": "python-ast" if module.path.endswith(".py") else "source",
                            "binding": tool.binding,
                            "framework": tool.framework,
                            "declaration_line": tool.line,
                            "source_sha256": module.digest,
                        },
                    )
                )
        for module in modules:
            for agent in module.agents:
                ref = f"agent:code:{_reference_text(module.path)}/{_reference_text(agent.name)}"
                if any(component.bom_ref == ref for component in components):
                    continue
                models = [
                    f"model:reference:{m.split('/', 1)[0]}/{_reference_text(m.split('/', 1)[1])}"
                    for m in agent.models
                    if "/" in m
                ]
                models = [m for m in models if any(c.bom_ref == m for c in components)]
                tools = [
                    tool_refs[(module.path, tool)]
                    for tool in agent.tools
                    if (module.path, tool) in tool_refs
                ]
                risks: list[RiskAssessment] = []
                if (
                    agent.permission_mode
                    and agent.permission_mode.lower() in _UNSAFE_PERMISSION_VALUES
                ):
                    risks.append(
                        RiskAssessment(
                            severity=RiskSeverity.HIGH,
                            category="permission_scope",
                            detail=(
                                f"Agent '{agent.name}' is constructed with permission mode "
                                f"'{agent.permission_mode}', which skips approval prompts."
                            ),
                            recommendation="Use a mode that requires approval for destructive tools.",
                        )
                    )
                properties: dict[str, Any] = {
                    "collection_mode": COLLECTION_MODE,
                    "builder": agent.builder,
                    "declaration_line": agent.line,
                    "source_sha256": module.digest,
                    "credential_env_vars": agent.credentials,
                    "tool_names": sorted(set(agent.tools)),
                }
                if agent.prompt_sources:
                    properties["instruction_sources"] = agent.prompt_sources
                if agent.mcp_servers:
                    properties["mcp_server_names"] = sorted(set(agent.mcp_servers))
                if agent.permission_mode:
                    properties["permission_mode"] = agent.permission_mode
                components.append(
                    AgentComponent(
                        bom_ref=ref,
                        name=agent.name,
                        framework=agent.framework,
                        model_refs=sorted(set(models)),
                        tool_refs=sorted(set(tools)),
                        source_path=module.path,
                        trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        deployment_status="declared",
                        risks=risks,
                        properties=properties,
                    )
                )
                for target in sorted(set(models)):
                    edges.append(
                        DependencyEdge(
                            source_ref=ref,
                            target_ref=target,
                            relationship="uses-model",
                            assurance_level="declared",
                        )
                    )
                for target in sorted(set(tools)):
                    edges.append(
                        DependencyEdge(
                            source_ref=ref,
                            target_ref=target,
                            relationship="invokes",
                            assurance_level="declared",
                        )
                    )
        seen_datasets: set[str] = set()
        for module in modules:
            for dataset, kind, locator, line in module.datasets:
                ref = f"data-source:code:{_reference_text(dataset)}"
                if ref in seen_datasets:
                    continue
                seen_datasets.add(ref)
                components.append(
                    DataSourceComponent(
                        bom_ref=ref,
                        name=dataset,
                        dataset_type="fine-tuning" if "train" in module.path.lower() else None,
                        source_uri=locator,
                        source_path=module.path,
                        trust_tier=(
                            TrustTier.UNTRUSTED_PUBLIC
                            if kind == "huggingface"
                            else TrustTier.INTERNAL_UNVERIFIED
                        ),
                        properties={
                            "collection_mode": COLLECTION_MODE,
                            "source_kind": kind,
                            "declaration_line": line,
                        },
                    )
                )
        result.components.extend(components)
        result.dependencies.extend(edges)


def frameworks_detected(result: ScanResult) -> Iterator[str]:
    """Framework labels of the agents a scan recorded, once each."""
    seen: set[str] = set()
    for component in result.components:
        if isinstance(component, AgentComponent) and component.framework:
            if component.framework not in seen:
                seen.add(component.framework)
                yield component.framework
