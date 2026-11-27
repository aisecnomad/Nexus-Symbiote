"""What the Python source reader recognises: SDK modules, constructors and keywords.

These are tables, not behaviour. A row says that a call imported from a module is an
agent, a model client, a tool, a store or a guardrail, and which of its arguments
hold the references the reader follows. A project module that shadows one of these
module names is never read as the SDK.
"""

from __future__ import annotations

from dataclasses import dataclass

# Top-level modules whose import makes a file one the reader analyses.
AI_ROOTS = frozenset(
    {
        "ag2",
        "agents",
        "agno",
        "anthropic",
        "autogen",
        "autogen_agentchat",
        "autogen_core",
        "autogen_ext",
        "boto3",
        "camel",
        "chromadb",
        "claude_agent_sdk",
        "claude_code_sdk",
        "cohere",
        "crewai",
        "crewai_tools",
        "datasets",
        "deepagents",
        "dspy",
        "faiss",
        "fireworks",
        "google",
        "groq",
        "guardrails",
        "haystack",
        "haystack_integrations",
        "huggingface_hub",
        "instructor",
        "lancedb",
        "langchain",
        "langchain_anthropic",
        "langchain_aws",
        "langchain_chroma",
        "langchain_cohere",
        "langchain_community",
        "langchain_core",
        "langchain_deepseek",
        "langchain_experimental",
        "langchain_fireworks",
        "langchain_google_genai",
        "langchain_google_vertexai",
        "langchain_groq",
        "langchain_huggingface",
        "langchain_mcp_adapters",
        "langchain_milvus",
        "langchain_mistralai",
        "langchain_nvidia_ai_endpoints",
        "langchain_ollama",
        "langchain_openai",
        "langchain_perplexity",
        "langchain_pinecone",
        "langchain_postgres",
        "langchain_qdrant",
        "langchain_tavily",
        "langchain_together",
        "langchain_weaviate",
        "langchain_xai",
        "langgraph",
        "litellm",
        "livekit",
        "llama_cpp",
        "llama_index",
        "llm_guard",
        "mcp",
        "mcp_use",
        "mem0",
        "mistralai",
        "nemoguardrails",
        "ollama",
        "openai",
        "phi",
        "pinecone",
        "presidio_analyzer",
        "pydantic_ai",
        "pymilvus",
        "qdrant_client",
        "replicate",
        "semantic_kernel",
        "sentence_transformers",
        "smolagents",
        "strands",
        "strands_tools",
        "swarm",
        "together",
        "transformers",
        "vertexai",
        "voyageai",
        "weaviate",
        "zep_cloud",
    }
)
# ``google`` and ``boto3`` hold much besides AI clients: only these parts count.
AI_SUBMODULES = {
    "google": ("google.adk", "google.genai", "google.generativeai", "google.cloud.aiplatform"),
}
# Bytes that say a file may import one of the roots, tested before it is parsed.
AI_MARKERS = tuple(sorted(name.encode() for name in AI_ROOTS))

# The provider a module's clients talk to, by the longest module prefix that matches.
MODULE_PROVIDERS: dict[str, str] = {
    "anthropic": "anthropic",
    "cohere": "cohere",
    "fireworks": "fireworks",
    "google.cloud.aiplatform": "google-vertex-ai",
    "google.genai": "google",
    "google.generativeai": "google",
    "groq": "groq",
    "huggingface_hub": "huggingface",
    "langchain_anthropic": "anthropic",
    "langchain_aws": "aws-bedrock",
    "langchain_cohere": "cohere",
    "langchain_deepseek": "deepseek",
    "langchain_fireworks": "fireworks",
    "langchain_google_genai": "google",
    "langchain_google_vertexai": "google-vertex-ai",
    "langchain_groq": "groq",
    "langchain_huggingface": "huggingface",
    "langchain_mistralai": "mistral",
    "langchain_nvidia_ai_endpoints": "nvidia",
    "langchain_ollama": "ollama",
    "langchain_openai": "openai",
    "langchain_perplexity": "perplexity",
    "langchain_together": "together",
    "langchain_xai": "xai",
    "llama_cpp": "llama-cpp",
    "mistralai": "mistral",
    "ollama": "ollama",
    "openai": "openai",
    "replicate": "replicate",
    "sentence_transformers": "huggingface",
    "together": "together",
    "transformers": "huggingface",
    "vertexai": "google-vertex-ai",
    "voyageai": "voyage",
}
# The service an agent framework sends a bare identifier to unless told otherwise. It
# is a default, not a declaration: it is recorded only for an identifier of a family
# that service serves.
FRAMEWORK_PROVIDERS: dict[str, str] = {
    "agents": "openai",
    "google.adk": "google",
    "strands": "aws-bedrock",
    "swarm": "openai",
}
# Integration packages that name the provider in their own path:
# ``llama_index.llms.anthropic``, ``autogen_ext.models.openai``, ``agno.models.groq``.
PROVIDER_SEGMENT_PARENTS = frozenset({"llms", "embeddings", "models", "model", "providers"})
SEGMENT_PROVIDERS: dict[str, str] = {
    "anthropic": "anthropic",
    "aws": "aws-bedrock",
    "azure": "azure-openai",
    "azure_openai": "azure-openai",
    "bedrock": "aws-bedrock",
    "bedrock_converse": "aws-bedrock",
    "cohere": "cohere",
    "deepseek": "deepseek",
    "fireworks": "fireworks",
    "gemini": "google",
    "google": "google",
    "google_genai": "google",
    "groq": "groq",
    "huggingface": "huggingface",
    "mistral": "mistral",
    "mistralai": "mistral",
    "nvidia": "nvidia",
    "ollama": "ollama",
    "openai": "openai",
    "openai_like": "openai-compatible",
    "openrouter": "openrouter",
    "perplexity": "perplexity",
    "together": "together",
    "vertex": "google-vertex-ai",
    "vertexai": "google-vertex-ai",
    "xai": "xai",
}
# The provider a client class talks to, whichever integration package exports it.
CLASS_PROVIDERS: dict[str, str] = {
    "Anthropic": "anthropic",
    "AnthropicBedrock": "aws-bedrock",
    "AnthropicChatCompletionClient": "anthropic",
    "AnthropicModel": "anthropic",
    "AnthropicVertex": "google-vertex-ai",
    "AsyncAnthropic": "anthropic",
    "AsyncAnthropicBedrock": "aws-bedrock",
    "AsyncAzureOpenAI": "azure-openai",
    "AsyncOpenAI": "openai",
    "AzureChatCompletion": "azure-openai",
    "AzureChatOpenAI": "azure-openai",
    "AzureOpenAI": "azure-openai",
    "AzureOpenAIChatCompletionClient": "azure-openai",
    "AzureOpenAIEmbeddings": "azure-openai",
    "AzureTextEmbedding": "azure-openai",
    "BedrockChat": "aws-bedrock",
    "BedrockConverseModel": "aws-bedrock",
    "BedrockEmbeddings": "aws-bedrock",
    "BedrockLLM": "aws-bedrock",
    "BedrockModel": "aws-bedrock",
    "ChatAnthropic": "anthropic",
    "ChatAnthropicVertex": "google-vertex-ai",
    "ChatBedrock": "aws-bedrock",
    "ChatBedrockConverse": "aws-bedrock",
    "ChatCohere": "cohere",
    "ChatDeepSeek": "deepseek",
    "ChatFireworks": "fireworks",
    "ChatGoogleGenerativeAI": "google",
    "ChatGroq": "groq",
    "ChatHuggingFace": "huggingface",
    "ChatMistralAI": "mistral",
    "ChatNVIDIA": "nvidia",
    "ChatOllama": "ollama",
    "ChatOpenAI": "openai",
    "ChatPerplexity": "perplexity",
    "ChatTogether": "together",
    "ChatVertexAI": "google-vertex-ai",
    "ChatXAI": "xai",
    "CohereEmbeddings": "cohere",
    "GeminiModel": "google",
    "GoogleGenerativeAIEmbeddings": "google",
    "GoogleModel": "google",
    "GroqModel": "groq",
    "HuggingFaceEmbeddings": "huggingface",
    "HuggingFaceEndpoint": "huggingface",
    "HuggingFacePipeline": "huggingface",
    "MistralAIEmbeddings": "mistral",
    "MistralModel": "mistral",
    "OllamaEmbeddings": "ollama",
    "OllamaLLM": "ollama",
    "OpenAIChatCompletion": "openai",
    "OpenAIChatCompletionClient": "openai",
    "OpenAIChatCompletionsModel": "openai",
    "OpenAIChatModel": "openai",
    "OpenAIEmbeddings": "openai",
    "OpenAIModel": "openai",
    "OpenAIResponsesModel": "openai",
    "OpenAITextEmbedding": "openai",
    "VertexAIEmbeddings": "google-vertex-ai",
}
# Libraries that load weights by an owner/name identifier, which is never a route.
WEIGHT_ROOTS = ("huggingface_hub", "langchain_huggingface", "sentence_transformers", "transformers")
WEIGHT_CLASSES = frozenset(
    {
        "CrossEncoder",
        "FastEmbedEmbeddings",
        "HuggingFaceBgeEmbeddings",
        "HuggingFaceEmbedding",
        "HuggingFaceEmbeddings",
        "HuggingFaceEndpoint",
        "HuggingFaceLLM",
        "HuggingFacePipeline",
        "InferenceClient",
        "InferenceClientModel",
        "HfApiModel",
        "SentenceTransformer",
        "SentenceTransformerEmbeddings",
        "TransformersModel",
    }
)

# Keyword arguments that hold a model identifier in a call of an analysed file.
MODEL_KEYWORDS = (
    "model",
    "model_name",
    "model_id",
    "modelId",
    "ai_model_id",
    "deployment_name",
    "azure_deployment",
    "embedding_model",
    "embed_model",
    "llm_model",
    "chat_model",
    "repo_id",
)
EMBEDDING_KEYWORDS = frozenset({"embedding_model", "embed_model"})
# ``repo_id`` names many things; it is a model only for these loaders.
REPO_ID_CLASSES = frozenset({"HuggingFaceEndpoint", "HuggingFaceHub", "InferenceClient"})
# Calls whose model identifier is positional: (module prefix, symbol) to its index.
POSITIONAL_MODELS: dict[tuple[str, str], int] = {
    ("dspy", "LM"): 0,
    ("google.generativeai", "GenerativeModel"): 0,
    ("langchain.chat_models", "init_chat_model"): 0,
    ("langchain.embeddings", "init_embeddings"): 0,
    ("sentence_transformers", "CrossEncoder"): 0,
    ("sentence_transformers", "SentenceTransformer"): 0,
    ("vertexai", "GenerativeModel"): 0,
    ("vertexai", "TextEmbeddingModel.from_pretrained"): 0,
    ("pydantic_ai", "OpenAIModel"): 0,
    ("pydantic_ai", "OpenAIChatModel"): 0,
    ("pydantic_ai", "OpenAIResponsesModel"): 0,
    ("pydantic_ai", "AnthropicModel"): 0,
    ("pydantic_ai", "GeminiModel"): 0,
    ("pydantic_ai", "GoogleModel"): 0,
    ("pydantic_ai", "GroqModel"): 0,
    ("pydantic_ai", "MistralModel"): 0,
    ("pydantic_ai", "BedrockConverseModel"): 0,
    ("transformers", "from_pretrained"): 0,
    ("huggingface_hub", "InferenceClient"): 0,
}
ENDPOINT_KEYWORDS = (
    "base_url",
    "api_base",
    "openai_api_base",
    "azure_endpoint",
    "endpoint",
    "endpoint_url",
    "host",
    "server_url",
)
CREDENTIAL_KEYWORDS = (
    "api_key",
    "token",
    "api_token",
    "auth_token",
    "openai_api_key",
    "anthropic_api_key",
    "google_api_key",
    "azure_ad_token",
    "aws_secret_access_key",
    "hf_token",
    "huggingfacehub_api_token",
)
CLIENT_KEYWORDS = ("client", "openai_client", "async_client", "http_client", "provider")
ENVIRONMENT_READS = frozenset({"os.getenv", "os.environ.get", "decouple.config"})
CLASS_METHODS = frozenset(
    {
        "as_tool",
        "connect",
        "from_agents",
        "from_connection_string",
        "from_content",
        "from_defaults",
        "from_dict",
        "from_documents",
        "from_existing_collection",
        "from_existing_index",
        "from_function",
        "from_llm",
        "from_mcp",
        "from_model_id",
        "from_params",
        "from_path",
        "from_pretrained",
        "from_pydantic",
        "from_rail",
        "from_string",
        "from_texts",
        "from_tools",
        "from_uri",
        "load_local",
    }
)


@dataclass(frozen=True)
class AgentSpec:
    """Which arguments of an agent constructor hold what."""

    framework: str
    name: tuple[str, ...] = ("name",)
    name_position: int | None = None
    model: tuple[str, ...] = ("model",)
    model_position: int | None = None
    tools: tuple[str, ...] = ("tools",)
    tools_position: int | None = None
    agents: tuple[str, ...] = ()
    guardrails: tuple[str, ...] = ()
    memory: tuple[str, ...] = ()
    data: tuple[str, ...] = ()
    # The provider of a bare identifier the framework sends to one service by default.
    provider: str | None = None


_LANGCHAIN_FACTORY = AgentSpec(
    "langchain", name=(), model=("llm",), model_position=0, tools_position=1
)
_AUTOGEN = AgentSpec(
    "autogen", name_position=0, model=("llm_config",), tools=("tools", "functions")
)
_AGENTCHAT = AgentSpec(
    "autogen",
    name_position=0,
    model=("model_client",),
    tools=("tools", "workbench"),
    agents=("handoffs",),
    memory=("memory",),
)
_ADK = AgentSpec("google-adk", agents=("sub_agents",), provider="google")
_ADK_WORKFLOW = AgentSpec("google-adk", model=(), tools=(), agents=("sub_agents",))
_SMOLAGENTS = AgentSpec("smolagents", agents=("managed_agents",))
_LLAMA_INDEX = AgentSpec("llamaindex", model=("llm",))
_AGNO = AgentSpec("agno", agents=("team",), memory=("memory", "storage", "db"), data=("knowledge",))
_SEMANTIC_KERNEL = AgentSpec("semantic-kernel", model=("service",), tools=("plugins",))
_REACT = AgentSpec(
    "langgraph",
    model_position=0,
    tools_position=1,
    memory=("checkpointer", "store"),
)
AGENTS: dict[tuple[str, str], AgentSpec] = {
    ("agents", "Agent"): AgentSpec(
        "openai-agents",
        tools=("tools", "mcp_servers"),
        agents=("handoffs",),
        guardrails=("input_guardrails", "output_guardrails"),
        provider="openai",
    ),
    ("swarm", "Agent"): AgentSpec("openai-swarm", tools=("functions",), provider="openai"),
    ("crewai", "Agent"): AgentSpec(
        "crewai",
        name=("role",),
        model=("llm", "function_calling_llm"),
        data=("knowledge_sources",),
    ),
    ("langgraph.prebuilt", "create_react_agent"): _REACT,
    ("langchain.agents", "create_agent"): AgentSpec(
        "langchain", model_position=0, tools_position=1, memory=("checkpointer", "store")
    ),
    ("langchain.agents", "create_tool_calling_agent"): _LANGCHAIN_FACTORY,
    ("langchain.agents", "create_openai_functions_agent"): _LANGCHAIN_FACTORY,
    ("langchain.agents", "create_openai_tools_agent"): _LANGCHAIN_FACTORY,
    ("langchain.agents", "create_react_agent"): _LANGCHAIN_FACTORY,
    ("langchain.agents", "create_structured_chat_agent"): _LANGCHAIN_FACTORY,
    ("langchain.agents", "create_json_chat_agent"): _LANGCHAIN_FACTORY,
    ("langchain.agents", "create_xml_agent"): _LANGCHAIN_FACTORY,
    ("langchain.agents", "initialize_agent"): AgentSpec(
        "langchain", name=(), model=("llm",), model_position=1, tools_position=0
    ),
    ("deepagents", "create_deep_agent"): AgentSpec("deepagents", agents=("subagents",)),
    ("llama_index", "ReActAgent"): _LLAMA_INDEX,
    ("llama_index", "FunctionAgent"): _LLAMA_INDEX,
    ("llama_index", "OpenAIAgent"): _LLAMA_INDEX,
    ("llama_index", "FunctionCallingAgent"): _LLAMA_INDEX,
    ("llama_index", "CodeActAgent"): _LLAMA_INDEX,
    ("autogen", "AssistantAgent"): _AUTOGEN,
    ("autogen", "ConversableAgent"): _AUTOGEN,
    ("autogen", "UserProxyAgent"): _AUTOGEN,
    ("ag2", "AssistantAgent"): _AUTOGEN,
    ("ag2", "ConversableAgent"): _AUTOGEN,
    ("autogen_agentchat", "AssistantAgent"): _AGENTCHAT,
    ("autogen_agentchat", "CodeExecutorAgent"): _AGENTCHAT,
    ("autogen_agentchat", "SocietyOfMindAgent"): _AGENTCHAT,
    ("pydantic_ai", "Agent"): AgentSpec(
        "pydantic-ai", model_position=0, tools=("tools", "toolsets", "mcp_servers")
    ),
    ("google.adk", "Agent"): _ADK,
    ("google.adk", "LlmAgent"): _ADK,
    ("google.adk", "SequentialAgent"): _ADK_WORKFLOW,
    ("google.adk", "ParallelAgent"): _ADK_WORKFLOW,
    ("google.adk", "LoopAgent"): _ADK_WORKFLOW,
    ("smolagents", "CodeAgent"): _SMOLAGENTS,
    ("smolagents", "ToolCallingAgent"): _SMOLAGENTS,
    ("strands", "Agent"): AgentSpec("strands", provider="aws-bedrock"),
    ("agno", "Agent"): _AGNO,
    ("phi", "Agent"): _AGNO,
    ("agno", "Team"): AgentSpec("agno", agents=("members",)),
    ("semantic_kernel", "ChatCompletionAgent"): _SEMANTIC_KERNEL,
    ("semantic_kernel", "OpenAIAssistantAgent"): _SEMANTIC_KERNEL,
    ("semantic_kernel", "AzureAIAgent"): _SEMANTIC_KERNEL,
    ("semantic_kernel", "OpenAIResponsesAgent"): _SEMANTIC_KERNEL,
    ("claude_agent_sdk", "AgentDefinition"): AgentSpec(
        "claude-agent-sdk", name=(), provider="anthropic"
    ),
    ("haystack", "Agent"): AgentSpec("haystack", model=("chat_generator",)),
    ("camel", "ChatAgent"): AgentSpec("camel"),
}
# A method of a provider client that creates a hosted agent.
HOSTED_AGENT_METHODS = {
    ".beta.assistants.create": AgentSpec("openai-assistants", provider="openai"),
}

# Decorators that make a function a tool: (module prefix, symbol) to the framework.
TOOL_DECORATORS: dict[tuple[str, str], str] = {
    ("agents", "function_tool"): "openai-agents",
    ("agno", "tool"): "agno",
    ("claude_agent_sdk", "tool"): "claude-agent-sdk",
    ("crewai", "tool"): "crewai",
    ("crewai_tools", "tool"): "crewai",
    ("haystack", "tool"): "haystack",
    ("langchain", "tool"): "langchain",
    ("langchain_core", "tool"): "langchain",
    ("livekit", "function_tool"): "livekit-agents",
    ("phi", "tool"): "agno",
    ("semantic_kernel", "kernel_function"): "semantic-kernel",
    ("smolagents", "tool"): "smolagents",
    ("strands", "tool"): "strands",
}
TOOL_NAME_KEYWORDS = ("name", "name_override", "name_or_callable")
# Methods of an agent object that register the decorated function as its tool.
AGENT_TOOL_METHODS = frozenset({"tool", "tool_plain", "register_for_llm"})
# Base classes whose subclass is a tool, and the framework that defines each.
TOOL_BASES: dict[tuple[str, str], str] = {
    ("agno", "Toolkit"): "agno",
    ("autogen_core", "BaseTool"): "autogen",
    ("crewai", "BaseTool"): "crewai",
    ("crewai_tools", "BaseTool"): "crewai",
    ("google.adk", "BaseTool"): "google-adk",
    ("langchain", "BaseTool"): "langchain",
    ("langchain_core", "BaseTool"): "langchain",
    ("llama_index", "BaseTool"): "llamaindex",
    ("phi", "Toolkit"): "agno",
    ("smolagents", "Tool"): "smolagents",
}
# Calls that wrap a function as a tool: where the function and the name are.
TOOL_WRAPPERS: dict[tuple[str, str], tuple[tuple[str, ...], int | None]] = {
    ("agents", "FunctionTool"): ((), None),
    ("autogen_core", "FunctionTool"): (("func",), 0),
    ("dspy", "Tool"): (("func",), 0),
    ("google.adk", "FunctionTool"): (("func",), 0),
    ("langchain", "StructuredTool.from_function"): (("func", "coroutine"), 0),
    ("langchain", "Tool"): (("func", "coroutine"), None),
    ("langchain", "Tool.from_function"): (("func", "coroutine"), 0),
    ("langchain_core", "StructuredTool.from_function"): (("func", "coroutine"), 0),
    ("langchain_core", "Tool"): (("func", "coroutine"), None),
    ("langchain_core", "Tool.from_function"): (("func", "coroutine"), 0),
    ("llama_index", "FunctionTool.from_defaults"): (("fn", "async_fn"), 0),
    ("llama_index", "QueryEngineTool"): ((), None),
    ("llama_index", "QueryEngineTool.from_defaults"): ((), None),
    ("openai", "pydantic_function_tool"): ((), 0),
}
# Calls that present an agent as a tool or hand off to it.
AGENT_WRAPPERS: dict[tuple[str, str], tuple[str, ...]] = {
    ("agents", "handoff"): ("agent",),
    ("google.adk", "AgentTool"): ("agent",),
    ("autogen_agentchat", "AgentTool"): ("agent",),
    ("autogen_agentchat", "Handoff"): ("target",),
}
# Keyword arguments of any call in an analysed file whose value is a list of tools.
TOOL_KEYWORDS = ("tools", "functions")
# Tools a provider runs on its own side, by the name the SDK exports them under.
HOSTED_TOOLS = frozenset(
    {
        "CodeInterpreterTool",
        "ComputerTool",
        "FileSearchTool",
        "HostedMCPTool",
        "ImageGenerationTool",
        "LocalShellTool",
        "WebSearchPreviewTool",
        "WebSearchTool",
        "code_execution",
        "google_search",
        "url_context",
    }
)
TOOL_BINDERS = frozenset({"bind_tools", "bind_functions"})
TOOL_NODES = frozenset({"ToolNode", "ToolExecutor"})

# MCP server declarations in code. A call from one of these modules whose symbol is
# listed, or that receives a launch command or an endpoint, is read as a server.
MCP_ROOTS = frozenset(
    {
        "agents",
        "agno",
        "anthropic",
        "autogen_ext",
        "claude_agent_sdk",
        "claude_code_sdk",
        "crewai",
        "crewai_tools",
        "fastmcp",
        "google.adk",
        "langchain_mcp_adapters",
        "livekit",
        "llama_index",
        "mcp",
        "mcp_use",
        "mcpadapt",
        "phi",
        "pydantic_ai",
        "semantic_kernel",
        "smolagents",
        "strands",
    }
)
MCP_STDIO = frozenset(
    {
        "MCPServerStdio",
        "MCPStdioPlugin",
        "StdioConnectionParams",
        "StdioServerParameters",
        "StdioServerParams",
        "StdioTransport",
    }
)
MCP_URL = frozenset(
    {
        "BasicMCPClient",
        "MCPServerHTTP",
        "MCPServerSSE",
        "MCPServerSse",
        "MCPServerStreamableHTTP",
        "MCPServerStreamableHttp",
        "MCPSsePlugin",
        "MCPStreamableHttpPlugin",
        "SSEConnectionParams",
        "SSETransport",
        "SseConnectionParams",
        "SseServerParams",
        "StreamableHTTPConnectionParams",
        "StreamableHttpServerParams",
        "StreamableHttpTransport",
        "sse_client",
        "streamable_http_client",
        "streamablehttp_client",
    }
)
MCP_SSE = frozenset(
    {
        "MCPServerSSE",
        "MCPServerSse",
        "MCPSsePlugin",
        "SSEConnectionParams",
        "SSETransport",
        "SseConnectionParams",
        "SseServerParams",
        "sse_client",
    }
)
MCP_MAPS = frozenset({"MultiServerMCPClient", "MCPClient.from_dict"})
MCP_WRAPPERS = frozenset(
    {
        "HostedMCPTool",
        "MCPClient",
        "MCPServerAdapter",
        "MCPTools",
        "MCPToolset",
        "McpToolset",
        "McpWorkbench",
        "ToolCollection.from_mcp",
        "mcp_server_tools",
        "stdio_client",
    }
)
MCP_NESTED_KEYWORDS = (
    "params",
    "server_params",
    "connection_params",
    "tool_config",
    "server_parameters",
    "serverparams",
    "transport",
)
MCP_MAP_KEYWORDS = ("mcp_servers", "mcpServers", "connections")

# Guardrails: decorators, constructors and keyword arguments.
GUARDRAIL_DECORATORS: dict[tuple[str, str], str] = {
    ("agents", "input_guardrail"): "input-filter",
    ("agents", "output_guardrail"): "output-filter",
    ("agents", "tool_input_guardrail"): "input-filter",
    ("agents", "tool_output_guardrail"): "output-filter",
}
GUARDRAIL_WRAPPERS: dict[tuple[str, str], str] = {
    ("agents", "InputGuardrail"): "input-filter",
    ("agents", "OutputGuardrail"): "output-filter",
}
# (module prefix, symbol) to the name recorded and its type. A symbol of ``*``
# matches every class of the module, each recorded under its own name.
GUARDRAIL_CALLS: dict[tuple[str, str], tuple[str | None, str]] = {
    ("azure.ai.contentsafety", "ContentSafetyClient"): ("azure-ai-content-safety", "classifier"),
    ("guardrails", "Guard"): ("guardrails-ai", "validator"),
    ("guardrails.hub", "*"): (None, "validator"),
    ("langchain.agents.middleware", "HumanInTheLoopMiddleware"): (None, "human-approval"),
    ("langchain.agents.middleware", "PIIMiddleware"): (None, "input-filter"),
    ("langchain_community", "HumanApprovalCallbackHandler"): (None, "human-approval"),
    ("langchain_core.rate_limiters", "InMemoryRateLimiter"): (None, "rate-limiter"),
    ("llm_guard.input_scanners", "*"): (None, "input-filter"),
    ("llm_guard.output_scanners", "*"): (None, "output-filter"),
    ("nemoguardrails", "LLMRails"): ("nemo-guardrails", "policy"),
    ("nemoguardrails", "RailsConfig"): ("nemo-guardrails", "policy"),
    ("presidio_analyzer", "AnalyzerEngine"): ("presidio-analyzer", "input-filter"),
    ("presidio_anonymizer", "AnonymizerEngine"): ("presidio-anonymizer", "output-filter"),
}
# Keyword arguments that put a person or a policy in front of an action.
APPROVAL_KEYWORDS: dict[str, tuple[str, frozenset[object] | None]] = {
    "interrupt_before": ("human-approval", None),
    "interrupt_after": ("human-approval", None),
    "human_input": ("human-approval", frozenset({True})),
    "human_input_mode": ("human-approval", frozenset({"ALWAYS", "TERMINATE"})),
}
# Settings of a coding-agent SDK's options object that restrict what the agent may do.
OPTION_CONTROLS: dict[tuple[str, str], tuple[tuple[str, str], ...]] = {
    ("claude_agent_sdk", "ClaudeAgentOptions"): (
        ("permission_mode", "policy"),
        ("disallowed_tools", "policy"),
        ("can_use_tool", "human-approval"),
        ("hooks", "policy"),
    ),
    ("claude_code_sdk", "ClaudeCodeOptions"): (
        ("permission_mode", "policy"),
        ("disallowed_tools", "policy"),
        ("can_use_tool", "human-approval"),
        ("hooks", "policy"),
    ),
}
BEDROCK_GUARDRAIL_KEYS = ("guardrailIdentifier", "guardrail_identifier", "guardrail_id")
BEDROCK_GUARDRAIL_VERSIONS = ("guardrailVersion", "guardrail_version")

# Retrieval stores: the class or function to the store it is.
VECTOR_STORES: dict[str, str] = {
    "Annoy": "annoy",
    "AstraDBVectorStore": "astra-db",
    "AzureAISearchVectorStore": "azure-ai-search",
    "AzureSearch": "azure-ai-search",
    "Cassandra": "cassandra",
    "Chroma": "chroma",
    "ChromaVectorStore": "chroma",
    "CouchbaseVectorStore": "couchbase",
    "DeepLake": "deeplake",
    "ElasticsearchStore": "elasticsearch",
    "FAISS": "faiss",
    "FaissVectorStore": "faiss",
    "InMemoryVectorStore": "in-memory",
    "LanceDB": "lancedb",
    "LanceDBVectorStore": "lancedb",
    "Milvus": "milvus",
    "MilvusVectorStore": "milvus",
    "MongoDBAtlasVectorSearch": "mongodb-atlas",
    "Neo4jVector": "neo4j",
    "OpenSearchVectorSearch": "opensearch",
    "PGVector": "pgvector",
    "PGVectorStore": "pgvector",
    "PineconeVectorStore": "pinecone",
    "Qdrant": "qdrant",
    "QdrantVectorStore": "qdrant",
    "RedisVectorStore": "redis",
    "SupabaseVectorStore": "supabase",
    "UpstashVectorStore": "upstash",
    "WeaviateVectorStore": "weaviate",
}
STORE_IDENTITY_KEYWORDS = (
    "collection_name",
    "index_name",
    "collection",
    "table_name",
    "namespace",
    "class_name",
)
# Methods that open a named collection or index on a store client, by client module.
STORE_METHODS: dict[tuple[str, str], str] = {
    ("chromadb", "create_collection"): "chroma",
    ("chromadb", "get_collection"): "chroma",
    ("chromadb", "get_or_create_collection"): "chroma",
    ("lancedb", "create_table"): "lancedb",
    ("lancedb", "open_table"): "lancedb",
    ("pinecone", "Index"): "pinecone",
}
EMBEDDING_ARGUMENTS = ("embedding", "embeddings", "embedding_function", "embed_model")
MEMORY_STORES: dict[str, str] = {
    "AsyncPostgresSaver": "conversation",
    "AsyncSqliteSaver": "conversation",
    "ChatMemoryBuffer": "conversation",
    "ChatMessageHistory": "conversation",
    "ChatSummaryMemoryBuffer": "conversation",
    "ChromaDBVectorMemory": "semantic",
    "ConversationBufferMemory": "conversation",
    "ConversationBufferWindowMemory": "conversation",
    "ConversationEntityMemory": "semantic",
    "ConversationKGMemory": "semantic",
    "ConversationSummaryBufferMemory": "conversation",
    "ConversationSummaryMemory": "conversation",
    "ConversationTokenBufferMemory": "conversation",
    "DatabaseSessionService": "conversation",
    "DynamoDBChatMessageHistory": "conversation",
    "EntityMemory": "semantic",
    "FileChatMessageHistory": "conversation",
    "InMemoryChatMessageHistory": "conversation",
    "InMemoryMemoryService": "semantic",
    "InMemorySaver": "conversation",
    "InMemorySessionService": "conversation",
    "InMemoryStore": "semantic",
    "ListMemory": "conversation",
    "LongTermMemory": "semantic",
    "Mem0Memory": "semantic",
    "MemoryClient": "semantic",
    "MemorySaver": "conversation",
    "MongoDBChatMessageHistory": "conversation",
    "MongoDBSaver": "conversation",
    "OpenAIConversationsSession": "conversation",
    "PostgresChatMessageHistory": "conversation",
    "PostgresDb": "conversation",
    "PostgresSaver": "conversation",
    "PostgresStorage": "conversation",
    "PostgresStore": "semantic",
    "RedisChatMessageHistory": "conversation",
    "RedisSaver": "conversation",
    "SQLAlchemySession": "conversation",
    "SQLChatMessageHistory": "conversation",
    "SQLiteSession": "conversation",
    "ShortTermMemory": "conversation",
    "SqliteDb": "conversation",
    "SqliteSaver": "conversation",
    "SqliteStorage": "conversation",
    "VectorMemory": "semantic",
    "VectorStoreRetrieverMemory": "semantic",
    "VertexAiMemoryBankService": "semantic",
    "VertexAiRagMemoryService": "semantic",
    "VertexAiSessionService": "conversation",
    "ZepChatMessageHistory": "conversation",
}
# Memory classes whose name alone is too common to recognise without their module.
MEMORY_BY_MODULE: dict[tuple[str, str], str] = {
    ("mem0", "AsyncMemory"): "semantic",
    ("mem0", "Memory"): "semantic",
    ("agno", "Memory"): "semantic",
    ("zep_cloud", "AsyncZep"): "semantic",
    ("zep_cloud", "Zep"): "semantic",
}
DATASET_LOADERS: dict[tuple[str, str], int] = {("datasets", "load_dataset"): 0}
DOCUMENT_LOADERS: dict[tuple[str, str], tuple[str, ...]] = {
    ("llama_index", "SimpleDirectoryReader"): ("input_dir",),
}
DOCUMENT_LOADER_SUFFIXES = ("Loader", "KnowledgeSource")
DOCUMENT_LOADER_ROOTS = ("langchain_community", "langchain", "crewai")
DOCUMENT_PATH_KEYWORDS = ("file_path", "path", "web_path", "file_paths", "url", "urls")

CLI_MODEL_OPTIONS = frozenset({"--model", "--model-name", "--model-id", "--llm", "--llm-model"})
MODEL_CONSTANT = (
    r"^(?:[a-z0-9_]*_)?(?:model|llm|deployment)(?:_(?:name|id|alias))?$|"
    r"^(?:model|llm)_[a-z0-9_]+$"
)
MODEL_DICT_KEYS = frozenset({"model", "model_name", "model_id", "modelId", "deployment_name"})
SETTINGS_BASES = frozenset({"BaseSettings"})
