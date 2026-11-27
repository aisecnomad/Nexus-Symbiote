"""What the Python source reader recognises: SDK modules, constructors and keywords.

These are tables, not behaviour. A row says which modules make a file one the reader
analyses and which arguments of a call hold a model identifier. A project module that
shadows one of these module names is never read as the SDK.
"""

from __future__ import annotations

import re

# Top-level modules whose import makes a file one the reader analyses.
AI_ROOTS = frozenset(
    {
        "ag2", "agents", "agno", "anthropic", "autogen", "autogen_agentchat", "autogen_core",
        "autogen_ext", "boto3", "camel", "chromadb", "claude_agent_sdk", "claude_code_sdk",
        "cohere", "crewai", "crewai_tools", "datasets", "deepagents", "dspy", "faiss", "fireworks",
        "google", "groq", "guardrails", "haystack", "haystack_integrations", "huggingface_hub",
        "instructor", "lancedb", "langchain", "langchain_anthropic", "langchain_aws",
        "langchain_chroma", "langchain_cohere", "langchain_community", "langchain_core",
        "langchain_deepseek", "langchain_experimental", "langchain_fireworks",
        "langchain_google_genai", "langchain_google_vertexai", "langchain_groq",
        "langchain_huggingface", "langchain_mcp_adapters", "langchain_milvus",
        "langchain_mistralai", "langchain_nvidia_ai_endpoints", "langchain_ollama",
        "langchain_openai", "langchain_perplexity", "langchain_pinecone", "langchain_postgres",
        "langchain_qdrant", "langchain_tavily", "langchain_together", "langchain_weaviate",
        "langchain_xai", "langgraph", "litellm", "livekit", "llama_cpp", "llama_index", "llm_guard",
        "mcp", "mcp_use", "mem0", "mistralai", "nemoguardrails", "ollama", "openai", "phi",
        "pinecone", "presidio_analyzer", "pydantic_ai", "pymilvus", "qdrant_client", "replicate",
        "semantic_kernel", "sentence_transformers", "smolagents", "strands", "strands_tools",
        "swarm", "together", "transformers", "vertexai", "voyageai", "weaviate", "zep_cloud",
    }
)  # fmt: skip
# ``google`` holds much besides AI clients: only these parts of it count.
AI_SUBMODULES = {
    "google": ("google.adk", "google.genai", "google.generativeai", "google.cloud.aiplatform"),
}
# An import statement that may name one of the roots, tested before a file is parsed: a
# word that only appears in text, such as ``graphics`` or ``camelCase``, is no import.
_ROOT_WORDS = b"|".join(sorted(re.escape(name).encode() for name in AI_ROOTS - {"google"}))
SDK_IMPORT = re.compile(
    rb"(?m)^(?:\xef\xbb\xbf)?[ \t]*(?:from[ \t]+|import[ \t]+(?:[\w.]+(?:[ \t]+as[ \t]+\w+)?"
    rb"[ \t]*,[ \t]*)*)(?:(?:" + _ROOT_WORDS + rb")\b(?![\w])"
    rb"|google(?:\.(?:adk|genai|generativeai|cloud\.aiplatform)\b|[ \t]+import\b))"
)
# Libraries that load weights by an owner/name identifier, which is never a route.
WEIGHT_ROOTS = ("huggingface_hub", "langchain_huggingface", "sentence_transformers", "transformers")
WEIGHT_CLASSES = frozenset(
    {
        "CrossEncoder", "FastEmbedEmbeddings", "HfApiModel", "HuggingFaceBgeEmbeddings",
        "HuggingFaceEmbedding", "HuggingFaceEmbeddings", "HuggingFaceEndpoint", "HuggingFaceLLM",
        "HuggingFacePipeline", "InferenceClient", "InferenceClientModel", "SentenceTransformer",
        "SentenceTransformerEmbeddings", "TransformersModel",
    }
)  # fmt: skip
# Keyword arguments that hold a model identifier in a call into an SDK.
MODEL_KEYWORDS = (
    "model", "model_name", "model_id", "modelId", "ai_model_id", "deployment_name",
    "azure_deployment", "embedding_model", "embed_model", "llm_model", "chat_model", "llm",
    "repo_id",
)  # fmt: skip
EMBEDDING_KEYWORDS = frozenset({"embedding_model", "embed_model"})
# ``repo_id`` names many things; it is a model only for these loaders.
REPO_ID_CLASSES = frozenset({"HuggingFaceEndpoint", "HuggingFaceHub", "InferenceClient"})
# Calls whose model identifier is positional: (module prefix, symbol) to its index.
POSITIONAL_MODELS: dict[tuple[str, str], int] = {
    ("dspy", "LM"): 0, ("google.generativeai", "GenerativeModel"): 0,
    ("huggingface_hub", "InferenceClient"): 0, ("langchain.chat_models", "init_chat_model"): 0,
    ("langchain.embeddings", "init_embeddings"): 0, ("litellm", "acompletion"): 0,
    ("litellm", "aembedding"): 0, ("litellm", "completion"): 0, ("litellm", "embedding"): 0,
    ("ollama", "chat"): 0, ("ollama", "embed"): 0, ("ollama", "generate"): 0,
    ("pydantic_ai", "Agent"): 0, ("pydantic_ai", "AnthropicModel"): 0,
    ("pydantic_ai", "BedrockConverseModel"): 0, ("pydantic_ai", "GeminiModel"): 0,
    ("pydantic_ai", "GoogleModel"): 0, ("pydantic_ai", "GroqModel"): 0,
    ("pydantic_ai", "MistralModel"): 0, ("pydantic_ai", "OpenAIChatModel"): 0,
    ("pydantic_ai", "OpenAIModel"): 0, ("pydantic_ai", "OpenAIResponsesModel"): 0,
    ("sentence_transformers", "CrossEncoder"): 0,
    ("sentence_transformers", "SentenceTransformer"): 0, ("transformers", "from_pretrained"): 0,
    ("vertexai", "GenerativeModel"): 0, ("vertexai", "TextEmbeddingModel.from_pretrained"): 0,
}  # fmt: skip
ENVIRONMENT_READS = frozenset({"os.getenv", "os.environ.get", "decouple.config"})
# Calls whose text is their default: whether the first positional argument is it too.
TEXT_DEFAULTS = {
    "builtins.str": True,
    "dataclasses.field": False,
    "pydantic.Field": True,
    "pydantic.fields.Field": True,
}
# Calls that call their first argument with the rest, so its keywords are that callee's.
FORWARDERS = frozenset(
    {
        "asyncio.to_thread",
        "concurrent.futures.ProcessPoolExecutor().submit",
        "concurrent.futures.ThreadPoolExecutor().submit",
        "fastapi.concurrency.run_in_threadpool",
        "functools.partial",
        "starlette.concurrency.run_in_threadpool",
    }
)
# Class methods that construct what the class names, so ``X.from_pretrained`` is ``X``.
CLASS_METHODS = frozenset({"from_defaults", "from_model_id", "from_pretrained"})
