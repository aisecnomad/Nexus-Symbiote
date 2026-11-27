"""What the Python source reader recognises: SDK modules, calls and keywords. These are
tables, not behaviour; a project module that shadows one of these names is never the SDK.
"""

from __future__ import annotations

import re

# Top-level modules whose import makes a file one the reader analyses.
AI_ROOTS = frozenset(
    {
        "ag2", "agents", "agno", "anthropic", "autogen", "autogen_agentchat", "autogen_core",
        "autogen_ext", "boto3", "camel", "chromadb", "claude_agent_sdk", "claude_code_sdk",
        "cohere", "crewai", "crewai_tools", "datasets", "deepagents", "diffusers", "dspy", "faiss",
        "fireworks",
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
        "peft", "pinecone", "presidio_analyzer", "pydantic_ai", "pymilvus", "qdrant_client",
        "replicate",
        "semantic_kernel", "sentence_transformers", "smolagents", "strands", "strands_tools",
        "swarm", "together", "transformers", "vertexai", "vllm", "voyageai", "weaviate", "zep_cloud",
    }
)  # fmt: skip
# ``google`` holds much besides AI clients: only these parts of it count.
AI_SUBMODULES = {
    "google": ("google.adk", "google.genai", "google.generativeai", "google.cloud.aiplatform"),
}
# An import statement that may name one of the roots, searched for in the text Python
# compiles, before a file is parsed. Python ends a statement at any newline, at ``;`` and
# after ``try:`` or ``if ...:``, never at a form feed, and joins lines a backslash ends; a
# word not in an import statement, such as ``graphics`` or one in a string, names none.
_GAP = r"(?:[ \t\f]|\\(?:\r\n?|\n))"
# A name earlier in an import list may hold any character an identifier may, such as a
# combining mark, so it runs to the next separator, and its dots may have gaps around them.
_DOT = rf"{_GAP}*\.{_GAP}*"
_NAME = rf"[^\s,;:\\#().]+(?:{_DOT}[^\s,;:\\#().]+)*"
_ROOT_NAMES = "|".join(sorted(map(re.escape, AI_ROOTS - {"google"})))
SDK_IMPORT = re.compile(
    rf"(?:\A|[\r\n;:])[ \t\f]*(?:from|import)(?!\w){_GAP}*(?:{_NAME}(?:{_GAP}+as{_GAP}+{_NAME})?"
    rf"{_GAP}*,{_GAP}*)*(?:(?:{_ROOT_NAMES})(?!\w)|google(?:{_DOT}cloud)?"
    rf"(?:{_DOT}(?:adk|genai|generativeai|aiplatform)(?!\w)|{_GAP}+import(?!\w)))"
)
# A root's name alone, searched for in text Python folds a slice at a time, where a
# statement may span slices: any such word admits the file, and the tree decides.
SDK_WORD = re.compile(r"(?<![\w.])(?:" + "|".join(sorted(map(re.escape, AI_ROOTS))) + r")(?!\w)")
# Names along a callee that SDK calls use: of an object the reader cannot tell, a call
# reached through one of them is read.
MODEL_CALLS = frozenset(
    {
        "__init__", "abatch", "achat", "acomplete", "acompletion", "acreate", "aembed",
        "aembedding", "agenerate", "ainvoke", "apredict", "arun", "astream", "batch", "chat",
        "chat_completion", "complete", "completion", "completions", "converse",
        "converse_stream", "create", "embed", "embed_content", "embed_documents", "embed_query",
        "embedding", "embeddings", "generate", "generate_content", "generate_images", "images",
        "invoke", "invoke_model", "messages", "models", "predict", "rerank", "responses", "run",
        "run_stream", "run_sync", "stream", "stream_chat", "stream_complete", "text_generation",
        "transcriptions", "with_options", "with_structured_output",
    }
)  # fmt: skip
# Calls that route by a prefix on the identifier, as LiteLLM reads ``anthropic/``, to the
# separators they read it by. A native owner/name, as Replicate and model hubs read it, an
# OpenAI-compatible gateway's names and a model class given its provider are no routes.
ROUTERS: dict[tuple[str, str], str] = {
    ("crewai", "Agent"): "/", ("crewai", "Crew"): "/", ("crewai", "LLM"): "/",
    ("dspy", "Embedder"): "/", ("dspy", "LM"): "/", ("litellm", "*"): "/",
    ("smolagents", "LiteLLMModel"): "/", ("smolagents", "LiteLLMRouterModel"): "/",
    ("langchain.chat_models", "init_chat_model"): ":",
    ("langchain.embeddings", "init_embeddings"): ":",
    ("pydantic_ai", "Agent"): ":", ("pydantic_ai", "infer_model"): ":",
}  # fmt: skip
# Libraries that load weights by an owner/name identifier, which is never a route.
WEIGHT_ROOTS = (
    "diffusers", "huggingface_hub", "langchain_huggingface", "llama_cpp", "peft",
    "sentence_transformers", "transformers", "vllm",
)  # fmt: skip
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
    "repo_id", "model_name_or_path", "pretrained_model_name_or_path", "manager_llm",
    "function_calling_llm", "planning_llm", "model_list", "fallbacks",
)  # fmt: skip
EMBEDDING_KEYWORDS = frozenset({"embedding_model", "embed_model"})
# ``repo_id`` names many things; it is a model only for these loaders.
REPO_ID_CLASSES = frozenset({"HuggingFaceEndpoint", "HuggingFaceHub", "InferenceClient", "Llama"})
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
    ("replicate", "run"): 0, ("diffusers", "from_pretrained"): 0, ("vllm", "LLM"): 0,
    ("peft", "PeftModel.from_pretrained"): 1, ("peft", "from_pretrained"): 0,
}  # fmt: skip
# Calls that give text or a path rather than an object an SDK makes: SDK helpers, str's
# methods and a type of model names. Neither does an SDK's ``types``, which hold its data.
TEXT_CALLS = frozenset({
    *dir(str), "KnownModelName", "cached_file", "get", "get_from_dict_or_env", "get_from_env",
    "get_secret", "hf_hub_download", "hf_hub_url", "snapshot_download", "try_to_load_from_cache",
})  # fmt: skip
# Calls that read an environment variable: its name first, then its default.
ENVIRONMENT_READS = frozenset({"decouple.config", "os.environ.get", "os.getenv"})
# Calls that call their first argument with the rest, so its keywords are that callee's.
FORWARDERS = frozenset(
    {
        "asyncio.to_thread",
        "concurrent.futures.Executor().submit",
        "concurrent.futures.ProcessPoolExecutor().submit",
        "concurrent.futures.ThreadPoolExecutor().submit",
        "fastapi.concurrency.run_in_threadpool",
        "functools.partial",
        "starlette.concurrency.run_in_threadpool",
    }
)
# Class methods that construct what the class names, so ``X.from_pretrained`` is ``X``.
CLASS_METHODS = frozenset({"from_defaults", "from_model_id", "from_pretrained"})
