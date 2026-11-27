"""Read what Go, Java, Kotlin, C# and Rust source declares, as text.

There is no parser for these languages here. A file is split into code, comments and
string literals, so that nothing is read out of a comment and a string is never
mistaken for code, and a small set of patterns is matched against the code with the
strings held apart. The patterns are the documented call shapes of the AI SDKs of
each language. They follow no names: an identifier held in a constant of another
file, or in an SDK's own enumeration, is not read.

Because a pattern is weaker evidence than a syntax tree, a model identifier is
recorded only when it belongs to a known model family, and only in a file that
names one of the SDKs.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.scanners.source_references import (
    AgentRecord,
    Declarations,
    declared_name,
    environment_name,
)

METHOD = "source-pattern"
CLIKE_SUFFIXES = frozenset({".go", ".java", ".kt", ".cs", ".rs"})
MAX_MATCHES = 2_000
MAX_SPAN = 2_000
# What an import of an AI SDK looks like in each language, and the provider it names.
SDK_MARKERS: dict[str, str | None] = {
    "Amazon.BedrockRuntime": "aws-bedrock",
    "Anthropic.SDK": "anthropic",
    "Azure.AI.OpenAI": "azure-openai",
    "Microsoft.Agents.AI": None,
    "Microsoft.Extensions.AI": None,
    "Microsoft.SemanticKernel": None,
    "ModelContextProtocol": None,
    "OllamaSharp": "ollama",
    "async_openai": "openai",
    "com.anthropic": "anthropic",
    "com.azure.ai.openai": "azure-openai",
    "com.google.adk": "google",
    "com.google.genai": "google",
    "com.microsoft.semantickernel": None,
    "com.openai": "openai",
    "dev.langchain4j": None,
    "github.com/anthropics/anthropic-sdk-go": "anthropic",
    "github.com/aws/aws-sdk-go-v2/service/bedrockruntime": "aws-bedrock",
    "github.com/cloudwego/eino": None,
    "github.com/firebase/genkit": None,
    "github.com/google/generative-ai-go": "google",
    "github.com/mark3labs/mcp-go": None,
    "github.com/modelcontextprotocol/go-sdk": None,
    "github.com/ollama/ollama/api": "ollama",
    "github.com/openai/openai-go": "openai",
    "github.com/sashabaranov/go-openai": "openai",
    "github.com/tmc/langchaingo": None,
    "google.golang.org/adk": "google",
    "google.golang.org/genai": "google",
    "io.modelcontextprotocol": None,
    "langchain_rust": None,
    "ollama_rs": "ollama",
    "org.springframework.ai": None,
    "rig::": None,
    "rmcp::": None,
    "software.amazon.awssdk.services.bedrockruntime": "aws-bedrock",
    "using OpenAI": "openai",
}
CLIKE_MARKERS = tuple(sorted(marker.encode() for marker in SDK_MARKERS))
_STRING = r"\x01(\d+)\x02"
_CLASS_PROVIDERS = {
    "azureopenai": "azure-openai",
    "openai": "openai",
    "anthropic": "anthropic",
    "ollama": "ollama",
    "bedrock": "aws-bedrock",
    "vertexai": "google-vertex-ai",
    "gemini": "google",
    "mistralai": "mistral",
}
# The longest name first, so that ``AzureOpenAI`` is not read as ``OpenAI``.
_CLASS_PROVIDER = re.compile(
    "|".join(sorted(_CLASS_PROVIDERS, key=len, reverse=True)), re.IGNORECASE
)
_KEYED_MODEL = re.compile(
    r"\b(?:with)?(?:chat|embedding|default)?_?(?:model|deployment)(?:_?(?:name|id))?\b"
    r"\s*(?::=|[:=(,])\s*" + _STRING,
    re.IGNORECASE,
)
_NAMED_MODEL = re.compile(r"\b\w*(?:model|llm)\w*\s*(?::=|=)\s*" + _STRING, re.IGNORECASE)
_POSITIONAL_MODEL = re.compile(
    r"\b(?:AddAzureOpenAIChatCompletion|AddOllamaChatCompletion|AddOpenAIChatCompletion|"
    r"AddOpenAITextEmbeddingGeneration|AsChatClient|ChatClient|GenerativeModel|"
    r"GetChatClient|GetEmbeddingClient|agent|completion_model|embedding_model)\s*\(\s*" + _STRING
)
_ENVIRONMENT = re.compile(
    r"\b(?:os\.Getenv|os\.LookupEnv|System\.getenv|Environment\.GetEnvironmentVariable|"
    r"env::var|getenv|getEnv|GetEnv)\s*\(\s*" + _STRING + r"(?:\s*,\s*" + _STRING + r")?"
)
_FALLBACK = re.compile(r"\)\s*(?:\?\?|\.unwrap_or\(|\.getOrDefault\(|\?:)\s*" + _STRING)
_GO_SCHEMA = re.compile(r"\b(?:FunctionDefinition(?:Param)?|ToolParam|FunctionDeclaration)\s*\{")
_NAME_FIELD = re.compile(r"\bName\s*[:=]\s*" + _STRING)
_NAME_CALL = re.compile(r"\.\s*name\s*\(\s*" + _STRING)
_NAME_ARGUMENT = re.compile(r"\bname\s*:\s*" + _STRING)
_CS_FUNCTION_TOOL = re.compile(r"\bCreateFunctionTool\s*\(\s*(?:functionName\s*:\s*)?" + _STRING)
_JAVA_TOOL = re.compile(
    r"@Tool\b\s*(\((?:[^()]|\([^()]*\))*\))?\s*"
    r"(?:(?:public|private|protected|static|final|suspend|fun)\s+)*"
    r"(?:[\w<>\[\],.?]+\s+)?(\w+)\s*\("
)
_CS_KERNEL_FUNCTION = re.compile(
    r"\[\s*KernelFunction\b\s*(?:\(\s*(?:" + _STRING + r")?\s*\))?[^\]]*\]"
    r"(?:\s*\[[^\]]*\])*\s*"
    r"(?:(?:public|private|internal|protected|static|async|virtual|override)\s+)*"
    r"[\w<>\[\],.?]+\s+(\w+)\s*\("
)
_AGENTS: tuple[tuple[re.Pattern[str], re.Pattern[str], str], ...] = (
    (re.compile(r"\bLlmAgent\s*\.\s*builder\s*\("), _NAME_CALL, "google-adk"),
    (re.compile(r"\bllmagent\.Config\s*\{"), _NAME_FIELD, "google-adk"),
    (re.compile(r"\bChatCompletionAgent\b[^;{}]{0,80}\{"), _NAME_FIELD, "semantic-kernel"),
    (re.compile(r"\bCreateAIAgent\s*\("), _NAME_ARGUMENT, "microsoft-agent-framework"),
)
_STDIO_SERVERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bStdioClientTransportOptions\b\s*(?:\(\s*\))?\s*\{"), "options"),
    (re.compile(r"\bServerParameters\s*\.\s*builder\s*\(\s*" + _STRING), "builder"),
    (re.compile(r"\bNewStdioMCPClient\s*\(\s*" + _STRING), "call"),
)
_URL_SERVERS = re.compile(
    r"\b(?:HttpClientSseClientTransport|HttpClientStreamableHttpTransport|NewSSEMCPClient|"
    r"NewStreamableHttpClient|SseClientTransportOptions|HttpClientTransportOptions)\b"
)
_COMMAND_FIELD = re.compile(r"\bCommand\s*=\s*" + _STRING)
_ARGUMENTS = re.compile(
    r"\b(?:Arguments\s*=|\.\s*args\s*\()\s*[\[({]?\s*((?:" + _STRING + r"\s*,?\s*)+)"
)
_ANY_STRING = re.compile(_STRING)
_MODEL_VARIABLE = re.compile(r"(?:MODEL|LLM|DEPLOYMENT)")


@dataclass
class _Source:
    """A file split into code and strings: ``code`` holds a numbered mark for each string."""

    code: str
    strings: list[str]
    lines: list[int]

    def line(self, position: int) -> int:
        return bisect.bisect_right(self.lines, position)

    def text(self, index: str | None) -> str | None:
        return None if index is None else self.strings[int(index)]


def split_source(text: str, suffix: str) -> _Source:
    """Blank the comments of ``text`` and lift its string literals out of the code."""
    out: list[str] = []
    strings: list[str] = []
    position, size = 0, len(text)
    raw_quote = "`" if suffix == ".go" else None
    while position < size:
        char = text[position]
        pair = text[position : position + 2]
        if pair == "//":
            end = text.find("\n", position)
            end = size if end < 0 else end
            position = end
        elif pair == "/*":
            end = text.find("*/", position + 2)
            end = size if end < 0 else end + 2
            out.append("\n" * text.count("\n", position, end))
            position = end
        elif char == '"' or char == raw_quote:
            triple = text[position : position + 3] == '"""'
            verbatim = char == raw_quote or (
                suffix == ".cs" and position and text[position - 1] == "@"
            )
            close = '"""' if triple else char
            start = position + len(close)
            end = start
            while end < size:
                if text.startswith(close, end):
                    break
                if text[end] == "\\" and not verbatim and not triple:
                    end += 1
                elif text[end] == "\n" and not (triple or verbatim):
                    break
                end += 1
            literal = text[start:end]
            out.append(f"\x01{len(strings)}\x02")
            out.append("\n" * literal.count("\n"))
            strings.append(literal)
            position = min(size, end + len(close))
        elif char == "'" and suffix != ".rs":
            # A character literal ends on its own line; an unclosed quote is one character.
            end = position + 1
            while end < size and text[end] not in "'\n":
                end += 2 if text[end] == "\\" and text[end + 1 : end + 2] != "\n" else 1
            closed = end < size and text[end] == "'"
            position = end + 1 if closed else position + 1
            out.append("' '")
        else:
            out.append(char)
            position += 1
    code = "".join(out)
    starts = [0]
    starts.extend(index + 1 for index, char in enumerate(code) if char == "\n")
    return _Source(code, strings, starts)


def _span(code: str, start: int) -> int:
    """Where the statement or literal that begins at ``start`` ends, within a bound."""
    depth = 0
    limit = min(len(code), start + MAX_SPAN)
    for position in range(start, limit):
        char = code[position]
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
            if depth < 0:
                return position
        elif (
            char == ";"
            and depth <= 0
            or char == "\n"
            and depth <= 0
            and code[position + 1 : position + 2] == "\n"
        ):
            return position
    return limit


class ClikeReader:
    """Reads one Go, Java, Kotlin, C# or Rust file at a time into a ``Declarations``."""

    def __init__(self, declarations: Declarations) -> None:
        self._found = declarations

    def read(self, path: str, content: bytes) -> None:
        if not any(marker in content for marker in CLIKE_MARKERS):
            return
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return
        suffix = PurePosixPath(path).suffix.lower()
        source = split_source(text, suffix)
        digest = hash_bytes(content)
        named = {
            provider
            for marker, provider in SDK_MARKERS.items()
            if provider is not None and marker in text
        }
        provider = named.pop() if len(named) == 1 else None
        models: list[tuple[int, str]] = []
        self._models(path, source, provider, models)
        self._credentials(path, source, provider, models)
        self._tools(path, source, digest)
        self._servers(path, source)
        self._agents(path, source, digest, models)

    def _provider(self, source: _Source, position: int, default: str | None) -> str | None:
        window = source.code[max(0, position - 240) : position]
        named = [match.group(0).lower() for match in _CLASS_PROVIDER.finditer(window)]
        return _CLASS_PROVIDERS[named[-1]] if named else default

    def _model(
        self,
        path: str,
        source: _Source,
        position: int,
        literal: str | None,
        provider: str | None,
        models: list[tuple[int, str]],
        *,
        environment: str | None = None,
    ) -> None:
        if literal is None:
            return
        ref = self._found.model(
            literal,
            path,
            source.line(position),
            method=METHOD,
            provider=self._provider(source, position, provider),
            environment=environment,
            embedding="mbedding" in source.code[max(0, position - 60) : position],
            require_family=True,
        )
        if ref is not None:
            models.append((position, ref))

    def _models(
        self, path: str, source: _Source, provider: str | None, models: list[tuple[int, str]]
    ) -> None:
        seen: set[int] = set()
        for pattern in (_KEYED_MODEL, _POSITIONAL_MODEL, _NAMED_MODEL):
            for count, match in enumerate(pattern.finditer(source.code)):
                if count >= MAX_MATCHES:
                    break
                index = int(match.group(1))
                if index not in seen:
                    seen.add(index)
                    self._model(
                        path, source, match.start(1), source.strings[index], provider, models
                    )

    def _credentials(
        self, path: str, source: _Source, provider: str | None, models: list[tuple[int, str]]
    ) -> None:
        for count, match in enumerate(_ENVIRONMENT.finditer(source.code)):
            if count >= MAX_MATCHES:
                break
            name = environment_name(source.text(match.group(1)))
            if name is None:
                continue
            self._found.credential(name, path, source.line(match.start()))
            default = source.text(match.group(2))
            if default is None:
                fallback = _FALLBACK.match(source.code, match.end())
                default = source.text(fallback.group(1)) if fallback else None
            if default is not None and _MODEL_VARIABLE.search(name.upper()):
                self._model(
                    path, source, match.start(), default, provider, models, environment=name
                )

    def _tools(self, path: str, source: _Source, digest: str) -> None:
        def record(position: int, name: str | None, kind: str) -> None:
            accepted = declared_name(name)
            if accepted is not None:
                self._found.tool(
                    path, source.line(position), accepted, method=METHOD, digest=digest, kind=kind
                )

        for match in _GO_SCHEMA.finditer(source.code):
            end = _span(source.code, match.end())
            name = _NAME_FIELD.search(source.code, match.end(), end)
            if name is not None:
                record(match.start(), source.text(name.group(1)), "schema")
        for match in _CS_FUNCTION_TOOL.finditer(source.code):
            record(match.start(), source.text(match.group(1)), "schema")
        for match in _JAVA_TOOL.finditer(source.code):
            options = match.group(1) or ""
            named = re.search(r"\bname\s*=\s*" + _STRING, options)
            record(
                match.start(),
                source.text(named.group(1)) if named else match.group(2),
                "function",
            )
        for match in _CS_KERNEL_FUNCTION.finditer(source.code):
            record(match.start(), source.text(match.group(1)) or match.group(2), "function")

    def _servers(self, path: str, source: _Source) -> None:
        for pattern, shape in _STDIO_SERVERS:
            for match in pattern.finditer(source.code):
                end = _span(source.code, match.end())
                body = source.code[match.end() : end]
                config: dict[str, object] = {}
                if shape == "options":
                    command = _COMMAND_FIELD.search(body)
                    name = _NAME_FIELD.search(body)
                    if command is not None:
                        config["command"] = source.strings[int(command.group(1))]
                    if name is not None:
                        config["name"] = source.strings[int(name.group(1))]
                else:
                    config["command"] = source.strings[int(match.group(1))]
                listed = _ARGUMENTS.search(body)
                arguments = listed.group(1) if listed else (body if shape == "call" else "")
                config["args"] = [
                    source.strings[int(index)] for index in _ANY_STRING.findall(arguments)
                ][:64]
                if config.get("command"):
                    self._found.declare_server(
                        path, source.line(match.start()), config, binding=None, method=METHOD
                    )
        for match in _URL_SERVERS.finditer(source.code):
            end = _span(source.code, match.end())
            body = source.code[match.end() : end]
            name = _NAME_FIELD.search(body)
            for index in _ANY_STRING.findall(body):
                literal = source.strings[int(index)]
                if literal.startswith(("http://", "https://")):
                    config = {"url": literal}
                    if name is not None:
                        config["name"] = source.strings[int(name.group(1))]
                    self._found.declare_server(
                        path, source.line(match.start()), config, binding=None, method=METHOD
                    )
                    break

    def _agents(
        self, path: str, source: _Source, digest: str, models: list[tuple[int, str]]
    ) -> None:
        for pattern, naming, framework in _AGENTS:
            for match in pattern.finditer(source.code):
                end = _span(source.code, match.end())
                named = naming.search(source.code, match.end(), end)
                name = declared_name(source.text(named.group(1))) if named else None
                if name is None:
                    continue
                agent: AgentRecord | None = self._found.agent(
                    path,
                    source.line(match.start()),
                    name,
                    framework=framework,
                    method=METHOD,
                    digest=digest,
                )
                if agent is not None:
                    agent.models.update(
                        ref for position, ref in models if match.start() <= position <= end
                    )
