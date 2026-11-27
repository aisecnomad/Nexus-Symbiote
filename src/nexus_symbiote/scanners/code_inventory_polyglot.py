"""Agent frameworks in Java, Kotlin, Go and C#, read from comment-free source text.

These languages have no parser in this build, so only distinctive, framework-specific
forms are read: Spring AI ``@Tool`` methods, LangChainGo agents and model options, and
Semantic Kernel agents, chat services and kernel functions. Environment variables that
name a credential are recorded by name.

Every pattern here starts at a literal or a word boundary and bounds what it repeats,
so the time spent on a file grows with its length, not faster.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import quote

from nexus_symbiote.core.enums import TrustTier
from nexus_symbiote.core.models import AgentComponent, ToolComponent
from nexus_symbiote.scanners.code_inventory import (
    _ENV_NAME,
    Builder,
    _scope,
    model_component,
    plausible_model,
)
from nexus_symbiote.scanners.mcp_credentials import credential_name

# A comment, a string or character literal, or a Go raw string; strings are kept so a
# comment marker inside one is not taken for a comment. An unclosed block comment runs
# to the end of the file, as a compiler reads it.
_LEXEME = re.compile(
    r"//[^\n]*"
    r"|/\*[^*]*\*+(?:[^/*][^*]*\*+)*/"
    r"|/\*[\s\S]*"
    r'|"(?:[^"\\\n]|\\.)*"?'
    r"|'(?:[^'\\\n]|\\.)*'?"
    r"|`[^`]*`?"
)
_ENV_READS = (
    re.compile(r"\bSystem\.getenv\(\s*\"([A-Z][A-Z0-9_]{2,127})\"\s*\)"),
    re.compile(r"\bos\.(?:Getenv|LookupEnv)\(\s*\"([A-Z][A-Z0-9_]{2,127})\"\s*\)"),
    re.compile(r"\bEnvironment\.GetEnvironmentVariable\(\s*\"([A-Z][A-Z0-9_]{2,127})\"\s*\)"),
)
_SPRING_TOOL = re.compile(r'@Tool\b\s*(?:\(((?:[^()"]|"(?:[^"\\\n]|\\.){0,500}"){0,1500})\))?')
_GO_MODEL = re.compile(r"\b(\w{1,64})\.WithModel\(\s*\"([^\"\n]{1,160})\"\s*\)")
_GO_AGENT = re.compile(r"\b(\w{1,64})\s*:?=\s*agents\.New\w{0,64}Agent\(")
_GO_TOOL = re.compile(r"\btools\.(\w{1,64})\s*\{")
_SK_SERVICE = re.compile(
    r"\bAdd(AzureOpenAI|OpenAI|Ollama|Google|MistralAI|Bedrock)ChatCompletion\(([^;]{0,2000})"
)
_SK_AGENT = re.compile(r"\bnew\s+ChatCompletionAgent\s*(?:\(\s*\))?\s*\{([^}]{0,4000})\}")
_SK_FUNCTION = re.compile(
    r'\[KernelFunction\b(?:\(\s*"([^"\n]{1,128})"[^\]\n]{0,500})?[^\]\n]{0,500}\]'
    r"(?:\s*\[[^\]\n]{0,500}\]){0,8}"
)
_IDENTIFIER = re.compile(r"[A-Za-z_]\w{0,127}")
_GO_PROVIDERS = {
    "openai": "openai",
    "anthropic": "anthropic",
    "googleai": "google",
    "ollama": "ollama",
    "mistral": "mistral",
    "bedrock": "aws-bedrock",
}
_SK_PROVIDERS = {
    "AzureOpenAI": "azure-openai",
    "OpenAI": "openai",
    "Ollama": "ollama",
    "Google": "google",
    "MistralAI": "mistral",
    "Bedrock": "aws-bedrock",
}


def _strip_comments(text: str) -> str:
    def keep(match: re.Match[str]) -> str:
        lexeme = match.group(0)
        if lexeme.startswith("//"):
            return ""
        if lexeme.startswith("/*"):
            return "\n" * lexeme.count("\n")
        return lexeme

    return _LEXEME.sub(keep, text)


def _line(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _method_after(text: str, index: int) -> str | None:
    """The name of the method declared next after ``index``: the last word before ``(``."""
    head = text[index : index + 400].split("(", 1)
    if len(head) < 2 or any(stop in head[0] for stop in ";{}="):
        return None
    words = _IDENTIFIER.findall(head[0])
    return words[-1] if words else None


def _tool(builder: Builder, path: str, name: str, line: int, description: str | None = None) -> str:
    return builder.add(
        ToolComponent(
            bom_ref=f"tool:code:{_scope(PurePosixPath(path))}/{quote(name, safe='')}",
            name=name,
            description_text=description[:300] if description else None,
            source_path=path,
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            properties={"collection_mode": "static-source", "declared_at": f"{path}:{line}"},
        )
    )


def _agent(builder: Builder, path: str, name: str, framework: str, line: int) -> str:
    return builder.add(
        AgentComponent(
            bom_ref=f"agent:code:{_scope(PurePosixPath(path))}/{quote(name, safe='')}",
            name=name,
            framework=framework,
            source_path=path,
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            properties={"collection_mode": "static-source", "declared_at": f"{path}:{line}"},
        )
    )


def _spring_tools(builder: Builder, path: str, text: str) -> list[str]:
    tools: list[str] = []
    for match in _SPRING_TOOL.finditer(text):
        arguments = match.group(1) or ""
        method = _method_after(text, match.end())
        if method is None:
            continue
        description = re.search(r'\bdescription\s*=\s*"((?:[^"\\\n]|\\.){0,500})"', arguments)
        name = re.search(r'\bname\s*=\s*"([^"\n]{1,128})"', arguments)
        tools.append(
            _tool(
                builder,
                path,
                name.group(1) if name else method,
                _line(text, match.start()),
                description.group(1) if description else None,
            )
        )
    return tools


def collect(builder: Builder, path: str, raw: str) -> None:
    text = _strip_comments(raw)
    suffix = PurePosixPath(path).suffix
    tools: list[str] = []
    models: list[str] = []
    agents: list[str] = []
    if suffix in {".java", ".kt"} and "org.springframework.ai" in text:
        tools.extend(_spring_tools(builder, path, text))
    if suffix == ".go" and "github.com/tmc/langchaingo" in text:
        for match in _GO_MODEL.finditer(text):
            if plausible_model(match.group(2)):
                models.append(
                    model_component(
                        builder,
                        match.group(2),
                        _GO_PROVIDERS.get(match.group(1)),
                        "hosted",
                        path,
                        _line(text, match.start()),
                    )
                )
        for match in _GO_AGENT.finditer(text):
            agents.append(
                _agent(builder, path, match.group(1), "langchaingo", _line(text, match.start()))
            )
        for match in _GO_TOOL.finditer(text):
            if match.group(1) != "Tool":
                tools.append(_tool(builder, path, match.group(1), _line(text, match.start())))
    if suffix == ".cs" and "Microsoft.SemanticKernel" in text:
        for match in _SK_SERVICE.finditer(text):
            body = match.group(2)
            value = re.search(r'\b(?:deploymentName|modelId)\s*:\s*"([^"\n]{1,160})"', body)
            value = value or re.match(r'\s*"([^"\n]{1,160})"', body)
            if value and plausible_model(value.group(1)):
                provider = _SK_PROVIDERS[match.group(1)]
                ref = model_component(
                    builder, value.group(1), provider, "hosted", path, _line(text, match.start())
                )
                builder.components[ref].properties.setdefault(
                    "deployment", provider == "azure-openai"
                )
                models.append(ref)
        for match in _SK_AGENT.finditer(text):
            name = re.search(r'\bName\s*=\s*"([^"\n]{1,128})"', match.group(1))
            if name:
                agents.append(
                    _agent(
                        builder, path, name.group(1), "semantic-kernel", _line(text, match.start())
                    )
                )
        for match in _SK_FUNCTION.finditer(text):
            method = match.group(1) or _method_after(text, match.end())
            if method is not None:
                tools.append(_tool(builder, path, method, _line(text, match.start())))
    for pattern in _ENV_READS:
        for match in pattern.finditer(text):
            variable = match.group(1)
            if _ENV_NAME.fullmatch(variable) and credential_name(variable):
                ref = builder.credential(variable, "environment-variable")
                for owner in models:
                    builder.edge(
                        owner, ref, "acts-as-identity", f"read from the environment in {path}"
                    )
    for agent in agents:
        stored = builder.components[agent]
        assert isinstance(stored, AgentComponent)
        if len(models) == 1 and models[0] not in stored.model_refs:
            stored.model_refs.append(models[0])
            builder.edge(agent, models[0], "uses-model")
        if len(agents) == 1:
            for tool in tools:
                if tool not in stored.tool_refs:
                    stored.tool_refs.append(tool)
                builder.edge(agent, tool, "invokes")
