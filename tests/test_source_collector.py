"""The source collector: what a project's own code and configuration declare.

Each rule has a fixture that must be read and one that must not be. A declaration
is never executed, never contacted, and no value of a secret leaves the file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.source import SourceScanner, eligible
from nexus_symbiote.scanners.source_references import (
    Declarations,
    credential_name,
    known_family,
    model_identifier,
    split_route,
)

PLANTED = "sk-proj-" + "Zq7" * 16


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def scan(root: Path, files: dict[str, str]) -> ScanResult:
    return SourceScanner().scan(write(root, files))


def named(result: ScanResult, kind: ComponentType) -> dict[str, object]:
    return {c.name: c for c in result.components if c.component_type is kind}


def models(result: ScanResult) -> dict[str, object]:
    return named(result, ComponentType.MODEL)


def agents(result: ScanResult) -> dict[str, object]:
    return named(result, ComponentType.AGENT)


def tools(result: ScanResult) -> dict[str, object]:
    return named(result, ComponentType.TOOL)


def servers(result: ScanResult) -> dict[str, object]:
    return named(result, ComponentType.MCP_SERVER)


AGENTS_SDK = '''\
"""Example in a docstring: Agent(name="Docstring agent", model="gpt-3.5-turbo")"""
import os
from agents import Agent, FileSearchTool, WebSearchTool, function_tool, handoff, input_guardrail
from agents import OpenAIChatCompletionsModel, SQLiteSession
from agents.mcp import MCPServerStdio, MCPServerStreamableHttp
from openai import AsyncOpenAI
from .settings import DEFAULT_MODEL, REVIEW_MODEL

# old = Agent(name="Commented agent", model="gpt-4-turbo")


@function_tool
def issue_refund(order_id: str) -> str:
    return order_id


@function_tool(name_override="lookup_order")
def _lookup(order_id: str) -> str:
    return order_id


@input_guardrail
async def pii_check(ctx, agent, text):
    return None


fs = MCPServerStdio(
    name="filesystem",
    params={
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/srv/data"],
        "env": {"FS_TOKEN": os.environ["FS_TOKEN"]},
    },
)
crm = MCPServerStreamableHttp(
    name="crm",
    params={
        "url": "https://crm.internal.example/mcp?tenant=acme",
        "headers": {"Authorization": f"Bearer {os.environ['CRM_API_KEY']}"},
    },
)
local = AsyncOpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
billing = Agent(
    name="Billing agent",
    model=OpenAIChatCompletionsModel(model="llama3.1:8b", openai_client=local),
    tools=[issue_refund, _lookup],
    mcp_servers=[crm],
)
research = Agent(
    name="Research agent",
    model=REVIEW_MODEL,
    tools=[WebSearchTool(), FileSearchTool(vector_store_ids=["vs_68a1f0c2e5b08191"])],
)
triage = Agent(
    name="Triage agent",
    model=DEFAULT_MODEL,
    handoffs=[billing, handoff(research)],
    input_guardrails=[pii_check],
    mcp_servers=[fs],
    tools=[research.as_tool(tool_name="ask_research", tool_description="Ask")],
)
session = SQLiteSession("user-1", "conversations.db")
'''
SETTINGS = """\
import os

DEFAULT_MODEL = os.getenv("TRIAGE_MODEL", "gpt-4o-mini")
FAMILY = "claude"
REVIEW_MODEL = f"{FAMILY}-sonnet-4-5"
"""


@pytest.fixture
def agents_sdk(tmp_path: Path) -> ScanResult:
    return scan(tmp_path, {"app/agents_def.py": AGENTS_SDK, "app/settings.py": SETTINGS})


def test_agents_are_named_as_declared_and_hold_what_they_are_given(agents_sdk: ScanResult):
    found = agents(agents_sdk)
    assert set(found) == {"Billing agent", "Research agent", "Triage agent"}
    triage = found["Triage agent"]
    assert triage.framework == "openai-agents"
    assert triage.assurance_level is AssuranceLevel.DECLARED
    assert triage.source_path == "app/agents_def.py"
    assert triage.model_refs == ["model:source:gpt-4o-mini"]
    assert triage.sub_agent_refs == [
        found["Billing agent"].bom_ref,
        found["Research agent"].bom_ref,
    ]
    assert len(triage.guardrail_refs) == 1 and triage.guardrail_refs[0].endswith("/pii_check")
    assert found["Billing agent"].model_refs == ["model:source:llama3.1:8b"]
    assert found["Research agent"].model_refs == ["model:source:claude-sonnet-4-5"]
    assert triage.claims["deployment"].unknown_reason


def test_a_docstring_and_a_comment_declare_nothing(agents_sdk: ScanResult):
    assert "Docstring agent" not in agents(agents_sdk)
    assert "Commented agent" not in agents(agents_sdk)
    assert not {"gpt-3.5-turbo", "gpt-4-turbo"} & set(models(agents_sdk))


def test_a_model_is_followed_through_a_default_a_format_and_another_module(agents_sdk: ScanResult):
    found = models(agents_sdk)
    assert set(found) == {"gpt-4o-mini", "llama3.1:8b", "claude-sonnet-4-5"}
    mini = found["gpt-4o-mini"]
    assert mini.properties["environment_variables"] == ["TRIAGE_MODEL"]
    assert mini.properties["collection_mode"] == "static-source-reference"
    assert mini.claims["source_reference"].locator == "app/agents_def.py:56"
    # A weight file is what ``source_path`` names on a model; a reference has none.
    assert mini.source_path is None


def test_the_provider_is_the_one_the_code_names_never_a_guess(agents_sdk: ScanResult):
    found = models(agents_sdk)
    assert (found["llama3.1:8b"].provider, found["llama3.1:8b"].endpoint) == (
        "ollama",
        "http://localhost:11434",
    )
    assert found["gpt-4o-mini"].provider == "openai"
    # The agents SDK sends a bare identifier to OpenAI, which does not serve this family.
    assert found["claude-sonnet-4-5"].provider is None


def test_tools_are_read_by_decorator_reference_and_constructor(agents_sdk: ScanResult):
    found = tools(agents_sdk)
    assert set(found) == {
        "issue_refund",
        "lookup_order",
        "WebSearchTool",
        "FileSearchTool",
        "ask_research",
    }
    assert found["WebSearchTool"].properties["tool_kind"] == "hosted"
    assert found["issue_refund"].properties["tool_kind"] == "function"
    billing = agents(agents_sdk)["Billing agent"]
    assert {ref.rsplit("/", 1)[-1] for ref in billing.tool_refs if ref.startswith("tool:")} == {
        "issue_refund",
        "lookup_order",
    }


def test_servers_started_from_code_go_through_the_mcp_parser(agents_sdk: ScanResult):
    found = servers(agents_sdk)
    assert set(found) == {"filesystem", "crm"}
    filesystem = found["filesystem"]
    assert filesystem.transport == "stdio"
    assert filesystem.launcher_package == "npm:@modelcontextprotocol/server-filesystem"
    assert filesystem.version == "2025.8.21" and filesystem.version_pinned is True
    assert filesystem.properties["collection_mode"] == "static-source-declaration"
    assert filesystem.properties["declaration_line"] == 27
    assert set(filesystem.env) == {"FS_TOKEN"}
    crm = found["crm"]
    assert (crm.transport, crm.endpoint_url) == ("streamable-http", "https://crm.internal.example")
    assert crm.properties["header_names"] == ["Authorization"]


def test_no_argument_environment_or_header_value_is_exported(agents_sdk: ScanResult):
    text = json.dumps([c.model_dump(mode="json") for c in agents_sdk.components])
    for value in ("/srv/data", "tenant=acme", "Bearer", "conversations.db"):
        assert value not in text


def test_credentials_are_recorded_by_name(agents_sdk: ScanResult):
    assert agents_sdk.credential_names == {
        "CRM_API_KEY": ["app/agents_def.py:39"],
        "FS_TOKEN": ["app/agents_def.py:32"],
    }


def test_guardrail_memory_and_vector_store_are_recorded(agents_sdk: ScanResult):
    guardrail = named(agents_sdk, ComponentType.GUARDRAIL_POLICY)["pii_check"]
    assert guardrail.guardrail_type == "input-filter"
    memory = named(agents_sdk, ComponentType.MEMORY_STORE)["SQLiteSession"]
    assert memory.store_type == "conversation"
    store = named(agents_sdk, ComponentType.RAG_SOURCE)["vs_68a1f0c2e5b08191"]
    assert store.properties["store"] == "openai-vector-store"


def test_a_secret_written_into_source_never_reaches_the_inventory(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "bot.py": f"""\
from openai import OpenAI
from agents import Agent
from agents.mcp import MCPServerStdio

client = OpenAI(api_key="{PLANTED}")
client.chat.completions.create(model="{PLANTED}", messages=[])
client.chat.completions.create(model="gpt-4o", messages=[])
leaky = Agent(name="{PLANTED}", model="gpt-4o")
server = MCPServerStdio(name="notes", params={{"command": "npx", "args": ["-y", "notes-mcp", "--key", "{PLANTED}"], "env": {{"NOTES_TOKEN": "{PLANTED}"}}}})
"""
        },
    )
    text = json.dumps(
        [c.model_dump(mode="json") for c in result.components]
        + list(result.surfaces_excluded)
        + list(result.scan_failures)
        + [result.credential_names]
    )
    assert PLANTED not in text and "Zq7Zq7" not in text
    assert set(models(result)) == {"gpt-4o"}
    # The agent whose name is a token is named by what binds it instead.
    assert set(agents(result)) == {"leaky"}
    assert set(servers(result)) == {"notes"}


def test_nothing_in_the_project_is_executed(tmp_path: Path):
    marker = tmp_path / "ran"
    scan(
        tmp_path,
        {
            "boot.py": f"""\
from pathlib import Path
from openai import OpenAI

Path({str(marker)!r}).write_text("ran")
MODEL = "gpt-4o"
OpenAI().chat.completions.create(model=MODEL, messages=[])
""",
            "setup.py": f"open({str(marker)!r}, 'w').write('ran')\n",
        },
    )
    assert not marker.exists()


def test_the_same_tree_gives_the_same_records(tmp_path: Path):
    files = {"app/agents_def.py": AGENTS_SDK, "app/settings.py": SETTINGS}
    first = scan(tmp_path / "a", files)
    second = scan(tmp_path / "b", files)
    assert [c.model_dump(mode="json") for c in first.components] == [
        c.model_dump(mode="json") for c in second.components
    ]
    assert list(first.surfaces_excluded) == list(second.surfaces_excluded)


def test_a_file_that_imports_no_sdk_declares_nothing(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "shop/models.py": """\
from django.db import models

class Order(models.Model):
    model = "gpt-4o"

def render(model="claude-sonnet-4-5"):
    return call(model=model, tools=[render])
"""
        },
    )
    assert result.components == []
    assert not result.surfaces_excluded


def test_a_project_module_named_like_an_sdk_is_not_the_sdk(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "agents/__init__.py": "class Agent:\n    def __init__(self, **options): ...\n",
            "main.py": 'from agents import Agent\n\nbot = Agent(name="Local class", model="gpt-4o")\n',
        },
    )
    assert agents(result) == {}


def test_words_that_name_no_model_are_not_models(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from openai import OpenAI

client = OpenAI()
for model in ("default", "auto", "test", "weights/llama.gguf", "https://x.example/v1", "str"):
    pass
client.chat.completions.create(model="default", messages=[])
client.chat.completions.create(model="weights/llama.gguf", messages=[])
client.chat.completions.create(model="has space", messages=[])
MODEL_NOTE = "the default below"
"""
        },
    )
    assert models(result) == {}


def test_a_model_only_the_environment_sets_is_a_named_gap(tmp_path: Path):
    files = {
        "run.py": """\
import os
from openai import OpenAI

OpenAI().chat.completions.create(model=os.environ["CHAT_MODEL"], messages=[])
"""
    }
    result = scan(tmp_path / "unset", files)
    assert models(result) == {}
    assert list(result.surfaces_excluded) == [
        "run.py:4: model set by environment variable CHAT_MODEL, which no file of the project "
        "gives a value; not inventoried"
    ]
    given = scan(tmp_path / "set", {**files, ".env.example": "CHAT_MODEL=gpt-4.1\n"})
    assert set(models(given)) == {"gpt-4.1"}
    assert not given.surfaces_excluded


def test_an_agent_without_a_readable_name_is_a_gap(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": 'from agents import Agent, Runner\n\nRunner.run_sync(Agent(model="gpt-4o"), "hi")\n'
        },
    )
    assert agents(result) == {}
    assert list(result.surfaces_excluded) == [
        "run.py:3: openai-agents agent declared without a name the collector can read; "
        "not inventoried"
    ]


def test_unparsed_source_that_names_an_sdk_is_a_gap(tmp_path: Path):
    result = scan(tmp_path, {"broken.py": "from openai import OpenAI\n\ndef (:\n"})
    assert list(result.surfaces_excluded) == [
        "broken.py:1: Python source could not be parsed; not read"
    ]


def test_a_name_bound_in_terms_of_itself_costs_no_more_than_its_length(tmp_path: Path):
    rebinds = "\n".join(f'text = text.replace("{index}", "x")' for index in range(400))
    result = scan(
        tmp_path,
        {
            "loop.py": f"""\
from openai import OpenAI

text = "gpt-4o"
{rebinds}
OpenAI().chat.completions.create(model=text, messages=[])
"""
        },
    )
    assert "gpt-4o" in models(result)
    assert not [gap for gap in result.surfaces_excluded if "name bindings" in gap]


CREW = """\
import os
from crewai import Agent, LLM
from crewai.project import CrewBase, agent
from crewai.tools import BaseTool, tool
from crewai_tools import SerperDevTool

SMART = LLM(model="anthropic/claude-sonnet-4-5-20250929", api_key=os.environ["ANTHROPIC_API_KEY"])


@tool("Company lookup")
def company_lookup(name: str) -> str:
    return name


class LedgerTool(BaseTool):
    name: str = "ledger_query"
    description: str = "Query the ledger"


@CrewBase
class ResearchCrew:
    agents_config = "config/agents.yaml"

    @agent
    def researcher(self) -> Agent:
        return Agent(
            config=self.agents_config["researcher"],
            tools=[SerperDevTool(), company_lookup],
            llm=SMART,
        )

    @agent
    def analyst(self) -> Agent:
        return Agent(config=self.agents_config["analyst"], tools=[LedgerTool()])


writer = Agent(role="Report Writer", goal="write", backstory="b", llm="gpt-4.1-mini")
"""
CREW_YAML = """\
researcher:
  role: Senior Researcher
  goal: Find facts
  backstory: You dig.
analyst:
  role: Analyst
  goal: Analyse
  backstory: Numbers.
  llm: openai/gpt-4o
"""


def test_a_crew_agent_is_one_record_for_its_file_and_its_code(tmp_path: Path):
    result = scan(tmp_path, {"src/crew.py": CREW, "src/config/agents.yaml": CREW_YAML})
    found = agents(result)
    assert set(found) == {"researcher", "analyst", "Report Writer"}
    researcher, analyst = found["researcher"], found["analyst"]
    assert researcher.source_path == analyst.source_path == "src/config/agents.yaml"
    assert researcher.model_refs == ["model:source:claude-sonnet-4-5-20250929"]
    assert {ref.rsplit("/", 1)[-1] for ref in researcher.tool_refs} == {
        "SerperDevTool",
        "Company%20lookup",
    }
    assert analyst.model_refs == ["model:source:gpt-4o"]
    assert [ref.rsplit("/", 1)[-1] for ref in analyst.tool_refs] == ["ledger_query"]
    routed = models(result)["claude-sonnet-4-5-20250929"]
    assert routed.provider == "anthropic"
    assert routed.requested_alias == "anthropic/claude-sonnet-4-5-20250929"
    assert routed.properties["credential_environment_names"] == ["ANTHROPIC_API_KEY"]
    assert tools(result)["ledger_query"].properties["tool_kind"] == "class"


def test_langgraph_agents_models_tools_servers_and_stores(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "graph.py": """\
import os
from langchain.chat_models import init_chat_model
from langchain_chroma import Chroma
from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent

MODEL_NAME = os.environ.get("AGENT_MODEL") or "gpt-4.1"
llm = ChatOpenAI(model=MODEL_NAME)
store = Chroma(
    collection_name="support-docs",
    embedding_function=OpenAIEmbeddings(model="text-embedding-3-large"),
)


@tool
def search_docs(query: str) -> str:
    return query


client = MultiServerMCPClient(
    {
        "weather": {"url": "http://localhost:8000/mcp", "transport": "streamable_http"},
        "math": {"command": "python", "args": ["./servers/math.py"], "transport": "stdio"},
    }
)
tools = [search_docs]
agent = create_react_agent(
    llm.bind_tools(tools), tools, name="support_agent", checkpointer=MemorySaver()
)
reviewer = create_react_agent(
    model=init_chat_model("anthropic:claude-3-5-haiku-latest"),
    tools=[search_docs],
    interrupt_before=["tools"],
)
"""
        },
    )
    found = agents(result)
    assert set(found) == {"support_agent", "reviewer"}
    assert found["support_agent"].model_refs == ["model:source:gpt-4.1"]
    assert found["support_agent"].memory_refs == ["memory:source:graph.py/MemorySaver"]
    assert found["reviewer"].model_refs == ["model:source:claude-3-5-haiku-latest"]
    assert models(result)["claude-3-5-haiku-latest"].provider == "anthropic"
    assert models(result)["text-embedding-3-large"].model_type == "embedding"
    store = named(result, ComponentType.RAG_SOURCE)["support-docs"]
    assert store.embedding_model_ref == "model:source:text-embedding-3-large"
    assert {name: server.transport for name, server in servers(result).items()} == {
        "weather": "streamable-http",
        "math": "stdio",
    }
    approval = named(result, ComponentType.GUARDRAIL_POLICY)["interrupt_before"]
    assert approval.guardrail_type == "human-approval"


def test_tools_taken_from_an_mcp_client_are_its_servers(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "agent.py": """\
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient(
    {"orders": {"command": "uvx", "args": ["mcp-server-sqlite==2025.4.25"], "transport": "stdio"}}
)


async def build():
    tools = await client.get_tools()
    return create_react_agent("openai:gpt-4.1", tools, name="orders_agent")
"""
        },
    )
    agent = agents(result)["orders_agent"]
    assert agent.tool_refs == [servers(result)["orders"].bom_ref]
    assert tools(result) == {}


SCRIPT = """\
import { Agent, tool, MCPServerStdio, webSearchTool, hostedMcpTool } from "@openai/agents";
import { anthropic } from "@ai-sdk/anthropic";
import { openai } from "@ai-sdk/openai";
import { generateText, tool as aiTool } from "ai";
import OpenAI from "openai";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";

// const old = new Agent({ name: "Legacy", model: "gpt-3.5-turbo" });
const MODEL = process.env.CHAT_MODEL ?? "gpt-4.1-mini";
const getWeather = tool({ name: "get_weather", description: "w", parameters: z.object({}), execute: async () => "ok" });
const fsServer = new MCPServerStdio({ name: "fs", fullCommand: "npx -y @modelcontextprotocol/server-filesystem@2025.8.21 ./docs" });
const transport = new StdioClientTransport({ command: "uvx", args: ["mcp-server-git==2025.7.1"], env: { GITHUB_TOKEN: process.env.GITHUB_TOKEN! } });
const billing = new Agent({ name: "Billing", model: "gpt-4.1", tools: [getWeather] });
export const triage = new Agent({
  name: "Triage",
  model: MODEL,
  tools: [webSearchTool(), hostedMcpTool({ serverLabel: "deepwiki", serverUrl: "https://mcp.deepwiki.com/mcp" })],
  handoffs: [billing],
  mcpServers: [fsServer],
});
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
await client.chat.completions.create({ model: "gpt-4o", messages: [] });
await generateText({ model: anthropic("claude-sonnet-4-5"), tools: { lookup: aiTool({ description: "x", inputSchema: z.object({}), execute: async () => 1 }) }, prompt: "hi" });
const embedder = openai.embedding("text-embedding-3-small");
"""


def test_typescript_agents_models_tools_and_servers(tmp_path: Path):
    result = scan(tmp_path, {"web/agent.ts": SCRIPT})
    found = agents(result)
    assert set(found) == {"Billing", "Triage"}
    triage = found["Triage"]
    assert triage.model_refs == ["model:source:gpt-4.1-mini"]
    assert triage.sub_agent_refs == [found["Billing"].bom_ref]
    assert set(models(result)) == {
        "gpt-4.1",
        "gpt-4.1-mini",
        "gpt-4o",
        "claude-sonnet-4-5",
        "text-embedding-3-small",
    }
    assert "gpt-3.5-turbo" not in models(result)
    assert models(result)["claude-sonnet-4-5"].provider == "anthropic"
    assert models(result)["gpt-4.1-mini"].properties["environment_variables"] == ["CHAT_MODEL"]
    assert set(tools(result)) == {"get_weather", "lookup", "webSearchTool"}
    declared = servers(result)
    assert set(declared) == {"fs", "mcp-server-git", "deepwiki"}
    assert declared["fs"].version == "2025.8.21"
    assert declared["mcp-server-git"].launcher_package == "pypi:mcp-server-git"
    assert declared["deepwiki"].endpoint_url == "https://mcp.deepwiki.com"
    assert {ref for ref in triage.tool_refs if ref.startswith("mcp-server:")} == {
        declared["fs"].bom_ref,
        declared["deepwiki"].bom_ref,
    }
    assert set(result.credential_names) == {"GITHUB_TOKEN", "OPENAI_API_KEY"}


WORKFLOW = {
    "name": "Lead triage",
    "nodes": [
        {"name": "Webhook", "type": "n8n-nodes-base.webhook", "parameters": {"path": "in"}},
        {"name": "Lead Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}},
        {
            "name": "OpenAI Chat Model",
            "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi",
            "parameters": {"model": {"__rl": True, "value": "gpt-4o-mini", "mode": "list"}},
            "credentials": {"openAiApi": {"id": "7", "name": "Sales OpenAI account"}},
        },
        {
            "name": "CRM lookup",
            "type": "@n8n/n8n-nodes-langchain.toolHttpRequest",
            "parameters": {"url": "https://crm.example.com/api?key=abc"},
        },
        {
            "name": "Window Buffer Memory",
            "type": "@n8n/n8n-nodes-langchain.memoryBufferWindow",
            "parameters": {},
        },
        {
            "name": "Docs MCP",
            "type": "@n8n/n8n-nodes-langchain.mcpClientTool",
            "parameters": {"sseEndpoint": "https://docs.example.com/sse"},
        },
    ],
    "connections": {
        "Webhook": {"main": [[{"node": "Lead Agent", "type": "main", "index": 0}]]},
        "OpenAI Chat Model": {
            "ai_languageModel": [[{"node": "Lead Agent", "type": "ai_languageModel", "index": 0}]]
        },
        "CRM lookup": {"ai_tool": [[{"node": "Lead Agent", "type": "ai_tool", "index": 0}]]},
        "Docs MCP": {"ai_tool": [[{"node": "Lead Agent", "type": "ai_tool", "index": 0}]]},
        "Window Buffer Memory": {
            "ai_memory": [[{"node": "Lead Agent", "type": "ai_memory", "index": 0}]]
        },
    },
}


def test_an_n8n_workflow_is_an_agent_with_what_is_wired_to_it(tmp_path: Path):
    result = scan(tmp_path, {"flows/lead.json": json.dumps(WORKFLOW, indent=1)})
    agent = agents(result)["Lead Agent"]
    assert agent.framework == "n8n"
    assert agent.model_refs == ["model:source:gpt-4o-mini"]
    assert agent.memory_refs == ["memory:source:flows%2Flead.json/Window%20Buffer%20Memory"]
    assert len(agent.tool_refs) == 2
    assert models(result)["gpt-4o-mini"].provider == "openai"
    assert servers(result)["Docs MCP"].endpoint_url == "https://docs.example.com"
    assert "Webhook" not in tools(result)
    # A stored credential is named by its kind; its display name is not read.
    assert result.credential_references == {"openAiApi": ["flows/lead.json:17"]}
    assert "Sales OpenAI account" not in json.dumps(
        [c.model_dump(mode="json") for c in result.components]
    )


def test_configuration_and_deployment_files(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "main.py": "from openai import OpenAI\n\nOpenAI()\n",
            ".env.example": "OPENAI_API_KEY=\nRERANK_MODEL=rerank-english-v3.0\nLOG_LEVEL=info\n",
            ".env": f"OPENAI_API_KEY={PLANTED}\nSUMMARY_MODEL=gpt-4o\n",
            "Modelfile": "FROM qwen2.5-coder:7b\nPARAMETER temperature 0.2\n",
            "Dockerfile": "FROM python:3.12\nENV CHAT_MODEL=gpt-4.1\nRUN ollama pull llama3.2:3b\n",
            "config.yaml": "llm:\n  provider: groq\n  model: llama-3.3-70b-versatile\n"
            "router:\n  fallbacks: [gpt-4o-mini, not-a-model]\n",
            "deploy/compose.yml": "services:\n  api:\n    build: .\n    environment:\n"
            "      - EMBEDDING_MODEL=text-embedding-3-small\n"
            "      - PINECONE_API_KEY=${PINECONE_API_KEY}\n",
            "deploy/worker.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n"
            "    spec:\n      containers:\n        - name: worker\n          env:\n"
            "            - name: SUMMARY_MODEL\n              value: claude-3-5-haiku-20241022\n"
            "            - name: ANTHROPIC_API_KEY\n              valueFrom: {secretKeyRef: {name: llm, key: k}}\n",
            "tools.json": json.dumps(
                [
                    {
                        "type": "function",
                        "function": {
                            "name": "create_ticket",
                            "description": "Create a ticket",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    }
                ]
            ),
            "package.json": json.dumps({"name": "x", "model": "gpt-4o"}),
        },
    )
    found = models(result)
    assert set(found) == {
        "rerank-english-v3.0",
        "qwen2.5-coder:7b",
        "gpt-4.1",
        "llama3.2:3b",
        "llama-3.3-70b-versatile",
        "gpt-4o-mini",
        "text-embedding-3-small",
        "claude-3-5-haiku-20241022",
    }
    # The value of an environment file that is not a template is never read.
    assert "gpt-4o" not in found
    assert found["llama-3.3-70b-versatile"].provider == "groq"
    assert found["qwen2.5-coder:7b"].provider == "ollama"
    assert found["gpt-4.1"].properties["environment_variables"] == ["CHAT_MODEL"]
    assert set(tools(result)) == {"create_ticket"}
    assert set(result.credential_names) == {
        "OPENAI_API_KEY",
        "PINECONE_API_KEY",
        "ANTHROPIC_API_KEY",
    }
    assert PLANTED not in json.dumps(result.credential_names)


def test_deployment_variables_alone_are_not_an_agents_credentials(tmp_path: Path):
    result = scan(
        tmp_path,
        {".env.example": "STRIPE_SECRET_KEY=\nDATABASE_PASSWORD=\n", "app.py": "print('shop')\n"},
    )
    assert result.components == []
    assert result.credential_names == {}


def test_a_notebook_is_read_as_its_code_cells(tmp_path: Path):
    notebook = {
        "cells": [
            {"cell_type": "markdown", "source": ['model="gpt-3.5-turbo"']},
            {
                "cell_type": "code",
                "source": [
                    "%pip install openai\n",
                    "from openai import OpenAI\n",
                    'OpenAI().responses.create(model="o4-mini", input="hi", tools=[{"type": "web_search"}])\n',
                ],
            },
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    result = scan(tmp_path, {"nb/explore.ipynb": json.dumps(notebook)})
    assert set(models(result)) == {"o4-mini"}
    assert set(tools(result)) == {"web_search"}


def test_go_java_and_csharp_are_read_by_documented_call_shapes(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "svc/main.go": """\
package main

import (
	"os"
	openai "github.com/sashabaranov/go-openai"
)

// model := "gpt-3.5-turbo"
const defaultModel = "gpt-4o-mini"

func main() {
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))
	note := "Model: \\"gpt-4-turbo\\" was used before"
	req := openai.ChatCompletionRequest{Model: "gpt-4.1", Tools: []openai.Tool{{Function: &openai.FunctionDefinition{Name: "get_invoice"}}}}
	_, _, _ = client, req, note
}
""",
            "svc/Assistant.java": """\
import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.model.openai.OpenAiChatModel;

public class Assistant {
  static final String MODEL = System.getenv().getOrDefault("LLM_MODEL", "gpt-4o");
  OpenAiChatModel model = OpenAiChatModel.builder().modelName("gpt-4.1-nano").build();
  @Tool("Looks up an order")
  public String lookupOrder(String id) { return id; }
}
""",
            "svc/Kernel.cs": """\
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Agents;
/* builder.AddOpenAIChatCompletion("gpt-3.5-turbo", key); */
builder.AddAzureOpenAIChatCompletion(deploymentName: "gpt-4o-prod", endpoint: e, apiKey: Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY"));
ChatCompletionAgent agent = new() { Name = "Concierge", Instructions = "help" };
public class Plugins {
  [KernelFunction, Description("Get time")]
  public string GetTime() => "now";
  [KernelFunction("book_table")]
  public string Book(string when) => when;
}
""",
            "svc/plain.go": 'package main\n\nconst model = "gpt-4o-2024-08-06"\n',
        },
    )
    found = models(result)
    assert set(found) == {"gpt-4o-mini", "gpt-4.1", "gpt-4.1-nano", "gpt-4o-prod"}
    assert found["gpt-4o-prod"].provider == "azure-openai"
    assert found["gpt-4.1-nano"].provider == "openai"
    assert set(tools(result)) == {"get_invoice", "lookupOrder", "GetTime", "book_table"}
    assert set(agents(result)) == {"Concierge"}
    assert set(result.credential_names) == {"OPENAI_API_KEY", "AZURE_OPENAI_API_KEY"}


@pytest.mark.parametrize(
    ("path", "read"),
    [
        ("app/agent.py", True),
        ("app/agent.ts", True),
        ("notebooks/demo.ipynb", True),
        ("deploy/compose.yml", True),
        (".env.example", True),
        ("tests/test_agent.py", False),
        ("app/test_agent.py", False),
        ("app/agent_test.py", False),
        ("app/agent.test.ts", False),
        ("app/types.d.ts", False),
        ("examples/agent.py", False),
        ("docs/snippets/agent.py", False),
        ("benchmarks/cases/agent.py", False),
        ("package.json", False),
        ("README.md", False),
    ],
)
def test_which_files_are_read(path: str, read: bool):
    from pathlib import PurePosixPath

    assert eligible(PurePosixPath(path)) is read


def test_a_file_named_for_credentials_is_not_read(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "secrets.py": 'from openai import OpenAI\n\nOpenAI().chat.completions.create(model="gpt-4o")\n',
            "config/secrets/agent.yaml": "model: gpt-4.1\n",
        },
    )
    assert result.components == []


@pytest.mark.parametrize(
    ("literal", "accepted"),
    [
        ("gpt-4o", True),
        ("anthropic.claude-3-5-sonnet-20241022-v2:0", True),
        ("BAAI/bge-small-en-v1.5", True),
        ("ft:gpt-4o-mini-2024-07-18:acme:support:AbCd1234", True),
        ("", False),
        ("x", False),
        ("model", False),
        ("two words", False),
        ("./models/llama", False),
        ("weights.safetensors", False),
        ("https://api.example.com/v1", False),
        (PLANTED, False),
        (42, False),
    ],
)
def test_what_can_be_recorded_as_a_model_identifier(literal: object, accepted: bool):
    assert (model_identifier(literal) is not None) is accepted


@pytest.mark.parametrize(
    ("literal", "weights", "expected"),
    [
        ("openai/gpt-4o", False, ("gpt-4o", "openai")),
        ("anthropic:claude-sonnet-4-5", False, ("claude-sonnet-4-5", "anthropic")),
        (
            "bedrock/anthropic.claude-3-haiku-20240307-v1:0",
            False,
            ("anthropic.claude-3-haiku-20240307-v1:0", "aws-bedrock"),
        ),
        ("llama3.1:8b", False, ("llama3.1:8b", None)),
        ("openai/whisper-large-v3", True, ("openai/whisper-large-v3", None)),
        ("mistralai/Mistral-7B-Instruct-v0.3", False, ("mistralai/Mistral-7B-Instruct-v0.3", None)),
        ("meta-llama/Llama-3.3-70B-Instruct", False, ("meta-llama/Llama-3.3-70B-Instruct", None)),
    ],
)
def test_a_routing_prefix_is_split_from_the_identifier(
    literal: str, weights: bool, expected: tuple[str, str | None]
):
    assert split_route(literal, weights=weights) == expected


@pytest.mark.parametrize(
    ("name", "known"),
    [
        ("gpt-4o", True),
        ("o4-mini", True),
        ("claude-sonnet-4-5", True),
        ("gemini-2.5-flash", True),
        ("llama3.1:8b", True),
        ("sentence-transformers/all-MiniLM-L6-v2", True),
        ("openai/gpt-4o", True),
        ("production", False),
        ("v2", False),
        ("user/profile", False),
        ("customer-support", False),
    ],
)
def test_known_model_families(name: str, known: bool):
    assert known_family(name) is known


@pytest.mark.parametrize(
    ("name", "accepted"),
    [
        ("OPENAI_API_KEY", True),
        ("GITHUB_TOKEN", True),
        ("DB_PASSWORD", True),
        ("AWS_SECRET_ACCESS_KEY", True),
        ("LOG_LEVEL", False),
        ("MONKEY_BUSINESS", False),
        ("TOKENIZER_PATH", False),
        ("not a name", False),
        (None, False),
    ],
)
def test_which_variable_names_are_credentials(name: object, accepted: bool):
    assert (credential_name(name) is not None) is accepted


def test_the_number_of_declarations_of_one_kind_is_bounded(monkeypatch: pytest.MonkeyPatch):
    from nexus_symbiote.scanners import source_references

    monkeypatch.setattr(source_references, "MAX_RECORDS", 3)
    result = ScanResult(scanner_name="source")
    found = Declarations(result)
    for index in range(6):
        found.model(f"gpt-4o-{index}", "a.py", index + 1, method="python-ast")
    assert len(found.components()) == 3
    assert list(result.scan_failures) == [
        "source: more than 3 declarations of one kind; the rest were not recorded"
    ]


def run_scan(runner, root: Path, *extra: str) -> AIBOM:
    out = root.parent / f"{root.name}.json"
    result = runner.invoke(
        main,
        ["scan", str(root), "--no-project-policy", "-o", str(out), *extra],
        catch_exceptions=False,
    )
    assert out.exists(), result.output
    return AIBOM.model_validate_json(out.read_text(encoding="utf-8"))


def test_a_scan_relates_declared_agents_and_names_credentials_on_the_repository(
    runner, tmp_path: Path
):
    root = write(
        tmp_path / "project", {"app/agents_def.py": AGENTS_SDK, "app/settings.py": SETTINGS}
    )
    bom = run_scan(runner, root)
    assert bom.metadata.completeness.scanner_status["source"] == "complete"
    refs = {c.bom_ref for c in bom.components}
    # One record for a function tool the decorator reader also recorded.
    assert "tool:python:app%2Fagents_def.py/issue_refund" in refs
    assert "tool:source:app%2Fagents_def.py/issue_refund" not in refs
    triage = next(c for c in bom.components if c.name == "Triage agent")
    edges = {
        (edge.relationship, edge.target_ref.rsplit("/", 1)[-1])
        for edge in bom.dependencies
        if edge.source_ref == triage.bom_ref
    }
    assert ("uses-model", "model:source:gpt-4o-mini") in edges
    assert ("delegates-to", "Billing%20agent") in edges
    assert ("uses-guardrail", "pii_check") in edges
    assert all(
        edge.assurance_level == "declared"
        for edge in bom.dependencies
        if edge.source_ref == triage.bom_ref
    )
    billing = next(c for c in bom.components if c.name == "Billing agent")
    assert "tool:python:app%2Fagents_def.py/issue_refund" in billing.tool_refs
    repository = next(c for c in bom.components if c.bom_ref.startswith("agent:repository:"))
    assert repository.properties["credential_environment_names"] == ["CRM_API_KEY", "FS_TOKEN"]
    assert repository.properties["credential_environment_names_locations"] == {
        "CRM_API_KEY": "app/agents_def.py:39",
        "FS_TOKEN": "app/agents_def.py:32",
    }
    associated = {
        edge.target_ref for edge in bom.dependencies if edge.source_ref == repository.bom_ref
    }
    assert triage.bom_ref in associated


def test_a_scan_reconciles_with_the_checkout_it_was_taken_from(runner, tmp_path: Path):
    root = write(
        tmp_path / "project",
        {
            "app/agents_def.py": AGENTS_SDK,
            "app/settings.py": SETTINGS,
            "flows/lead.json": json.dumps(WORKFLOW, indent=1),
        },
    )
    out = tmp_path / "bom.json"
    runner.invoke(main, ["scan", str(root), "--no-project-policy", "-o", str(out)])
    result = runner.invoke(main, ["validate", str(out), "--project", str(root)])
    assert "Missing or altered local relationship" not in result.output
    assert "has no local evidence" not in result.output
    assert "differs from" not in result.output


def test_a_project_without_ai_source_is_unchanged_by_the_collector(runner, tmp_path: Path):
    root = write(tmp_path / "project", {"app.py": "print('hello')\n", "README.md": "# x\n"})
    bom = run_scan(runner, root)
    repository = next(c for c in bom.components if c.bom_ref.startswith("agent:repository:"))
    assert "credential_environment_names" not in repository.properties
    assert [c for c in bom.components if ":source:" in c.bom_ref] == []
