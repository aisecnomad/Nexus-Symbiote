"""The agents collector records framework agents, their models, tools, credentials and
datasets from literal source declarations, and nothing from code it must not trust."""

from __future__ import annotations

import json
from pathlib import Path

from nexus_symbiote.core.enums import CapabilityClass, SideEffectProfile
from nexus_symbiote.core.models import (
    AgentComponent,
    DataSourceComponent,
    ModelComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.agents import AgentScanner, _plausible_model_id, _provider_for


def _scan(root: Path) -> tuple[list[AgentComponent], list[ModelComponent], list[ToolComponent]]:
    result = AgentScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    agents = [c for c in result.components if isinstance(c, AgentComponent)]
    models = [c for c in result.components if isinstance(c, ModelComponent)]
    tools = [c for c in result.components if isinstance(c, ToolComponent)]
    return agents, models, tools


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_openai_agents_sdk_agent_binds_model_tools_and_credentials(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "billing.py",
        """
import os
import stripe
from agents import Agent, Runner, function_tool

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]

@function_tool
def issue_refund(charge_id: str, amount_cents: int) -> str:
    \"\"\"Refund a charge.\"\"\"
    return stripe.Refund.create(charge=charge_id, amount=amount_cents).id

billing = Agent(name="Billing Agent", model="gpt-4.1", tools=[issue_refund])
""",
    )
    agents, models, tools = _scan(tmp_path)
    (agent,) = agents
    assert agent.name == "Billing Agent"
    assert agent.framework == "openai-agents"
    assert agent.model_refs == ["model:reference:openai/gpt-4.1"]
    assert [t.split("/")[-1] for t in agent.tool_refs] == ["issue_refund"]
    assert agent.properties["credential_env_vars"] == ["STRIPE_SECRET_KEY"]
    (model,) = models
    assert (model.name, model.provider, model.model_type) == ("gpt-4.1", "openai", "hosted")
    (tool,) = tools
    assert tool.capabilities is not None
    assert CapabilityClass.PAYMENT in tool.capabilities.capabilities
    assert tool.capabilities.side_effect_profile == SideEffectProfile.FINANCIAL_TRANSACTION
    assert any(r.category == "capability_scope" for r in tool.risks)


def test_a_checkout_package_named_agents_is_not_the_sdk(tmp_path: Path) -> None:
    _write(tmp_path, "agents/__init__.py", "")
    _write(
        tmp_path,
        "agents/billing.py",
        "from agents import Agent, function_tool\nbilling = Agent(name='x', model='gpt-4.1')\n",
    )
    agents, models, _ = _scan(tmp_path)
    assert agents == [] and models == []


def test_langgraph_graph_names_the_compiled_agent_and_its_module_model(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "triage.py",
        """
import os
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode

llm = ChatOpenAI(model="gpt-4o-mini", api_key=os.environ["OPENAI_API_KEY"])

@tool
def escalate(ticket: str) -> str:
    \"\"\"Escalate.\"\"\"
    import requests
    return requests.post("https://x.example", json={"t": ticket}).text

graph = StateGraph(dict)
graph.add_node("tools", ToolNode([escalate]))
triage_agent = graph.compile()
""",
    )
    agents, models, tools = _scan(tmp_path)
    (agent,) = agents
    assert agent.name == "triage_agent" and agent.framework == "langgraph"
    assert agent.model_refs == ["model:reference:openai/gpt-4o-mini"]
    assert [t.split("/")[-1] for t in agent.tool_refs] == ["escalate"]
    assert "OPENAI_API_KEY" in agent.properties["credential_env_vars"]
    (tool,) = tools
    assert tool.capabilities is not None
    assert CapabilityClass.NETWORK in tool.capabilities.capabilities


def test_claude_agent_sdk_options_record_builtin_tools_and_bypass_mode(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "ops.py",
        """
from claude_agent_sdk import ClaudeAgentOptions
options = ClaudeAgentOptions(
    model="claude-sonnet-4-5",
    allowed_tools=["Bash", "Read", "mcp__tickets__close"],
    permission_mode="bypassPermissions",
    mcp_servers={"tickets": {"command": "python", "args": ["-m", "srv"]}},
)
""",
    )
    agents, _, tools = _scan(tmp_path)
    (agent,) = agents
    assert agent.name == "ops" and agent.framework == "claude-agent-sdk"
    assert agent.properties["permission_mode"] == "bypassPermissions"
    assert agent.properties["mcp_server_names"] == ["tickets"]
    assert any(r.category == "permission_scope" for r in agent.risks)
    names = {t.name: t for t in tools}
    assert set(names) == {"Bash", "Read"}, "MCP tools belong to the MCP collector"
    assert names["Bash"].capabilities is not None
    assert CapabilityClass.EXECUTE in names["Bash"].capabilities.capabilities
    assert any(r.category == "capability_scope" for r in names["Bash"].risks)


def test_google_adk_crewai_and_pydantic_ai_agents(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "scheduler.py",
        """
from google.adk.agents import LlmAgent
from google.adk.tools import google_search

def book(customer: str) -> dict:
    \"\"\"Book.\"\"\"
    return {"c": customer}

scheduler_agent = LlmAgent(name="scheduler_agent", model="gemini-2.5-flash", tools=[google_search, book])
""",
    )
    _write(
        tmp_path,
        "research.py",
        """
import os
from crewai import LLM, Agent
from crewai_tools import SerperDevTool
llm = LLM(model="anthropic/claude-sonnet-4-5", api_key=os.environ["ANTHROPIC_API_KEY"])
search = SerperDevTool(api_key=os.environ["SERPER_API_KEY"])
researcher = Agent(role="Research Analyst", goal="g", backstory="b", tools=[search], llm=llm)
""",
    )
    _write(
        tmp_path,
        "kb.py",
        "from pydantic_ai import Agent\nkb_agent = Agent('openai:gpt-4o', system_prompt='x')\n",
    )
    agents, models, tools = _scan(tmp_path)
    by_name = {a.name: a for a in agents}
    assert set(by_name) == {"scheduler_agent", "Research Analyst", "kb_agent"}
    assert by_name["scheduler_agent"].framework == "google-adk"
    assert sorted(t.split("/")[-1] for t in by_name["scheduler_agent"].tool_refs) == [
        "book",
        "google_search",
    ]
    assert by_name["Research Analyst"].model_refs == ["model:reference:anthropic/claude-sonnet-4-5"]
    assert [t.split("/")[-1] for t in by_name["Research Analyst"].tool_refs] == ["SerperDevTool"]
    assert by_name["kb_agent"].model_refs == ["model:reference:openai/gpt-4o"]
    assert {(m.provider, m.name) for m in models} == {
        ("google", "gemini-2.5-flash"),
        ("anthropic", "claude-sonnet-4-5"),
        ("openai", "gpt-4o"),
    }
    assert {t.name for t in tools} == {"google_search", "book", "SerperDevTool"}


def test_model_literals_need_an_ai_sdk_and_a_plausible_identifier(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "models.py",
        "from django.db import models\n\nclass Device(models.Model):\n    model = models.CharField(max_length=32)\n",
    )
    _write(
        tmp_path,
        "catalog.py",
        'ITEMS = [{"model": "X200"}]\nclient = Service(model="gpt-4o-mini")\n',
    )
    _write(
        tmp_path,
        "providers.py",
        """
import boto3
import litellm
from langchain_openai import AzureChatOpenAI
from sentence_transformers import SentenceTransformer
from transformers import AutoTokenizer
BASE = "distilbert-base-uncased"
azure = AzureChatOpenAI(deployment_name="acme-gpt4o")
encoder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
tokenizer = AutoTokenizer.from_pretrained(BASE)
bedrock = boto3.client("bedrock-runtime")
def run(prompt):
    bedrock.invoke_model(modelId="anthropic.claude-3-5-haiku-20241022-v1:0", body=prompt)
    litellm.completion(model="bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0", messages=[])
    litellm.completion(model="your-model-here", messages=[])
""",
    )
    _write(
        tmp_path, "tests/test_x.py", "from openai import OpenAI\nOpenAI(model='test-model-stub')\n"
    )
    _, models, _ = _scan(tmp_path)
    found = {(m.provider, m.name, m.model_type) for m in models}
    assert found == {
        ("azure-openai", "acme-gpt4o", "hosted"),
        ("huggingface", "sentence-transformers/all-MiniLM-L6-v2", "embedding"),
        ("huggingface", "distilbert-base-uncased", "local"),
        ("aws-bedrock", "anthropic.claude-3-5-haiku-20241022-v1:0", "hosted"),
        ("aws-bedrock", "anthropic.claude-3-5-sonnet-20241022-v2:0", "hosted"),
    }
    assert not _plausible_model_id("your-model-here")
    assert not _plausible_model_id("OPENAI_API_KEY")
    assert _provider_for("azure/acme-gpt4o", "") == ("acme-gpt4o", "azure-openai")


def test_tool_bodies_classify_shell_raw_sql_and_file_writes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "srv.py",
        """
import os
import subprocess
from langchain_core.tools import tool
from sqlalchemy import create_engine, text
engine = create_engine(os.environ["DATABASE_URL"])

@tool
def run_shell(command: str) -> str:
    \"\"\"Run a command.\"\"\"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

@tool
def run_sql(statement: str) -> list:
    \"\"\"Run SQL.\"\"\"
    with engine.begin() as conn:
        return list(conn.execute(text(statement)))

@tool
def save_note(path: str, body: str) -> str:
    \"\"\"Save.\"\"\"
    with open(path, "w") as fh:
        fh.write(body)
    return path
""",
    )
    _, _, tools = _scan(tmp_path)
    by_name = {t.name: t for t in tools}
    assert by_name["run_shell"].capabilities is not None
    assert CapabilityClass.EXECUTE in by_name["run_shell"].capabilities.capabilities
    assert any(r.category == "capability_scope" for r in by_name["run_shell"].risks)
    assert by_name["run_sql"].capabilities is not None
    assert by_name["run_sql"].capabilities.side_effect_profile == SideEffectProfile.DESTRUCTIVE
    assert any("caller-supplied statement" in r.detail for r in by_name["run_sql"].risks)
    assert by_name["save_note"].capabilities is not None
    assert {CapabilityClass.FILESYSTEM, CapabilityClass.WRITE} <= set(
        by_name["save_note"].capabilities.capabilities
    )


def test_vercel_ai_sdk_agent_tools_and_env_in_typescript(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "web/assistant.ts",
        """
import { anthropic } from "@ai-sdk/anthropic";
import { generateText, tool } from "ai";
import { execSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { z } from "zod";
const key = process.env.ANTHROPIC_API_KEY;
export async function assist(task: string) {
  return generateText({
    model: anthropic("claude-opus-4-1"),
    system: "You help.",
    prompt: task,
    tools: {
      run_shell: tool({ description: "Run a shell command", inputSchema: z.object({ command: z.string() }), execute: async ({ command }) => execSync(command).toString() }),
      write_file: tool({ description: "Write", inputSchema: z.object({ path: z.string() }), execute: async ({ path }) => { writeFileSync(path, ""); return path; } }),
    },
  });
}
""",
    )
    agents, models, tools = _scan(tmp_path)
    (agent,) = agents
    assert agent.name == "assistant.assist" and agent.framework == "vercel-ai-sdk"
    assert agent.model_refs == ["model:reference:anthropic/claude-opus-4-1"]
    assert agent.properties["credential_env_vars"] == ["ANTHROPIC_API_KEY"]
    assert {(m.provider, m.name) for m in models} == {("anthropic", "claude-opus-4-1")}
    by_name = {t.name: t for t in tools}
    assert by_name["run_shell"].capabilities is not None
    assert CapabilityClass.EXECUTE in by_name["run_shell"].capabilities.capabilities
    assert by_name["write_file"].capabilities is not None
    assert CapabilityClass.WRITE in by_name["write_file"].capabilities.capabilities
    assert by_name["run_shell"].description_text == "Run a shell command"


def test_n8n_workflow_binds_agent_model_and_tool_through_connections(tmp_path: Path) -> None:
    workflow = {
        "name": "Support assistant",
        "nodes": [
            {"name": "AI Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}},
            {
                "name": "OpenAI Chat Model",
                "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi",
                "parameters": {"model": "gpt-4o-mini"},
                "credentials": {"openAiApi": {"id": "1"}},
            },
            {
                "name": "MCP Client",
                "type": "@n8n/n8n-nodes-langchain.mcpClientTool",
                "parameters": {"sseEndpoint": "https://mcp.example.com/crm/sse?token=abc"},
            },
        ],
        "connections": {
            "OpenAI Chat Model": {"ai_languageModel": [[{"node": "AI Agent"}]]},
            "MCP Client": {"ai_tool": [[{"node": "AI Agent"}]]},
        },
    }
    _write(tmp_path, "workflows/support.json", json.dumps(workflow))
    agents, models, tools = _scan(tmp_path)
    (agent,) = agents
    assert agent.framework == "n8n" and agent.name == "AI Agent"
    assert agent.model_refs == ["model:reference:openai/gpt-4o-mini"]
    assert [t.split("/")[-1] for t in agent.tool_refs] == ["MCP%20Client"]
    assert agent.properties["credential_env_vars"] == ["openAiApi"]
    (tool,) = tools
    assert tool.description_text == "MCP client endpoint https://mcp.example.com"
    assert "token=abc" not in json.dumps(tool.model_dump(mode="json"))


def test_configuration_files_contribute_model_references(tmp_path: Path) -> None:
    _write(tmp_path, "models/Modelfile", 'FROM llama3.1:8b\nSYSTEM """x"""\n')
    _write(tmp_path, ".codex/config.toml", 'model = "gpt-5-codex"\napproval_policy = "never"\n')
    _write(
        tmp_path,
        "configs/litellm_config.yaml",
        "model_list:\n  - model_name: default\n    litellm_params:\n      model: azure/acme-gpt4o\n  - model_name: fb\n    litellm_params:\n      model: bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0\n",
    )
    _write(
        tmp_path,
        ".continue/config.yaml",
        "models:\n  - name: Claude\n    provider: anthropic\n    model: claude-sonnet-4-5\n",
    )
    _, models, _ = _scan(tmp_path)
    assert {(m.provider, m.name) for m in models} == {
        ("ollama", "llama3.1:8b"),
        ("openai", "gpt-5-codex"),
        ("azure-openai", "acme-gpt4o"),
        ("aws-bedrock", "anthropic.claude-3-5-sonnet-20241022-v2:0"),
        ("anthropic", "claude-sonnet-4-5"),
    }


def test_datasets_loaded_for_training_are_data_sources(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "training/train.py",
        'from datasets import load_dataset\npublic = load_dataset("banking77", split="train")\n'
        'private = load_dataset("json", data_files="data/intents.jsonl")\n',
    )
    result = AgentScanner().scan(tmp_path)
    data = [c for c in result.components if isinstance(c, DataSourceComponent)]
    assert {(d.name, d.source_uri, d.dataset_type) for d in data} == {
        ("banking77", "hf:banking77", "fine-tuning"),
        ("data/intents.jsonl", "data/intents.jsonl", "fine-tuning"),
    }


def test_a_checkout_without_agent_code_records_nothing_and_stays_complete(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "import requests\nprint(requests.get('https://x.example').text)\n")
    result = AgentScanner().scan(tmp_path)
    assert result.components == []
    assert result.surfaces_scanned == ["agents (no agent framework declarations found)"]
    assert not result.surfaces_excluded
