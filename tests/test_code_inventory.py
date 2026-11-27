"""The code collector: agents, models, tools, MCP servers and credentials in source."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import AgentComponent, CredentialComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.code_inventory import NO_FINDINGS, CodeInventoryScanner

TOKEN = "ghp_" + "Zq7" * 12
# Nine anchors, each a list of nine aliases of the one before: 9**9 strings if expanded.
ALIAS_BOMB = (
    "a: &a [x, x, x, x, x, x, x, x, x]\n"
    + "".join(
        f"{name}: &{name} [{', '.join(['*' + previous] * 9)}]\n"
        for previous, name in zip("abcdefgh", "bcdefghi", strict=True)
    )
    + "rails: *i\nmodels: *i\n"
)


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _collect(root: Path) -> ScanResult:
    return CodeInventoryScanner().scan(root)


def _by_ref(result: ScanResult) -> dict[str, Any]:
    return {component.bom_ref: component for component in result.components}


def _edges(result: ScanResult) -> set[tuple[str, str, str]]:
    return {(e.source_ref, e.target_ref, e.relationship) for e in result.dependencies}


def _agents(result: ScanResult) -> dict[str, AgentComponent]:
    return {c.name: c for c in result.components if isinstance(c, AgentComponent)}


def _scan(root: Path, output: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    result = CliRunner().invoke(
        main, ["scan", str(root), "--no-project-policy", "-o", str(output), *extra]
    )
    return result.exit_code, json.loads(output.read_text(encoding="utf-8"))


LANGGRAPH = """\
import os

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent


@tool
def lookup_order(order_id: str) -> str:
    \"\"\"Look up an order.\"\"\"
    return order_id


llm = ChatOpenAI(model="gpt-4o-mini", api_key=os.environ["OPENAI_API_KEY"])
support = create_react_agent(llm, [lookup_order])
"""

OPENAI_AGENTS = """\
import subprocess

from agents import Agent, function_tool
from agents.mcp import MCPServerStdio


@function_tool
def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


files = MCPServerStdio(
    name="files",
    params={
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/srv"],
    },
)
billing = Agent(name="Billing", instructions="Answer billing questions.", model="gpt-4.1")
triage = Agent(
    name="Triage",
    instructions="Route the request.",
    model="o3-mini",
    handoffs=[billing],
    tools=[run_command],
    mcp_servers=[files],
)
"""


def test_a_langgraph_agent_records_its_model_tool_and_credential(tmp_path: Path) -> None:
    result = _collect(_write(tmp_path, {"app/agent.py": LANGGRAPH}))
    agents = _agents(result)
    assert set(agents) == {"support"}
    support = agents["support"]
    assert support.framework == "langgraph"
    assert support.model_refs == ["model:hosted:openai:gpt-4o-mini"]
    assert support.tool_refs == ["tool:python:app%2Fagent.py/lookup_order"]
    credential = _by_ref(result)["credential:OPENAI_API_KEY"]
    assert isinstance(credential, CredentialComponent)
    assert credential.value_in_checkout is False and credential.risks == []
    assert (
        "model:hosted:openai:gpt-4o-mini",
        "credential:OPENAI_API_KEY",
        "acts-as-identity",
    ) in _edges(result)
    assert result.surfaces_scanned == ["app/agent.py"]
    assert result.scan_failures == []


def test_handoffs_mcp_servers_and_a_shell_tool_are_wired_to_the_agent(tmp_path: Path) -> None:
    result = _collect(_write(tmp_path, {"main.py": OPENAI_AGENTS}))
    agents = _agents(result)
    assert set(agents) == {"Billing", "Triage"}
    triage, billing = agents["Triage"], agents["Billing"]
    edges = _edges(result)
    assert (triage.bom_ref, billing.bom_ref, "delegates-to") in edges
    (server,) = (c for c in result.components if c.component_type.value == "mcp-server")
    assert (triage.bom_ref, server.bom_ref, "invokes") in edges
    assert server.package_url == "pkg:npm/%40modelcontextprotocol/server-filesystem@2025.1.14"
    assert "/srv" not in json.dumps(server.model_dump(mode="json"))
    assert {"capability_scope"} <= {risk.category for risk in triage.risks}
    assert not billing.risks


def test_names_that_only_look_like_framework_calls_are_not_recorded(tmp_path: Path) -> None:
    decoy = """\
from langchain_core.messages import HumanMessage

GREETING = HumanMessage(content="hello")


class Agent:
    def __init__(self, name, model):
        self.name, self.model = name, model


def create_react_agent(model, tools):
    return (model, tools)


helper = Agent(name="Planner", model="gpt-4o")
graph = create_react_agent("gpt-4o", [])
"""
    result = _collect(_write(tmp_path, {"app/agents.py": decoy}))
    assert result.components == []
    assert result.surfaces_scanned == [NO_FINDINGS]


def test_a_token_shaped_literal_is_a_risk_and_its_value_is_never_recorded(
    tmp_path: Path,
) -> None:
    source = (
        "from langchain_anthropic import ChatAnthropic\n"
        f'llm = ChatAnthropic(model="claude-sonnet-4-5", api_key="{TOKEN}")\n'
    )
    result = _collect(_write(tmp_path, {"bot.py": source}))
    (credential,) = (c for c in result.components if isinstance(c, CredentialComponent))
    assert credential.credential_kind == "source-literal"
    assert credential.value_in_checkout is True
    assert [(r.category, r.severity.value) for r in credential.risks] == [
        ("credential_exposure", "high")
    ]
    assert TOKEN not in json.dumps([c.model_dump(mode="json") for c in result.components])


def test_a_dotenv_file_is_never_read_and_a_template_lists_names(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        {
            ".env": f"OPENAI_API_KEY={TOKEN}\nSTRIPE_SECRET_KEY={TOKEN}\n",
            ".env.example": f"ANTHROPIC_API_KEY=your-key-here\nGITHUB_TOKEN={TOKEN}\nDEBUG=1\n",
        },
    )
    result = _collect(root)
    credentials = {c.name: c for c in result.components if isinstance(c, CredentialComponent)}
    assert set(credentials) == {"ANTHROPIC_API_KEY", "GITHUB_TOKEN"}
    assert credentials["ANTHROPIC_API_KEY"].risks == []
    assert [r.category for r in credentials["GITHUB_TOKEN"].risks] == ["credential_exposure"]
    assert ".env" not in result.surfaces_scanned
    assert TOKEN not in json.dumps([c.model_dump(mode="json") for c in result.components])


def test_typescript_agents_models_and_tools(tmp_path: Path) -> None:
    source = """\
import { openai } from "@ai-sdk/openai";
import { generateText, tool } from "ai";
import { z } from "zod";

export async function plan(prompt: string) {
  return generateText({
    model: openai("gpt-4o"),
    prompt,
    tools: {
      getWeather: tool({
        description: "Current weather for a city",
        parameters: z.object({ city: z.string() }),
        execute: async ({ city }) => ({ city, celsius: 21 }),
      }),
    },
  });
}
"""
    result = _collect(_write(tmp_path, {"src/plan.ts": source}))
    names = {(c.component_type.value, c.name) for c in result.components}
    assert ("model", "gpt-4o") in names
    assert ("tool", "getWeather") in names


def test_spring_ai_tools_and_configuration(tmp_path: Path) -> None:
    java = """\
package com.example.hr;

import org.springframework.ai.tool.annotation.Tool;

class LeaveTools {
    // @Tool(description = "not a tool") void commented() {}
    @Tool(description = "Remaining leave (in days) for an employee")
    public int remainingLeave(String employeeId) {
        return 3;
    }
}
"""
    config = """\
spring:
  ai:
    openai:
      api-key: ${OPENAI_API_KEY}
      chat:
        options:
          model: gpt-4o
"""
    result = _collect(
        _write(
            tmp_path,
            {
                "src/main/java/com/example/hr/LeaveTools.java": java,
                "src/main/resources/application.yml": config,
            },
        )
    )
    tools = [c for c in result.components if c.component_type.value == "tool"]
    assert [(t.name, t.description_text) for t in tools] == [
        ("remainingLeave", "Remaining leave (in days) for an employee")
    ]
    refs = _by_ref(result)
    assert "model:hosted:openai:gpt-4o" in refs and "credential:OPENAI_API_KEY" in refs
    assert (
        "model:hosted:openai:gpt-4o",
        "credential:OPENAI_API_KEY",
        "acts-as-identity",
    ) in _edges(result)


def test_langchaingo_and_semantic_kernel(tmp_path: Path) -> None:
    go = """\
package main

import (
\t"os"

\t"github.com/tmc/langchaingo/agents"
\t"github.com/tmc/langchaingo/llms/openai"
\t"github.com/tmc/langchaingo/tools"
)

func main() {
\tllm, _ := openai.New(openai.WithModel("gpt-4o-mini"), openai.WithToken(os.Getenv("OPENAI_API_KEY")))
\tresearcher := agents.NewOneShotAgent(llm, []tools.Tool{tools.Calculator{}})
\t_ = researcher
}
"""
    csharp = """\
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Agents;

var builder = Kernel.CreateBuilder();
builder.AddAzureOpenAIChatCompletion(deploymentName: "gpt-4o", endpoint: "https://example", apiKey: Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY"));
var agent = new ChatCompletionAgent { Name = "Concierge", Kernel = builder.Build() };

public sealed class Bookings
{
    [KernelFunction("book_room")]
    [Description("Book a room")]
    public string Book(string room) => room;
}
"""
    result = _collect(_write(tmp_path, {"go/main.go": go, "dotnet/Program.cs": csharp}))
    agents = _agents(result)
    assert agents["researcher"].framework == "langchaingo"
    assert agents["researcher"].model_refs == ["model:hosted:openai:gpt-4o-mini"]
    assert agents["Concierge"].framework == "semantic-kernel"
    names = {(c.component_type.value, c.name) for c in result.components}
    assert {("tool", "Calculator"), ("tool", "book_room")} <= names
    assert {"credential:OPENAI_API_KEY", "credential:AZURE_OPENAI_API_KEY"} <= set(_by_ref(result))


def _n8n(authentication: str) -> str:
    return json.dumps(
        {
            "name": "Support triage",
            "nodes": [
                {
                    "name": "Inbound",
                    "type": "n8n-nodes-base.webhook",
                    "parameters": {"path": "support", "authentication": authentication},
                },
                {"name": "Triage", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}},
                {
                    "name": "Model",
                    "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi",
                    "parameters": {"model": {"value": "gpt-4o-mini"}},
                    "credentials": {"openAiApi": {"id": "1", "name": "OpenAI production"}},
                },
            ],
            "connections": {
                "Inbound": {"main": [[{"node": "Triage", "type": "main", "index": 0}]]},
                "Model": {
                    "ai_languageModel": [
                        [{"node": "Triage", "type": "ai_languageModel", "index": 0}]
                    ]
                },
            },
        }
    )


@pytest.mark.parametrize(("authentication", "risky"), [("none", True), ("headerAuth", False)])
def test_an_n8n_agent_behind_an_open_webhook_is_a_risk(
    tmp_path: Path, authentication: str, risky: bool
) -> None:
    result = _collect(_write(tmp_path, {"workflows/support.json": _n8n(authentication)}))
    triage = _agents(result)["Triage"]
    assert triage.framework == "n8n"
    model = _by_ref(result)["model:hosted:openai:gpt-4o-mini"]
    edges = _edges(result)
    assert (triage.bom_ref, model.bom_ref, "uses-model") in edges
    assert (model.bom_ref, "credential:OpenAI production", "acts-as-identity") in edges
    categories = {risk.category for risk in triage.risks}
    assert ("authentication" in categories) is risky


def test_guardrails_serving_images_and_cloud_agents(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        {
            "rails/config.yml": (
                "models:\n  - type: main\n    engine: openai\n    model: gpt-4o-mini\n"
                "rails:\n  input:\n    flows:\n      - self check input\n"
            ),
            "serve/Dockerfile": (
                "FROM vllm/vllm-openai:v0.6.3\n"
                'CMD ["--model", "mistralai/Mistral-7B-Instruct-v0.3"]\n'
            ),
            "docker-compose.yml": "services:\n  vectors:\n    image: qdrant/qdrant:v1.12.1\n",
            "infra/agent.tf": (
                'resource "aws_bedrockagent_agent" "helpdesk" {\n'
                '  agent_name       = "helpdesk"\n'
                '  foundation_model = "anthropic.claude-3-5-sonnet-20240620-v1:0"\n'
                "}\n"
            ),
            "k8s/isvc.yaml": (
                "apiVersion: serving.kserve.io/v1beta1\nkind: InferenceService\n"
                "metadata:\n  name: summarizer\nspec:\n  predictor:\n    model:\n"
                "      args: [--model_id=facebook/bart-large-cnn]\n"
            ),
            ".claude/agents/reviewer.md": (
                "---\nname: reviewer\ndescription: Reviews diffs\ntools: Read, Grep\n---\n"
                "Review the change.\n"
            ),
        },
    )
    result = _collect(root)
    names = {(c.component_type.value, c.name) for c in result.components}
    assert {
        ("model", "gpt-4o-mini"),
        ("model", "mistralai/Mistral-7B-Instruct-v0.3"),
        ("agent", "helpdesk"),
        ("model", "anthropic.claude-3-5-sonnet-20240620-v1:0"),
        ("model", "facebook/bart-large-cnn"),
        ("agent", "reviewer"),
    } <= names
    # Images are the registry collector's records; this one only names the served model.
    assert not [
        c
        for c in result.components
        if c.component_type.value == "registry-entry"
        and c.name in {"vllm/vllm-openai", "qdrant/qdrant"}
    ]
    served = _by_ref(result)["model:hub:mistralai/Mistral-7B-Instruct-v0.3"]
    assert served.properties["served_by"] == "model-server/vllm/vllm-openai"
    assert result.scan_failures == []


def test_unrelated_and_skipped_files_are_neither_read_nor_listed(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        {
            "app/strings.py": "def shout(text):\n    return text.upper()\n",
            "web/format.ts": "export const greet = (name: string) => name;\n",
            "tests/test_agent.py": LANGGRAPH,
            "examples/demo.py": LANGGRAPH,
            "dist/bundle.min.js": 'import { openai } from "@ai-sdk/openai"; openai("gpt-4o")\n',
            "data/big.json": json.dumps({"rows": list(range(1000))}),
        },
    )
    result = _collect(root)
    assert result.components == []
    assert result.surfaces_scanned == [NO_FINDINGS]
    assert result.scan_failures == [] and result.surfaces_excluded == []


@pytest.mark.parametrize(
    ("name", "text", "gap"),
    [
        ("rails/config.yml", ALIAS_BOMB, "YAML mapping parse failed or unsupported"),
        ("docker-compose.yml", "services:\n  qdrant: " + "[" * 5000 + "\n", None),
        (
            "workflows/flow.json",
            '{"nodes": ' + "[" * 5000 + '"n8n-nodes-x"' + "]" * 5000 + "}",
            "invalid JSON or duplicate keys",
        ),
        (
            "src/Main.java",
            "import org.springframework.ai.tool.annotation.Tool;\n" + "@Tool " * 40_000,
            None,
        ),
        ("src/Main.cs", "using Microsoft.SemanticKernel;\n" + "/*" * 100_000, None),
        (
            "go/main.go",
            'import "github.com/tmc/langchaingo/llms"\n' + "a" * 200_000 + ".WithModel",
            None,
        ),
        (
            "app/agent.py",
            "import openai\nx = " + "(" * 50_000 + ")" * 50_000 + "\n",
            "invalid Python syntax",
        ),
    ],
)
def test_hostile_inputs_finish_quickly_and_a_declaration_they_hide_is_a_gap(
    tmp_path: Path, name: str, text: str, gap: str | None
) -> None:
    root = _write(tmp_path, {name: text})
    started = time.monotonic()
    result = _collect(root)
    assert time.monotonic() - started < 10
    assert result.components == []
    assert result.scan_failures == ([] if gap is None else [f"{name}: {gap}"])


def test_an_unreadable_declaration_is_a_gap_and_an_unrelated_file_is_not(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        {
            "app/agent.py": "from langchain_openai import ChatOpenAI\nllm = ChatOpenAI(model=\n",
            "app/legacy.py": "print 'the agents are ready'\n",
            "web/chat.ts": 'import { openai } from "@ai-sdk/openai";\nconst a = ;;; {{{\n',
            ".claude/agents/broken.md": "---\nname: [unclosed\n---\nBody.\n",
        },
    )
    (root / "app" / "latin.py").write_bytes(
        b"from langgraph.prebuilt import create_react_agent\nNAME = 'caf\xe9'\n"
    )
    (root / "app" / "notes.py").write_bytes(b"NAME = 'caf\xe9'\n")
    result = _collect(root)
    assert sorted(result.scan_failures) == [
        ".claude/agents/broken.md: YAML mapping parse failed or unsupported",
        "app/agent.py: invalid Python syntax",
        "app/latin.py: invalid UTF-8",
    ]
    assert result.components == []


def test_a_full_scan_links_agents_to_tools_another_collector_records(tmp_path: Path) -> None:
    root = _write(tmp_path / "project", {"app/agent.py": LANGGRAPH})
    code, document = _scan(root, tmp_path / "all.json")
    assert code == 0, document["metadata"]["completeness"]["scan_failures"]
    by_ref = {c["bom_ref"]: c for c in document["components"]}
    support = next(c for c in document["components"] if c["name"] == "support")
    assert support["tool_refs"] == ["tool:python:app%2Fagent.py/lookup_order"]
    assert by_ref["tool:python:app%2Fagent.py/lookup_order"]["component_type"] == "tool"

    _, scoped = _scan(root, tmp_path / "code.json", "--scanner", "code")
    assert scoped["metadata"]["completeness"]["scan_failures"] == []
    support = next(c for c in scoped["components"] if c["name"] == "support")
    assert support["tool_refs"] == []
    assert support["model_refs"] == ["model:hosted:openai:gpt-4o-mini"]


def test_an_environment_value_is_never_read_into_the_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", TOKEN)
    root = _write(tmp_path / "project", {"app/agent.py": LANGGRAPH})
    _, document = _scan(root, tmp_path / "all.json")
    assert TOKEN not in json.dumps(document)
    assert any(c["bom_ref"] == "credential:OPENAI_API_KEY" for c in document["components"])


def test_a_checkout_package_that_shares_a_framework_name_is_project_code(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        {
            "agents/__init__.py": "class Agent:\n    def __init__(self, **kw):\n        self.kw = kw\n",
            "app/main.py": 'from agents import Agent\n\nhelper = Agent(name="Helper", model="gpt-4o")\n',
            "svc/pkg/__init__.py": "",
            "svc/pkg/agents.py": "VALUE = 1\n",
            "svc/pkg/router.py": (
                'from agents import Agent\n\nrouter = Agent(name="Router", model="gpt-4.1")\n'
            ),
        },
    )
    result = _collect(root)
    # The root package shadows the SDK for every file; a sibling module inside a package
    # does not, since an absolute import does not search the package's own directory.
    assert set(_agents(result)) == set()
    (root / "agents" / "__init__.py").unlink()
    (root / "agents").rmdir()
    assert set(_agents(_collect(root))) == {"Helper", "Router"}


def test_self_referential_names_and_shared_tools_stay_linear(tmp_path: Path) -> None:
    body = "".join(f"    out = subprocess.run(['echo', '{index}'])\n" for index in range(400))
    calls = "".join(
        f'agent_{index} = Agent(name="a{index}", model=model, tools=[run])\n'
        for index in range(400)
    )
    source = (
        "import subprocess\nfrom agents import Agent, function_tool\n"
        + 'model = "gpt-4o"\n'
        + "model = model.replace('4o', '4o')\n" * 2_000
        + "a = b\nb = a\n"
        + f"@function_tool\ndef run() -> None:\n{body}"
        + calls
    )
    root = _write(tmp_path, {"app.py": source})
    started = time.monotonic()
    result = _collect(root)
    assert time.monotonic() - started < 10
    assert len(_agents(result)) == 400
