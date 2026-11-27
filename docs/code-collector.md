# Code collector

The `code` collector (Experimental) records what an agent's own code and AI configuration
assemble: each agent, the hosted or hub model it calls, the tools and MCP servers it is
given, the agents it hands off to, its guardrails and datasets, and the credentials it
authenticates with. Configuration collectors record what a client launches; this one
records what the application constructs. Nothing it reads is executed, imported or loaded.

## What it records

A call is recorded only when it resolves to an import from a known framework module, so a
local class named `Agent` or a function named `create_react_agent` is not an agent.

| Surface | Read with | Frameworks and forms |
| --- | --- | --- |
| Python | `ast` | LangChain and LangGraph, OpenAI Agents SDK, CrewAI (with `agents.yaml` roles), Google ADK, LlamaIndex, AutoGen, smolagents, PydanticAI, Strands, Semantic Kernel, Haystack; Hugging Face `from_pretrained`, `pipeline` and `SentenceTransformer`; provider SDK calls such as `client.chat.completions.create(model=...)`; `datasets.load_dataset`; Guardrails AI and NeMo Guardrails |
| TypeScript and JavaScript | tree-sitter | AI SDK (`@ai-sdk/*`, `ai`), Mastra, OpenAI Agents JS, LangChain.js and LangGraph.js, VoltAgent |
| Java, Kotlin, Go, C# | comment-free text | Spring AI `@Tool` methods, LangChainGo agents and `WithModel`, Semantic Kernel agents, chat services and `[KernelFunction]` methods |
| AI configuration | bounded YAML, JSON or by line | Spring AI `application.yml`, `.yaml` and `.properties`; NeMo Guardrails `config.yml` models; n8n workflow JSON; `.claude/agents` and `.github/agents` subagent front matter; the model an AI serving image is started with in a `Dockerfile`; KServe `InferenceService`; Terraform Bedrock agents, Azure OpenAI deployments and Vertex AI endpoints and indexes |

Components carry typed edges: `uses-model`, `invokes` (tools and MCP servers),
`delegates-to` (handoffs and sub-agents), `uses-guardrail`, `retrieves-from` and
`acts-as-identity` (a credential the model, tool or agent authenticates with).

A hosted model alias such as `gpt-4o` is recorded with `model_type` `hosted`, and a hub
reference such as `org/model` loaded at run time with `properties.model_reference` `hub`.
Both are locators, not measured weight identities: `validate` reports each as a
`model_locator` warning, like a remote MCP endpoint, instead of an unknown artifact. A
hosted model that an [`agent.yaml` manifest](agent-manifest.md) declares is the
operator's declaration and keeps its unknown integrity.
Container images are the [registry collector's](registry-collector.md) records; this
collector only names the model an AI serving image runs.

## Credentials, by name only

A credential is a `credential` component named by the environment variable or setting
that holds it: an `os.environ`, `os.getenv`, `process.env`, `System.getenv`,
`os.Getenv` or `Environment.GetEnvironmentVariable` read of a credential-shaped name, a
`${NAME}` placeholder in Spring AI configuration, a key in a `.env.example`,
`.env.sample` or `.env.template` file, or an n8n credential label. A value is never read
into the inventory. A `.env` file, or any file whose name says it holds credentials, is
not read at all.

A token-shaped literal passed as a credential argument, such as
`ChatOpenAI(api_key="sk-...")`, or found in a `.env` template, is a `credential_exposure`
finding (high); the component records that a value sits in the checkout
(`value_in_checkout: true`) and never the value.

## Findings

| Category | Severity | When |
| --- | --- | --- |
| `credential_exposure` | high | A token-shaped credential literal in source or a `.env` template |
| `capability_scope` | high | A tool runs operating-system commands (`subprocess`, `os.system`, `os.popen`), and an agent is given such a tool |
| `authentication` | medium | An n8n agent is triggered by a webhook that requires no authentication |

See the [finding catalog](finding-catalog.md) for gate effects.

## What it reads, and what is a gap

A file is read only when it holds one of its surface's markers, outside directories named
`tests`, `test`, `__tests__`, `dist`, `build`, `docs`, `benchmarks` or `examples`, and
never when its name says it holds credentials. Minified files (`.min.`) and TypeScript
declaration, spec and test files are not read.

A file that holds a recognised declaration (a framework import line, an AI SDK package
specifier, an n8n workflow, a NeMo `rails` configuration, a CrewAI role, a Spring AI
setting or a subagent definition) but cannot be read is a collection failure, worded as
the `mcp` source search words it, so the gate groups both collectors' records: it is larger
than `syntax-bytes`, not text in its encoding, unparsable, over `python-nodes`, or YAML
with anchors, aliases or tags. Any other unreadable file declares nothing and is not a
gap. The text read is bounded by `source-scan-bytes`, and running out of it is a named
failure. Only files that declared something are listed in `surfaces_scanned`, so code that
declares nothing an agent uses leaves the inventory unchanged.

An agent's `tool_refs` can name a decorated tool that the `mcp` collector records. After
every collector has run, such a reference stays only if that collector recorded its
target, so a scan with `--scanner code` alone holds no dangling reference.

## Limits

- Wiring is read within one file: an agent built in one module from a tool defined in
  another is linked only when the tool is a decorated or framework tool the reference
  scheme names.
- Values are resolved through literals, module-level assignments and environment
  defaults; a model or tool chosen at run time is not recorded.
- Java, Kotlin, Go and C# have no parser in this build: an agent there is linked to its
  model and tools only when the file holds one agent and one model.
- A file larger than `file-bytes` is not read and is not a gap.

See also [known limitations](known-limitations.md#code-collector) and
[collection limits](collection-limits.md).
