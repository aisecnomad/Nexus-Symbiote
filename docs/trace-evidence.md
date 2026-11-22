# Trace evidence

`trace-diff` compares what an agent's inventory declares with the runtime use that the
agent's own OpenTelemetry traces report: what was used but never declared, and what was
declared but never seen in these traces. It reads trace files that you already
collected, offline, and never runs the agent.

## Why

A static inventory records declared composition: the MCP servers, models, prompts and
tools that a repository's files name. An agent can use more than it declares: a tool
that a remote MCP server serves but no file lists, a model chosen at run time, an MCP
endpoint configured outside the repository. Nexus SymBiote never executes what it
inventories, so it cannot watch an agent run. Operators who run agents can export
traces that follow the OpenTelemetry GenAI and MCP semantic conventions, and those
traces name the tools, models, agents and MCP endpoints that each run used.
`trace-diff` reconciles those names with the inventory, so that a CI job can fail when
the traces show a tool, model, agent or MCP endpoint that the inventory does not declare.

## Trust model: reported, not observed

[The security model](security-model.md) keeps declared, observed and verified evidence
apart. Telemetry is a fourth kind, and the evidence document labels it `reported`:

| Evidence | Who states it | What it can establish |
|---|---|---|
| Declared | A repository file, manifest, supplier or report | That someone says a component is used |
| Observed | A Nexus SymBiote collector that measured bytes | That a component with this identity was present where and when it was collected |
| Verified | A cryptographic check under operator policy | That a signer or a digest binds the artifact |
| Reported | The agent's own instrumentation, in its traces | That the instrumentation reported an operation that names these identifiers |

Traces come from code inside the process they describe. They can be incomplete,
sampled, or forged by that code, and an exporter or a person can drop spans before you
read them. A span therefore shows at most that the instrumentation reported an
operation, and a missing span proves nothing: a declaration that no span mentions may
still be used, and use that no span reports may still occur. Matching is by name and
reported endpoint, never by cryptographic identity, so a tool that reports a declared
name, at a declared endpoint when the span names one, is matched whatever it does.

Trace evidence never raises the assurance of anything. `trace-diff` reads the
inventory and never changes it; a match does not make a component observed or
verified, and an `undeclared` item is a finding to review, not a judgment that the
agent is malicious. Exit status 0 means that nothing undeclared appeared in these
traces; it does not mean that the agent is safe or that the traces are complete.

## What is read

Each trace file is an OTLP/JSON trace export: either one `ExportTraceServiceRequest`
object (`{"resourceSpans": [...]}`) or JSON Lines with one such object per line, as the
OpenTelemetry Collector's `file` exporter writes. The form is detected from the bytes: a
file whose first non-blank line is a complete JSON value and which has more non-blank
lines is JSON Lines; any other file must be one JSON document. Files are opened like
inventories (no symbolic link, FIFO, device or directory) and parsed as strict JSON:
duplicate keys, `NaN` and `Infinity`, lone surrogates and integers beyond 2^53 are
refused. OTLP/JSON writes 64-bit integers such as `startTimeUnixNano` as decimal
strings; a file that writes a nanosecond timestamp as a bare JSON number is refused.
Every level that is read is type-checked, and a malformed structure is an error that
names the file's position, the line for JSON Lines and the JSON path of the problem,
never a value from the file.

Only these attributes are read, from span attributes and, beneath them, from resource
attributes; a span's own value wins:

| Attribute | Used for |
|---|---|
| `gen_ai.operation.name`, `mcp.method.name` | What the span is: a tool call (`execute_tool` or `tools/call`), an agent operation (`create_agent` or `invoke_agent`), an MCP client call |
| `gen_ai.tool.name`, `gen_ai.tool.type` | The tool a span names, and its type. A span that names a tool is read as a call to it whatever its operation name or MCP method is, so a missing or custom operation name cannot hide the call |
| `gen_ai.request.model`, `gen_ai.response.model` | The model requested, and the model that answered |
| `gen_ai.provider.name`, legacy `gen_ai.system` | The model's provider; `gen_ai.system` is used, and counted, only when `gen_ai.provider.name` is absent |
| `gen_ai.agent.id`, `gen_ai.agent.name`, `gen_ai.agent.version` | The agent an agent operation names. A span whose `gen_ai.operation.name` is not a value of the convention and that names an agent is read as an agent operation; a span of another known operation, such as `chat`, may carry the name of the agent it runs in and is not |
| `network.transport`, `server.address`, `server.port`, `mcp.protocol.version` | The remote endpoint of an MCP client call |
| `gen_ai.skill.name`, `gen_ai.data_source.id`, `gen_ai.memory.store.id`, `gen_ai.prompt.name` | Identifiers reported for information |
| `service.name` (resource attributes only) | Which service reported each item |

A span carries GenAI or MCP semantics only when its own attributes include a `gen_ai.*`
or `mcp.*` key. Resource attributes apply beneath such spans but never make a span
count: an agent name set for the whole process does not stand in for spans from which
the GenAI instrumentation is missing. Nothing is extracted from a span without such a
key; it is counted under `spans_ignored`.

Values must be strings (`stringValue`), except `server.port`, which may also be an
`intValue`, written as a decimal string or a JSON number. A value is used only when it
is a string of at most 512 characters. Surrounding spaces, tabs and line breaks are
trimmed, and identifiers are reported and compared after trimming. Names are compared
by their raw text: an inventory name that collection
[neutralized](known-limitations.md#every-collector) is matched only by a reported name
whose raw text has the SHA-256 the inventory records for it, so a tool collected as
`run<TAB>job` and recorded as `run job` matches a span that reports `run<TAB>job`, not
one that reports `run job`. Both names are trimmed first, so a tool collected as
`lookup<TAB>` matches a span that reports `lookup`. A value that the
redactor would change (a known credential format, a credential assignment such as
`token=...`, an authorization scheme such as `Bearer ...`, or a URL with user
information, a path, a query or a fragment) is withheld. Such a value is never printed,
copied or hashed; the item records the field as `null` and names the reason under
`unreadable`: `invalid` (not a nonblank string, or not a port from 1 to 65535),
`oversized` (longer than 512 characters) or `withheld`.

Content attributes are recognized by key and their values are never read, copied,
hashed or printed: `gen_ai.input.messages`, `gen_ai.output.messages`,
`gen_ai.system_instructions`, `gen_ai.tool.definitions`, `gen_ai.tool.call.arguments`,
`gen_ai.tool.call.result`, `gen_ai.tool.description`, `gen_ai.agent.description`,
`gen_ai.main_agent.description`, `gen_ai.skill.description`, `gen_ai.retrieval.*` (except
the number `gen_ai.retrieval.top_k`), `gen_ai.memory.records`, `gen_ai.memory.query.text`,
`gen_ai.prompt.variable.*`, `gen_ai.evaluation.explanation`, every `gen_ai.*_ref`
reference, and the legacy `gen_ai.prompt`, `gen_ai.completion` and their indexed
`gen_ai.prompt.N.*` and `gen_ai.completion.N.*` forms. The spans that carry any of them
are counted, because operators often do not know that their traces hold message or
tool-call content. Every other attribute, span names, span events, links, status,
instrumentation scopes and log records are not read.

An MCP client span (span kind `CLIENT` with `mcp.method.name`) that sets
`server.address` names a remote endpoint when it leaves `network.transport` out or sets
it to any readable value other than `pipe` or `unix`; a transport that is present but
unreadable names no endpoint and fails the gate as an unclassified span; the host is
compared in lower case. A client span with `network.transport` `pipe` or `unix` is local
activity: a trace cannot attribute it to a configured server, so it is counted under
`mcp_client_spans.stdio`. A client span without `server.address` is counted as
unattributed. Spans of other kinds never name an endpoint item, but a tool call on any
span that sets `server.address`, other than over `pipe` or `unix`, is compared only with
the tools served at that address. A tool call whose `network.transport` is present but
unreadable fails the gate as an unclassified span, with or without `server.address`:
read as `pipe` or `unix`, it would not match the tools of a server that has only a
remote endpoint.

## What is extracted

| Kind | From | Identity |
|---|---|---|
| `tool` | `execute_tool` spans and MCP `tools/call` spans | `name`, and `endpoint` (`host:port`, or `host` when no port was reported) when the span sets `server.address` and its transport is not `pipe` or `unix`; `transport` (`pipe` or `unix`) when it is one of those |
| `model` | Spans with `gen_ai.request.model` or `gen_ai.response.model` | `provider` and `model`, the requested name or, without one, the response name; a different response name is listed under `resolved_models` |
| `agent` | `create_agent` and `invoke_agent` spans | `id` and `name` |
| `mcp-endpoint` | Remote MCP client spans | `host` and `port` |
| `skill`, `data-source`, `memory-store`, `prompt` | Any span with their identifier attribute | `name` or `id` |

Each observed item records its span count, the first and last span start time in UTC
from the spans' own `startTimeUnixNano` (to the nanosecond; spans without a start time
are counted but give no time), the trace files it appeared in, the operation and MCP
method names of its spans (a name outside the convention's list is counted as `other`),
the reporting services, and, by kind, the tool types, resolved models, agent versions
or MCP protocol versions.

## Matching rules

Every rule is an exact comparison after trimming; nothing is matched by similarity.

| Kind | Candidates in the inventory | Basis of a match |
|---|---|---|
| `tool` | `tool` components with the same `name`. When the span names a remote endpoint, only the tools of MCP servers at that endpoint: servers whose `endpoint_url` has the same host and port or, when none has, the same host and no port; without a reported port, servers on the host. The same name declared on another server does not match, so a call to a server that shadows another server's tool is undeclared. Over `pipe` or `unix`, tools of servers that have only a remote endpoint (an `endpoint_url`, no `command` and a transport other than `stdio`) do not match | `name-and-endpoint` (host and port compared), `name-and-host` (one side states no port) or `name` |
| `model` | `model` components whose `name` or `requested_alias` is the model name, case-sensitive; when both sides state a provider they must agree, compared without regard to case | `name-and-provider` or `name` |
| `mcp-endpoint` | `mcp-server` components whose `endpoint_url` has the same host and port, with the scheme's default port (80 for `http` and `ws`, 443 for `https` and `wss`); when none does, servers on the host whose endpoint states no port. Without a reported port, every server on the host | `host-and-port`, or `host` (one side states no port) |
| `agent` | `agent` components with the same `name`, other than the repository agent inferred without an `agent.yaml` (named `repository`). When the span reports an id and the [agent manifest](agent-manifest.md) declares one, the ids decide: the inventory derives the agent's reference from its declared id | `id` or `name` |
| `skill` | `skill-package` components with the same name | `name` |
| `data-source` | `rag-source` and `data-source` components with the same name | `name` |
| `memory-store` | `memory-store` components with the same name | `name` |
| `prompt` | `prompt-template` components with the same name | `name` |

One candidate is a match. Several are `ambiguous`: listed with up to 10 candidate
references and a count of the rest, neither matched nor undeclared. An ambiguous item
that reports a workload identity or tool definition hash is still compared: it passes
when at least one candidate declares exactly what it reports, and fails the gate as a
mismatch when none does or the value could not be read. No candidate makes a
tool, model, agent or MCP endpoint `undeclared`. A skill, data source, memory store or
prompt without a candidate is an `unmatched_identifier`, for information only, because
the inventory has no reliable key for them yet. An item whose identity includes a value
that was not used (invalid, oversized or withheld) is `unidentified`: it cannot be
compared, and for a tool, model, agent or MCP endpoint it fails the gate like an
undeclared item. A span whose `gen_ai.operation.name` or `mcp.method.name` was not used,
an MCP client span that names a `server.address` but whose `network.transport` was not
used, or a tool call whose `network.transport` was not used, cannot be classified: it
may be a tool or agent call, a call to a remote endpoint, or a call over `pipe` or
`unix`. Such spans are counted under `spans_unclassified` and fail the gate too. So a
value chosen to look like a credential, or one longer than the bound, cannot hide a call
that a span reports. A tool type, a response model beside a requested one, an agent
version, an MCP protocol version or a service name that was not used is counted and left
out, because it decides no match. An attribute that a span leaves out is another
matter: the span then reports less, as the instrumentation chose, and is read as such.

Declared tools, MCP servers, hosted models and named agents that no item names are
`unobserved`. That is information, not a finding: absence from these traces is not
absence from the agent. A stdio MCP server can be observed only through a tool that it
provides, because a trace cannot attribute stdio activity, so it is often unobserved.

An MCP client span need not report `server.port`. Without it, an endpoint is compared
by host alone: a call to another port of a declared host matches that host's servers,
and the basis, `host` for the endpoint and `name-and-host` for its tools, says that no
port was compared. The same holds for a server whose `endpoint_url` states no port and
whose scheme has no default port.

An `endpoint_url` declares a host only when every URL parser reads its authority
alike, as a host and an optional port from 1 to 65535. One with user information, a
backslash or a percent escape, such as `https://approved.example\@other.example`, which
Python reads as `other.example` and a browser or Node client as `approved.example`,
declares no host, so a span to either host is `undeclared`.

IP addresses and host names are compared as text; nothing is resolved, so a span that
reports an address and an inventory that records a host name do not match. A remote MCP
server's tools are declared only in an inventory that records them, such as one that
[`discover-mcp --record`](cli-reference.md#discover-mcp) writes; a static scan of a
repository does not list the tools that a remote server serves.

## The evidence document

`--json-output` prints the evidence and `-o` writes it. The JSON has sorted keys and
sorted lists and no wall-clock time, so the same inputs give the same bytes:

| Key | Content |
|---|---|
| `format` | `nexus-symbiote/trace-evidence/v1` |
| `assurance` | Always `reported` |
| `limitations` | Fixed sentences: what telemetry is, and what a span and its absence do not prove |
| `inputs` | `inventory`: its base name, size, `sha256` of the bytes read, and its `content_digest` with `content_profile` (`nexus-symbiote/inventory-content/v1`; `null` for a document without `metadata` or `components`). `trace_files`: for each file its `index` (its position among the `TRACE_FILE` arguments, from 1), base name, `size`, `sha256`, `form` (`json` or `json-lines`), `records` and `spans`. In both base names, control characters and bytes that are not UTF-8 are replaced by U+FFFD |
| `coverage` | `trace_files`, `records`, `resource_spans`, `spans_read`, `genai_or_mcp_spans` (spans with a `gen_ai.*` or `mcp.*` attribute of their own), `spans_ignored` (the other spans), `operation_names` and `mcp_method_names` (counts by convention value, or `other`), `legacy_attributes`, `spans_with_content_attributes`, `attribute_lists_over_bound`, `unreadable_identifiers` (`invalid`, `oversized`, `withheld`), `spans_without_identifier` (tool and agent spans that name none), `spans_unclassified` (spans whose operation name, MCP method or MCP transport was not used), `mcp_client_spans` (`attributed`, `stdio`, `unattributed`) and `time_range` (`first`, `last`, or `null`) |
| `observed` | The items, each with `kind`, its identity fields, `unreadable` when a field was not used, `span_count`, `first_seen`, `last_seen`, `trace_files`, `operations`, `services` and its kind's details |
| `reconciliation` | `matched` (with `inventory_ref` and `basis`), `undeclared`, `unidentified` (both with `span_count`), `ambiguous` (with `candidates` and `candidates_omitted`), `unobserved` (with the inventory's `inventory_ref`, `kind` and `name`) and `unmatched_identifiers` |
| `gate` | `fail_on`, `passed` and `reasons` |

Identifier text is kept as reported, after trimming, and escaped as JSON. Treat it as
untrusted: escape it before you place it in HTML, Markdown or a shell command.

## Exit codes and the gate

| `--fail-on` | Exit 1 when |
|---|---|
| `undeclared` (default) | A tool, model, agent or MCP endpoint is `undeclared` or `unidentified`, a span cannot be classified (`spans_unclassified`), a tool or agent span names no tool or agent (`spans_without_identifier`), a span or resource has more than 128 attributes (`attribute_lists_over_bound`), or no span carries a GenAI or MCP attribute of its own, so that traces from a pipeline that lost its GenAI instrumentation, or that dropped the identifiers, cannot pass |
| `none` | Never for a gate reason; the evidence and summary still list everything |

A trace file or inventory that cannot be read, a malformed structure and a bound that is
exceeded exit 1 whatever `--fail-on` says. More than 16 trace files, or an output path
that names the inventory, a trace file or the other output, is a usage error (exit 2).

## SARIF

`--sarif` writes SARIF 2.1.0 with one result per undeclared or unidentified tool, model,
agent or MCP endpoint: category `runtime_undeclared`, rule
`nexus_symbiote/runtime_undeclared/high`, level `error`, assurance `reported` and the
status `undeclared` or `unidentified` in its properties. The rule's text holds for both
statuses: its help says that the result comes from the agent's own telemetry, not from
the inventory, and that an unidentified component may or may not be declared, and it
links to this section. Unobserved declarations and informational identifiers are not findings and
are not emitted. Text from the traces is neutralized as the inventory's SARIF export
neutralizes inventory text, and results are anchored to the inventory's path relative
to the working directory, or to `.nexus-symbiote.yaml` when the inventory lies outside
it. Coverage gaps appear as tool execution notifications.

## Privacy

Traces that carry content are sensitive: messages, system instructions, tool arguments
and tool results can hold personal data and secrets. `trace-diff` never reads them, but
the files you pass it still hold them; restrict who can read them and how long you keep
them. Prefer exporting identifiers only. The GenAI semantic conventions (Development
status) ask instrumentations not to capture content by default, and name the
environment variable `OTEL_INSTRUMENTATION_GENAI_CAPTURE_CONTENT` for the opt-in, with
`NO_CONTENT` as the default; keep that default for traces you compare here. With
`EVENT_ONLY` or `SPAN_AND_EVENT`, content goes to span events, which `trace-diff` does
not read, so its count of spans with content attributes does not include that content.

The evidence document and the SARIF file hold the identifiers that the traces report,
such as MCP endpoint host names, model names and agent ids, and the inventory's
component references. Share them as you would share the inventory.

## Limits

| Bound | Value | Beyond it |
|---|---|---|
| Trace files per run | 16 | Usage error |
| Size of one trace file | 64 MiB | The file is refused |
| One JSON Lines line | 16 MiB | The file is refused |
| Spans in all files | 1,000,000 | The run is refused |
| Distinct identifiers recorded in all files: each item, and each service, tool type, resolved model, agent version or protocol version recorded for it | 100,000 | The run is refused |
| Characters in one identifier | 512 | The value is not used and is counted under `unreadable_identifiers`; an item that it would identify is `unidentified`, and a span that it would classify counts under `spans_unclassified` |
| Attributes read per span or resource | 128 | The rest are not read; counted under `attribute_lists_over_bound`, which fails the gate |
| Candidates listed per ambiguous item | 10 | Counted under `candidates_omitted` |
| Undeclared and unidentified items in the summary | 20 | Counted; the evidence document lists them all |

Attributes after the first 128 of a span or resource are not read, even when they name
a tool, so a list longer than that fails the gate with `--fail-on undeclared`: what its
later entries report cannot be compared with the inventory. OpenTelemetry SDKs keep at
most 128 attributes per span by default (`OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT`), so a
producer with default limits never reaches the bound.

A file in the one-object form is parsed whole, and parsed JSON takes far more memory
than its bytes: about 12 times the file's size for typical spans (about 500 MB for a
42 MiB file of 60,000 spans) and up to about 30 times for a file of densely packed small
objects, so a 64 MiB file can need 2 GB of memory and up to a minute to read. JSON Lines
is parsed one line at a time, so only one line of at most 16 MiB is held parsed at once;
prefer it for large exports, and allow 2 GB for a run that reads a large one-object file.

## Walk-through

The repository ships a synthetic trace of the [demo agent](../examples/README.md):
[`examples/traces/demo-agent.otlp.json`](../examples/traces/demo-agent.otlp.json). Its
four spans invoke the agent, chat with a hosted model, call a tool on the remote
`tickets` MCP server and initialize a stdio MCP server; the chat and the tool call
carry synthetic content. From the repository root:

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote trace-diff demo.aibom.json examples/traces/demo-agent.otlp.json
```

```text
Trace evidence: runtime use reported by the agent's own instrumentation; a missing span proves nothing
  Read: trace files 1, spans 4, of which with GenAI or MCP semantics 4
  Observed: 1 agent, 1 mcp-endpoint, 1 model, 1 tool
  Reconciliation: 1 matched, 3 undeclared, 0 unidentified, 0 ambiguous, 2 unobserved, 0 unmatched identifiers
  Undeclared: agent named 'support-research-assistant' (1 span)
  Undeclared: model 'gpt-4o-mini' from provider 'openai' (1 span)
  Undeclared: tool 'search_tickets' on MCP endpoint mcp.example.com:443 (1 span)
  Note: Spans with message, prompt or tool-call content attributes: 2. Protect these trace files.
  Note: MCP client spans over a pipe or unix socket: 1. A trace cannot attribute local activity to a configured server.
Trace gate failed: 3 reported tool, model, agent or MCP endpoint items are not declared in the inventory
```

The command exits 1. The endpoint `mcp.example.com:443` matches the `tickets` server
that `.mcp.json` declares, but the inventory lists no tools for that remote server, so
the `search_tickets` call is undeclared. The demo has no `agent.yaml`, so neither the
agent's name nor its hosted model is declared; an [agent manifest](agent-manifest.md)
that names the agent and the model would declare both. The A2A agent card names the
same agent, but a card is not an agent declaration. The `memory` and `notes` stdio
servers are unobserved: the stdio span cannot be attributed to either.

Write the evidence and SARIF for review or code scanning:

```bash
nexus-symbiote trace-diff demo.aibom.json examples/traces/demo-agent.otlp.json \
  --json-output -o trace-evidence.json --sarif trace.sarif
```

The `reconciliation` section of `trace-evidence.json` holds:

```json
{
  "ambiguous": [],
  "matched": [
    {
      "basis": "host-and-port",
      "host": "mcp.example.com",
      "inventory_ref": "mcp-server:3311f839ab71d55753e1b96e77b73367d8f010b87be713f8b592f31e23f82a82",
      "kind": "mcp-endpoint",
      "port": "443"
    }
  ],
  "undeclared": [
    {
      "id": null,
      "kind": "agent",
      "name": "support-research-assistant",
      "span_count": 1
    },
    {
      "kind": "model",
      "model": "gpt-4o-mini",
      "provider": "openai",
      "span_count": 1
    },
    {
      "endpoint": "mcp.example.com:443",
      "kind": "tool",
      "name": "search_tickets",
      "span_count": 1
    }
  ],
  "unidentified": [],
  "unmatched_identifiers": [],
  "unobserved": [
    {
      "inventory_ref": "mcp-server:c56be5e8e4f376d7d44d2f3af332507c8c938032e49a4d816d2de33334af242f",
      "kind": "mcp-server",
      "name": "memory"
    },
    {
      "inventory_ref": "mcp-server:da7146a8034e04b49f26a150811b1283ef7e3fa0c3b40353a73a5ac045d8d032",
      "kind": "mcp-server",
      "name": "notes"
    }
  ]
}
```

`trace.sarif` holds three `nexus_symbiote/runtime_undeclared/high` results anchored to
`demo.aibom.json`, and no synthetic message or tool-call content appears in either file.
To report without failing, for example while you add declarations, pass
`--fail-on none`: the summary then ends with `Trace gate: not applied (--fail-on none)`
and the command exits 0.

In CI, export the agent's traces from a test run with the Collector's `file` exporter,
scan the checkout, and run `trace-diff` against both; keep the trace files where the
change under review cannot rewrite them, as for [reviewed snapshots](drift-gate.md).
