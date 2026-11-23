# Examples

## Offline demo

[`demo-agent/`](demo-agent) is a synthetic agent project: a support assistant with
three MCP servers, an instruction file, a model file, a retrieval source, an A2A
agent card, a container image and a coding-agent configuration. Nothing in it is
installed, built or run. Every step below except optional live step 6 works without
network access or credentials.

For a real repository, see
[scanning a public agent project](../docs/tutorials/scanning-a-public-agent.md).

First complete [install from reviewed source](../README.md#install-from-reviewed-source),
including the reviewed commit and HEAD check. The wheel does not include examples.
After that block succeeds, enter the checkout and activate its environment:

```bash
cd Nexus-Symbiote && . .venv/bin/activate
```

### 1. Inventory the project

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
```

All eight collectors complete and record 11 components across 9 types. The scan
passes the default gate (exit 0) with a risk warning: score 41, below the default
fail threshold of 50, from three high, four medium and four low findings:

| Severity | Component | Finding |
|---|---|---|
| high | `memory` MCP server | Unpinned package reference (`@latest`) |
| high | `models/intent-classifier.safetensors` | No verified, artifact-bound signature |
| high | `ollama/ollama:latest` container image | No immutable digest pin |
| medium | `notes` and `memory` MCP servers | stdio transport: each runs as a local process |
| medium | `notes` MCP server | Exact package pin; dependencies still resolve at launch (`transitive_resolution`) |
| medium | `product-notes` retrieval source | No declared content-filtering control |
| low | `notes` and `tickets` MCP servers, `support-research-assistant` A2A card | Values not bound without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`: a launch argument, an endpoint path |
| low | `product-notes` retrieval source | Source URI path not bound without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` |

### 2. Check it

```bash
nexus-symbiote risk demo.aibom.json --no-project-policy
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy
```

`risk` passes the default gate. `validate` exits 1: completeness passes, but
integrity is unknown — no signer policy was supplied, so the model's signature
cannot be verified, and unknown evidence never passes. It also warns that `memory`
is unpinned and the remote `tickets` endpoint is unverified. This is the teaching
point: an inventory can be complete and still not approvable.

### 3. Export standard formats

```bash
nexus-symbiote scan examples/demo-agent -f cyclonedx -o demo.cdx.json
nexus-symbiote scan examples/demo-agent -f spdx -o demo.spdx.json
nexus-symbiote scan examples/demo-agent -f sarif -o demo.sarif
```

### 4. Catch drift

Take a reviewed snapshot of a copy, then simulate two changes an attacker or
careless update might make: float the pinned `notes` server and point `tickets` at
a different host.

```bash
cp -r examples/demo-agent /tmp/demo-agent
nexus-symbiote scan /tmp/demo-agent -o before.json
sed -i.bak -e 's/server-filesystem@2025.8.21/server-filesystem@latest/' \
  -e 's#https://mcp.example.com/mcp#https://mcp.attacker.example/mcp#' \
  /tmp/demo-agent/.mcp.json
nexus-symbiote scan /tmp/demo-agent -o after.json
nexus-symbiote diff before.json after.json --fail-on-alert
```

`diff` reports exactly two changes, both critical, and exits 1: the changed
`tickets` endpoint, and the floated `notes` package, whose static source binding
records its version and pin and which also names the removed version pin, the
new `version_pinning` finding and the `transitive_resolution` finding that a
floating version no longer carries:

```text
Security Alerts:
  [CRITICAL] Critical change in 'tickets': MCP server endpoint changed. Review before execution.; MCP server static source binding changed: launcher, arguments, environment, endpoint or declared tools differ, or the binding key changed. Review before execution.; properties.static_config_hash changed.; endpoint_url changed.
  [CRITICAL] Critical change in 'notes': MCP server static source binding changed: launcher, arguments, environment, endpoint or declared tools differ, or the binding key changed. Review before execution.; Version changed: 2025.8.21 → None; Version pin removed — now floating or unknown.; Risk findings added: 1 high (version_pinning).; Risk findings removed: 1 medium (transitive_resolution).; properties.static_config_hash changed.; properties.packages changed.; package_url changed.
```

An inventory records paths relative to the project, so a snapshot of one checkout
compares cleanly with a scan of a copy in another directory. In CI, keep the reviewed
snapshot where the change under review cannot rewrite it;
[Gate drift in CI](../docs/drift-gate.md) explains where, how to take comparable
snapshots, and what each alert means.

### 5. Import a discovery report

[Nexus ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) finds agents
across many surfaces; SymBiote turns its reports into AgentBOMs. A recorded
ShadowScan 0.1.4 report ships with the tests:

```bash
nexus-symbiote import-shadowscan tests/fixtures/shadowscan/code-report-0.1.4.json \
  --report-only -o imported.aibom.json
nexus-symbiote verify-discovery imported.aibom.json \
  tests/fixtures/shadowscan/code-report-0.1.4.json --projection
```

Without `--report-only`, `import-shadowscan` writes the inventory and then exits 1
on purpose: imported claims never establish complete, verified coverage.

### 6. Go live (optional, needs network access)

```bash
nexus-symbiote --live advisories demo.aibom.json -o advisories.json
```

The demo's `notes` server has an exact npm package, so `advisories` sends one
identity to OSV (`@modelcontextprotocol/server-filesystem@2025.8.21`); add
`--dry-run` to preview without contacting OSV. See
[offline and live modes](../docs/offline-and-live-modes.md).

### 7. Compare with runtime traces

[`traces/demo-agent.otlp.json`](traces/demo-agent.otlp.json) is a synthetic
OpenTelemetry trace of one demo agent run. `trace-diff` compares reported runtime
use with the inventory, offline:

```bash
nexus-symbiote trace-diff demo.aibom.json examples/traces/demo-agent.otlp.json
```

It exits 1: the trace reports the agent's name, its hosted model and a `search_tickets`
call that the inventory does not declare; the call's endpoint matches the declared
`tickets` server. See [trace evidence](../docs/trace-evidence.md).

## Collector demo

From a reviewed checkout of the repository:

```bash
nexus-symbiote scan examples --no-project-policy --report-only -o demo-agentbom.json
nexus-symbiote summary demo-agentbom.json
```

Exercises all eight collectors against the files in this directory. Zero matches for a collector is coverage information, not a failure.
