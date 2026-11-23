# Examples

## Offline demo

[`demo-agent/`](demo-agent) is a synthetic support-assistant project containing three MCP servers, an instruction file, a SafeTensors model, a RAG source, an A2A card, a Dockerfile, and IDE agent settings. Nothing is installed, built, or executed. Every step below (except optional step 6) runs completely offline without credentials.

For a real third-party repository walkthrough, see [Scanning a public agent project](../docs/tutorials/scanning-a-public-agent.md).

**Prerequisite:** Complete [Install from reviewed source](../README.md#install-from-reviewed-source) (the wheel does not bundle `examples/`), then activate the environment:

```bash
cd Nexus-Symbiote && . .venv/bin/activate
```

### 1. Inventory the project

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
```

All eight collectors complete and record 11 components across 9 types. The scan passes the default gate (exit `0`) with a risk warning: score 41, below the default fail threshold of 50, from three high, four medium and four low findings:

| Severity | Component | Finding |
| --- | --- | --- |
| high | `memory` MCP server | Unpinned package reference (`@latest`) |
| high | `models/intent-classifier.safetensors` | No verified, artifact-bound signature |
| high | `ollama/ollama:latest` container image | No immutable digest pin |
| medium | `notes` and `memory` MCP servers | `stdio` transport runs as an unverified local process |
| medium | `notes` MCP server | Exact pin still resolves transitive dependencies at launch (`transitive_resolution`) |
| medium | `product-notes` retrieval source | No declared content-filtering control |
| low | `notes`, `tickets`, `support-research-assistant`, `product-notes` | Values unbound without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` |

### 2. Validate and risk-gate

```bash
nexus-symbiote risk demo.aibom.json --no-project-policy
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy
```

`risk` exits `0`; `validate` exits `1` intentionally. Completeness passes, but model integrity remains `UNKNOWN` without an operator signer policy — showing that a complete inventory is not automatically approvable.

### 3. Export standard formats

```bash
nexus-symbiote scan examples/demo-agent -f cyclonedx -o demo.cdx.json
nexus-symbiote scan examples/demo-agent -f spdx -o demo.spdx.json
nexus-symbiote scan examples/demo-agent -f sarif -o demo.sarif
```

### 4. Catch supply-chain drift

Snapshot a temporary copy, then float a pinned MCP server and repoint an endpoint:

```bash
demo_copy="$(mktemp -d)"
cp -r examples/demo-agent/. "$demo_copy/"
nexus-symbiote scan "$demo_copy" -o before.json
sed -i.bak -e 's/server-filesystem@2025.8.21/server-filesystem@latest/' \
  -e 's#https://mcp.example.com/mcp#https://mcp.attacker.example/mcp#' \
  "$demo_copy/.mcp.json"
nexus-symbiote scan "$demo_copy" -o after.json
nexus-symbiote diff before.json after.json --fail-on-alert
```

`diff` raises two **CRITICAL** alerts (repointed `tickets` endpoint and floated `notes` package/binding change) and exits `1`. Because inventories record root-relative paths, snapshots compare cleanly across checkout locations. See [Gate drift in CI](../docs/drift-gate.md) for keeping baselines out of PR reach.

### 5. Import a ShadowScan report

[Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) discovers agents across broad surfaces; Nexus SymBiote imports and verifies its reports:

```bash
nexus-symbiote import-shadowscan tests/fixtures/shadowscan/code-report-0.1.4.json \
  --report-only -o imported.aibom.json
nexus-symbiote verify-discovery imported.aibom.json \
  tests/fixtures/shadowscan/code-report-0.1.4.json --projection
```

Without `--report-only`, `import-shadowscan` exits `1` because imported claims never establish complete local verification.

### 6. Query live advisories (optional, requires network)

```bash
nexus-symbiote --live advisories demo.aibom.json -o advisories.json
```

Queries OSV for the exact npm identity `@modelcontextprotocol/server-filesystem@2025.8.21` (add `--dry-run` to preview offline). See [offline and live modes](../docs/offline-and-live-modes.md).

### 7. Compare with OpenTelemetry traces

Compare the inventory against the synthetic trace [`traces/demo-agent.otlp.json`](traces/demo-agent.otlp.json) offline:

```bash
nexus-symbiote trace-diff demo.aibom.json examples/traces/demo-agent.otlp.json
```

Exits `1` because the trace reports an undeclared hosted model and a `search_tickets` call on the declared `tickets` endpoint. See [trace evidence](../docs/trace-evidence.md).
