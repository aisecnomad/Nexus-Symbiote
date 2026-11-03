# Examples

## Offline demo

[`demo-agent/`](demo-agent) is a small, synthetic agent project: a support
assistant with three MCP servers, an instruction file, a model file, a retrieval
source, an A2A agent card, a container image and a coding-agent configuration.
It exists to be inventoried. Nothing in it is installed, built or run, and the
whole walkthrough below works without network access or credentials.

For a target you did not author, see the tutorial on
[scanning a public agent project](../docs/tutorials/scanning-a-public-agent.md):
it walks through the same inventory against a real open-source repository
pinned to a reviewed revision.

Run it from a repository checkout (the wheel does not include the examples):

```bash
git clone https://github.com/Hunzee-VC/Nexus-Symbiote && cd Nexus-Symbiote
python -m venv .venv && . .venv/bin/activate && pip install .
```

### 1. Inventory the project

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
```

All eight collectors complete and record 11 components across 9 types. The scan
passes the default gate (exit 0) with a risk warning: score 33, below the default
fail threshold of 50, from three high and three medium findings:

| Severity | Component | Finding |
|---|---|---|
| high | `memory` MCP server | Unpinned package reference (`@latest`) |
| high | `models/intent-classifier.safetensors` | No verified, artifact-bound signature |
| high | `ollama/ollama:latest` container image | No immutable digest pin |
| medium | `notes` and `memory` MCP servers | stdio transport: each runs as a local process |
| medium | `product-notes` retrieval source | No declared content-filtering control |

### 2. Check it

```bash
nexus-symbiote risk demo.aibom.json --no-project-policy
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy
```

`risk` passes the default gate. `validate` exits 1. Completeness passes, but
integrity is unknown: no operator signer policy was supplied, so the model's
signature cannot be verified, and unknown evidence never passes. It also warns
that the `memory` package is unpinned and that the remote `tickets` endpoint's
identity is unverified. That is the intended teaching point: an inventory can be
complete and still not be approvable.

### 3. Export standard formats

```bash
nexus-symbiote scan examples/demo-agent -f cyclonedx -o demo.cdx.json
nexus-symbiote scan examples/demo-agent -f spdx -o demo.spdx.json
nexus-symbiote scan examples/demo-agent -f sarif -o demo.sarif
```

### 4. Catch drift

Take a reviewed snapshot of a copy, then make two changes an attacker or a
careless update might make: float the pinned `notes` server, and point `tickets`
at a different host.

```bash
cp -r examples/demo-agent /tmp/demo-agent
nexus-symbiote scan /tmp/demo-agent -o before.json
sed -i.bak -e 's/server-filesystem@2025.8.21/server-filesystem@latest/' \
  -e 's#https://mcp.example.com/mcp#https://mcp.attacker.example/mcp#' \
  /tmp/demo-agent/.mcp.json
nexus-symbiote scan /tmp/demo-agent -o after.json
nexus-symbiote diff before.json after.json --fail-on-alert
```

`diff` reports exactly two changes, a critical alert for the changed `tickets`
endpoint and a high alert for the removed version pin, and exits 1:

```text
Security Alerts:
  [CRITICAL] Critical change in 'tickets': MCP server endpoint changed. Review before execution.; MCP server static source binding changed: launcher, arguments, environment, endpoint or declared tools differ, or the binding key changed. Review before execution.; endpoint_url changed.; properties changed.
  [HIGH] High change in 'notes': Version changed: 2025.8.21 → None; Version pin removed — now floating or unknown.; risks changed.
```

Compare snapshots taken from the same checkout path: an inventory records where
each file was found, so scanning a copy in another directory also reports
location changes.

### 5. Import a discovery report

[Nexus ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) finds agents
across many surfaces; Nexus SymBiote turns its report into an AgentBOM. A recorded
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

The demo declares no exact PyPI or npm package URLs, so `advisories` checks none
and reports that. Point it at your own inventory to query OSV. See
[offline and live modes](../docs/offline-and-live-modes.md).

## Collector demo

From a reviewed checkout of the repository:

```bash
nexus-symbiote scan examples --no-project-policy --report-only -o demo-agentbom.json
nexus-symbiote summary demo-agentbom.json
```

This exercises the eight built-in collectors (`shadowscan`, `mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, `ide_agents`) against the files in this directory. A completed search may report zero matches for some collectors; that is expected and is recorded as coverage information rather than a failure.

Record a ~60 s asciinema of the above commands and link it from the root README once the v0.1.0 tag exists.
