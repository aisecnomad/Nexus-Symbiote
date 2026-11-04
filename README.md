<p align="center">
  <img src="https://raw.githubusercontent.com/Hunzee-VC/Nexus-Symbiote/main/docs/assets/nexus-symbiote-banner.jpg" alt="Nexus SymBiote: an Agent Bill of Materials for AI agent supply chains">
</p>

<h1 align="center">Nexus SymBiote</h1>

<p align="center">
  <strong>Know what your AI agents are built from. Gate them on evidence. Catch drift before it ships.</strong>
</p>

<p align="center">
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml"><img src="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml"><img src="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/pyproject.toml"><img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB?logo=python&amp;logoColor=white" alt="Python 3.11 | 3.12 | 3.13 | 3.14"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Hunzee-VC/Nexus-Symbiote" alt="MIT license"></a>
  <a href="#project-status"><img src="https://img.shields.io/badge/status-alpha-orange" alt="Status: alpha"></a>
  <a href="#what-it-produces"><img src="https://img.shields.io/badge/exports-CycloneDX%201.7%20%7C%20SPDX%203.0.1%20%7C%20SARIF%20%7C%20VEX-0B7285" alt="Exports: CycloneDX 1.7, SPDX 3.0.1, SARIF, VEX"></a>
</p>

<p align="center">
  <a href="#why"><b>Why</b></a> ·
  <a href="#what"><b>What</b></a> ·
  <a href="#how"><b>How</b></a> ·
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/README.md"><b>Docs</b></a> ·
  <a href="#project-status"><b>Status</b></a>
</p>

Nexus SymBiote generates an **Agent Bill of Materials (AgentBOM)** — an evidence-backed inventory of the MCP servers, models, instructions, retrieval sources, A2A cards, IDE settings and container images an AI agent is assembled from. It reads a project **without running it**, flags supply-chain risk, fails CI on drift, and exports to CycloneDX 1.7, SPDX 3.0.1, SARIF and VEX.

```bash
nexus-symbiote scan ./my-agent --no-project-policy -o agentbom.json    # inventory, offline
nexus-symbiote risk agentbom.json --no-project-policy --threshold 50   # gate on risk
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert        # gate on drift
```

> [!NOTE]
> **Alpha.** Interfaces, formats and policy semantics may change, and no package has been published yet. Install from a reviewed commit, as shown under [How](#how).

## Why

**AI agents are assembled from parts you did not write, and most of those parts never appear in a software bill of materials.**

An agent's behavior depends on its configuration as much as its code — MCP servers, model weights, instruction files, retrieval sources, agent endpoints, IDE permissions — and each can change without a code review. Package SBOMs don't cover these. The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) lists agentic supply-chain vulnerabilities (ASI04) among the top risks.

| Risk | What it looks like | What Nexus SymBiote records |
| --- | --- | --- |
| Floating dependencies | MCP server at `@latest`; image without digest | Unpinned-version and missing-digest findings |
| Tool rug pulls | Tool description or schema changed post-review | RFC 8785 tool fingerprints; drift alerts in `diff` |
| Endpoint repointing | MCP endpoint moved to another host; A2A card URL to HTTP | Critical/high drift alerts |
| Executable model files | Pickle checkpoint; `.safetensors` that isn't one | Format classification without loading; SafeTensors header validation |
| Unsigned weights | Model file with no artifact-bound signature | `UNKNOWN` integrity verdict until signer policy verifies |
| Hidden instructions | Bidi or zero-width characters in `CLAUDE.md` | Invisible-character findings |
| Over-broad permissions | IDE agent granted `Bash(*)` or a permissive default | Declared permissions; drift alert on widening |
| Credential exposure | Tokens in MCP env blocks or connection strings | Env vars by name, never value; known secret patterns redacted |

The full trust model, design principles and offline-by-default enforcement are in the [security model](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md).

## What

**An AgentBOM: one evidence-backed inventory of an agent, with gates, drift checks and standard exports.**

### What it inventories

Eight built-in collectors read declared configuration and artifacts from the project directory. Select a subset with `--scanner`; collectors you leave out are recorded as unknown, not clean.

| Collector | Reads | Records |
| --- | --- | --- |
| `mcp` | MCP config files (`.mcp.json`, `.claude/mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`) and server source | Clients, servers, launchers, pinned versions, transports, endpoints, tool fingerprints |
| `model` | `.safetensors`, `.gguf`, `.ggml`, `.onnx`, Keras (`.h5`, `.hdf5`, `.keras`), `saved_model.pb` and pickle-family files (including `.ckpt`, `.pdparams`, `.dill` and compressed dumps), with their config | SHA-256 hashes, serialization safety, SafeTensors structure, signature status |
| `prompt` | `CLAUDE.md`, `AGENTS.md`, `CODEX.md`, Copilot/Codex instructions, skill and command files | Instruction and skill digests, hidden-character findings |
| `rag` | `rag_config.*`, `retrieval_config.json`, `vector_store_config.json` | Declared retrieval sources and controls |
| `registry` | `package.json`, lockfiles, `requirements*.txt`, `pyproject.toml`, Dockerfiles | AI package identities, pins, lockfile integrity; container images and digests |
| `a2a` | `.well-known/agent-card.json`, legacy agent cards, A2A client config | Preferred interface, advertised transports and endpoint origins, declared authentication |
| `ide_agents` | Settings for Claude Code, Cursor, Codex (including `.codex/config.toml`), Windsurf, Cline, Copilot and others | Agent configuration, declared permissions and approval settings |
| `shadowscan` | [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) reports | Imported discovery claims, kept separate from local evidence |

### What it checks

| Command | What it answers |
| --- | --- |
| `validate` | Is the inventory complete? Do hashes, signatures and source bindings still match? |
| `risk` | What are the findings, and does the score or worst severity cross your gate? |
| `diff` | What changed since the reviewed snapshot? Is any change security-relevant? |
| `verify-artifact`, `verify-discovery` | Do these bytes match a trusted digest, Sigstore identity or ShadowScan report? |
| `blast-radius` | Which agents and components are associated with a compromised component? |
| `runtime keygen/sign/verify` | Are signed snapshots, approvals and trust statements valid for a gateway? |
| `discover-mcp`, `verify-live`, `advisories` | What does a running server actually serve? Do exact versions have known advisories? *(live mode)* |

The [CLI reference](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/cli-reference.md) documents every command and option.

### What it produces

| Output | How to get it | Use it for |
| --- | --- | --- |
| Native AgentBOM JSON | `scan` (default) | Full-fidelity record; defined by the [AgentBOM schema](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/schemas/README.md) |
| CycloneDX 1.7 | `scan -f cyclonedx` | SBOM tooling; validated against the pinned official schema |
| SPDX 3.0.1 | `scan -f spdx` | SPDX tooling; validated against the pinned official schema |
| SARIF 2.1.0 | `scan -f sarif` | GitHub code scanning and other SARIF viewers |
| CycloneDX VEX | `vex` | Findings marked `in_triage`, with no exploitability claim |

Standard exports embed the native inventory in a digest-bound extension. Keep that extension to recover full semantics.

### See it on the demo agent

The bundled [demo agent](https://github.com/Hunzee-VC/Nexus-Symbiote/tree/main/examples/demo-agent) is a small synthetic support assistant. Scanning it records 11 components across 9 types and six findings (risk score 33, below the default fail threshold of 50):

| Severity | Component | Finding |
| --- | --- | --- |
| high | `memory` MCP server | Unpinned package reference (`@latest`) |
| high | `models/intent-classifier.safetensors` | No verified, artifact-bound signature |
| high | `ollama/ollama:latest` container image | No immutable digest pin |
| medium | `notes` and `memory` MCP servers | stdio transport: each runs as a local process |
| medium | `product-notes` retrieval source | No declared content-filtering control |

The [examples walkthrough](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/examples/README.md) reproduces this, adds drift detection, validation, exports and a ShadowScan import — all offline.

### What a scan does not prove

A scan is an inventory, not a verdict. It does not show that a model is benign, that a tool's backend matches its description, or that every agent action was mediated. Read [what results do and do not establish](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md#what-results-do-and-do-not-establish) before using results in an approval process. Treat exported BOMs as sensitive.

## How

**Install from a reviewed commit, inventory the agent, then let CI hold the line.**

### Install from reviewed source

Requires Python 3.11+ on Linux. No release has been published yet — install a commit you have reviewed, with the hash-locked runtime:

```bash
git clone https://github.com/Hunzee-VC/Nexus-Symbiote.git
cd Nexus-Symbiote
git checkout --detach REVIEWED_COMMIT_SHA
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements-action.lock
python -m pip install --no-deps --no-build-isolation .
nexus-symbiote --version
```

Optional extras: `.[sigstore]` for Sigstore verification, `.[cyclonedx]` for CycloneDX library integration, `.[all]` for both. For development: `make install-locked` (see [CONTRIBUTING.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CONTRIBUTING.md)).

### Try it in 60 seconds

From the checkout, inventory the bundled demo agent — nothing is executed and no network is used:

```bash
export NEXUS_SYMBIOTE_SOURCE_BINDING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
nexus-symbiote risk demo.aibom.json --no-project-policy
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy
```

`validate` exits 1 on purpose: completeness passes, but the model's integrity stays unknown because no signer policy was supplied. An inventory can be complete and still not be approvable.

A2A cards and client declarations need the same operator binding key during collection, comparison and project reconciliation. Keep it outside the scanned checkout, preferably in your CI secret store. Without it, collection still records the inventory but marks A2A values as partial coverage and default gates fail. The keyed binding detects changed endpoint paths, credentials and authentication declarations without exporting those values. See [source binding and migration](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/verification-source-binding.md).

### Scan your own agent

```bash
nexus-symbiote scan /path/to/agent --no-project-policy -o agentbom.json
nexus-symbiote validate agentbom.json --project /path/to/agent --no-project-policy
nexus-symbiote risk agentbom.json --project /path/to/agent --no-project-policy --threshold 50
```

With `--project`, `risk` collects fresh evidence and refuses to score a BOM that disagrees with it. The [public-agent tutorial](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md) walks through a real repository end to end.

### Gate drift in CI

Record a reviewed snapshot once, then compare every new collection:

```bash
nexus-symbiote baseline /path/to/agent -o reviewed.json
nexus-symbiote scan /path/to/agent --no-project-policy -o agentbom.json
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert
```

`--fail-on-alert` fails on any security-relevant change rated medium or higher. A baseline is unsigned — review it before treating it as an approval.

### GitHub Action

Pin the Action to a reviewed 40-character commit:

```yaml
name: Agent inventory
on: [push, pull_request]
permissions:
  contents: read
jobs:
  inventory:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false
      - uses: Hunzee-VC/Nexus-Symbiote@<reviewed-40-character-commit-sha>
        env:
          NEXUS_SYMBIOTE_SOURCE_BINDING_KEY: ${{ secrets.NEXUS_SYMBIOTE_SOURCE_BINDING_KEY }}
        with:
          scan-path: .
          output-file: agentbom.json
          validate: 'true'
          risk-check: 'true'
          risk-threshold: '50'
          sarif-upload: 'false'
```

The Action installs its own hash-locked runtime, ignores policy in the scanned checkout, and fails on collection errors. Set `sarif-upload: 'true'` and add `security-events: write` for SARIF upload. Inputs and outputs are in [action.yml](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/action.yml). The repository also ships [pre-commit hooks](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/.pre-commit-hooks.yaml) (`nexus-symbiote-scan` and `nexus-symbiote-risk`).

Every command is offline by default. Only `discover-mcp`, `advisories` and `verify-live` reach the network, and only with `--live`. Use `nexus-symbiote init` to generate a `.nexus-symbiote.yaml` policy file for a trusted project, or pass `--no-project-policy` when the checkout is not yours. Details are in [offline and live modes](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/offline-and-live-modes.md).

### How it works

```text
             ┌──────────────────────────────────────────────┐
  agent      │ 8 static collectors: nothing is executed     │
  project ──>│ mcp · model · prompt · rag · registry        │
 (read-only) │ a2a · ide_agents · shadowscan                │
             └──────────────────────┬───────────────────────┘
                                    v
             ┌──────────────────────────────────────────────┐
             │ AgentBOM (native JSON)                       │
             │ components · relationships · findings        │
             │ coverage, gaps and assurance for every claim │
             └──────┬───────────────┬───────────────┬───────┘
                    v               v               v
             validate · risk       diff          exports
             gates, exit 0/1   drift alerts   CycloneDX · SPDX
                                               SARIF · VEX
```

1. **Collect.** Each collector reads its surfaces through confined, size-bounded file reads and returns components, findings and coverage status.
2. **Assemble.** Results merge into one AgentBOM. Every claim keeps its assurance level: declared, observed or verified.
3. **Gate.** `validate` checks completeness and integrity; `risk` scores findings against your policy. Unknown evidence fails closed.
4. **Compare.** `diff` compares two snapshots semantically and rates each change.
5. **Export.** Standard formats are generated from the same collection, so every export describes the same evidence.

### Exit codes

| Exit | Meaning |
| --- | --- |
| `0` | The command completed and every requested gate passed |
| `1` | A gate or check failed (risk, integrity, drift, incomplete collection, or unreadable input) |
| `2` | Usage error, including a live command run in offline mode |

## Documentation

The [documentation hub](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/README.md) organizes every guide by Why, What and How. Start here:

| If you want to… | Read |
| --- | --- |
| Understand the trust model | [Security model](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md) |
| Run the full offline demo | [Examples walkthrough](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/examples/README.md) |
| Scan a real project end to end | [Scanning a public agent](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md) |
| Look up a command or option | [CLI reference](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/cli-reference.md) |
| Import Nexus-ShadowScan discovery | [ShadowScan integration](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/shadowscan-integration.md) |
| Mediate tool calls with signed contracts | [Runtime assurance](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/runtime-assurance.md) |
| Release or verify a release | [Releasing](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/releasing.md) · [Repository controls](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/repository-controls.md) |

## Project status

Nexus SymBiote is **alpha** with a single maintainer: APIs, formats and policy semantics may change, and there is no SLA. CI, including CodeQL, runs on every push and pull request. Branch protection and PyPI trusted publishing still need administrator action: [issue #74](https://github.com/Hunzee-VC/Nexus-Symbiote/issues/74) records their status, and the [roadmap](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/ROADMAP.md) tracks them with the rest of the planned work. Changes are in the [changelog](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CHANGELOG.md).

[Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) is the companion discovery engine — it finds agents across many surfaces, and Nexus SymBiote turns its reports into AgentBOMs with local artifact and supply-chain verification.

## Security

Report vulnerabilities privately as described in [SECURITY.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md), never in a public issue.

## Contributing

Contributions are welcome — especially tested collector coverage, regression fixtures and documentation. See [CONTRIBUTING.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CONTRIBUTING.md) for setup and review contract, [GOVERNANCE.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/GOVERNANCE.md) for decisions, and [SUPPORT.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SUPPORT.md) for troubleshooting. Please follow the [code of conduct](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CODE_OF_CONDUCT.md).

## Citation

If you use Nexus SymBiote in research or tooling, cite it with the metadata in [CITATION.cff](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CITATION.cff), or use **Cite this repository** on GitHub.

## License

[MIT](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/LICENSE). Copyright (c) 2026 Emmanuel Dahunsi (AISecNomad).
