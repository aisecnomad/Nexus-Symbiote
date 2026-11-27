<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-Symbiote/main/docs/assets/nexus-symbiote-banner.jpg" alt="Nexus SymBiote: an Agent Bill of Materials for AI agent supply chains">
</p>

<h1 align="center">Nexus SymBiote</h1>

<p align="center">
  <strong>Know what your AI agents are built from. Gate them on evidence. Catch drift before it ships.</strong>
</p>

<p align="center">
  <a href="https://github.com/aisecnomad/Nexus-Symbiote/actions/workflows/ci.yml"><img src="https://github.com/aisecnomad/Nexus-Symbiote/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/aisecnomad/Nexus-Symbiote/actions/workflows/codeql.yml"><img src="https://github.com/aisecnomad/Nexus-Symbiote/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL"></a>
  <a href="https://github.com/aisecnomad/Nexus-Symbiote/blob/main/pyproject.toml"><img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB?logo=python&amp;logoColor=white" alt="Python 3.11 | 3.12 | 3.13 | 3.14"></a>
  <a href="https://github.com/aisecnomad/Nexus-Symbiote/blob/main/LICENSE"><img src="https://img.shields.io/github/license/aisecnomad/Nexus-Symbiote" alt="MIT license"></a>
  <a href="#project-status"><img src="https://img.shields.io/badge/status-alpha-orange" alt="Status: alpha"></a>
  <a href="#what-it-produces"><img src="https://img.shields.io/badge/exports-CycloneDX%201.7%20%7C%20SPDX%203.0.1%20%7C%20SARIF%20%7C%20VEX-0B7285" alt="Exports: CycloneDX 1.7, SPDX 3.0.1, SARIF, VEX"></a>
</p>

<p align="center">
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="#why"><b>Why</b></a> ·
  <a href="#how-it-works"><b>How it works</b></a> ·
  <a href="#ci-integration"><b>CI</b></a> ·
  <a href="https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/README.md"><b>Docs</b></a> ·
  <a href="#project-status"><b>Status</b></a>
</p>

Nexus SymBiote generates an **Agent Bill of Materials (AgentBOM)** — an evidence-backed inventory of the MCP servers, models, instruction files, retrieval sources, A2A cards, IDE agent settings, packages, and container images an AI agent is assembled from. It inspects projects **statically and offline by default** without executing them, gates on risk and supply-chain drift, and exports to **CycloneDX 1.7**, **SPDX 3.0.1**, **SARIF 2.1.0**, and **VEX**.

```bash
nexus-symbiote scan ./my-agent --no-project-policy --accept-default-exclude root:.git -o agentbom.json
nexus-symbiote risk agentbom.json --no-project-policy --threshold 50
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert
```

> **Alpha.** Interfaces, formats, and policy semantics may change. Not related to the 2022 Linux malware *Symbiote*. Review [known detection gaps](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/known-limitations.md) and [what results do and do not establish](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/security-model.md#what-results-do-and-do-not-establish) before using outputs in approval decisions.

## Quick start

### Install from reviewed source

Requires git and Python 3.11–3.14 on Linux or macOS (Windows fails closed by design; see [platforms](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/SECURITY.md#platforms)). Replace `REVIEWED_COMMIT_SHA` with the full 40-character commit SHA you reviewed and run as one block:

```bash
(
  set -euo pipefail
  reviewed_commit='REVIEWED_COMMIT_SHA'
  [[ "$reviewed_commit" =~ ^[0-9a-f]{40}$ ]]
  git clone https://github.com/aisecnomad/Nexus-Symbiote.git
  cd Nexus-Symbiote
  git checkout --detach "$reviewed_commit"
  test "$(git rev-parse HEAD)" = "$reviewed_commit"
  python3 -m venv --clear .venv
  .venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-action.lock
  .venv/bin/python -m pip install --no-deps --no-build-isolation .
  .venv/bin/nexus-symbiote --version
)
```

Activate with `cd Nexus-Symbiote && . .venv/bin/activate`. Optional extras: `.[sigstore]`, `.[cyclonedx]`, or `.[all]`. For contributors, run `make install-locked` (see [CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CONTRIBUTING.md)).

### Install a verified release

Requires Python 3.11–3.14, git, curl, and the [GitHub CLI](https://cli.github.com/) (`gh auth login`). Downloads the published `v0.2.0` wheel, verifies its GitHub build attestation against the signed `v0.2.0` tag commit, and installs the hash-locked runtime:

```bash
(
  set -euo pipefail
  python3 -m venv --clear .venv
  commit="$(git ls-remote https://github.com/aisecnomad/Nexus-Symbiote.git 'refs/tags/v0.2.0^{}' | cut -f1)"
  test -n "$commit" || { echo "tag v0.2.0 not found" >&2; exit 1; }
  .venv/bin/python -m pip download --no-deps --only-binary=:all: nexus-symbiote==0.2.0 -d dist
  gh attestation verify dist/nexus_symbiote-0.2.0-py3-none-any.whl --repo aisecnomad/Nexus-Symbiote \
    --signer-workflow aisecnomad/Nexus-Symbiote/.github/workflows/release.yml \
    --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners
  curl -fsSL -o requirements-action.lock \
    "https://raw.githubusercontent.com/aisecnomad/Nexus-Symbiote/$commit/requirements-action.lock"
  .venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-action.lock
  .venv/bin/python -m pip install --no-deps dist/nexus_symbiote-0.2.0-py3-none-any.whl
  .venv/bin/nexus-symbiote --version
)
```

See [Releasing](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/releasing.md) for attestation details and offline verification with `--bundle`.

### Try it in 60 seconds

From a [reviewed source checkout](#install-from-reviewed-source), inventory the bundled [demo agent](https://github.com/aisecnomad/Nexus-Symbiote/tree/main/examples/demo-agent) completely offline:

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
nexus-symbiote risk demo.aibom.json --no-project-policy
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy
```

The scan records 11 components across 9 types and eleven findings (risk score 41, below the default threshold of 50). `validate` exits 1 intentionally: completeness passes, but the model's integrity stays `UNKNOWN` without an operator-owned [signer policy](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/model-integrity.md#operator-signature-policy).

Pin the model digest in a policy outside the checkout (using a trusted digest in production):

```bash
policy_dir="$(mktemp -d)"   # must lie outside the scanned repository
digest="$(sha256sum examples/demo-agent/models/intent-classifier.safetensors | cut -d' ' -f1)"
printf '{"version": 2, "artifacts": [{"kind": "digest-pin", "expected_sha256": "sha256:%s",
  "artifact_path": "models/intent-classifier.safetensors"}]}\n' "$digest" > "$policy_dir/signers.json"
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy \
  --signature-policy "$policy_dir/signers.json"
```

`validate` now exits 0. Continue with the [offline examples walkthrough](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/examples/README.md) (drift, exports, ShadowScan import, OTLP traces) or the [public-agent tutorial](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md).

### Scan your own agent

```bash
nexus-symbiote scan /path/to/agent --no-project-policy --accept-default-exclude root:.git -o agentbom.json
nexus-symbiote validate agentbom.json --project /path/to/agent --no-project-policy --accept-default-exclude root:.git
nexus-symbiote risk agentbom.json --project /path/to/agent --no-project-policy --accept-default-exclude root:.git --threshold 50
```

Checkout policies (`.nexus-symbiote.yaml`) automatically tighten gates, require `--accept-project-policy` for relaxations, and are ignored with `--no-project-policy`. Passing `--project` forces fresh local evidence collection and fails on any mismatch.

## Why

**AI agents are assembled from parts traditional SBOMs never see** — MCP servers, model weights, prompts and skills, retrieval stores, A2A cards, and IDE permissions — all of which can alter behavior without a code review (see [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) ASI04).

| Supply-chain risk | What Nexus SymBiote does |
| --- | --- |
| **Floating dependencies** | Flags unpinned MCP packages (`@latest`) and container images lacking digest pins |
| **Tool rug pulls** | Fingerprints MCP tool definitions via RFC 8785 JCS ([live observations](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/offline-and-live-modes.md#detect-drift-on-a-remote-mcp-server) and declared static tools) so changes fire critical drift alerts |
| **Endpoint & scope widening** | Raises critical/high drift alerts when MCP or A2A hosts move or OAuth scopes expand |
| **Unsafe or unsigned weights** | Classifies model formats without loading them, validates SafeTensors headers, and keeps integrity `UNKNOWN` until verified by your [signer policy](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/model-integrity.md#operator-signature-policy) |
| **Hidden prompt injection** | Detects bidi/zero-width/tag characters and hidden HTML/Markdown comments in instructions and tool metadata |
| **Over-broad IDE permissions** | Flags `bypassPermissions`, blanket allow rules (`Bash(*)`), risky hooks, and unapproved settings drift |
| **Credential exposure** | Records secret names only, redacts known token patterns, and flags hardcoded literals |

Every control has explicit bounds: see [known limitations](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/known-limitations.md) and the [security model](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/security-model.md).

## How it works

```text
             ┌──────────────────────────────────────────────┐
  agent      │ 9 static collectors (nothing is executed)    │
  project ──>│ mcp · model · prompt · rag · registry        │
 (read-only) │ a2a · ide_agents · agents · shadowscan                │
             └──────────────────────┬───────────────────────┘
                                    v
             ┌──────────────────────────────────────────────┐
             │ AgentBOM (native JSON)                       │
             │ components · relationships · findings        │
             │ coverage, gaps, and assurance per claim      │
             └──────┬───────────────┬───────────────┬───────┘
                    v               v               v
             validate · risk       diff          exports
             gates (exit 0/1)  drift alerts   CycloneDX · SPDX
                                               SARIF · VEX
```

1. **Collect** — Confined, descriptor-relative, size-bounded reads emit components, findings, and coverage claims.
2. **Assemble** — Merges evidence into one deterministic AgentBOM keeping `declared`, `observed`, and `verified` distinct.
3. **Gate** — `validate` reconciles completeness, digests, bindings, and operator signer policies; `risk` enforces thresholds and severity cutoffs; `diff --fail-on-alert` gates drift against a reviewed baseline. Gaps fail closed.
4. **Export** — Emits schema-validated CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0, and VEX from the exact same collection.

### Built-in collectors

| Collector | Surface | Records |
| --- | --- | --- |
| `mcp` | MCP clients & servers | Launchers, package pins, transports, endpoints, static tool declarations & fingerprints |
| `model` | Model weights | File SHA-256, serialization safety, SafeTensors headers, signature status |
| `prompt` | Instructions & skills | Content digests, `@path` imports, hidden-character and hidden-markup findings |
| `rag` | RAG & vector stores | Retrieval sources, store/index/embedding identities, URI origins, guardrail/eval digests |
| `registry` | Packages & images | [AI package catalog](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/registry-collector.md#ai-package-catalog) pins, lockfile integrity, container digests, index redirects |
| `a2a` | A2A agent cards | Endpoints, security schemes, OAuth scopes, card signature status |
| `ide_agents` | IDE agent settings | Permission modes, blanket grants, hook commands, settings digests |
| `agents` | Agents built in source | Framework agents (LangGraph, CrewAI, OpenAI Agents, Claude Agent SDK, Google ADK, Pydantic AI, Vercel AI SDK, n8n) with their models, tools and capabilities, credential names, datasets |
| `shadowscan` | [ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) reports | Imported discovery claims kept separate from local evidence |

Nothing read is executed, imported, or loaded. Omitting a collector via `--scanner` records it as `unknown`, never clean. Full path coverage: [collector reference](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/collectors.md).

### Key commands

| Command | Purpose |
| --- | --- |
| `scan` | Inventory a project into native JSON, CycloneDX, SPDX, or SARIF |
| `validate` / `risk` | Enforce completeness, integrity, signer policy, and [risk policy](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/policy-reference.md) gates |
| `diff` / `diff-instructions` | Gate [supply-chain drift](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/drift-gate.md#what-the-alerts-mean) and instruction-scope changes |
| `digest` / `attest` / `verify-attestation` | Compute [content digests](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/reproducible-inventories.md#the-content-digest) and sign/verify DSSE [inventory attestations](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/inventory-attestation.md) |
| `trace-diff` / `audit-control-plane` / `trifecta` | Compare [OTLP traces](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/trace-evidence.md), audit hooks/bridges/steering surfaces, and flag lethal trifectas |
| `crosswalk` / `minimum-elements` / `graph` | Map [compliance frameworks](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/framework-crosswalk.md), check [G7 minimum elements](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/minimum-elements.md), and render offline [HTML graphs](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/graph-view.md) |
| `export-standard` / `export-policy` / `vex` | Export typed CycloneDX/SPDX, default-deny Cedar/Rego policies, and VEX triage |
| `verify-artifact` / `verify-discovery` / `import-shadowscan` | Verify local digests/Sigstore bundles and import/verify ShadowScan reports |
| `runtime keygen/sign/verify/…` | Manage signed [runtime contracts](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/runtime-contract-reference.md) |
| `discover-mcp` / `verify-live` / `advisories` | Opt-in **live mode** MCP observation, pinned stdio verification, and OSV lookups |

Exit codes: `0` passed, `1` gate/input failure, `2` usage error (`--detailed-exit-codes` splits `3` gate vs `4` input/internal). Full reference: [CLI reference](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/cli-reference.md).

### What it produces

| Output | Command | Use it for |
| --- | --- | --- |
| Native AgentBOM JSON | `scan` (default) | Full-fidelity record ([schemas](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/schemas/README.md)) |
| CycloneDX 1.7 / SPDX 3.0.1 | `scan -f cyclonedx\|spdx` | SBOM tooling; schema-validated with digest-bound native recovery ([standard exports](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/standard-exports.md)) |
| SARIF 2.1.0 | `scan -f sarif` | GitHub Code Scanning and SARIF viewers |
| CycloneDX VEX | `vex` | Triage statements (`in_triage`) and operator VEX decisions |
| Graph / Crosswalk / Attestation | `graph` · `crosswalk` · `attest` | Offline HTML exposure paths, compliance mappings, DSSE/in-toto signatures |

## CI integration

### GitHub Action

Pin to a reviewed 40-character commit SHA, keep permissions read-only, and set a job timeout:

```yaml
name: Agent inventory
on: [push, pull_request]
permissions:
  contents: read
jobs:
  inventory:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: aisecnomad/Nexus-Symbiote@<reviewed-40-character-commit-sha>
        with:
          scan-path: .
          output-file: agentbom.json
          validate: 'true'
          risk-check: 'true'
          risk-threshold: '50'
          fail-on-severity: 'high'
```

The Action installs its own hash-locked runtime off `PATH`, ignores checkout policies, and defaults `fail-on-severity` to `high`. Details on signer policies, SARIF upload, and gate outputs: [GitHub Action guide](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/github-action.md) and [action.yml](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/action.yml).

### Gate drift in CI

Approve a baseline on the protected branch and compare every pull request against it using a secret binding key (32+ chars) kept outside the checkout:

```bash
export NEXUS_SYMBIOTE_SOURCE_BINDING_KEY="$AGENTBOM_BINDING_KEY"

# On the protected branch (via a reviewed PR): approve the baseline
mkdir -p .nexus-symbiote
nexus-symbiote baseline . --no-project-policy --accept-default-exclude root:.git -o .nexus-symbiote/reviewed.json

# In the pull-request job: always read the baseline from the base commit, never the PR
BASE_SHA="${BASE_SHA:-origin/main}"
git show "$BASE_SHA:.nexus-symbiote/reviewed.json" > "$RUNNER_TEMP/reviewed.json"
nexus-symbiote scan . --no-project-policy --accept-default-exclude root:.git -o "$RUNNER_TEMP/agentbom.json"
nexus-symbiote diff "$RUNNER_TEMP/reviewed.json" "$RUNNER_TEMP/agentbom.json" --fail-on-alert
```

Without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, redacted arguments, environment values, and same-host paths raise medium unbound-value alerts so silent widening cannot pass. See [source binding](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/verification-source-binding.md), [Gate drift in CI](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/drift-gate.md), and [inventory attestation](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/inventory-attestation.md#gate-a-pull-request-on-an-attested-baseline).

### Policy and live mode

Every command is **offline by default**. Only `discover-mcp`, `advisories`, and `verify-live` access the network/processes, and only with `--live` or `NEXUS_SYMBIOTE_MODE=live` ([offline and live modes](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/offline-and-live-modes.md)). Generate `.nexus-symbiote.yaml` with `nexus-symbiote init` ([policy reference](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/policy-reference.md)). Optional [pre-commit hooks](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/cli-reference.md#pre-commit-hooks) are a local convenience, not a security control.

## Documentation

Browse the full [documentation hub](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/README.md) or jump straight to your goal:

| Goal | Start here |
| --- | --- |
| **Get hands-on** | [Offline demo](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/examples/README.md) · [Scanning a public agent](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md) |
| **Understand trust & limits** | [Security model](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/security-model.md) · [Architecture](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/architecture.md) · [Threat model](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/threat-model.md) · [Known limitations](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/known-limitations.md) |
| **Wire into CI** | [GitHub Action](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/github-action.md) · [Gate drift in CI](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/drift-gate.md) · [Inventory attestation](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/inventory-attestation.md) · [Container image](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/container-image.md) |
| **Look up CLI & schema details** | [CLI reference](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/cli-reference.md) · [Collectors](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/collectors.md) · [Finding catalog](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/finding-catalog.md) · [Policy](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/policy-reference.md) · [Collection limits](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/collection-limits.md) |
| **Compliance & exports** | [Standard exports](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/standard-exports.md) · [Framework crosswalk](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/framework-crosswalk.md) · [G7 minimum elements](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/minimum-elements.md) |
| **Integrate discovery & runtime** | [ShadowScan integration](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/shadowscan-integration.md) · [Trace evidence](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/trace-evidence.md) · [Runtime assurance](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/runtime-assurance.md) |
| **Release & operate** | [Releasing](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/releasing.md) · [Repository controls](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/repository-controls.md) · [Operational guidance](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/operational-guidance.md) |

## Project status

**Alpha** with a single maintainer: APIs, schemas, and policy defaults may evolve. CI tests Python 3.11–3.14 on Linux and macOS against hash-locked dependencies and declared floors, with CodeQL, OSV advisory checks, and attested releases ([releasing](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/releasing.md)). See the [roadmap](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/ROADMAP.md) and [changelog](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CHANGELOG.md).

Companion discovery engine: [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) discovers agents across broad infrastructure; Nexus SymBiote verifies local artifacts, builds evidence-backed AgentBOMs, and enforces CI gates.

## Security & contributing

- **Security:** Report vulnerabilities privately via [SECURITY.md](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/SECURITY.md) — never in a public issue.
- **Contributing:** PRs for collector coverage, regression fixtures, and docs are welcome. Read [CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CONTRIBUTING.md), [GOVERNANCE.md](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/GOVERNANCE.md), and the [Code of Conduct](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CODE_OF_CONDUCT.md).
- **Citation:** Use [CITATION.cff](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CITATION.cff) or GitHub's **Cite this repository** button.

## License

[MIT](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/LICENSE) © 2026 Emmanuel Dahunsi (AISecNomad). Vendored upstream schemas under `src/nexus_symbiote/generators/schemas/vendor/` retain their licenses: CycloneDX ([Apache-2.0](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/src/nexus_symbiote/generators/schemas/vendor/LICENSE-APACHE-2.0.txt)) and SPDX 3.0.1 ([Community-Spec-1.0 / CC-BY-3.0](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/src/nexus_symbiote/generators/schemas/vendor/LICENSE-SPDX-3.0.1.txt)); see [NOTICE.txt](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/src/nexus_symbiote/generators/schemas/vendor/NOTICE.txt). Package license expression: `MIT AND Apache-2.0 AND Community-Spec-1.0 AND CC-BY-3.0`.
