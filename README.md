<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-Symbiote/main/docs/assets/nexus-symbiote-banner.jpg" alt="Nexus SymBiote: an Agent Bill of Materials for AI agent supply chains">
</p>

<h1 align="center">Nexus SymBiote</h1>

<p align="center">
  <strong>Know what your AI agents are built from. Gate them on evidence. Catch drift before it ships.</strong>
</p>

<p align="center">
  <a href="https://github.com/aisecnomad/Nexus-Symbiote/actions/workflows/ci.yml"><img src="https://github.com/aisecnomad/Nexus-Symbiote/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/aisecnomad/Nexus-Symbiote/actions/workflows/codeql.yml"><img src="https://github.com/aisecnomad/Nexus-Symbiote/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
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

> Not related to Symbiote, the Linux malware of the same name reported in 2022.

Nexus SymBiote generates an **Agent Bill of Materials (AgentBOM)** — an evidence-backed inventory of the MCP servers, models, instructions, retrieval sources, A2A cards, IDE settings and container images an AI agent is assembled from. It reads a project **without running it**, flags supply-chain risk, fails CI on drift, and exports to CycloneDX 1.7, SPDX 3.0.1, SARIF and VEX.

```bash
nexus-symbiote scan ./my-agent --no-project-policy --accept-default-exclude root:.git -o agentbom.json    # inventory, offline
nexus-symbiote risk agentbom.json --no-project-policy --threshold 50   # gate on risk
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert        # gate on drift
```

> **Alpha.** Interfaces, formats and policy semantics may change. Verify the [build attestation before installing a release](#install-a-verified-release), or install a [reviewed commit from source](#install-from-reviewed-source). This release has [known detection gaps](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/known-limitations.md): what the collectors do not record, no gate can alert on.

## Quick start

### Install from reviewed source

**Requires:** git, Python 3.11–3.14, Linux. Installs the exact commit you reviewed with a hash-locked runtime:

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

Replace `REVIEWED_COMMIT_SHA` with the full lowercase commit SHA you reviewed, then paste the block. A failed checkout or mismatched HEAD stops before installation. After it succeeds:

```bash
cd Nexus-Symbiote && . .venv/bin/activate
```

Optional extras: `.[sigstore]` for Sigstore verification, `.[cyclonedx]` for CycloneDX cross-checks, `.[all]` for both. For development: `make install-locked` ([CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CONTRIBUTING.md)).

### Install a verified release

**Requires:** Python 3.11–3.14, git, curl, [GitHub CLI](https://cli.github.com/) (`gh auth login`). Downloads the `v0.1.0` wheel, verifies its attestation against the tagged commit, and installs the hash-locked runtime. (`0.2.0` is in preparation on `main`; use [Install from reviewed source](#install-from-reviewed-source) to run it before publication.)

```bash
(
  set -euo pipefail
  python3 -m venv --clear .venv
  commit="$(git ls-remote https://github.com/aisecnomad/Nexus-Symbiote.git 'refs/tags/v0.1.0^{}' | cut -f1)"
  test -n "$commit" || { echo "tag v0.1.0 not found" >&2; exit 1; }
  .venv/bin/python -m pip download --no-deps --only-binary=:all: nexus-symbiote==0.1.0 -d dist
  gh attestation verify dist/nexus_symbiote-0.1.0-py3-none-any.whl --repo Hunzee-VC/Nexus-Symbiote \
    --signer-workflow Hunzee-VC/Nexus-Symbiote/.github/workflows/release.yml \
    --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners
  curl -fsSL -o requirements-action.lock \
    "https://raw.githubusercontent.com/aisecnomad/Nexus-Symbiote/$commit/requirements-action.lock"
  .venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-action.lock
  .venv/bin/python -m pip install --no-deps dist/nexus_symbiote-0.1.0-py3-none-any.whl
  .venv/bin/nexus-symbiote --version
)
```

Paste the block unchanged. The package is not installed unless the attestation passes. `--repo` and `--signer-workflow` name the Hunzee-VC organization because `v0.1.0` was published while it owned the repository and the attestation certificate records that workflow; the clone, tag lookup and lock download use the current owner. [Releasing](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/releasing.md) describes what the attestation does and does not establish.

### Try it in 60 seconds

Needs the [source install](#install-from-reviewed-source) (the `v0.1.0` wheel has no checkout and does not read the signer policy format used below). From the checkout, inventory the bundled [demo agent](https://github.com/aisecnomad/Nexus-Symbiote/tree/main/examples/demo-agent) — nothing is executed, no network is used:

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
nexus-symbiote risk demo.aibom.json --no-project-policy
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy
```

The scan records 11 components across 9 types and eleven findings (risk score 41, below the default fail threshold of 50). `validate` exits 1 on purpose: completeness passes but the model's integrity stays unknown — no signer policy was supplied. An inventory can be complete and still not be approvable.

To approve the model, pin its digest in a [signer policy](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/model-integrity.md#operator-signature-policy) kept outside the scanned project. Here the digest comes from the checkout to show the mechanism; in real use, take it from a source you trust:

```bash
policy_dir="$(mktemp -d)"   # outside the checkout: a policy inside the repository is refused
digest="$(sha256sum examples/demo-agent/models/intent-classifier.safetensors | cut -d' ' -f1)"
printf '{"version": 2, "artifacts": [{"kind": "digest-pin", "expected_sha256": "sha256:%s",
  "artifact_path": "models/intent-classifier.safetensors"}]}\n' "$digest" > "$policy_dir/signers.json"
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy \
  --signature-policy "$policy_dir/signers.json"
```

`validate` now exits 0. The [examples walkthrough](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/examples/README.md) adds drift detection, exports, a ShadowScan import and a comparison with a synthetic runtime trace, all offline.

### Scan your own agent

```bash
nexus-symbiote scan /path/to/agent --no-project-policy --accept-default-exclude root:.git -o agentbom.json
nexus-symbiote validate agentbom.json --project /path/to/agent --no-project-policy --accept-default-exclude root:.git
nexus-symbiote risk agentbom.json --project /path/to/agent --no-project-policy --accept-default-exclude root:.git --threshold 50
```

Checkout tightenings apply automatically. Pass `--accept-project-policy` to accept reviewed relaxations within the operator policy, or `--no-project-policy` to ignore checkout policy. With `--project`, `validate` and `risk` collect fresh evidence and fail when it disagrees with the BOM. Full walkthrough: [scanning a public agent](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md).

## Why

**AI agents are assembled from parts you did not write, and most of those parts never appear in a software bill of materials.**

An agent's behavior depends on its configuration as much as its code, and each piece can change without a code review. Package SBOMs don't cover MCP servers, model weights, instruction files, retrieval sources, agent endpoints or IDE permissions. The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) lists agentic supply-chain vulnerabilities (ASI04) among the top risks.

| Risk | What Nexus SymBiote does |
| --- | --- |
| Floating dependencies | Flags unpinned MCP packages (`@latest`) and images without digests |
| Tool rug pulls | Fingerprints the tools a [live observation](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/offline-and-live-modes.md#detect-drift-on-a-remote-mcp-server) records, so a changed definition is a critical drift alert; a static scan records declared tools by name and file digest |
| Endpoint repointing, scope widening | Critical or high drift alert when an MCP or A2A endpoint moves host, or an A2A card's OAuth scopes grow |
| Executable or unsigned model files | Classifies formats without loading them and validates SafeTensors headers; integrity stays `UNKNOWN` until your [signer policy](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/model-integrity.md#operator-signature-policy) verifies the weights |
| Hidden instructions | Flags bidi and zero-width characters in instruction files and in declared MCP tool definitions, and text hidden in HTML comments, unused link reference definitions or unreferenced footnotes in instruction files |
| Over-broad agent permissions | Flags `bypassPermissions`, blanket grants such as `Bash(*)` and hook commands; a changed setting is a drift alert, and without the binding key a record whose setting values the redaction removes is a medium drift alert that they are unbound |
| Credential exposure | Records variable names, never values; redacts known secret patterns |

Every row has limits: [known limitations](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/known-limitations.md). Trust model and design principles: [security model](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/security-model.md).

## How it works

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

1. **Collect.** Each collector reads its surfaces through confined, size-bounded file reads and returns components, findings and coverage.
2. **Assemble.** Results merge into one AgentBOM. Every claim keeps its assurance level: declared, observed or verified.
3. **Gate.** `validate` checks completeness, local digests, bindings and operator signer policies. It does not authenticate MCP servers — gate those with `diff --fail-on-alert` against a reviewed baseline ([gates and drift](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/known-limitations.md#gates-and-drift)). `risk` scores findings against your policy. Gaps fail closed.
4. **Compare.** `diff` compares two snapshots semantically and rates each change.
5. **Export.** Standard formats come from the same collection, so every export describes the same evidence.

### Collectors

| Surface | Collector | Records |
| --- | --- | --- |
| MCP servers and clients | `mcp` | Clients, servers, launchers, package pins, transports, endpoints, tool fingerprints |
| Model weights | `model` | SHA-256 of weight files, serialization safety, SafeTensors structure, signature status |
| Instructions and rules | `prompt` | Content digests; hidden-character and hidden-comment findings |
| RAG and vector stores | `rag` | Retrieval sources, store/index/embedding identities, URI origins, control states; digests of guardrail and evaluation configuration files recognised by name |
| Packages and images | `registry` | AI packages in the [catalog](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/registry-collector.md#ai-package-catalog), pins, lockfile integrity, image digests, registry redirects |
| A2A agent cards | `a2a` | Endpoints, security schemes, scopes, card signatures |
| IDE agent settings | `ide_agents` | Permission modes, blanket grants, hooks, settings digests |
| [ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) reports | `shadowscan` | Imported discovery claims, kept separate from local evidence |

Nothing a collector reads is executed, imported or loaded. The `mcp`, `rag` and `a2a` collectors also search source code for SDK references. Select a subset with `--scanner`; omitted collectors are recorded as unknown, not clean. Full reference: [collectors](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/collectors.md).

### Commands

| Command | What it answers |
| --- | --- |
| `scan` | Inventory the project → native JSON, CycloneDX, SPDX or SARIF |
| `validate` | Did every collector finish? Do local digests, bindings and operator signer-policy rules match? |
| `risk` | Does the score or worst severity cross your [policy](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/policy-reference.md)? |
| `diff` | What [changed](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/drift-gate.md#what-the-alerts-mean) since the reviewed snapshot, and how much does it matter? |
| `digest` | Do two inventories record the same [content](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/reproducible-inventories.md#the-content-digest)? |
| `verify-attestation` | Did keys you trust sign exactly this [inventory](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/inventory-attestation.md#what-an-attestation-establishes)? |
| `trace-diff` | Do the agent's traces report something the inventory doesn't [declare](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/trace-evidence.md#trust-model-reported-not-observed)? |
| `minimum-elements` | Which G7 AI SBOM [minimum elements](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/minimum-elements.md) does a CycloneDX export carry? |
| `crosswalk` | Which OWASP, MITRE ATLAS, NIST, EU AI Act and CWE [entries](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/framework-crosswalk.md#what-a-reference-means) apply? |
| `blast-radius` | Which agents and components are associated with a compromised component? |
| `graph` | Self-contained [HTML view](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/graph-view.md) of components, associations and exposure paths |
| `verify-artifact`, `verify-discovery` | Do these bytes match a trusted digest, Sigstore identity or ShadowScan report? |
| `runtime keygen/sign/verify/…` | Are signed [runtime contracts](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/runtime-contract-reference.md) valid, current and canonical? |
| `discover-mcp`, `verify-live`, `advisories` | What does a running server serve? Known advisories? *(live mode)* |

Exit code `0` means every requested gate passed, `1` a gate or check failed or an input could not be read, `2` a usage error. Every command, option and exit condition: [CLI reference](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/cli-reference.md).

### What it produces

| Output | How to get it | Use it for |
| --- | --- | --- |
| Native AgentBOM JSON | `scan` (default) | Full-fidelity record; [AgentBOM schema](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/schemas/README.md) |
| CycloneDX 1.7 | `scan -f cyclonedx` | SBOM tooling; validated against the pinned official schema |
| SPDX 3.0.1 | `scan -f spdx` | SPDX tooling; validated against the pinned official schema |
| SARIF 2.1.0 | `scan -f sarif` | GitHub code scanning and other SARIF viewers |
| CycloneDX VEX | `vex` | Findings marked `in_triage` |
| Graph view | `graph` | Self-contained offline HTML of components and risk paths |
| Framework crosswalk | `crosswalk` | Findings grouped by compliance framework |
| Attestation envelope | `attest` | DSSE/in-toto signature over a reviewed inventory |

Standard exports embed the native inventory in a digest-bound extension; keep it to recover full semantics ([standard exports](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/standard-exports.md)). A scan is an inventory, not a verdict — read [what results do and do not establish](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/security-model.md#what-results-do-and-do-not-establish) before using results in an approval process.

## CI integration

### GitHub Action

Pin the Action to a reviewed 40-character commit, keep the token read-only, and set a job timeout: hostile input can keep a scan running until the job times out.

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

The Action installs its own hash-locked runtime, ignores checkout policy, and reports each gate in its `result` and `gates` outputs. `fail-on-severity` defaults to `high` — a high finding fails even when the aggregate score stays under `risk-threshold`. Full guide: [GitHub Action](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/github-action.md). Inputs and outputs: [action.yml](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/action.yml).

### Gate drift in CI

Approve a baseline once on the protected branch, then compare every pull request with it. The commands below accept the checkout's `.git` metadata. `baseline` writes an unsigned file and `diff` checks no signature, so read the baseline from a place the pull request cannot change:

```bash
# One secret of 32 or more characters, the same for the baseline and every later scan.
export NEXUS_SYMBIOTE_SOURCE_BINDING_KEY="$AGENTBOM_BINDING_KEY"

# On the protected branch, through a reviewed pull request: approve the baseline.
mkdir -p .nexus-symbiote
nexus-symbiote baseline . --no-project-policy --accept-default-exclude root:.git -o .nexus-symbiote/reviewed.json

# In the pull-request job (with fetch-depth: 0 or the base commit fetched): read the
# baseline from the base commit, never from the pull request.
BASE_SHA="${BASE_SHA:-origin/main}"
git show "$BASE_SHA:.nexus-symbiote/reviewed.json" > "$RUNNER_TEMP/reviewed.json"
nexus-symbiote scan . --no-project-policy --accept-default-exclude root:.git -o "$RUNNER_TEMP/agentbom.json"
nexus-symbiote diff "$RUNNER_TEMP/reviewed.json" "$RUNNER_TEMP/agentbom.json" --fail-on-alert
```

`--fail-on-alert` fails on any recorded change rated medium or higher, including a removed component and a coverage regression. Without the binding key, an MCP server whose launch arguments, environment values or endpoint path were not bound is itself a medium alert, so a widened filesystem root cannot pass silently; the alert does not name the new value. Set `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` on both snapshots to compare those values ([source binding](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/verification-source-binding.md)). Run the comparison in a job the pull request cannot edit ([protect the gate](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/drift-gate.md#protect-the-gate)), and sign the reviewed baseline to know who approved it ([inventory attestation](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/inventory-attestation.md#gate-a-pull-request-on-an-attested-baseline)). Full guide: [Gate drift in CI](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/drift-gate.md).

### Policy and live mode

Every command is offline by default. Only `discover-mcp`, `advisories` and `verify-live` reach the network, and only in live mode (`--live` or `NEXUS_SYMBIOTE_MODE=live`). Generate a project policy (`.nexus-symbiote.yaml`) with `nexus-symbiote init`. Stricter project gates apply automatically; review relaxations before passing `--accept-project-policy`. See [policy reference](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/policy-reference.md) and [offline and live modes](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/offline-and-live-modes.md). The [pre-commit hooks](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/cli-reference.md#pre-commit-hooks) are a convenience for your own tree, not a control.

## Documentation

The [documentation hub](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/README.md) organizes every guide by why, what and how. Start here:

| | |
| --- | --- |
| **Understand** | [Security model](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/security-model.md) · [Architecture](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/architecture.md) · [Threat model](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/threat-model.md) · [Known limitations](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/known-limitations.md) |
| **Learn** | [Examples walkthrough](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/examples/README.md) · [Scanning a public agent](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md) |
| **Reference** | [CLI reference](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/cli-reference.md) · [Collectors](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/collectors.md) · [Finding catalog](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/finding-catalog.md) · [Policy](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/policy-reference.md) · [Collection limits](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/collection-limits.md) · [Framework crosswalk](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/framework-crosswalk.md) |
| **Integrate** | [GitHub Action](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/github-action.md) · [Drift gate](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/drift-gate.md) · [Attestation](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/inventory-attestation.md) · [Trace evidence](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/trace-evidence.md) · [ShadowScan](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/shadowscan-integration.md) |
| **Operate** | [Runtime assurance](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/runtime-assurance.md) · [Releasing](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/releasing.md) · [Repository controls](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/repository-controls.md) |

## Project status

**Alpha** with a single maintainer — APIs, formats and policy semantics may change. CI tests Python 3.11–3.14 with hash-locked dependencies on every push. Releases go through the environment-gated [release workflow](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/releasing.md). [Roadmap](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/ROADMAP.md) · [Changelog](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CHANGELOG.md).

[Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) is the companion discovery engine — it finds agents across many surfaces, and Nexus SymBiote turns its reports into AgentBOMs with local supply-chain verification.

## Security

Report vulnerabilities privately: [SECURITY.md](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/SECURITY.md). Never in a public issue.

## Contributing

Contributions welcome — especially collector coverage, regression fixtures and documentation. [CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CONTRIBUTING.md) · [GOVERNANCE.md](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/GOVERNANCE.md) · [Code of conduct](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CODE_OF_CONDUCT.md).

## Citation

If you use Nexus SymBiote in research or tooling, cite it with the metadata in [CITATION.cff](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CITATION.cff), or use **Cite this repository** on GitHub.

## License

[MIT](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/LICENSE). Copyright (c) 2026 Emmanuel Dahunsi (AISecNomad). The vendored schemas under `src/nexus_symbiote/generators/schemas/vendor/` keep their upstream licenses: CycloneDX is [Apache-2.0](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/src/nexus_symbiote/generators/schemas/vendor/LICENSE-APACHE-2.0.txt), and SPDX 3.0.1 is [Community-Spec-1.0 with CC-BY-3.0](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/src/nexus_symbiote/generators/schemas/vendor/LICENSE-SPDX-3.0.1.txt) for pre-existing portions. The [notice](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/src/nexus_symbiote/generators/schemas/vendor/NOTICE.txt) gives their sources, so the distribution's license expression is `MIT AND Apache-2.0 AND Community-Spec-1.0 AND CC-BY-3.0`.
