# GitHub Action

The composite Action collects an AgentBOM and enforces collection, completeness, integrity, risk, and drift gates. All inputs and outputs are declared in [action.yml](../action.yml). Because `pull_request` runs the workflow from the PR head, see [Protect the gate](drift-gate.md#protect-the-gate) before relying on it for admission.

## Add it to a workflow

Pin the Action to a reviewed 40-character commit SHA:

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
          sarif-upload: 'false'
```

**Runtime isolation & hygiene:**

- Installs its own hash-locked runtime (including Sigstore verification) in a private virtual environment (`--isolated`, `PIP_CONFIG_FILE=/dev/null`, `--no-index` for the local package) kept off `PATH` without altering the job's Python or reading workspace pip configs.
- Passes `--no-project-policy` to ignore checkout policies and fails on collection errors.
- Neutralizes untrusted checkout text inside a `stop-commands` block so filenames/metadata cannot forge workflow commands or annotations.
- Always keep a job `timeout-minutes`: adversarial inputs can prolong parsing within size bounds.
- Records occupied accepted default exclusions in `metadata.completeness.unobserved_surfaces` (reconciled against observed directories during `--project` validation).

## What each gate checks

Outputs: `result` (`passed` or `failed`), `aibom-digest` (`sha256:<hex>` of the exported AIBOM), and `gates` (JSON object mapping `collection`, `completeness`, `integrity`, `risk`, `drift` to `passed`, `failed`, `skipped`, or `not-run`). Any gate disabled by input prints a warning.

| Gate / feature | Key inputs | Default & behavior |
| --- | --- | --- |
| **Collection & default excludes** | `scan-path`, `accept-default-excludes`, `limits` | Accepts root `.git` by default (`root:.git`; explicit `.git` also accepts nested submodule metadata files; set `'false'` to flag every occupied built-in exclusion). `limits` raises [collection limits](collection-limits.md#set-a-limit) (e.g. `'entries=200000,model-total-bytes=512GiB'`); job-level `NEXUS_SYMBIOTE_LIMITS` is ignored. |
| **Completeness & integrity** | `validate`, `validate-integrity`, `signature-policy`, `allow-unsigned-discovery` | `validate: 'true'` requires complete coverage plus at least one verified digest/signature with zero unknown evidence. Models pass only as SafeTensors with every weight file signed/pinned in caller-owned `signature-policy` ([model integrity](model-integrity.md#operator-signature-policy)). Unsigned ShadowScan reports fail unless `allow-unsigned-discovery: 'true'` (warns). Note: an instruction file digest satisfies integrity without verifying MCP servers ([known limitations](known-limitations.md#gates-and-drift))—use `reviewed-baseline` to gate MCP changes. Set `validate-integrity: 'false'` to check completeness only, or `validate: 'false'` to skip both. |
| **Risk gate** | `risk-check`, `fail-on-severity`, `risk-threshold` | Always reconciles against `scan-path` with the same signer policy. `fail-on-severity` defaults to **`high`** (set `critical` for CLI default or `none` to disable with warning). `risk-threshold` (0–100) gates the uncapped risk sum (`'0'` disables only the score threshold—severity, `invalid_safetensors`, completeness, and missing-evidence gates remain active). |
| **Drift gate** | `reviewed-baseline`, `reviewed-baseline-attestation`, `trusted-keys`, `source-binding-key` | Compares an absolute baseline path **outside the workspace** via `diff --fail-on-alert`, exporting `drift-passed` and `drift-alerts`. Requires a ≥32-char `source-binding-key` / `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` (refuses baseline without it; warns if absent without baseline). Optionally verifies a DSSE `reviewed` attestation using caller-owned Ed25519 public key PEMs outside `GITHUB_WORKSPACE` before diffing ([drift gate](drift-gate.md)). |
| **Provenance & SARIF** | `attest`, `sarif-upload`, `artifact-name`, `sarif-category` | `attest: 'true'` signs build provenance via `actions/attest-build-provenance` (requires `id-token: write`, `attestations: write`). `sarif-upload: 'true'` uploads SARIF (requires `security-events: write`; skipped with warning when ShadowScan discovery is merged). Give multiple Action steps distinct `artifact-name` and `sarif-category` values. |

### Job environment filtering

The Action withholds `NEXUS_SYMBIOTE_MODE`, `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT`, `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256`, `NEXUS_SYMBIOTE_LIMITS`, and GitHub runner/OIDC tokens (`ACTIONS_ID_TOKEN_REQUEST_*`, `ACTIONS_RUNTIME_*`, `ACTIONS_RESULTS_URL`, `ACTIONS_CACHE_URL`, `GITHUB_TOKEN`, `GH_TOKEN`) from collection, validation, risk, and drift child processes so earlier steps cannot force live mode, swap the Sigstore trust root, or expose runner tokens. This is environment filtering—not a process sandbox—so the Action's parent process and custom secrets (including the source-binding key) remain visible to same-UID processes.

## Supply the signer policy

Write the signer policy **outside the workspace** from a trusted repository or organization variable (see [signer policy format](cli-reference.md#signer-policy)):

```yaml
      - name: Write the signer policy
        env:
          SIGNER_POLICY: ${{ vars.NEXUS_SYMBIOTE_SIGNER_POLICY }}
        run: printf '%s' "$SIGNER_POLICY" > "$RUNNER_TEMP/signers.json"
      - uses: aisecnomad/Nexus-Symbiote@<reviewed-40-character-commit-sha>
        with:
          scan-path: .
          signature-policy: ${{ runner.temp }}/signers.json
```

**Ownership & path rules:**

- The original `signature-policy` (and any `trusted-keys`) must live outside `GITHUB_WORKSPACE` and any enclosing repository, with no symlinks or hard links.
- On POSIX, the file and every ancestor directory must be owned by the caller or root; the file must be owner-writable only (`0600` inside a `0700` directory recommended, with `022` umask), and any group-/world-writable ancestor must have the sticky bit.
- In `container:` jobs where the host UID owns `runner.temp`, mount operator files under a container-owned or root-owned path (for example `/run/nexus-operator/signers.json`) and remove group write bits (avoid `2775` `fsGroup` volumes).
- The Action snapshots one private copy into a verified temp directory (`RUNNER_TEMP`, platform temp dir, or `/tmp`), reports its SHA-256 in `signature-policy-digest`, and verifies signatures offline exclusively against the trust root embedded in its hash-locked `sigstore` package.
