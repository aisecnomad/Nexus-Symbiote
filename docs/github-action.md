# GitHub Action

The composite Action collects an AgentBOM in a workflow job and applies the collection, completeness, integrity, risk and drift gates. Every input and output is defined in [action.yml](../action.yml). On `pull_request` the workflow file comes from the change under review, so also [protect the gate](drift-gate.md#protect-the-gate).

## Add it to a workflow

Pin the Action to a reviewed 40-character commit:

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

The Action installs its own hash-locked runtime, including Sigstore verification, in a private virtual environment (`--isolated`, `PIP_CONFIG_FILE=/dev/null`, and `--no-index` for the local Action package) that it keeps off the job's `PATH`, without changing the job's default Python or reading runner/workspace pip configuration. It ignores policy in the scanned checkout and fails on collection errors. Text from the checkout reaches the job log only inside a `stop-commands` block, neutralized, so it cannot set outputs or create annotations. Keep a job timeout like the one above: hostile input can keep a scan running until the job times out.

The native inventory lists each occupied, accepted default name in
`metadata.completeness.unobserved_surfaces`, including a root name that also
appears in the configured `exclusions` on an empty checkout. Project
reconciliation checks this evidence against the directories it observes.

## What each gate checks

- **Every gate states its result.** The `result` output is `passed` or `failed`, `aibom-digest` reports the SHA-256 of the exported AIBOM bytes (`sha256:<hex>`), and `gates` is a JSON object with the state of each gate (`collection`, `completeness`, `integrity`, `risk`, `drift`): `passed`, `failed`, `skipped` (switched off by an input) or `not-run`. Every gate an input switches off is printed as a warning.
- **Integrity needs one matching digest or signature.** With `validate: 'true'`, integrity passes only when at least one artifact hash or signature verifies and no component's evidence is unknown, so a repository in which nothing verifies, such as an empty checkout or one with only an MCP configuration, fails. The digest of an instruction file counts, although the same run recorded it from the same checkout: adding a one-line `CLAUDE.md` to such a repository makes integrity pass without verifying anything about its MCP servers (a [known limitation](known-limitations.md#gates-and-drift); `signature-policy` covers models and discovery reports, not MCP servers, so gate MCP server changes with `reviewed-baseline`). A model counts only as a SafeTensors file whose every weight file is signed or digest-pinned in a [signer policy](model-integrity.md#operator-signature-policy) you own, so a repository that contains a model fails unless every model meets such a policy. `validate-integrity: 'false'` checks completeness without integrity, for a repository whose models cannot be signed yet; `validate: 'false'` skips both.
- The Action accepts the checkout’s root Git metadata by default through `root:.git`. Explicit `.git` also accepts regular nested Git metadata files, as used by submodules. The inventory records each accepted path. Use `accept-default-excludes` to supply a comma-separated list or set it to `'false'` to report every occupied built-in exclusion.
- **The risk gate.** `fail-on-severity` defaults to `high`: any finding at or above that severity fails the run, including a permission bypass or an unpinned launcher, even when the aggregate score stays under `risk-threshold`. Set `fail-on-severity: critical` to restore the previous Action behavior, which failed on severity only for critical findings, or `none` to disable the severity check (printed as a warning). The aggregate score is an unbounded sum of finding weights, not a percentage from 0 to 100; `risk-threshold` is a threshold for that sum and the Action accepts 0 to 100. `risk-threshold: '0'` removes only the score threshold; findings at or above `fail-on-severity`, unverified SafeTensors, incomplete coverage and missing evidence still fail it. Risk always reconciles the inventory against `scan-path` with the same signer policy, whether or not `validate` ran, so a reconciliation failure fails it too, without a score. `risk-check: 'false'` skips it.
- **Unverified discovery evidence.** A ShadowScan report in the repository is unsigned discovery evidence unless the signer policy verifies its producer, and the completeness and risk gates fail on it. `allow-unsigned-discovery: 'true'` accepts it explicitly, with a warning.
- **The drift gate.** `reviewed-baseline` adds it: the absolute path of a reviewed AgentBOM outside the workspace, written from a trusted source like the signer policy below, which the Action compares with `diff --fail-on-alert`. When `reviewed-baseline-attestation` and `trusted-keys` (comma- or newline-separated caller-owned Ed25519 public key PEM paths outside `GITHUB_WORKSPACE`) are also set, the Action verifies the DSSE attestation envelope over `reviewed-baseline` for purpose `reviewed` before running `diff`. The `drift-passed` and `drift-alerts` outputs report the result. The baseline requires a source binding key of at least 32 characters, passed as `source-binding-key` or as `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` on the step. Record the baseline with the same key. Without the key the Action refuses the baseline: launch arguments, environment values and endpoint paths would not be compared. When no baseline is set and the key is absent, the Action prints a warning. [Gate drift in CI](drift-gate.md) says where the baseline must come from.
- **Build provenance attestation.** Set `attest: 'true'` and grant `id-token: write` and `attestations: write` permissions to sign build provenance over the exported AIBOM with `actions/attest-build-provenance`.
- **Limits.** `limits` raises [collection limits](collection-limits.md#set-a-limit), for example `'entries=200000,model-total-bytes=512GiB'`. The job's own `NEXUS_SYMBIOTE_LIMITS` is ignored, and so are its `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` and `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256`: signatures verify against the trust root embedded in the Action's hash-locked `sigstore` package, never a file an earlier step named.
- **The job environment.** The Action's collection, validation, risk and drift commands never see the job's `NEXUS_SYMBIOTE_MODE`. These commands run offline whatever it says; withholding it keeps a job-level value from failing them. The runner and OIDC credential variables `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_URL`, `ACTIONS_RUNTIME_TOKEN`, `ACTIONS_RUNTIME_URL`, `ACTIONS_RESULTS_URL`, `ACTIONS_CACHE_URL`, `GITHUB_TOKEN` and `GH_TOKEN` are withheld too, so no library in those commands picks one up. This filtering is not a process sandbox: the Action's own process still holds those variables, a command running as the same user can read them from that process's environment, and other variables, including custom secrets and the source-binding key, are still inherited.
- **SARIF.** Set `sarif-upload: 'true'` and add `security-events: write` to upload SARIF. The upload is skipped, with a warning, for an inventory that merges imported ShadowScan discovery. Give each Action step in one workflow run its own `artifact-name` and `sarif-category`.

## Supply the signer policy

On a hosted job where the runner owns its temporary directory, write the signer policy outside the workspace from a trusted source such as a repository or organization variable. The following example uses that layout.

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

In a `container:` job, the host may own `runner.temp` under a different UID. Provision the original signer policy and any `trusted-keys` outside the checkout under a path owned by the container account or root, such as an operator-mounted `/run/nexus-operator/signers.json`, and supply that path to the Action. A dedicated 0700 directory and a 0600 file meet the permission requirements. A group-writable home or a 2775 `fsGroup` volume can invalidate an otherwise read-only key. For service-owned paths, remove group write access from the file and its ancestors, or move the trust anchor into a private directory. A 022 umask avoids new group-writable files and directories.

The Action requires the original policy outside the workspace and any enclosing repository, through a path with no symlinks or hard links. On POSIX the file and its ancestors must be owned by the caller or root. The file must be writable only by its owner, and a group- or world-writable ancestor needs sticky protection. In a container job, provision the original file in a directory satisfying these rules within the container.

The Action passes one private snapshot to collection, validation and the risk gate and reports its SHA-256 in the `signature-policy-digest` output. It uses `RUNNER_TEMP` when the directory satisfies the same ancestry checks and can try the platform temporary directory (which can come from `TMPDIR`, `TEMP` or `TMP`) and then `/tmp` on POSIX. Every candidate must pass the same checks. It verifies signatures offline against the Sigstore trust root shipped in its hash-locked `sigstore` package, never a cache on the runner. The job's `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT`, `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256` and `NEXUS_SYMBIOTE_MODE` variables are not passed to the Action's commands, so an earlier step cannot replace that trust root or select live mode through `GITHUB_ENV`. The [signer policy format](cli-reference.md#signer-policy) is in the CLI reference.
