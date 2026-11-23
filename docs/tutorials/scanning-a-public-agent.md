# Scanning a public agent project

Run Nexus SymBiote against a real, public agent project rather than the synthetic
[`examples/demo-agent/`](../../examples/README.md). Covers inventory, validation,
risk gating, drift detection and CI wiring.

The goal is to show output shape on a repository you did not author. This is not a
security review of the target — findings reflect what SymBiote sees in static files,
and absence of a finding is not approval.

## 1. Pick a reviewed revision

Pin to the exact revision you will review. Clone a public target and detach to that
commit:

```bash
git clone https://github.com/modelcontextprotocol/servers.git public-mcp-servers
cd public-mcp-servers
git checkout --detach <40-character-commit-sha-you-reviewed>
cd -
```

Any public agent repository works. `modelcontextprotocol/servers` is a convenient
target because it ships several MCP server packages with separate manifests.

## 2. Install SymBiote from a reviewed checkout

Follow the top-level [install from reviewed source](../../README.md#install-from-reviewed-source)
section. Confirm the CLI responds before you point it at anything:

```bash
nexus-symbiote --version
```

## 3. Collect an inventory

Collection is offline by default — no project modules, MCP launchers or model
loaders execute. Disable project-supplied policy so an untrusted checkout cannot
pick its own gates:

```bash
nexus-symbiote scan public-mcp-servers \
  --accept-default-exclude .git \
  --no-project-policy \
  -o public.aibom.json
nexus-symbiote summary public.aibom.json
```

`scan` prints each collector as it runs with its component count. `summary` counts
components by type, dependencies and findings by severity. Inspect per-collector
status, failures and exclusions:

```bash
jq '.metadata.completeness | {scanner_status, scan_failures, exclusions, surfaces_excluded}' public.aibom.json
```

A completed search can report zero matches for a collector; that is coverage
information, not a failure.

For targets with many dependency manifests, scope to the collectors you intend to
review:

```bash
nexus-symbiote scan public-mcp-servers \
  --accept-default-exclude .git \
  --no-project-policy \
  --scanner mcp --scanner registry \
  -o public.mcp-only.aibom.json
```

This scan writes the inventory but exits 1: omitted collectors are recorded as
`unknown`, not approved, and the default gate requires all eight. Add
`--report-only` while you explore, and never treat a scoped scan as an approval.

## 4. Validate and risk-gate

```bash
nexus-symbiote validate public.aibom.json \
  --project public-mcp-servers \
  --accept-default-exclude .git \
  --no-project-policy
nexus-symbiote risk public.aibom.json --no-project-policy
```

`validate` checks completeness and integrity against the project. `risk` scores
findings and applies the default gate. Both may exit 1 even on a healthy project:
unpinned packages, missing image digests and absent signer policies surface as
findings rather than passing silently. This is a review surface, not a yes/no
verdict.

The validator uses the exact MCP source bound at scan time. If you edited the
project between scanning and validating, re-scan: the fingerprint reconciliation
step will reject the stale snapshot. See
[verification-source-binding.md](../verification-source-binding.md).

## 5. Export reviewable BOMs

```bash
nexus-symbiote scan public-mcp-servers --accept-default-exclude .git --no-project-policy -f cyclonedx -o public.cdx.json
nexus-symbiote scan public-mcp-servers --accept-default-exclude .git --no-project-policy -f spdx     -o public.spdx.json
nexus-symbiote scan public-mcp-servers --accept-default-exclude .git --no-project-policy -f sarif    -o public.sarif
```

CycloneDX 1.7 and SPDX 3.0.1 exports carry a digest-bound native extension you
must preserve to recover full semantics. The SARIF export contains reviewable
findings, not an admission decision.

## 6. Catch drift on the next review

Use the same source binding key for the reviewed baseline and every later scan:
one secret of at least 32 characters, kept outside the checkout (a CI secret or
password manager, never a file in the repository). The key binds MCP launch
arguments, environment values and endpoint paths that the inventory otherwise
redacts, so `diff` can detect changes. The step-3 inventory has no key, so
re-collect:

```bash
# One secret of 32 or more characters, kept outside the checkout; the same for every scan.
export NEXUS_SYMBIOTE_SOURCE_BINDING_KEY="$AGENTBOM_BINDING_KEY"
nexus-symbiote scan public-mcp-servers --accept-default-exclude .git --no-project-policy -o reviewed.aibom.json
# ... after the target advances to a new commit ...
nexus-symbiote scan public-mcp-servers --accept-default-exclude .git --no-project-policy -o current.aibom.json
nexus-symbiote diff reviewed.aibom.json current.aibom.json --fail-on-alert
```

When nothing changed, `diff` prints `No changes detected.` and exits 0. Without
a key, `diff --fail-on-alert` exits 1 with a medium alert for every MCP server
whose launch arguments, environment values or endpoint path were left unbound, and
for every IDE settings, RAG, A2A or imported-file record whose values were,
even when the two inventories are identical, because redacted values cannot be
shown to have stayed the same.

`--fail-on-alert` fails on changes rated medium or higher: a changed MCP launcher
package or version, a swapped integrity value in an npm lockfile
(`npm-shrinkwrap.json` included), a replaced MCP tool implementation in the file
that declares the tool, an A2A card URL moved to plain HTTP, newly broad IDE agent
allowances, a removed component or a coverage regression. An added source file
that changes no component does not alert. [Gate drift in CI](../drift-gate.md#what-the-alerts-mean)
rates every change, and says where the reviewed baseline must come from.

## 7. Wire it into a reviewing repository's CI

Add SymBiote to the CI of a repository that **consumes** or **ships** an agent,
pinning this project to a reviewed 40-character commit SHA (not a tag):

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

The Action installs its own reviewed source and ignores policy files supplied
by the scanned checkout, so a `.nexus-symbiote.yaml` in a pull request cannot
relax its gates. The workflow file can: on `pull_request`, GitHub runs the
workflow from the pull request's merge commit, so a hostile pull request can
change the inputs above, switch a gate off or delete the step, and pass. The
Action prints every gate an input switches off as a warning and reports each
gate in its `gates` output, but to make the check one a pull request cannot
weaken, require the workflow through an organization ruleset or require
code-owner review of `.github/` and the reviewed baseline, as the
[Gate drift in CI](../drift-gate.md#protect-the-gate) guide shows. SARIF upload
needs `security-events: write` added to the job and the repository's
code-scanning entitlement; fork pull requests may have restricted tokens, in
which case the retained evidence is the fallback.

## 8. What you have, and what you don't

After this walkthrough you have:

- An AgentBOM for the exact revision you reviewed.
- Standard CycloneDX, SPDX and SARIF exports derived from one native inventory.
- A drift gate ready for the next revision.
- A pinned CI integration that fails closed on missing or invalid evidence.

What you **do not** have, however the gate reads:

- Proof that any model is benign, that any tool backend obeys its description or
  that any live agent action was mediated. Read
  [security-model.md](../security-model.md) before any approval decision.
- Complete enterprise discovery. SymBiote is a local-evidence tool;
  [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) is the
  multi-surface discovery counterpart.
- Any claim about future revisions. Re-scan on each review.

## Next steps

- Scan your own agent project; the demo in [`examples/README.md`](../../examples/README.md)
  shows the drift and import flows in isolation.
- Read the [security model](../security-model.md) for the trust boundaries this
  tool operates on, and [runtime assurance](../runtime-assurance.md) for the
  limits of signed-snapshot evidence.
- File issues at <https://github.com/aisecnomad/Nexus-Symbiote/issues> for
  collectors you need that are not listed above.
