# Scanning a public agent project

This tutorial walks through using Nexus SymBiote against a real, public agent
project rather than the synthetic [`examples/demo-agent/`](../../examples/README.md).
It covers inventory, validation, risk gating, drift detection and a CI wiring.

The goal is to show the shape of the output on a repository you did not control
the layout of. It is not a security review of the target. Findings reflect
what SymBiote can see in static files; absence of a finding is not approval.

## 1. Pick a reviewed revision

The repository and the exact revision are inputs to the review, not something
to pin loosely. Clone a public target and detach to the commit you will
actually read:

```bash
git clone https://github.com/modelcontextprotocol/servers.git public-mcp-servers
cd public-mcp-servers
git checkout --detach <40-character-commit-sha-you-reviewed>
cd -
```

Any public agent-ish repository works; `modelcontextprotocol/servers` is a
convenient target because it ships several MCP server packages, each with its
own package manifest, and the inventory exercise is representative.

## 2. Install SymBiote from a reviewed checkout

Follow the top-level [install from reviewed source](../../README.md#install-from-reviewed-source)
section. Confirm the CLI responds before you point it at anything:

```bash
nexus-symbiote --version
```

## 3. Collect an inventory

Static collection is offline by default and does not execute project modules,
MCP launchers or model loaders. Scan the target you detached in step 1, with
project-supplied policy disabled so an untrusted checkout cannot pick its own
gates. First create a random operator binding key and keep it exported for the
rest of this tutorial. A2A cards and client declarations need it for complete
coverage, and the later steps compare against collections made with the same key.
The key must be random, never a passphrase. See
[the operator binding key](../verification-source-binding.md#the-operator-binding-key).

```bash
export NEXUS_SYMBIOTE_SOURCE_BINDING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
nexus-symbiote scan public-mcp-servers \
  --no-project-policy \
  -o public.aibom.json
nexus-symbiote summary public.aibom.json
```

`scan` prints each of the eight built-in collectors (`mcp`, `model`, `prompt`,
`rag`, `registry`, `shadowscan`, `a2a`, `ide_agents`) as it runs, with the number
of components it found. `summary` then counts the inventory's components by
type, its dependencies and its findings by severity. The inventory itself
records per-collector status, failures and excluded paths:

```bash
jq '.metadata.completeness | {scanner_status, scan_failures, exclusions}' public.aibom.json
```

A completed search can report zero matches for a collector; that is coverage
information, not a failure.

For a target with a lot of dependency manifests, scope the pass to the
collectors you intend to review. Repeat `--scanner` once per collector:

```bash
nexus-symbiote scan public-mcp-servers \
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
  --no-project-policy
nexus-symbiote risk public.aibom.json --no-project-policy
```

Validation checks completeness and integrity against the project you scanned.
`risk` scores findings and applies the default gate. Both commands may fail
with exit 1 even on a healthy project: unpinned package references, missing
immutable image digests and absent signer policies all surface as findings
rather than passing silently. That is the intended behaviour — this is a
review surface, not a yes/no verdict.

The validator uses the exact MCP source bound at scan time. If you edited the
project between scanning and validating, re-scan: the fingerprint reconciliation
step will reject the stale snapshot. See
[verification-source-binding.md](../verification-source-binding.md).

## 5. Export reviewable BOMs

```bash
nexus-symbiote scan public-mcp-servers --no-project-policy -f cyclonedx -o public.cdx.json
nexus-symbiote scan public-mcp-servers --no-project-policy -f spdx     -o public.spdx.json
nexus-symbiote scan public-mcp-servers --no-project-policy -f sarif    -o public.sarif
```

The CycloneDX 1.7 and SPDX 3.0.1 exports carry a digest-bound native extension
you must preserve to recover full semantics; a dropped extension loses the
agent-native fields. The SARIF export contains reviewable findings, not an
admission decision.

## 6. Catch drift on the next review

Store the first inventory as a reviewed baseline. On the next revision, scan
again and diff:

```bash
cp public.aibom.json reviewed.aibom.json
# ... after the target advances to a new commit ...
nexus-symbiote scan public-mcp-servers --no-project-policy -o current.aibom.json
nexus-symbiote diff reviewed.aibom.json current.aibom.json --fail-on-alert
```

Collect both inventories with the same binding key. `--fail-on-alert` fails on
in-place changes rated medium or higher: an MCP server package bumped at the same
version, a swapped lockfile integrity value, a replaced MCP tool implementation,
an A2A card URL moved to plain HTTP, or newly broad IDE agent allowances. The
alert set is the one documented in the [CHANGELOG](../../CHANGELOG.md) and
exercised by the regression suite.

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

The Action installs its own reviewed source and ignores policy files supplied
by the scanned checkout, so a hostile PR cannot pick the gates it is reviewed
under. Generate the binding key once, store it as the repository secret
`NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, and pass it to the Action as step-level `env`
as shown; it is not an input. Use the same secret for every workflow whose
inventories you compare. Pull requests from forks receive no secrets, so for a
repository with A2A declarations their run fails closed; review such changes
from a branch of the repository itself. SARIF upload needs
`security-events: write` added to the job and the repository's code-scanning
entitlement; fork pull requests may have restricted tokens, in which case the
retained evidence is the fallback.

## 8. What you have, and what you don't

After this walkthrough you have:

- An AgentBOM for the exact revision you reviewed.
- Standard CycloneDX, SPDX and SARIF exports derived from one native inventory.
- A drift gate ready for the next revision.
- A pinned CI integration that fails closed on missing or invalid evidence.

What you **do not** have, however the gate reads:

- Proof that any model is benign, that any tool's backend obeys its description,
  or that any live agent action was mediated. Read
  [security-model.md](../security-model.md) before any approval decision.
- Complete enterprise discovery. SymBiote is a local-evidence tool;
  [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) is the
  multi-surface discovery counterpart whose reports SymBiote imports.
- Any claim about future revisions. Re-scan on each review.

## Next steps

- Scan your own agent project; the demo in [`examples/README.md`](../../examples/README.md)
  shows the drift and import flows in isolation.
- Read the [security model](../security-model.md) for the trust boundaries this
  tool operates on, and [runtime assurance](../runtime-assurance.md) for the
  limits of signed-snapshot evidence.
- File issues at <https://github.com/Hunzee-VC/Nexus-Symbiote/issues> for
  collectors you need that are not listed above.
