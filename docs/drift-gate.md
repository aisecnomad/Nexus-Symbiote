# Gate drift in CI

`nexus-symbiote diff OLD NEW --fail-on-alert` compares a reviewed snapshot with a
new collection and exits 1 when anything it rates medium or higher changed. This
page says where the reviewed snapshot must come from, how to take both snapshots so
they compare, and what each alert means.

The gate compares what the inventory records. Content the collectors do not record — instruction files under names the `prompt` collector does not read, or what a local program or project script started as an MCP server runs — cannot alert.

**Without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`**, the following changes also cannot alert: a changed MCP launch argument other than the launcher package, a changed environment or header value, an endpoint or package index path changed on the same host, a changed value of a project resolver setting such as an `.npmrc` entry, an A2A or RAG URL path changed on the same host that keeps its depth, changed inline RAG document content at the same count, the content of a prompt file whose content hash is withheld (such as an `@path` import that is not a Markdown file), or a value the settings digest of an IDE agent does not keep (such as an `env` value in `.claude/settings.json`, a token, a URL path in a hook or `notify` command, or the arguments of a command, an HTTP header value or the words of a permission rule, which it keeps by shape only). See [source binding](verification-source-binding.md).

None of those changes alters the record. A record that holds such values without the key carries a low `completeness` finding saying its values are not bound, or (as a prompt template) shares one such finding with the other templates. `diff` raises a medium alert for each such record on every comparison, changed or not. A keyless `diff --fail-on-alert` therefore fails on such a record; the alert says the values are unbound and records no value. The [known limitations](known-limitations.md) list those surfaces.

## The trust anchor is the baseline

`baseline` writes an unsigned JSON file, and `diff` checks no signature. `diff`
alone cannot tell a reviewed baseline from one the change under review wrote, so the
gate is only as strong as the place the baseline comes from.

- **Keep the baseline out of the pull request's reach.** Read it from the protected
  base branch (for example `git show "$BASE_SHA:.nexus-symbiote/reviewed.json"`), or
  from an artifact store only maintainers can write. Never read it from the
  pull-request head: an author who changes `.mcp.json` can regenerate a baseline in
  the same commit, and the diff then passes.
- **Copy it outside the scanned checkout** before you compare, for example into
  `$RUNNER_TEMP`, and write the candidate there too. A file inside the checkout can
  be replaced by a symlink or by another file the author controls.
- **Decide who may change it.** Updating the baseline approves everything in it.
  Change it only in a reviewed pull request to the protected branch, and require
  code-owner review for that path.
- **Verify its attestation before `diff`.** A reviewer can sign the baseline with
  `attest --purpose reviewed`, and the job can check it with `verify-attestation`,
  using a public key taken from outside the checkout, before it runs `diff`; see
  [gate a pull request on an attested baseline](inventory-attestation.md#gate-a-pull-request-on-an-attested-baseline).
  That establishes that a key holder you trust signed exactly that file for that
  purpose. It does not retire older attested baselines: an older file the same keys
  signed still verifies, so bound its age with `--max-age-days` and keep attested
  baselines where the change under review cannot choose among them.
- **Protect the gate itself.** On the `pull_request` event the workflow file comes
  from the pull request, so an author can add `--no-fail-on-alert`, or remove the diff
  step, unless workflow edits are gated. Require the workflow through an organization ruleset (*Require
  workflows to pass before merging*), and require `CODEOWNERS` review of `.github/`
  and `.nexus-symbiote/reviewed.json`, as described in [Protect the gate](#protect-the-gate)
  below. Avoid checking out an untrusted pull request head inside a `pull_request_target`
  workflow.

## Take both snapshots the same way

Approve a baseline on a checkout of the protected base branch, and commit it there
through a reviewed pull request (or upload it to a store only maintainers can write):

```bash
# One secret of 32 or more characters, the same for the baseline and every later scan.
export NEXUS_SYMBIOTE_SOURCE_BINDING_KEY="$AGENTBOM_BINDING_KEY"
mkdir -p .nexus-symbiote
nexus-symbiote baseline . --no-project-policy -o .nexus-symbiote/reviewed.json
```

The pull-request job then reads that baseline from the base commit, never from the
pull request, and compares it with a scan of the pull-request checkout:

```bash
export NEXUS_SYMBIOTE_SOURCE_BINDING_KEY="$AGENTBOM_BINDING_KEY"
BASE_SHA="${BASE_SHA:-origin/main}"
git show "$BASE_SHA:.nexus-symbiote/reviewed.json" > "$RUNNER_TEMP/reviewed.json"
nexus-symbiote scan . --no-project-policy -o "$RUNNER_TEMP/agentbom.json"
nexus-symbiote diff "$RUNNER_TEMP/reviewed.json" "$RUNNER_TEMP/agentbom.json" --fail-on-alert
```

Taking both snapshots in the same job from the same checkout compares the pull
request with itself, and that gate can never fail.

- **Use the same policy for both.** Pass `--no-project-policy` (and `--signature-policy`, if used) to both `baseline` and `scan` so checkout policies cannot narrow either snapshot.
- **Use the same binding key for both.** Set one ≥32-char `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` across both scans. Without it, records with unbound values (MCP servers, IDE agents, RAG sources, A2A agents/clients, redacted `agent.yaml` fields, or withheld-hash prompt files) emit a medium unbound-values alert on every comparison (failing `diff --fail-on-alert`), and the GitHub Action refuses `reviewed-baseline`. Using different keys alerts on every keyed binding. Fork PRs receive no secrets—run keyed drift gates on same-repository PRs and trusted branches ([Protect the gate](#protect-the-gate); [source binding](verification-source-binding.md)).
- **Recollect v1 RAG baselines once.** Under RAG structure profile v2, `static_config_hash` changes once per RAG source (alerting high in `diff` and failing `validate --project`); take a new baseline at the reviewed commit ([RAG sources](verification-source-binding.md#rag-sources)).
- **Paths are root-relative.** Snapshots compare cleanly across checkout paths. Without a manifest `id`, the repository agent is `agent:repository:cdb4ee2aea69cc6a83331bbe` (`repository`); add an [agent manifest](agent-manifest.md) `id` for a stable named reference.
- **Upgrading from 0.1.0:** Re-create baselines at their reviewed commit (0.1.0 recorded absolute paths and `spec_version` 1.0.0 vs. 1.1.0).
- **ShadowScan reports** compare by normalized content ([ShadowScan integration](shadowscan-integration.md#compare-discovery-across-reruns)).

## What the alerts mean

Security alerts appear first in text output, followed by notes and component/relationship changes (`--json-output` carries the same records).

| Change | Rating |
| --- | --- |
| Component added | at least medium, or highest effective finding severity on the added component |
| Component removed | high for MCP servers/clients, tools, models, instructions/skills, guardrails, IDE agents/extensions, A2A clients/servers, or any record with integrity/pin/binding evidence; medium otherwise |
| MCP endpoint, transport, launch command, launcher package, static source binding, or live-observed tools/instructions/prompts/resource templates changed | critical |
| Tool definition/schema/description/annotations changed; model serialization safety changed to unsafe format/template; `trust_remote_code` set to `true` | critical |
| Security field changed (capabilities, authorizations, claims, endpoints, A2A card URL, `purl`, provider, source URI, signing identity/key ref, permission mode, version pin, `*_ref`/`*_refs`, autonomy level), trust/signing downgraded, or digest removed/changed (including guardrail/eval `config_hash changed.`) | high |
| First content digest binding on a previously unpinned baseline (`Tool definition hash became available — first binding of content the baseline never pinned.`, `Content hash became available — first binding of content the baseline never pinned.`, `File hash (sha256) became available — first binding of content the baseline never pinned.`) | medium |
| Trust tier or signing status raised (unsigned claim to review) | medium |
| Risk findings added | highest added severity, at least medium |
| Risk findings removed; any other field or producer metadata (`tool_name`, `tool_vendor`) changed | medium |
| Values unbound in either snapshot without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` (raised on every comparison, naming no value: `MCP server launch values are unbound in one snapshot; argument, environment and endpoint-path drift is undetectable. Set NEXUS_SYMBIOTE_SOURCE_BINDING_KEY during both collections.` or `Values are unbound in one snapshot without the binding key; a change to them is undetectable and no value is recorded. Set NEXUS_SYMBIOTE_SOURCE_BINDING_KEY during both collections.`) | medium |
| Relationship added | medium; high for `invokes`, `delegates-to`, `acts-as-identity` |
| Relationship removed | medium; high for `uses-guardrail`, `approved-under` |
| Relationship assurance or conditions changed | high |
| Coverage regressed (new failure/gap/exclusion, worse or missing collector status, fewer collectors, changed scope, more unobserved surfaces, lower coverage assurance, or missing completeness claim) | high (naming collector/entries) |
| Scanned surface removed from completeness claim (`1 scanned surface removed (src/old.py): coverage narrowed; components found there are no longer compared.`); added surfaces are info | high |
| Offline advisory receipt narrowed or removed (`Offline advisory coverage narrowed: coverage complete → partial.`): lower `coverage`, fewer `components_checked`, more packages skipped, excluded or unidentified, or another scope; a count the new receipt drops or garbles is narrowing, while a count a baseline from before it existed lacks is compared as zero. The receipt is compared by meaning, not as a scanned surface | high |
| Collector newly recorded as non-complete (`Collector 'model' is now recorded as failed; the baseline does not show this gap predates the change.`); newly `complete` is an improvement | high |
| ShadowScan report content/bytes changed without matching digests, worse status, more unmapped entries, new projection limits, or lossy format | high |
| New graph consistency errors (dangling/mistyped refs), `spec_version` mismatch, or unsupported `spec_version` | high |
| IDE settings guardrail removed or widened (`deny_rule_removed`, `sandbox_egress_widened`, `scope_widened`, `malformed_settings_metadata`) | high |

**Non-alerting changes & notes:** Added scanned surfaces, coverage improvements, different Nexus SymBiote `tool_version`, a different advisory bundle or more packages checked (an info note that names both bundle digests), unchanged regenerated ShadowScan reports, and reordered unmapped ShadowScan entries never alert. **Notes** (printed even with zero changes) highlight shared gaps in both snapshots, shared graph problems, reversed snapshot timestamps, and absolute-vs-relative path mismatches.

## Exit status

`diff` exits 1 when it reports any security alert, and 0 otherwise; the gate is on
by default, and only an explicit `--no-fail-on-alert` turns it off. An unreadable or
invalid input is an error (exit 1); a missing file is a usage error (exit 2).

## Protect the gate

On `pull_request`, GitHub runs the workflow file of the pull request's merge commit, so the pull request under review can change these inputs, switch a gate off or delete the step unless workflow edits are restricted. Make the gate one the pull request cannot weaken:

1. **In a GitHub organization (recommended):** require the workflow through an organization ruleset (*Require workflows to pass before merging*), which pins the gate to a reusable workflow file and ref outside the pull request's reach.
2. **In any repository:** run on `pull_request` with read-only permissions, stage the baseline from `github.event.pull_request.base.sha` into `$RUNNER_TEMP`, pass the binding key the baseline was recorded with from a repository secret, require a mandatory `CODEOWNERS` review from security owners for `.github/` and `.nexus-symbiote/reviewed.json`, and configure branch protection to require that check to pass. The job below skips pull requests from forks, which receive no secrets; see the note after it:

```yaml
name: Agent inventory gate
on: pull_request
permissions:
  contents: read
jobs:
  inventory:
    # Fork pull requests receive no secrets, so the keyed comparison runs only for
    # pull requests from this repository.
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Stage the reviewed baseline from the base branch
        env:
          GH_TOKEN: ${{ github.token }}
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: >-
          gh api -H 'Accept: application/vnd.github.raw'
          "repos/$GITHUB_REPOSITORY/contents/.nexus-symbiote/reviewed.json?ref=$BASE_SHA"
          > "$RUNNER_TEMP/reviewed.json"
      - uses: aisecnomad/Nexus-Symbiote@<reviewed-40-character-commit-sha>
        env:
          NEXUS_SYMBIOTE_SOURCE_BINDING_KEY: ${{ secrets.AGENTBOM_BINDING_KEY }}
        with:
          scan-path: .
          reviewed-baseline: ${{ runner.temp }}/reviewed.json
```

**Avoid `pull_request_target` with an untrusted checkout** ("pwn request" hazard): `pull_request_target` runs in the base repository's security context, where adding any build, test, cache or secret step later turns an untrusted fork checkout into secret exfiltration or repository compromise.

**Same-repository vs. fork pull requests.** On `pull_request`, same-repository pull requests can supply `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` from repository secrets. Fork pull requests receive no secrets: the Action refuses `reviewed-baseline` without the key, and an unkeyed `diff --fail-on-alert` fails closed on unbound values (MCP launch values, IDE settings values, prompt files whose content hash is withheld) instead of comparing them. Run keyed comparisons only for same-repository pull requests and trusted branches.

**Required-check interaction.** A job that `if:` skips counts as passed for a required check, so in a repository that accepts fork pull requests, also run the keyed gate on a trusted event before merging, such as `merge_group` with a merge queue. A second, keyless job for forks, comparing with a baseline recorded without the key, passes only while no record carries unbound values.
