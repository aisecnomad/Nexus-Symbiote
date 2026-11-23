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

- **Use the same policy for both.** `--no-project-policy` keeps a policy file in the
  checkout from narrowing either snapshot. `baseline` accepts it, and
  `--signature-policy`, like `scan`.
- **Use the same binding key for both.** Set one `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`
  of 32 or more characters for the baseline and every candidate scan. Without it, the
  values described above cannot alert on a change: every record that carries the low
  `completeness` finding for unbound values (MCP server, IDE agent, RAG source, A2A
  agent or client, or repository agent when redaction changed an `agent.yaml` field),
  and every prompt file whose content hash is withheld, raises a medium alert on every
  comparison instead — so `diff --fail-on-alert` fails rather than reporting no change.
  The alert does not name the value.

  The same alert fires when only one of the two scans has the key and the digests of
  the IDE settings files then differ. With a *different* key, every MCP, A2A, RAG, IDE
  settings and prompt file binding changes and alerts. The Action refuses
  `reviewed-baseline` unless that key is set on the step or passed as
  `source-binding-key`. Fork `pull_request` jobs receive no secrets, so they cannot
  satisfy that input; run the keyed drift gate on same-repository pull requests and
  trusted branches, as the example under [Protect the gate](#protect-the-gate) does.
  See [source binding](verification-source-binding.md).
- **Recollect v1 RAG baselines once.** Under RAG structure profile v2, every RAG
  source's `static_config_hash` changes once, not only sources with inline
  documents: the profile name is part of the digested structure, and an absent
  `documents` key is digested as `{"present": false}` where v1 digested `null`. On
  an unchanged project, a baseline that 0.2.0 wrote raises a high
  `properties.static_config_hash changed` alert for every RAG source, and
  `validate --project` fails reconciliation on every v1 inventory that records a
  RAG source, until both are recollected. Take a new baseline at the commit the old
  one was reviewed at; see [RAG sources](verification-source-binding.md#rag-sources).
- **Paths are root-relative.** Recorded paths are relative to the scan root, so a
  snapshot taken in `/Users/alice/agent` compares with one taken in
  `/home/runner/work/agent/agent`. Without a manifest `id`, the repository agent is
  `agent:repository:cdb4ee2aea69cc6a83331bbe`, named `repository`, wherever the
  checkout is. An
  [agent manifest](agent-manifest.md) `id` gives it a stable, named reference.
- **Upgrading from 0.1.0: re-create the baseline.** Snapshots written by 0.1.0
  record absolute paths and a path-derived agent reference. `diff` does not treat
  `/old/root/CLAUDE.md` and `CLAUDE.md` as the same location, because the old root
  is not recorded and guessing it could hide a file that really moved. It adds a
  note when one snapshot has absolute paths and the other relative ones. The new
  native format version also alerts: `spec_version` 1.0.0 against 1.1.0 is high,
  and the policy record 1.1.0 adds (`policy_source`, `policy_weakened`) is medium.
  To migrate, check out the commit the old baseline was reviewed at, take a new
  baseline there with this release, and review `diff old.json new.json`: on the
  same commit it should show only how the evidence is recorded, not what it
  contains. Then adopt the new baseline through your usual review.
- **ShadowScan reports** are compared by normalized content; see
  [comparing discovery across reruns](shadowscan-integration.md#compare-discovery-across-reruns).

## What the alerts mean

Every alert names what changed. Security alerts are listed first in text output,
then notes, then the added, removed and modified components and relationships.
`--json-output` carries the same records.

| Change | Rating |
| --- | --- |
| Component added | at least medium, or the highest effective finding severity on the added component (for example critical for an executable model format) |
| Component removed | high for MCP servers and clients, tools, models, instruction and skill files, guardrails, IDE agents and extensions, A2A clients and servers, and for any record that carried integrity evidence (file, content, definition or schema digest, exact package URL, version pin, lockfile integrity, static source binding); medium otherwise. Confirm it was deleted, not moved where no collector reads it |
| MCP endpoint, transport, launch command, launcher package or static source binding changed; the served tool set, or the served instructions, prompts or resource templates, that a live observation recorded (`discover-mcp --record`, `verify-live --record`) changed | critical |
| Tool definition, input schema, description or annotations changed; model serialization safety changed to an unsafe execution or template format; a model's `trust_remote_code` set to true | critical |
| Security field changed (for example capabilities, authorizations, claims, endpoints, A2A card URL, package URL, provider, source URI, signing identity or key reference, permission mode, version pin), a `*_ref` or `*_refs` field changed, declared autonomy level changed, trust tier or signing status downgraded, a digest removed or changed, including the `config_hash` of a guardrail or evaluation configuration file (`config_hash changed.`) | high |
| Tool definition, content or file hash became available: the baseline carried no digest for content the new snapshot pins (`Tool definition hash became available — first binding of content the baseline never pinned.`, `Content hash became available — first binding of content the baseline never pinned.`, `File hash (sha256) became available — first binding of content the baseline never pinned.`). A baseline whose records carry no digest, such as a ShadowScan import or another lossy source, meets this once, when the next scan pins the content: review that snapshot and adopt it as the baseline | medium |
| Trust tier or signing status raised | medium: a snapshot is written unsigned, so a raised label is a claim to review |
| Risk findings added | the highest added severity, at least medium |
| Risk findings removed; any other field changed, including snapshot metadata such as the producer's `tool_name` or `tool_vendor` | medium |
| Values unbound in either snapshot: the record has no keyed binding (`static_value_binding`) and either carries a `completeness` finding saying its values are not bound in this inventory, as MCP launch values, IDE agent settings values and RAG and A2A values do without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, or has its content hash withheld, as a prompt file has without the key, such as an `@path` import that is not Markdown or a prompt template, which shares one such finding with the other templates. Raised on every comparison, changed or not, and names no value: `MCP server launch values are unbound in one snapshot; argument, environment and endpoint-path drift is undetectable. Set NEXUS_SYMBIOTE_SOURCE_BINDING_KEY during both collections.` for an MCP server, `Values are unbound in one snapshot without the binding key; a change to them is undetectable and no value is recorded. Set NEXUS_SYMBIOTE_SOURCE_BINDING_KEY during both collections.` for any other record | medium |
| Relationship added | medium; high for `invokes`, `delegates-to` and `acts-as-identity` |
| Relationship removed | medium; high for `uses-guardrail` and `approved-under` |
| Relationship kept but its assurance or conditions changed | high |
| Coverage regressed: a new scan failure, coverage gap or exclusion; a collector's status got worse or is no longer recorded; fewer collectors requested or completed; a different scope; more unobserved surfaces; lower coverage assurance; no completeness claim in the new snapshot; or a baseline without a completeness claim (such as a hand-made or supplied BOM) while the new snapshot records a scan failure, a coverage gap, a collector that did not complete or no collector at all, since nothing shows that gap predates the change | high, naming the collector or entries |
| A scanned surface removed from the completeness claim (`1 scanned surface removed (src/old.py): coverage narrowed; components found there are no longer compared.`); an added surface is recorded as info | high |
| A collector first recorded as anything but `complete`, such as `failed` or `partial`, when the baseline's completeness claim never recorded it (`Collector 'model' is now recorded as failed; the baseline does not show this gap predates the change.`); first recorded as `complete`, it is an improvement | high |
| ShadowScan: report content changed; report bytes changed without comparable content digests; source status worse; more unmapped entries; new projection limitations; a lossy format | high |
| The new snapshot has graph problems the baseline did not (dangling or mistyped references), the snapshots differ in `spec_version`, or either snapshot uses a `spec_version` this release does not support | high |
| IDE settings guardrail removed or widened on a retained `ide-agent` component: a `deny_rules` matcher removed (`deny_rule_removed`), a `sandbox.network.allowedDomains` host added (`sandbox_egress_widened`), a rule/subagent activation scope changed to `always_apply` or gained globs (`scope_widened`), or malformed settings metadata prevents verification (`malformed_settings_metadata`) | high |

A relationship to a component that was itself added or removed is listed but alerts
through that component, unless its own rating is high.

These are recorded but never alert: a scanned surface added to the completeness
claim (the components found there are compared separately, so an added source
file is not drift; a surface removed from the claim narrows coverage and alerts,
as the table says), a coverage improvement, such as a collector first recorded as
`complete`, a baseline without a completeness claim compared with a snapshot
whose coverage is complete, a different Nexus SymBiote release (`tool_version`),
a ShadowScan report regenerated with unchanged content, and unmapped ShadowScan
entries that moved within the report.

Notes describe the comparison, not a change, and are printed even when nothing
changed: gaps both snapshots share (the baseline was already incomplete, and changes
inside those gaps cannot be detected), graph problems in both, a baseline recorded
after the candidate (check the argument order, since swapped snapshots show
additions as removals), and snapshots that disagree on absolute paths.

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
