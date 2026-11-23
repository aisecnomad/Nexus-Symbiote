# ShadowScan discovery and Nexus SymBiote verification

Nexus-ShadowScan is a separate project: [Hunzee-VC/Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan). Install it from that repository at a reviewed commit. The PyPI project named `shadowscan` is an unrelated tool from another publisher.

Run Nexus-ShadowScan separately with the least privileges needed for the chosen connectors and save its JSON report. Keep the report under appropriate access and retention controls:

```sh
shadowscan code /path/to/repository --format json -o shadowscan.json
nexus-symbiote import-shadowscan shadowscan.json -o agentbom.json --report-only
nexus-symbiote import-shadowscan shadowscan.json --format cyclonedx -o agentbom.cdx.json --report-only
nexus-symbiote verify-discovery agentbom.json shadowscan.json --projection
nexus-symbiote verify-artifact model.safetensors --project /path/to/repository --sha256 "$TRUSTED_SHA256"
```

A standalone import always records partial coverage, so `validate` of `agentbom.json` always fails. To gate on discovery together with the repository's own evidence, place the report at a supported path in the repository and validate a merged scan:

```sh
shadowscan code /path/to/repository --format json -o /path/to/repository/shadowscan.json
nexus-symbiote scan /path/to/repository --no-project-policy -o merged.json
nexus-symbiote validate merged.json --project /path/to/repository --no-project-policy
```

The output path must not exist. An incomplete source produces a partial BOM and nonzero exit; a malformed or unsupported report is rejected. With `--report-only` the exit status is 0 either way, except that unverified discovery evidence fails in CI unless `--bundle` verifies the producer or `--allow-unsigned-discovery` accepts it; read `metadata.completeness.source_report_status` (`complete`, `incomplete` or `unknown`) in the written BOM to tell them apart.

A locally generated report digest binds the imported bytes, not the identity of their producer or the truth of their contents. Verification of signatures, sources and artifacts is a separate operation; this importer does not perform it. Do not infer production activity, effective access or authorization from a finding or inventory mismatch.

`verify-discovery` compares exact report bytes with the native BOM's recorded digest; without `--projection` it does not compare the BOM's components. It does not authenticate either the BOM or the report. `verify-artifact` hashes a selected local artifact within the project root against an operator-supplied expected digest. To verify a Sigstore bundle as well, pass `--bundle`, `--signer-identity`, and `--issuer`. The expected digest and signer policy must come from a trusted source. This verifies the selected artifact, not its association with a discovery finding, deployment, or safety.

The importer maps native `agent`, `mcp-server` and `local-model` findings,
including MCP tool observations distinguished by resource type, and two more kinds
for one resource type each: `agent-config` with `coding-agent-config` and
`framework-usage` with `project`.
[What each ShadowScan kind becomes](#what-each-shadowscan-kind-becomes) lists all
18 kinds. It
also accepts ShadowScan's CycloneDX 1.6/1.7 components and services, marking the
projection partial. Unmapped entries are counted with source indexes and by kind. For
CycloneDX, the index is into components followed by services. The source report
and its scope, timestamps, detailed evidence, identities and full graph remain
the authoritative discovery record. Only supported, mapped-endpoint CycloneDX
dependencies are projected as declared claims; the rest of those fields remain
in the report. This reduces leakage but does not create a complete evidence graph.

All imported components have declared assurance and unknown trust. The importer does not run ShadowScan, execute tools, fetch endpoints, infer agent autonomy, or promote a signature filename into verified evidence.

`validate --project` judges imported components as imported claims, not local
subjects. Once reconciliation has bound them to the report beneath the project
root, an imported model or MCP tool that has no local artifact or digest is listed
as an informational integrity issue instead of making integrity unknown; findings
about the claim itself, such as an unsafe loading format, still fail. Without
`--project`, or when the inventory's discovery evidence differs from the report,
nothing is bound and those components keep integrity unknown. Imported components
never count as the local subject that `validate --project` and `risk --project`
require. ShadowScan risk and shadow
flags remain source-reported heuristics; an inventory mismatch is not proof of
unauthorized activity. Output contains report and source-ID digests and indexes,
not raw source descriptions, locations or snippets. The exceptions belong to a model
that a merged scan names from cited evidence: its identifier, the locations the scan
read it at and the report's signal label; see
[models named from cited evidence](#models-named-from-cited-evidence). Both artifacts
may still be sensitive and must be handled accordingly.

The projection profile `nexus-symbiote/shadowscan-projection/v6` identifies the
SymBiote mapping, not a ShadowScan report schema or authenticated producer
version. Each component projected from a finding records the exact report digest
(`shadowscan:report-sha256`) and a content digest of its own source finding
(`shadowscan:finding-sha256`, see below); a model named from cited evidence records
neither. CycloneDX `dependsOn` edges are copied
only when both endpoints map to components. They remain declared, source-reported
relationships, with the dependency-array index recorded on the edge; the BOM
metadata binds them to the report digest. Unmapped endpoint
edges are counted as limitations; raw source identifiers are not included. This
does not verify deployment, association or authorization. The native ShadowScan
format has no general dependency graph, and this importer does not infer one from
fields that merely mention a model. Consumers of standards exports must retain
the SymBiote extension to preserve the edge assurance and provenance.

ShadowScan's endpoint connector can report an MCP tool using kind `mcp-server`
and resource type `mcp-tool`. Since projection version 2, the importer projects that
exact combination as a declared, unverified tool rather than as a server. It does not infer a server
association, tool definition hash, endpoint identity or authorization. Conflicting
tool and kind claims remain unmapped. Native JSON uses `resource_type` and
CycloneDX uses the `shadowscan:resource-type` property. This mapping follows the
[ShadowScan endpoint producer at 1a821e5](https://github.com/Hunzee-VC/Nexus-ShadowScan/blob/1a821e5763e9340ea96564b0606d1ab581fde90e/shadowscan/connectors/endpoint/runtime.py)
and its [CycloneDX reporter](https://github.com/Hunzee-VC/Nexus-ShadowScan/blob/1a821e5763e9340ea96564b0606d1ab581fde90e/shadowscan/reporters/cyclonedx.py).
Version 1 projections used the server type for these findings, and version 2
recorded the exact report digest on CycloneDX edges and had no finding digest.
Version 3 resolved a CycloneDX entry whose type or group contradicts its
`shadowscan:kind`, such as kind `agent` on a `machine-learning-model`, by
precedence; version 4 leaves it unmapped. Version 5 adds the models a merged scan
names from cited evidence; a standalone import projects the same components as
version 4. Version 6 projects `agent-config` findings of resource type
`coding-agent-config` and `framework-usage` findings of resource type `project`,
which version 5 left unmapped, and names the kinds of the entries it leaves
unmapped in the projection limitation and the coverage gap. In a CycloneDX report a
`dependsOn` edge of such a finding is now copied when its other endpoint maps too.
Retain the original importer to reproduce or verify an older projection, then
regenerate inventories with the current profile and review them before comparison or
approval. Producer schema and version changes require compatibility testing; the
report remains untrusted.

The bridge does not resolve agents across tenants or reports, verify live MCP identities, or map every ShadowScan finding type, model association or dependency; unmapped kinds are listed [below](#what-each-shadowscan-kind-becomes). A complete ShadowScan run is complete only for its configured scope; Nexus SymBiote records the imported BOM coverage as partial.

SARIF is not available for imported discovery because its finding projection does not retain complete coverage and provenance: `scan -f sarif` and `import-shadowscan -f sarif` refuse such an inventory, the GitHub Action skips its SARIF upload with a warning, and the `vex` command omits imported findings and records the count in `nexus-symbiote:omittedImportedFindings`.

## What each ShadowScan kind becomes

ShadowScan 0.1.4 reports 18 finding kinds. This table was reviewed against commit `2b80f199659a8de17ea9c7792c07940d5b747d72`. A kind that another version adds or renames stays unmapped until reviewed, as does a new resource type of `framework-usage` or `agent-config`. The kinds `agent`, `mcp-server` and `local-model` are projected for any resource type, so a new one of theirs is projected too.

| ShadowScan kind | Becomes | Condition, or why it is a gap |
| --- | --- | --- |
| `agent` | `agent` | Any resource type but `mcp-tool`. Autonomy is recorded as unknown. |
| `framework-usage` | `agent` | Resource type `project` only: a project that uses an agent framework, a model SDK or only the MCP SDK, in which ShadowScan saw no agent indicator. Autonomy is recorded as unknown. |
| `agent-config` | `ide-agent` | Resource type `coding-agent-config` only: one coding-agent signature in one project, which is a product such as Claude Code or an instruction convention such as an `AGENTS.md` file or a set of `SKILL.md` files. `ide_type` and `permission_mode` stay unset and no configuration file is listed. |
| `mcp-server` | `mcp-server`, or `tool` for resource type `mcp-tool` | A tool is recorded without a server association. |
| `local-model` | `model` | Any resource type: a model file in a repository, model weights stored for a local runtime, or a running process that holds model files open. |
| `secret`, `token` | Gap | A credential is never a component. ShadowScan's own CycloneDX export leaves both kinds out. |
| `oauth-grant`, `service-identity`, `iam-grant` | Gap | An identity or a grant, for which the inventory has no component type. |
| `infra`, `cloud-resource`, `workflow`, `bot-app`, `ai-app` | Gap | No component type describes it. |
| `gateway-caller`, `network-contact`, `runtime-process` | Gap | An observation of run-time activity. |

ShadowScan keeps one finding identifier while a project's kind moves from
`framework-usage` to `agent`, which happens when it sees an agent indicator. Both
kinds are therefore one component type: `diff` reports the move as one modified
component, not as a removed and an added one. The kind ShadowScan gave stays in
`shadowscan:kind` and in the label, such as "ShadowScan framework-usage
af2459bd4b84".

The importer reads the kind and the resource type and nothing else, so the component
type is no narrower than that pair. A project that only implements or configures an
MCP server is a `framework-usage` finding of resource type `project`, and becomes an
`agent`: `agent` in CycloneDX, an AI package in SPDX and a declared agent in
`trace-diff`, beside the `mcp-server` and `tool` components that the local collectors
may record for the same directory. An `AGENTS.md` file or a set of `SKILL.md` files
is an `agent-config` finding of resource type `coding-agent-config`, and becomes an
`ide-agent`, beside the `skill-package` components that the local collectors record
for the same files.

Other ShadowScan connectors use the two resource-bound kinds for other things. For
example, `framework-usage` is also a lockfile that lists AI packages
(`lockfile-inventory`), an agent constructed in one source file (`source-agent`), an
incomplete agent card (`agent-manifest`, or `a2a-agent-card` on an endpoint), a set
of Salesforce prompt templates (`prompt-templates`) and a process with model-runtime
indicators (`process/model-runtime-indicator`). `agent-config` is also a GitLab Duo
group setting (`platform-setting`), GitHub Copilot billing (`copilot-billing`), a
ServiceNow configuration without its parent (`unresolved-parent-configuration`), an
agent configuration or an editor extension on an endpoint (`agent-config`,
`ide-extension`), a registry skill (`agent-registry-skill`) and a skill record in an
AWS registry (`agent-registry-record`, `agentcore-registry-record`). None of those is
a project or a coding-agent signature in one, so any other resource type of the two
kinds, a missing one included, stays unmapped. The projected resource type is
recorded in `shadowscan:resource-type`, from the importer's own table. In a
CycloneDX report an entry of `type` `machine-learning-model` or `group` `mcp-server`
whose `shadowscan:kind` says otherwise stays unmapped whatever the kind. No other
`type` or `group` is compared with the kind.

An imported `agent` or `ide-agent` is a claim that the report holds such a finding.
It carries a digest-based label, declared assurance and unknown trust, it is never
linked to the repository agent or to the configuration the local collectors read
from the same files, and its ShadowScan rating counts in `risk` as a
`shadowscan-heuristic` finding.

### Entries left unmapped

An unmapped entry is counted in `source_unmapped_count`, listed by its index in
`source_unmapped_indexes` and counted by kind in a projection limitation, for
example "5 source entries were not mapped into BOM components (infra: 3; secret:
2)". A merged scan also records the coverage gap "ShadowScan report contains
unmapped entries: infra, secret", which lists the kinds without counts. One
unmapped entry of any kind keeps the shadowscan collector partial and the default
scan, validate and risk gates closed.

The kind is named from the importer's own list, never copied from the report:

| Label | Entry |
| --- | --- |
| The kind, such as `secret` | A finding of a kind that the table above shows as a gap |
| The kind and `(unprojected form)`, such as `framework-usage (unprojected form)` | A finding of a projected kind in a form that is not projected: another resource type, or a CycloneDX `type` or `group` that contradicts the kind |
| `no kind` | An entry with an empty kind or none, such as the `framework` components that ShadowScan's CycloneDX export adds beside its findings |
| `unrecognized kind` | Any other kind string, whatever it holds |

The importer also projects a kind named `model` as a model, as it did before;
ShadowScan 0.1.4 reports no finding of that kind.

## Models named from cited evidence

A ShadowScan code report cites where it saw a model identifier: an evidence entry
whose `signal` starts with `model:`, with a `location` of `path:line` and the
identifier in `attributes.value`. A merged `scan` re-reads that file and line with
its own confined reader and adds a model component when the identifier stands there.
The report says where to look; the name recorded is what the scan read.

```sh
shadowscan code /path/to/repository --format json -o /path/to/repository/shadowscan.json
nexus-symbiote scan /path/to/repository --no-project-policy -o merged.json
```

For a report that cites `gpt-4o-mini-2024-07-18` at `services/api/llm.py:28`, and a
file that holds `MODEL = "gpt-4o-mini-2024-07-18"` on that line, the inventory gains
this component, shown without its properties:

```json
{
  "bom_ref": "shadowscan:model:27bebe765c6e794efc03c584ab67ed05b9724cc0e62e41567db465dc3379aa41",
  "component_type": "model",
  "name": "gpt-4o-mini-2024-07-18",
  "trust_tier": "unknown",
  "assurance_level": "declared",
  "claims": {
    "cited_evidence": {
      "assurance": "declared",
      "method": "cited-line-reread",
      "scope": "repository",
      "collector": "shadowscan",
      "locator": "services/api/llm.py:28",
      "evidence_refs": ["services/api/llm.py:28"]
    }
  }
}
```

The component stays an imported claim: declared assurance, unknown trust, and never
the local subject that `validate --project` requires. The `cited_evidence` claim
records that the scan read the identifier at that location (method
`cited-line-reread`). It is `declared`, as a hosted-model alias in `agent.yaml` is:
an identifier in a source line measures no model, so neither the import nor the
re-read raises assurance, and the component fails
`validate.minimum_assurance_level: observed` unless `validate --project` binds it to
the report. The claim does not show that code calls the model, which provider serves
it or which revision answers. The component has no `source_path` and no digest: the
cited file is not the model's weight file, and an unkeyed digest of a small source
file would let anyone holding the inventory confirm a guess of its content.

### When an identifier is named

All of these must hold.

- **The cited file is one the scan may read.** Its path is a relative POSIX path of at
  most 256 characters inside the project, without `.` or `..` segments, and the
  confined reader can read it as UTF-8 within the operator's `file-bytes` and
  `source-scan-bytes` limits. A path under `.git`, `node_modules`, `__pycache__`,
  `.venv` or `venv`, and a path the collection policy excludes, is not read. A file
  [named as holding credentials](verification-source-binding.md#files-named-as-holding-credentials), such as
  `.env`, `id_rsa`, `server.pem` or `secrets/token.txt`, or a link that leads to one,
  is not read.
- **The cited file is not itself a scan result.** A JSON file whose top-level object
  has a `bomFormat`, `spdxVersion`, `@graph`, `runs`, `findings` or `components` key
  is a bill of materials or a scan report: CycloneDX, SPDX, SARIF, a ShadowScan
  report, a native inventory or a risk report. So is a top-level array that holds an
  object with `bomFormat`, `spdxVersion` or `@graph`; the other three names are
  ordinary words in a list of rows and do not count there. Text that starts as JSON
  and is not one JSON value, for example with a duplicate key, a trailing comma, a
  comment or a second document after the first, is read for the same keys in the same
  places, so it is neither let through as a report nor refused for a key nested
  deeper. Such a file repeats the identifiers a scan found, so it confirms none. The
  report cannot confirm its own citations, and an inventory kept in the tree, such as
  a drift baseline, cannot keep a model named after its source line is deleted.
- **The cited line holds the identifier as a whole identifier.** The line is at most
  4,096 characters. Text may not continue the identifier: `gpt-4o` is not named from
  `gpt-4o-mini`, `qwen2.5-coder` from `qwen2.5-coder:7b`, or `cohere` from
  `cohere/rerank-english-v3.0`. A namespace before it is allowed, so
  `claude-sonnet-4-5-20250929` is named from `anthropic/claude-sonnet-4-5-20250929`.
  Lines are counted by line feeds.
- **The identifier is model-shaped.** It is 2 to 128 characters of ASCII letters,
  digits and `._:/@+-`, starts and ends with a letter or digit, and contains a letter.
- **An Amazon Bedrock resource name is a model's.** A report can label any resource
  name as model evidence: ShadowScan 0.1.4 does so for a guardrail name in Terraform.
  An identifier that starts with `arn:aws:bedrock:`, in any partition, is named only
  when its resource is a `foundation-model`, `inference-profile`,
  `application-inference-profile`, `provisioned-model`, `custom-model` or
  `imported-model`. A guardrail, agent, knowledge-base or flow name is counted as
  unconfirmed. This is the only check on what an identifier names.
- **Nothing reads as a credential.** The identifier and the signal label must pass
  the scan's own redactor unchanged, and the identifier must still stand on the cited
  line after that line is redacted, so one assigned to a name such as `API_TOKEN` is
  withheld. A value can also follow its key on a later line. A line that holds one
  value and no key of its own is therefore read together with the line before it, as
  a value follows `Authorization: Bearer`, and as the value of each key that opens it
  within the eight lines above. A line opens a value when it is a key and its mark,
  after at most one opening bracket, with nothing after them but a YAML anchor or tag, a
  block indicator, an opening bracket, a shell line continuation or a comment:
  `password:`, `password: >-`, `password: &shared`, `{"credentials":`,
  `"credentials": [`, `export const credentials = [`, `export API_KEY=\`,
  `token =  # rotated`. Blank lines, comment lines, lines that only open a bracket and
  other single values, such as list entries, may lie in between. The redactor decides which keys name a credential,
  and it reads names broadly: a list below `requires_token:` or `cache_key = (` is
  withheld as a value on the same line as that key always was. What the lines hold
  decides all of this, not which identifier a report cites there, so the order of a
  report's citations does not change what is withheld. A line with a key and a value
  of its own, such as `model: gpt-4o-mini` below `credentials:`, is read alone, and so
  is a line of several words.

The scan records only an identifier that the report states and the repository
holds at the cited line. It never extends the cited text, so a report cannot make a
scan copy other text from a file into the inventory.

### What is recorded

One component is recorded for each identifier as written; the same model written as
`anthropic/claude-sonnet-4-5-20250929` and as `claude-sonnet-4-5-20250929` is two
components. The claim's `locator` is the first location in path and line order and
its `evidence_refs` list up to 16 locations, fewer when their paths hold characters
that the inventory writes as escapes: the listed locations take at most 4,256 bytes
as written, which one location always fits.

| Property | Value |
| --- | --- |
| `shadowscan:signals` | The report's `model:` labels for the identifier, such as `model:provider.openai`: at most four parts of 24 lowercase letters and digits, a source-reported label. The first 16 in order are listed |
| `shadowscan:signals-unlisted` | The number of labels past the 16 listed; absent when all are listed |
| `shadowscan:evidence-unlisted` | The number of confirmed locations that are not listed; absent when all are listed |
| `shadowscan:kind`, `shadowscan:projection-profile`, `collection_mode` | `model`, the projection profile and `imported-unverified-report`, as on every imported component |

`minimum-elements` counts the identifier as the model's name, on an imported basis. An
imported finding of kind `local-model` still carries a digest-based label, which it
does not count as a name.

Evidence the scan does not confirm stays in the report. The projection limitations
count it, for example "3 model evidence entries were not confirmed at a cited file
and line; they are not named". ShadowScan reports some identifiers by a matched
prefix, such as `qwen2.5-` for `qwen2.5-coder:7b`; those are counted, not named. At
most 500 models are named for one report, in identifier order; the rest are counted
as "confirmed model identifiers past the bound of 500 are not named". These counts
alone do not close the default gate. Two conditions are scan failures: cited files
that do not fit the `source-scan-bytes` limit, which names the limit, and cited
lines past the 1 MiB of text that the scan checks for credentials, "ShadowScan cited
lines exceed the text checked for credentials; the rest were not confirmed". At most
10,000 `model:` evidence entries have their identifier and label read by the
redactor, whether or not they are then kept; the entries after that are counted as
unconfirmed. An entry without a usable location or identifier is counted as
unconfirmed too and does not use up that number.

### Validation and drift

`validate --project` reproduces these components from the report and the files
beneath the project root, and a project that validated without the report's model
evidence validates with it. When a cited line no longer holds its identifier, the
recorded model is reported as "Unexpected discovery report component" and
validation fails; scan again to record the current state.

`diff` compares the cited files, not the line numbers, because a line moves with
every edit above it. A model whose lines shift, or that gains a location in a file
it was already cited in, is unchanged. One cited in another file is a high alert on
its component ("claims changed"), and one that is no longer cited is a removed
component. A rerun that changes only the report's run times raises no alert.

A standalone `import-shadowscan` has no project root, reads no project file and
names no model. CycloneDX reports carry no evidence entries. Findings of other
kinds are not named this way; see the limits below.

> [!WARNING]
> Anyone who can write the report and a file in the checkout can add a model
> component by citing that file. The component shows that the text is in the
> repository at that line. Treat it as a lead to review, as the declared assurance
> says, and require a signed report in CI. A scan result in a format the rule above
> does not recognize, such as a Markdown or HTML report kept in the tree, can still
> confirm an identifier.

## Import and policy gates

The native importer compares reported totals and supplied per-kind,
per-surface and per-risk-level counts and the shadow count with the final findings
array. A contradictory summary is an invalid report, including in report-only mode.
Reports must be UTF-8 JSON, optionally with a byte-order mark; UTF-16 and UTF-32
reports are rejected, because `verify-discovery` could not read them.

A finding is still imported when it carries a risk level, a shadow flag or a
surface the projection does not recognize, such as `Critical` instead of
`critical`, a `risk` object with a score but no level string, or the string
`"true"` instead of `true`, but the value is not represented: the projection
limitations count such entries and the collector
records the coverage gap "ShadowScan report contains values the projection does
not recognize", so the default gate does not pass on a finding whose rating was
dropped.

| Limit | Value |
| --- | --- |
| Report size | 16 MiB |
| Native findings, or CycloneDX components and services | 10,000 |
| CycloneDX dependency edges | 10,000 |
| Finding identifiers, CycloneDX `bom-ref` and dependency references | 4,096 characters |
| Model evidence entries examined in a merged scan | 10,000 |
| Cited path length | 256 characters |
| Cited line length | 4,096 characters |
| Locations listed for one model | 16, and 4,256 bytes as the inventory writes them |
| Signal labels listed for one model | 16 |
| Models named for one report | 500 |
| Lines above a cited value searched for the key that opens it | 8 |
| Text the redactor reads for cited lines: each line, the line before a single value, and the key that opens it | 1 MiB |

A report within these limits can still yield an inventory larger than the 16 MiB
that `validate`, `risk`, `diff` and the other commands read. A merged `scan` reaches
it at roughly 8,000 to 9,000 findings that each carry a risk level, fewer when they
are also flagged as shadow or when the report also cites many models, whose
components stay under 6 MiB; a standalone import of 10,000 such findings stays below
it. Individual connector counts can
precede filtering or deduplication and can legitimately differ from the final
array.

Standalone import records partial coverage even when the source reports a completed
scan. It writes the evidence and exits with status 1. Pass `--report-only` to
accept that result for inspection. The command ignores project policy in the
report directory and its ancestors. Incomplete source reports retain their
status in either mode. Each import requires a new output path.

Native JSON, CycloneDX and SPDX preserve report provenance, source status and
unmapped indexes. Portable formats embed a digest-bound native inventory extension;
its round trip preserves the imported limitations without authenticating the
producer. CycloneDX also declares an incomplete composition. SARIF imports remain
unavailable because a finding-only projection does not preserve this evidence.

The importer API returns `ImportedReport`, including `components`, coverage and
provenance, rather than a bare component list. It rejects bare finding arrays that
cannot carry source coverage. A finding of a kind or form the profile does not
project remains unmapped, and `ImportedReport.unmapped_kinds` counts such entries
under the labels listed in [entries left unmapped](#entries-left-unmapped). Imported
assets are not automatically linked to the repository agent or asserted present
on the local filesystem.

### Scope of a repository baseline

`scan` and `baseline` assess the supported static files in one repository. All eight collectors must finish for the default gate to pass. A successful search can find zero matching files. Git metadata, dependency directories and virtual environments are outside the built-in scope; the inventory lists those patterns under `exclusions`. Unreadable files, unsupported declarations and additional policy exclusions keep coverage partial. A baseline also requires a local subject: the inferred repository agent and imported findings alone provide no evidence of a local agent or artifact.

The collector reads a report at one of three paths beneath the project root: `.shadowscan/report.json`, `shadowscan-report.json` or `shadowscan.json`. Exactly one may exist. Multiple reports produce a failure, so a file committed under another name cannot silently replace one a pipeline generated.

A report reached through a symbolic link in a parent directory is refused. A leaf link such as `.shadowscan/report.json -> ../vendor/report.json` can still be read when it satisfies the ordinary [confinement rules](known-limitations.md#every-collector), including a relative target inside the project reached without another symlink. The inventory lists the path it read under `surfaces_scanned`. If none exists, the inventory records that observation. A fully mapped native report whose source collection completed can accompany a successful repository baseline.
The digest and `source_projection_limitations` record the external evidence
separately. Imported assets retain declared assurance and unknown trust, and
the CycloneDX composition remains incomplete. Incomplete sources, unmapped
entries and lossy CycloneDX inputs keep the default repository gate closed. For the
gate to pass, every finding of the report must have a projected form: one `secret`
or `infra` finding, or a lockfile that ShadowScan reports as `framework-usage` with
resource type `lockfile-inventory`, is an unmapped entry.

Project validation also compares imported dependency endpoints, relationship types,
assurance, provenance and multiplicity against the local report projection. Missing,
modified or additional edges involving imported components fail reconciliation.

### Compare discovery across reruns

The exact report digest changes on every ShadowScan run, because the report
records when the run started and finished. It stays the value that
`verify-discovery`, Sigstore and `validate --project` authenticate. For drift,
the inventory also records `source_report_content_digest` under the profile
`nexus-symbiote/shadowscan-content/v1`: the SHA-256 of the RFC 8785 canonical
JSON of the strictly parsed report without its run-event fields. These are, for
native JSON, the top-level and per-connector `started_at` and `finished_at` and
each finding's `last_seen`; for CycloneDX, `serialNumber` and
`metadata.timestamp`. Each is dropped only when it is null or shaped as an RFC
3339 timestamp written with ASCII digits, or for the serial number a URN UUID. The list is closed. Every
other field or value, including a field a later ShadowScan release adds, counts
as content. `shadowscan:finding-sha256`
applies the same rule to one finding, or to one CycloneDX component or service.

When both inventories carry content digests under the same profile, `diff`
ignores a changed exact digest and records an informational metadata note,
"ShadowScan report regenerated; normalized content unchanged", which is not a
security alert. A changed finding raises a medium alert on its own component,
including when only fields that the BOM does not project changed, and the
changed report content raises the high alert "ShadowScan report content changed".
Findings are matched by their source identifier, not their position: a finding
inserted before others alerts only as an added component, and reordering the
CycloneDX `dependencies` array changes no relationship. An inventory
written by an earlier version may have no content digests or an older projection
profile. The first comparison after an upgrade then falls back to the exact report
digest, which raises a high alert when the report bytes differ, and raises a medium
alert for every imported component, even when the report bytes are unchanged,
because the new inventory adds the content digests, a later projection profile and
the per-component finding digests. Later comparisons use the content digests. The content
digests are not authentication; `validate --project` compares them with the
local report as it does the exact digest. Text output prints the note under
Notes; `--json-output` lists it in `metadata_changes`.

A changed projection profile keeps the report's content digest comparable, but not
a component's finding digest: `diff` compares finding digests only between two
inventories of one projection profile. The first `diff` from a version 5 inventory to
a version 6 inventory of the same report file raises a medium alert for every
component the earlier inventory imported
("properties.shadowscan:projection-profile changed."), and reports each newly
projected finding as an added component, at medium or at its ShadowScan rating when
that is higher. When ShadowScan ran again between the two scans, which is the usual
case in a pipeline, the alert for each previously imported component is high instead
("properties.shadowscan:report-sha256 changed."), although the same `diff` notes that
the report's normalized content is unchanged. When entries are still unmapped it also
raises two high alerts, "New ShadowScan projection limitations" and "New coverage
gaps", because version 6 words both lines differently, although fewer entries are
unmapped. `validate --project`, `risk --project` and `verify-discovery --projection`
refuse a version 5 inventory, because each compares it with the current projection.

Between two version 6 inventories the coverage gap changes only when the set of
unmapped kinds does, and the limitation whenever a count does. A changed line is a
high alert in either direction. When entries left the report, the metadata change
"ShadowScan entries left unmapped fell from 2 to 1." says so.

ShadowScan's own finding content can include absolute paths of the directory it
scanned, which the content digests keep. Run ShadowScan from the same checkout path
for reports you intend to compare, or expect each finding to show as changed.

Reruns whose reports contain redacted credential findings compare cleanly only
when ShadowScan keys credential identities with a stable key, which the report
records as `collection_scope.credential_identity_scope` `keyed`; reports without
such findings compare cleanly in either scope. In the `run` scope, ShadowScan derives each redacted credential
finding's id from a random per-run key, so those findings get new ids on every
run and `diff` reports them as removed and added components. That fails safe,
as alerts, but configure a stable credential identity key in ShadowScan, by
setting `SHADOWSCAN_IDENTITY_KEY` for every run, before you compare reruns.

### Require a signed report in CI

`validate --project` and `risk --project` can require that the ShadowScan
evidence in a merged `scan` BOM comes from a report signed by the expected
producer. List the report in the operator signature policy passed with
`--signature-policy`, using the path the collector reads:

```json
{"version": 1, "artifacts": [{"artifact_path": ".shadowscan/report.json",
  "bundle_path": ".shadowscan/report.json.sigstore",
  "expected_identity": "https://github.com/acme/infra/.github/workflows/discovery.yml@refs/heads/main",
  "expected_issuer": "https://token.actions.githubusercontent.com"}]}
```

```sh
nexus-symbiote validate agentbom.json --project . --signature-policy /etc/ci/signers.json
nexus-symbiote risk agentbom.json --project . --signature-policy /etc/ci/signers.json
```

A signature policy entry that names one of the conventional report paths turns
the check on. An entry matches the report by path or by file, so another name
for the same file, such as a different case on a case-insensitive filesystem,
counts too. So does `--require-discovery-signature` on `validate` or `risk`, or
`validate.require_discovery_signature: true` in the project policy, which then
fails when no entry names the report. Set in an operator policy, it also fails
`validate` and `risk` without `--project` on an inventory that carries
ShadowScan evidence, whatever `--allow-unsigned-discovery` says, as no report
can be verified there. The project-policy setting is ignored, like
the rest of the file, under `--no-project-policy`, so CI that ignores the project
policy passes the command-line flag. Keep the signature policy outside the
checkout, as the project policy can be changed by the code it gates. When the
check runs on an inventory without ShadowScan evidence, it fails if a report lies
beneath the project root or a policy entry names one, so stripping the evidence
cannot pass it; with no evidence and no report it prints `not applicable`. When
no check runs, `validate` prints that discovery evidence was accepted unverified
and `risk --json-output` reports `discovery_producer` as `not-verified`. When the
BOM carries ShadowScan evidence, the check reads
the report beneath the project root with the collector's confined reader and
requires its digest to equal the BOM's recorded `source_report_digest`. It then
verifies the bundle offline over those exact bytes against the policy's identity
and issuer, and requires the BOM's discovery evidence to match the report's
projection. A missing entry or bundle, another signer or issuer, a bundle over
other bytes, or a report changed since the scan fails the command; `risk` then
reports `project-reconciliation-failed` with the reason. Values recorded in the
BOM are never trusted for this check. A passing check authenticates the
report's producer, not the truth of its findings, and imported components keep
declared assurance. Install the Sigstore extra for this mode.

The check binds the report to its producer and to the exact report bytes, and
the BOM records the verification outcome (`metadata.completeness.discovery_verification`):
`verified` with the signer identity and issuer, or `unverified`, together with
the report digest, the report's own run time, and the repository/commit the
report carries — currently both `unknown`, because the report format carries
neither. It does not bind the report to this repository or commit. Anyone who
can write to the checkout can substitute an older report, or another
repository's report, signed by the same identity, for example one from before a
shadow agent appeared, and regenerate the BOM from it. Give each repository's
discovery workflow its own signer identity, and bind the commit separately
where you need that. Unsigned evidence warns loudly on `import-shadowscan`,
`validate` and `risk`, and fails in CI (or with `--fail-on-unsigned-discovery`)
unless the operator explicitly passes `--allow-unsigned-discovery`.

The GitHub Action runs in CI, so a checkout with a ShadowScan report fails its
completeness and risk gates by default: the `gates` output records both as
`failed`, `risk-score` stays empty and the job log and step summary give the
reason. With `validate: 'true'` the Action passes its `signature-policy` snapshot
to both `validate --project` and `risk --project`, so a policy entry that names the report and
verifies its producer passes the check. To accept unsigned evidence instead, set
the `allow-unsigned-discovery` input to `'true'`, which passes
`--allow-unsigned-discovery` to `validate` and `risk` and prints a warning.

To accept only one report, write a
version 2 entry (`"kind": "sigstore-message-signature"`) with `expected_sha256`
set to the report's SHA-256: the check then also fails for other report bytes,
however they are signed. The report needs such a signature entry: a
`digest-pin` entry for it, or an entry for a report location the collector does
not read (it considers `.shadowscan/report.json`, `shadowscan-report.json` and
`shadowscan.json`, and rejects multiple distinct reports), is reported as an
unused policy entry by `scan` and `validate --project`
([model integrity](model-integrity.md#operator-signature-policy)).

### Verify the native import and its producer

For a BOM written by `import-shadowscan`, reproduce the direct import and compare
the component records, dependencies, coverage, unmapped indexes and metadata.

```sh
nexus-symbiote verify-discovery agentbom.json shadowscan.json --projection
```

For an independently signed report, pass the signing policy from trusted operator
configuration. The bundle must be a Sigstore artifact bundle over the exact
ShadowScan report bytes. Install the Sigstore extra for this mode.

```sh
nexus-symbiote verify-discovery agentbom.json shadowscan.json \
  --bundle shadowscan.json.sigstore --signer-identity "$EXPECTED_IDENTITY" \
  --issuer "$EXPECTED_ISSUER"
```

The same verification can run at import time: `import-shadowscan --bundle
shadowscan.json.sigstore --signer-identity "$EXPECTED_IDENTITY" --issuer
"$EXPECTED_ISSUER"` records the evidence as `verified` with the signer identity
and issuer in the BOM. Without `--bundle` the import records `unverified`;
`validate` and `risk` then warn loudly, and fail in CI (or with
`--fail-on-unsigned-discovery`) unless `--allow-unsigned-discovery` is given.

The signed mode also verifies the direct native projection. Use the same importer
version. The comparison ignores JSON object key ordering and the BOM's locally
generated timestamp and serial number. Source findings keep their declared
assurance. Merged, enriched and portable BOMs require their own provenance, so
`verify-discovery --bundle` rejects a `scan` BOM; use the CI check above for one.

The offline signature regression uses a public release bundle from
[sigstore-python at 19b8aec](https://github.com/sigstore/sigstore-python/blob/19b8aec7063e62c718efd327f5a45582472c3b3c/test/assets/bundle_v3_github.whl.sigstore).
Its Apache-2.0 license accompanies the fixture. Production report verification
requires your own producer identity, issuer and report bundle.

## Approve in SymBiote, reconcile in ShadowScan

ShadowScan's `--inventory` does not read the native AgentBOM; it refuses it. To
make an agent you approved in SymBiote review an approved agent in ShadowScan's
reconciliation, export the reviewed inventory and give the file to ShadowScan:

```sh
nexus-symbiote export-inventory reviewed.json --format shadowscan-simple \
  --resource-prefix github:acme/support-triager -o approved.json
```

The file approves only the project that ShadowScan's code connectors report for
the repository at that resource, registered under the agent's reference, which the
`id` in `agent.yaml` determines. Keep it where the change under review cannot
write, sign it with `attest`, and check the signature with `verify-attestation`
before ShadowScan reads it, because ShadowScan checks none. See
[Approve agents for ShadowScan reconciliation](shadowscan-inventory-export.md) for
the binding rules, the prefix to use and what the file does not establish.
