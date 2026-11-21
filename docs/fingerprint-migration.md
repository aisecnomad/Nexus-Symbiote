# Tool fingerprint migration

Prior versions used a serializer that was not RFC 8785 compliant. The corrected
serializer may produce different SHA-256 digests for the same tool definition,
particularly for floating point numbers and non-BMP property names. Current scanner
findings record `definition_hash_version: rfc8785-jcs-v2`. The v2 profile also
binds supported descriptor annotations; v1 and absent profiles require
recollection before verification.
An absent or unsupported version is not treated as verified. A bare
`sha256:` digest does not identify which serializer produced it.

Before using the corrected version for drift or policy decisions, re-collect
and re-approve both baseline and observed tool definitions under the same
version. Do not migrate a trusted baseline by copying its old digest or treat
old and new digests as directly comparable. Keep the original evidence for
audit. Malformed or non-finite numeric values now fail canonicalization rather
than being converted to null.

The source fingerprint covers the original declared name, description, input
schema and annotations, and also `title`, `outputSchema` and `_meta` when the
descriptor declares them. A definition without those members keeps the
fingerprint it had before they were bound, so `rfc8785-jcs-v2` is unchanged;
a tool whose descriptor declares one of them gets a new fingerprint once, and
its baseline needs one re-approval. Exported schemas omit literal defaults,
examples, constants and enumeration values, which can contain credentials. When
the displayed definition differs, `redacted_definition_hash` binds that view.
Static MCP configuration inventories display the name, description, input
schema and annotations; they omit `title`, `outputSchema` and `_meta`, so a
static tool that declares any of these has a `redacted_definition_hash`.
Current live observation inventories retain the safe extension values in
`mcp_title`, `mcp_output_schema` and `mcp_meta`. They have a
`redacted_definition_hash` only when their displayed descriptor differs from
the original. `validate` reports either kind as `unknown`
(`descriptor_source_unavailable`) until source evidence corroborates it.
Every displayed extension participates in the digest check. If both property
spellings are present (`mcp_title` and `title`, `mcp_output_schema` and
`output_schema`, or `mcp_meta` and `meta`), they must have equivalent JSON
values; a null value cannot hide a non-null alias. A historical
observation with an extension-free display hash still passes this consistency
check when its full displayed descriptor matches its original definition
hash. If redaction prevents that match, recollect it; an extension-free hash
cannot corroborate displayed extension values. The fingerprint profile and
digests of unchanged descriptors stay the same.

The source fingerprint is an unkeyed digest of the original, so anyone
holding the BOM who knows the rest of a descriptor can confirm a guess of an
omitted low-entropy literal or of scrubbed text; keep credentials out of tool
descriptors and treat exported BOMs as sensitive. For a static MCP
configuration, run `validate` with `--project` and
`--no-project-policy` to corroborate the source fingerprint against the
checkout. An inventory written by `discover-mcp --record` has no local source,
so such tools stay `unknown` there; `diff` against an earlier observation is the
check for them. A displayed schema with omitted literals is unsuitable for
deciding which arguments a live tool accepts.

Model components are now referenced by their path relative to the scanned
root: `model:<relative path>`, with the same relative path as `name` and
`source_path`. A model in a direct subdirectory of the root keeps its previous
reference; a model at the root or deeper in the tree gets a new one, so `diff`
against an older baseline reports it as removed and added. New model records
also bind ONNX external data, SavedModel variables, shard indexes,
configuration, tokenizer files, chat templates and declared custom code, and
`tokenizer_hash` and `chat_template_hash` are now digests over every such file
([model integrity](model-integrity.md)). Recollect and review the baseline once
after upgrading instead of comparing old and new model records.

For classified package launchers, new inventories retain `launcher_package`
alongside the declared version and, for an exact npm or PyPI version resolved
from the default registry, `package_url`. Inventories written by 0.1.0
identified only `npx`, `bunx`, `uvx`, `pipx` and `docker run` with a few
options, recorded a version-tagged image as pinned (only a digest pins an image
now) and carry the static configuration digest profile
`nexus-symbiote/mcp-static-config/v2`, which `validate --project` reports as
unknown. Recollect the baseline and review the identity, the new findings and
the `packages`, `package_sources` and `launch_context` properties before
approving the new snapshot. Python server references no longer contain the
declaration line, and the stdio note moved from `transport_security` to
`local_process`, so `diff` against a 0.1.0 baseline reports those records as
removed and added or changed once. An observed package name and version do not
establish the identity of installed executable bytes.

CycloneDX `dependsOn` contains only unconditional native `depends-on` edges
and, since projection 2, the dependency of a tool on the MCP server whose
unconditional `provides-tool` edge offers it. Invocation, lineage and
conditional relationships remain in the native extension, and the
`nexus-symbiote:dependency:relationship` property of a conditional edge carries
`"conditional": true`. CycloneDX and SPDX recovery check the standard projection
against the embedded document.

## MCP resolver binding v3

`nexus-symbiote/mcp-static-values/v3` retains the complete Deno import-name-to-target
and scope associations in the private keyed preimage. Version 2 could keep the
same binding when two import targets were swapped. Recollect and review keyed
MCP baselines and candidates under v3; v2 records fail project reconciliation.
Do not relabel an old digest or compare the profiles as if they authenticated the
same preimage. That change left the exported-structure profile at
`mcp-static-config/v3`; see [MCP static structure v4](#mcp-static-structure-v4).

Explicit Deno `--config`/`-c`/`--no-config` and `--import-map` selection, referenced
`importMap` files and unsupported import/scopes shapes now produce coverage gaps.
Review and replace those launch forms or resolve them outside this collector;
do not approve their partial inventories as trusted baselines.

## MCP static structure v4

`nexus-symbiote/mcp-static-config/v4` adds the sorted, redacted names of the
tools in each auto-approval and tool filter field to the exported structure
(`client_settings.auto_approved_tools` and `client_settings.tool_filter_names`,
one list per field). Under v3 only their counts were digested, so swapping which
tool is auto-approved or filtered, or moving a tool between `alwaysAllow` and
`autoApprove`, kept the digest. Every static MCP record's `static_config_hash`
changes once: `diff` against a v3 baseline reports a critical static source
binding change with `properties.static_config_hash_profile changed`, and
`validate --project` reports v3 records as unknown. Recollect and review the
baseline, including the exported tool names, before approving it.

The same release names client settings whose values the export records only as
present or redacted: a `cwd` other than the workspace root (`.`, `./`,
`${workspaceFolder}`, `${workspaceFolder}/` written exactly in a root configuration
file, so ` .` is another directory; nested configuration files mark every `cwd`
unbound), `envFile`, `watchPaths`, `oauth`, `auth`, `dev`, `env_vars`,
`bearer_token_env_var`, `env_http_headers`, and tool approval or
filter entries altered by redaction (which also record a coverage gap without the key).
Without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, a server that declares one carries the low
`completeness` finding, and `diff --fail-on-alert` raises the medium alert that
launch values are unbound for it, even between identical inventories. Set the key
on both collections to compare those values, or review and accept the alert.

## Pickle-family inspection evidence

A pickle-family file (`.pkl`, `.pt`, `.bin` and the other names listed in
[model integrity](model-integrity.md#model-files-and-references)) is rated by its
inspected content, and `properties.format_inspection` names what was recognized,
where it named the loader before. So `diff` against an inventory collected before
the upgrade reports every pickle-family file once as modified: at medium,
`properties.format_inspection changed`, for a file that keeps its rating, as a
recognized pickle does; at high for a file whose rating moved from
`unsafe-code-execution` to `unknown`, with the critical `serialization_format`
finding removed and the high `serialization_format_unknown` finding added, as a
zero-filled `embeddings.bin` does. `validate --project` against such an inventory
reports each of those files as a missing or mismatched local component and fails.
Recollect and review the baseline once after upgrading.

## Source MCP server names

An MCP server collected from source is named by the literal name its constructor
declares, `new McpServer({ name: "analytics-mcp" })` or `FastMCP("analytics-mcp")`,
instead of the variable it is bound to; the variable is kept in the `binding`
property. A TypeScript or JavaScript server's reference carries that name, so for
a server with a literal name both the reference and the references of its tools
change once: `mcp-source:src%2Fserver.ts:server:2:84` becomes
`mcp-source:src%2Fserver.ts:analytics-mcp:2:84`, and `diff` against an earlier
baseline reports the server and its tools as removed and added, with a high alert
for each removal and a medium alert for each addition. The repository agent lists
the old tool references, so it is reported as modified with a high
`tool_refs changed` alert, and its `configured-with` relationships to the server
and its tools and the server's `provides-tool` relationships are reported as
removed and added. A Python server keeps its `mcp-python:<path>:<variable>`
reference, so `diff` reports it as modified once, with `properties.binding added`
and `name changed`. A server whose name is computed keeps its name and reference,
and `diff` reports it as modified once, with a medium alert for
`properties.binding added`. Recollect and review the baseline once after upgrading.

Every source server gains the `binding` property, so an inventory written before
this change no longer matches a fresh collection of its project, whether its source
servers declare a literal or a computed name, in TypeScript, JavaScript or Python.
Recollect it before checking it against the project: `validate <inventory> --project .`
exits 1 with `Validation: FAILED` and an error such as
`Missing or mismatched local component from MCP inventory: mcp-source:src%2Fserver.ts:analytics-mcp:2:84`,
and `risk <inventory> --project .` exits 1 with
`Risk unknown. Project reconciliation failed.` followed by the same mismatch.
A server with a literal name is also listed as
`Supplied component has no matching local evidence` under its earlier reference.

One alert is lower than before. Renaming the variable of a TypeScript server with a
literal name and no tools, without moving its constructor, removed one server and
added another, with a high alert for the removal and a high
`repository: tool_refs changed` alert; the reference now keeps the name, so `diff`
reports a medium `properties.binding changed` alert instead. A new variable of
another length moves the constructor, and its offset in the reference, so that
rename still raises both high alerts. A server with tools still raises a high
alert, for the changed registration digests of its tools.

## MCP client dialects

Junie's `.junie/mcp/mcp.json` was read as a nested `mcp.json`: its servers were
inventoried as launched from `.junie/mcp`, with the medium `package_source` finding
of a launch in a nested directory and no `package_url`, beside a coverage gap that
the client file was not inventoried. It is now the `junie` client's own file, whose
servers the collector reads as launched from the project root, so the same server
keeps its `bom_ref` but loses the gap and the `package_source` finding, gains a
`package_url` for an exact version from the default registry, and joins a new
`junie` MCP client.
`diff` against an inventory written before this change reports each such server
once as a critical `MCP server launcher package changed` alert, with the static
source binding and `package_url` changed and the `package_source` finding removed,
and the new client and its `configured-with` relationship as added. `validate
--project` of the earlier inventory already failed on its `MCP client configuration
not inventoried` gap and partial coverage; it now also fails because each Junie
server's component changed (its `package_url` and static source binding) and because
the new `junie` client and its `configured-with` relationship are missing.
Recollect the baseline, review the servers' package identities and the client, and
approve the new snapshot instead of accepting the alerts against the old one.

Servers in Zed, opencode and Continue files, and servers in any client file that
declare neither a command nor an endpoint, were gaps or gap-free records before; the
first scan after upgrading reports them as added, or adds a high
`launcher_identity` finding and a gap to them. For a server with no launch, `diff`
also reports `version_pinned` changed (unset before, `false` now, as for a Zed
extension server), a high `New coverage gaps` alert and, where the baseline's MCP
coverage was complete, `Collector 'mcp' coverage changed from complete to
partial`; `validate` warns that its package version is not pinned although it names
no package. Review them the same way.

## Neutralized identifiers

A component's `name`, `description` and `supplier`, and the tool names under an MCP
server's `client_settings.auto_approved_tools` and `tool_filter_names`, are now
neutralized where collector output is merged into the inventory, and on the
repository agent and the components its `agent.yaml` declares: a tab, line break,
form feed, backspace or delete becomes a space, so does the second `#` of a CI
log-command introducer, and other C0 and C1 controls, ESC, bidirectional and other
format characters become U+FFFD. Variation selectors and joiners in ordinary
spelling, such as an emoji's U+FE0F or a Persian word's U+200C, are kept
([known limitations](known-limitations.md#every-collector)). The SHA-256 of each
field's raw text is recorded under the component's `neutralized_raw_sha256`
property. A component whose name, description, supplier or nested tool names held a
reported character carries a high `identifier_characters` finding
([finding catalog](finding-catalog.md#categories)); a tab or line break in a
description or supplier is replaced without one. The details and recommendations
of every component's findings, and the text of `surfaces_excluded` and
`scan_failures`, are neutralized the same way without a finding of their own, since
they quote such names.

A component whose fields and finding details held no such character is recorded
exactly as before, so its content digest, its `bom_ref` and its findings are
unchanged, and `diff` against an earlier baseline reports nothing for it. That
includes a name whose words are in different scripts, such as `MCP сервер`, and a
name spelled with an emoji's variation selector or a joiner in ordinary spelling.
A component that held one records different text, the `neutralized_raw_sha256`
property, and a new finding when the character was reported, so its content digest
changes once, and so does that of a component whose name only mixes scripts within
a word, or has a word of Latin lookalikes beside Latin text, which gains the finding: `diff` reports the change, and `validate --project`
against a baseline collected by an earlier release reports it as a mismatch. An agent
whose `agent.yaml` `purpose` is a block scalar whose parsed value keeps a line break,
a literal one or a folded one without the strip indicator `-`, is one of these: its
description held line breaks, which are now spaces. So is an agent whose `name` is a
clip block scalar (`name: >` or `name: |`), now recorded without the line break YAML
ends it with. Recollect that baseline and
review the finding, which records the SHA-256 of each raw value, before approving
it. A tool whose name changed keeps its `definition_hash` over the original
descriptor, and its `redacted_definition_hash` is bound to the neutralized name, so
integrity validation still verifies it.

A finding's fingerprint covers its `detail`, so a suppression copied from an earlier
release no longer matches a finding whose detail quotes a name that is now
neutralized: the suppression is reported stale, under `suppressions_stale`, and the
finding counts again. Review
the finding and suppress it again under its new fingerprint, which `risk
--json-output` prints.

MCP server and tool references are digests of the raw name, so the raw text never
appears in them and they are unchanged. A reference derived from an A2A card's or
A2A client's name (`a2a-server:<name>`, `a2a-client:<name>`) or a RAG source's name
(`rag:<name>`) now percent-encodes, as its UTF-8 bytes, each character that
neutralization replaces in the name, so `a2a-server:browser<ESC>[2K` becomes
`a2a-server:browser%1B[2K`. A name that is encoded, or that already holds a `%`
and two hex digits, also has each `%` written `%25`, so a literal
`browser%1B[2K` becomes `a2a-server:browser%251B[2K` and no two names share a
reference; a name with neither is its own reference. Such a component has a new
reference, which `diff` reports as one component removed and another added, and
policy entries and suppressions that name the old reference no longer apply. References derived from a
path, such as a prompt import's, keep the path as collected, as do `source_path`,
evidence locators and `surfaces_scanned`
([known limitations](known-limitations.md#every-collector)).

## SARIF rule identifiers

0.1.0 keyed SARIF rules by category (`nexus_symbiote/<category>`) and raised a
rule's `security-severity` to the highest severity among that category's
findings in the run. Rules are now keyed by category and severity
(`nexus_symbiote/<category>/<severity>`), so a rule's severity no longer
depends on the other findings. GitHub code scanning matches a result to an
existing alert only under the same rule, so the first upload after upgrading
closes every alert from 0.1.0 and opens new ones: dismissals and comments on
the old alerts do not carry over, so review the new alerts and dismiss them
again where that still applies. Later, a finding whose severity changes moves
to the rule of its new severity, and code scanning again opens a new alert and
closes the old one. The `nexus_symbiote/v1` fingerprint keeps its 0.1.0 value
and, like `primaryLocationLineHash`, stays the same when the severity changes;
consumers that match findings across runs should use it rather than the rule id.

## Standard projection versions

Every CycloneDX and SPDX export declares the projection that produced its
standard fields in the `nexus-symbiote:projection` property, and recovery checks
the document against that projection only. Projection 1 is what 0.1.0 wrote:
those exports have no marker and still recover. Projection 2
(`cyclonedx-1.7/2`, `spdx-3.0.1/2`) changes the standard fields as follows.

- CycloneDX: the repository agent of a scan is `metadata.component` instead of a
  component; registry entries are `library` or `container` instead of `platform`,
  their `version` carries exact versions only, and their other declarations move
  to the `nexus-symbiote:requestedVersion` property; instruction-file, RAG index,
  dataset and lockfile digests are `hashes`; `source_path` is
  `evidence.occurrences`; the composition names the subject; a repository scan
  has the `pre-build` lifecycle. Extension properties spell booleans `true` and
  `false` instead of `True` and `False`, write structured values as JSON, and
  omit a `toolCount` of 0.
- SPDX: license relationships point at `expandedlicensing_NoAssertionLicense`
  instead of `https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion`, which SPDX
  3.0.1 does not define; placeholder AI and dataset text, `noAssertion` presence
  fields and `software_downloadLocation` are omitted; a `software_Sbom` element is
  the document's root; `profileConformance` adds `expandedLicensing`; and the
  default identifiers are `urn:uuid` IRIs instead of IRIs under
  `https://spdx.org/spdxdocs/nexus_symbiote`.
- Both: the loss report (profile `nexus-symbiote-export/v2`) also lists risk
  findings and declared versions that are not exact. A package URL is a standard
  identifier only when it is a PyPI, npm or OCI identity that agrees with the
  component: a PyPI or npm package URL only on a registry entry whose
  `registry_type` names that ecosystem and the registry it was resolved from, and
  an MCP server's package URL when it names the server's launcher package and
  version.

A document with an unknown marker, or one whose standard fields match a
projection other than the one it declares, is rejected. Recovery returns the
embedded inventory unchanged; re-export it to give standard-only consumers the
current projection's fields. Only projection 1 recovery accepts the undefined license
IRI. Recovery compares standard fields with the embedded document text, so
fields that the native model gains in a later release do not make earlier
exports unrecoverable. See [standard exports](standard-exports.md) for every
field.

SPDX projection 3 (`spdx-3.0.1/3`) neutralizes the native text in relationship
comments: a tab becomes a space, a `##name[` CI log command is broken, and C0
and C1 controls, line and paragraph separators, format, bidirectional and other
default-ignorable characters and the noncharacters U+FFFE and U+FFFF become
U+FFFD. The projection fixes this character set rather than following terminal
output, whose set grows as new disguising characters are found, so later
releases render and recover projection 3 comments alike. The embedded native
conditions remain unchanged. Recovery continues to accept projection 2 with its
original comment rendering, including ordinary multiline conditions; it does not
silently reinterpret that marker as projection 3. To obtain the neutralized
display, recover an older export and re-export it. Do not change its projection
marker by hand. CycloneDX remains at projection 2, and neither native content
digests nor tool fingerprints change.

For historical CycloneDX exports that flattened all relationships into
`dependsOn` and wrote no `conditional` flag, the Python API accepts
`CycloneDXGenerator.recover(document, allow_legacy_relationships=True)`.
Legacy mode applies only to exports without a projection marker, and accepts
that exact historical edge projection only as a whole. It rejects a mixture of
the historical and current edge projections, and it still checks every other
public field, including the coverage composition, against projection 1.
Re-export the recovered inventory to give standard consumers the corrected
graph and flags.

Exports written by builds before 0.1.0 can fail recovery, because their
standard fields match none of the supported projections.
Legacy mode, which only CycloneDX recovery has, does not help with:

- a CycloneDX export whose `dependsOn` already lists only unconditional
  `depends-on` edges but whose conditional edges have no flag;
- a CycloneDX export of a scan whose coverage is now `incomplete`, such as one
  narrowed with `--scanner`, written before every export had a `compositions`
  entry;
- any SPDX export written before the document `comment` and relationship
  `completeness` existed, with or without an unconditional relationship exported
  as `other`.

Regenerate such exports from the native AIBOM or by rescanning. Keep the
original export when a downstream consumer discards fields such as the
CycloneDX incomplete-composition claim, because recovery requires that
evidence to remain present. cyclonedx-python-lib 11.12.0, for example, drops
`compositions` whenever it reserializes a BOM. A reserialized `incomplete`
export then no longer recovers, while a reserialized `unknown` export still
does.

Current CycloneDX 1.7 and SPDX 3.0.1 exports are checked against pinned official
schemas and exercised by independent consumer-library round trips. These checks
do not certify semantic equivalence or admission authority.

Static MCP configuration source binding is a separate versioned contract. See
[source reconciliation and snapshot migration](verification-source-binding.md).

## Documentation links in findings

Model-integrity findings carry a link to `docs/model-integrity.md` in the repository that
publishes this tool. When the repository's canonical owner changed to the aisecnomad account
(CHANGELOG, Unreleased), that link changed with it, so an inventory that holds a model-integrity
finding has a different content digest and serial number from the one the previous owner's build
wrote. The components, findings and relationships are otherwise the same. Re-baseline once; a
`diff --fail-on-alert` against an older baseline reports the changed recommendation text on each
such finding and nothing else.

## Upgrade attribution (`--expect-upgrade`)

When upgrading Nexus SymBiote across a documented profile transition (`0.1.0` or
`0.2.0`), `nexus-symbiote diff baseline.json candidate.json --expect-upgrade FROM_VERSION`
partitions alerts caused *exclusively* by the static list of serializer and profile
transitions since `FROM_VERSION` into `tool_upgrade_changes` while keeping genuine
supply-chain drift (added or removed components, changed commands or endpoints,
altered tool definitions, or any component where a profile transition co-occurs
with a content change) in `security_alerts`. Both supported releases wrote tool
fingerprints as `rfc8785-jcs-v2`, so `Tool fingerprint versions are unknown or
incompatible` is never attributed: it names a snapshot outside the documented
transition, and its changed hash can be a changed descriptor. Nor is an unsupported
`spec_version`, under which the comparison can miss any field. Re-collect and re-approve the baseline
once the upgrade diff has been reviewed.
