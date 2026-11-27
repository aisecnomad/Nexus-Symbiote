# Standard exports

One native AgentBOM projects to CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0 and a CycloneDX VEX document. This page says what each standard field carries, what only the native extension carries, and how to read the extension's properties. [What results do and do not establish](security-model.md#what-results-do-and-do-not-establish) applies to every format.

- [Projection versions](#projection-versions)
- [CycloneDX 1.7](#cyclonedx-17)
- [SPDX 3.0.1](#spdx-301)
- [Extension properties](#extension-properties)
- [SARIF for GitHub code scanning](#sarif-for-github-code-scanning)
- [VEX](#vex)
- [Minimum elements](#minimum-elements)
- [Loading exports into other tools](#loading-exports-into-other-tools)
- [Validation](#validation)

## Projection versions

CycloneDX and SPDX exports embed the native document and declare which projection produced their standard fields in the `nexus-symbiote:projection` property: `cyclonedx-1.7/2`, `cyclonedx-1.7/3`, `cyclonedx-1.6/3`, `spdx-3.0.1/3` or `spdx-3.0.1/4` (the last three from `export-standard`). Exports written by 0.1.0 carry no marker and use projection 1. SPDX projection 2 remains recoverable with its original relationship comments; projection 3 neutralizes those comments for display, with a character set the projection fixes, while preserving the original text in the embedded native document. Recovery (`CycloneDXGenerator.recover`, `SPDXGenerator.recover`) checks every standard field against the declared projection of the embedded document and rejects an unknown marker, a document that claims a projection it does not match, and any edit to a standard field. The one omission it accepts is a missing CycloneDX `compositions` array, which readers such as cyclonedx-python-lib drop, when the projection's only composition says `unknown`; a composition that is present must match exactly. Projection 3 likewise accepts the loss of every `modelCard`, which that library also drops, but not the loss or edit of only some. [Fingerprint migration](fingerprint-migration.md#standard-projection-versions) lists what changed between the projections.

## CycloneDX 1.7

| Native | CycloneDX | Notes |
| --- | --- | --- |
| Repository agent of a scan | `metadata.component` | The `agent:repository:` agent that `scan` assembles is the BOM's subject and is not repeated in `components`. Other inventories have no subject. |
| Component kind | `type` | Agents, MCP servers and clients, A2A endpoints and IDE agents are `application`; models are `machine-learning-model`; prompts, memory, RAG and data sources are `data`; tools, skills, guardrails and verified extensions are `library`. Registry entries are `container` for `docker-hub`, `docker` and `oci`, and `library` otherwise. |
| `version` | `version` | Exact versions only: a validated package URL version, an exact PyPI pin (`==`, `===` or a bare version), an exact npm version or an image version tag. Ranges, markers, URLs and tags such as `latest` go to `nexus-symbiote:requestedVersion` instead. Other component kinds export their declared version unchanged; any version longer than 1024 characters, the schema's limit, goes to the property too. |
| `package_url` | `purl` | Only a declared package URL that agrees with the component (see the loss report for omitted ones). A registry entry's names its `registry_type` (`pypi`, `npm`, or `oci` or `docker-hub` for an image pinned by digest), name, exact version and registry; an MCP server's names its `launcher_package` and version, from the default registry. |
| `hashes` and single-purpose digests | `hashes` | Declared digests, then an instruction file's `content_hash`, a RAG source's `index_snapshot_hash`, a dataset's `content_hash` and an npm lockfile integrity value when the algorithm is not already present. MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512 and BLAKE3 digests are supported; an empty, malformed or conflicting declared digest fails the export, and a malformed single-purpose digest is left out. |
| `source_path` | `evidence.occurrences[].location` | The file that declared the component. |
| `supplier`, `description` | `supplier.name`, `description` | As declared. |
| Unconditional `depends-on` | `dependencies[].dependsOn` | Source depends on target. |
| Unconditional `provides-tool` | `dependencies[].dependsOn` | The tool depends on the MCP server that provides it. |
| Conditional edges and every other relationship | `nexus-symbiote:dependency:relationship` property | Conditions, invocation, lineage and authority are not dependencies. A static scan's agent edges are all conditional, so a scan's graph holds at most tool-to-server rows. |
| Completeness claim | `compositions[].aggregate` | `incomplete` or `unknown`, never `complete`; with a subject, the composition names it in `assemblies` and `dependencies`. |
| Repository scan | `metadata.lifecycles` | `pre-build`: configuration read from a repository describes what is planned to run. |
| `metadata.authors` | `metadata.authors` | Exported when set; `scan` sets none. |

Risk findings, capabilities, authorizations, trust tiers, assurance levels and deployment profiles have no standard field and stay in the extension. Remote MCP servers and A2A endpoints are components, not CycloneDX `services`, and models have no `modelCard`.

## SPDX 3.0.1

| Native | SPDX | Notes |
| --- | --- | --- |
| Inventory | `software_Sbom` | The document's root element. Its root is the repository agent of a scan, otherwise every agent. `software_sbomType` is `source` for a repository scan. |
| Agents and models | `ai_AIPackage` | `software_primaryPurpose` is `application` or `model`; `ai_typeOfModel` carries a model's declared type, when the inventory records one, and `ai_informationAboutApplication` an agent's description. |
| Memory, RAG and data sources | `dataset_DatasetPackage` | `dataset_datasetType` is `noAssertion`, the only property the class requires. |
| Prompts | `software_File` | `verifiedUsing` carries the content digest. |
| Everything else | `software_Package` | |
| Licenses | `hasDeclaredLicense` and `hasConcludedLicense` | Every AI and dataset package points both at `expandedlicensing_NoAssertionLicense`, the individual SPDX 3.0.1 defines for no assertion. |
| Relationships | `Relationship` | Unconditional `invokes`, `depends-on`, `trained-on` and derivation edges are typed (`usesTool`, `dependsOn`, `trainedOn`, `descendantOf`); every other edge is `other` with a `comment` naming the native relationship and its condition, neutralized for display. |
| Coverage | relationship `completeness` and the document `comment` | `incomplete` or `noAssertion`. |

`profileConformance` lists `core`, `software` and `extension`, plus `expandedLicensing` when the license individual is used. The AI and Dataset profiles are not claimed: their classes are used, but the profiles also require a supplier, release time, version and download location (and, for datasets, an originator and build time) that an inventory does not collect. Unknown optional fields are omitted rather than filled with placeholder text, and `software_downloadLocation` is not written.

Element identifiers are scoped to one inventory revision. By default the document identifier is `urn:uuid:<uuid>` derived from the revision; `SPDXGenerator(namespace)` mints identifiers under `<namespace>/document/<revision digest>` instead. The namespace must be an absolute IRI without a query or fragment, and must not be under `spdx.org`.

## Extension properties

CycloneDX properties and SPDX `extension_CdxPropertyEntry` records use these names. A string value is written as is; booleans are `true` or `false`; numbers and structured values are compact JSON. Names and encodings are stable within a projection version. The `agentbom:` and `nexus-symbiote:` namespaces belong to this project and are not registered in the CycloneDX property taxonomy.

| Name | Where | Value |
| --- | --- | --- |
| `nexus-symbiote:document` | Document | The native AgentBOM as UTF-8 JSON with sorted keys and no whitespace (not RFC 8785). |
| `nexus-symbiote:documentDigest` | Document | `sha256:` and the SHA-256 of the document's deterministic JSON text (keys sorted, no whitespace, UTF-8), which is what `nexus-symbiote:document` holds as exported. Recovery recomputes it from the parsed value, so the check compares content: an embedded copy that differs only in key order, spacing or escapes still matches. Bind the export's exact bytes with an attestation. |
| `nexus-symbiote:lossReport` | Document | JSON naming selected native fields the standard fields omit or normalize (profile `nexus-symbiote-export/v2`). |
| `nexus-symbiote:projection` | Document | The projection version. |
| `nexus-symbiote:dependency:relationship` | CycloneDX document | One JSON object per native edge: `from`, `to`, `type`, and `"conditional": true` for a conditional edge. |
| `nexus-symbiote:discovery:reportSha256`, `:sourceFormat`, `:sourceStatus`, `:unmappedCount` | CycloneDX document | Imported ShadowScan report digest, format, status and number of unmapped entries. |
| `nexus-symbiote:omittedImportedFindings` | SARIF run, VEX document | How many imported ShadowScan findings were left out. |
| `nexus-symbiote:component` | Component | The native component as JSON. |
| `nexus-symbiote:relationship` | SPDX relationship | The native edge as JSON. |
| `agentbom:kind` | Component | The native component type. |
| `agentbom:claimsVerifiedByExporter` | Component | Always `false`: export does not verify claims. |
| `nexus-symbiote:packageIdentifierProjection` | Registry entry | `declared`, `unknown` or `unavailable-invalid`. |
| `nexus-symbiote:componentType`, `:trustTier`, `:assuranceLevel` | CycloneDX component | Native enumeration values. |
| `nexus-symbiote:requestedVersion` | CycloneDX component | A declared version that is not exact. |
| `nexus-symbiote:autonomyLevel`, `:framework`, `:modelRef`, `:toolRef` | CycloneDX agent | `autonomyLevel` is `unknown` when not declared; references repeat per target. |
| `nexus-symbiote:modelType`, `:provider`, `:serializationFormat`, `:serializationSafety`, `:signingStatus`, `:trustRemoteCode` | CycloneDX model | `trustRemoteCode` is a declared setting. `modelType` and `serializationFormat` are absent when the inventory records none, as for a model file whose [format was not established](model-integrity.md#format-and-model-type). |
| `nexus-symbiote:definitionHash`, `:definitionHashVersion`, `:annotation.<name>` | CycloneDX tool | One annotation property per MCP annotation. |
| `nexus-symbiote:transport`, `:toolCount`, `:versionPinned`, `:schemaHash` | CycloneDX MCP server | `toolCount` is written only when nonzero, because zero also means not observed. |
| `nexus-symbiote:promptType`, `:contentHash` | CycloneDX prompt | |
| `nexus-symbiote:guardrailType` | CycloneDX guardrail | |
| `nexus-symbiote:storeType`, `:tenantIsolated`, `:encryptionAtRest` | CycloneDX memory store | Absent means unknown. |
| `nexus-symbiote:corpusType`, `:embeddingModel` | CycloneDX RAG source | |
| `nexus-symbiote:registryType`, `:publisherVerified` | CycloneDX registry entry | |
| `nexus-symbiote:skillType` | CycloneDX skill | |

Projection 1 (0.1.0) wrote booleans as `True` and `False`, structured annotation values in Python notation, and `toolCount` `0` for unobserved counts.

## SARIF for GitHub code scanning

Every result has one location: a URI relative to `%SRCROOT%`, with no `originalUriBaseIds` and therefore no host path. `%SRCROOT%` is the working directory for `scan` (the scanned directory itself when it lies outside the working directory) and the workspace for the GitHub Action, so a project scanned below the repository root is located under its path. A finding takes its component's file; a tool without one takes its MCP server's file; anything else, such as a vector store detected from an import or a path outside the source root, is anchored to `.nexus-symbiote.yaml` in the scanned directory, and the result's `location_source` property says which applied. For a static source declaration with its own file and a recorded line, the location includes a one-based SARIF `region.startLine`. This identifies the declaration to inspect. Findings that use a fallback or lack a usable line keep their file-level location.

Rules are keyed by category and severity (`nexus_symbiote/<category>/<severity>`), so a rule's `security-severity` (critical 9.5, high 8.0, medium 5.0, low 2.0, info 0.0) and `defaultConfiguration.level` never depend on the other findings in a run. Rule descriptions and help come from the catalog below, never from the inventory. Each result carries `partialFingerprints.primaryLocationLineHash` and `nexus_symbiote/v1`, both derived from the category, the component reference and the finding text: they stay the same across runs, checkouts and severity changes, and differ for two findings in one file. Because the severity is part of the rule id, a finding whose severity changes is reported under another rule: GitHub code scanning then opens a new alert and closes the old one, and a dismissal of the old alert does not carry over. The first upload after upgrading from 0.1.0, whose rule ids had no severity, re-creates every alert this way ([migration](fingerprint-migration.md#sarif-rule-identifiers)).

Messages and recommendations are one line of plain text: control, bidirectional and invisible characters become U+FFFD, the text is cut at 1,000 characters, every `://` and `www.` is defanged (`https[:]//`, `www[.]`) whatever precedes it, and brackets and backslashes are escaped as SARIF requires. Text from a repository therefore cannot form an embedded link, and a web address in it is not turned into a link. SARIF message text is plain text; a viewer that rendered it as Markdown or HTML would need its own escaping.

`invocations[0].executionSuccessful` is `false` when the inventory records a collection failure or a failed collector. `toolExecutionNotifications` lists failures as errors, coverage gaps and collectors that did not run as warnings, and the coverage summary; at most 100 notifications are written. A run with more than 25,000 results, which GitHub does not keep in full, gets a warning. The run's `coverage` property is `incomplete` or `unknown`. Findings on components imported from a ShadowScan report are not this tool's findings: they are omitted, and the run property `nexus-symbiote:omittedImportedFindings` counts them.

| Category | Rule title | CWE | OWASP LLM 2025 | OWASP LLM 2026 | OWASP Agentic | MITRE ATLAS | NIST AI RMF |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `additional_directories` | Access outside the project | none | LLM06:2025 | LLM03:2026 | ASI03 | none | MEASURE-2.7 |
| `attestation` | Unattested extension | CWE-345 | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0010.001 | MANAGE-3.1 |
| `authentication` | Missing authentication requirement | CWE-306 | none | none | ASI03, ASI07 | none | MEASURE-2.7 |
| `auto_approval` | MCP tools without per-call approval | none | LLM06:2025 | LLM03:2026 | ASI02 | AML.T0053 | MEASURE-2.7 |
| `bidi_override` | Bidirectional override in instructions | CWE-451, CWE-1427 | LLM01:2025 | LLM01:2026 | ASI01 | AML.T0068 | MEASURE-2.7 |
| `capability_scope` | Destructive tool capability | none | LLM06:2025 | LLM03:2026 | ASI02 | AML.T0053 | MEASURE-2.7 |
| `code_execution` | Remote code execution enabled | CWE-494, CWE-829 | LLM03:2025 | LLM04:2026 | ASI04, ASI05 | AML.T0011.000 | MANAGE-3.2 |
| `completeness` | Incomplete declaration | none | none | none | none | none | GOVERN-1.6 |
| `credential_exposure` | Literal credential in an MCP launch | CWE-798 | LLM02:2025 | LLM02:2026 | ASI03 | none | MEASURE-2.7 |
| `credential_helper` | Credential helper command | none | none | none | ASI03, ASI05 | AML.T0142 | MEASURE-2.7 |
| `custom_code` | Custom model code | CWE-829 | LLM03:2025 | LLM04:2026 | ASI04, ASI05 | AML.T0011.000 | MANAGE-3.2 |
| `data_integrity` | Retrieval source integrity | CWE-319 (critical and high findings) | LLM04:2025, LLM08:2025 | LLM05:2026, LLM09:2026 | ASI06 | AML.T0070 | MEASURE-2.7 |
| `detection_method` | Code-detected reference | none | none | none | none | none | GOVERN-1.6 |
| `directional_marks` | Directional marks in instructions | none | LLM01:2025 | LLM01:2026 | ASI01 | AML.T0068 | MEASURE-2.7 |
| `endpoint_identity` | Unestablished endpoint identity | none | none | none | ASI07 | none | MEASURE-2.7 |
| `hidden_markup` | Comments in instructions | none | LLM01:2025 | LLM01:2026 | ASI01 | AML.T0068 | MEASURE-2.7 |
| `hook_commands` | Hook commands | none | none | none | ASI05 | AML.T0142 | MEASURE-2.7 |
| `identifier_characters` | Control, format or mixed-script characters in an identifier | CWE-451, CWE-1427 | LLM01:2025 | LLM01:2026 | ASI01 | AML.T0010.005, AML.T0068, AML.T0074 | MEASURE-2.7 |
| `instruction_injection` | Injected instructions or deception in prompt files | CWE-1427 | LLM01:2025 | LLM01:2026 | ASI01 | AML.T0068 | MEASURE-2.7 |
| `instruction_layering` | Layered instruction files | none | LLM01:2025 | LLM01:2026 | ASI01 | none | MEASURE-2.7 |
| `invalid_safetensors` | Unverified SafeTensors structure | none | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0011.000 | MANAGE-3.2 |
| `invisible_characters` | Invisible characters in instructions | CWE-451, CWE-1427 | LLM01:2025 | LLM01:2026 | ASI01 | AML.T0068 | MEASURE-2.7 |
| `launch_context` | Widened MCP launch context | none | none | none | ASI05 | none | MEASURE-2.7 |
| `launcher_identity` | Unknown MCP launcher identity | none | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0010.005 | MEASURE-2.7 |
| `line_separators` | Line or paragraph separators | none | LLM01:2025 | none | none | none | MEASURE-2.7 |
| `local_process` | Local MCP server process | none | none | none | ASI07 | AML.T0010.005 | MEASURE-2.7 |
| `lockfile_resolution_mismatch` | Lockfile resolution mismatch | none | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0010.001 | MANAGE-3.1 |
| `lockfile_unread` | Unread lockfile | none | none | none | none | none | GOVERN-1.6 |
| `mcp_auto_approval` | Project MCP servers approved without a prompt | none | none | none | ASI04 | AML.T0010.005 | MEASURE-2.7 |
| `missing_lockfile_integrity` | Lockfile record without integrity | CWE-494 | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0010.001 | MANAGE-3.1 |
| `mutable_image_tag` | Mutable image tag | CWE-829 | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0010.004 | MANAGE-3.1 |
| `nonregistry_source` | Package from outside a registry | CWE-829 (high findings) | LLM03:2025 (high findings) | LLM04:2026 (high findings) | ASI04 (high findings) | AML.T0010.001 (high findings) | MANAGE-3.1 (high findings) |
| `oversight_gap` | Destructive tool auto-approved | CWE-250 | LLM06:2025 | LLM03:2026 | ASI02 | none | none |
| `package_alias` | Package alias | none | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0074 | MANAGE-3.1 |
| `package_source` | Non-default MCP package source | none | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0010.005 | MANAGE-3.1 |
| `permission_scope` | Unscoped agent permissions | CWE-250 | LLM06:2025 | LLM03:2026 | ASI02, ASI03 | AML.T0053, AML.T0105 (high findings) | MEASURE-2.7 |
| `plugin_sources` | Plugin sources | none | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0010.005 | MANAGE-3.1 |
| `prompt_size` | Large instruction file | none | LLM01:2025 | LLM01:2026 | ASI01 | none | MEASURE-2.7 |
| `rag_discovery` | Undeclared retrieval source | none | LLM08:2025 | LLM09:2026 | ASI06 | none | GOVERN-1.6 |
| `registry_origin` | Non-default package registry | none | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0010.001 | MANAGE-3.1 |
| `runtime_undeclared` | Runtime component not matched to the inventory | none | none | none | ASI04 | none | GOVERN-1.6 |
| `serialization_format` | Unsafe model serialization | CWE-502 (critical findings), CWE-1336 (high findings) | LLM03:2025 | LLM04:2026 | ASI04, ASI05 | AML.T0011.000 | MANAGE-3.2 |
| `serialization_format_unknown` | Unknown model serialization safety | CWE-502 | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0011.000 | MANAGE-3.2 |
| `settings_environment` | Redirecting or code-loading settings environment | none | none | none | ASI03 (high findings), ASI05 (medium findings) | none | MEASURE-2.7 |
| `shadowscan-heuristic` | Imported discovery risk | none | none | none | none | none | none |
| `shadowscan-inventory-unmatched` | Imported unmatched discovery | none | none | none | none | none | GOVERN-1.6 |
| `signing_status` | Unsigned model artifact | CWE-345 | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0010.003 | MANAGE-3.2 |
| `subagent_inline_mcp_server` | Subagent inline MCP server | none | LLM03:2025 | none | ASI04 | none | MANAGE-3.1 |
| `tag_characters` | Unicode tag characters in instructions | CWE-451, CWE-1427 | LLM01:2025 | LLM01:2026 | ASI01 | AML.T0068 | MEASURE-2.7 |
| `tool_description_poisoning` | Poisoned instructions in tool description or schema | CWE-1427 | LLM01:2025 | LLM01:2026 | ASI01, ASI02 | AML.T0010.005, AML.T0068 | MEASURE-2.7 |
| `transitive_resolution` | Dependencies resolved at launch | CWE-829 | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0109 | MANAGE-3.1 |
| `transport_ambiguity` | Ambiguous MCP transport | none | none | none | none | none | MEASURE-2.7 |
| `transport_security` | Transport security | CWE-319 (critical and high findings) | none | none | ASI07 | none | MEASURE-2.7 |
| `version_pinning` | Unpinned version | CWE-829 | LLM03:2025 | LLM04:2026 | ASI04 | AML.T0109 | MANAGE-3.1 |

Every rule is tagged `security`, then with each entry in its row, in lower case as GitHub normalizes tags: `external/cwe/cwe-NNN`, `external/owasp-llm-top-10-2025/llmNN`, `external/owasp-agentic-top-10/asiNN`, `external/owasp-llm-top-10-2026/llmNN`, `external/mitre-atlas/` with the technique, such as `aml.t0010.005`, and `external/nist-ai-rmf/` with the subcategory, such as `measure-2.7`. Every tag that a rule carried before the 2026, ATLAS and NIST tags were added is still there, in the same order, so a filter on it still matches. The categories that had no catalog entry had generic rules tagged only `security`; most of their rules now carry CWE, OWASP 2025 or Agentic tags as well, so a filter on such a tag also matches their findings. A few earlier tags do not hold for every finding of their rule and were kept so that the rules keep their tags; the framework crosswalk's [limits](framework-crosswalk.md#limits) list them. Every category in the [finding catalog](finding-catalog.md#sarif-rules) has a rule, and so has `runtime_undeclared`, which only `trace-diff --sarif` writes, in SARIF of its own whose results are anchored to the inventory's path relative to the working directory, or to `.nexus-symbiote.yaml` when the inventory lies outside it ([trace evidence](trace-evidence.md#sarif)); a category outside the catalog, such as one that an edited inventory records, gets a generic rule titled after the category and tagged only `security`. The [framework crosswalk](framework-crosswalk.md) gives the rationale for each reference, the editions and their sources, and the EU AI Act and ISO/IEC 42001 references, which are not tags. A reference says what a finding records evidence of; a finding is a declaration in the repository, or for `runtime_undeclared` a use that the agent's own telemetry reports, not a confirmed vulnerability.

The exporter validates its output offline against the vendored official OASIS SARIF 2.1.0 JSON schema (`sarif/sarif-schema-2.1.0.json`, checked against its recorded SHA-256 digest in `SOURCES.json`) and a GitHub code scanning structural profile validator (required properties, levels, rule cross-references, relative locations and fingerprints).

## VEX

The `nexus-symbiote/vex-content/v2` serial profile identifies the complete exported VEX document. It hashes the deterministic JSON document before adding `serialNumber`, then derives a UUIDv5 in the project namespace from `nexus-symbiote/vex-content/v2:` and the prefixed SHA-256 digest. A change to a decision, evidence authentication, or advisory coverage produces a new serial. The BOM-Link continues to identify the source inventory. Consumers upgrading from the inventory-only serial should re-baseline VEX identifiers.

`vex` writes a CycloneDX 1.7 document whose `vulnerabilities` are the inventory's risk findings:

- Its version is the inventory's version. `metadata` names the producing tool and includes the inventory timestamp when recorded. An external reference of type `bom` points at the inventory with a BOM-Link (`urn:cdx:<serial>/<version>`). An inventory without a serial number gets the content-derived serial its CycloneDX export would have, so the link names that export. An inventory with a serial outside the `urn:uuid:` format omits the link. Like the CycloneDX and SPDX exports, `vex` rejects an inventory whose timestamp has no time zone, whose component references repeat, or whose dependencies name an unknown component.
- Components carry the type, version, package URL and digests the CycloneDX inventory export gives them.
- Each finding's identifier is `NEXUS-` and the SARIF `nexus_symbiote/v1` fingerprint: it stays the same when an artifact digest or the severity changes, and changes with the finding text.
- Descriptions and details are neutralized like SARIF messages.
- Findings on components imported from a ShadowScan report are omitted; the metadata property `nexus-symbiote:omittedImportedFindings` counts them.

A statement defaults to `in_triage`. Trace observations annotate findings and advisory matches without changing their state. To set `not_affected`, `resolved`, or `false_positive`, provide an unexpired operator decision naming the vulnerability, component reference, exact input file digest (`inventory_sha256: sha256:<hex>`), and deployment ID. Pass the same deployment ID with `--deployment-id` from trusted configuration. Use a new decision after changing the reviewed inventory. `NEXUS-` identifiers name inventory findings. When the input includes an advisory report, the export records that report's coverage.

## Minimum elements

How an export covers the minimum SBOM elements that NTIA published in 2021 and that later guidance builds on. "Unknown" means the inventory does not collect the element; the export omits it rather than guess.

| Element | CycloneDX | SPDX | Status |
| --- | --- | --- | --- |
| Supplier name | `components[].supplier.name` | `suppliedBy` | Only when declared, such as an `agent.yaml` owner; usually unknown. |
| Component name | `name` | `name` | Collected. |
| Version | `version` | `software_packageVersion` | Exact versions only for registry entries, whose ranges are in `nexus-symbiote:requestedVersion`; other kinds keep their declared version. |
| Other unique identifiers | `purl`, `bom-ref`, `hashes` | `externalIdentifier`, `software_packageUrl`, `verifiedUsing` | Package URLs for exact PyPI and npm declarations; digests for files, models, prompts and lockfile entries. |
| Dependency relationship | `dependencies`, `compositions` | `Relationship` | Unconditional relationships only; conditional ones are in the extension or SPDX `other`. |
| Author of SBOM data | `metadata.authors`, `metadata.tools` | `CreationInfo.createdBy`, `createdUsing` | The tool is recorded; `scan` records no author. |
| Timestamp | `metadata.timestamp` | `CreationInfo.created` | Omitted by native, CycloneDX and VEX exports so that two exports of the same inventory are byte-identical; present only when the inventory records one, as `scan`, `baseline` and `import-shadowscan` do with `SOURCE_DATE_EPOCH` set. SPDX 3.0.1 requires `CreationInfo.created`, so SPDX carries the inventory's timestamp or, without one, the export time. |

CISA's updated minimum elements add a component hash, a license, the generating tool and the generation context; check the current CISA publication for the exact list. Hashes and the tool are covered as above; licenses are not collected (SPDX states no assertion, CycloneDX omits them); the generation context is `metadata.lifecycles` (`pre-build`) and `software_sbomType` (`source`) for a repository scan. Fields of AI-specific baselines that the inventory does not collect, such as training data, model performance and energy use, are absent. An export is evidence for such a review, not a determination that a baseline or regulation is met.

[`minimum-elements`](minimum-elements.md) reports, element by element, which of the 50 G7 AI SBOM minimum elements (12 May 2026) the CycloneDX export carries in standard fields, and what each missing one needs.

## Loading exports into other tools

Neither integration below is tested by this project; check the version you run.

- **Dependency-Track** ingests CycloneDX BOMs through its BOM upload API and user interface. Use the CycloneDX export rather than VEX: VEX statements apply only to vulnerabilities Dependency-Track already tracks, and `NEXUS-` findings are not among them. Check that your release accepts specification version 1.7, and whether it keeps component properties: the `nexus-symbiote:document` property holds the whole native inventory and can be megabytes long. Keep the original export, because only it recovers.
- **GUAC** ingests SPDX and CycloneDX documents. Check its support for SPDX 3.0.1 JSON-LD before relying on the SPDX export; the CycloneDX export carries the same package identities.

## Validation

Every CycloneDX, SPDX and VEX export is validated before it is returned. Validation uses the schemas vendored under `src/nexus_symbiote/generators/schemas/vendor/`, each checked against its recorded SHA-256 digest before use; the CycloneDX cryptography definitions that the 1.7 schema references are vendored too. Format assertions (`date-time`, `date`, `iri-reference`, `uri`, `idn-email`) use checkers defined in the package, so the result is the same whichever optional packages are installed.

SPDX recovery accepts only the current or supported legacy Nexus SymBiote projection. It first parses and checks the digest-bound embedded native inventory and compares the document with its regenerated projection, using the existing unordered-array and render-time timestamp rules. A conflicting projection is rejected before general schema validation. This excludes inline reference-object topologies the exporter never emits: a few kilobytes of nested SPDX references can otherwise cause severe repeated schema work. A matching projection still passes the unchanged schema and graph checks before recovery returns. CycloneDX recovery also requires both schema validation and agreement with its supported projection. Recovery checks integrity and consistency, not producer authentication.

Array uniqueness is checked with a set and graph checks use indexes, but these optimizations do not establish a linear bound for arbitrary schema input. The public schema-validation helpers are not a CPU or memory sandbox; integrations validating arbitrary SPDX documents must run them with external process, time, memory and concurrency limits. The text recovery API's 64 MiB export limit and 16 MiB embedded-native limit bound input bytes, not elapsed time.

Large legitimate exports and their recovery can still be expensive. SPDX remains the slowest: an SPDX export takes about 50 to 120 milliseconds per component in the documented measurements, so 100,000 components, which MCP client files of under 2 MiB in all can declare (one file holds at most 5,000 tools), take hours. CycloneDX and VEX exports take about a millisecond per component. No export-generation limit stops a large export; bound the job's resources and time, for example with `timeout-minutes` in GitHub Actions. Recovery of a matching large SPDX export still performs schema validation and may take about as long as writing it.
