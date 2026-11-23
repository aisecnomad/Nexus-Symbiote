# G7 AI SBOM minimum elements

`nexus-symbiote minimum-elements INVENTORY` reports which of the 50 elements of the
G7 "Software Bill of Materials for AI – Minimum Elements" the CycloneDX 1.7 export of
a native inventory carries in standard fields, and how to supply each missing one.
**Coverage is not compliance.** The G7 elements are non-binding guidance, and a
present element is a value the inventory recorded, not one this command verified.

- [The G7 document](#the-g7-document)
- [Running the command](#running-the-command)
- [How each element is evaluated](#how-each-element-is-evaluated)
- [What extension-only means](#what-extension-only-means)
- [The elements](#the-elements)
- [Example: the demo agent](#example-the-demo-agent)
- [What a future projection could carry](#what-a-future-projection-could-carry)
- [Limits](#limits)

## The G7 document

"Software Bill of Materials for AI – Minimum Elements" was published on 12 May 2026 by
the G7 Cybersecurity Working Group (led by Germany's BSI and Italy's ACN, with ANSSI,
CSE, CISA, NCSC and NCO and the European Commission). It lists 50 elements in seven
clusters: Metadata (10), System Level Properties (9), Models (13), Datasets Properties
(10), Infrastructure (2), Security Properties (4) and Key Performance Indicators (2).
The elements come in addition to the general SBOM minimum elements, the list is not
exhaustive, and the issuing agencies describe the elements as not mandatory. The
document assigns no identifiers and no required or optional tiers.

This build implements edition `g7-ai-sbom-2026-05-12`. The element identifiers, such
as `g7ai-2026/slp/system-data-flow`, are minted by Nexus SymBiote; they are not G7
identifiers. The verification is **secondary**: the names and their order were checked
against four independent enumerations (cdxgen 13.7.0, BomLens 1.14.5, the openregtech
`g7ai.ttl` ontology and a draft SPDX conformance checker), which agree; the primary PDF
was not opened. The sources spell two names differently. Element 10 of Models is
"Model input-output properties" in cdxgen and BomLens and "Model input/output
properties" in openregtech and the draft checker. The dataset cluster heading is
"Datasets Properties" in BomLens, "Dataset Properties" in openregtech and the draft
checker, and "Datasets" in cdxgen. The catalog uses "Model input-output properties"
and "Datasets Properties"; the identifiers do not depend on either. The document's
landing page is
`https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html`.

## Running the command

```text
nexus-symbiote minimum-elements [-f text|json|markdown] [-o FILE] [--fail-under PERCENT] INVENTORY
```

The command reads one native inventory, generates its CycloneDX 1.7 export in memory
with the exporter `scan -f cyclonedx` uses, and evaluates that export. Nothing but the
report is written, and the command runs offline.

- `text` (the default) prints a summary, then per cluster the present elements and each
  missing element with why it is missing and how to supply it: the field-level fix
  list.
- `json` prints a document with `format` `nexus-symbiote/minimum-elements/v1`, the
  edition, the ratio with its denominator, the counts overall and per cluster, and
  every element's result: `status`, `basis`, `reasons`, `extension_only`, the subjects
  that lack it (for models and datasets), `relationships` (for SBOM dependency
  relationship: how many relationships the inventory records and how many of them the
  export carries), the `rule` it was evaluated by, the CycloneDX fields read with JSON
  pointers into the export (`cyclonedx.evidence`), JSON pointers into the native
  inventory (`native`) and the `hint`. Lists of subjects and pointers stop at 20 entries
  and count the rest in `omitted`. The same inventory always gives the same bytes.
- `markdown` prints the same report as tables. Component references, the only text that
  comes from the inventory, appear as code spans, so they cannot form links, markup or
  HTML.

The command exits 0 when the report was produced, whatever it says. `--fail-under
PERCENT` (a decimal number from 0 to 100) is an opt-in gate: the report states the
gate's verdict (a `Gate:` line after the `Overall:` line in text, a `**Gate:**` line
in Markdown, the `gate` object in JSON), and the command exits 1, and lists the
missing elements on standard error, when the ratio below is under `PERCENT`. The
ratio is compared exactly, not as the rounded figure.

An inventory that cannot be read, that is nested too deeply to export, or whose
CycloneDX export fails its schema or consistency checks exits 1 without a report; an
invalid option, or an output path that names the inventory itself, exits 2.

## How each element is evaluated

Every element gets one status:

| Status | Meaning |
| --- | --- |
| `present` | A standard field of the export carries a meaningful value. |
| `missing` | No standard field carries one. The result says why when the reason is not plain absence. |
| `explicit-unknown` | The value is the literal `unknown`. The G7 text asks for this when a version does not exist. |
| `needs-producer-input` | A static repository scan has no source for the element: only the producer's documentation, runtime data or a signing step can supply it. |
| `not-applicable` | The inventory has no subject of the element's kind: no model component for the 13 Models elements, no dataset or retrieval source for the 10 Datasets Properties elements. Nothing else is ever not applicable. |

The rules:

1. **Standard fields only.** An element is present for outside readers only when a
   standard CycloneDX field carries it. A value only a `nexus-symbiote:` property
   carries is [extension-only](#what-extension-only-means), which is missing.
2. **Meaningful values.** Empty text, text with no visible character (no letter, digit,
   punctuation mark or symbol other than a blank filler such as U+3164 HANGUL FILLER or
   U+2800 BRAILLE PATTERN BLANK, so spaces, control and format characters and combining
   marks alone do not count), `NOASSERTION` and `NoAssertionLicense` are missing. `unknown` is an explicit unknown. Blank fillers are ignored like white space, so `unknown` followed by U+2800 is still an explicit unknown. A digest counts
   for a model or dataset hash only when it is hexadecimal and its algorithm is neither
   MD5 nor SHA-1.
3. **Every subject.** A Models or Datasets Properties element is present only when
   every subject of that kind has it; the result lists the others.
4. **One system subject.** The System Level Properties elements describe the export's
   `metadata.component`, which is the repository agent that `scan` assembles. Without
   exactly one, every system element assessable from the BOM is missing.
5. **The inventory can only make a result stricter.** A value counts only when the
   inventory records it: without the inventory's own tool version or serial number, an
   export substitutes this build's version or a serial number derived from the content,
   so those elements are missing. Without the inventory's own timestamp, which a scan
   records only when `SOURCE_DATE_EPOCH` is set, the export writes none, and the SBOM
   timestamp is missing.

   The name `repository` that a scan gives an agent without an `agent.yaml` name is a
   placeholder, and so is the checkout directory's name that release 0.1.0 gave such
   an agent (a format 1.0 inventory records `identity_source: repository-path`). A
   label that the ShadowScan importer derives from a digest is not a model name.

   Infrastructure software counts the npm and PyPI packages and the container images
   that the inventory records as registry entries; tool definitions, which the export
   also types `library`, and other registry entries, such as a Hugging Face model
   reference, do not count. A model or dataset counts only when a standard field
   identifies it as one (`type` `machine-learning-model`; a `data[]` entry of type
   `dataset` or a `dataset` tag).
6. **No inference.** The BOM timestamp is not the system timestamp. A hosting provider
   is not the model producer. A `bom-ref` is not an identifier. `NEXUS-` findings are
   not vulnerability references. The absence of a sensitivity flag says nothing about
   sensitive data.
7. **Partial coverage is stated.** A static scan never claims that its list of
   components, data flows, relationships or infrastructure software is complete, so a
   present System components, System data flow, SBOM dependency relationship or
   Infrastructure software element is marked `partial`. For SBOM dependency relationship
   the report also counts the relationships: the export carries only unconditional
   `depends-on` and `provides-tool` relationships, so a present element reads, for
   example, "partial; 2 of 10 relationships exported", and the others are listed as
   [extension-only](#what-extension-only-means) values.

Datasets are the inventory's `data-source` components and its `rag-source` retrieval
sources. Scoring a retrieval source says nothing about the data a model was trained on;
the report notes this whenever one is scored.

A present element names its `basis`, how the inventory says the value was obtained:
`generated` (written by the producing tool about the document itself: format, tool,
time, serial number and generation context), `observed` (measured by a collector from
bytes, such as a weight file's digest), `declared` (stated by the repository or the
operator, such as an `agent.yaml` field) or `imported` (from a ShadowScan report). The
command verifies nothing, so no basis is `verified`. Where several models or datasets
contribute, the weakest basis is reported, in the order `imported`, `declared`,
`observed`.

**The ratio.** The report prints one ratio: present elements over the elements that
are applicable and assessable from the BOM, that is present, missing and
explicit-unknown ones, always with its denominator ("11 of 39 present (28.2%)").
Elements that need producer input and those not applicable are counted separately and
left out. An explicit unknown is in the denominator and not in the numerator, so
writing `unknown` never raises the ratio. The percentage is rounded down to a tenth.

## What extension-only means

The CycloneDX export embeds the whole native inventory in `nexus-symbiote:` properties,
which this project defines and which no other tool reads as G7 data. When the
inventory records a value related to an element but no standard field carries it, the
element is missing and `extension_only` is true; the result lists JSON pointers into
the native inventory where the value is. The demo's MCP and A2A endpoints are an
example: the inventory records them, the export carries them only inside
`nexus-symbiote:component`, and a standard reader sees no data flow.

These native values are recognized, and no others:

| Element | Native values |
| --- | --- |
| SBOM dependency relationship | Relationships the export does not write as `dependencies`: conditional ones and every type but `depends-on` and `provides-tool` |
| System version | The repository agent's `version`, when it is too long for the standard field |
| System data flow | `endpoint_url` of MCP and A2A servers, `agent_card_url` of A2A clients, `endpoint` of models and `source_uris` of retrieval sources |
| Model version, producer, description | `version` and `resolved_revision`; `supplier`; `description`, `base_model_ref`, `derivation_type` and `properties.base_model` |
| Model properties, license | `quantization_method` and `properties.gguf_architecture`; `properties.license` |
| Datasets Properties | `name`; `description` and `dataset_type`; `source_uri` and `source_uris`; `hashes`, `content_hash` and `index_snapshot_hash`; `supplier` and `collection_date`; `license` and `properties.license` |
| Infrastructure software | An agent's `framework` |
| Security controls | Guardrail components, an A2A server's `authentication_required`, a memory store's `encryption_at_rest` and `tenant_isolated` when true |

A recognized value is a lead for the projection to carry, not evidence that it meets
the element: a declared control does not show that it works.

## The elements

"Assessable" is `from-bom` when a static repository scan, a repository or operator
declaration, or enrichment can put the value in an SBOM, and `needs-producer-input`
otherwise. "Present when" is the rule each element is evaluated by; throughout, the
literal `unknown` is an explicit unknown instead. "This build" says whether this
build's CycloneDX projection writes the field (`written`), CycloneDX 1.7 has a field
it does not write (`not-written`), or CycloneDX 1.7 has no dedicated field
(`no-field`). The SPDX 3.0.1 column is for reference: the SPDX export is not
evaluated. `tests/test_minimum_elements_cli.py` checks that this table equals the
catalog.

| Id | Element | Subject | Assessable | Present when | CycloneDX 1.7 | SPDX 3.0.1 | This build |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `g7ai-2026/metadata/sbom-author` | SBOM author | document | from-bom | An author name or the BOM manufacturer's name is set. | `metadata.authors[].name`, `metadata.manufacturer.name` | `CreationInfo.createdBy` | written |
| `g7ai-2026/metadata/sbom-version` | SBOM version | document | from-bom | version is a positive integer, serialNumber is set, and the inventory records its serial number. | `version`, `serialNumber` | none | written |
| `g7ai-2026/metadata/sbom-data-format-name` | SBOM data format name | document | from-bom | bomFormat is set. | `bomFormat` | implied by `CreationInfo.specVersion` | written |
| `g7ai-2026/metadata/sbom-data-format-version` | SBOM data format version | document | from-bom | specVersion is set. | `specVersion` | `CreationInfo.specVersion` | written |
| `g7ai-2026/metadata/sbom-author-signature` | SBOM author signature | document | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | `signature` | none (detached signatures only) | not-written |
| `g7ai-2026/metadata/sbom-tool-name` | SBOM tool name | document | from-bom | A tool's name is set. | `metadata.tools.components[].name` | `CreationInfo.createdUsing` (Tool name) | written |
| `g7ai-2026/metadata/sbom-tool-version` | SBOM tool version | document | from-bom | A tool's version is set, and the inventory records the producing tool's version. | `metadata.tools.components[].version` | none | written |
| `g7ai-2026/metadata/sbom-generation-context` | SBOM generation context | document | from-bom | A lifecycle phase or name is set. | `metadata.lifecycles[].phase`, `metadata.lifecycles[].name` | `software_sbomType` | written |
| `g7ai-2026/metadata/sbom-timestamp` | SBOM timestamp | document | from-bom | metadata.timestamp is set, and the inventory records its own timestamp. | `metadata.timestamp` | `CreationInfo.created` | written |
| `g7ai-2026/metadata/sbom-dependency-relationship` | SBOM dependency relationship | document | from-bom | A dependencies entry lists a dependency, or a component lists pedigree ancestors. | `dependencies[].dependsOn`, `components[].pedigree.ancestors` | `Relationship` (`dependsOn`, `contains`, `descendantOf`) | written |
| `g7ai-2026/slp/system-name` | System name | system | from-bom | The system subject has a name other than the placeholder repository or a checkout directory's name. | `metadata.component.name` | name of the root `ai_AIPackage` | written |
| `g7ai-2026/slp/system-components` | System components | system | from-bom | The system subject exists and components is not empty. | `components[]` | `contains` and `dependsOn` relationships from the root | written |
| `g7ai-2026/slp/system-producer` | System producer | system | from-bom | The BOM supplier, or a supplier, manufacturer or author of the system subject, has a name. | `metadata.supplier.name`, `metadata.component.supplier.name`, `metadata.component.manufacturer.name`, `metadata.component.authors[].name` | `originatedBy`, `suppliedBy` | written |
| `g7ai-2026/slp/system-version` | System version | system | from-bom | The system subject has a version. | `metadata.component.version` | `software_packageVersion` | written |
| `g7ai-2026/slp/system-timestamp` | System timestamp | system | from-bom | Never: CycloneDX 1.7 has no dedicated field. | none | `releaseTime`, `builtTime` | no-field |
| `g7ai-2026/slp/system-data-flow` | System data flow | system | from-bom | A service lists endpoints or a data flow. | `services[].endpoints`, `services[].data[].flow` | none | not-written |
| `g7ai-2026/slp/system-data-usage` | System data usage | system | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | `services[].data[].description`, `services[].data[].classification` | `ai_useSensitivePersonalInformation` (close) | not-written |
| `g7ai-2026/slp/system-input-output-properties` | System input/output properties | system | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | none | none | no-field |
| `g7ai-2026/slp/intended-application-area` | Intended application area | system | from-bom | Never: CycloneDX 1.7 has no dedicated field. | none | `ai_domain` | no-field |
| `g7ai-2026/models/model-name` | Model name | model | from-bom | Every model has a name that is not an imported ShadowScan label. | `components[].name` | `name` | written |
| `g7ai-2026/models/model-identifier` | Model identifier | model | from-bom | Every model has a purl, CPE, SWID tag, OmniBOR or SWHID identifier. | `components[].purl`, `components[].cpe`, `components[].swid.tagId`, `components[].omniborId`, `components[].swhid` | `software_packageUrl`, `externalIdentifier`, `software_contentIdentifier` | not-written |
| `g7ai-2026/models/model-version` | Model version | model | from-bom | Every model has a version. | `components[].version` | `software_packageVersion` | written |
| `g7ai-2026/models/model-timestamp` | Model timestamp | model | from-bom | Never: CycloneDX 1.7 has no dedicated field. | none | `builtTime`, `releaseTime` | no-field |
| `g7ai-2026/models/model-producer` | Model producer | model | from-bom | Every model has a manufacturer, supplier or author name. | `components[].manufacturer.name`, `components[].supplier.name`, `components[].authors[].name` | `originatedBy` | written |
| `g7ai-2026/models/model-description` | Model description | model | from-bom | Every model has a description, a model card or pedigree ancestors. | `components[].description`, `components[].modelCard`, `components[].pedigree.ancestors` | `description`, `summary`, `ai_limitation`, `descendantOf` | written |
| `g7ai-2026/models/model-hash-value` | Model hash value | model | from-bom | Every model has a hexadecimal digest whose algorithm is neither MD5 nor SHA-1. | `components[].hashes[].content` | `verifiedUsing` `hashValue` | written |
| `g7ai-2026/models/model-hash-algorithm` | Model hash algorithm | model | from-bom | Every model has a hexadecimal digest whose algorithm is neither MD5 nor SHA-1. | `components[].hashes[].alg` | `verifiedUsing` `algorithm` | written |
| `g7ai-2026/models/model-properties` | Model properties | model | from-bom | Every model card names an architecture family or a model architecture. | `components[].modelCard.modelParameters.architectureFamily`, `components[].modelCard.modelParameters.modelArchitecture` | `ai_typeOfModel`, `ai_hyperparameter` | not-written |
| `g7ai-2026/models/model-input-output-properties` | Model input-output properties | model | from-bom | Every model card lists both inputs and outputs. | `components[].modelCard.modelParameters.inputs`, `components[].modelCard.modelParameters.outputs` | none | not-written |
| `g7ai-2026/models/model-training-properties` | Model training properties | model | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | `components[].modelCard.modelParameters.approach.type`, `components[].modelCard.modelParameters.datasets` | `ai_informationAboutTraining`, `trainedOn` | not-written |
| `g7ai-2026/models/model-license` | Model license | model | from-bom | Every model has a licence identifier, name or expression. | `components[].licenses` | `hasDeclaredLicense` | not-written |
| `g7ai-2026/models/model-external-references` | Model external references | model | from-bom | Every model has an external reference with a URL. | `components[].externalReferences[].url` | `externalRef` | not-written |
| `g7ai-2026/dp/dataset-name` | Dataset name | dataset | from-bom | Every dataset is marked as one and has a name. | `components[].name`, `components[].data[].name` | `name` | not-written |
| `g7ai-2026/dp/dataset-description` | Dataset description | dataset | from-bom | Every dataset is marked as one and has a description. | `components[].description`, `components[].data[].description` | `description`, `dataset_datasetAvailability` | not-written |
| `g7ai-2026/dp/dataset-content` | Dataset content | dataset | from-bom | Every dataset is marked as one and describes its contents. | `components[].data[].contents` | `dataset_datasetType` (narrow) | not-written |
| `g7ai-2026/dp/dataset-identifier` | Dataset identifier | dataset | from-bom | Every dataset is marked as one and has a purl, a contents URL or an external reference URL. | `components[].purl`, `components[].data[].contents.url`, `components[].externalReferences[].url` | `software_packageUrl`, `externalIdentifier` | not-written |
| `g7ai-2026/dp/dataset-hash` | Dataset hash | dataset | from-bom | Every dataset is marked as one and has a hexadecimal digest whose algorithm is neither MD5 nor SHA-1. | `components[].hashes[].content` | `verifiedUsing` | not-written |
| `g7ai-2026/dp/dataset-provenance` | Dataset provenance | dataset | from-bom | Every dataset is marked as one and has governance or a supplier name. | `components[].data[].governance`, `components[].supplier.name` | `originatedBy`, `dataset_dataCollectionProcess`, `dataset_dataPreprocessing` | not-written |
| `g7ai-2026/dp/dataset-statistical-properties` | Dataset statistical properties | dataset | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | none | `dataset_datasetSize`, `dataset_knownBias` | no-field |
| `g7ai-2026/dp/dataset-sensitivity` | Dataset sensitivity | dataset | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | `components[].data[].classification`, `components[].data[].sensitiveData` | `dataset_hasSensitivePersonalInformation`, `dataset_confidentialityLevel` | not-written |
| `g7ai-2026/dp/dataset-dependency-relationship` | Dataset dependency relationship | dataset | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | `dependencies[].dependsOn` | `dependsOn`, `descendantOf` from the dataset | not-written |
| `g7ai-2026/dp/dataset-license` | Dataset license | dataset | from-bom | Every dataset is marked as one and has a licence identifier, name or expression. | `components[].licenses` | `hasDeclaredLicense` | not-written |
| `g7ai-2026/infrastructure/infrastructure-software` | Infrastructure software | infrastructure | from-bom | An npm or PyPI package or a container image the inventory records as a registry entry is exported with one of these types, or a bom reference has a URL. | `components[].type` `library`, `framework`, `container`, `platform` or `operating-system`; `externalReferences[].type` `bom` | `software_Package`, `dependsOn` | written |
| `g7ai-2026/infrastructure/infrastructure-hardware` | Infrastructure hardware | infrastructure | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | `components[].type` `device`, `externalReferences[].type` `bom` | none | not-written |
| `g7ai-2026/sp/security-controls` | Security controls | security | from-bom | Never: CycloneDX 1.7 has no dedicated field. | none | none | no-field |
| `g7ai-2026/sp/security-compliance` | Security compliance | security | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | `declarations`, `externalReferences[].type` `certification-report` | `ai_standardCompliance` | not-written |
| `g7ai-2026/sp/cybersecurity-policy-information` | Cybersecurity policy information | security | from-bom | The BOM or its system subject has an rfc-9116 or security-contact reference with a URL. | `externalReferences[].type` `rfc-9116` or `security-contact` | `externalRef` of type `securityPolicy` | not-written |
| `g7ai-2026/sp/vulnerability-referencing` | Vulnerability referencing | security | from-bom | A vulnerability has an identifier that does not start with NEXUS-, or an advisories reference has a URL. | `vulnerabilities[].id`, `externalReferences[].type` `advisories` | `security_Vulnerability`, `externalRef` of type `securityAdvisory` | not-written |
| `g7ai-2026/kpi/security-metrics` | Security metrics | kpi | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | `components[].modelCard.quantitativeAnalysis.performanceMetrics`, `externalReferences[].type` `quality-metrics` | `ai_metric` | not-written |
| `g7ai-2026/kpi/operational-performance-kpis` | Operational performance KPIs | kpi | needs-producer-input | Not evaluated: only the producer's documentation, runtime data or a signing step can supply it. | none | `ai_metric` (close) | no-field |

## Example: the demo agent

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote minimum-elements demo.aibom.json
```

```text
G7 AI SBOM minimum-element coverage, edition g7-ai-sbom-2026-05-12
Statement: Coverage is not compliance. The G7 minimum elements are non-binding guidance. This report says which elements the CycloneDX 1.7 export of the inventory carries in standard fields; a value only a nexus-symbiote: property carries does not count, and a present element is a recorded value, not a verified one.
Evaluated: standard fields of the CycloneDX 1.7 export this build writes for the inventory (projection cyclonedx-1.7/2)
Subjects: system subject yes; models 1; datasets 0; retrieval sources 1
Overall: 11 of 39 present (28.2%) among the elements assessable from the BOM; missing 28, explicit unknown 0, needs producer input 11, not applicable 0
Metadata: 6 of 9 present (66.6%); missing 3, explicit unknown 0, needs producer input 1, not applicable 0
  present (generated): SBOM version; SBOM data format name; SBOM data format version; SBOM tool name; SBOM tool version; SBOM generation context
  missing: SBOM author
    how to supply it: Add the responsible person or organisation to metadata.authors in the inventory; no command records an author, and the tool is not one.
  needs producer input: SBOM author signature
    how to supply it: Sign the exact exported file in the release pipeline; this build embeds no signature, and a detached one is outside the BOM.
  missing: SBOM timestamp
    how to supply it: Collect the inventory with SOURCE_DATE_EPOCH set to the collection time, such as the commit time: scan, baseline and import-shadowscan then record it in metadata.timestamp, and without it an inventory records no timestamp.
  missing: SBOM dependency relationship (0 of 10 relationships exported)
    only in the inventory's extension: /dependencies/0, /dependencies/1, /dependencies/2, /dependencies/3, /dependencies/4, /dependencies/5, /dependencies/6, /dependencies/7, /dependencies/8, /dependencies/9
    how to supply it: Collect tools from MCP server source: only unconditional depends-on and provides-tool relationships are exported, and a scan's repository associations are conditional.
System Level Properties: 1 of 7 present (14.2%); missing 6, explicit unknown 0, needs producer input 2, not applicable 0
  present (observed): System components (partial)
  missing: System name
    why: The subject's name is inferred, not declared: the placeholder repository, or the checkout directory's name that release 0.1.0 gave an agent without agent.yaml.
    how to supply it: Declare name in agent.yaml.
  missing: System producer
    how to supply it: Declare owner in agent.yaml; it is exported as the subject's supplier.
  missing: System version
    how to supply it: Declare version in agent.yaml; the G7 text asks for unknown when there is none, which this report counts as an explicit unknown.
  missing: System timestamp
    why: CycloneDX 1.7 has no dedicated standard field for this element.
    how to supply it: Not available in this build: CycloneDX 1.7 has no field for when the system was last updated, and the BOM timestamp is not it.
  missing: System data flow
    only in the inventory's extension: /components/0/endpoint_url, /components/4/endpoint_url, /components/9/source_uris
    how to supply it: Not available in this build: it writes no services, so declared MCP, A2A, model and retrieval endpoints stay in the extension.
  needs producer input: System data usage
    how to supply it: Producer documentation: how the system processes and consumes its data, such as data used to improve models and API call logs.
  needs producer input: System input/output properties
    how to supply it: Producer documentation: the system's input and output modalities and preprocessing.
  missing: Intended application area
    why: CycloneDX 1.7 has no dedicated standard field for this element.
    how to supply it: Not available in this build: CycloneDX 1.7 has no dedicated field, and a declared purpose is exported as a description, which is not this element.
Models: 3 of 12 present (25.0%); missing 9, explicit unknown 0, needs producer input 1, not applicable 0
  present (observed): Model name; Model hash value; Model hash algorithm
  missing: Model identifier (0 of 1 have it)
    without it: model:models/intent-classifier.safetensors
    how to supply it: Not available in this build: it writes no purl, CPE, SWID tag, OmniBOR or SWHID for a model, and a bom-ref is not an identifier.
  missing: Model version (0 of 1 have it)
    without it: model:models/intent-classifier.safetensors
    how to supply it: State an exact revision as the model component's version in the inventory; no collector records one, and an alias such as gpt-4o is not a version.
  missing: Model timestamp (0 of 1 have it)
    why: CycloneDX 1.7 has no dedicated standard field for this element.
    without it: model:models/intent-classifier.safetensors
    how to supply it: Not available in this build: CycloneDX 1.7 has no field for a model's timestamp.
  missing: Model producer (0 of 1 have it)
    without it: model:models/intent-classifier.safetensors
    how to supply it: State the producer as the model component's supplier in the inventory; no collector records it, and a hosting provider is not the producer.
  missing: Model description (0 of 1 have it)
    without it: model:models/intent-classifier.safetensors
    how to supply it: State the model's capabilities and limitations as its description in the inventory; no collector records one.
  missing: Model properties (0 of 1 have it)
    without it: model:models/intent-classifier.safetensors
    how to supply it: Not available in this build: it writes no model card, so a quantization method or GGUF architecture it records stays in the extension.
  missing: Model input-output properties (0 of 1 have it)
    without it: model:models/intent-classifier.safetensors
    how to supply it: Not available in this build: it writes no model card inputs and outputs.
  needs producer input: Model training properties
    how to supply it: Producer documentation: the learning type and post-training techniques.
  missing: Model license (0 of 1 have it)
    without it: model:models/intent-classifier.safetensors
    how to supply it: Not available in this build: it records no model licence and writes no licenses for models.
  missing: Model external references (0 of 1 have it)
    without it: model:models/intent-classifier.safetensors
    how to supply it: Not available in this build: it writes no model card, documentation or paper references for models.
Datasets Properties: 0 of 7 present (0.0%); missing 7, explicit unknown 0, needs producer input 3, not applicable 0
  note: Retrieval sources (rag-source) are scored as datasets the system uses; this says nothing about the data its models were trained on.
  missing: Dataset name (0 of 1 have it)
    why: No standard field identifies the component as a model (type machine-learning-model) or a dataset (a data[] entry of type dataset, or a dataset tag).
    only in the inventory's extension: /components/9/name
    without it: rag:product-notes
    how to supply it: Not available in this build: it writes datasets and retrieval sources as generic data components without a data[] entry of type dataset.
  missing: Dataset description (0 of 1 have it)
    why: No standard field identifies the component as a model (type machine-learning-model) or a dataset (a data[] entry of type dataset, or a dataset tag).
    without it: rag:product-notes
    how to supply it: Not available in this build: it does not mark datasets; a description would state the use, such as pre-training, fine-tuning, evaluation or retrieval.
  missing: Dataset content (0 of 1 have it)
    why: No standard field identifies the component as a model (type machine-learning-model) or a dataset (a data[] entry of type dataset, or a dataset tag).
    without it: rag:product-notes
    how to supply it: Not available in this build: it writes no data[].contents describing a dataset's content and format.
  missing: Dataset identifier (0 of 1 have it)
    why: No standard field identifies the component as a model (type machine-learning-model) or a dataset (a data[] entry of type dataset, or a dataset tag).
    only in the inventory's extension: /components/9/source_uris
    without it: rag:product-notes
    how to supply it: Not available in this build: source URIs stay in the extension, and it writes no dataset identifier.
  missing: Dataset hash (0 of 1 have it)
    why: No standard field identifies the component as a model (type machine-learning-model) or a dataset (a data[] entry of type dataset, or a dataset tag).
    without it: rag:product-notes
    how to supply it: Not available in this build: it does not mark datasets, so a content or index snapshot digest is the hash of a generic data component.
  missing: Dataset provenance (0 of 1 have it)
    why: No standard field identifies the component as a model (type machine-learning-model) or a dataset (a data[] entry of type dataset, or a dataset tag).
    without it: rag:product-notes
    how to supply it: Not available in this build: it writes no data[].governance and does not mark datasets.
  needs producer input: Dataset statistical properties
    how to supply it: Producer documentation: dataset size, distribution statistics and known bias.
  needs producer input: Dataset sensitivity
    how to supply it: Producer documentation: personal or sensitive data and copyright status; no flag does not mean no sensitive data.
  needs producer input: Dataset dependency relationship
    how to supply it: Producer documentation: the software that created the dataset and the datasets it derives from.
  missing: Dataset license (0 of 1 have it)
    why: No standard field identifies the component as a model (type machine-learning-model) or a dataset (a data[] entry of type dataset, or a dataset tag).
    without it: rag:product-notes
    how to supply it: Not available in this build: a supplied dataset's license stays in the extension, and it writes no licenses for datasets.
Infrastructure: 1 of 1 present (100.0%); missing 0, explicit unknown 0, needs producer input 1, not applicable 0
  present (declared): Infrastructure software (partial)
  needs producer input: Infrastructure hardware
    how to supply it: Producer documentation: a link to a hardware bill of materials, if one exists.
Security Properties: 0 of 3 present (0.0%); missing 3, explicit unknown 0, needs producer input 1, not applicable 0
  missing: Security controls
    why: CycloneDX 1.7 has no dedicated standard field for this element.
    only in the inventory's extension: /components/0/authentication_required
    how to supply it: Not available in this build: CycloneDX 1.7 has no dedicated field; declared guardrail, authentication and encryption settings stay in the extension and do not show that a control works.
  needs producer input: Security compliance
    how to supply it: Producer documentation: the standards, certifications or frameworks the system complies with.
  missing: Cybersecurity policy information
    how to supply it: Not available in this build: it writes no rfc-9116 or security-contact reference; the producer publishes a security.txt.
  missing: Vulnerability referencing
    how to supply it: Not available in this build: it writes no vulnerabilities or advisory references, and NEXUS- findings are not vulnerability references.
Key Performance Indicators: no element is assessable from the BOM; missing 0, explicit unknown 0, needs producer input 2, not applicable 0
  needs producer input: Security metrics
    how to supply it: Producer documentation: security measurements of the models or system, such as robustness benchmarks.
  needs producer input: Operational performance KPIs
    how to supply it: Runtime measurements such as uptime, latency and throughput, which a repository does not contain.
```

Eleven of the 39 assessable elements are present. The scan ran without
`SOURCE_DATE_EPOCH`, so the inventory records no timestamp and the SBOM timestamp is
missing; with the variable set, it is present and twelve are.

The demo declares no `agent.yaml`, so the system name is the placeholder and no
producer or version is declared; its ten relationships are conditional repository
associations, so the export carries none of them; its one model is a local weight
file, so its name and SHA-256 digest are present and nothing else about it is; its
retrieval source is not marked as a dataset; and its registry entry, a container
image, is the one infrastructure component.

With `--fail-under 50` the report gains one line after its `Overall:` line:

```text
Gate: failed: 11 of 39 present (28.2%), below the required 50%
```

and is followed by this on standard error, and the command exits 1:

```text
Coverage gate failed: 11 of 39 present (28.2%), below the required 50%
  missing: SBOM author (g7ai-2026/metadata/sbom-author)
  missing: SBOM timestamp (g7ai-2026/metadata/sbom-timestamp)
  missing: SBOM dependency relationship (g7ai-2026/metadata/sbom-dependency-relationship)
```

and 25 more `missing:` lines, one per missing element.

## What a future projection could carry

These elements are assessable from a BOM, and CycloneDX 1.7 has a field for them that
this build's projection does not write. Each would need a new projection version (see
[standard exports](standard-exports.md#projection-versions)):

- System data flow: MCP, A2A and model endpoints the inventory records, as `services[]`
  with `endpoints` and `data[].flow`.
- Model identifier, properties, input-output properties, license and external
  references: an identifier where one exists, a `modelCard` with `modelParameters`,
  `licenses` and `externalReferences`.
- All seven assessable Datasets Properties elements: a `data[]` entry of type `dataset`
  for data sources and retrieval sources, with `contents`, `governance` and `licenses`.
- Cybersecurity policy information and vulnerability referencing: `externalReferences`
  of type `rfc-9116`, `security-contact` or `advisories`, and `vulnerabilities` from a
  known-vulnerability source.

System timestamp, intended application area, model timestamp and security controls
have no dedicated CycloneDX 1.7 field; SPDX 3.0.1 has fields for the first three.

## Limits

- **Coverage, not compliance.** The G7 elements are non-binding and create no
  requirement. A ratio is a measure of what an export carries, not a grade, and the
  command has no default gate.
- **Secondary verification.** The element names come from four enumerations that
  agree, not from the primary PDF, and the definitions behind each rule are
  paraphrases. When the document can be read, the catalog should move to primary
  verification, and a changed reading is a new edition.
- **Present means recorded.** Nothing is verified: an inventory is written unsigned
  and can be edited, the command checks no attestation, and the report reflects what
  the inventory says. `validate --project` reconciles an inventory with its checkout.
- **One export is evaluated.** Only the CycloneDX 1.7 export this build writes is
  read; the SPDX export, which points every licence at `NoAssertionLicense`, is not.
  The report is tied to the projection it names (`cyclonedx-1.7/2`).
- **Relationships are exported in part.** The export's `dependencies` carry only
  unconditional `depends-on` and `provides-tool` relationships. A scan records its
  repository associations and manifest dependencies as conditional, so for a scanned
  repository SBOM dependency relationship is present only when `scan` collected tools
  from MCP server source, and then the report states how many of the recorded
  relationships the export carries.
- **The system is a scanned repository.** The system subject is the repository agent
  that `scan` assembles. An inventory without one, such as the output of
  `import-shadowscan`, has every assessable system element missing.
- **A static scan sees a repository.** Eleven elements need producer input, and a
  repository does not hold the training data of third-party models, a deployment
  environment or runtime measurements. Agent authority, tool grants and permissions
  have no G7 element; the report does not stretch any element to cover them.
- **Cost.** The command generates and schema-validates the whole export in memory, so
  time and memory grow linearly with the number of components: about 0.6 ms of CPU time
  and 11 KiB of memory per component where this was measured. A minimal inventory just
  under the 16 MiB input bound, 255,000 model components, took about 150 s of CPU time
  and 2.6 GiB of memory. In a container with less memory, the command is killed before
  it writes a report.
