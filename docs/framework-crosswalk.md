# Framework crosswalk

Security and compliance reviews ask how each finding relates to the frameworks they
work with. This catalog maps every finding category to the entries of the OWASP Top 10
for LLM Applications (2025 and 2026 editions), the OWASP Top 10 for Agentic
Applications, MITRE ATLAS, the NIST AI RMF, the EU AI Act, ISO/IEC 42001 and CWE
that its findings bear on, each with a one-line rationale. SARIF rules take their
taxonomy tags from it, and the `crosswalk` command applies it to the findings of an
inventory. The [finding catalog](finding-catalog.md) says what each category records.

- [What a reference means](#what-a-reference-means)
- [The crosswalk command](#the-crosswalk-command)
- [SARIF tags](#sarif-tags)
- [Limits](#limits)
- [Editions](#editions)
- [Entries](#entries)
- [Mapping](#mapping)

## What a reference means

> A reference means that the finding records a precondition for the framework entry, a weakness of its type, or evidence relevant to it. It does not mean that a technique was used, that an attack happened, that a control fails or is met, or that a legal obligation applies. Findings describe what the inventory records; neither a finding nor its absence shows that an agent, model or tool is safe.

A reference ties one finding category to one entry of one framework edition. A
category can record several kinds of finding, which the finding catalog describes. A
reference holds for every kind that the category records, and one that holds only at
some severities names them in its Severities column. For example, `data_integrity`
findings are tied to CWE-319 at high and critical severity, where they record a
retrieval endpoint or connection without encryption, but not at medium severity, where
they record a RAG source that declares no content filtering. Where no reference holds
for every kind, none is made. `launch_context` has no MITRE ATLAS reference, although
its privileged-mode findings are preconditions for AML.T0105 Escape to Host, because a
high `launch_context` finding can also record only a command-valued field. Medium
`nonregistry_source` findings have no reference at all, because they also record
workspace members, local paths and local patches, which can be the project's own. The
exceptions are references that the earlier SARIF rules carried: they were kept so that
those rules keep their tags, their rationales name the kind of finding they do not hold
for, and [Limits](#limits) lists them.

A category without a reference in a framework says nothing about whether the risks of
that framework are present: the mapping states what findings record, not what a
project is free of.

Every identifier carries its edition. The 2026 edition of the OWASP Top 10 for LLM
Applications renumbered the list, so LLM03:2025 is Supply Chain and LLM03:2026 is
Excessive Agency. MITRE ATLAS names changed between releases too; this catalog uses
release 2026.10. An EU AI Act article is named where a finding can serve as evidence:
whether the article applies depends on the system's risk class and the operator's role,
which an inventory cannot establish, and a reference never says that an obligation
applies or is met. NIST AI RMF, EU AI Act and ISO/IEC 42001 titles are this project's
short summaries, not the text of those documents.

## The crosswalk command

```text
nexus-symbiote crosswalk AIBOM_PATH [--framework NAME ...] [--format json|markdown] [-o PATH]
```

`crosswalk` reads a native inventory and takes its findings exactly as `risk` scores
them under the built-in policy. Project risk settings cannot suppress or ignore a
finding. Evidence packs requested with `--project` read that project's scan exclusions
and discovery-signature requirement for corroboration. The report includes findings
that `risk` derives from a model's recorded fields. For each selected framework edition,
it lists the entries referenced by findings and the findings for each entry. It then
lists the categories with no references to those editions. All editions are included
by default. Pass `--framework` to select an edition.

The command runs offline. Exit status 0 means the report was written. Reading the
inventory, corroborating a requested evidence pack, or writing the report can fail
with exit status 1.

JSON, the default, is a document with `format` `nexus-symbiote/crosswalk/v1` and
sorted keys:

- `meaning`: the text quoted under [what a reference means](#what-a-reference-means);
- `policy_source`: `built-in`; `suppressed_findings` and `ignored_findings`: how many
  findings the policy left out, which the built-in policy never does;
- `coverage_status`: collection coverage as `risk` assesses it;
- `findings`: sorted by severity, category, component and detail, each with its
  `category`, `severity`, `component_ref` and `detail`. Only in `detail` are control,
  bidirectional and invisible characters, including every default-ignorable code point,
  replaced as on a terminal; `category` and
  `component_ref` are kept exactly as the inventory records them, so that they can be
  matched, and can hold any character. Treat them as untrusted: escape them before you
  print them or place them in HTML, Markdown or a shell command;
- `frameworks`: one per selected edition, in the order of the Editions table, with its
  `framework` key, `name`, `edition`, `source`, `verification`, `note`,
  `findings_with_reference`, `findings_without_reference` and `entries`. Each entry has
  its `entry` identifier, `title`, `severity_counts`, the `categories` that reference it
  with their `rationale`, and `findings`, the positions of its findings in the
  `findings` list. Entries that no finding references are not listed;
- `unmapped_categories`: the categories with findings that reference no entry of the
  selected editions, each with the number of such `findings` and whether the category is
  `in_catalog`, which an edited inventory or another version can make false.

Markdown (`--format markdown`) states what a reference means at the top, then gives a
summary table, a table of the referenced entries of each edition and, under each entry,
its rationales and its findings. Text from the inventory is escaped: control,
bidirectional and invisible characters, including every default-ignorable code point such
as variation selectors and blank fillers, become U+FFFD, a `##` CI log command is broken,
and every ASCII punctuation character is backslash-escaped, so that no table cell, link,
emphasis, code span or HTML can form from it; a terminal shows the backslashes. Each such
text is cut at 1,000 characters, ending with `...`, and at most 100 findings are listed
under one entry, followed by the number of the others; the JSON format lists every one.
`-o` writes the report to a file as every output file is written, and refuses a path
that names the inventory itself.

On the demo agent, scanned without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` as in the
[walkthrough](../examples/README.md), which is why its `completeness` findings appear:

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote crosswalk demo.aibom.json --framework mitre-atlas-2026.10 --format markdown
```

```text
# Framework crosswalk

A reference means that the finding records a precondition for the framework entry, a weakness of its type, or evidence relevant to it. It does not mean that a technique was used, that an attack happened, that a control fails or is met, or that a legal obligation applies. Findings describe what the inventory records; neither a finding nor its absence shows that an agent, model or tool is safe.

Findings: 11, as `risk` scores them under the built-in policy, with 0 suppressed and 0 ignored. Collection coverage, as `risk` assesses it: reported.

Entries that no finding references are not listed; that says nothing about whether the risk an entry names is present.

## Summary

| Framework | Edition | Verification | Entries referenced | Findings with a reference | Findings without a reference |
| --- | --- | --- | --- | --- | --- |
| MITRE ATLAS | 2026.10 | primary | 4 | 7 | 4 |

## MITRE ATLAS 2026.10

Source: <https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.10.yaml>. Verification: primary. Release 2026.10 (data format 6.1.0, modified 2026-10-28). Names are verbatim from this release and differ from older ones; a sub-technique is shown after its technique.

| Entry | Title | Findings | Critical | High | Medium | Low | Info |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AML.T0010.003 | Supply Chain Compromise: Model Repository | 1 | 0 | 1 | 0 | 0 | 0 |
| AML.T0010.005 | Supply Chain Compromise: AI Agent Tool | 2 | 0 | 0 | 2 | 0 | 0 |
| AML.T0070 | RAG Poisoning | 1 | 0 | 0 | 1 | 0 | 0 |
| AML.T0109 | AI Supply Chain Rug Pull | 3 | 0 | 2 | 1 | 0 | 0 |

### AML.T0010.003 Supply Chain Compromise: Model Repository

- signing\_status: Weights without a verified signature or pin could be replaced in a model repository undetected.

| Severity | Category | Component | Detail |
| --- | --- | --- | --- |
| high | signing\_status | model\:models\/intent\-classifier\.safetensors | Model \'intent\-classifier\.safetensors\' has no verified artifact\-bound signature \(signature\-not\-found\)\. |

### AML.T0010.005 Supply Chain Compromise: AI Agent Tool

- local\_process: An unverified tool executable could be a compromised agent tool without detection.

| Severity | Category | Component | Detail |
| --- | --- | --- | --- |
| medium | local\_process | mcp\-server\:c56be5e8e4f376d7d44d2f3af332507c8c938032e49a4d816d2de33334af242f | MCP server \'memory\' uses stdio transport \(local process\)\. |
| medium | local\_process | mcp\-server\:da7146a8034e04b49f26a150811b1283ef7e3fa0c3b40353a73a5ac045d8d032 | MCP server \'notes\' uses stdio transport \(local process\)\. |

### AML.T0070 RAG Poisoning

- data\_integrity: Content unprotected in transit or unfiltered at ingestion is a precondition for poisoning retrieval.

| Severity | Category | Component | Detail |
| --- | --- | --- | --- |
| medium | data\_integrity | rag\:product\-notes | RAG source \'product\-notes\' has no declared content filtering control\. |

### AML.T0109 AI Supply Chain Rug Pull

- transitive\_resolution: A dependency resolved at launch can be replaced without moving the package pin.
- version\_pinning: An unpinned reference takes the next published version, which a rug pull relies on.

| Severity | Category | Component | Detail |
| --- | --- | --- | --- |
| high | version\_pinning | mcp\-server\:c56be5e8e4f376d7d44d2f3af332507c8c938032e49a4d816d2de33334af242f | MCP server \'memory\' uses an unpinned package reference \(arguments omitted\)\. |
| high | version\_pinning | registry\:docker\/ollama\/ollama\:latest | Docker image \'ollama\/ollama\:latest\' lacks an immutable digest pin\. |
| medium | transitive\_resolution | mcp\-server\:da7146a8034e04b49f26a150811b1283ef7e3fa0c3b40353a73a5ac045d8d032 | MCP server \'notes\' pins its package but resolves dependencies at launch without a lockfile\. |

## Categories without a reference

Findings of these categories reference no entry of the selected framework editions. A category outside this version's catalog, as an edited inventory or another version can record, is marked no.

| Category | Findings | In the catalog |
| --- | --- | --- |
| completeness | 4 | yes |
```

## SARIF tags

SARIF rules carry the entries of the threat and weakness taxonomies as tags in the
forms that the Editions table shows, in lower case as GitHub normalizes tags: CWE, the
OWASP Top 10 for LLM Applications 2025 and 2026, the OWASP Top 10 for Agentic
Applications, MITRE ATLAS and the NIST AI RMF. Every tag that a rule carried before
this catalog is still there, in the same order, so a filter on it still matches, and
the 2026, ATLAS and NIST tags follow them. The rules of the 21 categories that had no
earlier catalog entry, and of `runtime_undeclared`, were generic rules tagged only
`security`; most of them now carry CWE, OWASP 2025 or Agentic tags as well, so a filter
on such a tag, such as `external/owasp-llm-top-10-2025/llm03`, also matches their
findings. EU AI Act and ISO/IEC 42001 entries are not tags, because they name neither
threats nor weaknesses; only the `crosswalk` report shows them. No rule has more than
ten tags.
[Standard exports](standard-exports.md#sarif-for-github-code-scanning) lists the tags of
every rule.

## Limits

- A reference is this project's reviewed statement, not a mapping that the owner of the
  framework published or reviewed.
- Some references were kept from the earlier SARIF rules, so that those rules keep
  their tags, although they do not hold for every kind of finding that their category
  records, as their rationales say: CWE-319 on `transport_security` does not hold for
  an endpoint URL that uses HTTPS but embeds credentials, or whose transport is unknown
  rather than unencrypted; ASI07 on `transport_security` does not hold for low findings
  on retrieval locators, which name data sources, not agents; CWE-502 on
  `serialization_format` does not hold for chat template findings, which are critical
  like those on code-executing formats; and CWE-306 on `authentication` does not hold
  for A2A client findings, which record only the client's own configuration. The
  earlier rules also put CWE-1336 on high `serialization_format` findings, which the
  collectors do not record; it stays on that rule.
- NIST AI RMF, EU AI Act, ISO/IEC 42001 and CWE identifiers were checked against
  secondary sources only, as the Editions table says.
- `crosswalk` applies only the built-in policy. Findings on components imported from a
  ShadowScan report are included, as `risk` includes them, although SARIF and VEX
  leave them out.
- The report does not identify the inventory it was made from; keep the two together.
- Escaping stops Markdown markup, not the text filters of a renderer: GitHub, for
  example, can still show an `@name` or `:name:` in rendered text as a mention or an
  emoji.

## Editions

| Key | Framework | Edition | Verification | SARIF tag, for example |
| --- | --- | --- | --- | --- |
| `owasp-llm-2025` | [OWASP Top 10 for LLM Applications](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2025) | 2025 | primary | `external/owasp-llm-top-10-2025/llm01` |
| `owasp-llm-2026` | [OWASP Top 10 for LLM Applications](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md) | 2026 | primary | `external/owasp-llm-top-10-2026/llm01` |
| `owasp-asi-2026` | [OWASP Top 10 for Agentic Applications](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/Appendix_A_Related_Framework_Mappings.md) | 2026 | primary | `external/owasp-agentic-top-10/asi01` |
| `mitre-atlas-2026.10` | [MITRE ATLAS](https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.10.yaml) | 2026.10 | primary | `external/mitre-atlas/aml.t0010` |
| `nist-ai-rmf-1.0` | [NIST AI Risk Management Framework (AI 100-1)](https://doi.org/10.6028/NIST.AI.100-1) | 1.0 | secondary | `external/nist-ai-rmf/govern-1.6` |
| `eu-ai-act-2024` | [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) | 2024 | secondary | none |
| `iso-iec-42001-2023` | [ISO/IEC 42001 Annex A](https://www.iso.org/standard/81230.html) | 2023 | secondary | none |
| `cwe` | [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) | 4.20 | secondary | `external/cwe/cwe-250` |

- `owasp-llm-2025`: The edition that the earlier SARIF tags name. The 2026 edition renumbered the list, so an identifier is meaningful only with its edition.
- `owasp-llm-2026`: Published on 2026-08-04 and renumbered: LLM03:2026 is Excessive Agency and LLM04:2026 is Supply Chain.
- `owasp-asi-2026`: Announced on 2025-12-09. Names were checked against Appendix A of the OWASP Top 10 for LLM Applications 2026, not against the list's own page.
- `mitre-atlas-2026.10`: Release 2026.10 (data format 6.1.0, modified 2026-10-28). Names are verbatim from this release and differ from older ones; a sub-technique is shown after its technique.
- `nist-ai-rmf-1.0`: Subcategory identifiers of the AI RMF Core, checked against secondary sources only. Titles are short summaries in this project's words, not the subcategory text.
- `eu-ai-act-2024`: Regulation (EU) 2024/1689. An article is named where a finding can serve as evidence. Whether it applies depends on the system's risk class and the operator's role, which an inventory cannot establish. Titles are this project's words.
- `iso-iec-42001-2023`: Control identifiers only: the standard's text is copyrighted and was not consulted, and the labels are this project's words.
- `cwe`: Identifiers from the earlier SARIF catalog, and CWE-798 for the credential exposure finding. The names of CWE-494, CWE-829 and CWE-1427 match CWE 4.20 as the OWASP Top 10 for LLM Applications 2026 cites them; the others were not checked against the CWE site for this release.

## Entries

### OWASP Top 10 for LLM Applications 2025

| Id | Title |
| --- | --- |
| LLM01:2025 | Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM03:2025 | Supply Chain |
| LLM04:2025 | Data and Model Poisoning |
| LLM06:2025 | Excessive Agency |
| LLM08:2025 | Vector and Embedding Weaknesses |

### OWASP Top 10 for LLM Applications 2026

| Id | Title |
| --- | --- |
| LLM01:2026 | Prompt Injection |
| LLM02:2026 | Sensitive Information Disclosure |
| LLM03:2026 | Excessive Agency |
| LLM04:2026 | Supply Chain |
| LLM05:2026 | Data and Model Poisoning |
| LLM09:2026 | Vector and Embedding Weaknesses |

### OWASP Top 10 for Agentic Applications 2026

| Id | Title |
| --- | --- |
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse & Exploitation |
| ASI03 | Identity & Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution (RCE) |
| ASI06 | Memory & Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |

### MITRE ATLAS 2026.10

| Id | Name | Technique |
| --- | --- | --- |
| AML.T0010 | Supply Chain Compromise |  |
| AML.T0010.001 | Software | AML.T0010 |
| AML.T0010.003 | Model Repository | AML.T0010 |
| AML.T0010.004 | Container Registry | AML.T0010 |
| AML.T0010.005 | AI Agent Tool | AML.T0010 |
| AML.T0011 | User Execution |  |
| AML.T0011.000 | Unsafe AI Artifacts | AML.T0011 |
| AML.T0053 | AI Agent Tool Invocation |  |
| AML.T0068 | LLM Prompt Obfuscation |  |
| AML.T0070 | RAG Poisoning |  |
| AML.T0074 | Masquerading |  |
| AML.T0105 | Escape to Host |  |
| AML.T0109 | AI Supply Chain Rug Pull |  |
| AML.T0142 | Event Triggered Execution |  |

### NIST AI Risk Management Framework (AI 100-1) 1.0

| Id | Title |
| --- | --- |
| GOVERN-1.6 | AI systems are inventoried |
| MEASURE-2.7 | Security and resilience are evaluated |
| MANAGE-3.1 | Third-party AI risks are monitored and controlled |
| MANAGE-3.2 | Pre-trained models are monitored |

### EU AI Act 2024

| Id | Title |
| --- | --- |
| Art. 11 | Technical documentation of the system and its elements (Annex IV) |
| Art. 15 | Robustness and cybersecurity, including resistance to manipulation |

### ISO/IEC 42001 Annex A 2023

| Id | Title |
| --- | --- |
| A.4.2 | Resources of the AI system are documented |
| A.7.5 | Data provenance is recorded |
| A.10.3 | Suppliers are managed |

### Common Weakness Enumeration (CWE) 4.20

| Id | Title |
| --- | --- |
| CWE-250 | Execution with Unnecessary Privileges |
| CWE-306 | Missing Authentication for Critical Function |
| CWE-319 | Cleartext Transmission of Sensitive Information |
| CWE-345 | Insufficient Verification of Data Authenticity |
| CWE-451 | User Interface (UI) Misrepresentation of Critical Information |
| CWE-494 | Download of Code Without Integrity Check |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-798 | Use of Hard-coded Credentials |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere |
| CWE-1395 | Dependency on Vulnerable Third-Party Component |
| CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine |
| CWE-1427 | Improper Neutralization of Input Used for LLM Prompting |

## Mapping

### `additional_directories`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM06:2025 Excessive Agency | all | Access to directories outside the project is more than a project task needs. |
| `owasp-llm-2026` | LLM03:2026 Excessive Agency | all | Access to directories outside the project is more than a project task needs. |
| `owasp-asi-2026` | ASI03 Identity & Privilege Abuse | all | Wider file system access widens what a misused agent reaches. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `attestation`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | An extension whose publisher is not verified is an unvetted third-party component. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | An extension whose publisher is not verified is an unvetted third-party component. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | An unverified extension is part of the agent tooling's supply chain. |
| `mitre-atlas-2026.10` | AML.T0010.001 Supply Chain Compromise: Software | all | An extension without verified identity could be a compromised software package. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |
| `cwe` | CWE-345 Insufficient Verification of Data Authenticity | all | The extension's identity and publisher are not verified. |

### `authentication`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI03 Identity & Privilege Abuse | all | No declared authentication identifies the agent's callers, or the client to the agent it calls. |
| `owasp-asi-2026` | ASI07 Insecure Inter-Agent Communication | all | Agent-to-agent communication has no declared authentication. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-306 Missing Authentication for Critical Function | all | An agent card that declares no authentication requirement can leave the agent's functions unauthenticated; kept from the earlier SARIF rules, it does not hold for client findings, which record only the client's own configuration. |

### `auto_approval`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM06:2025 Excessive Agency | all | Tool calls run without per-call approval, an excess of autonomy. |
| `owasp-llm-2026` | LLM03:2026 Excessive Agency | all | Tool calls run without per-call approval, an excess of autonomy. |
| `owasp-asi-2026` | ASI02 Tool Misuse & Exploitation | all | The tools can be used, or misused, without a human check. |
| `mitre-atlas-2026.10` | AML.T0053 AI Agent Tool Invocation | all | Whoever steers the agent can invoke these tools without approval. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `bidi_override`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Such text can redirect the agent's goal without a reviewer noticing. |
| `mitre-atlas-2026.10` | AML.T0068 LLM Prompt Obfuscation | all | Hiding or disguising instruction text from human review is what this technique describes. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-451 User Interface (UI) Misrepresentation of Critical Information | all | The file can display differently from what the agent processes. |
| `cwe` | CWE-1427 Improper Neutralization of Input Used for LLM Prompting | all | Instruction text reaches the model with characters that are not neutralized. |

### `capability_scope`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM06:2025 Excessive Agency | all | A tool with destructive or financial effects, or misdeclared as read-only, raises the impact of what the agent can do. |
| `owasp-llm-2026` | LLM03:2026 Excessive Agency | all | A tool with destructive or financial effects, or misdeclared as read-only, raises the impact of what the agent can do. |
| `owasp-asi-2026` | ASI02 Tool Misuse & Exploitation | all | These are the tools whose misuse causes harm. |
| `mitre-atlas-2026.10` | AML.T0053 AI Agent Tool Invocation | all | A tool with these effects is available for the agent to invoke. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |

### `code_execution`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | Code from a model repository runs when the model loads, a supply chain weakness. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | Code from a model repository runs when the model loads, a supply chain weakness. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The model repository's code becomes part of the agent's supply chain. |
| `owasp-asi-2026` | ASI05 Unexpected Code Execution (RCE) | all | Loading the model executes repository code. |
| `mitre-atlas-2026.10` | AML.T0011.000 User Execution: Unsafe AI Artifacts | all | Configuration that makes loading run repository code is an unsafe artifact as the technique defines one. |
| `nist-ai-rmf-1.0` | MANAGE-3.2 Pre-trained models are monitored | all | Records how safely a pre-trained model loads, or whether its weights are verified. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-494 Download of Code Without Integrity Check | all | Loading runs code fetched from the model repository without an integrity check. |
| `cwe` | CWE-829 Inclusion of Functionality from Untrusted Control Sphere | all | Loading includes code from the model repository, outside the project's control. |

### `completeness`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `nist-ai-rmf-1.0` | GOVERN-1.6 AI systems are inventoried | all | Records values the inventory cannot bind, identity fields it withholds, or an agent card without skills. |
| `iso-iec-42001-2023` | A.4.2 Resources of the AI system are documented | all | Records information about a component that the inventory does not document. |

### `credential_exposure`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM02:2025 Sensitive Information Disclosure | all | A credential committed with the agent's configuration is disclosed to everyone who reads the repository. |
| `owasp-llm-2026` | LLM02:2026 Sensitive Information Disclosure | all | A credential committed with the agent's configuration is disclosed to everyone who reads the repository. |
| `owasp-asi-2026` | ASI03 Identity & Privilege Abuse | all | A committed credential lets whoever reads the repository act as the agent does. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-798 Use of Hard-coded Credentials | all | The credential is written into the configuration rather than supplied at run time. |

### `credential_helper`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI03 Identity & Privilege Abuse | all | A command chosen in the settings supplies the agent's credentials. |
| `owasp-asi-2026` | ASI05 Unexpected Code Execution (RCE) | all | The command runs automatically whenever the agent needs a credential. |
| `mitre-atlas-2026.10` | AML.T0142 Event Triggered Execution | all | A command that runs on an agent event is a mechanism for automatic code execution. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `custom_code`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | Custom model code is a third-party component that runs when the model loads. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | Custom model code is a third-party component that runs when the model loads. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The model's code is part of the agent's supply chain. |
| `owasp-asi-2026` | ASI05 Unexpected Code Execution (RCE) | all | Loading the model executes its custom code. |
| `mitre-atlas-2026.10` | AML.T0011.000 User Execution: Unsafe AI Artifacts | all | Executable logic bundled with a model is an unsafe artifact as the technique defines one. |
| `nist-ai-rmf-1.0` | MANAGE-3.2 Pre-trained models are monitored | all | Records how safely a pre-trained model loads, or whether its weights are verified. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-829 Inclusion of Functionality from Untrusted Control Sphere | all | Loading runs modules from the model repository, outside the project's control. |

### `data_integrity`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM04:2025 Data and Model Poisoning | all | Retrieved content without transport protection or content controls can be poisoned. |
| `owasp-llm-2025` | LLM08:2025 Vector and Embedding Weaknesses | all | The weakness lies in a retrieval source of the agent. |
| `owasp-llm-2026` | LLM05:2026 Data and Model Poisoning | all | Retrieved content without transport protection or content controls can be poisoned. |
| `owasp-llm-2026` | LLM09:2026 Vector and Embedding Weaknesses | all | The weakness lies in a retrieval source of the agent. |
| `owasp-asi-2026` | ASI06 Memory & Context Poisoning | all | Retrieved content enters the agent's context. |
| `mitre-atlas-2026.10` | AML.T0070 RAG Poisoning | all | Content unprotected in transit or unfiltered at ingestion is a precondition for poisoning retrieval. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-319 Cleartext Transmission of Sensitive Information | critical and high | The retrieval endpoint or locator uses an unencrypted transport. |

### `detection_method`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `nist-ai-rmf-1.0` | GOVERN-1.6 AI systems are inventoried | all | Records an agent SDK use found in code with no declared deployment. |
| `eu-ai-act-2024` | Art. 11 Technical documentation of the system and its elements (Annex IV) | all | Records an element of the system that the inventory does not show as declared. |
| `iso-iec-42001-2023` | A.4.2 Resources of the AI system are documented | all | Records a resource of the AI system that the inventory does not show as declared. |

### `directional_marks`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Such text can redirect the agent's goal without a reviewer noticing. |
| `mitre-atlas-2026.10` | AML.T0068 LLM Prompt Obfuscation | all | Hiding or disguising instruction text from human review is what this technique describes. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `endpoint_identity`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI07 Insecure Inter-Agent Communication | all | The peer an MCP endpoint connects to cannot be identified from its declaration. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `hidden_markup`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Such text can redirect the agent's goal without a reviewer noticing. |
| `mitre-atlas-2026.10` | AML.T0068 LLM Prompt Obfuscation | all | Hiding or disguising instruction text from human review is what this technique describes. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `hook_commands`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI05 Unexpected Code Execution (RCE) | all | Commands run automatically on agent events. |
| `mitre-atlas-2026.10` | AML.T0142 Event Triggered Execution | all | Hooks that run commands on agent events are the mechanism this technique abuses. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `identifier_characters`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | A tool or server name that reads differently to a reviewer than to the model can carry injected text. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | A tool or server name that reads differently to a reviewer than to the model can carry injected text. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Such text can redirect the agent's goal without a reviewer noticing. |
| `mitre-atlas-2026.10` | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | all | A tool whose name is disguised can stand in for a trusted agent tool. |
| `mitre-atlas-2026.10` | AML.T0068 LLM Prompt Obfuscation | all | Hiding or disguising instruction text from human review is what this technique describes. |
| `mitre-atlas-2026.10` | AML.T0074 Masquerading | all | A lookalike or hidden-character name is a form of name manipulation. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-451 User Interface (UI) Misrepresentation of Critical Information | all | A name with control, format or lookalike characters displays differently from what the agent and the inventory compare. |
| `cwe` | CWE-1427 Improper Neutralization of Input Used for LLM Prompting | all | A tool name reaches the model's context with characters that are not neutralized. |

### `instruction_injection`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | Prompt or instruction text contains override, exfiltration, or deception directives. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | Prompt or instruction text contains override, exfiltration, or deception directives. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Injected directives in prompt or skill files can hijack the agent's goal. |
| `mitre-atlas-2026.10` | AML.T0068 LLM Prompt Obfuscation | all | Concealed or override directives disguise instructions to alter agent or auditor behavior. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-1427 Improper Neutralization of Input Used for LLM Prompting | all | Prompt or instruction text carries injection or auditor-deception directives without neutralization. |

### `instruction_layering`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | A second instruction location is another place where instructions can be inserted. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | A second instruction location is another place where instructions can be inserted. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Instructions from either location shape the agent's goal. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |

### `invalid_safetensors`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | A model file whose structural safety is not established is an unverified artifact. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | A model file whose structural safety is not established is an unverified artifact. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The model artifact is part of the agent's supply chain. |
| `mitre-atlas-2026.10` | AML.T0011.000 User Execution: Unsafe AI Artifacts | all | A file presented as SafeTensors that was not validated may be an unsafe artifact. |
| `nist-ai-rmf-1.0` | MANAGE-3.2 Pre-trained models are monitored | all | Records how safely a pre-trained model loads, or whether its weights are verified. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `invisible_characters`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Such text can redirect the agent's goal without a reviewer noticing. |
| `mitre-atlas-2026.10` | AML.T0068 LLM Prompt Obfuscation | all | Hiding or disguising instruction text from human review is what this technique describes. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-451 User Interface (UI) Misrepresentation of Critical Information | all | The file can display differently from what the agent processes. |
| `cwe` | CWE-1427 Improper Neutralization of Input Used for LLM Prompting | all | Instruction text reaches the model with characters that are not neutralized. |

### `known_vulnerability`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | A vulnerable package in the agent runtime is a supply chain weakness. |
| `owasp-llm-2026` | LLM05:2026 Data and Model Poisoning | all | A vulnerable package in the agent runtime is a supply chain weakness. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | A compromised or vulnerable dependency reaches every agent that loads it. |
| `mitre-atlas-2026.10` | AML.T0010 Supply Chain Compromise | all | A vulnerable dependency is a supply chain compromise vector. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-1395 Dependency on Vulnerable Third-Party Component | all | A dependency with a known vulnerability is part of the agent's supply chain. |

### `launch_context`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI05 Unexpected Code Execution (RCE) | all | The launch widens what code the server runs or how far it reaches: host privileges, code-loading options, command fields or a shell. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `launcher_identity`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | The package an MCP server launches, and its version, cannot be established. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | The package an MCP server launches, and its version, cannot be established. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | An agent tool of unknown identity is a supply chain gap. |
| `mitre-atlas-2026.10` | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | all | A tool whose identity and pin are unknown could be compromised without detection. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `line_separators`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | A line or paragraph separator can split instruction text in some renderers. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |

### `local_process`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI07 Insecure Inter-Agent Communication | all | The agent exchanges messages with a tool server process whose executable is not verified. |
| `mitre-atlas-2026.10` | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | all | An unverified tool executable could be a compromised agent tool without detection. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `lockfile_resolution_mismatch`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | The lockfile resolves a dependency to another package or version than it records. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | The lockfile resolves a dependency to another package or version than it records. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The agent's dependency resolution does not match its declaration. |
| `mitre-atlas-2026.10` | AML.T0010.001 Supply Chain Compromise: Software | all | A lockfile record that resolves to another package can substitute a dependency. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |

### `lockfile_unread`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `nist-ai-rmf-1.0` | GOVERN-1.6 AI systems are inventoried | all | Records an AI package whose resolution the inventory does not hold, because the collector does not read its lockfile. |
| `iso-iec-42001-2023` | A.4.2 Resources of the AI system are documented | all | Records information about a component that the inventory does not document. |

### `mcp_auto_approval`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | MCP servers that the project declares are admitted without a per-server review. |
| `mitre-atlas-2026.10` | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | all | A compromised server added to the project's server file would start without approval. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `missing_lockfile_integrity`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | A dependency installed without an integrity check is a supply chain weakness. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | A dependency installed without an integrity check is a supply chain weakness. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The agent's dependency is installed without an integrity check. |
| `mitre-atlas-2026.10` | AML.T0010.001 Supply Chain Compromise: Software | all | A download that is not checked can be substituted. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |
| `cwe` | CWE-494 Download of Code Without Integrity Check | all | Without an integrity value, the downloaded package is not checked. |

### `mutable_image_tag`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | An image referenced by a movable tag is a supply chain weakness. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | An image referenced by a movable tag is a supply chain weakness. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The image the agent runs can change without review. |
| `mitre-atlas-2026.10` | AML.T0010.004 Supply Chain Compromise: Container Registry | all | Pushing other content under an existing tag is how this technique replaces an image. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |
| `cwe` | CWE-829 Inclusion of Functionality from Untrusted Control Sphere | all | The tag can be moved to other image content outside the project's control. |

### `nonregistry_source`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | high | A package from a remote source that can change lacks a registry's identity and integrity evidence. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | high | A package from a remote source that can change lacks a registry's identity and integrity evidence. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | high | The agent's dependency comes from a remote source that can change. |
| `mitre-atlas-2026.10` | AML.T0010.001 Supply Chain Compromise: Software | high | A package from a remote source that can change is a software supply chain entry point. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | high | Records a third-party component whose identity, version or resolution is not established. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | high | Records a property of the system that bears on its robustness and cybersecurity. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | high | Records a supplied component whose identity, version or resolution is not established. |
| `cwe` | CWE-829 Inclusion of Functionality from Untrusted Control Sphere | high | The package comes from a git reference or plain HTTP source that can change. |

### `oversight_gap`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM06:2025 Excessive Agency | all | Auto-approving destructive tools grants excessive agency. |
| `owasp-llm-2026` | LLM03:2026 Excessive Agency | all | Auto-approving destructive tools grants excessive agency. |
| `owasp-asi-2026` | ASI02 Tool Misuse & Exploitation | all | Destructive tool calls lack human-in-the-loop confirmation. |
| `cwe` | CWE-250 Execution with Unnecessary Privileges | all | A destructive or shell tool executes without human approval. |

### `package_alias`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | A dependency is installed under another package's name. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | A dependency is installed under another package's name. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The package the agent's code imports is not the one it names. |
| `mitre-atlas-2026.10` | AML.T0074 Masquerading | all | Installing a package under another name is a form of name manipulation. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |

### `package_source`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | The server's packages come from a non-default registry or index, so name and version do not establish identity. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | The server's packages come from a non-default registry or index, so name and version do not establish identity. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The agent tool's packages come from a source outside the default registry. |
| `mitre-atlas-2026.10` | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | all | A tool package resolved through another registry can be substituted there. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |

### `permission_scope`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM06:2025 Excessive Agency | all | Skipped prompts, unscoped allowances or an unsandboxed mode give the agent excess permissions or autonomy. |
| `owasp-llm-2026` | LLM03:2026 Excessive Agency | all | Skipped prompts, unscoped allowances or an unsandboxed mode give the agent excess permissions or autonomy. |
| `owasp-asi-2026` | ASI02 Tool Misuse & Exploitation | all | Tools can be used without per-call approval or resource scope. |
| `owasp-asi-2026` | ASI03 Identity & Privilege Abuse | all | The agent's privileges are broader than its task. |
| `mitre-atlas-2026.10` | AML.T0053 AI Agent Tool Invocation | all | The agent can invoke tools without a prompt or beyond a resource scope. |
| `mitre-atlas-2026.10` | AML.T0105 Escape to Host | high | Skipping permission prompts or disabling the sandbox lets tool calls act on the host unchecked. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-250 Execution with Unnecessary Privileges | all | The agent runs with permissions beyond what a task needs. |

### `plugin_sources`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | Plugins and marketplaces add third-party commands, agents, hooks and MCP servers. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | Plugins and marketplaces add third-party commands, agents, hooks and MCP servers. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | Plugins extend the agent with components from a marketplace. |
| `mitre-atlas-2026.10` | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | all | Plugins deliver agent tools from a marketplace. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |

### `prompt_size`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | A large instruction file makes injected text harder to find in review. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | A large instruction file makes injected text harder to find in review. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Instructions that are hard to review can redirect the agent's goal unnoticed. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |

### `rag_discovery`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM08:2025 Vector and Embedding Weaknesses | all | A vector store is referenced without a declared configuration. |
| `owasp-llm-2026` | LLM09:2026 Vector and Embedding Weaknesses | all | A vector store is referenced without a declared configuration. |
| `owasp-asi-2026` | ASI06 Memory & Context Poisoning | all | An undeclared retrieval source can feed the agent's context. |
| `nist-ai-rmf-1.0` | GOVERN-1.6 AI systems are inventoried | all | Records a retrieval source found only in code or in environment variable names. |
| `eu-ai-act-2024` | Art. 11 Technical documentation of the system and its elements (Annex IV) | all | Records an element of the system that the inventory does not show as declared. |
| `iso-iec-42001-2023` | A.4.2 Resources of the AI system are documented | all | Records a resource of the AI system that the inventory does not show as declared. |
| `iso-iec-42001-2023` | A.7.5 Data provenance is recorded | all | The provenance of data from this source is not recorded. |

### `registry_origin`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | A package resolves, or is configured to resolve, from a registry or index other than the default one. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | A package resolves, or is configured to resolve, from a registry or index other than the default one. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The agent's dependency comes, or may come, from a non-default registry or index. |
| `mitre-atlas-2026.10` | AML.T0010.001 Supply Chain Compromise: Software | all | The registry or index a package resolves from is part of its software supply chain. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |

### `runtime_undeclared`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The agent's telemetry reports a component that the inventory does not show as declared, so the inventory's review cannot be shown to cover it. |
| `nist-ai-rmf-1.0` | GOVERN-1.6 AI systems are inventoried | all | The agent's telemetry reports an AI component that the inventory does not show as listed. |
| `eu-ai-act-2024` | Art. 11 Technical documentation of the system and its elements (Annex IV) | all | Records an element of the system that the inventory does not show as declared. |
| `iso-iec-42001-2023` | A.4.2 Resources of the AI system are documented | all | Records a resource of the AI system that the inventory does not show as declared. |

### `serialization_format`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | A model artifact that can run code when it is loaded or its chat template is rendered is a supply chain weakness. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | A model artifact that can run code when it is loaded or its chat template is rendered is a supply chain weakness. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The model artifact is part of the agent's supply chain. |
| `owasp-asi-2026` | ASI05 Unexpected Code Execution (RCE) | all | Loading the model, or rendering its chat template, can execute code. |
| `mitre-atlas-2026.10` | AML.T0011.000 User Execution: Unsafe AI Artifacts | all | Serialized models that run code when loaded, and chat templates that reach Python internals, are unsafe artifacts as the technique defines them. |
| `nist-ai-rmf-1.0` | MANAGE-3.2 Pre-trained models are monitored | all | Records how safely a pre-trained model loads, or whether its weights are verified. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-502 Deserialization of Untrusted Data | critical | Pickle-based formats run code when deserialized; kept from the earlier SARIF rules, it does not hold for chat template findings, which record a template engine weakness. |
| `cwe` | CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine | high | Kept on high findings, where the earlier SARIF rules put it: a chat template that matches a potential Python-internals access pattern; this does not establish a template engine weakness. The collectors record this category only at critical. |

### `serialization_format_unknown`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | A model artifact whose loading safety is unknown is an unverified supply chain component. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | A model artifact whose loading safety is unknown is an unverified supply chain component. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The model artifact is part of the agent's supply chain. |
| `mitre-atlas-2026.10` | AML.T0011.000 User Execution: Unsafe AI Artifacts | all | An artifact whose loading safety is unknown may be unsafe. |
| `nist-ai-rmf-1.0` | MANAGE-3.2 Pre-trained models are monitored | all | Records how safely a pre-trained model loads, or whether its weights are verified. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-502 Deserialization of Untrusted Data | all | The model may use a format that runs code when deserialized. |

### `settings_environment`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI03 Identity & Privilege Abuse | high | Settings can send the agent's credential to an endpoint or proxy they choose. |
| `owasp-asi-2026` | ASI05 Unexpected Code Execution (RCE) | medium | Settings can load code into the session and every command it starts. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |

### `shadowscan-heuristic`

No reference: no entry was defensible for this category.

### `shadowscan-inventory-unmatched`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `nist-ai-rmf-1.0` | GOVERN-1.6 AI systems are inventoried | all | A discovery report found an AI component that the inventory it was given does not list. |
| `eu-ai-act-2024` | Art. 11 Technical documentation of the system and its elements (Annex IV) | all | Records an element of the system that the inventory does not show as declared. |
| `iso-iec-42001-2023` | A.4.2 Resources of the AI system are documented | all | Records a resource of the AI system that the inventory does not show as declared. |

### `signing_status`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | Unverified model weights are a supply chain weakness. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | Unverified model weights are a supply chain weakness. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The model artifact is part of the agent's supply chain. |
| `mitre-atlas-2026.10` | AML.T0010.003 Supply Chain Compromise: Model Repository | all | Weights without a verified signature or pin could be replaced in a model repository undetected. |
| `nist-ai-rmf-1.0` | MANAGE-3.2 Pre-trained models are monitored | all | Records how safely a pre-trained model loads, or whether its weights are verified. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-345 Insufficient Verification of Data Authenticity | all | The model's weights are not bound to a verified signature or digest pin. |

### `subagent_inline_mcp_server`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | Unpinned inline MCP server declarations expand the agent supply chain. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | Inline subagent mcpServers bypass top-level MCP server inventory review. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |

### `tag_characters`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | Instruction text that reads differently to a reviewer than to the model can carry injected instructions. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Such text can redirect the agent's goal without a reviewer noticing. |
| `mitre-atlas-2026.10` | AML.T0068 LLM Prompt Obfuscation | all | Hiding or disguising instruction text from human review is what this technique describes. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-451 User Interface (UI) Misrepresentation of Critical Information | all | The file can display differently from what the agent processes. |
| `cwe` | CWE-1427 Improper Neutralization of Input Used for LLM Prompting | all | Instruction text reaches the model with characters that are not neutralized. |

### `tool_description_poisoning`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM01:2025 Prompt Injection | all | Poisoned tool descriptions act as indirect prompt injection inside tool metadata. |
| `owasp-llm-2026` | LLM01:2026 Prompt Injection | all | Poisoned tool descriptions act as indirect prompt injection inside tool metadata. |
| `owasp-asi-2026` | ASI01 Agent Goal Hijack | all | Hidden or coercive directives inside tool metadata can redirect agent execution. |
| `owasp-asi-2026` | ASI02 Tool Misuse & Exploitation | all | Poisoned tool guidance steers agents toward unintended sensitive reads or exfiltration. |
| `mitre-atlas-2026.10` | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | all | Local tool descriptors embed malicious behavioral instructions inside the agent tool chain. |
| `mitre-atlas-2026.10` | AML.T0068 LLM Prompt Obfuscation | all | Markup blocks or hidden directives inside tool schemas disguise injected instructions. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-1427 Improper Neutralization of Input Used for LLM Prompting | all | Tool or schema description carries directive tags or exfiltration instructions into the model prompt. |

### `transitive_resolution`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | A pinned MCP package whose dependencies are resolved at launch is a supply chain weakness. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | A pinned MCP package whose dependencies are resolved at launch is a supply chain weakness. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The agent's launched packages can change without a change to the pin. |
| `mitre-atlas-2026.10` | AML.T0109 AI Supply Chain Rug Pull | all | A dependency resolved at launch can be replaced without moving the package pin. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |
| `cwe` | CWE-829 Inclusion of Functionality from Untrusted Control Sphere | all | Dependencies of a pinned package are resolved when the server starts. |

### `transport_ambiguity`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |

### `transport_security`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-asi-2026` | ASI07 Insecure Inter-Agent Communication | all | Communication with an MCP server or A2A agent is not shown to be encrypted, or carries its credential in the URL; kept from the earlier SARIF rules, it does not hold for low findings on retrieval locators, which name data sources, not agents. |
| `nist-ai-rmf-1.0` | MEASURE-2.7 Security and resilience are evaluated | all | Records a security-relevant property of the configuration, an input to evaluating its security. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `cwe` | CWE-319 Cleartext Transmission of Sensitive Information | critical and high | An endpoint declared over plain HTTP or WebSocket transmits in cleartext; kept from the earlier SARIF rules, it does not hold for an endpoint URL that uses HTTPS but embeds credentials, or whose transport is unknown rather than unencrypted. |

### `version_pinning`

| Framework | Entry | Severities | Rationale |
| --- | --- | --- | --- |
| `owasp-llm-2025` | LLM03:2025 Supply Chain | all | An unpinned package, server package or image is a supply chain weakness. |
| `owasp-llm-2026` | LLM04:2026 Supply Chain | all | An unpinned package, server package or image is a supply chain weakness. |
| `owasp-asi-2026` | ASI04 Agentic Supply Chain Vulnerabilities | all | The agent's packages, servers or images can change without review. |
| `mitre-atlas-2026.10` | AML.T0109 AI Supply Chain Rug Pull | all | An unpinned reference takes the next published version, which a rug pull relies on. |
| `nist-ai-rmf-1.0` | MANAGE-3.1 Third-party AI risks are monitored and controlled | all | Records a third-party component whose identity, version or resolution is not established. |
| `eu-ai-act-2024` | Art. 15 Robustness and cybersecurity, including resistance to manipulation | all | Records a property of the system that bears on its robustness and cybersecurity. |
| `iso-iec-42001-2023` | A.10.3 Suppliers are managed | all | Records a supplied component whose identity, version or resolution is not established. |
| `cwe` | CWE-829 Inclusion of Functionality from Untrusted Control Sphere | all | What runs can change under a publisher's control without a change to the repository. |
