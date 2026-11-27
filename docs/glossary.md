# Glossary

The documentation uses each term below with one meaning. Where the code, the CLI or
another format uses a different word for the same thing, the entry says so.

## The document

### AgentBOM

The agent bill of materials that Nexus SymBiote writes: an agent's components, the
relationships between them, findings and coverage. The native form is JSON, format
1.1.0 ([schemas](../schemas/README.md)); CycloneDX, SPDX, SARIF and VEX output are
exports of it.

### AIBOM

The same document under the name the code and the CLI use: the `AIBOM` class,
`AIBOM_PATH` arguments, "Scan a project and generate an AIBOM", the schema file
`nexus-symbiote-aibom-1.0.schema.json` and the Action's `aibom-path` output. Other
tools use AIBOM or AI BOM for a bill of materials of models and datasets; here it
is not a separate artifact.

### Inventory, snapshot

An inventory is an AgentBOM, or the components it lists. A snapshot is an inventory
saved at one time so that a later one can be compared with it.

### Content digest

The SHA-256 of an inventory's RFC 8785 canonical JSON without the fields that record
the collection event: its serial number, its collection times and, for an import,
where the report was read from. Two collections of the same content have the same
content digest, wherever and whenever each was taken; equal digests say nothing about
who produced either file. `digest` prints it under the profile
`nexus-symbiote/inventory-content/v1`
([reproducible inventories](reproducible-inventories.md#the-content-digest)), and an
inventory's serial number is the version 5 UUID of it
([the serial number](reproducible-inventories.md#the-serial-number)).

### Component

One record in an inventory: an agent, MCP server or client, tool, model, prompt,
guardrail, memory store, RAG or data source, registry entry, skill, A2A client or
server, IDE agent or extension (`ComponentType` in `core/enums.py`). The type
`verified-extension` names the kind of record, an agent extension; it does not mean
that anything about the extension was verified.

## Collection and coverage

### Collector, scanner

One module that reads one class of declarations from a checkout. The documentation
says collector; the code and the CLI say scanner (`--scanner`, `scanners/`,
`scanner_status`, "Running mcp scanner..."). There are nine: `mcp`, `model`,
`prompt`, `rag`, `registry`, `a2a`, `ide_agents`, `shadowscan` and `source`.

### Coverage gap

An input a collector recognizes but cannot collect, such as an MCP client file it
only detects, or a path the policy excludes. Gaps are listed in
`surfaces_excluded`, the collector's status becomes `partial`, and the default
gates fail. What no collector recognizes is not a gap: it is not recorded at all
([known limitations](known-limitations.md)).

### Scan failure

A read, parse or limit problem that stopped the collection of a file or of a whole
collector, such as a file over a [collection limit](collection-limits.md). Failures
are listed in `scan_failures`, the collector's status becomes `failed`, and the
default gates fail. Also called a collection failure.

### Coverage words

Each layer reports coverage in its own words:

| Where | Values |
| --- | --- |
| One collector (`scanner_status`) | `complete`; `partial` (a gap); `failed` (a failure); `unknown` (did not run) |
| `validate` (`completeness.coverage_status`) | `complete`, `partial` or `unknown`; the check's `status` is `pass` or `fail` |
| `risk` (`coverage_status`) | `reported` (complete coverage of a nonempty inventory), `partial` or `unknown` |
| CycloneDX, SPDX and SARIF exports | `incomplete`, or `unknown` (`noAssertion` in SPDX); never complete |
| `advisories` | `complete`, `partial` or `none` |
| `crosswalk` (`coverage_status`) | The words `risk` uses |
| `graph` (`coverage`) | `status`: `incomplete` or `unknown`, as in the exports; `collection`: the words `validate` uses |

`minimum-elements` and `trace-diff` use the word for something else. The `coverage` of
`minimum-elements` counts G7 elements, not collected surfaces: how many are `present`
out of the `assessable` ones, with a `percent`. The `coverage` of the trace evidence
counts what was read from the traces, such as files and spans.

## Evidence

### Declared, observed, verified

The assurance level of a component or claim says how it was established.
**Declared**: a file, manifest, supplier or report says so. **Observed**: a named
collector measured it from bytes in a stated scope, such as a weight file's digest.
**Verified**: a check under operator policy succeeded, such as a signer-policy
signature or digest pin on a model's weights. Collection never makes a component's
identity verified, and an inventory's own `verified` labels are not trusted. The
[security model](security-model.md)'s four states add two that are not assurance
levels: approved configuration, a signed runtime approval, and mediated execution,
a gateway decision.

### Reported

What an agent's own telemetry states. `trace-diff` labels the tools, models, agents
and MCP endpoints that OpenTelemetry traces name as `reported`, a fourth kind of
evidence beside declared, observed and verified. The instrumentation can omit, sample
or forge spans, so reported use never raises a component's assurance, and a missing
span proves nothing
([trace evidence](trace-evidence.md#trust-model-reported-not-observed)).

### Trust tier

Who stands behind a component: `internal-verified`, `internal-unverified`,
`third-party-signed`, `third-party-unsigned`, `untrusted-public` or `unknown`. A
collector records the tier its evidence supports, such as `third-party-signed` for
a model whose weights are Sigstore-signed under the signer policy. In a supplied
inventory a tier is a claim, and `diff` rates a raised tier as a medium alert.

### Binding key

`NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, an operator secret of at least 32 characters.
With it, a scan records an HMAC over the MCP, A2A, RAG and IDE settings values the
inventory does not export, so `diff` and `validate --project` detect changes to
them. Without it, only unkeyed digests are recorded. An MCP record with unbound
values then carries a low `completeness` finding that names the key, and so does an
A2A or RAG record with an unbound URL path, tenant or redacted value, and an IDE
agent record whose `.codex/config.toml`, `.cursor/cli.json` or Antigravity, xAI or
Copilot settings digest leaves out a value the redaction removes, such as a token,
an environment value or a URL path on the same host; a change only to such a value
passes `diff`. Each URL in such a file keeps its host in the digest, also when it is
glued to the text before it after a shell operator or another URL scheme. The key never enters an inventory; use one key for a
baseline and every scan compared with it
([source binding](verification-source-binding.md)).

### Inventory attestation

A DSSE envelope that `attest` writes: an in-toto Statement v1, signed with Ed25519,
that binds a file's SHA-256 and, for a native inventory, its content digest to a
purpose, `generated` or `reviewed`. `verify-attestation` checks it against keys the
operator trusts. It establishes who signed which bytes or content for which purpose;
it does not make the inventory accurate or complete, or show that it is the newest
one ([inventory attestation](inventory-attestation.md#what-an-attestation-establishes)).

### Supplied inventory, reconciliation

An inventory a command reads rather than collects. With `--project`, `validate` and
`risk` collect the checkout again and reconcile the two; the result's
`assessment_basis` is `project-reconciled`, `project-reconciled-with-supplier-claims`
or `project-reconciliation-failed`; `validate` reports `project-not-reconciled` when
the project policy skips the completeness check. Without `--project`, the basis is
`supplied-bom` (the completeness check calls it `supplied-claims`): only the
inventory's own claims were checked.

## Gates and policy

### Finding, alert, issue

A finding, or risk, is a categorized observation about one component, listed in the
[finding catalog](finding-catalog.md). An alert is a change between two snapshots
that `diff` rates medium or higher ([drift gate](drift-gate.md#what-the-alerts-mean)).
An issue is a problem that `validate` reports in its completeness or integrity check.

### Severity

How serious one finding is: `critical`, `high`, `medium`, `low` or `info`. `diff`
rates each change with the same words.

### Risk level

The label `risk` prints beside the aggregate score, as in `Risk Score: 41.0 (high)`.
It reuses severity words with another meaning: `critical` for a critical finding or
a score at or above the fail threshold, `high` for a score at or above the warning
threshold (25 by default), `moderate` for any other score above 0, `clean` for 0,
and `unknown` when there are no findings and coverage is not reported, or when
`--project` reconciliation failed. A `high` risk level can therefore come with a
passing gate, as on the demo agent, whose score of 41 is below the default fail
threshold of 50.

### Gate

A check whose failure makes a command exit 1: the scan gate of `scan` and
`baseline`, the completeness and integrity checks of `validate`, the risk gate of
`risk`, the drift gate of `diff --fail-on-alert`, the trace gate of `trace-diff`,
which `--fail-on none` turns off, and the coverage gate of `minimum-elements`, which
only `--fail-under` turns on. The GitHub Action runs all but the trace and coverage
gates and reports them as `collection`, `completeness`, `integrity`, `risk` and
`drift`. By default the scan, `validate` and `risk` gates fail on unknown or
incomplete coverage, and the drift gate fails when coverage regresses.

### Baseline, candidate

A baseline is a reviewed snapshot that later snapshots, the candidates, are compared
with by `diff`. The `baseline` command writes one only when the scan gate passes,
and the built-in gate too, which a project policy cannot relax. A baseline is written
unsigned and `diff` checks no signature, so the gate is only as strong as the place
the baseline is read from ([trust anchor](drift-gate.md#the-trust-anchor-is-the-baseline)).
Verifying an [inventory attestation](#inventory-attestation) of it first shows that
trusted keys signed exactly that file, not that it is the newest one they signed.

### Policy kinds

| Policy | Written by | What it does |
| --- | --- | --- |
| Built-in policy | The release | The default gates, used with `--no-project-policy` |
| Project policy | The project, as `.nexus-symbiote.yaml` | Selects collectors, exclusions, gates and output. Tightening settings apply automatically, including in mixed files. A relaxation requires `--accept-project-policy`. Every relaxation is listed in `policy_weakened`. [Policy reference](policy-reference.md) |
| Signer policy | The operator, outside the project | Names the Sigstore signers or digest pins that verify model artifacts and ShadowScan reports ([signer policy](cli-reference.md#signer-policy)) |
| Launch policy | The operator, outside the project and its repository | Pins the stdio launchers `verify-live` may start ([launch policy](cli-reference.md#launch-policy)) |

Collection limits and the binding key are operator settings, not policies: nothing
in a checkout can change them. Runtime contracts and gateway configuration are
described in the [runtime contract reference](runtime-contract-reference.md).

## Reports and views

### Risk class, exposure path

A risk class (`code-exec`, `write-capable`, `exfil-capable`, `network-egress` or
`secret-access`) restates recorded evidence about what one component may do, with the
field that produced it. The `graph` view computes classes and never writes them to the
inventory. A component whose record holds nothing the rules read is unclassified:
unknown, not safe. An exposure path is the shortest chain of recorded associations
from an agent or IDE agent to a component with a `code-exec`, `write-capable`,
`exfil-capable` or `secret-access` class or a high or critical finding: potential
reach, not proof that the agent can invoke the component
([graph view](graph-view.md#risk-classes)).

### Framework crosswalk, reference

The catalog that ties each finding category to entries of framework editions: the
OWASP Top 10 for LLM Applications 2025 and 2026, the OWASP Top 10 for Agentic
Applications, MITRE ATLAS, the NIST AI RMF, the EU AI Act, ISO/IEC 42001 and CWE. A
reference means that a finding records a precondition, a weakness or evidence relevant
to an entry, never that an attack happened, that a control fails or that an obligation
applies. SARIF rule tags come from it, and `crosswalk` applies it to an inventory's
findings ([framework crosswalk](framework-crosswalk.md#what-a-reference-means)).

### Minimum element

One of the 50 elements of the G7 "Software Bill of Materials for AI – Minimum
Elements" (12 May 2026). `minimum-elements` reports whether an inventory's CycloneDX
export carries each one in a standard field: present, missing, explicit unknown, needs
producer input or not applicable. Coverage is shown with its denominator and is not
compliance: the elements are non-binding, and a present element is recorded, not
verified ([G7 minimum elements](minimum-elements.md#how-each-element-is-evaluated)).
