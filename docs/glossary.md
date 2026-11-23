# Glossary

Each term below has one meaning across this documentation. Where the code or CLI
uses a different word, the entry says so.

## The document

### AgentBOM

The agent bill of materials Nexus SymBiote writes: components, relationships,
findings and coverage. Native form is JSON, format 1.1.0
([schemas](../schemas/README.md)); CycloneDX, SPDX, SARIF and VEX are exports of it.

### AIBOM

The same document under the name the code and CLI use: the `AIBOM` class,
`AIBOM_PATH` arguments, the schema file `nexus-symbiote-aibom-1.0.schema.json` and
the Action's `aibom-path` output. Other tools use AIBOM for a bill of materials of
models and datasets; here it is not a separate artifact.

### Inventory, snapshot

An inventory is an AgentBOM or the components it lists. A snapshot is an inventory
saved at a point in time for later comparison.

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

A module that reads one class of declarations from a checkout. Documentation says
collector; code and CLI say scanner (`--scanner`, `scanners/`, `scanner_status`).
There are eight: `mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, `ide_agents`
and `shadowscan`.

### Coverage gap

An input a collector recognizes but cannot collect, such as an MCP client file it
only detects or a path the policy excludes. Listed in `surfaces_excluded`; the
collector's status becomes `partial` and the default gates fail. What no collector
recognizes is not a gap — it is not recorded at all
([known limitations](known-limitations.md)).

### Scan failure

A read, parse or limit problem that stopped collection of a file or a whole
collector, such as a file over a [collection limit](collection-limits.md). Listed
in `scan_failures`; the collector's status becomes `failed` and the default gates
fail.

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

How a component or claim was established. **Declared**: a file, manifest, supplier
or report says so. **Observed**: a collector measured it from bytes in a stated
scope, such as a weight file's digest. **Verified**: a check under operator policy
succeeded, such as a signer-policy signature on a model's weights. Collection
never makes a component's identity verified, and an inventory's own `verified`
labels are not trusted. The [security model](security-model.md)'s four states add
two more: approved configuration (a signed runtime approval) and mediated execution
(a gateway decision).

### Reported

What an agent's own telemetry states. `trace-diff` labels tools, models, agents and
MCP endpoints named in OpenTelemetry traces as `reported` — a fourth evidence kind
beside declared, observed and verified. Instrumentation can omit, sample or forge
spans, so reported use never raises assurance and a missing span proves nothing
([trace evidence](trace-evidence.md#trust-model-reported-not-observed)).

### Trust tier

Who stands behind a component: `internal-verified`, `internal-unverified`,
`third-party-signed`, `third-party-unsigned`, `untrusted-public` or `unknown`.
Collectors record the tier their evidence supports. In a supplied inventory a tier
is a claim, and `diff` rates a raised tier as a medium alert.

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

A DSSE envelope `attest` writes: an in-toto Statement v1, signed with Ed25519,
binding a file's SHA-256 (and, for a native inventory, its content digest) to a
purpose (`generated` or `reviewed`). `verify-attestation` checks it against
operator-trusted keys. Establishes who signed which bytes for which purpose; does
not make the inventory accurate or complete, or show it is the newest one
([inventory attestation](inventory-attestation.md#what-an-attestation-establishes)).

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

A finding is a categorized observation about one component, listed in the
[finding catalog](finding-catalog.md). An alert is a change `diff` rates medium or
higher ([drift gate](drift-gate.md#what-the-alerts-mean)). An issue is a problem
`validate` reports in its completeness or integrity check.

### Severity

`critical`, `high`, `medium`, `low` or `info`. `diff` rates each change with the
same words.

### Risk level

The label `risk` prints beside the aggregate score, as in `Risk Score: 41.0 (high)`.
Reuses severity words with different meaning: `critical` for a critical finding or
score at or above the fail threshold, `high` for score at or above the warning
threshold (25), `moderate` for any score above 0, `clean` for 0, and `unknown` when
there are no findings and coverage is not reported or when reconciliation failed. A
`high` risk level can come with a passing gate — the demo agent scores 41, below the
default fail threshold of 50.

### Gate

A check whose failure makes a command exit 1: the scan gate (`scan`, `baseline`),
completeness and integrity checks (`validate`), risk gate (`risk`), drift gate
(`diff --fail-on-alert`), trace gate (`trace-diff`, off with `--fail-on none`) and
coverage gate (`minimum-elements`, on with `--fail-under`). The GitHub Action runs
all but trace and coverage gates, reporting them as `collection`, `completeness`,
`integrity`, `risk` and `drift`. By default, gates fail on unknown or incomplete
coverage, and the drift gate fails when coverage regresses.

### Baseline, candidate

A baseline is a reviewed snapshot that later snapshots (candidates) are compared
with by `diff`. `baseline` writes one only when both the scan gate and the built-in
gate pass; a project policy cannot relax the built-in gate. Written unsigned — `diff`
checks no signature — so the gate is only as strong as the place the baseline is
read from ([trust anchor](drift-gate.md#the-trust-anchor-is-the-baseline)). Verifying
an [inventory attestation](#inventory-attestation) first shows that trusted keys
signed exactly that file, not that it is the newest one they signed.

### Policy kinds

| Policy | Written by | What it does |
| --- | --- | --- |
| Built-in policy | The release | The default gates, used with `--no-project-policy` |
| Project policy | The project, as `.nexus-symbiote.yaml` | Selects collectors, exclusions, gates and output. Tightening settings apply automatically, including in mixed files. A relaxation requires `--accept-project-policy`. Every relaxation is listed in `policy_weakened`. [Policy reference](policy-reference.md) |
| Signer policy | The operator, outside the project | Names the Sigstore signers or digest pins that verify model artifacts and ShadowScan reports ([signer policy](cli-reference.md#signer-policy)) |
| Launch policy | The operator, outside the project and its repository | Pins the stdio launchers `verify-live` may start ([launch policy](cli-reference.md#launch-policy)) |

Collection limits and the binding key are operator settings, not policies — nothing
in a checkout can change them. Runtime contracts and gateway configuration are in
the [runtime contract reference](runtime-contract-reference.md).

## Reports and views

### Risk class, exposure path

A risk class (`code-exec`, `write-capable`, `exfil-capable`, `network-egress` or
`secret-access`) restates recorded evidence about what one component may do. The
`graph` view computes classes at display time and never writes them to the inventory.
Unclassified means unknown, not safe. An exposure path is the shortest association
chain from an agent to a component with one of those classes or a high/critical
finding — potential reach, not proof of invocability
([graph view](graph-view.md#risk-classes)).

### Framework crosswalk, reference

The catalog mapping each finding category to framework entries: OWASP Top 10 for LLM
Applications (2025, 2026), OWASP Top 10 for Agentic Applications, MITRE ATLAS, NIST
AI RMF, EU AI Act, ISO/IEC 42001 and CWE. A reference means a finding records a
precondition, weakness or relevant evidence — never that an attack happened or an
obligation applies. SARIF rule tags come from it
([framework crosswalk](framework-crosswalk.md#what-a-reference-means)).

### Minimum element

One of the 50 elements of the G7 "Software Bill of Materials for AI — Minimum
Elements" (12 May 2026). `minimum-elements` reports whether an inventory's CycloneDX
export carries each in a standard field: present, missing, explicit unknown, needs
producer input or not applicable. Coverage is not compliance: elements are
non-binding, and a present element is recorded, not verified
([G7 minimum elements](minimum-elements.md#how-each-element-is-evaluated)).
