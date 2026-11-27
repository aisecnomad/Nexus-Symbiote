# Architecture and trust boundaries

Module layout, trust boundaries and data flow. Read this before changing a
collector, gate or export. The [security model](security-model.md) states the
design principles; the [threat model](threat-model.md) lists the attacks each
boundary stops; the [known limitations](known-limitations.md), summarized in the
[security policy](../SECURITY.md#known-limitations), list what the controls do not
cover.

- [Data flow](#data-flow)
- [What a scan does](#what-a-scan-does)
- [Modules](#modules)
- [Trust boundaries](#trust-boundaries)
- [Adding a collector](#adding-a-collector)

## Data flow

```text
            operator inputs (trusted): command-line options and environment,
        collection limits, signer policy, launch policy, binding key, live mode,
                           trusted attestation keys
                                      │
                                      v
 checkout ──> confined reader ──> 8 collectors ──> AgentBOM ──┬──> validate, risk, digest
 (untrusted)  utils/confined.py   scanners/        (native    ├──> diff, summary, blast-radius
                                                    JSON)     ├──> graph, crosswalk, minimum-elements
                                                              ├──> attest, export-inventory
                                                              └──> CycloneDX, SPDX, SARIF, VEX
 supplied AgentBOM (untrusted) ───────────────────────────────┘
 ShadowScan report (untrusted) ──> import-shadowscan ──> AgentBOM of imported claims
 attestation envelope (untrusted) + AgentBOM ──> verify-attestation
 OpenTelemetry traces (untrusted) + AgentBOM ──> trace-diff ──> reported trace evidence
```

Every command runs offline unless the operator selects live mode, which only three
commands use:

| Command | Reaches | Code |
| --- | --- | --- |
| `discover-mcp` | A remote MCP server over HTTPS, at an origin the operator approves | `scanners/live_mcp.py`, `live/inventory.py` |
| `verify-live` | MCP servers started from operator-pinned stdio launchers | `live/stdio.py`, `live/verify.py` |
| `advisories` | The OSV API, with exact package names and versions | `advisories.py` |

The runtime layer is separate: a Python library (`runtime.py`, `live/session.py`)
and the `runtime` commands, which sign and verify contracts and mediate tool calls
through `ReferenceGateway`. It reads no checkout; see
[runtime assurance](runtime-assurance.md).

## What a scan does

`scan` runs the whole pipeline in one command (`cli.py`):

1. **Policy.** It reads a bounded checkout policy from the scan root. Settings
   that tighten the governing gates apply automatically, including in a mixed file.
   A relaxation requires `--accept-project-policy`. `--no-project-policy` skips the file.
   A signed operator policy bounds the effective gates. Applied relaxations
   are recorded in `policy_weakened`.
2. **Collection.** Each selected collector reads the checkout through the confined
   reader and returns components, relationships, findings, scanned surfaces, gaps
   and failures. Recorded paths are made relative to the scan root.
3. **Assembly.** Results merge into one AgentBOM. The repository agent is added,
   from `agent.yaml` when it exists ([agent manifest](agent-manifest.md)), and the
   relationship graph is checked.
4. **Coverage.** The inventory records a completeness claim: which collectors were
   requested and completed, each collector's status (`complete`, `partial`,
   `failed`, or `unknown` when it did not run), what was excluded and what failed.
5. **Gate.** The risk policy scores the findings. The scan gate fails on any
   collection failure and on every reason the risk gate reports, such as
   incomplete coverage, a finding at or above `fail_on_severity` or a score at or
   above `fail_threshold`; the [finding catalog](finding-catalog.md#how-findings-affect-the-gates)
   lists them all.
6. **Output.** The inventory is written as native JSON or exported once to
   CycloneDX, SPDX or SARIF.

`validate --project` and `risk --project` repeat steps 1 to 4 on the checkout and
compare the result with the inventory they were given. `baseline` runs `scan` and
writes the inventory only when the scan gate passes, and passes again under the
built-in policy.

## Modules

| Module | Responsibility |
| --- | --- |
| `cli.py`, `supply_chain_cli.py`, `live_cli.py`, `runtime_cli.py`, `reporting.py` | Parse operator input, select the policy, run one command, print every untrusted string inert, and turn gate results into exit codes |
| `modes.py` | Keep every command offline unless the operator selects live mode for a live command; enforce it with patched entry points and a CPython audit hook |
| `limits.py` | The operator's [collection limits](collection-limits.md), from `--limit` and `NEXUS_SYMBIOTE_LIMITS` only |
| `utils/confined.py` | The only way collectors read the checkout: descriptor-relative and bounded, regular files only, with identity checked again after each read |
| `scanners/` | One collector per surface: `mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, `ide_agents`, `agents` and `shadowscan`. They parse statically and never execute, import or load what they read |
| `core/` | Pydantic models of the native format (`models.py`, `aibom.py`), RFC 8785 hashing of tool definitions and SHA-256 of files (`hashing.py`), and the coverage assessment that `validate` and `risk` share (`coverage.py`) |
| `validators/` | Completeness and reconciliation with a fresh collection (`completeness.py`), digests and operator signatures (`integrity.py`), and risk scoring (`risk.py`) |
| `policy.py`, `signature_policy.py` | The project policy a trusted checkout may supply, and the operator's signer policy, which is refused inside the scanned project |
| `diff/differ.py` | Compare two inventories field by field and rate each change |
| `graph.py`, `lineage.py` | Assemble the repository agent and answer `blast-radius`; `lineage.py` is a library helper that no command uses |
| `risk_classes.py`, `graph_view.py`, `graph_cli.py` | Derive risk classes and exposure paths for display, never writing them to the inventory, and render the self-contained `graph` view ([graph view](graph-view.md)) |
| `core/content_digest.py`, `digest_cli.py` | The inventory content digest and the `digest` command ([reproducible inventories](reproducible-inventories.md)) |
| `attestation.py`, `attestation_cli.py` | Sign and verify inventory attestations, DSSE envelopes over in-toto statements with operator-held Ed25519 keys ([inventory attestation](inventory-attestation.md)) |
| `otlp.py`, `trace_evidence.py`, `trace_cli.py` | Read OTLP/JSON traces within fixed bounds and an attribute allowlist, and reconcile what they report with an inventory as `reported` evidence ([trace evidence](trace-evidence.md)) |
| `crosswalk.py`, `crosswalk_cli.py` | The framework crosswalk catalog that SARIF rule tags come from, and the `crosswalk` report ([framework crosswalk](framework-crosswalk.md)) |
| `minimum_elements.py`, `minimum_elements_cli.py` | G7 AI SBOM minimum-element coverage of an inventory's CycloneDX export ([G7 minimum elements](minimum-elements.md)) |
| `inventory_export.py`, `inventory_export_cli.py` | Export the reviewed repository agent as a ShadowScan simple-list inventory ([ShadowScan approval](shadowscan-inventory-export.md)) |
| `generators/` | Project the native inventory to CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0 and CycloneDX VEX, and recover a native inventory from a CycloneDX or SPDX export |
| `scanners/live_mcp.py`, `live/`, `advisories.py` | Live observation and OSV queries; see [offline and live modes](offline-and-live-modes.md) |
| `runtime.py`, `runtime_validation.py`, `live/session.py` | Signed runtime contracts, the reference gateway, schema validation in a separate worker process, and the pinned stdio session |
| `utils/terminal.py`, `utils/files.py`, `utils/secrets.py` | Inert terminal and CI output, atomic output files, and redaction |
| `utils/markdown.py` | The text of a Markdown file outside its code, as CommonMark reads it, from which the `prompt` collector takes `@path` imports |

## Trust boundaries

| Boundary | What crosses it | Trust | Controls |
| --- | --- | --- | --- |
| Checkout | Every file under the scan root, with its name, size and links | Hostile | Descriptor-relative reads with `O_NOFOLLOW` on every path component; only a relative symlink to a regular file or directory inside the root is read through its target; [collection limits](collection-limits.md) that fail closed and name the limit; strict JSON (duplicate keys and non-finite numbers refused) and YAML (anchors, aliases and tags refused, except in Compose files, whose aliases and merge keys are followed within fixed bounds); static parsing only; the offline guard; problems recorded as gaps or failures |
| Project policy | `.nexus-symbiote.yaml` at the scan root, or at the `--project` root | Trusted only for your own checkout | Read from that root only, strict schema, every relaxation listed in `policy_weakened`; `--no-project-policy` ignores it; it cannot select live mode or change a collection limit ([policy reference](policy-reference.md)) |
| Operator inputs | Options, environment variables, the Action's inputs, signer and launch policies, the binding key, trusted attestation keys | Trusted | Signer and launch policies are refused inside the scanned project; the binding key never enters the inventory; a trusted attestation or runtime public key inside a git working tree that holds the command's inputs or the current directory is refused ([trusted keys](inventory-attestation.md#trusted-keys)) |
| Supplied inventories and reports | Native AgentBOMs, ShadowScan reports, exports passed to recovery, attestation envelopes, OpenTelemetry trace files | Hostile | Bounded strict loading of regular files without symbolic links (16 MiB for an inventory or a ShadowScan report, 64 MiB for an export passed to recovery or a trace file, 2 MiB for an attestation envelope); format-version check; reconciliation with a fresh collection under `--project`; digest checks on embedded native documents; imported claims kept apart from local evidence; attestation signatures checked before the payload is parsed; trace files read within fixed bounds, with content attributes never read and telemetry kept `reported` |
| Network peers | Remote MCP servers and OSV, in live mode | Hostile | HTTPS only, to the origins the operator approves with `--allowed-origin` or to the OSV API; resolution pinned to public addresses, no redirects or proxies, bounded responses; tools are never called |
| Pinned launchers | Executables a `verify-live` launch policy names | Trusted bytes, untrusted behavior | SHA-256 pin checked on a private copy, no inherited environment (only a default `PATH`), private working directory, process-group termination; run them in an external sandbox ([launch policy](cli-reference.md#launch-policy)) |
| Runtime callers | Tool calls, contracts and evidence given to the gateway | Hostile | Ed25519 DSSE envelopes, one key ring per purpose, signer quorums, revocation in signed trust statuses, supersession, rollback protection and one-use approvals in the state store, schema validation in a bounded worker ([runtime contract reference](runtime-contract-reference.md)) |
| Output | Terminal, CI log, files, the `graph` HTML page and Markdown reports | Not applicable | Untrusted text made inert and never at the start of a line; the Action relays child output inside a `stop-commands` block and writes its outputs before collection starts; files written atomically and never through a symbolic link ([output and CI logs](cli-reference.md#output-and-ci-logs)); the `graph` page HTML-escapes every inventory string and runs only its own style block and script, pinned by Content-Security-Policy hashes ([graph view](graph-view.md#how-the-page-is-made-safe-to-open)); `crosswalk` Markdown backslash-escapes inventory text, and `minimum-elements` Markdown quotes it as code spans |

Paths inside the scan root are recorded relative to it, so an inventory does not
depend on where the checkout lives. A record is labeled with how it was
established; the [glossary](glossary.md) defines declared, observed and verified,
and the [security model](security-model.md) explains how far each goes.

## Adding a collector

The collector set is closed. `scanner_catalog.py` names the built-in collectors,
and coverage is complete only when every one of them completed, so adding one
changes what a complete scan requires: inventories written before it lack its
status and become partial. A new collector:

- extends `scanners/base.py:Scanner`, returns a `ScanResult`, and reads only through
  `Scanner._collection`, which records the confined reader's failures and gaps on
  that result;
- records a recognized input it cannot collect as a gap (`surfaces_excluded`) and a
  read or parse problem as a failure (`scan_failures`), never as silence;
- never executes, imports or loads what it reads, and records paths that are inside
  the root or relative to it;
- is added to `scanner_catalog.py`, `scanners.ALL_SCANNERS`, the CLI registry, the
  policy's collector names and the Action runner's list;
  `tests/test_coverage_security.py` checks the catalog against the collector and
  Action lists;
- comes with tests for hostile input: oversized, malformed, deeply nested and
  symlinked files.

[CONTRIBUTING](../CONTRIBUTING.md#security-changes) gives the review contract for
security changes.
