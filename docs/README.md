# Nexus SymBiote documentation

Every page answers one of three questions: **why** Nexus SymBiote works the way it does, **what** it records and guarantees, or **how** to use, upgrade and release it. Start with the [README](../README.md), run the [offline demo](../examples/README.md), then follow the [public-agent tutorial](tutorials/scanning-a-public-agent.md). The [glossary](glossary.md) defines the terms these pages share.

- [Why: principles and trust model](#why-principles-and-trust-model)
- [What: formats, collectors and contracts](#what-formats-collectors-and-contracts)
- [How: guides](#how-guides)
- [Project records](#project-records)

## Why: principles and trust model

Read these, and the [known limitations](known-limitations.md), before you use any result in an approval decision.

| Page | Read it to understand |
| --- | --- |
| [Security model](security-model.md) | [Design principles](security-model.md#design-principles); declared, observed, approved and mediated evidence; [what results do and do not establish](security-model.md#what-results-do-and-do-not-establish); known false-positive and false-negative classes |
| [Architecture](architecture.md) | Module layout, scan pipeline, where untrusted data enters, and which control guards each trust boundary |
| [Threat model](threat-model.md) | Assets, adversaries, controls and residual risk |
| [Offline and live modes](offline-and-live-modes.md#why) | Why every command is offline by default and how that is enforced |
| [Security policy](../SECURITY.md) | Security boundaries, supported versions, vulnerability reporting and key limitations |
| [Governance](../GOVERNANCE.md) | Decision ownership, review expectations and active repository controls |

## What: formats, collectors and contracts

Exact behavior, fields and limits.

| Page | Covers |
| --- | --- |
| [CLI reference](cli-reference.md) | Every command, option and exit code, kept in sync with the CLI by a test |
| [Collector reference](collectors.md) | Every path each built-in collector reads, kept in sync with the collectors by a test, and what `ide_agents` records from coding-agent settings |
| [Glossary](glossary.md) | Terms used across these pages: AgentBOM, content digest, collectors, evidence levels, gates, policies, risk classes and more |
| [Finding catalog](finding-catalog.md) | Every finding category: severity, collector, meaning, remediation and gate effects |
| [Known limitations](known-limitations.md) | What each collector, gate, export and integration does not cover, and what to do about each limit |
| [Policy reference](policy-reference.md) | Every `.nexus-symbiote.yaml` setting, targeted suppressions and `policy_weakened` reports |
| [Collection limits](collection-limits.md) | Every bound on what a command reads, its default, what happens at the limit and how to raise it |
| [AgentBOM schemas](../schemas/README.md) | The native AgentBOM JSON Schema, the agent-manifest and deployment-profile schemas, and a minimal example |
| [Agent manifest](agent-manifest.md) | The optional `agent.yaml`: its fields, what it adds to the inventory, its failures and its trust limits |
| [Standard exports](standard-exports.md) | CycloneDX, SPDX, SARIF and VEX output: fields, extension properties, projection versions and the SARIF rule catalog |
| [G7 AI SBOM minimum elements](minimum-elements.md) | Which of the 50 G7 elements an inventory's CycloneDX export carries and how each is evaluated; coverage, not compliance |
| [Framework crosswalk](framework-crosswalk.md) | OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001 and CWE mappings per finding category, the `crosswalk` report and SARIF tags |
| [Reproducible inventories](reproducible-inventories.md) | What can differ between two collections, the content digest and serial number, and `SOURCE_DATE_EPOCH` |
| [Graph view](graph-view.md) | What `nexus-symbiote graph` shows, risk-class rules, exposure-path ranking and how the HTML is made safe to open |
| [Source binding](verification-source-binding.md) | How MCP, A2A, RAG and IDE settings records bind to their configuration and reconcile with a project |
| [TypeScript inventory](typescript-inventory.md) | Static collection of MCP tool registrations from TypeScript and JavaScript: supported SDK forms, gaps and limits |
| [Model integrity](model-integrity.md) | What the model collector binds by digest, the operator signature policy and signing evidence |
| [Registry collector](registry-collector.md) | Packages and images the registry collector inventories: sources, gaps, findings and limits |
| [Lockfile evidence](npm-lockfile-evidence.md) | What the registry collector records from npm, pnpm, Yarn, uv and Poetry lockfiles |
| [Deployment evidence](deployment-evidence.md) | The optional deployment profile and its scoped authority claims |
| [Runtime contract reference](runtime-contract-reference.md) | Signed runtime contracts: envelope, fields, digests, checks, reason codes, state store and key lifecycle |
| [Security regression corpus](../benchmarks/README.md) | The committed security fixtures CI enforces, and what passing them does not show |
| [Inventory regression corpus](../benchmarks/inventory/README.md) | Labeled tool-inventory cases from public MCP servers, with explicit uncertainty bounds |

## How: guides

### Use it

| Guide | When you need to |
| --- | --- |
| [Examples walkthrough](../examples/README.md) | Inventory, validate, export, diff, import and trace-compare a synthetic agent, offline |
| [Scanning a public agent](tutorials/scanning-a-public-agent.md) | Full workflow on a real repository, through to CI wiring |
| [GitHub Action](github-action.md) | Add the Action to a workflow, understand each gate and supply a signer policy |
| [Container image](container-image.md) | Verify the release image, run the CLI without the network, or build it yourself |
| [Gate drift in CI](drift-gate.md) | Protect the baseline, take comparable snapshots and read each alert |
| [Inventory attestation](inventory-attestation.md) | Sign and verify inventories with Ed25519 DSSE envelopes |
| [Trace evidence](trace-evidence.md) | Compare an inventory with runtime use from OpenTelemetry traces |
| [Offline and live modes](offline-and-live-modes.md#how) | Observe a live MCP server, query advisories or verify pinned launchers |
| [ShadowScan integration](shadowscan-integration.md) | Import and verify Nexus-ShadowScan discovery reports |
| [Approve agents for ShadowScan reconciliation](shadowscan-inventory-export.md) | Export the reviewed agent as an approved inventory for ShadowScan |
| [Runtime assurance](runtime-assurance.md) | Sign snapshots and approvals, mediate tool calls through a gateway |
| [Operational guidance](operational-guidance.md) | Practices that keep a deployment inside its documented guarantees |

### Upgrade existing inventories

| Guide | When you need to |
| --- | --- |
| [Tool fingerprint migration](fingerprint-migration.md) | Re-collect tool definitions hashed by an older serializer |
| [Security defaults migration](security-defaults-migration.md) | Handle security fields that are now unknown instead of an invented default |
| [Upgrade existing snapshots](verification-source-binding.md#upgrade-existing-snapshots) | Re-collect MCP snapshots that predate source binding |

### Contribute, operate and release

| Guide | When you need to |
| --- | --- |
| [Contributing](../CONTRIBUTING.md) | Set up the locked environment and meet the review contract |
| [Repository controls](repository-controls.md) | Branch protection, `Verified CI` and the publication preflight |
| [Releasing](releasing.md) | Build, attest, rehearse on TestPyPI and publish a release |
| [Support](../SUPPORT.md) | Troubleshoot collection, import and validation outcomes |
| [Labels](labels.md) | Pull-request label definitions and requirements |

## Project records

| Record | Contents |
| --- | --- |
| [Changelog](../CHANGELOG.md) | Notable changes, including breaking ones |
| [Decisions](decisions.md) | Where each kind of decision is recorded and how to record a new one |
| [Roadmap](../ROADMAP.md) | Release train (0.2.0–1.4), invariants, ShadowScan contract, delivered external review items, scorecard and traceability |
| [Security audit of the whole repository, 2026-11-14](audits/security-audit-2026-11-14.md) | Every module, script, workflow and page at `4aaf727`: verdict, 35 ranked findings, the controls confirmed under hostile input, and what to do next |

Documentation changes follow the same review as code. Local links, including links to headings, are checked in CI by `scripts/check_repository_hygiene.py`; run `make hygiene` before you open a pull request.
