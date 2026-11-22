# Nexus SymBiote documentation

Every page here answers one of three questions: **why** Nexus SymBiote works the way it does, **what** it records and guarantees, or **how** to use, upgrade and release it. New to the project? Read the [README](../README.md), run the [offline demo](../examples/README.md), then follow the [public-agent tutorial](tutorials/scanning-a-public-agent.md). The [glossary](glossary.md) defines the terms these pages share.

- [Why: principles and trust model](#why-principles-and-trust-model)
- [What: formats, collectors and contracts](#what-formats-collectors-and-contracts)
- [How: guides](#how-guides)
- [Project records](#project-records)

## Why: principles and trust model

Read these, and the [known limitations](known-limitations.md), before you use any result in an approval decision.

| Page | Read it to understand |
| --- | --- |
| [Security model](security-model.md) | [Design principles](security-model.md#design-principles); declared, observed, approved and mediated evidence; [what results do and do not establish](security-model.md#what-results-do-and-do-not-establish); known false-positive and false-negative classes |
| [Architecture](architecture.md) | How the modules fit together, what a scan does, where untrusted data enters, and which control guards each trust boundary |
| [Threat model](threat-model.md) | The assets and adversaries the tool is designed against, the control that answers each threat, and the risk that remains |
| [Offline and live modes](offline-and-live-modes.md#why) | Why every command is offline by default, and how that is enforced |
| [Security policy](../SECURITY.md) | Security boundaries, supported versions, how to report a vulnerability, and the limits that matter most |
| [Governance](../GOVERNANCE.md) | Who decides, how changes are reviewed, and which controls are actually active |

## What: formats, collectors and contracts

Reference material: exact behavior, fields and limits.

| Page | Covers |
| --- | --- |
| [CLI reference](cli-reference.md) | Every command, option and exit code, kept in sync with the CLI by a test |
| [Collector reference](collectors.md) | Every path each built-in collector reads, kept in sync with the collectors by a test, and what `ide_agents` records from coding-agent settings |
| [Glossary](glossary.md) | AgentBOM and AIBOM, the content digest, collectors, gaps and failures, assurance levels and reported evidence, the binding key, attestations, baselines, gates, the kinds of policy, risk classes and exposure paths, framework references and minimum elements |
| [Finding catalog](finding-catalog.md) | Every finding category: its severity, the collector that raises it, what it means, what to do, and how findings affect the gates |
| [Known limitations](known-limitations.md) | What each collector, gate, export and integration does not record or verify, by surface, and what to do about each limit |
| [Policy reference](policy-reference.md) | Every `.nexus-symbiote.yaml` setting, targeted suppressions, and what `policy_weakened` reports |
| [Collection limits](collection-limits.md) | Every bound on what a command reads from a project, its default, what happens when it is reached and how to raise it |
| [AgentBOM schemas](../schemas/README.md) | The native AgentBOM JSON Schema, the agent-manifest and deployment-profile schemas, and a minimal example |
| [Agent manifest](agent-manifest.md) | The optional `agent.yaml`: its fields, what it adds to the inventory, its failures and its trust limits |
| [Standard exports](standard-exports.md) | What CycloneDX, SPDX, SARIF and VEX output carry, the extension property names, projection versions and the SARIF rule catalog |
| [G7 AI SBOM minimum elements](minimum-elements.md) | Which of the 50 G7 AI SBOM minimum elements an inventory's CycloneDX export carries, how each element is evaluated, and how to supply a missing one; coverage, not compliance |
| [Framework crosswalk](framework-crosswalk.md) | Which OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001 and CWE entries each finding category bears on and why, what a reference means and does not mean, the `crosswalk` report, and the SARIF tags taken from it |
| [Reproducible inventories](reproducible-inventories.md) | What can differ between two collections of one project, the content digest and what equal digests do and do not establish, the serial number derived from it, and recording a collection time with `SOURCE_DATE_EPOCH` while keeping output byte-identical |
| [Graph view](graph-view.md) | What `nexus-symbiote graph` shows and does not show, the risk-class rules, exposure-path ranking and caps, and how the HTML file is made safe to open |
| [Source binding](verification-source-binding.md) | How MCP, A2A, RAG and IDE settings records are bound to their configuration, with and without the binding key, and reconciled with a project |
| [TypeScript inventory](typescript-inventory.md) | Static collection of MCP tool registrations from TypeScript and JavaScript servers, the SDK forms that are recorded as gaps, those that leave none, and its limits |
| [Model integrity](model-integrity.md) | What the model collector binds by digest, the operator signature policy (Sigstore entries and digest pins) and the signing evidence it records |
| [Registry collector](registry-collector.md) | Which packages and images the registry collector inventories, what it reads, which project settings redirect a package to another registry or index, its gaps, findings and limits |
| [Lockfile evidence](npm-lockfile-evidence.md) | What the registry collector records from npm, pnpm, Yarn, uv and Poetry lockfiles |
| [Deployment evidence](deployment-evidence.md) | The optional deployment profile and its scoped authority claims |
| [Runtime contract reference](runtime-contract-reference.md) | Signed runtime contracts: envelope, fields, digests, order of checks, reason codes, state store, key lifecycle and what an integrator must build |
| [Security regression corpus](../benchmarks/README.md) | The committed security fixtures CI enforces, and what passing them does not show |
| [Inventory regression corpus](../benchmarks/inventory/README.md) | Labeled tool-inventory cases from public MCP servers, with explicit uncertainty bounds |

## How: guides

### Use it

| Guide | When you need to |
| --- | --- |
| [Examples walkthrough](../examples/README.md) | Inventory, validate, export, diff, import and compare with a trace on a synthetic agent, offline |
| [Scanning a public agent](tutorials/scanning-a-public-agent.md) | Run the full workflow on a real repository and wire it into CI |
| [GitHub Action](github-action.md) | Add the Action to a workflow, read what each gate checks, and supply a signer policy from outside the workspace |
| [Container image](container-image.md) | Verify the release image's attestation, run the CLI in it without the network, or build the image yourself |
| [Gate drift in CI](drift-gate.md) | Keep the reviewed baseline out of the pull request's reach, protect the gate from the change under review, take comparable snapshots, and read each alert |
| [Inventory attestation](inventory-attestation.md) | Sign a reviewed baseline or a generated inventory, verify it in CI before `diff`, and check the envelope with other DSSE tooling |
| [Trace evidence](trace-evidence.md) | Compare an inventory with the runtime use that an agent's OpenTelemetry traces report: what is read and never read, the `reported` trust level, matching rules, evidence format, gate and limits |
| [Offline and live modes](offline-and-live-modes.md#how) | Observe a live MCP server, query advisories, or verify pinned launchers |
| [ShadowScan integration](shadowscan-integration.md) | Import and verify Nexus-ShadowScan discovery reports |
| [Approve agents for ShadowScan reconciliation](shadowscan-inventory-export.md) | Export the reviewed repository agent as an approved inventory ShadowScan's `--inventory` accepts, choose the resource prefix, and keep the file out of the reviewed change's reach |
| [Runtime assurance](runtime-assurance.md) | Sign snapshots and approvals, and mediate tool calls through a gateway |
| [Operational guidance](operational-guidance.md) | Practices that keep a deployment inside the documented guarantees |

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
| [Repository controls](repository-controls.md) | Apply branch protection, require `Verified CI`, and run the publication preflight |
| [Releasing](releasing.md) | Build, attest, rehearse on TestPyPI and publish a release |
| [Support](../SUPPORT.md) | Troubleshoot collection, import and validation outcomes |
| [Labels](labels.md) | What each pull-request label means, who sets it, and which labels every pull request carries |

## Project records

| Record | Contents |
| --- | --- |
| [Changelog](../CHANGELOG.md) | Notable changes, including breaking ones |
| [Decisions](decisions.md) | Where each kind of decision is recorded, and how to record a new one |
| [Roadmap](../ROADMAP.md) | The release train from 0.2.0 to 1.4 with dates, the eleven invariants, the ShadowScan contract requirements, what was delivered against the external reviews, acceptance tests, the scorecard, decisions and non-goals, and traceability to every earlier plan |
| [Closed-PR audit, 2026-11-02](audits/closed-pr-review-2026-11-02.md) | Disposition of every closed pull request up to #73, and what reached the supported package |
| [Pull-request, branch and issue review, 2026-11-03](audits/closed-pr-review-2026-11-03.md) | Pull requests #74–#116, every branch, and the issues still open on 2026-11-03 |
| [Security audit of the whole repository, 2026-11-14](audits/security-audit-2026-11-14.md) | Every module, script, workflow and page at `4aaf727`: verdict, 35 ranked findings, the controls confirmed under hostile input, and what to do next |
| [Status of the 2026-11-14 audit findings](audits/security-audit-2026-11-14-status.md) | Each finding on `main` at `a604c33` (batch 1, #202) and on the branch that carried the note: fixed and how it was verified, partly fixed, deferred, or awaiting an administrator or a decision |
| [Repository audit and open pull request review, 2026-11-16](audits/repository-audit-2026-11-16.md) | `main` after #226 and #227, and pull requests #224, #228 and #229: automated checks of the whole tree, eight ranked findings with their fixes, and recommendations |
| [Pull-request, branch and label review, 2026-11-19](audits/pull-request-review-2026-11-19.md) | Pull requests #117–#291: how each merged one reached `main` and whether its lines survive, why each closed one closed, the open ones against the roadmap with their overlaps, and every branch by whether deleting it loses a commit |
| [Feature enhancement plan, 2026-11-18](enhancement-plan-2026-11-18.md) | Where Nexus SymBiote stands on AIBOM-Bench, the competitor advantages to close, standards and regulatory gaps, the gaps no tool fills, what the maintainer may have missed, and a prioritized roadmap whose acceptance criteria are benchmark cases |

Documentation changes follow the same review as code. Local links, including links to headings, are checked in CI by `scripts/check_repository_hygiene.py`; run `make hygiene` before you open a pull request.
