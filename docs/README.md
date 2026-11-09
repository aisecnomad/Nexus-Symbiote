# Nexus SymBiote documentation

Every page here answers one of three questions: **why** Nexus SymBiote works the way it does, **what** it records and guarantees, or **how** to use, upgrade and release it. New to the project? Read the [README](../README.md), run the [offline demo](../examples/README.md), then follow the [public-agent tutorial](tutorials/scanning-a-public-agent.md).

- [Why: principles and trust model](#why-principles-and-trust-model)
- [What: formats, collectors and contracts](#what-formats-collectors-and-contracts)
- [How: guides](#how-guides)
- [Project records](#project-records)

## Why: principles and trust model

Read these before you use any result in an approval decision.

| Page | Read it to understand |
| --- | --- |
| [Security model](security-model.md) | [Design principles](security-model.md#design-principles); declared, observed, approved and mediated evidence; [what results do and do not establish](security-model.md#what-results-do-and-do-not-establish); known false-positive and false-negative classes |
| [Offline and live modes](offline-and-live-modes.md#why) | Why every command is offline by default, and how that is enforced |
| [Security policy](../SECURITY.md) | Security boundaries, supported versions and how to report a vulnerability |
| [Governance](../GOVERNANCE.md) | Who decides, how changes are reviewed, and which controls are actually active |

## What: formats, collectors and contracts

Reference material: exact behavior, fields and limits.

| Page | Covers |
| --- | --- |
| [CLI reference](cli-reference.md) | Every command, option and exit code, kept in sync with the CLI by a test |
| [AgentBOM schemas](../schemas/README.md) | The native AgentBOM JSON Schema, the deployment-profile schema and a minimal example |
| [Export interoperability](export-interoperability.md) | Standard-field projection, extension loss and tested external consumers |
| [Source binding](verification-source-binding.md) | How static MCP records are bound to their configuration and reconciled with a project |
| [TypeScript inventory](typescript-inventory.md) | Static collection of MCP tool registrations from TypeScript servers, and its limits |
| [npm lockfile evidence](npm-lockfile-evidence.md) | What the registry collector records from `package.json` and npm lockfiles |
| [Deployment evidence](deployment-evidence.md) | The optional deployment profile and its scoped authority claims |
| [Security regression corpus](../benchmarks/README.md) | The committed security fixtures CI enforces, and what passing them does not show |
| [Inventory regression corpus](../benchmarks/inventory/README.md) | Labeled tool-inventory cases from public MCP servers, with explicit uncertainty bounds |

## How: guides

### Use it

| Guide | When you need to |
| --- | --- |
| [Examples walkthrough](../examples/README.md) | Inventory, validate, export, diff and import on a synthetic agent, offline |
| [Scanning a public agent](tutorials/scanning-a-public-agent.md) | Run the full workflow on a real repository and wire it into CI |
| [Offline and live modes](offline-and-live-modes.md#how) | Observe a live MCP server, query advisories, or verify pinned launchers |
| [ShadowScan integration](shadowscan-integration.md) | Import and verify Nexus-ShadowScan discovery reports |
| [Runtime assurance](runtime-assurance.md) | Sign snapshots and approvals, and mediate tool calls through a gateway |

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

## Project records

| Record | Contents |
| --- | --- |
| [Changelog](../CHANGELOG.md) | Notable changes, including breaking ones |
| [Roadmap](../ROADMAP.md) | Near-term priorities and explicit non-goals |
| [Closed-PR audit, 2026-11-02](audits/closed-pr-review-2026-11-02.md) | Disposition of every closed pull request up to #73, and what reached the supported package |
| [Pull-request, branch and issue review, 2026-11-03](audits/closed-pr-review-2026-11-03.md) | Pull requests #74–#116, every branch, and the issues still open on 2026-11-03 |

Documentation changes follow the same review as code. Local links, including links to headings, are checked in CI by `scripts/check_repository_hygiene.py`; run `make hygiene` before you open a pull request.
