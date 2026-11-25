# Roadmap

> Nexus SymBiote is Agent Bill of Materials (AgentBOM) software for AI agent supply-chain security. It is unrelated to the 2022 Linux malware *Symbiote*.

## Vision and scope

Nexus SymBiote is the **verifiable AgentBOM**: a deterministic, offline-first inventory of what an AI agent is assembled from—MCP servers and tools, models, instructions and skills, retrieval sources, A2A endpoints, coding-agent settings, packages, and container images—where every claim carries its evidence and assurance tier, every gap is explicit, and every gate fails closed.

**Scope boundary with Nexus-ShadowScan:**

- **Nexus SymBiote** statically inspects agent control-plane surfaces directly (never executing target code), imports external discovery reports as producer-bound `declared` claims, builds the typed lineage graph, enforces fail-closed policy/drift gates, signs DSSE attestations, and exports standards-native CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0, and VEX documents.
- **Nexus-ShadowScan** handles broad discovery across application source code, data stores, workflows, notebooks, and cloud infrastructure, feeding findings into SymBiote through a producer-verified import contract.

## Core invariants

Every release preserves eleven non-negotiable engineering and security invariants (see the [security model](docs/security-model.md#design-principles) and [threat model](docs/threat-model.md)):

| # | Invariant | Enforcement |
| --- | --- | --- |
| 1 | **Never execute what is scanned** | Static parsers only (`ast`, `tree-sitter`, safe YAML/TOML/JSON) under an offline process-creation guard |
| 2 | **Offline by default** | Runtime audit hook blocks name resolution, non-Unix sockets, and subprocesses unless explicitly opted into `--live` |
| 3 | **No LLM in the core path** | Deterministic, reproducible rules and parsers; zero model-client runtime dependencies |
| 4 | **Unknown is never clean** | Exceeded limits, failed reads, skipped collectors, and unrecognized formats record explicit gaps and fail default gates |
| 5 | **Every claim carries assurance & evidence** | `declared`, `observed`, `reported`, and `verified` tiers stay separate; imports never upgrade trust |
| 6 | **Secrets by name, never by value** | Literal credentials are scrubbed before export; sensitive values are bound only via keyed HMAC (`NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`) |
| 7 | **Deterministic output** | Byte-identical inventories across runs and checkout paths (`SOURCE_DATE_EPOCH` honored for SPDX timestamps) |
| 8 | **Valid, lossless standard exports** | CycloneDX 1.7, SPDX 3.0.1, and VEX validate offline against vendored, SHA-256-pinned schemas with digest-bound native recovery |
| 9 | **Policy lives outside what it judges** | Untrusted checkouts cannot weaken governing gates; signer policies and reviewed baselines live outside the workspace |
| 10 | **Runtime observation is opt-in and unprivileged** | Only `advisories`, `discover-mcp`, and `verify-live` accept `--live`; pinned stdio runs under unprivileged user/PID namespaces |
| 11 | **Every rule has regression fixtures** | Two self-authored regression corpora run in CI (18 security and 10 inventory cases at v0.1.0, and 25 security cases now) alongside [AIBOM-Bench](benchmarks/aibom-bench/README.md) |

<a id="plan"></a>

## Release train

Dates for upcoming milestones are target estimates for a single-maintainer project and prioritize security verification and soak windows over calendar dates.

### 0.2.0 — Verification depth & public release (released 2026-11-25)

The first hardened release from the canonical `aisecnomad` owner, published with full publication controls:

- **Shipped in `0.2.0`:** Expanded static collectors across 8 surfaces (MCP dialects including Zed/Continue/opencode/Junie, Claude Code hooks/settings/subagents/skills, `prompts/` & `*.prompt.*`, identifier hygiene & mixed-script detection, content-inspected pickle/GGUF/SafeTensors ratings, credential exposure findings, deterministic text-poisoning rules, grouped coverage failures, `oversight_gap` & guardrail drift alerts, DSSE inventory attestation, `trace-diff`, G7 minimum-elements coverage, framework crosswalk, safe HTML graph view, `make precision` AIBOM-Bench recall-floor gate, parser fuzz smoke harness, and kernel network-denied `Offline invariant` CI verification).
- **Publication controls:** Active branch protection requiring `Verified CI`, dual tag-protection rulesets, TestPyPI/PyPI protected environments (`can_admins_bypass: false`), OIDC trusted publishing, PEP 740 attestations, signed release tag, and 24-hour soak before PyPI promotion (see [releasing](docs/releasing.md) and [repository controls](docs/repository-controls.md)).

### 0.3.0 — Precision depth, determinism & native format 1.2.0 (current)

- **Regression corpus & precision depth:** Expand per-category positive and negative fixtures (`model_drift`, `a2a_scope_drift`) and tighten per-class recall floors in `make precision` over `benchmarks/aibom-bench`.
- **Settings & determinism finish:** Replace remaining TypeScript wall-clock parse deadlines with proportional node budgets, bound export work on adversarial graphs, and add `diff --expect-upgrade` attribution.
- **Native format 1.2.0:** Add `serialization_evidence` re-derivation, `same-definition` tool relations, server deduplication across multi-config declarations, and root `.env` key-name exposure findings.

### 1.0.0-rc.1 & 1.0.0 — Frozen AgentBOM v1 contract

- **Schema 1.0 stability contract:** Freeze native format 1.x compatibility (additive minors only, CI schema-digest guard, wheel `Requires-Dist` allow-list test, standardized exit-code matrix, and `GOVERNANCE.md` supported-surface contract).
- **ShadowScan v1 import contract:** Expand projection coverage (models, frameworks, agent configs, workflows) with commit/run-time binding and file/line claim locators while keeping imported claims strictly `declared`.
- **Typed standard graph & validated SARIF:** Project additional native relationship kinds, remote MCP/A2A `services`, and minimal `modelCard` fields into CycloneDX/SPDX standard fields; vendor and validate the official OASIS SARIF 2.1.0 schema; register `nexus-symbiote` and `agentbom` property namespaces.
- **Attestation gates & parser hardening:** Enforce `--require-attestation` directly in `validate`/`risk` gates, expand Hypothesis fuzzing properties across all parsers, and tighten per-module coverage floors across remaining security collectors.

### 1.1 – 1.4 — Depth & ecosystem releases

- **1.1 (Judgment & forensics):** Stable lethal-trifecta (`untrusted-input`, read, egress) path tracking, deep hook/skill-preamble/launcher-target digest binding, pickle safe-global allow-list with byte offsets, and onboarding a second maintainer and security contact.
- **1.2 (Offline advisories & VEX):** Offline operator-supplied advisory snapshots (OSV/EPSS/KEV), SBOM merge/pinning-state fidelity, assurance-tiered taint reachability, operator-scoped VEX states, and an independent third-party benchmark corpus.
- **1.3 (Standards & signing):** OpenSSF Model Signing (OMS) and agent-card signatures, MCP contract lockfile updates, identity & authority inventory, SPDX AI profiles, and Dependency-Track/GUAC interoperability.
- **1.4 (Runtime & evidence):** Expanded reference-gateway observation sinks, training-lineage ingestion, live registry resolution, and complete compliance evidence packages.

## Decisions and non-goals

Recorded architectural boundaries (see [docs/decisions.md](docs/decisions.md) for how decisions are proposed or revised):

| Topic | Decision | Rationale |
| --- | --- | --- |
| Live agent execution (`observe --agent`) | **Replaced by `trace-diff`** | SymBiote never executes inspected targets; offline OTLP trace comparison provides declared-vs-reported visibility without execution risk |
| Importing telemetry or external scans as `observed` | **Declined (`reported` / `declared`)** | `observed` is reserved for direct byte measurement by a SymBiote collector; imports never upgrade assurance |
| Single 0–100 "TrustScore" | **Replaced by risk classes & evidence profile** | A single high score implies trustworthiness, which no static inventory can establish |
| Embedded OPA or Cedar runtime | **Declined (JSON contract & policy export)** | Embedding a second policy engine adds attack surface in the trusted path; export to external engines instead |
| `nsb` CLI alias | **Declined** | Collides with an unrelated PyPI package and splits documentation |
| In-process ShadowScan extra | **Declined** | Keeps dependency locks minimal and isolates discovery as a separate least-privilege process |
| LLM-based classification in core | **Not planned** | Deterministic collectors form the trusted path; non-deterministic classification must not govern fail-closed gates |
| eBPF runtime capture | **Not planned** | Privileged and host-specific; exported OTLP traces cover declared-vs-reported verification |
| Typosquat heuristics / registry proxy | **Out of scope** | Heuristic alarms degrade fail-closed CI gates; network services are outside an offline CLI's boundary |
| Inventory envelope encryption | **Not planned** | Inventories store secret references, never values; encryption at rest belongs to the artifact store |
| Escaping symlinks during collection | **Fail closed (confinement unchanged)** | Following or inspecting links outside the scan root violates confinement; replace with regular files or in-root relative links |
| Broadest scanner / CVE DB / MCP firewall | **Non-goals** | Import broader discovery (ShadowScan, CycloneDX/SPDX) and enforce contracts through external gateways ([runtime contract reference](docs/runtime-contract-reference.md)) |
| Proving an agent or model benign | **Non-goal** | Absence of findings is unknown, not verified safety |

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and [docs/decisions.md](docs/decisions.md) before proposing roadmap changes or new collectors.
