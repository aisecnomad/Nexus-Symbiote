# Roadmap

> Nexus SymBiote is unrelated to the 2022 Linux malware "Symbiote."

Nexus SymBiote is the **verifiable AgentBOM**: an offline-by-default inventory, validation, attestation, and drift-gating layer for AI agent supply chains. Every claim carries its evidence and assurance level, every gap is reported, and every gate fails closed.

- [Scope: ShadowScan finds, SymBiote proves](#scope-shadowscan-finds-symbiote-proves)
- [Core invariants](#core-invariants)
- [Release train](#release-train)
- [Decisions and non-goals](#decisions-and-non-goals)

## Scope: ShadowScan finds, SymBiote proves

New broad discovery across source code, infrastructure, notebooks, and data stores lives in the companion **Nexus-ShadowScan** engine. Nexus SymBiote directly reads agent control-plane surfaces without executing them, imports ShadowScan discovery reports as producer-bound declared claims (never upgrading assurance), and owns the graph, policy evaluation, attestations, standards exports, and CI/runtime gates.

| Surface | Owner | How it reaches the AgentBOM |
| --- | --- | --- |
| Agent control-plane files (MCP configs, skills, subagents, hooks, IDE settings/permissions, instructions, A2A cards) | Nexus SymBiote | Read directly by built-in collectors, never executed |
| MCP server/tool source declarations, model weights, declared RAG config, root manifests/lockfiles, catalog images | Nexus SymBiote | Built-in `mcp`, `model`, `rag`, `registry`, and `a2a` collectors |
| Broad source discovery (hosted models, inline prompts, workflows, datasets, notebooks, containers/IaC) | Nexus-ShadowScan | Signed report imported as declared, producer-bound claims |
| Graph, risk judgment, DSSE attestations, standards exports, and CI/runtime gates | Nexus SymBiote | Built and enforced here |

## Core invariants

Eleven invariants govern every release. A feature that violates any of them is not shipped.

| # | Invariant | Guarantee |
| --- | --- | --- |
| 1 | **Never execute what is scanned** | Static commands run under the offline guard refusing process creation; hostile fixtures (pickles, hooks, MCP launches) are read as data. |
| 2 | **Offline by default** | Zero outbound network access unless explicitly opted into `--live`; verified in CI inside a kernel network-denied namespace (`unshare --net`). |
| 3 | **No LLM in the core path** | Zero model SDKs or LLM clients in runtime dependencies, extras, or Action locks; deterministic, auditable static analysis only. |
| 4 | **Unknown is never clean** | Exceeded bounds, failed/unselected collectors, and unverified formats fail closed under the default policy. |
| 5 | **Every claim carries assurance and evidence** | Assurance, method, and scope are mandatory; only cryptographic verification elevates trust to `verified`. |
| 6 | **Secrets by name, never by value** | Credentials are redacted across inventories, exports, logs, and diagnostics; enforced by CI regression contracts and 25 security cases now. |
| 7 | **Output is deterministic** | Byte-identical inventories and exports across checkouts and reruns (honoring `SOURCE_DATE_EPOCH`). |
| 8 | **Exports are valid and lossless** | CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0, and VEX validate offline against vendored, digest-checked schemas with lossless native round-trips. |
| 9 | **Policy lives outside what it judges** | Operator policies, signer policies, and reviewed baselines must live outside the untrusted checkout; checkout relaxations never weaken CI gates silently. |
| 10 | **Runtime is opt-in and unprivileged** | Live observation and pinned stdio mediation are explicit opt-in commands isolated in unprivileged namespaces. |
| 11 | **No rule without fixtures** | Every security finding category and regression contract is backed by committed positive and negative fixtures enforced in CI. |

<a id="plan"></a>

## Release train

Every milestone preserves the [security model](docs/security-model.md#design-principles) and ships only with reproducible tests.

| Release | Theme | Key deliverables |
| --- | --- | --- |
| **0.2.0** | Release readiness & control-plane hardening | Publish `0.2.0` via OIDC trusted publishing with build attestations, 24h soak, and signed release tags; expand MCP/IDE/prompt/registry precision and redaction; clean documentation and repository hygiene. |
| **0.3.0** | Evidence depth & upgrade ergonomics | Per-category positive/negative fixture catalog parity, deterministic TypeScript analysis bounds, `diff --expect-upgrade` profile migration tooling, and paired ShadowScan benchmark scoring. |
| **1.0.0** | Verifiable AgentBOM baseline | All 11 invariants backed by passing CI gates (including kernel offline invariant, zero-LLM-SDK check, and native schema line/occurrence locators); N12 integrity-gate refinement so unverified surfaces never pass on a single unrelated file hash; ShadowScan producer-bound contract (`v5` projection). |
| **1.1** | Signed operator governance | Signed out-of-checkout operator policies with monotonic narrowing, CI/hosted-agent workflow rating, and expanded runtime gateway mediation adapters. |
| **1.2** | Multi-manifest & ecosystem coverage | Nested manifest/lockfile inventorying, foreign SBOM import reconciliation, and expanded offline advisory/VEX workflows. |
| **1.3** | Guardrail & RAG depth | Declared guardrail/eval configuration coverage and deeper RAG retrieval-surface verification. |
| **1.4** | Ecosystem continuity | Multi-maintainer governance and release continuity, independent external benchmark reproduction, and long-term schema stability. |

## Decisions and non-goals

Architectural decisions and explicit boundaries (see [docs/decisions.md](docs/decisions.md) for how new decisions are recorded):

- **No LLM-based classification in core analysis.** All static collection, risk scoring, and gate verdicts remain deterministic, offline, and reproducible.
- **No automatic execution of scanned repositories.** Collectors never import user Python modules, run package managers, or execute hooks during static scans.
- **Discovery vs. proof split.** Broad source/infrastructure discovery is routed through Nexus-ShadowScan and foreign SBOM imports rather than duplicating general-purpose scanners inside SymBiote.
- **In-process native parsing under strict bounds.** `tree-sitter` stays in-process under file-byte and AST-node caps so the offline guard's refusal of process creation holds without exception; untrusted repositories should be scanned in an isolated container/worker.
- **Historical records live in Git history.** Superseded draft plans, dated internal audit snapshots, and PR disposition logs are preserved in Git history rather than duplicated in the working tree.
