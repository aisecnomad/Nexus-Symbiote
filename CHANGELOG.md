# Changelog

Notable changes to Nexus SymBiote, newest release first. Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Within each release, breaking changes and security improvements come first.

## [Unreleased]

### Security

- **Deno sandbox, TLS-bypass, and runtime debugger launch auditing:** `scanners/mcp_launch.py` and `scanners/mcp.py` now flag unrestricted Deno permissions (`-A`/`--allow-all`), scoped and unscoped host permissions (`--allow-run`/`--allow-ffi`/`--allow-sys`), disabled TLS verification (`--unsafely-ignore-certificate-errors`), unscoped Deno permissions (`--allow-read`/`--allow-write`/`--allow-net`/`--allow-env` without targets), and Node/Deno flags that enable the inspector (`--inspect`, `--inspect-brk`, `--inspect-wait`). Scoped Deno short permissions (`-R`, `-W`, `-N`, `-E`, `-S` with `=target`) follow the same rules as their long forms. Configuring a debugger port alone leaves the inspector inactive.

## [0.2.0] - 2026-11-25

Major alpha milestone closing `0.1.0` detection gaps, adding reproducible content-addressed inventories, DSSE/in-toto inventory attestations, OTLP trace comparison, compliance crosswalks, G7 minimum-element coverage, interactive HTML risk graphs, control-plane auditing, typed CycloneDX/SPDX exports, and foreign SBOM import. Re-collect baselines after upgrading (see [Upgrading](#upgrading)).

### Breaking changes

- **Native format `1.1.0` & deterministic output:** All collected paths are now POSIX root-relative (making inventories portable across checkout locations), `serial_number` is derived deterministically via UUIDv5 from the run-independent content digest (`nexus-symbiote/inventory-content/v1`), components and edges are canonically sorted, and wall-clock timestamps are omitted unless `SOURCE_DATE_EPOCH` is explicitly set (1–12 ASCII digits; malformed values exit `2`). `0.1.0` inventories load for inspection but require re-collection before `validate --project` or `diff --fail-on-alert`.
- **Policy precedence & operator floors:** `scan`, `baseline`, and `--project` commands automatically apply checkout `.nexus-symbiote.yaml` settings that *tighten* gates, while relaxations require `--accept-project-policy` (bounded by any signed operator policy). `--no-project-policy` ignores checkout policies entirely. Policy files outside the scanned root and signer/launch policies inside the scanned repository are refused.
- **Fingerprint-bound suppressions:** Every `risk.suppressions` entry must now include the finding `fingerprint` printed by `risk` (binding component, category, severity, detail, and content/binding digests so modified files or changed severities retire stale suppressions automatically; see [fingerprint migration](docs/fingerprint-migration.md#suppression-content-digests)).
- **Non-Markdown import & skill digest rules:** Non-Markdown `@path` imports (e.g., `@prompts/system.txt`) and non-Markdown rule/prompt/subagent files no longer export an unkeyed `content_hash` (use `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` for keyed HMAC binding); comparing against an older snapshot raises `Content hash removed` in `diff` and `project-reconciliation-failed` on `--project` reconciliation. Skill/command resources retain SHA-256 digests (e.g., `.claude/skills/x/app.json` linked to `config/app.json`), while files named as credential stores are skipped as gaps.
- **ShadowScan discovery verification & projection v6:** `import-shadowscan`, `scan --check`, `baseline`, `validate`, and `risk` record `discovery_verification` and fail closed in CI on unverified ShadowScan discovery evidence unless verified with `--bundle` / `--signature-policy` or explicitly allowed with `--allow-unsigned-discovery`. Projection profile advances to `nexus-symbiote/shadowscan-projection/v6` (naming cited models from code evidence, projecting `agent-config` and `framework-usage` kinds, and reporting unmapped kinds by name).
- **Tighter drift & coverage gates:** `diff --fail-on-alert` alerts on removed components, relationship changes, unbound redacted values (without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`), and newly digested IDE settings files. Additional unrecognized SDK/launcher patterns, default-excluded entries inside agent config directories, and unreadable/invalid files now fail closed as coverage gaps.
- **SARIF rule IDs & standard export projections:** SARIF rules are now `nexus_symbiote/<category>/<severity>` with framework taxonomy tags (GitHub Code Scanning dismissals do not carry over; see [fingerprint migration](docs/fingerprint-migration.md#sarif-rule-identifiers)). Standard exports advance to CycloneDX projection 2/3 and SPDX projection 2/4 (`0.1.0` exports remain recoverable).
- **CLI, Action & runtime contract updates:** `validate`, `risk`, `diff`, `summary`, and `blast-radius` write primary results to stdout; `advisories` exits `1` on matches; `runtime` gateway passes RFC 8785 canonical arguments by default (`canonical_arguments=True`) and evaluates declared schema dialects strictly; `verify-live --no-isolation` is refused off Linux (`isolation-unavailable`); MCP stdio notes moved from `transport_security` to `local_process`; `evidence-profile` emits v2; Action `risk-threshold: '0'` no longer skips severity/coverage gates; pre-commit hooks run `scan . --no-project-policy --accept-default-exclude root:.git --check`.
- **Dependency floors & packaging:** Minimums raised to `click>=8.2.1`, `pydantic>=2.12`, `packaging>=24.2`, `jsonschema>=4.25`; dropped unused `rich` dependency and `yaml` extra; moved dev tools to `[dependency-groups]`; distribution license expression updated to `MIT AND Apache-2.0 AND Community-Spec-1.0 AND CC-BY-3.0`.

### Security

- **Control-plane & IDE agent hardening:** Collects Claude Code hooks (settings, subagent/skill front matter, plugin manifests, `statusLine`, `fileSuggestion`), deny/ask/allow precedence (`oversight_gap`), exact case-sensitive `mcp__` allow-wildcard precedence (skipping unanchored `mcp__*` globs), `settings_environment`, credential helpers, Codex `config.toml`, `.cursor/cli.json`, Antigravity/xAI/Copilot settings, and nested `CLAUDE.md`/`AGENTS.md`/`GEMINI.md`/`.cursorrules`. Rates download-and-execute shell/PowerShell hook cradles critical.
- **Prompt & text-poisoning defenses:** Added deterministic O(N) text-poisoning rules (`instruction_injection`, `tool_description_poisoning`), hidden HTML/Markdown comment detection (`hidden_markup`), unassigned plane-14/default-ignorable character detection (including served `verify-live`/`discover-mcp` MCP text rated before redaction), Claude Code marked-compatible `@path` import resolution, and linear-time bitmask NFA parsing for CommonMark kind-7 HTML tags (eliminating exponential regex backtracking).
- **MCP & source-collection hardening:** Inventories MCP servers across 11 client config dialects plus TypeScript/JavaScript/Python source files (resolving constructor literal names, launched scripts under `examples/`/`build/`, wrapper launchers, container volume/privilege risks, and bridge packages). Reports dynamic/unresolved SDK imports and application-launched servers as explicit gaps.
- **Model & lockfile integrity:** Inspects pickle opcodes across nested archive/compression suffixes (`.joblib.z`, `.pkl.tar.gz`, `.cloudpickle`), checks GGUF and Hugging Face Jinja chat templates for sandbox-escape patterns, validates Sigstore cached trust-root permissions via open descriptor (preventing TOCTOU swaps), and resolves npm, pnpm, Yarn, uv, and Poetry lockfiles with registry/index redirect detection (`registry_origin`).
- **Credential redaction & output neutralization:** Expanded scrubbing across registered HTTP auth schemes (DPoP, HOBA, Mutual, Bearer, Basic), split launch arguments, multiline base64 keys, refused server records (with bounded overflow scrubbing and `set`/`setx` extraction), high-entropy secret commands, NFKC/format-stripped matching, URL-safe base64 PEM keys, Zed `command.*` fields, `agent.yaml` fields, and registry identifiers. Neutralizes control, format, noncharacter, and default-ignorable code points and CI log commands across terminal, JSON, SARIF, HTML, and Markdown output.
- **Bounded parsing & offline/release assurance:** Enforced operator-owned `--limit` / `NEXUS_SYMBIOTE_LIMITS` bounds (including `source-scan-bytes`, `python-nodes`, `import-lookups`, `prompt-files`), linear-time YAML/TOML/JSONC/regex parsers, kernel network-denied CI invariant testing (`unshare --net`), trust-anchor ownership checks on Action/CLI key & baseline inputs, and signed-tag + 24-hour soak release preflights.

### Added

- **Reproducibility & attestations:** `digest` command, `SOURCE_DATE_EPOCH` support, `attest` and `verify-attestation` (Ed25519 DSSE/in-toto envelopes), and Action inputs `reviewed-baseline`, `reviewed-baseline-attestation`, `trusted-keys`, and `attest`.
- **Runtime & control-plane analysis:** `trace-diff` (OTLP/JSON trace comparison as `reported` evidence), `audit-control-plane` (hook targets, skill preambles, MCP bridges, steering surfaces, CI agents, identity blast radius), `trifecta` (lethal trifectas, toxic flows, tool shadowing), and `diff-instructions`.
- **Compliance, exports & interoperability:** `crosswalk` (OWASP LLM/ASI, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001, CWE), `minimum-elements` (G7 AI SBOM coverage), `graph` (CSP-pinned self-contained HTML/JSON risk view), `export-standard` (typed CycloneDX 1.6/1.7 & SPDX 3.0.1 AI/Dataset profiles with `agent.yaml` 1.1 declarations), `export-policy` (default-deny Cedar/Rego/JSON allowlists), `import-sbom`, `evidence-profile`, `export-inventory` (ShadowScan approved lists), offline advisory matching (`advisories --offline-db`), and `vex` operator decision support.
- **Container image & macOS CI:** Hardened multi-stage `Dockerfile` published and attested to `ghcr.io/aisecnomad/nexus-symbiote` on PyPI releases; full macOS 15 test suite integrated into `Verified CI` alongside parallel `pytest-xdist` execution and a fresh AIBOM-Bench precision gate (`make precision`).

### Changed

- Canonical repository moved to `aisecnomad/Nexus-Symbiote` (stable attestation predicate URIs and schema `$id` preserved for verification compatibility).
- Deduplicated multi-collector failure summaries in text/JSON/Action reports and raised default `depth` limit to 64 (`entries` to 100,000; `model-bytes` to 64 GiB).
- Added `--detailed-exit-codes` (`0` pass, `2` usage, `3` gate failed, `4` collection/input error) alongside legacy exit codes.

### Fixed

- Eliminated superlinear/quadratic scaling in HTML block regexes, `.npmrc` parsing, YAML flow nesting, pnpm lockfile scanning, Draft-04 mixed-type enum uniqueness checks, and TypeScript parse timeouts (switched to thread CPU time).
- Fixed confined descriptor/ctime tracking against in-place rewrites, macOS firmlink alias resolution, atomic symlink-safe file output (`-o -` refused), `graph` source ranking past 200 agents, and pinned-stdio cgroup teardown sequencing.

### Upgrading

1. **Re-collect baselines** from your reviewed commit using the same `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` (or none) as CI, then inspect `diff old.json new.json` once before adopting ([drift gate](docs/drift-gate.md#take-both-snapshots-the-same-way)).
2. **ShadowScan in CI:** Pass `--bundle` / `--signature-policy` to verify reports, or opt in explicitly with `--allow-unsigned-discovery` (Action: `allow-unsigned-discovery: 'true'`).
3. **Update suppressions & policies:** Add finding `fingerprint` values from `risk --json-output` to every `risk.suppressions` entry; replace `transport_security` with `local_process` where ignoring MCP stdio notices.
4. **GitHub Action & scripts:** Use `risk-check: 'false'` (not `risk-threshold: '0'`) to disable risk gating; keep signer/launch policies and trusted keys outside the repository; set `SOURCE_DATE_EPOCH` to integer seconds (or unset it); pass `--project` to `verify-live`.

## [0.1.0] - 2026-11-08

Initial alpha release of Nexus SymBiote published to PyPI with PEP 740 attestations (under the `Hunzee-VC` organization prior to repository transfer). See the [v0.1.0 known limitations](https://github.com/aisecnomad/Nexus-Symbiote/blob/v0.1.0/SECURITY.md#known-limitations-in-010).

### Security & Core

- Static, offline-by-default collection across 8 collectors (`mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, `ide_agents`, `shadowscan`) using POSIX `dir_fd`/`O_NOFOLLOW` confined reads and a CPython audit-hook offline guard blocking sockets, DNS, and subprocesses.
- Descriptor + inode/ctime verification on confined reads, strict JSON/YAML/TOML parsing, RFC 8785 JCS tool fingerprinting, SafeTensors header inspection, pickle/checkpoint/Keras/SavedModel detection, and A2A 0.3/1.0 security-scheme extraction.
- Scoped project policy discovery (scan root only), visible `policy_weakened` reporting, terminal/CI log neutralization, secret redaction, and constant-time HMAC source-binding comparisons.
- Ed25519 DSSE signed runtime contracts (`ReferenceGateway`) with signer quorums, tenant-scoped approval nonces, canonical predicate enforcement, and isolated schema validation worker.
- Exports to native AgentBOM JSON (`1.0.0`), CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0, and CycloneDX VEX validated against vendored upstream schemas, plus `diff`, `validate`, `risk`, `blast-radius`, `verify-artifact`, `verify-discovery`, `import-shadowscan`, and opt-in live commands (`discover-mcp`, `verify-live`, `advisories`).
- Supply-chain hardened delivery: hash-locked dependencies (`requirements-{ci,action,floor}.lock`), strict mypy + ruff + CodeQL + OSV advisory gates, composite GitHub Action, offline `examples/demo-agent` walkthrough, and OIDC trusted publishing with SLSA build attestations.
