# Nexus SymBiote

Agent Bill of Materials (AgentBOM) generator and validator for AI agent supply chain security.

## Project structure

```
src/nexus_symbiote/
  core/        — Domain models (Pydantic v2), enums, AIBOM container, RFC 8785 JCS hashing
  scanners/    — Component discovery (MCP, model weights, prompts, RAG, registry, A2A, IDE agents, ShadowScan reports)
  generators/  — Exports: native JSON, CycloneDX 1.7, SPDX 3.0, SARIF, VEX
  validators/  — Completeness, integrity, and risk scoring
  diff/        — AIBOM version comparison and the snapshot alert gate
  live/        — Opt-in observations through independently pinned local MCP launchers
  utils/       — Confined bounded reads, Sigstore/artifact verification, file hash utilities
  runtime.py   — Signed, operation-bound authorization for integrations that mediate tool calls
  runtime_validation.py, runtime_cli.py — Offline schema validation worker; `runtime` commands
  policy.py, signature_policy.py       — Caller-selected policy and operator signer policy
  graph.py, lineage.py                 — Repository association graph, blast radius, lineage
  advisories.py                        — Explicit, bounded OSV queries for exact package identities
  modes.py                             — Offline by default; live mode is opt-in
  scanner_catalog.py                   — Built-in collector universe for coverage checks
  cli.py, inventory_cli.py, review_cli.py — Click CLI root, shared helpers, offline inventory/review commands
  live_cli.py, supply_chain_cli.py — Live-mode and supply-chain commands
```

## Build and test

Match CI by installing the hash-locked environment first:

```bash
make install-locked   # hash-locked CI environment plus an editable install
make quality          # ruff, format check, mypy strict, workflow and hygiene checks
make test             # full pytest suite; `make coverage` enforces the CI floors
```

## Key conventions

- Python 3.11+, Pydantic v2, Click for CLI
- All hashing uses `core/hashing.py` — RFC 8785 JCS for tool definitions, SHA-256 for files
- Component types are in `core/enums.py:ComponentType`
- Every scanner extends `scanners/base.py:Scanner` and returns `ScanResult`
- Risk assessments use `RiskSeverity` enum: critical > high > medium > low > info
- Trust tiers: internal-verified > internal-unverified > third-party-signed > third-party-unsigned > untrusted-public > unknown
- Tests live in `tests/` and use pytest
- Ruff for linting (line-length 100), mypy strict mode
- No comments unless the why is non-obvious
