# Nexus SymBiote

Agent Bill of Materials (AgentBOM) generator and validator for AI agent supply chain security.

## Project structure

```
src/nexus_symbiote/
  core/        — Domain models (Pydantic v2), evidence/authority records, enums, AIBOM container, RFC 8785 JCS hashing, inventory content digest
  scanners/    — Component discovery (MCP, MCP launch/live wire, model weights, prompts, RAG, registry, A2A, IDE agents, ShadowScan reports)
  generators/  — Exports & PURL projection: native JSON, CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0, VEX
  validators/  — Completeness, integrity, and risk scoring
  diff/        — AIBOM version comparison and the snapshot alert gate
  live/        — Opt-in observations and pinned stdio execution (`inventory.py`, `pinned_process.py`, `session.py`, `stdio.py`, `verify.py`)
  utils/       — Confined `openat` reads (`confined.py`), Sigstore/Ed25519 verification (`crypto.py`), safe output writes (`files.py`), JSONC/model-header parsers, the CommonMark reader for `@path` imports (`markdown.py`), secret redaction, terminal neutralization
  runtime.py   — Signed, operation-bound authorization gateway (`canonical_arguments=True` by default)
  runtime_validation.py, runtime_cli.py — Isolated offline schema validation worker; `runtime` commands
  policy.py, operator_policy.py, policy_export.py, signature_policy.py — Caller-selected policy, signed operator policy, policy export, and operator signer policy
  settings_precedence.py               — IDE settings layer precedence and effective-policy resolution
  limits.py                            — Operator-controlled collection bounds (`--limit`, `NEXUS_SYMBIOTE_LIMITS`)
  graph.py, lineage.py, trifecta.py    — Repository association graph, blast radius, lineage, and toxic capability flows
  security_graph.py, security_graph_cli.py — Advisory, inventory and trace correlation for `security-graph`
  instruction_diff.py                  — Instruction-surface normalization and diffing
  risk_classes.py, graph_view.py, graph_cli.py — Risk classes, exposure paths; the `graph` HTML/JSON view
  digest_cli.py                        — `digest`: file, canonical and content digests of an inventory
  attestation.py, attestation_cli.py   — DSSE/in-toto inventory attestations; `attest`, `verify-attestation`
  otlp.py, trace_evidence.py, trace_cli.py — Bounded OTLP/JSON trace reading, reported evidence; `trace-diff`
  crosswalk.py, crosswalk_cli.py       — Framework crosswalk that SARIF tags come from; `crosswalk`
  minimum_elements.py, minimum_elements_cli.py — G7 AI SBOM minimum-element coverage; `minimum-elements`
  inventory_export.py, inventory_export_cli.py — ShadowScan simple-list export; `export-inventory`
  spdx_profiles.py, export_standard_cli.py — SPDX 3.0.1 AI/Dataset profiles, ISO 22989 mapping, `agent.yaml` declarations; `export-standard`
  control_plane_audit.py, control_plane_cli.py — Hook target/preamble binding, MCP bridges, steering surface, CI/hosted tools, identity blast radius (`audit-control-plane`)
  sbom_import.py, evidence_profile.py, sbom_cli.py — Foreign SBOM import, nested manifests, per-component evidence profile; `import-sbom`, `evidence-profile`
  advisories.py, offline_advisories.py, vex_decisions.py — Explicit OSV queries, offline advisory matching, and VEX decision records
  modes.py                             — Offline by default; live mode is opt-in
  reporting.py                         — Neutralized text and JSON gate reporting
  scanner_catalog.py                   — Built-in collector universe for coverage checks
  text_poisoning.py                    — Deterministic O(N) text-poisoning and injection rules
  cli.py, live_cli.py, runtime_cli.py, supply_chain_cli.py — Click CLI entrypoints
```

## Build and test

Match CI by installing the hash-locked environment first:

```bash
make install-locked   # hash-locked CI environment plus an editable install
make quality          # ruff, format check, mypy strict, workflow and hygiene checks
make test             # full pytest suite, one worker per core; `make coverage` enforces the CI floors
make check            # offline subset of the required CI checks
```

## Documentation

- `docs/README.md` is the documentation hub, organized by why, what and how. Add new guides there.
- `README.md` is also the PyPI long description (`readme` in `pyproject.toml`). Keep its links and images absolute (`https://github.com/aisecnomad/Nexus-Symbiote/blob/main/<path>`); relative paths do not resolve on PyPI, and `twine check` does not render Markdown. `make hygiene` rejects relative README links and checks that every absolute link resolves to a tracked file and heading.
- Every command and result shown in the docs must be reproducible from the current tree; re-run them when behavior changes.

## Key conventions

- Python 3.11+, Pydantic v2, Click for CLI
- All hashing uses `core/hashing.py` — RFC 8785 JCS for tool definitions, SHA-256 for files
- Component types are in `core/enums.py:ComponentType`
- Every scanner extends `scanners/base.py:Scanner` and returns `ScanResult`
- Risk assessments use `RiskSeverity` enum: critical > high > medium > low > info
- Trust tiers: internal-verified > internal-unverified > third-party-signed > third-party-unsigned > untrusted-public > unknown
- Tests live in `tests/` and use pytest (`conftest.py` isolates environment/HOME, blocks outbound non-loopback sockets, and enforces `--strict-skips` in CI)
- Ruff for linting (line-length 100), mypy strict mode (`mypy src/nexus_symbiote scripts`)
- No comments unless the why is non-obvious
