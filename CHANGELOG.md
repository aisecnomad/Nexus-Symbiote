# Changelog

## [0.1.0] - Unreleased

First alpha of the AgentBOM toolkit under the Hunzee-VC organization. Not yet tagged or published; the date is set when the release is tagged.

### Security

- Raise dependency minimums past known advisories: cryptography 50, sigstore 4.4 with tuf 7, and pytest 9.0.3 for development. Sigstore 3.x is no longer supported.
- Lock dependency versions without known advisories (cryptography 50.0.2, sigstore 4.5.1, tuf 7.0.1, pytest 9.2.0) so the required OSV audit of the locked environment passes.
- Keep unused jsonschema format checkers out of the runtime validation worker. With the cyclonedx or all extras installed, their import cost exceeded the worker's CPU limit and every runtime authorization failed closed.
- Require TLS 1.2 or later explicitly in the pinned HTTPS transport, and create `runtime keygen` public keys with mode 0600 like private keys.
- Bind static MCP server structure and reconcile configured tool fingerprints against fresh source evidence; with `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, bind configuration values by HMAC so exports never carry a digest that secrets could be guessed from. Require recollection of legacy snapshots without the binding.
- Reject same-version MCP package substitutions, argument and endpoint-path drift, and edited supplied descriptors during project validation.
- Replace raw scanner exception text with safe diagnostic codes and record malformed model metadata using field names only.
- Read Claude's declared `permissions.defaultMode`, recognize bare broad tool grants, and retain allowances across collected settings layers without claiming effective authorization.
- Add independent runtime signing quorums for snapshots, trust status and action approvals; preserve them through pinned stdio invocation.
- Reject runtime CLI FIFO, symlink and oversized inputs through the bounded regular-file reader.
- Detect same-version MCP launcher package substitutions in project validation and drift checks. Review older baselines that lack the launcher identity.
- Reconcile locally collected security fields and findings before accepting supplied BOMs. Project-backed risk scoring rejects a conflicting inventory.
- Omit schema literals from MCP descriptor exports and corroborate the original static definition against project evidence.
- Reject contradictory native ShadowScan finding counts and conflicting public fields during CycloneDX and SPDX recovery. Emit only unconditional dependencies in the standard CycloneDX graph.
- Require successful canonical CI-workflow evidence for the exact publication source SHA, in addition to protected-branch settings.
- Enforce offline tracked-source hygiene and vendored schema provenance digests in the required quality job.
- Check trust-status signers against the previous tenant revocation list and recheck the accepted status when consuming a tool approval. Upgrading an existing gateway may require replaying its last accepted trust status.
- Reconcile supplied BOMs with the project's static inventory. A completed search can record zero matches. Skipped collectors, failed reads, and unmapped discovery evidence still block the default repository gate.
- Ignore report-supplied project policy during standalone ShadowScan import. Use `--report-only` explicitly for exploratory imports.
- Report changes to an MCP server's recorded origin, transport, or launcher as critical drift. Use `diff --fail-on-alert` in CI to enforce those alerts.
- Detect semantic snapshot changes, including removed integrity evidence, changed endpoints,
  expanded capabilities, remote-code settings, and dependency conditions or assurance.
- Preserve unknown autonomy when a native agent omits the field, and parse Python
  package pins consistently using ecosystem-aware requirements and versions.
- Treat GitHub Action inputs as data and invoke the scanner without shell evaluation.
- Preserve validation failures and malformed risk-report errors as failed Action runs.
- Install the Action's checked-out source instead of an independently moving package-index release.
- Generate requested exports and SARIF from one collected native inventory.
- Pin third-party Actions to verified commit references and disable persisted checkout credentials.
- Add a pinned CodeQL workflow for push, pull request, and weekly schedule; hosted analysis requires runner availability and code-scanning entitlement.
- Run every command offline by default: the CLI refuses name resolution, network connections and process creation. Only `discover-mcp`, `advisories` and `verify-live` can reach outside local files, and only in live mode (`--live` before the command, or `NEXUS_SYMBIOTE_MODE=live`); every other command stays offline even then. A project policy file cannot select the mode. **Breaking:** add `--live` to existing invocations of those three commands.
- Report a malformed or truncated inventory in `summary`, `validate`, `risk`, `blast-radius` and `diff` as a short error instead of a traceback, without echoing the file's contents to the terminal.
- Make `diff --fail-on-alert` fail on every in-place component change rated medium or above, as additions already did. Previously a version bump of an MCP server package, a swapped npm lockfile integrity value, a replaced MCP tool implementation, an A2A card URL moved to plaintext HTTP, or an IDE agent newly granted `Bash(*)` was reported as a change but passed the gate.
- Scan container image references in linear time. A `docker-compose.yml` ending in `image:` followed by a long run of whitespace took minutes, and over a day at the 4 MiB read limit.
- Index collected components during `scan` instead of searching the whole inventory for each one. A project declaring 10,000 MCP tools now scans in 4.3 s instead of 10.9 s, with identical output. Very large tool declarations still need a collection limit.
- Print inventory-derived text literally in human-readable output. Rich markup and terminal-control, bidirectional or invisible characters in a component name could add hyperlinks, conceal text or rewrite earlier lines, for example to hide a critical `diff` alert. As a result `validate` again shows which component each issue belongs to, and the `risk` findings table keeps its severity column in an 80-column terminal.

### Delivery

- Restructure the README around a Why/What/How narrative: add the problem statement motivating AgentBOMs, a capabilities summary, an ASCII architecture diagram, a table of contents, and a contributing section linking all community files. Switch documentation links from absolute GitHub URLs to relative paths and add the CLI reference, npm lockfile evidence guide, and tutorials to the documentation table. Add a Python version badge.
- Optimize the hero image from 3.5 MB to 225 KB (resize to 1400 px, quality 85, strip metadata) to reduce clone size and improve page load.
- Lead the README with what a scan of the demo agent finds; move result limits and export semantics into the security model's "What results do and do not establish" section. Remove the static coverage badge and the link to a release asset that does not exist yet.
- Point documentation, issue templates, citation metadata and SARIF `informationUri` at Hunzee-VC/Nexus-Symbiote, and reject legacy-owner repository URLs in the repository hygiene check. Runtime and benchmark predicate-type identifiers are unchanged because signed evidence binds to them.
- Split the most complex collector and CLI functions without behavior changes, and add hypothesis property tests for strict JSON parsing, tool fingerprints, the runtime JSON budget, origin redaction and SafeTensors inspection.
- Scope exported SPDX document and element identifiers to each inventory revision so different package versions can coexist in a combined graph.
- Run security regressions against the exact wheel built by CI and the release workflow.
- Emit standard package identifiers for portable BOM consumers while retaining
  native evidence and explicit projection limitations.
- Exercise supported Python versions, built-wheel installation, Action abuse cases, and exporter conformance in CI.
- Add manually requested release candidates, distribution checksums, release evidence, build attestations, and environment-gated OIDC publication.
- Align documentation with MIT licensing and the alpha support boundary.
- Document every command and option in `docs/cli-reference.md`, checked against the CLI by a test, and add help text to the 20 options that had none. Add `docs/offline-and-live-modes.md`.
- Add an offline demo project, `examples/demo-agent`, with a walkthrough in `examples/README.md`. Remove `examples/customer-support-agent.json`, whose legacy tool fingerprints current validation rejects.
- Rehearse releases on TestPyPI through the same pipeline as PyPI, replacing the separate `publish-testpypi.yml` workflow: the release workflow's `publish` input is now `none`, `testpypi` or `pypi`, each with its own protected environment and trusted publisher.
- Build release distributions from a `git archive` export of the commit with `SOURCE_DATE_EPOCH`, and upload them before tests, evidence collection or the unpinned smoke installation run. Previously evidence written during the run could enter the sdist, and a dependency resolved without hashes ran before the distributions were hashed and uploaded. Attest and publish jobs now reject artifact digest mismatches.
- Check `.yaml` workflows as well as `.yml` for unpinned Actions and expressions in shell source.
- Canonical repository moved to Hunzee-VC/Nexus-Symbiote; documentation and package metadata updated accordingly.

### Fixed

- Detect a pathname replacement during pinned-descriptor reads on filesystems that do not refresh change time on rename-over: the before/after invariance check now includes the link count (shared `file_invariance` helper) and model scanning additionally verifies the confined pathname's `(st_dev, st_ino)` identity (`ConfinedCollection.path_identity`), so a swapped model or configuration artifact cannot bind its inspected structure and digest to the new pathname.
- Fix strict `mypy` annotations in `scripts/check_wheel_security.py` and `scripts/check_dependency_advisories.py` and include `scripts/` in the `typecheck` quality gate.
- Report a collector that produced a conflicting duplicate component or a dangling dependency edge as failed in `collectors_completed`, not only in `scanner_status`. A clean `ScanResult` no longer lets an orchestration-level failure be recorded as completed collection, or raise the inventory's completeness assurance to `observed` on its own. Gates were already failing through `scan_failures`; the emitted coverage record was the inaccurate part.

### Changed

- Split the CLI implementation: `cli.py` keeps the root group and shared helpers (`_get_scanners` patching seam unchanged), and the offline commands move to `inventory_cli.py` (scan, import-shadowscan, verify-artifact, verify-discovery) and `review_cli.py` (validate, risk, diff, summary, blast-radius, init). No command names, options or output changed.
- Enforce the canonical repository owner for tracked documentation and workflow metadata in the required quality job. Absolute GitHub URLs are outside the inline local-link check, so the `aisecnomad` to `Hunzee-VC` transfer had left stale links in `CITATION.cff`, `README.md`, `SUPPORT.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, both issue templates, `examples/README.md`, `benchmarks/inventory/README.md` and `docs/repository-controls.md`. Dated audits keep the owner recorded at the time.
- Remove the duplicated collector list and coverage-gap sentence from the README; both are stated under "How it works".

### Notes

- Attestation predicate URIs, `tool_vendor` and vendored schema provenance keep the original owner deliberately. The predicates are stable type identifiers, `tool_vendor` is compared by `diff` and would surface as metadata drift against every existing baseline, and `copiedFrom` is a historical provenance record.
- Add `config/github-main-protection-interim.json`, a branch-protection configuration identical to `config/github-main-protection.json` except that it does not require pull-request review. Applying the full proposal as written on a single-maintainer repository blocks the maintainer from merging their own pull requests, because GitHub does not count self-approval toward a required review; the interim configuration still enforces `Verified CI` for everyone, including administrators, and still disables force pushes and branch deletion. `scripts/check_repository_controls.py` does not check for required reviews, so the interim configuration satisfies the same publication preflight as the full one. See [repository controls](docs/repository-controls.md) and [issue #74](https://github.com/Hunzee-VC/Nexus-Symbiote/issues/74).
- Fix a stale repository-owner reference in `docs/repository-controls.md`'s preflight example left over from the move to the Hunzee-VC organization.
