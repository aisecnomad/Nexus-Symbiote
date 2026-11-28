# Governance

Nexus SymBiote is an alpha project with a single maintainer. This document defines decision authority, review expectations, repository controls, continuity risks, and the supported interface contract.

## Maintainer and decisions

[Emmanuel Dahunsi (@aisecnomad)](https://github.com/aisecnomad) holds final authority over project direction, architecture, dependencies, merges, and releases during alpha (see [MAINTAINERS.md](MAINTAINERS.md)). Contributors propose changes via issues and pull requests; experimental branches never replace the supported `nexus_symbiote` package on `main`.

## Review expectations

Follow the review contract in [CONTRIBUTING.md](CONTRIBUTING.md): explain the problem, behavior, tests, and limitations, and pass `Verified CI`. Security-sensitive changes require a stated trust boundary, abuse case, failing regression test, and security-corpus review. Record which checks actually ran; local runs never substitute for hosted matrix or CodeQL results.

### Review policy while there is one maintainer

No second human reviewer currently exists. Compensating controls and their limits:

- **Required checks:** `Verified CI` must pass on a branch up to date with `main` (enforced for administrators too). This confirms gates ran, not design correctness.
- **Gate integrity:** `scripts/check_workflows.py` blocks hollowed-out gate jobs, downgraded action pins, unsafe triggers, and unreviewed write scopes; diffs to gate files still require line-by-line review.
- **24-hour soak window:** Behavior- and security-changing PRs stay open ≥24 hours before merging; PyPI publication enforces a mechanical 24-hour soak on `main` (waivable only with a logged urgent-fix reason).
- **Review record & AI assistance:** Every PR records post-CI diff review and discloses AI assistance ([AI-assisted contributions](CONTRIBUTING.md#ai-assisted-contributions)). An AI review is a second opinion, not independent human approval.

Adopters requiring independent human review should treat the single-maintainer status as an active limitation until a second maintainer is onboarded and the full protection profile is activated.

## Repository controls and current status

- **Target vs. interim branch protection:** [`config/github-main-protection.json`](config/github-main-protection.json) specifies the full target (requiring `Verified CI`, up-to-date branches, independent & code-owner approval, resolved threads, admin enforcement, and no force-pushes/deletions). While a single maintainer operates the repository (GitHub does not count self-approval), [`config/github-main-protection-interim.json`](config/github-main-protection-interim.json) is active on `main`, preserving every control except required approving reviews.
- **Automated PR and release guardrails:** CI caps PR size at 1,500 changed lines outside `tests/` and `benchmarks/`. Signed commits are requested ([CONTRIBUTING.md](CONTRIBUTING.md#pull-requests)); remaining admin actions (required commit signatures, adding a second code owner) are tracked in [repository controls](docs/repository-controls.md#administrator-actions-still-outstanding).
- **Live verification, not claims:** Checked-in policy files do not configure GitHub. Before releasing, `scripts/check_repository_controls.py` queries live GitHub state to verify branch protection, exact-SHA `Verified CI` (including CodeQL and OSV advisories), active release-tag immutability rulesets, protected `testpypi`/`pypi` environments, and (for PyPI) the 24-hour soak and signed release tag. Because only an administrator token can inspect ruleset bypass actors, the maintainer runs `--verify-bypass-actors` before approving publication ([repository controls](docs/repository-controls.md#operator-prerequisites)).

## Releases

Publication is manually dispatched and privilege-separated across read-only build/verification, shell-free OIDC attestation, and environment-gated trusted publishing ([releasing](docs/releasing.md)). Review candidate checksums, SBOMs, and provenance at the approval gate; a build or upload alone never certifies package safety.

## Continuity

One account currently holds merge, release-approval, PyPI ownership, security-report, and conduct privileges:

- **Security reports:** GitHub private vulnerability reporting survives maintainer changes, with a non-disclosing public fallback in [SECURITY.md](SECURITY.md#reporting-a-vulnerability).
- **Verifiable installs:** Published wheels verify against immutable attestations and tagged lockfiles, independent of the maintainer.
- **Recovery via fork:** MIT licensing, hash locks, and `release.yml` let a successor rebuild and re-attest under their own identity (though not under the `nexus-symbiote` PyPI name).

**Open maintainer action:** Onboard a second maintainer with repository admin access, PyPI/TestPyPI co-ownership, `.github/CODEOWNERS` membership, and backup security/conduct contacts, then switch `main` to `config/github-main-protection.json`. Until then, organizations with supplier-continuity requirements should treat single-maintainer ownership as unresolved.

## Future governance

Additional maintainers, formal RFCs, and expanded decision processes will be introduced as adoption grows, documented through the same reviewed process.

## Supported surface (1.0 contract)

Every built-in collector and CLI command on `main` is classified below (`N8`, converging on schema 1.0). **Supported** interfaces follow documented compatibility, determinism, confinement and offline guarantees; **Experimental** interfaces remain opt-in or pre-freeze report surfaces whose output shapes may evolve faster during alpha.

### Gate reporting contract

Every gate prints each of its failure reasons. How many findings the console lists, and where the complete list is, differs by surface:

| Surface | Console lists | Complete list |
| --- | --- | --- |
| `scan`, `baseline` | Every gate reason, then the first 10 findings at or above the severity cutoff (`LISTED`) and a count of the rest; the first 20 collection failures and the first 10 excluded surfaces | No `--json-output`. The inventory that `scan -o FILE` writes holds every finding, and `risk FILE --json-output` lists them; `baseline` writes no inventory when its gate fails |
| `risk` | The first 15 findings (`TOP_FINDINGS`), under a heading that gives the total; on failure also every gate reason, the first 10 findings at or above the cutoff and the first 10 coverage gaps | `--json-output` |
| `validate` | Every issue in the report, with no console cap; each check keeps at most 1,000 issues, blocking ones first, and counts the rest | `--json-output`, which holds the same issues and the omitted count |
| `diff` | Every security alert and every change, with no cap | `--json-output` |
| GitHub Action | The `scan`, `validate`, `risk` and `diff` reports above, rendered by the same functions, so each keeps its own limit | The inventory at the `aibom-path` output |

### Built-in collectors

| Collector | Status | Notes |
| --- | --- | --- |
| `mcp` | Supported | Static MCP client, server config, launcher and source tool extraction; never executes servers |
| `model` | Supported | Static weight-file hashing, header inspection and signer-policy verification |
| `prompt` | Supported | Confined reading of instruction files, skills and prompt templates |
| `rag` | Supported | Declared retrieval configuration and source hint extraction |
| `registry` | Supported | Root dependency manifests and lockfiles, pinned container digests and index redirects |
| `a2a` | Supported | Static A2A agent cards, client configurations and SDK references |
| `ide_agents` | Supported | Coding-agent permissions, settings, hooks and credential helpers read as data |
| `shadowscan` | Supported | Imports producer-verified Nexus-ShadowScan discovery reports as `declared` claims |

### CLI commands

| Command | Status | Mode | Notes |
| --- | --- | --- | --- |
| `scan` | Supported | offline | Repository collection, gating and native/standard export |
| `validate` | Supported | offline | Completeness, integrity, graph and optional `--project` reconciliation gate |
| `risk` | Supported | offline | Deterministic risk scoring, policy evaluation and suppression gate |
| `diff` | Supported | offline | Semantic drift comparison and security-alert gate |
| `diff-instructions` | Experimental | offline | Instruction-file scope, tool-grant and hidden-content changes between two trees |
| `summary` | Supported | offline | Component, dependency and severity summary |
| `digest` | Supported | offline | File SHA-256, RFC 8785 canonical digest and run-independent content digest |
| `baseline` | Supported | offline | Writes unsigned snapshot only when the built-in scan gate passes |
| `vex` | Supported | offline | CycloneDX VEX (`in_triage`) export for inventory findings |
| `crosswalk` | Supported | offline | Evidence crosswalk across OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001 and CWE |
| `minimum-elements` | Supported | offline | G7 AI SBOM minimum-element coverage check over CycloneDX export |
| `verify-artifact` | Supported | offline | Artifact SHA-256 and optional offline Sigstore bundle verification |
| `verify-discovery` | Supported | offline | ShadowScan report digest, projection and Sigstore bundle verification |
| `import-shadowscan` | Supported | offline | Converts Nexus-ShadowScan report bytes into `declared` native BOM claims |
| `export-inventory` | Supported | offline | Exports reviewed repository agent inventory for ShadowScan reconciliation |
| `init` | Supported | offline | Writes default `.nexus-symbiote.yaml` policy template |
| `attest` | Supported | offline | Signs exact file or inventory bytes in an Ed25519 DSSE/in-toto envelope |
| `verify-attestation` | Supported | offline | Verifies DSSE/in-toto attestations against out-of-project trusted keys |
| `blast-radius` | Experimental | offline | Declared repository association traversal (`effective_authority: unknown`) |
| `security-graph` | Experimental | offline | Correlates advisories, component risks and trace evidence with inventory relationships |
| `graph` | Experimental | offline | Self-contained HTML/JSON risk-class and exposure-path graph view |
| `trace-diff` | Experimental | offline | OpenTelemetry GenAI/MCP trace-versus-inventory comparison (`reported` evidence) |
| `runtime keygen` | Supported | offline | Generates Ed25519 key pair for runtime authorization contracts |
| `runtime sign` | Supported | offline | Signs runtime authorization, approval and revocation contracts |
| `runtime verify` | Supported | offline | Verifies signed runtime contract purpose, signers and validity window |
| `runtime digest` | Supported | offline | Prints canonical digest of runtime contract, approval or revocation document |
| `runtime key-id` | Supported | offline | Prints canonical Ed25519 public key identifier |
| `runtime register` | Experimental | offline | Registers newly issued runtime snapshot in local gateway state store |
| `export-standard` | Experimental | offline | CycloneDX 1.6/1.7 or SPDX 3.0.1 export with typed AI and Dataset projections |
| `audit-control-plane` | Experimental | offline | Hook targets, skill preambles, MCP bridges, steering surfaces, CI agents and identities |
| `trifecta` | Experimental | offline | Lethal trifectas, chained toxic flows and tool shadowing in an inventory |
| `import-sbom` | Experimental | offline | Foreign CycloneDX or SPDX SBOM imported as declared evidence |
| `evidence-profile` | Experimental | offline | Evidence attributes per component, without a scalar trust score |
| `export-policy` | Experimental | offline | Default-deny Cedar, Rego v1 or JSON runtime allowlist from an inventory |
| `discover-mcp` | Experimental | **live** | Opt-in HTTPS MCP tool listing without calling tools |
| `advisories` | Experimental | **live** | Opt-in OSV lookup for exact PyPI and npm package versions |
| `verify-live` | Experimental | **live** | Opt-in namespace-isolated stdio MCP verification against operator launch policy |
