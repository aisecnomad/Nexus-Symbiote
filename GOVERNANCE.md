# Governance

Nexus SymBiote is an alpha project with a single maintainer. This document separates decision ownership from observed enforcement, and states what a single maintainer means for the people who rely on the tool.

## Maintainer and decisions

[Emmanuel Dahunsi (@aisecnomad)](https://github.com/aisecnomad) holds final authority on direction, architecture, dependency changes, merges and releases during alpha. See [MAINTAINERS.md](MAINTAINERS.md) for ownership and responsibilities.

Contributors propose changes through issues and pull requests. The maintainer evaluates scope, compatibility, security consequences and available evidence. Experimental branches do not replace the supported `nexus_symbiote` package on `main`; useful capabilities require explicit, reviewed ports.

## Review expectations

Use the review contract in [CONTRIBUTING.md](CONTRIBUTING.md): explain the concrete problem, resulting behavior, tests and material limitations. Changes should pass the configured `Verified CI` aggregate, quality checks, coverage floors, distribution checks and committed security contracts.

Security-sensitive changes require a stated trust boundary and abuse case, a regression that fails on the vulnerable behavior, and review of the affected security corpus. Record the checks that actually ran and any unavailable verification. Local evidence does not establish a successful hosted matrix or CodeQL run. Any maintainer-authorized alpha exception must state its scope and remaining checks; it must not be described as passing unavailable CI or satisfying inactive protection.

### Review policy while there is one maintainer

No second person reviews changes today. What stands in for that review, and what each part does and does not establish:

- **Required checks.** `Verified CI` must pass on a branch up to date with `main`; branch protection enforces it for everyone, administrators included. It establishes that the gates ran, not that the change is right.
- **Gate integrity.** `scripts/check_workflows.py` fails when a verification job stops running its gate command, when an action pin moves back past its floor, or when a workflow gains a privileged trigger, writable top-level permissions, or a job write scope outside the reviewed list (code-scanning upload, attestation signing, trusted publishing). A change to those files is still self-approved; read such diffs line by line.
- **Soak window.** Behavior- and security-changing pull requests stay open at least 24 hours before merging. Merging is not mechanically held; publication is: the release workflow refuses to publish to PyPI until the release commit has been on `main` for 24 hours, unless the maintainer states an urgent reason that the run log records.
- **Review record.** Each pull request records who reviewed the full rendered diff after CI and how, including whether an AI review ran outside the session that wrote the change.
- **AI-assisted changes.** Most of the history was written with AI assistance, disclosed in commit trailers. They receive the same review as any other change: the maintainer reads the full diff and is accountable for what merges. An assistant's review is a second opinion, not an independent reviewer. See "AI-assisted contributions" in CONTRIBUTING.md.

Adopters who need independent human review of their security tooling should treat this as a limitation: no release so far has had one. The first change once a second maintainer exists is the full branch-protection profile below, which requires their approval.

## Repository controls and current status

### Protection proposal

The checked-in [protection proposal](config/github-main-protection.json) requires `Verified CI`, up-to-date branches, independent review including the last push, code-owner review, resolved conversations, administrator enforcement, and no force pushes or branch deletion. It permits merge commits and does not require linear history. The proposed independent approval requires another authorized reviewer beyond the sole maintainer.

### What is active today

Pull requests are capped at 1,500 changed lines outside `tests/` and `benchmarks/` (CI-enforced; no second person required). Signed commits are requested in [CONTRIBUTING.md](CONTRIBUTING.md#pull-requests). `.github/CODEOWNERS` names the owner of gate paths; it requests review but enforces none under the interim profile.

This file does not apply GitHub settings. The hosted CI and CodeQL failures recorded by the 2026-11-02 audit were subsequently addressed; that historical remediation is not evidence that the latest revision passes. Check the latest trusted CI attempt for the exact source SHA before merging or releasing.

On 2026-11-06 the interim configuration was applied to `main`, the repository ruleset was retargeted to the default branch, and the `testpypi` and `pypi` environments were limited to deployments from `main`, with the sole maintainer as their required reviewer. [Issue #74](https://github.com/aisecnomad/Nexus-Symbiote/issues/74) records the remediation history; remaining administrator actions are tracked in the [roadmap](ROADMAP.md).

### Interim profile

Until a second authorized reviewer exists, applying the full configuration would block the sole maintainer from merging, since GitHub does not count self-approval toward a required review. [`config/github-main-protection-interim.json`](config/github-main-protection-interim.json) drops only the review requirement — `Verified CI` remains enforced for everyone (including administrators), and force pushes and branch deletion remain disabled. Treat it as a temporary floor, not a replacement for the full proposal.

### Publication preflight

The publication preflight checks that the release-tag ruleset is active, that tags cannot move or be deleted, and that the environment's reviewer, branch restriction and administrator bypass are configured. A missing prerequisite blocks the release. GitHub shows who may bypass a ruleset only to an administrator, so the workflow's read-only token cannot check that; before approving a publication, the maintainer runs the [administrator check](docs/repository-controls.md#apply-the-outstanding-controls), which fails unless the bypass list is readable and empty.

### Outstanding administrator actions

Turning the signature requirement on, adding a second code owner, applying the full protection profile, deleting merged branches and enabling automatic deletion of head branches are administrator settings. The commands are in [repository controls](docs/repository-controls.md#administrator-actions-still-outstanding). See [repository controls](docs/repository-controls.md#operator-prerequisites) for the observed state of each control.

Do not claim active merge enforcement from a workflow file, governance statement or local passing suite. Verify live settings and successful checks for the revision being considered.

## Releases

Publication requires an explicit maintainer request. The release procedure separates read-only build and verification from attestation and OIDC publication. Required repository, environment and package-index settings must be configured before publication; the preflight verifies the ones the workflow token can read and fails closed when they are missing or unreadable.

Review the exact candidate artifacts, checksums, source revision and provenance. The production publication preflight requires successful canonical CI evidence for the exact source SHA, protected-branch settings, the release-tag ruleset, a protected environment, the 24-hour soak and the signed release tag on that commit. See [releasing](docs/releasing.md) and [repository controls](docs/repository-controls.md). A candidate build or successful upload does not establish a production release or package safety.

## Continuity

One person is today the only reviewer, release approver, security contact and conduct contact. If that account is unavailable or compromised, nobody else can merge a fix, approve a release, yank a version or answer a report. Until that changes:

- **Security reports** go through GitHub's private vulnerability reporting, which survives a change of maintainer. [SECURITY.md](SECURITY.md#reporting-a-vulnerability) describes a public fallback that discloses nothing.
- **Published versions** stay installable and verifiable without the maintainer: the README's verified install checks the attestation and the tagged lock, not a person.
- **Forking** is the recovery path if the project stops: the MIT license, the hash locks and the release workflow let a successor rebuild and re-attest under their own identity, but not publish under this project's PyPI name.

The maintainer's open actions (no repository change can do these): give a second person administrator access to the repository, add them as a second owner of the `nexus-symbiote` project on PyPI and TestPyPI, record both in MAINTAINERS.md with who can yank a release and publish a fix, give the security and conduct policies a second contact, and keep recovery codes somewhere a successor can reach. Until then, organizations with supplier-continuity requirements should treat the single point of failure as unresolved.

## Future governance

Additional maintainers, architectural RFCs and broader decision processes may be introduced as participation grows. Governance changes follow the same review process, including who owns the decision and which external controls are actually active.

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
