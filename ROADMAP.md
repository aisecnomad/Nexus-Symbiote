# Roadmap

Nexus SymBiote is not related to Symbiote, the Linux malware of the same name reported in 2022.

This is the project's single roadmap. It consolidates the seven external reviews written between
9 and 10 November 2026 ("Road to #1", "Competitive Review and Path to #1", "The path to #1:
consolidated recommendations", "SymBiote Path to #1", "Blueprint to Undisputed #1", "Fixes, moves
and roadmap" and the end-to-end audit of v0.1.0), the owner's release plan of 18 November 2026
("Unified Roadmap to #1", which dates 1.0.0 and splits discovery from proof between
Nexus-ShadowScan and SymBiote) and the [enhancement plan](docs/enhancement-plan-2026-11-18.md)
derived from [AIBOM-Bench](benchmarks/aibom-bench/README.md). Every statement in the three was
checked against `main` at c64451d on 18 November 2026, and what survives is one release train,
0.2.0 to 1.4, in which every item carries a test that can pass or fail.

`main` at 7ca2235f (the merge of #249 on 18 November) carries native format 1.1.0 and package
version 0.2.0, unpublished. AIBOM-Bench (`benchmarks/aibom-bench/`) and the enhancement plan
(`docs/enhancement-plan-2026-11-18.md`) arrive with this page in pull request #267, on top of
`main` at 7ca2235f with `src/` unchanged. Pointers of the form `file:line` are to the tree that
holds this page unless they start with `main:`, and a line can move once a later pull request
lands; the benchmark's own results were produced at a13b622, whose `src/` differs
from `main` in six files (`crosswalk.py`, `generators/_rules.py`, `scanners/ide_agents.py`,
`scanners/mcp.py`, `scanners/mcp_launch.py` and `scanners/prompt.py`), as REPORT.md records.
Source pointers are relative to `src/nexus_symbiote/`; REPORT.md, AUDIT.md, SPEC.md and
`results/` are those of `benchmarks/aibom-bench/`; and `enhancement-plan:N` is line N of the
enhancement plan.

Eight verification passes located every statement of the owner's draft (its plan, scope,
invariants, absorb table, items 1 to 36, chains, proof conditions, risks, decisions and sources) in
the tree and gave each a verdict: holds, partly, wrong or unverifiable. Benchmark counts were
recomputed from the ground truth and score files; source and test sizes are counts from git. The
passes ran nothing from the repository, so a measurement that needs a run says when and where it
was last taken. External facts not read from a primary source are marked secondary or unverified.
The reviews' rankings stay dropped, and AIBOM-Bench's own ranking is cited only as a self-authored,
provisional result ([how first place is proven](#how-first-place-is-proven)).

**Contents.** [the lane](#the-lane) · [where it stands](#where-it-stands) ·
[scope](#scope-shadowscan-finds-symbiote-proves) · [invariants](#invariants) ·
[release train](#release-train) · [contract requirements](#shadowscan-report-contract) ·
[what to absorb](#what-to-absorb-and-from-whom) · [cut order](#cut-order-and-dependencies) ·
[delivered with this roadmap](#delivered-with-this-roadmap) · [acceptance tests](#acceptance-tests) ·
[scorecard](#scorecard) · [decisions and non-goals](#decisions-and-non-goals) ·
[corrections](#corrections-to-the-reviews) · [landscape](#landscape) ·
[risks](#risks-and-watch-items) · [traceability](#traceability)

## The lane

Nexus SymBiote is the **verifiable AgentBOM**: an inventory of what an AI agent is assembled from —
MCP servers and tools, models, instructions and skills, retrieval sources, A2A endpoints, coding-agent
settings, packages and images — in which every claim carries its evidence, every gap is reported,
and every gate fails closed. It reads a project without running it and works offline by default.

The reviews agree on where SymBiote can be first: not as the broadest scanner (cdxgen, Cisco AI BOM,
agent-bom and the companion Nexus-ShadowScan read more surfaces), but as the layer whose claims an
auditor can rely on, which other tools' discovery feeds and which a CI gate can enforce. Every item
in this roadmap is judged by whether it makes that claim stronger:

1. **Airtight evidence.** No gate passes over a change the collectors did not read.
2. **Declared versus actual.** Compare what the repository declares with what the agent reports
   doing at run time, without executing anything.
3. **Verifiable artifacts.** Inventories are reproducible, content-addressed and signed.
4. **Standards-native.** What SymBiote knows reaches the standard fields and frameworks consumers
   already read.
5. **Trust that code cannot supply.** Independent review, a second maintainer, benchmarks others
   can rerun.

On 18 November the owner split the work along that line. Nexus-ShadowScan finds what lives in
source code, data stores and infrastructure; SymBiote reads the agent's control-plane files
itself, imports ShadowScan's findings as declared claims bound to their producer, and builds the
graph, the judgment, the attestations and the gates
([scope](#scope-shadowscan-finds-symbiote-proves)). AIBOM-Bench measured both sides of that line
on two synthetic corpora. SymBiote was the only one of ten tools with zero egress, zero process
creation and no symbolic-link opens (REPORT.md:159-161), and its weighted recall fell from 0.555
to 0.357 on the corpus written from standards and other tools' documentation (AUDIT.md:28).

## Where it stands

Measured at c64451d by counting in git, except where a row names another commit:

| Measure | Value |
| --- | --- |
| Source | 67,776 lines of Python in 98 files under `src/nexus_symbiote` (39,476 in 74 at 3ad53a2; 16,864 in 61 at v0.1.0), about four times v0.1.0 |
| Tests | 4,742 test functions in 295 files (2,507 at 3ad53a2); collected cases not re-counted; the full suite takes about 6 minutes on 4 cores in the hash-locked environment (`make install-locked`, 18 November), and CI runs it with `--strict-skips` (.github/workflows/ci.yml:37-46) |
| Collectors | 8: `mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, `ide_agents`, `shadowscan` (scanner_catalog.py:7-9) |
| Finding categories | 47 (main:docs/finding-catalog.md:45-91), one more than a13b622: `settings_environment` |
| Exports | native JSON (format 1.1.0), CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0, CycloneDX VEX; each validated before it is written (CycloneDX, SPDX and VEX against the vendored official schemas, SARIF by a structural validator) |
| Gates | `scan`, `validate`, `risk`, `diff --fail-on-alert`, the GitHub Action, pre-commit hooks |
| Release | nexus-symbiote 0.1.0 on PyPI since 8 November 2026 through trusted publishing, with PEP 740 publish attestations on both files; pyproject.toml:7 reads 0.2.0, unpublished, and README.md:67 installs v0.1.0 until it is published |
| Open pull requests | 25 on 19 November, #253 to #277, all opened since 18 November: the first-wave pull requests #254, #255, #256, #257, #260, #262 and #263, the owner rename #266, this page's #267 and the test-race fix #274 from one session; #253, #258, #259, #261, #264, #265, #269 and #271 from two Claude Code sessions; #268, #270, #272, #273, #275, #276 and #277 from Antigravity sessions; issue 200 is the merge-coordination ledger of 14 November, where every session records its claims, reviews and merges ([0.2.0](#release-train)) |
| Platforms | Ubuntu qualified (Python 3.11–3.14; SECURITY.md:40); a macOS smoke job outside Verified CI; Windows refused |
| People | one maintainer; no second security contact (SECURITY.md:15); no independent human review of any release (GOVERNANCE.md:19, :27) |
| Time to first inventory | 4.6 s for the bundled demo agent, measured at 3ad53a2 and not re-measured |
| AIBOM-Bench 1.0 | 73.0, grade B, first of ten in a self-authored, provisional run (AUDIT.md:76, :90-92); weighted recall 0.555 on corpus A and 0.357 on corpus B, which read 0.344 before the corpus B correction of 18 November (AUDIT.md:28-31, :129); run on 0.2.0 at a13b622 (REPORT.md:30) |

**Strengths to protect.** All seven strengths the reviews name still hold at 3ad53a2: offline by
default with an audit hook that refuses sockets and process creation; declared, observed and
verified evidence kept distinct; integrity binding (file digests, RFC 8785 tool fingerprints,
SafeTensors header fingerprints, operator signer policy, keyed source binding); drift gating that
compares every field by default; A2A 0.3 and 1.0 security schemes, coding-agent permissions and MCP
launcher identity; signed runtime contracts for a reference gateway; and release discipline (hash
locks, CodeQL, trusted publishing, a 24-hour soak before publication).

AIBOM-Bench checked the same strengths from outside on 18 November: byte-identical repeats with
`SOURCE_DATE_EPOCH` honored and a run-independent content digest (REPORT.md:147-148), failures
and limits recorded inside the inventory, valid CycloneDX 1.7, SPDX 3.0.1, SARIF and VEX, the only
G7 minimum-elements report among the ten tools, and attested releases (REPORT.md:159-167).

**What the 3ad53a2 remediation already closed.** The v0.1.0 audit and the reviews were written
against v0.1.0. Since then, collection reads Claude Code hooks, deny and ask rules, `apiKeyHelper`,
subagents, skill scripts, nested `CLAUDE.md` and `AGENTS.md`, `.github/instructions`,
`.cursor/rules` and eleven MCP client files; MCP launchers behind wrappers are classified or become
a high finding and a gap; inventories record root-relative paths, so the same project gives the same
inventory at any checkout path; collection limits are operator settings; every gate prints its
reasons; CI log commands cannot be forged through inventory text; GGUF chat templates that reach
Python internals are critical; and 23 of the 44 finding categories have a SARIF rule of their own,
19 of them with CWE or OWASP tags.

**What still undermined the central claim** (reproduced at 3ad53a2, closed by the 12 November roadmap's
change, D1, unless stated): marker-only IDE settings files (`.cursor/cli.json` widened from `Shell(ls)` to `Shell(*)`)
and Codex settings other than three keys passed `diff --fail-on-alert`; hidden text in unassigned
default-ignorable code points produced no finding; MCP servers in `.js`, `.mjs`, `.cjs`, `.mts`,
`.cts` and `.tsx` files, servers launched from application code and agent files inside directories
named `venv` or `node_modules` left no coverage gap; the ShadowScan bridge still maps 3 of
ShadowScan's 18 finding kinds (open); and ShadowScan refuses the native inventory SymBiote writes, so
an approved SymBiote inventory cannot become ShadowScan's approved list.

**What `main` closed after 3ad53a2.** #131 treats as unknown launchers the shell startup code that
can replace a pinned MCP runner (`--rcfile` and `--init-file`, exported bash functions, a relative
or `/proc` `BASH_ENV`, `ENV` with an interactive shell, `PS4` expansions while tracing) and bounds
launch-argument expansion in time and memory. #132 closes four P0 findings of a separate audit:
SEC-F1 (a ShadowScan import records its producer verification in the inventory, and unverified
discovery evidence fails `import-shadowscan`, `validate` and `risk` in CI unless explicitly
allowed), SEC-C1 (offline Sigstore verification checks the cached trust root before trusting it, or
uses an explicit, optionally pinned one), ARCH-F1 (deterministic output: no wall-clock timestamp,
components and dependencies sorted, a content-derived serial number) and DOC-F3/F7 (stale roadmap
and repository-controls rows). #133 binds each `risk.suppressions` entry to the fingerprint of the
finding it accepted, so a changed finding counts again. #134 treats more package installs
(`pip3.12`, `gem i`, `pip install` after options) as unknown launchers, reads `cmd /c` quoting as
`cmd` does, and redacts a token inside a name and an MCP server or tool name that is a token. #135
makes the prompt collector's import lookups the operator limit `import-lookups`, keeps a refused
file distinct from an absent one past the failure listing bound, and reads a native document without
a `metadata` object as format 1.0.0 everywhere. #136 makes the workflow gate checks structural and
requires the publishing environment to admit only `main` and the PyPI soak to start from a push run.
#137 verifies the cached Sigstore trust root from the bytes that were checked, closing the window in
which a same-user process could replace it between the check and the load.

**What `main` closed on 18 November.** #247 (a13b622) and #251 (c64451d) merged batches B1 and
B2b of the audit of 16 November. On `main`, Claude Code `statusLine` and `fileSuggestion` commands
are rated as hook commands are, a credential helper takes the severity its command would give a
hook, settings `env` that redirects the API endpoint or loads code is a high or medium
`settings_environment` finding, every file under `.claude/hooks` and `.cursor/hooks` is bound by
digest, and `npx` and `npm exec` arguments are read by a port of npm 10.9.9's own handling
(main:CHANGELOG.md:9-12, :20).

**What still undermines the claim** (AIBOM-Bench, 18 November). SymBiote reads the agent surface it
documents and little else. On the corpus written from standards and other tools' documentation its
weighted recall fell to 0.357 (AUDIT.md:28); models were 0 of 13 on corpus A and 1 of 12 on corpus
B, datasets 0 of 6 and 0 of 4, and training runs, guardrails and CI agents were missed on both
corpora ([scope](#scope-shadowscan-finds-symbiote-proves)). A zero-filled `.bin` is rated critical
by its name alone (scanners/model.py:969-970), which fails the default gate. Names reach the
standard exports with control characters escaped rather than neutralized
(benchmarks/aibom-bench/results/nexus-symbiote/cyclonedx/bom.cdx.json:1052). The same symbolic-link failure is recorded
once per walking collector (enhancement-plan:127). No tool, SymBiote included, flagged the poisoned
tool descriptions (REPORT.md:105-109). The ShadowScan bridge maps 3 of 18 kinds and binds no commit
(scanners/shadowscan.py:54; docs/shadowscan-integration.md:297-302).

## Scope: ShadowScan finds, SymBiote proves

The owner decided on 18 November 2026 that new discovery lives in Nexus-ShadowScan and that
SymBiote turns what is found into evidence anyone can check. The decision extends the routing the
12 November roadmap recorded for containers, infrastructure as code, workflows and frameworks
("through ShadowScan and imports, not new collectors") to all discovery in source code, data
stores and infrastructure. It removes nothing SymBiote's collectors already read: the `mcp`, `rag`
and `a2a` collectors keep searching source code for SDK references (README.md:182), and the
inventory keeps the tool definitions of Python decorators and TypeScript MCP servers
(REPORT.md:164-166).

| What | Owner | How it reaches the inventory |
| --- | --- | --- |
| Agent control-plane files: MCP client configurations, skills, subagents, hooks, IDE settings and permissions, instruction files, A2A cards | SymBiote | Read directly by the existing collectors, never executed |
| MCP servers and tools in code, SDK references, weight files, declared retrieval configuration, root manifests and lockfiles, catalog images | SymBiote (kept) | The `mcp`, `model`, `rag`, `registry` and `a2a` collectors as today |
| Agents, hosted models, inline prompts and provider-hosted tools in source code; CI workflows; datasets, training pipelines and notebooks; containers, Kubernetes and infrastructure as code; data stores outside declared retrieval configuration | ShadowScan | A signed report, imported as declared claims bound to its producer (R1.0.0-rc.1-2) and shaped by the [contract requirements](#shadowscan-report-contract) |
| Graph, judgment, attestation and gates | SymBiote | Built here |

An import never raises assurance. Imported components are declared with unknown trust
(docs/shadowscan-integration.md:59), and a passing producer check authenticates the producer, not
its findings (docs/shadowscan-integration.md:293-295). The report's repository and commit are
recorded as unknown today because the report format carries neither
(docs/shadowscan-integration.md:297-302).

The pair is scored per ground-truth class of AIBOM-Bench 1.0. SPEC.md has no pair mode, so until
it gains one the pair figure is SymBiote's own detections plus those of an imported ShadowScan
report, scored by `score.py` after the import (R0.3.0-1). ShadowScan has not run on either corpus:
`results/` holds no ShadowScan output. The owner's draft gave a baseline from "AIBOM-Bench v1.1"
(models 0 of 16, agents 0 of 2, AI infrastructure 1 of 7, data and retrieval 1 of 9) and pair
targets of 13 of 16, 2 of 2, 7 of 7 and 7 of 9. Those counts are not reproducible from the tree:
it holds AIBOM-Bench 1.0 (`ground_truth.json` version 1.0, `ground_truth_b.json` version 1.0-b),
no class has 16 items, no `agent` class exists, and neither grouping is defined. The tree's own
counts follow, recomputed from both ground truths and both score files; pair targets are set per
class once ShadowScan has run on both corpora.

| Ground-truth class | Corpus A | Corpus B | Owner under the split | Target |
| --- | --- | --- | --- | --- |
| model | 0 of 13 | 1 of 12 | ShadowScan (CR-1, CR-2) | Set after ShadowScan's first run; the plan's SymBiote-side target was recall of 0.65 or more on A (enhancement-plan:153) |
| model-file | 5 of 6 | 4 of 5 | SymBiote (`model`) | Hold |
| mcp-server | 7 of 10 | 4 of 6 | SymBiote (`mcp`) | `mcp.zed-fetch` and `mcp.continue-slack` found on B (R0.2.0-3) |
| tool | 3 of 3 | 2 of 3 | SymBiote for MCP tools; ShadowScan for provider-hosted tools (CR-3) | Hold on A; B set after the first run |
| prompt | 9 of 14 | 2 of 7 | SymBiote for files (R0.2.0-5); ShadowScan for inline prompts (CR-5) | Every file-based item in 0.3.0; 0.85 on both corpora once CR-5 lands (enhancement-plan:159) |
| skill | 2 of 2 | none planted | SymBiote | Hold |
| agent-config | 1 of 3 | 0 of 2 | SymBiote for settings and hooks (R0.3.0-2, R1.1-3); ShadowScan for n8n and Assistants exports (CR-9) | `ide.hook-pretooluse` and `ide.permission-webfetch` on A |
| a2a | 1 of 1 | none planted | SymBiote | Hold |
| ci-agent | 0 of 1 | 0 of 1 | ShadowScan reads workflows (CR-7); SymBiote rates them (R1.1-7) | Set after the first run |
| package | 5 of 6 | 3 of 5 | SymBiote at the root; manifests below it in R1.2-2 | Set with R1.2-2 |
| container | 2 of 4 | 0 of 3 | SymBiote for catalog images; ShadowScan for every other image (CR-8) | 0.85 was the plan's target (enhancement-plan:155) |
| vector-store | 3 of 3 (2 of 3 by `rag-source` records) | 1 of 2 (0 of 2 by `rag-source` records) | SymBiote (`rag`) | Set with R1.3-6, from the `rag-source` counts: the tree's labels credit `rag.qdrant` from the container image and `rag.weaviate` from the npm package (AUDIT.md, corrections of 19 November) |
| dataset | 0 of 6 | 0 of 4 | ShadowScan (CR-4) | 0.85 was the plan's target (enhancement-plan:165) |
| training | 0 of 2 | 0 of 2 | ShadowScan (CR-4) | As dataset |
| guardrail | 0 of 2 | 0 of 1 | SymBiote for declared configuration (`rag`, R1.3-6); ShadowScan for Terraform (CR-9) | `guard.config` and `eval.promptfoo` on B; `guard.bedrock-guardrail` through CR-9 |

Corpus B's mcp-server class held 7 items until its Cline item was removed on 18 November
(AUDIT.md:110-113); the counts above are after that correction.
Three of SymBiote's credits come from a record of another type under the tree's own labels:
`rag.qdrant` from the image `qdrant/qdrant:v1.12.1`, `rag.weaviate` from the package
`weaviate-client`, and the soft item `prompt.relocated-claude-md` from the scan-failure line that
names the case variant. Counted by records of the item's own type the totals are 36 of 76 and
16 of 53, and the vector-store row is 2 of 3 and 0 of 2; a floor for the `rag` collector is set
from those.

## Invariants

Eleven rules hold in every release, and a feature that cannot be built inside them is not built.
The owner's draft said a CI test enforces each one; the tree shows something narrower. Rules 2, 6,
7 and 10 have named tests that CI runs, rules 1, 4, 8 and 9 are enforced by the suite with the
gaps listed, and rules 3, 5 (lines and offsets) and 11 are targets whose tests the named items
add. 1.0.0 goes out only when every row has a passing test.

| # | Rule | Proof in CI today | Still open, and the item that closes it |
| --- | --- | --- | --- |
| 1 | Never execute what is scanned | Every static command runs under the offline guard (tests/test_modes.py:298-331), which refuses `os.system`, `fork`, `forkpty`, `posix_spawn` and `execv` (modes.py:52-60; tests/test_modes.py:648-679); every collector on a hostile checkout whose stdio launch is `touch <marker>` leaves no marker (tests/test_modes.py:706-744); a PreToolUse hook is read as data (tests/test_ide_settings_binding.py:510-519); a weaponized pickle is rated without resolving its globals (tests/test_integrity_security.py:176-179) | The guard is a Python-level tripwire that native code bypasses (modes.py:10-17), and no CI step counts processes. `setup.py` is not a read surface (docs/known-limitations.md:989); a `.pth` file is read as a PyTorch model (scanners/model.py:78), so a hostile one is a valid read-without-execute fixture. Native-parser isolation is a decision in R1.0.0-1 |
| 2 | Offline by default | Offline is the default (modes.py:3-8); the suite fails any test that resolves or connects off loopback (tests/conftest.py:213-319); static commands stay offline even with `--live` (tests/test_modes.py:257-268) | The tripwire covers neither subprocesses nor native code (tests/conftest.py:6-7), and CI runs with ordinary network (.github/workflows/ci.yml:14-46). R1.0.0-1 adds a job that runs the suite with no network |
| 3 | No LLM in the core path | No test names the rule. Runtime dependencies and extras hold no model client (pyproject.toml:53-80), and LLM classification is not planned ([decisions](#decisions-and-non-goals)) | R1.0.0-rc.1-1 adds an allow-list test over the wheel's `Requires-Dist` and requirements-action.lock |
| 4 | Unknown is never clean | An exceeded limit is a named failure with exit 1 (tests/test_collection_limits.py:127-135); a failed or unselected collector never claims completeness (tests/test_coverage_security.py:11-40); partial coverage never passes `risk` (tests/test_security_assurance.py:167-216); an unverified format is an unknown issue that never passes `validate` under the default policy (validators/integrity.py:107-120; policy.py:141-142) | No mode is named "strict policy"; the rule holds under the default policy. A pickle-family name is critical before its content is read (R0.2.0-2); the TypeScript deadline is a time bound (R0.3.0-3); what no collector reads passes every gate (SECURITY.md:54; R1.2-2) |
| 5 | Every claim carries assurance and evidence | Assurance, method and scope are required on every claim (core/models.py:83-92); only cryptographic verification sets `verified` (core/evidence.py:76-80, :129; tests/test_security_assurance.py:27; tests/test_shadowscan_discovery_verification.py:498); imports round-trip without a trust upgrade (tests/test_export_conformance.py:269) | The locator is optional and no line or offset field exists (core/models.py:83-92). Lines arrive with R1.0.0-rc.1-2 (`line` and `key_path` on claims, native 1.3.0) and R1.0.0-rc.1-3 (`evidence.occurrences[].line`) |
| 6 | Secrets by name, never by value | Planted AWS, GitHub, OpenAI-project and bearer values reach no export (tests/test_secret_name_redaction.py:82-86, :173-189; tests/test_static_export_redaction.py:197-238); the `credential_export` control runs in CI and in the release (.github/workflows/ci.yml:208-211; .github/workflows/release.yml:99-100); Action log lines are neutralized (scripts/run_action.py:71-105) | No Anthropic-shaped `sk-ant-` value is planted (grep: none); the generic `sk-` shape covers it (utils/secrets.py:101-105). Rshipped-4 adds the fixture |
| 7 | Output is deterministic | Two CLI scans are byte-identical as written, with no time recorded (tests/test_determinism.py:97-102, :236-247); every format is byte-identical across two checkouts with `SOURCE_DATE_EPOCH`, which SPDX needs for its creation time (tests/test_reproducible_inventory.py:443-455) | Nothing needs masking. The TypeScript analysis deadline is the one time dependence left (scanners/ts_tools.py:370-389; R0.3.0-3) |
| 8 | Exports are valid and lossless | CycloneDX 1.7, SPDX 3.0.1 and VEX validate offline against vendored, digest-checked schemas (tests/test_export_validation.py:149-153, :196-199, :222-236); both standard exports recover the native document exactly and fail closed when its extension is altered (tests/test_export_conformance.py:88-106, :208, :401-414) | SARIF is validated structurally and is one-way (generators/validation.py:428-435; R1.0.0-rc.1-4); the standard fields alone carry two edge kinds (generators/cyclonedx.py:148-156; R1.0.0-rc.1-3) |
| 9 | Policy lives outside what it judges | The Action refuses a signer policy inside the workspace or reached through a link, and snapshots it (scripts/run_action.py:135-161; tests/test_action_signature_policy.py:58-92); it passes `--no-project-policy` to `scan`, `validate` and `risk` (scripts/run_action.py:595, :671, :702); the CLI refuses a weakening checkout policy in CI (tests/test_project_policy_ci_gate.py:47-57) | No workflow of this repository stages policy from the base ref (.github/workflows/ci.yml:154-160 uses it for the size check only; R1.0.0-2). A signed operator policy is R1.1-6. The workflow file itself is protected by rulesets and code-owner review, not by SymBiote (SECURITY.md:58) |
| 10 | Runtime is opt-in and unprivileged | Live commands refuse to run offline (tests/test_modes.py:199-205); a static scan never calls live discovery (tests/test_live_cli.py:31-40); pinned stdio will not start without its unprivileged user and PID namespace (live/pinned_process.py:286-310; tests/test_pinned_process_isolation.py:166) | Nothing. The namespace needs a kernel that allows unprivileged user namespaces (live/pinned_process.py:289-290) |
| 11 | No rule without fixtures | 22 committed cases in 7 kinds, each gated against its label (benchmarks/manifest.json; scripts/check_security_regressions.py:13-45; .github/workflows/ci.yml:208-211) | 47 finding categories on `main` against those 7 kinds. R0.3.0-1 adds a positive and a negative case per category and a test that iterates the catalog |

<a id="plan"></a>

## Release train

The train replaces the Now, Next and Later plan of 12 November; [traceability](#traceability)
maps every N, X and L id, every enhancement-plan item and gap, and every item of the owner's draft
to its row here. Every item keeps the [principles](docs/security-model.md#design-principles):
nothing executes what it inventories, nothing reaches the network unless the operator asks, and
an import or report never raises assurance. Severity names a gate: the CLI's built-in gate fails
on critical and the Action's default `fail-on-severity` is high (action.yml), so a finding kept at
high still fails the Action unless the operator lowers that input; a Done when that depends on it
says which gate it means.

The dates of 1.0.0 (31 January 2027) and of the depth releases, every two months to 30 September
2027, are the owner's. The draft's text does not date 0.2.0, 0.3.0 or 1.0.0-rc.1; their dates here
follow the decision due dates and the two-week soak the candidate needs before 1.0.0. Load is
counted in maintainer-weeks against one maintainer. In each table, Build says what changes, Done
when is the test that passes, and Sources name the draft items, the 12 November ids and the plan
ids the row absorbs; Status says Delivered, Partial, Open or In progress, with its evidence.

### Shipped

| # | Item | Build | Done when | Sources | Status |
| --- | --- | --- | --- | --- | --- |
| Rshipped-1 | Control-plane files read directly, never executed: MCP, skills, subagents, hooks, IDE settings and permissions, instruction files, A2A | Nothing new; the offline guard and confined reads stay the only read path | tests/test_modes.py:298-331 (every static command under the guard) and :706-744 (a hostile checkout leaves no marker) keep passing | draft scope row 3, product row, invariant 1; D1, D10 | Delivered. Eight collectors (scanner_catalog.py:7-9); nothing a collector reads is executed, imported or loaded (README.md:182; SECURITY.md:36); on `main` every file under `.claude/hooks` and `.cursor/hooks` is bound by digest as well (main:CHANGELOG.md:12) |
| Rshipped-2 | Deterministic, reproducible inventories | Nothing; no time is recorded by default, and `SOURCE_DATE_EPOCH` fixes the creation time SPDX requires | tests/test_determinism.py:236-247 and tests/test_reproducible_inventory.py:443-455 pass | draft invariant 7, absorb row AIROM; D2 | Delivered. AIBOM-Bench found the output byte-identical, honoring `SOURCE_DATE_EPOCH`, with a run-independent content digest (REPORT.md:147-148) |
| Rshipped-3 | Inventory attestation and offline Sigstore verification under a pinned trust root | Nothing; the CLI keeps operator-held keys for air-gapped use | A one-byte change fails `verify-attestation`, which matches bytes by default (attestation.py:3-5; attestation_cli.py:213-256) | draft 11 (its delivered half), absorb row cdxgen; D3 | Delivered. DSSE envelopes over in-toto Statements signed by 1 to 32 Ed25519 keys (attestation.py:1-5, :349); an explicit, optionally SHA-256-pinned trust root (utils/crypto.py:91-92, :732-757) |
| Rshipped-4 | Secrets by name, never by value | One `sk-ant-` fixture, so that every vendor the invariant names is planted | The `credential_export` control passes in CI (.github/workflows/ci.yml:208-211) and the new value reaches no export | draft invariant 6 | Delivered, one fixture short. AWS, GitHub, OpenAI-project and bearer values are planted and redacted (tests/test_secret_name_redaction.py:82-86; tests/test_redaction_union.py:370-389; tests/test_static_export_redaction.py:197-238); no `sk-ant-` string exists in tests or src (grep) |
| Rshipped-5 | Runtime opt-in and unprivileged | Nothing | tests/test_modes.py:199-205, :257-268 and tests/test_pinned_process_isolation.py:166 pass | draft invariant 10 | Delivered. Three live commands behind `--live` (modes.py:36-41); pinned stdio under `unshare --user --map-root-user --pid` (live/pinned_process.py:286-310) |
| Rshipped-6 | G7 minimum-element coverage with its denominator | Nothing; raising the present count is R1.0.0-rc.1-3 and R1.3-4 | The demo output in docs/minimum-elements.md:243-300 reproduces (11 of 39 assessable elements present) | draft 31, absorb rows Pitloom and OWASP AIBOM Generator; D6 | Delivered. Coverage per element and cluster with `fail_under`, never a score (minimum_elements.py:1651-1667, :1691-1733); the only G7 report among the ten tools graded (REPORT.md:134) |
| Rshipped-7 | Recorded decisions, with the scope split of 18 November | The split as a decision; every draft item that met a recorded decision is reworded in this train | No row below contradicts [decisions and non-goals](#decisions-and-non-goals) | draft scope, team row, plug-into line; the decisions of 12 November | Recorded in this revision ([decisions](#decisions-and-non-goals)) |
| Rshipped-8 | `trace-diff`, the framework crosswalk, the graph view and blast radius, the ShadowScan simple-list export, the positioning line | Nothing; R1.4-1, R1.4-4 and R1.3-3 extend them | Their tests and walk-throughs keep passing | D4, D5, D7, D8, D9 | Delivered with the 12 November roadmap ([delivered](#delivered-with-this-roadmap)); `trace-diff` is trace_cli.py, the crosswalk crosswalk_cli.py, and `blast-radius` returns declared principals (graph.py:697-699) |

### 0.2.0, 27 November 2026

0.2.0 ships after the seven first-wave branches below have merged, each under the 1,500-line cap
(CONTRIBUTING.md:93) and after the 24-hour soak (GOVERNANCE.md:23), and after the canonical owner
has become the aisecnomad account (R0.2.0-8), as the owner decided on 18 November. The branches
are written and were reviewed adversarially before they were pushed; what remains is the
maintainer's review of each rendered diff after Verified CI, the merges one at a time with `main`
brought into each, the owner rename, and the publication steps of R0.2.0-1: about one and a half
maintainer-weeks in 1.3. If the soak pushes the date, 0.2.0 slips rather than dropping a branch.

| # | Item | Build | Done when | Sources | Status |
| --- | --- | --- | --- | --- | --- |
| R0.2.0-1 | Publish 0.2.0 from `main` through the existing trusted-publishing and attestation pipeline | Apply both release-tag rulesets (config/github-release-tag-ruleset.json, config/github-release-tag-creation-ruleset.json) and turn off administrator bypass on the `testpypi` and `pypi` environments, recording the date; date the changelog heading at upload (docs/releasing.md:198); move the README's verified install to v0.2.0; add the Scorecard badge, register for the Best Practices badge and publish the v0.1.0 audit under docs/audits/; publish from the aisecnomad account once R0.2.0-8 has merged | `scripts/check_repository_controls.py --verify-bypass-actors` passes and is recorded; the README's `gh attestation verify ... --deny-self-hosted-runners` block succeeds against the 0.2.0 wheel | draft 1, release row; N7; plan OQ6, pull-request sequencing, P3.7 (badges) | Partial. The pipeline exists and published 0.1.0 (.github/workflows/release.yml:182-301; docs/repository-controls.md:248); the rulesets are not recorded as applied (docs/repository-controls.md:249; CHANGELOG.md:58) and administrator bypass is still on (docs/repository-controls.md:247); pyproject.toml:7 is 0.2.0, unpublished |
| R0.2.0-2 | Pickle evidence before a critical rating | Inspect content before trusting the suffix: a pickle-family name with no opcode, object-dtype or ZIP-pickle evidence in the inspected prefix is `serialization_format_unknown` (high), and the evidence text is recorded on the component (the `serialization_evidence` field and its re-derivation in `risk` follow in R0.3.0-4); recognised opcode streams and unreadable files stay critical | AIBOM-Bench `decoy.zero-bin-as-model` is no longer reported (its pattern counts a code-execution, unsafe-loader or pickle claim, not `serialization_format_unknown`); F04 is still raised on `intent.pkl` and `intent.pt`; GGUF content under a pickle-family name stays critical, as llama.cpp opens a model by its magic and the chat-template check runs only under a `.gguf` name; a `.pt` with no PROTO opcode in its first 64 KiB rates high, while `.pkl.gz` and other wrapped names and ZIP or NumPy files whose directories exceed the inspection bound stay critical; the relief applies to the CLI gate, since the Action fails on high by default | plan P0.1, OQ3, criterion D6 6.11; draft invariant 4; X4 (first slice) | In review as #254 (`claude/laughing-hawking-5f9x78-pickle-evidence`; full suite green on the pushed head; no native field, no format bump). Today a pickle-family suffix is critical before content is read (scanners/model.py:969-970), which charged the soft decoy (results/scores.json, `decoy.zero-bin-as-model`). Independent review of 18 November: GGUF content named `.bin` or `.pt` had dropped to `unknown` where `main` rated it critical by name and a `.gguf` name inspects its chat template; the branch keeps it critical with the evidence `Potential code-executing loader format (GGUF content under a pickle-family name; its chat templates are not inspected under this name)`, and records the one-time `diff` and `validate --project` cost of the new evidence text in docs/fingerprint-migration.md |
| R0.2.0-3 | MCP client dialects: Zed, Continue (file and directory), opencode, Junie | Promote the four recognised but unparsed dialects to `MCP_DIALECTS` (scanners/mcp.py:108-128), Continue's docker launcher through `mcp_launch`, each unknown shape a gap; a one-file reader for `.cursor/environment.json` | `mcp.zed-fetch` and `mcp.continue-slack` are found on corpus B; pin 2025.4.7 is captured; F01 is raised for `mcp/slack:latest`; an SSE entry in a Zed or Continue file is read with transport `sse` in the unit tests (corpus B's only SSE endpoint was the Cline item the benchmark audit removed, so F08 has no location there) | plan P0.2, bootstrap-manifest salvage | In review as #256 (`claude/laughing-hawking-5f9x78-mcp-client-dialects`; full suite green but for one load-sensitive process-isolation test that passes alone; the `.cursor/environment.json` reader is not on it). The four files are listed as unparsed (scanners/mcp.py:398-405); mcp-server 4 of 6 on corpus B. Acceptance run of 18 November (ledger, 21:51 UTC): `mcp.zed-fetch` with pin 2025.4.7 and `mcp.continue-slack` with a high `version_pinning` are found on corpus B |
| R0.2.0-4 | Identifier hygiene and hidden-character offsets | (a) Neutralize component names, descriptions and suppliers at collection and record `name_neutralized`, keeping the raw bytes only as a digest-bound property; (b) report control, format and mixed-script characters in tool and server names; (c) name TypeScript and Python servers from the `McpServer({name})` or `FastMCP(name=)` literal, with package.json `name` as `registered-as`; (d) a recorded decision on directional marks in right-to-left prose, a medium finding today. The line and byte offsets on claims move to R1.0.0-rc.1-2 with the other 1.3.0 fields, and the benign twin per hidden-character class to R0.3.0-1 | A regression fixture names the TypeScript server `analytics-mcp`; every JSON export passes a `jq -r` round trip with no control bytes | draft 4; plan P0.5, JSON-escape finding, criterion D4 4.6 | In review as #260 (`claude/laughing-hawking-5f9x78-identifier-hygiene`, a and b: names, descriptions and suppliers neutralized at `merge_collected`, a new high category `identifier_characters` with the raw-value digest in the finding, no `name_neutralized` property) and #262 (`claude/laughing-hawking-5f9x78-server-constructor-names`, c); both suites green on the pushed heads. Detection by category and range, with emoji exemptions, already exists (scanners/prompt.py:60-77, :223-231); names reach exports unneutralized (benchmarks/aibom-bench/results/nexus-symbiote/cyclonedx/bom.cdx.json:1052); findings carry counts, not offsets (scanners/prompt.py:353-409); lookalike letters are not detected (docs/known-limitations.md:837-839) |
| R0.2.0-5 | Prompt surfaces in files | `prompts/` at any depth, `*.prompt.md`, `*.prompt.yaml` and `*.prompt.yml` join the `prompt` collector (`llms.txt` stays unread and is documented as such) with the same hidden-character checks; inline prompts in source code arrive through CR-5 | Every file-based prompt item of both corpora is found; prompt recall reaches 0.85 on both once CR-5 lands (enhancement-plan:159) | plan P0.6 (file half) | In review as #263 (`claude/laughing-hawking-5f9x78-prompt-surfaces`; full suite green on the pushed head; prompt templates recorded after the instruction and skill walks claim their files; binary files under a `prompts` directory are not failures). prompt 9 of 14 on A, 2 of 7 on B |
| R0.2.0-6 | Failures reported once, depth 64, same-definition relation | Group scan failures by path and reason with the collectors listed, in `risk`, `validate` and the Action, keeping `scanner_status` per collector; depth default 64 (limits.py:138); the report says when a failure comes from an escaping link | `risk` prints one coverage line naming six collectors on corpus A instead of six lines; `mcp.deep-nested` (depth 40) is found at default limits | plan P0.7, OQ4, the duplicate and depth findings | In review as #257 (`claude/laughing-hawking-5f9x78-failure-report-depth`; full suite green on the pushed head; the `same-definition` relation and the server merge follow in R0.3.0-4). Corpus A records 22 scan failures from five causes (enhancement-plan:127); failing on escaping links stays decided ([decisions](#decisions-and-non-goals)) |
| R0.2.0-7 | Credential exposure finding | When `secrets.redact_*` fires in a position already read (MCP env values, headers and arguments; root `.env` key names follow in R0.3.0-4), raise `credential_exposure` (high) with file and pattern class, withholding a token-shaped key name and advising rotation; register it in `_rules.py`, `crosswalk.py` (LLM02:2025, ASI03, CWE-798) and docs/finding-catalog.md together | F03 is full on both corpora; the `credential_export` control still finds no sentinel in native, CycloneDX, SPDX or SARIF output; a benign redacted value raises nothing | draft 5, absorb row agent-bom; plan P1.4, notebook-output salvage | In review as #255 (`claude/laughing-hawking-5f9x78-credential-exposure`; full suite green on the pushed head; the review removed an unbounded recursion in the classifier). Values are redacted, not raised (scanners/mcp.py:1851-1880); only URL userinfo is a finding, `transport_security` (main:docs/finding-catalog.md:90); F03 scored half (REPORT.md:308) |
| R0.2.0-8 | Canonical owner: the aisecnomad account | Point `pyproject.toml` project URLs (from which scripts/check_repository_hygiene.py derives the canonical owner), the README's absolute links and badges, every docs page outside docs/audits/, the Action `uses:` examples, CITATION.cff, the issue-template chooser and the SARIF `informationUri` at the aisecnomad account; keep `tool_vendor` (already `aisecnomad`, core/models.py:703), the inventory attestation predicate type and the native schema id unchanged, because they are identifiers that existing verifiers and documents depend on, and say so in CHANGELOG.md; leave docs/audits/ and the committed benchmark results as the historical record they are; merge last in 0.2.0, since it touches 53 tracked files that the other branches also touch in places | `python scripts/check_repository_hygiene.py` passes with the new canonical owner and no stale slug; `gh attestation verify` of the 0.2.0 wheel succeeds with the new `--repo`; the README's verified-install block names the new owner | decided 18 November; plan OQ6; the enhancement plan's documentation finding | In review as #266 (`claude/laughing-hawking-5f9x78-canonical-owner`): 27 files outside tests change; the inventory attestation predicate type, the schema id and the v0.1.0 signer arguments stay as identifiers; the model-integrity documentation link is part of the inventory, so inventories with such a finding change digest once (docs/fingerprint-migration.md). Before it, 269 references outside docs/audits in 53 tracked files named the previous organization (git grep, 18 November); the hygiene check enforces whichever owner `pyproject.toml` names (scripts/check_repository_hygiene.py:204-213) |

### 0.3.0, 18 December 2026

Turn what is already read into findings and gates: the regression corpus with a precision gate,
settings as security events and the determinism residue. About three maintainer-weeks in three,
now that the first wave sits in 0.2.0. Native format 1.2.0 ships here with the first new fields
(R0.3.0-4; enhancement-plan:233-249), and every reviewed baseline needs one re-baselining, as 0.1.0
inventories did (SECURITY.md:59). The cut order reaches 0.3.0 at rank 5: R0.3.0-2 and R0.3.0-3
slide whole to 1.1, by the owner's call.

| # | Item | Build | Done when | Sources | Status |
| --- | --- | --- | --- | --- | --- |
| R0.3.0-1 | Regression corpus and precision gate | Keep the exact per-case gate; add `model_drift` and `a2a_scope_drift` kinds; map every remaining known limitation to a fixture; one positive case and one negative control per finding category, checked by a test that iterates the catalog; a `make precision` target that runs `score.py` on both ground truths and fails when a class recall drops below its recorded floor (today's values, not 0.98 and 0.95); the fixtures the plan's new criteria need | CI fails when a committed case differs from its label (true today) or a class recall falls below its floor; a test asserts every category has a true and a false case; the corpus fails if either drift alert disappears | draft 2, invariant 11, pair table, sources, absorb row Cisco AI BOM; N9; plan test strategy, fixtures, finding catalog, criteria, OQ10, P3.7 (accuracy regression) | Partial. 22 cases in 7 kinds (benchmarks/manifest.json) gated per case (scripts/check_security_regressions.py:13-45; .github/workflows/ci.yml:208-211); 47 categories on `main`; no `make precision` target (enhancement-plan:320) and no `benchmark` command (cli.py, grep) |
| R0.3.0-2 | Settings as security events | Per-tool `human_in_the_loop` from allow, ask and deny precedence, `alwaysAllow` arrays, subagent, command and skill front matter and Codex `approval_policy`, `unknown` for unmodelled hosts; `oversight_gap` (high) for a destructive tool resolved `auto`; an `activation` scope with a scope-widened alert; named alerts when a deny rule disappears or `sandbox.network.allowedDomains` widens; `subagent_inline_mcp_server`; a recorded severity for plain hook commands and credential helpers; the model named in `.codex/config.toml` (`model.codex-o4-mini` on corpus A), a control-plane model reference that the pair baseline of 18 November shows no ShadowScan report supplies | `mcp__github__delete_repo` in an allow list resolves `auto` and raises `oversight_gap` (the plan's new criterion F17; the benchmark's F14, permissive permissions, is raised by the same precedence); a removed deny rule fails `diff --fail-on-alert` with a named alert; a committed PreToolUse hook and an `apiKeyHelper` each raise a named finding at the recorded severity | draft 3; plan P1.5, gaps 3 and 26, the ledger, effective-context and egress salvages; reopens the 12 November tool-permission decision | Partial. Hooks, credential helpers, MCP auto-approval and unscoped grants are rated (main:docs/finding-catalog.md:53, :60, :70, :76); a plain hook command or `apiKeyHelper` is medium, below the Action's default `fail-on-severity: high` (main:CHANGELOG.md:9, :142); `human_in_the_loop` is never set (core/models.py:159) |
| R0.3.0-3 | Determinism residue and keyed drift | Replace the TypeScript parse and analysis deadlines with proportional node budgets, or record a deadline refusal as a named collection limit; bound export work; decide whether an Action scan without `source-binding-key` fails instead of warning; `diff --expect-upgrade FROM_VERSION` from a static list per release, with a row in docs/fingerprint-migration.md | Both determinism suites stay byte-identical; a crafted project whose SPDX export runs for hours stops at a named limit; a changed MCP env value fails the Action without a key, or warns, as decided; an unchanged fixture rerun under 0.3.0 with `--expect-upgrade 0.2.0` yields only tool-change alerts | draft 6, absorb row AIROM; plan gap 18, P2.8 (upgrade attribution), migration requirement, the refuted deadline proposal | Partial. Limits bound size, not time (SECURITY.md:60; limits.py has no time entry); the deadlines sit at scanners/ts_tools.py:88-91, :370-389; without the key the Action warns (scripts/run_action.py:495-506) and `diff` cannot see a changed value (SECURITY.md:55) |
| R0.3.0-4 | First-wave remainders and native format 1.2.0 | `serialization_evidence` as a component field that `risk` re-derives; `name_neutralized` and the raw-value digest as properties; an informational `same-definition` relation between tools with one `definition_hash` from different sources, and one server per launcher purl and version with two configuration claims; `credential_exposure` over root `.env` key names; the native schema regenerated under NATIVE_SPEC_VERSION 1.2.0 with its row in docs/fingerprint-migration.md and the differ's security-field list updated | Criterion 3.4 reaches 4 (the two `filesystem` servers are one); tests/test_native_contract.py passes at 1.2.0; a 0.2.0 inventory still loads and `diff` names the format difference | plan P0.1, P0.5, P0.7 and P1.4 (their remainders), the schema-versioning and migration requirements | Open. The first-wave branches carry the ratings, findings and reports without a native field (none bumps NATIVE_SPEC_VERSION, core/models.py:38) |

### 1.0.0-rc.1, 15 January 2027

The contract. About five maintainer-weeks in four, across the holidays, which is close to the
owner's estimate because rank 5 sends R0.3.0-2 and R0.3.0-3 to 1.1 rather than here. R1.0.0-rc.1-1, -2, -4 and -5 do
not slip (the draft's items 7, 8, 10 and 11). Their halves that depend on other people, ShadowScan's
report fields and the taxonomy registration, are tracked here and cannot be forced. R1.0.0-rc.1-3
is cut rank 3.

| # | Item | Build | Done when | Sources | Status |
| --- | --- | --- | --- | --- | --- |
| R1.0.0-rc.1-1 | Native format contract (owner: both): the schema 1.0 label, exit codes and the supported surface | Freeze native format 1.x under the schema 1.0 label once the 1.2.0 fields of 0.3.0 and this release's 1.3.0 fields (`line` and `key_path` on claims and the new imported kinds; the hosted model fields `provider`, `requested_alias` and `resolved_revision` already exist in 1.1.0, core/models.py:310-316) are in; later fields are additive minors under the reader rule (schemas/README.md), and removals or changes of meaning need 2.0; a CI test that records the native schema's digest per format version; an allow-list test over the wheel's `Requires-Dist` and requirements-action.lock; one exit-code decision ([decision 4](#open-decisions)), with the step summary and the junit and markdown formats; the N8 table of every command and collector, supported or experimental ([decision 2](#open-decisions)). "ShadowScan reads v1" is a dependency on Nexus-ShadowScan, not a gate of this release | Regenerating the native schema without a version bump fails tests/test_native_contract.py; the exit-code matrix of docs/cli-reference.md is tested; a component named with Markdown and a workflow command renders inert in a `GITHUB_STEP_SUMMARY` fixture; a test keeps GOVERNANCE.md, the README and docs/cli-reference.md listing the same commands | draft 7, decisions 1, 2 and 4, the plan's 1.0 lines, invariants 3 and 5, risk "the date"; N8, L3 (format half); plan P1.9, OQ5, OQ8, OQ9, schema versioning, scope cost | Partial. The format is versioned and the schema kept equal to the model (core/models.py:38-41; tests/test_native_contract.py:19-23, :335-345), but a changed schema under an unchanged version passes; no supported-surface statement exists (GOVERNANCE.md); exit 1 folds a failed gate, unreadable input and an internal error together (docs/cli-reference.md:136-140) |
| R1.0.0-rc.1-2 | ShadowScan import v1 (owner: both) | Map `framework-usage` and `agent-config` (projection profile v5), then the kinds the [contract requirements](#shadowscan-report-contract) define, every other kind an explicit gap; compare the report's repository, commit and run time with the checkout and record the binding; carry `line` and `key_path` on claims and export them; hosted model fields (`provider`, `requested_alias`, `resolved_revision`) with `version_pinning` medium for an undated alias and high for `revision="main"`, re-derived from the imported claims; readable names when the producer verifies. An imported claim stays declared; only a SymBiote collector that reads the artifact records observed evidence, and a cited file and line is a locator, never a promotion | SymBiote's half: a ShadowScan code report from an agent-framework repository imports with no unmapped entries, and a report naming another commit fails `validate --project` once CR-0 carries the commit. ShadowScan's half, on its own dates: with ShadowScan's report imported, model recall on corpus A reaches the pair target and the comment and README model decoys stay unreported; F12 is raised for cardiffnlp's `revision="main"` | draft 8, decision 3, scope rows 1 and 2, risk "the seam", absorb row AIROM (file and line); N3; plan P0.3, OQ1, OQ2, the ShadowScan projection finding | Partial. The import verifies its producer (scanners/shadowscan.py:232-272; SECURITY.md:32), and unverified evidence fails in CI unless allowed (cli.py:355-367); 3 of 18 kinds map (scanners/shadowscan.py:54); repository and commit are `unknown` (docs/shadowscan-integration.md:297-302); names are hashes (scanners/shadowscan.py:342) |
| R1.0.0-rc.1-3 | Typed graph in the standard fields: CycloneDX projection 3 and SPDX `spdx-3.0.1/4`, cut once | Project `uses-model`, `delegates-to`, `retrieves-from`, `loads-skill`, `trained-on`, `fine-tuned-from`, `quantized-from` and `merged-from` where the formats have fields; remote MCP and A2A servers as `services`; launcher purls; model licenses and a minimal `modelCard` from local model-card front matter, as declared evidence; `pedigree.ancestors`, `evidence.identity[]`, `evidence.occurrences[].line`, `externalReferences` and coverage `annotations`; `--spec-version 1.6`; projection 2 kept for recovery | Of the relationship kinds a scan emits, at least 8 of 10 planted edges are typed in standard fields without the extension; criterion 4.1 reaches 4; the G7 model-license, model-properties and model-external-references elements are present on the demo; cyclonedx-python-lib alone recovers MCP services and model licenses; both projections validate | draft 9, chain A; N4; plan P1.8, the CycloneDX standards gaps | Partial. 19 typed native relationships (core/aibom.py:46-66) recover exactly through the embedded document (tests/test_standard_only_consumer.py:309-316), but CycloneDX carries only `depends-on` and `provides-tool` (generators/cyclonedx.py:140-156) and SPDX six kinds (generators/spdx.py:404-428); impact already walks every edge backward (graph.py:672-716) |
| R1.0.0-rc.1-4 | Validated, registered exports (owner: both) | Vendor the OASIS SARIF 2.1.0 schema with a digest check and validate against it in tests; file the `nexus-symbiote` and `agentbom` namespaces with the CycloneDX property taxonomy, an upstream task that cannot gate this release | An invalid SARIF document fails the suite; the recovery tests (tests/test_export_conformance.py:88-106, :401-414) stay green; docs/standard-exports.md records the taxonomy pull request | draft 10, invariant 8; N10; plan's unregistered-namespace finding | Partial. CycloneDX, SPDX and VEX validate against vendored schemas, SARIF only structurally (generators/validation.py:428-435); properties are versioned by `nexus-symbiote:projection` (generators/cyclonedx.py:54; generators/spdx.py:54-55), and no `symbiote:v1:*` name exists (grep); the namespaces are unregistered (docs/standard-exports.md:58) |
| R1.0.0-rc.1-5 | Attestation enforced in the gates, keyless provenance in the Action | `validate` and `risk` accept `--require-attestation ENVELOPE` with operator-held keys and fail closed on a missing, altered, wrongly purposed or unsigned inventory; an Action input for a reviewed-baseline attestation; an optional `attest: true` with a pinned `actions/attest-build-provenance` step and an `aibom-digest` output. Ed25519 DSSE stays the air-gapped path; the CLI does not sign keylessly | An unsigned or altered baseline fails `validate` under the CI policy and a signed one names its signer; a third party verifies the Action's inventory with `gh attestation verify` from a clean machine | draft 11, scope row 4, chain C; N1, N2 | Open. `attest` and `verify-attestation` ship (Rshipped-3), but no gate requires them; utils/crypto.py signs nothing and refuses DSSE bundles (utils/crypto.py:36-40) |

### 1.0.0, 31 January 2027

The stability promise. About three maintainer-weeks in 2.3, so about one week over; cut ranks 1
and 2 apply first. 1.0.0 goes out when 1.0.0-rc.1 has run two weeks with no schema change and
every invariant has a passing CI test. Nothing in it widens collection beyond control-plane files.

| # | Item | Build | Done when | Sources | Status |
| --- | --- | --- | --- | --- | --- |
| R1.0.0-1 | Parser hardening | A Hypothesis property for each reader without one (TypeScript through tree-sitter, YAML, TOML, JSONC, GGUF and SafeTensors headers, the ECMA-262 pattern translator); a coverage-guided harness over every parser entry point beside the weekly profile; the randomized profile run before a release candidate; a CI job that runs the suite with no network, so invariant 2's proof becomes a deny rather than a tripwire; a recorded decision on isolating tree-sitter. A worker process would need an exception to the offline guard's refusal of process creation (modes.py:3-4), on which invariant 1's proof rests, so the recommended answer keeps the size, node and time bounds and the advice to scan untrusted repositories in an isolated worker (docs/threat-model.md, "Code execution") | The release workflow runs the profile and the harness with no crash or hang before 1.0.0 is tagged; a test checks a maintained reader list against the property modules; a CI job runs the full suite with no network; the decision and its threat-model row are recorded | draft 12, invariants 1 and 2, absorb row AIROM (fuzzing); plan P3.7 (fuzz half), threat-model rows | Partial. Properties exist (tests/test_parser_properties.py:1-12), and a weekly randomized profile with 2,000 examples runs outside Verified CI (.github/workflows/dependencies.yml:11, :127-147; tests/conftest.py:108-114); no coverage-guided harness exists; tree-sitter parses in-process (scanners/ts_tools.py:22-24; SECURITY.md:38) |
| R1.0.0-2 | Release and response controls that code can close | `scanners/`, `validators/` and `generators/` on the CODEOWNERS second-reviewer list, so the control switches on when a second maintainer exists; a job in this repository that stages the signer policy and the reviewed baseline from the pull request's base commit, as docs/drift-gate.md documents for callers; a fully offline `--bundle` verification recipe; one best-effort target in SECURITY.md until a second contact can honour tiers | .github/CODEOWNERS names the three directories; a test pull request that weakens the checkout policy still fails the staged job; the offline recipe is reproduced without `gh auth login` | draft 13, invariant 9, risk response "human review on detectors" | Partial. Every published artifact carries provenance and verifies in one command (docs/releasing.md:171-175, :187-196); no job stages policy from the base ref (.github/workflows/ci.yml:154-160); detectors are not on the second-reviewer list (CONTRIBUTING.md:93); SECURITY.md:13 states one best-effort target |
| R1.0.0-3 | Docs for the supported surface | Write the N8 table decided in R1.0.0-rc.1-1 into GOVERNANCE.md and the README; keep every gate reason and state the cap of 15 findings, with `--json-output` for the rest; time the README's 60-second block and the public-agent tutorial from a clean machine, saying whether installation is included; re-run every documented command | A test keeps the status table equal to the command list; the docs record both measured times; the README demo output matches after 1.0.0 | draft 14; plan documentation requirement, OQ7 | Partial. The quick start (README.md:41-123), the collector reference (docs/collectors.md:1-20), the threat model and the tutorial exist; every gate prints all its reasons (reporting.py:92-110) and caps findings at 15 (reporting.py:26); nothing has timed the tutorial |

### 1.1, judgment, 31 March 2027

The depth releases add native fields only as minor versions under the frozen major, and none
removes a 1.0 field or changes its meaning. New discovery in source code, data stores and
infrastructure arrives through the ShadowScan import; SymBiote's own collectors deepen the
surfaces they already own.

| # | Item | Build | Done when | Sources | Status |
| --- | --- | --- | --- | --- | --- |
| R1.1-1 | Lethal-trifecta paths with stable ids | An `untrusted-input` class from recorded evidence; (input, read, egress) triples over existing edges; path ids stable across runs and checkout renames; `path_added` and `path_unattended` diff alerts at high, raisable by policy; three related SARIF locations. A leak possible only by chaining two tools is one path | A fetch tool, a CRM tool and a WebFetch allow rule give one path whose id is stable across two runs; removing a leg removes it; the gated twin raises nothing; F15 is full | draft 15 and 24, absorb row Snyk Agent Scan (toxic flows); plan P2.1, gap 1 | Open. Risk classes are per component (risk_classes.py:30-36) and paths run from an agent to one sink (graph_view.py:398-447); there is one inferred agent per repository (graph.py:337-440) |
| R1.1-2 | Deterministic text rule pack | Versioned lexical rules, no LLM, over tool and schema descriptions, SKILL.md bodies, agent-card skills and assistant instructions; `tool_description_poisoning` and `instruction_injection` at high with rule id and offset, text withheld; the component set and the digest never change on text; the Sidenote salvage | F05 is raised on both corpora; a floor fixture of benign descriptions, a ticket-lookup tool among them, raises nothing | draft 16, absorb row Snyk Agent Scan (taxonomy); plan P1.3, Sidenote salvage | Open. Tool text is hashed and redacted, never judged (scanners/mcp.py:3156-3176, :3198-3230); no tool flagged the planted poisoning (REPORT.md:105-109); the verified prior art is agent-bom's rules (enhancement-plan:33) |
| R1.1-3 | Hook, skill-preamble and launcher-target binding | Resolve hook commands outside `.claude/hooks` and `.cursor/hooks`, skill `!` preamble lines and in-project launcher targets (`node ./server.js`) through confined reads; a `launch_target` digest whose change is a critical alert, and `invokes` edges; static body classification (egress, settings writes, `permissionDecision: allow`); `skill_shell_preamble` (high); gaps otherwise; nothing runs | The corpus hook `./scripts/audit-tool-call.sh` becomes a digest-bound component with an `invokes` edge; editing `server.js` fails `diff`; a fetching preamble raises `skill_shell_preamble`; a hook script that writes `permissionDecision: allow` raises its own finding (the plan's F19); a clean extraction script raises nothing | draft 17, absorb row Snyk Agent Scan (skills); plan P1.6, gaps 4 and 13 | Partial. Skill resources are bound by digest (scanners/prompt.py:660-661, :1296-1302), and on `main` so is every file under `.claude/hooks` and `.cursor/hooks` (main:CHANGELOG.md:12); other commands are rated by their text, not resolved; launcher targets are not hashed (docs/known-limitations.md:132, :142) |
| R1.1-4 | Model forensics depth | Pickle-family files checked against an allow-list of safe globals, without loading, with the resolved global and byte offset in the finding; GGUF `general.*` keys beyond the architecture under an allow-list; loader-safety binding as triage precision on imported claims (CR-10) | A pickle importing `os.system` is reported with its opcode evidence, global and offset; the GGUF template and ONNX external-path cases stay as they are; nothing is loaded | draft 18, absorb rows aisbom and Pitloom; X4 (opcode half); plan loader-safety salvage | Partial. Opcode streams are rated without loading (scanners/model.py:389-450), GGUF templates reaching Python internals are critical (:1158-1170) and ONNX external data is confined to the model directory (:1398-1428); findings name the file only (:2467-2474) |
| R1.1-5 | Second maintainer and second security contact (owner: other people) | Name a co-maintainer and a second security contact (decision 5 asks for both before 1.0.0-rc.1, so earlier if someone is found); apply config/github-main-protection.json; add a second owner on the organization and on PyPI; adopt tiered targets only once someone can honour them | Two people have merged and released; SECURITY.md names a second contact; no backup row of MAINTAINERS.md reads "None yet"; branch protection requires the second maintainer's approval; no detector or parser change merges on an assistant's review alone (draft 19) | draft 13 (the second contact) and 19, decision 5, risk "one maintainer"; L3 (people half) | Open. GOVERNANCE.md:19, :27, :55; MAINTAINERS.md:26-35; SECURITY.md:15 |
| R1.1-6 | Signed operator policy outside the checkout | `--operator-policy FILE` under the placement rules of signature_policy.py, with an optional DSSE purpose `policy`; a project policy may only narrow it; the policy's digest and signer in the inventory, the `risk` JSON, SARIF and the verdict | A pull request raising `max_risk_score` in the checkout still fails under the operator policy, and the verdict names the policy digest | draft invariant 9; plan P2.5, gap 15 | Open. `policy_source` is built-in or project only (core/models.py:706-713); SECURITY.md:58 |
| R1.1-7 | CI agents and provider-hosted tools from imported claims (owner: both) | From CR-3 and CR-7 claims, `hosted-tool` components with provider, approval mode, server origin and token presence by name; ide-agent components with host `github-actions:<action>`; findings `hosted_mcp_auto_approved`, `hosted_mcp_token_literal`, `provider_code_execution`, `ci_agent_skip_permissions`, `ci_agent_untrusted_trigger` and `ci_agent_action_unpinned`; inline `mcp_config` JSON through the dialect parser; hosted tools as CycloneDX services | `ci.claude-code-action` and `ci.codex-action` are found with ShadowScan's report imported; F16 and F18 are raised | plan P1.2, P1.7, gaps 6 and 7 | Open. No workflow reader exists (enhancement-plan:85); provider-hosted tools are invisible to every tool graded (enhancement-plan:84) |
| R1.1-8 | Per-component evidence profile | Show for each component which evidence it has (pinned, digest-bound, signed under policy, observed by a collector, reported at run time, findings), never a single trust score | `graph` and `risk --json-output` show for each component the evidence it lacks | X9 | Open. Risk classes ship (D7), and no per-component evidence profile exists (grep over src: none); the TrustScore decision stands ([decisions](#decisions-and-non-goals)) |
| R1.1-9 | Integrity that means what it says, and input binding | A re-hash of the checkout an inventory was just built from no longer counts as verified integrity; operator digest pins verify any model format; a per-file SHA-256 at the confined-read chokepoint and a `read_set_root` in metadata and the attestation only, never in the content digest, after re-evaluating the retired Merkle experiment; unread-by-reason counts per collector; the fleet census deferred | An MCP-only repository does not move from unknown to passing integrity by adding an instruction file; `validate --project` fails when the recomputed root differs; the root leaves the content digest unchanged | N12; plan P3.2, gaps 22 and 23, read-set salvage | Open. A re-hash of the checkout just collected still moves integrity from unknown to passing (docs/known-limitations.md:1328-1334) |
| R1.1-10 | Instruction change record | `diff-instructions BASE_TREE HEAD_TREE` through confined reads: a block-level CommonMark diff with the classes `tool_grant_changed`, `import_added`, `url_or_path_added`, `hidden_markup_added` and `scope_widened`; text withheld unless `--show-text`, every line redacted and neutralized | Widening `.mdc` globs raises `scope_widened`; adding a URL raises `url_or_path_added`; a reworded sentence raises nothing | plan P3.3, gap 14 | Open. A changed instruction file is a digest change only (diff/differ.py:712-726) |

### 1.2, exploitability, 31 May 2027

| # | Item | Build | Done when | Sources | Status |
| --- | --- | --- | --- | --- | --- |
| R1.2-1 | Advisory snapshot with provenance | An operator-supplied OSV, KEV and EPSS snapshot read offline, with its digest and date recorded as `reported` provenance; exact pins of AI-related packages only; OSV `aliases` collapsed; a KEV listing raises a finding's severity with its source named in `risk`, SARIF and VEX; no embedded CVE database | A planted, exactly pinned vulnerable `transformers` is matched from a snapshot with the suite's network tripwire on; two advisories sharing an alias appear once; a KEV-listed package raises severity and shows the snapshot date | draft 20, chain B, absorb row Dependency-Track (KEV); X6 | Open. `advisories` is a live OSV query over exact identities (advisories.py:1-16, :36, :51-54), deduplicated per id with no alias handling (:363-365); a CVE database is a non-goal |
| R1.2-2 | SBOM import and fidelity | Import any CycloneDX or SPDX BOM as declared evidence, with per-document and per-entry digests, hashed names by default, local binding only on matching digests, and `source_conflict`, never a winner; manifests below the root (package.json, requirements files, pyproject.toml, setup.cfg, go.mod, Cargo.toml, conda environment.yml, .devcontainer), the registry collector becoming a walking collector with the symbolic-link consequence documented, an exception to the split recorded in [decisions](#decisions-and-non-goals) because manifests are dependency identity SymBiote owns at the root, not AI discovery; `pinning_state` per server and ecosystem; an unread-shape census in `completeness.unread_shapes[]`, advisory by default | Merging a cdxgen SBOM into the demo yields valid CycloneDX 1.7 with every conflict listed and a stable content digest; corpus B reports `.ipynb`, `n8n/*.json` and `*.tf` as unread with counts; a manifest-only project exports `pinning_state: manifest-only`; the nested `mcp-server/package.json` is found | draft 21, absorb row cdxgen (fidelity); X1; plan P0.4 (manifests), P2.8, gap 17, cross-artifact salvage, starter tasks | Partial. Exports never claim complete coverage (generators/_common.py:252-264); no command imports a foreign BOM (cli.py:1026 is `import-shadowscan`); the registry collector reads the root only (docs/collectors.md, registry row) |
| R1.2-3 | Exposure paths, reach-rated alerts and agent identity (owner: both) | Reachability tiers reuse the assurance ladder (declared; reported through `trace-diff`; observed through `verify-live`) and an import never raises them; diff alerts gain a stable id, root cause, affected refs from `blast_radius` and reach-rated routing, so one upgrade that severs four paths is one alert; an agent component per imported framework constructor (CR-6) with `uses-model` and `provides-tool` edges; `filesystem_paths`, `egress_domains` and `registry_source` filled from control-plane sources | One changed shared skill gives one alert with five affected refs; corpus agents carry their own identity and R1.1-1 computes paths per agent | draft 22, absorb row agent-bom (chain); plan gap 11, P2.4 (alerts), P2.10, reserved-fields finding | Partial. `blast_radius` has one tier and `effective_authority: unknown` (graph.py:672-718); `diff` never consults it (enhancement-plan:89); every agent is the inferred repository agent (graph.py:432) |
| R1.2-4 | Operator decisions and VEX states | `vex --decisions FILE` outside the checkout records `not_affected`, `exploitable` and `resolved` with justification, owner and expiry; `--advisories REPORT` links snapshot results; expiring expected-change declarations for the drift gate; one decisions format with three sections beside the fingerprint-bound suppressions; an "invoked" justification cites `reported` or `observed` evidence and changes no assurance; no `not_affected` from absence | Declared-never-loaded, invoked (with a trace fixture) and operator-resolved fixtures give three VEX states with reasons; an expired decision reverts to `in_triage` with a warning; a declared addition passes `diff --fail-on-alert` and an undeclared one fails | draft 23, absorb row Dependency-Track (VEX); N5; plan P2.4, gap 10 | Open. Every statement is `in_triage` (generators/vex.py:9-11, :96), already scoped to its component (:109) |
| R1.2-5 | Independent benchmark round (owner: other people) | A named third party writes corpus C, keeps it sealed until the run and then publishes it with its manifest; every tool runs in its supported mode; results record the corpus manifest digest, the tool commit, the runner and the affiliation; until then AIBOM-Bench's rank is cited as provisional and no first place is claimed | A public results page by the third party records corpus C's digest, the Nexus release tag and its attestation, the runner and the affiliation; `make precision` reproduces the Nexus numbers from that corpus | draft 25, decision 6, the first-place conditions and rule; L4 | Open. Both corpora have one author, who also wrote the harness (AUDIT.md:90-92) |

### 1.3, provenance, 31 July 2027

| # | Item | Build | Done when | Sources | Status |
| --- | --- | --- | --- | --- | --- |
| R1.3-1 | OpenSSF Model Signing and model-card signatures | Verify OMS DSSE bundles and signed model cards under the operator signer policy, promoting to verified only on a cryptographic success | An OMS-signed model verifies offline; a tampered or unsigned one keeps its high `signing_status` finding and an unknown integrity issue under the default policy | draft 26; X4 (OMS half) | Partial. Weight-file Sigstore signatures and digest pins verify (scanners/model.py:1800-1814; validators/integrity.py:837-850); DSSE bundles are refused (utils/crypto.py:37-40) |
| R1.3-2 | MCP 2026-07-28 and an approved-descriptor registry | Read the primary changelog first; then the stateless flow without initialize, `Mcp-Method` headers, `deprecated_transport` for SSE, RFC 9728 metadata and `openWorldHint` and `idempotentHint` with the specification's defaults; `verify-models` as a live command with the controls of `discover-mcp`; `approve-descriptors` writing a signed registry keyed by purl and version or by image digest | A fixture matrix covers 2026-07-28, 2025-11-25 and 2025-06-18, and a changed description, a new tool and a removed tool each exit 1 on each; benchmark criteria 8.1 and 8.2 re-score as verified; a changed description under an unchanged version raises high | draft 27, risk "specification churn"; plan P2.9, P3.2 (descriptor registry), gap 16, protocol deltas | Partial. The drift gate and `verify-live` already fail on those three changes (diff/differ.py:668-691; live/verify.py:110-111, :191) for 2024-11-05 to 2025-11-25 (scanners/live_mcp.py:66) |
| R1.3-3 | Identity and authority inventory | Declared SPIFFE IDs and delegation edges; an identity component type for OAuth grants and for service identities imported from ShadowScan; blast radius over identities; declared writers per steering file and `steering_surface_writable` (critical for settings, hooks and MCP configurations), classified before redaction | `blast-radius` from a compromised tool lists the identities it can act as; a filesystem server rooted at `.` beside `acceptEdits` raises `steering_surface_writable` (the plan's F20), and a read-only mount or a deny rule clears it | draft 28; X3; plan P2.2, gap 2 | Partial. `blast-radius` lists declared principals with `effective_authority: unknown` (graph.py:697-699, :712); MCP env is recorded by name only (core/models.py:249) |
| R1.3-4 | SPDX AI profiles, producer declarations and consumer interoperability | agent.yaml 1.1 with `models[].training`, `datasets[]`, `licenses`, `owner`, `data_usage` and `compliance` as declared claims, and `declaration_conflict`; ISO/IEC 22989 automation names with one mapping table to SymBiote's L0 to L4 and ShadowScan's 0 to 5; the SPDX AI and Dataset profiles claimed only when every mandatory field is collected; SHACL validation; report-only jobs into a pinned Dependency-Track and GUAC with a defined carrier for findings; an `--author` option; CycloneDX 2.0 and the AgBOM mapping once others act | The SPDX export claims the AI profile and passes SHACL on a fully declared demo; the minimum-elements present count rises with the denominator unchanged; the Dependency-Track job records its version and shows modelCard, services and findings on their components; the autonomy table is tested against both enumerations | draft 29; N6, X7, X8, L1, L2; plan P2.7, gap 9, the SPDX and minimum-elements gaps | Open. The profiles are not claimed (generators/spdx.py:1-9, :317-322); no workflow loads an export into Dependency-Track or GUAC (grep over .github/workflows: none) |
| R1.3-5 | Alias indirection, registry references and licenses | Alias and target model components linked by `routes-to` from imported LiteLLM, vLLM and Modelfile claims (CR-2), with `model_alias_mutable` and `model_alias_retargeted`; MLflow `models:/x/Production`, `runs:/`, W&B and Hugging Face cache references classified as pinned or floating, whether SymBiote reads them in configuration or CR-4 reports them (one home for them); no retirement catalog unless a sourced one exists | Corpus B `k8s/vllm.yaml` and a LiteLLM configuration give linked components; `configs/mlflow.yaml` raises `floating_registry_reference`; a 40-hex revision raises nothing | draft 30, absorb row AIROM (retirement); plan P2.6, gaps 8 and 20 | Partial. `trust_remote_code: true` is already critical (scanners/model.py:2538-2544); launcher pins are recorded (core/models.py:257-260); licenses are never collected (enhancement-plan:63) |
| R1.3-6 | Guardrail, memory and retrieval provenance | The `rag` collector reads declared guardrail configuration into GuardrailComponent with `config_hash`; memory store declarations; retrieval lineage from the declared configuration the `rag` collector already reads (datasets and training in source code are CR-4); `data[].classification` and `pii_data_reaches_exposed_agent` over existing edges | A changed guardrail policy file is a high drift alert; `guard.config` and `eval.promptfoo` are found on corpus B; `guard.bedrock-guardrail` lives in Terraform and arrives through CR-9 | X5; plan P1.10 (guardrail half), gap 25 | Open. GuardrailComponent and MemoryStoreComponent exist and nothing fills them (core/models.py:381-416); guardrail 0 of 2 on A, 0 of 1 on B |
| R1.3-7 | Platforms and distribution | The full suite on macOS in Verified CI; a recorded Windows decision, failing closed by design; a container image from the hash-locked environment with its own attestation | The platforms workflow runs the full macOS suite as a required check; SECURITY.md states the Windows decision; `gh attestation verify` succeeds on the image digest | draft 32, absorb row AIROM (binaries); L6; plan P3.7 (image) | Partial. Wheels carry PEP 740 attestations (.github/workflows/release.yml:193-231, :298-301); macOS has a smoke job only (.github/workflows/platforms.yml:22-24); confinement needs POSIX primitives (SECURITY.md:40) |

### 1.4, runtime, 30 September 2027

| # | Item | Build | Done when | Sources | Status |
| --- | --- | --- | --- | --- | --- |
| R1.4-1 | Reference gateway records and more runtime evidence | A signed decision-record schema and a built-in sink for `on_decision`; a listing-time descriptor check in the reference adapter; k8s-aibom ML-BOMs and gateway records as `reported` sources for `trace-diff`; graph overlays of trace evidence; `trace-diff --record-resolutions` with `resolved_model_changed`; sampling and elicitation counts per endpoint; an MCP server mode for approved inventories after N8 | The refusal of a changed descriptor, which the gateway already does (runtime.py:1955-1986), produces a signed decision record that verifies and that the built-in sink retains; two OTLP fixtures with different `gen_ai.response.model` for one alias raise `resolved_model_changed`; an undeclared cluster image is reported | draft 33, absorb row agent-bom (proxy); X2, L7; plan P3.5, gap 21, trace salvage | Partial. The gateway refuses a changed served descriptor at call time (runtime.py:157, :1955-1986); its decision records are unsigned and unretained (enhancement-plan:70); a production MCP firewall stays a non-goal |
| R1.4-2 | Training-lineage ingestion | in-toto, SLSA and dataset attestations as declared evidence after X1; DataSourceComponent and a `training-run` component with `trained-on`, `fine-tuned-from` and `produces` edges from imported claims (CR-4); `.dvc` md5 values and local data digests verified against local bytes; `floating_dataset_revision`, `lineage_unpinned` and `lineage_conflict` | An attested fixture links a model to a dataset digest at declared assurance; an unsigned manifest stays declared; corpus A's pin 1c4513b2 in YAML beside unpinned code raises `lineage_unpinned` | draft 34, absorb row AIBoMGen and Project AIBOM; L5; plan P1.1, P3.4, gaps 19 and 24 | Open. The edges are defined (core/aibom.py:53-56) and mapped in SPDX (generators/spdx.py:413-419), but no collector emits them; dataset 0 of 6 on A, 0 of 4 on B |
| R1.4-3 | Bridges and registry resolution | A reviewed catalogue of bridge packages (`npx mcp-remote https://...`) whose URL argument becomes `endpoint_url` with transport `stdio-bridged`; in-root configurations through the dialect parser with `delegates-to` edges; `proxied_servers_unresolved` otherwise; a floating `npx` spec resolved only in live mode, as `reported` evidence; no typosquat heuristic | An `mcp-remote` entry raises `endpoint_identity` and `transport_security` (F21 for `http://`); in live mode a floating spec records its resolved version; a non-default registry is recorded by origin without a heuristic finding | draft 35, absorb row agent-bom (pre-install); plan P2.3, gap 5 | Partial. Launch specs are classified (scanners/mcp_launch.py:516-573), and a purl exists only for an exact pin (generators/package_identifiers.py:44-49); typosquat detection stays declined |
| R1.4-4 | Evidence packages, crosswalk breadth and admission | One command bundling the attested inventory, the crosswalk and the minimum-elements report, listing every framework entry no finding references as "no evidence"; crosswalk breadth from vendored, hash-pinned primary sources with a drift test; `data_residency` against agent.yaml `allowed_regions`; a gate-verdict attestation with image and content digest subjects in an offline OCI referrer layout; the documented JSON contract for OPA or Cedar, with example policies | Each mapped control links to its evidence and unmapped controls appear as gaps, never as passes; a Kyverno audit-mode recipe validates against the demo; the example policies pass and fail their fixtures in CI; the drift test fails when a pinned source changes | draft 36; X10; plan P3.1, P3.6, gap 12, the data-recipient and subject-keyed salvages | Partial. The crosswalk never states that a control is met (crosswalk.py:27-33) but omits entries no finding references (crosswalk_cli.py:93-95); attestations cover inventories only (attestation.py:71-73) |

## ShadowScan report contract

The owner's draft names the contract between the two tools AgentBOM v1 and asks ShadowScan to emit
signed reports in it (decision 3). In this roadmap the name covers only what ShadowScan's signed
report must carry for SymBiote to import it as evidence. It is not the retired AgentBOM 0.1
format, whose emission was declined ([decisions](#decisions-and-non-goals)), and it is not
SymBiote's native format, whose stability label is schema 1.0 (R1.0.0-rc.1-1). The contract runs
one way, from report to inventory; the other way is ShadowScan's simple list (D8). ShadowScan's
half of each row is on ShadowScan's dates, and SymBiote's half is the item in the last column.

| # | ShadowScan's signed report carries | Why SymBiote needs it | Sources | SymBiote side |
| --- | --- | --- | --- | --- |
| CR-0 | The repository URL, the commit SHA, the run's start and finish, the producer identity, a Sigstore bundle over the exact report bytes, a report format version and a fixed kind list; per finding its kind, root-relative path, line, byte offset and a stable source id, all at declared assurance | Repository and commit are recorded as `unknown` today because the report carries neither (scanners/shadowscan.py:210-229), and projected names are hashes (scanners/shadowscan.py:342) | draft 8, decision 3; N3 | R1.0.0-rc.1-2 |
| CR-1 | Model identifiers in code and configuration: provider, requested alias, a 40-hex resolved revision when present, the call or key that binds it (`model=`, `from_pretrained`, `pipeline`, YAML `base_model`, `model` or `embedding_model`), file and line; comments and docstrings excluded by construction; Go SDK shapes included | Models are 0 of 13 on A and 1 of 12 on B, and `version_pinning` and the hosted model fields re-derive from these values | plan P0.3; the draft's model row | R1.0.0-rc.1-2 |
| CR-2 | Alias indirection: LiteLLM `model_list`, vLLM `--served-model-name`, Modelfile `FROM`, with alias, target, file and line | `routes-to` edges and the alias alerts | plan gap 8, P2.6 | R1.3-5 |
| CR-3 | Provider-hosted tools in model API calls: provider, tool type, `require_approval`, server origin and token presence by name, never the value, with file and line | Provider-hosted tools are invisible to every tool graded (enhancement-plan:84) | plan P1.7, gap 6; draft 5 (tokens in application code) | R1.1-7 |
| CR-4 | Dataset and training references: `load_dataset` with its revision, `.dvc` path and md5, fine-tune base model and revision, pipeline references (MLflow, W&B, Kubeflow), notebook code cells with outputs never read, config.json `_name_or_path`, the adapter base and model-card `base_model`, each with file and line | Datasets are 0 of 6 and 0 of 4, training runs 0 of 2 on both corpora | plan P1.1, gaps 19 and 24; draft 34 | R1.4-2 |
| CR-5 | Inline prompts: digest, declaration line and the binding position (a module constant passed to a client call, TypeScript `instructions:`, Modelfile `SYSTEM`, Assistants `instructions`), never the text | A third of corpus B's prompt class is inline (enhancement-plan:159) | plan P0.6 (inline half) | R0.2.0-5 |
| CR-6 | Agent constructors: framework (LangGraph, CrewAI, AutoGen, pydantic-ai, OpenAI Agents SDK), name, bound model and tools, file and line | Every corpus agent is the inferred repository agent (graph.py:432) | plan P2.10; draft 22 | R1.2-3 |
| CR-7 | CI agent grants from workflows: the action and its pin state, `allowed_tools`, inline `mcp_config` verbatim, `--dangerously-skip-permissions` and similar flags, the trigger, job permissions and environment credential names | Workflows were routed through ShadowScan on 12 November; ci-agent is 0 of 1 on both corpora | plan P1.2, gap 7 | R1.1-7 |
| CR-8 | Images: every Dockerfile and Containerfile `FROM` and `COPY --from` at any depth, Kubernetes `containers[].image` and `args --model`, Helm charts recorded as unread, each with pin state, file and line; notebook outputs with credential shapes reported by position only | Containers are 2 of 4 on A and 0 of 3 on B | plan P0.4 (images), notebook-output salvage | R1.2-2 (pin state), R0.2.0-7 (credential shapes) |
| CR-9 | Infrastructure and workflow exports: Terraform attributes and locals carrying model ids, guardrail ARNs and agent resources; n8n AI nodes; OpenAI Assistants exports (instructions digest, `code_interpreter`, `file_search`); data stores outside declared retrieval configuration; each with file and line | agent-config is 0 of 2 on B, where its two items are an n8n workflow and an Assistants export | plan P1.10 (infrastructure half); draft scope row 2 | R1.3-6, R1.1-7 |
| CR-10 | Loader-safety binding: which code loads which local model file, the loader call and its `trust_remote_code` argument, file and line | A `trust_remote_code: true` in config.json is already critical (scanners/model.py:2538-2544); loader calls in application code are source-code discovery | plan loader-safety salvage; draft 30 | R1.1-4 |

ShadowScan's dates are decision 3's to set; the recommendation that keeps the train whole is CR-0
and CR-1 by 15 January 2027 (1.0.0-rc.1), CR-3, CR-6 and CR-7 by 31 March 2027 (1.1), and CR-2,
CR-4, CR-5, CR-8, CR-9 and CR-10 by 31 July 2027 (1.3).

Every imported claim stays declared, with unknown trust (docs/shadowscan-integration.md:59-61).
Reconciliation binds it to the report beneath the project root, never to a higher assurance
(docs/shadowscan-integration.md:63-70), and only a SymBiote collector that reads the artifact itself
records observed evidence for it. A field the report does not carry stays unknown, never guessed.

## What to absorb, and from whom

The owner's draft named eleven tools, each with something SymBiote should learn, and placed every
capability in a numbered item. The tree's benchmark ran or graded four of them; the others rest on
their own pages or on nothing the tree can check, and four were not found at all. The table keeps
each capability that is still open and names its item; where the attribution cannot be verified
it says so, and where the capability already ships it says that instead.

| From | What the tree knows of the tool | The draft's capability (draft item) | What the tree shows | Lands in |
| --- | --- | --- | --- | --- |
| agent-bom | Run: 0.115.4 (REPORT.md:32); 55.6, C, capped by gate G3 (AUDIT.md:78) | Literal-credential findings (5); the chain from package to agent to credential (22); an inline MCP proxy re-specified as contract pinning (33); a pre-install package check (35) | Plaintext MCP secret findings and a server-to-credential reach path were verified by the run (REPORT.md:216-217, :308, :320); its tool-description poisoning rules are the verified prior art for draft 16 (enhancement-plan:33); the proxy is read from its README; a pre-install check is not found in the tree, and typosquat detection is declined | R0.2.0-7, R1.2-3, R1.1-2, R1.4-1, R1.4-3 |
| cdxgen | Run: 12.9.2 (REPORT.md:37); 23.3, F (AUDIT.md:83); 13.7.0 is the latest release (landscape) | BOM signing and verification (11); a fidelity level per ecosystem (21) | JSF signing is read from its repository, not measured; SymBiote already signs any export with DSSE and Ed25519 (D3); "a fidelity level per ecosystem" is not found in the tree, and its `cdx-validate --benchmark cisa-ai` checks the G7 elements | JSF interoperability is unplanned; R1.2-2 (`pinning_state`) |
| Cisco AI BOM | Tier-1 scanners of 1.10.1 run without the LLM stage (REPORT.md:33; cisco_tier1.py:1-13); 37.0, F, provisional (AUDIT.md:79) | The benchmark as a command (2) | Not found; the only benchmark command in the tree is cdxgen's `cisa-ai` option, and SymBiote has no `benchmark` command (cli.py, grep) | R0.3.0-1 (`make precision`) |
| OWASP AIBOM Generator | Graded from source at 45851cb (REPORT.md:39); 22.7, F, provisional (AUDIT.md:84) | Completeness scoring against a field checklist (31) | Verified from source (REPORT.md:291-297); SymBiote reports coverage per element, never a score (D6; the TrustScore decision) | Rshipped-6; R1.0.0-rc.1-3; R1.3-4 |
| AIsbom (Lab700xOrg/aisbom) 1.7.0 | Read from its repository on 12 November, not run (landscape); `aisbom-cli` was not found | Static model forensics (18) | SymBiote already walks pickle opcodes without loading (scanners/model.py:389-414) | R1.1-4 |
| Dependency-Track 5.1.0 | Exists; not run; a destination (landscape) | CISA and ENISA KEV enrichment (20); component-scoped VEX (23) | KEV and EPSS are credited to agent-bom (landscape); an ENISA KEV source is not found; VEX is already component-scoped (generators/vex.py:109), with every statement `in_triage` (:9-11) | R1.2-1, R1.2-4; ingestion tests in R1.3-4 |
| AIROM | Unverified: `airomhq/airom` is on pkg.go.dev up to v0.3.4; the tree has not assessed it | Byte-identical output (6); file-and-line evidence on every claim (8); fuzzed, bounded parsers (12); an offline model-retirement catalog (30); signed binaries (32) | Byte-identical output is SymBiote's own verified strength (D2; REPORT.md:147-148); line-level evidence is open; a weekly randomized property profile exists and a coverage-guided harness does not; no retirement catalog exists; releases are attested wheels, not binaries | Rshipped-2; R1.0.0-rc.1-2 and -3; R1.0.0-1; dropped; R1.3-7 |
| Snyk Agent Scan | Not found; the `snyk aibom` command exists | A tool-poisoning and skill-scanning taxonomy run offline (16, 17); toxic-flow and shadowing analysis (24) | No graded tool flagged the poisoned descriptions (REPORT.md:105-109); tool-name shadowing was refuted (enhancement-plan:122); toxic flows are the triples of gap 1 | R1.1-2, R1.1-3, R1.1-1 |
| Pitloom | Not found | Model-file metadata (18); the G7 minimum-elements check (31) | SymBiote reads ONNX external data, SavedModel files, GGUF metadata and SafeTensors headers (scanners/model.py:64-91); the G7 check ships (D6) | R1.1-4; Rshipped-6 |
| AIBoMGen; Project AIBOM | AIBoMGen is a paper the tree has not assessed; Project AIBOM is not in the tree, and the draft did not open it | Signed training provenance (34) | L5 plans in-toto, SLSA and dataset attestations as declared evidence | R1.4-2 |

Plug into, do not rebuild, holds with two corrections. ShadowScan is the discovery engine once the
import maps more than 3 of its 18 kinds and binds a commit (R1.0.0-rc.1-2). Dependency-Track and
GUAC are destinations that report-only jobs test (R1.3-4); neither is an integration SymBiote
depends on.

## Cut order and dependencies

If a date is at risk, scope gives first. The owner estimated the draft's fourteen items before
1.0.0 at about 15 maintainer-weeks in a 10.5-week window that spans the year-end holidays; that is
the owner's estimate, and the tree holds no basis for it. The draft's cut order, mapped to this
train, applies in rank order:

| Rank | Cut | What remains |
| --- | --- | --- |
| 1 | R1.0.0-3 | The quick start and the threat model, re-run; the N8 table still lands with R1.0.0-rc.1-1 |
| 2 | R1.0.0-1 | The tree-sitter decision, the no-network CI job and one more reader property; the coverage-guided harness moves to 1.1 |
| 3 | R1.0.0-rc.1-3 | Projection 3 without `services` and `modelCard`. The draft's "item 9 without impact" would save nothing, because `blast_radius` already walks every edge backward (graph.py:672-716) |
| 4 | R0.2.0-4 | Nothing now: the identifier-hygiene and server-constructor-names branches are written, and the offsets moved to R1.0.0-rc.1-2 |
| 5 | R0.3.0-2, R0.3.0-3 | Both slide whole to 1.1, not to 1.0.0-rc.1, which is at its load already; by the owner's call |

Ranks 1 and 2 relieve 1.0.0, rank 3 relieves 1.0.0-rc.1 and rank 5 relieves 0.3.0; rank 4 cuts
nothing now. Loads, counted from the plan's S, M and L sizes and unverified by any run: 0.2.0 about
one and a half maintainer-weeks, 0.3.0 about three, 1.0.0-rc.1 about five, 1.0.0 about three, which
is about 12.5 in the 10.5-week window; each depth release carries about four to six weeks in its
eight-week window.

R1.0.0-rc.1-1, R1.0.0-rc.1-2, R1.0.0-rc.1-4 and R1.0.0-rc.1-5 do not slip; they are the draft's
items 7, 8, 10 and 11. Some work cannot be forced by any cut, and it is listed apart so that no
date depends on it: ShadowScan's report fields (CR-0 to CR-10), the CycloneDX taxonomy
registration, the second maintainer and security contact (R1.1-5), corpus C (R1.2-5), CycloneDX
2.0 (L1) and the AgBOM mapping (L2). R1.1-1's per-agent paths and R1.2-3's agent identity wait on
CR-3, CR-6 and CR-7; their SymBiote halves, MCP tools and control-plane sources, ship on their dates.

**The draft's three chains, corrected.** The detectors attach to edges that collectors must first
emit. The native format already types 19 relationships (core/aibom.py:46-66), so typing is not the
blocker: R1.1-1 needs per-tool approval state (R0.3.0-2), hosted tools (R1.1-7) and projection 3
(R1.0.0-rc.1-3), and it computes per agent only after R1.2-3. VEX states need operator decisions
and advisories, not reachability: R1.2-4 needs the advisory snapshot (R1.2-1) and the placement
rules of the operator policy (R1.1-6), imported SBOMs (R1.2-2) supply full dependency trees, and
reachability (R1.2-3) is a justification source. Signing, the lockfile and the proxy are not a
chain, because each link has shipped pieces: attestation (Rshipped-3), the drift gate
(diff/differ.py:668-691) and the gateway's descriptor pin (runtime.py:1955-1986). The open pieces,
R1.0.0-rc.1-5, R1.3-2 and R1.4-1, can land in any order.

**Item dependencies.**

| Item | Needs |
| --- | --- |
| R0.2.0-5 (its 0.85 target) | R1.0.0-rc.1-2 and CR-5 |
| R0.2.0-7 | R0.2.0-4 (neutralized names) |
| R0.3.0-1 | R0.2.0-2 (the decoy floor) |
| R0.3.0-2 | R0.2.0-3 (inline servers through the dialect parser) |
| R1.0.0-rc.1-1 | R0.3.0-4 (the 1.2.0 fields) |
| R1.0.0-rc.1-2 | R1.0.0-rc.1-1; CR-0 to CR-10 from ShadowScan |
| R1.0.0-rc.1-3, R1.0.0-3 | R1.0.0-rc.1-1 |
| R1.0.0-1 | R0.3.0-3 |
| R1.0.0-2 | R0.2.0-1 |
| R1.1-1 | R0.3.0-2, R1.1-7, R1.0.0-rc.1-3 |
| R1.1-2 | R0.3.0-1 (the floor fixture) |
| R1.1-3, R1.1-10 | R0.3.0-2 |
| R1.1-4 | R0.2.0-2 |
| R1.1-5 | R1.0.0-2 |
| R1.1-6, R1.1-9, R1.3-2 | R1.0.0-rc.1-5 |
| R1.1-7 | R1.0.0-rc.1-2 (CR-3, CR-7) |
| R1.2-2 | R1.0.0-rc.1-3 |
| R1.2-3 | R1.1-1, R1.0.0-rc.1-2 (CR-6) |
| R1.2-4 | R1.2-1, R1.1-6 |
| R1.2-5 | R0.2.0-1, R0.3.0-1 |
| R1.3-1 | R1.1-4 |
| R1.3-3 | R1.2-3, R1.0.0-rc.1-2 |
| R1.3-4 | R1.0.0-rc.1-3, R1.2-2 |
| R1.3-5 | R1.0.0-rc.1-2 (CR-2) |
| R1.3-6 | R1.0.0-rc.1-2 (CR-9, for guardrails declared in infrastructure code) |
| R1.3-7 | R1.0.0-2 |
| R1.4-1 | R1.3-2, R1.0.0-rc.1-1 |
| R1.4-2 | R1.2-2, R1.0.0-rc.1-2 (CR-4) |
| R1.4-3 | R1.3-2 |
| R1.4-4 | R1.0.0-rc.1-5, R1.1-6 |

**Pull-request order for 0.2.0 and 0.3.0.** The 1,500-line cap and the 24-hour soak make 0.2.0
eight pull requests (CONTRIBUTING.md:93; enhancement-plan:215), in an order where each is
reviewable alone and benchmark recall only rises: R0.2.0-2; the neutralization half of R0.2.0-4;
its constructor-name half; R0.2.0-6; R0.2.0-3; R0.2.0-5; R0.2.0-7; then R0.2.0-8 last, because
the rename touches files the others touch. 0.3.0 follows with R0.3.0-1, R0.3.0-2 and R0.3.0-3.
The plan's pull requests for hosted models, nested manifests and images leave both releases under
the split.

## Delivered with this roadmap

Delivered with the roadmap of 12 November. Each entry names the review items it closes
([traceability](#traceability)) and the guide that documents it.

| # | Delivered | Closes | Guide |
| --- | --- | --- | --- |
| D1 | **Coverage honesty.** Every IDE settings file the collector recognizes is bound by a digest, now including `.cursor/cli.json`, the Antigravity, xAI and Copilot files and `.codex/config.toml` as a whole (these are digested after redaction, so their digests cannot confirm a guess of a value the redaction removes, such as a token, and without the binding key a change only to such a value does not alert; with the key an HMAC covers every value as read); unassigned default-ignorable code points are hidden-character findings and are neutralized in output; Hugging Face chat templates get the template-escape check GGUF templates get; nested `GEMINI.md` and `.cursorrules` files are collected; agent files inside default-excluded directory names, JavaScript-family MCP servers, namespace and `require` imports, dynamic imports with literal module names and servers that application code starts or reaches through the SDK and framework classes the collector knows are inventoried or reported as coverage gaps | the 0.1.0 limitations on default exclusions inside agent directories and on JavaScript-family, namespace-import and `require` MCP servers; G fixes 1–3; c R3.d–f; audit related mediums | [known limitations](docs/known-limitations.md), [TypeScript inventory](docs/typescript-inventory.md), [source binding](docs/verification-source-binding.md) |
| D2 | **Reproducible inventories.** On top of ARCH-F1 (#132 on `main`), which makes native JSON and CycloneDX byte-identical by default by recording no collection time, sorting components and dependencies and deriving the serial number from the content: a published content digest (`nexus-symbiote/inventory-content/v1`, with known-answer vectors) that is equal for equal content whenever and wherever it was collected and that `digest` prints beside the file digest and the canonical digest signed runtime snapshots bind; the serial number derived from that digest, so anyone can recompute it from the native file; and `SOURCE_DATE_EPOCH`, which makes `scan`, `baseline` and `import-shadowscan` record that instant as the collection time, so native JSON, CycloneDX and SPDX are byte-identical for identical input with a recorded time (SARIF when both scans run from the same place relative to the scanned directory) | the P1 acceptance test "same agent, same inputs, same build-time BOM hash"; c R2.d | [reproducible inventories](docs/reproducible-inventories.md) |
| D3 | **Inventory attestation.** `attest` signs an inventory (or any export) as a DSSE envelope carrying an in-toto Statement bound to the file's SHA-256 and, for native inventories, to its content digest, for a stated purpose (`generated` or `reviewed`); `verify-attestation` checks it against operator-held Ed25519 keys with a threshold, purpose, age and either byte or content matching. Offline | A gap 6; B Now 4; c R7.a; d P0 6; e fix 6 | [inventory attestation](docs/inventory-attestation.md) |
| D4 | **Runtime telemetry versus the inventory.** `trace-diff` reads OpenTelemetry traces the operator exported (GenAI and MCP semantic conventions, OTLP/JSON), never the content they may carry, and reports the tools, models, agents and MCP endpoints that the traces report but the inventory does not declare (exit 1), declarations that no span mentions (which does not show they went unused), and ambiguities; optional SARIF. Telemetry is recorded as `reported` evidence and never raises assurance | A gap 2 ("the diff is the product"); B Now 8; c R2.a–b; d P0 3; e fix 2 | [trace evidence](docs/trace-evidence.md) |
| D5 | **Framework crosswalk.** Every finding category has a SARIF rule; SARIF tags add MITRE ATLAS 2026.10, OWASP LLM Top 10 2026 and NIST AI RMF identifiers beside the existing CWE, OWASP LLM 2025 and OWASP Agentic ones; `crosswalk` reports findings per framework entry, including EU AI Act articles and ISO/IEC 42001 controls | A compliance table; B gap 10; c 7.2.c; d P1 2; e 4.4; G fix 16 | [framework crosswalk](docs/framework-crosswalk.md) |
| D6 | **G7 minimum-element coverage.** `minimum-elements` evaluates an inventory and its CycloneDX export against the 50 elements of the G7 "Software Bill of Materials for AI – Minimum Elements" (12 May 2026): present, missing, explicitly unknown, not applicable or needing producer input, with a field-level list of what to supply; coverage with its denominator, never a compliance verdict | A gap/requirement "G7 completeness"; B Now 6; c R10.b–c; d P0 7; e 4.3 | [minimum elements](docs/minimum-elements.md) |
| D7 | **Graph view and risk classes.** `graph` writes a self-contained, script-hashed `graph.html` (and a JSON model) of components, relationships, findings and the shortest recorded exposure paths from agents to components whose recorded evidence gives a code-exec, write-capable, exfil-capable or secret-access risk class, or that carry a high or critical finding; risk classes restate recorded evidence, not what a component does at run time, and components with none are shown as unclassified, never as safe | A gap 7 and DevEx graph; B Next 7; c R8.a, R8.d; d P1 7; e fix 7 | [graph view](docs/graph-view.md) |
| D8 | **Approve in SymBiote, reconcile in ShadowScan.** `export-inventory --format shadowscan-simple` writes ShadowScan's documented simple inventory list from a reviewed inventory, so the repository agent approved in SymBiote review becomes an approved agent in ShadowScan, bound only to the repository's root project (checked against ShadowScan 999bef1) | G fix 9 (P0) and move 2.a; A ShadowScan target state 5 | [ShadowScan inventory export](docs/shadowscan-inventory-export.md) |
| D9 | **Positioning.** The disambiguation line in `README.md` and `SECURITY.md`; this roadmap | A gap 1; B Now 1; c R13.a; d P0 1; e fix 1 | this page |
| D10 | **No gate failures for reasons no operator can act on.** The Python MCP source cap (a hidden, fixed 20,000 syntax nodes that the repository's own `registry.py` exceeded) is the operator limit `python-nodes`, and reaching it is a collection failure that names it; the helper analysis and the MCP origin-label scan run in linear time; another spelling of an instruction file the `prompt` collector reads at any depth, such as `pkg/claude.md`, is a collection failure, also beside the exact name; the registry collector records the project settings that redirect an inventoried npm or PyPI package to another registry or index, by origin only, with a low `registry_origin` finding and no package URL; `action.yml` says that its `scanners` input makes coverage partial. Symbolic links out of the project stay failures ([decisions](#decisions-and-non-goals)) | audit H5 residue, M4; the self-scan | [collection limits](docs/collection-limits.md), [registry collector](docs/registry-collector.md#registry-and-index-settings), [known limitations](docs/known-limitations.md) |

## Acceptance tests

The reviews' acceptance tests, restated so that they can pass or fail:

| Test | Status |
| --- | --- |
| **P0.** An agent calls an MCP tool its repository does not declare. The static scan does not contain it; the agent's exported traces reach `trace-diff`, which reports the tool as undeclared and exits 1; CI fails; the SARIF result carries the crosswalk tags. | Delivered (D4, D5), with the [walk-through](docs/trace-evidence.md). The reviews' "graph shows the new edge" needs the graph to read trace evidence (X2). |
| **P1.** Same agent, same inputs: same build-time inventory hash; the runtime evidence shows only the delta, each item tagged with its evidence source. | Delivered (ARCH-F1 on `main`, D2, D4): byte-identical native JSON and CycloneDX by default, SPDX too with `SOURCE_DATE_EPOCH`, and an equal content digest and serial number whatever time is recorded; trace evidence is a separate `reported` document that lists undeclared and unobserved items apart from matched ones. |
| **P2.** An independent evaluator reruns the published benchmark and reproduces its numbers; two external reviewers have reviewed the security model; three or more maintainers. | Open (L3, L4). |
| An unsigned or altered baseline fails the CI gate; a signed one passes and names its signer. | Partly delivered: D3 verifies; N1 puts it in the gates. |
| Every known limitation in `SECURITY.md` has a regression fixture, and the list shrinks to items reported as gaps. | Partly delivered (D1); the fixture mapping is part of N9. |
| A new user produces a signed, validated inventory and graph for a public agent in under five minutes. | Partly delivered: each step works on the demo agent (`validate` with the README's signer policy, D3, D7), but no guide runs them end to end and nothing has timed it; the public-agent tutorial follows with N8. |
| 1.0.0 ships only when every invariant has a passing CI test and the release candidate has run two weeks with no schema change. | Open. Rules 3, 5 (lines and offsets) and 11 have no test yet ([invariants](#invariants)); R1.0.0-rc.1-1 adds the schema-digest test. |
| A ShadowScan report from an agent-framework repository imports with no unmapped entries, and a report naming another commit fails `validate --project`. | Open (R1.0.0-rc.1-2); the report carries no commit today (docs/shadowscan-integration.md:297-302). |
| `make precision` fails CI when the recall of any AIBOM-Bench 1.0 class drops below its recorded floor. | Open (R0.3.0-1); no such target exists (enhancement-plan:320). |

The N, X and L ids in the status column map to release-train items in
[traceability](#traceability).

### How first place is proven

First place is claimed only when three conditions hold together, and none is a score the
maintainers computed. Each is stated here against what the tree shows today.

1. **A corpus someone else wrote.** On a corpus the maintainers did not write, a signed release
   leads every open-source AI-BOM generator on typed edges (AIBOM-Bench criterion 3.5) and on
   planted risks caught (dimension D5), with no decoy or negative control charged; with
   ShadowScan's report imported, the pair also leads on components found. Today SymBiote wins 3.5
   and D5 only on two corpora written by its own benchmark author (enhancement-plan:15;
   AUDIT.md:90-92), one soft decoy is charged on each (`decoy.zero-bin-as-model` in
   `results/scores.json`, `decoy.vendored-mcp` in `results/corpus-b/scores.json`), the run graded
   unpublished 0.2.0 at a13b622 (REPORT.md:30), and ShadowScan has not run on either corpus.
2. **The safety bar.** It passes the benchmark's four hard gates (SPEC.md:228-234) and every
   invariant with a passing CI test. Today it is the only tool with zero egress, zero process
   creation and no symbolic-link opens (REPORT.md:159-161), and rules 3, 5 and 11 still need
   their tests.
3. **Reproduction.** A third party reproduces both results from the signed release, which needs
   0.2.0 or a later release published with its attestations (R0.2.0-1) and the round of R1.2-5.

Until then the project claims no first place. The committed security regression corpus supports
no ranking (benchmarks/README.md:3); AIBOM-Bench does rank and grade (AUDIT.md:72-86), and this
roadmap cites that rank only as a self-authored, self-run, provisional result, as the benchmark's
own audit says (AUDIT.md:104-106). Every number carries its corpus manifest digest, the tool's
version or commit, who ran it and who wrote the corpus.

## Scorecard

What "first in this lane" means, as measures anyone can check. Values are at the head of this change.

| Measure | Target | Now |
| --- | --- | --- |
| Coverage honesty | No documented surface passes every gate without a gap | D1 closed the bypasses reproduced at 3ad53a2 that [where it stands](#where-it-stands) lists, #131 the shell startup-code bypasses and D10 the audit residue; the remaining exceptions are listed in [known limitations](docs/known-limitations.md) |
| Evidence grading | Every component and claim carries its assurance and a locator | Met for collected components as assurance plus an optional locator; lines and offsets are open (invariant 5); telemetry is a separate `reported` document |
| Reproducibility | Identical input gives byte-identical output | Met by default for native JSON and CycloneDX (ARCH-F1, #132); with `SOURCE_DATE_EPOCH`, also for SPDX, whose schema requires a creation time; for SARIF when both scans run from the same place relative to the scanned directory; equal content digest and serial number whatever time is recorded (D2) |
| Integrity | Every exported inventory can be signed and verified offline, one command each | Met (D3); gate enforcement is N1. Offline Sigstore verification checks the trust root it uses (SEC-C1, #132) |
| Standards fidelity | CycloneDX and SPDX exports validate with the official schemas and load in Dependency-Track with properties intact | Schemas met; Dependency-Track untested (X7) |
| Completeness | G7 minimum-element coverage reported for every inventory, with the missing fields | Met (D6) |
| Runtime truth | Declared versus reported use, gated in CI | Met for OpenTelemetry GenAI and MCP traces (D4); more sources in X2 |
| Framework mapping | Every finding mapped, where defensible, to OWASP (LLM 2025 and 2026, Agentic), MITRE ATLAS, NIST AI RMF, EU AI Act and ISO/IEC 42001 | Met (D5) |
| Time to first inventory | Under five minutes from install on Linux and macOS | 4.6 s scan on Linux; macOS smoke only (L6) |
| Governance | Two or more maintainers; externally reviewed security model; schema 1.0 | One maintainer; no external review (L3) |

The N, X and L ids above map to release-train items in [traceability](#traceability);
AIBOM-Bench adds the measures in [how first place is proven](#how-first-place-is-proven).

## Decisions and non-goals

### Decided on 18 November 2026

| Decision | What it settles | Consequences in this roadmap |
| --- | --- | --- |
| 1.0.0 ships on 31 January 2027; 1.1 to 1.4 follow every two months, the last on 30 September 2027 | 1.0.0 is a promise about stability, not breadth: native format 1.x frozen under the schema 1.0 label, attestation enforced in the gates, keyless provenance in the Action and a passing CI test for every invariant | The [release train](#release-train). The governance half of L3, an independent review and a second maintainer, depends on people and is not promised by the date (R1.1-5) |
| New discovery lives in Nexus-ShadowScan; SymBiote proves | The [scope](#scope-shadowscan-finds-symbiote-proves) table | Extends the routing of breadth through ShadowScan recorded on 12 November and answers the enhancement plan's first open question; the rows below on AgentBOM 0.1 and an in-process ShadowScan still hold |
| The registry collector may walk manifests below the root (R1.2-2) | An exception to the discovery split: manifests and lockfiles are dependency identity SymBiote already owns at the root, not AI discovery | R1.2-2 keeps the walk; images, workflows and notebooks stay with ShadowScan |
| The canonical owner is the aisecnomad account, and 0.2.0 ships after the first-wave fixes and new features have merged | Links, package metadata, badges, Action examples, citation, issue templates and the SARIF `informationUri` move to the aisecnomad account; identifiers that existing verifiers and documents depend on (the inventory attestation predicate type, the native schema id) stay and say so; `tool_vendor` is already `aisecnomad` | R0.2.0-8, merged last in 0.2.0; the seven first-wave branches are the rest of the 0.2.0 table |

### Open decisions

The owner's draft leaves six decisions open, with due dates. The recommendations are the draft's,
corrected where the tree disagrees.

| # | Decision | Recommendation | Decide by |
| --- | --- | --- | --- |
| 1 | Scope of 1.0.0 | The 0.2.0 to 1.0.0 tables of the [release train](#release-train), which hold the draft's fourteen items as reworded and the enhancement plan's P0 items that stay in SymBiote, with the [cut order](#cut-order-and-dependencies); everything else rides the depth releases | 27 November 2026 |
| 2 | Supported surface in 1.0.0 | The draft's split, with collectors, exports, `attest` and `verify-attestation` supported and the live commands `advisories`, `discover-mcp` and `verify-live` experimental (modes.py:37-41), extended to classify each of the 29 commands docs/cli-reference.md:322-1060 documents, the runtime gateway, `trace-diff` and `import-shadowscan` among them, and written into GOVERNANCE.md and the README (N8) | 4 December 2026 |
| 3 | ShadowScan's side of the contract | ShadowScan adds repository, commit, run time and per-finding file and line to its signed report under the [contract requirements](#shadowscan-report-contract); SymBiote imports it under projection profile v5 and records the binding; pair targets are set per AIBOM-Bench 1.0 class once ShadowScan has run on both corpora | 4 December 2026 |
| 4 | Exit-code contract | Keep 0, 1 and 2, and give a failed gate its own code apart from a failed collection and an internal error, behind `--legacy-exit-codes` for one release (enhancement-plan:181, :315; criterion D9 9.5). Drift is a failed gate and already exits 1 (docs/cli-reference.md:149, :156), and insufficient fidelity is the completeness claim, not a new code | 18 December 2026 |
| 5 | Co-maintainer and second security contact | Name both before 1.0.0-rc.1, with a second owner on the organization and on PyPI (GOVERNANCE.md:55); the full branch protection follows (GOVERNANCE.md:27). The date depends on a person, so the train carries the item as R1.1-5 and lands it earlier if someone is found | 15 January 2027 |
| 6 | Who writes and runs the outside benchmark | A named third party writes corpus C, keeps it sealed until the run and then publishes it with its manifest (L4; AUDIT.md:90-92); a hidden holdout could not be reproduced by anyone else. The draft's candidates, the OWASP AIBOM initiative and the CycloneDX ML working group, appear nowhere in the tree; confirm that both exist before approaching them | 29 January 2027 |

The enhancement plan's ten open questions (enhancement-plan:309-320) are answered or carried as
follows.

| Plan question | Answer or home |
| --- | --- |
| 1. Breadth through ShadowScan or through SymBiote collectors | Answered by the scope decision: the control-plane dialects (P0.2) stay in SymBiote; hosted models, images, inline prompts, workflows, notebooks, n8n and Terraform arrive through the import (CR-1 to CR-9) |
| 2. Hosted model references in existing collectors or under a new name | Moot for SymBiote's collectors: they arrive as imported claims (R1.0.0-rc.1-2), so the coverage format does not change |
| 3. `serialization_format_unknown` at high | High, with critical kept for recognised opcode streams and unreadable files (R0.2.0-2); operators can raise it by policy |
| 4. One escaping link fails six collectors | The decision stands; the report names the cause once with its collectors (R0.2.0-6) |
| 5. A gate-failure exit code now or at schema 1.0 | Decision 4, by 18 December 2026 |
| 6. 0.2.0 on PyPI and the published remote | Decided on 18 November: the aisecnomad account is canonical (R0.2.0-8), and 0.2.0 publishes from it after the first wave (R0.2.0-1) |
| 7. Has the tutorial been timed | Not yet; R1.0.0-3 times it |
| 8. Native 1.2.0 and the X3 identity type | 1.2.0 in 0.3.0 (the first wave adds findings and relations, no native field), 1.3.0 in 1.0.0-rc.1, and the identity type as an additive minor in 1.3 (R1.3-3) |
| 9. Gaps to refuse on principle | Under the split the HCL, n8n and notebook readers leave SymBiote (CR-4, CR-9); the fleet census is deferred (R1.1-9); the approved-descriptor registry stays (R1.3-2) |
| 10. Corpus C and `make precision` | `make precision` in 0.3.0 (R0.3.0-1); corpus C is decision 6 (R1.2-5) |

### Earlier decisions and non-goals

Recorded on 12 November and still in force, except the last row, which is new.

| Recommendation | Decision | Why |
| --- | --- | --- |
| `observe --agent ./my_agent.py` runs the agent and captures its runtime BOM | **Replaced by `trace-diff`** | SymBiote never executes what it inventories; the operator's own telemetry, read offline, gives the declared-versus-actual comparison without that risk |
| Import telemetry, k8s-aibom or other reports as `observed` evidence | **Declined; recorded as `reported`** | `observed` means a SymBiote collector measured bytes ([security model](docs/security-model.md)); runtime metadata emitted by the agent has a different trust basis, and an import never raises assurance |
| A 0–100 TrustScore ("100 only if signed, scanned, pinned and observed"; "unsigned scores 0") | **Replaced by risk classes and an evidence profile (D7, X9)** | a single high number reads as "trustworthy", which no inventory can establish (a stated non-goal); evidence per component is actionable without that implication |
| OPA or Cedar embedded in the tool | **Declined; a documented JSON contract instead (X10)** | A second policy runtime in the trusted path is attack surface. Nexus SymBiote can generate Cedar and Rego policy text for external engines. The JSON contract is the documented interface. Nexus SymBiote embeds and runs no policy engine. |
| An `nsb` console alias | **Declined** | `nsb` is an unrelated distribution on PyPI; a second command name would collide on `PATH` and split documentation |
| Emit AgentBOM 0.1 so ShadowScan can read it | **Declined; ShadowScan's simple list instead (D8)** | AgentBOM 0.1 is the retired experimental format described below |
| In-process ShadowScan as a `[discovery]` extra | **Declined** | its dependencies would enter the hash locks, and discovery runs best as a separate least-privilege process |
| Optional LLM classification | **Not planned** | deterministic collectors are the trusted path; if ever added, advisory only and never changing a finding or a gate |
| eBPF capture | **Not planned here** | privileged and host-specific; exported telemetry covers the declared-versus-actual comparison |
| A private registry proxy with typosquat detection | **Out of scope** | a network service, not an inventory; typosquat heuristics would add false positives to a fail-closed gate |
| Envelope encryption of inventories | **Not planned** | inventories carry no secret values (names only; known secret patterns redacted); encryption at rest is a storage concern |
| The broadest scanner, a CVE database, a production MCP firewall | **Non-goals** | other projects do these well; SymBiote imports their output (X1) and publishes the contract gateways enforce ([runtime contract reference](docs/runtime-contract-reference.md)) |
| Claiming that an inventory or a low score proves an agent or model benign | **Non-goal** | absence of evidence is unknown, not safe |
| Default execution of project code, MCP launchers or model loaders | **Non-goal** | `verify-live` is the only explicit, operator-pinned exception |
| Stop failing the walking collectors on a symbolic link out of the project that none of them would read (audit residue) | **Declined; confinement unchanged** | a link's name cannot show whether it names a directory, and all six walking collectors read names at any depth below directories of any name; finding out would mean examining a path outside the project chosen by the checkout, and the answer would hold only on the scanning machine, not on the one that later opens the checkout. Replace the link with the file or a relative link inside the project ([known limitations](docs/known-limitations.md#every-collector)) |
| A per-tool permission and egress model, closed on 12 November because "per-tool egress has no source in a repository" | **Reopened for repository-resident sources only (R0.3.0-2, R1.1-1)** | allow and ask rules per tool, `alwaysAllow` arrays, subagent and skill front matter, MCP tool annotations, bridge URLs and sandbox domain lists are in the repository (enhancement-plan:137); a general egress model stays out, because host load orders are undocumented and settings outside the checkout override the project's (enhancement-plan:111, :119) |

**Historical experimental work.** The [closed-PR audit](docs/audits/closed-pr-review-2026-11-02.md)
records what reached the supported package and what remains separate. The experimental foundation's
salted Merkle disclosure protocol, full snapshot chain format, OPA/Rego export and parity suite, and
Kubernetes/trace import contracts are not supported interfaces on `main`. Evaluate any future port
against the current threat model and version its wire format; a merge into an experimental branch
does not establish shipped compatibility. Discovery expansion continues through Nexus-ShadowScan.

## Corrections to the reviews

Statements in the reviews that were wrong or had become stale by 12 November 2026, with what is true.

| Statement | Correction |
| --- | --- |
| "OWASP LLM Top 10 2025" as the current edition; LLM03 is Supply Chain | The 2026 edition was published on 4 August 2026 and renumbered the list (LLM03:2026 Excessive Agency, LLM04:2026 Supply Chain). Identifiers are meaningful only with their edition; SymBiote now tags both. |
| "50 G7 elements" could not be confirmed, or "roughly 50" | Exactly 50 elements in 7 clusters (10/9/13/10/2/4/2), non-binding, with no official identifiers and no required or optional tiers. Report coverage, not compliance. |
| "No CI gate, no SARIF, no pre-commit hook, no pickle detection, no self-validation" | All existed at v0.1.0 (SARIF validation is structural, not the official schema). |
| "Sigstore is only an optional extra; signing must become the default path" | Sigstore *verification* of model files and ShadowScan reports exists under an operator signer policy, and since #132 unverified ShadowScan discovery evidence fails in CI unless explicitly allowed (SEC-F1); inventory signing did not exist (D3 adds it; enforcing it in the gates is N1). |
| Claude hooks, deny rules, subagents, skill scripts, nested instruction files, `.vscode/mcp.json` are not read | Read or digest-bound since 3ad53a2; the reproduced residue (marker files, Codex keys, JavaScript-family servers, excluded directory names) is D1. |
| "Fixed list of hidden characters, instruction files only" | Every format character (Unicode category Cf) on every text file the prompt collector reads; the unassigned default-ignorable ranges were the remaining hole (D1). |
| "No GGUF template-injection assignment" | Assigned since 3ad53a2; Hugging Face chat templates were the remaining hole (D1). |
| "SymBiote 0.1.0 writes AIBOM 1.0.0; ShadowScan reads AgentBOM 0.1" | `main` writes format 1.1.0, which ShadowScan also refuses; ShadowScan additionally reads Capability Cards, a simple list and CSV, and the simple list is the target (D8). |
| "Symbiote records only what a repository declares" | `discover-mcp --record` and `verify-live --record` already record live MCP observations with observed assurance. |
| "The reference gateway should start writing observation records" | It already emits a decision record for every admitted or denied call (`on_decision`); a built-in sink is X2. |
| "Unpinned `latest` fails CI" | It raises a high finding; the built-in gate fails on critical findings, so it passes unless the policy lowers the cutoff. |
| "Capability classes inferred for MCP servers" | Only for tools listed in a configuration's `tools` array, a SymBiote convention; D7's risk classes say "unclassified" where no evidence exists. |
| "Freeze the schema at 1.0" | The native format is already 1.1.0; schema 1.0 is the stability label to aim for (L3), with a migration path from formats 1.0 and 1.1. |
| "Cisco AI BOM's LLM classification is optional" | Its `analyze` step requires an LLM since 1.0.0; `watch` is deterministic. |
| "k8s-aibom v1.2 / 1.7.0, a three-tier confidence model, immutable CRDs" | v1.6.2 (v1.7 planned for 24 November 2026); confidence values declared, verified, inferred and unresolved, each with an evidence locator; write-once objects in its storage sink. |
| "cdxgen 13.8.0 released" | 13.7.0 (7 November 2026) is the latest release; 13.8.0 is the development branch. |
| "agent-bom emits its own JSON; v0.108; 11 frameworks" | 0.114.0 (8 November 2026) exports CycloneDX 1.7, SPDX 3.0.1, SARIF, JSON and HTML; canonical repository koda-ai-studio/agent-bom. |
| "Runtime observation: nobody ships it" | k8s-aibom inventories running Kubernetes workloads and agent-bom proxies MCP traffic. SymBiote's addition is the declared-versus-reported comparison against a verified inventory. |
| "eBPF malware" (in the disambiguation line) | Unnecessary detail with an inaccurate label; "the Linux malware of the same name" is accurate. |
| Rankings (#1 on coverage; 3rd, 4th, 5th, 8th, 9th of 11 or 12) and head-to-head benchmark numbers | Dropped: they contradicted each other, were judgments rather than measurements, or compared tools run below their supported mode. L4 replaces them with a reproducible round. |
| "SymBiote itself has not been benchmarked" | Two self-authored regression corpora have run in CI since v0.1.0, with 18 security and 10 inventory cases then and 25 security cases now; what is missing is a comparative, third-party round. |

### Corrections to the 18 November draft

What the owner's draft says that the tree contradicts, cannot support or has overtaken, with what
is true. Line numbers are those of the draft's text export; the dates and the scope split are kept
as decided.

| The draft says | What is true |
| --- | --- |
| 1.0.0 ships "a frozen AgentBOM contract, a typed graph and signed exports" (line 4) | The typed graph exists (core/aibom.py:46-66) and `attest` signs any export (D3). 1.0.0 adds gate enforcement and keyless Action provenance (R1.0.0-rc.1-5) and freezes the native format after its 1.2.0 fields (R1.0.0-rc.1-1); "AgentBOM v1" collides with the retired, declined AgentBOM 0.1 |
| "2 inputs, 4 core stages, 3 opt-in live parts" (line 5) | Five core stages: collect, assemble, gate, compare, export (README.md:163-167). Three live commands: `advisories`, `discover-mcp`, `verify-live` (modes.py:37-41); `trace-diff` and the runtime gateway are offline |
| "only its signed output reaches the opt-in live plane" (line 6) | No live command reads a signed inventory. `verify-live` follows an operator-owned launch policy outside the project (SECURITY.md:42), `discover-mcp` contacts the endpoint the operator names and `advisories` queries OSV (modes.py:37-41); the reference gateway enforces signed runtime contracts, a separate artifact |
| "Agent and code discovery live in ShadowScan" (lines 4 and 15) | New discovery does. SymBiote keeps its code reads for MCP servers, tool definitions and SDK references (README.md:182; tool recall 3 of 3 on corpus A) |
| "main at a13b622 ... 0.2.0 waits on two open merges (issue 200)" (line 11) | `main` is 7ca2235f; 25 pull requests are open on 19 November, all opened since 18 November and coordinated on issue 200, the ledger of 14 November, which then listed 49; 0.2.0 waits on N7's controls (R0.2.0-1) |
| "Eight collectors read agent control-plane files" (line 12) | The eight cover MCP, model, instruction, retrieval, package, A2A and IDE-settings surfaces plus a ShadowScan report (README.md:173-180) |
| "Decided on Nov 18 ... The split matches the repository's own ROADMAP.md" (line 15) | It extends the 12 November roadmap, which routed only containers, infrastructure as code, workflows and frameworks through ShadowScan; this page records it as a decision |
| ShadowScan findings become "signed evidence" (line 15) | They stay declared claims bound to a producer-verified report (docs/shadowscan-integration.md:59-61, :293-295); the inventory that carries them can be attested |
| The baseline is "the maintainer's AIBOM-Bench v1.1 run of SymBiote alone on main" (line 31) | AIBOM-Bench 1.0 (`ground_truth.json` version 1.0; REPORT.md:1), run on 0.2.0 at a13b622 (REPORT.md:30); no "v1.1" string exists under benchmarks/ or docs/ |
| Models 0 of 16, agents 0 of 2, AI infrastructure 1 of 7, data and retrieval 1 of 9, with pair targets 13, 2, 7 and 7 (lines 35 to 46) | Not reproducible: no class has 16 items, no `agent` class exists and neither grouping is defined; the tree's counts are in [scope](#scope-shadowscan-finds-symbiote-proves) |
| "The pair is scored as one" (line 31) | SPEC.md has no pair mode; the pair figure is a per-class sum scored after an import until it gains one |
| "a CI test enforces each one" of the eleven invariants (line 48) | Rules 3, 5 (lines and offsets) and 11 have no enforcing test ([invariants](#invariants)) |
| Invariant 1's hostile fixture holds "setup.py, a .pth hook" and starts "0 child processes" (line 54) | `setup.py` is not read (docs/known-limitations.md:989) and `.pth` is the PyTorch suffix (scanners/model.py:78); the proof is the Python-level guard, not a process count (modes.py:10-17) |
| Invariant 2 passes "in a network-denied sandbox" (line 57) | The suite has a loopback-only tripwire (tests/conftest.py:213-319); no CI job denies the network (R1.0.0-1) |
| Invariant 4 holds "under strict policy" (line 63) | No mode has that name; it holds under the default policy (policy.py:141-142) |
| Invariant 5's schema "requires a tier plus file, offset and digest" (line 66) | The locator is optional and no offset field exists (core/models.py:83-92) |
| Invariant 6 plants an Anthropic secret (line 69) | No `sk-ant-` value is planted anywhere (grep); Rshipped-4 adds one |
| Invariant 7 holds "after masking timestamps" (line 72) | Nothing needs masking; no time is recorded by default (tests/test_determinism.py:97-102) |
| Invariant 8: "Every export validates offline; a round trip keeps 100%" (line 75) | SARIF is validated structurally and is one-way; the round trip is lossless through the embedded native document only (tests/test_export_conformance.py:88-106) |
| Invariant 9: "CI reads gate and signer policy from the trusted base ref" (line 78) | Documented for callers (docs/drift-gate.md:209-216), but no workflow of this repository does it (.github/workflows/ci.yml:154-160) |
| Invariant 11: "Every rule ships a positive fixture and a benign twin" (line 84) | 7 kinds in 22 cases cover 47 categories (benchmarks/manifest.json); R0.3.0-1 delivers the rule |
| Item 1: "Land the two open merges" (line 121) | Merge what is open at the cut; the publishing pipeline already exists (.github/workflows/release.yml:285-301) |
| Item 2: `nexus-symbiote benchmark`, recall 0.98 and precision 0.95, a holdout hidden from rule authors (lines 126 and 127) | No such command exists; the gate is exact per case today; floors start at today's recall; the holdout becomes corpus C, written by someone else (R1.2-5) |
| Item 3: a PreToolUse hook and an `apiKeyHelper` "each raise a named high finding" (line 132) | Both raise named findings, medium when their commands are plain (main:docs/finding-catalog.md:53, :60), below the Action's default `fail-on-severity: high` (main:CHANGELOG.md:142); the severity is a decision in R0.3.0-2 |
| Item 4: detect "by Unicode category and range"; right-to-left prose "stays clean" (lines 136 and 137) | Category and range detection exists (scanners/prompt.py:60-77, :231); directional marks in right-to-left prose are a medium finding by design (docs/security-model.md:68) |
| Item 5 flags "URL userinfo" (line 141) | Credentials in an endpoint URL are already `transport_security` (main:docs/finding-catalog.md:90) |
| Item 6: "Replace wall-clock limits" and make "the keyed digest the default" (line 146) | The only wall-clock bounds are the TypeScript deadlines (scanners/ts_tools.py:88-91); the Action requires the key whenever a reviewed baseline is set (action.yml:68-83) |
| Item 7: "A schema change without a version bump fails CI; ShadowScan reads v1" (line 152) | No test does that yet (tests/test_native_contract.py:19-23 only compares schema and model); ShadowScan reading SymBiote's format is a dependency on another repository |
| Item 8: reports "bound to commit and time ... with file and line"; re-read "the cited file and offset"; "an unsigned report is refused" (lines 156 and 157) | The report carries no commit (docs/shadowscan-integration.md:297-302) and output withholds locations (:73-74); no re-read promotes a claim; unsigned evidence already fails in CI unless explicitly allowed (cli.py:355-367) |
| Item 9: edges "hands off to ... bundles"; "impact walks them backward" (line 161) | The native names are `delegates-to` and the others in core/aibom.py:46-66, with no `bundles`; the backward walk ships (graph.py:672-716) |
| Item 10: "version the symbiote:v1:* properties" (line 166) | The namespaces are `nexus-symbiote:` and `agentbom:`, versioned by the projection marker (generators/cyclonedx.py:54) |
| Item 11: "Sigstore keyless signing" in `sign` (line 171) | The CLI verifies Sigstore bundles and signs nothing keylessly (utils/crypto.py:36-40); keyless provenance belongs to the Action (R1.0.0-rc.1-5) |
| Item 12: "bound reads; isolate native parsers" (line 176) | Reads are bounded (SECURITY.md:38); a parser worker process would need an exception to the guard's refusal of process creation, on which invariant 1's proof rests, so isolation is a decision (R1.0.0-1) |
| Item 13: "severity-tiered remediation targets ... in SECURITY.md" (lines 181 and 182) | SECURITY.md:13 states one best-effort target |
| Item 14: "top three reasons" (line 186) | Every gate prints all its reasons and caps findings at 15 (reporting.py:26, :92-110) |
| Item 15: such an agent "is critical" (line 198) | High by default and raisable by policy, because the built-in gate fails closed on critical (enhancement-plan:169, :270) |
| Item 18, for 1.1: "An unsafe pickle global, a GGUF template and an ONNX external path each give a file-and-offset finding" (line 210) | Pickle opcodes, GGUF templates and ONNX external paths are already checked without loading (scanners/model.py:389-450, :1158-1170, :1398-1428); offsets and an allow-list of safe globals are the work |
| Item 20 matches advisories "with no network" (line 218) | An embedded CVE database is a non-goal; R1.2-1 reads an operator-supplied snapshot offline |
| Item 21: "A manifest-only read is never exported as complete" (line 222) | Already true: exports never claim complete coverage (generators/_common.py:252-257) |
| Item 22: a path is modeled "until ShadowScan call evidence confirms it" (line 226) | An import never raises assurance, and no contract carries call evidence (scanners/shadowscan.py:118); tiers reuse the assurance ladder (R1.2-3) |
| Component-scoped VEX is to be absorbed from Dependency-Track for item 23 (line 98) | VEX is already component-scoped (generators/vex.py:109); the open part is its states |
| Item 24: toxic flows and shadowing (line 234) | Chained leaks are R1.1-1's triples; tool-name shadowing was refuted (enhancement-plan:122) |
| Item 27 runs "on MCP 2026-07-28 and the two revisions before it" (line 246) | The live client supports 2024-11-05 to 2025-11-25 and needs initialize (scanners/live_mcp.py:66, :1085-1089) |
| Item 30, for 1.3: "Planted alias, license and remote-code risks are caught" (line 258) | `trust_remote_code: true` is already critical (scanners/model.py:2538-2544) |
| Item 31, for 1.3: "A valid but undocumented model scores high on structure and low on completeness" (line 262) | Delivered as D6, as coverage per element, never a score (the TrustScore decision) |
| Item 32: "All eleven invariants pass on Linux, macOS and Windows" (line 266) | Confinement needs POSIX primitives and fails closed elsewhere (SECURITY.md:40); Windows is a decision (R1.3-7) |
| Item 33, for 1.4: "A one-character description change is blocked before the model sees it" (line 270) | The reference gateway already refuses a changed descriptor (runtime.py:157); a production MCP firewall is a non-goal |
| Item 35: "a typosquat fixture is flagged" (line 278) | Typosquat detection is declined: heuristics would add false positives to a fail-closed gate |
| Item 36: unmapped controls listed as gaps (line 282) | The crosswalk omits entries no finding references (crosswalk_cli.py:93-95); R1.4-4 lists them |
| 1.0.0 "closes every known silent pass" (line 7) | The silent passes the tree knows are the known limitations; R0.3.0-1 maps each to a fixture (N9), and what no collector reads still passes until the unread-shape census (R1.2-2) |
| Item 14: a new user reads a result "in under 2 minutes" (line 187) | Three targets existed (the README's 60-second block, the five-minute acceptance test, the draft's two minutes); R1.0.0-3 times the README block and the tutorial and records both, with the five-minute test as the gate |
| Item 23's "shadowed" fixture (line 230) | No detector exists for a shadowed component, and tool-name shadowing was refuted as prior art (enhancement-plan:122); R1.2-4 keeps the declared-never-loaded and invoked fixtures |
| The three chains (lines 285 to 287) | Corrected in [cut order and dependencies](#cut-order-and-dependencies) |
| The depth items: "None changes the 1.0 contract" (line 191) | They add native fields as minor versions under the frozen major |
| First place: "no benign-twin alarms"; "counts only ... in line with its benchmark README" (lines 290 and 293) | One soft decoy is charged on each corpus; the README that forbids ranking is the security corpus's (benchmarks/README.md:3), while AIBOM-Bench ranks (AUDIT.md:72-86) |
| Risk signals: "49 open pull requests and 475 conflicting pairs"; "nine of ten ordinary FastMCP and PydanticAI idioms"; "no shared contract yet"; "MCP removed sessions" (lines 303 to 312) | Stale (the 49 and the 475 pairs were the ledger of 14 November; the 25 open on 19 November are all from 18 November on and coordinated there); not found in the tree; a one-way, producer-verified import exists (scanners/shadowscan.py:37); established only from secondary sources |
| "AgentBOM v1 frozen at the release candidate" (line 307) | The name collides with the declined AgentBOM 0.1; the freeze is the native format's schema 1.0 label (R1.0.0-rc.1-1) |
| "Two were made on Nov 18 ... discovery in ShadowScan" (line 315) | The routing of breadth was recorded on 12 November and refined on 18 November; the 1.0.0 date is new |
| Decision 4: distinct codes "for drift and for insufficient fidelity" (line 334) | Drift already exits 1; "fidelity" is not a concept of the tree (decision 4 corrected) |
| Sources: "cdxgen 13.6.0", "snyk-agent-scan, aisbom-cli, pitloom" (line 347) | cdxgen 13.7.0 is the latest release (landscape); the other three were not found |

### Corrections to the enhancement plan

What in the [enhancement plan](docs/enhancement-plan-2026-11-18.md) the tree or the decisions of
18 November have overtaken. The plan stays as written; this roadmap is what changed.

| The plan says | What is true |
| --- | --- |
| "Class recall 0.00 on model ... on both corpora; mcp-server 0.778 A, 0.571 B" (enhancement-plan:16) | After the corpus B correction, model is 0.10 on B (1 of 12), as enhancement-plan:26 says, and mcp-server is 0.667 on B (4 of 6) (`results/corpus-b/scores.json`) |
| It was written against "this repository at `eb6a853`" (enhancement-plan:5) | `main` is 7ca2235f. On `main` a credential helper is rated as a hook command is, `statusLine` and `fileSuggestion` commands are rated, `settings_environment` is new, and every file under `.claude/hooks` and `.cursor/hooks` is bound by digest (main:CHANGELOG.md:9-12), which meets part of gap 4 and P1.6; its pointers into scanners/ide_agents.py sit lower on `main` |
| Open question 1 asks whether breadth ships in SymBiote (enhancement-plan:311) | Decided on 18 November: P0.2 stays in SymBiote; the discovery halves of P0.3, P0.4 (images), P0.6 (inline prompts), P1.1, P1.2, P1.7, P1.10 and P2.10 become the [contract requirements](#shadowscan-report-contract) |
| P0.3's acceptance, model recall of 0.65 or more on A, is a SymBiote collector target (enhancement-plan:153) | It becomes a pair target, set once ShadowScan has run on both corpora |
| "Only one bump per release: 0.3.0 ships 1.2.0 ...; 0.4.0 ships 1.3.0" (enhancement-plan:249) | The train has no 0.4.0: 1.2.0 ships in 0.3.0, 1.3.0 in 1.0.0-rc.1 under the schema 1.0 label, and later fields are additive minors |
| P1.4, the credential finding, ships in 0.4.0 (enhancement-plan:171) | It ships in 0.2.0 (R0.2.0-7) with the first-wave branch |
| "no fuzz targets or scheduled accuracy regression" (enhancement-plan:134) | A weekly randomized property profile with 2,000 examples runs outside Verified CI (.github/workflows/dependencies.yml:11, :127-147; tests/conftest.py:108-114); a coverage-guided harness and the accuracy regression are what is missing |
| P1.8's acceptance includes "a Dependency-Track import shows modelCard and services" (enhancement-plan:179) | No Dependency-Track job exists; that half of the acceptance moves to R1.3-4 |
| P0.2's acceptance includes "mcp.cline-time ... detected" (enhancement-plan:151) | That item left corpus B's ground truth on 18 November, because Cline documents no project-level MCP file (AUDIT.md:110-113; enhancement-plan:133); R0.2.0-3's acceptance drops it |

## Landscape

Dated facts, read from each project's own repository or registry entry on 12 November 2026. Counts
move between releases; read them as "per its README on that date".

| Tool | What it is good at | Relation to SymBiote | AIBOM-Bench 1.0, 18 November |
| --- | --- | --- | --- |
| [cdxgen](https://github.com/cdxgen/cdxgen) 13.7.0 (OWASP) | Polyglot SBOMs; CycloneDX 1.7 by default, 1.6 and draft 2.0 by option; SPDX 3.0.1; AI-BOM coverage of MCP configs, skills, Hugging Face model cards and formulation; JSF signing; `cdx-validate --benchmark cisa-ai` for the G7 elements | Import its SBOMs (X1); match its standard fields (N4) | 23.3, F; ran 12.9.2, which executed package managers in the corpus (AUDIT.md:83; REPORT.md:37) |
| [Cisco AI BOM](https://github.com/cisco-ai-defense/aibom) 1.10.1 | 23 scanners, 30 component types, seven languages (structural scanners Python-only); CycloneDX 1.6, SPDX 3.0 AI and Dataset, SARIF; `analyze` requires an LLM | Import as declared evidence (X1); keep the deterministic trusted path | 37.0, F, provisional, gate G1 (a token copied from a launch argument); Tier-1 scanners of 1.10.1 only (AUDIT.md:79; REPORT.md:33) |
| [agent-bom](https://github.com/koda-ai-studio/agent-bom) 0.114.0 | Exposure graph, CVE context (OSV, GHSA, NVD, EPSS, KEV), MCP proxy and gateway; CycloneDX 1.7, SPDX 3.0.1, SARIF | Gateways can enforce SymBiote's signed contract; EPSS and KEV in X6 | 55.6, C, capped by gate G3; ran 0.115.4; best coverage on both corpora (AUDIT.md:78; REPORT.md:32) |
| [k8s-aibom](https://github.com/GoogleCloudPlatform/k8s-aibom) v1.6.2 (Google Cloud) | Runtime ML-BOMs of Kubernetes workloads with per-attribute confidence and evidence locators | A further `reported` source for `trace-diff` (X2) | 59.0, C, provisional; graded from source at 7be6465 (AUDIT.md:77; REPORT.md:31) |
| [Trusera ai-bom](https://github.com/Trusera/ai-bom) 3.6.0 | 13 scanners, 25+ SDKs, n8n workflows, a Cedar gate; last release March 2026 | Import as declared evidence (X1) | 29.1, F; ran 3.6.0 (AUDIT.md:80; REPORT.md:34) |
| [OWASP AIBOM Generator](https://github.com/GenAI-Security-Project/aibom-generator) | Hugging Face model card to CycloneDX 1.6 with a completeness score | Link its model AIBOMs (N4, X1) | 22.7, F, provisional; graded from source at 45851cb (AUDIT.md:84; REPORT.md:39) |
| [AIsbom](https://github.com/Lab700xOrg/aisbom) 1.7.0 | Static analysis of Pickle, Keras, GGUF, ONNX and SafeTensors files | Opcode-level depth in X4 | Not graded |
| [model-signing](https://github.com/sigstore/model-transparency) 1.1.1 | OpenSSF Model Signing, stable since 1.0.0 (April 2025) | Verification in X4 | Not graded |
| [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) 0.1.4 | Nine discovery surfaces, 38 connectors, reconciliation against an approved inventory | Discovery engine; D8 and N3 deepen the bridge | Not run on either corpus |
| [Dependency-Track](https://dependencytrack.org/) | CycloneDX-native store with policies; accepts CycloneDX 1.7 from 4.14.4 and 5.1.0 | Destination; ingestion tests in X7 | Not graded; a destination |

Standards to track: CycloneDX 2.0 (draft; agents as parties with declared and observed behaviors),
SPDX 3.1 (development draft; `isoAutomationLevel`), the OWASP Agent Observability Standard (AgBOM),
the OpenTelemetry GenAI and MCP semantic conventions (now in
[their own repository](https://github.com/open-telemetry/semantic-conventions-genai), all at
Development stability), MITRE ATLAS (release 2026.10 renamed several techniques), and the G7 minimum
elements.

The same round graded Nexus SymBiote 0.2.0 at a13b622 (73.0, B), scanoss ai-finder 0.5.0 (28.1,
F, gate G4 for telemetry by default), ai-agentbom 0.8.0 (28.1, F) and Syft 1a72047 (22.2, F,
graded from source) (AUDIT.md:74-85; REPORT.md:28-39). One author wrote both corpora and the
harness (AUDIT.md:90-92), so every grade is a self-authored, provisional result. The owner's draft
also names AIROM (`airomhq/airom`, on pkg.go.dev up to v0.3.4), which the tree has not assessed,
and Snyk Agent Scan, Pitloom and aisbom-cli, which were not found
([what to absorb](#what-to-absorb-and-from-whom)).

MCP revision 2026-07-28 exists. Third-party summaries and the title of the official changelog page
say it removes protocol-level sessions, the `Mcp-Session-Id` header and the initialize handshake,
deprecates roots, sampling and logging, adds a required `resultType` and moves tasks to an
extension; the changelog itself was not read, and the live client supports 2024-11-05 to
2025-11-25 (scanners/live_mcp.py:66). The G7 minimum elements were published in May 2026, on
12 May according to the title of an Italian government PDF; sources give 48 or 50 elements, and
the tree records its edition, source and secondary verification at minimum_elements.py:53-66.

## Risks and watch items

Each risk names the signal to watch on 18 November and the response already in this roadmap.

- **One maintainer.** Every privilege has one holder and no backup (MAINTAINERS.md:26-35), and
  there is no second security contact (SECURITY.md:15). The draft's signal, 49 open pull requests
  and 475 conflicting pairs, is the ledger of 14 November (issue 200); on 19 November 25 pull
  requests are open, all opened since 18 November and coordinated on that ledger. The 24-hour soak, the
  1,500-line cap and the review record compensate only partly (GOVERNANCE.md:19-25, :33). R1.1-5 is
  the fix, and R1.0.0-2 puts detectors and parsers on the second-reviewer list so that the control
  switches on the day it lands.
- **The date.** The owner estimated the fourteen items before 1.0.0 at about 15 maintainer-weeks
  in a 10.5-week window that spans the year-end holidays. 1.0.0-rc.1 is the most loaded release,
  about five maintainer-weeks in four across the holidays. The [cut order](#cut-order-and-dependencies) gives first; the
  items that do not slip still have halves that only other people can deliver.
- **Scope growth.** The source is about four times its v0.1.0 size (67,776 lines against 16,864).
  The plan's P0 to P2 would add nine hostile-input parsers (enhancement-plan:290-292); under the
  split most of them become ShadowScan's, and N8 (R1.0.0-rc.1-1) decides what SymBiote supports.
  Each new importer is still new hostile-input parsing.
- **The ShadowScan seam.** Two alpha tools (SECURITY.md:5; ShadowScan 0.1.4) are joined by a
  one-way, producer-verified import (projection profile v4, scanners/shadowscan.py:37) that maps 3
  of 18 kinds, binds no commit and has never run on AIBOM-Bench; the other direction is the simple
  list (D8). The [contract requirements](#shadowscan-report-contract), R1.0.0-rc.1-2 and
  decision 3 respond.
- **Convergence.** Microsoft's Agent Governance Toolkit ships a discover, inventory, reconcile and
  govern loop; cdxgen ships agent and MCP coverage and draft CycloneDX 2.0. On AIBOM-Bench
  agent-bom covered the most on both corpora (AUDIT.md:78) while SymBiote led on safety,
  provenance, standards and determinism (AUDIT.md:76). SymBiote's answer stays evidence quality
  and verification, with breadth through the ShadowScan import.
- **Standards and specification drift.** Agent semantics in CycloneDX and SPDX are unsettled; the
  native format and the digest-bound extension carry them until L1 and L2 (R1.3-4). MCP 2026-07-28
  removes protocol-level sessions according to secondary sources, while the live client stops at
  2025-11-25 (scanners/live_mcp.py:66). R1.3-2 reads the primary changelog before coding; the
  static drift gate does not depend on the protocol revision.
- **Fail-closed noise.** The draft's signal, one pull request that turned nine of ten ordinary
  FastMCP and PydanticAI idioms into gaps, is not found in the tree. The recorded signals are one
  soft decoy charged on each corpus and one escaping symbolic link failing six collectors, so both
  corpora exit 1 whatever the findings (enhancement-plan:19). The rule that ordinary use stays
  complete (CHANGELOG.md:151) and the FastMCP gap taxonomy (docs/known-limitations.md:368-442)
  guard against it; R0.2.0-2, R0.2.0-6 and R0.3.0-1 respond, and a gap-rate measure on public
  agent projects joins R1.2-5.
- **A self-authored benchmark.** AIBOM-Bench's corpora, harness and grader share one author with
  the tool they rank first (AUDIT.md:90-92), and corpus B was corrected after publication
  (AUDIT.md:108-113). The roadmap cites its rank as provisional; R1.2-5 is the fix.
- **Telemetry is self-reported.** `trace-diff` can show undeclared use; it cannot prove absence, and
  an agent that controls its own instrumentation can hide activity. The documentation says so.

## Traceability

Every recommendation in the seven reviews, by theme, with its status after this change. Review keys:
A "Road to #1", B "Competitive Review and Path to #1", c "The path to #1", d "SymBiote Path to #1",
e "Blueprint to Undisputed #1", G "Fixes, moves and roadmap", audit "end-to-end audit of v0.1.0".

| Theme | Recommendations | Status | Roadmap |
| --- | --- | --- | --- |
| Name collision | A gap 1; B gap 1; c gap 1, R13.a; d P0 1; e fix 1 | Done (one name everywhere; disambiguation line added); `nsb` declined | D9 |
| Static only / runtime layer | A gap 2, Layer 2; B gap 2, Now 8; c gap 2, R2; d P0 3; e fix 2 | Done for exported telemetry; more sources next | D4, X2 |
| Reproducibility | A ALOHA row; B 7.1 determinism; c R2.d; e P1 test | Done (ARCH-F1 on `main`, #132; content digest, recomputable serial and `SOURCE_DATE_EPOCH` here) | D2 |
| Tool permission model and risk classes | A gap 3; B gap 3, Now 5; c gap 3, R8.a; d P0 4; e fix 3 | Risk classes done; per-tool approval and egress reopened for repository-resident sources only: allow and ask rules, `alwaysAllow` arrays, front matter, tool annotations, bridge URLs and sandbox domain lists ([decisions](#decisions-and-non-goals)) | D7, X9, R0.3.0-2, R1.1-1 |
| Data, memory, RAG and guardrail provenance | A gap 4; B Next 1; c gap 4; d P1 1; e fix 4 | Open | X5 |
| Identity and delegation graph | A gap 5; B Next 2; c gap 5, R1.b; d P0 5; e fix 5 | Open (needs a format minor version) | X3 |
| Verifiable BOM | A gap 6; B gap 6, Now 4; c gap 6, R7.a–b; d P0 6; e fix 6; G fix 17 | Signing and verification done; gate and Action next | D3, N1, N2 |
| Enforcement, policy language, graph | A gap 7; B gap 7, Next 6–7; c gap 7, R8.d, R9; d P0 9, P1 6–7; e fix 7 | Graph done; default denials exist as findings and gates; external engines next | D7, X10 |
| Model security | A gap 8; B gap 8, Next 5; c gap 8, R7.d; d P1 5; e fix 8; G borrow 2 | Pickle and loaders critical, GGUF and HF templates checked; opcode depth and OMS next | D1, X4 |
| Hardening and offline | A gap 9; e fix 8; c 7.2.d | Done (offline default, redaction); envelope encryption declined | — |
| Maturity and governance | A gap 10; B gaps 11–12; c R11–R12; d P2 5; G move 5 | Open; depends on people | N7, N8, L3, L4 |
| Coverage honesty | G fixes 1–3, move 1; c R3; audit H1–H5 and related mediums | Done for the bypasses reproduced at 3ad53a2, the shell startup-code bypasses (#131 on `main`) and the audit residue; out-of-project links stay failures by decision; remaining limits documented | D1, D10 |
| ShadowScan bridge | A integration 1–5; B Now 2; c R1; d discovery row; G fixes 7–12, move 2 | Inventory export done; producer verification recorded and unsigned discovery failing in CI (SEC-F1, #132 on `main`); kind mapping, names and autonomy next | D8, N3, N6 |
| Compliance crosswalk | A table; B gap 10; c 7.2.c; d P1 2; e 4.4; G fix 16 | Done | D5 |
| G7 minimum elements | A; B; c R10; d; e; G standards row | Coverage report done; standard fields that would satisfy more elements in N4 | D6, N4 |
| Standard fields (services, modelCard, SPDX AI, CycloneDX 1.6) | A data model; B 7.1; c R5–R6; d P0 8; e 4.1; G fixes 13–14 | Open | N4, X8 |
| VEX states | c R8.e; G fix 15 | Open | N5 |
| CVE context | B Next; c R8.b; d P1 3 | OSV lookups exist; EPSS and KEV next | X6 |
| BOM import and SBOM merge | A AIBoMGen row; B 7.3; c R4; d; e; G move 3 | Open | X1 |
| Dependency-Track and GUAC | B Now 9; c R6.b; G borrow 7 | Open | X7 |
| Breadth (containers, IaC, workflows, frameworks) | A Layer 1; B gap 9; c gap 13; d P1 4; e P1 | Through ShadowScan and imports, not new collectors; since 18 November this covers all discovery in source code, data stores and infrastructure ([scope](#scope-shadowscan-finds-symbiote-proves)) | N3, X1, R1.0.0-rc.1-2 |
| Platforms | B gap 11; G fix 19 | macOS smoke only | L6 |
| Developer experience (one command, graph, quickstart) | A DevEx; B 7.4; c R13; d P0 10; e 5 | Graph and digest done; one-command tutorial with N8 | D2, D7, N8 |
| Audit order of work (19 items) | audit section 5 | See the audit status note below | — |

**Audit status.** Every item of the v0.1.0 audit's main body and order of work (52 in all) was
re-checked at 3ad53a2, most by running the tool: 29 done, 22 partial, 1 open. All high findings
(H1–H7) are fixed and were reproduced as fixed, as were M1, M2, M6 and M8 and the demo numbers;
the audit's three section-6 checks now give: the two-path scans compare clean, the README
quickstart matches exactly, and the self-scan still fails, correctly, on the deliberately hostile
regression fixtures. Since then D10 closed the residue on the Python MCP source-size cap, nested
case variants, registry redirects and the `scanners` input note in `action.yml`, and out-of-scope
symlinks stay failures by [decision](#decisions-and-non-goals). The rest maps to this roadmap:
integrity semantics for non-SafeTensors pins and self-re-hashes (N12), operator-side suppressions
and signed baselines (N1), SARIF schema validation (N10), a library scan pipeline with typed
coverage records (N8), and the second maintainer (L3). The P0 findings of the separate audit that
#132 names (SEC-F1, SEC-C1, ARCH-F1, DOC-F3/F7), the shell startup-code bypasses #131 closes and
the fixes of #133 to #137 are closed on `main` and merged here.

### Roadmap ids of 12 November

| Id | Item now | Release |
| --- | --- | --- |
| D1, D10 | Rshipped-1 | shipped |
| D2 | Rshipped-2 | shipped |
| D3 | Rshipped-3 | shipped |
| D4, D5, D7, D8, D9 | Rshipped-8 | shipped |
| D6 | Rshipped-6 | shipped |
| N1, N2 | R1.0.0-rc.1-5 | 1.0.0-rc.1 |
| N3 | R1.0.0-rc.1-2 | 1.0.0-rc.1 |
| N4 | R1.0.0-rc.1-3 | 1.0.0-rc.1 |
| N5 | R1.2-4 | 1.2 |
| N6 | R1.3-4 | 1.3 |
| N7 | R0.2.0-1 | 0.2.0 |
| N8 | R1.0.0-rc.1-1 (the decision), R1.0.0-3 (the documents) | 1.0.0-rc.1, 1.0.0 |
| N9 | R0.3.0-1 | 0.3.0 |
| N10 | R1.0.0-rc.1-4 | 1.0.0-rc.1 |
| N11 | Not found; the 12 November roadmap has no N11 | none |
| N12 | R1.1-9 | 1.1 |
| X1 | R1.2-2 | 1.2 |
| X2 | R1.4-1 | 1.4 |
| X3 | R1.3-3 | 1.3 |
| X4 | R1.1-4 (opcode allow-list), R1.3-1 (OpenSSF Model Signing); R0.2.0-2 is its first slice | 0.2.0, 1.1, 1.3 |
| X5 | R1.3-6 | 1.3 |
| X6 | R1.2-1 | 1.2 |
| X7, X8 | R1.3-4 | 1.3 |
| X9 | R1.1-8 | 1.1 |
| X10 | R1.4-4 | 1.4 |
| L1, L2 | R1.3-4, when Ecma ratifies CycloneDX 2.0 and when the AgBOM maintainers take the mapping | 1.3 or later |
| L3 | R1.0.0-rc.1-1 (the schema 1.0 label of the format), R1.1-5 (the people) | 1.0.0-rc.1, 1.1 |
| L4 | R1.2-5 | 1.2 |
| L5 | R1.4-2 | 1.4 |
| L6 | R1.3-7 | 1.3 |
| L7 | R1.4-1 | 1.4 |

### Enhancement plan items and gaps

Where a plan item is split, its discovery half is a
[contract requirement](#shadowscan-report-contract).

| Plan item | Item now | Plan item | Item now |
| --- | --- | --- | --- |
| P0.1 | R0.2.0-2 | P2.1 | R1.1-1 |
| P0.2 | R0.2.0-3 | P2.2 | R1.3-3 |
| P0.3 | R1.0.0-rc.1-2, CR-1 | P2.3 | R1.4-3 |
| P0.4 | R1.2-2 (manifests), CR-8 (images) | P2.4 | R1.2-4 (decisions), R1.2-3 (alerts) |
| P0.5 | R0.2.0-4 | P2.5 | R1.1-6 |
| P0.6 | R0.2.0-5 (files), CR-5 (inline) | P2.6 | R1.3-5, CR-2 |
| P0.7 | R0.2.0-6, R0.3.0-4 | P2.7 | R1.3-4 |
| P1.1 | R1.4-2, CR-4 | P2.8 | R1.2-2 (census), R0.3.0-3 (upgrade attribution in its simplest form) |
| P1.2 | R1.1-7, CR-7 | P2.9 | R1.3-2 |
| P1.3 | R1.1-2 | P2.10 | R1.2-3, CR-6 |
| P1.4 | R0.2.0-7 | P3.1 | R1.4-4 |
| P1.5 | R0.3.0-2 | P3.2 | R1.1-9 (input binding; the fleet census deferred), R1.3-2 (descriptor registry) |
| P1.6 | R1.1-3 | P3.3 | R1.1-10 |
| P1.7 | R1.1-7, CR-3 | P3.4 | R1.4-2 |
| P1.8 | R1.0.0-rc.1-3 | P3.5 | R1.4-1 |
| P1.9 | R1.0.0-rc.1-1 | P3.6 | R1.4-4 |
| P1.10 | R1.3-6 (guardrails), CR-9 (Assistants, n8n, Terraform) | P3.7 | R1.0.0-1 (fuzzing), R0.3.0-1 (accuracy regression), R1.3-7 (image), R0.2.0-1 (badge) |

| Gap | Item now | Gap | Item now | Gap | Item now |
| --- | --- | --- | --- | --- | --- |
| 1 | R1.1-1 | 10 | R1.2-4 | 19 | R1.4-2, CR-4 |
| 2 | R1.3-3 | 11 | R1.2-3 | 20 | R1.3-5 |
| 3 | R0.3.0-2 | 12 | R1.4-4 | 21 | R1.4-1 |
| 4 | R1.1-3 | 13 | R1.1-3 | 22 | Deferred under R1.1-9; no benchmark class, procurement value only |
| 5 | R1.4-3 | 14 | R1.1-10 | 23 | R1.1-9 |
| 6 | R1.1-7, CR-3 | 15 | R1.1-6 | 24 | R1.4-2, CR-4 |
| 7 | R1.1-7, CR-7 | 16 | R1.3-2 | 25 | R1.3-6 |
| 8 | R1.3-5, CR-2 | 17 | R1.2-2 | 26 | R0.3.0-2 |
| 9 | R1.3-4 | 18 | R0.3.0-3 | | |

The plan's contested items enter only as their salvaged slices: Sidenote in R1.1-2; effective
context, the unattended ledger and egress against policy in R0.3.0-2; the bootstrap manifest in
R0.2.0-3; trace-side confirmation in R1.4-1; the read-set manifest in R1.1-9; the data-recipient
register and the subject-keyed chain in R1.4-4; cross-artifact consistency in R1.2-2; loader safety
in R1.1-4 and CR-10; notebook outputs in R0.2.0-7 and CR-8. Its delivery requirements map to
R0.2.0-1 (sequencing), R1.0.0-rc.1-1 (schema versioning and cost), R0.3.0-3 (migration), R0.3.0-1
(finding catalog, test strategy, fixtures and criteria), R1.0.0-3 (documentation) and R1.0.0-1
(threat-model rows).

### The 18 November draft

| Draft item | Item now | Release | What changed |
| --- | --- | --- | --- |
| 1 Release from main | R0.2.0-1 | 0.2.0 | Merges what is open at the cut; adds turning off administrator bypass |
| 2 Fixture-first benchmark | R0.3.0-1 | 0.3.0 | A `make precision` target, not a command; floors at today's recall; the holdout moves to R1.2-5 |
| 3 Settings as security events | R0.3.0-2 | 0.3.0 | The keys are already read and rated; per-tool approval state and named alerts are the work |
| 4 Hidden-content grammar | R0.2.0-4 | 0.2.0 | Detection exists; offsets, identifier hygiene and twins remain |
| 5 Credential findings | R0.2.0-7 | 0.2.0 | Positions already read; file and pattern class only |
| 6 Determinism and keyed drift | R0.3.0-3 | 0.3.0 | Determinism ships (Rshipped-2); the TypeScript deadline, export bound and key default remain |
| 7 AgentBOM v1 contract | R1.0.0-rc.1-1 | 1.0.0-rc.1 | The native format's schema 1.0 label; ShadowScan reading it is a dependency |
| 8 ShadowScan evidence import | R1.0.0-rc.1-2 | 1.0.0-rc.1 | Imports stay declared; commit binding and lines need CR-0 |
| 9 Typed lineage graph | R1.0.0-rc.1-3 | 1.0.0-rc.1 | Native typing and impact ship; the standard fields are the work |
| 10 Lossless, registered exports | R1.0.0-rc.1-4 | 1.0.0-rc.1 | Round trip ships; SARIF schema and taxonomy registration remain |
| 11 Signed BOMs | R1.0.0-rc.1-5 | 1.0.0-rc.1 | DSSE ships (Rshipped-3); gate enforcement and Action provenance remain |
| 12 Parser hardening | R1.0.0-1 | 1.0.0 | Reads are bounded; native-parser isolation is a decision |
| 13 Release and response | R1.0.0-2 | 1.0.0 | Code-closable controls only; tiers wait for a second contact |
| 14 Docs for the supported surface | R1.0.0-3 | 1.0.0 | Every reason and the top 15 findings; times measured |
| 15 Lethal-trifecta analysis | R1.1-1 | 1.1 | High by default, not critical |
| 16 Tool-description analysis | R1.1-2 | 1.1 | Attributed to agent-bom's verified rules |
| 17 Skill and plugin script analysis | R1.1-3 | 1.1 | Static body classification of resolved scripts |
| 18 Model artifact forensics | R1.1-4 | 1.1 | Most cases ship; the allow-list and offsets remain |
| 19 Second maintainer | R1.1-5 | 1.1 | Earlier if someone is found (decision 5) |
| 20 Offline advisories | R1.2-1 | 1.2 | An operator-supplied snapshot, not a CVE database |
| 21 SBOM merge and fidelity | R1.2-2 | 1.2 | Never-complete exports ship; `pinning_state` replaces "fidelity level" |
| 22 Taint graph with reachability tiers | R1.2-3 | 1.2 | Tiers are the assurance ladder |
| 23 Execution-bound VEX | R1.2-4 | 1.2 | States from operator decisions; scoping ships |
| 24 Toxic flows and shadowing | R1.1-1 | 1.1 | Merged into the triples; shadowing dropped |
| 25 Independent benchmark run | R1.2-5 | 1.2 | Corpus C sealed until the run, then published |
| 26 Model and card signatures | R1.3-1 | 1.3 | Weight-file verification ships; OMS and cards remain |
| 27 MCP contract lockfile | R1.3-2 | 1.3 | The lockfile ships for supported revisions; 2026-07-28 and the registry remain |
| 28 Identity and authority inventory | R1.3-3 | 1.3 | Needs a native minor version |
| 29 SPDX AI profiles and downstream compatibility | R1.3-4 | 1.3 | Profiles claimed only when every field is collected |
| 30 Pinning, license and retirement policy | R1.3-5 | 1.3 | Remote-code risks ship; no retirement catalog without a source |
| 31 Completeness scoring | Rshipped-6 | shipped | Delivered as coverage (D6) |
| 32 Signed binaries; macOS and Windows qualified | R1.3-7 | 1.3 | Attested wheels and an image; Windows is a decision |
| 33 Contract-pinning proxy | R1.4-1 | 1.4 | The reference gateway's listing check and signed records |
| 34 Training-lineage ingestion | R1.4-2 | 1.4 | Attributed to the standards (L5) |
| 35 Registry resolution and squatting | R1.4-3 | 1.4 | Resolution in live mode only; typosquat detection dropped |
| 36 Evidence packages | R1.4-4 | 1.4 | Unreferenced entries listed as no evidence |

The draft's other sections map as follows: its invariants to [invariants](#invariants) and
Rshipped-1 to Rshipped-5, its scope and pair table to [scope](#scope-shadowscan-finds-symbiote-proves)
and R0.3.0-1, its absorb table to [what to absorb](#what-to-absorb-and-from-whom), its chains and
cut order to [cut order and dependencies](#cut-order-and-dependencies), its proof conditions to
[how first place is proven](#how-first-place-is-proven) and R1.2-5, its risks to
[risks](#risks-and-watch-items), and its decisions to [decisions](#decisions-and-non-goals).
