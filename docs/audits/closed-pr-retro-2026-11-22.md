# Closed pull-request retrospective — 2026-11-22

Baseline: `main` at `e03f980e` (after #375). Independent line-by-line review of the code that the
closed pull requests #2–#376 left on `main`, by Claude Code session `great-fermat-nyhrnb`, at the
maintainer's request and recorded on the merge coordination ledger (issue 200). It continues the
[2026-11-19 review](pull-request-review-2026-11-19.md) (#117–#291), the
[2026-11-03 review](closed-pr-review-2026-11-03.md) (#74–#116) and the
[2026-11-02 review](closed-pr-review-2026-11-02.md) (#2–#73), which checked what each pull request
landed. This review asks a different question of the same history: what the landed code still gets
wrong.

## Scope and method

- **Unit of review: the live code, not the pull-request body.** The source, scripts and workflows on
  `main` were split into eighteen lanes by subsystem. Each lane's reviewer read every line of its
  files, with the list of pull requests that landed each file (from first-parent history and
  `refs/pull/*/head`), and attacked what those pull requests added or claimed to fix: missed gaps,
  sibling bypasses of a landed fix, later regressions, fixes lost with a pull request closed
  without merging, test quality and documentation drift. Reference behaviour came from the real
  tools (bash, CPython's pickle and zipfile, npm and uv, the vendored CycloneDX, SPDX and SARIF
  schemas), not from the project's own documentation.
- **Every Medium-or-higher finding was reproduced** against the installed `requirements-ci.lock`
  environment (Python 3.13.18) before it was recorded. Evidence is labelled verified, inferred or
  assumed.
- **Independence.** The lane reviewers did not read the ledger, the other sessions' retro posts of
  2026-11-22 or `docs/audits/`. Overlaps with Muse Batches 1–4, Antigravity's 14:43 UTC review and
  `sharp-babbage`'s Parts 1–2 were identified afterwards and are recorded as confirmations or
  refutations, not as new findings. A separate verification lane re-reproduced a sample of those
  sessions' Medium-or-higher findings.
- **Landing check.** Every first-parent landing after the 2026-11-19 baseline (`f6045e2`) was
  measured as the earlier reviews measured theirs: the share of its added lines (eight characters
  or more, whitespace-stripped, excluding `CHANGELOG.md`, lock files, JSON and `docs/audits/`)
  still in the same file on `main`, and whether every test function it added still exists by
  name. Every closed-unmerged pull request was measured the same way against its merge base.

## Verdict

No Critical finding survived reproduction. **19 High and 39 Medium findings reproduce on
`main` at `e03f980e`**, most of them sibling forms of a class that a merged pull request
claimed to close. Four are fixed on this branch with regression tests (below). The rest are
either already fixed on an open pull request head, recorded in the table with that head, or
open with a recommended fix. Three earlier reviews were checked independently: of the
Medium-or-higher findings re-run, Muse's batches gave 23 confirmed, 4 partial and 1 refuted,
and Antigravity's gave 26 confirmed, 10 partial, 4 refuted and 2 untestable.

The pattern behind most findings is the same: a fix lands for the form a reviewer showed and
its twin path keeps the old behaviour. Examples are the precision gate added to CI but not
to the workflow checker's required commands, the trace identity gate added for one candidate
but not several, the suppression binding added for prompts but not configuration records,
and the hidden-character decoding added for Markdown front matter but not TOML or YAML
commands. The structural recommendation at the end addresses that.

## Fixed on this branch

| Commit | Finding | Severity | Where | Test that fails before and passes after |
| --- | --- | --- | --- | --- |
| `eba4b73b` | `make lock` applied the checkout's `[tool.uv.sources]` despite `--no-config`, so a pull request could route one dependency to an index it names; the lock showed an ordinary pin and the offline check passed. Reproduced with uv 0.11.32 against a loopback index | High | `scripts/check_locks.py` (`regenerate`, `check`) | `test_regeneration_ignores_package_sources_from_the_checkout`, `test_uv_settings_in_pyproject_fail_the_lock_check` (3 cases) |
| `a010e6c6` | The precision gate (`--fresh`) and the parser fuzz smoke gate were not required commands, so dropping them or scoring from a committed file kept every check green (#302) | Medium | `scripts/check_workflows.py` (`REQUIRED_COMMANDS`) | two new `test_a_gate_job_hollowed_out_under_its_name_is_rejected` cases, `test_a_precision_gate_scored_from_a_committed_file_is_rejected` |
| `10307006` | `trace-diff` checked reported definition hashes and SPIFFE IDs only for a single candidate; with two servers sharing a tool name, a foreign or unreadable hash passed with exit 0 (#281). Reproduced on `main` and on #380's head | High | `trace_evidence.py` (`reconcile`, `_gate`, `_findings`) | `test_an_ambiguous_tool_reporting_a_hash_no_candidate_declares_fails_the_gate` (2), `test_an_ambiguous_agent_reporting_a_foreign_spiffe_id_fails_the_gate`, positive control `test_an_ambiguous_tool_reporting_one_candidates_hash_passes` |
| `1e830999` | A suppression on an MCP, IDE, RAG or A2A record bound no content, so it kept matching after the configuration changed (#133). **Breaking:** such suppressions go stale once | High | `validators/risk.py` (`component_content_digest`) | `test_a_suppression_on_an_mcp_server_does_not_follow_a_changed_configuration` |

Each of these files is also held by open pull request #380. The commits are small and
self-contained so that #380's fixer can take them, or #380 can land first and this branch
merges forward.

## Ranked findings still open

Severity and confidence are this review's. "PR status" is the result of running the lane's
probe against each open head (see [cross-check](#cross-check-against-the-open-pull-requests)).

<!-- OPEN -->

## Cross-check against the open pull requests

<!-- CROSSCHECK -->



## Landing check, #253–#376

| Landing | Date | Pull request | Added lines | Kept | Tests added | Tests missing on `main` |
| --- | --- | --- | --- | --- | --- | --- |
| `32eef2ee` | 2026-11-19 | #253 | 123 | 123 (100%) | 5 | none |
| `d15afa0d` | 2026-11-19 | #290 | 9 | 6 (66%) | 0 | none |
| `f635983f` | 2026-11-19 | #267 | 16678 | 16678 (100%) | 0 | none |
| `f03c4075` | 2026-11-19 | #254 | 1001 | 990 (98%) | 31 | none |
| `6f9f5cf7` | 2026-11-19 | #282 | 1 | 1 (100%) | 0 | none |
| `cbe2849b` | 2026-11-19 | #257 | 373 | 373 (100%) | 14 | none |
| `44396c22` | 2026-11-20 | #266 | 288 | 280 (97%) | 4 | none |
| `dee837bc` | 2026-11-20 | #262 | 1052 | 1038 (98%) | 29 | none |
| `c30bce66` | 2026-11-20 | #258 | 1733 | 1707 (98%) | 84 | none |
| `766c4eb8` | 2026-11-20 | #298 | 106 | 105 (99%) | 9 | none |
| `038c7a2c` | 2026-11-20 | #300 | 42 | 42 (100%) | 2 | none |
| `1598d482` | 2026-11-20 | #265, #292, #299 | 427 | 427 (100%) | 13 | none |
| `4f237e98` | 2026-11-20 | #278 | 73 | 52 (71%) | 4 | test_sources_with_a_path_keep_their_order_at_the_cut |
| `d547c14b` | 2026-11-20 | #263 | 1074 | 1050 (97%) | 48 | none |
| `1168ffc2` | 2026-11-20 | #256, #293, #295, #301 | 2474 | 2464 (99%) | 123 | none |
| `8e5406c6` | 2026-11-20 | #283 | 116 | 116 (100%) | 4 | none |
| `4dae03aa` | 2026-11-20 | #264, #269, #275, #302 | 2768 | 2721 (98%) | 68 | none |
| `9293d462` | 2026-11-20 | #268 | 1561 | 1493 (95%) | 10 | none |
| `f0404849` | 2026-11-20 | #273 | 2255 | 2073 (91%) | 36 | none |
| `03f628fb` | 2026-11-20 | #305 | 15 | 15 (100%) | 0 | none |
| `5d85d94d` | 2026-11-20 | #287, #260, #304 | 2367 | 2362 (99%) | 52 | none |
| `d16dc44a` | 2026-11-20 | #296, #297, #306 | 1206 | 1164 (96%) | 26 | none |
| `9f2904b5` | 2026-11-21 | #255 | 2769 | 2753 (99%) | 90 | none |
| `be357f0f` | 2026-11-21 | #291 | 2068 | 1986 (96%) | 54 | none |
| `e7138bbd` | 2026-11-21 | #279 | 2239 | 2199 (98%) | 26 | none |
| `30bb9da6` | 2026-11-21 | #288 | 1680 | 1608 (95%) | 13 | none |
| `a9d2a023` | 2026-11-21 | #309 | 10 | 10 (100%) | 0 | none |
| `8912c070` | 2026-11-21 | #310 | 21 | 21 (100%) | 1 | none |
| `7d3888e7` | 2026-11-21 | #276 | 1586 | 1546 (97%) | 26 | none |
| `cc0d2a93` | 2026-11-21 | #272 | 1823 | 1759 (96%) | 37 | none |
| `e00a4dd1` | 2026-11-21 | #277 | 1659 | 1659 (100%) | 15 | none |
| `374eba06` | 2026-11-21 | #280 | 2320 | 2132 (91%) | 11 | none |
| `d310d75d` | 2026-11-21 | #270 | 1432 | 1430 (99%) | 9 | none |
| `eb81c8c2` | 2026-11-21 | #307 | 53 | 53 (100%) | 2 | none |
| `8d4f0e69` | 2026-11-21 | #313, #308, #311, #338 | 421 | 402 (95%) | 11 | none |
| `8b3d8bf4` | 2026-11-21 | #336, #337, #335, #339 | 181 | 180 (99%) | 5 | none |
| `fea5e852` | 2026-11-21 | #349 | 377 | 374 (99%) | 11 | none |
| `c7d18cf9` | 2026-11-21 | #315, #316, #352, #344 | 105 | 105 (100%) | 4 | none |
| `9c58cd5f` | 2026-11-21 | #294 | 1027 | 1026 (99%) | 25 | none |
| `fa41df4f` | 2026-11-21 | #326, #324, #353 | 312 | 305 (97%) | 5 | none |
| `c6adda88` | 2026-11-21 | #331, #346, #314, #354 | 876 | 876 (100%) | 29 | none |
| `5692a2e4` | 2026-11-21 | #340 | 125 | 125 (100%) | 4 | none |
| `31706351` | 2026-11-22 | #281 | 2344 | 2332 (99%) | 28 | none |
| `d437be4d` | 2026-11-22 | #334 | 948 | 946 (99%) | 26 | none |
| `2650e82b` | 2026-11-22 | #364 | 58 | 58 (100%) | 1 | none |
| `fd86afa6` | 2026-11-22 | #348 | 494 | 487 (98%) | 18 | none |
| `de24655f` | 2026-11-22 | #328 | 1056 | 1033 (97%) | 26 | none |
| `4c539989` | 2026-11-22 | #329 | 756 | 756 (100%) | 34 | none |
| `cc6e8672` | 2026-11-22 | #312 | 721 | 699 (96%) | 27 | none |
| `f95d0c89` | 2026-11-22 | #320 | 752 | 750 (99%) | 38 | none |
| `ca9bf4df` | 2026-11-22 | #332 | 1480 | 1480 (100%) | 29 | none |
| `100f17c9` | 2026-11-22 | #345 | 721 | 720 (99%) | 21 | none |
| `7ef580f4` | 2026-11-22 | #365 | 245 | 238 (97%) | 9 | none |
| `63047bce` | 2026-11-22 | #318 | 1071 | 1071 (100%) | 50 | none |
| `bc0c37ee` | 2026-11-22 | #323 | 1031 | 1031 (100%) | 34 | none |
| `771aebd6` | 2026-11-22 | #330 | 477 | 477 (100%) | 20 | none |
| `fd336a95` | 2026-11-22 | #347 | 846 | 846 (100%) | 34 | none |
| `a33f3d6e` | 2026-11-22 | #322 | 1350 | 1350 (100%) | 50 | none |
| `c0e3bc60` | 2026-11-22 | #319 | 1816 | 1816 (100%) | 60 | none |
| `6b8834de` | 2026-11-22 | #325 | 1458 | 1458 (100%) | 31 | none |
| `01a3f248` | 2026-11-22 | #333 | 805 | 805 (100%) | 26 | none |
| `7dde009d` | 2026-11-22 | #351, #373 | 541 | 541 (100%) | 4 | none |
| `0552b9fe` | 2026-11-22 | #371, #374 | 324 | 324 (100%) | 5 | none |
| `b0133386` | 2026-11-22 | #376 | 343 | 343 (100%) | 13 | none |
| `e03f980e` | 2026-11-22 | #350, #375 | 169 | 169 (100%) | 3 | none |

Every landing keeps at least 91% of its lines except two small ones: #290 (3 of 9 lines were CI time limits that #298 and #304 raised again) and #278 (21 of 73 lines; #283 reworked the graph search the same day and renamed its one missing test `test_sources_with_a_path_keep_their_order_at_the_cut`). No test added by any landing is missing from `main` except that renamed one. No merged change was silently reverted.


## Closed without merging

| Pull request | On `main` by ancestry | Added lines kept (all) | Added lines kept (`src/`, `scripts/`) | Title |
| --- | --- | --- | --- | --- |
| #5 | not ancestor | 7141/57 (0%) | 3709/0 (0%) | WP5: snapshot engine — builder, chain state with anti-rollback, digest-based diff (superseded by #6) |
| #20 | not ancestor | 61/4 (6%) | 46/0 (0%) | Verify artifact signatures against explicit identities and canonicalize signed data (superseded by #25) |
| #22 | not ancestor | 335/128 (38%) | 197/0 (0%) | Confine model and registry scanner file reads (superseded by #26) |
| #39 | not ancestor | 227/8 (3%) | 148/0 (0%) | Generate schema-valid SPDX 3.0.1 and validate both interchange formats offline (superseded by #48) |
| #43 | not ancestor | 1776/13 (0%) | 538/0 (0%) | Detect disguised model weights, recover declared MCP tools and bind static evidence to source (superseded) |
| #58 | not ancestor | 253/48 (18%) | 207/33 (15%) | Restore the scan CLI and bind model evidence and coverage to the actual collection (superseded) |
| #59 | ancestor | 0/0 (100%) | 0/0 (100%) | Prevent a scanned checkout from disabling the Action's validation policy (superseded) |
| #60 | ancestor | 0/0 (100%) | 0/0 (100%) | Attest inventory benchmark results for the tested release wheel (superseded) |
| #61 | ancestor | 0/0 (100%) | 0/0 (100%) | Collect literal Python MCP SDK tool declarations and report unsupported callbacks (superseded) |
| #91 | not ancestor | 1/0 (0%) | 0/0 (100%) | deps: update tree-sitter requirement from &lt;0.26,&gt;=0.25 to &gt;=0.25,&lt;0.27 |
| #104 | not ancestor | 10/0 (0%) | 0/0 (100%) | docs: point stale repo references to the Hunzee-VC canonical location |
| #114 | not ancestor | 581/354 (60%) | 113/109 (96%) | docs: organize README and docs by why/what/how; close hygiene gaps |
| #160 | not ancestor | 29/7 (24%) | 0/0 (100%) | fix(security): harden test socket guard against UDP and non-standard addresses |
| #170 | not ancestor | 40/8 (20%) | 22/6 (27%) | security: a checkout policy cannot pass a failed scan gate in CI |
| #209 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(mcp): bind Python helper arguments by call semantics |
| #210 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(mcp): gap on FastMCP servers reached through SDK handles |
| #211 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(registry): read yarn.lock as Yarn does and refuse repeated selectors |
| #212 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(mcp): bind named tool approval and filter lists without the key |
| #213 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(mcp): fail on case variants of nested MCP client files |
| #214 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(registry): unbind npm packages that a pnpm or Bun patch changes |
| #215 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(registry): keep lockfile key credentials out of record locators |
| #216 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(prompt): report Markdown and HTML forms that render as nothing |
| #217 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(live): kill the PID namespace init when a pinned session ends |
| #219 | ancestor | 0/0 (100%) | 0/0 (100%) | fix: stop batch-4 CI failures in the walk budget and template heuristic |
| #224 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(launcher): kill CLONE_PARENT escapees under --no-isolation (stacked on #153) |
| #229 | not ancestor | 1227/1163 (94%) | 471/427 (90%) | fix(model): rate a renamed pickle padded past an inspection bound by content |
| #234 | not ancestor | 677/653 (96%) | 259/254 (98%) | fix(ci): close ways a pull request could hollow out its own gates; run CodeQL on workflows in CI (audit 2026-11-16) |
| #235 | ancestor | 0/0 (100%) | 0/0 (100%) | ci: give the test and coverage suites room for slow hosted runners |
| #248 | ancestor | 0/0 (100%) | 0/0 (100%) | Merge #239's follow-up (npx/npm argument handling, audit 2026-11-16, batch B2a) |
| #259 | not ancestor | 1076/36 (3%) | 331/28 (8%) | feat(mcp): report literal credentials by file, position and type |
| #261 | not ancestor | 1209/57 (4%) | 497/45 (9%) | feat: report instruction-bearing tool descriptions and skill scripts that run a download in a shell |
| #265 | not ancestor | 302/302 (100%) | 72/72 (100%) | fix(mcp): count the TypeScript parse deadline after the parser is built |
| #284 | not ancestor | 1719/2 (0%) | 1226/0 (0%) | feat(provenance): model forensics depth, alias/registry provenance, guardrails, memory, and training lineage (R1.1-4, R1.3-5, R1.3-6, R1.4-2) |
| #285 | not ancestor | 1568/4 (0%) | 1141/0 (0%) | feat(mcp): deterministic MCP contract lockfile and opt-in contract-pinning proxy (Roadmap items 27 & 33) |
| #286 | not ancestor | 1149/4 (0%) | 809/0 (0%) | feat(governance): model pinning, AIROM retirement policy, and dual-axis completeness scoring (Roadmap items 30 & 31) |
| #289 | not ancestor | 1098/4 (0%) | 783/0 (0%) | feat(runtime): add read-set input binding, MCP 2026-07-28 descriptor registry, signed gateway decisions, and evidence pack (R1.1-9, R1.3-2, R1.4-1, R1.4-4, R1.3-7, Rshipped-4) |
| #296 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(advisories): a stale or undated offline feed is not a complete result |
| #297 | ancestor | 0/0 (100%) | 0/0 (100%) | fix(advisories): index offline advisories by version and bound what still multiplies |
| #317 | not ancestor | 19/0 (0%) | 3/0 (0%) | Require independent approval for publishing deployments |
| #341 | not ancestor | 1558/1460 (93%) | 890/808 (90%) | Batch C: #332, #331, #329 and #320 (SBOM identities, VEX inputs, launch wrappers, IDE hooks) |
| #343 | not ancestor | 1128/1072 (95%) | 675/630 (93%) | Batch C: #332, #331 and #320 (SBOM identities, VEX inputs, IDE hooks) |
| #372 | not ancestor | 7919/7794 (98%) | 3206/3118 (97%) | Integrate audited & hardened PRs #318, #319, #322, #323, #325 (+#321), #330, #333, and #347 |

A closed pull request whose head is an ancestor of `main` reached `main` through another pull request (#209–#217 and #219 through #226; #224 through #228; #235 through #236; #248 through #250; #296 and #297 through #306). #229 and #234 are not ancestors but keep 90% and 98% of their source lines (they landed through #230 and #236 at other heads). #265 keeps every line (through #299). The feature pull requests #284, #285, #286 and #289 were closed on recorded decisions and keep nothing, as intended; #317 (wontfix) likewise.

Three closed integration branches keep most but not all of their source lines: #341 (90%), #343 (93%) and #372 (97%). The lines they leave behind are hardening commits made on the integration branch after the member pull requests were reviewed, which the member pull requests then merged without. See [lost hardening](#lost-hardening) for the disposition of each.

## Lost hardening

<!-- LOST -->

