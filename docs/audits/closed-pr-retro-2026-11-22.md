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
claimed to close. Five are fixed on this branch with regression tests (below). The rest are
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
| `0de28359` | A SafeTensors polyglot whose pickle call sits past the walk's 4,096-opcode or 64 KiB bounds was rated safe while `pickle.load` ran it (#376 left it as a design decision). The undecided walk is repeated over the header plus 64 KiB, charged to the shared inspection budget; 0 of 3,000 benign headers change rating | Medium | `scanners/model.py` (`_safetensors_polyglot`) | `test_a_polyglot_padded_past_the_pickle_bounds_is_rated_critical[4200]`, `test_the_wide_polyglot_walk_is_charged_to_the_shared_budget` |
| `1e830999` | A suppression on an MCP, IDE, RAG or A2A record bound no content, so it kept matching after the configuration changed (#133). **Breaking:** such suppressions go stale once | High | `validators/risk.py` (`component_content_digest`) | `test_a_suppression_on_an_mcp_server_does_not_follow_a_changed_configuration` |

Each of these files is also held by open pull request #380. The commits are small and
self-contained so that #380's fixer can take them, or #380 can land first and this branch
merges forward. The cross-check found that #380's head `ea55d1f3` already fixes the
suppression finding by its own route, so `1e830999` is redundant once #380 lands; its
regression test is still worth keeping. The other three are on no open head.

## Ranked findings still open

Severity and confidence are this review's. "PR status" is the result of running the lane's
probe against each open head (see [cross-check](#cross-check-against-the-open-pull-requests)).

| # | Severity | Finding | Where | Introduced, or claimed and missed | PR status |
| --- | --- | --- | --- | --- | --- |
| 1 | High | A filesystem server root of `${HOME}`, `~`, `${workspaceFolder}` or a symlink to `.claude` is not a steering surface, so the critical finding never fires | `control_plane_audit.py` `_covers_steering_path` | #288; missed by #312, #330 | Fixed on #377 `99c4b054` |
| 2 | High | Hook targets behind `VAR=`, `cd &&`, `exec`, `bash -c`, `;` or a pipe are never resolved and record no gap; a baseline diff misses a swapped script | `control_plane_audit.py` `_extract_local_script_target` | #288; missed by #330 | #377 adds shell splitting; re-run lane M `probe_cp2` P2/P3 on its head before merge |
| 3 | High | Skill and command preambles: only the line-start form in `SKILL.md`; `.claude/commands/*.md` is never scanned | `control_plane_audit.py` `_PREAMBLE_RE` | #288 | Partial on #377 (inline form in skills); commands directory open |
| 4 | High | Front-matter grants and hooks in subagents, commands and skills are never rated; `frontmatter_tools` is unwired | `settings_precedence.py` | #277; missed by #320 | Not fixed by #382 |
| 5 | High | A plugin's `hooks` given as a path, and marketplace-nested plugins, are not read | `ide_agents.py` plugin reader | #130; missed by #320 | Not fixed by #382 |
| 6 | High | Glob prefixes `Bash(ba*)`, `Bash(pyth*)` grant a shell with no oversight gap | `settings_precedence.py`, `ide_agents.py` | #277, #130; missed by #226/#251 | Not fixed by #382 (only `sh*`, `python*`) |
| 7 | High | Code-built MCP launchers and servers under `build`, `dist`, `docs`, `examples`, `tests`, `test`, `benchmarks` at any depth are skipped with no gap (A2A and prompts use the same set) | `mcp_sources.py` `SOURCE_SEARCH_SKIPPED`, `a2a.py` | #128, #130, #263 | Not fixed by any open PR |
| 8 | High | A2A 0.3 field `additional_interfaces` is ignored, so a plaintext alternative interface drops the transport finding | `a2a.py` | #126 | Not fixed by any open PR |
| 9 | High | A runner given as a path into the checkout (`./npx`, `bin/uvx`, `./docker`) is recorded as a pinned registry package | `mcp_launch.py` `_classify` | #130; missed by #329 | Not fixed by #383 |
| 10 | High | `uv.lock` wheel and sdist URLs and hashes are never checked; an artifact from any host is reported as `pkg:pypi` from pypi.org | `registry.py` `_resolve_python_lockfiles` | #128; missed by #149 | Not fixed by #378 or #383 |
| 11 | High | Escaped hidden characters in Gemini TOML commands and `.github/prompts/*.prompt.yml` are not decoded | `prompt.py` | #263, #318 | Fixed on #381 `3c738ad7` |
| 12 | High | C0/C1 controls (NUL, ESC, NEL) are not reported or stripped; a NUL also makes the file binary in PR review | `prompt.py` `_hidden_counts`, `text_poisoning.py` | #130, #291 | Not fixed by #378 or #381 |
| 13 | High | The `@path` import tokenizer uses Python `\s` (U+0085, U+001C–1F) and no escaped space; the import is never inventoried and no gap is recorded (host regex assumed) | `prompt.py` `_IMPORT` | #130 | Not fixed |
| 14 | High | `diff-instructions` ignores Copilot `mcp-servers` front matter and a `mode` change (schema assumed) | `instruction_diff.py` | #276 | Not fixed by #381 |
| 15 | High | `validate --project` without the binding key passes while launch values, env values and imported content differ | `completeness.py` `validate_against_project` | #203 fixed `diff` only | Not fixed by #380 |
| 16 | High | A reviewed suppression on a configuration record survives any configuration change | `validators/risk.py` | #133 | Fixed on #380 `ea55d1f3`, and on this branch `1e830999` |
| 17 | High | Deny rule coverage: a bare deny clears `my__filesystem` (Antigravity R-CRIT-02, confirmed, rated High) | `control_plane_audit.py` | #312, #330 | Not fixed by #377 |
| 18 | Medium | Hook-script classifier misses `ssh`, `scp`, `Invoke-WebRequest`, writes to `.mcp.json` or `.claude/hooks`, and `"behavior":"allow"` output | `control_plane_audit.py` | #288 | Partial on #377 (`fetch("…")` only) |
| 19 | Medium | Trifecta legs come only from a fixed tool-name list; `browser_navigate`, `read_text_file`, `slack_post_message` give nothing and no unassessed count | `trifecta.py` | #272 | Not fixed by #382 |
| 20 | Medium | CycloneDX projection-3 `services[].endpoints` copies supplied endpoint URLs verbatim (userinfo, query tokens, `javascript:`, `file:`) | `cyclonedx.py` `_services` | #279; missed by #347 | Not fixed by #380 |
| 21 | Medium | Offline OSV matching misses PEP 440 local builds (`torch==2.0.0+cu118`) for listed versions and `last_affected` | `offline_advisories.py` | #273, #306 | Not fixed by #380 |
| 22 | Medium | Root-level npm declarations compare ranges with PEP 440 instead of node-semver | `sbom_import.py` | #280, #332; missed by #353 | Partial on #383 (lock check fixed, root not) |
| 23 | Medium | An unqualified supplier purl against a private-index lock raises no conflict | `sbom_import.py` `_provenance_disagrees` | #332 | Not fixed by #383 |
| 24 | Medium | Node lock versions outside the declared range are accepted (npm, pnpm, Yarn 1) | `registry.py` | #128, #130 | Not fixed |
| 25 | Medium | Dockerfile `COPY --from=<image>` and `RUN --mount=from=<image>` are ignored | `registry.py` | #126 | Not fixed |
| 26 | Medium | `project.dynamic` dependencies and `setup.py` give a positive "no AI dependencies" | `registry.py` | #52 | Not fixed |
| 27 | Medium | A cleartext index in requirements, pip.conf or .npmrc is Low; in `uv.lock` it is High | `registry.py` `_redirect` | #126, #130 | Not fixed |
| 28 | Medium | A duplicated `source`/`src` key in `docker run --mount` silences the host-root mount | `mcp_launch.py` `_host_source` | #130; missed by #329 | Not fixed by #383 |
| 29 | Medium | `infisical run --command` is not read (semantics assumed); podman `--cap-add` comma lists are not split | `mcp_launch.py` | #130 | Not fixed by #383 |
| 30 | Medium | MCP client APIs in the SDK (`ClientSessionGroup`, `SseServerParameters`), fastmcp `Client`, mcp_use and others start servers with no gap | `mcp_sources.py` | #138, #149, #203 | Not fixed |
| 31 | Medium | `_launch_words` runs shlex with no length cap (quadratic; its twin is capped) | `mcp.py` | #226, #255 | Not fixed |
| 32 | Medium | Credentials in refused, duplicate, replaced or normalised-away servers print through a sibling (13 shapes) | `mcp.py` `_file_secrets` | #226, #247, #301 | Partial on #327 (2 shapes remain); #384 no longer carries scrubbing |
| 33 | Medium | A credential in a JSON-valued env or header over 64 KiB or depth 8 raises nothing and no gap | `mcp_credentials.py` `_json_hits` | #255 | Not fixed |
| 34 | Medium | Continue `apiKey`/`requestOptions.headers` and Codex `experimental_bearer_token` get a gap but no `credential_exposure` | `mcp.py` | #301 vs #255 | Not fixed |
| 35 | Medium | A code-built tool with a wrapped callee `(server.tool as any)(…)` is dropped with no gap | `ts_tools.py` | #84; missed by #149 | Not fixed by #381 |
| 36 | Medium | LangChain `langchain.agents.tool`, `crewai_tools.tool`, `create_agent`/`create_react_agent` tools, smolagents base tools give no tool and no gap | `python_tools.py` | #128, #319 | Not fixed by #381 |
| 37 | Medium | Hook handlers of type `http`, `prompt`, `agent` are counted but never rated (schema assumed) | `ide_agents.py` | #226 | Not fixed by #382 |
| 38 | Medium | The settings layer merge drops committed findings | `ide_agents.py` | #81, #130 | Partial on #382 (findings kept, counts still zeroed) |
| 39 | Medium | The two rule classifiers drift (`mcp__x` vs `mcp__x__*`, `Bash(bash)`) | `ide_agents.py`, `settings_precedence.py` | #277 | Partial on #382 |
| 40 | Medium | Codex profiles and `notify`, Gemini hooks and `tools.allowed`, Cursor `cli.json` are digested but not rated | `ide_agents.py` | #130, #226 | Not fixed by #382 |
| 41 | Medium | The hook ladder rates `npx -y`, `uvx`, `docker run`, non-http schemes and `ssh`/`nc` Medium | `ide_agents.py` | #226 | Not fixed by #382 |
| 42 | Medium | Brace-group fetch-and-execute `{ curl …; } | bash` is High, not Critical (Muse verification, new) | `ide_agents.py` | #251, #375 | Not fixed by #382 |
| 43 | Medium | A vendor credential in `.claude/settings.json` `env` gets no finding; the same value in `.mcp.json` is High (Muse verification, new) | `ide_agents.py` | #255 | Not fixed by #382 |
| 44 | Medium | A computed PowerShell word with a computed payload (`$p -ec $b`) is Medium; it was Critical on the closed #341/#343 branch | `ide_agents.py` `_computed_powershell` | #320 narrowed it | Not fixed; patch verified on a copy (9,969 hook tests pass) |
| 45 | Medium | `diff-instructions` does not read prompt templates | `instruction_diff.py` | #276 | Fixed on #381 |
| 46 | Medium | `diff-instructions` compares hidden Unicode in raw text only | `instruction_diff.py` | #276 | Partial on #381 |
| 47 | Medium | A new always-loaded instruction file, or a removed guardrail file, is not a change | `instruction_diff.py` | #276 | Not fixed by #381 |
| 48 | Medium | TP-SIDENOTE-004 is O(P×N), about 17 s per MB per tool | `text_poisoning.py` | #291 | Not fixed by #381 |
| 49 | Medium | Lost with closed #261: skill and hook scripts that pipe a download into a shell are not reported | `prompt.py` | #261 closed unmerged | Not fixed |
| 50 | Medium | A SafeTensors polyglot whose pickle call sits past the 4,096-opcode or 64 KiB walk is rated safe (#376 item left as a design decision); lane E's wider-sample fix gives 0 of 3,000 benign false positives | `model.py` | #376 | Fixed on this branch `0de28359` (#385 merged without it) |
| 51 | Medium | The shared model inspection budget is hard-coded, so earlier files turn a later GGUF's critical template finding into high unknown | `model_formats.py` | #130 | Not fixed |
| 52 | Medium | `--no-isolation`: the launcher can write the verifier's memory and read its environment as the same uid | `live/pinned_process.py` | #203, #228, #231 | Not fixed by #379 |
| 53 | Medium | Draft-04 `enum` reaches jsonschema's quadratic `uniqueItems`; a server still verifies past the deadline | `live_mcp.py`, `live/verify.py` | #130, #202 | Fixed on #381 (with a false refusal of valid enums) |
| 54 | Medium | Served descriptors never run the text-poisoning rules | `live/inventory.py`, `live/verify.py` | #130 | Partial on #381 (hidden characters only) |
| 55 | Medium | The trace redactor runs on every distinct identifier; about one hour of runner time within the documented bounds | `otlp.py` | #138 | Not fixed |

Lows (49) and Infos are listed per lane in the session's lane reports and summarised on the
ledger. The ones worth a quick change are: `trace-diff` and `import-shadowscan` ignoring
`--detailed-exit-codes`; three emitted risk categories (`source_conflict`,
`source_conflict_unresolved`, `declaration_conflict`) missing from the SARIF rule catalog;
`diff` printing "No changes detected." while its gate fails; an int64 schema bound
dropping a whole MCP server under RFC 8785's integer domain; and confined reads following a
hard link out of the root.

Several tests are load-sensitive under `pytest -n 8` and passed alone:
`test_prompt_imports::test_scan_memory_grows_with_the_files_not_with_the_paths_they_reference`,
`test_pinned_process_isolation::test_the_wrapper_and_a_launcher_that_watches_its_parent_end_with_a_crashed_client`,
`test_typescript_analysis_bounds::test_a_source_over_a_budget_is_refused_for_that_budget_on_a_stalled_machine`
(its parse budget counts wall time while the machine is busy) and
`test_scan_of_collected_payload_files_finishes`.

## Cross-check against the open pull requests

Every High and Medium above was re-run against the open heads #327 `2d5d9085`, #377
`99c4b054`, #378 `0267f41d`, #379 `f8508052`, #380 `ea55d1f3`, #381 `3c738ad7`, #382
`6cd15bd4`, #383 `9fc40f71`, #384 `4e2459b5` and #385 `73b4fbe2`, by running the lane's
probe on each tree. Seven are fixed outright on a head and eight in part; the status column
above records which. Three side effects of the open heads:

- #381 refuses a valid 1,000-member object `enum` with no dialect. That fails closed but
  rejects valid servers.
- #384's head (`4e2459b5`, reduced to F-370-1) no longer carries the #255 scrubbing its
  title names; its leak probes give the same result as `main`.
- #382 brings `bash.exe` into agreement in both rule classifiers, but `Bash(bash)`,
  `mcp__github` and `Bash(/)` still drift.

## Recommendations

1. **Land the branch commits or their equivalents.** The uv-sources lock fix, the
   precision-gate registration, the trace ambiguous-match fix and the SafeTensors polyglot
   fix are not on any open head.
2. **Close the twin-path class structurally, not per finding.** Most findings above are a
   second code path that kept the old behaviour. Three changes would stop the pattern:
   one shared decoded-text view for the prompt collector, the instruction diff gate and the
   text-poisoning rules; one rule classifier exported from `settings_precedence.py` for both
   uses; and one tokenizer for shell-split launch values with a single bound.
3. **Make unknown fail closed by default in the collectors that still allowlist.** The
   source search skip set, the MCP client API table, the framework roots and the
   per-host settings keys all treat "not recognised" as "nothing there". Each should record
   a gap for anything it skipped, so a new form shows up as a gap instead of silence.
4. **Require the binding key for `validate --project` when the collection redacts.** `diff`
   already treats unbound values as an alert; `validate` and `risk --project` should too.
5. **Add a lock regeneration job.** A network-limited, token-less `pull_request` job that
   runs `check_locks.py --regenerate` and `git diff --exit-code` closes the forged `# via`
   and extra-hash findings, which the offline check cannot see.
6. **Stabilise the load-sensitive tests** listed above before the next merge batch, since
   each one has already cost a re-run today.




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

All 43 hunks that the closed integration branches #341, #343 and #372 carry beyond their
member pull requests were checked by running probes on `main` and on each branch tree: 30
are on `main` in a stricter form, 12 in an equivalent form, and one is partly lost (row 44
above: a computed PowerShell payload). Nothing else from those branches needs reviving.

