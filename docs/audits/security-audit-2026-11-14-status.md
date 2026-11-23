# Status of the 2026-11-14 security audit findings

This note records, finding by finding, where the
2026-11-14 security audit (archived in git history) stands on `main` at
`a604c33` (batch 1, #202, merged) plus the commits on the branch that carries this
note. It was produced with Claude Code at the maintainer's request on 2026-11-15; no
second person has reviewed it. Re-check each claim against the commit it names.

- [How each status was established](#how-each-status-was-established)
- [Summary](#summary)
- [Findings](#findings)
- [Information items](#information-items)
- [New finding from this pass](#new-finding-from-this-pass)
- [Deferred: pin pip (L20)](#deferred-pin-pip-l20)
- [Decisions for the maintainer](#decisions-for-the-maintainer)

## How each status was established

- **Fixed** means the code was read on `main` and the regression test named for the
  finding passes there. For every code fix that batch 1 merged (the M and L rows), the
  test was also run against the parent of the fixing commit (`eddf85e^`, `8a2250f^`,
  `18b93aa^`, `59aec4f^`) and failed there, except where the table says otherwise. The
  T rows are test additions; their tests pass on `main`. The 34 batch-1 regression files
  pass on `main` (1,340 tests).
- **Fixed here** means a commit on this branch, each with a test that fails without it.
- Open pull requests were checked for overlap: batches 2 to 4 (#203, #208, #218) and the
  "audit v2" series (#204 to #207) use their own finding identifiers (`NS-AUD-*`), so
  overlap was judged by the code they change, read on #218's head `1e23eff`. This
  branch's code commits merge into `1e23eff` without conflicts, and their new and
  changed tests (170) pass in the merged tree.

## Summary

| Status | Findings |
| --- | --- |
| Fixed on `main` (batch 1) | M2, M3, L1 to L9, L11, L13 to L18, L24, T1, T2, T4 |
| Fixed on `main`, completed here | L10 (all noncharacters), L12 (a test that reproduces it), T3 (worker traced in-process) |
| Fixed here | L25 |
| Addressed, residual documented | L26 (already redacted; pinned by tests), L27 (unit budgets bound size, not time) |
| Partly fixed | L19 (creation ruleset committed, not applied), L22 (one of three jobs still builds from source) |
| Open: administrator action | M1, M4, L19, L21, L23 |
| Open: deferred on purpose | L20 (pin pip), see below |

## Findings

| ID | Status | Evidence |
| --- | --- | --- |
| M1 | Open (administrator) | Needs a required workflow or code-owner rule outside the pull request's reach, or a second maintainer. #154 (open) records the administrator-only controls. |
| M2 | Fixed (`eddf85e`) | `tests/test_shadowscan_symlinked_report.py`: 2 fail on `eddf85e^`. |
| M3 | Fixed (`eddf85e`) | `tests/test_ide_interpreter_prefix_grants.py`: 21 fail on `eddf85e^`. |
| M4 | Open (administrator, and a decision) | The release-tag rulesets are committed as two files (`ff71849`); applying them and running `check_repository_controls.py --verify-bypass-actors` needs an administrator. Candidate runs still attest: see [decisions](#decisions-for-the-maintainer). |
| L1 | Fixed (`59aec4f`) | `test_the_trust_root_comes_only_from_the_locked_runtime` fails on `59aec4f^`. |
| L2 | Fixed (`59aec4f`) | `tests/test_trace_unidentified_spans_gate.py`: 3 fail on `59aec4f^`. |
| L3 | Fixed (`59aec4f`, `8b0833a`) | `tests/test_project_policy_ci_gate.py`: 4 fail on `59aec4f^`. |
| L4 | Fixed (`eddf85e`) | `tests/test_policy_output_format_weakening.py`: 2 fail on `eddf85e^`. |
| L5 | Fixed (`eddf85e`) | `tests/test_shadowscan_binding_characters.py`: 5 fail on `eddf85e^`. |
| L6 | Fixed (`18b93aa`) | `test_marker_existence_checks_spend_no_byte_budget` fails on `18b93aa^`. |
| L7 | Fixed (`59aec4f`) | `tests/test_inventory_export_cli.py`: 2 fail on `59aec4f^`. |
| L8 | Fixed (`18b93aa`, `ee19d00`) | `tests/test_native_nesting_bound.py` cannot import the bound on `18b93aa^`. |
| L9 | Fixed (`eddf85e`) | `tests/test_diff_alert_text_bounds.py`: 2 fail on `eddf85e^`. |
| L10 | Fixed (`18b93aa`); completed here | Tab and U+FFFE/U+FFFF were fixed; this branch adds the other 64 noncharacters (`tests/test_terminal_noncharacters.py`). Private-use characters stay printable by decision: they draw as a visible glyph and cannot move the cursor or hide text. |
| L11 | Fixed (`eddf85e`) | `tests/test_recovery_load_export_confinement.py`: 2 fail on `eddf85e^`. |
| L12 | Fixed (`eddf85e`); test added here | The timed test passes on `eddf85e^` too, as the audit said. The new case counts the items handed to `sorted`: 82,600 to 1,290,400 on `eddf85e^` (fails), about four times on `main`. |
| L13 | Fixed (`eddf85e`) | `tests/test_npmrc_resolver_failures.py`: 2 fail on `eddf85e^`. |
| L14 | Fixed (`8a2250f`) | `test_token_shaped_package_identity_is_withheld`: 4 fail on `8a2250f^`. |
| L15 | Fixed (`8a2250f`, `2837e58`) | `test_one_servers_secret_value_is_scrubbed_from_every_server_of_the_file`: 3 fail on `8a2250f^`. |
| L16 | Fixed (`18b93aa`, `62d97c0`) | `tests/test_model_integrity.py`: 5 fail on `18b93aa^`. |
| L17 | Fixed (`8a2250f`) | `tests/test_vendor_key_redaction.py`: 27 fail on `8a2250f^`. |
| L18 | Fixed (`8a2250f`) | `tests/test_rag_identifier_redaction.py`: 12 fail on `8a2250f^`. |
| L19 | Partly fixed | A creation-only ruleset is committed (`config/github-release-tag-creation-ruleset.json`); applying it, and requiring signed commits on `main` once a second maintainer exists, needs an administrator. |
| L20 | Open, deferred | See [below](#deferred-pin-pip-l20). |
| L21 | Open (administrator) | Removing the stale `platform-smoke.yml` registration and the unmerged branches deletes data; the maintainer decides which branches go. |
| L22 | Partly fixed (`aac3605`) | The CI wheel smoke and the release compatibility installs are binary-only. The newest-dependency job in `dependencies.yml` still runs `pip install --upgrade ... -e '.[all]'` without `--only-binary=:all:`; whether that job may build from source is a decision. |
| L23 | Open (administrator) | Same root as M1. |
| L24 | Fixed (`eddf85e`) | Documentation. |
| L25 | Fixed here (`98bfd79`) | The launcher now starts on the gateway's first `describe`, after verification-order steps 1 to 7. `tests/test_pinned_launcher_starts_after_admission.py`: six refusal cases fail on `main`. Residual, documented: the approval is checked after the descriptor (step 9), so a caller with a valid snapshot and trust status but no approval still starts the launcher. |
| L26 | Addressed | The three forms already passed through `redact_text`; `tests/test_registry_free_text_redaction.py` pins it and passes on `8a2250f^` too, consistent with no code change. |
| L27 | Addressed, residual documented | Root requirements files stop at 100,000 logical lines (`18b93aa`); model parsers share an `InspectionBudget` (16 million units, at most 4 million ONNX fields). Limits bound size, not time; the threat model asks for a job timeout. |
| T1 | Fixed (`5617188`) | One fixture-transport case per live-mode refusal in `tests/test_live_mcp.py`. |
| T2 | Fixed (`5617188`) | One misbehaving launcher per pinned-stdio bound in `tests/test_pinned_stdio.py` and `tests/test_runtime_stdio_session.py`. |
| T3 | Fixed (`5617188`); completed here | Floors were added. This branch runs the worker's code in-process (`tests/test_runtime_validation_in_process.py`), each case cross-checked against the real isolated worker; `runtime_validation.py` measures 76% before and 92% after on the runtime tests; on the full suite 93.88% of statements and 90.29% of branches, so its floor is raised from 76/73 to 92/88. |
| T4 | Fixed (`5617188`, `5c9a780`, `ddec60b`) | `tests/test_suite_infrastructure.py`, `tests/test_suite_resolver_guards.py`. |

## Information items

| Item | Status |
| --- | --- |
| Walk failures recorded once per collector | Open: noise, not a wrong verdict. |
| Loopback HTTP MCP endpoints raise no finding | Documented in the known limitations (`aac3605`). |
| DNS resolver thread waits under the offline guard | Fixed (`18b93aa`, `5721ca0`). |
| Server `instructions` bounded only by the response limit | Open: redacted and hashed, never executed. |
| Hostnames exported as origins without a token-shape check | In review: #205 adds a token-shaped host guard to URL redaction (not verified here). |
| `_load_jsonc` lacks the non-finite guard | Fixed (`18b93aa`). |
| `-o -` creates a file named `-` | Fixed here (`8742481`): refused, with how to print to standard output. |
| `baseline` stages its file through a linked directory | Fixed here (`590af00`): staged through the no-link directory walk. |
| Environment variables are trusted operator input | Documented. |
| Export digest check is value-based, documentation says byte-exact | Documentation corrected here (`4ce18a6`). |
| An empty `bom_ref` is valid native but not valid CycloneDX | Fails closed: the CycloneDX export refuses it, as "dependency references an unknown component". Not changed: refusing it at load would break the native format for a case no collector produces. |
| SARIF URIs percent-encode backslashes | Not changed: a design choice, not a wrong verdict. |
| Release evidence after the tests ran | Documented. |
| `CHANGELOG.md` lists 0.2.0 as released | Open: a [decision](#decisions-for-the-maintainer). |
| A2A and Gemini failures misattributed | Fixed (`18b93aa`). |
| Written inventory JSON keeps a literal `##[` | Open: only standard output is escaped. Escaping written files changes the bytes of an inventory, which the canonical-form and file-digest guarantees depend on; it needs a design decision. An Azure Pipelines step that prints the file could act on a `##vso[` in a component name. |
| `SECURITY.md` supported versions and second contact | Supported versions added (`aac3605`); a second contact needs a second person. |
| `make quality` and numpy stubs | Environment-specific; `make quality` passes in the hash-locked environment. |

## New finding from this pass

**[Low | Medium] N1. The gateway ignores a keyword no JSON Schema dialect defines, so an
approver can read a constraint that is never enforced.** `_ignores_a_keyword` in
`runtime_validation.py` refuses keywords of another dialect and keywords jsonschema does
not apply, which its docstring frames as "a constraint that whoever approves the schema
reads". A name no dialect defines is ignored, as JSON Schema specifies: a misspelling
such as `maxProperites`, or a lookalike such as `maxLength` with its `e` replaced by the Cyrillic U+0435, reads
as a limit in review and validates as nothing. Precondition: the approver reads the
schema text and the server's author is hostile. Options: refuse keywords outside the
dialect's vocabularies except an allowlist of annotations such as `x-*`, or show
undefined keywords to the approver. Refusing them fails closed but may reject servers
that use custom annotations, so it is a policy choice.
`tests/test_runtime_validation_in_process.py` pins the current behavior
(`undefined-keyword`).

## Deferred: pin pip (L20)

Not changed on this branch, deliberately. Batch 4 (#218, from #207) rewrites the same
install lines in `ci.yml`, `release.yml`, `action.yml` and the `Makefile`, and 165 lines
of `check_workflows.py`; a change here would conflict on almost every line, and CI runs
only on pull requests to `main`. The pinned uv (0.11.32) installs and runs in this
environment, so the change itself is unblocked. Apply it on top of batch 4:

1. Add `pip` to the `dev` dependency group in `pyproject.toml` and run `make lock`
   (no `--upgrade`, so the recorded cut-off and every other pin stay).
2. In `scripts/check_locks.py`, write a fourth lock, `requirements-pip.lock`, holding
   pip alone at its `requirements-ci.lock` version and hashes, and check offline that the
   two agree and that the cut-offs match.
3. In every job, the `Makefile` and the Action, install that lock first:
   `python -m pip install --require-hashes --only-binary=:all: --no-deps -r requirements-pip.lock`,
   then the job's lock as now. The runner's pip then verifies one hash, and the pinned
   pip enforces the rest.
4. Drop `pip` from `BOOTSTRAP` in `scripts/environment_sbom.py` once the release smoke
   environment installs it from the lock, so the environment SBOM covers it.

## Decisions for the maintainer

- **Candidate attestations (M4).** The `attest` job runs for `publish=none`. Gating it on
  `publish != 'none'` would break step 2 of the [release process](../releasing.md), which
  inspects the candidate's attestations. The control that closes M4's attack is the tag
  ruleset; pinning the lock's SHA-256 in each release's notes would add a byte check to
  the README's verified install.
- **0.2.0.** Publish it through the release workflow, or relabel the changelog section
  as unreleased.
- **N1**, **L22's newest-dependency job**, and **escaping `##[` in written files**, as
  described above.
- **After batch 4 lands:** batch 4 adds `_JSON_UNSAFE_TEXT` in `utils/terminal.py` as a
  copy of the `UNSAFE_TEXT` class from before this branch; build it from `UNSAFE_TEXT`
  so the two do not drift over the 64 noncharacters added here.
