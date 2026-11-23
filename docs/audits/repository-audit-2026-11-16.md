# Repository audit and open pull request review, 2026-11-16

**Scope:** `main` at `6a866e0` (after #226 and #227) and the open pull requests #224, #228 and #229. The tree holds about 81,000 lines under `src/`, 110,000 under `tests/` and 7,400 in `scripts/`, `.github/` and `action.yml`.

**Verdict:** no critical or high finding. Three security gaps let a hostile repository hide something from the inventory or the redaction:
- a pickle trigger;
- an unsignalled survivor of the opt-out launcher;
- a credential in an escaped quote.

Each is reproduced and fixed with a regression test. One CI flake failed `Verified CI` on two pull requests and is fixed. The remaining items are recommendations.

## How it was audited

**Breadth, automated, whole tree.** Scanner output was treated as leads and triaged by hand.

| Check | Result |
| --- | --- |
| `ruff`, `ruff format`, `mypy --strict` (113 files) | Pass |
| `bandit` on `src/` and `scripts/` | 50 low or medium results. The YAML load uses a `SafeLoader` subclass. The 15 `assert` statements in `src/` are type narrowing; where `-O` strips one, the next line fails closed (for example `os.dup(None)` in `confined.py`). |
| `zizmor` on `.github/workflows` and `action.yml` | 4 low suggestions to use the self-repository syntax. Every Action input reaches its `run:` step through an environment variable, never through `${{ }}` in script text. |
| `pip-audit` on `requirements-ci.lock`, `requirements-action.lock`, `requirements-floor.lock` | No known vulnerabilities |
| `detect-secrets` and a token-format search on tracked files outside `tests/` and `benchmarks/` | 319 hits: digests, schema keywords, a documented example URL. No real credential. |
| `vulture` (confidence 80 or higher) | 7 unused variables. 6 are interface parameters; one is a finding below. |
| Wall-clock bounds in the suite, against the hosted Coverage job's durations | 69 bounded tests. The ones close to their bound are listed below. |

**Depth, by hand, with adversarial tests.** These areas got manual reading and adversarial tests:
- secret redaction (differential fuzzing against `main` and each parent);
- the pickle interpreter and content sniffing (real `pickle.load` as the oracle, and a 12,436-file false-positive corpus);
- the Python MCP collector's `getattr` handling (132 parity rewrites, 35 unusual spellings);
- the opt-out launcher teardown (`/proc` behavior of multi-threaded processes);
- the composite Action's input handling.

**What was not read line by line.** The other modules were covered by the automated checks and by the full test suite, not by a manual reading. That includes the exporters, validators, graph, attestation, crosswalk and minimum-element code, most scanners, and `runtime.py`.

The 2026-11-14 audit (archived in git history) read every module at `4aaf727`. This audit does not repeat that reading; it targets what changed since (#202, #203, #226) and the open pull requests.

## Findings

| # | Severity, confidence | Where | Finding | Status |
| --- | --- | --- | --- | --- |
| 1 | Medium, high | `utils/pickle_load.py` on `main` | A pickle checked only by content was **not inventoried** when it named a module that is not a Python identifier, such as `cev-il\nrun\n)R.` saved as `models/weights`, `.dat` or `.npy`. The interpreter took such a name for a failed import. `find_class` imports the module before it looks the name up, and `importlib` imports a committed `ev-il.py` and runs it. Precondition: the attacker also commits the module file, and the loader runs with the repository on `sys.path`. | Fixed in #230 (`c8c767a`). Only a module that no finder can name now fails before an import runs. The same 7 of 12,436 real files are inventoried before and after. One documented example, a `.gitignore` starting `checkpoint*`, `*.pth`, `.DS_Store` under a model directory, is now `unknown`: **maintainer decision on that trade-off** |
| 2 | Medium, high | `utils/pickle_load.py` on #229 | The new line validators repeated finding 1's assumption for a `GLOBAL` line cut by the 64 KiB sample. A padded payload with module `ev-il` stayed uninventoried while `evxil` became `unknown`. | Fixed on #229 (`8947399`) |
| 3 | Medium, high | `utils/secrets.py` on `main` | `https://api.example/v1?api_key=\"value\"`, an escaped quote after a credential name that ends a URL, kept the value in clear. It is common in JSON or shell text inside strings. | Fixed in #230 (`bd78c9d`). A fuzz of 120,000 redactions against `main` shows 0 values newly revealed and 1,742 newly hidden. |
| 4 | Low, high | `live/pinned_process.py` on #228 | The opt-out teardown read only the thread-group leader's state. A tree process whose main thread exited while another thread ran (`State: Z`, `Threads: 2`), and which this user may not signal, was reported as ended. | Fixed on #228 (`3efb613`) |
| 5 | Low (reliability), high | `tests/test_secret_name_redaction.py` | A 5-second wall-clock bound on 2.1 MB of input failed `Verified CI` on #208 and #228 (5.85–6.04 s under coverage), while the redaction is linear. | Fixed in #230 (`80e4076`): the test now uses a scaling ratio |
| 6 | Low (performance), medium | `utils/secrets.py` | Batch 3's union redactor runs about 2.5× slower in constant factor on adversarial `Bearer` and `Authorization: Bearer` text: 2.1 MB of `"Authorization: Bearer "` takes 8.7 s against 3.3 s before (`8872d72` against `9f65d3a`). It remains linear. | Recommendation 1 |
| 7 | Low, high | `live/verify.py` | `verify_mcp_servers(config_lookup=...)` accepts a mapping and never reads it. A library caller that passes server configuration expecting it to be checked gets no error. | Recommendation 2 |
| 8 | Low, high | Process | Two implementations of the opt-out launcher fix exist: #228 and the unmerged `claude/intelligent-hypatia-zn4xp8`. #229 is stacked on the second and has never run CI, and #224 is superseded by #228 but open. | Recommendation 3 |

## Recommendations, in order

1. **Profile the union redactor on adversarial scheme words** (finding 6). Most of the cost is per scheme occurrence. A cheap pre-check would recover the constant factor: skip the masked re-read when the text holds no URL. Keep the floor guarantee and the differential fuzz as the acceptance test.
2. **Remove `config_lookup` from `verify_mcp_servers`, or raise when it is passed** (finding 7). No caller in the repository passes it.
3. **Land #228, close #224, and move #229's six pickle files onto `main`** (finding 8). Then delete `claude/intelligent-hypatia-zn4xp8`, so the next reader does not review a second implementation.
4. **Review the remaining wall-clock bounds that use half or more of their limit under coverage on hosted runners:**
   - `test_live_wire.py::test_tls_handshake_that_never_completes_stops_at_the_deadline` uses 2.0 s of 2.5 s. It times a 2 s deadline, so its margin is fixed at 0.5 s.
   - `test_prompt_surfaces.py::test_hidden_markup_scan_is_linear` uses 57%.
   - `test_runtime_schema_semantics.py::test_backreference_bookkeeping_stays_linear_on_deep_nesting` uses 55%.
   - `test_verify_live_scope.py::test_descriptor_checks_share_the_session_deadline` uses 52%.

   Where a test asserts linearity, `tests.support.scaling_ratio` holds on any runner. Where it asserts a deadline, give the bound room for scheduler delay.
5. **Keep finding 1's rule in one place.** `resolve()` and the test oracle now share `_unimportable`. Any future cut-line validator should call it, not a character class.
6. **Run `scripts/benchmark_security.py`** on #230 before merging. That run was not done in this audit.

## Reproduction

Every fix carries a regression test that fails on the parent commit, and each commit message records its checks. The probes used here: a real `pickle.load` with the module file on `sys.path`, a differential redaction fuzz, and a threaded `pthread_exit` survivor with `os.kill` refused. They are written into those tests rather than kept as separate scripts.
