# Contributing to Nexus SymBiote

## Quick start

```bash
git clone https://github.com/aisecnomad/Nexus-Symbiote.git && cd Nexus-Symbiote
make install-locked   # hash-locked CI environment + editable install
make check            # quality, tests, security regressions, distribution build
# Open a pull request against main
```

Nexus SymBiote's compatibility baseline is the `nexus_symbiote` package and `nexus-symbiote` CLI on `main`. Experimental branches are not interchangeable packages; port useful capabilities through reviewed, tested changes.

## First contribution

Read [SUPPORT.md](SUPPORT.md) for how the tool behaves and what to include when asking for help. Well-bounded starter tasks are in the [known limitations](docs/known-limitations.md): each names a file type, collector or check that is not covered yet. Open an issue with the feature form saying which one you will take, so two people do not do the same work.

Contributions are accepted under the project's [MIT license](LICENSE): by opening a pull request you agree that your contribution is licensed under the same terms (inbound equals outbound) and that you have the right to submit it.

## Development

Use Python 3.11 through 3.14 on Linux with an isolated virtual environment. `make install-locked` installs the locked environment; `make check` runs the offline subset of the required CI checks: quality, the coverage-gated test suite, the security regression contracts and the distribution build.

The individual commands, from a checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pip check
python -m pytest -n auto --dist worksteal --strict-skips
ruff check src tests scripts
ruff format --check src tests scripts
mypy src/nexus_symbiote scripts
python scripts/check_workflows.py
python scripts/check_repository_hygiene.py
python scripts/check_locks.py
python scripts/check_security_regressions.py --out security-regressions.json
python -m pytest -n auto --dist worksteal --strict-skips --cov=nexus_symbiote --cov=scripts --cov-branch --cov-report=json:coverage.json
python scripts/check_coverage.py coverage.json
python -m build --no-isolation
python -m twine check --strict dist/*
```

`make test-floor` runs the suite on Python 3.11 with every runtime dependency at its declared lower bound (needs `python3.11`; set `PYTHON_FLOOR` for another interpreter), as the CI `floor` job does. Both leave out `locked_only` tests, which compare pinned-library output (such as the JSON schema pydantic derives) with a committed file; every behavior test still runs. A test that fails only at the floors means the declared floor is wrong: raise it and run `make lock`.

## Tests

### Environment isolation

`tests/conftest.py` gives every test a clean environment: the variables the tool, the Action runner and the gate scripts read (`NEXUS_SYMBIOTE_*`, `SYMBIOTE_*`, `SHADOWSCAN_*`, `GITHUB_*`, `RUNNER_*`, `GH_TOKEN`, the Actions token variables, `SOURCE_DATE_EPOCH`, CI markers, color/width/terminal settings) are removed, and `HOME` and XDG directories point at a private temporary directory. A test that leaves an operating mode enforced fails. Use the `runner` fixture for a `CliRunner` and `tests/support.py`'s `load_script` (or the `load_script` fixture) to import a script from `scripts/`; do not import one test module from another.

### Time limits

Each test has a time limit and fails with its traceback when it hangs, instead of consuming the CI job's budget: `test_timeout` in `pyproject.toml` (300 s, for loaded development machines), tightened to 120 s in CI (240 under coverage). Mark a known slow test with `@pytest.mark.timeout(seconds)`, and give every `subprocess.run` in a test its own `timeout`. To show that parsing hostile input stays linear, compare two input sizes with `tests.support.scaling_ratio` instead of asserting a duration: a busy runner or coverage tracing slows both sizes alike.

### Parallel execution

CI's test, dependency-floor and coverage jobs run the suite on one pytest-xdist worker per core (`-n auto --dist worksteal`): each worker starts with a contiguous share of the tests in collection order, and idle workers take tests from the longest queue. The same tests run, and the clean environment, time limit, skip accounting and `no_cover` apply in every worker (`tests/test_suite_infrastructure.py` verifies this).

A test shares the machine with others and does not always run after its file neighbours. It must not depend on what another test left behind, on a fixed port or on a fixed path, and a wall-clock bound must hold on a busy machine. A test that fails only in parallel has an isolation defect: fix the test instead of selecting it out.

With `-vv` a parallel run prints each test's ID when it starts and `[gwN] ... PASSED <id>` when it ends, so the tests a killed run was inside are the IDs with no result line. To run in one process (for a debugger or `--durations=0`), leave the two options out (`make test PYTEST_PARALLEL=`).

### Test budget

The suite has a per-change time budget: the tests one pull request adds take at most 60 seconds total without coverage. Measure with `python -m pytest --durations=0` and state the figure in the pull request. A suite that documents its own budget is held to that budget instead.

Coverage tracing makes a test about twice as slow (1.6 to 2.7x in CI), so mark a black-box CLI subprocess test, a test that builds a large hostile input, or a `scaling_ratio` test with `@pytest.mark.no_cover` when it takes more than 2 seconds: it still runs in every job, only without tracing. Never leave tests out of a CI job with `-m` or `-k`; only the dependency-floor and Dependency health jobs leave out `locked_only` tests, because they install different versions.

### Skips and expected failures

The run lists every skip with its reason. With `--strict-skips` (which CI and `make test` pass), any skip other than a host file-system difference (case-insensitive aliases on a case-sensitive file system, or names the file system refuses), a Linux-only interface (`/proc`, `prctl`, `clone(CLONE_PARENT)`) on another host, or (outside CI) a missing pip fails the run. So does any expected failure (`pytest.xfail()`, `xfail(run=False)` or a conditional `xfail` marker). Do not guard a required dependency with `pytest.importorskip`; import it.

### Property-based tests

Parsers of hostile input need generated inputs as well as examples. `tests/test_parser_properties.py` checks the requirements collector against `packaging`, Dockerfile `FROM` handling, redaction of planted secrets, that no collected file can crash `scan`, and that hostile inputs parse in bounded time. The suite's Hypothesis profile is deterministic; a weekly job runs the same properties with the randomized `fuzz` profile (`python -m pytest --hypothesis-profile=fuzz tests/test_parser_properties.py`). Write new properties without a fixed `max_examples` so the fuzz profile can widen them.

## Dependency locks

Three hash locks are generated from `pyproject.toml`; never edit them by hand.

| Lock | Contents | Used by |
| --- | --- | --- |
| `requirements-ci.lock` | Every extra and the `dev` dependency group, CPython 3.11+ on every platform | CI, the release build, `make install-locked` |
| `requirements-action.lock` | Core dependencies, `sigstore` extra and build backend, resolved inside the CI lock (same versions and hashes) | The GitHub Action and the README's verified installs |
| `requirements-floor.lock` | Each runtime dependency and build backend at its declared lower bound on Python 3.11, with test tools at their CI versions | The `floor` CI job, `make test-floor` |

### Regenerating locks

`make lock` regenerates all three with the uv version pinned in `scripts/check_locks.py` (it refuses any other). It keeps existing CI pins unless a declaration needs a change, considers only packages uploaded before the cut-off recorded in the locks, and records that cut-off, the uv version and a digest of the dependency declarations in each lock's header.

`make lock-upgrade` moves the cut-off to seven days ago and upgrades every CI pin to the newest release older than that, so a release has a week of public scrutiny before it can be locked. Both need PyPI access; never run them with release credentials or on an unreviewed pull request.

### Lock verification

`make lock-check` (`python scripts/check_locks.py`, also part of CI quality) verifies offline that:

- Each lock header records the digest of the current declarations, the pinned uv and one cut-off
- The cut-off is at midnight UTC, at least seven days in the past
- Every pin is an exact, hashed version inside its declared range
- Every pin is either declared in `pyproject.toml` or required by another pin of the same lock (a `-c` constraint is not a reason)
- The Action lock repeats the CI lock's versions and hashes and holds no test tool
- The floor lock tests exactly each declared lower bound

A declared floor that cannot co-install with others (such as `pydantic>=2.10` beside the `sigstore` extra, which needs 2.12) fails until the floor is raised.

### Trust boundaries of the lock check

The check trusts the `# via` lines it reads: a pin inserted with a forged `# via` naming a real parent passes offline. The locked test suite walks installed metadata from `pyproject.toml` and fails on a CI-lock or Action-lock pin outside that closure, but only for pins the test platform installs. It runs inside the installed environment, so a hostile package could rewrite metadata at startup (a `.pth` file runs before the tests); closing that needs a job that resolves declarations before installing anything, which CI does not run yet.

For the floor lock, for platform-limited pins, and against a hostile published package, only regenerating with `make lock` and comparing the result catches it. Review every added pin in a lock diff, and its `# via` lines, against the package's published metadata.

### Dependabot and dependency health

Dependabot proposes range changes in `pyproject.toml` only. Such a pull request fails `make lock-check` until a maintainer runs `make lock` on its branch. Before merging any range or lock change, review new packages, hashes, markers and licenses, and wait for the "Dependency health" workflow, which runs the full suite on the newest releases the ranges admit. That run is not part of `Verified CI` because a new release, not the change, decides its result. "Dependency health" also audits every locked pin against OSV daily, audits the floor lock, and runs the randomized property tests weekly.

Every CI and release install uses `--require-hashes --only-binary=:all:` followed by `pip check`: a missing wheel stops the job instead of building a source distribution with unpinned build tools.

### Dependency advisories

`Dependency advisories` blocks on any OSV advisory for a CI or Action lock pin. If an advisory cannot be fixed in time and does not affect this project, add a waiver to `config/dependency-advisory-waivers.json` in a reviewed pull request, with exactly the keys `advisory_id`, `package`, `version` (exact), `reason` (at least 20 characters) and `expires` (at most 90 days ahead). The gate prints and records every waiver, fails on an expired or malformed one, and fails on a waiver that no longer matches an advisory. If OSV is unreachable, the gate fails closed: re-run the job later; there is no bypass.

## Verified CI and coverage

`Verified CI` aggregates the test matrix, macOS suite, dependency-floor tests, coverage, quality, distribution, security-regression, dependency-advisory and CodeQL jobs, and the Action's end-to-end run on passing, failing and hostile fixtures with the check that the hostile one created no annotation. Missing, failed, cancelled or skipped prerequisites fail that stable check. Branch protection must require it; see [repository controls](docs/repository-controls.md). `scripts/check_workflows.py` fails if any gate job stops running its gate command, so a job cannot be emptied while keeping its name.

The coverage gate (`scripts/check_coverage.py`) uses exact counts, not rounded percentages. It holds the package to its statement and branch floors and each security-critical module (confined reads, hashing, signature verification and policy, validators, differ, offline guard, runtime authorization, redaction, terminal neutralization) to its own floor, so a well-tested average cannot hide an untested module. Gate scripts are measured as well (without counting toward the package figure), and `scripts/run_action.py` has its own floor. The floors live only in that script; they prevent regression and are not a completeness claim. Raise them as missing paths gain tests.

## Architecture boundaries

Nexus-ShadowScan is the primary discovery engine. Preserve the `import-shadowscan` workflow when changing collection or graph code. Imported claims, local observations, approved snapshots, and mediated operations have different assurance. Keep A2A, IDE, and registry declarations explicit rather than inferring deployment or effective permissions from presence alone.

Run `PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json` after security changes. Review individual cases, corpus/source digests, unknowns, and denominators. Do not replace labels or remove negative fixtures to improve the result. The corpus is a finite regression suite, not representative field efficacy evidence.

CI and release candidates also run `scripts/check_security_regressions.py`. Every committed detection label and control contract must pass; missing cases, abstentions, duplicates and evaluator errors fail. New labels and changed expectations require review of the fixture and its rationale; passing these fixtures establishes no production accuracy.

## Security changes

State the trust boundary and an abuse case before changing security decisions. Add a regression that fails on the vulnerable behavior, including unknown and invalid inputs. Keep evidence of origin separate from evidence of approval and observed runtime behavior. Invalid policies, incomplete collection, missing required evidence, and unsupported critical semantics must not become silent successful verdicts.

Exporter changes must validate against the pinned official schema and preserve references, unknown states, and loss reports. Canonical digest changes require versioned profiles and test vectors. Do not update a golden file merely to make a failing test pass.

## Pull requests

Explain the concrete problem, resulting behavior, validation, and material limitations. Keep changes focused and include applicable documentation. Do not claim production enforcement for paths that bypass the adapter. Add no network access, executable discovery, or credential collection without an explicit design and tests.

### Size and signing

Keep a pull request under 1,500 changed lines outside `tests/` and `benchmarks/` (insertions plus deletions). `scripts/check_pull_request_size.py` enforces this. Split larger changes. Sign commits (`git commit -S`); requiring signatures on `main` is an administrator setting not yet active. Changes under `.github/`, `action.yml`, `scripts/`, `config/`, `pyproject.toml`, the lockfiles and `tests/conftest.py` need a second reviewer once one exists. `.github/CODEOWNERS` names that owner; GitHub enforces the review only under the full protection profile.

### Single-maintainer review process

During the interim single-maintainer period (see [repository controls](docs/repository-controls.md)), keep every change on a pull request, up to date with `main` before it merges. Leave behavior- or security-changing pull requests open for a soak window of at least 24 hours; re-read the full rendered diff after `Verified CI` completes and treat it as the reviewed artifact. Small documentation-only fixes may merge once CI is green.

Fill in the pull request's review record: who reviewed the diff, when, and how. Publication repeats the soak mechanically: the release workflow refuses to publish to PyPI until the release commit has been on `main` for 24 hours (see [releasing](docs/releasing.md)).

### Labeling and tracking

Name the roadmap item the change implements and any recorded decision it relies on, as the pull-request template asks. Check that no open pull request already implements the same item. Label the pull request as the [label guide](docs/labels.md) describes: at least one type label, at least one area label and, while open, exactly one review-state label. When work moves between pull requests, update both descriptions so each lists only what its diff contains.

### Conflict resolution

A pull request that rewrites a whole file from an old branch can silently revert merged changes. Resolve conflicts against current `main`, never by taking your side wholesale, and verify the diff removes nothing you did not intend. `scripts/check_workflows.py` also refuses an action pin older than its recorded floor and a gate job that lost its command.

### How a pull request merges

- **One at a time.** Bring `main` into the branch with a merge commit; never rebase or force-push a branch someone else may hold. Wait for `Verified CI` on that head, then merge.
- **The merge commit.** Since #236 (2026-11-16), `main` takes each pull request as a merge commit, `<title> (#N)`. Before that, most were squash-merged; the [2026-11-03 review](docs/audits/closed-pr-review-2026-11-03.md#findings) records how a squash merge silently reverted #99. `git log --first-parent main` lists one commit per directly merged pull request.
- **Labels gate the merge.** A pull request merges only with `review: verified` at its current head and without `do-not-merge`. The [label guide](docs/labels.md) lists requirements.
- **Integration pull requests.** An integration pull request carries several reviewed pull requests at their reviewed heads; the 1,500-line cap applies to the whole. Target each constituent at `main` so GitHub records it as merged when the integration lands. Otherwise, close each by hand with a comment naming the integration's merge commit, and label it `superseded`.
- **Recording.** The [pull-request reviews](docs/README.md#project-records) under `docs/audits/` record how each pull request reached `main`.

## AI-assisted contributions

Contributions written with an AI assistant are welcome on the same terms as any other, and much of this project's history was written that way. The person who opens the pull request is its author: they must understand every line, have run the checks, and answer review questions themselves.

- Disclose the assistance: a `Co-Authored-By:` trailer naming the assistant, or a sentence in the pull request.
- Review the full rendered diff yourself after `Verified CI` completes. Generated code tends to restate what it was asked rather than what the code does; check tests for assertions that cannot fail.
- A review by an assistant is not an independent review unless it runs outside the session that wrote the change, with its findings attached to the pull request. Record which it was.
- Never paste secrets, private BOMs or unpublished vulnerability details into an assistant.

## Repository hygiene

### Secret scanning

Gitleaks uses upstream default rules in both source and tests. The configuration exempts no directory or token prefix: a real credential can occur beside a synthetic fixture. Investigate each finding before recording an exception. If a fixture must retain detected bytes, record only that reviewed finding's exact Gitleaks fingerprint in `.gitleaksignore`, with its synthetic origin and rationale in the pull request; review the fingerprint again if the fixture or its location changes. Never baseline unreviewed findings or suppress a whole file/tree. Gitleaks is not a required CI job; this configuration governs local or external invocations.

### Quality checks

The quality job checks tracked source for conflict markers and invisible characters (bidirectional controls, zero-width spaces), which code writes as escapes (`"\u202e"`). It reads Python and shell scripts everywhere outside `fixtures` directories, and other text files (`Dockerfile*`, `Makefile`, `CODEOWNERS`) outside `tests/` and `benchmarks/`. A file it reads that is not valid UTF-8 fails.

The job also checks:

- Documentation links, including heading anchors and absolute links into this repository
- Package, distribution and citation version agreement
- Vendored schemas' recorded SHA-256 digests
- README links (must be absolute for PyPI; each must resolve to a tracked file and heading)

These checks are offline and do not authenticate an upstream publisher. Review schema byte changes and their provenance manifest together.

Read [SECURITY.md](SECURITY.md) before reporting security-sensitive defects. This project is licensed under MIT as specified in [LICENSE](LICENSE).
