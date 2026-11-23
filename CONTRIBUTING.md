# Contributing to Nexus SymBiote

Nexus SymBiote's supported baseline is the `nexus_symbiote` Python package and `nexus-symbiote` CLI on `main`. Contributions are accepted under the [MIT license](LICENSE) (inbound equals outbound).

## Quick start

Requires Python 3.11–3.14 on Linux (or macOS for static features) inside an isolated virtual environment:

```bash
python3 -m venv .venv && . .venv/bin/activate
make install-locked   # hash-locked CI dependencies + editable install + pip check
make check            # offline CI checks: quality, coverage, security regressions, precision, fuzz, build
```

## First contribution

- **Questions & troubleshooting:** Start with [SUPPORT.md](SUPPORT.md).
- **Good starter tasks:** Browse [known limitations](docs/known-limitations.md) for well-bounded gaps (new config surfaces, collector coverage, regression fixtures). Open an issue first so work isn't duplicated.

## Development workflow

Run `make help` to list every target. The most common checks:

| Target | What it runs |
| --- | --- |
| `make install-locked` | Hash-locked `requirements-ci.lock` + editable install + `pip check` |
| `make quality` | `ruff check`, `ruff format --check`, `mypy` strict (`src/` & `scripts/`), workflow, hygiene, and lock checks |
| `make test` | Full parallel pytest suite (`-n auto --dist worksteal --strict-skips`) |
| `make coverage` | Branch coverage enforcing package, script, and security-module floors (`scripts/check_coverage.py`) |
| `make test-floor` | Full suite on Python 3.11 at declared dependency floors (`requirements-floor.lock`, excluding `locked_only`) |
| `make security-regressions` | Committed security regression contracts (`scripts/check_security_regressions.py`) |
| `make precision` | Fresh drift-regression and class-recall precision gate (`scripts/check_precision_gate.py`) |
| `make fuzz-smoke` | Deterministic bounded parser fuzz corpus (`scripts/fuzz_parsers.py`) |
| `make wheel-smoke` | Fresh wheel build + isolated security acceptance (`scripts/check_wheel_security.py`) |

## Testing

- **Clean isolation (`tests/conftest.py`):** Strips ambient `NEXUS_SYMBIOTE_*`, `SYMBIOTE_*`, `SHADOWSCAN_*`, `GITHUB_*`, `CI`, proxy, and terminal variables; points `HOME`/XDG to a temp directory; blocks outbound non-loopback sockets; and fails any test that leaves a mode override active. Use the `runner` fixture for CLI calls and `tests/support.py:load_script` for importing `scripts/`; never import one test module from another.
- **Parallelism & determinism:** CI runs `pytest -n auto --dist worksteal`. Tests must never share fixed ports, paths, or global state. Pass `make test PYTEST_PARALLEL=` to run single-process for debugging.
- **Timeouts & linear scaling:** Default timeout is 300 s locally (`pyproject.toml`), 120 s in CI (240 s under coverage). Mark intentionally slow tests with `@pytest.mark.timeout(N)` and pass `timeout=` to every `subprocess.run`. For linearity/DoS tests, use `tests.support.scaling_ratio` instead of fixed wall-clock ceilings (`make hygiene` rejects wall-clock cost bounds).
- **Per-PR time budget:** Tests added by one PR should run in ≤60 s without coverage (`python -m pytest --durations=0`); state the measured time in the PR. Mark >2 s subprocess, bomb-input, or `scaling_ratio` tests with `@pytest.mark.no_cover` (they still run in every job, without coverage tracing overhead).
- **Strict skips:** `--strict-skips` rejects unexpected skips and all `xfail` markers. Never use `pytest.importorskip` for required dependencies; only host filesystem differences, Linux-only kernel interface checks off Linux, or missing `pip` outside CI may skip.
- **Property & fuzz tests:** Parsers of hostile inputs need Hypothesis properties in `tests/test_parser_properties.py` (without fixed `max_examples`, so the weekly randomized `fuzz` profile can widen them).

## Dependency locks

Three hash-locked files are generated from `pyproject.toml` using the pinned `uv` version in `scripts/check_locks.py` — never edit them by hand:

| Lockfile | Scope | Used by |
| --- | --- | --- |
| `requirements-ci.lock` | All extras + `dev` group (CPython ≥3.11, all platforms) | CI, release builds, `make install-locked` |
| `requirements-action.lock` | Core + `sigstore` extra + build backend (exact subset of CI lock) | GitHub Action, Docker image, verified installs |
| `requirements-floor.lock` | Runtime dependencies & build backend at declared lower bounds (Python 3.11) | `floor` CI job, `make test-floor` |

- **`make lock`** regenerates all three locks while keeping existing pins unless declarations changed, enforcing a ≥7-day public-scrutiny cooldown.
- **`make lock-upgrade`** moves the cut-off to 7 days ago and upgrades pins accordingly. Never run with release credentials or on unreviewed PRs.
- **`make lock-check`** verifies offline that lock headers match `pyproject.toml`, cooldowns are ≥7 days old, versions/hashes are aligned across locks, and floor pins match declared lower bounds. Review added `# via` lines and package metadata carefully on lock diffs.
- **Dependabot & OSV advisories:** Dependabot updates ranges in `pyproject.toml` only; a maintainer runs `make lock` and waits for the *Dependency health* workflow before merging. `Dependency advisories` blocks on any OSV advisory across all three locks (failing closed if OSV is unreachable). For non-applicable advisories that cannot be upgraded immediately, add a reviewed waiver to `config/dependency-advisory-waivers.json` (`advisory_id`, `package`, `version`, `reason` ≥20 chars, `expires` ≤90 days).

## Architecture boundaries

- **ShadowScan separation:** [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) is the companion multi-surface discovery engine; keep `import-shadowscan` intact and preserve the separation between imported claims, local observations, approved snapshots, and mediated execution.
- **Explicit declarations:** Keep A2A, IDE, and registry claims explicit rather than inferring deployment or runtime permissions from presence alone.
- **Security regression corpus:** Run `make security-regressions` (and `PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json`) after security changes. Never weaken labels or drop negative controls to improve scores.

## Security changes

- State the **trust boundary** and **abuse case** in the PR before modifying security logic.
- Add a **regression test** that fails on the vulnerable behavior (including unknown and malformed inputs).
- Keep unknown/invalid inputs, incomplete collection, and unsupported critical semantics **failing closed** — never silently clean.
- Validate exporter changes against the pinned official schemas while preserving unknown states, loss reports, and references; version canonical digest profiles with test vectors. Never overwrite golden files blindly.

## Pull requests

- **Size cap:** Keep PRs under **1,500 changed lines** (insertions + deletions) outside `tests/` and `benchmarks/`, enforced by `scripts/check_pull_request_size.py`. Split larger work into focused PRs.
- **Branch & merge hygiene:** Merge `main` into your branch rather than rebasing/force-pushing shared branches, resolve conflicts carefully (never overwriting `main` wholesale), and wait for `Verified CI`. Gate paths (`.github/`, `action.yml`, `scripts/`, `config/`, `pyproject.toml`, lockfiles, `tests/conftest.py`, `scanners/`, `validators/`, `generators/`) are listed in `.github/CODEOWNERS`.
- **Single-maintainer soak window:** While one maintainer reviews changes, behavior- and security-changing PRs stay open for a ≥24-hour soak window, with a full post-CI diff review recorded in the PR description. Small docs-only PRs may merge once `Verified CI` is green.
- **Commits & labels:** Sign commits (`git commit -S`), reference relevant [roadmap](ROADMAP.md) items or [decisions](docs/decisions.md), and apply type, area, and review-state labels per the [label guide](docs/labels.md). A pull request merges only with `review: verified` at its current head and without `do-not-merge`.

## AI-assisted contributions

AI-assisted contributions are welcome under the same quality and review standards:

- **Accountability:** The PR author is responsible for understanding every line, running the checks, and answering review questions.
- **Disclosure:** Include a `Co-Authored-By:` trailer or a disclosure sentence in the PR review record.
- **Verification:** Re-read the full rendered diff after `Verified CI` passes; check tests for tautological assertions. An AI review counts as a second opinion, not independent human approval unless run outside the authoring session with findings attached.
- **Confidentiality:** Never paste secrets, private inventories, or unpublished vulnerability details into an assistant.

## Repository hygiene

- **`make hygiene`** (`scripts/check_repository_hygiene.py`) checks offline for merge markers, invisible/bidi characters (write escapes such as `"\u202e"` in code), broken local/absolute links and heading anchors, relative links in `README.md` (which breaks PyPI rendering), stale repository-owner URLs, version alignment (`pyproject.toml`, `__init__.py`, `CITATION.cff`), vendored schema SHA-256 digests, and wall-clock cost bounds in tests.
- **`make workflow-check`** (`scripts/check_workflows.py`) enforces SHA-pinned actions with version floors, read-only top-level permissions, safe triggers, and intact CI/release gate commands.
- **Secrets (`.gitleaks.toml`):** Uses upstream default rules across source and tests with zero directory exemptions. Investigate every hit; only reviewed synthetic fixtures may record exact fingerprints in `.gitleaksignore`.

Report security vulnerabilities via [SECURITY.md](SECURITY.md). Licensed under [MIT](LICENSE).
