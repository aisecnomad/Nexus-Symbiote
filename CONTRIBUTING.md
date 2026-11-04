# Contributing to Nexus SymBiote

Nexus SymBiote's compatibility baseline is the `nexus_symbiote` Python package and `nexus-symbiote` CLI on `main`. The product name is Nexus SymBiote. Experimental implementations on other branches are not interchangeable packages; port useful capabilities through reviewed, tested changes.

## Development

Use Python 3.11 through 3.14 on Linux and an isolated virtual environment. `make install-locked` installs the locked environment, and `make check` runs the offline subset of the required CI checks: quality, the coverage-gated test suite, the security regression contracts and the distribution build. The individual commands, from a checkout:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-ci.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pytest
ruff check src tests scripts
ruff format --check src tests scripts
mypy src/nexus_symbiote scripts
python scripts/check_workflows.py
python scripts/check_repository_hygiene.py
python scripts/check_security_regressions.py --out security-regressions.json
python -m pytest --cov=nexus_symbiote --cov-branch --cov-report=json:coverage.json
python scripts/check_coverage.py coverage.json
python -m build
python -m twine check dist/*
```

The lock records the full CI dependency set. The wheel smoke test separately checks a minimal runtime installation. Regenerate the lock after changing declared dependencies; inspect new packages, hashes, supported Python markers, and license implications. Never resolve or publish dependencies from an untrusted pull request with release credentials.

Dependabot's pip pull requests change only the ranges in `pyproject.toml`. Dependabot cannot update these uv-generated hash locks, so such a pull request's CI still installs and tests the previously locked versions, while an installation from a package index can resolve the newly allowed versions untested. Regenerate the locks in that pull request before merging it: rerun the `uv pip compile` command recorded at the top of `requirements-ci.lock` with `--upgrade-package <name>`, then copy the new pins and hashes of any package that `requirements-action.lock` also lists. The scheduled `dependency-audit.yml` workflow audits the locked versions against OSV daily.

The consuming GitHub Action creates a private virtual environment and installs `requirements-action.lock` with required hashes and binary distributions only. This smaller lock contains the core runtime and Hatchling dependencies copied from the reviewed CI lock, without development or optional signing packages. Refresh both locks when dependencies change, then install the Action lock and the source with `--no-deps --no-build-isolation` in a clean environment. The CI security-regression job exercises that runtime dependency boundary.

`Verified CI` aggregates the full test matrix, coverage, quality, distribution and security-regression jobs. Missing, failed, cancelled and skipped prerequisites fail that stable check. Branch protection must require it; see [repository controls](docs/repository-controls.md). The coverage gate independently requires at least 90% statement coverage and 75% branch coverage, using exact counts rather than rounded display percentages. On 2026-11-03 the 1,507-test suite measured 92.35% of statements and 84.23% of branches on Python 3.12. These floors prevent regression and are not a completeness claim. Use the Python 3.12 CI environment for comparable measurements; raise floors as missing paths gain tests.

## Architecture boundaries

Nexus-ShadowScan is the primary discovery engine. Preserve the `import-shadowscan` workflow when changing collection or graph code. Imported claims, local observations, approved snapshots, and mediated operations have different assurance. Keep A2A, IDE, and registry declarations explicit rather than inferring deployment or effective permissions from presence alone.

Run `PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json` after security changes. Review individual cases, corpus/source digests, unknowns, and denominators. Do not replace labels or remove negative fixtures to improve the result. The corpus is a finite regression suite, not representative field efficacy evidence.

CI and release candidates also run `scripts/check_security_regressions.py`. Every committed detection label and control contract must pass; missing cases, abstentions on detection cases, duplicate cases and evaluator errors fail. A passing malformed-input coverage control can deliberately have an unknown detection prediction. The full per-case report is retained even when this gate fails. New labels and changed expectations require review of the fixture and its rationale; passing these fixtures establishes no production accuracy or percentile ranking.

## Security changes

State the trust boundary and an abuse case before changing security decisions. Add a regression that fails on the vulnerable behavior, including unknown and invalid inputs. Keep evidence of origin separate from evidence of approval and observed runtime behavior. Invalid policies, incomplete collection, missing required evidence, and unsupported critical semantics must not become silent successful verdicts.

Exporter changes must validate against the pinned official schema and preserve references, unknown states, and loss reports. Canonical digest changes require versioned profiles and test vectors. Do not update a golden file merely to make a failing test pass.

## Pull requests

Explain the concrete problem, resulting behavior, validation, and material limitations. Keep changes focused and include applicable documentation. Do not claim production enforcement for execution paths that bypass the adapter. Add no network access, executable discovery, or credential collection without an explicit design and tests.

During the interim single-maintainer period (see [repository controls](docs/repository-controls.md)), keep every change on a pull request and leave behavior- or security-changing pull requests open for a soak window of at least 24 hours before merging; re-read the full rendered diff after `Verified CI` completes and treat it as the reviewed artifact. Small documentation-only fixes may merge once CI is green. High-volume days of self-merged reviews are where defects slip through; the soak window is the control that compensates for the absent second reviewer.

The quality job also checks tracked source for conflict markers; documentation links, including heading anchors and absolute links into this repository; package/distribution version agreement; and the vendored schemas' recorded SHA-256 digests. The README is also the package-index description, and `twine check` does not render Markdown, so the check rejects relative links and images in it and confirms that each absolute one still resolves to a tracked file and heading. These checks are offline and do not authenticate an upstream publisher. Review changes to schema bytes and their provenance manifest together. Keep experimental-branch merges and manually ported changes distinct from ancestry on `main`; the [closed-PR audit](docs/audits/closed-pr-review-2026-11-02.md) records that distinction.

Read [SECURITY.md](SECURITY.md) before reporting security-sensitive defects. This project is licensed under MIT as specified in [LICENSE](LICENSE).
