# Release procedure

`.github/workflows/release.yml` is dispatched manually from `main` with one input,
`publish`:

| `publish` | What the run does |
|---|---|
| `none` (default) | Builds, tests and attests a release candidate. Uploads nothing to a package index. |
| `testpypi` | The same candidate, then uploads it to [TestPyPI](https://test.pypi.org/p/nexus-symbiote) as a rehearsal. |
| `pypi` | The same candidate, then uploads it to [PyPI](https://pypi.org/p/nexus-symbiote). |

TestPyPI and PyPI use the same pipeline, the same gates and the same kind of attested
bytes, so a successful rehearsal exercises everything except the final index. This is
the only workflow that publishes to either index.

This repository change does not configure GitHub environments, package-index
ownership, trusted publishers or repository protection. A maintainer does that once,
as described below.

## One-time setup

1. **Make the repository's controls available.** Artifact attestations, and the
   environment protection the `pypi` and `testpypi` environments rely on, are
   available on every GitHub plan for public repositories. For private repositories
   they depend on the plan; for example, attestations in a private repository need
   GitHub Enterprise Cloud. GitHub Actions must also be able to run: check
   *Billing & plans* if jobs end without starting.
2. **Create two environments**, `testpypi` and `pypi`. Give each required reviewers,
   enable *Prevent self-review*, and restrict deployments to `main` with a single
   *Selected branches and tags* rule for the branch `main`. The publication
   preflight rejects any other deployment rule, including *Protected branches
   only*. With one maintainer, *Prevent self-review* means a second reviewer
   approves, or an administrator bypasses the rule; the preflight cannot detect
   that bypass.
3. **Create a pending trusted publisher on each index**, right before the first
   upload, because a pending publisher does not reserve the name:
   - PyPI: <https://pypi.org/manage/account/publishing/>
   - TestPyPI: <https://test.pypi.org/manage/account/publishing/>

   Use project name `nexus-symbiote`, the repository's current owner (`Hunzee-VC`;
   the repository was transferred from `aisecnomad`, and the OIDC token carries the
   current owner), repository `Nexus-Symbiote`, workflow `release.yml`, and
   environment `pypi` or `testpypi` respectively. Always set the environment:
   without it, any job in the workflow holding an OIDC token could publish. No API
   token is needed or stored.
4. **Protect `main`** and require reviewed changes and successful `Verified CI`,
   including CodeQL high/critical and dependency-advisory acceptance, following
   [repository controls](repository-controls.md). The workflow cannot create these
   controls itself.

## Each release

1. Choose the version. `pyproject.toml` and `src/nexus_symbiote/__init__.py` must
   agree; `scripts/check_repository_hygiene.py` fails CI otherwise. Move the
   changelog's *Unreleased* entries under the new version.
2. Dispatch with `publish=none`. Inspect the run's wheel, source distribution, SBOM,
   exact source record, installed-distribution inventory, dependency advisory
   report, checksums and build/evidence attestations. Test the wheel in an isolated
   environment outside the checkout.
3. Dispatch with `publish=testpypi` and approve the `testpypi` environment. Fetch
   only this project from TestPyPI, check it against the run's `SHA256SUMS`, then
   install it with dependencies from PyPI alone. Anyone can register project names
   on TestPyPI, so never let it resolve dependencies (for example through
   `--extra-index-url`):

   ```bash
   python -m venv /tmp/rehearsal && . /tmp/rehearsal/bin/activate
   pip download --no-deps --index-url https://test.pypi.org/simple/ \
     nexus-symbiote==<version> -d /tmp/rehearsal-dist
   cd /tmp/rehearsal-dist
   sed 's#  dist/#  #' /path/to/run/SHA256SUMS | grep -F "$(ls ./*.whl | xargs -n1 basename)" \
     | sha256sum --strict -c -
   pip install /tmp/rehearsal-dist/*.whl
   nexus-symbiote --version
   ```

   An index never accepts the same file name twice, so a second rehearsal of the
   same version needs a new version number, for example a release candidate such
   as `0.1.0rc2`.
4. Dispatch with `publish=pypi` and approve the `pypi` environment. Review the
   artifacts of this exact run at the approval gate.
5. Verify the published files against this run's checksums and provenance. Constrain
   the signer, ref, commit and runner, not only the repository:

   ```bash
   gh attestation verify <file> --repo Hunzee-VC/Nexus-Symbiote \
     --signer-workflow Hunzee-VC/Nexus-Symbiote/.github/workflows/release.yml \
     --source-ref refs/heads/main --source-digest <release commit SHA> \
     --deny-self-hosted-runners
   ```

   Create a matching signed tag `v<version>` and release notes. Do not claim
   publication succeeded until the package index and the source revision agree.

A `testpypi` or `pypi` run fails closed if its read-only preflight cannot establish
the required branch controls and successful CI for the exact source commit, or that
the environment it is about to deploy to requires a reviewer with self-review
prevented and allows deployments from `main` alone. A missing environment also
fails: GitHub would otherwise create it, unprotected, on first use.
Candidate runs remain available before those controls are configured; an
inspectable candidate is not publication approval.

## What the pipeline guarantees

**Build integrity.** The build job exports the checked-out commit with `git archive`
and builds there with `SOURCE_DATE_EPOCH` set to the commit time. Nothing that a
later step writes into the workspace, such as test output or release evidence, can
reach the source distribution. Two local builds of the same commit produced
identical files; reproducibility across runners is not attested. The job then
checks that there is exactly one wheel and one sdist, runs `twine check --strict`,
and uploads them **before** anything runs tests, writes evidence or installs
packages. Later jobs receive those bytes by their immutable artifact ID, so a step
that misbehaves later in the build job cannot change the distributions that are
attested or published. Before deriving benchmark and checksum evidence from `dist/`,
the build re-checks the files against the digests recorded at staging and fails on
any difference. That evidence is produced after the upload, so its attestation binds
it to this run, not to the pre-test state of the job.

**Locked build tools.** The CI distribution build and the release build use
`--no-isolation` after installing `requirements-ci.lock` with hash verification. The
build frontend, backend and their dependencies come from the reviewed environment
instead of a fresh, unpinned one. Locking the backend does not make the build
bit-for-bit reproducible or authenticate the runner; those properties are not
claimed. Test the supported minimum and current dependency sets before widening
version bounds.

**Acceptance against the exact wheel.** The `distribution` CI job and the release
build install the exact candidate wheel into the locked test environment. The
acceptance runner verifies its SHA-256 against pip installation metadata, checks
the package import location, and runs selected tests outside the checkout. These
cover a clean repository baseline, a complete ShadowScan source report, a forged
inventory omitting a project file, an MCP endpoint substitution, supplier-controlled
policy discovery, a revoked trust signer, and distinct SPDX revision identities. A
failed or skipped acceptance case blocks the candidate before attestation.

**Public dependency ranges.** A separate compatibility job downloads the candidate
wheel by ID onto a fresh runner and resolves its runtime dependencies from PyPI, as
users will, then exercises it. Its token has no repository or OIDC permissions, and
it must pass before attestation. Files a floating dependency modifies there cannot
replace the candidate.

**Evidence.** The release build installs the wheel into a fresh environment with
hash-checked binaries from `requirements-action.lock`, then collects the SBOM and
benchmark evidence. `project.cdx.json` is a static inventory of the checked-out
project, not a guarantee of complete runtime or build dependency coverage.
`installed-distributions.json` records that locked environment. `source-revision.json`
requires the actual clean checkout to match the workflow's exact `GITHUB_SHA` and
records the repository, ref and run identity. `SHA256SUMS` covers that source
record, the release distributions and evidence files. The workflow bundles all
candidate evidence, including the checksums, in `release-evidence.tar.gz` and
attests that archive as well as the distributions and the inventory benchmark.

Every candidate runs the committed per-case security-regression gate and keeps its
complete `security-regressions.json` report, including failures, and rechecks its
installed locked dependencies against current OSV data, retaining that report even
on failure. Passing those finite fixture contracts is a release prerequisite, not an
estimate of production efficacy. The normal CI `Verified CI` check also requires
measured statement and branch coverage floors (90% and 75%), complete dependency
advisory lookups with no known advisories, a successful CodeQL analysis with no
high/critical security results, and every verification job to succeed. Publication
checks those security job results for the exact source. See the precise acceptance
policy and its knowledge limits in [repository controls](repository-controls.md).

**Privilege separation.** The build job reads repository content and Actions run
metadata only. A separate attest job holds OIDC and attestation-write permissions,
and only the environment-gated publish job can upload, through the trusted
publisher configured for its environment. Neither of those jobs checks out or runs
project source or any shell step. Every job that receives artifacts downloads them
by ID with `digest-mismatch: error`, so a corrupted transfer stops the run.

**Attestation verification.** After attestation, a separate verification job with
only read access to repository contents and attestations downloads the candidate
distributions and the retained distribution attestation bundle from this run. It
requires exactly one wheel and one source distribution and no other file, then
verifies each with GitHub CLI, constraining the repository, signing workflow, main
ref, source digest and runner type. The publish job depends on that job, so neither
the CLI nor its token runs with OIDC permissions. Missing artifacts, an extra file,
a missing bundle or failed verification block publishing. This validates the
attestation and subject bytes; it does not prove that the builder or its
dependencies were uncompromised.

The composite GitHub Action uses the same hashed runtime/build lock in an isolated
environment, then installs its reviewed source with dependency resolution and build
isolation disabled. This fixes its dependency input set without claiming
byte-identical builds.

A configured workflow is not execution evidence. At this review, no release run,
signed source tag, project release attestation or published package was verified.
Hosted runners and account features must be made operational before any such claim.
