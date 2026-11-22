# Release procedure

`.github/workflows/release.yml` is dispatched manually from `main` with one input,
`publish`:

| `publish` | What the run does |
|---|---|
| `none` (default) | Builds, tests and attests a release candidate. Uploads nothing to a package index. |
| `testpypi` | The same candidate, then uploads it to [TestPyPI](https://test.pypi.org/p/nexus-symbiote) as a rehearsal. |
| `pypi` | The same candidate, then uploads it to [PyPI](https://pypi.org/p/nexus-symbiote) and pushes its [container image](container-image.md) to `ghcr.io`. Refused until the release commit has been on `main` for 24 hours and its signed tag exists. |

A second input, `soak_override`, stays empty. To publish an urgent security fix before the
24 hours are up, give the reason there; the run log records it.

TestPyPI and PyPI use the same pipeline, the same gates and the same kind of attested
bytes, so a successful rehearsal exercises everything except the final index. This is
the only workflow that publishes to either index.

Nothing in this repository configures GitHub environments, package-index
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
   enable *Prevent self-review*, and restrict deployments to `main`. While the
   project has a single maintainer, *Prevent self-review* would leave nobody able to
   approve a deployment, so leave it off until a second reviewer exists, as with the
   interim branch protection; the required review still makes every upload wait for
   an explicit approval. The `main`-only restriction matters because the main-only
   checks live inside `release.yml`, which a branch could edit.
3. **Create a pending trusted publisher on each index**, right before the first
   upload, because a pending publisher does not reserve the name:
   - PyPI: <https://pypi.org/manage/account/publishing/>
   - TestPyPI: <https://test.pypi.org/manage/account/publishing/>

   Use project name `nexus-symbiote`, the repository's current owner (`aisecnomad`;
   the repository moved back from the Hunzee-VC organization, and the OIDC token
   carries the current owner), repository `Nexus-Symbiote`, workflow `release.yml`, and
   environment `pypi` or `testpypi` respectively. Always set the environment:
   without it, any job in the workflow holding an OIDC token could publish. No API
   token is needed or stored.

   After a repository move, the project's existing trusted publishers still name the
   previous owner, and the next run's OIDC token names the new one, so publishing
   fails. Before dispatching a publish, edit the trusted publisher on PyPI and on
   TestPyPI to the current owner, keeping the repository, workflow and environment.
4. **Protect `main`** and require successful `Verified CI`, including CodeQL
   high/critical and dependency-advisory acceptance, and, once a second
   authorized reviewer exists, reviewed changes, following the configurations in
   [repository controls](repository-controls.md). The workflow cannot create these
   controls itself. Apply both release-tag rulesets described there before creating the
   first `v*` tag: the README's verified-release install trusts the tag to stay on the
   published commit. Turn off administrator bypass on both environments. The
   creation-only rule allows repository administrators to create tags; the separate
   update/deletion rule allows nobody to move or delete them. The preflight of every
   `testpypi` and `pypi` run checks the immutable-tag ruleset and the
   environment and refuses to publish while either is missing. It cannot see who may
   bypass the ruleset, which GitHub shows only to administrators; the administrator
   check in [repository controls](repository-controls.md#apply-the-outstanding-controls)
   verifies that list.
5. **Register the tag-signing key** as a signing key on the maintainer's GitHub
   account, so that GitHub reports the release tag as verified; the preflight of a
   `pypi` run requires that.

## Each release

1. Choose the version. `pyproject.toml`, `src/nexus_symbiote/__init__.py` and
   `CITATION.cff` must agree; `scripts/check_repository_hygiene.py` fails CI
   otherwise. Move the changelog's *Unreleased* entries under the new version, and
   date its heading and `date-released` with the planned publication day; correct
   both afterwards if publication slips. Merge behavior-changing work at least 72
   hours before the planned publication, so that the release pull request itself
   changes only versions and records. Check that `NATIVE_SPEC_VERSION` in
   `core/models.py` has its schema digest pinned in `tests/test_native_contract.py`:
   that digest freezes when this release, the first to ship the version, is tagged,
   and any later schema change needs a new spec version.
2. Freeze `main`: after the release pull request merges, merge nothing else until
   the `pypi` run is approved. `workflow_dispatch --ref main` builds whatever `main`
   is at dispatch time and the preflight requires that exact head, so a Dependabot
   merge between runs would silently change the published bytes from the
   rehearsed ones. Builds of one commit from the locked environment are expected to
   produce identical files, so the `SHA256SUMS` of the candidate, TestPyPI and PyPI
   runs must list identical distribution digests; compare them. Dispatch with
   `publish=none`. Inspect the run's wheel, source distribution,
   environment SBOM, exact source record, installed-distribution inventory,
   dependency advisory report, checksums and build/evidence attestations. Test the
   wheel in an isolated environment outside the checkout.
3. Dispatch with `publish=testpypi` and approve the `testpypi` environment. Fetch
   only this project from TestPyPI, check it against the run's `SHA256SUMS`, then
   install it with dependencies from PyPI alone. Anyone can register project names
   on TestPyPI, so never let it resolve dependencies (for example through
   `--extra-index-url`):

   ```bash
   (
     set -euo pipefail
     version='REPLACE_WITH_VERSION'
     run_checksums='/path/to/run/SHA256SUMS'
     [[ "$version" =~ ^[0-9][0-9A-Za-z.!+_-]*$ ]]
     rehearsal="$(mktemp -d)"
     wheel_dir="$(mktemp -d)"
     python3 -m venv "$rehearsal"
     wheel="nexus_symbiote-${version}-py3-none-any.whl"
     "$rehearsal/bin/python" -m pip download --no-deps --only-binary=:all: \
       --index-url https://test.pypi.org/simple/ "nexus-symbiote==$version" -d "$wheel_dir"
     shopt -s nullglob dotglob
     downloaded=("$wheel_dir"/*)
     test "${#downloaded[@]}" -eq 1
     test "${downloaded[0]}" = "$wheel_dir/$wheel"
     test -f "$wheel_dir/$wheel"
     test ! -L "$wheel_dir/$wheel"
     expected_sha="$(awk -v file="dist/$wheel" \
       '$2 == file { n++; print $1 } END { if (n != 1) exit 1 }' "$run_checksums")"
     [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]]
     check=(sha256sum --strict -c -)
     command -v sha256sum >/dev/null || check=(shasum -a 256 --strict -c -)  # macOS
     (cd "$wheel_dir" && printf '%s  %s\n' "$expected_sha" "$wheel" | "${check[@]}")
     "$rehearsal/bin/python" -m pip install --index-url https://pypi.org/simple/ "$wheel_dir/$wheel"
     "$rehearsal/bin/nexus-symbiote" --version
   )
   ```

   Replace the version and checksum-file placeholders, using the independently
   reviewed run's manifest, and paste the whole block. It requires exactly one
   downloaded wheel and one exact manifest entry, stops on every failed step,
   and installs only that verified path. The installer selects PyPI for dependencies;
   use pip configuration that does not add extra indexes. The two fresh temporary directories remain available for inspection;
   remove them after the rehearsal. The checksum check does not protect against
   another process running as your account replacing the wheel after verification.

   Confirm the PEP 740 provenance the index itself publishes: the file page must
   show a verified provenance entry naming this repository and `release.yml`.
   `pypi-attestations verify pypi` fetches provenance only from PyPI, so for a
   TestPyPI file download
   `https://test.pypi.org/integrity/nexus-symbiote/<version>/<file>/provenance` and
   run `pypi-attestations verify pypi --repository https://github.com/aisecnomad/Nexus-Symbiote --provenance-file <provenance> <local file>`
   in a throwaway environment. Open the rendered project page and check the
   headings, the banner and the alpha note.

   An index never accepts the same file name twice, so a second rehearsal after a
   fix needs a new version number. A pre-release such as `0.1.0rc2` is not a valid
   successor: it sorts before `0.1.0` and would not satisfy `nexus-symbiote==0.1.0`.
   Bump to the next patch version, rehearse it, and publish that version.
4. Tag the release commit before publishing, so that the README's verified install
   works from the moment the package appears. A repository administrator creates a
   signed, annotated tag and pushes it using their own authenticated identity:

   ```bash
   git tag -s v<version> -m "nexus-symbiote <version>" <release commit SHA>
   git push origin v<version>
   git ls-remote origin 'refs/tags/v<version>^{}'   # must print the release commit
   ```

   A lightweight tag, which the GitHub release page creates when the tag does not
   exist yet, breaks the README's install; the release-tag ruleset then prevents
   replacing the tag, so check the commit before pushing. If the release is abandoned
   after tagging, the tag stays where it is; publish the next patch version under a
   new tag.
5. Wait until the release commit has been on `main` for 24 hours, the soak period that
   stands in for a second reviewer, then dispatch with `publish=pypi` and approve the
   `pypi` environment. The preflight refuses an earlier run, a tag that is missing,
   unverified or on another commit, and an environment or tag ruleset that is missing
   or not protected. Its log and job summary note that the workflow token could not
   read the ruleset's bypass list: before approving, run the administrator check
   (`--verify-bypass-actors`, see
   [repository controls](repository-controls.md#apply-the-outstanding-controls)) for
   the release commit. Review the artifacts of this exact run at the approval gate.
   For an urgent security fix, set `soak_override` to the reason instead of waiting;
   say so in the release notes. Once the upload has succeeded, the `image` job waits for
   a second approval of the `pypi` environment: check the published files first. It
   builds the image from the run's wheel, runs it without the network, pushes it to
   `ghcr.io/<owner>/<repository>` (lowercased) under the version, and the shell-free
   `image-attest` job attests the pushed digest; `image-verify` then checks that
   attestation as step 6 does. After the first release, check the package's visibility:
   depending on the account's settings a new `ghcr.io` package can start private, and
   only a public one can be pulled and verified by others.
6. Verify the published files against this run's checksums and provenance. Constrain
   the signer, ref, commit and runner, not only the repository:

   ```bash
   gh auth login
   gh attestation verify <file> --repo aisecnomad/Nexus-Symbiote \
     --signer-workflow aisecnomad/Nexus-Symbiote/.github/workflows/release.yml \
     --source-ref refs/heads/main --source-digest <release commit SHA> \
     --deny-self-hosted-runners
   ```

   For the image, take the digest from the `image` job's summary and verify it the
   same way, as `oci://ghcr.io/aisecnomad/nexus-symbiote@<digest>` (see
   [container image](container-image.md#verify-and-run-a-published-image)).

   Do not claim publication succeeded until the package index and the source revision
   agree.
7. Publish the GitHub release and its evidence. The run's artifacts expire after 90
   days; the release keeps them:

   ```bash
   gh run download <run id> --dir release-assets \
     --name release-distributions --name release-evidence \
     --name distribution-attestation --name release-evidence-attestation \
     --name inventory-benchmark-attestation
   gh release create v<version> --verify-tag --notes-file <notes> \
     release-assets/release-distributions/* \
     release-assets/release-evidence/SHA256SUMS \
     release-assets/release-evidence/release-evidence.tar.gz \
     release-assets/*-attestation/*
   ```

   Offline verification with `gh attestation verify --bundle` then stays possible
   after the run is gone. Fetch the Sigstore trusted root once while online, with
   `gh attestation trusted-root > trusted_root.jsonl`; the verification itself then
   needs neither `gh auth login` nor a network connection. `SHA256SUMS` names the
   distributions as `dist/<file>`, so map that prefix to where they were downloaded.
   From the directory that holds `release-assets`:

   ```bash
   sed -n 's#  dist/#  release-assets/release-distributions/#p' \
     release-assets/release-evidence/SHA256SUMS | sha256sum --strict -c -
   bundles=(release-assets/distribution-attestation/*)   # the run retains exactly one
   gh attestation verify \
     release-assets/release-distributions/nexus_symbiote-<version>-py3-none-any.whl \
     --repo aisecnomad/Nexus-Symbiote \
     --bundle "${bundles[0]}" \
     --custom-trusted-root trusted_root.jsonl \
     --signer-workflow aisecnomad/Nexus-Symbiote/.github/workflows/release.yml \
     --source-ref refs/heads/main --source-digest <release commit SHA> \
     --deny-self-hosted-runners
   ```

   Name the image digest in the notes.
8. Update the records that describe the release, in one documentation pull request:
   the changelog heading's date (the day of the PyPI upload, in UTC), `date-released`
   in `CITATION.cff`, the dated rows of the
   [operator prerequisites](repository-controls.md#operator-prerequisites) table with
   what the preflight verified, the roadmap, and the
   [release record](#release-record) below.

## Rollback and incidents

- A file name can never be reused on either index. A fix is always a new version;
  the next patch version is the successor of a bad release.
- Yanking: a project owner yanks a release on the index with a reason. A yanked
  version still installs for anyone who pins it exactly, so yank only together with
  a published fix and a changelog entry naming the defect. Yank rather than merely
  supersede when the published bytes are wrong or vulnerable.
- Partial upload: if one of the two files uploads and the other fails, do not edit
  `release.yml` to retry. A new commit changes the bytes of both files, because the
  sdist ships the workflow and the build timestamp comes from the commit, so the two
  files of one release would come from different commits. Confirm the uploaded file's
  digest against that run's `SHA256SUMS`, then use **Re-run failed jobs** on the same
  run: `publish` downloads that run's `release-distributions` artifact again instead
  of rebuilding. If the index still refuses the retry, leave the version incomplete
  and publish the next patch version.
- Image failure after the PyPI upload: the upload stands. Use **Re-run failed jobs** on
  the same run; the image job builds again from that run's wheel, the version's tag
  moves to the new digest, and `image-attest` attests that digest.
- Burned TestPyPI version: PyPI can still take the version, but the published bytes
  would not be the rehearsed ones. Prefer bumping and rehearsing again.
- Name rejected at upload time: the publish job fails before any file lands. Choose a
  new name only after checking both indexes, and update `pyproject.toml`, the trusted
  publishers and the environments' URLs together.
- Security defect after publication: open a GitHub Security Advisory, publish the
  fixed version first, then yank the affected one and reference the advisory in the
  release notes and the changelog.

A `testpypi` or `pypi` run fails closed if its read-only preflight cannot establish
the required branch controls, successful CI for the exact source commit, the
release-tag ruleset and the environment's protection; a `pypi` run also needs the
24-hour soak and the signed tag on that commit. Who may bypass the ruleset is not
readable with the workflow token; the administrator check covers it. Candidate runs
remain available before those controls are configured; an inspectable candidate is not
publication approval.

## What the pipeline guarantees

**Build integrity.** The build job exports the checked-out commit with `git archive`
and builds there with `SOURCE_DATE_EPOCH` set to the commit time. Nothing that a
later step writes into the workspace, such as test output or release evidence, can
reach the source distribution. Two local builds of the same commit produced
identical files; reproducibility across runners is not attested. The job then
checks that there is exactly one wheel and one sdist, runs `twine check --strict`,
and uploads them **before** anything runs tests, writes evidence or installs
anything but the hash-locked build environment and the checkout, which it installs
first. Later jobs receive those bytes by their immutable artifact ID, so a step
that misbehaves later in the build job cannot change the distributions that are
attested or published. Before deriving benchmark and checksum evidence from `dist/`,
the build re-checks the files against the digests recorded at staging and fails on
any difference. That evidence is produced after the upload, so its attestation binds
it to this run, not to the pre-test state of the job.

**Locked build tools.** The CI distribution build and the release build use
`--no-isolation` after installing `requirements-ci.lock` with hash verification and
`--only-binary=:all:`, so a missing wheel stops the job instead of building a source
distribution with unpinned, unhashed build requirements. The build frontend, backend
and their dependencies come from the reviewed environment instead of a fresh,
unpinned one. Two builds of one commit from that environment are expected to match,
and the checksums of the candidate, TestPyPI and PyPI runs are compared by hand
(step 2); bit-for-bit reproducibility across runners is not attested.

**Declared dependency ranges.** CI runs the full suite on the locked versions, on every
supported Python, and on the declared floors (`requirements-floor.lock`, Python 3.11);
the scheduled "Dependency health" workflow runs it on the newest releases the ranges
admit and on any pull request that changes them. See "Dependency locks" in
[CONTRIBUTING.md](../CONTRIBUTING.md).

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
users will, then scans the demo agent with a TypeScript MCP server added, in every
export format, and scores the result (`scripts/check_installed_wheel.py`, taken from
the candidate's own sdist). Its token has no repository or OIDC permissions, and it
must pass before attestation. Files a floating dependency modifies there cannot
replace the candidate.

**Evidence.** The release build installs the wheel into a fresh environment with
hash-checked binaries from `requirements-action.lock`, then collects the SBOM and
benchmark evidence. `project.cdx.json` is a static inventory of the checked-out
project, not a guarantee of complete runtime or build dependency coverage. The build
job sets `SOURCE_DATE_EPOCH` to the commit time, so `project.cdx.json` records that
time, not the time of the scan, as its collection time; without it the inventory would
record none. Its serial number is derived from its content either way (see
[reproducible inventories](reproducible-inventories.md)).
`installed-distributions.json` records that locked environment and
`environment.cdx.json` is the same record as a CycloneDX 1.7 SBOM of the installed
distributions, validated against the vendored schema. Writing it fails unless every
installed distribution other than the wheel and the virtual environment's own pip is
pinned by `requirements-action.lock` at the installed version, and the SBOM records
that lock's SHA-256. Its dependency edges come from each distribution's declared
requirements, kept only where the requirement's marker holds for the inspected
interpreter and an active extra; it describes what pip reports, not file
authenticity, and carries no file hashes because pip does not record which of a
lock entry's files it installed. `source-revision.json`
requires the actual clean checkout to match the workflow's exact `GITHUB_SHA` and
records the repository, ref and run identity. `SHA256SUMS` covers that source
record, the release distributions and evidence files. The workflow bundles all
candidate evidence, including the checksums, in `release-evidence.tar.gz` and
attests that archive as well as the distributions and the inventory benchmark.

Every candidate runs the committed per-case security-regression gate and keeps its
complete `security-regressions.json` report, including failures, and rechecks every
pin of `requirements-ci.lock` and `requirements-action.lock` against current OSV
data, retaining that report even on failure. Passing those finite fixture contracts
is a release prerequisite, not an estimate of production efficacy. The normal CI
`Verified CI` check also requires the package and per-module coverage floors in
`scripts/check_coverage.py`, the full suite at the declared dependency floors,
complete dependency advisory lookups with no unwaived advisory, a successful CodeQL
analysis with no high/critical security results, and every verification job to
succeed. Publication checks those security job results for the exact source. See the
precise acceptance policy and its knowledge limits in
[repository controls](repository-controls.md).

**Privilege separation.** The build job reads repository content and Actions run
metadata only. A separate attest job holds OIDC and attestation-write permissions,
and only the environment-gated publish job can upload, through the trusted
publisher configured for its environment. Neither of those jobs checks out or runs
project source or any shell step. On a `pypi` run, the image job, gated by the same
environment, holds a token that can write packages but no OIDC; the image-attest job holds
OIDC and attestation-write permissions for the digest that job pushed, and runs no
shell either. Every job that receives artifacts downloads them
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

A configured workflow is not execution evidence; each release records what was
verified below.

## Release record

- **0.1.0.** `release.yml` (environment `pypi`) published the wheel and sdist to
  PyPI on 2026-11-08 at 01:28 UTC, 24 minutes after the TestPyPI rehearsal and
  100 minutes after the release commit `d8c54e4` merged; both files carry PEP 740
  provenance naming this workflow, which also confirmed the trusted publishers. The
  package files in the published wheel are byte-identical to `src/nexus_symbiote` at
  the tag. The signed, annotated tag
  `v0.1.0` was created on 2026-11-09, after publication, so the README's verified
  install failed closed in between. Whether the release-tag ruleset was applied and
  administrator bypass turned off before the tag was not recorded. From the next
  release the preflight requires the soak, the tag, the ruleset and the protected
  environment before it publishes.
