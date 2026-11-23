# Repository verification controls

The `Verified CI` job summarizes the full test matrix, the full suite on macOS, the
tests at the declared dependency floors, quality checks (including the lock check),
coverage, distribution checks, security regressions, dependency-advisory acceptance,
CodeQL security policy, and the composite Action run end to end on passing, failing
and hostile fixtures, with a check that the hostile fixture created no annotation.
CodeQL is part of this same CI run rather than an independent green badge.

It fails if any prerequisite fails, is skipped or is cancelled. Make this exact
context a required status check on `main`; running a workflow alone does not enforce
it.

`config/github-main-protection.json` is a proposed GitHub branch-protection
configuration. It binds `Verified CI` to the GitHub Actions app (ID 15368) and
requires an up-to-date branch, that successful check, one
independent approval including approval of the last push and of the code owner
named in `.github/CODEOWNERS`, resolved discussions, and enforcement for
administrators. It disables branch deletion and force pushes. The configuration file
is not an applied repository setting. The approval requirement needs another
authorized reviewer, who must also be added to `.github/CODEOWNERS`.

`config/github-main-protection-interim.json` is the same configuration with
`required_pull_request_reviews` set to `null`. Use it only while the project
has no second authorized reviewer: applying the full configuration's
`required_approving_review_count: 1` with `enforce_admins: true` and no
bypass actor/restrictions on a single-maintainer repository blocks the
maintainer from merging their own pull requests, because GitHub does not
count self-approval toward a required review. The interim file still binds
`Verified CI` to the GitHub Actions app, enforces it for administrators, and
disables force pushes and branch deletion. `scripts/check_repository_controls.py`
checks that protection is enabled, that `Verified CI` is required, bound to
the GitHub Actions app and enforced for administrators, and the CI results; it
cannot see force-push, deletion or review settings, so the interim configuration
satisfies the same publication preflight. Switch to the full configuration once a second
reviewer can approve changes, rather than leaving the weaker one in place
indefinitely.

After reviewing the exact configuration, an administrator with the appropriate
GitHub plan and repository Administration permission can apply it with:

```sh
# Solo-maintainer interim: no required review, same enforced status check
gh api --method PUT repos/aisecnomad/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection-interim.json

# Full target configuration, once a second reviewer is available
gh api --method PUT repos/aisecnomad/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection.json
```

Do not place an administrative token in CI. The publication preflight uses
only repository contents-read and Actions-read permissions:

```sh
python scripts/check_repository_controls.py --repo aisecnomad/Nexus-Symbiote --branch main --sha "$GITHUB_SHA" --publish pypi
```

The preflight requires `GH_TOKEN` or `GITHUB_TOKEN`. It checks GitHub's live
branch metadata, requires protection and administrator-wide status-check
enforcement, and verifies that `Verified CI` is required. It also requires the exact
source SHA to match the live branch head, the newest trusted run of
`.github/workflows/ci.yml` for that SHA (a `push` or `workflow_dispatch` run on the
expected branch in this repository) to have succeeded, and exactly one successful
job each named `Verified CI`, `CodeQL policy` and `Dependency advisories` in that
run's latest attempt. A pull-request or fork run for the same commit is not
evidence and cannot displace the trusted run, whether it is newer or still waiting
for approval; a newer trusted run that is pending or failed still wins over an
older success. An unbound status with the same name cannot satisfy the protection
preflight.

With `--publish testpypi` or `--publish pypi`, as the release workflow passes, it
also requires an active ruleset that stops `refs/tags/v*` from being updated or
deleted and that the checking token itself cannot bypass. It refuses such a ruleset
that also restricts tag creation (no one could then create a release tag; creation
belongs to the separate creation-only ruleset described
[below](#apply-the-outstanding-controls)). It requires the named environment to have
a required reviewer, administrator bypass turned off and deployments limited to
`main` by a single branch policy (the *Protected branches* option admits every
protected branch, so it is refused).

GitHub returns a ruleset's bypass actors only to a caller that may edit the ruleset,
so the release workflow's read-only token cannot tell whether an administrator, a
team or an app may bypass it: the run prints a notice instead of treating the unseen
list as empty. Only the
[administrator check](#apply-the-outstanding-controls), run with
`--verify-bypass-actors` and an administrator's token, verifies that the list is
empty, and it fails when the list cannot be read.

With `--publish pypi` it further requires the release commit to have been on `main`
for 24 hours, measured from the later of its commit time and the first `push` run
GitHub created for it, unless the `SOAK_OVERRIDE` variable states a reason of at
least 20 characters, which is printed. A commit with no `push` run, such as one
pushed with `[skip ci]`, has no landing time and needs that override.

It also requires the signed, annotated tag `v<version>` (the version in
`pyproject.toml`) to point at the source commit with a signature GitHub reports as
verified; when `ALLOWED_RELEASE_TAG_SIGNERS` lists comma-separated tagger emails,
the tag's `tagger.email` must also match that allowlist. The release workflow passes
the repository variable `ALLOWED_RELEASE_TAG_SIGNERS` to this preflight; a value
that names no signer fails.

All GitHub API calls ignore ambient proxy environment variables, verify certificates
with TLS 1.2 or later without reading `SSLKEYLOGFILE`, and reject duplicate JSON
keys and non-finite numbers (`NaN`, `Infinity` and overflowing literals such as
`1e999`).

Missing or truncated run, job, ruleset or environment data, an API failure,
redirects and an unprotected branch fail closed; the one exception is the bypass list
described above, which the workflow token is never shown. The SHA defaults to
`GITHUB_SHA`; local invocations must supply their reviewed commit explicitly.

The preflight does not audit approval counts, force-push and deletion settings or
package-index ownership; an administrator must review those separately, for example
with `gh api repos/aisecnomad/Nexus-Symbiote/branches/main/protection`. It checks
live state during the build; it does not lock GitHub settings or cancel a candidate
after later administrative changes. Review the exact run and current controls at the
environment approval. Candidate builds remain available while controls are being
configured; publication requires a successful preflight.

If GitHub reports an unavailable plan feature or insufficient Administration
permission, resolve that account setting before claiming branch protection is
active. Review the latest run annotations to resolve failures that happen
before any job steps start; a local passing suite does not establish that GitHub
Actions successfully ran.

Repository rulesets do not substitute for this configuration. The preflight reads
the classic branch-protection metadata that GitHub reports on the branch, so a
ruleset, however strict, cannot satisfy it. A ruleset whose target list is empty
applies to no branch at all, even when its enforcement is `active`. Check what
actually applies to `main` with `gh api repos/aisecnomad/Nexus-Symbiote/rules/branches/main`.

## Security acceptance evidence

The `CodeQL policy` job in `ci.yml` analyzes the workflow checkout's Python with the
pinned CodeQL Action and `security-and-quality` queries. The `CodeQL` workflow
(`codeql.yml`) analyzes Python and the `actions` language (the workflows and
`action.yml`) on every pull request, every push to `main` and weekly. It must run on
pull requests: code scanning compares a pull request with every CodeQL configuration
`main` holds, keyed by workflow and category, and the repository ruleset holds the
merge until each has a result, so a configuration only `main` produces blocks every
merge. For each analysis, the next step requires a nonempty
CodeQL rule catalog and rejects every security result with `security-severity`
7.0 or greater, including existing and suppressed results. Missing or invalid
severity on a security-tagged result fails closed. A successful analysis step
alone is not a zero-alert policy decision. Raw SARIF and the policy reports are
retained together.

The policy script requires the actual Git `HEAD` to equal `GITHUB_SHA` and no
tracked source changes. On pull requests, default checkout and `GITHUB_SHA` both
identify the merge commit; substituting the PR head SHA fails. On `main` they
identify the push commit. Each SARIF run must record at least one invocation and
every invocation must explicitly report success. When a run supplies source
revision metadata, each revision must match the checkout. The workflow checker
binds checkout, initialization, analysis and their inputs to the policy step.
The report records a digest of the SARIF produced by that sequence. The
standalone SARIF evaluator does not authenticate an arbitrary file's origin.
Weekly/manual CodeQL runs apply the same policy; only the exact-source CI run
supplies publication acceptance.

`Dependency advisories` audits every exact version pinned by `requirements-ci.lock`,
`requirements-action.lock` and `requirements-floor.lock`, whatever its environment marker, so pins that only
Python 3.11 or Windows installs are queried too even though the job runs on Python
3.12 on Linux. Distributions installed on the runner but pinned by no lock, such as
the runner's own pip, are listed in the report and not audited: they are not part of
the reviewed set. It reuses the bounded HTTPS transport and follows
[OSV's per-query batch pagination](https://google.github.io/osv.dev/post-v1-querybatch/)
with package, page, response and total-time limits. Every query must complete;
transport errors, malformed results and missing pages deny acceptance and retain
a failure report. Any known advisory blocks the gate. The only exception is an
expiring waiver in `config/dependency-advisory-waivers.json`, made in a reviewed pull
request for one advisory of one exact package version, with a reason and an expiry
at most 90 days ahead; the gate prints and records each waived advisory and fails on
an expired, malformed or stale waiver. No new audit-tool dependency is resolved
outside the lock. This queries public `https://api.osv.dev/v1/querybatch` without
credentials and needs direct outbound HTTPS. If OSV is unavailable the gate fails
closed; re-run it later. This source-built project is excluded from PyPI lookups and
identified by the reviewed source revision instead. An empty OSV response means no
advisory known to OSV for that queried version; it does not establish absence of
vulnerabilities, malicious packages or undisclosed defects.

The "Dependency health" workflow repeats the audit every day, so an advisory
published in a week without pushes still turns a run red, and audits the floor lock
in a separate job: an advisory at a declared floor means a user can satisfy the
published range with a vulnerable version, and the floor should rise. Each failed
scheduled run notifies the maintainer through GitHub's workflow notifications.

## Workflow integrity

`scripts/check_workflows.py` runs in the quality job. It requires every remote action
in the workflows and in `action.yml`, and in any local action they reference, to be
pinned to a commit with a full-version comment (`# v1.2.3`) that agrees wherever the
same commit is used and is not older than the floor recorded for that action; a local
action that does not exist fails.

It rejects `${{ }}` expressions in shell source, triggers other than `push`,
`pull_request`, `workflow_dispatch`, `schedule` and `branch_protection_rule` (so
`pull_request_target` and `workflow_run` cannot appear), missing or writable
top-level permissions, jobs without `timeout-minutes`, and checkouts that persist
credentials, and it checks a file in `.github/workflows` as a workflow whatever its
name.

In `ci.yml`, `release.yml` and `codeql.yml` it rejects `continue-on-error` on a job,
and on a step unless a later step that runs reads that step's outcome (naming it in
the later step's name does not count), and requires each verification job, `Verified
CI` and the release attestation check among them, to still run the command that makes
it a gate as a command of its own, under errexit, in `bash` (GitHub's default or
`shell: bash`) and in the checkout's root: a gate command that is quoted,
in an `if` or loop condition, negated, joined with `&&` or `||` (other than
`|| exit N` for an N that is not a multiple of 256), in the background or in a pipeline
without `pipefail`, that follows `set +e`, `set -n`, `set -t`, `shopt -u -o errexit`,
`shopt -s -o noexec`, a `set` or `shopt` whose options come from an expansion, `cd`,
`trap`, `exit`, `eval` or `hash` (also through `builtin`, `command` or `time`, or a
command name built from an expansion, braces included), that runs under an option that
prints and exits instead (`python -h`, `-V` or `-i`, `bash --version` or `-D`, a
`timeout` option other than the reviewed ones), whose step continues on error, or whose
step, job or workflow sets another shell or a working directory, does not count. A pin
written in any form other than a `uses:` line of its own is rejected, because its version
comment cannot be read.
A `$VAR` command name counts only while a plain `VAR=value` line still binds it, and a
script the checker reads differently from `bash` (a here-document delimiter that is
partly quoted, or a `case` inside `$(...)`) has no gates. A gate step whose workflow, job
or step `env` sets a variable that loads code into it or changes how it runs is refused:
the loader and Python variables, `PYTEST_ADDOPTS`, the bash start-up variables
(`SHELLOPTS`, `BASHOPTS`, `PS4`, `ENV`, `BASH_ENV`, `PATH`), `HOME` (Python's default
user site and git's global configuration are under it), and any name that starts
`BASH_FUNC_`, `PYTHON`, `GIT_` or `XDG_` or has a character outside `[A-Za-z0-9_]`. The steps of
the pull-request size cap and of the CodeQL policies must match their reviewed run script
and environment exactly, so `--limit`, `--base HEAD` or `--numstat-file` cannot
neutralize the cap and each policy reads the SARIF its analysis wrote; `codeql.yml`
must analyze `python` and `actions` and run on `push`, `pull_request` and `schedule`.
A job that runs a gate may not run in a job `container` or beside `services`, whose
image would supply its own `python`, `git` and `HOME`. A job that runs a gate may not name
`GITHUB_ENV` or `GITHUB_PATH` anywhere in its run scripts, other than the release's
reviewed `SOURCE_DATE_EPOCH` write. That is a tripwire for the forms a reviewer would
miss (`printenv`, `${!name}`, `os.environ`), not a boundary: an earlier step can still
reach those files without naming them, or overwrite a gate script, so earlier steps of a
gate job need the same line-by-line reading. All of these checks live in
files a pull request can change; read changes to them line by line.

The OpenSSF Scorecard workflow publishes the repository's
[Scorecard results](https://scorecard.dev/viewer/?uri=github.com/aisecnomad/Nexus-Symbiote)
weekly and on every push to `main`, and uploads them to code scanning. It is an
external, repeatable view of these controls, not a gate.

## Operator prerequisites

Status of the controls tracked in
[issue #74](https://github.com/aisecnomad/Nexus-Symbiote/issues/74), as observed
through the GitHub API on 2026-11-06, with what the 0.1.0 publication on 2026-11-08
established. Re-check live settings before relying on any row; this table is a
dated record, not enforcement. The publication preflight now checks the immutable tag
ruleset and the environments at every `testpypi` and `pypi` run, so the rows marked
"checked at publication" are verified, or the publication refused, each time; the
ruleset's bypass list is the exception, which only the administrator check can read.

| Control | Observed state | Required action |
| --- | --- | --- |
| Hosted CI matrix and CodeQL | Passing on `main` at `3ad53a25`: CI and Code Quality green (observed 2026-11-12). The earlier failures were a runtime-validation CPU budget and real dependency advisories, fixed in [#97](https://github.com/aisecnomad/Nexus-Symbiote/pull/97) and [#98](https://github.com/aisecnomad/Nexus-Symbiote/pull/98) | None; keep `Verified CI` required |
| Branch protection on `main` | The interim configuration was applied on 2026-11-06: `Verified CI` is required, bound to the GitHub Actions app, on an up-to-date branch and for administrators too; conversations must be resolved; force pushes and deletion are disabled; no review is required | Switch to the full configuration once a second reviewer exists |
| Repository ruleset `main` | Retargeted on 2026-11-06 to the default branch, where its deletion, non-fast-forward, CodeQL (high or higher), pull-request (no approvals required; the extra approval for unattributed changes is enabled), code-quality, secret-scanning-resolution and Copilot-review rules now apply. Its required-checks list is empty: classic protection supplies the `Verified CI` requirement | Keep it alongside classic protection, which is the only thing the preflight reads |
| Private vulnerability reporting | Enabled | None |
| Secret scanning and push protection | On 2026-11-19 the repository settings API reported both `secret_scanning` and `secret_scanning_push_protection` as `disabled`. The earlier "Enabled" was not dated | Enable both under Settings, Code security, then record the date here |
| `testpypi` and `pypi` environments | Both exist with @aisecnomad as the required reviewer, *Prevent self-review* off because there is a single maintainer (see [releasing](releasing.md)), and deployments limited to `main`. On 2026-11-06 administrators could bypass the protection rules; whether that was turned off before 0.1.0 was not recorded. Checked at publication | Turn off administrator bypass before the next publication, which is refused otherwise; turn on *Prevent self-review* once a second reviewer exists |
| Trusted publishers | Confirmed by the 0.1.0 uploads on 2026-11-08: the OIDC uploads to TestPyPI (01:04 UTC) and PyPI (01:28 UTC) succeeded, and the PyPI files carry provenance naming `release.yml` and the `pypi` environment | None |
| Release tags `v*` | `v0.1.0` (signed, annotated, on `d8c54e4`) was created on 2026-11-09, after publication. Whether the release-tag ruleset was applied first was not recorded; without it, anyone with write access can move or delete the tag. The README's verified-release install requires the wheel's attestation to name the commit the tag points at. That stops a plain tag move, but not a move to a second commit that differs only in its lock file: candidate runs are attested without approval. Only the immutable-tag ruleset keeps the tag on the published commit. Checked at publication, except who may bypass it | Confirm with `gh api repos/aisecnomad/Nexus-Symbiote/rulesets`; apply the [immutable-tag rule](../config/github-release-tag-ruleset.json) if it is missing, which the next publication otherwise refuses, and the [creation-only rule](../config/github-release-tag-creation-ruleset.json), which limits who may create a `v*` tag; see [apply the outstanding controls](#apply-the-outstanding-controls) |

The repository is public, so branch protection, rulesets, artifact attestations
and environment protection are available on every GitHub plan; the
private-repository plan restriction recorded by the 2026-11-02 audit no longer
applies. An administrator applies these settings. Repository changes cannot.
Do not remove the acceptance gates to work around an unavailable platform feature.

### Apply the outstanding controls

The other controls in the table were applied on 2026-11-06; to re-apply branch
protection, use the interim command above. Run these as a repository
administrator, after reviewing each configuration:

Use two independent tag rulesets. The [immutable-tag rule](../config/github-release-tag-ruleset.json)
forbids updates and deletions with no bypass actors. The
[creation-only rule](../config/github-release-tag-creation-ruleset.json) permits only
repository administrators to create `v*` tags (`RepositoryRole` ID 5). A creator's
bypass applies only to that second rule; it does not permit moving or deleting an
existing tag. Administrators can still edit repository settings, so the rule
configuration itself remains an administrative trust boundary.

First list the live rulesets and review their full details. If a `release tags`
rule already exists, **update that rule** with the immutable configuration below;
do not leave an older no-bypass creation rule active beside a new rule. Every
matching rule applies, and the old one would still block all creation. For a
missing rule, use `POST .../rulesets` instead of `PUT .../rulesets/<id>`.

```sh
gh api repos/aisecnomad/Nexus-Symbiote/rulesets --jq '.[] | {id, name, target, enforcement}'

# 1. Set this to the reviewed existing "release tags" ID from the listing.
: "${IMMUTABILITY_RULESET_ID:?Set the existing release tags ruleset ID}"
gh api --method PUT "repos/aisecnomad/Nexus-Symbiote/rulesets/$IMMUTABILITY_RULESET_ID" \
  --input config/github-release-tag-ruleset.json

# 2. Create the separate creation rule only if it is absent.
#    If it exists, PUT its reviewed ID instead; do not create duplicates.
gh api --method POST repos/aisecnomad/Nexus-Symbiote/rulesets \
  --input config/github-release-tag-creation-ruleset.json

# 3. Confirm the publication preflight accepts the immutable-tag rule,
#    its empty bypass list, and the testpypi environment.
GH_TOKEN="$(gh auth token)" python scripts/check_repository_controls.py \
  --repo aisecnomad/Nexus-Symbiote --branch main --sha "$(git rev-parse origin/main)" \
  --publish testpypi --verify-bypass-actors
```

Step 3 is the administrator check. Run it after any change to the rulesets and before
approving each publication: it is the only check of who may bypass the release-tag
immutability rule, because GitHub does not show that list to the release workflow's
token. It rejects a creation restriction combined with the immutable rule; it
does not certify the separate creator list. Read back that rule's full details
and verify its sole rule is `creation`, its targets are exactly `refs/tags/v*`
with no exclusions, and its only bypass is the repository administrator role.
Confirm the intended release operator has that role before pushing the signed
tag described in [releasing](releasing.md#each-release). Do not grant the release
workflow permission to create tags or add a bypass to the immutable rule.

Turn off administrator bypass for the `pypi` and `testpypi` environments under
*Settings → Environments* first; step 3 fails while it is on. Step 3 passes only once
the newest trusted CI run for the `main` head has succeeded. Do not delete ruleset
`main` (ID 26325547): it now protects the default branch.

Under the interim protection, a commit can reach `main`, including the
maintainer's own, only after its `Verified CI` check has passed on a branch that
is up to date with `main`. In practice that means a pull request. That check is
produced by the workflow file in the pull request itself, so a pull request can
change the checks that admit it: `scripts/check_workflows.py` refuses a gate job that
lost its command, and changes to `.github/`, `scripts/`, `config/` and the locks
need a line-by-line reading, which `.github/CODEOWNERS` requests and the full
protection profile will enforce.

### Administrator actions still outstanding

These are not applied by a merge. An administrator has to run them. Until a second person can approve pull requests, do not apply `config/github-main-protection.json`: GitHub does not count the author's own approval, so the sole maintainer would be unable to merge.

```sh
# Require signed commits on main. Confirm contributors can sign before turning this on.
gh api --method POST repos/aisecnomad/Nexus-Symbiote/branches/main/protection/required_signatures

# Delete the head branch when a pull request merges.
gh api --method PATCH repos/aisecnomad/Nexus-Symbiote -f delete_branch_on_merge=true
```

Add the second reviewer to the repository as a collaborator, to `.github/CODEOWNERS`, to [MAINTAINERS.md](../MAINTAINERS.md), and to the PyPI project, then apply [the full protection profile](../config/github-main-protection.json). Do not invent an account to satisfy the file.

### Clean up merged branches

Branches whose work is on `main` only add places to base work on by mistake. Keep
what must survive as a tag, then delete the rest with one leased push, so that a
branch that moved since you listed it is not deleted:

```sh
git fetch --prune origin
# Keep the pre-reset foundation commit that the vendored schemas' SOURCES.json cites.
git tag archive/foundation-pre-reset 2afcee74ecbe7b71918e0ed977fe604aec4bf4be
git push origin archive/foundation-pre-reset
# Review the list, then delete branches fully merged into main, each leased to its SHA.
git for-each-ref --merged origin/main --format='%(refname:strip=3) %(objectname)' \
  refs/remotes/origin | grep -v -E '^(main|HEAD) ' > merged-branches.txt
args=()
while read -r name sha; do args+=("--force-with-lease=refs/heads/$name:$sha" ":refs/heads/$name"); done \
  < merged-branches.txt
# With no refspec, git push would push the current branch instead of deleting nothing.
if [ "${#args[@]}" -gt 0 ]; then git push --atomic origin "${args[@]}"; fi
```

Branches with commits that are not on `main` need a decision each: tag them under
`archive/` or delete them deliberately. Then turn on *Automatically delete head
branches* under *Settings → General*, so merged pull requests leave no branch behind.
