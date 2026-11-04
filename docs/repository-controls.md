# Repository verification controls

The `Verified CI` job summarizes the full test matrix, quality checks,
coverage, distribution checks, security regressions, dependency-advisory acceptance
and CodeQL security policy. CodeQL is part of this same CI run rather than an
independent green badge. It fails if
any prerequisite fails, is skipped or is cancelled. Make this exact context a
required status check on `main`; running a workflow alone does not enforce it.

`config/github-main-protection.json` is a proposed GitHub branch-protection
configuration. It binds `Verified CI` to the GitHub Actions app (ID 15368) and
requires an up-to-date branch, that successful check, one
independent approval including approval of the last push, resolved discussions,
and enforcement for administrators. It disables branch deletion and force pushes.
The configuration file is not an applied repository setting. The approval
requirement needs another authorized reviewer.

`config/github-main-protection-interim.json` is the same configuration with
`required_pull_request_reviews` set to `null`. Use it only while the project
has no second authorized reviewer: applying the full configuration's
`required_approving_review_count: 1` with `enforce_admins: true` and no
bypass actor/restrictions on a single-maintainer repository blocks the
maintainer from merging their own pull requests, because GitHub does not
count self-approval toward a required review. The interim file still binds
`Verified CI` to the GitHub Actions app, enforces it for administrators, and
disables force pushes and branch deletion. `scripts/check_repository_controls.py`
checks only the enforced, Actions-bound status check, not required reviews,
force pushes or deletion, which GitHub's branch metadata does not report without
administration access; the interim configuration therefore satisfies the same
publication preflight. Switch to the full configuration once a second
reviewer can approve changes, rather than leaving the weaker one in place
indefinitely.

After reviewing the exact configuration, an administrator with the appropriate
GitHub plan and repository Administration permission can apply it with:

```sh
# Solo-maintainer interim: no required review, same enforced status check
gh api --method PUT repos/Hunzee-VC/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection-interim.json

# Full target configuration, once a second reviewer is available
gh api --method PUT repos/Hunzee-VC/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection.json
```

Do not place an administrative token in CI. The publication preflight uses
only repository contents-read and Actions-read permissions:

```sh
python scripts/check_repository_controls.py --repo Hunzee-VC/Nexus-Symbiote --branch main --sha "$GITHUB_SHA"
```

The preflight requires `GH_TOKEN` or `GITHUB_TOKEN`. It checks GitHub's live
branch metadata, requires protection and administrator-wide status-check
enforcement, and verifies that `Verified CI` is required. It also requires the exact
source SHA to match the live branch head, the newest run of `.github/workflows/ci.yml`
for that SHA to succeed in this repository on the expected branch, and exactly one
successful `Verified CI`, `CodeQL policy` and `Dependency advisories` jobs in that
run's latest attempt. With `--environment pypi` or `--environment testpypi`, which
the release workflow passes for the index it is about to publish to, it also
requires that GitHub environment to exist, to have one required-reviewers rule
that names a reviewer and prevents self-review, and to allow deployments from
`main` alone through a single custom branch rule. A package index's trusted
publisher accepts the release workflow file from any ref, so these environment
settings, not the workflow's own `if:` conditions, stop a modified copy of the
workflow on another branch from publishing. An unbound status with the same name
cannot satisfy the protection preflight. A pending or failed
newer run cannot be replaced by an older success. Missing or truncated job data,
an API failure, redirects and an unprotected branch fail closed. The SHA defaults
to `GITHUB_SHA`; local invocations must supply their reviewed commit explicitly.
This limited preflight
does not independently audit approval counts, bypass actors (including an
environment's administrator bypass) or package-index ownership; an administrator
must review those separately. The preflight checks live state during the build; it
does not lock GitHub settings or cancel a candidate after later administrative
changes. Review the exact run and current controls at the environment approval.
Candidate builds remain available while controls are
being configured; publication requires a successful preflight.

If GitHub reports an unavailable plan feature or insufficient Administration
permission, resolve that account setting before claiming branch protection is
active. Review the latest run annotations to resolve failures that happen
before any job steps start; a local passing suite does not establish that GitHub
Actions successfully ran.

Repository rulesets do not substitute for this configuration. The preflight reads
the classic branch-protection metadata that GitHub reports on the branch, so a
ruleset, however strict, cannot satisfy it. A ruleset whose target list is empty
applies to no branch at all, even when its enforcement is `active`. Check what
actually applies to `main` with `gh api repos/Hunzee-VC/Nexus-Symbiote/rules/branches/main`.

## Security acceptance evidence

The `CodeQL policy` job analyzes the workflow checkout with the pinned CodeQL
Action and `security-and-quality` queries. The next step requires a nonempty
CodeQL rule catalog and rejects every security result with `security-severity`
7.0 or greater, including existing and suppressed results. Missing or invalid
severity on a security-tagged result fails closed. A successful analysis step
alone is not a zero-alert policy decision. Raw SARIF and the policy report are
retained together.

The policy script requires the actual Git `HEAD` to equal `GITHUB_SHA` and no
tracked source changes. On pull requests, default checkout and `GITHUB_SHA` both
identify the merge commit; substituting the PR head SHA fails. On `main` they
identify the push commit. Optional SARIF revision metadata must agree, and any
supplied invocation must explicitly report success. Native CodeQL can omit those
optional fields: source binding then comes from the trusted, pinned preceding
workflow step and the checked checkout, with a SARIF digest in the report. The
standalone SARIF evaluator does not authenticate an arbitrary file's origin.
Weekly/manual CodeQL runs apply the same policy; only the exact-source CI run
supplies publication acceptance.

`Dependency advisories` audits exact installed distribution versions after the
hashed CI lock is installed, together with every exact pin in
`requirements-ci.lock` and `requirements-action.lock`. The locks also pin packages
that only other Python versions or platforms install, such as the Python 3.11
backports the 3.11 test job uses, which the single audit interpreter would
otherwise never query. Every lock line must be blank, a comment, a lone SHA-256
hash or an exact pin, indented or not, because pip ignores indentation. Anything
else, such as a range, an include or an index option, fails the audit. It
reuses the bounded HTTPS transport and follows
[OSV's per-query batch pagination](https://google.github.io/osv.dev/post-v1-querybatch/)
with package, page, response and total-time limits. Every query must complete;
transport errors, malformed results and missing pages deny acceptance and retain
a failure report. Any known advisory blocks the gate, without a hidden severity
exception or allowlist. No new audit-tool dependency is resolved outside the lock.
This queries public `https://api.osv.dev/v1/querybatch` without credentials and
needs direct outbound HTTPS. This source-built project is excluded from PyPI
lookups and identified by the reviewed source revision instead. An empty OSV
response means no advisory known to OSV for that queried version; it does not
establish absence of vulnerabilities, malicious packages or undisclosed defects.

CI runs this audit only when something is pushed, so
`.github/workflows/dependency-audit.yml` repeats the same job daily, and on
manual dispatch, against `main`'s locks. A new advisory against a locked version
then fails that run, and so does the next pull request; refresh the locks in a
dedicated pull request. The scheduled run is not publication evidence: it is a
separate workflow because the preflight accepts only push and manual runs of
`ci.yml`. GitHub disables scheduled workflows in a public repository after 60
days without repository activity.

## Operator prerequisites

Status of the controls tracked in
[issue #74](https://github.com/Hunzee-VC/Nexus-Symbiote/issues/74), as observed
through the GitHub API on 2026-11-03. Re-check live settings before relying on
any row; this table is a dated record, not enforcement.

| Control | Observed state | Required action |
| --- | --- | --- |
| Hosted CI matrix and CodeQL | Passing. The earlier failures were a runtime-validation CPU budget and real dependency advisories, fixed in [#97](https://github.com/Hunzee-VC/Nexus-Symbiote/pull/97) and [#98](https://github.com/Hunzee-VC/Nexus-Symbiote/pull/98) | None; keep `Verified CI` required |
| Branch protection on `main` | Not protected: `protected: false`, and `GET /branches/main/protection` returns 404. At `c31d1ef`, 16 of the 94 first-parent commits on `main` were created outside GitHub's merge flow and pushed directly: 11 without a pull-request reference and 5 local merges or squashes of pull requests #57 and #59-#62. The other 9 commits without a pull-request number in their subject were committed by GitHub's web flow (8 squash merges and the initial commit) | Apply the interim configuration above |
| Repository ruleset `main` | Enforcement `active`, but `conditions.ref_name.include` is empty, so it targets no branch and its pull-request, code-scanning and non-fast-forward rules are inert; its required-checks list is also empty | Delete it, or deliberately retarget it in addition to classic protection |
| Private vulnerability reporting | Disabled, although [SECURITY.md](../SECURITY.md) directs reporters to it | Enable it under *Settings → Code security* |
| Secret scanning and push protection | Disabled | Enable both; they are free for public repositories |
| `testpypi` and `pypi` environments, trusted publishers | Not verifiable through the integration used for this review | Configure and verify as described in [releasing](releasing.md) |

The repository is public, so branch protection, rulesets, artifact attestations
and environment protection are available on every GitHub plan; the
private-repository plan restriction recorded by the 2026-11-02 audit no longer
applies. An administrator applies these settings. Repository changes cannot.
Do not remove the acceptance gates to work around an unavailable platform feature.

A gap review on 2026-11-04 recorded these further items, which issue #74 did not
track:

| Setting | Observed state | Required action |
| --- | --- | --- |
| Dependabot alerts and security updates | Not recorded. Dependabot version updates change only `pyproject.toml` ranges, never the hash locks that CI, the Action and releases install | Enable both (step 6 below). The scheduled `dependency-audit.yml` workflow audits the locked versions daily |
| Automatically delete head branches | Off in effect: the head branches of 86 merged pull requests remained | Enable it (step 7) |
| Stale branches | 119 branches besides `main`: 96 preserved, meaning every commit is on `main` or in a pull-request ref, among them the open #118 head; 23 hold commits found nowhere else | Delete the preserved ones as described in [delete preserved branches](#delete-preserved-branches); tag or deliberately abandon the rest |
| Issue labels | The feature-request form applies `enhancement`, which the label list recorded for the review (bug, core, dependencies, documentation, scanner, security, testing) lacks; issue forms skip labels the repository does not define | Create the label (step 8), or change the form |

### Apply the outstanding controls

Run these as a repository administrator, after reviewing each configuration:

```sh
# 1. Protect main with the solo-maintainer interim configuration
gh api --method PUT repos/Hunzee-VC/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection-interim.json

# 2. Confirm the publication preflight now accepts the live state
GH_TOKEN="$(gh auth token)" python scripts/check_repository_controls.py \
  --repo Hunzee-VC/Nexus-Symbiote --branch main --sha "$(git rev-parse origin/main)"

# 3. Enable private vulnerability reporting
gh api --method PUT repos/Hunzee-VC/Nexus-Symbiote/private-vulnerability-reporting

# 4. Enable secret scanning and push protection
gh api --method PATCH repos/Hunzee-VC/Nexus-Symbiote --input - <<'JSON'
{"security_and_analysis": {"secret_scanning": {"status": "enabled"},
                           "secret_scanning_push_protection": {"status": "enabled"}}}
JSON

# 5. Remove the ruleset that targets no branch (or retarget it deliberately)
gh api --method DELETE repos/Hunzee-VC/Nexus-Symbiote/rulesets/26325547

# 6. Enable Dependabot alerts and Dependabot security updates
gh api --method PUT repos/Hunzee-VC/Nexus-Symbiote/vulnerability-alerts
gh api --method PUT repos/Hunzee-VC/Nexus-Symbiote/automated-security-fixes

# 7. Delete head branches automatically once their pull request merges
gh api --method PATCH repos/Hunzee-VC/Nexus-Symbiote -F delete_branch_on_merge=true

# 8. Define the label the feature-request form applies
gh api --method POST repos/Hunzee-VC/Nexus-Symbiote/labels \
  -f name=enhancement -f color=a2eeef -f description='New feature or request'
```

After step 1, a commit can reach `main`, including the maintainer's own, only
after its `Verified CI` check has passed on a branch that is up to date with
`main`. In practice that means a pull request. Step 2
passes only once the newest CI run for the `main` head has succeeded. Configure
the `testpypi` and `pypi` environments' reviewers and main-only deployment
restriction as described in [releasing](releasing.md), and confirm them by adding
`--environment testpypi` and then `--environment pypi` to step 2, before
requesting publication.

### Delete preserved branches

A branch is preserved when every commit on it is reachable from `main` or from a
pull-request ref, which GitHub keeps after the branch is deleted, so deleting it
loses no commit. Keep the head and base branches of open pull requests: deleting
either closes the pull request. With push access, this lists the preserved
branches and leases each deletion to the commit that was checked:

```sh
repo=Hunzee-VC/Nexus-Symbiote
url="https://github.com/$repo.git"
git fetch --no-tags "$url" '+refs/heads/*:refs/audit/heads/*' '+refs/pull/*/head:refs/audit/pull/*'
keep=$(gh api --paginate "repos/$repo/pulls?state=open&per_page=100" --jq '.[] | .base.ref, .head.label')
set --
for ref in $(git for-each-ref --format='%(refname:strip=3)' refs/audit/heads/); do
  [ "$ref" = main ] && continue
  printf '%s\n' "$keep" | grep -qxF -e "$ref" -e "${repo%%/*}:$ref" && continue
  sha=$(git rev-parse "refs/audit/heads/$ref")
  [ -z "$(git rev-list -n 1 "$sha" --not refs/audit/heads/main --glob='refs/audit/pull/*')" ] || continue
  echo "delete $ref $sha"
  set -- "$@" "--force-with-lease=refs/heads/$ref:$sha" ":refs/heads/$ref"
done
```

Review the printed list, then delete those branches in one atomic push from the
same shell. A branch that moved after it was checked fails its lease, and the
whole push then deletes nothing:

```sh
[ "$#" -gt 0 ] && git push --atomic "$url" "$@"
git for-each-ref --format='delete %(refname)' refs/audit/ | git update-ref --stdin
```

Branches that hold commits found nowhere else are left in place. Tag the ones
worth keeping, for example
`git push "$url" "refs/audit/heads/<branch>:refs/tags/archive/<branch>"`, before
deleting them deliberately.
