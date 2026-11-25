# Repository verification controls

`Verified CI` aggregates every required verification job on pull requests and `main`: Python 3.11–3.14 test matrix, full macOS 15 suite, dependency-floor suite (`requirements-floor.lock`), branch coverage floors, quality (`ruff`, `mypy`, workflow/hygiene/lock/PR-size checks), built-wheel distribution & security checks with the container image built from that wheel and run offline, security regression contracts, AIBOM-Bench precision gate, parser fuzz smoke, OSV dependency advisories, CodeQL security policy, end-to-end composite Action tests (including injection-annotation checks), and kernel network-denied offline invariant tests (`unshare --net`). Missing, failed, cancelled, or skipped prerequisites fail `Verified CI`.

## Branch protection profiles

- **Target profile ([`config/github-main-protection.json`](../config/github-main-protection.json)):** Requires `Verified CI` (bound to GitHub Actions app ID `15368`), up-to-date branches, independent & code-owner review (`.github/CODEOWNERS`), resolved conversations, administrator enforcement, and blocks force-pushes and branch deletion. Apply once a second authorized reviewer exists.
- **Interim single-maintainer profile ([`config/github-main-protection-interim.json`](../config/github-main-protection-interim.json)):** Active on `main`. Drops only `required_pull_request_reviews` (since GitHub does not count self-approval) while preserving `Verified CI` for administrators, resolved conversations, and force-push/deletion blocks.

Checked-in JSON files do not configure GitHub; an administrator applies them explicitly:

```sh
# Interim single-maintainer protection
gh api --method PUT repos/aisecnomad/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection-interim.json

# Target profile once a second reviewer exists
gh api --method PUT repos/aisecnomad/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection.json
```

> Classic branch protection is what the publication preflight queries; repository rulesets complement it rather than substituting for it.

## Publication preflight (`scripts/check_repository_controls.py`)

Runs read-only with repository `contents: read` and `actions: read` permissions (never an admin token in CI):

```sh
python scripts/check_repository_controls.py \
  --repo aisecnomad/Nexus-Symbiote --branch main --sha "$GITHUB_SHA" --publish pypi
```

It fails closed on missing, truncated, or malformed GitHub responses, redirects, or API errors, and enforces:

1. **Branch protection & exact-SHA CI:** Classic branch protection enabled, `Verified CI` required for everyone (GitHub Actions app `15368`), exact commit SHA matching live `main` HEAD, and newest trusted `ci.yml` run (`push` or `workflow_dispatch`) succeeded with `Verified CI`, `CodeQL policy`, and `Dependency advisories` green.
2. **Release-tag immutability (`--publish`):** Active tag ruleset blocking `update` and `deletion` on `refs/tags/v*` without creation-deadlock rules or caller bypass. Because GitHub reveals `bypass_actors` only to administrators, the workflow logs a notice and the maintainer runs `--verify-bypass-actors` locally before approving.
3. **Protected publishing environments (`--publish`):** `testpypi` / `pypi` environment requires a reviewer, disables admin bypass (`can_admins_bypass: false`), and restricts deployments to `main` via a single custom branch policy.
4. **24-hour soak & signed tag (`--publish pypi`):** Commit on `main` for ≥24 hours from its first `push` CI run (or `SOAK_OVERRIDE` with a ≥20-character urgent reason logged in the run), and signed annotated tag `v<version>` pointing at the exact commit with GitHub-verified signature (optionally restricted by `ALLOWED_RELEASE_TAG_SIGNERS`).

## Security acceptance evidence

- **CodeQL (`ci.yml` & `codeql.yml`):** Analyzes Python and GitHub Actions (`security-and-quality` queries) on every PR, push to `main`, and weekly schedule. `scripts/check_codeql_sarif.py` binds checkout revision to the SARIF output and fails closed on any security finding with `security-severity >= 7.0` (including suppressed findings) or incomplete invocations.
- **Dependency advisories (`scripts/check_dependency_advisories.py`):** Queries `https://api.osv.dev/v1/querybatch` for every pinned version across `requirements-ci.lock`, `requirements-action.lock`, and `requirements-floor.lock` (failing closed if OSV is unreachable). Temporary waivers require a reviewed PR editing `config/dependency-advisory-waivers.json` (max 90 days, exact version, ≥20-char reason; expired or stale waivers fail the gate). The daily *Dependency health* workflow repeats this audit.
- **Workflow integrity (`scripts/check_workflows.py`):** Enforces 40-char commit-SHA action pins with version floors, read-only top-level permissions, safe triggers (no `pull_request_target` or `workflow_run`), job timeouts, `persist-credentials: false`, zero `${{ }}` shell interpolation, exact PR-size/CodeQL step scripts, and intact gate commands across `ci.yml`, `release.yml`, and `codeql.yml`.
- **OpenSSF Scorecard (`scorecard.yml`):** Publishes weekly and on-push results to [scorecard.dev](https://scorecard.dev/viewer/?uri=github.com/aisecnomad/Nexus-Symbiote) and GitHub Code Scanning as an external signal.

## Operator prerequisites

Observed live through the GitHub API on **2026-11-24**. Always re-verify live settings before relying on any row; `--publish` preflights re-check the marked controls automatically.

| Control | Observed state (2026-11-24) | Action |
| --- | --- | --- |
| Branch protection on `main` | Active (interim profile): `Verified CI` required (`app_id: 15368`, `enforcement_level: everyone`), force-push and deletion disabled, no approving review required | Switch to target profile once a second reviewer exists |
| Repository ruleset `main` | Active on default branch (CodeQL, secret-scanning resolution, deletion, non-fast-forward) | Keep alongside classic branch protection |
| Private vulnerability reporting | Enabled | None |
| Secret scanning & push protection | Enabled (`secret_scanning`, `secret_scanning_push_protection`, `dependabot_security_updates`) | None |
| Auto-delete head branches | Enabled (`delete_branch_on_merge: true`) | None |
| `testpypi` & `pypi` environments | Protected: `@aisecnomad` required reviewer, `can_admins_bypass: false`, custom branch policy restricted to `main` (checked at publication) | Enable *Prevent self-review* once a second reviewer exists |
| Trusted publishers | Confirmed under owner `aisecnomad` on PyPI and TestPyPI for `Nexus-Symbiote`, `release.yml`, and `pypi` / `testpypi` environments | None |
| Release tag rulesets (`refs/tags/v*`) | Both active: `release tags` (immutability, ID `26831613`, `bypass_actors: []`, `current_user_can_bypass: never`) and `release tag creation` (ID `27907590`, admin-only creation) | Re-verify `--verify-bypass-actors` before approving publication |

### Apply the outstanding controls

Use two separate tag rulesets: [`config/github-release-tag-ruleset.json`](../config/github-release-tag-ruleset.json) blocks `update` and `deletion` with zero bypass actors, and [`config/github-release-tag-creation-ruleset.json`](../config/github-release-tag-creation-ruleset.json) restricts `creation` to repository administrators (`RepositoryRole` ID `5`). Before approving a TestPyPI or PyPI publication, run the administrator bypass check:

```sh
GH_TOKEN="$(gh auth token)" python scripts/check_repository_controls.py \
  --repo aisecnomad/Nexus-Symbiote --branch main --sha "$(git rev-parse origin/main)" \
  --publish testpypi --verify-bypass-actors
```

To update or recreate either ruleset as a repository administrator:

```sh
gh api repos/aisecnomad/Nexus-Symbiote/rulesets --jq '.[] | {id, name, target, enforcement}'
gh api --method PUT "repos/aisecnomad/Nexus-Symbiote/rulesets/$IMMUTABILITY_RULESET_ID" \
  --input config/github-release-tag-ruleset.json
gh api --method PUT "repos/aisecnomad/Nexus-Symbiote/rulesets/$CREATION_RULESET_ID" \
  --input config/github-release-tag-creation-ruleset.json
```

### Administrator actions still outstanding

These settings require administrator action outside Git (do not apply `config/github-main-protection.json` until a second reviewer exists):

```sh
# Require signed commits on main once contributors are ready
gh api --method POST repos/aisecnomad/Nexus-Symbiote/branches/main/protection/required_signatures
```

Once a second maintainer is onboarded, add them as a repository collaborator, in `.github/CODEOWNERS`, in [MAINTAINERS.md](../MAINTAINERS.md), and on PyPI/TestPyPI, then apply [`config/github-main-protection.json`](../config/github-main-protection.json).

### Clean up merged branches

Preserve any historical ref needed by provenance manifests as a tag, then prune merged remote branches using leased deletes:

```sh
git fetch --prune origin
git for-each-ref --merged origin/main --format='%(refname:strip=3) %(objectname)' \
  refs/remotes/origin | grep -v -E '^(main|HEAD) ' > merged-branches.txt
args=()
while read -r name sha; do args+=("--force-with-lease=refs/heads/$name:$sha" ":refs/heads/$name"); done \
  < merged-branches.txt
if [ "${#args[@]}" -gt 0 ]; then git push --atomic origin "${args[@]}"; fi
```
