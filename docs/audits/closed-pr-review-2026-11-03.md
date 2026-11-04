# Pull-request, branch and issue review — 2026-11-03

Baseline: `main` at `c31d1ef` (after #115). Continues the [2026-11-02 review](closed-pr-review-2026-11-02.md), which covered #2–#73.

## Scope and method

- **Pull requests #74–#116.** For each merged pull request, the lines its merge added were compared with current `main`, excluding the changelog and lock files. Any pull request missing more than a fifth of its added lines was reviewed by hand. Pull requests closed without merging were checked for a superseding change.
- **Branches.** Every branch and every `refs/pull/*/head` was mirrored. A branch is *preserved* when each of its commits is reachable from `main` or from a pull-request ref, which GitHub keeps after a branch is deleted.
- **Unmerged work.** The unique commits on the remaining branches were read, and any finding they record was reproduced on `main`.
- **Merge state.** Some pull requests were squash-merged through GitHub's web flow with edited subjects that omit the pull-request number, such as `d852727`, whose tree equals the head of #102. Such a commit is attributed to its pull request by its GitHub committer and by tree equality with the pull-request head, not by its subject.

These are evidence of what reached `main`, not re-certifications of historical heads.

## Findings

| Finding | Evidence | Disposition |
| --- | --- | --- |
| A merged change was silently reverted | #99 bumped `actions/checkout` to v7.0.1 (`3d3c42e`). The squash merge of #109 rewrote every workflow from a branch that predated #99, restoring v6. #100 and #101 were lost the same way and restored in #113 | #116 re-proposes the same reviewed SHA and passes `Verified CI`; merge it |
| Model formats were invisible | `.ckpt`, `.pdparams`, `.h5`, `.hdf5`, `.keras` and `saved_model.pb` were never discovered, so a malicious checkpoint produced no finding while the model collector reported complete coverage. Recorded in the unmerged `fix/audit-remediation` branch (`8233c13`) and reproduced on `main` | Fixed: inventoried, with the pickle-based formats rated code-executing |
| Pathname swaps went undetected on overlayfs | With a file in a lower layer, a rename-over leaves the open descriptor's link count and timestamps unchanged. A model swapped mid-scan was reported `safe` with a weight hash. Four submitted variants (#113, bundle `35d25e1`, patches `2d37d65` and `6cdcb93`) each left a gap | Fixed: every confined read also requires the pathname to resolve to the open descriptor when it ends |
| Squash merges hide reverts | The same failure mode produced #96 ("restore the reviewed fixes that the squash merges of #77–#85 left out") and the #99 loss | Process: rebase or merge `main` into a long-lived branch before squash-merging it, and review the full diff against current `main` |

The earlier `fix/audit-remediation` branch also recorded a false rug-pull alert for tools without annotations. It no longer reproduces: a scan followed by `validate --project` verifies such a tool. Its audit report's other findings (NS-01 to NS-19) are resolved on `main`; NS-08, NS-09 and NS-13 were re-tested for this review.

## Pull requests #74–#116

| Pull request | Disposition |
| --- | --- |
| #74 | Issue, not a pull request; see [issues](#issues) |
| #75, #77, #79–#84, #86, #88, #89, #93, #94, #96–#98, #100–#103, #105–#107, #109–#111, #113, #115 | Merged; their changes are present on `main` or deliberately reworked by a later pull request |
| #76 | Merged. Its README and templates were later rewritten, its `.github/CONTRIBUTING.md` stub was removed in #115, and `publish-testpypi.yml` outlived the #85 release consolidation until #96 removed it |
| #78, #85 | Merged. The release workflow was consolidated afterwards; attestation verification and the TestPyPI rehearsal remain, covered by `tests/test_release_provenance.py` and `tests/test_testpypi_security.py` |
| #87, #90 | Merged. Their version ranges were superseded by #98's higher floors |
| #92, #95 | Merged. The workflow they updated, `publish-testpypi.yml`, was later removed |
| #99 | Merged, then silently reverted by #109; see [findings](#findings) |
| #108, #112 | Merged. Their README sections were replaced by #111 and #115 |
| #91 | Closed. tree-sitter 0.26 removed the parse timeout that bounds untrusted TypeScript; Dependabot ignores that range |
| #104 | Closed. Superseded by #110 |
| #114 | Closed. Superseded by #115, the same commits rebased after #113 merged |
| #116 | Merged after this review as `14f2ecf`. Restores #99 |

## Branches

114 branches other than `main` existed at review time.

- **92 are preserved** and safe to delete. Delete them in one atomic push that leases each deletion to its verified SHA, so a branch that moved after the review is kept: `git push --atomic origin --force-with-lease=refs/heads/<branch>:<sha> :refs/heads/<branch> …`. The runbook's [delete preserved branches](../repository-controls.md#delete-preserved-branches) procedure selects them and runs that push.
- **22 hold commits found nowhere else**, under 13 roots:
  - The `claude/*` experimental foundation line (`claude/symbiote-foundation`, `claude/reconcile-main`, `claude/integration-staging` and the `claude/wp-*` work packages), including two commits added to `claude/wp-05-snapshot-2` and `claude/wp-10-live-collectors` after their pull requests merged. The [roadmap](../../ROADMAP.md) records that this line is not a supported interface. Keep or tag it before deleting.
  - `codex/runtime-lineage`, `codex/security-conformance` and `codex/validate-wire-exports` each hold only the merge commit of a pull request whose content reached `main` through #57 or #48.
  - `codex/collect-python-sdk-tool-declarations` holds only an empty commit that re-triggered CI.
  - `feat/world-class-standards` is an unmerged documentation restructure; its offline mode shipped in #83.
  - `fix/audit-remediation` and `review-remediation` are early remediation work that `main` superseded, except the model-format gap above.

## Issues

- **#1**, the multi-session build-coordination board from 2026-11-01, was closed as obsolete: the sessions, the branches it names and the separate foundation package were superseded by `main`.
- **#74** was closed with each item's status recorded. Hosted CI and CodeQL were restored by #97 and #98. Branch protection, private vulnerability reporting, secret scanning and the inert ruleset need repository administration; the [runbook](../repository-controls.md#operator-prerequisites) applies them and the publication preflight refuses to publish until protection is enforced. PyPI trusted publishing needs the package-index account. Both remaining actions are tracked in the [roadmap](../../ROADMAP.md).
