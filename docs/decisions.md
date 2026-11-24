# Decisions

Where each kind of decision about Nexus SymBiote is recorded, and how to record a new one. Read the
record before you change the code it governs. Many choices that look arbitrary in the code, such as
a refused input, a rating or a missing feature, are deliberate, and the record says why.

## Where decisions are recorded

| Kind of decision | Where it is recorded |
| --- | --- |
| Scope, non-goals and declined features | [Roadmap: decisions and non-goals](../ROADMAP.md#decisions-and-non-goals) |
| Design principles every feature must keep | [Security model: design principles](security-model.md#design-principles) |
| Threats the tool defends against, and those out of scope | [Threat model](threat-model.md), including [what is out of scope](threat-model.md#out-of-scope) |
| Who decides, and how changes are reviewed and released | [Governance](../GOVERNANCE.md#maintainer-and-decisions) and [contributing](../CONTRIBUTING.md#pull-requests) |
| Repository settings and the controls that are actually active | [Repository controls](repository-controls.md) |
| Behaviour that is deliberately incomplete, and what to do about it | [Known limitations](known-limitations.md) and [collection limits](collection-limits.md) |
| Breaking changes, and when inventories must be collected again | [Changelog](../CHANGELOG.md) entries marked **Breaking**, and [fingerprint migration](fingerprint-migration.md) |
| Audit follow-up decisions | Maintainer review comments on the corresponding pull requests and [Project records](README.md#project-records) |
| Dependency floors, upper bounds and ignored updates | The comment above `dependencies` in `pyproject.toml` for the floors; comments in `.github/dependabot.yml` for ignored updates and the tree-sitter cap |
| CI time limits and job budgets | Comments beside the test and coverage limits in `.github/workflows/ci.yml`; other limits in the pull request that set them |
| Why a pull request was merged, reworked or closed | Its pull-request description, disposition label (`superseded`, `duplicate`, `wontfix`), and review record |

## How to record a new decision

1. **State it in the pull request.** Say what the change decides, under "Roadmap and decisions" in the
   pull-request template.
2. **Record it where readers of that area look,** in the same pull request:
   - Scope, a non-goal or a declined feature goes in the roadmap's decisions table.
   - A principle goes in the security model.
   - A review or release rule goes in governance or contributing.
   - A deliberate gap goes in the known limitations.
3. **Give the context, the alternatives you did not take, and the consequence** for anything a later
   change could easily undo. A short template:

   > **Decision:** what is decided, in one sentence.
   > **Context:** the problem and the evidence, with links.
   > **Alternatives:** what else was considered, and why not.
   > **Consequences:** what this rules in and out, and what would make us revisit it.
   > **Recorded:** date, pull request.

4. **To reverse a decision,** change its record in the same pull request that changes the code, and
   say what changed.
