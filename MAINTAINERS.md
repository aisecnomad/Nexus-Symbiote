# Maintainers

## Current maintainers

| Name | GitHub | Role | Since |
| --- | --- | --- | --- |
| Emmanuel Dahunsi | [@aisecnomad](https://github.com/aisecnomad) | Lead maintainer | 2026 |

## Responsibilities

The lead maintainer is responsible for:

- Reviewing and merging pull requests
- Triaging issues and security reports
- Managing releases and PyPI publication
- Maintaining CI, branch protection and repository controls
- Regenerating dependency locks and reviewing dependency updates
- Setting project direction and roadmap priorities

These are ownership responsibilities, not a claim that external CI, branch protection or publication settings are already active. See [repository controls](docs/repository-controls.md#operator-prerequisites) for verification status and the administrator runbook, and [issue #74](https://github.com/aisecnomad/Nexus-Symbiote/issues/74) for the remediation history.

## Access and continuity

Who can act for the project today. Every row has one holder; [GOVERNANCE.md](GOVERNANCE.md#continuity) explains what that means and which second holders are still to be added.

| Privilege | Holder | Backup |
| --- | --- | --- |
| Merge to `main` and administer the repository | @aisecnomad | None yet |
| Approve the `testpypi` and `pypi` environments (publication) | @aisecnomad, the required reviewer of both | None yet |
| Own the `nexus-symbiote` project on PyPI and TestPyPI (yank, manage trusted publishers) | The maintainer's package-index account; not recorded here | None yet |
| Own the aisecnomad GitHub account, which owns the repository | @aisecnomad | Not possible for a personal account; see the repository administrator row |
| Receive private vulnerability reports | Repository administrators, through GitHub's private vulnerability reporting | None yet |
| Sign release tags | @aisecnomad | None yet |

Add the second holder of each privilege here, with the date, when one exists.

## Becoming a maintainer

Nexus SymBiote is in alpha with a single maintainer. Contributors who demonstrate sustained, high-quality participation may be invited to take on maintainer responsibilities.

Qualities valued in potential maintainers:

- Consistent, reviewed contributions over time
- Understanding of the security model and trust boundaries
- Attention to supply-chain security practices
- Responsiveness to issues and community questions
- Willingness to review others' pull requests thoroughly

Start by reading [CONTRIBUTING.md](CONTRIBUTING.md) and engaging with open issues.
