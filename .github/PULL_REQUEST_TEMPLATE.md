## Summary

<!-- Explain the concrete problem, resulting behavior, and validation. -->

## Related issues

<!-- For example: Closes #123. Write "None" if there is no issue. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Security fix (see SECURITY.md for reporting guidelines)
- [ ] Refactoring (no functional changes)

## Checklist

`make check` runs the offline subset of the required CI checks. See [CONTRIBUTING.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CONTRIBUTING.md).

- [ ] Tests cover the new or changed behavior
- [ ] `ruff check src tests scripts` passes
- [ ] `ruff format --check src tests scripts` passes
- [ ] `mypy src/nexus_symbiote scripts` passes
- [ ] Workflow and repository hygiene checks pass (`make workflow-check hygiene`)
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated under Unreleased
- [ ] Behavior- or security-changing: open for at least 24 hours, and the full diff re-read after `Verified CI` passed (see CONTRIBUTING.md)

### Security-sensitive changes

- [ ] Trust boundary and abuse case stated
- [ ] Regression test fails on the vulnerable behavior
- [ ] Security regression corpus reviewed (`scripts/benchmark_security.py`)
- [ ] No new network access, executable discovery, or credential collection without design and tests

## Limitations

<!-- Describe what this change does not cover or what it assumes. -->
