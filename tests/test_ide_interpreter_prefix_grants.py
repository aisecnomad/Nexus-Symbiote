"""A Claude Code allow rule that names a shell or interpreter grants every command.

``Bash(sh:*)`` approves ``sh -c '<anything>'`` without a prompt, as ``Bash(*)`` does, so
the collector reports it as an unscoped tool allowance instead of a scoped command.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.core.models import IDEAgentComponent
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner, _broad_grants

INTERPRETER_PREFIXED = [
    "Bash(sh:*)",
    "Bash(bash -c:*)",
    "Bash(zsh:*)",
    "Bash(python3:*)",
    "Bash(python -c:*)",
    "Bash(node:*)",
    "Bash(perl:*)",
    "Bash(eval:*)",
    "Bash(exec:*)",
    "Bash(sudo:*)",
    "Bash(env:*)",
    "Bash(xargs:*)",
    "Bash(nohup:*)",
    "Bash(timeout:*)",
    "Bash(/bin/sh:*)",
    "Bash(/usr/bin/env python3:*)",
    "Bash(busybox:*)",
    "Bash(docker run:*)",
    "Bash(npx:*)",
    "Bash(uvx:*)",
]


@pytest.mark.parametrize("rule", INTERPRETER_PREFIXED)
def test_an_interpreter_prefixed_bash_rule_is_an_unscoped_shell_grant(rule: str) -> None:
    assert _broad_grants([rule]) == ["shell commands"]


@pytest.mark.parametrize(
    "rule",
    [
        "Bash(git diff *)",
        "Bash(npm run test:*)",
        "Bash(ls:*)",
        "Bash(make lint)",
        "Bash(shellcheck:*)",
    ],
)
def test_a_rule_scoped_to_an_ordinary_program_stays_scoped(rule: str) -> None:
    assert _broad_grants([rule]) == []


def test_the_scanner_reports_the_grant_as_a_permission_scope_finding(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps({"permissions": {"allow": ["Bash(sh:*)", "Read(src/**)"]}})
    )
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    agent = next(
        c
        for c in result.components
        if isinstance(c, IDEAgentComponent) and c.ide_type == "claude-code"
    )
    finding = next(r for r in agent.risks if r.category == "permission_scope")
    assert "shell commands" in finding.detail


@pytest.mark.parametrize(
    "rule",
    [
        r"Bash(C:\Windows\System32\cmd.exe /c *)",
        r"Bash(C:\Program Files\PowerShell\7\pwsh.exe -c *)",
        r"Bash(C:\Python312\python.exe -c *)",
        r'Bash("C:\Tools\my python.exe" -c *)',
        r'Bash("C:\Program Files\Python\python.exe":*)',
        "Bash('/opt/Team Tools/bin/python3' -c *)",
        r"Bash(.\tools\bash.exe *)",
        "Bash(python.exe -c *)",
        "Bash(node.cmd -e *)",
        "Bash(perl.exe -e *)",
        "Bash(FOO=1 bash -c *)",
        "Bash(A=1 B=2 bash *)",
        "Bash(NODE_ENV=prod node -e *)",
    ],
)
def test_a_windows_path_suffix_or_assignment_does_not_hide_an_interpreter(rule: str) -> None:
    assert _broad_grants([rule]) == ["shell commands"]


@pytest.mark.parametrize("rule", ["WebFetch(domain:**)", "WebFetch(domain:*.*)"])
def test_a_domain_made_only_of_wildcards_is_an_unscoped_fetch_grant(rule: str) -> None:
    assert _broad_grants([rule]) == ["web fetches"]


@pytest.mark.parametrize(
    "rule",
    [
        r"Bash(C:\tools\lint.exe *)",
        r'Bash("C:\Program Files\Tools\lint.exe" -c *)',
        r'Bash("C:\Tools\my python.exe" --version *)',
        r'Bash("C:\Tools\python helper.exe" --version *)',
        "Bash(FOO=1 npm test *)",
        "WebFetch(domain:example.com)",
    ],
)
def test_a_windows_or_assigned_ordinary_program_stays_scoped(rule: str) -> None:
    assert _broad_grants([rule]) == []
