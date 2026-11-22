"""A named checkout with an invalid policy must fail before a gate publishes output."""

import errno
import os
from types import SimpleNamespace

import pytest

from nexus_symbiote import policy
from nexus_symbiote.cli import main


@pytest.mark.parametrize("command", ["scan", "baseline", "risk", "validate"])
@pytest.mark.parametrize(
    ("contents", "diagnostic"),
    [
        ("risk: {fail_on_severity: High}\n", "invalid or unsupported settings"),
        ("unrecognized_setting: fixture-value\n", "invalid or unsupported settings"),
        ("", "configuration must be a YAML mapping"),
    ],
    ids=["misspelled-severity", "unknown-setting", "empty-file"],
)
def test_invalid_checkout_policy_requires_an_explicit_opt_out(
    runner, tmp_path, command, contents, diagnostic
):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Use sentence case.\n", encoding="utf-8")
    inventory = tmp_path / "input.json"
    initial = runner.invoke(main, ["scan", str(project), "-o", str(inventory)])
    assert initial.exit_code == 0, initial.output

    (project / ".nexus-symbiote.yaml").write_text(contents, encoding="utf-8")
    output = tmp_path / "result.json"
    if command in {"scan", "baseline"}:
        args = [command, str(project), "-o", str(output)]
    else:
        args = [command, str(inventory), "--project", str(project), "--json-output"]

    for extra in ([], ["--accept-project-policy"]):
        refused = runner.invoke(main, [*args, *extra])
        assert refused.exit_code == 1, refused.output
        assert diagnostic in refused.stderr
        assert "fixture-value" not in refused.output
        assert not refused.stdout
        assert not output.exists()

    ignored = runner.invoke(main, [*args, "--no-project-policy"])
    assert ignored.exit_code == 0, ignored.output


def test_unreadable_checkout_policy_fails_until_explicitly_ignored(runner, tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Read the notes.\n", encoding="utf-8")
    config = project / ".nexus-symbiote.yaml"
    config.write_text("risk: {fail_threshold: 50}\n", encoding="utf-8")
    output = tmp_path / "inventory.json"
    args = ["scan", str(project), "-o", str(output)]
    real_open = os.open

    def refuse_policy(path, *other, **kwargs):
        if path == config:
            raise PermissionError(errno.EACCES, "fixture policy is unreadable", str(config))
        return real_open(path, *other, **kwargs)

    policy_os = SimpleNamespace(**vars(os))
    policy_os.open = refuse_policy
    monkeypatch.setattr(policy, "os", policy_os)
    for extra in ([], ["--accept-project-policy"]):
        refused = runner.invoke(main, [*args, *extra])
        assert refused.exit_code == 1, refused.output
        assert "fixture policy is unreadable" in refused.stderr
        assert not output.exists()
    ignored = runner.invoke(main, [*args, "--no-project-policy"])
    assert ignored.exit_code == 0, ignored.output
