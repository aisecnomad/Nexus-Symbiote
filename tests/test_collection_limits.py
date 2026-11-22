"""Collection limits are operator settings: named, documented, raisable and never silent."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.limits import CollectionLimits, LimitError, parse_setting, resolve
from nexus_symbiote.scanners import base

DOCS = Path(__file__).resolve().parents[1] / "docs" / "collection-limits.md"


def _project(root: Path, files: int) -> Path:
    root.mkdir()
    (root / "AGENTS.md").write_text("Keep receipts.")
    for index in range(files):
        (root / f"note{index:03d}.txt").write_text("plain text")
    return root


def _scan(runner: CliRunner, project: Path, output: Path, *prefix: str, **env: str):
    return runner.invoke(
        main,
        [*prefix, "scan", str(project), "--no-project-policy", "-o", str(output)],
        env=env or None,
    )


def _failures(output: Path) -> list[str]:
    failures: list[str] = json.loads(output.read_text())["metadata"]["completeness"][
        "scan_failures"
    ]
    return failures


@pytest.mark.parametrize(
    "text,expected",
    [
        ("entries=200000", ("entries", 200_000)),
        (" depth = 64 ", ("depth", 64)),
        ("file-bytes=8MiB", ("file-bytes", 8 * limits.MIB)),
        ("total-bytes=512 kib", ("total-bytes", 512 * limits.KIB)),
        ("model-bytes=128GiB", ("model-bytes", 128 * limits.GIB)),
        ("Model_Total_Bytes=1024GiB", ("model-total-bytes", 1024 * limits.GIB)),
        ("syntax-bytes=300000", ("syntax-bytes", 300_000)),
    ],
)
def test_settings_accept_whole_numbers_and_binary_suffixes(text, expected):
    assert parse_setting(text) == expected


@pytest.mark.parametrize(
    "text,message",
    [
        ("entries", "NAME=VALUE"),
        ("entires=5", "unknown limit name; did you mean entries?"),
        ("bogus=5", "unknown limit name. Known limits: file-bytes"),
        ("entries=5MiB", "entries needs a whole number"),
        ("entries=-5", "entries needs a whole number"),
        ("entries=1.5", "entries needs a whole number"),
        ("file-bytes=4MB", "file-bytes needs a whole number of bytes"),
        ("entries=0", "between 1 and"),
        ("depth=257", "depth must be between 1 and 256"),
        ("model-bytes=1025GiB", "model-bytes must be between 1 and 1024 GiB"),
    ],
)
def test_malformed_settings_are_errors(text, message):
    with pytest.raises(LimitError, match=re.escape(message)):
        parse_setting(text)


def test_errors_never_repeat_the_supplied_value():
    for text in ("entries=token-1234567890", "secret-token-1234567890=5", "=token-1234567890"):
        with pytest.raises(LimitError) as raised:
            parse_setting(text)
        assert "1234567890" not in str(raised.value)


def test_option_wins_over_environment_for_its_names_only():
    environ = {limits.ENV_VAR: "entries=10, depth=12,"}
    resolved = resolve(["entries=30"], environ)
    assert (resolved.entries, resolved.depth) == (30, 12)
    assert resolve([], {}) == limits.DEFAULTS
    with pytest.raises(LimitError, match="entries is set more than once in --limit"):
        resolve(["entries=1", "entries=2"], {})
    with pytest.raises(LimitError, match=f"depth is set more than once in {limits.ENV_VAR}"):
        resolve([], {limits.ENV_VAR: "depth=1,depth=2"})


def test_applied_limits_are_restored_after_use():
    custom = replace(limits.DEFAULTS, entries=7)
    with limits.applied(custom):
        assert limits.current() is custom
        assert limits.bound("entries") == limits.Bound(7, "entries")
    assert limits.current() == limits.DEFAULTS


def test_every_limit_is_documented_with_its_default_and_maximum():
    rows = {
        name: (default, maximum)
        for name, default, maximum in re.findall(
            r"^\| `([a-z-]+)` \| ([^|]+) \| ([^|]+) \|", DOCS.read_text(encoding="utf-8"), re.M
        )
    }
    assert set(rows) == set(limits.SPECS)
    for name, spec in limits.SPECS.items():
        assert rows[name] == (
            limits.format_value(name, limits.DEFAULTS.value(name)),
            limits.format_value(name, spec.maximum),
        )


def test_a_single_byte_is_not_plural():
    assert limits.format_value("total-bytes", 1) == "1 byte"
    assert limits.format_value("total-bytes", 2) == "2 bytes"
    assert limits.Bound(1, "total-bytes").exceeded().startswith("total-bytes limit of 1 byte ")


def test_reaching_a_limit_fails_the_scan_and_names_how_to_raise_it(tmp_path):
    project = _project(tmp_path / "project", files=12)
    runner = CliRunner()
    output = tmp_path / "limited.json"
    result = _scan(runner, project, output, "--limit", "entries=5")
    assert result.exit_code == 1
    failures = _failures(output)
    assert ".: entries limit of 5 exceeded; raise it with --limit entries=N" in failures
    assert not any(str(tmp_path) in failure for failure in failures)
    assert limits.current() == limits.DEFAULTS
    raised = tmp_path / "raised.json"
    assert _scan(runner, project, raised, "--limit", "entries=500").exit_code == 0
    assert not _failures(raised)


def test_environment_sets_limits_and_the_option_overrides_it(tmp_path):
    project = _project(tmp_path / "project", files=12)
    runner = CliRunner()
    output = tmp_path / "env.json"
    env = {limits.ENV_VAR: "entries=5"}
    assert _scan(runner, project, output, **env).exit_code == 1
    assert any("entries limit of 5 exceeded" in failure for failure in _failures(output))
    assert _scan(runner, project, output, "--limit", "entries=500", **env).exit_code == 0


@pytest.mark.parametrize(
    "prefix,env,message",
    [
        (["--limit", "entires=5"], {}, "did you mean entries?"),
        (["--limit", "entries=0"], {}, "entries must be between 1 and"),
        ([], {limits.ENV_VAR: "depth=deep"}, "depth needs a whole number"),
    ],
)
def test_invalid_limits_are_usage_errors(tmp_path, prefix, env, message):
    project = _project(tmp_path / "project", files=1)
    result = _scan(CliRunner(), project, tmp_path / "out.json", *prefix, **env)
    assert result.exit_code == 2
    assert message in result.output
    assert not (tmp_path / "out.json").exists()


def test_a_misplaced_limit_option_explains_where_it_goes(tmp_path):
    project = _project(tmp_path / "project", files=1)
    result = CliRunner().invoke(main, ["scan", str(project), "--limit", "entries=5"])
    assert result.exit_code == 2
    assert "Limits go before the command" in result.output


def test_nothing_in_the_checkout_can_set_a_limit(tmp_path):
    project = _project(tmp_path / "project", files=12)
    (project / ".env").write_text(f"{limits.ENV_VAR}=entries=5\n")
    runner = CliRunner()
    output = tmp_path / "out.json"
    assert _scan(runner, project, output).exit_code == 0
    assert not _failures(output)
    (project / ".nexus-symbiote.yaml").write_text("limits:\n  entries: 5000000\n")
    result = runner.invoke(main, ["--limit", "entries=5", "scan", str(project), "-o", str(output)])
    assert result.exit_code == 1
    assert "entries limit of 5 exceeded" in result.output
    result = runner.invoke(
        main,
        [
            "--limit",
            "entries=500",
            "scan",
            str(project),
            "--accept-project-policy",
            "-o",
            str(output),
        ],
    )
    assert result.exit_code == 1
    assert "invalid policy" in result.output


def test_limits_apply_to_project_validation(tmp_path):
    project = _project(tmp_path / "project", files=12)
    runner = CliRunner()
    output = tmp_path / "out.json"
    assert _scan(runner, project, output).exit_code == 0
    command = ["validate", str(output), "--project", str(project), "--no-project-policy"]
    assert runner.invoke(main, command).exit_code == 0
    limited = runner.invoke(main, ["--limit", "entries=5", *command])
    assert limited.exit_code == 1
    assert "entries limit of 5 exceeded" in limited.output


def test_defaults_are_the_documented_values():
    assert CollectionLimits() == limits.DEFAULTS
    assert limits.DEFAULTS.file_bytes == 4 * limits.MIB
    assert limits.DEFAULTS.total_bytes == 32 * limits.MIB
    # Upstream's source budget: the text read, not a file count.
    assert limits.DEFAULTS.source_scan_bytes == 64 * limits.MIB == base.MAX_SOURCE_BYTES
    assert not hasattr(limits.DEFAULTS, "source_files")
    assert limits.DEFAULTS.syntax_bytes == 256 * limits.KIB
    assert limits.DEFAULTS.ts_nodes == 20_000
