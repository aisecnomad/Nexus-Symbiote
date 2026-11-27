"""Policy configuration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.policy import Policy, PolicyError, default_policy, load_policy


class TestDefaultPolicy:
    def test_default_values(self) -> None:
        policy = default_policy()
        assert policy.version == "1.0"
        assert "mcp" in policy.scan.scanners
        assert "model" in policy.scan.scanners
        assert policy.risk.fail_threshold == 50.0
        assert policy.risk.warn_threshold == 25.0
        assert policy.validation.require_completeness is True
        assert policy.output.default_format == "json"

    def test_default_exclude_paths(self) -> None:
        policy = default_policy()
        assert "node_modules" in policy.scan.exclude_paths
        assert ".git" in policy.scan.exclude_paths


class TestLoadPolicy:
    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        content = (
            'version: "1.0"\nscan:\n  scanners: ["mcp", "prompt"]\nrisk:\n  fail_threshold: 75.0\n'
        )
        (tmp_path / ".nexus-symbiote.yaml").write_text(content)
        policy = load_policy(tmp_path)
        assert policy is not None
        assert policy.scan.scanners == ["mcp", "prompt"]
        assert policy.risk.fail_threshold == 75.0

    def test_load_yml_extension(self, tmp_path: Path) -> None:
        content = 'version: "1.0"\nrisk:\n  fail_threshold: 30.0\n'
        (tmp_path / ".nexus-symbiote.yml").write_text(content)
        policy = load_policy(tmp_path)
        assert policy is not None
        assert policy.risk.fail_threshold == 30.0

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        assert load_policy(tmp_path) is None

    def test_load_invalid_yaml_raises_policy_error(self, tmp_path: Path) -> None:
        (tmp_path / ".nexus-symbiote.yaml").write_text("{{invalid yaml:::")
        with pytest.raises(PolicyError):
            load_policy(tmp_path)

    def test_load_empty_file_raises_policy_error(self, tmp_path: Path) -> None:
        (tmp_path / ".nexus-symbiote.yaml").write_text("")
        with pytest.raises(PolicyError):
            load_policy(tmp_path)

    def test_load_ignores_parent_dirs(self, tmp_path: Path) -> None:
        content = 'version: "1.0"\n'
        (tmp_path / ".nexus-symbiote.yaml").write_text(content)
        subdir = tmp_path / "subproject" / "src"
        subdir.mkdir(parents=True)
        assert load_policy(subdir) is None
        policy = load_policy(tmp_path)
        assert policy is not None
        assert policy.version == "1.0"

    def test_defaults_for_missing_sections(self, tmp_path: Path) -> None:
        (tmp_path / ".nexus-symbiote.yaml").write_text('version: "1.0"\n')
        policy = load_policy(tmp_path)
        assert policy is not None
        assert len(policy.scan.scanners) == 9
        assert policy.risk.fail_threshold == 50.0


class TestPolicyModel:
    def test_model_validation(self) -> None:
        policy = Policy(
            version="1.0",
        )
        assert policy.scan.scanners == [
            "mcp",
            "model",
            "prompt",
            "rag",
            "registry",
            "shadowscan",
            "a2a",
            "ide_agents",
            "agents",
        ]

    def test_custom_risk_config(self) -> None:
        from nexus_symbiote.policy import RiskPolicy

        risk = RiskPolicy(fail_threshold=80.0, ignore_categories=["signing_status"])
        assert risk.fail_threshold == 80.0
        assert "signing_status" in risk.ignore_categories


@pytest.mark.parametrize(
    "text",
    [
        "scan: {scanners: [unknown]}",
        "output: {default_format: html}",
        "risk: {fail_threshold: -1}",
        "risk: {fail_threshold: .nan}",
        "risk: {warn_threshold: 99}",
        'validate: {require_integrity: "false"}',
        "validate: {typo: false}",
        'version: "2.0"',
        "risk: {}\nrisk: {}",
        'scan: {exclude_paths: ["../escape"]}',
        "validation: {require_integrity: false}",
    ],
)
def test_invalid_settings_fail_closed(tmp_path, text):
    (tmp_path / ".nexus-symbiote.yaml").write_text(text)
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def test_weakened_settings_names_only_relaxations():
    from nexus_symbiote.policy import Policy, weakened_settings

    assert weakened_settings(Policy()) == []
    relaxed = Policy.model_validate(
        {
            "validate": {"require_integrity": False},
            "risk": {
                "fail_on_severity": "none",
                "fail_threshold": 90.0,
                "ignore_categories": ["x"],
            },
            "scan": {"failure_mode": "report-only", "scanners": ["mcp"]},
        }
    )
    assert weakened_settings(relaxed) == [
        "validate.require_integrity=false",
        "risk.fail_on_severity=none",
        "risk.fail_threshold=90.0",
        "risk.ignore_categories=x",
        "scan.failure_mode=report-only",
        "scan.scanners=mcp",
    ]
    stricter = Policy.model_validate(
        {"risk": {"fail_on_severity": "high", "fail_threshold": 10.0, "warn_threshold": 5.0}}
    )
    assert weakened_settings(stricter) == []
    barely = Policy.model_validate({"risk": {"fail_threshold": 50.000001}})
    assert weakened_settings(barely) == ["risk.fail_threshold=50.000001"]


def test_weakened_settings_include_every_setting_that_changes_reported_results():
    from nexus_symbiote.policy import Policy, weakened_settings

    relaxed = Policy.model_validate(
        {
            "risk": {"warn_threshold": 49.0},
            "scan": {"exclude_paths": ["node_modules", "tests/fixtures"]},
        }
    )
    assert weakened_settings(relaxed) == [
        "risk.warn_threshold=49.0",
        "scan.exclude_paths=tests/fixtures",
    ]
    # Dropping a default exclusion excludes nothing more, so it relaxes nothing.
    assert weakened_settings(Policy.model_validate({"scan": {"exclude_paths": []}})) == []


def test_a_stricter_fail_threshold_alone_is_accepted(tmp_path):
    (tmp_path / ".nexus-symbiote.yaml").write_text("risk: {fail_threshold: 20}\n")
    policy = load_policy(tmp_path)
    assert policy is not None
    assert (policy.risk.fail_threshold, policy.risk.warn_threshold) == (20.0, 20.0)
    (tmp_path / ".nexus-symbiote.yaml").write_text(
        "risk: {fail_threshold: 20, warn_threshold: 30}\n"
    )
    with pytest.raises(PolicyError, match=r"risk \(warn_threshold cannot exceed fail_threshold\)"):
        load_policy(tmp_path)


def test_a_project_root_that_cannot_be_listed_is_not_taken_to_have_no_policy(tmp_path, monkeypatch):
    import os

    (tmp_path / ".nexus-symbiote.yaml").write_text('risk: {fail_on_severity: "medium"}\n')

    def unlistable(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os, "scandir", unlistable)
    with pytest.raises(PolicyError, match="cannot be listed: Permission denied"):
        load_policy(tmp_path)


def test_a_policy_path_that_is_a_directory_is_refused_without_leaking_its_descriptor(
    tmp_path, monkeypatch
):
    import os

    (tmp_path / ".nexus-symbiote.yaml").mkdir()
    opened, closed = [], []
    real_open, real_close = os.open, os.close

    def recording_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def recording_close(fd):
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "close", recording_close)
    with pytest.raises(PolicyError, match="regular file no larger than 1 MiB"):
        load_policy(tmp_path)
    monkeypatch.undo()
    assert opened and set(opened) <= set(closed)


def test_both_policy_file_names_are_refused_instead_of_one_shadowing_the_other(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    (tmp_path / ".nexus-symbiote.yml").write_text('risk: {fail_on_severity: "high"}\n')
    runner = CliRunner()
    assert runner.invoke(main, ["init", "--path", str(tmp_path)]).exit_code == 1
    assert not (tmp_path / ".nexus-symbiote.yaml").exists()
    forced = runner.invoke(main, ["init", "--path", str(tmp_path), "--force"])
    assert forced.exit_code == 0, forced.output
    assert not (tmp_path / ".nexus-symbiote.yaml").exists()
    assert "suppressions" in (tmp_path / ".nexus-symbiote.yml").read_text()
    (tmp_path / ".nexus-symbiote.yaml").write_text('version: "1.0"\n')
    with pytest.raises(PolicyError, match="keep one policy file"):
        load_policy(tmp_path)
    assert runner.invoke(main, ["init", "--path", str(tmp_path), "--force"]).exit_code == 1


def test_the_reported_policy_is_the_applied_policy(tmp_path, monkeypatch):
    from nexus_symbiote import policy as module
    from nexus_symbiote.policy import load_policy_file

    (tmp_path / ".nexus-symbiote.yaml").write_text("risk: {fail_on_severity: none}\n")
    calls = []
    find = module.find_policy_path

    def counted(root):
        calls.append(root)
        return find(root)

    monkeypatch.setattr(module, "find_policy_path", counted)
    loaded = load_policy_file(tmp_path)
    assert loaded is not None and len(calls) == 1
    policy, path, digest = loaded
    assert path.name == ".nexus-symbiote.yaml" and digest.startswith("sha256:")
    assert policy.risk.fail_on_severity == "none"


def test_the_generated_template_loads_to_the_built_in_policy(tmp_path):
    from nexus_symbiote.policy import DEFAULT_POLICY_YAML, Policy, weakened_settings

    (tmp_path / ".nexus-symbiote.yaml").write_text(DEFAULT_POLICY_YAML)
    policy = load_policy(tmp_path)
    assert policy == Policy() and weakened_settings(policy) == []


def _scan_and_validate(tmp_path: Path) -> list[str]:
    """The outputs of scan and validate --project on tmp_path.

    An unsafe policy file is an error only when ``--accept-project-policy`` is passed.
    """
    from click.testing import CliRunner

    from nexus_symbiote.cli import main
    from nexus_symbiote.core.aibom import AIBOM

    project = tmp_path
    inventory = tmp_path.parent / "inventory.json"
    AIBOM().save(inventory)
    runner = CliRunner()
    outputs = []
    for args in (
        [
            "scan",
            str(project),
            "--accept-project-policy",
            "-o",
            str(tmp_path.parent / "scanned.json"),
        ],
        [
            "validate",
            str(inventory),
            "--project",
            str(project),
            "--accept-project-policy",
        ],
    ):
        result = runner.invoke(main, args)
        assert result.exit_code == 1, result.output
        outputs.append(result.output)
    assert not (tmp_path.parent / "scanned.json").exists()
    return outputs


def test_a_symlinked_policy_file_is_refused_by_scan_and_validate(tmp_path):
    elsewhere = tmp_path.parent / "elsewhere.yaml"
    elsewhere.write_text("risk: {fail_on_severity: none}\n")
    (tmp_path / ".nexus-symbiote.yaml").symlink_to(elsewhere)
    with pytest.raises(PolicyError, match="policy must not be a symlink"):
        load_policy(tmp_path)
    for output in _scan_and_validate(tmp_path):
        assert "policy must not be a symlink" in output


def test_a_policy_file_over_one_mebibyte_is_refused_by_scan_and_validate(tmp_path):
    policy = tmp_path / ".nexus-symbiote.yaml"
    policy.write_bytes(b"#" * (1024 * 1024 + 1))
    with pytest.raises(PolicyError, match="regular file no larger than 1 MiB"):
        load_policy(tmp_path)
    for output in _scan_and_validate(tmp_path):
        assert "no larger than 1 MiB" in output
    # One byte less is read: a file of comments is then refused for what it says.
    policy.write_bytes(b"#" * (1024 * 1024))
    with pytest.raises(PolicyError, match="YAML mapping"):
        load_policy(tmp_path)
