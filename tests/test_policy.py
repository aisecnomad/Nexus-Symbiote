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

    def test_load_invalid_yaml_returns_none(self, tmp_path: Path) -> None:
        (tmp_path / ".nexus-symbiote.yaml").write_text("{{invalid yaml:::")
        with pytest.raises(PolicyError):
            load_policy(tmp_path)

    def test_load_empty_file_returns_none(self, tmp_path: Path) -> None:
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
        assert len(policy.scan.scanners) == 8
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
        "risk.fail_threshold=90",
        "risk.ignore_categories=x",
        "scan.failure_mode=report-only",
        "scan.scanners=mcp",
    ]
    stricter = Policy.model_validate(
        {"risk": {"fail_on_severity": "high", "fail_threshold": 10.0, "warn_threshold": 5.0}}
    )
    assert weakened_settings(stricter) == []
