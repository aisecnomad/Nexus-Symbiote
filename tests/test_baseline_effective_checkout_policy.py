"""Baseline promotion uses the policy and signer configuration that collected its inventory."""

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import policy
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.validators.risk import RiskScorer


@pytest.mark.parametrize(
    ("policy_flags", "expected"),
    [([], 1), (["--accept-project-policy"], 1), (["--no-project-policy"], 0)],
)
def test_baseline_honors_collected_signature_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_flags: list[str], expected: int
) -> None:
    root = tmp_path / "project"
    discovery = root / ".shadowscan"
    discovery.mkdir(parents=True)
    fixture = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
    shutil.copyfile(fixture, discovery / "report.json")
    (root / "CLAUDE.md").write_text("Use local project instructions.\n")
    (root / ".nexus-symbiote.yaml").write_text("validate: {require_discovery_signature: true}\n")
    reads = []
    load = policy.load_policy_file

    def count_reads(path: Path):
        reads.append(path)
        return load(path)

    monkeypatch.setattr(policy, "load_policy_file", count_reads)
    baseline = tmp_path / "baseline.json"
    result = CliRunner().invoke(
        main,
        ["baseline", str(root), "-o", str(baseline), "--allow-unsigned-discovery", *policy_flags],
    )
    assert result.exit_code == expected, result.output
    assert reads == ([] if "--no-project-policy" in policy_flags else [root])
    if expected:
        assert "unverified imported discovery cannot be promoted" in result.output
        assert not baseline.exists()
    else:
        assert baseline.is_file()


def test_init_preserves_operator_approved_suppression(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "CLAUDE.md").write_text("Synthetic direction marker: \u202e\n")
    runner = CliRunner()
    inventory = tmp_path / "inventory.json"
    collected = runner.invoke(main, ["scan", str(root), "--report-only", "-o", str(inventory)])
    assert collected.exit_code == 0, collected.output
    finding = next(
        f
        for f in RiskScorer().score(AIBOM.load(inventory)).findings
        if f.category == "bidi_override"
    )
    operator = tmp_path / "operator.json"
    operator.write_text(
        json.dumps(
            {
                "risk": {
                    "suppressions": [
                        {
                            "component_ref": finding.component_ref,
                            "category": finding.category,
                            "fingerprint": finding.fingerprint,
                            "owner": "fixture-reviewer",
                            "reason": "Synthetic direction marker under review",
                            "expires": "2099-01-01",
                        }
                    ]
                }
            }
        )
    )
    operator.chmod(0o600)
    gate = [
        "scan",
        str(root),
        "--check",
        "--operator-policy",
        str(operator),
        "--allow-unsigned-operator-policy",
    ]
    before = runner.invoke(main, gate)
    assert before.exit_code == 0, before.output
    initialized = runner.invoke(main, ["init", "--path", str(root)])
    assert initialized.exit_code == 0, initialized.output
    after = runner.invoke(main, gate)
    assert after.exit_code == 0, after.output
