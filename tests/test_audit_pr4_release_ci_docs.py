"""Audit PR 4 regression tests for release gates, Action config, benchmarks, and docs."""

from __future__ import annotations

import importlib.util
import socket
import tomllib
from pathlib import Path

import pytest
import yaml

import nexus_symbiote
from tests.support import ROOT, load_script, scaling_ratio


def test_version_and_spdx_license_expression_are_aligned() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    citation = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    assert nexus_symbiote.__version__ == "0.2.0"
    assert pyproject["project"]["version"] == "0.2.0"
    assert str(citation["version"]) == "0.2.0"
    assert pyproject["project"]["license"] == (
        "MIT AND Apache-2.0 AND Community-Spec-1.0 AND CC-BY-3.0"
    )
    overrides = pyproject["tool"]["mypy"]["overrides"]
    assert any("sigstore_models.*" in entry.get("module", []) for entry in overrides)


def test_action_rejects_scanner_subset_when_validate_is_enabled(tmp_path: Path) -> None:
    run_action = load_script("run_action")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    base_env = {
        "GITHUB_WORKSPACE": str(workspace),
        "SYMBIOTE_SCAN_PATH": ".",
        "SYMBIOTE_OUTPUT_FILE": "agentbom.json",
        "SYMBIOTE_FORMAT": "json",
    }
    with pytest.raises(
        run_action.InputError,
        match="scanners subset requires validate and risk-check to be false",
    ):
        run_action.Config.from_env({**base_env, "SYMBIOTE_SCANNERS": "mcp,model"})

    # Allowed when both gates that need full coverage are explicitly disabled
    cfg_no_val = run_action.Config.from_env(
        {
            **base_env,
            "SYMBIOTE_SCANNERS": "mcp,model",
            "SYMBIOTE_VALIDATE": "false",
            "SYMBIOTE_RISK_CHECK": "false",
        }
    )
    assert cfg_no_val.scanners == ("mcp", "model")
    assert cfg_no_val.validate is False

    # Allowed when all built-in scanners are explicitly listed
    all_names = ",".join(sorted(run_action.SCANNERS))
    cfg_all = run_action.Config.from_env({**base_env, "SYMBIOTE_SCANNERS": all_names})
    assert set(cfg_all.scanners) == run_action.SCANNERS


def test_verified_ci_requires_the_full_suite_on_macos() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))
    assert {"pull_request", "push"} <= set(triggers)
    macos = workflow["jobs"]["macos"]
    assert macos["runs-on"].startswith("macos-")
    assert "macos" in workflow["jobs"]["verified"]["needs"]
    pytest_cmd = next(s["run"] for s in macos["steps"] if "pytest" in s.get("run", ""))
    # The whole suite: no file or directory narrows it (test_suite_infrastructure.py
    # rejects a marker or keyword selection).
    assert "--strict-skips" in pytest_cmd
    assert "tests/" not in pytest_cmd and ".py" not in pytest_cmd


def test_protect_the_gate_avoids_pull_request_target_head_checkout() -> None:
    guide = (ROOT / "docs" / "drift-gate.md").read_text(encoding="utf-8")
    protect = guide.split("\n## Protect the gate\n", 1)[1].split("\n## ", 1)[0]
    assert "on: pull_request\n" in protect
    assert "ref: ${{ github.event.pull_request.head.sha }}" not in protect


def test_protect_the_gate_example_is_keyed_and_skips_fork_pull_requests() -> None:
    guide = (ROOT / "docs" / "drift-gate.md").read_text(encoding="utf-8")
    protect = guide.split("\n## Protect the gate\n", 1)[1].split("\n## ", 1)[0]
    example = yaml.safe_load(protect.split("```yaml\n", 1)[1].split("```", 1)[0])
    job = example["jobs"]["inventory"]
    assert job["if"] == "github.event.pull_request.head.repo.full_name == github.repository"
    (gate,) = [step for step in job["steps"] if "Nexus-Symbiote@" in step.get("uses", "")]
    key = gate["env"]["NEXUS_SYMBIOTE_SOURCE_BINDING_KEY"]
    assert key.startswith("${{ secrets.")
    attestation = (ROOT / "docs" / "inventory-attestation.md").read_text(encoding="utf-8")
    stricter = attestation.split("For a stricter gate", 1)[1].split("```", 1)[0]
    assert "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY" in " ".join(stricter.split())


def test_benchmark_evidence_rejects_non_object_statement_and_predicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "benchmarks/inventory"))
    spec = importlib.util.spec_from_file_location(
        "inventory_evidence_pr4", ROOT / "benchmarks/inventory/evidence.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    archive = tmp_path / "archive"
    archive.mkdir()
    results = b'{"passed": true}\n'
    (archive / "results.json").write_bytes(results)

    (archive / "statement.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="statement does not bind"):
        module.check(archive)

    bad_pred = (
        '{"_type":"https://in-toto.io/Statement/v1",'
        f'"predicateType":"{module.PREDICATE_TYPE}",'
        f'"subject":[{{"name":"results.json","digest":{{"sha256":"{module.digest(results)}"}}}}],'
        '"predicate":"not-an-object"}'
    )
    (archive / "statement.json").write_text(bad_pred, encoding="utf-8")
    with pytest.raises(ValueError, match="statement predicate must be a JSON object"):
        module.check(archive, compare_installation=True)


def test_sub_millisecond_scaling_ratio_and_non_loopback_socket_guard() -> None:
    # Sub-millisecond work is amortized accurately rather than clipped at 1ms/1ms == 1.0
    ratio = scaling_ratio(lambda scale: sum(range(2_000 * scale)))
    assert 1.5 < ratio < 10.0

    # Non-loopback connect is blocked by conftest's autouse socket guard
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(OSError, match="blocked outbound non-loopback"):
            sock.connect(("93.184.216.34", 443))
        with pytest.raises(OSError, match="blocked outbound non-loopback"):
            sock.connect((b"93.184.216.34", 443))
    finally:
        sock.close()
