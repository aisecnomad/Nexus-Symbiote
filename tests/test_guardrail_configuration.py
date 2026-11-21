"""Guardrail and evaluation configuration is recognised by name and bound by digest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, TrustTier
from nexus_symbiote.core.hashing import hash_canonical
from nexus_symbiote.core.models import GuardrailComponent
from nexus_symbiote.generators.validation import (
    validate_cyclonedx,
    validate_sarif,
    validate_spdx,
)
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.rag import (
    GUARDRAIL_CONFIG_FILES,
    GUARDRAIL_DIRECTORY_PROFILE,
    RAGScanner,
)

POLICY = b"rails:\n  input:\n    flows: [self check input]\n"


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write(root: Path, relative: str, data: bytes = POLICY) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _guardrails(result: ScanResult) -> list[GuardrailComponent]:
    return [c for c in result.components if isinstance(c, GuardrailComponent)]


def _scan(root: Path) -> list[GuardrailComponent]:
    result = RAGScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    return _guardrails(result)


def _inventory(runner, project: Path, output: Path, *options: str) -> dict:
    run = runner.invoke(main, ["scan", str(project), "-o", str(output), *options])
    assert run.exit_code == 0, run.output
    return json.loads(output.read_text())


@pytest.mark.parametrize(("name", "kind"), sorted(GUARDRAIL_CONFIG_FILES.items()))
def test_each_recognised_name_is_recorded_by_digest(tmp_path, name, kind):
    _write(tmp_path, name)

    (component,) = _scan(tmp_path)

    assert kind == ("evaluation" if name.startswith("promptfooconfig") else "policy")
    assert component.component_type is ComponentType.GUARDRAIL_POLICY
    assert component.guardrail_type == kind
    assert component.bom_ref == f"guardrail:{name}"
    assert component.name == component.source_path == name
    assert component.config_hash == _sha256(POLICY)
    assert component.properties == {
        "collection_mode": "static-file-digest",
        "size_bytes": len(POLICY),
    }
    assert component.trust_tier is TrustTier.INTERNAL_UNVERIFIED
    assert component.assurance_level is AssuranceLevel.DECLARED
    assert (component.model_ref, component.policy_version, component.version) == (None,) * 3
    assert component.risks == []


def test_the_recognised_names_are_the_documented_set():
    assert set(GUARDRAIL_CONFIG_FILES) == {
        f"{stem}.{suffix}"
        for stem in ("promptfooconfig", "guardrails")
        for suffix in ("yaml", "yml", "json")
    }


@pytest.mark.parametrize("name", ["config.yml", "config.yaml"])
def test_a_nemo_directory_binds_its_configuration_and_colang_files(tmp_path, name):
    _write(tmp_path, f"rails/{name}", b"models: []\n")
    _write(tmp_path, "rails/topics.co", b"define flow topics\n")
    _write(tmp_path, "rails/greeting.co", b"define flow greeting\n")
    _write(tmp_path, "rails/nested/ignored.co", b"define flow nested\n")

    (component,) = _scan(tmp_path)

    rail_files = {
        "greeting.co": _sha256(b"define flow greeting\n"),
        "topics.co": _sha256(b"define flow topics\n"),
    }
    assert component.bom_ref == f"guardrail:rails/{name}"
    assert component.guardrail_type == "policy"
    assert list(component.properties["rail_files"]) == sorted(rail_files)
    assert component.properties["rail_files"] == rail_files
    assert component.properties["config_file_hash"] == _sha256(b"models: []\n")
    assert component.properties["config_hash_profile"] == GUARDRAIL_DIRECTORY_PROFILE
    assert component.properties["size_bytes"] == len(b"models: []\n")
    assert component.config_hash == hash_canonical({name: _sha256(b"models: []\n"), **rail_files})


def test_a_changed_colang_file_changes_the_directory_digest(tmp_path):
    _write(tmp_path, "rails/config.yml", b"models: []\n")
    rail = _write(tmp_path, "rails/main.co", b"define flow a\n")
    (before,) = _scan(tmp_path)

    rail.write_bytes(b"define flow b\n")
    (after,) = _scan(tmp_path)

    assert before.config_hash != after.config_hash
    assert before.properties["config_file_hash"] == after.properties["config_file_hash"]


def test_a_config_file_without_colang_siblings_is_not_collected(tmp_path):
    _write(tmp_path, "config.yml", b"models: []\n")
    _write(tmp_path, "app/config.yaml", b"debug: true\n")
    _write(tmp_path, "app/rails/main.co", b"define flow a\n")
    _write(tmp_path, "Config.yml", b"other: true\n")

    result = RAGScanner().scan(tmp_path)

    assert result.components == []
    assert result.scan_failures == []
    assert "config.yml" not in result.surfaces_scanned


@pytest.mark.parametrize(
    "content",
    [b"key: [unclosed\n\t- {", b"\x00\xff\xfe\x80binary", b"", b'{"a": 1, "a": 2}'],
    ids=["invalid-yaml", "binary", "empty", "duplicate-keys"],
)
@pytest.mark.parametrize("name", ["guardrails.yaml", "promptfooconfig.json"])
def test_content_is_never_parsed(tmp_path, name, content):
    _write(tmp_path, name, content)

    (component,) = _scan(tmp_path)

    assert component.config_hash == _sha256(content)
    assert component.properties["size_bytes"] == len(content)


def test_content_does_not_reach_the_record(tmp_path):
    secret = "sk-" + "a1B2c3D4" * 5
    _write(tmp_path, "guardrails.yaml", f"model: gpt-4\nversion: 9\nkey: {secret}\n".encode())

    (component,) = _scan(tmp_path)

    exported = component.model_dump_json()
    assert secret not in exported
    assert "gpt-4" not in exported


def test_nested_files_are_recorded_in_path_order_and_excluded_directories_skipped(tmp_path):
    for relative in (
        "services/b/guardrails.yml",
        "evals/promptfooconfig.yaml",
        "configs/guardrails.yaml",
        "node_modules/pkg/promptfooconfig.yaml",
        ".venv/lib/guardrails.json",
        ".git/guardrails.yaml",
        "skipped/guardrails.json",
    ):
        _write(tmp_path, relative)
    scanner = RAGScanner()
    scanner.configure(exclude_paths=["skipped"])

    result = scanner.scan(tmp_path)

    assert [c.source_path for c in _guardrails(result)] == [
        "configs/guardrails.yaml",
        "evals/promptfooconfig.yaml",
        "services/b/guardrails.yml",
    ]
    assert result.scan_failures == []
    assert set(result.surfaces_scanned) >= {"configs/guardrails.yaml", "services/b/guardrails.yml"}


def test_a_file_over_the_size_limit_is_a_named_failure(tmp_path):
    _write(tmp_path, "guardrails.yaml", b"a" * (64 * limits.KIB + 1))

    with limits.applied(limits.resolve(["file-bytes=64KiB"], {})):
        result = RAGScanner().scan(tmp_path)

    assert _guardrails(result) == []
    (failure,) = result.scan_failures
    assert failure.startswith("guardrails.yaml: ")
    assert "file-bytes" in failure


def test_an_oversized_colang_file_withholds_the_directory_record(tmp_path):
    _write(tmp_path, "rails/config.yml", b"models: []\n")
    _write(tmp_path, "rails/main.co", b"a" * (64 * limits.KIB + 1))

    with limits.applied(limits.resolve(["file-bytes=64KiB"], {})):
        result = RAGScanner().scan(tmp_path)

    assert _guardrails(result) == []
    (failure,) = result.scan_failures
    assert failure.startswith("rails/main.co: ")
    assert "rails/config.yml" not in result.surfaces_scanned


def test_a_symlink_out_of_the_root_is_a_failure_and_reads_nothing(tmp_path):
    outside = _write(tmp_path, "outside/policy.yaml", b"outside: true\n")
    project = tmp_path / "project"
    project.mkdir()
    (project / "guardrails.yaml").symlink_to(outside)

    result = RAGScanner().scan(project)

    assert _guardrails(result) == []
    (failure,) = result.scan_failures
    assert failure.startswith("guardrails.yaml: ")


def test_a_symlink_inside_the_root_is_read_and_names_its_target(tmp_path):
    _write(tmp_path, "configs/policy.yaml")
    (tmp_path / "guardrails.yaml").symlink_to("configs/policy.yaml")

    (component,) = _scan(tmp_path)

    assert component.config_hash == _sha256(POLICY)
    assert component.properties["symlink_target"] == "configs/policy.yaml"


def test_an_unreadable_entry_is_a_failure(tmp_path):
    (tmp_path / "guardrails.yaml").mkdir()
    (tmp_path / "guardrails.yaml" / "promptfooconfig.yaml").mkdir()

    result = RAGScanner().scan(tmp_path)

    assert _guardrails(result) == []
    assert result.scan_failures == []

    (tmp_path / "guardrails.json").symlink_to("missing.json")
    result = RAGScanner().scan(tmp_path)

    assert _guardrails(result) == []
    assert any(failure.startswith("guardrails.json: ") for failure in result.scan_failures)


@pytest.mark.parametrize(
    ("relative", "canonical"),
    [
        ("Guardrails.YAML", "guardrails.yaml"),
        ("evals/PromptfooConfig.yaml", "evals/promptfooconfig.yaml"),
    ],
)
def test_another_spelling_of_a_name_is_a_collection_failure(tmp_path, relative, canonical):
    _write(tmp_path, relative)

    result = RAGScanner().scan(tmp_path)

    assert _guardrails(result) == []
    assert result.scan_failures == [
        f"{relative}: case variant of {canonical} is the active file on case-insensitive "
        "file systems and is not inventoried"
    ]


def test_another_spelling_of_a_nemo_configuration_is_a_collection_failure(tmp_path):
    _write(tmp_path, "rails/Config.YML", b"models: []\n")
    _write(tmp_path, "rails/main.co", b"define flow a\n")

    result = RAGScanner().scan(tmp_path)

    assert _guardrails(result) == []
    (failure,) = result.scan_failures
    assert failure.startswith("rails/Config.YML: case variant of rails/config.yml ")


def test_too_many_colang_files_are_a_named_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus_symbiote.scanners.rag._MAX_ENTRIES", 2)
    _write(tmp_path, "rails/config.yml", b"models: []\n")
    for index in range(3):
        _write(tmp_path, f"rails/{index}.co", b"define flow a\n")

    result = RAGScanner().scan(tmp_path)

    assert _guardrails(result) == []
    assert result.scan_failures == [
        "rails/config.yml: more than 2 Colang files beside the configuration"
    ]


def _project(root: Path) -> Path:
    project = root / "project"
    _write(project, "configs/guardrails.yaml")
    _write(project, "evals/promptfooconfig.yaml", b'prompts: ["{{q}}"]\n')
    _write(project, "rails/config.yml", b"models: []\n")
    _write(project, "rails/main.co", b"define flow a\n")
    return project


def test_a_collection_failure_fails_scan(runner, tmp_path):
    project = _project(tmp_path)
    _write(project, "Guardrails.yaml")

    run = runner.invoke(main, ["scan", str(project), "-o", str(tmp_path / "bom.json")])

    assert run.exit_code == 1, run.output
    assert "case variant of guardrails.yaml" in run.output


def test_two_scans_are_byte_identical_and_raise_no_finding(runner, tmp_path):
    project = _project(tmp_path)

    first = _inventory(runner, project, tmp_path / "a.json")
    _inventory(runner, project, tmp_path / "b.json")

    assert (tmp_path / "a.json").read_bytes() == (tmp_path / "b.json").read_bytes()
    recorded = [c for c in first["components"] if c["component_type"] == "guardrail-policy"]
    assert [c["bom_ref"] for c in recorded] == [
        "guardrail:configs/guardrails.yaml",
        "guardrail:evals/promptfooconfig.yaml",
        "guardrail:rails/config.yml",
    ]
    assert all(c["risks"] == [] for c in first["components"])
    risk = runner.invoke(main, ["risk", str(tmp_path / "a.json")])
    assert risk.exit_code == 0, risk.output
    assert "Risk Score: 0.0" in risk.output


@pytest.mark.parametrize("changed", ["configs/guardrails.yaml", "rails/main.co"])
def test_a_changed_file_is_a_high_drift_alert(runner, tmp_path, changed):
    project = _project(tmp_path)
    _inventory(runner, project, tmp_path / "before.json")
    (project / changed).write_bytes(b"rails: {}\n")
    _inventory(runner, project, tmp_path / "after.json")
    snapshots = [str(tmp_path / "before.json"), str(tmp_path / "after.json")]

    run = runner.invoke(main, ["diff", *snapshots, "--fail-on-alert"])
    report = json.loads(runner.invoke(main, ["diff", *snapshots, "--json-output"]).output)

    assert run.exit_code == 1, run.output
    assert "[HIGH]" in run.output
    assert "config_hash changed." in run.output
    (modified,) = report["components_modified"]
    assert modified["type"] == "guardrail-policy"
    assert modified["severity"] == "high"
    assert report["components_added"] == report["components_removed"] == []


def test_an_unchanged_project_raises_no_drift_alert(runner, tmp_path):
    project = _project(tmp_path)
    _inventory(runner, project, tmp_path / "before.json")
    _inventory(runner, project, tmp_path / "after.json")

    run = runner.invoke(
        main,
        ["diff", str(tmp_path / "before.json"), str(tmp_path / "after.json"), "--fail-on-alert"],
    )

    assert run.exit_code == 0, run.output


def test_added_and_removed_files_alert(runner, tmp_path):
    project = _project(tmp_path)
    _inventory(runner, project, tmp_path / "with.json")
    (project / "evals/promptfooconfig.yaml").unlink()
    _inventory(runner, project, tmp_path / "without.json")
    with_file, without = str(tmp_path / "with.json"), str(tmp_path / "without.json")

    removed = runner.invoke(main, ["diff", with_file, without, "--fail-on-alert"])
    added = runner.invoke(main, ["diff", without, with_file, "--fail-on-alert"])

    assert removed.exit_code == 1, removed.output
    assert (
        "[HIGH] Component 'evals/promptfooconfig.yaml' (guardrail-policy) is no longer in the "
        "inventory" in removed.output
    )
    assert added.exit_code == 1, added.output
    assert (
        "[MEDIUM] New component 'evals/promptfooconfig.yaml' (guardrail-policy) added"
        in added.output
    )


def test_project_validation_reconciles_until_a_file_changes(runner, tmp_path):
    project = _project(tmp_path)
    inventory = tmp_path / "bom.json"
    _inventory(runner, project, inventory)
    command = ["validate", str(inventory), "--project", str(project)]

    fresh = runner.invoke(main, command)
    (project / "configs/guardrails.yaml").write_bytes(b"rails: {}\n")
    edited = runner.invoke(main, command)

    assert "Basis: project-reconciled" in fresh.output
    assert "project-reconciliation-failed" not in fresh.output
    assert edited.exit_code == 1, edited.output
    assert "project-reconciliation-failed" in edited.output
    assert (
        "[guardrail:configs/guardrails.yaml] Missing or mismatched local component" in edited.output
    )


def test_exports_validate_and_reports_run(runner, tmp_path):
    project = _project(tmp_path)
    inventory = tmp_path / "bom.json"
    _inventory(runner, project, inventory)

    cyclonedx = _inventory(runner, project, tmp_path / "bom.cdx.json", "-f", "cyclonedx")
    spdx = _inventory(runner, project, tmp_path / "bom.spdx.json", "-f", "spdx")
    sarif = _inventory(runner, project, tmp_path / "bom.sarif", "-f", "sarif")

    assert validate_cyclonedx(cyclonedx) == []
    assert validate_spdx(spdx) == []
    assert validate_sarif(sarif) == []
    exported = {c["bom-ref"]: c for c in cyclonedx["components"]}
    assert exported["guardrail:configs/guardrails.yaml"]["type"] == "library"
    for command in (
        ["vex", str(inventory), "-o", str(tmp_path / "bom.vex.json")],
        ["minimum-elements", str(inventory)],
        ["graph", str(inventory), "-o", str(tmp_path / "graph.html")],
        ["risk", str(inventory)],
        ["summary", str(inventory)],
    ):
        run = runner.invoke(main, command)
        assert run.exit_code == 0, (command[0], run.output)
    assert "guardrail-policy: 3" in runner.invoke(main, ["summary", str(inventory)]).output


def test_a_configuration_linked_to_a_credential_file_is_a_gap_and_not_digested(tmp_path):
    _write(tmp_path, ".env.prod", b"API_TOKEN=synthetic-value\n")
    (tmp_path / "guardrails.yml").symlink_to(".env.prod")
    result = RAGScanner().scan(tmp_path)
    assert result.components == [] and result.scan_failures == []
    assert result.surfaces_excluded == [
        "guardrails.yml: a symlink leads to .env.prod, whose name says it holds credentials; "
        "not read or inventoried"
    ]


def test_a_colang_file_linked_to_a_credential_file_is_a_gap_and_not_digested(tmp_path):
    secret = b"define flow x\n  synthetic\n"
    _write(tmp_path, "rails/config.yml")
    _write(tmp_path, "rails/flows.co", b"define flow greet\n")
    _write(tmp_path, "rails/secret.token", secret)
    (tmp_path / "rails" / "main.co").symlink_to("secret.token")
    result = RAGScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [
        "rails/main.co: a symlink leads to rails/secret.token, whose name says it holds "
        "credentials; not read or inventoried"
    ]
    (component,) = result.components
    assert component.properties["rail_files"] == {"flows.co": _sha256(b"define flow greet\n")}
    assert _sha256(secret) not in json.dumps(component.model_dump(mode="json"))
