"""Operator-selected package and advisory scopes in the project gates."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main


def _scan(project: Path, *options: str) -> Path:
    path = project.parent / "inventory.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(path), *options],
    )
    assert result.exit_code == 0, result.output
    return path


def _replay(command: str, project: Path, inventory: Path, *options: str) -> dict:
    gate_options = (
        ["--skip-integrity"]
        if command == "validate"
        else ["--no-score-threshold", "--fail-on-severity", "none"]
    )
    result = CliRunner().invoke(
        main,
        [
            command,
            str(inventory),
            "--project",
            str(project),
            "--no-project-policy",
            "--json-output",
            *gate_options,
            *options,
        ],
    )
    report = json.loads(result.stdout)
    assert result.exit_code == (0 if report["passed"] else 1), result.output
    return report


def _diagnostics(report: dict) -> list[str]:
    if "completeness" in report:
        return [issue["description"] for issue in report["completeness"]["issues"]]
    return report["gate_reasons"]


def _bundle(root: Path, *, affected_version: str = "9.0.0") -> Path:
    path = root / "osv.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": "PYSEC-2026-999999",
                    "modified": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "pillow"},
                            "versions": [affected_version],
                        }
                    ],
                    "database_specific": {"severity": "HIGH"},
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("langchain==0.3.27\npillow==9.0.0\n", encoding="utf-8")
    return root


def test_all_packages_recollects_non_catalog_images(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "Dockerfile").write_text(
        "FROM debian:bookworm AS builder\nFROM builder AS intermediate\nFROM scratch\n"
    )
    (project / "compose.yaml").write_text("services:\n  db:\n    image: postgres:16\n")

    def images(path: Path) -> set[str]:
        components = json.loads(path.read_bytes())["components"]
        return {entry["name"] for entry in components if entry.get("registry_type") == "docker-hub"}

    assert not images(_scan(project))
    inventory = _scan(project, "--all-packages")
    assert images(inventory) == {"debian:bookworm", "postgres:16"}
    for command in ("validate", "risk"):
        assert _replay(command, project, inventory, "--all-packages")["assessment_basis"] == (
            "project-reconciled"
        )


@pytest.mark.parametrize("command", ["validate", "risk"])
def test_package_scope_is_explicit_and_detects_pin_drift(command: str, project: Path) -> None:
    catalog = _scan(project)
    assert _replay(command, project, catalog)["assessment_basis"] == "project-reconciled"
    too_narrow = _replay(command, project, catalog, "--all-packages")
    assert too_narrow["assessment_basis"] == "project-reconciliation-failed"
    assert any("pillow" in issue for issue in _diagnostics(too_narrow))

    document = json.loads(catalog.read_bytes())
    (langchain,) = [row for row in document["components"] if row["name"] == "langchain"]
    langchain["properties"]["ai_catalog"] = True
    catalog.write_text(json.dumps(document), encoding="utf-8")
    assert (
        _replay(command, project, catalog)["assessment_basis"]
        == "project-reconciled-with-supplier-claims"
    )

    inventory = _scan(project, "--all-packages")
    default = _replay(command, project, inventory)
    assert default["assessment_basis"] == "project-reconciliation-failed"
    assert any(
        "no matching local evidence" in issue and "pillow" in issue
        for issue in _diagnostics(default)
    )
    assert (
        _replay(command, project, inventory, "--all-packages")["assessment_basis"]
        == "project-reconciled"
    )

    (project / "requirements.txt").write_text(
        "langchain==0.3.27\npillow==10.0.0\n", encoding="utf-8"
    )
    drifted = _replay(command, project, inventory, "--all-packages")
    assert drifted["assessment_basis"] == "project-reconciliation-failed"
    assert any(
        "mismatched local component" in issue and "pillow" in issue
        for issue in _diagnostics(drifted)
    )


@pytest.mark.parametrize("command", ["validate", "risk"])
@pytest.mark.parametrize("flag", ["--all-packages", "--advisory-db"])
def test_replay_options_require_project(command: str, flag: str, project: Path) -> None:
    inventory = _scan(project)
    options = [flag, str(_bundle(project.parent))] if flag == "--advisory-db" else [flag]
    result = CliRunner().invoke(main, [command, str(inventory), *options])
    assert result.exit_code == 2
    assert f"{flag} requires --project" in result.output


@pytest.mark.parametrize("command", ["validate", "risk"])
def test_replay_rederives_advisories_only_with_independent_bundle(
    command: str, project: Path
) -> None:
    bundle = _bundle(project.parent)
    options = ["--all-packages", "--advisory-db", str(bundle)]
    inventory = _scan(project, *options)
    report = _replay(command, project, inventory, *options)
    assert report["assessment_basis"] == "project-reconciled"

    uncorroborated = _replay(command, project, inventory, "--all-packages")
    assert uncorroborated["assessment_basis"] == "project-reconciled-with-supplier-claims"
    claims = uncorroborated.get("completeness", uncorroborated)["supplier_claims"]
    assert {claim["detail"] for claim in claims} == {
        "advisories",
        "surfaces_scanned",
        "high known_vulnerability: not in the local collection",
    }

    document = json.loads(inventory.read_bytes())
    (package,) = [row for row in document["components"] if row["name"] == "pillow"]
    package["risks"] = [
        risk for risk in package["risks"] if risk["category"] != "known_vulnerability"
    ]
    inventory.write_text(json.dumps(document), encoding="utf-8")
    missing = _replay(command, project, inventory, *options)
    assert missing["assessment_basis"] == "project-reconciliation-failed"
    assert any(
        "mismatched local component" in issue and "pillow" in issue
        for issue in _diagnostics(missing)
    )


def test_zero_checked_advisory_receipt_requires_independent_bundle(project: Path) -> None:
    (project / "requirements.txt").unlink()
    (project / "AGENTS.md").write_text("Record source declarations.", encoding="utf-8")
    bundle = _bundle(project.parent)
    inventory = _scan(project, "--advisory-db", str(bundle))

    report = _replay("validate", project, inventory, "--advisory-db", str(bundle))
    assert report["assessment_basis"] == "project-reconciled"
    assert not any(
        "offline OSV bundle" in surface for surface in report["completeness"]["surfaces_covered"]
    )

    uncorroborated = _replay("validate", project, inventory)
    assert uncorroborated["assessment_basis"] == "project-reconciled-with-supplier-claims"
    assert [claim["detail"] for claim in uncorroborated["completeness"]["supplier_claims"]] == [
        "unobserved_surfaces"
    ]


def test_bundle_inside_project_is_refused(project: Path) -> None:
    inside = _bundle(project)
    inventory = _scan(project)
    report = _replay("validate", project, inventory, "--advisory-db", str(inside))
    assert report["assessment_basis"] == "project-reconciliation-failed"
    assert any("must lie outside the scanned project" in issue for issue in _diagnostics(report))


@pytest.mark.parametrize("command", ["scan", "validate", "risk"])
def test_feed_in_checkout_enclosing_the_nested_project_is_refused(
    command: str, tmp_path: Path
) -> None:
    checkout = tmp_path / "checkout"
    project = checkout / "services" / "app"
    project.mkdir(parents=True)
    (checkout / ".git").mkdir()
    (project / ".git").write_text("gitdir: submodule-metadata\n")
    (project / "requirements.txt").write_text("langchain==0.3.27\n")
    feed = _bundle(checkout)
    inventory = _scan(project)
    if command == "scan":
        result = CliRunner().invoke(
            main, ["scan", str(project), "--advisory-db", str(feed), "-o", str(inventory)]
        )
        assert result.exit_code == 1, result.output
        claim = json.loads(inventory.read_bytes())["metadata"]["completeness"]
        reasons = claim["scan_failures"]
    else:
        report = _replay(command, project, inventory, "--advisory-db", str(feed))
        assert report["assessment_basis"] == "project-reconciliation-failed"
        reasons = _diagnostics(report)
    assert any("outside every git repository" in reason for reason in reasons)


@pytest.mark.parametrize("command", ["validate", "risk"])
def test_feed_in_inventory_repository_is_refused(command: str, project: Path) -> None:
    artifacts = project.parent / "artifacts"
    artifacts.mkdir()
    (artifacts / ".git").mkdir()
    inventory = _scan(project).rename(artifacts / "inventory.json")
    feed = _bundle(artifacts)
    report = _replay(command, project, inventory, "--advisory-db", str(feed))
    assert report["assessment_basis"] == "project-reconciliation-failed"
    assert any("outside every git repository" in issue for issue in _diagnostics(report))


@pytest.mark.parametrize("command", ["validate", "risk"])
def test_replay_rejects_changed_bundle_with_same_zero_hits(command: str, project: Path) -> None:
    bundle = _bundle(project.parent, affected_version="11.0.0")
    options = ["--all-packages", "--advisory-db", str(bundle)]
    inventory = _scan(project, *options)
    document = json.loads(inventory.read_bytes())
    assert all("advisories" not in c.get("properties", {}) for c in document["components"])
    assert (
        _replay(command, project, inventory, *options)["assessment_basis"] == "project-reconciled"
    )

    bundle.write_bytes(bundle.read_bytes() + b"\n")
    report = _replay(command, project, inventory, *options)
    assert report["assessment_basis"] == "project-reconciliation-failed"
    assert any("Advisory coverage receipt" in issue for issue in _diagnostics(report))


@pytest.mark.parametrize("flag", ["--all-packages", "--advisory-db"])
def test_validate_honors_explicit_replay_when_project_policy_skips_completeness(
    flag: str, project: Path
) -> None:
    options = [flag, str(_bundle(project.parent))] if flag == "--advisory-db" else [flag]
    inventory = _scan(project, *options)
    (project / ".nexus-symbiote.yaml").write_text(
        "validate:\n  require_completeness: false\n", encoding="utf-8"
    )
    arguments = [
        "validate",
        str(inventory),
        "--project",
        str(project),
        "--accept-project-policy",
        "--json-output",
        "--skip-integrity",
    ]
    runner = CliRunner()
    default = runner.invoke(main, arguments)
    assert default.exit_code == 0, default.output
    assert json.loads(default.stdout)["assessment_basis"] == "project-not-reconciled"

    replay = runner.invoke(main, [*arguments, *options])
    assert replay.exit_code == 0, replay.output
    assert json.loads(replay.stdout)["assessment_basis"] == "project-reconciled"
