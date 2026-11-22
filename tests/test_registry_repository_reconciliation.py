"""Compare declared repository identities against inert local lockfile records."""

import base64
import hashlib
import json

import pytest
from click.testing import CliRunner
from packageurl import PackageURL

from nexus_symbiote import sbom_import
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.sbom_import import import_foreign_sbom
from nexus_symbiote.scanners.registry import RegistryScanner


def _project(root, ecosystem, repository):
    root.mkdir()
    if ecosystem == "pypi":
        (root / "requirements.txt").write_text("openai==1.2.3\n")
        (root / "uv.lock").write_text(
            f'[[package]]\nname="openai"\nversion="1.2.3"\nsource={{registry="{repository}"}}\n'
        )
    else:
        requirements = {"openai": "1.2.3"}
        (root / "package.json").write_text(json.dumps({"dependencies": requirements}))
        integrity = base64.b64encode(hashlib.sha512(b"public fixture").digest()).decode()
        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": requirements},
                        "node_modules/openai": {
                            "version": "1.2.3",
                            "resolved": repository.rstrip("/") + "/openai/-/openai-1.2.3.tgz",
                            "integrity": "sha512-" + integrity,
                        },
                    },
                }
            )
        )


def _supplier(path, ecosystem, repository):
    purl = PackageURL(
        type=ecosystem, name="openai", version="1.2.3", qualifiers={"repository_url": repository}
    ).to_string()
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"type": "library", "name": "openai", "version": "1.2.3", "purl": purl}
                ],
            }
        )
    )
    return path


@pytest.mark.parametrize(
    ("ecosystem", "locked", "supplied", "unresolved"),
    [
        ("npm", "https://registry.npmjs.org", "https://registry.yarnpkg.com", 0),
        ("npm", "https://registry.yarnpkg.com", "https://registry.npmjs.org:443/", 0),
        ("pypi", "https://pypi.org/simple", "https://files.pythonhosted.org", 0),
        ("pypi", "https://files.pythonhosted.org", "https://pypi.org/simple/", 0),
        ("pypi", "https://python.example.test/simple", "https://python.example.test/simple/", 0),
        (
            "npm",
            "https://repo.example.test/repository/team-a",
            "https://repo.example.test/repository/team-a",
            0,
        ),
        (
            "npm",
            "https://repo.example.test/artifactory/api/npm/team-a",
            "https://repo.example.test/artifactory/api/npm/team-a",
            0,
        ),
        (
            "npm",
            "https://repo.example.test/repository/team-a",
            "https://repo.example.test/repository/team-b",
            1,
        ),
        (
            "pypi",
            "https://repo.example.test/team-a/simple",
            "https://repo.example.test/team-b/simple",
            1,
        ),
        ("pypi", "https://repo.example.test/simple", "https://other.example.test/simple", 1),
        ("pypi", "https://repo.example.test:444/simple", "https://repo.example.test/simple", 1),
        ("npm", "https://registry.npmjs.org", "https://registry.npmjs.org/unrelated", 1),
        ("pypi", "https://pypi.org/simple", "https://pypi.org/unrelated", 1),
    ],
)
def test_public_scan_import_and_gate_compare_the_selected_repository(
    tmp_path, ecosystem, locked, supplied, unresolved
):
    project = tmp_path / "project"
    _project(project, ecosystem, locked)
    supplier = _supplier(tmp_path / "supplier.json", ecosystem, supplied)
    base, merged = tmp_path / "base.json", tmp_path / "merged.json"
    cli = CliRunner()
    scan = cli.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(base)])
    assert base.is_file(), scan.output
    result = cli.invoke(
        main,
        [
            "import-sbom",
            str(supplier),
            "--project",
            str(project),
            "--into",
            str(base),
            "--walk-manifests",
            "--json-output",
            "-o",
            str(merged),
        ],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)
    assert (summary["conflict_count"], summary["unresolved_conflict_count"]) == (0, unresolved)
    gate = cli.invoke(
        main, ["risk", str(merged), "--no-project-policy", "--fail-on-severity", "medium"]
    )
    assert gate.exit_code == int(bool(unresolved)), gate.output


@pytest.mark.parametrize(
    "project_evidence", ["absent", "changed", "linked", "other-record", "bare-index"]
)
def test_same_host_does_not_substitute_for_a_missing_selected_record(tmp_path, project_evidence):
    project = tmp_path / "project"
    origin = "https://repo.example.test/team-a/simple"
    _project(project, "pypi", origin)
    native = AIBOM(components=RegistryScanner().scan(project).components)
    supplier = _supplier(tmp_path / "supplier.json", "pypi", origin)
    if project_evidence == "changed":
        (project / "uv.lock").write_text((project / "uv.lock").read_text() + "# changed\n")
    if project_evidence == "linked":
        original = project / "preserved.lock"
        (project / "uv.lock").rename(original)
        (project / "uv.lock").symlink_to(original.name)
    if project_evidence == "other-record":
        native.components[0].properties["lockfile_record"] = "uv.lock#/package/99"
    if project_evidence == "bare-index":
        native.components[0].properties["lockfile_record"] = "0"
    summary = import_foreign_sbom(
        supplier,
        target_aibom=native,
        project_root=None if project_evidence == "absent" else project,
    )
    assert (summary.conflict_count, summary.unresolved_conflict_count) == (0, 1)


@pytest.mark.parametrize(
    ("eco", "old", "new"),
    [
        ("npm", "https://registry.yarnpkg.com", "https://registry.npmjs.org"),
        ("pypi", "https://files.pythonhosted.org", "https://pypi.org/simple"),
        ("pypi", "https://pypi.org/simple", "https://pypi.org"),
    ],
)
def test_hidden_inventory_written_before_public_alias_normalization(
    tmp_path, monkeypatch, eco, old, new
):
    first = _supplier(tmp_path / "old.json", eco, old)
    second = _supplier(tmp_path / "new.json", eco, new)
    with monkeypatch.context() as before:
        before.setattr(
            sbom_import, "_repository_identity", lambda value, ecosystem=None: value.rstrip("/")
        )
        old_bom = import_foreign_sbom(first).aibom
    summary = import_foreign_sbom(second, target_aibom=AIBOM.model_validate_json(old_bom.to_json()))
    assert (summary.conflict_count, summary.unresolved_conflict_count) == (0, 0)


def test_registry_paths_from_two_suppliers_on_one_host_remain_distinct(tmp_path):
    first = _supplier(tmp_path / "a.json", "npm", "https://repo.example.test/repository/a")
    second = _supplier(tmp_path / "b.json", "npm", "https://repo.example.test/repository/b")
    saved = import_foreign_sbom(first).aibom
    summary = import_foreign_sbom(second, target_aibom=AIBOM.model_validate_json(saved.to_json()))
    assert (summary.conflict_count, summary.unresolved_conflict_count) == (0, 1)
