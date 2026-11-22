"""Compare ordinary supplier declarations to configured registries without publishing a package URL."""

import json

import pytest
from click.testing import CliRunner
from packageurl import PackageURL

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.sbom_import import import_foreign_sbom
from nexus_symbiote.scanners.registry import RegistryScanner
from tests.test_registry_repository_reconciliation import _project, _supplier

_ORIGIN = "https://packages.example.test"
_LOCKED = _ORIGIN + "/departments/amber"
_OTHER = _ORIGIN + "/departments/blue"


def _configured(root, setting):
    ecosystem = "npm" if setting == "npm" else "pypi"
    _project(root, ecosystem, _LOCKED)
    if setting == "npm":
        (root / ".npmrc").write_text(f"registry={_LOCKED}/\n")
    elif setting == "pip":
        (root / "pip.conf").write_text(f"[global]\nindex-url={_LOCKED}\n")
    elif setting == "uv":
        (root / "pyproject.toml").write_text(f'[[tool.uv.index]]\nname="team"\nurl="{_LOCKED}"\n')
    else:
        (root / "uv.lock").unlink()
        (root / "pyproject.toml").write_text(
            f'[[tool.poetry.source]]\nname="team"\nurl="{_LOCKED}"\npriority="primary"\n'
        )
        (root / "poetry.lock").write_text(
            '[[package]]\nname="openai"\nversion="1.2.3"\n'
            f'[package.source]\ntype="legacy"\nurl="{_LOCKED}"\nreference="team"\n'
        )
    return ecosystem


@pytest.mark.parametrize("setting", ["npm", "pip", "uv", "poetry"])
@pytest.mark.parametrize("repository", [_LOCKED, _OTHER, "https://mirror.example.test/amber"])
def test_withheld_source_leaves_explicit_supplier_provenance_unresolved(
    tmp_path, setting, repository
):
    project = tmp_path / "project"
    ecosystem = _configured(project, setting)
    saved = AIBOM(components=RegistryScanner().scan(project).components)
    saved = AIBOM.model_validate_json(saved.to_json())
    (component,) = saved.components
    assert component.package_url is None and component.properties["package_sources"]
    supplier = _supplier(tmp_path / "supplier.json", ecosystem, repository)
    result = import_foreign_sbom(supplier, target_aibom=saved, project_root=project)
    assert (result.conflict_count, result.unresolved_conflict_count) == (0, 1)
    assert result.aibom.components[0].package_url is None


@pytest.mark.parametrize("setting", ["npm", "uv"])
@pytest.mark.parametrize(
    "claim", ["same-unqualified", "unrelated", "other-ecosystem", "qualified", "display-alias"]
)
def test_manifest_only_does_not_decide_a_qualified_repository(tmp_path, setting, claim):
    project = tmp_path / "project"
    ecosystem = _configured(project, setting)
    (project / ("package-lock.json" if setting == "npm" else "uv.lock")).unlink()
    native = AIBOM(components=RegistryScanner().scan(project).components)
    (component,) = native.components
    assert component.package_url is None and component.properties["package_sources"]
    supplier = _supplier(tmp_path / "supplier.json", ecosystem, _LOCKED)
    doc = json.loads(supplier.read_text())
    (entry,) = doc["components"]
    name = "another-package" if claim == "unrelated" else "openai"
    kind = ("pypi" if setting == "npm" else "npm") if claim == "other-ecosystem" else ecosystem
    entry["name"] = "workspace-sdk" if claim == "display-alias" else name
    entry["purl"] = PackageURL(
        type=kind,
        name=name,
        version="1.2.3",
        qualifiers={} if claim == "same-unqualified" else {"repository_url": _LOCKED},
    ).to_string()
    supplier.write_text(json.dumps(doc))
    result = import_foreign_sbom(supplier, target_aibom=native, project_root=project)
    assert (result.conflict_count, result.unresolved_conflict_count) == (
        0,
        int(claim in {"qualified", "display-alias"}),
    )


@pytest.mark.parametrize("alias", [False, True])
def test_scoped_npm_record_compares_its_installed_name(tmp_path, alias):
    repository = _OTHER
    project = tmp_path / "workspace"
    _project(project, "npm", _LOCKED)
    name = "@anthropic-ai/sdk"
    key = "workspace-sdk" if alias else name
    spec = f"npm:{name}@1.2.3" if alias else "1.2.3"
    (project / ".npmrc").write_text(f"@anthropic-ai:registry={_LOCKED}/\n")
    (project / "package.json").write_text(json.dumps({"dependencies": {key: spec}}))
    path = project / "package-lock.json"
    lock = json.loads(path.read_text())
    packages = lock["packages"]
    packages[""]["dependencies"] = {key: spec}
    record = packages.pop("node_modules/openai")
    record.update(name=name, resolved=f"{_LOCKED}/{name}/-/sdk-1.2.3.tgz")
    packages[f"node_modules/{key}"] = record
    path.write_text(json.dumps(lock))
    supplier = _supplier(tmp_path / "supplier.json", "npm", repository)
    doc = json.loads(supplier.read_text())
    (entry,) = doc["components"]
    entry.update(
        name=name,
        purl=PackageURL(
            type="npm",
            namespace="@anthropic-ai",
            name="sdk",
            version="1.2.3",
            qualifiers={"repository_url": repository},
        ).to_string(),
    )
    supplier.write_text(json.dumps(doc))
    native = AIBOM(components=RegistryScanner().scan(project).components)
    (component,) = native.components
    assert component.name == name and component.package_url is None
    result = import_foreign_sbom(supplier, target_aibom=native, project_root=project)
    assert (result.conflict_count, result.unresolved_conflict_count) == (0, 1)


def test_cli_carries_unresolved_source_to_the_risk_gate(tmp_path):
    project = tmp_path / "project"
    _configured(project, "npm")
    saved, merged = tmp_path / "base.json", tmp_path / "merged.json"
    runner = CliRunner()
    runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(saved)])
    assert saved.is_file()
    supplier = _supplier(tmp_path / "supplier.json", "npm", _OTHER)
    imported = runner.invoke(
        main,
        [
            "import-sbom",
            str(supplier),
            "--into",
            str(saved),
            "--project",
            str(project),
            "--walk-manifests",
            "--json-output",
            "-o",
            str(merged),
        ],
    )
    assert imported.exit_code == 0, imported.output
    assert json.loads(imported.stdout)["unresolved_conflict_count"] == 1
    gate = runner.invoke(
        main, ["risk", str(merged), "--no-project-policy", "--fail-on-severity", "medium"]
    )
    assert gate.exit_code == 1, gate.output


def test_a_supplier_record_cannot_claim_a_native_redirect(tmp_path):
    project = tmp_path / "project"
    _configured(project, "pip")
    native = AIBOM(components=RegistryScanner().scan(project).components)
    (component,) = native.components
    component.properties["imported_source_format"] = "cyclonedx-1.5"
    supplier = _supplier(tmp_path / "supplier.json", "pypi", _OTHER)
    result = import_foreign_sbom(supplier, target_aibom=native)
    assert (result.conflict_count, result.unresolved_conflict_count) == (0, 0)
