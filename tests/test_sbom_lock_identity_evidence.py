"""Exercise supplier reconciliation with ordinary package and lock records, offline."""

import json

import pytest
from packageurl import PackageURL

from nexus_symbiote import sbom_import as sbom
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import RegistryEntryComponent
from nexus_symbiote.scanners.registry import RegistryScanner
from tests.test_registry_repository_reconciliation import _project, _supplier

_HOST = "https://packages.example.test"
_REPO = _HOST + "/department/simple"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("packages", []),
        ("locator", "package-lock.json#/packages/other"),
        ("version", "1.2.4"),
        ("resolved", None),
        ("resolved", _REPO + "/openai/releases/1.2.3.tgz"),
        ("resolved", _REPO + "/notes/-/openai-1.2.3.tgz"),
        ("raw", "[]"),
        ("raw", "incomplete document"),
    ],
)
def test_unusable_npm_record_leaves_supplier_origin_unresolved(tmp_path, field, replacement):
    root = tmp_path / "project"
    _project(root, "npm", _REPO)
    native = AIBOM(components=RegistryScanner().scan(root).components)
    record = native.components[0]
    lock = root / "package-lock.json"
    data = json.loads(lock.read_bytes())
    if field == "locator":
        record.properties["lockfile_record"] = replacement
    elif field == "packages":
        data[field] = replacement
    elif field != "raw":
        data["packages"]["node_modules/openai"][field] = replacement
    contents = (replacement if field == "raw" else json.dumps(data)).encode()
    lock.write_bytes(contents)
    record.properties["lockfile_sha256"] = hash_bytes(contents)
    supplier = _supplier(tmp_path / "supplier.json", "npm", _REPO)
    result = sbom.import_foreign_sbom(supplier, target_aibom=native, project_root=root)
    assert (result.conflict_count, result.unresolved_conflict_count) == (0, 1)


def _poetry_record(raw):
    return RegistryEntryComponent(
        bom_ref="registry:poetry-sample",
        name="openai",
        version="1.2.3",
        registry_type="pypi",
        registry_uri=_HOST,
        package_url=PackageURL(type="pypi", name="openai", version="1.2.3").to_string(),
        source_path="poetry.lock",
        properties={
            "collection_mode": "lockfile-resolution-claim",
            "lockfile_record": "poetry.lock#/package/0",
            "lockfile_sha256": hash_bytes(raw),
        },
    )


@pytest.mark.parametrize(
    ("name", "version", "source", "unresolved"),
    [
        ("openai", "1.2.3", _REPO, 0),
        ("openai", "1.2.3", _HOST + "/different/simple", 1),
        ("sample", "1.2.3", _REPO, 1),
        ("openai", "1.2.4", _REPO, 1),
        ("openai", "1.2.3", None, 1),
        (None, "1.2.3", _REPO, 1),
    ],
)
def test_saved_poetry_inventory_must_identify_the_exact_selected_row(
    tmp_path, name, version, source, unresolved
):
    root = tmp_path / "project"
    root.mkdir()
    lines = ["[[package]]", f'version = "{version}"']
    if name:
        lines.append(f'name = "{name}"')
    if source:
        lines.extend(["[package.source]", 'type = "legacy"', f'url = "{source}"'])
    raw = ("\n".join(lines) + "\n").encode()
    (root / "poetry.lock").write_bytes(raw)
    native = AIBOM(components=[_poetry_record(raw)])
    result = sbom.import_foreign_sbom(
        _supplier(tmp_path / "supplier.json", "pypi", _REPO), target_aibom=native, project_root=root
    )
    assert (result.conflict_count, result.unresolved_conflict_count) == (0, unresolved)


@pytest.mark.parametrize(
    "defect", ["imported", "wrong-ecosystem", "manifest-only", "missing-locator"]
)
def test_inventory_without_native_lock_evidence_cannot_corroborate_a_path(tmp_path, defect):
    raw = f'[[package]]\nname="openai"\nversion="1.2.3"\nsource={{url="{_REPO}"}}\n'.encode()
    (tmp_path / "poetry.lock").write_bytes(raw)
    record = _poetry_record(raw)
    if defect == "imported":
        record.properties["imported_source_format"] = "CycloneDX"
    elif defect == "wrong-ecosystem":
        record.registry_type = "npm"
    elif defect == "manifest-only":
        record.properties["collection_mode"] = "manifest-reference"
    else:
        del record.properties["lockfile_record"]
    supplier = sbom._purl_identity(
        PackageURL(type="pypi", name="openai", qualifiers={"repository_url": _REPO}).to_string()
    )
    assert sbom._matched_lock_repositories(tmp_path, [record], [supplier], None, []) == {}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://[2001:db8::10]:443/team/", "https://[2001:db8::10]/team"),
        ("https://packages.example.test:8081/team/", _HOST + ":8081/team"),
        ("notes:local", "notes:local"),
        ("https://packages.example.test:bad/team", "https://packages.example.test:bad/team"),
        ("répertoire", "répertoire"),
    ],
)
def test_only_unambiguous_repository_locations_are_normalized(value, expected):
    assert sbom._repository_identity(value, "pypi") == expected


@pytest.mark.parametrize(
    ("ecosystem", "requirement", "version", "expected"),
    [
        ("npm", "*", "1.2.3", True),
        ("npm", "~2.3", "2.4.0", False),
        ("npm", ">2", "3.0.0", True),
        ("npm", "<=2", "3.0.0", False),
        ("npm", "<2.1", "2.0.9", True),
        ("npm", "2.1.x", "2.1.9", True),
        ("npm", "^*", "1.2.3", None),
        ("npm", "1.x.2", "1.2.3", None),
        ("npm", "^1.0.1-01", "1.2.3", None),
        ("npm", "latest", "1.2.3", None),
        ("npm", "", "1.2.3", None),
        ("cargo", "1.2", "1.2", None),
        ("cargo", "*", "", None),
        ("conda", "", "1.2.3", None),
        ("conda", "stable", "1.2.3", None),
        ("conda", ">2.*", "2.3", None),
        ("conda", "=2.alpha*", "2.3", None),
        ("conda", "==2.invalid.local", "2.3", None),
        ("conda", ">=2", "unversioned", None),
        ("conda", "!=1.2.*", "1.3.0", True),
    ],
)
def test_nested_lock_comparisons_preserve_unknown_versions(
    ecosystem, requirement, version, expected
):
    assert sbom._satisfies_nested_requirement(ecosystem, requirement, version) is expected


@pytest.mark.parametrize(
    ("requirement", "locked", "expected"),
    [
        ("openai>=1,<2", "invalid version", ("<2,>=1", "manifest-only")),
        ("openai>=1,<2", "2.0.0", ("<2,>=1", "manifest-only")),
        ("openai>=1,<2", "1.2.1", ("1.2.1", "locked")),
    ],
)
def test_pypi_lock_can_confirm_only_a_matching_parseable_version(requirement, locked, expected):
    item = sbom._py_req_item(requirement, {"openai": locked})
    assert item is not None
    assert (item[1], item[3]) == expected
