"""Verify compatible requirements and disagreements using inert supplier records."""

import hashlib
import json
from urllib.parse import quote

import pytest
from packageurl import PackageURL

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import RegistryEntryComponent
from nexus_symbiote.sbom_import import (
    _satisfies_nested_requirement,
    import_foreign_sbom,
    walk_nested_manifests,
)
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV


@pytest.mark.parametrize(
    ("ecosystem", "requirement", "supplied", "satisfies"),
    [
        ("cargo", "1.2.*", "1.2.9", True),
        ("cargo", "1.2.*", "1.5.0", False),
        ("cargo", "2.0.x", "2.3.0", False),
        ("cargo", "1.2", "1.5.0", True),
        ("cargo", "^4.0.0", "4.8.1-0", False),
        ("npm", "^4.0.0", "4.8.1-0", False),
        ("npm", "^4.0.0-0 <4.5.0", "4.9.0", False),
        ("npm", "^4.0.0-0 <4.5.0", "4.0.0-beta.3", True),
        ("npm", "^4.0.0-0 <4.5.0", "4.1.0-beta.3", False),
        ("npm", "=4.0.0", "4.0.0+build.2", True),
        ("conda", "=2.1.*", "2.1.1", True),
        ("conda", "==2.1.*", "2.0.0", False),
        ("conda", "=2.1=py312_0", "2.0.0", False),
        ("conda", "=2.1=py312_0", "2.1.1", False),
        ("conda", "=2.1=py312_0", "2.1.0", None),
        ("conda", "==2.1=py312_0", "2.1.1", False),
        ("conda", "=2.1.*=py312_0", "2.1.1", None),
        ("conda", ">2.1", "2.1.0.post1", True),
        ("conda", "<2.2", "2.2.0rc1", True),
        ("conda", ">2.1", "2.1.0+cu118", True),
    ],
)
def test_version_requirement_uses_package_manager_ordering(
    ecosystem, requirement, supplied, satisfies
):
    assert _satisfies_nested_requirement(ecosystem, requirement, supplied) is satisfies


@pytest.mark.parametrize(
    ("version", "expected"), [("2.0.0", (1, 0)), ("2.1.1", (1, 0)), ("2.1.0", (0, 1))]
)
def test_conda_manifest_preserves_build_pin_evidence(tmp_path, version, expected):
    nested = tmp_path / "worker"
    nested.mkdir()
    (nested / "environment.yml").write_text("dependencies:\n  - langchain=2.1=py312_0\n")
    components, failures = walk_nested_manifests(tmp_path)
    assert not failures and len(components) == 1
    path = tmp_path / "supplier.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [{"type": "library", "name": "langchain", "version": version}],
            }
        )
    )
    report = import_foreign_sbom(path, target_aibom=AIBOM(components=components))
    assert (report.conflict_count, report.unresolved_conflict_count) == expected


def _package_url(version, qualifiers):
    return PackageURL(
        type="npm", namespace="@example", name="widget", version=version, qualifiers=qualifiers
    ).to_string()


def _supplier(path, version, qualifiers):
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [
                    {
                        "type": "library",
                        "name": "widget",
                        "purl": _package_url(version, qualifiers),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    "qualifiers", [{"repository_url": "https://mirror.example.test"}, {"platform": "sample"}]
)
@pytest.mark.parametrize(("version", "expected"), [("1.2.3", (0, 1)), ("1.4.0", (1, 0))])
def test_package_provenance_difference_is_reported(tmp_path, qualifiers, version, expected):
    local = RegistryEntryComponent(
        bom_ref="registry:widget",
        name="@example/widget",
        version="1.2.3",
        registry_type="npm",
        package_url=_package_url("1.2.3", {"repository_url": "https://packages.example.test"}),
    )
    path = _supplier(tmp_path / "supplier.json", version, qualifiers)
    report = import_foreign_sbom(path, target_aibom=AIBOM(components=[local]))
    assert (report.conflict_count, report.unresolved_conflict_count) == expected


def test_keyed_provenance_survives_reimport_of_hidden_inventory(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "s" * 40)
    first = _supplier(
        tmp_path / "first.json", "1.2.3", {"repository_url": "https://packages.example.test"}
    )
    hidden = AIBOM.model_validate_json(import_foreign_sbom(first).aibom.to_json())
    second = _supplier(
        tmp_path / "second.json", "1.2.3", {"repository_url": "https://mirror.example.test"}
    )
    report = import_foreign_sbom(second, target_aibom=hidden)
    assert report.conflict_count == 0
    assert report.unresolved_conflict_count == 1


def test_displayed_purl_withholds_credentials_in_encoded_locator(tmp_path):
    marker = hashlib.sha256(b"public test fixture value").hexdigest()[:24]
    locator = quote(f"https://sample:{marker}@packages.example.test/npm", safe="")
    path = _supplier(
        tmp_path / "supplier.json", "1.2.3", {"repository_url": locator, "arch": "x64"}
    )
    inventory = import_foreign_sbom(path, reveal_names=True).aibom
    assert marker not in inventory.to_json()
    component = inventory.components[-1]
    assert isinstance(component, RegistryEntryComponent)
    assert component.package_url and "arch=x64" in component.package_url
