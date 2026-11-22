"""Public resolution claims only identify the dependency the manifest selected."""

import json

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner
from tests.test_npm_lockfile_staleness_and_precedence import INTEGRITY, _pnpm_lock
from tests.test_registry_credential_links import _everything
from tests.test_registry_free_text_redaction import TOKEN


@pytest.mark.parametrize("berry", [False, True])
@pytest.mark.parametrize("prefix", ["password=", "Bearer ", "api_key="])
def test_private_selector_is_omitted_from_yarn_evidence(tmp_path, prefix, berry):
    marker = "EXAMPLE_ONLY_SELECTOR_1234567890"
    spec = prefix + marker
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"openai": spec}}))
    if berry:
        lock = (
            f'__metadata:\n  version: 8\n\n"openai@npm:{spec}":\n'
            '  version: 4.0.0\n  resolution: "openai@npm:4.0.0"\n'
        )
    else:
        lock = (
            f'# yarn lockfile v1\n\n"openai@{spec}":\n  version "4.0.0"\n'
            '  resolved "https://registry.npmjs.org/openai/-/openai-4.0.0.tgz"\n'
        )
    (tmp_path / "yarn.lock").write_text(lock)
    (component,) = RegistryScanner().scan(tmp_path).components
    assert marker not in _everything(tmp_path)
    assert component.claims["package_resolution"].locator == "yarn.lock"
    assert component.properties["lockfile_record"] == "yarn.lock"
    assert "missing_lockfile_integrity" in {risk.category for risk in component.risks}


@pytest.mark.parametrize(
    "spec",
    [
        "file:./fixtures/sample",
        "github:example/sample",
        "https://packages.example.invalid/sample.tgz",
    ],
)
def test_selected_nonregistry_pnpm_source_has_no_registry_claim(tmp_path, spec):
    manifest = {"optionalDependencies": {"openai": spec}, "devDependencies": {"openai": "4.0.0"}}
    (tmp_path / "package.json").write_text(json.dumps(manifest))
    (tmp_path / "pnpm-lock.yaml").write_text(_pnpm_lock(spec, "4.1.0"))
    result = RegistryScanner().scan(tmp_path)
    (component,) = result.components
    assert any("selected non-registry source" in gap for gap in result.surfaces_excluded)
    assert "nonregistry_source" in {risk.category for risk in component.risks}
    assert component.registry_uri is None and component.package_url is None
    assert "package_resolution" not in component.claims


def test_unbound_pnpm_source_keeps_independent_integrity_error(tmp_path):
    spec = "file:./fixtures/sample"
    manifest = {"optionalDependencies": {"openai": spec}, "devDependencies": {"openai": "4.0.0"}}
    (tmp_path / "package.json").write_text(json.dumps(manifest))
    lock = _pnpm_lock(spec, "4.1.0")
    (tmp_path / "pnpm-lock.yaml").write_text(lock.replace(INTEGRITY, "invalid"))
    result = RegistryScanner().scan(tmp_path)
    assert any("invalid selected package integrity" in failure for failure in result.scan_failures)
    assert any("selected non-registry source" in gap for gap in result.surfaces_excluded)


def test_redacted_marker_preserves_conditional_python_identity_and_origin_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text(f'openai>=1; platform_release == "{TOKEN}"\n')
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname="openai"\nversion="1.0.0"\nsource={registry="http://mirror.example.invalid/simple"}\n'
    )
    (component,) = RegistryScanner().scan(tmp_path).components
    assert component.properties["collection_mode"] == "manifest-reference"
    assert "package_resolution" not in component.claims
    assert component.package_url is None and TOKEN not in component.model_dump_json()
    assert any(r.category == "registry_origin" and r.severity == "high" for r in component.risks)
