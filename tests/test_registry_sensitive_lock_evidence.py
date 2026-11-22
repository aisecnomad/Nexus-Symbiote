"""Lock evidence remains visible when a manifest or record contains a private identifier."""

import json

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner
from tests.test_npm_lockfile_staleness_and_precedence import _pnpm_lock
from tests.test_registry_free_text_redaction import GITLAB, TOKEN


@pytest.mark.parametrize("scope", ["dependencies", "peerDependencies"])
def test_sensitive_npm_declaration_preserves_independent_lock_findings(tmp_path, scope):
    manifest = {"dependencies": {"openai": "4.0.0"}, scope: {"openai": TOKEN}}
    record = {
        "version": "4.0.0",
        "resolved": "https://mirror.example/openai/-/openai-5.0.0.tgz",
    }
    (tmp_path / "package.json").write_text(json.dumps(manifest))
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {"lockfileVersion": 3, "packages": {"": manifest, "node_modules/openai": record}}
        )
    )
    result = RegistryScanner().scan(tmp_path)
    (component,) = result.components
    assert {
        "credential_exposure",
        "lockfile_resolution_mismatch",
        "missing_lockfile_integrity",
        "registry_origin",
    } <= {r.category for r in component.risks}
    assert TOKEN not in component.model_dump_json()


def test_sensitive_yarn_version_preserves_record_findings(tmp_path):
    version = "4.0.0-" + GITLAB
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"openai": "^4"}}))
    (tmp_path / "yarn.lock").write_text(
        f'# yarn lockfile v1\n\n"openai@^4":\n  version "{version}"\n'
        '  resolved "https://mirror.example/openai/-/openai-5.0.0.tgz"\n'
    )
    (component,) = RegistryScanner().scan(tmp_path).components
    assert {
        "credential_exposure",
        "missing_lockfile_integrity",
        "lockfile_resolution_mismatch",
        "registry_origin",
    } <= {r.category for r in component.risks}
    assert component.package_url is None and GITLAB not in component.model_dump_json()


def test_sensitive_pip_spec_keeps_its_hash_and_lock_comparison(tmp_path):
    digest = "sha256:" + "a" * 64
    (tmp_path / "requirements.txt").write_text(f"openai==1.0.0+{TOKEN} --hash={digest}\n")
    (tmp_path / "uv.lock").write_text('[[package]]\nname="openai"\nversion="2.0.0"')
    result = RegistryScanner().scan(tmp_path)
    (component,) = result.components
    assert (
        "uv.lock: selected package version disagrees with requirements.txt" in result.scan_failures
    )
    assert component.properties["requirement_hashes"] == [f"requirements.txt: {digest}"]
    assert TOKEN.casefold() not in component.model_dump_json().casefold()


def test_sensitive_python_lock_version_keeps_the_cleartext_origin_finding(tmp_path):
    version = "1.0.0+" + TOKEN
    (tmp_path / "requirements.txt").write_text("openai>=1")
    (tmp_path / "uv.lock").write_text(
        f'[[package]]\nname="openai"\nversion="{version}"\nsource={{registry="http://mirror.example/simple"}}'
    )
    (component,) = RegistryScanner().scan(tmp_path).components
    assert any(r.category == "registry_origin" and r.severity == "high" for r in component.risks)
    assert (
        component.package_url is None
        and TOKEN.casefold() not in component.model_dump_json().casefold()
    )


def test_pnpm_compares_the_selected_raw_spec_even_if_it_is_redacted(tmp_path):
    spec = "1.0.0-" + GITLAB
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"openai": spec}}))
    (tmp_path / "pnpm-lock.yaml").write_text(_pnpm_lock(spec, "2.0.0"))
    result = RegistryScanner().scan(tmp_path)
    (component,) = result.components
    assert (
        "pnpm-lock.yaml: selected package version disagrees with package.json"
        in result.scan_failures
    )
    assert GITLAB not in component.model_dump_json()
