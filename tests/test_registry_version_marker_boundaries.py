"""Ordinary dependency labels and private marker values retain distinct evidence."""

import json

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.utils.secrets import holds_token_shape
from tests.test_npm_lockfile_staleness_and_precedence import _pnpm_lock
from tests.test_registry_credential_links import _everything
from tests.test_registry_free_text_redaction import GITLAB, TOKEN


def test_a_later_delimited_generic_shape_is_still_private():
    word = "task-runner-build-2024-01"
    synthetic = "-".join(("sk", "EXAMPLE_ONLY_1234567890123456"))
    assert not holds_token_shape(word, require_sk_boundary=True)
    assert holds_token_shape(word + "-" + synthetic, require_sk_boundary=True)
    assert holds_token_shape("prefix" + TOKEN, require_sk_boundary=True)


@pytest.mark.parametrize("label", ["flask-sqlalchemy-2-0-compat", "task-runner-v2-build-2024"])
def test_marker_word_suffix_is_not_a_credential(tmp_path, label):
    (tmp_path / "requirements.txt").write_text(f'openai==1.30.0; extra == "{label}"\n')
    (tmp_path / "uv.lock").write_text('[[package]]\nname="openai"\nversion="1.30.0"')
    (component,) = RegistryScanner().scan(tmp_path).components
    assert label in component.version
    assert component.properties["collection_mode"] == "manifest-reference"
    assert not any(r.category == "credential_exposure" for r in component.risks)


def test_marker_is_checked_before_extra_normalization(tmp_path):
    (tmp_path / "requirements.txt").write_text(f'openai==1.30.0; extra == "{TOKEN}"\n')
    (component,) = RegistryScanner().scan(tmp_path).components
    assert TOKEN.lower().replace("_", "-") not in _everything(tmp_path).lower()
    assert any("environment marker" in r.detail for r in component.risks)
    assert component.package_url is None


@pytest.mark.parametrize("lock", ["yarn", "pnpm"])
@pytest.mark.parametrize("private", [False, True])
def test_exact_prerelease_keeps_its_identity_or_one_private_value_finding(tmp_path, lock, private):
    version = "4.0.0-" + (GITLAB if private else "task-runner-build-2024-01")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"openai": version}}))
    if lock == "pnpm":
        (tmp_path / "pnpm-lock.yaml").write_text(_pnpm_lock(version, version))
    else:
        (tmp_path / "yarn.lock").write_text(
            f'# yarn lockfile v1\n\n"openai@{version}":\n  version "{version}"\n'
        )
    (component,) = RegistryScanner().scan(tmp_path).components
    risks = [r for r in component.risks if r.category == "credential_exposure"]
    assert len(risks) == int(private)
    if private:
        assert GITLAB not in _everything(tmp_path)
        assert component.package_url is None
    else:
        assert component.version == version
        assert component.package_url == f"pkg:npm/openai@{version}"
