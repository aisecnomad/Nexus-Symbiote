"""Registry identities derived from versions and alternative package indexes."""

import json

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.utils.secrets import holds_token_shape
from tests.support import scaling_ratio
from tests.test_npm_lockfile_staleness_and_precedence import _pnpm_lock
from tests.test_registry_free_text_redaction import GITLAB, TOKEN


@pytest.mark.parametrize("source", ["requirements", "uv", "npm", "npm-lock", "pnpm", "yarn"])
def test_a_credential_in_a_version_never_becomes_an_exported_identity(tmp_path, source):
    sentinel = TOKEN if source in {"requirements", "uv"} else GITLAB
    version = "1.0.0+" + sentinel
    if source in {"requirements", "uv"}:
        spec = f"=={version}" if source == "requirements" else ">=1"
        (tmp_path / "requirements.txt").write_text("openai" + spec)
        if source == "uv":
            (tmp_path / "uv.lock").write_text(f'[[package]]\nname="openai"\nversion="{version}"')
    else:
        spec = version if source == "npm" else "^1.0.0"
        manifest = {"dependencies": {"openai": spec}}
        (tmp_path / "package.json").write_text(json.dumps(manifest))
        if source == "npm-lock":
            records = {"": manifest, "node_modules/openai": {"version": version}}
            (tmp_path / "package-lock.json").write_text(
                json.dumps({"lockfileVersion": 3, "packages": records})
            )
        elif source == "pnpm":
            (tmp_path / "pnpm-lock.yaml").write_text(_pnpm_lock(spec, version))
        elif source == "yarn":
            (tmp_path / "yarn.lock").write_text(
                f'# yarn lockfile v1\n\n"openai@{spec}":\n  version "{version}"\n'
            )
    result = RegistryScanner().scan(tmp_path)
    (component,) = result.components
    assert component.package_url is None
    assert sentinel.casefold() not in component.model_dump_json().casefold()
    assert any(
        r.category == "credential_exposure" and r.severity == "high" for r in component.risks
    )


def test_untranslated_poetry_condition_cannot_inherit_public_registry_origin(tmp_path):
    mirror = "https://mirror.example/simple"
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\nopenai = { version = "^1.0", python = ">=3.9" }\n'
        f'[[tool.poetry.source]]\nname = "mirror"\nurl = "{mirror}"\n'
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "openai"\nversion = "1.30.0"\n'
        f'source = {{ type = "legacy", url = "{mirror}", reference = "mirror" }}'
    )
    (component,) = RegistryScanner().scan(tmp_path).components
    assert component.package_url is None
    assert component.registry_uri is None
    assert any(r.category == "registry_origin" for r in component.risks)


def test_two_python_lockfiles_cannot_confirm_a_manifest_only_identity(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai==1.0.0")
    for name in ("uv.lock", "poetry.lock"):
        (tmp_path / name).write_text('[[package]]\nname = "openai"\nversion = "1.0.0"')
    result = RegistryScanner().scan(tmp_path)
    (component,) = result.components
    assert any("multiple Python lockfiles" in reason for reason in result.surfaces_excluded)
    assert component.package_url is None and component.registry_uri is None


@pytest.mark.parametrize(
    "selected", ["https://mirror.example/pkg.tgz", "git+https://mirror.example/pkg", "localorg/pkg"]
)
def test_yarn_classic_records_the_nonregistry_source_its_manifest_selects(tmp_path, selected):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"openai": selected}, "devDependencies": {"openai": "1.0.0"}})
    )
    (tmp_path / "yarn.lock").write_text(
        f'# yarn lockfile v1\n\n"openai@{selected}":\n  version "1.0.0"\n'
    )
    result = RegistryScanner().scan(tmp_path)
    (component,) = result.components
    assert component.package_url is None and component.registry_uri is None
    assert any(r.category == "nonregistry_source" for r in component.risks)
    assert any("non-registry" in gap for gap in result.surfaces_excluded)


@pytest.mark.parametrize("prefix", ["sk-", "eyJ"])
def test_incomplete_token_prefixes_in_names_take_linear_work(prefix):
    names = {scale: prefix * (750 * scale) for scale in (1, 4)}
    assert not holds_token_shape(names[4])
    assert scaling_ratio(lambda scale: holds_token_shape(names[scale])) < 10
