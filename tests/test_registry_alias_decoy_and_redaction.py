"""Adversarial regression tests for PR #322 alias spoofing and sensitive registry URI redaction."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner

_INTEGRITY = "sha512-" + base64.b64encode(hashlib.sha512(b"fixture-tarball").digest()).decode()


@pytest.mark.parametrize("alias_spec", ["npm:evil-pkg", "npm:@evil/pkg", "npm:evil-pkg@1.0.0"])
def test_yarn_v1_dev_dependency_decoy_cannot_spoof_aliased_identity(
    tmp_path: Path, alias_spec: str
) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"openai": alias_spec},
                "devDependencies": {"openai": "4.0.0"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "yarn.lock").write_text(
        "# yarn lockfile v1\n\n"
        f'"openai@{alias_spec}":\n'
        '  version "1.0.0"\n'
        '  resolved "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"\n'
        f"  integrity {_INTEGRITY}\n",
        encoding="utf-8",
    )

    result = RegistryScanner().scan(tmp_path)
    comp = next(c for c in result.components if c.name == "openai")
    assert comp.package_url is None
    assert comp.registry_uri is None
    assert any("aliased package identity is unresolved" in g for g in result.surfaces_excluded)


def test_pnpm_dev_dependency_decoy_cannot_spoof_aliased_identity(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"openai": "npm:evil-pkg@1.0.0"},
                "devDependencies": {"openai": "4.0.0"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      openai:\n"
        "        specifier: 'npm:evil-pkg@1.0.0'\n"
        "        version: '1.0.0'\n"
        "packages:\n"
        "  openai@1.0.0:\n"
        "    resolution:\n"
        f"      integrity: {_INTEGRITY}\n",
        encoding="utf-8",
    )

    result = RegistryScanner().scan(tmp_path)
    comp = next(c for c in result.components if c.name == "openai")
    assert comp.package_url is None
    assert comp.registry_uri is None
    assert any("aliased package identity is unresolved" in g for g in result.surfaces_excluded)


def test_sensitive_npm_lockfile_resolution_keeps_registry_uri_redacted(tmp_path: Path) -> None:
    secret_token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"openai": f"1.0.0-{secret_token}"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"openai": f"1.0.0-{secret_token}"}},
                    "node_modules/openai": {
                        "version": f"1.0.0-{secret_token}",
                        "resolved": (
                            f"https://registry.example.test/openai/-/openai-1.0.0-{secret_token}.tgz"
                        ),
                        "integrity": _INTEGRITY,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    result = RegistryScanner().scan(tmp_path)
    comp = next(c for c in result.components if c.name == "openai")
    assert comp.package_url is None
    assert comp.registry_uri is None
    assert secret_token not in comp.model_dump_json()
