"""Registry inputs that are, or lead to, credential files are gaps, never read."""

from __future__ import annotations

import hashlib
import json
import secrets
import string
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.generators import CycloneDXGenerator, SPDXGenerator
from nexus_symbiote.scanners.registry import RegistryScanner


def _value(length: int = 40) -> str:
    # Random, so no fixture can be token-shaped by accident or by design.
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


def _everything(root: Path) -> str:
    result = RegistryScanner().scan(root)
    bom = AIBOM()
    for component in result.components:
        bom.add_component(component)
    return "\n".join(
        [
            json.dumps([c.model_dump(mode="json") for c in result.components]),
            json.dumps(result.scan_failures + result.surfaces_excluded),
            CycloneDXGenerator().generate_json(bom),
            SPDXGenerator().generate_json(bom),
        ]
    )


@pytest.mark.parametrize(
    "name", ["requirements-dev.txt", "requirements.txt", "package-lock.json", "poetry.lock"]
)
def test_a_registry_input_that_links_to_dotenv_is_a_gap_and_is_not_read(
    tmp_path: Path, name: str
) -> None:
    value = _value()
    (tmp_path / ".env").write_text(f"COHERE_API_KEY={value}\nOPENAI_ORG=org-{value[:12]}\n")
    # Declarations that make the collector consult each lockfile.
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.52.0"}}')
    if name != "requirements.txt":
        (tmp_path / "requirements.txt").write_text("openai==1.0.0\n")
    (tmp_path / name).symlink_to(".env")
    result = RegistryScanner().scan(tmp_path)
    assert f"{name}: a symlink leads to .env, whose name says it holds credentials; " in "\n".join(
        result.surfaces_excluded
    )
    text = _everything(tmp_path)
    assert value not in text
    assert value[:12] not in text


def test_an_invalid_requirement_is_redacted_before_its_name_is_removed(tmp_path: Path) -> None:
    # The name is what marks the value as a credential; cutting it off first left the
    # value to the token shapes alone.
    value = _value(12)
    (tmp_path / "requirements.txt").write_text(f"transformers_token={value}\nopenai==1.0.0\n")
    text = _everything(tmp_path)
    assert value not in text


def test_a_package_json_that_links_to_a_credential_file_is_a_gap(tmp_path: Path) -> None:
    (tmp_path / "secrets.json").write_text('{"dependencies":{"openai":"4.52.0"}}')
    (tmp_path / "package.json").symlink_to("secrets.json")
    result = RegistryScanner().scan(tmp_path)
    assert result.components == []
    assert any(
        entry.startswith("package.json: a symlink leads to secrets.json")
        for entry in (result.surfaces_excluded)
    )


@pytest.mark.parametrize("target", ["prod.env", "app.env", "prod.env.local", "secrets.env.example"])
def test_requirements_that_link_to_a_named_env_file_are_a_gap(tmp_path: Path, target: str) -> None:
    value = _value(12)
    (tmp_path / target).write_text(f"openai_org=org-{value}\n")
    (tmp_path / "requirements.txt").symlink_to(target)
    result = RegistryScanner().scan(tmp_path)
    assert any(
        entry.startswith(f"requirements.txt: a symlink leads to {target}")
        for entry in (result.surfaces_excluded)
    )
    assert value not in _everything(tmp_path)


def test_an_npmrc_that_links_to_another_credential_file_is_a_gap(tmp_path: Path) -> None:
    # .npmrc is read by its own name for its registry settings only; a link to .env is
    # not the npm configuration it is read for.
    value = _value()
    (tmp_path / ".env").write_text(f"registry=https://npm.example/\nOPENAI_KEY=sk-{value}\n")
    (tmp_path / ".npmrc").symlink_to(".env")
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.52.0"}}')
    result = RegistryScanner().scan(tmp_path)
    assert any(
        entry.startswith(".npmrc: a symlink leads to .env") for entry in (result.surfaces_excluded)
    )
    assert ".npmrc" not in result.surfaces_scanned
    assert value not in _everything(tmp_path)


def test_an_npmrc_linked_from_a_secrets_folder_is_read_as_npmrc_without_its_values(
    tmp_path: Path,
) -> None:
    # The link names an .npmrc, so its registry settings are read as the file's own are;
    # neither its credential nor a digest of the file is recorded.
    value = _value()
    (tmp_path / "secrets").mkdir()
    npmrc = f"registry=https://npm.example/\n//npm.example/:_authToken={value}\n"
    (tmp_path / "secrets" / ".npmrc").write_text(npmrc)
    (tmp_path / ".npmrc").symlink_to("secrets/.npmrc")
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.52.0"}}')
    result = RegistryScanner().scan(tmp_path)
    assert ".npmrc" in result.surfaces_scanned
    (component,) = result.components
    assert component.properties["package_sources"] == [".npmrc:registry=https://npm.example"]
    everything = _everything(tmp_path)
    assert value not in everything
    assert hashlib.sha256(npmrc.encode()).hexdigest() not in everything
