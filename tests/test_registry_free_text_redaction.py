"""Marker operands, arbitrary-equality versions and Compose defaults are recorded redacted."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner

# Assembled at run time so the source holds no token-shaped literal.
TOKEN = "".join(("gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"))
ASSIGNMENT = "password=Secret4567"  # noqa: S105 - synthetic fixture
VALUES = {"token": TOKEN, "assignment": ASSIGNMENT}


def _scan(root: Path, filename: str, content: str):
    root.mkdir(parents=True, exist_ok=True)
    (root / filename).write_text(content)
    result = RegistryScanner().scan(root)
    text = json.dumps(
        [c.model_dump(mode="json") for c in result.components]
        + result.scan_failures
        + result.surfaces_excluded
    )
    return result, text


@pytest.mark.parametrize("shape", sorted(VALUES))
def test_quoted_marker_operands_are_redacted(tmp_path, shape):
    value = VALUES[shape]
    result, text = _scan(
        tmp_path, "requirements.txt", f'openai==1.0.0; sys_platform == "{value}"\n'
    )
    (component,) = [c for c in result.components if c.bom_ref == "registry:pypi/openai"]
    assert "Secret4567" not in text
    assert TOKEN not in text
    assert "***" in component.properties["requested_requirement"]


@pytest.mark.parametrize("shape", sorted(VALUES))
def test_arbitrary_equality_versions_are_redacted(tmp_path, shape):
    value = VALUES[shape]
    result, text = _scan(tmp_path, "requirements.txt", f"openai==={value}\n")
    (component,) = [c for c in result.components if c.bom_ref == "registry:pypi/openai"]
    assert "Secret4567" not in text
    assert TOKEN not in text
    assert component.version is not None and "***" in component.version
    assert component.package_url is None


@pytest.mark.parametrize("shape", sorted(VALUES))
def test_compose_variable_defaults_are_redacted(tmp_path, shape):
    value = VALUES[shape]
    result, text = _scan(
        tmp_path,
        "docker-compose.yml",
        f"services:\n  app:\n    image: ${{IMAGE:-reg.example/ollama/{value}:1}}\n",
    )
    (component,) = [c for c in result.components if c.bom_ref.startswith("registry:docker/")]
    assert "Secret4567" not in text
    assert TOKEN not in text
    assert "***" in component.name


GITLAB = "".join(("gl", "pat-", "Ab3Cd5Ef7Gh9Jk1Lm2Np"))


@pytest.mark.parametrize(
    "filename, content",
    [
        ("requirements.txt", f"openai[{TOKEN}]==1.0.0\n"),
        ("requirements.txt", f"openai-{GITLAB}==1.0.0\n"),
        ("requirements.txt", f"openai{TOKEN}==1.0.0\n"),
        ("Dockerfile", f"FROM ollama/ollama:{TOKEN}\n"),
        ("Dockerfile", f"FROM {GITLAB.lower()}.example.invalid/ollama:latest\n"),
        ("Dockerfile", f"FROM {GITLAB}.example.invalid/ollama:latest\n"),
    ],
    ids=["pypi-extra", "pypi-name", "pypi-name-glued", "oci-tag", "oci-host", "oci-host-mixed"],
)
def test_a_token_in_a_package_name_or_image_reference_is_redacted(tmp_path, filename, content):
    result, text = _scan(tmp_path, filename, content)
    (component,) = result.components
    assert TOKEN.lower() not in text.lower() and GITLAB.lower() not in text.lower()
    assert component.package_url is None and component.registry_uri is None
    assert "image_repository" not in component.properties
    assert "credential_exposure" in {r.category for r in component.risks}
