"""Verify lock matching and credential redaction with synthetic package identifiers."""

import hashlib

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.registry import RegistryScanner, _identifier
from nexus_symbiote.utils.secrets import holds_token_shape


@pytest.mark.parametrize("extra", [False, True])
@pytest.mark.parametrize("matches", [False, True])
def test_benign_name_or_extra_preserves_uv_lock_comparison(tmp_path, extra, matches):
    label = "flask-sqlalchemy-2-0-compat"
    package = "openai" if extra else f"langchain-{label}"
    declared = f"{package}[{label}]" if extra else package
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text(f"{declared}==1.29.0\n")
    version = "1.29.0" if matches else "1.30.0"
    (project / "uv.lock").write_text(
        f'[[package]]\nname = "{package}"\nversion = "{version}"\n'
        'source = {registry = "https://pypi.org/simple"}\n'
    )
    result = RegistryScanner().scan(project)
    [component] = result.components
    assert component.name == package
    assert not any(r.category == "credential_exposure" for r in component.risks)
    assert any("selected package version disagrees" in f for f in result.scan_failures) is (
        not matches
    )
    if matches:
        assert component.package_url == f"pkg:pypi/{package}@{version}"
    gate = CliRunner().invoke(
        main, ["--detailed-exit-codes", "scan", str(project), "--check", "--no-project-policy"]
    )
    assert gate.exit_code == (0 if matches else 4), gate.output


@pytest.mark.parametrize("prefix", ["build", "sample_", "-"])
def test_distinctive_project_key_is_private_inside_identifiers(prefix):
    body = hashlib.sha256(b"synthetic registry test fixture").hexdigest()
    value = prefix + "-".join(("sk", "proj", body))
    assert holds_token_shape(value, require_sk_boundary=True)
    shown, removed = _identifier(value)
    assert removed and body not in shown
