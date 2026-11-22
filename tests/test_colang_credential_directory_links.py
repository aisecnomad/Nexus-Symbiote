"""Inert rail text cannot supply a digest through a link into a credential store."""

import hashlib

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import GuardrailComponent
from nexus_symbiote.scanners.rag import RAGScanner


@pytest.mark.parametrize("directory", [".aws", ".SSH", "nested/vault", ".gnupg", ".kube"])
@pytest.mark.parametrize("alias", ["db_password.co", "policy.co"])
def test_rail_link_into_a_credential_store_is_withheld(tmp_path, directory, alias):
    project = tmp_path / "project"
    rails = project / "nemo"
    rails.mkdir(parents=True)
    (rails / "config.yml").write_text("rails: {}\n")
    (rails / "main.co").write_text("define flow welcome\n")
    target = project / directory / "db_password.co"
    target.parent.mkdir(parents=True)
    contents = b"define flow synthetic_configuration\n"
    target.write_bytes(contents)
    (rails / alias).symlink_to("../" + directory + "/" + target.name)

    scan = RAGScanner().scan(project)
    [rail] = [c for c in scan.components if isinstance(c, GuardrailComponent)]
    assert alias not in rail.properties["rail_files"]
    assert "main.co" in rail.properties["rail_files"]
    assert scan.surfaces_excluded
    inventory = tmp_path / "inventory.json"
    run = CliRunner().invoke(
        main,
        [
            "--detailed-exit-codes",
            "scan",
            str(project),
            "--no-project-policy",
            "-o",
            str(inventory),
        ],
    )
    assert run.exit_code == 3, run.output
    assert hashlib.sha256(contents).hexdigest() not in inventory.read_text()


@pytest.mark.parametrize("directory", ["shared", "vault-tools", "ssh-handlers"])
def test_same_named_executable_rail_in_a_source_directory_remains_visible(tmp_path, directory):
    rails = tmp_path / "nemo"
    rails.mkdir()
    (rails / "config.yml").write_text("rails: {}\n")
    source = tmp_path / directory
    source.mkdir()
    data = b"define flow ordinary_example\n"
    (source / "check_secrets.co").write_bytes(data)
    (rails / "check_secrets.co").symlink_to("../" + directory + "/check_secrets.co")
    scan = RAGScanner().scan(tmp_path)
    [rail] = [c for c in scan.components if isinstance(c, GuardrailComponent)]
    assert (
        rail.properties["rail_files"]["check_secrets.co"]
        == "sha256:" + hashlib.sha256(data).hexdigest()
    )
    assert not scan.surfaces_excluded
