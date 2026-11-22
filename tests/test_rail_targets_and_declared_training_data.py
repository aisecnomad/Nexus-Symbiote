"""Verify scoped rail collection and typed training edges with inert project files."""

import hashlib

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import DataSourceComponent, GuardrailComponent, ModelComponent
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.spdx_profiles import apply_agent_yaml_declarations


@pytest.mark.parametrize(
    ("link", "target", "included"),
    [
        ("check_secrets.co", "shared/check_secrets.co", True),
        ("password_reset.co", "shared/password_reset.co", True),
        ("rotate-api-key.co", "shared/rotate-api-key.co", True),
        ("secrets.co", "shared/secrets.co", False),
        ("flow.co", "shared/.credential.co", False),
        ("check_secrets.co", "credentials/check_secrets.co", False),
        ("config.env.co", "shared/config.env.co", False),
        ("flow.co", "shared/check_secrets.txt", False),
        ("flow.co", "shared/service-credentials.co", False),
        ("flow.co", "shared/ordinary.co", True),
    ],
)
def test_linked_nemo_source_checks_the_resolved_file_in_rail_context(
    tmp_path, link, target, included
):
    rails = tmp_path / "nemo"
    rails.mkdir()
    (rails / "config.yml").write_text("rails: {}\n", encoding="utf-8")
    (rails / "main.co").write_text("define flow welcome\n", encoding="utf-8")
    resolved = tmp_path / target
    resolved.parent.mkdir()
    fixture = b"define flow sample\n"
    resolved.write_bytes(fixture)
    (rails / link).symlink_to("../" + target)

    result = RAGScanner().scan(tmp_path)
    [component] = [c for c in result.components if isinstance(c, GuardrailComponent)]
    files = component.properties["rail_files"]
    assert "main.co" in files and not result.scan_failures
    assert (link in files) is included
    assert bool(result.surfaces_excluded) is (not included)
    if included:
        assert files[link] == "sha256:" + hashlib.sha256(fixture).hexdigest()
        if link == resolved.name:
            assert credential_shaped(target)


@pytest.mark.parametrize("holder_type", [ModelComponent, DataSourceComponent])
def test_explicit_model_and_dataset_share_a_name_and_keep_the_training_edge(tmp_path, holder_type):
    (tmp_path / "agent.yaml").write_text(
        "datasets:\n  - name: sample-corpus\n    version: '1.0'\n"
        "models:\n  - name: sample-corpus\n    version: '2.0'\n"
        "    training:\n      datasets: [sample-corpus]\n",
        encoding="utf-8",
    )
    holder = holder_type(bom_ref="collected:sample", name="sample-corpus")
    bom = AIBOM(components=[holder])
    notices = apply_agent_yaml_declarations(bom, tmp_path)
    assert not notices
    [model] = [c for c in bom.components if isinstance(c, ModelComponent)]
    [dataset] = [c for c in bom.components if isinstance(c, DataSourceComponent)]
    assert (model.version, dataset.version) == ("2.0", "1.0")
    assert (model if holder_type is ModelComponent else dataset).bom_ref == holder.bom_ref
    assert [(edge.source_ref, edge.target_ref, edge.relationship) for edge in bom.dependencies] == [
        (model.bom_ref, dataset.bom_ref, "trained-on")
    ]


@pytest.mark.parametrize("field", ["version", "supplier"])
def test_conflicting_identity_still_reports_cross_type_declaration(tmp_path, field):
    found = ModelComponent(
        bom_ref="model:held", name="sample-corpus", version="1.0", supplier="Example"
    )
    (tmp_path / "agent.yaml").write_text(
        "datasets:\n  - name: sample-corpus\nmodels:\n  - name: sample-corpus\n"
        f"    {field}: 'other'\n",
        encoding="utf-8",
    )
    bom = AIBOM(components=[found])
    notices = apply_agent_yaml_declarations(bom, tmp_path)
    assert len(bom.components) == 1
    assert any("dataset name conflict" in item for item in notices)
    assert any(f"{field} conflict" in item for item in notices)
    assert not bom.dependencies
