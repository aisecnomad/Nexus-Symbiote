"""Public approval verdicts for finite resources and explicit network grants."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import HumanInTheLoop
from nexus_symbiote.core.models import AgentComponent, AuthorizationRecord, CapabilityDeclaration
from nexus_symbiote.scanners.model import ModelPackages
from nexus_symbiote.utils.confined import ConfinedCollection
from tests.test_model_integrity import write_safetensors
from tests.test_trifecta_and_toxic_flows import _name_only_tools


@pytest.mark.parametrize(
    ("action", "scope", "critical"),
    [
        ("search", "web/*", True),
        ("get", "LOCALHOST/*", True),
        ("get", "intranet/items", True),
        ("read", "www/*", True),
        ("query", "ｗｅｂ/*", True),
        ("get", "127.0.0.1/*", True),
        ("get", "12345/*", True),
        ("get", "api.example.invalid/*", True),
        ("read", "http://example.invalid/items", True),
        ("read", "host:443/items", True),
        ("read", "/*", True),
        ("read", "*/*", True),
        ("read", "kb/../other", True),
        ("read", "arn:aws:s3:::*/*", True),
        ("read", "arn:aws:s3:::127.0.0.1/*", True),
        ("read", "arn:aws:s3:::kb-bucket/../other", True),
        ("write", "customers", True),
        ("read", "kb", False),
        ("list", "customers", False),
        ("query", "données/*", False),
        ("read", "kb/", False),
        ("read", "arn:aws:s3:::kb-bucket/*", False),
        ("read", "arn:aws-us-gov:s3:::kb-bucket/records/*", False),
        ("get", "kb/*", False),
    ],
)
def test_named_read_and_network_scopes_in_the_cli(tmp_path, action, scope, critical):
    tools = _name_only_tools()
    owner = AgentComponent(
        bom_ref="agent:owner",
        name="owner",
        tool_refs=[tool.bom_ref for tool in tools],
        capabilities=CapabilityDeclaration(human_in_the_loop=HumanInTheLoop.REQUIRED),
        authorizations=[
            AuthorizationRecord(
                principal="reviewer", action=action, resource_scope=scope, approval_required=False
            )
        ],
    )
    path = tmp_path / "inventory.json"
    AIBOM(components=[owner, *tools]).save(path)
    result = CliRunner().invoke(main, ["trifecta", str(path)])
    assert result.exit_code == int(critical), result.output
    finding = next(
        item
        for item in json.loads(result.output)["findings"]
        if item["kind"] == "lethal_trifecta" and item["scope_ref"] == owner.bom_ref
    )
    assert finding["severity"] == ("critical" if critical else "high")
    if not critical:
        assert "enforcement is unverified" in finding["summary"]


def test_a_stale_ordinary_config_identity_leaves_the_observation_incomplete(tmp_path, monkeypatch):
    (tmp_path / "settings.json").write_text('{"trust_remote_code": false}')
    (tmp_path / "settings2.json").write_text('{"trust_remote_code": true}')
    (tmp_path / "config.json").symlink_to("settings2.json")
    write_safetensors(tmp_path / "weights.safetensors")
    actual_target = ConfinedCollection.in_root_target

    def observed_target(self, path):
        if path.name == "config.json":
            return Path("settings.json")
        return actual_target(self, path)

    monkeypatch.setattr(ConfinedCollection, "in_root_target", observed_target)
    observed = ModelPackages(tmp_path).observe(Path("weights.safetensors"))
    assert not observed.loading_config_complete
    assert observed.trust_remote_code is None
