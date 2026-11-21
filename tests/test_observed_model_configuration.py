"""Package policy and locally declared loading behavior are independent observations."""

import hashlib
import json

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.evidence_profile import build_evidence_profile
from nexus_symbiote.scanners.model import ModelPackages
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.crypto import DigestPinPolicy, SignaturePolicySet
from tests.test_model_integrity import write_safetensors


@pytest.mark.parametrize("declared", [False, True, None])
def test_local_model_config_contributes_one_critical_finding(tmp_path, declared):
    artifacts = []
    for directory, remote in (("reviewed", True), ("sibling", False)):
        folder = tmp_path / directory
        folder.mkdir()
        (folder / "config.json").write_text(
            json.dumps(
                {"trust_remote_code": remote, "auto_map": {"AutoModel": "modeling_example.Example"}}
            )
        )
        (folder / "modeling_example.py").write_text('"""An inert marker used by the test."""\n')
        path = folder / "weights.safetensors"
        write_safetensors(path)
        digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        model = ModelComponent(
            bom_ref="model:" + directory,
            name=directory,
            source_path=path.relative_to(tmp_path).as_posix(),
            hashes={"sha256": digest},
            trust_remote_code=declared if remote else False,
        )
        artifacts.append((model, DigestPinPolicy(path, digest)))
    policy = SignaturePolicySet(digest_pins=[pin for _, pin in artifacts])
    report = build_evidence_profile(
        AIBOM(components=[m for m, _ in artifacts]),
        project_root=tmp_path,
        signature_policies=policy,
    )
    reviewed, sibling = report["components"]
    assert (
        reviewed["evidence"]["digest_pinned_under_policy"]
        and sibling["evidence"]["digest_pinned_under_policy"]
    )
    assert reviewed["integrity_findings"] == [
        {"category": "trust_remote_code", "severity": "critical"}
    ]
    assert reviewed["finding_count"] == 1
    assert sibling["finding_count"] == 0
    assert not report["policy_verified"]


@pytest.mark.parametrize("mode", ["inconsistent", "malformed", "withheld"])
def test_local_loading_behavior_uses_confined_collector_config_rules(tmp_path, mode):
    artifact = tmp_path / "weights.safetensors"
    write_safetensors(artifact)
    config = tmp_path / "config.json"
    if mode == "malformed":
        config.write_text('{"trust_remote_code": "yes"}')
    elif mode == "withheld":
        another = tmp_path / ".env"
        another.write_text('{"trust_remote_code": true}')
        config.symlink_to(another.name)
    else:
        config.write_text('{"trust_remote_code": false}')
        (tmp_path / "tokenizer_config.json").write_text('{"trust_remote_code": true}')
    package = ModelPackages(tmp_path).observe(artifact.relative_to(tmp_path))
    assert package.loading_config_complete is (mode == "inconsistent")
    assert package.trust_remote_code is (True if mode == "inconsistent" else None)


@pytest.mark.parametrize("remote_code", [False, True])
def test_validation_observes_one_in_root_config_link(tmp_path, remote_code):
    model = tmp_path / "model"
    model.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "base.json").write_text(json.dumps({"trust_remote_code": remote_code}))
    (model / "config.json").symlink_to("../shared/base.json")
    artifact = model / "weights.safetensors"
    write_safetensors(artifact)

    package = ModelPackages(tmp_path).observe(artifact.relative_to(tmp_path))
    assert package.complete
    assert package.loading_config_complete
    assert package.trust_remote_code is remote_code


def test_config_link_cannot_change_its_checked_target(tmp_path, monkeypatch):
    (tmp_path / "settings.json").write_text('{"trust_remote_code": false}')
    (tmp_path / ".env").write_text('{"trust_remote_code": true}')
    config = tmp_path / "config.json"
    config.symlink_to("settings.json")
    artifact = tmp_path / "weights.safetensors"
    write_safetensors(artifact)
    original = ConfinedCollection.in_root_target

    def retarget(self, path):
        target = original(self, path)
        if path.name == "config.json":
            config.unlink()
            config.symlink_to(".env")
        return target

    monkeypatch.setattr(ConfinedCollection, "in_root_target", retarget)
    package = ModelPackages(tmp_path).observe(artifact.relative_to(tmp_path))
    assert not package.loading_config_complete
    assert package.trust_remote_code is None
