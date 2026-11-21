"""A digest proves byte identity even when the local format permits unsafe loading."""

import hashlib
import zipfile

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.evidence_profile import build_evidence_profile
from nexus_symbiote.utils.crypto import DigestPinPolicy, SignaturePolicySet
from nexus_symbiote.validators import integrity


@pytest.mark.parametrize("issue_limit", [0, 1000])
@pytest.mark.parametrize("already_declared", [False, True])
def test_verified_model_bytes_keep_their_observed_format_finding(
    tmp_path, monkeypatch, issue_limit, already_declared
):
    monkeypatch.setattr(integrity, "MAX_REPORTED_ISSUES", issue_limit)
    artifact = tmp_path / "weights.pt"
    with zipfile.ZipFile(artifact, "w") as archive:
        # The archive contains only a serialized None. The container format is the risk.
        archive.writestr("archive/data.pkl", b"\x80\x04N.")
    digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    model = ModelComponent(
        bom_ref="model:sample",
        name="sample",
        source_path=artifact.name,
        hashes={"sha256": digest},
        serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION
        if already_declared
        else SerializationSafety.UNKNOWN,
    )
    policy = SignaturePolicySet(digest_pins=[DigestPinPolicy(artifact, digest)])
    report = build_evidence_profile(
        AIBOM(components=[model]), project_root=tmp_path, signature_policies=policy
    )
    (record,) = report["components"]
    assert record["evidence"]["digest_pinned_under_policy"]
    assert not report["policy_verified"]
    assert record["finding_count"] == 1
    assert record["highest_finding_severity"] == "critical"
    assert record["integrity_findings"] == [{"category": "unsafe_format", "severity": "critical"}]
