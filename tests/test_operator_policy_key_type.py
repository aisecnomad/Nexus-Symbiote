"""A trusted operator-policy key that loads as anything but Ed25519 is refused.

The loader already refuses other key types; these callers check again instead of casting,
so a loader that returns another object cannot reach the key ring unchecked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import nexus_symbiote.attestation_cli as attestation_cli
from nexus_symbiote import operator_policy


def test_the_operator_policy_gate_refuses_a_key_that_is_not_ed25519(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = tmp_path / "operator-policy.yaml"
    policy.write_text("version: '1.0'\n", encoding="utf-8")
    envelope = tmp_path / "operator-policy.att.json"
    envelope.write_text("{}", encoding="utf-8")
    keys = tmp_path / "keys"
    keys.mkdir()
    key = keys / "operator.pub"
    key.write_text("not a key", encoding="utf-8")
    monkeypatch.setattr(attestation_cli, "_load_trusted_public", lambda _path: object())

    with pytest.raises(operator_policy.OperatorPolicyError, match="only Ed25519 public keys"):
        operator_policy._verify_policy_attestation(
            policy.read_bytes(), policy, None, envelope, (key,)
        )


def test_the_staged_policy_gate_refuses_a_key_that_is_not_ed25519(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.verify_staged_policy as staged

    project = tmp_path / "project"
    project.mkdir()
    ops = tmp_path / "ops"
    ops.mkdir()
    policy = ops / "operator-policy.yaml"
    policy.write_text("version: '1.0'\n", encoding="utf-8")
    envelope = ops / "operator-policy.att.json"
    envelope.write_text("{}", encoding="utf-8")
    key = ops / "operator.pub"
    key.write_text("not a key", encoding="utf-8")
    monkeypatch.setattr(staged, "_load_trusted_public", lambda _path: object())
    if staged.POLICY_PURPOSE not in staged.get_args(staged.attestation.Purpose):
        pytest.fail("this tree's attestations have no policy purpose")

    code, out = staged.run_staged_gate(
        project, policy, attestation_source=envelope, trusted_keys=(key,)
    )

    assert code != 0
    assert "only Ed25519 public keys are supported" in out
