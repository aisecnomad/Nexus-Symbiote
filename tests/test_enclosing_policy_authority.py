"""A submodule marker cannot make its superproject an operator authority."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from nexus_symbiote.signature_policy import SignaturePolicyError, load_signature_policies


def git(root: Path, *args: str) -> str:
    executable = shutil.which("git", path=os.defpath)
    assert executable is not None
    return subprocess.run(  # noqa: S603 - fixed local fixture commands, never repository hooks
        [
            executable,
            "-C",
            str(root),
            "-c",
            "user.name=Policy fixture",
            "-c",
            "user.email=policy@example.invalid",
            "-c",
            "advice.addEmbeddedRepo=false",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    ).stdout


@pytest.fixture(params=["submodule", "nested"])
def nested_policy(tmp_path: Path, request: pytest.FixtureRequest):
    outer = tmp_path / "superproject"
    source = tmp_path / "source"
    outer.mkdir()
    source.mkdir()
    git(outer, "init", "--quiet")
    git(source, "init", "--quiet")
    (source / "model.bin").write_bytes(b"synthetic local model")
    git(source, "add", "model.bin")
    git(source, "commit", "--quiet", "-m", "model fixture")
    project = outer / "agent"
    if request.param == "submodule":
        git(
            outer,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--quiet",
            str(source),
            "agent",
        )
        assert (project / ".git").is_file()
    else:
        git(outer, "clone", "--quiet", str(source), "agent")
        assert (project / ".git").is_dir()
    record = {
        "kind": "digest-pin",
        "artifact_path": "model.bin",
        "expected_sha256": hashlib.sha256((project / "model.bin").read_bytes()).hexdigest(),
    }
    document = json.dumps({"version": 2, "artifacts": [record]})
    policy = outer / "operator-policy.json"
    policy.write_text(document)
    git(outer, "add", "agent", "operator-policy.json")
    if request.param == "submodule":
        git(outer, "add", ".gitmodules")
    git(outer, "commit", "--quiet", "-m", "policy and gitlink fixture")
    tree = git(outer, "ls-tree", "-r", "HEAD")
    assert "160000 commit" in tree and "operator-policy.json" in tree
    outside = tmp_path / "trusted-policy.json"
    outside.write_text(document)
    return project, policy, outside


def test_signature_policy_rejects_an_enclosing_repository(nested_policy):
    project, policy, outside = nested_policy
    with pytest.raises(SignaturePolicyError, match="outside.*repository"):
        load_signature_policies(policy, project)
    assert len(load_signature_policies(outside, project).digest_pins) == 1


def test_signature_policy_rejects_the_checkout_it_runs_from(tmp_path, monkeypatch):
    # CI scans an artifact outside the pull request's checkout; a policy in that checkout
    # is part of the change under review, as for the operator policy.
    checkout = tmp_path / "checkout"
    project = tmp_path / "artifact"
    checkout.mkdir()
    project.mkdir()
    git(checkout, "init", "--quiet")
    (project / "model.bin").write_bytes(b"synthetic local model")
    record = {
        "kind": "digest-pin",
        "artifact_path": "model.bin",
        "expected_sha256": hashlib.sha256(b"synthetic local model").hexdigest(),
    }
    document = json.dumps({"version": 2, "artifacts": [record]})
    (checkout / "policy.json").write_text(document)
    (tmp_path / "trusted-policy.json").write_text(document)
    monkeypatch.chdir(checkout)
    with pytest.raises(SignaturePolicyError, match="outside.*repository"):
        load_signature_policies(checkout / "policy.json", project)
    assert len(load_signature_policies(tmp_path / "trusted-policy.json", project).digest_pins) == 1
