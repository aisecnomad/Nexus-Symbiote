"""New trust-boundary and diagnostic regressions with temporary local files."""

from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.runtime_cli import _check_key_placement, _json_object, _KeyFileError
from tests.test_action_signature_policy import runner


def test_in_workspace_temp_candidate_yields_to_a_trusted_fallback(tmp_path, monkeypatch):
    work = tmp_path / "checkout"
    work.mkdir()
    scratch = tmp_path / "operator-temp"
    scratch.mkdir()
    monkeypatch.setattr(runner.tempfile, "gettempdir", lambda: str(scratch))
    from nexus_symbiote.utils import crypto

    checked = []

    def check_candidate(path, info):
        checked.append(path)
        return None if path == scratch else "unexpected directory"

    monkeypatch.setattr(crypto, "_trust_anchor_error", check_candidate)
    config = SimpleNamespace(
        signature_policy=tmp_path / "signers.json", scratch_parent=work, workspace=work
    )
    assert runner._scratch_parent(config) == scratch
    assert checked == [scratch]


def test_signer_scope_map_refuses_a_writable_file(tmp_path):
    scopes = tmp_path / "scopes.json"
    scopes.write_text("{}")
    scopes.chmod(0o666)
    with pytest.raises(_KeyFileError, match="signer scope policy"):
        _json_object(scopes, trust_anchor="signer scope policy")


def test_operator_key_report_identifies_the_refused_checkout(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    key = root / "reviewer.pub"
    key.write_text("inert fixture")
    with pytest.raises(click.UsageError) as err:
        _check_key_placement((key,), (root,), option="--operator-policy-key", holders="PROJECT")
    assert "--operator-policy-key must lie outside the target checkout" in err.value.message
    assert "that holds PROJECT" in err.value.message


@pytest.mark.parametrize("kind", ["implicit-policy", "name-too-long"])
def test_step_summary_refusals_leave_the_policy_intact(tmp_path, kind):
    root = tmp_path / "project"
    root.mkdir()
    policy = root / ".nexus-symbiote.yaml"
    original = "version: '1.0'\n"
    policy.write_text(original)
    inventory = tmp_path / "inventory.json"
    AIBOM().save(inventory)
    destination = policy if kind == "implicit-policy" else tmp_path / ("a" * 300)
    run = CliRunner().invoke(
        main,
        ["validate", str(inventory), "--project", str(root), "--step-summary", str(destination)],
    )
    assert run.exit_code in (1, 2), run.output
    assert (
        "must not name a file this command reads" in run.output
        if kind == "implicit-policy"
        else "output" in run.output.lower()
    )
    assert "internal error" not in run.output.lower()
    assert policy.read_text() == original
