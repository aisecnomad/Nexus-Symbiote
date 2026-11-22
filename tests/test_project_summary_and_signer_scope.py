"""Regression cases through the public gate and runtime commands."""

import os

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main


@pytest.mark.parametrize("location", ["checkout", "writable"])
def test_register_checks_the_signer_scope_file_before_opening_state(tmp_path, location):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").mkdir()
    snapshot = checkout / "snapshot.json"
    trust = tmp_path / "trust.json"
    key = tmp_path / "public.pem"
    for path in (snapshot, trust, key):
        path.write_text("{}")
    state = tmp_path / "state.sqlite"
    scopes = (checkout if location == "checkout" else tmp_path) / "scopes.json"
    scopes.write_text("{}")
    if location == "writable":
        if os.name != "posix":
            pytest.skip("POSIX file modes")
        scopes.chmod(0o666)
    args = [
        "runtime",
        "register",
        str(snapshot),
        "--trust",
        str(trust),
        "--state",
        str(state),
        "--snapshot-key",
        str(key),
        "--trust-key",
        str(key),
        "--signer-scopes",
        str(scopes),
    ]
    result = CliRunner().invoke(main, args)
    if location == "checkout":
        assert result.exit_code == 2 and "--signer-scopes" in result.output
        assert "outside every git working tree" in result.output
    else:
        assert result.exit_code == 1 and "signer scope policy" in result.output
        assert "group- or world-writable" in result.output
    assert not state.exists()


@pytest.mark.parametrize("gate", ["validate", "risk"])
@pytest.mark.parametrize("destination", ["source", "nested", "alias", "new", "outside"])
def test_step_summary_preserves_checked_project_files(tmp_path, gate, destination):
    project = tmp_path / "project"
    project.mkdir()
    source = (project / "docs" if destination == "nested" else project) / "AGENTS.md"
    source.parent.mkdir(exist_ok=True)
    original = "Use the local documentation.\n"
    source.write_text(original)
    inventory = tmp_path / "inventory.json"
    runner = CliRunner()
    scanned = runner.invoke(main, ["scan", str(project), "-o", str(inventory)])
    assert scanned.exit_code == 0, scanned.output
    summary = tmp_path / "summary.md"
    if destination in {"source", "nested"}:
        summary = source
    elif destination == "alias":
        summary.hardlink_to(source)
    elif destination == "new":
        summary = project / "new-report.md"
    else:
        summary.write_text("Earlier report.\n")
    result = runner.invoke(
        main, [gate, str(inventory), "--project", str(project), "--step-summary", str(summary)]
    )
    assert source.read_text() == original
    if destination in {"source", "nested"}:
        assert result.exit_code == 2 and "--step-summary" in result.output
    elif destination == "alias":
        assert result.exit_code == 1 and "output" in result.output.lower()
    else:
        assert f"### Nexus SymBiote {gate}:" in summary.read_text()
        if destination == "outside":
            assert summary.read_text().startswith("Earlier report.\n")
