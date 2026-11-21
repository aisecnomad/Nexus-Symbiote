"""Report malformed instruction-directory metadata through the normal CLI gates."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from tests.test_project_reconciliation import _scanned


@pytest.mark.parametrize("directory", [[], {}])
def test_non_string_instruction_directory_does_not_crash_gate_reports(tmp_path, directory):
    path = ".clinerules/style"
    project, target, doc = _scanned(tmp_path, {path: "Use sentence case for headings."})
    rule = next(c for c in doc["components"] if c.get("source_path") == path)
    rule["properties"].update(content_hash_withheld=True, instruction_directory=directory)
    target.write_text(json.dumps(doc))
    runner = CliRunner()

    crosswalk = runner.invoke(main, ["crosswalk", str(target)])
    assert crosswalk.exit_code == 0, crosswalk.output
    assert "findings" in json.loads(crosswalk.stdout)

    risk = runner.invoke(
        main,
        ["risk", str(target), "--project", str(project), "--no-project-policy", "--json-output"],
    )
    assert risk.exit_code == 1, risk.output
    assert json.loads(risk.stdout)["assessment_basis"] == "project-reconciliation-failed"
