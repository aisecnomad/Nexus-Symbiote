"""Keep hook output and permission evidence under their documented bounds."""

import json

import pytest

from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.scanners import ide_agents


def test_url_derived_names_do_not_end_explicit_output_inspection():
    urls = " ".join(f"https://data.example.test/sample-{n}.csv" for n in range(70))
    segment = f"wget {urls} wget -O summary.csv https://data.example.test/summary"
    explicit, inferred, redirected = ide_agents._saved_names(segment)
    assert explicit == {"summary.csv"}
    assert "sample-69.csv" in inferred
    assert redirected == set()


@pytest.mark.parametrize("downloader", ["wget", "curl -O"])
def test_url_derived_data_passed_to_python_retains_its_transport_rating(downloader):
    command = f"{downloader} https://data.example.test/sample.csv; python analyze.py sample.csv"
    assert ide_agents._command_severity(command) is RiskSeverity.HIGH


def test_assignments_do_not_occupy_the_executable_position():
    assert ide_agents._executable_index(["MODE=preview", "formatter", "summary.txt"]) == 1


@pytest.mark.parametrize("program", ["$FORMATTER", "./tools/*"])
def test_short_flag_on_unidentified_program_is_not_an_encoded_shell(program):
    assert ide_agents._command_severity(f"{program} -e sample") is RiskSeverity.MEDIUM


def test_interpreter_scope_with_slashes_is_retained_in_permission_evidence(tmp_path):
    settings = tmp_path / ".claude/settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps({"permissions": {"allow": ["Bash(python3:reports/*.py)"], "ask": ["Bash"]}})
    )
    result = ide_agents.IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    assert any(r.category == "permission_scope" for c in result.components for r in c.risks)
