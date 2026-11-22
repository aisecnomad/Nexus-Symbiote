"""The required analysis consumes the reviewed languages and their own SARIF output."""

from pathlib import Path

import pytest
import yaml

from tests.support import ROOT
from tests.test_workflow_checker import checker, workflow_errors


@pytest.mark.parametrize(("name", "job"), [("ci.yml", "codeql"), ("codeql.yml", "analyze")])
@pytest.mark.parametrize("change", ["language", "query", "output", "extra-step", "local-action"])
def test_required_codeql_producer_and_inputs_are_bound(tmp_path, name, job, change):
    def edit(jobs):
        steps = jobs[job]["steps"]
        init = next(s for s in steps if "/init@" in s.get("uses", ""))
        analyze = next(s for s in steps if "/analyze@" in s.get("uses", ""))
        if change == "language":
            init["with"]["languages"] = "javascript"
        elif change == "query":
            init["with"]["queries"] = "documentation-example"
        elif change == "output":
            analyze["with"]["output"] = "example-results"
        elif change == "extra-step":
            steps.insert(steps.index(analyze) + 1, {"run": "echo example"})
        else:
            init["uses"] = "./example/" + init["uses"]

    assert any("reviewed CodeQL" in e for e in workflow_errors(tmp_path, name, edit))


def test_required_codeql_matrix_is_not_filtered(tmp_path):
    def edit(jobs):
        jobs["analyze"]["strategy"]["matrix"]["exclude"] = [{"language": "python"}]

    assert any("CodeQL matrix" in e for e in workflow_errors(tmp_path, "codeql.yml", edit))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runs-on", "self-hosted"),
        ("env", {"CODEQL_ACTION_EXTRA_OPTIONS": "example"}),
        ("env", {"NODE_PATH": "example-modules"}),
    ],
)
def test_analysis_runs_on_its_reviewed_host_and_tool_environment(tmp_path, field, value):
    def edit(jobs):
        jobs["codeql"][field] = value

    assert any("reviewed CodeQL" in e for e in workflow_errors(tmp_path, "ci.yml", edit))


def test_one_excluded_configuration_can_leave_every_language_covered(tmp_path):
    def edit(jobs):
        matrix = jobs["analyze"]["strategy"]["matrix"]
        matrix["variant"] = ["first", "second"]
        matrix["exclude"] = [{"language": "python", "variant": "second"}]

    assert not workflow_errors(tmp_path, "codeql.yml", edit)


@pytest.mark.parametrize(
    ("options", "covers"),
    [
        (None, True),
        ({"branches": ["main", "release"]}, True),
        ({"branches": ["m*"], "types": ["opened", "reopened", "synchronize"]}, True),
        ({"branches-ignore": ["release"]}, True),
        ({"branches": ["*", "!main"]}, False),
        ({"branches": ["*", "!main", "main"]}, True),
        ({"branches-ignore": ["ma*"]}, False),
        ({"types": ["opened"]}, False),
        ({"paths-ignore": ["docs/**"]}, False),
    ],
)
def test_branch_and_activity_filters_preserve_main_coverage(options, covers):
    assert checker._covers_main(options, "pull_request") is covers


@pytest.mark.parametrize("name", ["ci.yml", "codeql.yml"])
def test_codeql_runs_for_all_changes_to_main(tmp_path: Path, name):
    doc = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
    events = doc.get("on", doc.get(True))
    events["pull_request"]["paths"] = ["docs/**"]
    path = tmp_path / name
    path.write_text(yaml.safe_dump(doc))
    assert any("every pull request to main" in e for e in checker.check(path))
