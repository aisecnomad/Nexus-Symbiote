"""The verifier accepts harmless main-branch filters and binds all analysis producers."""

import pytest

from tests.test_workflow_checker import checker, workflow_errors


@pytest.mark.parametrize(
    ("options", "covered"),
    [
        ({"branches": ["main"], "tags": ["v*"]}, True),
        ({"branches-ignore": ["dependabot/**"], "tags-ignore": ["preview-*"]}, True),
        ({"branches": ["main", "!release/**"]}, True),
        ({"branches": ["main", "!main"], "tags": ["v*"]}, False),
        ({"tags": ["v*"]}, False),
        ({"tags-ignore": ["preview-*"]}, False),
        ({"branches": [], "tags": ["v*"]}, False),
        ({"branches-ignore": ["main"]}, False),
        ({"branches-ignore": ["**/main"]}, False),
        ({"branches": ["main"], "tags": ["v*"], "tags-ignore": ["preview-*"]}, False),
    ],
)
def test_push_filters_retain_every_main_push(options, covered):
    assert checker._covers_main(options, "push") is covered


@pytest.mark.parametrize(
    "key", ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "SEMMLE_CONFIGURATION"]
)
def test_java_and_analysis_settings_are_bound(tmp_path, key):
    def edit(jobs):
        jobs["codeql"]["env"] = {key: "fixture"}

    assert any("reviewed CodeQL" in e for e in workflow_errors(tmp_path, "ci.yml", edit))


@pytest.mark.parametrize(
    "action",
    [
        "actions/checkout",
        "actions/setup-python",
        "github/codeql-action/init",
        "github/codeql-action/analyze",
    ],
)
def test_full_sha_of_another_producer_revision_is_refused(tmp_path, action):
    def edit(jobs):
        step = next(
            s for s in jobs["codeql"]["steps"] if s.get("uses", "").partition("@")[0] == action
        )
        step["uses"] = action + "@" + "1" * 40

    assert any("reviewed CodeQL" in e for e in workflow_errors(tmp_path, "ci.yml", edit))
