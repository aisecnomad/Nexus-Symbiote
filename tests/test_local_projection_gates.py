"""Security gates on freshly recollected and imported evidence, via the public CLI."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main

SHADOWSCAN_FIXTURE = Path(__file__).parent / "fixtures" / "shadowscan" / "code-report-0.1.4.json"


@pytest.mark.parametrize("edit", ["source", "remove-risk", "downgrade-risk"])
def test_project_validation_rejects_forged_rag_evidence(tmp_path, edit):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / "rag_config.json").write_text(
        json.dumps({"sources": [{"name": "policy", "source_uris": ["http://kb.test"] * 8}]})
    )
    runner = CliRunner()
    output = tmp_path / "bom.json"
    args = ["validate", str(output), "--project", str(project), "--no-project-policy"]
    scan = runner.invoke(main, ["scan", str(project), "-o", str(output), "--no-project-policy"])
    assert scan.exit_code == 1 and "Scan gate failed" in scan.output
    risk = runner.invoke(main, ["risk", str(output), "--no-project-policy", "--json-output"])
    assert risk.exit_code == 1 and json.loads(risk.output)["overall_score"] == 60
    assert json.loads(risk.output)["assessment_basis"] == "supplied-bom"
    project_risk = [
        "risk",
        str(output),
        "--project",
        str(project),
        "--no-project-policy",
        "--json-output",
    ]
    fresh = runner.invoke(main, project_risk)
    expected = json.loads(fresh.output)
    assert fresh.exit_code == 1 and expected["overall_score"] == 60
    assert expected["assessment_basis"] == "project-reconciled"
    assert runner.invoke(main, args).exit_code == 0
    doc = json.loads(output.read_bytes())
    rag = next(c for c in doc["components"] if c["bom_ref"] == "rag:policy")
    # Runtime-only enrichment can accompany the same local declaration.
    rag["document_count"] = 70
    rag["risks"].reverse()
    output.write_text(json.dumps(doc))
    assert runner.invoke(main, args).exit_code == 0
    if edit == "source":
        rag["source_uris"] = ["https://claimed-safe.test"]
    elif edit == "remove-risk":
        # Eight identical HIGH findings must not match a single retained copy.
        rag["risks"].pop()
    else:
        rag["risks"][0]["severity"] = "info"
    output.write_text(json.dumps(doc))
    checked = runner.invoke(main, args)
    assert checked.exit_code == 1, checked.output
    assert (
        "Missing or mismatched local component" in checked.output and "rag:policy" in checked.output
    )
    refused = runner.invoke(main, project_risk)
    assert refused.exit_code == 1, refused.output
    unknown = json.loads(refused.output)
    assert unknown["assessment_basis"] == "project-reconciliation-failed"
    assert unknown["overall_score"] is None and unknown["risk_level"] == "unknown"
    assert any("rag:policy" in reason for reason in unknown["gate_reasons"])


def test_project_risk_requires_reconciliation_even_when_validation_is_disabled(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    output = tmp_path / "bom.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(project), "-o", str(output)]).exit_code == 0
    invalid = runner.invoke(main, ["risk", str(output), "--signature-policy", str(output)])
    assert invalid.exit_code != 0 and "requires --project" in invalid.output
    args = ["risk", str(output), "--project", str(project), "--json-output"]
    original = runner.invoke(main, args)
    assert original.exit_code == 0 and json.loads(original.output)["overall_score"] == 0
    (project / ".nexus-symbiote.yaml").write_text("validate:\n  require_completeness: false\n")
    (project / "AGENTS.md").write_text("Different instructions.")
    altered = runner.invoke(main, [*args, "--accept-project-policy"])
    assert altered.exit_code == 1 and json.loads(altered.output)["overall_score"] is None


@pytest.mark.parametrize(
    "edit", ["omitted-findings", "boolean", "missing-total", "surface", "kind"]
)
def test_native_report_rejects_contradictory_summary(tmp_path, edit):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    source = project / "shadowscan.json"
    data = json.loads(SHADOWSCAN_FIXTURE.read_bytes())
    source.write_text(json.dumps(data))
    runner = CliRunner()
    original = tmp_path / "original.json"
    run = runner.invoke(main, ["scan", str(project), "-o", str(original), "--no-project-policy"])
    assert run.exit_code == 0, run.output
    if edit == "omitted-findings":
        data["findings"] = []
    elif edit == "boolean":
        data["summary"]["by_kind"]["agent"] = True  # In Python True compares equal to 1.
    elif edit == "missing-total":
        del data["summary"]["total"]
    elif edit == "surface":
        data["summary"]["by_surface"] = {"cloud": 2}
    else:
        data["summary"]["by_kind"] = {"agent": 2}
    source.write_text(json.dumps(data))
    direct = tmp_path / "direct.json"
    imported = runner.invoke(
        main, ["import-shadowscan", str(source), "-o", str(direct), "--report-only"]
    )
    assert imported.exit_code == 1 and not direct.exists()
    output = tmp_path / "current.json"
    scanned = runner.invoke(main, ["scan", str(project), "-o", str(output), "--no-project-policy"])
    assert scanned.exit_code == 1, scanned.output
    coverage = json.loads(output.read_bytes())["metadata"]["completeness"]
    assert coverage["scanner_status"]["shadowscan"] == "failed"
    checked = runner.invoke(
        main, ["validate", str(original), "--no-project-policy", "--project", str(project)]
    )
    assert checked.exit_code == 1, checked.output


def test_native_counts_use_final_findings_and_accept_legacy_reports(tmp_path):
    report = json.loads(SHADOWSCAN_FIXTURE.read_bytes())
    report["stats"][0]["findings"] += 1  # A connector may count an observation before filtering.
    runner = CliRunner()
    source = tmp_path / "source.json"
    for variant in ("current", "legacy"):
        if variant == "legacy":
            del report["finding_identity_schema"]
            for field in ("total", "by_kind", "by_surface"):
                del report["summary"][field]
        source.write_text(json.dumps(report))
        path = tmp_path / f"{variant}.json"
        imported = runner.invoke(
            main,
            [
                "import-shadowscan",
                str(source),
                "-o",
                str(path),
                "--report-only",
                "--allow-unsigned-discovery",
            ],
        )
        assert imported.exit_code == 0, imported.output
        assert (
            json.loads(path.read_bytes())["metadata"]["completeness"]["source_report_status"]
            == "complete"
        )


@pytest.mark.parametrize("delete_all", [False, True])
def test_project_risk_refuses_stale_local_components(tmp_path, delete_all):
    project = tmp_path / "project"
    project.mkdir()
    prompt = project / "AGENTS.md"
    prompt.write_text("Keep receipts.")
    retrieval = project / "rag_config.json"
    retrieval.write_text(
        json.dumps(
            {
                "sources": [
                    {"name": "policy", "source_uris": ["https://kb.test"], "content_filter": True}
                ]
            }
        )
    )
    runner = CliRunner()
    output = tmp_path / "bom.json"
    assert runner.invoke(main, ["scan", str(project), "-o", str(output)]).exit_code == 0
    args = ["risk", str(output), "--project", str(project), "--no-project-policy", "--json-output"]
    original = runner.invoke(main, args)
    assert original.exit_code == 0 and json.loads(original.output)["risk_level"] == "clean"
    retrieval.unlink()
    if delete_all:
        prompt.unlink()
    result = runner.invoke(main, args)
    assert result.exit_code == 1, result.output
    unknown = json.loads(result.output)
    assert unknown["overall_score"] is None
    assert any("rag:policy" in reason for reason in unknown["gate_reasons"])
    assert runner.invoke(main, ["validate", str(output), "--project", str(project)]).exit_code == 1


def test_project_risk_requires_a_local_subject_even_with_external_observations(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    runner = CliRunner()
    output = tmp_path / "bom.json"
    assert (
        runner.invoke(main, ["scan", str(project), "-o", str(output), "--report-only"]).exit_code
        == 0
    )
    doc = json.loads(output.read_bytes())
    doc["components"].append(
        {
            "bom_ref": "tool:observed",
            "component_type": "tool",
            "name": "observed",
            "claims": {
                "tool_definition": {
                    "scope": "served-descriptor",
                    "method": "operator-pinned-stdio-tools-list",
                    "assurance": "observed",
                }
            },
        }
    )
    output.write_text(json.dumps(doc))
    result = runner.invoke(main, ["risk", str(output), "--project", str(project), "--json-output"])
    unknown = json.loads(result.output)
    assert result.exit_code == 1 and unknown["overall_score"] is None
    assert unknown["gate_reasons"] == ["No local project subject was available to reconcile."]
