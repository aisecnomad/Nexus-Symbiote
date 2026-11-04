"""Human-readable output prints inventory text literally: no markup, no terminal controls."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import CompletenessClaim, MCPServerComponent, PromptComponent
from nexus_symbiote.utils.terminal import one_line

MARKUP = "[link=https://attacker.example/approve]docs[/link][conceal]"
CONTROLS = "\x1b]8;;https://attacker.example\x07x\x1b]8;;\x07\x1b[1A\x1b[2K\rfake\u202egpj.exe"


def test_hostile_component_names_cannot_hide_a_critical_alert(tmp_path):
    server = MCPServerComponent(
        bom_ref="mcp:pay", name="payments", endpoint_url="https://trusted.example"
    )
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(AIBOM(components=[server]).to_json())
    new.write_text(
        AIBOM(
            components=[
                server.model_copy(update={"endpoint_url": "https://attacker.example"}),
                PromptComponent(bom_ref="prompt:1", name=MARKUP),
                PromptComponent(bom_ref="prompt:2", name=CONTROLS),
            ]
        ).to_json()
    )
    result = CliRunner().invoke(main, ["diff", str(old), str(new)])
    output = result.output
    assert "[CRITICAL] Critical change in 'payments'" in output
    assert MARKUP in output
    for character in ("\x1b", "\x07", "\r", "\u202e"):
        assert character not in output


def test_validate_shows_the_component_each_issue_belongs_to(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"tickets": {"type": "http", "url": "https://mcp.example.com/mcp"}}}
        )
    )
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    assert (
        runner.invoke(main, ["scan", str(project), "--report-only", "-o", str(bom)]).exit_code == 0
    )
    result = runner.invoke(
        main, ["validate", str(bom), "--project", str(project), "--no-project-policy"]
    )
    assert "[mcp-server:" in result.output, result.output


def test_validate_prints_dangling_graph_references_literally(tmp_path):
    hostile = "tool:" + MARKUP + CONTROLS
    server = MCPServerComponent(bom_ref="mcp:docs", name="docs", tool_refs=[hostile])
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM(components=[server]).to_json())
    result = CliRunner().invoke(main, ["validate", str(bom), "--no-project-policy"])
    assert "ERROR:" in result.output, result.output
    assert MARKUP in result.output
    for character in ("\x1b", "\x07", "\r", "\u202e"):
        assert character not in result.output


def test_risk_project_failure_reasons_print_without_terminal_controls(tmp_path):
    # File names are project data; reconciliation reasons quote the component ref.
    project = tmp_path / "project"
    (project / "models").mkdir(parents=True)
    hostile = "evil\x1b[1A\x1b[2K\rfake‮gpj"
    sample = Path(__file__).parents[1] / "examples/demo-agent/models/intent-classifier.safetensors"
    (project / "models" / f"{hostile}.safetensors").write_bytes(sample.read_bytes())
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM(components=[]).to_json())
    result = CliRunner().invoke(
        main, ["risk", str(bom), "--project", str(project), "--no-project-policy"]
    )
    assert result.exit_code == 1, result.output
    assert "Project reconciliation failed." in result.output
    assert "evil" in result.output and "fake" in result.output
    for character in ("\x1b", "\r", "‮"):
        assert character not in result.output


WORKFLOW_COMMAND = "x\n::error title=Spoofed::All checks passed\n::add-mask::CRITICAL\u2028y"


def _injected_lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.lstrip().startswith("::")]


def test_line_breaks_in_inventory_text_cannot_forge_output_lines(tmp_path):
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(AIBOM().to_json())
    new.write_text(
        AIBOM(components=[PromptComponent(bom_ref="prompt:1", name=WORKFLOW_COMMAND)]).to_json()
    )
    result = CliRunner().invoke(main, ["diff", str(old), str(new)])
    assert not _injected_lines(result.output)
    assert (
        "x\ufffd::error title=Spoofed::All checks passed\ufffd::add-mask::CRITICAL\ufffdy"
        in result.output
    )


def test_validate_prints_hostile_collection_paths_on_one_line(tmp_path):
    bom = AIBOM(components=[PromptComponent(bom_ref="prompt:1", name="CLAUDE.md")])
    bom.metadata.completeness = CompletenessClaim(
        scope="repository",
        surfaces_scanned=["."],
        scan_failures=[WORKFLOW_COMMAND + ".pkl: nonregular file excluded"],
    )
    path = tmp_path / "bom.json"
    path.write_text(bom.to_json())
    result = CliRunner().invoke(main, ["validate", str(path), "--no-project-policy"])
    assert result.exit_code == 1
    assert "::error title=Spoofed" in result.output
    assert not _injected_lines(result.output)


def _workflow_command_lines(output: str) -> list[str]:
    # The GitHub Actions runner trims leading whitespace before reading a "::" command.
    return [line for line in output.splitlines() if line.lstrip().startswith("::")]


def test_risk_reconciliation_reasons_never_start_an_output_line(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# instructions\n")
    bom = AIBOM(
        components=[
            MCPServerComponent(
                bom_ref="::warning title=Risk gate::Passed (score 0)",
                name="x",
                tool_refs=["tool:none"],
            )
        ]
    )
    bom.metadata.completeness = CompletenessClaim(
        scope="repository", surfaces_scanned=["."], scan_failures=["::stop-commands::nexus"]
    )
    path = tmp_path / "bom.json"
    path.write_text(bom.to_json())
    result = CliRunner().invoke(
        main, ["risk", str(path), "--project", str(project), "--no-project-policy"]
    )
    assert result.exit_code == 1, result.output
    assert "Project reconciliation failed" in result.output
    assert "::stop-commands::nexus" in result.output
    assert _workflow_command_lines(result.output) == []


def test_policy_and_inventory_errors_cannot_forge_output_lines(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# instructions\n")
    forged = "x\\n::error title=Nexus SymBiote::Scan passed\\r::add-mask::resume\\u2028::group::"
    runner = CliRunner()
    for section, command in (
        ("scan", ["scan", str(project), "-o", str(tmp_path / "scan.json")]),
        ("risk", ["baseline", str(project), "-o", str(tmp_path / "baseline.json")]),
    ):
        (project / ".nexus-symbiote.yaml").write_text(
            f'version: "1.0"\n{section}:\n  "{forged}": 1\n'
        )
        result = runner.invoke(main, command)
        assert result.exit_code != 0, result.output
        assert "Scan passed" in result.output
        assert _workflow_command_lines(result.output) == []
    payload = "x\n::error title=Nexus SymBiote::No findings\r::group::details"
    graph = tmp_path / "graph.json"
    graph.write_text(
        AIBOM(
            components=[
                MCPServerComponent(bom_ref="mcp:a", name="a", tool_refs=["tool:" + payload])
            ]
        ).to_json()
    )
    document = json.loads(AIBOM().to_json())
    document["metadata"][payload] = 1
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps(document))
    for command in (["blast-radius", str(graph), "mcp:a"], ["vex", str(extra)]):
        result = runner.invoke(main, command)
        assert result.exit_code != 0, result.output
        assert "No findings" in result.output
        assert _workflow_command_lines(result.output) == []


def test_literal_text_renders_no_emoji_or_invisible_characters(tmp_path):
    hidden = "\u061c\u00ad\u034f\u115f\u3164\ufff9\U000e0041"
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(AIBOM().to_json())
    new.write_text(
        AIBOM(
            components=[
                PromptComponent(bom_ref="prompt:1", name=f"evil :white_check_mark: {hidden} ok")
            ]
        ).to_json()
    )
    result = CliRunner().invoke(main, ["diff", str(old), str(new)])
    assert result.exit_code == 0, result.output
    assert ":white_check_mark:" in result.output
    assert "\u2705" not in result.output
    for character in hidden:
        assert character not in result.output


def test_one_line_replaces_every_line_boundary_and_undecodable_name():
    for boundary in "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029":
        assert len(f"a{boundary}b".splitlines()) == 2
        assert len(one_line(f"a{boundary}b").splitlines()) == 1
    # os.fsdecode maps undecodable file-name bytes to lone surrogates.
    assert one_line("model\udc80.pt") == "model\ufffd.pt"
    assert one_line("tab\tkept") == "tab\tkept"
