"""Structured configuration keeps the schema evidence on the tool that owns the text."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.text_poisoning import CATEGORY_TOOL_POISONING, apply_text_poisoning_rules
from tests.test_text_poisoning import _ESCAPED_OVERRIDE, _VISIBLE_OVERRIDE


@pytest.mark.parametrize(
    ("filename", "template"),
    [
        (
            ".continue/config.yaml",
            'tools:\n  - name: lookup\n    description: "%s"\n    annotations: {readOnlyHint: true}\n  - name: sibling\n    description: "Public lookup"\n',
        ),
        (
            ".codex/config.toml",
            '[[tools]]\nname = "lookup"\ndescription = "%s"\nannotations = {readOnlyHint = true}\n[[tools]]\nname = "sibling"\ndescription = "Public lookup"\n',
        ),
        (
            "opencode.jsonc",
            '{"tools":[{"name":"lookup","description":"%s","annotations":{"readOnlyHint":true}},{"name":"sibling","description":"Public lookup"}]}',
        ),
    ],
)
def test_decoded_source_keeps_the_schema_rule_and_its_owner(tmp_path, filename, template):
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(template % _ESCAPED_OVERRIDE)
    tool = ToolComponent(bom_ref="tool:lookup", name="lookup", source_path=filename)
    sibling = ToolComponent(bom_ref="tool:sibling", name="sibling", source_path=filename)
    apply_text_poisoning_rules(AIBOM(components=[tool, sibling]), tmp_path)
    (finding,) = [risk for risk in tool.risks if risk.category == CATEGORY_TOOL_POISONING]
    assert set(finding.references) == {"rule:II-OVR-001", "rule:TP-SIDENOTE-004"}
    assert sibling.risks == []


def test_cli_preserves_schema_rule_with_an_ordinary_escaped_launcher_path(tmp_path):
    root = tmp_path / "project"
    (root / ".continue").mkdir(parents=True)
    descriptor = {
        "name": "lookup",
        "description": _VISIBLE_OVERRIDE.strip(),
        "annotations": {"readOnlyHint": True},
    }
    document = {
        "name": "fixture",
        "version": "0.0.1",
        "schema": "v1",
        "mcpServers": [
            {
                "name": "fixtures",
                "command": "node",
                "args": [r"C:\local\fixtures.js"],
                "tools": [descriptor],
            }
        ],
    }
    # A JSON document is also valid YAML. Its string escaping triggers the YAML tree pass.
    (root / ".continue/config.yaml").write_text(json.dumps(document))
    output = tmp_path / "inventory.json"
    result = CliRunner().invoke(
        main, ["scan", str(root), "--report-only", "--no-project-policy", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    tool = next(
        c
        for c in AIBOM.load(output).components
        if isinstance(c, ToolComponent) and c.name == "lookup"
    )
    (finding,) = [r for r in tool.risks if r.category == CATEGORY_TOOL_POISONING]
    assert set(finding.references) == {"rule:II-OVR-001", "rule:TP-SIDENOTE-004"}


def test_a_raw_source_hit_keeps_independent_component_metadata_evidence(tmp_path):
    filename = "tool-notes.yaml"
    (tmp_path / filename).write_text("description: " + _VISIBLE_OVERRIDE)
    tool = ToolComponent(
        bom_ref="tool:fixture",
        name="fixture",
        source_path=filename,
        description=_VISIBLE_OVERRIDE,
        annotations={"readOnlyHint": True},
    )
    apply_text_poisoning_rules(AIBOM(components=[tool]), tmp_path)
    (finding,) = [r for r in tool.risks if r.category == CATEGORY_TOOL_POISONING]
    assert set(finding.references) == {"rule:II-OVR-001", "rule:TP-SIDENOTE-004"}


@pytest.mark.parametrize("spelling", ['"true"', "!!str true", "tRuE"])
def test_yaml_string_annotations_do_not_become_boolean_evidence(tmp_path, spelling):
    name = "tools.yaml"
    (tmp_path / name).write_text(
        f'tools:\n  - name: lookup\n    description: "{_ESCAPED_OVERRIDE}"\n'
        f"    annotations: {{readOnlyHint: {spelling}}}\n"
    )
    tool = ToolComponent(bom_ref="tool:lookup", name="lookup", source_path=name)
    apply_text_poisoning_rules(AIBOM(components=[tool]), tmp_path)
    (finding,) = [r for r in tool.risks if r.category == CATEGORY_TOOL_POISONING]
    assert finding.references == ["rule:II-OVR-001"]
