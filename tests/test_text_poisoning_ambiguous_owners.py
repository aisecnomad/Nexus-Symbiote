"""Verify attribution and schema handling with inert synthetic findings."""

import json

import pytest

from nexus_symbiote import text_poisoning
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import AgentComponent, ToolComponent
from nexus_symbiote.text_poisoning import TextPoisoningHit


def _synthetic_hits(text, *, surface, is_tool_surface, where=""):
    marker = "review marker"
    if not is_tool_surface or marker not in text:
        return []
    return [
        TextPoisoningHit(
            rule_id="TP-CONCEAL-003",
            category=text_poisoning.CATEGORY_TOOL_POISONING,
            severity=RiskSeverity.HIGH,
            byte_offset=text.index(marker),
            surface=surface,
            summary="Synthetic review finding",
            where=where,
        )
    ]


@pytest.mark.parametrize("format_name", ["json", "yaml", "yaml-raw"])
def test_shared_tool_name_keeps_file_evidence_without_charging_either_tool(
    tmp_path, monkeypatch, format_name
):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    filename = f"config.{format_name.split('-')[0]}"
    path = tmp_path / filename
    if format_name == "json":
        path.write_text(
            json.dumps(
                {
                    "tools": [
                        {"name": "lookup", "annotations": {"readOnlyHint": True}},
                        {"name": "lookup", "description": "review marker"},
                    ]
                }
            )
        )
    else:
        description = "review marker" if format_name == "yaml-raw" else r"review\u0020marker"
        path.write_text(
            "tools:\n  - name: lookup\n    annotations: {readOnlyHint: true}\n"
            f'  - name: lookup\n    description: "{description}"\n'
        )
    first = ToolComponent(name="lookup", bom_ref="tool:first", source_path=filename)
    second = ToolComponent(name="lookup", bom_ref="tool:second", source_path=filename)
    root = AgentComponent(name="workspace", bom_ref="agent:workspace")
    inventory = AIBOM(components=[root, first, second])

    assert text_poisoning.apply_text_poisoning_rules(inventory, root=tmp_path) == 1
    assert not first.risks and not second.risks
    assert root.risks[0].severity == RiskSeverity.HIGH
    assert filename in root.risks[0].detail
    assert "TP-SIDENOTE-004" not in root.risks[0].detail


def test_ambiguous_finding_with_no_owning_component_records_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    (tmp_path / "tools.json").write_text(
        json.dumps({"name": "lookup", "description": "review marker"})
    )
    tools = [
        ToolComponent(name="lookup", bom_ref=f"tool:{host}", source_path="tools.json")
        for host in ("docs", "inventory")
    ]
    failures = []
    text_poisoning.apply_text_poisoning_rules(AIBOM(components=tools), tmp_path, failures=failures)
    assert all(not tool.risks for tool in tools)
    assert failures and "unambiguous component owner" in failures[0]


def test_nonstring_property_keys_do_not_prevent_sidenote_evaluation():
    schema = {"properties": {"note": {}, ("note", 2): {}, True: {}}}
    hits = _synthetic_hits("review marker", surface="config", is_tool_surface=True)
    result = text_poisoning.check_sidenote_tool_schema(
        schema, "review marker contains a note", None, surface="config", existing_hits=hits
    )
    assert [hit.rule_id for hit in result] == ["TP-SIDENOTE-004"]


def test_property_keys_alone_are_not_sidenote_text(monkeypatch):
    monkeypatch.setattr(text_poisoning, "scan_text_block", _synthetic_hits)
    tool = ToolComponent(name="lookup", bom_ref="tool:lookup", source_path="config.yaml")
    declaration = {
        "name": "lookup",
        "description": "review marker",
        "inputSchema": {"properties": {"note": {"type": "string"}}},
    }
    groups = text_poisoning._scan_structured_source(
        "config.yaml", declaration, [tool], None, include_keys=True
    )
    assert [hit.rule_id for target, hits in groups for hit in hits if target is tool] == [
        "TP-CONCEAL-003"
    ]
