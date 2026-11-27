from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from replay import main, score

POSITIVE = Path(__file__).with_name("known-positive.json")


@pytest.fixture
def positive() -> dict:
    return json.loads(POSITIVE.read_text(encoding="utf-8"))


def test_saved_positive_attributes_every_relationship(tmp_path: Path) -> None:
    output = tmp_path / "receipt.json"
    assert main(["--bom", str(POSITIVE), "--out", str(output)]) == 0
    receipt = json.loads(output.read_text(encoding="utf-8"))
    assert receipt["score"] == receipt["total"] == 4
    assert receipt["decoys"] == []
    assert receipt["inventory_sha256"] == hashlib.sha256(POSITIVE.read_bytes()).hexdigest()
    assert receipt["checks"][0]["evidence"][0]["line"] == 39
    assert [row["evidence"]["source_ref"] for row in receipt["checks"][1:]] == [
        "agent:order-router"
    ] * 3
    assert [row["evidence"]["relationships"] for row in receipt["checks"][1:]] == [
        ["uses-model"],
        ["invokes"],
        ["reads-instructions"],
    ]


@pytest.mark.parametrize(("name", "line"), [("build_order_router", 21), ("workflow", 33)])
def test_builder_or_uncompiled_graph_does_not_count(positive: dict, name: str, line: int) -> None:
    owner = positive["components"][0]
    owner["name"], owner["properties"]["source_line"] = name, line
    assert score(positive)["score"] == 0


@pytest.mark.parametrize(
    ("claim", "scope"),
    [
        ("owner", "repository"),
        ("source_declaration", "runtime"),
        ("source_reference", "repository"),
    ],
)
def test_workflow_requires_declaration_evidence(positive: dict, claim: str, scope: str) -> None:
    workflow = positive["components"][0]
    workflow["properties"]["source_line"] = 21
    workflow["claims"] = {
        claim: {"method": "static-source", "scope": scope, "locator": "agent.py:39"}
    }
    assert score(positive)["score"] == 0


def test_native_source_declaration_and_model_reference_locators_count(positive: dict) -> None:
    workflow, model = positive["components"][:2]
    workflow["properties"].clear()
    model["properties"].clear()
    workflow["claims"] = {
        "source_declaration": {
            "method": "python-ast",
            "scope": "repository",
            "locator": "agent.py:39",
        }
    }
    model["claims"] = {
        "source_reference": {
            "method": "python-ast",
            "scope": "repository",
            "locator": "agent.py:22",
        }
    }
    assert score(positive)["passed"]


def test_repository_and_wrong_owner_edges_do_not_count(positive: dict) -> None:
    repository = {
        "component_type": "agent",
        "bom_ref": "agent:repository:fixture",
        "name": "fixture",
    }
    wrong_owner = {"component_type": "agent", "bom_ref": "agent:other", "name": "other"}
    positive["components"].extend([repository, wrong_owner])
    chat, tool, prompt = positive["dependencies"]
    chat["source_ref"] = repository["bom_ref"]
    tool["source_ref"] = wrong_owner["bom_ref"]
    prompt["conditions"] = "repository association; runtime use and authority unobserved"
    assert score(positive)["score"] == 1


def test_swapped_model_and_untyped_tool_ref_do_not_count(positive: dict) -> None:
    embedding = {
        "component_type": "model",
        "bom_ref": "model:embedding",
        "name": "text-embedding-3-small",
    }
    positive["components"].append(embedding)
    chat, tool, prompt = positive["dependencies"]
    chat["target_ref"] = embedding["bom_ref"]
    tool["relationship"] = "depends-on"
    assert positive["components"][0]["tool_refs"] == [tool["target_ref"]]
    assert score(positive)["score"] == 2
    assert score(positive)["checks"][3]["evidence"]["relationships"] == [prompt["relationship"]]


@pytest.mark.parametrize("representation", ["dependency", "tool_refs"])
@pytest.mark.parametrize("kind", ["tool", "mcp-server"])
def test_unregistered_tool_contradicts_acceptance(
    positive: dict, representation: str, kind: str
) -> None:
    positive["components"][-1]["component_type"] = kind
    if representation == "dependency":
        positive["dependencies"].append(
            {
                "source_ref": "agent:order-router",
                "target_ref": "tool:sample-lookup",
                "relationship": "invokes",
            }
        )
    else:
        positive["components"][0]["tool_refs"].append("tool:sample-lookup")
    receipt = score(positive)
    assert receipt["score"] == 4
    assert receipt["decoys"] == [{"id": "unregistered-tool", "bom_ref": "tool:sample-lookup"}]
    assert not receipt["passed"]


@pytest.mark.parametrize(
    ("relationship", "conditions"),
    [("configured-with", "repository association; runtime use unobserved"), ("depends-on", None)],
)
def test_unowned_decoy_does_not_disqualify_workflow(
    positive: dict, relationship: str, conditions: str | None
) -> None:
    positive["dependencies"].append(
        {
            "source_ref": "agent:order-router",
            "target_ref": "tool:sample-lookup",
            "relationship": relationship,
            "conditions": conditions,
        }
    )
    assert score(positive)["passed"]


@pytest.mark.parametrize("json_version", ["1e999", "42", '["0.2.0"]'])
def test_invalid_tool_version_does_not_produce_a_receipt(
    positive: dict, tmp_path: Path, json_version: str
) -> None:
    positive["metadata"]["tool_version"] = "VERSION_PLACEHOLDER"
    path = tmp_path / "input.json"
    path.write_text(
        json.dumps(positive).replace('"VERSION_PLACEHOLDER"', json_version), encoding="utf-8"
    )
    out = tmp_path / "receipt.json"
    assert main(["--bom", str(path), "--out", str(out)]) == 2
    assert not out.exists()


def test_retired_model_contradicts_acceptance_even_without_an_edge(positive: dict) -> None:
    positive["components"].append(
        {
            "component_type": "model",
            "bom_ref": "model:old",
            "name": "gpt-3.5-turbo-0613",
        }
    )
    assert score(positive)["decoys"] == [{"id": "retired-model", "bom_ref": "model:old"}]
    assert not score(positive)["passed"]


def test_ref_and_source_ambiguity_are_refused(positive: dict) -> None:
    chat = positive["components"][1]
    positive["components"].append(dict(chat, bom_ref="model:openai/duplicate-candidate"))
    assert score(positive)["score"] == 3
    positive["components"][-1]["bom_ref"] = chat["bom_ref"]
    with pytest.raises(ValueError, match="unique nonempty bom_ref"):
        score(positive)


def test_unresolved_dependencies_and_duplicate_json_keys_are_malformed(
    positive: dict, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    positive["dependencies"][0]["target_ref"] = "model:unknown"
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(positive), encoding="utf-8")
    assert main(["--bom", str(path)]) == 2
    assert "unresolved dependency reference" in capsys.readouterr().err
    path.write_text('{"components":[],"components":[],"dependencies":[]}', encoding="utf-8")
    assert main(["--bom", str(path)]) == 2
    assert "duplicate JSON key" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("field", "ref"),
    [("model_refs", "model:unknown"), ("tool_refs", "model:openai/order-chat")],
)
def test_malformed_workflow_typed_references_are_refused(
    positive: dict, field: str, ref: str
) -> None:
    positive["components"][0][field] = [ref]
    with pytest.raises(ValueError, match=rf"{field} must resolve"):
        score(positive)


@pytest.mark.parametrize(
    ("completeness", "code"),
    [
        ({"scan_failures": ["agent.py: limit exceeded"], "scanner_status": {}}, 2),
        ({"scan_failures": [], "scanner_status": {"source": "failed"}}, 2),
        ({"scan_failures": [], "scanner_status": {"source": "complete"}}, 0),
    ],
)
def test_recorded_collection_failures_are_not_scored(
    positive: dict, tmp_path: Path, completeness: dict, code: int
) -> None:
    positive["metadata"]["completeness"] = completeness
    path = tmp_path / "input.json"
    path.write_text(json.dumps(positive), encoding="utf-8")
    out = tmp_path / "receipt.json"
    assert main(["--bom", str(path), "--out", str(out)]) == code
    assert out.exists() == (code == 0)


def test_report_only_scan_with_a_failed_collector_is_a_scan_failure(
    positive: dict, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    positive["metadata"]["completeness"] = {
        "scan_failures": ["agent.py: file-bytes limit of 8 bytes exceeded"],
        "scanner_status": {"source": "failed"},
    }
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(positive), encoding="utf-8")
    scanner = tmp_path / "scanner"
    scanner.write_text(
        f'#!/bin/sh\nwhile [ "$1" != "-o" ]; do shift; done\ncp "{inventory}" "$2"\n',
        encoding="utf-8",
    )
    scanner.chmod(0o755)
    assert main(["--nexus", str(scanner)]) == 2
    assert "collection failures" in capsys.readouterr().err


def test_score_itself_refuses_an_inventory_with_collection_failures(positive: dict) -> None:
    positive["metadata"]["completeness"] = {
        "scan_failures": [],
        "scanner_status": {"source": "failed"},
    }
    with pytest.raises(ValueError, match="collection failures"):
        score(positive)
