"""ARCH-F1 regression: two runs of the same scan are byte-identical.

Native JSON, CycloneDX and SARIF carry no wall-clock field, so two exports
of the same inventory must be byte-identical. SPDX 3.0.1 requires
``CreationInfo.created``, so its exports differ only in that one field.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import (
    AIBOM,
    NO_CONTENT_SERIAL,
    DependencyEdge,
    native_document,
    prepare,
)
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    AgentComponent,
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import validate_cyclonedx, validate_spdx
from nexus_symbiote.generators.vex import VEXGenerator


def _fixture_bom() -> AIBOM:
    """Small inventory with no timestamp, as the CLI now emits."""
    bom = AIBOM()
    bom.add_component(AgentComponent(bom_ref="agent:main", name="main"))
    bom.add_component(MCPServerComponent(bom_ref="server:one", name="one", version_pinned=True))
    bom.add_component(
        ToolComponent(
            bom_ref="tool:send",
            name="send",
            mcp_server_ref="server:one",
            hashes={"sha256": "sha256:" + "ab" * 32},
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail="Model is unsigned.",
                )
            ],
        )
    )
    bom.add_component(
        ModelComponent(
            bom_ref="model:one",
            name="one",
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="serialization_format",
                    detail="Pickle format allows arbitrary code execution.",
                )
            ],
        )
    )
    bom.add_dependency(
        DependencyEdge(source_ref="agent:main", target_ref="tool:send", relationship="invokes")
    )
    bom.add_dependency(
        DependencyEdge(source_ref="agent:main", target_ref="model:one", relationship="depends-on")
    )
    return bom


def _without_created(value: Any) -> Any:
    """Recursively replace every SPDX ``created`` value with a fixed marker."""
    if isinstance(value, dict):
        return {
            key: "<created>" if key == "created" else _without_created(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_without_created(item) for item in value]
    return value


def test_native_json_two_runs_byte_identical() -> None:
    first = _fixture_bom().to_json()
    second = _fixture_bom().to_json()
    assert first == second
    data = json.loads(first)
    assert "timestamp" not in data["metadata"]
    assert data["metadata"]["serial_number"].startswith("urn:uuid:")
    # Native JSON is sorted, not insertion order.
    assert [c["bom_ref"] for c in data["components"]] == sorted(
        c["bom_ref"] for c in data["components"]
    )


def test_serial_is_content_derived_and_ignores_timestamps() -> None:
    plain = _fixture_bom()
    plain.metadata.completeness = CompletenessClaim(scope="repository")
    prepare(plain)
    stamped = _fixture_bom()
    stamped.metadata.timestamp = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    stamped.metadata.completeness = CompletenessClaim(
        scope="repository", timestamp=datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    )
    prepare(stamped)
    assert stamped.metadata.serial_number == plain.metadata.serial_number
    moved = _fixture_bom()
    moved.metadata.timestamp = datetime(2026, 11, 1, 12, 0, tzinfo=UTC) + timedelta(days=1)
    moved.metadata.completeness = CompletenessClaim(
        scope="repository", timestamp=datetime(2026, 11, 1, 12, 0, tzinfo=UTC) + timedelta(days=1)
    )
    prepare(moved)
    assert moved.metadata.serial_number == plain.metadata.serial_number


def test_serial_is_stable_across_component_order() -> None:
    forward = _fixture_bom()
    prepare(forward)
    reordered = _fixture_bom()
    reordered.components.reverse()
    reordered.dependencies.reverse()
    prepare(reordered)
    assert reordered.metadata.serial_number == forward.metadata.serial_number


def test_explicit_timestamp_is_preserved() -> None:
    bom = _fixture_bom()
    bom.metadata.timestamp = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    data = json.loads(bom.to_json())
    assert datetime.fromisoformat(data["metadata"]["timestamp"]) == datetime(
        2026, 11, 1, 12, 0, tzinfo=UTC
    )


def test_cyclonedx_two_runs_byte_identical() -> None:
    first = CycloneDXGenerator().generate_json(_fixture_bom())
    second = CycloneDXGenerator().generate_json(_fixture_bom())
    assert first == second
    document = json.loads(first)
    assert validate_cyclonedx(document) == []
    assert "timestamp" not in document["metadata"]
    assert document["serialNumber"].startswith("urn:uuid:")


def test_sarif_two_runs_byte_identical() -> None:
    first = SARIFGenerator().generate_json(_fixture_bom())
    second = SARIFGenerator().generate_json(_fixture_bom())
    assert first == second
    document = json.loads(first)
    assert "endTimeUtc" not in document["runs"][0]["invocations"][0]


def test_spdx_two_runs_identical_except_created() -> None:
    first = SPDXGenerator().generate_json(_fixture_bom())
    second = SPDXGenerator().generate_json(_fixture_bom())
    assert _without_created(json.loads(first)) == _without_created(json.loads(second))
    document = json.loads(first)
    assert validate_spdx(document) == []
    created = [node["created"] for node in document["@graph"] if node.get("type") == "CreationInfo"]
    assert len(created) == 1


def test_spdx_recover_round_trip_without_timestamp() -> None:
    # recover() re-projects the recovered BOM; the render-time ``created``
    # must not break the round trip when the BOM carries no timestamp.
    bom = _fixture_bom()
    document = SPDXGenerator().generate(bom)
    recovered = SPDXGenerator.recover(document)
    assert native_document(recovered) == native_document(bom)


def test_vex_has_deterministic_serial() -> None:
    first_bom, second_bom = _fixture_bom(), _fixture_bom()
    # Fix producer metadata so this vector also works after a package release.
    for inventory in (first_bom, second_bom):
        inventory.metadata.tool_version = "0.2.0"
    first = VEXGenerator().generate_json(first_bom)
    assert first == VEXGenerator().generate_json(second_bom)
    document = json.loads(first)
    assert document["serialNumber"] == "urn:uuid:ba81bf78-55da-5d50-a929-69204e539334"
    inventory_uuid = str(first_bom.metadata.serial_number).removeprefix("urn:uuid:")
    assert (
        document["externalReferences"][0]["url"]
        == f"urn:cdx:{inventory_uuid}/{first_bom.metadata.version}"
    )
    assert document["serialNumber"] != str(first_bom.metadata.serial_number)


def _create_cli_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/data"],
                    }
                }
            }
        )
    )
    (project / "CLAUDE.md").write_text("You are a helpful assistant.")
    (project / "requirements.txt").write_text("transformers==4.40.0\n")
    return project


def _scan_twice(tmp_path: Path, output_format: str) -> tuple[bytes, bytes]:
    project = _create_cli_project(tmp_path)
    runner = CliRunner()
    outputs = []
    for name in ("run1", "run2"):
        out = tmp_path / f"{name}.{output_format}.json"
        result = runner.invoke(
            main, ["scan", "--report-only", str(project), "-f", output_format, "-o", str(out)]
        )
        assert result.exit_code == 0, result.output
        outputs.append(out.read_bytes())
    return outputs[0], outputs[1]


def test_cli_scan_twice_byte_identical(tmp_path: Path) -> None:
    first, second = _scan_twice(tmp_path, "json")
    assert first == second
    data = json.loads(first)
    assert "timestamp" not in data["metadata"]
    assert data["metadata"]["serial_number"].startswith("urn:uuid:")


def test_cli_scan_cyclonedx_twice_byte_identical(tmp_path: Path) -> None:
    first, second = _scan_twice(tmp_path, "cyclonedx")
    assert first == second
    assert json.loads(first)["bomFormat"] == "CycloneDX"


def test_cli_scan_spdx_twice_identical_except_created(tmp_path: Path) -> None:
    first, second = _scan_twice(tmp_path, "spdx")
    assert _without_created(json.loads(first)) == _without_created(json.loads(second))


def test_a_lone_surrogate_from_the_checkout_stops_the_export_without_a_crash(tmp_path):
    # The serial is the uuid5 of the inventory content digest, which RFC 8785 leaves
    # undefined for a lone surrogate, so the scan fails closed with the documented error
    # ("Malformed input stops some exports" in docs/known-limitations.md), never with an
    # internal error or an export refusal, and writes nothing.
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_bytes(b'{"dependencies":{"openai":"\\ud800"}}')
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(out)])
    assert "internal error" not in result.output and "cannot be exported" not in result.output
    assert result.exit_code == 1
    assert result.stderr.endswith(f"Error: {NO_CONTENT_SERIAL}\n")
    assert not out.exists()
