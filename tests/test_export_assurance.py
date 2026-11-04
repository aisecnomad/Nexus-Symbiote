"""Regression tests for canonical fingerprints, CycloneDX projections and received exports."""

import json
import subprocess
import sys
import time

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.hashing import canonical_json
from nexus_symbiote.core.models import AgentComponent, MCPServerComponent, ToolComponent
from nexus_symbiote.generators._common import content_digest, json_text
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from tests.test_generators import _sample_aibom

FORMATS = [("cyclonedx", CycloneDXGenerator), ("spdx", SPDXGenerator)]
FAILED = "Error: Export or embedded native inventory failed verification"
OVERSIZED = "Error: Export exceeds the verification limits and was not verified"
UNREADABLE = (
    "Error: Cannot read the export: a regular UTF-8 file of at most 16 MiB is required, "
    "and no part of its path may be a symbolic link"
)


def test_jcs_numbers_and_unicode_order():
    assert canonical_json(1e-7) == "1e-7"
    assert canonical_json(1e20) == "100000000000000000000"
    assert canonical_json({"\ue000": 1, "\U00010000": 2}) == '{"\U00010000":2,"\ue000":1}'
    with pytest.raises(ValueError):
        canonical_json(float("nan"))


def test_cyclonedx_preserves_edge_semantics_without_invalid_fields():
    bom = _sample_aibom()
    exported = CycloneDXGenerator().generate(bom)
    assert all(set(edge) == {"ref", "dependsOn"} for edge in exported["dependencies"])
    relationship = json.loads(exported["metadata"]["properties"][0]["value"])
    assert relationship["type"] == "invokes"
    agent = next(c for c in exported["components"] if c["bom-ref"] == "agent:main")
    assert agent["type"] == "application"


def test_cyclonedx_strict_validator():
    # Optional dependency; CI should install a CycloneDX 1.7-capable version.
    pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    if not hasattr(SchemaVersion, "V1_7"):
        pytest.skip("installed cyclonedx library does not support 1.7")
    data = CycloneDXGenerator().generate_json(_sample_aibom())
    assert JsonStrictValidator(SchemaVersion.V1_7).validate_str(data) is None


def test_legacy_tool_fingerprint_requires_migration():
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.core.models import ToolComponent
    from nexus_symbiote.validators.integrity import IntegrityValidator

    bom = AIBOM()
    bom.add_component(
        ToolComponent(bom_ref="tool:legacy", name="legacy", definition_hash="sha256:old")
    )
    report = IntegrityValidator().validate(bom)
    assert not report.is_valid
    assert report.hashes_verified == 0
    assert any(i.category == "fingerprint_version_unknown" for i in report.issues)


def test_diff_does_not_compare_legacy_and_new_fingerprints():
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.core.models import ToolComponent
    from nexus_symbiote.diff.differ import AIBOMDiffer

    old = AIBOM()
    new = AIBOM()
    old.add_component(ToolComponent(bom_ref="tool:t", name="t", definition_hash="sha256:old"))
    new.add_component(
        ToolComponent(
            bom_ref="tool:t",
            name="t",
            definition_hash="sha256:new",
            definition_hash_version="rfc8785-jcs-v1",
        )
    )
    result = AIBOMDiffer().diff(old, new)
    assert result.has_changes
    assert any(
        "unknown or incompatible" in item for c in result.components_modified for item in c.details
    )


def _verify(path, fmt):
    return CliRunner().invoke(main, ["verify-export", "--format", fmt, str(path)])


def _assert_clean_failure(result, message=FAILED):
    # A controlled failure exits through SystemExit. An escaping exception is a
    # crash: CliRunner keeps it in result.exception, and the CLI prints a traceback.
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    assert result.exit_code == 1
    assert result.output.splitlines() == [message]


def _small_bom() -> AIBOM:
    return AIBOM(components=[AgentComponent(bom_ref="agent:a", name="a")])


def _replace_native(document, fmt, mutate):
    """Edit the embedded native document and recompute its unauthenticated digest."""
    if fmt == "cyclonedx":
        properties, name, value = document["metadata"]["properties"], "name", "value"
    else:
        node = next(n for n in document["@graph"] if n["type"] == "SpdxDocument")
        properties = node["extension"][0]["extension_cdxProperty"]
        name, value = "extension_cdxPropName", "extension_cdxPropValue"
    entries = {p[name]: p for p in properties}
    native = json.loads(entries["nexus-symbiote:document"][value])
    mutate(native)
    entries["nexus-symbiote:document"][value] = json_text(native)
    entries["nexus-symbiote:documentDigest"][value] = content_digest(native)


@pytest.mark.parametrize("fmt,generator", FORMATS)
def test_verify_export_rejects_extension_loss_and_projection_tampering(tmp_path, fmt, generator):
    path = tmp_path / "export.json"
    original = generator().generate(_sample_aibom())
    runner = CliRunner()
    args = ["verify-export", "--format", fmt, str(path)]

    path.write_text(json.dumps(original))
    result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    assert "not authenticated" in result.output

    altered = json.loads(json.dumps(original))
    if fmt == "cyclonedx":
        altered["metadata"]["properties"] = [
            p for p in altered["metadata"]["properties"] if p["name"] != "nexus-symbiote:document"
        ]
    else:
        document = next(n for n in altered["@graph"] if n["type"] == "SpdxDocument")
        properties = document["extension"][0]["extension_cdxProperty"]
        properties[:] = [
            p for p in properties if p["extension_cdxPropName"] != "nexus-symbiote:document"
        ]
    path.write_text(json.dumps(altered))
    _assert_clean_failure(runner.invoke(main, args))

    altered = json.loads(json.dumps(original))
    if fmt == "cyclonedx":
        altered["components"][0]["name"] = "altered"
    else:
        node = next(n for n in altered["@graph"] if n["type"] == "software_Package")
        node["name"] = "altered"
    path.write_text(json.dumps(altered))
    _assert_clean_failure(runner.invoke(main, args))

    path.write_text(json.dumps({**original, "unexpected": [{"name": "\n::error::forged"}]}))
    _assert_clean_failure(runner.invoke(main, args))


@pytest.mark.parametrize(
    "fmt,generator,duplicate",
    [
        ("cyclonedx", CycloneDXGenerator, '"specVersion":"9.9",'),
        ("spdx", SPDXGenerator, '"@context":"https://example.test/other",'),
    ],
)
def test_verify_export_rejects_duplicate_json_keys(tmp_path, fmt, generator, duplicate):
    path = tmp_path / "export.json"
    text = json.dumps(generator().generate(_small_bom()))
    path.write_text(text)
    assert _verify(path, fmt).exit_code == 0
    # A last-value-wins parser reads exactly the verified export, while a
    # first-value-wins consumer reads another document. Only strict parsing fails.
    ambiguous = "{" + duplicate + text[1:]
    assert json.loads(ambiguous) == json.loads(text)
    path.write_text(ambiguous)
    _assert_clean_failure(_verify(path, fmt))


@pytest.mark.parametrize("fmt,generator", FORMATS)
@pytest.mark.parametrize("timestamp", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-23:00"])
def test_verify_export_unrepresentable_embedded_timestamp_fails_cleanly(
    tmp_path, fmt, generator, timestamp
):
    document = generator().generate(_small_bom())
    _replace_native(document, fmt, lambda native: native["metadata"].update(timestamp=timestamp))
    path = tmp_path / "export.json"
    path.write_text(json.dumps(document))
    _assert_clean_failure(_verify(path, fmt))
    with pytest.raises(ValueError):
        generator.recover(document)


def test_verify_export_crash_inputs_print_no_traceback(tmp_path):
    document = SPDXGenerator().generate(_small_bom())
    _replace_native(
        document,
        "spdx",
        lambda native: native["metadata"].update(timestamp="9999-12-31T23:59:59-23:00"),
    )
    path = tmp_path / "export.spdx.json"
    path.write_text(json.dumps(document))
    completed = subprocess.run(  # noqa: S603 - the installed CLI with fixed arguments
        [sys.executable, "-m", "nexus_symbiote", "verify-export", "--format", "spdx", str(path)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr.splitlines() == [FAILED]


def _conditional_dependency_bom() -> AIBOM:
    bom = AIBOM()
    bom.add_component(AgentComponent(bom_ref="agent:a", name="a"))
    bom.add_component(AgentComponent(bom_ref="agent:b", name="b"))
    bom.add_component(MCPServerComponent(bom_ref="mcp:payments", name="payments"))
    bom.add_component(ToolComponent(bom_ref="tool:t", name="t"))
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:a",
            target_ref="mcp:payments",
            relationship="depends-on",
            conditions="when approved",
        )
    )
    bom.add_dependency(
        DependencyEdge(source_ref="agent:b", target_ref="tool:t", relationship="invokes")
    )
    return bom


def test_verify_export_rejects_no_dependency_rows_that_contradict_native_edges(tmp_path):
    document = CycloneDXGenerator().generate(_conditional_dependency_bom())
    assert document["dependencies"] == []
    path = tmp_path / "export.cdx.json"
    # CycloneDX reads a row without dependsOn as "has no dependencies". Standard
    # SDKs add one for each component without emitted edges; it agrees with the
    # inventory for components that have no native depends-on edge.
    agreeing = [{"ref": "agent:b"}, {"ref": "mcp:payments"}, {"ref": "tool:t"}]
    path.write_text(json.dumps({**document, "dependencies": agreeing}))
    result = _verify(path, "cyclonedx")
    assert result.exit_code == 0, result.output
    # agent:a has a conditional depends-on edge that the standard graph withholds.
    for rows in ([{"ref": "agent:a"}], [*agreeing, {"ref": "agent:a"}]):
        contradicting = {**document, "dependencies": rows}
        path.write_text(json.dumps(contradicting))
        _assert_clean_failure(_verify(path, "cyclonedx"))
        with pytest.raises(ValueError, match="projection conflicts"):
            CycloneDXGenerator.recover(contradicting)


def test_verify_export_rejects_sdk_round_trip_that_drops_a_withheld_edge(tmp_path):
    pytest.importorskip("cyclonedx.output.json")
    from cyclonedx.model.bom import Bom
    from cyclonedx.output.json import JsonV1Dot7

    document = CycloneDXGenerator().generate(_conditional_dependency_bom())
    consumed = json.loads(JsonV1Dot7(Bom.from_json(document)).output_as_string())
    assert {"ref": "agent:a"} in consumed["dependencies"]
    path = tmp_path / "consumed.cdx.json"
    path.write_text(json.dumps(consumed))
    _assert_clean_failure(_verify(path, "cyclonedx"))


def _minimal_cyclonedx(components: int) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [
            {"type": "library", "bom-ref": f"r{i}", "name": "p"} for i in range(components)
        ],
    }


def _minimal_spdx(packages: int) -> dict:
    creation = "urn:c"
    return {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {
                "type": "SpdxDocument",
                "spdxId": "https://example.test/document/r",
                "creationInfo": creation,
                "element": ["urn:a"],
                "rootElement": [],
                "profileConformance": ["core"],
            },
            {"type": "SoftwareAgent", "spdxId": "urn:a", "creationInfo": creation, "name": "a"},
            *(
                {
                    "type": "ai_AIPackage",
                    "spdxId": f"urn:p:{i}",
                    "creationInfo": creation,
                    "name": "p",
                    "software_downloadLocation": "NOASSERTION",
                }
                for i in range(packages)
            ),
            {
                "type": "CreationInfo",
                "@id": creation,
                "specVersion": "3.0.1",
                "created": "2026-01-01T00:00:00Z",
                "createdBy": ["urn:a"],
            },
        ],
    }


def _nested(depth: int) -> list:
    value: list = []
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize(
    "fmt,build",
    [
        pytest.param(
            "cyclonedx",
            lambda limits: _minimal_cyclonedx(limits.MAX_RECEIVED_COMPONENTS + 1),
            id="cyclonedx-components",
        ),
        pytest.param(
            "spdx",
            lambda limits: _minimal_spdx(limits.MAX_RECEIVED_SPDX_ELEMENTS),
            id="spdx-elements",
        ),
        pytest.param(
            "cyclonedx",
            lambda limits: {"components": _nested(limits.MAX_RECEIVED_DEPTH)},
            id="depth",
        ),
        pytest.param(
            "spdx",
            lambda limits: {"@graph": [[0] * 1000] * (limits.MAX_RECEIVED_VALUES // 1000)},
            id="values",
        ),
    ],
)
def test_verify_export_refuses_oversized_documents_before_validation(
    tmp_path, monkeypatch, fmt, build
):
    from nexus_symbiote.generators import validation

    validated = []
    schema_errors = validation._schema_errors
    monkeypatch.setattr(
        validation, "_schema_errors", lambda *args: validated.append(args) or schema_errors(*args)
    )
    path = tmp_path / "oversized.json"
    path.write_text(json.dumps(build(validation)))
    assert path.stat().st_size < 16 * 1024 * 1024
    started = time.monotonic()
    result = _verify(path, fmt)
    assert time.monotonic() - started < 30
    _assert_clean_failure(result, OVERSIZED)
    assert validated == []


@pytest.mark.parametrize("fmt,generator", FORMATS)
def test_recover_refuses_an_oversized_embedded_inventory(fmt, generator):
    from nexus_symbiote.generators.validation import (
        MAX_RECEIVED_COMPONENTS,
        VerificationLimitError,
    )

    document = generator().generate(_small_bom())
    extra = [
        {"bom_ref": f"agent:{i}", "name": "x", "component_type": "agent"}
        for i in range(MAX_RECEIVED_COMPONENTS)
    ]
    _replace_native(document, fmt, lambda native: native["components"].extend(extra))
    with pytest.raises(VerificationLimitError):
        generator.recover(document)


def test_verify_export_reports_refused_reads_separately(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    path = real / "export.cdx.json"
    path.write_text(json.dumps(CycloneDXGenerator().generate(_small_bom())))
    assert _verify(path, "cyclonedx").exit_code == 0
    (tmp_path / "linked-dir").symlink_to(real, target_is_directory=True)
    (tmp_path / "linked.cdx.json").symlink_to(path)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (16 * 1024 * 1024 + 1))
    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(b'{"bomFormat": "\xff"}')
    for refused in (
        tmp_path / "linked-dir" / "export.cdx.json",
        tmp_path / "linked.cdx.json",
        oversized,
        invalid,
    ):
        _assert_clean_failure(_verify(refused, "cyclonedx"), UNREADABLE)


def test_spdx_license_cardinality_check_is_linear(monkeypatch):
    from nexus_symbiote.generators import validation

    # Isolate the local graph checks; scanning the graph once per package took over 30 s.
    monkeypatch.setattr(validation, "_schema_errors", lambda document, fmt: [])
    started = time.monotonic()
    errors = validation.validate_spdx(_minimal_spdx(20_000))
    assert time.monotonic() - started < 10
    assert sum("requires exactly one" in error for error in errors) == 40_000
