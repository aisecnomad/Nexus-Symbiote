from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import NATIVE_SPEC_VERSION, AgentComponent, CapabilityDeclaration

# Committed SHA-256 pins per NATIVE_SPEC_VERSION (R1.0.0-rc.1-1). Any edit to the
# native schema without bumping NATIVE_SPEC_VERSION and registering its new digest fails CI.
# A spec version's digest may still be re-pinned until the release that first ships it is
# tagged; from then on it is frozen (docs/releasing.md, step 1, re-verifies the pin).
PINNED_NATIVE_SCHEMA_BYTES_SHA256: dict[str, str] = {
    "1.1.0": "876a82dcd9737a21d391201be3762ebbbff562badeb44646ce570c71445ce64f",
    "1.2.0": "f4261752a959a1b6fb0a43365f5194b7894d305b25d9c04475c9d8f04fd8974c",
}
PINNED_NATIVE_SCHEMA_CANONICAL_SHA256: dict[str, str] = {
    "1.1.0": "59cbd2c45069fd66039d034fd692c2944f28bf3b83d1cf457d879fd164fff309",
    "1.2.0": "e2df31eebd2ebfd277217c453ecc8042cd9f605da1b32797b490bea0eea6ced5",
}


def _schema_digests(schema_bytes: bytes) -> tuple[str, str]:
    parsed = json.loads(schema_bytes.decode("utf-8"))
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(schema_bytes).hexdigest(), hashlib.sha256(canonical).hexdigest()


@pytest.mark.locked_only
def test_native_schema_matches_runtime():
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json").read_text()
    )
    assert schema == AIBOM.model_json_schema()


def test_native_schema_digest_pinned_per_spec_version():
    schema_path = Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json"
    schema_bytes = schema_path.read_bytes()
    bytes_sha, canon_sha = _schema_digests(schema_bytes)
    assert NATIVE_SPEC_VERSION in PINNED_NATIVE_SCHEMA_CANONICAL_SHA256, (
        f"NATIVE_SPEC_VERSION {NATIVE_SPEC_VERSION!r} has no pinned schema digest"
    )
    assert bytes_sha == PINNED_NATIVE_SCHEMA_BYTES_SHA256[NATIVE_SPEC_VERSION], (
        "schemas/nexus-symbiote-aibom-1.0.schema.json changed without bumping "
        "NATIVE_SPEC_VERSION in core/models.py and pinning its digest"
    )
    assert canon_sha == PINNED_NATIVE_SCHEMA_CANONICAL_SHA256[NATIVE_SPEC_VERSION]

    mutated = json.loads(schema_bytes.decode("utf-8"))
    mutated["description"] = "mutated-without-version-bump"
    _, mutated_sha = _schema_digests(json.dumps(mutated).encode("utf-8"))
    assert mutated_sha != PINNED_NATIVE_SCHEMA_CANONICAL_SHA256[NATIVE_SPEC_VERSION]


@pytest.mark.parametrize("future_version", ["1.3.0", "1.99.0", "2.0.0"])
def test_unsupported_future_minor_or_major_spec_version_fails_closed(tmp_path, future_version):
    doc = AIBOM().to_dict()
    doc["metadata"]["spec_version"] = future_version
    path = tmp_path / "future.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(NativeFormatError):
        AIBOM.load(path)
    with pytest.raises(ValidationError):
        AIBOM.model_validate(doc)


def test_native_schema_preserves_unknowns():
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json").read_text()
    )
    bom = AIBOM(components=[AgentComponent(bom_ref="agent:one", name="one", autonomy_level=None)])
    document = bom.to_dict()
    assert not list(Draft202012Validator(schema).iter_errors(document))
    assert AIBOM.model_validate(document).components[0].autonomy_level is None
    document["components"][0]["unrecognized_authority"] = {"admin": True}
    assert list(Draft202012Validator(schema).iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)


def test_published_examples_match_schema_and_runtime():
    schemas = Path(__file__).parents[1] / "schemas"
    validator = Draft202012Validator(
        json.loads((schemas / "nexus-symbiote-aibom-1.0.schema.json").read_text())
    )
    examples = sorted((schemas / "examples").glob("*.json"))
    assert examples
    for example in examples:
        document = json.loads(example.read_text())
        assert not list(validator.iter_errors(document)), example.name
        AIBOM.model_validate(document)


def test_the_example_links_and_fingerprints_tools_as_collection_does():
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
    from nexus_symbiote.graph import validate_graph

    example = AIBOM.load(Path(__file__).parents[1] / "schemas/examples/minimal-aibom.json")
    servers = {c.bom_ref for c in example.get_components_by_type(ComponentType.MCP_SERVER)}
    tools = {c.bom_ref for c in example.get_components_by_type(ComponentType.TOOL)}
    provided = {
        (edge.source_ref, edge.target_ref)
        for edge in example.dependencies
        if edge.relationship == "provides-tool"
    }
    assert {target for _, target in provided} == tools and {s for s, _ in provided} == servers
    assert not validate_graph(example)
    exported = CycloneDXGenerator().generate(example)["dependencies"]
    assert {entry["ref"] for entry in exported} >= tools
    digests = [
        digest
        for component in example.to_dict()["components"]
        for key, digest in component.items()
        if key in {"schema_hash", "definition_hash", "content_hash"}
    ]
    assert len(digests) == 4
    assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) for digest in digests)


def test_nested_capability_unknown_semantics_rejected():
    with pytest.raises(ValidationError):
        CapabilityDeclaration.model_validate({"unrecognized_approval_bypass": True})


def test_loader_rejects_duplicate_keys(tmp_path):
    from nexus_symbiote.core.aibom import NativeFormatError

    path = tmp_path / "bom.json"
    path.write_text('{"components":[],"components":[]}')
    with pytest.raises(NativeFormatError, match="duplicate keys"):
        AIBOM.load(path)


def test_signature_policy_cli_requires_explicit_project(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"version":1,"artifacts":[]}')
    path = tmp_path / "bom.json"
    AIBOM().save(path)
    result = CliRunner().invoke(main, ["validate", str(path), "--signature-policy", str(policy)])
    assert result.exit_code != 0 and "requires --project" in result.output
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--signature-policy", str(policy)])
    assert result.exit_code != 0


def _schema_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads(
            (Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json").read_text()
        )
    )


def test_dependency_edges_reject_unknown_fields_in_schema_and_model():
    edge = {
        "source_ref": "agent:a",
        "target_ref": "agent:a",
        "relationship": "depends-on",
        "condition": "only after human approval",
    }
    document = AIBOM(components=[AgentComponent(bom_ref="agent:a", name="a")]).to_dict()
    document["dependencies"] = [edge]
    assert list(_schema_validator().iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)


def test_the_schema_requires_the_component_type_the_reader_selects_a_model_by():
    validator = _schema_validator()
    mapping = validator.schema["properties"]["components"]["items"]["discriminator"]["mapping"]
    assert set(mapping) == {kind.value for kind in ComponentType}
    for kind in mapping:
        component = AIBOM.model_validate(
            {"components": [{"bom_ref": "c", "component_type": kind, "name": "c"}]}
        ).to_dict()["components"][0]
        # A document that declares no version is read as 1.0.0, which has no credentials.
        current = {"metadata": {"spec_version": NATIVE_SPEC_VERSION}, "components": [component]}
        assert not list(validator.iter_errors(current)), kind
        del component["component_type"]
        document = {"components": [component]}
        assert list(validator.iter_errors(document)), kind
        with pytest.raises(ValidationError, match="discriminator 'component_type'"):
            AIBOM.model_validate(document)
    untyped = {"components": [{"bom_ref": "agent:x", "name": "x", "autonomy_level": "L2-agent"}]}
    assert list(validator.iter_errors(untyped))


@pytest.mark.parametrize(
    ("field", "value"),
    [("trust_remote_code", "no"), ("trust_remote_code", 0), ("tool_count", "3"), ("timestamp", 1)],
)
def test_scalars_are_as_strict_as_the_published_schema(field, value):
    document = AIBOM().to_dict()
    if field == "timestamp":
        document["metadata"]["timestamp"] = value
    elif field == "tool_count":
        document["components"] = [
            {"bom_ref": "s", "component_type": "mcp-server", "name": "s", field: value}
        ]
    else:
        document["components"] = [
            {"bom_ref": "m", "component_type": "model", "name": "m", field: value}
        ]
    assert list(_schema_validator().iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)


@pytest.mark.parametrize(
    ("version", "shown"),
    [("2.0.0", "version 2.0.0"), ("1.3.0", "version 1.3.0"), ("\x1b[2Jx", "an unrecognised")],
)
def test_unsupported_native_versions_fail_with_the_supported_versions(tmp_path, version, shown):
    from nexus_symbiote.core.aibom import NativeFormatError

    document = AIBOM().to_dict()
    document["metadata"]["spec_version"] = version
    document["metadata"]["future_field"] = True
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    with pytest.raises(NativeFormatError, match="supported: 1.0.x, 1.1.x, 1.2.x") as raised:
        AIBOM.load(path)
    assert shown in str(raised.value) and "\x1b" not in str(raised.value)
    result = CliRunner().invoke(main, ["summary", str(path)])
    assert result.exit_code == 1 and "supported: 1.0.x, 1.1.x, 1.2.x" in result.output


def test_format_1_0_documents_still_load_and_new_documents_are_1_2(tmp_path):
    example = Path(__file__).parents[1] / "schemas/examples/minimal-aibom.json"
    assert AIBOM.load(example).metadata.spec_version == "1.0.0"
    assert AIBOM().to_dict()["metadata"]["spec_version"] == "1.2.0"


def test_loader_refuses_links_and_special_files_without_blocking(tmp_path):
    import os
    import threading

    from nexus_symbiote.core.aibom import NativeFormatError

    real = tmp_path / "real.json"
    AIBOM().save(real)
    (tmp_path / "link.json").symlink_to(real)
    with pytest.raises(NativeFormatError, match="symbolic link"):
        AIBOM.load(tmp_path / "link.json")
    (tmp_path / "linked").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(NativeFormatError, match="symbolic link"):
        AIBOM.load(tmp_path / "linked" / "real.json")
    with pytest.raises(NativeFormatError, match="not a regular file"):
        AIBOM.load(tmp_path)
    with pytest.raises(NativeFormatError, match="does not exist"):
        AIBOM.load(tmp_path / "missing.json")
    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)
    outcome: list[BaseException] = []
    reader = threading.Thread(
        target=lambda: outcome.append(pytest.raises(NativeFormatError, AIBOM.load, fifo).value)
    )
    reader.start()
    reader.join(timeout=10)
    assert not reader.is_alive() and outcome
    assert "not a regular file" in str(outcome[0])


def test_cli_names_why_an_inventory_could_not_be_opened(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    (tmp_path / "real").mkdir()
    AIBOM().save(tmp_path / "real" / "bom.json")
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)
    result = CliRunner().invoke(main, ["summary", str(tmp_path / "linked" / "bom.json")])
    assert result.exit_code == 1
    assert "pass the real path" in result.output
    assert "Not a directory" not in result.output and "Errno" not in result.output


def test_save_replaces_a_link_instead_of_writing_through_it(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    target = tmp_path / "bom.json"
    target.symlink_to(victim)
    AIBOM().save(target)
    assert victim.read_text() == "keep"
    assert not target.is_symlink() and AIBOM.load(target).components == []


def test_writer_and_reader_share_one_size_limit(tmp_path, monkeypatch):
    from nexus_symbiote.core import aibom as module
    from nexus_symbiote.core.aibom import NativeFormatError

    bom = AIBOM(components=[AgentComponent(bom_ref=f"agent:{i}", name="a") for i in range(40)])
    indented, compact = bom.to_json(), json.dumps(bom.to_dict(), separators=(",", ":"))
    monkeypatch.setattr(module, "MAX_NATIVE_BYTES", len(compact.encode()))
    assert len(indented) > len(compact)
    path = tmp_path / "bom.json"
    bom.save(path)
    assert path.read_text() == compact and len(AIBOM.load(path).components) == 40
    monkeypatch.setattr(module, "MAX_NATIVE_BYTES", len(compact.encode()) - 1)
    with pytest.raises(NativeFormatError, match="limit that native readers accept"):
        bom.to_native_json()
    with pytest.raises(NativeFormatError, match="native inventory limit"):
        AIBOM.load(path)


@pytest.mark.parametrize(
    ("document", "check"),
    [
        (
            {"metadata": {"timestamp": "2026-01-01T00:00:00"}},
            "export timestamps must include a timezone",
        ),
        (
            {
                "components": [{"bom_ref": "agent:a", "component_type": "agent", "name": "a"}],
                "dependencies": [
                    {"source_ref": "agent:a", "target_ref": "agent:b", "relationship": "invokes"}
                ],
            },
            "dependency references an unknown component",
        ),
    ],
)
def test_a_readable_document_the_writer_refuses_fails_as_a_format_error(tmp_path, document, check):
    from nexus_symbiote.core.aibom import NativeFormatError

    bom = AIBOM.from_native(document)
    with pytest.raises(NativeFormatError, match=f"consistency checks: {check}"):
        bom.to_native_json()
    with pytest.raises(NativeFormatError):
        bom.save(tmp_path / "bom.json")
    assert not (tmp_path / "bom.json").exists()


def test_an_inventory_without_a_serial_fails_as_a_format_error_with_the_serial_text():
    from nexus_symbiote.core.aibom import NO_CONTENT_SERIAL, NativeFormatError

    bom = AIBOM(components=[AgentComponent(bom_ref="agent:a", name="\ud800")])
    with pytest.raises(NativeFormatError) as refused:
        bom.to_native_json()
    assert f"Inventory not written. {refused.value}" == NO_CONTENT_SERIAL


@pytest.mark.parametrize("value", ["1700000000", "99999999999", "-5"])
def test_a_string_of_digits_is_not_read_as_a_timestamp(value):
    document = AIBOM().to_dict()
    document["metadata"]["timestamp"] = value
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)


def test_overlong_references_are_refused():
    from nexus_symbiote.core.models import MAX_REFERENCE_CHARS

    with pytest.raises(ValidationError):
        AgentComponent(bom_ref="a" * (MAX_REFERENCE_CHARS + 1), name="a")


def _versionless(document: dict) -> dict:
    del document["metadata"]["spec_version"]
    return document


def test_a_document_that_declares_no_format_version_is_read_as_format_1_0(tmp_path):
    document = _versionless(AIBOM().to_dict())
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    assert AIBOM.load(path).metadata.spec_version == "1.0.0"
    assert AIBOM.model_validate(document).metadata.spec_version == "1.0.0"
    assert "spec_version" not in document["metadata"], "the caller's document is not changed"
    path.write_text(json.dumps({"components": [], "dependencies": []}))
    assert AIBOM.load(path).metadata.spec_version == "1.0.0"
    AIBOM.load(path).save(tmp_path / "saved.json")
    saved = json.loads((tmp_path / "saved.json").read_text())
    assert saved["metadata"]["spec_version"] == "1.0.0"
    assert AIBOM.load(tmp_path / "saved.json").metadata.spec_version == "1.0.0"


def test_objects_built_in_process_keep_the_format_this_build_writes(tmp_path):
    from nexus_symbiote.core.models import NATIVE_SPEC_VERSION, AIBOMMetadata

    assert NATIVE_SPEC_VERSION == "1.2.0"
    assert AIBOM().metadata.spec_version == NATIVE_SPEC_VERSION
    assert AIBOM(components=[]).metadata.spec_version == NATIVE_SPEC_VERSION
    built = AIBOM(metadata=AIBOMMetadata(authors=["a"]))
    assert built.metadata.spec_version == NATIVE_SPEC_VERSION
    assert AIBOM.model_validate(built.to_dict()).metadata.spec_version == NATIVE_SPEC_VERSION
    built.save(tmp_path / "bom.json")
    assert AIBOM.load(tmp_path / "bom.json").metadata.spec_version == NATIVE_SPEC_VERSION


@pytest.mark.parametrize("version", [None, 1, "1.1", "", "2.0.0"])
def test_a_declared_version_is_still_checked(tmp_path, version):
    from nexus_symbiote.core.aibom import NativeFormatError

    document = AIBOM().to_dict()
    document["metadata"]["spec_version"] = version
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    with pytest.raises(NativeFormatError):
        AIBOM.load(path)
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)


def test_the_published_schema_reads_an_undeclared_version_as_format_1_0():
    schema = _schema_validator().schema
    spec_version = schema["$defs"]["AIBOMMetadata"]["properties"]["spec_version"]
    assert spec_version["default"] == "1.0.0"
    assert not list(_schema_validator().iter_errors(_versionless(AIBOM().to_dict())))


def test_diff_alerts_when_an_undeclared_format_meets_the_current_one(tmp_path):
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(json.dumps(_versionless(AIBOM().to_dict())))
    AIBOM().save(new)
    result = CliRunner().invoke(
        main, ["diff", str(old), str(new), "--json-output", "--fail-on-alert"]
    )
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout)["security_alerts"] == [
        {
            "severity": "high",
            "component": "metadata",
            "alert": "Snapshot metadata spec_version changed.",
        }
    ]


def test_validate_explains_an_undeclared_format_1_0_inventory_that_does_not_reconcile(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Read-only triage.\n")
    path = tmp_path / "bom.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(path)]
    )
    assert scanned.exit_code == 0, scanned.output
    document = json.loads(path.read_text())
    for component in document["components"]:
        if component["bom_ref"] == "prompt:CLAUDE.md":
            component["source_path"] = "/home/reviewer/checkout/CLAUDE.md"
    path.write_text(json.dumps(_versionless(document)))
    result = CliRunner().invoke(
        main, ["validate", str(path), "--project", str(project), "--no-project-policy"]
    )
    assert result.exit_code == 1, result.output
    assert "INFO [format] The inventory uses native format 1.0" in result.stdout


@pytest.mark.parametrize("document", [{"components": []}, {"metadata": {}, "components": []}, {}])
def test_every_reader_reads_a_versionless_document_as_format_1_0(tmp_path, monkeypatch, document):
    from nexus_symbiote import advisories
    from nexus_symbiote.core.canonical import content_digest
    from nexus_symbiote.generators._common import recover_native

    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    assert AIBOM.load(path).metadata.spec_version == "1.0.0"
    assert AIBOM.from_document(dict(document)).metadata.spec_version == "1.0.0"
    embedded = [
        {"name": "nexus-symbiote:document", "value": json.dumps(document)},
        {"name": "nexus-symbiote:documentDigest", "value": content_digest(document)},
        {"name": "nexus-symbiote:lossReport", "value": "[]"},
    ]
    recovered, original = recover_native(embedded)
    assert recovered.metadata.spec_version == "1.0.0" and original == document
    seen = []
    original_fetch = advisories.fetch_advisories

    def spy(bom, **options):
        seen.append(bom.metadata.spec_version)
        return original_fetch(bom, **options)

    monkeypatch.setattr(advisories, "fetch_advisories", spy)
    CliRunner().invoke(main, ["advisories", str(path), "--dry-run"])
    assert seen == ["1.0.0"]


def test_native_documents_are_read_only_through_the_shared_reader():
    # A dict without metadata cannot be told from AIBOM(components=...) inside the model,
    # so every reader of a native document goes through AIBOM.from_document.
    source = Path(__file__).parents[1] / "src" / "nexus_symbiote"
    callers = [
        path.relative_to(source).as_posix()
        for path in sorted(source.rglob("*.py"))
        if "AIBOM.model_validate(" in path.read_text(encoding="utf-8")
    ]
    assert callers == []


@pytest.mark.parametrize("document", [{"components": []}, {"metadata": {}, "components": []}, {}])
def test_the_digest_readers_read_a_versionless_document_alike(document):
    # digest, attest, trace-diff and export-inventory read through the same helpers: a
    # document without metadata has the format and the content digest of one with an
    # empty metadata object, and one without components has no content digest either way.
    from datetime import UTC, datetime

    from nexus_symbiote.attestation import build_statement
    from nexus_symbiote.core.content_digest import inventory_content_digest
    from nexus_symbiote.core.inventory_digests import inventory_digests

    raw = json.dumps(document).encode()
    digests = inventory_digests(raw)
    assert digests.spec_version == "1.0.0"
    stated = {"metadata": {}, **document}
    expected = inventory_content_digest(stated) if "components" in document else None
    assert digests.content_digest == expected
    signed_at = datetime(2026, 1, 1, tzinfo=UTC)
    predicate = build_statement(raw, name="s", purpose="generated", signed_at=signed_at)[
        "predicate"
    ]
    assert predicate.get("content_digest") == expected
    assert predicate.get("spec_version") == (None if expected is None else "1.0.0")


def test_an_embedded_document_that_fails_the_schema_is_refused_without_its_values():
    from nexus_symbiote.core.canonical import content_digest
    from nexus_symbiote.generators._common import recover_native

    document = {"components": [{"bom_ref": "x", "component_type": "tool", "name": {"SYNTH": 1}}]}
    embedded = [
        {"name": "nexus-symbiote:document", "value": json.dumps(document)},
        {"name": "nexus-symbiote:documentDigest", "value": content_digest(document)},
        {"name": "nexus-symbiote:lossReport", "value": "[]"},
    ]
    with pytest.raises(NativeFormatError) as refused:
        recover_native(embedded)
    assert not isinstance(refused.value, ValidationError)
    assert str(refused.value) == "It does not match the native AgentBOM schema."
