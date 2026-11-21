"""Regressions for the #279 review of cdf955ba: projection pins, SDK round trip, declarations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from cyclonedx.model.bom import Bom
from cyclonedx.output.json import JsonV1Dot6, JsonV1Dot7

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge, native_document
from nexus_symbiote.core.enums import AssuranceLevel, AutonomyLevel
from nexus_symbiote.core.models import AgentComponent, DataSourceComponent, ModelComponent
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import spdx_errors
from nexus_symbiote.spdx_profiles import (
    apply_agent_yaml_declarations,
    spdx_license_expression,
    spdx_license_ids,
)
from tests.support import scaling_ratio
from tests.test_export_conformance import fixture_bom
from tests.test_typed_exports_and_spdx_ai import _rich_aibom

FROZEN_V3 = Path(__file__).parent / "fixtures/export-projection-3/fixture.spdx.json"
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"


def _observed() -> AIBOM:
    bom = AIBOM()
    bom.components = [
        AgentComponent(
            bom_ref="agent:a",
            name="a",
            autonomy_level=AutonomyLevel.L2_AGENT,
            assurance_level=AssuranceLevel.OBSERVED,
        ),
        ModelComponent(
            bom_ref="model:m",
            name="models/clf.safetensors",
            model_type="classifier",
            assurance_level=AssuranceLevel.OBSERVED,
        ),
        DataSourceComponent(
            bom_ref="dataset:d",
            name="tickets",
            source_uri="https://data.example.com/tickets.parquet",
            license="CC-BY-4.0",
            assurance_level=AssuranceLevel.OBSERVED,
        ),
    ]
    return bom


def _declare(tmp_path: Path, text: str) -> tuple[AIBOM, list[str]]:
    (tmp_path / "agent.yaml").write_text(text, encoding="utf-8")
    bom = _observed()
    return bom, apply_agent_yaml_declarations(bom, tmp_path, relative_path="agent.yaml")


def _graph_node(document: dict, **match: str) -> dict:
    return next(n for n in document["@graph"] if all(n.get(k) == v for k, v in match.items()))


def test_spdx_projection_3_reprojects_a_frozen_export_byte_for_byte() -> None:
    text = FROZEN_V3.read_text(encoding="utf-8")
    recovered = SPDXGenerator.recover(json.loads(text))
    assert SPDXGenerator().generate_json(recovered) + "\n" == text


@pytest.mark.parametrize("spec, writer", [("1.7", JsonV1Dot7), ("1.6", JsonV1Dot6)])
def test_cdx_projection_3_survives_cyclonedx_python_lib(spec, writer) -> None:
    original = fixture_bom()
    document = CycloneDXGenerator(projection_version=3, spec_version=spec).generate(original)
    assert any("modelCard" in c for c in document["components"])
    output = json.loads(writer(Bom.from_json(document)).output_as_string())
    assert native_document(CycloneDXGenerator.recover(output)) == native_document(original)


def test_cdx_projection_3_rejects_a_partly_removed_or_edited_model_card() -> None:
    document = CycloneDXGenerator(projection_version=3).generate(_rich_aibom())
    cards = [c for c in document["components"] if "modelCard" in c]
    assert len(cards) >= 2
    del cards[0]["modelCard"]
    with pytest.raises(ValueError, match="conflicts"):
        CycloneDXGenerator.recover(document)
    edited = CycloneDXGenerator(projection_version=3).generate(_rich_aibom())
    next(c for c in edited["components"] if "modelCard" in c)["modelCard"] = {
        "modelParameters": {"task": "edited"}
    }
    with pytest.raises(ValueError, match="conflicts"):
        CycloneDXGenerator.recover(edited)


def test_declarations_never_replace_observed_dataset_location_or_license(tmp_path: Path) -> None:
    bom, notices = _declare(
        tmp_path,
        'schema_version: "1.1"\ndatasets:\n  - name: tickets\n    license: MIT\n'
        "    download_location: https://attacker.example.net/tickets.parquet\n"
        "models:\n  - name: models/clf.safetensors\n"
        "    download_location: https://models.example.com/clf.safetensors\n"
        "    training:\n      datasets: [tickets]\n",
    )
    assert notices == [
        "dataset:d: license conflict with agent.yaml",
        "dataset:d: source_uri conflict with agent.yaml",
    ]
    dataset = bom.get_component("dataset:d")
    assert "declared_license" not in dataset.properties
    assert "declared_download_location" not in dataset.properties
    # A declared training edge is exported as a typed edge but keeps its provenance.
    assert [e.model_dump(exclude_none=True) for e in bom.dependencies] == [
        {
            "source_ref": "model:m",
            "target_ref": "dataset:d",
            "relationship": "trained-on",
            "assurance_level": "declared",
        }
    ]

    cdx = CycloneDXGenerator(projection_version=3).generate(bom)
    by_ref = {c["bom-ref"]: c for c in cdx["components"]}
    assert by_ref["dataset:d"]["externalReferences"] == [
        {"type": "distribution", "url": "https://data.example.com/tickets.parquet"}
    ]
    assert by_ref["dataset:d"]["licenses"] == [{"license": {"id": "CC-BY-4.0"}}]
    assert by_ref["model:m"]["externalReferences"] == [
        {
            "type": "distribution",
            "url": "https://models.example.com/clf.safetensors",
            "comment": "declared by producer",
        }
    ]

    spdx_doc = SPDXGenerator(projection_version=4).generate(bom)
    ds = _graph_node(spdx_doc, name="tickets")
    assert ds["software_downloadLocation"] == "https://data.example.com/tickets.parquet"
    licence = _graph_node(spdx_doc, relationshipType="hasDeclaredLicense", **{"from": ds["spdxId"]})
    expression = _graph_node(spdx_doc, spdxId=licence["to"][0])
    assert expression["simplelicensing_licenseExpression"] == "CC-BY-4.0"
    trained = _graph_node(spdx_doc, relationshipType="trainedOn")
    (native_edge,) = trained["extension"][0]["extension_cdxProperty"]
    assert json.loads(native_edge["extension_cdxPropValue"])["assurance_level"] == "declared"


def test_declared_dataset_without_observed_location_is_marked_declared(tmp_path: Path) -> None:
    bom = _observed()
    bom.get_component("dataset:d").source_uri = None
    (tmp_path / "agent.yaml").write_text(
        "datasets:\n  - name: tickets\n    download_location: https://d.example.com/t.parquet\n",
        encoding="utf-8",
    )
    apply_agent_yaml_declarations(bom, tmp_path, relative_path="agent.yaml")
    ds = _graph_node(SPDXGenerator(projection_version=4).generate(bom), name="tickets")
    assert ds["software_downloadLocation"] == "https://d.example.com/t.parquet"
    declared = [
        p["extension_cdxPropValue"]
        for p in ds["extension"][0]["extension_cdxProperty"]
        if p["extension_cdxPropName"] == "nexus-symbiote:declaredField"
    ]
    assert "software_downloadLocation" in declared


@pytest.mark.parametrize("token", [AWS_KEY, GH_TOKEN])
def test_token_shaped_url_host_never_reaches_exports(tmp_path: Path, token: str) -> None:
    bom, _ = _declare(tmp_path, f"download_location: https://{token}.example.com/agent.tgz\n")
    assert "declared_download_location" not in bom.get_component("agent:a").properties
    for generator in (
        CycloneDXGenerator(projection_version=3),
        SPDXGenerator(projection_version=4),
    ):
        assert token not in generator.generate_json(bom)


def test_declared_free_text_secrets_are_redacted(tmp_path: Path) -> None:
    bom, _ = _declare(
        tmp_path,
        f'owner: "{GH_TOKEN}"\ndata_usage: "password=hunter2hunter2 {AWS_KEY}"\n'
        f'compliance: ["{GH_TOKEN}"]\n',
    )
    for generator in (
        CycloneDXGenerator(projection_version=3),
        SPDXGenerator(projection_version=4),
    ):
        rendered = generator.generate_json(bom)
        assert GH_TOKEN not in rendered
        assert AWS_KEY not in rendered
        assert "hunter2hunter2" not in rendered


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_author_option_is_redacted(tmp_path: Path, fmt: str) -> None:
    bom_path = tmp_path / "inv.json"
    _observed().save(bom_path)
    result = CliRunner().invoke(
        main, ["export-standard", str(bom_path), "-f", fmt, "--author", f"ops {AWS_KEY}"]
    )
    assert result.exit_code == 0, result.output
    assert AWS_KEY not in result.output
    assert "ops ***" in result.output
    assert AWS_KEY not in SPDXGenerator(
        projection_version=4, author=f"ops {AWS_KEY}"
    ).generate_json(_observed())


@pytest.mark.parametrize(
    "value, valid",
    [
        ("Apache-2.0", True),
        ("MIT OR Apache-2.0", True),
        ("(MIT AND BSD-3-Clause) OR Apache-2.0", True),
        ("GPL-2.0-or-later WITH Classpath-exception-2.0", True),
        ("LicenseRef-acme-1", True),
        ("Apache License 2.0", False),
        ("Proprietary", False),
        ("MIT OR", False),
        ("(MIT", False),
        ("MIT)", False),
        ("AND MIT", False),
        ("MIT Apache-2.0", False),
        ("MIT+", True),
        ("GPL-2.0+", True),
        ("MIT AND Apache-2.0 OR BSD-3-Clause AND 0BSD", True),
        ("MIT WITH MIT", False),
        ("Classpath-exception-2.0", False),
        ("Classpath-exception-2.0 OR MIT", False),
        ("(MIT OR Apache-2.0) WITH Classpath-exception-2.0", False),
        ("MIT WITH Classpath-exception-2.0 WITH LLVM-exception", False),
        ("MIT WITH (Classpath-exception-2.0 OR LLVM-exception)", False),
        ("GPL-2.0++", False),
        ("GPL-2.0-only+", False),
        ("GPL-2.0-or-later+", False),
        ("MIT WITH Classpath-exception-2.0+", False),
        ("MIT WITH LicenseRef-x", False),
        ("LicenseRef-x+", False),
        ("()", False),
        ("(MIT))", False),
        ("MIT WITH", False),
    ],
)
def test_spdx_license_expression_grammar(value: str, valid: bool) -> None:
    assert spdx_license_expression(value) == (value if valid else None)


def test_invalid_license_text_is_no_assertion_in_spdx_and_name_in_cdx(tmp_path: Path) -> None:
    bom, _ = _declare(
        tmp_path,
        'licenses: ["Apache License 2.0"]\nmodels:\n  - name: models/clf.safetensors\n'
        "    license: Proprietary\n",
    )
    bom.get_component("dataset:d").license = None
    spdx_doc = SPDXGenerator(projection_version=4).generate(bom)
    expressions = [
        n["simplelicensing_licenseExpression"]
        for n in spdx_doc["@graph"]
        if n["type"] == "simplelicensing_LicenseExpression"
    ]
    assert expressions == []
    assert "simpleLicensing" not in _graph_node(spdx_doc, type="SpdxDocument")["profileConformance"]
    assert "Proprietary" in json.dumps(spdx_doc)  # kept in the native extension

    cdx = {
        c["bom-ref"]: c
        for c in CycloneDXGenerator(projection_version=3).generate(bom)["components"]
    }
    assert cdx["model:m"]["licenses"] == [
        {"license": {"name": "Proprietary", "acknowledgement": "declared"}}
    ]
    bom.get_component("dataset:d").license = "MIT OR Apache-2.0"
    cdx = {
        c["bom-ref"]: c
        for c in CycloneDXGenerator(projection_version=3).generate(bom)["components"]
    }
    assert cdx["dataset:d"]["licenses"] == [{"expression": "MIT OR Apache-2.0"}]


@pytest.mark.parametrize("spec, writer", [("1.7", JsonV1Dot7), ("1.6", JsonV1Dot6)])
def test_cdx_projection_3_of_a_real_scan_survives_cyclonedx_python_lib(
    tmp_path: Path, spec, writer
) -> None:
    inventory = tmp_path / "inv.json"
    demo = Path(__file__).resolve().parents[1] / "examples/demo-agent"
    result = CliRunner().invoke(
        main,
        ["scan", str(demo), "-f", "json", "--report-only", "-o", str(inventory)],
        env={"SOURCE_DATE_EPOCH": "1700000000"},
    )
    assert result.exit_code == 0, result.output
    original = AIBOM.load(inventory)
    assert original.metadata.timestamp is not None
    document = CycloneDXGenerator(projection_version=3, spec_version=spec).generate(original)
    output = json.loads(writer(Bom.from_json(document)).output_as_string())
    assert native_document(CycloneDXGenerator.recover(output)) == native_document(original)


def test_licence_and_exception_ids_are_split_from_the_vendored_enum() -> None:
    licences, exceptions = spdx_license_ids()
    assert {"MIT", "Apache-2.0", "GPL-2.0+"} <= licences
    assert {"Classpath-exception-2.0", "LLVM-exception", "389-exception"} <= exceptions
    assert not licences & exceptions


def test_invalid_expressions_never_reach_spdx_or_cdx_license_id() -> None:
    bom = _observed()
    bom.get_component("dataset:d").license = "MIT WITH MIT"
    spdx_doc = SPDXGenerator(projection_version=4).generate(bom)
    assert spdx_errors(spdx_doc) == []
    assert not [n for n in spdx_doc["@graph"] if n["type"] == "simplelicensing_LicenseExpression"]
    bom.get_component("dataset:d").license = "Classpath-exception-2.0"
    cdx = CycloneDXGenerator(projection_version=3).generate(bom)
    dataset = next(c for c in cdx["components"] if c["bom-ref"] == "dataset:d")
    assert dataset["licenses"] == [{"license": {"name": "Classpath-exception-2.0"}}]


def test_percent_encoded_path_secret_never_reaches_exports(tmp_path: Path) -> None:
    encoded = "".join(f"%{ord(ch):02X}" for ch in GH_TOKEN)
    bom, _ = _declare(tmp_path, f"download_location: https://example.com/{encoded}/agent.tgz\n")
    assert "declared_download_location" not in bom.get_component("agent:a").properties
    for generator in (
        CycloneDXGenerator(projection_version=3),
        SPDXGenerator(projection_version=4),
    ):
        rendered = generator.generate_json(bom)
        assert encoded not in rendered
        assert GH_TOKEN not in rendered


def test_observed_source_uri_query_token_stays_out_of_standard_fields() -> None:
    bom = _observed()
    bom.get_component(
        "dataset:d"
    ).source_uri = f"https://data.example.com/t.parquet?token={GH_TOKEN}"
    cdx = CycloneDXGenerator(projection_version=3).generate(bom)
    dataset = next(c for c in cdx["components"] if c["bom-ref"] == "dataset:d")
    assert dataset["externalReferences"] == [
        {"type": "distribution", "url": "https://data.example.com/t.parquet"}
    ]
    ds = _graph_node(SPDXGenerator(projection_version=4).generate(bom), name="tickets")
    assert ds["software_downloadLocation"] == "https://data.example.com/t.parquet"


def test_spdx_marks_a_licence_filled_from_a_declaration(tmp_path: Path) -> None:
    bom, _ = _declare(tmp_path, "models:\n  - name: models/clf.safetensors\n    license: MIT\n")
    spdx_doc = SPDXGenerator(projection_version=4).generate(bom)
    model = _graph_node(spdx_doc, name="models/clf.safetensors")
    declared = _graph_node(
        spdx_doc, relationshipType="hasDeclaredLicense", **{"from": model["spdxId"]}
    )
    assert declared["comment"] == "declared by producer"
    dataset = _graph_node(spdx_doc, name="tickets")
    observed = _graph_node(
        spdx_doc, relationshipType="hasDeclaredLicense", **{"from": dataset["spdxId"]}
    )
    assert "comment" not in observed


def test_declared_training_edge_dedup_is_linear(tmp_path: Path) -> None:
    # Declared and existing edges both grow with scale; a scan per declared edge is quadratic
    # (old code: ratio about 13 here, this code about 4). Sizes stay under the YAML node budget.
    datasets = [f"d{j}" for j in range(40)]

    def run(scale: int) -> None:
        bom = AIBOM()
        bom.dependencies = [
            DependencyEdge.model_construct(
                source_ref=f"x:{i}", target_ref="y", relationship="depends-on"
            )
            for i in range(3000 * scale)
        ]
        names = "".join(
            f"  - name: m{i}\n    training:\n      datasets: [{', '.join(datasets)}]\n"
            for i in range(20 * scale)
        )
        listed = "".join(f"  - name: {d}\n" for d in datasets)
        (tmp_path / "agent.yaml").write_text(f"datasets:\n{listed}models:\n{names}")
        apply_agent_yaml_declarations(bom, tmp_path, relative_path="agent.yaml")
        assert len(bom.dependencies) == 3000 * scale + 800 * scale

    assert scaling_ratio(run) < 8


@pytest.mark.parametrize("reorder", ["exceptions-first", "licence-appended"])
def test_a_reordered_spdx_enum_fails_closed(monkeypatch, reorder: str) -> None:
    from nexus_symbiote.generators import validation

    real = validation._schema("cyclonedx/spdx.schema.json")
    ids = real["enum"]
    cut = ids.index("389-exception")
    if reorder == "exceptions-first":
        reordered = ids[cut:] + ids[:cut]
    else:
        reordered = [i for i in ids if i != "Zlib"] + ["Zlib"]
    monkeypatch.setattr(validation, "_schema", lambda name: real | {"enum": reordered})
    spdx_license_ids.cache_clear()
    try:
        with pytest.raises(ValueError):
            spdx_license_ids()
    finally:
        spdx_license_ids.cache_clear()


def test_a_refused_declared_url_is_reported_not_dropped_silently(tmp_path: Path) -> None:
    _, notices = _declare(
        tmp_path,
        "download_location: http://example.com/agent.tgz\n"
        "datasets:\n  - name: tickets\n    download_location: ftp://example.com/t\n"
        "models:\n  - name: models/clf.safetensors\n"
        f"    download_location: https://{GH_TOKEN}.example.com/m\n",
    )
    assert notices == [
        "agent:a: download_location refused (scheme, credentials or secret)",
        "dataset tickets: download_location refused (scheme, credentials or secret)",
        "model models/clf.safetensors: download_location refused (scheme, credentials or secret)",
    ]
    assert GH_TOKEN not in "".join(notices)


@pytest.mark.parametrize(
    "args",
    [["-f", "cyclonedx"], ["-f", "spdx"], ["-f", "cyclonedx", "--cyclonedx-projection", "2"]],
)
def test_an_observed_http_source_uri_left_out_is_noted(tmp_path: Path, args) -> None:
    bom = _observed()
    bom.get_component("dataset:d").source_uri = "http://data.example.com/tickets.parquet"
    bom.save(tmp_path / "inv.json")
    result = CliRunner().invoke(main, ["export-standard", str(tmp_path / "inv.json"), *args])
    assert result.exit_code == 0, result.output
    noted = "dataset:d: source_uri left out of standard fields" in result.stderr
    assert noted == ("--cyclonedx-projection" not in args)


@pytest.mark.parametrize(
    "declared",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://user:pass@host.example/x",
        "https://example.com/a\x1b[31mb",
    ],
)
def test_a_supplied_declared_download_location_is_cleaned_at_export(declared: str) -> None:
    bom = _observed()
    bom.get_component("dataset:d").source_uri = None
    for comp in bom.components:
        comp.properties["declared_download_location"] = declared
    cdx = CycloneDXGenerator(projection_version=3).generate(bom)
    assert [c["bom-ref"] for c in cdx["components"] if "externalReferences" in c] == []
    spdx = SPDXGenerator(projection_version=4).generate(bom)
    assert [n["name"] for n in spdx["@graph"] if "software_downloadLocation" in n] == []
    clean = "https://example.com/models/clf.safetensors"
    bom.get_component("model:m").properties["declared_download_location"] = clean
    spdx = SPDXGenerator(projection_version=4).generate(bom)
    assert _graph_node(spdx, name="models/clf.safetensors")["software_downloadLocation"] == clean


@pytest.mark.parametrize("char", ["\x1b", "\x00", "\x7f", "\u202e", "\u200b", "\u00e9"])
def test_a_declared_url_with_a_control_or_non_ascii_character_is_refused(char: str) -> None:
    from urllib.parse import quote

    from nexus_symbiote.spdx_profiles import _clean_url

    assert _clean_url(f"https://example.com/a{char}b") is None
    encoded = f"https://example.com/a{quote(char)}b"
    assert _clean_url(encoded) == encoded


def test_a_declaration_named_like_a_component_of_the_other_type_is_a_conflict(
    tmp_path: Path,
) -> None:
    bom = _observed()
    model = bom.get_component("model:m")
    model.version, model.supplier = "1.0.0", "Good Org"
    (tmp_path / "agent.yaml").write_text(
        "datasets:\n  - name: models/clf.safetensors\n"
        "models:\n  - name: models/clf.safetensors\n    version: 9.9.9\n"
        "    supplier: Evil Corp\n  - name: tickets\n",
        encoding="utf-8",
    )
    notices = apply_agent_yaml_declarations(bom, tmp_path, relative_path="agent.yaml")
    assert [c.bom_ref for c in bom.components] == ["agent:a", "model:m", "dataset:d"]
    assert notices == [
        "model:m: dataset name conflict with agent.yaml",
        "model:m: version conflict with agent.yaml",
        "model:m: supplier conflict with agent.yaml",
        "dataset:d: model name conflict with agent.yaml",
    ]
    assert (model.version, model.supplier) == ("1.0.0", "Good Org")
    assert [r.category for r in model.risks] == ["declaration_conflict"] * 3
    assert [r.category for r in bom.get_component("dataset:d").risks] == ["declaration_conflict"]


def test_a_conflict_finding_neutralizes_the_declaration_locator() -> None:
    from nexus_symbiote.spdx_profiles import _conflict_risk

    risk = _conflict_risk("version", "m", "agent\x1b[31m.yaml")
    assert "\x1b" not in risk.detail and "\x1b" not in risk.recommendation


def test_declarations_link_to_both_observed_types_when_names_match(tmp_path: Path) -> None:
    bom = _observed()
    model = bom.get_component("model:m")
    dataset = bom.get_component("dataset:d")
    assert model is not None and dataset is not None
    model.name = dataset.name = "validation"
    (tmp_path / "agent.yaml").write_text(
        'datasets:\n  - name: validation\n    version: "1.0"\n'
        'models:\n  - name: validation\n    version: "2.0"\n'
        "    training:\n      datasets: [validation]\n",
        encoding="utf-8",
    )
    assert apply_agent_yaml_declarations(bom, tmp_path) == []
    assert dataset.properties["declared_version"] == "1.0"
    assert model.properties["declared_version"] == "2.0"
    assert any(
        edge.source_ref == model.bom_ref
        and edge.target_ref == dataset.bom_ref
        and edge.relationship == "trained-on"
        for edge in bom.dependencies
    )


@pytest.mark.parametrize("value", ["[unknown]", "{value: unknown}"])
def test_dataset_omits_non_string_pii_status(tmp_path: Path, value: str) -> None:
    bom, notices = _declare(
        tmp_path,
        "datasets:\n  - name: tickets\n"
        f"    sensitive_personal_information: {value}\n"
        '    version: "1.0"\n',
    )
    dataset = bom.get_component("dataset:d")
    assert dataset is not None and notices == []
    assert dataset.properties["declared_version"] == "1.0"
    assert "declared_sensitive_pii" not in dataset.properties
