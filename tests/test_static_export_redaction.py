"""Recognized credentials in static display fields never reach inventories or exports."""

from __future__ import annotations

import json

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import AgentComponent, ModelComponent, RAGSourceComponent
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.generators.recovery import recover_export
from nexus_symbiote.generators.validation import (
    validate_cyclonedx,
    validate_sarif,
    validate_spdx,
)
from nexus_symbiote.graph import assemble_repository_agent
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.scanners.source_binding import SOURCE_BINDING_KEY_ENV

HF_TOKEN = "hf_" + "A1" * 18
NPM_TOKEN = "npm_" + "B2" * 18
ANTHROPIC_TOKEN = "".join(("sk-ant-", "api03-", "0123456789abcdefABCDEF0123456789"))
PASSWORD = "synthetic-static-password-12345"  # noqa: S105 - synthetic sentinel
SECRET_TEXT = (HF_TOKEN, NPM_TOKEN, ANTHROPIC_TOKEN, f"password: {PASSWORD}")
MANIFEST_FIELDS = ("name", "version", "framework", "owner", "purpose")
RAG_FIELDS = (
    "type",
    "store_type",
    "embedding_model",
    "embeddings",
    "chunking_strategy",
    "chunk_size",
    "index_name",
    "collection",
    "collection_name",
    "namespace",
)


@pytest.mark.parametrize("text", SECRET_TEXT)
def test_manifest_display_fields_mask_recognized_credentials(tmp_path, text):
    (tmp_path / "agent.yaml").write_text(json.dumps(dict.fromkeys(MANIFEST_FIELDS, text)))
    bom = AIBOM()
    agent = assemble_repository_agent(bom, tmp_path)
    assert text not in bom.model_dump_json()
    for field in ("name", "version", "framework", "supplier", "description"):
        assert "***" in getattr(agent, field)


@pytest.mark.parametrize("field", RAG_FIELDS)
@pytest.mark.parametrize("text", SECRET_TEXT)
def test_rag_identifiers_mask_recognized_credentials_and_report_unbound_values(
    tmp_path, field, text
):
    source = {"name": "knowledge", "sanitization": True}
    if field == "chunk_size":
        source["chunking_strategy"] = "fixed"
    source[field] = {"model": text} if field == "embeddings" else text
    (tmp_path / "rag_config.json").write_text(json.dumps(source))
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = [c for c in result.components if isinstance(c, RAGSourceComponent)]
    assert text not in component.model_dump_json()
    assert "[redacted]" in component.model_dump_json()
    assert any(risk.category == "completeness" for risk in component.risks)


@pytest.mark.parametrize("token", [HF_TOKEN, NPM_TOKEN, ANTHROPIC_TOKEN])
def test_credential_shaped_plain_path_is_redacted(tmp_path, token):
    source = {"name": "knowledge", "source_uris": [token], "sanitization": True}
    (tmp_path / "rag_config.json").write_text(json.dumps(source))
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = [c for c in result.components if isinstance(c, RAGSourceComponent)]
    assert component.source_uris == ["[redacted]"]
    assert token not in component.model_dump_json()
    assert any(risk.category == "completeness" for risk in component.risks)


def test_manifest_names_keep_ordinary_token_shapes_and_purpose_does_not(tmp_path):
    # Identity fields use the identifier rule, which keeps names such as an sk- prefix.
    name = "sk-research-assistant-agent"
    declaration = {"name": name, "owner": name, "purpose": f"key {name}-0123456789"}
    (tmp_path / "agent.yaml").write_text(json.dumps(declaration))
    agent = assemble_repository_agent(AIBOM(), tmp_path)
    assert agent.name == name and agent.supplier == name
    assert agent.description is not None and "***" in agent.description


def test_ordinary_manifest_and_rag_values_are_preserved(tmp_path):
    declaration = {
        "name": "knowledge-agent",
        "version": "1.2.3",
        "framework": "custom",
        "owner": "Research team",
        "purpose": "Answer questions from reviewed notes",
    }
    (tmp_path / "agent.yaml").write_text(json.dumps(declaration))
    agent = assemble_repository_agent(AIBOM(), tmp_path)
    assert agent.name == declaration["name"] and agent.version == declaration["version"]
    assert agent.framework == declaration["framework"] and agent.supplier == declaration["owner"]
    assert agent.description == declaration["purpose"]
    source = {
        "name": "knowledge",
        "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
        "namespace": "notes-v1",
        "source_uris": ["docs/reference.md"],
        "sanitization": True,
    }
    (tmp_path / "rag_config.json").write_text(json.dumps(source))
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = [c for c in result.components if isinstance(c, RAGSourceComponent)]
    assert component.embedding_model_name == source["embedding_model"]
    assert component.source_uris == source["source_uris"]
    assert component.properties["index_identities"] == {"namespace": "notes-v1"}
    assert not any(risk.category == "completeness" for risk in component.risks)


OWNERS = ("https://github.com/acme-platform", "https://github.com/another-org")


def _manifest_agents(tmp_path):
    agents = []
    for owner in OWNERS:
        (tmp_path / "agent.yaml").write_text(json.dumps({"name": "bot", "owner": owner}))
        agents.append(assemble_repository_agent(AIBOM(), tmp_path))
    return agents


def test_a_redacted_manifest_field_is_named_as_unbound_without_the_key(tmp_path):
    before, after = _manifest_agents(tmp_path)
    # The export cuts the URL to its origin, so the two records show the same owner.
    assert before.supplier == after.supplier == "https://github.com"
    for agent in (before, after):
        assert "static_value_binding" not in agent.properties
        (finding,) = [risk for risk in agent.risks if risk.category == "completeness"]
        assert "values not bound in this inventory: owner" in finding.detail
    report = AIBOMDiffer().diff(_inventory(before), _inventory(after))
    assert any("unbound" in alert["alert"] for alert in report.security_alerts)


def test_keyed_binding_detects_a_redacted_manifest_field_change(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "static-export-binding-key-0123456789abcdef")
    before, after = _manifest_agents(tmp_path)
    assert before.supplier == after.supplier == "https://github.com"
    for agent in (before, after):
        assert not any(risk.category == "completeness" for risk in agent.risks)
        assert (
            agent.properties["static_value_binding_profile"]
            == "nexus-symbiote/agent-manifest-values/v1"
        )
    assert before.properties["static_value_binding"] != after.properties["static_value_binding"]
    report = AIBOMDiffer().diff(_inventory(before), _inventory(after))
    assert any("static_value_binding changed" in alert["alert"] for alert in report.security_alerts)
    (same,) = _manifest_agents(tmp_path)[:1]
    assert same.properties["static_value_binding"] == before.properties["static_value_binding"]


def test_a_manifest_that_redaction_leaves_alone_carries_no_binding_or_finding(
    tmp_path, monkeypatch
):
    for key in ("", "static-export-binding-key-0123456789abcdef"):
        monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
        (tmp_path / "agent.yaml").write_text(json.dumps({"name": "bot", "owner": "Research team"}))
        agent = assemble_repository_agent(AIBOM(), tmp_path)
        assert "static_value_binding" not in agent.properties
        assert not agent.risks


def _inventory(agent):
    return AIBOM(components=[agent])


def test_keyed_binding_still_detects_a_redacted_rag_identifier_change(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "static-export-binding-key-0123456789abcdef")
    records = []
    for token in (HF_TOKEN, "hf_" + "C3" * 18):
        (tmp_path / "rag_config.json").write_text(
            json.dumps({"name": "knowledge", "embedding_model": token, "sanitization": True})
        )
        result = RAGScanner().scan(tmp_path)
        assert not result.scan_failures
        (component,) = [c for c in result.components if isinstance(c, RAGSourceComponent)]
        assert component.embedding_model_name == "[redacted]"
        assert not any(risk.category == "completeness" for risk in component.risks)
        records.append(component)
    before, after = records
    assert before.properties["static_config_hash"] == after.properties["static_config_hash"]
    assert before.properties["static_value_binding"] != after.properties["static_value_binding"]


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx", "sarif"])
@pytest.mark.parametrize("keyed", [False, True])
def test_static_credentials_reach_no_cli_export(
    tmp_path, runner, monkeypatch, output_format, keyed
):
    if keyed:
        monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "static-export-binding-key-0123456789abcdef")
    project = tmp_path / "project"
    project.mkdir()
    (project / "agent.yaml").write_text(
        json.dumps({"name": "knowledge-agent", "purpose": f"Authorization: Bearer {HF_TOKEN}"})
    )
    (project / "rag_config.json").write_text(
        json.dumps(
            {
                "name": "knowledge",
                "embedding_model": HF_TOKEN,
                "namespace": f"password: {PASSWORD}",
                "source_uris": [NPM_TOKEN, ANTHROPIC_TOKEN],
                "sanitization": True,
            }
        )
    )
    output = tmp_path / "inventory.json"
    result = runner.invoke(
        main,
        ["scan", str(project), "--no-project-policy", "-f", output_format, "-o", str(output)],
    )
    assert result.exit_code == 0, result.output
    exported = output.read_text()
    assert all(
        secret not in exported + result.output
        for secret in (HF_TOKEN, NPM_TOKEN, ANTHROPIC_TOKEN, PASSWORD)
    )
    document = json.loads(exported)
    if output_format == "sarif":
        assert validate_sarif(document) == []
        return
    if output_format == "json":
        bom = AIBOM.model_validate(document)
    else:
        validator = validate_cyclonedx if output_format == "cyclonedx" else validate_spdx
        assert validator(document) == []
        bom = recover_export(exported)
    agent = next(c for c in bom.components if isinstance(c, AgentComponent))
    rag = next(c for c in bom.components if isinstance(c, RAGSourceComponent))
    assert agent.description == "Authorization: Bearer ***"
    assert rag.embedding_model_name == "[redacted]"
    assert rag.source_uris == ["[redacted]", "[redacted]"]
    assert rag.properties["source_values_bound"] is keyed
    assert any(risk.category == "completeness" for risk in rag.risks) is not keyed


GITHUB_TOKEN = "ghp_" + "C3" * 18
OPENAI_TOKEN = "sk-proj-" + "D4e5" * 10


def test_agent_manifest_hosted_model_fields_are_redacted(tmp_path, runner):
    project = tmp_path / "project"
    project.mkdir()
    (project / "agent.yaml").write_text(
        json.dumps(
            {
                "name": "helper",
                "models": {
                    "primary": {
                        "provider": f"openai api_key={OPENAI_TOKEN}",
                        "requested_ref": f"gpt-4o?token={GITHUB_TOKEN}",
                    },
                    GITHUB_TOKEN: {"provider": "openai", "requested_ref": OPENAI_TOKEN},
                    "planner": {"provider": "anthropic", "requested_ref": "claude-sonnet-4-5"},
                    "sk-research-assistant": {
                        "provider": "openai",
                        "requested_ref": "openai/gpt-4o-mini",
                    },
                },
            }
        )
    )
    inventory = tmp_path / "inventory.json"
    scanned = runner.invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(inventory)]
    )
    assert scanned.exit_code == 0, scanned.output
    outputs = [inventory.read_text(), scanned.output]
    for output_format, validator in (("cyclonedx", validate_cyclonedx), ("spdx", validate_spdx)):
        exported = tmp_path / f"inventory.{output_format}.json"
        result = runner.invoke(
            main, ["export-standard", str(inventory), "-f", output_format, "-o", str(exported)]
        )
        assert result.exit_code == 0, result.output
        assert validator(json.loads(exported.read_text())) == []
        outputs += [exported.read_text(), result.output]
    for output in outputs:
        assert GITHUB_TOKEN not in output
        assert OPENAI_TOKEN not in output

    bom = AIBOM.model_validate_json(outputs[0])
    hosted = {
        c.bom_ref.rsplit("/", 1)[1]: (c.name, c.provider, c.requested_alias)
        for c in bom.components
        if isinstance(c, ModelComponent) and c.model_type == "hosted"
    }
    assert hosted == {
        "primary": ("gpt-4o?token=***", "openai api_key=***", "gpt-4o?token=***"),
        "planner": ("claude-sonnet-4-5", "anthropic", "claude-sonnet-4-5"),
        "sk-research-assistant": ("openai/gpt-4o-mini", "openai", "openai/gpt-4o-mini"),
    }
    assert "agent.yaml#/models: a model key is shaped like a credential" in (
        bom.metadata.completeness.scan_failures
    )
