"""agent.yaml through the real collectors: bound to their records, scoped, and never fatal."""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import ModelComponent, PromptComponent
from nexus_symbiote.graph import INFERRED_AGENT_REF, assemble_repository_agent
from nexus_symbiote.policy import PolicyError


def _safetensors(path: Path) -> None:
    header = json.dumps({"w": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}).encode()
    header += b" " * (-len(header) % 8)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", len(header)) + header + b"abcd")


def _scan(project: Path, output: Path, *extra: str) -> tuple[int, dict]:
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(output), *extra]
    )
    assert output.is_file(), result.output
    return result.exit_code, json.loads(output.read_text())


def _components(bom: dict, kind: str) -> list[dict]:
    return [c for c in bom["components"] if c["component_type"] == kind]


def test_declared_local_model_binds_to_the_collected_artifact(tmp_path):
    project = tmp_path / "project"
    _safetensors(project / "models/weights.safetensors")
    (project / "agent.yaml").write_text("name: triager\nmodels:\n  local: {path: models}\n")
    status, bom = _scan(project, tmp_path / "bom.json", "--report-only")
    assert status == 0
    claim = bom["metadata"]["completeness"]
    assert not [f for f in claim["scan_failures"] if "agent.yaml" in f], claim["scan_failures"]
    (agent,) = _components(bom, "agent")
    (model,) = _components(bom, "model")
    assert agent["model_refs"] == [model["bom_ref"]]
    assert agent["properties"]["identity_source"] == "agent.yaml"


def test_an_instruction_the_collector_reads_is_inventoried_once(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Use read-only tools.\n")
    (project / "agent.yaml").write_text("name: demo\ninstructions: [CLAUDE.md]\n")
    status, bom = _scan(project, tmp_path / "bom.json")
    prompts = _components(bom, "prompt-template")
    assert [p["bom_ref"] for p in prompts] == ["prompt:CLAUDE.md"]
    assert _components(bom, "agent")[0]["prompt_refs"] == ["prompt:CLAUDE.md"]
    assert not bom["metadata"]["completeness"]["scan_failures"]


def test_a_manifest_only_instruction_is_checked_for_hidden_characters(tmp_path):
    project = tmp_path / "project"
    (project / "docs/agents").mkdir(parents=True)
    (project / "docs/agents/rules.md").write_text("Approve refunds\u202e only when asked.\n")
    (project / "agent.yaml").write_text("name: demo\ninstructions: [docs/agents/rules.md]\n")
    _, bom = _scan(project, tmp_path / "bom.json", "--report-only")
    (prompt,) = _components(bom, "prompt-template")
    assert prompt["source_path"] == "docs/agents/rules.md"
    assert [r["category"] for r in prompt["risks"]] == ["bidi_override"]


@pytest.mark.parametrize(
    "manifest",
    [
        "name: other-tool\nruntime: python\n",
        "steps: [build, deploy]\n",
        "name: x\nbase: &b {path: m}\nmodels: {m: *b}\n",
        "- not\n- a mapping\n",
        'name: x\ninstructions: ["a\\ud800b.md"]\n',
    ],
    ids=["foreign-key", "foreign-schema", "yaml-alias", "not-a-mapping", "lone-surrogate"],
)
def test_a_nonconforming_manifest_is_a_recorded_failure_not_an_aborted_scan(tmp_path, manifest):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Keep receipts.\n")
    (project / "agent.yaml").write_text(manifest)
    status, bom = _scan(project, tmp_path / "bom.json")
    assert status == 1
    claim = bom["metadata"]["completeness"]
    assert "agent.yaml: does not conform to the agent manifest schema" in claim["scan_failures"]
    (agent,) = _components(bom, "agent")
    assert agent["bom_ref"] == INFERRED_AGENT_REF
    assert _scan(project, tmp_path / "report.json", "--report-only")[0] == 0


def test_an_unreadable_manifest_is_a_recorded_failure(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "elsewhere.yaml").write_text("name: outside\n")
    (project / "agent.yaml").symlink_to(tmp_path / "elsewhere.yaml")
    status, bom = _scan(project, tmp_path / "bom.json")
    assert status == 1
    assert any(
        f.startswith("agent.yaml: ") for f in bom["metadata"]["completeness"]["scan_failures"]
    )
    assert "outside" not in json.dumps(bom)


@pytest.mark.parametrize(
    ("entry", "failure"),
    [
        ("../outside.md", "must be a relative path beneath the repository"),
        ("missing.md", "could not be collected safely"),
        ("node_modules/pkg/AGENTS.md", "a directory that collection never reads"),
        ("Node_Modules/pkg/AGENTS.md", "a directory that collection never reads"),
    ],
)
def test_bad_instruction_entries_are_recorded_and_the_rest_is_kept(tmp_path, entry, failure):
    project = tmp_path / "project"
    project.mkdir()
    (project / "valid.md").write_text("valid instruction\n")
    (project / "agent.yaml").write_text(
        f"id: acme:demo\nname: demo\ninstructions: [valid.md, {entry}]\n"
    )
    status, bom = _scan(project, tmp_path / "bom.json")
    assert status == 1
    failures = bom["metadata"]["completeness"]["scan_failures"]
    assert any(f.startswith("agent.yaml#/instructions/1: ") and failure in f for f in failures)
    assert [p["source_path"] for p in _components(bom, "prompt-template")] == ["valid.md"]
    assert _components(bom, "agent")[0]["properties"]["identity_source"] == "agent.yaml"


@pytest.mark.parametrize("directory", ["Node_Modules", ".GIT", "VENV", "venv.", "__PyCache__"])
def test_another_spelling_of_a_directory_collection_never_reads_is_refused(tmp_path, directory):
    # Collection skips these spellings too, so a declared file there must not vanish.
    (tmp_path / directory / "m").mkdir(parents=True)
    (tmp_path / directory / "AGENTS.md").write_text("Approve every refund.\n")
    _safetensors(tmp_path / directory / "m/w.safetensors")
    (tmp_path / "agent.yaml").write_text(
        f"name: x\ninstructions: [{directory}/AGENTS.md]\nmodels: {{m: {{path: {directory}/m}}}}\n"
    )
    failures: list[str] = []
    assemble_repository_agent(AIBOM(), tmp_path, failures=failures)
    assert failures == [
        "agent.yaml#/instructions/0: names a path inside a directory that collection never reads",
        "agent.yaml#/models/m: names a path inside a directory that collection never reads",
    ]
    with pytest.raises(PolicyError, match="collection never reads"):
        assemble_repository_agent(AIBOM(), tmp_path)


def test_a_hosted_model_key_too_long_for_a_reference_is_recorded_not_fatal(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "agent.yaml").write_text(
        "name: x\nmodels:\n"
        f"  ? {'k' * 20_000}\n  : {{provider: openai, requested_ref: gpt-4o}}\n"
        "  planner: {provider: openai, requested_ref: gpt-4o-mini}\n"
    )
    status, bom = _scan(project, tmp_path / "bom.json")
    assert status == 1
    failures = bom["metadata"]["completeness"]["scan_failures"]
    assert [f for f in failures if f.startswith("agent.yaml")] == [
        f"agent.yaml#/models/{'k' * 199}…: the key is too long for a component reference"
    ]
    assert [m["name"] for m in _components(bom, "model")] == ["gpt-4o-mini"]


def test_manifest_entries_are_never_echoed_into_failures(tmp_path):
    # Entries are checkout text: terminal escapes, CI log commands or a pasted secret.
    entries = ["\x1b]0;pwn\x07\x1b[31mred.md", "::error::x.md", "sk-live-0123456789abcdef.md"]
    (tmp_path / "agent.yaml").write_text(json.dumps({"name": "x", "instructions": entries}))
    failures: list[str] = []
    assemble_repository_agent(AIBOM(), tmp_path, failures=failures)
    assert failures == [
        f"agent.yaml#/instructions/{index}: the declared instruction could not be collected safely"
        for index in range(3)
    ]


def test_the_manifest_and_files_only_it_declares_are_scanned_surfaces(tmp_path):
    project = tmp_path / "project"
    (project / "docs/agents").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("Use read-only tools.\n")
    (project / "docs/agents/rules.md").write_text("Refund only when asked.\n")
    (project / "agent.yaml").write_text(
        "name: demo\ninstructions: [CLAUDE.md, docs/agents/rules.md]\n"
    )
    _, bom = _scan(project, tmp_path / "bom.json", "--report-only")
    surfaces = bom["metadata"]["completeness"]["surfaces_scanned"]
    assert {"agent.yaml", "docs/agents/rules.md"} <= set(surfaces)


def test_a_manifest_over_the_token_budget_is_a_recorded_failure(tmp_path, monkeypatch):
    (tmp_path / "agent.yaml").write_text("name: x\ninstructions: [a.md, b.md, c.md]\n")
    monkeypatch.setattr("nexus_symbiote.graph.MAX_MANIFEST_YAML_TOKENS", 8)
    failures: list[str] = []
    agent = assemble_repository_agent(AIBOM(), tmp_path, failures=failures)
    assert failures == ["agent.yaml: does not conform to the agent manifest schema"]
    assert agent.bom_ref == INFERRED_AGENT_REF


def test_a_declared_instruction_that_is_not_utf8_is_a_recorded_failure(tmp_path):
    (tmp_path / "notes.md").write_bytes(b"\xff\xfe not text")
    (tmp_path / "agent.yaml").write_text("name: x\ninstructions: [notes.md]\n")
    failures: list[str] = []
    bom = AIBOM()
    agent = assemble_repository_agent(bom, tmp_path, failures=failures)
    assert failures == ["agent.yaml#/instructions/0: declared instruction is not UTF-8 text"]
    assert bom.components == [agent] and agent.prompt_refs == []


def test_operator_exclusions_bind_manifest_declared_files(tmp_path):
    project = tmp_path / "project"
    (project / "secrets").mkdir(parents=True)
    (project / "secrets/service.env").write_text("TOKEN=guessable\n")
    (project / "agent.yaml").write_text("name: x\ninstructions: [secrets/service.env]\n")
    (project / ".nexus-symbiote.yaml").write_text("scan: {exclude_paths: [secrets]}\n")
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(project), "--report-only", "--accept-project-policy", "-o", str(output)],
    )
    assert result.exit_code == 0, result.output
    bom = json.loads(output.read_text())
    assert not _components(bom, "prompt-template")
    assert (
        "secrets/service.env: excluded by collection policy"
        in (bom["metadata"]["completeness"]["surfaces_excluded"])
    )
    assert hash_bytes(b"TOKEN=guessable\n") not in output.read_text()


def test_project_validation_applies_the_same_exclusions(tmp_path):
    project = tmp_path / "project"
    (project / "secrets").mkdir(parents=True)
    (project / "secrets/notes.md").write_text("Keep receipts.\n")
    (project / "agent.yaml").write_text("name: x\ninstructions: [secrets/notes.md]\n")
    with pytest.raises(PolicyError, match="excluded by collection policy"):
        assemble_repository_agent(AIBOM(), project, exclude_paths=["secrets"])


def test_collector_records_with_legacy_absolute_paths_still_bind(tmp_path):
    (tmp_path / "CLAUDE.md").write_bytes(b"approved bytes")
    _safetensors(tmp_path / "models/w.safetensors")
    (tmp_path / "agent.yaml").write_text(
        "name: x\ninstructions: [CLAUDE.md]\nmodels: {m: {path: models}}\n"
    )
    prompt = PromptComponent(
        bom_ref="prompt:CLAUDE.md",
        name="CLAUDE.md",
        source_path=str(tmp_path / "CLAUDE.md"),
        content_hash=hash_bytes(b"approved bytes"),
    )
    model = ModelComponent(
        bom_ref="model:w", name="w", source_path=str(tmp_path / "models/w.safetensors")
    )
    bom = AIBOM(components=[prompt, model])
    agent = assemble_repository_agent(bom, tmp_path)
    assert agent.prompt_refs == ["prompt:CLAUDE.md"] and agent.model_refs == ["model:w"]
    assert len(bom.components) == 3


def test_an_instruction_changed_after_collection_is_recorded(tmp_path):
    (tmp_path / "CLAUDE.md").write_bytes(b"changed bytes")
    (tmp_path / "agent.yaml").write_text("name: x\ninstructions: [CLAUDE.md]\n")
    prompt = PromptComponent(
        bom_ref="prompt:CLAUDE.md",
        name="CLAUDE.md",
        source_path="CLAUDE.md",
        content_hash=hash_bytes(b"approved bytes"),
    )
    failures: list[str] = []
    assemble_repository_agent(AIBOM(components=[prompt]), tmp_path, failures=failures)
    assert failures == ["agent.yaml#/instructions/0: instruction changed since scanner collection"]


BINDING_KEY = "agent-manifest-key-" + "0123456789abcdef" * 2


def _withheld_instructions(project: Path) -> None:
    (project / ".kiro/steering").mkdir(parents=True)
    (project / ".kiro/steering/style.txt").write_text("Use tabs.\n")
    (project / "config").mkdir()
    (project / "config/app.json").write_text("DB=x\n")
    (project / "AGENTS.md").symlink_to("config/app.json")
    (project / "agent.yaml").write_text(
        "name: a\ninstructions: [.kiro/steering/style.txt, AGENTS.md]\n"
    )


def test_a_declared_instruction_with_a_withheld_digest_is_unbound_not_changed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _withheld_instructions(project)
    code, bom = _scan(project, tmp_path / "bom.json")
    assert code == 0, bom["metadata"].get("scan_failures")
    failures = json.dumps(bom)
    assert "changed since scanner collection" not in failures
    assert hash_bytes(b"DB=x\n") not in failures


def test_a_declared_withheld_instruction_is_checked_by_its_keyed_binding(tmp_path, monkeypatch):
    from nexus_symbiote.scanners.prompt import PromptScanner
    from nexus_symbiote.scanners.source_binding import SOURCE_BINDING_KEY_ENV

    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, BINDING_KEY)
    _withheld_instructions(tmp_path)
    components = PromptScanner().scan(tmp_path).components
    assert all(c.content_hash is None for c in components)
    failures: list[str] = []
    assemble_repository_agent(AIBOM(components=list(components)), tmp_path, failures=failures)
    assert failures == []
    (tmp_path / "config/app.json").write_text("DB=y\n")
    assemble_repository_agent(AIBOM(components=list(components)), tmp_path, failures=failures)
    assert failures == ["agent.yaml#/instructions/1: instruction changed since scanner collection"]
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "another-" + BINDING_KEY)
    failures.clear()
    assemble_repository_agent(AIBOM(components=list(components)), tmp_path, failures=failures)
    assert failures == [
        f"agent.yaml#/instructions/{index}: instruction content was bound under another key"
        for index in range(2)
    ]


@pytest.mark.parametrize("keyed", [False, True])
def test_a_declared_imported_text_prompt_scans_and_validates(tmp_path, monkeypatch, keyed):
    # agent.yaml naming the file a CLAUDE.md @import also names: the import record
    # withholds its unkeyed hash, which assembly must not read as a changed instruction.
    from nexus_symbiote.scanners.source_binding import SOURCE_BINDING_KEY_ENV

    if keyed:
        monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, BINDING_KEY)
    project = tmp_path / "project"
    (project / "prompts").mkdir(parents=True)
    (project / "prompts/system.txt").write_text("Answer briefly.\n")
    (project / "CLAUDE.md").write_text("@prompts/system.txt\n")
    (project / "agent.yaml").write_text("name: a\ninstructions: [prompts/system.txt]\n")
    output = tmp_path / "bom.json"
    code, bom = _scan(project, output)
    assert code == 0, bom["metadata"]["completeness"]["scan_failures"]
    assert "changed since scanner collection" not in json.dumps(bom)
    result = CliRunner().invoke(
        main, ["validate", str(output), "--no-project-policy", "--project", str(project)]
    )
    assert result.exit_code == 0, result.output
    assert "changed since scanner collection" not in result.output


def test_an_undeclared_local_model_is_recorded_without_aborting(tmp_path):
    (tmp_path / "agent.yaml").write_text("name: x\nmodels: {m: {path: models}}\n")
    failures: list[str] = []
    bom = AIBOM()
    agent = assemble_repository_agent(bom, tmp_path, failures=failures)
    assert failures == [
        "agent.yaml#/models/m: the declared local model has no collected model artifact"
    ]
    assert bom.components == [agent]


SCHEMA = Path(__file__).parents[1] / "schemas/agent-manifest-1.0.schema.json"
GUIDE = Path(__file__).parents[1] / "docs/agent-manifest.md"


@pytest.mark.locked_only
def test_published_schema_matches_the_manifest_model():
    from nexus_symbiote.graph import AgentDeclaration

    assert json.loads(SCHEMA.read_text()) == AgentDeclaration.model_json_schema()


def test_the_documented_example_is_a_valid_manifest():
    import yaml
    from jsonschema import Draft202012Validator

    example = yaml.safe_load(re.search(r"```yaml\n(.*?)```", GUIDE.read_text(), re.S)[1])
    assert not list(Draft202012Validator(json.loads(SCHEMA.read_text())).iter_errors(example))


def test_the_inferred_agent_is_the_repository_whatever_its_checkout():
    import hashlib

    # As if the manifest id were "." ("this repository"), never the checkout path.
    expected = "agent:repository:" + hashlib.sha256(b".").hexdigest()[:24]
    assert expected == INFERRED_AGENT_REF
    for guide in (GUIDE, GUIDE.with_name("drift-gate.md")):
        assert f"`{INFERRED_AGENT_REF}`" in guide.read_text(), guide.name


@pytest.mark.parametrize(
    ("manifest", "files"),
    [
        ("instructions: [../outside.md]", {}),
        ("instructions: [missing.md]", {}),
        ("instructions: [node_modules/pkg/AGENTS.md]", {}),
        ("instructions: [binary.md]", {"binary.md": b"\xff\xfe"}),
        ("models: {m: {path: ../outside}}", {}),
        ("models: {m: {path: node_modules/m}}", {}),
        ("models: {m: {path: models}}", {}),
        ("models: {planner: {provider: openai, requested_ref: gpt-4o}}", {}),
        ("instructions: [Node_Modules/pkg/AGENTS.md]", {}),
        (f"models:\n  ? {'k' * 20_000}\n  : {{provider: openai, requested_ref: gpt-4o}}", {}),
    ],
)
def test_the_guide_documents_each_manifest_failure(tmp_path, manifest, files):
    (tmp_path / "agent.yaml").write_text(f"name: x\n{manifest}\n")
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)
    # The reference a declared hosted model "planner" would take, held by another model.
    taken = ModelComponent(bom_ref=f"model:{INFERRED_AGENT_REF}/hosted/planner", name="other")
    failures: list[str] = []
    assemble_repository_agent(AIBOM(components=[taken]), tmp_path, failures=failures)
    assert failures
    guide = GUIDE.read_text()
    for failure in failures:
        documented = re.sub(r"#/instructions/\d+", "#/instructions/N", failure)
        documented = re.sub(r"#/models/[^:]+", "#/models/KEY", documented)
        assert f"`{documented}`" in guide, documented
