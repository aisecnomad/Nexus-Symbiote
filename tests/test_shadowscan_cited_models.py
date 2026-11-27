"""A merged scan names a model only from a cited line it reads itself.

The report says where a model identifier is. The scan re-reads that file and line
with its own confined reader, and records the identifier when it stands there as a
whole identifier outside anything the redactor withholds. The name in the inventory
is therefore text both the report and the repository state, never text only one does.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits, minimum_elements
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, TrustTier
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners import shadowscan
from nexus_symbiote.scanners.shadowscan import (
    EVIDENCE_CLAIM,
    MODEL_REF_PREFIX,
    PROJECTION_PROFILE,
    ShadowScanImporter,
    names_whole_identifier,
)
from nexus_symbiote.validators.completeness import assurance_problems
from tests.support import scaling_ratio

MODEL = "gpt-4o-mini"
SOURCE = f'import openai\n\nreply = client.chat(model="{MODEL}")\n'
UNNAMED = "1 model evidence entries were not confirmed at a cited file and line; they are not named"


def _evidence(location, literal, signal="model:provider.openai", **extra):
    return {
        "signal": signal,
        "description": "model id matched",
        "location": location,
        "attributes": {"category": "provider", "value": literal},
        **extra,
    }


def _report(*evidence, findings=None, finished="2026-01-01T00:00:01Z"):
    findings = findings or [list(evidence)]
    return {
        "version": "0.1.4",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": finished,
        "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
        "stats": [
            {
                "connector": "code.filesystem",
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": finished,
                "errors": [],
                "skipped": False,
                "incomplete": False,
            }
        ],
        "findings": [
            {"id": f"ss-{index}", "kind": "agent", "surface": "code", "evidence": items}
            for index, items in enumerate(findings)
        ],
    }


def _project(tmp_path, report, files=None):
    project = tmp_path / "proj"
    for name, text in (files or {"app.py": SOURCE}).items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode())
    project.mkdir(exist_ok=True)
    (project / "shadowscan.json").write_text(json.dumps(report))
    return project


def _models(result):
    return [c for c in result.components if c.bom_ref.startswith(MODEL_REF_PREFIX)]


def _scan(tmp_path, report, files=None):
    return ShadowScanImporter().scan(_project(tmp_path, report, files))


def test_cited_model_is_named_from_the_line_the_scan_reads(tmp_path):
    result = _scan(tmp_path, _report(_evidence("app.py:3", MODEL)))
    (model,) = _models(result)
    assert model.name == MODEL
    assert model.bom_ref == MODEL_REF_PREFIX + hashlib.sha256(MODEL.encode()).hexdigest()
    assert (model.assurance_level, model.trust_tier) == (
        AssuranceLevel.DECLARED,
        TrustTier.UNKNOWN,
    )
    # The cited file is not the model's weight file, so the record names no source path.
    assert (model.source_path, model.hashes) == (None, {})
    assert (model.provider, model.model_type, model.version) == (None, None, None)
    assert model.properties == {
        "collection_mode": "imported-unverified-report",
        "shadowscan:projection-profile": PROJECTION_PROFILE,
        "shadowscan:kind": "model",
        "shadowscan:signals": ["model:provider.openai"],
    }
    claim = model.claims[EVIDENCE_CLAIM]
    assert (claim.assurance, claim.method, claim.locator, claim.evidence_refs) == (
        AssuranceLevel.DECLARED,
        "cited-line-reread",
        "app.py:3",
        ["app.py:3"],
    )
    assert result.source_projection_limitations is not None
    assert not any("not confirmed" in text for text in result.source_projection_limitations)
    assert not result.scan_failures


@pytest.mark.parametrize(
    ("line", "literal"),
    [
        (f'model = "{MODEL}"', MODEL),
        (f"MODEL={MODEL}", MODEL),
        (f"llm: anthropic/{MODEL}", MODEL),
        (f"agent = Agent('openai:{MODEL}')", MODEL),
        (f"We call {MODEL}.", MODEL),
        (f"{MODEL}: primary", MODEL),
        (f"  - {MODEL}\r", MODEL),
        ("id = cohere/rerank-english-v3.0", "cohere/rerank-english-v3.0"),
        (f'models = ["{MODEL}-2024-07-18", "{MODEL}"]', MODEL),
        (
            'model = "anthropic.claude-3-5-haiku-20241022-v1:0"',
            "anthropic.claude-3-5-haiku-20241022-v1:0",
        ),
    ],
)
def test_a_whole_identifier_is_recognised(line, literal):
    assert names_whole_identifier(line.removesuffix("\r"), literal)


@pytest.mark.parametrize(
    ("line", "literal"),
    [
        ("FROM qwen2.5-coder:7b", "qwen2.5-coder"),
        ("FROM qwen2.5-coder:7b", "qwen2.5"),
        ('model = "gpt-4o-mini-2024-07-18"', MODEL),
        ("id = cohere/rerank-english-v3.0", "cohere"),
        ("id = cohere/rerank-english-v3.0", "rerank-english-v3"),
        (f"x{MODEL}", MODEL),
        (f"my-{MODEL}", MODEL),
        (f"vendor.{MODEL}", MODEL),
        (f"{MODEL}_v2", MODEL),
        (f"{MODEL}@2024", MODEL),
        ("nothing here", MODEL),
        ("", MODEL),
        ('model = "gpt-4o"', "gpt-4"),
        (f"{MODEL}2", MODEL),
        (f"7{MODEL}", MODEL),
        (f"my_{MODEL}", MODEL),
        (f"user@{MODEL}", MODEL),
        (f"c+{MODEL}", MODEL),
        (f"{MODEL}+tools", MODEL),
        ("ollama run llama3:latest", "llama3"),
        ("MODEL = GPT-4O-MINI", MODEL),
        ("FROM command-r7b:7b", "command-r"),
        ("FROM codestral:latest", "codestral"),
    ],
)
def test_part_of_a_longer_identifier_is_not_a_name(line, literal):
    assert not names_whole_identifier(line, literal)


@pytest.mark.parametrize(
    "evidence",
    [
        _evidence("app.py:1", MODEL),
        _evidence("app.py:4", MODEL),
        _evidence("app.py:9999999", MODEL),
        _evidence("app.py:0", MODEL),
        _evidence("app.py:03", MODEL),
        _evidence("app.py", MODEL),
        _evidence("missing.py:3", MODEL),
        _evidence("../outside.py:1", MODEL),
        _evidence("sub/../app.py:3", MODEL),
        _evidence("./app.py:3", MODEL),
        _evidence("/etc/hostname:1", MODEL),
        _evidence("sub\\app.py:3", MODEL),
        _evidence("link.py:1", MODEL),
        _evidence("app.py:3", "gpt-4o"),
        _evidence("app.py:3", "gpt-4o-"),
        _evidence("app.py:3", 'model="gpt-4o-mini"'),
        _evidence("app.py:3", "chat(model"),
        _evidence("app.py:3", "g"),
        _evidence("app.py:3", "2024"),
        _evidence("app.py:3", "x" * 129),
        _evidence("app.py:3", MODEL, signal="model:Provider OpenAI"),
        _evidence("app.py:3", MODEL, signal="model:"),
        {"signal": "model:provider.openai", "location": "app.py:3"},
        {"signal": "model:provider.openai", "location": "app.py:3", "attributes": {"value": 7}},
        {"signal": "model:provider.openai", "location": 3, "attributes": {"value": MODEL}},
    ],
)
def test_evidence_the_scan_cannot_confirm_names_nothing(tmp_path, evidence):
    outside = tmp_path / "outside.py"
    outside.write_text(f'model = "{MODEL}"\n')
    project = _project(tmp_path, _report(evidence))
    os.symlink(outside, project / "link.py")
    result = ShadowScanImporter().scan(project)
    assert not _models(result)
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED
    assert not result.scan_failures


def _line_of(text, row):
    return next(n for n, line in enumerate(text.split("\n"), 1) if line.strip() == row)


def _line_holding(text, part):
    return next(n for n, line in enumerate(text.split("\n"), 1) if part in line)


def test_the_report_does_not_confirm_its_own_citations(tmp_path):
    # A pretty-printed report holds each cited identifier on a line of its own.
    report = _report(_evidence("shadowscan.json:1", MODEL))
    row = f'"value": "{MODEL}"'
    line = _line_of(json.dumps(report, indent=1), row)
    for cited in ("shadowscan.json", "alias.json", "hard.json", "copy.json"):
        report["findings"][0]["evidence"][0]["location"] = f"{cited}:{line}"
        project = tmp_path / cited / "proj"
        project.mkdir(parents=True)
        text = json.dumps(report, indent=1)
        assert text.split("\n")[line - 1].strip() == row
        (project / "shadowscan.json").write_text(text)
        (project / "copy.json").write_text(text)
        os.symlink("shadowscan.json", project / "alias.json")
        os.link(project / "shadowscan.json", project / "hard.json")
        result = ShadowScanImporter().scan(project)
        assert result.source_report_digest and not _models(result), cited
        assert result.source_projection_limitations is not None
        assert result.source_projection_limitations[-1] == UNNAMED


def test_a_report_read_through_a_link_does_not_confirm_itself(tmp_path):
    report = _report(_evidence("real.json:1", MODEL))
    row = f'"value": "{MODEL}"'
    line = _line_of(json.dumps(report, indent=1), row)
    report["findings"][0]["evidence"][0]["location"] = f"real.json:{line}"
    project = tmp_path / "proj"
    project.mkdir()
    (project / "real.json").write_text(json.dumps(report, indent=1))
    os.symlink("real.json", project / "shadowscan.json")
    result = ShadowScanImporter().scan(project)
    assert result.source_report_digest and not _models(result)


RESTATED = [
    {"bomFormat": "CycloneDX", "specVersion": "1.7", "name": MODEL},
    {"spdxVersion": "SPDX-2.3", "name": MODEL},
    {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [], "name": MODEL},
    {"version": "2.1.0", "runs": [], "name": MODEL},
    {"findings": [], "name": MODEL},
    {"metadata": {}, "components": [], "name": MODEL},
]


@pytest.mark.parametrize("document", RESTATED, ids=lambda d: sorted(d)[0])
def test_a_bill_of_materials_or_scan_report_confirms_nothing(tmp_path, document):
    text = json.dumps(document, indent=1)
    line = _line_of(text, f'"name": "{MODEL}"')
    report = _report(_evidence(f"out/earlier.json:{line}", MODEL))
    result = _scan(tmp_path, report, {"out/earlier.json": "\ufeff" + text})
    assert not _models(result)
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED


def _unparseable(text):
    """The same document in forms that are not one JSON value, or not strict JSON."""
    name = f'"name": "{MODEL}"'
    return {
        "duplicate-key": text.replace(name, f'"name": "x",\n {name}'),
        "trailing-comma": text.replace(name, name + ","),
        "two-documents": text + "\n" + text,
        "second-document-is-the-report": '{"note": "first"}\n' + text,
        "comment-inside": text.replace(name, f"// kept\n {name}"),
        "space-before-the-colon": text.replace(name, name + ",").replace('": ', '" : '),
    }


@pytest.mark.parametrize("document", RESTATED, ids=lambda d: sorted(d)[0])
@pytest.mark.parametrize("form", sorted(_unparseable("")))
def test_a_report_that_is_not_one_strict_json_object_confirms_nothing(tmp_path, document, form):
    written = _unparseable(json.dumps(document, indent=1))[form]
    name = f'"name": "{MODEL}"'
    name = name.replace('": ', '" : ') if form == "space-before-the-colon" else name
    with pytest.raises(ValueError):
        shadowscan.parse_json_strict(written)
    line = _line_holding(written, name)
    report = _report(_evidence(f"out/earlier.json:{line}", MODEL))
    result = _scan(tmp_path, report, {"out/earlier.json": written})
    assert not _models(result)
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED


@pytest.mark.parametrize("document", RESTATED, ids=lambda d: sorted(d)[0])
def test_in_a_top_level_array_only_a_bill_of_materials_confirms_nothing(tmp_path, document):
    # A row of a benchmark matrix has `runs` and a list of screens has `components`, so in
    # an array only the three names that no ordinary file uses make a member a report.
    written = json.dumps([{"note": "wrapped"}, document], indent=1)
    line = _line_holding(written, f'"name": "{MODEL}"')
    report = _report(_evidence(f"out/earlier.json:{line}", MODEL))
    result = _scan(tmp_path, report, {"out/earlier.json": written})
    restated = not set(document).isdisjoint({"bomFormat", "spdxVersion", "@graph"})
    assert [model.name for model in _models(result)] == ([] if restated else [MODEL])


def test_an_ordinary_json_file_confirms_an_identifier(tmp_path):
    text = json.dumps({"name": "lead-enrichment", "nodes": [{"model": MODEL}]}, indent=1)
    line = _line_of(text, f'"model": "{MODEL}"')
    result = _scan(tmp_path, _report(_evidence(f"flow.json:{line}", MODEL)), {"flow.json": text})
    assert [model.name for model in _models(result)] == [MODEL]


NESTED = '"layout": {"components": ["a"], "runs": 2, "findings": []}'
ORDINARY = {
    "strict-json-with-a-nested-key": f'{{\n {NESTED},\n "model": "{MODEL}"\n}}\n',
    "array-of-rows": f'[\n {{"model": "{MODEL}"}},\n {{"model": "other"}}\n]\n',
    "array-of-rows-with-a-generic-key": (
        f'[\n {{\n  "model": "{MODEL}",\n  "runs": 5,\n  "components": 2\n }}\n]\n'
    ),
    "trailing-comma-and-a-nested-key": f'{{\n {NESTED},\n "model": "{MODEL}",\n}}\n',
    "comment-and-a-nested-key": f'{{\n // editor settings\n {NESTED},\n "model": "{MODEL}"\n}}\n',
    "integer-past-2-to-the-53": f'{{\n "id": 9007199254740993,\n {NESTED},\n "model": "{MODEL}"\n}}\n',
    "json-lines-with-a-nested-key": f'{{"model": "{MODEL}"}}\n{{"row": {{"runs": 3}}}}\n',
    "readme-that-opens-with-a-link": (
        f"[![build](https://ci.example/badge.svg)](https://ci.example)\n\n"
        f'We call "model": "{MODEL}" and return {{"findings": []}}.\n'
    ),
    "template-that-opens-with-a-brace": (
        f'{{% set reply = {{"findings": []}} %}}\nUse "model": "{MODEL}" here.\n'
    ),
    "log-that-opens-with-a-bracket": f'[2026-11-19] "runs": 4 "model": "{MODEL}"\n',
}


@pytest.mark.parametrize("name", sorted(ORDINARY))
def test_text_that_starts_like_json_and_is_no_report_still_confirms(tmp_path, name):
    text = ORDINARY[name]
    line = _line_holding(text, f'"model": "{MODEL}"')
    result = _scan(tmp_path, _report(_evidence(f"cfg.json:{line}", MODEL)), {"cfg.json": text})
    assert [model.name for model in _models(result)] == [MODEL]


def test_the_two_readers_of_the_report_rule_agree_on_json(tmp_path):
    documents = [
        *RESTATED,
        [{"note": 1}, RESTATED[0]],
        [{"note": 1}, RESTATED[4]],
        {"a": {"components": 1}},
        [[{"findings": []}]],
        [1, "findings", {"x": {"runs": []}}],
        {"text": 'a "findings": b', "list": [{"components": 2}]},
        {},
        [],
    ]
    for document in documents:
        raw = json.dumps(document, indent=1).encode()
        whole = shadowscan._restates_a_scan(raw)
        assert shadowscan._restated_in_tokens(raw) is whole, document
    assert [shadowscan._restates_a_scan(json.dumps(d).encode()) for d in documents] == (
        [True] * 7 + [False] * 7
    )


def test_a_cited_json_file_is_not_canonicalised_to_be_read(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a cited file went through the strict parser")

    real = shadowscan.parse_json_strict
    text = json.dumps([{"model": MODEL}, {"model": "other"}], indent=1)
    project = _project(tmp_path, _report(_evidence("rows.json:3", MODEL)), {"rows.json": text})
    report = (project / "shadowscan.json").read_text()
    monkeypatch.setattr(
        shadowscan,
        "parse_json_strict",
        lambda text, **kwargs: real(text, **kwargs) if text == report else refuse(),
    )
    result = ShadowScanImporter().scan(project)
    assert [model.name for model in _models(result)] == [MODEL]


def test_a_kept_inventory_does_not_keep_a_deleted_model_named(tmp_path):
    # ShadowScan reads every file, so it cites a committed inventory that names the
    # model. Once the source line is gone, that inventory must not keep the model alive.
    project = _project(tmp_path, _report(_evidence("app.py:3", MODEL)))
    baseline = project / ".nexus-symbiote" / "reviewed.json"
    baseline.parent.mkdir()
    CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(baseline)])
    kept = baseline.read_text()
    assert MODEL_REF_PREFIX in kept
    line = _line_of(kept, f'"name": "{MODEL}",')
    (project / "app.py").write_text("import openai\n")
    stale = _report(_evidence(f".nexus-symbiote/reviewed.json:{line}", MODEL))
    (project / "shadowscan.json").write_text(json.dumps(stale))
    result = ShadowScanImporter().scan(project)
    assert not _models(result)
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED


CREDENTIAL_FILES = [
    ".env",
    "deploy/prod.env",
    "id_rsa",
    "certs/server.pem",
    ".netrc",
    "secrets/t.txt",
]


@pytest.mark.parametrize("cited", [*CREDENTIAL_FILES, "notes.txt"])
def test_a_file_named_as_holding_credentials_is_not_read(tmp_path, cited):
    # notes.txt is a link to .env: the name the link leads to decides, as for any collector.
    content = f"REGION = {MODEL}\n"
    files = {".env": content} if cited == "notes.txt" else {cited: content}
    project = _project(tmp_path, _report(_evidence(f"{cited}:1", MODEL)), files)
    if cited == "notes.txt":
        os.symlink(".env", project / "notes.txt")
    out = tmp_path / "bom.json"
    CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(out)]
    )
    text = out.read_text()
    assert MODEL_REF_PREFIX not in text
    assert hashlib.sha256(content.encode()).hexdigest() not in text


def test_a_credential_template_is_read(tmp_path):
    files = {".env.example": f"CHAT_MODEL={MODEL}\n"}
    result = _scan(tmp_path, _report(_evidence(".env.example:1", MODEL)), files)
    assert [model.name for model in _models(result)] == [MODEL]


def test_no_digest_of_a_cited_file_reaches_the_inventory(tmp_path):
    # An unkeyed digest of a small file confirms a guess of its content offline.
    project = _project(tmp_path, _report(_evidence("app.py:3", MODEL)))
    out = tmp_path / "bom.json"
    for fmt in ("json", "cyclonedx", "spdx"):
        out.unlink(missing_ok=True)
        CliRunner().invoke(
            main,
            [
                "scan",
                str(project),
                "--no-project-policy",
                "--report-only",
                "-f",
                fmt,
                "-o",
                str(out),
            ],
        )
        text = out.read_text()
        assert MODEL_REF_PREFIX in text
        assert hashlib.sha256(SOURCE.encode()).hexdigest() not in text, fmt


def test_a_value_on_the_line_after_a_credential_key_is_withheld(tmp_path):
    literal = f"{MODEL}-0123456789"
    files = {
        "a.yaml": f"api_token:\n  {literal}\n",
        "b.yaml": f"chat_model:\n  {literal}\n",
        "c.yaml": f"headers:\n  Authorization: Bearer\n    {literal}\n",
    }
    for cited in ("a.yaml:2", "c.yaml:3"):
        withheld = _scan(tmp_path / cited[0], _report(_evidence(cited, literal)), files)
        assert not _models(withheld), cited
    named = _scan(tmp_path / "b", _report(_evidence("b.yaml:2", literal)), files)
    assert [model.name for model in _models(named)] == [literal]


def test_what_is_withheld_does_not_depend_on_which_identifier_is_cited_first(tmp_path):
    whole, part = "abc/def123456789", "def123456789"
    files = {"c.yaml": f"password:\n{whole}\n", "m.yaml": f"models:\n{whole}\n"}
    orders = ([part, whole], [whole, part], [part], [whole])
    for number, cited in enumerate(orders):
        for name, expected in (("c.yaml", []), ("m.yaml", sorted(cited))):
            report = _report(*(_evidence(f"{name}:2", literal) for literal in cited))
            result = _scan(tmp_path / f"{number}-{name[0]}", report, files)
            assert sorted(model.name for model in _models(result)) == expected, (cited, name)


VALUE = f"{MODEL}-0123456789"
BELOW_A_KEY = {
    "folded-block": "{key}: >-\n  {value}\n",
    "literal-block": "{key}: |\n  {value}\n",
    "block-that-keeps-line-breaks": "{key}: |+\n  {value}\n",
    "block-with-indent-and-chomp": "{key}: |2-\n  {value}\n",
    "block-and-a-comment": "{key}: >- # folded\n  {value}\n",
    "blank-line-between": "{key}:\n\n  {value}\n",
    "block-then-blank-line": "{key}: >-\n\n  {value}\n",
    "comment-after-the-key": "{key}:  # rotated monthly\n  {value}\n",
    "comment-that-ends-in-a-colon": "{key}:  # example:\n  {value}\n",
    "slash-comment-after-the-key": "{key} = // see the vault\n  '{value}'\n",
    "comment-line-between": "{key}:\n  # rotated monthly\n  {value}\n",
    "json-value-two-lines-down": '{{\n "{key}":\n\n  "{value}"\n}}\n',
    "json-array": '{{\n "{key}": [\n  "first-entry",\n  "{value}"\n ]\n}}\n',
    "yaml-list": "{key}:\n  - first-entry\n  - {value}\n",
    "equals-and-parenthesis": "{key} = (\n  '{value}',\n)\n",
    "equals-and-brace": '{key} = {{\n  "{value}",\n}}\n',
    "declared-constant": "export const {key} = [\n  '{value}',\n];\n",
    "two-values-on-the-line": '{key} = [\n  "first","{value}"\n]\n',
    "comma-inside-the-value": "{key}:\n  first,{value}\n",
    "namespace-before-the-value": "{key}:\n  openai:{value}\n",
    "spaces-inside-the-quotes": '{key}:\n  " {value} "\n',
    "single-quotes": "{key}:\n  ' {value} '\n",
    "comma-after-a-space": '{key}:\n  "{value}" ,\n',
    "brackets-around-it": '{key}:\n  [ "{value}" ]\n',
    "tab-before-the-comma": '{key}:\n  "{value}"\t,\n',
    "padded-entry-above": "{key}:\n  - Zmlyc3QtZW50cnktMDAwMQ==\n  - {value}\n",
    "empty-assignment-entry-above": "[auth]\n{key}=\n    first-entry\n    {value}\n",
    "bracket-on-its-own-line": '{{"{key}":\n[\n"{value}"]}}\n',
    "brace-and-bracket-on-their-own-lines": '{{\n"{key}":\n[\n"{value}"\n]\n}}\n',
    "yaml-anchor-after-the-key": "{key}: &shared\n  {value}\n",
    "yaml-tag-after-the-key": "{key}: !vault\n  {value}\n",
    "shell-line-continuation": "export {key}=\\\n{value}\n",
    "compact-entry-between": '{{\n  "{key}": [\n    {{"type":"basic"}},\n    "{value}"\n  ]\n}}\n',
    "compact-entry-in-a-constant": 'const {key} = [\n  {{"id":"primary"}},\n  "{value}",\n];\n',
    "compact-entry-cited": '{{\n  "{key}": [\n    {{"value":"{value}"}}\n  ]\n}}\n',
}


@pytest.mark.parametrize("form", sorted(BELOW_A_KEY))
def test_a_value_written_below_a_credential_key_is_withheld(tmp_path, form):
    for key, expected in (("credentials", []), ("chat_models", [VALUE])):
        text = BELOW_A_KEY[form].format(key=key, value=VALUE)
        report = _report(_evidence(f"cfg.yaml:{_line_holding(text, VALUE)}", VALUE))
        result = _scan(tmp_path / key, report, {"cfg.yaml": text})
        assert [model.name for model in _models(result)] == expected, key


# A key nested in a bracket below a credential key opens a value inside that key's value.
NESTED_BELOW_A_KEY = {
    "key-in-a-compact-entry": '{{\n  "{key}": [\n    {{"values": [\n      "{value}"\n    ]}}\n  ]\n}}\n',
    "key-in-a-compact-entry-alone": '{{\n  "{key}": [\n    {{"values":\n      "{value}"\n    }}\n  ]\n}}\n',
    "key-in-an-object": '{{\n  "{key}": {{\n    "values": [\n      "{value}"\n    ]\n  }}\n}}\n',
    "keys-two-levels-down": (
        '{{\n  "{key}": [\n    {{"entries": [\n      {{"values": [\n        "{value}"\n'
        "      ]}}\n    ]}}\n  ]\n}}\n"
    ),
}


@pytest.mark.parametrize("form", sorted(NESTED_BELOW_A_KEY))
def test_a_value_below_a_key_nested_in_a_credential_key_is_withheld(tmp_path, form):
    for key, expected in (("credentials", []), ("secret", []), ("chat_models", [VALUE])):
        text = NESTED_BELOW_A_KEY[form].format(key=key, value=VALUE)
        report = _report(_evidence(f"cfg.json:{_line_holding(text, VALUE)}", VALUE))
        result = _scan(tmp_path / key, report, {"cfg.json": text})
        assert [model.name for model in _models(result)] == expected, key


@pytest.mark.parametrize("padding", ["=", "=="])
@pytest.mark.parametrize("form", ["folded-block", "json-array", "yaml-list", "blank-line-between"])
def test_a_value_that_ends_in_padding_is_still_a_value(tmp_path, form, padding):
    # Base64 padding after the cited text reads like `NAME=` with nothing assigned.
    for key, expected in (("credentials", []), ("chat_models", [VALUE])):
        text = BELOW_A_KEY[form].format(key=key, value=VALUE + padding)
        report = _report(_evidence(f"cfg.yaml:{_line_holding(text, VALUE)}", VALUE))
        result = _scan(tmp_path / key, report, {"cfg.yaml": text})
        assert [model.name for model in _models(result)] == expected, key


def test_every_key_that_may_open_a_value_is_read(tmp_path):
    # `credentials=` may be an empty assignment or a padded value, so the search goes on
    # above it and both keys are tried. A long single value in between does not end it.
    blob = "A" * (shadowscan.MAX_CITED_LINE_CHARS + 100)
    files = {
        "near.ini": f"chat_models:\n  credentials=\n  first\n  {VALUE}\n",
        "far.ini": f"credentials:\n  chat_models=\n  first\n  {VALUE}\n",
        "blob.yaml": f"credentials:\n  - {blob}\n  - {VALUE}\n",
        "call.py": f"credentials = (\n    decode(\n        '{VALUE}',\n    ),\n)\n",
        "plain.ini": f"chat_models:\n  other_models=\n  first\n  {VALUE}\n",
    }
    for name, expected in (
        ("near.ini", []),
        ("far.ini", []),
        ("blob.yaml", []),
        ("call.py", []),
        ("plain.ini", [VALUE]),
    ):
        line = _line_holding(files[name], VALUE)
        result = _scan(tmp_path / name, _report(_evidence(f"{name}:{line}", VALUE)), files)
        assert [model.name for model in _models(result)] == expected, name


def test_a_scheme_word_alone_on_the_line_above_withholds_the_value(tmp_path):
    files = {"cfg.yaml": f"auth:\n  Bearer\n  {VALUE}\n", "ok.yaml": f"auth:\n  first\n  {VALUE}\n"}
    withheld = _scan(tmp_path / "a", _report(_evidence("cfg.yaml:3", VALUE)), files)
    named = _scan(tmp_path / "b", _report(_evidence("ok.yaml:3", VALUE)), files)
    assert (_models(withheld), [model.name for model in _models(named)]) == ([], [VALUE])


NOT_THE_KEYS_VALUE = {
    "a-key-of-its-own": "credentials:\n  model: {value}\n  region: eu\n",
    "a-quoted-key-of-its-own": 'credentials:\n  "model":"{value}"\n',
    "a-key-of-its-own-in-a-list": "credentials:\n  - MODEL={value}\n",
    "a-key-of-its-own-with-another-mark": "OPENAI_API_KEY:=\nMODEL:={value}\n",
    "the-value-is-itself-a-key": "credentials:\n  {value}:\n    region: eu\n",
    "several-words-on-the-line": "Password:\n We call {value} in this service\n",
    "a-key-with-its-value-above": "db_password: abc\n  {value}\n",
    "a-nearer-key-opens-it": "db_password:\n  example.com/models:\n    {value}\n",
    "a-typed-declaration-above": "const credentials: string[] = [\n  '{value}',\n];\n",
    "a-condition-above-a-list": (
        "if settings.openai_api_key:\n    models.extend([\n        '{value}',\n    ])\n"
    ),
    "a-condition-above-a-return": "if not api_key:\n    return [\n        '{value}',\n    ]\n",
    "a-sentence-above-a-list": "To use these models you need an access token:\n\n- {value}\n",
    "a-sentence-and-a-blank-line-above": "The CLI then asks for the passphrase:\n\n    {value}\n",
    "a-comment-above-a-list": "# gated on the Hub, export HF_TOKEN:\nMODELS = [\n  '{value}',\n]\n",
    "an-empty-credential-above-an-assignment": "OPENAI_API_KEY=\nOPENAI_MODEL={value}\n",
    "a-closed-credential-list-above": '{{\n  "credentials": [],\n  "models": [\n    "{value}"\n  ]\n}}\n',
}


@pytest.mark.parametrize("form", sorted(NOT_THE_KEYS_VALUE))
def test_a_line_that_is_not_the_value_of_a_credential_key_is_named(tmp_path, form):
    text = NOT_THE_KEYS_VALUE[form].format(value=VALUE)
    report = _report(_evidence(f"cfg.txt:{_line_holding(text, VALUE)}", VALUE))
    result = _scan(tmp_path, report, {"cfg.txt": text})
    assert [model.name for model in _models(result)] == [VALUE]


def test_the_key_that_opens_a_value_is_looked_for_a_bounded_number_of_lines_up(tmp_path):
    def named(entries_between, filler="  - entry-{n}\n"):
        items = "".join(filler.format(n=n) for n in range(entries_between))
        files = {"cfg.yaml": f"credentials:\n{items}  - {VALUE}\n"}
        report = _report(_evidence(f"cfg.yaml:{entries_between + 2}", VALUE))
        result = _scan(tmp_path / f"{entries_between}{len(filler)}", report, files)
        return [model.name for model in _models(result)]

    assert named(shadowscan.MAX_KEY_LOOKBACK - 1) == []
    assert named(shadowscan.MAX_KEY_LOOKBACK) == [VALUE]
    # Blank lines and comment lines count toward the same bound.
    assert named(shadowscan.MAX_KEY_LOOKBACK - 1, "\n") == []
    assert named(shadowscan.MAX_KEY_LOOKBACK, "\n") == [VALUE]
    assert named(shadowscan.MAX_KEY_LOOKBACK - 1, "  # note\n") == []


def test_only_the_text_the_redactor_reads_counts_toward_the_credential_check_bound(
    tmp_path, monkeypatch
):
    entries = [f"id-{n:04d}-{MODEL}" for n in range(shadowscan.MAX_MODEL_CITATIONS)]
    text = "chat_models:\n" + "".join(f"  - {entry}\n" for entry in entries)
    report = _report(*(_evidence(f"cfg.yaml:{n + 2}", entry) for n, entry in enumerate(entries)))
    read = []
    real = shadowscan.redact_text
    monkeypatch.setattr(shadowscan, "redact_text", lambda text: read.append(text) or real(text))
    result = _scan(tmp_path, report, {"cfg.yaml": text})
    # A long list in which every entry is cited: each line is checked with the one line
    # above it, and with the key while that is within reach, never with all eight.
    assert len(_models(result)) == shadowscan.MAX_NAMED_MODELS and not result.scan_failures
    assert not any("not confirmed" in line for line in result.source_projection_limitations)
    lines = [text for text in read if "\n" in text]
    assert sum(map(len, lines)) < shadowscan.MAX_REDACTED_CHARS
    assert max(text.count("\n") for text in lines) == 1


def test_a_long_line_above_a_value_is_read_from_its_end(tmp_path):
    long = "x" * (shadowscan.MAX_CITED_LINE_CHARS + 50)
    files = {"a.yaml": f"{long} password:\n  {VALUE}\n", "b.yaml": f"password: {long}\n  {VALUE}\n"}
    withheld = _scan(tmp_path / "a", _report(_evidence("a.yaml:2", VALUE)), files)
    named = _scan(tmp_path / "b", _report(_evidence("b.yaml:2", VALUE)), files)
    assert (_models(withheld), [model.name for model in _models(named)]) == ([], [VALUE])


def test_a_line_with_its_own_key_is_read_alone(tmp_path):
    # An empty credential in a template does not withhold the assignment after it.
    files = {".env.example": f"OPENAI_API_KEY=\nOPENAI_MODEL={MODEL}\n"}
    result = _scan(tmp_path, _report(_evidence(".env.example:2", MODEL)), files)
    assert [model.name for model in _models(result)] == [MODEL]


@pytest.mark.parametrize(
    "signal",
    [
        "model:" + "s" + "k-" + "a1b2c3d4" * 3,
        "model:provider." + "a" * 25,
        "model:provider.a.b.c.d",
        "model:provider_openai",
    ],
)
def test_a_signal_that_is_not_a_short_label_is_not_copied(tmp_path, signal):
    project = _project(tmp_path, _report(_evidence("app.py:3", MODEL, signal=signal)))
    out = tmp_path / "bom.json"
    CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(out)]
    )
    assert signal not in out.read_text() and MODEL_REF_PREFIX not in out.read_text()


def test_a_file_over_the_file_limit_is_not_charged_to_the_source_limit(tmp_path):
    files = {"a.py": f'A = "{MODEL}"\n' + "#" * 4096, "b.py": f'B = "{MODEL}"\n'}
    report = _report(_evidence("a.py:1", MODEL), _evidence("b.py:1", MODEL))
    project = _project(tmp_path, report, files)
    settings = replace(limits.DEFAULTS, file_bytes=limits.KIB, source_scan_bytes=2 * limits.KIB)
    with limits.applied(settings):
        result = ShadowScanImporter().scan(project)
    (model,) = _models(result)
    assert model.claims[EVIDENCE_CLAIM].evidence_refs == ["b.py:1"]
    assert not result.scan_failures
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED


def test_named_models_are_bounded_and_the_rest_are_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(shadowscan, "MAX_NAMED_MODELS", 1)
    files = {"app.py": f'A = "{MODEL}"\nB = "text-embedding-3-small"\n'}
    report = _report(_evidence("app.py:2", "text-embedding-3-small"), _evidence("app.py:1", MODEL))
    result = _scan(tmp_path, report, files)
    assert [model.name for model in _models(result)] == [MODEL]
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == (
        "1 confirmed model identifiers past the bound of 1 are not named"
    )


def test_cited_lines_are_checked_in_time_linear_in_the_citations(tmp_path):
    # One long line that repeats each cited identifier inside longer ones.
    line = "".join(f"m{n % 7}x" for n in range(1300))[:4000] + f' "{MODEL}"'
    projects = {}
    for scale in (1, 4):
        entries = [
            _evidence("app.py:1", f"m{n % 7}", signal=f"model:provider.p{n % 50}")
            for n in range(250 * scale)
        ]
        report = _report(*entries, _evidence("app.py:1", MODEL))
        projects[scale] = _project(tmp_path / str(scale), report, {"app.py": line + "\n"})
    assert [m.name for m in _models(ShadowScanImporter().scan(projects[4]))] == [MODEL]
    assert scaling_ratio(lambda scale: ShadowScanImporter().scan(projects[scale])) < 10


def test_a_file_with_carriage_returns_is_read(tmp_path):
    files = {"app.py": f'import openai\r\n\r\nM = "{MODEL}"\r\n  {MODEL}\r\n'}
    report = _report(_evidence("app.py:3", MODEL), _evidence("app.py:4", MODEL))
    (model,) = _models(_scan(tmp_path, report, files))
    assert model.claims[EVIDENCE_CLAIM].evidence_refs == ["app.py:3", "app.py:4"]


def test_a_number_is_not_a_model_identifier(tmp_path):
    files = {"app.py": 'YEAR = "2024"\nTAG = "v2024"\n'}
    report = _report(_evidence("app.py:1", "2024"), _evidence("app.py:2", "v2024"))
    result = _scan(tmp_path, report, files)
    assert [model.name for model in _models(result)] == ["v2024"]


@pytest.mark.parametrize("cited", [".git/config", "node_modules/pkg/index.js", ".venv/lib/x.py"])
def test_paths_outside_the_static_scope_are_not_read(tmp_path, cited):
    project = _project(
        tmp_path, _report(_evidence(f"{cited}:1", MODEL)), {cited: f'model = "{MODEL}"\n'}
    )
    result = ShadowScanImporter().scan(project)
    assert not _models(result)


def test_a_cited_named_pipe_is_not_read(tmp_path):
    project = _project(tmp_path, _report(_evidence("pipe.py:1", MODEL)))
    os.mkfifo(project / "pipe.py")
    result = ShadowScanImporter().scan(project)
    assert not _models(result)
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED


def test_a_cited_path_is_bounded(tmp_path):
    name = "d/" * 126 + "app.py"
    assert len(name) == shadowscan.MAX_CITED_PATH_CHARS + 2
    for path, named in ((name, []), (name[4:], [MODEL])):
        files = {path: f'M = "{MODEL}"\n'}
        result = _scan(tmp_path / str(len(path)), _report(_evidence(f"{path}:1", MODEL)), files)
        assert [model.name for model in _models(result)] == named


def test_other_evidence_is_not_model_evidence(tmp_path):
    result = _scan(
        tmp_path,
        _report(
            _evidence("app.py:1", "openai", signal="import:provider.openai"),
            _evidence("app.py:3", MODEL, signal="code:provider.openai"),
            "model:provider.openai",
            None,
        ),
    )
    assert not _models(result)
    assert result.source_projection_limitations is not None
    assert not any("not confirmed" in text for text in result.source_projection_limitations)


# Built at run time: a secret-shaped literal must not be committed.
CREDENTIALS = ["s" + "k-" + "a1B2c3D4" * 4, "AK" + "IA" + "ABCDEFGH12345678"]


@pytest.mark.parametrize("token", CREDENTIALS)
def test_a_credential_is_never_recorded_as_a_model_name(tmp_path, token):
    # The redactor also withholds the token on its line, so the scan cannot tell which
    # check refused it; the parse at the end isolates the check on the identifier itself.
    project = _project(
        tmp_path, _report(_evidence("app.py:1", token)), {"app.py": f"FIXTURE = [{token}]\n"}
    )
    assert names_whole_identifier(f"FIXTURE = [{token}]", token)
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(out)]
    )
    assert MODEL_REF_PREFIX not in out.read_text()
    assert token not in out.read_text() and token not in result.output
    imported = ShadowScanImporter().parse_report(json.dumps(_report(_evidence("app.py:1", token))))
    assert not imported.model_citations and imported.uncited_model_evidence == 1


def test_a_literal_in_text_the_redactor_withholds_is_not_named(tmp_path):
    # The cited line assigns the literal to a credential name, so the scan's own
    # redaction withholds it; a twin on an ordinary name is read.
    files = {"deploy.conf": f"API_TOKEN={MODEL}-0123456789\nCHAT_MODEL={MODEL}-0123456789\n"}
    literal = f"{MODEL}-0123456789"
    withheld = _scan(tmp_path / "a", _report(_evidence("deploy.conf:1", literal)), files)
    assert not _models(withheld)
    named = _scan(tmp_path / "b", _report(_evidence("deploy.conf:2", literal)), files)
    assert [model.name for model in _models(named)] == [literal]


def test_one_component_per_identifier_lists_every_confirmed_location(tmp_path):
    files = {
        "b/worker.py": f'A = "{MODEL}"\nB = "{MODEL}"\n',
        "a/config.yaml": f"model: {MODEL}\nother: text-embedding-3-small\n",
    }
    report = _report(
        findings=[
            [_evidence("b/worker.py:2", MODEL), _evidence("b/worker.py:1", MODEL)],
            [
                _evidence("a/config.yaml:1", MODEL, signal="model:provider.azure-openai"),
                _evidence("a/config.yaml:1", MODEL, signal="model:provider.azure-openai"),
                _evidence("a/config.yaml:2", "text-embedding-3-small"),
                _evidence("a/config.yaml:2", MODEL),
            ],
        ]
    )
    result = _scan(tmp_path, report, files)
    by_name = {model.name: model for model in _models(result)}
    assert sorted(by_name) == [MODEL, "text-embedding-3-small"]
    model = by_name[MODEL]
    assert model.claims[EVIDENCE_CLAIM].locator == "a/config.yaml:1"
    assert model.claims[EVIDENCE_CLAIM].evidence_refs == [
        "a/config.yaml:1",
        "b/worker.py:1",
        "b/worker.py:2",
    ]
    assert "shadowscan:evidence-unlisted" not in model.properties
    assert model.properties["shadowscan:signals"] == [
        "model:provider.azure-openai",
        "model:provider.openai",
    ]
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED


def test_listed_locations_are_bounded_and_the_total_is_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(shadowscan, "MAX_EVIDENCE_LOCATIONS", 2)
    files = {"app.py": f'M = "{MODEL}"\n' * 5}
    report = _report(*(_evidence(f"app.py:{line}", MODEL) for line in range(1, 6)))
    (model,) = _models(_scan(tmp_path, report, files))
    assert model.claims[EVIDENCE_CLAIM].evidence_refs == ["app.py:1", "app.py:2"]
    assert model.properties["shadowscan:evidence-unlisted"] == 3


def test_listed_signals_are_bounded_and_the_rest_are_counted(tmp_path):
    labels = [f"model:provider.p{n:02d}" for n in range(shadowscan.MAX_EVIDENCE_SIGNALS + 4)]
    report = _report(*(_evidence("app.py:3", MODEL, signal=label) for label in reversed(labels)))
    (model,) = _models(_scan(tmp_path, report))
    assert model.properties["shadowscan:signals"] == labels[: shadowscan.MAX_EVIDENCE_SIGNALS]
    assert model.properties["shadowscan:signals-unlisted"] == 4
    exact = _report(*(_evidence("app.py:3", MODEL, signal=label) for label in labels[:16]))
    (model,) = _models(_scan(tmp_path / "exact", exact))
    assert "shadowscan:signals-unlisted" not in model.properties


def test_listed_locations_are_bounded_as_the_inventory_writes_them(tmp_path):
    def listed(paths):
        model = shadowscan._model_component(MODEL, {(path, 7) for path in paths}, {"model:x"})
        return model.claims[EVIDENCE_CLAIM].evidence_refs, model.properties

    plain = [f"d{n:02d}/".ljust(253, "p") + ".py" for n in range(20)]
    refs, properties = listed(plain)
    assert len(refs) == shadowscan.MAX_EVIDENCE_LOCATIONS == 16
    assert properties["shadowscan:evidence-unlisted"] == 4
    # A path the writer escapes takes up to twelve bytes a character: fewer are listed
    # and every one is counted. One location always fits.
    assert shadowscan.MAX_LISTED_LOCATION_BYTES >= 12 * shadowscan.MAX_CITED_PATH_CHARS + 10
    wide = ["\U0001f9ea" * 252 + f"/{n:02d}" for n in range(16)]
    refs, properties = listed(wide)
    assert refs == [f"{wide[0]}:7"] and properties["shadowscan:evidence-unlisted"] == 15
    refs, properties = listed([wide[0], *("\U0001f9eb" + path[1:] for path in plain[:6])])
    assert len(refs) == 5 and properties["shadowscan:evidence-unlisted"] == 2
    assert sum(len(json.dumps(ref)) for ref in refs) <= shadowscan.MAX_LISTED_LOCATION_BYTES


def test_the_largest_named_models_stay_under_the_documented_size():
    # The most a report can make the inventory hold for its cited models: 500 identifiers
    # of 128 characters, each with more labels than are listed, and locations whose paths
    # are written at twelve bytes a character.
    labels = {
        f"model:{n:02d}{'z' * 22}." + "-".join(["a" * 24, "b" * 24, "c" * 24]) for n in range(20)
    }
    wide = "\U0001f9ea" * 256
    others = ["\U0001f9eb" + "p" * 255 for _ in range(1)] + [
        "\U0001f9eb" + f"{n:02d}".ljust(255, "p") for n in range(15)
    ]
    locations = {(path, 9_999_999) for path in (wide, *others)}
    models = [
        shadowscan._model_component(f"m{n:03d}".ljust(128, "x"), locations, labels)
        for n in range(shadowscan.MAX_NAMED_MODELS)
    ]
    assert all(len(m.properties["shadowscan:signals"]) == 16 for m in models)
    assert all(m.properties["shadowscan:signals-unlisted"] == 4 for m in models)
    size = len(AIBOM(components=models).to_json().encode())
    assert 4.5 * 1024 * 1024 < size < 6 * 1024 * 1024


def test_a_report_of_many_cited_models_is_read_within_the_bounds(tmp_path):
    names = [f"m{n:03d}".ljust(128, "x") for n in range(shadowscan.MAX_NAMED_MODELS)]
    paths = [f"d{n:02d}/".ljust(256 - 3, "p") + ".py" for n in range(16)]
    source = "".join(f"m={name}\n" for name in names)
    evidence = [
        _evidence(f"{path}:{line + 1}", name, signal=f"model:provider.p{number:02d}")
        for number, path in enumerate(paths)
        for line, name in enumerate(names)
    ]
    assert len(evidence) <= shadowscan.MAX_MODEL_CITATIONS
    assert len(source) * len(paths) <= shadowscan.MAX_REDACTED_CHARS
    result = _scan(tmp_path, _report(*evidence), dict.fromkeys(paths, source))
    models = _models(result)
    assert len(models) == shadowscan.MAX_NAMED_MODELS and not result.scan_failures
    assert all(len(m.claims[EVIDENCE_CLAIM].evidence_refs) == 16 for m in models)


def test_an_entry_the_scan_refuses_counts_toward_the_citation_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(shadowscan, "MAX_MODEL_CITATIONS", 3)
    calls = []
    real = shadowscan.redact_text
    monkeypatch.setattr(shadowscan, "redact_text", lambda text: calls.append(text) or real(text))
    refused = [_evidence("app.py:3", CREDENTIALS[0]) for _ in range(40)]
    result = _scan(tmp_path, _report(*refused, _evidence("app.py:3", MODEL)))
    assert not _models(result)
    assert len(calls) <= 2 * shadowscan.MAX_MODEL_CITATIONS
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED.replace("1 model", "41 model")


def test_an_entry_the_redactor_never_reads_does_not_use_up_the_citation_bound(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(shadowscan, "MAX_MODEL_CITATIONS", 3)
    unusable = [
        _evidence("app.py", MODEL),
        _evidence("app.py:0", MODEL),
        _evidence("app.py:3", "x" * 200),
        {"signal": "model:provider.openai", "location": "app.py:3"},
    ] * 10
    result = _scan(tmp_path, _report(*unusable, _evidence("app.py:3", MODEL)))
    assert [model.name for model in _models(result)] == [MODEL]
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED.replace("1 model", "40 model")


def test_evidence_past_the_citation_bound_is_counted_not_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(shadowscan, "MAX_MODEL_CITATIONS", 1)
    files = {"app.py": f'A = "{MODEL}"\nB = "text-embedding-3-small"\n'}
    report = _report(_evidence("app.py:1", MODEL), _evidence("app.py:2", "text-embedding-3-small"))
    result = _scan(tmp_path, report, files)
    assert [model.name for model in _models(result)] == [MODEL]
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED


def test_cited_files_past_the_source_limit_are_a_named_failure(tmp_path):
    files = {"a.py": f'A = "{MODEL}"\n' + "#" * 2048, "b.py": f'B = "{MODEL}"\n' + "#" * 2048}
    report = _report(_evidence("a.py:1", MODEL), _evidence("b.py:1", MODEL))
    project = _project(tmp_path, report, files)
    settings = replace(limits.DEFAULTS, source_scan_bytes=3 * limits.KIB)
    with limits.applied(settings):
        result = ShadowScanImporter().scan(project)
    (model,) = _models(result)
    assert model.claims[EVIDENCE_CLAIM].evidence_refs == ["a.py:1"]
    assert len(result.scan_failures) == 1
    assert result.scan_failures[0].startswith("b.py: ShadowScan cited files exceed")
    assert "source-scan-bytes" in result.scan_failures[0]


def test_cited_lines_past_the_credential_check_bound_are_a_named_failure(tmp_path, monkeypatch):
    first, second = f'A = "{MODEL}"', 'B = "text-embedding-3-small"'
    monkeypatch.setattr(shadowscan, "MAX_REDACTED_CHARS", len(first))
    report = _report(
        _evidence("app.py:1", MODEL),
        _evidence("app.py:1", MODEL, signal="model:provider.azure-openai"),
        _evidence("app.py:2", "text-embedding-3-small"),
        _evidence("app.py:3", MODEL),
    )
    result = _scan(tmp_path, report, {"app.py": f"{first}\n{second}\n{first}\n"})
    (model,) = _models(result)
    assert model.claims[EVIDENCE_CLAIM].evidence_refs == ["app.py:1"]
    assert result.scan_failures == [shadowscan.CITED_LINES_GAP]
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED.replace("1 model", "2 model")


def test_the_credential_check_runs_once_for_each_cited_line(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        shadowscan, "redact_text", lambda text: calls.append(text) or text, raising=True
    )
    files = {"app.py": f'A = "{MODEL}"\nB = "unrelated"\n'}
    report = _report(
        *(_evidence("app.py:1", MODEL, signal=f"model:provider.p{n}") for n in range(50)),
        _evidence("app.py:2", MODEL),
    )
    result = _scan(tmp_path, report, files)
    assert [model.name for model in _models(result)] == [MODEL]
    # One call for the cited line; the other calls check each entry's identifier and label.
    assert [text for text in calls if "\n" in text] == [f'\nA = "{MODEL}"']


def test_a_cited_file_too_long_or_not_text_names_nothing(tmp_path):
    files = {
        "long.py": f'M = "{MODEL}"' + " " * shadowscan.MAX_CITED_LINE_CHARS + "\n",
        "binary.bin": b"\xff\xfe" + f'M = "{MODEL}"\n'.encode(),
    }
    report = _report(_evidence("long.py:1", MODEL), _evidence("binary.bin:1", MODEL))
    result = _scan(tmp_path, report, files)
    assert not _models(result)
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED.replace("1 model", "2 model")


def test_operator_exclusions_apply_to_cited_files(tmp_path):
    project = _project(tmp_path, _report(_evidence("app.py:3", MODEL)))
    importer = ShadowScanImporter()
    importer.configure(exclude_paths=["app.py"])
    result = importer.scan(project)
    assert not _models(result)
    assert result.source_projection_limitations is not None
    assert result.source_projection_limitations[-1] == UNNAMED


def test_a_report_cannot_take_a_cited_model_reference(tmp_path):
    # A finding identifier chosen to collide with a model reference maps elsewhere.
    report = _report(_evidence("app.py:3", MODEL))
    report["findings"][0]["id"] = MODEL
    result = _scan(tmp_path, report)
    refs = [component.bom_ref for component in result.components]
    assert len(refs) == len(set(refs)) == 2
    assert sum(ref.startswith(MODEL_REF_PREFIX) for ref in refs) == 1


def test_a_standalone_import_reads_no_project_file(tmp_path):
    report = json.dumps(_report(_evidence("app.py:3", MODEL)))
    imported = ShadowScanImporter().parse_report(report)
    assert [citation.literal for citation in imported.model_citations] == [MODEL]
    bom = imported.to_native_bom()
    assert not [c for c in bom.components if c.bom_ref.startswith(MODEL_REF_PREFIX)]
    (tmp_path / "report.json").write_text(report)
    (tmp_path / "app.py").write_text(SOURCE)
    out = tmp_path / "bom.json"
    runner = CliRunner()
    runner.invoke(
        main, ["import-shadowscan", str(tmp_path / "report.json"), "-o", str(out), "--report-only"]
    )
    assert MODEL not in out.read_text()
    verified = runner.invoke(
        main, ["verify-discovery", str(out), str(tmp_path / "report.json"), "--projection"]
    )
    assert verified.exit_code == 0, verified.output


def _merged(tmp_path, name, project):
    out = tmp_path / f"{name}.json"
    CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(out)])
    return out


def _validate(bom, project):
    return CliRunner().invoke(
        main,
        [
            "validate",
            str(bom),
            "--project",
            str(project),
            "--no-project-policy",
            "--allow-unsigned-discovery",
        ],
    )


def test_project_validation_reproduces_the_cited_models(tmp_path):
    project = _project(tmp_path, _report(_evidence("app.py:3", MODEL)))
    bom = _merged(tmp_path, "bom", project)
    # The report's claim, and the source collector's own reading of the same line.
    assert sorted(
        c.properties["collection_mode"]
        for c in AIBOM.model_validate(json.loads(bom.read_text())).components
        if c.name == MODEL
    ) == ["imported-unverified-report", "static-source-reference"]
    unchanged = _validate(bom, project).output
    assert "discovery report" not in unchanged

    # The cited line no longer holds the identifier: the recorded model is not reproduced.
    (project / "app.py").write_text("import openai\n\n\n" + SOURCE.splitlines()[2] + "\n")
    moved = _validate(bom, project)
    assert moved.exit_code != 0
    assert "Unexpected discovery report component: " + MODEL_REF_PREFIX in moved.output


def test_an_honest_project_with_a_cited_model_validates(tmp_path):
    # The demo agent validates under a digest pin for its weight file. A cited model
    # must not change that: it names no local artifact for the integrity check to bind.
    project = tmp_path / "proj"
    shutil.copytree(Path(__file__).parents[1] / "examples/demo-agent", project)
    (project / "app.py").write_text(SOURCE)
    weights = "models/intent-classifier.safetensors"
    policy = tmp_path / "signers.json"
    pin = {
        "kind": "digest-pin",
        "artifact_path": weights,
        "expected_sha256": "sha256:" + hashlib.sha256((project / weights).read_bytes()).hexdigest(),
    }
    policy.write_text(json.dumps({"version": 2, "artifacts": [pin]}))
    runner = CliRunner()
    outcomes = {}
    for name, evidence in (("finding-only", []), ("cited-model", [_evidence("app.py:3", MODEL)])):
        (project / "shadowscan.json").write_text(
            json.dumps(_report(*evidence, findings=[evidence]))
        )
        bom = tmp_path / f"{name}.json"
        common = ["--no-project-policy", "--signature-policy", str(policy)]
        runner.invoke(main, ["scan", str(project), "-o", str(bom), *common])
        named = MODEL_REF_PREFIX in bom.read_text()
        result = runner.invoke(
            main,
            [
                "validate",
                str(bom),
                "--project",
                str(project),
                "--allow-unsigned-discovery",
                *common,
            ],
        )
        outcomes[name] = (named, result.exit_code, "Validation: PASSED" in result.output)
    assert outcomes == {"finding-only": (False, 0, True), "cited-model": (True, 0, True)}


def test_project_validation_rejects_an_edited_or_added_model(tmp_path):
    project = _project(tmp_path, _report(_evidence("app.py:3", MODEL)))
    bom = _merged(tmp_path, "bom", project)
    doc = json.loads(bom.read_text())
    (model,) = [c for c in doc["components"] if c["bom_ref"].startswith(MODEL_REF_PREFIX)]
    model["name"] = "gpt-4o"
    bom.write_text(json.dumps(doc))
    edited = _validate(bom, project)
    assert edited.exit_code != 0
    assert "Component differs from the discovery report projection: " + model["bom_ref"] in (
        edited.output
    )


def _model_name_element(bom):
    report = minimum_elements.assess(bom)
    return next(r for r in report.elements if r.element.id.endswith("/model-name"))


def test_minimum_elements_counts_the_name_of_a_cited_model(tmp_path):
    # An imported finding carries a digest-based label; a cited model carries the
    # identifier the scan read, on the report's word that it is a model.
    project = _project(tmp_path, _report(_evidence("app.py:3", MODEL)))
    bom = AIBOM.model_validate(json.loads(_merged(tmp_path, "bom", project).read_text()))
    name = _model_name_element(bom)
    assert (name.status, name.basis) == (minimum_elements.PRESENT, minimum_elements.IMPORTED)
    for component in bom.components:
        component.claims.pop(EVIDENCE_CLAIM, None)
    name = _model_name_element(bom)
    assert (name.status, name.reasons) == (minimum_elements.MISSING, ("synthetic-name",))


def test_a_cited_model_does_not_raise_assurance(tmp_path):
    # An identifier read from a source line is a declaration, as a hosted-model alias
    # in agent.yaml is. Neither the import nor the re-read satisfies the observed minimum.
    project = _project(tmp_path, _report(_evidence("app.py:3", MODEL)))
    bom = AIBOM.model_validate(json.loads(_merged(tmp_path, "bom", project).read_text()))
    (model,) = [c for c in bom.components if c.bom_ref.startswith(MODEL_REF_PREFIX)]
    assert model.assurance_level is AssuranceLevel.DECLARED
    assert all(claim.assurance is AssuranceLevel.DECLARED for claim in model.claims.values())
    assert assurance_problems(bom, "observed") == [
        "minimum observed assurance not attained (2 declared components)"
    ]
    kept = [c for c in bom.components if c is not model]
    assert assurance_problems(bom.model_copy(update={"components": kept}), "observed") == [
        "minimum observed assurance not attained (1 declared component)"
    ]


def test_a_rerun_with_new_run_times_is_not_drift(tmp_path):
    first = _project(tmp_path / "one", _report(_evidence("app.py:3", MODEL)))
    second = _project(
        tmp_path / "two",
        _report(_evidence("app.py:3", MODEL), finished="2026-11-02T00:10:05+00:00"),
    )
    boms = [
        AIBOM.model_validate(json.loads(_merged(tmp_path, name, project).read_text()))
        for name, project in (("one", first), ("two", second))
    ]
    assert boms[0].metadata.completeness.source_report_digest != (
        boms[1].metadata.completeness.source_report_digest
    )
    report = AIBOMDiffer().diff(*boms)
    assert report.security_alerts == []
    assert not report.components_added and not report.components_removed


def _diff(tmp_path, first, second):
    boms = []
    for name, (evidence, files) in (("one", first), ("two", second)):
        project = _project(tmp_path / name, _report(*evidence), files)
        boms.append(AIBOM.model_validate(json.loads(_merged(tmp_path, name, project).read_text())))
    return AIBOMDiffer().diff(*boms)


def _alerts(report, literal=MODEL):
    ref = MODEL_REF_PREFIX + hashlib.sha256(literal.encode()).hexdigest()
    return [alert for alert in report.security_alerts if alert["component"] == ref]


def test_a_cited_line_that_only_moves_is_not_drift(tmp_path):
    # An import added above the model shifts its line; a second use in the same file
    # adds a location. Neither changes which files state the model.
    shifted = (
        f'import os\nimport openai\n\nreply = client.chat(model="{MODEL}")\nagain = "{MODEL}"\n'
    )
    report = _diff(
        tmp_path,
        ([_evidence("app.py:3", MODEL)], {"app.py": SOURCE}),
        ([_evidence("app.py:4", MODEL), _evidence("app.py:5", MODEL)], {"app.py": shifted}),
    )
    assert _alerts(report) == []
    assert not report.components_added and not report.components_removed


def test_a_model_cited_in_another_file_is_a_changed_component(tmp_path):
    report = _diff(
        tmp_path,
        ([_evidence("app.py:3", MODEL)], {"app.py": SOURCE}),
        ([_evidence("lib/llm.py:1", MODEL)], {"lib/llm.py": f'M = "{MODEL}"\n'}),
    )
    (alert,) = _alerts(report)
    assert alert["severity"] == "high" and "claims changed" in json.dumps(alert)


def test_a_model_that_is_no_longer_cited_is_a_removed_component(tmp_path):
    report = _diff(
        tmp_path,
        (
            [_evidence("app.py:3", MODEL), _evidence("app.py:1", "text-embedding-3-small")],
            {"app.py": f'E = "text-embedding-3-small"\n\nM = "{MODEL}"\n'},
        ),
        ([_evidence("app.py:1", MODEL)], {"app.py": f'M = "{MODEL}"\n'}),
    )
    assert _alerts(report) == []
    assert [alert["severity"] for alert in _alerts(report, "text-embedding-3-small")] == ["high"]


def test_two_scans_of_the_same_tree_agree(tmp_path):
    report = _report(_evidence("app.py:3", MODEL), _evidence("app.py:1", "openai"))
    project = _project(tmp_path, report)
    first, second = (ShadowScanImporter().scan(project) for _ in range(2))
    assert [c.model_dump() for c in first.components] == [c.model_dump() for c in second.components]
    assert first.source_projection_limitations == second.source_projection_limitations


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_standard_exports_carry_the_cited_model(tmp_path, fmt):
    project = _project(tmp_path, _report(_evidence("app.py:3", MODEL)))
    out = tmp_path / f"bom.{fmt}.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(project), "--no-project-policy", "--report-only", "-f", fmt, "-o", str(out)],
    )
    assert result.exit_code == 0, result.output
    text = out.read_text()
    assert MODEL_REF_PREFIX in text and "cited-line-reread" in text


def test_the_guide_example_is_what_a_scan_records(tmp_path):
    guide = Path(__file__).parents[1] / "docs/shadowscan-integration.md"
    section = guide.read_text().split("## Models named from cited evidence")[1]
    shown = json.loads(section.split("```json\n")[1].split("```")[0])
    name, locator = shown["name"], shown["claims"]["cited_evidence"]["locator"]
    path, line = locator.rsplit(":", 1)
    source = "\n" * (int(line) - 1) + f'MODEL = "{name}"\n'
    project = _project(tmp_path, _report(_evidence(locator, name)), {path: source})
    bom = json.loads(_merged(tmp_path, "bom", project).read_text())
    (model,) = [c for c in bom["components"] if c["bom_ref"].startswith(MODEL_REF_PREFIX)]
    claims = shown.pop("claims")
    assert shown == {key: model[key] for key in shown}
    assert claims == {"cited_evidence": model["claims"]["cited_evidence"]}


@pytest.mark.parametrize("name", shadowscan.REPORT_PATHS)
def test_no_report_path_confirms_its_own_citations(tmp_path, name):
    report = _report(_evidence(f"{name}:1", MODEL))
    row = f'"value": "{MODEL}"'
    line = _line_of(json.dumps(report, indent=1), row)
    report["findings"][0]["evidence"][0]["location"] = f"{name}:{line}"
    project = tmp_path / "proj"
    (project / name).parent.mkdir(parents=True)
    (project / name).write_text(json.dumps(report, indent=1))
    result = ShadowScanImporter().scan(project)
    assert result.source_report_path == name and not _models(result)


OUT_OF_SHAPE = [
    "2024",
    "x" * 129,
    "g",
    "gpt-4o-",
    "-gpt-4o",
    "gpt 4o",
    "model=gpt-4o",
    "chat(gpt-4o",
]


@pytest.mark.parametrize("literal", OUT_OF_SHAPE)
def test_text_that_is_not_identifier_shaped_is_refused_where_it_stands(tmp_path, literal):
    # The cited line holds the text whole, so only the shape rule can refuse it.
    result = _scan(
        tmp_path, _report(_evidence("app.py:1", literal)), {"app.py": f"X = [ {literal} ]\n"}
    )
    assert not _models(result)
    assert (
        not ShadowScanImporter()
        .parse_report(json.dumps(_report(_evidence("app.py:1", literal))))
        .model_citations
    )


IN_SHAPE = [
    "claude-3.5-sonnet",
    "qwen2.5-coder:7b",
    "cohere/rerank-english-v3.0",
    "org/model@v1",
    "gpt-4o+tools",
    "o1",
    "Meta-Llama-3.1-8B-Instruct",
]


@pytest.mark.parametrize("literal", IN_SHAPE)
def test_identifier_shapes_are_named_as_written(tmp_path, literal):
    result = _scan(
        tmp_path, _report(_evidence("app.py:1", literal)), {"app.py": f'M = "{literal}"\n'}
    )
    (model,) = _models(result)
    assert model.name == literal
    assert model.bom_ref == MODEL_REF_PREFIX + hashlib.sha256(literal.encode()).hexdigest()


BEDROCK = "arn:aws:bedrock:us-east-1:123456789012:"
BEDROCK_MODELS = [
    "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
    "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/amazon.titan-embed-text-v2:0",
    BEDROCK + "inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0",
    BEDROCK + "application-inference-profile/q3xmpl8zadbf",
    BEDROCK + "provisioned-model/q3xmpl8zadbf",
    BEDROCK + "custom-model/amazon.titan-text-express-v1:0:8k/q3xmpl8zadbf",
    BEDROCK + "imported-model/q3xmpl8zadbf",
]
BEDROCK_OTHERS = [
    BEDROCK + "guardrail/benchb",
    BEDROCK + "guardrail",
    BEDROCK + "agent/Q3XMPL8ZAD",
    BEDROCK + "agent-alias/Q3XMPL8ZAD/TSTALIASID",
    BEDROCK + "knowledge-base/Q3XMPL8ZAD",
    BEDROCK + "flow/Q3XMPL8ZAD",
    BEDROCK + "prompt/Q3XMPL8ZAD",
    BEDROCK + "model-customization-job/q3xmpl8zadbf",
    "ARN:AWS:BEDROCK:us-east-1:123456789012:foundation-model/amazon.nova-pro-v1:0",
    "arn:aws:bedrock:us-east-1::Foundation-Model/amazon.nova-pro-v1:0",
]


@pytest.mark.parametrize("literal", BEDROCK_MODELS)
def test_a_bedrock_resource_name_of_a_model_kind_is_named(tmp_path, literal):
    result = _scan(
        tmp_path, _report(_evidence("main.tf:1", literal)), {"main.tf": f'model_id = "{literal}"\n'}
    )
    assert [model.name for model in _models(result)] == [literal]


@pytest.mark.parametrize("literal", BEDROCK_OTHERS)
def test_a_bedrock_resource_name_of_another_kind_is_not_named_as_a_model(tmp_path, literal):
    # ShadowScan 0.1.4 labels a guardrail name in Terraform as model evidence. The cited
    # line holds the text whole, so only the kind the name states can refuse it.
    report = _report(_evidence("main.tf:1", literal, signal="model:provider.aws-bedrock"))
    result = _scan(tmp_path, report, {"main.tf": f'guardrail = "{literal}"\n'})
    assert not _models(result)
    assert UNNAMED in (result.source_projection_limitations or [])
    imported = ShadowScanImporter().parse_report(json.dumps(report))
    assert (imported.model_citations, imported.uncited_model_evidence) == ([], 1)


def test_the_kind_check_reads_bedrock_names_only(tmp_path):
    # No other identifier states what it names in a form the scan can check.
    literal = "arn:aws:sagemaker:us-east-1:123456789012:endpoint/support-llm"
    result = _scan(
        tmp_path, _report(_evidence("main.tf:1", literal)), {"main.tf": f'endpoint = "{literal}"\n'}
    )
    assert [model.name for model in _models(result)] == [literal]


def test_an_identifier_made_whole_only_by_redaction_is_not_named(tmp_path):
    # In the raw line the identifier continues into the token; the redactor cuts it there.
    token = "s" + "k-" + "a1B2c3D4" * 4
    files = {"app.py": f'KEY = "{MODEL}{token}"\nM = "{MODEL}" # {token}\n'}
    joined = _scan(tmp_path / "a", _report(_evidence("app.py:1", MODEL)), files)
    assert not _models(joined)
    beside = _scan(tmp_path / "b", _report(_evidence("app.py:2", MODEL)), files)
    assert [model.name for model in _models(beside)] == [MODEL]


@pytest.mark.parametrize(
    "signal",
    [
        "model:provider.OpenAI",
        "model:provider.openai extra",
        "model:provider.openai\n",
        "model:provider.openai\u202e",
        "models:provider.openai",
    ],
)
def test_a_signal_out_of_shape_names_nothing(tmp_path, signal):
    result = _scan(tmp_path, _report(_evidence("app.py:3", MODEL, signal=signal)))
    assert not _models(result)


def test_evidence_of_a_finding_the_projection_does_not_map_still_names_a_model(tmp_path):
    report = _report(_evidence("app.py:3", MODEL))
    report["findings"][0]["kind"] = "infra"
    report["findings"].append({"id": "odd", "kind": "agent", "surface": "code", "evidence": 7})
    result = _scan(tmp_path, report)
    assert result.source_unmapped_count == 1
    assert [model.name for model in _models(result)] == [MODEL]
    assert not result.scan_failures


@pytest.mark.parametrize(
    ("content", "line", "named"),
    [
        (f'A = 1\nM = "{MODEL}"', 2, True),
        (f'A = 1\nM = "{MODEL}"', 0, False),
        (f'A = 1\x0cB = 2\u2028C = 3\nM = "{MODEL}"\n', 2, True),
        (f'A = 1\x0cB = 2\u2028C = 3\nM = "{MODEL}"\n', 4, False),
        (f'M = "{MODEL}"' + " " * (4096 - len(f'M = "{MODEL}"')) + "\n", 1, True),
        (f'M = "{MODEL}"' + " " * (4097 - len(f'M = "{MODEL}"')) + "\n", 1, False),
    ],
    ids=[
        "last-line-without-a-line-feed",
        "line-zero",
        "line-feeds-only",
        "other-separators",
        "bound",
        "past-bound",
    ],
)
def test_lines_are_addressed_by_line_feeds_within_the_bound(tmp_path, content, line, named):
    result = _scan(tmp_path, _report(_evidence(f"app.py:{line}", MODEL)), {"app.py": content})
    assert bool(_models(result)) is named


@pytest.mark.parametrize("number", ["3x", "\u0663", "12345678", "+3", " 3"])
def test_a_malformed_line_number_is_unconfirmed_evidence(tmp_path, number):
    result = _scan(tmp_path, _report(_evidence(f"app.py:{number}", MODEL)))
    assert result.source_report_digest and not _models(result) and not result.scan_failures


def test_identifier_case_is_kept_and_the_first_location_is_by_path_then_line(tmp_path):
    files = {"b.py": 'M = "GPT-4o-Mini"\n', "a.py": 'X = 1\nM = "GPT-4o-Mini"\n'}
    report = _report(_evidence("b.py:1", "GPT-4o-Mini"), _evidence("a.py:2", "GPT-4o-Mini"))
    (model,) = _models(_scan(tmp_path, report, files))
    assert model.name == "GPT-4o-Mini"
    assert model.bom_ref == MODEL_REF_PREFIX + hashlib.sha256(b"GPT-4o-Mini").hexdigest()
    assert model.claims[EVIDENCE_CLAIM].locator == "a.py:2"
    assert model.claims[EVIDENCE_CLAIM].evidence_refs == ["a.py:2", "b.py:1"]


def test_cited_files_are_read_in_path_order_under_the_source_limit(tmp_path):
    files = {"a.py": f'A = "{MODEL}"\n' + "#" * 2048, "b.py": f'B = "{MODEL}"\n' + "#" * 2048}
    report = _report(_evidence("b.py:1", MODEL), _evidence("a.py:1", MODEL))
    project = _project(tmp_path, report, files)
    with limits.applied(replace(limits.DEFAULTS, source_scan_bytes=3 * limits.KIB)):
        result = ShadowScanImporter().scan(project)
    (model,) = _models(result)
    assert model.claims[EVIDENCE_CLAIM].evidence_refs == ["a.py:1"]


def test_the_documented_bounds_and_names():
    assert (
        shadowscan.MAX_MODEL_CITATIONS,
        shadowscan.MAX_CITED_PATH_CHARS,
        shadowscan.MAX_CITED_LINE_CHARS,
        shadowscan.MAX_EVIDENCE_LOCATIONS,
        shadowscan.MAX_EVIDENCE_SIGNALS,
        shadowscan.MAX_NAMED_MODELS,
        shadowscan.MAX_REDACTED_CHARS,
        shadowscan.MAX_KEY_LOOKBACK,
        shadowscan.MAX_LISTED_LOCATION_BYTES,
    ) == (10_000, 256, 4_096, 16, 16, 500, 1024 * 1024, 8, 4_256)
    assert PROJECTION_PROFILE == "nexus-symbiote/shadowscan-projection/v6"
    assert (EVIDENCE_CLAIM, MODEL_REF_PREFIX) == ("cited_evidence", "shadowscan:model:")
    assert shadowscan.CITED_LINES_GAP == (
        "ShadowScan cited lines exceed the text checked for credentials; the rest were not "
        "confirmed"
    )


def test_scans_in_processes_with_different_hash_seeds_agree(tmp_path):
    files = {f"m{n}.py": f'A = "{MODEL}"\nB = "text-embedding-3-small"\n' for n in range(6)}
    entries = [
        _evidence(f"m{n}.py:{line}", literal, signal=f"model:provider.p{n}")
        for n in range(6)
        for line, literal in ((1, MODEL), (2, "text-embedding-3-small"))
    ]
    project = _project(tmp_path, _report(*entries), files)
    outputs = set()
    for seed in ("1", "2", "3"):
        out = tmp_path / f"bom-{seed}.json"
        subprocess.run(  # noqa: S603
            [sys.executable, "-m", "nexus_symbiote.cli", "scan", str(project)]
            + ["--no-project-policy", "--report-only", "-o", str(out)],
            env={**os.environ, "PYTHONHASHSEED": seed, "SOURCE_DATE_EPOCH": "1700000000"},
            cwd=tmp_path,
            capture_output=True,
            check=False,
            timeout=120,
        )
        outputs.add(out.read_bytes())
    assert len(outputs) == 1
    (only,) = outputs
    assert MODEL_REF_PREFIX.encode() in only


def test_shadowscan_fixture_report_is_unchanged_by_the_new_projection():
    fixture = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
    imported = ShadowScanImporter().parse_report(fixture.read_bytes())
    assert imported.model_citations == [] and imported.uncited_model_evidence == 0
