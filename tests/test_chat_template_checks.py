"""Hugging Face chat templates get the access-pattern check that GGUF templates get.

`tokenizer_config.json` `chat_template`, `chat_template.json`, `chat_template.jinja` and
`additional_chat_templates/*.jinja` were digested but never inspected, so a template
with a suspicious access pattern left a SafeTensors model rated safe.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.validators.risk import RiskScorer
from tests.support import scaling_ratio

ESCAPES = [
    "{{ self.__init__.__globals__.__builtins__ }}",
    "{{ ''['__class__'] }}",
    "{{ x|attr('\\x5f\\x5fclass\\x5f\\x5f') }}",
    "{{ ''['__cl\\\nass__'] }}",
    "{{ cycler['_'~'_'~'init'~'_'~'_']['_'~'_'~'globals'~'_'~'_'] }}",
]
BENIGN = (
    "{% for message in messages %}<|{{ message['role'] }}|>{{ message['content'] }}"
    "{% endfor %}{% if add_generation_prompt %}<|assistant|>{% endif %}"
)
SOURCES = [
    "tokenizer_config.json#chat_template",
    "chat_template.json#chat_template",
    "processor_config.json#chat_template",
    "chat_template.jinja",
    "chat_template.jinja2",
    "additional_chat_templates/tool_use.jinja",
]
DETAIL = (
    "Model 'model.safetensors' is configured with a chat template containing "
    "a potential Python-internals access pattern: "
)
DETAIL_END = ". Actual behavior depends on the renderer and its sandbox."


def _safetensors(path: Path) -> None:
    header = json.dumps({"w": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}).encode()
    header += b" " * (-len(header) % 8)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(len(header).to_bytes(8, "little") + header + b"abcd")


def _gguf(template: str) -> bytes:
    def string(text: str) -> bytes:
        raw = text.encode()
        return len(raw).to_bytes(8, "little") + raw

    entries = [
        ("general.architecture", 8, string("llama")),
        ("tokenizer.chat_template", 8, string(template)),
    ]
    header = b"GGUF" + (3).to_bytes(4, "little") + (0).to_bytes(8, "little")
    header += len(entries).to_bytes(8, "little")
    for key, kind, value in entries:
        header += string(key) + kind.to_bytes(4, "little") + value
    return header + b"\0" * 32


def _template(directory: Path, source: str, template: str | list[dict[str, str]]) -> None:
    name, _, field = source.partition("#")
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if field:
        path.write_text(json.dumps({field: template}), encoding="utf-8")
    else:
        assert isinstance(template, str)
        path.write_text(template, encoding="utf-8")


def _model(root: Path, name: str = "model.safetensors") -> ModelComponent:
    result = ModelScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    found = [c for c in result.components if isinstance(c, ModelComponent)]
    return next(c for c in found if c.name.endswith(name))


def _template_findings(component: ModelComponent) -> list[str]:
    return [
        risk.detail
        for risk in component.risks
        if risk.category == "serialization_format" and "chat template" in risk.detail
    ]


@pytest.mark.parametrize("template", ESCAPES)
@pytest.mark.parametrize("source", SOURCES)
def test_an_escaping_template_in_any_source_is_critical(tmp_path, source, template):
    _safetensors(tmp_path / "m" / "model.safetensors")
    _template(tmp_path / "m", source, template)
    component = _model(tmp_path)
    assert component.serialization_safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION
    (risk,) = [r for r in component.risks if r.category == "serialization_format"]
    assert risk.severity == RiskSeverity.CRITICAL
    assert risk.detail == f"{DETAIL}m/{source}{DETAIL_END}"
    assert risk.references == [
        "https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/model-integrity.md"
    ]
    assert template not in risk.detail


@pytest.mark.parametrize("source", SOURCES)
def test_a_benign_template_changes_nothing_but_the_digest(tmp_path, source):
    _safetensors(tmp_path / "plain" / "m" / "model.safetensors")
    _safetensors(tmp_path / "templated" / "m" / "model.safetensors")
    _template(tmp_path / "templated" / "m", source, BENIGN)
    plain, templated = _model(tmp_path / "plain"), _model(tmp_path / "templated")
    assert templated.serialization_safety == SerializationSafety.SAFE
    assert templated.risks == plain.risks
    assert templated.chat_template_hash is not None
    assert [item["source"] for item in templated.properties["chat_templates"]] == [f"m/{source}"]


def test_each_named_template_of_a_list_is_checked(tmp_path):
    directory = tmp_path / "m"
    _safetensors(directory / "model.safetensors")
    named = [{"name": "default", "template": BENIGN}, {"name": "tool_use", "template": BENIGN}]
    _template(directory, "tokenizer_config.json#chat_template", named)
    assert _template_findings(_model(tmp_path)) == []
    named[1]["template"] = BENIGN + ESCAPES[0]
    _template(directory, "tokenizer_config.json#chat_template", named)
    component = _model(tmp_path)
    assert component.serialization_safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION
    assert _template_findings(component) == [
        f"{DETAIL}m/tokenizer_config.json#chat_template/1{DETAIL_END}"
    ]


def test_a_finding_names_three_templates_and_counts_the_rest(tmp_path):
    directory = tmp_path / "m"
    _safetensors(directory / "model.safetensors")
    for index in range(5):
        _template(directory, f"additional_chat_templates/t{index}.jinja", ESCAPES[0])
    (detail,) = _template_findings(_model(tmp_path))
    assert detail == (
        f"{DETAIL}m/additional_chat_templates/t0.jinja, m/additional_chat_templates/t1.jinja, "
        f"m/additional_chat_templates/t2.jinja and 2 more{DETAIL_END}"
    )


def test_a_template_larger_than_the_file_limit_is_digested_and_a_gap(runner, tmp_path):
    project = tmp_path / "project"
    directory = project / "m"
    _safetensors(directory / "model.safetensors")
    # The escape lies past the limit: a template that was not inspected must not pass.
    _template(directory, "chat_template.jinja", "{# padding #}" * 6_000 + ESCAPES[0])
    with limits.applied(limits.resolve(["file-bytes=64KiB"], {})):
        result = ModelScanner().scan(project)
    assert not result.scan_failures
    assert result.surfaces_excluded == [
        "m/chat_template.jinja: chat template not inspected: file-bytes limit of 64 KiB "
        "exceeded; raise it with --limit file-bytes=N"
    ]
    (component,) = result.components
    assert component.serialization_safety == SerializationSafety.SAFE
    assert [item["source"] for item in component.properties["chat_templates"]] == [
        "m/chat_template.jinja"
    ]
    run = runner.invoke(
        main,
        [
            *("--limit", "file-bytes=64KiB", "scan", str(project)),
            *("--no-project-policy", "-o", str(tmp_path / "bom.json")),
        ],
    )
    assert run.exit_code == 1, run.output
    assert "Scan gate failed" in run.output


def test_an_unreadable_template_file_is_a_failure(tmp_path):
    directory = tmp_path / "m"
    _safetensors(directory / "model.safetensors")
    outside = tmp_path.parent / f"{tmp_path.name}-template.jinja"
    outside.write_text(ESCAPES[0], encoding="utf-8")
    (directory / "chat_template.jinja").symlink_to(outside)
    result = ModelScanner().scan(tmp_path)
    assert [f for f in result.scan_failures if f.startswith("m/chat_template.jinja: ")]
    assert not result.surfaces_excluded


def test_a_code_executing_format_keeps_its_rating_and_gains_the_template_finding(tmp_path):
    directory = tmp_path / "m"
    directory.mkdir()
    (directory / "pytorch_model.bin").write_bytes(b"\x80\x04K\x01.")
    _template(directory, "tokenizer_config.json#chat_template", ESCAPES[1])
    component = _model(tmp_path, "pytorch_model.bin")
    assert component.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    serialization = [r for r in component.risks if r.category == "serialization_format"]
    assert [r.severity for r in serialization] == [RiskSeverity.CRITICAL] * 2
    assert _template_findings(component) == [
        "Model 'pytorch_model.bin' is configured with a chat template containing "
        "a potential Python-internals access pattern: m/tokenizer_config.json#chat_template"
        + DETAIL_END
    ]


@pytest.mark.parametrize(
    ("embedded", "configured", "expected"),
    [
        (BENIGN, ESCAPES[0], ["configured"]),
        (ESCAPES[0], BENIGN, ["embeds"]),
        (ESCAPES[0], ESCAPES[2], ["embeds", "configured"]),
        (BENIGN, BENIGN, []),
    ],
)
def test_gguf_and_directory_templates_are_reported_by_their_own_finding(
    tmp_path, embedded, configured, expected
):
    directory = tmp_path / "m"
    directory.mkdir()
    (directory / "model.gguf").write_bytes(_gguf(embedded))
    _template(directory, "tokenizer_config.json#chat_template", configured)
    component = _model(tmp_path, "model.gguf")
    found = [
        "embeds" if "embeds a chat template" in risk.detail else "configured"
        for risk in component.risks
        if risk.category == "serialization_format"
    ]
    assert found == expected
    # Only the file's own template rates it; a directory template leaves it unknown.
    assert component.serialization_safety == (
        SerializationSafety.UNSAFE_TEMPLATE_INJECTION
        if "embeds" in expected
        else SerializationSafety.UNKNOWN
    )
    unknown = [r for r in component.risks if r.category == "serialization_format_unknown"]
    assert len(unknown) == (0 if "embeds" in expected else 1)


_BAD_HEADER = b'{"bad json!!!!}'
MALFORMED_SAFETENSORS = len(_BAD_HEADER).to_bytes(8, "little") + _BAD_HEADER
UNKNOWN_ARTIFACTS = {
    "model.safetensors": MALFORMED_SAFETENSORS,
    "model.onnx": b"\x08\x08",
    "model.gguf": _gguf(BENIGN),
}


@pytest.mark.parametrize("artifact", sorted(UNKNOWN_ARTIFACTS))
def test_an_unknown_rating_and_its_findings_survive_an_escaping_template(
    tmp_path, monkeypatch, artifact
):
    # The unverified-SafeTensors gate and the unknown-format finding derive from the
    # unknown rating; the template adds its own finding beside them.
    if artifact == "model.gguf":
        # A GGUF file over the metadata bounds keeps the rating unknown.
        monkeypatch.setattr("nexus_symbiote.utils.model_formats.MAX_INSPECTION_UNITS", 2)
    directory = tmp_path / "m"
    directory.mkdir()
    (directory / artifact).write_bytes(UNKNOWN_ARTIFACTS[artifact])
    _template(directory, "tokenizer_config.json#chat_template", ESCAPES[0])
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = result.components
    assert component.serialization_safety == SerializationSafety.UNKNOWN
    assert _template_findings(component) == [
        f"Model '{artifact}' is configured with a chat template containing "
        "a potential Python-internals access pattern: m/tokenizer_config.json#chat_template"
        + DETAIL_END
    ]
    assert [
        (risk.severity, risk.category)
        for risk in component.risks
        if risk.category.startswith("serialization_format")
    ] == [
        (RiskSeverity.CRITICAL, "serialization_format"),
        (RiskSeverity.HIGH, "serialization_format_unknown"),
    ]
    report = RiskScorer().score(AIBOM(components=[component]))
    unverified = "SafeTensors structural safety is unverified" in report.gate_reasons
    assert unverified == (artifact == "model.safetensors")


SUPPRESS_TEMPLATE = """\
version: "1.0"
risk:
  suppressions:
    - component_ref: "model:m/{artifact}"
      category: "serialization_format"
      fingerprint: "{fingerprint}"
      reason: "Template reviewed; rendered only in a sandboxed environment"
      owner: "sec@example.com"
      expires: 2099-12-31
"""


@pytest.mark.parametrize("artifact", ["model.safetensors", "model.onnx"])
def test_accepting_the_template_does_not_accept_the_model_file(runner, tmp_path, artifact):
    # A suppression accepts one category on one component, never the file's own state.
    project = tmp_path / "project"
    directory = project / "m"
    directory.mkdir(parents=True)
    (directory / artifact).write_bytes(UNKNOWN_ARTIFACTS[artifact])
    _template(directory, "tokenizer_config.json#chat_template", ESCAPES[0])
    bom = tmp_path / "bom.json"
    runner.invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(bom)]
    )
    (fingerprint,) = [
        finding.fingerprint
        for finding in RiskScorer().score(AIBOM.load(bom)).findings
        if finding.component_ref == f"model:m/{artifact}"
        and finding.category == "serialization_format"
    ]
    (project / ".nexus-symbiote.yaml").write_text(
        SUPPRESS_TEMPLATE.format(artifact=artifact, fingerprint=fingerprint), encoding="utf-8"
    )
    run = runner.invoke(main, ["scan", str(project), "--accept-project-policy", "-o", str(bom)])
    risk = runner.invoke(
        main,
        [
            "risk",
            str(bom),
            "--project",
            str(project),
            "--accept-project-policy",
            "--json-output",
        ],
    )
    assert risk.exit_code == run.exit_code, risk.output
    scored = json.loads(risk.stdout)
    assert [item["category"] for item in scored["suppressed_findings"]] == ["serialization_format"]
    found = {finding["category"] for finding in scored["findings"]}
    assert "serialization_format_unknown" in found
    if artifact == "model.safetensors":
        assert run.exit_code == 1, run.output
        assert "SafeTensors structural safety is unverified" in run.output
        assert "invalid_safetensors" in found


def test_a_template_changed_to_escape_fails_the_drift_gate(runner, tmp_path):
    project = tmp_path / "project"
    _safetensors(project / "models" / "m" / "model.safetensors")
    outputs = []
    for index, template in enumerate((BENIGN, BENIGN + ESCAPES[0])):
        _template(project / "models" / "m", "tokenizer_config.json#chat_template", template)
        outputs.append(str(tmp_path / f"{index}.json"))
        run = runner.invoke(
            main,
            ["scan", str(project), "--no-project-policy", "--report-only", "-o", outputs[-1]],
        )
        assert run.exit_code == 0, run.output
    run = runner.invoke(main, ["diff", *outputs, "--fail-on-alert"])
    assert run.exit_code == 1, run.output
    assert "[CRITICAL]" in run.output
    risk = runner.invoke(
        main, ["risk", outputs[1], "--no-project-policy", "--project", str(project)]
    )
    assert risk.exit_code == 1, risk.output
    assert "[serialization_format]" in risk.output
    validated = runner.invoke(
        main, ["validate", outputs[1], "--no-project-policy", "--project", str(project)]
    )
    assert validated.exit_code == 1, validated.output
    assert "Declared model loading format permits unsafe behavior" in validated.output


def test_a_tampered_template_verdict_fails_the_completeness_check_not_integrity(runner, tmp_path):
    # validate re-observes each model file's own structure, not its directory's
    # templates; its completeness check and risk --project compare them with a new
    # collection, so an inventory that claims the model safe fails there.
    project = tmp_path / "project"
    weights = project / "models" / "m" / "model.safetensors"
    _safetensors(weights)
    _template(weights.parent, "tokenizer_config.json#chat_template", ESCAPES[0])
    signers = tmp_path / "signers.json"
    pin = {
        "kind": "digest-pin",
        "artifact_path": "models/m/model.safetensors",
        "expected_sha256": "sha256:" + hashlib.sha256(weights.read_bytes()).hexdigest(),
    }
    signers.write_text(json.dumps({"version": 2, "artifacts": [pin]}), encoding="utf-8")
    trusted = ("--project", str(project), "--signature-policy", str(signers))
    bom = tmp_path / "bom.json"
    run = runner.invoke(
        main, ["scan", str(project), "--no-project-policy", *trusted[2:], "-o", str(bom)]
    )
    assert run.exit_code == 1, run.output
    document = json.loads(bom.read_text(encoding="utf-8"))
    (model,) = [c for c in document["components"] if c["bom_ref"].startswith("model:")]
    assert model["serialization_safety"] == "unsafe-template-injection"
    model["serialization_safety"] = "safe"
    model["risks"] = [r for r in model["risks"] if r["category"] != "serialization_format"]
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(document), encoding="utf-8")
    mismatch = (
        "Missing or mismatched local component from model files: model:models/m/model.safetensors"
    )
    for command in ("validate", "risk"):
        checked = runner.invoke(main, [command, str(tampered), "--no-project-policy", *trusted])
        assert checked.exit_code == 1, checked.output
        assert mismatch in checked.output, checked.output
    (project / ".nexus-symbiote.yaml").write_text(
        'version: "1.0"\nvalidate:\n  require_completeness: false\n', encoding="utf-8"
    )
    skipped = runner.invoke(main, ["validate", str(tampered), *trusted])
    assert "Integrity check\n  Status: PASS" in skipped.output, skipped.output


def test_joined_dunder_template_fails_scan_validate_and_risk_with_pinned_weights(runner, tmp_path):
    project = tmp_path / "project"
    weights = project / "models" / "m" / "model.safetensors"
    _safetensors(weights)
    _template(weights.parent, "tokenizer_config.json#chat_template", ESCAPES[-1])
    signers = tmp_path / "signers.json"
    signers.write_text(
        json.dumps(
            {
                "version": 2,
                "artifacts": [
                    {
                        "kind": "digest-pin",
                        "artifact_path": "models/m/model.safetensors",
                        "expected_sha256": "sha256:"
                        + hashlib.sha256(weights.read_bytes()).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    bom = tmp_path / "bom.json"
    policy = ["--no-project-policy", "--signature-policy", str(signers)]
    scan = runner.invoke(main, ["scan", str(project), *policy, "-o", str(bom)])
    assert scan.exit_code == 1, scan.output
    model = next(
        c for c in json.loads(bom.read_text())["components"] if c["bom_ref"].startswith("model:")
    )
    assert model["serialization_safety"] == "unsafe-template-injection"
    for command in ("validate", "risk"):
        checked = runner.invoke(main, [command, str(bom), "--project", str(project), *policy])
        assert checked.exit_code == 1, checked.output


def test_joined_dunder_in_embedded_gguf_template_is_reported(tmp_path):
    directory = tmp_path / "m"
    directory.mkdir()
    (directory / "model.gguf").write_bytes(_gguf(ESCAPES[-1]))
    component = _model(tmp_path, "model.gguf")
    assert component.serialization_safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION
    (risk,) = [r for r in component.risks if r.category == "serialization_format"]
    assert risk.severity == RiskSeverity.CRITICAL
    assert "potential Python-internals access pattern" in risk.detail
    assert risk.references == [
        "https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/model-integrity.md"
    ]


def test_joined_literal_check_scales_with_template_size():
    from nexus_symbiote.utils.model_formats import template_escape_markers

    unit = b"{{ 'a' ~ 'b' ~ 'c' ~ 'd' }}"

    def run(scale: int) -> None:
        assert not template_escape_markers(unit * 5_000 * scale)

    assert scaling_ratio(run) < 10


def test_records_are_identical_wherever_the_project_is_checked_out(tmp_path):
    components = []
    for root in (tmp_path / "one", tmp_path / "two" / "nested"):
        _safetensors(root / "m" / "model.safetensors")
        _template(root / "m", "tokenizer_config.json#chat_template", ESCAPES[0])
        _template(root / "m", "additional_chat_templates/a.jinja", ESCAPES[2])
        components.append(ModelScanner().scan(root).components)
    assert components[0] == components[1]
    assert str(tmp_path) not in repr(components[0])


def test_checking_large_templates_scales_linearly(tmp_path):
    # Near-misses of every escape shape, which a backtracking pattern could make quadratic.
    unit = ".__" + "a" * 40 + " ['__" + "b" * 40 + "'" + "attr " * 4 + ". " * 8
    unit += "\\N{" + "A" * 99 + " \\\\ \\x5 \\u005 \\U0000005 '_\\x5f" + "c" * 40 + "_ "
    roots: dict[int, Path] = {}
    for scale in (1, 4):
        root = tmp_path / str(scale)
        _safetensors(root / "m" / "model.safetensors")
        _template(root / "m", "chat_template.jinja", unit * 2_000 * scale)
        _template(root / "m", "tokenizer_config.json#chat_template", unit * 2_000 * scale)
        roots[scale] = root

    def run(scale: int) -> None:
        component = _model(roots[scale])
        assert component.serialization_safety == SerializationSafety.SAFE

    assert scaling_ratio(run) < 10


def test_a_template_replaced_while_it_is_read_is_digested_and_a_gap(tmp_path, monkeypatch):
    from nexus_symbiote.utils.confined import ConfinedCollection

    directory = tmp_path / "m"
    _safetensors(directory / "model.safetensors")
    _template(directory, "chat_template.jinja", ESCAPES[0])
    regular_file = ConfinedCollection.regular_file

    def replaced(self: ConfinedCollection, path: str | Path) -> tuple[Path, int] | None:
        return None if Path(path).name == "chat_template.jinja" else regular_file(self, path)

    monkeypatch.setattr(ConfinedCollection, "regular_file", replaced)
    result = ModelScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        "m/chat_template.jinja: chat template not inspected: the file could not be read whole"
    ]
    (component,) = result.components
    assert [item["source"] for item in component.properties["chat_templates"]] == [
        "m/chat_template.jinja"
    ]


def test_a_template_that_cannot_be_read_is_not_recorded(tmp_path, monkeypatch):
    from nexus_symbiote.utils.confined import ConfinedCollection

    directory = tmp_path / "m"
    _safetensors(directory / "model.safetensors")
    _template(directory, "chat_template.jinja", ESCAPES[0])
    read_bytes = ConfinedCollection.read_bytes

    def refused(self: ConfinedCollection, path: str | Path, **options: Any) -> bytes | None:
        if Path(path).name == "chat_template.jinja":
            self._fail(path, "file changed during collection")
            return None
        return read_bytes(self, path, **options)

    monkeypatch.setattr(ConfinedCollection, "read_bytes", refused)
    result = ModelScanner().scan(tmp_path)
    assert result.scan_failures == ["m/chat_template.jinja: file changed during collection"]
    (component,) = result.components
    assert "chat_templates" not in component.properties


def test_a_large_template_that_cannot_be_digested_is_a_failure_not_a_gap(tmp_path):
    directory = tmp_path / "m"
    _safetensors(directory / "model.safetensors")
    _template(directory, "chat_template.jinja", "{# padding #}" * 6_000)
    with limits.applied(limits.resolve(["file-bytes=64KiB", "model-bytes=64KiB"], {})):
        result = ModelScanner().scan(tmp_path)
    assert result.scan_failures == [
        "m/chat_template.jinja: model-bytes limit of 64 KiB exceeded; "
        "raise it with --limit model-bytes=N"
    ]
    assert not result.surfaces_excluded


def test_an_in_root_linked_template_is_read_through_its_target(tmp_path):
    # As configuration files are: a relative link to a regular file in the project.
    directory = tmp_path / "m"
    _safetensors(directory / "model.safetensors")
    _template(tmp_path / "shared", "t.jinja", ESCAPES[0])
    (directory / "chat_template.jinja").symlink_to("../shared/t.jinja")
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    (component,) = result.components
    assert component.serialization_safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION
    assert _template_findings(component) == [f"{DETAIL}m/chat_template.jinja{DETAIL_END}"]


@pytest.mark.parametrize(
    ("link", "target"),
    [("../../shared/extra", "shared/extra"), ("templates", "m/m/templates")],
    ids=["elsewhere", "beside"],
)
def test_a_linked_template_directory_is_read_through_the_link(tmp_path, link, target):
    # The walk lists a linked directory under its target's name; a loader opens the link.
    directory = tmp_path / "m" / "m"
    _safetensors(directory / "model.safetensors")
    _template(tmp_path / target, "tool_use.jinja", ESCAPES[0])
    _template(tmp_path / target, "notes.txt", "not a template")
    (directory / "additional_chat_templates").symlink_to(link)
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    (component,) = result.components
    assert component.serialization_safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION
    source = "m/m/additional_chat_templates/tool_use.jinja"
    assert _template_findings(component) == [f"{DETAIL}{source}{DETAIL_END}"]
    assert [item["source"] for item in component.properties["chat_templates"]] == [source]


def test_a_linked_template_directory_that_leaves_the_root_is_a_failure(tmp_path):
    root = tmp_path / "project"
    _safetensors(root / "m" / "model.safetensors")
    _template(tmp_path / "outside", "tool_use.jinja", ESCAPES[0])
    (root / "m" / "additional_chat_templates").symlink_to("../../outside")
    result = ModelScanner().scan(root)
    assert any(
        failure.startswith("m/additional_chat_templates: ") for failure in result.scan_failures
    )


def test_a_template_directory_with_only_a_subdirectory_records_nothing(tmp_path):
    _safetensors(tmp_path / "m" / "model.safetensors")
    (tmp_path / "m" / "additional_chat_templates" / "nested").mkdir(parents=True)
    _template(tmp_path / "m" / "additional_chat_templates" / "nested", "t.jinja", ESCAPES[0])
    component = _model(tmp_path)
    assert component.serialization_safety == SerializationSafety.SAFE
    assert "chat_templates" not in component.properties


VARIANT = (
    "{variant}: case variant of {path} is the active file on case-insensitive file systems "
    "and is not inventoried"
)


@pytest.mark.parametrize(
    ("variant", "path"),
    [
        ("Chat_Template.jinja", "chat_template.jinja"),
        ("CHAT_TEMPLATE.JINJA2", "chat_template.jinja2"),
        ("Tokenizer_Config.json#chat_template", "tokenizer_config.json"),
        ("Config.json#trust_remote_code", "config.json"),
        ("Tokenizer.json#x", "tokenizer.json"),
        ("Additional_Chat_Templates/tool_use.jinja", "additional_chat_templates"),
    ],
)
def test_a_case_variant_of_a_model_file_is_a_failure(tmp_path, variant, path):
    # Case-insensitive file systems open the variant when a loader asks for the exact name.
    _safetensors(tmp_path / "m" / "model.safetensors")
    _template(tmp_path / "m", variant, ESCAPES[0])
    result = ModelScanner().scan(tmp_path)
    name = variant.partition("#")[0].partition("/")[0]
    assert result.scan_failures == [VARIANT.format(variant=f"m/{name}", path=f"m/{path}")]


def test_a_case_variant_of_a_linked_template_directory_is_a_failure(tmp_path):
    _safetensors(tmp_path / "m" / "model.safetensors")
    _template(tmp_path / "shared", "tool_use.jinja", ESCAPES[0])
    (tmp_path / "m" / "Additional_Chat_Templates").symlink_to("../shared")
    result = ModelScanner().scan(tmp_path)
    assert result.scan_failures == [
        VARIANT.format(variant="m/Additional_Chat_Templates", path="m/additional_chat_templates")
    ]


def test_another_spelling_beside_the_exact_name_is_not_read_or_reported(tmp_path):
    (tmp_path / "probe").write_text("")
    sensitive = not (tmp_path / "PROBE").exists()
    (tmp_path / "probe").unlink()
    if not sensitive:
        pytest.skip("needs a case-sensitive file system to hold both spellings")
    _safetensors(tmp_path / "m" / "model.safetensors")
    _template(tmp_path / "m", "chat_template.jinja", BENIGN)
    _template(tmp_path / "m", "Chat_Template.jinja", ESCAPES[0])
    component = _model(tmp_path)
    assert component.serialization_safety == SerializationSafety.SAFE
    assert [item["source"] for item in component.properties["chat_templates"]] == [
        "m/chat_template.jinja"
    ]


def test_a_case_variant_fails_the_scan_gate(runner, tmp_path):
    project = tmp_path / "project"
    _safetensors(project / "m" / "model.safetensors")
    _template(project / "m", "tokenizer_config.json#chat_template", BENIGN)
    _template(project / "m", "Chat_Template.jinja", ESCAPES[0])
    output = tmp_path / "agentbom.json"
    result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert result.exit_code == 1, result.output
    assert "case variant of m/chat_template.jinja" in result.output
