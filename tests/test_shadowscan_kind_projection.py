"""Project ShadowScan's agent-config and framework-usage findings, one resource type each.

Producer contract reviewed at ShadowScan 0.1.4, commit
2b80f199659a8de17ea9c7792c07940d5b747d72. connectors/code/project_findings.py reports a
project as kind=framework-usage with resource_type=project, and connectors/common.py
gives the same finding kind=agent once it carries an agent indicator. The project may
use an agent framework, a model SDK or only the MCP SDK. One coding-agent signature in
one project is kind=agent-config with resource_type=coding-agent-config: a product such
as Claude Code, or an instruction convention such as AGENTS.md or a set of SKILL.md
files. Other connectors use both kinds for a lockfile, a platform setting or a registry
record; those stay unmapped. The synthetic reports below carry hostile metadata.
fixtures/shadowscan/README.md describes the real one.
"""

import hashlib
import json
import re
import shutil
from collections import Counter
from pathlib import Path

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, RiskSeverity, TrustTier
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.vex import VEXGenerator
from nexus_symbiote.scanners import shadowscan
from nexus_symbiote.scanners.shadowscan import PROJECTION_PROFILE, ShadowScanImporter
from nexus_symbiote.validators.risk import RiskScorer

FIXTURES = Path(__file__).parent / "fixtures/shadowscan"
REPORT = FIXTURES / "agent-framework-report-0.1.4.json"
CYCLONEDX = FIXTURES / "agent-framework-report-0.1.4.cdx.json"
README = FIXTURES / "README.md"
DOCS = Path(__file__).parents[1] / "docs/shadowscan-integration.md"
PAIRS = [
    ("agent-config", "coding-agent-config", ComponentType.IDE_AGENT),
    ("framework-usage", "project", ComponentType.AGENT),
]
BOUND = {kind: resource_type for kind, resource_type, _ in PAIRS}
# Resource types that ShadowScan 0.1.4 gives the two kinds elsewhere, and near misses.
TWINS = [
    ("agent-config", "platform-setting"),
    ("agent-config", "copilot-billing"),
    ("agent-config", "unresolved-parent-configuration"),
    ("agent-config", "agent-config"),
    ("agent-config", "ide-extension"),
    ("agent-config", "agent-registry-skill"),
    ("agent-config", "agent-registry-record"),
    ("agent-config", "agentcore-registry-record"),
    ("agent-config", "project"),
    ("agent-config", "Coding-Agent-Config"),
    ("agent-config", "coding-agent-config "),
    ("agent-config", "coding-agent-config/x"),
    ("agent-config", ""),
    ("agent-config", None),
    ("framework-usage", "lockfile-inventory"),
    ("framework-usage", "source-agent"),
    ("framework-usage", "agent-manifest"),
    ("framework-usage", "prompt-templates"),
    ("framework-usage", "process/model-runtime-indicator"),
    ("framework-usage", "a2a-agent-card"),
    ("framework-usage", "coding-agent-config"),
    ("framework-usage", "Project"),
    ("framework-usage", "project "),
    ("framework-usage", "project/x"),
    ("framework-usage", ""),
    ("framework-usage", None),
]
# Kind and resource type of the 24 findings of a code report of a larger synthetic
# project, in the report's order.
BENCHMARK = [
    ("agent-config", "coding-agent-config"),
    ("secret", "file"),
    ("mcp-server", "mcp-config"),
    ("agent-config", "coding-agent-config"),
    ("agent", "project"),
    ("secret", "file"),
    ("mcp-server", "mcp-config"),
    ("mcp-server", "mcp-config"),
    ("mcp-server", "mcp-config"),
    ("agent-config", "coding-agent-config"),
    ("agent-config", "coding-agent-config"),
    ("agent", "agent-manifest"),
    ("mcp-server", "mcp-config"),
    ("mcp-server", "mcp-config"),
    ("mcp-server", "mcp-config"),
    ("agent-config", "coding-agent-config"),
    ("agent-config", "coding-agent-config"),
    ("agent", "project"),
    ("agent", "workflow-export"),
    ("framework-usage", "project"),
    ("infra", "iac"),
    ("infra", "iac"),
    ("agent-config", "coding-agent-config"),
    ("infra", "iac"),
]
LIMITATION = "5 source entries were not mapped into BOM components (infra: 3; secret: 2)"
GAP = "ShadowScan report contains unmapped entries: infra, secret"


def finding(kind, resource_type=None, ident="f-0", **fields):
    record = {
        "id": ident,
        "kind": kind,
        "surface": "code",
        "title": "CANARY",
        "resource": "/abs/CANARY",
        "metadata": {"path": "CANARY", "files": ["CANARY.md"]},
        **fields,
    }
    if resource_type is not None:
        record["resource_type"] = resource_type
    return record


def native(*findings):
    return {
        "version": "0.1.4",
        "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
        "stats": [{"errors": [], "skipped": False, "incomplete": False}],
        "findings": list(findings),
    }


def entry(kind, resource_type=None, ident="f-0", **fields):
    properties = [{"name": "shadowscan:resource", "value": "/abs/CANARY"}]
    if kind is not None:
        properties.append({"name": "shadowscan:kind", "value": kind})
    if resource_type is not None:
        properties.append({"name": "shadowscan:resource-type", "value": resource_type})
    return {
        "bom-ref": ident,
        "type": "application",
        "group": "code",
        "name": "CANARY",
        "properties": properties,
        **fields,
    }


def cyclonedx(*entries, key="components"):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {"properties": [{"name": "shadowscan:scan:status", "value": "complete"}]},
        key: list(entries),
    }


def parse(report):
    return ShadowScanImporter().parse_report(json.dumps(report))


def scan_gaps(tmp_path, report):
    (tmp_path / "shadowscan.json").write_text(json.dumps(report), encoding="utf-8")
    return list(ShadowScanImporter().scan(tmp_path).surfaces_excluded)


def project(tmp_path, report):
    root = tmp_path / "project"
    root.mkdir()
    (root / "agent.yaml").write_text("name: Local agent\ninstructions: [protocol.txt]\n")
    (root / "protocol.txt").write_text("Use the declared tools.")
    (root / "shadowscan.json").write_bytes(report)
    return root


def validation(root, inventory):
    args = ["validate", str(inventory), "--project", str(root)]
    return [*args, "--no-project-policy", "--allow-unsigned-discovery"]


def with_findings(report, *kinds, resource_type=None):
    """The real report with one more finding of each kind, and a summary that agrees."""
    data = json.loads(report)
    for number, kind in enumerate(kinds):
        data["findings"].append(finding(kind, resource_type, ident=f"ss-twin-{number}"))
    summary = data["summary"]
    summary["total"] += len(kinds)
    summary["by_surface"]["code"] += len(kinds)
    summary["by_kind"] = dict(Counter(found["kind"] for found in data["findings"]))
    return json.dumps(data).encode()


def merged(runner, tmp_path, name, report):
    """A merged scan of the same small project holding ``report``, as a document."""
    root = tmp_path / name
    root.mkdir()
    target = root / "bom.json"
    args = ["scan", str(project(root, report)), "--no-project-policy", "--report-only"]
    result = runner.invoke(main, [*args, "-o", str(target)])
    assert result.exit_code == 0, result.output
    return json.loads(target.read_bytes())


def as_projection_v5(document):
    """What projection version 5 recorded for the same report and project.

    It projected no agent-config or framework-usage finding and named no kind.
    """
    older = json.loads(json.dumps(document))
    claim = older["metadata"]["completeness"]
    dropped = [c for c in older["components"] if c["properties"].get("shadowscan:kind") in BOUND]
    older["components"] = [c for c in older["components"] if c not in dropped]
    for component in older["components"]:
        if "shadowscan:projection-profile" in component["properties"]:
            component["properties"]["shadowscan:projection-profile"] = (
                "nexus-symbiote/shadowscan-projection/v5"
            )
    indexes = claim["source_unmapped_indexes"] + [
        c["properties"]["shadowscan:finding-index"] for c in dropped
    ]
    claim["source_unmapped_indexes"] = sorted(indexes)
    claim["source_unmapped_count"] = len(indexes)
    counted = f"{len(indexes)} source entries were not mapped into BOM components"
    limitations = [
        line for line in claim["source_projection_limitations"] if "not mapped" not in line
    ]
    claim["source_projection_limitations"] = [*limitations[:2], counted, *limitations[2:]]
    claim["surfaces_excluded"] = ["ShadowScan report contains unmapped entries"]
    claim["scanner_status"]["shadowscan"] = "partial"
    return older


def alerts(report, severity="high"):
    return [a["alert"] for a in report.security_alerts if a["severity"] == severity]


def documented_tree():
    text = README.read_text(encoding="utf-8")
    return dict(re.findall(r"^`([^`\n]+)`\n\n```[a-z]+\n(.*?)^```$", text, re.M | re.S))


def strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, str):
        yield value


@pytest.mark.parametrize(("kind", "resource_type", "component_type"), PAIRS)
@pytest.mark.parametrize("form", ["native", "cyclonedx-component", "cyclonedx-service"])
def test_the_bound_resource_type_is_projected_from_every_report_form(
    kind, resource_type, component_type, form
):
    service = entry(kind, resource_type)
    del service["type"]
    report = {
        "native": native(finding(kind, resource_type)),
        "cyclonedx-component": cyclonedx(entry(kind, resource_type)),
        "cyclonedx-service": cyclonedx(service, key="services"),
    }[form]
    result = parse(report)
    assert (result.unmapped_count, result.unmapped_indexes, result.unmapped_kinds) == (0, [], {})
    (component,) = result.components
    digest = hashlib.sha256(b"f-0").hexdigest()
    assert component.component_type == component_type
    assert component.bom_ref == "shadowscan:" + digest
    assert component.name == f"ShadowScan {kind} {digest[:12]}"
    assert component.assurance_level == AssuranceLevel.DECLARED
    assert component.trust_tier == TrustTier.UNKNOWN
    assert component.properties["shadowscan:kind"] == kind
    assert component.properties["shadowscan:resource-type"] == resource_type
    assert component.properties["shadowscan:projection-profile"] == PROJECTION_PROFILE
    assert component.properties["collection_mode"] == "imported-unverified-report"
    assert component.source_path is None and component.claims == {} and component.risks == []
    if component_type == ComponentType.IDE_AGENT:
        assert (component.ide_type, component.permission_mode) == (None, None)
        assert component.config_files == component.mcp_server_refs == component.prompt_refs == []
    else:
        assert (component.autonomy_level, component.framework) == (None, None)
        assert component.deployment_status == "unknown"
        assert component.model_refs == component.tool_refs == component.prompt_refs == []
    assert "CANARY" not in repr(result)
    assert "CANARY" not in result.to_native_bom().model_dump_json()


@pytest.mark.parametrize(("kind", "resource_type"), TWINS)
def test_any_other_resource_type_of_the_two_kinds_stays_unmapped(tmp_path, kind, resource_type):
    for report in (native(finding(kind, resource_type)), cyclonedx(entry(kind, resource_type))):
        result = parse(report)
        assert result.components == []
        assert result.unmapped_indexes == [0]
        assert result.unmapped_kinds == {f"{kind} (unprojected form)": 1}
        gap = f"ShadowScan report contains unmapped entries: {kind} (unprojected form)"
        assert gap in scan_gaps(tmp_path, report)


@pytest.mark.parametrize(("kind", "resource_type"), sorted(BOUND.items()))
@pytest.mark.parametrize("spelling", ["upper", "title", "leading space", "trailing space"])
def test_another_spelling_of_the_two_kinds_is_not_read_as_the_kind(kind, resource_type, spelling):
    written = {
        "upper": kind.upper(),
        "title": kind.title(),
        "leading space": " " + kind,
        "trailing space": kind + " ",
    }[spelling]
    for report in (
        native(finding(written, resource_type)),
        cyclonedx(entry(written, resource_type)),
    ):
        result = parse(report)
        assert result.components == []
        assert result.unmapped_kinds == {"unrecognized kind": 1}


@pytest.mark.parametrize(
    "kind",
    ["secret ", " secret", "secret\n", "infra\t", "agent ", "\tmcp-server", "model ", " ", "\n"],
)
def test_a_kind_with_white_space_around_it_is_never_named_by_the_report(kind):
    for report in (native(finding(kind)), cyclonedx(entry(kind))):
        result = parse(report)
        assert result.components == []
        assert result.unmapped_kinds == {"unrecognized kind": 1}
        assert result.limitations[-1] == (
            "1 source entries were not mapped into BOM components (unrecognized kind: 1)"
        )


@pytest.mark.parametrize(
    ("report", "label"),
    [
        (native(finding("agent", "mcp-tool")), "agent (unprojected form)"),
        (
            cyclonedx(entry("mcp-server", type="machine-learning-model")),
            "mcp-server (unprojected form)",
        ),
        (cyclonedx(entry("local-model", group="mcp-server")), "local-model (unprojected form)"),
        (native(finding("model", "mcp-tool")), "model (unprojected form)"),
    ],
)
def test_a_refused_form_of_every_projected_kind_reads_unprojected_form(report, label):
    result = parse(report)
    assert result.components == [] and result.unmapped_kinds == {label: 1}


@pytest.mark.parametrize("kind", sorted(BOUND))
@pytest.mark.parametrize("shape", ["number", "boolean", "list", "object"])
def test_a_resource_type_that_is_not_a_string_stays_unmapped(kind, shape):
    bound = BOUND[kind]
    value = {"number": 7, "boolean": True, "list": [bound], "object": {bound: bound}}[shape]
    result = parse(native(finding(kind, value)))
    assert result.components == []
    assert result.unmapped_kinds == {f"{kind} (unprojected form)": 1}


@pytest.mark.parametrize(("kind", "resource_type"), sorted(BOUND.items()))
def test_a_contradicting_classification_is_not_resolved_by_precedence(kind, resource_type):
    for report in (
        native(finding(kind, "mcp-tool")),
        cyclonedx(entry(kind, "mcp-tool")),
        cyclonedx(entry(kind, resource_type, type="machine-learning-model")),
        cyclonedx(entry(kind, resource_type, group="mcp-server")),
    ):
        result = parse(report)
        assert result.components == []
        assert result.unmapped_indexes == [0]
        assert result.unmapped_kinds == {f"{kind} (unprojected form)": 1}


@pytest.mark.parametrize(("kind", "resource_type"), sorted(BOUND.items()))
def test_a_rating_and_a_shadow_flag_are_carried_and_an_unreadable_rating_is_a_gap(
    tmp_path, kind, resource_type
):
    rated = finding(kind, resource_type, risk={"level": "high"}, shadow=True)
    (component,) = parse(native(rated)).components
    assert [(r.severity.value, r.category) for r in component.risks] == [
        ("high", "shadowscan-heuristic"),
        ("info", "shadowscan-inventory-unmatched"),
    ]
    assert component.properties["shadowscan:inventory-unmatched"] is True
    unreadable = native(finding(kind, resource_type, risk={"level": "Critical"}))
    result = parse(unreadable)
    assert result.components[0].risks == [] and result.unmapped_count == 0
    assert (
        "1 source entries carry a risk level the projection does not recognize; it is not "
        "represented" in result.limitations
    )
    assert scan_gaps(tmp_path, unreadable) == [shadowscan.UNRECOGNIZED_VALUES_GAP]


def test_cyclonedx_edges_of_the_two_kinds_are_copied_when_both_ends_map():
    report = cyclonedx(
        entry("agent-config", "coding-agent-config", "c-0"),
        entry("framework-usage", "project", "c-1"),
        entry(None, ident="c-2", type="machine-learning-model"),
        entry("agent-config", "ide-extension", "c-3"),
    )
    report["dependencies"] = [
        {"ref": "c-0", "dependsOn": ["c-2"]},
        {"ref": "c-1", "dependsOn": ["c-2", "c-3"]},
        {"ref": "c-3", "dependsOn": ["c-2"]},
    ]
    result = parse(report)
    types = {c.bom_ref: c.component_type.value for c in result.components}
    assert sorted(
        (types[e.source_ref], types[e.target_ref], e.relationship, e.assurance_level)
        for e in result.dependencies
    ) == [
        ("agent", "model", "depends-on", "declared"),
        ("ide-agent", "model", "depends-on", "declared"),
    ]
    assert (
        "2 source dependency edges have unmapped endpoints and were not projected"
        in result.limitations
    )
    assert "CANARY" not in repr(result)


def test_existing_rows_keep_their_types_and_record_no_resource_type():
    result = parse(
        native(
            finding("agent", "project", "f-0"),
            finding("agent", "coding-agent-config", "f-1"),
            finding("mcp-server", "mcp-config", "f-2"),
            finding("local-model", "project", "f-3"),
        )
    )
    assert [c.component_type.value for c in result.components] == [
        "agent",
        "agent",
        "mcp-server",
        "model",
    ]
    assert not any("shadowscan:resource-type" in c.properties for c in result.components)
    assert result.unmapped_kinds == {}


def test_unmapped_entries_are_counted_by_kind_from_a_fixed_vocabulary(tmp_path):
    hostile = "secret\u202e CANARY"
    report = native(
        finding("secret", "file", "f-0"),
        finding("infra", "iac", "f-1"),
        finding("token", ident="f-2"),
        finding("oauth-grant", ident="f-3"),
        finding("infra", "iac", "f-4"),
        finding(hostile, ident="f-5"),
        finding("framework-usage", "lockfile-inventory", "f-6"),
        finding("", ident="f-7"),
        finding("Secret", "file", "f-8"),
        finding("agent", "project", "f-9"),
    )
    result = parse(report)
    assert result.unmapped_indexes == [0, 1, 2, 3, 4, 5, 6, 7, 8]
    assert result.unmapped_count == sum(result.unmapped_kinds.values()) == 9
    assert result.limitations[-1] == (
        "9 source entries were not mapped into BOM components (framework-usage (unprojected "
        "form): 1; infra: 2; no kind: 1; oauth-grant: 1; secret: 1; token: 1; "
        "unrecognized kind: 2)"
    )
    assert scan_gaps(tmp_path, report) == [
        "ShadowScan report contains unmapped entries: framework-usage (unprojected form), "
        "infra, no kind, oauth-grant, secret, token, unrecognized kind"
    ]
    document = result.to_native_bom().model_dump_json()
    for text in (repr(result), document):
        assert "CANARY" not in text and "\u202e" not in text and "Secret" not in text


def test_a_cyclonedx_entry_without_a_kind_reads_no_kind(tmp_path):
    report = cyclonedx(entry(None, ident="c-0"), entry("agent", ident="c-1"))
    result = parse(report)
    assert result.unmapped_indexes == [0] and result.unmapped_kinds == {"no kind": 1}
    assert "1 source entries were not mapped into BOM components (no kind: 1)" in result.limitations
    assert "ShadowScan report contains unmapped entries: no kind" in scan_gaps(tmp_path, report)


def test_report_text_never_names_an_unmapped_entry():
    kinds = ["CANARY", "infra\x1b[2K", "agent-config\u200b", "x" * 5000]
    result = parse(native(*(finding(kind, ident=f"f-{n}") for n, kind in enumerate(kinds))))
    assert result.unmapped_kinds == {"unrecognized kind": 4}
    assert result.limitations[-1] == (
        "4 source entries were not mapped into BOM components (unrecognized kind: 4)"
    )
    text = repr(result) + result.to_native_bom().model_dump_json()
    assert not any(part in text for part in ("CANARY", "infra", "agent-config", "xxxx"))


def test_a_report_shaped_like_a_larger_code_scan_leaves_only_its_secrets_and_infrastructure(
    tmp_path,
):
    findings = [
        finding(kind, resource_type, f"f-{n}") for n, (kind, resource_type) in enumerate(BENCHMARK)
    ]
    result = parse(native(*findings))
    assert result.unmapped_indexes == [1, 5, 20, 21, 23]
    assert result.unmapped_kinds == {"infra": 3, "secret": 2}
    assert result.limitations[-1] == LIMITATION
    assert Counter(c.component_type.value for c in result.components) == {
        "ide-agent": 7,
        "mcp-server": 7,
        "agent": 5,
    }
    assert scan_gaps(tmp_path, native(*findings)) == [GAP]
    backwards = parse(native(*reversed(findings)))
    assert backwards.limitations[-1] == LIMITATION
    assert scan_gaps(tmp_path, native(*reversed(findings))) == [GAP]


def test_a_promoted_finding_is_one_modified_component_not_a_new_type():
    before, after = (
        parse(native(finding(kind, "project"))).to_native_bom()
        for kind in ("framework-usage", "agent")
    )
    (earlier,), (later,) = before.components, after.components
    assert earlier.bom_ref == later.bom_ref
    assert earlier.component_type == later.component_type == ComponentType.AGENT
    report = AIBOMDiffer().diff(before, after)
    assert not report.components_added and not report.components_removed
    (change,) = report.components_modified
    assert (change.bom_ref, change.severity) == (later.bom_ref, "medium")
    assert "properties.shadowscan:kind changed." in change.details
    assert not any("component_type" in detail for detail in change.details)


def test_the_first_diff_from_projection_v5_alerts_as_documented(runner, tmp_path):
    newer = merged(runner, tmp_path, "newer", with_findings(REPORT.read_bytes(), "infra"))
    older = as_projection_v5(newer)
    report = AIBOMDiffer().diff(AIBOM.model_validate(older), AIBOM.model_validate(newer))
    assert sorted((c.component_type, c.severity) for c in report.components_added) == [
        ("agent", "medium"),
        ("ide-agent", "medium"),
    ]
    assert not report.components_removed
    assert sorted(
        (c.component_type, c.severity, *c.details) for c in report.components_modified
    ) == [
        ("agent", "medium", "properties.shadowscan:projection-profile changed."),
        ("mcp-server", "medium", "properties.shadowscan:projection-profile changed."),
    ]
    assert alerts(report) == [
        "New coverage gaps: ShadowScan report contains unmapped entries: infra.",
        "New ShadowScan projection limitations: 1 source entries were not mapped into BOM "
        "components (infra: 1).",
    ]
    assert len(alerts(report, "medium")) == 4 and not alerts(report, "critical")
    assert "ShadowScan entries left unmapped fell from 3 to 1." in [
        change["detail"] for change in report.metadata_changes
    ]


def test_the_first_diff_from_projection_v5_alerts_high_when_shadowscan_ran_again(runner, tmp_path):
    first = with_findings(REPORT.read_bytes(), "infra")
    older = as_projection_v5(merged(runner, tmp_path, "first", first))
    again = json.loads(first)
    again["started_at"] = again["finished_at"] = "2026-11-20T08:00:00+00:00"
    newer = merged(runner, tmp_path, "again", json.dumps(again).encode())
    report = AIBOMDiffer().diff(AIBOM.model_validate(older), AIBOM.model_validate(newer))
    assert sorted(
        (c.component_type, c.severity, *c.details) for c in report.components_modified
    ) == [
        (
            component_type,
            "high",
            "properties.shadowscan:report-sha256 changed.",
            "properties.shadowscan:projection-profile changed.",
        )
        for component_type in ("agent", "mcp-server")
    ]
    assert "ShadowScan report regenerated; normalized content unchanged." in [
        change["detail"] for change in report.metadata_changes
    ]
    same_profile = AIBOMDiffer().diff(
        AIBOM.model_validate(merged(runner, tmp_path, "same", first)), AIBOM.model_validate(newer)
    )
    assert not same_profile.components_modified and not same_profile.security_alerts


def test_the_coverage_gap_changes_with_the_set_of_unmapped_kinds_and_the_limitation_with_a_count(
    runner, tmp_path
):
    one, two, mixed = (
        AIBOM.model_validate(
            merged(runner, tmp_path, name, with_findings(REPORT.read_bytes(), *kinds))
        )
        for name, kinds in (("a", ["infra"]), ("b", ["infra", "infra"]), ("c", ["infra", "secret"]))
    )
    content = "ShadowScan report content changed; review the report and the imported components."
    limitation = (
        "New ShadowScan projection limitations: {} source entries were not mapped into BOM "
        "components ({})."
    )
    more = AIBOMDiffer().diff(one, two)
    assert set(alerts(more)) == {
        content,
        "ShadowScan entries left unmapped rose from 1 to 2.",
        limitation.format(2, "infra: 2"),
    }
    fewer = AIBOMDiffer().diff(two, one)
    assert set(alerts(fewer)) == {content, limitation.format(1, "infra: 1")}
    assert "ShadowScan entries left unmapped fell from 2 to 1." in [
        change["detail"] for change in fewer.metadata_changes
    ]
    another_kind = AIBOMDiffer().diff(two, mixed)
    assert set(alerts(another_kind)) == {
        content,
        "New coverage gaps: ShadowScan report contains unmapped entries: infra, secret.",
        limitation.format(2, "infra: 1; secret: 1"),
    }


def test_agent_framework_code_report_imports_with_no_unmapped_entries(runner, tmp_path):
    imported = ShadowScanImporter().parse_report(REPORT.read_bytes())
    assert (imported.unmapped_count, imported.unmapped_indexes) == (0, [])
    assert [
        (c.properties["shadowscan:kind"], c.component_type.value) for c in imported.components
    ] == [
        ("mcp-server", "mcp-server"),
        ("agent-config", "ide-agent"),
        ("agent", "agent"),
        ("framework-usage", "agent"),
    ]
    root = project(tmp_path, REPORT.read_bytes())
    output = tmp_path / "baseline.json"
    result = runner.invoke(main, ["baseline", str(root), "-o", str(output)])
    assert result.exit_code == 0, result.output
    claim = AIBOM.load(output).metadata.completeness
    assert claim.scanner_status["shadowscan"] == "complete"
    assert (claim.source_unmapped_count, claim.surfaces_excluded) == (0, [])
    validated = runner.invoke(main, validation(root, output))
    assert validated.exit_code == 0, validated.output


def test_the_cyclonedx_report_of_the_same_tree_projects_the_same_findings():
    findings = ShadowScanImporter().parse_report(REPORT.read_bytes()).components
    imported = ShadowScanImporter().parse_report(CYCLONEDX.read_bytes())
    by_ref = {c.bom_ref: c for c in imported.components}
    for found in findings:
        twin = by_ref[found.bom_ref]
        assert (twin.component_type, twin.name) == (found.component_type, found.name)
        for name in ("shadowscan:kind", "shadowscan:resource-type", "shadowscan:surface"):
            assert twin.properties.get(name) == found.properties.get(name)
        assert twin.risks == found.risks
    assert len(imported.components) == 6 and imported.unmapped_kinds == {"no kind": 4}
    assert sorted(
        (by_ref[e.source_ref].name, by_ref[e.target_ref].component_type.value)
        for e in imported.dependencies
    ) == [
        ("ShadowScan framework-usage af2459bd4b84", "model"),
        ("ShadowScan mcp-server 7551b9e779c2", "mcp-server"),
    ]
    paths = {text for text in strings(json.loads(CYCLONEDX.read_bytes())) if text.startswith("/")}
    assert all(path.startswith("/work/agent-framework-demo") for path in paths) and paths


@pytest.mark.parametrize(
    ("kind", "resource_type", "label"),
    [
        pytest.param("infra", None, "infra", id="a-kind-that-is-a-gap"),
        pytest.param(
            "framework-usage",
            "lockfile-inventory",
            "framework-usage (unprojected form)",
            id="a-projected-kind-in-another-form",
        ),
    ],
)
def test_one_unmapped_finding_still_closes_the_merged_gate_and_is_named(
    runner, tmp_path, kind, resource_type, label
):
    report = with_findings(REPORT.read_bytes(), kind, resource_type=resource_type)
    root = project(tmp_path, report)
    output = tmp_path / "bom.json"
    result = runner.invoke(main, ["scan", str(root), "--no-project-policy", "-o", str(output)])
    assert result.exit_code == 1, result.output
    assert f"excluded: ShadowScan report contains unmapped entries: {label}" in result.output
    bom = AIBOM.load(output)
    claim = bom.metadata.completeness
    assert claim.scanner_status["shadowscan"] == "partial"
    assert (claim.source_unmapped_count, claim.source_unmapped_indexes) == (1, [4])
    assert claim.surfaces_excluded == [f"ShadowScan report contains unmapped entries: {label}"]
    assert (
        f"1 source entries were not mapped into BOM components ({label}: 1)"
        in claim.source_projection_limitations
    )
    assert len([c for c in bom.components if c.bom_ref.startswith("shadowscan:")]) == 4
    assert not RiskScorer().passes_gate(bom)[0]
    assert runner.invoke(main, validation(root, output)).exit_code == 1
    baseline = tmp_path / "baseline.json"
    assert runner.invoke(main, ["baseline", str(root), "-o", str(baseline)]).exit_code == 1
    assert not baseline.exists()


@pytest.mark.parametrize(
    ("kind", "edit"),
    [
        pytest.param("agent-config", {"ide_type": "claude-code"}, id="ide-type"),
        pytest.param("agent-config", {"permission_mode": "bypassPermissions"}, id="permission"),
        pytest.param("agent-config", {"config_files": ["CLAUDE.md"]}, id="config-files"),
        pytest.param("framework-usage", {"framework": "langgraph"}, id="framework"),
        pytest.param("framework-usage", {"autonomy_level": "L3-autonomous"}, id="autonomy"),
    ],
)
def test_detail_added_to_an_imported_component_fails_reconciliation(runner, tmp_path, kind, edit):
    root = project(tmp_path, REPORT.read_bytes())
    target = tmp_path / "bom.json"
    scanned = runner.invoke(main, ["scan", str(root), "--no-project-policy", "-o", str(target)])
    assert scanned.exit_code == 0, scanned.output
    original = runner.invoke(main, validation(root, target))
    assert original.exit_code == 0, original.output
    document = json.loads(target.read_bytes())
    (component,) = (
        c for c in document["components"] if c["properties"].get("shadowscan:kind") == kind
    )
    component.update(edit)
    target.write_text(json.dumps(document), encoding="utf-8")
    altered = runner.invoke(main, validation(root, target))
    assert altered.exit_code == 1, altered.output
    assert (
        f"Component differs from the discovery report projection: {component['bom_ref']}"
        in altered.output
    )


def test_portable_exports_keep_both_types_and_finding_exports_omit_the_ratings():
    bom = ShadowScanImporter().parse_report(REPORT.read_bytes()).to_native_bom()
    imported = {c.bom_ref: c for c in bom.components}
    assert [c.component_type.value for c in bom.components] == [
        "mcp-server",
        "ide-agent",
        "agent",
        "agent",
    ]
    for generator in (CycloneDXGenerator(), SPDXGenerator()):
        recovered = generator.recover(generator.generate(bom))
        assert {c.bom_ref: c for c in recovered.components} == imported
        assert recovered.metadata.completeness.scanner_status["shadowscan"] == "partial"
    ratings = sum(len(c.risks) for c in bom.components)
    assert ratings == 4
    sarif = SARIFGenerator().generate(bom)["runs"][0]
    assert sarif["results"] == []
    assert sarif["properties"]["nexus-symbiote:omittedImportedFindings"] == ratings
    vex = VEXGenerator().generate(bom)
    assert vex["vulnerabilities"] == []
    assert vex["metadata"]["properties"] == [
        {"name": "nexus-symbiote:omittedImportedFindings", "value": str(ratings)}
    ]


def test_a_critical_agent_config_rating_closes_the_risk_gate_unless_its_category_is_ignored(
    runner, tmp_path
):
    rated = finding("agent-config", "coding-agent-config", risk={"level": "critical"})
    root = project(tmp_path, json.dumps(native(rated)).encode())
    target = tmp_path / "bom.json"
    result = runner.invoke(main, ["scan", str(root), "--no-project-policy", "-o", str(target)])
    assert result.exit_code == 1, result.output
    bom = AIBOM.load(target)
    assert bom.metadata.completeness.scanner_status["shadowscan"] == "complete"
    passed, risk = RiskScorer().passes_gate(bom)
    assert not passed and risk.gate_reasons == ["finding at or above critical"]
    (critical,) = (f for f in risk.findings if f.severity == RiskSeverity.CRITICAL)
    assert critical.category == "shadowscan-heuristic"
    assert bom.get_component(critical.component_ref).component_type == ComponentType.IDE_AGENT
    assert RiskScorer(ignore_categories=["shadowscan-heuristic"]).passes_gate(bom)[0]
    (root / ".nexus-symbiote.yaml").write_text(
        'version: "1.0"\nrisk:\n  ignore_categories: ["shadowscan-heuristic"]\n', encoding="utf-8"
    )
    ignored = runner.invoke(
        main,
        ["scan", str(root), "--accept-project-policy", "-o", str(tmp_path / "ignored.json")],
    )
    assert ignored.exit_code == 0, ignored.output


def test_the_documented_kind_table_is_what_the_importer_does():
    text = DOCS.read_text(encoding="utf-8")
    assert f"`{PROJECTION_PROFILE}`" in text
    assert f'"{LIMITATION}"' in text.replace("\n", " ")
    assert f'"{GAP}"' in text.replace("\n", " ")
    real = ShadowScanImporter().parse_report(REPORT.read_bytes())
    (label,) = (
        c.name for c in real.components if c.properties["shadowscan:kind"] == "framework-usage"
    )
    assert f'"{label}"' in text.replace("\n", " ")
    section = text.split("## What each ShadowScan kind becomes", 1)[1].split("\n### ", 1)[0]
    documented = {
        kind: becomes.strip()
        for kinds, becomes in re.findall(r"^\| (`[^|]+) \| ([^|]+) \|", section, re.M)
        for kind in re.findall(r"`([a-z-]+)`", kinds)
    }
    assert set(documented) == shadowscan._SOURCE_KINDS and len(documented) == 18
    for kind, becomes in documented.items():
        result = parse(native(finding(kind, BOUND.get(kind))))
        if becomes == "Gap":
            assert result.components == [] and result.unmapped_kinds == {kind: 1}
        else:
            (component,) = result.components
            assert becomes.startswith(f"`{component.component_type.value}`")
    for kind, resource_type in BOUND.items():
        assert f"`{kind}` | `{documented[kind].strip('`')}` | Resource type `{resource_type}`" in (
            section
        )


def test_the_documented_tree_is_the_one_the_report_cites():
    tree = documented_tree()
    report = json.loads(REPORT.read_bytes())
    cited = set()
    for item in (item for found in report["findings"] for item in found["evidence"]):
        path, line = re.fullmatch(r"(.+?)(?::([0-9]+))?", item["location"]).groups()
        cited.add(path)
        if line and item["signal"].startswith(("import:", "code:", "model:")):
            assert tree[path].split("\n")[int(line) - 1].strip() == item["snippet"]
    assert cited == set(tree) and len(tree) == 6
    assert {text for text in strings(report) if text.startswith("/")} == {
        "/work/agent-framework-demo",
        "/work/agent-framework-demo/.mcp.json",
        "/work/agent-framework-demo/services/summarizer",
    }
    assert report["started_at"] in README.read_text(encoding="utf-8")


def test_a_merged_scan_of_the_documented_tree_passes_its_gates(runner, tmp_path):
    root = tmp_path / "agent-framework-demo"
    for name, content in documented_tree().items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(content, encoding="utf-8")
    shutil.copyfile(REPORT, root / "shadowscan.json")
    target = tmp_path / "bom.json"
    result = runner.invoke(main, ["scan", str(root), "--no-project-policy", "-o", str(target)])
    assert result.exit_code == 0, result.output
    bom = AIBOM.load(target)
    claim = bom.metadata.completeness
    assert set(claim.scanner_status.values()) == {"complete"}
    assert (claim.source_unmapped_count, claim.surfaces_excluded) == (0, [])
    imported = {c.name: c for c in bom.components if c.bom_ref.startswith("shadowscan:")}
    assert Counter(c.component_type.value for c in imported.values()) == {
        "agent": 2,
        "ide-agent": 1,
        "mcp-server": 1,
        "model": 1,
    }
    cited = imported["gpt-4o-mini"].claims["cited_evidence"]
    assert cited.evidence_refs == ["services/summarizer/summarize.py:7"]
    local = [c for c in bom.components if c.component_type == ComponentType.IDE_AGENT]
    assert sorted(c.ide_type or "" for c in local) == ["", "claude-code"]
    validated = runner.invoke(main, validation(root, target))
    assert validated.exit_code == 0, validated.output
