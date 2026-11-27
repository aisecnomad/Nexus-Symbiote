"""SARIF stays usable in GitHub code scanning: located, severity-stable, plain and honest."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote import modes
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.canonical import content_digest
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    CompletenessClaim,
    MCPServerComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.generators.sarif import SARIFGenerator, plain_text
from nexus_symbiote.generators.validation import require_valid, validate_sarif
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo-agent"
HIGH, MEDIUM, INFO = RiskSeverity.HIGH, RiskSeverity.MEDIUM, RiskSeverity.INFO


def _risk(severity: RiskSeverity, category: str = "version_pinning", detail: str = "x") -> Any:
    return RiskAssessment(severity=severity, category=category, detail=detail)


def _results(document: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = document["runs"][0]["results"]
    return results


def _location(result: dict[str, Any]) -> tuple[str, str, str]:
    artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
    return artifact["uri"], artifact["uriBaseId"], result["properties"]["location_source"]


def _by_component(document: dict[str, Any]) -> dict[str, tuple[str, str, str]]:
    return {r["properties"]["component_ref"]: _location(r) for r in _results(document)}


def _claim(**changes: Any) -> CompletenessClaim:
    names = sorted(BUILTIN_SCANNER_NAMES)
    fields: dict[str, Any] = {
        "scope": "repository",
        "collectors_requested": names,
        "collectors_completed": names,
        "scanner_status": dict.fromkeys(names, "complete"),
    }
    return CompletenessClaim(**{**fields, **changes})


def test_every_result_is_located_relative_to_the_source_root(tmp_path):
    repo = tmp_path / "repo"
    project = repo / "services" / "agent"
    project.mkdir(parents=True)
    bom = AIBOM(
        components=[
            MCPServerComponent(
                bom_ref="server", name="s", source_path=".mcp.json", risks=[_risk(HIGH)]
            ),
            ToolComponent(
                bom_ref="tool",
                name="t",
                mcp_server_ref="server",
                risks=[_risk(HIGH, "capability_scope")],
            ),
            RAGSourceComponent(
                bom_ref="rag:import-chroma", name="chroma", risks=[_risk(INFO, "rag_discovery")]
            ),
            RegistryEntryComponent(
                bom_ref="pinned",
                name="openai",
                registry_type="pypi",
                source_path=str(project / "requirements with space.txt"),
                risks=[_risk(MEDIUM)],
            ),
        ]
    )
    document = SARIFGenerator(repo, scan_root=project).generate(bom)
    assert validate_sarif(document) == []
    assert _by_component(document) == {
        "server": ("services/agent/.mcp.json", "%SRCROOT%", "component"),
        "tool": ("services/agent/.mcp.json", "%SRCROOT%", "server"),
        "rag:import-chroma": ("services/agent/.nexus-symbiote.yaml", "%SRCROOT%", "anchor"),
        "pinned": ("services/agent/requirements%20with%20space.txt", "%SRCROOT%", "component"),
    }
    anchored = SARIFGenerator(repo, scan_root=project, anchor="aibom.json").generate(bom)
    assert _by_component(anchored)["rag:import-chroma"][0] == "services/agent/aibom.json"


def test_sarif_uses_the_collected_declaration_line_for_python_and_typescript(tmp_path):
    from nexus_symbiote.scanners.mcp import MCPScanner

    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "srv = FastMCP('catalog')\n"
        "@srv.tool()\ndef lookup():\n    return 'ok'\n"
    )
    (tmp_path / "index.ts").write_text(
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'const srv = new McpServer({name:"catalog",version:"1.0.0"});\n'
        '\nsrv.registerTool("lookup", {}, async () => ({content: []}));\n'
    )
    tools = [c for c in MCPScanner().scan(tmp_path).components if isinstance(c, ToolComponent)]
    assert {t.source_path for t in tools} == {"server.py", "index.ts"}
    for tool in tools:
        tool.risks = [_risk(HIGH)]
    output = SARIFGenerator(tmp_path).generate(AIBOM(components=tools))
    assert validate_sarif(output) == []
    observed = {}
    for row in _results(output):
        location = row["locations"][0]["physicalLocation"]
        observed[location["artifactLocation"]["uri"]] = location["region"]["startLine"]
    assert observed == {"server.py": 3, "index.ts": 4}


@pytest.mark.parametrize("line", [None, True, "12", 0, -1, 1.5, 2**31])
def test_sarif_invalid_lines_keep_the_same_file_location_and_fingerprint(tmp_path, line):
    tool = ToolComponent(
        bom_ref="t",
        name="lookup",
        source_path="src/agent.py",
        risks=[_risk(HIGH)],
        properties={"collection_mode": "static-source-declaration", "declaration_line": 12},
    )
    generator = SARIFGenerator(tmp_path)

    def finding():
        return _results(generator.generate(AIBOM(components=[tool])))[0]

    original = finding()
    tool.properties["declaration_line"] = line
    result = finding()
    assert result["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "src/agent.py", "uriBaseId": "%SRCROOT%"}
    }
    assert result["partialFingerprints"] == original["partialFingerprints"]


def test_sarif_never_transplants_a_line_to_a_server_or_anchor_or_config_file(tmp_path):
    props = {"collection_mode": "static-source-declaration", "declaration_line": 14}
    server = MCPServerComponent(bom_ref="server", name="s", source_path="mcp.json")
    tools = [
        ToolComponent(bom_ref="via-server", name="t", mcp_server_ref="server", properties=props),
        ToolComponent(
            bom_ref="via-anchor", name="t", source_path="../external.py", properties=props
        ),
        ToolComponent(
            bom_ref="config",
            name="t",
            source_path="mcp.json",
            properties={**props, "collection_mode": "static-config"},
        ),
    ]
    for tool in tools:
        tool.risks = [_risk(HIGH)]
    results = _results(SARIFGenerator(tmp_path).generate(AIBOM(components=[server, *tools])))
    assert len(results) == 3
    assert all("region" not in r["locations"][0]["physicalLocation"] for r in results)


def test_a_scan_root_outside_the_source_root_becomes_the_source_root(tmp_path):
    project = tmp_path / "checkout"
    project.mkdir()
    bom = AIBOM(
        components=[
            MCPServerComponent(
                bom_ref="relative", name="r", source_path=".mcp.json", risks=[_risk(HIGH)]
            ),
            MCPServerComponent(
                bom_ref="absolute",
                name="a",
                source_path=str(project / "nested" / ".mcp.json"),
                risks=[_risk(HIGH)],
            ),
        ]
    )
    document = SARIFGenerator(tmp_path / "elsewhere", scan_root=project).generate(bom)
    assert _by_component(document) == {
        "relative": (".mcp.json", "%SRCROOT%", "component"),
        "absolute": ("nested/.mcp.json", "%SRCROOT%", "component"),
    }


@pytest.mark.parametrize(
    "source", ["../outside/.mcp.json", "/elsewhere/secret/.mcp.json", "https://host/x", "."]
)
def test_unlocatable_sources_are_anchored_and_never_disclosed(tmp_path, source):
    bom = AIBOM(
        components=[
            MCPServerComponent(bom_ref="s", name="s", source_path=source, risks=[_risk(HIGH)])
        ]
    )
    document = SARIFGenerator(tmp_path).generate(bom)
    assert _by_component(document) == {"s": (".nexus-symbiote.yaml", "%SRCROOT%", "anchor")}
    assert "secret" not in json.dumps(document) and "outside" not in json.dumps(document)


@pytest.mark.parametrize(
    "anchor", ["../outside.yaml", "/elsewhere/policy.yaml", "https://host/x", ".", ""]
)
def test_an_anchor_that_cannot_be_located_is_rejected(tmp_path, anchor):
    with pytest.raises(ValueError, match="anchor"):
        SARIFGenerator(tmp_path, anchor=anchor)


def test_notifications_never_name_where_the_scan_root_lies(tmp_path):
    project = tmp_path / "checkout"
    project.mkdir()
    bom = AIBOM()
    bom.metadata.completeness = _claim(
        scan_failures=[
            f"{project / '.mcp.json'}: invalid JSON or duplicate keys",
            f"{project}: unreadable",
            f"{tmp_path / 'checkout-old' / 'x.json'}: sibling",
        ],
        surfaces_excluded=[f"{project / 'models' / 'big.bin'}: model size limit exceeded"],
    )
    document = SARIFGenerator(tmp_path, scan_root=project).generate(bom)
    texts = {
        n["message"]["text"]
        for n in document["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    }
    assert "Collection failure: .mcp.json: invalid JSON or duplicate keys" in texts
    assert "Collection failure: .: unreadable" in texts
    assert "Coverage gap: models/big.bin: model size limit exceeded" in texts
    # Only the scan root is removed: another directory's path is left as written.
    assert [text for text in texts if str(tmp_path) in text] == [
        f"Collection failure: {tmp_path / 'checkout-old' / 'x.json'}: sibling"
    ]


def test_rules_are_keyed_by_category_and_severity_with_stable_metadata(tmp_path):
    server = MCPServerComponent(
        bom_ref="server",
        name="s",
        risks=[
            RiskAssessment(
                severity=HIGH,
                category="version_pinning",
                detail="MCP server 's' uses an unpinned package reference.",
                recommendation="Pin the server package.",
            )
        ],
    )
    package = RegistryEntryComponent(
        bom_ref="package",
        name="sdk",
        registry_type="npm",
        risks=[_risk(MEDIUM, detail="npm package 'sdk' has a nonexact declared reference: ^1")],
    )
    alone = SARIFGenerator(tmp_path).generate(AIBOM(components=[package]))
    mixed = SARIFGenerator(tmp_path).generate(AIBOM(components=[server, package]))
    rules = {rule["id"]: rule for rule in mixed["runs"][0]["tool"]["driver"]["rules"]}
    assert set(rules) == {
        "nexus_symbiote/version_pinning/high",
        "nexus_symbiote/version_pinning/medium",
    }
    # Another finding in the run never changes a rule's severity.
    assert alone["runs"][0]["tool"]["driver"]["rules"] == [
        rules["nexus_symbiote/version_pinning/medium"]
    ]
    assert rules["nexus_symbiote/version_pinning/high"]["properties"]["security-severity"] == "8.0"
    medium = rules["nexus_symbiote/version_pinning/medium"]
    assert medium["properties"]["security-severity"] == "5.0"
    assert medium["defaultConfiguration"] == {"level": "warning"}
    assert {"security", "external/cwe/cwe-829"} <= set(medium["properties"]["tags"])
    assert any("owasp" in tag for tag in medium["properties"]["tags"])
    # Rule text is application-owned, never a finding's recommendation.
    assert "Pin the server package." not in json.dumps(rules)
    for result in _results(mixed):
        rule = mixed["runs"][0]["tool"]["driver"]["rules"][result["ruleIndex"]]
        assert rule["id"] == result["ruleId"]
        assert result["level"] == rule["defaultConfiguration"]["level"]


def test_category_specific_cwe_tags_follow_the_finding_kind(tmp_path):
    bom = AIBOM(
        components=[
            MCPServerComponent(
                bom_ref="remote",
                name="r",
                risks=[_risk(HIGH, "transport_security"), _risk(MEDIUM, "transport_security")],
            )
        ]
    )
    rules = {
        rule["id"]: set(rule["properties"]["tags"])
        for rule in SARIFGenerator(tmp_path).generate(bom)["runs"][0]["tool"]["driver"]["rules"]
    }
    assert "external/cwe/cwe-319" in rules["nexus_symbiote/transport_security/high"]
    assert not any("cwe" in tag for tag in rules["nexus_symbiote/transport_security/medium"])


def test_fingerprints_are_stable_distinct_and_match_0_1_0(tmp_path):
    servers = [
        MCPServerComponent(
            bom_ref=f"server:{index}",
            name=f"s{index}",
            source_path=".mcp.json",
            risks=[
                _risk(HIGH, detail=f"MCP server 's{index}' uses an unpinned package reference.")
            ],
        )
        for index in range(3)
    ]

    def run(components: list[Any]) -> dict[str, Any]:
        bom = AIBOM(components=deepcopy(components))
        bom.metadata.timestamp = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
        return SARIFGenerator(tmp_path).generate(bom)

    first = run(servers)
    assert first == run(servers)
    hashes = [r["partialFingerprints"]["primaryLocationLineHash"] for r in _results(first)]
    assert len(set(hashes)) == 3
    result = _results(first)[0]
    assert result["partialFingerprints"]["nexus_symbiote/v1"] == content_digest(
        {
            "rule": "nexus_symbiote/version_pinning",
            "component": "server:0",
            "detail": "MCP server 's0' uses an unpinned package reference.",
        }
    ).removeprefix("sha256:")
    servers[0].risks[0].severity = MEDIUM
    changed = run(servers)
    moved = next(r for r in _results(changed) if r["properties"]["component_ref"] == "server:0")
    assert moved["partialFingerprints"] == result["partialFingerprints"]


@pytest.mark.parametrize(
    "name",
    [
        "[Reviewed and approved - details](https://evil.example)",
        "see //evil.example/path or www.evil.example",
        "\x1b[31mred\x1b[0m\u202eevil\u200b",
        "x" * 5000,
        "_https://evil.example/x and _www.evil.example",
        "\u00e9https://evil.example and WwW.evil.example",
        "a" * 40 + "://evil.example",
    ],
)
def test_messages_are_plain_text_that_cannot_render_links(tmp_path, name):
    detail = f"MCP server '{name}' uses stdio transport (local process)."
    bom = AIBOM(
        components=[
            MCPServerComponent(
                bom_ref="s",
                name=name,
                risks=[
                    RiskAssessment(
                        severity=MEDIUM,
                        category="transport_security",
                        detail=detail,
                        recommendation=f"Review {name}",
                    )
                ],
            )
        ]
    )
    document = SARIFGenerator(tmp_path).generate(bom)
    (result,) = _results(document)
    for text in (result["message"]["text"], result["properties"]["recommendation"]):
        assert "](" not in text.replace("\\]", "")
        assert "://" not in text and "www." not in text.lower()
        assert not any(char in text for char in "\x1b\u202e\u200b\n")
        assert len(text) <= 2000
    assert plain_text("[a](b)") == "\\[a\\](b)"
    assert plain_text("C:\\path") == "C:\\\\path"
    assert plain_text("_https://evil.example") == "_https\\[:\\]//evil.example"
    # The cut cannot leave a "www." that defanging has not seen.
    assert "www." not in plain_text("x" * 994 + "www" + "y" * 10)


def test_collection_failures_and_gaps_reach_the_invocation(tmp_path):
    def invocation(claim: CompletenessClaim | None) -> dict[str, Any]:
        bom = AIBOM()
        bom.metadata.completeness = claim
        document = SARIFGenerator(tmp_path).generate(bom)
        assert validate_sarif(document) == []
        result: dict[str, Any] = document["runs"][0]["invocations"][0]
        return result

    failed = invocation(
        _claim(
            scan_failures=[".mcp.json: invalid JSON or duplicate keys"],
            surfaces_excluded=["tools.py: unresolved Python MCP tool name"],
            scanner_status={**dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete"), "mcp": "failed"},
        )
    )
    assert failed["executionSuccessful"] is False
    levels = [(n["level"], n["message"]["text"]) for n in failed["toolExecutionNotifications"]]
    assert ("error", "Collection failure: .mcp.json: invalid JSON or duplicate keys") in levels
    assert ("error", "Collector mcp failed.") in levels
    assert ("warning", "Coverage gap: tools.py: unresolved Python MCP tool name") in levels

    complete = invocation(_claim())
    assert complete["executionSuccessful"] is True
    assert [n["level"] for n in complete["toolExecutionNotifications"]] == ["note"]

    scoped = invocation(_claim(collectors_requested=["mcp"], collectors_completed=["mcp"]))
    assert scoped["executionSuccessful"] is True
    assert any(
        n["message"]["text"].startswith("Collector model was not run")
        for n in scoped["toolExecutionNotifications"]
    )
    unknown = invocation(None)
    assert unknown["executionSuccessful"] is True
    many = invocation(_claim(scan_failures=[f"failure {index}" for index in range(500)]))
    assert len(many["toolExecutionNotifications"]) == 100
    assert many["executionSuccessful"] is False


@pytest.mark.parametrize(
    "change",
    [
        "no-location",
        "absolute-uri",
        "escaping-uri",
        "level",
        "rule-index",
        "fingerprint",
        "untagged-rule",
        "severity",
        "message",
        "execution",
    ],
)
def test_structural_validation_rejects_what_code_scanning_cannot_use(tmp_path, change):
    bom = AIBOM(
        components=[
            MCPServerComponent(bom_ref="s", name="s", source_path=".mcp.json", risks=[_risk(HIGH)])
        ]
    )
    document = SARIFGenerator(tmp_path).generate(bom)
    run = document["runs"][0]
    result, rule = run["results"][0], run["tool"]["driver"]["rules"][0]
    artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
    if change == "no-location":
        del result["locations"]
    elif change == "absolute-uri":
        artifact["uri"] = "/etc/passwd"
    elif change == "escaping-uri":
        artifact["uri"] = "../outside"
    elif change == "level":
        result["level"] = "fatal"
    elif change == "rule-index":
        result["ruleIndex"] = 4
    elif change == "fingerprint":
        del result["partialFingerprints"]["primaryLocationLineHash"]
    elif change == "untagged-rule":
        rule["properties"]["tags"] = []
    elif change == "severity":
        rule["properties"]["security-severity"] = "11"
    elif change == "message":
        result["message"] = {"text": ""}
    else:
        del run["invocations"][0]["executionSuccessful"]
    assert validate_sarif(document)
    with pytest.raises(ValueError):
        require_valid(document, "sarif")


def test_an_empty_inventory_is_valid_sarif(tmp_path):
    document = SARIFGenerator(tmp_path).generate(AIBOM())
    assert validate_sarif(document) == []
    assert _results(document) == []


@pytest.fixture
def checkout(tmp_path):
    if not DEMO.is_dir():
        pytest.skip("the demo project ships in the repository, not in the wheel")
    target = tmp_path / "repo" / "agent"
    shutil.copytree(DEMO, target)
    (tmp_path / "elsewhere").mkdir()
    return target


@pytest.mark.parametrize("cwd,prefix", [("elsewhere", ""), ("repo", "agent/")])
def test_cli_scan_locates_every_result_from_any_working_directory(
    checkout, monkeypatch, cwd, prefix
):
    base = checkout.parents[1]
    monkeypatch.chdir(base / cwd)
    output = base / "out.sarif"
    result = CliRunner().invoke(
        main,
        ["scan", str(checkout), "-f", "sarif", "-o", str(output), "--report-only"],
        env={modes.ENV_VAR: None},
    )
    assert result.exit_code == 0, result.output
    document = json.loads(output.read_text(encoding="utf-8"))
    assert validate_sarif(document) == []
    assert document["runs"][0]["invocations"][0]["executionSuccessful"] is True
    uris = {_location(r)[0] for r in _results(document)}
    assert uris and all(uri.startswith(prefix) for uri in uris)
    assert prefix + ".mcp.json" in uris
    assert str(base) not in output.read_text(encoding="utf-8")


def _action_runner() -> Any:
    spec = importlib.util.spec_from_file_location(
        "sarif_action_runner", Path(__file__).parents[1] / "scripts" / "run_action.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_action_sarif_is_relative_to_the_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    project = workspace / "services" / "agent"
    project.mkdir(parents=True)
    bom = AIBOM(
        components=[
            MCPServerComponent(bom_ref="s", name="s", source_path=".mcp.json", risks=[_risk(HIGH)])
        ]
    )
    native = tmp_path / "native.json"
    native.write_text(bom.to_json(), encoding="utf-8")
    output = workspace / "aibom.sarif"
    _action_runner()._export(native, output, "sarif", root=workspace, scan_root=project)
    document = json.loads(output.read_text(encoding="utf-8"))
    assert _by_component(document) == {"s": ("services/agent/.mcp.json", "%SRCROOT%", "component")}


def test_imported_discovery_findings_are_omitted_and_counted(tmp_path):
    bom = AIBOM(
        components=[
            MCPServerComponent(
                bom_ref="local", name="l", source_path=".mcp.json", risks=[_risk(HIGH)]
            ),
            MCPServerComponent(
                bom_ref="shadowscan:server",
                name="imported",
                risks=[_risk(HIGH, "shadowscan-heuristic"), _risk(INFO, "rag_discovery")],
            ),
        ]
    )
    run = SARIFGenerator(tmp_path).generate(bom)["runs"][0]
    assert [r["properties"]["component_ref"] for r in run["results"]] == ["local"]
    assert run["properties"]["nexus-symbiote:omittedImportedFindings"] == 2
