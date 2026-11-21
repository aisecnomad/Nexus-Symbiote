"""Security regressions for reconciled supply-chain reports and CLI commands."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.advisories import MAX_RESPONSE_BYTES, fetch_advisories, package_identity
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    RiskAssessment,
)
from nexus_symbiote.generators.validation import validate_cyclonedx
from nexus_symbiote.generators.vex import VEXGenerator
from nexus_symbiote.scanners.live_mcp import HTTPReply
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner, safetensors_fingerprint
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.validators.integrity import IntegrityValidator


def _tensor(path: Path, data: bytes = b"0000", offsets: object = None) -> None:
    header = json.dumps(
        {
            "weight": {
                "dtype": "F32",
                "shape": [1],
                "data_offsets": [0, 4] if offsets is None else offsets,
            }
        }
    ).encode()
    path.write_bytes(struct.pack("<Q", len(header)) + header + data)


def test_tensor_metadata_is_confined_and_does_not_claim_weight_byte_integrity(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    a, b = project / "a.safetensors", project / "b.safetensors"
    _tensor(a)
    _tensor(b, b"1111")
    assert safetensors_fingerprint(a, root=project) == safetensors_fingerprint(b, root=project)
    outside = tmp_path / "outside.safetensors"
    _tensor(outside)
    with pytest.raises(OSError, match="confined stream unavailable"):
        safetensors_fingerprint(outside, root=project)
    (project / "link.safetensors").symlink_to(outside)
    with pytest.raises((OSError, ValueError)):
        safetensors_fingerprint(project / "link.safetensors", root=project)


@pytest.mark.parametrize("offsets", [[0], {}, "oops", [0, 5], [False, 4]])
def test_malformed_tensor_metadata_is_refused(tmp_path, offsets):
    path = tmp_path / "bad.safetensors"
    _tensor(path, offsets=offsets)
    with pytest.raises(ValueError):
        safetensors_fingerprint(path, root=tmp_path)


def test_collected_tensor_metadata_is_revalidated_and_missing_input_fails(tmp_path):
    path = tmp_path / "weights.safetensors"
    _tensor(path)
    comp = next(
        c for c in ModelScanner().scan(tmp_path).components if isinstance(c, ModelComponent)
    )
    assert comp.tensor_inventory_hash
    assert set(comp.hashes) == {"sha256"}
    bom = AIBOM(components=[comp])
    assert not any(
        i.category == "tensor_metadata_unverified"
        for i in IntegrityValidator().validate(bom, tmp_path).issues
    )
    path.unlink()
    assert any(
        i.category == "tensor_metadata_unverified"
        for i in IntegrityValidator().validate(bom, tmp_path).issues
    )


def test_unchanged_tensor_metadata_cannot_corroborate_replaced_weight_bytes(tmp_path):
    path = tmp_path / "weights.safetensors"
    _tensor(path, b"0000")
    component = ModelScanner().scan(tmp_path).components[0]
    before = safetensors_fingerprint(path, root=tmp_path)
    _tensor(path, b"1111")
    assert safetensors_fingerprint(path, root=tmp_path) == before
    with pytest.raises(ValueError, match="different artifact bytes"):
        safetensors_fingerprint(path, root=tmp_path, expected_digest=component.hashes["sha256"])
    report = IntegrityValidator(require_model_signatures=False).validate(
        AIBOM(components=[component]), tmp_path
    )
    assert not report.is_valid
    assert any(issue.category == "tensor_metadata_unverified" for issue in report.issues)


def test_vex_is_schema_valid_with_unique_ids_and_truthful_triage():
    risk = RiskAssessment(
        severity=RiskSeverity.HIGH, category="signing_status", detail="Unverified signer"
    )
    bom = AIBOM(
        components=[
            ModelComponent(bom_ref="model:a", name="a", risks=[risk]),
            ModelComponent(bom_ref="model:b", name="b", risks=[risk]),
        ]
    )
    doc = VEXGenerator().generate(bom)
    assert not validate_cyclonedx(doc)
    refs = [v["bom-ref"] for v in doc["vulnerabilities"]]
    assert len(refs) == len(set(refs)) == 2
    assert all(v["analysis"]["state"] == "in_triage" for v in doc["vulnerabilities"])
    assert not validate_cyclonedx(VEXGenerator().generate(AIBOM()))
    assert (
        VEXGenerator().generate_with_report(bom).loss_report["extensionRoundTripComplete"] is False
    )


class _Transport:
    def __init__(self, body: bytes = b'{"results":[{}]}', status: int = 200):
        self.body, self.status, self.calls = body, status, []

    def request(self, endpoint, body, headers, *, timeout, max_bytes):
        self.calls.append((endpoint, json.loads(body), timeout, max_bytes))
        return HTTPReply(self.status, {"content-type": "application/json"}, self.body)


def _package(**kw):
    return RegistryEntryComponent(
        bom_ref="registry:pypi/requests",
        name="requests",
        version="==2.19.0",
        registry_type="pypi",
        package_url="pkg:pypi/requests@2.19.0",
        **kw,
    )


def test_osv_exact_identity_bound_transport_and_timeout():
    transport = _Transport(b'{"results":[{"vulns":[{"id":"GHSA-test"}]}]}')
    report = fetch_advisories(AIBOM(components=[_package()]), timeout=0.25, transport=transport)
    assert report.components_checked == 1 and not report.errors
    assert transport.calls == [
        (
            "https://api.osv.dev/v1/querybatch",
            {
                "queries": [
                    {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"}
                ]
            },
            0.25,
            MAX_RESPONSE_BYTES,
        )
    ]
    assert report.advisories[0]["advisory_id"] == "GHSA-test"
    assert report.queries == [
        {
            "component_ref": "registry:pypi/requests",
            "ecosystem": "PyPI",
            "name": "requests",
            "version": "2.19.0",
        }
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        {"package_url": None},
        {"version": ">=2.0"},
        {"package_url": "pkg:pypi/other@2.19.0"},
        {"package_url": "pkg:npm/requests@2.19.0"},
        {"package_url": "pkg:pypi/requests@2.19.0?repository_url=evil"},
    ],
)
def test_osv_identity_mismatch_prevents_network(mutation):
    comp = _package().model_copy(update=mutation)
    transport = _Transport()
    report = fetch_advisories(AIBOM(components=[comp]), transport=transport)
    assert report.errors and not transport.calls


@pytest.mark.parametrize(
    "body,status",
    [
        (b'{"results":[{}]}', 302),
        (b"[]", 200),
        (b'{"results":[{"vulns":{}}]}', 200),
        (b'{"results":[{"vulns":[],"next_page_token":"more"}]}', 200),
        (b'{"results":[{}],"error":"x"}', 200),
        (b'{"results":[{}' + b" " * MAX_RESPONSE_BYTES + b"]}", 200),
    ],
)
def test_osv_incomplete_or_malformed_results_fail(body, status):
    assert fetch_advisories(
        AIBOM(components=[_package()]), transport=_Transport(body, status)
    ).errors


def test_osv_does_not_guess_huggingface_or_mcp_ecosystems():
    transport = _Transport()
    components = [
        RegistryEntryComponent(bom_ref="hf:a", name="requests", registry_type="huggingface"),
        RegistryEntryComponent(bom_ref="mcp:a", name="requests", registry_type="mcp-registry"),
    ]
    report = fetch_advisories(AIBOM(components=components), transport=transport)
    assert report.components_skipped == 2 and not transport.calls


def test_registry_scanner_emits_only_exact_declared_package_urls(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai==1.2.3\nlangchain>=1.0\n")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "1.2.3"}})
    )
    components = [
        c
        for c in RegistryScanner().scan(tmp_path).components
        if isinstance(c, RegistryEntryComponent)
    ]
    assert sum(c.package_url is not None for c in components) == 2
    for comp in components:
        if comp.package_url:
            package_identity(comp)


def test_verify_live_never_launches_project_command(tmp_path):
    marker = tmp_path / "marker"
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"bad": {"command": "touch", "args": [str(marker)]}}})
    )
    source = tmp_path / "bom.json"
    source.write_text(AIBOM().to_json())
    result = CliRunner().invoke(
        main, ["--live", "verify-live", str(source), "--project", str(tmp_path), "--record"]
    )
    assert result.exit_code != 0 and "--launch-policy" in result.output
    assert not marker.exists()


def test_verify_live_refuses_host_credentials(tmp_path, monkeypatch):
    source = tmp_path / "bom.json"
    project = tmp_path / "project"
    project.mkdir()
    source.write_text(AIBOM().to_json())
    policy = project / "launch.json"
    policy.write_text("{}")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "not-a-real-secret")
    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "k" * 32)
    args = [
        "--live",
        "verify-live",
        str(source),
        "--project",
        str(project),
        "--launch-policy",
        str(policy),
    ]
    refused = CliRunner().invoke(main, args)
    assert refused.exit_code == 2
    assert "AWS_SECRET_ACCESS_KEY" in refused.output
    assert "not-a-real-secret" not in refused.output
    assert "--allow-host-credentials" in refused.output
    allowed = CliRunner().invoke(main, [*args, "--allow-host-credentials"])
    assert allowed.exit_code == 2
    assert "launch policy must be provisioned outside the untrusted project" in allowed.output
    assert "AWS_SECRET_ACCESS_KEY" not in allowed.output
    assert "not-a-real-secret" not in allowed.output


def test_advisories_cli_fails_when_inventory_identity_is_unknown(tmp_path):
    path = tmp_path / "bom.json"
    path.write_text(
        AIBOM(components=[_package().model_copy(update={"package_url": None})]).to_json()
    )
    result = CliRunner().invoke(main, ["--live", "advisories", str(path)])
    assert result.exit_code == 1
    assert json.loads(result.output)["complete"] is False


def test_baseline_failure_preserves_previous_baseline(tmp_path):
    target = tmp_path / "baseline.json"
    target.write_text("reviewed old baseline")
    (tmp_path / ".mcp.json").write_text("{malformed")
    result = CliRunner().invoke(main, ["baseline", str(tmp_path), "-o", str(target)])
    assert result.exit_code != 0
    assert target.read_text() == "reviewed old baseline"
    assert not list(tmp_path.glob(".nexus-baseline-*"))


def test_remote_and_bare_mcp_have_no_package_pin_claim(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {"url": "https://example.org/mcp"},
                    "local": {"command": "custom-server"},
                    "package": {"command": "npx", "args": ["package@latest"]},
                }
            }
        )
    )
    servers = [
        c for c in MCPScanner().scan(tmp_path).components if isinstance(c, MCPServerComponent)
    ]
    assert {s.name: s.version_pinned for s in servers} == {
        "remote": None,
        "local": None,
        "package": False,
    }
    report = IntegrityValidator().validate(AIBOM(components=servers))
    package = next(s for s in servers if s.name == "package")
    assert [i.component_ref for i in report.issues if i.category == "unpinned_version"] == [
        package.bom_ref
    ]
    assert any(i.category == "unpinned_remote_server" for i in report.issues)


def test_same_named_servers_and_tools_are_scoped_to_configuration(tmp_path):
    from nexus_symbiote.core.models import MCPClientComponent, ToolComponent

    (tmp_path / ".cursor").mkdir()
    for filename, command in [(".mcp.json", "first"), (".cursor/mcp.json", "second")]:
        (tmp_path / filename).write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "shared": {
                            "command": command,
                            "tools": [
                                {
                                    "name": "lookup",
                                    "description": command,
                                    "inputSchema": {"type": "object"},
                                }
                            ],
                        }
                    }
                }
            )
        )
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    servers = [c for c in result.components if isinstance(c, MCPServerComponent)]
    tools = [c for c in result.components if isinstance(c, ToolComponent)]
    assert len(servers) == len({s.bom_ref for s in servers}) == 2
    assert len(tools) == len({t.bom_ref for t in tools}) == 2
    by_host = {
        c.host_application: c for c in result.components if isinstance(c, MCPClientComponent)
    }
    assert set(by_host["cursor"].server_refs).isdisjoint(by_host["claude-code"].server_refs)
    for server in servers:
        assert server.tool_refs == [t.bom_ref for t in tools if t.mcp_server_ref == server.bom_ref]
    # Stable references survive moving the checkout to a different absolute path.
    import shutil

    moved = tmp_path / "copied"
    shutil.copytree(tmp_path, moved, ignore=shutil.ignore_patterns("copied"))
    assert {c.bom_ref for c in MCPScanner().scan(moved).components} == {
        c.bom_ref for c in result.components
    }


def test_readme_commands_exist():
    import re

    readme = (Path(__file__).parents[1] / "README.md").read_text()
    commands = re.findall(r"^nexus-symbiote ([a-z][a-z-]+)\b", readme, re.MULTILINE)
    assert set(commands).issubset(main.commands)


def test_baseline_runs_the_registered_scan_and_publishes_on_pass(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Use read-only tools.\n")
    target = tmp_path / "baseline.json"
    result = CliRunner().invoke(main, ["baseline", str(project), "--baseline-path", str(target)])
    assert result.exit_code == 0, result.output
    assert json.loads(target.read_text())["components"]
