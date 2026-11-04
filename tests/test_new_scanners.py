"""Tests for A2A, IDE agent, MCP client, and verified extension scanners."""

from __future__ import annotations

import json

from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import MCPScanner


class TestA2AScanner:
    def test_scan_agent_card(self, tmp_path):
        card = {
            "name": "travel-agent",
            "version": "1.0.0",
            "url": "https://agent.example.com/a2a",
            "skills": [
                {"name": "book-flight", "id": "book-flight"},
                {"name": "search-hotels", "id": "search-hotels"},
            ],
            "authentication": {"schemes": ["bearer"]},
        }
        well_known = tmp_path / ".well-known"
        well_known.mkdir()
        (well_known / "agent.json").write_text(json.dumps(card))

        result = A2AScanner().scan(tmp_path)
        servers = [c for c in result.components if c.component_type == ComponentType.A2A_SERVER]
        assert len(servers) == 1
        assert servers[0].name == "travel-agent"
        assert servers[0].authentication_required is True
        assert "book-flight" in servers[0].skills_declared
        assert servers[0].version == "1.0.0"

    def test_scan_root_agent_json(self, tmp_path):
        card = {"name": "helper-agent", "url": "https://example.com/agent"}
        (tmp_path / "agent.json").write_text(json.dumps(card))

        result = A2AScanner().scan(tmp_path)
        assert (
            len([c for c in result.components if c.component_type == ComponentType.A2A_SERVER]) >= 1
        )

    def test_insecure_endpoint_risk(self, tmp_path):
        card = {"name": "insecure", "url": "http://agent.example.com/a2a"}
        (tmp_path / "agent.json").write_text(json.dumps(card))

        result = A2AScanner().scan(tmp_path)
        server = [c for c in result.components if c.component_type == ComponentType.A2A_SERVER][0]
        assert any(r.category == "transport_security" for r in server.risks)

    def test_no_auth_risk(self, tmp_path):
        card = {"name": "open-agent", "url": "https://agent.example.com"}
        (tmp_path / "agent.json").write_text(json.dumps(card))

        result = A2AScanner().scan(tmp_path)
        server = [c for c in result.components if c.component_type == ComponentType.A2A_SERVER][0]
        assert any(r.category == "authentication" for r in server.risks)

    def test_no_skills_risk(self, tmp_path):
        card = {"name": "empty-agent", "url": "https://agent.example.com"}
        (tmp_path / "agent.json").write_text(json.dumps(card))

        result = A2AScanner().scan(tmp_path)
        server = [c for c in result.components if c.component_type == ComponentType.A2A_SERVER][0]
        assert any(r.category == "completeness" for r in server.risks)

    def test_scan_a2a_client_config(self, tmp_path):
        config = {
            "clients": [
                {
                    "name": "weather-agent",
                    "agentCardUrl": "https://weather.example.com/.well-known/agent.json",
                    "authMethods": ["api-key"],
                }
            ]
        }
        (tmp_path / "a2a.json").write_text(json.dumps(config))

        result = A2AScanner().scan(tmp_path)
        clients = [c for c in result.components if c.component_type == ComponentType.A2A_CLIENT]
        assert len(clients) == 1
        assert clients[0].name == "weather-agent"
        assert "api-key" in clients[0].authentication_methods

    def test_scan_a2a_client_insecure(self, tmp_path):
        config = {
            "clients": [
                {
                    "name": "insecure-client",
                    "agentCardUrl": "http://agent.example.com/agent.json",
                }
            ]
        }
        (tmp_path / "a2a.json").write_text(json.dumps(config))

        result = A2AScanner().scan(tmp_path)
        clients = [c for c in result.components if c.component_type == ComponentType.A2A_CLIENT]
        assert any(r.category == "transport_security" for r in clients[0].risks)

    def test_scan_a2a_code_pattern(self, tmp_path):
        (tmp_path / "main.py").write_text("from a2a import A2AClient\nclient = A2AClient()\n")

        result = A2AScanner().scan(tmp_path)
        clients = [c for c in result.components if c.component_type == ComponentType.A2A_CLIENT]
        assert len(clients) >= 1
        assert any(r.category == "detection_method" for r in clients[0].risks)

    def test_scan_no_a2a(self, tmp_path):
        result = A2AScanner().scan(tmp_path)
        assert len(result.components) == 0
        assert not result.surfaces_excluded
        assert any("a2a" in e for e in result.surfaces_scanned)

    def test_malformed_agent_card(self, tmp_path):
        (tmp_path / "agent.json").write_text("{not valid json")

        result = A2AScanner().scan(tmp_path)
        assert len(result.scan_failures) >= 1


class TestIDEAgentScanner:
    def test_scan_claude_code(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {"permissions": {"defaultMode": "default", "allow": ["Read"]}}
        (claude_dir / "settings.json").write_text(json.dumps(settings))
        (tmp_path / "CLAUDE.md").write_text("# System prompt")

        result = IDEAgentScanner().scan(tmp_path)
        agents = [c for c in result.components if c.component_type == ComponentType.IDE_AGENT]
        assert any(a.ide_type == "claude-code" for a in agents)
        claude = next(a for a in agents if a.ide_type == "claude-code")
        assert claude.permission_mode == "default"

    def test_scan_cursor(self, tmp_path):
        (tmp_path / ".cursorrules").write_text("Use TypeScript")

        result = IDEAgentScanner().scan(tmp_path)
        agents = [c for c in result.components if c.component_type == ComponentType.IDE_AGENT]
        assert any(a.ide_type == "cursor" for a in agents)

    def test_scan_codex(self, tmp_path):
        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        (codex_dir / "config.json").write_text("{}")

        result = IDEAgentScanner().scan(tmp_path)
        agents = [c for c in result.components if c.component_type == ComponentType.IDE_AGENT]
        assert any(a.ide_type == "codex" for a in agents)

    def test_scan_windsurf(self, tmp_path):
        (tmp_path / ".windsurfrules").write_text("Use Python 3.12")

        result = IDEAgentScanner().scan(tmp_path)
        agents = [c for c in result.components if c.component_type == ComponentType.IDE_AGENT]
        assert any(a.ide_type == "windsurf" for a in agents)

    def test_scan_cline(self, tmp_path):
        (tmp_path / ".clinerules").write_text("Be concise")

        result = IDEAgentScanner().scan(tmp_path)
        agents = [c for c in result.components if c.component_type == ComponentType.IDE_AGENT]
        assert any(a.ide_type == "cline" for a in agents)

    def test_scan_copilot(self, tmp_path):
        gh = tmp_path / ".github"
        gh.mkdir()
        (gh / "copilot-instructions.md").write_text("Follow our style guide")

        result = IDEAgentScanner().scan(tmp_path)
        agents = [c for c in result.components if c.component_type == ComponentType.IDE_AGENT]
        assert any(a.ide_type == "copilot" for a in agents)

    def test_broad_permissions_risk(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {"permissions": {"allow": ["Bash(*)", "Edit(*)"]}}
        (claude_dir / "settings.json").write_text(json.dumps(settings))

        result = IDEAgentScanner().scan(tmp_path)
        agents = [c for c in result.components if c.ide_type == "claude-code"]
        assert len(agents) == 1
        assert any(r.category == "permission_scope" for r in agents[0].risks)

    def test_instruction_layering_risk(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (tmp_path / "CLAUDE.md").write_text("Top level")
        (claude_dir / "CLAUDE.md").write_text("Nested level")

        result = IDEAgentScanner().scan(tmp_path)
        agents = [c for c in result.components if c.ide_type == "claude-code"]
        assert len(agents) == 1
        assert any(r.category == "instruction_layering" for r in agents[0].risks)

    def test_scan_vscode_ai_extensions(self, tmp_path):
        vscode = tmp_path / ".vscode"
        vscode.mkdir()
        ext = {"recommendations": ["github.copilot", "saoudrizwan.claude-dev", "some.other"]}
        (vscode / "extensions.json").write_text(json.dumps(ext))

        result = IDEAgentScanner().scan(tmp_path)
        exts = [
            c for c in result.components if c.component_type == ComponentType.VERIFIED_EXTENSION
        ]
        assert len(exts) == 2
        assert any("copilot" in e.name for e in exts)
        assert any("claude" in e.name for e in exts)

    def test_scan_no_ide_agents(self, tmp_path):
        result = IDEAgentScanner().scan(tmp_path)
        assert len(result.components) == 0
        assert not result.surfaces_excluded
        assert any("ide-agents" in e for e in result.surfaces_scanned)

    def test_multiple_ide_agents(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("Claude prompt")
        (tmp_path / ".cursorrules").write_text("Cursor rules")
        (tmp_path / ".windsurfrules").write_text("Windsurf rules")

        result = IDEAgentScanner().scan(tmp_path)
        agents = [c for c in result.components if c.component_type == ComponentType.IDE_AGENT]
        ide_types = {a.ide_type for a in agents}
        assert "claude-code" in ide_types
        assert "cursor" in ide_types
        assert "windsurf" in ide_types


class TestMCPClientDetection:
    def test_mcp_client_from_claude_config(self, tmp_path):
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))

        result = MCPScanner().scan(tmp_path)
        clients = [c for c in result.components if c.component_type == ComponentType.MCP_CLIENT]
        assert len(clients) == 1
        assert clients[0].host_application == "claude-code"
        server = next(c for c in result.components if c.component_type == ComponentType.MCP_SERVER)
        assert clients[0].server_refs == [server.bom_ref]

    def test_mcp_client_from_cursor_config(self, tmp_path):
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        config = {
            "mcpServers": {"db": {"command": "npx", "args": ["-y", "mcp-server-sqlite@1.0.0"]}}
        }
        (cursor_dir / "mcp.json").write_text(json.dumps(config))

        result = MCPScanner().scan(tmp_path)
        clients = [c for c in result.components if c.component_type == ComponentType.MCP_CLIENT]
        assert len(clients) == 1
        assert clients[0].host_application == "cursor"

    def test_mcp_sdk_client_code_detection(self, tmp_path):
        (tmp_path / "agent.py").write_text("from mcp import Client\nclient = Client()\n")

        result = MCPScanner().scan(tmp_path)
        clients = [c for c in result.components if c.component_type == ComponentType.MCP_CLIENT]
        assert len(clients) >= 1
        assert any(c.host_application == "sdk" for c in clients)

    def test_mcp_ts_client_code_detection(self, tmp_path):
        (tmp_path / "agent.ts").write_text('import { Client } from "@modelcontextprotocol/sdk";\n')

        result = MCPScanner().scan(tmp_path)
        clients = [c for c in result.components if c.component_type == ComponentType.MCP_CLIENT]
        assert len(clients) >= 1


class TestNewComponentTypes:
    def test_new_enums_exist(self):
        from nexus_symbiote.core.enums import ComponentType

        assert ComponentType.MCP_CLIENT == "mcp-client"
        assert ComponentType.A2A_CLIENT == "a2a-client"
        assert ComponentType.A2A_SERVER == "a2a-server"
        assert ComponentType.IDE_AGENT == "ide-agent"
        assert ComponentType.VERIFIED_EXTENSION == "verified-extension"

    def test_new_models_serializable(self):
        from nexus_symbiote.core.models import (
            A2AClientComponent,
            A2AServerComponent,
            IDEAgentComponent,
            MCPClientComponent,
            VerifiedExtensionComponent,
        )

        mcp_c = MCPClientComponent(bom_ref="mcp-client:test", name="test")
        assert mcp_c.model_dump()["component_type"] == "mcp-client"

        a2a_c = A2AClientComponent(bom_ref="a2a-client:test", name="test")
        assert a2a_c.model_dump()["component_type"] == "a2a-client"

        a2a_s = A2AServerComponent(bom_ref="a2a-server:test", name="test")
        assert a2a_s.model_dump()["component_type"] == "a2a-server"

        ide = IDEAgentComponent(bom_ref="ide-agent:test", name="test")
        assert ide.model_dump()["component_type"] == "ide-agent"

        ext = VerifiedExtensionComponent(bom_ref="ext:test", name="test")
        assert ext.model_dump()["component_type"] == "verified-extension"

    def test_new_components_in_aibom(self):
        from nexus_symbiote.core.aibom import AIBOM
        from nexus_symbiote.core.models import (
            A2AServerComponent,
            IDEAgentComponent,
            MCPClientComponent,
        )

        bom = AIBOM()
        bom.add_component(MCPClientComponent(bom_ref="mcp-client:a", name="a"))
        bom.add_component(A2AServerComponent(bom_ref="a2a-server:b", name="b"))
        bom.add_component(IDEAgentComponent(bom_ref="ide-agent:c", name="c"))
        assert len(bom.components) == 3

        data = bom.to_dict()
        types = {c["component_type"] for c in data["components"]}
        assert "mcp-client" in types
        assert "a2a-server" in types
        assert "ide-agent" in types


class TestNewCollectorBoundaries:
    def test_a2a_yaml_configuration_and_secret_url_minimization(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", raising=False)
        (tmp_path / "a2a.yaml").write_text(
            "clients:\n  - name: docs-agent\n    agentCardUrl: 'https://user:CANARY@agent.example/private/CANARY?token=CANARY'\n"
        )
        result = A2AScanner().scan(tmp_path)
        assert not result.scan_failures
        client = result.components[0]
        assert client.agent_card_url == "https://agent.example"
        assert "CANARY" not in repr(result)

    def test_a2a_comments_and_strings_are_not_sdk_evidence(self, tmp_path):
        (tmp_path / "agent.py").write_text('# from a2a import A2AClient\nmessage = "A2AClient()"\n')
        assert not A2AScanner().scan(tmp_path).components

    def test_a2a_yaml_alias_and_bad_field_shapes_report_failures(self, tmp_path):
        (tmp_path / "a2a.yaml").write_text("clients: &c [*c]\n")
        result = A2AScanner().scan(tmp_path)
        assert result.scan_failures
        assert not result.components
        (tmp_path / "a2a.yaml").unlink()
        (tmp_path / "agent.json").write_text('{"name":"bad","skills":true}')
        assert A2AScanner().scan(tmp_path).scan_failures

    def test_a2a_and_ide_and_importer_do_not_read_symlink_inputs(self, tmp_path):
        from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "agent.json").write_text('{"name":"CANARY"}')
        (outside / "settings.json").write_text('{"permissions":{"mode":"default"}}')
        (outside / "report.json").write_text('[{"id":"CANARY","kind":"agent"}]')
        root = tmp_path / "root"
        root.mkdir()
        (root / "agent.json").symlink_to(outside / "agent.json")
        (root / ".claude").symlink_to(outside, target_is_directory=True)
        (root / "shadowscan-report.json").symlink_to(outside / "report.json")
        for scanner in (A2AScanner(), IDEAgentScanner(), ShadowScanImporter()):
            result = scanner.scan(root)
            assert result.scan_failures
            assert not result.components
            assert "CANARY" not in repr(result)

    def test_new_scanners_honor_policy_exclusions(self, tmp_path):
        from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

        (tmp_path / "agent.json").write_text('{"name":"excluded"}')
        (tmp_path / "CLAUDE.md").write_text("excluded")
        (tmp_path / "shadowscan.json").write_text('[{"kind":"agent","title":"excluded"}]')
        for scanner, excluded in (
            (A2AScanner(), "agent.json"),
            (IDEAgentScanner(), "CLAUDE.md"),
            (ShadowScanImporter(), "shadowscan.json"),
        ):
            scanner.configure(exclude_paths=[excluded])
            result = scanner.scan(tmp_path)
            assert not result.components
            assert any(
                "excluded by collection policy" in reason for reason in result.surfaces_excluded
            )

    def test_malformed_ide_settings_and_extensions_do_not_crash_or_claim_complete(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude/settings.json").write_text('{"permissions":"not-an-object"}')
        (tmp_path / ".vscode").mkdir()
        (tmp_path / ".vscode/extensions.json").write_text('{"recommendations":"not-a-list"}')
        result = IDEAgentScanner().scan(tmp_path)
        assert len(result.scan_failures) >= 2
        agent = next(
            component for component in result.components if component.name == "claude-code"
        )
        assert agent.permission_mode is None

    def test_empty_ide_directory_is_not_agent_deployment_evidence(self, tmp_path):
        (tmp_path / ".claude/skills").mkdir(parents=True)
        assert not IDEAgentScanner().scan(tmp_path).components

    def test_mcp_host_clients_do_not_inherit_other_hosts_servers(self, tmp_path):
        (tmp_path / ".mcp.json").write_text('{"mcpServers":{"claude-only":{}}}')
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".cursor/mcp.json").write_text('{"mcpServers":{"cursor-only":{}}}')
        result = MCPScanner().scan(tmp_path)
        clients = {
            component.host_application: component
            for component in result.components
            if component.component_type == ComponentType.MCP_CLIENT
        }
        servers = {
            c.name: c for c in result.components if c.component_type == ComponentType.MCP_SERVER
        }
        assert clients["claude-code"].server_refs == [servers["claude-only"].bom_ref]
        assert clients["cursor"].server_refs == [servers["cursor-only"].bom_ref]

    def test_mcp_same_host_settings_merge_without_duplicate_client_identity(self, tmp_path):
        (tmp_path / ".mcp.json").write_text('{"mcpServers":{"one":{}}}')
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude/mcp.json").write_text('{"mcpServers":{"two":{}}}')
        result = MCPScanner().scan(tmp_path)
        clients = [
            component
            for component in result.components
            if component.component_type == ComponentType.MCP_CLIENT
        ]
        assert len(clients) == 1
        assert clients[0].server_refs == sorted(
            c.bom_ref for c in result.components if c.component_type == ComponentType.MCP_SERVER
        )

    def test_mcp_python_comments_are_not_sdk_evidence(self, tmp_path):
        (tmp_path / "agent.py").write_text('# from mcp import Client\nmessage = "MCPClient()"\n')
        assert not MCPScanner().scan(tmp_path).components

    def test_mcp_ts_comment_does_not_hide_real_sdk_import(self, tmp_path):
        (tmp_path / "agent.ts").write_text(
            '// comment\nimport { Client } from "@modelcontextprotocol/sdk";\n'
        )
        assert any(
            component.component_type == ComponentType.MCP_CLIENT
            for component in MCPScanner().scan(tmp_path).components
        )

    def test_mcp_tool_digest_stamps_versioned_normalized_profile(self, tmp_path):
        from nexus_symbiote.core.hashing import TOOL_DEFINITION_HASH_VERSION

        (tmp_path / "mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "server": {"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}
                    }
                }
            )
        )
        tool = next(
            component
            for component in MCPScanner().scan(tmp_path).components
            if component.component_type == ComponentType.TOOL
        )
        assert tool.definition_hash_version == TOOL_DEFINITION_HASH_VERSION

    def test_shadowscan_native_mapping_omits_raw_sensitive_payloads(self, tmp_path):
        from nexus_symbiote.core.enums import AssuranceLevel, TrustTier
        from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

        findings = [
            {
                "id": "agent:one",
                "kind": "agent",
                "surface": "code",
                "title": "demo",
                "resource": "https://user:CANARY@agent.example/private/CANARY?token=CANARY",
                "shadow": True,
                "risk": {"level": "high", "score": 80},
                "evidence": {"api_key": "CANARY"},
                "command": "echo CANARY",
            }
        ]
        report = {
            "version": "0.1.4",
            "findings": findings,
            "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
            "stats": [
                {"errors": [], "skipped": False, "incomplete": False, "declared_omissions": 0}
            ],
        }
        (tmp_path / "shadowscan-report.json").write_text(json.dumps(report))
        result = ShadowScanImporter().scan(tmp_path)
        assert not result.scan_failures
        component = result.components[0]
        assert component.bom_ref.startswith("shadowscan:")
        assert component.assurance_level == AssuranceLevel.DECLARED
        assert component.trust_tier == TrustTier.UNKNOWN
        assert component.source_path is None
        assert component.properties["shadowscan:report-sha256"].startswith("sha256:")
        assert component.autonomy_level is None
        assert "CANARY" not in repr(result)
        assert any(risk.category == "shadowscan-inventory-unmatched" for risk in component.risks)

    def test_shadowscan_cyclonedx_mapping_preserves_kind_without_raw_properties(self, tmp_path):
        from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

        report = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {"properties": [{"name": "shadowscan:scan:status", "value": "complete"}]},
            "components": [
                {
                    "bom-ref": "mcp:one",
                    "name": "server",
                    "group": "mcp-server",
                    "properties": [
                        {"name": "secret", "value": "CANARY"},
                        {"name": "shadowscan:heuristic-risk", "value": "high"},
                    ],
                }
            ],
        }
        (tmp_path / "shadowscan.json").write_text(json.dumps(report))
        result = ShadowScanImporter().scan(tmp_path)
        assert not result.scan_failures
        assert result.components[0].component_type == ComponentType.MCP_SERVER
        assert "CANARY" not in repr(result)
        assert result.components[0].risks[0].severity.value == "high"

    def test_shadowscan_malformed_and_duplicate_reports_fail_without_payload_leak(self, tmp_path):
        from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

        for content in (
            '{"findings":"CANARY"}',
            '[{"id":"dup"},{"id":"dup"}]',
            '[{"risk":{"score":"CANARY"}}]',
            '{"bomFormat":"CycloneDX","components":[{"properties":[{}]}]}',
        ):
            (tmp_path / "shadowscan.json").write_text(content)
            result = ShadowScanImporter().scan(tmp_path)
            assert result.scan_failures
            assert not result.components
            assert "CANARY" not in repr(result)

    def test_shadowscan_explicit_import_rejects_symlink(self, tmp_path):
        import pytest

        from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

        target = tmp_path / "target"
        target.write_text("[]")
        link = tmp_path / "link.json"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="unavailable"):
            ShadowScanImporter().import_report(link)
