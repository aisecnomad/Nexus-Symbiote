"""Tests for component scanners."""

from __future__ import annotations

import json

from nexus_symbiote.core.enums import ComponentType, RiskSeverity, SerializationSafety
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.scanners.registry import RegistryScanner


class TestMCPScanner:
    def test_scan_mcp_json_config(self, tmp_path):
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/data"],
                }
            }
        }
        (tmp_path / "mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        mcp_comps = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER]
        assert len(mcp_comps) >= 1
        assert mcp_comps[0].name == "filesystem"

    def test_scan_claude_config(self, tmp_path):
        config = {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "***"},
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1

    def test_scan_no_config(self, tmp_path):
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0
        assert not result.surfaces_excluded
        assert "mcp-config (no config files found)" in result.surfaces_scanned


class TestModelScanner:
    def test_scan_safetensors(self, tmp_path):
        model_dir = tmp_path / "my_model"
        model_dir.mkdir()
        header = json.dumps(
            {"weight": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}
        ).encode()
        header += b" " * (-len(header) % 8)
        (model_dir / "model.safetensors").write_bytes(
            len(header).to_bytes(8, "little") + header + b"abcd"
        )
        (model_dir / "config.json").write_text('{"model_type": "llama"}')

        scanner = ModelScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        comp = result.components[0]
        assert comp.component_type == ComponentType.MODEL
        assert comp.serialization_safety == SerializationSafety.SAFE

    def test_scan_pickle_flags_risk(self, tmp_path):
        model_dir = tmp_path / "unsafe_model"
        model_dir.mkdir()
        (model_dir / "model.pkl").write_bytes(b"\x00" * 100)

        scanner = ModelScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        comp = result.components[0]
        assert comp.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION
        critical_risks = [r for r in comp.risks if r.severity == RiskSeverity.CRITICAL]
        assert len(critical_risks) >= 1

    def test_scan_trust_remote_code(self, tmp_path):
        model_dir = tmp_path / "remote_code_model"
        model_dir.mkdir()
        (model_dir / "model.safetensors").write_bytes(b"\x00" * 100)
        (model_dir / "config.json").write_text('{"trust_remote_code": true}')

        scanner = ModelScanner()
        result = scanner.scan(tmp_path)
        comp = result.components[0]
        assert comp.trust_remote_code is True
        critical = [r for r in comp.risks if r.category == "code_execution"]
        assert len(critical) >= 1

    def test_scan_no_models(self, tmp_path):
        scanner = ModelScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0


class TestPromptScanner:
    def test_scan_claude_md(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("You are a helpful assistant.")
        scanner = PromptScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        comp = result.components[0]
        assert comp.component_type == ComponentType.PROMPT_TEMPLATE
        assert comp.content_hash is not None

    def test_scan_cursorrules(self, tmp_path):
        (tmp_path / ".cursorrules").write_text("Always use TypeScript.")
        scanner = PromptScanner()
        result = scanner.scan(tmp_path)
        prompts = [
            c for c in result.components if c.component_type == ComponentType.PROMPT_TEMPLATE
        ]
        assert len(prompts) >= 1

    def test_scan_skills_directory(self, tmp_path):
        skill_dir = tmp_path / ".claude" / "skills"
        skill_dir.mkdir(parents=True)
        (skill_dir / "deploy.md").write_text("Deploy the app")
        scanner = PromptScanner()
        result = scanner.scan(tmp_path)
        skills = [c for c in result.components if c.component_type == ComponentType.SKILL_PACKAGE]
        assert len(skills) >= 1

    def test_scan_no_prompts(self, tmp_path):
        scanner = PromptScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0


class TestRAGScanner:
    def test_scan_rag_config(self, tmp_path):
        config = {
            "sources": [
                {
                    "name": "docs-index",
                    "type": "vector-store",
                    "embedding_model": "text-embedding-3-small",
                    "source_uris": ["https://docs.example.com"],
                }
            ]
        }
        (tmp_path / "rag_config.json").write_text(json.dumps(config))
        scanner = RAGScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        assert result.components[0].corpus_type == "vector-store"

    def test_scan_env_detection(self, tmp_path):
        (tmp_path / ".env.example").write_text("PINECONE_API_KEY=xxx\nPINECONE_INDEX=my-index\n")
        scanner = RAGScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1

    def test_scan_python_imports(self, tmp_path):
        (tmp_path / "app.py").write_text("import chromadb\nclient = chromadb.Client()\n")
        scanner = RAGScanner()
        result = scanner.scan(tmp_path)
        chroma = [c for c in result.components if "chroma" in c.name]
        assert len(chroma) >= 1

    def test_scan_no_rag(self, tmp_path):
        scanner = RAGScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0


class TestRegistryScanner:
    def test_scan_npm_ai_deps(self, tmp_path):
        pkg = {
            "dependencies": {
                "@modelcontextprotocol/sdk": "^1.0.0",
                "express": "^4.18.0",
            }
        }
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        ai_deps = [c for c in result.components if "modelcontextprotocol" in c.name]
        assert len(ai_deps) >= 1
        non_ai = [c for c in result.components if "express" in c.name]
        assert len(non_ai) == 0

    def test_scan_pip_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("transformers==4.40.0\nrequests>=2.31\n")
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        assert any(c.name == "transformers" for c in result.components)

    def test_scan_unpinned_version_risk(self, tmp_path):
        pkg = {"dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        for comp in result.components:
            if "modelcontextprotocol" in comp.name:
                pin_risks = [r for r in comp.risks if r.category == "version_pinning"]
                assert len(pin_risks) >= 1

    def test_scan_no_deps(self, tmp_path):
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0

    def test_scan_dockerfile_ai_image(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM vllm/vllm-openai:latest\nRUN pip install app\n")
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        docker_comps = [c for c in result.components if c.registry_type == "docker-hub"]
        assert len(docker_comps) >= 1
        assert any(r.category == "version_pinning" for c in docker_comps for r in c.risks)

    def test_scan_dockerfile_pinned_tag(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM vllm/vllm-openai:0.4.2\n")
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        docker_comps = [c for c in result.components if c.registry_type == "docker-hub"]
        assert len(docker_comps) >= 1
        assert not any(r.category == "version_pinning" for c in docker_comps for r in c.risks)

    def test_scan_pyproject_toml_ai_deps(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = [\n  "transformers>=4.40",\n]\n'
        )
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        assert any(c.name == "transformers" for c in result.components)

    def test_unparsable_pyproject_toml_keeps_other_manifests(self, tmp_path):
        # tomllib raises a plain ValueError for an integer beyond Python's digit limit.
        (tmp_path / "requirements.txt").write_text("transformers==4.40.0\n")
        (tmp_path / "pyproject.toml").write_text("x = " + "1" * 5000 + "\n")
        result = RegistryScanner().scan(tmp_path)
        assert "pyproject.toml: invalid TOML" in result.scan_failures
        assert any(c.name == "transformers" for c in result.components)

    def test_pyproject_toml_over_structure_limit_is_not_parsed(self, tmp_path, monkeypatch):
        from nexus_symbiote.scanners import registry as registry_module

        def refuse(_: str) -> dict[str, object]:
            raise AssertionError("parsed a TOML file over the structure limit")

        monkeypatch.setattr(registry_module.tomllib, "loads", refuse)
        (tmp_path / "pyproject.toml").write_text("a." * 1000 + "a = 1\n")
        result = RegistryScanner().scan(tmp_path)
        assert result.scan_failures == ["pyproject.toml: TOML size or structure limit exceeded"]

    def test_scan_pinned_pip_no_risk(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("transformers==4.40.0\n")
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        tf = [c for c in result.components if c.name == "transformers"]
        assert len(tf) == 1
        assert not any(r.category == "version_pinning" for r in tf[0].risks)


class TestMCPScannerAdvanced:
    def test_sse_transport_detected(self, tmp_path):
        config = {
            "mcpServers": {
                "remote": {
                    "url": "https://example.com/sse",
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        mcp_comps = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER]
        assert len(mcp_comps) == 1
        assert mcp_comps[0].transport == "sse"

    def test_streamable_http_transport(self, tmp_path):
        config = {
            "mcpServers": {
                "remote": {
                    "url": "https://api.example.com/mcp",
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        mcp_comps = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER]
        assert mcp_comps[0].transport == "streamable-http"

    def test_insecure_endpoint_risk(self, tmp_path):
        config = {
            "mcpServers": {
                "insecure": {
                    "url": "http://remote-server.example.com/mcp",
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        mcp_comps = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER]
        assert any(r.category == "transport_security" for r in mcp_comps[0].risks)

    def test_docker_package_ref(self, tmp_path):
        config = {
            "mcpServers": {
                "dockersrv": {
                    "command": "docker",
                    "args": ["run", "--rm", "mcp/filesystem:latest"],
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        mcp_comps = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER]
        assert len(mcp_comps) == 1

    def test_uvx_package_ref(self, tmp_path):
        config = {
            "mcpServers": {
                "pysrv": {
                    "command": "uvx",
                    "args": ["mcp-server-fetch@0.6.2"],
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        mcp_comps = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER]
        assert mcp_comps[0].version == "0.6.2"
        assert mcp_comps[0].version_pinned is True

    def test_tool_extraction_with_annotations(self, tmp_path):
        config = {
            "mcpServers": {
                "toolsrv": {
                    "command": "npx",
                    "args": ["-y", "some-server@1.0.0"],
                    "tools": [
                        {
                            "name": "delete_file",
                            "description": "Delete a file from disk",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                            },
                            "annotations": {"destructiveHint": True},
                        }
                    ],
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        tools = [c for c in result.components if c.component_type == ComponentType.TOOL]
        assert len(tools) == 1
        assert tools[0].definition_hash is not None
        assert any(r.category == "capability_scope" for r in tools[0].risks)

    def test_capability_inference(self, tmp_path):
        config = {
            "mcpServers": {
                "capsrv": {
                    "command": "npx",
                    "args": ["-y", "some-server@1.0.0"],
                    "tools": [
                        {
                            "name": "fetch_url",
                            "description": "Fetch content from a URL via http",
                        },
                        {
                            "name": "read_file",
                            "description": "Read a file from the filesystem path",
                        },
                    ],
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        tools = [c for c in result.components if c.component_type == ComponentType.TOOL]
        assert len(tools) == 2
        from nexus_symbiote.core.enums import CapabilityClass

        fetch = next(t for t in tools if t.name == "fetch_url")
        assert CapabilityClass.NETWORK in fetch.capabilities.capabilities
        read = next(t for t in tools if t.name == "read_file")
        assert CapabilityClass.FILESYSTEM in read.capabilities.capabilities

    def test_env_vars_redacted(self, tmp_path):
        config = {
            "mcpServers": {
                "envsrv": {
                    "command": "npx",
                    "args": ["-y", "some-server@1.0.0"],
                    "env": {"API_KEY": "sk-secret-12345", "OTHER": "value"},
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        mcp = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER][0]
        assert mcp.env.get("API_KEY") == "***"
        assert mcp.env.get("OTHER") == "***"

    def test_malformed_json_handled(self, tmp_path):
        (tmp_path / ".mcp.json").write_text("{not valid json")
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        assert len(result.scan_failures) >= 1

    def test_servers_key_alias(self, tmp_path):
        config = {
            "servers": {
                "alt": {
                    "command": "npx",
                    "args": ["-y", "some-server@2.0.0"],
                }
            }
        }
        (tmp_path / "mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        assert (
            len([c for c in result.components if c.component_type == ComponentType.MCP_SERVER]) >= 1
        )
