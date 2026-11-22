"""Adversarial regression tests for PR #319 Python and TypeScript coverage-gap evasions."""

from __future__ import annotations

from pathlib import Path

from nexus_symbiote.scanners.mcp import MCPScanner


def test_openai_agents_sdk_import_records_coverage_gap(tmp_path: Path) -> None:
    (tmp_path / "agent_app.py").write_text(
        "from agents import Agent, FunctionTool\n"
        "agent = Agent(name='ops', tools=[FunctionTool(name='exec_shell')])\n",
        encoding="utf-8",
    )
    result = MCPScanner().scan(tmp_path)
    assert any("agent_app.py" in gap for gap in result.surfaces_excluded)


def test_low_level_mcp_server_survives_dead_branch_overwrite_and_alias(tmp_path: Path) -> None:
    (tmp_path / "overwrite.py").write_text(
        "import mcp\n"
        "def unused():\n"
        "    import os as mcp\n"
        "    return mcp\n"
        "srv = mcp.server.Server('hidden')\n",
        encoding="utf-8",
    )
    (tmp_path / "aliased.py").write_text(
        "import mcp\ns = mcp.server\nsrv = s.Server('hidden')\n",
        encoding="utf-8",
    )
    result = MCPScanner().scan(tmp_path)
    assert any("overwrite.py" in gap for gap in result.surfaces_excluded)
    assert any("aliased.py" in gap for gap in result.surfaces_excluded)


def test_honest_loggers_rejects_alias_mutation_and_local_logging_shadow(tmp_path: Path) -> None:
    alias_dir = tmp_path / "alias_case"
    alias_dir.mkdir()
    (alias_dir / "app.py").write_text(
        "import logging\n"
        "import logging as L\n"
        "import importlib\n"
        "L.getLogger = importlib.import_module\n"
        "logging.getLogger('mcp.server.fastmcp')\n",
        encoding="utf-8",
    )
    res_alias = MCPScanner().scan(alias_dir)
    assert any("app.py" in gap for gap in res_alias.surfaces_excluded)

    shadow_dir = tmp_path / "shadow_case"
    shadow_dir.mkdir()
    (shadow_dir / "logging.py").write_text(
        "import importlib\ngetLogger = importlib.import_module\n",
        encoding="utf-8",
    )
    (shadow_dir / "app.py").write_text(
        "import logging\nlogging.getLogger('mcp.server.fastmcp')\n",
        encoding="utf-8",
    )
    res_shadow = MCPScanner().scan(shadow_dir)
    assert any("app.py" in gap for gap in res_shadow.surfaces_excluded)


def test_typescript_computed_method_non_identifier_initializer_and_loader_aliases(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.ts").write_text(
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'const server = new McpServer({ name: "app", version: "1.0.0" });\n'
        "const target = [server][0];\n"
        'const m = "tool";\n'
        'target[m]("hidden_tool", {}, async () => ({ content: [] }));\n',
        encoding="utf-8",
    )
    (tmp_path / "reverse_creator.ts").write_text(
        "function load(p: string) {\n"
        "  const mk = cr;\n"
        "  return mk(import.meta.url)(p);\n"
        "}\n"
        'import { createRequire as cr } from "node:module";\n'
        'export const mod = load("@modelcontextprotocol/sdk/server/mcp.js");\n',
        encoding="utf-8",
    )
    (tmp_path / "require_alias.ts").write_text(
        "const load = require;\n"
        'const suffix = "mcp.js";\n'
        'const mod = load("@modelcontextprotocol/sdk/server/" + suffix);\n',
        encoding="utf-8",
    )
    result = MCPScanner().scan(tmp_path)
    assert any("server.ts" in gap for gap in result.surfaces_excluded)
    assert any("reverse_creator.ts" in gap for gap in result.surfaces_excluded)
    assert any("require_alias.ts" in gap for gap in result.surfaces_excluded)
