"""Adversarial source inputs must terminate and refuse incomplete inventory."""

import time

from nexus_symbiote.core.models import MCPClientComponent, ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner, _strip_js_comments


def test_many_unterminated_comment_openers_finish_quickly(tmp_path):
    # The former non-greedy block-comment regex restarted at each opener,
    # repeatedly searching the whole remaining string for a missing terminator.
    (tmp_path / "client.js").write_text("/*" * 100_000)
    started = time.monotonic()
    MCPScanner().scan(tmp_path)
    assert time.monotonic() - started < 5


def test_comment_removal_preserves_sdk_hint_and_ignores_comments(tmp_path):
    (tmp_path / "client.js").write_text(
        '/* from "@modelcontextprotocol/sdk" */\n'
        '  // from "@modelcontextprotocol/sdk"\n'
        'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
    )
    result = MCPScanner().scan(tmp_path)
    assert any(isinstance(c, MCPClientComponent) for c in result.components)
    assert _strip_js_comments("/* a */\n // b\nabc /* unterminated") == ("\n\nabc /* unterminated")


def test_deep_typescript_ast_fails_closed_quickly(tmp_path):
    source = (
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        "const deep = " + "new (" * 180 + "McpServer" + ")()" * 180 + ";\n"
    )
    (tmp_path / "server.ts").write_text(source)
    started = time.monotonic()
    result = MCPScanner().scan(tmp_path)
    assert time.monotonic() - started < 5
    assert result.scan_failures
    assert not any(isinstance(c, ToolComponent) for c in result.components)


def test_analysis_budget_exhaustion_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus_symbiote.scanners.ts_tools.MAX_ANALYSIS_SECONDS", -1)
    (tmp_path / "server.ts").write_text(
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'const server = new McpServer({}); server.tool("read", {}, handler);\n'
    )
    result = MCPScanner().scan(tmp_path)
    assert any("TypeScript source parsing or AST limit refused" in e for e in result.scan_failures)
    assert not any(isinstance(c, ToolComponent) for c in result.components)
