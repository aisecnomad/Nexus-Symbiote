"""Known uncollected agent surfaces must keep the coverage gate closed."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.validators.completeness import CompletenessValidator


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("sub/AGENTS.md", "do something"),
        (".github/instructions/agent.instructions.md", "do something"),
        (".cursor/rules/rule.mdc", "do something"),
        (".claude/agents/helper.md", "do something"),
        (".claude/skills/example/run.sh", "echo hello"),
        (".claude/skills/venv/skill.md", "do something"),
        (".claude/settings.json", '{"hooks": {}}'),
        (".codex/config.toml", 'sandbox_mode = "full-access"'),
        (".vscode/mcp.json", '{"servers": {}}'),
        (".windsurf/mcp.json", '{"mcpServers": {}}'),
        ("server.py", "from mcp.server import FastMCP\n"),
        ("build/server.py", "import mcp.server.lowlevel\n"),
        ("server_import.py", "import mcp.server.lowlevel\n"),
        ("server_star.py", "from mcp.server.lowlevel import *\n"),
        ("server.js", 'const {McpServer} = require("@modelcontextprotocol/sdk/server/mcp.js");'),
        ("server.test.ts", 'import {McpServer} from "@modelcontextprotocol/sdk/server/mcp.js";'),
        (
            "server.ts",
            'import * as sdk from "@modelcontextprotocol/sdk/server/mcp.js";\nnew sdk.McpServer({});',
        ),
    ],
)
def test_unobserved_surfaces_fail_default_gate(tmp_path: Path, name: str, content: str) -> None:
    source = tmp_path / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(content, encoding="utf-8")
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "-o", str(output)])
    assert result.exit_code != 0, result.output
    bom = AIBOM.load(output)
    assert bom.metadata.completeness is not None
    expected = ".claude/skills/venv" if name.startswith(".claude/skills/venv/") else name
    assert any(expected in entry for entry in bom.metadata.completeness.surfaces_excluded)
    assert not CompletenessValidator().validate(bom).is_complete
