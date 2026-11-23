"""The collector reference table names every path these collectors read."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.scanners.a2a import A2A_CONFIG_FILES, AGENT_CARD_NAMES
from nexus_symbiote.scanners.mcp import (
    _RESOLVER_FILES,
    MCP_CONFIG_DIRECTORIES,
    MCP_CONFIG_FILES,
    MCP_CONFIG_NAMES,
)
from nexus_symbiote.scanners.model import NAMED_MODEL_FILES
from nexus_symbiote.scanners.prompt import (
    INSTRUCTION_DIRECTORIES,
    INSTRUCTION_FILES,
    NESTED_INSTRUCTION_NAMES,
    PROMPT_DIRECTORY_NAME,
    PROMPT_FILE_SUFFIXES,
    PROMPT_SEARCH_SKIPPED,
    PROMPT_TEXT_SUFFIXES,
    SKILL_DIRECTORIES,
)
from nexus_symbiote.scanners.rag import (
    ENV_FILES,
    GUARDRAIL_CONFIG_FILES,
    NEMO_CONFIG_NAMES,
    RAG_CONFIG_PATTERNS,
)

REFERENCE = (Path(__file__).parents[1] / "docs" / "collectors.md").read_text(encoding="utf-8")


def _row(collector: str) -> str:
    return next(line for line in REFERENCE.splitlines() if line.startswith(f"| `{collector}` |"))


@pytest.mark.parametrize(
    ("collector", "paths"),
    [
        (
            "mcp",
            [
                *MCP_CONFIG_FILES,
                *MCP_CONFIG_DIRECTORIES,
                *MCP_CONFIG_NAMES,
                *(path for paths in _RESOLVER_FILES.values() for path in paths),
            ],
        ),
        ("model", list(NAMED_MODEL_FILES)),
        (
            "prompt",
            [
                *INSTRUCTION_FILES,
                *NESTED_INSTRUCTION_NAMES,
                *INSTRUCTION_DIRECTORIES,
                *SKILL_DIRECTORIES,
                PROMPT_DIRECTORY_NAME,
                *(f"*{suffix}" for suffix in PROMPT_FILE_SUFFIXES),
                *PROMPT_SEARCH_SKIPPED,
                *PROMPT_TEXT_SUFFIXES,
            ],
        ),
        ("rag", [*RAG_CONFIG_PATTERNS, *ENV_FILES, *GUARDRAIL_CONFIG_FILES, *NEMO_CONFIG_NAMES]),
        ("a2a", [*A2A_CONFIG_FILES, *AGENT_CARD_NAMES, "a2a/agent.json"]),
        (
            "ide_agents",
            [
                ".codex/config.toml",
                ".codex/config.json",
                ".cursor/hooks.json",
                ".gemini/settings.json",
                ".vscode/extensions.json",
                ".claude-plugin/plugin.json",
                ".claude/agents",
                ".claude/skills",
            ],
        ),
    ],
)
def test_reference_row_names_every_collected_path(collector, paths):
    row = _row(collector)
    missing = [path for path in paths if f"`{path}`" not in row]
    assert not missing, f"docs/collectors.md `{collector}` row omits {missing}"
