"""Built-in scanner universe used when assessing static coverage.

Adding a scanner changes the minimum evidence required for a complete scan.
Keep this set synchronized with the CLI registry and its regression test.
"""

BUILTIN_SCANNER_NAMES = frozenset(
    {"mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents", "code"}
)

INSTRUCTION_DIRECTORIES: dict[str, str] = {
    ".clinerules": "rules-file",
    ".claude/rules": "rules-file",
    ".cursor/rules": "rules-file",
    ".windsurf/rules": "rules-file",
    ".roo/rules": "rules-file",
    ".kiro/steering": "rules-file",
    ".github/instructions": "instruction",
    ".github/prompts": "instruction",
    ".claude/output-styles": "instruction",
    ".claude/agents": "subagent",
    ".github/agents": "subagent",
}

SKILL_DIRECTORIES = [
    ".claude/skills",
    ".claude/commands",
    "skills",
    ".agents/skills",
    ".github/skills",
    ".cursor/skills",
    ".gemini/skills",
    ".cursor/commands",
    ".gemini/commands",
    # The scripts hooks conventionally run: settings bind only the program word that
    # names one, so the script itself is bound here.
    ".claude/hooks",
    ".cursor/hooks",
]
