"""System prompt, instruction file, and skill definition scanner."""

from __future__ import annotations

import re
from pathlib import Path

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import PromptComponent, RiskAssessment, SkillPackageComponent
from nexus_symbiote.core.textsafety import hidden_character_kinds
from nexus_symbiote.scanners.base import Scanner, ScanResult, case_variants, folded_name
from nexus_symbiote.utils.confined import ConfinedCollection

INVISIBLE_CHARS: dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "­": "SOFT HYPHEN",
}

BIDI_OVERRIDES: dict[str, str] = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}

TAG_CHAR_RANGE = re.compile(r"[\U000e0001-\U000e007f]")


def detect_invisible_characters(content: str, source_name: str) -> list[RiskAssessment]:
    """Detect invisible Unicode characters that could be used for prompt trojans.

    Checks for zero-width characters, bidirectional overrides, and deprecated
    tag characters — all of which are invisible in most editors and can alter
    LLM interpretation of prompts. Other hidden characters follow the rules for
    MCP tool text, so variation selectors without a matching base are reported
    and a zero-width joiner inside an emoji sequence is not.
    """
    risks: list[RiskAssessment] = []

    # Editors commonly save a leading byte order mark, and it hides nothing.
    if "invisible" in hidden_character_kinds(content.removeprefix("\ufeff")):
        found_invisible = []
        for char, name in INVISIBLE_CHARS.items():
            count = content.count(char)
            if count > 0:
                found_invisible.append(f"{name} (U+{ord(char):04X}) x{count}")
        listed = (
            ", ".join(found_invisible)
            if found_invisible
            else "variation selectors or other format characters"
        )
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="invisible_characters",
                detail=(
                    f"'{source_name}' contains invisible Unicode characters: "
                    f"{listed}. "
                    "These are invisible in most editors and may alter LLM behavior."
                ),
                recommendation="Remove all zero-width characters or document their purpose.",
            )
        )

    found_bidi = []
    for char, name in BIDI_OVERRIDES.items():
        count = content.count(char)
        if count > 0:
            found_bidi.append(f"{name} (U+{ord(char):04X}) x{count}")

    if found_bidi:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="bidi_override",
                detail=(
                    f"'{source_name}' contains bidirectional override characters: "
                    f"{', '.join(found_bidi)}. "
                    "Bidi overrides can make malicious instructions appear as benign text."
                ),
                recommendation="Remove all bidirectional override characters immediately.",
            )
        )

    tag_matches = TAG_CHAR_RANGE.findall(content)
    if tag_matches:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="tag_characters",
                detail=(
                    f"'{source_name}' contains {len(tag_matches)} deprecated Unicode tag "
                    "characters (U+E0001–U+E007F). These are invisible and have no "
                    "legitimate use in prompt files."
                ),
                recommendation="Remove all tag characters — likely a prompt trojan.",
            )
        )

    return risks


INSTRUCTION_FILES: dict[str, str] = {
    "CLAUDE.md": "system-prompt",
    ".claude/CLAUDE.md": "system-prompt",
    "AGENTS.md": "system-prompt",
    "CODEX.md": "system-prompt",
    "codex.md": "system-prompt",
    ".cursorrules": "rules-file",
    ".clinerules": "rules-file",
    ".windsurfrules": "rules-file",
    ".github/copilot-instructions.md": "instruction",
    ".github/AGENTS.md": "instruction",
    ".codex/instructions.md": "instruction",
    "system_prompt.txt": "system-prompt",
    "system_prompt.md": "system-prompt",
}

SKILL_DIRECTORIES = [".claude/skills", ".claude/commands", "skills"]


def _documented_paths(
    files: ConfinedCollection,
    name: str,
    failures: list[str],
    listings: dict[str, dict[str, int]],
    *,
    directory: bool = False,
) -> list[str]:
    """Paths that agents open as a documented name on case-insensitive file systems.

    Agents join fixed names such as CLAUDE.md or .claude/skills, which the default macOS
    and Windows file systems resolve to claude.md or .Claude/Skills. When no listing
    shows the name, it is read itself, so a parent that cannot be listed or is not a
    directory is still reported. A directory under a documented file name, in any case,
    is listed and its read refused.
    """
    return case_variants(files, name, failures, directory=directory, listings=listings) or [name]


class PromptScanner(Scanner):
    name = "prompt"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        with self._collection(project_root, result) as files:
            listings: dict[str, dict[str, int]] = {}
            instructions: dict[str, str] = {}
            for name, prompt_type in INSTRUCTION_FILES.items():
                # CODEX.md and codex.md fold to the same paths; each file is read once.
                for relative in _documented_paths(files, name, result.scan_failures, listings):
                    instructions.setdefault(relative, prompt_type)
            for rel_path, prompt_type in instructions.items():
                content = files.read_bytes(rel_path, missing_ok=True)
                if content is None:
                    continue
                full_path = files.root / rel_path
                result.surfaces_scanned.append(str(full_path))
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    result.scan_failures.append(f"{rel_path}: invalid UTF-8 instruction")
                    continue
                comp = self._scan_instruction_file(full_path, rel_path, prompt_type, content, text)
                result.components.append(comp)

            for skill_dir in SKILL_DIRECTORIES:
                found = False
                directories = _documented_paths(
                    files, skill_dir, result.scan_failures, listings, directory=True
                )
                for path in (path for d in directories for path in files.iter_files(d)):
                    # HFS+ opens SKILL.md\u200c as SKILL.md, so the suffix is compared folded.
                    if path.name.startswith(".") or Path(folded_name(path.name)).suffix not in (
                        ".md",
                        ".txt",
                        ".yaml",
                        ".yml",
                        ".json",
                    ):
                        continue
                    content = files.read_bytes(path)
                    if content is None:
                        continue
                    try:
                        content.decode("utf-8")
                    except UnicodeDecodeError:
                        result.scan_failures.append(f"{path}: invalid UTF-8 skill declaration")
                        continue
                    found = True
                    relative = path.as_posix()
                    result.surfaces_scanned.append(str(files.root / path))
                    result.components.append(
                        SkillPackageComponent(
                            bom_ref=f"skill:{relative}",
                            name=relative,
                            skill_type="skill",
                            hashes={"sha256": hash_bytes(content)},
                            source_path=str(files.root / path),
                            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        )
                    )
                if not found and not result.scan_failures and not result.surfaces_excluded:
                    result.surfaces_scanned.append(f"skills ({skill_dir} no skill files found)")

        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("prompts (no instruction files found)")

        return result

    def _scan_instruction_file(
        self, path: Path, rel_path: str, prompt_type: str, raw: bytes, text: str
    ) -> PromptComponent:
        content_hash = hash_bytes(raw)
        file_size = len(raw)
        risks: list[RiskAssessment] = []

        if file_size > 50_000:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="prompt_size",
                    detail=f"'{rel_path}' is {file_size:,} bytes — large prompts increase injection surface.",
                    recommendation="Review for unnecessary content.",
                )
            )

        risks.extend(detect_invisible_characters(text, rel_path))

        return PromptComponent(
            bom_ref=f"prompt:{rel_path}",
            name=rel_path,
            prompt_type=prompt_type,
            content_hash=content_hash,
            source_path=str(path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
        )
