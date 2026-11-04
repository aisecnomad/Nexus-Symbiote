"""docs/verification-source-binding.md states the A2A collection semantics the tests pin."""

from __future__ import annotations

from pathlib import Path

from nexus_symbiote.scanners.a2a import _ANONYMOUS_SCHEMES, _SCHEME_TYPES
from tests.test_a2a_v1_cards import NULL_FAILS

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "verification-source-binding.md"
CHANGELOG = ROOT / "CHANGELOG.md"


def _paragraph(path: Path, phrase: str) -> str:
    """Return the one paragraph containing ``phrase``, with line wrapping undone."""
    paragraphs = [" ".join(block.split()) for block in path.read_text().split("\n\n")]
    (found,) = [paragraph for paragraph in paragraphs if phrase in paragraph]
    return found


def test_only_the_listed_legacy_scheme_names_are_anonymous():
    paragraph = _paragraph(GUIDE, "legacy scheme named")
    assert all(f"`{name}`" in paragraph for name in _ANONYMOUS_SCHEMES - {""})
    assert "Only these names are anonymous" in paragraph


def test_scheme_definitions_are_checked_for_their_type_only():
    paragraph = _paragraph(GUIDE, "An unsupported form leaves the requirement unknown coverage")
    assert all(f"`{kind}`" in paragraph for kind in _SCHEME_TYPES)
    assert "checked for their type, not for completeness" in paragraph


def test_null_fields_are_not_all_absent():
    for path in (GUIDE, CHANGELOG):
        assert "A `null` field counts as absent" not in " ".join(path.read_text().split())
    paragraph = _paragraph(GUIDE, "fails collection of the card")
    assert all(f"`{field}`" in paragraph for field in NULL_FAILS)


def test_declaration_failures_are_separate_from_whole_file_parse_failures():
    assert "non-string key" not in _paragraph(GUIDE, "fails that declaration alone")
    whole_file = _paragraph(GUIDE, "fails as a whole")
    assert "non-string" in whole_file and "`NaN`" in whole_file
