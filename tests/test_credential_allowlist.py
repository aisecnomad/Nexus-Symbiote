"""Vendor shapes that look like examples stay findings unless an allowlist names them."""

from __future__ import annotations

import hashlib
from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.credential_allowlist import (
    bind_credential_allowlist,
    load_credential_allowlist,
    path_glob_matches,
)
from nexus_symbiote.literal_credentials import apply_literal_credential_findings
from nexus_symbiote.scanners.mcp_credentials import normalize_credential, placeholder

_FAKE = "sk-proj-thisisfake0123456789ab"
_LOW = "sk-proj-" + ("a" * 24)
_DUMMY = "ghp_" + ("dummy1" * 8)


def _digest(token: str) -> str:
    return hashlib.sha256(normalize_credential(token).encode("utf-8")).hexdigest()


def test_example_words_do_not_make_a_vendor_shape_a_placeholder() -> None:
    example = "sk-proj-" + ("example" * 4)
    assert placeholder(example)
    assert placeholder(_LOW)


def test_pure_non_tokens_are_not_vendor_shapes() -> None:
    from nexus_symbiote.utils.secrets import TOKEN_SHAPE

    for text in ("<YOUR_API_KEY>", "sk-...", "xxxx", "sk-short"):
        assert TOKEN_SHAPE.search(text) is None


def test_a_fingerprint_allowlist_suppresses_one_spelling(tmp_path: Path) -> None:
    (tmp_path / "docs.md").write_text(f'key = "{_FAKE}"\n', encoding="utf-8")
    (tmp_path / ".nexus-symbiote-credential-allowlist.yaml").write_text(
        f'allow:\n  - fingerprint: "{_digest(_FAKE)}"\n    reason: "Reviewed sample."\n',
        encoding="utf-8",
    )
    allowlist, error = load_credential_allowlist(tmp_path)
    assert error is None
    docs = PromptComponent(bom_ref="prompt:docs", name="docs", source_path="docs.md")
    with bind_credential_allowlist(allowlist):
        added = apply_literal_credential_findings(AIBOM(components=[docs]), tmp_path)
    assert added == 0
    assert docs.risks == []


def test_a_path_glob_suppresses_the_file_and_not_its_neighbour(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "sample.md").write_text(f'key = "{_FAKE}"\n', encoding="utf-8")
    (tmp_path / "app.md").write_text(f'key = "{_LOW}"\n', encoding="utf-8")
    (tmp_path / ".nexus-symbiote-credential-allowlist.yaml").write_text(
        'allow:\n  - path: "docs/**"\n    reason: "Documentation samples."\n',
        encoding="utf-8",
    )
    allowlist, error = load_credential_allowlist(tmp_path)
    assert error is None and path_glob_matches("docs/**", "docs/sample.md")
    sample = PromptComponent(bom_ref="prompt:sample", name="sample", source_path="docs/sample.md")
    app = PromptComponent(bom_ref="prompt:app", name="app", source_path="app.md")
    with bind_credential_allowlist(allowlist):
        added = apply_literal_credential_findings(AIBOM(components=[sample, app]), tmp_path)
    assert added == 1
    assert sample.risks == []
    assert _LOW not in app.risks[0].detail


def test_a_broken_allowlist_suppresses_nothing(tmp_path: Path) -> None:
    (tmp_path / "docs.md").write_text(f'key = "{_DUMMY}"\n', encoding="utf-8")
    (tmp_path / ".nexus-symbiote-credential-allowlist.yaml").write_text(
        "allow:\n  - reason: missing a target\n",
        encoding="utf-8",
    )
    allowlist, error = load_credential_allowlist(tmp_path)
    assert error is not None and allowlist.allow == []
    docs = PromptComponent(bom_ref="prompt:docs", name="docs", source_path="docs.md")
    with bind_credential_allowlist(allowlist):
        added = apply_literal_credential_findings(AIBOM(components=[docs]), tmp_path)
    assert added == 1
    assert _DUMMY not in docs.risks[0].detail
    assert _DUMMY not in error


def test_a_marked_token_matches_the_normalized_fingerprint(tmp_path: Path) -> None:
    marked = "sk-proj-thisis" + "\u200b" + "fake0123456789ab"
    (tmp_path / "docs.md").write_text(f'key = "{marked}"\n', encoding="utf-8")
    (tmp_path / ".nexus-symbiote-credential-allowlist.yaml").write_text(
        "allow:\n"
        f'  - fingerprint: "{_digest(marked)}"\n'
        '    reason: "Same spelling with a format character."\n',
        encoding="utf-8",
    )
    allowlist, error = load_credential_allowlist(tmp_path)
    assert error is None
    docs = PromptComponent(bom_ref="prompt:docs", name="docs", source_path="docs.md")
    with bind_credential_allowlist(allowlist):
        assert apply_literal_credential_findings(AIBOM(components=[docs]), tmp_path) == 0
