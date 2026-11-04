"""Fixtures shared by every test module."""

from __future__ import annotations

import pytest

from nexus_symbiote.core.hashing import SOURCE_BINDING_KEY_ENV


@pytest.fixture(autouse=True)
def _no_ambient_binding_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests set the key they need; an operator key exported in the shell must not leak in."""
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
