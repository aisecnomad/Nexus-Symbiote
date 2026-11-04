"""Session checks and fixtures shared by every test module."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

import pytest

from nexus_symbiote.core.hashing import SOURCE_BINDING_KEY_ENV

_PROBE = (
    "import importlib.util as u; s = u.find_spec('nexus_symbiote'); "
    "print(s.origin if s is not None and s.origin else '')"
)


def _resolved(origin: str | None) -> str | None:
    return os.path.realpath(origin) if origin else None


def pytest_sessionstart(session: pytest.Session) -> None:
    """Refuse to run when isolated subprocesses would import another package copy.

    The Action runner, the runtime validation worker and several tests start
    ``python -I``, which ignores PYTHONPATH and the working directory and imports
    the installed ``nexus_symbiote``. When that is a different checkout, for
    example a virtual environment shared by several git worktrees, those tests
    pass or fail for code that is not under test.
    """
    spec = importlib.util.find_spec("nexus_symbiote")
    expected = _resolved(spec.origin if spec is not None else None)
    probe = subprocess.run(  # noqa: S603 - the running interpreter with fixed arguments
        [sys.executable, "-I", "-c", _PROBE],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    isolated = _resolved(probe.stdout.strip() or None)
    if expected is None or isolated != expected:
        raise pytest.UsageError(
            "isolated subprocesses import nexus_symbiote from "
            f"{isolated or 'nowhere'}, but the tests import it from {expected or 'nowhere'}. "
            "Install this checkout into the interpreter that runs pytest: "
            "python -m pip install --no-deps --no-build-isolation -e ."
        )


@pytest.fixture(autouse=True)
def _no_ambient_binding_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests set the key they need; an operator key exported in the shell must not leak in."""
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
