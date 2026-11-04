"""Session checks and fixtures shared by every test module."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from nexus_symbiote.core.hashing import SOURCE_BINDING_KEY_ENV

_PROBE = (
    "import importlib.util as u; s = u.find_spec('nexus_symbiote'); "
    "print(s.origin if s is not None and s.origin else '')"
)
_SOURCE = Path(__file__).resolve().parents[1] / "src" / "nexus_symbiote" / "__init__.py"
_INSTALL = "python -m pip install --no-deps --no-build-isolation -e ."


def _resolved(origin: str | None) -> str | None:
    return os.path.realpath(origin) if origin else None


def _regular_install() -> str | None:
    """Where a regular, non-editable install of the distribution puts the package."""
    try:
        installed = importlib.metadata.distribution("nexus-symbiote")
    except importlib.metadata.PackageNotFoundError:
        return None
    return _resolved(str(installed.locate_file("nexus_symbiote/__init__.py")))


def pytest_sessionstart(session: pytest.Session) -> None:
    """Refuse to run tests against a ``nexus_symbiote`` other than the one under test.

    Two checks, each stopping the session with a usage error (exit status 4):

    * When this file sits in a checkout with ``src/nexus_symbiote``, the tests
      must import that source, or a regular (non-editable) install as when a
      built wheel is tested. An editable install of another checkout, for
      example in a virtual environment shared by several git worktrees, fails.
      A regular install is accepted without checking which source built it.
    * ``python -I``, which the Action runner, the runtime validation worker and
      several tests start, ignores PYTHONPATH and the working directory. It
      must import the same file as the tests, so PYTHONPATH cannot point the
      tests at one copy while those subprocesses import another.
    """
    spec = importlib.util.find_spec("nexus_symbiote")
    expected = _resolved(spec.origin if spec is not None else None)
    if (
        expected is not None
        and _SOURCE.is_file()
        and expected not in {_resolved(str(_SOURCE)), _regular_install()}
    ):
        raise pytest.UsageError(
            f"the tests import nexus_symbiote from {expected}, which is neither "
            f"this checkout's {_SOURCE} nor a regular install. "
            f"Install this checkout into the interpreter that runs pytest: {_INSTALL}"
        )
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
            f"Install this checkout into the interpreter that runs pytest: {_INSTALL}"
        )


@pytest.fixture(autouse=True)
def _no_ambient_binding_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests set the key they need; an operator key exported in the shell must not leak in."""
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
