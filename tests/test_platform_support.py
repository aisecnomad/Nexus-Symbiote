"""Every command refuses a host without the primitives confinement needs (SECURITY.md)."""

from __future__ import annotations

import os

import pytest

from nexus_symbiote import cli


class _Windows:
    """The os module as the CLI would see it on Windows; faking os.name itself breaks pathlib."""

    name = "nt"

    def __getattr__(self, attribute: str) -> object:
        return getattr(os, attribute)


def test_this_host_has_the_primitives_confinement_needs():
    assert cli.supported_platform()


@pytest.mark.parametrize("missing", ["posix", "O_NOFOLLOW", "O_DIRECTORY", "dir_fd"])
def test_a_host_without_them_runs_no_command(runner, tmp_path, monkeypatch, missing):
    (tmp_path / "CLAUDE.md").write_text("Use the configured tools.\n")
    output = tmp_path / "inventory.json"
    if missing == "posix":
        monkeypatch.setattr(cli, "os", _Windows())
    elif missing == "dir_fd":
        monkeypatch.setattr(os, "supports_dir_fd", set())
    else:
        monkeypatch.delattr(os, missing)
    assert not cli.supported_platform()
    result = runner.invoke(cli.main, ["scan", str(tmp_path), "-o", str(output)])
    assert result.exit_code == 1
    assert "unsupported platform" in result.output
    assert "Windows is not supported" in result.output
    assert not output.exists()
    version = runner.invoke(cli.main, ["--version"])
    assert version.exit_code == 0
    assert "nexus-symbiote, version" in version.output
