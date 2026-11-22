"""Keep launch arguments in the scope of the component that reads them."""

import pytest

from nexus_symbiote.scanners import mcp_launch


@pytest.mark.parametrize(
    ("spec", "source"),
    [
        ("./assets:/opt/app/assets:ro", "./assets"),
        ("${env:DATA_DIR}/assets:/opt/app/assets", "${env:DATA_DIR}/assets"),
        ("C:/assets/${env:LOCALE}:/opt/app/assets", "C:/assets/${env:LOCALE}"),
        ("./assets/${label:archive}", "./assets/${label"),
    ],
)
def test_volume_separator_respects_only_supported_substitutions(spec, source):
    assert mcp_launch._host_source(spec, mount=False) == source


def test_deno_task_passes_options_after_its_dispatch_flag(monkeypatch):
    seen = []
    monkeypatch.setattr(mcp_launch, "_shell_subcommand", lambda words, _: seen.append(words))
    mcp_launch.analyze("deno", ["task", "--eval", "formatter", "--eval", "sample"])
    assert seen == [["formatter", "--eval", "sample"]]
