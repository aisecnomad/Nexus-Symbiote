"""Codex collection stays fast on hostile layers within the TOML limits."""

import time
from pathlib import Path

from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import IDEAgentComponent, MCPServerComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import MCPScanner

LIMIT = "Codex configuration: MCP server redaction work limit exceeded"
PROFILE_LIMIT = "Codex configuration: permission profile work limit exceeded"
FULL_ACCESS = "Codex declares unrestricted filesystem access."
# The limit assertions catch a removed or loosened budget. The time bound catches only
# catastrophic regressions: unbounded collection of these shapes took minutes to hours.
# It counts this process's CPU time, so a busy machine cannot fail it, and leaves room
# for branch-coverage tracing, which slows collection several times.
CPU_SECONDS = 30


def bounded_scan(scanner: IDEAgentScanner | MCPScanner, root: Path) -> ScanResult:
    started = time.process_time()
    result = scanner.scan(root)
    assert time.process_time() - started < CPU_SECONDS
    return result


def write_layer(root: Path, value: str, directory: str = ".") -> None:
    folder = root / directory / ".codex"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.toml").write_text(value)


def heavy_server(secrets: int, names: int) -> str:
    env = ", ".join(f'E{i} = "v{i}"' for i in range(secrets))
    forwarded = ", ".join(f'"N{i}"' for i in range(names))
    return f'[mcp_servers.s]\ncommand = "npx"\nenv = {{ {env} }}\nenv_vars = [{forwarded}]\n'


def test_redacting_many_names_against_many_secrets_is_bounded(tmp_path: Path) -> None:
    # Every recorded name is redacted against every secret value of its server.
    write_layer(tmp_path, heavy_server(8000, 12000))
    result = bounded_scan(MCPScanner(), tmp_path)
    assert result.scan_failures == [LIMIT]
    assert not any(isinstance(c, MCPServerComponent) for c in result.components)


def test_inherited_servers_cannot_multiply_redaction_work(tmp_path: Path) -> None:
    # A nested layer merges an ancestor's server, however large, in a few bytes.
    write_layer(tmp_path, heavy_server(1900, 1900))
    for index in range(15):
        write_layer(tmp_path, "[mcp_servers.s]\nenabled = false\n", f"p{index:02d}")
    result = bounded_scan(MCPScanner(), tmp_path)
    assert result.scan_failures == [LIMIT]
    assert len([c for c in result.components if isinstance(c, MCPServerComponent)]) == 1


def test_growing_profile_grants_across_layers_are_bounded(tmp_path: Path) -> None:
    # One extends chain through 16 layers whose filesystem grants grow at each step.
    directory, offset = ".", 0
    for depth in range(16):
        write_layer(
            tmp_path,
            "".join(
                f"[permissions.p{offset + i}]\n"
                f'extends = "{f"p{offset + i - 1}" if offset + i else ":workspace"}"\n'
                f'filesystem = {{ "/f{offset + i}" = "read" }}\n'
                for i in range(500)
            ),
            directory,
        )
        offset += 500
        directory = "d0" if directory == "." else f"{directory}/d{depth}"
    result = bounded_scan(IDEAgentScanner(), tmp_path)
    assert result.scan_failures == [PROFILE_LIMIT]


def test_resolving_inherited_profile_chains_is_bounded(tmp_path: Path) -> None:
    # Each sibling overrides only the leaf of a long root chain, so checking its own
    # profile is cheap but resolving it copies every grant the chain accumulated.
    write_layer(
        tmp_path,
        "".join(
            f'[permissions.p{i}]\nextends = "{f"p{i - 1}" if i else ":workspace"}"\n'
            f'filesystem = {{ "/f{i}" = "read" }}\n'
            for i in range(1000)
        ),
    )
    for index in range(15):
        write_layer(tmp_path, '[permissions.p999.filesystem]\n"/s" = "read"\n', f"s{index:02d}")
    result = IDEAgentScanner().scan(tmp_path)
    assert result.scan_failures == [PROFILE_LIMIT]


def test_large_profile_selected_in_every_layer_is_bounded(tmp_path: Path) -> None:
    # Each layer adds grants to one profile and selects it, so it grows with depth.
    directory = "."
    for depth in range(16):
        entries = ", ".join(f'"/d{depth}f{i}" = "read"' for i in range(9000))
        write_layer(
            tmp_path,
            f'default_permissions = "wide"\n[permissions.wide]\nfilesystem = {{ {entries} }}\n',
            directory,
        )
        directory = "d0" if directory == "." else f"{directory}/d{depth}"
    result = bounded_scan(IDEAgentScanner(), tmp_path)
    assert result.scan_failures == [PROFILE_LIMIT]


def test_long_permission_profile_chain_resolves_quickly(tmp_path: Path) -> None:
    count = 3000
    write_layer(
        tmp_path,
        f'default_permissions = "p{count - 1}"\n'
        '[permissions.p0]\nextends = ":workspace"\n'
        + "".join(f'[permissions.p{i}]\nextends = "p{i - 1}"\n' for i in range(1, count)),
    )
    result = bounded_scan(IDEAgentScanner(), tmp_path)
    assert not result.scan_failures
    agent = next(c for c in result.components if isinstance(c, IDEAgentComponent))
    assert agent.permission_mode == f"profile:p{count - 1}"
    assert (RiskSeverity.HIGH, FULL_ACCESS) not in {
        (risk.severity, risk.detail) for risk in agent.risks
    }
