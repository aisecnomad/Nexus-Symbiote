"""Positive and adversarial regression tests for Bundle F2:
External #255 (refused-server secret scrubbing) and Muse F-370-1 (walk_complete with .git).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.scanners.mcp import MAX_ARGUMENTS, MCPScanner


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# External #255: refused MCP server must still scrub sibling servers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("case", "refused_cfg"),
    [
        (
            "cli_password",
            {
                "command": "npx",
                "args": ["-y", "srv", "--password", "Open-Sesame-Pass"],
                "tools": 1,
            },
        ),
        (
            "auth_client_secret",
            {
                "url": "https://api.example/mcp",
                "auth": {"client_secret": "Open-Sesame-Pass"},
                "tools": 1,
            },
        ),
        (
            "oauth_client_secret",
            {
                "url": "https://api.example/mcp",
                "oauth": {"clientSecret": "Open-Sesame-Pass"},
                "tools": 1,
            },
        ),
        (
            "non_dict_auth",
            {
                "url": "https://api.example/mcp",
                "auth": "Bearer Open-Sesame-Pass",
                "tools": 1,
            },
        ),
        (
            "url_userinfo",
            {
                "url": "https://user:Open-Sesame-Pass@api.example/mcp",
                "tools": 1,
            },
        ),
        (
            "gallery_userinfo",
            {
                "url": "https://api.example/mcp",
                "gallery": "https://user:Open-Sesame-Pass@gallery.example/mcp",
                "tools": 1,
            },
        ),
        (
            "inline_shell_assignment",
            {
                "command": "sh",
                "args": ["-c", "API_KEY=Open-Sesame-Pass exec srv"],
                "tools": 1,
            },
        ),
        (
            "over_limit_args",
            {
                "command": "npx",
                "args": ["x"] * (MAX_ARGUMENTS + 2) + ["--password", "Open-Sesame-Pass"],
            },
        ),
    ],
)
def test_external_255_refused_server_scrubs_sibling_tool_descriptions(
    tmp_path: Path, case: str, refused_cfg: dict[str, object]
) -> None:
    probe_value = "Open-Sesame-Pass"
    doc = {
        "mcpServers": {
            "broken": refused_cfg,
            "sibling": {
                "command": "python3",
                "args": ["server.py"],
                "tools": [
                    {
                        "name": "describe_config",
                        "description": f"Uses credential {probe_value} for upstream requests",
                    }
                ],
            },
        }
    }
    _write(tmp_path, ".mcp.json", json.dumps(doc))
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures, case
    exported = json.dumps(
        [c.model_dump(mode="json") for c in result.components]
        + list(result.scan_failures)
        + list(result.surfaces_excluded)
    )
    assert probe_value not in exported, f"{case} leaked {probe_value} into sibling output"


def test_external_255_huge_refused_arg_scrubs_linearly(tmp_path: Path) -> None:
    probe_value = "Open-Sesame-Pass"
    huge_arg = ("a " * 40_000) + f"API_KEY={probe_value}"
    doc = {
        "mcpServers": {
            "broken": {"command": "sh", "args": ["-c", huge_arg], "tools": 1},
            "sibling": {
                "command": "python3",
                "args": ["server.py"],
                "tools": [{"name": "t", "description": f"echo {probe_value}"}],
            },
        }
    }
    _write(tmp_path, ".mcp.json", json.dumps(doc))
    result = MCPScanner().scan(tmp_path)
    exported = json.dumps([c.model_dump(mode="json") for c in result.components])
    assert probe_value not in exported


# ---------------------------------------------------------------------------
# Muse F-370-1: .git default exclude must not break walk_complete
# ---------------------------------------------------------------------------


def _write_shadow_repo(root: Path, *, with_git: bool = False, with_pycache: bool = False) -> None:
    _write(root, "pkg/__init__.py", "")
    _write(root, "pkg/mcp.py", "HELPER = 1\n")
    _write(
        root,
        "pkg/srv.py",
        (
            "from mcp.server.fastmcp import FastMCP\n"
            "app = FastMCP('real')\n"
            "@app.tool()\n"
            "def ping() -> str:\n"
            "    return 'pong'\n"
        ),
    )
    if with_git:
        _write(root, ".git/HEAD", "ref: refs/heads/main\n")
    if with_pycache:
        _write(root, "pkg/__pycache__/mcp.cpython-312.pyc", "bytecode")


def test_muse_f_370_1_git_default_exclude_preserves_walk_complete(tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    with_git = tmp_path / "with_git"
    with_cache = tmp_path / "with_cache"
    _write_shadow_repo(clean, with_git=False)
    _write_shadow_repo(with_git, with_git=True)
    _write_shadow_repo(with_cache, with_git=True, with_pycache=True)

    clean_names = sorted(c.name for c in MCPScanner().scan(clean).components)
    git_names = sorted(c.name for c in MCPScanner().scan(with_git).components)
    assert "real" in clean_names
    assert "ping" in clean_names
    assert git_names == clean_names

    # Explicit pkg/__pycache__ still marks pkg uncertain (fail-closed preserved).
    cache_names = sorted(c.name for c in MCPScanner().scan(with_cache).components)
    assert "ping" not in cache_names

    # Explicit policy exclusion still sets walk_complete=False (fail-closed preserved).
    excluded_scanner = MCPScanner()
    excluded_scanner.configure(exclude_paths=("other_excluded",))
    _write(with_git, "other_excluded/x.py", "x = 1\n")
    excl_names = sorted(c.name for c in excluded_scanner.scan(with_git).components)
    assert "ping" not in excl_names


@pytest.mark.parametrize(
    ("label", "refused_cfg"),
    [
        (
            "args_string",
            {"command": "npx", "args": "--api-key=sk-proj-RefusedStrArgSecret9876543210"},
        ),
        (
            "command_list",
            {"command": ["npx", "--api-key=sk-proj-RefusedCmdListSecret9876543210"]},
        ),
        (
            "env_nested_dict",
            {
                "command": "npx",
                "args": [123],
                "env": {"API_KEY": {"val": "sk-proj-RefusedEnvDictSecret9876543210"}},
            },
        ),
    ],
)
def test_refused_server_malformed_field_shapes_scrub_siblings(
    tmp_path: Path, label: str, refused_cfg: dict[str, object]
) -> None:
    secret_map = {
        "args_string": "sk-proj-RefusedStrArgSecret9876543210",
        "command_list": "sk-proj-RefusedCmdListSecret9876543210",
        "env_nested_dict": "sk-proj-RefusedEnvDictSecret9876543210",
    }
    probe = secret_map[label]
    doc = {
        "mcpServers": {
            "refused": refused_cfg,
            "sibling": {"command": "echo", "args": [f"leak={probe}"]},
        }
    }
    case_dir = tmp_path / label
    _write(case_dir, ".mcp.json", json.dumps(doc))
    result = MCPScanner().scan(case_dir)
    exported = json.dumps([c.model_dump(mode="json") for c in result.components])
    assert probe not in exported
