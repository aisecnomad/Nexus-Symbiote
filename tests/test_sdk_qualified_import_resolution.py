"""Compare static Python source layouts without importing or launching a checkout."""

import pytest

from nexus_symbiote.scanners.mcp import MCPScanner
from tests.test_python_sdk_entry_layouts import _SERVER, _TOOL, _write


@pytest.mark.parametrize("module", ["agents", "agents.tool"])
@pytest.mark.parametrize("alias", ["", " as framework"])
def test_qualified_framework_import_stays_unresolved_in_a_regular_checkout(tmp_path, module, alias):
    _write(tmp_path, "agents/__init__.py", "")
    _write(tmp_path, "agents/tool.py", "provider = 'notes'\n")
    _write(tmp_path, "server.py", _SERVER + _TOOL + f"import {module}{alias}\n")
    result = MCPScanner().scan(tmp_path)
    assert "server.py: unresolved Python SDK tool import" in result.surfaces_excluded


@pytest.mark.parametrize("prefix", ["", "src/"])
@pytest.mark.parametrize(
    "name,source",
    [
        ("mcp.py", "def label(): return 'notes'\n"),
        ("mcp.py", "from __future__ import annotations\nfrom mcp.server.fastmcp import FastMCP\n"),
        ("mcp/__init__.py", "def label(): return 'notes'\n"),
    ],
)
def test_ordinary_package_helper_cannot_supply_the_dotted_factory(tmp_path, prefix, name, source):
    _write(tmp_path, prefix + "pkg/__init__.py", "")
    _write(tmp_path, prefix + "pkg/" + name, source)
    _write(tmp_path, prefix + "pkg/server.py", _SERVER + _TOOL)
    result = MCPScanner().scan(tmp_path)
    assert any(c.name == "notes" for c in result.components)
    assert (
        prefix + "pkg/server.py: Python SDK import may resolve to checkout code"
        not in result.surfaces_excluded
    )


@pytest.mark.parametrize(
    "flat",
    [
        "from other import configure\n",
        "def __getattr__(name): return 'notes'\n",
        "def note(x=factory()): return x\n",
        "@label\ndef note(): pass\n",
    ],
)
def test_unknown_import_time_behavior_retains_the_provenance_gap(tmp_path, flat):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/mcp.py", flat)
    _write(tmp_path, "pkg/server.py", _SERVER + _TOOL)
    result = MCPScanner().scan(tmp_path)
    assert (
        "pkg/server.py: Python SDK import may resolve to checkout code" in result.surfaces_excluded
    )


@pytest.mark.parametrize(
    "leaf", ["server.py", "server/other.py", "server.native", "server/__init__.py"]
)
def test_local_package_with_a_possible_submodule_retains_the_gap(tmp_path, leaf):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/mcp/__init__.py", "")
    _write(tmp_path, "pkg/mcp/" + leaf, "label = 'notes'\n")
    _write(tmp_path, "pkg/server.py", _SERVER + _TOOL)
    result = MCPScanner().scan(tmp_path)
    assert (
        "pkg/server.py: Python SDK import may resolve to checkout code" in result.surfaces_excluded
    )


@pytest.mark.parametrize(
    "source",
    [
        "from agents import function_tool\n",
        "from __future__ import annotations\nfrom agents import function_tool\n",
    ],
)
def test_sibling_agents_module_can_import_the_installed_decorator(tmp_path, source):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/agents.py", source + "@function_tool\ndef describe(): return 'notes'\n")
    result = MCPScanner().scan(tmp_path)
    assert any(c.name == "describe" for c in result.components)
    assert (
        "pkg/agents.py: Python SDK import may resolve to checkout code"
        not in result.surfaces_excluded
    )


@pytest.mark.parametrize("quoted", [True, False])
def test_optional_generic_context_provenance_is_preserved(tmp_path, quoted):
    name = "Context[ServerSession, None] | None"
    if quoted:
        name = repr(name)
    _write(
        tmp_path,
        "server.py",
        _SERVER
        + "from mcp.server.session import ServerSession\n@server.tool()\n"
        + f"def page(ctx: {name} = None) -> str: return 'notes'\n",
    )
    result = MCPScanner().scan(tmp_path)
    assert any(c.name == "page" for c in result.components)
    assert result.surfaces_excluded == []


def test_package_future_module_keeps_postponed_annotation_source_uncertain(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/__future__.py", "annotations = 'settings'\n")
    _write(tmp_path, "pkg/mcp/__init__.py", "from __future__ import annotations\n")
    _write(tmp_path, "pkg/server.py", _SERVER + _TOOL)
    result = MCPScanner().scan(tmp_path)
    assert (
        "pkg/server.py: Python SDK import may resolve to checkout code" in result.surfaces_excluded
    )


@pytest.mark.parametrize("path", ["pkg/agents.py", "pkg/agents/__init__.py"])
def test_declared_local_sdk_member_still_has_uncertain_provenance(tmp_path, path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, path, "def function_tool(arg): return arg\n")
    _write(
        tmp_path,
        "pkg/server.py",
        "from agents import function_tool\n@function_tool\ndef label(): return 'notes'\n",
    )
    result = MCPScanner().scan(tmp_path)
    assert (
        "pkg/server.py: Python SDK import may resolve to checkout code" in result.surfaces_excluded
    )


@pytest.mark.parametrize(
    "source",
    [
        (
            "import mcp as m\n"
            "app = m.server.Server('x')\n"
            "def _unused():\n"
            "    import os as m\n"
            "    return m\n"
        ),
        (
            "from mcp import server as m\n"
            "app = m.Server('x')\n"
            "def _unused():\n"
            "    import mcp as m\n"
            "    return m\n"
        ),
    ],
)
def test_later_import_alias_cannot_clobber_low_level_mcp_detection(tmp_path, source):
    _write(tmp_path, "server.py", source)
    result = MCPScanner().scan(tmp_path)
    assert "server.py: low-level MCP server tool list uncollected" in result.surfaces_excluded


def test_shadowed_logging_module_withdraws_getlogger_exemption(tmp_path):
    _write(tmp_path, "logging.py", "def getLogger(name):\n    return __import__(name)\n")
    _write(
        tmp_path,
        "app.py",
        "import logging\nmod = logging.getLogger('mcp.client.stdio')\n",
    )
    result = MCPScanner().scan(tmp_path)
    assert any(gap.startswith("app.py:") for gap in result.surfaces_excluded)
