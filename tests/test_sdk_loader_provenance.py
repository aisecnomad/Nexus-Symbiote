"""Exercise static file discovery with inert names. No helper or cache is imported."""

import pytest

from nexus_symbiote.scanners.mcp import MCPScanner
from tests.test_python_sdk_entry_layouts import _TOOL, _write

_SERVER = "from mcp.server.fastmcp import FastMCP\nserver = FastMCP('sample')\n"


@pytest.mark.parametrize(
    ("helper", "other"),
    [
        ("mcp.py", "mcp.abi3.so"),
        ("mcp.py", "mcp.cp313-win_amd64.pyd"),
        ("mcp.py", "mcp.pyi"),
        ("mcp.py", "__pycache__/mcp.cpython-313.pyc"),
        ("mcp/__init__.py", "mcp/__init__.abi3.so"),
        ("mcp/__init__.py", "mcp/__init__.pyc"),
        ("mcp/__init__.py", "mcp/__pycache__/__init__.cpython-313.pyc"),
        (None, "mcp.abi3.so"),
        (None, "mcp/__init__.pyd"),
    ],
)
def test_alternative_module_layout_keeps_checkout_provenance_uncertain(tmp_path, helper, other):
    _write(tmp_path, "pkg/__init__.py", "")
    if helper:
        _write(tmp_path, "pkg/" + helper, "def label(): return 'notes'\n")
    _write(tmp_path, "pkg/" + other, "Only a marker for static discovery.\n")
    _write(tmp_path, "pkg/server.py", _SERVER + _TOOL)
    result = MCPScanner().scan(tmp_path)
    assert (
        "pkg/server.py: Python SDK import may resolve to checkout code" in result.surfaces_excluded
    )


@pytest.mark.parametrize("relative", ["mcp/server", "mcp/nested/labels"])
def test_directory_link_beneath_a_package_keeps_its_provenance_uncertain(tmp_path, relative):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/mcp/__init__.py", "")
    _write(tmp_path, "notes/data.txt", "Project notes.")
    link = tmp_path / "pkg" / relative
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(tmp_path / "notes", target_is_directory=True)
    _write(tmp_path, "pkg/server.py", _SERVER + _TOOL)
    result = MCPScanner().scan(tmp_path)
    assert (
        "pkg/server.py: Python SDK import may resolve to checkout code" in result.surfaces_excluded
    )


@pytest.mark.parametrize(
    "header", ["import logging", "from typing import Any", "import pathlib as paths"]
)
@pytest.mark.parametrize("layout", ["sibling", "same-file"])
def test_ordinary_standard_import_before_sdk_declaration_preserves_its_tools(
    tmp_path, header, layout
):
    _write(tmp_path, "pkg/__init__.py", "")
    if layout == "sibling":
        _write(tmp_path, "pkg/mcp.py", header + "\ndef label(): return 'notes'\n")
        _write(tmp_path, "pkg/server.py", _SERVER + _TOOL)
    else:
        _write(tmp_path, "pkg/mcp.py", header + "\n" + _SERVER + _TOOL)
    result = MCPScanner().scan(tmp_path)
    assert not result.surfaces_excluded
    assert any(c.name == "notes" for c in result.components)


@pytest.mark.parametrize("header", ["import logging", "from typing import Any"])
def test_possible_checkout_standard_module_keeps_header_unresolved(tmp_path, header):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/logging.py", "label = 'sample'\n")
    _write(tmp_path, "pkg/typing.py", "label = 'sample'\n")
    _write(tmp_path, "pkg/mcp.py", header + "\ndef label(): return 'notes'\n")
    _write(tmp_path, "pkg/server.py", _SERVER + _TOOL)
    result = MCPScanner().scan(tmp_path)
    assert (
        "pkg/server.py: Python SDK import may resolve to checkout code" in result.surfaces_excluded
    )


@pytest.mark.parametrize("relative", ["examples/logging.py", "examples/typing/__init__.py"])
def test_standard_name_outside_first_search_roots_does_not_hide_tools(tmp_path, relative):
    _write(tmp_path, ".mcp.json", '{"mcpServers":{}}')
    _write(tmp_path, relative, "label = 'sample'\n")
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/mcp.py", "import logging\ndef label(): return 'notes'\n")
    _write(tmp_path, "pkg/server.py", _SERVER + _TOOL)
    outcome = MCPScanner().scan(tmp_path)
    assert not outcome.surfaces_excluded
    assert any(component.name == "notes" for component in outcome.components)


@pytest.mark.parametrize(
    "header", ["import logging as __info__", "from typing import Any as __memo__"]
)
def test_special_namespace_bindings_remain_uncertain(tmp_path, header):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/mcp.py", header + "\ndef label(): return 'notes'\n")
    _write(tmp_path, "pkg/server.py", _SERVER + _TOOL)
    outcome = MCPScanner().scan(tmp_path)
    assert (
        "pkg/server.py: Python SDK import may resolve to checkout code" in outcome.surfaces_excluded
    )
