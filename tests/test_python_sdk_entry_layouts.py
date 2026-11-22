"""Exercise Python SDK provenance using inert source text and public type names."""

from dataclasses import replace
from pathlib import Path

import pytest

from nexus_symbiote import limits
from nexus_symbiote.scanners.mcp import MCPScanner

_SERVER = "from mcp.server.fastmcp import Context, FastMCP\nserver = FastMCP('sample')\n"
_TOOL = "@server.tool()\ndef notes() -> str: return 'sample'\n"


def _write(root, relative, source):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)


@pytest.mark.parametrize(
    ("entry", "local_root"),
    [
        ("server.py", "src"),
        ("app/server.py", "."),
        ("app/server.py", "app"),
        ("src/worker/server.py", "src"),
    ],
)
def test_partial_search_root_cannot_exempt_a_framework_import(tmp_path, entry, local_root):
    agents = Path(local_root) / "agents"
    _write(tmp_path, agents / "__init__.py", "")
    _write(tmp_path, agents / "tool.py", "label = 'sample'\n")
    _write(tmp_path, entry, _SERVER + _TOOL + "import agents.tool\n")
    result = MCPScanner().scan(tmp_path)
    assert any(c.name == "notes" for c in result.components)
    assert f"{entry}: unresolved Python SDK tool import" in result.surfaces_excluded


@pytest.mark.parametrize(
    ("module", "files"),
    [
        ("fastmcp", ["worker/fastmcp.py"]),
        ("mcp.server.fastmcp", ["worker/mcp/__init__.py", "worker/mcp/server/__init__.py"]),
        ("mcp.server.fastmcp", ["worker/mcp.py"]),
    ],
)
def test_package_entry_reports_possible_script_path_resolution(tmp_path, module, files):
    _write(tmp_path, "worker/__init__.py", "")
    for path in files:
        _write(tmp_path, path, "def configure(): return 'sample'\n")
    _write(
        tmp_path, "worker/server.py", f"from {module} import FastMCP\nserver = FastMCP('sample')\n"
    )
    result = MCPScanner().scan(tmp_path)
    assert (
        "worker/server.py: Python SDK import may resolve to checkout code"
        in result.surfaces_excluded
    )


@pytest.mark.parametrize(
    ("imports", "arguments"),
    [
        ("from mcp.server.session import ServerSession", "ServerSession, None"),
        ("from mcp import ServerSession as Session", "Session, None"),
        ("import mcp.server.session as session", "session.ServerSession, None"),
        ("from mcp.shared.context import RequestContext", "None, RequestContext"),
        (
            "from mcp.server.session import ServerSession\nfrom starlette.requests import Request",
            "ServerSession, None, Request",
        ),
    ],
)
def test_standard_sdk_context_arguments_are_annotation_data(tmp_path, imports, arguments):
    _write(
        tmp_path,
        "server.py",
        _SERVER
        + imports
        + "\n@server.tool()\n"
        + f"def notes(ctx: Context[{arguments}]) -> str: return ctx.request_id\n",
    )
    result = MCPScanner().scan(tmp_path)
    assert any(c.name == "notes" for c in result.components)
    assert result.surfaces_excluded == []


@pytest.mark.parametrize(
    ("imports", "argument"),
    [
        ("from local_types import ServerSession", "ServerSession"),
        ("from mcp import ServerSession\nServerSession = object()", "ServerSession"),
        ("from mcp import ServerSession", "ServerSession()"),
        ("from mcp import ServerSession", "ServerSession | FastMCP"),
    ],
)
def test_context_arguments_with_unknown_provenance_remain_visible(tmp_path, imports, argument):
    _write(
        tmp_path,
        "server.py",
        _SERVER
        + imports
        + "\n@server.tool()\n"
        + f"def notes(ctx: Context[{argument}, None]) -> str: return ctx.request_id\n",
    )
    result = MCPScanner().scan(tmp_path)
    assert (
        "server.py: Python MCP server reachable through a request context"
        in result.surfaces_excluded
    )


def test_checkout_sdk_request_type_does_not_get_the_installed_type_exemption(tmp_path):
    _write(tmp_path, "starlette/__init__.py", "")
    _write(tmp_path, "starlette/requests.py", "class Request: pass\n")
    _write(
        tmp_path,
        "server.py",
        _SERVER + "from starlette.requests import Request\n"
        "@server.tool()\ndef notes(ctx: Context[None, Request]) -> str: return ctx.request_id\n",
    )
    result = MCPScanner().scan(tmp_path)
    assert (
        "server.py: Python MCP server reachable through a request context"
        in result.surfaces_excluded
    )


@pytest.mark.parametrize("assignments", [1, 30])
def test_plain_sibling_evidence_respects_the_python_node_budget(tmp_path, assignments):
    _write(tmp_path, "worker/__init__.py", "")
    _write(tmp_path, "worker/mcp.py", "label = 'sample'\n" * assignments)
    _write(tmp_path, "worker/server.py", _SERVER + _TOOL)
    with limits.applied(replace(limits.DEFAULTS, python_nodes=65)):
        result = MCPScanner().scan(tmp_path)
    gap = "worker/server.py: Python SDK import may resolve to checkout code"
    assert (gap in result.surfaces_excluded) is (assignments == 30)
