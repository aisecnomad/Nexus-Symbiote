"""python-nodes: the operator limit on the syntax nodes the mcp collector analyses in one
Python file, the failure that names it, and the linear analysis it bounds."""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from tests.support import scaling_ratio

FACTORY = "from mcp.server.fastmcp import FastMCP\nserver = FastMCP('demo')\n"
# The size scanners/registry.py once had, which the fixed bound of earlier releases refused;
# the module has grown since, so this is a floor, not its current size.
REGISTRY_MODULE_NODES = 21_623
OVER_DEFAULT = "python-nodes limit of 200000 exceeded; raise it with --limit python-nodes=N"


def _nodes(source: str) -> int:
    return sum(1 for _ in ast.walk(ast.parse(source)))


def _ordinary(functions: int) -> str:
    """A generated module of ordinary code that names mcp only in a comment."""
    body = "".join(
        f"def handler_{index}(value: int, label: str = 'x') -> dict[str, int]:\n"
        "    result = {label: value * 2, 'other': len(label)}\n"
        "    for key in sorted(result):\n"
        "        if key.startswith('o') and value > 3:\n"
        "            result[key] += value\n"
        "    return result\n\n"
        for index in range(functions)
    )
    return "# Talks to the mcp gateway through a queue.\n" + body


def _dense(lines: int) -> str:
    """A server module whose body is one name per line: three syntax nodes per two bytes."""
    return FACTORY + "@server.tool()\ndef ping(): pass\n" + "x\n" * lines


def _project(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "AGENTS.md").write_text("Keep receipts.\n")
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _scan(project: Path, output: Path, *prefix: str, env: dict[str, str] | None = None):
    result = CliRunner().invoke(
        main, [*prefix, "scan", str(project), "--no-project-policy", "-o", str(output)], env=env
    )
    document = json.loads(output.read_text()) if output.exists() else {}
    return result, document


def _failures(document: dict) -> list[str]:
    failures: list[str] = document["metadata"]["completeness"]["scan_failures"]
    return failures


def test_the_default_is_documented_and_settable_only_as_a_count():
    assert limits.DEFAULTS.python_nodes == 200_000
    spec = limits.SPECS["python-nodes"]
    assert (spec.unit, spec.maximum) == ("count", 10_000_000)
    assert limits.parse_setting("python-nodes=400000") == ("python-nodes", 400_000)
    assert limits.parse_setting("Python_Nodes=1") == ("python-nodes", 1)
    for text, message in (
        ("python-nodes=0", "between 1 and 10000000"),
        ("python-nodes=10000001", "between 1 and 10000000"),
        ("python-nodes=1MiB", "python-nodes needs a whole number"),
        ("python-node=5", "did you mean python-nodes?"),
    ):
        with pytest.raises(limits.LimitError, match=message):
            limits.parse_setting(text)


def test_the_default_analyses_an_ordinary_module_above_the_old_fixed_bound(tmp_path):
    source = _ordinary(700)
    assert _nodes(source) > REGISTRY_MODULE_NODES
    assert len(source.encode()) < limits.DEFAULTS.syntax_bytes
    project = _project(tmp_path / "project", {"app/big.py": source})
    result, document = _scan(project, tmp_path / "out.json")
    assert result.exit_code == 0, result.output
    assert _failures(document) == []
    assert document["metadata"]["completeness"]["surfaces_excluded"] == []
    assert document["metadata"]["completeness"]["scanner_status"]["mcp"] == "complete"


def test_a_module_over_the_limit_is_a_failure_that_names_the_limit(tmp_path):
    project = _project(tmp_path / "project", {"app/big.py": _ordinary(700)})
    result, document = _scan(project, tmp_path / "out.json", "--limit", "python-nodes=20000")
    assert result.exit_code == 1
    assert _failures(document) == [
        "app/big.py: python-nodes limit of 20000 exceeded; raise it with --limit python-nodes=N"
    ]
    assert "python-nodes limit of 20000 exceeded" in result.output
    assert str(tmp_path) not in json.dumps(document["metadata"]["completeness"])


def test_a_dense_module_within_syntax_bytes_reaches_the_default(tmp_path):
    source = _dense(110_000)
    assert len(source.encode()) < limits.DEFAULTS.syntax_bytes
    assert _nodes(source) > limits.DEFAULTS.python_nodes
    project = _project(tmp_path / "project", {"server.py": source})
    result, document = _scan(project, tmp_path / "out.json")
    assert result.exit_code == 1
    assert _failures(document) == [f"server.py: {OVER_DEFAULT}"]
    # Nothing is collected from the file: no server, tool or launch gap.
    assert not [c for c in document["components"] if c.get("source_path") == "server.py"]


@pytest.mark.parametrize("how", ["option", "environment"])
def test_the_operator_raises_the_limit(tmp_path, how):
    project = _project(tmp_path / "project", {"server.py": _dense(110_000)})
    if how == "option":
        result, document = _scan(project, tmp_path / "out.json", "--limit", "python-nodes=400000")
    else:
        env = {limits.ENV_VAR: "python-nodes=400000"}
        result, document = _scan(project, tmp_path / "out.json", env=env)
    assert _failures(document) == []
    names = {(c["component_type"], c["name"]) for c in document["components"]}
    assert {("mcp-server", "demo"), ("tool", "ping")} <= names
    assert result.exit_code == 0, result.output


def test_nothing_in_the_checkout_raises_the_limit(tmp_path):
    project = _project(
        tmp_path / "project",
        {"server.py": _dense(110_000), ".env": f"{limits.ENV_VAR}=python-nodes=10000000\n"},
    )
    result, document = _scan(project, tmp_path / "out.json")
    assert result.exit_code == 1
    assert _failures(document) == [f"server.py: {OVER_DEFAULT}"]
    (project / ".nexus-symbiote.yaml").write_text("limits:\n  python-nodes: 10000000\n")
    refused = CliRunner().invoke(
        main, ["scan", str(project), "--accept-project-policy", "-o", str(tmp_path / "p.json")]
    )
    assert refused.exit_code == 1
    assert "invalid policy" in refused.output


def test_every_analysis_of_the_file_waits_for_the_bound(tmp_path):
    # A launched server is a gap once the file is analysed; past the bound only the
    # limit is reported, and the file is listed nowhere else.
    launch = (
        "from mcp import StdioServerParameters\n"
        "params = StdioServerParameters(command='npx', args=['-y', 'pkg'])\n"
    )
    source = launch + "x\n" * 200
    with limits.applied(replace(limits.DEFAULTS, python_nodes=_nodes(source))):
        analysed = MCPScanner().scan(_project(tmp_path / "a", {"server.py": source}))
    assert analysed.scan_failures == []
    assert any(gap.startswith("server.py: ") for gap in analysed.surfaces_excluded)
    with limits.applied(replace(limits.DEFAULTS, python_nodes=_nodes(source) - 1)):
        refused = MCPScanner().scan(_project(tmp_path / "b", {"server.py": source}))
    limit = f"python-nodes limit of {_nodes(source) - 1} exceeded"
    assert refused.scan_failures == [f"server.py: {limit}; raise it with --limit python-nodes=N"]
    assert refused.surfaces_excluded == []
    assert "server.py" not in refused.surfaces_scanned


def _helper_calls(scale: int) -> str:
    """A server passed to one large helper from many calls: quadratic when each call
    walks the helper again."""
    return (
        FACTORY
        + "def helper(s):\n"
        + "    s.run\n" * (1_500 * scale)
        + "helper(server)\n" * (1_500 * scale)
    )


def test_the_analysis_of_a_large_module_is_linear(tmp_path):
    generous = replace(limits.DEFAULTS, python_nodes=1_000_000, syntax_bytes=4 * limits.MIB)
    roots = {
        scale: _project(tmp_path / f"p{scale}", {"server.py": _helper_calls(scale)})
        for scale in (1, 4)
    }

    def run(scale: int) -> None:
        with limits.applied(generous):
            result = MCPScanner().scan(roots[scale])
        assert result.scan_failures == [] and result.surfaces_excluded == []

    assert scaling_ratio(run) < 8


@pytest.mark.parametrize(
    "helper, call, benign",
    [
        ("def run(app, /, *, host):\n    app.run(host=host)\n", "run(server, host='x')", True),
        ("def run(*, app):\n    return app.settings\n", "run(app=server)", True),
        ("def wire(*, app):\n    app.add_tool(f)\n", "wire(app=server)", False),
        ("def wire(app, /):\n    keep = app\n", "wire(server)", False),
        ("def wire(app):\n    app.run\n    del app\n", "wire(server)", False),
        ("def wire(a, b):\n    b.run()\n    a.add_tool(f)\n", "wire(server, server)", False),
        ("def wire(a, b):\n    a.run()\n    b.add_tool(f)\n", "wire(b=other, a=server)", True),
        ("def wire(app):\n    app.run()\n", "wire(other, server)", False),
        ("def serve(app):\n    return app.streamable_http_app()\n", "serve(server)", True),
        ("async def serve(app):\n    await app.run_stdio_async()\n", "serve(server)", True),
        ("def wire(app):\n    return app\n", "wire(server)", False),
        ("def wire(app):\n    yield app\n", "wire(server)", False),
        ("def wire(app):\n    return app.run\n", "wire(server)", False),
        ("def wire(app):\n    return lambda: app.run()\n", "wire(server)", False),
        (
            "def wire(app):\n    def later():\n        app.run()\n    return later\n",
            "wire(server)",
            False,
        ),
        ("def wire(app):\n    app.run()\n    return vars()\n", "wire(server)", False),
    ],
)
def test_helpers_are_judged_by_how_they_use_each_parameter(tmp_path, helper, call, benign):
    source = FACTORY + "other = object()\n" + helper + "\n".join([call] * 3) + "\n"
    result = MCPScanner().scan(_project(tmp_path / "p", {"server.py": source}))
    assert any(isinstance(c, MCPServerComponent) for c in result.components)
    assert not [c for c in result.components if isinstance(c, ToolComponent)]
    gap = "server.py: unsupported Python MCP binding or dynamic registration"
    assert (gap not in result.surfaces_excluded) is benign, result.surfaces_excluded
