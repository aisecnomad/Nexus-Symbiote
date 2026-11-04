"""Format checkers that are unsafe on received input stay out of core installs.

jsonschema imports every installed format checker and applies it wherever a schema
declares that format, including when check_schema() validates a schema against its
metaschema. These checkers must not come with the core dependencies, which the
GitHub Action's lock also installs. rfc3987-syntax checks each "iri-reference" with
an Earley parser that spends about half a millisecond of CPU and 16 KB of memory per
character, so one long IRI in a received export could exhaust the host. With
rfc3986-validator, a plain check_schema() asserts "uri-reference" on "$ref" and "$id",
so tool schemas are meta-validated with a checker limited to "regex" instead; otherwise
live discovery would refuse tool schemas that jsonschema resolves and the runtime
validation worker accepts. The GPL-licensed rfc3987 checks the same formats.

The behavioral tests run in a simulated core install: a subprocess that hides every
module that no core distribution provides.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import resource
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from jsonschema import FormatChecker
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from nexus_symbiote.runtime_validation import ValidationBudgetError, validate_arguments
from tests.test_ci_assurance import lock_entries

ROOT = Path(__file__).resolve().parents[1]
PYTHONS = ["3.11", "3.12", "3.13", "3.14"]
UNSAFE_CHECKERS = {"rfc3986-validator", "rfc3987", "rfc3987-syntax"}
# zod-to-json-schema 3.23.5 output for a zod object that reuses one address schema
# under two property names containing a space; it does not escape the $ref path.
ORDER_INPUT = {
    "type": "object",
    "properties": {
        "billing address": {
            "type": "object",
            "properties": {"city": {"type": "string"}, "country": {"type": "string"}},
            "required": ["city", "country"],
            "additionalProperties": False,
        },
        "shipping address": {"$ref": "#/properties/billing address"},
    },
    "required": ["billing address", "shipping address"],
    "additionalProperties": False,
    "$schema": "http://json-schema.org/draft-07/schema#",
}
TOOLS = [
    {"name": "create_order", "description": "Create an order", "inputSchema": ORDER_INPUT},
    {
        "name": "describe_city",
        "description": "Describe a city",
        "inputSchema": {
            "$id": "https://例え.jp/tool-input",
            "type": "object",
            "$defs": {"Città": {"type": "string"}, "My Model": {"type": "string"}},
            "properties": {
                "city": {"$ref": "#/$defs/Città"},
                "model": {"$ref": "#/$defs/My Model"},
            },
        },
    },
]
HIDE = "import json, sys\nfor name in json.loads(sys.argv[1]):\n    sys.modules[name] = None\n"
VERIFY_EXPORT = HIDE + (
    "import resource\n"
    "limit = 256 * 1024 * 1024\n"
    "resource.setrlimit(resource.RLIMIT_AS, (limit, limit))\n"
    "resource.setrlimit(resource.RLIMIT_CPU, (20, 20))\n"
    "from nexus_symbiote.cli import main\n"
    "main(['verify-export', sys.argv[2], '--format', 'cyclonedx'], prog_name='nexus-symbiote')\n"
)
DISCOVER = HIDE + (
    "from nexus_symbiote.core.aibom import AIBOM\n"
    "from nexus_symbiote.core.models import MCPServerComponent\n"
    "from nexus_symbiote.live import verify\n"
    "from nexus_symbiote.scanners.live_mcp import _tool\n"
    "tools = json.loads(sys.argv[2])\n"
    "discovered = [_tool(tool, []).name for tool in tools]\n"
    "verify.fetch_tools_from_config = lambda *args, **kwargs: ('stdio', tools)\n"
    "server = MCPServerComponent(bom_ref='mcp:orders', name='orders')\n"
    "report = verify.verify_mcp_servers(AIBOM(components=[server]))\n"
    "print(json.dumps([discovered, report.complete]))\n"
)


def core_distributions(python: str) -> set[str]:
    """Distributions a plain install resolves, including the extras it requests."""
    environment = default_environment()
    environment.update(python_version=python, python_full_version=python + ".0")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    pending = [(Requirement(text), "") for text in project["project"]["dependencies"]]
    expanded: set[tuple[str, str]] = set()
    while pending:
        requirement, extra = pending.pop()
        if requirement.marker and not requirement.marker.evaluate({**environment, "extra": extra}):
            continue
        name = canonicalize_name(requirement.name)
        for requested in ("", *requirement.extras):
            if (name, requested) not in expanded:
                expanded.add((name, requested))
                requires = importlib.metadata.distribution(name).requires or []
                pending.extend((Requirement(text), requested) for text in requires)
    return {name for name, _ in expanded}


def run_in_core_install(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    core = core_distributions(f"{sys.version_info.major}.{sys.version_info.minor}")
    core.add("nexus-symbiote")
    absent = [
        module
        for module, providers in importlib.metadata.packages_distributions().items()
        if not core & {canonicalize_name(name) for name in providers}
    ]
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", script, json.dumps(absent), *args],
        capture_output=True,
        text=True,
        env={"PATH": os.defpath},
        timeout=120,
        check=False,
    )


@pytest.mark.parametrize("python", PYTHONS)
def test_core_dependencies_leave_out_unsafe_format_checkers(python):
    unsafe = core_distributions(python) & UNSAFE_CHECKERS
    assert not unsafe, f"a core install would check formats with {sorted(unsafe)}"


def test_action_lock_installs_no_unsafe_format_checker():
    unsafe = lock_entries(ROOT / "requirements-action.lock").keys() & UNSAFE_CHECKERS
    assert not unsafe, f"requirements-action.lock installs {sorted(unsafe)}"


@pytest.mark.parametrize("python", PYTHONS)
def test_action_lock_pins_every_distribution_the_core_dependencies_resolve(python):
    missing = core_distributions(python) - lock_entries(ROOT / "requirements-action.lock").keys()
    assert not missing, f"requirements-action.lock lacks {sorted(missing)}"


def test_core_install_rejects_an_export_with_a_long_iri_in_bounded_cpu_and_memory(tmp_path):
    supplier = {"name": "Example", "url": ["https://example.test/" + "a" * 1024 * 1024]}
    document = {"bomFormat": "CycloneDX", "specVersion": "1.7", "metadata": {"supplier": supplier}}
    export = tmp_path / "received.cdx.json"
    export.write_text(json.dumps(document))
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = run_in_core_install(VERIFY_EXPORT, str(export))
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    assert (result.returncode, result.stderr) == (
        1,
        "Error: Export or embedded native inventory failed verification\n",
    )
    assert after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime < 5


def test_core_install_discovers_tool_schemas_whose_refs_jsonschema_resolves():
    result = run_in_core_install(DISCOVER, json.dumps(TOOLS))
    assert result.returncode == 0, result.stderr[-2000:]
    assert json.loads(result.stdout) == [["create_order", "describe_city"], True]


def test_runtime_worker_resolves_a_ref_that_is_not_a_uri_reference():
    address = {"city": "Lyon", "country": "FR"}
    validate_arguments(ORDER_INPUT, {"billing address": address, "shipping address": address})
    with pytest.raises(ValidationBudgetError):
        validate_arguments(
            ORDER_INPUT, {"billing address": address, "shipping address": {"city": "Lyon"}}
        )


@pytest.mark.skipif(
    "uri-reference" not in FormatChecker().checkers,
    reason="needs an install whose jsonschema asserts uri-reference, as the dev extras do",
)
def test_installed_format_checkers_do_not_refuse_tool_schemas(monkeypatch):
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.core.models import MCPServerComponent
    from nexus_symbiote.live import verify
    from nexus_symbiote.scanners.live_mcp import DiscoveryError, _tool

    assert [_tool(tool, []).name for tool in TOOLS] == ["create_order", "describe_city"]
    monkeypatch.setattr(verify, "fetch_tools_from_config", lambda *a, **k: ("stdio", TOOLS))
    server = MCPServerComponent(bom_ref="mcp:orders", name="orders")
    assert verify.verify_mcp_servers(AIBOM(components=[server])).complete is True
    bad_pattern = {"type": "object", "properties": {"q": {"type": "string", "pattern": "("}}}
    with pytest.raises(DiscoveryError):
        _tool({"name": "search", "inputSchema": bad_pattern}, [])
    bad_tool = {"name": "search", "inputSchema": bad_pattern}
    monkeypatch.setattr(verify, "fetch_tools_from_config", lambda *a, **k: ("stdio", [bad_tool]))
    assert verify.verify_mcp_servers(AIBOM(components=[server])).complete is False
