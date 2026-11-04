"""Export validation enforces the formats the pinned schemas declare, in every install.

jsonschema silently skips a "format" whose checker library is not installed, so those
libraries must come from the core dependencies rather than from an optional extra.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from jsonschema import FormatChecker
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from tests.test_ci_assurance import lock_entries

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "src/nexus_symbiote/generators/schemas/vendor"
PROBE = (
    "import json, sys\n"
    "for name in json.loads(sys.argv[1]):\n"
    "    sys.modules[name] = None\n"
    "from jsonschema import FormatChecker\n"
    "print(json.dumps(sorted(FormatChecker().checkers)))\n"
)


def declared_formats() -> set[str]:
    formats: set[str] = set()
    pending = [json.loads(path.read_text()) for path in VENDOR.glob("*/*.json")]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if isinstance(node.get("format"), str):
                formats.add(node["format"])
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return formats


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


def test_core_jsonschema_requirement_selects_non_gpl_checkers_for_every_format():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    requirements = map(Requirement, project["project"]["dependencies"])
    jsonschema = next(r for r in requirements if r.name == "jsonschema")
    # The "format" extra adds the GPL-licensed rfc3987. "format-nongpl" checks
    # iri and iri-reference only from jsonschema 4.25.0, through rfc3987-syntax.
    assert jsonschema.extras == {"format-nongpl"}
    assert list(jsonschema.specifier.filter(["4.23.0", "4.24.1", "4.25.0"])) == ["4.25.0"]


def test_format_checker_enforces_every_format_the_vendored_schemas_declare():
    formats = declared_formats()
    assert {"date-time", "iri-reference", "uri"} <= formats
    missing = formats - FormatChecker().checkers.keys()
    assert not missing, f"export validation would silently skip {sorted(missing)}"


def test_core_dependencies_alone_provide_every_declared_format_checker():
    core = core_distributions(f"{sys.version_info.major}.{sys.version_info.minor}")
    absent = [
        module
        for module, providers in importlib.metadata.packages_distributions().items()
        if not core & {canonicalize_name(name) for name in providers}
    ]
    probe = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", PROBE, json.dumps(absent)],
        capture_output=True,
        text=True,
        env={"PATH": os.defpath},
        timeout=60,
        check=True,
    )
    missing = declared_formats() - set(json.loads(probe.stdout))
    assert not missing, f"a core install would silently skip {sorted(missing)}"


@pytest.mark.parametrize("python", ["3.11", "3.12", "3.13", "3.14"])
def test_action_lock_pins_every_distribution_the_core_dependencies_resolve(python):
    missing = core_distributions(python) - lock_entries(ROOT / "requirements-action.lock").keys()
    assert not missing, f"requirements-action.lock lacks {sorted(missing)}"
