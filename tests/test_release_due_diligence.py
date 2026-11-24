"""Regressions found by the 0.1.0 pre-publication review."""

from __future__ import annotations

import ast
import errno
import hashlib
import json
import os
import sys
import warnings
from pathlib import Path

import pytest
from click.testing import CliRunner
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import Specifier
from packaging.version import Version

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanners.base import parse_python
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.utils.crypto import SIGSTORE_MISSING
from nexus_symbiote.utils.files import OutputRefusedError, write_output_file
from tests.support import scaling_ratio

FORGED = "x\n::error file=README.md,line=1::forged by inventory\n\x1b[2J\x1b]8;;http://e/\x07"


def _injected(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.lstrip().startswith("::")]


@pytest.mark.parametrize("command", [["vex"], ["--live", "advisories"]])
def test_vex_and_advisories_do_not_echo_inventory_text(tmp_path, command):
    document = json.loads(AIBOM().to_json())
    document[FORGED] = 1
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(document))
    result = CliRunner().invoke(main, [*command, str(inventory)])
    assert result.exit_code == 1
    assert "is not a valid native AIBOM file" in result.output
    assert not _injected(result.output)
    assert "\x1b" not in result.output and "forged by inventory" not in result.output


def test_registry_reads_every_root_requirements_file_with_hash_continuations(tmp_path):
    (tmp_path / "requirements-gpu.txt").write_text(
        "torch==2.4.0 \\\n"
        "    --hash=sha256:" + "a" * 64 + " \\\n"
        "    --hash=sha256:" + "b" * 64 + "\n"
        "transformers==4.40.0 --hash=sha256:" + "c" * 64 + "  # pinned\n"
    )
    result = RegistryScanner().scan(tmp_path)
    versions = {c.name: c.version for c in result.components}
    assert versions == {"torch": "==2.4.0", "transformers": "==4.40.0"}
    assert result.scan_failures == []
    # Recorded relative to the scan root, so the same tree scans the same anywhere.
    assert "requirements-gpu.txt" in result.surfaces_scanned
    by_name = {c.name: c for c in result.components}
    assert by_name["torch"].properties["requirement_hashes"] == [
        f"requirements-gpu.txt: sha256:{'a' * 64}",
        f"requirements-gpu.txt: sha256:{'b' * 64}",
    ]


CONFLICT = "PyPI package '{}' is declared more than once with requirements that conflict."


def test_registry_keeps_one_component_per_package_across_requirements_files(tmp_path):
    (tmp_path / "AGENTS.md").write_text("Keep receipts.")
    (tmp_path / "requirements.txt").write_text(
        "openai==1.3.0\ntorch==2.3.0\ntransformers==4.40.0\nlangchain @ https://a.example/l.whl\n"
    )
    (tmp_path / "requirements-lock.txt").write_text(
        "openai==1.3.0\ntorch>=2\ntransformers<4.40\nlangchain==0.2.5\n"
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    by_name = {c.name: c for c in result.components}
    assert sorted(by_name) == ["langchain", "openai", "torch", "transformers"]
    assert str(by_name["openai"].source_path).endswith("requirements.txt")
    assert by_name["openai"].risks == []
    assert by_name["openai"].properties["declarations"] == [
        "requirements-lock.txt: openai==1.3.0",
        "requirements.txt: openai==1.3.0",
    ]
    # A range that the other file's pin satisfies is a compiled lock, not a conflict.
    assert by_name["torch"].version == "==2.3.0"
    assert by_name["torch"].risks == []
    assert by_name["torch"].properties["declarations"] == [
        "requirements-lock.txt: torch>=2",
        "requirements.txt: torch==2.3.0",
    ]
    for name in ("transformers", "langchain"):
        assert CONFLICT.format(name) in [r.detail for r in by_name[name].risks]
    scanned = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(tmp_path / "bom.json")]
    )
    assert "conflicting duplicate component" not in scanned.output


@pytest.mark.parametrize(
    ("one", "other", "conflict"),
    [
        ("torch==2.3.0", "torch==2.3", False),
        ("torch==2.3.0", "torch>=2.2,<2.4", False),
        ("torch>=2.2", "torch==2.3.0+cu121", False),
        ("torch==2.3.0 ; sys_platform == 'linux'", "torch==2.3.0", False),
        ("torch==2.3.0", "torch==2.3.0+cpu", False),
        ("torch==2.3.0", "torch===2.3.0+cpu", False),
        ("torch===2.3", "torch==2.3.0", False),
        ("torch===2.3.0-custom", "torch===2.3.0-custom", False),
        ("torch===foo", "torch", False),
        (
            "torch==2.2.2 ; platform_machine == 'x86_64'",
            "torch==2.5.1 ; sys_platform == 'linux'",
            False,
        ),
        ("torch==2.3.0,<3", "torch==2.3.1,<3", True),
        ("torch==1.8.0", "torch==1.8.0.post1", True),
        ("torch===foo", "torch>=1", True),
        ("torch[cuda]==2.3.0", "torch==2.3.0", False),
        ("torch>=2.2", "torch<2.2", False),
        ("torch", "torch==2.3.0", False),
        ("torch==2.3.0", "torch==2.2.2", True),
        ("torch==2.3.0+cpu", "torch==2.3.0+cu121", True),
        ("torch==2.1.0", "torch>=2.2", True),
        ("torch===2.3.0-custom", "torch==2.3.0", True),
        ("torch @ https://a.example/t.whl", "torch==2.3.0", True),
        ("torch @ https://a.example/t.whl", "torch @ https://b.example/t.whl", True),
        ("torch @ https://a.example/x.whl", "torch @ https://a.example/y.whl", False),
    ],
)
def test_only_declarations_that_cannot_both_hold_conflict(one, other, conflict):
    assert RegistryScanner._conflict(one, other) is conflict
    assert RegistryScanner._conflict(other, one) is conflict


@pytest.mark.parametrize(
    ("one", "other"),
    [
        ("torch===2.3.0-custom", "torch===2.3.0-custom"),
        ("torch===foo", "torch"),
        ("torch===foo", "torch>=1"),
        ("torch===foo", "torch==2.3.0"),
        ("torch===2.3", "torch==2.3.0"),
        ("torch==2.3.0", "torch==2.3.0+cpu"),
    ],
)
def test_conflicts_do_not_depend_on_the_packaging_release(monkeypatch, one, other):
    # packaging before 26 raises InvalidVersion for a version that is not PEP 440,
    # even against ===; the dependency range still allows it.
    native = RegistryScanner._conflict(one, other)
    original = Specifier.contains

    def strict(self, item, prereleases=None):
        Version(str(item))
        return original(self, item, prereleases=prereleases)

    monkeypatch.setattr(Specifier, "contains", strict)
    assert RegistryScanner._conflict(one, other) is native
    assert RegistryScanner._conflict(other, one) is native


def test_many_declarations_of_one_package_scan_in_linear_time(tmp_path):
    roots = {}
    for scale in (1, 4):
        lines = ["torch>=2.2"] * (1000 * scale) + [f"torch>=0.0.{i}" for i in range(1000 * scale)]
        lines += ["torch==2.3.0"] * (500 * scale)
        lines += [f'torch==2.{i}.0 ; python_version == "3.{i}"' for i in range(500 * scale)]
        roots[scale] = tmp_path / f"scale-{scale}"
        roots[scale].mkdir()
        (roots[scale] / "requirements.txt").write_text("\n".join(lines) + "\n")
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10
    (component,) = RegistryScanner().scan(roots[4]).components
    assert CONFLICT.format("torch") not in [r.detail for r in component.risks]
    assert len(component.properties["declarations"]) == 4002 + 2000


def test_a_quote_inside_a_direct_url_does_not_leave_its_tail_behind(tmp_path):
    (tmp_path / "AGENTS.md").write_text("Keep receipts.")
    (tmp_path / "requirements.txt").write_text(
        "torch @ https://files.example/t.whl'alice:PW3@other.example/secret-path\n"
        "torch @ https://files.example/u.whl ; sys_platform == 'linux'\n"
    )
    (component,) = RegistryScanner().scan(tmp_path).components
    assert component.version == "@ https://files.example"
    assert component.properties["requested_requirement"] == "torch @ https://files.example"
    runner = CliRunner()
    for fmt in ("json", "cyclonedx", "spdx"):
        out = tmp_path / f"{fmt}.json"
        scanned = runner.invoke(
            main,
            [
                "scan",
                str(tmp_path),
                "--no-project-policy",
                "--report-only",
                "-f",
                fmt,
                "-o",
                str(out),
            ],
        )
        assert scanned.exit_code == 0, scanned.output
        text = out.read_text(encoding="utf-8")
        assert "PW3" not in text and "secret-path" not in text and "alice" not in text


def _packaging_rejects_nbsp_url() -> bool:
    """Return True when the installed `packaging` rejects NBSP in PEP 508 URLs (>=26.4)."""
    try:
        Requirement("safetensors @ https://h.example/a\u00a0alice:S3CR1@o.example/S3CR2")
    except InvalidRequirement:
        return True
    return False


@pytest.mark.parametrize(
    ("files", "failures"),
    [
        # Unparseable (unquoted marker value): no URL boundary is known.
        (
            {
                "requirements.txt": "torch @ https://h.example/t.whl'alice:S3CR1@o.example/S3CR2"
                " ; python_version >= 3.8\n"
            },
            True,
        ),
        # A newly read file with the same line.
        (
            {
                "requirements.txt": "torch==2.3.0\n",
                "requirements-gpu.txt": "torch @ https://h.example/t.whl<alice:S3CR1@o/S3CR2> x\n",
            },
            True,
        ),
        # A Poetry value that is a URL.
        (
            {
                "pyproject.toml": "[tool.poetry.dependencies]\n"
                'torch = "https://alice:S3CR1@h.example/S3CR2/t.whl?sig=S3CR3"\n'
            },
            True,
        ),
        # pip keeps a no-break space inside a URL; so must the option splitting.
        (
            {
                "requirements.txt": "torch==2.3.0\n"
                "safetensors @ https://h.example/a\u00a0alice:S3CR1@o.example/S3CR2\n"
            },
            _packaging_rejects_nbsp_url(),
        ),
        # A scheme-relative URL.
        ({"requirements.txt": "openai @ //alice:S3CR1@h.example/S3CR2/o.whl\n"}, False),
        # A continuation that splits //: pip joins it into one credentialed URL.
        (
            {"requirements.txt": "torch @ git+https:/\\\n/ghp_S3CR1@github.com/org/S3CR2.git\n"},
            False,
        ),
        # An unparseable line whose first // is not right after the scheme.
        ({"requirements.txt": "torch==1.0 @ https:/alice:S3CR1@h.example/a//S3CR2.whl\n"}, True),
        # A URL inside a marker literal.
        (
            {
                "requirements.txt": "torch==2.3.0 ; platform_release == "
                '"https://h.example/x\'alice:S3CR1@o/S3CR2"\n'
            },
            False,
        ),
    ],
)
def test_no_url_tail_reaches_any_output(tmp_path, files, failures):
    (tmp_path / "AGENTS.md").write_text("Keep receipts.")
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    result = RegistryScanner().scan(tmp_path)
    assert bool(result.scan_failures) is failures, result.scan_failures
    runner = CliRunner()
    for fmt in ("json", "cyclonedx", "spdx"):
        out = tmp_path / f"{fmt}.json"
        scanned = runner.invoke(
            main,
            [
                "scan",
                str(tmp_path),
                "--no-project-policy",
                "--report-only",
                "-f",
                fmt,
                "-o",
                str(out),
            ],
        )
        assert scanned.exit_code == 0, scanned.output
        text = out.read_text(encoding="utf-8") + scanned.output
        assert not any(s in text for s in ("S3CR1", "S3CR2", "S3CR3", "alice")), fmt


# Each line a quarter of the length this test always used, times ``scale``.
_LONG_PINS = {
    # One long pin against many clauses, in one declaration.
    "long-release": lambda scale: (
        "torch=="
        + "1." * (7_500 * scale)
        + "1"
        + "".join(f",!=0.{i}" for i in range(5_000 * scale))
    ),
    # The same with a local label, whose comparison re-joins the label.
    "long-local-label": lambda scale: (
        "torch==1.0+"
        + "a." * (7_500 * scale)
        + "a"
        + "".join(f",!=0.{i}" for i in range(5_000 * scale))
    ),
}


@pytest.mark.parametrize("shape", sorted(_LONG_PINS))
def test_long_versions_do_not_make_the_comparison_quadratic(tmp_path, shape):
    roots = {}
    for scale in (1, 4):
        ranges = "".join(f"torch>=0.{i}\n" for i in range(5_000 * scale))
        roots[scale] = tmp_path / f"scale-{scale}"
        roots[scale].mkdir()
        (roots[scale] / "requirements.txt").write_text(_LONG_PINS[shape](scale) + "\n" + ranges)
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10
    (component,) = RegistryScanner().scan(roots[4]).components
    assert CONFLICT.format("torch") not in [r.detail for r in component.risks]


def test_optional_dependency_groups_are_not_compared_with_each_other(tmp_path):
    # uv's documented pattern: alternative local builds in conflicting extras.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "agent"\nversion = "0.1.0"\ndependencies = []\n'
        "[project.optional-dependencies]\n"
        'cpu = ["torch==2.3.0+cpu"]\n'
        'cu121 = ["torch==2.3.0+cu121"]\n'
        'dev = ["openai==1.30.0", "openai==1.31.0"]\n'
    )
    by_name = {c.name: c for c in RegistryScanner().scan(tmp_path).components}
    assert CONFLICT.format("torch") not in [r.detail for r in by_name["torch"].risks]
    assert CONFLICT.format("openai") in [r.detail for r in by_name["openai"].risks]


def test_a_pin_in_another_group_does_not_hide_a_conflict_within_a_group(tmp_path):
    # The same text in requirements.txt, read first, is still compared in the extra.
    (tmp_path / "requirements.txt").write_text("torch==2.0.0\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "agent"\nversion = "0.1.0"\ndependencies = []\n'
        "[project.optional-dependencies]\n"
        'gpu = ["torch==2.0.0", "torch==2.1.0"]\n'
    )
    (component,) = RegistryScanner().scan(tmp_path).components
    assert CONFLICT.format("torch") in [r.detail for r in component.risks]
    assert component.package_url is None


@pytest.mark.parametrize(
    "text",
    [
        # pip joins continued lines with nothing in between.
        "openai @ https://files.example/wheels/openai-1.0.0-py3-none-\\\nany.whl\n",
        "torch==2.3\\\n.0\n",
        # pip splits options on spaces only; a tab inside a marker literal stays.
        "torch==2.3.0 ; platform_version == '#1\t-SMP'\n",
    ],
)
def test_lines_pip_reads_as_valid_are_not_collection_failures(tmp_path, text):
    (tmp_path / "AGENTS.md").write_text("Keep receipts.")
    (tmp_path / "requirements.txt").write_text(text)
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    scanned = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(tmp_path / "bom.json")]
    )
    assert scanned.exit_code == 0, scanned.output


def test_requirements_files_share_one_size_budget(tmp_path, monkeypatch):
    # Every root requirements file is read, so their parsing time is bounded together.
    monkeypatch.setattr("nexus_symbiote.scanners.registry._REQUIREMENTS_BUDGET", 100)
    (tmp_path / "requirements.txt").write_text("openai==1.30.1\n" * 4)
    (tmp_path / "requirements-gpu.txt").write_text("torch==2.3.0\n" * 8)
    result = RegistryScanner().scan(tmp_path)
    assert [c.name for c in result.components] == ["openai"]
    assert result.scan_failures == [
        "requirements files exceed the combined size limit: the rest were not read"
    ]


def test_requirements_files_share_one_line_budget(tmp_path, monkeypatch):
    # Within the size budget, parsing time grows with the logical lines; many short
    # lines are bounded together the way the bytes are.
    monkeypatch.setattr("nexus_symbiote.scanners.registry._REQUIREMENTS_LINES", 10)
    (tmp_path / "requirements.txt").write_text("openai==1.30.1\n" * 4)
    (tmp_path / "requirements-gpu.txt").write_text("torch==2.3.0\n" * 8)
    result = RegistryScanner().scan(tmp_path)
    assert [c.name for c in result.components] == ["openai"]
    assert result.scan_failures == [
        "requirements files exceed the combined line limit: the rest were not read"
    ]


def test_a_pyproject_comment_is_not_compared(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "agent"\nversion = "0.1.0"\ndependencies = ["openai==1.3.0 # pinned"]\n'
    )
    (tmp_path / "requirements.txt").write_text("openai==1.3.0\n")
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    (component,) = result.components
    assert component.risks == []


def test_pins_in_a_lock_file_resolve_the_ranges_they_satisfy(tmp_path):
    # Main read only requirements.txt here and rated each of its seven ranges medium
    # (7 x 4 = 28), but rated the same ranges in pyproject.toml as resolved by these
    # pins. The rating now follows every declaration whichever file is read first:
    # an exact pin resolves the ranges it satisfies in any root file, so the gate
    # score is 0 and each pin is the package URL. docs/registry-collector.md states
    # that a pin in any file counts, including one in a file that is never installed.
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    pins = {
        "anthropic": ("0.34", "0.34.2"),
        "openai": ("1.40", "1.51.0"),
        "langchain": ("0.3", "0.3.3"),
        "langchain-anthropic": ("0.2", "0.2.3"),
        "chromadb": ("0.5", "0.5.11"),
        "transformers": ("4.40", "4.44.2"),
        "torch": ("2.2", "2.3.0"),
    }
    (project / "requirements.txt").write_text(
        "".join(f"{name}>={low}\n" for name, (low, _) in pins.items())
    )
    (project / "requirements-lock.txt").write_text(
        "".join(f"{name}=={pin}\n" for name, (_, pin) in pins.items())
    )
    runner = CliRunner()
    bom = tmp_path / "bom.json"
    scanned = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(bom)])
    assert scanned.exit_code == 0, scanned.output
    risk = runner.invoke(main, ["risk", str(bom), "--json-output"])
    assert risk.exit_code == 0, risk.output
    assert json.loads(risk.stdout)["overall_score"] == 0.0
    components = json.loads(bom.read_text())["components"]
    assert {c["name"]: c["package_url"] for c in components if c.get("registry_type")} == {
        name: f"pkg:pypi/{name}@{pin}" for name, (_, pin) in pins.items()
    }


def test_requirements_file_names_match_without_regard_to_case(tmp_path):
    # Main opened the fixed name requirements.txt, which macOS and Windows resolve
    # to Requirements.txt; the glob must not lose such a file on any platform.
    (tmp_path / "Requirements.txt").write_text("openai==1.30.1\n")
    (tmp_path / "REQUIREMENTS-GPU.TXT").write_text("torch==2.3.0\n")
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert {c.name: c.version for c in result.components} == {
        "openai": "==1.30.1",
        "torch": "==2.3.0",
    }


def test_the_exact_requirements_txt_is_kept_ahead_of_its_case_variants(tmp_path):
    # On a case-sensitive system pip and main read requirements.txt itself, so its
    # declaration is the component; a variant is recorded beside it.
    (tmp_path / "Requirements.txt").write_text("torch>=2\n")
    if (tmp_path / "requirements.txt").exists():
        pytest.skip("file system rejects distinct case spellings")
    (tmp_path / "requirements.txt").write_text("torch==2.3.0\n")
    try:
        (tmp_path / "requirement\u017f.txt").write_text("openai==1.30.1\n")
    except OSError:
        pytest.skip("file system rejects the name")
    by_name = {c.name: c for c in RegistryScanner().scan(tmp_path).components}
    assert by_name["torch"].source_path == "requirements.txt"
    assert by_name["torch"].version == "==2.3.0" and by_name["torch"].risks == []
    assert by_name["openai"].version == "==1.30.1"


def test_differing_declarations_in_one_requirements_file_get_one_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("torch==2.3.0\ntorch==2.2.2\ntorch==2.1.0\n")
    (component,) = RegistryScanner().scan(tmp_path).components
    details = [r.detail for r in component.risks]
    assert details.count(CONFLICT.format("torch")) == 1
    assert len(component.properties["declarations"]) == 3


@pytest.mark.parametrize(
    "content",
    [
        "-e .\n",
        "-e .[dev]\n",
        ".\n",
    ],
)
def test_lines_the_collector_does_not_follow_leave_the_default_gate_as_on_main(tmp_path, content):
    # The project's own install is covered by its pyproject.toml.
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / "requirements.txt").write_text("openai==1.3.0\n")
    (project / "requirements-dev.txt").write_text("\ufeff" + content)
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert [c.name for c in result.components] == ["openai"]
    scanned = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(tmp_path / "bom.json")]
    )
    assert scanned.exit_code == 0, scanned.output


@pytest.mark.parametrize(
    ("content", "gap"),
    [
        ("-c constraints.txt\n", "constraints file not followed"),
        ("-r requirements/base.txt\n", "requirements include not followed"),
        (
            "--index-url https://pypi.org/simple -r ../shared/ai.txt\n",
            "requirements include not followed",
        ),
        (
            "-e git+https://github.com/openai/openai-python@v1.3.0#egg=openai\n",
            "editable install not followed",
        ),
        ("-r 'unbalanced\n", "option line not parsed"),
        # pip installs these without a package name, so the collector names none.
        ("git+https://github.com/example/unknown\n", "URL, VCS or path requirement not followed"),
        (
            "https://files.example/python-dateutil-2.8.2.tar.gz\n",
            "URL, VCS or path requirement not followed",
        ),
        (
            "./wheels/openai-1.3.0-py3-none-any.whl\n",
            "URL, VCS or path requirement not followed",
        ),
    ],
)
def test_lines_that_pull_in_unread_packages_are_a_coverage_gap(tmp_path, content, gap):
    # These were skipped without a gap, so a dependency reached only through them was
    # missing while the collector reported complete coverage.
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / "requirements.txt").write_text("openai==1.3.0\n")
    (project / "requirements-dev.txt").write_text("\ufeff" + content)
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [f"requirements-dev.txt: {gap}"]
    assert result.scan_failures == []
    assert [c.name for c in result.components] == ["openai"]
    scanned = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(tmp_path / "bom.json")]
    )
    assert scanned.exit_code == 1, scanned.output


def test_pyproject_ranges_with_compiled_pins_leave_the_default_gate_as_on_main(tmp_path):
    # pip-tools and uv keep ranges in pyproject.toml and the pins that satisfy them
    # in requirements.txt. Main dropped the pyproject.toml declaration without a
    # finding; it is now recorded, and a satisfied range is not a conflict.
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"],
                    },
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"},
                    },
                    "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
                }
            }
        )
    )
    ranges = ["anthropic>=0.34", "openai>=1.40", "langchain>=0.3,<0.4", "chromadb>=0.5"]
    (project / "pyproject.toml").write_text(
        '[project]\nname = "agent"\nversion = "0.1.0"\ndependencies = '
        + json.dumps([*ranges, "langchain-anthropic>=0.2"])
        + '\n[project.optional-dependencies]\nfast = ["openai>=1.50"]\n'
    )
    (project / "requirements.txt").write_text(
        "anthropic==0.34.2\nopenai==1.51.0\nlangchain==0.3.3\n"
        "langchain-anthropic==0.2.3\nchromadb==0.5.11\n"
    )
    result = RegistryScanner().scan(project)
    assert result.scan_failures == []
    by_name = {c.name: c for c in result.components}
    assert all(c.risks == [] for c in by_name.values())
    assert by_name["openai"].version == "==1.51.0"
    assert by_name["openai"].properties["declarations"] == [
        "pyproject.toml: openai>=1.40",
        "pyproject.toml: openai>=1.50",
        "requirements.txt: openai==1.51.0",
    ]
    runner = CliRunner()
    bom = tmp_path / "bom.json"
    scanned = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(bom)])
    assert scanned.exit_code == 0, scanned.output
    assert runner.invoke(main, ["risk", str(bom)]).exit_code == 0


def test_a_pyproject_pin_that_contradicts_a_requirements_pin_is_a_conflict(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "agent"\nversion = "0.1.0"\n'
        'dependencies = ["openai==1.52.0", "anthropic>=0.30"]\n'
    )
    (tmp_path / "requirements.txt").write_text("openai==1.51.0\nanthropic==0.34.2\n")
    by_name = {c.name: c for c in RegistryScanner().scan(tmp_path).components}
    assert [r.detail for r in by_name["openai"].risks] == [CONFLICT.format("openai")]
    assert by_name["anthropic"].risks == []


def test_a_utf8_byte_order_mark_does_not_hide_the_first_requirement(tmp_path):
    (tmp_path / "requirements.txt").write_text("\ufeffopenai==1.3.0\n", encoding="utf-8")
    assert [c.name for c in RegistryScanner().scan(tmp_path).components] == ["openai"]


def test_a_changed_second_declaration_reaches_the_drift_gate(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / "requirements.txt").write_text("torch==2.3.0+cpu\n")
    gpu = project / "requirements-gpu.txt"
    gpu.write_text("torch==2.3.0+cu121\n")
    runner = CliRunner()
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    assert runner.invoke(main, [*args, str(tmp_path / "before.json")]).exit_code == 0
    gpu.write_text("torch @ https://attacker.example/torch-2.3.0-py3-none-any.whl\n")
    assert runner.invoke(main, [*args, str(tmp_path / "after.json")]).exit_code == 0
    drift = runner.invoke(
        main,
        ["diff", "--fail-on-alert", str(tmp_path / "before.json"), str(tmp_path / "after.json")],
    )
    assert drift.exit_code != 0, drift.output
    report = json.loads(
        runner.invoke(
            main,
            ["diff", "--json-output", str(tmp_path / "before.json"), str(tmp_path / "after.json")],
        ).output
    )
    assert [c["bom_ref"] for c in report["components_modified"]] == ["registry:pypi/torch"]
    assert any("torch" in json.dumps(alert) for alert in report["security_alerts"])


def test_vex_refuses_a_second_name_for_its_input(tmp_path, monkeypatch):
    inventory = tmp_path / "inv.json"
    inventory.write_text(AIBOM().to_json())
    original = inventory.read_bytes()
    (tmp_path / "alias.json").hardlink_to(inventory)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, ["vex", "inv.json", "-o", "alias.json"])
    assert result.exit_code == 2 and "must not overwrite the source inventory" in result.output
    assert inventory.read_bytes() == original


def test_init_refuses_a_symlinked_or_looping_path_without_a_traceback(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    (tmp_path / "loop").symlink_to(tmp_path / "loop")
    runner = CliRunner()
    for path in ("link", "loop"):
        result = runner.invoke(main, ["init", "--path", str(tmp_path / path)])
        assert result.exit_code == 1, result.output
        assert result.exception.__class__ is SystemExit
    assert not (tmp_path / "real" / ".nexus-symbiote.yaml").exists()
    created = runner.invoke(main, ["init", "--path", str(tmp_path / "real")])
    assert created.exit_code == 0 and (tmp_path / "real" / ".nexus-symbiote.yaml").exists()


def test_a_link_to_an_unreachable_target_is_replaced_not_refused(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (tmp_path / "regular").write_text("keep")
    (tmp_path / "dangling").symlink_to(tmp_path / "missing" / "bom.json")
    (tmp_path / "through-file").symlink_to(tmp_path / "regular" / "bom.json")
    runner = CliRunner()
    for name in ("dangling", "through-file"):
        result = runner.invoke(
            main,
            [
                "scan",
                str(project),
                "--no-project-policy",
                "--report-only",
                "-o",
                str(tmp_path / name),
            ],
        )
        assert result.exit_code == 0, result.output
        assert not (tmp_path / name).is_symlink()
    assert (tmp_path / "regular").read_text() == "keep"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_no_command_replaces_a_fifo_or_a_link_to_one(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    (tmp_path / "to-pipe").symlink_to(fifo)
    runner = CliRunner()
    for target in (fifo, tmp_path / "to-pipe"):
        result = runner.invoke(
            main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(target)]
        )
        assert result.exit_code == 1 and "Cannot write the output file" in result.output
    assert fifo.is_fifo() and (tmp_path / "to-pipe").is_symlink()


def test_output_parent_references_follow_the_kernel_and_never_a_link(tmp_path, monkeypatch):
    work = tmp_path / "work"
    (work / "real").mkdir(parents=True)
    (work / "link").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    (tmp_path / "elsewhere").mkdir()
    inventory = work / "inv.json"
    inventory.write_text(AIBOM().to_json())
    original = inventory.read_bytes()
    monkeypatch.chdir(work)
    runner = CliRunner()
    through_link = runner.invoke(main, ["vex", "inv.json", "-o", "link/../inv.json"])
    assert through_link.exit_code == 1
    assert "Cannot write the output file" in through_link.output
    same_file = runner.invoke(main, ["vex", "inv.json", "-o", "real/../inv.json"])
    assert (
        same_file.exit_code == 2 and "must not overwrite the source inventory" in same_file.output
    )
    assert inventory.read_bytes() == original
    (work / "loop").symlink_to(work / "loop")
    loop = runner.invoke(main, ["vex", "inv.json", "-o", "loop/vex.json"])
    assert loop.exit_code == 1 and "Traceback" not in loop.output
    assert loop.exception.__class__ is SystemExit
    beside = runner.invoke(main, ["vex", "inv.json", "-o", "real/../vex.json"])
    assert beside.exit_code == 0, beside.output
    assert (work / "vex.json").exists() and not list((tmp_path / "elsewhere").iterdir())


def test_baseline_and_import_refuse_unwritable_outputs_without_a_traceback(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    runner = CliRunner()
    baseline = runner.invoke(main, ["baseline", str(project), "-o", str(tmp_path / "no/b.json")])
    assert baseline.exit_code == 1 and "Cannot write the output file" in baseline.output
    assert baseline.exception.__class__ is SystemExit
    report = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
    imported = runner.invoke(main, ["import-shadowscan", str(report), "-o", "/", "--report-only"])
    assert imported.exit_code == 1 and "Cannot write the output file" in imported.output
    assert imported.exception.__class__ is SystemExit
    existing = tmp_path / "existing.json"
    existing.write_text("{}")
    again = runner.invoke(
        main, ["import-shadowscan", str(report), "-o", str(existing), "--report-only"]
    )
    assert again.exit_code == 1 and "choose a new output path" in again.output
    assert existing.read_text() == "{}"


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (PermissionError(errno.EACCES, "denied", "/private/x"), "file: Permission denied."),
        (OSError(errno.ENOSPC, "full", "/private/x"), "file: No space left on device."),
        (OSError(errno.ELOOP, "link", "/private/x"), "no directory on the path may be"),
        (
            OutputRefusedError(errno.EINVAL, "special", "/private/x"),
            "must not be a directory, device",
        ),
        (OSError(errno.EINVAL, "kernel", "/private/x"), "file: Invalid argument."),
        (ValueError("bad"), "its directory must exist"),
    ],
)
def test_an_unwritable_output_reports_its_reason_without_the_path(
    tmp_path, monkeypatch, error, message
):
    def refuse(*_args, **_kwargs):
        raise error

    monkeypatch.setattr("nexus_symbiote.utils.terminal.write_output_file", refuse)
    (tmp_path / "AGENTS.md").write_text("Keep receipts.")
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(tmp_path / "out.json")]
    )
    assert result.exit_code == 1 and result.exception.__class__ is SystemExit
    assert "Cannot write the output file" in result.output and message in result.output
    assert "/private/x" not in result.output


def test_a_requirements_file_with_an_undecodable_name_is_a_gap_not_a_crash(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / "requirements.txt").write_text("openai==1.40.0\n")
    undecodable = project / os.fsdecode(b"requirements-\xff.txt")
    try:
        undecodable.write_bytes(b"openai==1.41.0\n")
    except (OSError, UnicodeEncodeError):
        pytest.skip("file system rejects names that are not UTF-8")
    result = RegistryScanner().scan(project)
    assert result.scan_failures == ["requirements file with an unprintable name: not read"]
    assert [c.version for c in result.components] == ["==1.40.0"]
    runner = CliRunner()
    for fmt in ("json", "cyclonedx", "spdx"):
        out = tmp_path / f"{fmt}.json"
        scanned = runner.invoke(
            main,
            [
                "scan",
                str(project),
                "--no-project-policy",
                "--report-only",
                "-f",
                fmt,
                "-o",
                str(out),
            ],
        )
        assert scanned.exit_code == 0, scanned.output
        json.loads(out.read_text(encoding="utf-8"))


def test_a_cleanup_failure_does_not_replace_a_written_output(tmp_path, monkeypatch):
    # In an append-only directory the rename or link succeeds but the temporary
    # file cannot be removed; the output is written and no error is raised.
    def refuse(*_args, **_kwargs):
        raise PermissionError(errno.EPERM, "append-only")

    monkeypatch.setattr("nexus_symbiote.utils.files.os.unlink", refuse)
    for overwrite in (True, False):
        target = tmp_path / f"out-{overwrite}.json"
        write_output_file(target, "{}", overwrite=overwrite)
        assert target.read_text() == "{}"


@pytest.mark.parametrize(
    ("name", "read"),
    [
        ("requirements-\u00a0dev.txt", True),
        ("requirements-\u3000.txt", True),
        ("requirements-\x1b[2J.txt", False),
        ("requirements-\u202e.txt", False),
        ("requirements-\u200b.txt", False),
        ("requirements-\tdev.txt", False),
    ],
)
def test_only_names_that_disguise_output_are_refused(tmp_path, name, read):
    (tmp_path / "requirements.txt").write_text("openai==1.40.0\n")
    try:
        (tmp_path / name).write_text("torch==2.3.0\n")
    except OSError:
        pytest.skip("file system rejects the name")
    result = RegistryScanner().scan(tmp_path)
    assert ("torch" in [c.name for c in result.components]) is read
    expected = [] if read else ["requirements file with an unprintable name: not read"]
    assert result.scan_failures == expected


def test_output_paths_are_refused_cleanly_and_parent_references_resolve(tmp_path, monkeypatch):
    project = tmp_path / "work" / "project"
    project.mkdir(parents=True)
    (project / "AGENTS.md").write_text("Keep receipts.")
    (tmp_path / "real").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real")
    monkeypatch.chdir(project)
    runner = CliRunner()
    args = ["scan", ".", "--no-project-policy", "--report-only", "-o"]
    parent = runner.invoke(main, [*args, "../bom.json"])
    assert parent.exit_code == 0, parent.output
    assert AIBOM.load(tmp_path / "work" / "bom.json").components
    for refused in (tmp_path / "linked" / "bom.json", tmp_path / "missing" / "bom.json", tmp_path):
        result = runner.invoke(main, [*args, str(refused)])
        assert result.exit_code == 1
        assert "Cannot write the output file" in result.output
        assert "Traceback" not in result.output and result.exception.__class__ is SystemExit
    assert not (tmp_path / "real" / "bom.json").exists()


def test_missing_sigstore_is_not_reported_as_a_failed_signature(tmp_path, monkeypatch):
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"weights")
    bundle = tmp_path / "model.sigstore.json"
    bundle.write_text("{}")
    for name in [m for m in sys.modules if m == "sigstore" or m.startswith("sigstore.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "sigstore", None)
    result = CliRunner().invoke(
        main,
        [
            "verify-artifact",
            "model.bin",
            "--project",
            str(tmp_path),
            "--sha256",
            "sha256:" + hashlib.sha256(b"weights").hexdigest(),
            "--bundle",
            str(bundle),
            "--signer-identity",
            "release@example.com",
            "--issuer",
            "https://token.actions.githubusercontent.com",
        ],
    )
    assert result.exit_code == 1
    assert SIGSTORE_MISSING in result.output
    assert "signature or signer policy verification failed" not in result.output


def test_scanned_python_compiles_without_printing_its_bytes():
    source = 'value = "\\\x1b"\n'
    with warnings.catch_warnings(record=True) as unguarded:
        warnings.simplefilter("always")
        ast.parse(source)
    assert unguarded, "the interpreter no longer warns; this regression test needs updating"
    with warnings.catch_warnings(record=True) as guarded:
        warnings.simplefilter("always")
        assert isinstance(parse_python(source), ast.Module)
    assert guarded == []
