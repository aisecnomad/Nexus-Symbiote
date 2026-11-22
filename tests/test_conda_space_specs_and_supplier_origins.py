"""Exercise supplier reconciliation with synthetic manifests and package records."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import RegistryEntryComponent
from nexus_symbiote.sbom_import import import_foreign_sbom
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV


def _supplier(path, name, version, purl=None):
    entry = {"type": "library", "name": name, "version": version}
    if purl:
        entry["purl"] = purl
    path.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [entry]}),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("spec", "supplied", "counts"),
    [
        ("2.1.0", "2.1.0", (0, 0)),
        ("2.1.0", "2.1.3", (1, 0)),
        ("2.1.*", "2.1.3", (0, 0)),
        ("2.1*", "2.1.3", (0, 0)),
        ("2.1*", "2.10.0", (1, 0)),
        ("2.1.*", "2.0.0", (1, 0)),
        ("2.1.0 py312_0", "2.1.0", (0, 1)),
        ("2.1.0 py312_0", "2.2.0", (1, 0)),
    ],
)
def test_conda_space_spec_through_risk_gate(tmp_path, spec, supplied, counts):
    project = tmp_path / "project"
    worker = project / "worker"
    worker.mkdir(parents=True)
    (project / "requirements.txt").write_text("openai==1.0.0\n", encoding="utf-8")
    (worker / "environment.yml").write_text(f'dependencies:\n  - "pytorch {spec}"\n')
    supplier = _supplier(tmp_path / "supplier.json", "pytorch", supplied)
    base = tmp_path / "base.json"
    result = tmp_path / "merged.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", str(project), "-o", str(base)])
    assert scan.exit_code == 0, scan.output
    imported = runner.invoke(
        main,
        [
            "import-sbom",
            str(supplier),
            "--into",
            str(base),
            "--project",
            str(project),
            "--walk-manifests",
            "--json-output",
            "-o",
            str(result),
        ],
    )
    assert imported.exit_code == 0, imported.output
    summary = json.loads(imported.stdout)
    assert (summary["conflict_count"], summary["unresolved_conflict_count"]) == counts
    risk = runner.invoke(
        main, ["risk", str(result), "--no-project-policy", "--fail-on-severity", "medium"]
    )
    assert risk.exit_code == int(any(counts)), risk.output


@pytest.mark.parametrize(
    "query",
    [
        "repository_url=https://packages.example.test&repository_url=https://mirror.example.test",
        "repository_url=https://mirror.example.test&REPOSITORY_URL=https://packages.example.test",
        "broken",
        "=unassigned",
    ],
)
@pytest.mark.parametrize("ambiguous_first", [True, False])
def test_supplier_with_ambiguous_origin_is_order_independent(
    tmp_path, monkeypatch, query, ambiguous_first
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "r" * 40)
    stem = "pkg:npm/%40example/widget@1.2.3"
    ambiguous = _supplier(tmp_path / "ambiguous.json", "widget", "1.2.3", f"{stem}?{query}")
    known = _supplier(
        tmp_path / "known.json",
        "@example/widget",
        "1.2.3",
        f"{stem}?repository_url=https://packages.example.test",
    )
    first, second = (ambiguous, known) if ambiguous_first else (known, ambiguous)
    hidden = AIBOM.model_validate_json(import_foreign_sbom(first).aibom.to_json())
    report = import_foreign_sbom(second, target_aibom=hidden)
    assert (report.conflict_count, report.unresolved_conflict_count) == (0, 1)
    displayed = import_foreign_sbom(ambiguous, reveal_names=True).aibom.components[-1]
    assert isinstance(displayed, RegistryEntryComponent)
    assert displayed.package_url is None


@pytest.mark.parametrize(
    ("ecosystem", "public"), [("npm", "https://registry.npmjs.org"), ("pypi", "https://pypi.org")]
)
@pytest.mark.parametrize(
    ("mode", "observed", "same_origin", "unresolved"),
    [
        ("lockfile-resolution-claim", True, False, 1),
        ("lockfile-resolution-claim", True, True, 0),
        ("lockfile-resolution-claim", False, False, 0),
        ("manifest-reference", True, False, 0),
    ],
)
def test_registry_comparison_uses_recorded_lock_origin(
    tmp_path, ecosystem, public, mode, observed, same_origin, unresolved
):
    stem = f"pkg:{ecosystem}/widget@1.2.3"
    local = RegistryEntryComponent(
        bom_ref="registry:widget",
        name="widget",
        version="1.2.3",
        registry_type=ecosystem,
        package_url=stem,
        registry_uri=public if observed else None,
        properties={"collection_mode": mode},
    )
    supplier_origin = public if same_origin else "https://packages.example.test"
    supplier = _supplier(
        tmp_path / "supplier.json", "widget", "1.2.3", f"{stem}?repository_url={supplier_origin}"
    )
    report = import_foreign_sbom(supplier, target_aibom=AIBOM(components=[local]))
    assert (report.conflict_count, report.unresolved_conflict_count) == (0, unresolved)
