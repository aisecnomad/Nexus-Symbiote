"""The environment SBOM describes exactly what pip reports and validates against the schema."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus_symbiote.generators.validation import validate_cyclonedx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from environment_sbom import build_sbom  # noqa: E402

INSPECT = {
    "version": "1",
    "pip_version": "26.0",
    "environment": {"python_full_version": "3.12.13"},
    "installed": [
        {
            "metadata": {
                "name": "Nexus_Symbiote",
                "version": "0.1.0",
                "summary": "AgentBOM",
                "requires_dist": ["click<9,>=8.1", "sigstore>=4.4; extra == 'sigstore'"],
                "license_expression": "MIT AND Apache-2.0",
            }
        },
        {
            "metadata": {
                "name": "click",
                "version": "8.5.0",
                "classifier": ["License :: OSI Approved :: BSD License"],
            }
        },
    ],
}


def test_sbom_is_valid_deterministic_and_limited_to_installed_dependencies():
    when = datetime(2026, 11, 4, 21, 30, 8, tzinfo=UTC)
    first = build_sbom(INSPECT, timestamp=when)
    second = build_sbom(json.loads(json.dumps(INSPECT)), timestamp=when)
    assert first == second
    assert validate_cyclonedx(first) == []
    assert first["metadata"]["timestamp"] == "2026-11-04T21:30:08Z"
    refs = {c["bom-ref"] for c in first["components"]}
    assert refs == {"pkg:pypi/nexus-symbiote@0.1.0", "pkg:pypi/click@8.5.0"}
    edges = {d["ref"]: d["dependsOn"] for d in first["dependencies"]}
    assert edges["pkg:pypi/nexus-symbiote@0.1.0"] == ["pkg:pypi/click@8.5.0"]
    assert set(edges) == refs
    assert first["components"][1]["licenses"] == [{"expression": "MIT AND Apache-2.0"}]
    assert first["components"][0]["licenses"] == [
        {"license": {"name": "OSI Approved :: BSD License"}}
    ]


@pytest.mark.parametrize(
    "broken",
    [{"installed": "no"}, {"installed": [{"metadata": {"name": "a", "version": "1"}}] * 2}],
)
def test_malformed_or_duplicate_inventories_are_rejected(broken):
    with pytest.raises(ValueError):
        build_sbom(broken, timestamp=datetime.now(UTC))


def test_cli_writes_a_file_from_pip_inspect(tmp_path):
    source = tmp_path / "inspect.json"
    source.write_text(json.dumps(INSPECT))
    out = tmp_path / "environment.cdx.json"
    script = Path(__file__).resolve().parents[1] / "scripts" / "environment_sbom.py"
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(script), str(source), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
        env={
            "PATH": "",
            "SOURCE_DATE_EPOCH": "1793827808",
            "PYTHONPATH": str(script.parents[1] / "src"),
        },
    )
    assert completed.returncode == 0, completed.stderr
    document = json.loads(out.read_text())
    assert document["metadata"]["timestamp"] == "2026-11-04T21:30:08Z"
    assert validate_cyclonedx(document) == []
