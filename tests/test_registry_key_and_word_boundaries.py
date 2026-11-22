"""Registry identity and export checks using generated identifier suffixes."""

import hashlib
import json
import uuid

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.registry import _identifier
from nexus_symbiote.utils.secrets import holds_token_shape

HEX = hashlib.sha256(b"public boundary comparison").hexdigest()
LETTERS = "".join(chr(97 + int(c, 16)) for c in HEX)


@pytest.mark.parametrize("prefix", ["build", "x", "X", "release-2"])
@pytest.mark.parametrize(
    "parts",
    [
        ("or", "v1", HEX[:32]),
        ("lf", HEX[:32]),
        (HEX[:13], HEX[13:35]),
        (HEX[:12] + "_" + HEX[12:36],),
        ("opaque", HEX[:19]),
    ],
)
def test_glued_private_shapes_do_not_reach_registry_identity(prefix, parts):
    marker = "-".join(("sk", *parts))
    label = prefix + marker
    assert holds_token_shape(label, require_sk_boundary=True)
    shown, removed = _identifier(label)
    assert removed and marker not in shown


@pytest.mark.parametrize(
    "name",
    [
        "desk-admin-console-integration-tools",
        "risk-svcacct-rotation-helper-utilities",
        "kiosk-" + LETTERS[:32],
        "task-" + HEX[:32],
        "flask-sqlalchemy-2-0-compat",
        "task-runner-build-2024-01",
    ],
)
def test_complete_package_words_keep_identity_and_purl(tmp_path, name):
    package = "langchain-" + name
    assert _identifier(package) == (package, False)
    (tmp_path / "requirements.txt").write_text(package + "==1.2.0\n")
    report = tmp_path / "report.json"
    run = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--scanner", "registry", "--no-project-policy", "-o", str(report)],
    )
    assert report.is_file(), run.output
    records = json.loads(report.read_text())["components"]
    assert any(
        c.get("name") == package and package in (c.get("package_url") or "") for c in records
    )


@pytest.mark.parametrize("provider", ["or-v1", "lf"])
def test_specific_provider_shape_inside_a_package_word_stays_private(tmp_path, provider):
    marker = "-".join(("sk", provider, HEX[:36]))
    package = "langchain-ta" + marker
    (tmp_path / "requirements.txt").write_text(package + "==1.2.0\n")
    report = tmp_path / "report.json"
    check = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--scanner", "registry", "--no-project-policy", "-o", str(report)],
    )
    assert report.is_file(), check.output
    content = report.read_text()
    assert marker not in content and marker not in check.output
    assert "credential_exposure" in content


@pytest.mark.parametrize("kind", ["image", "version", "extra", "marker"])
@pytest.mark.parametrize("document", ["json", "cyclonedx", "spdx"])
@pytest.mark.parametrize("provider", ["or-v1", "lf"])
def test_glued_provider_values_stay_out_of_each_export(tmp_path, kind, document, provider):
    tail = HEX if provider == "or-v1" else str(uuid.UUID(hex=HEX[:32]))
    marker = "-".join(("sk", provider, tail))
    label = "build" + marker
    project = tmp_path / "project"
    project.mkdir()
    if kind == "image":
        digest = hashlib.sha256(b"generated registry image").hexdigest()
        (project / "docker-compose.yml").write_text(
            f"services:\n  service:\n    image: ghcr.io/example/vllm:{label}@sha256:{digest}\n"
        )
    elif kind == "version":
        version = "4.0.0-" + label
        (project / "package.json").write_text(json.dumps({"dependencies": {"openai": version}}))
        (project / "yarn.lock").write_text(
            f'# yarn lockfile v1\n\n"openai@{version}":\n  version "{version}"\n'
        )
    else:
        spec = (
            f"openai[{label}]==1.2.0" if kind == "extra" else f'openai==1.2.0; extra == "{label}"'
        )
        (project / "requirements.txt").write_text(spec + "\n")
    report = tmp_path / (document + ".json")
    run = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--scanner",
            "registry",
            "--no-project-policy",
            "-f",
            document,
            "-o",
            str(report),
        ],
    )
    assert report.is_file(), run.output
    assert marker not in report.read_text() and marker not in run.output
