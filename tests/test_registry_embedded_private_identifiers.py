"""Check exported registry evidence using generated, nonsecret fixture values."""

import hashlib
import json
import string

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.registry import _identifier
from nexus_symbiote.utils.secrets import holds_token_shape


def _sample(shape):
    digest = hashlib.sha256(b"public registry regression fixture").hexdigest()
    if shape == "lower":
        body = "".join(string.ascii_lowercase[int(ch, 16)] for ch in digest[:44])
    elif shape in ("admin", "svcacct", "proj"):
        body = shape + "-" + digest[:24]
    elif shape == "hex":
        body = digest[:32]
    else:
        body = digest[:48]
    return "sk" + "-" + body


@pytest.mark.parametrize("shape", ["hex", "legacy", "lower", "admin", "svcacct", "proj"])
@pytest.mark.parametrize("prefix", ["1", "sample_", "build"])
def test_private_shapes_are_withheld_at_each_identifier_boundary(shape, prefix):
    value = _sample(shape)
    assert holds_token_shape(prefix + value, require_sk_boundary=True)
    shown, removed = _identifier(prefix + value)
    assert removed and value not in shown


@pytest.mark.parametrize(
    "kind", ["image", "name", "extra", "marker", "version", "npm_name", "npm_alias"]
)
@pytest.mark.parametrize("shape", ["hex", "svcacct", "admin", "lower"])
def test_public_registry_scan_withholds_embedded_values(tmp_path, kind, shape):
    project = tmp_path / "project"
    project.mkdir()
    value = _sample(shape)
    label = ("1" if kind == "image" else "build") + value
    if kind == "image":
        digest = hashlib.sha256(b"synthetic image").hexdigest()
        (project / "docker-compose.yml").write_text(
            f"services:\n  inference:\n    image: ghcr.io/example/vllm:{label}@sha256:{digest}\n"
        )
    elif kind == "version":
        version = "4.0.0-" + label
        (project / "package.json").write_text(json.dumps({"dependencies": {"openai": version}}))
        (project / "yarn.lock").write_text(
            f'# yarn lockfile v1\n\n"openai@{version}":\n  version "{version}"\n'
        )
    elif kind == "npm_name":
        (project / "package.json").write_text(
            json.dumps({"dependencies": {f"langchain-{label}": "1.0.0"}})
        )
    elif kind == "npm_alias":
        (project / "package.json").write_text(
            json.dumps({"dependencies": {label: "npm:openai@1.0.0"}})
        )
    else:
        requirement = {
            "name": f"langchain-{label}==1.2.0",
            "extra": f"openai[{label}]==1.2.0",
            "marker": f'openai==1.2.0; extra == "{label}"',
        }[kind]
        (project / "requirements.txt").write_text(requirement + "\n")
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(
        main,
        ["scan", str(project), "--scanner", "registry", "--no-project-policy", "-o", str(output)],
    )
    assert output.is_file(), run.output
    text = output.read_text()
    assert value not in text and value not in run.output
    risks = [
        risk["category"] for c in json.loads(text)["components"] for risk in c.get("risks", [])
    ]
    assert "credential_exposure" in risks


@pytest.mark.parametrize(
    "name",
    [
        "flask-sqlalchemy-2-0-compat",
        "task-runner-v2-build-2024",
        "disk-management-service-v2",
        "mask-generation-tool-2024-11",
        "langchain-multitask-classifier-v12-release-2",
    ],
)
def test_plain_compound_names_keep_their_identity(name):
    assert not holds_token_shape(name, require_sk_boundary=True)
    assert _identifier(name) == (name, False)


@pytest.mark.parametrize("prefix", ["4", "_", "-"])
def test_a_shorter_segmented_candidate_after_a_nonletter_is_private(prefix):
    label = prefix + "-".join(("sk", "example", "fixture", "12345678"))
    assert holds_token_shape(label, require_sk_boundary=True)
    shown, removed = _identifier(label)
    assert removed and "12345678" not in shown
