"""Exact pin claims follow each launcher's package grammar."""

from __future__ import annotations

import json

import pytest

from nexus_symbiote.core.hashing import extract_version_pin
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.mcp_launch import analyze


@pytest.mark.parametrize(
    "version",
    [
        "1",
        "1.2",
        "1.2.3",
        "1.2.3.4",
        "1.2.3rc1",
        "1.2.3.dev2",
        "1.2.3.post1",
        "1!2.3.4",
        "1.2.3+local.1",
        "1.2.3+local_1",
    ],
)
def test_finite_pep440_pins(version):
    for operator in ["=="] if "_" in version else ["==", "==="]:
        assert extract_version_pin("mcp-server-git" + operator + version) == version
        assert (
            extract_version_pin(
                "mcp-server-git[cli] " + operator + " " + version, ecosystem="python"
            )
            == version
        )


@pytest.mark.parametrize(
    "reference",
    [
        "pkg==1.2.*",
        "pkg>=1.2.3",
        "pkg~=1.2.3",
        "pkg!=1.2.3",
        "pkg==1.2.3,>=1",
        "pkg==1.2.3,==2.0.0",
        "pkg==1.2.3 || pkg==2.0.0",
        "pkg==1.2.3-unsupported",
        "pkg===arbitrary",
        "pkg===01.2.3",
        "pkg===v1.2.3",
        "pkg===1.2.3+local_1",
        'pkg==1.2.3; python_version>="3.11"',
        "pkg @ https://example.test/1.2.3/package.whl",
        "https://example.test/1.2.3/latest",
        "vendor/1.2.3/package",
        "registry.example.test/1.2.3/server:latest",
        "registry.example.test/1.2.3/server:nightly",
        "pkg@1.2",
        "pkg@^1.2.3",
        "pkg@~1.2.3",
        "pkg@1.2.3 || ^2.0.0",
        "pkg@1.2.3-01",
    ],
)
def test_ranges_ambiguous_references_and_url_digits_do_not_establish_pins(reference):
    assert extract_version_pin(reference) is None


@pytest.mark.parametrize(
    "reference,expected",
    [
        ("@scope/pkg@1.2.3", "1.2.3"),
        ("pkg@1.2.3-beta.1+build.2", "1.2.3-beta.1+build.2"),
        ("1.2.3", "1.2.3"),
        ("repo/image:1.2.3", "1.2.3"),
        ("registry.test:5000/repo/image:1.2", "1.2"),
        ("registry.test/repo@sha256:" + "AB" * 32, "sha256:" + "ab" * 32),
    ],
)
def test_existing_npm_semver_and_oci_forms(reference, expected):
    assert extract_version_pin(reference) == expected


@pytest.mark.parametrize(
    "command,args,expected",
    [
        ("uvx", ["mcp-server-git==0.6.2"], "0.6.2"),
        ("uvx", ["mcp-server-git==1!2.3rc1+local.1"], "1!2.3rc1+local.1"),
        ("uvx", ["mcp-server-git@0.6.2"], "0.6.2"),
        ("uvx", ["--from", "mcp-server-git==1.2.3.dev1", "mcp-server-git"], "1.2.3.dev1"),
        ("pipx", ["run", "mcp-server-git==1.2.3.post1"], "1.2.3.post1"),
        ("pipx", ["run", "--spec", "mcp-server-git[cli]==1.2.3", "mcp-server-git"], "1.2.3"),
        ("npx", ["-y", "@scope/server@1.2.3-beta.1"], "1.2.3-beta.1"),
        ("npx", ["server@^1.2.3"], None),
        ("npx", ["server@1.2.3 || ^2.0.0"], None),
        ("npx", ["server@1.2"], None),
        ("npx", ["1.2.3"], None),
        ("docker", ["run", "1.2.3"], None),
        ("uvx", ["mcp-server-git==1.2.*"], None),
        ("uvx", ["mcp-server-git==1.2.3,>=1"], None),
        ("pipx", ["run", "mcp-server-git>=1.2"], None),
        ("docker", ["run", "image@sha256:" + "AB" * 32], "sha256:" + "ab" * 32),
        ("docker", ["run", "image:1.4.2@sha256:" + "CD" * 32], "sha256:" + "cd" * 32),
        ("docker", ["run", "image/1.2.3/server:nightly"], None),
        ("docker", ["run", "image/1.2.3/server:latest"], None),
        ("docker", ["run", "--rm", "python:3"], None),
        ("docker", ["run", "--rm", "node:20"], None),
    ],
)
def test_real_mcp_launchers_preserve_only_exact_version_claims(tmp_path, command, args, expected):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"test": {"command": command, "args": args}}})
    )
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.version == expected
    assert server.version_pinned is (expected is not None)
    assert bool([r for r in server.risks if r.category == "version_pinning"]) is (expected is None)
    assert all(arg == "***" for arg in server.args)


DEEP_MARKER = "mcp-server-git==1.2.3;" + "(" * 2000


def test_a_deeply_nested_marker_is_no_pin():
    # packaging parses marker parentheses recursively and raises RecursionError.
    assert extract_version_pin(DEEP_MARKER, ecosystem="python") is None
    assert extract_version_pin(DEEP_MARKER) is None


@pytest.mark.parametrize(
    "image", ["registry.test:5000/image:1.2.3", "image:v2.0.1", "image:1.2.3-alpine"]
)
def test_release_tag_without_digest_is_a_mutable_reference_not_a_pin(tmp_path, image):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"test": {"command": "docker", "args": ["run", "--rm", image]}}})
    )
    server = next(
        c for c in MCPScanner().scan(tmp_path).components if isinstance(c, MCPServerComponent)
    )
    assert server.version == image.rsplit(":", 1)[1]
    assert server.version_pinned is False
    assert [(r.severity.value, r.category) for r in server.risks if "image" in r.detail] == [
        ("medium", "mutable_image_tag")
    ]


@pytest.mark.parametrize("command", ["uvx", "pipx run", "npx", "bunx", "docker run"])
def test_unknown_flags_do_not_reinterpret_following_secrets(command):
    words = command.split()
    launch = analyze(words[0], [*words[1:], "--password", "secret@1.2.3"])
    assert launch.unknown is not None
    assert not launch.packages
