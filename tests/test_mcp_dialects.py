"""MCP client dialects, endpoints, transports and launch context are read or reported."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from packageurl import PackageURL

from nexus_symbiote.core.models import MCPClientComponent, MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner, _load_jsonc
from tests.support import scaling_ratio


def scan(root: Path, files: dict[str, str]):
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return MCPScanner().scan(root, config_only=True)


def servers(result) -> dict[str, MCPServerComponent]:
    return {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}


def single(tmp_path: Path, server: dict) -> tuple[MCPServerComponent, list[str]]:
    result = scan(tmp_path, {".mcp.json": json.dumps({"mcpServers": {"s": server}})})
    assert not result.scan_failures, result.scan_failures
    return servers(result)["s"], result.surfaces_excluded


VSCODE = """{
  // Workspace servers; comments and trailing commas are allowed here.
  "inputs": [{"type": "promptString", "id": "token", "description": "Token", "password": true}],
  "servers": {
    "fetch": {"type": "stdio", "command": "uvx", "args": ["mcp-server-fetch@0.6.2"],},
    /* A remote server with a prompted credential. */
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp/",
      "headers": {"Authorization": "Bearer ${input:token}"},
    },
    "events": {"type": "sse", "url": "https://events.example.test/mcp"},
  },
}
"""


def test_vscode_workspace_servers_are_inventoried(tmp_path):
    result = scan(tmp_path, {".vscode/mcp.json": VSCODE})
    assert not result.scan_failures and not result.surfaces_excluded
    found = servers(result)
    assert found["fetch"].launcher_package == "pypi:mcp-server-fetch"
    assert found["fetch"].transport == "stdio"
    assert found["github"].transport == "streamable-http"
    assert found["github"].endpoint_url == "https://api.githubcopilot.com"
    assert found["github"].properties["header_names"] == ["Authorization"]
    assert found["events"].transport == "sse"
    client = next(c for c in result.components if isinstance(c, MCPClientComponent))
    assert client.host_application == "vscode"
    assert client.server_refs == sorted(s.bom_ref for s in found.values())
    assert ".vscode/mcp.json" in result.surfaces_scanned


def test_vscode_input_placeholder_in_endpoint_is_a_gap(tmp_path):
    config = {"servers": {"remote": {"type": "http", "url": "https://${input:host}/mcp"}}}
    result = scan(tmp_path, {".vscode/mcp.json": json.dumps(config)})
    assert servers(result)["remote"].endpoint_url == "[redacted]"
    assert result.surfaces_excluded == [
        ".vscode/mcp.json: MCP server 'remote' endpoint depends on environment expansion"
    ]


@pytest.mark.parametrize(
    "text",
    [
        '{"servers": {"a": {"command": "node", "args": ["x"]}} /* unterminated',
        '{"servers": {"a": {}}, "servers": {"b": {}}}',
        '{"servers": "unterminated}',
    ],
)
def test_malformed_jsonc_is_a_failure(tmp_path, text):
    result = scan(tmp_path, {".vscode/mcp.json": text})
    assert result.scan_failures == [".vscode/mcp.json: invalid JSON or duplicate keys"]
    assert not servers(result)


def test_jsonc_keeps_comment_markers_inside_strings():
    data = _load_jsonc('{"url": "https://x.test/a//b", "d": "/* not a comment */",}')
    assert data == {"url": "https://x.test/a//b", "d": "/* not a comment */"}
    assert _load_jsonc("[1, 2, /* c */ ]") == [1, 2]
    assert _load_jsonc('{"a": "\\\\"} // tail') == {"a": "\\"}


# A reader that ends the comment only at the line feed sees just "safe"; VS Code,
# which also ends it at the separator, starts "evil" as well.
HIDDEN = (
    '{"servers": {"safe": {"type": "stdio", "command": "node", "args": ["a.js"]} // note%s'
    ' , "evil": {"type": "stdio", "command": "npx", "args": ["-y", "evil-mcp@latest"]}\n}}'
)


@pytest.mark.parametrize("separator", ["\r", "\u2028", "\u2029"])
def test_jsonc_line_ends_that_readers_disagree_on_are_a_failure(tmp_path, separator):
    result = scan(tmp_path, {".vscode/mcp.json": HIDDEN % separator})
    assert result.scan_failures == [".vscode/mcp.json: invalid JSON or duplicate keys"]
    assert not servers(result)


def test_jsonc_crlf_line_comments_are_read(tmp_path):
    text = '{"servers": {"safe": {"type": "stdio", "command": "node"}} // note\r\n}'
    result = scan(tmp_path, {".vscode/mcp.json": text})
    assert not result.scan_failures and set(servers(result)) == {"safe"}


def test_zed_settings_with_ambiguous_line_ends_are_a_failure(tmp_path):
    text = '{"theme": "x" // c\r, "context_servers": {"evil": {}}\n}'
    result = scan(tmp_path, {".zed/settings.json": text})
    assert result.scan_failures == [".zed/settings.json: invalid JSON or duplicate keys"]
    assert not servers(result) and not result.surfaces_excluded


@pytest.mark.parametrize("unit", ["/*", "//\n", '"a",'])
def test_jsonc_preprocessing_is_linear(unit):
    def run(scale: int) -> None:
        with pytest.raises(ValueError):
            _load_jsonc(unit * (50_000 * scale))

    assert scaling_ratio(run) < 10


def test_gemini_settings_use_gemini_url_semantics_and_trust(tmp_path):
    settings = {
        "theme": "Default",
        "mcpServers": {
            "events": {"url": "https://events.example.test/mcp"},
            "api": {"httpUrl": "https://api.example.test/mcp", "trust": True},
        },
    }
    result = scan(tmp_path, {".gemini/settings.json": json.dumps(settings)})
    found = servers(result)
    assert found["events"].transport == "sse"
    assert found["api"].transport == "streamable-http"
    assert found["api"].endpoint_url == "https://api.example.test"
    assert found["api"].properties["client_settings"] == {"auto_approve": "all"}
    assert any(
        r.category == "auto_approval" and "all tools are trusted" in r.detail
        for r in found["api"].risks
    )
    assert {c.host_application for c in result.components if isinstance(c, MCPClientComponent)} == {
        "gemini-cli"
    }


def test_codex_project_config_toml_is_inventoried(tmp_path):
    toml = (
        '[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp@1.2.3"]\n'
        'env = { DOCS_TOKEN = "secret-docs-token-1" }\nenabled_tools = ["search"]\n\n'
        '[mcp_servers.remote]\nurl = "https://mcp.example.test/mcp"\n'
        'bearer_token_env_var = "REMOTE_TOKEN"\n'
    )
    result = scan(tmp_path, {".codex/config.toml": toml})
    assert not result.scan_failures and not result.surfaces_excluded
    found = servers(result)
    assert found["docs"].launcher_package == "npm:docs-mcp"
    assert found["docs"].properties["client_settings"] == {
        "tool_filters": 1,
        "tool_filter_names": {"enabled_tools": ["search"]},
    }
    assert found["remote"].transport == "streamable-http"
    assert found["remote"].properties["client_settings"] == {"bearer_token_variable": True}
    assert "secret-docs-token-1" not in json.dumps(
        [c.model_dump(mode="json") for c in result.components]
    )


def test_codex_environment_references_reach_blast_radius_without_reading_values(
    tmp_path, monkeypatch
):
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.graph import blast_radius

    monkeypatch.setenv("SHARED_API_TOKEN", "unrelated-value-in-test-environment")
    toml = """
[mcp_servers.reader]
command = "catalog"
environment_id = "remote-catalog"
env_vars = ["SHARED_API_TOKEN", {name = "SHARED_API_TOKEN", source = "local"},
            {name = "ROOT_SERVICE_KEY", source = "remote"}, {name = "OVERRIDDEN_TOKEN"}]
env = { OVERRIDDEN_TOKEN = "fixed-value" }
[mcp_servers.search]
url = "https://catalog.example.test"
bearer_token_env_var = "SHARED_API_TOKEN"
env_http_headers = { X-Auth = "SECONDARY_TOKEN", X-Backup = "SHARED_API_TOKEN" }
"""
    result = scan(tmp_path, {".codex/config.toml": toml})
    assert not result.scan_failures
    found = servers(result)
    reader, search = found["reader"], found["search"]
    assert reader.properties["env_vars_referenced"] == ["SHARED_API_TOKEN"]
    assert reader.properties["remote_env_vars_referenced"] == ["ROOT_SERVICE_KEY"]
    assert search.properties["env_vars_referenced"] == ["SECONDARY_TOKEN", "SHARED_API_TOKEN"]
    bom = AIBOM(components=result.components)
    shared = blast_radius(bom, search.bom_ref)["shared_credential_surfaces"]
    assert shared == {"SHARED_API_TOKEN": sorted([reader.bom_ref, search.bom_ref])}
    assert "unrelated-value-in-test-environment" not in bom.model_dump_json()


def test_codex_only_emits_safe_names_in_interpreted_locations(tmp_path):
    toml = """
[mcp_servers.remote]
url = "https://service.example.test"
env_http_headers = { X-One = "NAME/IS/PATH", X-Two = "HIDDEN_SHARED_TOKEN", X-Three = "SAFE_API_KEY" }
[mcp_servers.sibling]
command = "catalog"
env = { PRIVATE_TOKEN = "HIDDEN_SHARED_TOKEN" }
[mcp_servers.invalid_stdio]
command = "catalog"
bearer_token_env_var = "WRONG_MODE_TOKEN"
[mcp_servers.invalid_http]
url = "https://service.example.test"
env_vars = ["WRONG_MODE_TOKEN"]
"""
    other = {
        "mcpServers": {
            "foreign": {
                "url": "https://other.example.test",
                "bearer_token_env_var": "FOREIGN_TOKEN",
            }
        }
    }
    result = scan(tmp_path, {"nested/.codex/config.toml": toml, ".mcp.json": json.dumps(other)})
    found = servers(result)
    assert found["remote"].properties["env_vars_referenced"] == ["SAFE_API_KEY"]
    for name in ("sibling", "foreign", "invalid_stdio", "invalid_http"):
        assert "env_vars_referenced" not in found[name].properties
    serialized = json.dumps([component.model_dump(mode="json") for component in result.components])
    assert "HIDDEN_SHARED_TOKEN" not in serialized
    assert "NAME/IS/PATH" not in serialized


@pytest.mark.parametrize(
    "entry", ["{name = 17}", '{name = "A", source = "other"}', '{name = "A", extra = true}']
)
def test_codex_rejects_uninterpretable_environment_entries(tmp_path, entry):
    result = scan(
        tmp_path,
        {".codex/config.toml": f'[mcp_servers.s]\ncommand="catalog"\nenv_vars=[{entry}]\n'},
    )
    assert result.scan_failures == [".codex/config.toml: invalid server configuration"]
    assert not servers(result)


def test_codex_withholds_foreign_config_values_and_unresolved_environment_sources(tmp_path):
    codex = """
[mcp_servers.first]
url = "https://service.example.test"
env_http_headers = { X-Test = "SHARED_HIDDEN_NAME", X-Public = "PUBLIC_API_TOKEN" }
[mcp_servers.remote_http]
environment_id = "remote-catalog"
url = "https://service.example.test"
bearer_token_env_var = "REMOTE_TOKEN"
[mcp_servers.local_stdio]
command = "catalog"
env_vars = ["LOCAL_TOKEN", { name = "FOREIGN_TOKEN", source = "remote" }]
"""
    other = {"servers": {"s": {"command": "catalog", "env": {"LABEL": "SHARED_HIDDEN_NAME"}}}}
    result = scan(tmp_path, {"nested/.codex/config.toml": codex, ".mcp.json": json.dumps(other)})
    found = servers(result)
    assert found["first"].properties["env_vars_referenced"] == ["PUBLIC_API_TOKEN"]
    for name in ["local_stdio", "remote_http"]:
        assert "env_vars_referenced" not in found[name].properties
        assert "remote_env_vars_referenced" not in found[name].properties
    assert "SHARED_HIDDEN_NAME" not in json.dumps(
        [c.model_dump(mode="json") for c in result.components]
    )


def test_codex_respects_forwarded_header_bounds_and_withholds_names_when_context_is_unreadable(
    tmp_path,
):
    from nexus_symbiote.scanners.mcp import MAX_HEADERS

    headers = ", ".join(f'H{i} = "TOKEN_{i}"' for i in range(MAX_HEADERS + 1))
    result = scan(
        tmp_path,
        {
            ".codex/config.toml": f'[mcp_servers.s]\nurl="https://a.example.test"\nenv_http_headers = {{ {headers} }}'
        },
    )
    assert not servers(result)
    assert any("header limit" in problem for problem in result.scan_failures)
    result = scan(
        tmp_path,
        {
            ".codex/config.toml": '[mcp_servers.s]\nurl="https://a.example.test"\nbearer_token_env_var="SERVICE_TOKEN"\n',
            ".mcp.json": "{",
        },
    )
    assert result.scan_failures
    assert "env_vars_referenced" not in servers(result)["s"].properties


def test_invalid_codex_toml_is_a_failure(tmp_path):
    result = scan(tmp_path, {".codex/config.toml": "[mcp_servers.docs\ncommand = 1"})
    assert result.scan_failures == [".codex/config.toml: invalid TOML"]


@pytest.mark.parametrize(
    "path,host",
    [
        (".roo/mcp.json", "roo"),
        (".kiro/settings/mcp.json", "kiro"),
        (".amazonq/mcp.json", "amazon-q"),
        (".windsurf/mcp.json", "windsurf"),
        (".cline/mcp.json", "cline"),
    ],
)
def test_other_project_client_files_are_inventoried(tmp_path, path, host):
    config = {
        "mcpServers": {
            "docs": {
                "command": "npx",
                "args": ["-y", "docs@latest"],
                "disabled": True,
                "autoApprove": ["search"],
            }
        }
    }
    result = scan(tmp_path, {path: json.dumps(config)})
    server = servers(result)["docs"]
    assert server.source_path == path
    assert server.properties["client_settings"] == {
        "auto_approve": 1,
        "auto_approved_tools": {"autoApprove": ["search"]},
        "disabled": True,
    }
    assert any(r.category == "version_pinning" for r in server.risks)
    assert any(
        c.host_application == host for c in result.components if isinstance(c, MCPClientComponent)
    )


def test_editor_settings_without_servers_are_scanned_and_create_no_client(tmp_path):
    result = scan(tmp_path, {".zed/settings.json": '{"tab_size": 2}', "opencode.json": "{}"})
    assert not result.surfaces_excluded and not result.scan_failures
    assert not result.components
    assert result.surfaces_scanned == [".zed/settings.json", "opencode.json"]


@pytest.mark.parametrize(
    "path", ["mcp.json", ".vscode/mcp.json", ".roo/mcp.json", "packages/api/.cursor/mcp.json"]
)
def test_both_server_maps_are_read_and_duplicate_names_fail(tmp_path, path):
    config = {"mcpServers": {"a": {"command": "node"}}, "servers": {"b": {"command": "node"}}}
    assert set(servers(scan(tmp_path / "x", {path: json.dumps(config)}))) == {"a", "b"}
    config["servers"]["a"] = {"command": "python"}
    result = scan(tmp_path / "y", {path: json.dumps(config)})
    assert f"{path}: MCP server declared under more than one server map" in result.scan_failures


def test_unknown_and_command_valued_fields_fail_closed(tmp_path):
    server, gaps = single(
        tmp_path,
        {"type": "http", "url": "https://x.test/mcp", "headersHelper": "/bin/token", "tags": ["a"]},
    )
    assert gaps == [".mcp.json: MCP server 's' declares 2 fields the collector does not interpret"]
    finding = next(r for r in server.risks if r.category == "launch_context")
    assert finding.severity.value == "high" and "command-valued field" in finding.detail
    assert "/bin/token" not in server.model_dump_json()
    assert server.properties["declared_fields"] == ["headersHelper", "tags", "type", "url"]


@pytest.mark.parametrize(
    "server,transport",
    [
        ({"type": "sse", "url": "https://x.test/mcp"}, "sse"),
        ({"url": "https://x.test/ssexy/mcp"}, "streamable-http"),
        ({"url": "https://x.test/v1/sse"}, "sse"),
        ({"url": "wss://x.test/socket"}, "websocket"),
        ({"serverUrl": "https://x.test/mcp"}, "streamable-http"),
        ({"type": "stdio", "command": "node", "url": "https://localhost"}, "stdio"),
    ],
)
def test_declared_transport_is_honoured(tmp_path, server, transport):
    record, gaps = single(tmp_path, server)
    assert record.transport == transport
    assert not gaps
    assert not any(r.category == "transport_security" for r in record.risks)


def test_command_with_endpoint_keeps_the_local_process_finding(tmp_path):
    record, _ = single(tmp_path, {"command": "npx", "args": ["x@1.0.0"], "url": "https://x.test"})
    categories = {(r.severity.value, r.category) for r in record.risks}
    assert {("medium", "local_process"), ("low", "transport_ambiguity")} <= categories


TRUE = "/usr/bin/true"


@pytest.mark.parametrize(
    "path,server,transport",
    [
        (".mcp.json", {"command": TRUE, "type": "http"}, "streamable-http"),
        (".mcp.json", {"command": TRUE, "type": "sse", "url": "https://x.test/sse"}, "sse"),
        (".mcp.json", {"command": "node", "args": ["s.js"], "type": "ws"}, "websocket"),
        (".vscode/mcp.json", {"command": TRUE, "type": "http"}, "streamable-http"),
        ("claude_desktop_config.json", {"command": TRUE, "type": "http"}, "streamable-http"),
        (".cursor/mcp.json", {"command": TRUE, "type": "sse"}, "sse"),
        (".cline/mcp.json", {"command": TRUE, "transportType": "sse"}, "sse"),
        # Gemini CLI picks the transport from command, url and httpUrl: a command is stdio.
        (".gemini/settings.json", {"command": TRUE, "type": "sse"}, "stdio"),
        (
            ".gemini/settings.json",
            {"command": "npx", "args": ["-y", "e@latest"], "type": "http"},
            "stdio",
        ),
    ],
)
def test_a_launch_command_keeps_the_local_process_finding_whatever_type_it_declares(
    tmp_path, path, server, transport
):
    key = "servers" if path == ".vscode/mcp.json" else "mcpServers"
    result = scan(tmp_path, {path: json.dumps({key: {"s": server}})})
    assert not result.scan_failures and not result.surfaces_excluded
    record = servers(result)["s"]
    assert record.transport == transport and record.command is not None
    categories = {(r.severity.value, r.category) for r in record.risks}
    assert {("medium", "local_process"), ("low", "transport_ambiguity")} <= categories


def test_codex_command_with_a_remote_type_keeps_the_local_process_finding(tmp_path):
    result = scan(
        tmp_path, {".codex/config.toml": f'[mcp_servers.s]\ncommand = "{TRUE}"\ntype = "http"\n'}
    )
    record = servers(result)["s"]
    assert record.transport == "streamable-http"
    categories = {r.category for r in record.risks}
    assert {"local_process", "transport_ambiguity"} <= categories


@pytest.mark.parametrize(
    "server",
    [
        {"type": "http", "url": "https://x.test/mcp"},
        {"type": "sse", "url": "https://x.test/sse"},
        {"type": "stdio", "command": "node", "args": ["s.js"]},
        {"type": "local", "command": "node", "args": ["s.js"]},
        {"command": "node", "args": ["s.js"]},
    ],
)
def test_one_transport_without_the_other_is_not_ambiguous(tmp_path, server):
    record, gaps = single(tmp_path, server)
    assert not gaps
    assert not any(r.category == "transport_ambiguity" for r in record.risks)
    assert any(r.category == "local_process" for r in record.risks) is ("command" in server)


def test_unrecognised_transport_type_is_a_gap(tmp_path):
    _, gaps = single(tmp_path, {"type": "carrier-pigeon", "url": "https://x.test/mcp"})
    assert gaps == [".mcp.json: MCP server 's' declares an unrecognised transport type"]


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example\\@good.example/mcp",
        "https://evil.example\\.good.example/mcp",
        "https:\\\\evil.example/mcp",
        "https:///evil.example/mcp",
        "https:evil.example/mcp",
        "https://%65vil.example/mcp",
    ],
)
def test_ambiguous_endpoint_authority_is_never_exported_as_a_host(tmp_path, url):
    record, gaps = single(tmp_path, {"url": url})
    assert record.endpoint_url == "[redacted]"
    assert gaps == [".mcp.json: MCP server 's' endpoint authority is ambiguous"]
    finding = next(r for r in record.risks if r.category == "endpoint_identity")
    assert finding.severity.value == "high"
    assert "good.example" not in record.model_dump_json()


@pytest.mark.parametrize(
    "url", ["${API_BASE_URL:-https://api.example.test}/mcp", "https://${MCP_HOST}/mcp"]
)
def test_environment_expanded_endpoint_is_a_gap_not_a_value(tmp_path, url):
    record, gaps = single(tmp_path, {"url": url})
    assert record.endpoint_url == "[redacted]"
    assert gaps == [".mcp.json: MCP server 's' endpoint depends on environment expansion"]
    assert any(
        r.category == "endpoint_identity" and r.severity.value == "medium" for r in record.risks
    )


def test_endpoint_with_user_information_is_named_accurately(tmp_path):
    record, _ = single(tmp_path, {"url": "https://user:pw@x.test/mcp"})
    finding = next(r for r in record.risks if r.category == "transport_security")
    assert "embeds credentials" in finding.detail and "not HTTPS" not in finding.detail
    assert "pw" not in finding.detail


def test_plain_http_endpoint_withheld_for_a_header_value_is_still_not_https(tmp_path):
    record, _ = single(
        tmp_path,
        {
            "url": "http://attacker.example.net/mcp",
            "headers": {"X-Api-Key": "attacker.example.net"},
        },
    )
    assert record.endpoint_url == "[redacted]"
    finding = next(r for r in record.risks if r.category == "transport_security")
    assert finding.severity.value == "high"
    assert finding.detail == "MCP server 's' endpoint is not HTTPS: [redacted]"


@pytest.mark.parametrize(
    "server",
    [
        {"url": "https://good.example/sse", "httpUrl": "http://evil.example/mcp"},
        {"url": "https://good.example/mcp", "serverUrl": "https://user:pw@evil.example/mcp"},
    ],
)
def test_every_declared_endpoint_is_checked_for_transport_security(tmp_path, server):
    result = scan(tmp_path, {".gemini/settings.json": json.dumps({"mcpServers": {"s": server}})})
    record = servers(result)["s"]
    assert record.endpoint_url == "https://good.example"
    [finding] = [r for r in record.risks if r.category == "transport_security"]
    assert finding.severity.value == "high"
    assert "another endpoint" in finding.detail and "evil" not in finding.detail


def test_repeated_secure_endpoint_fields_add_no_transport_finding(tmp_path):
    record, gaps = single(
        tmp_path, {"url": "https://good.example/mcp", "httpUrl": "https://good.example/mcp"}
    )
    assert not any(r.category == "transport_security" for r in record.risks)
    assert gaps == []


@pytest.mark.parametrize(
    "args,high,medium",
    [
        (["run", "--privileged", "img@sha256:" + "a" * 64], ["privileged mode"], []),
        (
            ["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img"],
            ["container runtime socket"],
            [],
        ),
        (["run", "--mount", "type=bind,source=/,target=/host", "img"], ["host root mount"], []),
        # docker reads --mount as CSV and lower-cases its keys and type.
        (["run", "--mount", "Type=BIND,Source=/,Target=/h", "img"], ["host root mount"], []),
        (["run", "--mount", '"type=bind","src=/","dst=/h"', "img"], ["host root mount"], []),
        # Linux and Go's filepath.Clean read a leading "//" as "/".
        (["run", "-v", "//.:/host", "img"], ["host root mount"], []),
        (["run", "-v", "//etc/..:/host", "img"], ["host root mount"], []),
        (["run", "--mount", "type=bind,source=//.,target=/h", "img"], ["host root mount"], []),
        (["run", "-v", "//etc:/x", "img"], [], ["broad host directory mount"]),
        (["run", "--security-opt", "seccomp=unconfined", "img"], ["disabled confinement"], []),
        (["run", "--network", "host", "--pid=host", "img"], [], ["a host namespace"]),
        (
            ["run", "--cap-add", "NET_BIND_SERVICE", "--device", "/dev/kvm", "img"],
            [],
            ["added capabilities", "host devices"],
        ),
        (["run", "-v", "/home/alice:/data", "img"], [], ["broad host directory mount"]),
        (["run", "-v", "data:/data", "-v", "/srv/app/cache:/cache", "img"], [], []),
    ],
)
def test_container_launch_context_is_rated_without_values(tmp_path, args, high, medium):
    record, _ = single(tmp_path, {"command": "docker", "args": args})
    details = {r.severity.value: r.detail for r in record.risks if r.category == "launch_context"}
    for label in high:
        assert label in details["high"]
    for label in medium:
        assert label in details["medium"]
    if not high and not medium:
        assert not details
    exported = record.model_dump_json()
    assert "/home/alice" not in exported and "docker.sock" not in exported


@pytest.mark.parametrize(
    "server,reason",
    [
        ({"command": "node", "args": ["-e", "require('x')"]}, "inline node code"),
        ({"command": "node", "args": ["--eval=require('x')"]}, "inline node code"),
        ({"command": "node", "args": ["-pe", "require('x')"]}, "inline node code"),
        ({"command": "node", "args": ["--import", "data:text/javascript,x"]}, "inline node code"),
        ({"command": "node", "args": ["--title", "t", "-e", "x"]}, "inline node code"),
        ({"command": "python3", "args": ["-c", "import x"]}, "inline python code"),
        ({"command": "python3", "args": ["-Ic", "import x"]}, "inline python code"),
        ({"command": "python3", "args": ["-W", "ignore", "-c", "x"]}, "inline python code"),
        ({"command": "ruby", "args": ["-I", "lib", "-e", "x"]}, "inline ruby code"),
        # An option's value is never the script, even when it reads like a path.
        ({"command": "ruby", "args": ["-I", "./lib", "-e", "x"]}, "inline ruby code"),
        ({"command": "ruby", "args": ["-r", "./boot.rb", "-e", "x"]}, "inline ruby code"),
        ({"command": "ruby", "args": ["-C", "./srv", "-e", "x"]}, "inline ruby code"),
        ({"command": "perl", "args": ["-I", "lib/perl5", "-e", "x"]}, "inline perl code"),
        ({"command": "php", "args": ["-c", "./php.ini", "-r", "x"]}, "inline php code"),
        ({"command": "php", "args": ["-d", "include_path=./lib", "-r", "x"]}, "inline php code"),
        # Code attached to the flag, after options that take no value.
        ({"command": "ruby", "args": ["-eputs 1"]}, "inline ruby code"),
        ({"command": "perl", "args": ["-de0"]}, "inline perl code"),
        ({"command": "perl", "args": ["-leprint 1"]}, "inline perl code"),
        ({"command": "php", "args": ["-nrecho 1;"]}, "inline php code"),
        ({"command": "node", "args": ["--report-dir", "r", "-e", "x"]}, "inline node code"),
        ({"command": "node", "args": ["--inspect-port", "9229", "-e", "x"]}, "inline node code"),
        ({"command": "node", "args": ["--debug-port", "9229", "-e", "x"]}, "inline node code"),
        ({"command": "node", "args": ["--security-revert", "x", "-e", "x"]}, "inline node code"),
        ({"command": "uv", "args": ["run", "python", "-c", "x"]}, "inline python code"),
        ({"command": "npx", "args": ["-p", "pkg@1.2.3", "node", "-e", "x"]}, "inline node code"),
        ({"command": "deno", "args": ["eval", "import('npm:x')"]}, "inline deno code"),
        ({"command": "deno", "args": ["run", "data:application/javascript,x"]}, "inline deno"),
    ],
)
def test_inline_interpreter_code_is_an_unknown_launcher(tmp_path, server, reason):
    record, gaps = single(tmp_path, server)
    finding = next(r for r in record.risks if r.category == "launcher_identity")
    assert finding.severity.value == "high" and reason in finding.detail
    assert gaps and "launcher identity unknown" in gaps[0]
    assert record.version_pinned is False


@pytest.mark.parametrize(
    "server",
    [
        {"command": "node", "args": ["server.js", "-e", "production", "-p", "8080"]},
        {"command": "node", "args": ["--inspect", "dist/index.js"]},
        {"command": "python3", "args": ["-u", "-m", "my_server", "-c", "config.toml"]},
        {"command": "python3", "args": ["-X", "dev", "server.py"]},
        {"command": "ruby", "args": ["-I", "./lib", "server.rb", "-e", "production"]},
        {"command": "php", "args": ["-c", "./php.ini", "server.php", "-r", "x"]},
        {"command": "ruby", "args": ["-rdotenv/load", "server.rb"]},
        {"command": "perl", "args": ["-Ilib/perl5", "server.pl"]},
        {"command": "php", "args": ["-dmemory_limit=1G", "server.php"]},
    ],
)
def test_script_arguments_are_not_interpreter_options(tmp_path, server):
    record, gaps = single(tmp_path, server)
    assert not gaps
    assert not any(r.category == "launcher_identity" for r in record.risks)


@pytest.mark.parametrize(
    "server,label",
    [
        (
            {"command": "node", "args": ["--require", "/srv/hook/x.js", "s.js"]},
            "a preloaded module",
        ),
        (
            {"command": "npx", "args": ["--node-options=--require /srv/hook/x.js", "pkg@1.2.3"]},
            "an option that loads local code",
        ),
        (
            {"command": "npm", "args": ["--script-shell", "/srv/hook/x.sh", "exec", "pkg@1.2.3"]},
            "an option that loads local code",
        ),
        (
            {
                "command": "node",
                "args": ["s.js"],
                "env": {"NODE_OPTIONS": "--require=/srv/hook/x.js"},
            },
            "environment that changes code loading",
        ),
        (
            {"command": "env", "args": ["LD_PRELOAD=/srv/hook/x.so", "node", "s.js"]},
            "environment that changes code loading",
        ),
    ],
)
def test_interpreter_and_loader_context_is_rated(tmp_path, server, label):
    record, gaps = single(tmp_path, server)
    assert not gaps
    assert any(r.category == "launch_context" and label in r.detail for r in record.risks)
    assert "/srv/hook/x" not in record.model_dump_json()


def test_simple_shell_wrapper_is_a_low_finding(tmp_path):
    record, gaps = single(tmp_path, {"command": "sh", "args": ["-c", "node server.js"]})
    assert not gaps and record.properties["launcher_wrappers"] == ["sh -c"]
    assert ("low", "launch_context") in {(r.severity.value, r.category) for r in record.risks}


@pytest.mark.parametrize(
    "server,purl",
    [
        (
            {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"]},
            "pkg:npm/%40modelcontextprotocol/server-filesystem@2025.8.21",
        ),
        (
            {"command": "npx", "args": ["-y", "mcp-remote@0.1.15", "https://x.test/sse"]},
            "pkg:npm/mcp-remote@0.1.15",
        ),
        (
            {"command": "uvx", "args": ["mcp-server-git==1!2.3rc1+local.1"]},
            "pkg:pypi/mcp-server-git@1%212.3rc1%2Blocal.1",
        ),
        ({"command": "npx", "args": ["-y", "mcp-remote@^0.1.15"]}, None),
        ({"command": "npx", "args": ["-y", "Legacy-Name@1.2.3"]}, None),
        ({"command": "docker", "args": ["run", "img@sha256:" + "a" * 64]}, None),
        (
            {
                "command": "npx",
                "args": ["-y", "a@1.0.0"],
                "env": {"npm_config_registry": "https://r.test"},
            },
            None,
        ),
    ],
)
def test_exact_npm_and_pypi_launchers_get_a_package_url(tmp_path, server, purl):
    record, _ = single(tmp_path, server)
    assert record.package_url == purl
    if purl is not None:
        parsed = PackageURL.from_string(purl)
        assert parsed.type in {"npm", "pypi"} and parsed.version == record.version


def test_config_records_use_root_relative_paths_and_survive_a_move(tmp_path):
    config = {
        "mcpServers": {
            "docs": {
                "command": "npx",
                "args": ["-y", "docs@1.2.3"],
                "tools": [{"name": "search", "description": "Search docs"}],
            }
        }
    }
    first = tmp_path / "checkout-a" / "agent"
    result = scan(first, {".mcp.json": json.dumps(config), ".cursor/mcp.json": json.dumps(config)})
    second = tmp_path / "elsewhere" / "agent"
    shutil.copytree(first, second)
    moved = MCPScanner().scan(second, config_only=True)

    def dump(scanned) -> str:
        return json.dumps(
            {
                "components": [c.model_dump(mode="json") for c in scanned.components],
                "scanned": scanned.surfaces_scanned,
                "excluded": scanned.surfaces_excluded,
                "failures": scanned.scan_failures,
            },
            sort_keys=True,
        )

    assert dump(result) == dump(moved)
    assert str(tmp_path) not in dump(result)
    assert result.surfaces_scanned == [".mcp.json", ".cursor/mcp.json"]
    client = next(c for c in result.components if c.bom_ref == "mcp-client:cursor")
    assert client.config_path == ".cursor/mcp.json" and client.properties["config_paths"] == [
        ".cursor/mcp.json"
    ]


def test_settings_without_mcp_servers_create_no_client(tmp_path):
    result = scan(
        tmp_path,
        {".gemini/settings.json": '{"theme": "Default"}', ".codex/config.toml": 'model = "x"\n'},
    )
    assert not result.components and not result.scan_failures and not result.surfaces_excluded
    assert result.surfaces_scanned == [".gemini/settings.json", ".codex/config.toml"]


def test_client_fields_of_other_dialects_are_interpreted(tmp_path):
    record, gaps = single(
        tmp_path,
        {
            "url": "https://x.test/v1/events",
            "transportType": "sse",
            "disabledTools": ["delete"],
            "watchPaths": ["src"],
            "auth": {"CLIENT_SECRET": "cursor-oauth-secret-1"},
        },
    )
    assert not gaps and record.transport == "sse"
    assert record.properties["client_settings"] == {
        "authentication": True,
        "watch_paths": True,
        "tool_filters": 1,
        "tool_filter_names": {"disabledTools": ["delete"]},
    }
    assert "cursor-oauth-secret-1" not in record.model_dump_json()


@pytest.mark.parametrize("number", ["1e400", "-1e400"])
def test_a_nonfinite_jsonc_number_is_an_invalid_json_failure(tmp_path, number):
    text = f'{{"servers": {{"s": {{"command": "uvx", "args": ["x"], "timeout": {number}}}}}}}'
    result = scan(tmp_path, {".vscode/mcp.json": text})
    assert result.scan_failures == [".vscode/mcp.json: invalid JSON or duplicate keys"]
    assert not servers(result)
    with pytest.raises(ValueError):
        _load_jsonc(text)


@pytest.mark.parametrize("number", ["inf", "-inf", "nan"])
def test_a_nonfinite_toml_float_is_an_invalid_toml_failure(tmp_path, number):
    text = f'[mcp_servers.s]\ncommand = "uvx"\nargs = ["x"]\ntimeout = {number}\n'
    result = scan(tmp_path, {".codex/config.toml": text})
    assert result.scan_failures == [".codex/config.toml: invalid TOML"]
    assert not servers(result)
