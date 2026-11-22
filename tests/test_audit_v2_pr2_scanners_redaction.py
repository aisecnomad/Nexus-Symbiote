"""Adversarial regression tests for PR 2 scanner, redaction, and live MCP hardening."""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.core.models import (
    A2AServerComponent,
    IDEAgentComponent,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.base import sanitized_origin
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner, _broad_grants, _starting_mode_risk
from nexus_symbiote.scanners.live_mcp import (
    DiscoveryError,
    PinnedHTTPTransport,
    _local_pointer_exists,
    _resolve_public,
    check_served_tool,
)
from nexus_symbiote.scanners.mcp import (
    SOURCE_BINDING_KEY_ENV,
    MCPScanner,
    SourceBindingKeyError,
    _load_jsonc,
    source_binding_key,
    without_js_comments,
)
from nexus_symbiote.scanners.mcp_launch import analyze
from nexus_symbiote.scanners.model import ModelScanner, inspect_model_format, observe_model_artifact
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
from nexus_symbiote.scanners.source_binding import BindingError, origin, value_binding
from nexus_symbiote.utils.model_formats import template_escape_markers
from nexus_symbiote.utils.secrets import REDACTED, redact_metadata, redact_text, redact_url


def test_secrets_redaction_long_quoted_jwt_url_token_host_and_jwk_fields() -> None:
    long_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + ("A" * 600) + ".sig_part_12345"
    text = f'token="{long_jwt}"'
    scrubbed = redact_text(text)
    assert long_jwt not in scrubbed
    assert REDACTED in scrubbed

    # Space-containing >256-char non-token quoted secret pins the raised 8192-char _ASSIGNMENT bound
    long_spaced_secret = "word " * 80
    spaced_scrubbed = redact_text(f'password="{long_spaced_secret}"')
    assert "word word" not in spaced_scrubbed
    assert REDACTED in spaced_scrubbed

    gh_token = "ghp_" + ("A1b2C3d4E5f6" * 3)
    assert redact_url(f"https://{gh_token}.attacker.example/v1") == "[redacted-url]"
    assert sanitized_origin(f"https://{gh_token}.attacker.example/v1") == "[redacted]"
    assert sanitized_origin("https://bad\\host.example/v1") == "[redacted]"
    assert origin(f"//{gh_token}.attacker.example:8443/mcp") == "[redacted]"
    assert redact_url("https://api.openai.com/v1/models") == "https://api.openai.com"

    jwk_and_meta = {
        "jwk": {
            "kty": "RSA",
            "kid": "prod-key-1",
            "n": "publicModulusValue",
            "e": "AQAB",
            "d": "superSecretPrivateExponentValue12345",
            "p": "primeFactorOneValue",
            "oth": [{"r": "prime3"}],
            "dp": "",
        },
        "oauth": {
            "client_id": "public-client-id",
            "client_secret": "plainwordswithoutdigitsorshapesbutsecret",
            "endpoint": "https://oauth2.googleapis.com/token",
        },
    }
    redacted = redact_metadata(jwk_and_meta)
    assert redacted["jwk"]["n"] == "publicModulusValue"
    assert redacted["jwk"]["d"] == REDACTED
    assert redacted["jwk"]["p"] == REDACTED
    assert redacted["jwk"]["oth"] == REDACTED
    assert redacted["jwk"]["dp"] == ""
    assert redacted["oauth"]["client_id"] == "public-client-id"
    assert redacted["oauth"]["client_secret"] == REDACTED
    assert redacted["oauth"]["endpoint"] == "https://oauth2.googleapis.com"


def test_source_binding_surrogate_key_does_not_echo_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    canary_prefix = "operator_hmac_material_" + ("x" * 16)
    monkeypatch.setitem(
        os.environb,
        SOURCE_BINDING_KEY_ENV.encode("ascii"),
        canary_prefix.encode("ascii") + b"\xff",
    )

    with pytest.raises(SourceBindingKeyError) as mcp_exc:
        source_binding_key()
    assert canary_prefix not in str(mcp_exc.value)
    assert mcp_exc.value.__cause__ is None

    with pytest.raises(BindingError) as bind_exc:
        value_binding("nexus-symbiote/test/v1", {"url": "https://mcp.example.com"})
    assert canary_prefix not in str(bind_exc.value)
    assert bind_exc.value.__cause__ is None


def test_template_escape_markers_catch_pipe_attr_and_single_underscore_frames() -> None:
    assert template_escape_markers(b"{{ '' | attr }}")
    assert template_escape_markers(b"{{ '' | attr('class') }}")
    assert template_escape_markers(b"{{ cycler.next._globals.os }}")
    assert template_escape_markers(b"{{ namespace._builtins }}")
    assert template_escape_markers(b'{{ cycler.next["_" ~ "_globals_" ~ "_"] }}')
    assert template_escape_markers(b'{{ x[("_" ~ "_globals_" ~ "_")] }}')
    assert template_escape_markers(b'{{ x[("_") ~ ("_globals_") ~ ("_")] }}')
    assert template_escape_markers(b"{{ cycler.next['_' + '_class_' + '_'] }}")
    assert not template_escape_markers(b"{{ messages[0]['content'] | trim }}")
    assert not template_escape_markers(b"{{ message._init }}")


def test_mcp_launch_rejects_package_runner_shells_and_marks_uv_env_file() -> None:
    for shell_cmd in ("sh", "bash", "csh", "tcsh", "busybox", "toybox", "env"):
        verdict = analyze(
            "npx", ["-y", "--package", "@modelcontextprotocol/server-memory@0.6.2", shell_cmd]
        )
        assert verdict.unknown is not None

    single_package_shells = [
        ("npx", ["-y", "csh"]),
        ("npx", ["-y", "tcsh", "-c", "id"]),
        ("uvx", ["tcsh", "-c", "id"]),
        ("bunx", ["tcsh", "-c", "id"]),
        ("bunx", ["csh", "-c", "id"]),
        ("bunx", ["toybox", "sh"]),
        ("pnpm", ["dlx", "toybox", "sh"]),
        ("pnpm", ["dlx", "sh"]),
        ("yarn", ["dlx", "busybox", "sh"]),
    ]
    for cmd, args in single_package_shells:
        assert analyze(cmd, args).unknown is not None, (cmd, args)

    uv_env = analyze("uv", ["run", "--env-file", ".env.local", "--with", "mcp==1.2.0", "s.py"])
    assert uv_env.injected_environment is True


def test_mcp_jsonc_depth_nonfinite_float_js_comments_and_dup_tools(
    tmp_path: Path,
) -> None:
    deep = "[" * 300 + "]" * 300
    with pytest.raises(RecursionError, match="nesting limit"):
        _load_jsonc(deep)

    with pytest.raises(ValueError, match=r"nonfinite (?:JSON|number)"):
        _load_jsonc('{"timeout": 1e309}')

    assert _load_jsonc('{"timeout": 30.5 /* ok */}') == {"timeout": 30.5}

    code_with_string_comment = (
        'const open = "/*";\n'
        "const tpl = `multiline\n/* not a comment`;\n"
        "const x = 1; // https://example.com/*\n"
        'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
        "  // whole line comment across /*\n"
        'const close = "*/";\n'
        '/* real block comment */const trail = "http://example.com";\n'
    )
    stripped = without_js_comments(code_with_string_comment)
    assert "@modelcontextprotocol/sdk/client/index.js" in stripped
    assert "whole line comment" not in stripped
    assert "real block comment" not in stripped
    assert 'const trail = "http://example.com";' in stripped

    # Nested .gemini/settings.json and duplicate static tool names
    nested_gemini = tmp_path / "packages" / "sub" / ".gemini"
    nested_gemini.mkdir(parents=True)
    (nested_gemini / "settings.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "nested-srv": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-memory@0.6.2"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    dup_cfg = tmp_path / ".mcp.json"
    dup_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "dup-srv": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-memory@0.6.2"],
                        "tools": [
                            {"name": "ping", "description": "first"},
                            {"name": "ping", "description": "second"},
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    scan_res = MCPScanner().scan(tmp_path)
    servers = [c for c in scan_res.components if isinstance(c, MCPServerComponent)]
    assert any(s.name == "nested-srv" for s in servers)
    assert any(".mcp.json: invalid tool definition" in f for f in scan_res.scan_failures)


def test_live_mcp_rejects_external_schema_refs_vocabularies_and_non_ascii_content_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Allowed root $id, local $defs reference, and properties literally named $id / $schema / id
    valid_tool = check_served_tool(
        {
            "name": "search_docs",
            "description": "Search docs",
            "inputSchema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://example.com/tools/search.json",
                "$vocabulary": {
                    "https://json-schema.org/draft/2020-12/vocab/core": True,
                    "https://json-schema.org/draft/2020-12/vocab/validation": True,
                },
                "type": "object",
                "$defs": {"Query": {"type": "string", "pattern": "^[a-z]+$"}},
                "properties": {
                    "q": {"$ref": "#/$defs/Query"},
                    "$id": {"type": "string"},
                    "$schema": {"type": "string"},
                    "id": {"type": "string"},
                },
            },
        }
    )
    assert valid_tool.name == "search_docs"
    assert _local_pointer_exists({}, "https://example.com/schema") is False

    root_ref = check_served_tool(
        {"name": "root_ref", "inputSchema": {"type": "object", "$ref": "#"}}
    )
    assert root_ref.name == "root_ref"
    list_ref = check_served_tool(
        {
            "name": "list_ref",
            "inputSchema": {
                "type": "object",
                "anyOf": [{"type": "string"}],
                "$ref": "#/anyOf/0",
            },
        }
    )
    assert list_ref.name == "list_ref"
    draft07_anchor = check_served_tool(
        {
            "name": "draft07_anchor",
            "inputSchema": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "properties": {"x": {"$id": "#local", "type": "string"}},
            },
        }
    )
    assert draft07_anchor.name == "draft07_anchor"

    bad_schemas: list[dict[str, Any]] = [
        {"type": "object", "$schema": 1},
        {
            "type": "object",
            "anyOf": [{"type": "string"}],
            "$ref": "#/anyOf/01",
        },
        {
            "type": "object",
            "anyOf": [{"type": "string"}],
            "$ref": "#/anyOf/9",
        },
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "$vocabulary": {},
        },
        {"type": "object", "$vocabulary": []},
        {"type": "object", "$ref": "https://attacker.example/schema.json"},
        {"type": "object", "properties": {"x": {"$dynamicRef": "https://attacker.example/s#x"}}},
        {"type": "object", "properties": {"x": {"$id": "https://attacker.example/sub.json"}}},
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "type": "object",
            "properties": {"x": {"id": "https://attacker.example/sub.json", "type": "string"}},
        },
        {"type": "object", "$schema": "https://attacker.example/custom-dialect"},
        {
            "type": "object",
            "properties": {"x": {"$schema": "http://json-schema.org/draft-07/schema#"}},
        },
        {
            "type": "object",
            "$vocabulary": {"https://attacker.example/vocab/custom": True},
        },
        {
            "type": "object",
            "$vocabulary": {"https://attacker.example/vocab/custom": False},
        },
        {
            "type": "object",
            "$vocabulary": {"https://json-schema.org/draft/2020-12/vocab/validation": False},
        },
        {
            "type": "object",
            "$vocabulary": {"https://json-schema.org/draft/2020-12/vocab/core": True},
        },
        {
            "type": "object",
            "properties": {"q": {"type": "string", "pattern": "(?i)abc"}},
        },
        {
            "type": "object",
            "properties": {"q": {"$ref": "#/$defs/MissingTarget"}},
        },
    ]
    for schema in bad_schemas:
        with pytest.raises(DiscoveryError):
            check_served_tool({"name": "bad", "inputSchema": schema})

    # Invalid IDNA hostname raising UnicodeError/ValueError in getaddrinfo fails fast without leaking slot
    monkeypatch.setattr(
        "nexus_symbiote.scanners.live_mcp.socket.getaddrinfo",
        lambda *_a, **_k: (_ for _ in ()).throw(UnicodeError("label empty or too long")),
    )
    with pytest.raises(DiscoveryError, match="DNS resolution failed"):
        _resolve_public("..bad-idna.example", 443, timeout=0.2)

    # Non-ASCII digit Content-Length ("\uff11\uff10") must be refused
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.getheaders.return_value = [
        ("Content-Type", "application/json"),
        ("Content-Length", "\uff11\uff10"),
    ]
    fake_conn = MagicMock()
    fake_conn.getresponse.return_value = fake_resp
    transport = PinnedHTTPTransport()
    transport._peers[("mcp.example.com", 443)] = (2, "93.184.216.34")
    monkeypatch.setattr(
        "nexus_symbiote.scanners.live_mcp._PinnedHTTPSConnection",
        lambda *_args, **_kwargs: fake_conn,
    )
    with pytest.raises(DiscoveryError, match="HTTP body length refused"):
        transport.request(
            "https://mcp.example.com/mcp",
            b"{}",
            {"Accept": "application/json"},
            timeout=5.0,
            max_bytes=1024,
        )


def test_registry_scanner_tarball_mismatch_pnpm_risks_and_patched_dependencies(
    tmp_path: Path,
) -> None:
    assert RegistryScanner._tarball_matches(
        "https://npm.pkg.github.com",
        "/download/@modelcontextprotocol/sdk/1.2.0/sdk-1.2.0.tgz",
        "@modelcontextprotocol/sdk",
        "1.2.0",
    )
    assert not RegistryScanner._tarball_matches(
        "https://npm.pkg.github.com",
        "/download/evil-backdoor/9.9.9/evil-9.9.9.tgz",
        "@modelcontextprotocol/sdk",
        "1.2.0",
    )

    # A pnpm record with no integrity from a custom registry carries both risks.
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      openai:\n"
        "        specifier: 4.80.0\n"
        "        version: 4.80.0\n"
        "packages:\n"
        "  openai@4.80.0:\n"
        "    resolution:\n"
        "      tarball: https://npm.custom-corp.example/openai/-/openai-4.80.0.tgz\n",
        encoding="utf-8",
    )
    manifest = {"name": "demo-app", "version": "1.0.0", "dependencies": {"openai": "4.80.0"}}
    (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    res = RegistryScanner().scan(tmp_path)
    assert res.scan_failures == [] and res.surfaces_excluded == []
    comp = next(
        c for c in res.components if isinstance(c, RegistryEntryComponent) and c.name == "openai"
    )
    categories = {r.category for r in comp.risks}
    assert "missing_lockfile_integrity" in categories
    assert "registry_origin" in categories

    # pnpm.patchedDependencies is not read as a project-wide override; the patched AI
    # package itself is not the registry artifact and is reported as such.
    manifest["pnpm"] = {"patchedDependencies": {"openai@4.80.0": "patches/openai.patch"}}
    (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    res = RegistryScanner().scan(tmp_path)
    assert res.scan_failures == []
    assert res.surfaces_excluded == ["package.json: patched dependency is unverified"]
    assert RegistryScanner._NPM_GAPS["override"] not in res.surfaces_excluded

    # Python lockfile: cleartext http:// -> HIGH registry_origin; uppercase HTTP:// or token-host -> excluded & purl=None
    py_dir = tmp_path / "py-http"
    py_dir.mkdir()
    (py_dir / "pyproject.toml").write_text(
        '[project]\ndependencies = ["langgraph>=0.2.0", "anthropic>=0.30.0", "openai>=1.0.0"]\n',
        encoding="utf-8",
    )
    (py_dir / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "langgraph"\nversion = "0.2.14"\n'
        'source = { registry = "http://pypi.corp.example/simple" }\n\n'
        '[[package]]\nname = "anthropic"\nversion = "0.34.2"\n'
        'source = { registry = "HTTP://pypi.corp.example/simple" }\n\n'
        '[[package]]\nname = "openai"\nversion = "1.40.0"\n'
        f'source = {{ registry = "https://glpat-{"A1b2C3d4E5" * 2}.corp.example/simple" }}\n',
        encoding="utf-8",
    )
    res3 = RegistryScanner().scan(py_dir)
    comp3 = next(
        c
        for c in res3.components
        if isinstance(c, RegistryEntryComponent) and c.name == "langgraph"
    )
    py_categories = {(r.category, r.severity.value) for r in comp3.risks}
    assert ("registry_origin", "high") in py_categories
    upper_comp = next(
        c
        for c in res3.components
        if isinstance(c, RegistryEntryComponent) and c.name == "anthropic"
    )
    assert upper_comp.package_url is None
    redacted_comp = next(
        c for c in res3.components if isinstance(c, RegistryEntryComponent) and c.name == "openai"
    )
    assert redacted_comp.package_url is None
    assert len([e for e in res3.surfaces_excluded if "origin is unverified" in e]) == 2

    # Yarn Berry bogus checksum ("0") vs valid 128-hex SHA-512 checksum
    berry_bad = tmp_path / "berry_bad"
    berry_bad.mkdir()
    (berry_bad / "package.json").write_text(
        '{"dependencies":{"openai":"^4.0.0"}}', encoding="utf-8"
    )
    (berry_bad / "yarn.lock").write_text(
        '__metadata:\n  version: 8\n\n"openai@npm:^4.0.0":\n'
        '  version: 4.52.0\n  resolution: "openai@npm:4.52.0"\n  checksum: "0"\n',
        encoding="utf-8",
    )
    berry_bad_comp = next(
        c
        for c in RegistryScanner().scan(berry_bad).components
        if isinstance(c, RegistryEntryComponent)
    )
    assert any(r.category == "missing_lockfile_integrity" for r in berry_bad_comp.risks)

    berry_ok = tmp_path / "berry_ok"
    berry_ok.mkdir()
    (berry_ok / "package.json").write_text('{"dependencies":{"openai":"^4.0.0"}}', encoding="utf-8")
    (berry_ok / "yarn.lock").write_text(
        # Yarn checks the checksum only when its cache key is the lockfile's.
        '__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"openai@npm:^4.0.0":\n'
        f'  version: 4.52.0\n  resolution: "openai@npm:4.52.0"\n  checksum: 10c0/{"a" * 128}\n',
        encoding="utf-8",
    )
    berry_ok_comp = next(
        c
        for c in RegistryScanner().scan(berry_ok).components
        if isinstance(c, RegistryEntryComponent)
    )
    assert not any(r.category == "missing_lockfile_integrity" for r in berry_ok_comp.risks)


def test_model_scanner_second_zip_pickle_member_jinja2_and_nested_custom_code(
    tmp_path: Path,
) -> None:
    # ZIP container disguised as .onnx where first member is benign and second member is data.pkl
    disguised = tmp_path / "model.onnx"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/version", b"3\n")
        zf.writestr("archive/data.pkl", b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00N.")
    disguised.write_bytes(buf.getvalue())

    safety, reason = inspect_model_format(disguised)
    assert safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert "pickle member" in reason

    # Also test streaming data-descriptor ZIP (flag 0x08) via Central Directory fallback
    stream_zip = tmp_path / "streamed.onnx"
    raw_bytes = bytearray(buf.getvalue())
    raw_bytes[6] |= 0x08
    stream_zip.write_bytes(bytes(raw_bytes))
    with stream_zip.open("rb") as f:
        obs = observe_model_artifact(stream_zip, stream=f)
    assert obs.safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert "pickle member" in obs.explanation

    # Model directory with uppercase .JINJA2 and nested uppercase .PY custom code
    mdir = tmp_path / "hf_model"
    (mdir / "additional_chat_templates").mkdir(parents=True)
    (mdir / "subpkg").mkdir(parents=True)
    (mdir / "tests").mkdir(parents=True)
    (mdir / "config.json").write_text(
        json.dumps({"model_type": "llama", "auto_map": {"AutoModel": "subpkg.modeling.MyModel"}}),
        encoding="utf-8",
    )
    (mdir / "additional_chat_templates" / "default.JINJA2").write_text(
        "{{ '' | attr('__class__') }}",
        encoding="utf-8",
    )
    (mdir / "subpkg" / "modeling.PY").write_text("class MyModel:\n    pass\n", encoding="utf-8")
    (mdir / "tests" / "test_unrelated.py").write_text("assert True\n", encoding="utf-8")
    (mdir / "secrets.py").write_text("API_KEY = 'secret'\n", encoding="utf-8")
    (mdir / "model.safetensors").write_bytes((2).to_bytes(8, "little") + b"{}")

    mres = ModelScanner().scan(mdir)
    mcomp = next(c for c in mres.components if isinstance(c, ModelComponent))
    assert any(
        r.severity == RiskSeverity.CRITICAL
        and r.category == "serialization_format"
        and "default.JINJA2" in r.detail
        for r in mcomp.risks
    )
    assert any(
        entry["source"].lower().endswith("default.jinja2")
        for entry in mcomp.properties.get("chat_templates", [])
    )
    custom = mcomp.properties.get("custom_code", {})
    recorded_py = [entry["path"].lower() for entry in custom.get("python_files", [])]
    assert any(p.endswith("subpkg/modeling.py") for p in recorded_py)
    assert not any("test_unrelated.py" in p for p in recorded_py)
    assert not any("secrets.py" in p for p in recorded_py)


def test_ide_agents_subshell_grants_dont_ask_and_codex_full_access(tmp_path: Path) -> None:
    from nexus_symbiote.scanners.ide_agents import _SUBSHELL_SPECIFIER
    from tests.support import scaling_ratio

    assert "shell commands" in _broad_grants(["Bash(sh -c *)"])
    assert "shell commands" in _broad_grants(["Bash(sh -c evil\nid)"])
    assert "shell commands" in _broad_grants(["Bash(/usr/local/bin/bash -c *)"])
    assert "shell commands" in _broad_grants(["Bash(env python3 -c *)"])
    assert "shell commands" in _broad_grants(["Bash(cmd /c *)"])
    assert "shell commands" in _broad_grants(["Bash(pwsh -Command *)"])
    assert "shell commands" in _broad_grants(["Bash(pwsh -enco SQBEAA==)"])
    assert "shell commands" in _broad_grants(["Bash(powershell /en SQBEAA==)"])
    assert "shell commands" in _broad_grants(["Bash(pwsh -co Get-Date)"])
    assert _broad_grants(["Bash(pwsh -ExecutionPolicy Bypass file.ps1)"]) == []
    assert _broad_grants(["Bash(git status)"]) == []
    assert _broad_grants(["Bash(sh scripts/check.sh)"]) == []
    assert _broad_grants(["Bash(sh" + " " * 32000 + "a\nb)"]) == []

    samples = {scale: "/a" * (1_250 * scale) + "/env" for scale in (1, 4)}
    assert _SUBSHELL_SPECIFIER.search(samples[4]) is None
    assert scaling_ratio(lambda scale: _SUBSHELL_SPECIFIER.search(samples[scale])) < 10

    assert _starting_mode_risk("claude-code", "dontAsk") is None
    for med_mode in ("auto", "never"):
        risk = _starting_mode_risk("claude-code", med_mode)
        assert risk is not None and risk.severity == RiskSeverity.MEDIUM
    for high_mode in ("bypassPermissions", "always", "full-access", "danger-full-access"):
        risk_h = _starting_mode_risk("cursor", high_mode)
        assert risk_h is not None and risk_h.severity == RiskSeverity.HIGH

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        'sandbox_mode = "full-access"\napproval_policy = "on-request"\n',
        encoding="utf-8",
    )
    ide_res = IDEAgentScanner().scan(tmp_path)
    codex = next(c for c in ide_res.components if isinstance(c, IDEAgentComponent))
    assert any(
        r.severity == RiskSeverity.HIGH and r.category == "permission_scope" for r in codex.risks
    )


def test_a2a_secondary_cleartext_interface_ts_escaped_namespace_and_nested_cyclonedx(
    tmp_path: Path,
) -> None:
    # A2A card with HTTPS primary URL but HTTP additionalInterfaces fallback
    well_known = tmp_path / ".well-known"
    well_known.mkdir()
    (well_known / "agent.json").write_text(
        json.dumps(
            {
                "name": "billing-agent",
                "url": "https://agent.example.com/a2a",
                "version": "1.0.0",
                "capabilities": {},
                "skills": [{"id": "s1", "name": "Skill 1"}],
                "additionalInterfaces": [
                    {"url": "http://cleartext.example.com/a2a", "transport": "JSONRPC"}
                ],
            }
        ),
        encoding="utf-8",
    )
    a2a_res = A2AScanner().scan(tmp_path)
    agent = next(c for c in a2a_res.components if isinstance(c, A2AServerComponent))
    assert any(r.category == "transport_security" for r in agent.risks)

    # TypeScript namespace import with hex-escaped McpServer property
    ts_dir = tmp_path / "ts_proj"
    ts_dir.mkdir()
    (ts_dir / "server.ts").write_text(
        'import * as sdk from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'const server = new sdk["\\x4dcpServer"]({ name: "hex-srv", version: "1.0.0" });\n'
        'server.registerTool("lookup", {}, async () => ({ content: [] }));\n',
        encoding="utf-8",
    )
    ts_res = MCPScanner().scan(ts_dir)
    tools = [c for c in ts_res.components if isinstance(c, ToolComponent)]
    assert [t.name for t in tools] == ["lookup"]

    # ShadowScan CycloneDX nested components flattening
    cdx_path = tmp_path / "shadowscan-cdx.json"
    cdx_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {
                    "properties": [{"name": "shadowscan:scan:status", "value": "complete"}]
                },
                "components": [
                    {
                        "type": "application",
                        "bom-ref": "parent-app",
                        "name": "parent-app",
                        "properties": [
                            {"name": "shadowscan:kind", "value": "agent"},
                            {"name": "shadowscan:shadow", "value": "false"},
                        ],
                        "components": [
                            {
                                "type": "service",
                                "group": "mcp-server",
                                "bom-ref": "nested-mcp-server",
                                "name": "nested-mcp-server",
                                "properties": [
                                    {"name": "shadowscan:kind", "value": "mcp-server"},
                                    {"name": "shadowscan:shadow", "value": "true"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    imported = ShadowScanImporter().import_report(cdx_path)
    assert any(isinstance(c, MCPServerComponent) for c in imported.components)
    assert len(imported.components) == 2
