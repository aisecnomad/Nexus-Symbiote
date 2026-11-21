"""Tests for foreign SBOM import, nested manifest walking, shape census, and evidence-profile (R1.2-2, R1.1-8)."""

from __future__ import annotations

import hashlib
import json
import os
import tracemalloc
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.models import (
    AgentComponent,
    ClaimEvidence,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.evidence_profile import (
    EVIDENCE_PROFILE_SCHEMA,
    build_evidence_profile,
    is_exact_version,
    purl_has_exact_version,
)
from nexus_symbiote.sbom_import import (
    MAX_FOREIGN_COMPONENTS,
    MAX_FOREIGN_SBOM_BYTES,
    classify_pinning_state,
    import_foreign_sbom,
    unread_shape_census,
    walk_nested_manifests,
)
from nexus_symbiote.signature_policy import load_signature_policies
from tests.support import scaling_ratio


def _sample_aibom() -> AIBOM:
    return AIBOM(
        components=[
            AgentComponent(
                bom_ref="agent:repo",
                name="customer-support-agent",
                version="1.2.0",
                supplier="Acme AI",
                assurance_level=AssuranceLevel.OBSERVED,
                trust_tier=TrustTier.INTERNAL_VERIFIED,
            ),
            ModelComponent(
                bom_ref="model:tuned",
                name="support-llama-8b-ft",
                version="1.0.0",
                source_path="models/tuned.safetensors",
                resolved_revision="a" * 40,
                signing_status="sigstore-signed",
                safetensors_header_hash="sha256:" + "1" * 64,
                hashes={"sha256": "sha256:" + "2" * 64},
                assurance_level=AssuranceLevel.VERIFIED,
                trust_tier=TrustTier.INTERNAL_VERIFIED,
            ),
            MCPServerComponent(
                bom_ref="mcp:remote-crm",
                name="crm-mcp",
                transport="streamable-http",
                endpoint_url="https://mcp.example.com/v1",
                schema_hash="sha256:" + "8" * 64,
                version_pinned=False,
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            ToolComponent(
                bom_ref="tool:lookup-ticket",
                name="lookup_ticket",
                definition_hash="sha256:" + "3" * 64,
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            PromptComponent(
                bom_ref="prompt:sys",
                name="CLAUDE.md",
                content_hash="sha256:" + "5" * 64,
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            RegistryEntryComponent(
                bom_ref="pkg:mcp-sdk",
                name="mcp",
                version="1.4.0",
                registry_type="pypi",
                package_url="pkg:pypi/mcp@1.4.0",
                hashes={"sha256": "sha256:" + "6" * 64},
                assurance_level=AssuranceLevel.OBSERVED,
            ),
        ]
    )


def test_import_foreign_sbom_conflicts_local_binding_privacy_and_census(
    tmp_path: Path,
) -> None:
    (tmp_path / "models").mkdir()
    local_weights = b"safetensors-mock-bytes"
    local_sha = "sha256:" + hashlib.sha256(local_weights).hexdigest()
    (tmp_path / "models" / "embed.bin").write_bytes(local_weights)

    # Credential-shaped files and hidden secret dirs MUST NEVER be bound by digest.
    env_bytes = b"OPENAI_API_KEY=placeholder-test-value\n"
    env_sha = hashlib.sha256(env_bytes).hexdigest()
    (tmp_path / ".env").write_bytes(env_bytes)
    (tmp_path / ".ssh").mkdir()
    ssh_bytes = b"ssh-mock-key-material\n"
    ssh_sha = hashlib.sha256(ssh_bytes).hexdigest()
    (tmp_path / ".ssh" / "id_rsa").write_bytes(ssh_bytes)

    (tmp_path / "mcp-server").mkdir()
    (tmp_path / "mcp-server" / "package.json").write_text(
        json.dumps({"name": "sub-mcp", "dependencies": {"@modelcontextprotocol/sdk": "^1.2.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "setup.cfg").write_text(
        "[options]\ninstall_requires =\n    langchain>=0.3.0\n",
        encoding="utf-8",
    )
    (tmp_path / "rust-worker").mkdir()
    (tmp_path / "rust-worker" / "Cargo.toml").write_text(
        '[package]\nname = "w"\n[dependencies]\ncandle-core = { version = "0.8.0" }\n',
        encoding="utf-8",
    )
    (tmp_path / "rust-worker" / "Cargo.lock").write_text(
        '[[package]]\nname = "candle-core"\nversion = "0.8.1"\n',
        encoding="utf-8",
    )
    (tmp_path / "go-svc").mkdir()
    (tmp_path / "go-svc" / "go.mod").write_text(
        "module example.com/svc\ngo 1.22\nrequire (\n\tgithub.com/sashabaranov/go-openai v1.32.0\n)\n",
        encoding="utf-8",
    )
    (tmp_path / "go-svc" / "go.sum").write_text(
        "github.com/sashabaranov/go-openai v1.32.0 h1:abc=\n",
        encoding="utf-8",
    )
    (tmp_path / "notebooks").mkdir()
    (tmp_path / "notebooks" / "exp.ipynb").write_text("{}", encoding="utf-8")
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "main.tf").write_text("# terraform\n", encoding="utf-8")
    (tmp_path / "chart").mkdir()
    (tmp_path / "chart" / "Chart.yaml").write_text("name: demo\nversion: 0.1.0\n", encoding="utf-8")
    (tmp_path / "workflows").mkdir()
    (tmp_path / "workflows" / "flow.json").write_text(
        '{"nodes": [], "connections": {}}', encoding="utf-8"
    )

    base_bom = AIBOM(
        components=[
            RegistryEntryComponent(
                bom_ref="pkg:openai",
                name="openai",
                version="==1.52.0",
                registry_type="pypi",
                package_url=None,
                hashes={"sha256": "sha256:" + "e" * 64},
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            RegistryEntryComponent(
                bom_ref="pkg:langchain",
                name="langchain",
                version=">=0.2.0,<0.4.0",
                registry_type="pypi",
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            MCPServerComponent(
                bom_ref="mcp:unpinned",
                name="srv",
                transport="stdio",
                version_pinned=True,
                assurance_level=AssuranceLevel.OBSERVED,
            ),
        ]
    )
    foreign_cdx = tmp_path / "syft.cdx.json"
    foreign_cdx.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "library",
                        "name": "openai",
                        "version": "1.40.0",
                        "purl": "pkg:pypi/openai@1.40.0",
                        "hashes": [{"alg": "SHA-256", "content": "f" * 64}],
                    },
                    {
                        "type": "library",
                        "name": "langchain",
                        "version": "0.3.5",
                        "purl": "pkg:pypi/langchain@0.3.5",
                    },
                    {
                        "type": "machine-learning-model",
                        "name": "internal-secret-embedder",
                        "version": "1.0.0",
                        "supplier": {"name": "Private Division Alpha"},
                        "hashes": [
                            {
                                "alg": "SHA-256",
                                "content": local_sha.removeprefix("sha256:"),
                            }
                        ],
                    },
                    {
                        "type": "data",
                        "name": "env-probe",
                        "version": "1.0.0",
                        "hashes": [{"alg": "SHA-256", "content": env_sha}],
                    },
                    {
                        "type": "data",
                        "name": "ssh-probe",
                        "version": "1.0.0",
                        "hashes": [{"alg": "SHA-256", "content": ssh_sha}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    summary = import_foreign_sbom(
        foreign_cdx, target_aibom=base_bom, project_root=tmp_path, reveal_names=False
    )
    assert summary.imported_count == 5
    # Only models/embed.bin is bound; .env and .ssh/id_rsa are excluded.
    assert summary.bound_local_count == 1
    # openai conflicts on version+digest; langchain 0.3.5 satisfies >=0.2.0,<0.4.0 so 0 conflict!
    assert summary.conflict_count == 1
    imported_items = [c for c in summary.aibom.components if c.bom_ref.startswith("sbom:")]
    assert all(c.assurance_level == AssuranceLevel.DECLARED for c in imported_items)
    assert all(c.trust_tier == TrustTier.UNKNOWN for c in imported_items)
    assert all(c.name.startswith("imported-") for c in imported_items)
    assert all(c.properties.get("name_hash_mode") == "unsalted-sha256" for c in imported_items)
    assert all(getattr(c, "package_url", None) is None for c in imported_items)
    assert all(getattr(c, "supplier", None) is None for c in imported_items)
    serialized = summary.aibom.to_native_json()
    assert "internal-secret-embedder" not in serialized
    assert "Private Division Alpha" not in serialized
    assert ".env" not in serialized
    assert ".ssh" not in serialized

    # Without --project, even if base_bom has a matching hash, bound_local_count MUST be 0.
    base_with_hash = AIBOM(
        components=[
            ModelComponent(
                bom_ref="model:existing",
                name="embed",
                version="1.0.0",
                hashes={"sha256": local_sha},
                assurance_level=AssuranceLevel.OBSERVED,
            )
        ]
    )
    no_proj_summary = import_foreign_sbom(
        foreign_cdx, target_aibom=base_with_hash, project_root=None, reveal_names=False
    )
    assert no_proj_summary.bound_local_count == 0
    assert all(
        "local_digest_binding" not in c.properties
        for c in no_proj_summary.aibom.components
        if c.bom_ref.startswith("sbom:")
    )

    nested, failures = walk_nested_manifests(tmp_path)
    assert not failures
    by_name = {c.name: c for c in nested}
    assert by_name["@modelcontextprotocol/sdk"].properties["pinning_state"] == "manifest-only"
    assert by_name["langchain"].properties["pinning_state"] == "manifest-only"
    assert by_name["candle-core"].properties["pinning_state"] == "locked"
    assert by_name["candle-core"].version == "0.8.1"
    assert by_name["github.com/sashabaranov/go-openai"].properties["pinning_state"] == "locked"

    states = classify_pinning_state(summary.aibom)
    assert states["pkg:openai"] == "locked"
    assert states["mcp:unpinned"] == "pinned-version"

    census = {row.shape: row.count for row in unread_shape_census(tmp_path)}
    assert census == {"*.ipynb": 1, "*.tf": 1, "Chart.yaml": 1, "n8n/*.json": 1}


def test_import_sbom_hmac_key_mode_no_name_oracle_and_redaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sbom_a = tmp_path / "a.cdx.json"
    sbom_a.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"type": "library", "name": "secret-internal-pkg", "version": "1.0.0"},
                    {"type": "library", "name": "secret-internal-pkg", "version": "2.0.0"},
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "k" * 32)
    res_hmac = import_foreign_sbom(sbom_a, reveal_names=False)
    assert res_hmac.conflict_count == 1
    for c in res_hmac.aibom.components:
        assert c.properties["name_hash_mode"] == "hmac-sha256"
        assert str(c.properties["imported_entry_sha256"]).startswith("hmac-sha256:")
    dumped = res_hmac.aibom.to_native_json()
    assert "secret-internal-pkg" not in dumped

    # Short key must fail closed.
    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "too-short")
    with pytest.raises(ValueError, match="NEXUS_SYMBIOTE_SOURCE_BINDING_KEY"):
        import_foreign_sbom(sbom_a)
    runner = CliRunner()
    bad_key_res = runner.invoke(main, ["import-sbom", str(sbom_a)])
    assert bad_key_res.exit_code == 2
    assert "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY" in bad_key_res.output

    # Secret token inside name/purl is redacted even when --reveal-names is used.
    monkeypatch.delenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", raising=False)
    tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    sbom_sec = tmp_path / "sec.cdx.json"
    sbom_sec.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "library",
                        "name": f"pkg-{tok}",
                        "version": "1.0.0",
                        "purl": f"pkg:npm/demo@1.0.0?token={tok}",
                    },
                    {
                        "type": "data",
                        "name": "public-dataset",
                        "version": "1.0.0",
                        "supplier": {"name": "DatasetOrg"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    sec_summary = import_foreign_sbom(sbom_sec, reveal_names=True)
    sec_json = sec_summary.aibom.to_native_json()
    assert tok not in sec_json
    assert "DatasetOrg" in sec_json


def test_import_sbom_10000_same_name_components_is_linear_time_and_memory(
    tmp_path: Path,
) -> None:
    sbom_10k = tmp_path / "ten_thousand.cdx.json"
    sbom_10k.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"type": "library", "name": "same-pkg", "version": f"1.0.{i}"}
                    for i in range(MAX_FOREIGN_COMPONENTS)
                ],
            }
        ),
        encoding="utf-8",
    )
    summary = import_foreign_sbom(sbom_10k, reveal_names=False)

    assert summary.imported_count == MAX_FOREIGN_COMPONENTS
    assert summary.conflict_count == MAX_FOREIGN_COMPONENTS - 1

    # Growth, not a wall-clock bound, which coverage tracing and a busy runner move:
    # four times the same-name components cost about four times as much if linear.
    sized = {}
    for scale in (1, 4):
        path = tmp_path / f"same-name-{scale}.cdx.json"
        count = MAX_FOREIGN_COMPONENTS * scale // 4
        components = [
            {"type": "library", "name": "same-pkg", "version": f"1.0.{i}"} for i in range(count)
        ]
        path.write_text(
            json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}),
            encoding="utf-8",
        )
        sized[scale] = path

    def run(scale: int) -> None:
        import_foreign_sbom(sized[scale], reveal_names=False)

    assert scaling_ratio(run) < 10

    # Also verify peak allocation stays bounded on a 2,000-entry slice under tracemalloc.
    sbom_2k = tmp_path / "two_thousand.cdx.json"
    sbom_2k.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"type": "library", "name": "same-pkg", "version": f"1.0.{i}"}
                    for i in range(2000)
                ],
            }
        ),
        encoding="utf-8",
    )
    tracemalloc.start()
    import_foreign_sbom(sbom_2k, reveal_names=False)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak_bytes < 24 * 1024 * 1024


def test_nested_cdx_spdx3_format_validation_and_lockfile_membership(tmp_path: Path) -> None:
    nested_cdx = tmp_path / "nested.cdx.json"
    nested_cdx.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "metadata": {
                    "component": {
                        "type": "machine-learning-model",
                        "name": "root-model",
                        "version": "1.0.0",
                        "provider": {"name": "ModelOrg"},
                        "components": [
                            {"type": "data", "name": "train-corpus", "version": "2026.1"}
                        ],
                    }
                },
                "services": [{"name": "inference-gateway", "version": "2.1.0"}],
            }
        ),
        encoding="utf-8",
    )
    cdx_res = import_foreign_sbom(nested_cdx, reveal_names=True)
    assert cdx_res.imported_count == 3
    names = {c.name for c in cdx_res.aibom.components}
    assert names == {"root-model", "train-corpus", "inference-gateway"}

    spdx3 = tmp_path / "bom.spdx3.json"
    sha_hex = "a" * 64
    spdx3.write_text(
        json.dumps(
            {
                "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                "@graph": [
                    {
                        "type": "ai_AIPackage",
                        "spdxId": "urn:spdx:model-1",
                        "name": "qwen-coder",
                        "software_packageVersion": "2.5.0",
                        "verifiedUsing": [{"algorithm": "sha256", "hashValue": sha_hex}],
                    },
                    {
                        "type": "dataset_DatasetPackage",
                        "spdxId": "urn:spdx:data-1",
                        "name": "eval-bench",
                    },
                    {
                        "type": "software_Package",
                        "spdxId": "urn:spdx:pkg-1",
                        "name": "vllm",
                        "software_packageUrl": "pkg:pypi/vllm@0.6.3",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    spdx3_res = import_foreign_sbom(spdx3, reveal_names=True)
    assert spdx3_res.source_format == "spdx-3.0.1"
    assert spdx3_res.imported_count == 3

    for idx, bad_doc in enumerate(
        [
            {"bomFormat": "CycloneDX", "specVersion": "0.1", "components": []},
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": "bad"},
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "services": "bad"},
            {"packages": []},
            {"@graph": [{"type": "Person", "name": "Alice"}]},
        ]
    ):
        p = tmp_path / f"bad_{idx}.json"
        p.write_text(json.dumps(bad_doc), encoding="utf-8")
        with pytest.raises(ValueError):
            import_foreign_sbom(p)

    proj = tmp_path / "lock_proj"
    (proj / "js_unlocked").mkdir(parents=True)
    (proj / "js_unlocked" / "package.json").write_text(
        json.dumps({"dependencies": {"openai": "^4.0.0"}}), encoding="utf-8"
    )
    (proj / "js_unlocked" / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/chalk": {"version": "5.0.0"}}}),
        encoding="utf-8",
    )

    (proj / "js_locked").mkdir()
    (proj / "js_locked" / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "openai": "^4.0.0",
                    "anthropic": "^0.30.0",
                    "@modelcontextprotocol/sdk": "^1.0.0",
                }
            }
        ),
        encoding="utf-8",
    )
    (proj / "js_locked" / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {"node_modules/openai": {"version": "4.68.1"}},
                "dependencies": {},
            }
        ),
        encoding="utf-8",
    )
    (proj / "js_locked" / "yarn.lock").write_text(
        '"anthropic@^0.30.0":\n  version "0.30.1"\n',
        encoding="utf-8",
    )
    (proj / "js_locked" / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '6.0'\npackages:\n  /@modelcontextprotocol/sdk@1.2.1:\n    resolution: {}\n",
        encoding="utf-8",
    )

    (proj / "py_hashed").mkdir()
    req_sha = "b" * 64
    (proj / "py_hashed" / "requirements-prod.txt").write_text(
        f"openai==1.52.0 \\\n    --hash=sha256:{req_sha}\n"
        f"langchain>=0.3.0 --hash=sha256:{'c' * 64}\n",
        encoding="utf-8",
    )

    (proj / "py_uv").mkdir()
    (proj / "py_uv" / "pyproject.toml").write_text(
        '[project]\nname = "sub"\ndependencies = ["litellm>=1.40", "transformers==4.45.0"]\n',
        encoding="utf-8",
    )
    (proj / "py_uv" / "uv.lock").write_text(
        '[[package]]\nname = "litellm"\nversion = "1.50.2"\n',
        encoding="utf-8",
    )

    (proj / ".devcontainer").mkdir()
    (proj / ".devcontainer" / "devcontainer.json").write_text(
        json.dumps({"image": f"vllm/vllm-openai@sha256:{'d' * 64}"}),
        encoding="utf-8",
    )

    (proj / "conda_env").mkdir()
    (proj / "conda_env" / "environment.yml").write_text(
        "name: ml\ndependencies:\n  - pytorch=2.4.0\n",
        encoding="utf-8",
    )

    nested, failures = walk_nested_manifests(proj)
    assert not failures
    by_loc_name = {(c.properties["manifest_path"], c.name): c for c in nested}
    assert (
        by_loc_name[("js_unlocked/package.json", "openai")].properties["pinning_state"]
        == "manifest-only"
    )
    assert by_loc_name[("js_locked/package.json", "openai")].properties["pinning_state"] == "locked"
    assert by_loc_name[("js_locked/package.json", "openai")].version == "4.68.1"
    assert (
        by_loc_name[("js_locked/package.json", "anthropic")].properties["pinning_state"] == "locked"
    )
    assert (
        by_loc_name[("js_locked/package.json", "@modelcontextprotocol/sdk")].properties[
            "pinning_state"
        ]
        == "locked"
    )
    assert (
        by_loc_name[("py_hashed/requirements-prod.txt", "openai")].properties["pinning_state"]
        == "digest-pinned"
    )
    assert (
        by_loc_name[("py_hashed/requirements-prod.txt", "langchain")].properties["pinning_state"]
        == "manifest-only"
    )
    assert by_loc_name[("py_uv/pyproject.toml", "litellm")].properties["pinning_state"] == "locked"
    assert (
        by_loc_name[("py_uv/pyproject.toml", "transformers")].properties["pinning_state"]
        == "pinned-version"
    )
    assert (
        by_loc_name[
            (".devcontainer/devcontainer.json", f"vllm/vllm-openai@sha256:{'d' * 64}")
        ].properties["pinning_state"]
        == "digest-pinned"
    )
    assert by_loc_name[("conda_env/environment.yml", "pytorch")].version == "2.4.0"


def test_import_sbom_adversarial_symlink_size_cap_and_malformed_manifests(
    tmp_path: Path,
) -> None:
    real_sbom = tmp_path / "real.cdx.json"
    real_sbom.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}),
        encoding="utf-8",
    )
    linked_sbom = tmp_path / "linked.cdx.json"
    linked_sbom.symlink_to(real_sbom)
    with pytest.raises(OSError):
        import_foreign_sbom(linked_sbom)

    runner = CliRunner()
    res_sym_cli = runner.invoke(main, ["import-sbom", str(linked_sbom)])
    assert res_sym_cli.exit_code == 1
    assert "symlinks" in res_sym_cli.output.lower()

    bad_syntax = tmp_path / "bad_syntax.json"
    bad_syntax.write_text("{invalid", encoding="utf-8")
    res_bad_json = runner.invoke(main, ["import-sbom", str(bad_syntax)])
    assert res_bad_json.exit_code == 1
    assert "invalid json" in res_bad_json.output.lower()

    large_sbom = tmp_path / "large.cdx.json"
    large_sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"comment": "x" * (4 * 1024 * 1024 + 65536)},
                "components": [{"type": "library", "name": "openai", "version": "1.52.0"}],
            }
        ),
        encoding="utf-8",
    )
    assert import_foreign_sbom(large_sbom, reveal_names=True).imported_count == 1

    too_big = tmp_path / "too_big.cdx.json"
    too_big.write_bytes(b"{" + b" " * (MAX_FOREIGN_SBOM_BYTES + 10) + b"}")
    with pytest.raises(ValueError, match="exceeds maximum size limit"):
        import_foreign_sbom(too_big)

    over_cap = tmp_path / "over_cap.cdx.json"
    over_cap.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"type": "library", "name": f"pkg-{i}", "version": "1.0.0"}
                    for i in range(MAX_FOREIGN_COMPONENTS + 1)
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exceeds maximum component count"):
        import_foreign_sbom(over_cap)

    proj = tmp_path / "hostile_proj"
    (proj / "broken-js").mkdir(parents=True)
    (proj / "broken-js" / "package.json").write_text("{not-json", encoding="utf-8")
    (proj / "deep-conda").mkdir()
    (proj / "deep-conda" / "environment.yml").write_text(
        "a: &a [1, 2]\nb: *a\n",
        encoding="utf-8",
    )
    (proj / "good-py").mkdir()
    (proj / "good-py" / "requirements.txt").write_text("openai==1.52.0\n", encoding="utf-8")

    nested, failures = walk_nested_manifests(proj)
    assert any(c.name == "openai" for c in nested)
    assert len(failures) == 2
    assert any("broken-js/package.json" in f for f in failures)
    assert any("deep-conda/environment.yml" in f for f in failures)


def test_evidence_profile_policy_corroboration_and_pinning_accuracy(tmp_path: Path) -> None:
    assert is_exact_version("1.2.3")
    assert is_exact_version("==1.2.3")
    assert is_exact_version("===1.2.3")
    assert not is_exact_version("   ")
    assert not is_exact_version(">=1.0")
    assert not is_exact_version("^4.0.0")
    assert not is_exact_version("latest")
    assert purl_has_exact_version("pkg:pypi/requests@2.32.3")
    assert purl_has_exact_version("pkg:oci/vllm@sha256:" + "a" * 64)
    assert not purl_has_exact_version("pkg:pypi/requests")
    assert not purl_has_exact_version("pkg:pypi/requests#sub@1.0")

    bom = _sample_aibom()
    bom.components.append(
        RegistryEntryComponent(
            bom_ref="pkg:range-with-hash",
            name="langchain",
            version=">=0.3.0",
            registry_type="pypi",
            hashes={"sha256": "sha256:" + "7" * 64},
            assurance_level=AssuranceLevel.OBSERVED,
        )
    )
    bom.components.append(
        RegistryEntryComponent(
            bom_ref="pkg:versionless-purl",
            name="requests",
            version=None,
            registry_type="pypi",
            package_url="pkg:pypi/requests",
            assurance_level=AssuranceLevel.OBSERVED,
        )
    )
    bom.components.append(
        RegistryEntryComponent(
            bom_ref="sbom:pkg:unbound",
            name="imported-1234",
            version="1.0.0",
            registry_type="pypi",
            hashes={"sha256": "sha256:" + "9" * 64},
            properties={"imported_source_format": "cyclonedx-1.6", "version_pinned": True},
            assurance_level=AssuranceLevel.DECLARED,
            claims={
                "rt": ClaimEvidence(
                    assurance=AssuranceLevel.OBSERVED,
                    method="otlp-trace",
                    scope="runtime",
                )
            },
        )
    )
    bom.components[2].risks.append(
        RiskAssessment(
            severity=RiskSeverity.HIGH,
            category="version_pinning",
            detail="Unpinned dependency.",
        )
    )

    unverified_profile = build_evidence_profile(bom, runtime_matched_refs={"model:tuned"})
    assert unverified_profile["schema"] == EVIDENCE_PROFILE_SCHEMA
    assert unverified_profile["policy_verified"] is False
    serialized_profile = json.dumps(unverified_profile)
    assert "trust_score" not in serialized_profile.lower()
    assert "trustscore" not in serialized_profile.lower()
    by_ref = {c["bom_ref"]: c for c in unverified_profile["components"]}
    assert by_ref["model:tuned"]["declared_signing_status"] == "sigstore-signed"
    assert by_ref["model:tuned"]["evidence"]["signed_under_policy"] is False
    assert "signed_under_policy" in by_ref["model:tuned"]["missing_evidence"]
    assert by_ref["pkg:range-with-hash"]["evidence"]["pinned"] is False
    assert by_ref["pkg:versionless-purl"]["evidence"]["pinned"] is False
    assert by_ref["sbom:pkg:unbound"]["evidence"]["digest_bound"] is False
    assert by_ref["sbom:pkg:unbound"]["inventory_claims"]["runtime_observation"] is True

    proj_dir = tmp_path / "proj"
    (proj_dir / "models").mkdir(parents=True)
    model_bytes = b"\x02\x00\x00\x00\x00\x00\x00\x00{}"
    model_sha = "sha256:" + hashlib.sha256(model_bytes).hexdigest()
    (proj_dir / "models" / "tuned.safetensors").write_bytes(model_bytes)
    bom.components[1] = ModelComponent(
        bom_ref="model:tuned",
        name="support-llama-8b-ft",
        version="1.0.0",
        source_path="models/tuned.safetensors",
        serialization_format="safetensors",
        hashes={"sha256": model_sha},
        signing_status="unsigned",
        assurance_level=AssuranceLevel.OBSERVED,
    )
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)

    policy_dir = tmp_path / "operator_policy"
    policy_dir.mkdir(mode=0o700)
    sig_policy_path = policy_dir / "sig-policy.json"
    sig_policy_path.write_text(
        json.dumps(
            {
                "version": 2,
                "artifacts": [
                    {
                        "kind": "digest-pin",
                        "artifact_path": "models/tuned.safetensors",
                        "expected_sha256": model_sha,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(sig_policy_path, 0o600)

    loaded_pol = load_signature_policies(sig_policy_path, proj_dir)
    verified_profile = build_evidence_profile(
        bom, project_root=proj_dir, signature_policies=loaded_pol
    )
    assert verified_profile["policy_verified"] is True
    tuned_verified = next(
        c for c in verified_profile["components"] if c["bom_ref"] == "model:tuned"
    )
    assert tuned_verified["evidence"]["signed_under_policy"] is False
    assert tuned_verified["evidence"]["digest_pinned_under_policy"] is True
    assert "signed_under_policy" in tuned_verified["missing_evidence"]

    # Mismatched digest pin MUST keep signed_under_policy=False!
    wrong_policy_path = policy_dir / "wrong-policy.json"
    wrong_policy_path.write_text(
        json.dumps(
            {
                "version": 2,
                "artifacts": [
                    {
                        "kind": "digest-pin",
                        "artifact_path": "models/tuned.safetensors",
                        "expected_sha256": "sha256:" + "0" * 64,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(wrong_policy_path, 0o600)
    wrong_pol = load_signature_policies(wrong_policy_path, proj_dir)
    wrong_profile = build_evidence_profile(bom, project_root=proj_dir, signature_policies=wrong_pol)
    assert wrong_profile["policy_loaded"] is True
    assert wrong_profile["policy_verified"] is False
    assert (
        next(c for c in wrong_profile["components"] if c["bom_ref"] == "model:tuned")["evidence"][
            "signed_under_policy"
        ]
        is False
    )

    runner = CliRunner()
    ep_json_file = tmp_path / "ep.json"
    res_ep_cli = runner.invoke(
        main,
        [
            "evidence-profile",
            str(bom_path),
            "--project",
            str(proj_dir),
            "--signature-policy",
            str(sig_policy_path),
            "--json-output",
            "-o",
            str(ep_json_file),
        ],
    )
    assert res_ep_cli.exit_code == 0, res_ep_cli.output
    cli_doc = json.loads(ep_json_file.read_text(encoding="utf-8"))
    assert cli_doc["policy_verified"] is True
    assert (
        next(c for c in cli_doc["components"] if c["bom_ref"] == "model:tuned")["evidence"][
            "digest_pinned_under_policy"
        ]
        is True
    )

    # Symlinked project directory note path on CLI.
    proj_link = tmp_path / "proj_link"
    proj_link.symlink_to(proj_dir)
    res_link_ep = runner.invoke(
        main,
        ["evidence-profile", str(bom_path), "--project", str(proj_link), "--json-output"],
    )
    assert res_link_ep.exit_code == 0

    res_stdout_json = runner.invoke(main, ["evidence-profile", str(bom_path), "--json-output"])
    assert res_stdout_json.exit_code == 0
    assert json.loads(res_stdout_json.stdout)["policy_verified"] is False

    txt_out = tmp_path / "ep.txt"
    res_txt = runner.invoke(main, ["evidence-profile", str(bom_path), "-o", str(txt_out)])
    assert res_txt.exit_code == 0, res_txt.output
    assert "Policy verified: no" in txt_out.read_text(encoding="utf-8")

    res_txt_stdout = runner.invoke(main, ["evidence-profile", str(bom_path)])
    assert res_txt_stdout.exit_code == 0
    assert "Policy verified: no" in res_txt_stdout.stdout

    res_missing_proj = runner.invoke(
        main, ["evidence-profile", str(bom_path), "--signature-policy", str(sig_policy_path)]
    )
    assert res_missing_proj.exit_code == 2

    # Policy inside project must fail closed (exit 2).
    in_proj_pol = proj_dir / "bad-pol.json"
    in_proj_pol.write_text('{"version": 2, "artifacts": []}', encoding="utf-8")
    res_in_proj_pol = runner.invoke(
        main,
        [
            "evidence-profile",
            str(bom_path),
            "--project",
            str(proj_dir),
            "--signature-policy",
            str(in_proj_pol),
        ],
    )
    assert res_in_proj_pol.exit_code == 2


def test_evidence_profile_reuses_one_artifact_budget_and_derives_model_risk(tmp_path):
    from nexus_symbiote.utils.crypto import DigestPinPolicy, SignaturePolicySet

    artifact = tmp_path / "reviewed.safetensors"
    content = b"\x02\x00\x00\x00\x00\x00\x00\x00{}"
    artifact.write_bytes(content)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    model = ModelComponent(
        bom_ref="model:a",
        name="reviewed",
        source_path=artifact.name,
        hashes={"sha256": digest},
        assurance_level=AssuranceLevel.OBSERVED,
        trust_remote_code=True,
    )
    duplicate = model.model_copy(update={"bom_ref": "model:b"})
    risky = ModelComponent(bom_ref="model:c", name="remote", trust_remote_code=True)
    policy = SignaturePolicySet(digest_pins=[DigestPinPolicy(artifact, digest)])
    report = build_evidence_profile(
        AIBOM(components=[duplicate, risky, model]),
        project_root=tmp_path,
        signature_policies=policy,
    )
    first, second, third = report["components"]
    assert report["policy_loaded"] is True
    assert report["policy_verified"] is False
    assert first["evidence"]["digest_bound"] is True
    assert first["evidence"]["digest_pinned_under_policy"] is True
    assert first["evidence"]["signed_under_policy"] is False
    assert first["highest_finding_severity"] == "critical"
    assert second["evidence"]["digest_bound"] is False
    assert second["evidence"]["digest_recorded"] is True
    assert third["finding_count"] == 1
    assert third["highest_finding_severity"] == "critical"


def test_scan_into_import_sbom_reconciles_cleanly_diff_idempotency_and_limits(
    tmp_path: Path,
) -> None:
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "CLAUDE.md").write_text("# Agent project instructions\n", encoding="utf-8")
    (proj / "requirements.txt").write_text("openai==1.52.0\n", encoding="utf-8")
    (proj / "sub").mkdir()
    (proj / "sub" / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "1.2.0"}}),
        encoding="utf-8",
    )
    (proj / "nb.ipynb").write_text("{}", encoding="utf-8")

    runner = CliRunner()
    scan_bom = tmp_path / "scan.aibom.json"
    res_scan = runner.invoke(main, ["scan", str(proj), "-o", str(scan_bom)])
    assert res_scan.exit_code == 0, res_scan.output

    # 1. Empty foreign SBOM merged with --into produces ZERO diff alerts and passes validate --project.
    empty_cdx = tmp_path / "empty.cdx.json"
    empty_cdx.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}),
        encoding="utf-8",
    )
    merged_empty = tmp_path / "merged_empty.aibom.json"
    res_empty = runner.invoke(
        main, ["import-sbom", str(empty_cdx), "--into", str(scan_bom), "-o", str(merged_empty)]
    )
    assert res_empty.exit_code == 0, res_empty.output

    # Also test stdout emission without -o or --json-output.
    res_stdout_bom = runner.invoke(main, ["import-sbom", str(empty_cdx)])
    assert res_stdout_bom.exit_code == 0
    assert json.loads(res_stdout_bom.stdout)["metadata"]["completeness"]["scope"] == "sbom-imported"

    res_diff = runner.invoke(main, ["diff", str(scan_bom), str(merged_empty), "--json-output"])
    assert res_diff.exit_code == 0, res_diff.output
    assert json.loads(res_diff.stdout)["total_changes"] == 0

    res_val_empty = runner.invoke(
        main, ["validate", str(merged_empty), "--project", str(proj), "--json-output"]
    )
    assert res_val_empty.exit_code == 0, res_val_empty.output
    assert json.loads(res_val_empty.stdout)["passed"] is True

    # 2. Matching version (openai==1.52.0 vs SBOM 1.52.0) has 0 conflicts, reconciles with --project,
    #    and re-importing the same SBOM is idempotent (imported_count == 0).
    same_ver_spdx = tmp_path / "supplier.spdx.json"
    same_ver_spdx.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "openai",
                        "versionInfo": "1.52.0",
                        "checksums": [{"algorithm": "SHA256", "checksumValue": "1" * 64}],
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/openai@1.52.0",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    merged_full = tmp_path / "merged_full.aibom.json"
    res_full = runner.invoke(
        main,
        [
            "import-sbom",
            str(same_ver_spdx),
            "--into",
            str(scan_bom),
            "--project",
            str(proj),
            "--walk-manifests",
            "--census",
            "--reveal-names",
            "-o",
            str(merged_full),
            "--json-output",
        ],
    )
    assert res_full.exit_code == 0, res_full.output
    full_summary = json.loads(res_full.stdout)
    assert full_summary["imported_count"] == 1
    assert full_summary["conflict_count"] == 0
    assert full_summary["nested_manifest_components"] == 1

    res_val_full = runner.invoke(
        main, ["validate", str(merged_full), "--project", str(proj), "--json-output"]
    )
    assert res_val_full.exit_code == 0, res_val_full.output
    val_doc = json.loads(res_val_full.stdout)
    assert val_doc["passed"] is True
    assert val_doc["assessment_basis"] == "project-reconciled-with-supplier-claims"

    merged_twice = tmp_path / "merged_twice.aibom.json"
    res_reimport = runner.invoke(
        main,
        [
            "import-sbom",
            str(same_ver_spdx),
            "--into",
            str(merged_full),
            "-o",
            str(merged_twice),
            "--json-output",
        ],
    )
    assert res_reimport.exit_code == 0, res_reimport.output
    assert json.loads(res_reimport.stdout)["imported_count"] == 0

    # 3. CLI guards: -o inside --project, overwriting input, --walk-manifests without --project,
    #    invalid --into BOM, and --limit entries=1 failing closed (exit 1).
    assert (
        runner.invoke(
            main,
            ["import-sbom", str(empty_cdx), "--project", str(proj), "-o", str(proj / "out.json")],
        ).exit_code
        == 2
    )
    assert runner.invoke(main, ["import-sbom", str(empty_cdx), "-o", str(empty_cdx)]).exit_code == 2
    assert runner.invoke(main, ["import-sbom", str(empty_cdx), "--walk-manifests"]).exit_code == 2
    assert (
        runner.invoke(main, ["import-sbom", str(empty_cdx), "--into", str(empty_cdx)]).exit_code
        == 1
    )

    res_limit = runner.invoke(
        main,
        [
            "--limit",
            "entries=1",
            "import-sbom",
            str(empty_cdx),
            "--project",
            str(proj),
            "--census",
        ],
    )
    assert res_limit.exit_code == 1
    assert "limit" in res_limit.output.lower()


def test_sbom_import_and_cli_edge_branches(tmp_path: Path) -> None:
    from nexus_symbiote.core.models import CompletenessClaim
    from nexus_symbiote.sbom_cli import _refuse_source_overwrite
    from nexus_symbiote.sbom_import import _clean_exact_spec, _versions_conflict

    assert _clean_exact_spec(None) is None
    assert _clean_exact_spec("===1.0.0") == "1.0.0"
    assert _clean_exact_spec("=1.0.0") == "1.0.0"
    assert not _versions_conflict(None, "1.0.0")
    assert _versions_conflict(">>bad", "1.0.0")

    import click

    missing = tmp_path / "does_not_exist.json"
    with pytest.raises(click.UsageError):
        _refuse_source_overwrite(missing, missing)

    # Non-UTF8 foreign SBOM & corrupt --into file on CLI.
    runner = CliRunner()
    bad_utf8 = tmp_path / "bad_utf8.json"
    bad_utf8.write_bytes(b"\xff\xfe\x00\x00")
    assert runner.invoke(main, ["import-sbom", str(bad_utf8)]).exit_code == 1
    assert runner.invoke(main, ["evidence-profile", str(bad_utf8)]).exit_code == 1

    # Non-dict JSON root & CycloneDX nesting > 32 & child services & MD5 hash ignored.
    arr_json = tmp_path / "arr.json"
    arr_json.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        import_foreign_sbom(arr_json)

    deep_node: dict[str, object] = {"type": "library", "name": "leaf"}
    for _ in range(35):
        deep_node = {"type": "library", "name": "mid", "components": [deep_node]}
    deep_cdx = tmp_path / "deep.cdx.json"
    deep_cdx.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [deep_node]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="maximum depth"):
        import_foreign_sbom(deep_cdx)

    svc_cdx = tmp_path / "svc.cdx.json"
    svc_cdx.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "library",
                        "name": "parent",
                        "hashes": [{"alg": "MD5", "content": "1234"}],
                        "services": [{"name": "child-svc"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert import_foreign_sbom(svc_cdx, reveal_names=True).imported_count == 2

    # Edge manifests: v1 package-lock dependencies, corrupt locks, unlocked Cargo/go,
    # trailing backslash in requirements, invalid requirement lines, oversized conda, root .devcontainer.json.
    ep = tmp_path / "edge_proj"
    (ep / "v1_js").mkdir(parents=True)
    (ep / "v1_js" / "package.json").write_text(
        json.dumps({"dependencies": {"openai": "^4.0.0", "anthropic": "0.30.0"}}),
        encoding="utf-8",
    )
    (ep / "v1_js" / "package-lock.json").write_text(
        json.dumps({"dependencies": {"openai": {"version": "4.1.0"}}}),
        encoding="utf-8",
    )
    (ep / "bad_locks").mkdir()
    (ep / "bad_locks" / "package.json").write_text(
        json.dumps({"dependencies": {"openai": "^4.0.0"}}), encoding="utf-8"
    )
    (ep / "bad_locks" / "package-lock.json").write_text("{corrupt", encoding="utf-8")
    (ep / "bad_locks" / "pnpm-lock.yaml").write_text("a: &a [1]\nb: *a\n", encoding="utf-8")
    (ep / "bad_locks" / "pyproject.toml").write_text(
        '[project]\ndependencies = ["not a valid req ???", "openai==1.0.0"]\n', encoding="utf-8"
    )
    (ep / "bad_locks" / "uv.lock").write_text("{corrupt-toml", encoding="utf-8")
    (ep / "bad_locks" / "requirements-dev.txt").write_text(
        "-r base.txt\n???invalid\nopenai==1.0.0 \\\n", encoding="utf-8"
    )
    (ep / "setup.cfg").write_text(
        "[options]\ninstall_requires =\n\n    ???bad\n    openai==1.2.0\n", encoding="utf-8"
    )
    (ep / "rs").mkdir()
    (ep / "rs" / "Cargo.toml").write_text(
        '[dependencies]\ncandle-core = "0.8.0"\n', encoding="utf-8"
    )
    (ep / "go").mkdir()
    (ep / "go" / "go.mod").write_text(
        "module x\n\nrequire github.com/sashabaranov/go-openai v1.0.0\n", encoding="utf-8"
    )
    (ep / "big_conda").mkdir()
    (ep / "big_conda" / "conda.yml").write_text("x" * (520 * 1024), encoding="utf-8")
    (ep / ".devcontainer.json").write_text(
        json.dumps({"image": "ollama/ollama:latest"}), encoding="utf-8"
    )
    # Escape symlink inside ep to record non-limit walk warning on CLI.
    (ep / "escape_link").symlink_to(tmp_path)

    res_walk_warn = runner.invoke(
        main,
        ["import-sbom", str(svc_cdx), "--project", str(ep), "--walk-manifests", "--json-output"],
    )
    assert res_walk_warn.exit_code == 0, res_walk_warn.output
    assert "Warning:" in res_walk_warn.output

    # Target BOM with existing completeness records local_failures.
    target = AIBOM()
    target.metadata.completeness = CompletenessClaim(scope="repository")
    imp_with_fail = import_foreign_sbom(svc_cdx, target_aibom=target, project_root=ep)
    assert imp_with_fail.aibom.metadata.completeness is not None
    assert imp_with_fail.aibom.metadata.completeness.scan_failures

    # classify_pinning_state variants (MCP hashed, MCP unpinned, Registry pinned-version & unpinned).
    misc_bom = AIBOM(
        components=[
            MCPServerComponent(bom_ref="mcp:h", name="h", hashes={"sha256": "sha256:" + "1" * 64}),
            MCPServerComponent(bom_ref="mcp:u", name="u", version_pinned=False),
            RegistryEntryComponent(
                bom_ref="reg:p", name="openai", version="1.0.0", registry_type="pypi"
            ),
            RegistryEntryComponent(
                bom_ref="reg:m", name="openai", version="^1.0.0", registry_type="pypi"
            ),
        ]
    )
    st = classify_pinning_state(misc_bom)
    assert st == {
        "mcp:h": "digest-pinned",
        "mcp:u": "unpinned",
        "reg:p": "pinned-version",
        "reg:m": "manifest-only",
    }


def test_re_review_regressions_n1_to_n5_and_ecosystem_ranges(tmp_path: Path) -> None:
    from nexus_symbiote.utils.crypto import SignaturePolicySet

    # Finding 5: major-only and .x wildcards are NOT exact versions.
    assert not is_exact_version("4")
    assert not is_exact_version("1.x")
    assert not is_exact_version("1.2.x")

    # N1: only the artifact covered by the digest pin is verified under that policy.
    proj = tmp_path / "n1_proj"
    (proj / "models").mkdir(parents=True)
    good_bytes = b"\x02\x00\x00\x00\x00\x00\x00\x00{}"
    good_sha = "sha256:" + hashlib.sha256(good_bytes).hexdigest()
    (proj / "models" / "good.safetensors").write_bytes(good_bytes)
    (proj / "models" / "unsigned.safetensors").write_bytes(good_bytes)

    pol_dir = tmp_path / "n1_pol"
    pol_dir.mkdir(mode=0o700)
    pol_file = pol_dir / "pol.json"
    pol_file.write_text(
        json.dumps(
            {
                "version": 2,
                "artifacts": [
                    {
                        "kind": "digest-pin",
                        "artifact_path": "models/good.safetensors",
                        "expected_sha256": good_sha,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(pol_file, 0o600)
    pol = load_signature_policies(pol_file, proj)

    many_models: list[ModelComponent] = [
        ModelComponent(
            bom_ref="model:good",
            name="good",
            source_path="models/good.safetensors",
            serialization_format="safetensors",
            hashes={"sha256": good_sha},
            assurance_level=AssuranceLevel.OBSERVED,
        ),
        ModelComponent(
            bom_ref="model:unsigned",
            name="unsigned",
            source_path="models/unsigned.safetensors",
            serialization_format="safetensors",
            hashes={"sha256": good_sha},
            assurance_level=AssuranceLevel.OBSERVED,
        ),
    ]
    for i in range(1200):
        many_models.append(
            ModelComponent(
                bom_ref=f"model:missing-{i}",
                name=f"missing-{i}",
                source_path=f"models/missing_{i}.safetensors",
                hashes={"sha256": good_sha},
                assurance_level=AssuranceLevel.OBSERVED,
            )
        )
    ep = build_evidence_profile(
        AIBOM(components=many_models), project_root=proj, signature_policies=pol
    )
    pinned_refs = {
        c["bom_ref"] for c in ep["components"] if c["evidence"]["digest_pinned_under_policy"]
    }
    assert pinned_refs == {"model:good"}
    assert not any(c["evidence"]["signed_under_policy"] for c in ep["components"])
    empty_ep = build_evidence_profile(
        AIBOM(components=many_models[:2]),
        project_root=proj,
        signature_policies=SignaturePolicySet(),
    )
    assert empty_ep["policy_verified"] is False

    # N2: symlinks, .docker/config.json, .kube/config, .aws/config, .htpasswd, terraform.tfstate,
    # config/prod.yaml, and empty pkg/__init__.py MUST NEVER match; matched models stay digest_bound=False.
    p2 = tmp_path / "n2_proj"
    for rel, content in [
        (".env", b"SECRET_ENV_VALUE=1234567890\n"),
        (".docker/config.json", b'{"auths":{"x":{"auth":"dGVzdA=="}}}'),
        (".kube/config", b"apiVersion: v1\nclusters: []\n"),
        (".aws/config", b"[default]\nregion = us-east-1\n"),
        (".htpasswd", b"admin:$apr1$xyz$1234567890\n"),
        ("terraform.tfstate", b'{"version":4,"outputs":{"pw":"x"}}'),
        ("config/prod.yaml", b"db_password: secret_value\n"),
        ("pkg/__init__.py", b""),
        ("models/real.bin", b"real-model-weights-payload"),
    ]:
        f = p2 / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(content)
    (p2 / "link_env.bin").symlink_to(".env")

    probes = [
        {
            "type": "machine-learning-model",
            "name": f"probe-{idx}",
            "version": "1.0.0",
            "hashes": [
                {"alg": "SHA-256", "content": hashlib.sha256((p2 / rel).read_bytes()).hexdigest()}
            ],
        }
        for idx, rel in enumerate(
            [
                ".env",
                ".docker/config.json",
                ".kube/config",
                ".aws/config",
                ".htpasswd",
                "terraform.tfstate",
                "config/prod.yaml",
                "pkg/__init__.py",
                "models/real.bin",
            ]
        )
    ]
    n2_sbom = tmp_path / "n2.cdx.json"
    n2_sbom.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": probes}),
        encoding="utf-8",
    )
    n2_res = import_foreign_sbom(n2_sbom, project_root=p2, reveal_names=True)
    assert n2_res.bound_local_count == 1
    matched_comp = next(
        c for c in n2_res.aibom.components if "declared_digest_local_match" in c.properties
    )
    assert matched_comp.properties["declared_digest_local_match"] == "models/real.bin"
    assert matched_comp.properties["pinning_state"] == "pinned-version"
    n2_ep = build_evidence_profile(n2_res.aibom)
    assert all(not c["evidence"]["digest_bound"] for c in n2_ep["components"])

    # N3: unnamed {} entries exceeding 10,000 fail closed.
    unnamed_sbom = tmp_path / "unnamed.cdx.json"
    unnamed_sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{} for _ in range(MAX_FOREIGN_COMPONENTS + 5)],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="maximum component count"):
        import_foreign_sbom(unnamed_sbom)

    # N5 + Finding 6: @anthropic-ai/sdk & @langchain/core in nested package.json; npm ^/~/*, ==1.2.*, and pypi vs npm.
    n5_proj = tmp_path / "n5_proj"
    (n5_proj / "web").mkdir(parents=True)
    (n5_proj / "web" / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "@anthropic-ai/sdk": "^0.30.0",
                    "@langchain/core": "~0.3.0",
                    "openai": "4",
                }
            }
        ),
        encoding="utf-8",
    )
    nested_n5, fails_n5 = walk_nested_manifests(n5_proj)
    assert not fails_n5
    n5_map = {c.name: c.properties["pinning_state"] for c in nested_n5}
    assert n5_map == {
        "@anthropic-ai/sdk": "manifest-only",
        "@langchain/core": "manifest-only",
        "openai": "manifest-only",
    }

    eco_base = AIBOM(
        components=[
            RegistryEntryComponent(
                bom_ref="pkg:pypi-openai", name="openai", version="==1.2.*", registry_type="pypi"
            ),
            RegistryEntryComponent(
                bom_ref="pkg:npm-sdk",
                name="@anthropic-ai/sdk",
                version="^0.30.0",
                registry_type="npm",
            ),
            RegistryEntryComponent(
                bom_ref="pkg:npm-lc", name="@langchain/core", version="~0.3.0", registry_type="npm"
            ),
            RegistryEntryComponent(
                bom_ref="pkg:npm-any", name="ai", version="*", registry_type="npm"
            ),
        ]
    )
    eco_sbom = tmp_path / "eco.cdx.json"
    eco_sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "library",
                        "name": "openai",
                        "version": "1.2.5",
                        "purl": "pkg:pypi/openai@1.2.5",
                    },
                    {
                        "type": "library",
                        "name": "openai",
                        "version": "4.2.0",
                        "purl": "pkg:npm/openai@4.2.0",
                    },
                    {
                        "type": "library",
                        "name": "@anthropic-ai/sdk",
                        "version": "0.30.1",
                        "purl": "pkg:npm/%40anthropic-ai/sdk@0.30.1",
                    },
                    {
                        "type": "library",
                        "name": "@langchain/core",
                        "version": "0.3.5",
                        "purl": "pkg:npm/%40langchain/core@0.3.5",
                    },
                    {
                        "type": "library",
                        "name": "ai",
                        "version": "3.4.0",
                        "purl": "pkg:npm/ai@3.4.0",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    assert import_foreign_sbom(eco_sbom, target_aibom=eco_base).conflict_count == 0


def _cdx(path: Path, *components: dict[str, object]) -> Path:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": list(components)}
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_import_sbom_project_binds_weights_over_file_bytes_and_names_a_skipped_one(
    tmp_path: Path,
) -> None:
    proj = tmp_path / "proj"
    (proj / "models").mkdir(parents=True)
    weights = b"\x07" * (5 * 1024 * 1024)
    (proj / "models" / "w.bin").write_bytes(weights)
    model = {"type": "machine-learning-model", "name": "w", "version": "1"}
    sha = hashlib.sha256(weights).hexdigest()
    hashed = _cdx(
        tmp_path / "hashed.json", {**model, "hashes": [{"alg": "SHA-256", "content": sha}]}
    )
    out = tmp_path / "out.json"
    runner = CliRunner()

    def run(*args: str) -> tuple[int, str]:
        res = runner.invoke(main, [*args, "--project", str(proj), "-o", str(out), "--json-output"])
        return res.exit_code, res.output

    code, text = run("import-sbom", str(hashed))
    assert code == 0, text
    assert '"bound_local_count": 1' in text
    assert '"scan_failure_count": 0' in text

    code, text = run("--limit", "model-bytes=1MiB", "import-sbom", str(hashed))
    assert code == 0, text
    assert '"bound_local_count": 0' in text
    assert "Warning: models/w.bin: exceeds model-bytes; not hashed, so left unbound" in text
    written = AIBOM.load(out)
    assert written.metadata.completeness is not None
    assert written.metadata.completeness.scan_failures == [
        "models/w.bin: exceeds model-bytes; not hashed, so left unbound"
    ]
    assert all("declared_digest_local_match" not in c.properties for c in written.components)

    code, text = run("--limit", "model-total-bytes=1MiB", "import-sbom", str(hashed))
    assert code == 1
    assert "Collection limit exceeded under --project: models/w.bin: model-total-bytes" in text

    unhashed = _cdx(tmp_path / "unhashed.json", model)
    code, text = run("--limit", "model-total-bytes=1MiB", "import-sbom", str(unhashed))
    assert code == 0, text
    assert '"scan_failure_count": 0' in text


def test_import_sbom_entry_without_purl_conflicts_with_any_ecosystem(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("openai==1.0.0\n", encoding="utf-8")
    base = tmp_path / "base.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(proj), "-o", str(base)]).exit_code == 0
    local = [c for c in AIBOM.load(base).components if c.name == "openai"]
    assert [c.version for c in local] == ["==1.0.0"]

    bare = _cdx(tmp_path / "bare.json", {"name": "openai", "version": "2.0.0"})
    res = runner.invoke(main, ["import-sbom", str(bare), "--into", str(base), "--json-output"])
    assert res.exit_code == 0, res.output
    assert '"conflict_count": 1' in res.output

    summary = import_foreign_sbom(bare, target_aibom=AIBOM.load(base))
    assert summary.conflict_count == 1
    flagged = {c.bom_ref for c in summary.aibom.components if c.risks}
    assert flagged == {local[0].bom_ref, summary.conflicts[0].split(": ")[0]}
    assert all(r.category == "source_conflict" for c in summary.aibom.components for r in c.risks)

    # The same disagreement inside one document, in either order.
    npm = {"name": "openai", "version": "4.2.0", "purl": "pkg:npm/openai@4.2.0"}
    pypi = {"name": "openai", "version": "1.0.0", "purl": "pkg:pypi/openai@1.0.0"}
    none = {"name": "openai", "version": "2.0.0"}
    for order, expected in (([pypi, none], 1), ([none, pypi], 1), ([pypi, npm], 0)):
        doc = _cdx(tmp_path / "mixed.json", *order)
        assert import_foreign_sbom(doc).conflict_count == expected, order

    # An agreeing entry without a purl is no conflict.
    same = _cdx(tmp_path / "same.json", {"name": "openai", "version": "1.0.0"})
    assert import_foreign_sbom(same, target_aibom=AIBOM.load(base)).conflict_count == 0
