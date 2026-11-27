"""Tests for the offline ``k8s-drift`` cluster CycloneDX ML-BOM vs AgentBOM check."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    A2AServerComponent,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
)
from nexus_symbiote.generators.validation import validate_sarif
from nexus_symbiote.modes import Mode, enforce
from nexus_symbiote.runtime_bom_drift import (
    ASSURANCE,
    FORMAT,
    MAX_RUNTIME_BOMS,
    MAX_RUNTIME_DEPTH,
    RuntimeBOMInputError,
    collect,
    render,
    sarif_document,
)

_SYNTHETIC_CRED = "sk-ant-" + "api03-clustersecret1234567890"
_SHA_A = "a" * 64
_SHA_B = "b" * 64
_SHA_C = "c" * 64


def _write_static_bom(tmp_path: Path) -> Path:
    bom = AIBOM(
        components=[
            ModelComponent(
                bom_ref="model:llama3",
                name="meta-llama/Llama-3.1-8B",
                version="1.0.0",
                requested_alias="llama-3.1-8b",
                hashes={"SHA-256": _SHA_A},
            ),
            MCPServerComponent(
                bom_ref="mcp:tools",
                name="tools-gateway",
                version="2.1.0",
                endpoint_url="https://tools.cluster.local:8443/mcp",
            ),
            A2AServerComponent(
                bom_ref="a2a:planner",
                name="planner-agent",
                version="1.0.0",
                endpoint_url="https://planner.cluster.local/a2a",
            ),
            RegistryEntryComponent(
                bom_ref="pkg:oci/agent-runner",
                name="ghcr.io/org/agent-runner",
                version=f"sha256:{_SHA_A}",
                package_url=f"pkg:oci/agent-runner@sha256:{_SHA_A}",
                registry_type="oci",
            ),
            RegistryEntryComponent(
                bom_ref="pkg:oci/unpinned-sidecar",
                name="ghcr.io/org/sidecar",
                version="1.2.0",
                package_url="pkg:oci/sidecar:1.2.0",
                registry_type="oci",
            ),
            RegistryEntryComponent(
                bom_ref="pkg:pypi/langchain-core",
                name="langchain-core",
                version="0.3.1",
                package_url="pkg:pypi/langchain-core@0.3.1",
                registry_type="pypi",
            ),
            RegistryEntryComponent(
                bom_ref="pkg:pypi/unobserved-sdk",
                name="openai",
                version="1.50.0",
                registry_type="pypi",
            ),
        ]
    )
    path = tmp_path / "static.aibom.json"
    path.write_text(bom.to_native_json(), encoding="utf-8")
    return path


def _cdx(
    *,
    components: list[dict[str, Any]] | None = None,
    services: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
    spec_version: str = "1.6",
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
    }
    if metadata is not None:
        doc["metadata"] = metadata
    if components is not None:
        doc["components"] = components
    if services is not None:
        doc["services"] = services
    return doc


def test_clean_cluster_match_and_reported_assurance(tmp_path):
    inv = _write_static_bom(tmp_path)
    runtime = tmp_path / "cluster.cdx.json"
    runtime.write_text(
        json.dumps(
            _cdx(
                metadata={
                    "properties": [
                        {"name": "k8s.namespace", "value": "ai-prod"},
                        {"name": "other.prop", "value": "ignored"},
                        "not-a-dict",
                        {"name": 123, "value": "skip"},
                        *[{"name": f"k8s.tag{i}", "value": f"v{i}"} for i in range(20)],
                    ],
                    "component": {
                        "type": "container",
                        "name": "ghcr.io/org/agent-runner",
                        "version": f"sha256:{_SHA_A}",
                        "purl": f"pkg:oci/agent-runner@sha256:{_SHA_A}",
                    },
                },
                services=[
                    {
                        "name": "tools-gateway",
                        "version": "2.1.0",
                        "endpoints": ["https://tools.cluster.local:8443/mcp", "http://"],
                    },
                    {
                        "name": "planner-agent",
                        "version": "1.0.0",
                        "endpoints": ["https://planner.cluster.local/a2a"],
                    },
                ],
                components=[
                    {
                        "type": "machine-learning-model",
                        "name": "llama-3.1-8b:latest",
                        "version": "1.0.0",
                        "hashes": [{"alg": "SHA-256", "content": _SHA_A}],
                    },
                    {
                        "type": "library",
                        "name": "langchain_core",
                        "version": "0.3.1",
                        "purl": "pkg:pypi/langchain-core@0.3.1",
                    },
                    # Non-AI OS package & non-package asset ignored cleanly.
                    {"type": "library", "name": "libc6", "version": "2.39"},
                    {"type": "file", "name": "/etc/passwd"},
                ],
            )
        ),
        encoding="utf-8",
    )

    with enforce(Mode.OFFLINE):
        doc = collect(inv, [runtime], fail_on="drift")

    assert doc["format"] == FORMAT
    assert doc["assurance"] == ASSURANCE
    assert doc["gate"]["passed"] is True
    assert doc["coverage"]["non_ai_packages_ignored"] == 2
    assert len(doc["reconciliation"]["matched"]) == 5
    assert doc["reconciliation"]["drifted"] == []
    assert doc["reconciliation"]["undeclared"] == []
    assert doc["reconciliation"]["mutable_tags"] == []
    assert any(
        u["bom_ref"] == "pkg:pypi/unobserved-sdk" for u in doc["reconciliation"]["unobserved"]
    )
    assert doc["reconciliation"]["matched"][0]["cluster_context"]["k8s.namespace"] == "ai-prod"
    assert render(doc) == render(doc)

    sarif = sarif_document(doc, ".nexus-symbiote.yaml")
    assert validate_sarif(sarif) == []
    assert sarif["runs"][0]["results"] == []


def test_drift_mutable_tags_undeclared_sanitization_and_sarif(tmp_path):
    inv = _write_static_bom(tmp_path)
    runtime_a = tmp_path / "a.cdx.json"
    runtime_b = tmp_path / "b.cdx.json"

    runtime_a.write_text(
        json.dumps(
            _cdx(
                services=[
                    {
                        "name": "tools-gateway",
                        "version": "9.9.9",
                        "endpoints": ["https://wrong.cluster.local:9000/v2"],
                    },
                    {
                        "name": f"shadow-mcp\x1b[31m-{_SYNTHETIC_CRED}",
                        "endpoints": ["https://evil.example.com/sse"],
                    },
                ],
                components=[
                    {
                        "type": "machine-learning-model",
                        "name": "meta-llama/Llama-3.1-8B",
                        "version": "1.0.1",
                        "hashes": [{"alg": "SHA-256", "content": _SHA_B}],
                    },
                    {
                        "type": "container",
                        "name": "ghcr.io/org/sidecar:latest",
                        "version": "latest",
                        "purl": "pkg:oci/sidecar:latest",
                        "properties": [{"name": "k8s.workload", "value": "deployment/sidecar"}],
                    },
                ],
            )
        ),
        encoding="utf-8",
    )
    runtime_b.write_text(
        json.dumps(
            _cdx(
                spec_version="1.7",
                components=[
                    {
                        "type": "machine-learning-model",
                        "name": "rogue\u202emodel",
                        "version": "0.1",
                        "hashes": [{"alg": "SHA-256", "content": _SHA_C}],
                    },
                    {
                        "type": "container",
                        "name": "unpinned-worker",
                        "purl": "pkg:docker/worker",
                    },
                ],
            )
        ),
        encoding="utf-8",
    )

    doc_undeclared = collect(inv, [runtime_a, runtime_b], fail_on="undeclared")
    assert doc_undeclared["gate"]["passed"] is False
    rec = doc_undeclared["reconciliation"]
    assert len(rec["undeclared"]) == 3  # shadow-mcp, rogue model, unpinned-worker
    assert len(rec["drifted"]) == 3  # tools-gateway (ver+ep), llama3 (ver+sha), sidecar (ver)
    assert len(rec["mutable_tags"]) == 1  # sidecar:latest

    reasons_by_name = {d["name"]: d["drift_reasons"] for d in rec["drifted"]}
    assert "digest_mismatch" in reasons_by_name["meta-llama/Llama-3.1-8B"]
    assert "version_mismatch" in reasons_by_name["meta-llama/Llama-3.1-8B"]
    assert reasons_by_name["tools-gateway"] == ["version_mismatch", "endpoint_mismatch"]

    # Deterministic order regardless of CLI arg ordering
    assert render(collect(inv, [runtime_b, runtime_a])) == render(
        collect(inv, [runtime_a, runtime_b])
    )

    # SARIF validation + secret redaction + URL defanging
    sarif = sarif_document(doc_undeclared, ".nexus-symbiote.yaml")
    assert validate_sarif(sarif) == []
    sarif_text = json.dumps(sarif)
    assert _SYNTHETIC_CRED not in sarif_text
    assert "\x1b" not in sarif_text
    assert "\u202e" not in sarif_text
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {
        f"nexus_symbiote/runtime_undeclared/{RiskSeverity.HIGH.value}",
        f"nexus_symbiote/data_integrity/{RiskSeverity.HIGH.value}",
        f"nexus_symbiote/mutable_image_tag/{RiskSeverity.MEDIUM.value}",
    }


def test_runtime_bom_input_refusals(tmp_path):
    inv = _write_static_bom(tmp_path)

    with pytest.raises(RuntimeBOMInputError, match="between 1 and"):
        collect(inv, [])
    with pytest.raises(RuntimeBOMInputError, match="between 1 and"):
        collect(inv, [inv] * (MAX_RUNTIME_BOMS + 1))

    # Symlink refused
    real = tmp_path / "real.cdx.json"
    real.write_text(json.dumps(_cdx(components=[])), encoding="utf-8")
    link = tmp_path / "link.cdx.json"
    link.symlink_to(real)
    with pytest.raises(RuntimeBOMInputError, match="symbolic link"):
        collect(inv, [link])

    # Missing & non-CycloneDX & unsupported version & duplicate JSON keys & deep nesting & bad UTF-8
    missing = tmp_path / "missing.cdx.json"
    with pytest.raises(RuntimeBOMInputError, match="does not exist"):
        collect(inv, [missing])

    not_cdx = tmp_path / "spdx.json"
    not_cdx.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
    with pytest.raises(RuntimeBOMInputError, match="bomFormat='CycloneDX'"):
        collect(inv, [not_cdx])

    bad_ver = tmp_path / "old.cdx.json"
    bad_ver.write_text(json.dumps(_cdx(spec_version="1.2")), encoding="utf-8")
    with pytest.raises(RuntimeBOMInputError, match="specVersion"):
        collect(inv, [bad_ver])

    dup = tmp_path / "dup.cdx.json"
    dup.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"version":2}')
    with pytest.raises(RuntimeBOMInputError, match="duplicate keys"):
        collect(inv, [dup])

    arr = tmp_path / "arr.cdx.json"
    arr.write_text("[1, 2, 3]")
    with pytest.raises(RuntimeBOMInputError, match="JSON object"):
        collect(inv, [arr])

    bad_utf8 = tmp_path / "raw.cdx.json"
    bad_utf8.write_bytes(b"\xff\xfe")
    with pytest.raises(RuntimeBOMInputError, match="UTF-8"):
        collect(inv, [bad_utf8])

    deep: Any = {"type": "library", "name": "torch"}
    for _ in range(MAX_RUNTIME_DEPTH + 4):
        deep = [deep]
    nested = tmp_path / "deep.cdx.json"
    nested.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "x": deep}))
    with pytest.raises(RuntimeBOMInputError, match="nesting limit"):
        collect(inv, [nested])


def test_k8s_drift_cli_gates_outputs_and_errors(tmp_path, runner):
    inv = _write_static_bom(tmp_path)
    drifted_only = tmp_path / "drifted.cdx.json"
    drifted_only.write_text(
        json.dumps(
            _cdx(
                components=[
                    {
                        "type": "container",
                        "name": "ghcr.io/org/sidecar:main",
                        "version": "main",
                        "purl": "pkg:oci/sidecar@main",
                    }
                ]
            )
        ),
        encoding="utf-8",
    )

    out_json = tmp_path / "drift.json"
    out_sarif = tmp_path / "drift.sarif"

    # --fail-on undeclared passes when only matched drift/mutable-tag exists
    ok_res = runner.invoke(
        main,
        [
            "k8s-drift",
            str(inv),
            str(drifted_only),
            "-o",
            str(out_json),
            "--sarif",
            str(out_sarif),
        ],
    )
    assert ok_res.exit_code == 0, ok_res.output
    assert out_json.exists()
    assert validate_sarif(json.loads(out_sarif.read_text(encoding="utf-8"))) == []

    # --fail-on drift fails with exit 1 on drifted + mutable tag
    drift_fail = runner.invoke(
        main,
        ["k8s-drift", str(inv), str(drifted_only), "--fail-on", "drift", "--json-output"],
    )
    assert drift_fail.exit_code == 1
    assert json.loads(drift_fail.stdout)["gate"]["passed"] is False

    # --fail-on none never fails even on empty BOM
    empty_cdx = tmp_path / "empty.cdx.json"
    empty_cdx.write_text(json.dumps(_cdx(components=[])), encoding="utf-8")
    empty_fail = runner.invoke(main, ["k8s-drift", str(inv), str(empty_cdx)])
    assert empty_fail.exit_code == 1
    report_only = runner.invoke(main, ["k8s-drift", str(inv), str(empty_cdx), "--fail-on", "none"])
    assert report_only.exit_code == 0, report_only.output

    # Overwrite protection and bad inputs
    overwrite = runner.invoke(main, ["k8s-drift", str(inv), str(drifted_only), "-o", str(inv)])
    assert overwrite.exit_code == 2
    same_outs = runner.invoke(
        main,
        ["k8s-drift", str(inv), str(drifted_only), "-o", str(out_json), "--sarif", str(out_json)],
    )
    assert same_outs.exit_code == 2

    too_many = runner.invoke(
        main, ["k8s-drift", str(inv), *([str(drifted_only)] * (MAX_RUNTIME_BOMS + 1))]
    )
    assert too_many.exit_code == 2

    bad_inv = tmp_path / "bad.aibom.json"
    bad_inv.write_text("{bad", encoding="utf-8")
    assert runner.invoke(main, ["k8s-drift", str(bad_inv), str(drifted_only)]).exit_code == 1

    sym_rt = tmp_path / "sym.cdx.json"
    sym_rt.symlink_to(drifted_only)
    assert runner.invoke(main, ["k8s-drift", str(inv), str(sym_rt)]).exit_code == 1


def test_mutability_helpers_endpoint_defaults_and_edge_branches(tmp_path, monkeypatch):
    from nexus_symbiote import runtime_bom_drift as mod

    assert mod._clean("x" * 700, limit=16).endswith("...")
    assert mod._normalize_sha256("not-a-hash") is None
    assert mod._normalize_endpoint("") is None
    assert mod._normalize_endpoint("http://svc.cluster.local/api") == "svc.cluster.local:80/api"
    assert mod._normalize_endpoint("https://") is None
    assert mod._check_container_mutability("img", "sha256:" + _SHA_A, None) is None
    assert (
        mod._check_container_mutability("img", "latest", None) == "mutable container tag ':latest'"
    )
    assert (
        mod._check_container_mutability("img:nightly", None, None)
        == "mutable container tag ':nightly'"
    )
    assert (
        mod._static_sha256(
            RegistryEntryComponent(bom_ref="r:1", name="x", hashes={"sha512": _SHA_A * 2})
        )
        is None
    )

    # Duplicate component split across two BOMs fills missing sha256 & merges endpoints
    inv = _write_static_bom(tmp_path)
    p1 = tmp_path / "p1.cdx.json"
    p2 = tmp_path / "p2.cdx.json"
    p1.write_text(
        json.dumps(
            _cdx(
                services=[
                    {"name": "tools-gateway", "version": "2.1.0", "endpoints": ["https://a:443"]}
                ],
                components=[
                    {"type": "machine-learning-model", "name": "llama-3.1-8b", "version": "1.0.0"}
                ],
            )
        ),
        encoding="utf-8",
    )
    p2.write_text(
        json.dumps(
            _cdx(
                services=[
                    {
                        "name": "tools-gateway",
                        "version": "2.1.0",
                        "endpoints": ["https://tools.cluster.local:8443/mcp"],
                    }
                ],
                components=[
                    {
                        "type": "machine-learning-model",
                        "name": "llama-3.1-8b",
                        "version": "1.0.0",
                        "hashes": [{"alg": "SHA-256", "content": _SHA_A}],
                    }
                ],
            )
        ),
        encoding="utf-8",
    )
    merged = collect(inv, [p1, p2])
    assert any(
        m["name"] == "llama-3.1-8b" and m["sha256"] == f"sha256:{_SHA_A}"
        for m in merged["reconciliation"]["matched"]
    )

    # Size limit & non-regular error + permission error + missing digest fallback + large SARIF cap
    monkeypatch.setattr(mod, "MAX_FOREIGN_SBOM_BYTES", 8)
    with pytest.raises(RuntimeBOMInputError, match="byte limit"):
        collect(inv, [p1])
    monkeypatch.undo()

    from nexus_symbiote.generators import sarif as sarif_mod

    monkeypatch.setattr(sarif_mod, "GITHUB_MAX_RESULTS", 1)
    monkeypatch.setattr(
        mod, "inventory_content_digest", lambda _d: (_ for _ in ()).throw(ValueError("bad"))
    )
    assert mod._check_container_mutability("img", None, f"pkg:oci/img@sha256:{_SHA_A}") is None
    assert "without digest" in (mod._check_container_mutability("img", None, "pkg:oci/img") or "")
    assert "no immutable" in (mod._check_container_mutability("img", None, None) or "")
    huge_rt = tmp_path / "many.cdx.json"
    huge_rt.write_text(
        json.dumps(
            _cdx(
                components=[
                    {
                        "type": "container",
                        "name": f"rogue-{i}:latest",
                        "purl": f"pkg:oci/rogue-{i}:latest",
                    }
                    for i in range(3)
                ]
            )
        ),
        encoding="utf-8",
    )
    doc_many = collect(inv, [huge_rt])
    assert doc_many["inputs"]["inventory"]["content_digest"] is None
    sarif_many = sarif_document(doc_many, ".nexus-symbiote.yaml")
    assert len(sarif_many["runs"][0]["invocations"][0]["toolExecutionNotifications"]) == 2
    # CLI human text output for undeclared items
    from click.testing import CliRunner

    text_res = CliRunner().invoke(main, ["k8s-drift", str(inv), str(huge_rt)])
    assert text_res.exit_code == 1
    assert "Undeclared (container):" in text_res.output

    # Permission & non-regular open error formatting
    assert "not a regular file" in mod._open_error(p1, OSError(None, "dir"))
    perm = PermissionError(13, "denied")
    assert "cannot be read" in mod._open_error(p1, perm)
    assert "exceeds bounds" in mod._open_error(p1, OSError(5, "eio"))
