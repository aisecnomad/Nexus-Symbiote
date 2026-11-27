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
                        "endpoints": ["https://tools.cluster.local:8443/mcp"],
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

    hardlink = tmp_path / "also-real.json"
    hardlink.hardlink_to(real)
    with pytest.raises(RuntimeBOMInputError, match="single-link"):
        collect(inv, [hardlink])

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
    assert (
        mod._normalize_endpoint("http://svc.cluster.local/api") == "http://svc.cluster.local:80/api"
    )
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

    # Distinct snapshots retain their own digests and endpoints.
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


def test_cluster_identities_and_endpoints(tmp_path):
    inv = _write_static_bom(tmp_path)
    rt = tmp_path / "reported.cdx.json"
    rt.write_text(
        json.dumps(
            _cdx(
                components=[
                    {"type": "library", "name": "openai", "purl": "pkg:npm/openai@1.50.0"},
                    {"type": "library", "name": "openai", "purl": "pkg:pypi/openai@1.50.0"},
                    {
                        "type": "machine-learning-model",
                        "name": "other/Llama-3.1-8B",
                        "version": "1.0.0",
                    },
                    {
                        "type": "machine-learning-model",
                        "name": "Llama-3.1-8B",
                        "supplier": {"name": "other"},
                        "version": "1.0.0",
                    },
                ],
                services=[
                    {"name": "tools-gateway", "endpoints": ["https://planner.cluster.local/a2a"]},
                    {"name": "tools-gateway", "endpoints": []},
                    {"name": "tools-gateway", "endpoints": ["http://tools.cluster.local:8443/mcp"]},
                    {
                        "name": "tools-gateway",
                        "endpoints": [
                            "https://tools.cluster.local:8443/mcp",
                            "https://aux.cluster.local/mcp",
                        ],
                    },
                ],
                metadata={
                    "properties": [
                        {"name": "cdx:k8s:token", "value": "ordinary-property-sample"},
                        {"name": "k8s.namespace", "value": "training"},
                    ]
                },
            )
        )
    )
    with enforce(Mode.OFFLINE):
        result = collect(inv, [rt], fail_on="drift")
    assert not result["gate"]["passed"]
    rec = result["reconciliation"]
    assert [x["purl"] for x in rec["matched"]] == ["pkg:pypi/openai@1.50.0"]
    assert sorted(x["name"] for x in rec["undeclared"]) == [
        "Llama-3.1-8B",
        "openai",
        "other/Llama-3.1-8B",
    ]
    assert len(rec["drifted"]) == 4
    assert all(x["drift_reasons"] == ["endpoint_mismatch"] for x in rec["drifted"])
    assert "ordinary-property-sample" not in render(result)
    assert rec["matched"][0]["cluster_context"]["k8s.namespace"] == "training"


def test_each_declaration_binds_one_version_and_digest(tmp_path):
    inv = tmp_path / "inventory.json"
    inv.write_text(
        AIBOM(
            components=[
                ModelComponent(
                    name="org/weights", bom_ref="model:a", version="1", hashes={"SHA-256": _SHA_A}
                ),
                ModelComponent(
                    name="org/weights", bom_ref="model:b", version="2", hashes={"SHA-256": _SHA_B}
                ),
                RegistryEntryComponent(
                    name="openai", bom_ref="pkg:openai", version="==1.9.0", registry_type="pypi"
                ),
            ]
        ).to_native_json()
    )
    reports = []
    for label, digest in (("first", _SHA_A), ("second", _SHA_B)):
        path = tmp_path / f"{label}.json"
        path.write_text(
            json.dumps(
                _cdx(
                    components=[
                        {
                            "type": "machine-learning-model",
                            "name": "org/weights",
                            "version": "1",
                            "hashes": [{"alg": "SHA-256", "content": digest}],
                        },
                        {"type": "library", "name": "openai", "purl": "pkg:pypi/openai@1.9.0"},
                    ]
                )
            )
        )
        reports.append(path)
    with enforce(Mode.OFFLINE):
        one = collect(inv, [reports[1]], fail_on="drift")
        combined = collect(inv, reports, fail_on="drift")
        assert render(combined) == render(collect(inv, reports[::-1], fail_on="drift"))
    assert not one["gate"]["passed"]
    assert one["reconciliation"]["drifted"][0]["drift_reasons"] == [
        "version_mismatch",
        "digest_mismatch",
    ]
    assert combined["reconciliation"]["matched"][0]["inventory_refs"] == ["pkg:openai"]
    assert not combined["gate"]["passed"]
    assert {r["sha256"] for r in combined["reconciliation"]["drifted"]} == {
        f"sha256:{_SHA_A}",
        f"sha256:{_SHA_B}",
    }
    assert all(
        "conflicting_reported_digests" in r["drift_reasons"]
        for r in combined["reconciliation"]["drifted"]
    )
    assert len(sarif_document(combined, "inventory.json")["runs"][0]["results"]) == 2


def test_cluster_image_pin_and_observation_cap(tmp_path, monkeypatch):
    from nexus_symbiote import runtime_bom_drift as mod

    inv = _write_static_bom(tmp_path)
    rt = tmp_path / "reported.cdx.json"
    rt.write_text(
        json.dumps(
            _cdx(
                components=[
                    {"type": "container", "name": "ghcr.io/org/agent-runner@sha256:" + _SHA_B},
                    {"type": "container", "name": "ghcr.io/org/agent-runner@sha256:" + _SHA_A},
                    {"type": "container", "name": "ghcr.io/org/sidecar:1.2.0", "version": "1.2.0"},
                ]
            )
        )
    )
    result = collect(inv, [rt], fail_on="drift")
    assert not result["gate"]["passed"]
    assert [r["name"] for r in result["reconciliation"]["mutable_tags"]] == [
        "ghcr.io/org/sidecar:1.2.0"
    ]
    assert any("digest_mismatch" in r["drift_reasons"] for r in result["reconciliation"]["drifted"])
    assert mod._check_container_mutability("image@sha512:" + "a" * 128, None, None) is None
    assert mod._check_container_mutability("image", _SHA_A, None)
    monkeypatch.setattr(mod, "MAX_DRIFT_ITEMS", 2)
    with pytest.raises(RuntimeBOMInputError, match="observation limit"):
        collect(inv, [rt], fail_on="none")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"components": [None]}, "objects"),
        ({"components": None}, "JSON array"),
        ({"metadata": {"component": []}}, "objects"),
        ({"components": [{"name": "model"}]}, "type"),
        ({"components": [{"type": "library", "name": "torch", "version": 1}]}, "version"),
        (
            {"components": [{"type": "library", "name": "torch", "purl": "unstructured"}]},
            "package URL",
        ),
        (
            {
                "components": [
                    {"type": "library", "name": "torch", "purl": "pkg:pypi/torch@1", "version": "2"}
                ]
            },
            "disagree",
        ),
        ({"services": [{"name": "chat", "endpoints": 123}]}, "endpoints"),
        ({"services": [{"name": "chat", "endpoints": ["https://"]}]}, "no host"),
        ({"services": [{"name": "chat", "endpoints": ["https://host:port"]}]}, "host or port"),
        ({"services": [{"name": "chat", "services": {}}]}, "nested services"),
        ({"components": [{"type": "library", "name": "torch", "hashes": {}}]}, "array"),
        (
            {"components": [{"type": "library", "name": "torch", "hashes": [{"content": "aaa"}]}]},
            "algorithm",
        ),
        (
            {
                "components": [
                    {
                        "type": "library",
                        "name": "torch",
                        "hashes": [{"alg": "SHA-256", "content": "abc"}],
                    }
                ]
            },
            "invalid value",
        ),
        (
            {
                "components": [
                    {
                        "type": "library",
                        "name": "torch",
                        "hashes": [
                            {"alg": "SHA-256", "content": _SHA_A},
                            {"alg": "SHA-256", "content": _SHA_B},
                        ],
                    }
                ]
            },
            "conflicting",
        ),
        (
            {
                "components": [
                    {
                        "type": "container",
                        "name": "image@sha256:" + _SHA_A,
                        "purl": "pkg:oci/image@sha256:" + _SHA_B,
                    }
                ]
            },
            "conflicting",
        ),
        (
            {
                "components": [
                    {
                        "type": "container",
                        "name": "image@sha256:" + _SHA_A,
                        "hashes": [{"alg": "SHA-256", "content": _SHA_B}],
                    }
                ]
            },
            "disagree",
        ),
    ],
)
def test_invalid_comparison_fields_are_refused(tmp_path, change, message):
    inv = _write_static_bom(tmp_path)
    rt = tmp_path / "reported.cdx.json"
    rt.write_text(json.dumps({**_cdx(), **change}))
    with enforce(Mode.OFFLINE), pytest.raises(RuntimeBOMInputError, match=message):
        collect(inv, [rt], fail_on="none")


def test_qualified_model_names_retain_snapshot_supplier_and_one_declaration(tmp_path):
    def write_snapshot(path, supplier, digest):
        path.write_text(
            json.dumps(
                _cdx(
                    components=[
                        {
                            "type": "machine-learning-model",
                            "name": "fieldlab/forecast",
                            "version": "1",
                            "supplier": {"name": supplier},
                            "hashes": [{"alg": "SHA-256", "content": digest}],
                        }
                    ]
                )
            )
        )
        return path

    def static(provider, digest):
        return ModelComponent(
            name="fieldlab/forecast",
            bom_ref=f"model:{provider}",
            version="1",
            provider=provider,
            hashes={"SHA-256": digest},
        )

    inv = tmp_path / "inventory.json"
    AIBOM(components=[static("Provider A", _SHA_A)]).save(inv)
    a = write_snapshot(tmp_path / "a.json", "Provider A", _SHA_A)
    b = write_snapshot(tmp_path / "b.json", "Provider B", _SHA_A)
    for order in ([a, b], [b, a]):
        report = collect(inv, order, fail_on="undeclared")
        assert not report["gate"]["passed"]
        assert report["coverage"]["observed_distinct"] == 2
        assert [(row["supplier"], row["source_files"]) for row in report["observed"]] == [
            ("Provider A", ["a.json"]),
            ("Provider B", ["b.json"]),
        ]
        assert [row["supplier"] for row in report["reconciliation"]["undeclared"]] == ["Provider B"]
        assert report["reconciliation"]["matched"][0]["inventory_refs"] == ["model:Provider A"]

    write_snapshot(b, "Provider B", _SHA_B)
    AIBOM(components=[static("Provider A", _SHA_A), static("Provider B", _SHA_B)]).save(inv)
    independent = collect(inv, [a, b], fail_on="drift")
    assert independent["gate"]["passed"]
    assert {tuple(row["inventory_refs"]) for row in independent["reconciliation"]["matched"]} == {
        ("model:Provider A",),
        ("model:Provider B",),
    }
    write_snapshot(b, "Provider A", _SHA_B)
    conflicts = collect(inv, [a, b], fail_on="drift")
    assert not conflicts["gate"]["passed"]
    assert all(
        "conflicting_reported_digests" in row["drift_reasons"]
        for row in conflicts["reconciliation"]["drifted"]
    )


def test_producer_model_provider_property_is_independent_of_supplier(tmp_path):
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

    model = ModelComponent(
        name="fieldlab/forecast",
        bom_ref="model:forecast",
        provider="Compute A",
        supplier="Distribution",
        version="1",
    )
    bom = AIBOM(components=[model])
    inventory = tmp_path / "static.json"
    bom.save(inventory)
    snapshot = tmp_path / "snapshot.json"
    doc = CycloneDXGenerator(projection_version=3).generate(bom)
    (row,) = [c for c in doc["components"] if c["type"] == "machine-learning-model"]
    (prop,) = [v for v in row["properties"] if v["name"] == "nexus-symbiote:provider"]
    assert prop["value"] == "Compute A" and row["supplier"]["name"] == "Distribution"
    for provider, supplier, passed in [
        ("Compute A", "Distribution", True),
        ("Compute B", "Distribution", False),
        ("Compute A", "Distribution B", False),
    ]:
        prop["value"] = provider
        row["supplier"]["name"] = supplier
        snapshot.write_text(json.dumps(_cdx(components=[row])))
        result = collect(inventory, [snapshot], fail_on="undeclared")
        assert result["gate"]["passed"] is passed
        (observed,) = result["observed"]
        assert (observed["provider"], observed["supplier"]) == (provider, supplier)
    row["properties"].append({"name": "nexus-symbiote:provider", "value": "Compute B"})
    snapshot.write_text(json.dumps(_cdx(components=[row])))
    with pytest.raises(RuntimeBOMInputError, match="conflicting provider"):
        collect(inventory, [snapshot])


def test_context_key_redaction_recognizes_nested_names(tmp_path):
    inv = _write_static_bom(tmp_path)
    snapshot = tmp_path / "properties.json"
    sensitive = [
        "k8s.secret.value",
        "container.env.API_TOKEN.value",
        "k8s.http.authorization",
        "k8s.http.authorization.value",
        "cdx:k8s:headers:cookie:value",
    ]
    props = [{"name": name, "value": "session=inert-ordinary-sample"} for name in sensitive]
    props.append({"name": "k8s.workload.label", "value": "training"})
    snapshot.write_text(
        json.dumps(
            _cdx(
                components=[
                    {
                        "type": "machine-learning-model",
                        "name": "fieldlab/model",
                        "properties": props,
                    }
                ]
            )
        )
    )
    report = collect(inv, [snapshot], fail_on="none")
    assert "inert-ordinary-sample" not in render(report)
    (observed,) = report["observed"]
    assert set(observed["cluster_context"]) == {*sensitive, "k8s.workload.label"}
    assert observed["cluster_context"]["k8s.workload.label"] == "training"
