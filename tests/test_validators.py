"""Tests for completeness, integrity, and risk validators."""

from __future__ import annotations

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import TOOL_DEFINITION_HASH_VERSION
from nexus_symbiote.core.models import (
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.validators.completeness import CompletenessValidator
from nexus_symbiote.validators.integrity import IntegrityValidator
from nexus_symbiote.validators.risk import RiskScorer


def _full_bom() -> AIBOM:
    bom = AIBOM()
    bom.metadata.completeness = CompletenessClaim(
        scope="full-agent",
        surfaces_scanned=[".mcp.json", "CLAUDE.md", "package.json"],
        assurance_level=AssuranceLevel.OBSERVED,
    )
    bom.add_component(
        MCPServerComponent(
            bom_ref="mcp:fs",
            name="filesystem",
            transport="stdio",
            version_pinned=True,
        )
    )
    bom.add_component(
        ToolComponent(
            bom_ref="tool:read",
            name="read_file",
            mcp_server_ref="mcp:fs",
            definition_hash="sha256:abc123",
            definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
            description_text="Read a file",
        )
    )
    bom.add_component(
        PromptComponent(
            bom_ref="prompt:system",
            name="CLAUDE.md",
            prompt_type="system-prompt",
            content_hash="sha256:def456",
        )
    )
    return bom


def _risky_bom() -> AIBOM:
    bom = AIBOM()
    bom.add_component(
        ModelComponent(
            bom_ref="model:unsafe",
            name="unsafe-model.pkl",
            serialization_format="pickle",
            serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
            signing_status="unsigned",
            trust_remote_code=True,
            trust_tier=TrustTier.UNTRUSTED_PUBLIC,
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="serialization_format",
                    detail="Pickle allows arbitrary code execution.",
                ),
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="code_execution",
                    detail="trust_remote_code=True.",
                ),
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail="Model is unsigned.",
                ),
            ],
        )
    )
    bom.add_component(
        ToolComponent(
            bom_ref="tool:danger",
            name="dangerous_tool",
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="capability_scope",
                    detail="Tool has broad permissions.",
                ),
            ],
        )
    )
    return bom


class TestCompletenessValidator:
    def test_complete_bom_passes(self):
        bom = _full_bom()
        cv = CompletenessValidator()
        report = cv.validate(bom)
        assert report.total_components == 3
        assert len(report.surfaces_covered) > 0

    def test_missing_completeness_claim(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(bom_ref="tool:t", name="t"))
        cv = CompletenessValidator()
        report = cv.validate(bom)
        assert not report.is_complete
        assert any(i.surface == "metadata" for i in report.issues)

    def test_orphan_ref_detected(self):
        bom = _full_bom()
        bom.add_dependency(
            DependencyEdge(
                source_ref="mcp:fs",
                target_ref="tool:nonexistent",
                relationship="invokes",
            )
        )
        cv = CompletenessValidator()
        report = cv.validate(bom)
        assert not report.is_complete
        assert any("nonexistent" in i.description for i in report.issues)

    def test_report_to_dict(self):
        bom = _full_bom()
        cv = CompletenessValidator()
        report = cv.validate(bom)
        d = report.to_dict()
        assert "is_complete" in d
        assert "issues" in d
        assert "total_components" in d


class TestIntegrityValidator:
    def test_tool_hash_mismatch(self):
        bom = AIBOM()
        bom.add_component(
            ToolComponent(
                bom_ref="tool:test",
                name="test_tool",
                description_text="Does something",
                definition_hash="sha256:wrong_hash_value",
                definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert not report.is_valid
        assert report.hashes_failed > 0

    def test_tool_hash_correct(self):
        from nexus_symbiote.core.hashing import hash_tool_definition

        correct_hash = hash_tool_definition("test_tool", "Does something")
        bom = AIBOM()
        bom.add_component(
            ToolComponent(
                bom_ref="tool:test",
                name="test_tool",
                description_text="Does something",
                definition_hash=correct_hash,
                definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert report.tool_descriptors_self_consistent == 1
        assert report.hashes_verified == 0
        assert report.status == "unknown"
        assert report.hashes_failed == 0

    def test_unsafe_model_flagged(self):
        bom = AIBOM()
        bom.add_component(
            ModelComponent(
                bom_ref="model:pkl",
                name="model.pkl",
                serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
                signing_status="unsigned",
                trust_remote_code=True,
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert not report.is_valid
        categories = {i.category for i in report.issues}
        assert "unsafe_format" in categories
        assert "trust_remote_code" in categories

    def test_unpinned_mcp_flagged(self):
        bom = AIBOM()
        bom.add_component(
            MCPServerComponent(
                bom_ref="mcp:test",
                name="test-server",
                version_pinned=False,
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert any(i.category == "unpinned_version" for i in report.issues)

    def test_report_to_dict(self):
        bom = _full_bom()
        iv = IntegrityValidator()
        report = iv.validate(bom)
        d = report.to_dict()
        assert "is_valid" in d
        assert "components_checked" in d


class TestRiskScorer:
    def test_clean_bom_low_score(self):
        bom = _full_bom()
        scorer = RiskScorer()
        report = scorer.score(bom)
        assert report.overall_score == 0.0
        assert report.risk_level == "unknown"

    def test_risky_bom_high_score(self):
        bom = _risky_bom()
        scorer = RiskScorer()
        report = scorer.score(bom)
        assert report.overall_score > 20.0
        assert report.risk_level in ("high", "critical")
        assert report.severity_counts.get("critical", 0) >= 2

    def test_passes_gate(self):
        bom = _full_bom()
        scorer = RiskScorer(fail_threshold=50.0)
        passed, report = scorer.passes_gate(bom)
        assert not passed
        assert report.coverage_status == "unknown"

    def test_fails_gate(self):
        bom = _risky_bom()
        scorer = RiskScorer(fail_threshold=10.0)
        passed, report = scorer.passes_gate(bom)
        assert not passed

    def test_report_to_dict(self):
        bom = _risky_bom()
        scorer = RiskScorer()
        report = scorer.score(bom)
        d = report.to_dict()
        assert "overall_score" in d
        assert "risk_level" in d
        assert "findings" in d
        assert len(d["findings"]) > 0


class TestAIBOMDiffer:
    def test_no_changes(self):
        bom = _full_bom()
        differ = AIBOMDiffer()
        result = differ.diff(bom, bom)
        assert not result.has_changes

    def test_component_added(self):
        old = _full_bom()
        new = _full_bom()
        new.add_component(
            ModelComponent(
                bom_ref="model:new",
                name="new-model",
            )
        )
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert result.has_changes
        assert len(result.components_added) == 1
        assert result.components_added[0].bom_ref == "model:new"

    def test_component_removed(self):
        old = _full_bom()
        new = AIBOM()
        new.add_component(MCPServerComponent(bom_ref="mcp:fs", name="filesystem"))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert len(result.components_removed) == 2

    def test_component_modified(self):
        old = _full_bom()
        new = _full_bom()
        new.replace_component(
            MCPServerComponent(
                bom_ref="mcp:fs",
                name="filesystem",
                transport="sse",
                trust_tier=TrustTier.UNTRUSTED_PUBLIC,
            )
        )
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert len(result.components_modified) == 1
        assert any("trust tier" in d.lower() for d in result.components_modified[0].details)

    def test_security_alert_on_hash_change(self):
        old = _full_bom()
        new = _full_bom()
        new.replace_component(
            ToolComponent(
                bom_ref="tool:read",
                name="read_file",
                mcp_server_ref="mcp:fs",
                definition_hash="sha256:changed_hash",
                definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
                description_text="Read a file (modified)",
            )
        )
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert len(result.security_alerts) >= 1
        assert any("critical" in a["severity"] for a in result.security_alerts)

    def test_diff_to_dict(self):
        old = _full_bom()
        new = _full_bom()
        new.add_component(ModelComponent(bom_ref="model:x", name="x"))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        d = result.to_dict()
        assert "has_changes" in d
        assert "components_added" in d

    def test_dependency_added(self):
        old = _full_bom()
        new = _full_bom()
        new.add_dependency(
            DependencyEdge(source_ref="mcp:fs", target_ref="tool:read", relationship="invokes")
        )
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert len(result.dependencies_added) == 1
        assert result.dependencies_added[0].source_ref == "mcp:fs"

    def test_dependency_removed(self):
        old = _full_bom()
        old.add_dependency(
            DependencyEdge(source_ref="mcp:fs", target_ref="tool:read", relationship="invokes")
        )
        new = _full_bom()
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert len(result.dependencies_removed) == 1

    def test_trust_tier_downgrade(self):
        old = AIBOM()
        old.add_component(
            MCPServerComponent(
                bom_ref="mcp:fs",
                name="filesystem",
                trust_tier=TrustTier.INTERNAL_VERIFIED,
            )
        )
        new = AIBOM()
        new.add_component(
            MCPServerComponent(
                bom_ref="mcp:fs",
                name="filesystem",
                trust_tier=TrustTier.UNTRUSTED_PUBLIC,
            )
        )
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        modified = [c for c in result.components_modified if c.bom_ref == "mcp:fs"]
        assert len(modified) == 1
        assert any("downgraded" in d.lower() for d in modified[0].details)
        assert modified[0].severity == "high"

    def test_trust_tier_upgrade(self):
        old = AIBOM()
        old.add_component(
            MCPServerComponent(
                bom_ref="mcp:fs",
                name="filesystem",
                trust_tier=TrustTier.UNTRUSTED_PUBLIC,
            )
        )
        new = AIBOM()
        new.add_component(
            MCPServerComponent(
                bom_ref="mcp:fs",
                name="filesystem",
                trust_tier=TrustTier.INTERNAL_VERIFIED,
            )
        )
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        modified = result.components_modified
        assert len(modified) == 1
        assert any("upgraded" in d.lower() for d in modified[0].details)

    def test_version_pin_removed(self):
        old = AIBOM()
        old.add_component(MCPServerComponent(bom_ref="mcp:s", name="s", version_pinned=True))
        new = AIBOM()
        new.add_component(MCPServerComponent(bom_ref="mcp:s", name="s", version_pinned=False))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        modified = result.components_modified
        assert any("pin removed" in d.lower() for c in modified for d in c.details)

    def test_serialization_safety_change(self):
        old = AIBOM()
        old.add_component(
            ModelComponent(
                bom_ref="model:m",
                name="m",
                serialization_safety=SerializationSafety.SAFE,
            )
        )
        new = AIBOM()
        new.add_component(
            ModelComponent(
                bom_ref="model:m",
                name="m",
                serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
            )
        )
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert any(
            "serialization safety" in d.lower()
            for c in result.components_modified
            for d in c.details
        )

    def test_signing_status_change_to_unsigned(self):
        old = AIBOM()
        old.add_component(
            ModelComponent(bom_ref="model:m", name="m", signing_status="sigstore-signed")
        )
        new = AIBOM()
        new.add_component(ModelComponent(bom_ref="model:m", name="m", signing_status="unsigned"))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        modified = result.components_modified
        assert len(modified) == 1
        assert modified[0].severity == "high"

    def test_content_hash_change(self):
        old = AIBOM()
        old.add_component(PromptComponent(bom_ref="p:1", name="p", content_hash="sha256:aaa"))
        new = AIBOM()
        new.add_component(PromptComponent(bom_ref="p:1", name="p", content_hash="sha256:bbb"))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert any(
            "content hash" in d.lower() for c in result.components_modified for d in c.details
        )

    def test_file_hash_change(self):
        old = AIBOM()
        old.add_component(
            ModelComponent(bom_ref="model:m", name="m", hashes={"sha256": "sha256:aaa"})
        )
        new = AIBOM()
        new.add_component(
            ModelComponent(bom_ref="model:m", name="m", hashes={"sha256": "sha256:bbb"})
        )
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert any("file hash" in d.lower() for c in result.components_modified for d in c.details)


class TestCompletenessValidatorAdvanced:
    def test_validate_against_project_mcp_missing(self, tmp_path):
        (tmp_path / ".mcp.json").write_text('{"mcpServers": {}}')
        bom = AIBOM()
        bom.metadata.completeness = CompletenessClaim(scope="full-agent")
        bom.add_component(ToolComponent(bom_ref="tool:t", name="t"))
        bom.add_component(PromptComponent(bom_ref="p:1", name="p"))
        cv = CompletenessValidator()
        report = cv.validate_against_project(bom, tmp_path)
        assert not report.is_complete
        assert any("MCP" in i.description for i in report.issues)

    def test_validate_against_project_prompts_missing(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("prompt content")
        bom = AIBOM()
        bom.metadata.completeness = CompletenessClaim(scope="full-agent")
        bom.add_component(MCPServerComponent(bom_ref="mcp:s", name="s"))
        bom.add_component(ToolComponent(bom_ref="tool:t", name="t"))
        cv = CompletenessValidator()
        report = cv.validate_against_project(bom, tmp_path)
        assert not report.is_complete
        assert any("instruction files" in i.description for i in report.issues)

    def test_validate_against_project_models_missing(self, tmp_path):
        model_dir = tmp_path / "models"
        model_dir.mkdir()
        (model_dir / "weights.safetensors").write_bytes(b"\x00" * 10)
        bom = AIBOM()
        bom.metadata.completeness = CompletenessClaim(scope="full-agent")
        bom.add_component(MCPServerComponent(bom_ref="mcp:s", name="s"))
        bom.add_component(ToolComponent(bom_ref="tool:t", name="t"))
        bom.add_component(PromptComponent(bom_ref="p:1", name="p"))
        cv = CompletenessValidator()
        report = cv.validate_against_project(bom, tmp_path)
        assert not report.is_complete
        assert any("model files" in i.description for i in report.issues)

    def test_validate_against_project_all_present(self, tmp_path):
        (tmp_path / ".mcp.json").write_text('{"mcpServers": {}}')
        (tmp_path / "CLAUDE.md").write_text("prompt")
        bom = _full_bom()
        cv = CompletenessValidator()
        report = cv.validate_against_project(bom, tmp_path)
        assert not any("MCP config" in i.description for i in report.issues)

    def test_surfaces_missing_info_issues(self):
        bom = AIBOM()
        bom.metadata.completeness = CompletenessClaim(
            scope="full-agent",
            surfaces_scanned=[".mcp.json"],
            surfaces_excluded=["mcp-config: no servers defined"],
        )
        bom.add_component(MCPServerComponent(bom_ref="mcp:s", name="s"))
        bom.add_component(ToolComponent(bom_ref="tool:t", name="t"))
        bom.add_component(PromptComponent(bom_ref="p:1", name="p"))
        cv = CompletenessValidator()
        report = cv.validate(bom)
        info_issues = [i for i in report.issues if i.severity == "info"]
        assert len(info_issues) >= 1

    def test_missing_hash_warning(self):
        bom = AIBOM()
        bom.metadata.completeness = CompletenessClaim(scope="test")
        bom.add_component(ModelComponent(bom_ref="model:m", name="m"))
        bom.add_component(MCPServerComponent(bom_ref="mcp:s", name="s"))
        bom.add_component(ToolComponent(bom_ref="tool:t", name="t"))
        bom.add_component(PromptComponent(bom_ref="p:1", name="p"))
        cv = CompletenessValidator()
        report = cv.validate(bom)
        hash_issues = [i for i in report.issues if "integrity hash" in i.description]
        assert len(hash_issues) >= 1


class TestIntegrityValidatorAdvanced:
    def test_prompt_hash_verified_on_disk(self, tmp_path):
        from nexus_symbiote.core.hashing import hash_file

        prompt_file = tmp_path / "CLAUDE.md"
        prompt_file.write_text("System prompt content")
        correct_hash = hash_file(prompt_file)

        bom = AIBOM()
        bom.add_component(
            PromptComponent(
                bom_ref="prompt:sys",
                name="CLAUDE.md",
                content_hash=correct_hash,
                source_path=str(prompt_file),
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom, tmp_path)
        assert report.hashes_verified >= 1
        assert report.hashes_failed == 0

    def test_prompt_hash_mismatch_on_disk(self, tmp_path):
        prompt_file = tmp_path / "CLAUDE.md"
        prompt_file.write_text("Original content")

        bom = AIBOM()
        bom.add_component(
            PromptComponent(
                bom_ref="prompt:sys",
                name="CLAUDE.md",
                content_hash="sha256:wrong_value",
                source_path=str(prompt_file),
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom, tmp_path)
        assert not report.is_valid
        assert report.hashes_failed >= 1
        assert any(i.category == "hash_mismatch" for i in report.issues)

    def test_prompt_hash_relative_path(self, tmp_path):
        from nexus_symbiote.core.hashing import hash_file

        prompt_file = tmp_path / "CLAUDE.md"
        prompt_file.write_text("Relative path test")
        correct_hash = hash_file(prompt_file)

        bom = AIBOM()
        bom.add_component(
            PromptComponent(
                bom_ref="prompt:sys",
                name="CLAUDE.md",
                content_hash=correct_hash,
                source_path="CLAUDE.md",
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom, tmp_path)
        assert report.hashes_verified >= 1

    def test_missing_prompt_hash_warning(self):
        bom = AIBOM()
        bom.add_component(PromptComponent(bom_ref="prompt:sys", name="CLAUDE.md"))
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert any(i.category == "missing_hash" for i in report.issues)

    def test_missing_tool_hash_warning(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(bom_ref="tool:t", name="tool_without_hash"))
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert any(i.category == "missing_hash" for i in report.issues)

    def test_unsigned_model_warning(self):
        bom = AIBOM()
        bom.add_component(
            ModelComponent(
                bom_ref="model:m",
                name="m",
                signing_status="unsigned",
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert any(i.category == "unsigned_model" for i in report.issues)

    def test_file_hash_verified(self, tmp_path):
        from nexus_symbiote.core.hashing import hash_file

        model_file = tmp_path / "model.safetensors"
        model_file.write_bytes(b"\x00" * 50)
        correct_hash = hash_file(model_file)

        bom = AIBOM()
        bom.add_component(
            ModelComponent(
                bom_ref="model:m",
                name="model",
                source_path=str(model_file),
                hashes={"sha256": correct_hash},
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom, tmp_path)
        assert report.hashes_verified >= 1

    def test_file_hash_mismatch(self, tmp_path):
        model_file = tmp_path / "model.safetensors"
        model_file.write_bytes(b"\x00" * 50)

        bom = AIBOM()
        bom.add_component(
            ModelComponent(
                bom_ref="model:m",
                name="model",
                source_path=str(model_file),
                hashes={"sha256": "sha256:wrong_hash"},
            )
        )
        iv = IntegrityValidator()
        report = iv.validate(bom, tmp_path)
        assert not report.is_valid
        assert any(i.category == "file_hash_mismatch" for i in report.issues)
