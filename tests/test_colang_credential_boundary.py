"""Limit the Colang exception to rails discovered by the NeMo collector."""

from nexus_symbiote.core.models import GuardrailComponent
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.scanners.rag import RAGScanner


def test_instruction_import_of_credential_named_colang_file_reports_gap(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("Additional documentation in @service-credentials.co\n")
    (tmp_path / "service-credentials.co").write_text("Sample fixture text.\n")

    result = PromptScanner().scan(tmp_path)

    assert any("service-credentials.co" in gap for gap in result.surfaces_excluded)
    assert all(component.source_path != "service-credentials.co" for component in result.components)


def test_colang_exception_applies_to_the_direct_rail_only(tmp_path):
    (tmp_path / "config.yml").write_text("rails: {}\n")
    (tmp_path / "rotate-api-key.co").write_text("define bot welcome\n  'Welcome'\n")
    stored = tmp_path / "fixtures"
    stored.mkdir()
    (stored / "service-credentials.co").write_text("Sample fixture text.\n")
    (tmp_path / "linked.co").symlink_to("fixtures/service-credentials.co")

    result = RAGScanner().scan(tmp_path)

    (guardrail,) = [
        component for component in result.components if isinstance(component, GuardrailComponent)
    ]
    assert set(guardrail.properties["rail_files"]) == {"rotate-api-key.co"}
    assert any("linked.co" in gap and "credentials" in gap for gap in result.surfaces_excluded)


def test_direct_credential_named_colang_files_are_withheld(tmp_path):
    (tmp_path / "config.yml").write_text("rails: {}\n", encoding="utf-8")
    (tmp_path / "check_secrets.co").write_text("define flow check\n", encoding="utf-8")
    for withheld_name in ("secrets.co", ".credential.co", "config.env.co"):
        (tmp_path / withheld_name).write_text("TOKEN = 'sample'\n", encoding="utf-8")

    result = RAGScanner().scan(tmp_path)

    (guardrail,) = [
        component for component in result.components if isinstance(component, GuardrailComponent)
    ]
    assert set(guardrail.properties["rail_files"]) == {"check_secrets.co"}
    for withheld_name in ("secrets.co", ".credential.co", "config.env.co"):
        assert any(
            withheld_name in gap and "credentials" in gap for gap in result.surfaces_excluded
        )
