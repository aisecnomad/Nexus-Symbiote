"""The framework crosswalk names only verified identifiers, covers every category, and the
pages that print it stay equal to it."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from nexus_symbiote import crosswalk
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.crosswalk import CROSSWALK, FRAMEWORKS, Reference, framework, label
from nexus_symbiote.generators._rules import RULES, rule_tags

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PAGE = ROOT / "docs" / "framework-crosswalk.md"
FINDING_CATALOG = ROOT / "docs" / "finding-catalog.md"
STANDARD_EXPORTS = ROOT / "docs" / "standard-exports.md"
# Introduced with runtime telemetry comparison; it is not raised by a collector.
RUNTIME_CATEGORY = "runtime_undeclared"

# MITRE ATLAS release 2026.10 (dist/v6/ATLAS-2026.10.yaml, modified 2026-10-28), copied
# from the release file: identifier -> (name, parent technique).
ATLAS_2026_10 = {
    "AML.T0010": ("Supply Chain Compromise", None),
    "AML.T0010.001": ("Software", "AML.T0010"),
    "AML.T0010.003": ("Model Repository", "AML.T0010"),
    "AML.T0010.004": ("Container Registry", "AML.T0010"),
    "AML.T0010.005": ("AI Agent Tool", "AML.T0010"),
    "AML.T0011": ("User Execution", None),
    "AML.T0011.000": ("Unsafe AI Artifacts", "AML.T0011"),
    "AML.T0053": ("AI Agent Tool Invocation", None),
    "AML.T0068": ("LLM Prompt Obfuscation", None),
    "AML.T0070": ("RAG Poisoning", None),
    "AML.T0074": ("Masquerading", None),
    "AML.T0105": ("Escape to Host", None),
    "AML.T0109": ("AI Supply Chain Rug Pull", None),
    "AML.T0142": ("Event Triggered Execution", None),
}
# The GenAI Security Project's repository: 2025/ and 2026/README.md (published 2026-08-04).
OWASP_LLM_2025 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}
OWASP_LLM_2026 = {
    "LLM01:2026": "Prompt Injection",
    "LLM02:2026": "Sensitive Information Disclosure",
    "LLM03:2026": "Excessive Agency",
    "LLM04:2026": "Supply Chain",
    "LLM05:2026": "Data and Model Poisoning",
    "LLM06:2026": "Unbounded Consumption",
    "LLM07:2026": "Misinformation",
    "LLM08:2026": "Hidden Context Exposure",
    "LLM09:2026": "Vector and Embedding Weaknesses",
    "LLM10:2026": "Improper Output Handling",
}
# Appendix A of the OWASP Top 10 for LLM Applications 2026.
OWASP_ASI_2026 = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}
# Identifiers checked against secondary sources; titles are the catalog's own words.
NIST_AI_RMF = {
    "GOVERN-1.6",
    "GOVERN-6.1",
    "GOVERN-6.2",
    "MAP-4.1",
    "MAP-4.2",
    "MEASURE-2.7",
    "MANAGE-3.1",
    "MANAGE-3.2",
}
EU_AI_ACT = {"Art. 11", "Art. 12", "Art. 15", "Art. 25", "Art. 53"}
ISO_42001 = {"A.4.2", "A.6.2.6", "A.6.2.8", "A.7.5", "A.10.3"}
# The identifiers of the earlier SARIF catalog and CWE-798, with their CWE names.
CWE_NAMES = {
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-451": "User Interface (UI) Misrepresentation of Critical Information",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
    "CWE-1427": "Improper Neutralization of Input Used for LLM Prompting",
}
VERIFIED_TITLES = {
    "owasp-llm-2025": OWASP_LLM_2025,
    "owasp-llm-2026": OWASP_LLM_2026,
    "owasp-asi-2026": OWASP_ASI_2026,
    "mitre-atlas-2026.10": {key: name for key, (name, _) in ATLAS_2026_10.items()},
    "cwe": CWE_NAMES,
}
VERIFIED_IDS = {
    "nist-ai-rmf-1.0": NIST_AI_RMF,
    "eu-ai-act-2024": EU_AI_ACT,
    "iso-iec-42001-2023": ISO_42001,
}
# References that the earlier SARIF rules carried and that do not hold for every kind of
# finding of their category. They were kept so that those rules keep their tags; each
# rationale names the kind it misses, and the page lists them under Limits.
KEPT = "kept from the earlier SARIF rules, it does not hold for"
KEPT_EXCEPTIONS = {
    ("authentication", "cwe", "CWE-306"),
    ("serialization_format", "cwe", "CWE-502"),
    ("transport_security", "cwe", "CWE-319"),
    ("transport_security", "owasp-asi-2026", "ASI07"),
}
# Text that a Markdown table or the docs would read as markup.
MARKUP = re.compile(r"[|`<>\[\]*_\\\n]")
ORDER = {
    (edition.key, entry.id): (index, position)
    for index, edition in enumerate(FRAMEWORKS)
    for position, entry in enumerate(edition.entries)
}


def documented_category_rows() -> list[str]:
    text = FINDING_CATALOG.read_text(encoding="utf-8")
    table = text.split("## Categories", 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^\| `([^`]+)` \|", table, re.M)


def documented_categories() -> set[str]:
    return set(documented_category_rows())


def _all_references() -> list[tuple[str, Reference]]:
    return [(category, reference) for category, refs in CROSSWALK.items() for reference in refs]


def test_every_documented_category_has_a_rule_and_a_crosswalk_entry():
    documented = documented_categories()
    assert len(documented) >= 44 and "launcher_identity" in documented
    expected = documented | {RUNTIME_CATEGORY}
    assert set(RULES) == expected
    assert set(CROSSWALK) == expected


def test_framework_editions_are_the_specified_ones_with_their_verification():
    assert crosswalk.FRAMEWORK_KEYS == (
        "owasp-llm-2025",
        "owasp-llm-2026",
        "owasp-asi-2026",
        "mitre-atlas-2026.10",
        "nist-ai-rmf-1.0",
        "eu-ai-act-2024",
        "iso-iec-42001-2023",
        "cwe",
    )
    verification = {edition.key: edition.verification for edition in FRAMEWORKS}
    assert {key for key, value in verification.items() if value == "primary"} == {
        "owasp-llm-2025",
        "owasp-llm-2026",
        "owasp-asi-2026",
        "mitre-atlas-2026.10",
    }
    for edition in FRAMEWORKS:
        assert edition.source.startswith("https://")
        assert edition.key.endswith(edition.edition) or edition.key == "cwe"


@pytest.mark.parametrize("key", sorted(VERIFIED_TITLES))
def test_identifiers_and_names_equal_the_verified_editions(key):
    verified = VERIFIED_TITLES[key]
    for entry in framework(key).entries:
        assert verified.get(entry.id) == entry.title, (key, entry.id, entry.title)


def test_atlas_parents_equal_the_release():
    for entry in framework("mitre-atlas-2026.10").entries:
        assert ATLAS_2026_10[entry.id][1] == entry.parent, entry.id
    assert label("mitre-atlas-2026.10", "AML.T0010.005") == "Supply Chain Compromise: AI Agent Tool"
    assert label("mitre-atlas-2026.10", "AML.T0109") == "AI Supply Chain Rug Pull"


@pytest.mark.parametrize("key", sorted(VERIFIED_IDS))
def test_identifiers_are_verified_for_frameworks_named_in_own_words(key):
    assert {entry.id for entry in framework(key).entries} <= VERIFIED_IDS[key]


def test_every_reference_names_an_entry_of_its_edition_once():
    known = {(edition.key, entry.id) for edition in FRAMEWORKS for entry in edition.entries}
    for category, refs in CROSSWALK.items():
        keys = [(reference.framework, reference.entry) for reference in refs]
        assert len(keys) == len(set(keys)), category
        assert set(keys) <= known, category
        for reference in refs:
            assert reference.severities <= set(RiskSeverity)


def test_every_listed_entry_is_used():
    used = {(reference.framework, reference.entry) for _, reference in _all_references()}
    parents = {
        (edition.key, entry.parent)
        for edition in FRAMEWORKS
        for entry in edition.entries
        if entry.parent and (edition.key, entry.id) in used
    }
    listed = {(edition.key, entry.id) for edition in FRAMEWORKS for entry in edition.entries}
    assert listed == used | parents


def test_catalog_text_is_plain_single_line_prose():
    texts = [crosswalk.MEANING]
    for edition in FRAMEWORKS:
        texts += [edition.name, edition.edition, edition.note]
        texts += [entry.title for entry in edition.entries]
        assert re.fullmatch(r"https://[A-Za-z0-9./_:-]+", edition.source), edition.source
    texts += [reference.rationale for _, reference in _all_references()]
    for text in texts:
        assert text and text == text.strip() and not MARKUP.search(text), text
    for _, reference in _all_references():
        assert reference.rationale.endswith(".")
    assert "does not mean" in crosswalk.MEANING


def test_unknown_categories_have_no_references():
    assert crosswalk.references("not_a_category", RiskSeverity.HIGH) == []
    assert crosswalk.sarif_tags("not_a_category", RiskSeverity.HIGH) == []


def test_severity_scoped_references_hold_only_at_their_severities():
    cwe = ["external/cwe/cwe-319"]
    assert [t for t in rule_tags("transport_security", RiskSeverity.HIGH) if "cwe" in t] == cwe
    assert not [t for t in rule_tags("transport_security", RiskSeverity.LOW) if "cwe" in t]
    high = rule_tags("permission_scope", RiskSeverity.HIGH)
    assert "external/mitre-atlas/aml.t0105" in high
    assert "external/mitre-atlas/aml.t0105" not in rule_tags(
        "permission_scope", RiskSeverity.MEDIUM
    )
    selected = crosswalk.references("permission_scope", RiskSeverity.HIGH, {"mitre-atlas-2026.10"})
    assert [reference.entry for reference in selected] == ["AML.T0053", "AML.T0105"]


def test_only_the_listed_references_kept_from_the_earlier_rules_miss_a_kind_of_finding():
    marked = {
        (category, reference.framework, reference.entry)
        for category, reference in _all_references()
        if KEPT in reference.rationale
    }
    assert marked == KEPT_EXCEPTIONS
    page = CATALOG_PAGE.read_text(encoding="utf-8")
    limits = " ".join(page.split("\n## Limits\n", 1)[1].split("\n## ", 1)[0].split())
    for category, _, entry in sorted(KEPT_EXCEPTIONS):
        assert f"{entry} on `{category}` does not hold for" in limits, (category, entry)


def test_references_name_only_what_every_kind_of_finding_records():
    def entries(category: str, severity: RiskSeverity) -> list[str]:
        return [reference.entry for reference in crosswalk.references(category, severity)]

    # A pickle file holds no template, and a chat template is not deserialized by pickle.
    assert "CWE-1336" not in entries("serialization_format", RiskSeverity.CRITICAL)
    assert "CWE-502" not in entries("serialization_format", RiskSeverity.HIGH)
    # A finding on an A2A client records the client's configuration, not an exposed service.
    assert not crosswalk.references("authentication", RiskSeverity.MEDIUM, {"mitre-atlas-2026.10"})
    # Medium findings include workspace members and local paths, which can be the project's.
    assert entries("nonregistry_source", RiskSeverity.MEDIUM) == []
    assert "LLM03:2025" in entries("nonregistry_source", RiskSeverity.HIGH)
    assert entries("lockfile_unread", RiskSeverity.LOW) == ["GOVERN-1.6", "A.4.2"]


# The pages print the catalog. These renderers define how; the tests compare the result.


def _scope(reference: Reference) -> str:
    names = [severity.value for severity in RiskSeverity if severity in reference.severities]
    if not names:
        return "all"
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def catalog_markdown() -> str:
    lines = [
        "## Editions",
        "",
        "| Key | Framework | Edition | Verification | SARIF tag, for example |",
        "| --- | --- | --- | --- | --- |",
    ]
    for edition in FRAMEWORKS:
        tag = crosswalk.sarif_tag(edition.key, edition.entries[0].id)
        lines.append(
            f"| `{edition.key}` | [{edition.name}]({edition.source}) | {edition.edition} | "
            f"{edition.verification} | {f'`{tag}`' if tag else 'none'} |"
        )
    lines.append("")
    lines += [f"- `{edition.key}`: {edition.note}" for edition in FRAMEWORKS]
    lines += ["", "## Entries"]
    for edition in FRAMEWORKS:
        lines += ["", f"### {edition.name} {edition.edition}", ""]
        if any(entry.parent for entry in edition.entries):
            lines += ["| Id | Name | Technique |", "| --- | --- | --- |"]
            lines += [f"| {e.id} | {e.title} | {e.parent or ''} |" for e in edition.entries]
        else:
            lines += ["| Id | Title |", "| --- | --- |"]
            lines += [f"| {e.id} | {e.title} |" for e in edition.entries]
    lines += ["", "## Mapping"]
    for category in sorted(CROSSWALK):
        lines += ["", f"### `{category}`", ""]
        refs = CROSSWALK[category]
        if not refs:
            lines.append("No reference: no entry was defensible for this category.")
            continue
        lines += [
            "| Framework | Entry | Severities | Rationale |",
            "| --- | --- | --- | --- |",
        ]
        for reference in sorted(refs, key=lambda r: ORDER[(r.framework, r.entry)]):
            lines.append(
                f"| `{reference.framework}` | {reference.entry} "
                f"{label(reference.framework, reference.entry)} | {_scope(reference)} | "
                f"{reference.rationale} |"
            )
    return "\n".join(lines) + "\n"


def _cell(category: str, key: str) -> str:
    refs = sorted(
        (reference for reference in CROSSWALK[category] if reference.framework == key),
        key=lambda r: ORDER[(r.framework, r.entry)],
    )
    if not refs:
        return "none"
    parts = []
    for reference in refs:
        scope = _scope(reference)
        parts.append(reference.entry + ("" if scope == "all" else f" ({scope} findings)"))
    return ", ".join(parts)


SARIF_TABLE_HEADER = (
    "| Category | Rule title | CWE | OWASP LLM 2025 | OWASP LLM 2026 | OWASP Agentic | "
    "MITRE ATLAS | NIST AI RMF |"
)


def sarif_rule_table() -> str:
    keys = (
        "cwe",
        "owasp-llm-2025",
        "owasp-llm-2026",
        "owasp-asi-2026",
        "mitre-atlas-2026.10",
        "nist-ai-rmf-1.0",
    )
    lines = [SARIF_TABLE_HEADER, "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for category in sorted(RULES):
        cells = " | ".join(_cell(category, key) for key in keys)
        lines.append(f"| `{category}` | {RULES[category].title} | {cells} |")
    return "\n".join(lines) + "\n"


def test_the_crosswalk_page_prints_the_catalog():
    text = CATALOG_PAGE.read_text(encoding="utf-8")
    assert "\n## Editions\n" in text, "docs/framework-crosswalk.md has no Editions section"
    assert text[text.index("## Editions\n") :] == catalog_markdown()
    assert crosswalk.MEANING in text


def test_the_standard_exports_rule_table_prints_the_catalog():
    text = STANDARD_EXPORTS.read_text(encoding="utf-8")
    start = text.index(SARIF_TABLE_HEADER)
    rows = []
    for line in text[start:].splitlines():
        if not line.startswith("|"):
            break
        rows.append(line)
    assert "\n".join(rows) + "\n" == sarif_rule_table()


def test_the_finding_catalog_no_longer_lists_uncatalogued_categories():
    section = FINDING_CATALOG.read_text(encoding="utf-8").split("## SARIF rules", 1)[1]
    assert "generic rule" in section
    assert "`launcher_identity`" not in section
    assert "framework-crosswalk.md" in section


def test_the_finding_catalog_lists_each_category_once_in_alphabetical_order():
    rows = documented_category_rows()
    assert len(rows) == len(set(rows))
    assert rows == sorted(rows)


def test_rationales_claim_no_weakness_or_documentation_gap_that_findings_do_not_record():
    # Art. 15 is attached to findings that record an unknown or an ordinary property, and
    # Art. 11 and A.4.2 to findings that record only what the inventory does not declare.
    for category, reference in _all_references():
        text = reference.rationale
        if (reference.framework, reference.entry) == ("eu-ai-act-2024", "Art. 15"):
            assert "weakness" not in text, category
        if (reference.framework, reference.entry) in {
            ("eu-ai-act-2024", "Art. 11"),
            ("iso-iec-42001-2023", "A.4.2"),
        }:
            assert "documentation" not in text and "inventory" in text, category


def test_runtime_references_hold_for_unidentified_items_too():
    # trace-diff writes unidentified items, which may be declared, under the same category.
    texts = [reference.rationale for reference in CROSSWALK[RUNTIME_CATEGORY]]
    texts.append(RULES[RUNTIME_CATEGORY].description)
    for text in texts:
        assert "does not list" not in text and "not in the inventory" not in text
        assert "used at run time" not in text and "never went through" not in text
    assert "could not be read" in RULES[RUNTIME_CATEGORY].description
