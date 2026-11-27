"""Framework crosswalk: the framework entries that each finding category bears on.

A reference attaches one entry of one framework edition to a finding category, with a
one-line rationale. It says that a finding of that category records a precondition for
the entry, a weakness of its type, or evidence relevant to it; it never says that a
technique was used or an attack happened, that a control fails or is met, or that a
legal obligation applies. A category can record different kinds of finding at different
severities, so a reference limited to some severities holds only for findings of those
severities. A reference holds for every kind of finding that the category records at
its severities, except references kept from the earlier SARIF rules so that those rules
keep their tags: the rationale of each names the kind of finding it does not hold for.
An empty mapping says only that no reference was defensible.

Framework editions, their sources and how their identifiers were checked are data here.
SARIF tags, the ``crosswalk`` report and docs/framework-crosswalk.md derive from these
tables, and the tests check every identifier and verbatim name against its edition.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from typing import Literal

from nexus_symbiote.core.enums import RiskSeverity

MEANING = (
    "A reference means that the finding records a precondition for the framework entry, "
    "a weakness of its type, or evidence relevant to it. It does not mean that a technique "
    "was used, that an attack happened, that a control fails or is met, or that a legal "
    "obligation applies. Findings describe what the inventory records; neither a finding "
    "nor its absence shows that an agent, model or tool is safe."
)

OWASP_LLM_2025 = "owasp-llm-2025"
OWASP_LLM_2026 = "owasp-llm-2026"
OWASP_ASI_2026 = "owasp-asi-2026"
MITRE_ATLAS = "mitre-atlas-2026.10"
NIST_AI_RMF = "nist-ai-rmf-1.0"
EU_AI_ACT = "eu-ai-act-2024"
ISO_42001 = "iso-iec-42001-2023"
CWE = "cwe"


@dataclass(frozen=True)
class Entry:
    """One identifier of a framework edition; ``parent`` is a sub-technique's technique."""

    id: str
    title: str
    parent: str | None = None


@dataclass(frozen=True)
class Framework:
    """One framework edition: where it was read, how it was checked, the entries used.

    ``sarif_prefix`` is the tag namespace under which SARIF rules carry its entries;
    frameworks without one are not weakness or threat taxonomies and get no tag.
    """

    key: str
    name: str
    edition: str
    source: str
    verification: Literal["primary", "secondary"]
    note: str
    entries: tuple[Entry, ...]
    sarif_prefix: str | None = None


@dataclass(frozen=True)
class Reference:
    """One framework entry that findings of a category bear on, and why.

    An empty ``severities`` set means every severity.
    """

    framework: str
    entry: str
    rationale: str
    severities: frozenset[RiskSeverity] = frozenset()

    def applies(self, severity: RiskSeverity) -> bool:
        return not self.severities or severity in self.severities


FRAMEWORKS: tuple[Framework, ...] = (
    Framework(
        key=OWASP_LLM_2025,
        name="OWASP Top 10 for LLM Applications",
        edition="2025",
        source="https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2025",
        verification="primary",
        note=(
            "The edition that the earlier SARIF tags name. The 2026 edition renumbered the "
            "list, so an identifier is meaningful only with its edition."
        ),
        entries=(
            Entry("LLM01:2025", "Prompt Injection"),
            Entry("LLM02:2025", "Sensitive Information Disclosure"),
            Entry("LLM03:2025", "Supply Chain"),
            Entry("LLM04:2025", "Data and Model Poisoning"),
            Entry("LLM06:2025", "Excessive Agency"),
            Entry("LLM08:2025", "Vector and Embedding Weaknesses"),
        ),
        sarif_prefix="external/owasp-llm-top-10-2025/",
    ),
    Framework(
        key=OWASP_LLM_2026,
        name="OWASP Top 10 for LLM Applications",
        edition="2026",
        source="https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md",
        verification="primary",
        note=(
            "Published on 2026-08-04 and renumbered: LLM03:2026 is Excessive Agency and "
            "LLM04:2026 is Supply Chain."
        ),
        entries=(
            Entry("LLM01:2026", "Prompt Injection"),
            Entry("LLM02:2026", "Sensitive Information Disclosure"),
            Entry("LLM03:2026", "Excessive Agency"),
            Entry("LLM04:2026", "Supply Chain"),
            Entry("LLM05:2026", "Data and Model Poisoning"),
            Entry("LLM09:2026", "Vector and Embedding Weaknesses"),
        ),
        sarif_prefix="external/owasp-llm-top-10-2026/",
    ),
    Framework(
        key="owasp-asi-2026",
        name="OWASP Top 10 for Agentic Applications",
        edition="2026",
        source=(
            "https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/"
            "Appendix_A_Related_Framework_Mappings.md"
        ),
        verification="primary",
        note=(
            "Announced on 2025-12-09. Names were checked against Appendix A of the OWASP Top "
            "10 for LLM Applications 2026, not against the list's own page."
        ),
        entries=(
            Entry("ASI01", "Agent Goal Hijack"),
            Entry("ASI02", "Tool Misuse & Exploitation"),
            Entry("ASI03", "Identity & Privilege Abuse"),
            Entry("ASI04", "Agentic Supply Chain Vulnerabilities"),
            Entry("ASI05", "Unexpected Code Execution (RCE)"),
            Entry("ASI06", "Memory & Context Poisoning"),
            Entry("ASI07", "Insecure Inter-Agent Communication"),
        ),
        sarif_prefix="external/owasp-agentic-top-10/",
    ),
    Framework(
        key=MITRE_ATLAS,
        name="MITRE ATLAS",
        edition="2026.10",
        source="https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.10.yaml",
        verification="primary",
        note=(
            "Release 2026.10 (data format 6.1.0, modified 2026-10-28). Names are verbatim "
            "from this release and differ from older ones; a sub-technique is shown after "
            "its technique."
        ),
        entries=(
            Entry("AML.T0010", "Supply Chain Compromise"),
            Entry("AML.T0010.001", "Software", parent="AML.T0010"),
            Entry("AML.T0010.003", "Model Repository", parent="AML.T0010"),
            Entry("AML.T0010.004", "Container Registry", parent="AML.T0010"),
            Entry("AML.T0010.005", "AI Agent Tool", parent="AML.T0010"),
            Entry("AML.T0011", "User Execution"),
            Entry("AML.T0011.000", "Unsafe AI Artifacts", parent="AML.T0011"),
            Entry("AML.T0053", "AI Agent Tool Invocation"),
            Entry("AML.T0068", "LLM Prompt Obfuscation"),
            Entry("AML.T0070", "RAG Poisoning"),
            Entry("AML.T0074", "Masquerading"),
            Entry("AML.T0105", "Escape to Host"),
            Entry("AML.T0109", "AI Supply Chain Rug Pull"),
            Entry("AML.T0142", "Event Triggered Execution"),
        ),
        sarif_prefix="external/mitre-atlas/",
    ),
    Framework(
        key=NIST_AI_RMF,
        name="NIST AI Risk Management Framework (AI 100-1)",
        edition="1.0",
        source="https://doi.org/10.6028/NIST.AI.100-1",
        verification="secondary",
        note=(
            "Subcategory identifiers of the AI RMF Core, checked against secondary sources "
            "only. Titles are short summaries in this project's words, not the subcategory "
            "text."
        ),
        entries=(
            Entry("GOVERN-1.6", "AI systems are inventoried"),
            Entry("MEASURE-2.7", "Security and resilience are evaluated"),
            Entry("MANAGE-3.1", "Third-party AI risks are monitored and controlled"),
            Entry("MANAGE-3.2", "Pre-trained models are monitored"),
        ),
        sarif_prefix="external/nist-ai-rmf/",
    ),
    Framework(
        key=EU_AI_ACT,
        name="EU AI Act",
        edition="2024",
        source="https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
        verification="secondary",
        note=(
            "Regulation (EU) 2024/1689. An article is named where a finding can serve as "
            "evidence. Whether it applies depends on the system's risk class and the operator's "
            "role, which an inventory cannot establish. Titles are this project's words."
        ),
        entries=(
            Entry("Art. 11", "Technical documentation of the system and its elements (Annex IV)"),
            Entry("Art. 15", "Robustness and cybersecurity, including resistance to manipulation"),
        ),
    ),
    Framework(
        key=ISO_42001,
        name="ISO/IEC 42001 Annex A",
        edition="2023",
        source="https://www.iso.org/standard/81230.html",
        verification="secondary",
        note=(
            "Control identifiers only: the standard's text is copyrighted and was not "
            "consulted, and the labels are this project's words."
        ),
        entries=(
            Entry("A.4.2", "Resources of the AI system are documented"),
            Entry("A.7.5", "Data provenance is recorded"),
            Entry("A.10.3", "Suppliers are managed"),
        ),
    ),
    Framework(
        key=CWE,
        name="Common Weakness Enumeration (CWE)",
        edition="4.20",
        source="https://cwe.mitre.org/",
        verification="secondary",
        note=(
            "Identifiers from the earlier SARIF catalog, and CWE-798 for the credential "
            "exposure finding. The names of CWE-494, CWE-829 and CWE-1427 match CWE 4.20 as "
            "the OWASP Top 10 for LLM Applications 2026 cites them; the others were not "
            "checked against the CWE site for this release."
        ),
        entries=(
            Entry("CWE-250", "Execution with Unnecessary Privileges"),
            Entry("CWE-306", "Missing Authentication for Critical Function"),
            Entry("CWE-319", "Cleartext Transmission of Sensitive Information"),
            Entry("CWE-345", "Insufficient Verification of Data Authenticity"),
            Entry("CWE-451", "User Interface (UI) Misrepresentation of Critical Information"),
            Entry("CWE-494", "Download of Code Without Integrity Check"),
            Entry("CWE-502", "Deserialization of Untrusted Data"),
            Entry("CWE-798", "Use of Hard-coded Credentials"),
            Entry("CWE-829", "Inclusion of Functionality from Untrusted Control Sphere"),
            Entry("CWE-1395", "Dependency on Vulnerable Third-Party Component"),
            Entry(
                "CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"
            ),
            Entry("CWE-1427", "Improper Neutralization of Input Used for LLM Prompting"),
        ),
        sarif_prefix="external/cwe/",
    ),
)

FRAMEWORK_KEYS: tuple[str, ...] = tuple(framework.key for framework in FRAMEWORKS)
_FRAMEWORKS = {framework.key: framework for framework in FRAMEWORKS}
_ENTRIES = {
    (framework.key, entry.id): entry for framework in FRAMEWORKS for entry in framework.entries
}
_POSITION = {
    (framework.key, entry.id): (index, position)
    for index, framework in enumerate(FRAMEWORKS)
    for position, entry in enumerate(framework.entries)
}
# The earlier tags come first, in their earlier order, so a rule's tag list only grows.
_SARIF_ORDER = (CWE, OWASP_LLM_2025, OWASP_ASI_2026, OWASP_LLM_2026, MITRE_ATLAS, NIST_AI_RMF)

_HIGH_OR_CRITICAL = (RiskSeverity.HIGH, RiskSeverity.CRITICAL)


def _ref(framework: str, entry: str, rationale: str, *severities: RiskSeverity) -> Reference:
    return Reference(framework, entry, rationale, frozenset(severities))


# Rationales shared by every category whose findings bear on the entry in the same way.
_EVALUATION = (
    "Records a security-relevant property of the configuration, an input to evaluating its "
    "security."
)
_RESILIENCE = "Records a property of the system that bears on its robustness and cybersecurity."
_THIRD_PARTY = (
    "Records a third-party component whose identity, version or resolution is not established."
)
_SUPPLIER = "Records a supplied component whose identity, version or resolution is not established."
_PRETRAINED = "Records how safely a pre-trained model loads, or whether its weights are verified."
_DOCUMENTATION = "Records an element of the system that the inventory does not show as declared."
_RESOURCES = "Records a resource of the AI system that the inventory does not show as declared."
_HIDDEN_PROMPT = (
    "Instruction text that reads differently to a reviewer than to the model can carry "
    "injected instructions."
)
_HIDDEN_GOAL = "Such text can redirect the agent's goal without a reviewer noticing."
_HIDDEN_REVIEW = (
    "Hiding or disguising instruction text from human review is what this technique describes."
)
_UI_MISREPRESENTATION = "The file can display differently from what the agent processes."
_PROMPT_INPUT = "Instruction text reaches the model with characters that are not neutralized."
_MODEL_SUPPLY = "The model artifact is part of the agent's supply chain."

# Directional marks and comments are ordinary in some files, so they carry no CWE.
_DISGUISED_TEXT = (
    _ref(OWASP_LLM_2025, "LLM01:2025", _HIDDEN_PROMPT),
    _ref(OWASP_ASI_2026, "ASI01", _HIDDEN_GOAL),
    _ref(OWASP_LLM_2026, "LLM01:2026", _HIDDEN_PROMPT),
    _ref(MITRE_ATLAS, "AML.T0068", _HIDDEN_REVIEW),
    _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
    _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
)
_HIDDEN_CHARACTERS = (
    _ref(CWE, "CWE-451", _UI_MISREPRESENTATION),
    _ref(CWE, "CWE-1427", _PROMPT_INPUT),
    *_DISGUISED_TEXT,
)

CROSSWALK: dict[str, tuple[Reference, ...]] = {
    "additional_directories": (
        _ref(
            OWASP_LLM_2025,
            "LLM06:2025",
            "Access to directories outside the project is more than a project task needs.",
        ),
        _ref(
            OWASP_ASI_2026, "ASI03", "Wider file system access widens what a misused agent reaches."
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM03:2026",
            "Access to directories outside the project is more than a project task needs.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "attestation": (
        _ref(CWE, "CWE-345", "The extension's identity and publisher are not verified."),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "An extension whose publisher is not verified is an unvetted third-party component.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "An unverified extension is part of the agent tooling's supply chain.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "An extension whose publisher is not verified is an unvetted third-party component.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.001",
            "An extension without verified identity could be a compromised software package.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
    "authentication": (
        _ref(
            CWE,
            "CWE-306",
            "An agent card that declares no authentication requirement can leave the agent's "
            "functions unauthenticated; kept from the earlier SARIF rules, it does not hold for "
            "client findings, which record only the client's own configuration.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI03",
            "No declared authentication identifies the agent's callers, or the client to the "
            "agent it calls.",
        ),
        _ref(
            OWASP_ASI_2026, "ASI07", "Agent-to-agent communication has no declared authentication."
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "auto_approval": (
        _ref(
            OWASP_LLM_2025,
            "LLM06:2025",
            "Tool calls run without per-call approval, an excess of autonomy.",
        ),
        _ref(OWASP_ASI_2026, "ASI02", "The tools can be used, or misused, without a human check."),
        _ref(
            OWASP_LLM_2026,
            "LLM03:2026",
            "Tool calls run without per-call approval, an excess of autonomy.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0053",
            "Whoever steers the agent can invoke these tools without approval.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "bidi_override": _HIDDEN_CHARACTERS,
    "capability_scope": (
        _ref(
            OWASP_LLM_2025,
            "LLM06:2025",
            "A tool with destructive or financial effects, or misdeclared as read-only, raises "
            "the impact of what the agent can do.",
        ),
        _ref(OWASP_ASI_2026, "ASI02", "These are the tools whose misuse causes harm."),
        _ref(
            OWASP_LLM_2026,
            "LLM03:2026",
            "A tool with destructive or financial effects, or misdeclared as read-only, raises "
            "the impact of what the agent can do.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0053",
            "A tool with these effects is available for the agent to invoke.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
    ),
    "known_vulnerability": (
        _ref(
            CWE,
            "CWE-1395",
            "A dependency with a known vulnerability is part of the agent's supply chain.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "A vulnerable package in the agent runtime is a supply chain weakness.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "A vulnerable package in the agent runtime is a supply chain weakness.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "A compromised or vulnerable dependency reaches every agent that loads it.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010",
            "A vulnerable dependency is a supply chain compromise vector.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "code_execution": (
        _ref(
            CWE,
            "CWE-494",
            "Loading runs code fetched from the model repository without an integrity check.",
        ),
        _ref(
            CWE,
            "CWE-829",
            "Loading includes code from the model repository, outside the project's control.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "Code from a model repository runs when the model loads, a supply chain weakness.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "The model repository's code becomes part of the agent's supply chain.",
        ),
        _ref(OWASP_ASI_2026, "ASI05", "Loading the model executes repository code."),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "Code from a model repository runs when the model loads, a supply chain weakness.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0011.000",
            "Configuration that makes loading run repository code is an unsafe artifact as the "
            "technique defines one.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.2", _PRETRAINED),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "completeness": (
        _ref(
            NIST_AI_RMF,
            "GOVERN-1.6",
            "Records values the inventory cannot bind, identity fields it withholds, or an "
            "agent card without skills.",
        ),
        _ref(
            ISO_42001,
            "A.4.2",
            "Records information about a component that the inventory does not document.",
        ),
    ),
    "credential_exposure": (
        _ref(
            OWASP_LLM_2025,
            "LLM02:2025",
            "A credential committed with the agent's configuration is disclosed to everyone "
            "who reads the repository.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM02:2026",
            "A credential committed with the agent's configuration is disclosed to everyone "
            "who reads the repository.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI03",
            "A committed credential lets whoever reads the repository act as the agent does.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
        _ref(
            CWE,
            "CWE-798",
            "The credential is written into the configuration rather than supplied at run time.",
        ),
    ),
    "credential_helper": (
        _ref(
            OWASP_ASI_2026,
            "ASI03",
            "A command chosen in the settings supplies the agent's credentials.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI05",
            "The command runs automatically whenever the agent needs a credential.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0142",
            "A command that runs on an agent event is a mechanism for automatic code execution.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "custom_code": (
        _ref(
            CWE,
            "CWE-829",
            "Loading runs modules from the model repository, outside the project's control.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "Custom model code is a third-party component that runs when the model loads.",
        ),
        _ref(OWASP_ASI_2026, "ASI04", "The model's code is part of the agent's supply chain."),
        _ref(OWASP_ASI_2026, "ASI05", "Loading the model executes its custom code."),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "Custom model code is a third-party component that runs when the model loads.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0011.000",
            "Executable logic bundled with a model is an unsafe artifact as the technique "
            "defines one.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.2", _PRETRAINED),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "data_integrity": (
        _ref(
            CWE,
            "CWE-319",
            "The retrieval endpoint or locator uses an unencrypted transport.",
            *_HIGH_OR_CRITICAL,
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM04:2025",
            "Retrieved content without transport protection or content controls can be poisoned.",
        ),
        _ref(OWASP_LLM_2025, "LLM08:2025", "The weakness lies in a retrieval source of the agent."),
        _ref(OWASP_ASI_2026, "ASI06", "Retrieved content enters the agent's context."),
        _ref(
            OWASP_LLM_2026,
            "LLM05:2026",
            "Retrieved content without transport protection or content controls can be poisoned.",
        ),
        _ref(OWASP_LLM_2026, "LLM09:2026", "The weakness lies in a retrieval source of the agent."),
        _ref(
            MITRE_ATLAS,
            "AML.T0070",
            "Content unprotected in transit or unfiltered at ingestion is a precondition for "
            "poisoning retrieval.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "detection_method": (
        _ref(
            NIST_AI_RMF,
            "GOVERN-1.6",
            "Records an agent SDK use found in code with no declared deployment.",
        ),
        _ref(EU_AI_ACT, "Art. 11", _DOCUMENTATION),
        _ref(ISO_42001, "A.4.2", _RESOURCES),
    ),
    "directional_marks": _DISGUISED_TEXT,
    "endpoint_identity": (
        _ref(
            OWASP_ASI_2026,
            "ASI07",
            "The peer an MCP endpoint connects to cannot be identified from its declaration.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "hidden_markup": _DISGUISED_TEXT,
    "line_separators": (
        _ref(
            OWASP_LLM_2025,
            "LLM01:2025",
            "A line or paragraph separator can split instruction text in some renderers.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
    ),
    "identifier_characters": (
        _ref(
            CWE,
            "CWE-451",
            "A name with control, format or lookalike characters displays differently from "
            "what the agent and the inventory compare.",
        ),
        _ref(
            CWE,
            "CWE-1427",
            "A tool name reaches the model's context with characters that are not neutralized.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM01:2025",
            "A tool or server name that reads differently to a reviewer than to the model can "
            "carry injected text.",
        ),
        _ref(OWASP_ASI_2026, "ASI01", _HIDDEN_GOAL),
        _ref(
            OWASP_LLM_2026,
            "LLM01:2026",
            "A tool or server name that reads differently to a reviewer than to the model can "
            "carry injected text.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.005",
            "A tool whose name is disguised can stand in for a trusted agent tool.",
        ),
        _ref(MITRE_ATLAS, "AML.T0068", _HIDDEN_REVIEW),
        _ref(
            MITRE_ATLAS,
            "AML.T0074",
            "A lookalike or hidden-character name is a form of name manipulation.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "hook_commands": (
        _ref(OWASP_ASI_2026, "ASI05", "Commands run automatically on agent events."),
        _ref(
            MITRE_ATLAS,
            "AML.T0142",
            "Hooks that run commands on agent events are the mechanism this technique abuses.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "instruction_injection": (
        _ref(
            CWE,
            "CWE-1427",
            "Prompt or instruction text carries injection or auditor-deception directives without neutralization.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM01:2025",
            "Prompt or instruction text contains override, exfiltration, or deception directives.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI01",
            "Injected directives in prompt or skill files can hijack the agent's goal.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM01:2026",
            "Prompt or instruction text contains override, exfiltration, or deception directives.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0068",
            "Concealed or override directives disguise instructions to alter agent or auditor behavior.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "instruction_layering": (
        _ref(
            OWASP_LLM_2025,
            "LLM01:2025",
            "A second instruction location is another place where instructions can be inserted.",
        ),
        _ref(OWASP_ASI_2026, "ASI01", "Instructions from either location shape the agent's goal."),
        _ref(
            OWASP_LLM_2026,
            "LLM01:2026",
            "A second instruction location is another place where instructions can be inserted.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
    ),
    "invalid_safetensors": (
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "A model file whose structural safety is not established is an unverified artifact.",
        ),
        _ref(OWASP_ASI_2026, "ASI04", _MODEL_SUPPLY),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "A model file whose structural safety is not established is an unverified artifact.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0011.000",
            "A file presented as SafeTensors that was not validated may be an unsafe artifact.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.2", _PRETRAINED),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "invisible_characters": _HIDDEN_CHARACTERS,
    "launch_context": (
        _ref(
            OWASP_ASI_2026,
            "ASI05",
            "The launch widens what code the server runs or how far it reaches: host "
            "privileges, code-loading options, command fields or a shell.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "launcher_identity": (
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "The package an MCP server launches, and its version, cannot be established.",
        ),
        _ref(OWASP_ASI_2026, "ASI04", "An agent tool of unknown identity is a supply chain gap."),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "The package an MCP server launches, and its version, cannot be established.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.005",
            "A tool whose identity and pin are unknown could be compromised without detection.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "local_process": (
        _ref(
            OWASP_ASI_2026,
            "ASI07",
            "The agent exchanges messages with a tool server process whose executable is not "
            "verified.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.005",
            "An unverified tool executable could be a compromised agent tool without detection.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "lockfile_resolution_mismatch": (
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "The lockfile resolves a dependency to another package or version than it records.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "The agent's dependency resolution does not match its declaration.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "The lockfile resolves a dependency to another package or version than it records.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.001",
            "A lockfile record that resolves to another package can substitute a dependency.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
    # The package can be part of the project, as a workspace member is, so no third-party
    # or supplier reference holds; the finding records what the inventory leaves out.
    "lockfile_unread": (
        _ref(
            NIST_AI_RMF,
            "GOVERN-1.6",
            "Records an AI package whose resolution the inventory does not hold, because the "
            "collector does not read its lockfile.",
        ),
        _ref(
            ISO_42001,
            "A.4.2",
            "Records information about a component that the inventory does not document.",
        ),
    ),
    "mcp_auto_approval": (
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "MCP servers that the project declares are admitted without a per-server review.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.005",
            "A compromised server added to the project's server file would start without approval.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "missing_lockfile_integrity": (
        _ref(CWE, "CWE-494", "Without an integrity value, the downloaded package is not checked."),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "A dependency installed without an integrity check is a supply chain weakness.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "The agent's dependency is installed without an integrity check.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "A dependency installed without an integrity check is a supply chain weakness.",
        ),
        _ref(MITRE_ATLAS, "AML.T0010.001", "A download that is not checked can be substituted."),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
    "mutable_image_tag": (
        _ref(
            CWE,
            "CWE-829",
            "The tag can be moved to other image content outside the project's control.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "An image referenced by a movable tag is a supply chain weakness.",
        ),
        _ref(OWASP_ASI_2026, "ASI04", "The image the agent runs can change without review."),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "An image referenced by a movable tag is a supply chain weakness.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.004",
            "Pushing other content under an existing tag is how this technique replaces an image.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
    # Medium findings also record workspace and local path packages and local patches, which
    # can be part of the project, so every reference holds only for the high findings of
    # remote sources.
    "nonregistry_source": (
        _ref(
            CWE,
            "CWE-829",
            "The package comes from a git reference or plain HTTP source that can change.",
            RiskSeverity.HIGH,
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "A package from a remote source that can change lacks a registry's identity and "
            "integrity evidence.",
            RiskSeverity.HIGH,
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "The agent's dependency comes from a remote source that can change.",
            RiskSeverity.HIGH,
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "A package from a remote source that can change lacks a registry's identity and "
            "integrity evidence.",
            RiskSeverity.HIGH,
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.001",
            "A package from a remote source that can change is a software supply chain entry "
            "point.",
            RiskSeverity.HIGH,
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY, RiskSeverity.HIGH),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE, RiskSeverity.HIGH),
        _ref(ISO_42001, "A.10.3", _SUPPLIER, RiskSeverity.HIGH),
    ),
    "package_alias": (
        _ref(
            OWASP_LLM_2025, "LLM03:2025", "A dependency is installed under another package's name."
        ),
        _ref(
            OWASP_ASI_2026, "ASI04", "The package the agent's code imports is not the one it names."
        ),
        _ref(
            OWASP_LLM_2026, "LLM04:2026", "A dependency is installed under another package's name."
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0074",
            "Installing a package under another name is a form of name manipulation.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
    "package_source": (
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "The server's packages come from a non-default registry or index, so name and "
            "version do not establish identity.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "The agent tool's packages come from a source outside the default registry.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "The server's packages come from a non-default registry or index, so name and "
            "version do not establish identity.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.005",
            "A tool package resolved through another registry can be substituted there.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
    "oversight_gap": (
        _ref(CWE, "CWE-250", "A destructive or shell tool executes without human approval."),
        _ref(
            OWASP_LLM_2025,
            "LLM06:2025",
            "Auto-approving destructive tools grants excessive agency.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI02",
            "Destructive tool calls lack human-in-the-loop confirmation.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM03:2026",
            "Auto-approving destructive tools grants excessive agency.",
        ),
    ),
    "subagent_inline_mcp_server": (
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "Inline subagent mcpServers bypass top-level MCP server inventory review.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "Unpinned inline MCP server declarations expand the agent supply chain.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
    ),
    "permission_scope": (
        _ref(CWE, "CWE-250", "The agent runs with permissions beyond what a task needs."),
        _ref(
            OWASP_LLM_2025,
            "LLM06:2025",
            "Skipped prompts, unscoped allowances or an unsandboxed mode give the agent excess "
            "permissions or autonomy.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI02",
            "Tools can be used without per-call approval or resource scope.",
        ),
        _ref(OWASP_ASI_2026, "ASI03", "The agent's privileges are broader than its task."),
        _ref(
            OWASP_LLM_2026,
            "LLM03:2026",
            "Skipped prompts, unscoped allowances or an unsandboxed mode give the agent excess "
            "permissions or autonomy.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0053",
            "The agent can invoke tools without a prompt or beyond a resource scope.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0105",
            "Skipping permission prompts or disabling the sandbox lets tool calls act on the "
            "host unchecked.",
            RiskSeverity.HIGH,
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "plugin_sources": (
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "Plugins and marketplaces add third-party commands, agents, hooks and MCP servers.",
        ),
        _ref(
            OWASP_ASI_2026, "ASI04", "Plugins extend the agent with components from a marketplace."
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "Plugins and marketplaces add third-party commands, agents, hooks and MCP servers.",
        ),
        _ref(MITRE_ATLAS, "AML.T0010.005", "Plugins deliver agent tools from a marketplace."),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
    "prompt_size": (
        _ref(
            OWASP_LLM_2025,
            "LLM01:2025",
            "A large instruction file makes injected text harder to find in review.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI01",
            "Instructions that are hard to review can redirect the agent's goal unnoticed.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM01:2026",
            "A large instruction file makes injected text harder to find in review.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
    ),
    "rag_discovery": (
        _ref(
            OWASP_LLM_2025,
            "LLM08:2025",
            "A vector store is referenced without a declared configuration.",
        ),
        _ref(
            OWASP_ASI_2026, "ASI06", "An undeclared retrieval source can feed the agent's context."
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM09:2026",
            "A vector store is referenced without a declared configuration.",
        ),
        _ref(
            NIST_AI_RMF,
            "GOVERN-1.6",
            "Records a retrieval source found only in code or in environment variable names.",
        ),
        _ref(EU_AI_ACT, "Art. 11", _DOCUMENTATION),
        _ref(ISO_42001, "A.4.2", _RESOURCES),
        _ref(ISO_42001, "A.7.5", "The provenance of data from this source is not recorded."),
    ),
    "registry_origin": (
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "A package resolves, or is configured to resolve, from a registry or index other "
            "than the default one.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "The agent's dependency comes, or may come, from a non-default registry or index.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "A package resolves, or is configured to resolve, from a registry or index other "
            "than the default one.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.001",
            "The registry or index a package resolves from is part of its software supply chain.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
    "runtime_undeclared": (
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "The agent's telemetry reports a component that the inventory does not show as "
            "declared, so the inventory's review cannot be shown to cover it.",
        ),
        _ref(
            NIST_AI_RMF,
            "GOVERN-1.6",
            "The agent's telemetry reports an AI component that the inventory does not show "
            "as listed.",
        ),
        _ref(EU_AI_ACT, "Art. 11", _DOCUMENTATION),
        _ref(ISO_42001, "A.4.2", _RESOURCES),
    ),
    "serialization_format": (
        _ref(
            CWE,
            "CWE-502",
            "Pickle-based formats run code when deserialized; kept from the earlier SARIF "
            "rules, it does not hold for chat template findings, which record a template "
            "engine weakness.",
            RiskSeverity.CRITICAL,
        ),
        _ref(
            CWE,
            "CWE-1336",
            "Kept on high findings, where the earlier SARIF rules put it: a chat template that "
            "matches a potential Python-internals access pattern; this does not establish a "
            "template engine weakness. The collectors record "
            "this category only at critical.",
            RiskSeverity.HIGH,
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "A model artifact that can run code when it is loaded or its chat template is "
            "rendered is a supply chain weakness.",
        ),
        _ref(OWASP_ASI_2026, "ASI04", _MODEL_SUPPLY),
        _ref(
            OWASP_ASI_2026,
            "ASI05",
            "Loading the model, or rendering its chat template, can execute code.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "A model artifact that can run code when it is loaded or its chat template is "
            "rendered is a supply chain weakness.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0011.000",
            "Serialized models that run code when loaded, and chat templates that reach "
            "Python internals, are unsafe artifacts as the technique defines them.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.2", _PRETRAINED),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "serialization_format_unknown": (
        _ref(CWE, "CWE-502", "The model may use a format that runs code when deserialized."),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "A model artifact whose loading safety is unknown is an unverified supply chain "
            "component.",
        ),
        _ref(OWASP_ASI_2026, "ASI04", _MODEL_SUPPLY),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "A model artifact whose loading safety is unknown is an unverified supply chain "
            "component.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0011.000",
            "An artifact whose loading safety is unknown may be unsafe.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.2", _PRETRAINED),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    # The report's own rating is a heuristic of another tool; no reference is defensible.
    "shadowscan-heuristic": (),
    "shadowscan-inventory-unmatched": (
        _ref(
            NIST_AI_RMF,
            "GOVERN-1.6",
            "A discovery report found an AI component that the inventory it was given does "
            "not list.",
        ),
        _ref(EU_AI_ACT, "Art. 11", _DOCUMENTATION),
        _ref(ISO_42001, "A.4.2", _RESOURCES),
    ),
    "settings_environment": (
        _ref(
            OWASP_ASI_2026,
            "ASI03",
            "Settings can send the agent's credential to an endpoint or proxy they choose.",
            RiskSeverity.HIGH,
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI05",
            "Settings can load code into the session and every command it starts.",
            RiskSeverity.MEDIUM,
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "signing_status": (
        _ref(
            CWE,
            "CWE-345",
            "The model's weights are not bound to a verified signature or digest pin.",
        ),
        _ref(OWASP_LLM_2025, "LLM03:2025", "Unverified model weights are a supply chain weakness."),
        _ref(OWASP_ASI_2026, "ASI04", _MODEL_SUPPLY),
        _ref(OWASP_LLM_2026, "LLM04:2026", "Unverified model weights are a supply chain weakness."),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.003",
            "Weights without a verified signature or pin could be replaced in a model "
            "repository undetected.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.2", _PRETRAINED),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "tag_characters": _HIDDEN_CHARACTERS,
    "tool_description_poisoning": (
        _ref(
            CWE,
            "CWE-1427",
            "Tool or schema description carries directive tags or exfiltration instructions into the model prompt.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM01:2025",
            "Poisoned tool descriptions act as indirect prompt injection inside tool metadata.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI01",
            "Hidden or coercive directives inside tool metadata can redirect agent execution.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI02",
            "Poisoned tool guidance steers agents toward unintended sensitive reads or exfiltration.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM01:2026",
            "Poisoned tool descriptions act as indirect prompt injection inside tool metadata.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0010.005",
            "Local tool descriptors embed malicious behavioral instructions inside the agent tool chain.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0068",
            "Markup blocks or hidden directives inside tool schemas disguise injected instructions.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "transport_ambiguity": (_ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),),
    "transport_security": (
        _ref(
            CWE,
            "CWE-319",
            "An endpoint declared over plain HTTP or WebSocket transmits in cleartext; kept "
            "from the earlier SARIF rules, it does not hold for an endpoint URL that uses HTTPS "
            "but embeds credentials, or whose transport is unknown rather than unencrypted.",
            *_HIGH_OR_CRITICAL,
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI07",
            "Communication with an MCP server or A2A agent is not shown to be encrypted, or "
            "carries its credential in the URL; kept from the earlier SARIF rules, it does not "
            "hold for low findings on retrieval locators, which name data sources, not agents.",
        ),
        _ref(NIST_AI_RMF, "MEASURE-2.7", _EVALUATION),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
    ),
    "version_pinning": (
        _ref(
            CWE,
            "CWE-829",
            "What runs can change under a publisher's control without a change to the repository.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "An unpinned package, server package or image is a supply chain weakness.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "The agent's packages, servers or images can change without review.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "An unpinned package, server package or image is a supply chain weakness.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0109",
            "An unpinned reference takes the next published version, which a rug pull relies on.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
    "transitive_resolution": (
        _ref(
            CWE,
            "CWE-829",
            "Dependencies of a pinned package are resolved when the server starts.",
        ),
        _ref(
            OWASP_LLM_2025,
            "LLM03:2025",
            "A pinned MCP package whose dependencies are resolved at launch is a supply chain weakness.",
        ),
        _ref(
            OWASP_ASI_2026,
            "ASI04",
            "The agent's launched packages can change without a change to the pin.",
        ),
        _ref(
            OWASP_LLM_2026,
            "LLM04:2026",
            "A pinned MCP package whose dependencies are resolved at launch is a supply chain weakness.",
        ),
        _ref(
            MITRE_ATLAS,
            "AML.T0109",
            "A dependency resolved at launch can be replaced without moving the package pin.",
        ),
        _ref(NIST_AI_RMF, "MANAGE-3.1", _THIRD_PARTY),
        _ref(EU_AI_ACT, "Art. 15", _RESILIENCE),
        _ref(ISO_42001, "A.10.3", _SUPPLIER),
    ),
}


def framework(key: str) -> Framework:
    """The framework edition with this key; KeyError for an unknown key."""
    return _FRAMEWORKS[key]


def label(framework_key: str, entry_id: str) -> str:
    """An entry's title, after its technique's title when it is a sub-technique."""
    entry = _ENTRIES[(framework_key, entry_id)]
    if entry.parent is None:
        return entry.title
    return f"{_ENTRIES[(framework_key, entry.parent)].title}: {entry.title}"


def references(
    category: str, severity: RiskSeverity, frameworks: Collection[str] | None = None
) -> list[Reference]:
    """The references that hold for a finding, in framework and entry order.

    A category outside the catalog has none. ``frameworks`` limits them to those keys.
    """
    return sorted(
        (
            reference
            for reference in CROSSWALK.get(category, ())
            if reference.applies(severity)
            and (frameworks is None or reference.framework in frameworks)
        ),
        key=lambda reference: _POSITION[(reference.framework, reference.entry)],
    )


def sarif_tag(framework_key: str, entry_id: str) -> str | None:
    """GitHub's lower-case tag for an entry; None for a framework that SARIF does not tag."""
    prefix = _FRAMEWORKS[framework_key].sarif_prefix
    if prefix is None:
        return None
    if framework_key == CWE:
        return f"{prefix}cwe-{int(entry_id.removeprefix('CWE-')):03d}"
    return prefix + entry_id.split(":", 1)[0].lower()


def sarif_tags(category: str, severity: RiskSeverity) -> list[str]:
    """The taxonomy tags of a SARIF rule for this category and severity.

    The frameworks that the earlier catalog tagged come first, in its order, so that a
    consumer that matches those tags sees the same list with new tags after it.
    """
    held = references(category, severity)
    tags: list[str] = []
    for key in _SARIF_ORDER:
        for reference in held:
            if reference.framework == key and (tag := sarif_tag(key, reference.entry)):
                tags.append(tag)
    return tags
