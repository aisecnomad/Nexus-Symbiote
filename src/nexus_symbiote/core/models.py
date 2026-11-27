"""Pydantic domain models for all AgentBOM component types.

These extend CycloneDX/SPDX with agent-native semantics that neither standard
provides: tool capability declarations, prompt provenance, memory governance,
registry trust, and authorization records.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    StrictBool,
    StrictInt,
    field_validator,
    model_serializer,
    model_validator,
)

from nexus_symbiote.core.enums import (
    AssuranceLevel,
    AutonomyLevel,
    CapabilityClass,
    ComponentType,
    ExecutionIsolation,
    HumanInTheLoop,
    RiskSeverity,
    SerializationSafety,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.evidence import DeploymentProfile, Timestamp
from nexus_symbiote.utils.secrets import holds_token_shape

NATIVE_SPEC_VERSION = "1.2.0"
"""Version written by this build. 1.1.0 records scan-root-relative POSIX paths; 1.2.0 adds
credential components, which record a credential by name and never by value."""

SUPPORTED_SPEC_MINORS = {1: (0, 1, 2)}
"""Native format versions this build reads, as major -> supported minor versions."""

MAX_REFERENCE_CHARS = 16_384
"""Upper bound for a component reference; collector references stay far below it."""

UNBOUND_VALUES_DETAIL = "values not bound in this inventory"
"""Phrase in the completeness finding for values that only a source binding key binds."""

NAMED_FORMAT_PROPERTY = "named_format"
"""Model property: the format a file's name claims, recorded when its header did not
establish it, so the record has no ``serialization_format``."""

_SPEC_VERSION = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,5})")


class UnsupportedSpecVersionError(ValueError):
    """A native document declares a format version this build cannot interpret."""


def supported_spec_versions() -> str:
    return ", ".join(
        f"{major}.{minor}.x" for major, minors in SUPPORTED_SPEC_MINORS.items() for minor in minors
    )


def check_spec_version(value: object) -> None:
    """Refuse a native format version this build does not understand.

    The message quotes the declared version only when it has the expected numeric
    form, so document text cannot reach a terminal through it.
    """
    match = _SPEC_VERSION.fullmatch(value) if isinstance(value, str) else None
    if match is not None and int(match[2]) in SUPPORTED_SPEC_MINORS.get(int(match[1]), ()):
        return
    shown = f"version {value}" if match is not None else "an unrecognised version"
    raise UnsupportedSpecVersionError(
        f"Native format {shown} is not supported by this build (supported: "
        f"{supported_spec_versions()}); upgrade nexus-symbiote or re-collect the inventory."
    )


CREDENTIAL_SPEC_VERSION = (1, 2)
"""The first native format version, as (major, minor), whose documents carry credentials."""

CREDENTIAL_FORMAT_REFUSAL = "credential components need native format 1.2.0 or later"

CREDENTIAL_SPEC_VERSION_PATTERN = r"^1\.(?:[2-9]|[1-9][0-9]{1,3})\.(?:0|[1-9][0-9]{0,5})$"
"""A supported 1.x version at or after ``CREDENTIAL_SPEC_VERSION``, for the native schema."""


def admits_credentials(spec_version: str) -> bool:
    match = _SPEC_VERSION.fullmatch(spec_version)
    return match is not None and (int(match[1]), int(match[2])) >= CREDENTIAL_SPEC_VERSION


class InventoryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClaimEvidence(InventoryModel):
    """Evidence about one named claim; observation never establishes runtime permission."""

    assurance: AssuranceLevel = AssuranceLevel.DECLARED
    method: str
    scope: str
    collector: str | None = None
    locator: str | None = None
    observed_at: Timestamp | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    unknown_reason: str | None = None


def _require_component_type(schema: dict[str, Any]) -> None:
    """Publish ``component_type`` as required: it is the tag a reader selects the model by.

    Each subclass keeps its type as the default for objects built in process.
    """
    properties = schema["properties"]
    properties["component_type"].pop("default", None)
    required = {*schema.get("required", ()), "component_type"}
    schema["required"] = [name for name in properties if name in required]


class ComponentBase(InventoryModel):
    """Base for every AgentBOM component."""

    model_config = ConfigDict(json_schema_extra=_require_component_type)

    bom_ref: str = Field(
        description="Unique reference within this BOM", max_length=MAX_REFERENCE_CHARS
    )
    component_type: ComponentType
    name: str
    version: str | None = None
    supplier: str | None = None
    description: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    trust_tier: TrustTier = TrustTier.UNKNOWN
    assurance_level: AssuranceLevel = Field(
        default=AssuranceLevel.DECLARED,
        description=(
            "declared: stated by configuration, a manifest or a supplier; observed: a named "
            "collector measured the component's identity from bytes (a file, weight or "
            "descriptor digest); verified: established by cryptographic verification, which "
            "offline collection never assigns"
        ),
    )
    source_path: str | None = Field(
        default=None,
        description=(
            "Where this was discovered: a POSIX path relative to the scan root (native "
            "format 1.1.0 and later), or a URL. Format 1.0.0 recorded absolute scan-host paths"
        ),
    )
    properties: dict[str, Any] = Field(default_factory=dict, description="Extension properties")
    claims: dict[str, ClaimEvidence] = Field(default_factory=dict)


class CapabilityDeclaration(InventoryModel):
    """What a component is declared to do; a declaration, not a granted permission."""

    capabilities: list[CapabilityClass] = Field(default_factory=list)
    oauth_scopes: list[str] = Field(default_factory=list)
    egress_domains: list[str] = Field(
        default_factory=list,
        description="Reserved: no built-in collector populates this field; supplier assertion",
    )
    filesystem_paths: list[str] = Field(
        default_factory=list,
        description="Reserved: no built-in collector populates this field; supplier assertion",
    )
    side_effect_profile: SideEffectProfile = SideEffectProfile.UNKNOWN
    execution_isolation: ExecutionIsolation | None = Field(
        default=None, description="Declared isolation; null or absent means unknown"
    )
    human_in_the_loop: HumanInTheLoop | None = Field(
        default=None, description="Declared human-approval setting; null or absent means unknown"
    )


class AuthorizationRecord(InventoryModel):
    """Who authorized what, under which policy."""

    principal: str
    delegating_principal: str | None = None
    action: str
    resource_scope: str | None = None
    conditions: list[str] = Field(default_factory=list)
    approval_required: StrictBool | None = None
    expires_at: Timestamp | None = None
    policy_reference: str | None = None


class RiskAssessment(InventoryModel):
    """Per-component supply chain risk assessment."""

    severity: RiskSeverity
    category: str
    detail: str
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)


class AgentComponent(ComponentBase):
    """An autonomous AI agent deployment."""

    component_type: Literal[ComponentType.AGENT] = ComponentType.AGENT
    autonomy_level: AutonomyLevel | None = None
    deployment_status: Literal["unknown", "declared", "observed"] = "unknown"
    deployment_id: str | None = None
    workload_identity: str | None = None
    tenant: str | None = None
    data_refs: list[str] = Field(default_factory=list)
    skill_refs: list[str] = Field(default_factory=list)
    framework: str | None = Field(
        default=None, description="Agent framework (LangGraph, CrewAI, etc.)"
    )
    model_refs: list[str] = Field(
        default_factory=list, description="bom_ref pointers to model components"
    )
    tool_refs: list[str] = Field(
        default_factory=list, description="bom_ref pointers to tool/MCP components"
    )
    memory_refs: list[str] = Field(default_factory=list)
    prompt_refs: list[str] = Field(default_factory=list)
    guardrail_refs: list[str] = Field(default_factory=list)
    sub_agent_refs: list[str] = Field(
        default_factory=list,
        description="bom_ref pointers to delegated sub-agents",
    )
    capabilities: CapabilityDeclaration | None = None
    authorizations: list[AuthorizationRecord] = Field(default_factory=list)
    risks: list[RiskAssessment] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def preserve_unknown_autonomy(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        # Explicit unknown must survive exclude_none exports and legacy snapshot loading.
        if self.autonomy_level is None:
            data["autonomy_level"] = None
        return data

    deployment_profile: DeploymentProfile | None = Field(
        default=None,
        description="Optional deployment-scoped authority claims and their evidence provenance",
    )


class MCPServerComponent(ComponentBase):
    """An MCP server that provides tools to agents."""

    component_type: Literal[ComponentType.MCP_SERVER] = ComponentType.MCP_SERVER
    transport: str | None = Field(
        default=None, description="stdio, sse, streamable-http, websocket"
    )
    command: str | None = None
    launcher_package: str | None = Field(
        default=None,
        description="Declared ecosystem and package name or image repository, when safely identified",
    )
    package_url: str | None = Field(
        default=None,
        description="Exact npm or PyPI package URL of the launched package, only for an exact pin from the default registry; not proof of installed artifact identity",
    )
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    endpoint_url: str | None = None
    tool_count: StrictInt = 0
    tool_refs: list[str] = Field(default_factory=list)
    registry_source: str | None = Field(
        default=None,
        description="Reserved: no built-in collector populates this field; supplier assertion",
    )
    version_pinned: StrictBool | None = Field(
        default=None,
        description="True for an exact version, commit or digest; false for a floating or unclassified package runner reference; null when no package runner is declared",
    )
    schema_hash: str | None = Field(
        default=None,
        description="Hash of the aggregate tool definitions served by this MCP server",
    )
    risks: list[RiskAssessment] = Field(default_factory=list)


class ToolComponent(ComponentBase):
    """A single tool definition (from MCP, plugin, or function call)."""

    component_type: Literal[ComponentType.TOOL] = ComponentType.TOOL
    mcp_server_ref: str | None = None
    input_schema: dict[str, Any] | None = None
    description_text: str | None = Field(
        default=None,
        description="The natural-language description fed into the LLM context",
    )
    definition_hash: str | None = Field(
        default=None,
        description=(
            "RFC 8785 JCS hash of name, description, inputSchema and annotations, plus "
            "title, outputSchema and _meta when the descriptor declares them"
        ),
    )
    redacted_definition_hash: str | None = Field(
        default=None,
        description="Digest of the displayed descriptor when sensitive content was removed; the original definition_hash remains the source fingerprint",
    )
    capabilities: CapabilityDeclaration | None = None
    annotations: dict[str, Any] = Field(
        default_factory=dict,
        description="MCP tool annotations (readOnlyHint, destructiveHint, etc.)",
    )
    risks: list[RiskAssessment] = Field(default_factory=list)

    definition_hash_version: str | None = Field(
        default=None,
        description="Canonicalization protocol; absent, or an earlier one, for legacy fingerprints",
    )


class ModelComponent(ComponentBase):
    """A model (weights, adapter, embedding model) used by an agent."""

    component_type: Literal[ComponentType.MODEL] = ComponentType.MODEL
    model_type: str | None = Field(
        default=None,
        description="foundation, fine-tuned, adapter, embedding, quantized, hosted",
    )
    provider: str | None = None
    endpoint: str | None = None
    requested_alias: str | None = Field(
        default=None, description="The alias requested (e.g. 'gpt-4o')"
    )
    resolved_revision: str | None = Field(
        default=None, description="Provider-specific snapshot identifier"
    )
    serialization_format: str | None = None
    serialization_safety: SerializationSafety = SerializationSafety.UNKNOWN
    signing_status: str | None = Field(
        default=None,
        description=(
            "Collector-reported signature evidence under the operator signer policy: "
            "sigstore-signed, digest-pinned, partially-verified, verification-failed, "
            "verification-unavailable, signature-present-unverified or signature-not-found; "
            "never trusted as verification. unsigned and pgp-signed appear only in older "
            "inventories"
        ),
    )
    signing_identity: str | None = None
    base_model_ref: str | None = Field(
        default=None, description="bom_ref of the base model this derives from"
    )
    derivation_type: str | None = Field(
        default=None,
        description="fine-tune, lora, qlora, merge, quantization, distillation",
    )
    quantization_method: str | None = None
    tokenizer_hash: str | None = None
    chat_template_hash: str | None = None
    tensor_inventory_hash: str | None = Field(
        default=None,
        description="SHA-256 of tensor names, dtypes, shapes and offsets; not tensor bytes",
    )
    safetensors_header_hash: str | None = None
    trust_remote_code: StrictBool | None = Field(
        default=None, description="Declared configuration only; the runtime value may differ"
    )
    risks: list[RiskAssessment] = Field(default_factory=list)


class PromptComponent(ComponentBase):
    """A system prompt, instruction template, or behavior-shaping artifact."""

    component_type: Literal[ComponentType.PROMPT_TEMPLATE] = ComponentType.PROMPT_TEMPLATE
    prompt_type: str | None = Field(
        default=None,
        description=(
            "system-prompt, planner, instruction, rules-file, skill-definition, subagent, "
            "imported-instruction, template"
        ),
    )
    content_hash: str | None = Field(default=None, description="Hash of the exact prompt bytes")
    variable_schema: dict[str, Any] | None = Field(
        default=None, description="Schema of template variables"
    )
    modification_authority: str | None = Field(
        default=None,
        description="Who can edit this prompt (owner, admin, agent, public)",
    )
    risks: list[RiskAssessment] = Field(default_factory=list)


class GuardrailComponent(ComponentBase):
    """A safety classifier, content filter, output validator, or evaluation configuration.

    The rag collector records guardrail and evaluation configuration files that it
    recognises by name, with the digest of their bytes in config_hash; it never parses
    them, so a record does not show what the file configures or that anything enforces
    it. Every other field appears only in supplied inventories.
    """

    component_type: Literal[ComponentType.GUARDRAIL_POLICY] = ComponentType.GUARDRAIL_POLICY
    guardrail_type: str | None = Field(
        default=None,
        description=(
            "policy or evaluation when a collector derived it from the file name; supplied "
            "inventories also use input-filter, output-filter, classifier, rate-limiter"
        ),
    )
    model_ref: str | None = Field(
        default=None, description="bom_ref of the model backing this guardrail"
    )
    policy_version: str | None = None
    config_hash: str | None = Field(
        default=None,
        description=(
            "sha256:<hex> of the configuration file's bytes; for a directory with Colang "
            "files, the RFC 8785 digest of the map from each file name to its digest"
        ),
    )
    risks: list[RiskAssessment] = Field(default_factory=list)


class MemoryStoreComponent(ComponentBase):
    """Persistent memory (conversation history, learned facts, skills).

    Reserved: no built-in collector emits this type; it appears only in supplied inventories.
    """

    component_type: Literal[ComponentType.MEMORY_STORE] = ComponentType.MEMORY_STORE
    store_type: str | None = Field(
        default=None,
        description="conversation, episodic, semantic, procedural, skill",
    )
    write_authority: str | None = Field(
        default=None,
        description="Who may write: agent-only, user, system, public",
    )
    retention_policy: str | None = None
    tenant_isolated: StrictBool | None = None
    encryption_at_rest: StrictBool | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class RAGSourceComponent(ComponentBase):
    """A retrieval-augmented generation data source or vector index."""

    component_type: Literal[ComponentType.RAG_SOURCE] = ComponentType.RAG_SOURCE
    corpus_type: str | None = Field(
        default=None,
        description="vector-store, knowledge-base, web-scraper, api-connector",
    )
    embedding_model_ref: str | None = None
    embedding_model_name: str | None = None
    chunking_strategy: str | None = None
    index_snapshot_hash: str | None = None
    source_uris: list[str] = Field(default_factory=list)
    refresh_policy: str | None = None
    last_indexed_at: Timestamp | None = None
    document_count: StrictInt | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class DataSourceComponent(ComponentBase):
    """A training or fine-tuning dataset.

    Reserved: no built-in collector emits this type; it appears only in supplied inventories.
    """

    component_type: Literal[ComponentType.DATA_SOURCE] = ComponentType.DATA_SOURCE
    dataset_type: str | None = Field(
        default=None,
        description="pre-training, fine-tuning, evaluation, alignment",
    )
    source_uri: str | None = None
    content_hash: str | None = None
    collection_date: str | None = None
    license: str | None = None
    consent_status: str | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class RegistryEntryComponent(ComponentBase):
    """A package or image reference and the registry it comes from."""

    component_type: Literal[ComponentType.REGISTRY_ENTRY] = ComponentType.REGISTRY_ENTRY
    package_url: str | None = Field(
        default=None,
        description="Declared exact package URL; not proof of installed artifact identity",
    )
    registry_type: str | None = Field(
        default=None,
        description=(
            "npm, pypi, docker-hub or oci from built-in collectors; huggingface, mcp-registry "
            "and skill-marketplace are reserved for supplied inventories"
        ),
    )
    registry_uri: str | None = None
    publisher_identity: str | None = None
    publisher_verified: StrictBool | None = None
    attestation_status: str | None = None
    signing_key_reference: str | None = None
    trust_model: str | None = Field(default=None, description="tofu, pki, sigstore, none")
    risks: list[RiskAssessment] = Field(default_factory=list)


class SkillPackageComponent(ComponentBase):
    """A skill or plugin package that extends agent capabilities."""

    component_type: Literal[ComponentType.SKILL_PACKAGE] = ComponentType.SKILL_PACKAGE
    skill_type: str | None = Field(
        default=None, description="skill, skill-resource, plugin, connector, hook, extension"
    )
    registry_ref: str | None = None
    entry_point: str | None = None
    capabilities: CapabilityDeclaration | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class MCPClientComponent(ComponentBase):
    """An MCP client that connects to MCP servers."""

    component_type: Literal[ComponentType.MCP_CLIENT] = ComponentType.MCP_CLIENT
    host_application: str | None = Field(
        default=None, description="The IDE or agent host (claude-code, cursor, etc.)"
    )
    server_refs: list[str] = Field(
        default_factory=list, description="bom_ref pointers to connected MCP servers"
    )
    config_path: str | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class A2AClientComponent(ComponentBase):
    """An A2A protocol client that discovers and invokes remote agents."""

    component_type: Literal[ComponentType.A2A_CLIENT] = ComponentType.A2A_CLIENT
    agent_card_url: str | None = Field(default=None, description="URL of the remote agent card")
    supported_protocols: list[str] = Field(default_factory=list)
    authentication_methods: list[str] = Field(default_factory=list)
    capabilities: CapabilityDeclaration | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class A2AServerComponent(ComponentBase):
    """An A2A protocol server exposing agent capabilities to other agents."""

    component_type: Literal[ComponentType.A2A_SERVER] = ComponentType.A2A_SERVER
    agent_card_path: str | None = Field(
        default=None, description="Path or URL to the agent card JSON"
    )
    endpoint_url: str | None = None
    supported_protocols: list[str] = Field(default_factory=list)
    skills_declared: list[str] = Field(default_factory=list)
    authentication_required: StrictBool | None = None
    capabilities: CapabilityDeclaration | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class IDEAgentComponent(ComponentBase):
    """An IDE coding agent configuration (Claude Code, Codex, Cursor, etc.)."""

    component_type: Literal[ComponentType.IDE_AGENT] = ComponentType.IDE_AGENT
    ide_type: str | None = Field(
        default=None,
        description=(
            "claude-code, codex, cursor, gemini, antigravity, xai, windsurf, cline, copilot"
        ),
    )
    config_files: list[str] = Field(default_factory=list)
    mcp_server_refs: list[str] = Field(default_factory=list)
    prompt_refs: list[str] = Field(default_factory=list)
    permission_mode: str | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class VerifiedExtensionComponent(ComponentBase):
    """An AI agent extension with verification/attestation status."""

    component_type: Literal[ComponentType.VERIFIED_EXTENSION] = ComponentType.VERIFIED_EXTENSION
    extension_type: str | None = Field(
        default=None, description="ide-extension, plugin, skill, connector, integration, action"
    )
    publisher: str | None = None
    publisher_verified: StrictBool | None = Field(
        default=None, description="Whether a publisher was verified; null or absent means unknown"
    )
    attestation_status: str | None = Field(
        default=None, description="verified, unverified, revoked, expired"
    )
    signing_identity: str | None = None
    marketplace_url: str | None = None
    install_count: StrictInt | None = None
    capabilities: CapabilityDeclaration | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


CredentialKind = Literal["environment-variable", "workflow-credential", "source-literal"]


class CredentialComponent(ComponentBase):
    """A credential that a component authenticates with, recorded by name, never by value.

    The name is what holds the credential: an environment variable, the label under
    which a workflow tool stores it, or the parameter a literal is passed as. A record
    with any text shaped like a credential value, or with any digest, is refused when it
    is built and again by every export (``core.aibom.prepare``), which a record changed
    after it was built cannot bypass. Only format 1.2.0 and later documents carry one.
    """

    component_type: Literal[ComponentType.CREDENTIAL] = ComponentType.CREDENTIAL
    hashes: dict[str, str] = Field(
        default_factory=dict,
        max_length=0,
        description=(
            "Always empty: an unkeyed digest of a secret can be checked against a guessed or "
            "leaked value"
        ),
    )
    credential_kind: CredentialKind | None = Field(
        default=None,
        description=(
            "What the name is: environment-variable (a variable that source reads, a .env "
            "template lists or a ${NAME} placeholder names), workflow-credential (the label "
            "under which a workflow tool stores the credential) or source-literal (the "
            "parameter a literal value is passed as in source)"
        ),
    )
    value_in_checkout: StrictBool | None = Field(
        default=None,
        description=(
            "Whether a literal value sits beside the reference in the scanned checkout; "
            "the value itself is never recorded"
        ),
    )
    risks: list[RiskAssessment] = Field(default_factory=list)

    @model_validator(mode="after")
    def _holds_no_value(self) -> CredentialComponent:
        problem = credential_value_problem(self)
        if problem is not None:
            raise ValueError(problem)
        return self


def credential_value_problem(component: CredentialComponent) -> str | None:
    """Why a credential record may not be written, as fixed text, or ``None``."""
    if component.hashes:
        return "a credential records no digest of its value"
    if any(holds_token_shape(text) for text in _texts(component.model_dump(mode="json"))):
        return "a credential record holds text shaped like a credential value"
    return None


def _texts(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _texts(item)
    elif isinstance(value, list):
        for item in value:
            yield from _texts(item)


class DiscoveryVerification(InventoryModel):
    """How imported ShadowScan discovery evidence was authenticated at import.

    The record binds the imported report to its exact bytes (``report_digest``),
    its normalized content (``report_content_digest``), and whatever
    repository/commit/time the report itself carries: its top-level ``repository``
    and ``commit``, or a CycloneDX report's ``shadowscan:repository`` and
    ``shadowscan:commit`` properties, and as ``report_time`` a CycloneDX report's
    ``metadata.timestamp``, else the report's own ``finished_at`` (else
    ``started_at``). A value the report does not carry reads ``"unknown"`` —
    never a fabricated value; the current ShadowScan report formats carry no
    repository or commit. Import time is not recorded: ``metadata.timestamp`` is
    set only when a caller supplies one. A ``verified`` record names the signer
    identity and issuer whose Sigstore bundle was checked over the exact report
    bytes; ``unverified`` means no such check ran at import; ``not-applicable``
    means no discovery report was imported.
    """

    status: Literal["verified", "unverified", "not-applicable"] = "unverified"
    method: Literal["sigstore", "none"] = "none"
    report_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
        description="SHA-256 of the exact imported report bytes",
    )
    report_content_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
        description="SHA-256 of the RFC 8785 canonical report without run-event fields",
    )
    signer_identity: str | None = Field(
        default=None, description="Sigstore identity that signed the report, when verified"
    )
    issuer: str | None = Field(
        default=None, description="OIDC issuer of the report signer, when verified"
    )
    repository: str = Field(
        default="unknown",
        description=(
            "Repository the report claims (top-level repository, or a CycloneDX report's "
            "shadowscan:repository property), or 'unknown' when it carries none"
        ),
    )
    commit: str = Field(
        default="unknown",
        description=(
            "Commit the report claims (top-level commit, or a CycloneDX report's "
            "shadowscan:commit property), or 'unknown' when it carries none"
        ),
    )
    report_time: str = Field(
        default="unknown",
        description=(
            "A CycloneDX report's metadata.timestamp, else the report's own finished_at "
            "(else started_at), or 'unknown' when it carries none"
        ),
    )


class CompletenessClaim(InventoryModel):
    """What was actually scanned and what was excluded."""

    scope: str = Field(
        description=(
            "What this completeness claim covers. Built-in collection writes repository, "
            "or repository+shadowscan with an imported discovery report (scan), "
            "shadowscan-imported (import-shadowscan) or mcp-endpoint-observation "
            "(discover-mcp)"
        )
    )
    surfaces_scanned: list[str] = Field(default_factory=list)
    surfaces_excluded: list[str] = Field(default_factory=list)
    scan_failures: list[str] = Field(default_factory=list)
    timestamp: Timestamp | None = None
    assurance_level: AssuranceLevel = AssuranceLevel.DECLARED
    collectors_requested: list[str] = Field(default_factory=list)
    collectors_completed: list[str] = Field(default_factory=list)
    unobserved_surfaces: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)

    source_report_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
        description="SHA-256 of exact imported report bytes, not producer authentication",
    )
    source_report_content_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
        description=(
            "SHA-256 of the RFC 8785 canonical report without run-event fields, for drift "
            "comparison; neither authentication nor a substitute for source_report_digest"
        ),
    )
    source_report_content_profile: Literal["nexus-symbiote/shadowscan-content/v1"] | None = None
    source_report_format: Literal["shadowscan-json", "shadowscan-cyclonedx"] | None = None
    source_report_status: Literal["complete", "incomplete", "unknown"] | None = None
    source_projection_limitations: list[str] | None = Field(
        default=None,
        description="Limitations of the imported discovery projection, independent of static repository coverage",
    )
    source_unmapped_count: StrictInt = Field(default=0, ge=0)
    source_unmapped_indexes: list[Annotated[StrictInt, Field(ge=0)]] = Field(default_factory=list)
    source_report_path: str | None = Field(
        default=None,
        description=(
            "POSIX path of the imported report relative to the scan root, or only its file "
            "name when imported from outside a root; never an absolute local path"
        ),
    )
    discovery_verification: DiscoveryVerification | None = Field(
        default=None,
        description=(
            "Signature-verification outcome for the imported discovery report, "
            "with its digest and repo/commit/time binding; absent on BOMs written "
            "before this record existed"
        ),
    )

    scanner_status: dict[str, str] = Field(default_factory=dict)


class AIBOMMetadata(InventoryModel):
    """Header metadata for an AgentBOM document."""

    spec_version: str = Field(
        default=NATIVE_SPEC_VERSION,
        description=(
            "Native format version. This build reads 1.0.x, 1.1.x and 1.2.x; 1.1.0 records "
            "scan-root-relative paths, and 1.2.0 adds credential components, which no earlier "
            "version carries"
        ),
    )
    serial_number: str | None = None
    version: StrictInt = 1
    timestamp: Timestamp | None = None
    tool_name: str = "nexus-symbiote"
    tool_version: str | None = None
    tool_vendor: str = "aisecnomad"
    authors: list[str] = Field(default_factory=list)
    completeness: CompletenessClaim | None = None
    policy_source: str | None = Field(
        default=None,
        description=(
            "Policy that governed collection: built-in, or project:<file relative to the scan "
            "root>. Absent when the producer did not record it"
        ),
    )
    policy_weakened: list[str] | None = Field(
        default=None,
        description="Settings of that policy that gate less strictly than the built-in policy",
    )

    @field_validator("spec_version")
    @classmethod
    def supported_version(cls, value: str) -> str:
        check_spec_version(value)
        return value


AnyComponent = Annotated[
    (
        AgentComponent
        | MCPServerComponent
        | ToolComponent
        | ModelComponent
        | PromptComponent
        | GuardrailComponent
        | MemoryStoreComponent
        | RAGSourceComponent
        | DataSourceComponent
        | RegistryEntryComponent
        | SkillPackageComponent
        | MCPClientComponent
        | A2AClientComponent
        | A2AServerComponent
        | IDEAgentComponent
        | VerifiedExtensionComponent
        | CredentialComponent
    ),
    Field(discriminator="component_type"),
]
