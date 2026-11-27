"""Rule catalog for SARIF: application-owned titles, help and taxonomy tags.

Rule text never comes from the inventory. Every documented finding category has an
entry. A ``RuleInfo`` holds only a title and a description: a rule's taxonomy tags come
from the framework crosswalk (``nexus_symbiote.crosswalk.CROSSWALK``), as CWE in GitHub's
``external/cwe/cwe-NNN`` form, the OWASP Top 10 for LLM Applications 2025 and 2026, the
OWASP Top 10 for Agentic Applications, MITRE ATLAS and the NIST AI RMF. A new category
needs an entry here and one in ``CROSSWALK``, which may be an empty tuple.
docs/standard-exports.md lists the same table, and a test keeps the two equal.
"""

from __future__ import annotations

from dataclasses import dataclass

from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.crosswalk import sarif_tags


@dataclass(frozen=True)
class RuleInfo:
    title: str
    description: str


RULES: dict[str, RuleInfo] = {
    "version_pinning": RuleInfo(
        "Unpinned version",
        "A dependency, MCP server package or container image is declared without an exact "
        "version or digest, so what runs can change without a change to the repository.",
    ),
    "transitive_resolution": RuleInfo(
        "Dependencies resolved at launch",
        "An MCP server pins its package version, but the package runner resolves that "
        "package's dependencies when the server starts, without a lockfile.",
    ),
    "mutable_image_tag": RuleInfo(
        "Mutable image tag",
        "A container image is referenced by a tag rather than a digest; the tag can be "
        "moved to different image content.",
    ),
    "transport_security": RuleInfo(
        "Transport security",
        "An endpoint is declared without TLS or with credentials in its URL, or a retrieval "
        "locator's transport is not shown to be encrypted.",
    ),
    "local_process": RuleInfo(
        "Local MCP server process",
        "An MCP server runs as a local process whose executable the inventory does not verify.",
    ),
    "authentication": RuleInfo(
        "Missing authentication requirement",
        "An A2A agent card declares no authentication requirement for itself or a skill, or "
        "an A2A client declares no authentication method.",
    ),
    "serialization_format": RuleInfo(
        "Unsafe model serialization",
        "A model artifact uses a format or loader that can execute code or evaluate "
        "templates when the model is loaded.",
    ),
    "serialization_format_unknown": RuleInfo(
        "Unknown model serialization safety",
        "The safety of a model artifact's format or loader could not be established.",
    ),
    "settings_environment": RuleInfo(
        "Redirecting or code-loading settings environment",
        "Claude Code settings set environment variables that send the API key and prompts to "
        "another endpoint, proxy or trust store, or that load code into the session and the "
        "commands it runs.",
    ),
    "signing_status": RuleInfo(
        "Unsigned model artifact",
        "A model artifact has no verified signature bound to its bytes.",
    ),
    "code_execution": RuleInfo(
        "Remote code execution enabled",
        "A model configuration lets the loader run code from the model repository.",
    ),
    "invisible_characters": RuleInfo(
        "Invisible characters in instructions",
        "An instruction file contains invisible Unicode characters that can carry hidden "
        "instructions.",
    ),
    "bidi_override": RuleInfo(
        "Bidirectional override in instructions",
        "An instruction file contains bidirectional control characters that can make text "
        "read differently from how it is processed.",
    ),
    "tag_characters": RuleInfo(
        "Unicode tag characters in instructions",
        "An instruction file contains invisible Unicode tag characters, or unassigned "
        "default-ignorable code points of plane 14, a known way to hide "
        "prompt text.",
    ),
    "prompt_size": RuleInfo(
        "Large instruction file",
        "An instruction file is large enough to make review for injected text difficult.",
    ),
    "instruction_injection": RuleInfo(
        "Injected instructions or deception in prompt files",
        "An instruction file, skill declaration, or assistant prompt contains prompt-injection "
        "override directives, exfiltration instructions, or automated-auditor deception.",
    ),
    "instruction_layering": RuleInfo(
        "Layered instruction files",
        "An IDE agent reads instructions from more than one location.",
    ),
    "permission_scope": RuleInfo(
        "Unscoped agent permissions",
        "An IDE agent configuration skips or relaxes approval prompts, turns off the "
        "sandbox, or allows tools without scoping them to resources.",
    ),
    "oversight_gap": RuleInfo(
        "Destructive tool auto-approved",
        "A destructive or shell-capable tool resolves to automatic approval without "
        "human-in-the-loop oversight under the declared settings precedence.",
    ),
    "subagent_inline_mcp_server": RuleInfo(
        "Subagent inline MCP server",
        "A subagent markdown front-matter block declares inline mcpServers outside the "
        "top-level .mcp.json inventory.",
    ),
    "capability_scope": RuleInfo(
        "Destructive tool capability",
        "A tool declares destructive or financial side effects, or is declared read-only "
        "but named for a destructive operation; or its source body runs commands or makes a "
        "payment.",
    ),
    "data_integrity": RuleInfo(
        "Retrieval source integrity",
        "A retrieval source is reached without encryption or declares no content control.",
    ),
    "rag_discovery": RuleInfo(
        "Undeclared retrieval source",
        "A vector store or retrieval source is referenced without a declared configuration.",
    ),
    "attestation": RuleInfo(
        "Unattested extension",
        "An agent extension has no verified attestation of its identity or publisher.",
    ),
    "completeness": RuleInfo(
        "Incomplete declaration",
        "A declaration lacks information the inventory needs to detect changes.",
    ),
    "detection_method": RuleInfo(
        "Code-detected reference",
        "A component was inferred from source code rather than declared configuration.",
    ),
    "shadowscan-heuristic": RuleInfo(
        "Imported discovery risk",
        "An imported ShadowScan report rated this component; the rating is heuristic.",
    ),
    "shadowscan-inventory-unmatched": RuleInfo(
        "Imported unmatched discovery",
        "An imported ShadowScan report found no matching inventory entry.",
    ),
    "additional_directories": RuleInfo(
        "Access outside the project",
        "Claude Code settings grant the agent access to directories outside the project.",
    ),
    "auto_approval": RuleInfo(
        "MCP tools without per-call approval",
        "An MCP server's tools run without per-call approval: alwaysAllow, autoApprove or "
        "trust is set.",
    ),
    "credential_exposure": RuleInfo(
        "Literal credential in an MCP launch",
        "An MCP server's env value, launch argument, header or endpoint URL query holds a "
        "literal credential, which the inventory redacts: a vendor token shape, an "
        "authorization scheme credential or a generic secret-like value. The finding names "
        "the positions, never a value.",
    ),
    "credential_helper": RuleInfo(
        "Credential helper command",
        "Claude Code settings declare a credential helper, a command that runs to obtain "
        "credentials: apiKeyHelper, awsAuthRefresh, awsCredentialExport, gcpAuthRefresh or "
        "otelHeadersHelper. The finding names each one declared.",
    ),
    "custom_code": RuleInfo(
        "Custom model code",
        "A model's configuration declares custom code (auto_map or custom_pipelines), which "
        "loading runs under trust_remote_code.",
    ),
    "directional_marks": RuleInfo(
        "Directional marks in instructions",
        "An instruction file contains left-to-right, right-to-left or Arabic letter marks, "
        "which are ordinary in right-to-left text but can reorder neutral characters.",
    ),
    "endpoint_identity": RuleInfo(
        "Unestablished endpoint identity",
        "An MCP endpoint's host cannot be established from its URL, or the endpoint "
        "depends on the environment.",
    ),
    "hidden_markup": RuleInfo(
        "Comments in instructions",
        "An instruction file contains HTML or Markdown comments, which rendered views hide "
        "and agents read.",
    ),
    "line_separators": RuleInfo(
        "Line or paragraph separators",
        "An instruction file contains U+2028 or U+2029, which can split a line in some renderers.",
    ),
    "identifier_characters": RuleInfo(
        "Control, format or mixed-script characters in an identifier",
        "A component's name, description, supplier or nested tool name was collected with "
        "terminal control, bidirectional or invisible format characters, which the inventory "
        "replaces, or an MCP server or tool name mixes letters of more than one script within "
        "a word or beside Latin text has a word whose every letter reads as Latin, which can "
        "disguise one name as another.",
    ),
    "hook_commands": RuleInfo(
        "Hook commands",
        "IDE agent settings declare hook commands that run automatically on agent events.",
    ),
    "invalid_safetensors": RuleInfo(
        "Unverified SafeTensors structure",
        "A model file named or recorded as SafeTensors has no established structural safety: "
        "its header is malformed, over the inspection limit, or was not inspected.",
    ),
    "launch_context": RuleInfo(
        "Widened MCP launch context",
        "An MCP server's launch grants host-level privileges, devices or mounts, loads local "
        "code, declares a command-valued field, or runs through a shell or wrapper.",
    ),
    "launcher_identity": RuleInfo(
        "Unknown MCP launcher identity",
        "The package that an MCP server launches, and its pin, cannot be established.",
    ),
    "lockfile_resolution_mismatch": RuleInfo(
        "Lockfile resolution mismatch",
        "An npm lockfile record's tarball URL names another package or version than the record.",
    ),
    "lockfile_unread": RuleInfo(
        "Unread lockfile",
        "A package may be resolved by a lockfile that the collector does not read.",
    ),
    "mcp_auto_approval": RuleInfo(
        "Project MCP servers approved without a prompt",
        "Claude Code settings approve every MCP server in the project's .mcp.json without a "
        "prompt.",
    ),
    "missing_lockfile_integrity": RuleInfo(
        "Lockfile record without integrity",
        "An npm lockfile record has no integrity value.",
    ),
    "nonregistry_source": RuleInfo(
        "Package from outside a registry",
        "An npm or PyPI package is declared from a git, URL or path source instead of a registry, "
        "or a patch applied at install may change an npm package.",
    ),
    "package_alias": RuleInfo(
        "Package alias",
        "An npm dependency installs a package under another name.",
    ),
    "package_source": RuleInfo(
        "Non-default MCP package source",
        "An MCP server resolves packages through a non-default registry or index, so name "
        "and version do not establish identity.",
    ),
    "plugin_sources": RuleInfo(
        "Plugin sources",
        "Claude Code settings enable plugins or register plugin marketplaces, which can add "
        "commands, agents, hooks and MCP servers.",
    ),
    "registry_origin": RuleInfo(
        "Non-default package registry",
        "An npm or PyPI package resolves, or the project configures it to resolve, from a "
        "registry or index other than the default one.",
    ),
    "transport_ambiguity": RuleInfo(
        "Ambiguous MCP transport",
        "An MCP server declares both a launch command and an endpoint or a remote transport type.",
    ),
    "tool_description_poisoning": RuleInfo(
        "Poisoned instructions in tool description or schema",
        "A tool description, JSON schema field, or agent card contains coercive "
        "tags, override directives, credential-relay instructions, or user-concealment guidance.",
    ),
    "runtime_undeclared": RuleInfo(
        "Runtime component not matched to the inventory",
        "The agent's runtime telemetry reports a tool, model, agent or MCP endpoint that no "
        "inventory entry matches, or whose identifier could not be read, so that it could not "
        "be compared with the inventory.",
    ),
}

GENERIC_HELP = (
    "The finding comes from the Nexus SymBiote inventory. Review the component named in "
    "the result and its recommendation, which the result's properties carry. Findings "
    "describe declarations in the repository; they do not establish exploitability."
)


def rule_tags(category: str, severity: RiskSeverity) -> list[str]:
    """``security``, then the crosswalk's taxonomy tags for this category and severity."""
    return ["security", *sarif_tags(category, severity)]
