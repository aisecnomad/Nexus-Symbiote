"""Repository association graph and potential blast radius, never effective authority."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel, AutonomyLevel, ComponentType, RiskSeverity
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.identifiers import neutralize_identifiers
from nexus_symbiote.core.models import (
    MAX_REFERENCE_CHARS,
    UNBOUND_VALUES_DETAIL,
    AgentComponent,
    AnyComponent,
    ClaimEvidence,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RegistryEntryComponent,
    RiskAssessment,
    SkillPackageComponent,
)
from nexus_symbiote.utils.secrets import redact_text

if TYPE_CHECKING:
    from nexus_symbiote.utils.confined import ConfinedCollection

NonemptyString = Annotated[str, Field(min_length=1)]

MANIFEST = "agent.yaml"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFEST_YAML_TOKENS = 20_000
# Without a declared id the agent is "this repository", wherever it is checked out:
# the same tree scanned at two locations must yield the same inventory.
INFERRED_AGENT_IDENTITY = "."
INFERRED_AGENT_NAME = "repository"
MANIFEST_VALUE_BINDING_PROFILE = "nexus-symbiote/agent-manifest-values/v1"
_DISPLAYED_FIELDS = ("name", "version", "framework", "owner", "purpose")
MAX_GRAPH_ISSUES = 100
_SHOWN = 200
_REPOSITORY_ASSOCIATION = "repository association; runtime use and authority unobserved"


def _repository_agent_ref(identity: str) -> str:
    """The repository agent's reference for a declared id, or for the inferred identity."""
    return "agent:repository:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


INFERRED_AGENT_REF = _repository_agent_ref(INFERRED_AGENT_IDENTITY)


class ModelDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: NonemptyString | None = None
    provider: NonemptyString | None = None
    requested_ref: NonemptyString | None = None

    @model_validator(mode="after")
    def one_model_source(self) -> ModelDeclaration:
        local = self.path is not None
        hosted = self.provider is not None and self.requested_ref is not None
        if local == hosted or (local and (self.provider or self.requested_ref)):
            raise ValueError("model requires a local path or both provider and requested_ref")
        return self


class AgentDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(default=None, min_length=1)
    name: str = Field(min_length=1)
    version: str | None = None
    purpose: str | None = None
    framework: str | None = None
    owner: str | None = None
    instructions: list[NonemptyString] = Field(default_factory=list, max_length=1024)
    models: dict[NonemptyString, ModelDeclaration] = Field(default_factory=dict, max_length=1024)
    autonomy_level: AutonomyLevel | None = None


def _clip(value: object) -> str:
    text = str(value)
    return text if len(text) <= _SHOWN else text[: _SHOWN - 1] + "…"


def _manifest_path(value: str) -> Path | None:
    """A manifest entry as a path beneath the root, or None when it may not name one."""
    if "\x00" in value or "\\" in value:
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return path


def _root_relative(source_path: str | None, relative: Callable[[str], str]) -> str | None:
    """A recorded location as root-relative POSIX text, or None when it names none.

    ``relative`` is the rule collection records paths by (``project_relative``), so a
    record an earlier release wrote with an absolute path under the root reads the same.
    """
    if not source_path or "://" in source_path:
        return None
    path = Path(relative(source_path))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return path.as_posix()


def _parse_manifest(text: str, problems: list[str]) -> AgentDeclaration | None:
    from nexus_symbiote.policy import parse_yaml_mapping

    try:
        import yaml
    except ImportError:
        problems.append(f"{MANIFEST}: YAML parser unavailable")
        return None
    try:
        # The manifest comes from the checkout: refuse YAML graphs and unbounded documents.
        for index, token in enumerate(yaml.scan(text)):
            if index >= MAX_MANIFEST_YAML_TOKENS or isinstance(
                token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)
            ):
                raise ValueError("unsupported YAML graph")
        data = parse_yaml_mapping(text)
        # A YAML escape can produce a lone surrogate, which no path or digest can encode.
        json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        return AgentDeclaration.model_validate(data)
    except (ValueError, RecursionError, yaml.YAMLError):
        problems.append(f"{MANIFEST}: does not conform to the agent manifest schema")
        return None


def _collected_digest(component: AnyComponent) -> str | None:
    if isinstance(component, PromptComponent):
        return component.content_hash
    return component.hashes.get("sha256")


_CHANGED = "instruction changed since scanner collection"


def _collection_mismatch(component: AnyComponent, path: str, raw: bytes) -> str | None:
    """Why ``raw``, read now from ``path``, does not match what the collector recorded,
    or None.

    A prompt file whose unkeyed hash the collector withholds is checked against its keyed
    binding instead. Without the operator key, or without a binding, nothing recorded its
    content, so it is unbound rather than changed, as integrity validation counts it.
    """
    from nexus_symbiote.scanners.prompt import (
        IMPORT_CONTENT_BINDING_PROFILE,
        withholds_content_hash,
    )
    from nexus_symbiote.scanners.source_binding import BindingError, value_binding

    if not (isinstance(component, PromptComponent) and withholds_content_hash(component)):
        return _CHANGED if _collected_digest(component) != hash_bytes(raw) else None
    recorded = component.properties.get("static_value_binding")
    if recorded is None:
        return None
    profile = component.properties.get("static_value_binding_profile")
    if profile != IMPORT_CONTENT_BINDING_PROFILE:
        return "instruction content binding has an unknown profile"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _CHANGED
    try:
        binding = value_binding(IMPORT_CONTENT_BINDING_PROFILE, {"path": path, "content": text})
    except BindingError as exc:
        return str(exc)
    if not binding:
        return None
    if binding["static_value_binding_key_id"] != component.properties.get(
        "static_value_binding_key_id"
    ):
        return "instruction content was bound under another key"
    return _CHANGED if binding["static_value_binding"] != recorded else None


def _readable_entry(
    files: ConfinedCollection, path: Path, locator: str, problems: list[str]
) -> bool:
    """Apply the operator's exclusions to a manifest-selected path before anything reads it."""
    from nexus_symbiote.utils.confined import DEFAULT_EXCLUDES, fold_name

    # Collection skips these in any spelling a case-insensitive file system treats as
    # the same name, without recording a gap, so each spelling must be refused here.
    if any(part in DEFAULT_EXCLUDES or fold_name(part) in DEFAULT_EXCLUDES for part in path.parts):
        problems.append(f"{locator}: names a path inside a directory that collection never reads")
        return False
    # A policy exclusion is recorded as a coverage gap by the collection itself.
    return not files.excluded(path)


def _manifest_dependencies(
    bom: AIBOM,
    declared: AgentDeclaration,
    files: ConfinedCollection,
    agent_ref: str,
    problems: list[str],
) -> list[AnyComponent]:
    """Bind declared instructions and local models to collected records before changing the BOM."""
    from nexus_symbiote import limits
    from nexus_symbiote.scanners.base import project_relative
    from nexus_symbiote.scanners.prompt import detect_invisible_characters

    in_root = project_relative(files.root)
    collected_text: dict[str, list[AnyComponent]] = {}
    collected_models: dict[str, list[ModelComponent]] = {}
    for comp in bom.components:
        relative = _root_relative(comp.source_path, in_root)
        if relative is None:
            continue
        if isinstance(comp, (PromptComponent, SkillPackageComponent)):
            collected_text.setdefault(relative, []).append(comp)
        elif isinstance(comp, ModelComponent):
            collected_models.setdefault(relative, []).append(comp)
            collected_models.setdefault(Path(relative).parent.as_posix(), []).append(comp)

    additions: list[AnyComponent] = []
    for index, instruction in enumerate(declared.instructions):
        locator = f"{MANIFEST}#/instructions/{index}"
        path = _manifest_path(instruction)
        if path is None:
            problems.append(f"{locator}: must be a relative path beneath the repository")
            continue
        if not _readable_entry(files, path, locator, problems):
            continue
        raw = files.read_bytes(path)
        if raw is None:
            problems.append(f"{locator}: the declared instruction could not be collected safely")
            continue
        digest = hash_bytes(raw)
        records = collected_text.get(path.as_posix(), [])
        if records:
            # The collector already inventoried this file, with its own checks.
            mismatches = {
                reason
                for record in records
                if (reason := _collection_mismatch(record, path.as_posix(), raw)) is not None
            }
            problems.extend(f"{locator}: {reason}" for reason in sorted(mismatches))
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{locator}: declared instruction is not UTF-8 text")
            continue
        ref = "prompt:manifest:" + hashlib.sha256(path.as_posix().encode()).hexdigest()[:24]
        additions.append(
            PromptComponent(
                bom_ref=ref,
                name=path.name,
                source_path=path.as_posix(),
                content_hash=digest,
                assurance_level=AssuranceLevel.OBSERVED,
                risks=detect_invisible_characters(text, path.as_posix()),
                claims={
                    "content_hash": ClaimEvidence(
                        assurance=AssuranceLevel.OBSERVED,
                        method="confined-file-sha256",
                        scope="repository",
                        locator=path.as_posix(),
                        observed_at=bom.metadata.timestamp,
                    )
                },
            )
        )
    for key, model in declared.models.items():
        locator = f"{MANIFEST}#/models/{_clip(quote(key, safe=''))}"
        if model.path is None:
            ref = f"model:{agent_ref}/hosted/{quote(key, safe='')}"
            if len(ref) > MAX_REFERENCE_CHARS:
                problems.append(f"{locator}: the key is too long for a component reference")
                continue
            additions.append(
                ModelComponent(
                    bom_ref=ref,
                    name=model.requested_ref or key,
                    provider=model.provider,
                    requested_alias=model.requested_ref,
                    model_type="hosted",
                    source_path=MANIFEST,
                    claims={
                        "requested_alias": ClaimEvidence(
                            assurance=AssuranceLevel.DECLARED,
                            method="agent-manifest",
                            scope="repository",
                            locator=f"{MANIFEST}#/models/{quote(key, safe='')}",
                        )
                    },
                )
            )
            continue
        local = _manifest_path(model.path)
        if local is None:
            problems.append(f"{locator}: must be a relative path beneath the repository")
            continue
        if not _readable_entry(files, local, locator, problems):
            continue
        matches = collected_models.get(local.as_posix(), [])
        if not matches:
            problems.append(f"{locator}: the declared local model has no collected model artifact")
            continue
        for comp in matches:
            relative = _root_relative(comp.source_path, in_root)
            assert relative is not None
            try:
                with files.open_regular(relative, max_bytes=limits.bound("model-bytes")):
                    pass
            except OSError:
                problems.append(f"{locator}: the declared local model is unavailable")
    return additions


def _launcher_key(registry: RegistryEntryComponent) -> str | None:
    """The MCP launcher-package spelling of a manifest dependency, when one exists."""
    if registry.registry_type in {"pypi", "npm"}:
        return f"{registry.registry_type}:{registry.name}"
    if registry.registry_type in {"docker-hub", "oci"}:
        image = re.sub(r"@sha256:[0-9A-Fa-f]{64}$", "", registry.name)
        head, _, last = image.rpartition("/")
        last = last.split(":", 1)[0]
        return "oci:" + (f"{head}/{last}" if head else last).lower()
    return None


def assemble_repository_agent(
    bom: AIBOM,
    root: Path,
    *,
    exclude_paths: Iterable[str | Path] = (),
    failures: list[str] | None = None,
    exclusions: list[str] | None = None,
    surfaces: list[str] | None = None,
) -> AgentComponent:
    """Associate repository-discovered dependencies with a definition, not a running agent.

    The optional ``agent.yaml`` manifest is read beneath ``root`` under the caller's
    ``exclude_paths``. Given a ``failures`` list, manifest problems are recorded there,
    and policy exclusions in ``exclusions``, and the inventory is still assembled from
    what could be collected. Without one, any problem raises ``PolicyError`` before the
    BOM is changed. Given ``surfaces``, the manifest and each instruction file only it
    declares are recorded there once read.
    """
    from nexus_symbiote.policy import PolicyError
    from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
    from nexus_symbiote.scanners.source_binding import BindingError, value_binding
    from nexus_symbiote.utils.confined import ConfinedCollection

    strict = failures is None
    problems: list[str] = []
    recorded: list[str] = [] if failures is None else failures
    # Without a place for coverage gaps, a policy exclusion is recorded as a failure.
    gaps: list[str] = recorded if strict or exclusions is None else exclusions
    before = (len(recorded), len(gaps))
    with ConfinedCollection(
        root, recorded, gaps, exclude_paths=exclude_paths, max_file_bytes=MAX_MANIFEST_BYTES
    ) as files:
        text = files.read_text(MANIFEST, missing_ok=True)
    declared = None if text is None else _parse_manifest(text, problems)
    # Without a declared id the agent is "this repository", wherever it is checked out.
    identity = declared.id if declared and declared.id else INFERRED_AGENT_IDENTITY
    agent_ref = _repository_agent_ref(identity)
    additions: list[AnyComponent] = []
    if declared is not None:
        # Entries are checkout text, not paths found on disk: a read problem is recorded
        # under the entry's locator and never echoes the entry itself.
        unread: list[str] = []
        with ConfinedCollection(root, unread, gaps, exclude_paths=exclude_paths) as files:
            additions = _manifest_dependencies(bom, declared, files, agent_ref, problems)

    # The export shows these fields redacted. A field that redaction changed, such as
    # an owner URL cut to its origin, would otherwise compare equal after any change to
    # it, so its value is bound with the operator key or named as unbound.
    displayed: dict[str, str] = {}
    withheld: dict[str, str] = {}
    binding: dict[str, str] = {}
    if declared:
        for field in _DISPLAYED_FIELDS:
            value = getattr(declared, field)
            if field == "name" and value.endswith("\n") and value.strip():
                # ``name: >`` or ``name: |`` ends the name with the line break YAML's clip
                # chomping keeps; it is not part of the name.
                value = value[:-1]
            if value is not None:
                # Names keep the token formats ordinary names take, such as
                # ``sk-research-assistant``; the free-text purpose does not.
                displayed[field] = redact_text(value, identifier=field != "purpose")
                if displayed[field] != value:
                    withheld[field] = value
        if withheld:
            try:
                binding = value_binding(MANIFEST_VALUE_BINDING_PROFILE, withheld)
            except BindingError as exc:
                problems.append(f"{MANIFEST}: {exc}")

    index: dict[str, AnyComponent] = {c.bom_ref: c for c in bom.components}
    accepted: list[AnyComponent] = []
    for addition in additions:
        # Manifest entries are checkout text like any collector's, and are recorded the
        # way ``merge_collected`` records a collected component.
        neutralize_identifiers(addition)
        existing = index.get(addition.bom_ref)
        if existing is not None and existing != addition:
            problems.append(f"{MANIFEST}: declares a component reference that is already in use")
        elif existing is None:
            index[addition.bom_ref] = addition
            accepted.append(addition)
    if strict and (problems or (len(recorded), len(gaps)) != before):
        raise PolicyError("; ".join([*problems, *recorded]))
    if failures is not None:
        failures.extend(problems)
    if surfaces is not None and text is not None:
        surfaces.append(MANIFEST)
        surfaces.extend(
            c.source_path for c in accepted if isinstance(c, PromptComponent) and c.source_path
        )
    if agent_ref in index:
        raise ValueError(f"{MANIFEST}: the repository agent reference is already in use")

    discovery = ClaimEvidence(
        assurance=AssuranceLevel.OBSERVED,
        method="filesystem-inventory",
        scope="repository",
        collector="repository-assembler",
        locator=MANIFEST if declared else ".",
        observed_at=bom.metadata.timestamp,
    )
    agent = AgentComponent(
        bom_ref=agent_ref,
        name=displayed.get("name", INFERRED_AGENT_NAME),
        version=displayed.get("version"),
        framework=displayed.get("framework"),
        supplier=displayed.get("owner"),
        description=displayed.get("purpose")
        if declared
        else "Repository agent definition inferred from configuration",
        autonomy_level=None,
        deployment_status="unknown",
        assurance_level=AssuranceLevel.OBSERVED,
        claims={
            "repository_presence": discovery,
            "deployment": ClaimEvidence(
                method="not-collected",
                scope="runtime",
                unknown_reason="Repository scan cannot identify a running workload",
            ),
        },
        properties={
            "identity_source": MANIFEST if declared else "repository-path",
            "runtime_use": "unknown",
        },
    )
    if binding:
        agent.properties.update(binding)
    elif withheld:
        agent.risks.append(
            RiskAssessment(
                severity=RiskSeverity.LOW,
                category="completeness",
                detail=(
                    f"Agent manifest {UNBOUND_VALUES_DETAIL}: "
                    f"{', '.join(sorted(withheld))}, exported redacted."
                ),
                recommendation=(
                    f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to "
                    "these values."
                ),
            )
        )
    neutralize_identifiers(agent)
    if declared:
        if declared.autonomy_level is not None:
            agent.properties["declared_autonomy_level"] = declared.autonomy_level.value
        for key in (
            "name",
            "version",
            "framework",
            "owner",
            "purpose",
            "autonomy_level",
            "instructions",
            "models",
        ):
            if key in declared.model_fields_set and getattr(declared, key) is not None:
                agent.claims[key] = ClaimEvidence(
                    assurance=AssuranceLevel.DECLARED,
                    method="agent-manifest",
                    scope="repository",
                    collector="repository-assembler",
                    locator=f"{MANIFEST}#/{key}",
                )
    bom.components.extend(accepted)
    relations = {
        ComponentType.MCP_SERVER: ("tool_refs", "configured-with"),
        ComponentType.TOOL: ("tool_refs", "configured-with"),
        ComponentType.MODEL: ("model_refs", "uses-model"),
        ComponentType.PROMPT_TEMPLATE: ("prompt_refs", "reads-instructions"),
        ComponentType.SKILL_PACKAGE: ("skill_refs", "loads-skill"),
        ComponentType.MEMORY_STORE: ("memory_refs", "uses-memory"),
        ComponentType.GUARDRAIL_POLICY: ("guardrail_refs", "uses-guardrail"),
        ComponentType.RAG_SOURCE: ("data_refs", "retrieves-from"),
        ComponentType.DATA_SOURCE: ("data_refs", "retrieves-from"),
    }
    # Components with no reference field on the agent are still linked, so a compromise
    # of a package or image reaches the agent in blast-radius and a removal shows as an
    # edge change.
    associated = {
        ComponentType.MCP_CLIENT: ("configured-with", _REPOSITORY_ASSOCIATION),
        ComponentType.A2A_CLIENT: ("configured-with", _REPOSITORY_ASSOCIATION),
        ComponentType.A2A_SERVER: ("configured-with", _REPOSITORY_ASSOCIATION),
        ComponentType.IDE_AGENT: ("configured-with", _REPOSITORY_ASSOCIATION),
        ComponentType.VERIFIED_EXTENSION: ("configured-with", _REPOSITORY_ASSOCIATION),
        ComponentType.REGISTRY_ENTRY: (
            "depends-on",
            "repository manifest dependency; installed artifact, runtime use and authority "
            "unobserved",
        ),
    }
    registries: dict[str, list[str]] = {}
    for component in bom.components:
        if (
            isinstance(component, RegistryEntryComponent)
            and component.properties.get("collection_mode") != "imported-unverified-report"
        ):
            launcher = _launcher_key(component)
            if launcher is not None:
                registries.setdefault(launcher, []).append(component.bom_ref)
    for component in list(bom.components):
        # A report stored in this repository does not associate discovered assets
        # with this repository agent. Imported relationships remain unobserved.
        if component.properties.get("collection_mode") == "imported-unverified-report":
            continue
        if component.component_type in associated:
            relationship, conditions = associated[component.component_type]
            bom.add_dependency(
                DependencyEdge(
                    source_ref=agent_ref,
                    target_ref=component.bom_ref,
                    relationship=relationship,
                    assurance_level="declared",
                    conditions=conditions,
                )
            )
        if isinstance(component, MCPServerComponent) and component.launcher_package:
            for target in registries.get(component.launcher_package, []):
                bom.add_dependency(
                    DependencyEdge(
                        source_ref=component.bom_ref,
                        target_ref=target,
                        relationship="registered-as",
                        assurance_level="declared",
                        conditions="launcher package name matches a manifest dependency; "
                        "versions and artifacts are not compared; runtime use and authority "
                        "unobserved",
                    )
                )
        if component.component_type not in relations:
            continue
        field_name, relationship = relations[component.component_type]
        getattr(agent, field_name).append(component.bom_ref)
        bom.add_dependency(
            DependencyEdge(
                source_ref=agent_ref,
                target_ref=component.bom_ref,
                relationship=relationship,
                assurance_level="declared",
                conditions=_REPOSITORY_ASSOCIATION,
            )
        )
        server_ref = getattr(component, "mcp_server_ref", None)
        if server_ref and server_ref in index:
            bom.add_dependency(
                DependencyEdge(
                    source_ref=server_ref,
                    target_ref=component.bom_ref,
                    relationship="provides-tool",
                    assurance_level="declared",
                )
            )
    bom.components.append(agent)
    return agent


_REF_TYPES: dict[str, set[ComponentType]] = {
    "server_refs": {ComponentType.MCP_SERVER},
    "mcp_server_refs": {ComponentType.MCP_SERVER},
    "model_refs": {ComponentType.MODEL},
    "tool_refs": {ComponentType.TOOL, ComponentType.MCP_SERVER},
    "memory_refs": {ComponentType.MEMORY_STORE},
    "prompt_refs": {ComponentType.PROMPT_TEMPLATE},
    "guardrail_refs": {ComponentType.GUARDRAIL_POLICY},
    "sub_agent_refs": {ComponentType.AGENT},
    "data_refs": {ComponentType.DATA_SOURCE, ComponentType.RAG_SOURCE},
    "skill_refs": {ComponentType.SKILL_PACKAGE},
    "mcp_server_ref": {ComponentType.MCP_SERVER},
    "model_ref": {ComponentType.MODEL},
    "embedding_model_ref": {ComponentType.MODEL},
    "base_model_ref": {ComponentType.MODEL},
    "registry_ref": {ComponentType.REGISTRY_ENTRY},
}


def _references(component: AnyComponent) -> Iterable[tuple[str, str]]:
    for field_name in _REF_TYPES:
        value = getattr(component, field_name, None)
        for ref in value if isinstance(value, list) else [value] if value else []:
            yield field_name, ref


def validate_graph(bom: AIBOM) -> list[str]:
    """Structural problems, at most MAX_GRAPH_ISSUES distinct ones, with identifiers shortened.

    A hostile inventory can hold a very long reference and a million dangling targets,
    so the message count and size are bounded, not the work. A repeated message takes
    one place, so repeats cannot crowd out the distinct problems.
    """
    nodes = {c.bom_ref: c for c in bom.components}
    issues: set[str] = set()
    omitted = 0

    def issue(message: str) -> None:
        nonlocal omitted
        if message in issues:
            return
        if len(issues) < MAX_GRAPH_ISSUES:
            issues.add(message)
        else:
            omitted += 1

    if len(nodes) != len(bom.components):
        issue("duplicate component references")
    for component in bom.components:
        for field_name, ref in _references(component):
            target = nodes.get(ref)
            if target is None:
                issue(f"{_clip(component.bom_ref)}.{field_name}: missing target {_clip(ref)}")
            elif target.component_type not in _REF_TYPES[field_name]:
                issue(f"{_clip(component.bom_ref)}.{field_name}: wrong target type {_clip(ref)}")
    for edge in bom.dependencies:
        if edge.source_ref not in nodes or edge.target_ref not in nodes:
            issue(
                f"{edge.relationship}: dangling edge {_clip(edge.source_ref)} -> "
                f"{_clip(edge.target_ref)}"
            )
        elif edge.relationship == "provides-tool" and (
            nodes[edge.source_ref].component_type is not ComponentType.MCP_SERVER
            or nodes[edge.target_ref].component_type is not ComponentType.TOOL
        ):
            issue("provides-tool must link an MCP server to a tool")
    shown = sorted(issues)
    if omitted:
        shown.append(f"{omitted} further graph issues not shown")
    return shown


def _reach(graph: dict[str, set[str]], starts: Iterable[str]) -> set[str]:
    """Everything reachable from any start, each node visited once."""
    seen: set[str] = set()
    pending = list(starts)
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(graph.get(current, ()))
    return seen


MAX_SHARED_CREDENTIAL_VARS = 32
MAX_SHARED_CREDENTIAL_HOLDERS = 20
_VALID_ENV_VAR_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,127}")


def _is_credential_env_var_name(name: str) -> bool:
    from nexus_symbiote.utils.secrets import _CREDENTIAL_KEY

    if not _VALID_ENV_VAR_NAME.fullmatch(name) or "redacted" in name.lower():
        return False
    return _CREDENTIAL_KEY.search(name) is not None


def blast_radius(bom: AIBOM, component_ref: str) -> dict[str, Any]:
    """Potential reach of a compromised component through recorded relationships.

    Linear in the size of the inventory: one reverse traversal finds what depends on
    the subject, one forward traversal from the subject and every affected agent finds
    what those agents can reach.
    """
    issues = validate_graph(bom)
    if issues:
        raise ValueError("invalid graph: " + "; ".join(issues))
    nodes = {c.bom_ref: c for c in bom.components}
    if component_ref not in nodes:
        raise ValueError(f"unknown component: {_clip(component_ref)}")
    forward: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    env_index: dict[str, set[str]] = {}
    for component in bom.components:
        for _, ref in _references(component):
            forward.setdefault(component.bom_ref, set()).add(ref)
            reverse.setdefault(ref, set()).add(component.bom_ref)
        upstreams = component.properties.get("upstream_server_refs")
        if isinstance(upstreams, list):
            for srv_ref in upstreams:
                if isinstance(srv_ref, str) and srv_ref in nodes:
                    forward.setdefault(component.bom_ref, set()).add(srv_ref)
                    reverse.setdefault(srv_ref, set()).add(component.bom_ref)
        env_map = getattr(component, "env", None)
        env_vars = list(env_map.keys()) if isinstance(env_map, dict) else []
        prop_vars = component.properties.get("env_vars_referenced")
        if isinstance(prop_vars, list):
            env_vars.extend(v for v in prop_vars if isinstance(v, str))
        for var in env_vars:
            if isinstance(var, str) and _is_credential_env_var_name(var):
                env_index.setdefault(var, set()).add(component.bom_ref)
    for edge in bom.dependencies:
        forward.setdefault(edge.source_ref, set()).add(edge.target_ref)
        reverse.setdefault(edge.target_ref, set()).add(edge.source_ref)

    upstream = _reach(reverse, [component_ref])
    affected = sorted(ref for ref in upstream if nodes[ref].component_type is ComponentType.AGENT)
    reach = _reach(forward, [component_ref, *affected])
    principals = sorted(
        {auth.principal for ref in reach for auth in getattr(nodes[ref], "authorizations", [])}
    )
    credential_names = sorted(
        var
        for var, holders in env_index.items()
        if len(holders) > 1 and not holders.isdisjoint(reach)
    )
    shared_credentials: dict[str, list[str]] = {}
    omitted_holders: dict[str, int] = {}
    for var in credential_names[:MAX_SHARED_CREDENTIAL_VARS]:
        holders = env_index[var]
        if len(holders) > MAX_SHARED_CREDENTIAL_HOLDERS:
            # Keep the subject and other reachable holders that explain the association.
            ranked = sorted(holders, key=lambda ref: (ref != component_ref, ref not in reach, ref))
            shared_credentials[var] = ranked[:MAX_SHARED_CREDENTIAL_HOLDERS]
            omitted_holders[var] = len(holders) - MAX_SHARED_CREDENTIAL_HOLDERS
        else:
            shared_credentials[var] = sorted(holders)
    gateways = sorted(
        ref
        for ref in reach
        if nodes[ref].properties.get("mcp_role") == "gateway"
        or isinstance(nodes[ref].properties.get("upstream_server_refs"), list)
    )
    limitations = [
        "Reachability describes potential dependencies, not proven exploitability or runtime access."
    ]
    if not forward.get(component_ref) and not reverse.get(component_ref):
        limitations.append(
            "The component has no recorded relationships: reachability is unknown, not empty."
        )
    if omitted_holders or len(credential_names) > MAX_SHARED_CREDENTIAL_VARS:
        limitations.append(
            f"shared_credential_surfaces is bounded to at most {MAX_SHARED_CREDENTIAL_VARS} "
            f"credential variables and {MAX_SHARED_CREDENTIAL_HOLDERS} holders each."
        )
    return {
        "subject": component_ref,
        "affected_agents": affected,
        "dependent_components": sorted(upstream - {component_ref}),
        "reachable_components": sorted(reach),
        "declared_principals": principals,
        "shared_credential_surfaces": shared_credentials,
        "shared_credential_holders_omitted": omitted_holders,
        "mcp_gateways": gateways,
        "scope": "repository-association",
        "effective_authority": "unknown",
        "linked": bool(forward.get(component_ref) or reverse.get(component_ref)),
        "limitations": limitations,
    }
