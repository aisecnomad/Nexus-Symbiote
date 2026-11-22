"""Lethal-trifecta, toxic-flow chain, and tool-shadowing analysis.

Evaluates an AgentBOM offline for three structural agentic risks:

1. **Lethal trifecta (Item 15):** an agent scope combining untrusted input, private
   data access, and external egress or state mutation without an explicit approval gate
   is rated ``critical``. Complete declared approval coverage lowers it to ``high``.
2. **Chained toxic flows (Item 24):** a leak or state-mutation chain possible only by
   combining two distinct components (source + sink) produces one ``toxic_flow`` finding
   naming both components rather than treating each in isolation as clean.
3. **Tool shadowing (Item 24):** two distinct tool definitions that collide on a
   normalized, confusable-folded tool name across servers or sources produce one
   ``tool_shadowing`` finding, escalated to ``high`` when a lower-trust source shadows
   a higher-trust one.

All rules operate strictly on recorded inventory evidence without executing code or
contacting the network. Untrusted ad-hoc inventory properties (such as
``properties.requires_approval`` or ``properties.effective_authorization_verified``) and
static IDE starting modes cannot clear a gate. Every finding lists at most
``EVIDENCE_LIMIT`` components per leg, so a report grows linearly with its inventory.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from heapq import merge as merge_sorted
from itertools import groupby, islice
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    CapabilityClass,
    HumanInTheLoop,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AnyComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    DataSourceComponent,
    IDEAgentComponent,
    MCPClientComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    RAGSourceComponent,
    ToolComponent,
)
from nexus_symbiote.risk_classes import RiskClass, RiskClassification, classify

# Case-preserving confusable skeleton table covering Cyrillic, Greek, and common
# Latin homoglyphs so evasion via look-alike letters normalizes identically.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic uppercase
        "\u0410": "A",
        "\u0412": "B",
        "\u0421": "C",
        "\u0415": "E",
        "\u0401": "E",
        "\u041d": "H",
        "\u0406": "I",
        "\u0407": "I",
        "\u0408": "J",
        "\u041a": "K",
        "\u041c": "M",
        "\u041e": "O",
        "\u0420": "P",
        "\u0405": "S",
        "\u0422": "T",
        "\u0425": "X",
        "\u04ae": "Y",
        # Cyrillic lowercase
        "\u0430": "a",
        "\u0432": "b",
        "\u0441": "c",
        "\u0501": "d",
        "\u0435": "e",
        "\u0451": "e",
        "\u04bb": "h",
        "\u043d": "h",
        "\u0456": "i",
        "\u0457": "i",
        "\u0458": "j",
        "\u043a": "k",
        "\u04cf": "l",
        "\u043c": "m",
        "\u043e": "o",
        "\u0440": "p",
        "\u0455": "s",
        "\u0442": "t",
        "\u0443": "y",
        "\u0475": "v",
        "\u0445": "x",
        # Greek uppercase
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0396": "Z",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a5": "Y",
        "\u03a7": "X",
        # Greek lowercase
        "\u03b1": "a",
        "\u03b2": "b",
        "\u03b5": "e",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03bc": "m",
        "\u03bd": "v",
        "\u03bf": "o",
        "\u03c1": "p",
        "\u03c4": "t",
        "\u03c5": "u",
        "\u03c7": "x",
        # Latin/Armenian look-alikes
        "\u0261": "g",
        "\u0578": "n",
        "\u0131": "i",
        "\u03f2": "c",
        "\u1d04": "c",
        "\u1d0f": "o",
        "\u0192": "f",
        "\u0251": "a",
        "\u0585": "o",
    }
)
# Zero-width boundaries: a capturing run such as ([A-Z]+) rescans a long run of capitals
# from every start position, which is quadratic on a hostile tool name.
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])|(?<=[a-z0-9])(?=[A-Z])")
_SEPARATOR_RE = re.compile(r"[\s\-_.]+")
_IDENT_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_WITHHELD_ENV_NAME_RE = re.compile(r"\[redacted-[1-9][0-9]{0,5}\]")

# Environment variable names that plausibly carry credentials, tokens, or private DSNs.
# Benign runtime knobs (TZ, LANG, NODE_ENV, PORT, DEBUG, LOG_LEVEL) do not match. The
# first alternatives match inside a word (PGPASSWORD), and a URL or URI counts only
# beside a datastore name, since such a locator usually embeds its credentials. That
# test starts only where a letter-and-digit run starts and checks the run's end once,
# so a long run of datastore names (DBDBDB...) is scanned in linear time.
_SECRET_ENV_KEY_RE = re.compile(
    r"secret|passw(?:or)?d|credential|apikey|"
    r"(?:\A|_)(?:"
    r"key|keys|token|tokens|pass|pwd|cred|creds|auth|bearer|cookie|cookies|session|"
    r"private|jwt|oauth|pat|pem|dsn|conn_str|connection_string|kubeconfig|vault"
    r")(?:_|\n?\Z)|"
    r"(?<![a-z0-9])(?=[a-z0-9]*+_ur[il])[a-z0-9]*?"
    r"(?:postgres|pg|mysql|maria|mongo|redis|database|db|amqp|rabbitmq|supabase|neon|"
    r"clickhouse|elastic|sqlalchemy)|"
    r"\A(?:aws_access|aws_session|openai_|anthropic_|stripe_|gcp_)",
    re.IGNORECASE,
)

# Tool name patterns (applied to canonical_tool_name(), which splits camelCase and
# folds Unicode confusables). Outbound sinks (send_webhook, post_slack) are excluded
# from external-reader patterns so they do not satisfy untrusted_input on their own.
# A tool that requests a URL of the caller's choosing reads untrusted content and is also
# a way out: the model can put private data in the URL it asks for.
_URL_FETCH_NAMES = (
    r"fetch|fetch_url|web_fetch|get_url|load_url|read_url|open_url|fetch_page|get_page|"
    r"scrape|scrape_url|crawl|browse|browser|web_browse|http_get|curl|download|"
    r"download_url|read_web"
)
_URL_FETCH_TOOL_RE = re.compile(rf"(?:^|_)(?:{_URL_FETCH_NAMES})(?:$|_)")
_UNTRUSTED_TOOL_RE = re.compile(
    r"(?:^|_)(?:" + _URL_FETCH_NAMES + r"|web_search|search_web|external_read|"
    r"read_email|fetch_email|get_email|list_emails|read_issue|read_pr|"
    r"read_comment|read_message|read_slack|read_webhook|receive_webhook"
    r")(?:$|_)"
)
_UNTRUSTED_DESC_RE = re.compile(
    r"(?:^|_)(?:fetch_external|web_page|web_pages|scrape|crawl|browse_web|"
    r"read_email|search_web|download_url|http_get|external_web)(?:$|_)"
)
_PRIVATE_TOOL_RE = re.compile(
    r"(?:^|_)(?:"
    r"read_file|file_read|read_files|cat_file|open_file|view_file|load_file|get_file|"
    r"list_files|read_dir|search_files|grep_files|"
    r"read_secret|read_secrets|get_secret|get_secrets|list_secret|list_secrets|"
    r"fetch_secret|secret|secrets|vault|keychain|credential|credentials|"
    r"env_read|read_env|get_env|dump_env|"
    r"db_query|query_db|sql_query|run_sql|execute_sql|read_db|"
    r"customer_data|private_data|internal_doc|internal_docs|"
    r"read_email|list_emails|get_email|read_drive|read_s3|get_object|"
    r"read_config|read_ssh|read_key|private_key"
    r")(?:$|_)"
)
_EGRESS_TOOL_RE = re.compile(
    r"(?:^|_)(?:"
    r"send_webhook|post_webhook|webhook_send|send_email|send_mail|email_send|"
    r"send_message|post_message|post_slack|slack_post|send_report|send_data|"
    r"http_post|http_put|http_patch|http_delete|http_request|post_data|upload|publish|"
    r"notify|write_file|delete_file|exec|execute|shell|bash|run_command|eval|run_code|"
    r"git_push|create_pr|create_issue"
    r")(?:$|_)"
)

# Token sets for static MCP server launcher packages and declared server names.
_MCP_UNTRUSTED_TOKENS = frozenset(
    [
        "fetch",
        "web",
        "browser",
        "playwright",
        "puppeteer",
        "brave",
        "tavily",
        "exa",
        "firecrawl",
        "crawl",
        "scrape",
        "http",
        "curl",
        "rss",
        "slack",
        "discord",
        "email",
        "gmail",
        "outlook",
        "imap",
        "github",
        "gitlab",
        "jira",
        "linear",
        "notion",
        "confluence",
        "zendesk",
        "intercom",
        "reddit",
        "twitter",
        "youtube",
        "wikipedia",
        "docs",
        "search",
        "news",
        "feed",
    ]
)
_MCP_PRIVATE_TOKENS = frozenset(
    [
        "filesystem",
        "fs",
        "files",
        "postgres",
        "postgresql",
        "sqlite",
        "mysql",
        "mariadb",
        "mssql",
        "mongodb",
        "mongo",
        "redis",
        "dynamodb",
        "bigquery",
        "snowflake",
        "duckdb",
        "database",
        "db",
        "sql",
        "vault",
        "secrets",
        "secret",
        "keychain",
        "onepassword",
        "1password",
        "bitwarden",
        "aws",
        "gcp",
        "azure",
        "s3",
        "gcs",
        "gdrive",
        "drive",
        "dropbox",
        "onedrive",
        "email",
        "gmail",
        "outlook",
        "imap",
        "crm",
        "salesforce",
        "hubspot",
        "zendesk",
        "stripe",
        "plaid",
        "git",
    ]
)
# Public documentation about a platform is not that platform's account data.
_MCP_DOC_TOKENS = frozenset({"doc", "docs", "documentation"})
_MCP_PLATFORM_TOKENS = frozenset(
    {"aws", "gcp", "azure", "git", "stripe", "plaid", "salesforce", "hubspot", "zendesk"}
)
_MCP_EGRESS_TOKENS = frozenset(
    [
        "fetch",
        "curl",
        "crawl",
        "scrape",
        "firecrawl",
        "slack",
        "discord",
        "email",
        "gmail",
        "outlook",
        "smtp",
        "webhook",
        "github",
        "gitlab",
        "jira",
        "linear",
        "shell",
        "bash",
        "terminal",
        "exec",
        "playwright",
        "puppeteer",
        "browser",
        "twilio",
        "sendgrid",
        "pagerduty",
        "stripe",
    ]
)

_MUTATING_CAPABILITIES = frozenset(
    {
        CapabilityClass.WRITE,
        CapabilityClass.EXECUTE,
        CapabilityClass.DESTRUCTIVE,
        CapabilityClass.PAYMENT,
    }
)
_PRIVATE_CAPABILITIES = frozenset({CapabilityClass.CREDENTIALS, CapabilityClass.FILESYSTEM})
_MUTATING_SIDE_EFFECTS = frozenset(
    {
        SideEffectProfile.STATE_MODIFYING,
        SideEffectProfile.DESTRUCTIVE,
        SideEffectProfile.FINANCIAL_TRANSACTION,
    }
)

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.CRITICAL: 0,
    RiskSeverity.HIGH: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.LOW: 3,
    RiskSeverity.INFO: 4,
}
_TRUST_RANK: dict[TrustTier, int] = {
    TrustTier.INTERNAL_VERIFIED: 5,
    TrustTier.INTERNAL_UNVERIFIED: 4,
    TrustTier.THIRD_PARTY_SIGNED: 3,
    TrustTier.THIRD_PARTY_UNSIGNED: 2,
    TrustTier.UNTRUSTED_PUBLIC: 1,
    TrustTier.UNKNOWN: 0,
}
_LEGS = frozenset({"untrusted", "private", "egress"})
_IDE_GRANT = "permission_scope"
_IDE_GRANT_RE = re.compile(r"unscoped tool allowances \(([^)]*)\)")
_IDE_GRANT_LEGS: dict[str, frozenset[str]] = {
    "web fetches": frozenset({"untrusted", "egress"}),
    # A shell reads any file the agent can and sends it with curl.
    "shell commands": _LEGS,
    "file edits": frozenset({"egress"}),
    "file reads": frozenset({"private"}),
    "MCP server tools": frozenset(),
}
# An approval record gates its component only when it covers every action or all egress.
_GATING_ACTIONS = frozenset({"*", "egress"})
_READ_ACTIONS = frozenset({"read", "query", "list", "search", "get"})
_DATA_NAME = r"[^\W\d][\w-]*"
_TABLE_NAME = re.compile(rf"{_DATA_NAME}(?:\.{_DATA_NAME})*")
_KB_NAME = re.compile(rf"(?P<root>{_DATA_NAME})(?:/[\w.?*-]+)*/?")
_S3_BUCKET_SCOPE = re.compile(
    r"arn:(?:aws|aws-cn|aws-us-gov):s3:::"
    r"(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:/[\w.?*-]+)*/?"
)
_DYNAMODB_SCOPE = re.compile(
    r"arn:(?:aws|aws-cn|aws-us-gov):dynamodb:[a-z]{2}(?:-[a-z0-9]+)+-[1-9][0-9]*:"
    r"[0-9]{12}:table/[A-Za-z0-9_.-]{3,255}(?:/index/[A-Za-z0-9_.-]{3,255})?"
)
_HOST_SUFFIXES = frozenset(
    [
        "arpa",
        "com",
        "edu",
        "example",
        "gov",
        "int",
        "internal",
        "invalid",
        "local",
        "mil",
        "net",
        "org",
        "test",
    ]
)
_UNBOUNDED_OR_NETWORK_NAMES = frozenset(
    [
        "all",
        "any",
        "everything",
        "everywhere",
        "global",
        "wildcard",
        "egress",
        "api",
        "cloud",
        "dns",
        "endpoint",
        "external",
        "ftp",
        "ftps",
        "gateway",
        "host",
        "http",
        "https",
        "imds",
        "internal",
        "internet",
        "intranet",
        "localhost",
        "loopback",
        "mail",
        "metadata",
        "network",
        "outbound",
        "proxy",
        "public",
        "remote",
        "smtp",
        "url",
        "uri",
        "vpn",
        "web",
        "ws",
        "wss",
        "www",
    ]
)
_UNGATED_CLAUDE_MODES = frozenset({"bypassPermissions", "acceptEdits"})
_UNGATED_CODEX_POLICIES = frozenset({"never"})
_UNCONFINED_CODEX_SANDBOXES = frozenset({"danger-full-access", "full-access"})
EVIDENCE_LIMIT = 10
"""Most components one finding lists for each leg."""
_SHADOW_HIGH_TIERS = frozenset(
    {TrustTier.THIRD_PARTY_UNSIGNED, TrustTier.UNTRUSTED_PUBLIC, TrustTier.UNKNOWN}
)
_WORKSPACE_SURFACE_TYPES = (
    MCPServerComponent,
    ToolComponent,
    DataSourceComponent,
    MemoryStoreComponent,
    RAGSourceComponent,
    A2AServerComponent,
    A2AClientComponent,
)
_CHAINABLE_TYPES = (ToolComponent, MCPServerComponent)


@dataclass(frozen=True)
class LegEvidence:
    """Evidence tying one component to a trifecta leg."""

    component_ref: str
    component_name: str
    basis: tuple[str, ...]
    locator: str | None
    assurance: AssuranceLevel
    gated: bool


@dataclass(frozen=True)
class FlowFinding:
    """A deterministic, evidence-backed trifecta, toxic-flow, or shadowing finding."""

    kind: str
    severity: RiskSeverity
    scope_ref: str
    summary: str
    component_refs: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity.value,
            "scope_ref": self.scope_ref,
            "summary": self.summary,
            "component_refs": list(self.component_refs),
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class TrifectaReport:
    """Result of lethal-trifecta, toxic-flow, and tool-shadowing analysis."""

    scopes_evaluated: int
    findings: tuple[FlowFinding, ...]
    shadowed_refs: tuple[str, ...]

    @property
    def has_critical(self) -> bool:
        return any(f.severity is RiskSeverity.CRITICAL for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return {
            "scopes_evaluated": self.scopes_evaluated,
            "finding_count": len(self.findings),
            "severity_counts": dict(sorted(counts.items())),
            "shadowed_refs": list(self.shadowed_refs),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(frozen=True)
class _ComponentSignals:
    """Precomputed classification and leg bases for a single component."""

    component: AnyComponent
    risk_classification: RiskClassification
    locator: str | None
    untrusted_basis: tuple[str, ...]
    private_basis: tuple[str, ...]
    egress_basis: tuple[str, ...]
    explicitly_gated: bool
    explicitly_ungated: bool


def _normalize_identifier(text: str) -> str:
    """NFKC-normalize, strip invisible/combining chars, fold confusables, split camelCase."""
    # Folded before as well as after: NFKC rewrites some look-alikes, such as the lunate
    # sigma, into letters that no longer resemble the Latin one.
    normalized = unicodedata.normalize("NFKC", text.translate(_CONFUSABLES))
    cleaned = "".join(
        ch
        for ch in normalized
        if unicodedata.category(ch) not in {"Cf", "Cc", "Cs", "Co", "Cn", "Mn"}
    )
    folded = cleaned.translate(_CONFUSABLES)
    return _CAMEL_BOUNDARY_RE.sub("_", folded).strip().lower()


def canonical_tool_name(name: str) -> str:
    """Normalize a tool name for shadowing and naming-rule detection."""
    return _SEPARATOR_RE.sub("_", _normalize_identifier(name)).strip("_")


def _identifier_tokens(text: str) -> set[str]:
    norm = _normalize_identifier(text)
    return {tok for tok in _IDENT_SPLIT_RE.split(norm) if tok}


def _component_locator(component: AnyComponent) -> str | None:
    if component.source_path:
        return component.source_path
    for claim in component.claims.values():
        if claim.locator:
            return claim.locator
    return None


def _mcp_package_identities(server: MCPServerComponent) -> list[str]:
    identities: list[str] = []
    if server.launcher_package:
        identities.append(server.launcher_package)
    raw_packages = server.properties.get("packages")
    if isinstance(raw_packages, list):
        for entry in raw_packages:
            if isinstance(entry, dict):
                ident = entry.get("identity")
                if isinstance(ident, str) and ident:
                    identities.append(ident)
    return identities


def _private_identity(identity: str) -> bool:
    tokens = _identifier_tokens(identity)
    private = tokens & _MCP_PRIVATE_TOKENS
    if tokens & _MCP_DOC_TOKENS:
        private -= _MCP_PLATFORM_TOKENS
    return bool(private)


def _ide_grant_legs(component: AnyComponent) -> frozenset[str]:
    """The legs an IDE agent's unscoped allow rules hold by themselves.

    The ide_agents collector records such rules only as the class names in a
    ``permission_scope`` finding. A class this table does not name, such as
    ``every tool``, holds all three legs, and so does an agent that runs every tool,
    shell included, without a prompt or a sandbox.
    """
    legs: set[str] = set()
    if isinstance(component, IDEAgentComponent):
        if _runs_every_tool_unprompted(component):
            return _LEGS
        for risk in component.risks:
            match = _IDE_GRANT_RE.search(risk.detail) if risk.category == _IDE_GRANT else None
            for name in match.group(1).split(", ") if match else ():
                legs.update(_IDE_GRANT_LEGS.get(name, _LEGS))
    return frozenset(legs)


def _runs_every_tool_unprompted(component: IDEAgentComponent) -> bool:
    if component.ide_type == "claude-code":
        return component.permission_mode == "bypassPermissions"
    if component.ide_type == "codex":
        policy, sandbox = (component.properties.get(k) for k in ("approval_policy", "sandbox_mode"))
        return (
            isinstance(policy, str)
            and isinstance(sandbox, str)
            and policy in _UNGATED_CODEX_POLICIES
            and sandbox in _UNCONFINED_CODEX_SANDBOXES
        )
    return False


def _is_explicitly_ungated(component: AnyComponent) -> bool:
    """True when the component explicitly opts out of approval gates."""
    decl = getattr(component, "capabilities", None)
    if isinstance(decl, CapabilityDeclaration) and decl.human_in_the_loop is HumanInTheLoop.NONE:
        return True
    if isinstance(component, IDEAgentComponent):
        if (
            component.ide_type == "claude-code"
            and component.permission_mode in _UNGATED_CLAUDE_MODES
        ):
            return True
        if component.ide_type == "codex":
            policy = component.properties.get("approval_policy")
            if isinstance(policy, str) and policy in _UNGATED_CODEX_POLICIES:
                return True
    return False


def _approval_state(
    component: AnyComponent, now: datetime, assume_declared_approvals: bool
) -> tuple[bool, bool]:
    """Return (declared gate, explicit opt-out) for the selected approval policy."""
    if _is_explicitly_ungated(component):
        return False, True
    decl = getattr(component, "capabilities", None)
    required = (
        isinstance(decl, CapabilityDeclaration)
        and decl.human_in_the_loop is HumanInTheLoop.REQUIRED
    )
    # The explicit modeling API historically gives a required declaration precedence.
    if assume_declared_approvals and required:
        return True, False
    records = [
        r
        for r in getattr(component, "authorizations", ()) or ()
        if isinstance(r, AuthorizationRecord)
    ]
    for record in records:
        if not assume_declared_approvals and _independent_read(record):
            continue
        if record.approval_required is not True or not _unexpired(record, now):
            return False, not assume_declared_approvals
    broad = any(
        r.action in _GATING_ACTIONS
        and r.resource_scope in (None, "*")
        and (assume_declared_approvals or not r.conditions)
        for r in records
    )
    return required or broad, False


def _independent_read(record: AuthorizationRecord) -> bool:
    """A named read can coexist with egress approval. A network or unbounded grant cannot."""
    if record.action.strip().casefold() not in _READ_ACTIONS or not record.resource_scope:
        return False
    scope = record.resource_scope
    if {".", ".."}.intersection(scope.split("/")):
        return False
    # A bare identifier, host, or slash namespace cannot establish what a tool
    # reads. Only an explicit data type or a resource-specific ARN supplies it.
    kind, colon, value = scope.partition(":")
    if not colon or not kind.isascii():
        return False
    if kind.lower() == "table" and _TABLE_NAME.fullmatch(value):
        parts = [canonical_tool_name(part) for part in value.split(".")]
        if len(parts) > 1 and parts[-1] in _HOST_SUFFIXES:
            return False
        return all(
            part not in _UNBOUNDED_OR_NETWORK_NAMES or (part == "public" and i < len(parts) - 1)
            for i, part in enumerate(parts)
        )
    if kind.lower() == "kb":
        kb = _KB_NAME.fullmatch(value)
        return kb is not None and canonical_tool_name(kb["root"]) not in _UNBOUNDED_OR_NETWORK_NAMES
    bucket = _S3_BUCKET_SCOPE.fullmatch(scope)
    if bucket is not None:
        name = bucket["bucket"]
        return ".." not in name and re.fullmatch(r"\d+(?:\.\d+){3}", name) is None
    return _DYNAMODB_SCOPE.fullmatch(scope) is not None


def _unexpired(record: AuthorizationRecord, now: datetime) -> bool:
    expires = record.expires_at
    # An expiry without a zone cannot be compared with the clock, so it does not gate.
    return expires is None or (expires.utcoffset() is not None and expires > now)


def _is_pure_readonly_network_reader(component: ToolComponent) -> bool:
    """True for a read-only search tool with no mutating, exfil or URL-fetching capability."""
    decl = component.capabilities
    if not isinstance(decl, CapabilityDeclaration):
        return False
    caps = set(decl.capabilities)
    if caps & _MUTATING_CAPABILITIES or caps & _PRIVATE_CAPABILITIES:
        return False
    if decl.egress_domains:
        return False
    if decl.side_effect_profile in _MUTATING_SIDE_EFFECTS:
        return False
    canon = canonical_tool_name(component.name)
    if _EGRESS_TOOL_RE.search(canon) or _URL_FETCH_TOOL_RE.search(canon):
        return False
    return CapabilityClass.NETWORK in caps and CapabilityClass.READ in caps


def _untrusted_input_basis(component: AnyComponent, rc: RiskClassification) -> tuple[str, ...]:
    basis: set[str] = set()
    props = component.properties
    if props.get("untrusted_input") is True or props.get("reads_untrusted_input") is True:
        basis.add("property:untrusted_input")
    if isinstance(component, (A2AServerComponent, A2AClientComponent)):
        basis.add(f"component_type:{component.component_type.value}")
    if isinstance(component, MCPServerComponent):
        if component.endpoint_url and RiskClass.NETWORK_EGRESS in rc.classes:
            basis.add("mcp_server:remote_endpoint")
        for ident in _mcp_package_identities(component):
            if _identifier_tokens(ident) & _MCP_UNTRUSTED_TOKENS:
                basis.add("mcp_server:untrusted_input_package")
                break
        if _identifier_tokens(component.name) & _MCP_UNTRUSTED_TOKENS:
            basis.add("mcp_server:untrusted_input_name")
    if "untrusted" in _ide_grant_legs(component):
        basis.add("ide_agent:unscoped_allowance")
    decl = getattr(component, "capabilities", None)
    if isinstance(decl, CapabilityDeclaration):
        caps = set(decl.capabilities)
        if CapabilityClass.NETWORK in caps and CapabilityClass.READ in caps:
            basis.add("capabilities:network+read")
    if isinstance(component, ToolComponent):
        canon = canonical_tool_name(component.name)
        if _UNTRUSTED_TOOL_RE.search(canon):
            basis.add("tool_name:external_reader")
        else:
            # Collectors record a tool's description as description_text.
            text = f"{component.description_text or ''} {component.description or ''}"
            if _UNTRUSTED_DESC_RE.search(_IDENT_SPLIT_RE.sub("_", _normalize_identifier(text))):
                basis.add("tool_description:external_reader")
    return tuple(sorted(basis))


def _private_data_basis(component: AnyComponent, rc: RiskClassification) -> tuple[str, ...]:
    basis: set[str] = set()
    if RiskClass.SECRET_ACCESS in rc.classes:
        basis.add("risk_class:secret-access")
    if isinstance(component, (DataSourceComponent, MemoryStoreComponent, RAGSourceComponent)):
        basis.add(f"component_type:{component.component_type.value}")
    if isinstance(component, MCPServerComponent):
        if any(
            _WITHHELD_ENV_NAME_RE.fullmatch(key) or _SECRET_ENV_KEY_RE.search(key)
            for key in component.env
        ):
            basis.add("mcp_server:secret_env")
        if any(_private_identity(ident) for ident in _mcp_package_identities(component)):
            basis.add("mcp_server:private_data_package")
        if _private_identity(component.name):
            basis.add("mcp_server:private_data_name")
    if "private" in _ide_grant_legs(component):
        basis.add("ide_agent:unscoped_allowance")
    decl = getattr(component, "capabilities", None)
    if isinstance(decl, CapabilityDeclaration):
        caps = set(decl.capabilities)
        for cap in (CapabilityClass.CREDENTIALS, CapabilityClass.FILESYSTEM, CapabilityClass.READ):
            if cap in caps and (
                cap is not CapabilityClass.READ
                or component.properties.get("private_data") is True
                or bool(decl.filesystem_paths)
                or bool(decl.oauth_scopes)
            ):
                basis.add(f"capabilities:{cap.value}")
        if decl.filesystem_paths:
            basis.add("filesystem_paths:declared")
        if decl.oauth_scopes:
            basis.add("oauth_scopes:declared")
    if component.properties.get("private_data") is True:
        basis.add("property:private_data")
    if isinstance(component, ToolComponent):
        canon = canonical_tool_name(component.name)
        if _PRIVATE_TOOL_RE.search(canon):
            basis.add("tool_name:private_reader")
    return tuple(sorted(basis))


def _egress_basis(component: AnyComponent, rc: RiskClassification) -> tuple[str, ...]:
    basis: set[str] = set()
    skip_readonly_net = isinstance(component, ToolComponent) and _is_pure_readonly_network_reader(
        component
    )
    for cls in (
        RiskClass.NETWORK_EGRESS,
        RiskClass.EXFIL_CAPABLE,
        RiskClass.WRITE_CAPABLE,
        RiskClass.CODE_EXEC,
    ):
        if skip_readonly_net and cls in {RiskClass.NETWORK_EGRESS, RiskClass.EXFIL_CAPABLE}:
            continue
        if cls in rc.classes:
            basis.add(f"risk_class:{cls.value}")
    if component.properties.get("external_egress") is True:
        basis.add("property:external_egress")
    if isinstance(component, MCPServerComponent):
        for ident in _mcp_package_identities(component):
            if _identifier_tokens(ident) & _MCP_EGRESS_TOKENS:
                basis.add("mcp_server:egress_package")
                break
        if _identifier_tokens(component.name) & _MCP_EGRESS_TOKENS:
            basis.add("mcp_server:egress_name")
    if "egress" in _ide_grant_legs(component):
        basis.add("ide_agent:unscoped_allowance")
    if isinstance(component, ToolComponent) and not skip_readonly_net:
        canon = canonical_tool_name(component.name)
        if _EGRESS_TOOL_RE.search(canon):
            basis.add("tool_name:egress_or_mutation")
        if _URL_FETCH_TOOL_RE.search(canon):
            basis.add("tool_name:url_fetcher")
    return tuple(sorted(basis))


def _tarjan_scc(nodes: list[str], adj: dict[str, list[str]]) -> list[list[str]]:
    """Iterative Tarjan's strongly connected components in O(V + E) time."""
    index_counter = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    sccs: list[list[str]] = []

    for start in nodes:
        if start in indices:
            continue
        call_stack: list[tuple[str, int]] = [(start, 0)]
        indices[start] = lowlinks[start] = index_counter
        index_counter += 1
        stack.append(start)
        on_stack.add(start)

        while call_stack:
            v, edge_idx = call_stack[-1]
            neighbors = adj.get(v, ())
            if edge_idx < len(neighbors):
                call_stack[-1] = (v, edge_idx + 1)
                w = neighbors[edge_idx]
                if w not in indices:
                    indices[w] = lowlinks[w] = index_counter
                    index_counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    call_stack.append((w, 0))
                elif w in on_stack:
                    if indices[w] < lowlinks[v]:
                        lowlinks[v] = indices[w]
            else:
                call_stack.pop()
                if call_stack:
                    parent = call_stack[-1][0]
                    if lowlinks[v] < lowlinks[parent]:
                        lowlinks[parent] = lowlinks[v]
                if lowlinks[v] == indices[v]:
                    comp_scc: list[str] = []
                    while True:
                        member = stack.pop()
                        on_stack.remove(member)
                        comp_scc.append(member)
                        if member == v:
                            break
                    sccs.append(comp_scc)
    return sccs


_Reach = dict[str, tuple[str, ...]]
"""Per tag, the first ``EVIDENCE_LIMIT`` component references that carry it."""


def _own_reach(sig: _ComponentSignals) -> _Reach:
    comp = sig.component
    chained = (
        isinstance(comp, _CHAINABLE_TYPES)
        and RiskClass.EXFIL_CAPABLE not in sig.risk_classification.classes
    )
    tags: list[str] = []
    if sig.untrusted_basis:
        tags.append("untrusted")
    if sig.private_basis:
        tags.extend(("private", "source") if chained else ("private",))
    # Keep every egress for reporting unverified declarations. Track uncovered
    # egress separately so the display cap cannot hide a single open path.
    if sig.egress_basis:
        tags.extend(("egress", "sink") if chained else ("egress",))
        if not sig.explicitly_gated:
            tags.extend(("egress_open", "sink_open") if chained else ("egress_open",))
        if sig.explicitly_ungated:
            tags.extend(("egress_forced", "sink_forced") if chained else ("egress_forced",))
    if isinstance(comp, IDEAgentComponent) and sig.explicitly_ungated:
        tags.append("ungated_ide")
    if isinstance(comp, (MCPServerComponent, ToolComponent)):
        tags.append("surface")
    return dict.fromkeys(tags, (comp.bom_ref,))


def _merge(into: _Reach, other: _Reach) -> None:
    for tag, refs in other.items():
        have = into.get(tag)
        if have is None:
            into[tag] = refs
        elif have is not refs:
            into[tag] = tuple(sorted({*have, *refs})[:EVIDENCE_LIMIT])


def _uncovered_paths(reach: _Reach, *, all_egress: bool = False) -> _Reach:
    """The open egress reached without a directly governing approval declaration."""
    suffix = "" if all_egress else "_open"
    return {
        "path_" + leg: reach[leg + suffix] for leg in ("egress", "sink") if leg + suffix in reach
    }


def _summarize(refs: Iterable[str], own: dict[str, _Reach]) -> _Reach:
    lists: dict[str, list[str]] = {}
    for ref in sorted(refs):
        for tag in own[ref]:
            found = lists.setdefault(tag, [])
            if len(found) < EVIDENCE_LIMIT:
                found.append(ref)
    reach = {tag: tuple(found) for tag, found in lists.items()}
    # Inventory-wide, implicit workspace and unbound pools have no binding owner.
    return {**reach, **_uncovered_paths(reach)}


def _scopes(
    bom: AIBOM,
    signals: dict[str, _ComponentSignals],
    assume_declared_approvals: bool,
) -> list[tuple[str, bool, _Reach]]:
    """Compute evaluation scopes in O(V + E) time using SCC condensation.

    Returns tuples of ``(scope_ref, scope_owner_gated, reach)``, where ``reach`` names
    at most ``EVIDENCE_LIMIT`` components per leg. It is merged upwards through the
    condensed graph, so no scope materializes its member set and many agents that
    share one tool surface cost the surface once.
    - Cyclic agent graphs collapse into a single SCC so traversal is linear.
    - IDE agents without explicit MCP/tool bindings inherit the workspace MCP/tool
      surface even when they carry edges to prompt components.
    - Components that no agent reaches are bound to no one, so nothing keeps them from
      any agent: they are evaluated as ``inventory:unscoped`` and again with every
      agent scope that holds a leg itself, so legs split between the two still meet.
    """
    by_ref = {comp.bom_ref: comp for comp in bom.components}
    own = {ref: _own_reach(signals[ref]) for ref in by_ref}
    agents = sorted(
        (c for c in bom.components if isinstance(c, (AgentComponent, IDEAgentComponent))),
        key=lambda c: c.bom_ref,
    )
    if not agents:
        return [("inventory:root", False, _summarize(by_ref, own))] if by_ref else []

    adj: dict[str, list[str]] = {ref: [] for ref in by_ref}
    declared_bindings: set[tuple[str, str]] = set()
    # Inventory containment is evidence of visibility. It does not introduce a
    # second caller for a tool already directly bound by the governing agent.
    contained: dict[str, set[str]] = {}
    independent: set[tuple[str, str]] = set()

    def containment(source: str, target: str) -> None:
        contained.setdefault(source, set()).add(target)

    for dep in bom.dependencies:
        if dep.source_ref in by_ref and dep.target_ref in by_ref:
            adj[dep.source_ref].append(dep.target_ref)
            if (
                dep.relationship == "provides-tool"
                and isinstance(by_ref[dep.source_ref], MCPServerComponent)
                and isinstance(by_ref[dep.target_ref], ToolComponent)
            ):
                containment(dep.source_ref, dep.target_ref)
            elif dep.relationship in {"invokes", "configured-with"}:
                declared_bindings.add((dep.source_ref, dep.target_ref))
            else:
                independent.add((dep.source_ref, dep.target_ref))

    clients_by_host: dict[str, list[MCPClientComponent]] = {}
    for comp in bom.components:
        if isinstance(comp, AgentComponent):
            declared_bindings.update((comp.bom_ref, ref) for ref in comp.tool_refs)
            independent.update(
                (comp.bom_ref, ref)
                for ref in (
                    *comp.data_refs,
                    *comp.memory_refs,
                    *comp.skill_refs,
                    *comp.sub_agent_refs,
                )
            )
            for ref in (
                *comp.tool_refs,
                *comp.data_refs,
                *comp.memory_refs,
                *comp.skill_refs,
                *comp.sub_agent_refs,
            ):
                if ref in by_ref:
                    adj[comp.bom_ref].append(ref)
        elif isinstance(comp, IDEAgentComponent):
            declared_bindings.update((comp.bom_ref, ref) for ref in comp.mcp_server_refs)
            for ref in (*comp.mcp_server_refs, *comp.prompt_refs):
                if ref in by_ref:
                    adj[comp.bom_ref].append(ref)
        elif isinstance(comp, MCPClientComponent):
            if comp.host_application:
                clients_by_host.setdefault(comp.host_application, []).append(comp)
            for ref in comp.server_refs:
                if ref in by_ref:
                    adj[comp.bom_ref].append(ref)
                    if isinstance(by_ref[ref], MCPServerComponent):
                        containment(comp.bom_ref, ref)
        elif isinstance(comp, ToolComponent) and comp.mcp_server_ref in by_ref:
            adj[comp.mcp_server_ref].append(comp.bom_ref)
            if isinstance(by_ref[comp.mcp_server_ref], MCPServerComponent):
                containment(comp.mcp_server_ref, comp.bom_ref)

    for comp in agents:
        if isinstance(comp, IDEAgentComponent) and not comp.mcp_server_refs and comp.ide_type:
            for client in clients_by_host.get(comp.ide_type, ()):
                adj[comp.bom_ref].append(client.bom_ref)

    nodes_sorted = sorted(by_ref)
    sccs = _tarjan_scc(nodes_sorted, adj)
    scc_of: dict[str, int] = {}
    for scc_id, scc_members in enumerate(sccs):
        for ref in scc_members:
            scc_of[ref] = scc_id

    agent_refs = {a.bom_ref for a in agents}
    scc_agents: dict[int, list[AnyComponent]] = {}
    for scc_id, scc_members in enumerate(sccs):
        a_list = sorted(
            (by_ref[r] for r in scc_members if r in agent_refs), key=lambda c: c.bom_ref
        )
        if a_list:
            scc_agents[scc_id] = a_list

    # Condensed DAG edges between SCCs, plus agent-to-agent parent tracking.
    dag_adj: dict[int, list[int]] = {i: [] for i in range(len(sccs))}
    agent_parents: dict[int, set[int]] = {scc_id: set() for scc_id in scc_agents}
    open_targets = {
        ref: _uncovered_paths(tags) for ref, tags in own.items() if "egress_open" in tags
    }
    path_exposure: list[_Reach] = [{} for _ in sccs]
    # A client lists servers, and a server lists tools. Those two typed layers
    # preserve the incoming caller. An invocation or other dependency starts an
    # independent route, even alongside a containment edge between the same refs.
    open_members: dict[str, dict[str, list[str]]] = {}
    for container, members in contained.items():
        open_members[container] = {
            tag: [v for v in sorted(members) if tag in open_targets.get(v, {})]
            for tag in ("path_egress", "path_sink")
        }
    # Cache the ordinary uncovered sample. The common case of shared, unbound
    # catalogs costs one scan, regardless of how many agents reference a client.
    nested = {
        ref: sorted(v for v in values if v in contained)
        for ref, values in contained.items()
        if isinstance(by_ref[ref], MCPClientComponent)
    }
    ordinary: dict[str, _Reach] = {}
    for ref in sorted(contained, key=lambda r: isinstance(by_ref[r], MCPClientComponent)):
        gaps = {
            tag: tuple(values[:EVIDENCE_LIMIT])
            for tag, values in open_members[ref].items()
            if values
        }
        for server in nested.get(ref, ()):
            _merge(gaps, ordinary[server])
        ordinary[ref] = gaps

    # Owners who cover part of the ordinary sample may need later members. Share
    # those ordered candidates across owners and expand only as far as requested.
    expanded: dict[tuple[str, str], tuple[list[str], Iterator[str]]] = {}

    def containment_candidates(target: str, tag: str) -> Iterator[str]:
        key = (target, tag)
        if key not in expanded:
            sources = [open_members[target][tag]]
            sources.extend(open_members[server][tag] for server in nested.get(target, ()))
            expanded[key] = ([], (ref for ref, _ in groupby(merge_sorted(*sources))))
        known, pending = expanded[key]
        yield from known
        for ref in pending:
            known.append(ref)
            yield ref

    def containment_gaps(owner: str, target: str, binding: bool) -> _Reach:
        sample = ordinary[target]
        if not binding:
            return sample

        def uncovered(ref: str) -> bool:
            return (owner, ref) not in declared_bindings or signals[ref].explicitly_ungated

        gaps: _Reach = {}
        for tag, refs in sample.items():
            if all(map(uncovered, refs)):
                gaps[tag] = refs
            else:
                remaining = tuple(
                    islice(filter(uncovered, containment_candidates(target, tag)), EVIDENCE_LIMIT)
                )
                if remaining:
                    gaps[tag] = remaining
        return gaps

    for u, targets in adj.items():
        su = scc_of[u]
        seen_t: set[int] = set()
        governing_agent = u in agent_refs and signals[u].explicitly_gated
        visited_containers: set[str] = set()
        if u in agent_refs and u in open_targets and not assume_declared_approvals:
            _merge(path_exposure[su], open_targets[u])
        for v in targets:
            edge = (u, v)
            passive_only = (
                v in contained.get(u, ())
                and edge not in independent
                and edge not in declared_bindings
            )
            if not assume_declared_approvals and not passive_only:
                binding = governing_agent and edge in declared_bindings and edge not in independent
                if v in open_targets and not (
                    binding
                    and isinstance(by_ref[v], (ToolComponent, MCPServerComponent))
                    and not signals[v].explicitly_ungated
                ):
                    _merge(path_exposure[su], open_targets[v])
                if v in contained and v not in visited_containers:
                    visited_containers.add(v)
                    _merge(path_exposure[su], containment_gaps(u, v, binding))
            sv = scc_of[v]
            if sv != su and sv not in seen_t:
                seen_t.add(sv)
                dag_adj[su].append(sv)
                if su in scc_agents and sv in scc_agents:
                    agent_parents[sv].add(su)

    # An agent SCC is gated only if EVERY agent in that SCC has an explicit approval gate
    # and NONE is explicitly ungated.
    scc_gated: dict[int, bool] = {}
    for scc_id, a_list in scc_agents.items():
        scc_gated[scc_id] = all(signals[a.bom_ref].explicitly_gated for a in a_list) and not any(
            signals[a.bom_ref].explicitly_ungated for a in a_list
        )

    # Tarjan emits SCCs in reverse topological order, so reversed(range(len(sccs))) is
    # topological order. Track whether an SCC already has an ungated agent ancestor so
    # alternating-gate chains stay O(V + E) without missing any ungated scope.
    has_ungated_ancestor: dict[int, bool] = dict.fromkeys(range(len(sccs)), False)
    for su in reversed(range(len(sccs))):
        propagates_ungated = has_ungated_ancestor[su] or (su in scc_agents and not scc_gated[su])
        if propagates_ungated:
            for sv in dag_adj[su]:
                has_ungated_ancestor[sv] = True

    selected_sccs: list[int] = []
    for scc_id in sorted(scc_agents, key=lambda sid: scc_agents[sid][0].bom_ref):
        parents = agent_parents[scc_id]
        if not parents or (not scc_gated[scc_id] and not has_ungated_ancestor[scc_id]):
            selected_sccs.append(scc_id)

    # Tarjan numbers a strongly connected component after everything it reaches.
    reach: list[_Reach] = []
    for scc_id, scc_members in enumerate(sccs):
        merged = path_exposure[scc_id]
        for ref in scc_members:
            _merge(merged, own[ref])
        for child in dag_adj[scc_id]:
            _merge(merged, reach[child])
        if not assume_declared_approvals and scc_id in scc_agents and not scc_gated[scc_id]:
            _merge(merged, _uncovered_paths(merged, all_egress=True))
        reach.append(merged)

    covered = set(scc_agents)
    stack = list(scc_agents)
    while stack:
        for nxt in dag_adj[stack.pop()]:
            if nxt not in covered:
                covered.add(nxt)
                stack.append(nxt)
    unbound = {ref for ref in by_ref if scc_of[ref] not in covered}

    # An IDE agent without explicit MCP/tool bindings governs the repository's
    # workspace MCP/tool surface regardless of prompt edges.
    inherits = {
        scc_id
        for scc_id in selected_sccs
        if "surface" not in reach[scc_id]
        and any(isinstance(a, IDEAgentComponent) for a in scc_agents[scc_id])
    }
    workspace: _Reach = {}
    if inherits:
        surface = [c.bom_ref for c in bom.components if isinstance(c, _WORKSPACE_SURFACE_TYPES)]
        workspace = _summarize(surface, own)
        unbound.difference_update(surface)
    pool = _summarize(unbound, own)

    scope_legs = {"untrusted", "private", "egress_open"} if assume_declared_approvals else _LEGS
    result: list[tuple[str, bool, _Reach]] = []
    for scc_id in selected_sccs:
        scope = dict(reach[scc_id])
        if scc_id in inherits:
            _merge(scope, workspace)
        if scope_legs & scope.keys():
            _merge(scope, pool)
        if not assume_declared_approvals and not scc_gated[scc_id]:
            _merge(scope, _uncovered_paths(scope, all_egress=True))
        result.append((scc_agents[scc_id][0].bom_ref, scc_gated[scc_id], scope))
    if unbound:
        result.append(("inventory:unscoped", False, pool))
    return result


def _evidence_entry(
    leg: str, item: LegEvidence, *, egress_approval_declared: bool | None = None
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "leg": leg,
        "component_ref": item.component_ref,
        "component_name": item.component_name,
        "basis": list(item.basis),
        "locator": item.locator,
        "assurance": item.assurance.value,
        "gated": item.gated,
    }
    if egress_approval_declared is not None:
        evidence["egress_approval_declared"] = egress_approval_declared
        evidence["approval_enforcement_verified"] = False
    return evidence


def _detect_shadowing(bom: AIBOM) -> tuple[list[FlowFinding], set[str]]:
    tools = [c for c in bom.components if isinstance(c, ToolComponent)]
    groups: dict[str, list[ToolComponent]] = {}
    for tool in sorted(tools, key=lambda t: t.bom_ref):
        key = canonical_tool_name(tool.name)
        if key:
            groups.setdefault(key, []).append(tool)

    findings: list[FlowFinding] = []
    shadowed_refs: set[str] = set()
    for canon_name, group in sorted(groups.items()):
        if len(group) < 2:
            continue
        distinct_origins = {(t.mcp_server_ref, t.source_path) for t in group}
        if len(distinct_origins) < 2 and len({t.bom_ref for t in group}) < 2:
            continue
        tiers = [t.trust_tier for t in group]
        has_trusted = any(
            _TRUST_RANK[t] >= _TRUST_RANK[TrustTier.THIRD_PARTY_SIGNED] for t in tiers
        )
        has_untrusted = any(t in _SHADOW_HIGH_TIERS for t in tiers)
        severity = RiskSeverity.HIGH if (has_trusted and has_untrusted) else RiskSeverity.MEDIUM
        refs = tuple(t.bom_ref for t in group)
        shadowed_refs.update(refs)
        evidence = tuple(
            {
                "leg": "shadowed_tool",
                "component_ref": t.bom_ref,
                "component_name": t.name,
                "canonical_name": canon_name,
                "server_ref": t.mcp_server_ref,
                "trust_tier": t.trust_tier.value,
                "locator": _component_locator(t),
                "assurance": t.assurance_level.value,
            }
            for t in group
        )
        findings.append(
            FlowFinding(
                kind="tool_shadowing",
                severity=severity,
                scope_ref="inventory:root",
                summary=(
                    f"Tool name '{canon_name}' is defined by {len(group)} distinct components "
                    f"({', '.join(refs)}), creating a tool-shadowing conflict."
                ),
                component_refs=refs,
                evidence=evidence,
                recommendation=(
                    "Namespace tools per server, pin tool definition digests, and remove "
                    "duplicate or lower-trust tool definitions that shadow trusted tools."
                ),
            )
        )
    return findings, shadowed_refs


def _scope_findings(
    scope_ref: str,
    owner_gated: bool,
    reach: _Reach,
    signals: dict[str, _ComponentSignals],
    assume_declared_approvals: bool,
) -> list[FlowFinding]:
    # Fail closed: an IDE agent that opts out of approval overrides an owner gate.
    gated_owner = owner_gated and "ungated_ide" not in reach

    def items(tag: str) -> list[LegEvidence]:
        found = []
        for ref in reach.get(tag, ()):
            sig = signals[ref]
            comp = sig.component
            basis = sig.private_basis if tag in ("private", "source") else sig.egress_basis
            found.append(
                LegEvidence(
                    ref,
                    comp.name,
                    sig.untrusted_basis if tag == "untrusted" else basis,
                    sig.locator,
                    comp.assurance_level,
                    assume_declared_approvals
                    and tag not in {"path_egress", "path_sink"}
                    and (gated_owner or sig.explicitly_gated)
                    and not sig.explicitly_ungated,
                )
            )
        return found

    findings: list[FlowFinding] = []
    untrusted = items("untrusted")
    private = items("private")
    open_egress = (
        items("egress_forced" if gated_owner else "egress_open")
        if assume_declared_approvals
        else items("path_egress")
    )
    egress = open_egress
    if not egress and not assume_declared_approvals:
        egress = items("egress")
    if untrusted and private and egress:
        involved = sorted({i.component_ref for i in (*untrusted, *private, *egress)})
        capped = EVIDENCE_LIMIT in (len(untrusted), len(private), len(egress))
        findings.append(
            FlowFinding(
                kind="lethal_trifecta",
                severity=RiskSeverity.CRITICAL if open_egress else RiskSeverity.HIGH,
                scope_ref=scope_ref,
                summary=(
                    f"Scope '{scope_ref}' combines untrusted input, private data access, "
                    "and external egress/state mutation across "
                    f"{'at least ' if capped else ''}{len(involved)} component(s). "
                    + (
                        "At least one egress has no applicable declared approval gate."
                        if open_egress
                        else "A human-approval declaration covers every egress. Runtime enforcement is unverified."
                    )
                ),
                component_refs=tuple(involved),
                evidence=(
                    *(_evidence_entry("untrusted_input", i) for i in untrusted),
                    *(_evidence_entry("private_data", i) for i in private),
                    *(
                        _evidence_entry(
                            "egress",
                            i,
                            egress_approval_declared=None
                            if assume_declared_approvals
                            else not open_egress,
                        )
                        for i in egress
                    ),
                ),
                recommendation=(
                    "Break at least one leg of the trifecta or enforce an explicit "
                    "human-in-the-loop approval gate (human_in_the_loop: required) on "
                    "every egress and state-modifying tool."
                ),
            )
        )

    # Item 24: Chained toxic flow across two distinct components where neither alone
    # is EXFIL_CAPABLE (linear time without materializing Cartesian pairs).
    chained_sources = items("source")
    sink_tag = (
        ("sink_forced" if gated_owner else "sink_open") if assume_declared_approvals else "sink"
    )
    chained_sinks = items(sink_tag)
    source_refs = {src.component_ref for src in chained_sources}
    sink_refs = {snk.component_ref for snk in chained_sinks}
    active_sources = [
        src for src in chained_sources if len(sink_refs) > 1 or src.component_ref not in sink_refs
    ]
    active_sinks = [
        snk for snk in chained_sinks if len(source_refs) > 1 or snk.component_ref not in source_refs
    ]
    if active_sources and active_sinks:
        pair_refs = tuple(sorted({i.component_ref for i in (*active_sources, *active_sinks)}))
        capped = EVIDENCE_LIMIT in (len(chained_sources), len(chained_sinks))
        findings.append(
            FlowFinding(
                kind="toxic_flow",
                severity=RiskSeverity.HIGH,
                scope_ref=scope_ref,
                summary=(
                    f"Scope '{scope_ref}' enables a chained toxic flow across "
                    f"{'at least ' if capped else ''}{len(pair_refs)} distinct components "
                    f"({', '.join(pair_refs)}) where "
                    "private data from one component can leave through "
                    + (
                        "an ungated sink."
                        if not assume_declared_approvals
                        and any(
                            len(source_refs) > 1 or ref not in source_refs
                            for ref in reach.get("path_sink", ())
                        )
                        else "a sink with unverified approval enforcement."
                    )
                ),
                component_refs=pair_refs,
                evidence=(
                    *(_evidence_entry("toxic_source", src) for src in active_sources),
                    *(_evidence_entry("toxic_sink", snk) for snk in active_sinks),
                ),
                recommendation=(
                    "Require explicit approval on egress/state-modifying sink tools or "
                    "isolate private-data tools from network-capable tools."
                ),
            )
        )
    return findings


def analyze_trifecta(
    bom: AIBOM, *, now: datetime | None = None, assume_declared_approvals: bool = False
) -> TrifectaReport:
    """Analyze an inventory for lethal trifectas, chained toxic flows, and tool shadowing.

    ``now`` is the time approval records' expiry is read against; the default is the clock.
    ``assume_declared_approvals`` is for modeling a proposed design. Admission gates
    must use the default, since an inventory cannot establish effective authorization.
    """
    moment = now or datetime.now(UTC)
    signals: dict[str, _ComponentSignals] = {}
    for comp in bom.components:
        rc = classify(comp)
        gated, ungated = _approval_state(comp, moment, assume_declared_approvals)
        signals[comp.bom_ref] = _ComponentSignals(
            component=comp,
            risk_classification=rc,
            locator=_component_locator(comp),
            untrusted_basis=_untrusted_input_basis(comp, rc),
            private_basis=_private_data_basis(comp, rc),
            egress_basis=_egress_basis(comp, rc),
            explicitly_gated=gated,
            explicitly_ungated=ungated,
        )

    scopes = _scopes(bom, signals, assume_declared_approvals)
    findings: list[FlowFinding] = []
    for scope_ref, owner_gated, reach in scopes:
        findings.extend(
            _scope_findings(scope_ref, owner_gated, reach, signals, assume_declared_approvals)
        )

    shadow_findings, shadowed_refs = _detect_shadowing(bom)
    findings.extend(shadow_findings)
    findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.kind, f.scope_ref, f.component_refs))
    return TrifectaReport(
        scopes_evaluated=len(scopes),
        findings=tuple(findings),
        shadowed_refs=tuple(sorted(shadowed_refs)),
    )
