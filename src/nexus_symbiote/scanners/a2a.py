"""Bounded offline A2A card, client configuration and SDK-reference collection."""

from __future__ import annotations

import ast
import base64
import codecs
import json
import re
import unicodedata
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO, NamedTuple
from urllib.parse import urlsplit

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import canonical_json, hash_canonical
from nexus_symbiote.core.identifiers import reference_text
from nexus_symbiote.core.models import (
    UNBOUND_VALUES_DETAIL,
    A2AClientComponent,
    A2AServerComponent,
    CapabilityDeclaration,
    RiskAssessment,
)
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    SourceBudget,
    parse_python,
    source_collection_bytes,
)
from nexus_symbiote.scanners.credential_files import relinked, withheld
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.scanners.mcp_sources import _INVALID_UTF8, _source_encoding, _UnreadableError
from nexus_symbiote.scanners.source_binding import ORIGIN_PATHS as _ORIGIN_PATHS
from nexus_symbiote.scanners.source_binding import BindingError as _BindingError
from nexus_symbiote.scanners.source_binding import beyond_origin as _beyond_origin
from nexus_symbiote.scanners.source_binding import origin as _origin
from nexus_symbiote.scanners.source_binding import url_shape as _url_shape
from nexus_symbiote.scanners.source_binding import url_shapes as _url_shapes
from nexus_symbiote.scanners.source_binding import value_binding as _value_binding
from nexus_symbiote.scanners.source_binding import whatwg_form as _whatwg_form
from nexus_symbiote.utils.confined import CollectionError, ConfinedCollection, fold_name
from nexus_symbiote.utils.secrets import REDACTED, redact_text
from nexus_symbiote.utils.terminal import neutralize

# Python source is parsed only when the text Python reads can name the SDK.
_A2A_SOURCE_HINTS = ("a2a", "A2AClient", "AgentCard")
_HINT_OVERLAP = max(len(hint) for hint in _A2A_SOURCE_HINTS) - 1
# Source under these directories is not searched for SDK references.
_SOURCE_EXCLUDED_DIRS = frozenset(
    {"tests", "test", "dist", "build", "docs", "benchmarks", "examples"}
)

AGENT_CARD_NAMES = ("agent.json", "agent-card.json")
# Cards are read from these root paths and from a .well-known directory at any depth,
# such as public/.well-known/agent-card.json, where web frameworks serve static files.
AGENT_CARD_FILES = [
    ".well-known/agent.json",
    ".well-known/agent-card.json",
    "agent.json",
    "agent-card.json",
    "a2a/agent.json",
]
# Outside .well-known these names are generic, so a file there is a card only when it
# carries a field that only A2A cards declare.
_GENERIC_CARD_PATHS = frozenset({"agent.json", "agent-card.json", "a2a/agent.json"})
_CARD_MARKERS = frozenset(
    {
        "url",
        "supportedInterfaces",
        "supported_interfaces",
        "additionalInterfaces",
        "skills",
        "securitySchemes",
        "security_schemes",
        "securityRequirements",
        "security_requirements",
        "capabilities",
        "protocolVersion",
        "protocol_version",
        "preferredTransport",
        "defaultInputModes",
        "default_input_modes",
    }
)
A2A_CONFIG_FILES = ["a2a.json", "a2a.yaml", "a2a.yml", "a2a_config.json"]

# Exports keep only URL origins, and paths or queries may carry credentials, so no
# unkeyed digest covers them: it would let anyone holding the BOM confirm guesses. The
# structure digests cover names, counts, flags and values exported in clear. They
# also cover the requirement values of schemes other than OAuth 2.0 and OpenID Connect,
# which are not exported, so a BOM holder can confirm guesses of those values. Other
# values are bound only by an HMAC under the operator key, as for MCP.
CARD_STRUCTURE_PROFILE = "nexus-symbiote/a2a-card-structure/v4"
CARD_VALUE_BINDING_PROFILE = "nexus-symbiote/a2a-card-values/v1"
CLIENT_STRUCTURE_PROFILE = "nexus-symbiote/a2a-client-structure/v1"
CLIENT_VALUE_BINDING_PROFILE = "nexus-symbiote/a2a-client-values/v1"
SECURITY_SCHEME_TYPES = frozenset({"apiKey", "http", "oauth2", "openIdConnect", "mutualTLS"})
# Requirements list scopes for these types and role names for the others, as in OpenAPI.
SCOPED_SCHEME_TYPES = frozenset({"oauth2", "openIdConnect"})
_SCHEME_TYPE_NAMES = {kind.lower(): kind for kind in SECURITY_SCHEME_TYPES}
# A2A 1.0 (lf.a2a.v1) serializes SecurityScheme as a oneof, and proto3 JSON parsers
# accept each field under its JSON name or its proto name.
_WRAPPED_SCHEME_TYPES = {
    "apiKeySecurityScheme": "apiKey",
    "api_key_security_scheme": "apiKey",
    "httpAuthSecurityScheme": "http",
    "http_auth_security_scheme": "http",
    "oauth2SecurityScheme": "oauth2",
    "oauth2_security_scheme": "oauth2",
    "openIdConnectSecurityScheme": "openIdConnect",
    "open_id_connect_security_scheme": "openIdConnect",
    "mtlsSecurityScheme": "mutualTLS",
    "mtls_security_scheme": "mutualTLS",
}
# Legacy scheme and client method names that declare no authentication.
_ANONYMOUS = frozenset({"none", "noauth", "no-auth", "anonymous", "public", "unauthenticated"})
_MAX_ENTRIES = 1000
_MAX_DEPTH = 8
_MAX_NAME = 256


class _BoundError(ValueError):
    """A card reached a collection bound; the failure names the bound, not a field type."""


TOO_DEEP = "A2A card nests too deeply"
TOO_MANY_ENTRIES = "A2A card has too many entries"
# OAuth scopes are short public identifiers; a longer value is withheld unmatched,
# which also keeps the token-shape search linear.
_MAX_SCOPE = 512
_MAX_PROTECTED_HEADER = 8192
_CARD_PATHS = _ORIGIN_PATHS | {"/.well-known/agent.json", "/.well-known/agent-card.json"}
# Credential formats that redact_text leaves intact; no OAuth scope takes these forms.
# Both alternatives start only where a word starts, so a long run is scanned once.
_TOKEN_SHAPE = re.compile(
    r"(?<![\w-])(?:eyJ[\w-]{8,}\.[\w-]{8,}"
    r"|(?:gh[oprsu]_|github_pat_|glpat-|xox[abeoprs]-|sk-|[rs]k_live_|AKIA|ASIA|AIza)"
    r"[\w-]{12,})"
)
_JWS_ALGORITHM = re.compile(r"[A-Za-z0-9+._-]{1,32}")
_KEY_ID = re.compile(r"[\w.:#+=/-]{1,256}")
_SERVER_CALLS = frozenset(
    {"AgentCard", "A2AStarletteApplication", "A2AFastAPIApplication", "A2ARESTFastAPIApplication"}
)
_CLIENT_CALLS = frozenset({"A2AClient", "A2ACardResolver", "ClientFactory"})
# Pydantic class methods that build an AgentCard: the loaders read a mapping or JSON, and
# the constructors take fields as the class does.
_CARD_LOADERS = frozenset(
    {"model_validate", "model_validate_json", "model_validate_strings", "parse_obj", "parse_raw"}
)
_CARD_CONSTRUCTORS = frozenset({"model_construct", "construct"})
_MAX_PYTHON_CHARACTERS = 262_144
# No character of an encoding the search follows takes more than four bytes, so a longer
# source holds more characters than are parsed.
_HEAD_BYTES = 4 * _MAX_PYTHON_CHARACTERS
_CHUNK_BYTES = 1024 * 1024
_FOLD_SLICE = 4096


class _CodeReferences(NamedTuple):
    server: list[str]
    client: list[str]
    built_cards: list[str]
    loaded_cards: list[str]
    unparsed_cards: list[str]
    unfollowed: list[str]


class _BudgetSpentError(Exception):
    """The source budget ran out during a read; the budget recorded the one gap."""


class _Hints:
    """The SDK hints one Python source names, in its bytes or in the text Python reads.

    Python compares identifiers in NFKC form, so text not in that form is also searched
    in NFKD form, which keeps every run of ASCII letters that NFKC gives. It is folded a
    slice at a time, so one character's expansion (up to 18 characters) stays within its
    slice. Each search keeps the end of the one before, so a hint split across reads is
    found.
    """

    def __init__(self, encoding: str) -> None:
        self.found: set[str] = set()
        self._tail = b""
        self._text_tail = ""
        self._decoder = codecs.getincrementaldecoder(encoding)("replace")

    def feed(self, chunk: bytes) -> None:
        window = self._tail + chunk
        self.found.update(hint for hint in _A2A_SOURCE_HINTS if hint.encode() in window)
        self._tail = window[-_HINT_OVERLAP:]
        text = self._decoder.decode(chunk)
        if text.isascii() or unicodedata.is_normalized("NFKC", text):
            self._search(text)
            return
        for start in range(0, len(text), _FOLD_SLICE):
            self._search(unicodedata.normalize("NFKD", text[start : start + _FOLD_SLICE]))

    def _search(self, text: str) -> None:
        window = self._text_tail + text
        self.found.update(hint for hint in _A2A_SOURCE_HINTS if hint in window)
        self._text_tail = window[-_HINT_OVERLAP:]


class _Source(NamedTuple):
    """One searched Python source: the whole of it when it fits the parsed window."""

    content: bytes | None
    # None when the search cannot follow the source's encoding declaration.
    encoding: str | None
    hints: frozenset[str]


def _encoding(head: bytes, *, complete: bool) -> str | None:
    """The encoding Python decodes a source with, or None when the search cannot follow it.

    Source that Python cannot decode is searched as the UTF-8 that Python expected.
    """
    try:
        encoding, _ = _source_encoding(head, complete=complete, skipped=None)
    except _UnreadableError as exc:
        return "utf-8" if str(exc) == _INVALID_UTF8 else None
    return encoding


def _chunks(stream: BinaryIO, budget: SourceBudget, path: Path) -> Iterator[bytes]:
    while chunk := stream.read(_CHUNK_BYTES):
        if not budget.admit(len(chunk), path):
            raise _BudgetSpentError
        yield chunk


def _search(files: ConfinedCollection, target: Path, path: Path, budget: SourceBudget) -> _Source:
    """Read ``target``, the file ``path`` names, in chunks and note each hint it names.

    Every chunk is charged to the source budget. A file larger than the whole budget is
    refused alone before it is read, so it does not spend the budget. Its head is read
    first, because its encoding declaration decides how all of it is searched.
    """
    with files.open_regular(target, max_bytes=budget.bound) as stream:
        reads = _chunks(stream, budget, path)
        kept: list[bytes] = []
        size = 0
        for chunk in reads:
            kept.append(chunk)
            size += len(chunk)
            if size > _HEAD_BYTES:
                break
        head = b"".join(kept)
        complete = size <= _HEAD_BYTES
        encoding = _encoding(head, complete=complete)
        if encoding is None:
            return _Source(None, None, frozenset())
        hints = _Hints(encoding)
        for start in range(0, size, _CHUNK_BYTES):
            hints.feed(head[start : start + _CHUNK_BYTES])
        for chunk in reads:
            hints.feed(chunk)
    return _Source(head if complete else None, encoding, frozenset(hints.found))


def _parsed(source: _Source) -> ast.Module | None:
    """The syntax tree of a source within the parsed window, or None."""
    if source.content is None or source.encoding is None:
        return None
    try:
        text = source.content.decode(source.encoding)
        if len(text) > _MAX_PYTHON_CHARACTERS:
            return None
        return parse_python(text)
    except (SyntaxError, ValueError):
        return None


class _Security(NamedTuple):
    required: bool
    skills_required: bool
    scopes: list[str]
    scheme_types: list[str]
    scheme_urls: list[str]
    structure: dict[str, Any]
    unbound: list[str]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("invalid string-list declaration")
    if len(value) > _MAX_ENTRIES:
        raise _BoundError(TOO_MANY_ENTRIES)
    if not all(isinstance(item, str) for item in value):
        raise ValueError("invalid string-list declaration")
    return value


def _strings(value: Any) -> list[str]:
    return [redact_text(item) for item in _string_list(value)]


def _fields(declaration: dict[str, Any]) -> list[str]:
    if len(declaration) > _MAX_ENTRIES:
        raise _BoundError(TOO_MANY_ENTRIES)
    return sorted(redact_text(key) for key in declaration)


def _scope(value: str) -> str:
    """Export a scope, a public identifier (RFC 6749 section 3.3), unless it may be a secret."""
    if len(value) > _MAX_SCOPE or _TOKEN_SHAPE.search(value):
        return REDACTED
    redacted = redact_text(value)
    if redacted == value:
        return value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return redacted
    # Scope URIs such as https://www.googleapis.com/auth/drive.readonly name the
    # permission in their path, which redact_text would cut down to the origin.
    locator = parsed.netloc + parsed.path
    if (
        parsed.scheme
        and parsed.netloc
        and not any(char in "@?#" or char.isspace() for char in value)
        and redact_text(locator) == locator
    ):
        return value
    return redacted


def _declared_urls(value: Any, depth: int = 0) -> list[str]:
    """Collect URL fields, such as tokenUrl, wherever a declaration nests them."""
    if depth > _MAX_DEPTH:
        raise _BoundError(TOO_DEEP)
    if isinstance(value, list):
        if len(value) > _MAX_ENTRIES:
            raise _BoundError(TOO_MANY_ENTRIES)
        urls = [url for item in value for url in _declared_urls(item, depth + 1)]
    elif isinstance(value, dict):
        if len(value) > _MAX_ENTRIES:
            raise _BoundError(TOO_MANY_ENTRIES)
        urls = []
        for key, item in value.items():
            if isinstance(item, str) and key.lower().endswith(("url", "uri")):
                urls.append(item)
            elif key != "scopes":
                urls.extend(_declared_urls(item, depth + 1))
    else:
        return []
    if len(urls) > _MAX_ENTRIES:
        raise _BoundError(TOO_MANY_ENTRIES)
    return urls


def _member(declaration: dict[str, Any], name: str, proto_name: str) -> Any:
    if name in declaration and proto_name in declaration:
        raise ValueError(f"duplicate {name} field")
    return declaration.get(name, declaration.get(proto_name))


def _unwrap(message: Any, field: str, default: Any) -> Any:
    """Read the only field of an A2A 1.0 SecurityRequirement or StringList message."""
    if not isinstance(message, dict) or set(message) - {field}:
        raise ValueError(f"invalid {field} message")
    value = message.get(field)
    return default if value is None else value


def _scheme_type(scheme: Any) -> tuple[str, bool]:
    """Map a 0.3 type or a 1.0 oneof member onto SECURITY_SCHEME_TYPES, and say if one is stated."""
    if not isinstance(scheme, dict):
        raise ValueError("invalid security scheme")
    declared = scheme.get("type")
    declared = "" if declared is None else declared
    if not isinstance(declared, str):
        raise ValueError("invalid security scheme type")
    kind = _SCHEME_TYPE_NAMES.get(declared.strip().lower(), "other")
    members = [
        (_WRAPPED_SCHEME_TYPES[key], body)
        for key, body in scheme.items()
        if key in _WRAPPED_SCHEME_TYPES and body is not None
    ]
    if len(members) > 1 or any(not isinstance(body, dict) for _, body in members):
        raise ValueError("invalid security scheme")
    if not members:
        return kind, bool(declared.strip())
    if declared.strip() and kind != members[0][0]:
        raise ValueError("conflicting security scheme types")
    return members[0][0], True


def _alternatives(requirements: Any, wrapped: bool) -> list[dict[str, list[str]]]:
    """Read 0.3 `security` or 1.0 `securityRequirements` alternatives as scheme-to-values maps."""
    if not isinstance(requirements, list) or len(requirements) > _MAX_ENTRIES:
        raise ValueError("invalid security requirements")
    alternatives, entries = [], 0
    for requirement in requirements:
        if wrapped:
            requirement = _unwrap(requirement, "schemes", {})
        if not isinstance(requirement, dict):
            raise ValueError("invalid security requirement")
        alternative = {}
        for scheme_name, required in requirement.items():
            if wrapped:
                required = _unwrap(required, "list", [])
            entries += 1 + (len(required) if isinstance(required, list) else 0)
            if not isinstance(required, list) or entries > _MAX_ENTRIES:
                raise ValueError("invalid or oversized security requirement")
            alternative[scheme_name] = _string_list(required)
        alternatives.append(alternative)
    return alternatives


def _requirement_forms(declaration: dict[str, Any]) -> tuple[tuple[str, Any], ...]:
    """Cards and skills both take 0.3 `security` and 1.0 `securityRequirements` lists."""
    return (
        ("security", declaration.get("security")),
        (
            "security_requirements",
            _member(declaration, "securityRequirements", "security_requirements"),
        ),
    )


def _declares_current_security(data: dict[str, Any]) -> bool:
    return any(
        data.get(name) is not None
        for name in (
            "securitySchemes",
            "security_schemes",
            "securityRequirements",
            "security_requirements",
            "supportedInterfaces",
            "supported_interfaces",
        )
    )


def _requires_authentication(alternatives: list[dict[str, list[str]]], typed: set[str]) -> bool:
    # An empty alternative ({}) permits anonymous access, as in OpenAPI.
    return all(alternative and set(alternative) <= typed for alternative in alternatives)


def _scheme_label(name: str, seen: dict[str, str]) -> str:
    label = redact_text(name)
    if label in seen and seen[label] != name:
        # Hashing original names would expose guesses of withheld credentials;
        # keeping only projected names would erase scheme-to-value associations.
        raise _BindingError(
            "security scheme names collide after redaction; "
            "use distinct non-secret scheme identifiers"
        )
    seen[label] = name
    return label


def _digested(
    alternatives: list[dict[str, list[str]]], kinds: dict[str, str], names: dict[str, str]
) -> tuple[list[dict[str, list[str]]], set[str], bool]:
    """Return the digested alternatives, the exported scopes and whether one was redacted."""
    digested: list[dict[str, list[str]]] = []
    scopes: set[str] = set()
    redacted = False
    for alternative in alternatives:
        values: dict[str, list[str]] = {}
        for scheme_name, named in alternative.items():
            label = _scheme_label(scheme_name, names)
            if kinds.get(scheme_name) in SCOPED_SCHEME_TYPES:
                exported = {scope: _scope(scope) for scope in named}
                redacted |= any(scope != kept for scope, kept in exported.items())
                values[label] = sorted(set(exported.values()))
                scopes.update(exported.values())
            else:
                # Role names may be anything, even a pasted credential, so they stay
                # out of the export; only the digest covers them.
                values[label] = sorted(set(named))
        digested.append(values)
    return sorted(digested, key=canonical_json), scopes, redacted


def _supported_interfaces(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Read A2A 1.0 AgentInterface entries, which list endpoints with the preferred first."""
    entries = _member(data, "supportedInterfaces", "supported_interfaces")
    entries = [] if entries is None else entries
    if not isinstance(entries, list) or len(entries) > _MAX_ENTRIES:
        raise ValueError("invalid supported interfaces")
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("url"), str)
            or not entry["url"].strip()
            or not isinstance(entry.get("tenant"), str | None)
        ):
            raise ValueError("invalid supported interface")
    return entries


def _security(data: dict[str, Any], skills: list[tuple[str, dict[str, Any]]]) -> _Security:
    """Read declared requirements; a card cannot show that an endpoint enforces them."""
    schemes = _member(data, "securitySchemes", "security_schemes")
    schemes = {} if schemes is None else schemes
    if not isinstance(schemes, dict) or len(schemes) > _MAX_ENTRIES:
        raise ValueError("invalid security schemes")
    kinds: dict[str, str] = {}
    typed: set[str] = set()
    names: dict[str, str] = {}
    for scheme_name, scheme in schemes.items():
        _scheme_label(scheme_name, names)
        kinds[scheme_name], stated = _scheme_type(scheme)
        # A type such as "none" or an unknown extension shows no authentication.
        if stated and kinds[scheme_name] != "other":
            typed.add(scheme_name)
    scheme_urls = _declared_urls(schemes)
    decisions: list[bool] = []
    scopes: set[str] = set()
    redacted_scopes = False
    forms: dict[str, list[dict[str, list[str]]] | None] = {}
    for form, requirements in _requirement_forms(data):
        if requirements is None:
            forms[form] = None
            continue
        alternatives = _alternatives(requirements, wrapped=form == "security_requirements")
        forms[form], named_scopes, redacted = _digested(alternatives, kinds, names)
        scopes |= named_scopes
        redacted_scopes |= redacted
        decisions.append(bool(alternatives) and _requires_authentication(alternatives, typed))
    skill_security: list[list[Any]] = []
    skills_required, entries = True, 0
    for label, skill in skills:
        declared: dict[str, list[dict[str, list[str]]]] = {}
        for form, requirements in _requirement_forms(skill):
            if requirements is None:
                continue
            alternatives = _alternatives(requirements, wrapped=form == "security_requirements")
            entries += sum(1 + len(alt) + sum(map(len, alt.values())) for alt in alternatives)
            if entries > _MAX_ENTRIES:
                raise ValueError("oversized skill security requirements")
            declared[form], named_scopes, redacted = _digested(alternatives, kinds, names)
            scopes |= named_scopes
            redacted_scopes |= redacted
            # The specifications leave open how a skill's requirements combine with the
            # card's, so they can lower authentication_required but never raise it. An
            # empty list adds none: proto3 JSON does not tell it from an absent field.
            skills_required &= _requires_authentication(alternatives, typed)
        if declared:
            skill_security.append([label, declared])
    legacy = data.get("authentication")
    legacy_count = None
    if legacy is not None:
        if not isinstance(legacy, dict):
            raise ValueError("invalid authentication declaration")
        named_schemes = legacy.get("schemes")
        named_schemes = [] if named_schemes is None else named_schemes
        if not isinstance(named_schemes, list):
            raise ValueError("invalid authentication schemes")
        legacy_count = sum(
            1
            for scheme in _string_list(named_schemes)
            if scheme.strip() and scheme.strip().lower() not in _ANONYMOUS
        )
        # Clients of cards that use the 0.3 or 1.0 security declarations do not read
        # the earlier authentication object, so it cannot decide for such a card.
        if not _declares_current_security(data):
            decisions.append(legacy_count > 0)
    structure = {
        "security_schemes": sorted([redact_text(name), kind] for name, kind in kinds.items()),
        "security_scheme_urls": _url_shapes(scheme_urls),
        **forms,
        "skill_security": sorted(skill_security, key=canonical_json),
        "authentication_schemes": legacy_count,
    }
    unbound = [
        label
        for label, gap in (
            (
                "security scheme URLs beyond their exported origins",
                any(_beyond_origin(url, _ORIGIN_PATHS) for url in scheme_urls),
            ),
            ("redacted OAuth scopes", redacted_scopes),
        )
        if gap
    ]
    return _Security(
        required=bool(decisions) and all(decisions),
        skills_required=skills_required,
        scopes=sorted(scopes),
        scheme_types=sorted(set(kinds.values())),
        scheme_urls=scheme_urls,
        structure=structure,
        unbound=unbound,
    )


def _bounded_name(value: str) -> str:
    if len(value) > _MAX_NAME:
        raise ValueError("name exceeds the supported length")
    return redact_text(value)


def _signatures(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Read each card signature's protected JWS header; nothing is verified."""
    declared = data.get("signatures")
    if declared is None:
        return []
    if not isinstance(declared, list) or len(declared) > _MAX_ENTRIES:
        raise ValueError("invalid signatures")
    records = []
    for entry in declared:
        if not isinstance(entry, dict):
            raise ValueError("invalid signature")
        header: Any = None
        protected = entry.get("protected")
        if isinstance(protected, str) and len(protected) <= _MAX_PROTECTED_HEADER:
            try:
                raw = base64.urlsafe_b64decode(protected + "=" * (-len(protected) % 4))
                header = json.loads(raw.decode("utf-8"))
            except (ValueError, RecursionError):
                header = None
        if not isinstance(header, dict):
            records.append({"alg": None, "kid": None, "header": "unreadable"})
            continue
        alg, kid = header.get("alg"), header.get("kid")
        records.append(
            {
                "alg": alg
                if isinstance(alg, str) and _JWS_ALGORITHM.fullmatch(alg) and not _secret(alg)
                else (None if alg is None else "[redacted]"),
                "kid": _key_id(kid),
                "header": "read",
            }
        )
    return sorted(records, key=canonical_json)


def _key_id(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return "[redacted]"
    if "://" in value:
        return _origin(value)
    return value if _KEY_ID.fullmatch(value) and not _secret(value) else "[redacted]"


def _secret(value: str) -> bool:
    """Whether a short header value takes the form of a credential pasted in by mistake."""
    return bool(_TOKEN_SHAPE.search(value)) or redact_text(value) != value


def _capabilities(data: dict[str, Any]) -> tuple[dict[str, bool], list[dict[str, Any]], list[str]]:
    """Return boolean capability flags, extensions and their URIs, without descriptions."""
    flags: dict[str, bool] = {}
    for name in ("supportsAuthenticatedExtendedCard", "supports_authenticated_extended_card"):
        if isinstance(data.get(name), bool):
            flags[name] = data[name]
    declared = data.get("capabilities")
    if declared is None:
        return flags, [], []
    if not isinstance(declared, dict) or len(declared) > _MAX_ENTRIES:
        raise ValueError("invalid capabilities")
    for key, value in declared.items():
        if isinstance(value, bool):
            flags[redact_text(key)] = value
    extensions = declared.get("extensions")
    extensions = [] if extensions is None else extensions
    if not isinstance(extensions, list) or len(extensions) > _MAX_ENTRIES:
        raise ValueError("invalid extensions")
    records, uris = [], []
    for extension in extensions:
        if not isinstance(extension, dict):
            raise ValueError("invalid extension")
        uri, required = extension.get("uri"), extension.get("required")
        if (uri is not None and not isinstance(uri, str)) or (
            required is not None and not isinstance(required, bool)
        ):
            raise ValueError("invalid extension")
        if uri is not None:
            uris.append(uri)
        records.append(
            {
                "origin": _origin(uri) if uri else None,
                "required": bool(required),
                "uri": _url_shape(uri, _ORIGIN_PATHS),
            }
        )
    return flags, sorted(records, key=canonical_json), uris


def _provider_url(data: dict[str, Any]) -> str | None:
    provider = data.get("provider")
    if provider is None:
        return None
    if not isinstance(provider, dict):
        raise ValueError("invalid provider")
    url = provider.get("url")
    if url is not None and not isinstance(url, str):
        raise ValueError("invalid provider")
    return url


def _client_methods(declared: Any) -> list[str]:
    # The dict form names methods by key and enables each one by its value.
    if isinstance(declared, dict):
        declared = [
            key for key, value in declared.items() if value not in (False, None, "", [], {})
        ]
    return _strings(declared)


def _same_declaration(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Whether two cards hold the same JSON values of the same types, whatever the key
    order; unlike ``==``, ``true`` and ``1`` differ."""
    try:
        return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)
    except RecursionError:
        return False


def _card_location(path: Path) -> tuple[str, bool] | None:
    """The supported card path a walked file spells, and whether it spells it exactly."""
    parts = path.parts
    folded = [fold_name(part) for part in parts]
    if len(parts) >= 2 and folded[-2] == ".well-known" and folded[-1] in AGENT_CARD_NAMES:
        canonical = (*parts[:-2], ".well-known", folded[-1])
    elif "/".join(folded) in _GENERIC_CARD_PATHS:
        canonical = tuple(folded)
    else:
        return None
    return "/".join(canonical), tuple(parts) == canonical


def _card_preference(path: str) -> tuple[bool, int, bool, str]:
    # Well-known locations first, shallower before deeper, then the 0.3 name
    # (agent-card.json) before the earlier agent.json.
    parts = path.split("/")
    return (parts[-2:-1] != [".well-known"], len(parts), not path.endswith("card.json"), path)


def _calls(tree: ast.Module) -> tuple[set[str], bool, bool]:
    """Names of called SDK constructors, and whether AgentCard is built from literals."""
    card_names = {"AgentCard"}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module is not None
            and node.module.split(".")[0] == "a2a"
        ):
            card_names.update(
                alias.asname or alias.name for alias in node.names if alias.name == "AgentCard"
            )
    called: set[str] = set()
    literal_card = mapping_card = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        loaded = False
        if isinstance(func, ast.Name):
            name = "AgentCard" if func.id in card_names else func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
            owner = func.value
            if (
                (isinstance(owner, ast.Name) and owner.id in card_names)
                or (isinstance(owner, ast.Attribute) and owner.attr == "AgentCard")
            ) and name in _CARD_LOADERS | _CARD_CONSTRUCTORS:
                name, loaded = "AgentCard", name in _CARD_LOADERS
        else:
            continue
        called.add(name)
        if name == "AgentCard":
            if not loaded and (
                node.args or any(keyword.arg is not None for keyword in node.keywords)
            ):
                literal_card = True
            else:
                mapping_card = True
    return called, literal_card, mapping_card


def _module_roles(tree: ast.Module) -> tuple[bool, bool, bool]:
    """Whether the source imports the a2a SDK, and its server or client packages."""
    imported = server = client = False
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            modules = [node.module]
        elif isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        for module in modules:
            parts = module.split(".")
            if parts[0] != "a2a":
                continue
            imported = True
            server |= parts[1:2] == ["server"]
            client |= parts[1:2] == ["client"]
    return imported, server, client


class A2AScanner(Scanner):
    name = "a2a"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            cards: list[str] = []
            sources: list[Path] = []
            links: list[Path] = []
            for path in files.iter_files(directory_links=links):
                location = _card_location(path)
                if location is None:
                    if path.suffix == ".py" and not _SOURCE_EXCLUDED_DIRS.intersection(path.parts):
                        sources.append(path)
                    continue
                self._found_card(path, location, cards, files, result)
            # The walk covers a linked directory under its target's name, where card
            # names are not recognised, so they are looked up through the link.
            for link in links:
                for name in AGENT_CARD_NAMES:
                    path = link / name
                    location = _card_location(path)
                    if location is None:
                        continue
                    if files.regular_file(path) is None:
                        # Records a refused link, or another spelling below the link.
                        files.read_bytes(path, missing_ok=True)
                    else:
                        self._found_card(path, location, cards, files, result)
            parsed: list[tuple[str, dict[str, Any]]] = []
            for relative in sorted(cards, key=_card_preference):
                if relative in _GENERIC_CARD_PATHS:
                    # Another tool's file may use a generic name; without an object that
                    # carries an A2A field it is not a card, and not a failure.
                    data = files.read_json(relative)
                    if self._relinked(relative, files, result):
                        continue
                    if not isinstance(data, dict) or not _CARD_MARKERS & set(data):
                        continue
                else:
                    data = self._read_mapping(Path(relative), result)
                    if data is None:
                        continue
                result.surfaces_scanned.append(relative)
                parsed.append((relative, data))
            self._record_cards(parsed, result)
            for relative in A2A_CONFIG_FILES:
                data = self._read_mapping(Path(relative), result)
                if data is None:
                    continue
                result.surfaces_scanned.append(relative)
                self._record_clients(relative, data, result)
            # A record read through an in-root symlink also names the file that held it.
            for component in result.components:
                target = files.link_target(component.source_path or "")
                if target is not None:
                    component.properties["symlink_target"] = target
            self._scan_code_patterns(files, sources, result)
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("a2a (no A2A configurations found)")
        return result

    def _read_mapping(
        self, path: Path, result: ScanResult, *, missing_ok: bool = True
    ) -> dict[str, Any] | None:
        """A card or client configuration; a credential-named file is a gap and is not read."""
        files = self._files
        if files is None:
            raise RuntimeError("_read_mapping called outside a _collection context")
        relative = path.as_posix()
        known_well_known = len(path.parts) >= 2 and path.parts[-2].casefold() == ".well-known"
        if withheld(
            files, relative, result.surfaces_excluded, allow_service_parent=known_well_known
        ):
            return None
        data = super()._read_mapping(path, result, missing_ok=missing_ok)
        return None if self._relinked(relative, files, result) else data

    @staticmethod
    def _relinked(relative: str, files: ConfinedCollection, result: ScanResult) -> bool:
        if not relinked(files, relative):
            return False
        result.scan_failures.append(f"{relative}: file changed during collection")
        return True

    def _found_card(
        self,
        path: Path,
        location: tuple[str, bool],
        cards: list[str],
        files: ConfinedCollection,
        result: ScanResult,
    ) -> None:
        """Queue a card path; one named as holding credentials, by its own name or that of
        the in-root file a symlink there leads to, such as ``agent.json ->
        credentials.json``, is a gap and is not read."""
        known_well_known = len(path.parts) >= 2 and path.parts[-2].casefold() == ".well-known"
        if withheld(
            files,
            path.as_posix(),
            result.surfaces_excluded,
            allow_service_parent=known_well_known,
        ):
            return
        canonical, exact = location
        if exact:
            cards.append(canonical)
        elif self._is_card(path, canonical, files, result):
            result.scan_failures.append(
                f"{path.as_posix()}: case variant of {canonical} is the active "
                "file on case-insensitive file systems and is not inventoried"
            )

    @classmethod
    def _is_card(
        cls, path: Path, canonical: str, files: ConfinedCollection, result: ScanResult
    ) -> bool:
        if canonical not in _GENERIC_CARD_PATHS:
            return True
        # A generic name is a card only with an A2A field; a read failure is recorded.
        data = files.read_json(path)
        if cls._relinked(path.as_posix(), files, result):
            return False
        return data is None or (isinstance(data, dict) and bool(_CARD_MARKERS & set(data)))

    def _record_cards(self, parsed: list[tuple[str, dict[str, Any]]], result: ScanResult) -> None:
        """One record per card; equal declarations at several paths are merged."""
        recorded: dict[str, tuple[dict[str, Any], A2AServerComponent]] = {}
        for relative, data in parsed:
            try:
                component = self._parse_agent_card(data, relative, relative)
            except (_BindingError, _BoundError) as exc:
                result.scan_failures.append(f"{relative}: {exc}")
                continue
            except (TypeError, ValueError, RecursionError):
                result.scan_failures.append(f"{relative}: invalid A2A card field types")
                continue
            previous = recorded.get(component.bom_ref)
            if previous is None:
                recorded[component.bom_ref] = (data, component)
                result.components.append(component)
            elif _same_declaration(previous[0], data):
                paths = previous[1].properties["agent_card_paths"]
                paths.append(relative)
                paths.sort()
            else:
                result.scan_failures.append(
                    f"{relative}: declares the same agent as "
                    f"{previous[1].agent_card_path} with different content"
                )

    def _record_clients(self, relative: str, data: dict[str, Any], result: ScanResult) -> None:
        declared = [data[key] for key in ("clients", "remoteAgents") if data.get(key) is not None]
        if data and not declared and not {"clients", "remoteAgents"} & set(data):
            result.surfaces_excluded.append(
                f"{relative}: unrecognised A2A client configuration shape is not inventoried"
            )
            return
        if not all(isinstance(value, list) for value in declared) or (
            sum(len(value) for value in declared) > _MAX_ENTRIES
        ):
            result.scan_failures.append(f"{relative}: invalid or oversized A2A client list")
            return
        for client in (entry for value in declared for entry in value):
            try:
                if not isinstance(client, dict):
                    raise ValueError("invalid client")
                result.components.append(self._parse_a2a_client(client, relative))
            except (_BindingError, _BoundError) as exc:
                result.scan_failures.append(f"{relative}: {exc}")
            except (TypeError, ValueError, RecursionError):
                result.scan_failures.append(f"{relative}: invalid A2A client field types")

    def _parse_agent_card(
        self, data: dict[str, Any], rel_path: str, card_path: str
    ) -> A2AServerComponent:
        declared_name, version = data.get("name"), data.get("version")
        declared = [data[key] for key in ("url", "endpoint") if data.get(key) is not None]
        if (
            (declared_name is not None and not isinstance(declared_name, str))
            or (version is not None and not isinstance(version, str))
            or not all(isinstance(url, str) for url in declared)
        ):
            raise ValueError("invalid card identity")
        # Both endpoint spellings are checked, so neither can hide behind the other.
        named: list[str] = [_whatwg_form(url) for url in declared if url]
        endpoint: str | None = named[0] if named else None
        aliases = named[1:]
        name = _bounded_name(declared_name) if declared_name is not None else "unnamed-agent"
        # An unnamed card is identified by its location, so two of them do not collide.
        bom_ref = (
            f"a2a-server:{reference_text(name)}"
            if declared_name is not None
            else f"a2a-server:{rel_path}"
        )
        shown = neutralize(name)
        protocols = _strings(data.get("protocols", []))
        declared_skills = data.get("skills", [])
        if not isinstance(declared_skills, list) or len(declared_skills) > _MAX_ENTRIES:
            raise ValueError("invalid skills")
        skills, skill_declarations = [], []
        for skill in declared_skills:
            label = (
                skill.get("name", skill.get("id", "unknown")) if isinstance(skill, dict) else skill
            )
            if not isinstance(label, str):
                raise ValueError("invalid skill name")
            skills.append(_bounded_name(label))
            if isinstance(skill, dict):
                skill_declarations.append((skills[-1], skill))
        # This records declarations only; neither a card nor this collector proves
        # that an endpoint actually enforces authentication.
        security = _security(data, skill_declarations)
        # Clients may send credentials to these alternative endpoints too.
        interface_urls = [
            _whatwg_form(url) for url in _declared_urls(data.get("additionalInterfaces"))
        ]
        supported = _supported_interfaces(data)
        supported_urls: list[str] = [_whatwg_form(entry["url"]) for entry in supported]
        endpoint = endpoint or (supported_urls[0] if supported_urls else None)
        signatures = _signatures(data)
        flags, extensions, extension_uris = _capabilities(data)
        provider_url = _provider_url(data)
        structure_hash = hash_canonical(
            {
                "profile": CARD_STRUCTURE_PROFILE,
                "structure": {
                    "fields": _fields(data),
                    "endpoint": _url_shape(endpoint, _ORIGIN_PATHS),
                    **(
                        {"endpoint_aliases": [_url_shape(url, _ORIGIN_PATHS) for url in aliases]}
                        if aliases
                        else {}
                    ),
                    "additional_interfaces": _url_shapes(interface_urls),
                    "supported_interfaces": [
                        _url_shape(url, _ORIGIN_PATHS) for url in supported_urls
                    ],
                    "signatures": signatures,
                    "capabilities": dict(sorted(flags.items())),
                    "extensions": extensions,
                    "provider_url": _url_shape(provider_url, _ORIGIN_PATHS),
                    **security.structure,
                },
            }
        )
        binding = _value_binding(CARD_VALUE_BINDING_PROFILE, data)
        unbound = [
            label
            for label, gap in (
                (
                    "endpoint URL beyond its exported origin",
                    any(
                        _beyond_origin(url, _ORIGIN_PATHS)
                        for url in (endpoint, *aliases)
                        if url is not None
                    ),
                ),
                (
                    "additional interface URLs beyond their exported origins",
                    any(_beyond_origin(url, _ORIGIN_PATHS) for url in interface_urls),
                ),
                (
                    "supported interface URLs beyond their exported origins",
                    any(_beyond_origin(url, _ORIGIN_PATHS) for url in supported_urls),
                ),
                # A tenant routes requests on the same origin, as a path does.
                ("supported interface tenants", any(entry.get("tenant") for entry in supported)),
                (
                    "extension URIs beyond their exported origins",
                    any(_beyond_origin(uri, _ORIGIN_PATHS) for uri in extension_uris),
                ),
            )
            if gap
        ] + security.unbound
        risks: list[RiskAssessment] = []
        # A2A 1.0 clients use the first supported interface even when `url` is
        # present, and may send credentials to any declared alternative interface.
        # An alternative counts only with an explicit non-HTTPS scheme: 1.0 gRPC
        # interfaces give host:port without one, which declares no cleartext.
        alternatives = (*supported_urls[1:], *interface_urls)
        if any(
            url and not url.lower().startswith("https://")
            for url in (endpoint, *aliases, *supported_urls[:1])
        ) or any(
            (url.startswith("//") or "://" in url) and not url.lower().startswith("https://")
            for url in alternatives
        ):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"A2A agent '{shown}' declares an endpoint without HTTPS.",
                    recommendation="Use authenticated HTTPS transport for agent endpoints.",
                )
            )
        gap = ""
        if not security.required:
            gap = "has no nonempty authentication requirement declared"
        elif not security.skills_required:
            gap = "has a skill without a nonempty authentication requirement declared"
        if gap:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="authentication",
                    detail=f"A2A agent '{shown}' {gap}.",
                    recommendation="Declare and independently verify endpoint authentication requirements.",
                )
            )
        if not skills:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"A2A agent '{shown}' declares no skills in its agent card.",
                    recommendation="Document declared skills and separately verify effective capabilities.",
                )
            )
        if unbound and not binding:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"A2A agent '{shown}' values not bound in this inventory: {'; '.join(unbound)}.",
                    recommendation=f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to these values.",
                )
            )
        return A2AServerComponent(
            bom_ref=bom_ref,
            name=name,
            version=redact_text(version) if version else None,
            agent_card_path=rel_path,
            endpoint_url=_origin(endpoint) if endpoint else None,
            supported_protocols=protocols,
            skills_declared=skills,
            authentication_required=security.required and security.skills_required,
            capabilities=(
                CapabilityDeclaration(oauth_scopes=security.scopes) if security.scopes else None
            ),
            source_path=card_path,
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
            properties={
                "collection_mode": "static-agent-card",
                "agent_card_paths": [rel_path],
                "authentication_evidence": "declaration-only",
                "security_scheme_types": security.scheme_types,
                "security_scheme_origins": sorted({_origin(url) for url in security.scheme_urls}),
                "additional_interface_origins": sorted({_origin(url) for url in interface_urls}),
                "supported_interface_origins": [_origin(url) for url in supported_urls],
                "card_signatures": signatures,
                "card_signature_verified": "not-checked",
                "capability_flags": dict(sorted(flags.items())),
                "extensions": [
                    {"origin": record["origin"], "required": record["required"]}
                    for record in extensions
                ],
                "provider_origin": _origin(provider_url) if provider_url else None,
                **({"endpoint_origins": [_origin(url) for url in aliases]} if aliases else {}),
                "source_values_bound": bool(binding),
                "static_card_hash": structure_hash,
                "static_card_hash_profile": CARD_STRUCTURE_PROFILE,
                **binding,
            },
        )

    def _parse_a2a_client(self, config: dict[str, Any], config_path: str) -> A2AClientComponent:
        name = config.get("name", config.get("agentName", "unnamed-client"))
        urls = [
            config[key]
            for key in ("agentCardUrl", "url", "endpoint")
            if config.get(key) is not None
        ]
        auth_methods = _client_methods(config.get("authMethods", config.get("authentication", [])))
        if not isinstance(name, str) or not all(isinstance(url, str) for url in urls):
            raise ValueError("invalid client identity")
        card_url = urls[0] if urls else None
        name = _bounded_name(name)
        shown = neutralize(name)
        structure_hash = hash_canonical(
            {
                "profile": CLIENT_STRUCTURE_PROFILE,
                "structure": {
                    "fields": _fields(config),
                    "card_url": _url_shape(card_url, _CARD_PATHS),
                },
            }
        )
        binding = _value_binding(CLIENT_VALUE_BINDING_PROFILE, config)
        path_bound = bool(binding) or not any(_beyond_origin(url, _CARD_PATHS) for url in urls)
        risks = []
        if any(url and not url.lower().startswith("https://") for url in urls):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"A2A client '{shown}' declares an insecure endpoint transport.",
                    recommendation="Use authenticated HTTPS for agent card retrieval.",
                )
            )
        if not any(method.strip().lower() not in _ANONYMOUS for method in auth_methods):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="authentication",
                    detail=f"A2A client '{shown}' has no authentication method declared.",
                    recommendation="Configure and independently verify remote-agent authentication.",
                )
            )
        if not path_bound:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=(
                        f"A2A client '{shown}' {UNBOUND_VALUES_DETAIL}: "
                        "agent card URL beyond its exported origin."
                    ),
                    recommendation=f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect same-origin card changes.",
                )
            )
        properties: dict[str, Any] = {
            "collection_mode": "static-config",
            "remote_agent_contacted": False,
            "source_values_bound": bool(binding),
            "static_config_hash": structure_hash,
            "static_config_hash_profile": CLIENT_STRUCTURE_PROFILE,
            **binding,
        }
        if len(urls) > 1:
            properties["endpoint_origins"] = [_origin(url) for url in urls[1:]]
        return A2AClientComponent(
            bom_ref=f"a2a-client:{reference_text(name)}",
            name=name,
            agent_card_url=_origin(card_url) if card_url else None,
            authentication_methods=auth_methods,
            source_path=config_path,
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties=properties,
        )

    def _code_references(
        self, root: Path, sources: list[Path], result: ScanResult
    ) -> _CodeReferences:
        """Find SDK use in Python source, searched in the text Python reads.

        Each file is searched as a stream, root files first, and the source budget
        bounds the text read: running out of it is one named coverage gap, and nothing
        after it is read. A file the reader refuses, such as one larger than the whole
        budget, is a failure that names it. Only a file that builds an agent card, one
        that names AgentCard and cannot be parsed, or one whose encoding declaration
        cannot be followed is a gap, so an ordinary repository's Python files never fail
        this collector.
        """
        references = _CodeReferences([], [], [], [], [], [])
        budget = SourceBudget("a2a code references", result)
        # Source is read apart from the collection, so it does not spend the bytes that
        # cards are read with; this limit leaves room for the whole budget. Every file
        # can fail, so failures past the listing bound are summarized by reason.
        limit = source_collection_bytes()
        with (
            ConfinedCollection(
                root,
                result.scan_failures,
                exclude_paths=self._exclude_paths,
                max_total_bytes=limit,
            ) as heuristic,
            heuristic.bounded_failures(),
        ):
            for path in sorted(sources, key=lambda path: len(path.parts) > 1):
                # None for a file gone since the walk, which recorded any refused link.
                target = heuristic.in_root_target(path)
                if target is None:
                    continue
                try:
                    source = _search(heuristic, target, path, budget)
                except _BudgetSpentError:
                    break
                except (OSError, CollectionError):
                    # The reader recorded why. Once its byte limit is spent, no later
                    # file can be read either.
                    if heuristic.bytes_exhausted:
                        break
                    continue
                self._classify(path.as_posix(), source, references)
        return references

    @staticmethod
    def _classify(relative: str, source: _Source, references: _CodeReferences) -> None:
        if source.encoding is None:
            references.unfollowed.append(relative)
            return
        if not source.hints:
            return
        tree = _parsed(source)
        if tree is None:
            if "AgentCard" in source.hints:
                references.unparsed_cards.append(relative)
            return
        imported, server, client = _module_roles(tree)
        called, literal_card, mapping_card = _calls(tree)
        if literal_card:
            references.built_cards.append(relative)
        elif mapping_card:
            references.loaded_cards.append(relative)
        if server or called & _SERVER_CALLS:
            references.server.append(relative)
        elif client or called & _CLIENT_CALLS or imported:
            references.client.append(relative)

    def _scan_code_patterns(
        self, files: ConfinedCollection, sources: list[Path], result: ScanResult
    ) -> None:
        references = self._code_references(files.root, sources, result)
        result.surfaces_scanned.append("a2a: Python SDK references (heuristic)")
        result.surfaces_excluded.extend(
            f"{path}: A2A agent card built in Python code is not inventoried"
            for path in references.built_cards
        )
        result.surfaces_excluded.extend(
            f"{path}: Python source that names AgentCard could not be parsed; "
            "an agent card it builds is not inventoried"
            for path in references.unparsed_cards
        )
        result.surfaces_excluded.extend(
            f"{path}: Python source encoding declaration could not be followed; "
            "an agent card it builds is not inventoried"
            for path in references.unfollowed
        )
        # Nothing ties a loaded card to a static one, so a static card does not cover it.
        result.surfaces_excluded.extend(
            f"{path}: A2A agent card loaded in Python code is not inventoried"
            for path in references.loaded_cards
        )
        if any(component.bom_ref.startswith("a2a-") for component in result.components):
            return
        for kind, paths in (("server", references.server), ("client", references.client)):
            if not paths:
                continue
            component_type = A2AServerComponent if kind == "server" else A2AClientComponent
            result.components.append(
                component_type(
                    bom_ref=f"a2a-{kind}:code-detected",
                    name=f"a2a-{kind} (code-detected)",
                    source_path=min(paths),
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                    properties={"collection_mode": "static-syntax-reference"},
                    risks=[
                        RiskAssessment(
                            severity=RiskSeverity.INFO,
                            category="detection_method",
                            detail=f"A2A SDK {kind} reference detected in Python syntax; deployment not verified.",
                            recommendation="Add explicit agent card or client configuration and deployment evidence.",
                        )
                    ],
                )
            )
