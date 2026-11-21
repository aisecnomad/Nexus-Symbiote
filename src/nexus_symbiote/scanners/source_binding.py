"""Structure digests and keyed value bindings shared by the static collectors.

Exports keep only URL origins, and paths or queries may carry credentials, so no
unkeyed digest covers them: it would let anyone holding the BOM confirm guesses.
Structure digests cover names, counts, flags, URL shapes and values exported in
clear. Other values are bound only by an HMAC under the operator key, which never
enters the BOM.
"""

from __future__ import annotations

import hmac
import os
import re
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.hashing import canonical_json
from nexus_symbiote.scanners.base import sanitized_origin
from nexus_symbiote.scanners.mcp import _MIN_SOURCE_BINDING_KEY_LENGTH, SOURCE_BINDING_KEY_ENV

ORIGIN_PATHS = frozenset({"", "/"})
_HOSTNAME = re.compile(r"[\w.-]+|[0-9a-f:.]+")
# A2A 1.0 gRPC interfaces give a "hostname:port" address without a scheme.
_HOST_PORT = re.compile(r"(?:(?:[\w-]+\.)+[\w-]+|localhost|\[[0-9a-f:.]+\]):\d{1,5}", re.I)
_SPECIAL_SCHEME = re.compile(r"(ftp|https?|wss?):(?!//)", re.I)
_URL_ASCII_WHITESPACE = str.maketrans("", "", "\t\r\n")


class BindingError(ValueError):
    """The operator binding key or a bound value cannot produce a binding."""


def value_binding(profile: str, declaration: dict[str, Any]) -> dict[str, str]:
    """HMAC a whole declaration under the operator key, or return nothing without one."""
    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if not key:
        return {}
    if len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise BindingError(
            f"{SOURCE_BINDING_KEY_ENV} must contain at least "
            f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
        )
    try:
        message = canonical_json({"profile": profile, "configuration": declaration})
    except ValueError as exc:
        raise BindingError(
            f"{SOURCE_BINDING_KEY_ENV} binding needs RFC 8785 JSON values (quote YAML "
            "dates; avoid lone surrogates and integers beyond 2**53)"
        ) from exc
    try:
        material = key.encode("utf-8")
    except UnicodeError:
        raise BindingError(f"{SOURCE_BINDING_KEY_ENV} must be valid UTF-8 text") from None
    key_id = hmac.new(material, b"nexus-symbiote/source-binding-key-id", "sha256").hexdigest()
    return {
        "static_value_binding": "hmac-sha256:"
        + hmac.new(material, message.encode(), "sha256").hexdigest(),
        "static_value_binding_key_id": key_id[:32],
        "static_value_binding_profile": profile,
    }


def odd_host(url: str) -> bool:
    """Whether urlsplit and WHATWG parsers may read different hosts from ``url``.

    WHATWG parsers end the authority at a backslash. urlsplit does not: it keeps
    "host\\path" in the host, and in "evil\\@good" it reads the host after the "@",
    so the exported host would be one the client never connects to.
    """
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
    except ValueError:
        return True
    if "\\" in parsed.netloc:
        return True
    return hostname is not None and not _HOSTNAME.fullmatch(hostname)


def whatwg_form(url: str) -> str:
    """``url`` with "//" before the authority of a special scheme, as WHATWG parsers read it.

    They skip any run of "/" and "\\" after ``http:``, so ``http:host/x`` and
    ``http:\\\\host`` connect to ``host`` in clear text, while urlsplit reads no host in
    them and the origin and transport checks would see none.
    """
    value = url.strip()
    match = _SPECIAL_SCHEME.match(value)
    if match is None:
        return url
    rest = value[match.end() :].translate(_URL_ASCII_WHITESPACE).lstrip("/\\")
    if not rest or rest.startswith(" "):
        return url
    return f"{match[1]}://{rest}"


def authority(url: str) -> str:
    return f"//{url}" if _HOST_PORT.fullmatch(url) else url


def origin(url: str) -> str:
    """Export scheme, host and port; a URL without a scheme keeps "//host:port"."""
    from nexus_symbiote.utils.secrets import TOKEN_SHAPE

    url = authority(url)
    if odd_host(url):
        return "[redacted]"
    if not url.startswith("//"):
        return sanitized_origin(url)
    try:
        parsed = urlsplit(url)
        raw_host = parsed.netloc.rpartition("@")[2]
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return "[redacted]"
    if not host or TOKEN_SHAPE.search(raw_host):
        return "[redacted]"
    host = f"[{host}]" if ":" in host else host
    return f"//{host}" + (f":{port}" if port is not None else "")


def url_shape(url: str | None, plain_paths: frozenset[str]) -> dict[str, Any] | None:
    """Describe what an origin-only export omits from a URL, without the values."""
    if url is None:
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return {"valid": False}
    return {
        "path_separators": parsed.path.count("/"),
        "plain_path": parsed.path if parsed.path in plain_paths else None,
        "query": bool(parsed.query),
        "fragment": bool(parsed.fragment),
        "userinfo": "@" in parsed.netloc,
    }


def url_shapes(urls: list[str]) -> list[dict[str, Any] | None]:
    return sorted((url_shape(url, ORIGIN_PATHS) for url in urls), key=canonical_json)


def beyond_origin(url: str, plain_paths: frozenset[str]) -> bool:
    """Whether the export leaves part of a URL unbound, all of it when no origin was kept."""
    if origin(url) == "[redacted]":
        return True
    parsed = urlsplit(authority(url))
    return (
        parsed.path not in plain_paths
        or bool(parsed.query or parsed.fragment)
        or "@" in parsed.netloc
    )
