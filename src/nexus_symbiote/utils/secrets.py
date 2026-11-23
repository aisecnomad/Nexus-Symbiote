"""Conservative redaction for collector output, never credential retrieval."""

from __future__ import annotations

import base64
import binascii
import bisect
import heapq
import re
import string
from collections.abc import Iterable, Iterator, Mapping
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

from nexus_symbiote.utils._legacy_redaction import (
    hidden_spans,
    origin_sources,
    redaction,
    shown_unchanged,
)

REDACTED = "***"
# What a known value reads as to the rules on the masked pass: a separator, as its
# redaction was, that no token, scheme value or header value contains.
_MASK = REDACTED[0]
# Shorter environment values are flags such as "1", "en" or "info", not credentials;
# scrubbing them out of free text would corrupt ordinary names and descriptions.
MIN_SECRET_LENGTH = 8
_URL = re.compile(r"(?<![a-zA-Z0-9+.-])[a-zA-Z0-9+.-]+://[^\s\"'<>]+")
# No leading word boundary: "_" is a word character, so a boundary would skip
# GITHUB_TOKEN= and client_secret=. Delimited suffixes (DB_PASSWORD_PROD=) and
# digits (token2=) may follow the keyword; "max_tokens" and "tokenizer" may not.
# A backslash escapes the next character of a quoted value, as JSON reads it.
# Possessive and bounded quantifiers keep every attempt linear.
_CREDENTIAL_WORD = (
    r"(?:api[-_]?key|access[-_]?key|secret[-_]?key|private[-_]?key|account[-_]?key"
    r"|[a-z0-9]{2,24}[-_]key|connection[-_]?string"
    r"|token|password|passwd|passphrase|pwd|secret|credentials?|sig)"
)
_CREDENTIAL_KEYWORD = _CREDENTIAL_WORD + r"(?:\d{1,4})?(?:[-_.][a-z0-9]{1,32}){0,4}"
# The mark between a name and its value: `:` or `=`, or a two-character operator that
# starts with one, such as `:=`, `=>`, `::` or `==`. Read as a one-character mark, the
# operator's second character became the value and the real one stayed in clear.
_MARK = r"[:=]{1,2}+>?+"
_ASSIGNMENT = re.compile(
    rf"(?i)({_CREDENTIAL_KEYWORD}[\"']?\s*+{_MARK}\s*+)"
    r"(\"(?:[^\"\\\n]|\\.){0,8192}\"|'(?:[^'\\\n]|\\.){0,8192}'|[^\s,;]++)"
)
# A long command-line option named for a credential, with its value as the next word:
# `--password value`, `--db-password "value"`. A word that starts with `-` is the next
# option, not a value.
_FLAG = re.compile(
    rf"(?i)(?<![\w-])--(?:[a-z0-9]{{1,32}}[-_]){{0,4}}{_CREDENTIAL_KEYWORD}\s++"
    r"(\"(?:[^\"\\\n]|\\.){0,8192}\"|'(?:[^'\\\n]|\\.){0,8192}'|(?!-)[^\s,;]++)"
)
# A mapping key that _ASSIGNMENT would read as the name in `name: value`.
_CREDENTIAL_KEY = re.compile(rf"(?i){_CREDENTIAL_KEYWORD}\Z")
_AUTHORIZATION_KEY = re.compile(r"(?i)(?:proxy-)?authorization")
_COOKIE_KEY = re.compile(r"(?i)(?:set-)?cookie")
_SCHEME_AND_VALUE = re.compile(r"([A-Za-z0-9-]{1,32})(\s++)(\S.*+)", re.DOTALL)
# A reference names where a credential comes from and holds none. Only the braced and
# the upper-case forms count: a password may itself begin with "$".
_REFERENCE = re.compile(r"\$\{[^{}\s]{1,128}\}|\$[A-Z][A-Z0-9_]{1,127}")
_TEMPLATE = re.compile(r"\{\{[^{}]{1,128}\}\}")
_AUTH = re.compile(r"(?i)\b(Bearer|Basic|Token|Bot|ApiKey|Api-Key)(\s++)([A-Za-z0-9_+/=.~-]{6,}+)")
# After an Authorization or Proxy-Authorization header name the scheme's value is a
# credential whatever its shape; the shape checks only tell prose from credentials.
# Searched in a bounded window before each scheme, so the cost per match is constant.
_AUTHORIZATION_HEADER = re.compile(
    r"(?i)authorization(?:\\*+[\"'])?\s{0,8}[:=]\s{0,8}(?:\\*+[\"'])?$"
)
_AUTHORIZATION_LOOKBACK = 40
# A prose word after a scheme ("Bearer authentication") is shorter than this; a value
# this long after Bearer, Token, Bot, ApiKey or Api-Key is redacted whatever its shape.
LONG_CREDENTIAL_LENGTH = 16
_ASCII_DIGITS = frozenset(string.digits)
_ASCII_UPPER = frozenset(string.ascii_uppercase)
_ASCII_LOWER = frozenset(string.ascii_lowercase)
_CREDENTIAL_PUNCTUATION = frozenset("._~+/=-")
# Formats distinctive enough to stand out inside a name (AWS_AKIA..., X_glpat-...).
# Each stops at the end of its own run or matches the rest, so starting one after
# every "_" or "-" keeps the scan linear. An AWS key id must end there, or
# REGION_ASIAPACIFICSOUTHEAST1 would read as one. The AI-vendor prefixes also open
# ordinary names (pplx-7b-online, fw_config_loader), so each needs a body of at
# least 20 characters in the vendor's own alphabet.
_OTHER_DISTINCT_SHAPES = (
    r"gh[oprsu]_[A-Za-z0-9]{36,}+|github_pat_\w{22,}+|glpat-[\w-]{20,}+"
    r"|xox[abeoprs]-[\w-]{10,}+|[rs]k_(?:live|test)_[A-Za-z0-9]{16,}+"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])|AIza[\w-]{35}|ya29\.[\w-]{20,}+"
    r"|npm_[A-Za-z0-9]{36}|pypi-[\w-]{50,}+|hf_[A-Za-z0-9]{30,}+"
    r"|pcsk_[A-Za-z0-9_]{20,}+|gsk_[A-Za-z0-9]{20,}+|r8_[A-Za-z0-9]{20,}+"
    r"|pplx-[A-Za-z0-9]{20,}+|xai-[A-Za-z0-9]{20,}+|lsv2_(?:pt|sk)_[A-Za-z0-9_]{20,}+"
    r"|tvly-[A-Za-z0-9-]{20,}+|fw_[A-Za-z0-9]{20,}+"
    r"|SG\.[\w-]{16,}+\.[\w-]{16,}+|dckr_pat_[\w-]{20,}+|shp(?:at|ss|ca)_[0-9a-fA-F]{32}"
    r"|SK[0-9a-f]{32}(?![A-Za-z0-9])"
    r"|shppa_[0-9a-fA-F]{32}|dapi[0-9a-f]{32}|xapp-[\w-]{20,}+|PMAK-[0-9a-f]{24}-[0-9a-f]{34}"
    # A Doppler service token may name its config first: dp.st.<config>.<token>.
    r"|dp\.(?:pt|ct|sa|scim|audit|st(?:\.[a-z0-9_-]{2,35}+)?)\.[A-Za-z0-9]{40,}+"
    r"|do[opr]_v1_[0-9a-f]{64}|lin_(?:api|oauth)_[A-Za-z0-9]{40}|ATATT3[\w=-]{40,}+"
    r"|AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}"
    # Discord: a decimal id in base64 (M, N or O first, with a digit), a 6-character
    # stamp that is not a lower-case word, and an HMAC: not plugin.module.Class names.
    r"|(?<![A-Za-z0-9])[MNO](?=[A-Za-z0-9]{0,26}[0-9])[A-Za-z0-9]{23,27}"
    r"\.(?![A-Za-z][a-z]{5}\.)[\w-]{6}\.[\w-]{27,38}(?![\w-])"
)
_SK_BODY = (
    r"(?:or-v1|lf|proj|svcacct|admin)-[A-Za-z0-9_-]{20,}+"
    r"|ant-[\w-]{20,}+|[A-Za-z0-9]{32,}+"
)
_DISTINCT_SHAPES = rf"{_OTHER_DISTINCT_SHAPES}|sk-(?:{_SK_BODY})"
# A JWT can fail only at its first dot, so it starts only at a word boundary: started
# after every "_" its first segment would be rescanned once per position.
_JWT = r"eyJ[\w-]{8,}+\.[\w-]{8,}+(?:\.[\w-]++)?"
# Credential formats with a fixed prefix. sk- also names ordinary things
# (sk-learn-classifier), so it counts only at a word boundary.
TOKEN_SHAPE = re.compile(
    rf"(?<![\w-])(?:{_JWT}|sk-[\w-]{{20,}}+|(?:AKIA|ASIA)[A-Z0-9]{{16}})"
    rf"|(?<![A-Za-z0-9])(?:{_DISTINCT_SHAPES})"
)
# Names matched against other evidence keep sk-... forms; a distinct token is redacted.
_NAMED_TOKEN = re.compile(rf"(?<![\w-]){_JWT}|(?<![A-Za-z0-9])(?:{_DISTINCT_SHAPES})")
# The same shapes with no boundary before them: a credential glued to a prefix, as in
# "prod-sk-ant-...", "1ghp_..." or "xAKIA...". The sk- form also needs two digits, so a
# plain name such as disk-management-service-v2 does not read as one.
_EMBEDDED_TOKEN = re.compile(rf"(?:AKIA|ASIA)[A-Z0-9]{{16}}|(?:{_OTHER_DISTINCT_SHAPES})")
_EMBEDDED_SK = re.compile(rf"sk-(?:{_SK_BODY})")
_DISTINCT_SK_BODY = re.compile(_SK_BODY)
_TOKEN_SEGMENT = re.compile(r"[\w-]++")
# A complete public package word can end in the two letters of the key prefix.
# Treat that lexical component as a unit. A specific provider marker with an
# opaque body still supplies independent evidence, even after one of these words.
_REGISTRY_SK_START = re.compile(
    r"(?P<word>(?<![A-Za-z0-9])(?i:desk|disk|dusk|flask|husk|kiosk|mask|multitask|risk|task|tusk)-)|sk-"
)
_PROVIDER_SK_BODY = re.compile(
    r"(?:(?:or-v1|lf)-[A-Za-z0-9_-]{20}|ant-[\w-]{20}|(?:proj|svcacct|admin)-[A-Za-z0-9]{20})"
)
_DECIMAL_DIGIT = re.compile(r"\d")
_JWT_PAYLOAD_START = re.compile(r"\.[\w-]{8}")


def holds_token_shape(text: str, *, require_sk_boundary: bool = False) -> bool:
    """Find token shapes, optionally distinguishing a generic sk- prefix from a word suffix."""
    if _EMBEDDED_TOKEN.search(text) or (not require_sk_boundary and _EMBEDDED_SK.search(text)):
        return True
    if "sk-" not in text and "eyJ" not in text:
        return False
    # Every later prefix in the same segment has a shorter suffix. Only the first
    # can tell us anything new about the remaining length and digit count.
    for segment in _TOKEN_SEGMENT.finditer(text):
        start, end = segment.span()
        if require_sk_boundary:
            key = -1
            for match in _REGISTRY_SK_START.finditer(text, start, end):
                if match.lastgroup == "word":
                    if _PROVIDER_SK_BODY.match(text, match.end(), end):
                        return True
                    continue
                if _DISTINCT_SK_BODY.match(text, match.end(), end):
                    return True
                if key < 0:
                    key = match.start()
        else:
            key = text.find("sk-", start, end)
        if key >= 0 and end - key >= 23:
            first = _DECIMAL_DIGIT.search(text, key + 3, end)
            if first is not None and _DECIMAL_DIGIT.search(text, first.end(), end) is not None:
                return True
        jwt = text.find("eyJ", start, end)
        if jwt >= 0 and end - jwt >= 11 and _JWT_PAYLOAD_START.match(text, end):
            return True
    return False


# A header value with no scheme is redacted when it looks like a credential; after
# Negotiate, NTLM, DPoP (RFC 9449), HOBA (RFC 7486) or Mutual (RFC 8120), which the scheme
# rule above does not know, whatever its shape. "Mutual" is an English word, so it counts
# only after an Authorization header name, never in prose.
_RAW_AUTH_HEADER = re.compile(
    r"(?i)(\b(?:proxy-)?authorization(?:\\*+[\"'])?\s{0,8}[:=]\s{0,8}(?:\\*+[\"'])?)"
    r"(?:(negotiate|ntlm|dpop|hoba|mutual)([ \t]++)([A-Za-z0-9_+/=.~-]++)"
    r"|([A-Za-z0-9_+/=.~:-]{8,}+))"
)
_AUTH_SCHEMES = frozenset(
    {
        "bearer",
        "basic",
        "token",
        "bot",
        "apikey",
        "api-key",
        "digest",
        "negotiate",
        "aws4-hmac-sha256",
        "dpop",
        "hoba",
        "mutual",
    }
)
_AUTH_SCHEME_LENGTH = max(map(len, _AUTH_SCHEMES))


def _is_auth_scheme(value: str, span: Span) -> bool:
    # A value can run to the end of the text, once for every URL before it; slicing it
    # whole each time is quadratic, and no longer value is a scheme.
    start, end = span
    return end - start <= _AUTH_SCHEME_LENGTH and value[start:end].lower() in _AUTH_SCHEMES


_COOKIE_HEADER = re.compile(
    r"(?i)(\b(?:set-)?cookie(?:\\*+[\"'])?\s{0,8}[:=]\s{0,8})"
    r"(?:\"((?:[^\"\\\r\n]++|\\.)*+)\""
    r"|\\\"((?:[^\"\\\r\n]++|\\\\\\\\|\\\\\\\"|\\\\[^\"\\\r\n]|\\[^\"\\\r\n])*+)\\\""
    r"|'((?:[^'\\\r\n]++|\\.)*+)'"
    r"|([^\r\n]++))"
)
_COOKIE_PAIR = re.compile(
    r"([A-Za-z0-9_.-]{1,64}=)"
    r"(\"(?:[^\"\\\r\n]++|\\.)*+\""
    r"|\\\\\\\"(?:[^\"\\\r\n]++|\\\\\\\\|\\\\[^\"\\\r\n]|\\[^\"\\\r\n])*+\\\\\\\""
    r"|\\\"(?:[^\"\\\r\n]++|\\\\\\\\|\\\\\\\"|\\\\[^\"\\\r\n]|\\[^\"\\\r\n])*+\\\""
    r"|\\'(?:[^'\\\r\n]++|\\\\|\\[^'\\\r\n])*+\\'"
    r"|'(?:[^'\\\r\n]++|\\.)*+'"
    r"|(?:[^\s;,\"'\\]++|\\(?![\"']))++)"
)
_COOKIE_ATTRS = frozenset(
    {"path", "domain", "samesite", "max-age", "expires", "priority", "version"}
)
_CREDENTIAL_NAME = re.compile(
    r"(?i)key|token|secret|pass|pwd|credential|auth|cookie|session|private|signature|cert"
    r"|dsn|connection_?str|conn_?str|jwt|bearer|header|(?:^|_)pat(?:_|$)"
)
_URL_USERINFO = re.compile(r"://[^/\s@?#]*@")
_PLAIN_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s@?#]+")
# The authority a URL's shown origin is taken from, as urlsplit delimits it.
_NETLOC = re.compile(r"[^/?#]*")


def redact_url(value: str) -> str:
    """Keep URL origin only; paths, userinfo, queries and fragments may hold secrets.

    These are locators with credentials omitted, not round-trippable connection
    strings. No URL is fetched or resolved by this helper.
    """
    try:
        parts = urlsplit(value)
        raw_host = parts.netloc.rpartition("@")[2]
        # WHATWG parsers, as browsers use, end the host at a backslash; urlsplit does not.
        if (
            not parts.scheme
            or not parts.hostname
            or "\\" in parts.netloc
            or TOKEN_SHAPE.search(raw_host)
        ):
            return "[redacted-url]"
        host = parts.hostname
        if ":" in host:
            host = f"[{host}]"
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, "", "", ""))
    except ValueError:
        return "[redacted-url]"


def secret_like(name: str, value: str) -> bool:
    """Whether a variable's value must be kept out of free text and identity fields.

    The variable name marks a credential (KEY, TOKEN, SECRET, PASS, AUTH, ...), or
    the value has a known token format or carries URL user information. Values
    shorter than MIN_SECRET_LENGTH never qualify, and a plain URL without user
    information, query or fragment is a locator, not a secret.
    """
    if len(value) < MIN_SECRET_LENGTH:
        return False
    if TOKEN_SHAPE.search(value) or _URL_USERINFO.search(value):
        return True
    if _PLAIN_URL.fullmatch(value):
        return False
    return bool(_CREDENTIAL_NAME.search(name))


def secret_values(variables: Mapping[str, Any]) -> list[str]:
    """The string values of ``variables`` that ``secret_like`` selects.

    A value such as ``Bearer <token>`` also yields the credential after the scheme
    word, so a text that repeats the bare token without the scheme is scrubbed too.
    """
    values = []
    for name, value in variables.items():
        if isinstance(name, str) and isinstance(value, str) and secret_like(name, value):
            values.append(value)
            values.extend(scheme_credentials(value))
    return values


def scheme_credentials(value: str) -> list[str]:
    """The credential of ``value`` when it is an auth scheme word, whitespace and a credential."""
    parts = _SCHEME_AND_VALUE.fullmatch(value.strip())
    if parts is None or parts.group(1).lower() not in _AUTH_SCHEMES:
        return []
    credential = parts.group(3).strip()
    if len(credential) < MIN_SECRET_LENGTH or _REFERENCE.fullmatch(credential):
        return []
    return [credential]


def is_reference(value: str) -> bool:
    """Whether ``value`` only names a variable (``${NAME}``, ``$NAME``) and holds no secret."""
    return _REFERENCE.fullmatch(value) is not None


def names_reference(value: str) -> bool:
    """Whether ``value`` names where a credential comes from and holds none.

    A reference (``${NAME}``, ``$NAME``) or a template (``{{ name }}``), on its own or
    after an auth scheme word (``Bearer ${TOKEN}``).
    """
    stripped = value.strip()
    parts = _SCHEME_AND_VALUE.fullmatch(stripped)
    if parts is not None and parts.group(1).lower() in _AUTH_SCHEMES:
        stripped = parts.group(3).strip()
    return is_reference(stripped) or _TEMPLATE.fullmatch(stripped) is not None


def scheme_parts(value: str) -> tuple[str, str] | None:
    """The auth scheme word of ``value`` and the rest after it, or None without one."""
    parts = _SCHEME_AND_VALUE.fullmatch(value.strip())
    if parts is None or parts.group(1).lower() not in _AUTH_SCHEMES:
        return None
    return parts.group(1), parts.group(3).strip()


def scheme_credential_like(token: str, scheme: str) -> bool:
    """Whether ``token`` after ``scheme`` reads as a credential, as the scheme rule decides.

    Basic decodes to ``user:password``; any other scheme's value has 16 or more
    characters, or a digit, credential punctuation or mixed case.
    """
    return _credential_like(token, scheme)


def authorization_header(name: str) -> bool:
    """Whether ``name`` is the Authorization or Proxy-Authorization header."""
    return _AUTHORIZATION_KEY.fullmatch(name.strip()) is not None


def private_key_block(value: str) -> bool:
    """Whether ``value`` holds a PEM private key block, terminated or not."""
    return next(iter(_private_key_spans(value)), None) is not None


def credential_shaped(value: str) -> bool:
    """Whether a bare word reads as a credential, by the shape rule for scheme values.

    At least 16 characters, or a digit, credential punctuation, or both cases with an
    upper-case letter after the first: ``postgres`` or ``changeme`` read as words.
    """
    return _credential_like(value, "")


def _longest_first(value: str) -> tuple[int, str]:
    return (-len(value), value)


def _smallest_period(value: str) -> int:
    """The smallest shift at which ``value`` overlaps itself, its length when none does."""
    border = 0
    borders = [0] * len(value)
    for index in range(1, len(value)):
        while border and value[index] != value[border]:
            border = borders[border - 1]
        if value[index] == value[border]:
            border += 1
        borders[index] = border
    return len(value) - (borders[-1] if value else 0)


Span = tuple[int, int]


def _periodic_end(text: str, end: int, period: int) -> int:
    """Extend ``end`` while ``text`` repeats itself ``period`` characters back.

    Galloping, then halving, compares slices in C, so a run costs its length and only
    the logarithm of it in interpreted steps. Steps are powers of two, so halving the
    first one that fails tries every length below it.
    """
    step = 1
    while text.startswith(text[end - period : end - period + step], end):
        end += step
        step *= 2
    while step > 1:
        step //= 2
        if text.startswith(text[end - period : end - period + step], end):
            end += step
    return end


_COVERED = re.compile(rb"\x01+")


class SecretScrubber:
    """Known secret values, prepared once per source and applied linearly per text.

    Every occurrence of every value is located in the original text, overlapping ones
    included, so one value can never hide part of another. Each value costs a search
    of the text in C. Values go longest first and mark what they cover: a run of a
    value overlapping itself is measured along its smallest period, an occurrence
    wholly inside covered text is passed over to the next uncovered character, and
    every occurrence found otherwise covers a new one, so the interpreted steps grow
    with the text, not with the number of values times their occurrences. Values
    that are parts of one another, repeated between uncovered gaps, could still make
    each value pass over every repetition; past ``len(text) // 8`` passes and a few
    per value, the cover is every value's greedy replacement widened by the longest
    value on each side, which holds every overlapping occurrence. Texts shorter than
    the shortest value are skipped.
    """

    __slots__ = ("_periods", "_shortest", "_values")

    def __init__(self, values: Iterable[str] = ()) -> None:
        unique = {value for value in values if value}
        self._values = tuple(sorted(unique, key=_longest_first))
        self._periods = {value: _smallest_period(value) for value in self._values}
        self._shortest = len(self._values[-1]) if self._values else 0

    def __bool__(self) -> bool:
        return bool(self._values)

    def __len__(self) -> int:
        return len(self._values)

    @property
    def values(self) -> tuple[str, ...]:
        """The known values, longest first."""
        return self._values

    def extended(self, values: Iterable[str]) -> SecretScrubber:
        """This scrubber with ``values`` added, merged without sorting its own again.

        A file's values are prepared once and each server adds its own few, so the
        cost per server grows with the file's values, not with their sort.
        """
        known = self._periods
        extra = sorted(
            {value for value in values if value and value not in known}, key=_longest_first
        )
        if not extra:
            return self
        merged = SecretScrubber()
        merged._values = tuple(heapq.merge(self._values, extra, key=_longest_first))
        merged._periods = {**known, **{value: _smallest_period(value) for value in extra}}
        merged._shortest = len(merged._values[-1])
        return merged

    def contains(self, text: str) -> bool:
        if not self._values or len(text) < self._shortest:
            return False
        return any(value in text for value in self._values)

    def spans(self, text: str) -> list[Span]:
        """Where known values occur in ``text``: sorted, disjoint, touching runs joined."""
        if not self._values or len(text) < self._shortest:
            return []
        covered = self._covered(text)
        return [] if covered is None else [run.span() for run in _COVERED.finditer(covered)]

    def _covered(self, text: str) -> bytearray | None:
        covered: bytearray | None = None
        passes = len(text) // 8 + 4 * len(self._values) + 1024
        # Only an occurrence reaching an uncovered character, between the first and
        # the last, can add to the cover.
        first, last_free = 0, len(text) - 1
        for value in self._values:
            # A value the text does not hold adds nothing to the cover; testing that
            # first keeps the per-value bookkeeping below off the common path.
            if value not in text:
                continue
            size = len(value)
            period = self._periods[value]
            # An occurrence overlapping a run at a shift that is not a multiple of the
            # period starts past both the period and size - period (Fine and Wilf).
            resume = min(size, max(period, size - period) + 1)
            if covered is not None:
                first = covered.find(0, first)
                if first < 0:
                    break
                last_free = covered.rfind(0, 0, last_free + 1)
            bound = last_free + size
            start = text.find(value, max(0, first - size + 1), bound)
            while start >= 0:
                if covered is None:
                    covered = bytearray(len(text))
                elif covered.find(0, start, start + size) < 0:
                    # Every occurrence starting before the next uncovered character
                    # lies wholly in covered text.
                    passes -= 1
                    if passes < 0:
                        return self._widened_greedy(text)
                    free = covered.find(0, start + size)
                    if free < 0:
                        break
                    start = text.find(value, max(start + 1, free - size + 1), bound)
                    continue
                end = _periodic_end(text, start + size, period)
                last = start + (end - size - start) // period * period
                covered[start : last + size] = b"\x01" * (last + size - start)
                start = text.find(value, last + resume, bound)
        return covered

    def _widened_greedy(self, text: str) -> bytearray:
        """Every value replaced in turn, each run then widened by the longest value.

        An occurrence the replacements skip overlaps a replaced one, so it lies within
        the longest value's length of a run. A marker no value holds keeps a replaced
        run from matching a shorter value; one the text holds only widens the cover.
        """
        covered = bytearray(len(text))
        held = set("".join(self._values))
        marker = next((chr(code) for code in range(0x110000) if chr(code) not in held), None)
        if marker is None:
            covered[:] = b"\x01" * len(text)
            return covered
        replaced = text
        for value in self._values:
            replaced = replaced.replace(value, marker * len(value))
        reach = len(self._values[0]) - 1
        for run in re.finditer(re.escape(marker) + "+", replaced):
            start, end = max(0, run.start() - reach), min(len(text), run.end() + reach)
            covered[start:end] = b"\x01" * (end - start)
        return covered

    def scrub(self, text: str) -> str:
        spans = self.spans(text)
        return _apply(text, spans, []) if spans else text


def _scrubber(secrets: Iterable[str] | SecretScrubber) -> SecretScrubber:
    return secrets if isinstance(secrets, SecretScrubber) else SecretScrubber(secrets)


def _credential_like(token: str, scheme: str) -> bool:
    if scheme.lower() == "basic":
        # Basic credentials are base64 of "user:password"; prose such as
        # "basic arithmetic" does not decode to a pair.
        padded = token + "=" * (-len(token) % 4)
        try:
            return b":" in base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return False
    if len(token) >= LONG_CREDENTIAL_LENGTH:
        return True
    if token.isascii():
        # Set checks run in C: a text of scheme words is one match per word.
        return (
            not _ASCII_DIGITS.isdisjoint(token)
            or not _CREDENTIAL_PUNCTUATION.isdisjoint(token)
            or (not _ASCII_UPPER.isdisjoint(token[1:]) and not _ASCII_LOWER.isdisjoint(token))
        )
    return (
        any(char.isdigit() for char in token)
        or (any(char.isupper() for char in token[1:]) and any(char.islower() for char in token))
        or any(char in _CREDENTIAL_PUNCTUATION for char in token)
    )


def _authorization_scheme_credential(match: re.Match[str]) -> bool:
    scheme, _space, token = match.groups()
    start = match.start()
    header = _AUTHORIZATION_HEADER.search(
        match.string, max(0, start - _AUTHORIZATION_LOOKBACK), start
    )
    return header is not None or _credential_like(token, scheme)


def _scheme_matches(value: str) -> Iterator[re.Match[str]]:
    """Scheme matches, each search resuming where the previous credential starts.

    A scheme word can end a credential and start the next (``x=Bearer``, then the
    value after it). Applied one after another, the rules used to find it once an
    earlier rule had redacted the first scheme. A credential holds no whitespace and
    a scheme is followed by some, so a resumed search reads each credential twice at
    most.
    """
    position = 0
    while (match := _AUTH.search(value, position)) is not None:
        yield match
        position = match.start(3)


def _private_key_spans(value: str) -> Iterable[Span]:
    """PEM private key blocks, including unterminated ones, in one pass."""
    if "-----BEGIN" not in value:
        return
    search = 0
    while (start := value.find("-----BEGIN", search)) >= 0:
        label_end = value.find("-----", start + 10)
        if label_end < 0:
            break
        if "PRIVATE KEY" not in value[start + 10 : label_end]:
            # The closing dashes may open the next BEGIN line.
            search = label_end
            continue
        cursor = label_end + 5
        while True:
            end = value.find("-----END", cursor)
            if end < 0:
                search = len(value)
                break
            close = value.find("-----", end + 8)
            if close < 0:
                search = len(value)
                break
            end_label = value[end + 8 : close]
            if "\n" not in end_label and "\r" not in end_label and "PRIVATE KEY" in end_label:
                search = close + 5
                break
            # The closing dashes of a non-matching END marker may open another marker.
            cursor = close
        yield start, search


def _raw_auth_span(match: re.Match[str]) -> Span | None:
    _prefix, scheme, _space, _credential, token = match.groups()
    if scheme is not None:
        return match.span(4)
    if token.lower() in _AUTH_SCHEMES or not _credential_like(token, "token"):
        return None
    return match.span(5)


def _cookie_pair_secret(match: re.Match[str]) -> bool:
    name_eq, val = match.groups()
    if name_eq[:-1].lower() in _COOKIE_ATTRS:
        return False
    if val.startswith('\\\\\\"') and val.endswith('\\\\\\"') and len(val) >= 8:
        inner = val[4:-4]
    elif len(val) >= 4 and (
        (val.startswith('\\"') and val.endswith('\\"'))
        or (val.startswith("\\'") and val.endswith("\\'"))
    ):
        inner = val[2:-2]
    elif len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
        inner = val[1:-1]
    else:
        inner = val
    return len(inner) >= MIN_SECRET_LENGTH or _credential_like(inner, "token")


def _cookie_header_span(match: re.Match[str]) -> Span:
    for group in (2, 3, 4, 5):
        if match.start(group) >= 0:
            return match.span(group)
    return match.span(0)  # pragma: no cover - pattern matches one of groups 2..5


def _cookie_pair_replacement(match: re.Match[str]) -> str:
    return match.group(1) + REDACTED if _cookie_pair_secret(match) else match.group()


def _cookie_spans(value: str, start: int = 0, end: int | None = None) -> Iterable[Span]:
    stop = len(value) if end is None else end
    for pair in _COOKIE_PAIR.finditer(value, start, stop):
        if _cookie_pair_secret(pair):
            yield pair.span(2)


class _Rewrite:
    """A URL shown as its origin.

    ``revealed`` ends the source text the origin is read from, and ``removed`` are the
    spans of the URL the origin does not show: its user info, path, query and fragment.
    """

    __slots__ = ("end", "removed", "replacement", "revealed", "start")

    def __init__(
        self, start: int, end: int, replacement: str, revealed: int, removed: list[Span]
    ) -> None:
        self.start, self.end = start, end
        self.replacement, self.revealed, self.removed = replacement, revealed, removed


def _url_rewrite(match: re.Match[str]) -> _Rewrite | None:
    url = match.group()
    shown = redact_url(url)
    if shown == url:
        return None
    start, end = match.span()
    if shown == "[redacted-url]":
        return _Rewrite(start, end, shown, start, [(start, end)])
    scheme_end = url.index("://") + 3
    netloc = _NETLOC.match(url, scheme_end)
    revealed = start + (netloc.end() if netloc else scheme_end)
    sources = origin_sources(url, shown)
    if sources is None:
        # Not aligned: only what follows the authority counts as removed, so main's
        # floor marks the rest hidden and the whole URL is redacted.
        return _Rewrite(start, end, shown, revealed, [(revealed, end)])
    # What the origin shows as written stays; the rest, a letter it lower-cases among
    # them, is removed, as main's rewrite of the same URL removed it.
    removed: list[Span] = []
    position = start
    for index in shown_unchanged(url, shown, sources):
        if index is None:
            continue
        if start + index > position:
            removed.append((position, start + index))
        position = start + index + 1
    if end > position:
        removed.append((position, end))
    return _Rewrite(start, end, shown, revealed, removed)


def _merged(spans: list[Span]) -> list[Span]:
    """Sorted, disjoint spans; touching spans become one."""
    spans.sort()
    merged: list[Span] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def _apply(value: str, spans: list[Span], rewrites: list[_Rewrite]) -> str:
    """Replace each maximal union of ``spans`` and ``rewrites`` in one pass.

    ``spans`` are disjoint and sorted. A rewrite whose revealed origin no span touches,
    and which no span extends past, is shown as rewritten; any other union of a
    rewrite and spans is redacted as a whole, so a rewrite never shows a known value.
    """
    items: list[tuple[int, int, _Rewrite | None]] = [(start, end, None) for start, end in spans]
    for rewrite in rewrites:
        # The last span starting inside the revealed origin is the only one that can
        # reach into it: the spans are disjoint and sorted.
        index = bisect.bisect_left(spans, (rewrite.revealed, -1))
        touched = (
            rewrite.revealed > rewrite.start and index > 0 and spans[index - 1][1] > rewrite.start
        )
        items.append((rewrite.start, rewrite.end, None if touched else rewrite))
    items.sort(key=lambda item: (item[0], -item[1]))
    parts: list[str] = []
    copied = 0
    group_start = group_end = -1
    shown: list[_Rewrite] = []

    def flush() -> None:
        if len(shown) == 1 and (group_start, group_end) == (shown[0].start, shown[0].end):
            parts.append(shown[0].replacement)
        else:
            parts.append(REDACTED)

    for start, end, shape in items:
        if group_end >= 0 and (
            start < group_end or (start == group_end and shape is None and not shown)
        ):
            group_end = max(group_end, end)
        else:
            if group_end >= 0:
                flush()
                copied = group_end
            parts.append(value[copied:start])
            group_start, group_end = start, end
            shown = []
        if shape is not None:
            shown.append(shape)
    if group_end < 0:
        return value
    flush()
    parts.append(value[group_end:])
    return "".join(parts)


# The name part of an assignment, and the two quoted value forms; an unquoted value runs
# to the next whitespace, `,` or `;`. The value forms are those of _ASSIGNMENT.
_ASSIGNMENT_NAME = re.compile(rf"(?i){_CREDENTIAL_KEYWORD}(?:\\*+[\"'])?\s*+{_MARK}\s*+")
_QUOTED_VALUE = re.compile(r"\"(?:[^\"\\\n]|\\.){0,8192}\"|'(?:[^'\\\n]|\\.){0,8192}'")
_VALUE_END = re.compile(r"[\s,;]")
# What stands in for a URL while the rules read the rest of the text. It is no keyword,
# separator, quote or space, so a value that runs into a URL is not cut short and no
# rule reads a URL's path or query, which its rewrite removes. Each URL is read on its
# own instead, bounded at its end, so an assignment inside one ends there, as
# `<a href="https://h/cb?token=v">password: w` needs.
_URL_MASK = "\x00"
# A credential name that ends a URL, with its mark when the URL holds it, and the rest
# of an assignment after the URL: a closing quote, spaces and the mark.
# One or more backslashes may end the URL too: in nested JSON or shell text written
# inside a string, `?api_key=\"value\"` or `?api_key=\\"value\\"` escapes the opening quote.
_URL_END_NAME = re.compile(rf"(?i)(?:{_CREDENTIAL_KEYWORD})(?:\\*+[\"'])?(?P<mark>{_MARK})?\\*+\Z")
_AFTER_URL_MARK = re.compile(rf"[\"']?\s*+(?P<mark>{_MARK})?\s*+")
# How far before a URL's start a credential name that runs into it may begin, and how
# far past it the name may end: longer than any keyword with its suffixes.
_NAME_REACH = 256


def _masked_urls(value: str, url_spans: list[Span]) -> str:
    if not url_spans:
        return value
    parts: list[str] = []
    position = 0
    for start, end in url_spans:
        parts.append(value[position:start])
        parts.append(_URL_MASK * (end - start))
        position = end
    parts.append(value[position:])
    return "".join(parts)


class _UnquotedRuns:
    """The end of the unquoted value that starts at a position, found once per run.

    Values are asked for in nondecreasing order. One that starts inside the run found
    for an earlier value ends where that run does, as no whitespace, `,` or `;` lies between,
    so a run is never scanned twice however many names lead into it.
    """

    __slots__ = ("end", "limit", "text")

    def __init__(self, text: str, limit: int) -> None:
        self.text, self.limit, self.end = text, limit, -1

    def value_end(self, start: int) -> int:
        if start >= self.end:
            stop = _VALUE_END.search(self.text, start, self.limit)
            self.end = self.limit if stop is None else stop.start()
        return self.end


def _escaped_quote_span(text: str, start: int, limit: int) -> Span | None:
    """Match a backslash-escaped quoted value such as ``\\"secret val\\"`` in linear time."""
    slashes = start
    while slashes < limit and text[slashes] == "\\":
        slashes += 1
    slash_count = slashes - start
    if slash_count == 0 or slashes >= limit or text[slashes] not in "\"'":
        return None
    quote = text[slashes]
    pos = slashes + 1
    max_end = min(limit, pos + 8192)
    newline = text.find("\n", pos, max_end)
    stop = max_end if newline < 0 else newline
    search = pos
    fallback_end: int | None = None
    while search < stop:
        close = text.find(quote, search, stop)
        if close < 0:
            break
        back = close - 1
        while back >= pos and text[back] == "\\":
            back -= 1
        run = close - 1 - back
        if run >= slash_count and (run - slash_count) % 2 == 0:
            if slash_count != 1 or (run - 1) % 4 == 0:
                return start, close + 1
            if fallback_end is None:
                fallback_end = close + 1
        search = close + 1
    return (start, fallback_end) if fallback_end is not None else None


def _value_span(
    text: str, start: int, limit: int, runs: _UnquotedRuns, original: str | None = None
) -> Span | None:
    if start >= limit or text[start] in ",;" or text[start].isspace():
        return None
    quoted = _QUOTED_VALUE.match(text, start, limit)
    if quoted is not None:
        # A URL's mask covers a backslash that escapes the quote after it, so the value is
        # read in the original text too, and runs to the later end.
        written = None if original is None else _QUOTED_VALUE.match(original, start, limit)
        return start, max(quoted.end(), written.end() if written else 0)
    if text[start] == "\\":
        escaped = _escaped_quote_span(text, start, limit)
        if escaped is not None:
            return escaped
    return start, runs.value_end(start)


def _every_assignment(
    text: str, start: int, limit: int, original: str | None = None
) -> Iterable[Span]:
    """The value of every assignment whose name starts in ``text[start:limit]``.

    Each place a credential name can start is read, not only where the previous
    assignment ended, so a value that holds another name, as in `sort_key = token = v`,
    `PRIMARY_KEY=sig_v: v` or `signing_key:` with `password: v` below it, cannot hide
    that name's own value. Values end at ``limit``.
    """
    runs = _UnquotedRuns(text, limit)
    position = start
    while (name := _ASSIGNMENT_NAME.search(text, position, limit)) is not None:
        position = name.start() + 1
        span = _value_span(text, name.end(), limit, runs, original)
        if span is not None:
            yield span


def _assignment_spans(value: str, url_spans: list[Span]) -> Iterable[Span]:
    """Assignment value spans: read with every URL masked, and in each URL on its own.

    A credential name that ends a URL, as in `https://h/?a=b,password: v`, takes the value
    that whitespace or a quote sets off after it, unless that is a scheme word such as
    `Bearer`, which the scheme rule reads.
    """
    yield from _every_assignment(_masked_urls(value, url_spans), 0, len(value), value)
    yield from _straddling_assignments(value, url_spans)
    after_runs = _UnquotedRuns(value, len(value))
    for url_start, url_end in url_spans:
        yield from _every_assignment(value, url_start, url_end)
        if url_end >= len(value):
            continue
        tail = _URL_END_NAME.search(value, max(url_start, url_end - 180), url_end)
        if tail is None:
            continue
        # The mark is in the URL (`?a,password: v`), after it (`?a,password : v`), or
        # split by it: a URL ends before `>`, so `?a,API_KEY=>v` and `:>v` leave `>` outside. A
        # `>` that a name follows ends an autolink instead, as in `<https://h/?p=>token:`.
        gap = url_end
        if (
            tail.group("mark") in ("=", ":")
            and value[gap] == ">"
            and _ASSIGNMENT_NAME.match(value, gap + 1) is None
        ):
            gap += 1
        elif not (value[gap].isspace() or value[gap] in "\"'"):
            continue
        if gap < len(value) and tail.group("mark") is not None and value[gap] in "\"'":
            slash_start = gap
            while slash_start > url_start and value[slash_start - 1] == "\\":
                slash_start -= 1
            if slash_start < gap:
                escaped = _escaped_quote_span(value, slash_start, len(value))
                if escaped is not None:
                    if not _is_auth_scheme(value, escaped):
                        yield escaped
                    continue
            else:
                direct = _value_span(value, gap, len(value), after_runs)
                if direct is not None and not _is_auth_scheme(value, direct):
                    yield direct
                continue
        # Every part of the pattern is optional, so it always matches.
        after = cast(re.Match[str], _AFTER_URL_MARK.match(value, gap))
        if tail.group("mark") is None and after.group("mark") is None:
            continue
        span = _value_span(value, after.end(), len(value), after_runs)
        if span is not None and not _is_auth_scheme(value, span):
            yield span


def _straddling_assignments(value: str, url_spans: list[Span]) -> Iterable[Span]:
    """Values of credential names that run into a URL's scheme.

    In `api_key:///x>v` the URL is `key:///x`, so masking it takes the name with it. A
    keyword's parts are those of a scheme but for `_`, so only a URL right after `_` can
    start inside a name; each such name is read in the original text across the start,
    in a window no other URL's search reads again.
    """
    runs = _UnquotedRuns(value, len(value))
    searched = 0
    for url_start, _url_end in url_spans:
        if url_start == 0 or value[url_start - 1] != "_":
            continue
        position = max(searched, url_start - _NAME_REACH)
        limit = min(len(value), url_start + _NAME_REACH)
        while (name := _ASSIGNMENT_NAME.search(value, position, limit)) is not None:
            if name.start() >= url_start:
                break
            position = name.start() + 1
            if name.end() > url_start:
                span = _value_span(value, name.end(), len(value), runs)
                if span is not None:
                    yield span
        searched = url_start


def _rule_matches(
    value: str, *, identifier: bool, cookie: bool
) -> tuple[list[Span], list[_Rewrite]]:
    url_matches = list(_URL.finditer(value))
    url_spans = [match.span() for match in url_matches]
    rewrites = [rewrite for match in url_matches if (rewrite := _url_rewrite(match)) is not None]
    spans: list[Span] = []
    if not identifier:
        spans.extend(_private_key_spans(value))
    spans.extend(_assignment_spans(value, url_spans))
    spans.extend(match.span(1) for match in _FLAG.finditer(value))
    # The scheme, header and cookie rules read the text as it is, where a scheme word or
    # header name inside a URL still marks the credential after it, and again with each
    # URL masked, as main read it with each URL rewritten: a URL then ends the word or
    # header before it, so a credential glued to a URL is still a credential.
    masked = _masked_urls(value, url_spans)
    readings = (value, masked) if url_spans else (value,)
    for reading in readings:
        spans.extend(
            match.span(3)
            for match in _scheme_matches(reading)
            if _authorization_scheme_credential(match)
        )
    if identifier:
        spans.extend(match.span() for match in _NAMED_TOKEN.finditer(value))
        return spans, rewrites
    for reading in readings:
        for match in _RAW_AUTH_HEADER.finditer(reading):
            if (span := _raw_auth_span(match)) is not None:
                spans.append(span)
    spans.extend(_url_clipped_cookie_spans(value, url_spans))
    if url_spans:
        for match in _COOKIE_HEADER.finditer(masked):
            spans.extend(_cookie_spans(value, *_cookie_header_span(match)))
    spans.extend(match.span() for match in TOKEN_SHAPE.finditer(value))
    if cookie:
        spans.extend(_cookie_spans(value))
    return spans, rewrites


def _url_clipped_cookie_spans(value: str, url_spans: list[Span]) -> Iterable[Span]:
    """The pairs of each ``Cookie`` header in the text as it is, cut at the end of a URL
    the header starts in, where the URL's own query is not a header's value."""
    url_index = 0
    for match in _COOKIE_HEADER.finditer(value):
        start, end = _cookie_header_span(match)
        while url_index < len(url_spans) and url_spans[url_index][1] <= match.start():
            url_index += 1
        if url_index < len(url_spans) and url_spans[url_index][0] <= match.start():
            end = min(end, url_spans[url_index][1])
        if start < end:
            yield from _cookie_spans(value, start, end)


def _masked(value: str, spans: list[Span]) -> str:
    """``value`` with each span replaced by as many marker characters, offsets kept."""
    parts: list[str] = []
    copied = 0
    for start, end in spans:
        parts.append(value[copied:start])
        parts.append(_MASK * (end - start))
        copied = end
    parts.append(value[copied:])
    return "".join(parts)


def _redaction(
    value: str, scrubber: SecretScrubber, *, identifier: bool, cookie: bool = False
) -> tuple[list[Span], list[_Rewrite]]:
    """Every rule's and every known value's match in ``value``.

    The rules read the original text, where a known value cannot erase the context
    they need, and again the text with each known value masked, where a value's edge
    separates words as its redaction did: a token, header or URL right next to a known
    value still matches. ``cookie`` reads the whole value as cookie pairs.
    """
    known = scrubber.spans(value)
    spans, rewrites = _rule_matches(value, identifier=identifier, cookie=cookie)
    # The rules applied one after another, as before this engine, hide some values a
    # union of matches shows; whatever they hide is hidden here too. What a URL rewrite
    # removes is the rewrite's in both. With no known value in the text, main replaced
    # none: a replacement is what could make another value occur.
    spans.extend(
        hidden_spans(
            value,
            scrubber.values if known else (),
            identifier=identifier,
            removed=[span for rewrite in rewrites for span in rewrite.removed],
            cookie=cookie,
        )
    )
    if known:
        masked_spans, masked_rewrites = _rule_matches(
            _masked(value, known), identifier=identifier, cookie=cookie
        )
        spans.extend(masked_spans)
        spans.extend(known)
        # A masked URL runs on through a known value holding a space or quote, so it
        # replaces the shorter URL read at the same place.
        starts = {rewrite.start: rewrite for rewrite in rewrites}
        starts.update((rewrite.start, rewrite) for rewrite in masked_rewrites)
        rewrites = list(starts.values())
    return spans, rewrites


def _redact(value: str, spans: list[Span], rewrites: list[_Rewrite]) -> str:
    return _apply(value, _merged(spans), rewrites) if spans or rewrites else value


def redact_text(
    value: str,
    secrets: Iterable[str] | SecretScrubber = (),
    *,
    identifier: bool = False,
) -> str:
    """Remove known secret values and common URL/auth/assignment/token encodings.

    Every rule and every known value is matched in the original text, and each union
    of their matches is replaced at once: a known value cannot erase the context a
    rule needs, such as the name before ``=`` or an ``Authorization`` header, nor can
    a rule's rewrite hide part of a known value from the scrubber.

    ``identifier`` keeps names that are matched against other evidence, such as tool
    names, free of the private key rule and of the token formats that ordinary names
    take: an innocuous name like ``sk-learn-classifier`` must keep matching the name a
    live server reports. A name holding a distinctive token such as ``ghp_...`` is
    still redacted.
    """
    spans, rewrites = _redaction(value, _scrubber(secrets), identifier=identifier)
    return _redact(value, spans, rewrites)


def redact_keyed_text(
    key: str,
    value: str,
    secrets: Iterable[str] | SecretScrubber = (),
    *,
    redacted: str | None = None,
) -> str:
    """Redact a mapping's text value as ``redact_text`` redacts ``key: value``.

    Parsed JSON or TOML hands a header or an assignment over as a key and a value, so
    the rules of ``redact_text`` that read both in one string never see them. The value
    of an ``Authorization`` or ``Proxy-Authorization`` key is a credential after any
    scheme word, the pairs of a ``Cookie`` or ``Set-Cookie`` key are cookies, and the
    value of a key that names a credential, such as ``password`` or ``X-Api-Key``, is
    one whatever its shape. A reference to a variable and a plain URL stay, as
    locators. ``redacted`` is the value as the caller already redacted it, when that
    is not ``redact_text(value, secrets)``.
    """
    if not value:
        return redact_text(value, secrets) if redacted is None else redacted
    cookie = _COOKIE_KEY.fullmatch(key) is not None
    scrubber = _scrubber(secrets)
    if redacted is not None:
        safe = redacted
    else:
        # The pairs are read in the original value too: a known value redacted first
        # could hide the name that marks the pair after it.
        spans, rewrites = _redaction(value, scrubber, identifier=False, cookie=cookie)
        safe = _redact(value, spans, rewrites)
    if _AUTHORIZATION_KEY.fullmatch(key):
        parts = _SCHEME_AND_VALUE.fullmatch(value)
        if parts is not None and parts.group(1).lower() in _AUTH_SCHEMES:
            scheme, space, credential = parts.groups()
            return safe if _REFERENCE.fullmatch(credential) else scheme + space + REDACTED
        return safe if _REFERENCE.fullmatch(value) else REDACTED
    if cookie:
        return safe if redacted is None else _COOKIE_PAIR.sub(_cookie_pair_replacement, safe)
    if _CREDENTIAL_KEY.search(key):
        if _REFERENCE.fullmatch(value) or _locator(value, safe, scrubber, redacted is None):
            return safe
        return REDACTED
    return safe


def _locator(value: str, safe: str, scrubber: SecretScrubber, ours: bool) -> bool:
    """Whether a credential-keyed ``value``, redacted to ``safe``, is a plain URL to show.

    The whole value must be one URL: a credential glued to a URL after a quote or `<`
    is no locator. When ``safe`` is this engine's own, main's redaction must read as a
    plain URL too: hiding what both hid can merge away the `@`, `?` or `#` that made
    main's text fall back to the marker.
    """
    if _URL.fullmatch(value) is None or _PLAIN_URL.fullmatch(safe) is None:
        return False
    if not ours:
        return True
    values = scrubber.values if scrubber.spans(value) else ()
    return _PLAIN_URL.fullmatch(redaction(value, values)) is not None


_JWK_PRIVATE_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"})


def redact_metadata(value: Any, secrets: Iterable[str] | SecretScrubber = ()) -> Any:
    """Redact textual metadata while retaining its JSON structure."""
    return _redact_metadata(value, _scrubber(secrets))


def _redact_metadata(value: Any, scrubber: SecretScrubber) -> Any:
    if isinstance(value, str):
        return redact_text(value, scrubber)
    if isinstance(value, dict):
        is_jwk = isinstance(value.get("kty"), str)
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            redacted_key = redact_text(key_text, scrubber)
            if is_jwk and key_text in _JWK_PRIVATE_FIELDS and item not in (None, "", [], {}):
                out[redacted_key] = REDACTED
            elif isinstance(item, str):
                out[redacted_key] = redact_keyed_text(key_text, item, scrubber)
            else:
                out[redacted_key] = _redact_metadata(item, scrubber)
        return out
    if isinstance(value, list):
        return [_redact_metadata(item, scrubber) for item in value]
    return value


_SCHEMA_LITERALS = frozenset({"default", "const", "enum", "example", "examples"})
_SCHEMA_MAPS = frozenset(
    {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies"}
)


def _schema_projection(value: Any, *, named_schemas: bool = False) -> Any:
    """Drop embedded instance data. Property and definition names are not keywords."""
    if isinstance(value, list):
        return [_schema_projection(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _schema_projection(item, named_schemas=not named_schemas and key in _SCHEMA_MAPS)
            for key, item in value.items()
            if named_schemas or key not in _SCHEMA_LITERALS
        }
    return value


def redact_descriptor(
    descriptor: dict[str, Any], secrets: Iterable[str] | SecretScrubber = ()
) -> dict[str, Any]:
    """Project an MCP descriptor for display; its original digest binds omitted literals.

    The tool name is an identifier compared with live observations, so only the
    identifier rules of ``redact_text`` apply to it.
    """
    scrubber = _scrubber(secrets)
    safe = {}
    for key, value in descriptor.items():
        raw_key = str(key)
        if raw_key in {"inputSchema", "outputSchema"}:
            value = _schema_projection(value)
            out_key = raw_key
        elif raw_key not in {"name", "title", "description", "annotations", "_meta"}:
            out_key = redact_text(raw_key, scrubber)
        else:
            out_key = raw_key
        if raw_key == "name" and isinstance(value, str):
            safe[out_key] = redact_text(value, scrubber, identifier=True)
        elif isinstance(value, str):
            safe[out_key] = redact_keyed_text(raw_key, value, scrubber)
        else:
            safe[out_key] = _redact_metadata(value, scrubber)
    return safe
