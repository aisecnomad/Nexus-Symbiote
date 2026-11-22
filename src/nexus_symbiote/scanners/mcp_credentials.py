"""Whether an MCP launch value is a literal credential, judged by its name and its value.

The MCP collector chooses each position (an env value, a header, an argument word, an
endpoint URL query); this module reads its name and value. Every hit carries its
literal, so a name that repeats one can be withheld.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import string
import unicodedata
from array import array
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from nexus_symbiote.utils.secrets import (
    MIN_SECRET_LENGTH,
    TOKEN_SHAPE,
    authorization_header,
    credential_shaped,
    private_key_block,
    scheme_credential_like,
    scheme_parts,
)


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


def _word_tuple(text: str) -> tuple[str, ...]:
    return tuple(text.split())


SHAPE_CLASS = "a vendor token shape"
SCHEME_CLASS = "an authorization scheme credential"
NAMED_CLASS = "a generic secret-like value"
# Strongest first: a token shape stands whatever surrounds it.
CREDENTIAL_CLASSES = (SHAPE_CLASS, SCHEME_CLASS, NAMED_CLASS)

Hit = tuple[str, str]

# A name is read as words split at separators, lowerCamel and letter-digit boundaries;
# digits alone are dropped, so TOKEN2 and Secret2 read as token and secret.
_NAME_PARTS = re.compile(
    r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])"
    r"|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])"
)
_CREDENTIAL_WORDS = _words(
    "token password passwd passphrase pass pwd pw pswd psw secret credential credentials apikey "
    "auth authorization bearer jwt sig signature dsn pat cookie mnemonic seedphrase"
)
# PGPASSWORD, ACCESSTOKEN, CLIENTSECRET: a compound written without separators.
_COMPOUND_ENDINGS = _word_tuple(
    "password passwd passphrase token secret credential credentials pw pswd"
)
_COMPOUND_KEYS = _words(
    "secretkey privatekey apikey accesskey apitoken sessionkey signingkey sshkey licensekey"
)
_CREDENTIAL_PAIRS = frozenset(
    tuple(pair.split("_"))
    for pair in _words(
        "api_key access_key secret_key private_key account_key signing_key ssh_key "
        "connection_string conn_str session_token session_key session_secret client_secret "
        "refresh_token access_token id_token auth_token bearer_token seed_phrase recovery_phrase"
    )
)
# A key that holds no secret: CACHE_KEY, SORT_KEY, IDEMPOTENCY_KEY.
_PLAIN_KEY_QUALIFIERS = _words(
    "cache sort partition primary foreign index row hash range shard lookup search order "
    "group composite candidate super natural surrogate unique idempotency dedup correlation "
    "routing aggregate shortcut site"
)
_QUALIFIED_KEY_LENGTH = 32
_ACCOUNT_KEY_QUALIFIERS = _words("primary routing")
# The last word describes a property of a credential, not the credential: API_KEY_ID,
# SECRET_NAME, TOKEN_PATH, PASSWORD_POLICY, --token-env.
_DESCRIPTORS = _words(
    "name id fingerprint audience issuer provider strategy method backend algorithm alg "
    "scope scopes policy endpoint url uri path file filename dir home type mode format "
    "version count limit size length ttl timeout expiry expires expiration interval env var "
    "variable header prefix suffix label description help hint usage source store manager "
    "region bucket arn role user username realm domain host port flag enabled required "
    "optional field column attribute hasher hashers complexity rules"
)
# A pass that is a stage, not a password: FIRST_PASS, COMPILER_PASS, PASS_THROUGH.
_PLAIN_PASS_WORDS = _words("first second third last final next compiler render multi single")
_PASS_CONTINUATIONS = frozenset({"through", "thru"})
_PUBLIC_WORDS = _words("publishable public pub verify verification")
_JWT_PUBLIC_WORDS = _words("anon anonymous public publishable pk")
_PUBLIC_JWT = re.compile(r"(?:[Bb]earer\s+)?eyJ[\w-]+\.[\w-]+\.[\w-]*")
_PASSWORD_WORDS = _words("password passwd passphrase pass pw pswd psw")
# An owner after a password or key word: DB_PASSWORD_ROOT, API_KEY_SERVICE, not AUTH_SERVICE.
_OWNERS, _OWNED = _words("root service"), _PASSWORD_WORDS | {"key"}
_PASSWORD_ENDINGS = _word_tuple("password passwd passphrase pw pswd")
# BIP39: 12 to 24 words, in steps of three, under a mnemonic or seed phrase name.
_MNEMONIC = re.compile(r"[a-z]{3,8}(?: [a-z]{3,8}){11}(?:(?: [a-z]{3,8}){3}){0,4}")
_MNEMONIC_WORDS = _words("mnemonic seedphrase phrase")
# Query parameters that carry paging or protocol state, never a credential.
_STATE_WORDS = _words("page next continuation pagination cursor csrf nonce state challenge")

# Public keys and certificates are published; a private key block among them is not.
_PUBLIC_PREFIXES = (
    "pk_",
    "phc_",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
    "ssh-rsa ",
    "ssh-ed25519 ",
    "-----BEGIN PUBLIC KEY-----",
    "-----BEGIN CERTIFICATE-----",
)

# A reference names where a credential comes from, whole or as part of the value.
# An opened ``${`` or ``$(`` is a reference even when shell word splitting cut it short:
# ``"${API_KEY:?set API_KEY}"`` reaches a word as ``${API_KEY:?set``.
_REFERENCE = re.compile(
    r"\$\{|\$\(|`[^`]{1,256}`|\$[A-Z][A-Z0-9_]{1,127}(?![A-Za-z0-9_])"
    r"|(?<![A-Za-z0-9])%[A-Za-z_][A-Za-z0-9_]{0,127}%(?![A-Za-z0-9])|\$env:"
    r"|\{\{[^{}]{0,256}\}\}|#\{[^{}]{0,256}\}"
    r"|(?<![A-Za-z0-9])\{[A-Za-z_][A-Za-z0-9_.:-]{0,127}\}(?![A-Za-z0-9])"
    r"|%\([A-Za-z_][A-Za-z0-9_]{0,127}\)[sdr]|__[A-Za-z][A-Za-z0-9_]{0,127}__"
    r"|@@[A-Za-z][A-Za-z0-9_]{0,127}@@"
)
_VARIABLE_NAME = re.compile(r"[A-Z]+(?:_[A-Z]+)+")
# A shell expansion with a default or alternate value (``${TOKEN:-x}``, ``:=``, ``-``,
# ``=``, ``:+``, ``+``): the text after the operator is in the file, so a literal
# there is committed. ``:?`` carries a message, not a value.
_SHELL_DEFAULT = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]{0,127})(?::?[-=+])((?:[^{}\\]|\\.){1,8192})\}"
)
# A shell variable in lower case (``$api_token``) names one too, but under a password
# name ``$hunter_two_pw`` is as likely a password: there only ``$NAME`` is a reference.
_SHELL_VARIABLE = re.compile(r"\$(?:[a-z][a-z0-9]{0,63}(?:_[a-z0-9]{1,63}){1,8}|[a-z]{1,64})")
# A negated flag takes no value: --no-password.
_NEGATIONS = frozenset({"no", "without"})
# A dotted module or attribute path: fastmcp.server.auth.providers.github.GitHubProvider.
_DOTTED_PATH = re.compile(r"[a-z_][a-z0-9_]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){2,16}")
_CODE_READ = re.compile(
    r"(?:process\.env|Bun\.env|Deno\.env|import\.meta\.env|os\.environ|os\.getenv|getenv"
    r"|ENV\[|System\.getenv|settings\.|secrets\.|config\.|env\.)"
)
# A call, chained or cut short at a quote: fs.readFileSync(p).toString(), keyring.get_password(.
_CALL = re.compile(
    r"[A-Za-z_][\w.]{0,63}\([^()]{0,256}\)(?:\.[A-Za-z_]\w{0,63}(?:\([^()]{0,256}\))?){0,8}"
)
_OPEN_CALL = re.compile(r"[A-Za-z_]\w{0,63}(?:\.[A-Za-z_]\w{0,63}){1,8}\([^()]{0,256}")
_STORE_SCHEMES = _words(
    "vault op arn sm secretsmanager secret secrets secretref secretkeyref keyvault "
    "azurekeyvault akv gcpsm gsm awssm ssm parameterstore env file k8s kubernetes doppler "
    "infisical bitwarden bw credstash chamber sops keyring keychain gopass pass berglas hcp "
    "conjur cyberark akeyless 1password projects"
)
_STORE_REFERENCE = re.compile(r"([A-Za-z0-9][A-Za-z0-9-]{0,31})(?::|/)")
_STORE_PREFIXES = ("@microsoft.keyvault(", "enc[")

_PATH_START = re.compile(
    r"(?i)(?:\./|\.\./|~|\\\\|\.\\|[a-z]:[\\/]|file://|%(?:userprofile|appdata|localappdata|home)%)"
)
_FILE_SUFFIX = re.compile(
    r"(?i)\.(?:json|pem|crt|cer|key|p8|p12|pfx|der|txt|yaml|yml|toml|ini|cfg|conf|env|db"
    r"|sqlite|sock|jks|keystore|pub|asc|gpg|log)\Z"
)
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._-]{1,255}")
_PATH_SEPARATOR = re.compile(r"[/\\]")
_RANDOM_SEGMENT = 12
_BASE64_SEGMENT = re.compile(r"[A-Za-z0-9+]+={0,2}")
_ASCII_UPPER = frozenset(string.ascii_uppercase)
_ASCII_LOWER = frozenset(string.ascii_lowercase)
_ASCII_DIGITS = frozenset(string.digits)
_KEY_FILE = re.compile(
    r"(?i)id_(?:rsa|ed25519|ecdsa|dsa)(?:_sk)?(?:\.pub)?|known_hosts|authorized_keys"
)
_PATH_WORDS = _words(
    "keys key certs cert ssl tls secrets credentials config .ssh .config .aws .gnupg etc "
    "home var opt usr tmp"
)
_NUMBER = re.compile(r"(?i)[+-]?\d+(?:[.,_]\d+)*(?:ms|s|m|h|d|k|kb|mb|gb)?")
_VERSION = re.compile(r"(?i)v?\d++(?:\.\d++)++(?:[-+][0-9a-z.-]++)?+|v\d++")
_WORD_VALUES = _words("true false yes no on off null none nil undefined")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}")
_MAILBOX = re.compile(r"[A-Za-z0-9._%+-]{2,64}@(?:[A-Za-z-]{1,63}\.)+[A-Za-z]{2,63}")
_IMAGE = re.compile(
    r"(?:docker://|oci://|containers-storage:)?[a-z0-9][a-z0-9./_-]{0,255}"
    r"(?:(?::[A-Za-z0-9._-]{1,128})?@sha256:[0-9a-f]{12,64}"
    r"|:(?:latest|stable|edge|v?\d++(?:[-._][A-Za-z0-9]++)*+))"
)
# A repository with a namespace takes any tag: acme/token-server:main.
_NAMESPACED_IMAGE = re.compile(
    r"[a-z0-9][a-z0-9._-]{0,127}(?:/[a-z0-9._-]{1,128}){1,8}:([\w.-]{1,128})"
)
_URN = re.compile(r"(?i)urn:[a-z0-9][a-z0-9-]{0,31}:\S{1,2048}")
_DURATION = re.compile(r"P(?:\d+[YMWD])*(?:T(?:\d+[HMS])+)?|(?:\d+(?:ms|[wdhms])){2,6}")
# ISO 8601 and RFC 3339 dates and times, a time of day, and RFC 2822 dates.
_DATE = re.compile(
    r"(?i)\d{4}-?(?:\d{2}-?\d{2}|\d{3}|w\d{2}(?:-?\d)?)"
    r"(?:[t _]?\d{2}[:-]?\d{2}(?:[:-]?\d{2}(?:[.,]\d{1,9})?)?)?(?:z|[+-]\d{2}:?\d{2})?"
    r"|\d{1,2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?|(?:[a-z]{3}, ?)?\d{1,2}[ -][a-z]{3}[ -]\d{4}"
    r"(?: \d{2}:\d{2}(?::\d{2})?)?(?: (?:[+-]\d{4}|[a-z]{1,5}))?"
)
_PACKAGE = re.compile(
    r"(?:@[a-z0-9._-]{1,214}/)?[a-z0-9._-]{1,214}"
    r"(?:@(?:[~^]?v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?|latest|next)"
    r"|(?:==|>=|<=|~=|!=|>|<)[\w.*+!-]{1,64})"
)
# A bare host has a dot and a letter-only last label, or is localhost; a port or a
# path after it makes a locator. A single word is never a host.
_HOST = re.compile(
    r"(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,16}[a-z]{2,24}|localhost)"
    r"(?::\d{1,5})?(?:/\S{0,2048})?"
)
_HOST_PORT = re.compile(r"[A-Za-z0-9.-]{1,253}:(\d{1,5})(?:/\S{0,2048})?")
_PORT_PATH = re.compile(r"\d{1,5}(?:/\S{0,2048})?")
_PLAIN_PORT_PATH = re.compile(r"\d{1,5}(?:/[\w./-]{0,2048})?")
_PORT_OR_PATH = re.compile(r"[^:/]*[:/]")
# NAME=VALUE options and flags of plain characters (sslmode=require, SameSite=Lax;Secure);
# a lone pair needs a key of three or more characters: T=/0NbJ and Kq=7mZw9x are passwords.
_OPTION = r"[A-Za-z][\w.-]{0,63}(?:=[\w./:@+-]{0,256})?"
_OPTION_LIST = re.compile(
    rf"(?=[^=]*=)(?:{_OPTION}(?:[,;&] ?{_OPTION})+|[A-Za-z][\w.-]{{2,63}}=[\w./:@+-]{{1,256}})"
)

_PLACEHOLDER_MARK = re.compile(r"<([^<>]{0,256})>|\[([^\[\]]{0,256})\]|\.\.\.|…")
# Inside a value, a mark holds a word or phrase (<token-1>) or a character class
# ([0-9]); aB3[x9]Kq7 is a password.
_PLACEHOLDER_PHRASE = re.compile(
    r"[a-z]{2,}(?:[ _-][a-z0-9]+)*|[A-Z]{2,}(?:[ _-][A-Z0-9]+)*|(?:\w-\w)+_?"
)
_PLACEHOLDER_WORDS = _words(
    "your here paste enter insert replace changeme change placeholder example sample dummy "
    "todo tbd fixme goes from dashboard settings console portal my test dev local "
    "development only fake mock stub demo foo bar baz dein hier einfuegen schluessel "
    "ejemplo exemple"
)
# Long enough that a random value holds one only by design, so they count inside a
# word: AKIAIOSFODNN7EXAMPLE, ghp_REPLACEWITHYOURTOKEN.
_PLACEHOLDER_INFIXES = ("example", "replace", "placeholder", "changeme")
_DEFAULT_VALUES = _words(
    "none null nil undefined unused notneeded notrequired notset disabled optional na empty "
    "default test dummy sample example placeholder changeme password postgres admin secret "
    "token string value redacted hidden omitted xxx todo tbd"
)
_SPACE = re.compile(r"\s")
_VALUE_WORDS = re.compile(r"[^\W_]+", re.UNICODE)
_NUMBERED_WORD = re.compile(r"([^\W\d_]+)\d+")
_CAMEL_WORD = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
_PROPER_CAMEL = re.compile(r"[A-Za-z][a-z]+(?:[A-Z][a-z]+)+")
# A label may start with a known acronym (OAuthClientCredentials); a random run of
# letters may start with any capitals, so only these are read as words.
_ACRONYM_CAMEL = re.compile(
    r"(?:OAuth|OIDC|SAML|JWT|JWK|API|SSO|MFA|AWS|GCP|HTTP|URL)(?:[A-Z][a-z]+)+"
)
_ALPHA_RUN = re.compile(r"[^\W\d_]+")
# Inside a random token a camelCase run of short words turns up by chance.
_INNER_WORD_LENGTH = 4
_PHRASE_SEPARATORS = re.compile(r"[-_.:,\s]+")
# A word, a word with digits after it (sha256, oauth2) or a numeronym (k8s, i18n).
_PHRASE_WORD = re.compile(r"[^\W\d_]{1,12}\d{0,6}|[a-z]\d{1,2}[a-z]")
_PHRASE_NUMBER = re.compile(r"\d{1,4}[dhkmswy]?|v\d{1,4}")
_SETTING = re.compile(r"[a-z0-9]{1,15}(?:[-_.:][a-z0-9]{1,15}){1,7}")
_PHRASE_LENGTH = 32
_SETTING_LENGTH = 16
_RUN_LENGTH = 6
_RUN = re.compile(
    "|".join(
        [r"(.)\1{5}"]
        + [("0123456789" * 2)[i : i + 6] for i in range(10)]
        + [string.ascii_lowercase[i : i + 6] for i in range(21)]
    )
)
_PASSPHRASE_WORDS = 3
_PASSPHRASE_LENGTH = 16
# A sentence holds these; a passphrase of random words seldom does.
_PROSE_WORDS = _words(
    "a an the by in on of to for from with via and or is are be it as at if this that use set see"
)
_COOKIE_PAIR = re.compile(r"([A-Za-z0-9_.-]{1,64})=([^\s;,\"']{1,8192})")
_COOKIE_ATTRIBUTES = _words("path domain samesite max-age expires priority version")
_COOKIE_HEADERS = frozenset({"cookie", "set-cookie"})
# A short cookie value counts only under a session or credential name; analytics and
# preference cookies (_ga, _gid, theme, tz) hold none.
_COOKIE_LENGTH = 16
_SESSION_COOKIE_WORDS = _words("sid session sess auth token jwt remember login connect")
_ANALYTICS_COOKIES = ("_ga", "_gid", "_gat", "_gcl", "_fbp", "_fbc", "_hj", "_uet", "ajs_", "_pk")
_CHALLENGE = re.compile(r"(?i)(?:realm|charset|scope|error)=")
_CONNECTION_PAIR = re.compile(r"\s*([A-Za-z][A-Za-z0-9 _.-]{0,40}?)\s*=(.*)", re.DOTALL)
_CONNECTION_KEYS = _words("password pwd secret token apikey accesskey sharedaccesskey accountkey")
_CONNECTION_PASSWORDS = frozenset({"password", "pwd"})
# libpq's keyword form: host=db user=app password=x dbname=app.
_KEYWORD_PAIR = re.compile(r"([A-Za-z_][A-Za-z0-9_]{0,40})=(\S{1,8192})")
_KEYWORD_PAIRS = range(3, 65)
# A comma may sit in user information, before the "@": postgres://app:p,w@db/app.
_LOCATOR = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}://"
    r"(?:[^\s/?#@\"'<>]{0,256}@)?[^\s,\"'<>]{1,4096}"
)
_ASSIGNMENT = re.compile(
    r"(?<![\w$])(?:--?|/)?([A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?[ \t]{0,8}[:=](?![=>])[ \t]{0,8}"
    r"(\"[^\"\n]{0,8192}\"|'[^'\n]{0,8192}'|[^\s,;\"'&|]{1,8192})"
)
_NETRC_WORDS = frozenset({"password", "passwd"})
_BASE64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_ENCODED_LIMIT = 65536
_KEY_WRAP_CHARS = frozenset("\u200b\ufeff\u2060\u200c\u200d\u00ad")
_KEY_WRAP = re.compile(r"[\s\u200b\ufeff\u2060\u200c\u200d\u00ad]+")
_KEY_PREFIX_LENGTH = 16
_WRAP_COMPARISON_FACTOR = 64
JSON_LIMIT = 65536
JSON_DEPTH = 8


def name_words(name: str) -> list[str]:
    """The lower-case words of ``name``, digits dropped: X-Api-Key reads as x, api, key."""
    return [word.lower() for word in _NAME_PARTS.split(name) if word and not word.isdigit()]


def credential_name(name: str) -> bool:
    """Whether ``name`` names a credential, by its words rather than by a substring.

    API_TOKEN, apiKey, X-Api-Key, PGPASSWORD, DB_PASS and KEY do; TOKENIZER,
    SECRET_NAME, TOKEN_PATH, CACHE_KEY and STRIPE_PUBLISHABLE_KEY do not.
    """
    stripped = name.strip().strip("\"'")
    if stripped == "-k":
        return True
    words = name_words(stripped)
    if not words or words[-1] in _DESCRIPTORS or not _PUBLIC_WORDS.isdisjoint(words):
        return False
    if words[-1] in _OWNERS and _OWNED.isdisjoint(words[-2:-1]):
        return False
    if len(words) > 1 and words[0] in _NEGATIONS:
        return False
    if words == ["key"]:
        return True
    for index, word in enumerate(words):
        if word == "pass" and _plain_pass(words, index):
            continue
        if word in _CREDENTIAL_WORDS or word in _COMPOUND_KEYS:
            return True
        if word.endswith(_COMPOUND_ENDINGS) and word not in _COMPOUND_ENDINGS:
            return True
    if any(pair in _CREDENTIAL_PAIRS for pair in zip(words, words[1:], strict=False)):
        return True
    return len(words) > 1 and words[-1] == "key" and not _plain_key(words)


def _plain_pass(words: list[str], index: int) -> bool:
    """A ``pass`` that names a stage or a passage: FIRST_PASS, PASS_THROUGH_HEADERS."""
    following = words[index + 1] if index + 1 < len(words) else ""
    return following in _PASS_CONTINUATIONS or (index > 0 and words[index - 1] in _PLAIN_PASS_WORDS)


def password_name(name: str) -> bool:
    """Whether ``name`` names a password or passphrase, under which word phrases count."""
    words = name_words(name)
    return credential_name(name) and any(
        (word in _PASSWORD_WORDS and not (word == "pass" and _plain_pass(words, index)))
        or word.endswith(_PASSWORD_ENDINGS)
        for index, word in enumerate(words)
    )


def _passphrase_name(name: str) -> bool:
    words = name_words(name)
    return bool(words) and (words[-1] in _PASSWORD_WORDS or words[-1].endswith(_PASSWORD_ENDINGS))


def _spaced(text: str) -> bool:
    return _SPACE.search(text) is not None


def _strip(value: str) -> str:
    return value.strip().strip("\"'").strip()


def public_material(value: str) -> bool:
    """Whether ``value`` is a public key or certificate, published by design."""
    return value.lstrip().startswith(_PUBLIC_PREFIXES) and not private_key_block(value)


def reference(value: str) -> bool:
    """Whether ``value`` names where a credential comes from, in part or whole."""
    if _REFERENCE.search(value) or "<%=" in value or _CODE_READ.match(value):
        return True
    if any(form.fullmatch(value) for form in (_VARIABLE_NAME, _CALL, _OPEN_CALL, _DOTTED_PATH)):
        return True
    if value.lower().startswith(_STORE_PREFIXES):
        return True
    store = _STORE_REFERENCE.match(value)
    if store is not None and store.group(1).lower() in _STORE_SCHEMES:
        return True
    return value.startswith("@") and _path(value[1:])


def _runs(value: str) -> int:
    """Characters in runs of six or more repeated or ascending characters (9 wraps to 0)."""
    lowered = value.lower()
    if _RUN.search(lowered) is None:
        return 0
    covered = 0
    index = 0
    while index < len(lowered):
        same = index + 1
        while same < len(lowered) and lowered[same] == lowered[index]:
            same += 1
        ascending = index + 1
        while ascending < len(lowered) and _successor(lowered[ascending - 1]) == lowered[ascending]:
            ascending += 1
        longest = max(same, ascending) - index
        if longest >= _RUN_LENGTH:
            covered += longest
            index += longest
        else:
            index += 1
    return covered


def _successor(character: str) -> str:
    if character == "9":
        return "0"
    if character.isascii() and character.isalnum() and character != "z":
        return chr(ord(character) + 1)
    return ""


def _value_words(value: str) -> list[str]:
    """The words of ``value``: parts between separators, camelCase words, and the word
    before a number (``test1234``). A random token is not split between its letters
    and digits, where a short word such as ``my`` or ``dev`` would turn up by chance.
    """
    words: list[str] = []
    for part in _VALUE_WORDS.findall(value):
        numbered = _NUMBERED_WORD.fullmatch(part)
        piece = numbered.group(1) if numbered is not None else part
        if _PROPER_CAMEL.fullmatch(piece):
            words.extend(_CAMEL_WORD.findall(piece))
            continue
        words.append(piece)
        if piece.isalpha():
            continue
        # YourGitHubTokenGoesHere1234567890ab: a camelCase run between digits.
        for run in _ALPHA_RUN.findall(piece):
            if _PROPER_CAMEL.fullmatch(run):
                words.extend(
                    word for word in _CAMEL_WORD.findall(run) if len(word) >= _INNER_WORD_LENGTH
                )
    return [word.lower() for word in words]


def placeholder(value: str) -> bool:
    """Whether ``value`` is a placeholder or a documented default, not a real credential."""
    for mark in _PLACEHOLDER_MARK.finditer(value):
        inner = mark.group(1) if mark.group(1) is not None else mark.group(2)
        if mark.span() == (0, len(value)) or inner is None or _PLACEHOLDER_PHRASE.fullmatch(inner):
            return True
        if not _PLACEHOLDER_WORDS.isdisjoint(_value_words(inner)):
            return True
    lowered = value.lower()
    if any(infix in lowered for infix in _PLACEHOLDER_INFIXES):
        return True
    # Placeholder words make up the value, not one segment among random ones.
    found = sum(word in _PLACEHOLDER_WORDS for word in _value_words(value))
    if found and found >= sum(map(credential_shaped, _VALUE_WORDS.findall(value))):
        return True
    if re.sub(r"[-_.\s]+", "", lowered) in _DEFAULT_VALUES:
        return True
    return 2 * _runs(value) >= len(value)


def _path(value: str) -> bool:
    if not value or _spaced(value):
        return False
    if _PATH_START.match(value) or _FILE_SUFFIX.search(value) or _KEY_FILE.fullmatch(value):
        return True
    segments = _PATH_SEPARATOR.split(value)
    # Base64 holds "/" too: a segment of random letters and digits is not a directory.
    if len(segments) > 1 and any(_random_segment(segment) for segment in segments):
        return False
    if value.startswith("/"):
        return "/" in value[1:]
    if len(segments) < 2 or not all(_PATH_SEGMENT.fullmatch(segment) for segment in segments):
        return False
    return any(
        (segment.isalpha() and segment.islower() and len(segment) >= 3)
        or segment.lower() in _PATH_WORDS
        or _KEY_FILE.fullmatch(segment) is not None
        for segment in segments
    )


def _random_segment(segment: str) -> bool:
    """A segment of base64: 12 or more letters and digits in both cases, and ``+`` or ``=``."""
    return (
        len(segment) >= _RANDOM_SEGMENT
        and _BASE64_SEGMENT.fullmatch(segment) is not None
        and not _ASCII_UPPER.isdisjoint(segment)
        and not _ASCII_LOWER.isdisjoint(segment)
        and not _ASCII_DIGITS.isdisjoint(segment)
    )


def _locator_or_value(value: str, *, password: bool = False) -> bool:
    """A path, number, version, image, package, host, port, e-mail or flag word.

    Under a password name a dotted word is a host only with a port or a path after it,
    and an address only with two or more characters before the "@" and no digit after
    it: ``p4ssw0rd.secure`` and ``p@ssw0rd.secure`` are passwords.
    """
    if _path(value):
        return True
    lowered = value.lower()
    if lowered in _WORD_VALUES or any(
        form.fullmatch(value) for form in (_NUMBER, _VERSION, _DURATION, _URN, _IMAGE, _PACKAGE)
    ):
        return True
    if _EMAIL.fullmatch(value) and not (password and _MAILBOX.fullmatch(value) is None):
        return True
    image = _NAMESPACED_IMAGE.fullmatch(value)
    if image is not None and not _random_segment(image.group(1)):
        return True
    # Base64 holds "/": a random segment is not a port's or a host's path.
    segments = _PATH_SEPARATOR.split(value)
    if len(segments) > 1 and any(_random_segment(segment) for segment in segments):
        return False
    host = _HOST.fullmatch(value)
    if host is not None and not (password and _PORT_OR_PATH.match(value) is None):
        return True
    if (_PLAIN_PORT_PATH if password else _PORT_PATH).fullmatch(value):
        return True
    port = _HOST_PORT.fullmatch(value)
    return port is not None and int(port.group(1)) <= 65535


def _word_phrase(value: str) -> bool:
    """Two or more short words with at most one number: a setting or a label."""
    if len(value) > _PHRASE_LENGTH:
        return False
    tokens = []
    for part in filter(None, _PHRASE_SEPARATORS.split(value)):
        if _PROPER_CAMEL.fullmatch(part) or _ACRONYM_CAMEL.fullmatch(part):
            tokens.extend(_CAMEL_WORD.findall(part))
        else:
            tokens.append(part)
    numbers = sum(1 for token in tokens if _PHRASE_NUMBER.fullmatch(token))
    words = sum(1 for t in tokens if not _PHRASE_NUMBER.fullmatch(t) and _PHRASE_WORD.fullmatch(t))
    return words >= 2 and numbers <= 1 and words + numbers == len(tokens)


def _setting(value: str) -> bool:
    """A short lower-case setting such as ``cl100k_base`` or ``oauth2-pkce``."""
    return (
        len(value) < _SETTING_LENGTH
        and _SETTING.fullmatch(value) is not None
        and len(re.findall(r"\d+", value)) <= 1
        and any(char.isalpha() for char in value)
    )


def _foreign_script(value: str) -> bool:
    """Prose written in a script other than Latin: a placeholder in another language."""
    found = 0
    for char in value:
        if char.isalpha() and not char.isascii() and "LATIN" not in unicodedata.name(char, ""):
            found += 1
            if found >= 2:
                return True
    return False


def _passphrase(value: str) -> bool:
    """Three or more words of 16 or more characters, in any case, that are not a sentence."""
    words = value.split()
    return (
        len(words) >= _PASSPHRASE_WORDS
        and len(value) >= _PASSPHRASE_LENGTH
        and _PROSE_WORDS.isdisjoint(word.lower().strip(string.punctuation) for word in words)
    )


def literal_value(value: str, *, password: bool = False) -> bool:
    """Whether ``value``, under a name that marks a credential, reads as a literal one.

    A reference, placeholder, public key, path, locator, number or option list holds
    none; nor does prose, except a passphrase of three or more words and 16 or more
    characters, without a sentence's small words (by, the, in), under a passphrase or
    password name. Under any other credential name a word phrase, a short setting or a
    phrase in a non-Latin script is a label, not a literal. What remains must be credential-shaped: 16 or more characters, or a digit,
    credential punctuation or an upper-case letter after the first.
    """
    value = _strip(value)
    if len(value) < MIN_SECRET_LENGTH or all(map(_DATE.fullmatch, value.split("/", 1))):
        return False
    if _spaced(value) and not (password and _passphrase(value)):
        return False
    if "://" in value or public_material(value) or reference(value) or placeholder(value):
        return False
    if not password and _SHELL_VARIABLE.fullmatch(value) is not None:
        return False
    if _OPTION_LIST.fullmatch(value) or _locator_or_value(value, password=password):
        return False
    if not password and (_word_phrase(value) or _setting(value) or _foreign_script(value)):
        return False
    return credential_shaped(value)


def _token_hits(value: str) -> list[Hit]:
    return [
        (SHAPE_CLASS, match.group())
        for match in TOKEN_SHAPE.finditer(value)
        if not placeholder(match.group())
    ]


def _private_key(value: str) -> str | None:
    """Return the unpadded text to redact, unwrapped when the key is base64-encoded."""
    if private_key_block(value):
        return None if "..." in value or "…" in value else value.strip()
    if _putty_key(value):
        return value.strip()
    # base64 and openssl wrap their output at 76 and 64 columns by default.
    compact = _KEY_WRAP.sub("", value.strip())
    if len(compact) > _ENCODED_LIMIT or _BASE64.fullmatch(compact) is None:
        return None
    try:
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4))
    except (binascii.Error, ValueError):
        return None
    text = decoded.decode("utf-8", "replace")
    if private_key_block(text) or '"private_key"' in text or _putty_key(text):
        return compact
    return None


def private_key_forms(value: str) -> tuple[str, ...]:
    """Every form of a private key or base64-encoded private key to scrub from siblings."""
    key = _private_key(value)
    if key is None:
        return ()
    unpadded = key.rstrip("=")
    if unpadded and len(unpadded) >= 40 and _BASE64.fullmatch(key):
        return tuple(dict.fromkeys((value, value.strip(), key, unpadded)))
    return tuple(dict.fromkeys((value, value.strip(), key)))


def _putty_key(text: str) -> bool:
    return "PuTTY-User-Key-File-" in text and "Private-Lines:" in text


class WrappedKeySearchLimitError(ValueError):
    """A complete search for alternate wrapping would exceed the per-text work bound."""


def rewrapped_key_literals(document: Any, values: Iterable[str]) -> Iterable[str]:
    """Find differently wrapped copies without comparing every key with every field."""
    keys: set[str] = set()
    for value in values:
        compact = _private_key(value)
        if compact is not None and len(compact) <= _ENCODED_LIMIT and _BASE64.fullmatch(compact):
            keys.add(compact.rstrip("="))
    if not keys:
        return
    shortest = min(map(len, keys))
    # Anchor on each key's midpoint rather than its header prefix: standard PEM,
    # OpenSSH, PuTTY and GCP JSON keys share constant 16-char base64 prefixes.
    grouped: dict[str, set[tuple[int, int]]] = {}
    for key in keys:
        offset = len(key) // 2
        grouped.setdefault(key[offset : offset + _KEY_PREFIX_LENGTH], set()).add((offset, len(key)))
    anchors = {anchor: sorted(specs) for anchor, specs in grouped.items()}

    pending = [document]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            pending.extend(node.keys())
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, str) and len(node) >= shortest and _KEY_WRAP.search(node):
            compact = _KEY_WRAP.sub("", node)
            if len(compact) < shortest:
                continue
            budget = _WRAP_COMPARISON_FACTOR * len(node)
            offsets = None
            for mid in range(len(compact) - _KEY_PREFIX_LENGTH + 1):
                for offset, size in anchors.get(compact[mid : mid + _KEY_PREFIX_LENGTH], ()):
                    start = mid - offset
                    end = start + size
                    if start < 0 or end > len(compact):
                        continue
                    # Account for slicing and hashing even if an anchor is shared by
                    # many lengths. Never return a partial set as a complete search.
                    budget -= size
                    if budget < 0:
                        raise WrappedKeySearchLimitError
                    if compact[start:end] not in keys:
                        continue
                    if offsets is None:
                        offsets = array(
                            "I",
                            (
                                i
                                for i, c in enumerate(node)
                                if not (c.isspace() or c in _KEY_WRAP_CHARS)
                            ),
                        )
                    pad = 0
                    while pad < 2 and end + pad < len(compact) and compact[end + pad] == "=":
                        pad += 1
                    first, last = offsets[start], offsets[end + pad - 1] + 1
                    if last - first > size + pad:
                        budget -= last - first
                        if budget < 0:
                            raise WrappedKeySearchLimitError
                        yield node[first:last]


def _json_hits(value: str) -> list[Hit]:
    """Hits of each string leaf of a JSON object or array, read under its key."""
    stripped = value.strip()
    if not stripped.startswith(("{", "[")) or len(stripped) > JSON_LIMIT:
        return []
    try:
        document = json.loads(stripped)
    except (ValueError, RecursionError):
        return []
    hits: list[Hit] = []
    pending: list[tuple[str, Any, int]] = [("", document, 0)]
    while pending:
        key, node, depth = pending.pop()
        if isinstance(node, str):
            hits.extend(value_hits(key, node, header=_header_name(key)))
        elif depth < JSON_DEPTH and isinstance(node, dict):
            pending.extend((str(name), item, depth + 1) for name, item in node.items())
        elif depth < JSON_DEPTH and isinstance(node, list):
            pending.extend((key, item, depth + 1) for item in node)
    return hits


def _header_name(name: str) -> bool:
    return authorization_header(name) or name.strip().lower() in _COOKIE_HEADERS


def _connection_hits(value: str) -> list[Hit]:
    """The credential pairs of a ``key=value;key=value`` connection string.

    libpq's keyword form, three or more ``key=value`` words with a password among
    them, is read the same way. An ODBC value in braces (``Pwd={...}``) is unquoted.
    """
    if ";" in value:
        pairs = [_CONNECTION_PAIR.fullmatch(part) for part in value.split(";")]
        found = [(pair.group(1), pair.group(2)) for pair in pairs if pair is not None]
    else:
        split = value.split()
        if len(split) not in _KEYWORD_PAIRS:
            return []
        words = [_KEYWORD_PAIR.fullmatch(word) for word in split]
        if None in words:
            return []
        found = [(word.group(1), word.group(2)) for word in words if word is not None]
    if len(found) < 2:
        return []
    hits: list[Hit] = []
    for name, pair_value in found:
        key = re.sub(r"[\s_.-]+", "", name).lower()
        literal = _strip(pair_value)
        if literal.startswith("{") and literal.endswith("}"):
            literal = literal[1:-1]
        if key in _CONNECTION_KEYS and literal_value(
            literal, password=key in _CONNECTION_PASSWORDS
        ):
            hits.append((NAMED_CLASS, literal))
    return hits


def _phrase_or_placeholder(credential: str) -> bool:
    return reference(credential) or placeholder(credential) or _word_phrase(credential)


def _authorization_hits(value: str) -> list[Hit]:
    """An Authorization value: whatever its shape, unless a reference or a placeholder."""
    if reference(value):
        return []
    parts = scheme_parts(value)
    credential = parts[1] if parts is not None else value
    if len(credential) < MIN_SECRET_LENGTH or _phrase_or_placeholder(credential):
        return []
    if _foreign_script(credential):
        return []
    return [(SCHEME_CLASS if parts is not None else NAMED_CLASS, credential)]


def _scheme_hits(value: str) -> list[Hit]:
    """A scheme word and one credential-like word after it, under any name."""
    parts = scheme_parts(value)
    if parts is None:
        return []
    scheme, credential = parts
    if _spaced(credential) or len(credential) < MIN_SECRET_LENGTH:
        return []
    if _CHALLENGE.match(credential) is not None or _phrase_or_placeholder(credential):
        return []
    return [(SCHEME_CLASS, credential)] if scheme_credential_like(credential, scheme) else []


def _cookie_hits(value: str) -> list[Hit]:
    hits: list[Hit] = []
    for name, literal in _COOKIE_PAIR.findall(value):
        lowered = name.lower()
        if lowered in _COOKIE_ATTRIBUTES or lowered.startswith(_ANALYTICS_COOKIES):
            continue
        named = not _SESSION_COOKIE_WORDS.isdisjoint(name_words(name))
        if (named or len(literal) >= _COOKIE_LENGTH) and literal_value(literal):
            hits.append((NAMED_CLASS, literal))
    return hits


def _url_hits(value: str, *, userinfo: bool = True) -> list[Hit]:
    """A password in URL user information, or a credential-named query parameter."""
    hits: list[Hit] = []
    for locator in _LOCATOR.findall(value):
        try:
            parts = urlsplit(locator)
            password = parts.password
            host = parts.hostname or ""
            query = parse_qsl(parts.query.replace(";", "&"))
        except ValueError:
            continue
        if userinfo and password is not None and not host.startswith("sha256"):
            literal = unquote(password)
            if literal_value(literal, password=True):
                hits.append((NAMED_CLASS, literal))
        hits.extend(query_hits(query))
    return hits


def query_hits(query: list[tuple[str, str]]) -> list[Hit]:
    """Hits of credential-named query parameters, and token shapes under any parameter."""
    hits: list[Hit] = []
    for name, literal in query:
        shapes = _token_hits(literal)
        hits.extend(shapes)
        words = name_words(name)
        if shapes or not _STATE_WORDS.isdisjoint(words) or not credential_name(name):
            continue
        if literal_value(literal, password=password_name(name)):
            hits.append((NAMED_CLASS, _strip(literal)))
    return hits


def endpoint_hits(locator: str) -> list[Hit]:
    """Hits in the query of an endpoint URL; its user information is transport security's."""
    return _url_hits(locator, userinfo=False)


def _netrc_hits(value: str) -> list[Hit]:
    words = value.split()
    return [
        (NAMED_CLASS, words[index + 1])
        for index in range(len(words) - 1)
        if words[index].lower() in _NETRC_WORDS and literal_value(words[index + 1], password=True)
    ]


def assignment_hits(text: str, *, spaced: bool = False) -> list[Hit]:
    """Credential-named ``NAME=value`` and ``NAME: value`` assignments anywhere in ``text``.

    ``spaced`` reads only those that hold white space, which no single word holds.
    """
    hits: list[Hit] = []
    for match in _ASSIGNMENT.finditer(text):
        name, literal = match.group(1), match.group(2)
        if spaced and not _spaced(match.group()):
            continue
        if credential_name(name):
            hits.extend(value_hits(name, literal.strip("\"'")))
    return hits


def value_hits(name: str, value: str, *, header: bool = False) -> list[Hit]:
    """Each literal credential ``value`` holds at a position named ``name``.

    ``header`` marks a header name, under which an Authorization or Proxy-Authorization
    value counts whatever its shape and a Cookie value is read pair by pair.
    """
    if _PUBLIC_JWT.fullmatch(_strip(value)) and not _JWT_PUBLIC_WORDS.isdisjoint(name_words(name)):
        return []  # A JWT under an anon or public name is a key published by design.
    hits = _token_hits(value)
    if forms := private_key_forms(value):
        # A sibling can repeat the same key without the original field's padding or wrapping.
        hits.extend((NAMED_CLASS, form) for form in forms)
    stripped = _strip(value)
    if not stripped or public_material(stripped):
        return hits
    hits.extend(_json_hits(stripped))
    hits.extend(_connection_hits(stripped))
    hits.extend(_default_hits(name, stripped))
    if header and authorization_header(name):
        return hits + _authorization_hits(stripped)
    if header and name.strip().lower() in _COOKIE_HEADERS:
        return hits + (_cookie_hits(stripped) or _named_hits(name, stripped))
    hits.extend(_scheme_hits(stripped))
    if "://" in stripped:
        return hits + _url_hits(stripped)
    if _spaced(stripped):
        hits.extend(_netrc_hits(stripped))
    return hits + _named_hits(name, stripped)


def _default_hits(name: str, value: str) -> list[Hit]:
    """Literal defaults of shell expansions in ``value``, read by the rules for ``name``."""
    hits: list[Hit] = []
    for match in _SHELL_DEFAULT.finditer(value):
        var_name = match.group(1)
        default = match.group(2).strip(" \"'")
        if "$" in default or "`" in default:
            continue
        found = _named_hits(name, default)
        if not found and credential_name(var_name):
            found = _named_hits(var_name, default)
        hits.extend(found)
    return hits


def _named_hits(name: str, value: str) -> list[Hit]:
    words = name_words(name)
    if credential_name(name):
        if literal_value(value, password=_password_or_phrase(name, value)):
            return [(NAMED_CLASS, value)]
        phrase = " ".join(value.lower().split())
        if _MNEMONIC.fullmatch(phrase) and not _MNEMONIC_WORDS.isdisjoint(words):
            return [(NAMED_CLASS, value)]
    elif _plain_key(words) and words[-2] in _ACCOUNT_KEY_QUALIFIERS:
        # PRIMARY_KEY=id is a column; 32 random characters there are an account key.
        if len(value) >= _QUALIFIED_KEY_LENGTH and literal_value(value):
            return [(NAMED_CLASS, value)]
    return []


def _plain_key(words: list[str]) -> bool:
    return len(words) > 1 and words[-1] == "key" and words[-2] in _PLAIN_KEY_QUALIFIERS


def _password_or_phrase(name: str, value: str) -> bool:
    if _spaced(value):
        return _passphrase_name(name)
    return password_name(name)


def strongest(hits: Iterable[Hit]) -> str | None:
    """The strongest class among ``hits``."""
    found = {kind for kind, _ in hits}
    return next((kind for kind in CREDENTIAL_CLASSES if kind in found), None)
