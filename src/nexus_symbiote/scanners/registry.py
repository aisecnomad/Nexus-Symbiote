"""Offline registry references collected from bounded local manifests.

These declarations do not establish registry authenticity, resolved artifacts,
installed versions, or cryptographic verification.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import posixpath
import re
import shlex
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, NamedTuple
from urllib.parse import quote, unquote, urlsplit

from packageurl import PackageURL
from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, Specifier
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import extract_version_pin, hash_bytes, parse_json_strict
from nexus_symbiote.core.identifiers import reference_text
from nexus_symbiote.core.models import ClaimEvidence, RegistryEntryComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.credential_files import credential_gap, link_gap
from nexus_symbiote.scanners.mcp import (
    _npmrc,
    _origin_label,
    _registries,
    _setting_name,
    _uv_settings,
    _yarnrc,
    npm_registry_settings,
    npm_scope_registry,
)
from nexus_symbiote.scanners.mcp_launch import expands
from nexus_symbiote.utils.confined import ConfinedCollection, recorded_count
from nexus_symbiote.utils.secrets import (
    REDACTED,
    TOKEN_SHAPE,
    holds_token_shape,
    redact_text,
    redact_url,
)
from nexus_symbiote.utils.terminal import UNSAFE_TEXT
from nexus_symbiote.utils.toml import TOMLBoundsError
from nexus_symbiote.utils.toml import loads as load_toml

# The registry collector inventories only the packages these name, on PyPI and npm
# alike; docs/registry-collector.md lists them. A name is compared in its normal
# form, in which runs of "-", "_" and "." are one "-" and letters are lower case, as
# PEP 503 normalises a PyPI name. A name matches when it is listed whole in
# AI_PACKAGE_NAMES, when its npm scope is in AI_PACKAGE_SCOPES, or when the part
# after any scope starts with one of AI_PACKAGE_PREFIXES or has one of
# AI_PACKAGE_WORDS among its "-"-separated words. A prefix without a trailing "-"
# also matches longer names, as the patterns of earlier releases did.
AI_PACKAGE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "@aws-sdk/client-bedrock-agent-runtime",
        "@aws-sdk/client-bedrock-runtime",
        "@browserbasehq/stagehand",
        "@google-cloud/aiplatform",
        "@google-cloud/vertexai",
        "@google/adk",
        "@google/genai",
        "@google/generative-ai",
        "accelerate",
        "ag2",
        "agno",
        "ai",
        "ai21",
        "bitsandbytes",
        "browser-use",
        "camel-ai",
        "ctransformers",
        "deepspeed",
        "dspy",
        "e2b",
        "farm-haystack",
        "fireworks-ai",
        "flash-attn",
        "flax",
        "gguf",
        "griptape",
        "groq",
        "groq-sdk",
        "haystack-ai",
        "instructor",
        "jax",
        "jaxlib",
        "js-tiktoken",
        "lancedb",
        "letta",
        "mastra",
        "mcp",
        "mem0ai",
        "mlx",
        "node-llama-cpp",
        "onnx",
        "optimum",
        "paddlepaddle",
        "pyautogen",
        "pymilvus",
        "redisvl",
        "replicate",
        "sentencepiece",
        "together",
        "trl",
        "vertexai",
        "voyageai",
        "xformers",
    }
)
# npm scopes that hold a vendor's agent packages; every package in them matches.
AI_PACKAGE_SCOPES: Final[frozenset[str]] = frozenset(
    {
        "@a2a-js",
        "@ai-sdk",
        "@anthropic-ai",
        "@huggingface",
        "@lancedb",
        "@langchain",
        "@llamaindex",
        "@mastra",
        "@mistralai",
        "@mlc-ai",
        "@modelcontextprotocol",
        "@openai",
        "@pinecone-database",
        "@qdrant",
        "@smithery",
        "@tensorflow",
        "@tensorflow-models",
        "@xenova",
        "@zilliz",
    }
)
AI_PACKAGE_PREFIXES: Final[tuple[str, ...]] = (
    # The families earlier releases matched.
    "anthropic",
    "autogen",
    "chromadb",
    "cohere",
    "crewai",
    "faiss",
    "guardrails",
    "langchain",
    "llama-index",
    "mcp-",
    "nemo-guardrails",
    "openai",
    "pgvector",
    "pinecone",
    "qdrant",
    "rebuff",
    "safetensors",
    "tensorflow",
    "tokenizers",
    "torch",
    "transformers",
    "weaviate",
    # Agent frameworks, model SDKs and runtimes added since.
    "a2a-sdk",
    "agno-",
    "claude-agent-sdk",
    "claude-code-sdk",
    "diffusers",
    "dspy-",
    "e2b-",
    "fastmcp",
    "google-adk",
    "google-cloud-aiplatform",
    "google-genai",
    "google-generativeai",
    "huggingface",
    "keras",
    "langgraph",
    "langsmith",
    "letta-",
    "litellm",
    "llama-cpp",
    "llamaindex",
    "mistralai",
    "mlx-",
    "nemoguardrails",
    "ollama",
    "onnxruntime",
    "peft",
    "pydantic-ai",
    "semantic-kernel",
    "sentence-transformers",
    "smolagents",
    "strands-agents",
    "tiktoken",
    "vllm",
)
AI_PACKAGE_WORDS: Final[frozenset[str]] = frozenset({"llm", "mcp"})

# A container image is inventoried when its reference, in lower case, contains one
# of these strings or has one of the words among its parts.
AI_IMAGE_KEYWORDS: Final[tuple[str, ...]] = (
    # The keywords earlier releases matched.
    "llama",
    "model",
    "ollama",
    "tgi",
    "triton",
    "vllm",
    # Inference servers, vector stores and frameworks added since.
    "chroma",
    "huggingface",
    "litellm",
    "lmdeploy",
    "localai",
    "milvus",
    "onnxruntime",
    "pgvector",
    "pytorch",
    "qdrant",
    "sglang",
    "tensorflow",
    "text-embeddings-inference",
    "text-generation-inference",
    "weaviate",
)
AI_IMAGE_WORDS: Final[frozenset[str]] = frozenset({"mcp", "tei"})

_SEPARATORS = re.compile(r"[-_.]+")
_IMAGE_WORD = re.compile(r"[^a-z0-9]+")


def is_ai_image(reference: str) -> bool:
    """Whether a container image reference is one the collector inventories."""
    lowered = reference.lower()
    return any(keyword in lowered for keyword in AI_IMAGE_KEYWORDS) or not (
        AI_IMAGE_WORDS.isdisjoint(_IMAGE_WORD.split(lowered))
    )


class ImageReference(NamedTuple):
    """An image reference as the distribution reference grammar reads it."""

    domain: str
    path: str
    tag: str | None
    digest: str | None

    @property
    def repository(self) -> str:
        return f"{self.domain}/{self.path}"

    @property
    def pinned(self) -> bool:
        """Whether the digest is one Docker pulls and verifies: sha256, sha384 or
        sha512 in lower-case hex of the algorithm's length. Docker refuses any other
        digest the reference grammar admits."""
        return self.digest is not None and _PULLED_DIGEST.fullmatch(self.digest) is not None


_DOMAIN_COMPONENT = re.compile(r"[A-Za-z0-9]+(?:-+[A-Za-z0-9]+)*")
_PATH_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_DIGEST = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}")
_IPV6 = re.compile(r"\[[0-9A-Fa-f:.]+\]")
_PULLED_DIGEST = re.compile(r"sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128}")
# docker/distribution's longest reference: a 255-character name, a 128-character tag
# and a sha512 digest, with their separators.
_LONGEST_IMAGE = 255 + 1 + 128 + 1 + 135


def parse_image_reference(text: str) -> ImageReference | None:
    """Split an image reference as Docker does, or None if it is not one.

    The first path component is a registry host when it contains "." or ":", is
    "localhost" or has upper-case letters; otherwise the image is on Docker Hub,
    where a single-component name is in the library namespace.
    """
    if not text or len(text) > _LONGEST_IMAGE or not text.isascii():
        return None
    name, at, digest = text.partition("@")
    if at and _DIGEST.fullmatch(digest) is None:
        return None
    slash, colon = name.rfind("/"), name.rfind(":")
    tag = None
    if colon > slash:
        name, tag = name[:colon], name[colon + 1 :]
        if _TAG.fullmatch(tag) is None:
            return None
    parts = name.split("/")
    first = parts[0]
    if len(parts) > 1 and (
        "." in first or ":" in first or first == "localhost" or first != first.lower()
    ):
        if first.startswith("["):
            close = first.find("]") + 1
            host, rest = first[:close], first[close:]
            if not close or _IPV6.fullmatch(host) is None:
                return None
        else:
            host, separator, port = first.partition(":")
            rest = separator + port
            if not all(_DOMAIN_COMPONENT.fullmatch(label) for label in host.split(".")):
                return None
        if rest and not (rest[0] == ":" and rest[1:].isdigit() and len(rest) <= 6):
            return None
        domain, path = first.lower(), parts[1:]
    else:
        domain, path = "docker.io", parts
    if domain in ("index.docker.io", "registry-1.docker.io"):
        domain = "docker.io"
    if not path or not all(_PATH_COMPONENT.fullmatch(part) for part in path):
        return None
    if domain == "docker.io" and len(path) == 1:
        path = ["library", *path]
    return ImageReference(domain, "/".join(path), tag, digest if at else None)


_INDEX_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:.]{2,45}\]")


def _same_index(declared: str, recorded: str | None) -> bool:
    """Whether two index origins are the same, PyPI's spellings counted as one."""
    if recorded is None:
        return False
    if declared in _PYPI_ORIGINS or declared == _PYPI_ORIGIN:
        return recorded in _PYPI_ORIGINS or recorded == _PYPI_ORIGIN
    return declared.removesuffix(":443") == recorded.removesuffix(":443")


def _index_origin(value: object) -> str | None:
    """The origin of a lockfile's package index, or None when it cannot be established.

    Only a URL with a lower-case ``http://`` or ``https://`` scheme whose authority every
    URL parser reads the same way has one: no backslash, percent-escape, control character
    or text outside ASCII. The host is compared and recorded in lower case. urlsplit takes the host after the last ``@``, while WHATWG parsers,
    which uv uses, end the authority at a backslash. User information is dropped.
    """
    if not isinstance(value, str) or not value.isascii() or len(value) > 4096:
        return None
    if not value.startswith(("https://", "http://")):
        return None
    if any(c <= " " or c in "\\\x7f" for c in value):
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    netloc = parts.netloc.rpartition("@")[2]
    # Host names are case-insensitive, and Poetry writes a configured URL as typed.
    host = (netloc.rsplit(":", 1)[0] if port is not None else netloc).lower()
    if "%" in netloc or not _INDEX_HOST.fullmatch(host):
        return None
    candidate = f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")
    return None if _sensitive_origin(candidate) else candidate


def _sensitive_origin(origin: str | None) -> bool:
    """Whether a registry origin URL itself carries a credential or token shape."""
    return origin is not None and (
        redact_url(origin) == "[redacted-url]"
        or holds_token_shape(origin, require_sk_boundary=True)
    )


# A scheme-prefixed direct-reference URL without "//" (e.g., https:user:pass@host/path)
# is parsed by packaging but missed by patterns requiring "://". Single-letter prefixes
# (Windows drive letters), file:, and mailto: are excluded.
_NOSLASH_CREDENTIAL_URL = re.compile(
    r"(?<![A-Za-z0-9+.-])"
    r"(?!file:|mailto:)[A-Za-z][A-Za-z0-9+.-]++:"
    r"(?!//)"
    r"[^\s/\"'<>@:]*+:[^\s/\"'<>@:]++@"
    r"[^\s\"'<>]++",
    re.IGNORECASE,
)


def _redact_noslash_url(text: str) -> str:
    return _NOSLASH_CREDENTIAL_URL.sub("[redacted-url]", text) if "@" in text else text


def _url_origin(url: str) -> str:
    # The parsed URL as one token: a pattern over the whole line stops at a quote
    # and would leave the rest of the path, query or a credential behind.
    if "//" in url:
        return redact_url(url)
    if "@" in url and _NOSLASH_CREDENTIAL_URL.search(url):
        return "[redacted-url]"
    return redact_text(url)


def _unparsed(text: str) -> str:
    """Text with no reliable URL boundary, kept only up to the word holding its first //.

    Words end at an ASCII space or tab, as in a PEP 508 URL; any other character,
    including a quote, @, / or another space, may still belong to the URL.
    """
    cut = text.find("//")
    if cut < 0:
        return redact_text(_redact_noslash_url(text))
    while cut and text[cut - 1] not in " \t":
        cut -= 1
    return redact_text(_redact_noslash_url(text[:cut])) + "[redacted-url]"


def _identifier(text: str) -> tuple[str, bool]:
    """A package name, extra or image reference as the inventory records it, and whether
    a credential token was taken out of it.

    Only token shapes count: the assignment rules of free text would read a tag such as
    ``llama-token:1.0`` as a credential. A token glued to other text takes the whole
    identifier with it.
    """
    if not holds_token_shape(text, require_sk_boundary=True):
        return text, False
    shown = TOKEN_SHAPE.sub(REDACTED, text)
    return (REDACTED if holds_token_shape(shown, require_sk_boundary=True) else shown), True


def _recorded_requirement(requirement: Requirement) -> str:
    """A requirement as the inventory records it, with a direct URL reduced to its origin.

    The name and extras are PEP 508 identifiers and are kept as written unless they
    hold a credential; free text that could hold one is redacted, so a name that ends
    in a word such as "token" does not lose the version that follows it.
    """
    shown = sorted(_identifier(extra)[0] for extra in requirement.extras)
    extras = f"[{','.join(shown)}]" if shown else ""
    name = _identifier(requirement.name)[0]
    if requirement.url:
        text = f"{name}{extras} @ {_url_origin(requirement.url)}"
    else:
        text = name + extras + _unparsed(str(requirement.specifier))
    if requirement.marker:
        text += f" ; {_unparsed(str(requirement.marker))}"
    return text


# Real versions are short. packaging re-parses a clause's version on every
# comparison, so a declaration with a longer one is recorded but not compared.
_LONGEST_VERSION = 128
# The public index and its file host; any other origin qualifies a pkg:pypi package URL.
_PYPI_ORIGINS = frozenset({"https://pypi.org", "https://files.pythonhosted.org"})
# All root requirements*.txt files together, in characters and in logical lines: within
# the characters, parsing time grows with the lines.
_REQUIREMENTS_BUDGET = 4 * 1024 * 1024
_REQUIREMENTS_LINES = 100_000
# shlex builds a token one character at a time, so its cost grows with the square
# of a quoted word's length; option text this long is not read.
_LONGEST_OPTIONS = 16 * 1024
# tomllib keeps every prefix of a dotted key, so its cost grows with the square of
# a key's parts and with the file's size. Real files are tens of kilobytes and
# their keys have a handful of parts.
_PYPROJECT_BUDGET = 256 * 1024
# A pnpm lockfile holds about 40 YAML tokens per package, so a lockfile at the 4 MiB
# read limit is about 650,000. The bound refuses denser input before it is parsed.
_MAX_PNPM_LOCK_TOKENS = 1_000_000
_PNPM_NAME_END = re.compile("[@/]")
# The opening of one peer in a pnpm package key's suffix as pnpm writes it: an npm
# package name and the exact version it resolved to; or the hash of a patch applied
# to the package, which holds no peers of its own.
_PNPM_PEER = re.compile(
    r"\((?:(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*@"
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
    r"|patch_hash=[0-9a-z]{1,128}(?=\)))"
)


def _pointer_token(text: str) -> str:
    """``text`` as one reference token of a JSON pointer (RFC 6901)."""
    return text.replace("~", "~0").replace("/", "~1")


def _plain_pnpm_peers(suffix: str) -> bool:
    """Whether a pnpm package key's peer suffix names only packages, exact versions and
    patch hashes in balanced groups, which a locator can carry: a URL, a path or a
    credential cannot be told apart from the parentheses around it, and is not
    recorded."""
    depth = index = 0
    while index < len(suffix):
        if suffix[index] == ")" and depth:
            depth, index = depth - 1, index + 1
            continue
        match = _PNPM_PEER.match(suffix, index)
        if match is None:
            return False
        depth, index = depth + 1, match.end()
    return (
        depth == 0
        and redact_text(suffix) == suffix
        and not holds_token_shape(suffix, require_sk_boundary=True)
    )


_PNPM_PATCH_HASH = re.compile(r"\s*patch_hash")


# The order in which pnpm takes a package.json section's spec for a name it finds in
# several (getSpecFromPackageManifest); npm takes the last of _NPM_SECTIONS instead.
_PNPM_SECTION_ORDER: Final = (
    "optionalDependencies",
    "dependencies",
    "devDependencies",
    "peerDependencies",
)
# The order in which Yarn 1 takes a package.json section's spec for a name it finds in
# several: the first that is neither "" nor "*" (cleanDependencies).
_YARN_V1_SECTION_ORDER: Final = ("optionalDependencies", "dependencies", "devDependencies")
# The packages key pnpm reads for an importer's version reference, by lockfile major
# version: 5.x keys by path, 6.x by the reference with its peers, and 9.x by the exact
# version alone, its peers moving to the snapshots.
_PNPM_RECORD_KEYS: Final = {
    "5": "/{name}/{ref}",
    "6": "/{name}@{ref}",
    "9": "{name}@{version}",
}
# Every spelling of a record for one name and version that any of those formats uses.
_PNPM_KEY_SPELLINGS: Final = (
    "{name}@{ref}",
    "/{name}@{ref}",
    "{name}@{version}",
    "/{name}@{version}",
    "/{name}/{version}",
    "/{name}/{ref}",
)
# The spellings each format writes itself. pnpm 5 and 6 keep a record per peer context,
# so the same version with and without peers are siblings there, not decoys; pnpm 9
# moves the peers to the snapshots and writes no slash.
_PNPM_OWN_SPELLINGS: Final = {
    "5": frozenset({"/{name}/{version}", "/{name}/{ref}"}),
    "6": frozenset({"/{name}@{ref}", "/{name}@{version}"}),
    "9": frozenset({"{name}@{version}"}),
}


def _pnpm_patched(reference: str) -> bool:
    """Whether a pnpm version reference marks its own package as patched.

    pnpm writes the hash as a group after the version, among the peer groups, as in
    ``4.0.0(patch_hash=ab)(zod@3.23.8)``; a hash inside a peer's group is that peer's.
    A hash anywhere else, or in a reference whose parentheses do not balance, counts.
    """
    lowered = reference.lower()
    if "patch_hash" not in lowered:
        return False
    depth = 0
    for index, char in enumerate(lowered):
        if char == "(":
            depth += 1
            if depth == 1 and _PNPM_PATCH_HASH.match(lowered, index + 1):
                return True
        elif char == ")":
            depth -= 1
            if depth < 0:
                return True
        elif depth == 0 and lowered.startswith("patch_hash", index):
            return True
    return depth != 0


def _parsed(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _exact_pin(requirement: Requirement) -> tuple[str, object] | None:
    """A requirement's single exact version and the key pins are compared by.

    The same rule as extract_version_pin, which advisories apply, without its
    rejection of markers: a pin under a marker is still an exact version.
    """
    clauses = list(requirement.specifier)
    if requirement.url or len(clauses) != 1:
        return None
    clause = clauses[0]
    if (
        clause.operator not in ("==", "===")
        or "*" in clause.version
        or len(clause.version) > _LONGEST_VERSION
    ):
        return None
    version = _parsed(clause.version)
    if version is None or not clause.contains(version, prereleases=True):
        return None
    if clause.operator == "===":
        return clause.version, ("===", clause.version.lower())
    return clause.version, version


_POETRY_RANGE = re.compile(r"([\^~])[ \t]*([0-9]{1,64})(?:\.([0-9]{1,64}))?(?:\.([0-9]{1,64}))?")
# The characters of Poetry's constraint grammar. A constraint made only of them
# that is not translated is a condition left out; anything else is invalid.
_POETRY_CONSTRAINT = re.compile(r"[0-9A-Za-z.*+!_^~=<>|, \t-]*")
_PEP508_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_PLATFORM = re.compile(r"[A-Za-z0-9_.-]+")


def _poetry_specifier(text: str) -> str | None:
    """A Poetry version constraint as a PEP 440 specifier set, or None if not translated.

    A bare version is exact; ^ allows changes that keep the first non-zero part
    given, and ~ changes below the minor part, or below the major part if it is
    the only one given.
    """
    text = text.strip()
    if text in ("", "*"):
        return ""
    clauses: list[str] = []
    for part in (p.strip() for p in text.split(",")):
        ranged = _POETRY_RANGE.fullmatch(part)
        if ranged is not None:
            given = [g for g in ranged.groups()[1:] if g is not None]
            numbers = [int(g) for g in given]
            if ranged.group(1) == "~":
                bump = min(1, len(numbers) - 1)
            else:
                bump = next((i for i, n in enumerate(numbers) if n), len(numbers) - 1)
            upper = [*numbers[:bump], numbers[bump] + 1]
            clauses += [f">={'.'.join(given)}", f"<{'.'.join(map(str, upper))}"]
            continue
        if "0" <= part[:1] <= "9":
            part = "==" + part
        elif part[:1] == "=" and part[1:2] != "=":
            part = "=" + part
        try:
            Specifier(part)
        except InvalidSpecifier:
            return None
        clauses.append(part)
    return ",".join(clauses)


def _valid_marker(text: str) -> bool:
    try:
        Marker(text)
    except (InvalidMarker, RecursionError):
        return False
    return True


def _admits(clause: Specifier, text: str, version: Version | None) -> bool:
    """Whether a clause admits a pin, given as written and as parsed once."""
    if clause.operator == "===":
        # PEP 440 arbitrary equality compares the text, ignoring case; deciding it
        # here keeps the answer the same on every supported packaging release.
        return clause.version.lower() == text.lower()
    # Only arbitrary equality can name a version that is not PEP 440.
    return version is not None and clause.contains(version, prereleases=True)


def _satisfies(requirement: Requirement, text: str, version: Version | None) -> bool:
    """Whether a pin meets every clause of a requirement; a clause too long to
    compare is taken as not met."""
    clauses = list(requirement.specifier)
    return all(
        len(clause.version) <= _LONGEST_VERSION and _admits(clause, text, version)
        for clause in clauses
    )


class _Declared:
    """What a package's declarations under one set of markers require together.

    Pins are kept once per version and range clauses once each, so a declaration
    costs a pass over the ranges only when it brings a new pin, and pins that do
    not conflict with each other are few. With versions bounded in length, the
    work is linear in the size of the files read.
    """

    def __init__(self) -> None:
        self.pins: dict[object, tuple[Specifier, str, Version | None]] = {}
        self.ranges: set[Specifier] = set()
        self.origins: set[str] = set()
        self.plain = False

    def add(self, requirement: Requirement) -> bool:
        """Record a declaration; whether it cannot hold with an earlier one."""
        if requirement.url:
            # Only the origin is kept (paths and queries can carry credentials).
            origin = _url_origin(requirement.url)
            conflict = self.plain or bool(self.origins - {origin})
            self.origins.add(origin)
            return conflict
        clauses = list(requirement.specifier)
        if any(len(clause.version) > _LONGEST_VERSION for clause in clauses):
            return False
        conflict = bool(self.origins)
        self.plain = True
        exact = [c for c in clauses if c.operator in ("==", "===") and not c.version.endswith(".*")]
        pin = exact[0] if len(exact) == 1 else None
        for clause in clauses:
            if clause is pin or clause in self.ranges:
                continue
            if any(not _admits(clause, text, parsed) for _, text, parsed in self.pins.values()):
                conflict = True
            self.ranges.add(clause)
        if pin is not None:
            text, parsed = pin.version, _parsed(pin.version)
            key: object = (
                ("===", text.lower()) if pin.operator == "===" or parsed is None else parsed
            )
            if key not in self.pins:
                # Two pins conflict only when neither admits the other: ==2.3.0
                # admits the local build 2.3.0+cu121 that a lock file records.
                if any(
                    not (_admits(pin, known, known_parsed) or _admits(clause, text, parsed))
                    for clause, known, known_parsed in self.pins.values()
                ) or any(not _admits(clause, text, parsed) for clause in self.ranges):
                    conflict = True
                self.pins[key] = (pin, text, parsed)
        return conflict


@dataclass
class _PipDeclaration:
    """One declaration of an inventoried PyPI package, as read and as recorded."""

    name: str
    source: str
    reference: str
    recorded: str
    spec: str | None
    group: str = ""
    requirement: Requirement | None = None
    # Why the declaration does not state what is installed: a Poetry or uv source,
    # another index, an untranslated condition, an override or invalid input.
    untranslated: str | None = None
    hashes: tuple[str, ...] = ()
    marker: str = ""
    sensitive_marker: bool = False
    pin: str | None = None
    pin_key: object = None
    # The name or an extra held a credential and is recorded redacted.
    redacted: bool = False


@dataclass
class _Package:
    """Every declaration of one PyPI package, and whether two of them conflict."""

    declarations: list[_PipDeclaration] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    seen: set[tuple[str, str, str]] = field(default_factory=set)
    states: dict[tuple[str, str], _Declared] = field(default_factory=dict)
    conflict: bool = False

    @property
    def representative(self) -> _PipDeclaration:
        """The unconditional pin, or the first declaration when no such pin exists."""
        return next(
            (d for d in self.declarations if d.pin is not None and not d.marker),
            self.declarations[0],
        )

    def add(self, declaration: _PipDeclaration) -> None:
        # One component per package across manifests. Every declaration is kept
        # on it, so a change to any of them changes the inventory and its diff.
        self.sources.add(f"{declaration.source}: {declaration.recorded}")
        first = not self.declarations
        self.declarations.append(declaration)
        requirement = declaration.requirement
        # A text is compared once in each state, not only in the first that holds it.
        key = (declaration.marker, declaration.group, declaration.reference)
        if (
            self.conflict
            or requirement is None
            or declaration.untranslated is not None
            or key in self.seen
        ):
            return
        self.seen.add(key)
        # Declarations under different markers apply to different environments
        # (uv writes platform splits that way), and so do different optional-
        # dependency groups (uv's cpu and cu121 extras), so only equal ones are
        # compared.
        state = self.states.setdefault((declaration.marker, declaration.group), _Declared())
        if state.add(requirement) and not first:
            self.conflict = True


def _risk(
    severity: RiskSeverity, category: str, detail: str, recommendation: str
) -> RiskAssessment:
    return RiskAssessment(
        severity=severity, category=category, detail=detail, recommendation=recommendation
    )


def _identifier_risk(subject: str, where: str) -> RiskAssessment:
    return _risk(
        RiskSeverity.HIGH,
        "credential_exposure",
        f"{subject} holds a literal credential in its {where}; the inventory records it "
        "redacted and claims no package identity for it.",
        "Remove the credential from the declaration and rotate it: it is committed.",
    )


def _npm_exact(version: str) -> bool:
    return extract_version_pin("package@" + version, ecosystem="npm") == version


_FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?")
_HASH_VALUE = re.compile(r"sha(?:256|384|512):[0-9a-fA-F]{64,128}")


def _vcs_pinned(url: str) -> bool:
    """Whether a VCS reference names a full commit; branch and tag names can move."""
    reference = url.split("#", 1)[0]
    revision = reference.rsplit("@", 1)[1] if "@" in reference.split("//", 1)[-1] else ""
    return _FULL_COMMIT.fullmatch(revision) is not None


# Project files that choose the registry npm, pnpm, Yarn and Bun fetch from, each with
# the setting that names its default registry: npm and pnpm read .npmrc, Yarn 1 .npmrc
# and .yarnrc, later Yarn .yarnrc.yml, and Bun .npmrc and bunfig.toml. Which of them
# installs is not known, so every one is read.
_NPM_REGISTRY_FILES = (
    (".npmrc", "registry"),
    (".yarnrc", "registry"),
    (".yarnrc.yml", "npmRegistryServer"),
    ("bunfig.toml", "registry"),
)
# Letter case is ignored in ASCII only: Unicode case folding would also match dotless
# i and other letters that IDNA turns into another host.
_DEFAULT_NPM_REGISTRY = re.compile(
    r"https://registry\.(?:npmjs\.org|yarnpkg\.com)(?::443)?/?", re.ASCII | re.IGNORECASE
)
_DEFAULT_PYPI_INDEX = re.compile(r"(?i:https://pypi\.org)(?::443)?/simple/?", re.ASCII)
_PYPI_ORIGIN = "https://pypi.org"
# The pip options and configuration keys that replace or add where packages come from;
# pip reads --pypi-url as --index-url. Index options on a requirement line are ignored.
# pip looks a configuration key up as the long option --<key>, so the long name of each
# of these options is also a key.
_PIP_INDEX_OPTIONS = frozenset({"--index-url", "--pypi-url", "--extra-index-url", "--find-links"})
_PIP_INDEX_KEYS = frozenset(option.removeprefix("--") for option in _PIP_INDEX_OPTIONS)
# The keys that name requirements, constraints or editable sources for pip install.
_PIP_PACKAGE_KEYS = frozenset({"requirement", "constraint", "editable"})
# pip reads a configuration file that PIP_CONFIG_FILE names or that lies at the root of
# the virtual environment it runs in; a project that keeps one there means it to be used.
_PIP_CONFIG_FILES = ("pip.conf", "pip.ini")
_PIP_CONFIG_LINE = re.compile(r"\r\n|\r|\n")
# A redirect value longer than this is recorded without its origins.
_LONGEST_REDIRECT = 4096
# Package sources one entry lists; one more entry counts the rest.
_MAX_LISTED_SOURCES = 32
# Settings named in a finding's detail; the rest are counted.
_MAX_NAMED_SOURCES = 8
_REDIRECT_ADVICE = (
    "Confirm that each configured registry or index is intended and trusted for this "
    "package, and pin artifact digests or integrity hashes."
)


def _pip_config(text: str) -> list[tuple[str, str]] | None:
    """The index and package settings of a pip configuration file, read as configparser
    reads it.

    Keys are lowercased, and pip reads ``_`` as ``-`` and ignores a leading ``--`` and
    an empty value. An indented line continues the value above it, and a comment line
    ends nothing. None when configparser, and so pip, refuses the file: text before the
    first section, a line that is neither a section nor ``key = value`` or
    ``key: value``, or a section or key given twice. Every section counts, because the
    sections pip reads depend on the command it runs and DEFAULT applies to all of them.
    """
    found: list[tuple[str, str]] = []
    sections: set[str] = set()
    keys: set[tuple[str, str]] = set()
    section: str | None = None
    key: str | None = None
    values: list[str] = []
    indent = 0

    def close() -> None:
        if key is not None:
            name = key.replace("_", "-").removeprefix("--")
            value = "\n".join(values).strip()
            if name in _PIP_INDEX_KEYS | _PIP_PACKAGE_KEYS and value:
                found.append((name, value))

    for line in _PIP_CONFIG_LINE.split(text):
        stripped = line.strip()
        if stripped.startswith(("#", ";")):
            continue
        if not stripped:
            values.append("")
            continue
        level = len(line) - len(line.lstrip())
        if key is not None and level > indent:
            values.append(stripped)
            continue
        close()
        key, values, indent = None, [], level
        end = stripped.rfind("]")
        if stripped.startswith("[") and end > 1:
            section = stripped[1:end]
            if section in sections:
                return None
            if section != "DEFAULT":
                sections.add(section)
            continue
        found_delimiters = [i for i in (stripped.find("="), stripped.find(":")) if i >= 0]
        if section is None or not found_delimiters or min(found_delimiters) == 0:
            return None
        delimiter = min(found_delimiters)
        name = stripped[:delimiter].rstrip().lower()
        if (section, name) in keys:
            return None
        keys.add((section, name))
        key, values = name, [stripped[delimiter + 1 :].strip()]
    close()
    return found


class _SourceLabels:
    """Exported ``setting=origin`` entries for redirecting settings; each value is read once.

    Only a value's origins are exported, never paths or credentials, as for MCP servers.
    """

    def __init__(self) -> None:
        self._origins: dict[str, list[str]] = {}

    def _locations(self, value: str) -> list[str]:
        origins = self._origins.get(value)
        if origins is None:
            origins = (
                ["[not parsed]"]
                if len(value) > _LONGEST_REDIRECT
                else _origin_label(value) or ["[set]"]
            )
            self._origins[value] = origins
        return origins

    def entries(self, redirects: Iterable[tuple[str, str]]) -> list[str]:
        found = {
            f"{label}={location}"
            for label, value in redirects
            for location in self._locations(value)
        }
        listed = sorted(found)
        if len(listed) > _MAX_LISTED_SOURCES:
            more = len(listed) - _MAX_LISTED_SOURCES
            listed = [*listed[:_MAX_LISTED_SOURCES], f"[{more} more not listed]"]
        return listed


def _named(redirects: Iterable[tuple[str, str]]) -> str:
    names = sorted({label for label, _ in redirects})
    shown = ", ".join(names[:_MAX_NAMED_SOURCES])
    more = len(names) - _MAX_NAMED_SOURCES
    return shown + (f" and {more} more" if more > 0 else "")


def _redirect(component: RegistryEntryComponent, sources: list[str], detail: str) -> None:
    """Record the settings that send a package's resolution elsewhere.

    Its name and version then do not identify what is installed, so no package URL
    is claimed for it.
    """
    component.package_url = None
    component.properties["package_sources"] = sources
    component.risks.append(_risk(RiskSeverity.LOW, "registry_origin", detail, _REDIRECT_ADVICE))


class _Resolution(NamedTuple):
    version: str
    origin: str | None
    integrity: str | None
    locator: str
    risks: list[RiskAssessment]
    # The record binds an exact version to a strong integrity value and a tarball
    # that names this package and version, so the declared range is resolved.
    resolved: bool
    consistent: bool
    sensitive_origin: bool = False


_YARN_LINES = 100_000
_YARN_DEPTH = 8
_YARN_LINE_BREAK = re.compile(r"\r?\n")
# What Yarn 1's tokenizer and a YAML reader both read as one plain word.
_YARN_WORD = re.compile(r"""[^\x00-\x20\x7f-\U0010ffff:,"'\\#\[\]{}]+""")
_YARN_V1_WORD_START = re.compile(r"[A-Za-z/.-]")
_YARN_BERRY_WORD_START = re.compile(r"[A-Za-z0-9/._~^<=-]")
# Yarn 1 refuses a version comment above 1 and then re-reads the whole file as YAML.
_YARN_VERSION_COMMENT = re.compile(r"yarn lockfile v([0-9]+)")
# The plain scalars Berry's stringifier writes unquoted, which a YAML reader reads as
# the same string: inner single or repeated spaces, no indicator at the start.
_BERRY_PLAIN = re.compile(
    r"""(?![-?:,\[\]{}#&*!|>%@`])[^\x00-\x20\x7f-\U0010ffff,\[\]{}:#'"\\]"""
    r"""(?: *[^\x00-\x20\x7f-\U0010ffff,\[\]{}:#'"\\])*"""
)
# Fields the collector reads, from a record or from Berry's `__metadata`: each must be
# a string Yarn reads as one.
_YARN_SCALAR_FIELDS = frozenset(
    {
        "version",
        "resolved",
        "integrity",
        "resolution",
        "checksum",
        "linkType",
        "conditions",
        "cacheKey",
    }
)
_YARN_BERRY_ONLY_FIELDS = frozenset({"resolution", "languageName", "linkType"})
# The nested maps Yarn 1 writes in a stanza (its implodeEntry).
_YARN_V1_MAP_FIELDS = frozenset(
    {"dependencies", "optionalDependencies", "permissions", "prebuiltVariants"}
)
_BERRY_LOCATOR_PROTOCOLS = ("@npm:", "@workspace:", "@patch:", "@portal:", "@link:", "@file:")
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
# The cache key Yarn 4 gives the archives it fetches at its default compression level.
# Yarn checks a fetched archive against a checksum only when the checksum names the
# key Yarn computes, and accepts the archive unchecked when it names another.
_YARN_CACHE_KEY = "10c0"
# A Yarn 4 version as `packageManager` names one, and a range of Yarn 4 versions only.
_YARN_4_VERSION = re.compile(r"4(?:\.(?:[0-9]+|x)){0,2}(?:-[0-9A-Za-z.-]+)?")
_YARN_4_RANGE = re.compile(r"[\^~]?" + _YARN_4_VERSION.pattern)
# Yarn 4 hashes a package's scope and name joined with nothing between them, and a
# descriptor or locator as that and its range or reference (structUtils.makeIdent), so
# it reads `@op/enai@npm:4.0.0` as `openai@npm:4.0.0`.
_BERRY_IDENT = re.compile(r"(?:@([^/]+?)/)?([^@/]+)")
_BERRY_DESCRIPTOR = re.compile(r"(?:@([^/]+?)/)?([^@/]+?)@(.+)")


def _yarn_cache_key(settings: dict[str, Any] | None) -> str | None:
    """The cache key Yarn 4 computes under the root ``.yarnrc.yml`` settings, or None
    when Yarn does not check a fetched archive against the lockfile's checksum: a
    ``checksumBehavior`` other than ``throw``, a ``compressionLevel`` other than 0,
    which gives another key, archives the project may supply, from a cache folder
    with the global cache turned off or from a ``globalFolder`` it chooses, a
    ``yarnPath``, which runs a Yarn release the project supplies, or ``plugins``, which
    Yarn loads as code that can change how it fetches and checks archives."""
    settings = settings or {}
    level = settings.get("compressionLevel", 0)
    if (
        settings.get("checksumBehavior", "throw") != "throw"
        or not (level == "0" or (type(level) is int and level == 0))
        or settings.get("enableGlobalCache", True) is not True
        or "globalFolder" in settings
        or "yarnPath" in settings
        or "plugins" in settings
    ):
        return None
    return _YARN_CACHE_KEY


def _yarn_4_selected(manifest: dict[str, Any]) -> bool:
    """Whether package.json names no Yarn release but Yarn 4 for Corepack to run: its
    ``packageManager`` and ``devEngines.packageManager`` name Yarn 4 or nothing."""
    if "packageManager" in manifest:
        named = manifest["packageManager"]
        if not (
            isinstance(named, str)
            and named.startswith("yarn@")
            and _YARN_4_VERSION.fullmatch(named[5:].partition("+")[0])
        ):
            return False
    if "devEngines" not in manifest:
        return True
    engines = manifest["devEngines"]
    if not isinstance(engines, dict):
        return False
    if "packageManager" not in engines:
        return True
    engine = engines["packageManager"]
    if not isinstance(engine, dict) or engine.get("name") != "yarn":
        return False
    version = engine.get("version", "4")
    return isinstance(version, str) and _YARN_4_RANGE.fullmatch(version) is not None


def _berry_ident(name: str) -> str:
    """What Yarn 4 hashes for a package name, or the name when Yarn reads none in it."""
    match = _BERRY_IDENT.fullmatch(name)
    return name if match is None else (match.group(1) or "") + match.group(2)


def _berry_hashed(text: str) -> tuple[str, str, str] | None:
    """The package name in a Berry descriptor or locator, what Yarn 4 hashes for that
    name, and the range or reference; None when Yarn reads no package name in it."""
    match = _BERRY_DESCRIPTOR.fullmatch(text)
    if match is None:
        return None
    scope, name, rest = match.groups()
    return text[: match.start(3) - 1], (scope or "") + name, rest


def _berry_checksum_checked(
    fields: dict[str, str], metadata: dict[str, str], cache_key: str | None
) -> bool:
    """Whether Yarn 4 checks the archive it fetches for a Berry record against the
    record's SHA-512 checksum. The checksum's cache key, its own prefix or else the
    lockfile's ``cacheKey``, must be the key Yarn computes, and so must the lockfile's.
    A record with ``conditions`` does not count: Yarn does not check the archive of
    such a package when it is installed as an optional dependency."""
    checksum = fields.get("checksum")
    if not checksum or cache_key is None or "conditions" in fields:
        return False
    key, slash, digest = checksum.rpartition("/")
    return (
        metadata.get("cacheKey") == cache_key
        and (key if slash else cache_key) == cache_key
        and len(digest) == 128
        and all(ch in _HEX_CHARS for ch in digest)
    )


class _YarnToken(NamedTuple):
    kind: str
    value: str
    spaced: bool


def _yarn_string_end(line: str, start: int) -> int:
    # Yarn's end rule: a quote ends the string unless one backslash precedes it.
    end = start + 1
    while True:
        end = line.find('"', end)
        if end < 0:
            raise ValueError("unterminated yarn.lock string")
        if not (line[end - 1] == "\\" and line[end - 2] != "\\"):
            return end
        end += 1


def _berry_field(content: str) -> tuple[str, _YarnToken | None]:
    """The key and value of a Berry field line: a YAML mapping entry whose value is
    a JSON string, a plain scalar as Berry writes one, or empty for a nested map."""
    key_end = _yarn_string_end(content, 0) + 1 if content.startswith('"') else content.find(":")
    if key_end <= 0:
        raise ValueError("yarn.lock field without a colon")
    key_tokens = _yarn_tokens(content[:key_end], True)
    if len(key_tokens) != 1 or key_tokens[0].kind != "str" or key_tokens[0].spaced:
        raise ValueError("invalid yarn.lock key")
    rest = content[key_end:]
    if rest == ":":
        return key_tokens[0].value, None
    if not rest.startswith(": "):
        raise ValueError("yarn.lock field without a colon")
    value = rest[2:]
    if value.startswith('"'):
        value_tokens = _yarn_tokens(value, True)
        if len(value_tokens) != 1 or value_tokens[0].kind != "str":
            raise ValueError("invalid yarn.lock field")
        return key_tokens[0].value, _YarnToken("str", value_tokens[0].value, True)
    if not _BERRY_PLAIN.fullmatch(value):
        raise ValueError("invalid yarn.lock field")
    return key_tokens[0].value, _YarnToken("str", value, True)


def _yarn_tokens(line: str, berry: bool) -> list[_YarnToken]:
    """Tokenize one line as Yarn 1 does, refusing what it or a YAML reader reads
    otherwise: quoted strings are JSON strings, and comments, tabs, single quotes and
    words that Yarn splits into a number or boolean and a string are refused."""
    tokens: list[_YarnToken] = []
    i, spaced = 0, False
    while i < len(line):
        ch = line[i]
        if ch == " ":
            i, spaced = i + 1, True
            continue
        if ch == '"':
            end = _yarn_string_end(line, i)
            value = json.loads(line[i : end + 1])
            if not isinstance(value, str):
                raise ValueError("invalid yarn.lock string")
            value.encode("utf-8")
            tokens.append(_YarnToken("str", value, spaced))
            i = end + 1
        elif ch in ":,":
            tokens.append(_YarnToken(ch, ch, spaced))
            i, spaced = i + 1, False
            continue
        else:
            match = _YARN_WORD.match(line, i)
            if match is None:
                raise ValueError("unsupported yarn.lock character")
            word = match.group()
            if berry:
                if not _YARN_BERRY_WORD_START.match(word):
                    raise ValueError("unsupported yarn.lock word")
                kind = "str"
            elif word.isdigit():
                kind = "number"
            elif word in ("true", "false"):
                kind = "boolean"
            elif not _YARN_V1_WORD_START.match(word) or word.startswith(("true", "false")):
                raise ValueError("unsupported yarn.lock word")
            else:
                kind = "str"
            tokens.append(_YarnToken(kind, word, spaced))
            i = match.end()
        if i < len(line) and line[i] not in " :,":
            raise ValueError("adjacent yarn.lock tokens")
        spaced = False
    return tokens


def _yarn_selectors(
    tokens: list[_YarnToken], berry: bool, *, v1_comment: bool = False
) -> list[str]:
    if len(tokens) < 2 or tokens[-1].kind != ":" or tokens[-1].spaced:
        raise ValueError("invalid yarn.lock header")
    keys = tokens[:-1]
    if any(t.kind != "str" for t in keys[::2]) or any(t.kind != "," for t in keys[1::2]):
        raise ValueError("invalid yarn.lock header")
    if len(keys) % 2 == 0:
        raise ValueError("invalid yarn.lock header")
    selectors = [t.value for t in keys[::2]]
    if berry:
        # Berry reads one YAML key and splits it at / *, */, keeping other whitespace in
        # a descriptor. A regular expression backtracks over a long run of spaces that
        # no comma follows, so the split is done by hand.
        if len(selectors) != 1:
            raise ValueError("invalid yarn.lock header")
        parts = selectors[0].split(",")
        selectors = []
        for index, part in enumerate(parts):
            if index:
                part = part.lstrip(" ")
            if index < len(parts) - 1:
                part = part.rstrip(" ")
            selectors.append(part)
    else:
        for sel in selectors:
            if "," not in sel:
                continue
            parts = [part.strip() for part in sel.split(",")]
            if (
                not v1_comment
                or any(not p or p.find("@", 1) <= 0 for p in parts)
                or any(proto in sel for proto in _BERRY_LOCATOR_PROTOCOLS)
                or len({p[: p.find("@", 1)] for p in parts}) > 1
            ):
                raise ValueError("ambiguous comma-joined yarn.lock selector")
    if any(not s or s != s.strip() for s in selectors):
        raise ValueError("empty yarn.lock selector")
    return selectors


def _yarn_v1_field(content: str) -> tuple[str, _YarnToken | None]:
    tokens = _yarn_tokens(content, False)
    if not tokens or tokens[0].kind != "str":
        raise ValueError("invalid yarn.lock key")
    rest = tokens[1:]
    colon = bool(rest) and rest[0].kind == ":"
    if colon:
        rest = rest[1:]
    if not rest and colon:
        return tokens[0].value, None
    if len(rest) != 1 or not rest[0].spaced or rest[0].kind in (":", ","):
        raise ValueError("invalid yarn.lock field")
    return tokens[0].value, rest[0]


def _yarn_source(fields: dict[str, str]) -> tuple[str | None, ...]:
    return tuple(fields.get(k) for k in ("resolved", "integrity", "resolution"))


def _yarn_lockfile_stanzas(
    text: str,
) -> tuple[dict[str, str] | None, list[tuple[list[str], dict[str, str]]]]:
    """The string fields of a Berry lockfile's ``__metadata``, None for a Yarn 1
    lockfile, and the stanzas, each with its selectors and the string fields at its
    first level. Raises ValueError on any line that Yarn 1's parser, or the YAML reader
    Berry uses, would read differently or not at all, and on some that Yarn never
    writes."""
    lines = _YARN_LINE_BREAK.split(text)
    # Yarn 1 ends a line at a lone CR but reads the spaces after it as no indentation.
    if any("\r" in line for line in lines):
        raise ValueError("lone carriage return in yarn.lock")
    if len(lines) > _YARN_LINES:
        raise ValueError("yarn.lock line limit exceeded")
    berry = False
    v1_comment = False
    metadata: dict[str, str] = {}
    stanzas: list[tuple[list[str], dict[str, str]]] = []
    fields: dict[str, str] = {}
    # The keys of each open object; a line may be indented one level past the last.
    open_keys: list[set[str]] = []
    first_header = True
    for line in lines:
        if not line or line.startswith("#"):
            for match in _YARN_VERSION_COMMENT.finditer(line):
                if int(match.group(1)) > 1:
                    raise ValueError("unsupported yarn.lock version")
                if berry:
                    raise ValueError("conflicting yarn.lock format headers")
                v1_comment = True
            if any(not keys for keys in open_keys):
                raise ValueError("empty yarn.lock mapping")
            # Yarn 1 reads an indented line after one empty line as part of the stanza and
            # stops reading the lockfile at one after more; refusing it covers both.
            open_keys = []
            continue
        content = line.lstrip(" ")
        spaces = len(line) - len(content)
        if not content or spaces % 2 or spaces // 2 > len(open_keys):
            raise ValueError("invalid yarn.lock indentation")
        level = spaces // 2
        if any(not keys for keys in open_keys[level:]):
            raise ValueError("empty yarn.lock mapping")
        if first_header:
            probe = _yarn_tokens(content, True)
            berry = (
                level == 0
                and len(probe) == 2
                and probe[0].kind == "str"
                and not probe[0].spaced
                and probe[0].value == "__metadata"
                and probe[1].kind == ":"
                and not probe[1].spaced
            )
            if berry and v1_comment:
                raise ValueError("conflicting yarn.lock format headers")
        if level == 0:
            selectors = _yarn_selectors(_yarn_tokens(content, berry), berry, v1_comment=v1_comment)
            fields = {}
            if selectors == ["__metadata"]:
                if not berry or not first_header:
                    raise ValueError("misplaced yarn.lock metadata")
                metadata = fields
            else:
                # A key without a package name is no package's record, only an alias target.
                if any(s.find("@", 1) <= 0 for s in selectors):
                    raise ValueError("yarn.lock selector without a package name")
                stanzas.append((selectors, fields))
            first_header = False
            open_keys = [set()]
            continue
        del open_keys[level:]
        if berry:
            key, value = _berry_field(content)
        else:
            key, value = _yarn_v1_field(content)
            # Inside a map a key is a name, such as a dependency named `resolution`.
            if level == 1 and key in _YARN_BERRY_ONLY_FIELDS:
                raise ValueError("berry field in yarn v1 lockfile")
        if not key:
            raise ValueError("invalid yarn.lock key")
        if key in open_keys[-1]:
            raise ValueError("duplicate key in yarn.lock stanza")
        open_keys[-1].add(key)
        if value is None:
            if not berry and (level != 1 or key not in _YARN_V1_MAP_FIELDS):
                raise ValueError("unsupported nested mapping in yarn.lock")
            if level == 1 and key in _YARN_SCALAR_FIELDS:
                raise ValueError("yarn.lock field is not a string")
            if len(open_keys) >= _YARN_DEPTH:
                raise ValueError("yarn.lock nesting limit exceeded")
            open_keys.append(set())
            continue
        if level == 1 and key in _YARN_SCALAR_FIELDS:
            if value.kind != "str":
                raise ValueError("yarn.lock field is not a string")
            fields[key] = value.value
    if any(not keys for keys in open_keys) or not stanzas:
        raise ValueError("empty yarn.lock")
    return (metadata if berry else None), stanzas


class RegistryScanner(Scanner):
    name = "registry"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            entries = files.root_entries()
            npm = self._scan_npm(result, entries)
            pypi = self._scan_pip(result, entries)
            self._note_unread_lockfiles(entries, npm, pypi)
            result.components.extend(npm)
            result.components.extend(pypi)
            result.components.extend(self._scan_docker(result))
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("registry (no AI-related dependencies found)")
        return result

    def _confined(self) -> ConfinedCollection:
        if self._files is None:
            raise RuntimeError("registry files read outside a _collection context")
        return self._files

    # Read on purpose although their names say they hold credentials: only the registry
    # settings of .npmrc and whether .env names COMPOSE_FILE are used, and no value of
    # either is recorded.
    _CREDENTIAL_INPUTS = frozenset({".npmrc", ".env"})

    def _withheld(self, name: str, result: ScanResult) -> bool:
        """Whether the root file ``name``, or the in-root file a symlink there leads to, is
        named as holding credentials, such as ``requirements-dev.txt -> .env``.

        Such a file is a recorded gap and is not read: a line of ``.env`` that names an
        AI package would otherwise carry its value into a component's version.
        """
        target = self._confined().in_root_target(name)
        if name in self._CREDENTIAL_INPUTS:
            # Read by its own name, but not through a link to another credential file,
            # which is not the configuration it is read for.
            reason = None if target is None or target.name == name else link_gap(target.as_posix())
        else:
            reason = credential_gap(name, None if target is None else target.as_posix())
        if reason is None:
            return False
        message = f"{name}: {reason}; not read or inventoried"
        if message not in result.surfaces_excluded:
            result.surfaces_excluded.append(message)
        return True

    def _read(self, name: str, result: ScanResult) -> str | None:
        """A root file by its name, which is also how the inventory records it."""
        if self._withheld(name, result):
            return None
        content = self._confined().read_text(name, missing_ok=True)
        if content is not None:
            result.surfaces_scanned.append(name)
        return content

    def _read_mapping(
        self, path: Path, result: ScanResult, *, missing_ok: bool = True
    ) -> dict[str, Any] | None:
        if self._withheld(path.as_posix(), result):
            return None
        return super()._read_mapping(path, result, missing_ok=missing_ok)

    # Lockfiles of other package managers, which the collector does not read; the
    # npm, pnpm, Yarn, uv and Poetry lockfiles are read below.
    _UNREAD_LOCKFILES = {
        "npm": ("bun.lock", "bun.lockb"),
        "pypi": ("Pipfile.lock", "pdm.lock"),
    }

    @classmethod
    def _note_unread_lockfiles(
        cls,
        entries: list[str],
        npm: list[RegistryEntryComponent],
        pypi: list[RegistryEntryComponent],
    ) -> None:
        # A finding, not a coverage gap: the declarations are read, but what the
        # package manager resolves them to is not, and that stays visible per package.
        present = set(entries)
        for ecosystem, components, label in (("npm", npm, "npm"), ("pypi", pypi, "PyPI")):
            unread = [name for name in cls._UNREAD_LOCKFILES[ecosystem] if name in present]
            if not unread:
                continue
            for component in components:
                component.risks.append(
                    _risk(
                        RiskSeverity.LOW,
                        "lockfile_unread",
                        f"{label} package '{component.name}' may be resolved by "
                        f"{', '.join(unread)}, which the collector does not read.",
                        "Review that lockfile's record for this package; the inventory "
                        "records only what the manifests declare.",
                    )
                )

    # Read in npm's order of precedence: a later section's spec replaces an earlier one.
    _NPM_SECTIONS = ("peerDependencies", "dependencies", "optionalDependencies", "devDependencies")
    # npm uses npm-shrinkwrap.json instead of package-lock.json when both exist.
    _NPM_LOCKFILES = ("npm-shrinkwrap.json", "package-lock.json")
    # The lockfiles of npm, pnpm and Yarn. Each package manager installs from its own,
    # so a root that holds more than one of them is resolved ambiguously.
    _NODE_LOCKFILES = (_NPM_LOCKFILES, ("pnpm-lock.yaml",), ("yarn.lock",))
    _NPM_DEFAULT_REGISTRIES = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
    _NPM_GAPS = {
        "override": "package.json: dependency override not translated",
        "unclassified": "package.json: git, URL or path dependency not classified",
        "workspaces": "package.json: workspaces not followed",
        # pnpm reads workspace packages, overrides and version catalogs from it.
        "pnpm": "pnpm-workspace.yaml: workspace settings not read",
    }
    # After the name of the file that patches the package.
    _PATCHED_GAP = "patched dependency is unverified"

    def _npm_lock(
        self, result: ScanResult
    ) -> tuple[tuple[str, dict[str, Any], str] | None, tuple[str, bytes] | None, bool]:
        """The lockfile package.json is installed from: npm's packages map with the
        digest of its bytes, or the bytes of a pnpm or Yarn lockfile; and whether a
        lockfile is present that neither comes from.

        With the lockfiles of more than one package manager in the root, which one
        installs is unknown, so none is bound and the ambiguity is a coverage gap.
        """
        files = self._confined()
        found: list[tuple[str, bytes | None]] = []
        for names in self._NODE_LOCKFILES:
            for name in names:
                before = files.failures_recorded, files.exclusions_recorded
                if self._withheld(name, result):
                    # Present but not read: no other file stands in for it.
                    found.append((name, None))
                    break
                # Parse and bind the same bounded bytes; a second open for hashing could
                # associate a swapped lockfile with a previously parsed resolution.
                raw = files.read_bytes(name, missing_ok=True)
                if raw is not None:
                    result.surfaces_scanned.append(name)
                    found.append((name, raw))
                    break
                if (files.failures_recorded, files.exclusions_recorded) != before:
                    # Present but refused or excluded: the package manager still
                    # prefers it, so no other file stands in for it.
                    found.append((name, None))
                    break
        if len(found) > 1:
            listed = ", ".join(name for name, _ in found)
            result.surfaces_excluded.append(
                f"multiple npm lockfiles present ({listed}); resolution is ambiguous"
            )
            return None, None, True
        if not found:
            return None, None, False
        name, raw = found[0]
        if raw is None:
            return None, None, True
        if name not in self._NPM_LOCKFILES:
            return None, (name, raw), False
        try:
            # The operator's file-bytes limit already bounded the read; a fixed parser
            # cap below it would fail every larger lockfile whatever the limit says.
            lock = parse_json_strict(raw, max_bytes=files.max_file_bytes)
            if (
                not isinstance(lock, dict)
                or not isinstance(lock.get("packages"), dict)
                or any(
                    not isinstance(k, str)
                    or (
                        k != ""
                        and (
                            "\\" in k
                            or k.startswith(("/", "../"))
                            or k.endswith("/")
                            or k in {".", ".."}
                            or posixpath.normpath(k) != k
                        )
                    )
                    for k in lock["packages"]
                )
                or (
                    lock.get("lockfileVersion") is not None
                    and (
                        type(lock["lockfileVersion"]) is not int
                        or lock["lockfileVersion"] not in (2, 3)
                    )
                )
            ):
                raise ValueError("unsupported npm lockfile structure")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            result.scan_failures.append(f"{name}: invalid or unsupported lockfile")
            return None, None, True
        return (name, lock["packages"], hash_bytes(raw)), None, False

    @staticmethod
    def _npm_spec(spec: str) -> tuple[str, str | None, str]:
        """How npm reads a dependency spec: its kind, an alias's package, and its range.

        The kinds follow npm-package-arg: a file path, an "npm:" alias, a hosted git
        shorthand or URL, another URL scheme, a path with a slash or an archive name,
        and otherwise a registry range, version or tag.
        """
        text = spec.strip()
        lowered = text.lower()
        if lowered.startswith("file:") or re.match(r"(?:[.]|~/|[/\\]|[a-zA-Z]:)", text):
            return "path", None, text
        if lowered.startswith("npm:"):
            target = text[4:]
            at = target.find("@", 1)
            return "alias", target if at < 0 else target[:at], "" if at < 0 else target[at + 1 :]
        if (
            lowered.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:"))
            or re.fullmatch(r"[^@/:\s]+/[^/:\s#]+(?:#\S*)?", text)
            or re.match(r"[\w.-]+@[\w.-]+:", text)
        ):
            return "git", None, text
        if lowered.startswith(("http://", "https://")):
            return "url", None, text
        if lowered.startswith("workspace:"):
            # pnpm and yarn resolve it to the workspace package named by the key.
            return "workspace", None, text
        if lowered.startswith("catalog:"):
            # pnpm reads the version from its workspace catalog; the key names the package.
            return "registry", None, text
        if re.match(r"[a-z]+:", lowered) or "/" in text or "\\" in text:
            return "path", None, text
        if re.search(r"[.](?:tgz|tar[.]gz|tar)$", lowered):
            return "path", None, text
        return "registry", None, text

    def _scan_npm(self, result: ScanResult, entries: list[str]) -> list[RegistryEntryComponent]:
        has_pnpm_workspace = any(self._fold(entry) == "pnpm-workspace.yaml" for entry in entries)
        if has_pnpm_workspace:
            result.surfaces_excluded.append(self._NPM_GAPS["pnpm"])
        if self._withheld("package.json", result):
            return []
        data = self._confined().read_json("package.json", missing_ok=True)
        if data is None:
            return []
        result.surfaces_scanned.append("package.json")
        if not isinstance(data, dict):
            result.scan_failures.append("package.json: expected an object")
            return []
        declared: dict[str, list[tuple[str, str]]] = {}
        for section in self._NPM_SECTIONS:
            deps = data.get(section, {})
            if not isinstance(deps, dict) or not all(
                isinstance(value, str) for value in deps.values()
            ):
                result.scan_failures.append(f"package.json: invalid {section} map")
                continue
            for key, spec in deps.items():
                declared.setdefault(key, []).append((section, spec))
        workspaces = data.get("workspaces")
        if (isinstance(workspaces, list) and workspaces) or (
            isinstance(workspaces, dict) and workspaces.get("packages")
        ):
            # Each workspace's package.json declares dependencies npm installs.
            result.surfaces_excluded.append(self._NPM_GAPS["workspaces"])
        lock, other_lock, lock_unread = self._npm_lock(result)
        resolutions: dict[str, Any] = lock[1] if lock else {}
        overrides = self._npm_overrides(data)
        components: list[RegistryEntryComponent] = []
        # Each package fetched from a registry, by the name the registry knows it by.
        fetched: list[tuple[RegistryEntryComponent, str]] = []
        # Those a pnpm or Yarn record may resolve: fetched and not patched.
        registry: list[RegistryEntryComponent] = []
        gaps: dict[str, None] = {}
        selected: list[tuple[str, list[tuple[str, str]], str, str, Any, str, set[str], bool]] = []
        for key, specs in sorted(declared.items()):
            parsed_specs = [(section, item, *self._npm_spec(item)) for section, item in specs]
            _, spec, kind, target, version_range = parsed_specs[-1]
            record = resolutions.get("node_modules/" + key)
            installed = self._installed_name(key, record, resolutions)
            package = target if kind == "alias" and target else key
            alias_targets = {t for _, _, k, t, _ in parsed_specs if k == "alias" and t}
            fetches = any(k in ("registry", "alias") for _, _, k, _, _ in parsed_specs)
            if not (
                self._is_ai_package(key)
                or self._is_ai_package(package)
                or any(self._is_ai_package(t) for t in alias_targets)
                or (installed is not None and self._is_ai_package(installed))
            ):
                if (
                    any(k in ("git", "url", "path") for _, _, k, _, _ in parsed_specs)
                    and installed is None
                ):
                    # npm installs such a source under the key whatever package it
                    # holds; without a lock record naming it, it is not classified.
                    gaps[self._NPM_GAPS["unclassified"]] = None
                continue
            selected.append(
                (key, specs, kind, version_range, record, package, alias_targets, fetches)
            )
        # Without an inventoried npm package, the workspace gap already covers what
        # pnpm-workspace.yaml may patch, so a file pnpm would refuse fails nothing.
        patches = self._npm_patches(data, result, workspace=bool(selected) and has_pnpm_workspace)
        for (
            key,
            specs,
            kind,
            version_range,
            record,
            package,
            aliased,
            fetches,
        ) in selected:
            # Every name the dependency is installed as, or an alias in any section installs.
            installs = {key.lower(), package.lower(), *(t.lower() for t in aliased)}
            overridden = overrides is None or bool(installs & overrides[0])
            if overridden:
                gaps[self._NPM_GAPS["override"]] = None
            # Whichever package manager installs applies the patch to the registry
            # artifact, so no lockfile record or exact spec names what is installed.
            patched = [
                source
                for source, names in patches.items()
                if names is None or not names.isdisjoint(installs)
            ]
            for source in patched:
                gaps[f"{source}: {self._PATCHED_GAP}"] = None
            component = self._npm_component(
                key,
                package,
                kind,
                version_range,
                specs,
                None if patched else record,
                lock,
                overridden or lock_unread or bool(patched),
                result,
            )
            if patched:
                component.risks.append(self._npm_patch_risk(component.name, patched))
            components.append(component)
            if fetches:
                # A registry spec in any section resolves through the project's registry
                # settings when the install flags select that section.
                fetched.append((component, package))
            if kind in ("registry", "alias") and not patched:
                registry.append(component)
        if overrides is None or any(self._is_ai_package(t) for t in overrides[1]):
            # Too many overrides to read, or one that installs an AI package under
            # another package's name.
            gaps[self._NPM_GAPS["override"]] = None
        for source, names in patches.items():
            if names is None or any(self._is_ai_package(name) for name in names):
                # Also a patch of an AI package that package.json does not declare,
                # such as one an inventoried package depends on: no component binds
                # it, yet what is installed is not the registry artifact.
                gaps[f"{source}: {self._PATCHED_GAP}"] = None
        for replaced in sorted(overrides[2]) if overrides is not None else ():
            # As for a dependency: a git, URL or path source is installed under the
            # name whatever package it holds, and only a lock record names that.
            record = resolutions.get("node_modules/" + replaced)
            if not self._is_ai_package(replaced) and (
                self._installed_name(replaced, record, resolutions) is None
            ):
                gaps[self._NPM_GAPS["unclassified"]] = None
        result.surfaces_excluded.extend(gaps)
        # A pnpm or Yarn record resolves only a package package.json declares from a
        # registry: npm installs a git, URL or path source whatever the record says.
        # A settings file read here is not read again for the registry settings.
        read_files: dict[str, dict[str, Any] | None] = {}
        if registry and other_lock is not None:
            lock_name, raw_lock = other_lock
            if lock_name == "pnpm-lock.yaml":
                read = self._resolve_pnpm_lockfile(
                    raw_lock,
                    registry,
                    components,
                    result,
                    declared_specs=declared,
                    override_specs=self._pnpm_override_specs(data),
                )
            else:
                before = (
                    recorded_count(result.scan_failures),
                    recorded_count(result.surfaces_excluded),
                )
                yarnrc = read_files[".yarnrc.yml"] = self._read_mapping(Path(".yarnrc.yml"), result)
                # A file that cannot be read or is excluded leaves Yarn's settings unknown,
                # and another Yarn release computes another cache key.
                after = (
                    recorded_count(result.scan_failures),
                    recorded_count(result.surfaces_excluded),
                )
                cache_key = (
                    _yarn_cache_key(yarnrc) if after == before and _yarn_4_selected(data) else None
                )
                read = self._resolve_yarn_lockfile(
                    raw_lock, registry, result, cache_key, declared_specs=declared
                )
            if not read:
                for component in registry:
                    # The lockfile installs it, so the version an exact spec names
                    # is in doubt.
                    component.package_url = None
        if fetched:
            self._redirect_npm(result, fetched, read_files)
        return components

    def _npm_registries(
        self, result: ScanResult, read_files: dict[str, dict[str, Any] | None]
    ) -> list[tuple[str, dict[str, str], str, str | None]]:
        """Each project file's registry settings, the setting that names its default
        registry, and for .npmrc the scope its ``scope`` setting selects.

        The files are read with the MCP collector's readers. An empty value selects
        nothing, as npm reads it. A .npmrc key that names an environment variable may
        be any setting, so its registries are a coverage gap.
        """
        found: list[tuple[str, dict[str, str], str, str | None]] = []
        for name, default in _NPM_REGISTRY_FILES:
            scope: str | None = None
            if name == "bunfig.toml":
                data = self._toml(name, result)
                if data is None:
                    continue
                install = data.get("install")
                settings = (
                    _registries(install, default, "scopes") if isinstance(install, dict) else []
                )
            elif name == ".yarnrc.yml":
                mapping = (
                    read_files[name]
                    if name in read_files
                    else self._read_mapping(Path(name), result)
                )
                if mapping is None:
                    continue
                result.surfaces_scanned.append(name)
                settings = _registries(mapping, default, "npmScopes")
            else:
                text = self._read(name, result)
                if text is None:
                    continue
                if name == ".yarnrc":
                    settings = list(_yarnrc(text))
                else:
                    parsed = _npmrc(text)
                    if parsed.unresolved:
                        result.surfaces_excluded.append(
                            ".npmrc: a setting name depends on the environment; registries "
                            "not resolved"
                        )
                    settings = list(parsed.settings)
                    scope = dict(parsed.settings).get("scope")
            found.append((name, {key: value for key, value in settings if value}, default, scope))
        return found

    def _redirect_npm(
        self,
        result: ScanResult,
        fetched: list[tuple[RegistryEntryComponent, str]],
        read_files: dict[str, dict[str, Any] | None],
    ) -> None:
        """Record on every package fetched from a registry the project settings that may
        choose another registry for it.

        Every package manager takes the registry of the package's own scope. For a
        package without one, npm takes the registry of the scope that .npmrc ``scope``
        names, and pnpm, Yarn 1 and Bun, which ignore ``scope``, the default registry;
        which of them installs is not known, so both count. A ``scope`` that npm fills
        in from the environment counts as ``.npmrc:scope=[unresolved]`` when the file
        gives some scope a registry other than the default one.
        """
        registries: list[tuple[str, dict[str, str], str, str | None]] = []
        for name, settings, default, scope in self._npm_registries(result, read_files):
            if expands(scope or "") and not any(
                npm_scope_registry(key) and not _DEFAULT_NPM_REGISTRY.fullmatch(value)
                for key, value in settings.items()
            ):
                # No scope the environment can name has a registry here but the default.
                scope = None
            registries.append((name, settings, default, scope))
        labels = _SourceLabels()
        for component, package in fetched:
            found: list[tuple[str, str]] = []
            for name, settings, default, scope in registries:
                selected = dict.fromkeys(
                    [
                        *npm_registry_settings(settings, package, default, scope),
                        *npm_registry_settings(settings, package, default),
                    ]
                )
                found.extend(
                    (f"{name}:{_setting_name(key, set(), selected=True)}", settings[key])
                    for key in selected
                    if not _DEFAULT_NPM_REGISTRY.fullmatch(settings[key])
                )
            if found:
                _redirect(
                    component,
                    labels.entries(found),
                    f"npm package '{component.name}' may resolve from a registry that the project "
                    f"configures ({_named(found)}), not the default npm registry; its name and "
                    "version do not establish identity.",
                )

    @staticmethod
    def _installed_name(key: str, record: Any, resolutions: dict[str, Any]) -> str | None:
        """The package a lock record says is installed under a key: its name, the key
        when it has none, or for a link the name of the entry it links to."""
        if not isinstance(record, dict):
            return None
        if record.get("link") is True:
            resolved = record.get("resolved")
            target = resolutions.get(resolved) if isinstance(resolved, str) else None
            name = target.get("name") if isinstance(target, dict) else None
            return name if isinstance(name, str) else None
        name = record.get("name", key)
        return name if isinstance(name, str) else None

    def _npm_component(
        self,
        key: str,
        package: str,
        kind: str,
        version_range: str,
        specs: list[tuple[str, str]],
        record: Any,
        lock: tuple[str, dict[str, Any], str] | None,
        in_doubt: bool,
        result: ScanResult,
    ) -> RegistryEntryComponent:
        spec = specs[-1][1]
        shown_name, sensitive_name = _identifier(package)
        name = shown_name if sensitive_name else redact_text(package)
        shown_key, sensitive_key = _identifier(key)
        key_name = shown_key if sensitive_key else redact_text(key)
        sensitive_specs = {
            value for _, value in specs if holds_token_shape(value, require_sk_boundary=True)
        }
        recorded_specs = {
            value: REDACTED if value in sensitive_specs else redact_text(value)
            for _, value in specs
        }
        locked_version = record.get("version") if isinstance(record, dict) else None
        sensitive_version = spec in sensitive_specs or (
            isinstance(locked_version, str)
            and holds_token_shape(locked_version, require_sk_boundary=True)
        )
        properties: dict[str, Any] = {
            "collection_mode": "manifest-reference",
            "registry_origin_verified": False,
            "requested_version": recorded_specs[spec],
        }
        if kind == "alias":
            # npm installs the package under the key, which the code imports.
            properties["npm_alias"] = key_name
        if len({value for _, value in specs}) > 1:
            properties["declarations"] = sorted(
                f"{section}: {recorded_specs[value]}" for section, value in specs
            )
        claims: dict[str, ClaimEvidence] = {}
        all_parsed = [(section, item, *self._npm_spec(item)) for section, item in specs]
        nonregistry_entries: list[tuple[str, str]] = list(
            dict.fromkeys(
                (item_kind, item_spec)
                for _, item_spec, item_kind, _, _ in all_parsed
                if item_kind not in ("registry", "alias")
            )
        )
        source_disagreement = self._sections_disagree(specs)
        if source_disagreement:
            result.surfaces_excluded.append(
                f"package.json: conflicting dependency sources for '{name}' across sections are ambiguous"
            )
        registry = kind in ("registry", "alias")
        version = redact_text(version_range if registry and version_range else spec)
        source = "package.json"
        resolution = None
        if lock is not None and record is not None and not source_disagreement:
            lock_name, _, lock_digest = lock
            # The key as the inventory records the name or alias it installs: redacted.
            locator = f"{lock_name}#/packages/" + _pointer_token("node_modules/" + key_name)
            if registry and not self._lock_root_agrees(lock[1], key, specs):
                # npm ci refuses a lockfile resolved for other specs, and npm install
                # resolves again: the record is not what installs.
                result.scan_failures.append(
                    f"{lock_name}: selected package version disagrees with package.json"
                )
            elif registry:
                resolution = self._npm_resolution(
                    lock_name, key, package, version_range, record, locator, result
                )
            properties["lockfile_sha256"] = lock_digest
            properties["lockfile_record"] = locator
            if resolution is not None:
                version, source = resolution.version, lock_name
                properties.update(
                    {
                        "collection_mode": "lockfile-resolution-claim",
                        "artifact_verified": False,
                    }
                )
                if resolution.integrity is not None:
                    properties["lockfile_integrity"] = resolution.integrity
                claims["package_resolution"] = ClaimEvidence(
                    assurance=AssuranceLevel.DECLARED,
                    method="npm-lockfile",
                    scope="dependency-resolution",
                    collector="registry",
                    locator=locator,
                )
            elif registry:
                # A record that was not taken binds nothing; the failure or gap says why.
                del properties["lockfile_sha256"], properties["lockfile_record"]
        risks = list(resolution.risks) if resolution else []
        if sensitive_name or sensitive_key:
            risks.append(_identifier_risk(f"npm package '{name}'", "name or alias"))
        if sensitive_specs or sensitive_version:
            risks.append(_identifier_risk(f"npm package '{name}'", "version"))
        if kind == "alias":
            risks.append(
                _risk(
                    RiskSeverity.LOW,
                    "package_alias",
                    f"npm dependency '{key_name}' installs '{name}' under another name.",
                    "Check that the aliased package is the one the code expects to import.",
                )
            )
        for alias_target in dict.fromkeys(
            item_target
            for _, _, item_kind, item_target, _ in all_parsed
            if item_kind == "alias" and item_target and item_target != package
        ):
            shown_alias, sensitive_alias = _identifier(alias_target)
            alias_display = shown_alias if sensitive_alias else redact_text(alias_target)
            risks.append(
                _risk(
                    RiskSeverity.LOW,
                    "package_alias",
                    f"npm dependency '{key_name}' installs '{alias_display}' under another name.",
                    "Check that the aliased package is the one the code expects to import.",
                )
            )
        # npm takes the last section's spec, pnpm the first of optional, dependencies,
        # dev and peer, so a spec counts only when both take the same one.
        by_section = dict(specs)
        pnpm_spec = next(
            by_section[section] for section in _PNPM_SECTION_ORDER if section in by_section
        )
        uniform = pnpm_spec == spec
        if (
            registry
            and not (uniform and _npm_exact(version_range))
            and not (resolution and resolution.resolved)
        ):
            shown_spec = (
                recorded_specs[spec]
                if uniform
                else ", ".join(f"{section}: {recorded_specs[value]}" for section, value in specs)
            )
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM,
                    "version_pinning",
                    f"npm package '{name}' has a nonexact declared reference: {shown_spec}",
                    "Resolve and verify an immutable artifact with lockfile integrity evidence.",
                )
            )
        if not registry:
            risks.append(self._npm_source_risk(name, kind, spec))
        for item_kind, item_spec in nonregistry_entries:
            if registry or (item_kind, item_spec) != (kind, spec):
                risk = self._npm_source_risk(name, item_kind, item_spec)
                if risk not in risks:
                    risks.append(risk)
        package_url = None
        # A name the redaction changed is exported as the marker; no package URL may
        # spell it out.
        if (
            not sensitive_name
            and name == package
            and not sensitive_version
            and not source_disagreement
            and resolution is not None
            and resolution.consistent
            and not resolution.sensitive_origin
        ):
            package_url = self._npm_purl(package, resolution.version, resolution.origin)
        elif (
            not sensitive_name
            and name == package
            and not sensitive_version
            and not source_disagreement
            and registry
            and record is None
            and not in_doubt
            and uniform
            and _npm_exact(version_range)
        ):
            # Only without a lock record: one that was not taken, a lockfile that was
            # not read and an override each leave the version the spec names in doubt.
            package_url = self._npm_purl(package, version_range, None)
        withhold_origin = (
            sensitive_name
            or sensitive_version
            or name != package
            or (resolution is not None and resolution.sensitive_origin)
        )
        return RegistryEntryComponent(
            bom_ref=f"registry:npm/{reference_text(key_name)}",
            name=name,
            version=REDACTED if sensitive_version else version or None,
            package_url=package_url,
            registry_type="npm",
            registry_uri=None if withhold_origin else (resolution.origin if resolution else None),
            source_path=source,
            trust_tier=TrustTier.UNKNOWN,
            assurance_level=AssuranceLevel.DECLARED,
            risks=risks,
            properties=properties,
            claims=claims,
        )

    @classmethod
    def _lock_root_agrees(
        cls, packages: dict[str, Any], key: str, specs: list[tuple[str, str]]
    ) -> bool:
        """Whether the lockfile's root entry records the specs package.json declares for
        ``key``, section by section, as npm ci checks. npm writes a root entry in every
        lockfile with packages, so one without it agrees with nothing.

        A name optionalDependencies lists is no dependency on either side: npm drops it
        from dependencies before writing the lockfile and before comparing."""
        root = packages.get("")
        if not isinstance(root, dict):
            return False
        declared = dict(specs)
        optional = root.get("optionalDependencies")
        if "optionalDependencies" in declared:
            declared.pop("dependencies", None)
        for section in cls._NPM_SECTIONS:
            recorded = root.get(section)
            value = recorded.get(key) if isinstance(recorded, dict) else None
            if section == "dependencies" and isinstance(optional, dict) and key in optional:
                value = None
            if value != declared.get(section):
                return False
        return True

    @classmethod
    def _npm_purl(cls, package: str, version: str, origin: str | None) -> str | None:
        if re.fullmatch(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*", package) is None:
            return None
        purl = f"pkg:npm/{quote(package, safe='/')}@{quote(version, safe='')}"
        if origin is not None and not cls._default_registry(origin):
            # The package URL names the registry it was resolved from, so it is not
            # mistaken for the public package of the same name.
            purl += f"?repository_url={origin}"
        return purl

    @classmethod
    def _default_registry(cls, origin: str) -> bool:
        return origin.removeprefix("https://") in cls._NPM_DEFAULT_REGISTRIES

    @classmethod
    def _npm_record_risks(
        cls, name: str, digest_recorded: bool, origin: str | None
    ) -> list[RiskAssessment]:
        """What a lockfile record leaves open, whichever package manager wrote it."""
        risks: list[RiskAssessment] = []
        if not digest_recorded:
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM,
                    "missing_lockfile_integrity",
                    f"npm package '{name}' has a lockfile record without an integrity value.",
                    "Regenerate the lockfile so that it records a sha512 integrity value.",
                )
            )
        if origin is not None and not cls._default_registry(origin):
            risks.append(
                _risk(
                    RiskSeverity.LOW,
                    "registry_origin",
                    f"npm package '{name}' is resolved from {origin}, not the default npm "
                    "registry.",
                    "Confirm that this registry is intended and trusted for this package.",
                )
            )
        return risks

    @staticmethod
    def _npm_patch_risk(name: str, sources: list[str]) -> RiskAssessment:
        """The finding of a package that a patch may change at install: each of
        ``sources`` names one for it, or could not be read."""
        return _risk(
            RiskSeverity.MEDIUM,
            "nonregistry_source",
            f"npm package '{name}' may be patched at install ({', '.join(sources)}), so its "
            "installed code is not known to be the registry artifact.",
            "Review the patch and what it changes, or remove it and install the registry "
            "release with lockfile integrity.",
        )

    @staticmethod
    def _npm_source_risk(name: str, kind: str, spec: str) -> RiskAssessment:
        lowered = spec.strip().lower()
        mutable = (kind == "git" and not _FULL_COMMIT.fullmatch(lowered.rsplit("#", 1)[-1])) or (
            lowered.startswith("http://")
        )
        label = {
            "git": "git",
            "url": "URL",
            "path": "local path or other",
            "workspace": "workspace",
        }[kind]
        return _risk(
            RiskSeverity.HIGH if mutable else RiskSeverity.MEDIUM,
            "nonregistry_source",
            f"npm package '{name}' is declared from a {label} source, not a registry.",
            "Install it from a registry with an exact version and lockfile integrity, "
            "or review the source and pin it to a full commit.",
        )

    def _npm_resolution(
        self,
        lock_name: str,
        key: str,
        package: str,
        version_range: str,
        record: Any,
        locator: str,
        result: ScanResult,
    ) -> _Resolution | None:
        """A lock record's resolution of a registry dependency, checked for consistency.

        None, with a failure or gap recorded, when the record is not taken.
        """
        if not isinstance(record, dict):
            result.scan_failures.append(f"{lock_name}: invalid selected package record")
            return None
        if record.get("name", key) != package:
            result.surfaces_excluded.append(f"{lock_name}: aliased package identity is unresolved")
            return None
        if record.get("link") is True:
            result.surfaces_excluded.append(f"{lock_name}: local link resolution is unverified")
            return None
        version = record.get("version")
        if not (
            isinstance(version, str) and len(version) <= _LONGEST_VERSION and _npm_exact(version)
        ):
            result.scan_failures.append(f"{lock_name}: selected package lacks an exact version")
            return None
        if _npm_exact(version_range) and version_range != version:
            # npm ci refuses a lockfile that does not satisfy package.json.
            result.scan_failures.append(
                f"{lock_name}: selected package version disagrees with package.json"
            )
            return None
        origin = None
        consistent = True
        resolved = record.get("resolved")
        if resolved is not None:
            parsed = self._https_resolution(resolved)
            if parsed is None:
                result.scan_failures.append(
                    f"{lock_name}: selected package has an unsupported resolved URL"
                )
                return None
            origin, path = parsed
            consistent = self._tarball_matches(origin, path, package, version)
        integrity = record.get("integrity")
        if integrity is not None and not self._validate_sri_integrity(integrity):
            result.scan_failures.append(f"{lock_name}: invalid selected package integrity")
            return None
        shown_name, sensitive_name = _identifier(package)
        name = shown_name if sensitive_name else redact_text(package)
        sensitive_origin = _sensitive_origin(origin)
        risks: list[RiskAssessment] = []
        if not consistent:
            risks.append(
                _risk(
                    RiskSeverity.HIGH,
                    "lockfile_resolution_mismatch",
                    f"npm package '{name}' has a lockfile record whose tarball URL names "
                    "another package or version.",
                    "Regenerate the lockfile from the registry and review the change.",
                )
            )
        risks.extend(
            self._npm_record_risks(
                name, integrity is not None, REDACTED if sensitive_origin else origin
            )
        )
        if sensitive_origin:
            risks.append(_identifier_risk(f"npm package '{name}'", "registry origin"))
        return _Resolution(
            version=version,
            origin=None if sensitive_origin else origin,
            integrity=integrity,
            locator=locator,
            risks=risks,
            resolved=integrity is not None and consistent,
            consistent=consistent,
            sensitive_origin=sensitive_origin,
        )

    @staticmethod
    def _https_resolution(resolved: Any) -> tuple[str, str] | None:
        """The origin and path of a resolved https URL, or None if a WHATWG parser,
        which npm uses, could read it differently.

        Control characters, white space, backslashes and percent signs in the host
        are such cases, and so is any character outside ASCII. User information is
        dropped, never recorded.
        """
        if not isinstance(resolved, str) or len(resolved) > 4096 or not resolved.isascii():
            return None
        if any(c <= " " or c in "\\\x7f" for c in resolved):
            return None
        try:
            parts = urlsplit(resolved)
            port = parts.port
        except ValueError:
            return None
        host = parts.hostname
        if parts.scheme.lower() != "https" or not host or "%" in parts.netloc.rpartition("@")[2]:
            return None
        host = f"[{host}]" if ":" in host else host
        origin = f"https://{host}" + (f":{port}" if port is not None and port != 443 else "")
        return origin, parts.path

    @classmethod
    def _tarball_matches(cls, origin: str, path: str, package: str, version: str) -> bool:
        """Whether a registry tarball path names this package and version.

        npm registries serve /<name>/-/<unscoped name>-<version>.tgz. Direct archive
        URLs ending in .tgz or .tar.gz must also name <unscoped name>-<version>; opaque
        download paths without an archive filename are not checked.
        """
        try:
            decoded = unquote(path, errors="strict")
        except UnicodeDecodeError:
            return False
        tail = f"/{package}/-/{package.rsplit('/', 1)[-1]}-{version}.tgz"
        if cls._default_registry(origin):
            return decoded == tail
        if "/-/" in decoded:
            return decoded.endswith(tail)
        lowered = decoded.lower()
        if lowered.endswith((".tgz", ".tar.gz")):
            stem = package.rsplit("/", 1)[-1].lower()
            expected = f"/{stem}-{version.lower()}"
            return lowered.endswith((f"{expected}.tgz", f"{expected}.tar.gz"))
        return True

    @staticmethod
    def _validate_sri_integrity(integrity: Any) -> bool:
        """Whether an SRI value binds the artifact as npm, pnpm and Yarn check it.

        Every hash in it must decode to its algorithm's length, and one must be
        SHA-256, SHA-384 or SHA-512: the package managers check the strongest, so a
        value with only SHA-1 is refused, as is anything else.
        """
        if not isinstance(integrity, str) or not integrity or len(integrity) > 1024:
            return False
        algorithms: set[str] = set()
        for item in integrity.split():
            algorithm, separator, encoded = item.partition("-")
            size = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}.get(algorithm)
            if not separator or size is None:
                return False
            try:
                if len(base64.b64decode(encoded, validate=True)) != size:
                    return False
            except (ValueError, binascii.Error):
                return False
            algorithms.add(algorithm)
        return bool(algorithms - {"sha1"})

    def _bind_npm_resolution(
        self,
        component: RegistryEntryComponent,
        lock_name: str,
        method: str,
        version: str,
        resolved: Any,
        integrity: Any,
        locator: str,
        lock_digest: str,
        result: ScanResult,
        *,
        checksum_recorded: bool = False,
        requested: str | None = None,
        bind_identity: bool = True,
    ) -> None:
        """Bind a pnpm or Yarn record's exact version to a component, checked as an npm
        record is: an exact spec must agree with it, a download URL is read as a
        WHATWG parser reads it, an integrity value must be strong, and a record
        without one or from another registry carries the finding an npm record does.
        ``checksum_recorded`` says the record holds Yarn's own checksum instead, and
        ``requested`` is the spec the package manager takes when it is not npm's.
        Nothing is bound, and a failure says why, when a check fails."""

        def private(value: str) -> bool:
            return holds_token_shape(value, require_sk_boundary=True) or redact_text(value) != value

        sensitive_locator = private(locator)
        sensitive = sensitive_locator or private(version)
        if sensitive:
            component.package_url = component.registry_uri = None
            # The selected version can appear in both the manifest and the lock
            # key. Check the rest of the key for an independently private value.
            repeated = (
                requested == version
                and any(r.category == "credential_exposure" for r in component.risks)
                and not private(locator.replace(_pointer_token(version), ""))
            )
            if not repeated:
                component.risks.append(
                    _identifier_risk(f"npm package '{component.name}'", "lock record")
                )
        if sensitive_locator:
            # The file digest still supports this claim. Its selector cannot be exported.
            locator = lock_name
        if requested is None:
            requested = str(component.properties.get("requested_version", "")).strip()
        if _npm_exact(requested) and requested != version:
            result.scan_failures.append(
                f"{lock_name}: selected package version disagrees with package.json"
            )
            return
        origin = None
        consistent = True
        if resolved is not None:
            parsed = self._https_resolution(resolved)
            if parsed is None:
                result.scan_failures.append(
                    f"{lock_name}: selected package has an unsupported resolved URL"
                )
                return
            origin, path = parsed
            consistent = self._tarball_matches(origin, path, component.name, version)
        if integrity is not None and not self._validate_sri_integrity(integrity):
            result.scan_failures.append(f"{lock_name}: invalid selected package integrity")
            return
        shown_name, sensitive_comp = _identifier(component.name)
        shown = shown_name if sensitive_comp else redact_text(component.name)
        sensitive_origin = _sensitive_origin(origin)
        if sensitive_origin:
            component.risks.append(_identifier_risk(f"npm package '{shown}'", "registry origin"))
        if not consistent:
            component.risks.append(
                _risk(
                    RiskSeverity.HIGH,
                    "lockfile_resolution_mismatch",
                    f"npm package '{shown}' has a lockfile record whose tarball URL "
                    "names another package or version.",
                    "Regenerate the lockfile from the registry and review the change.",
                )
            )
        digest_recorded = integrity is not None or checksum_recorded
        component.risks.extend(
            self._npm_record_risks(shown, digest_recorded, REDACTED if sensitive_origin else origin)
        )
        if not bind_identity:
            # A registry record can expose an independent integrity or origin problem
            # even when its source does not match the one the package manager selected.
            return
        if digest_recorded and consistent:
            component.risks = [r for r in component.risks if r.category != "version_pinning"]
        withhold_identity = sensitive or sensitive_origin or sensitive_comp
        component.version = REDACTED if sensitive else version
        component.package_url = (
            self._npm_purl(component.name, version, origin)
            if consistent and not withhold_identity
            else None
        )
        component.registry_uri = None if withhold_identity else origin
        component.source_path = lock_name
        component.assurance_level = AssuranceLevel.DECLARED
        component.properties.update(
            {
                "collection_mode": "lockfile-resolution-claim",
                "lockfile_sha256": lock_digest,
                "lockfile_record": locator,
                "artifact_verified": False,
            }
        )
        if integrity is not None:
            component.properties["lockfile_integrity"] = integrity
        component.claims["package_resolution"] = ClaimEvidence(
            assurance=AssuranceLevel.DECLARED,
            method=method,
            scope="dependency-resolution",
            collector="registry",
            locator=locator,
        )

    @staticmethod
    def _pnpm_selections(
        packages: dict[Any, Any], names: set[str]
    ) -> dict[str, tuple[str, str] | None]:
        """The `packages` record each of these names selects: its key and version
        reference, or None when records of more than one version make the choice
        ambiguous. A name without a record, or with several records of one version,
        selects none.

        A key is the record of one name: its text up to the first "@" or "/" after the
        first character, or after a scope's "/". So each key is read once and the cost
        is linear in the lockfile: matching every name against every key cost their
        product, and indexing a key under the text before each separator would cost
        the square of its length.
        """
        if not names:
            return {}
        found: dict[str, list[tuple[str, str]]] = {}
        for key in packages:
            if not isinstance(key, str):
                continue
            clean = key.lstrip("/")
            start = clean.find("/", 1) + 1 if clean.startswith("@") else 1
            end = _PNPM_NAME_END.search(clean, start) if start else None
            if end is None:
                continue
            name = clean[: end.start()]
            if name not in names:
                continue
            suffix = clean[end.end() :]
            if suffix and not suffix.startswith("/"):
                found.setdefault(name, []).append((key, suffix))
        selections: dict[str, tuple[str, str] | None] = {}
        for name, records in found.items():
            if len({suffix.split("(", 1)[0] for _, suffix in records}) > 1:
                selections[name] = None
            elif len(records) == 1:
                selections[name] = records[0]
        return selections

    @staticmethod
    def _bounded_yaml_loader(max_depth: int = 64) -> type[Any]:
        """PyYAML SafeLoader subclass enforcing a strict flow-collection depth cap.

        The scanner's own ``flow_level`` has no floor: a run of "]" drives it negative,
        after which every "[" passes the cap while the scanner's simple-key bookkeeping
        grows with each level, which is quadratic. A flow end at level 0 is a parse
        error whatever follows it, so it is refused where it occurs.
        """
        import yaml

        class _BoundedFlowLoader(yaml.SafeLoader):
            def fetch_flow_collection_start(self, token_class: Any) -> None:
                if self.flow_level >= max_depth:
                    raise ValueError(f"YAML flow nesting exceeds depth limit ({max_depth})")
                super().fetch_flow_collection_start(token_class)

            def fetch_flow_collection_end(self, token_class: Any) -> None:
                if self.flow_level <= 0:
                    raise yaml.scanner.ScannerError(
                        None, None, "found a flow collection end outside one", self.get_mark()
                    )
                super().fetch_flow_collection_end(token_class)

        return _BoundedFlowLoader

    def _resolve_pnpm_lockfile(
        self,
        lock_bytes: bytes,
        components: list[RegistryEntryComponent],
        declared: list[RegistryEntryComponent],
        result: ScanResult,
        *,
        declared_specs: dict[str, list[tuple[str, str]]] | None = None,
        override_specs: dict[str, str] | None = None,
    ) -> bool:
        """Bind pnpm records to the components, which package.json declares from a
        registry; ``declared`` is every inventoried npm package. False when the
        lockfile is not read."""
        try:
            import yaml
        except ImportError:
            result.scan_failures.append("pnpm-lock.yaml: YAML parser unavailable")
            return False
        from nexus_symbiote.policy import PolicyError, parse_yaml_mapping

        try:
            text = lock_bytes.decode("utf-8")
            loader = self._bounded_yaml_loader()
            for index, token in enumerate(yaml.scan(text, Loader=loader)):
                if index >= _MAX_PNPM_LOCK_TOKENS or isinstance(
                    token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)
                ):
                    raise ValueError("unsupported YAML graph")
            lock_doc = parse_yaml_mapping(text)
            lock_ver = lock_doc.get("lockfileVersion")
            if (
                lock_ver is None
                or isinstance(lock_ver, bool)
                or not isinstance(lock_ver, (str, int, float))
            ):
                raise ValueError("unsupported pnpm lockfile structure")
            family = str(lock_ver).split(".", 1)[0]
            if family not in _PNPM_RECORD_KEYS:
                raise ValueError("unsupported pnpm lockfile version")
            packages = lock_doc.get("packages", {})
            if packages is not None and not isinstance(packages, dict):
                raise ValueError("unsupported pnpm packages structure")
            lock_patches = self._patched_names(lock_doc.get("patchedDependencies"))
            if lock_patches is None:
                raise ValueError("unsupported pnpm patchedDependencies structure")
        except (ValueError, UnicodeError, PolicyError, RecursionError, yaml.YAMLError):
            result.scan_failures.append("pnpm-lock.yaml: invalid or unsupported lockfile")
            return False
        lock_digest = hash_bytes(lock_bytes)
        if any(self._is_ai_package(name) for name in lock_patches):
            # As for package.json: an AI package that no component binds is patched too.
            self._pnpm_patch_gap(result)
        packages = packages or {}
        importers = lock_doc.get("importers")
        root_importer = (
            importers.get(".", {})
            if isinstance(importers, dict) and isinstance(importers.get("."), dict)
            else lock_doc
        )
        importer_specs: dict[str, str] = {}
        # Names that two sections of the root importer resolve to different versions:
        # which one pnpm installs is not resolved here.
        disagreeing: set[str] = set()
        # The package.json specs the lockfile was resolved for: pnpm 6 and 9 record one
        # with each dependency, pnpm 5 in one map.
        specifiers: dict[str, set[str]] = {}
        dep_keys = ("dependencies", "devDependencies", "optionalDependencies")
        for dep_key in dep_keys:
            dep_map = root_importer.get(dep_key, {})
            if isinstance(dep_map, dict):
                for pkg_name, entry in dep_map.items():
                    if isinstance(entry, dict) and isinstance(entry.get("version"), str):
                        version_ref = entry["version"]
                        if isinstance(entry.get("specifier"), str):
                            specifiers.setdefault(pkg_name, set()).add(entry["specifier"])
                    elif isinstance(entry, str):
                        version_ref = entry
                    else:
                        continue
                    if importer_specs.setdefault(pkg_name, version_ref) != version_ref:
                        disagreeing.add(pkg_name)
        listed = root_importer.get("specifiers")
        if isinstance(listed, dict):
            for pkg_name, specifier in listed.items():
                if isinstance(specifier, str):
                    specifiers.setdefault(pkg_name, set()).add(specifier)
        counts = Counter(c.name for c in declared if c.properties.get("npm_alias") is None)
        # The root importer lists what pnpm installs for package.json; a name it does
        # not list is not resolved by records that other packages' dependencies left.
        # Only a lockfile without one is searched by name.
        unlisted = "importers" not in lock_doc and not any(key in lock_doc for key in dep_keys)
        selections = (
            self._pnpm_selections(packages, set(counts).difference(importer_specs))
            if unlisted
            else {}
        )
        for comp in components:
            alias = comp.properties.get("npm_alias")
            names = {comp.name.lower()} if alias is None else {comp.name.lower(), alias.lower()}
            if not lock_patches.isdisjoint(names):
                # The record's integrity is the unpatched tarball's, whichever version
                # the patch names: pnpm refuses a patch it does not apply.
                self._pnpm_patched_component(comp, result)
                continue
            if alias is not None:
                # Only npm's own lockfile record is resolved against an alias's package.
                if alias in importer_specs:
                    comp.package_url = None
                    result.surfaces_excluded.append(
                        "pnpm-lock.yaml: aliased package identity is unresolved"
                    )
                continue
            ver_ref = importer_specs.get(comp.name)
            matched_pkg_key: str | None = None
            if ver_ref is None and comp.name in selections:
                selected = selections[comp.name]
                if selected is None:
                    comp.package_url = None
                    result.surfaces_excluded.append(
                        f"pnpm-lock.yaml: multiple package resolutions for {comp.name} are ambiguous"
                    )
                    continue
                matched_pkg_key, ver_ref = selected
            if ver_ref is None:
                continue
            # A record the lockfile holds decides the identity, or nothing does: one
            # that is not taken leaves the version an exact spec names in doubt.
            comp.package_url = None
            if comp.name in disagreeing:
                result.surfaces_excluded.append(
                    f"pnpm-lock.yaml: multiple package resolutions for {comp.name} are ambiguous"
                )
                continue
            if counts[comp.name] > 1:
                # Redaction gave several dependencies this name, so which of them the
                # record belongs to is unknown; binding it to each would also copy its
                # key, however long, into every one.
                result.surfaces_excluded.append(
                    f"pnpm-lock.yaml: packages whose names redact to {comp.name} are unresolved"
                )
                continue
            if _pnpm_patched(ver_ref):
                self._pnpm_patched_component(comp, result)
                continue
            if ver_ref.startswith("npm:"):
                result.surfaces_excluded.append(
                    "pnpm-lock.yaml: aliased package identity is unresolved"
                )
                continue
            if ver_ref.startswith(("link:", "file:", "workspace:", "git+", "http:", "https:")):
                result.surfaces_excluded.append(
                    "pnpm-lock.yaml: local or non-registry resolution is unverified"
                )
                continue
            # A record found by name records no specifier: pnpm lists the root's
            # dependencies in every format, so a lockfile that does not is stale, whatever
            # a top-level `specifiers` map claims.
            if matched_pkg_key is not None or not self._pnpm_spec_agrees(
                specifiers.get(comp.name),
                (declared_specs or {}).get(comp.name),
                (override_specs or {}).get(comp.name),
            ):
                # pnpm --frozen-lockfile refuses a lockfile resolved for other specs, and
                # pnpm install resolves again: the record is not what installs.
                result.scan_failures.append(
                    "pnpm-lock.yaml: selected package version disagrees with package.json"
                )
                continue
            base_ver = ver_ref.split("(", 1)[0]
            if base_ver.startswith("/"):
                pkg_prefix, _, base_ver = base_ver.lstrip("/").rpartition("@")
                if pkg_prefix and pkg_prefix != comp.name:
                    result.surfaces_excluded.append(
                        "pnpm-lock.yaml: aliased package identity is unresolved"
                    )
                    continue
            if len(base_ver) > _LONGEST_VERSION or not _npm_exact(base_ver):
                result.scan_failures.append(
                    "pnpm-lock.yaml: selected package lacks an exact version"
                )
                continue
            # pnpm reads one key for an importer's version, by lockfile format; a
            # record under another format's spelling is one pnpm never writes or
            # reads, so letting it stand in would let a decoy supply the integrity
            # and the origin.
            expected = _PNPM_RECORD_KEYS[family].format(
                name=comp.name, ref=ver_ref, version=base_ver
            )
            spellings = {
                spelling: spelling.format(name=comp.name, ref=ver_ref, version=base_ver)
                for spelling in _PNPM_KEY_SPELLINGS
            }
            own = {spellings[spelling] for spelling in _PNPM_OWN_SPELLINGS[family]}
            if any(key in packages for key in set(spellings.values()) - own):
                comp.package_url = None
                result.surfaces_excluded.append(
                    f"pnpm-lock.yaml: multiple package resolutions for {comp.name} are ambiguous"
                )
                continue
            pkg_key: str | None = expected if expected in packages else None
            tarball: Any = None
            integrity: Any = None
            if pkg_key is not None:
                pkg_record = packages[pkg_key]
                if not isinstance(pkg_record, dict):
                    result.scan_failures.append("pnpm-lock.yaml: invalid selected package record")
                    continue
                if pkg_record.get("patched", False) is not False:
                    # Lockfile v6 marks the record of a patched package.
                    self._pnpm_patched_component(comp, result)
                    continue
                resolution = pkg_record.get("resolution")
                if resolution is not None and not isinstance(resolution, dict):
                    result.scan_failures.append("pnpm-lock.yaml: invalid selected package record")
                    continue
                if isinstance(resolution, dict):
                    tarball = resolution.get("tarball")
                    if resolution.get("type") in {"directory", "git"} or (
                        isinstance(tarball, str) and tarball.startswith(("file:", "link:"))
                    ):
                        result.surfaces_excluded.append(
                            "pnpm-lock.yaml: local or non-registry resolution is unverified"
                        )
                        continue
                    integrity = resolution.get("integrity")
                # The key is the component's name and exact version, then any peers.
                peers = ver_ref[len(ver_ref.split("(", 1)[0]) :]
                recorded = pkg_key
                if peers and pkg_key.endswith(peers) and not _plain_pnpm_peers(peers):
                    recorded = pkg_key[: -len(peers)] + f"({REDACTED})"
                locator = "pnpm-lock.yaml#/packages/" + _pointer_token(recorded)
            else:
                locator = "pnpm-lock.yaml#/importers/./" + _pointer_token(comp.name)
            selected_specs = specifiers.get(comp.name, set())
            requested = next(iter(selected_specs)) if len(selected_specs) == 1 else None
            kind, alias_target, _ = (
                self._npm_spec(requested) if requested is not None else ("registry", None, "")
            )
            unresolved_alias = kind == "alias" and alias_target != comp.name
            bind_identity = kind == "registry" or (kind == "alias" and not unresolved_alias)
            if unresolved_alias:
                comp.registry_uri = None
                result.surfaces_excluded.append(
                    "pnpm-lock.yaml: aliased package identity is unresolved"
                )
            elif not bind_identity and requested is not None:
                comp.registry_uri = None
                risk = self._npm_source_risk(comp.name, kind, requested)
                if risk not in comp.risks:
                    comp.risks.append(risk)
                result.surfaces_excluded.append(
                    f"pnpm-lock.yaml: selected non-registry source for {comp.name} is unverified"
                )
            elif self._sections_disagree((declared_specs or {}).get(comp.name)):
                # The sections name different sources, so which one installs depends on
                # the install flags: the record's checks run, its identity is not bound.
                bind_identity = False
                result.surfaces_excluded.append(
                    f"pnpm-lock.yaml: conflicting dependency sources for {comp.name} are ambiguous"
                )
            self._bind_npm_resolution(
                comp,
                "pnpm-lock.yaml",
                "pnpm-lockfile",
                base_ver,
                tarball,
                integrity,
                locator,
                lock_digest,
                result,
                requested=requested,
                bind_identity=bind_identity,
            )
        return True

    @classmethod
    def _sections_disagree(cls, specs: Sequence[tuple[str, str]] | None) -> bool:
        """Whether package.json's sections declare a name from different sources. Which
        one installs then depends on the install flags (--omit=dev, --no-optional), so
        no lockfile record decides the identity."""
        identities: set[tuple[str, str | None]] = set()
        for _, spec in specs or ():
            kind, target, _ = cls._npm_spec(spec)
            identities.add((kind, target if kind == "alias" and target else None))
        return len(identities) > 1

    @staticmethod
    def _pnpm_spec_agrees(
        recorded: set[str] | None,
        specs: list[tuple[str, str]] | None,
        override: str | None,
    ) -> bool:
        """Whether the lockfile records, as its only spec for a dependency, the one pnpm
        takes from package.json, or the override pnpm writes in its place. A lockfile
        that records none was not resolved for package.json."""
        if not specs:
            return True
        by_section = dict(specs)
        taken = next(
            by_section[section] for section in _PNPM_SECTION_ORDER if section in by_section
        )
        return any(recorded == {spec} for spec in (taken, override) if spec is not None)

    @staticmethod
    def _pnpm_override_specs(data: dict[str, Any]) -> dict[str, str]:
        """The spec pnpm's overrides give each name they select whole: Yarn's
        ``resolutions``, then ``pnpm.overrides`` over it, as pnpm merges them. A
        selector with a range or a parent, or a ``$`` reference, is not resolved here,
        so a lockfile resolved through one is not bound."""
        found: dict[str, str] = {}
        for path in (("resolutions",), ("pnpm", "overrides")):
            node: Any = data
            for part in path:
                node = node.get(part) if isinstance(node, dict) else None
            for name, spec in node.items() if isinstance(node, dict) else ():
                if isinstance(spec, str) and not spec.startswith("$"):
                    found[name] = spec
                else:
                    found.pop(name, None)
        return found

    def _pnpm_patched_component(
        self, component: RegistryEntryComponent, result: ScanResult
    ) -> None:
        """Leave a package the lockfile records as patched unbound, with the gap and
        finding a patch that package.json names gives it."""
        component.package_url = None
        self._pnpm_patch_gap(result)
        component.risks.append(self._npm_patch_risk(component.name, ["pnpm-lock.yaml"]))

    def _pnpm_patch_gap(self, result: ScanResult) -> None:
        gap = f"pnpm-lock.yaml: {self._PATCHED_GAP}"
        if gap not in result.surfaces_excluded:
            result.surfaces_excluded.append(gap)

    def _resolve_yarn_lockfile(
        self,
        lock_bytes: bytes,
        components: list[RegistryEntryComponent],
        result: ScanResult,
        cache_key: str | None,
        *,
        declared_specs: dict[str, list[tuple[str, str]]] | None = None,
    ) -> bool:
        """Bind Yarn records to the components, which package.json declares from a
        registry. ``cache_key`` is the one Yarn 4 computes for the project, None when it
        checks no checksum. False when the lockfile is not read."""
        try:
            metadata, stanzas = _yarn_lockfile_stanzas(lock_bytes.decode("utf-8"))
        except (ValueError, UnicodeError):
            result.scan_failures.append("yarn.lock: invalid or unsupported lockfile")
            return False
        berry = metadata is not None
        lock_digest = hash_bytes(lock_bytes)
        by_pkg: dict[str, list[tuple[str, dict[str, str], int]]] = {}
        for index, (selectors, fields) in enumerate(stanzas):
            for sel in selectors:
                at_idx = sel.find("@", 1) if sel.startswith("@") else sel.find("@")
                if at_idx <= 0:
                    continue
                sel_name, sel_spec = sel[:at_idx], sel[at_idx + 1 :]
                by_pkg.setdefault(sel_name, []).append((sel_spec, fields, index))
        # Yarn 4 keeps what it reads by hash, so the last record of a locator replaces
        # its package, checksum and conditions, and a name it hashes alike, as it does
        # `@op/enai` and `openai`, resolves the other's descriptors and locators.
        alike: dict[str, set[str]] = {}
        locators: Counter[tuple[str, str]] = Counter()
        for selectors, fields in stanzas if berry else ():
            resolution = _berry_hashed(fields.get("resolution", ""))
            if resolution is not None:
                locators[resolution[1:]] += 1
            for hashed in (*map(_berry_hashed, selectors), resolution):
                if hashed is not None:
                    alike.setdefault(hashed[1], set()).add(hashed[0])
        for comp in components:
            alias = comp.properties.get("npm_alias")
            if alias is not None:
                # Only npm's own lockfile record is resolved against an alias's package.
                if alias in by_pkg or _berry_ident(alias) in alike:
                    comp.package_url = None
                    result.surfaces_excluded.append(
                        "yarn.lock: aliased package identity is unresolved"
                    )
                continue
            if alike.get(_berry_ident(comp.name), {comp.name}) != {comp.name}:
                comp.package_url = None
                result.surfaces_excluded.append(
                    f"yarn.lock: multiple package resolutions for {comp.name} are ambiguous"
                )
                continue
            raw_specs = (declared_specs or {}).get(comp.name, ())
            req = (
                raw_specs[-1][1] if raw_specs else str(comp.properties.get("requested_version", ""))
            ).strip()
            # requested_version is npm's choice, the last section's spec. Yarn 1 takes
            # another, so a decoy spec in devDependencies must not pick the record;
            # which one Yarn Berry takes is not resolved here.
            by_section = dict(raw_specs)
            installed = [by_section[s] for s in _YARN_V1_SECTION_ORDER if s in by_section]
            if len(set(installed)) > 1:
                comp.package_url = None
                if berry:
                    result.surfaces_excluded.append(
                        f"yarn.lock: multiple package resolutions for {comp.name} are ambiguous"
                    )
                    continue
                parsed_installed = [(item, *self._npm_spec(item)) for item in installed]
                if any(
                    item_kind == "alias" and item_target != comp.name
                    for _, item_kind, item_target, _ in parsed_installed
                ):
                    comp.registry_uri = None
                    result.surfaces_excluded.append(
                        "yarn.lock: aliased package identity is unresolved"
                    )
                    continue
                nonreg = [
                    (item, item_kind)
                    for item, item_kind, _, _ in parsed_installed
                    if item_kind not in ("registry", "alias")
                ]
                if nonreg:
                    comp.registry_uri = None
                    if not any(r.category == "nonregistry_source" for r in comp.risks):
                        comp.risks.append(
                            self._npm_source_risk(comp.name, nonreg[0][1], nonreg[0][0])
                        )
                    result.surfaces_excluded.append(
                        f"yarn.lock: selected non-registry source for {comp.name} is unverified"
                    )
                    continue
                selected = next((spec for spec in installed if spec not in ("", "*")), installed[0])
                req = selected.strip()
            entries = by_pkg.get(comp.name)
            if not entries:
                continue
            # As for pnpm: the record decides the identity, or nothing does.
            comp.package_url = None
            chosen = [e for e in entries if e[0] in (req, f"npm:{req}")]
            if not chosen:
                continue
            # Yarn keeps the last stanza of a repeated selector, and which of `X` and
            # `npm:X` it looks up depends on its version; more than one stanza binds none.
            if len({e[2] for e in chosen}) > 1:
                result.surfaces_excluded.append(
                    f"yarn.lock: multiple package resolutions for {comp.name} are ambiguous"
                )
                continue
            sel_spec, fields, chosen_index = chosen[0]
            # Yarn 1 installs the first stanza of the package it resolves with the same
            # version, which may be another range's, by package.json key order.
            source = _yarn_source(fields)
            if not berry and any(
                e[2] != chosen_index
                and e[1].get("version") == fields.get("version")
                and _yarn_source(e[1]) != source
                for e in entries
            ):
                result.surfaces_excluded.append(
                    f"yarn.lock: multiple package resolutions for {comp.name} are ambiguous"
                )
                continue
            resolution_val = fields.get("resolution", "")
            resolved_val = fields.get("resolved", "")
            if sel_spec.lower().startswith("npm:") and (
                req.lower().startswith("npm:") or sel_spec != f"npm:{req}" or "@" in sel_spec[4:]
            ):
                _, alias_pkg, _ = self._npm_spec(sel_spec)
                if alias_pkg and alias_pkg != comp.name:
                    comp.registry_uri = None
                    result.surfaces_excluded.append(
                        "yarn.lock: aliased package identity is unresolved"
                    )
                    continue
            if "@npm:" in resolution_val and not resolution_val.startswith(f"{comp.name}@npm:"):
                result.surfaces_excluded.append("yarn.lock: aliased package identity is unresolved")
                continue
            non_registry_prefixes = (
                "workspace:",
                "link:",
                "portal:",
                "file:",
                "patch:",
                "git+",
                "git:",
            )
            if (
                sel_spec.startswith(non_registry_prefixes)
                or resolved_val.startswith(non_registry_prefixes)
                or any(f"@{p}" in resolution_val for p in non_registry_prefixes)
                or fields.get("linkType") == "soft"
            ):
                result.surfaces_excluded.append(
                    "yarn.lock: local or non-registry resolution is unverified"
                )
                continue
            resolved_version = fields.get("version")
            if (
                not isinstance(resolved_version, str)
                or len(resolved_version) > _LONGEST_VERSION
                or not _npm_exact(resolved_version)
            ):
                result.scan_failures.append("yarn.lock: selected package lacks an exact version")
                continue
            if "resolution" in fields and resolution_val != f"{comp.name}@npm:{resolved_version}":
                # Yarn Berry fetches the locator its resolution names, which has no
                # resolved URL to check: only the registry's package and version is one.
                result.surfaces_excluded.append(
                    "yarn.lock: local or non-registry resolution is unverified"
                )
                continue
            bound = _berry_hashed(resolution_val)
            if bound is not None and locators[bound[1:]] > 1:
                result.surfaces_excluded.append(
                    f"yarn.lock: multiple package resolutions for {comp.name} are ambiguous"
                )
                continue
            # The selector that matched holds only the name and spec the inventory
            # records; another selector of the stanza may be a URL with a credential.
            locator = "yarn.lock#/" + _pointer_token(f"{comp.name}@{sel_spec}")
            disputed = self._sections_disagree(raw_specs)
            if disputed:
                # As for pnpm: the record's checks run, its identity is not bound.
                result.surfaces_excluded.append(
                    f"yarn.lock: conflicting dependency sources for {comp.name} are ambiguous"
                )
            # Yarn 1 reads `integrity` and not `checksum`, and Berry the reverse.
            self._bind_npm_resolution(
                comp,
                "yarn.lock",
                "yarn-lockfile",
                resolved_version,
                resolved_val or None,
                None if metadata is not None else fields.get("integrity"),
                locator,
                lock_digest,
                result,
                checksum_recorded=metadata is not None
                and _berry_checksum_checked(fields, metadata, cache_key),
                requested=req,
                bind_identity=not disputed,
            )
        return True

    _OVERRIDE_FIELDS = (("overrides",), ("resolutions",), ("pnpm", "overrides"))
    _OVERRIDE_ENTRIES = 10_000
    # Bun patches the packages the top-level field names, and pnpm those of its own.
    _PATCHED_FIELDS = (("patchedDependencies",), ("pnpm", "patchedDependencies"))

    @classmethod
    def _patched_names(cls, node: Any) -> frozenset[str] | None:
        """The lower-case names of the packages a ``patchedDependencies`` map patches.

        A key is a name, or a name and the version or range it patches; any version
        counts. None when the map is not one, has more entries than are read, or has a
        key that names no package.
        """
        if node is None:
            return frozenset()
        if not isinstance(node, dict) or len(node) > cls._OVERRIDE_ENTRIES:
            return None
        names: set[str] = set()
        for key in node:
            text = str(key).strip().lstrip("/")
            at = text.find("@", text.find("/") + 1 if text.startswith("@") else 1)
            name = (text if at < 0 else text[:at]).strip().lower()
            if not name:
                return None
            names.add(name)
        return frozenset(names)

    def _npm_patches(
        self, data: dict[str, Any], result: ScanResult, *, workspace: bool
    ) -> dict[str, frozenset[str] | None]:
        """The names package.json, and with ``workspace`` pnpm-workspace.yaml, patch,
        by file; None for a file whose names are not known, which then counts for
        every package."""
        patches: dict[str, frozenset[str] | None] = {}
        manifest: frozenset[str] | None = frozenset()
        for path in self._PATCHED_FIELDS:
            node: Any = data
            for part in path:
                node = node.get(part) if isinstance(node, dict) else None
            names = self._patched_names(node)
            manifest = None if names is None or manifest is None else manifest | names
        if manifest is None or manifest:
            patches["package.json"] = manifest
        if workspace:
            names = self._workspace_patches(result)
            if names is None or names:
                patches["pnpm-workspace.yaml"] = names
        return patches

    def _workspace_patches(self, result: ScanResult) -> frozenset[str] | None:
        """The names pnpm-workspace.yaml patches, which pnpm 10 reads there, parsed as
        pnpm-lock.yaml is; None when the file is not read."""
        files = self._confined()
        before = files.failures_recorded, files.exclusions_recorded
        if self._withheld("pnpm-workspace.yaml", result):
            return None
        text = files.read_text("pnpm-workspace.yaml", missing_ok=True)
        if text is None:
            unread = (files.failures_recorded, files.exclusions_recorded) != before
            return None if unread else frozenset()
        result.surfaces_scanned.append("pnpm-workspace.yaml")
        try:
            import yaml
        except ImportError:
            result.scan_failures.append("pnpm-workspace.yaml: YAML parser unavailable")
            return None
        from nexus_symbiote.policy import PolicyError, parse_yaml_mapping

        frame = (
            yaml.StreamStartToken,
            yaml.StreamEndToken,
            yaml.DocumentStartToken,
            yaml.DocumentEndToken,
        )
        try:
            loader = self._bounded_yaml_loader()
            empty = True
            for index, token in enumerate(yaml.scan(text, Loader=loader)):
                if index >= _MAX_PNPM_LOCK_TOKENS or isinstance(
                    token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)
                ):
                    raise ValueError("unsupported YAML graph")
                empty = empty and isinstance(token, frame)
            # A file of comments, or an empty document, holds no settings.
            workspace = {} if empty else parse_yaml_mapping(text)
        except (ValueError, UnicodeError, PolicyError, RecursionError, yaml.YAMLError):
            result.scan_failures.append(
                "pnpm-workspace.yaml: invalid or unsupported workspace file"
            )
            return None
        return self._patched_names(workspace.get("patchedDependencies"))

    @classmethod
    def _npm_overrides(cls, data: dict[str, Any]) -> tuple[set[str], set[str], set[str]] | None:
        """The package names npm, yarn and pnpm override fields name, the alias
        targets they install, and the packages they replace with a git, URL or path
        source; None when there are too many entries to read."""
        names: set[str] = set()
        targets: set[str] = set()
        sources: set[str] = set()
        stack: list[tuple[Any, int, list[str]]] = []
        for path in cls._OVERRIDE_FIELDS:
            node: Any = data
            for part in path:
                node = node.get(part) if isinstance(node, dict) else None
            if node is not None:
                stack.append((node, 0, []))
        remaining = cls._OVERRIDE_ENTRIES
        while stack:
            node, depth, parent = stack.pop()
            if not isinstance(node, dict):
                continue
            for selector, value in node.items():
                remaining -= 1
                if remaining < 0 or depth > 32:
                    return None
                selected = cls._override_names(str(selector))
                names.update(name.lower() for name in selected)
                if isinstance(value, dict):
                    stack.append((value, depth + 1, selected or parent))
                elif isinstance(value, str):
                    kind, target, _ = cls._npm_spec(value)
                    if kind == "alias" and target:
                        targets.add(target)
                    elif kind in ("git", "url", "path"):
                        # The last name is the package replaced; "." replaces the
                        # package of the enclosing selector.
                        sources.update((selected or parent)[-1:])
        return names, targets, sources

    @staticmethod
    def _override_names(selector: str) -> list[str]:
        """Package names in an override selector: "name@range" (npm), "a/**/name"
        (yarn resolutions) or "a>name" (pnpm), with scoped names kept whole."""
        names: list[str] = []
        for part in selector.split(">"):
            segments = part.split("/")
            index = 0
            while index < len(segments):
                segment = segments[index]
                index += 1
                if segment.startswith("@") and index < len(segments):
                    segment += "/" + segments[index]
                    index += 1
                at = segment.find("@", 1)
                segment = segment[:at] if at > 0 else segment
                if segment not in ("", "**", "*", "."):
                    names.append(segment)
        return names

    _PIP_NAME = re.compile(r"[a-zA-Z0-9_.-]+")

    def _pip_declaration(
        self,
        reference: str,
        source: str,
        result: ScanResult | None = None,
        group: str = "",
        hashes: tuple[str, ...] = (),
        untranslated: str | None = None,
    ) -> _PipDeclaration | None:
        """A declaration of an inventoried PyPI package, or None for any other name."""
        match = self._PIP_NAME.match(reference)
        if not match or not self._is_ai_package(match.group()):
            return None
        # Redacted before canonicalize_name lowercases a credential out of its shape.
        shown, redacted = _identifier(match.group())
        name = str(canonicalize_name(shown))
        if untranslated is not None:
            # The bare name, never compared: what it leaves out is unknown.
            return _PipDeclaration(
                name,
                source,
                reference,
                shown,
                None,
                group,
                untranslated=untranslated,
                redacted=redacted,
            )
        try:
            requirement = Requirement(reference)
            shown, redacted = _identifier(requirement.name)
            redacted = redacted or any(_identifier(extra)[1] for extra in requirement.extras)
            name = str(canonicalize_name(shown))
            # Retain markers and URLs as declared, unresolved conditions; they
            # must not silently turn into an unconditional exact package URL.
            marker = str(requirement.marker) if requirement.marker else ""
            # Packaging normalizes extra-marker operands, including case and
            # underscores. Check the original marker before that can hide a token.
            raw_marker = ""
            if marker:
                after_url = (
                    reference.partition(requirement.url)[2] if requirement.url else reference
                )
                raw_marker = after_url.partition(";")[2] or reference
            sensitive_marker = holds_token_shape(raw_marker, require_sk_boundary=True)
            sensitive = sensitive_marker or holds_token_shape(
                str(requirement.specifier), require_sk_boundary=True
            )
            if requirement.url:
                spec = "@ " + _url_origin(requirement.url)
            else:
                spec = _unparsed(str(requirement.specifier))
            if marker:
                spec += "; " + _unparsed(marker)
            recorded = shown + REDACTED if sensitive else _recorded_requirement(requirement)
            pin = _exact_pin(requirement)
        except (InvalidRequirement, RecursionError):
            # packaging parses markers by recursion; a deeply nested one is invalid
            # input for this line, not the end of the collection.
            if result is not None:
                message = f"{source}: invalid or unsupported PyPI requirement"
                if message not in result.scan_failures:
                    result.scan_failures.append(message)
            # Redacted whole: the name before the value can be what marks it as a
            # credential, as in COHERE_API_KEY=..., so it must not be cut off first.
            whole = redact_text(_unparsed(reference))
            spec = (
                whole[len(match.group()) :].strip() if whole.startswith(match.group()) else REDACTED
            )
            return _PipDeclaration(
                name=name,
                source=source,
                reference=reference,
                recorded=_unparsed(reference),
                spec=spec or None,
                group=group,
                untranslated="invalid",
                hashes=hashes,
                redacted=redacted,
            )
        return _PipDeclaration(
            name=name,
            source=source,
            reference=reference,
            recorded=recorded,
            spec=REDACTED if sensitive else redact_text(spec) or None,
            group=group,
            requirement=requirement,
            hashes=hashes,
            marker=marker,
            sensitive_marker=sensitive_marker,
            pin=pin[0] if pin else None,
            pin_key=pin[1] if pin else None,
            redacted=redacted or sensitive,
        )

    def _pip_component(
        self, line: str, path: Path, result: ScanResult | None = None
    ) -> RegistryEntryComponent | None:
        """The component one requirement line alone declares."""
        reference = line.strip().split(" #", 1)[0].strip()
        declaration = self._pip_declaration(reference, str(path), result)
        if declaration is None:
            return None
        package = _Package()
        package.add(declaration)
        return self._pypi_component(package)

    @staticmethod
    def _pypi_component(package: _Package) -> RegistryEntryComponent:
        """One component from every declaration of a package, in the order read.

        The version, package URL and findings follow from all of them, whichever file
        is read first. The first exact pin without a marker is the version reported,
        and it resolves the ranges it satisfies in every file, as a compiled
        requirements file resolves the ranges of pyproject.toml; a range it does not
        satisfy, under any marker or group, is a version_pinning finding. A URL or VCS
        declaration anywhere is a finding and no PyPI package URL. A package URL is
        emitted only when every exact pin names the same version, every other
        declaration admits it, and nothing conflicts or is left untranslated.
        """
        declarations = package.declarations
        name = declarations[0].name
        urls: list[_PipDeclaration] = []
        others: list[_PipDeclaration] = []
        for declaration in declarations:
            requirement = declaration.requirement
            (urls if requirement is not None and requirement.url else others).append(declaration)
        exact = [d for d in others if d.pin is not None]
        unconditional = [d for d in exact if not d.marker]
        chosen = package.representative
        loose: list[_PipDeclaration] = []
        if chosen.pin is not None and unconditional:
            pinned = _parsed(chosen.pin)
            loose = [
                d
                for d in others
                if d.pin is None
                and d.requirement is not None
                and not _satisfies(d.requirement, chosen.pin, pinned)
            ]
        risks: list[RiskAssessment] = []
        if urls:
            files = ", ".join(dict.fromkeys(d.source for d in urls))
            mutable = any(
                d.requirement is not None
                and d.requirement.url
                and (
                    d.requirement.url.lower().startswith("http://")
                    or (
                        re.match(r"(?:git|hg|svn|bzr)\+", d.requirement.url, re.I) is not None
                        and not _vcs_pinned(d.requirement.url)
                    )
                )
                for d in urls
            )
            risks.append(
                _risk(
                    RiskSeverity.HIGH if mutable else RiskSeverity.MEDIUM,
                    "nonregistry_source",
                    f"PyPI package '{name}' is declared from a URL, VCS or path source in {files}.",
                    "Install it from the package index with an exact version and verified "
                    "hashes, or review the source and pin it to a full commit.",
                )
            )
        if others and not unconditional:
            if all(d.pin is not None for d in others):
                risks.append(
                    _risk(
                        RiskSeverity.LOW,
                        "version_pinning",
                        f"PyPI package '{name}' is pinned only under environment markers.",
                        "Check that every environment the project supports has a pin, and "
                        "verify artifact hashes.",
                    )
                )
            else:
                risks.append(
                    _risk(
                        RiskSeverity.MEDIUM,
                        "version_pinning",
                        f"PyPI package '{name}' has an unresolved or nonexact declared reference.",
                        "Resolve the declared conditions, pin the version and verify artifact "
                        "hashes.",
                    )
                )
        elif loose and not package.conflict:
            files = ", ".join(dict.fromkeys(d.source for d in loose))
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM,
                    "version_pinning",
                    f"PyPI package '{name}' has a nonexact declaration in {files} that its "
                    "exact pin does not satisfy.",
                    "Make every declaration admit the pinned version, pin it where it floats, "
                    "and verify artifact hashes.",
                )
            )
        if package.conflict:
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM,
                    "version_pinning",
                    f"PyPI package '{name}' is declared more than once with requirements that "
                    "conflict.",
                    "Check that each declaration is intended, make them agree where possible, "
                    "and verify artifact hashes.",
                )
            )
        redacted = any(d.redacted for d in declarations)
        if redacted:
            where = "version" if any(d.spec == REDACTED for d in declarations) else "name or extras"
            if any(d.sensitive_marker for d in declarations):
                where = "environment marker"
            risks.append(_identifier_risk(f"PyPI package '{name}'", where))
        package_url = None
        if (
            unconditional
            and not urls
            and not loose
            and not package.conflict
            and not redacted
            and all(d.untranslated is None for d in declarations)
            and len({d.pin_key for d in exact}) == 1
            and chosen.pin is not None
        ):
            package_url = f"pkg:pypi/{quote(name, safe='')}@{quote(chosen.pin, safe='')}"
        origins = {
            _url_origin(d.requirement.url)
            for d in urls
            if d.requirement is not None and d.requirement.url
        }
        registry_uri: str | None = "https://pypi.org"
        if urls or any(d.untranslated in ("source", "index", "override") for d in declarations):
            registry_uri = origins.pop() if not others and len(origins) == 1 else None
        if redacted:
            registry_uri = None
        properties: dict[str, Any] = {
            "collection_mode": "manifest-reference",
            "registry_origin_verified": False,
            "requested_requirement": chosen.recorded,
        }
        if len(package.sources) > 1:
            properties["declarations"] = sorted(package.sources)
        hashes = sorted({f"{d.source}: {value}" for d in declarations for value in d.hashes})
        if hashes:
            # pip checks the artifact against these; a changed or removed hash is drift.
            properties["requirement_hashes"] = hashes
        return RegistryEntryComponent(
            bom_ref=f"registry:pypi/{reference_text(name)}",
            name=name,
            version=chosen.spec,
            package_url=package_url,
            registry_type="pypi",
            registry_uri=registry_uri,
            source_path=chosen.source,
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties=properties,
        )

    _COMMENT = re.compile(r"(?:^|\s)#.*$")
    # The options pip accepts in a requirements file that add or constrain packages.
    _PACKAGE_OPTIONS = {
        "--requirement": "requirements include not followed",
        "--constraint": "constraints file not followed",
        "--editable": "editable install not followed",
    }
    # Every option pip 26.3 accepts in a requirements file, and whether it takes a value.
    _PIP_OPTIONS = {
        "--index-url": True,
        "--pypi-url": True,
        "--extra-index-url": True,
        "--no-index": False,
        "--constraint": True,
        "--requirement": True,
        "--editable": True,
        "--find-links": True,
        "--no-binary": True,
        "--only-binary": True,
        "--prefer-binary": False,
        "--require-hashes": False,
        "--no-require-hashes": False,
        "--pre": False,
        "--all-releases": True,
        "--only-final": True,
        "--trusted-host": True,
        "--use-feature": True,
        "--hash": True,
        "--config-settings": True,
    }
    _SHORT_OPTIONS = {
        "i": "--index-url",
        "c": "--constraint",
        "r": "--requirement",
        "e": "--editable",
        "f": "--find-links",
        "C": "--config-settings",
    }
    # shlex's whitespace; str.split() would also split on a no-break space.
    _SHLEX_SPACE = re.compile(r"[ \t\r\n]+")
    # pip replaces ${NAME} with the environment variable before it reads a line.
    _ENV_VAR = re.compile(r"\$\{[A-Z0-9_]+\}")
    _ENV_NAME = re.compile(r"[A-Za-z0-9_.-]*\$\{[A-Z0-9_]+\}")
    # pip decodes a file without a byte order mark by the PEP 263 declaration in its
    # first two lines.
    _CODING = re.compile(r"coding[:=]\s*([-\w.]+)", re.ASCII)
    # A URL scheme as urlsplit finds one, after it drops leading C0 controls and spaces
    # and every tab, CR and LF. Any scheme, not only pip's: no PEP 508 name has one.
    _URL_SCHEME = re.compile(r"[\x00-\x20]*[A-Za-z0-9+.-]+:")
    _URL_DROPPED = dict.fromkeys(map(ord, "\t\r\n"))
    # "name @ URL", which pip reads by its name.
    _NAMED_URL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*[ \t]*(?:\[[^\]/\\]*\][ \t]*)?@")
    # pip 26.3's archive extensions.
    _ARCHIVES = (
        ".zip",
        ".whl",
        ".tar.bz2",
        ".tbz",
        ".tar.gz",
        ".tgz",
        ".tar",
        ".tar.xz",
        ".txz",
        ".tlz",
        ".tar.lz",
        ".tar.lzma",
    )

    @staticmethod
    def _requirement_files(entries: list[str]) -> list[str]:
        # Without regard to case, as a fixed-name open is on macOS and Windows file
        # systems. The exact name, which pip reads on a case-sensitive system, comes
        # first, then its case variants, then the other files.
        names = [n for n in entries if fnmatch.fnmatchcase(n.casefold(), "requirements*.txt")]
        return sorted(
            names,
            key=lambda n: (n.casefold() != "requirements.txt", n != "requirements.txt", n),
        )

    @classmethod
    def _options(cls, text: str) -> tuple[list[tuple[str, str]], list[str]]:
        """The options pip reads from option words, with their values, and what it
        may read that is not known.

        pip splits the words with shlex and parses them with optparse, so one line
        can hold several options, and "-rX", "-r X", "--requirement=X" and an
        unambiguous prefix of a long name all apply. An option that takes a value
        takes the next word, even "--". An option pip 26.3 does not know may take
        one in another pip.
        """
        if cls._unsplittable(text):
            return [], ["option line not parsed"]
        quoted = any(c in text for c in "\"'\\")
        try:
            words = shlex.split(text) if quoted else [w for w in cls._SHLEX_SPACE.split(text) if w]
        except ValueError:
            return [], ["option line not parsed"]
        options: list[tuple[str, str]] = []
        problems: list[str] = []
        index = 0
        while index < len(words):
            word = words[index]
            index += 1
            if word == "--":
                # optparse leaves the rest as arguments, which pip ignores.
                break
            if not word.startswith("-") or word == "-":
                if cls._ENV_VAR.search(word):
                    # An ignored argument, unless the variable holds an option.
                    problems.append("environment variable not resolved")
                continue
            if word.startswith("--"):
                name, equals, value = word.partition("=")
                found = [o for o in cls._PIP_OPTIONS if o.startswith(name)]
                if name in cls._PIP_OPTIONS:
                    found = [name]
                option = found[0] if len(found) == 1 else None
                attached = bool(equals)
            else:
                option = cls._SHORT_OPTIONS.get(word[1])
                value, attached = word[2:], len(word) > 2
            if option is None:
                variable = cls._ENV_VAR.search(word.partition("=")[0])
                problems.append(
                    "environment variable not resolved" if variable else "option line not parsed"
                )
                continue
            if cls._PIP_OPTIONS[option] and not attached:
                value = words[index] if index < len(words) else ""
                index += 1
            options.append((option, value))
        return options, problems

    @staticmethod
    def _unsplittable(text: str) -> bool:
        """Whether option text is too long for shlex, whose cost grows with the square
        of a quoted word's length."""
        return len(text) > _LONGEST_OPTIONS and any(c in text for c in "\"'\\")

    @classmethod
    def _option_gaps(
        cls, options: list[tuple[str, str]], names: set[str], entries: set[str]
    ) -> list[str]:
        """What the options of a line add or pin that the collector does not read.

        The gap never names the target, which can be a URL carrying a credential.
        """
        gaps: list[str] = []
        for option, value in options:
            gap = cls._PACKAGE_OPTIONS.get(option)
            if gap is None:
                continue
            covered = (
                cls._editable_covered(value, entries)
                if option == "--editable"
                else cls._include_covered(value, names)
            )
            if not covered:
                gaps.append(gap)
        return gaps

    @staticmethod
    def _include_covered(target: str, names: set[str]) -> bool:
        """Whether -r or -c names a root requirements file the collector reads."""
        parts = [part for part in target.split("/") if part not in ("", ".")]
        return (
            len(parts) == 1
            and not target.startswith("/")
            # A separator on Windows and a name character elsewhere; pip expands
            # ${VAR} from the environment.
            and not any(c in target for c in "\\$")
            and parts[0].casefold() in names
        )

    # The format characters HFS+ ignores when it compares names.
    _IGNORED_IN_NAMES = dict.fromkeys(
        [*range(0x200C, 0x2010), *range(0x202A, 0x202F), *range(0x206A, 0x2070), 0xFEFF]
    )

    @classmethod
    def _fold(cls, name: str) -> str:
        """A name as file systems may compare it.

        Case and Unicode normalisation are folded, as on APFS, HFS+ and NTFS; so are
        the format characters HFS+ ignores and the trailing dots and spaces Windows
        drops.
        """
        folded = unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())
        return folded.translate(cls._IGNORED_IN_NAMES).rstrip(". ")

    @classmethod
    def _editable_covered(cls, target: str, entries: set[str]) -> bool:
        """Whether -e installs the project itself, whose pyproject.toml is read."""
        # One trailing extras group, as pip strips it from a local path.
        match = re.fullmatch(r"([^\[\]]+)(?:\[[^\[\]]+\])?", target)
        if match is None:
            return False
        path = match.group(1)
        if path[:5].lower() == "file:":
            # pip installs a directory with that name instead, if there is one.
            if cls._fold(path.split("/", 1)[0]) in entries:
                return False
            path = path[5:]
        return (
            bool(path)
            and not path.startswith("/")
            and all(part in ("", ".") for part in path.split("/"))
        )

    @staticmethod
    def _without_extras(path: str) -> str:
        """pip's strip_extras in linear time: the text before a last bracketed group
        that runs to the end and holds no "]", without the white space before it."""
        end = len(path) - 1
        if end < 0 or path[end] != "]":
            return path
        start = path.rfind("[", path.rfind("]", 0, end) + 1, end - 1)
        return path[:start].rstrip() if start >= 0 else path

    @staticmethod
    def _normalised(parts: list[str]) -> list[str] | None:
        """Path parts as normpath leaves them, or None if they leave the directory."""
        kept: list[str] = []
        for part in parts:
            if part == "..":
                if not kept:
                    return None
                kept.pop()
            elif part not in ("", "."):
                kept.append(part)
        return kept

    @classmethod
    def _local_paths(cls, target: str) -> Iterator[list[str] | None]:
        """The paths pip 26.3 may read a requirement as, relative to where it runs.

        pip normalises the whole text as a path, with "/" as the only separator on
        POSIX and with "\\" as well on Windows, and then takes the extras off; the
        file system resolves a "." or ".." this leaves. None stands for a path that
        leaves the directory.
        """
        for separators in ("/", r"[/\\]"):
            parts = cls._normalised(re.split(separators, target))
            if parts is not None:
                rest = cls._without_extras("/".join(parts))
                parts = cls._normalised(re.split(separators, rest))
            yield parts

    @classmethod
    def _unnamed(cls, reference: str, entries: set[str]) -> bool:
        """Whether pip installs a requirement from a URL, an archive or a path other
        than the project itself, where the collector reads no package name.

        pip 26.3 takes a URL by its scheme, then a path with a separator or a leading
        ".", then a name ending in an archive extension once the extras are off;
        only then a PEP 508 requirement. Whether such a directory or file exists is
        known only where pip runs, so it is taken to exist.
        """
        named = cls._NAMED_URL.match(reference) is not None
        url = not named and cls._URL_SCHEME.match(reference.translate(cls._URL_DROPPED))
        # pip's marker separator, which a URL may contain without a space.
        target = reference.split("; " if url else ";", 1)[0].strip()
        if named:
            return cls._shadowed(target, entries)
        if url:
            # pip takes extras off a path but not off a URL: "file:.[dev]" is a
            # directory named ".[dev]".
            return "[" in target or not cls._editable_covered(target, entries)
        if not (
            any(c in target for c in "/\\")
            or target.startswith(".")
            or cls._without_extras(target).lower().endswith(cls._ARCHIVES)
        ):
            return False
        return any(path != [] for path in cls._local_paths(target))

    @classmethod
    def _bare_archive(cls, reference: str) -> bool:
        """Whether a requirements line is a bare local archive filename rather than a named package."""
        if cls._NAMED_URL.match(reference) is not None:
            return False
        if cls._URL_SCHEME.match(reference.translate(cls._URL_DROPPED)):
            return False
        target = reference.split(";", 1)[0].strip()
        if not target or any(c in target for c in "/\\") or target.startswith("."):
            return False
        return cls._without_extras(target).lower().endswith(cls._ARCHIVES)

    @classmethod
    def _shadowed(cls, target: str, entries: set[str]) -> bool:
        """Whether pip may install "name @ URL" from a local path instead.

        pip first reads the whole text as a path and installs a directory or archive
        it finds there. Such a path can exist where pip runs only if it leaves that
        directory or starts with an entry of the project root. A "~" may make the
        entry's Windows short name, and a ":" may start an NTFS stream name.
        """
        for path in cls._local_paths(target):
            if path is None:
                return True
            if path:
                first = cls._fold(path[0])
                if "~" in first or {first, first.partition(":")[0].rstrip(". ")} & entries:
                    return True
        return False

    # Python's names for UTF-8, lower case with "-" as "_".
    _UTF8_NAMES = frozenset({"utf_8", "utf8", "u8", "utf", "cp65001", "utf_8_sig"})

    @classmethod
    def _declares_other_encoding(cls, content: str) -> bool:
        """Whether pip decodes the file by a PEP 263 declaration of another encoding."""
        if content.startswith("\ufeff"):
            return False
        for line in content.split("\n", 2)[:2]:
            match = cls._CODING.search(line) if line.startswith("#") else None
            if match is not None:
                return match.group(1).lower().replace("-", "_") not in cls._UTF8_NAMES
        return False

    @staticmethod
    def _requirement_lines(content: str) -> list[str]:
        """Logical lines as pip's join_lines builds them.

        A trailing backslash continues a line and the parts are joined with nothing
        in between, so a URL or version wrapped mid-token reads as pip reads it.
        """
        lines: list[str] = []
        pending: list[str] = []
        for raw in content.removeprefix("\ufeff").splitlines():
            comment = raw.lstrip().startswith("#")
            if raw.endswith("\\") and not comment:
                pending.append(raw.strip("\\"))
                continue
            if pending:
                pending.append(" " + raw if comment else raw)
                lines.append("".join(pending))
                pending = []
            else:
                lines.append(raw)
        if pending:
            lines.append("".join(pending))
        return lines

    def _scan_pip(self, result: ScanResult, entries: list[str]) -> list[RegistryEntryComponent]:
        packages: dict[str, _Package] = {}
        redirects: set[tuple[str, str]] = set()
        # Poetry's sources by name, explicit ones included, as pyproject.toml declares
        # them; None when the table cannot be read.
        self._poetry_sources: dict[str, str | None] | None = {}

        def declare(
            source: str,
            reference: str,
            group: str = "",
            hashes: tuple[str, ...] = (),
            untranslated: str | None = None,
        ) -> None:
            declaration = self._pip_declaration(
                reference, source, result, group, hashes, untranslated
            )
            if declaration is not None:
                packages.setdefault(declaration.name, _Package()).add(declaration)

        self._scan_requirements(result, entries, declare, redirects)
        for text, group, untranslated in self._pyproject_declarations(result, redirects):
            # Compare the text the requirement is parsed from, without a trailing comment.
            declare(
                "pyproject.toml", text.strip().split(" #", 1)[0].strip(), group, (), untranslated
            )
        uv_settings = None
        if any(
            not all(d.requirement is not None and d.requirement.url for d in p.declarations)
            for p in packages.values()
        ):
            # uv applies the overrides and constraints of uv.toml to every project and
            # `uv pip` resolution; `sources` is not valid there.
            uv_settings = self._toml("uv.toml", result)
            if uv_settings is not None:
                found: list[tuple[str, str, str | None]] = []
                failures: dict[str, None] = {}
                gaps: dict[str, None] = {}
                self._uv_overrides(
                    uv_settings,
                    "uv.toml: invalid uv settings",
                    "uv.toml: uv override or constraint not followed",
                    found,
                    failures,
                    gaps,
                )
                result.scan_failures.extend(failures)
                result.surfaces_excluded.extend(gaps)
                for text, group, untranslated in found:
                    declare("uv.toml", text, group, (), untranslated)
        if "Pipfile" in entries:
            # pipenv installs what Pipfile declares; it is not read.
            result.surfaces_excluded.append("Pipfile: dependencies not read")
        components = [self._pypi_component(package) for package in packages.values()]
        if components:
            # A lockfile records a registry resolution, so it does not stand for a
            # package that a URL, VCS or path declaration installs, in any file.
            from_urls = {
                name
                for name, package in packages.items()
                if any(
                    d.requirement is not None and d.requirement.url for d in package.declarations
                )
            }
            self._resolve_python_lockfiles(components, result, from_urls, packages)
            indexed = [
                component
                for component, package in zip(components, packages.values(), strict=True)
                if not all(
                    d.requirement is not None and d.requirement.url for d in package.declarations
                )
            ]
            if indexed:
                self._redirect_python(result, indexed, redirects, uv_settings)
        return components

    def _redirect_python(
        self,
        result: ScanResult,
        components: list[RegistryEntryComponent],
        redirects: set[tuple[str, str]],
        uv: dict[str, Any] | None,
    ) -> None:
        """Record on every package installed from an index the settings that redirect it.

        pip applies index options and its configuration to every package of a run, and
        uv, Poetry and PDM their sources to every package they resolve; which files one
        install reads is not known, so each such setting may apply to each package.
        """
        for name in _PIP_CONFIG_FILES:
            text = self._read(name, result)
            if text is None:
                continue
            settings = _pip_config(text)
            if settings is None:
                result.surfaces_excluded.append(
                    f"{name}: not read as pip reads it; index settings not resolved"
                )
                continue
            for key, value in settings:
                option = f"--{key}"
                if option in self._PACKAGE_OPTIONS:
                    # pip install adds or constrains packages from it as from the
                    # option on its command line, so no exact pin names what installs.
                    gap = f"{name}:{key}: {self._PACKAGE_OPTIONS[option]}"
                    if gap not in result.surfaces_excluded:
                        result.surfaces_excluded.append(gap)
                    for component in components:
                        component.package_url = None
                else:
                    redirects.add((f"{name}:{key}", value))
        if uv is not None:
            redirects.update(self._uv_redirects(uv, "uv.toml:"))
        found = sorted(
            (label, value) for label, value in redirects if not _DEFAULT_PYPI_INDEX.fullmatch(value)
        )
        if not found:
            return
        sources = _SourceLabels().entries(found)
        named = _named(found)
        for component in components:
            if "package_resolution" not in component.claims:
                # PyPI was assumed, not recorded; a lockfile record names its index.
                component.registry_uri = None
            _redirect(
                component,
                list(sources),
                f"PyPI package '{component.name}' may resolve from an index or location that "
                f"the project configures ({named}); its name and version do not establish "
                "identity.",
            )

    def _resolve_python_lockfiles(
        self,
        components: list[RegistryEntryComponent],
        result: ScanResult,
        from_urls: set[str],
        packages_declared: dict[str, _Package],
    ) -> None:
        files = self._confined()
        found_locks: list[tuple[str, str, bytes | None]] = []
        for lock_name, method in (("uv.lock", "uv-lockfile"), ("poetry.lock", "poetry-lockfile")):
            before = files.failures_recorded, files.exclusions_recorded
            if self._withheld(lock_name, result):
                # Present but not read: the other lockfile does not stand in for it.
                found_locks.append((lock_name, method, None))
                continue
            raw = files.read_bytes(lock_name, missing_ok=True)
            if raw is not None:
                result.surfaces_scanned.append(lock_name)
                found_locks.append((lock_name, method, raw))
            elif (files.failures_recorded, files.exclusions_recorded) != before:
                found_locks.append((lock_name, method, None))
        if not found_locks:
            return
        if len(found_locks) > 1:
            for comp in components:
                comp.package_url = comp.registry_uri = None
            result.surfaces_excluded.append(
                "multiple Python lockfiles present (uv.lock and poetry.lock); resolution is ambiguous"
            )
            return
        lock_name, method, lock_bytes = found_locks[0]
        if lock_bytes is None:
            # The lockfile that installs is not read, so the version an exact pin names
            # is in doubt; the gap or failure says why.
            for comp in components:
                comp.package_url = None
            return
        try:
            text = lock_bytes.decode("utf-8")
            lock_doc = load_toml(text)
            packages = lock_doc.get("package", [])
            if (
                not isinstance(packages, list)
                or len(packages) > 10_000
                or not all(isinstance(item, dict) for item in packages)
            ):
                raise ValueError("unsupported Python lockfile structure")
        except (ValueError, UnicodeError, RecursionError, MemoryError):
            # TOMLDecodeError is a ValueError, as is a decimal integer past CPython's
            # limit on digits it converts.
            result.scan_failures.append(f"{lock_name}: invalid or unsupported lockfile")
            for comp in components:
                comp.package_url = None
            return
        lock_digest = hash_bytes(lock_bytes)
        indexed: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        for index, entry in enumerate(packages):
            raw_name = entry.get("name")
            if not isinstance(raw_name, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", raw_name
            ):
                result.scan_failures.append(f"{lock_name}: invalid package entry name")
                continue
            indexed.setdefault(str(canonicalize_name(raw_name)), []).append((index, entry))
        for comp in components:
            matches = indexed.get(comp.name)
            if not matches or comp.name in from_urls:
                continue
            if comp.version and comp.version.startswith("@ "):
                continue
            package = packages_declared.get(comp.name)
            declarations = package.declarations if package is not None else []
            # A record is still checked for a package declared only under markers, or
            # through a source, override or conflict the lockfile does not stand for:
            # unresolved packages receive neither a package URL nor a registry origin,
            # while marker-conditional ones record the resolved index origin without
            # claiming a package URL or version binding.
            # Rendering can redact the complete declared version, including its marker.
            conditional = (
                bool(package.representative.marker)
                if package is not None and declarations
                else bool(comp.version and ";" in comp.version)
            )
            unresolved = (package is not None and package.conflict) or any(
                d.untranslated is not None or d.redacted for d in declarations
            )
            if len(matches) > 1:
                comp.package_url = comp.registry_uri = None
                result.surfaces_excluded.append(
                    f"{lock_name}: multiple package resolutions for {comp.name} are ambiguous"
                )
                continue
            index, record = matches[0]
            source = record.get("source")
            if source is not None and not isinstance(source, dict):
                comp.package_url = comp.registry_uri = None
                result.scan_failures.append(f"{lock_name}: invalid selected package source")
                continue
            if isinstance(source, dict):
                non_registry_keys = {"editable", "directory", "path", "git", "virtual", "url"}
                if (method == "uv-lockfile" and non_registry_keys.intersection(source)) or (
                    method == "poetry-lockfile"
                    and source.get("type") in {"directory", "file", "git", "url"}
                ):
                    comp.package_url = comp.registry_uri = None
                    result.surfaces_excluded.append(
                        f"{lock_name}: non-registry package source for {comp.name} is unverified"
                    )
                    continue
            resolved_version = record.get("version")
            sensitive_version = isinstance(resolved_version, str) and holds_token_shape(
                resolved_version, require_sk_boundary=True
            )
            if sensitive_version:
                comp.package_url = comp.registry_uri = None
                comp.risks.append(
                    _identifier_risk(f"PyPI package '{comp.name}'", "lock record version")
                )
                unresolved = True
            pinned = (
                extract_version_pin(f"{comp.name}=={resolved_version}", ecosystem="python")
                if isinstance(resolved_version, str) and len(resolved_version) <= _LONGEST_VERSION
                else None
            )
            if pinned is None or pinned != resolved_version:
                comp.package_url = comp.registry_uri = None
                result.scan_failures.append(f"{lock_name}: selected package lacks an exact version")
                continue
            parsed = _parsed(resolved_version)
            # uv and Poetry lock no build requirements; they are resolved at build time.
            disagree = [
                d.source
                for d in declarations
                if d.requirement is not None
                and d.group != "build-system"
                and not _satisfies(d.requirement, resolved_version, parsed)
            ]
            if disagree:
                # The lockfile is stale, or the file that declares it is not installed
                # from it: which version is installed is unknown.
                comp.package_url = None
                result.scan_failures.append(
                    f"{lock_name}: selected package version disagrees with "
                    + ", ".join(dict.fromkeys(disagree))
                )
                continue
            registry_origin = _PYPI_ORIGIN
            if isinstance(source, dict):
                # A source the collector cannot read as one index origin is not PyPI:
                # a directory of wheels, an upper-case scheme or an authority that URL
                # parsers split differently names somewhere else.
                index_origin = _index_origin(
                    source.get("registry") if method == "uv-lockfile" else source.get("url")
                )
                if index_origin is None:
                    comp.package_url = comp.registry_uri = None
                    result.surfaces_excluded.append(
                        f"{lock_name}: package index of the selected record is not a plain "
                        "http(s) URL; its origin is unverified"
                    )
                    continue
                if method == "poetry-lockfile" and not self._poetry_reference_holds(source):
                    # Poetry downloads from the source the reference names, not from the
                    # record's url, so a record whose url and named source disagree, or
                    # whose source pyproject.toml does not declare, has no known origin.
                    comp.package_url = comp.registry_uri = None
                    result.surfaces_excluded.append(
                        f"{lock_name}: package source reference is unverified"
                    )
                    continue
                registry_origin = (
                    index_origin.removesuffix(":443")
                    if index_origin.startswith("https://")
                    else index_origin
                )
            package_url = (
                None
                if unresolved
                else f"pkg:pypi/{quote(comp.name, safe='')}@{quote(resolved_version, safe='')}"
            )
            artifact_mismatch = False
            if method == "uv-lockfile":
                sdist = record.get("sdist")
                wheels = record.get("wheels")
                if (sdist is not None and not isinstance(sdist, dict)) or (
                    wheels is not None
                    and (
                        not isinstance(wheels, list)
                        or not all(isinstance(item, dict) for item in wheels)
                    )
                ):
                    comp.package_url = comp.registry_uri = None
                    result.scan_failures.append(
                        f"{lock_name}: invalid package artifact entry for {comp.name}"
                    )
                    continue
                artifact_entries = [
                    *([] if sdist is None else [sdist]),
                    *([] if wheels is None else wheels),
                ]
                raw_artifact_urls = [entry["url"] for entry in artifact_entries if "url" in entry]
                parsed_artifact_origins = [_index_origin(u) for u in raw_artifact_urls]
                if any(ao is None for ao in parsed_artifact_origins):
                    comp.package_url = comp.registry_uri = None
                    result.surfaces_excluded.append(
                        f"{lock_name}: package artifact URL of the selected record is not a plain "
                        "http(s) URL; its origin is unverified"
                    )
                    continue
                artifact_origins = [
                    ao.removesuffix(":443") if ao.startswith("https://") else ao
                    for ao in parsed_artifact_origins
                    if ao is not None
                ]
                disallowed_artifacts = sorted(
                    {
                        ao
                        for ao in artifact_origins
                        if (registry_origin in _PYPI_ORIGINS and ao not in _PYPI_ORIGINS)
                        or (not registry_origin.startswith("http://") and ao.startswith("http://"))
                    }
                )
                if disallowed_artifacts:
                    artifact_mismatch = True
                    package_url = None
                    cleartext_art = any(ao.startswith("http://") for ao in disallowed_artifacts)
                    comp.risks.append(
                        _risk(
                            RiskSeverity.HIGH if cleartext_art else RiskSeverity.MEDIUM,
                            "registry_origin",
                            f"PyPI package '{redact_text(comp.name)}' declares index "
                            f"{registry_origin} but downloads artifacts from "
                            f"{', '.join(disallowed_artifacts)}.",
                            "Confirm that every sdist/wheel download origin in uv.lock matches a "
                            "trusted HTTPS package host.",
                        )
                    )
            if registry_origin not in _PYPI_ORIGINS:
                # As for npm: the package URL names the index it was resolved from.
                if package_url is not None:
                    package_url += f"?repository_url={registry_origin}"
                cleartext = registry_origin.startswith("http://")
                comp.risks.append(
                    _risk(
                        RiskSeverity.HIGH if cleartext else RiskSeverity.LOW,
                        "registry_origin",
                        f"PyPI package '{redact_text(comp.name)}' is resolved from {registry_origin}, "
                        + (
                            "over cleartext HTTP, where a download can be replaced in transit."
                            if cleartext
                            else "not the default Python package index."
                        ),
                        "Use an HTTPS index and confirm that it is intended and trusted for "
                        "this package."
                        if cleartext
                        else "Confirm that this index is intended and trusted for this package.",
                    )
                )
            comp.registry_uri = None if (unresolved or artifact_mismatch) else registry_origin
            if conditional:
                # The declared version keeps its markers; no exact identity is claimed.
                continue
            locator = f"{lock_name}#/package/{index}"
            comp.version = REDACTED if sensitive_version else resolved_version
            comp.package_url = package_url
            comp.source_path = lock_name
            comp.assurance_level = AssuranceLevel.DECLARED
            comp.properties.update(
                {
                    "collection_mode": "lockfile-resolution-claim",
                    "lockfile_sha256": lock_digest,
                    "lockfile_record": locator,
                    "artifact_verified": False,
                }
            )
            comp.claims["package_resolution"] = ClaimEvidence(
                assurance=AssuranceLevel.DECLARED,
                method=method,
                scope="dependency-resolution",
                collector="registry",
                locator=locator,
            )

    def _scan_requirements(
        self,
        result: ScanResult,
        entries: list[str],
        declare: Callable[[str, str, str, tuple[str, ...]], None],
        redirects: set[tuple[str, str]],
    ) -> None:
        filenames = self._requirement_files(entries)
        names = {n.casefold() for n in filenames}
        folded = {self._fold(n) for n in entries}
        noted: set[str] = set()
        unprintable = False
        remaining = _REQUIREMENTS_BUDGET
        remaining_lines = _REQUIREMENTS_LINES
        for filename in filenames:
            if (
                UNSAFE_TEXT.search(filename)
                or "\t" in filename
                or any("\ud800" <= c <= "\udfff" for c in filename)
            ):
                # Undecodable bytes (lone surrogates) cannot be carried in the inventory
                # or its exports, and controls or format characters disguise output, so
                # the file is a gap, not data. A fixed list, unlike str.isprintable(),
                # gives the same answer on every supported Python.
                if not unprintable:
                    result.scan_failures.append(
                        "requirements file with an unprintable name: not read"
                    )
                    unprintable = True
                continue
            content = self._read(filename, result)
            if content is None:
                continue
            remaining -= len(content)
            if remaining < 0:
                # Every root requirements file is read, so their parsing time must be
                # bounded together; what does not fit is a coverage gap.
                result.scan_failures.append(
                    "requirements files exceed the combined size limit: the rest were not read"
                )
                break
            if self._declares_other_encoding(content):
                # pip would decode other text than the UTF-8 read here.
                result.scan_failures.append(
                    f"{filename}: declared encoding other than UTF-8: not read"
                )
                continue
            lines = self._requirement_lines(content)
            remaining_lines -= len(lines)
            if remaining_lines < 0:
                result.scan_failures.append(
                    "requirements files exceed the combined line limit: the rest were not read"
                )
                break
            for line in lines:
                text = self._COMMENT.sub("", line).strip()
                if not text:
                    continue
                gaps: list[str] = []
                if text.startswith("-"):
                    # Includes, constraints and editable installs are not followed. One
                    # that reaches beyond what is read here is a coverage gap. Index
                    # options add no package, but pip applies them to every package
                    # of the run that reads them.
                    options, gaps = self._options(text)
                    gaps += self._option_gaps(options, names, folded)
                    redirects.update(
                        (f"{filename}:{option}", value)
                        for option, value in options
                        if option in _PIP_INDEX_OPTIONS
                    )
                else:
                    # Per-requirement options such as --hash follow the requirement
                    # itself. pip splits them off on spaces only, so a tab or another
                    # space character stays inside the requirement.
                    tokens = text.split(" ")
                    split = next(
                        (i for i, t in enumerate(tokens) if t.startswith("-")), len(tokens)
                    )
                    # pip reads the words before them as written, with the empty
                    # words two spaces leave.
                    args = " ".join(tokens[:split])
                    reference = " ".join(t for t in tokens[:split] if t)
                    option_text = " ".join(tokens[split:])
                    options, _ = self._options(option_text)
                    if self._unsplittable(option_text):
                        # Too long to split: an -e among them would go unseen.
                        gaps = ["option line not parsed"]
                    # pip accepts only these; other text after --hash is not recorded.
                    hashes = tuple(
                        sorted(
                            {v for o, v in options if o == "--hash" and _HASH_VALUE.fullmatch(v)}
                        )
                    )
                    if self._ENV_NAME.match(reference):
                        # The variable can make the line any package, or an option.
                        gaps = ["environment variable not resolved"]
                    else:
                        skip_declare = False
                        if any(o == "--editable" for o, _ in options) and not (
                            self._editable_covered(reference, folded)
                        ):
                            # pip installs the requirement itself as editable.
                            gaps = ["editable install not followed"]
                        elif self._unnamed(args, folded):
                            # The gap never names the reference, which can carry a
                            # credential.
                            gaps = ["URL, VCS or path requirement not followed"]
                            skip_declare = self._bare_archive(args)
                        if not skip_declare:
                            declare(filename, reference, "", hashes)
                for gap in gaps:
                    message = f"{filename}: {gap}"
                    if message not in noted:
                        noted.add(message)
                        result.surfaces_excluded.append(message)

    def _toml(self, name: str, result: ScanResult) -> dict[str, Any] | None:
        """A root TOML file read within the bounds that keep tomllib's work linear."""
        content = self._read(name, result)
        if content is None:
            return None
        if len(content) > _PYPROJECT_BUDGET:
            result.scan_failures.append(f"{name}: exceeds the size limit: not read")
            return None
        try:
            return load_toml(content)
        except TOMLBoundsError as exc:
            result.scan_failures.append(f"{name}: {exc}: not read")
            return None
        except (ValueError, RecursionError, MemoryError):
            # TOMLDecodeError is a ValueError; tomllib raises a plain one for a decimal
            # integer past CPython's limit on digits it converts.
            result.scan_failures.append(f"{name}: invalid TOML")
            return None

    def _pyproject_declarations(
        self, result: ScanResult, redirects: set[tuple[str, str]]
    ) -> list[tuple[str, str, str | None]]:
        """Each declaration with its group ("" for none) and, when it is not translated,
        why. The index settings of uv, Poetry and PDM go to ``redirects``."""
        data = self._toml("pyproject.toml", result)
        if data is None:
            return []
        declarations: list[tuple[str, str, str | None]] = []
        project = data.get("project", {})
        if not isinstance(project, dict):
            result.scan_failures.append("pyproject.toml: invalid project table")
            return []
        failures: dict[str, None] = {}
        gaps: dict[str, None] = {}

        def strings(value: Any, group: str, failure: str) -> None:
            if isinstance(value, list) and all(isinstance(item, str) for item in value):
                declarations.extend((item, group, None) for item in value)
            else:
                failures[failure] = None

        strings(project.get("dependencies", []), "", "pyproject.toml: invalid project dependencies")
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for extra, values in optional.items():
                strings(values, str(extra), "pyproject.toml: invalid optional dependencies")
        else:
            failures["pyproject.toml: invalid optional dependencies"] = None
        build = data.get("build-system", {})
        strings(
            build.get("requires", []) if isinstance(build, dict) else None,
            "build-system",
            "pyproject.toml: invalid build-system requires",
        )
        self._dependency_groups(data.get("dependency-groups", {}), declarations, failures)
        tool = data.get("tool", {})
        tool = tool if isinstance(tool, dict) else {}
        self._uv_declarations(tool.get("uv", {}), declarations, failures, gaps, strings)
        self._pdm_declarations(tool.get("pdm", {}), declarations, failures, gaps, strings)
        self._poetry_declarations(tool.get("poetry", {}), declarations, failures, gaps)
        redirects.update(self._uv_redirects(tool.get("uv"), "pyproject.toml:tool.uv."))
        self._poetry_sources = self._named_sources(tool.get("poetry"))
        for name, shown in (("poetry", "Poetry"), ("pdm", "PDM")):
            found = self._source_redirects(tool.get(name), name)
            if found is None:
                failures[f"pyproject.toml: invalid {shown} source"] = None
            else:
                redirects.update(found)
        result.scan_failures.extend(failures)
        result.surfaces_excluded.extend(gaps)
        return declarations

    @staticmethod
    def _dependency_groups(
        groups: Any, declarations: list[tuple[str, str, str | None]], failures: dict[str, None]
    ) -> None:
        """PEP 735 groups. An included group is read as a group of its own; group
        names are compared in their normal form, as PEP 735 requires."""
        failure = "pyproject.toml: invalid dependency groups"
        if not isinstance(groups, dict):
            failures[failure] = None
            return
        names = {canonicalize_name(str(name)) for name in groups}
        for name, values in groups.items():
            if not isinstance(values, list):
                failures[failure] = None
                continue
            for value in values:
                if isinstance(value, str):
                    declarations.append((value, f"group:{canonicalize_name(str(name))}", None))
                elif not (
                    isinstance(value, dict)
                    and set(value) == {"include-group"}
                    and isinstance(value["include-group"], str)
                    and canonicalize_name(value["include-group"]) in names
                ):
                    failures[failure] = None

    _UV_GAPS = {
        "source": "pyproject.toml: uv source not translated",
        "override": "pyproject.toml: uv override or constraint not followed",
        "workspace": "pyproject.toml: uv workspace members not followed",
    }

    @classmethod
    def _uv_declarations(
        cls,
        uv: Any,
        declarations: list[tuple[str, str, str | None]],
        failures: dict[str, None],
        gaps: dict[str, None],
        strings: Callable[[Any, str, str], None],
    ) -> None:
        """uv's development dependencies, and the sources, overrides and constraints
        that change what an inventoried package resolves to."""
        failure = "pyproject.toml: invalid uv table"
        if not isinstance(uv, dict):
            failures[failure] = None
            return
        strings(uv.get("dev-dependencies", []), "uv:dev", failure)
        workspace = uv.get("workspace", {})
        if not isinstance(workspace, dict):
            failures[failure] = None
        elif workspace.get("members"):
            # uv sync installs what each member's pyproject.toml declares.
            gaps[cls._UV_GAPS["workspace"]] = None
        sources = uv.get("sources", {})
        if not isinstance(sources, dict):
            failures[failure] = None
            sources = {}
        for name in sources:
            if cls._is_ai_package(str(name)):
                # A git, URL, path, workspace or index source replaces the package.
                declarations.append((str(name), "", "source"))
                gaps[cls._UV_GAPS["source"]] = None
        cls._uv_overrides(uv, failure, cls._UV_GAPS["override"], declarations, failures, gaps)

    @classmethod
    def _uv_overrides(
        cls,
        uv: dict[str, Any],
        failure: str,
        gap: str,
        declarations: list[tuple[str, str, str | None]],
        failures: dict[str, None],
        gaps: dict[str, None],
    ) -> None:
        """The overrides and constraints of a uv table or of ``uv.toml``."""
        for key in ("override-dependencies", "constraint-dependencies"):
            values = uv.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                failures[failure] = None
                continue
            for value in values:
                # uv reads a requirement past leading whitespace.
                name = cls._PIP_NAME.match(value.strip())
                if name is not None and cls._is_ai_package(name.group()):
                    gaps[gap] = None
                    if key == "override-dependencies":
                        declarations.append((name.group(), "", "override"))

    @staticmethod
    def _uv_redirects(settings: Any, label: str) -> list[tuple[str, str]]:
        """The index settings of a uv table and of its pip table: every index but an
        explicit one, which serves only the packages a source names and is a gap there."""
        if not isinstance(settings, dict):
            return []
        found: list[tuple[str, str]] = []
        for table, prefix in ((settings, label), (settings.get("pip"), label + "pip.")):
            if not isinstance(table, dict):
                continue
            chosen = {
                key: table[key]
                for key in ("index-url", "extra-index-url", "find-links")
                if key in table
            }
            if "index" in table:
                indexes = table["index"] if isinstance(table["index"], list) else [table["index"]]
                chosen["index"] = [
                    index
                    for index in indexes
                    if not (isinstance(index, dict) and index.get("explicit") is True)
                ]
            found += [(prefix + key, value) for key, value in _uv_settings(chosen).settings]
        return found

    def _poetry_reference_holds(self, source: dict[str, Any]) -> bool:
        """Whether a poetry.lock record's ``reference`` names a source pyproject.toml
        declares at the same index origin as the record's ``url``; a record without a
        reference is read by its url alone, as before Poetry 1.2 wrote one."""
        reference = source.get("reference")
        if reference is None:
            return True
        sources = getattr(self, "_poetry_sources", None)
        if not isinstance(reference, str) or not sources or reference.lower() not in sources:
            return False
        declared = sources[reference.lower()]
        declared_origin = _PYPI_ORIGIN if declared is None else _index_origin(declared)
        recorded = _index_origin(source.get("url"))
        return declared_origin is not None and _same_index(declared_origin, recorded)

    @staticmethod
    def _named_sources(table: Any) -> dict[str, str | None] | None:
        """Each Poetry source's URL by its name in lower case, explicit sources included;
        ``pypi`` is Poetry's own index. None when the source list cannot be read."""
        sources = table.get("source", []) if isinstance(table, dict) else []
        if not isinstance(sources, list) or not all(isinstance(item, dict) for item in sources):
            return None
        named: dict[str, str | None] = {"pypi": None}
        for source in sources:
            name, url = source.get("name"), source.get("url")
            if not isinstance(name, str) or not (url is None or isinstance(url, str)):
                return None
            named[name.lower()] = url
        return named

    @staticmethod
    def _source_redirects(table: Any, tool: str) -> list[tuple[str, str]] | None:
        """The package sources of a Poetry or PDM table that may serve any package.

        A Poetry source with ``priority = "explicit"`` serves only the dependencies that
        name it, which are gaps already. A source without a URL other than Poetry's
        ``PyPI`` cannot be read, and neither can a source list that is not a list of
        tables: None.
        """
        sources = table.get("source", []) if isinstance(table, dict) else []
        if not isinstance(sources, list) or not all(isinstance(item, dict) for item in sources):
            return None
        found: list[tuple[str, str]] = []
        for source in sources:
            if tool == "poetry" and source.get("priority") == "explicit":
                continue
            url = source.get("url")
            if isinstance(url, str):
                found.append((f"pyproject.toml:tool.{tool}.source", url))
            elif not (
                url is None and tool == "poetry" and str(source.get("name")).lower() == "pypi"
            ):
                return None
        return found

    @classmethod
    def _pdm_declarations(
        cls,
        pdm: Any,
        declarations: list[tuple[str, str, str | None]],
        failures: dict[str, None],
        gaps: dict[str, None],
        strings: Callable[[Any, str, str], None],
    ) -> None:
        failure = "pyproject.toml: invalid PDM table"
        if not isinstance(pdm, dict):
            failures[failure] = None
            return
        groups = pdm.get("dev-dependencies", {})
        if not isinstance(groups, dict):
            failures[failure] = None
            groups = {}
        for group, values in groups.items():
            strings(values, f"pdm:{group}", failure)
        resolution = pdm.get("resolution", {})
        overrides = resolution.get("overrides", {}) if isinstance(resolution, dict) else None
        if not isinstance(overrides, dict):
            failures[failure] = None
            return
        for name in overrides:
            if cls._is_ai_package(str(name)):
                declarations.append((str(name), "", "override"))
                gaps["pyproject.toml: PDM override not followed"] = None

    def _poetry_declarations(
        self,
        poetry: Any,
        declarations: list[tuple[str, str, str | None]],
        failures: dict[str, None],
        gaps: dict[str, None],
    ) -> None:
        if not isinstance(poetry, dict):
            failures[self._POETRY_PROBLEMS["table"]] = None
            return
        # The legacy dev-dependencies table is Poetry's dev group. Group labels keep
        # main and group declarations from being compared with each other.
        tables: list[tuple[str, Any]] = [
            ("", poetry.get("dependencies", {})),
            ("poetry:group:dev", poetry.get("dev-dependencies", {})),
        ]
        groups = poetry.get("group", {})
        if not isinstance(groups, dict):
            failures[self._POETRY_PROBLEMS["table"]] = None
            groups = {}
        for group_name, group in groups.items():
            dependencies = group.get("dependencies", {}) if isinstance(group, dict) else None
            tables.append((f"poetry:group:{group_name}", dependencies))
        for group_label, table in tables:
            if not isinstance(table, dict):
                failures[self._POETRY_PROBLEMS["table"]] = None
                continue
            for name, value in table.items():
                if not self._is_ai_package(name):
                    continue
                if not _PEP508_NAME.fullmatch(name):
                    failures[self._POETRY_PROBLEMS["invalid"]] = None
                    continue
                for entry in value if isinstance(value, list) and value else [value]:
                    text, problem = self._poetry_requirement(name, entry)
                    if problem is None:
                        declarations.append((text, group_label, None))
                        continue
                    declarations.append((name, group_label, problem))
                    record = failures if problem == "invalid" else gaps
                    record[self._POETRY_PROBLEMS[problem]] = None

    _POETRY_PROBLEMS = {
        "table": "pyproject.toml: invalid Poetry dependencies",
        "invalid": "pyproject.toml: invalid or unsupported Poetry dependency",
        "source": "pyproject.toml: Poetry git, path or URL dependency not translated",
        "index": "pyproject.toml: Poetry dependency from a source other than PyPI not translated",
        "condition": "pyproject.toml: Poetry dependency condition not translated",
    }

    @staticmethod
    def _poetry_requirement(name: str, entry: Any) -> tuple[str, str | None]:
        """One Poetry declaration as PEP 508 text, or the bare name and why it is not.

        A version, extras, markers and platform are translated. A git, path or URL
        source, a package source other than PyPI and a python restriction are left
        out, and so is a constraint that does not translate, such as a || union.
        """
        if isinstance(entry, str):
            entry = {"version": entry}
        if not isinstance(entry, dict):
            return name, "invalid"
        if any(key in entry for key in ("git", "path", "url", "file")):
            return name, "source"
        source = entry.get("source", "pypi")
        if not isinstance(source, str):
            return name, "invalid"
        if source.lower() != "pypi":
            # Not a PyPI package, though it may share a name with one.
            return name, "index"
        version = entry.get("version", "*")
        extras = entry.get("extras", [])
        markers = entry.get("markers")
        platform = entry.get("platform")
        if (
            not isinstance(version, str)
            or not isinstance(extras, list)
            or not all(isinstance(e, str) and _PEP508_NAME.fullmatch(e) for e in extras)
            or not (markers is None or (isinstance(markers, str) and _valid_marker(markers)))
            or not (
                platform is None or (isinstance(platform, str) and _PLATFORM.fullmatch(platform))
            )
        ):
            return name, "invalid"
        if "python" in entry:
            return name, "condition"
        specifier = _poetry_specifier(version)
        if specifier is None:
            return name, "condition" if _POETRY_CONSTRAINT.fullmatch(version) else "invalid"
        conditions = [markers] if markers else []
        if platform:
            conditions.append(f'sys_platform == "{platform}"')
        text = name + (f"[{','.join(extras)}]" if extras else "") + specifier
        if len(conditions) == 1:
            text += f" ; {conditions[0]}"
        elif conditions:
            text += " ; " + " and ".join(f"({c})" for c in conditions)
        return text, None

    # Containerfile is the name Podman and Buildah read by default.
    _DOCKERFILES = ("Dockerfile", "Dockerfile.agent", "Containerfile")
    # Compose reads the first of the four base names that exists and merges the
    # first override file; every one of them is read, so none can hide an image.
    _COMPOSE_FILES = (
        "compose.yaml",
        "compose.yml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.override.yml",
        "compose.override.yaml",
        "docker-compose.override.yml",
        "docker-compose.override.yaml",
    )

    def _scan_docker(self, result: ScanResult) -> list[RegistryEntryComponent]:
        environment = (
            None
            if self._withheld(".env", result)
            else self._confined().read_bytes(".env", missing_ok=True)
        )
        if environment is not None:
            # Read as bytes, so that no encoding fails the collector; nothing in it
            # is recorded.
            result.surfaces_scanned.append(".env")
            if self._names_compose_file(environment):
                # Compose reads the files it names instead of the default ones.
                result.surfaces_excluded.append(".env: COMPOSE_FILE not followed")
        # One component per image, with every file that names it.
        found: dict[str, list[str]] = {}
        unresolved: set[str] = set()
        models: set[str] = set()

        def collect(image: str, filename: str, gaps: list[str]) -> None:
            files = found.setdefault(image, [])
            if filename not in files:
                files.append(filename)
            if gaps:
                unresolved.add(image)

        for filename in self._DOCKERFILES:
            content = self._read(filename, result)
            if content is None:
                continue
            images, gaps = self._dockerfile_images(content)
            result.surfaces_excluded.extend(f"{filename}: {gap}" for gap in gaps)
            for image in images:
                collect(image, filename, self._image_gaps(image))
        for filename in self._COMPOSE_FILES:
            content = self._read(filename, result)
            if content is None:
                continue
            read = self._compose_images(content)
            if read is None:
                result.scan_failures.append(f"{filename}: YAML mapping parse failed or unsupported")
                continue
            images, model_references, gaps = read
            result.surfaces_excluded.extend(f"{filename}: {gap}" for gap in gaps)
            for image in images:
                collect(image, filename, self._image_gaps(image))
            for reference in model_references:
                # A model Docker Model Runner pulls is AI-related whatever its name.
                models.add(reference)
                collect(reference, filename, self._image_gaps(reference))
        components: list[RegistryEntryComponent] = []
        noted: set[str] = set()
        for raw, files in found.items():
            if not (is_ai_image(raw) or raw in models):
                continue
            component = self._image_component(raw, files, raw in unresolved, raw in models)
            if component is None:
                for filename in files:
                    message = f"{filename}: image reference not parsed"
                    if message not in noted:
                        noted.add(message)
                        result.surfaces_excluded.append(message)
                continue
            components.append(component)
        return components

    @staticmethod
    def _names_compose_file(environment: bytes) -> bool:
        """Whether a .env mentions COMPOSE_FILE, in any letter case.

        Compose's dotenv parser reads statements, not lines: it skips any Unicode
        space before a name and before "=", and a statement can start right after a
        closing quote. No line pattern finds every setting, so any mention counts; one
        in a comment or a value costs only a false gap.
        """
        return "COMPOSE_FILE" in environment.decode("utf-8", "replace").upper()

    @staticmethod
    def _image_gaps(image: str) -> list[str]:
        """Why an image as written is not the image pulled; the parsers record the gap."""
        return ["unresolved"] if "$" in image or any(c in image for c in "\"'\\") else []

    @staticmethod
    def _image_component(
        raw: str, files: list[str], unresolved: bool, model: bool = False
    ) -> RegistryEntryComponent | None:
        properties: dict[str, Any] = {
            "collection_mode": "manifest-reference",
            "registry_origin_verified": False,
        }
        if model:
            properties["artifact_type"] = "model"
        if len(files) > 1:
            properties["source_paths"] = sorted(files)
        registry_type: str | None = None
        registry_uri = None
        package_url = None
        redacted = False
        if unresolved:
            # Kept as written, with the gap that says why it is not the image pulled.
            shown, redacted = _identifier(raw)
            name = shown if redacted else redact_text(raw)
            has_digest = "@" in raw and _PULLED_DIGEST.fullmatch(raw.rpartition("@")[2]) is not None
            has_tag = ":" in raw.rsplit("/", 1)[-1] and not raw.endswith(":latest")
        else:
            reference = parse_image_reference(raw)
            if reference is None:
                return None
            # Recorded exactly unless it holds a credential, in its host, repository or
            # tag; two references that redact alike then conflict and fail the merge.
            name, redacted = _identifier(raw)
            has_digest = reference.pinned
            has_tag = reference.tag not in (None, "latest")
            registry_type = "docker-hub" if reference.domain == "docker.io" else "oci"
            if not redacted:
                registry_uri = f"https://{reference.domain}"
                properties["image_repository"] = reference.repository
            if reference.digest is not None and has_digest and not redacted:
                qualifiers = {"repository_url": reference.repository}
                if reference.tag is not None:
                    qualifiers["tag"] = reference.tag
                package_url = PackageURL(
                    type="oci",
                    name=reference.path.rsplit("/", 1)[-1],
                    version=reference.digest,
                    qualifiers=qualifiers,
                ).to_string()
        risks: list[RiskAssessment] = []
        if not has_digest:
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM if has_tag else RiskSeverity.HIGH,
                    "mutable_image_tag" if has_tag else "version_pinning",
                    f"Docker image '{name}' lacks an immutable digest pin.",
                    "Pin to a SHA256 artifact digest and verify its provenance.",
                )
            )
        if redacted:
            risks.append(_identifier_risk(f"Docker image '{name}'", "reference"))
        return RegistryEntryComponent(
            bom_ref=f"registry:docker/{reference_text(name)}",
            name=name,
            package_url=package_url,
            registry_type=registry_type,
            registry_uri=registry_uri,
            source_path=files[0],
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties=properties,
        )

    # The pre-scan bounds YAML's work as Scanner._read_mapping does; the walk below
    # bounds what merge keys add.
    _COMPOSE_TOKENS = 20_000
    _COMPOSE_STEPS = 100_000

    @classmethod
    def _compose_images(cls, text: str) -> tuple[list[str], list[str], list[str]] | None:
        """Service images and top-level models in a Compose file, and what was not followed.

        The YAML is composed into nodes, never constructed: an alias is the node it
        names, not a copy, and values keep the text Compose reads. Merge keys are
        followed as YAML defines them, once per mapping and within a step budget.
        None when the file is not a YAML mapping read this way.
        """
        try:
            import yaml
        except ImportError:
            return None
        try:
            loader = cls._bounded_yaml_loader()
            for index, _ in enumerate(yaml.scan(text, Loader=loader)):
                if index >= cls._COMPOSE_TOKENS:
                    return None
            root = yaml.compose(text, Loader=loader)
            if root is None:
                return [], [], []
            return _ComposeWalk(cls._COMPOSE_STEPS).images(root)
        except (yaml.YAMLError, RecursionError, ValueError):
            return None

    # BuildKit's word separators; a no-break space is part of a word.
    _DOCKER_WORD = re.compile(r"[^\t\v\f\r ]+")
    # Go's unicode.IsSpace, which BuildKit trims lines with and splits shell words on;
    # str.strip() would also take \x1c-\x1f.
    _GO_SPACE = (
        "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
        "\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
    )
    # Go's \s, which has no \v.
    _GO_REGEX_SPACE = "\t\n\f\r "
    _DIRECTIVE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]*")
    # The substitutions BuildKit's lexer keeps as written when no variable is set.
    # The others can move word boundaries or fail the line.
    _DOLLAR = r"\$(?:\{(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[-@*#?$!])\}|(?!\{))"
    _SHELL_TOKEN = re.compile(
        f"(?P<space>[{_GO_SPACE}]+)"
        f"|(?P<plain>[^{_GO_SPACE}'\"$<\\\\]+|<(?!<))"
        r"|(?P<heredoc><<[\t\r ]*)"
        r"|(?P<single>'[^']*')"
        rf'|(?P<double>"(?:[^"\\$]|\\[\s\S]|{_DOLLAR})*")'
        rf"|(?P<dollar>{_DOLLAR})"
        r"|(?P<escape>\\[\s\S]?)"
    )
    _QUOTED_ESCAPE = re.compile(r'\\([\\"$])')

    @classmethod
    def _directive(cls, line: str) -> tuple[str, str] | None:
        """A parser directive as BuildKit's ^#\\s*([a-zA-Z][a-zA-Z0-9]*)\\s*=\\s*(.+?)\\s*$
        matches it, in linear time.

        The value is the rest of the line without the white space around it; when
        the rest is only white space, the lazy group still takes its last character.
        """
        if not line.startswith("#"):
            return None
        rest = line[1:].lstrip(cls._GO_REGEX_SPACE)
        name = cls._DIRECTIVE_NAME.match(rest)
        if name is None:
            return None
        rest = rest[name.end() :].lstrip(cls._GO_REGEX_SPACE)
        if not rest.startswith("="):
            return None
        rest = rest[1:]
        value = rest.strip(cls._GO_REGEX_SPACE) or rest[-1:]
        return (name.group(), value) if value else None

    @staticmethod
    def _heredoc_word(word: str) -> tuple[bool, str] | None:
        """A raw word as [0-9]*<<(-?)[\\t\\n\\f\\r ]*([^<]*) matches it whole, in linear
        time: whether leading tabs are removed, and the terminator as written."""
        start = len(word) - len(word.lstrip("0123456789"))
        if not word.startswith("<<", start):
            return None
        rest = word[start + 2 :]
        chomp = rest.startswith("-")
        rest = rest[chomp:].lstrip("\t\n\f\r ")
        return None if "<" in rest else (chomp, rest)

    @classmethod
    def _dockerfile_images(cls, content: str) -> tuple[list[str], list[str]]:
        """Images named by FROM instructions, as written, and what was not collected.

        The file is read as BuildKit reads it: a trailing backslash continues an
        instruction and comment lines are dropped, even inside one; the lines of a
        heredoc are its body, not instructions; the instruction word is
        case-insensitive; --flag words come before the image; and a FROM naming an
        earlier stage is not an image. Each line is handled once.
        """
        lines = content.removeprefix("\ufeff").split("\n")
        for line in lines:
            directive = cls._directive(line.rstrip("\r").lstrip(cls._GO_SPACE))
            if directive is None:
                break
            if directive[0].lower() == "escape" and directive[1] != "\\":
                # Another escape character changes where instructions end.
                return [], ["escape parser directive not followed"]
        images: list[str] = []
        gaps: list[str] = []
        stages: set[str] = set()
        for joined in cls._dockerfile_instructions(lines, gaps):
            # BuildKit trims the arguments too: a trailing no-break space is not part
            # of the image, and "latest\xa0" is still the latest tag.
            line = joined.rstrip(cls._GO_SPACE)
            instruction = cls._DOCKER_WORD.match(line)
            if instruction is None or cls._command(instruction.group()) != "from":
                continue
            words = cls._DOCKER_WORD.findall(line, instruction.end())
            start = 0
            while start < len(words) and words[start].startswith("--"):
                start += 1
            if start == len(words) or any(c in w for w in words[:start] for c in "\"'\\"):
                # No image, or a quoted or escaped flag whose end is not certain.
                gaps.append("FROM instruction not parsed")
                continue
            image, rest = words[start], words[start + 1 :]
            if image.lower() not in stages:
                if "$" in image:
                    gaps.append("FROM image substitution not resolved")
                if any(c in image for c in "\"'\\"):
                    # BuildKit's lexer removes them, so the image pulled is another word.
                    gaps.append("FROM image quoting not resolved")
                images.append(image)
            if len(rest) == 2 and rest[0].lower() == "as":
                stages.add(rest[1].lower())
        return images, list(dict.fromkeys(gaps))

    @staticmethod
    def _command(word: str) -> str:
        # As Go's strings.ToLower does; str.lower() makes U+0130 two characters.
        return word.replace("İ", "i").lower()

    @classmethod
    def _dockerfile_instructions(cls, lines: list[str], gaps: list[str]) -> Iterator[str]:
        """Instructions as BuildKit joins their lines, without comment, empty or heredoc lines."""
        index = 0
        while index < len(lines):
            parts: list[str] = []
            while index < len(lines):
                line = lines[index].rstrip("\r")
                index += 1
                stripped = line.lstrip(cls._GO_SPACE)
                if not stripped or stripped.startswith("#"):
                    continue
                body = line if parts else stripped
                trimmed = body.rstrip(" \t")
                # One backslash continues the line; an escaped one does not.
                if not trimmed.endswith("\\") or trimmed.endswith("\\\\"):
                    parts.append(body)
                    break
                parts.append(trimmed[:-1])
            if not parts:
                return
            # BuildKit trims the joined line, which keeps a continuation line's
            # indentation when the first line holds only the backslash.
            instruction = "".join(parts).lstrip(cls._GO_SPACE)
            yield instruction
            heredocs = cls._heredocs(instruction)
            if heredocs is None:
                gaps.append("heredoc not parsed")
                continue
            for name, chomp in heredocs:
                # The body runs to the terminator as written: no comment or
                # continuation applies inside it.
                while index < len(lines):
                    line = lines[index].rstrip("\r")
                    index += 1
                    if (line.lstrip("\t") if chomp else line) == name:
                        break
                else:
                    gaps.append("heredoc not parsed")
                    return

    @classmethod
    def _heredocs(cls, instruction: str) -> list[tuple[str, bool]] | None:
        """The terminator of each heredoc BuildKit reads after an instruction.

        With whether leading tabs are removed before the comparison. Only RUN, COPY
        and ADD, alone or after ONBUILD, take heredocs. None when the line uses
        shell syntax that is not modelled, so where the instruction ends is unknown.
        """
        if "<<" not in instruction:
            return []
        words = cls._DOCKER_WORD.findall(instruction)
        command = cls._command(words[0]) if words else ""
        if command == "onbuild":
            command = cls._command(next((w for w in words[1:] if not w.startswith("--")), ""))
        if command not in ("run", "copy", "add"):
            return []
        raw = cls._shell_words(instruction, raw=True)
        if raw is None:
            return None
        heredocs: list[tuple[str, bool]] = []
        for word in raw:
            match = cls._heredoc_word(word)
            if match is None or not match[1]:
                continue
            name = cls._shell_words(match[1], raw=False)
            if name is None:
                return None
            if len(name) == 1:
                heredocs.append((name[0], match[0]))
        return heredocs

    @classmethod
    def _shell_words(cls, text: str, *, raw: bool) -> list[str] | None:
        """Words as BuildKit's shell lexer splits text when no variable is set.

        With raw, quotes and escapes stay in the words, as when BuildKit looks for
        heredocs; without, they are resolved, as for a heredoc's terminator. None
        for a substitution that is not modelled, for text the lexer rejects, and
        for a byte order mark, which Go's scanner can drop.
        """
        if "\ufeff" in text:
            return None
        words: list[str] = []
        word = ""
        position = 0
        while position < len(text):
            token = cls._SHELL_TOKEN.match(text, position)
            if token is None:
                return None
            position = token.end()
            kind, value = token.lastgroup, token.group()
            if kind == "space":
                if word:
                    words.append(word)
                word = ""
            elif raw or kind in ("plain", "heredoc", "dollar"):
                word += value
            elif kind == "single":
                word += value[1:-1]
            elif kind == "double":
                word += cls._QUOTED_ESCAPE.sub(r"\1", value[1:-1])
            else:
                word += value[1:]
        if word:
            words.append(word)
        return words

    @staticmethod
    def _conflict(one: str, other: str) -> bool:
        """Whether two declarations of a package in one group conflict, as the
        collector decides it.

        Only declarations under the same markers are compared, and the extras a
        requirement names are not. A range and a pin that satisfies it, as pip-tools,
        uv and lock files write them, do not conflict; two ranges are not compared.
        """
        try:
            first, second = Requirement(one), Requirement(other)
        except (InvalidRequirement, RecursionError):
            return False
        if str(first.marker or "") != str(second.marker or ""):
            return False
        state = _Declared()
        state.add(first)
        return state.add(second)

    @staticmethod
    def _is_ai_package(name: str) -> bool:
        """Whether a PyPI or npm package name is in the catalog, after normalisation.

        pip, uv and Poetry treat "Llama.Index", "llama_index" and "llama-index" as
        one package, so every spelling matches as its normal form does.
        """
        normal = _SEPARATORS.sub("-", name).lower()
        base = normal
        scope, slash, rest = normal.partition("/")
        if slash and scope.startswith("@"):
            if scope in AI_PACKAGE_SCOPES:
                return True
            base = rest
        return (
            normal in AI_PACKAGE_NAMES
            or base.startswith(AI_PACKAGE_PREFIXES)
            or not AI_PACKAGE_WORDS.isdisjoint(base.split("-"))
        )


class _ComposeWalk:
    """Service images found by walking a Compose file's YAML nodes.

    A mapping's keys are its own keys, then those of the mappings its merge keys
    name, earlier ones first, as YAML's merge key type defines. Each mapping's keys
    are worked out once; a mapping that merges itself, directly or through
    others, is a gap rather than a loop. An alias is the node it names, so each
    image, model, build, inline Dockerfile and build path node is read once,
    however many services share it, through aliases or merge keys.
    """

    _STR = "tag:yaml.org,2002:str"
    _NULL = "tag:yaml.org,2002:null"
    # The scalars YAML 1.1 and 1.2 both read as null.
    _NULL_TEXT = frozenset({"", "~", "null", "Null", "NULL"})
    # Linux's PATH_MAX. A longer build path is not followed, even one that names the
    # project root, and is never split.
    _LONGEST_PATH = 4_096

    def __init__(self, budget: int) -> None:
        self.budget = budget
        self.gaps: dict[str, None] = {}
        self._keys: dict[int, dict[str, Any]] = {}
        self._open: set[int] = set()
        self._read: set[tuple[str, int]] = set()
        self._paths: dict[int, list[str] | None] = {}

    def _spend(self, steps: int = 1) -> None:
        self.budget -= steps
        if self.budget < 0:
            raise ValueError("compose walk budget exhausted")

    def _first(self, role: str, node: Any) -> bool:
        """Whether a node is read in this role for the first time."""
        read = (role, id(node))
        if read in self._read:
            return False
        self._read.add(read)
        return True

    def keys(self, node: Any) -> dict[str, Any]:
        import yaml

        known = self._keys.get(id(node))
        if known is not None:
            return known
        if not isinstance(node, yaml.MappingNode):
            raise ValueError("expected a mapping")
        if id(node) in self._open:
            self.gaps["YAML merge key cycle not followed"] = None
            return {}
        self._open.add(id(node))
        own: dict[str, Any] = {}
        merged: list[Any] = []
        for key, value in node.value:
            self._spend()
            if key.tag == "tag:yaml.org,2002:merge":
                merged.extend(value.value if isinstance(value, yaml.SequenceNode) else [value])
            elif isinstance(key, yaml.ScalarNode):
                if key.tag == "tag:yaml.org,2002:binary" or not key.tag.startswith(
                    "tag:yaml.org,2002:"
                ):
                    # Compose would read another key than the text, such as the
                    # base64-decoded name of a !!binary key.
                    raise ValueError("tagged key")
                if key.value in own:
                    # Compose refuses a mapping with a repeated key.
                    raise ValueError("duplicate key")
                own[key.value] = value
            else:
                raise ValueError("complex key")
        result = dict(own)
        for source in merged:
            inherited = self.keys(source)
            self._spend(len(inherited))
            for name, value in inherited.items():
                result.setdefault(name, value)
        self._open.discard(id(node))
        self._keys[id(node)] = result
        return result

    def images(self, root: Any) -> tuple[list[str], list[str], list[str]]:
        """Service images, the references of top-level models, and the gaps."""
        import yaml

        top = self.keys(root)
        if "include" in top:
            self.gaps["include not followed"] = None
        images: list[str] = []
        models: list[str] = []
        declared = top.get("models")
        if declared is not None and not self._empty(declared):
            for model in self.keys(declared).values():
                reference = (
                    model if isinstance(model, yaml.ScalarNode) else self.keys(model).get("model")
                )
                if reference is not None and self._first("model", reference):
                    models.extend(self._image(reference))
        services = top.get("services")
        if services is None or self._empty(services):
            return images, models, list(self.gaps)
        for service in self.keys(services).values():
            fields = self.keys(service)
            image = fields.get("image")
            if image is not None and self._first("image", image):
                images.extend(self._image(image))
            build = fields.get("build")
            if build is not None and self._first("build", build):
                images.extend(self._build(build))
            extends = fields.get("extends")
            if isinstance(extends, yaml.MappingNode) and "file" in self.keys(extends):
                self.gaps["extends not followed"] = None
        return images, models, list(self.gaps)

    def _empty(self, node: Any) -> bool:
        import yaml

        return isinstance(node, yaml.ScalarNode) and (
            node.value in self._NULL_TEXT and node.tag in (self._NULL, self._STR, "!reset")
        )

    def _text(self, node: Any, gap: str) -> str | None:
        """The text Compose reads from a scalar: "" when it holds none, None after
        recording the gap.

        An untagged or !!str scalar, or one with Compose's !override, is read as
        written, and !reset or null hold no value. Any other tag can make Compose
        read other text, such as base64-decoded !!binary, or nothing at all.
        """
        if node.tag == "!reset" or (node.tag == self._NULL and node.value in self._NULL_TEXT):
            return ""
        if node.tag not in (self._STR, "!override"):
            self.gaps[gap] = None
            return None
        return str(node.value)

    def _image(self, node: Any) -> list[str]:
        import yaml

        if not isinstance(node, yaml.ScalarNode):
            self.gaps["image not parsed"] = None
            return []
        value = (self._text(node, "tagged image value not resolved") or "").strip()
        if not value:
            # No image, such as an override file's !reset, or a gap recorded.
            return []
        if "$" in value:
            # Compose fills ${NAME} from the environment and .env.
            self.gaps["image substitution not resolved"] = None
        return [value]

    def _build(self, node: Any) -> list[str]:
        """A build's FROM images when its Dockerfile is inline or is a root Dockerfile
        the collector reads; otherwise a gap."""
        import yaml

        unread = "build context not followed"
        context: list[str] | None
        dockerfile: list[str] | None
        if isinstance(node, yaml.ScalarNode):
            text = self._text(node, "build not followed")
            if not text:
                # No build, such as an override file's !reset, or a gap recorded.
                return []
            context, dockerfile = self._parts(node, text), ["Dockerfile"]
        elif isinstance(node, yaml.MappingNode):
            fields = self.keys(node)
            if self._named_contexts(fields):
                # BuildKit uses a named context in place of the image that a FROM
                # line of that name pulls.
                self.gaps[unread] = None
            if "dockerfile_inline" in fields:
                return self._inline(fields["dockerfile_inline"])
            context = self._path(fields.get("context"), ".")
            dockerfile = self._path(fields.get("dockerfile"), "Dockerfile")
        else:
            self.gaps["build not followed"] = None
            return []
        if not (
            context == []
            and dockerfile is not None
            and len(dockerfile) == 1
            and dockerfile[0] in RegistryScanner._DOCKERFILES
        ):
            # The Dockerfile it builds from is not one the collector reads.
            self.gaps[unread] = None
        return []

    def _named_contexts(self, fields: dict[str, Any]) -> bool:
        """Whether a build names contexts: Compose's additional_contexts, or the
        contexts that docker buildx bake reads from x-bake in the same file."""
        import yaml

        bake = fields.get("x-bake")
        if isinstance(bake, yaml.MappingNode):
            bake = self.keys(bake).get("contexts")
        return any(
            node is not None and not self._unset(node)
            for node in (fields.get("additional_contexts"), bake)
        )

    def _unset(self, node: Any) -> bool:
        """Whether a node holds no entries: null, empty, or Compose's !reset."""
        import yaml

        if node.tag == "!reset":
            return True
        return self._empty(node) if isinstance(node, yaml.ScalarNode) else not node.value

    def _path(self, node: Any, default: str) -> list[str] | None:
        """A build path setting's parts, its default's when unset, or None when the
        collector does not follow it."""
        import yaml

        if node is None:
            return self._local(default)
        if not isinstance(node, yaml.ScalarNode):
            return None
        text = self._text(node, "build context not followed")
        if text is None:
            return None
        return self._parts(node, text) if text else self._local(default)

    def _parts(self, node: Any, text: str) -> list[str] | None:
        """A scalar's path parts, worked out once however many builds share it."""
        if id(node) not in self._paths:
            self._paths[id(node)] = self._local(text)
        return self._paths[id(node)]

    @classmethod
    def _local(cls, path: str) -> list[str] | None:
        """A relative path's parts as Compose resolves it, None for any other path.

        An absolute path, such as "/" for the root of the host, is not the project
        root; a backslash separates paths on Windows. A path too long to open is not
        split at all.
        """
        if len(path) > cls._LONGEST_PATH or path.startswith("/") or "\\" in path:
            return None
        return RegistryScanner._normalised(path.split("/"))

    def _inline(self, node: Any) -> list[str]:
        """The FROM images of an inline Dockerfile, parsed once however many builds
        share it."""
        import yaml

        text = self._text(node, "build not followed") if isinstance(node, yaml.ScalarNode) else None
        if not text:
            self.gaps["build not followed"] = None
            return []
        if not self._first("dockerfile_inline", node):
            return []
        images, gaps = RegistryScanner._dockerfile_images(text)
        for gap in gaps:
            self.gaps[f"dockerfile_inline {gap}"] = None
        return images
