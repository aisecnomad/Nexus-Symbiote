"""Classify MCP launch commands statically, without executing anything.

Commands are matched by normalised basename. Common wrappers (``env``, ``sh -c``,
``cmd /c``, ``powershell -Command``, ``wsl`` and secret-injection runners such as
``op run --``) are unwrapped with bounded parsing. Each recognised package runner
reads only the options it documents, with a table of the options that take a
value, so a value, possibly a secret, is never taken for the package; where the
runner's parser may leave a value empty and read the next word as an option, the
launch is unknown. A runner
whose arguments do not fit its grammar, or whose package is not a registry name,
is reported through ``Launch.unknown``; it is never guessed.

Any other command is a local program. Its arguments, and those a runner passes to
the program it starts, are scanned for a package runner, shell or wrapper name
followed by words that make it a launch, and for inline interpreter code; either
makes the launcher unknown, because an unrecognised wrapper (``nice``, ``sudo``,
``cross-env``, a gateway package) may start it.
"""

from __future__ import annotations

import csv
import fnmatch
import posixpath
import re
import shlex
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.hashing import extract_version_pin
from nexus_symbiote.scanners.base import sanitized_origin


def _set(words: str) -> frozenset[str]:
    return frozenset(words.split())


def _moves(directory: str) -> bool:
    """Whether a working directory given to a launcher is other than the project root."""
    return directory not in {"", ".", "./", ".\\"}


MAX_WRAPPERS = 4
MAX_SCRIPT_CHARS = 4096
MAX_SCRIPT_TOKENS = 256
MAX_SPEC_CHARS = 2048

_EXECUTABLE_SUFFIXES = (".exe", ".cmd", ".bat", ".ps1", ".com")
# Shell parameters ($1, $@, $#, ...) count as expansion: their values come from the caller.
_EXPANSION = re.compile(r"\$[{(\w@*#?$!-]|%[A-Za-z_][A-Za-z0-9_]*(?::[^%\s]*)?%|`")
_SHELL_OPERATOR = re.compile(r"[;&|<>()`\n\r]|\$\(")
_CMD_OPERATOR = re.compile(r"[&|<>^()\n\r]")
_POWERSHELL_OPERATOR = re.compile(r"[;&|<>(){}\[\]$`\n\r]|(?:^|\s)@")
_POSIX_PATH_OPERATOR = re.compile(r"[;&|<>()`$\\'\"\n\r]")
_WINDOWS_PATH_OPERATOR = re.compile(r"[&|<>^\"\n\r]")
_NOT_SIMPLE = "command line is not a simple command"
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=", re.ASCII)
# ASCII only: a non-ASCII host is an ambiguous authority, not a plain name.
_HOSTNAME = re.compile(r"[\w.-]+|[0-9a-f:.]+", re.ASCII)
_COMMIT = re.compile(r"[0-9a-fA-F]{40}")

_NPM_NAME = r"(?:@[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*"
_NPM_SPEC = re.compile(rf"({_NPM_NAME})(?:@(.+))?", re.ASCII | re.DOTALL)
_GITHUB_SHORTHAND = re.compile(r"[A-Za-z0-9][\w.-]*/[\w.-]+(?:#.*)?", re.ASCII | re.DOTALL)
_GIT_HOSTED = re.compile(r"(?:github|gitlab|bitbucket|gist):", re.IGNORECASE)
_LOCAL_PATH = re.compile(r"(?:\.{1,2}|~)(?:[\\/]|$)|[\\/]|[A-Za-z]:[\\/]|file:|link:", re.I)
_ARCHIVE = re.compile(r"\.(?:tgz|tar|tar\.gz|zip|whl)$", re.IGNORECASE)
_OCI = re.compile(
    r"(?P<repository>(?:[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?/)?"
    r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?"
    r"(?:@sha256:(?P<digest>[0-9a-fA-F]{64}))?"
)
# A release tag names three version components; "1", "20" or "3.12" roll forward.
_RELEASE_TAG = re.compile(r"v?\d+\.\d+\.\d+(?:[-+._][0-9A-Za-z.+_-]*)?")
_JSR = re.compile(r"(@[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*)(?:@([^/]+))?(?:/.*)?", re.S)

_NODE_INLINE = frozenset({"-e", "--eval", "-p", "--print", "-pe", "-ep", "-"})
_NODE_PRELOAD = frozenset({"-r", "--require", "--import", "--loader", "--experimental-loader"})
_NODE_DEBUGGERS = frozenset({"--inspect", "--inspect-brk", "--inspect-wait"})
_NODE_DEBUGGER_NEGATIONS = {option.replace("--", "--no-", 1): option for option in _NODE_DEBUGGERS}
_NODE_DEBUG_PORTS = frozenset({"--inspect-port", "--debug-port"})
# Node options that take a value as the next word (node --help); the value is never the script.
_NODE_VALUES = _NODE_PRELOAD | _set(
    "--allow-fs-read --allow-fs-write --build-snapshot-config -C --conditions --cpu-prof-dir"
    " --cpu-prof-interval --cpu-prof-name --debug-port --diagnostic-dir --disable-proto"
    " --disable-warning --dns-result-order --env-file --env-file-if-exists"
    " --experimental-config-file --experimental-default-type --experimental-sea-config"
    " --experimental-test-isolation --heap-prof-dir --heap-prof-interval --heap-prof-name"
    " --heapsnapshot-near-heap-limit --heapsnapshot-signal --icu-data-dir --input-type"
    " --inspect-port --inspect-publish-uid --localstorage-file --max-http-header-size"
    " --max-old-space-size-percentage --network-family-autoselection-attempt-timeout"
    " --openssl-config --redirect-warnings --report-dir --report-directory --report-filename"
    " --report-signal --run --secure-heap --secure-heap-min --security-revert --snapshot-blob"
    " --test-concurrency --test-coverage-branches --test-coverage-exclude"
    " --test-coverage-functions --test-coverage-include --test-coverage-lines"
    " --test-name-pattern --test-reporter --test-reporter-destination --test-shard"
    " --test-skip-pattern --test-timeout --title --tls-cipher-list --tls-keylog"
    " --trace-event-categories --trace-event-file-pattern --trace-require-module"
    " --unhandled-rejections --use-largepages --v8-pool-size --watch-kill-signal --watch-path"
)
_INLINE_SOURCES = ("data:", "http:", "https:")
# Rarely used interpreters: inline code flags anywhere before the script file, alone, at
# the end of a cluster, or with the code attached after a run of options that take none.
_INLINE_FLAGS = {
    "lua": re.compile(r"-e.*", re.S),
    "rscript": re.compile(r"-e"),
    "osascript": re.compile(r"-i*e.*", re.S),
    "ruby": re.compile(r"-[a-zA-Z]*e|-[acdlnpsSvwyhUW0-9]*e.+", re.S),
    "perl": re.compile(r"-[a-zA-Z]*[eE]|-[acdfgnpsStTuUvwWXhl0-9]*[eE].+", re.S),
    "php": re.compile(
        r"-[aehilmnsvwH]*[rBRE].*|--(?:run|process-begin|process-code|process-end)(?:=.*)?", re.S
    ),
}
# Their options that take the next word as a value when none is attached (ruby --help,
# perl -h, php --help); the value is never the script.
_INLINE_VALUES = {
    "lua": _set("-l"),
    "rscript": frozenset(),
    "osascript": _set("-l -s"),
    "ruby": _set(
        "-I -r -C -E --encoding --external-encoding --internal-encoding --enable --disable"
        " --dump --parser --backtrace-limit --crash-report"
    ),
    "perl": _set("-I"),
    "php": _set(
        "-c -d -z -t -S --php-ini --define --zend-extension --docroot --server"
        " --rf --rc --re --rz --ri"
    ),
}
_SCRIPT_SUFFIX = re.compile(r"(?:-cli)?\.[cm]?js$|\.py$")
# Python options that end a short-option cluster: inline code, a module, or a value.
_PYTHON_SPECIAL = re.compile("[cmWX]")
# Windows' windowed interpreters (pythonw, pyw) and free-threaded builds (python3.13t).
_PYTHON_NAME = re.compile(r"(?:python|pypy)w?[0-9.]*t?w?(?:d|-dbg)?|pyw?")
# Version-suffixed interpreter binaries (lua5.4, lua-5.4, luajit-2.1.0-beta3, ruby3.2, php8.2).
_VERSIONED_INTERPRETER = re.compile(r"(lua(?:jit)?|ruby|php|perl)(?:-?[0-9][-0-9.a-z]*)?")
# Standard library modules that run their arguments as Python code or read it from the
# terminal, by the normalized module name ("_" becomes "-", so _pyrepl is -pyrepl).
_PYTHON_CODE_MODULES = frozenset({"timeit", "code", "asyncio", "idlelib", "-pyrepl"})


def _pdb_runs_commands(args: list[str]) -> bool:
    """Whether pdb's own options hold -c/--command.

    getopt reads them up to the first word that is not an option, the script or the
    module, and takes any unambiguous prefix of --command; a -c after that word belongs
    to the debugged program.
    """
    for word in args:
        if word == "--" or word == "-" or not word.startswith("-"):
            return False
        if word.startswith("--"):
            option = word.partition("=")[0]
            if len(option) > 2 and "--command".startswith(option):
                return True
        elif "c" in word[1:]:
            return True
    return False


# TypeScript and transpiling Node runners accept node's inline code options.
_NODE_RUNNERS = frozenset({"tsx", "esno", "babel-node"})
_TS_NODE = frozenset(
    {
        "ts-node",
        "ts-node-esm",
        "ts-node-cwd",
        "ts-node-script",
        "ts-node-transpile-only",
        "ts-script",
    }
)
# ts-node options that take a value (ts-node --help); node's own are in _NODE_VALUES.
_TS_NODE_VALUES = _set(
    "--cwd --dir -C --compiler -O --compiler-options --compilerOptions -P --project -D"
    " --ignore-diagnostics --ignoreDiagnostics -I --ignore --transpiler --scope-dir --scopeDir"
    " --experimental-specifier-resolution --experimentalSpecifierResolution"
)


def _script_like(word: str) -> bool:
    """A word that names a script file rather than a program option or value."""
    return "." in word or "/" in word or "\\" in word


@dataclass(frozen=True)
class Package:
    """A package a launcher fetches. ``spec`` is raw input and is never exported."""

    ecosystem: str
    spec: str
    name: str | None = None
    version: str | None = None
    pinned: bool = False
    pin: str | None = None
    origin: str | None = None

    @property
    def registry(self) -> bool:
        return self.ecosystem in {"npm", "pypi", "oci", "jsr", "golang"} and self.name is not None

    @property
    def identity(self) -> str:
        if self.registry:
            return f"{self.ecosystem}:{self.name}"
        if self.ecosystem in {"git", "url"} and self.origin:
            return f"{self.ecosystem}:{self.origin}"
        return self.ecosystem


@dataclass
class Launch:
    """What a declared command runs, without any argument value."""

    command: str | None = None
    launcher: str | None = None
    family: str | None = None
    runner: bool = False
    wrappers: list[str] = field(default_factory=list)
    executable: str | None = None
    packages: list[Package] = field(default_factory=list)
    unknown: str | None = None
    sources: list[tuple[str, str]] = field(default_factory=list)
    context: dict[str, int] = field(default_factory=dict)
    environment: list[tuple[str, str]] = field(default_factory=list)
    # The launch changes the working directory, so project resolver files may differ.
    relocated: bool = False
    # A wrapper adds variables from a file or secret store the inventory cannot read.
    injected_environment: bool = False
    # A shell in the launch runs interactively (-i), so it also reads $ENV.
    interactive: bool = False
    # A shell in the launch traces its commands (-x), expanding $PS4 before each one.
    xtrace: bool = False
    # npm exec names packages and no command, so npm runs a configured call or its script shell.
    script_shell: bool = False
    # env -S and --split-string values read so far, across every env wrapper.
    split_strings: int = 0
    # Wrapper override for NODE_TLS_REJECT_UNAUTHORIZED: None = inherit server env,
    # "" = explicitly cleared/unset by env -i/-u, otherwise the last wrapper value.
    node_tls_override: str | None = None

    def mark(self, flag: str, count: int = 1) -> None:
        self.context[flag] = self.context.get(flag, 0) + count

    def fail(self, reason: str) -> None:
        if self.unknown is None:
            self.unknown = reason


def known_executable(name: str | None) -> bool:
    """A runner, wrapper or interpreter name from a fixed vocabulary, safe to export."""
    return name is not None and (
        name in _RUNNERS
        or name in _SHELLS
        or name in _INJECTORS
        or name in _INTERPRETERS
        or _runner_key(name) in _UNCLASSIFIED_RUNNERS
        or name in _NODE_RUNNERS
        or name in _TS_NODE
        or bool(_PYTHON_NAME.fullmatch(name))
        or bool(_VERSIONED_INTERPRETER.fullmatch(name))
        or name in {"node", "nodejs"}
    )


def normalize_command(value: str) -> str:
    """Basename for POSIX and Windows paths, without a Windows suffix, casefolded."""
    # Win32 drops trailing dots and spaces from a path's last component (npx.cmd. is npx.cmd).
    base = re.split(r"[\\/]", value.strip().strip("\"'"))[-1].casefold().rstrip(". ")
    for suffix in _EXECUTABLE_SUFFIXES:
        if base.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)]
    return base


def expands(value: str) -> bool:
    """Whether a value depends on environment, input or command substitution."""
    return bool(_EXPANSION.search(value))


def origin(url: str) -> str | None:
    """Scheme, host and port of a URL; None when it has none or its host is ambiguous."""
    if expands(url):
        return None
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if "\\" in parsed.netloc or not hostname or not _HOSTNAME.fullmatch(hostname):
            return None
    except ValueError:
        return None
    exported = sanitized_origin(url)
    return None if exported == "[redacted]" else exported


# Characters a POSIX shell rewrites in a word: brace and pattern expansion, tilde,
# comments, history and zsh's ^ and =cmd forms, parameter and command expansion. Quoting
# is not among them: shlex removes it as a POSIX shell does.
_POSIX_REWRITE = re.compile(r"[{}*?\[\]~#!^$`]|[^\x00-\x7f]")
# Quoting, for a reader that does not remove it as shlex does (env -S, wsl, eval's second
# reading, PowerShell).
_QUOTING = re.compile(r"['\"\\]")
_LITERAL_WORD = re.compile(r"[A-Za-z0-9_@%+=:,./-]+")


def _split_script(
    script: str, operators: re.Pattern[str] = _SHELL_OPERATOR, *, literal: bool = False
) -> list[str] | None:
    """Words of a simple command; None for anything a shell would do more with.

    Every word must read as written: no character a shell rewrites, no whitespace or
    other character inside a word, and, with ``literal``, no quoting at all. A command
    word that is itself an expansion is returned, so that it is reported as depending
    on the environment.
    """
    if len(script) > MAX_SCRIPT_CHARS or operators.search(script):
        return None
    if literal and _QUOTING.search(script):
        return None
    try:
        words = shlex.split(script, posix=True)
    except ValueError:
        return None
    if not 0 < len(words) <= MAX_SCRIPT_TOKENS:
        return None
    head = next((word for word in words if not _ASSIGNMENT.match(word) and word != "exec"), None)
    if head is not None and expands(head):
        return words
    if _POSIX_REWRITE.search(script) or not all(
        _LITERAL_WORD.fullmatch(word) and not word.startswith("=") for word in words
    ):
        return None
    return words


def _basename_text(token: str) -> str:
    """The text after the last path separator outside any ${...}, as written."""
    depth = 0
    start = 0
    index = 0
    while index < len(token):
        if token.startswith("${", index):
            depth += 1
            index += 2
            continue
        char = token[index]
        if char == "}" and depth:
            depth -= 1
        elif char in "/\\" and not depth:
            start = index + 1
        index += 1
    return token[start:]


@dataclass(frozen=True)
class _Options:
    flags: frozenset[str] = frozenset()
    values: frozenset[str] = frozenset()
    value_patterns: tuple[re.Pattern[str], ...] = ()
    flag_patterns: tuple[re.Pattern[str], ...] = ()
    combined: bool = False
    boolean_values: bool = False
    # npm's parser (nopt) gives a String option an empty value when the next word starts
    # with "-" and reads that word as an option; a value such a parser may not consume is
    # not taken from the next word.
    dashed_values: bool = True
    # nopt also reads a value word (_NOPT_BOOLEAN_WORDS) after a Boolean option as its
    # value, which moves the next positional word; such a pair is not read.
    nopt_booleans: bool = False
    # Letters of the single-letter options, for checking option clusters in C.
    short_flags: frozenset[str] = frozenset()
    short_values: frozenset[str] = frozenset()


# Every word nopt reads as the value of a Boolean or [null, Boolean] option written without
# "=": true and false for any Boolean, null where the type allows null.
_NOPT_BOOLEAN_WORDS = frozenset({"true", "false", "null"})


def _letters(options: str) -> frozenset[str]:
    return frozenset(word[1] for word in options.split() if len(word) == 2 and word[0] == "-")


def _table(
    flags: str = "",
    values: str = "",
    *,
    value_patterns: tuple[str, ...] = (),
    flag_patterns: tuple[str, ...] = (),
    combined: bool = False,
    boolean_values: bool = False,
    dashed_values: bool = True,
    nopt_booleans: bool = False,
) -> _Options:
    return _Options(
        frozenset(flags.split()),
        frozenset(values.split()),
        tuple(re.compile(pattern) for pattern in value_patterns),
        tuple(re.compile(pattern) for pattern in flag_patterns),
        combined,
        boolean_values,
        dashed_values,
        nopt_booleans,
        _letters(flags),
        _letters(values),
    )


def _scan(tokens: list[str], table: _Options) -> tuple[list[tuple[str, str | None]], int] | None:
    """Options before the first positional word; None when one is not in the table."""
    seen: list[tuple[str, str | None]] = []
    index = 0
    while index < len(tokens):
        word = tokens[index]
        if word == "--":
            return seen, index + 1
        if not word.startswith("-") or word == "-":
            return seen, index
        name, equals, attached = word.partition("=")
        takes_value = name in table.values or any(
            pattern.fullmatch(name) for pattern in table.value_patterns
        )
        is_flag = name in table.flags or any(
            pattern.fullmatch(name) for pattern in table.flag_patterns
        )
        if takes_value:
            if not equals:
                if index + 1 >= len(tokens):
                    return None
                if not table.dashed_values and tokens[index + 1].startswith("-"):
                    return None
                index += 1
                attached = tokens[index]
            seen.append((name, attached))
        elif is_flag and (
            not equals
            or any(pattern.fullmatch(name) for pattern in table.flag_patterns)
            or (table.boolean_values and attached.lower() in {"true", "false", "1", "0"})
        ):
            if (
                table.nopt_booleans
                and not equals
                and index + 1 < len(tokens)
                and tokens[index + 1] in _NOPT_BOOLEAN_WORDS
            ):
                return None
            seen.append((name, attached if equals else None))
        elif table.combined and not word.startswith("--"):
            consumed = _combined(word, tokens, index, table, seen)
            if consumed is None:
                return None
            index = consumed
        else:
            return None
        index += 1
    return seen, len(tokens)


def _combined(
    word: str,
    tokens: list[str],
    index: int,
    table: _Options,
    seen: list[tuple[str, str | None]],
) -> int | None:
    letters = word[1:]
    for position, letter in enumerate(letters):
        option = "-" + letter
        if option in table.flags:
            seen.append((option, None))
            continue
        if option not in table.values:
            return None
        rest = letters[position + 1 :]
        if rest:
            seen.append((option, rest.removeprefix("=")))
            return index
        if index + 1 >= len(tokens):
            return None
        seen.append((option, tokens[index + 1]))
        return index + 1
    return index


def _git(spec: str, *, python: bool = False) -> Package:
    """A git source is pinned only by a full 40-hexadecimal commit.

    npm names the commit after ``#``. pip and uv name it after the last ``@`` in the
    path and read the fragment only for ``egg=`` and ``subdirectory=``.
    """
    body = spec[4:] if spec.lower().startswith("git+") else spec
    reference = ""
    try:
        if python:
            body = body.partition("#")[0]
            if "@" in urlsplit(body).path:
                reference = urlsplit(body).path.rsplit("@", 1)[1]
        elif "#" in body:
            body, _, reference = body.partition("#")
            reference = reference.removeprefix("commit=")
        elif "@" in urlsplit(body).path:
            reference = urlsplit(body).path.rsplit("@", 1)[1]
    except ValueError:
        return Package("unknown", spec)
    source: str | None
    if _GIT_HOSTED.match(body):
        host = body.split(":", 1)[0].lower()
        source = "https://gist.github.com" if host == "gist" else f"https://{host}.com"
    elif body.startswith("git@"):
        host = body[4:].split(":", 1)[0]
        source = f"ssh://{host}" if _HOSTNAME.fullmatch(host) else None
    else:
        source = origin(body)
    pinned = bool(_COMMIT.fullmatch(reference))
    return Package(
        "git",
        spec,
        version=reference.lower() if pinned else None,
        pinned=pinned,
        pin="commit" if pinned else None,
        origin=source,
    )


def _plain(spec: str) -> bool:
    return (
        0 < len(spec) <= MAX_SPEC_CHARS
        and not spec.isspace()
        and not any(char in spec for char in "\r\n\x00")
        and not expands(spec)
    )


def npm_spec(spec: str) -> Package:
    """An npm package spec: registry name and version, alias, git, URL or path."""
    if not _plain(spec):
        return Package("unknown", spec)
    lowered = spec.lower()
    if lowered.startswith(("git+", "git://", "git@", "ssh://")) or _GIT_HOSTED.match(spec):
        return _git(spec)
    if "://" in spec:
        return Package("url", spec, origin=origin(spec))
    if _LOCAL_PATH.match(spec) or _ARCHIVE.search(spec):
        return Package("path", spec)
    match = _NPM_SPEC.fullmatch(spec)
    if match is None:
        if _GITHUB_SHORTHAND.fullmatch(spec):
            return _git("github:" + spec)
        return Package("unknown", spec)
    name, reference = match.groups()
    if reference is None:
        return Package("npm", spec, name=name)
    if reference.startswith("npm:"):
        target = npm_spec(reference[4:])
        aliased = target.ecosystem == "npm" and "@npm:" not in reference[4:]
        return target if aliased else Package("unknown", spec)
    if reference.lower().startswith(("git+", "git://", "git@")) or _GIT_HOSTED.match(reference):
        return _git(reference)
    if "://" in reference:
        return Package("url", spec, origin=origin(reference))
    if _LOCAL_PATH.match(reference) or _ARCHIVE.search(reference):
        return Package("path", spec)
    if reference.startswith("workspace:"):
        return Package("path", spec)
    if "/" in reference:
        return _git("github:" + reference)
    version = extract_version_pin(f"{name}@{reference}", ecosystem="npm")
    return Package(
        "npm",
        spec,
        name=name,
        version=version,
        pinned=version is not None,
        pin="version" if version else None,
    )


def python_spec(spec: str, *, shorthand: bool = False) -> Package:
    """A PEP 508 requirement, uvx ``name@version`` shorthand, git URL, URL or path."""
    if not _plain(spec):
        return Package("unknown", spec)
    lowered = spec.lower()
    if lowered.startswith("git+"):
        return _git(spec, python=True)
    if "://" in spec and " @ " not in spec and "@ " not in spec:
        return Package("url", spec, origin=origin(spec))
    if _LOCAL_PATH.match(spec) or (_ARCHIVE.search(spec) and "://" not in spec):
        return Package("path", spec)
    reference = spec
    if shorthand and "@" in spec and " " not in spec:
        name, _, wanted = spec.rpartition("@")
        if wanted == "latest":
            reference = name
        else:
            try:
                Version(wanted)
            except InvalidVersion:
                return Package("unknown", spec)
            reference = f"{name}=={wanted}"
    try:
        requirement = Requirement(reference)
    except InvalidRequirement:
        return Package("unknown", spec)
    if requirement.url:
        url = requirement.url
        if url.lower().startswith("git+"):
            return _git(url, python=True)
        return Package(
            "path" if url.lower().startswith("file:") else "url", spec, origin=origin(url)
        )
    version = extract_version_pin(reference, ecosystem="python")
    return Package(
        "pypi",
        spec,
        name=str(canonicalize_name(requirement.name)),
        version=version,
        pinned=version is not None,
        pin="version" if version else None,
    )


def oci_spec(spec: str) -> Package:
    """An image is pinned only by a digest; a tag, even ``1.2.3``, can be moved."""
    if not _plain(spec) or spec.startswith("-"):
        return Package("unknown", spec)
    match = _OCI.fullmatch(spec)
    if match is None:
        return Package("unknown", spec)
    repository = match["repository"].lower()
    if match["digest"]:
        digest = "sha256:" + match["digest"].lower()
        return Package("oci", spec, name=repository, version=digest, pinned=True, pin="digest")
    tag = match["tag"]
    if tag and _RELEASE_TAG.fullmatch(tag):
        return Package("oci", spec, name=repository, version=tag, pin="tag")
    return Package("oci", spec, name=repository)


def jsr_spec(spec: str) -> Package:
    match = _JSR.fullmatch(spec) if _plain(spec) else None
    if match is None:
        return Package("unknown", spec)
    name, reference = match.groups()
    version = extract_version_pin(f"x@{reference}", ecosystem="npm") if reference else None
    return Package(
        "jsr",
        spec,
        name=name,
        version=version,
        pinned=version is not None,
        pin="version" if version else None,
    )


_NPM_SOURCE = frozenset(
    {
        "--registry",
        "--userconfig",
        "--globalconfig",
        "--prefix",
        "-C",
        "--cache",
        "-w",
        "--workspace",
        "--store-dir",
        "--cache-dir",
    }
)
# npx rewrites --shell to --script-shell; npm reads --shell for an exec without a command.
_NPM_CODE_LOADING = frozenset({"--node-options", "--script-shell", "--shell"})
_SCOPED_REGISTRY = r"--@[a-z0-9][a-z0-9._-]*:registry"
# npx and npm exec are read by a port of npm 10.9.9's own argument handling: the rewrite in
# bin/npx-cli.js, then nopt 8 with the @npmcli/config types of the options below. A word or
# sequence the port does not model exactly is unknown, so npm cannot read an argument list
# differently from the record (the differential test replays the real npx-cli.js and nopt).
_NOPT_BOOLEAN = _set(
    "offline prefer-online prefer-offline legacy-peer-deps foreground-scripts"
    " include-workspace-root update-notifier audit fund parseable ignore-scripts"
)
_NOPT_NULL_BOOLEAN = _set("yes workspaces")
# Options whose type is exactly String: nopt reads a value that starts with "-" as an option.
_NOPT_STRING = _set("call tag shell")
_NOPT_VALUE = _set(
    "package cache userconfig globalconfig registry prefix node-options loglevel workspace"
    " before script-shell"
)
# Keys without a type, which nopt reads as Booleans; npx removes or rewrites them first.
_NOPT_UNTYPED = _set("ignore-existing no-install")
_NOPT_SHORTHANDS: dict[str, tuple[str, ...]] = {
    "y": ("--yes",),
    "n": ("--no-yes",),
    "no": ("--no-yes",),
    "c": ("--call",),
    "p": ("--parseable",),
    "q": ("--loglevel", "warn"),
    "quiet": ("--loglevel", "warn"),
    "s": ("--loglevel", "silent"),
    "silent": ("--loglevel", "silent"),
    "verbose": ("--loglevel", "verbose"),
    "d": ("--loglevel", "info"),
    "dd": ("--loglevel", "verbose"),
    "ddd": ("--loglevel", "silly"),
    "w": ("--workspace",),
    "ws": ("--workspaces",),
    "C": ("--prefix",),
}
_NOPT_LONG_SHORTHANDS = _set("no quiet silent verbose")
_NPX_REMOVED_OPTS = _set("npm node-arg n")
_NPX_REMOVED = _NPX_REMOVED_OPTS | {"ignore-existing"}
# npx's switches (npm's Boolean definitions and its own) and the options it knows take a value.
_NPX_SWITCHES = _NOPT_BOOLEAN | _NOPT_NULL_BOOLEAN | _set("ignore-existing no-install")
_NPX_OPTS = _set("package p cache userconfig call c shell") | _NPX_REMOVED_OPTS
_NPX_KEYS = (
    _NPX_SWITCHES
    | _NPX_OPTS
    | _NOPT_STRING
    | _NOPT_VALUE
    | frozenset(_NOPT_SHORTHANDS)
    | frozenset(f"no-{key}" for key in _NOPT_BOOLEAN | _NOPT_NULL_BOOLEAN)
)
_SCOPED_REGISTRY_KEY = re.compile(_SCOPED_REGISTRY.removeprefix("--"))
# String.prototype.trim, which nopt applies to every value.
_JS_SPACE = " \t\n\v\f\r\u00a0\u1680\u2028\u2029\u202f\u205f\u3000\ufeff" + "".join(
    chr(c) for c in range(0x2000, 0x200B)
)


def _npx_argv(args: list[str]) -> list[str] | None:
    """The argument list bin/npx-cli.js hands to npm after "exec"; None for a word it does
    not model, such as a lone "-", which npx reads as an option and nopt as a word."""
    argv = list(args)
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            break
        if not arg.startswith("-"):
            argv.insert(index, "--")
            break
        key, *values = arg.lstrip("-").split("=")
        if key not in _NPX_KEYS and not _SCOPED_REGISTRY_KEY.fullmatch(key):
            return None
        if key == "p":
            argv[index] = "=".join(["--package", *values])
        elif key == "shell":
            argv[index] = "=".join(["--script-shell", *values])
        elif key == "no-install":
            argv[index] = "--yes=false"
        elif key in _NOPT_SHORTHANDS and key not in _NPX_REMOVED:
            argv[index : index + 1] = [*_NOPT_SHORTHANDS[key], *(["=".join(values)] * bool(values))]
            continue
        dashed = index + 1 < len(argv) and argv[index + 1].startswith("-")
        steps = not values and key not in _NPX_SWITCHES and (key in _NPX_OPTS or not dashed)
        if key in _NPX_REMOVED:
            del argv[index]
            if steps:
                del argv[index : index + 1]
            continue
        index += 2 if steps else 1
    return argv


def _nopt_value(key: str, value: str, equals: bool) -> bool:
    """Whether nopt keeps this word, as written, as the option's value."""
    if not value or value[0] in _JS_SPACE or value[-1] in _JS_SPACE:
        return False
    if key in _NOPT_STRING or not equals:
        return not value.startswith("-")
    return not re.fullmatch(r"-{2,}", value)


@dataclass
class _NpmArgs:
    # npm's options, each with the count of positional words before it.
    options: list[tuple[str, str | None, int]] = field(default_factory=list)
    remain: list[str] = field(default_factory=list)
    # The words after the first positional word (npm's command), as written.
    after: list[str] = field(default_factory=list)
    # "late" for an option after the second positional word (npm's command and its package
    # or command word); "unrecognised" for anything the port does not model.
    failure: str | None = None
    # On a failure, the words from the one the port stopped at, as written.
    unread: list[str] = field(default_factory=list)


def _nopt(tokens: list[str]) -> _NpmArgs:
    """npm's options and positional words, as nopt reads them."""
    parsed = _NpmArgs()
    options, remain = parsed.options, parsed.remain
    words = list(tokens)
    index = 0
    while index < len(words):
        arg = words[index]
        if arg == "--":
            if not remain:
                parsed.after = words[index + 2 :]
            remain.extend(words[index + 1 :])
            return parsed
        if not arg.startswith("-") or (arg == "-" and len(remain) >= 2):
            if not remain:
                parsed.after = words[index + 1 :]
            remain.append(arg)
            index += 1
            continue
        if len(remain) >= 2:
            parsed.failure = "late"
            break
        following = words[index + 1] if index + 1 < len(words) else None
        name, equals, value = arg.partition("=")
        short = not name.startswith("--")
        key = name[1:] if short else name[2:]
        if key in _NOPT_SHORTHANDS and (short or key in _NOPT_LONG_SHORTHANDS):
            if equals or following in _NOPT_BOOLEAN_WORDS:
                parsed.failure = "unrecognised"
                break
            words[index : index + 1] = _NOPT_SHORTHANDS[key]
            continue
        base = key.removeprefix("no-")
        if not short and (
            base in _NOPT_BOOLEAN | _NOPT_NULL_BOOLEAN or (key in _NOPT_UNTYPED and not equals)
        ):
            allowed = {"true", "false"} | ({"null"} if base in _NOPT_NULL_BOOLEAN else set())
            if (value not in allowed) if equals else (following in _NOPT_BOOLEAN_WORDS):
                parsed.failure = "unrecognised"
                break
            options.append((f"--{key}", value if equals else None, len(remain)))
            index += 1
            continue
        typed = key in _NOPT_STRING or key in _NOPT_VALUE
        if short or not (typed or (equals and _SCOPED_REGISTRY_KEY.fullmatch(key))):
            parsed.failure = "unrecognised"
            break
        if not equals:
            value = following or ""
        if not _nopt_value(key, value, bool(equals)):
            parsed.failure = "unrecognised"
            break
        options.append((f"--{key}", value, len(remain)))
        index += 1 if equals else 2
    parsed.unread = words[index:]
    return parsed


_PNPM_DLX = _table(
    "-s --silent --reporter-hide-prefix",
    "--package --allow-build --reporter --registry --store-dir --cache-dir",
    value_patterns=(_SCOPED_REGISTRY,),
    dashed_values=False,
    nopt_booleans=True,
)
_YARN_DLX = _table("-q --quiet", "-p --package")
_BUNX = _table("--bun --silent --verbose --no-install", "-p --package")
_UV_GLOBAL = (
    "-q --quiet -v --verbose --offline --no-cache -n --native-tls --no-config --no-progress"
    " --no-env-file --refresh -U --upgrade --reinstall --no-build --no-sources --preview"
    " --compile-bytecode --no-python-downloads --no-managed-python --managed-python --isolated",
    "--cache-dir --directory --project --config-file --color --python-preference"
    " --allow-insecure-host --index --default-index --index-url -i --extra-index-url"
    " --find-links -f --index-strategy --keyring-provider --resolution --prerelease"
    " --exclude-newer --refresh-package --reinstall-package --upgrade-package -P"
    " --link-mode --config-setting -C --python -p --env-file",
)
_UV_GLOBAL_TABLE = _table(*_UV_GLOBAL)
_UV_TOOL_RUN = _table(
    _UV_GLOBAL[0],
    _UV_GLOBAL[1] + " --from --with --with-editable --with-requirements --constraints"
    " --overrides --build-constraints",
)
_UV_RUN = _table(
    _UV_GLOBAL[0] + " --no-project --no-sync --frozen --locked --all-extras --no-dev"
    " --only-dev --all-groups --no-default-groups --active --script -s --module -m"
    " --gui-script --no-editable --exact --all-packages",
    _UV_GLOBAL[1] + " --with --with-editable --with-requirements --extra --group --no-group"
    " --only-group --package",
)
_UV_SOURCE = frozenset(
    {
        "--index",
        "--default-index",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--allow-insecure-host",
        "--config-file",
        "--cache-dir",
    }
)
_UV_LOCATION = frozenset({"--directory", "--project"})
# uv tool run options that name local files that change what is installed.
_UV_TOOL_PATHS = frozenset(
    {
        "--with-editable",
        "--with-requirements",
        "--constraints",
        "--overrides",
        "--build-constraints",
    }
)
_PIPX_RUN = _table(
    "--no-cache --pypackages --path --system-site-packages -e --editable -v --verbose -q"
    " --quiet --fetch-missing-python --global",
    "--spec --python --pip-args -i --index-url --backend",
)
# pip install options (pip's optparse accepts any unique prefix of a long option).
# True marks an option that takes a value; sources redirect or replace the download.
_PIP_LONG = {
    **dict.fromkeys(
        _set(
            "index-url extra-index-url find-links trusted-host proxy cert client-cert constraint"
            " requirement editable cache-dir only-binary no-binary upgrade-strategy platform"
            " python-version implementation abi root prefix target src exists-action timeout"
            " retries progress-bar config-settings global-option keyring-provider log report"
            " root-user-action use-feature use-deprecated python group resume-retries"
        ),
        True,
    ),
    **dict.fromkeys(
        _set(
            "no-index pre no-deps no-cache-dir upgrade force-reinstall ignore-installed"
            " ignore-requires-python no-build-isolation use-pep517 no-use-pep517 prefer-binary"
            " require-hashes isolated quiet verbose disable-pip-version-check no-color user"
            " no-warn-script-location no-warn-conflicts no-compile compile check-build-dependencies"
            " break-system-packages no-input require-virtualenv dry-run debug no-clean"
        ),
        False,
    ),
}
_PIP_SHORT_VALUES = frozenset("ifcret")
_PIP_SHORT_FLAGS = frozenset("qvUI")
_PIP_SOURCE = frozenset(
    {
        "index-url",
        "extra-index-url",
        "find-links",
        "trusted-host",
        "proxy",
        "cert",
        "client-cert",
        "constraint",
        "requirement",
        "editable",
        "cache-dir",
        "no-index",
    }
)
_PIP_SHORT_NAMES = {"i": "index-url", "f": "find-links", "c": "constraint", "r": "requirement"}
_DOCKER_FLAGS = (
    "-d --detach --disable-content-trust --init -i --interactive --no-healthcheck"
    " --oom-kill-disable --privileged -P --publish-all -q --quiet --read-only --rm"
    " --sig-proxy -t --tty --use-api-socket"
)
_DOCKER_VALUES = (
    "-a --attach --add-host --annotation --blkio-weight --blkio-weight-device --cap-add"
    " --cap-drop --cgroup-parent --cgroupns --cidfile --cpu-period --cpu-quota"
    " --cpu-rt-period --cpu-rt-runtime -c --cpu-shares --cpus --cpuset-cpus --cpuset-mems"
    " --device --device-cgroup-rule --device-read-bps --device-read-iops --device-write-bps"
    " --device-write-iops --dns --dns-option --dns-search --domainname --entrypoint -e --env"
    " --env-file --expose --gpus --group-add --health-cmd --health-interval --health-retries"
    " --health-start-interval --health-start-period --health-timeout -h --hostname --ip --ip6"
    " --ipc --isolation --kernel-memory -l --label --label-file --link --link-local-ip"
    " --log-driver --log-opt --mac-address -m --memory --memory-reservation --memory-swap"
    " --memory-swappiness --mount --name --network --net --network-alias --net-alias"
    " --oom-score-adj --pid --pids-limit --platform -p --publish --pull --restart --runtime"
    " --security-opt --shm-size --stop-signal --stop-timeout --storage-opt --sysctl --tmpfs"
    " --ulimit -u --user --userns --uts -v --volume --volume-driver --volumes-from -w --workdir"
)
_CONTAINER_RUN = {
    "docker": _table(_DOCKER_FLAGS, _DOCKER_VALUES, combined=True, boolean_values=True),
    "podman": _table(
        _DOCKER_FLAGS + " --replace --rmi --env-host --passwd --read-only-tmpfs --no-hosts"
        " --rootfs --unsetenv-all --tls-verify --http-proxy",
        _DOCKER_VALUES + " --pod --secret --uidmap --gidmap --subuidname --subgidname --arch"
        " --os --variant --authfile --cert-dir --creds --decryption-key --image-volume"
        " --passwd-entry --group-entry --personality --preserve-fds --requires --sdnotify"
        " --seccomp-policy --timeout --tz --umask --unsetenv --chrootdirs --detach-keys"
        " --env-merge --hostuser --pidfile --systemd --retry --retry-delay",
        combined=True,
        boolean_values=True,
    ),
    "nerdctl": _table(
        _DOCKER_FLAGS + " --insecure-registry",
        _DOCKER_VALUES + " --namespace --snapshotter --cosign-key --verify",
        combined=True,
        boolean_values=True,
    ),
}
_CONTAINER_GLOBAL = {
    "docker": _table(
        "-D --debug --tls --tlsverify",
        "-c --context -H --host --config -l --log-level --tlscacert --tlscert --tlskey",
    ),
    "podman": _table(
        "-r --remote --syslog",
        "--url --connection -c --identity --root --runroot --storage-driver --storage-opt"
        " --cgroup-manager --events-backend --log-level --tmpdir --runtime --module",
    ),
    "nerdctl": _table(
        "--debug --debug-full --insecure-registry --experimental",
        "-n --namespace -a -H --address --snapshotter --storage-driver --cni-path"
        " --data-root --hosts-dir --host-gateway-ip --cgroup-manager",
    ),
}
_DENO_RUN = _table(
    "-A --allow-all -q --quiet --no-check --no-lock --frozen --cached-only --no-remote"
    " --no-npm --no-config --no-prompt --unstable -R -W -N -E -S -P",
    "-c --config --import-map --cert --location --seed --ext --preload --require",
    flag_patterns=(
        r"--(?:allow|deny)-[a-z-]+",
        r"--unstable-[a-z-]+",
        r"--unsafely-ignore-certificate-errors",
        r"--(?:reload|lock|node-modules-dir|env-file|inspect|inspect-brk|inspect-wait"
        r"|allow-scripts|check|watch|watch-hmr|v8-flags|frozen|cached-only)",
        r"-[rRWNES]",  # Reload and permission short options accept an attached =value.
    ),
)
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish"})
_EXTRA_RUNNER_SHELLS = frozenset({"csh", "tcsh", "busybox", "toybox"})
# bash's long options, which it also reads after a single dash: -rcfile is --rcfile.
_BASH_LONG_OPTIONS = _set(
    "debug debugger dump-po-strings dump-strings help init-file login noediting noprofile"
    " norc posix pretty-print protected rcfile restricted verbose version wordexp"
)
_SHELL_STARTUP_FILES = frozenset({"rcfile", "init-file"})
_AMBIGUOUS_SHELL = "shell options before the script are ambiguous"
# bash sources the named file before the script when it runs interactively, and also, as
# for rshd, when its standard input is a socket, which is how Node-based MCP clients start
# servers. A function or alias defined there replaces any program the script names.
_STARTUP_FILE = "shell options name a startup file the shell runs before the script"
# fish reads its options with getopt "+hPilNnvc:C:p:d:f:D:o:" and unique long prefixes.
_FISH_FLAG_RUN = re.compile("[hPilNnv]*")
_FISH_VALUES = frozenset("cCpdfDo")
_FISH_LONG = {
    "command": ("c", True),
    "init-command": ("C", True),
    "features": ("f", True),
    "debug": ("d", True),
    "debug-output": ("o", True),
    "debug-stack-frames": ("D", True),
    "profile": ("p", True),
    "profile-startup": ("p", True),
    "interactive": ("i", False),
    "login": ("l", False),
    "no-config": ("N", False),
    "no-execute": ("n", False),
    "private": ("P", False),
    "print-rusage-self": ("", False),
    "print-debug-categories": ("", False),
    "help": ("h", False),
    "version": ("v", False),
}
_INTERPRETERS = frozenset(
    {"cmd", "powershell", "pwsh", "wsl", "env", "exec", "nohup", "java", *_INLINE_FLAGS}
)
_INJECTORS = frozenset({"op", "doppler", "infisical", "dotenvx", "aws-vault", "with-secrets"})
# Injectors that add variables the inventory cannot read (files, secret stores).
_ENVIRONMENT_INJECTORS = frozenset({"doppler", "infisical", "dotenvx", "with-secrets"})
_WRAPPERS = frozenset({"cmd", "powershell", "pwsh", "wsl", "env"})
# Package runners this grammar does not classify: always unknown, or when one of
# these subcommands follows the name and its options.
_UNCLASSIFIED_RUNNERS: dict[str, frozenset[str] | None] = {
    "dnx": None,
    "jbang": None,
    "pip-run": None,
    "nix-shell": None,
    "corepack": None,
    "mise": None,
    "rtx": None,
    "pkgx": None,
    "finch": None,
    "dx": None,
    "dotnet": frozenset({"dnx", "tool"}),
    # RubyGems reads i as install and any unique prefix of a command name.
    "gem": _set("exec ex exe install i in ins inst insta instal update up upd upda updat"),
    # Installers fetch an attacker-chosen package and run its build code.
    "pip": frozenset({"install", "download", "wheel"}),
    "pip3": frozenset({"install", "download", "wheel"}),
    "cargo": frozenset({"install"}),
    "conda": frozenset({"install", "create", "update", "env"}),
    "mamba": frozenset({"install", "create", "update", "env"}),
    "micromamba": frozenset({"install", "create", "update", "env"}),
    "nix": frozenset({"run", "shell", "develop"}),
    "pixi": frozenset({"exec"}),
    "container": frozenset({"run", "create", "start", "exec", "build"}),
    "apptainer": frozenset({"run", "exec", "shell", "instance", "build", "test"}),
    "singularity": frozenset({"run", "exec", "shell", "instance", "build", "test"}),
}
# pip2, pip3.12 and pip3.11 are pip as installed for one interpreter version.
_VERSIONED_PIP = re.compile(r"pip\d+(?:\.\d+)*")


def _runner_key(name: str) -> str:
    """The runner table entry a program name stands for."""
    if name not in _UNCLASSIFIED_RUNNERS and _VERSIONED_PIP.fullmatch(name):
        return "pip"
    return name


_ENV_OPTIONS = _set(
    "- -- -i -u -S -C -0 -v --ignore-environment --unset --chdir --split-string --null"
    " --debug --block-signal --default-signal --ignore-signal"
)
# Characters env -S gives a meaning a shell reading would not (escapes, quotes,
# expansion, comments) and whitespace other than space and tab.
_ENV_SPLIT_SPECIAL = re.compile(r"[\\'\"$#\v\f]")
# Each env -S value is spliced back into the words, so the reads are bounded: a value
# that splits into another -S would otherwise cost quadratic time in its length.
MAX_SPLIT_STRINGS = MAX_WRAPPERS
# GNU env reads any operand with an = after a non-empty name as an assignment.
_ENV_ASSIGNMENT = re.compile(r"[^=]+=", re.S)
MAX_SCAN_WORDS = 4096


class _ScanLimitError(Exception):
    """The argument scan spent its linear work budget."""


class _UnreadableExpansionError(Exception):
    """Braces nest deeper than the expansion reader follows."""


def _charge(budget: list[int] | None, units: int) -> None:
    if budget is not None:
        budget[0] -= units
        if budget[0] < 0:
            raise _ScanLimitError


def _spend(budget: list[int] | None, word: str = "") -> None:
    """Charge one step, plus one per 64 characters the step may examine."""
    _charge(budget, 1 + len(word) // 64)


def _draw(budget: list[int], allowance: list[int], units: int) -> None:
    """Charge ``units`` to a word's own allowance first, then to the shared budget."""
    taken = min(allowance[0], units)
    allowance[0] -= taken
    _charge(budget, units - taken)


def _interpreter_family(name: str) -> str | None:
    if name in {"node", "nodejs"} or name in _NODE_RUNNERS:
        return "node"
    if name in _TS_NODE:
        return "ts-node"
    if _PYTHON_NAME.fullmatch(name):
        return "python"
    if name in _INLINE_FLAGS:
        return name
    versioned = _VERSIONED_INTERPRETER.fullmatch(name)
    if versioned is not None:
        base = versioned.group(1)
        return "lua" if base == "luajit" else base
    return None


def _program_name(word: str) -> str | None:
    """The runner, shell, wrapper or interpreter a word names by basename, if any.

    A version suffix (``pnpm@9.15.0``, as corepack reads it) and an ``npm:`` or
    ``jsr:`` prefix (as Deno reads it) do not change the program a word names.
    """
    name = normalize_command(word)
    bare = name.split(":", 1)[1] if name.startswith(("npm:", "jsr:")) else name
    unversioned = bare.partition("@")[0] if not bare.startswith("@") else bare
    for candidate in (name, _SCRIPT_SUFFIX.sub("", name), unversioned):
        family = _interpreter_family(candidate)
        if family is not None:
            return family
        if candidate in _PROGRAM_NAMES:
            return candidate
        if _runner_key(candidate) in _PROGRAM_NAMES:
            return _runner_key(candidate)
    return None


def _shell_script(
    name: str,
    words: list[str],
    start: int,
    budget: list[int] | None = None,
    launch: Launch | None = None,
) -> tuple[str | None, list[str], str | None]:
    """The inline script a shell started with ``words[start:]`` runs.

    Returns the script, the words after it and None; (None, [], None) for a script
    file or standard input; or (None, [], reason) when the options do not establish
    the script. Shells read every option word before the script, so ``-c -- x``,
    ``-c -e x`` and ``-co posix x`` all run ``x``.
    """
    if name == "fish":
        return _fish_script(words, start, budget)
    index = start
    inline = False
    interactive = False
    xtrace = False
    while index < len(words):
        word = words[index]
        _spend(budget, word)
        if word[:1] not in {"-", "+"}:
            break
        index += 1
        if word in {"-", "--"}:
            break
        if word == "+":
            # zsh reads a lone "+" as the end of options, other shells as an empty option.
            return None, [], _AMBIGUOUS_SHELL
        option = word.lstrip("-").partition("=")[0]
        if word.startswith("--") or (word[0] == "-" and option in _BASH_LONG_OPTIONS):
            if option in _SHELL_STARTUP_FILES:
                return None, [], _STARTUP_FILE
            if not word.startswith("--"):
                # bash reads -login as --login; other shells read the letters l o g i n.
                return None, [], _AMBIGUOUS_SHELL
            if name == "zsh":
                # zsh sets any option in GNU long form (--xtrace), ignoring case, - and _.
                setting = option.replace("-", "").replace("_", "").lower()
                interactive = interactive or setting == "interactive"
                xtrace = xtrace or setting == "xtrace"
            continue
        letters = word[1:]
        inline = inline or "c" in letters
        interactive = interactive or (word[0] == "-" and "i" in letters)
        xtrace = xtrace or (word[0] == "-" and "x" in letters)
        valued = "oO" if name == "bash" else "o"
        takes = sum(letters.count(letter) for letter in valued)
        if takes:
            # Each o takes the next word in bash and dash; zsh reads a value
            # attached to -o instead, so only a final o reads the same everywhere.
            if takes > 1 or letters[-1] not in valued:
                return None, [], _AMBIGUOUS_SHELL
            if word[0] == "-" and letters[-1] == "o" and index < len(words):
                # dash, ksh and mksh take -o interactive; any shell -o xtrace.
                setting = words[index].lower()
                interactive = interactive or _names_option(setting, "interactive")
                xtrace = xtrace or _names_option(setting, "xtrace")
            index += 1
        if ("O" in letters and name != "bash") or (
            name in {"ksh", "mksh"} and ("R" in letters or "T" in letters)
        ):
            return None, [], _AMBIGUOUS_SHELL
        if name == "zsh" and "b" in letters:
            break
    if launch is not None:
        launch.interactive = launch.interactive or interactive
        launch.xtrace = launch.xtrace or xtrace
    if not inline:
        return None, [], None
    if index >= len(words):
        return None, [], "shell -c without a script"
    return words[index], words[index + 1 :], None


def _names_option(setting: str, option: str) -> bool:
    """Whether an -o value names ``option``: ksh accepts abbreviations, zsh ignores ``_``."""
    setting = setting.replace("_", "")
    return len(setting) >= 3 and option.startswith(setting)


def _fish_script(
    words: list[str], start: int, budget: list[int] | None
) -> tuple[str | None, list[str], str | None]:
    """fish's -c/--command value; -C/--init-command runs code before it and is unknown."""
    script: str | None = None
    index = start
    while index < len(words):
        word = words[index]
        _spend(budget, word)
        if not word.startswith("-") or word == "-":
            break
        index += 1
        if word == "--":
            break
        pairs: list[tuple[str, str]] = []
        if word.startswith("--"):
            given, equals, value = word[2:].partition("=")
            matches = [option for option in _FISH_LONG if option.startswith(given)]
            option = given if given in _FISH_LONG else (matches[0] if len(matches) == 1 else "")
            if not option:
                return None, [], "unrecognised fish option"
            letter, takes = _FISH_LONG[option]
            if takes and not equals:
                if index >= len(words):
                    return None, [], "unrecognised fish option"
                value, index = words[index], index + 1
            pairs.append((letter, value))
        else:
            letters = word[1:]
            position = _FISH_FLAG_RUN.match(letters).end()  # type: ignore[union-attr]
            if position < len(letters):
                letter = letters[position]
                if letter not in _FISH_VALUES:
                    return None, [], "unrecognised fish option"
                value = letters[position + 1 :]
                if not value:
                    if index >= len(words):
                        return None, [], "unrecognised fish option"
                    value, index = words[index], index + 1
                pairs.append((letter, value))
        for letter, value in pairs:
            if letter == "C":
                return None, [], "fish init command runs a script"
            if letter == "c":
                if script is not None:
                    return None, [], "fish runs more than one command"
                script = value
    if script is None:
        return None, [], None
    return script, words[index:], None


_CMD_SWITCHES = r"(?:/[a-z](?::\w+)?)*"
_CMD_SWITCH = re.compile(r"/[a-z](?::\w+)?", re.IGNORECASE)
# /C, /K and /R run the rest of the line, which may start right after the switch.
_CMD_RUN = re.compile(rf"({_CMD_SWITCHES})/[ckr](.*)", re.IGNORECASE | re.DOTALL)


def _cmd_runs(words: list[str], start: int) -> bool:
    """Whether cmd started with ``words[start:]`` runs a command line."""
    leading = True
    for word in words[start : start + 8]:
        found = _CMD_RUN.fullmatch(word)
        if found is not None and (leading or not found.group(2)):
            return True
        leading = leading and bool(_CMD_SWITCH.fullmatch(word))
    return False


@dataclass(frozen=True)
class _Starts:
    """When a runner name followed by more words in an argument list starts code.

    The runner's options before its subcommand are skipped. An option the table
    does not know is a flag or takes the next word; both readings are checked,
    unless the runner rejects unknown options (``strict``). ``starts`` decides
    whether a subcommand word starts code; ``inline`` options run code by themselves.
    """

    options: _Options
    starts: Callable[[str], bool]
    strict: bool = False
    inline: frozenset[str] = frozenset()


def _subcommands(words: list[str], start: int, grammar: _Starts, budget: list[int] | None) -> bool:
    """Whether a word a runner may read as its subcommand starts code."""
    table = grammar.options
    inline = {option[1] for option in grammar.inline if len(option) == 2}
    index = start
    while index < len(words):
        word = words[index]
        _spend(budget, word)
        if word == "--":
            if index + 1 >= len(words):
                return False
            _spend(budget, words[index + 1])
            return grammar.starts(words[index + 1])
        if not word.startswith("-") or word == "-":
            return grammar.starts(word)
        name, equals, _ = word.partition("=")
        if name in grammar.inline or (
            not word.startswith("--") and not inline.isdisjoint(name[1:])
        ):
            return True
        if name in table.values or any(p.fullmatch(name) for p in table.value_patterns):
            index += 1 if equals else 2
        elif name in table.flags or any(p.fullmatch(name) for p in table.flag_patterns):
            index += 1
        elif not word.startswith("--") and len(word) > 2 and _letters_known(word, table):
            index += 2 if word[-1:] and f"-{word[-1]}" in table.values else 1
        elif grammar.strict:
            return False
        elif equals:
            index += 1
        else:
            following = words[index + 1] if index + 1 < len(words) else ""
            _spend(budget, following)
            if following[:1] not in {"", "-"} and grammar.starts(following):
                return True
            index += 2 if following[:1] not in {"", "-"} else 1
    return False


def _letters_known(word: str, table: _Options) -> bool:
    """A cluster of short options the table knows, such as ``-Dl`` for ``-D -l``."""
    letters = word[1:]
    return (
        bool(letters)
        and table.short_flags.issuperset(letters[:-1])
        and (letters[-1] in table.short_flags or letters[-1] in table.short_values)
    )


_Walks = dict[int, frozenset[str]]
_RUNNER_STARTS = frozenset().union(*filter(None, _UNCLASSIFIED_RUNNERS.values()))


def _launches(
    name: str,
    words: list[str],
    start: int,
    budget: list[int] | None = None,
    walks: _Walks | None = None,
) -> bool:
    """Whether ``name`` followed by ``words[start:]`` can start a program."""
    if start >= len(words):
        return False
    first = words[start]
    option = first.partition("=")[0]
    if name in _SHELLS:
        script, _, problem = _shell_script(name, words, start, budget)
        return script is not None or problem is not None
    if name in _EXTRA_RUNNER_SHELLS:
        return True
    if name == "cmd":
        return _cmd_runs(words, start)
    if name in {"powershell", "pwsh"}:
        return first[:1] in {"-", "/"} and not first.startswith("--")
    if name == "env":
        return (
            option in _ENV_OPTIONS or first.startswith("-S") or bool(_ENV_ASSIGNMENT.match(first))
        )
    grammar = _STARTS.get(name)
    if grammar is not None:
        return _subcommands(words, start, grammar, budget)
    unclassified = _UNCLASSIFIED_RUNNERS.get(name)
    if unclassified is not None:
        # Their options are not tabled and may take several values (nix --option
        # name value), so any of the next words naming a start counts, and so does
        # one after any run of options each followed by at most one value.
        return any(word in unclassified for word in words[start : start + 8]) or (
            _leading_start(words, start, unclassified, budget, walks)
        )
    return True


def _leading_start(
    words: list[str],
    start: int,
    starts: frozenset[str],
    budget: list[int] | None,
    walks: _Walks | None = None,
) -> bool:
    """Whether a start word follows options that may each take the next word as a value.

    The run an option word begins does not depend on where the walk began or on the
    runner, so ``walks`` keeps, for each option position of one word list, the start
    words its run reaches. Each position is walked once, keeping a scan of many
    runner names linear.
    """
    if walks is None:
        walks = {}
    after_option = False
    passed: list[tuple[int, str]] = []
    reached: frozenset[str] = frozenset()
    for index in range(start, len(words)):
        word = words[index]
        if word.startswith("-") and index in walks:
            reached = walks[index]
            break
        _spend(budget, word)
        passed.append((index, word))
        if word.startswith("-"):
            after_option = "=" not in word
        elif after_option:
            after_option = False
        else:
            break
    for index, word in reversed(passed):
        if word in _RUNNER_STARTS:
            reached |= {word}
        if word.startswith("-"):
            walks[index] = reached
    return not reached.isdisjoint(starts)


def _interpreter_reason(
    family: str,
    words: list[str],
    launch: Launch | None = None,
    budget: list[int] | None = None,
    start: int = 0,
) -> str | None:
    """Inline code, or a package runner run as a module, among an interpreter's options."""
    debugger_flags: set[str] = set()
    index = start
    while index < len(words):
        word = words[index]
        _spend(budget, word)
        if word == "--" or not word.startswith("-"):
            if family in _INLINE_FLAGS and not _script_like(word):
                index += 1
                continue
            return None
        option, equals, value = word.partition("=")
        follows = words[index + 1] if index + 1 < len(words) else ""
        step = 1
        if family in {"node", "ts-node"}:
            norm = "--" + option[2:].replace("_", "-") if option.startswith("--") else option
            target = value if equals else follows
            if norm in _NODE_INLINE or (
                norm in _NODE_PRELOAD and target.lower().startswith(_INLINE_SOURCES)
            ):
                return _inline(family, launch)
            if norm in _NODE_PRELOAD and launch is not None:
                launch.mark("preload_module")
            negated = _NODE_DEBUGGER_NEGATIONS.get(norm)
            if family == "ts-node" and (
                norm in _NODE_DEBUGGERS or negated or norm in _NODE_DEBUG_PORTS
            ):
                return "direct ts-node arguments do not accept Node inspector flags"
            if launch is not None and (norm in _NODE_DEBUGGERS or negated):
                if negated:
                    debugger_flags.discard(negated)
                else:
                    # Starting with a break/wait also enables the inspector. Negating
                    # either switch later clears only its own flag.
                    debugger_flags.update(("--inspect", norm))
                if debugger_flags:
                    launch.context["debugger_enabled"] = 1
                else:
                    launch.context.pop("debugger_enabled", None)
            takes = norm in _NODE_VALUES or (
                family == "ts-node" and (option in _TS_NODE_VALUES or norm in _TS_NODE_VALUES)
            )
            step = 2 if takes and not equals else 1
        elif family == "python":
            if word == "-":
                return _inline(family, launch)
            if word.startswith("--"):
                step = 2 if word == "--check-hash-based-pycs" else 1
            else:
                letters = word[1:]
                found = _PYTHON_SPECIAL.search(letters)
                letter = found.group() if found is not None else ""
                position = found.start() if found is not None else 0
                if letter == "c":
                    return _inline(family, launch)
                if letter == "m":
                    module = letters[position + 1 :] or follows
                    name = module.split(".")[0].replace("_", "-").casefold()
                    mod_args = words[index + (1 if letters[position + 1 :] else 2) :]
                    if name in _PYTHON_CODE_MODULES or (
                        name == "pdb" and _pdb_runs_commands(mod_args)
                    ):
                        return _inline(family, launch)
                    return f"python -m {name}" if name in _PROGRAM_NAMES else None
                if letter in {"W", "X"}:
                    step = 2 if position + 1 == len(letters) else 1
        elif word == "-" or _INLINE_FLAGS[family].fullmatch(word):
            # `-` reads the script from standard input, as it does for node and python.
            return _inline(family, launch)
        elif option in _INLINE_VALUES[family] and not equals:
            step = 2
        index += step
    return None


def _inline(family: str, launch: Launch | None) -> str:
    if launch is not None:
        launch.mark("inline_code")
    return f"inline {family} code"


def _embedded_reason(words: list[str], stop: int | None = None) -> str | None:
    """A package runner, shell, wrapper or inline interpreter code that a word starts.

    Work is linear: every nested option scan spends from one budget proportional to
    the number of words and characters, each step is charged for the characters it
    may examine, and an exhausted budget is a failure, not a pass.
    """
    total = len(words) + sum(
        len(word.split()) for word in words if any(char.isspace() for char in word)
    )
    if total > MAX_SCAN_WORDS * 16:
        return "arguments exceed the launcher scan limit"
    characters = sum(len(word) for word in words)
    budget = [4 * total + characters // 16 + 256]
    try:
        return _scan_words(words, len(words) if stop is None else stop, budget)
    except _ScanLimitError:
        return "arguments exceed the launcher scan limit"


def _scan_words(words: list[str], stop: int, budget: list[int]) -> str | None:
    walks: _Walks = {}
    for index in range(min(stop, len(words))):
        word = words[index]
        _spend(budget, word)
        if word.startswith("-"):
            _, equals, word = word.partition("=")
            if not equals:
                continue
        if _OPAQUE.search(word):
            return "arguments contain shell syntax that can start a program"
        if any(char.isspace() for char in word):
            # A command line a shell reads again: as written, and with its quoting removed.
            for parts in _command_line_readings(word):
                reason = _scan_words(parts, len(parts), budget)
                if reason is not None:
                    return reason
            continue
        readings = _rewritten(word, budget) if _REWRITABLE.search(word) else [[word]]
        if readings is None:
            return "arguments contain an expansion too large to read"
        for reading in readings:
            if len(reading) == 1:
                reason = _starts_code(reading[0], words, index + 1, budget, walks)
            else:
                # Brace expansion made several words; the copy is charged, so many such
                # readings exhaust the budget instead of costing the square of the input.
                budget[0] -= len(words) - index
                if budget[0] < 0:
                    raise _ScanLimitError
                reason = _starts_code(reading[0], [*reading, *words[index + 1 :]], 1, budget)
            if reason is not None:
                return reason
    return None


def _command_line_readings(text: str) -> list[list[str]]:
    readings = [text.split()]
    if _QUOTING.search(text):
        try:
            unquoted = shlex.split(text, posix=True)
        except ValueError:
            unquoted = text.replace("'", " ").replace('"', " ").replace("\\", "").split()
        if unquoted != readings[0]:
            readings.append(unquoted)
    return readings


def _starts_code(
    word: str, words: list[str], start: int, budget: list[int], walks: _Walks | None = None
) -> str | None:
    """What ``word`` followed by ``words[start:]`` starts, if it names a program that may."""
    for name in _program_names(word, budget):
        if name in {"node", "ts-node", "python"} or name in _INLINE_FLAGS:
            found = _interpreter_reason(name, words, budget=budget, start=start)
            if found is not None:
                return f"arguments run {found}"
        elif _launches(name, words, start, budget, walks):
            return f"arguments start {name}"
    return None


def _program_names(word: str, budget: list[int] | None = None) -> list[str]:
    """Programs a word names exactly, or that a pattern or open expansion in it may name."""
    exact = _program_name(word)
    if exact is not None or not any(char in word for char in "*?\x00"):
        return [exact] if exact is not None else []
    base = normalize_command(word.replace("\x00", "*"))
    base = base.split("@", 1)[0] if not base.startswith("@") else base
    for suffix in _EXECUTABLE_SUFFIXES:
        base = base.removesuffix(suffix)
    if not any(char.isalnum() for char in base):
        # A bare pattern such as * or ** names files, not a program the pattern spells.
        return []
    base = _STARS.sub("*", base)
    width = _pattern_width(base, _LONGEST_PROGRAM)
    if width > _LONGEST_PROGRAM:
        # Every character but * matches one, so no program name is long enough; compiling
        # a pattern from the whole word cost seconds and gigabytes for a few megabytes.
        return []
    _charge(budget, 1)
    # The literal text before the first and after the last wildcard bounds the names a
    # pattern can match, so most patterns are settled without compiling one.
    first = _WILDCARD.search(base)
    head = base if first is None else base[: first.start()]
    tail = base[max(base.rfind(char) for char in "*?[]") + 1 :]
    starred = "*" in base
    candidates = [
        name
        for name in _VOCABULARY
        if (len(name) >= width if starred else len(name) == width)
        and name.startswith(head)
        and name.endswith(tail)
    ]
    if not candidates:
        return []
    pattern = _pattern(base, budget)
    found: list[str] = []
    for name in candidates:
        if pattern.fullmatch(name):
            program = _program_name(name)
            if program is not None and program not in found:
                found.append(program)
    return found


_STARS = re.compile(r"\*+")
_WILDCARD = re.compile(r"[*?\[\]]")
_PATTERNS: dict[str, re.Pattern[str]] = {}
_PATTERN_CACHE = 1024


def _pattern(text: str, budget: list[int] | None) -> re.Pattern[str]:
    """The compiled pattern; short patterns are kept.

    Every use is charged as a compile, so that the budget, and whether a scan runs out
    of it, never depends on which patterns earlier scans left in the cache.
    """
    # Compiling costs about what reading 2 KB of words does.
    _charge(budget, 32 + len(text) // 16)
    found = _PATTERNS.get(text)
    if found is None:
        found = re.compile(fnmatch.translate(text))
        if len(text) <= 2 * _LONGEST_PROGRAM + 2:
            if len(_PATTERNS) >= _PATTERN_CACHE:
                _PATTERNS.clear()
            _PATTERNS[text] = found
    return found


_NOT_STAR = re.compile(r"[^*]")


def _pattern_width(pattern: str, enough: int) -> int:
    """The fewest characters ``pattern`` matches as fnmatch reads it, counted past ``enough``.

    A * matches none, and ?, a character or a closed [...] exactly one, so this is a
    lower bound on the length of anything the pattern matches.
    """
    width = 0
    found = _NOT_STAR.search(pattern)
    while found is not None and width <= enough:
        width += 1
        index = found.end()
        if found.group() == "[":
            close = index
            if close < len(pattern) and pattern[close] == "!":
                close += 1
            if close < len(pattern) and pattern[close] == "]":
                close += 1
            close = pattern.find("]", close)
            if close >= 0:
                index = close + 1
        found = _NOT_STAR.search(pattern, index)
    return width


# A word holding one of these is read the ways a shell or cmd may read it.
_REWRITABLE = re.compile(r"[{}*?\[\]'\"\\$%!^@;,=]")
# Shell syntax whose result cannot be read: command substitution and $'...' or $"..." strings.
_OPAQUE = re.compile(r"\$\(|`|\$'|\$\"")
_BRACKET = re.compile(r"\[!?\^?\]?(?:\[:[a-z]+:\]|[^\]])*\]")
_CMD_VARIABLE = re.compile(r"%[^%\s]*%|![^!\s]*!")
_PLAIN_VARIABLE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
_SEQUENCE = re.compile(r"(-?\d{1,3}|[A-Za-z])\.\.(-?\d{1,3}|[A-Za-z])")
MAX_READINGS = 64
# Default operands nested deeper than this make a word unreadable rather than read in part.
MAX_EXPANSION_DEPTH = 8
# Braces open at once deeper than this make a word unreadable.
MAX_BRACE_DEPTH = 256
_EXPANSION_SYNTAX = re.compile(r"\$\{|\}")
_BRACE_SYNTAX = re.compile(r"[{},]")
# The longest text a {x..y} sequence can hold: -999..-999.
_MAX_SEQUENCE_TEXT = 10


def _rewritten(word: str, budget: list[int]) -> list[list[str]] | None:
    """The word sequences a shell or cmd may make of ``word``, the word itself first.

    Quoting is removed; cmd's leading @ ; , = and ^ escapes are dropped; %VAR% and
    !VAR! are empty or anything; a parameter expansion is empty, anything, or its
    default operand; brace lists and sequences become separate words; a pattern stays a
    pattern, which the program vocabulary is matched against. None when the readings
    would exceed MAX_READINGS or the word nests expansions deeper than the reader follows.
    """
    readings = [word]
    for variant in (
        re.sub(r"['\"\\]", "", word),
        re.sub(r"\^", "", word.lstrip("@;,=")).replace("'", "").replace('"', ""),
    ):
        if variant not in readings:
            readings.append(variant)
    # A brace list's items are searched and expanded in each reading, so the commas inside
    # a word's braces pay for that word's own reading, and for no other word's.
    first_open, last_close = word.find("{"), word.rfind("}")
    commas = word.count(",", first_open, last_close) if 0 <= first_open < last_close else 0
    allowance = [4 * min(commas, MAX_READINGS + 1)]
    expanded: dict[str, None] = {}
    for reading in readings:
        _draw(budget, allowance, 1 + len(reading) // 64)
        if not _variables(reading, budget, expanded, allowance):
            return None
    sequences: dict[tuple[str, ...], None] = {}
    for reading in expanded:
        words = _braces(_brackets(reading), budget, allowance)
        if words is None:
            return None
        sequences[tuple(words)] = None
        if len(sequences) > MAX_READINGS:
            return None
    return [list(words) for words in sequences]


def _brackets(text: str) -> str:
    """``text`` with each bracket expression read as one character, ``?``.

    A bracket expression ends at a ``]``, so none starts after the last one. Matching
    only up to it keeps every attempt to one that succeeds, in linear time, instead of
    one failed scan to the end of the word for each ``[`` after it.
    """
    end = text.rfind("]") + 1
    return _BRACKET.sub("?", text[:end]) + text[end:]


def _variables(text: str, budget: list[int], kept: dict[str, None], allowance: list[int]) -> bool:
    """Keep each reading of ``text`` with its expansions empty, anything (NUL) or default.

    Each new reading is charged for its characters as it is kept, and readings are made
    one at a time, so a long word with many expansions exhausts the budget instead of
    holding MAX_READINGS copies of itself. False when the kept readings exceed
    MAX_READINGS or default operands nest deeper than MAX_EXPANSION_DEPTH.
    """
    results = [text]
    for pattern in (_CMD_VARIABLE, _PLAIN_VARIABLE):
        results = [
            variant
            for result in results
            for variant in (pattern.sub("", result), pattern.sub("\x00", result))
        ]
    for result in results:
        parsed = _expansions(result, budget)
        if parsed is None:
            return False
        for reading in _readings(*parsed, MAX_READINGS + 1):
            if reading not in kept:
                _draw(budget, allowance, 1 + len(reading) // 64)
                kept[reading] = None
                if len(kept) > MAX_READINGS:
                    return False
    return True


def _parameters(text: str, limit: int, budget: list[int], depth: int = 0) -> list[str] | None:
    """The first ``limit`` readings of ``text`` with each ${...} empty, anything or its default.

    None when default operands nest deeper than MAX_EXPANSION_DEPTH.
    """
    parsed = _expansions(text, budget, depth)
    return None if parsed is None else list(_readings(*parsed, limit))


def _expansions(
    text: str, budget: list[int], depth: int = 0
) -> tuple[list[str], list[list[str]], str] | None:
    """The text between the ${...} of ``text``, the choices for each, and the text after.

    One pass finds the expansions, each charged to ``budget``. A choice is empty,
    anything (NUL) or the first readings of the default operand. None when default
    operands nest deeper than MAX_EXPANSION_DEPTH.
    """
    if depth > MAX_EXPANSION_DEPTH:
        return None
    pieces: list[str] = []
    choices: list[list[str]] = []
    position = 0
    while True:
        start = text.find("${", position)
        end = _expansion_end(text, start) if start >= 0 else -1
        if end < 0:
            break
        _spend(budget)
        inner = text[start + 2 : end]
        found = re.match(r"[A-Za-z_][A-Za-z0-9_]*(:?[-=+?])(.*)", inner, re.DOTALL)
        replaced = re.match(r"[A-Za-z_][A-Za-z0-9_]*/[/#%]?[^/]*/(.*)", inner, re.DOTALL)
        operand: str | None = None
        if found is not None and found.group(1)[-1] in "-=+":
            operand = found.group(2)
        elif replaced is not None:
            # ${NAME/pattern/text} may become text, or a value holding it.
            operand = replaced.group(1)
        options = ["", "\x00"]
        if operand is not None:
            nested = _parameters(operand, 4, budget, depth + 1)
            if nested is None:
                return None
            options.extend(nested)
        pieces.append(text[position:start])
        choices.append(options)
        position = end + 1
    return pieces, choices, text[position:]


def _readings(pieces: list[str], choices: list[list[str]], tail: str, limit: int) -> Iterator[str]:
    """The first ``limit`` readings, the first expansion varying slowest, made one by one."""
    if not choices:
        yield "".join(pieces) + tail
        return
    total = 1
    for options in choices:
        total = min(total * len(options), limit)
    # Only the last expansions vary among the first ``total`` readings; each earlier one
    # takes its first choice in all of them, so that text is joined once.
    varying = 0
    span = 1
    while span < total:
        varying += 1
        span *= len(choices[-varying])
    fixed = len(choices) - varying
    head = "".join(
        piece + options[0] for piece, options in zip(pieces[:fixed], choices[:fixed], strict=True)
    )
    for index in range(total):
        picked: list[str] = []
        for options in reversed(choices[fixed:]):
            index, digit = divmod(index, len(options))
            picked.append(options[digit])
        picked.reverse()
        varied = "".join(part for pair in zip(pieces[fixed:], picked, strict=True) for part in pair)
        yield head + varied + tail


def _expansion_end(text: str, start: int) -> int:
    """The index of the } that closes the ${ at ``start``, or -1."""
    depth = 0
    for match in _EXPANSION_SYNTAX.finditer(text, start):
        if match.group() == "}":
            depth -= 1
            if depth == 0:
                return match.start()
        else:
            depth += 1
    return -1


def _braces(text: str, budget: list[int], allowance: list[int]) -> list[str] | None:
    """The words bash brace expansion makes of ``text``; None past MAX_READINGS.

    A round searches only the words the previous round made. Each search is charged
    for the brace syntax it reads and each expansion for the characters it would make,
    before it makes them, so a word that keeps expanding exhausts the budget instead of
    costing its length for each of up to MAX_READINGS words in each round.
    """
    words: list[tuple[str, bool]] = [(text, False)]
    for _ in range(MAX_READINGS):
        changed: list[tuple[str, bool]] = []
        expanded = False
        for word, done in words:
            if done:
                changed.append((word, True))
                continue
            try:
                group = _brace_group(word, budget, allowance)
            except _UnreadableExpansionError:
                return None
            if group is None:
                changed.append((word, True))
                continue
            expanded = True
            start, end, items = group
            if len(changed) + len(items) > MAX_READINGS:
                return None
            outside = len(word) - (end + 1 - start)
            _draw(budget, allowance, (len(items) * outside + sum(map(len, items))) // 64)
            prefix, suffix = word[:start], word[end + 1 :]
            changed.extend((prefix + item + suffix, False) for item in items)
        words = changed
        if not expanded:
            return [word for word, _ in words]
    return None


def _brace_group(
    word: str, budget: list[int], allowance: list[int]
) -> tuple[int, int, list[str]] | None:
    """The first {a,b} or {x..y} group of a word, with its items, in one pass.

    Each { is paired with the } that closes it; a pair is a group when a comma sits
    directly inside it or it holds a sequence, and the group that opens first wins. The
    pass is charged for the brace syntax it reads, and braces open more than
    MAX_BRACE_DEPTH deep make the word unreadable.
    """
    first_open, last_close = word.find("{"), word.rfind("}")
    if first_open < 0 or last_close < first_open:
        # No { has a } after it: no group, and nothing to read or charge.
        return None
    opens: list[int] = []
    commas: list[bool] = []
    first: tuple[int, int] | None = None
    read = 0
    for match in _BRACE_SYNTAX.finditer(word, first_open, last_close + 1):
        read += 1
        index = match.start()
        char = match.group()
        if char == "{":
            if len(opens) >= MAX_BRACE_DEPTH:
                raise _UnreadableExpansionError
            opens.append(index)
            commas.append(False)
        elif not opens:
            continue
        elif char == ",":
            commas[-1] = True
        else:
            start = opens.pop()
            comma = commas.pop()
            if first is not None and first[0] < start:
                continue
            if comma or (
                index - start - 1 <= _MAX_SEQUENCE_TEXT
                and _brace_items(word[start + 1 : index]) is not None
            ):
                first = (start, index)
    _draw(budget, allowance, 1 + read // 64)
    if first is None:
        return None
    start, end = first
    items = _brace_items(word[start + 1 : end])
    return None if items is None else (start, end, items)


def _brace_items(inner: str, limit: int = MAX_READINGS + 1) -> list[str] | None:
    """The items of a {x..y} sequence or {a,b} list; None when ``inner`` is neither.

    A list stops at ``limit`` items: more than MAX_READINGS make the word unreadable
    anyway, and building every one cost the item count times the word's length.
    """
    sequence = _SEQUENCE.fullmatch(inner)
    if sequence is not None:
        first, last = sequence.groups()
        if first.lstrip("-").isdigit() and last.lstrip("-").isdigit():
            low, high = int(first), int(last)
            step = 1 if high >= low else -1
            if abs(high - low) >= MAX_READINGS:
                return [str(low), str(high)] * MAX_READINGS
            return [str(value) for value in range(low, high + step, step)]
        if first.isalpha() and last.isalpha():
            low, high = ord(first), ord(last)
            step = 1 if high >= low else -1
            return [chr(value) for value in range(low, high + step, step)]
        return None
    items: list[str] = []
    depth = 0
    start = 0
    for match in _BRACE_SYNTAX.finditer(inner):
        char = match.group()
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif depth == 0:
            items.append(inner[start : match.start()])
            start = match.end()
            if len(items) >= limit:
                return items
    if not items:
        return None
    items.append(inner[start:])
    return items


def _program_reason(name: str, rest: list[str], launch: Launch) -> str | None:
    """Why a program and its arguments may start code the inventory cannot place."""
    family = _interpreter_family(name)
    if family is not None:
        reason = _interpreter_reason(family, rest, launch)
        if reason is not None:
            return reason
    return _embedded_reason(rest)


def _start(words: list[str], launch: Launch, *, package_entry: bool = False) -> None:
    """A program a runner starts by name: record it and check what it starts in turn."""
    launch.executable = normalize_command(words[0])
    family = _interpreter_family(launch.executable)
    reason = _interpreter_reason(family, words[1:], launch) if family else None
    # What the words start in turn is the more specific reason, so it is named first.
    reason = reason or _embedded_reason(words)
    if reason is None and package_entry:
        if re.search(r"[\\/]", words[0]) or words[0].startswith("."):
            reason = "runner command is a path, not a package entry point"
        elif family is not None:
            reason = f"runner starts {family} instead of a package entry point"
        elif launch.executable in (_SHELLS | _INJECTORS | _WRAPPERS | _EXTRA_RUNNER_SHELLS):
            reason = f"runner starts {launch.executable} instead of a package entry point"
    if reason is not None:
        launch.fail(reason)


def _program_arguments(words: list[str], launch: Launch) -> None:
    """Arguments a runner passes to a package or image; they must not start another one."""
    reason = _embedded_reason(words)
    if reason is not None:
        launch.fail(reason)


def _package_program(package: Package, words: list[str], launch: Launch) -> None:
    """A package started by its default program, which runners name after the package."""
    implied = package.name.rsplit("/", 1)[-1] if package.name else ""
    norm = normalize_command(implied) if implied else ""
    if norm and norm in (_SHELLS | _INJECTORS | _WRAPPERS | _EXTRA_RUNNER_SHELLS):
        launch.fail(f"runner starts {norm} instead of a package entry point")
        return
    _program_arguments([implied, *words] if implied else words, launch)


def _command_words(command: str, args: list[str]) -> tuple[list[str] | None, str]:
    """Words of a declared command, or why it cannot be read.

    A command without whitespace is one path. A command whose last path segment
    contains whitespace is a command line. Otherwise the whitespace sits inside
    directory names: a client spawning it directly runs the path, one spawning it
    through a shell runs the first word. The path is accepted only when the shell
    reading cannot start anything else.
    """
    stripped = command.strip()
    if stripped[:1] in {'"', "'"}:
        close = stripped.find(stripped[0], 1)
        if close < 0:
            return None, _NOT_SIMPLE
        tail = stripped[close + 1 :]
        if tail[:1] and not tail[0].isspace():
            # A shell joins text after the closing quote to the quoted word: "np"x is npx.
            return None, _NOT_SIMPLE
        words = _split_script(tail) if tail.strip() else []
        return (None, _NOT_SIMPLE) if words is None else ([stripped[1:close], *words], "")
    if not any(char.isspace() for char in stripped):
        return [stripped], ""
    last = re.split(r"[\\/]", stripped)[-1]
    if last == stripped or any(char.isspace() for char in last):
        words = _split_script(stripped)
        return (None, _NOT_SIMPLE) if words is None else (words, "")
    windows = bool(re.match(r"[A-Za-z]:[\\/]", stripped))
    operators = _WINDOWS_PATH_OPERATOR if windows else _POSIX_PATH_OPERATOR
    pieces = stripped.split()
    if (
        operators.search(stripped)
        or expands(stripped)
        or _embedded_reason([*pieces, *args], stop=len(pieces) - 1) is not None
    ):
        return None, "command may be a path with spaces or a command line"
    return [stripped], ""


_NODE_TLS_FAMILIES = frozenset({"npm", "yarn", "bun"})


def node_tls_runtime(launch: Launch) -> bool:
    """Whether the launch runs on Node.js or Bun, which honor NODE_TLS_REJECT_UNAUTHORIZED=0."""
    return launch.family in _NODE_TLS_FAMILIES or (
        launch.executable is not None
        and _interpreter_family(launch.executable) in {"node", "ts-node"}
    )


def node_tls_disabled(launch: Launch, server_env: Mapping[str, object] | None = None) -> bool:
    """Whether the effective launch environment disables Node/Bun TLS verification."""
    if not node_tls_runtime(launch):
        return False
    if launch.node_tls_override is not None:
        return launch.node_tls_override == "0"
    if server_env is None:
        return False
    value = server_env.get("NODE_TLS_REJECT_UNAUTHORIZED")
    return isinstance(value, str) and value == "0"


def analyze(command: str, args: list[str]) -> Launch:
    """Classify a declared command and its arguments, recording no argument value."""
    launch = Launch()
    if not command:
        return launch
    words, problem = _command_words(command, args)
    if words is None:
        launch.command = "[redacted-command]"
        if problem == _NOT_SIMPLE:
            launch.launcher = "shell"
            launch.mark("inline_shell_code")
        else:
            launch.launcher = "unknown"
        launch.fail(problem)
        return launch
    if len(words) > 1:
        launch.wrappers.append("command-line")
    tokens = [*words, *args]
    launch.command = normalize_command(tokens[0])
    for _ in range(MAX_WRAPPERS + 1):
        inner = _unwrap(tokens, launch)
        if launch.unknown is not None:
            return launch
        if inner is None:
            _classify(tokens, launch)
            if node_tls_disabled(launch):
                launch.mark("tls_verification_disabled")
            return launch
        tokens = inner
    launch.fail("wrapper nesting limit")
    return launch


def _unwrap(tokens: list[str], launch: Launch) -> list[str] | None:
    name = normalize_command(tokens[0])
    rest = tokens[1:]
    if name == "env":
        return _unwrap_env(rest, launch)
    if name in _SHELLS:
        return _unwrap_shell(name, rest, launch)
    if name == "cmd":
        return _unwrap_cmd(rest, launch)
    if name in {"powershell", "pwsh"}:
        return _unwrap_powershell(name, rest, launch)
    if name == "wsl":
        return _unwrap_wsl(rest, launch)
    if name in {"exec", "nohup"} and rest:
        command = _exec_operands(name, rest, launch)
        if command is not None:
            launch.wrappers.append(name)
        return command
    if name == "eval":
        # Behind a reader that keeps quoting (wsl, env -S), what eval reads is not established.
        reread = not any(wrapper in {"wsl", "env"} for wrapper in launch.wrappers)
        words = _split_script(" ".join(rest), literal=True) if rest and reread else None
        if words is None:
            launch.launcher = "shell"
            launch.mark("inline_shell_code")
            launch.fail("eval script is not a simple command")
            return None
        launch.wrappers.append("eval")
        return words
    if name in _INJECTORS:
        if "--" not in rest or rest.index("--") + 1 >= len(rest):
            launch.launcher = name
            launch.fail(f"{name} wrapper without '--' before the command")
            return None
        separator = rest.index("--")
        if name in _ENVIRONMENT_INJECTORS or any(
            word.partition("=")[0] == "--env-file" for word in rest[:separator]
        ):
            # Variables from an environment file or secret store are not visible here.
            launch.injected_environment = True
        launch.wrappers.append(name)
        return rest[separator + 1 :]
    return None


def _exec_operands(name: str, rest: list[str], launch: Launch) -> list[str] | None:
    """The command after ``nohup [--]``, or after the shell builtin's ``exec [-cl] [-a name]``."""
    index = 0
    while index < len(rest) and rest[index].startswith("-") and rest[index] != "-":
        word = rest[index]
        index += 1
        if word == "--":
            break
        named = re.fullmatch(r"-[cl]*(a.*)?", word, re.S) if name == "exec" else None
        if named is None:
            launch.fail(f"unrecognised {name} option")
            return None
        flags = word[1 : named.start(1)] if named.group(1) is not None else word[1:]
        if "c" in flags:
            launch.node_tls_override = ""
        if named.group(1) == "a":
            index += 1
    if index >= len(rest):
        launch.fail(f"{name} without a command")
        return None
    return rest[index:]


def _unwrap_env(rest: list[str], launch: Launch) -> list[str] | None:
    index = 0
    while index < len(rest):
        word = rest[index]
        if word in {"-i", "-", "--ignore-environment", "-0", "--null", "-v", "--debug", "--"}:
            if word in {"-i", "-", "--ignore-environment"}:
                launch.node_tls_override = ""
            index += 1
        elif word in {"-u", "-C", "--unset", "--chdir"}:
            target = rest[index + 1] if index + 1 < len(rest) else ""
            if word in {"-C", "--chdir"} and _moves(target):
                launch.relocated = True
            elif word in {"-u", "--unset"} and target == "NODE_TLS_REJECT_UNAUTHORIZED":
                launch.node_tls_override = ""
            index += 2
        elif word.startswith(("--unset=", "--chdir=")):
            if word.startswith("--chdir=") and _moves(word.partition("=")[2]):
                launch.relocated = True
            elif word.partition("=")[2] == "NODE_TLS_REJECT_UNAUTHORIZED":
                launch.node_tls_override = ""
            index += 1
        elif word in {"-S", "--split-string"} or word.startswith(("-S", "--split-string=")):
            if word in {"-S", "--split-string"}:
                if index + 1 >= len(rest):
                    break
                value, skip = rest[index + 1], 2
            elif word.startswith("--split-string="):
                value, skip = word.partition("=")[2], 1
            else:
                value, skip = word[2:], 1
            # env -S has its own grammar: \_ separates words, \c ends the string,
            # ${VAR} expands and # starts a comment. Such a value is not read here.
            launch.split_strings += 1
            if launch.split_strings > MAX_SPLIT_STRINGS:
                launch.launcher = "unknown"
                launch.fail("env -S values nest beyond the collector limit")
                return None
            words = None if _ENV_SPLIT_SPECIAL.search(value) else _split_script(value, literal=True)
            if words is None:
                launch.fail("env -S value is not a simple command")
                return None
            rest = [*words, *rest[index + skip :]]
            index = 0
        elif word.startswith("-"):
            launch.fail("unrecognised env option")
            return None
        elif _ENV_ASSIGNMENT.match(word):
            name, _, value = word.partition("=")
            launch.environment.append((name, value))
            if name == "NODE_TLS_REJECT_UNAUTHORIZED":
                launch.node_tls_override = value
            index += 1
        else:
            launch.wrappers.append("env")
            return rest[index:]
    launch.fail("env without a command")
    return None


def _script_words(words: list[str], launch: Launch) -> list[str] | None:
    while words and _ASSIGNMENT.match(words[0]):
        name, _, value = words[0].partition("=")
        launch.environment.append((name, value))
        if name == "NODE_TLS_REJECT_UNAUTHORIZED":
            launch.node_tls_override = value
        words = words[1:]
    if words and words[0] == "exec":
        return _exec_operands("exec", words[1:], launch)
    return words or None


def _unwrap_shell(name: str, rest: list[str], launch: Launch) -> list[str] | None:
    script, parameters, problem = _shell_script(name, rest, 0, launch=launch)
    if script is None and problem is None:
        # A script file or standard input: the shell runs local code, which the
        # inventory does not read; _classify still checks what its arguments start.
        launch.launcher = "local"
        launch.executable = name
        return None
    launch.launcher = "shell"
    launch.mark("shell_wrapper")
    if script is None:
        launch.mark("inline_shell_code")
        launch.fail(problem or "inline shell script")
        return None
    if parameters and "$" in script:
        # The script reads its positional parameters, which are argument values.
        launch.mark("inline_shell_code")
        launch.fail("inline shell script uses positional parameters")
        return None
    words = _split_script(script, literal=name == "fish")
    words = _script_words(words, launch) if words is not None else None
    if words is None:
        launch.mark("inline_shell_code")
        launch.fail("inline shell script")
        return None
    launch.wrappers.append(f"{name} -c")
    return words


# cmd drops leading @ ; , = from its command word, reads ^ as an escape, expands
# %VAR% (with :~ substrings) and !VAR!, and treats other whitespace as separators.
_CMD_REWRITE = re.compile(r"[%!\"^]|[^\S \t]|[^\x00-\x7f]")
_CMD_PROGRAM = re.compile(r"[A-Za-z0-9_.:\\/-]+")


# cmd keeps backslashes and single quotes; only double quotes group its words.
_CMD_WORD = re.compile(r"[A-Za-z0-9_@%+=:,./\\'-]+")


def _split_cmd(line: str) -> list[str] | None:
    """Words of a cmd command line as cmd separates them; None for anything more."""
    if len(line) > MAX_SCRIPT_CHARS or _CMD_OPERATOR.search(line) or _POSIX_REWRITE.search(line):
        return None
    words = line.split()
    if not 0 < len(words) <= MAX_SCRIPT_TOKENS or not all(
        _CMD_WORD.fullmatch(word) for word in words
    ):
        return None
    return words


def _unwrap_cmd(rest: list[str], launch: Launch) -> list[str] | None:
    """cmd runs the rest of its command line after /C, /K or /R, glued or not."""
    index = 0
    found = None
    while index < len(rest):
        found = _CMD_RUN.fullmatch(rest[index])
        if found is not None:
            break
        if not _CMD_SWITCH.fullmatch(rest[index]):
            launch.launcher = "local"
            launch.executable = "cmd"
            if rest[index].startswith("/") or any(_CMD_RUN.fullmatch(word) for word in rest):
                # Where cmd starts reading its command line is not established.
                launch.fail("cmd switches are not simple")
            return None
        index += 1
    if found is None:
        launch.launcher = "local"
        launch.executable = "cmd"
        return None
    launch.launcher = "shell"
    launch.mark("shell_wrapper")
    glued = found.group(2)
    remainder = [glued, *rest[index + 1 :]] if glued else rest[index + 1 :]
    if len(remainder) == 1 and any(char.isspace() for char in remainder[0]):
        words = _split_cmd(remainder[0])
    elif (
        remainder
        and not any(_CMD_OPERATOR.search(word) for word in remainder)
        and not any(char.isspace() for char in remainder[0])
    ):
        # A first word with spaces among several is quoted or not by the client,
        # so the program cmd runs is not established.
        words = remainder
    else:
        words = None
    if (
        not words
        or not _CMD_PROGRAM.fullmatch(words[0])
        or any(_CMD_REWRITE.search(word) for word in [*remainder, *words])
    ):
        launch.mark("inline_shell_code")
        launch.fail("cmd /c command line is not a simple command")
        return None
    launch.wrappers.append("cmd /c")
    return words


# PowerShell parameters and the shortest prefix of each that names it, as pwsh 7's
# CommandLineParameterParser matches them. A word pwsh does not recognise starts the -File
# path, so it fails closed here; so does -Version and -PSConsoleFile, which pwsh 7 and
# Windows PowerShell 5.1 read differently. CommandWithArgs depends on the edition and
# passes its arguments separately. RemoveWorkingDirectoryTrailingCharacter depends on
# the platform. An executable name alone does not establish those semantics.
_POWERSHELL_PARAMETERS = (
    ("command", "c", "command"),
    ("file", "f", "file"),
    ("encodedcommand", "e", "encoded"),
    ("ec", "e", "encoded"),
    ("encodedarguments", "encodeda", "encoded"),
    ("ea", "ea", "encoded"),
    ("executionpolicy", "ex", "value"),
    ("ep", "ep", "value"),
    ("configurationname", "config", "configuration"),
    ("configurationfile", "configurationfile", "configuration"),
    ("custompipename", "cus", "value"),
    ("settingsfile", "settings", "configuration"),
    ("inputformat", "inp", "value"),
    ("if", "if", "value"),
    ("outputformat", "o", "value"),
    ("of", "o", "value"),
    ("windowstyle", "w", "value"),
    ("workingdirectory", "wo", "directory"),
    ("wd", "wd", "directory"),
    ("noprofile", "nop", "switch"),
    ("noprofileloadtime", "noprofileloadtime", "switch"),
    ("nologo", "nol", "switch"),
    ("noninteractive", "noni", "switch"),
    ("noexit", "noe", "switch"),
    ("interactive", "i", "switch"),
    ("login", "l", "switch"),
    ("mta", "mta", "switch"),
    ("sta", "sta", "switch"),
    ("servermode", "s", "switch"),
    ("socketservermode", "so", "switch"),
    ("namedpipeservermode", "nam", "switch"),
    ("sshservermode", "sshs", "switch"),
    ("help", "h", "switch"),
    ("?", "?", "switch"),
)
# Use the documented format names on Windows PowerShell 5.1. The separate
# -if and -of spellings are verified only for the modern parser.
_WINDOWS_POWERSHELL_NAMES = _set(
    "command file encodedcommand ec encodedarguments ea executionpolicy ep configurationname "
    "inputformat outputformat windowstyle noprofile nologo noninteractive noexit "
    "mta sta help ?"
)
_WINDOWS_POWERSHELL_PARAMETERS = tuple(
    item for item in _POWERSHELL_PARAMETERS if item[0] in _WINDOWS_POWERSHELL_NAMES
)


def _powershell_parameter(word: str, executable: str) -> str | None:
    """The kind of PowerShell parameter a word names; None for none, or several kinds."""
    if word[:1] != "-" or (executable == "powershell" and word.startswith("--")):
        return None
    name = word[2:] if word[1:2] == "-" else word[1:]
    kinds: set[str] = set()
    short: set[str] = set()
    parameters = (
        _WINDOWS_POWERSHELL_PARAMETERS if executable == "powershell" else _POWERSHELL_PARAMETERS
    )
    for full, shortest, kind in parameters:
        if full.startswith(name):
            if len(name) >= len(shortest):
                kinds.add(kind)
            elif len(name) > 1 and kind != "switch":
                short.add(kind)
    # A word too short for a parameter of another kind that takes a value or code (-co,
    # -in) may resolve there in another edition, so it is ambiguous.
    return kinds.pop() if len(kinds) == 1 and short <= kinds else None


def _unwrap_powershell(executable: str, rest: list[str], launch: Launch) -> list[str] | None:
    index = 0
    while index < len(rest):
        kind = _powershell_parameter(rest[index].lower(), executable)
        if kind == "command":
            break
        if kind == "file":
            launch.launcher = "local"
            launch.executable = "powershell"
            if rest[index + 1 : index + 2] == ["-"]:
                # -File - reads the script from standard input, as node - does.
                launch.fail(_inline("powershell", launch))
            return None
        if kind == "configuration":
            # A session configuration or settings file can import modules and run a
            # startup script before the command; the inventory does not read it.
            launch.fail("PowerShell configuration selection is not collected")
            return None
        if kind in {"value", "directory"}:
            if kind == "directory" and index + 1 < len(rest):
                launch.relocated = launch.relocated or _moves(rest[index + 1])
            index += 2
        elif kind == "switch":
            index += 1
        else:
            # Encoded code, a script path or an unmodelled parameter, whose value may be
            # the next word: where PowerShell's command starts is not established.
            index = len(rest)
    launch.launcher = "shell"
    launch.mark("shell_wrapper")
    script = " ".join(rest[index + 1 :])
    if script == "-":
        launch.mark("inline_shell_code")
        launch.fail("PowerShell reads its command from standard input")
        return None
    words = _split_script(script, _POWERSHELL_OPERATOR, literal=True) if script else None
    if words is None:
        launch.mark("inline_shell_code")
        launch.fail("PowerShell command is not a simple command")
        return None
    if words and words[0].casefold() in {"iex", "invoke-expression"}:
        launch.fail(_inline("powershell", launch))
        return None
    launch.wrappers.append("powershell -Command")
    return words


def _unwrap_wsl(rest: list[str], launch: Launch) -> list[str] | None:
    index = 0
    direct = False
    while index < len(rest):
        word = rest[index]
        if word in {"-d", "--distribution", "-u", "--user", "--cd", "--shell-type"}:
            if word == "--cd" and index + 1 < len(rest):
                launch.relocated = launch.relocated or _moves(rest[index + 1])
            index += 2
        elif word in {"-e", "--exec"}:
            direct = True
            index += 1
            break
        elif word in {"--system", "--"}:
            index += 1
            if word == "--":
                break
        elif word.startswith("-"):
            launch.fail("unrecognised wsl option")
            return None
        else:
            break
    words = rest[index:]
    # Without -e, wsl hands its words to a shell as one command line, which reads
    # quoting and expansions again, so every word must read as written.
    if words and not direct:
        # A first word with spaces among several is quoted or not by the client.
        spaced = any(char.isspace() for char in words[0])
        words = [] if spaced else _split_script(" ".join(words), literal=True) or []
    if not words:
        launch.mark("inline_shell_code")
        launch.fail("wsl command line is not a simple command")
        return None
    launch.wrappers.append("wsl")
    return words


def _classify(tokens: list[str], launch: Launch) -> None:
    raw = tokens[0].strip().strip("\"'")
    name = normalize_command(tokens[0])
    rest = tokens[1:]
    launch.executable = name
    if expands(name) or expands(_basename_text(tokens[0])) or not name:
        launch.launcher = "unknown"
        launch.fail("command depends on the environment")
        return
    if raw.startswith(("./", ".\\", "../", "..\\")):
        launch.launcher = "local"
        launch.fail("command is a relative path in the working directory")
        return
    handler = _RUNNERS.get(name)
    if handler is not None:
        launch.runner = True
        handler(name, rest, launch)
        return
    runner = _runner_key(name)
    if runner in _UNCLASSIFIED_RUNNERS and (
        _UNCLASSIFIED_RUNNERS[runner] is None or _launches(runner, tokens, 1)
    ):
        launch.launcher, launch.runner = runner, True
        launch.fail(
            _embedded_reason(rest)
            or f"{runner} runs packages in a form the collector does not classify"
        )
        return
    # A local program: what it runs is local code, unless its arguments start a
    # runner, a shell or inline interpreter code that an unknown wrapper may run.
    launch.launcher = "local"
    reason = _program_reason(name, rest, launch)
    if reason is not None:
        launch.fail(reason)


def _npm_options(options: list[tuple[str, str | None]], launch: Launch) -> bool:
    """Record option sources and code loading; False when an option runs a shell command."""
    for option, value in options:
        if option in {"-c", "--call"}:
            launch.fail(f"{launch.launcher} --call runs a shell command")
            return False
        if option in _NPM_CODE_LOADING:
            launch.mark("code_loading_option")
        elif (option in _NPM_SOURCE or option.endswith(":registry")) and value is not None:
            launch.sources.append((option, value))
    return True


def _package_runner(
    rest: list[str],
    launch: Launch,
    table: _Options,
    package_options: set[str],
    *,
    last_package: bool = False,
) -> None:
    """npx-style grammar: packages from -p/--package, else the first word."""
    scanned = _scan(rest, table)
    if scanned is None:
        launch.fail(f"unrecognised {launch.launcher} option")
        return
    options, position = scanned
    if last_package:
        # bun installs only the package its last -p or --package names.
        named = [pair for pair in options if pair[0] in package_options]
        options = [pair for pair in options if pair[0] not in package_options] + named[-1:]
    _run_packages(options, rest[position:], launch, package_options, through_sh=False)


def _run_packages(
    options: list[tuple[str, str | None]],
    words: list[str],
    launch: Launch,
    package_options: set[str],
    *,
    through_sh: bool,
) -> None:
    if not _npm_options(options, launch):
        return
    specs = [value for option, value in options if option in package_options and value]
    if not specs:
        if not words:
            launch.fail("no package named")
            return
        package = npm_spec(words[0])
        _package_program(package, words[1:], launch)
        launch.packages.append(package)
        return
    if words:
        command: list[str] | None = words
        if through_sh:
            # npm exec hands the command word to sh as a script (@npmcli/run-script) and
            # quotes only the words after it, so that word must be a simple command.
            script = _split_script(words[0])
            command = _script_words(script, launch) if script else None
            if command is not None:
                command = [*command, *words[1:]]
            else:
                launch.mark("inline_shell_code")
                launch.fail(f"{launch.launcher} command is not a simple command")
        if command is not None:
            _start(command, launch, package_entry=True)
            if through_sh and expands(command[0]):
                launch.fail(f"{launch.launcher} command depends on the environment")
    elif through_sh:
        # Without a configured call, npm runs its script shell (sh) on the MCP client's stdin.
        launch.script_shell = True
        launch.fail(f"{launch.launcher} --package without a command runs the script shell")
    launch.packages.extend(npm_spec(spec) for spec in specs)


def _npm_exec(
    options: list[tuple[str, str | None, int]], remain: list[str], launch: Launch
) -> None:
    """npm exec after the port: packages from --package, else the first word."""
    pairs = [(option, value) for option, value, _ in options]
    _run_packages(pairs, remain[1:], launch, {"--package"}, through_sh=True)


def _npx(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "npx", "npm"
    argv = _npx_argv(rest)
    parsed = _nopt(["exec", *argv]) if argv is not None else None
    if parsed is None or parsed.failure is not None:
        launch.fail("unrecognised npx option")
        return
    _npm_exec(parsed.options, parsed.remain, launch)


def _subcommand(
    rest: list[str], table: _Options, launch: Launch
) -> tuple[str, list[str], list[tuple[str, str | None]]] | None:
    scanned = _scan(rest, table)
    if scanned is None or scanned[1] >= len(rest):
        launch.fail(f"unrecognised {launch.launcher} invocation")
        return None
    options, position = scanned
    return rest[position], rest[position + 1 :], options


_NPM_LOCAL = frozenset(
    {"run", "run-script", "rum", "urn", "start", "test", "t", "tst", "restart", "stop"}
)
# Package manager subcommands that fetch packages and may run their install scripts.
_PNPM_FETCHES = _set(
    "dlx create add install i update up upgrade install-test it rebuild rb import env"
    " self-update approve-builds link ln fetch dedupe remove rm uninstall un"
)
_YARN_FETCHES = _set("dlx create add install global up upgrade set plugin import")
# Subcommands that run another one: in one workspace, or in each (pnpm m is pnpm recursive).
_YARN_NESTED = _set("workspace workspaces")
_PNPM_NESTED = _set("recursive multi m")
_BUN_FETCHES = _set("x create c add a install i update upgrade link pm remove rm")


def _local_subcommand(words: list[str], launch: Launch) -> None:
    """A runner subcommand that runs project code; its arguments are still checked."""
    reason = _embedded_reason(words)
    if reason is not None:
        launch.fail(reason)


def _shell_subcommand(words: list[str], launch: Launch) -> None:
    """A runner subcommand that runs its words through a shell as one command line."""
    script = _split_script(" ".join(words)) if words else None
    if script is None:
        launch.mark("inline_shell_code")
        launch.fail(f"{launch.launcher} command line is not a simple command")
        return
    _local_subcommand(script, launch)


# pnpm exec runs its command through a shell with -c or --shell-mode.
_PNPM_SHELL_MODE = re.compile(r"-[A-Za-z]*c[A-Za-z]*|--shell-mode(?:=.*)?", re.S)


def _pnpm_shell_mode(words: list[str]) -> bool:
    """Whether pnpm exec's own options, before its command word, select shell mode."""
    for index, word in enumerate(words):
        if word == "--":
            return False
        if word.startswith("-"):
            if _PNPM_SHELL_MODE.fullmatch(word):
                return True
        elif index == 0 or not words[index - 1].startswith("-") or "=" in words[index - 1]:
            # Not the value of an option before it: the command, whose words pnpm passes on.
            return False
    return False


# Options _npm_options reads, with the length of the shortest abbreviation npm 10.9.9's nopt
# resolves to each once it drops the leading dashes (cache and workspace have none).
_NPM_ABBREVIATED = {
    "script-shell": 3,
    "node-options": 3,
    "shell": 3,
    "registry": 3,
    "userconfig": 5,
    "globalconfig": 7,
    "prefix": 5,
    "cache": 5,
    "workspace": 9,
}
_NPM_SPELLINGS = {
    name[:size]: name
    for name, least in _NPM_ABBREVIATED.items()
    for size in range(least, len(name) + 1)
}
# npm's one-letter shorthands. nopt reads a word made of them as a cluster (-SC is --save
# --prefix) unless it is one of the shorthands dd, ddd and ws.
_NPM_SINGLES = frozenset("?BCDEHLOPSacdfghlmnpqsvwy")
# npm 10.9.9's options whose type allows a string, each with the length of the shortest
# abbreviation nopt resolves to it. Written --no-<name>, or as --browser, which is Boolean too,
# such an option takes a following run of dashes as its value, and nopt reads on.
_NPM_DASH_ABBREVIATED = {
    "_auth": 1,
    "browser": 2,
    "ca": 2,
    "cert": 2,
    "cidr": 2,
    "cpu": 2,
    "diff": 4,
    "key": 1,
    "libc": 3,
    "node-options": 3,
    "noproxy": 3,
    "os": 2,
    "otp": 2,
    "package": 7,
    "replace-registry-host": 3,
    "script-shell": 3,
    "workspace": 9,
}
_NPM_DASH_VALUES = {
    name[:size]: name
    for name, least in _NPM_DASH_ABBREVIATED.items()
    for size in range(least, len(name) + 1)
}


def _npm_takes_dashes(word: str) -> bool:
    """Whether nopt takes a run of dashes after this word as the value of its option."""
    key = word.lstrip("-")
    bare = re.sub("^(?:no-)+", "", key, flags=re.IGNORECASE)
    name = _NPM_DASH_VALUES.get(bare)
    return (
        word.startswith("-")
        and "=" not in word
        and name is not None
        and (bare != key or name == "browser")
    )


def _npm_unread_options(words: list[str]) -> list[tuple[str, str | None]] | None:
    """Those options among words the port did not read, up to the end of npm's options,
    spelled in full; None when an option's name depends on the environment."""
    found: list[tuple[str, str | None]] = []
    for index, word in enumerate(words):
        if re.fullmatch(r"-{2,}", word):
            if index and _npm_takes_dashes(words[index - 1]):
                continue
            break
        if not word.startswith("-"):
            continue
        key, equals, value = word.lstrip("-").partition("=")
        if "${" in key:
            # @npmcli/config replaces ${VAR} in an option's name after nopt has read it.
            return None
        bare = _NPM_SPELLINGS.get(re.sub("^(?:no-)+", "", key, flags=re.IGNORECASE))
        if key in _NPM_SPELLINGS:
            names = [_NPM_SPELLINGS[key]]
        elif bare in {"script-shell", "node-options", "workspace"}:
            # nopt drops any "no-" and still sets these options to the value.
            names = [bare]
        elif key not in {"dd", "ddd", "ws"} and set(key) <= _NPM_SINGLES:
            names = [{"C": "prefix", "w": "workspace"}[c] for c in key if c in "Cw"]
        else:
            names = [key] if _SCOPED_REGISTRY_KEY.fullmatch(key) else []
        # A separate value is read but not skipped, so the next word is checked too.
        following = words[index + 1] if index + 1 < len(words) else ""
        found.extend((f"--{name}", value if equals else following) for name in names)
    return found


def _npm(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "npm", "npm"
    parsed = _nopt(rest)
    options, remain, failure = parsed.options, parsed.remain, parsed.failure
    if not remain:
        launch.fail("unrecognised npm invocation")
        return
    subcommand = remain[0]
    if subcommand in {"exec", "x"}:
        launch.launcher = "npm exec"
        if failure == "late":
            launch.fail("npm exec options after the package without '--'")
        elif failure is not None:
            launch.fail("unrecognised npm exec option")
        else:
            # npm reads its options in any position, so one before the subcommand
            # applies to it as much as one after it.
            _npm_exec(options, remain, launch)
    elif subcommand in _NPM_LOCAL:
        launch.launcher = f"npm {subcommand}"
        # npm reads its options anywhere before their end, also after the script name. Only
        # npm exec reads --call (the port spells -c so), so here it runs nothing.
        found = [(option, value) for option, value, _ in options if option != "--call"]
        unread = _npm_unread_options(parsed.unread)
        if unread is None:
            launch.fail("npm option name depends on the environment")
        elif _npm_options([*found, *unread], launch):
            # The words after the subcommand, as written: a script's own arguments may
            # hold options the port does not model.
            _local_subcommand(parsed.after, launch)
    else:
        launch.fail("npm subcommand fetches or installs packages")


def _pnpm(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "pnpm", "npm"
    if name == "pnpx":
        launch.launcher = "pnpm dlx"
        _package_runner(rest, launch, _PNPM_DLX, {"--package"})
        return
    found = _subcommand(rest, _table(), launch)
    if found is None:
        return
    subcommand, remainder, _ = found
    while subcommand in _PNPM_NESTED:
        # pnpm recursive runs the next command in the directory of each workspace package.
        launch.relocated = True
        found = _subcommand(remainder, _table(), launch)
        if found is None:
            return
        subcommand, remainder, _ = found
    if subcommand == "dlx":
        launch.launcher = "pnpm dlx"
        _package_runner(remainder, launch, _PNPM_DLX, {"--package"})
    elif subcommand in _PNPM_FETCHES:
        launch.fail("pnpm subcommand fetches or installs packages")
    else:
        launch.launcher = f"pnpm {subcommand}" if subcommand in {"exec", "run", "start"} else "pnpm"
        if subcommand == "exec" and _pnpm_shell_mode(remainder):
            _shell_subcommand(remainder, launch)
        else:
            _local_subcommand([subcommand, *remainder], launch)


def _yarn(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "yarn", "yarn"
    found = _subcommand(rest, _table(), launch)
    if found is None:
        return
    subcommand, remainder, _ = found
    while subcommand == "workspace":
        # yarn workspace <name> <command> runs the command in that workspace's directory.
        if len(remainder) < 2 or remainder[1].startswith("-"):
            launch.fail("unrecognised yarn invocation")
            return
        launch.relocated = True
        subcommand, remainder = remainder[1], remainder[2:]
    if subcommand == "workspaces":
        launch.fail("yarn workspaces runs a command in each workspace")
    elif subcommand == "dlx":
        launch.launcher = "yarn dlx"
        _package_runner(remainder, launch, _YARN_DLX, {"-p", "--package"})
    elif subcommand in _YARN_FETCHES:
        launch.fail("yarn subcommand fetches or installs packages")
    elif subcommand == "exec":
        # yarn exec runs its command word as a script in Yarn's portable shell.
        _shell_subcommand(remainder, launch)
    else:
        _local_subcommand([subcommand, *remainder], launch)


def _bun(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "bun", "bun"
    if name == "bunx":
        launch.launcher = "bunx"
        _package_runner(rest, launch, _BUNX, {"-p", "--package"}, last_package=True)
        return
    found = _subcommand(rest, _table("--bun --silent"), launch)
    if found is None:
        return
    subcommand, remainder, _ = found
    if subcommand == "x":
        launch.launcher = "bun x"
        _package_runner(remainder, launch, _BUNX, {"-p", "--package"}, last_package=True)
    elif subcommand in _BUN_FETCHES:
        launch.fail("bun subcommand fetches or installs packages")
    elif subcommand == "exec":
        # bun exec runs its words as a Bun Shell script.
        _shell_subcommand(remainder, launch)
    elif subcommand == "-" or (
        subcommand == "run" and next((w for w in remainder if w == "-" or w[:1] != "-"), "") == "-"
    ):
        # `bun -` and `bun run -` read the script from standard input, as node - does.
        launch.fail(_inline("bun", launch))
    else:
        _local_subcommand([subcommand, *remainder], launch)


def _python_options(options: list[tuple[str, str | None]], launch: Launch) -> None:
    """Index sources, project location and interpreter paths among uv or pipx options."""
    for option, value in options:
        if value is None:
            continue
        if option in _UV_SOURCE:
            launch.sources.append((option, value))
        elif option in _UV_LOCATION:
            launch.relocated = launch.relocated or _moves(value)
        elif option == "--env-file":
            launch.injected_environment = True
        elif option in {"--python", "-p"} and re.search(r"[\\/]", value):
            # An interpreter path runs local code in place of a managed Python.
            launch.mark("code_loading_option")


def _python_runner(
    rest: list[str],
    launch: Launch,
    table: _Options,
    *,
    primary: str | None,
    extras: set[str],
    paths: set[str] | frozenset[str],
    shorthand: bool,
) -> list[tuple[str, str | None]] | None:
    scanned = _scan(rest, table)
    if scanned is None:
        launch.fail(f"unrecognised {launch.launcher} option")
        return None
    options, position = scanned
    _python_options(options, launch)
    declared: str | None = None
    with_specs: list[str] = []
    for option, value in options:
        if value is None:
            continue
        if option == primary:
            declared = value
        elif option in extras:
            with_specs.append(value)
        elif option in paths:
            launch.packages.append(Package("path", value))
    if primary is not None:
        if declared is None and position >= len(rest):
            launch.fail("no package named")
            return None
        if declared is not None:
            launch.packages.insert(0, python_spec(declared))
            if position < len(rest):
                _start(rest[position:], launch, package_entry=True)
        else:
            package = python_spec(rest[position], shorthand=shorthand)
            launch.packages.insert(0, package)
            _package_program(package, rest[position + 1 :], launch)
    elif position < len(rest):
        program = rest[position]
        module_root = program.split(".")[0].replace("_", "-").casefold()
        if any(opt in {"-m", "--module"} for opt, _ in options) and (
            module_root in _PYTHON_CODE_MODULES
            or (module_root == "pdb" and _pdb_runs_commands(rest[position + 1 :]))
        ):
            # The --with packages below are still part of what the launch installs.
            launch.fail(_inline("python", launch))
        elif "://" in program or program == "-":
            # uv run downloads and runs a script named by URL, or reads one from stdin; both
            # are recorded as a URL source, standard input as one without an origin.
            launch.packages.insert(0, Package("url", program, origin=origin(program)))
        else:
            _start(rest[position:], launch)
    launch.packages.extend(python_spec(spec) for spec in with_specs)
    return options


def _uvx(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "uvx", "uv-tool"
    _python_runner(
        rest,
        launch,
        _UV_TOOL_RUN,
        primary="--from",
        extras={"--with"},
        paths=_UV_TOOL_PATHS,
        shorthand=True,
    )


def _uv(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher = "uv"
    found = _subcommand(rest, _UV_GLOBAL_TABLE, launch)
    if found is None:
        return
    subcommand, remainder, options = found
    # Global options given before the subcommand apply to it.
    _python_options(options, launch)
    if subcommand == "tool" and remainder[:1] == ["run"]:
        launch.launcher, launch.family = "uv tool run", "uv-tool"
        _python_runner(
            remainder[1:],
            launch,
            _UV_TOOL_RUN,
            primary="--from",
            extras={"--with"},
            paths=_UV_TOOL_PATHS,
            shorthand=True,
        )
    elif subcommand == "run":
        launch.launcher, launch.family = "uv run", "uv-project"
        _python_runner(
            remainder,
            launch,
            _UV_RUN,
            primary=None,
            extras={"--with"},
            paths={"--with-editable", "--with-requirements"},
            shorthand=False,
        )
    else:
        launch.fail("uv subcommand is not a supported runner")


def _pip_arguments(value: str, launch: Launch) -> None:
    """pip install options inside pipx --pip-args, matched as pip's parser matches them."""
    words = _split_script(value)
    if words is None:
        launch.fail("pipx --pip-args value is not a simple option list")
        return
    index = 0
    while index < len(words):
        word = words[index]
        if word.startswith("--"):
            given, equals, attached = word[2:].partition("=")
            matches = [name for name in _PIP_LONG if name.startswith(given)] if given else []
            name = given if given in _PIP_LONG else (matches[0] if len(matches) == 1 else None)
            if name is None:
                launch.fail("pipx --pip-args option is not recognised")
                return
            if _PIP_LONG[name] and not equals:
                if index + 1 >= len(words):
                    launch.fail("pipx --pip-args option is not recognised")
                    return
                index += 1
                attached = words[index]
        elif word.startswith("-") and len(word) > 1:
            name = None
            for position, letter in enumerate(word[1:], start=2):
                if letter in _PIP_SHORT_FLAGS:
                    continue
                if letter not in _PIP_SHORT_VALUES:
                    launch.fail("pipx --pip-args option is not recognised")
                    return
                name = _PIP_SHORT_NAMES.get(letter, "editable" if letter == "e" else "target")
                attached = word[position:]
                if not attached:
                    if index + 1 >= len(words):
                        launch.fail("pipx --pip-args option is not recognised")
                        return
                    index += 1
                    attached = words[index]
                break
        else:
            launch.fail("pipx --pip-args names a package")
            return
        if name in _PIP_SOURCE:
            launch.sources.append((f"--pip-args --{name}", attached))
        if name in {"requirement", "editable"}:
            # pip installs what the file or directory names into the server's environment,
            # as uvx --with-requirements and --with-editable do.
            launch.packages.append(Package("path", attached))
        elif name == "python":
            # pip re-runs itself under the named interpreter, a path or a file in the
            # working directory.
            launch.mark("code_loading_option")
        index += 1


def _pipx(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "pipx run", "pip"
    if rest[:1] != ["run"]:
        launch.fail("pipx subcommand is not a supported runner")
        return
    options = _python_runner(
        rest[1:],
        launch,
        _PIPX_RUN,
        primary="--spec",
        extras=set(),
        paths=set(),
        shorthand=False,
    )
    if options is None:
        return
    for option, value in options:
        if option == "--pip-args" and value is not None:
            _pip_arguments(value, launch)
        elif option in {"--path", "-e", "--editable"} and launch.packages:
            launch.packages[0] = Package("path", launch.packages[0].spec)


_DANGEROUS_CAPABILITIES = frozenset(
    {"all", "sys_admin", "net_admin", "sys_ptrace", "sys_module", "dac_read_search", "sys_rawio"}
)
_SOCKETS = ("docker.sock", "podman.sock", "containerd.sock", "crio.sock", "docker_engine")
# Directories that hold engine, agent and session-bus sockets (/var/run is /run).
_SOCKET_DIRECTORIES = re.compile(
    r"/(?:var/)?run(?:/(?:user|containerd|podman|docker|dbus|crio|systemd|k3s|lxd|snapd)(?:/.*)?)?"
)
# Engine state: other containers' layers and volumes, and the kubelet's pod secrets.
_ENGINE_STATE = re.compile(r"/var/lib/(?:docker|containers|containerd|kubelet)(?:/.*)?")
# /proc/<pid>/root is that process's root directory, and init's cwd is "/": the host's,
# for a host process.
_PROC_ROOT = re.compile(r"(?:/proc/[^/]+/(?:root|cwd)(?=/|$))+")
# A home directory named by the client or shell, which normpath does not resolve.
_HOME = re.compile(
    r"(?:~|\$\{?home\}?|%userprofile%|\$\{?userprofile\}?|\$\{userhome\}"
    r"|\$\{env:(?:home|userprofile)\})(?=[\\/]|$)",
    re.IGNORECASE,
)
_BROAD = re.compile(
    r"(?:~|\$\{?home\}?|%userprofile%|\$\{?userprofile\}?|\$\{userhome\}"
    r"|\$\{env:(?:home|userprofile)\}"
    r"|/home|/users|/root|/etc|/var|/proc|/sys|/dev|/boot|/usr"
    r"|[a-z]:[\\/]users)(?:[\\/][^\\/]*)?[\\/]?$",
    re.IGNORECASE,
)
_CREDENTIAL_DIRECTORIES = _set(".ssh .aws .gnupg .kube .docker .config .azure .gcloud")
# Client variables for the project directory, which a mount source may climb out of.
_WORKSPACE = re.compile(r"\$\{(?:workspaceFolder|workspaceRoot)\}|\$\{?PWD\}?(?=[\\/]|$)")
# Variables the image's interpreter reads at start, after the digest is checked.
_CONTAINER_CODE_ENVIRONMENT = _set(
    "LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONSTARTUP"
    " PYTHONHOME PERL5OPT PERL5LIB RUBYOPT RUBYLIB JAVA_TOOL_OPTIONS _JAVA_OPTIONS"
    " JDK_JAVA_OPTIONS BASH_ENV ENV SHELLOPTS BASHOPTS PS4 NPM_CONFIG_NODE_OPTIONS"
    " NPM_CONFIG_SCRIPT_SHELL"
)
# Variables that move startup and user-site files into the checkout beside a host mount.
_CONTAINER_HOME_ENVIRONMENT = _set("HOME ZDOTDIR XDG_CONFIG_HOME PYTHONUSERBASE")
# Directories on an image's default PATH; a mount over one replaces the programs it runs.
_CONTAINER_PATH = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


def _mount_parts(spec: str) -> list[tuple[str, str]]:
    # docker reads --mount as one CSV record and lower-cases each key and the type.
    try:
        parts = next(csv.reader([spec]), [])
    except csv.Error:
        parts = spec.split(",")
    return [(key.lower(), value) for key, _, value in (part.partition("=") for part in parts)]


def _mount_fields(spec: str) -> dict[str, str]:
    return dict(_mount_parts(spec))


_VOLUME_VARIABLE = re.compile(
    r"\$\{(?:(?P<client>env|input|config|command|workspaceFolder|extensionInstallFolder):[^{}:]+"
    r"|(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:(?P<operator>:?-)(?P<default>[^{}]*))?)\}"
)
_ANY_VOLUME_VAR = re.compile(r"\$\{[^{}]*\}")


def _has_unresolved_volume_var(text: str) -> bool:
    if "${" not in text:
        return False
    matches = list(_ANY_VOLUME_VAR.finditer(text))
    if len(matches) != text.count("${"):
        return True
    return any(_VOLUME_VARIABLE.fullmatch(match.group()) is None for match in matches)


def _nonempty_volume_variable(variable: re.Match[str]) -> bool:
    """A variable the client or shell resolves to a directory: the workspace, an
    installed extension or the home directory, never the empty string."""
    if variable["client"] is not None:
        return variable["client"] in {"workspaceFolder", "extensionInstallFolder"}
    reference = "${" + variable["name"] + "}"
    return bool(_WORKSPACE.fullmatch(reference) or _HOME.fullmatch(reference))


def _unresolved_mount_fields(spec: str) -> bool:
    """A --mount whose field names or type are substitutions names no readable source."""
    return any(
        "${" in key or (key == "type" and "${" in value) for key, value in _mount_parts(spec)
    )


def _volume_source_end(spec: str) -> int:
    """Find the source separator, accounting for a drive and documented client variables."""
    index = 2 if re.match(r"[A-Za-z]:[\\/]", spec) else 0
    for variable in _VOLUME_VARIABLE.finditer(spec, index):
        colon = spec.find(":", index, variable.start())
        if colon >= 0:
            return colon
        index = variable.end()
    return spec.find(":", index)


def _host_source(spec: str, *, mount: bool, end: int | None = None) -> str | None:
    if mount:
        parts = _mount_parts(spec)
        fields = dict(parts)
        kind = fields.get("type", "volume").lower()
        if kind == "bind":
            return fields.get("source") or fields.get("src") or None
        # The local volume driver with o=bind mounts its device option, a host path.
        driver = {
            key.lower(): value
            for name, option in parts
            if name == "volume-opt"
            for key, _, value in [option.partition("=")]
        }
        binds = {"bind", "rbind"} & set(driver.get("o", "").lower().split(","))
        device = driver.get("device", "")
        local_device = fields.get(
            "volume-driver", "local"
        ).lower() == "local" and device.startswith("/")
        if kind != "volume" or not (binds or local_device):
            return None
        return device or None
    # A client variable such as ${env:HOME} holds a colon of its own.
    if end is None:
        end = _volume_source_end(spec)
    if end < 0:
        return None
    source = spec[:end]
    return (
        source
        if source in {".", ".."}
        or source.startswith(("/", "./", "../", ".\\", "..\\", "~", "$", "%", "\\"))
        or re.match(r"[A-Za-z]:", source)
        else None
    )


def _volume_source_ends(spec: str) -> list[int]:
    """The separator a client-variable reading finds, then the engine's first colon."""
    drive = 2 if re.match(r"[A-Za-z]:[\\/]", spec) else 0
    return list(dict.fromkeys((_volume_source_end(spec), spec.find(":", drive))))


def _host_sources(spec: str, *, mount: bool) -> list[str]:
    """Every host source a mount spec may name, under each reading of its separator."""
    sources: list[str] = []
    if mount:
        source = _host_source(spec, mount=True)
        if source is not None:
            sources.append(source)
    else:
        for end in _volume_source_ends(spec):
            source = _host_source(spec, mount=False, end=end)
            if source is not None:
                sources.append(source)

    def fallback(variable: re.Match[str]) -> str:
        if variable["default"] is not None:
            return variable["default"]
        return "v" if _nonempty_volume_variable(variable) else ""

    def empty(variable: re.Match[str]) -> str:
        # ${X-default} keeps a set but empty X, which only ${X:-default} replaces.
        if variable["operator"] == "-" and not _nonempty_volume_variable(variable):
            return ""
        return fallback(variable)

    for source in list(sources):
        if _VOLUME_VARIABLE.search(source):
            sources.append(_VOLUME_VARIABLE.sub("v", source))
            for reading in (fallback, empty):
                alternative = _VOLUME_VARIABLE.sub(reading, source)
                if alternative:
                    sources.append(alternative)
    return list(dict.fromkeys(sources))


_CREDENTIAL_STORE_MOUNT = re.compile(
    r"/(?:var/)?run/(?:secrets|credentials)(?:/.*)?", re.IGNORECASE
)


def _host_source_flag(source: str) -> str | None:
    """The host root, runtime socket, broad host or credential store mount flag, if any."""
    if _WORKSPACE.match(source):
        source = _WORKSPACE.sub(".", source, count=1)
    normalized = source.rstrip("/\\") or ("/" if source.startswith("/") else "\\")
    # normpath keeps a leading "//", which Linux and Go's filepath.Clean read as "/".
    canonical = (
        posixpath.normpath("/" + normalized.lstrip("/"))
        if normalized.startswith("/") and "\\" not in normalized
        else normalized
    )
    if _PROC_ROOT.match(canonical):
        canonical = _PROC_ROOT.sub("", canonical, count=1) or "/"
    home = _HOME.match(canonical)
    climbs = False
    if home:
        tail = posixpath.normpath(canonical[home.end() :].replace("\\", "/").strip("/") or ".")
        climbs = tail == ".." or tail.startswith("../")
        canonical = home.group() + ("" if tail == "." else "/" + tail)
    if canonical in {"/", "\\"} or re.fullmatch(r"[A-Za-z]:[\\/]?", canonical):
        return "host_root_mount"
    if canonical.lower().endswith(_SOCKETS) or _SOCKET_DIRECTORIES.fullmatch(canonical):
        return "runtime_socket_mount"
    if (
        climbs
        or _BROAD.fullmatch(canonical)
        or _ENGINE_STATE.fullmatch(canonical)
        or canonical.startswith("/proc/")
        or canonical == ".."
        or canonical.startswith(("../", "..\\"))
        or posixpath.normpath(normalized.replace("\\", "/")).startswith("..")
        or (
            not canonical.startswith(".")
            and not _CREDENTIAL_DIRECTORIES.isdisjoint(re.split(r"[\\/]", canonical))
        )
    ):
        return "broad_host_mount"
    if _CREDENTIAL_STORE_MOUNT.fullmatch(canonical):
        return "credential_store_mount"
    return None


def _container_context(options: list[tuple[str, str | None]], launch: Launch) -> None:
    # Docker forwards both the engine socket and client credentials; the last flag wins.
    api_socket = dict(options).get("--use-api-socket", "false")
    if api_socket is None or api_socket.lower() in {"true", "1"}:
        launch.mark("runtime_socket_mount")
        launch.mark("runtime_credentials_forwarded")
    home_environment = False
    search_path: list[str] = []
    for option, value in options:
        text = (value or "").strip().lower()
        if option == "--privileged" and text in {"", "true", "1"}:
            launch.mark("privileged")
        elif option in {"--network", "--net", "--pid", "--ipc", "--uts", "--userns", "--cgroupns"}:
            # ns:<path> joins the namespace at that path, which may be the host's.
            if text == "host" or text.startswith("ns:"):
                launch.mark("host_namespaces")
        elif option == "--cap-add":
            launch.mark("added_capabilities")
            if text.removeprefix("cap_") in _DANGEROUS_CAPABILITIES:
                launch.mark("dangerous_capabilities")
        elif option == "--device":
            launch.mark("devices")
        elif option == "--security-opt" and re.search(
            r"unconfined|disable|no-new-privileges[:=](?:false|0|f)\b", text
        ):
            launch.mark("security_options_disabled")
        elif option == "--security-opt" and re.match(r"seccomp[:=]", text):
            # A profile file, possibly from the checkout, may allow every system call.
            launch.mark("custom_security_profile")
        elif option in {"-e", "--env", "--env-merge"} and value is not None:
            name, equals, assigned = value.partition("=")
            if name.upper().startswith("NPM_CONFIG_"):
                # npm reads a dash and an underscore alike in a configuration name.
                name = name.replace("-", "_")
            # bash in the image imports BASH_FUNC_<name>%% as a function that replaces a program.
            if equals and (
                name.upper() in _CONTAINER_CODE_ENVIRONMENT
                or name.startswith("BASH_FUNC_")
                or assigned.startswith("() {")
            ):
                launch.mark("code_loading_environment")
            home_environment |= bool(equals) and name.upper() in _CONTAINER_HOME_ENVIRONMENT
            if equals and name.upper() == "PATH":
                search_path.extend(assigned.split(":"))
        elif option == "--env-file":
            launch.mark("container_environment_file")
        elif option == "--health-cmd" and text not in {"", "none"}:
            # The engine runs a string health check with /bin/sh -c inside the container.
            launch.mark("container_command")
        elif option in {"-v", "--volume", "--mount"} and value:
            sources = _host_sources(value, mount=option == "--mount")
            if option == "--mount":
                unresolved = _unresolved_mount_fields(value) or any(
                    _has_unresolved_volume_var(source) for source in sources
                )
            else:
                # The host side ends at the separator a client-variable reading finds; a
                # substitution in the container path is the image's concern. An unreadable
                # form is cut at its own colon, so the cut keeps its "${".
                end = _volume_source_end(value)
                unresolved = _has_unresolved_volume_var(value if end < 0 else value[:end])
            if unresolved:
                launch.fail("container volume source substitution is unresolved")
            if sources:
                launch.mark("host_mounts")
            for flag in dict.fromkeys(_host_source_flag(source) for source in sources):
                if flag is not None:
                    launch.mark(flag)
        elif option == "--entrypoint":
            launch.mark("entrypoint_override")
    if launch.context.get("entrypoint_override") and launch.context.get("host_mounts"):
        # The entrypoint may be a script on a host mount, outside the pinned image.
        launch.mark("code_loading_option")
    if home_environment and launch.context.get("host_mounts"):
        launch.mark("code_loading_environment")
    # A relative or empty PATH entry is the working directory, which may be the checkout.
    targets = _mount_targets(options)
    if launch.context.get("host_mounts") and any(
        not entry.startswith("/") or _under(entry, targets) for entry in search_path
    ):
        launch.mark("code_loading_environment")


_CONTAINER_SCRIPT_RUNNERS = re.compile(
    r"node(?:js)?|(?:python|pypy)w?[0-9.]*t?w?(?:d|-dbg)?|pyw?|deno|bun"
    r"|(?:lua(?:jit)?|ruby|perl|php)(?:-?[0-9][-0-9.a-z]*)?"
    r"|(?:ba|da|z|k|mk)?sh|ash|env|java|npm|pnpm|yarn|uv|tsx|ts-node|make|tini|dumb-init|timeout|nice"
)
# Programs that run the command in their arguments; the words after them are still read.
_CONTAINER_WRAPPERS = _set("env tini dumb-init timeout nice")
# Python's flag letters (CPython 3.13 also takes -R and -t), and a cluster of them that ends in
# -m, which imports the module from the working directory, or in -X or -W, whose value is the
# rest of the word or the next word.
_PYTHON_FLAGS = "bBdEiIOPqRsStuvx"
_PYTHON_MODULE = re.compile(rf"-[{_PYTHON_FLAGS}]*m.*", re.S)
_PYTHON_SETTING = re.compile(rf"-([{_PYTHON_FLAGS}]*)[XW](.*)", re.S)
# Package managers that run a project's scripts from the working directory.
_CONTAINER_PACKAGE_RUNNERS = _set("npm pnpm yarn bun uv")
_CONTAINER_PACKAGE_SCRIPTS = _set("run run-script start test")
# A file the image runs as its command; a mounted data or configuration file is not code.
_CONTAINER_SCRIPT_SUFFIX = re.compile(
    r".+\.(?:sh|bash|zsh|js|mjs|cjs|ts|mts|cts|py|rb|pl|php|lua|jar)", re.IGNORECASE
)
# Interpreter options whose separate value is a setting, never a file.
_CONTAINER_SETTING_OPTIONS = frozenset({"-X", "-W"})


def _absolute(path: str) -> str:
    # normpath keeps a leading "//", which Linux reads as "/".
    return posixpath.normpath("/" + path.lstrip("/"))


def _under(path: str, targets: list[str]) -> bool:
    path = _absolute(path)
    return any(path == t or path.startswith(t.rstrip("/") + "/") for t in targets)


def _mount_targets(options: list[tuple[str, str | None]]) -> list[str]:
    """The absolute container targets of host mounts."""
    targets: list[str] = []
    for option, value in options:
        if option not in {"-v", "--volume", "--mount"} or not value:
            continue
        if option == "--mount":
            if _host_source(value, mount=True) is None:
                continue
            fields = _mount_fields(value)
            found = [fields.get("target") or fields.get("dst") or fields.get("destination")]
        else:
            found = [
                value[end + 1 :].split(":", 1)[0]
                for end in _volume_source_ends(value)
                if _host_source(value, mount=False, end=end) is not None
            ]
        targets.extend(_absolute(target) for target in found if target and target.startswith("/"))
    return targets


def _file_like(word: str) -> bool:
    # A port, host, version or dotted module name is not a path; a file name in the working
    # directory counts when it has a script suffix.
    return "/" in word or bool(_CONTAINER_SCRIPT_SUFFIX.fullmatch(word))


def _mounted_command(options: list[tuple[str, str | None]], words: list[str]) -> bool:
    """Whether the command that replaces the image's CMD runs a file from a host mount."""
    targets = _mount_targets(options)
    workdir = ""
    for option, value in options:
        if option in {"-w", "--workdir"} and value:
            workdir = value
    # A mount over a directory on the default PATH, or over one program in it.
    if any(_under(directory, targets) for directory in _CONTAINER_PATH) or any(
        _under(target, list(_CONTAINER_PATH)) for target in targets
    ):
        return True
    if not targets or not words:
        return False

    def mounted(word: str, *, relative: bool = True) -> bool:
        if not word.startswith("/"):
            if not relative or not workdir.startswith("/"):
                return False
            word = posixpath.join(workdir, word)
        return _under(word, targets)

    command = normalize_command(words[0])
    if not _CONTAINER_SCRIPT_RUNNERS.fullmatch(command):
        # A path with no executable suffix is more often a directory or file the server
        # is given than its own command.
        return (
            "/" in words[0]
            and bool(_CONTAINER_SCRIPT_SUFFIX.fullmatch(words[0]))
            and (mounted(words[0]))
        )
    program, at = command, 0
    for index, word in enumerate(words):
        name = normalize_command(word)
        if name not in _CONTAINER_WRAPPERS and _CONTAINER_SCRIPT_RUNNERS.fullmatch(name):
            program, at = name, index
            break
    if mounted(".") and (
        program == "make"
        or (
            program in _CONTAINER_PACKAGE_RUNNERS
            and not _CONTAINER_PACKAGE_SCRIPTS.isdisjoint(words[at + 1 :])
        )
    ):
        return True
    if _PYTHON_NAME.fullmatch(program) and mounted("."):
        # -I and -P keep the working directory off sys.path, but a module run with them can
        # still load it: pdb and cProfile run the file they are given, and uvicorn, gunicorn
        # or fastmcp import the app from the working directory. Any -m counts.
        options_before = iter(words[at + 1 :])
        for word in options_before:
            setting = _PYTHON_SETTING.fullmatch(word)
            if setting or word == "--check-hash-based-pycs":
                if not (setting and setting[2]):
                    next(options_before, None)
            elif not word.startswith("-") or word in {"-", "--"}:
                break
            elif _PYTHON_MODULE.fullmatch(word):
                return True
    rest = iter(words[1:])
    for word in rest:
        if word in _CONTAINER_SETTING_OPTIONS:
            next(rest, None)
            continue
        if word.startswith("-"):
            name, equals, value = word.partition("=")
            if equals and name not in _CONTAINER_SETTING_OPTIONS:
                if mounted(value, relative=_file_like(value)):
                    return True
            continue
        # A relative word counts only when it reads as a file path, not as a value.
        if mounted(word, relative=_file_like(word)):
            return True
    return False


# Global options that point the client at another engine, store or registry configuration.
_CONTAINER_SOURCES = {
    "docker": frozenset({"-c", "--context", "-H", "--host", "--config", "--tlscacert"}),
    "podman": frozenset(
        {"--url", "--connection", "-c", "--identity", "--root", "--runroot", "--module", "-r"}
    ),
    "nerdctl": frozenset(
        {"-a", "-H", "--address", "--data-root", "--hosts-dir", "--insecure-registry"}
    ),
}
_CONTAINER_RUN_SOURCES = frozenset({"--cert-dir", "--insecure-registry"})


def _container(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = name, "oci"
    scanned = _scan(rest, _CONTAINER_GLOBAL[name])
    if scanned is None or scanned[1] >= len(rest):
        launch.fail(f"unrecognised {name} invocation")
        return
    global_options, position = scanned
    launch.sources.extend(
        (option, value or "")
        for option, value in global_options
        if option in _CONTAINER_SOURCES[name]
    )
    if rest[position] == "run":
        run = rest[position + 1 :]
    elif rest[position] == "container" and rest[position + 1 : position + 2] == ["run"]:
        run = rest[position + 2 :]
    else:
        launch.fail(f"{name} subcommand does not start an image")
        return
    launch.launcher = f"{name} run"
    parsed = _scan(run, _CONTAINER_RUN[name])
    if parsed is None or parsed[1] >= len(run):
        launch.fail(f"unrecognised {name} run option")
        return
    options, image = parsed
    _container_context(options, launch)
    entrypoint: list[str] = []
    for option, value in options:
        disabled = (value or "").strip().lower() in {"false", "0"}
        if option in _CONTAINER_RUN_SOURCES or (option == "--tls-verify" and disabled):
            launch.sources.append((option, value or ""))
        elif option == "--entrypoint" and value:
            entrypoint = [value]
    if any(option == "--rootfs" for option, _ in options):
        # The image argument names a local root file system, not an image.
        package = Package("path", run[image])
    else:
        package = oci_spec(run[image])
    launch.packages.append(package)
    if entrypoint or package.name is None:
        _program_arguments([*entrypoint, *run[image + 1 :]], launch)
    else:
        # Without --entrypoint, an interpreter image (node, python, deno) runs its
        # interpreter with the arguments: node@sha256:... -e <code> is inline code.
        _package_program(package, run[image + 1 :], launch)
        if _mounted_command(options, run[image + 1 :]):
            launch.mark("code_loading_option")


_DENO_SUBCOMMANDS = _set(
    "add approve-scripts audit bench cache check clean compile completions coverage deploy doc"
    " fmt info init install jupyter lint lsp outdated publish remove test types uninstall"
    " update upgrade vendor x"
)
_DENO_SOURCES = frozenset({"--import-map", "--cert"})
_DENO_ALL_PERMISSIONS = frozenset({"-A", "--allow-all"})
_DENO_DANGEROUS_PERMISSIONS = frozenset({"-S", "--allow-run", "--allow-ffi", "--allow-sys"})
_DENO_BROAD_PERMISSIONS = frozenset(
    {"-R", "-W", "-N", "-E", "--allow-read", "--allow-write", "--allow-net", "--allow-env"}
)
_DENO_DEBUGGERS = frozenset({"--inspect", "--inspect-brk", "--inspect-wait"})
_DENO_TASK_VALUES = frozenset({"-c", "--config", "--cwd", "-f", "--filter", "-L", "--log-level"})
# A short-option cluster ending in one that takes a value, with the value attached or
# not: clap reads -qc deno.json and -cdeno.json as -c with its value.
_DENO_TASK_CLUSTER = re.compile(r"-[^-cfL]*([cfL])(.*)", re.S)


def _deno_task_eval(rest: list[str], launch: Launch | None = None) -> int | None:
    """The index of deno task's own --eval, among its options before the task word.

    Deno hands every word after the task name to the task, so an --eval there belongs
    to the program the task runs. When ``launch`` is given, explicit configuration and
    working-directory options before the task word are also recorded.
    """
    index = 1
    eval_index: int | None = None
    while index < len(rest) and rest[index].startswith("-") and rest[index] != "--":
        word = rest[index]
        flag, equals, value = word.partition("=")
        cluster = _DENO_TASK_CLUSTER.fullmatch(word)
        if cluster is not None:
            flag, equals, value = "-" + cluster.group(1), cluster.group(2), cluster.group(2)
        if word == "--eval":
            if eval_index is None:
                eval_index = index
            index += 1
            continue
        if flag in {"-c", "--config", "--no-config", "--cwd"}:
            if flag != "--no-config" and not equals and index + 1 < len(rest):
                value = rest[index + 1]
                index += 2
            else:
                index += 1
            if launch is not None:
                launch.fail("explicit Deno configuration selection is not collected")
                if flag == "--cwd":
                    launch.relocated = launch.relocated or _moves(value or "")
                elif flag != "--no-config":
                    directory = re.split(r"[\\/]", value or "")[:-1]
                    # A file at the root of the filesystem or a drive has a directory too.
                    where = "/".join(directory) or ("/" if directory else "")
                    launch.relocated = launch.relocated or _moves(where)
            continue
        index += 2 if flag in _DENO_TASK_VALUES and not equals else 1
    return eval_index


def _deno(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "deno run", "deno"
    if rest[:1] in (["run"], ["serve"]):
        rest = rest[1:]
    elif rest[:1] == ["task"]:
        launch.launcher = "deno task"
        flag = _deno_task_eval(rest)
        if flag is not None:
            # deno task --eval runs the task name as a command line in its task shell.
            _shell_subcommand([*rest[1:flag], *rest[flag + 1 :]], launch)
        _local_subcommand(rest[1:], launch)
        _deno_task_eval(rest, launch)
        return
    elif rest[:1] in (["eval"], ["repl"]):
        launch.fail(_inline("deno", launch))
        return
    elif not rest or rest[0].startswith("-") or rest[0] in _DENO_SUBCOMMANDS:
        launch.fail("deno subcommand is not a supported runner")
        return
    scanned = _scan(rest, _DENO_RUN)
    if scanned is None or scanned[1] >= len(rest):
        launch.fail("unrecognised deno run option")
        return
    options, position = scanned
    if position and rest[position - 1] == "--lock":
        # Deno may take the next word as the lock file, which would make the word after
        # it the script: the recorded package could be a decoy.
        launch.fail("deno --lock is followed by a word that may be its file; write --lock=FILE")
        return
    for option, value in options:
        if option in {"-c", "--config", "--no-config"}:
            # The fixed root resolver view does not resolve an explicitly selected
            # file's precedence or dependencies; a keyed binding cannot cover it.
            launch.fail("explicit Deno configuration selection is not collected")
            # Deno reads .npmrc next to its configuration file.
            directory = re.split(r"[\\/]", value or "")[:-1]
            launch.relocated = launch.relocated or _moves("/".join(directory))
        elif option in _DENO_SOURCES and value is not None:
            launch.sources.append((option, value))
            if option == "--import-map":
                launch.fail("explicit Deno import-map selection is not collected")
        elif option in {"--preload", "--require"}:
            launch.mark("preload_module")
        elif option in _DENO_ALL_PERMISSIONS:
            launch.mark("deno_all_permissions")
        elif option in _DENO_DANGEROUS_PERMISSIONS:
            launch.mark("deno_scoped_host_permissions" if value else "deno_dangerous_permissions")
        elif option in _DENO_BROAD_PERMISSIONS and not value:
            launch.mark("deno_broad_permissions")
        elif option == "--unsafely-ignore-certificate-errors":
            launch.mark("tls_verification_disabled")
        elif option in _DENO_DEBUGGERS:
            launch.mark("debugger_enabled")
        elif option == "--env-file":
            # Deno loads the file before it resolves npm: specifiers, so it may set
            # NPM_CONFIG_REGISTRY or DENO_DIR where the inventory cannot read them.
            launch.injected_environment = True
    script = rest[position]
    if script == "-" or script.lower().startswith(_INLINE_SOURCES[:1]):
        launch.fail(_inline("deno", launch))
        return
    arguments = rest[position + 1 :]
    if script.startswith(("npm:", "jsr:")):
        body = script[4:]
        parts = body.split("/")
        width = 2 if body.startswith("@") else 1
        package = (npm_spec if script.startswith("npm:") else jsr_spec)("/".join(parts[:width]))
        launch.packages.append(package)
        # The package's own program receives the arguments: a bin path after the
        # package, else the program named after it (npm:npm@10 exec ... runs npm).
        program = parts[-1] if len(parts) > width else ""
        if program:
            _program_arguments([program, *arguments], launch)
        else:
            _package_program(package, arguments, launch)
        return
    if "://" in script and not script.lower().startswith("file:"):
        launch.packages.append(Package("url", script, origin=origin(script)))
    elif expands(script):
        launch.fail("deno script depends on the environment")
        return
    _program_arguments(arguments, launch)


def _flags(names: str) -> str:
    return " ".join(f"{prefix}{name}" for name in names.split() for prefix in ("-", "--"))


_GO_RUN = _table(
    _flags("a race msan asan cover v x n work trimpath linkshared modcacherw"),
    _flags(
        "C p covermode coverpkg asmflags buildmode buildvcs compiler gccgoflags gcflags"
        " installsuffix ldflags mod modfile overlay pgo pkgdir tags toolexec exec"
    ),
    boolean_values=True,
)
_GO_VERSION = re.compile(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?")


def go_spec(spec: str) -> Package:
    """``module/path@version``: an exact semantic or pseudo-version is a pin."""
    if not _plain(spec) or spec.count("@") != 1:
        return Package("unknown", spec)
    path, _, version = spec.partition("@")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~/-]*", path):
        return Package("unknown", spec)
    exact = bool(_GO_VERSION.fullmatch(version))
    return Package(
        "golang",
        spec,
        name=path,
        version=version if exact else None,
        pinned=exact,
        pin="version" if exact else None,
    )


def _go(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "go", "go"
    if rest[:1] != ["run"]:
        launch.fail("go subcommand is not a supported runner")
        return
    launch.launcher = "go run"
    scanned = _scan(rest[1:], _GO_RUN)
    if scanned is None or scanned[1] >= len(rest) - 1:
        launch.fail("unrecognised go run option")
        return
    options, position = scanned
    if any(option.lstrip("-") in {"exec", "toolexec", "overlay"} for option, _ in options):
        # A program that wraps the build tools or the built binary is local code, and an
        # overlay replaces the module's source files with local ones.
        launch.mark("code_loading_option")
    target = rest[1 + position]
    if "@" in target:
        launch.packages.append(go_spec(target))
    _program_arguments(rest[2 + position :], launch)


_RUNNERS: dict[str, Callable[[str, list[str], Launch], None]] = {
    "npx": _npx,
    "npm": _npm,
    "pnpm": _pnpm,
    "pnpx": _pnpm,
    "yarn": _yarn,
    # Yarn 1 and corepack install the same program under this name.
    "yarnpkg": _yarn,
    "bunx": _bun,
    "bun": _bun,
    "uvx": _uvx,
    "uv": _uv,
    "pipx": _pipx,
    "docker": _container,
    "podman": _container,
    "nerdctl": _container,
    "deno": _deno,
    "go": _go,
}
# Names whose appearance in an argument, followed by words that make it a launch,
# means a wrapper the grammar does not know may start it.
_PROGRAM_NAMES = (
    frozenset(_RUNNERS)
    | _SHELLS
    | _EXTRA_RUNNER_SHELLS
    | _INJECTORS
    | _WRAPPERS
    | frozenset(_UNCLASSIFIED_RUNNERS)
)

# npm 10 configuration keys (@npmcli/config definitions), by the values they take.
NPM_CONFIG_FLAGS = _set(
    "all allow-same-version audit bin-links commit-hooks description dev diff-ignore-all-space"
    " diff-name-only diff-no-prefix diff-text dry-run engine-strict expect-results force"
    " foreground-scripts format-package-lock fund git-tag-version global global-style if-present"
    " ignore-scripts include-staged include-workspace-root install-links json legacy-bundling"
    " legacy-peer-deps link long offline omit-lockfile-registry-resolved optional package-lock"
    " package-lock-only parseable prefer-dedupe prefer-offline prefer-online production progress"
    " provenance read-only rebuild-bundle save save-bundle save-dev save-exact save-optional"
    " save-peer save-prod shrinkwrap sign-git-commit sign-git-tag strict-peer-deps strict-ssl"
    " timing unicode update-notifier usage version versions workspaces workspaces-update yes"
)
NPM_CONFIG_VALUES = _set(
    "_auth access also audit-level auth-type before ca cache cache-max cache-min cafile call cert"
    " cidr cpu depth diff diff-dst-prefix diff-src-prefix diff-unified editor expect-result-count"
    " fetch-retries fetch-retry-factor fetch-retry-maxtimeout fetch-retry-mintimeout fetch-timeout"
    " git globalconfig heading https-proxy include init-author-email init-author-name"
    " init-author-url init-license init-module init-version init.author.email init.author.name"
    " init.author.url init.license init.module init.version install-strategy key libc"
    " local-address location lockfile-version loglevel logs-dir logs-max maxsockets message"
    " node-options noproxy omit only os otp package pack-destination prefix preid provenance-file"
    " proxy registry replace-registry-host save-prefix sbom-format sbom-type scope script-shell"
    " searchexclude searchlimit searchopts searchstaleness shell tag tag-version-prefix umask"
    " user-agent userconfig viewer which workspace"
)
# Keys whose value may be a flag or a word (browser, color) are left out of both
# tables, so both readings of the next word are checked.
_NPM_OPTIONS = _table(
    " ".join(f"--{key}" for key in NPM_CONFIG_FLAGS) + " -a -B -D -E -f -g -h -H -l -n -O -p -P"
    " -q -s -S -v -y -d -dd -ddd -ws -iwr --no --quiet --silent --verbose --local --porcelain"
    " --readonly --help",
    " ".join(f"--{key}" for key in NPM_CONFIG_VALUES) + " -c -C -L -m -w --reg --desc --enjoy-by",
)
_NPM_COMMANDS = _set(
    "access adduser audit bugs cache ci completion config dedupe deprecate diff dist-tag docs"
    " doctor edit exec explain explore find-dupes fund get help help-search hook init install"
    " install-ci-test install-test link ll login logout ls org outdated owner pack ping pkg"
    " prefix profile prune publish query rebuild repo restart root run-script sbom search set"
    " shrinkwrap star stars start stop team test token uninstall unpublish unstar update"
    " version view whoami"
)
_NPM_ALIASES = {
    **dict.fromkeys(_set("author"), "owner"),
    **dict.fromkeys(_set("home"), "docs"),
    **dict.fromkeys(_set("issues"), "bugs"),
    **dict.fromkeys(_set("info show v"), "view"),
    **dict.fromkeys(_set("find s se"), "search"),
    **dict.fromkeys(_set("add i in ins inst insta instal isnt isnta isntal isntall"), "install"),
    **dict.fromkeys(_set("unlink remove rm r un"), "uninstall"),
    **dict.fromkeys(_set("rb"), "rebuild"),
    **dict.fromkeys(_set("list"), "ls"),
    **dict.fromkeys(_set("ln"), "link"),
    **dict.fromkeys(_set("create innit"), "init"),
    **dict.fromkeys(_set("it"), "install-test"),
    **dict.fromkeys(_set("cit clean-install-test sit"), "install-ci-test"),
    **dict.fromkeys(_set("up upgrade udpate"), "update"),
    **dict.fromkeys(_set("c"), "config"),
    **dict.fromkeys(_set("tst t"), "test"),
    **dict.fromkeys(_set("ddp"), "dedupe"),
    **dict.fromkeys(_set("run rum urn"), "run-script"),
    **dict.fromkeys(_set("clean-install ic install-clean isntall-clean"), "ci"),
    **dict.fromkeys(_set("x"), "exec"),
    **dict.fromkeys(_set("why"), "explain"),
    **dict.fromkeys(_set("la"), "ll"),
    **dict.fromkeys(_set("verison"), "version"),
    **dict.fromkeys(_set("hlep"), "help"),
    **dict.fromkeys(_set("dist-tags"), "dist-tag"),
    **dict.fromkeys(_set("ogr"), "org"),
    **dict.fromkeys(_set("add-user"), "adduser"),
}


def _abbreviations(names: frozenset[str]) -> dict[str, str]:
    """Every unambiguous prefix of each name, as npm's ``abbrev`` computes them."""
    ordered = sorted(names)
    found: dict[str, str] = {}
    for position, name in enumerate(ordered):
        shared = 0
        for neighbour in ordered[max(position - 1, 0) : position + 2]:
            if neighbour != name:
                common = 0
                while common < min(len(name), len(neighbour)) and (
                    name[common] == neighbour[common]
                ):
                    common += 1
                shared = max(shared, common)
        for length in range(shared + 1, len(name) + 1):
            found[name[:length]] = name
        found[name] = name
    return found


_NPM_ABBREVIATIONS = _abbreviations(_NPM_COMMANDS | frozenset(_NPM_ALIASES))


_NPM_LONGEST = max(len(name) for name in _NPM_ABBREVIATIONS)


def npm_command(word: str) -> str | None:
    """The npm command a word names as npm resolves it: alias, typo or unique prefix."""
    if len(word) > _NPM_LONGEST:
        # Converting camelCase only lengthens a word, so no command is that long.
        return None
    if not word.islower():
        word = re.sub(r"[A-Z]", lambda letter: "-" + letter.group().lower(), word)
    if word in _NPM_COMMANDS:
        return word
    if word in _NPM_ALIASES:
        return _NPM_ALIASES[word]
    resolved = _NPM_ABBREVIATIONS.get(word)
    while resolved in _NPM_ALIASES:
        resolved = _NPM_ALIASES[resolved]
    return resolved


# npm commands that fetch and run nothing: project scripts (local code) and queries.
_NPM_QUIET = _set(
    "access adduser bugs cache completion config deprecate diff dist-tag docs doctor explain"
    " find-dupes fund get help help-search hook ll login logout ls org outdated owner pack ping"
    " pkg prefix profile publish query repo restart root run-script sbom search set shrinkwrap"
    " star stars start stop team test token unpublish unstar version view whoami"
)
_SUBCOMMAND = re.compile(r"[a-z][a-z0-9-]*")
# Container engine commands that start no image (plugins such as `docker mcp` may).
_CONTAINER_QUIET = _set(
    "attach commit cp diff events export history images import info inspect kill load login"
    " logout logs pause port ps pull push rename rm rmi save search stats stop tag top unpause"
    " update version wait network volume system context config secret node manifest trust"
    " checkpoint scout sbom help completion mount umount generate healthcheck"
)
# uv and pipx have closed command sets; these commands fetch and run or build
# packages. Their global options change between releases, so an unknown option is
# read both ways instead of ending the check.
_UV_STARTS = _set("run tool pip sync add remove lock export tree build publish format version")
_PIPX_STARTS = _set(
    "run install install-all inject upgrade upgrade-all upgrade-shared reinstall reinstall-all"
    " runpip"
)
_DENO_STARTS = _set("run serve x eval repl install add init jupyter upgrade")


def _deno_starts(word: str) -> bool:
    """A Deno subcommand that runs code, or a script it runs from outside the project."""
    if word in _DENO_STARTS:
        return True
    if word in _DENO_SUBCOMMANDS or word in {"task", "help"}:
        return False
    remote = ("npm:", "jsr:", "http:", "https:", "data:")
    return word == "-" or expands(word) or word.lower().startswith(remote)


def _named(quiet: frozenset[str]) -> Callable[[str], bool]:
    """A subcommand-shaped word other than a quiet one, so engine plugins count."""
    return lambda word: bool(_SUBCOMMAND.fullmatch(word)) and word not in quiet


_STARTS: dict[str, _Starts] = {
    "npm": _Starts(
        _NPM_OPTIONS,
        lambda word: (npm_command(word) or "help") not in _NPM_QUIET,
        inline=frozenset({"-c", "--call"}),
    ),
    "pnpm": _Starts(
        _table(
            "-r --recursive -w --workspace-root -s --silent --stream --parallel"
            " --aggregate-output --color --no-color --use-stderr",
            "-C --dir -F --filter --filter-prod --reporter --loglevel --workspace-concurrency",
        ),
        (_PNPM_FETCHES | _PNPM_NESTED).__contains__,
    ),
    "yarn": _Starts(
        _table("-s --silent --verbose --offline --prefer-offline", "--cwd"),
        (_YARN_FETCHES | _YARN_NESTED).__contains__,
    ),
    "yarnpkg": _Starts(
        _table("-s --silent --verbose --offline --prefer-offline", "--cwd"),
        (_YARN_FETCHES | _YARN_NESTED).__contains__,
    ),
    "bun": _Starts(
        _table(
            "--bun --silent --smol --hot --watch --no-install --verbose --no-clear-screen",
            "-r --preload --cwd -c --config --env-file --tsconfig-override",
        ),
        _BUN_FETCHES.__contains__,
        inline=frozenset({"-e", "--eval", "-p", "--print"}),
    ),
    "deno": _Starts(_DENO_RUN, _deno_starts),
    "docker": _Starts(_CONTAINER_GLOBAL["docker"], _named(_CONTAINER_QUIET), strict=True),
    "podman": _Starts(_CONTAINER_GLOBAL["podman"], _named(_CONTAINER_QUIET), strict=True),
    "nerdctl": _Starts(_CONTAINER_GLOBAL["nerdctl"], _named(_CONTAINER_QUIET), strict=True),
    "uv": _Starts(_UV_GLOBAL_TABLE, _UV_STARTS.__contains__),
    "pipx": _Starts(
        _table("-q --quiet -v --verbose --global --version -h --help"),
        _PIPX_STARTS.__contains__,
    ),
    # go reads only -C before its command and rejects any other option.
    "go": _Starts(_table("", "-C"), _set("run test generate tool").__contains__, strict=True),
}


_VOCABULARY: tuple[str, ...] = tuple(
    sorted(
        {
            *_PROGRAM_NAMES,
            *_INLINE_FLAGS,
            *_NODE_RUNNERS,
            *_TS_NODE,
            "node",
            "nodejs",
            "python",
            "python3",
            "py",
            "pypy3",
        }
    )
)
_LONGEST_PROGRAM = max(len(name) for name in _VOCABULARY)
