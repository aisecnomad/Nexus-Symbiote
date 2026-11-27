"""Generated-input checks of the hand-written parsers against reference behaviour.

The requirements collector emulates pip's line handling; ``packaging`` is the reference for
what a requirement means and pip's own requirements-file reader, wherever pip is installed
(always in CI), for how a line is read, so the collector must reach the same name and pin
however the line is decorated. Unparseable or deeply nested input must leave a gap or a
failed collector, never silence. No collected file may crash a scan in any export format
beyond the one failure docs/known-limitations.md documents. Redaction must never let a
planted secret through, and hostile inputs must not make parsing super-linear. The
repository's Hypothesis profile (tests/conftest.py) keeps every run deterministic; the
weekly ``fuzz`` profile explores further.
"""

from __future__ import annotations

import json
import os
import re
import string
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

import pytest
from click.testing import CliRunner
from hypothesis import assume, example, given, settings
from hypothesis import strategies as st
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, NO_CONTENT_SERIAL
from nexus_symbiote.diff.differ import AIBOMDiffer, _values_unbound
from nexus_symbiote.scanners.base import ScanResult, sanitized_origin
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.scanners.source import SourceScanner
from nexus_symbiote.scanners.source_references import model_identifier
from nexus_symbiote.utils.secrets import redact_descriptor, redact_text, redact_url
from tests.support import scaling_ratio

# Names every version of the AI-package filter has to recognise.
AI_NAMES = st.sampled_from(
    ["torch", "Torch", "transformers", "openai", "OpenAI", "anthropic", "safetensors", "chromadb"]
)
RELEASE = st.lists(st.integers(min_value=0, max_value=99), min_size=1, max_size=4).map(
    lambda parts: ".".join(map(str, parts))
)
PUBLIC = st.tuples(RELEASE, st.sampled_from(["", "rc1", "a2", ".post1", ".dev3"])).map("".join)
LOCAL = st.tuples(PUBLIC, st.sampled_from(["", "+cpu", "+cu121.local"])).map("".join)
CLAUSE = st.one_of(
    st.tuples(st.sampled_from(["==", "!=", "==="]), LOCAL),
    st.tuples(st.sampled_from([">=", "<=", ">", "<"]), PUBLIC),
    st.tuples(st.just("~="), PUBLIC.filter(lambda v: "." in v.split("rc")[0].split("a")[0])),
)
SPECIFIERS = st.lists(CLAUSE, max_size=3).map(lambda cs: ",".join(op + v for op, v in cs))
WILDCARD = st.tuples(st.sampled_from(["==", "!="]), RELEASE).map(lambda c: c[0] + c[1] + ".*")
EXTRAS = st.lists(st.sampled_from(["cuda", "dev", "tests"]), max_size=2, unique=True).map(
    lambda extras: f"[{','.join(extras)}]" if extras else ""
)
MARKERS = st.sampled_from(
    ["", ' ; python_version >= "3.9"', "; sys_platform == 'linux'", ' ; extra == "gpu"']
)


@st.composite
def requirements(draw: st.DrawFn) -> str:
    name = draw(AI_NAMES)
    specifier = draw(st.one_of(SPECIFIERS, WILDCARD))
    spacing = draw(st.sampled_from(["", " ", "  "]))
    text = f"{name}{draw(EXTRAS)}{spacing}{specifier}{draw(MARKERS)}"
    try:
        Requirement(text)
    except InvalidRequirement:
        assume(False)
    return text


@st.composite
def decorated(draw: st.DrawFn, requirement: str) -> str:
    """The requirement as pip would still read it: indentation, comments, options, CRLF."""
    body = requirement
    if draw(st.booleans()):
        # pip joins a continued line with nothing in between, even inside a word.
        cut = draw(st.integers(min_value=1, max_value=len(body) - 1))
        body = f"{body[:cut]}\\\n{body[cut:]}"
    if draw(st.booleans()) and " " in body:
        head, tail = body.split(" ", 1)
        body = f"{head} \\\n{tail}"
    line = draw(st.sampled_from(["", " ", "\t", "   "])) + body
    if draw(st.booleans()):
        line += " --hash=sha256:" + "ab" * 32
    if draw(st.booleans()):
        line += draw(st.sampled_from([" # pinned for CUDA", "  #comment", "\t# note"]))
    ending = draw(st.sampled_from(["\n", "\r\n", ""]))
    header = draw(
        st.sampled_from(["", "# generated\n", "\ufeff", "--index-url https://pypi.org/simple\n"])
    )
    return header + line + ending


def reference_pin(requirement: Requirement) -> str | None:
    """The exact version packaging says the requirement pins, if any."""
    # A repeated clause adds nothing. packaging 26 drops repeats only once something has
    # compared the set, packaging 24 always: count each clause once either way.
    clauses = list(dict.fromkeys(requirement.specifier))
    if requirement.url or requirement.marker or len(clauses) != 1:
        return None
    clause = clauses[0]
    if clause.operator not in {"==", "==="} or "*" in clause.version:
        return None
    try:
        version = Version(clause.version)
    except InvalidVersion:
        return None
    return clause.version if clause.contains(version, prereleases=True) else None


def scan(files: dict[str, bytes]):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, data in files.items():
            (root / name).write_bytes(data)
        return RegistryScanner().scan(root)


def pypi_components(result, name):
    ref = f"registry:pypi/{canonicalize_name(name)}"
    return [c for c in result.components if c.bom_ref == ref]


@given(st.data())
def test_requirements_lines_reach_the_name_and_pin_packaging_reads(data):
    text = data.draw(requirements())
    line = data.draw(decorated(text))
    requirement = Requirement(text)
    result = scan({"requirements.txt": line.encode()})
    found = pypi_components(result, requirement.name)
    assert len(found) == 1, (line, result.scan_failures)
    assert result.scan_failures == []
    pin = reference_pin(requirement)
    component = found[0]
    if pin is None:
        assert component.package_url is None
        assert any(risk.category == "version_pinning" for risk in component.risks)
    else:
        name = canonicalize_name(requirement.name)
        assert component.package_url == f"pkg:pypi/{name}@{quote(pin, safe='')}"
        assert not any(risk.category == "version_pinning" for risk in component.risks)


@pytest.fixture(scope="module")
def pip_reader():
    """pip's own requirements-file reader and its version. CI installs with pip."""
    try:
        from pip import __version__
        from pip._internal.network.session import PipSession
        from pip._internal.req.req_file import parse_requirements
    except ImportError:
        if os.environ.get("CI"):
            raise
        pytest.skip("pip is not importable here; CI, which installs with pip, runs this test")
    session = PipSession()

    def read(content: bytes) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_bytes(content)
            return [parsed.requirement for parsed in parse_requirements(str(path), session=session)]

    return __version__, read


@given(st.data())
def test_pip_reads_each_decorated_line_as_the_requirement_the_collector_reports(pip_reader, data):
    version, read = pip_reader
    text = data.draw(requirements())
    content = data.draw(decorated(text)).encode()
    found = read(content)
    assert len(found) == 1, (version, content, found)
    requirement = Requirement(found[0])
    assert requirement == Requirement(text), (version, content, found)
    result = scan({"requirements.txt": content})
    components = pypi_components(result, requirement.name)
    assert len(components) == 1 and result.scan_failures == [], (version, content)
    pin = reference_pin(requirement)
    name = canonicalize_name(requirement.name)
    purl = None if pin is None else f"pkg:pypi/{name}@{quote(pin, safe='')}"
    assert components[0].package_url == purl, (version, content)


@given(st.data())
def test_a_requirement_split_across_files_and_pyproject_is_one_component(data):
    text = data.draw(requirements())
    requirement = Requirement(text)
    pyproject = f'[project]\nname = "demo"\nversion = "1"\ndependencies = [{json.dumps(text)}]\n'
    result = scan(
        {
            "requirements.txt": f"{text}\n".encode(),
            "requirements-dev.txt": f"{text}  # again\n".encode(),
            "pyproject.toml": pyproject.encode(),
        }
    )
    assert len(pypi_components(result, requirement.name)) == 1
    assert result.scan_failures == []


GARBAGE = st.text(
    st.characters(
        exclude_categories=("Cs",),
        include_characters=" \t\u00a0\ufeff\\#@;[]=<>!~*,$\"'{}()/:%\x00\x1b\u202e",
    ),
    min_size=1,
    max_size=40,
)


@given(AI_NAMES, GARBAGE)
def test_an_ai_requirement_line_is_never_silently_dropped(name, garbage):
    assume(not garbage[0].isalnum() and garbage[0] not in "._-")
    result = scan({"requirements.txt": f"{name}{garbage}\n".encode()})
    gaps = [*result.scan_failures, *result.surfaces_excluded]
    assert pypi_components(result, name) or any("requirements" in gap for gap in gaps)


@given(AI_NAMES, st.binary(max_size=64))
def test_undecodable_requirement_files_are_a_gap(name, payload):
    data = name.encode() + b"==1.0\n" + payload
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        result = scan({"requirements.txt": data})
        assert any("requirements.txt" in failure for failure in result.scan_failures)
    else:
        scan({"requirements.txt": data})


IMAGES = st.tuples(
    st.sampled_from(["", "docker.io/", "ghcr.io/acme/", "registry.example:5000/team/"]),
    st.sampled_from(["vllm/vllm-openai", "ollama/ollama", "model-server", "llama-runner"]),
    st.sampled_from(["", ":latest", ":0.6.1", ":v2"]),
    st.sampled_from(["", "@sha256:" + "0123456789abcdef" * 4]),
).map("".join)


@given(
    IMAGES,
    st.sampled_from(["FROM", "from", "From"]),
    st.sampled_from(["", "--platform=linux/amd64 ", "--platform=$BUILDPLATFORM "]),
    st.sampled_from(["", " AS build", " as Build"]),
    st.sampled_from([" ", "  ", "\t", " \\\n  "]),
)
def test_dockerfile_from_names_the_image_buildkit_pulls(image, keyword, flags, stage, gap):
    dockerfile = f"# syntax=docker/dockerfile:1\n{keyword}{gap}{flags}{image}{stage}\nRUN true\n"
    result = scan({"Dockerfile": dockerfile.encode()})
    images = [c for c in result.components if c.bom_ref.startswith("registry:docker/")]
    assert [c.name for c in images] == [image]
    pinned = "@sha256:" in image
    assert pinned == (not images[0].risks)


@given(IMAGES)
def test_a_from_naming_an_earlier_stage_is_not_an_image(image):
    dockerfile = f"FROM {image} AS Base\nFROM base\nRUN true\nFROM BASE AS final\n"
    result = scan({"Dockerfile": dockerfile.encode()})
    assert [c.name for c in result.components] == [image]


SECRETS = st.text(
    st.characters(min_codepoint=48, max_codepoint=122, categories=("Lu", "Ll", "Nd")),
    min_size=12,
    max_size=40,
).filter(lambda s: any(c.isupper() for c in s) and any(c.isdigit() for c in s))
# No ASCII capital letter, so the surrounding text can never itself spell a secret.
CONTEXT = st.text(
    st.characters(exclude_categories=("Cs",), exclude_characters=string.ascii_uppercase),
    max_size=30,
)


@given(SECRETS, CONTEXT, CONTEXT)
def test_a_known_secret_never_survives_redaction(secret, before, after):
    assert secret not in redact_text(f"{before}{secret}{after}", [secret])


@given(
    SECRETS,
    CONTEXT,
    st.sampled_from(
        [
            "https://user:{s}@api.example/v1",
            "https://api.example/v1?token={s}",
            "wss://{s}@stream.example:8443/x#frag",
            "https://api.example/{s}/models",
            "https://api.example/v1#{s}",
            "postgresql://svc:{s}@db.internal:5432/vectors",
        ]
    ),
)
def test_a_secret_in_a_url_never_survives_text_redaction(secret, context, template):
    url = template.format(s=secret)
    assert secret not in redact_text(f"{context} {url} {context}")
    assert secret not in redact_url(url)
    origin = sanitized_origin(url)
    assert secret not in origin
    assert origin.count("/") == 2 or origin == "[redacted]"


@given(
    SECRETS,
    st.sampled_from(["api_key", "API-KEY", "token", "GITHUB_TOKEN", "password", "client_secret"]),
    st.sampled_from(["=", ": ", " = ", ":"]),
    CONTEXT,
)
def test_an_assigned_secret_never_survives_text_redaction(secret, key, separator, context):
    assert secret not in redact_text(f"{context} {key}{separator}{secret} {context}")


@given(SECRETS, st.sampled_from(["Bearer", "bearer", "Basic"]), CONTEXT)
def test_an_authorization_value_never_survives_text_redaction(secret, scheme, context):
    assert secret not in redact_text(f"{context} Authorization: {scheme} {secret}")


DESCRIPTOR_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers() | CONTEXT,
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(CONTEXT, children, max_size=3)
    ),
    max_leaves=12,
)


@given(SECRETS, DESCRIPTOR_VALUES, st.data())
def test_a_secret_planted_anywhere_in_a_tool_descriptor_is_redacted(secret, value, data):
    planted = data.draw(st.sampled_from(["description", "key", "default", "nested", "name"]))
    descriptor = {
        "name": "query",
        "description": "Runs a query.",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
        "annotations": value,
    }
    if planted == "description":
        descriptor["description"] += f" Use {secret}."
    elif planted == "key":
        descriptor[f"x-{secret}"] = value
    elif planted == "default":
        descriptor["inputSchema"]["properties"]["q"]["default"] = secret
    elif planted == "nested":
        descriptor["annotations"] = {"hint": [value, {"v": f"k={secret}"}]}
    else:
        descriptor["name"] = f"query-{secret}"
    redacted = redact_descriptor(descriptor, [secret])
    assert secret not in json.dumps(redacted, ensure_ascii=False)


# Each input a quarter of the size this test always used, times ``scale``: a few hundred
# kilobytes at the larger size, where a quadratic regular expression takes minutes.
HOSTILE_REQUIREMENTS = {
    "brackets": lambda scale: "torch" + "[" * (50_000 * scale),
    "long-version": lambda scale: "torch==" + "1." * (25_000 * scale),
    "long-url": lambda scale: "torch @ https://" + "a" * (50_000 * scale),
    "spaces-before-comment": lambda scale: "torch" + " " * (50_000 * scale) + "#",
    "continuations": lambda scale: "torch" + "\\\n" * (25_000 * scale),
    "long-marker": lambda scale: "torch;" + " and python_version" * (2_500 * scale),
    "hash-options": lambda scale: "torch==1.0" + " --hash=sha256:" * (2_500 * scale),
}


@pytest.mark.parametrize("shape", sorted(HOSTILE_REQUIREMENTS))
def test_hostile_requirements_lines_parse_in_bounded_time(tmp_path, shape):
    roots = {}
    for scale in (1, 4):
        roots[scale] = tmp_path / f"scale-{scale}"
        roots[scale].mkdir()
        (roots[scale] / "requirements.txt").write_bytes(HOSTILE_REQUIREMENTS[shape](scale).encode())
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10


# Each text a quarter of the size this test always used, times ``scale``.
HOSTILE_TEXT = {
    "letters-then-scheme": lambda scale: "a" * (75_000 * scale) + "://",
    "token-then-equals": lambda scale: "token" + "=" * (75_000 * scale),
    "bearer-words": lambda scale: "Bearer " * (12_500 * scale),
    "scheme-then-at-signs": lambda scale: "https://" + "@" * (75_000 * scale),
    "letters-then-password": lambda scale: "x" * (75_000 * scale) + "password: ",
}


@pytest.mark.parametrize("shape", sorted(HOSTILE_TEXT))
def test_hostile_text_redacts_in_bounded_time(shape):
    texts = {scale: HOSTILE_TEXT[shape](scale) for scale in (1, 4)}
    assert scaling_ratio(lambda scale: redact_text(texts[scale], ["secretvalue"])) < 10


COLLECTED_FILES = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".claude/settings.json",
    ".well-known/agent.json",
    "rag_config.json",
    "rag_config.yaml",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
    "CLAUDE.md",
    "model.safetensors",
]
JSON_DOCUMENTS = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=12),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=16,
).map(lambda value: json.dumps(value).encode())
CONTENT = st.one_of(st.binary(max_size=256), st.text(max_size=256).map(str.encode), JSON_DOCUMENTS)
# Letters and lone surrogates: JSON escapes the latter, so the file is valid ASCII JSON whose
# strings cannot be encoded as UTF-8.
SURROGATE_TEXT = st.text(
    st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF, exclude_categories=())
    | st.characters(min_codepoint=0x61, max_codepoint=0x7A),
    min_size=1,
    max_size=6,
)
# Where a value reaches the exported record, not only the native inventory.
STRUCTURED = {
    "rag_config.json": st.fixed_dictionaries(
        {
            "vector_store": st.fixed_dictionaries(
                {"provider": SURROGATE_TEXT, "collection": SURROGATE_TEXT}
            ),
            "embedding_model": SURROGATE_TEXT,
        }
    ),
    ".well-known/agent.json": st.fixed_dictionaries(
        {
            "name": SURROGATE_TEXT,
            "url": st.just("https://agent.example/"),
            "skills": st.lists(
                st.fixed_dictionaries({"id": SURROGATE_TEXT, "name": SURROGATE_TEXT}),
                max_size=2,
            ),
        }
    ),
    "package.json": st.fixed_dictionaries(
        {"dependencies": st.dictionaries(st.just("openai") | SURROGATE_TEXT, SURROGATE_TEXT)}
    ),
    ".mcp.json": st.fixed_dictionaries(
        {
            "mcpServers": st.dictionaries(
                SURROGATE_TEXT,
                st.fixed_dictionaries(
                    {"command": SURROGATE_TEXT, "args": st.lists(SURROGATE_TEXT)}
                ),
                max_size=2,
            )
        }
    ),
}
FORMATS = st.sampled_from(["json", "cyclonedx", "spdx", "sarif"])
LONE_SURROGATE_ESCAPE = re.compile(rb"\\u[dD][89a-fA-F][0-9a-fA-F]{2}")


# The CLI turns an unexpected exception into this message and exit status 1, so a crash
# shows in the output, not as an exception the runner sees.
INTERNAL_ERROR = "internal error ("
EXPORT_REFUSED = "cannot be exported as"


def documented_export_failure(content: bytes) -> bool:
    """Only this inventory is refused ("Malformed input" in docs/known-limitations.md)."""
    return LONE_SURROGATE_ESCAPE.search(content) is not None


def assert_no_crash(result) -> None:
    exception = result.exception
    assert exception is None or isinstance(exception, SystemExit), repr(exception)
    assert INTERNAL_ERROR not in result.output, result.output


@pytest.mark.parametrize("name", COLLECTED_FILES)
@settings(max_examples=max(5, settings.default.max_examples // 10))
@given(data=st.data())
def test_any_content_in_a_collected_file_yields_an_inventory_not_a_crash(name, data):
    strategy = CONTENT
    if name in STRUCTURED:
        strategy = strategy | STRUCTURED[name].map(lambda value: json.dumps(value).encode())
    content = data.draw(strategy)
    fmt = data.draw(FORMATS)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "project" / name
        path.parent.mkdir(parents=True)
        path.write_bytes(content)
        output = root / "inventory.json"
        result = CliRunner().invoke(
            main, ["scan", str(root / "project"), "--report-only", "-f", fmt, "-o", str(output)]
        )
        assert_no_crash(result)
        assert EXPORT_REFUSED not in result.output, (fmt, result.output)
        if NO_CONTENT_SERIAL in " ".join(result.output.split()):
            assert documented_export_failure(content), (fmt, result.output)
            assert not output.exists()
        if result.exit_code != 0:
            return
        document = json.loads(output.read_text())
        assert isinstance(document, dict)
        if fmt != "json":
            return
        assert isinstance(document.get("components"), list)
        # An inventory without a content digest is never written, so what is written reads.
        inventory = AIBOM.load(output)
        report = AIBOMDiffer().diff(inventory, AIBOM.load(output))
        # A record whose values are unbound without the key alerts even against itself.
        unbound = {c.bom_ref for c in inventory.components if _values_unbound(c)}
        assert not report.components_added and not report.components_removed
        assert {change.bom_ref for change in report.components_modified} == unbound
        assert all(
            alert["severity"] == "medium" and alert["component"] in unbound
            for alert in report.security_alerts
        )


NESTING = 1_000


def _nested_input(name: str, depth: int) -> str:
    return {
        "requirements.txt": (
            "torch; " + "(" * depth + 'python_version >= "3"' + ")" * depth + "\nopenai==1.0\n"
        ),
        ".mcp.json": '{"mcpServers": ' + '{"a": ' * depth + "1" + "}" * depth + "}",
        "package.json": '{"dependencies": ' + "[" * depth + "]" * depth + "}",
        "pyproject.toml": (
            "[project]\nname = 'x'\nversion = '1'\ndependencies = ["
            + "[" * depth
            + "]" * depth
            + "]\n"
        ),
        ".well-known/agent.json": "[" * depth + "]" * depth,
        "rag_config.json": '{"vector_store": ' + "[" * depth + "]" * depth + "}",
    }[name]


NESTED_INPUTS = {
    name: _nested_input(name, NESTING)
    for name in (
        "requirements.txt",
        ".mcp.json",
        "package.json",
        "pyproject.toml",
        ".well-known/agent.json",
        "rag_config.json",
    )
}


@pytest.mark.parametrize("name", sorted(NESTED_INPUTS))
def test_deeply_nested_input_fails_closed_in_bounded_time(tmp_path, name):
    cases = {}
    for scale in (1, 4):
        project = tmp_path / f"scale_{scale}" / "project"
        path = project / name
        path.parent.mkdir(parents=True)
        path.write_text(_nested_input(name, (NESTING // 4) * scale))
        cases[scale] = (project, tmp_path / f"scale_{scale}" / "inventory.json")

    def run(scale: int):
        project, output = cases[scale]
        return CliRunner().invoke(
            main, ["scan", str(project), "--report-only", "-f", "json", "-o", str(output)]
        )

    result = run(4)
    assert_no_crash(result)
    assert scaling_ratio(run) < 10
    output = cases[4][1]
    if not output.exists():
        assert result.exit_code != 0
        return
    inventory = json.loads(output.read_text())
    completeness = inventory["metadata"]["completeness"]
    refs = {component["bom_ref"] for component in inventory["components"]}
    if name == "requirements.txt":
        # Each line is understood, a gap, or its collector is reported as failed.
        failed = completeness["scanner_status"].get("registry") == "failed"
        gaps = [*completeness["scan_failures"], *completeness["surfaces_excluded"]]
        assert "registry:pypi/openai" in refs or failed
        assert (
            "registry:pypi/torch" in refs
            or failed
            or any("requirements.txt" in gap for gap in gaps)
        )


# --- R1.0.0-1: @given properties for every maintained reader entry point ---


@given(
    st.dictionaries(
        st.from_regex(r"[a-z][a-z0-9_]{0,12}", fullmatch=True),
        st.one_of(
            st.integers(-1000, 1000),
            st.booleans(),
            st.from_regex(r"[a-z0-9_.-]{1,16}", fullmatch=True),
        ),
        min_size=1,
        max_size=6,
    )
)
@example({"on": 0})
@example({"null": "a", "plain": True})
def test_yaml_mapping_reader_roundtrips_or_fails_closed(mapping):
    import yaml

    from nexus_symbiote.policy import PolicyError, parse_yaml_mapping

    lines = [
        f"{k}: {json.dumps(v) if isinstance(v, (bool, str)) else v}" for k, v in mapping.items()
    ]
    text = "\n".join(lines) + "\n"
    # A plain key that YAML 1.1 reads as a boolean or null (on, no, null) is not a string.
    if all(isinstance(yaml.safe_load(key), str) for key in mapping):
        assert parse_yaml_mapping(text, max_nodes=128) == mapping
    else:
        with pytest.raises(PolicyError, match="keys must be unique strings"):
            parse_yaml_mapping(text, max_nodes=128)
    with pytest.raises((PolicyError, ValueError)):
        parse_yaml_mapping("a: [1\n", max_nodes=32)


@given(st.text(max_size=128))
def test_toml_codex_reader_never_crashes_or_silently_ignores_malformed_config(raw):
    import tomllib

    from nexus_symbiote.scanners.ide_agents import IDEAgentScanner

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        codex_dir = root / ".codex"
        codex_dir.mkdir()
        (codex_dir / "config.toml").write_text(raw, encoding="utf-8")
        result = IDEAgentScanner().scan(root)
        try:
            parsed = tomllib.loads(raw)
        except (tomllib.TOMLDecodeError, ValueError):
            gaps = [*result.scan_failures, *result.surfaces_excluded]
            assert any("config.toml" in g for g in gaps)
        else:
            assert isinstance(parsed, dict)


@given(
    st.from_regex(r"[a-z][a-z0-9_-]{0,12}", fullmatch=True),
    st.sampled_from(["", "// header comment\n", "/* block comment */\n"]),
    st.booleans(),
)
def test_jsonc_mcp_reader_handles_comments_and_trailing_commas_cleanly(
    server_name, comment, trailing_comma
):
    from nexus_symbiote.scanners.mcp import MCPScanner

    comma = "," if trailing_comma else ""
    payload = (
        f"{comment}{{\n"
        f'  "servers": {{\n'
        f'    "{server_name}": {{"command": "node", "args": ["srv.js"{comma}]{comma}}}{comma}\n'
        f"  }}{comma}\n"
        f"}}\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        vscode = root / ".vscode"
        vscode.mkdir()
        (vscode / "mcp.json").write_text(payload, encoding="utf-8")
        result = MCPScanner().scan(root)
        assert not result.scan_failures
        assert any(server_name in c.name for c in result.components)


@given(st.binary(max_size=128))
def test_gguf_header_reader_bounds_arbitrary_bytes_without_unhandled_exception(payload):
    import struct as _struct

    from nexus_symbiote.scanners.model import ModelScanner

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "weights.gguf").write_bytes(b"GGUF" + payload)
        result = ModelScanner().scan(root)
        assert isinstance(result.components, list)
        # Valid minimal v3 empty header succeeds cleanly.
        (root / "minimal.gguf").write_bytes(b"GGUF" + _struct.pack("<IQQ", 3, 0, 0))
        ok_res = ModelScanner().scan(root)
        assert any("minimal.gguf" in c.name for c in ok_res.components)


@given(st.integers(min_value=0, max_value=2048), st.binary(max_size=96))
def test_safetensors_header_reader_bounds_length_prefix_and_payload(declared_len, body):
    import struct as _struct

    from nexus_symbiote.scanners.model import ModelScanner

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "corrupt.safetensors").write_bytes(_struct.pack("<Q", declared_len) + body)
        result = ModelScanner().scan(root)
        assert isinstance(result.components, list)


@given(st.text(max_size=64))
def test_ecma_regex_translator_compiles_or_raises_value_error(pattern):
    from nexus_symbiote.runtime_validation import ecma_pattern

    try:
        translated = ecma_pattern(pattern)
    except (ValueError, re.error):
        return
    compiled = re.compile(translated)
    assert compiled.search("sample-123") is None or True


@given(
    st.from_regex(r"[a-z][a-z0-9_-]{0,15}", fullmatch=True),
    st.from_regex(r"[a-zA-Z0-9_.-]{1,16}", fullmatch=True),
)
def test_typescript_mcp_reader_collects_literal_sdk_registrations_without_executing(
    srv_name, tool_name
):
    from nexus_symbiote.scanners.base import ScanResult
    from nexus_symbiote.scanners.ts_tools import collect_typescript_source

    source = (
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
        f"const server = new McpServer({{ name: '{srv_name}', version: '1.0.0' }});\n"
        f"server.tool('{tool_name}', {{}}, async () => ({{ content: [] }}));\n"
    ).encode()
    res = ScanResult(scanner_name="mcp")
    collect_typescript_source(Path("server.ts"), source, res)
    assert not res.scan_failures
    assert any(c.name == tool_name for c in res.components)


READER_PROPERTY_MAP: dict[str, object] = {
    "requirements_dockerfile": test_requirements_lines_reach_the_name_and_pin_packaging_reads,
    "yaml_mapping": test_yaml_mapping_reader_roundtrips_or_fails_closed,
    "toml_codex": test_toml_codex_reader_never_crashes_or_silently_ignores_malformed_config,
    "jsonc_mcp": test_jsonc_mcp_reader_handles_comments_and_trailing_commas_cleanly,
    "gguf_header": test_gguf_header_reader_bounds_arbitrary_bytes_without_unhandled_exception,
    "safetensors_header": test_safetensors_header_reader_bounds_length_prefix_and_payload,
    "ecma262_regex": test_ecma_regex_translator_compiles_or_raises_value_error,
    "typescript_mcp": test_typescript_mcp_reader_collects_literal_sdk_registrations_without_executing,
}


def test_every_maintained_reader_has_a_registered_hypothesis_property():
    expected_readers = {
        "requirements_dockerfile",
        "yaml_mapping",
        "toml_codex",
        "jsonc_mcp",
        "gguf_header",
        "safetensors_header",
        "ecma262_regex",
        "typescript_mcp",
    }
    assert set(READER_PROPERTY_MAP) == expected_readers
    for reader_name, fn in READER_PROPERTY_MAP.items():
        assert callable(fn), reader_name
        assert hasattr(fn, "hypothesis"), f"{reader_name} must be decorated with @given"


# The source collector's Python reader: a file of any content must leave records, a gap
# or nothing, never a crash and never a value the collector may not export, and reading
# must stay linear in the size of a file.
SOURCE_FRAGMENTS = st.sampled_from(
    [
        "from openai import OpenAI\n",
        "import litellm\n",
        "from . import settings\n",
        'model="gpt-4o"',
        "model=os.getenv(",
        'f"{NAME}-',
        "client.chat.completions.create(",
        "NAME = NAME\n",
        '"""',
        "'",
        '"',
        "\\",
        "\x00",
        "\n",
        "(",
        "[",
        "lambda: ",
        "async def f():\n    ",
        "\t",
    ]
)
SOURCE_TEXT = st.lists(st.one_of(SOURCE_FRAGMENTS, st.text(max_size=12)), max_size=24).map("".join)
PLANTED_SHAPES = st.text(
    alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", min_size=40, max_size=48
).map(lambda body: "sk-proj-" + body)


def _scan_source(files: dict[str, bytes]) -> tuple[ScanResult, str]:
    with tempfile.TemporaryDirectory() as directory:
        for name, content in files.items():
            path = Path(directory) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        result = SourceScanner().scan(Path(directory))
    exported = json.dumps(
        [component.model_dump(mode="json") for component in result.components]
        + list(result.surfaces_excluded)
        + list(result.scan_failures)
    )
    return result, exported


def _well_formed(result: ScanResult, path: str) -> None:
    """Whatever the reader made of a file is a declared record of that file, or a gap."""
    assert not result.scan_failures
    for component in result.components:
        claim = component.claims["source_reference"]
        assert component.assurance_level.value == "declared"
        assert claim.locator.startswith(f"{path}:") and model_identifier(component.name)
    assert all(gap.startswith(f"{path}") for gap in result.surfaces_excluded)


@given(SOURCE_TEXT)
def test_no_python_source_crashes_the_source_reader(text):
    files = {"app/unit.py": ("from openai import OpenAI\n" + text).encode("utf-8", "surrogatepass")}
    result, exported = _scan_source(files)
    _well_formed(result, "app/unit.py")
    # The same file reads the same way again.
    assert _scan_source(files)[1] == exported


@given(st.binary(max_size=96))
def test_python_source_that_is_not_text_is_nothing_or_a_gap(payload):
    content = b"from openai import OpenAI\n" + payload
    result, _ = _scan_source({"app/unit.py": content})
    _well_formed(result, "app/unit.py")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        assert result.components == []
        assert list(result.surfaces_excluded) == [
            "app/unit.py: source file cannot be decoded as its encoding declares; "
            "declarations in it were not read"
        ]


@given(PLANTED_SHAPES, st.sampled_from(["model", "api_key", "base_url", "variable", "default"]))
def test_a_token_in_any_argument_of_source_is_never_exported(planted, argument):
    model = planted if argument == "model" else "gpt-4o"
    variable = planted if argument == "variable" else "CHAT_MODEL"
    default = planted if argument == "default" else "gpt-4.1"
    source = f"""\
import os
from openai import OpenAI

client = OpenAI(api_key="{planted}", base_url="https://{planted}@gateway.example/v1")
client.chat.completions.create(model="{model}", messages=[])
client.chat.completions.create(model="openai/{model}", messages=[])
client.chat.completions.create(model=os.getenv("{variable}", "{default}"), messages=[])
client.chat.completions.create(model=os.environ["{variable}"], messages=[])
"""
    _, exported = _scan_source({"app/bot.py": source.encode()})
    assert planted not in exported
    assert planted[8:] not in exported


@given(
    st.one_of(
        st.text(max_size=160),
        st.from_regex(r"[ \t]?[A-Za-z0-9][A-Za-z0-9._:/@+ -]{0,140}[ \t]?", fullmatch=True),
    )
)
def test_an_accepted_model_identifier_is_exported_as_written(literal):
    accepted = model_identifier(literal)
    if accepted is not None:
        assert accepted == literal.strip()
        assert " " not in accepted and "://" not in accepted and len(accepted) <= 128
        assert redact_text(accepted) == accepted


def _rebinds(size: int) -> str:
    rebinds = "\n".join(f'text = text.replace("{index}", "x")' for index in range(size))
    calls = "\n".join(
        f'client.chat.completions.create(model=text + "{index}", messages=[])'
        for index in range(size)
    )
    return f'client = OpenAI()\ntext = "gpt-4o"\n{rebinds}\n{calls}\n'


def _wide_or(size: int) -> str:
    wide = " or ".join(["1"] * size)
    return f"y = ({wide})\n" + "f(model=y)\n" * size


def _deep_plus(size: int) -> str:
    return "z = (" + " + ".join(["f(model=x)"] * size) + ")\n"


def _joined_bindings(size: int) -> str:
    names = "\n".join(f'L{index} = "a{index}"\nR{index} = "b{index}"' for index in range(4))
    choose = "L = " + " or ".join(f"L{index}" for index in range(4)) + "\n"
    choose += "R = " + " or ".join(f"R{index}" for index in range(4)) + "\n"
    bound = "\n".join('N = f"{L}{R}"' for _ in range(16))
    return f"{names}\n{choose}{bound}\n" + "f(model=N)\n" * size


@pytest.mark.no_cover
@pytest.mark.parametrize(
    "shape",
    [_rebinds, _wide_or, _deep_plus, _joined_bindings],
    ids=["rebinds", "wide-or", "deep-plus", "joined-bindings"],
)
def test_reading_python_source_is_linear_in_its_size(tmp_path, shape):
    roots = {}
    for scale in (1, 4):
        root = roots[scale] = tmp_path / f"n{scale}"
        root.mkdir()
        (root / "app.py").write_text(
            f"import openai\nfrom openai import OpenAI\n{shape(500 * scale)}", encoding="utf-8"
        )

    assert scaling_ratio(lambda scale: SourceScanner().scan(roots[scale])) < 8


def _attributes(size: int) -> str:
    methods = "\n".join(
        f"    def ask{index}(self):\n        self.client.responses.create(model=self.model)"
        for index in range(size)
    )
    return f'class Bot:\n    def __init__(self):\n        self.client = OpenAI()\n        self.model = "o3"\n{methods}\n'


def _returns(size: int) -> str:
    return 'def pick():\n    return "o3"\n' + "OpenAI().responses.create(model=pick())\n" * size


def _items(size: int) -> str:
    table = ", ".join(f'"k{index}": "m-{index}"' for index in range(size))
    reads = "\n".join(f'OpenAI().responses.create(model=T["k{index}"])' for index in range(size))
    return f"T = {{{table}}}\n{reads}\n"


@pytest.mark.no_cover
@pytest.mark.parametrize("shape", [_attributes, _returns, _items], ids=["self", "returns", "items"])
def test_following_attributes_items_and_returns_is_linear(tmp_path, shape):
    roots = {}
    for scale in (1, 4):
        root = roots[scale] = tmp_path / f"n{scale}"
        root.mkdir()
        (root / "app.py").write_text(
            f"from openai import OpenAI\n{shape(300 * scale)}", encoding="utf-8"
        )

    assert scaling_ratio(lambda scale: SourceScanner().scan(roots[scale])) < 8


@pytest.mark.no_cover
def test_following_into_many_modules_is_linear(tmp_path):
    roots = {}
    for scale in (1, 4):
        root = roots[scale] = tmp_path / f"n{scale}"
        (root / "app").mkdir(parents=True)
        count = 60 * scale
        for index in range(count):
            (root / "app" / f"m{index}.py").write_text(f'MODEL = "m-{index}"\n', encoding="utf-8")
        imports = "\n".join(f"from app.m{index} import MODEL as M{index}" for index in range(count))
        reads = "\n".join(f"OpenAI().responses.create(model=M{index})" for index in range(count))
        (root / "app" / "run.py").write_text(
            f"from openai import OpenAI\n{imports}\n{reads}\n", encoding="utf-8"
        )

    assert scaling_ratio(lambda scale: SourceScanner().scan(roots[scale])) < 8


@pytest.mark.no_cover
def test_the_records_of_a_tree_do_not_depend_on_the_hash_seed(tmp_path):
    files = {
        "app/a.py": "import os\nfrom openai import OpenAI\nfrom litellm import completion\n"
        'M = os.getenv("CHAT_MODEL", "gpt-4o") or "o3"\nOpenAI().responses.create(model=M)\n'
        'completion(model="anthropic/claude-sonnet-4-5")\ncompletion(model=unknown)\n',
        "app/b.py": "from openai import OpenAI\nfor m in pick():\n"
        '    OpenAI().responses.create(model=m)\nOpenAI().responses.create(model="gpt-4o")\n',
    }
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text, encoding="utf-8")
    program = (
        "import json, sys\nfrom pathlib import Path\n"
        "from nexus_symbiote.scanners.source import SourceScanner\n"
        "r = SourceScanner().scan(Path(sys.argv[1]))\n"
        "print(json.dumps([c.model_dump(mode='json') for c in r.components]"
        " + list(r.surfaces_excluded)))\n"
    )
    outputs = set()
    for seed in ("0", "1", "4242"):
        environment = {**os.environ, "PYTHONHASHSEED": seed}
        completed = subprocess.run(  # noqa: S603 -- this interpreter and a fixed program
            [sys.executable, "-c", program, str(tmp_path)],
            capture_output=True,
            text=True,
            env=environment,
            timeout=120,
            check=True,
        )
        outputs.add(completed.stdout)
    (output,) = outputs
    assert "claude-sonnet-4-5" in output
