"""MCP source collection parses only files that reference the SDK, so size alone never fails it."""

from __future__ import annotations

import ast
import codecs
import encodings
import json
import re
import shutil
import tracemalloc
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nexus_symbiote import limits
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import MCPClientComponent, ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner, without_js_comments
from nexus_symbiote.utils.confined import MAX_LISTED_FAILURES
from tests.support import scaling_ratio

REPOSITORY = Path(__file__).resolve().parents[1]
CLIENT_PY = "from mcp import ClientSession\n"
SERVER_TS = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'const server = new McpServer({ name: "s", version: "1" });\n'
    'server.registerTool("read", {}, handler);\n'
)
CLIENT_JS = 'const { Client } = require("@modelcontextprotocol/sdk/client/index.js");\n'
OLD_STRIPPER = re.compile(r"/\*.*?\*/|(?m:^\s*//[^\n]*$)", re.S)


def _write(root: Path, relative: str, text: str | bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))


def _unrelated(root: Path, count: int) -> None:
    for index in range(count):
        _write(root, f"pkg{index % 7}/module{index:03d}.py", f"def f{index}(x):\n    return x\n")
        _write(root, f"web/view{index:03d}.ts", f"export const v{index} = {index};\n")
    for index in range(12):
        _write(root, f"root{index}.js", f"module.exports = {index};\n")
        _write(root, f"root{index}.ts", f"export default {index};\n")


def _client(result) -> MCPClientComponent | None:
    found = [c for c in result.components if isinstance(c, MCPClientComponent)]
    return found[0] if found else None


def test_a_large_project_without_mcp_source_completes(tmp_path):
    _unrelated(tmp_path, 120)
    (tmp_path / "big").mkdir()
    (tmp_path / "big" / "generated_pb2.py").write_text("DATA = '" + "x" * 300_000 + "'\n")
    (tmp_path / "py2.py").write_text("print 'python 2'\n")
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"files": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}})
    )
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert result.surfaces_excluded == []
    assert len(result.surfaces_scanned) == 1
    assert result.surfaces_scanned[0].endswith(".mcp.json")


def test_sdk_references_are_found_wherever_the_files_are(tmp_path):
    _unrelated(tmp_path, 60)
    _write(tmp_path, "agents/deep/client.py", CLIENT_PY)
    _write(tmp_path, "server/src/index.ts", SERVER_TS)
    _write(tmp_path, "cli.js", CLIENT_JS)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    client = _client(result)
    assert client is not None
    # Nested scripts are searched for SDK imports too, the server's included.
    assert client.properties["source_paths"] == [
        "agents/deep/client.py",
        "server/src/index.ts",
        "cli.js",
    ]
    assert client.source_path == "agents/deep/client.py"
    # A client module loaded by require is opaque to the analysis, so it is a gap too.
    assert result.surfaces_excluded == [
        "cli.js:1 (MCP client SDK loaded by require or dynamic import; servers it starts or "
        "reaches not inventoried)"
    ]
    assert sorted(result.surfaces_scanned) == [
        "agents/deep/client.py",
        "cli.js",
        "server/src/index.ts",
    ]
    assert [c.name for c in result.components if c.component_type == "tool"] == ["read"]


def test_unrelated_source_changes_leave_the_result_unchanged(tmp_path):
    _write(tmp_path, "client.py", CLIENT_PY)
    _write(tmp_path, "server.ts", SERVER_TS)

    def snapshot():
        result = MCPScanner().scan(tmp_path)
        return (
            [c.model_dump(mode="json") for c in result.components],
            result.surfaces_scanned,
            result.surfaces_excluded,
            result.scan_failures,
        )

    before = snapshot()
    _write(tmp_path, "helpers/strings.py", "def shout(text):\n    return text.upper()\n")
    _write(tmp_path, "notes.ts", "export const greeting = 'hello';\n")
    _write(tmp_path, "notes.js", "// mentions mcp in a comment\nmodule.exports = 1;\n")
    _write(tmp_path, "broken.py", "def broken(:\n")
    assert snapshot() == before


def test_the_same_tree_at_two_locations_gives_the_same_result(tmp_path):
    first = tmp_path / "one" / "checkout"
    _write(first, "agents/client.py", CLIENT_PY)
    _write(first, "server/index.ts", SERVER_TS)
    _write(first, "cli.js", CLIENT_JS)
    second = tmp_path / "elsewhere" / "renamed"
    shutil.copytree(first, second)

    def dump(root: Path) -> str:
        result = MCPScanner().scan(root)
        return json.dumps(
            [
                [c.model_dump(mode="json") for c in result.components],
                result.surfaces_scanned,
                result.scan_failures,
            ]
        )

    assert dump(first) == dump(second)
    assert str(tmp_path) not in dump(first)


def test_candidates_are_bounded_by_the_text_read_not_by_their_number(tmp_path):
    # A file count says nothing about cost: every candidate is parsed, and only the
    # source budget, which names the first file it did not read, stops the search.
    for index in range(53):
        _write(tmp_path, f"clients/c{index:02d}.py", CLIENT_PY)
    _unrelated(tmp_path, 80)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    client = _client(result)
    assert client is not None and len(client.properties["source_paths"]) == 53


def test_only_candidate_files_are_held_to_the_syntax_limit(tmp_path):
    _write(tmp_path, "data.py", "DATA = '" + "x" * 300_000 + "'\n")
    assert MCPScanner().scan(tmp_path).scan_failures == []
    _write(tmp_path, "pkg/agent.py", CLIENT_PY + "PAD = '" + "x" * 300_000 + "'\n")
    _write(tmp_path, "server.ts", SERVER_TS + "//" + "x" * 300_000 + "\n")
    assert sorted(MCPScanner().scan(tmp_path).scan_failures) == [
        (
            "pkg/agent.py: syntax-bytes limit of 256 KiB exceeded; "
            "raise it with --limit syntax-bytes=N"
        ),
        "server.ts: syntax-bytes limit of 256 KiB exceeded; raise it with --limit syntax-bytes=N",
    ]
    with limits.applied(replace(limits.DEFAULTS, syntax_bytes=512 * limits.KIB)):
        result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert _client(result) is not None


def test_the_source_scan_budget_names_the_first_file_not_searched(tmp_path):
    for index in range(6):
        _write(tmp_path, f"m{index}.py", "x = 1\n" * 100)
    with limits.applied(replace(limits.DEFAULTS, source_scan_bytes=1500)):
        failures = MCPScanner().scan(tmp_path).scan_failures
    hint = (
        "source-scan-bytes limit of 1500 bytes exceeded; raise it with --limit source-scan-bytes=N"
    )
    assert failures == [
        f"m2.py: MCP source references exceed the combined size limit: the rest were not "
        f"read; {hint}"
    ]


def test_python_identifiers_are_compared_as_python_reads_them(tmp_path):
    fullwidth = "".join(chr(ord(letter) + 0xFEE0) for letter in "mcp")
    _write(tmp_path, "pkg/stealth.py", f"from {fullwidth} import ClientSession\n")
    _write(tmp_path, "pkg/direct.py", "client = MCPClient()\n")
    result = MCPScanner().scan(tmp_path)
    client = _client(result)
    assert client is not None
    assert client.properties["source_paths"] == ["pkg/direct.py", "pkg/stealth.py"]


def test_python_source_is_read_in_its_declared_encoding(tmp_path):
    (tmp_path / "latin.py").write_bytes(b"# -*- coding: latin-1 -*-\nname = '\xe9'\n")
    (tmp_path / "declared.py").write_bytes(b"# -*- coding: latin-1 -*-\nname = 'plain'\n")
    (tmp_path / "ascii.py").write_bytes(b"name = 'plain'\n")
    assert MCPScanner().scan(tmp_path).scan_failures == []
    fullwidth = "".join(chr(ord(letter) + 0xFEE0) for letter in "mcp")
    source = f"# coding: cp932\nfrom {fullwidth} import ClientSession\n"
    _write(tmp_path, "pkg/japanese.py", source.encode("cp932"))
    _write(
        tmp_path, "pkg/legacy.py", b"# coding: latin-1\n# caf\xe9\nfrom mcp import ClientSession\n"
    )
    # Python cannot import a nested module that declares no codec and is not UTF-8,
    # so it is no failure there; at the root every source is held to its encoding,
    # and so is a nested one whose rest python -x would read as a reference.
    _write(tmp_path, "pkg/undeclared.py", b"name = '\xe9'\n")
    _write(tmp_path, "undeclared.py", b"name = '\xe9'\n")
    _write(
        tmp_path, "pkg/skipped.py", b"\xff\n" + f"from {fullwidth}.client import Client\n".encode()
    )
    result = MCPScanner().scan(tmp_path)
    assert sorted(result.scan_failures) == [
        "pkg/skipped.py: invalid UTF-8",
        "undeclared.py: invalid UTF-8",
    ]
    assert result.surfaces_excluded == []
    client = _client(result)
    assert client is not None
    assert client.properties["source_paths"] == ["pkg/japanese.py", "pkg/legacy.py"]


HIDDEN_REFERENCES = {
    "unicode_escape": b"# -*- coding: unicode_escape -*-\nfrom \\x6dcp.client import Client\n",
    "utf-7": b"# coding: utf-7\nfrom +AG0AYwBw-.client import Client\n",
    "raw_unicode_escape": b"# coding: raw_unicode_escape\nfrom \\u006dcp.client import Client\n",
    "carriage_returns": b"\r# coding: utf-7\rfrom +AG0AYwBw-.client import Client\r",
    "continued_declaration": b"# coding: unicode_escape \\\nfrom \\x6dcp.client import Client\n",
    "iso2022": b"# coding: iso2022_jp\nfrom \x1b$B#m#c#p\x1b(B.client import Client\n",
    "utf-16": b"# coding: utf-16\n" + "from mcp.client import Client\n".encode("utf-16-le"),
    "idna": b"# coding: idna\nfrom xn--mcp.client import Client\n",
    "unknown": b"# coding: no-such-codec\nfrom mcp.client import Client\n",
    "bom_conflict": b"\xef\xbb\xbf# coding: latin-1\nfrom mcp.client import Client\n",
}


@pytest.mark.parametrize("location", ["agent.py", "pkg/deep/agent.py"])
@pytest.mark.parametrize("source", HIDDEN_REFERENCES.values(), ids=HIDDEN_REFERENCES)
def test_a_declaration_static_reading_cannot_follow_is_a_failure(tmp_path, location, source):
    path = tmp_path / location
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(source)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [f"{location}: unsupported source encoding declaration"]
    assert result.components == []


def test_a_hostile_declaration_is_refused_without_decoding(tmp_path):
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        payload = b"a" * (500_000 * scale) + b"-" + b"b" * (500_000 * scale)
        _write(root, "slow.py", b"# coding: punycode\n" + payload)
        roots[scale] = root

    def run(scale: int) -> None:
        assert MCPScanner().scan(roots[scale]).scan_failures == [
            "slow.py: unsupported source encoding declaration"
        ]

    assert scaling_ratio(run) < 10


def test_an_import_spelled_with_compatibility_characters_is_a_gap(tmp_path):
    fullwidth = "".join(chr(ord(letter) + 0xFEE0) for letter in "mcp")
    # The class name is a tool hint too, so it is spelled the same way.
    server_class = "".join(chr(ord(letter) + 0xFEE0) for letter in "FastMCP")
    _write(
        tmp_path,
        "pkg/server.py",
        f"from {fullwidth}.server.fast{fullwidth} import {server_class}\n"
        f'server = {server_class}("files")\n'
        "@server.tool()\n"
        "def read(path: str) -> str:\n"
        "    return path\n",
    )
    result = MCPScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        "pkg/server.py: Python MCP server import spelled with compatibility characters; "
        "its servers and tools are not collected"
    ]
    assert result.surfaces_scanned == ["pkg/server.py"]
    literal = (tmp_path / "pkg" / "server.py").read_text(encoding="utf-8")
    _write(
        tmp_path,
        "pkg/server.py",
        literal.replace(server_class, "FastMCP").replace(fullwidth, "mcp"),
    )
    result = MCPScanner().scan(tmp_path)
    assert result.surfaces_excluded == []
    assert [c.name for c in result.components if c.component_type == "tool"] == ["read"]


@pytest.mark.parametrize(
    ("module", "name"),
    [("langchain_core.tools", "tool"), ("smolagents", "tool"), ("crewai.tools", "tool")],
)
def test_a_framework_import_spelled_with_compatibility_characters_is_a_gap(tmp_path, module, name):
    # The agent framework hints reach the parser in NFKC form as well, but the tool
    # collector reads only files that name a framework literally.
    hidden = "".join(chr(ord(letter) + 0xFEE0) if letter.isalpha() else letter for letter in module)
    source = f"from {{}} import {name}\n\n@{name}\ndef lookup(order: str) -> str:\n"
    source += '    """Look up an order."""\n    return order\n'
    _write(tmp_path, "pkg/tools.py", source.format(hidden))
    result = MCPScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        "pkg/tools.py: Python agent framework tool import spelled with compatibility "
        "characters; its tools are not collected"
    ]
    assert result.surfaces_scanned == ["pkg/tools.py"]
    _write(tmp_path, "pkg/tools.py", source.format(module))
    result = MCPScanner().scan(tmp_path)
    assert result.surfaces_excluded == []
    assert [c.name for c in result.components if c.component_type == "tool"] == ["lookup"]


@pytest.mark.parametrize(
    "statement",
    [
        "import {pydantic_ai} as p\nagent = p.Agent('m')\n",
        "from {pydantic_ai} import *\nagent = Agent('m')\n",
        "import {langchain_core}.tools as t\n",
        "from {langchain_core}.tools import *\n",
    ],
    ids=["qualified-agent", "star-agent", "qualified-decorator", "star-decorator"],
)
def test_a_qualified_or_star_framework_import_with_compatibility_characters_is_a_gap(
    tmp_path, statement
):
    # Spelled in ASCII, the same import is a gap of the tool collector.
    packages = ("pydantic_ai", "langchain_core")
    hidden = {
        name: "".join(chr(ord(letter) + 0xFEE0) if letter.isalpha() else letter for letter in name)
        for name in packages
    }
    _write(tmp_path, "pkg/tools.py", statement.format(**hidden))
    result = MCPScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        "pkg/tools.py: Python agent framework tool import spelled with compatibility "
        "characters; its tools are not collected"
    ]
    _write(tmp_path, "pkg/tools.py", statement.format(**{name: name for name in packages}))
    result = MCPScanner().scan(tmp_path)
    assert result.surfaces_excluded == ["pkg/tools.py: unresolved Python SDK tool import"]


@pytest.mark.parametrize("character", ["\ufdfa", "\u3300", "\uff4d"])
def test_compatibility_characters_cannot_inflate_the_search(tmp_path, character):
    # U+FDFA has an 18-character compatibility form; folding the whole text at once
    # held about 150 MiB and took seconds for this 4 MiB file.
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        body = "# " + character * ((scale * limits.MIB - 16) // len(character.encode()))
        _write(root, "wide.py", body + "\n")
        roots[scale] = root
    tracemalloc.start()
    try:
        failures = MCPScanner().scan(roots[4]).scan_failures
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert failures == []
    assert peak < 32 * limits.MIB
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale]).scan_failures) < 10


def test_unrelated_sources_larger_than_file_bytes_are_searched_as_a_stream(tmp_path):
    padding = "x" * (5 * limits.MIB)
    _write(tmp_path, "pkg/generated_pb2.py", f"DATA = '{padding}'\n")
    _write(tmp_path, "web/generated.ts", f"export const data = '{padding}';\n")
    _write(tmp_path, "bundle.js", f"module.exports = '{padding}';\n")
    _write(tmp_path, "bundle.ts", f"export default '{padding}';\n")
    assert MCPScanner().scan(tmp_path).scan_failures == []
    _write(tmp_path, "pkg/text.py", f"DATA = '{padding}\u00e9'\n")
    # "m" ends the first one-MiB read and "cp" starts the second.
    marker_across_reads = "x" * (limits.MIB - 3) + "mcp" + padding
    _write(tmp_path, "pkg/late.py", f"# {marker_across_reads}\n")
    assert sorted(MCPScanner().scan(tmp_path).scan_failures) == [
        "pkg/late.py: syntax-bytes limit of 256 KiB exceeded; raise it with --limit syntax-bytes=N",
        "pkg/text.py: file-bytes limit of 4 MiB exceeded; raise it with --limit file-bytes=N",
    ]


def test_a_source_symlinked_within_the_project_is_read_through_its_target(tmp_path):
    _write(tmp_path, "pkg/real.py", "x = 1\n")
    _write(tmp_path, "web/real.ts", "export const x = 1;\n")
    _write(tmp_path, "web/server.ts", SERVER_TS)
    (tmp_path / "pkg" / "alias.py").symlink_to("real.py")
    (tmp_path / "web" / "alias.ts").symlink_to("real.ts")
    (tmp_path / "web" / "linked.ts").symlink_to("server.ts")
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert sorted(c.source_path for c in result.components if c.component_type == "tool") == [
        "web/linked.ts",
        "web/server.ts",
    ]


def test_a_byte_order_mark_does_not_make_python_source_invalid(tmp_path):
    (tmp_path / "agent.py").write_bytes(b"\xef\xbb\xbf" + CLIENT_PY.encode())
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert _client(result) is not None


def _utf16(text: str, codec: str) -> bytes:
    marks = {"utf-16-le": codecs.BOM_UTF16_LE, "utf-16-be": codecs.BOM_UTF16_BE}
    return marks[codec] + text.encode(codec, "surrogatepass")


def _python_x_imports(source: bytes) -> list[str | None]:
    """What `python -x` imports: it skips through the first line feed, then reads on."""
    tree = ast.parse(source[source.index(b"\n") :])
    return [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]


SCRIPTS = {
    "client.ts": 'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
    'const client = new Client({ name: "agent", version: "1.0.0" });\n',
    "agent.js": CLIENT_JS,
    "server.ts": SERVER_TS,
    "src/server.ts": SERVER_TS,
}


@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("location", SCRIPTS)
def test_scripts_are_searched_as_tsc_decodes_them(tmp_path, location, codec):
    # tsc decodes a file that starts with a UTF-16 byte order mark as UTF-16, and bun
    # runs the little-endian form; a byte search saw no reference in these files.
    plain, wide = tmp_path / "plain", tmp_path / "wide"
    _write(plain, location, SCRIPTS[location])
    _write(wide, location, _utf16(SCRIPTS[location], codec))
    expected, result = MCPScanner().scan(plain), MCPScanner().scan(wide)
    assert result.scan_failures == []
    # Only agent.js, which loads the client SDK by require, is a gap.
    assert result.surfaces_excluded == expected.surfaces_excluded
    assert bool(expected.surfaces_excluded) is (location == "agent.js")
    assert result.surfaces_scanned == expected.surfaces_scanned

    def described(scan):
        return [
            (c.bom_ref, c.name, {k: v for k, v in c.properties.items() if k != "source_sha256"})
            for c in scan.components
        ]

    assert described(result) == described(expected) != []
    for tool in (c for c in result.components if isinstance(c, ToolComponent)):
        assert tool.properties["source_sha256"] == hash_bytes((wide / location).read_bytes())


def test_a_script_is_held_to_the_encoding_it_is_read_in(tmp_path):
    latin = "export const name = 'café';\n".encode("latin-1")
    _write(tmp_path, "util.ts", latin)
    _write(tmp_path, "util.js", latin)
    # Nested sources are searched by bytes only, as earlier releases did.
    _write(tmp_path, "src/util.ts", latin)
    _write(tmp_path, "wide.ts", _utf16("export const x = 1;\n", "utf-16-le"))
    _write(tmp_path, "wide.js", _utf16("module.exports = '\ud800';\n", "utf-16-be"))
    _write(tmp_path, "lone.js", _utf16("// \ud800\n" + CLIENT_JS, "utf-16-le"))
    _write(tmp_path, "server.ts", SERVER_TS.encode() + b"// caf\xe9\n")
    result = MCPScanner().scan(tmp_path)
    assert sorted(result.scan_failures) == [
        "lone.js: invalid UTF-16",
        "server.ts: invalid UTF-8",
        "util.js: invalid UTF-8",
        "util.ts: invalid UTF-8",
    ]
    assert result.components == []


def test_a_declaration_python_x_reads_after_a_line_of_code_is_a_failure(tmp_path):
    payload = b"from +AG0AYwBw-.client import Client\n"
    fullwidth = "".join(chr(ord(letter) + 0xFEE0) for letter in "mcp")
    hidden = {
        "agent.py": b"import sys\n# coding: utf-7\n" + payload,
        # -x skips through the first line feed, whatever the line endings before it.
        "pkg/carriage.py": b"x = 1\r# coding: latin-1\ry = 2\n# coding: utf-7\n" + payload,
        # Declared latin-1 on line 1; -x reads the rest as UTF-8.
        "pkg/wide.py": b"# coding: latin-1\n" + f"from {fullwidth}.client import Client\n".encode(),
    }
    unchanged = {
        "pkg/third.py": b"x = 1\n#\n# coding: utf-7\n" + payload,
        "pkg/same.py": b"import os\n# -*- coding: utf-8 -*-\nname = 'caf\xc3\xa9'\n",
        "pkg/legacy.py": b"# coding: latin-1\nname = 'caf\xe9'\n",
        "pkg/ascii.py": b"import os\n# coding: latin-1\nname = 'plain'\n",
    }
    for location, source in {**hidden, **unchanged}.items():
        _write(tmp_path, location, source)
    assert all(_python_x_imports(source) == ["mcp.client"] for source in hidden.values())
    result = MCPScanner().scan(tmp_path)
    assert sorted(result.scan_failures) == [
        f"{location}: unsupported source encoding declaration" for location in sorted(hidden)
    ]
    assert result.components == []


def test_a_name_too_long_for_any_codec_is_refused_without_a_lookup(tmp_path):
    # The codec registry spends time per character on a name and keeps every name
    # it failed to find; 63 such 4 MiB names left 252 MiB behind after a scan.
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        span = (limits.MIB // 4) * scale
        for index in range(3):
            name = f"n{index}" + "x" * span
            _write(root, f"long{index}.py", b"# coding: " + name.encode() + b"\n")
        _write(root, "pkg/second.py", b"#!/usr/bin/env python\n# coding: " + b"y" * 65 + b"\n")
        _write(root, "pkg/skipped.py", b"x = 1\n# coding: " + b"z" * 65 + b"\n")
        _write(root, "pkg/utf8.py", b"# coding: utf-8-" + b"u" * span + b"\nVALUE = 1\n")
        roots[scale] = root
    cache = getattr(encodings, "_cache", {})
    before = sum(len(key) for key in cache)
    failures = MCPScanner().scan(roots[4]).scan_failures
    assert sum(len(key) for key in cache) - before < 1_000
    assert sorted(failures) == [
        "long0.py: unsupported source encoding declaration",
        "long1.py: unsupported source encoding declaration",
        "long2.py: unsupported source encoding declaration",
        "pkg/second.py: unsupported source encoding declaration",
        "pkg/skipped.py: unsupported source encoding declaration",
    ]
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale]).scan_failures) < 10


def test_failures_of_the_source_search_are_listed_within_the_listing_bounds(tmp_path):
    for index in range(MAX_LISTED_FAILURES + 50):
        _write(tmp_path, f"pkg/m{index:04d}.py", b"# coding: utf-7\n")
    failures = MCPScanner().scan(tmp_path).scan_failures
    assert len(failures) == MAX_LISTED_FAILURES + 1
    assert failures[-1] == (
        f"pkg/m{MAX_LISTED_FAILURES:04d}.py: unsupported source encoding declaration "
        "(and 49 more not listed)"
    )


def test_the_repository_itself_passes_the_mcp_collector():
    # Nested MCP configurations are collected wherever they are, so the benchmark's
    # deliberately malformed fixture is the one failure; the source search adds none.
    result = MCPScanner().scan(REPOSITORY)
    assert result.scan_failures == [
        "benchmarks/fixtures/mcp-malformed-coverage/project/.mcp.json: "
        "invalid JSON or duplicate keys"
    ]


# Each shape at a quarter of the syntax limit times ``scale``; at 4 it is the limit.
_COMMENT_SHAPES = {
    "open-comments": lambda scale: "/* " * (21_845 * scale),
    "newlines": lambda scale: "\n" * (65_536 * scale),
    "blank-lines": lambda scale: " \n" * (32_768 * scale),
    "short-lines": lambda scale: "a\n" * (32_768 * scale),
    "slash-star-slash": lambda scale: "/*/" * (21_845 * scale),
    "line-comments-then-block": lambda scale: (
        "//\n" * (10_922 * scale) + "/*" + "x" * (32_767 * scale) + "*/"
    ),
}


@pytest.mark.parametrize("shape", sorted(_COMMENT_SHAPES))
def test_comment_stripping_is_linear_at_the_syntax_limit(shape):
    make = _COMMENT_SHAPES[shape]
    assert scaling_ratio(lambda scale: without_js_comments(make(scale))) < 10


class _SearchCountingText(str):
    searched = 0

    def find(self, sub, start=None, end=None):  # type: ignore[override]
        begin = 0 if start is None else start
        found = super().find(sub, begin, len(self) if end is None else end)
        self.searched += (len(self) if found < 0 else found + len(sub)) - begin
        return found


@pytest.mark.parametrize(
    "text",
    [
        "//\n" * 4_000 + "/*" + "x" * 12_000 + "*/",
        "// /*\n" * 2_000 + "x" * 12_000 + "*/",
    ],
)
def test_comment_stripping_searches_for_each_block_close_once(text):
    # Every whole-line comment before a long block comment once searched the block
    # for its close again, so the work grew with the product of the two.
    counted = _SearchCountingText(text)
    assert without_js_comments(counted) == OLD_STRIPPER.sub("", text)
    assert counted.searched <= 4 * len(text)


@settings(max_examples=3_000, deadline=None)
@given(st.lists(st.sampled_from(["/", "*", "\n", " ", "\t", "a", chr(0xA0), "\x0b", "//"])))
def test_comment_stripping_matches_the_previous_expression(pieces):
    text = "".join(pieces)
    assert without_js_comments(text) == OLD_STRIPPER.sub("", text)
