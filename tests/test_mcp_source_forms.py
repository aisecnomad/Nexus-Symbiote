"""MCP servers declared in source are inventoried or recorded as gaps, never skipped silently."""

from __future__ import annotations

import codecs
import json
import os
import re
import tracemalloc
from dataclasses import replace
from pathlib import Path

import pytest

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from tests.support import scaling_ratio

MODULE = "@modelcontextprotocol/sdk/server/mcp.js"
IMPORT = f'import {{ McpServer }} from "{MODULE}";\n'
SERVER = 'const server = new McpServer({ name: "notes", version: "1.0.0" });\n'
TOOL = 'server.registerTool("read_note", {}, readNote);\n'
REQUIRE = f'const {{ McpServer }} = require("{MODULE}");\n'
INVENTORIED = [("mcp-server", "notes"), ("tool", "read_note")]
LOADED = "MCP server SDK loaded by require or dynamic import; servers and tools not inventoried"
CLIENT_LOADED = (
    "MCP client SDK loaded by require or dynamic import; servers it starts or reaches not "
    "inventoried"
)
LAUNCHED = "MCP server launched from application code; launcher not inventoried"
REACHED = "MCP server reached from application code; endpoint not inventoried"
BINDING = "unsupported MCP server SDK binding"
COMPUTED = (
    "require or dynamic import of a module name the analysis cannot read; what it loads not "
    "inventoried"
)
NAMED = "MCP SDK module named as a call argument; what the call loads not inventoried"
IMPORT_FORM = "unsupported MCP SDK import"
NAMESPACE = "unsupported use of an MCP SDK namespace"
LOW_LEVEL = "low-level MCP server tool list uncollected"
REEXPORTED = (
    "MCP SDK class re-exported; servers it builds, starts or reaches elsewhere not inventoried"
)
RECEIVER = "unresolved MCP registration receiver"
SERVER_LOADED = "MCP server module loaded dynamically; tools not inventoried"
PYTHON_CLIENT_LOADED = "MCP client module loaded dynamically; launched servers not inventoried"
PASSED_ON = (
    "MCP launcher imported without a use here; servers started or reached through it "
    "elsewhere not inventoried"
)
LAUNCHER_ELSEWHERE = (
    "MCP launcher imported from a module other than its package; servers started or "
    "reached through it not inventoried"
)
SERVER_CLASS_ELSEWHERE = (
    "MCP server class imported from a module the collector does not recognize as its "
    "own; servers built "
    "from it not inventoried"
)
SERVER_CLASS_ATTRIBUTE = (
    "MCP server class reached as an attribute; servers built from it not inventoried"
)
SERVER_CLASS_PASSED_ON = (
    "MCP server class imported without a use here; servers built from it elsewhere not inventoried"
)
BOTH = "MCP servers launched or reached from application code; not inventoried"
OVERRIDE = chr(0x202E)


def _scan(root: Path, files: dict[str, str | bytes]):
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return MCPScanner().scan(root)


def _inventory(result) -> list[tuple[str, str]]:
    return [
        (component.component_type.value, component.name)
        for component in result.components
        if isinstance(component, (MCPServerComponent, ToolComponent))
    ]


def _gap(name: str, line: int, reason: str) -> str:
    return f"{name}:{line} ({reason})"


# Each suffix tsc reads with JSX gets JSX, so the TSX grammar is shown to be the one used.
JSX = "export const view = () => <p>{server.name}</p>;\n"


@pytest.mark.parametrize(
    ("name", "extra"),
    [
        ("server.js", JSX),
        ("server.mjs", JSX),
        ("server.jsx", JSX),
        ("server.tsx", JSX),
        ("server.mts", "export const port: number = 3000;\n"),
        ("server.cts", "export const port: number = 3000;\n"),
    ],
)
def test_es_module_servers_in_every_script_suffix_are_inventoried(tmp_path, name, extra):
    result = _scan(
        tmp_path, {f"src/{name}": "#!/usr/bin/env node\n" + IMPORT + SERVER + TOOL + extra}
    )
    assert result.scan_failures == []
    assert result.surfaces_excluded == []
    assert _inventory(result) == INVENTORIED
    assert f"src/{name}" in result.surfaces_scanned
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.source_path == f"src/{name}"


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("server.cjs", REQUIRE + SERVER + TOOL),
        ("server.js", REQUIRE + SERVER + TOOL),
        ("server.ts", REQUIRE + SERVER + TOOL),
        ("template.js", f"const {{ McpServer }} = require(`{MODULE}`);\n" + SERVER + TOOL),
        ("dynamic.mjs", f'const {{ McpServer }} = await import("{MODULE}");\n' + SERVER + TOOL),
        (
            "legacy.cts",
            f'import sdk = require("{MODULE}");\nconst server = new sdk.McpServer({{}});\n',
        ),
    ],
)
def test_require_and_dynamic_imports_of_the_server_sdk_are_gaps(tmp_path, name, source):
    result = _scan(tmp_path, {name: source})
    assert result.surfaces_excluded == [_gap(name, 1, LOADED)]
    assert result.scan_failures == []
    assert _inventory(result) == []


# The module name, split so that only the marker search sees it.
NAME = 'const m = "@modelcontextprotocol/sdk/server/" + "mcp.js";\n'


@pytest.mark.parametrize(
    ("name", "load", "line"),
    [
        ("variable.cjs", "const { McpServer } = require(m);\n", 2),
        ("concatenated.cjs", 'require("@modelcontextprotocol/sdk/server/" + "mcp.js");\n', 2),
        ("template.mjs", "const { McpServer } = await import(`${m}`);\n", 2),
        ("dynamic.ts", "const sdk = await import(m);\n", 2),
        ("call.cjs", "const { McpServer } = require.call(null, m);\n", 2),
        ("apply.cjs", "const { McpServer } = require.apply(null, [m]);\n", 2),
        ("apply-list.cjs", "const { McpServer } = require.apply(null, names);\n", 2),
        ("module.cjs", "const { McpServer } = module.require(m);\n", 2),
        ("created.mjs", "const { McpServer } = createRequire(import.meta.url)(m);\n", 2),
        (
            "bound.mjs",
            "const load = createRequire(import.meta.url);\nconst { McpServer } = load(m);\n",
            3,
        ),
        (
            "assigned.mjs",
            "let load;\nload = module.createRequire(import.meta.url);\nload(m);\n",
            4,
        ),
        ("sequence.cjs", "const { McpServer } = (0, require)(m);\n", 2),
        ("asserted.ts", "const { McpServer } = (require as NodeRequire)(m);\n", 2),
        ("spread.cjs", "const { McpServer } = require(...[m]);\n", 2),
    ],
)
def test_a_module_load_the_analysis_cannot_read_is_a_gap(tmp_path, name, load, line):
    result = _scan(tmp_path, {name: NAME + load + SERVER + TOOL})
    assert result.surfaces_excluded == [_gap(name, line, COMPUTED)]
    assert result.scan_failures == []
    assert _inventory(result) == []


@pytest.mark.parametrize(
    ("load", "expected"),
    [
        (f'require.call(null, "{MODULE}");\n', LOADED),
        (f'module.require("{MODULE}");\n', LOADED),
        ('require.apply(null, ["@modelcontextprotocol/sdk/client/stdio.js"]);\n', CLIENT_LOADED),
        (f'createRequire(import.meta.url)("{MODULE}");\n', LOADED),
        (f'console.log("{MODULE}");\n', NAMED),
        (f'load("npm:{MODULE}");\n', NAMED),
    ],
)
def test_literal_module_names_in_calls_are_worded_by_what_loads_them(tmp_path, load, expected):
    result = _scan(tmp_path, {"loader.mjs": "// McpServer\n" + load})
    assert result.surfaces_excluded == [_gap("loader.mjs", 2, expected)]


def test_loads_of_other_modules_and_type_imports_are_not_gaps(tmp_path):
    other = (
        NAME + 'const z = require("zod");\nconst tools = await import("./tools.js");\n'
        "const where = require.resolve(m);\nconst url = import.meta.resolve(m);\n"
        "handler.call(null, m);\nhandler.apply(null, [m]);\n"
        f'type Sdk = typeof import("{MODULE}");\n'
        'let launch: typeof import("@modelcontextprotocol/sdk/client/stdio.js");\n'
    )
    result = _scan(
        tmp_path,
        {
            "server.mts": IMPORT + SERVER + TOOL + other,
            "plugin.mjs": "const plugin = await import(process.env.PLUGIN);\n",
        },
    )
    assert result.surfaces_excluded == []
    assert _inventory(result) == INVENTORIED


# A file that also names the scope plainly is parsed, so the specifier itself is read.
SCOPE = "// @modelcontextprotocol/ McpServer\n"


@pytest.mark.parametrize(
    ("specifier", "line"),
    [
        ("npm:@modelcontextprotocol/sdk@1.17.0/server/mcp.js", 1),
        ("npm:@modelcontextprotocol/sdk/server/mcp.js", 1),
        ("jsr:@modelcontextprotocol/sdk/server/mcp.js", 1),
        ("https://esm.sh/@modelcontextprotocol/sdk@1.17.0/server/mcp.js", 1),
        ("../node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js", 1),
        ("/srv/app/node_modules/@modelcontextprotocol/sdk/dist/cjs/server/mcp.js", 1),
        ("@modelcontextprotocol/sdk@1.17.0/server/mcp.js", 1),
        ("npm:@modelcontextprotocol/server@2.0.0", 1),
        ("https://esm.sh/%40modelcontextprotocol/sdk/server/mcp.js", 2),
        ("..\\\\node_modules\\\\@modelcontextprotocol\\\\sdk\\\\server\\\\mcp.js", 2),
        ("./node_modules/@ModelContextProtocol/SDK/server/mcp.js", 2),
    ],
)
def test_the_server_class_from_any_other_specifier_of_the_sdk_is_a_gap(tmp_path, specifier, line):
    source = f'import {{ McpServer }} from "{specifier}";\n' + SERVER + TOOL
    result = _scan(tmp_path, {"src/main.ts": (SCOPE if line == 2 else "") + source})
    assert result.surfaces_excluded == [_gap("src/main.ts", line, IMPORT_FORM)]
    assert result.scan_failures == []
    assert _inventory(result) == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'import { StdioClientTransport } from "npm:@modelcontextprotocol/sdk/client/stdio.js";\n'
            'new StdioClientTransport({ command: "npx", args: ["-y", "notes-mcp"] });\n',
            _gap("main.ts", 2, LAUNCHED),
        ),
        (
            'import * as sdk from "npm:@modelcontextprotocol/sdk@1.17.0/server/mcp.js";\n'
            "const server = new sdk[name]({});\n",
            _gap("main.ts", 2, NAMESPACE),
        ),
        (
            'const sdk = await import("https://esm.sh/@modelcontextprotocol/sdk/server/mcp.js");\n',
            _gap("main.ts", 1, LOADED),
        ),
        (
            'export * from "./node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js";\n',
            _gap("main.ts", 1, REEXPORTED),
        ),
        (
            'import { Server } from "npm:@modelcontextprotocol/sdk/server/index.js";\n',
            _gap("main.ts", 1, LOW_LEVEL),
        ),
    ],
    ids=["client", "namespace", "load", "reexport", "low-level"],
)
def test_every_rule_applies_to_every_specifier_form(tmp_path, source, expected):
    result = _scan(tmp_path, {"main.ts": source})
    assert result.surfaces_excluded == [expected]


def test_specifier_forms_fail_the_default_gate(tmp_path, runner):
    project = tmp_path / "project"
    _scan(
        project,
        {
            "src/main.ts": IMPORT.replace(MODULE, f"npm:{MODULE}") + SERVER + TOOL,
            "src/relative.mjs": IMPORT.replace(MODULE, f"../node_modules/{MODULE}") + SERVER,
            "src/server.cjs": NAME + "const { McpServer } = require(m);\n" + SERVER + TOOL,
        },
    )
    result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert result.exit_code == 1, result.output
    excluded = [line for line in result.output.splitlines() if line.startswith("  - excluded:")]
    assert excluded == [
        f"  - excluded: {_gap('src/main.ts', 1, IMPORT_FORM)} (from mcp)",
        f"  - excluded: {_gap('src/relative.mjs', 1, IMPORT_FORM)} (from mcp)",
        f"  - excluded: {_gap('src/server.cjs', 2, COMPUTED)} (from mcp)",
    ]


@pytest.mark.parametrize(
    ("construction", "name"),
    [
        ("new sdk.McpServer({ name: 'notes' })", "notes"),
        ('new sdk["McpServer"]({})', "server"),
        ("new sdk[`McpServer`]({})", "server"),
    ],
)
def test_a_namespace_import_is_collected_when_its_binding_is_exact(tmp_path, construction, name):
    source = f'import * as sdk from "{MODULE}";\nconst server = {construction};\n' + TOOL
    result = _scan(tmp_path, {"src/server.mts": source})
    assert result.surfaces_excluded == []
    assert _inventory(result) == [("mcp-server", name), ("tool", "read_note")]


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("const server = new sdk[className]({});\n", [_gap("ns.ts", 2, NAMESPACE)]),
        (
            "const { McpServer } = sdk;\nconst server = new McpServer({});\n",
            [_gap("ns.ts", 2, NAMESPACE)],
        ),
        ("register(sdk);\n", [_gap("ns.ts", 2, NAMESPACE)]),
        ("const server = new sdk.default.McpServer({});\n", [_gap("ns.ts", 2, NAMESPACE)]),
        (
            "const Server = sdk.McpServer;\nconst server = new Server({});\n",
            [_gap("ns.ts", 2, BINDING)],
        ),
        ("export default sdk;\n", [_gap("ns.ts", 2, NAMESPACE)]),
    ],
)
def test_namespace_uses_the_analysis_cannot_follow_are_gaps(tmp_path, body, expected):
    result = _scan(tmp_path, {"ns.ts": f'import * as sdk from "{MODULE}";\n' + body + TOOL})
    assert _inventory(result) == []
    gaps = [gap for gap in result.surfaces_excluded if RECEIVER not in gap]
    assert gaps == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (f'import sdk from "{MODULE}";\nconst server = new sdk.McpServer({{}});\n', IMPORT_FORM),
        (
            'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp";\n' + SERVER,
            IMPORT_FORM,
        ),
        (
            'import * as sdk from "@modelcontextprotocol/sdk/dist/esm/server/mcp.js";\n'
            "const server = new sdk.McpServer({});\n",
            IMPORT_FORM,
        ),
        (
            'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n'
            "const server = new Server({}, { capabilities: { tools: {} } });\n",
            LOW_LEVEL,
        ),
        (
            'import * as lowLevel from "@modelcontextprotocol/sdk/server/index.js";\n'
            "const server = new lowLevel.Server({}, {});\n",
            LOW_LEVEL,
        ),
        ('import { Server } from "@modelcontextprotocol/server";\n', LOW_LEVEL),
    ],
    ids=["default", "module-path", "namespace-module-path", "low-level", "low-level-ns", "v2"],
)
def test_other_import_forms_of_the_server_sdk_are_gaps(tmp_path, source, expected):
    result = _scan(tmp_path, {"server.ts": source})
    assert _inventory(result) == []
    assert [gap.split(" (", 1)[1] for gap in result.surfaces_excluded] == [f"{expected})"]


@pytest.mark.parametrize(
    "source",
    [
        f'import {{ "McpServer" as Factory }} from "{MODULE}";\n'
        + SERVER.replace("McpServer", "Factory"),
        'import { McpServer } from "@modelcontextprotocol/server";\n' + SERVER,
        f'import {{ McpServer }} from "{MODULE}";\n'
        'import * as stdio from "@modelcontextprotocol/sdk/server/stdio.js";\n'
        + SERVER
        + "await server.connect(new stdio.StdioServerTransport());\n",
        IMPORT + "export " + SERVER + "const version = 1;\nexport { version as McpServer };\n",
    ],
    ids=["string-name", "v2-module", "other-namespace-member", "exported-names"],
)
def test_supported_imports_stay_collected(tmp_path, source):
    result = _scan(tmp_path, {"server.ts": source + TOOL})
    assert result.surfaces_excluded == []
    assert _inventory(result) == INVENTORIED


@pytest.mark.parametrize(
    ("name", "use", "line"),
    [
        ("alias.ts", "const Factory = McpServer;\n", 3),
        ("subclass.ts", "class Notes extends McpServer {}\n", 3),
        ("parenthesized.ts", "const other = new (McpServer)({});\n", 3),
        ("instance.ts", "if (value instanceof McpServer) {}\n", 3),
        ("reexported.ts", "export { McpServer };\n", 3),
        ("renamed.ts", "export { McpServer as Factory };\n", 3),
        ("shorthand.ts", "export default { McpServer };\n", 3),
        ("element.tsx", "export const view = <McpServer />;\n", 3),
        ("argument.mjs", "register(McpServer);\n", 3),
    ],
)
def test_uses_of_the_server_class_other_than_construction_are_gaps(tmp_path, name, use, line):
    result = _scan(tmp_path, {name: IMPORT + SERVER + use + TOOL})
    assert result.surfaces_excluded == [_gap(name, line, BINDING)]
    assert _inventory(result) == INVENTORIED


def test_a_direct_eval_beside_sdk_imports_is_a_gap(tmp_path):
    hidden = "eval(\"server.registerTool('hidden', {}, handler)\");\n"
    comment_only = "// @modelcontextprotocol/sdk/server and McpServer, in prose\n"
    result = _scan(
        tmp_path,
        {"server.mjs": IMPORT + SERVER + hidden + TOOL, "other.mjs": comment_only + hidden},
    )
    assert result.surfaces_excluded == [
        _gap(
            "server.mjs",
            3,
            "direct eval can use the MCP SDK imports of the file; what it builds not inventoried",
        )
    ]
    assert _inventory(result) == INVENTORIED


@pytest.mark.parametrize(
    ("name", "call", "direct"),
    [
        ("server.mjs", "(eval)(code);\n", True),
        ("server.ts", "(eval as any)(code);\n", True),
        ("server.ts", "eval!(code);\n", True),
        ("server.ts", "(eval<any>)(code);\n", True),
        ("server.ts", "(eval /* c */ <any>)(code);\n", True),
        ("server.ts", "(eval<any> as any)(code);\n", True),
        ("server.mjs", "(0, eval)(code);\n", False),
        ("server.ts", "(0, eval<any>)(code);\n", False),
    ],
)
def test_a_parenthesized_or_asserted_eval_is_still_direct(tmp_path, name, call, direct):
    result = _scan(tmp_path, {name: IMPORT + SERVER + call + TOOL})
    reason = "direct eval can use the MCP SDK imports of the file; what it builds not inventoried"
    assert result.surfaces_excluded == ([_gap(name, 3, reason)] if direct else [])
    assert _inventory(result) == INVENTORIED


# Audit 2026-11-16 S6-02: the grammar gives comments as children, so a comment in
# the parentheses or the arguments was read as the callee or the module name.
@pytest.mark.parametrize(
    ("call", "direct"),
    [
        ("(eval /* c */)(code);\n", True),
        ("(/* c */ eval)(code);\n", True),
        ("(eval /* c */ as any)(code);\n", True),
        ("(0, eval /* c */)(code);\n", False),
    ],
)
def test_a_comment_beside_eval_does_not_hide_a_direct_eval(tmp_path, call, direct):
    result = _scan(tmp_path, {"server.ts": IMPORT + SERVER + call + TOOL})
    reason = "direct eval can use the MCP SDK imports of the file; what it builds not inventoried"
    assert result.surfaces_excluded == ([_gap("server.ts", 3, reason)] if direct else [])
    assert _inventory(result) == INVENTORIED


@pytest.mark.parametrize(
    "load",
    [
        f'(require /* c */)(/* c */ "{MODULE}");\n',
        f'require(/* c */ "{MODULE}");\n',
        f'await import(/* webpackChunkName: "mcp" */ "{MODULE}");\n',
        f'require.call(null, /* c */ "{MODULE}");\n',
        f'require.apply(null, [/* c */ "{MODULE}"]);\n',
    ],
)
def test_a_comment_beside_a_module_load_does_not_hide_the_module(tmp_path, load):
    result = _scan(tmp_path, {"server.mjs": load})
    assert result.surfaces_excluded == [_gap("server.mjs", 1, LOADED)]


def test_a_comment_before_a_tool_name_does_not_hide_the_name(tmp_path):
    tool = 'server.registerTool(/* c */ "read_note", {}, readNote);\n'
    result = _scan(tmp_path, {"server.ts": IMPORT + SERVER + tool})
    assert result.surfaces_excluded == []
    assert _inventory(result) == INVENTORIED


@pytest.mark.parametrize(
    ("name", "source", "reason"),
    [
        (
            "server.mjs",
            'await import("https://esm.sh/@modelcontextprotocol/server?bundle");\n',
            LOADED,
        ),
        (
            "server.ts",
            'import { Server } from "https://esm.sh/@modelcontextprotocol/sdk/server?dev";\n',
            LOW_LEVEL,
        ),
        ("client.cjs", 'require("@modelcontextprotocol/client#main");\n', CLIENT_LOADED),
    ],
)
def test_a_query_or_fragment_does_not_hide_the_module_kind(tmp_path, name, source, reason):
    result = _scan(tmp_path, {name: source})
    assert result.surfaces_excluded == [_gap(name, 1, reason)]


def test_a_method_named_like_the_server_class_does_not_shadow_it(tmp_path):
    method = "export const plugin = {\n  McpServer() {\n    const Factory = McpServer;\n  },\n};\n"
    result = _scan(tmp_path, {"server.mjs": IMPORT + method})
    assert result.surfaces_excluded == [_gap("server.mjs", 4, BINDING)]


def test_names_in_type_syntax_are_not_uses(tmp_path):
    types = (
        "const typed: McpServer = new McpServer({});\n"
        "let callback: (McpServer: number) => void;\n"
        "type Instance = InstanceType<typeof McpServer>;\n"
        "value as typeof McpServer;\n"
        "value satisfies Partial<typeof McpServer>;\n"
        "interface Extended extends McpServer {}\n"
        "declare const ambient: typeof McpServer;\n"
        "function overload(McpServer: string): void;\n"
        "function overload(value: unknown) {}\n"
        "export type { McpServer };\n"
    )
    result = _scan(tmp_path, {"server.ts": IMPORT + SERVER + types + TOOL})
    assert result.surfaces_excluded == []
    assert ("tool", "read_note") in _inventory(result)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (f'export {{ McpServer }} from "{MODULE}";\n', [_gap("index.ts", 1, REEXPORTED)]),
        (f'export * from "{MODULE}";\n', [_gap("index.ts", 1, REEXPORTED)]),
        (f'export * as sdk from "{MODULE}";\n', [_gap("index.ts", 1, REEXPORTED)]),
        (
            'export { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\n',
            [_gap("index.ts", 1, REEXPORTED)],
        ),
        (f'export type {{ McpServer }} from "{MODULE}";\n', []),
        (f'export {{ type McpServer }} from "{MODULE}";\n', []),
        ('export { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";\n', []),
        ('export * from "@modelcontextprotocol/sdk/types.js";\nexport { McpServer };\n', []),
    ],
    ids=["named", "star", "namespace", "transport", "type", "type-specifier", "other", "types"],
)
def test_reexports_of_sdk_classes_are_gaps(tmp_path, source, expected):
    result = _scan(tmp_path, {"index.ts": source})
    assert result.surfaces_excluded == expected
    assert result.scan_failures == []


@pytest.mark.parametrize(
    ("name", "source", "expected"),
    [
        (
            "client.ts",
            'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\n'
            'const transport = new StdioClientTransport({ command: "npx", args: ["-y", "x"] });\n',
            [_gap("client.ts", 2, LAUNCHED)],
        ),
        (
            "client.mjs",
            'import * as sse from "@modelcontextprotocol/sdk/client/sse.js";\n'
            'const transport = new sse.SSEClientTransport(new URL("https://example.com/sse"));\n',
            [_gap("client.mjs", 2, REACHED)],
        ),
        (
            "client.js",
            "import { StreamableHTTPClientTransport as Http } from "
            '"@modelcontextprotocol/sdk/client/streamableHttp.js";\n'
            "const transport = new Http(endpoint);\n",
            [_gap("client.js", 2, REACHED)],
        ),
        (
            "client.cjs",
            'const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");\n',
            [_gap("client.cjs", 1, CLIENT_LOADED)],
        ),
        (
            "typed.ts",
            'import type { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\n'
            "let transport: StdioClientTransport;\n",
            [],
        ),
        (
            "unused.ts",
            'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\n',
            [],
        ),
    ],
)
def test_client_transports_that_start_or_reach_a_server_are_gaps(tmp_path, name, source, expected):
    result = _scan(tmp_path, {name: source})
    assert result.surfaces_excluded == expected
    assert result.scan_failures == []
    assert _inventory(result) == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            f'import {{ default as sdk }} from "{MODULE}";\nconst server = new sdk.McpServer({{}});\n',
            [_gap("index.ts", 1, IMPORT_FORM)],
        ),
        (
            'import { default as stdio } from "@modelcontextprotocol/sdk/client/stdio.js";\n',
            [_gap("index.ts", 1, IMPORT_FORM)],
        ),
        (f'export {{ default }} from "{MODULE}";\n', [_gap("index.ts", 1, REEXPORTED)]),
        (f'export {{ default as Mcp }} from "{MODULE}";\n', [_gap("index.ts", 1, REEXPORTED)]),
        (
            'import { default as types } from "@modelcontextprotocol/sdk/types.js";\n'
            'export { default } from "@modelcontextprotocol/sdk/types.js";\n' + IMPORT + SERVER,
            [],
        ),
    ],
    ids=["import", "client-import", "reexport", "reexport-alias", "other-module"],
)
def test_the_default_export_of_a_server_or_client_module_is_a_gap(tmp_path, source, expected):
    result = _scan(tmp_path, {"index.ts": source})
    assert result.surfaces_excluded == expected
    assert result.scan_failures == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'import * as stdio from "@modelcontextprotocol/sdk/client/stdio.js";\n'
            "const T = stdio[Object.keys(stdio)[0]];\n"
            'new T({ command: "npx", args: ["-y", "notes-mcp"] });\n',
            _gap("client.mjs", 2, NAMESPACE),
        ),
        (
            "import { Stdio\\u0043lientTransport as T } from "
            '"@modelcontextprotocol/sdk/client/stdio.js";\n'
            'new T({ command: "npx", args: ["-y", "notes-mcp"] });\n',
            _gap("client.mjs", 2, LAUNCHED),
        ),
        (
            'import * as client from "@modelcontextprotocol/client";\n'
            'new client[kind]({ command: "npx" });\n',
            _gap("client.mjs", 2, NAMESPACE),
        ),
    ],
    ids=["computed-member", "escaped-name", "client-package"],
)
def test_client_modules_are_parsed_without_a_transport_class_name(tmp_path, source, expected):
    result = _scan(tmp_path, {"client.mjs": source})
    assert result.surfaces_excluded == [expected]
    assert result.scan_failures == []


def test_javascript_the_grammar_cannot_read_is_a_gap_and_typescript_a_failure(tmp_path):
    broken = IMPORT + "const server = new McpServer({};\n"
    comparison = IMPORT + SERVER + TOOL + "const ordered = low < value > (high);\n"
    result = _scan(
        tmp_path,
        {
            "broken.mjs": broken,
            "broken.mts": broken,
            "compare.js": comparison,
            "src/compare.ts": comparison,
        },
    )
    assert result.surfaces_excluded == [
        "broken.mjs: JavaScript the TypeScript grammar cannot parse; servers and tools in the "
        "file not inventoried",
        _gap(
            "compare.js",
            4,
            "JavaScript comparison the TypeScript grammar reads as type arguments; servers and "
            "tools in the file not inventoried",
        ),
    ]
    assert result.scan_failures == ["broken.mts: invalid TypeScript syntax"]
    # TypeScript reads the comparison as a call too, so its server is inventoried.
    assert [c.source_path for c in result.components if isinstance(c, ToolComponent)] == [
        "src/compare.ts"
    ]


def test_names_are_read_as_javascript_reads_them(tmp_path):
    escaped = (
        f'import {{ \\u004dcpServer as Factory }} from "{MODULE}";\n'
        "const \\u{73}erver = new Factory({});\n" + TOOL
    )
    hex_module = (
        "// @modelcontextprotocol/sdk/server is the module below\n"
        'import { McpServer } from "@modelcontextprotocol\\x2fsdk/server/mcp.js";\n' + SERVER + TOOL
    )
    continued = 'import { McpServer } from "@modelcontextprotocol/sdk/server/\\\nmcp.js";\n'
    identity = 'import { McpServer } from "@modelcontextprotocol/sdk/server/\\mcp.js";\n'
    octal = "@modelcontextprotocol/sdk/server/mcp\\056js"
    result = _scan(
        tmp_path,
        {
            "escaped.ts": escaped,
            "hex.ts": hex_module,
            "continued.ts": continued + SERVER + TOOL,
            "identity.ts": identity + SERVER + TOOL,
            "nul.ts": f'import {{ McpServer }} from "{MODULE}\\0";\n' + SERVER,
            "octal.js": f'import {{ McpServer }} from "{octal}";\n',
            "reexport.ts": f'export {{ McpServer }} from "{octal}";\n',
        },
    )
    unread = "module specifier the analysis cannot read"
    assert sorted(result.surfaces_excluded) == [
        _gap("nul.ts", 1, IMPORT_FORM),
        _gap("octal.js", 1, unread),
        _gap("reexport.ts", 1, unread),
    ]
    tools = sorted(c.source_path for c in result.components if isinstance(c, ToolComponent))
    assert tools == ["continued.ts", "escaped.ts", "hex.ts", "identity.ts"]
    servers = [c for c in result.components if isinstance(c, MCPServerComponent)]
    assert sorted((server.source_path, server.name) for server in servers) == [
        ("continued.ts", "notes"),
        ("escaped.ts", "server"),
        ("hex.ts", "notes"),
        ("identity.ts", "notes"),
    ]
    assert {server.properties["binding"] for server in servers} == {"server"}


def test_shadowed_names_and_other_imports_are_not_sdk_uses(tmp_path):
    source = (
        'import React from "react";\n'
        f'import {{ McpServer, ResourceTemplate }} from "{MODULE}";\n'
        'import * as types from "@modelcontextprotocol/sdk/types.js";\n'
        + SERVER
        + "function wrap(McpServer: unknown) { return McpServer; }\n"
        "const template = new ResourceTemplate('notes://{id}', { list: undefined });\n"
        "const schema = types.CallToolRequestSchema;\n"
        "register(types, <React.Fragment />);\n" + TOOL
    )
    result = _scan(tmp_path, {"server.tsx": source})
    assert result.scan_failures == []
    assert result.surfaces_excluded == []
    assert _inventory(result) == INVENTORIED


@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("name", ["server.mjs", "server.tsx", "server.cjs"])
def test_new_suffixes_are_searched_as_tsc_decodes_them(tmp_path, name, codec):
    source = (REQUIRE if name.endswith(".cjs") else IMPORT) + SERVER + TOOL
    marks = {"utf-16-le": codecs.BOM_UTF16_LE, "utf-16-be": codecs.BOM_UTF16_BE}
    plain = _scan(tmp_path / "plain", {name: source})
    wide = _scan(tmp_path / "wide", {name: marks[codec] + source.encode(codec)})
    assert wide.scan_failures == plain.scan_failures == []
    assert wide.surfaces_excluded == plain.surfaces_excluded
    assert _inventory(wide) == _inventory(plain)
    assert (_inventory(wide) == []) is name.endswith(".cjs")


def test_files_that_only_mention_the_sdk_produce_nothing(tmp_path):
    hidden_server = IMPORT + SERVER + TOOL
    result = _scan(
        tmp_path,
        {
            "notes.mjs": "// mentions mcp in a comment\nexport const label = 'mcp';\n",
            "readme.js": (
                "// see @modelcontextprotocol/sdk/server and McpServer in the docs\n"
                "const text = 'new McpServer() from @modelcontextprotocol/server';\n"
                "module.exports = { text };\n"
            ),
            "launch.cjs": (
                "// spawns @modelcontextprotocol/server-filesystem through a ClientTransport\n"
                "module.exports = ['npx', '@modelcontextprotocol/server-filesystem'];\n"
            ),
            "tests/fixtures/server.mjs": REQUIRE,
            "src/__tests__/server.tsx": hidden_server,
            "test/server.cjs": REQUIRE,
            "dist/server.js": REQUIRE,
            "build/server.mjs": REQUIRE,
            "src/server.test.mjs": REQUIRE,
            "src/server.spec.cjs": REQUIRE,
            "src/server.d.mts": IMPORT,
            "node_modules/pkg/server.mjs": REQUIRE,
        },
    )
    assert result.scan_failures == []
    assert result.surfaces_excluded == ["node_modules: default collection exclude; not collected"]
    assert _inventory(result) == []
    # As before, only server analysis skips __tests__: an SDK import there is a client
    # reference. The excluded dependency tree prevents a complete empty-config report.
    assert result.surfaces_scanned == ["src/__tests__/server.tsx"]


@pytest.mark.parametrize(
    "source",
    [
        'import importlib\nimportlib.import_module("mcp.server.fastmcp")\n',
        'from importlib import import_module\nmodule = import_module("fastmcp")\n',
        '__import__("mcp", fromlist=["server"])\n',
        'import importlib\nimportlib.import_module(".fastmcp", package="mcp.server")\n',
        'import importlib as loader\nloader.import_module(name="mcp.server.mcpserver")\n',
        'from importlib import import_module as load\nload("fastmcp.server")\n',
        'from builtins import __import__ as load\nload("mcp.server")\n',
        'import importlib\nimportlib.import_module(f"mcp.server.fastmcp")\n',
        'import importlib\nimportlib.import_module("..server.fastmcp", "mcp.types")\n',
        '__import__("server.fastmcp", {"__package__": "mcp"}, None, ["FastMCP"], 1)\n',
        '__import__("mcpserver", globals={"__name__": "mcp.server.app"}, level=1)\n',
        '__import__("mcpserver", {"__name__": "mcp.server", "__path__": []}, None, [], 1)\n',
        'import pkgutil\nFastMCP = pkgutil.resolve_name("mcp.server.fastmcp:FastMCP")\n',
        'from pkgutil import resolve_name as resolve\nresolve("fastmcp:FastMCP")\n',
    ],
)
def test_python_dynamic_imports_of_an_mcp_server_module_are_gaps(tmp_path, source):
    result = _scan(tmp_path, {"pkg/server.py": source})
    assert result.surfaces_excluded == [f"pkg/server.py: {SERVER_LOADED}"]
    assert result.surfaces_scanned == ["pkg/server.py"]
    assert _inventory(result) == []


@pytest.mark.parametrize(
    "source",
    [
        'import importlib\nimportlib.import_module("mcp.client.stdio")\n',
        'import importlib\nimportlib.import_module("agents.mcp")\n',
        '__import__("langchain_mcp_adapters.client")\n',
        'import importlib\nimportlib.import_module("pydantic_ai.mcp")\n',
    ],
)
def test_python_dynamic_imports_of_an_mcp_client_module_are_gaps(tmp_path, source):
    result = _scan(tmp_path, {"pkg/client.py": source})
    assert result.surfaces_excluded == [f"pkg/client.py: {PYTHON_CLIENT_LOADED}"]


@pytest.mark.parametrize(
    "source",
    [
        'import importlib\nload = importlib.import_module\nload("mcp.server.fastmcp")\n',
        'import importlib\nfirst = importlib.import_module\nsecond = first\nsecond("mcp.server")\n',
        'second = first\nfirst = __import__\nsecond("fastmcp")\n',
        "from importlib import import_module as im\nload = im\nload('mcp.server.fastmcp')\n",
        "import importlib as il\nload: object = il.import_module\nload('mcp.server')\n",
        "import pkgutil\nif (load := pkgutil.resolve_name):\n    load('mcp.server.fastmcp:FastMCP')\n",
        (
            "import importlib\ndef make():\n    load = importlib.import_module\n"
            "    return load('mcp.server.fastmcp')\n"
        ),
        "import importlib\nload, other = importlib.import_module, 1\nload('mcp.server.fastmcp')\n",
        (
            "import importlib\n[first, (load, *rest)] = 1, [2, importlib.import_module]\n"
            "load('mcp.server')\n"
        ),
        "import importlib\ndef f(load=importlib.import_module):\n    load('mcp.server.fastmcp')\n",
        (
            "from importlib import import_module\ndef f(a, *, load=import_module):\n"
            "    load('fastmcp')\n"
        ),
        "import importlib\nf = lambda load=importlib.import_module: load('mcp.server')\n",
        (
            "import importlib\nfor load in (importlib.import_module,):\n"
            "    load('mcp.server.fastmcp')\n"
        ),
        (
            "import importlib\nloaders = [importlib.import_module]\nfor load in loaders:\n"
            "    load('mcp.server')\n"
        ),
        "import importlib\n[load('mcp.server') for load in {importlib.import_module}]\n",
        (
            "import contextlib, importlib\n"
            "with contextlib.nullcontext(importlib.import_module) as load:\n"
            "    load('mcp.server.fastmcp')\n"
        ),
        "import importlib\nwith importlib.import_module as (load, other):\n    load('fastmcp')\n",
    ],
    ids=[
        "assigned",
        "chain",
        "reverse-order",
        "from-import",
        "annotated",
        "walrus",
        "local",
        "tuple-unpacking",
        "nested-unpacking",
        "default",
        "keyword-only-default",
        "lambda-default",
        "for-target",
        "for-over-a-name",
        "comprehension-target",
        "with-argument",
        "with-target",
    ],
)
def test_python_dynamic_imports_through_an_assigned_loader_are_gaps(tmp_path, source):
    result = _scan(tmp_path, {"pkg/server.py": source + "mcp_note = 1\n"})
    assert result.surfaces_excluded == [f"pkg/server.py: {SERVER_LOADED}"]
    assert result.scan_failures == []


@pytest.mark.parametrize(
    "source",
    [
        (
            "import importlib\ndef run(load):\n    return load('mcp.server.fastmcp')\n"
            "run(importlib.import_module)\n"
        ),
        (
            "import importlib\ndef run(*, load):\n    return load('fastmcp')\n"
            "run(load=importlib.import_module)\n"
        ),
        (
            "import importlib\nmatch importlib.import_module:\n    case load:\n"
            "        load('mcp.server.fastmcp')\n"
        ),
        (
            "import importlib\nmatch [importlib.import_module]:\n    case [load]:\n"
            "        load(name='mcp.server')\n"
        ),
        (
            "import importlib\nloaders = {'x': importlib.import_module}\n"
            "loaders['x']('mcp.server.fastmcp')\n"
        ),
        "import importlib\nself.load = importlib.import_module\nself.load('mcp.server')\n",
        "def make():\n    return __import__\nmake()('fastmcp.server')\n",
        "load = make_loader()\nload('mcp.server:FastMCP')\n",
        "import importlib\nload = importlib.reload\nload('mcp.server')\n",
        "find('mcp')\n",
    ],
    ids=[
        "argument",
        "keyword-argument",
        "match-capture",
        "match-sequence",
        "container",
        "attribute",
        "returned",
        "unknown-callee",
        "other-attribute",
        "top-level-package",
    ],
)
def test_any_call_whose_first_argument_names_an_mcp_server_module_is_a_gap(tmp_path, source):
    # Whatever the callee is, so a loader no binding shows still leaves a gap.
    result = _scan(tmp_path, {"pkg/server.py": source + "mcp_note = 1\n"})
    assert result.surfaces_excluded == [f"pkg/server.py: {SERVER_LOADED}"]
    assert result.scan_failures == []
    assert _inventory(result) == []


@pytest.mark.parametrize(
    "source",
    [
        "import functools, importlib\nf = functools.partial(importlib.import_module, 'mcp.server.fastmcp')\n",
        "import importlib\nlist(map(importlib.import_module, ['mcp.server.fastmcp']))\n",
        (
            "import importlib, threading\n"
            "threading.Thread(target=importlib.import_module, args=('mcp.server.fastmcp',))\n"
        ),
        "import importlib\nFastMCP = importlib.import_module\nFastMCP('mcp.server.fastmcp')\n",
        'import importlib\nimportlib.reload(mcp_module)\nprint("x", "mcp.server")\n',
        (
            "import importlib, threading\n"
            "threading.Thread(target=importlib.import_module, kwargs={'name': 'fastmcp'})\n"
        ),
        "import importlib\nimportlib.import_module(*['mcp.server.fastmcp'])\n",
        "import importlib\nimportlib.import_module(**{'name': 'mcp.server'})\n",
        "run(*('fastmcp.server',))\n",
        "__import__(*['server', {'__package__': 'mcp'}, None, None, 1])\n",
        "__import__(**{'name': 'server', 'globals': {'__package__': 'mcp'}, 'level': 1})\n",
    ],
    ids=[
        "partial",
        "map",
        "thread-target",
        "loader-named-like-a-server-class",
        "later-argument",
        "thread-target-keywords",
        "starred-argument",
        "double-starred-argument",
        "starred-argument-of-another-callee",
        "starred-relative-name",
        "double-starred-relative-name",
    ],
)
def test_a_literal_in_any_argument_position_is_a_gap(tmp_path, source):
    result = _scan(tmp_path, {"pkg/server.py": source + "mcp_note = 1\n"})
    assert result.surfaces_excluded == [f"pkg/server.py: {SERVER_LOADED}"]


@pytest.mark.parametrize(
    "source",
    [
        "import logging\nlogging.getLogger('mcp').setLevel(30)\n",
        "from logging import getLogger\ngetLogger('mcp.server')\n",
    ],
    ids=["logging-module", "imported-getLogger"],
)
def test_a_logger_named_after_the_sdk_is_not_a_gap(tmp_path, source):
    result = _scan(tmp_path, {"pkg/quiet.py": source + "mcp_note = 1\n"})
    assert result.surfaces_excluded == []


def test_a_server_named_mcp_is_inventoried_without_a_gap(tmp_path):
    source = (
        "from mcp.server.fastmcp import FastMCP\nserver = FastMCP('mcp')\n\n"
        "@server.tool()\ndef hello() -> str:\n    return 'hi'\n"
    )
    result = _scan(tmp_path, {"pkg/server.py": source})
    assert result.surfaces_excluded == []
    assert _inventory(result) == [("mcp-server", "mcp"), ("tool", "hello")]


def test_any_call_whose_first_argument_names_an_mcp_client_module_is_a_gap(tmp_path):
    source = "def run(load):\n    load('agents.mcp')\nrun(__import__)\n"
    result = _scan(tmp_path, {"pkg/client.py": source})
    assert result.surfaces_excluded == [f"pkg/client.py: {PYTHON_CLIENT_LOADED}"]


def test_following_loader_aliases_is_linear_in_their_number(tmp_path):
    roots = {}
    for scale in (1, 4):
        count = 3_000 * scale
        chain = "".join(f"a{index + 1} = a{index}\n" for index in reversed(range(count)))
        roots[scale] = tmp_path / f"scale-{scale}"
        _scan(
            roots[scale],
            {
                "pkg/server.py": f"import importlib\n{chain}a0 = importlib.import_module\n"
                f"a{count}('mcp.server')\n"
            },
        )
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale])) < 10
    assert MCPScanner().scan(roots[4]).surfaces_excluded == [f"pkg/server.py: {SERVER_LOADED}"]


def test_following_unpacked_loader_bindings_is_linear_in_their_size(tmp_path):
    # Each unpacking binds every name to every value, through one joint node.
    roots = {}
    for scale in (1, 4):
        count = 2_000 * scale
        targets = ", ".join(f"t{index}" for index in range(count))
        values = ", ".join(f"v{index}" for index in range(count))
        roots[scale] = tmp_path / f"scale-{scale}"
        _scan(
            roots[scale],
            {
                "pkg/server.py": f"import importlib\nv0 = importlib.import_module\n"
                f"{targets} = {values}\nt{count - 1}('mcp.server')\n"
            },
        )
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale])) < 10
    assert MCPScanner().scan(roots[4]).surfaces_excluded == [f"pkg/server.py: {SERVER_LOADED}"]


@pytest.mark.parametrize(
    "source",
    [
        'import importlib\nname = "mcp.server"\nimportlib.import_module(name)\n',
        'import importlib\nimportlib.import_module("mcp.types")\n',
        'import importlib\nimportlib.import_module("mcpx.server")\nimport_module("fastmcpx")\n',
        "text = \"importlib.import_module('mcp.server')\"\n",
        'import logging\nlogging.getLogger(level="mcp.server")\nlog("mcp.serverx")\n',
        '__import__("server.fastmcp", {"__package__": "myapp"}, None, [], 1)\n',
        'import pkgutil\npkgutil.resolve_name("mcpx.server:App")\n',
        '__import__("server.fastmcp", {"__package__": "mcp"}, None, [], 1000000000000)\n',
        '__import__("server.fastmcp", globals(), None, [], 1)\n',
    ],
    ids=[
        "computed",
        "types",
        "lookalikes",
        "string",
        "other-keyword",
        "relative",
        "resolve",
        "level-beyond-package",
        "globals-unknown",
    ],
)
def test_python_imports_that_load_no_mcp_server_module_are_not_gaps(tmp_path, source):
    result = _scan(tmp_path, {"pkg/loader.py": source})
    assert result.surfaces_excluded == []
    assert result.scan_failures == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "from mcp import ClientSession, StdioServerParameters\n"
            'params = StdioServerParameters(command="npx", args=["-y", "notes-mcp@1.0.0"])\n',
            [LAUNCHED],
        ),
        (
            "from mcp.client.stdio import StdioServerParameters as Params\n"
            'params = Params(command="uvx", args=["notes-mcp"])\n',
            [LAUNCHED],
        ),
        ("from mcp import *\nparams = StdioServerParameters(command='npx')\n", [LAUNCHED]),
        ("import mcp\nparams = mcp.StdioServerParameters(command='npx')\n", [LAUNCHED]),
        ("from mcp import StdioServerParameters\nfactory = StdioServerParameters\n", [LAUNCHED]),
        (
            "from agents.mcp import MCPServerSse, MCPServerStdio\n"
            "local = MCPServerStdio(params={'command': 'npx', 'args': ['-y', 'notes-mcp']})\n"
            "remote = MCPServerSse(params={'url': 'https://example.com/sse'})\n",
            [LAUNCHED, REACHED],
        ),
        (
            "from agents import mcp\n"
            "remote = mcp.MCPServerStreamableHttp(params={'url': 'https://example.com/mcp'})\n",
            [REACHED],
        ),
        (
            "from pydantic_ai.mcp import MCPServerStdio\n"
            "server = MCPServerStdio('npx', args=['-y', 'notes-mcp'])\n",
            [LAUNCHED],
        ),
        (
            "from langchain_mcp_adapters.client import MultiServerMCPClient\n"
            "client = MultiServerMCPClient({'notes': {'command': 'npx', 'transport': 'stdio'}})\n",
            [BOTH],
        ),
        (
            "from mcp.client.sse import sse_client\n"
            "from mcp.client.streamable_http import streamablehttp_client\n"
            "async def main():\n"
            "    async with sse_client('https://example.com/sse') as streams:\n"
            "        pass\n"
            "    async with streamablehttp_client('https://example.com/mcp') as streams:\n"
            "        pass\n",
            [REACHED],
        ),
    ],
    ids=[
        "stdio-parameters",
        "submodule-alias",
        "star-import",
        "qualified",
        "rebound",
        "openai-agents",
        "openai-agents-attribute",
        "pydantic-ai",
        "langchain",
        "sdk-transports",
    ],
)
def test_python_code_that_starts_or_reaches_a_server_is_a_gap(tmp_path, source, expected):
    result = _scan(tmp_path, {"pkg/agent.py": source})
    assert result.surfaces_excluded == [f"pkg/agent.py: {reason}" for reason in expected]
    assert result.scan_failures == []
    assert "pkg/agent.py" in result.surfaces_scanned


@pytest.mark.parametrize(
    "source",
    [
        "class StdioServerParameters:\n    pass\nparams = StdioServerParameters()\nmcp_note = 1\n",
        "from mcp import *\nmcp_note = 1\n",
        "self.sse_client = make()\nself.sse_client.get('/events')\n",
        "from tools import *\nwebsocket_client = connect()\n",
    ],
    ids=["local-class", "star-import-only", "function-attribute", "function-name-bound"],
)
def test_python_launcher_names_that_launch_nothing_are_not_gaps(tmp_path, source):
    result = _scan(tmp_path, {"pkg/agent.py": source})
    assert result.surfaces_excluded == []
    assert result.scan_failures == []


@pytest.mark.parametrize(
    "source",
    [
        (
            "from mcp import StdioServerParameters\n"
            "def connect(params: StdioServerParameters) -> StdioServerParameters:\n"
            "    return params\n"
        ),
        "from mcp import StdioServerParameters\n",
        "from pydantic_ai import Agent\nfrom pydantic_ai.mcp import MCPServerStdio\nagent = Agent('m')\n",
        'from agents.mcp import MCPServerStdio\n__all__ = ["MCPServerStdio"]\n',
        "from mcp import StdioServerParameters as StdioServerParameters\n",
        (
            "try:\n    from agents.mcp import MCPServerStdio as Launcher\nexcept ImportError:\n"
            "    Launcher = None\n"
        ),
    ],
    ids=["annotation", "import-only", "unused", "all", "explicit-re-export", "compat-shim"],
)
def test_a_python_launcher_imported_without_a_use_is_passed_on_and_a_gap(tmp_path, source):
    result = _scan(tmp_path, {"pkg/__init__.py": source})
    assert result.surfaces_excluded == [f"pkg/__init__.py: {PASSED_ON}"]
    assert result.scan_failures == []


def test_a_python_launcher_re_exported_by_a_local_module_fails_the_gates(tmp_path, runner):
    project = tmp_path / "project"
    files = {
        "CLAUDE.md": "# Notes\n",
        "tools/__init__.py": 'from agents.mcp import MCPServerStdio\n__all__ = ["MCPServerStdio"]\n',
        "app/main.py": "from agents import Agent\nfrom tools import MCPServerStdio\n"
        "async def main():\n"
        "    async with MCPServerStdio(params={'command': 'npx', 'args': ['-y', 'x']}) as s:\n"
        "        Agent(name='a', mcp_servers=[s])\n",
    }
    _scan(project, files)
    output = tmp_path / "agentbom.json"
    result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert result.exit_code == 1, result.output
    completeness = json.loads(output.read_text())["metadata"]["completeness"]
    assert completeness["scanner_status"]["mcp"] == "partial"
    assert completeness["surfaces_excluded"] == [
        f"app/main.py: {LAUNCHER_ELSEWHERE}",
        f"tools/__init__.py: {PASSED_ON}",
    ]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import tools\ntools.MCPServerStdio(params={'command': 'npx'})\n", [LAUNCHED]),
        ("from . import compat\ncompat.sdk.StdioServerParameters(command='npx')\n", [LAUNCHED]),
        ("from .compat import MCPServerStdio\nMCPServerStdio(params={})\n", [LAUNCHER_ELSEWHERE]),
        ("from mylib import MCPServerStdio\nserver = MCPServerStdio()\n", [LAUNCHER_ELSEWHERE]),
        ("params = settings.StdioServerParameters(command='npx')\n", [LAUNCHED]),
    ],
    ids=["imported-module", "relative-module", "relative-name", "other-package", "any-value"],
)
def test_a_python_launcher_reached_through_an_imported_module_is_a_gap(tmp_path, source, expected):
    result = _scan(tmp_path, {"pkg/agent.py": source + "mcp_note = 1\n"})
    assert result.surfaces_excluded == [f"pkg/agent.py: {reason}" for reason in expected]


@pytest.mark.parametrize(
    "source",
    [
        "from mcp.server.fastmcp import FastMCP\n",
        "from fastmcp import FastMCP as FastMCP\n",
        (
            "from mcp.server.fastmcp import FastMCP\ndef build(server: FastMCP) -> FastMCP:\n"
            "    return server\n"
        ),
    ],
    ids=["import-only", "explicit-re-export", "annotation"],
)
def test_a_python_server_class_imported_without_a_use_is_a_gap(tmp_path, source):
    result = _scan(tmp_path, {"core/__init__.py": source})
    assert result.surfaces_excluded == [f"core/__init__.py: {SERVER_CLASS_PASSED_ON}"]
    assert _inventory(result) == []


def test_a_python_server_class_used_where_imported_is_not_passed_on(tmp_path):
    source = (
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
        "@mcp.tool()\ndef add(a: int) -> int:\n    return a\n"
    )
    result = _scan(tmp_path, {"core/server.py": source})
    assert result.surfaces_excluded == []
    assert _inventory(result) == [("mcp-server", "x"), ("tool", "add")]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("from core import FastMCP\nevil = FastMCP('evil')\n", [SERVER_CLASS_ELSEWHERE]),
        ("from . import MCPServer\n", [SERVER_CLASS_ELSEWHERE]),
        (
            "from core import FastMCP as Server\ndef build(s: Server) -> None: ...\n",
            [SERVER_CLASS_ELSEWHERE],
        ),
        ("from core import *\nevil = FastMCP('evil')\n", [SERVER_CLASS_ELSEWHERE]),
        ("from tools import *\nMCPServerStdio(params={})\n", [LAUNCHER_ELSEWHERE]),
        ("import core\nevil = core.FastMCP('evil')\n", [SERVER_CLASS_ATTRIBUTE]),
        ("def build(module):\n    return module.MCPServer('evil')\n", [SERVER_CLASS_ATTRIBUTE]),
        ("from pydantic_ai.mcp import MCPServer\ndef run(s: MCPServer) -> None: ...\n", []),
        ("from core import *\nfrom tools import *\n", []),
    ],
    ids=[
        "used",
        "relative",
        "annotation-only",
        "star-import",
        "launcher-star-import",
        "module-attribute",
        "parameter-attribute",
        "launcher-base-class",
        "star-imports-only",
    ],
)
def test_a_python_server_class_from_another_module_is_a_gap(tmp_path, source, expected):
    # None of these files names the SDK; the class name alone has it read.
    assert "mcp" not in source.replace("pydantic_ai.mcp", "")
    result = _scan(tmp_path, {"app/server.py": source})
    assert result.surfaces_excluded == [f"app/server.py: {reason}" for reason in expected]
    assert result.scan_failures == []
    assert _inventory(result) == []


@pytest.mark.parametrize(
    "module",
    [
        "mcp.server.lowlevel_whatever",
        "fastmcp.contrib.x",
        "mcp.shared",
        "mcp",
        "fastmcp.server.server.extra",
    ],
)
def test_a_python_server_class_from_an_unrecognized_sdk_submodule_is_a_gap(tmp_path, module):
    source = (
        f"from {module} import FastMCP\nevil = FastMCP('evil')\n"
        "@evil.tool()\ndef run_shell(cmd: str) -> str:\n    return cmd\n"
    )
    result = _scan(tmp_path, {"app/server.py": source})
    assert result.surfaces_excluded == [f"app/server.py: {SERVER_CLASS_ELSEWHERE}"]
    assert _inventory(result) == []


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("mcp.server", "FastMCP"),
        ("mcp.server.fastmcp", "FastMCP"),
        ("mcp.server.fastmcp.server", "FastMCP"),
        ("fastmcp", "FastMCP"),
        ("fastmcp.server", "FastMCP"),
        ("fastmcp.server.server", "FastMCP"),
        ("mcp.server.mcpserver", "MCPServer"),
    ],
)
def test_a_python_server_class_from_a_recognized_module_is_inventoried(tmp_path, module, name):
    source = (
        f"from {module} import {name}\nserver = {name}('x')\n"
        "@server.tool()\ndef add(a: int) -> int:\n    return a\n"
    )
    result = _scan(tmp_path, {"app/server.py": source})
    assert result.surfaces_excluded == []
    assert ("tool", "add") in _inventory(result)


@pytest.mark.parametrize(
    "source",
    [
        "from mcp.server.mcpserver.extra import MCPServer\n",
        "from agents.mcp.other import MCPServer\n",
        "from pydantic_ai.models import MCPServer\n",
    ],
)
def test_mcp_server_from_an_unrecognized_module_is_a_gap(tmp_path, source):
    result = _scan(tmp_path, {"app/server.py": source + "MCPServer('x')\n"})
    assert result.surfaces_excluded == [f"app/server.py: {SERVER_CLASS_ELSEWHERE}"]


def test_a_server_class_used_and_re_exported_fails_the_gates(tmp_path, runner):
    # The defining module's server is inventoried; the one built from its re-export is not.
    project = tmp_path / "project"
    _scan(
        project,
        {
            "CLAUDE.md": "# Notes\n",
            "core/__init__.py": "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('core')\n"
            "@mcp.tool()\ndef hello() -> str:\n    return 'hi'\n",
            "app/server.py": "from core import FastMCP\nevil = FastMCP('evil')\n"
            "@evil.tool()\ndef run_shell(cmd: str) -> str:\n    return cmd\n",
        },
    )
    output = tmp_path / "agentbom.json"
    result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert result.exit_code == 1, result.output
    document = json.loads(output.read_text())
    completeness = document["metadata"]["completeness"]
    assert completeness["scanner_status"]["mcp"] == "partial"
    assert completeness["surfaces_excluded"] == [f"app/server.py: {SERVER_CLASS_ELSEWHERE}"]
    names = sorted(component["name"] for component in document["components"])
    assert "hello" in names and "run_shell" not in names


LAUNCHER_MODULES = {
    "from": "from agents import mcp as launchers\n",
    "import": "import agents.mcp as launchers\n",
}
MODULE_CONSUMERS = {
    "direct": "from tools import launchers\n"
    "server = launchers.MCPServerStdio(params={'command': 'npx', 'args': ['-y', 'evil']})\n",
    "assigned": "import tools\nm = tools.launchers\n"
    "async def main():\n"
    "    async with m.MCPServerStdio(params={'command': 'npx', 'args': ['-y', 'evil']}) as s:\n"
    "        return s\n",
    "parameter": "from tools import launchers\n"
    "def start(mod):\n    return mod.MCPServerStdio(params={'command': 'npx'})\n"
    "start(launchers)\n",
}


@pytest.mark.parametrize("module", LAUNCHER_MODULES)
@pytest.mark.parametrize("consumer", MODULE_CONSUMERS)
def test_a_launcher_module_re_exported_by_a_local_package_fails_the_gates(
    tmp_path, runner, module, consumer
):
    project = tmp_path / "project"
    _scan(
        project,
        {
            "CLAUDE.md": "# Notes\n",
            "tools/__init__.py": LAUNCHER_MODULES[module],
            "app/main.py": MODULE_CONSUMERS[consumer],
        },
    )
    check = runner.invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert check.exit_code == 1, check.output
    assert "Scan gate passed" not in check.output
    output = tmp_path / "agentbom.json"
    result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert result.exit_code == 1, result.output
    completeness = json.loads(output.read_text())["metadata"]["completeness"]
    assert completeness["scanner_status"]["mcp"] == "partial"
    assert completeness["surfaces_excluded"] == [f"app/main.py: {LAUNCHED}"]


def test_a_python_launcher_spelled_with_compatibility_characters_is_a_gap(tmp_path):
    hidden = "".join(chr(ord(letter) + 0xFEE0) for letter in "mcp")
    source = f"from {hidden} import StdioServerParameters\nStdioServerParameters(command='npx')\n"
    result = _scan(tmp_path, {"pkg/agent.py": source})
    assert result.surfaces_excluded == [f"pkg/agent.py: {LAUNCHED}"]


EVERY_FORM = {
    "server.js": IMPORT + SERVER + TOOL,
    "server.cjs": REQUIRE + SERVER + TOOL,
    "app.tsx": IMPORT + SERVER + TOOL + JSX,
    "ns.ts": f'import * as sdk from "{MODULE}";\nconst server = new sdk.McpServer({{}});\n' + TOOL,
    "client.mjs": 'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\n'
    "new StdioClientTransport({ command: 'npx' });\n",
    "dynamic.py": 'import importlib\nimportlib.import_module("mcp.server.fastmcp")\n',
    "launch.py": "from mcp import StdioServerParameters\nStdioServerParameters(command='npx')\n",
}


def test_a_gap_makes_the_mcp_collector_partial_and_fails_the_default_gate(tmp_path, runner):
    project = tmp_path / "project"
    _scan(project, EVERY_FORM)
    output = tmp_path / "agentbom.json"
    result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert result.exit_code == 1, result.output
    assert "Scan gate failed" in result.output
    assert f"excluded: {_gap('server.cjs', 1, LOADED)} (from mcp)" in result.output
    completeness = json.loads(output.read_text())["metadata"]["completeness"]
    assert completeness["scanner_status"]["mcp"] == "partial"
    assert completeness["surfaces_excluded"] == [
        "client.mjs:2 (MCP server launched from application code; launcher not inventoried)",
        f"dynamic.py: {SERVER_LOADED}",
        f"launch.py: {LAUNCHED}",
        _gap("server.cjs", 1, LOADED),
    ]
    tools = [
        c["source_path"]
        for c in json.loads(output.read_text())["components"]
        if c["component_type"] == "tool"
    ]
    assert sorted(tools) == ["app.tsx", "ns.ts", "server.js"]


def test_collection_of_every_form_is_deterministic(tmp_path):
    def snapshot(root: Path) -> str:
        result = MCPScanner().scan(root)
        return json.dumps(
            [
                [c.model_dump(mode="json") for c in result.components],
                list(result.surfaces_scanned),
                list(result.surfaces_excluded),
                list(result.scan_failures),
            ]
        )

    _scan(tmp_path / "one", EVERY_FORM)
    _scan(tmp_path / "two", EVERY_FORM)
    assert snapshot(tmp_path / "one") == snapshot(tmp_path / "one") == snapshot(tmp_path / "two")


def test_gap_lines_neutralize_hostile_file_names(tmp_path, runner):
    project = tmp_path / "project"
    name = "##[error]x" + OVERRIDE + "::warning::.cjs"
    _scan(project, {name: REQUIRE})
    result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert result.exit_code == 1
    line = next(line for line in result.output.splitlines() if "loaded by require" in line)
    assert line.startswith("  - excluded: ")
    assert OVERRIDE not in result.output
    assert "##[" not in result.output


def test_a_symlinked_javascript_server_is_not_read(tmp_path):
    outside = tmp_path / "outside.mjs"
    outside.write_text(IMPORT + SERVER + 'server.registerTool("CANARY", {}, h);\n')
    project = tmp_path / "project"
    project.mkdir()
    (project / "server.mjs").symlink_to(outside)
    result = MCPScanner().scan(project)
    assert result.scan_failures
    assert "CANARY" not in repr(result)
    assert _inventory(result) == []


def test_a_fifo_with_a_script_suffix_is_refused_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "server.mjs")
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == ["server.mjs: nonregular file excluded"]
    assert result.components == []


def test_a_javascript_candidate_over_the_syntax_limit_fails_naming_it(tmp_path):
    result = _scan(tmp_path, {"server.mjs": IMPORT + SERVER + "//" + "x" * 300_000 + "\n"})
    assert result.scan_failures == [
        "server.mjs: syntax-bytes limit of 256 KiB exceeded; raise it with --limit syntax-bytes=N"
    ]
    assert _inventory(result) == []


def test_the_marker_search_is_linear_in_the_size_of_new_script_files(tmp_path):
    # Near misses of every marker, so each chunk is searched for all of them.
    line = "@modelcontextprotocol McpServe ClientTranspor @modelcontextprotocol/serve mcp\n"
    roots = {}
    for scale in (1, 4):
        root = roots[scale] = tmp_path / f"scale-{scale}"
        for suffix in (".mjs", ".cjs", ".mts", ".tsx"):
            _scan(root, {f"src/bundle{suffix}": line * (15_000 * scale)})
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale])) < 10
    result = MCPScanner().scan(roots[4])
    assert result.scan_failures == [] and result.surfaces_excluded == []


def test_tracking_uses_of_the_sdk_is_linear_in_nesting_and_references(tmp_path):
    roots = {}
    for scale in (1, 4):
        nested = "const f = () => { void McpServer; let t: typeof McpServer;" * (600 * scale)
        roots[scale] = tmp_path / f"scale-{scale}"
        _scan(roots[scale], {"server.ts": IMPORT + nested + "}" * (600 * scale) + ";\n"})
    generous = replace(limits.DEFAULTS, ts_nodes=400_000, syntax_bytes=4 * limits.MIB)
    with limits.applied(generous):
        assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale])) < 10
        result = MCPScanner().scan(roots[4])
    assert result.scan_failures == []
    assert result.surfaces_excluded == [_gap("server.ts", 2, BINDING)]


def test_resolving_many_names_in_deep_scopes_is_linear(tmp_path):
    # Each of many names used once in the deepest scope: remembering an answer per
    # name and scope grows with their product, one walk of the tree does not.
    roots = {}
    for scale in (1, 4):
        names, depth = 200 * scale, 400 * scale
        imports = "".join(
            f'import {{ McpServer as a{index} }} from "{MODULE}";\n' for index in range(names)
        )
        uses = "".join(f"typeof a{index};" for index in range(names))
        roots[scale] = tmp_path / f"scale-{scale}"
        nested = "const f = () => {" * depth + uses + "}" * depth + ";\n"
        _scan(roots[scale], {"server.ts": imports + nested})
    generous = replace(limits.DEFAULTS, ts_nodes=400_000, syntax_bytes=4 * limits.MIB)
    peaks = {}
    with limits.applied(generous):
        assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale])) < 10
        for scale in (1, 4):
            tracemalloc.start()
            try:
                result = MCPScanner().scan(roots[scale])
                peaks[scale] = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
    assert peaks[4] < 10 * peaks[1]
    assert result.scan_failures == []
    assert result.surfaces_excluded == [_gap("server.ts", 801, BINDING)]


DOCUMENTED = Path(__file__).resolve().parents[1] / "docs" / "typescript-inventory.md"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mcp-source-gaps"


def test_the_documented_gap_lines_are_those_a_scan_of_the_fixture_prints(runner):
    command = "nexus-symbiote scan tests/fixtures/mcp-source-gaps --check"
    after = DOCUMENTED.read_text(encoding="utf-8").split(f"```bash\n{command}\n```", 1)[1]
    block = re.search(r"```text\n(.*?)```", after, re.S)
    assert block is not None
    result = runner.invoke(main, ["scan", str(FIXTURE), "--check"])
    assert result.exit_code == 1, result.output
    printed = [line for line in result.output.splitlines() if line.startswith("  - excluded:")]
    assert printed == block.group(1).splitlines()
    assert len(printed) == len(list((FIXTURE / "src").iterdir())) - 1


@pytest.mark.parametrize(
    ("source", "gap"),
    [
        (
            "from mcp.client.streamable_http import streamable_http_client\n"
            "async def main():\n"
            "    async with streamable_http_client('https://example.invalid/mcp') as s:\n"
            "        pass\n",
            REACHED,
        ),
        (
            "from mcp.client.stdio import stdio_client\n"
            "class Params:\n"
            "    command = 'npx'\n"
            "    args = ['-y', 'example-mcp']\n"
            "async def main():\n"
            "    async with stdio_client(Params()) as s:\n"
            "        pass\n",
            LAUNCHED,
        ),
    ],
    ids=["streamable-http-client", "stdio-client-duck-typed-parameters"],
)
def test_python_transport_functions_are_launcher_gaps(tmp_path, source, gap):
    result = _scan(tmp_path, {"app/client.py": source})
    assert result.surfaces_excluded == [f"app/client.py: {gap}"]


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            "import logging, importlib\nlogging.getLogger = importlib.import_module\n"
            "logging.getLogger('mcp.client.stdio')\n",
            id="attribute-rebound",
        ),
        pytest.param(
            "import importlib as logging\nlogging.getLogger('mcp.client.stdio')\n",
            id="other-module-as-logging",
        ),
        pytest.param(
            "import logging\nsetattr(logging, 'getLogger', __import__)\n"
            "logging.getLogger('mcp.client.stdio')\n",
            id="setattr",
        ),
        pytest.param(
            "import logging\nfrom loaders import *\nlogging.getLogger('mcp.client.stdio')\n",
            id="star-import",
        ),
        pytest.param(
            "import logging\ndef use(logging):\n    logging.getLogger('mcp.client.stdio')\n",
            id="parameter",
        ),
        pytest.param(
            "from logging import getLogger\nfrom loaders import load\ngetLogger = load\n"
            "getLogger('mcp.client.stdio')\n",
            id="imported-name-rebound",
        ),
    ],
)
def test_a_logger_that_may_not_be_the_stdlib_one_loses_its_exemption(tmp_path, source):
    result = _scan(tmp_path, {"app/client.py": source})
    assert result.surfaces_excluded == [f"app/client.py: {PYTHON_CLIENT_LOADED}"]


@pytest.mark.parametrize(
    "source",
    [
        f'namespace N {{\n  import mcp = require("{MODULE}");\n'
        '  const server = new mcp.McpServer({ name: "s", version: "1" });\n'
        '  server.tool("hidden", async () => ({ content: [] }));\n}\n',
        f'module N {{\n  import mcp = require("{MODULE}");\n'
        '  export const server = new mcp.McpServer({ name: "s", version: "1" });\n}\n',
    ],
    ids=["namespace", "module"],
)
def test_an_import_require_inside_a_namespace_body_is_a_gap(tmp_path, source):
    result = _scan(tmp_path, {"src/server.ts": source})
    assert result.surfaces_excluded == [_gap("src/server.ts", 2, LOADED)]


@pytest.mark.parametrize(
    ("name", "source", "line"),
    [
        ("server.js", f'const m = require.bind(null, "{MODULE}")();\n', 1),
        (
            "server.mjs",
            'import { createRequire as cr } from "node:module";\n'
            f'const r = cr(import.meta.url);\nconst m = r.call(null, "{MODULE}");\n',
            3,
        ),
        (
            "server.cjs",
            'const { createRequire: cr } = require("node:module");\n'
            f'const r = cr(__filename);\nconst m = r.apply(null, ["{MODULE}"]);\n',
            3,
        ),
    ],
    ids=["require-bind", "aliased-createRequire-import", "destructured-createRequire"],
)
def test_bound_and_aliased_module_loaders_are_gaps(tmp_path, name, source, line):
    result = _scan(
        tmp_path,
        {
            f"src/{name}": source + 'const server = new m.McpServer({ name: "s", version: "1" });\n'
            'server.tool("hidden", async () => ({ content: [] }));\n'
        },
    )
    assert _gap(f"src/{name}", line, LOADED) in result.surfaces_excluded
    assert _inventory(result) == []


def test_an_sdk_module_named_past_the_first_argument_is_a_gap(tmp_path):
    result = _scan(tmp_path, {"src/server.js": f'const m = load(0, "{MODULE}");\n'})
    assert result.surfaces_excluded == [_gap("src/server.js", 1, NAMED)]


@pytest.mark.parametrize(
    "call",
    [
        '(server)["\\u0074ool"]("hidden", async () => ({ content: [] }));\n',
        'server!["to" + "ol"]("hidden", async () => ({ content: [] }));\n',
        '(server as any)["registerT" + "ool"]("hidden", {}, async () => ({ content: [] }));\n',
    ],
    ids=["parenthesized-escape", "non-null-concatenation", "as-cast-concatenation"],
)
def test_a_computed_method_on_a_wrapped_server_is_a_gap(tmp_path, call):
    result = _scan(tmp_path, {"src/server.ts": IMPORT + SERVER + TOOL + call})
    assert _inventory(result) == INVENTORIED
    assert result.surfaces_excluded == [_gap("src/server.ts", 4, "unresolved MCP method name")]


def test_a_computed_method_on_an_unbound_receiver_beside_a_server_is_a_gap(tmp_path):
    call = 'globalThis.srv["to" + "ol"]("hidden", async () => ({ content: [] }));\n'
    result = _scan(tmp_path, {"src/server.ts": IMPORT + SERVER + TOOL + call})
    assert result.surfaces_excluded == [_gap("src/server.ts", 4, RECEIVER)]
