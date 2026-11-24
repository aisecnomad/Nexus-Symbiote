"""Collect literal Python SDK tool declarations without importing scanned code."""

from __future__ import annotations

import ast
import re
import warnings
from collections import Counter, deque
from collections.abc import Container, Iterable, Sequence
from pathlib import Path
from typing import NamedTuple
from urllib.parse import quote

from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import (
    ClaimEvidence,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.base import KnownValues, ScanResult, declared_server_name

PYTHON_TOOL_HINTS = (
    "mcp",
    "FastMCP",
    "MCPServer",
    "langchain",
    "crewai",
    "function_tool",
    "smolagents",
    "pydantic_ai",
    "agents",
)


def _names(words: str) -> frozenset[str]:
    return frozenset(words.split())


class _PassiveModule(NamedTuple):
    names: frozenset[str]
    imports_stdlib: bool


class _ProjectImports(NamedTuple):
    """Possible Python search roots and the files found by the confined walk."""

    sources: frozenset[Path]
    entry_dir: Path
    plain_modules: dict[Path, _PassiveModule]
    entries: frozenset[Path]
    uncertain_modules: frozenset[Path]
    stdlib_search_clear: bool

    def _passive_names(self, path: Path) -> frozenset[str] | None:
        module = self.plain_modules.get(path)
        if module is None or (module.imports_stdlib and not self.stdlib_search_clear):
            return None
        return module.names

    def _module_at(self, root: Path, relative: Path) -> bool:
        return (
            root / relative.with_suffix(".py") in self.sources
            or root / relative / "__init__.py" in self.sources
        ) and all(root / p / "__init__.py" in self.sources for p in relative.parents if p.parts)

    def has_module(self, module: str) -> bool:
        # A local exemption requires a regular module in every plausible first
        # search root: the checkout for -m, the entry directory for a script,
        # and the source root for a module installed from a src layout.
        relative = Path(*module.split("."))
        return (
            self._module_at(Path(), relative)
            and self._module_at(self.entry_dir, relative)
            and (self.entry_dir.parts[:1] != ("src",) or self._module_at(Path("src"), relative))
        )

    def shadows(self, module: str, member: str | None = None) -> bool:
        # Any unresolved first search root withholds SDK provenance. A passive
        # sibling can only supply its own names or an existing package child.
        name, dot, rest = module.partition(".")
        for root in (Path(), Path("src"), self.entry_dir):
            package = root / name
            if package in self.uncertain_modules:
                return True
            init = package / "__init__.py"
            if init in self.sources:
                names = self._passive_names(init)
                child = rest.partition(".")[0] if dot else member
                if names is None or child is None or package / child in self.entries:
                    return True
                if not dot and member in names:
                    return True
            flat = root / (name + ".py")
            if flat in self.sources:
                names = self._passive_names(flat)
                if names is None or (not dot and (member is None or member in names)):
                    return True
        return False


_FACTORIES = {
    ("mcp.server", "FastMCP"),
    ("mcp.server", "MCPServer"),
    ("mcp.server.fastmcp", "FastMCP"),
    ("mcp.server.fastmcp.server", "FastMCP"),
    ("mcp.server.mcpserver", "MCPServer"),
    ("fastmcp", "FastMCP"),
    ("fastmcp.server", "FastMCP"),
    ("fastmcp.server.server", "FastMCP"),
}
# How a recognised server's name may be used without the server escaping the
# collector. A data attribute's value does not hold the server.
_SERVER_DATA = _names("name instructions settings")
# A run method or app factory may be called and its result used anywhere: the
# coroutine or app holds the server only where reflection reaches it. A method read
# without a call is a bound method that holds the server in __self__.
_SERVER_CALLS = _names(
    "run run_async run_stdio_async run_sse_async run_streamable_http_async run_http_async "
    "sse_app streamable_http_app http_app"
)
# Each returns a decorator that closes over the server, so only one applied directly
# to a function is followed.
_SERVER_DECORATORS = _names("resource prompt custom_route")
# Reflection that can reach a server or agent without naming it: these builtins
# referenced by name, getattr and its kin on an object that could be one, these names
# bound or read, whose strings the SDKs evaluate as annotations, and these attributes,
# also imported by name, which expose frames, closures, namespaces and bound instances
# or evaluate strings as code.
_REFLECTIVE_BUILTINS = _names("locals globals vars eval exec __import__ setattr delattr")
_ATTRIBUTE_BUILTINS = _names("getattr")
_REFLECTIVE_NAMES = _names("__builtins__ __annotations__ __annotate__")
_REFLECTIVE_MODULES = _names(
    "builtins __main__ _imp imp _frozen_importlib _frozen_importlib_external _importlib runpy"
)
_REFLECTIVE_ATTRIBUTES = _names(
    "__self__ __closure__ __globals__ __builtins__ __dict__ __annotations__ __annotate__ "
    "__traceback__ __code__ __getattribute__ __setattr__ __delattr__ __import__ import_module "
    "resolve_name attrgetter methodcaller getattr ForwardRef exec_module load_module "
    "spec_from_file_location _gcd_import _bootstrap _bootstrap_external tb_frame tb_next "
    "f_back f_locals f_globals f_builtins gi_frame cr_frame ag_frame _getframe currentframe "
    "getouterframes getinnerframes getargvalues getclosurevars getmodule stack trace "
    "getattr_static"
)
# Generics whose subscript only records its arguments as types.
_TYPING_MODULES = frozenset({"typing", "typing_extensions", "collections.abc"})
_GENERIC_BUILTINS = _names("dict frozenset list set tuple type")


def _decorates(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    owner = parents.get(node)
    return isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
        node in owner.decorator_list
    )


def _safe_use(
    name: ast.Name,
    parents: dict[ast.AST, ast.AST],
    data: frozenset[str],
    calls: frozenset[str],
    decorators: frozenset[str],
) -> bool:
    """Whether ``name`` is only read for an attribute in ``data``, called for a method
    in ``calls`` or applied directly as a decorator in ``decorators``.

    A method read and discarded is safe too. Stored, passed or dereferenced, it hands
    out the receiver through ``__self__`` or a closure.
    """
    attribute = parents.get(name)
    if not isinstance(attribute, ast.Attribute) or not isinstance(attribute.ctx, ast.Load):
        return False
    use = parents.get(attribute)
    call = use if isinstance(use, ast.Call) and use.func is attribute else None
    if attribute.attr in data or (attribute.attr in calls and call is not None):
        return True
    if attribute.attr not in calls and attribute.attr not in decorators:
        return False
    return isinstance(use, ast.Expr) or (
        attribute.attr in decorators and _decorates(call or attribute, parents)
    )


def _safe_receivers(
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    receivers: Container[str],
    data: frozenset[str],
    calls: frozenset[str],
    decorators: frozenset[str],
) -> set[ast.AST]:
    return {
        node
        for node in nodes
        if isinstance(node, ast.Name)
        and node.id in receivers
        and _safe_use(node, parents, data, calls, decorators)
    }


def _plain_attribute(call: ast.Call) -> bool:
    """Whether getattr names a literal attribute, not a reflective one, by position."""
    if (
        call.keywords
        or len(call.args) not in (2, 3)
        or any(isinstance(a, ast.Starred) for a in call.args)
    ):
        return False
    attribute = call.args[1]
    return (
        isinstance(attribute, ast.Constant)
        and isinstance(attribute.value, str)
        and attribute.value not in _REFLECTIVE_ATTRIBUTES
        and attribute.value != "modules"
    )


def _names_parameter(name: ast.Name, parents: dict[ast.AST, ast.AST]) -> bool:
    """Whether ``name`` is read in the body of the function, not a nested one or a
    class, that has a parameter so named.

    A parameter is local to the whole body, so the name is not the builtin there.
    Defaults, annotations and decorators are evaluated outside the function.
    """
    child: ast.AST = name
    owner = parents.get(name)
    while owner is not None and not isinstance(
        owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    ):
        child, owner = owner, parents.get(owner)
    if isinstance(owner, ast.Lambda):
        inside = child is owner.body
    elif isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
        inside = any(child is stmt for stmt in owner.body)
    else:
        return False
    arguments = owner.args
    return inside and any(
        arg is not None and arg.arg == name.id
        for arg in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        )
    )


def _reflective_access(
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    bindings: Counter[str],
) -> bool:
    """Whether reflection can reach a server, context or agent of the file without naming it.

    The builtins count whenever referenced by their own names, outside the body of a
    function with a parameter so named, and through the builtins module; a method that
    only shares a name, such as ``model.eval()``, does not. ``modules`` counts unless
    it is called, so ``sys.modules[__name__]`` does and ``model.modules()`` does not.
    """
    if any(bindings[name] for name in _REFLECTIVE_NAMES):
        return True
    for node in nodes:
        if isinstance(node, ast.Name) and node.id in _REFLECTIVE_NAMES:
            return True
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            use = parents.get(node)
            if node.id in _REFLECTIVE_BUILTINS and not _names_parameter(node, parents):
                return True
            if node.id in _ATTRIBUTE_BUILTINS and not (
                not bindings[node.id]
                and isinstance(use, ast.Call)
                and use.func is node
                and _plain_attribute(use)
            ):
                return True
        elif isinstance(node, ast.Attribute):
            use = parents.get(node)
            if node.attr in _REFLECTIVE_ATTRIBUTES or (
                node.attr == "modules" and not (isinstance(use, ast.Call) and use.func is node)
            ):
                return True
        elif isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] in _REFLECTIVE_MODULES for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0] if not node.level else ""
            if root in _REFLECTIVE_MODULES or any(
                alias.name in _REFLECTIVE_ATTRIBUTES
                or (not node.level and node.module == "sys" and alias.name == "modules")
                for alias in node.names
            ):
                return True
    return False


# Constructor keywords that carry tools, or could, are registrations the
# collector does not resolve. The SDK hands a lifespan the server, middleware
# sees and rewrites tool lists, transformations and transforms add, rename or hide
# tools, and an extension's tools are added to the server.
_REGISTERING_KEYWORDS = _names(
    "tools tool_serializer providers mount lifespan middleware tool_transformations"
    " transforms extensions resources"
)
# Past the name and instructions, older `fastmcp` releases take keywords such as
# `lifespan` positionally. The `mcp` SDK's FastMCP and MCPServer take at most seven
# positionals that are not handed the server; later `fastmcp` releases are unknown.
_PLAIN_POSITIONALS = 2
_SDK_POSITIONALS = {
    "mcp.server": 9,
    "mcp.server.fastmcp": 7,
    "mcp.server.fastmcp.server": 7,
    "mcp.server.mcpserver": 9,
}
# A request context hands handler and middleware code the server: `fastmcp` on a
# context (`_fastmcp` in the `mcp` SDK), `mcp_server` on an `MCPServer` context, the
# context a middleware context holds, the context variables the SDKs keep the current
# context in, and the request context. The HTTP app `fastmcp` serves keeps the
# server as `app.state.fastmcp_server`. Leading underscores are ignored. Only
# `fastmcp` and `fastmcp_server` count in a file that imports from neither SDK; the
# others are common names outside MCP.
_SERVER_HANDLES = _names("fastmcp fastmcp_server")
_SDK_SERVER_HANDLES = _names(
    "fastmcp_context current_context request_ctx request_context mcp_server"
)
# What `fastmcp` hands a handler the server, its context or its HTTP request through:
# accessors, the dependency defaults it injects into an unannotated parameter, and the
# context variables and hooks that hold them.
_SDK_ACCESSORS = _names(
    "get_server current_server fastmcp_request_ctx CurrentFastMCP CurrentContext"
    " OptionalCurrentContext get_http_request CurrentRequest current_http_request"
    " extension_dispatch_scope delegated_extension_scope worker_server_resolver"
    " background_context_factory"
)
_SDK_ROOTS = _names("mcp fastmcp")
# The one SDK module whose path names `fastmcp` below the root.
_FASTMCP_MODULE = "mcp.server.fastmcp"
# What a handler may read from a context without calling it, and the methods it may
# call. Any other attribute read could be a bound method, which holds the context in
# __self__, and another method could return the context, as `model_copy` does.
_CONTEXT_DATA = _names(
    "request_id client_id session_id session headers protocol_version"
    " client_capabilities transport task_id origin_request_id is_background_task"
)
_CONTEXT_METHODS = _names(
    "debug info warning error log report_progress read_resource list_resources"
    " get_prompt list_prompts elicit elicit_url sample list_roots get_state set_state"
    " delete_state send_notification close_sse_stream close_standalone_sse_stream"
    " notify_tools_changed notify_resources_changed notify_resource_updated"
    " notify_prompts_changed send_tool_list_changed send_resource_list_changed"
    " send_prompt_list_changed client_supports_extension client_extension_settings"
    " enable_components disable_components reset_visibility"
)

_DECORATOR_IMPORTS = {
    ("langchain_core.tools", "tool"): "langchain",
    ("langchain.tools", "tool"): "langchain",
    ("crewai.tools", "tool"): "crewai",
    ("agents", "function_tool"): "openai-agents",
    ("agents.tool", "function_tool"): "openai-agents",
    ("smolagents", "tool"): "smolagents",
    ("smolagents.tools", "tool"): "smolagents",
    ("langchain_core.tools.convert", "tool"): "langchain",
    ("crewai.tools.base_tool", "tool"): "crewai",
}

_AGENT_FACTORIES = {
    ("pydantic_ai", "Agent"): "pydantic-ai",
    ("pydantic_ai.agent", "Agent"): "pydantic-ai",
}
# The packages, or the tool packages, of the frameworks whose tools are collected, and
# the MCP client modules among them, which the source collector reads instead.
_FRAMEWORK_ROOTS = (
    "agents",
    "pydantic_ai",
    "langchain_core.tools",
    "langchain.tools",
    "crewai.tools",
    "smolagents",
)
_FRAMEWORK_CLIENTS = ("agents.mcp", "pydantic_ai.mcp")
_NON_REGISTERING_IMPORTS = frozenset(
    {
        ("agents", "ToolCallItem"),
        ("agents", "ToolCallOutputItem"),
        ("agents", "custom_span"),
        ("agents", "gen_trace_id"),
        ("agents", "set_default_openai_client"),
        ("agents", "set_default_openai_key"),
        ("agents", "set_tracing_disabled"),
        ("agents", "trace"),
        ("agents.items", "ToolCallItem"),
        ("agents.tracing", "trace"),
        ("langchain_core.tools", "InjectedToolCallId"),
        ("langchain_core.tools", "ToolException"),
        ("pydantic_ai", "capture_run_messages"),
        ("pydantic_ai.messages", "ToolCallPart"),
    }
)
# Agent constructor keywords that carry tools, or could; a prepare function can add,
# rename or drop the tool definitions of each step.
_AGENT_REGISTERING_KEYWORDS = frozenset(
    {"tools", "toolsets", "builtin_tools", "mcp_servers", "prepare_tools", "prepare_output_tools"}
)
# How a recognised agent's name may be used without the agent escaping, as for a
# server: a run's result holds the agent only where reflection reaches it.
_AGENT_DATA = _names("name")
_AGENT_CALLS = _names("run run_sync run_stream iter")
_AGENT_DECORATORS = _names("system_prompt instructions output_validator")


def _bindings(nodes: list[ast.AST]) -> Counter[str]:
    # Count even nested writes conservatively. A shadowed name needs scope
    # analysis before it can be attributed to the SDK or a particular server.
    names: Counter[str] = Counter()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names[node.id] += 1
        elif isinstance(node, ast.alias):
            names[node.asname or node.name.split(".")[0]] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names[node.name] += 1
        elif isinstance(node, ast.arg):
            names[node.arg] += 1
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            names[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names[node.rest] += 1
    return names


# ``.tool`` keywords that do not change the name a tool is registered under. fastmcp
# also takes the name as ``name_or_fn``, so any keyword not listed here may carry it.
_TOOL_OPTIONS = frozenset(
    {
        "name",
        "title",
        "description",
        "tags",
        "annotations",
        "output_schema",
        "exclude_args",
        "meta",
        "structured_output",
        "icons",
        "enabled",
        "version",
        "app",
        "task",
        "timeout",
        "auth",
        "run_in_thread",
    }
)


def _string_constants(roots: Iterable[ast.AST]) -> list[str]:
    """Every string literal under ``roots``; the trees are parsed already, so walking
    them whole stays linear and no literal is left behind a node budget."""
    return [
        node.value
        for root in roots
        for node in ast.walk(root)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def _declaration_text_risks(
    deco: ast.AST,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef | None,
    source_name: str,
) -> list[RiskAssessment]:
    """Rate hidden Unicode characters in a Python tool's docstring, decorator literals and
    parameter annotations and defaults, which the SDKs put in its description and schema."""
    payload: dict[str, object] = {}
    if func_node is not None:
        doc = ast.get_docstring(func_node, clean=False)
        if doc:
            payload["docstring"] = doc
        parameters = _string_constants([func_node.args])
        if parameters:
            payload["parameters"] = parameters
    if isinstance(deco, ast.Call):
        strings = _string_constants([*deco.args, *(kw.value for kw in deco.keywords)])
        if strings:
            payload["decorator"] = strings
    if not payload:
        return []
    from nexus_symbiote.scanners.prompt import definition_text_risks

    return definition_text_risks(payload, source_name)


def _record_decorator(
    deco: ast.Call | ast.Attribute,
    default_name: str,
    server: MCPServerComponent,
    path: Path,
    source_digest: str,
    result: ScanResult,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
) -> None:
    keywords = deco.keywords if isinstance(deco, ast.Call) else []
    options = {kw.arg: kw.value for kw in keywords}
    name: object = default_name
    if "name" in options:
        value = options["name"]
        name = value.value if isinstance(value, ast.Constant) else None
    if (
        (isinstance(deco, ast.Call) and deco.args)
        or len(options) != len(keywords)
        or None in options
        or not options.keys() <= _TOOL_OPTIONS
        or not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
    ):
        result.surfaces_excluded.append(
            f"{path.as_posix()}:{deco.lineno}: unresolved Python MCP tool name"
        )
        return
    ref = f"tool:{server.bom_ref}/{name}"
    if ref in server.tool_refs:
        result.scan_failures.append(
            f"{path.as_posix()}:{deco.lineno}: duplicate Python MCP tool declaration"
        )
        return
    risks = _declaration_text_risks(deco, func_node, f"{path.as_posix()}:{deco.lineno} ({name})")
    result.components.append(
        ToolComponent(
            bom_ref=ref,
            name=name,
            mcp_server_ref=server.bom_ref,
            source_path=path.as_posix(),
            risks=risks,
            claims={
                "tool_definition": ClaimEvidence(
                    method="not-collected",
                    scope="source-declaration",
                    unknown_reason="Effective descriptor requires runtime evidence",
                )
            },
            properties={
                "method": "python-ast",
                "collection_mode": "static-source-declaration",
                "declaration_line": deco.lineno,
                "source_sha256": source_digest,
            },
        )
    )
    server.tool_refs.append(ref)
    server.tool_count += 1


def _record_sdk_decorator(
    deco: ast.AST,
    default_name: str,
    framework: str,
    path: Path,
    source_digest: str,
    seen_refs: set[str],
    result: ScanResult,
    owner: str | None = None,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
) -> None:
    """Record one decorated tool; ``owner`` names the agent it is registered on."""
    lineno = getattr(deco, "lineno", 1)
    name: object = default_name
    if isinstance(deco, ast.Call):
        options = {kw.arg: kw.value for kw in deco.keywords}
        name_keys = [k for k in ("name", "name_or_callable", "name_override") if k in options]
        if (
            len(deco.args) > 1
            or any(isinstance(arg, ast.Starred) for arg in deco.args)
            or len(options) != len(deco.keywords)
            or None in options
            or len(name_keys) > 1
            or (deco.args and name_keys)
        ):
            result.surfaces_excluded.append(
                f"{path.as_posix()}:{lineno}: unresolved Python SDK tool name"
            )
            return
        if len(deco.args) == 1:
            arg = deco.args[0]
            name = arg.value if isinstance(arg, ast.Constant) else None
        elif name_keys:
            val = options[name_keys[0]]
            name = val.value if isinstance(val, ast.Constant) else None
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
        result.surfaces_excluded.append(
            f"{path.as_posix()}:{lineno}: unresolved Python SDK tool name"
        )
        return
    scope = quote(path.as_posix(), safe="") + (f"/{owner}" if owner else "")
    ref = f"tool:python:{scope}/{name}"
    if ref in seen_refs:
        result.scan_failures.append(
            f"{path.as_posix()}:{lineno}: duplicate Python SDK tool declaration"
        )
        return
    seen_refs.add(ref)
    risks = _declaration_text_risks(deco, func_node, f"{path.as_posix()}:{lineno} ({name})")
    result.components.append(
        ToolComponent(
            bom_ref=ref,
            name=name,
            source_path=path.as_posix(),
            risks=risks,
            claims={
                "tool_definition": ClaimEvidence(
                    method="not-collected",
                    scope="source-declaration",
                    unknown_reason="Effective descriptor requires runtime evidence",
                )
            },
            properties={
                "method": "python-ast",
                "framework": framework,
                "collection_mode": "static-source-declaration",
                "declaration_line": lineno,
                "source_sha256": source_digest,
            },
        )
    )


def _collect_sdk_decorators(
    tree: ast.Module,
    nodes: list[ast.AST],
    decorators: dict[str, tuple[ast.ImportFrom, str]],
    bindings: Counter[str],
    path: Path,
    source_digest: str,
    seen_refs: set[str],
    result: ScanResult,
) -> None:
    top_level = set(tree.body)
    valid: dict[str, tuple[int, str]] = {}
    unsupported = False
    for alias, (imported, framework) in decorators.items():
        if imported not in top_level or bindings[alias] != 1:
            unsupported = True
            continue
        valid[alias] = (imported.lineno, framework)
    if sum(isinstance(n, ast.Name) and n.id in decorators for n in nodes) > 1000:
        result.scan_failures.append(
            f"{path.as_posix()}: Python SDK tool registration limit exceeded"
        )
        return
    handled: set[ast.AST] = set()
    for stmt in tree.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        registrations = [
            target if isinstance(target, ast.Name) and target.id in valid else None
            for target in (
                deco.func if isinstance(deco, ast.Call) else deco for deco in stmt.decorator_list
            )
        ]
        unwrapped = _unwrapped([target is not None for target in registrations])
        for index, deco in enumerate(stmt.decorator_list):
            target = registrations[index]
            if target is None:
                continue
            import_line, framework = valid[target.id]
            if import_line >= stmt.lineno:
                unsupported = True
                continue
            handled.add(target)
            if not unwrapped[index]:
                result.surfaces_excluded.append(
                    f"{path.as_posix()}:{deco.lineno}: unresolved Python SDK tool name"
                )
                continue
            _record_sdk_decorator(
                deco, stmt.name, framework, path, source_digest, seen_refs, result, func_node=stmt
            )
    load_uses = {
        node
        for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in decorators
    }
    if unsupported or (load_uses - handled):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: unsupported Python SDK tool binding or dynamic registration"
        )


def _collect_agent_decorators(
    tree: ast.Module,
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    parsed: _ParsedAnnotations,
    annotations: set[ast.AST],
    agent_factories: dict[str, tuple[ast.ImportFrom, str]],
    bindings: Counter[str],
    path: Path,
    source_digest: str,
    seen_refs: set[str],
    result: ScanResult,
) -> set[str]:
    top_level = set(tree.body)
    calls = {
        node
        for node in nodes
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in agent_factories
    }
    changed_receivers = {
        node.value.id
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr in {"tool", "tool_plain"}
        and isinstance(node.value, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    if (
        sum(
            isinstance(node, ast.Attribute) and node.attr in {"tool", "tool_plain"}
            for node in nodes
        )
        > 1000
    ):
        result.scan_failures.append(
            f"{path.as_posix()}: Python SDK tool registration limit exceeded"
        )
        return set()
    unsupported_factory = any(
        imported not in top_level or bindings[factory] != 1
        for factory, (imported, _) in agent_factories.items()
    )
    agents: dict[str, tuple[int, str]] = {}
    handled: set[ast.AST] = set()
    for stmt in tree.body:
        target: ast.AST | None = None
        call: ast.AST | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            call = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            target = stmt.target
            call = stmt.value
        if target is not None and call is not None:
            if not (
                isinstance(target, ast.Name)
                and isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call in calls
            ):
                continue
            factory = call.func.id
            imported, framework = agent_factories[factory]
            if (
                imported not in top_level
                or imported.lineno >= stmt.lineno
                or bindings[factory] != 1
                or target.id in changed_receivers
                or bindings[target.id] != 1
                or any(isinstance(arg, ast.Starred) for arg in call.args)
                or any(
                    kw.arg is None or kw.arg in _AGENT_REGISTERING_KEYWORDS for kw in call.keywords
                )
            ):
                continue
            handled.add(call)
            agents[target.id] = (stmt.lineno, framework)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            registrations = [
                target
                if isinstance(target, ast.Attribute)
                and target.attr in {"tool", "tool_plain"}
                and isinstance(target.value, ast.Name)
                and target.value.id in agents
                else None
                for target in (
                    deco.func if isinstance(deco, ast.Call) else deco
                    for deco in stmt.decorator_list
                )
            ]
            unwrapped = _unwrapped([target is not None for target in registrations])
            for index, deco in enumerate(stmt.decorator_list):
                registration = registrations[index]
                if registration is None or not isinstance(registration.value, ast.Name):
                    continue
                owner = registration.value.id
                decl_line, framework = agents[owner]
                if decl_line >= stmt.lineno:
                    continue
                handled.add(registration)
                if not unwrapped[index]:
                    result.surfaces_excluded.append(
                        f"{path.as_posix()}:{deco.lineno}: unresolved Python SDK tool name"
                    )
                    continue
                _record_sdk_decorator(
                    deco,
                    stmt.name,
                    framework,
                    path,
                    source_digest,
                    seen_refs,
                    result,
                    owner,
                    func_node=stmt,
                )
    candidates: set[ast.AST] = set(calls)
    candidates.update(
        node
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr in {"tool", "tool_plain"}
        and isinstance(node.value, ast.Name)
        and node.value.id in agents
    )
    # An agent used other than through a handled decorator, a read, run or decorator
    # that _safe_use accepts, or a `with` statement without `as`, such as aliased,
    # passed to a function or held in a list, can be given tools elsewhere.
    reached: set[ast.AST] = {node.value for node in handled if isinstance(node, ast.Attribute)}
    reached |= _safe_receivers(nodes, parents, agents, _AGENT_DATA, _AGENT_CALLS, _AGENT_DECORATORS)
    reached.update(
        node.context_expr
        for node in nodes
        if isinstance(node, ast.withitem) and node.optional_vars is None
    )
    factory_calls = {call.func for call in calls}
    escaped = any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and (
            (node.id in agents and node not in reached)
            or (
                node.id in agent_factories and node not in factory_calls and node not in annotations
            )
        )
        for node in parsed.all_nodes
    )
    if (
        unsupported_factory
        or escaped
        or (candidates - handled)
        or (
            agents
            and (
                parsed.overflow
                or _reflective_access(parsed.all_nodes, parsed.all_parents, bindings)
            )
        )
    ):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: unsupported Python SDK tool binding or dynamic registration"
        )
    return set(agents)


_LOW_LEVEL_MODULE = "mcp.server.lowlevel"


def _low_level_step(state: str | None, attr: str) -> str | None:
    """Where an attribute of ``mcp``, ``mcp.server`` or the low-level module leads."""
    if state == "mcp" and attr == "server":
        return "mcp.server"
    if state == "mcp.server" and attr in {"lowlevel", "Server"}:
        return _LOW_LEVEL_MODULE
    return _LOW_LEVEL_MODULE if state == _LOW_LEVEL_MODULE else None


def _low_level_state(module: str) -> str | None:
    if module == _LOW_LEVEL_MODULE or module.startswith(f"{_LOW_LEVEL_MODULE}."):
        return _LOW_LEVEL_MODULE
    return module if module in {"mcp", "mcp.server"} else None


def _reaches_low_level(nodes: list[ast.AST]) -> bool:
    """Whether the file imports the low-level server or reaches it as an attribute.

    Any import of the low-level module, of ``Server``, ``lowlevel`` or ``*`` from
    ``mcp.server``, and any attribute path (including via arbitrary-length variable
    alias chains such as ``a = mcp; b = a; ...; z.server.Server(...)``) from a name
    bound to ``mcp`` or ``mcp.server`` to ``lowlevel`` or ``Server`` counts. Earlier
    bindings are never erased by unrelated imports of the same local name in dead
    branches. Runs in O(N) time via a bounded two-state worklist.
    """
    bound: dict[str, set[str]] = {}
    name_nodes: dict[str, list[ast.AST]] = {}
    attr_children: dict[ast.AST, list[tuple[ast.AST, str]]] = {}
    assign_targets: dict[ast.AST, list[str]] = {}
    # A walrus expression carries its value's state: ``(a := mcp).server``.
    carriers: dict[ast.AST, list[ast.AST]] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for a in node.names:
                if _low_level_state(a.name) == _LOW_LEVEL_MODULE:
                    return True
                module = a.name if a.asname else a.name.split(".")[0]
                state = _low_level_state(module)
                if state is not None:
                    bound.setdefault(a.asname or module, set()).add(state)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            for a in node.names:
                state = _low_level_step(_low_level_state(node.module), a.name)
                if state == _LOW_LEVEL_MODULE or (a.name == "*" and node.module == "mcp.server"):
                    return True
                if state is not None:
                    bound.setdefault(a.asname or a.name, set()).add(state)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            name_nodes.setdefault(node.id, []).append(node)
        elif (access := _attribute_access(node)) is not None:
            attr_children.setdefault(access[0], []).append((node, access[1]))
        elif isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if targets:
                assign_targets.setdefault(node.value, []).extend(targets)
            for target in node.targets:
                # ``a, b = mcp, x`` binds each name to the value at its position.
                if (
                    isinstance(target, (ast.Tuple, ast.List))
                    and isinstance(node.value, (ast.Tuple, ast.List))
                    and len(target.elts) == len(node.value.elts)
                    and not any(
                        isinstance(e, ast.Starred) for e in (*target.elts, *node.value.elts)
                    )
                ):
                    for bound_name, value in zip(target.elts, node.value.elts, strict=True):
                        if isinstance(bound_name, ast.Name):
                            assign_targets.setdefault(value, []).append(bound_name.id)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                assign_targets.setdefault(node.value, []).append(node.target.id)
        elif isinstance(node, ast.NamedExpr):
            assign_targets.setdefault(node.value, []).append(node.target.id)
            carriers.setdefault(node.value, []).append(node)
        elif isinstance(node, ast.IfExp):
            carriers.setdefault(node.body, []).append(node)
            carriers.setdefault(node.orelse, []).append(node)
        elif isinstance(node, ast.BoolOp):
            for value in node.values:
                carriers.setdefault(value, []).append(node)
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, (ast.Tuple, ast.List))
            and isinstance(node.slice, ast.Constant)
            and type(node.slice.value) is int
            and -len(node.value.elts) <= node.slice.value < len(node.value.elts)
        ):
            carriers.setdefault(node.value.elts[node.slice.value], []).append(node)
    if not bound:
        return False
    node_states: dict[ast.AST, set[str]] = {}
    pending_nodes: deque[tuple[ast.AST, str]] = deque()
    for var_name, initial_states in bound.items():
        for state in initial_states:
            for expr in name_nodes.get(var_name, ()):
                seen = node_states.setdefault(expr, set())
                if state not in seen:
                    seen.add(state)
                    pending_nodes.append((expr, state))
    while pending_nodes:
        expr, state = pending_nodes.popleft()
        for attr_node, attr_name in attr_children.get(expr, ()):
            stepped = _low_level_step(state, attr_name)
            if stepped == _LOW_LEVEL_MODULE:
                return True
            if stepped is not None:
                seen = node_states.setdefault(attr_node, set())
                if stepped not in seen:
                    seen.add(stepped)
                    pending_nodes.append((attr_node, stepped))
        for carrier in carriers.get(expr, ()):
            seen = node_states.setdefault(carrier, set())
            if state not in seen:
                seen.add(state)
                pending_nodes.append((carrier, state))
        for target_name in assign_targets.get(expr, ()):
            existing = bound.setdefault(target_name, set())
            if state not in existing:
                existing.add(state)
                for next_expr in name_nodes.get(target_name, ()):
                    seen = node_states.setdefault(next_expr, set())
                    if state not in seen:
                        seen.add(state)
                        pending_nodes.append((next_expr, state))
    return False


def _report_import_scope(
    imports: list[ast.ImportFrom],
    nodes: list[ast.AST],
    annotations: set[ast.AST],
    path: Path,
    result: ScanResult,
    *,
    project_imports: _ProjectImports | None,
) -> None:
    if _reaches_low_level(nodes):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: low-level MCP server tool list uncollected"
        )
    modules = {module for module, _ in _FACTORIES}
    qualified_import = any(
        isinstance(node, ast.Import) and any(a.name in modules for a in node.names)
        for node in nodes
    )
    if qualified_import or any(
        stmt.module in modules and any(a.name == "*" for a in stmt.names) for stmt in imports
    ):
        result.surfaces_excluded.append(f"{path.as_posix()}: unresolved Python MCP factory import")
    # Isolated and installed entry points may skip the checkout even when a
    # regular package of the same name is present beside this file.
    qualified_sdk_import = any(
        isinstance(node, ast.Import) and any(_framework_module(a.name, None) for a in node.names)
        for node in nodes
    )
    if qualified_sdk_import or _unrecognized_framework_import(
        imports, nodes, annotations, project_imports
    ):
        result.surfaces_excluded.append(f"{path.as_posix()}: unresolved Python SDK tool import")


def _under(module: str, roots: Sequence[str]) -> bool:
    return any(module == root or module.startswith(f"{root}.") for root in roots)


def _framework_module(module: str, project_imports: _ProjectImports | None) -> bool:
    if _under(module, ("agents",)) and project_imports and project_imports.has_module(module):
        return False
    return _under(module, _FRAMEWORK_ROOTS) and not _under(module, _FRAMEWORK_CLIENTS)


def _unrecognized_framework_import(
    imports: list[ast.ImportFrom],
    nodes: list[ast.AST],
    annotations: set[ast.AST],
    project_imports: _ProjectImports | None,
) -> bool:
    """Whether the file imports from a framework something that can carry tools unseen.

    A star import counts, and so does any name the collector does not read tools from
    that is a submodule or function, either of which can reach the tool decorator, or a
    tool or toolset class, unless it is used only as a type in annotations. Names an
    exact module exports by name, a framework's ``mcp`` client module included, are
    the collector's or the source collector's to read.
    """
    found: set[str] = set()
    for stmt in imports:
        module = stmt.module
        if module is None or not _framework_module(module, project_imports):
            continue
        for a in stmt.names:
            if (module, a.name) in _DECORATOR_IMPORTS or (module, a.name) in _AGENT_FACTORIES:
                continue
            if (module, a.name) in _NON_REGISTERING_IMPORTS and (
                project_imports is None or not project_imports.shadows(module, a.name)
            ):
                continue
            if a.name == "*":
                return True
            if a.name == "mcp" and module in _FRAMEWORK_ROOTS:
                continue
            if not a.name[0].isupper() or "tool" in a.name.lower():
                found.add(a.asname or a.name)
    if not found:
        return False
    typed = {
        node.id
        for node in nodes
        if isinstance(node, ast.Name) and node.id in found and node in annotations
    }
    return any(
        isinstance(node, ast.Name)
        and node.id in found
        and isinstance(node.ctx, ast.Load)
        and node not in annotations
        for node in nodes
    ) or bool(found - typed)


def _factory_calls_and_rebinds(
    nodes: list[ast.AST], factories: dict[str, ast.ImportFrom]
) -> tuple[set[ast.Call], set[str]]:
    calls = {
        node
        for node in nodes
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in factories
    }
    changed_receivers = {
        node.value.id
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr == "tool"
        and isinstance(node.value, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    return calls, changed_receivers


def _server_from_assignment(
    stmt: ast.Assign,
    calls: set[ast.Call],
    factories: dict[str, ast.ImportFrom],
    top_level: set[ast.stmt],
    bindings: Counter[str],
    changed_receivers: set[str],
    path: Path,
    source_digest: str,
    known: KnownValues | None,
) -> tuple[ast.Call, MCPServerComponent] | None:
    target = stmt.targets[0]
    call = stmt.value
    if not (
        isinstance(target, ast.Name)
        and isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call in calls
    ):
        return None
    factory = call.func.id
    imported = factories[factory]
    if (
        imported not in top_level
        or imported.lineno >= stmt.lineno
        or bindings[factory] != 1
        or target.id in changed_receivers
        or bindings[target.id] != 1
        or len(call.args) > _SDK_POSITIONALS.get(imported.module or "", _PLAIN_POSITIONALS)
        or any(isinstance(arg, ast.Starred) for arg in call.args)
        or any(kw.arg is None or kw.arg in _REGISTERING_KEYWORDS for kw in call.keywords)
    ):
        return None
    # The variable is bound once in this file, so path and variable identify the
    # server, where a declared name can repeat; the line is informational and moving
    # it is not a new server.
    constructor = _string_constants([*call.args, *(kw.value for kw in call.keywords)])
    risks: list[RiskAssessment] = []
    if constructor:
        # The name and instructions a constructor declares reach the model as served.
        from nexus_symbiote.scanners.prompt import definition_text_risks

        risks = definition_text_risks(
            {"constructor": constructor}, f"{path.as_posix()}:{stmt.lineno} ({target.id})"
        )
    server = MCPServerComponent(
        bom_ref=f"mcp-python:{quote(path.as_posix(), safe='')}:{target.id}",
        name=_declared_python_name(call, known) or target.id,
        source_path=path.as_posix(),
        risks=risks,
        properties={
            "binding": target.id,
            "method": "python-ast",
            "collection_mode": "static-source-declaration",
            "runtime_registration": "unknown",
            "declaration_line": stmt.lineno,
            "source_sha256": source_digest,
        },
    )
    return call, server


def _declared_python_name(call: ast.Call, known: KnownValues | None) -> str | None:
    """The name a constructor declares as a string literal, first or as ``name=``."""
    given = [*call.args[:1], *(kw.value for kw in call.keywords if kw.arg == "name")]
    if len(given) != 1 or not isinstance(given[0], ast.Constant):
        return None
    return declared_server_name(given[0].value, known)


def _tool_decorator(deco: ast.expr) -> tuple[str, ast.Call | ast.Attribute] | None:
    """The receiver name of ``@name.tool(...)`` or ``@name.tool``."""
    target = deco.func if isinstance(deco, ast.Call) else deco
    if (
        isinstance(target, ast.Attribute)
        and target.attr == "tool"
        and isinstance(target.value, ast.Name)
    ):
        return target.value.id, deco if isinstance(deco, ast.Call) else target
    return None


def _unwrapped(registers: list[bool]) -> list[bool]:
    """For each decorator, whether every decorator below it registers a tool too.

    Decorators apply from the bottom up, so one below a registration hands it whatever
    function it returns, under whatever name and signature it gives.
    """
    unwrapped = [True] * len(registers)
    below = True
    for index in range(len(registers) - 1, -1, -1):
        unwrapped[index] = below
        below = below and registers[index]
    return unwrapped


def _record_decorated_tools(
    stmt: ast.FunctionDef | ast.AsyncFunctionDef,
    servers: dict[str, MCPServerComponent],
    handled: set[ast.AST],
    path: Path,
    source_digest: str,
    result: ScanResult,
) -> None:
    unwrapped = _unwrapped(
        [
            (found := _tool_decorator(deco)) is not None and found[0] in servers
            for deco in stmt.decorator_list
        ]
    )
    for index, deco in enumerate(stmt.decorator_list):
        found = _tool_decorator(deco)
        if found is None or found[0] not in servers:
            continue
        receiver, node = found
        attribute = node.func if isinstance(node, ast.Call) else node
        if isinstance(attribute, ast.Attribute):
            handled.update((attribute, attribute.value))
        if not unwrapped[index]:
            result.surfaces_excluded.append(
                f"{path.as_posix()}:{deco.lineno}: unresolved Python MCP tool name"
            )
            continue
        _record_decorator(
            node, stmt.name, servers[receiver], path, source_digest, result, func_node=stmt
        )


class _Helper(NamedTuple):
    """How a call binds a top-level function's parameters, and the parameters it uses
    unsafely: any use a server's name could not have at the top level, and any use in a
    nested scope, which closes over the parameter. A keyword never binds a
    positional-only parameter, so ``keywords`` leaves those out of ``named``."""

    positional: tuple[str, ...]
    keywords: frozenset[str]
    named: frozenset[str]
    unsafe: frozenset[str]


_SCOPES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.GeneratorExp,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
)


def _helper(
    function: ast.FunctionDef | ast.AsyncFunctionDef, parents: dict[ast.AST, ast.AST]
) -> _Helper:
    positional = tuple(arg.arg for arg in (*function.args.posonlyargs, *function.args.args))
    keywords = frozenset(arg.arg for arg in (*function.args.args, *function.args.kwonlyargs))
    named = keywords | frozenset(arg.arg for arg in function.args.posonlyargs)
    unsafe: set[str] = set()
    pending: list[tuple[ast.AST, bool]] = [(n, False) for n in ast.iter_child_nodes(function)]
    while pending:
        node, nested = pending.pop()
        if (
            isinstance(node, ast.Name)
            and node.id in named
            and (
                nested
                or not isinstance(node.ctx, ast.Load)
                or not _safe_use(node, parents, _SERVER_DATA, _SERVER_CALLS, _SERVER_DECORATORS)
            )
        ):
            unsafe.add(node.id)
        nested = nested or isinstance(node, _SCOPES)
        pending.extend((child, nested) for child in ast.iter_child_nodes(node))
    return _Helper(positional, keywords, named, frozenset(unsafe))


def _referenced_outside_calls(nodes: list[ast.AST], parents: dict[ast.AST, ast.AST]) -> set[str]:
    """Names and attribute names the file uses other than as the function called."""
    referenced: set[str] = set()
    for node in nodes:
        if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
            use = parents.get(node)
            if isinstance(use, ast.Call) and use.func is node:
                continue
        if isinstance(node, ast.Name):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            referenced.add(node.attr)
        elif (pair := _getattr_attr(node)) is not None:
            use = parents.get(node)
            if not (isinstance(use, ast.Call) and use.func is node):
                referenced.add(pair[1])
    return referenced


def _benign_helper_arguments(
    tree: ast.Module,
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    servers: dict[str, MCPServerComponent],
    bindings: Counter[str],
) -> set[ast.AST]:
    """Servers passed to a helper of this file that registers nothing on them and keeps
    no reference to them.

    Only an undecorated function whose name the file binds once is read, since a
    call can otherwise reach another definition or what a decorator returned. Each
    helper is read once, however many calls pass it a server, so the work stays
    linear in the size of the file. A positional argument at or after a ``*``
    spread binds a parameter that cannot be read from the call, so it is not judged
    benign. A ``**`` spread cannot rebind a parameter the call already binds, since
    Python raises before the body runs, so it changes nothing here. A helper the file
    names other than by calling it, by its name or as an attribute, could have its
    code, defaults or module binding replaced, as ``object.__setattr__(configure,
    "__code__", code)`` or ``module.configure = swap`` do, so it is not read.
    """
    referenced = _referenced_outside_calls(nodes, parents)
    functions = {
        stmt.name: stmt
        for stmt in tree.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not stmt.decorator_list
        and bindings[stmt.name] == 1
        and stmt.name not in referenced
    }
    helpers: dict[str, _Helper] = {}
    benign: set[ast.AST] = set()
    for node in nodes:
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        function = functions.get(node.func.id)
        if function is None or not any(
            isinstance(value, ast.Name) and value.id in servers
            for value in (*node.args, *(keyword.value for keyword in node.keywords))
        ):
            continue
        helper = helpers.get(function.name)
        if helper is None:
            helper = helpers[function.name] = _helper(function, parents)
        known = len(helper.positional)
        for index, value in enumerate(node.args):
            if isinstance(value, ast.Starred):
                known = min(known, index)
        passed = [
            (helper.positional[index] if index < known else None, value)
            for index, value in enumerate(node.args)
        ] + [
            (keyword.arg if keyword.arg in helper.keywords else None, keyword.value)
            for keyword in node.keywords
        ]
        for parameter, value in passed:
            if (
                isinstance(value, ast.Name)
                and value.id in servers
                and parameter is not None
                and parameter not in helper.unsafe
            ):
                benign.add(value)
    return benign


def _chain(node: ast.expr) -> list[ast.AST] | None:
    """The nodes of a name, or of attributes of a name, the name last."""
    chain: list[ast.AST] = []
    while isinstance(node, ast.Attribute):
        chain.append(node)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    chain.append(node)
    return chain


def _typing_generics(nodes: list[ast.AST]) -> tuple[set[str], dict[str, str]]:
    """Names the file binds only to a typing generic or leaves to a built-in generic,
    and names it binds only to one module, with that module."""
    bindings = _bindings(nodes)
    generics: Counter[str] = Counter()
    modules: dict[str, list[str]] = {}
    mutated: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and not node.level and node.module in _TYPING_MODULES:
            generics.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                modules.setdefault(name, []).append(alias.name if alias.asname else name)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            target: ast.expr = node.value
            while True:
                if isinstance(target, ast.Attribute):
                    target = target.value
                elif (pair := _getattr_attr(target)) is not None:
                    target = pair[0]
                else:
                    break
            if isinstance(target, ast.Name):
                mutated.add(target.id)
    names = {name for name, count in generics.items() if bindings[name] == count}
    names.update(name for name in _GENERIC_BUILTINS if not bindings[name])
    roots = {
        name: paths[0]
        for name, paths in modules.items()
        if bindings[name] == len(paths) and len(set(paths)) == 1 and name not in mutated
    }
    return names, roots


def _generic(node: ast.expr, names: set[str], roots: dict[str, str]) -> bool:
    """Whether ``node`` is a generic whose subscript only records types."""
    attributes: list[str] = []
    while isinstance(node, ast.Attribute):
        attributes.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return False
    if not attributes:
        return node.id in names
    if node.id not in roots:
        return False
    module = ".".join((roots[node.id], *reversed(attributes))).rpartition(".")[0]
    return module in _TYPING_MODULES


# Built-in classes an annotation may name or combine with ``|`` as types, while the
# file leaves the name to the builtin.
_TYPE_BUILTINS = _names(
    "bool bytearray bytes complex dict float frozenset int list memoryview object set str tuple"
    " type"
)
# Named SDK types with specific annotation semantics. Other imports from these
# packages still need analysis when operators such as subscription evaluate them.
_SDK_GENERICS = frozenset(
    {
        ("agents", "RunContextWrapper"),
        ("agents.run_context", "RunContextWrapper"),
        ("fastmcp", "Context"),
        ("fastmcp.server", "Context"),
        ("fastmcp.server.context", "Context"),
        ("mcp.server.fastmcp", "Context"),
        ("mcp.server.fastmcp.server", "Context"),
        ("mcp.server.mcpserver", "Context"),
        ("pydantic_ai", "RunContext"),
        ("pydantic_ai.tools", "RunContext"),
    }
)
_SDK_TYPES = (
    _SDK_GENERICS | _FACTORIES | {("agents", "Agent"), ("agents.agent", "Agent"), *_AGENT_FACTORIES}
)


# Concrete SDK context parameters used by its public examples. They are safe as
# direct arguments of the real Context generic, not operands of arbitrary code.
_CONTEXT_ARGUMENTS = frozenset(
    {
        ("mcp", "ServerSession"),
        ("mcp.server.session", "ServerSession"),
        ("mcp.shared.context", "RequestContext"),
        ("mcp.types", "Request"),
        ("mcp.types", "ServerRequest"),
        ("starlette.requests", "Request"),
    }
)
SDK_IMPORT_ROOTS = frozenset(
    module.partition(".")[0]
    for module, _ in _SDK_TYPES | _CONTEXT_ARGUMENTS | set(_DECORATOR_IMPORTS)
)


class _TypeSyntax:
    """Which parts of annotations Python evaluates only as types.

    Evaluating ``A | B`` hands each operand to the other's ``__or__`` or ``__ror__``,
    and FastMCP and ``typing.get_type_hints`` evaluate annotations whatever the
    ``__future__`` import says. Plain builtin and typing expressions are checked
    recursively. Optional server types are recognized separately. Combining
    SDK objects, or passing a server class to an SDK subscript, remains visible
    to registration analysis. Purity is cached per node.
    """

    def __init__(self, nodes: list[ast.AST], project_imports: _ProjectImports | None) -> None:
        self._names, self._roots = _typing_generics(nodes)
        self._sdk_types = frozenset(
            identity
            for identity in _SDK_TYPES
            if project_imports is None or not project_imports.shadows(*identity)
        )
        self._sdk_generics = _SDK_GENERICS & self._sdk_types
        self._optional_types = (_FACTORIES | _SDK_GENERICS) & self._sdk_types
        self._context_arguments = {
            identity
            for identity in _CONTEXT_ARGUMENTS
            if project_imports is None or not project_imports.shadows(*identity)
        }
        known_classes = self._sdk_types | self._context_arguments
        bindings = _bindings(nodes)
        imported: dict[str, list[tuple[str, str]]] = {}
        for node in nodes:
            if isinstance(node, ast.ImportFrom) and not node.level and node.module is not None:
                for alias in node.names:
                    identity = (node.module, alias.name)
                    if identity in known_classes:
                        imported.setdefault(alias.asname or alias.name, []).append(identity)
        self._classes = {
            name: paths[0]
            for name, paths in imported.items()
            if bindings[name] == len(paths) and len(set(paths)) == 1
        }
        self._builtins = {name for name in _TYPE_BUILTINS if not bindings[name]}
        self._pure: dict[ast.AST, bool] = {}

    def _sdk_type(self, node: ast.expr) -> tuple[str, str] | None:
        attributes: list[str] = []
        while isinstance(node, ast.Attribute):
            attributes.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        if not attributes:
            return self._classes.get(node.id)
        module = self._roots.get(node.id)
        if module is None:
            return None
        return ".".join((module, *reversed(attributes[1:]))), attributes[0]

    def _children(self, node: ast.AST) -> list[ast.AST] | None:
        """The parts whose purity decides ``node``'s, or None when it is not pure."""
        if isinstance(node, ast.Constant):
            return []
        if isinstance(node, (ast.Name, ast.Attribute)):
            if isinstance(node, ast.Name) and node.id in self._builtins:
                return []
            return [] if _generic(node, self._names, self._roots) else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return [node.left, node.right]
        if isinstance(node, ast.Subscript):
            return [node.slice] if _generic(node.value, self._names, self._roots) else None
        if isinstance(node, (ast.Tuple, ast.List)):
            return list(node.elts)
        return None

    def pure(self, node: ast.AST) -> bool:
        known = self._pure
        stack = [node]
        while stack:
            item = stack[-1]
            if item in known:
                stack.pop()
                continue
            children = self._children(item)
            if children is None:
                known[item] = False
                stack.pop()
                continue
            missing = [child for child in children if child not in known]
            if missing:
                stack.extend(missing)
                continue
            known[item] = all(known[child] for child in children)
            stack.pop()
        return known[node]

    def _sdk_subscript(self, annotation: ast.Subscript) -> bool:
        generic = self._sdk_type(annotation.value)
        if generic is None or generic not in self._sdk_generics:
            return False
        if self.pure(annotation.slice):
            return True
        if generic[1] != "Context":
            return False
        arguments = (
            annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
        )
        return all(
            self.pure(arg) or self._sdk_type(arg) in self._context_arguments for arg in arguments
        )

    def parts(self, annotations: Sequence[ast.expr]) -> set[ast.AST]:
        """The names, attributes of names and string constants used only as types."""
        pending = list(annotations)
        found: set[ast.AST] = set()
        while pending:
            annotation = pending.pop()
            chain = _chain(annotation)
            if chain is not None:
                found.update(chain)
            elif isinstance(annotation, ast.Constant):
                found.add(annotation)
            elif isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
                # A union of two SDK values can invoke SDK-defined operators.
                # A simple optional SDK annotation retains its type-only use.
                optional_sdk_type = any(
                    (
                        self._sdk_type(value) in self._optional_types
                        or (isinstance(value, ast.Subscript) and self._sdk_subscript(value))
                    )
                    and isinstance(other, ast.Constant)
                    and other.value is None
                    for value, other in (
                        (annotation.left, annotation.right),
                        (annotation.right, annotation.left),
                    )
                )
                if self.pure(annotation) or optional_sdk_type:
                    pending += (annotation.left, annotation.right)
            elif isinstance(annotation, (ast.Tuple, ast.List)):
                pending += annotation.elts
            elif isinstance(annotation, ast.Subscript) and (
                _generic(annotation.value, self._names, self._roots)
                or self._sdk_subscript(annotation)
            ):
                found.update(_chain(annotation.value) or ())
                pending.append(annotation.slice)
        return found


def _annotation_names(
    nodes: list[ast.AST],
    extra_roots: Sequence[ast.expr] = (),
    *,
    project_imports: _ProjectImports | None = None,
) -> set[ast.AST]:
    """Names, and attributes of names, that annotations use only as types.

    Annotations are evaluated, at definition time or later, so only these parts are
    set aside: the whole annotation, a member of a ``|`` union of pure type syntax
    (see ``_TypeSyntax``), and an argument of a generic of ``typing``,
    ``typing_extensions`` or ``collections.abc``, such as ``Optional[...]``, of a
    built-in generic such as ``list[...]``, or of a recognized SDK generic with only
    plain type arguments. A call, a walrus, any other
    subscript or union and every other expression in an annotation is analyzed as code.
    """
    pending: list[ast.expr] = list(extra_roots)
    for node in nodes:
        if isinstance(node, ast.arg) and node.annotation is not None:
            pending.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns:
            pending.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            pending.append(node.annotation)
    return _TypeSyntax(nodes, project_imports).parts(pending)


class _ParsedAnnotations(NamedTuple):
    all_nodes: list[ast.AST]
    all_parents: dict[ast.AST, ast.AST]
    by_arg: dict[ast.arg, list[ast.AST]]
    roots: tuple[ast.expr, ...]
    overflow: bool


def _typing_aliases(nodes: list[ast.AST]) -> dict[str, str]:
    """Names the file binds only to one name imported from a typing module, with it."""
    bindings = _bindings(nodes)
    imported: dict[str, set[str]] = {}
    counts: Counter[str] = Counter()
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and not node.level and node.module in _TYPING_MODULES:
            for alias in node.names:
                imported.setdefault(alias.asname or alias.name, set()).add(alias.name)
                counts[alias.asname or alias.name] += 1
    return {
        name: next(iter(names))
        for name, names in imported.items()
        if len(names) == 1 and bindings[name] == counts[name]
    }


def _typing_name(node: ast.expr, aliases: dict[str, str], roots: dict[str, str]) -> str | None:
    """The name in a typing module that ``node`` refers to, by its imported name."""
    chain = _chain(node)
    root = chain[-1] if chain is not None else None
    if chain is None or not isinstance(root, ast.Name):
        return None
    if len(chain) == 1:
        return aliases.get(root.id)
    if root.id not in roots:
        return None
    attributes = [link.attr for link in reversed(chain) if isinstance(link, ast.Attribute)]
    module, _, name = ".".join((roots[root.id], *attributes)).rpartition(".")
    return name if module in _TYPING_MODULES else None


# Bounds on the strings parsed from one file's annotations: one string's characters,
# strings nested in strings, and syntax nodes parsed from all of them.
_ANNOTATION_CHARACTERS = 4096
_ANNOTATION_NESTING = 4
_ANNOTATION_NODES = 10_000


def _forward_reference(text: str) -> ast.expr | None:
    """``text`` parsed as ``typing.ForwardRef`` compiles it, or None if it does not parse.

    ForwardRef unpacks a leading ``*`` by compiling ``(text,)[0]``. Compiler warnings
    quote the text's raw bytes, and as errors they would fail the parse, so they are
    ignored.
    """
    source = f"({text},)[0]" if text.startswith("*") else text
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return ast.parse(source, mode="eval").body
        except (SyntaxError, ValueError, MemoryError, OverflowError, RecursionError):
            return None


def _parse_string_annotations(
    nodes: list[ast.AST], parents: dict[ast.AST, ast.AST]
) -> _ParsedAnnotations:
    """Parse the strings in annotations that can be evaluated as forward references.

    ``typing.get_type_hints`` and the SDKs evaluate a string that is the annotation, a
    member of a ``|`` union, an element of a tuple or list in it, or an argument of
    any subscript, since a generic converts string arguments to forward references.
    ``Literal`` arguments and ``Annotated`` metadata are values, recognized by the name
    they are imported as. A string past the bounds, one that does not parse, perhaps
    only for this Python, and an f-string overflow, so the caller can fail closed.
    """
    _, roots = _typing_generics(nodes)
    aliases = _typing_aliases(nodes)
    pending: list[tuple[ast.expr, ast.arg | None, int]] = []
    for node in nodes:
        if isinstance(node, ast.arg) and node.annotation is not None:
            pending.append((node.annotation, node, 0))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns:
            pending.append((node.returns, None, 0))
        elif isinstance(node, ast.AnnAssign):
            pending.append((node.annotation, None, 0))
    extra_nodes: list[ast.AST] = []
    extra_parents: dict[ast.AST, ast.AST] = {}
    by_arg: dict[ast.arg, list[ast.AST]] = {}
    parsed_roots: list[ast.expr] = []
    overflow = False
    while pending:
        annotation, owner_arg, depth = pending.pop()
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            pending.append((annotation.left, owner_arg, depth))
            pending.append((annotation.right, owner_arg, depth))
        elif isinstance(annotation, (ast.Tuple, ast.List)):
            for elt in annotation.elts:
                pending.append((elt, owner_arg, depth))
        elif isinstance(annotation, ast.Starred):
            pending.append((annotation.value, owner_arg, depth))
        elif isinstance(annotation, ast.Subscript):
            pending.append((annotation.value, owner_arg, depth))
            origin = _typing_name(annotation.value, aliases, roots)
            arguments = annotation.slice
            if origin == "Literal":
                continue
            if origin == "Annotated" and isinstance(arguments, ast.Tuple) and arguments.elts:
                arguments = arguments.elts[0]
            pending.append((arguments, owner_arg, depth))
        elif isinstance(annotation, ast.JoinedStr):
            overflow = True
        elif isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            text = annotation.value.strip()
            if not text:
                # ForwardRef cannot compile it, so nothing is evaluated.
                continue
            parsed = (
                _forward_reference(text)
                if len(text) <= _ANNOTATION_CHARACTERS and depth < _ANNOTATION_NESTING
                else None
            )
            if parsed is None:
                overflow = True
                continue
            walked = list(ast.walk(parsed))
            if len(extra_nodes) + len(walked) > _ANNOTATION_NODES:
                overflow = True
                continue
            extra_nodes.extend(walked)
            parsed_roots.append(parsed)
            for parent_node in walked:
                for child in ast.iter_child_nodes(parent_node):
                    extra_parents[child] = parent_node
            if owner_arg is not None:
                by_arg.setdefault(owner_arg, []).extend(walked)
            pending.append((parsed, owner_arg, depth + 1))
    if not extra_nodes:
        return _ParsedAnnotations(nodes, parents, by_arg, (), overflow)
    return _ParsedAnnotations(
        [*nodes, *extra_nodes],
        {**parents, **extra_parents},
        by_arg,
        tuple(parsed_roots),
        overflow,
    )


def _has_unsupported_registration(
    tree: ast.Module,
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    parsed: _ParsedAnnotations,
    annotations: set[ast.AST],
    sdk_import: bool,
    calls: set[ast.Call],
    handled: set[ast.AST],
    servers: dict[str, MCPServerComponent],
    factories: dict[str, ast.ImportFrom],
    bindings: Counter[str],
) -> bool:
    """Whether a recognised server or factory escapes the supported forms."""
    if (
        parsed.overflow
        or calls - handled
        or (
            (servers or sdk_import)
            and _reflective_access(parsed.all_nodes, parsed.all_parents, bindings)
        )
    ):
        return True
    factory_calls = {call.func for call in calls}
    # A server named in an annotation is exposed through __annotations__.
    safe = {node for node in annotations if not (isinstance(node, ast.Name) and node.id in servers)}
    safe |= _safe_receivers(
        nodes, parents, servers, _SERVER_DATA, _SERVER_CALLS, _SERVER_DECORATORS
    )
    safe |= _benign_helper_arguments(tree, nodes, parents, servers, bindings)
    for node in parsed.all_nodes:
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load) or node in safe:
            continue
        if node.id in servers and node not in handled:
            return True
        if node.id in factories and node not in factory_calls:
            return True
    return False


def _imported_receivers(tree: ast.Module) -> bool:
    """A ``.tool`` decorator whose receiver, or its root module, is bound by an import."""
    imported = {
        (alias.asname or alias.name).split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if any(name.id in imported for name in _expr_roots(node.value)):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id not in imported:
                            imported.add(target.id)
                            changed = True
            elif (
                isinstance(node, ast.AnnAssign)
                and node.value is not None
                and isinstance(node.target, ast.Name)
                and node.target.id not in imported
                and any(name.id in imported for name in _expr_roots(node.value))
            ):
                imported.add(node.target.id)
                changed = True
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            target = deco.func if isinstance(deco, ast.Call) else deco
            t_pair = _getattr_attr(target)
            if isinstance(target, ast.Attribute) and target.attr == "tool":
                pending: list[ast.expr] = [target.value]
            elif t_pair is not None and t_pair[1] == "tool":
                pending = [t_pair[0]]
            else:
                continue
            while pending:
                root = pending.pop()
                if any(name.id in imported for name in _expr_roots(root)):
                    return True
    return False


def _unrecognized_tool_receivers(tree: ast.Module, known_agent_receivers: set[str]) -> bool:
    """Whether a function carries a ``.tool`` decorator on an unrecognized receiver."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            target = deco.func if isinstance(deco, ast.Call) else deco
            t_pair = _getattr_attr(target)
            if isinstance(target, ast.Attribute) and target.attr == "tool":
                recv = target.value
            elif t_pair is not None and t_pair[1] == "tool":
                recv = t_pair[0]
            else:
                continue
            if isinstance(recv, ast.Name) and recv.id in known_agent_receivers:
                continue
            return True
    return False


def _report_imported_receivers(tree: ast.Module, path: Path, result: ScanResult) -> bool:
    """A file without a recognised server factory may still register tools on an imported one."""
    if _imported_receivers(tree):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: Python MCP tools registered on an imported server"
        )
        return True
    return False


def _sdk_module(module: str | None) -> bool:
    return (module or "").split(".")[0] in _SDK_ROOTS


def _imports_mcp_sdk(nodes: list[ast.AST]) -> bool:
    return any(
        (isinstance(node, ast.Import) and any(_sdk_module(a.name) for a in node.names))
        or (isinstance(node, ast.ImportFrom) and not node.level and _sdk_module(node.module))
        for node in nodes
    )


def _sdk_module_names(nodes: list[ast.AST], bindings: Counter[str]) -> set[str]:
    """Names the file binds only to a module of ``mcp`` or ``fastmcp``."""
    imports: Counter[str] = Counter()
    for node in nodes:
        if isinstance(node, ast.Import):
            for a in node.names:
                if _sdk_module(a.name):
                    imports[a.asname or a.name.split(".")[0]] += 1
    return {name for name, count in imports.items() if bindings[name] == count}


def _module_paths(nodes: list[ast.AST], modules: set[str]) -> dict[str, str]:
    """The module each of ``modules`` is bound to, where every import binds the same."""
    paths: dict[str, set[str]] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for a in node.names:
                name = a.asname or a.name.split(".")[0]
                if name in modules:
                    paths.setdefault(name, set()).add(a.name if a.asname else name)
    return {name: next(iter(found)) for name, found in paths.items() if len(found) == 1}


def _module_path(node: ast.Attribute, paths: dict[str, str]) -> str | None:
    """The dotted path of attributes alone from a name bound to a module."""
    chain = _chain(node)
    root = chain[-1] if chain is not None else None
    if chain is None or not isinstance(root, ast.Name) or root.id not in paths:
        return None
    attributes = [link.attr for link in reversed(chain) if isinstance(link, ast.Attribute)]
    return ".".join((paths[root.id], *attributes))


def _getattr_attr(node: ast.AST) -> tuple[ast.expr, str] | None:
    """The target and literal attribute name of ``getattr(target, "attr", ...)``.

    The builtin takes its arguments by position, so anything past the first two can
    only supply the default or make the call fail.
    """
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and not any(isinstance(a, ast.Starred) for a in node.args[:2])
    ):
        return None
    attribute = node.args[1]
    if isinstance(attribute, ast.Constant) and isinstance(attribute.value, str):
        return node.args[0], attribute.value
    return None


def _attribute_access(node: ast.AST) -> tuple[ast.expr, str] | None:
    if isinstance(node, ast.Attribute):
        return node.value, node.attr
    return _getattr_attr(node)


def _carried(item: ast.expr) -> list[ast.expr]:
    """The parts an attribute, literal ``getattr`` or non-call carrier expression
    takes its value from, other than through a constructor call."""
    if isinstance(item, (ast.Attribute, ast.Starred, ast.Subscript)):
        return [item.value]
    pair = _getattr_attr(item)
    if pair is not None and isinstance(item, ast.Call):
        return [pair[0], *item.args[2:]]
    if isinstance(item, ast.NamedExpr):
        return [item.target, item.value]
    if isinstance(item, (ast.Tuple, ast.List, ast.Set)):
        return list(item.elts)
    if isinstance(item, ast.Dict):
        return [val for val in item.values if val is not None]
    if isinstance(item, ast.BoolOp):
        return list(item.values)
    if isinstance(item, ast.IfExp):
        return [item.body, item.orelse]
    return []


def _expr_roots(node: ast.expr) -> list[ast.Name]:
    """The names an attribute, literal ``getattr`` or non-call carrier expression can
    start from without crossing a constructor call."""
    pending: list[ast.expr] = [node]
    roots: list[ast.Name] = []
    while pending:
        item = pending.pop()
        if isinstance(item, ast.Name):
            roots.append(item)
        else:
            pending.extend(_carried(item))
    return roots


class _RootedAt:
    """Whether an expression starts from one of ``names``, as ``_expr_roots`` finds.

    Every link of an attribute chain is asked about, and each would walk the rest of
    the chain again; deciding each node once keeps the work linear in the nodes.
    """

    def __init__(self, names: set[str]) -> None:
        self._names = names
        self._known: dict[ast.AST, bool] = {}

    def __call__(self, node: ast.expr) -> bool:
        known = self._known
        stack: list[ast.expr] = [node]
        while stack:
            item = stack[-1]
            if item in known:
                stack.pop()
                continue
            if isinstance(item, ast.Name):
                known[item] = item.id in self._names
                stack.pop()
                continue
            parts = _carried(item)
            missing = [part for part in parts if part not in known]
            if missing:
                stack.extend(missing)
                continue
            known[item] = any(known[part] for part in parts)
            stack.pop()
        return known[node]


def _target_names(node: ast.expr) -> list[str]:
    pending: list[ast.expr] = [node]
    names: list[str] = []
    while pending:
        item = pending.pop()
        if isinstance(item, ast.Name):
            names.append(item.id)
        elif isinstance(item, (ast.Tuple, ast.List, ast.Set)):
            pending.extend(item.elts)
        elif isinstance(item, ast.Starred):
            pending.append(item.value)
    return names


def _sdk_roots(nodes: list[ast.AST], modules: set[str]) -> set[str]:
    """SDK module names, symbols imported from them, and variables bound from them."""
    roots = set(modules) | {bound for _, bound in _sdk_imported(nodes)}
    edges: dict[str, set[str]] = {}
    pairs: list[tuple[list[ast.expr], list[ast.expr]]] = []
    for node in nodes:
        if isinstance(node, ast.Assign):
            pairs.append((node.targets, [node.value]))
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            pairs.append(([node.target], [node.value]))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            pairs.append(([node.target], [node.iter]))
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            value = node.context_expr
            values = [value]
            if isinstance(value, ast.Call):
                values.extend((*value.args, *(kw.value for kw in value.keywords)))
            pairs.append(([node.optional_vars], values))
        elif isinstance(node, ast.arguments):
            positional = [*node.posonlyargs, *node.args]
            arg_pairs = [
                *zip(
                    positional[len(positional) - len(node.defaults) :], node.defaults, strict=True
                ),
                *zip(node.kwonlyargs, node.kw_defaults, strict=True),
            ]
            pairs.extend(
                ([ast.Name(id=argument.arg)], [default])
                for argument, default in arg_pairs
                if default is not None
            )
    for index, (targets, values) in enumerate(pairs):
        joint = f"#{index}"
        for val in values:
            for src in _expr_roots(val):
                edges.setdefault(src.id, set()).add(joint)
        for target in targets:
            for dst in _target_names(target):
                edges.setdefault(joint, set()).add(dst)
    queue = deque(roots)
    while queue:
        current = queue.popleft()
        for target_name in edges.get(current, ()):
            if target_name not in roots:
                roots.add(target_name)
                queue.append(target_name)
    return {name for name in roots if not name.startswith("#")}


def _scopes(parents: dict[ast.AST, ast.AST]) -> dict[ast.AST, ast.AST | None]:
    """The function, lambda or class each node is in, or None at module level.

    Climbing from each name separately would take time in the depth of the
    expression around it; each node is resolved once here.
    """
    scopes: dict[ast.AST, ast.AST | None] = {}
    for node in parents:
        chain: list[ast.AST] = []
        item = node
        while item not in scopes:
            owner = parents.get(item)
            if owner is None or isinstance(
                owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                scopes[item] = owner
                break
            chain.append(item)
            item = owner
        for link in chain:
            scopes[link] = scopes[item]
    return scopes


def _sdk_imported(nodes: list[ast.AST]) -> list[tuple[str, str]]:
    """What the file imports from ``mcp`` or ``fastmcp`` modules, and the names bound."""
    return [
        (a.name, a.asname or a.name)
        for node in nodes
        if isinstance(node, ast.ImportFrom) and not node.level and _sdk_module(node.module)
        for a in node.names
    ]


def _gets_context(node: ast.AST) -> bool:
    """Whether ``node`` is ``getattr(..., "Context")``, which names the SDK class as
    ``X.Context`` does."""
    pair = _getattr_attr(node)
    return pair is not None and pair[1] == "Context"


def _names_context(
    annotation: ast.expr,
    extra: Sequence[ast.AST],
    types: set[str],
    roots: set[str],
    rooted: _RootedAt,
) -> bool:
    for node in (*ast.walk(annotation), *extra):
        if (isinstance(node, ast.Name) and node.id in types) or _gets_context(node):
            return True
        access = _attribute_access(node)
        if access is not None and access[1] == "Context" and rooted(access[0]):
            return True
        if (isinstance(node, ast.Name) and node.id == "getattr") or (
            isinstance(node, ast.Attribute) and node.attr == "getattr"
        ):
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            words = set(re.findall(r"[A-Za-z_]\w*", node.value))
            if words & types or ("Context" in words and words & roots):
                return True
    return False


def _reads_context(use: ast.Attribute, parents: dict[ast.AST, ast.AST]) -> bool:
    """Whether reading ``use`` from a context, or calling it, cannot return the context."""
    call = parents.get(use)
    if isinstance(call, ast.Call) and call.func is use:
        return use.attr in _CONTEXT_METHODS
    return use.attr in _CONTEXT_DATA


def _context_bindings(
    parsed: _ParsedAnnotations,
    roots: set[str],
    rooted: _RootedAt,
    scopes: dict[ast.AST, ast.AST | None],
    project_imports: _ProjectImports | None,
) -> tuple[set[tuple[ast.AST | None, str]], bool]:
    """Parameters typed as an SDK context and names bound to ``get_context()``, by scope.

    The second value is whether the SDK ``Context`` or ``get_context`` is used other
    than to annotate a parameter, or to read from or bind the result of a call. An
    alias, a subclass or a re-export of ``Context`` can type a parameter in a file the
    analysis does not follow it into. A name declared ``global`` or ``nonlocal``, or
    assigned in a class or module body, is exposed beyond local function scope, so
    binding the result to one is a use.
    """
    nodes = parsed.all_nodes
    parents = parsed.all_parents
    imported = _sdk_imported(nodes)
    types = {bound for name, bound in imported if name == "Context"}
    getters = {bound for name, bound in imported if name == "get_context"}
    declared = {
        (scopes.get(node), name)
        for node in nodes
        if isinstance(node, (ast.Global, ast.Nonlocal))
        for name in node.names
    }
    syntax = _TypeSyntax(nodes, project_imports)
    parsed_roots = set(parsed.roots)
    annotations: set[ast.AST] = set()
    bound: set[tuple[ast.AST | None, str]] = set()
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            arguments = node.args
            for arg in [
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
                *(a for a in (arguments.vararg, arguments.kwarg) if a is not None),
            ]:
                if arg.annotation is None:
                    continue
                extra = parsed.by_arg.get(arg, ())
                annotations |= syntax.parts(
                    [
                        arg.annotation,
                        *(n for n in extra if n in parsed_roots and isinstance(n, ast.expr)),
                    ]
                )
                if _names_context(arg.annotation, extra, types, roots, rooted):
                    bound.add((node, arg.arg))
    escaped = False
    used: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Name) and node.id in types:
            used.add(node.id)
            escaped = escaped or node not in annotations
        elif isinstance(node, ast.Constant) and node in annotations and isinstance(node.value, str):
            used.update(re.findall(r"[A-Za-z_]\w*", node.value))
        elif (
            (
                (
                    (access := _attribute_access(node)) is not None
                    and access[1] == "Context"
                    and rooted(access[0])
                )
                or _gets_context(node)
            )
            and node not in annotations
        ) or ((pair := _getattr_attr(node)) is not None and pair[1] == "get_context"):
            escaped = True
        elif (isinstance(node, ast.Name) and node.id in getters) or (
            isinstance(node, ast.Attribute) and node.attr == "get_context"
        ):
            call = parents.get(node)
            use = parents.get(call) if isinstance(call, ast.Call) else None
            if not isinstance(call, ast.Call) or call.func is not node:
                escaped = True
            elif isinstance(use, ast.Assign) and len(use.targets) == 1:
                target = use.targets[0]
                scope = scopes.get(use)
                if (
                    isinstance(target, ast.Name)
                    and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
                    and (scope, target.id) not in declared
                ):
                    bound.add((scope, target.id))
                else:
                    escaped = True
            elif not (
                isinstance(use, ast.Attribute)
                and use.value is call
                and _reads_context(use, parents)
            ):
                escaped = True
    return bound, escaped or bool(types - used)


def _context_escapes(
    name: ast.Name,
    parents: dict[ast.AST, ast.AST],
    scopes: dict[ast.AST, ast.AST | None],
    bound: set[tuple[ast.AST | None, str]],
    resolved: dict[tuple[ast.AST | None, str], bool],
) -> bool:
    """Whether a use of a context can hand it to code the collector does not read.

    ``resolved`` records, for each scope climbed, whether the name there refers to a
    context, so nested scopes are climbed once in all and not once for each use.
    """
    scope = scopes.get(name)
    climbed: list[tuple[ast.AST | None, str]] = []
    while (key := (scope, name.id)) not in resolved:
        if key in bound or scope is None:
            resolved[key] = key in bound
            break
        climbed.append(key)
        scope = scopes.get(scope)
    for key in climbed:
        resolved[key] = resolved[(scope, name.id)]
    if not resolved[(scope, name.id)]:
        return False
    use = parents.get(name)
    if isinstance(use, ast.Attribute):
        return not _reads_context(use, parents)
    if isinstance(use, ast.Compare):
        return not all(isinstance(op, (ast.Is, ast.IsNot)) for op in use.ops)
    test: ast.AST = name
    while isinstance(use, ast.BoolOp) or (
        isinstance(use, ast.UnaryOp) and isinstance(use.op, ast.Not)
    ):
        test, use = use, parents.get(use)
    return not (isinstance(use, (ast.If, ast.While, ast.IfExp, ast.Assert)) and use.test is test)


def _private(name: str) -> bool:
    return name.startswith("_") and not name.endswith("__")


def _names_handle(name: str, sdk_import: bool) -> bool:
    bare = name.lstrip("_")
    return bare in _SERVER_HANDLES or (
        sdk_import and (bare in _SDK_SERVER_HANDLES or bare in _SDK_ACCESSORS)
    )


def _report_context_handles(
    parsed: _ParsedAnnotations,
    sdk_import: bool,
    bindings: Counter[str],
    path: Path,
    result: ScanResult,
    project_imports: _ProjectImports | None,
) -> None:
    """A server reached through a request context can be given tools from any handler.

    Handle names other than ``fastmcp`` and ``fastmcp_server`` are common outside MCP,
    so they count only in a file that imports from ``mcp`` or ``fastmcp``.
    ``mcp.server.fastmcp``, reached by attributes alone from a name bound to an SDK
    module, is a module path, not a context; any other object can hold one. A private
    name of an SDK module can hold any of these in a release the lists do not know.
    Storing an attribute of an SDK module or symbol can change what servers built
    elsewhere are given, or carry a context to a read the path does not reveal. A
    context typed as the SDK ``Context``, or returned by ``get_context()``, that is
    passed on, stored or returned can reach code the collector does not read.
    """
    nodes = parsed.all_nodes
    parents = parsed.all_parents
    modules = _sdk_module_names(nodes, bindings)
    paths = _module_paths(nodes, modules)
    roots = _sdk_roots(nodes, modules)
    rooted = _RootedAt(roots)
    handle = False
    for node in nodes:
        access = _attribute_access(node)
        if access is not None:
            target, attr = access
            if _names_handle(attr, sdk_import) and not (
                isinstance(node, ast.Attribute)
                and attr == "fastmcp"
                and _module_path(node, paths) == _FASTMCP_MODULE
            ):
                handle = True
                break
            if _private(attr) and rooted(target):
                handle = True
                break
            if (
                isinstance(node, ast.Attribute)
                and not isinstance(node.ctx, ast.Load)
                and rooted(target)
            ):
                handle = True
                break
        elif (
            isinstance(node, ast.ImportFrom)
            and not node.level
            and _sdk_module(node.module)
            and any(_names_handle(a.name, True) or _private(a.name) for a in node.names)
        ):
            handle = True
            break
    if not handle and sdk_import:
        scopes = _scopes(parents)
        bound, handle = _context_bindings(parsed, roots, rooted, scopes, project_imports)
        names = {name for _, name in bound}
        resolved: dict[tuple[ast.AST | None, str], bool] = {}
        handle = handle or any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in names
            and _context_escapes(node, parents, scopes, bound, resolved)
            for node in nodes
        )
    if handle:
        result.surfaces_excluded.append(
            f"{path.as_posix()}: Python MCP server reachable through a request context"
        )


def _report_unused_factories(
    nodes: list[ast.AST],
    annotations: set[ast.AST],
    factories: dict[str, ast.ImportFrom],
    path: Path,
    result: ScanResult,
) -> None:
    """A server class imported and not used other than as a type in an annotation is
    passed on.

    Another module can import it from this one and build servers the collector does
    not see there, because that import does not name the SDK.
    """
    if not factories:
        return
    used = {
        node.id
        for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node not in annotations
    }
    if set(factories) - used:
        result.surfaces_excluded.append(
            f"{path.as_posix()}: MCP server class imported without a use here; servers built "
            "from it elsewhere not inventoried"
        )


def collect_python_tools(
    tree: ast.Module,
    nodes: list[ast.AST],
    source: str,
    path: Path,
    result: ScanResult,
    known: KnownValues | None = None,
    *,
    project_imports: _ProjectImports | None = None,
) -> None:
    """Support direct SDK imports, module constructors and top-level decorators.

    ``nodes`` holds every node of ``tree``; the caller holds their number to the
    ``python-nodes`` limit, and the work here is linear in it. A declared server name
    holding one of the ``known`` values is not recorded.
    """
    if not any(hint in source for hint in PYTHON_TOOL_HINTS):
        return
    imports = [node for node in nodes if isinstance(node, ast.ImportFrom) and not node.level]
    candidates = [
        stmt
        for stmt in imports
        if any(
            (stmt.module, alias.name) in _SDK_TYPES
            or (stmt.module, alias.name) in _DECORATOR_IMPORTS
            for alias in stmt.names
        )
    ]
    resolved = [
        stmt
        for stmt in candidates
        if stmt.module is not None
        and (
            project_imports is None
            or all(not project_imports.shadows(stmt.module, alias.name) for alias in stmt.names)
        )
    ]
    if len(resolved) != len(candidates):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: Python SDK import may resolve to checkout code"
        )
    factories = {
        a.asname or a.name: stmt
        for stmt in resolved
        for a in stmt.names
        if (stmt.module, a.name) in _FACTORIES
    }
    decorators = {
        a.asname or a.name: (stmt, _DECORATOR_IMPORTS[(stmt.module, a.name)])
        for stmt in resolved
        for a in stmt.names
        if stmt.module is not None and (stmt.module, a.name) in _DECORATOR_IMPORTS
    }
    agent_factories = {
        a.asname or a.name: (stmt, _AGENT_FACTORIES[(stmt.module, a.name)])
        for stmt in resolved
        for a in stmt.names
        if stmt.module is not None and (stmt.module, a.name) in _AGENT_FACTORIES
    }
    bindings = _bindings(nodes)
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    sdk_import = _imports_mcp_sdk(nodes)
    parsed = _parse_string_annotations(nodes, parents)
    annotations = _annotation_names(nodes, parsed.roots, project_imports=project_imports)
    _report_import_scope(imports, nodes, annotations, path, result, project_imports=project_imports)
    _report_context_handles(parsed, sdk_import, bindings, path, result, project_imports)
    _report_unused_factories(nodes, annotations, factories, path, result)
    if not factories and not decorators and not agent_factories:
        imported_gap = _report_imported_receivers(tree, path, result)
        if (
            sdk_import
            and not imported_gap
            and (
                parsed.overflow
                or _reflective_access(parsed.all_nodes, parsed.all_parents, bindings)
                or _unrecognized_tool_receivers(tree, set())
            )
        ):
            result.surfaces_excluded.append(
                f"{path.as_posix()}: unsupported Python MCP binding or dynamic registration"
            )
        return
    if any(
        isinstance(stmt, ast.ImportFrom) and any(a.name == "*" for a in stmt.names)
        for stmt in nodes
    ):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: Python MCP bindings exceed supported scope"
        )
        return

    source_digest = hash_bytes(source.encode("utf-8"))
    seen_refs: set[str] = set()
    if decorators:
        _collect_sdk_decorators(
            tree, nodes, decorators, bindings, path, source_digest, seen_refs, result
        )
    agent_receivers: set[str] = set()
    if agent_factories:
        agent_receivers = _collect_agent_decorators(
            tree,
            nodes,
            parents,
            parsed,
            annotations,
            agent_factories,
            bindings,
            path,
            source_digest,
            seen_refs,
            result,
        )
    if not factories:
        imported_gap = _report_imported_receivers(tree, path, result)
        if (
            sdk_import
            and not imported_gap
            and (
                parsed.overflow
                or _reflective_access(parsed.all_nodes, parsed.all_parents, bindings)
                or _unrecognized_tool_receivers(tree, agent_receivers)
            )
        ):
            result.surfaces_excluded.append(
                f"{path.as_posix()}: unsupported Python MCP binding or dynamic registration"
            )
        return
    top_level = set(tree.body)
    servers: dict[str, MCPServerComponent] = {}
    calls, changed_receivers = _factory_calls_and_rebinds(nodes, factories)
    if sum(isinstance(node, ast.Attribute) and node.attr == "tool" for node in nodes) > 1000:
        result.scan_failures.append(
            f"{path.as_posix()}: Python MCP tool registration limit exceeded"
        )
        return
    handled: set[ast.AST] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            found = _server_from_assignment(
                stmt,
                calls,
                factories,
                top_level,
                bindings,
                changed_receivers,
                path,
                source_digest,
                known,
            )
            target = stmt.targets[0]
            if found is None or not isinstance(target, ast.Name):
                continue
            call, server = found
            handled.add(call)
            handled.add(target)
            servers[target.id] = server
            result.components.append(server)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _record_decorated_tools(stmt, servers, handled, path, source_digest, result)
    if _has_unsupported_registration(
        tree,
        nodes,
        parents,
        parsed,
        annotations,
        sdk_import,
        calls,
        handled,
        servers,
        factories,
        bindings,
    ) or _imported_receivers(tree):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: unsupported Python MCP binding or dynamic registration"
        )
