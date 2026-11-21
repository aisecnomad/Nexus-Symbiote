"""Helpers shared by test modules; fixtures that wrap them live in conftest.py."""

from __future__ import annotations

import gc
import importlib.util
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load_script(name: str) -> ModuleType:
    """Import scripts/<name>.py once, by its own name, with its sibling scripts importable."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve string annotations through sys.modules.
    sys.modules[name] = module
    added = str(SCRIPTS) not in sys.path
    if added:
        sys.path.insert(0, str(SCRIPTS))
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    finally:
        if added:
            sys.path.remove(str(SCRIPTS))
    return module


def scaling_ratio(run: Callable[[int], object], factor: int = 4, repeats: int = 2) -> float:
    """CPU time of run(factor) over run(1), each the best of ``repeats`` runs.

    Linear work grows about ``factor`` times, quadratic work about ``factor`` squared. Two
    sizes measured on the same machine cancel what an absolute bound cannot: a slow or busy
    runner and coverage tracing. A burst of load during one size still skews the ratio, so
    a ratio well above linear is measured once more and the smaller one returned: work
    that is not linear measures high both times.

    The cyclic collector is off while a run is timed, as in ``timeit``. A full collection
    costs time in proportion to every object the test process holds, not to the work
    measured, and starts once a run allocates enough: late in a long suite that is every
    larger run and few smaller ones, which reads as growth the code does not have.
    """

    def timed(scale: int, iterations: int) -> float:
        gc.collect()
        collecting = gc.isenabled()
        gc.disable()
        try:
            started = time.process_time()
            for _ in range(iterations):
                run(scale)
            return time.process_time() - started
        finally:
            if collecting:
                gc.enable()

    def best(scale: int) -> float:
        timings = []
        for _ in range(repeats):
            iterations = 1
            elapsed = timed(scale, iterations)
            while elapsed < 2e-3 and iterations < 32:
                iterations *= 2
                elapsed = timed(scale, iterations)
            timings.append(elapsed / iterations)
        return max(min(timings), 1e-5)

    ratio = best(factor) / best(1)
    if ratio > 1.5 * factor:
        ratio = min(ratio, best(factor) / best(1))
    return ratio


def otlp_attribute(key: str, value: object) -> dict[str, object]:
    """One OTLP/JSON attribute: a string as stringValue, an int as intValue, a dict as is."""
    if isinstance(value, dict):
        return {"key": key, "value": value}
    if isinstance(value, int) and not isinstance(value, bool):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": value}}


def otlp_span(
    attributes: dict[str, object], *, kind: int = 1, start: int | None = 1_700_000_000_000_000_000
) -> dict[str, object]:
    """An OTLP/JSON span with these attributes, in the order given."""
    span: dict[str, object] = {
        "traceId": "5b8efff798038103d269b633813fc60c",
        "spanId": "eee19b7ec3c1b174",
        "name": "span",
        "kind": kind,
        "attributes": [otlp_attribute(key, value) for key, value in attributes.items()],
    }
    if start is not None:
        span["startTimeUnixNano"] = str(start)
    return span


def otlp_export(
    *spans: dict[str, object], resource: dict[str, object] | None = None
) -> dict[str, object]:
    """One ExportTraceServiceRequest holding ``spans`` under one resource and scope."""
    attributes = [otlp_attribute(key, value) for key, value in (resource or {}).items()]
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": attributes},
                "scopeSpans": [{"scope": {"name": "tests"}, "spans": list(spans)}],
            }
        ]
    }


STDIO_HELLO = {
    "protocolVersion": "2025-06-18",
    "capabilities": {"tools": {}},
    "serverInfo": {"name": "fixture", "version": "1"},
}
_LAUNCHER_TEMPLATE = """#!{python}
import json, os, sys, time
log = {log!r}
hello = {hello!r}


def record(*entry):
    with open(log, "a") as stream:
        stream.write(json.dumps(list(entry)) + "\\n")


def emit(raw):
    sys.stdout.write(raw + "\\n")
    sys.stdout.flush()


def reply(result, request_id=None):
    emit(json.dumps({{"jsonrpc": "2.0", "id": msg["id"] if request_id is None else request_id, "result": result}}))


record("started", os.getpid())
page = 0
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    record(method, os.getpid())
    if method == "notifications/initialized":
        continue
    if method == "initialize":
{on_initialize}
        continue
    if method == "tools/list":
        page += 1
{on_list}
        continue
    raise SystemExit(1)
"""


def misbehaving_launcher(
    path: Path,
    log: Path,
    *,
    on_list: str = "reply({'tools': []})",
    on_initialize: str = "reply(hello)",
    hello: dict[str, object] | None = None,
) -> str:
    """Write a pinned stdio MCP launcher whose replies are the Python snippets given.

    Each snippet runs inside the request loop with ``msg`` (the request), ``page`` (how many
    ``tools/list`` requests arrived so far), ``reply(result)``, ``emit(raw_line)`` and
    ``hello``. The launcher appends ``["started", pid]`` and then ``[method, pid]`` for every
    request to ``log``. Returns the launcher's ``sha256:`` pin.
    """
    import hashlib
    import textwrap

    script = _LAUNCHER_TEMPLATE.format(
        python=sys.executable,
        log=str(log),
        hello=STDIO_HELLO if hello is None else hello,
        on_initialize=textwrap.indent(textwrap.dedent(on_initialize).strip("\n"), " " * 8),
        on_list=textwrap.indent(textwrap.dedent(on_list).strip("\n"), " " * 8),
    )
    path.write_text(script)
    path.chmod(0o700)
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def launcher_log(log: Path) -> list[list[object]]:
    """The entries a misbehaving launcher recorded, oldest first."""
    import json

    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


# Layouts in which someone other than the caller or root could replace a trust anchor.
REPLACEABLE_ANCHOR_LAYOUTS = (
    "group-writable file",
    "group-writable parent",
    "world-writable grandparent",
    "foreign-owned grandparent",
)


def trust_anchor_in_layout(
    base: Path, layout: str, name: str, data: bytes, monkeypatch: Any
) -> Path:
    """Write ``base/anchors/dir/name`` so the file or a directory above it fits ``layout``.

    ``"sticky grandparent"`` is the accepted control: a world-writable sticky directory,
    such as ``/tmp``, owned by the caller. A foreign owner is shown through ``os.lstat``
    so the case runs without root.
    """
    grandparent = base / "anchors"
    parent = grandparent / "dir"
    parent.mkdir(parents=True)
    path = parent / name
    path.write_bytes(data)
    path.chmod(0o664 if layout == "group-writable file" else 0o600)
    parent.chmod(0o775 if layout == "group-writable parent" else 0o700)
    modes = {"world-writable grandparent": 0o777, "sticky grandparent": 0o1777}
    grandparent.chmod(modes.get(layout, 0o700))
    if layout == "foreign-owned grandparent":
        host_lstat = os.lstat
        target = os.fspath(grandparent.absolute())

        def lstat(entry: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            info = host_lstat(entry, *args, **kwargs)
            if os.fspath(entry) == target:
                return os.stat_result((*info[:4], 4242, *info[5:10]))
            return info

        monkeypatch.setattr(os, "lstat", lstat)
    return path
