#!/usr/bin/env python3
"""Replay the named order router and its three source-benchmark links on a native BOM.

The fixture snapshots the source benchmark's agent.py and order policy with an
unregistered tool example added. The replay reads these files as data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

FIXTURE = Path(__file__).resolve().parent / "fixture"
FIXTURE_FILES = ("agent.py", "examples/unregistered.py", "prompts/order_policy.md")
MAX_BOM_BYTES = 16 * 1024 * 1024
RELATIONSHIPS = (
    ("chat", "model", "gpt-4o-mini", "agent.py", {22}, {"uses-model"}),
    ("tool", "tool", "lookup_order", "agent.py", {15, 16}, {"invokes", "configured-with"}),
    ("prompt", "prompt-template", None, "prompts/order_policy.md", None, {"reads-instructions"}),
)
WORKFLOW_REF_TYPES = {
    "model_refs": {"model"},
    "tool_refs": {"tool", "mcp-server"},
    "prompt_refs": {"prompt-template"},
}


def _rows(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = document.get(key)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError(f"Native AgentBOM needs an array of objects in {key}")
    return rows


def _locations(component: dict[str, Any]) -> set[tuple[str, int | None]]:
    """Recognize native source evidence without matching filename suffixes."""
    properties = component.get("properties") or {}
    claims = component.get("claims") or {}
    if not isinstance(properties, dict) or not isinstance(claims, dict):
        return set()
    line = properties.get("declaration_line", properties.get("source_line"))
    candidates = [
        (component.get("source_path"), line),
        (properties.get("reference_path"), line),
        *((claim.get("locator"), None) for claim in claims.values() if isinstance(claim, dict)),
    ]
    locations = set()
    for path, line in candidates:
        if not isinstance(path, str):
            continue
        stem, separator, suffix = path.rpartition(":")
        if separator and 0 < len(suffix) <= 8 and suffix.isascii() and suffix.isdecimal():
            path, line = stem, int(suffix)
        locations.add((path.removeprefix("./"), line if type(line) is int else None))
    return locations


def _subject(
    component: dict[str, Any],
    kind: str,
    name: str | None,
    path: str,
    lines: set[int] | None,
) -> dict[str, Any] | None:
    if component.get("component_type") != kind or (
        name is not None and component.get("name") != name
    ):
        return None
    matches = [
        line
        for file, line in _locations(component)
        if file == path and (lines is None or line in lines)
    ]
    if not matches:
        return None
    return {
        "bom_ref": component["bom_ref"],
        "kind": kind,
        "name": component.get("name"),
        "path": path,
        "line": min((line for line in matches if line is not None), default=None),
    }


def _workflow(component: dict[str, Any]) -> dict[str, Any] | None:
    framework = component.get("framework")
    if framework is not None and (
        not isinstance(framework, str) or framework.casefold() != "langgraph"
    ):
        return None
    if component["bom_ref"].startswith("agent:repository:"):
        return None
    return _subject(component, "agent", "atlas_order_router", "agent.py", {39})


def _workflow_edge(edge: dict[str, Any]) -> bool:
    conditions = edge.get("conditions")
    return conditions is None or (
        isinstance(conditions, str) and "repository association" not in conditions.casefold()
    )


def score(document: dict[str, Any]) -> dict[str, Any]:
    """Require a unique named owner and three independently attributable edges."""
    components = _rows(document, "components")
    edges = _rows(document, "dependencies")
    by_ref: dict[str, dict[str, Any]] = {}
    for component in components:
        ref = component.get("bom_ref")
        if not isinstance(ref, str) or not ref.strip() or ref in by_ref:
            raise ValueError("Each native component needs a unique nonempty bom_ref")
        if not isinstance(component.get("name"), str) or not isinstance(
            component.get("component_type"), str
        ):
            raise ValueError("Each native component needs name and component_type strings")
        by_ref[ref] = component
    for edge in edges:
        source, target = edge.get("source_ref"), edge.get("target_ref")
        if not isinstance(source, str) or not isinstance(target, str):
            raise ValueError("Each native dependency needs source_ref and target_ref strings")
        if source not in by_ref or target not in by_ref:
            raise ValueError("Native AgentBOM has an unresolved dependency reference")
    components = [by_ref[ref] for ref in sorted(by_ref)]
    owners = [
        evidence for component in components if (evidence := _workflow(component)) is not None
    ]
    owner_ref = owners[0]["bom_ref"] if len(owners) == 1 else None
    owned_edges = [
        edge for edge in edges if owner_ref is not None and edge.get("source_ref") == owner_ref
    ]
    owned_targets = {edge["target_ref"] for edge in owned_edges}
    if owner_ref is not None:
        for field, kinds in WORKFLOW_REF_TYPES.items():
            refs = by_ref[owner_ref].get(field, [])
            if not isinstance(refs, list) or any(
                not isinstance(ref, str)
                or ref not in by_ref
                or by_ref[ref]["component_type"] not in kinds
                for ref in refs
            ):
                raise ValueError(
                    f"The workflow's {field} must resolve to the expected component kinds"
                )
            if field == "tool_refs":
                owned_targets.update(refs)
    checks: list[dict[str, Any]] = [
        {"id": "workflow", "passed": owner_ref is not None, "evidence": owners}
    ]
    for label, kind, name, path, lines, predicates in RELATIONSHIPS:
        targets = [
            evidence
            for component in components
            if (evidence := _subject(component, kind, name, path, lines)) is not None
        ]
        matches = (
            sorted(
                {
                    edge["relationship"]
                    for edge in owned_edges
                    if edge.get("target_ref") == targets[0]["bom_ref"]
                    and isinstance(edge.get("relationship"), str)
                    and edge["relationship"] in predicates
                    and _workflow_edge(edge)
                }
            )
            if len(targets) == 1
            else []
        )
        checks.append(
            {
                "id": label,
                "passed": bool(matches),
                "evidence": {"source_ref": owner_ref, "targets": targets, "relationships": matches},
            }
        )

    decoys = [
        {"id": "retired-model", "bom_ref": ref}
        for ref, component in by_ref.items()
        if component.get("component_type") == "model"
        and component.get("name") == "gpt-3.5-turbo-0613"
    ]
    decoys.extend(
        {"id": "unregistered-tool", "bom_ref": ref}
        for ref, component in by_ref.items()
        if component.get("component_type") == "tool"
        and component.get("name") == "sample_order_lookup"
        and ref in owned_targets
    )
    earned = sum(check["passed"] for check in checks)
    return {
        "score": earned,
        "total": len(checks),
        "passed": earned == len(checks) and not decoys,
        "checks": checks,
        "decoys": sorted(decoys, key=lambda evidence: (evidence["id"], evidence["bom_ref"])),
    }


def _read_bom(path: Path) -> bytes:
    with path.open("rb") as stream:
        contents = stream.read(MAX_BOM_BYTES + 1)
    if len(contents) > MAX_BOM_BYTES:
        raise ValueError("Native AgentBOM exceeds the 16 MiB replay limit")
    return contents


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("The native AgentBOM contains a duplicate JSON key")
    return value


def _invalid_constant(_value: str) -> None:
    raise ValueError("The native AgentBOM contains a non-finite JSON number")


def _scan(executable: str, fixture: dict[str, bytes]) -> bytes:
    path = shutil.which(executable)
    if path is None:
        raise ValueError("Selected Nexus SymBiote executable was not found")
    scanner = Path(path).resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-workflow-") as directory:
        root = Path(directory)
        project = root / "fixture"
        for filename, contents in fixture.items():
            target = project / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)
        home = root / "home"
        home.mkdir()
        output = root / "inventory.json"
        subprocess.run(  # noqa: S603 - run only the operator-selected scanner
            [
                str(scanner),
                "scan",
                str(project),
                "--no-project-policy",
                "--report-only",
                "-o",
                str(output),
            ],
            cwd=root,
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": str(home),
                "TZ": "UTC",
                "NO_COLOR": "1",
                "NEXUS_SYMBIOTE_MODE": "offline",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=60,
        )
        if any((project / name).read_bytes() != contents for name, contents in fixture.items()):
            raise ValueError("The scanner changed the workflow fixture during replay")
        return _read_bom(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--bom", type=Path, help="Score a saved native AgentBOM")
    inputs.add_argument(
        "--nexus", default="nexus-symbiote", help="Nexus SymBiote executable on PATH or by path"
    )
    parser.add_argument("--out", type=Path, help="Write the receipt to a new JSON file")
    args = parser.parse_args(argv)
    try:
        fixture = {name: (FIXTURE / name).read_bytes() for name in FIXTURE_FILES}
        contents = _read_bom(args.bom) if args.bom is not None else _scan(args.nexus, fixture)
        document = json.loads(
            contents, object_pairs_hook=_unique_keys, parse_constant=_invalid_constant
        )
        if not isinstance(document, dict):
            raise ValueError("Native AgentBOM needs a JSON object")
        receipt = score(document)
        metadata = document.get("metadata")
        receipt["tool_version"] = (
            metadata.get("tool_version") if isinstance(metadata, dict) else None
        )
        receipt["inventory_sha256"] = hashlib.sha256(contents).hexdigest()
        receipt["fixture_files"] = {
            name: hashlib.sha256(contents).hexdigest() for name, contents in fixture.items()
        }
        output = json.dumps(receipt, indent=2) + "\n"
        if args.out is None:
            print(output, end="")
        else:
            with args.out.open("x", encoding="utf-8") as stream:
                stream.write(output)
    except (OSError, ValueError, subprocess.SubprocessError, RecursionError) as error:
        print(f"Workflow replay failed: {error}", file=sys.stderr)
        return 2
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
