"""Replay the LangGraph/CrewAI ownership swap through an installed Nexus CLI."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

FIXTURES = Path(__file__).resolve().parent
EXPECTED = {
    "before": {("CopperReader", "gpt-4o-mini"), ("VioletCurator", "gpt-4.1-mini")},
    "after": {("CopperReader", "gpt-4.1-mini"), ("VioletCurator", "gpt-4o-mini")},
}
MODEL_TYPES = {"model", "model-endpoint", "model-weights"}


def bindings(document: dict) -> set[tuple[str, str]]:
    """Read the two named agents' explicit model references from native inventory."""
    components = document["components"]
    by_ref = {component["bom_ref"]: component for component in components}
    if len(by_ref) != len(components):
        raise ValueError("Duplicate native component reference")
    owners = {
        ref: component
        for ref, component in by_ref.items()
        if component["component_type"] == "agent"
        and component["name"] in {"CopperReader", "VioletCurator"}
    }
    if len({agent["name"] for agent in owners.values()}) != len(owners):
        raise ValueError("Ambiguous native agent identity")
    links = {(ref, model) for ref, agent in owners.items() for model in agent.get("model_refs", [])}
    links.update(
        (edge["source_ref"], edge["target_ref"])
        for edge in document["dependencies"]
        if edge["relationship"] == "uses-model" and edge["source_ref"] in owners
    )
    found = set()
    for owner, ref in links:
        model = by_ref.get(ref)
        if model is None or model["component_type"] not in MODEL_TYPES:
            raise ValueError(f"Agent model reference {ref!r} has no typed model target")
        name = model["name"]
        if name.startswith(("openai:", "openai/")):
            name = name[7:]
        found.add((owners[owner]["name"], name))
    return found


def score(observed: dict[str, set[tuple[str, str]]]) -> dict:
    snapshots = {}
    for phase, expected in EXPECTED.items():
        actual = observed[phase]
        snapshots[phase] = {
            "found": sorted(actual),
            "missing": sorted(expected - actual),
            "extra": sorted(actual - expected),
        }

    # An extra static binding in both snapshots disappears from a delta. Check both as well.
    def changes(pair):
        return {("-", *binding) for binding in pair["before"] - pair["after"]} | {
            ("+", *binding) for binding in pair["after"] - pair["before"]
        }

    wanted, found = changes(EXPECTED), changes(observed)
    return {
        "passed": observed == EXPECTED,
        "snapshots": snapshots,
        "correct_changes": len(wanted & found),
        "expected_changes": len(wanted),
        "missing_changes": sorted(wanted - found),
        "extra_changes": sorted(found - wanted),
    }


def replay(cli: str, scratch: Path, output: Path) -> dict:
    project = scratch / "project"
    observed = {}
    for phase in EXPECTED:
        shutil.copytree(FIXTURES / phase, project)
        artifact = output / f"{phase}.json"
        # The scanner's working directory is outside the fixture (which declares a queue.py).
        command = [
            cli,
            "--offline",
            "scan",
            str(project),
            "--no-project-policy",
            "-f",
            "json",
            "-o",
            str(artifact),
        ]
        subprocess.run(command, cwd=scratch, check=True, stdout=sys.stderr, timeout=120)  # noqa: S603 -- operator-selected CLI with literal scan arguments
        document = json.loads(artifact.read_text(encoding="utf-8"))
        failures = document["metadata"]["completeness"]["scan_failures"]
        if failures:
            raise ValueError(f"{phase} scan recorded collection failures: {failures}")
        observed[phase] = bindings(document)
        shutil.rmtree(project)
    return score(observed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", default="nexus-symbiote", help="Installed executable")
    parser.add_argument(
        "--out", type=Path, help="Create a new directory for both inventories and the score"
    )
    args = parser.parse_args()
    cli = shutil.which(args.cli)
    if cli is None:
        parser.error(f"CLI executable not found: {args.cli}")
    try:
        with TemporaryDirectory(prefix="nexus-model-swap-") as directory:
            scratch = Path(directory).resolve()
            output = args.out.resolve() if args.out else scratch / "reports"
            if any(output.is_relative_to(FIXTURES / phase) for phase in EXPECTED):
                raise ValueError("Choose an output directory outside the input fixtures")
            output.mkdir(parents=True, exist_ok=False)
            result = replay(str(Path(cli).resolve()), scratch, output)
            rendered = json.dumps(result, indent=2) + "\n"
            (output / "score.json").write_text(rendered, encoding="utf-8")
            sys.stdout.write(rendered)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"Could not complete model-swap replay: {exc}", file=sys.stderr)
        return 2
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
