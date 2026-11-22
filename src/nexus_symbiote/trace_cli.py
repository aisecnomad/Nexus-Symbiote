"""The trace-diff command: a native inventory against the runtime use that traces report.

Offline: it reads an inventory and OTLP/JSON trace files that the operator already
collected. It never runs the agent, never contacts a collector and never changes the
inventory. The evidence it writes is ``reported``: telemetry comes from the agent's own
instrumentation, so it can reveal undeclared use and cannot prove absence.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import click

from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    neutralize,
    output_failure,
    write_cli_output,
)

LISTED = 20
"""How many undeclared and unidentified items the summary lists; the rest are counted."""


def _same(first: Path, second: Path) -> bool:
    # Path text misses a second name for the same file (a hard link, a bind mount or a
    # case variant), so two existing files are also compared by identity.
    try:
        return first.resolve() == second.resolve() or (
            first.exists() and second.exists() and os.path.samefile(first, second)
        )
    except (OSError, RuntimeError) as exc:
        raise output_failure(exc) from exc


def _refuse_overwrite(outputs: Sequence[Path], inputs: Sequence[Path]) -> None:
    for position, output in enumerate(outputs):
        if any(_same(output, source) for source in inputs):
            raise click.BadParameter("an output must not overwrite the inventory or a trace file")
        if any(_same(output, other) for other in outputs[position + 1 :]):
            raise click.BadParameter("-o and --sarif must name different files")


def _anchor(inventory: Path) -> str:
    """The SARIF location of runtime findings, which no repository file records.

    It is the inventory's path relative to the working directory, or the project policy
    file when the inventory lies outside it, as the inventory's own SARIF export does.
    """
    from nexus_symbiote.generators.sarif import SARIFGenerator

    try:
        return SARIFGenerator(anchor=inventory)._anchor
    except ValueError:
        return SARIFGenerator()._anchor


def _summary(document: Mapping[str, Any]) -> None:
    from nexus_symbiote.trace_evidence import _is_mismatched, coverage_notes, describe

    coverage = document["coverage"]
    reconciliation = document["reconciliation"]
    gate = document["gate"]
    echo_line(
        "Trace evidence: ",
        "runtime use reported by the agent's own instrumentation; a missing span proves nothing",
    )
    echo_line(
        "  Read: ",
        f"trace files {coverage['trace_files']}, spans {coverage['spans_read']}, ",
        f"of which with GenAI or MCP semantics {coverage['genai_or_mcp_spans']}",
    )
    kinds = Counter(entry["kind"] for entry in document["observed"])
    echo_line(
        "  Observed: ",
        ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items())) or "nothing",
    )
    echo_line(
        "  Reconciliation: ",
        ", ".join(
            f"{len(reconciliation[name])} {name.replace('_', ' ')}"
            for name in (
                "matched",
                "undeclared",
                "unidentified",
                "ambiguous",
                "unobserved",
                "unmatched_identifiers",
            )
        ),
    )
    listed = [
        *(("Undeclared", entry) for entry in reconciliation["undeclared"]),
        *(("Unidentified", entry) for entry in reconciliation["unidentified"]),
        *(("Mismatched", entry) for entry in reconciliation["matched"] if _is_mismatched(entry)),
    ]
    for label, entry in listed[:LISTED]:
        spans = entry["span_count"]
        echo_line(f"  {label}: ", describe(entry), f" ({spans} span{'' if spans == 1 else 's'})")
    if len(listed) > LISTED:
        echo_line(
            "  ... ", f"{len(listed) - LISTED} more; -o FILE or --json-output records every one"
        )
    for _level, text in coverage_notes(document):
        echo_line("  Note: ", text)
    if gate["fail_on"] == "none":
        echo_line("Trace gate: ", "not applied (--fail-on none)")
    elif gate["passed"]:
        echo_line(
            "Trace gate passed: ",
            "nothing undeclared appeared in these traces; this does not show that the agent "
            "is safe or that the traces are complete",
        )
    else:
        echo_line("Trace gate failed: ", "; ".join(gate["reasons"]))


@click.command("trace-diff")
@click.argument("inventory", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument(
    "trace_files",
    nargs=-1,
    required=True,
    metavar="TRACE_FILE...",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Write the evidence document to this file.",
)
@click.option(
    "--json-output", is_flag=True, help="Print the evidence document as JSON instead of a summary."
)
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(path_type=Path),
    metavar="SARIF_PATH",
    help="Also write SARIF 2.1.0 results for undeclared runtime use to this file.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["undeclared", "none"]),
    default="undeclared",
    show_default=True,
    help=(
        "undeclared: exit 1 when the traces report a tool, model, agent or MCP endpoint "
        "that the inventory does not declare or whose identifier cannot be read, or a span "
        "whose operation, MCP method or MCP transport cannot be read, or a span or resource "
        "with more than 128 attributes, or when no span carries GenAI or MCP semantics. "
        "none: report only."
    ),
)
def trace_diff(
    inventory: Path,
    trace_files: tuple[Path, ...],
    output: Path | None,
    json_output: bool,
    sarif_path: Path | None,
    fail_on: str,
) -> None:
    """Compare the runtime use that OpenTelemetry traces report with a native inventory.

    TRACE_FILE is an OTLP/JSON trace export the operator already collected: one export
    object, or JSON Lines as the Collector's file exporter writes. Only identifier
    attributes are read; message, prompt and tool-call content is never read, copied or
    printed. Telemetry is a report by the agent's own instrumentation: it can reveal
    undeclared use and cannot prove absence. Exit 0 means that nothing undeclared appeared
    in these traces, not that the agent is safe or that the traces are complete.
    """
    from nexus_symbiote.core.aibom import NativeFormatError
    from nexus_symbiote.otlp import MAX_TRACE_FILES, TraceInputError
    from nexus_symbiote.trace_evidence import collect, render, sarif_document

    if len(trace_files) > MAX_TRACE_FILES:
        raise click.UsageError(f"at most {MAX_TRACE_FILES} trace files can be compared at once")
    _refuse_overwrite(
        [path for path in (output, sarif_path) if path is not None], [inventory, *trace_files]
    )
    try:
        document = collect(inventory, trace_files, fail_on=fail_on)
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(inventory)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from None
    except TraceInputError as exc:
        raise click.ClickException(neutralize(exc)) from None
    text = render(document)
    if sarif_path is not None:
        sarif = sarif_document(document, _anchor(inventory))
        write_cli_output(sarif_path, json.dumps(sarif, indent=2) + "\n")
    if output is not None:
        write_cli_output(output, text)
    if json_output:
        click.echo(json_text(text), nl=False)
    else:
        _summary(document)
    if not document["gate"]["passed"]:
        raise click.exceptions.Exit(1)


def register_trace_commands(main: click.Group) -> None:
    main.add_command(trace_diff)
