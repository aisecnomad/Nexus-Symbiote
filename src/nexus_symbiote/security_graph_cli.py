"""The ``security-graph`` CLI command: multi-hop advisory and risk correlation."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.runtime_cli import _refuse_source_overwrite
from nexus_symbiote.security_graph import (
    MAX_CORRELATION_CHAINS,
    build_security_graph,
    render_security_graph_html,
    render_security_graph_json,
    render_security_graph_markdown,
    render_security_graph_mermaid,
)
from nexus_symbiote.utils.terminal import echo_line, json_text, neutralize, write_cli_output
from nexus_symbiote.vex_decisions import (
    VEXDecisionError,
    load_advisory_report,
    load_execution_evidence,
)


def register_security_graph_commands(main: click.Group) -> None:
    @main.command("security-graph")
    @click.argument("inventory", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "--advisories",
        "advisories_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Optional advisory report JSON produced by `advisories` (live or --offline-db).",
    )
    @click.option(
        "--allow-partial-advisories",
        is_flag=True,
        help="Accept an advisory report whose coverage is partial or none.",
    )
    @click.option(
        "--trace-evidence",
        "trace_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Optional trace-diff report JSON annotating reported runtime invocation status.",
    )
    @click.option(
        "--trace-attestation",
        "trace_attestation",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Verified Ed25519 DSSE attestation envelope for --trace-evidence.",
    )
    @click.option(
        "--trusted-key",
        "trusted_keys",
        multiple=True,
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Trusted Ed25519 public key PEM for --trace-attestation (repeatable).",
    )
    @click.option(
        "--allow-unsigned-trace-evidence",
        is_flag=True,
        help="Accept unattested --trace-evidence explicitly.",
    )
    @click.option(
        "--format",
        "output_format",
        type=click.Choice(["json", "mermaid", "markdown", "html"]),
        default="json",
        show_default=True,
        help="Output format.",
    )
    @click.option(
        "--max-chains",
        type=click.IntRange(1, MAX_CORRELATION_CHAINS),
        default=MAX_CORRELATION_CHAINS,
        show_default=True,
        help="Maximum correlated exposure chains to emit.",
    )
    @click.option(
        "--fail-on-chain",
        is_flag=True,
        help="Exit non-zero if any correlated exposure chain is found.",
    )
    @click.option(
        "--fail-on-kev",
        is_flag=True,
        help="Exit non-zero if any KEV-listed advisory reaches an inventory component or agent.",
    )
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        default=None,
        help="Write the report to this file instead of standard output (required for HTML).",
    )
    def security_graph_command(
        inventory: Path,
        advisories_path: Path | None,
        allow_partial_advisories: bool,
        trace_path: Path | None,
        trace_attestation: Path | None,
        trusted_keys: tuple[Path, ...],
        allow_unsigned_trace_evidence: bool,
        output_format: str,
        max_chains: int,
        fail_on_chain: bool,
        fail_on_kev: bool,
        output: Path | None,
    ) -> None:
        """Correlate advisories, risks, tools, agents, credentials, and data sinks."""
        if output_format == "html" and output is None:
            raise click.UsageError("the HTML view is written to a file: pass -o/--output")
        for protected in (
            inventory,
            *(p for p in (advisories_path, trace_path, trace_attestation) if p is not None),
            *trusted_keys,
        ):
            _refuse_source_overwrite(output, protected)
        try:
            bom, raw_inventory = AIBOM.load_with_bytes(inventory)
            inv_sha = hash_bytes(raw_inventory)
        except (NativeFormatError, OSError) as exc:
            raise click.ClickException(
                f"{neutralize(inventory)} is not a valid native AIBOM file. {neutralize(exc)}"
            ) from exc

        advisory_report = None
        if advisories_path is not None:
            try:
                advisory_report = load_advisory_report(
                    advisories_path,
                    expected_inventory_sha256=inv_sha,
                    allow_partial=allow_partial_advisories,
                )
            except (VEXDecisionError, ValueError, RecursionError) as exc:
                raise click.ClickException(neutralize(exc)) from exc

        execution_evidence = None
        if trace_path is not None:
            try:
                execution_evidence = load_execution_evidence(
                    trace_path,
                    inventory_path=inventory,
                    expected_inventory_sha256=inv_sha,
                    attestation_path=trace_attestation,
                    trusted_key_paths=trusted_keys,
                    allow_unsigned=allow_unsigned_trace_evidence,
                )
            except (VEXDecisionError, ValueError, RecursionError) as exc:
                raise click.ClickException(neutralize(exc)) from exc

        try:
            report = build_security_graph(
                bom,
                advisory_report=advisory_report,
                execution_evidence=execution_evidence,
                inventory_sha256=inv_sha,
                max_chains=max_chains,
            )
        except ValueError as exc:
            raise click.ClickException(neutralize(exc)) from exc

        if output_format == "json":
            rendered = render_security_graph_json(report)
        elif output_format == "mermaid":
            rendered = render_security_graph_mermaid(report)
        elif output_format == "markdown":
            rendered = render_security_graph_markdown(report)
        else:
            rendered = render_security_graph_html(report)

        if output is None:
            click.echo(json_text(rendered) if output_format == "json" else rendered, nl=False)
            if output_format == "json":
                click.echo()
        else:
            write_cli_output(output, rendered)
            echo_line(
                "Security graph: ",
                f"{report.node_count} nodes, {report.edge_count} edges, "
                f"{report.chain_count} chains ({report.kev_chain_count} KEV)",
                err=True,
            )

        if (fail_on_kev and report.kev_chain_count > 0) or (
            fail_on_chain and report.chain_count > 0
        ):
            sys.exit(1)
