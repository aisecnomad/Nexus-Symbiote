"""The ``graph`` command: an inventory's associations, risk classes and exposure paths.

It writes one self-contained HTML file or a JSON document, offline. It restates the
native inventory and its recorded edges; it does not observe runtime reachability or
effective authority.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.runtime_cli import _refuse_source_overwrite
from nexus_symbiote.utils.terminal import echo_line, json_text, neutralize, write_cli_output

DEFAULT_MAX_NODES = 2_000
MAX_NODES = 20_000


def register_graph_commands(main: click.Group) -> None:
    @main.command("graph")
    @click.argument("inventory", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the view to this file; required for HTML. JSON goes to standard output without it.",
    )
    @click.option(
        "--format",
        "output_format",
        type=click.Choice(["html", "json"]),
        default="html",
        show_default=True,
        help="A self-contained HTML page, or the view as a JSON document.",
    )
    @click.option(
        "--focus",
        metavar="REF",
        help=(
            "Show only this component's potential blast radius: it, what depends on it, and "
            "what it and the components of type agent among those reach."
        ),
    )
    @click.option(
        "--max-nodes",
        type=click.IntRange(1, MAX_NODES),
        default=DEFAULT_MAX_NODES,
        show_default=True,
        help=f"Fail rather than show more components than this (at most {MAX_NODES}).",
    )
    def graph(
        inventory: Path,
        output: Path | None,
        output_format: str,
        focus: str | None,
        max_nodes: int,
    ) -> None:
        """Write a view of an inventory's associations, risk classes and exposure paths.

        Exposure paths are the shortest recorded paths from agents and IDE agents to
        components with a code-exec, exfil-capable, write-capable or secret-access class
        or a high or critical finding. Edges are static repository associations; runtime
        use and effective authority are not observed.
        """
        from nexus_symbiote.graph_view import (
            GraphViewError,
            TooManyComponentsError,
            build_view,
            render_html,
            view_document,
        )

        if output_format == "html" and output is None:
            raise click.UsageError("the HTML view is written to a file: pass -o/--output")
        _refuse_source_overwrite(output, inventory)
        bom = _load_inventory(inventory)
        try:
            view = build_view(bom, max_nodes=max_nodes, focus=focus)
        except TooManyComponentsError as exc:
            raise click.ClickException(
                f"The view would show {exc.count} components, more than --max-nodes "
                f"{exc.limit}. Select part of the graph with --focus REF, or raise "
                f"--max-nodes (at most {MAX_NODES})."
            ) from exc
        except GraphViewError as exc:
            raise click.ClickException(neutralize(exc)) from exc
        if output_format == "html":
            text = render_html(view)
        else:
            text = json.dumps(view_document(view), indent=2)
        if output is None:
            click.echo(json_text(text))
            return
        write_cli_output(output, text)
        echo_line(
            "Graph view: ",
            f"{len(view.nodes)} components, {len(view.edges)} edges, "
            f"{len(view.paths)} exposure paths; coverage {view.coverage.status}",
            err=True,
        )

    @main.command("export-policy")
    @click.argument("inventory", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "--format",
        "policy_format",
        type=click.Choice(["cedar", "rego", "json"]),
        default="cedar",
        show_default=True,
        help="Target authorization policy language.",
    )
    @click.option(
        "--verified-only/--include-declared",
        default=True,
        show_default=True,
        help="Allowlist only observed/verified components with pinned digests, or include declared entries.",
    )
    @click.option(
        "--project",
        type=click.Path(exists=True, file_okay=False, path_type=Path),
        default=None,
        help="Reconcile INVENTORY against this project before exporting a --verified-only policy.",
    )
    @click.option(
        "--signature-policy",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Explicit operator signer policy JSON for model verification; requires --project.",
    )
    @click.option(
        "--require-attestation",
        "attestation_envelope",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Verify a reviewed DSSE inventory attestation envelope for INVENTORY; requires --trusted-key.",
    )
    @click.option(
        "--trusted-key",
        "trusted_keys",
        multiple=True,
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Trusted Ed25519 public key PEM for --require-attestation (repeatable).",
    )
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the policy to this file instead of standard output.",
    )
    def export_policy(
        inventory: Path,
        policy_format: str,
        verified_only: bool,
        project: Path | None,
        signature_policy: Path | None,
        attestation_envelope: Path | None,
        trusted_keys: tuple[Path, ...],
        output: Path | None,
    ) -> None:
        """Export a default-deny Cedar, Rego, or JSON runtime allowlist from an inventory."""
        from nexus_symbiote.policy_export import run_export_policy

        run_export_policy(
            inventory,
            policy_format=policy_format,
            verified_only=verified_only,
            project=project,
            signature_policy=signature_policy,
            attestation_envelope=attestation_envelope,
            trusted_keys=trusted_keys,
            output=output,
        )


def _load_inventory(path: str | Path) -> AIBOM:
    # The error names the class of problem; it never quotes the document.
    try:
        return AIBOM.load(Path(path))
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc
