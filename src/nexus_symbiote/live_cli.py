"""Explicit opt-in served-interface observations; static scans remain offline."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click

from nexus_symbiote import modes
from nexus_symbiote.scanners.live_mcp import discover_tools
from nexus_symbiote.utils.files import write_output_file
from nexus_symbiote.utils.terminal import inert_json


@click.command("discover-mcp")
@click.argument("endpoint")
@click.option(
    "--allowed-origin",
    multiple=True,
    required=True,
    help="Exact HTTPS origin explicitly approved by the operator",
)
@click.option(
    "--token-env",
    help="Environment variable holding a bearer token; the token is never written to evidence",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Write the observation to this file instead of standard output.",
)
def discover_mcp(
    endpoint: str, allowed_origin: tuple[str, ...], token_env: str | None, output: Path | None
) -> None:
    """Live: observe tools/list without executing tools or starting local servers."""
    modes.require_live("discover-mcp")
    token = os.environ.get(token_env) if token_env else None
    if token_env and not token:
        raise click.ClickException("the explicitly selected token environment variable is empty")
    result = discover_tools(endpoint, allowed_origins=allowed_origin, bearer_token=token)
    text = json.dumps(result.to_dict(), indent=2) + "\n"
    if output:
        write_output_file(output, text)
    else:
        click.echo(inert_json(text), nl=False)
    if not result.complete:
        raise click.exceptions.Exit(1)


def register_live_commands(main: click.Group) -> None:
    main.add_command(discover_mcp)
