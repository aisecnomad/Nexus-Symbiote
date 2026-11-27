"""Offline read-only ``mcp-server`` CLI command over stdio."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from nexus_symbiote.core.aibom import AIBOM, NativeFormatError, parse_native_bytes
from nexus_symbiote.core.content_digest import inventory_content_digest
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.mcp_server import (
    DEFAULT_MAX_REQUESTS,
    MAX_ALLOWED_REQUESTS,
    OfflineMCPServer,
    run_mcp_server_streams,
)
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.vex_decisions import (
    VEXDecisionError,
    _ensure_outside_project,
    load_advisory_report,
)


def register_mcp_server_commands(main: click.Group) -> None:
    """Register the offline read-only ``mcp-server`` query command on ``main``."""

    @main.command("mcp-server")
    @click.argument(
        "aibom_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
    )
    @click.option(
        "--advisories",
        "advisories_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Optional advisories JSON report bound to AIBOM_PATH's SHA-256.",
    )
    @click.option(
        "--allow-partial-advisories",
        is_flag=True,
        help="Accept an incomplete advisory report with its coverage counters.",
    )
    @click.option(
        "--project-root",
        type=click.Path(exists=True, file_okay=False, path_type=Path),
        default=None,
        help="Scanned project root used to refuse advisory files inside the checkout.",
    )
    @click.option(
        "--max-requests",
        type=click.IntRange(1, MAX_ALLOWED_REQUESTS),
        default=DEFAULT_MAX_REQUESTS,
        show_default=True,
        help="Maximum JSON-RPC requests/notifications served before exiting.",
    )
    def mcp_server_command(
        aibom_path: Path,
        advisories_path: Path | None,
        allow_partial_advisories: bool,
        project_root: Path | None,
        max_requests: int,
    ) -> None:
        """Serve read-only offline AgentBOM queries over stdio JSON-RPC 2.0 (MCP)."""
        if allow_partial_advisories and advisories_path is None:
            raise click.UsageError("--allow-partial-advisories requires --advisories")
        if project_root is not None and advisories_path is None:
            raise click.UsageError("--project-root requires --advisories")

        try:
            bom, inv_bytes = AIBOM.load_with_bytes(aibom_path)
        except NativeFormatError as exc:
            raise click.ClickException(
                f"{neutralize(aibom_path)} is not a valid native AIBOM file. {neutralize(exc)}"
            ) from None
        except (OSError, ValueError, TypeError, RecursionError):
            raise click.ClickException(
                f"{neutralize(aibom_path)} is not a valid native AIBOM file."
            ) from None

        inv_sha256 = hash_bytes(inv_bytes)
        try:
            raw_doc = parse_native_bytes(inv_bytes)
            content_digest = (
                inventory_content_digest(raw_doc) if isinstance(raw_doc, dict) else None
            )
        except (ValueError, RecursionError):
            content_digest = None

        loaded_advisories = None
        if advisories_path is not None:
            try:
                _ensure_outside_project(
                    advisories_path,
                    project_root,
                    inventory_path=aibom_path,
                    forbid_inventory_dir=False,
                    label="Advisory report",
                )
                loaded_advisories = load_advisory_report(
                    advisories_path,
                    expected_inventory_sha256=inv_sha256,
                    allow_partial=allow_partial_advisories,
                )
            except VEXDecisionError as exc:
                raise click.ClickException(neutralize(exc)) from None
            except (OSError, ValueError, RecursionError):
                raise click.ClickException("Cannot safely load advisory report.") from None

        server = OfflineMCPServer(
            bom,
            advisory_report=loaded_advisories,
            inventory_sha256=inv_sha256,
            content_digest=content_digest,
        )
        run_mcp_server_streams(
            server,
            client_in=sys.stdin.buffer,
            client_out=sys.stdout.buffer,
            max_requests=max_requests,
        )
