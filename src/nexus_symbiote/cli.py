"""Nexus SymBiote CLI — Agent Bill of Materials for AI supply chain security.

Command implementations live in sibling modules (``inventory_cli``,
``review_cli``, ``live_cli``, ``runtime_cli``, ``supply_chain_cli``) and are
registered on this root group. Shared helpers stay here so imports and the
documented ``nexus_symbiote.cli`` test patching seam remain stable.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click
from rich.console import Console
from rich.markup import escape

from nexus_symbiote import __version__, modes
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.inventory_cli import register_inventory_commands
from nexus_symbiote.live_cli import register_live_commands
from nexus_symbiote.policy import Policy
from nexus_symbiote.review_cli import register_review_commands
from nexus_symbiote.runtime_cli import register_runtime_commands
from nexus_symbiote.supply_chain_cli import register_supply_chain_commands

if TYPE_CHECKING:
    from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy

console = Console(stderr=True)
err_console = console


def _scanner_error_summary(exc: Exception) -> str:
    # Exception messages can include Pydantic input values, parser snippets or
    # credentials. Only application-owned diagnostic codes cross this boundary.
    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        return "component validation failed (scanner-validation-error)"
    if isinstance(exc, OSError):
        return "collection I/O failed (scanner-io-error)"
    if isinstance(exc, (ValueError, TypeError, RecursionError)):
        return "invalid or unsupported input (scanner-input-error)"
    return "collector failed (scanner-internal-error)"


def _policy(root: Path, *, ignore_project: bool = False) -> Policy:
    from nexus_symbiote.policy import PolicyError, default_policy, load_policy

    if ignore_project:
        return default_policy()
    try:
        return load_policy(root) or default_policy()
    except PolicyError as exc:
        raise click.ClickException(str(exc)) from exc


# C0/C1 controls move the cursor or rewrite earlier output; bidirectional and
# invisible format characters disguise text. Inventory data may contain any of them.
_UNSAFE_TEXT = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)


def _safe(value: object) -> str:
    """Render untrusted text literally: no Rich markup and no terminal control sequences."""
    return escape(_UNSAFE_TEXT.sub("\ufffd", str(value)))


def _load_bom(path: str | Path) -> AIBOM:
    # Parser and validation messages can quote attacker-controlled input; keep them out.
    try:
        return AIBOM.load(Path(path))
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(f"{path} is not a valid native AIBOM file.") from exc


SCANNER_REGISTRY: dict[str, type] = {}


def _signer_policies(path: Path | None, project: Path | None) -> list[SigstoreArtifactPolicy]:
    from nexus_symbiote.signature_policy import load_signature_policies

    if path is None:
        return []
    if project is None:
        raise click.BadParameter("--signature-policy requires --project")
    try:
        return load_signature_policies(path, project)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None


def _get_scanners() -> dict[str, type]:
    if not SCANNER_REGISTRY:
        from nexus_symbiote.scanners.a2a import A2AScanner
        from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
        from nexus_symbiote.scanners.mcp import MCPScanner
        from nexus_symbiote.scanners.model import ModelScanner
        from nexus_symbiote.scanners.prompt import PromptScanner
        from nexus_symbiote.scanners.rag import RAGScanner
        from nexus_symbiote.scanners.registry import RegistryScanner
        from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

        SCANNER_REGISTRY.update(
            {
                "shadowscan": ShadowScanImporter,
                "mcp": MCPScanner,
                "model": ModelScanner,
                "prompt": PromptScanner,
                "rag": RAGScanner,
                "registry": RegistryScanner,
                "a2a": A2AScanner,
                "ide_agents": IDEAgentScanner,
            }
        )
    return SCANNER_REGISTRY


_MODE_FLAGS = frozenset({"--offline", "--live"})


class _RootGroup(click.Group):
    """Root group that turns mode refusals into clear, nonzero CLI errors."""

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except click.NoSuchOption as exc:
            if exc.option_name not in _MODE_FLAGS:
                raise
            raise click.UsageError(
                f"No such option: {exc.option_name}. Mode flags go before the command: "
                f"nexus-symbiote {exc.option_name} <command> ...",
                ctx=exc.ctx,
            ) from None
        except modes.LiveModeRequiredError as exc:
            raise click.UsageError(str(exc)) from None
        except modes.OfflineViolation as exc:
            raise click.ClickException(
                f"offline mode blocked {exc} before the command completed. This command "
                "never needs the network or a subprocess; please report this as a defect."
            ) from None


@click.group(cls=_RootGroup)
@click.version_option(version=__version__, prog_name="nexus-symbiote")
@click.option(
    "--offline",
    "offline_flag",
    is_flag=True,
    help="Refuse network access and process creation (the default).",
)
@click.option(
    "--live",
    "live_flag",
    is_flag=True,
    help=(
        "Allow the network and process steps of the live commands "
        "(discover-mcp, advisories, verify-live). Other commands stay offline."
    ),
)
@click.pass_context
def main(ctx: click.Context, offline_flag: bool, live_flag: bool) -> None:
    """Nexus SymBiote — Agent Bill of Materials for AI supply chain security.

    Every command runs offline by default: no name resolution, network
    connections or subprocesses. Only discover-mcp, advisories and verify-live
    reach outside local files, and only in live mode: pass --live before the
    command or set NEXUS_SYMBIOTE_MODE=live.
    """
    try:
        requested = modes.resolve(offline=offline_flag, live=live_flag, environ=os.environ)
    except ValueError as exc:
        raise click.UsageError(str(exc), ctx=ctx) from None
    ctx.meta["nexus_symbiote.mode"] = requested
    ctx.with_resource(modes.enforce(modes.command_mode(requested.mode, ctx.invoked_subcommand)))


register_inventory_commands(main)
register_review_commands(main)
register_runtime_commands(main)
register_live_commands(main)
register_supply_chain_commands(main)

if __name__ == "__main__":
    main()
