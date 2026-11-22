"""The ``export-inventory`` command: an approved inventory for Nexus-ShadowScan's reconciliation."""

from __future__ import annotations

import os
from pathlib import Path

import click

from nexus_symbiote.runtime_cli import _refuse_source_overwrite
from nexus_symbiote.utils.terminal import echo_line, neutralize, write_cli_output


def _resource_prefix(_ctx: click.Context, _param: click.Parameter, value: str) -> str:
    from nexus_symbiote.inventory_export import InventoryExportError, checked_resource_prefix

    try:
        return checked_resource_prefix(value)
    except InventoryExportError as exc:
        raise click.BadParameter(str(exc)) from exc


def register_inventory_export_commands(main: click.Group) -> None:
    @main.command("export-inventory")
    @click.argument("inventory", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "--format",
        type=click.Choice(["shadowscan-simple"]),
        required=True,
        expose_value=False,
        help="ShadowScan's simple inventory list as JSON (the only format).",
    )
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        required=True,
        help="Write the approved inventory to this .json file.",
    )
    @click.option(
        "--resource-prefix",
        required=True,
        callback=_resource_prefix,
        metavar="PREFIX",
        help=(
            "The exact resource ShadowScan reports for the repository's root project: "
            "github:OWNER/REPO, gitlab:NAMESPACE/PROJECT, the label of a code.filesystem "
            "connector with a single path (LABEL/root-id-ID with labelled paths), or the "
            "absolute scan root when it has no label."
        ),
    )
    @click.option(
        "--include-unnamed",
        is_flag=True,
        help=(
            "Also export a repository agent whose agent.yaml declares no id, under an id "
            "derived from the inventory content digest."
        ),
    )
    @click.option(
        "--force",
        is_flag=True,
        help=(
            "Replace an existing output file. Without it an existing approved inventory, "
            "which may be reviewed and attested, is left as it is and the command fails."
        ),
    )
    def export_inventory(
        inventory: Path,
        output: Path,
        resource_prefix: str,
        include_unnamed: bool,
        force: bool = False,
    ) -> None:
        """Offline: write the reviewed repository agent as a ShadowScan approved inventory.

        The file approves one finding kind in ShadowScan: the project that its code
        connectors report at the resource PREFIX. Whoever can change the file approves
        findings, so keep it outside the reach of the change ShadowScan scans and sign it.
        """
        from nexus_symbiote.core.aibom import NativeFormatError
        from nexus_symbiote.core.content_digest import INVENTORY_CONTENT_PROFILE
        from nexus_symbiote.inventory_export import (
            SHADOWSCAN_COMMIT,
            InventoryExportError,
            read_native_inventory,
            shadowscan_simple_inventory,
        )

        if output.suffix.lower() != ".json":
            raise click.BadParameter(
                "the approved inventory must be a .json file: ShadowScan reads strict JSON only "
                "by that suffix and skips other names when it loads a directory",
                param_hint="'-o' / '--output'",
            )
        _refuse_source_overwrite(output, inventory)
        try:
            native = read_native_inventory(inventory)
        except NativeFormatError as exc:
            raise click.ClickException(
                f"{neutralize(inventory)} is not a valid native AIBOM file. {neutralize(exc)}"
            ) from exc
        try:
            export = shadowscan_simple_inventory(
                native, resource_prefix=resource_prefix, include_unnamed=include_unnamed
            )
        except InventoryExportError as exc:
            raise click.ClickException(neutralize(exc)) from exc
        if not force and os.path.lexists(output):
            raise click.ClickException(
                "The output file exists and was not replaced: an approved inventory may be "
                "reviewed and attested. Pass --force to replace it."
            )
        write_cli_output(output, export.text, overwrite=force)
        echo_line(
            f"Wrote a ShadowScan {SHADOWSCAN_COMMIT[:7]} simple-list inventory: ", output, err=True
        )
        echo_line("Agent id: ", export.entry.id, err=True)
        if not export.declared:
            echo_line(
                "The agent's identity is not declared; its id is derived from the inventory "
                "content digest.",
                err=True,
            )
        if export.other_agents:
            echo_line(
                "Not exported: ",
                export.other_agents,
                " agent component(s) other than the repository agent, such as imported discovery.",
                err=True,
            )
        echo_line("Inventory file SHA-256: ", native.file_sha256, err=True)
        echo_line(
            f"Inventory content digest ({INVENTORY_CONTENT_PROFILE}): ",
            native.content_digest,
            err=True,
        )
        echo_line(
            "Review and sign the exported file, and keep it where the change ShadowScan scans "
            "cannot write: whoever can change it approves findings.",
            err=True,
        )
