"""Inventory and verification commands: scan, import, and artifact checks.

Shared helpers (``_safe``, ``_policy``, ``_get_scanners``, ...) stay on
``nexus_symbiote.cli`` and are resolved through that module at call time so the
documented test patching seam keeps working.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

import click

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import AIBOMMetadata, CompletenessClaim
from nexus_symbiote.utils.files import write_output_file

if TYPE_CHECKING:
    from nexus_symbiote.scanners.base import ScanResult


def _cli() -> ModuleType:
    """Resolve shared CLI helpers on ``nexus_symbiote.cli`` at call time.

    Tests patch helpers such as ``_get_scanners`` on the ``nexus_symbiote.cli``
    module; late attribute lookup through that module keeps the seam intact.
    """
    from nexus_symbiote import cli

    return cli


def _merge_scan_result(
    name: str,
    result: ScanResult,
    aibom: AIBOM,
    collected: dict[str, Any],
    scan_failures: list[str],
) -> None:
    from nexus_symbiote.core.models import ClaimEvidence

    accepted_refs: set[str] = set()
    for comp in result.components:
        # Discovery of a file/configuration does not verify every supplier assertion.
        imported = name == "shadowscan"
        comp.claims["discovery_report_entry" if imported else "repository_presence"] = (
            ClaimEvidence(
                assurance=AssuranceLevel.DECLARED if imported else AssuranceLevel.OBSERVED,
                method="imported-discovery-report" if imported else "filesystem-inventory",
                scope="source-report" if imported else "repository",
                collector=name,
                locator=comp.source_path,
                observed_at=aibom.metadata.timestamp,
            )
        )
        if comp.assurance_level is AssuranceLevel.VERIFIED:
            comp.assurance_level = AssuranceLevel.DECLARED
        existing = collected.get(comp.bom_ref)
        if existing is not None and existing != comp:
            scan_failures.append(f"{name}: conflicting duplicate component {comp.bom_ref}")
            continue
        if existing is None:
            aibom.components.append(comp)
            collected[comp.bom_ref] = comp
        accepted_refs.add(comp.bom_ref)
    for edge in result.dependencies:
        if edge.source_ref in accepted_refs and edge.target_ref in accepted_refs:
            aibom.add_dependency(edge)
        else:
            scan_failures.append(f"{name}: dependency endpoint was not imported")


def _render_aibom(aibom: AIBOM, output_format: str) -> str:
    if output_format == "cyclonedx":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

        return CycloneDXGenerator().generate_json(aibom)
    if output_format == "spdx":
        from nexus_symbiote.generators.spdx import SPDXGenerator

        return SPDXGenerator().generate_json(aibom)
    if output_format == "sarif":
        from nexus_symbiote.generators.sarif import SARIFGenerator

        return SARIFGenerator().generate_json(aibom)
    return aibom.to_json()


@click.command()
@click.argument("project_path", type=click.Path(exists=True), default=".")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "cyclonedx", "spdx", "sarif"]),
    default=None,
    help="Output format (default: json, or from .nexus-symbiote.yaml)",
)
@click.option(
    "--scanner",
    "scanners",
    multiple=True,
    help="Specific scanners to run (default: all, or from .nexus-symbiote.yaml)",
)
@click.option(
    "--report-only", is_flag=True, help="Emit findings and collection failures without a CI failure"
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit operator signer policy JSON",
)
@click.option(
    "--no-project-policy",
    is_flag=True,
    help="Use built-in policy without reading configuration from the target.",
)
def scan(
    project_path: str,
    output: str | None,
    output_format: str | None,
    scanners: tuple[str, ...],
    report_only: bool = False,
    signature_policy: Path | None = None,
    no_project_policy: bool = False,
) -> None:
    """Scan a project and generate an AIBOM."""
    cli = _cli()
    console, err_console, _safe = cli.console, cli.err_console, cli._safe
    root = Path(project_path).resolve()
    if not root.is_dir():
        err_console.print(f"[red]Error:[/] '{_safe(project_path)}' is not a directory")
        sys.exit(1)

    from nexus_symbiote.graph import assemble_repository_agent, validate_graph
    from nexus_symbiote.policy import PolicyError
    from nexus_symbiote.utils.confined import DEFAULT_EXCLUDES
    from nexus_symbiote.validators.risk import RiskScorer

    policy = cli._policy(root, ignore_project=no_project_policy)
    signature_policies = cli._signer_policies(signature_policy, root)
    output_format = output_format or policy.output.default_format
    all_scanners = cli._get_scanners()
    selected = scanners or tuple(policy.scan.scanners)
    unknown = set(selected) - set(all_scanners)
    if unknown:
        raise click.BadParameter(
            "Unknown scanner: " + ", ".join(sorted(unknown)), param_hint="--scanner"
        )
    if output_format not in {"json", "cyclonedx", "spdx", "sarif"}:
        raise click.BadParameter("Unknown output format", param_hint="--format")
    console.print(f"[bold]Scanning[/] {_safe(root)}")
    aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
    aibom.finalize()
    surfaces_scanned: list[str] = []
    surfaces_excluded: list[str] = []
    scan_failures: list[str] = []
    completed: list[str] = []
    source_report_digest = None
    source_report_format = None
    source_report_status = None
    source_projection_limitations = None
    source_unmapped_count = 0
    source_unmapped_indexes: list[int] = []
    scanner_status: dict[str, str] = dict.fromkeys(all_scanners, "unknown")
    # AIBOM lookups scan the whole list; a project can declare tens of thousands of
    # tools, so index what this loop adds instead of searching for each component.
    collected: dict[str, Any] = {}
    for name in selected:
        scanner = (
            all_scanners[name](signature_policies=signature_policies)
            if name == "model"
            else all_scanners[name]()
        )
        console.print(f"  Running [cyan]{_safe(name)}[/] scanner...")
        try:
            configure = getattr(scanner, "configure", None)
            if configure:
                configure(exclude_paths=policy.scan.exclude_paths)
            elif policy.scan.exclude_paths:
                raise ValueError("scanner does not support configured exclude_paths")
            failure_count = len(scan_failures)
            result = scanner.scan(root)
            if name == "shadowscan":
                source_report_digest = result.source_report_digest
                source_report_format = result.source_report_format
                source_report_status = result.source_report_status
                source_projection_limitations = result.source_projection_limitations
                source_unmapped_count = result.source_unmapped_count
                source_unmapped_indexes = result.source_unmapped_indexes
            _merge_scan_result(name, result, aibom, collected, scan_failures)
            surfaces_scanned.extend(result.surfaces_scanned)
            surfaces_excluded.extend(result.surfaces_excluded)
            scan_failures.extend(result.scan_failures)
            # A collector that produced a conflicting duplicate component or a
            # dangling dependency edge has failed even when its own ScanResult
            # reports no failure. Derive both coverage records from the same
            # delta so the emitted claim cannot list a failed collector as
            # completed, or call the inventory OBSERVED on the strength of it.
            scanner_status[name] = (
                "failed"
                if len(scan_failures) > failure_count
                else "partial"
                if result.surfaces_excluded
                else "complete"
            )
            if scanner_status[name] != "failed":
                completed.append(name)
            console.print(f"    Found [green]{len(result.components)}[/] components")
        except Exception as exc:
            summary = cli._scanner_error_summary(exc)
            err_console.print(
                f"  [red]Scanner '{_safe(name)}' failed:[/] {_safe(summary)}", soft_wrap=True
            )
            scan_failures.append(f"{name}: {summary}")
            scanner_status[name] = "failed"
    try:
        assemble_repository_agent(aibom, root)
    except (PolicyError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    scan_failures.extend(validate_graph(aibom))
    aibom.metadata.completeness = CompletenessClaim(
        scope="repository+shadowscan" if source_report_digest else "repository",
        source_report_digest=source_report_digest,
        source_report_format=source_report_format,
        source_report_status=source_report_status,
        source_projection_limitations=source_projection_limitations,
        source_unmapped_count=source_unmapped_count,
        source_unmapped_indexes=source_unmapped_indexes,
        surfaces_scanned=sorted(set(surfaces_scanned)),
        surfaces_excluded=sorted(set(surfaces_excluded)),
        scan_failures=scan_failures,
        timestamp=aibom.metadata.timestamp,
        assurance_level=AssuranceLevel.OBSERVED if completed else AssuranceLevel.DECLARED,
        scanner_status=scanner_status,
        collectors_requested=list(selected),
        collectors_completed=completed,
        exclusions=sorted(
            {*policy.scan.exclude_paths, *(f"**/{name}" for name in DEFAULT_EXCLUDES)}
        ),
        unobserved_surfaces=[
            "runtime",
            "effective-identity",
            "effective-authorization",
            "live-tools",
            "network",
        ],
    )
    passed, risk_report = RiskScorer(
        fail_threshold=policy.risk.fail_threshold,
        warn_threshold=policy.risk.warn_threshold,
        ignore_categories=policy.risk.ignore_categories,
        fail_on_severity=policy.risk.fail_on_severity,
    ).passes_gate(aibom)
    report_mode = report_only or policy.scan.failure_mode == "report-only"

    if source_report_digest and output_format == "sarif":
        raise click.ClickException(
            "SARIF cannot preserve imported discovery coverage; use native JSON, CycloneDX or SPDX."
        )
    out_data = _render_aibom(aibom, output_format)

    if output:
        write_output_file(Path(output), out_data)
        console.print(f"[bold green]Saved[/] {_safe(output)}")
    else:
        click.echo(out_data)

    if risk_report.warning_threshold_exceeded:
        err_console.print(f"[yellow]Risk warning:[/] score {risk_report.overall_score:.1f}")
    if scan_failures or not passed:
        err_console.print("[yellow]Report only[/]" if report_mode else "[red]Scan gate failed[/]")
        if not report_mode:
            raise click.exceptions.Exit(1)


@click.command("import-shadowscan")
@click.argument("report_path", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), required=True, help="Output AIBOM path")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "cyclonedx", "spdx", "sarif"]),
    default="json",
    help="Output format (default: json). sarif is refused: it cannot carry imported coverage.",
)
@click.option("--report-only", is_flag=True, help="Emit imported claims without a CI gate failure")
def import_shadowscan(
    report_path: str, output: str, output_format: str, report_only: bool = False
) -> None:
    """Import a Nexus-ShadowScan report and generate an AIBOM of imported claims.

    This is the recommended primary workflow: run ShadowScan for discovery,
    then Nexus SymBiote for verification, integrity, and BOM emission.
    """
    cli = _cli()
    console = cli.console
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

    importer = ShadowScanImporter()
    try:
        imported = importer.read_report(Path(report_path))
    except (ValueError, TypeError, OSError, UnicodeError, RecursionError) as exc:
        raise click.ClickException("Failed to safely import the ShadowScan report") from exc

    aibom = imported.to_native_bom()
    aibom.finalize()

    if output_format == "sarif":
        raise click.ClickException(
            "SARIF cannot preserve imported discovery coverage; use native JSON, CycloneDX or SPDX."
        )
    if output_format == "cyclonedx":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

        out_data = CycloneDXGenerator().generate_json(aibom)
    elif output_format == "spdx":
        from nexus_symbiote.generators.spdx import SPDXGenerator

        out_data = SPDXGenerator().generate_json(aibom)
    else:
        out_data = aibom.to_json()

    try:
        write_output_file(Path(output), out_data, overwrite=False)
    except OSError as exc:
        raise click.ClickException("Cannot create output; choose a new output path") from exc
    console.print(
        f"Imported {len(imported.components)} components and saved {output}; discovery coverage remains partial."
    )
    if report_only:
        return
    if imported.source_status != "complete":
        raise click.ClickException("ShadowScan source report is incomplete; the BOM is partial")
    raise click.ClickException("Imported claims do not establish complete verified coverage")


@click.command("verify-artifact")
@click.argument("artifact_path")
@click.option(
    "--project",
    required=True,
    type=click.Path(exists=True, file_okay=False),
    help="Trusted project root",
)
@click.option(
    "--sha256", "expected_digest", required=True, help="Expected sha256:<hex> from a trusted source"
)
@click.option(
    "--bundle", type=click.Path(exists=True, dir_okay=False), help="Optional Sigstore bundle"
)
@click.option("--signer-identity", help="Expected Sigstore signing identity")
@click.option("--issuer", help="Expected Sigstore OIDC issuer")
def verify_artifact(
    artifact_path: str,
    project: str,
    expected_digest: str,
    bundle: str | None,
    signer_identity: str | None,
    issuer: str | None,
) -> None:
    """Verify a local artifact's digest and optionally its Sigstore bundle."""
    import hmac

    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.utils.confined import hash_confined_file
    from nexus_symbiote.utils.crypto import verify_sigstore_digest

    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
        raise click.ClickException(
            "Expected SHA-256 must be sha256:<64 lowercase hexadecimal characters>"
        )
    if bool(bundle) != bool(signer_identity and issuer) or (
        not bundle and (signer_identity or issuer)
    ):
        raise click.ClickException("Bundle verification requires both signer identity and issuer")
    try:
        digest = hash_confined_file(Path(project), artifact_path)
    except OSError as exc:
        raise click.ClickException(
            "Cannot safely hash the artifact within the project root"
        ) from exc
    if not hmac.compare_digest(digest, expected_digest):
        raise click.ClickException("Artifact digest mismatch")
    if bundle:
        try:
            bundle_bytes = read_regular_text(Path(bundle)).encode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise click.ClickException("Cannot safely read the Sigstore bundle") from exc
        if signer_identity is None or issuer is None:
            raise click.ClickException(
                "Bundle verification requires both signer identity and issuer"
            )
        verified = verify_sigstore_digest(digest, bundle_bytes, signer_identity, issuer)
        if not verified.verified:
            raise click.ClickException("Sigstore signature or signer policy verification failed")
        click.echo(
            "Artifact digest and Sigstore signer policy verified. This does not establish artifact safety or a deployment binding."
        )
    else:
        click.echo(
            "Artifact bytes match the expected digest. Signer, artifact safety, and deployment binding were not verified."
        )


@click.command("verify-discovery")
@click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("report_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--projection", is_flag=True, help="Rebuild and compare the direct native import.")
@click.option(
    "--bundle",
    type=click.Path(exists=True, dir_okay=False),
    help="Verify the report producer's Sigstore bundle and the direct native projection.",
)
@click.option("--signer-identity", help="Expected report signer from operator policy.")
@click.option("--issuer", help="Expected OIDC issuer from operator policy.")
def verify_discovery(
    aibom_path: str,
    report_path: str,
    projection: bool,
    bundle: str | None,
    signer_identity: str | None,
    issuer: str | None,
) -> None:
    """Verify source bytes and optionally their native projection and producer."""
    import hashlib
    import hmac

    from nexus_symbiote.core.hashing import parse_json_strict
    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.scanners.shadowscan import MAX_REPORT_BYTES, ShadowScanImporter
    from nexus_symbiote.utils.crypto import verify_sigstore_digest

    if any(x is not None for x in (bundle, signer_identity, issuer)) and not all(
        (bundle, signer_identity, issuer)
    ):
        raise click.UsageError("--bundle, --signer-identity and --issuer must be supplied together")
    try:
        doc = parse_json_strict(
            read_regular_text(Path(aibom_path), max_bytes=MAX_REPORT_BYTES),
            max_bytes=MAX_REPORT_BYTES,
        )
        bom = AIBOM.model_validate(doc)
        text = read_regular_text(Path(report_path), max_bytes=MAX_REPORT_BYTES)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise click.ClickException("Cannot safely read the BOM or discovery report") from exc
    claim = bom.metadata.completeness
    expected = claim.source_report_digest if claim else None
    if not isinstance(expected, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        raise click.ClickException("BOM does not contain a valid ShadowScan report digest")
    actual = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise click.ClickException("Discovery report digest mismatch")
    if projection or bundle:
        try:
            projected = ShadowScanImporter().parse_report(text).to_native_bom().to_dict()
            # Import time and UUID are generated on each run. Everything else,
            # including unknown fields in the original JSON, must match.
            for field in ("timestamp", "serial_number"):
                projected["metadata"].pop(field)
                if not isinstance(doc["metadata"].pop(field, None), str):
                    raise ValueError("missing generated metadata")
            if json.dumps(projected, sort_keys=True) != json.dumps(doc, sort_keys=True):
                raise ValueError("projection differs")
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise click.ClickException(
                "BOM does not match the direct native ShadowScan projection"
            ) from exc
    if bundle and signer_identity and issuer:
        try:
            bundle_bytes = read_regular_text(Path(bundle)).encode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise click.ClickException("Cannot safely read the Sigstore bundle") from exc
        if not verify_sigstore_digest(actual, bundle_bytes, signer_identity, issuer).verified:
            raise click.ClickException(
                "ShadowScan report signature or signer policy verification failed"
            )
        click.echo(
            "Report signer and direct native projection verified. Discovery claims retain declared assurance."
        )
    elif projection:
        click.echo(
            "Report bytes and direct native projection match. Producer identity is unverified."
        )
    else:
        click.echo(
            "Report bytes match the recorded digest. Source identity, signature, and truth were not verified."
        )


def register_inventory_commands(group: click.Group) -> None:
    group.add_command(scan)
    group.add_command(import_shadowscan)
    group.add_command(verify_artifact)
    group.add_command(verify_discovery)
