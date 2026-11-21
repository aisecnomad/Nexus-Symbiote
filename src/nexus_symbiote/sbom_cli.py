"""CLI commands for foreign SBOM import and per-component evidence profiles."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import click

from nexus_symbiote import limits
from nexus_symbiote import sbom_import as _imp
from nexus_symbiote.core import aibom as _aibom
from nexus_symbiote.evidence_profile import build_evidence_profile
from nexus_symbiote.policy import PolicyError
from nexus_symbiote.scanners.mcp import _MIN_SOURCE_BINDING_KEY_LENGTH, SOURCE_BINDING_KEY_ENV
from nexus_symbiote.signature_policy import SignaturePolicyError, load_signature_policies
from nexus_symbiote.utils import terminal as _term

_PATH_FILE = click.Path(exists=True, dir_okay=False, path_type=Path)
_PATH_DIR = click.Path(exists=True, file_okay=False, path_type=Path)
_PATH_OUT = click.Path(path_type=Path)
_ERR_MAP: tuple[tuple[type[BaseException], str], ...] = (
    (json.JSONDecodeError, "invalid JSON syntax"),
    (OSError, "cannot open regular file (symlinks and special files are refused)"),
    (UnicodeError, "input is not valid UTF-8"),
    (RecursionError, "input exceeds maximum nesting depth"),
)


def _refuse_source_overwrite(output: Path | None, source: Path) -> None:
    if output is None:
        return
    _term.refuse_dash_output(output)
    try:
        if output.exists() and source.exists() and os.path.samefile(output, source):
            raise click.UsageError("Refusing to overwrite input file with -o/--output.")
    except OSError:
        pass
    if output.resolve() == source.resolve():
        raise click.UsageError("Refusing to overwrite input file with -o/--output.")


def _resolve_project_root(value: Path, *, label: str) -> Path:
    requested, resolved = Path(value), Path(value).resolve()
    if Path(os.path.normpath(requested.absolute())) == resolved:
        return resolved
    if (
        not requested.is_absolute()
        and ".." not in requested.parts
        and not resolved.is_relative_to(Path.cwd().resolve())
    ):
        msg = f"{_term.neutralize(value)} leads outside the current directory through a symbolic link; name {_term.neutralize(resolved)} directly"
        raise click.BadParameter(msg, param_hint=label)
    _term.echo_line(
        "Note: ", label, " ", value, " resolves through a symlink to ", resolved, err=True
    )
    return resolved


def _validate_io(output: Path | None, root: Path | None, *inputs: Path | None) -> None:
    for src in inputs:
        if src is not None:
            _refuse_source_overwrite(output, src)
    if output is not None:
        _term.refuse_dash_output(output)
        if root is not None and output.resolve().is_relative_to(root):
            raise click.UsageError("Refusing to write -o/--output inside --project.")


def _load_native(path: Path) -> _aibom.AIBOM:
    try:
        return _aibom.AIBOM.load(path)
    except _aibom.NativeFormatError as exc:
        raise click.ClickException(
            f"{_term.neutralize(path)} is not a valid native AIBOM file. {_term.neutralize(exc)}"
        ) from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(
            f"{_term.neutralize(path)} is not a valid native AIBOM file ({type(exc).__name__})."
        ) from exc


def _handle_walk_failures(bom: _aibom.AIBOM, failures: list[str]) -> None:
    limit_failures: list[str] = []
    scan_fails = bom.metadata.completeness.scan_failures if bom.metadata.completeness else None
    for fail in failures:
        _term.echo_line("Warning: ", fail, err=True)
        if scan_fails is not None and fail not in scan_fails:
            scan_fails.append(fail)
        if limits.OPTION in fail or "entries limit" in fail or "bytes limit" in fail:
            limit_failures.append(fail)
    if limit_failures:
        raise click.ClickException(
            f"Collection limit exceeded under --project: {_term.neutralize(limit_failures[0])}"
        )


@click.command("import-sbom")
@click.argument("foreign_bom_path", type=_PATH_FILE)
@click.option("-o", "--output", type=_PATH_OUT, help="Write resulting native AgentBOM JSON.")
@click.option("--into", "into_bom", type=_PATH_FILE, help="Existing native AgentBOM to merge into.")
@click.option("--project", type=_PATH_DIR, help="Project root for binding, manifests, census.")
@click.option(
    "--shareable",
    is_flag=True,
    help="Export a standalone supplier inventory with keyed identifiers and no local paths.",
)
@click.option("--reveal-names", is_flag=True, help="Retain plain component names.")
@click.option("--walk-manifests", is_flag=True, help="Walk nested manifests below --project.")
@click.option("--census", is_flag=True, help="Count unread artifact shapes below --project.")
@click.option("--json-output", is_flag=True, help="Print structured JSON import summary.")
def import_sbom_cmd(
    foreign_bom_path: Path,
    output: Path | None,
    into_bom: Path | None,
    project: Path | None,
    reveal_names: bool,
    shareable: bool,
    walk_manifests: bool,
    census: bool,
    json_output: bool,
) -> None:
    """Import a foreign CycloneDX or SPDX SBOM as DECLARED evidence without picking silent winners."""
    if shareable and (into_bom or project or reveal_names or walk_manifests or census):
        raise click.UsageError(
            "--shareable requires a standalone import without local inventory or names"
        )
    if (walk_manifests or census) and project is None:
        raise click.UsageError("--walk-manifests and --census require --project")
    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if key and len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise click.UsageError(
            f"{SOURCE_BINDING_KEY_ENV} must contain at least {_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
        )
    root = _resolve_project_root(project, label="--project") if project is not None else None
    _validate_io(output, root, foreign_bom_path, into_bom)
    base_bom = _load_native(into_bom) if into_bom is not None else None
    pre_refs = {c.bom_ref for c in base_bom.components} if base_bom is not None else None
    all_failures: list[str] = []
    nested_count = 0
    if walk_manifests and root is not None:
        nested_items, manifest_failures = _imp.walk_nested_manifests(root)
        all_failures.extend(manifest_failures)
        if base_bom is None:
            base_bom = _aibom.AIBOM()
        existing_refs = {c.bom_ref for c in base_bom.components}
        for comp in nested_items:
            if comp.bom_ref not in existing_refs:
                base_bom.components.append(comp)
                existing_refs.add(comp.bom_ref)
                nested_count += 1

    try:
        summary = _imp.import_foreign_sbom(
            foreign_bom_path,
            target_aibom=base_bom,
            project_root=root,
            reveal_names=reveal_names,
            shareable=shareable,
        )
    except (OSError, ValueError, UnicodeError, RecursionError, PolicyError) as exc:
        detail = next(
            (msg for cls, msg in _ERR_MAP if isinstance(exc, cls)),
            _term.neutralize(str(exc)) or type(exc).__name__,
        )
        raise click.ClickException(f"Cannot safely import foreign SBOM: {detail}") from exc

    bom = summary.aibom
    all_failures.extend(summary.scan_failures)

    shapes_payload: list[dict[str, Any]] = []
    if census and root is not None:
        shapes, census_failures = _imp.unread_shape_census_with_failures(root)
        all_failures.extend(census_failures)
        shapes_payload = [{"shape": s.shape, "count": s.count, "owner": s.owner} for s in shapes]
        if bom.metadata.completeness is not None:
            for item in shapes:
                marker = f"unread-shape:{item.shape}:{item.count}"
                if marker not in bom.metadata.completeness.unobserved_surfaces:
                    bom.metadata.completeness.unobserved_surfaces.append(marker)

    if all_failures:
        _handle_walk_failures(bom, all_failures)
    only_refs = ({c.bom_ref for c in bom.components} - pre_refs) if pre_refs is not None else None
    _imp.classify_pinning_state(bom, only_refs=only_refs)
    try:
        _aibom.prepare(bom)
        serialized = bom.to_native_json()
    except (_aibom.ContentSerialError, _aibom.ExportCheckError, _aibom.NativeFormatError) as exc:
        raise click.ClickException(_term.neutralize(str(exc))) from exc

    if output is not None:
        _term.write_cli_output(output, serialized)
        _term.echo_line("Imported ", summary.imported_count, " components into ", output, err=True)
    if json_output:
        report = {
            "source_format": summary.source_format,
            ("document_hmac_sha256" if shareable else "document_sha256"): summary.document_sha256,
            "imported_count": summary.imported_count,
            "bound_local_count": summary.bound_local_count,
            "conflict_count": summary.conflict_count,
            "unresolved_conflict_count": summary.unresolved_conflict_count,
            "nested_manifest_components": nested_count,
            "scan_failure_count": len(all_failures),
            "unread_shapes": shapes_payload,
        }
        click.echo(_term.json_text(json.dumps(report, indent=2)))
    elif output is None:
        click.echo(_term.json_text(serialized))


@click.command("evidence-profile")
@click.argument("aibom_path", type=_PATH_FILE)
@click.option("-o", "--output", type=_PATH_OUT, help="Write evidence profile report to this file.")
@click.option("--project", type=_PATH_DIR, help="Project root for --signature-policy.")
@click.option("--signature-policy", type=_PATH_FILE, help="Operator signer policy JSON.")
@click.option("--json-output", is_flag=True, help="Emit per-component evidence profile as JSON.")
def evidence_profile_cmd(
    aibom_path: Path,
    output: Path | None,
    project: Path | None,
    signature_policy: Path | None,
    json_output: bool,
) -> None:
    """Report concrete evidence attributes per component without a scalar TrustScore."""
    if signature_policy is not None and project is None:
        raise click.UsageError("--signature-policy requires --project")
    root = _resolve_project_root(project, label="--project") if project is not None else None
    _validate_io(output, root, aibom_path, signature_policy)
    sig_policies = None
    if signature_policy is not None and root is not None:
        try:
            sig_policies = load_signature_policies(signature_policy, root)
        except SignaturePolicyError as exc:
            raise click.UsageError(_term.neutralize(str(exc))) from exc

    profile = build_evidence_profile(
        _load_native(aibom_path), project_root=root, signature_policies=sig_policies
    )
    if json_output:
        payload = json.dumps(profile, indent=2) + "\n"
        _term.write_cli_output(output, payload) if output is not None else click.echo(
            _term.json_text(payload), nl=False
        )
        return
    lines = [
        _term.safe_line("Evidence profile schema: ", profile["schema"]),
        _term.safe_line("Policy verified: ", "yes" if profile["policy_verified"] else "no"),
        _term.safe_line("Components evaluated: ", str(profile["component_count"])),
    ]
    for e in profile["components"]:
        present = ", ".join(k for k, v in e["evidence"].items() if v) or "none"
        missing = ", ".join(e["missing_evidence"]) or "none"
        sev = f" (highest={e['highest_finding_severity']})" if e["highest_finding_severity"] else ""
        hdr = f"{e['bom_ref']} ({e['component_type']}, assurance={e['assurance_level']})"
        lines += [
            _term.safe_line("  component: ", hdr),
            _term.safe_line("    present: ", present),
            _term.safe_line("    missing: ", missing),
            _term.safe_line("    findings: ", str(e["finding_count"]), sev),
        ]
    out_txt = "\n".join(lines) + "\n"
    _term.write_cli_output(output, out_txt) if output is not None else click.echo(out_txt, nl=False)


def register_sbom_commands(main: click.Group) -> None:
    main.add_command(import_sbom_cmd)
    main.add_command(evidence_profile_cmd)
