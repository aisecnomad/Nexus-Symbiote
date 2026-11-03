"""Review and gate commands: validate, risk, diff, summary, and configuration.

Shared helpers (``_safe``, ``_policy``, ``_load_bom``, ...) stay on
``nexus_symbiote.cli`` and are resolved through that module at call time so the
documented test patching seam keeps working.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from types import ModuleType

import click
from rich.table import Table

from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.utils.files import write_output_file


def _cli() -> ModuleType:
    """Resolve shared CLI helpers on ``nexus_symbiote.cli`` at call time.

    Tests patch helpers such as ``_get_scanners`` on the ``nexus_symbiote.cli``
    module; late attribute lookup through that module keeps the seam intact.
    """
    from nexus_symbiote import cli

    return cli


@click.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--project",
    type=click.Path(exists=True),
    help="Project root for cross-validation",
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit operator signer policy JSON; requires --project",
)
@click.option(
    "--no-project-policy",
    is_flag=True,
    help="Use built-in policy without reading configuration from the target.",
)
def validate(
    aibom_path: str,
    project: str | None,
    signature_policy: Path | None = None,
    no_project_policy: bool = False,
) -> None:
    """Validate an AIBOM for completeness and integrity."""
    cli = _cli()
    console, _safe, _load_bom = cli.console, cli._safe, cli._load_bom
    bom = _load_bom(aibom_path)

    from nexus_symbiote.validators.completeness import CompletenessValidator
    from nexus_symbiote.validators.integrity import IntegrityValidator

    signature_policies = cli._signer_policies(signature_policy, Path(project) if project else None)

    policy = cli._policy(
        Path(project).resolve() if project else Path(aibom_path).parent,
        ignore_project=no_project_policy,
    )
    valid = True
    console.print("[bold]Completeness check[/]")
    if policy.validation.require_completeness:
        cv = CompletenessValidator()
        c_report = (
            cv.validate_against_project(
                bom,
                Path(project).resolve(),
                exclude_paths=policy.scan.exclude_paths,
                signature_policies=signature_policies,
            )
            if project
            else cv.validate(bom)
        )
        console.print("  Status: " + ("[green]PASS[/]" if c_report.is_complete else "[red]FAIL[/]"))
        console.print(f"  Components: {c_report.total_components}")
        for issue in c_report.issues:
            console.print(
                f"  {_safe(issue.severity.upper())} \\[{_safe(issue.surface)}] "
                f"{_safe(issue.description)}",
                soft_wrap=True,
            )
        valid = valid and c_report.is_complete
    else:
        console.print("  SKIPPED by explicit policy")
    console.print("\n[bold]Integrity check[/]")
    if policy.validation.require_integrity:
        i_report = IntegrityValidator(signature_policies=signature_policies).validate(
            bom,
            Path(project).resolve() if project else None,
            exclude_paths=policy.scan.exclude_paths,
        )
        console.print("  Status: " + ("[green]PASS[/]" if i_report.is_valid else "[red]FAIL[/]"))
        console.print(
            f"  Hashes verified: {i_report.hashes_verified}, failed: {i_report.hashes_failed}"
        )
        for integrity_issue in i_report.issues:
            console.print(
                f"  {_safe(integrity_issue.severity.upper())} \\[{_safe(integrity_issue.component_ref)}] "
                f"{_safe(integrity_issue.detail)}",
                soft_wrap=True,
            )
        valid = valid and i_report.is_valid
    else:
        console.print("  SKIPPED by explicit policy")
    minimum = policy.validation.minimum_assurance_level
    if minimum == "verified":
        raise click.ClickException(
            "offline validate cannot establish verified assurance; use subject-bound cryptographic verification"
        )
    if minimum == "observed":
        levels = [c.assurance_level for c in bom.components]
        if (
            not bom.metadata.completeness
            or not levels
            or any(level is AssuranceLevel.DECLARED for level in levels)
        ):
            console.print("  ERROR: minimum observed assurance not attained")
            valid = False
        elif any(not c.claims for c in bom.components):
            console.print("  ERROR: observed assurance requires claim provenance")
            valid = False
    # Graph integrity is structural and cannot be disabled by a coverage policy.
    if bom.graph_issues():
        console.print("  ERROR: " + _safe("; ".join(bom.graph_issues())), soft_wrap=True)
        valid = False
    if not valid:
        raise click.exceptions.Exit(1)


@click.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option("--threshold", type=float, default=None, help="Fail threshold score")
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.option(
    "--project",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Reconcile the supplied BOM against this project's static evidence before scoring.",
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Explicit operator signer policy for model recollection; requires --project.",
)
@click.option(
    "--fail-on-severity",
    type=click.Choice(["critical", "high", "medium", "low", "info", "none"]),
    default=None,
    help="Fail on any finding at or above this severity (default: from policy, built-in critical); none disables it.",
)
@click.option(
    "--no-project-policy",
    is_flag=True,
    help="Use built-in policy without reading configuration from the target.",
)
def risk(
    aibom_path: str,
    threshold: float | None,
    json_output: bool,
    fail_on_severity: str | None,
    no_project_policy: bool = False,
    project: Path | None = None,
    signature_policy: Path | None = None,
) -> None:
    """Score supply-chain risks in an AIBOM."""
    cli = _cli()
    console, _safe, _load_bom = cli.console, cli._safe, cli._load_bom
    bom = _load_bom(aibom_path)

    from nexus_symbiote.validators.risk import RiskScorer

    root = project.resolve() if project else None
    signature_policies = cli._signer_policies(signature_policy, root)
    policy = cli._policy(root or Path(aibom_path).parent, ignore_project=no_project_policy)
    threshold = threshold if threshold is not None else policy.risk.fail_threshold
    if threshold <= 0 or not math.isfinite(threshold):
        raise click.BadParameter("threshold must be positive and finite", param_hint="--threshold")
    basis = "supplied-bom"
    if root is not None:
        from nexus_symbiote.validators.completeness import CompletenessValidator

        checked = CompletenessValidator().validate_against_project(
            bom,
            root,
            exclude_paths=policy.scan.exclude_paths,
            signature_policies=signature_policies,
        )
        if not checked.is_complete or not checked.local_subjects:
            reasons = [issue.description for issue in checked.issues if issue.severity == "error"]
            if not checked.local_subjects:
                reasons.append("No local project subject was available to reconcile.")
            if json_output:
                click.echo(
                    json.dumps(
                        {
                            "assessment_basis": "project-reconciliation-failed",
                            "overall_score": None,
                            "risk_level": "unknown",
                            "coverage_status": "unreconciled",
                            "gate_reasons": reasons,
                        },
                        indent=2,
                    )
                )
            else:
                click.echo("Risk unknown. Project reconciliation failed.", err=True)
                for reason in reasons:
                    click.echo(cli._UNSAFE_TEXT.sub("\ufffd", reason), err=True)
            raise click.exceptions.Exit(1)
        basis = "project-reconciled"
    scorer = RiskScorer(
        fail_threshold=threshold,
        warn_threshold=policy.risk.warn_threshold,
        ignore_categories=policy.risk.ignore_categories,
        fail_on_severity=fail_on_severity or policy.risk.fail_on_severity,
    )
    passed, report = scorer.passes_gate(bom)

    if json_output:
        click.echo(json.dumps({**report.to_dict(), "assessment_basis": basis}, indent=2))
        sys.exit(0 if passed else 1)

    level_colors = {
        "critical": "red",
        "high": "red",
        "moderate": "yellow",
        "clean": "green",
        "unknown": "yellow",
    }
    color = level_colors[report.risk_level]
    score = report.overall_score
    level = report.risk_level
    console.print(f"[bold]Risk Score:[/] [{color}]{score:.1f}[/] ({level})")
    console.print(f"  Assessment basis: {basis}")
    total = report.total_components
    risky = report.components_with_risks
    console.print(f"  Components: {total} total, {risky} with risks")

    if report.severity_counts:
        console.print("  Severity breakdown:")
        for sev, count in sorted(report.severity_counts.items()):
            console.print(f"    {sev}: {count}")

    if report.findings:
        table = Table(title="Top Findings", show_lines=True)
        table.add_column("Severity", style="bold", min_width=8, no_wrap=True)
        table.add_column("Component", ratio=2, max_width=30)
        table.add_column("Category", ratio=1, max_width=20)
        table.add_column("Detail", ratio=3)

        for finding in report.findings[:15]:
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(
                finding.severity.value, "white"
            )
            table.add_row(
                f"[{sev_color}]{_safe(finding.severity.value)}[/]",
                _safe(finding.component_name),
                _safe(finding.category),
                _safe(finding.detail),
            )
        console.print(table)

    gate = "[green]PASSED[/]" if passed else "[red]FAILED[/]"
    console.print(f"\nGate (threshold={threshold}): {gate}")

    if not passed:
        sys.exit(1)


@click.command()
@click.argument("old_path", type=click.Path(exists=True))
@click.argument("new_path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.option(
    "--fail-on-alert", is_flag=True, help="Exit with status 1 if the diff reports a security alert."
)
def diff(old_path: str, new_path: str, json_output: bool, fail_on_alert: bool = False) -> None:
    """Compare two AIBOM snapshots for supply-chain drift."""
    cli = _cli()
    console, _safe, _load_bom = cli.console, cli._safe, cli._load_bom
    old_bom = _load_bom(old_path)
    new_bom = _load_bom(new_path)

    from nexus_symbiote.diff.differ import AIBOMDiffer

    differ = AIBOMDiffer()
    result = differ.diff(old_bom, new_bom)

    if json_output:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if not result.has_changes:
            console.print("[green]No changes detected.[/]")
            return

        console.print(f"[bold]{result.total_changes} changes detected[/]")

        if result.security_alerts:
            console.print("\n[bold red]Security Alerts:[/]")
            for alert in result.security_alerts:
                console.print(
                    f"  \\[{_safe(alert['severity'].upper())}] {_safe(alert['alert'])}",
                    soft_wrap=True,
                )

        if result.components_added:
            console.print(f"\n[green]+{len(result.components_added)} added[/]")
            for c in result.components_added:
                console.print(f"  + {_safe(c.name)} ({_safe(c.component_type)})", soft_wrap=True)
        if result.components_removed:
            console.print(f"\n[red]-{len(result.components_removed)} removed[/]")
            for c in result.components_removed:
                console.print(f"  - {_safe(c.name)} ({_safe(c.component_type)})", soft_wrap=True)
        if result.components_modified:
            console.print(f"\n[yellow]~{len(result.components_modified)} modified[/]")
            for c in result.components_modified:
                console.print(f"  ~ {_safe(c.name)}: {_safe('; '.join(c.details))}", soft_wrap=True)

    if fail_on_alert and result.security_alerts:
        raise click.exceptions.Exit(1)


@click.command()
@click.argument("aibom_path", type=click.Path(exists=True))
def summary(aibom_path: str) -> None:
    """Print a summary of an AIBOM."""
    cli = _cli()
    console, _safe, _load_bom = cli.console, cli._safe, cli._load_bom
    bom = _load_bom(aibom_path)
    s = bom.summary()

    console.print("[bold]AIBOM Summary[/]")
    console.print(f"  Components: {s['total_components']}")
    console.print(f"  Dependencies: {s['total_dependencies']}")
    console.print(f"  Risks: {s['total_risks']}")

    if s["component_types"]:
        console.print("  Component types:")
        for ctype, count in sorted(s["component_types"].items()):
            console.print(f"    {_safe(ctype)}: {count}")
    if s["risk_breakdown"]:
        console.print("  Risk breakdown:")
        for sev, count in sorted(s["risk_breakdown"].items()):
            console.print(f"    {_safe(sev)}: {count}")


@click.command("blast-radius")
@click.argument("aibom_path", type=click.Path(exists=True))
@click.argument("component_ref")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def blast_radius_command(aibom_path: str, component_ref: str, json_output: bool) -> None:
    """Show repository dependencies potentially affected by a component compromise."""
    cli = _cli()
    console, _safe, _load_bom = cli.console, cli._safe, cli._load_bom
    from nexus_symbiote.graph import blast_radius

    bom = _load_bom(aibom_path)
    try:
        result = blast_radius(bom, component_ref)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        console.print(
            "[bold]Potential blast radius[/] (repository association; effective authority unknown)"
        )
        console.print("  Agents: " + _safe(", ".join(result["affected_agents"])), soft_wrap=True)
        console.print(
            "  Components: " + _safe(", ".join(result["reachable_components"])), soft_wrap=True
        )


@click.command()
@click.option("--force", is_flag=True, help="Overwrite existing .nexus-symbiote.yaml")
@click.option(
    "--path",
    type=click.Path(),
    default=".",
    help="Directory to create .nexus-symbiote.yaml in",
)
def init(force: bool, path: str) -> None:
    """Initialize a .nexus-symbiote.yaml policy configuration."""
    cli = _cli()
    console, err_console, _safe = cli.console, cli.err_console, cli._safe
    from nexus_symbiote.policy import DEFAULT_POLICY_YAML

    target = Path(path).resolve() / ".nexus-symbiote.yaml"

    if target.exists() and not force:
        err_console.print(
            f"[yellow]Warning:[/] {_safe(target)} already exists. Use --force to overwrite."
        )
        sys.exit(1)

    write_output_file(target, DEFAULT_POLICY_YAML, overwrite=force)
    console.print(f"[bold green]Created[/] {_safe(target)}")
    console.print("  Edit this file to customize scan, risk, and validation policies.")


def register_review_commands(group: click.Group) -> None:
    group.add_command(validate)
    group.add_command(risk)
    group.add_command(diff)
    group.add_command(summary)
    group.add_command(blast_radius_command)
    group.add_command(init)
