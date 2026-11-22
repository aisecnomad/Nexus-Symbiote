"""CLI registration for control-plane hook, bridge, steering, CI, and identity auditing."""

from __future__ import annotations

import json
from pathlib import Path

import click

from nexus_symbiote.control_plane_audit import (
    audit_project_control_plane,
    compute_identity_blast_radius,
)
from nexus_symbiote.utils.secrets import redact_metadata
from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    neutralize,
    refuse_dash_output,
    write_cli_output,
)

_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def register_control_plane_commands(main: click.Group) -> None:
    """Register the audit-control-plane command on the root Click group."""

    @main.command("audit-control-plane")
    @click.argument(
        "project_path",
        type=click.Path(exists=True, file_okay=False, path_type=Path),
        default=Path(),
    )
    @click.option(
        "--claims",
        "claims_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Optional imported CR-3/CR-6/CR-7 ShadowScan JSON claims file.",
    )
    @click.option(
        "--baseline",
        "baseline_root",
        type=click.Path(exists=True, file_okay=False, path_type=Path),
        default=None,
        help="Optional baseline project directory for reach-rated control-plane diff alerts.",
    )
    @click.option(
        "--compromised-ref",
        type=str,
        default=None,
        help="Component ref to compute reachable identities.",
    )
    @click.option(
        "--output", "-o", type=str, default=None, help="Write JSON audit report to a file path."
    )
    @click.option(
        "--json-output",
        is_flag=True,
        default=False,
        help="Emit JSON audit summary to standard output.",
    )
    @click.option(
        "--fail-on-severity",
        type=click.Choice(["critical", "high", "medium", "low", "none"], case_sensitive=False),
        default="critical",
        show_default=True,
        help="Exit 1 when a finding or reach-rated diff alert meets or exceeds this severity, "
        "or when an input could not be read or parsed.",
    )
    def audit_control_plane_cmd(
        project_path: Path,
        claims_path: Path | None,
        baseline_root: Path | None,
        compromised_ref: str | None,
        output: str | None,
        json_output: bool,
        fail_on_severity: str,
    ) -> None:
        """Audit hook targets, skill preambles, MCP bridges, steering surfaces, CI agents, and identities."""
        summary = audit_project_control_plane(
            project_path, claims_path=claims_path, baseline_root=baseline_root
        )
        payload = summary.to_dict()
        if compromised_ref is not None:
            payload["compromised_blast_radius"] = {
                "compromised_ref": neutralize(compromised_ref),
                "reachable_identities": compute_identity_blast_radius(summary, compromised_ref),
            }
        # Names, paths and rules come from the checkout and can hold a credential; every
        # output, JSON, file and text, is rendered from this redacted copy.
        payload = redact_metadata(payload)

        rendered = json_text(json.dumps(payload, indent=2, sort_keys=True))
        if output is not None:
            refuse_dash_output(output)
            write_cli_output(Path(output), rendered, overwrite=True)

        if json_output:
            click.echo(rendered)
        else:
            msg = (
                f"Control-plane audit: {len(summary.hook_targets)} hook targets, "
                f"{len(summary.bridged_servers)} bridges, {len(summary.steering_surfaces)} steering surfaces, "
                f"{len(summary.ci_agents)} CI agents, {len(summary.identities)} identities, {len(summary.findings)} findings."
            )
            echo_line(msg)
            for fl in payload["security_flags"]:
                echo_line(
                    "  [", fl["severity"].upper(), "] ", fl["category"], ": ", fl["description"]
                )
            for al in payload["reach_alerts"]:
                targets = ", ".join(al["affected_refs"]) or al["changed_ref"]
                echo_line(
                    f"  [ALERT:{al['severity'].upper()}:{al['reachability_tier']}] {al['root_cause']} -> {targets}"
                )
            for gap in payload["gaps"]:
                echo_line("  [INCOMPLETE] ", gap)

        cutoff_key = fail_on_severity.lower()
        if cutoff_key != "none":
            threshold = _SEV_ORDER.get(cutoff_key, 4)
            triggered = any(
                _SEV_ORDER.get(f["severity"], 0) >= threshold for f in summary.findings
            ) or any(_SEV_ORDER.get(a["severity"], 0) >= threshold for a in summary.reach_alerts)
            # What could not be read or parsed may hide a finding, so it fails closed.
            if triggered or payload["gaps"]:
                raise click.exceptions.Exit(1)
