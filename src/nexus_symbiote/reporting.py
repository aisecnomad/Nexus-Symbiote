"""Human-readable reports in which no inventory text can act as markup or a command.

A report is a list of (text, style) lines. Every line that carries inventory or checkout
text is built by safe_line(): neutralized as a whole, behind a fixed prefix, and printed
as plain text, never through a markup parser, highlighter or line wrapper. The Action
runner renders the CLI's JSON documents with the same functions, so both read alike.
"""

from __future__ import annotations

import math
import os
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import click

from nexus_symbiote.core.coverage import failure_reason, group_failures
from nexus_symbiote.utils.terminal import neutralize, safe_line

ReportLine = tuple[str, str | None]

LISTED = 10
"""How many findings, excluded surfaces or coverage gaps a gate failure lists."""
MAX_SHOWN_FAILURES = 20
"""How many collection failures a gate failure lists; the rest are counted."""
TOP_FINDINGS = 15
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _style(text: str, style: str | None) -> str:
    if style is None:
        return text
    if style == "bold":
        return click.style(text, bold=True)
    return click.style(text, fg=style)


def print_lines(lines: Iterable[ReportLine], *, err: bool = False) -> None:
    """Print report lines; styles are dropped off a terminal and under NO_COLOR."""
    color = False if os.environ.get("NO_COLOR") else None
    for text, style in lines:
        click.echo(_style(text, style), err=err, color=color)


def severity_rank(item: tuple[str, object]) -> tuple[int, str]:
    name = item[0]
    return (SEVERITY_ORDER.index(name) if name in SEVERITY_ORDER else len(SEVERITY_ORDER), name)


def _at_or_above(severity: object, cutoff: object) -> bool:
    if severity not in SEVERITY_ORDER or cutoff not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(str(severity)) <= SEVERITY_ORDER.index(str(cutoff))


def _finding_line(prefix: str, finding: Mapping[str, Any]) -> str:
    return safe_line(
        prefix,
        finding.get("severity"),
        " ",
        finding.get("component_name"),
        " [",
        finding.get("category"),
        "] ",
        finding.get("detail"),
    )


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return math.nan
    return float(value)


def _shown(value: object, spec: str = ".0f") -> str:
    """A number from a report, or "?" when the report carries none."""
    number = _number(value)
    return "?" if not math.isfinite(number) else format(number, spec)


def _more(count: int, label: str, field: str, *, recorded: bool, what: str = "") -> ReportLine:
    """How many items a list left out, and where the inventory keeps all of them."""
    where = (
        f" in metadata.completeness.{field}"
        if recorded
        else "; this run keeps no inventory: scan with -o FILE records them all under "
        f"metadata.completeness.{field}"
    )
    return (f"  - {label}: {count} more{what}{where}", None)


def listed_failures(failures: Iterable[str]) -> list[str]:
    """The inventory's failures as a gate lists them: each distinct one once."""
    return [failure_reason(failure, records) for failure, records in group_failures(failures)]


def gate_reason_lines(
    document: Mapping[str, Any],
    failures: Sequence[str] = (),
    *,
    recorded: bool = True,
    not_collected: Sequence[str] = (),
    excluded: Sequence[str] = (),
) -> list[ReportLine]:
    """Why a gate failed, one neutralized line per item behind the fixed prefix "  - ".

    This is the one gate-reason report, for scan, risk, baseline and the Action: each
    reason, the findings at or above the severity cutoff and the score with its
    threshold, then the collectors not run, the first distinct collection failures and
    excluded surfaces, and how many more the inventory records under
    metadata.completeness. A failure the inventory records more than once, as every
    walking collector that meets the same escaping symlink does, is one line that says
    how many records it has. ``recorded`` is false when the run keeps no inventory
    (scan --check, baseline).
    """
    lines: list[ReportLine] = []
    reasons = [str(reason) for reason in document.get("gate_reasons") or []]
    lines.extend((safe_line("  - ", reason), None) for reason in reasons)
    cutoff = document.get("fail_on_severity")
    if any(reason.startswith("finding at or above") for reason in reasons):
        tripped = [
            finding
            for finding in document.get("findings") or []
            if isinstance(finding, Mapping) and _at_or_above(finding.get("severity"), cutoff)
        ]
        lines.extend(
            (_finding_line("  - finding: ", finding), None) for finding in tripped[:LISTED]
        )
        if len(tripped) > LISTED:
            more = len(tripped) - LISTED
            lines.append((safe_line("  - finding: ", more, " more at or above ", cutoff), None))
    if math.isfinite(_number(document.get("overall_score"))) and "score_threshold" in document:
        threshold = document["score_threshold"]
        limit = (
            "no aggregate score threshold"
            if threshold is None
            else f"fail threshold {_shown(threshold, 'g')}"
        )
        lines.append((f"  - score: {_shown(document['overall_score'], '.1f')} ({limit})", None))
    if not_collected:
        names = ", ".join(not_collected)
        lines.append(
            (safe_line("  - not collected: ", names, " (coverage needs every collector)"), None)
        )
    distinct = listed_failures(failures)
    lines.extend(
        (safe_line("  - collection: ", failure), None) for failure in distinct[:MAX_SHOWN_FAILURES]
    )
    if len(distinct) > MAX_SHOWN_FAILURES:
        lines.append(
            _more(
                len(distinct) - MAX_SHOWN_FAILURES,
                "collection",
                "scan_failures",
                recorded=recorded,
                what=" distinct failures",
            )
        )
    lines.extend((safe_line("  - excluded: ", surface), None) for surface in excluded[:LISTED])
    if len(excluded) > LISTED:
        lines.append(
            _more(len(excluded) - LISTED, "excluded", "surfaces_excluded", recorded=recorded)
        )
    return lines


def _producer_lines(document: Mapping[str, Any]) -> list[ReportLine]:
    if document.get("discovery_producer") != "not-verified":
        return []
    outcome = (
        "unsigned"
        if document.get("assessment_basis") == "unsigned-discovery-evidence"
        else "unsigned evidence accepted"
    )
    return [(f"  Discovery producer: not verified ({outcome})", None)]


def _attestation_summary_lines(document: Mapping[str, Any]) -> list[ReportLine]:
    attestation = document.get("attestation")
    if not isinstance(attestation, Mapping):
        return []
    if attestation.get("verified") is True:
        signers = ", ".join(str(s) for s in attestation.get("signers") or [])
        return [
            (
                safe_line(
                    "  Attestation: verified (purpose ",
                    attestation.get("purpose"),
                    ", match ",
                    attestation.get("match"),
                    ", signers ",
                    signers,
                    ")",
                ),
                None,
            )
        ]
    return [
        (
            safe_line(
                "  Attestation: FAILED (",
                attestation.get("reason"),
                ": ",
                attestation.get("detail"),
                ")",
            ),
            "red",
        )
    ]


def risk_report_lines(
    document: Mapping[str, Any], *, failures: Sequence[str] = ()
) -> list[ReportLine]:
    """The human-readable form of a `risk --json-output` document.

    ``failures`` are the inventory's own collection failures, listed under a failed gate.
    """
    lines: list[ReportLine] = []
    passed = document.get("passed") is True
    if document.get("overall_score") is None:
        basis = document.get("assessment_basis")
        if basis == "project-reconciliation-failed":
            lines.append(("Risk unknown. Project reconciliation failed.", "yellow"))
        else:
            lines.append((safe_line("Risk unknown (", basis, "): not scored."), "yellow"))
        lines.extend(_producer_lines(document))
        lines.extend(_attestation_summary_lines(document))
    else:
        level = neutralize(document.get("risk_level", "unknown"))
        color = {"critical": "red", "high": "red", "moderate": "yellow", "clean": "green"}
        score = _shown(document.get("overall_score"), ".1f")
        lines.append((f"Risk Score: {score} ({level})", color.get(level, "yellow")))
        basis = document.get("assessment_basis", "unknown")
        lines.append((safe_line("  Assessment basis: ", basis), None))
        lines.extend(_producer_lines(document))
        lines.extend(_attestation_summary_lines(document))
        lines.append((safe_line("  Coverage: ", document.get("coverage_status", "unknown")), None))
        total = _shown(document.get("total_components"))
        risky = _shown(document.get("components_with_risks"))
        lines.append((f"  Components: {total} total, {risky} with risks", None))
        counts = document.get("severity_counts") or {}
        if counts:
            lines.append(("  Severity breakdown:", None))
            for severity, count in sorted(counts.items(), key=severity_rank):
                lines.append((safe_line("    - ", severity, ": ", count), None))
        findings = [f for f in document.get("findings") or [] if isinstance(f, Mapping)]
        if findings:
            heading = "Top findings:"
            if len(findings) > TOP_FINDINGS:
                heading = (
                    f"Top findings ({TOP_FINDINGS} of {len(findings)}; --json-output lists all):"
                )
            lines.append((heading, "bold"))
            for finding in findings[:TOP_FINDINGS]:
                lines.append((_finding_line("  - ", finding), None))
                if finding.get("fingerprint"):
                    lines.append((safe_line("    fingerprint: ", finding["fingerprint"]), None))
    lines.append(("Gate: PASSED", "green") if passed else ("Gate: FAILED", "red"))
    listed = [] if passed else [str(failure) for failure in failures]
    lines.extend(gate_reason_lines(document, listed))
    # Coverage gaps restate collection failures; list only what the failures do not say.
    known = set(listed_failures(listed))
    gaps = [str(gap) for gap in document.get("coverage_gaps") or [] if str(gap) not in known]
    lines.extend((safe_line("  - coverage gap: ", gap), None) for gap in gaps[:LISTED])
    if len(gaps) > LISTED:
        lines.append((f"  - coverage gap: {len(gaps) - LISTED} more in --json-output", None))
    suppressed = document.get("suppressed_findings") or []
    if suppressed:
        lines.append(
            (
                f"  - suppressed by project policy: {len(suppressed)} findings "
                "(reasons, owners and expiry in --json-output)",
                "yellow",
            )
        )
    for stale in document.get("suppressions_stale") or []:
        if isinstance(stale, Mapping):
            lines.append(
                (
                    safe_line(
                        "  - suppression no longer matches: ",
                        stale.get("category"),
                        " on ",
                        stale.get("component_ref"),
                        " (the finding changed; review it and copy its new fingerprint)",
                    ),
                    "yellow",
                )
            )
    return lines


def _omitted(section: Mapping[str, Any]) -> list[ReportLine]:
    count = _number(section.get("issues_omitted"))
    if not math.isfinite(count) or count <= 0:
        return []
    return [(f"  ... and {count:.0f} more issues, counted in --json-output", None)]


def validation_report_lines(
    document: Mapping[str, Any], *, project: object = None
) -> list[ReportLine]:
    """The human-readable form of a `validate --json-output` document."""
    status_color = {"PASS": "green", "FAIL": "red", "UNKNOWN": "yellow"}
    lines: list[ReportLine] = [(safe_line("Policy: ", document.get("policy_source")), None)]
    basis = document.get("assessment_basis")
    compared = project if project is not None else "the project"
    if basis == "project-reconciled":
        lines.append(
            (
                safe_line(
                    "Assessment basis: project-reconciled: the inventory was compared with a "
                    "fresh local collection of ",
                    compared,
                ),
                None,
            )
        )
    elif basis == "project-reconciled-with-supplier-claims":
        lines.append(
            (
                safe_line(
                    "Assessment basis: project-reconciled-with-supplier-claims: the inventory "
                    "was compared with a fresh local collection of ",
                    compared,
                    "; what it adds beyond that collection is listed as supplier claims",
                ),
                None,
            )
        )
    elif basis == "project-reconciliation-failed":
        lines.append(
            (
                safe_line(
                    "Assessment basis: project-reconciliation-failed: the inventory was "
                    "compared with a fresh local collection of ",
                    compared,
                    " and does not match it",
                ),
                "red",
            )
        )
    elif basis == "project-not-reconciled":
        lines.append(
            (
                safe_line(
                    "Assessment basis: project-not-reconciled: the completeness check, and "
                    "with it the comparison with ",
                    compared,
                    ", was skipped by policy",
                ),
                "yellow",
            )
        )
    elif basis == "supplied-bom":
        lines.append(
            (
                "Assessment basis: supplied-bom: only the inventory's own claims were checked; "
                "nothing was compared with a project. Pass --project to reconcile it.",
                "yellow",
            )
        )
    else:
        lines.append(
            (
                safe_line(
                    "Assessment basis: ",
                    "unknown" if basis is None else basis,
                    ": not a basis this release reports; nothing shows that the inventory "
                    "was compared with a project",
                ),
                "yellow",
            )
        )

    def issues(section: Mapping[str, Any], ref: str, text: str) -> None:
        for issue in section.get("issues") or []:
            if isinstance(issue, Mapping):
                severity = neutralize(issue.get("severity", "")).upper()
                lines.append(
                    (safe_line(f"  {severity} [", issue.get(ref), "] ", issue.get(text)), None)
                )

    completeness = document.get("completeness") or {}
    lines.append(("Completeness check", "bold"))
    if completeness.get("status") == "skipped":
        lines.append(("  SKIPPED by explicit policy", "yellow"))
    else:
        status = neutralize(completeness.get("status", "unknown")).upper()
        lines.append((f"  Status: {status}", status_color.get(status)))
        if "assessment_basis" in completeness:
            lines.append((safe_line("  Basis: ", completeness["assessment_basis"]), None))
        lines.append((f"  Components: {_shown(completeness.get('total_components'))}", None))
        issues(completeness, "surface", "description")
        lines.extend(_omitted(completeness))
        for claim in completeness.get("supplier_claims") or []:
            if isinstance(claim, Mapping):
                line = safe_line(
                    "  SUPPLIER-CLAIM [",
                    claim.get("subject"),
                    "] ",
                    claim.get("kind"),
                    ": ",
                    claim.get("detail"),
                )
                lines.append((line, None))
        claims_omitted = _number(completeness.get("supplier_claims_omitted"))
        if math.isfinite(claims_omitted) and claims_omitted > 0:
            lines.append(
                (
                    f"  ... and {claims_omitted:.0f} further supplier claims omitted, "
                    "counted in --json-output",
                    None,
                )
            )
    integrity = document.get("integrity") or {}
    lines.append(("Integrity check", "bold"))
    if integrity.get("status") == "skipped":
        if integrity.get("skipped_by") == "--skip-integrity":
            lines.append(
                ("  SKIPPED by --skip-integrity: no hash or signature was checked", "yellow")
            )
        else:
            lines.append(("  SKIPPED by explicit policy", "yellow"))
    else:
        status = neutralize(integrity.get("status", "unknown")).upper()
        lines.append((f"  Status: {status}", status_color.get(status)))
        verified = _shown(integrity.get("hashes_verified"))
        failed = _shown(integrity.get("hashes_failed"))
        summary = f"  Hashes verified: {verified}, failed: {failed}"
        if _number(integrity.get("hashes_unbound")) > 0:
            summary += f", unbound: {_shown(integrity.get('hashes_unbound'))}"
        lines.append((summary, None))
        issues(integrity, "component_ref", "detail")
        lines.extend(_omitted(integrity))
        explained = any(
            isinstance(issue, Mapping) and issue.get("severity") in {"unknown", "error", "critical"}
            for issue in integrity.get("issues") or []
        )
        if status == "UNKNOWN" and not explained:
            lines.append(("  UNKNOWN: no hash or signature could be verified", None))
    attestation = document.get("attestation")
    if isinstance(attestation, Mapping):
        lines.append(("Attestation check", "bold"))
        if attestation.get("verified") is True:
            lines.append(("  Status: PASS", "green"))
            signers = ", ".join(str(s) for s in attestation.get("signers") or [])
            lines.append(
                (
                    safe_line(
                        "  Purpose: ",
                        attestation.get("purpose"),
                        ", match: ",
                        attestation.get("match"),
                        ", signers: ",
                        signers,
                    ),
                    None,
                )
            )
        else:
            lines.append(("  Status: FAIL", "red"))
            lines.append(
                (
                    safe_line(
                        "  ERROR [attestation] ",
                        attestation.get("detail"),
                        " (",
                        attestation.get("reason"),
                        ")",
                    ),
                    None,
                )
            )
    discovery = document.get("discovery_producer")
    if isinstance(discovery, Mapping):
        problems = discovery.get("problems") or []
        producer = discovery.get("status")
        if producer == "not-verified":
            unsigned = document.get("unsigned_discovery")
            if unsigned:
                lines.append((safe_line("Discovery producer: not verified. ", unsigned), "red"))
            else:
                lines.append(
                    ("Discovery producer: not verified (unsigned evidence accepted)", None)
                )
        else:
            lines.append(("Discovery producer check", "bold"))
            if problems or producer == "failed":
                lines.append(("  Status: FAIL", "red"))
            elif producer == "not-applicable":
                lines.append(("  Status: not applicable (no discovery evidence or report)", None))
            else:
                lines.append(("  Status: PASS", "green"))
            lines.extend((safe_line("  ERROR [shadowscan] ", p), None) for p in problems)
    for error in document.get("assurance_errors") or []:
        lines.append((safe_line("  ERROR: ", error), None))
    for issue in document.get("graph_issues") or []:
        lines.append((safe_line("  ERROR: ", issue), None))
    passed = document.get("passed") is True
    lines.append(("Validation: PASSED", "green") if passed else ("Validation: FAILED", "red"))
    return lines


def diff_report_lines(document: Mapping[str, Any]) -> list[ReportLine]:
    """The human-readable form of a `diff --json-output` document."""
    # Context about the comparison itself, such as gaps both snapshots share.
    context = [
        (safe_line("  [NOTE] ", note.get("detail")), None)
        for note in document.get("notes") or []
        if isinstance(note, Mapping)
    ]
    if not document.get("has_changes"):
        return [("No changes detected.", "green"), *context]
    lines: list[ReportLine] = [
        (f"{_shown(document.get('total_changes'))} changes detected", "bold")
    ]
    alerts = [a for a in document.get("security_alerts") or [] if isinstance(a, Mapping)]
    if alerts:
        lines += [("", None), ("Security Alerts:", "red")]
        for alert in alerts:
            severity = neutralize(alert.get("severity", "")).upper()
            lines.append((safe_line("  [", severity, "] ", alert.get("alert")), None))
    notes = [
        change
        for change in document.get("metadata_changes") or []
        if isinstance(change, Mapping) and change.get("severity") == "info"
    ]
    if notes or context:
        lines += [("", None), ("Notes:", "bold")]
        lines.extend((safe_line("  [INFO] ", change.get("detail")), None) for change in notes)
        lines.extend(context)
    for key, mark, label, color in (
        ("components_added", "+", "added", "green"),
        ("components_removed", "-", "removed", "red"),
        ("components_modified", "~", "modified", "yellow"),
    ):
        changes = [c for c in document.get(key) or [] if isinstance(c, Mapping)]
        if not changes:
            continue
        lines += [("", None), (f"{mark}{len(changes)} {label}", color)]
        for change in changes:
            if mark == "~":
                details = "; ".join(map(str, change.get("details") or []))
                lines.append((safe_line("  ~ ", change.get("name"), ": ", details), None))
            else:
                line = safe_line(f"  {mark} ", change.get("name"), " (", change.get("type"), ")")
                lines.append((line, None))
    for key, mark, label, color in (
        ("dependencies_added", "+", "relationships added", "green"),
        ("dependencies_removed", "-", "relationships removed", "red"),
    ):
        edges = [e for e in document.get(key) or [] if isinstance(e, Mapping)]
        if not edges:
            continue
        lines += [("", None), (f"{mark}{len(edges)} {label}", color)]
        for edge in edges:
            severity = neutralize(edge.get("severity", "")).upper()
            condition = edge.get("conditions")
            lines.append(
                (
                    safe_line(
                        f"  {mark} [",
                        severity,
                        "] ",
                        edge.get("source"),
                        " ",
                        edge.get("relationship"),
                        " ",
                        edge.get("target"),
                        f" (when {condition})" if condition else "",
                    ),
                    None,
                )
            )
    return lines


def _attributed(records: Mapping[str, Sequence[str]]) -> list[str]:
    """Each distinct message once, with the collectors (or checks) that recorded it.

    A message that names its only collector itself, such as a shadowscan report
    problem, is not attributed again. The collectors are named in alphabetical order,
    so a failure six walking collectors record reads the same whatever their run order.
    """
    recorded: dict[str, list[str]] = {}
    for name, messages in records.items():
        for message in map(str, messages):
            names = recorded.setdefault(message, [])
            if name not in names:
                names.append(name)
    return [
        message
        if len(names) == 1 and message.startswith(f"{names[0]}: ")
        else f"{message} (from {', '.join(sorted(names))})"
        for message, names in recorded.items()
    ]


def scan_gate_lines(
    document: Mapping[str, Any],
    failures: Mapping[str, Sequence[str]],
    excluded: Mapping[str, Sequence[str]],
    not_collected: Sequence[str],
    *,
    recorded: bool,
    discovery: Sequence[str] = (),
) -> list[ReportLine]:
    """The scan gate's reasons; `recorded` says whether this run keeps an inventory.

    `discovery` holds the discovery-verification failures, which report-only never
    relaxes, so they are labelled apart from collection failures.
    """
    lines = gate_reason_lines(
        document,
        _attributed(failures),
        recorded=recorded,
        not_collected=not_collected,
        excluded=_attributed(excluded),
    )
    lines.extend((safe_line("  - discovery verification: ", reason), None) for reason in discovery)
    return lines
