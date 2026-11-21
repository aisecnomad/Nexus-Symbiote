"""The ``crosswalk`` command: the framework entries that an inventory's findings bear on.

The findings are exactly those that ``risk`` scores under the built-in policy: no project
policy applies, so nothing is suppressed or ignored, and the findings that ``risk`` derives
from a model's recorded fields are included. For each selected framework edition the
report lists every entry that a finding references, with those findings, and the
categories whose findings reference no entry. It is a report, not a gate: exit status 0
says only that the report was written.

What a reference means is fixed text from the catalog (``crosswalk.MEANING``) in every
report. Inventory text appears in JSON as strings: the finding detail neutralized as on a
terminal, the category and component reference exactly as recorded, so that consumers can
match them and must escape them; in Markdown every piece of it is escaped so that no
renderer reads it as markup.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.crosswalk import FRAMEWORK_KEYS
from nexus_symbiote.runtime_cli import _refuse_source_overwrite
from nexus_symbiote.utils.terminal import json_text, neutralize, write_cli_output

if TYPE_CHECKING:
    from nexus_symbiote.validators.risk import RiskReport

FORMAT = "nexus-symbiote/crosswalk/v1"
POLICY_SOURCE = "built-in"
# Markdown lists at most this many findings under one entry and counts the rest; the
# JSON report lists every one. Each inventory string is cut to MAX_MARKDOWN_TEXT.
MAX_MARKDOWN_FINDINGS = 100
MAX_MARKDOWN_TEXT = 1000
SEVERITIES = ("critical", "high", "medium", "low", "info")
_MARKDOWN_PUNCTUATION = re.compile(r"([!-/:-@\[-`{-~])")


def markdown_text(value: object) -> str:
    """Inventory text as Markdown that renders literally, on one line.

    Control, line-break, bidirectional and invisible characters become U+FFFD and a
    ``##`` CI log command is broken, as on a terminal; text longer than
    ``MAX_MARKDOWN_TEXT`` characters is cut and ends with ``...``. Every ASCII
    punctuation character is then backslash-escaped, which CommonMark reads as that
    literal character, so no table cell, link, autolink, emphasis, code span, HTML or
    heading can form from it.
    """
    text = neutralize(value)
    if len(text) > MAX_MARKDOWN_TEXT:
        text = text[: MAX_MARKDOWN_TEXT - 3] + "..."
    return _MARKDOWN_PUNCTUATION.sub(r"\\\1", text)


def build_report(report: RiskReport, frameworks: Sequence[str]) -> dict[str, Any]:
    """The crosswalk document for scored findings and the framework keys to report.

    Findings are sorted by severity, category, component and detail; each entry lists
    the positions of its findings in that list.
    """
    from nexus_symbiote.crosswalk import CROSSWALK, MEANING, framework, label, references

    rank = {severity: position for position, severity in enumerate(SEVERITIES)}
    findings = sorted(
        report.findings,
        key=lambda f: (rank[f.severity.value], f.category, f.component_ref, f.detail),
    )
    positions: dict[tuple[str, str], list[int]] = {}
    reasons: dict[tuple[str, str], dict[str, str]] = {}
    referencing = dict.fromkeys(frameworks, 0)
    unmapped: dict[str, int] = {}
    for position, finding in enumerate(findings):
        applicable = references(finding.category, finding.severity, frameworks)
        if not applicable:
            unmapped[finding.category] = unmapped.get(finding.category, 0) + 1
        for key in {reference.framework for reference in applicable}:
            referencing[key] += 1
        for reference in applicable:
            entry_key = (reference.framework, reference.entry)
            positions.setdefault(entry_key, []).append(position)
            reasons.setdefault(entry_key, {})[finding.category] = reference.rationale
    editions = []
    for key in frameworks:
        edition = framework(key)
        entries = []
        for entry in edition.entries:
            listed = positions.get((key, entry.id))
            if not listed:
                continue
            counts = dict.fromkeys(SEVERITIES, 0)
            for position in listed:
                counts[findings[position].severity.value] += 1
            entries.append(
                {
                    "entry": entry.id,
                    "title": label(key, entry.id),
                    "findings": listed,
                    "severity_counts": counts,
                    "categories": [
                        {"category": category, "rationale": rationale}
                        for category, rationale in sorted(reasons[(key, entry.id)].items())
                    ],
                }
            )
        editions.append(
            {
                "framework": key,
                "name": edition.name,
                "edition": edition.edition,
                "source": edition.source,
                "verification": edition.verification,
                "note": edition.note,
                "entries": entries,
                "findings_with_reference": referencing[key],
                "findings_without_reference": len(findings) - referencing[key],
            }
        )
    return {
        "format": FORMAT,
        "meaning": MEANING,
        "policy_source": POLICY_SOURCE,
        "coverage_status": report.coverage_status,
        "suppressed_findings": len(report.suppressed),
        "ignored_findings": report.ignored_findings,
        "findings": [
            {
                "category": finding.category,
                "severity": finding.severity.value,
                "component_ref": finding.component_ref,
                "detail": neutralize(finding.detail),
            }
            for finding in findings
        ],
        "frameworks": editions,
        "unmapped_categories": [
            {"category": category, "findings": count, "in_catalog": category in CROSSWALK}
            for category, count in sorted(unmapped.items())
        ],
    }


def render_markdown(document: dict[str, Any]) -> str:
    """The report as Markdown: fixed text, catalog text and escaped inventory text."""
    findings = document["findings"]
    lines = [
        "# Framework crosswalk",
        "",
        document["meaning"],
        "",
        (
            f"Findings: {len(findings)}, as `risk` scores them under the {document['policy_source']} "
            f"policy, with {document['suppressed_findings']} suppressed and "
            f"{document['ignored_findings']} ignored. Collection coverage, as `risk` assesses it: "
            f"{document['coverage_status']}."
        ),
        "",
        (
            "Entries that no finding references are not listed; that says nothing about whether "
            "the risk an entry names is present."
        ),
        "",
        "## Summary",
        "",
        (
            "| Framework | Edition | Verification | Entries referenced | Findings with a reference "
            "| Findings without a reference |"
        ),
        "| --- | --- | --- | --- | --- | --- |",
        *(
            f"| {edition['name']} | {edition['edition']} | {edition['verification']} | "
            f"{len(edition['entries'])} | {edition['findings_with_reference']} | "
            f"{edition['findings_without_reference']} |"
            for edition in document["frameworks"]
        ),
    ]
    for edition in document["frameworks"]:
        lines += [
            "",
            f"## {edition['name']} {edition['edition']}",
            "",
            (
                f"Source: <{edition['source']}>. Verification: {edition['verification']}. "
                f"{edition['note']}"
            ),
            "",
        ]
        if not edition["entries"]:
            lines.append("No finding references an entry of this framework edition.")
            continue
        lines += [
            "| Entry | Title | Findings | Critical | High | Medium | Low | Info |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for entry in edition["entries"]:
            counts = " | ".join(str(entry["severity_counts"][s]) for s in SEVERITIES)
            lines.append(
                f"| {entry['entry']} | {entry['title']} | {len(entry['findings'])} | {counts} |"
            )
        for entry in edition["entries"]:
            listed = entry["findings"]
            lines += ["", f"### {entry['entry']} {entry['title']}", ""]
            lines += [
                f"- {markdown_text(item['category'])}: {item['rationale']}"
                for item in entry["categories"]
            ]
            lines += [
                "",
                "| Severity | Category | Component | Detail |",
                "| --- | --- | --- | --- |",
                *(
                    f"| {findings[position]['severity']} | "
                    f"{markdown_text(findings[position]['category'])} | "
                    f"{markdown_text(findings[position]['component_ref'])} | "
                    f"{markdown_text(findings[position]['detail'])} |"
                    for position in listed[:MAX_MARKDOWN_FINDINGS]
                ),
            ]
            if len(listed) > MAX_MARKDOWN_FINDINGS:
                lines += [
                    "",
                    (
                        f"{len(listed) - MAX_MARKDOWN_FINDINGS} more findings reference this "
                        "entry; the JSON format lists every one."
                    ),
                ]
    lines += ["", "## Categories without a reference", ""]
    if not findings:
        lines.append("There are no findings.")
    elif not document["unmapped_categories"]:
        lines.append("Every finding references an entry of the selected framework editions.")
    else:
        lines += [
            (
                "Findings of these categories reference no entry of the selected framework "
                "editions. A category outside this version's catalog, as an edited inventory "
                "or another version can record, is marked no."
            ),
            "",
            "| Category | Findings | In the catalog |",
            "| --- | --- | --- |",
            *(
                f"| {markdown_text(item['category'])} | {item['findings']} | "
                f"{'yes' if item['in_catalog'] else 'no'} |"
                for item in document["unmapped_categories"]
            ),
        ]
    return "\n".join(lines) + "\n"


def _load_with_bytes(path: Path) -> tuple[AIBOM, bytes]:
    # The error names the class of problem; it never quotes the document.
    try:
        return AIBOM.load_with_bytes(path)
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc


def register_crosswalk_commands(main: click.Group) -> None:
    @main.command()
    @click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "--framework",
        "frameworks",
        multiple=True,
        type=click.Choice(FRAMEWORK_KEYS),
        help="Report only this framework edition (repeatable; default: every edition).",
    )
    @click.option(
        "--format",
        "output_format",
        type=click.Choice(["json", "markdown"]),
        default="json",
        show_default=True,
        help="Report format.",
    )
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the report to this file instead of standard output.",
    )
    @click.option(
        "--include-evidence-pack",
        is_flag=True,
        help="Attach cryptographic inventory digests, verified models, pinned MCP servers, and fingerprinted tools.",
    )
    @click.option(
        "--project",
        type=click.Path(exists=True, file_okay=False, path_type=Path),
        default=None,
        help="Reconcile AIBOM_PATH against this project to corroborate verified_models in --include-evidence-pack.",
    )
    @click.option(
        "--signature-policy",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Explicit operator signer policy JSON for --include-evidence-pack; requires --project.",
    )
    def crosswalk(
        aibom_path: Path,
        frameworks: tuple[str, ...],
        output_format: str,
        output: Path | None,
        include_evidence_pack: bool = False,
        project: Path | None = None,
        signature_policy: Path | None = None,
    ) -> None:
        """Map findings to OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001 and CWE.

        Findings are those that the risk command scores under the built-in policy. A reference
        means that a finding records a precondition for an entry, a weakness of its
        type or evidence relevant to it, never that an attack happened, that a control
        fails or that an obligation applies. A report, not a gate: exit status 0 means
        only that the report was written.
        """
        from nexus_symbiote.policy import default_policy
        from nexus_symbiote.validators.risk import RiskScorer

        if signature_policy is not None and project is None:
            raise click.UsageError("--signature-policy requires --project")
        if project is not None and not include_evidence_pack:
            raise click.UsageError(
                "--project and --signature-policy require --include-evidence-pack"
            )
        if include_evidence_pack and output_format == "markdown":
            raise click.UsageError("--include-evidence-pack requires --format json")
        _refuse_source_overwrite(output, aibom_path)
        bom, raw_bytes = _load_with_bytes(aibom_path)
        report = RiskScorer.from_policy(default_policy().risk).score(bom)
        selected = [key for key in FRAMEWORK_KEYS if not frameworks or key in frameworks]
        document = build_report(report, selected)
        if include_evidence_pack:
            from nexus_symbiote.policy_export import build_evidence_pack

            document["evidence_pack"] = build_evidence_pack(
                raw_bytes, bom, project=project, signature_policy=signature_policy
            )
        if output_format == "markdown":
            text = render_markdown(document)
            if output:
                write_cli_output(output, text)
            else:
                click.echo(text, nl=False)
            return
        text = json.dumps(document, indent=2, sort_keys=True)
        if output:
            write_cli_output(output, text)
        else:
            click.echo(json_text(text))
