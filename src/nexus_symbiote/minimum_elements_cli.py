"""The ``minimum-elements`` command: G7 AI SBOM minimum-element coverage of an inventory.

The report says which elements the CycloneDX export of an inventory carries in
standard fields, generated in memory and never written. It is not a compliance
verdict; ``--fail-under`` is an opt-in gate on the one ratio the report prints.
Inventory text reaches the report only as component references, neutralized for
terminals and CI logs and set as inert code spans in Markdown.
"""

from __future__ import annotations

import json
import re
from fractions import Fraction
from pathlib import Path
from typing import TYPE_CHECKING

import click

from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.runtime_cli import _refuse_source_overwrite
from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    neutralize,
    safe_line,
    write_cli_output,
)

if TYPE_CHECKING:
    from nexus_symbiote.minimum_elements import Cluster, Coverage, ElementResult, Report

_PERCENT = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,6})?")
_LABELS = {
    "present": "present",
    "missing": "missing",
    "explicit-unknown": "explicit unknown",
    "needs-producer-input": "needs producer input",
    "not-applicable": "not applicable",
}
_COUNTED = ("missing", "explicit-unknown", "needs-producer-input", "not-applicable")
EXPORT_FAILED = (
    "The inventory cannot be exported as CycloneDX 1.7: the export failed its schema or "
    "consistency checks (for example a timestamp without a time zone, a malformed or "
    "conflicting digest, or a relationship to an unknown component), so the elements it "
    "carries cannot be assessed."
)
EXPORT_TOO_DEEP = (
    "The inventory cannot be exported as CycloneDX 1.7: a value in it is nested too deeply, "
    "so the elements it carries cannot be assessed."
)


def _percent(ctx: click.Context, param: click.Parameter, value: str | None) -> str | None:
    """A decimal percentage from 0 to 100; NaN, infinities, signs and exponents are refused."""
    if value is not None and (_PERCENT.fullmatch(value) is None or Fraction(value) > 100):
        raise click.BadParameter("must be a decimal number from 0 to 100, such as 80 or 92.5")
    return value


def _load(path: Path) -> AIBOM:
    # A NativeFormatError names the class of problem and never quotes the document.
    try:
        return AIBOM.load(path)
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc


def _ratio(coverage: Coverage) -> str:
    percent = coverage.percent()
    if percent is None:
        return "no element is assessable from the BOM"
    return f"{coverage.present} of {coverage.assessable} present ({percent}%)"


def _counts(report: Report, cluster: Cluster | None = None) -> str:
    counts = report.counts(cluster)
    return ", ".join(f"{_LABELS[status]} {counts[status]}" for status in _COUNTED)


def _have_it(result: ElementResult, suffix: str = "") -> str:
    """How many subjects have the element, or how many relationships the export carries."""
    if result.subjects is not None:
        return f"{result.subjects.present} of {result.subjects.total}{suffix}"
    counted = result.relationships
    if counted is None:
        return ""
    return f"{counted.exported} of {counted.recorded} relationships exported"


def _more(omitted: int) -> str:
    return f" and {omitted} more" if omitted else ""


def _gate(report: Report, fail_under: str) -> tuple[bool, str]:
    """Whether the overall ratio meets the threshold, and that statement in words."""
    coverage = report.coverage()
    passed = not coverage.below(Fraction(fail_under))
    relation = "at or above" if passed else "below"
    return passed, f"{_ratio(coverage)}, {relation} the required {fail_under}%"


def _gate_line(report: Report, fail_under: str) -> str:
    passed, statement = _gate(report, fail_under)
    return f"{'passed' if passed else 'failed'}: {statement}"


def text_report(report: Report, fail_under: str | None = None) -> str:
    """The report as plain lines, each opening with fixed text."""
    from nexus_symbiote.minimum_elements import (
        CLUSTERS,
        EDITION,
        NOT_APPLICABLE,
        NOTES,
        PRESENT,
        REASONS,
        STATEMENT,
    )

    subjects = report.subjects
    lines = [
        safe_line("G7 AI SBOM minimum-element coverage, edition ", EDITION),
        safe_line("Statement: ", STATEMENT),
        safe_line(
            "Evaluated: standard fields of the CycloneDX 1.7 export this build writes for the "
            "inventory (projection ",
            report.projection or "unknown",
            ")",
        ),
        safe_line(
            "Subjects: system subject ",
            "yes" if subjects["system"] else "no",
            f"; models {subjects['models']}; datasets {subjects['datasets']}; "
            f"retrieval sources {subjects['retrieval_sources']}",
        ),
        safe_line(
            "Overall: ",
            _ratio(report.coverage()),
            " among the elements assessable from the BOM; ",
            _counts(report),
        ),
    ]
    if fail_under is not None:
        lines.append(safe_line("Gate: ", _gate_line(report, fail_under)))
    for cluster in CLUSTERS:
        results = report.results(cluster)
        if all(result.status == NOT_APPLICABLE for result in results):
            reason = REASONS[results[0].reasons[0]]
            lines.append(safe_line(cluster.heading, ": not applicable: ", reason))
            continue
        lines.append(
            safe_line(
                cluster.heading,
                ": ",
                _ratio(report.coverage(cluster)),
                "; ",
                _counts(report, cluster),
            )
        )
        lines += [safe_line("  note: ", NOTES[note]) for note in report.notes(cluster)]
        present: dict[str, list[str]] = {}
        for result in results:
            if result.status == PRESENT:
                # The coverage claim stands beside the element: partial, and how much.
                claims = ["partial"] if "partial" in result.reasons else []
                claims += [_have_it(result)] if result.relationships is not None else []
                claim = f" ({'; '.join(claims)})" if claims else ""
                present.setdefault(result.basis or "unknown", []).append(
                    result.element.name + claim
                )
        lines += [
            safe_line("  present (", basis, "): ", "; ".join(names))
            for basis, names in present.items()
        ]
        for result in results:
            if result.status != PRESENT:
                lines += _element_lines(result, REASONS)
    return "\n".join(lines) + "\n"


def _element_lines(result: ElementResult, reasons: dict[str, str]) -> list[str]:
    have = _have_it(result, " have it")
    lines = [
        safe_line(
            f"  {_LABELS[result.status]}: ",
            result.element.name,
            f" ({have})" if have else "",
        )
    ]
    lines += [safe_line("    why: ", reasons[code]) for code in result.reasons]
    if result.native.items:
        lines.append(
            safe_line(
                "    only in the inventory's extension: ",
                ", ".join(result.native.items),
                _more(result.native.omitted),
            )
        )
    if result.subjects is not None:
        offenders = result.subjects.offenders
        lines += [safe_line("    without it: ", ref) for ref in offenders.items]
        if offenders.omitted:
            lines.append(safe_line("    without it: ", f"{offenders.omitted} more not listed"))
    lines.append(safe_line("    how to supply it: ", result.element.hint))
    return lines


def _code(value: str) -> str:
    """Inventory text as an inert Markdown code span: no link, markup, HTML or entity.

    A space on each side keeps an edge backtick from joining the fence; CommonMark
    removes it again, except from text that is only spaces, which needs none.
    """
    text = neutralize(value)
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    edged = text[:1] in {"`", " "} or text[-1:] in {"`", " "}
    padding = " " if edged and text.strip(" ") else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def markdown_report(report: Report, fail_under: str | None = None) -> str:
    """The report as Markdown; only component references come from the inventory."""
    from nexus_symbiote.minimum_elements import (
        CLUSTERS,
        EDITION,
        NOTES,
        PRESENT,
        PUBLISHED,
        PUBLISHER,
        REASONS,
        STATEMENT,
        TITLE,
    )

    lines = [
        "# G7 AI SBOM minimum-element coverage",
        "",
        (
            f"Edition `{EDITION}`: {TITLE}, {PUBLISHER}, published {PUBLISHED}. The element "
            "identifiers are minted by Nexus SymBiote; the G7 document defines none."
        ),
        "",
        STATEMENT,
        "",
        (
            "Evaluated: standard fields of the CycloneDX 1.7 export this build writes for the "
            f"inventory (projection {_code(report.projection or 'unknown')})."
        ),
        "",
        (
            f"**Overall:** {_ratio(report.coverage())} among the elements assessable from the "
            f"BOM; {_counts(report)}."
        ),
    ]
    if fail_under is not None:
        lines += ["", f"**Gate:** {_gate_line(report, fail_under)}."]
    lines += [
        "",
        (
            "| Cluster | Coverage | Present | Missing | Explicit unknown | Needs producer input "
            "| Not applicable |"
        ),
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for cluster in CLUSTERS:
        counts = report.counts(cluster)
        cells = [cluster.heading, _ratio(report.coverage(cluster)), *map(str, counts.values())]
        lines.append("| " + " | ".join(cells) + " |")
    for cluster in CLUSTERS:
        lines += ["", f"## {cluster.heading}", ""]
        lines += [f"{NOTES[note]}" for note in report.notes(cluster)]
        if report.notes(cluster):
            lines.append("")
        lines += [
            "| Element | Status | Basis | Have it | Why | How to supply it |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        offenders: list[str] = []
        for result in report.results(cluster):
            why = " ".join(REASONS[code] for code in result.reasons)
            if result.extension_only:
                why = (why + " Recorded only in the inventory's extension.").strip()
            hint = "" if result.status == PRESENT else result.element.hint
            cells = [
                result.element.name,
                _LABELS[result.status],
                result.basis or "",
                _have_it(result),
                why,
                hint,
            ]
            lines.append("| " + " | ".join(cells) + " |")
            if result.subjects is not None and result.subjects.offenders.items:
                listed = result.subjects.offenders
                refs = ", ".join(_code(ref) for ref in listed.items)
                offenders.append(f"- {result.element.name}: {refs}{_more(listed.omitted)}")
        if offenders:
            lines += ["", "Subjects without the element:", "", *offenders]
    # Every line is neutralized as a whole, so pieces cannot join into a log command.
    return "\n".join(neutralize(line) for line in lines) + "\n"


def json_report(report: Report, fail_under: str | None = None) -> str:
    return json.dumps(report.to_dict(fail_under=fail_under), indent=2) + "\n"


_RENDERERS = {"text": text_report, "json": json_report, "markdown": markdown_report}


@click.command("minimum-elements")
@click.argument("inventory", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(list(_RENDERERS)),
    default="text",
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
    "--fail-under",
    callback=_percent,
    metavar="PERCENT",
    help=(
        "Exit with status 1, listing the missing elements, when fewer than PERCENT (0 to "
        "100) of the elements assessable from the BOM are present. Off by default: "
        "coverage is not compliance."
    ),
)
def minimum_elements(
    inventory: Path, output_format: str, output: Path | None, fail_under: str | None
) -> None:
    """Report which G7 AI SBOM minimum elements an inventory's CycloneDX export carries.

    Coverage is not compliance: the G7 minimum elements (Software Bill of Materials
    for AI, 12 May 2026) are non-binding guidance. The command generates the CycloneDX
    1.7 export of the native inventory in memory and reports, per element, whether a
    standard field carries it; a value only a nexus-symbiote: property carries does
    not count, and present means recorded, not verified. Missing elements come with
    how to supply them.
    """
    from nexus_symbiote.minimum_elements import EXPLICIT_UNKNOWN, MISSING, assess

    _refuse_source_overwrite(output, inventory)
    bom = _load(inventory)
    try:
        report = assess(bom)
    except RecursionError as exc:
        raise click.ClickException(EXPORT_TOO_DEEP) from exc
    except ValueError as exc:
        raise click.ClickException(EXPORT_FAILED) from exc
    text = _RENDERERS[output_format](report, fail_under)
    if output is not None:
        write_cli_output(output, text)
    else:
        click.echo(json_text(text) if output_format == "json" else text, nl=False)
    if fail_under is None:
        return
    passed, statement = _gate(report, fail_under)
    if passed:
        echo_line("Coverage gate passed: ", statement, err=True)
        return
    echo_line("Coverage gate failed: ", statement, err=True)
    for result in report.elements:
        if result.status in {MISSING, EXPLICIT_UNKNOWN}:
            echo_line(
                f"  {_LABELS[result.status]}: ",
                result.element.name,
                " (",
                result.element.id,
                ")",
                err=True,
            )
    raise click.exceptions.Exit(1)


def register_minimum_elements_commands(main: click.Group) -> None:
    main.add_command(minimum_elements)
