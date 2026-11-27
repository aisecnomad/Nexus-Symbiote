"""SARIF 2.1.0 output for GitHub code scanning and other SARIF viewers.

Every result has a location relative to ``%SRCROOT%``: its component's file, the
file of the MCP server that provides it, or an anchor file for findings that no
file records. Rules are keyed by category and severity, so a rule's severity never
depends on the other findings of a run, and rule text comes from the catalog in
``_rules``. Messages are single-line plain text in which links and markup from the
inventory are neutralized. The invocation reports collection failures and coverage
gaps from the completeness claim.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from datetime import UTC
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM, prepare
from nexus_symbiote.core.canonical import content_digest
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import AnyComponent, CompletenessClaim
from nexus_symbiote.generators._common import (
    OMITTED_IMPORTED_FINDINGS,
    PROJECTION_SCANNERS,
    coverage_aggregate,
    imported_discovery_component,
)
from nexus_symbiote.generators._rules import GENERIC_HELP, RULES, rule_tags
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.validation import require_valid
from nexus_symbiote.utils.terminal import UNSAFE_TEXT

SEVERITY_TO_SARIF = {
    RiskSeverity.CRITICAL: "error",
    RiskSeverity.HIGH: "error",
    RiskSeverity.MEDIUM: "warning",
    RiskSeverity.LOW: "note",
    RiskSeverity.INFO: "note",
}
SECURITY_SEVERITY = {
    RiskSeverity.CRITICAL: "9.5",
    RiskSeverity.HIGH: "8.0",
    RiskSeverity.MEDIUM: "5.0",
    RiskSeverity.LOW: "2.0",
    RiskSeverity.INFO: "0.0",
}
SEVERITY_ORDER = {severity: rank for rank, severity in enumerate(SECURITY_SEVERITY)}
SRCROOT = "%SRCROOT%"
# Findings no file records are anchored to the project's policy file, where
# their handling is configured.
DEFAULT_ANCHOR = ".nexus-symbiote.yaml"
HELP_URI = (
    "https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/standard-exports.md"
    "#sarif-for-github-code-scanning"
)
GITHUB_MAX_RESULTS = 25_000
MAX_MESSAGE = 1000
MAX_NOTIFICATIONS = 100
# Every "://" and "www.", whatever precedes them: autolinkers also start a link
# after "_" or another word character, and schemes have no length limit.
_URL_SEPARATOR = re.compile(r":(?=//)")
_WWW = re.compile(r"(?i)www\.")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_CATEGORY = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
# The scan root where a path starts in a message, followed by separators or the
# end of the path; never a root that only ends or begins a longer path name.
_ROOT_START = r"(?<![\w./\\-])"
_ROOT_END = r"(?:[\\/]+|(?![^\s:;,'\")\]]))"


def plain_text(value: object, limit: int = MAX_MESSAGE) -> str:
    """One line of plain text that no SARIF viewer renders as a link or markup.

    Control, bidirectional and invisible characters become U+FFFD; the text is cut
    to ``limit`` characters; every ``://`` and ``www.`` is defanged (``https[:]//``,
    ``www[.]``), including one that the cut produces; backslashes and brackets are
    escaped as SARIF requires for literal text, which also disables embedded links.
    """
    text = UNSAFE_TEXT.sub("\ufffd", str(value))
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    text = _URL_SEPARATOR.sub("[:]", text)
    text = _WWW.sub(lambda match: match[0][:-1] + "[.]", text)
    return text.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def _rule_slug(category: str) -> str:
    if _CATEGORY.fullmatch(category):
        return category
    return "category-" + hashlib.sha256(category.encode("utf-8")).hexdigest()[:12]


class SARIFGenerator(Generator):
    """SARIF for one inventory.

    ``root`` is the directory ``%SRCROOT%`` denotes, normally the repository checkout
    (default: the working directory). ``scan_root`` is the directory the inventory's
    relative paths are relative to (default: ``root``); when it lies outside ``root``
    it becomes the source root itself. ``anchor`` locates findings that no file
    records, relative to ``scan_root`` (default: ``.nexus-symbiote.yaml``); an anchor
    that is a URL or lies outside the source root raises ValueError.
    """

    format_name = "sarif"

    def __init__(
        self,
        root: Path | None = None,
        *,
        scan_root: Path | None = None,
        anchor: str | Path | None = None,
        operator_policy_digest: str | None = None,
        operator_policy_signers: tuple[str, ...] = (),
    ) -> None:
        self.root = (root or Path.cwd()).resolve()
        self.scan_root = (scan_root or self.root).resolve()
        if not self.scan_root.is_relative_to(self.root):
            self.root = self.scan_root
        self._prefix = PurePosixPath(self.scan_root.relative_to(self.root).as_posix())
        located = self._uri(anchor if anchor is not None else DEFAULT_ANCHOR)
        if located is None:
            raise ValueError("SARIF anchor must be a file path inside the source root")
        self._anchor = located
        self._operator_policy_digest = operator_policy_digest
        self._operator_policy_signers = operator_policy_signers
        roots = {str(self.scan_root), str((scan_root or self.root).absolute())}
        bases = sorted((r for r in roots if Path(r).parent != Path(r)), key=len, reverse=True)
        self._root_text = (
            re.compile(_ROOT_START + "(?:" + "|".join(map(re.escape, bases)) + ")" + _ROOT_END)
            if bases
            else None
        )

    def _relative_text(self, text: str) -> str:
        """Message text with the scan root's location removed from the paths it names.

        Inventory messages name files relative to the scan root; one that still names
        an absolute path under it must not disclose where the checkout lies.
        """
        if self._root_text is None:
            return text
        return self._root_text.sub(lambda match: "" if match[0][-1] in "/\\" else ".", text)

    def _uri(self, source: str | Path | None) -> str | None:
        """A %SRCROOT%-relative URI for a file path; None for URLs and escaping paths."""
        from urllib.parse import unquote

        if source is None or str(source) in {"", "."}:
            return None
        text = source.as_posix() if isinstance(source, Path) else source
        decoded = unquote(text)
        if (
            "\\" in text
            or "\\" in decoded
            or "\x00" in text
            or "\x00" in decoded
            or any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)
            or (not text.startswith("/") and (_SCHEME.match(text) or decoded.startswith("/")))
            or ".." in PurePosixPath(decoded).parts
        ):
            return None
        path = Path(text)
        if path.is_absolute():
            try:
                relative = PurePosixPath(path.relative_to(self.root).as_posix())
            except ValueError:
                return None
        else:
            relative = self._prefix / PurePosixPath(path.as_posix())
        if (
            ".." in relative.parts
            or ".." in PurePosixPath(unquote(relative.as_posix())).parts
            or str(relative) in {"", "."}
        ):
            return None
        return quote(relative.as_posix(), safe="/")

    def _location(
        self, component: AnyComponent, by_ref: dict[str, AnyComponent]
    ) -> tuple[str, str]:
        uri = self._uri(component.source_path)
        if uri:
            return uri, "component"
        server = by_ref.get(getattr(component, "mcp_server_ref", None) or "")
        if server is not None and (uri := self._uri(server.source_path)):
            return uri, "server"
        return self._anchor, "anchor"

    def generate(self, bom: AIBOM) -> dict[str, Any]:
        from nexus_symbiote.validators.risk import effective_component_risks

        prepare(bom)
        by_ref = {component.bom_ref: component for component in bom.components}
        findings: dict[tuple[str, str], dict[str, Any]] = {}
        rules: dict[str, dict[str, Any]] = {}
        omitted = 0
        for comp in sorted(bom.components, key=lambda c: c.bom_ref):
            comp_risks = effective_component_risks(comp)
            if imported_discovery_component(comp):
                omitted += len(comp_risks)
                continue
            risks = sorted(
                comp_risks,
                key=lambda r: (r.category, r.detail, SEVERITY_ORDER[r.severity]),
            )
            for risk in risks:
                rule_id = f"nexus_symbiote/{_rule_slug(risk.category)}/{risk.severity.value}"
                rules.setdefault(rule_id, self._rule(rule_id, risk.category, risk.severity))
                # The first fingerprint, from 0.1.0, stays stable across runs and
                # severity changes; GitHub reads primaryLocationLineHash.
                fingerprint = content_digest(
                    {
                        "rule": f"nexus_symbiote/{risk.category}",
                        "component": comp.bom_ref,
                        "detail": risk.detail,
                    }
                ).split(":", 1)[1]
                uri, source = self._location(comp, by_ref)
                physical: dict[str, Any] = {"artifactLocation": {"uri": uri, "uriBaseId": SRCROOT}}
                declaration_line = comp.properties.get("declaration_line")
                if (
                    source == "component"
                    and comp.properties.get("collection_mode") == "static-source-declaration"
                    and type(declaration_line) is int
                    and 1 <= declaration_line <= 2**31 - 1
                ):
                    physical["region"] = {"startLine": declaration_line}
                properties: dict[str, Any] = {
                    "component_ref": comp.bom_ref,
                    "trust_tier": comp.trust_tier.value,
                    "severity": risk.severity.value,
                    "location_source": source,
                }
                if risk.recommendation:
                    properties["recommendation"] = plain_text(risk.recommendation)
                findings.setdefault(
                    (rule_id, fingerprint),
                    {
                        "ruleId": rule_id,
                        "level": SEVERITY_TO_SARIF[risk.severity],
                        "message": {
                            "text": plain_text(risk.detail)
                            or rules[rule_id]["shortDescription"]["text"]
                        },
                        "locations": [{"physicalLocation": physical}],
                        "partialFingerprints": {
                            "nexus_symbiote/v1": fingerprint,
                            "primaryLocationLineHash": fingerprint[:16] + ":1",
                        },
                        "properties": properties,
                    },
                )
        ordered_rules = [rules[rule_id] for rule_id in sorted(rules)]
        index = {rule["id"]: position for position, rule in enumerate(ordered_rules)}
        results = [{**result, "ruleIndex": index[result["ruleId"]]} for result in findings.values()]
        claim = bom.metadata.completeness
        successful, notifications = _notifications(claim, len(results), self._relative_text)
        invocation: dict[str, Any] = {"executionSuccessful": successful}
        if notifications:
            invocation["toolExecutionNotifications"] = notifications
        if bom.metadata.timestamp is not None:
            invocation["endTimeUtc"] = (
                bom.metadata.timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
            )
        document = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "nexus-symbiote",
                            "version": __version__,
                            "informationUri": "https://github.com/aisecnomad/Nexus-Symbiote",
                            "rules": ordered_rules,
                        }
                    },
                    "results": results,
                    "invocations": [invocation],
                    "properties": {
                        "coverage": coverage_aggregate(claim),
                        **({OMITTED_IMPORTED_FINDINGS: omitted} if omitted else {}),
                        **(
                            {"operatorPolicyDigest": self._operator_policy_digest}
                            if self._operator_policy_digest
                            else {}
                        ),
                        **(
                            {"operatorPolicySigners": list(self._operator_policy_signers)}
                            if self._operator_policy_signers
                            else {}
                        ),
                    },
                }
            ],
        }
        require_valid(document, "sarif")
        return document

    @staticmethod
    def _rule(
        rule_id: str,
        category: str,
        severity: RiskSeverity,
        *,
        help_text: str = GENERIC_HELP,
        help_uri: str = HELP_URI,
    ) -> dict[str, Any]:
        info = RULES.get(category)
        if info is None:
            label = plain_text(category.replace("_", " ").replace("-", " "), 120)
            title = label[:1].upper() + label[1:] or "Finding"
            description = f"Inventory findings of category '{label}'."
            tags = ["security"]
        else:
            title, description = info.title, info.description
            tags = rule_tags(category, severity)
        return {
            "id": rule_id,
            "shortDescription": {"text": f"{title} ({severity.value})"},
            "fullDescription": {"text": description},
            "help": {"text": f"{description} {help_text}"},
            "helpUri": help_uri,
            "defaultConfiguration": {"level": SEVERITY_TO_SARIF[severity]},
            "properties": {
                "security-severity": SECURITY_SEVERITY[severity],
                "tags": tags,
                "precision": "medium",
            },
        }


def _notifications(
    claim: CompletenessClaim | None, result_count: int, relative: Callable[[str], str]
) -> tuple[bool, list[dict[str, Any]]]:
    """Collection failures make the run unsuccessful; gaps and scoping are warnings."""
    errors: list[str] = []
    warnings: list[str] = []
    notes: list[str] = []
    if claim is None:
        notes.append("The inventory carries no completeness claim; collection coverage is unknown.")
    else:
        failed = sorted(name for name, state in claim.scanner_status.items() if state == "failed")
        errors.extend(
            f"Collection failure: {plain_text(relative(item))}" for item in claim.scan_failures
        )
        errors.extend(f"Collector {plain_text(name)} failed." for name in failed)
        warnings.extend(
            f"Coverage gap: {plain_text(relative(item))}" for item in claim.surfaces_excluded
        )
        not_run = (PROJECTION_SCANNERS | set(claim.scanner_status)) - set(
            claim.collectors_requested
        )
        warnings.extend(
            f"Collector {plain_text(name)} was not run; its surfaces are not covered."
            for name in sorted(not_run)
        )
        if coverage_aggregate(claim) == "incomplete":
            warnings.append(
                "Collection coverage is incomplete: this run does not cover every surface."
            )
        else:
            notes.append(
                "Collection coverage is unknown: static collection does not observe runtime, "
                "network or live tool surfaces."
            )
    if result_count > GITHUB_MAX_RESULTS:
        warnings.append(
            f"This run has {result_count} results; GitHub code scanning keeps at most "
            f"{GITHUB_MAX_RESULTS} per run."
        )
    successful = not errors
    entries = [
        *(("error", text) for text in errors),
        *(("warning", text) for text in warnings),
        *(("note", text) for text in notes),
    ]
    if len(entries) > MAX_NOTIFICATIONS:
        omitted = len(entries) - MAX_NOTIFICATIONS + 1
        entries = [
            *entries[: MAX_NOTIFICATIONS - 1],
            ("warning", f"{omitted} more notifications are recorded in the native inventory."),
        ]
    return successful, [{"level": level, "message": {"text": text}} for level, text in entries]
