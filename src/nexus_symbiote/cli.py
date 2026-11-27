"""Nexus SymBiote CLI — Agent Bill of Materials for AI supply chain security."""

from __future__ import annotations

import contextvars
import errno
import json
import math
import os
import re
import sys
from collections.abc import Callable, Mapping
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar, cast

import click

from nexus_symbiote import __version__, limits, modes
from nexus_symbiote.attestation_cli import register_attestation_commands
from nexus_symbiote.control_plane_cli import register_control_plane_commands
from nexus_symbiote.core.aibom import AIBOM, ContentSerialError, NativeFormatError, prepare
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    DiscoveryVerification,
)
from nexus_symbiote.crosswalk_cli import register_crosswalk_commands
from nexus_symbiote.digest_cli import register_digest_commands, source_date_epoch
from nexus_symbiote.export_standard_cli import register_export_standard_commands
from nexus_symbiote.graph import validate_graph
from nexus_symbiote.graph_cli import register_graph_commands
from nexus_symbiote.instruction_diff import register_instruction_diff_commands
from nexus_symbiote.inventory_export_cli import register_inventory_export_commands
from nexus_symbiote.live_cli import register_live_commands
from nexus_symbiote.minimum_elements_cli import register_minimum_elements_commands
from nexus_symbiote.policy import Policy
from nexus_symbiote.policy import running_in_ci as _running_in_ci
from nexus_symbiote.reporting import (
    ReportLine,
    diff_report_lines,
    print_lines,
    risk_report_lines,
    scan_gate_lines,
    severity_rank,
    validation_report_lines,
)
from nexus_symbiote.runtime_cli import register_runtime_commands
from nexus_symbiote.sbom_cli import register_sbom_commands
from nexus_symbiote.supply_chain_cli import STAGED_INVENTORY, register_supply_chain_commands
from nexus_symbiote.text_poisoning import apply_text_poisoning_rules
from nexus_symbiote.trace_cli import register_trace_commands
from nexus_symbiote.utils.confined import DEFAULT_EXCLUDE_ACCEPTANCE, DEFAULT_EXCLUDES
from nexus_symbiote.utils.files import write_output_file
from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    neutralize,
    output_failure,
    refuse_dash_output,
    safe_line,
    write_cli_output,
)

if TYPE_CHECKING:
    from nexus_symbiote.scanners.base import ScanResult
    from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy

DEBUG_KEY = "nexus_symbiote.debug"
BUILTIN_SCANNERS = "mcp, model, prompt, rag, registry, a2a, ide_agents, shadowscan"
# Gate reports name the agent manifest and the graph check like collectors.
MANIFEST = "agent.yaml"


def _debug_enabled() -> bool:
    ctx = click.get_current_context(silent=True)
    return bool(ctx is not None and ctx.meta.get(DEBUG_KEY))


def _staged_inventory() -> bool:
    ctx = click.get_current_context(silent=True)
    return bool(ctx is not None and ctx.meta.get(STAGED_INVENTORY))


def _print_traceback(exc: BaseException) -> None:
    import traceback

    # An error's message can quote project or inventory text, secrets included; its
    # class and where it was raised are what a defect report needs, so only those print.
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        echo_line("Debug: ", type(current).__name__, " raised at:", err=True)
        for frame in traceback.extract_tb(current.__traceback__):
            echo_line("Debug:   ", frame.filename, ":", frame.lineno, " in ", frame.name, err=True)
        cause = current.__cause__
        current = (
            cause if cause is not None or current.__suppress_context__ else current.__context__
        )


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


def _input_problem(exc: BaseException) -> str:
    """Name the class of an input failure without quoting the input."""
    from pydantic import ValidationError

    if isinstance(exc, OSError):
        return "it cannot be read"
    if isinstance(exc, RecursionError):
        return "it is nested too deeply"
    if isinstance(exc, UnicodeError):
        return "it is not UTF-8 text"
    if isinstance(exc, ValidationError):
        return "it does not match the native AIBOM schema"
    if isinstance(exc, json.JSONDecodeError):
        return "it is not valid JSON"
    return (
        "it is not strict JSON (duplicate keys and non-finite numbers are refused) "
        "or exceeds the size limit"
    )


def _resolve_operator_policy(
    operator_policy: Path | None,
    root: Path | None,
    *,
    attestation_path: Path | None = None,
    trusted_keys: tuple[Path, ...] = (),
    allow_unsigned: bool = False,
    max_age_days: int = 90,
) -> tuple[Any | None, str | None, tuple[str, ...]]:
    from nexus_symbiote.operator_policy import (
        OperatorPolicyAttestationError,
        OperatorPolicyError,
        load_operator_policy,
    )

    if operator_policy is None:
        if attestation_path is not None or trusted_keys or allow_unsigned:
            raise click.UsageError(
                "--operator-policy-attestation, --operator-policy-key, and "
                "--allow-unsigned-operator-policy require --operator-policy"
            )
        return None, None, ()
    if allow_unsigned and (attestation_path is not None or trusted_keys):
        raise click.UsageError(
            "--allow-unsigned-operator-policy cannot be combined with "
            "--operator-policy-attestation or --operator-policy-key"
        )
    try:
        loaded = load_operator_policy(
            operator_policy,
            root,
            envelope_path=attestation_path,
            trusted_keys=trusted_keys,
            allow_unsigned=allow_unsigned,
            max_age_days=max_age_days,
        )
    except OperatorPolicyAttestationError as exc:
        raise _GateClickException(neutralize(exc)) from exc
    except OperatorPolicyError as exc:
        raise _failure(exc) from exc
    return loaded.policy, loaded.digest, loaded.signers


def _format_operator_source(digest: str, signers: tuple[str, ...]) -> str:
    if signers:
        return f"operator:{digest} (signers: {','.join(signers)})"
    return f"operator:{digest}"


_LAST_CLAMPED_SETTINGS: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "_LAST_CLAMPED_SETTINGS", default=()
)


def _warn_unapplied_project_policy(path: Path) -> dict[str, str]:
    """Report a withheld relaxation without echoing untrusted contents."""
    echo_line(
        "WARNING: project policy ",
        path,
        " was not applied. Pass --accept-project-policy to apply it, or "
        "--no-project-policy to ignore it explicitly.",
        err=True,
    )
    return {"file": path.name, "reason": "not-accepted"}


def _policy_with_source(
    root: Path,
    *,
    ignore_project: bool = False,
    warn: bool = True,
    allow_weakening: bool = False,
    operator: Policy | None = None,
    operator_digest: str | None = None,
    operator_signers: tuple[str, ...] = (),
) -> tuple[Policy, str, list[str], dict[str, str] | None]:
    """Load the governing policy and say where it came from and what it relaxes.

    Apply each tightening even if the checkout also asks to relax a different
    setting. An operator policy always bounds the result.
    """
    from nexus_symbiote.operator_policy import narrow_policy
    from nexus_symbiote.policy import (
        PolicyError,
        default_policy,
        load_policy_file,
        weakened_settings,
    )

    _LAST_CLAMPED_SETTINGS.set(())
    if operator is not None and operator_digest is not None:
        baseline = operator
        source = _format_operator_source(operator_digest, operator_signers)
    else:
        baseline = default_policy()
        source = "built-in"

    baseline_weaker = weakened_settings(baseline)
    if ignore_project:
        return baseline, source, baseline_weaker, None
    try:
        loaded = load_policy_file(root)
    except PolicyError as exc:
        raise _failure(exc) from exc
    if loaded is None:
        return baseline, source, baseline_weaker, None
    project, path, _ = loaded
    has_operator = operator is not None and operator_digest is not None
    weaker = weakened_settings(project)
    if has_operator or (weaker and not allow_weakening):
        narrowed, clamped = narrow_policy(baseline, project, inherit_unspecified=True)
        _LAST_CLAMPED_SETTINGS.set(tuple(clamped))
        if not allow_weakening and (clamped or not has_operator):
            if narrowed == baseline:
                return baseline, source, baseline_weaker, _warn_unapplied_project_policy(path)
            echo_line(
                "WARNING: project policy ",
                path,
                " tightened the governing gates. Its relaxations were withheld. "
                "Pass --accept-project-policy to accept relaxations within the operator policy.",
                err=True,
            )
            if not has_operator:
                # Attribute only effective overrides to the checkout in machine reports.
                narrowed = type(baseline).model_validate(
                    narrowed.model_dump(by_alias=True, exclude_defaults=True)
                )
                source = f"project:{path}"
            return (
                narrowed,
                source,
                weakened_settings(narrowed),
                {"file": path.name, "reason": "relaxations-not-accepted"},
            )
        if clamped and warn:
            echo_line(
                "WARNING: project policy ",
                path,
                " attempted to relax operator policy; clamped: ",
                "; ".join(clamped),
                err=True,
            )
        return narrowed, source, weakened_settings(narrowed), None
    if weaker and warn:
        echo_line(
            "WARNING: policy ", path, " weakens the built-in gates: ", "; ".join(weaker), err=True
        )
    return project, f"project:{path}", weaker, None


def _inventory_policy(
    project: Path | None,
    aibom_path: str,
    *,
    ignore_project: bool,
    warn: bool = True,
    allow_weakening: bool = False,
    operator: Policy | None = None,
    operator_digest: str | None = None,
    operator_signers: tuple[str, ...] = (),
) -> tuple[Policy, str, list[str], dict[str, str] | None]:
    """Policy for a command that reads an inventory: only a named project or operator supplies one."""
    from nexus_symbiote.policy import default_policy, nearest_policy_file, weakened_settings

    _LAST_CLAMPED_SETTINGS.set(())
    if project is not None:
        return _policy_with_source(
            project,
            ignore_project=ignore_project,
            warn=warn,
            allow_weakening=allow_weakening,
            operator=operator,
            operator_digest=operator_digest,
            operator_signers=operator_signers,
        )
    if operator is not None and operator_digest is not None:
        return (
            operator,
            _format_operator_source(operator_digest, operator_signers),
            weakened_settings(operator),
            None,
        )
    if not ignore_project:
        unapplied = nearest_policy_file(Path(aibom_path).resolve().parent)
        if unapplied is not None:
            echo_line(
                "Note: ",
                unapplied,
                " was not applied. Without --project the built-in policy is used; "
                "use --project to evaluate its policy and --accept-project-policy to accept relaxations.",
                err=True,
            )
            return (
                default_policy(),
                "built-in",
                [],
                {"file": unapplied.name, "reason": "project-not-specified"},
            )
    return default_policy(), "built-in", [], None


def _gate_sources(
    policy: Policy, policy_source: str, threshold_from_cli: bool, fail_on_severity: str | None
) -> dict[str, str]:
    """Where each effective risk-gate parameter came from: cli, operator, project policy or built-in."""

    def origin(name: str) -> str:
        if policy_source.startswith("operator:"):
            return "operator policy"
        if policy_source.startswith("project:") and name in policy.risk.model_fields_set:
            return "project policy"
        return "built-in"

    return {
        "fail_threshold_source": "cli" if threshold_from_cli else origin("fail_threshold"),
        "fail_on_severity_source": "cli" if fail_on_severity else origin("fail_on_severity"),
        "warn_threshold_source": origin("warn_threshold"),
        "ignore_categories_source": origin("ignore_categories"),
        "suppressions_source": origin("suppressions"),
    }


def _silence_broken_pipe() -> None:
    """Point standard output at /dev/null so shutdown does not print a traceback.

    The Python file object may already be closed, so this uses descriptor 1
    rather than ``sys.stdout.fileno()``.
    """
    try:
        null = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        return
    try:
        os.dup2(null, 1)
    except OSError:
        # Descriptor 1 is already gone; the interpreter then has nothing left to flush.
        pass
    finally:
        os.close(null)


def _failure(exc: Exception) -> click.ClickException:
    # Policy, graph and inventory errors quote keys, file names and paths from the
    # checkout or the inventory, so they get the same neutralization as other output.
    return click.ClickException(neutralize(exc))


def _load_bom_with_bytes(path: str | Path) -> tuple[AIBOM, bytes]:
    # Parser and validation messages can quote attacker-controlled input; name only the
    # class of the problem. A NativeFormatError names it without quoting the document.
    try:
        return AIBOM.load_with_bytes(Path(path))
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. Reason: {_input_problem(exc)}."
        ) from exc


def _load_bom(path: str | Path) -> AIBOM:
    return _load_bom_with_bytes(path)[0]


def _project_root(value: str | Path, *, label: str) -> Path:
    """Resolve a project directory, saying so when a symbolic link redirects it.

    The confined collectors refuse a root reached through a symbolic link, so the CLI
    resolves the path first. A checkout can replace a directory it contains with a
    link to any directory on the machine, and a plain relative path can only leave
    the working directory through such a link, so that case is refused.
    """
    requested = Path(value)
    resolved = requested.resolve()
    if Path(os.path.normpath(requested.absolute())) == resolved:
        return resolved
    if (
        not requested.is_absolute()
        and ".." not in requested.parts
        and not resolved.is_relative_to(Path.cwd().resolve())
    ):
        raise click.BadParameter(
            f"{value} leads outside the current directory through a symbolic link; "
            f"name the directory it resolves to, {resolved}, to collect that directory",
            param_hint=label,
        )
    echo_line(
        "Note: ", label, " ", value, " resolves through a symbolic link to ", resolved, err=True
    )
    return resolved


def _require_binding_key() -> None:
    """A malformed operator key is a usage error, not a failure of the scanned files."""
    from nexus_symbiote.scanners.mcp import _MIN_SOURCE_BINDING_KEY_LENGTH, SOURCE_BINDING_KEY_ENV

    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if key and len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise click.UsageError(
            f"{SOURCE_BINDING_KEY_ENV} must contain at least "
            f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
        )


def _unsigned_discovery_flags(fail_on_unsigned_discovery: bool, allow: bool) -> None:
    if fail_on_unsigned_discovery and allow:
        raise click.UsageError(
            "--fail-on-unsigned-discovery and --allow-unsigned-discovery contradict each other"
        )


DISCOVERY_SIGNATURE_NEEDS_PROJECT = (
    "The policy sets validate.require_discovery_signature and the inventory carries "
    "ShadowScan discovery evidence; only --project with --signature-policy can verify "
    "the report's signer."
)


def _discovery_signature_unverifiable(policy: Policy, bom: AIBOM) -> bool:
    """The policy requires a verified discovery signer that this run has no project to check.

    ``--allow-unsigned-discovery`` does not waive it: like ``scan --check``, the policy
    requirement is the operator's and only a producer check over the report bytes meets it.
    """
    from nexus_symbiote.validators.completeness import carries_discovery_evidence

    return policy.validation.require_discovery_signature and carries_discovery_evidence(bom)


def _unsigned_discovery_failure_reason(
    bom: AIBOM,
    *,
    fail_on_unsigned_discovery: bool,
    allow_unsigned_discovery: bool,
    already_verified: bool = False,
) -> str | None:
    """Warn loudly about unverified ShadowScan evidence; return a failure reason when it must not pass.

    Only a producer check made in this run counts as verification
    (``already_verified``: ``import-shadowscan --bundle``, or
    ``--project --signature-policy`` at validate and risk time). The BOM's own
    ``discovery_verification`` record is unsigned text that anyone who can
    write the BOM can set, so a recorded ``verified`` or ``not-applicable``
    is reported, never trusted. A BOM that carries no discovery evidence
    passes. Otherwise the run warns, and fails when the operator asked for it
    with ``--fail-on-unsigned-discovery``, or when the run looks like CI and
    the operator did not explicitly accept unsigned evidence with
    ``--allow-unsigned-discovery``. Interactive runs warn only.
    """
    from nexus_symbiote.validators.completeness import _carries_discovery

    if already_verified or not _carries_discovery(bom):
        return None
    claim = bom.metadata.completeness
    record = claim.discovery_verification if claim is not None else None
    if record is not None:
        detail = (
            f"report {record.report_digest}, report time {record.report_time}, "
            f"repository {record.repository}, commit {record.commit}"
        )
        if record.status != "unverified":
            detail += (
                f"; the BOM records {record.status!s} at import, but that record is unsigned "
                "and is not checked again here"
            )
    else:
        detail = "no verification outcome was recorded at import (BOM predates the record)"
    echo_line(
        "WARNING: ShadowScan discovery evidence is UNVERIFIED. ",
        detail,
        ". The producer's signature was not checked at import, "
        "so a substituted or replayed report would import the same way. "
        "Verify it with `verify-discovery --bundle`, require a signer with "
        "`validate --project --signature-policy`, or import it with "
        "`import-shadowscan --bundle`.",
        err=True,
    )
    if allow_unsigned_discovery:
        return None
    if fail_on_unsigned_discovery:
        return "Unsigned ShadowScan discovery evidence (--fail-on-unsigned-discovery)."
    if _running_in_ci():
        echo_line(
            "  In CI, pass --allow-unsigned-discovery to accept unsigned discovery "
            "evidence explicitly.",
            err=True,
        )
        return (
            "Unsigned ShadowScan discovery evidence in CI; pass "
            "--allow-unsigned-discovery to accept it explicitly."
        )
    return None


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
        raise _failure(exc) from None


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


_ACCEPT_PROJECT_POLICY_HELP = (
    "Accept checkout settings that relax a gate. Tightening settings apply automatically, "
    "including in mixed policies. Operator policy always sets the minimum."
)
DETAILED_EXIT_KEY = "nexus_symbiote.detailed_exit_codes"
_MODE_FLAGS = frozenset({"--offline", "--live"})
# Click 8.2+ shows a group's own help, which carries no input, through this error.
_HELP_ERRORS = tuple(
    error
    for error in (getattr(click.exceptions, "NoArgsIsHelpError", None),)
    if isinstance(error, type)
)


def supported_platform() -> bool:
    """Whether this host has the no-follow, descriptor-relative opens confinement needs.

    Windows has neither, and every command refuses to run there rather than reading,
    hashing or writing with checks that cannot hold (SECURITY.md, "Platforms").
    """
    return (
        os.name == "posix"
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
    )


class _CollectionClickException(click.ClickException):
    """Collection, input, or internal failure under Decision 4 (--detailed-exit-codes -> 4)."""

    exit_code = 4


class _GateClickException(click.ClickException):
    """Gate or verification failure under Decision 4 (--detailed-exit-codes -> 3)."""

    exit_code = 3


def _neutralized(exc: click.ClickException, *, detailed: bool = False) -> click.ClickException:
    """The same error with neutralized text: it can quote checkout or inventory text."""
    message = neutralize(exc.format_message())
    if isinstance(exc, click.UsageError):
        return click.UsageError(message, ctx=exc.ctx)
    if detailed:
        if isinstance(exc, _GateClickException) or exc.exit_code == 3:
            return _GateClickException(message)
        return _CollectionClickException(message)
    return click.ClickException(message)


def _apply_exit_code_flags(detailed: bool, legacy: bool) -> bool:
    if detailed and legacy:
        raise click.UsageError(
            "--detailed-exit-codes and --legacy-exit-codes contradict each other"
        )
    ctx = click.get_current_context(silent=True)
    inherited = bool(ctx is not None and ctx.meta.get(DETAILED_EXIT_KEY))
    if inherited and legacy:
        raise click.UsageError(
            "--detailed-exit-codes and --legacy-exit-codes contradict each other"
        )
    effective = (detailed or inherited) and not legacy
    if ctx is not None:
        ctx.meta[DETAILED_EXIT_KEY] = effective
    return effective


def _gate_exit(detailed: bool, *, collection_failed: bool = False) -> None:
    from nexus_symbiote.operator_policy import EXIT_COLLECTION_FAILED, EXIT_GATE_FAILED

    if detailed:
        raise click.exceptions.Exit(
            EXIT_COLLECTION_FAILED if collection_failed else EXIT_GATE_FAILED
        )
    raise click.exceptions.Exit(1)


def _resolve_report_format(json_output: bool, report_format: str | None) -> str:
    if json_output and report_format is not None and report_format != "json":
        raise click.UsageError("--json-output and --report-format disagree; choose one format")
    return "json" if json_output else (report_format or "text")


def _refuse_step_summary_input(step_summary: Path) -> None:
    """Refuse a step summary that is a file this command also reads, such as its inventory.

    Appending Markdown to an input would corrupt it in place. Compared by identity, so a
    hard link or a case variant of the input is refused too.
    """
    from nexus_symbiote.policy import POLICY_FILE_NAMES

    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return
    try:
        if not step_summary.exists():
            return
        named: list[object] = []
        for param in ctx.command.params:
            if param.name == "step_summary" or not isinstance(param.type, click.Path):
                continue
            value = ctx.params.get(param.name or "")
            named.extend(value if isinstance(value, tuple | list) else [value])
        project = ctx.params.get("project")
        if project and not ctx.params.get("no_project_policy"):
            # The checkout policy consulted by risk and validate has no explicit file option.
            named.extend(Path(project) / name for name in POLICY_FILE_NAMES)
        same = any(
            os.path.exists(source) and os.path.samefile(step_summary, source)
            for source in named
            if isinstance(source, str | os.PathLike)
        )
    except OSError as exc:
        raise output_failure(exc) from exc
    if same:
        raise click.UsageError("--step-summary must not name a file this command reads")


def _emit_gate_report(
    gate_name: str,
    report_format: str,
    document: dict[str, Any],
    text_lines: Any,
    *,
    step_summary: Path | None = None,
    project: Path | None = None,
    operator_source: str | None = None,
) -> None:
    from nexus_symbiote.operator_policy import (
        append_step_summary,
        render_gate_junit,
        render_gate_markdown,
    )

    if step_summary is not None:
        _refuse_step_summary_input(step_summary)
        append_step_summary(
            step_summary, render_gate_markdown(gate_name, document), project=project
        )
    if report_format == "json":
        click.echo(json_text(json.dumps(document, indent=2)))
    elif report_format == "markdown":
        click.echo(render_gate_markdown(gate_name, document), nl=False)
    elif report_format == "junit":
        click.echo(render_gate_junit(gate_name, document), nl=False)
    else:
        print_lines(text_lines())
        if operator_source is not None and gate_name != "validate":
            echo_line("  Policy: ", operator_source)


_F = TypeVar("_F", bound=Callable[..., Any])


def _apply_options(func: _F, *options: Callable[[_F], _F]) -> _F:
    for opt in reversed(options):
        func = opt(func)
    return func


def _exit_code_options(func: _F) -> _F:
    return _apply_options(
        func,
        click.option(
            "--detailed-exit-codes",
            is_flag=True,
            help="Use distinct exit codes: 0 passed, 2 usage, 3 gate failed, 4 collection/input failure.",
        ),
        click.option(
            "--legacy-exit-codes",
            is_flag=True,
            help="Use legacy exit codes: 0 passed, 1 gate or input failure, 2 usage error.",
        ),
    )


def _operator_policy_options(func: _F) -> _F:
    return _apply_options(
        func,
        click.option(
            "--operator-policy",
            type=click.Path(exists=True, dir_okay=False, path_type=Path),
            help="Signed operator policy YAML outside the scanned checkout; checkout policy may only narrow it.",
        ),
        click.option(
            "--operator-policy-attestation",
            type=click.Path(exists=True, dir_okay=False, path_type=Path),
            help="DSSE attestation envelope (purpose 'policy') over --operator-policy.",
        ),
        click.option(
            "--operator-policy-key",
            type=click.Path(exists=True, dir_okay=False, path_type=Path),
            multiple=True,
            help="Trusted Ed25519 public key for --operator-policy-attestation (repeatable).",
        ),
        click.option(
            "--allow-unsigned-operator-policy",
            is_flag=True,
            help="Accept --operator-policy without a verified DSSE signature envelope.",
        ),
        click.option(
            "--operator-policy-max-age-days",
            type=click.IntRange(min=0),
            default=90,
            show_default=True,
            help="Maximum attestation age in days when --operator-policy-attestation is verified (0 disables).",
        ),
    )


def _step_summary_path(
    ctx: click.Context, param: click.Parameter, value: str | None
) -> Path | None:
    if value is None:
        return None
    try:
        return cast(Path, click.Path(dir_okay=False, path_type=Path).convert(value, param, ctx))
    except ValueError as exc:
        raise output_failure(exc) from exc


def _gate_report_options(func: _F) -> _F:
    @wraps(func)
    def gate(*args: Any, **kwargs: Any) -> Any:
        if kwargs.get("step_summary") is None:
            return func(*args, **kwargs)
        from nexus_symbiote.core.hashing import gate_input_files

        token = gate_input_files.set(set())
        try:
            return func(*args, **kwargs)
        finally:
            gate_input_files.reset(token)

    return _apply_options(
        cast(_F, gate),
        click.option(
            "--report-format",
            type=click.Choice(["text", "json", "markdown", "junit"]),
            default=None,
            help="Gate report format (default: text, or json with --json-output).",
        ),
        click.option(
            "--step-summary",
            type=click.STRING,
            metavar="FILE",
            callback=_step_summary_path,
            default=None,
            help=(
                "Append a Markdown gate summary (for example GITHUB_STEP_SUMMARY) to a new file "
                "or an existing singly linked report. Files read by this gate are protected."
            ),
        ),
    )


def _declared_text_only(exc: click.ClickException) -> bool:
    """Click's own missing-parameter error, worded only from the parameter's declaration.

    Its lines (such as one per allowed choice) come from this program, never from input,
    so they keep Click's layout instead of being joined into one neutralized line.
    """
    return (
        type(exc) is click.MissingParameter
        and not exc.message
        and exc.param is not None
        and exc.param_hint is None
        and exc.param_type is None
    )


class _RootGroup(click.Group):
    """Root group: clear mode refusals, neutralized error text and no tracebacks."""

    def _main_shell_completion(
        self,
        ctx_args: Any,
        prog_name: str,
        complete_var: str | None = None,
    ) -> None:
        # Shell completion is not offered: an inherited _NEXUS_SYMBIOTE_COMPLETE would
        # make every command, gates included, print a script and exit 0 without running.
        return None

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except click.NoSuchOption as exc:
            if exc.option_name == limits.OPTION:
                raise click.UsageError(
                    f"No such option: {limits.OPTION}. Limits go before the command: "
                    f"nexus-symbiote {limits.OPTION} NAME=VALUE <command> ...",
                    ctx=exc.ctx,
                ) from None
            if exc.option_name not in _MODE_FLAGS:
                raise _neutralized(exc, detailed=bool(ctx.meta.get(DETAILED_EXIT_KEY))) from None
            raise click.UsageError(
                f"No such option: {exc.option_name}. Mode flags go before the command: "
                f"nexus-symbiote {exc.option_name} <command> ...",
                ctx=exc.ctx,
            ) from None
        except modes.LiveModeRequiredError as exc:
            raise click.UsageError(neutralize(exc)) from None
        except modes.OfflineViolation as exc:
            err_cls: type[click.ClickException] = (
                _CollectionClickException
                if ctx.meta.get(DETAILED_EXIT_KEY)
                else click.ClickException
            )
            raise err_cls(
                f"offline mode blocked {neutralize(exc)} before the command completed. This "
                "command never needs the network or a subprocess; please report this as a defect."
            ) from None
        except click.ClickException as exc:
            if isinstance(exc, _HELP_ERRORS) or _declared_text_only(exc):
                raise
            raise _neutralized(exc, detailed=bool(ctx.meta.get(DETAILED_EXIT_KEY))) from None
        except (click.exceptions.Exit, click.Abort):
            raise
        except Exception as exc:
            if isinstance(exc, BrokenPipeError) or (
                isinstance(exc, OSError) and exc.errno == errno.EPIPE
            ):
                _silence_broken_pipe()
                raise click.exceptions.Exit(141) from None
            # A traceback can quote project or inventory text, so it is shown only on
            # request; the command still fails closed.
            if ctx.meta.get(DEBUG_KEY):
                _print_traceback(exc)
            internal_cls: type[click.ClickException] = (
                _CollectionClickException
                if ctx.meta.get(DETAILED_EXIT_KEY)
                else click.ClickException
            )
            raise internal_cls(
                f"internal error ({type(exc).__name__}); nothing was approved. Rerun with "
                "--debug before the command to see where it was raised, and please report it."
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
@click.option(
    "--debug",
    "debug_flag",
    is_flag=True,
    help=(
        "Print where a collector or internal error was raised (its class, files, lines and "
        "functions) on standard error, without its message, which can quote input."
    ),
)
@_exit_code_options
@click.option(
    limits.OPTION,
    "limit_settings",
    multiple=True,
    metavar="NAME=VALUE",
    help=(
        "Set one collection limit for this command, for example entries=200000 or "
        "model-bytes=128GiB. Repeatable; overrides NEXUS_SYMBIOTE_LIMITS for that name. "
        "Limits: " + ", ".join(limits.SPECS) + "."
    ),
)
@click.pass_context
def main(
    ctx: click.Context,
    offline_flag: bool,
    live_flag: bool,
    debug_flag: bool,
    detailed_exit_codes: bool = False,
    legacy_exit_codes: bool = False,
    limit_settings: tuple[str, ...] = (),
) -> None:
    """Nexus SymBiote — Agent Bill of Materials for AI supply chain security.

    Every command runs offline by default: no name resolution, network
    connections or subprocesses. Only discover-mcp, advisories and verify-live
    reach outside local files, and only in live mode: pass --live before the
    command or set NEXUS_SYMBIOTE_MODE=live.

    Collection limits bound what one command reads from a project. Reaching one
    fails the scan and names the limit; raise it with --limit before the command
    or with NEXUS_SYMBIOTE_LIMITS=NAME=VALUE,NAME=VALUE. A project's own files
    never change a limit.
    """
    ctx.meta[DEBUG_KEY] = debug_flag
    _apply_exit_code_flags(detailed_exit_codes, legacy_exit_codes)
    if not supported_platform():
        raise click.ClickException(
            "unsupported platform: confined file access needs POSIX O_NOFOLLOW, O_DIRECTORY "
            "and descriptor-relative opens, which this host lacks; Windows is not supported"
        )
    try:
        requested = modes.resolve(offline=offline_flag, live=live_flag, environ=os.environ)
        collection_limits = limits.resolve(limit_settings, os.environ)
    except ValueError as exc:
        raise click.UsageError(str(exc), ctx=ctx) from None
    ctx.meta["nexus_symbiote.mode"] = requested
    ctx.with_resource(limits.applied(collection_limits))
    ctx.with_resource(modes.enforce(modes.command_mode(requested.mode, ctx.invoked_subcommand)))


def _merge_scan_result(
    name: str,
    result: ScanResult,
    aibom: AIBOM,
    collected: dict[str, Any],
    scan_failures: list[str],
) -> None:
    from nexus_symbiote.core.collection import merge_collected

    accepted_refs: set[str] = set()
    for comp in result.components:
        # Discovery of a file/configuration does not verify every supplier assertion.
        outcome = merge_collected(collected, comp, name, aibom.metadata.timestamp)
        if outcome == "conflict":
            scan_failures.append(f"{name}: conflicting duplicate component {comp.bom_ref}")
            continue
        if outcome == "added":
            aibom.components.append(comp)
        accepted_refs.add(comp.bom_ref)
    for edge in result.dependencies:
        if edge.source_ref in accepted_refs and edge.target_ref in accepted_refs:
            aibom.add_dependency(edge)
        else:
            scan_failures.append(f"{name}: dependency endpoint was not imported")


def _render_aibom(
    aibom: AIBOM,
    output_format: str,
    root: Path,
    *,
    operator_policy_digest: str | None = None,
    operator_policy_signers: tuple[str, ...] = (),
) -> str:
    if output_format == "cyclonedx":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

        return CycloneDXGenerator().generate_json(aibom)
    if output_format == "spdx":
        from nexus_symbiote.generators.spdx import SPDXGenerator

        return SPDXGenerator().generate_json(aibom)
    if output_format == "sarif":
        from nexus_symbiote.generators.sarif import SARIFGenerator

        # Inventory paths are relative to the scanned root; SARIF URIs to the working
        # directory, or to the scanned root when the scan starts outside it.
        return SARIFGenerator(
            scan_root=root,
            operator_policy_digest=operator_policy_digest,
            operator_policy_signers=operator_policy_signers,
        ).generate_json(aibom)
    try:
        return aibom.to_native_json()
    except NativeFormatError as exc:
        raise click.ClickException(f"Inventory not written. {exc}") from exc


@main.command()
@click.argument("project_path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option(
    "-o", "--output", type=click.Path(), help="Output file path (default: standard output)"
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "cyclonedx", "spdx", "sarif"]),
    default=None,
    help="Output format. Defaults to json unless the accepted policy sets a format.",
)
@click.option(
    "--scanner",
    "scanners",
    multiple=True,
    help=(
        f"Collector to run, once each: {BUILTIN_SCANNERS}. Defaults to all unless the "
        "accepted policy selects collectors. A collector left out makes coverage partial."
    ),
)
@click.option(
    "--report-only",
    is_flag=True,
    help=(
        "Emit findings and collection failures without a CI failure. With --check, unverified "
        "discovery evidence and a failed producer check still exit 1."
    ),
)
@click.option(
    "--check",
    "check_only",
    is_flag=True,
    help="Collect and apply the scan gate without writing an inventory.",
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit operator signer policy JSON",
)
@_operator_policy_options
@click.option(
    "--no-project-policy",
    is_flag=True,
    help="Use built-in policy without reading configuration from the target.",
)
@click.option(
    "--accept-project-policy",
    is_flag=True,
    help=_ACCEPT_PROJECT_POLICY_HELP,
)
@click.option(
    "--accept-default-exclude",
    type=click.Choice(sorted(DEFAULT_EXCLUDE_ACCEPTANCE)),
    multiple=True,
    help="Accept one default exclusion while retaining the path in the inventory. Repeat as needed.",
)
@click.option(
    "--accept-default-excludes",
    is_flag=True,
    help=(
        "Do not record a coverage gap for a non-empty default-excluded name (.git, "
        "node_modules, __pycache__, .venv, venv). Without this flag such an entry "
        "makes coverage partial. An empty directory does not."
    ),
)
@click.option(
    "--fail-on-unsigned-discovery",
    is_flag=True,
    help="With --check, exit with status 1 when ShadowScan discovery evidence is unverified.",
)
@click.option(
    "--allow-unsigned-discovery",
    is_flag=True,
    help=(
        "With --check, accept unverified ShadowScan discovery evidence explicitly (still warns); "
        "required in CI."
    ),
)
@click.option(
    "--all-packages",
    is_flag=True,
    help=(
        "Inventory every declared or locked package and base image, not only the AI catalog, "
        "so that advisory matching covers the whole dependency set the agent process loads."
    ),
)
@click.option(
    "--advisory-db",
    type=click.Path(exists=True, path_type=Path),
    help=(
        "Offline OSV bundle (a JSON file or a flat directory of OSV records) matched against "
        "every exact PyPI/npm pin in the inventory during the scan; matches are recorded as "
        "known_vulnerability findings on the package and exported as CycloneDX vulnerabilities. "
        "No network I/O."
    ),
)
@_exit_code_options
def scan(
    project_path: str,
    output: str | None,
    output_format: str | None,
    scanners: tuple[str, ...],
    report_only: bool = False,
    signature_policy: Path | None = None,
    operator_policy: Path | None = None,
    operator_policy_attestation: Path | None = None,
    operator_policy_key: tuple[Path, ...] = (),
    allow_unsigned_operator_policy: bool = False,
    operator_policy_max_age_days: int = 90,
    no_project_policy: bool = False,
    accept_project_policy: bool = False,
    accept_default_excludes: bool = False,
    accept_default_exclude: tuple[str, ...] = (),
    check_only: bool = False,
    fail_on_unsigned_discovery: bool = False,
    allow_unsigned_discovery: bool = False,
    detailed_exit_codes: bool = False,
    legacy_exit_codes: bool = False,
    all_packages: bool = False,
    advisory_db: Path | None = None,
) -> tuple[Path, Policy, list[SigstoreArtifactPolicy]] | None:
    """Scan a project and generate an AIBOM."""
    detailed = _apply_exit_code_flags(detailed_exit_codes, legacy_exit_codes)
    _unsigned_discovery_flags(fail_on_unsigned_discovery, allow_unsigned_discovery)
    if (fail_on_unsigned_discovery or allow_unsigned_discovery) and not check_only:
        raise click.UsageError(
            "--fail-on-unsigned-discovery and --allow-unsigned-discovery require --check; "
            "gate a written inventory with validate or risk"
        )
    if check_only and output:
        raise click.UsageError("--check writes no inventory; drop -o/--output or --check")
    _require_binding_key()
    collected_at = source_date_epoch()
    root = _project_root(project_path, label="PROJECT_PATH")
    if not root.is_dir():
        raise click.ClickException(f"{neutralize(project_path)} is not a directory")

    from nexus_symbiote.graph import assemble_repository_agent
    from nexus_symbiote.policy import PolicyError
    from nexus_symbiote.validators.risk import RiskScorer

    op_policy, op_digest, op_signers = _resolve_operator_policy(
        operator_policy,
        root,
        attestation_path=operator_policy_attestation,
        trusted_keys=operator_policy_key,
        allow_unsigned=allow_unsigned_operator_policy,
        max_age_days=operator_policy_max_age_days,
    )
    policy, policy_source, policy_weakened, _ = _policy_with_source(
        root,
        ignore_project=no_project_policy,
        allow_weakening=accept_project_policy,
        operator=op_policy,
        operator_digest=op_digest,
        operator_signers=op_signers,
    )
    signature_policies = _signer_policies(signature_policy, root)
    output_format = output_format or policy.output.default_format
    all_scanners = _get_scanners()
    selected = scanners or tuple(policy.scan.scanners)
    unknown = set(selected) - set(all_scanners)
    if unknown:
        raise click.BadParameter(
            "Unknown scanner: " + ", ".join(sorted(unknown)), param_hint="--scanner"
        )
    if len(set(selected)) != len(selected):
        raise click.BadParameter("each collector may be selected only once", param_hint="--scanner")
    if output_format not in {"json", "cyclonedx", "spdx", "sarif"}:
        raise click.BadParameter("Unknown output format", param_hint="--format")
    echo_line("Scanning ", root, err=True)
    # The policy file always sits in the scan root; record it relative to that root.
    # No finalize() here: rendering owns the export metadata. prepare() derives the
    # serial from the inventory content digest, and the only collection time recorded
    # is the one SOURCE_DATE_EPOCH pins, so two scans of the same project are
    # byte-identical.
    aibom = AIBOM(
        metadata=AIBOMMetadata(
            authors=[],
            policy_source=(
                "project:" + policy_source.rsplit("/", 1)[-1]
                if policy_source.startswith("project:")
                else policy_source
            ),
            policy_weakened=policy_weakened,
            timestamp=collected_at,
        )
    )
    surfaces_scanned: list[str] = []
    surfaces_excluded: list[str] = []
    accepted_default_exclusions: set[str] = set()
    accepted_default_names: set[str] = set()
    scan_failures: list[str] = []
    failures_by: dict[str, list[str]] = {}
    excluded_by: dict[str, list[str]] = {}
    completed: list[str] = []
    source_report_digest = None
    source_report_content_digest = None
    source_report_content_profile = None
    source_report_format = None
    source_report_status = None
    source_report_path = None
    discovery_verification: DiscoveryVerification | None = None
    source_projection_limitations = None
    source_unmapped_count = 0
    source_unmapped_indexes: list[int] = []
    scanner_status: dict[str, str] = dict.fromkeys(all_scanners, "unknown")
    # AIBOM lookups scan the whole list; a project can declare tens of thousands of
    # tools, so index what this loop adds instead of searching for each component.
    collected: dict[str, Any] = {}
    for name in selected:
        if name == "model":
            scanner = all_scanners[name](signature_policies=signature_policies)
        elif name == "registry" and all_packages:
            from nexus_symbiote.scanners.registry import AllPackagesRegistryScanner

            scanner = AllPackagesRegistryScanner()
        else:
            scanner = all_scanners[name]()
        echo_line("  Running ", name, " scanner...", err=True)
        failure_count = len(scan_failures)
        try:
            configure = getattr(scanner, "configure", None)
            if configure:
                configure(
                    exclude_paths=policy.scan.exclude_paths,
                    accept_default_excludes=accept_default_excludes or accept_default_exclude,
                )
            elif policy.scan.exclude_paths:
                raise ValueError("scanner does not support configured exclude_paths")
            result = scanner.scan(root)
            result.make_portable(root)
            if name == "shadowscan":
                source_report_digest = result.source_report_digest
                source_report_content_digest = result.source_report_content_digest
                source_report_content_profile = result.source_report_content_profile
                source_report_path = result.source_report_path
                source_report_format = result.source_report_format
                source_report_status = result.source_report_status
                source_projection_limitations = result.source_projection_limitations
                source_unmapped_count = result.source_unmapped_count
                source_unmapped_indexes = result.source_unmapped_indexes
                discovery_verification = result.discovery_verification
            _merge_scan_result(name, result, aibom, collected, scan_failures)
            surfaces_scanned.extend(result.surfaces_scanned)
            surfaces_excluded.extend(result.surfaces_excluded)
            accepted_default_exclusions.update(result.accepted_default_exclusions)
            accepted_default_names.update(result.accepted_default_names)
            scan_failures.extend(result.scan_failures)
            failures_by[name] = scan_failures[failure_count:]
            excluded_by[name] = list(result.surfaces_excluded)
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
            state = "" if scanner_status[name] == "complete" else f" ({scanner_status[name]})"
            click.echo(f"    Found {len(result.components)} components{state}", err=True)
        except Exception as exc:
            summary = _scanner_error_summary(exc)
            echo_line("  Scanner '", name, "' failed: ", summary, err=True)
            if _debug_enabled():
                _print_traceback(exc)
            scan_failures.append(f"{name}: {summary}")
            failures_by[name] = scan_failures[failure_count:]
            scanner_status[name] = "failed"
    failure_count, exclusion_count = len(scan_failures), len(surfaces_excluded)
    try:
        # Manifest problems are recorded like collector failures; the inventory is still written.
        assemble_repository_agent(
            aibom,
            root,
            exclude_paths=policy.scan.exclude_paths,
            failures=scan_failures,
            exclusions=surfaces_excluded,
            surfaces=surfaces_scanned,
        )
    except (PolicyError, ValueError, OSError) as exc:
        raise _failure(exc) from exc
    if len(scan_failures) > failure_count:
        failures_by[MANIFEST] = scan_failures[failure_count:]
    if len(surfaces_excluded) > exclusion_count:
        excluded_by[MANIFEST] = surfaces_excluded[exclusion_count:]
    tp_failure_count, tp_exclusion_count = len(scan_failures), len(surfaces_excluded)
    apply_text_poisoning_rules(
        aibom,
        root,
        exclude_paths=policy.scan.exclude_paths,
        failures=scan_failures,
        exclusions=surfaces_excluded,
        surfaces=surfaces_scanned,
    )
    if len(scan_failures) > tp_failure_count:
        failures_by["text_poisoning"] = scan_failures[tp_failure_count:]
    if len(surfaces_excluded) > tp_exclusion_count:
        excluded_by["text_poisoning"] = surfaces_excluded[tp_exclusion_count:]
    graph_failures = validate_graph(aibom)
    scan_failures.extend(graph_failures)
    if graph_failures:
        failures_by["graph"] = graph_failures
    if advisory_db is not None:
        from nexus_symbiote.scan_advisories import attach_offline_advisories

        advisory_failures = attach_offline_advisories(aibom, advisory_db, root)
        if advisory_failures:
            scan_failures.extend(advisory_failures)
            failures_by["advisories"] = advisory_failures
        else:
            surfaces_scanned.append(f"advisories: offline OSV bundle {advisory_db.name}")
    aibom.metadata.completeness = CompletenessClaim(
        scope="repository+shadowscan" if source_report_digest else "repository",
        source_report_digest=source_report_digest,
        source_report_content_digest=source_report_content_digest,
        source_report_content_profile=source_report_content_profile,
        source_report_path=source_report_path,
        discovery_verification=(
            discovery_verification
            if discovery_verification is not None
            else DiscoveryVerification(status="not-applicable", method="none")
        ),
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
            {
                *policy.scan.exclude_paths,
                *(f"**/{name}" for name in DEFAULT_EXCLUDES),
                *accepted_default_exclusions,
            }
        ),
        unobserved_surfaces=[
            *(f"accepted default exclusion: {name}" for name in sorted(accepted_default_names)),
            *(
                f"accepted default exclusion path: {path}"
                for path in sorted(accepted_default_exclusions)
            ),
            "runtime",
            "effective-identity",
            "effective-authorization",
            "live-tools",
            "network",
        ],
    )
    discovery_failures: list[str] = []
    if check_only:
        from nexus_symbiote.validators.completeness import (
            carries_discovery_evidence,
            discovery_producer_check,
            discovery_signature_required,
        )

        producer_verified = False
        if discovery_signature_required(
            policy.validation.require_discovery_signature, root, signature_policies
        ):
            prod_status, prod_problems = discovery_producer_check(
                aibom, root, signature_policies, exclude_paths=policy.scan.exclude_paths
            )
            producer_verified = prod_status == "verified" and not prod_problems
            if prod_problems:
                for problem in prod_problems:
                    scan_failures.append(f"shadowscan: {problem}")
                discovery_failures.extend(prod_problems)
        if carries_discovery_evidence(aibom):
            unsigned_reason = _unsigned_discovery_failure_reason(
                aibom,
                fail_on_unsigned_discovery=(
                    policy.validation.require_discovery_signature or fail_on_unsigned_discovery
                ),
                allow_unsigned_discovery=allow_unsigned_discovery,
                already_verified=producer_verified,
            )
            if unsigned_reason is not None:
                scan_failures.append(f"shadowscan: {unsigned_reason}")
                discovery_failures.append(unsigned_reason)

    scorer = RiskScorer.from_policy(policy.risk)
    passed, risk_report = scorer.passes_gate(aibom)
    # Report-only (flag or project policy) relaxes collection and findings only; it
    # must not cancel the separate discovery-verification gate the operator relies on.
    report_requested = report_only or policy.scan.failure_mode == "report-only"
    report_mode = report_requested and not discovery_failures
    staged = _staged_inventory()
    # Baseline promotion must use exactly what the scanner read from disk.
    staged_policy = (root, policy, signature_policies) if staged else None

    if not check_only:
        if source_report_digest and output_format == "sarif":
            raise click.ClickException(
                "SARIF cannot preserve imported discovery coverage; use native JSON, CycloneDX "
                "or SPDX."
            )
        try:
            out_data = _render_aibom(
                aibom,
                output_format,
                root,
                operator_policy_digest=op_digest,
                operator_policy_signers=op_signers,
            )
        except ContentSerialError as exc:
            raise click.ClickException(str(exc)) from exc
        except (ValueError, RecursionError) as exc:
            # Export checks quote inventory values; name the format, never the values.
            if _debug_enabled():
                _print_traceback(exc)
            raise click.ClickException(
                f"The inventory cannot be exported as {output_format}: the export failed its "
                "schema or consistency checks. Write native JSON to inspect the inventory, or "
                "rerun with --debug before the command for details."
            ) from exc
        if output:
            write_cli_output(Path(output), out_data)
            if not staged:
                echo_line("Saved ", output, err=True)
        else:
            click.echo(json_text(out_data))

    if risk_report.warning_threshold_exceeded:
        click.echo(f"Risk warning: score {risk_report.overall_score:.1f}", err=True)
    if not scan_failures and passed:
        print_lines([("Scan gate passed", "green")], err=True)
        if op_digest is not None:
            echo_line("  Policy: ", policy_source, err=True)
        return staged_policy
    if report_mode:
        heading = "Scan gate failed (report only: exit status 0)"
    elif report_requested:
        heading = "Scan gate failed (report-only does not cover unverified discovery evidence)"
    else:
        heading = "Scan gate failed"
    document = {
        **risk_report.to_dict(),
        "fail_on_severity": scorer.fail_on_severity,
        "score_threshold": scorer.fail_threshold,
    }
    not_collected = sorted(set(all_scanners) - set(selected))
    gate = scan_gate_lines(
        document,
        failures_by,
        excluded_by,
        not_collected,
        recorded=not (check_only or staged),
        discovery=discovery_failures,
    )
    print_lines([(heading, "yellow" if report_mode else "red"), *gate], err=True)
    if op_digest is not None:
        echo_line("  Policy: ", policy_source, err=True)
    if not report_mode:
        _gate_exit(detailed, collection_failed=bool(scan_failures))
    return staged_policy


@main.command("import-shadowscan")
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
@click.option(
    "--report-only",
    is_flag=True,
    help=(
        "Emit imported claims without failing on incomplete coverage. Unverified discovery "
        "evidence still fails in CI unless --allow-unsigned-discovery is given."
    ),
)
@click.option(
    "--bundle",
    type=click.Path(exists=True, dir_okay=False),
    help="Verify the report producer's Sigstore bundle over the exact report bytes.",
)
@click.option("--signer-identity", help="Expected report signer, with --bundle and --issuer.")
@click.option("--issuer", help="Expected OIDC issuer, with --bundle and --signer-identity.")
@click.option(
    "--fail-on-unsigned-discovery",
    is_flag=True,
    help="Exit with status 1 when the imported discovery evidence is unverified.",
)
@click.option(
    "--allow-unsigned-discovery",
    is_flag=True,
    help="Accept unverified discovery evidence explicitly (still warns); required in CI.",
)
def import_shadowscan(
    report_path: str,
    output: str,
    output_format: str,
    report_only: bool = False,
    bundle: str | None = None,
    signer_identity: str | None = None,
    issuer: str | None = None,
    fail_on_unsigned_discovery: bool = False,
    allow_unsigned_discovery: bool = False,
) -> None:
    """Import a Nexus-ShadowScan report and generate an AIBOM of imported claims.

    This is the recommended primary workflow: run ShadowScan for discovery,
    then Nexus SymBiote for verification, integrity, and BOM emission.

    Without --bundle the import records the discovery evidence as unverified
    in the BOM. In CI that fails unless --allow-unsigned-discovery is given;
    interactively it warns. Pass --bundle with the expected signer identity
    and issuer to record the evidence as verified instead.
    """
    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter, verify_discovery_report
    from nexus_symbiote.utils.crypto import SIGSTORE_MISSING

    _unsigned_discovery_flags(fail_on_unsigned_discovery, allow_unsigned_discovery)

    if any(x is not None for x in (bundle, signer_identity, issuer)) and not all(
        (bundle, signer_identity, issuer)
    ):
        raise click.UsageError("--bundle, --signer-identity and --issuer must be supplied together")

    collected_at = source_date_epoch()
    importer = ShadowScanImporter()
    try:
        imported = importer.read_report(Path(report_path))
    except (ValueError, TypeError, OSError, UnicodeError, RecursionError) as exc:
        raise click.ClickException("Failed to safely import the ShadowScan report") from exc
    if bundle and signer_identity and issuer:
        try:
            bundle_bytes = read_regular_text(Path(bundle)).encode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise click.ClickException("Cannot safely read the Sigstore bundle") from exc
        record = imported.discovery_verification
        if record is None:
            raise click.ClickException("Failed to safely import the ShadowScan report")
        try:
            imported = imported.with_verification(
                verify_discovery_report(record, bundle_bytes, signer_identity, issuer)
            )
        except ValueError as exc:
            if str(exc) == SIGSTORE_MISSING:
                raise click.ClickException(SIGSTORE_MISSING) from exc
            raise click.ClickException(
                "ShadowScan report signature or signer policy verification failed"
            ) from exc

    aibom = imported.to_native_bom()
    aibom.metadata.timestamp = collected_at

    if output_format == "sarif":
        raise click.ClickException(
            "SARIF cannot preserve imported discovery coverage; use native JSON, CycloneDX or SPDX."
        )
    try:
        prepare(aibom)
    except ContentSerialError as exc:
        raise click.ClickException(str(exc)) from exc
    if output_format == "cyclonedx":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

        out_data = CycloneDXGenerator().generate_json(aibom)
    elif output_format == "spdx":
        from nexus_symbiote.generators.spdx import SPDXGenerator

        out_data = SPDXGenerator().generate_json(aibom)
    else:
        try:
            out_data = aibom.to_native_json()
        except NativeFormatError as exc:
            raise click.ClickException(f"Inventory not written. {exc}") from exc

    unsigned_reason = _unsigned_discovery_failure_reason(
        aibom,
        fail_on_unsigned_discovery=fail_on_unsigned_discovery,
        allow_unsigned_discovery=allow_unsigned_discovery,
        already_verified=bool(bundle),
    )
    if unsigned_reason is not None:
        raise click.exceptions.Exit(1)

    refuse_dash_output(output)
    try:
        write_output_file(Path(output), out_data, overwrite=False)
    except FileExistsError as exc:
        raise click.ClickException("Cannot create output; choose a new output path") from exc
    except (OSError, ValueError) as exc:
        raise output_failure(exc) from exc
    echo_line(
        "Imported ",
        len(imported.components),
        " components and saved ",
        output,
        "; discovery coverage remains partial.",
        err=True,
    )
    if report_only:
        return
    if imported.source_status != "complete":
        raise click.ClickException("ShadowScan source report is incomplete; the BOM is partial")
    raise click.ClickException("Imported claims do not establish complete verified coverage")


def _check_unpinned_trust_root(
    trust_root: str | None,
    trust_root_sha256: str | None,
    untrusted_inputs: tuple[Path, ...],
) -> None:
    """Refuse an unpinned Sigstore trust root located inside an untrusted checkout or git tree."""
    if trust_root is None or trust_root_sha256 is not None:
        return
    from nexus_symbiote.runtime_cli import _verify_outside_checkout

    raw_path = Path(trust_root)
    target = (
        raw_path / "trusted_root.json"
        if raw_path.is_dir() and os.path.lexists(raw_path / "trusted_root.json")
        else raw_path
    )
    if target.is_dir():
        resolved = target.resolve()
        for inp in (*untrusted_inputs, Path.cwd()):
            base = inp.resolve()
            root_dir = base if base.is_dir() else base.parent
            for candidate in (root_dir, *root_dir.parents):
                if (candidate == root_dir and base.is_dir()) or os.path.lexists(candidate / ".git"):
                    if resolved == candidate or resolved.is_relative_to(candidate):
                        raise click.UsageError(
                            "--trust-root must lie outside the target checkout and every git "
                            "working tree that holds the checkout or the current directory"
                        )
        return
    _verify_outside_checkout(target, untrusted_inputs, label="--trust-root")


@main.command("verify-artifact")
@click.argument("artifact_path")
@click.option(
    "--project",
    required=True,
    type=click.Path(exists=True, file_okay=False),
    help="Trusted project root; ARTIFACT_PATH is relative to it",
)
@click.option(
    "--sha256", "expected_digest", required=True, help="Expected sha256:<hex> from a trusted source"
)
@click.option(
    "--bundle", type=click.Path(exists=True, dir_okay=False), help="Optional Sigstore bundle"
)
@click.option("--signer-identity", help="Expected Sigstore signing identity")
@click.option("--issuer", help="Expected Sigstore OIDC issuer")
@click.option(
    "--trust-root",
    type=click.Path(exists=True, dir_okay=True, file_okay=True),
    help="Explicit Sigstore trusted_root.json file (or directory holding one); "
    "overrides NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT and the user cache.",
)
@click.option(
    "--trust-root-sha256",
    help="Pinned SHA-256 (sha256:<hex>) the explicit trust root must match.",
)
@click.option(
    "--oms-dsse",
    is_flag=True,
    help="Verify an OpenSSF Model Signing DSSE in-toto Statement/v1 Sigstore bundle.",
)
@click.option(
    "--rekor-root-hash",
    help="Operator-witnessed Rekor checkpoint root hash (sha256:<hex>) that the bundle inclusion proof must match.",
)
@click.option(
    "--minimum-rekor-tree-size",
    type=click.IntRange(min=1),
    help="Minimum Rekor transparency log tree size required in the bundle checkpoint.",
)
def verify_artifact(
    artifact_path: str,
    project: str,
    expected_digest: str,
    bundle: str | None,
    signer_identity: str | None,
    issuer: str | None,
    trust_root: str | None,
    trust_root_sha256: str | None,
    oms_dsse: bool = False,
    rekor_root_hash: str | None = None,
    minimum_rekor_tree_size: int | None = None,
) -> None:
    """Verify a local artifact's digest and optionally its Sigstore bundle."""
    import hmac

    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.utils.confined import hash_confined_file
    from nexus_symbiote.utils.crypto import SIGSTORE_MISSING, verify_sigstore_digest

    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
        raise click.BadParameter(
            "Expected SHA-256 must be sha256:<64 lowercase hexadecimal characters>",
            param_hint="'--sha256'",
        )
    if bool(bundle) != bool(signer_identity and issuer) or (
        not bundle and (signer_identity or issuer)
    ):
        raise click.UsageError("--bundle, --signer-identity and --issuer must be supplied together")
    if not bundle and (
        trust_root or trust_root_sha256 or oms_dsse or rekor_root_hash or minimum_rekor_tree_size
    ):
        raise click.UsageError(
            "--trust-root, --trust-root-sha256, --oms-dsse, --rekor-root-hash and "
            "--minimum-rekor-tree-size require --bundle"
        )
    try:
        digest = hash_confined_file(_project_root(project, label="--project"), artifact_path)
    except OSError as exc:
        raise click.ClickException(
            "Cannot safely hash the artifact within the project root"
        ) from exc
    if not hmac.compare_digest(digest, expected_digest):
        raise click.ClickException("Artifact digest mismatch")
    if bundle:
        _check_unpinned_trust_root(trust_root, trust_root_sha256, (Path(project), Path(bundle)))
        try:
            bundle_bytes = read_regular_text(Path(bundle)).encode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise click.ClickException("Cannot safely read the Sigstore bundle") from exc
        if signer_identity is None or issuer is None:
            raise click.UsageError(
                "--bundle, --signer-identity and --issuer must be supplied together"
            )
        extra_kwargs: dict[str, Any] = {}
        if oms_dsse or rekor_root_hash is not None or minimum_rekor_tree_size is not None:
            extra_kwargs = {
                "allow_oms_dsse": oms_dsse,
                "rekor_root_hash": rekor_root_hash,
                "minimum_rekor_tree_size": minimum_rekor_tree_size,
                **({"artifact_name": artifact_path} if oms_dsse else {}),
            }
        verified = verify_sigstore_digest(
            digest,
            bundle_bytes,
            signer_identity,
            issuer,
            trust_root=trust_root,
            trust_root_sha256=trust_root_sha256,
            **extra_kwargs,
        )
        if not verified.verified:
            if verified.error == SIGSTORE_MISSING:
                raise click.ClickException(SIGSTORE_MISSING)
            raise click.ClickException(
                "Sigstore signature or signer policy verification failed"
                + (f": {verified.error}" if verified.error else "")
            )
        trust_root_path = (verified.details or {}).get("trust_root_path", "unavailable")
        echo_line(
            "Artifact digest and Sigstore signer policy verified. Trust root: ",
            trust_root_path,
            ". This does not establish artifact safety or a deployment binding.",
        )
    else:
        click.echo(
            "Artifact bytes match the expected digest. Signer, artifact safety, and deployment binding were not verified."
        )


@main.command("verify-discovery")
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
@click.option(
    "--trust-root",
    type=click.Path(exists=True, dir_okay=True, file_okay=True),
    help="Explicit Sigstore trusted_root.json file (or directory holding one); "
    "overrides NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT and the user cache.",
)
@click.option(
    "--trust-root-sha256",
    help="Pinned SHA-256 (sha256:<hex>) the explicit trust root must match.",
)
def verify_discovery(
    aibom_path: str,
    report_path: str,
    projection: bool,
    bundle: str | None,
    signer_identity: str | None,
    issuer: str | None,
    trust_root: str | None,
    trust_root_sha256: str | None,
) -> None:
    """Verify source bytes and optionally their native projection and producer."""
    import hashlib
    import hmac

    from nexus_symbiote.core.hashing import parse_json_strict
    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.scanners.shadowscan import MAX_REPORT_BYTES, ShadowScanImporter
    from nexus_symbiote.utils.crypto import SIGSTORE_MISSING, verify_sigstore_digest

    if any(x is not None for x in (bundle, signer_identity, issuer)) and not all(
        (bundle, signer_identity, issuer)
    ):
        raise click.UsageError("--bundle, --signer-identity and --issuer must be supplied together")
    if not bundle and (trust_root or trust_root_sha256):
        raise click.UsageError("--trust-root and --trust-root-sha256 require --bundle")
    if bundle:
        _check_unpinned_trust_root(
            trust_root,
            trust_root_sha256,
            (Path(aibom_path), Path(report_path), Path(bundle)),
        )
    try:
        doc = parse_json_strict(
            read_regular_text(Path(aibom_path), max_bytes=MAX_REPORT_BYTES),
            max_bytes=MAX_REPORT_BYTES,
        )
        bom = AIBOM.from_document(doc)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise click.ClickException(f"Cannot safely read the BOM: {_input_problem(exc)}") from exc
    try:
        text = read_regular_text(Path(report_path), max_bytes=MAX_REPORT_BYTES)
    except (OSError, ValueError, UnicodeError) as exc:
        raise click.ClickException(
            f"Cannot safely read the discovery report: {_input_problem(exc)}"
        ) from exc
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
            # The serial is derived from content on each run and no import
            # time is stamped any more. Everything else, including unknown
            # fields in the original JSON, must match. The import-time
            # source path is likewise local to the import, not to the
            # report bytes.
            for field in ("timestamp", "serial_number"):
                projected["metadata"].pop(field, None)
            if not isinstance(doc["metadata"].pop("serial_number", None), str):
                raise ValueError("missing generated metadata")
            doc["metadata"].pop("timestamp", None)
            stored = doc.get("metadata", {}).get("completeness")
            recorded = isinstance(stored, dict) and "discovery_verification" in stored
            for document in (projected, doc):
                completeness = document.get("metadata", {}).get("completeness")
                if isinstance(completeness, dict):
                    completeness.pop("source_report_path", None)
                    if not recorded:
                        # A BOM imported before the record existed has none to compare.
                        completeness.pop("discovery_verification", None)
                    if bundle:
                        # A bundle check re-verifies the producer now, so the
                        # import-time outcome is not part of the projection
                        # that must reproduce. Without a bundle it still is:
                        # a BOM claiming verified must not pass on an
                        # unverified re-projection.
                        verification = completeness.get("discovery_verification")
                        if isinstance(verification, dict):
                            for key in ("status", "method", "signer_identity", "issuer"):
                                verification.pop(key, None)
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
        verified = verify_sigstore_digest(
            actual,
            bundle_bytes,
            signer_identity,
            issuer,
            trust_root=trust_root,
            trust_root_sha256=trust_root_sha256,
        )
        if not verified.verified:
            if verified.error == SIGSTORE_MISSING:
                raise click.ClickException(SIGSTORE_MISSING)
            raise click.ClickException(
                "ShadowScan report signature or signer policy verification failed"
                + (f": {verified.error}" if verified.error else "")
            )
        trust_root_path = (verified.details or {}).get("trust_root_path", "unavailable")
        echo_line(
            "Report signer and direct native projection verified. Trust root: ",
            trust_root_path,
            ". Discovery claims retain declared assurance.",
        )
    elif projection:
        click.echo(
            "Report bytes and direct native projection match. Producer identity is unverified."
        )
    else:
        click.echo(
            "Report bytes match the recorded digest. Source identity, signature, and truth were not verified."
        )


def _attestation_gate_options(command: Any) -> Any:
    for option in reversed(
        (
            click.option(
                "--require-attestation",
                "attestation_envelope",
                type=click.Path(dir_okay=False, path_type=Path),
                default=None,
                help=(
                    "Require a verified inventory attestation DSSE envelope for AIBOM_PATH; "
                    "requires at least one --trusted-key."
                ),
            ),
            click.option(
                "--trusted-key",
                "trusted_keys",
                multiple=True,
                type=click.Path(dir_okay=False, path_type=Path),
                help=(
                    "Trusted Ed25519 public key PEM for --require-attestation; repeat to build "
                    "the ring. Must lie outside every git working tree holding AIBOM_PATH, the "
                    "envelope, --project or the current directory."
                ),
            ),
            click.option(
                "--attestation-purpose",
                type=click.Choice(["generated", "reviewed"]),
                default=None,
                help="Purpose the attestation must have been signed for (default: reviewed).",
            ),
            click.option(
                "--attestation-threshold",
                type=click.IntRange(min=1, max=32),
                default=None,
                help="Minimum number of distinct trusted keys that must have signed (default: 1).",
            ),
            click.option(
                "--attestation-match",
                type=click.Choice(["bytes", "content"]),
                default=None,
                help="bytes (default): AIBOM_PATH is the attested file; content: same inventory content digest.",
            ),
            click.option(
                "--attestation-max-age-days",
                type=click.IntRange(min=1, max=36500),
                default=None,
                help="Refuse an attestation signed more than this many days ago.",
            ),
        )
    ):
        command = option(command)
    return command


def _resolve_attestation_gate_options(
    attestation_envelope: Path | None,
    trusted_keys: tuple[Path, ...],
    attestation_purpose: str | None,
    attestation_threshold: int | None,
    attestation_match: str | None,
    attestation_max_age_days: int | None,
) -> tuple[str, int, str, int | None]:
    if attestation_envelope is None:
        for flag, supplied in (
            ("--trusted-key", bool(trusted_keys)),
            ("--attestation-purpose", attestation_purpose is not None),
            ("--attestation-threshold", attestation_threshold is not None),
            ("--attestation-match", attestation_match is not None),
            ("--attestation-max-age-days", attestation_max_age_days is not None),
        ):
            if supplied:
                raise click.UsageError(f"{flag} requires --require-attestation")
    elif not trusted_keys:
        raise click.UsageError("--require-attestation requires at least one --trusted-key")
    return (
        "reviewed" if attestation_purpose is None else attestation_purpose,
        1 if attestation_threshold is None else attestation_threshold,
        "bytes" if attestation_match is None else attestation_match,
        attestation_max_age_days,
    )


_ATTESTATION_COLLECTION_REASONS = frozenset({"key-invalid", "input-too-large", "input-unreadable"})


def _raise_on_misplaced_attestation_key(attestation_report: Mapping[str, object]) -> None:
    if attestation_report.get("verified"):
        return
    detail = str(attestation_report.get("detail", ""))
    if attestation_report.get("reason") == "key-invalid" and (
        "must lie outside" in detail or "hard links" in detail or "cannot be inspected" in detail
    ):
        raise click.UsageError(detail)


def _attestation_collection_failed(attestation_report: Mapping[str, object] | None) -> bool:
    return (
        attestation_report is not None
        and not attestation_report.get("verified")
        and attestation_report.get("reason") in _ATTESTATION_COLLECTION_REASONS
    )


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--project",
    type=click.Path(exists=True, file_okay=False),
    help="Project root for cross-validation; the only source of a project policy",
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit operator signer policy JSON; requires --project",
)
@_operator_policy_options
@click.option(
    "--no-project-policy",
    is_flag=True,
    help="Use built-in policy without reading configuration from the target.",
)
@click.option(
    "--accept-project-policy",
    is_flag=True,
    help=_ACCEPT_PROJECT_POLICY_HELP,
)
@click.option(
    "--accept-default-exclude",
    type=click.Choice(sorted(DEFAULT_EXCLUDE_ACCEPTANCE)),
    multiple=True,
    help="Accept one default exclusion while retaining the path in the inventory. Repeat as needed.",
)
@click.option(
    "--accept-default-excludes",
    is_flag=True,
    help=(
        "Do not record a coverage gap for a non-empty default-excluded name (.git, "
        "node_modules, __pycache__, .venv, venv) when reconciling the project. Without "
        "this flag such an entry makes the local collection partial."
    ),
)
@click.option(
    "--skip-integrity",
    is_flag=True,
    help=(
        "Check completeness only and report integrity as skipped, for a repository whose "
        "models cannot be signed yet. The skip is printed and recorded in --json-output."
    ),
)
@click.option("--json-output", is_flag=True, help="Print the validation report as JSON.")
@_gate_report_options
@click.option(
    "--require-discovery-signature",
    is_flag=True,
    help=(
        "Require the operator signature policy to verify any ShadowScan report the inventory "
        "records or the project contains, whatever the project policy says; requires --project."
    ),
)
@click.option(
    "--fail-on-unsigned-discovery",
    is_flag=True,
    help="Exit with status 1 when the BOM's ShadowScan evidence is unverified.",
)
@click.option(
    "--allow-unsigned-discovery",
    is_flag=True,
    help="Accept unverified discovery evidence explicitly (still warns); required in CI.",
)
@_attestation_gate_options
@_exit_code_options
def validate(
    aibom_path: str,
    project: str | None,
    signature_policy: Path | None = None,
    operator_policy: Path | None = None,
    operator_policy_attestation: Path | None = None,
    operator_policy_key: tuple[Path, ...] = (),
    allow_unsigned_operator_policy: bool = False,
    operator_policy_max_age_days: int = 90,
    no_project_policy: bool = False,
    accept_project_policy: bool = False,
    accept_default_excludes: bool = False,
    accept_default_exclude: tuple[str, ...] = (),
    skip_integrity: bool = False,
    json_output: bool = False,
    report_format: str | None = None,
    step_summary: Path | None = None,
    require_discovery_signature: bool = False,
    fail_on_unsigned_discovery: bool = False,
    allow_unsigned_discovery: bool = False,
    attestation_envelope: Path | None = None,
    trusted_keys: tuple[Path, ...] = (),
    attestation_purpose: str | None = None,
    attestation_threshold: int | None = None,
    attestation_match: str | None = None,
    attestation_max_age_days: int | None = None,
    detailed_exit_codes: bool = False,
    legacy_exit_codes: bool = False,
) -> None:
    """Validate an AIBOM for completeness and integrity.

    Without --project only the inventory's own claims are checked: its coverage claim
    and its self-consistency. With --project the inventory is compared with a fresh
    local collection of that project, unless the policy skips the completeness check.
    """
    detailed = _apply_exit_code_flags(detailed_exit_codes, legacy_exit_codes)
    effective_format = _resolve_report_format(json_output, report_format)
    _unsigned_discovery_flags(fail_on_unsigned_discovery, allow_unsigned_discovery)
    if require_discovery_signature and not project:
        raise click.BadParameter(
            "--require-discovery-signature requires --project",
            param_hint="--require-discovery-signature",
        )
    resolved_purpose, resolved_threshold, resolved_match, resolved_max_age = (
        _resolve_attestation_gate_options(
            attestation_envelope,
            trusted_keys,
            attestation_purpose,
            attestation_threshold,
            attestation_match,
            attestation_max_age_days,
        )
    )
    bom, raw_bom_bytes = _load_bom_with_bytes(aibom_path)

    from nexus_symbiote.attestation_cli import verify_gate_attestation
    from nexus_symbiote.validators.completeness import (
        CompletenessValidator,
        assurance_problems,
        carries_discovery_evidence,
        discovery_producer_check,
        discovery_signature_required,
    )
    from nexus_symbiote.validators.integrity import IntegrityValidator

    root = _project_root(project, label="--project") if project else None
    if root is not None:
        _require_binding_key()
    signature_policies = _signer_policies(signature_policy, root)
    op_policy, op_digest, op_signers = _resolve_operator_policy(
        operator_policy,
        root,
        attestation_path=operator_policy_attestation,
        trusted_keys=operator_policy_key,
        allow_unsigned=allow_unsigned_operator_policy,
        max_age_days=operator_policy_max_age_days,
    )
    policy, policy_source, policy_weakened, policy_unapplied = _inventory_policy(
        root,
        aibom_path,
        ignore_project=no_project_policy,
        warn=(effective_format == "text"),
        allow_weakening=accept_project_policy,
        operator=op_policy,
        operator_digest=op_digest,
        operator_signers=op_signers,
    )
    minimum = policy.validation.minimum_assurance_level
    if minimum == "verified":
        raise click.ClickException(
            "offline validate cannot establish verified assurance; use subject-bound cryptographic verification"
        )
    passed = True
    # Only the reconciliation below may claim that the inventory was compared with the project.
    basis = "project-not-reconciled" if root is not None else "supplied-bom"
    bound_imports: frozenset[str] = frozenset()
    supplier_observed: frozenset[str] = frozenset()
    completeness: dict[str, Any] = {"status": "skipped", "skipped_by": "policy"}
    if policy.validation.require_completeness:
        cv = CompletenessValidator()
        c_report = (
            cv.validate_against_project(
                bom,
                root,
                exclude_paths=policy.scan.exclude_paths,
                signature_policies=signature_policies,
                accept_default_excludes=accept_default_excludes or accept_default_exclude,
            )
            if root is not None
            else cv.validate(bom)
        )
        completeness = {"status": "pass" if c_report.is_complete else "fail", **c_report.to_dict()}
        bound_imports = c_report.bound_imports
        supplier_observed = c_report.supplier_observed
        if root is not None:
            # The risk command's vocabulary: reconciled, with supplier claims, or failed.
            basis = c_report.basis
        passed = passed and c_report.is_complete
    integrity: dict[str, Any] = {"status": "skipped", "skipped_by": "--skip-integrity"}
    if not skip_integrity:
        if policy.validation.require_integrity:
            i_report = IntegrityValidator(signature_policies=signature_policies).validate(
                bom, root, exclude_paths=policy.scan.exclude_paths, bound_imports=bound_imports
            )
            integrity = i_report.to_dict()
            passed = passed and i_report.is_valid
        else:
            integrity = {"status": "skipped", "skipped_by": "policy"}
    attestation_report: dict[str, object] | None = None
    if attestation_envelope is not None:
        attestation_report = verify_gate_attestation(
            Path(aibom_path),
            attestation_envelope,
            trusted_keys=trusted_keys,
            purpose=resolved_purpose,
            threshold=resolved_threshold,
            match=resolved_match,
            max_age_days=resolved_max_age,
            project=root,
            subject_bytes=raw_bom_bytes,
        )
        _raise_on_misplaced_attestation_key(attestation_report)
        passed = passed and bool(attestation_report["verified"])
    discovery: dict[str, Any] | None = None
    if root is not None and discovery_signature_required(
        policy.validation.require_discovery_signature or require_discovery_signature,
        root,
        signature_policies,
    ):
        status, problems = discovery_producer_check(
            bom, root, signature_policies, exclude_paths=policy.scan.exclude_paths
        )
        discovery = {"status": status, "problems": problems}
        passed = passed and not problems
    elif root is None and _discovery_signature_unverifiable(policy, bom):
        discovery = {"status": "failed", "problems": [DISCOVERY_SIGNATURE_NEEDS_PROJECT]}
        passed = False
    elif carries_discovery_evidence(bom):
        discovery = {"status": "not-verified", "problems": []}
    producer_verified = discovery is not None and discovery["status"] == "verified"
    unsigned_reason = _unsigned_discovery_failure_reason(
        bom,
        fail_on_unsigned_discovery=fail_on_unsigned_discovery,
        allow_unsigned_discovery=allow_unsigned_discovery,
        already_verified=producer_verified,
    )
    passed = passed and unsigned_reason is None
    assurance_errors = assurance_problems(
        bom, minimum, imported_claims=bound_imports, supplier_observed=supplier_observed
    )
    # Graph integrity is structural and cannot be disabled by a coverage policy.
    graph_issues = validate_graph(bom)
    passed = passed and not assurance_errors and not graph_issues
    document: dict[str, Any] = {
        "passed": passed,
        "verification_mode": "static-offline",
        "assessment_basis": basis,
        "policy_source": policy_source,
        "policy_weakened": policy_weakened,
        "completeness": completeness,
        "integrity": integrity,
        **({"attestation": attestation_report} if attestation_report is not None else {}),
        "discovery_producer": discovery,
        "unsigned_discovery": unsigned_reason,
        "minimum_assurance_level": minimum,
        "assurance_errors": assurance_errors,
        "graph_issues": graph_issues,
    }
    if policy_unapplied is not None:
        document["policy_unapplied"] = policy_unapplied
    if op_digest is not None:
        document["operator_policy_digest"] = op_digest
        document["operator_policy_signers"] = list(op_signers)
        document["clamped_project_settings"] = list(_LAST_CLAMPED_SETTINGS.get())
    _emit_gate_report(
        "validate",
        effective_format,
        document,
        lambda: validation_report_lines(document, project=root),
        step_summary=step_summary,
        project=root,
        operator_source=policy_source if op_digest is not None else None,
    )
    if not passed:
        _gate_exit(detailed, collection_failed=_attestation_collection_failed(attestation_report))


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--threshold",
    type=float,
    default=None,
    help="Fail when the aggregate score reaches this positive value (default: from policy, built-in 50).",
)
@click.option(
    "--no-score-threshold",
    is_flag=True,
    help=(
        "Do not gate on the aggregate score. Findings at or above --fail-on-severity, "
        "unverified SafeTensors, incomplete coverage and missing evidence still fail the gate."
    ),
)
@click.option("--json-output", is_flag=True, help="Output as JSON")
@_gate_report_options
@click.option(
    "--project",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help=(
        "Reconcile the supplied BOM against this project's static evidence before scoring; "
        "the only source of a project policy."
    ),
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Explicit operator signer policy for model recollection; requires --project.",
)
@_operator_policy_options
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
@click.option(
    "--accept-project-policy",
    is_flag=True,
    help=_ACCEPT_PROJECT_POLICY_HELP,
)
@click.option(
    "--accept-default-exclude",
    type=click.Choice(sorted(DEFAULT_EXCLUDE_ACCEPTANCE)),
    multiple=True,
    help="Accept one default exclusion while retaining the path in the inventory. Repeat as needed.",
)
@click.option(
    "--accept-default-excludes",
    is_flag=True,
    help=(
        "Do not record a coverage gap for a non-empty default-excluded name (.git, "
        "node_modules, __pycache__, .venv, venv) when reconciling the project. Without "
        "this flag such an entry makes the local collection partial."
    ),
)
@click.option(
    "--require-discovery-signature",
    is_flag=True,
    help=(
        "Require the operator signature policy to verify any ShadowScan report the inventory "
        "records or the project contains, whatever the project policy says; requires --project."
    ),
)
@click.option(
    "--fail-on-unsigned-discovery",
    is_flag=True,
    help="Exit with status 1 when the BOM's ShadowScan evidence is unverified.",
)
@click.option(
    "--allow-unsigned-discovery",
    is_flag=True,
    help="Accept unverified discovery evidence explicitly (still warns); required in CI.",
)
@_attestation_gate_options
@_exit_code_options
def risk(
    aibom_path: str,
    threshold: float | None,
    json_output: bool,
    fail_on_severity: str | None,
    report_format: str | None = None,
    step_summary: Path | None = None,
    operator_policy: Path | None = None,
    operator_policy_attestation: Path | None = None,
    operator_policy_key: tuple[Path, ...] = (),
    allow_unsigned_operator_policy: bool = False,
    operator_policy_max_age_days: int = 90,
    no_project_policy: bool = False,
    accept_project_policy: bool = False,
    accept_default_excludes: bool = False,
    accept_default_exclude: tuple[str, ...] = (),
    fail_on_unsigned_discovery: bool = False,
    allow_unsigned_discovery: bool = False,
    project: Path | None = None,
    signature_policy: Path | None = None,
    no_score_threshold: bool = False,
    require_discovery_signature: bool = False,
    attestation_envelope: Path | None = None,
    trusted_keys: tuple[Path, ...] = (),
    attestation_purpose: str | None = None,
    attestation_threshold: int | None = None,
    attestation_match: str | None = None,
    attestation_max_age_days: int | None = None,
    detailed_exit_codes: bool = False,
    legacy_exit_codes: bool = False,
) -> None:
    """Score supply-chain risks in an AIBOM."""
    detailed = _apply_exit_code_flags(detailed_exit_codes, legacy_exit_codes)
    effective_format = _resolve_report_format(json_output, report_format)
    _unsigned_discovery_flags(fail_on_unsigned_discovery, allow_unsigned_discovery)
    if no_score_threshold and threshold is not None:
        raise click.UsageError("--threshold and --no-score-threshold cannot be combined")
    if require_discovery_signature and project is None:
        raise click.BadParameter(
            "--require-discovery-signature requires --project",
            param_hint="--require-discovery-signature",
        )
    resolved_purpose, resolved_threshold, resolved_match, resolved_max_age = (
        _resolve_attestation_gate_options(
            attestation_envelope,
            trusted_keys,
            attestation_purpose,
            attestation_threshold,
            attestation_match,
            attestation_max_age_days,
        )
    )
    bom, raw_bom_bytes = _load_bom_with_bytes(aibom_path)

    from nexus_symbiote.attestation_cli import verify_gate_attestation
    from nexus_symbiote.validators.completeness import carries_discovery_evidence
    from nexus_symbiote.validators.risk import RiskReport, RiskScorer

    root = _project_root(project, label="--project") if project else None
    if root is not None:
        _require_binding_key()
    attestation_report: dict[str, object] | None = None
    attestation_failure_reason: str | None = None
    if attestation_envelope is not None:
        attestation_report = verify_gate_attestation(
            Path(aibom_path),
            attestation_envelope,
            trusted_keys=trusted_keys,
            purpose=resolved_purpose,
            threshold=resolved_threshold,
            match=resolved_match,
            max_age_days=resolved_max_age,
            project=root,
            subject_bytes=raw_bom_bytes,
        )
        _raise_on_misplaced_attestation_key(attestation_report)
        if not attestation_report["verified"]:
            attestation_failure_reason = (
                f"attestation verification failed: {attestation_report['detail']} "
                f"({attestation_report['reason']})"
            )
    signature_policies = _signer_policies(signature_policy, root)
    op_policy, op_digest, op_signers = _resolve_operator_policy(
        operator_policy,
        root,
        attestation_path=operator_policy_attestation,
        trusted_keys=operator_policy_key,
        allow_unsigned=allow_unsigned_operator_policy,
        max_age_days=operator_policy_max_age_days,
    )
    policy, policy_source, policy_weakened, policy_unapplied = _inventory_policy(
        root,
        aibom_path,
        ignore_project=no_project_policy,
        warn=(effective_format == "text"),
        allow_weakening=accept_project_policy,
        operator=op_policy,
        operator_digest=op_digest,
        operator_signers=op_signers,
    )
    threshold_from_cli = threshold is not None or no_score_threshold
    threshold = threshold if threshold is not None else policy.risk.fail_threshold
    if threshold <= 0 or not math.isfinite(threshold):
        raise click.BadParameter("threshold must be positive and finite", param_hint="--threshold")
    severity = fail_on_severity or policy.risk.fail_on_severity
    context: dict[str, Any] = {
        "verification_mode": "static-offline",
        "fail_on_severity": severity,
        "score_threshold": None if no_score_threshold else threshold,
        "policy_source": policy_source,
        "policy_weakened": policy_weakened,
        **({"attestation": attestation_report} if attestation_report is not None else {}),
    }
    if policy_unapplied is not None:
        context["policy_unapplied"] = policy_unapplied
    if op_digest is not None:
        context["operator_policy_digest"] = op_digest
        context["operator_policy_signers"] = list(op_signers)
        context["clamped_project_settings"] = list(_LAST_CLAMPED_SETTINGS.get())
    op_source_line = policy_source if op_digest is not None else None
    basis = "supplied-bom"
    supplier_claims: list[dict[str, str]] = []
    supplier_claims_omitted = 0
    producer = "not-verified" if carries_discovery_evidence(bom) else "not-applicable"
    producer_verified = False
    if root is not None:
        from nexus_symbiote.validators.completeness import (
            CompletenessValidator,
            discovery_producer_check,
            discovery_signature_required,
        )

        checked = CompletenessValidator().validate_against_project(
            bom,
            root,
            exclude_paths=policy.scan.exclude_paths,
            signature_policies=signature_policies,
            accept_default_excludes=accept_default_excludes or accept_default_exclude,
        )
        discovery: list[str] = []
        if discovery_signature_required(
            policy.validation.require_discovery_signature or require_discovery_signature,
            root,
            signature_policies,
        ):
            producer, discovery = discovery_producer_check(
                bom, root, signature_policies, exclude_paths=policy.scan.exclude_paths
            )
            producer_verified = producer == "verified"
        if not checked.is_complete or discovery:
            reasons = [
                issue.description
                for issue in checked.issues
                if issue.severity in {"error", "unknown"}
            ]
            reasons.extend(discovery)
            if attestation_failure_reason is not None:
                reasons.append(attestation_failure_reason)
            # The same keys as a scored report, so consumers need not special-case it.
            failed = {
                **RiskReport().to_dict(),
                "passed": False,
                "assessment_basis": checked.basis,
                "overall_score": None,
                "risk_level": "unknown",
                "coverage_status": "unknown" if checked.is_complete else "unreconciled",
                "gate_reasons": reasons,
                "total_components": len(bom.components),
                "supplier_claims": [],
                "supplier_claims_omitted": 0,
                "discovery_producer": producer,
                **context,
            }
            _emit_gate_report(
                "risk",
                effective_format,
                failed,
                lambda: risk_report_lines(failed),
                step_summary=step_summary,
                project=root,
                operator_source=op_source_line,
            )
            _gate_exit(
                detailed, collection_failed=_attestation_collection_failed(attestation_report)
            )
        basis = checked.basis
        supplier_claims = [
            {"subject": c.subject, "kind": c.kind, "detail": c.detail}
            for c in checked.supplier_claims
        ]
        supplier_claims_omitted = checked.supplier_claims_omitted
    unsigned_reason = _unsigned_discovery_failure_reason(
        bom,
        fail_on_unsigned_discovery=fail_on_unsigned_discovery,
        allow_unsigned_discovery=allow_unsigned_discovery,
        already_verified=producer_verified,
    )
    if root is None and _discovery_signature_unverifiable(policy, bom):
        unsigned_reason, producer = DISCOVERY_SIGNATURE_NEEDS_PROJECT, "failed"
    if unsigned_reason is not None:
        reasons = [unsigned_reason]
        if attestation_failure_reason is not None:
            reasons.append(attestation_failure_reason)
        # The same keys as a scored report, so consumers need not special-case it.
        unsigned = {
            **RiskReport().to_dict(),
            "passed": False,
            "assessment_basis": "unsigned-discovery-evidence",
            "overall_score": None,
            "risk_level": "unknown",
            "gate_reasons": reasons,
            "total_components": len(bom.components),
            "supplier_claims": supplier_claims,
            "supplier_claims_omitted": supplier_claims_omitted,
            "discovery_producer": producer,
            **context,
        }
        _emit_gate_report(
            "risk",
            effective_format,
            unsigned,
            lambda: risk_report_lines(unsigned),
            step_summary=step_summary,
            project=root,
            operator_source=op_source_line,
        )
        _gate_exit(detailed, collection_failed=_attestation_collection_failed(attestation_report))
    scorer = RiskScorer.from_policy(
        policy.risk,
        # The scorer requires a finite threshold; none can be reached by a sum of weights.
        fail_threshold=sys.float_info.max if no_score_threshold else threshold,
        fail_on_severity=fail_on_severity,
    )
    passed, report = scorer.passes_gate(bom)
    gate_reasons = list(report.gate_reasons)
    if attestation_failure_reason is not None:
        passed = False
        gate_reasons.append(attestation_failure_reason)
    gate = {
        **report.gate,
        **_gate_sources(policy, policy_source, threshold_from_cli, fail_on_severity),
    }
    if no_score_threshold:
        gate["fail_threshold"] = None
    document = {
        **report.to_dict(),
        "gate": gate,
        "gate_reasons": gate_reasons,
        "passed": passed,
        "assessment_basis": basis,
        "supplier_claims": supplier_claims,
        "supplier_claims_omitted": supplier_claims_omitted,
        "discovery_producer": producer,
        **context,
    }
    coverage = bom.metadata.completeness
    failures = list(coverage.scan_failures) if coverage else []
    _emit_gate_report(
        "risk",
        effective_format,
        document,
        lambda: risk_report_lines(document, failures=failures),
        step_summary=step_summary,
        project=root,
        operator_source=op_source_line,
    )
    if not passed:
        _gate_exit(detailed, collection_failed=_attestation_collection_failed(attestation_report))


@main.command()
@click.argument("old_path", type=click.Path(exists=True))
@click.argument("new_path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Output as JSON")
@_gate_report_options
@click.option(
    "--expect-upgrade",
    type=click.Choice(["0.1.0", "0.2.0"]),
    default=None,
    help="Attribute documented serializer/profile transitions since FROM_VERSION to tool_upgrade_changes.",
)
@click.option(
    "--fail-on-alert/--no-fail-on-alert",
    default=True,
    show_default=True,
    help="Exit non-zero if the diff reports an active security alert.",
)
@_exit_code_options
def diff(
    old_path: str,
    new_path: str,
    json_output: bool,
    report_format: str | None = None,
    step_summary: Path | None = None,
    expect_upgrade: str | None = None,
    fail_on_alert: bool = True,
    detailed_exit_codes: bool = False,
    legacy_exit_codes: bool = False,
) -> None:
    """Compare two AIBOM snapshots for supply-chain drift."""
    detailed = _apply_exit_code_flags(detailed_exit_codes, legacy_exit_codes)
    effective_format = _resolve_report_format(json_output, report_format)
    old_bom = _load_bom(old_path)
    new_bom = _load_bom(new_path)

    from nexus_symbiote.diff.differ import AIBOMDiffer, _values_unbound
    from nexus_symbiote.diff.upgrade_attribution import attribute_expected_upgrade

    result = AIBOMDiffer().diff(old_bom, new_bom)
    document = result.to_dict()
    if expect_upgrade is not None:
        unbound_refs = frozenset(
            comp.bom_ref
            for comp in (*old_bom.components, *new_bom.components)
            if _values_unbound(comp)
        )
        try:
            document = attribute_expected_upgrade(
                document,
                expect_upgrade,
                baseline_tool_version=old_bom.metadata.tool_version,
                unbound_components=unbound_refs,
            )
        except ValueError as exc:
            raise click.UsageError(str(exc)) from None
    document_with_verdict = {**document, "passed": not bool(document.get("security_alerts"))}
    _emit_gate_report(
        "diff",
        effective_format,
        document if effective_format == "json" else document_with_verdict,
        lambda: diff_report_lines(document),
        step_summary=step_summary,
    )
    if fail_on_alert and document.get("security_alerts"):
        _gate_exit(detailed)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Print the summary as JSON.")
def summary(aibom_path: str, json_output: bool = False) -> None:
    """Print a summary of an AIBOM."""
    bom = _load_bom(aibom_path)
    s = bom.summary()
    if json_output:
        click.echo(json_text(json.dumps(s, indent=2)))
        return
    lines: list[ReportLine] = [
        ("AIBOM Summary", "bold"),
        (f"  Components: {s['total_components']}", None),
        (f"  Dependencies: {s['total_dependencies']}", None),
        (f"  Risks: {s['total_risks']}", None),
    ]
    if s["component_types"]:
        lines.append(("  Component types:", None))
        for ctype, count in sorted(s["component_types"].items()):
            lines.append((safe_line("    - ", ctype, ": ", count), None))
    if s["risk_breakdown"]:
        lines.append(("  Risk breakdown:", None))
        for sev, count in sorted(s["risk_breakdown"].items(), key=severity_rank):
            lines.append((safe_line("    - ", sev, ": ", count), None))
    print_lines(lines)


@main.command("blast-radius")
@click.argument("aibom_path", type=click.Path(exists=True))
@click.argument("component_ref")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def blast_radius_command(aibom_path: str, component_ref: str, json_output: bool) -> None:
    """Show repository dependencies potentially affected by a component compromise."""
    from nexus_symbiote.graph import blast_radius

    bom = _load_bom(aibom_path)
    try:
        result = blast_radius(bom, component_ref)
    except ValueError as exc:
        raise _failure(exc) from exc
    if json_output:
        click.echo(json_text(json.dumps(result, indent=2)))
        return
    print_lines(
        [
            (
                "Potential blast radius (repository association; effective authority unknown)",
                "bold",
            ),
            (safe_line("  Agents: ", ", ".join(result["affected_agents"])), None),
            (safe_line("  Dependents: ", ", ".join(result["dependent_components"])), None),
            (safe_line("  Components: ", ", ".join(result["reachable_components"])), None),
            *((safe_line("  Note: ", note), None) for note in result["limitations"][1:]),
        ]
    )


@main.command()
@click.option("--force", is_flag=True, help="Overwrite the existing project policy file")
@click.option(
    "--path",
    type=click.Path(),
    default=".",
    help="Directory to create the project policy file in",
)
def init(force: bool, path: str) -> None:
    """Initialize a .nexus-symbiote.yaml policy configuration."""
    from nexus_symbiote.policy import DEFAULT_POLICY_YAML, POLICY_FILE_NAMES

    # absolute(), not resolve(): a symlinked directory is refused like any other output.
    directory = Path(path).absolute()
    try:
        existing = [
            directory / name
            for name in POLICY_FILE_NAMES
            if (directory / name).exists() or (directory / name).is_symlink()
        ]
    except OSError as exc:
        raise output_failure(exc) from exc
    # A second policy name would shadow, or be shadowed by, the existing one.
    target = existing[0] if len(existing) == 1 else directory / POLICY_FILE_NAMES[0]
    if len(existing) > 1:
        echo_line(
            "Warning: both ",
            POLICY_FILE_NAMES[0],
            " and ",
            POLICY_FILE_NAMES[1],
            " exist in ",
            directory,
            "; keep one policy file.",
            err=True,
        )
        sys.exit(1)
    if existing and not force:
        echo_line("Warning: ", target, " already exists. Use --force to overwrite.", err=True)
        sys.exit(1)

    write_cli_output(target, DEFAULT_POLICY_YAML, overwrite=force)
    echo_line("Created ", target)
    click.echo(
        "  Tightening settings apply automatically. Use --accept-project-policy for a reviewed relaxation."
    )


register_runtime_commands(main)
register_live_commands(main)
register_supply_chain_commands(main)
register_digest_commands(main)
register_attestation_commands(main)
register_graph_commands(main)
register_crosswalk_commands(main)
register_trace_commands(main)
register_inventory_export_commands(main)
register_minimum_elements_commands(main)
register_export_standard_commands(main)
register_control_plane_commands(main)
register_instruction_diff_commands(main)
register_sbom_commands(main)

if __name__ == "__main__":
    main()
