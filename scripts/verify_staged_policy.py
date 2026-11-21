"""Enforce an out-of-tree, optionally DSSE-signed operator policy on a checkout (`R1.0.0-2`).

In pull-request CI, the target checkout controls `.nexus-symbiote.yaml` and every file inside
the working tree. This gate verifies that `--operator-policy` (and any `--operator-policy-key`
or `--baseline`) resides outside the target checkout and every enclosing git working tree
*without* copying it into a temporary path, verifies its DSSE attestation (purpose `policy`)
unless `--allow-unsigned-operator-policy` is given, clamps any checkout `.nexus-symbiote.yaml`
to a non-weakening floor, and runs collection, the checks of `validate --project`, risk scoring,
and optional baseline diffing. Anything short of a pass verdict fails: unknown integrity,
ShadowScan discovery evidence (this gate has no signer policy to verify its producer), and an
assurance level the offline checks cannot establish.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast, get_args

import click
from click.testing import CliRunner
from pydantic import ValidationError

from nexus_symbiote import attestation, limits
from nexus_symbiote.attestation_cli import _load_trusted_public
from nexus_symbiote.cli import main as cli_main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.graph import validate_graph
from nexus_symbiote.policy import (
    DEFAULT_WARN_THRESHOLD,
    MAX_POLICY_YAML_NODES,
    Policy,
    PolicyError,
    RiskPolicy,
    ValidatePolicy,
    load_policy,
    parse_yaml_mapping,
)
from nexus_symbiote.runtime import key_id
from nexus_symbiote.runtime_cli import (
    _check_key_placement,
    _identity,
    _InputTooLargeError,
    _KeyFileError,
    _read,
    _working_trees,
)
from nexus_symbiote.utils.terminal import safe_line
from nexus_symbiote.validators.completeness import (
    CompletenessValidator,
    assurance_problems,
    carries_discovery_evidence,
    discovery_producer_check,
)
from nexus_symbiote.validators.integrity import IntegrityValidator
from nexus_symbiote.validators.risk import RiskScorer

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_OPERATOR_POLICY_BYTES = 1024 * 1024
# The signed-policy contract of `nexus_symbiote.operator_policy` and the CLI's operator-policy
# options: one envelope and one set of flags must work for this gate and for the CLI.
POLICY_PURPOSE: Final = "policy"
ALLOW_UNSIGNED_FLAG: Final = "--allow-unsigned-operator-policy"
MAX_AGE_FLAG: Final = "--operator-policy-max-age-days"
DEFAULT_MAX_AGE_DAYS: Final = 90
_SEVERITY_STRICTNESS: dict[str, int] = {
    "none": 0,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}
_ASSURANCE_STRICTNESS: dict[str, int] = {"declared": 0, "observed": 1, "verified": 2}


def _verify_outside_checkout(
    target: Path, untrusted_roots: tuple[Path, ...], *, label: str
) -> None:
    try:
        resolved_roots = [p.resolve() for p in untrusted_roots]
        search_starts = [
            *(p if p.is_dir() else p.parent for p in resolved_roots),
            Path.cwd().resolve(),
        ]
        trees = _working_trees(search_starts)
        forbidden_dirs = [
            *trees,
            *(p for p in resolved_roots if p.is_dir() and p not in trees),
        ]
        forbidden_ids = {_identity(d) for d in forbidden_dirs}
        resolved_target = target.resolve()
        ancestor_ids = {_identity(parent) for parent in resolved_target.parents}
        if any(resolved_target.is_relative_to(d) for d in forbidden_dirs) or bool(
            ancestor_ids & forbidden_ids
        ):
            raise click.UsageError(
                f"{label} must lie outside the target checkout and every git working tree "
                "that holds the checkout or the current directory"
            )
        if os.stat(resolved_target).st_nlink != 1:
            raise click.UsageError(f"{label} must not have multiple hard links")
    except click.UsageError:
        raise
    except (OSError, RuntimeError):
        raise click.UsageError(f"{label} cannot be inspected safely") from None


def clamp_operator_floor(operator_policy: Policy, project_policy: Policy | None) -> Policy:
    """Combine operator and checkout policies so the checkout can only tighten controls."""
    if project_policy is None:
        return operator_policy

    op_r, pr_r = operator_policy.risk, project_policy.risk
    fail_threshold = min(op_r.fail_threshold, pr_r.fail_threshold)
    warn_threshold = min(
        op_r.warn_threshold, pr_r.warn_threshold, fail_threshold, DEFAULT_WARN_THRESHOLD
    )
    fail_on_severity = (
        pr_r.fail_on_severity
        if _SEVERITY_STRICTNESS[pr_r.fail_on_severity] > _SEVERITY_STRICTNESS[op_r.fail_on_severity]
        else op_r.fail_on_severity
    )
    allowed_ignored = set(op_r.ignore_categories)
    ignore_categories = [c for c in pr_r.ignore_categories if c in allowed_ignored]

    op_v, pr_v = operator_policy.validation, project_policy.validation
    min_assurance = (
        pr_v.minimum_assurance_level
        if _ASSURANCE_STRICTNESS[pr_v.minimum_assurance_level]
        > _ASSURANCE_STRICTNESS[op_v.minimum_assurance_level]
        else op_v.minimum_assurance_level
    )

    return Policy(
        version="1.0",
        scan=operator_policy.scan,
        risk=RiskPolicy(
            fail_threshold=fail_threshold,
            warn_threshold=warn_threshold,
            ignore_categories=ignore_categories,
            fail_on_severity=fail_on_severity,
            suppressions=list(op_r.suppressions),
        ),
        validate=ValidatePolicy(
            require_completeness=op_v.require_completeness or pr_v.require_completeness,
            require_integrity=op_v.require_integrity or pr_v.require_integrity,
            minimum_assurance_level=min_assurance,
            require_discovery_signature=(
                op_v.require_discovery_signature or pr_v.require_discovery_signature
            ),
        ),
        output=operator_policy.output,
    )


def _line(prefix: str, *values: object) -> str:
    # Checkout text reaches a CI job log, where a line start or an escape is a command.
    return safe_line(prefix, *values) + "\n"


def validation_failures(bom: AIBOM, root: Path, policy: Policy) -> list[str]:
    """Apply the checks of `validate --project`; only a pass verdict yields no failure."""
    validation = policy.validation
    minimum = validation.minimum_assurance_level
    if minimum == "verified":
        return [
            "validate.minimum_assurance_level: verified cannot be established by this offline gate"
        ]
    failures: list[str] = []
    excluded = policy.scan.exclude_paths
    bound_imports: frozenset[str] = frozenset()
    if validation.require_completeness:
        c_rep = CompletenessValidator().validate_against_project(bom, root, exclude_paths=excluded)
        bound_imports = c_rep.bound_imports
        if not c_rep.is_complete:
            failures.append("completeness validation failed under operator policy")
    if validation.require_integrity:
        i_rep = IntegrityValidator().validate(
            bom, root, exclude_paths=excluded, bound_imports=bound_imports
        )
        if not i_rep.is_valid:
            failures.append(
                f"integrity validation failed under operator policy (status: {i_rep.status})"
            )
    if carries_discovery_evidence(bom):
        failures.append(
            "unsigned ShadowScan discovery evidence: this gate has no signer policy to verify "
            "its producer"
        )
    elif validation.require_discovery_signature:
        failures.extend(discovery_producer_check(bom, root, [], exclude_paths=excluded)[1])
    failures.extend(assurance_problems(bom, minimum, imported_claims=bound_imports))
    failures.extend(validate_graph(bom))
    return failures


def _has_option(command: str, option: str) -> bool:
    subcommand = cli_main.commands.get(command)
    return subcommand is not None and any(option in param.opts for param in subcommand.params)


def run_staged_gate(
    project_dir: Path,
    operator_policy_source: Path,
    *,
    baseline_source: Path | None = None,
    attestation_source: Path | None = None,
    trusted_keys: tuple[Path, ...] = (),
    allow_unsigned: bool = False,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> tuple[int, str]:
    """Verify operator policy placement/attestation in-place and run repository gates."""
    try:
        if not project_dir.is_dir():
            raise click.UsageError("--project must name an existing directory")
        if allow_unsigned and (attestation_source is not None or trusted_keys):
            raise click.UsageError(
                f"{ALLOW_UNSIGNED_FLAG} cannot be combined with "
                "--operator-policy-attestation or --operator-policy-key"
            )
        if attestation_source is not None and not trusted_keys:
            raise click.UsageError(
                "--operator-policy-attestation requires at least one --operator-policy-key"
            )
        if trusted_keys and attestation_source is None:
            raise click.UsageError("--operator-policy-key requires --operator-policy-attestation")
        if max_age_days < 0:
            raise click.UsageError(f"{MAX_AGE_FLAG} must be >= 0")
        if attestation_source is not None and POLICY_PURPOSE not in get_args(attestation.Purpose):
            raise click.UsageError(
                f"this build's attestations have no '{POLICY_PURPOSE}' purpose, so a signed "
                "operator policy cannot be verified with it"
            )
        collection_limits = limits.resolve((), os.environ)

        untrusted = (project_dir,)
        _verify_outside_checkout(operator_policy_source, untrusted, label="--operator-policy")
        if baseline_source is not None:
            _verify_outside_checkout(baseline_source, untrusted, label="--baseline")

        if attestation_source is not None:
            _verify_outside_checkout(
                attestation_source, untrusted, label="--operator-policy-attestation"
            )
            for key_path in trusted_keys:
                _verify_outside_checkout(key_path, untrusted, label="--operator-policy-key")
            _check_key_placement(
                trusted_keys,
                (project_dir, operator_policy_source, attestation_source),
                option="--operator-policy-key",
                holders="PROJECT, OPERATOR_POLICY, ATTESTATION",
            )

        raw_policy = _read(operator_policy_source, MAX_OPERATOR_POLICY_BYTES)
        if attestation_source is None and not allow_unsigned:
            raise click.UsageError(
                "--operator-policy requires --operator-policy-attestation and "
                f"--operator-policy-key (or pass {ALLOW_UNSIGNED_FLAG} explicitly)"
            )
        if attestation_source is not None:
            ring: dict[str, Ed25519PublicKey] = {}
            for key_path in trusted_keys:
                pub = cast("Ed25519PublicKey", _load_trusted_public(key_path))
                ring[key_id(pub)] = pub
            raw_env = _read(attestation_source, attestation.MAX_ENVELOPE_BYTES)
            attestation.verify_attestation(
                attestation.parse_envelope(raw_env),
                raw_policy,
                trusted_keys=ring,
                purpose=POLICY_PURPOSE,
                threshold=1,
                match="bytes",
                max_age=timedelta(days=max_age_days) if max_age_days else None,
            )

        operator_policy = Policy.model_validate(
            parse_yaml_mapping(raw_policy.decode("utf-8"), max_nodes=MAX_POLICY_YAML_NODES)
        )
        policy_digest = "sha256:" + hashlib.sha256(raw_policy).hexdigest()
    except click.UsageError as exc:
        return 2, _line("Error: ", exc.format_message())
    except (PolicyError, ValidationError, UnicodeDecodeError) as exc:
        return 2, _line("Error: invalid operator policy (", type(exc).__name__, ")")
    except (_KeyFileError, _InputTooLargeError, OSError) as exc:
        return 2, _line("Error: operator policy input rejected (", exc or type(exc).__name__, ")")
    except attestation.AttestationError as exc:
        return 1, _line("Error: operator policy attestation verification failed (", exc.reason, ")")
    except ValueError as exc:
        return 2, _line("Error: ", exc)

    cli_policy_args: list[str] = []
    # Collection uses the operator's settings. The checks below apply any stricter checkout floor.
    supports_operator = _has_option("scan", "--operator-policy")
    scan_extra_args = []
    if not supports_operator or _has_option("scan", "--no-project-policy"):
        scan_extra_args.append("--no-project-policy")
    if supports_operator:
        cli_policy_args.extend(["--operator-policy", str(operator_policy_source)])
        if attestation_source is not None:
            cli_policy_args.extend(["--operator-policy-attestation", str(attestation_source)])
        for key_path in trusted_keys:
            cli_policy_args.extend(["--operator-policy-key", str(key_path)])
        if attestation_source is None:
            cli_policy_args.append(ALLOW_UNSIGNED_FLAG)
        else:
            cli_policy_args.extend([MAX_AGE_FLAG, str(max_age_days)])
    else:
        # Ignore untrusted checkout .nexus-symbiote.yaml during collection so a PR cannot
        # hide files via scan.exclude_paths, disable collectors via scan.scanners, or
        # trigger the CI weakened-project-policy abort before operator clamping runs.
        for scanner_name in operator_policy.scan.scanners:
            scan_extra_args.extend(["--scanner", scanner_name])

    # The checks below collect outside any CLI command, which is where the operator's
    # NEXUS_SYMBIOTE_LIMITS would otherwise be applied.
    with (
        limits.applied(collection_limits),
        tempfile.TemporaryDirectory(prefix="nsb-staged-out-") as out_root,
    ):
        candidate_bom = Path(out_root) / "candidate-aibom.json"
        runner = CliRunner()
        scan_res = runner.invoke(
            cli_main,
            [
                "scan",
                str(project_dir),
                "-o",
                str(candidate_bom),
                "--report-only",
                *cli_policy_args,
                *scan_extra_args,
            ],
        )
        if scan_res.exit_code != 0 or not candidate_bom.is_file():
            return scan_res.exit_code or 1, scan_res.output

        bom = AIBOM.load(candidate_bom)
        resolved_project = project_dir.resolve()
        try:
            project_policy = load_policy(resolved_project)
        except PolicyError as exc:
            return 1, scan_res.output + _line("Error: invalid checkout policy (", exc, ")")

        effective = clamp_operator_floor(operator_policy, project_policy)
        lines = [scan_res.output, f"Policy: operator:{policy_digest}\n"]
        if project_policy is not None:
            lines.append("The checkout policy was used only to tighten the operator's checks.\n")

        failures = validation_failures(bom, resolved_project, effective)
        lines.extend(_line("Error: ", failure) for failure in failures)

        scorer = RiskScorer(
            fail_threshold=effective.risk.fail_threshold,
            warn_threshold=effective.risk.warn_threshold,
            ignore_categories=effective.risk.ignore_categories,
            fail_on_severity=effective.risk.fail_on_severity,
            suppressions=effective.risk.suppressions,
        )
        passed, risk_report = scorer.passes_gate(bom)
        if not passed:
            reasons = "; ".join(risk_report.gate_reasons) or "risk gate failed"
            lines.append(_line("Error: operator risk gate failed: ", reasons))
        if failures or not passed:
            return 1, "".join(lines)

        if supports_operator:
            risk_args = [*cli_policy_args]
            if _has_option("risk", "--no-project-policy"):
                risk_args.append("--no-project-policy")
            risk_res = runner.invoke(
                cli_main,
                ["risk", str(candidate_bom), "--project", str(project_dir), *risk_args],
            )
            lines.append(risk_res.output)
            if risk_res.exit_code != 0:
                return risk_res.exit_code, "".join(lines)

        if baseline_source is not None:
            diff_res = runner.invoke(
                cli_main,
                ["diff", str(baseline_source), str(candidate_bom), "--fail-on-alert"],
            )
            lines.append(diff_res.output)
            if diff_res.exit_code != 0:
                return diff_res.exit_code, "".join(lines)

        return 0, "".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True, help="Target checkout directory")
    parser.add_argument(
        "--operator-policy",
        type=Path,
        required=True,
        help="Trusted operator policy file outside the checkout and its git working tree",
    )
    parser.add_argument(
        "--operator-policy-attestation",
        type=Path,
        default=None,
        help="DSSE attestation envelope (purpose 'policy') over --operator-policy",
    )
    parser.add_argument(
        "--operator-policy-key",
        type=Path,
        action="append",
        default=[],
        help="Trusted Ed25519 public key PEM for --operator-policy-attestation (repeatable)",
    )
    parser.add_argument(
        ALLOW_UNSIGNED_FLAG,
        action="store_true",
        help="Accept --operator-policy without a verified DSSE attestation",
    )
    parser.add_argument(
        MAX_AGE_FLAG,
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help="Maximum attestation age in days (0 disables; default: %(default)s)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Optional reviewed baseline AIBOM outside the checkout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    code, output = run_staged_gate(
        args.project,
        args.operator_policy,
        baseline_source=args.baseline,
        attestation_source=args.operator_policy_attestation,
        trusted_keys=tuple(args.operator_policy_key),
        allow_unsigned=args.allow_unsigned_operator_policy,
        max_age_days=args.operator_policy_max_age_days,
    )
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
