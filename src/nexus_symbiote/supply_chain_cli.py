"""Explicit supply-chain reports and reviewed-baseline operations."""

from __future__ import annotations

import contextlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import click

from nexus_symbiote import modes
from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.live_cli import review_notice
from nexus_symbiote.utils.files import create_staging_file
from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    neutralize,
    output_failure,
    refuse_dash_output,
    write_cli_output,
)

if TYPE_CHECKING:
    from nexus_symbiote.live.verify import LiveVerifyReport

# Set while `baseline` runs `scan` into a staged inventory that it discards on failure.
STAGED_INVENTORY = "nexus_symbiote.staged-inventory"


def _running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _load_inventory(path: Path) -> AIBOM:
    # Parser and validation messages can quote attacker-controlled input; keep them out.
    try:
        return AIBOM.load(path)
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(f"{neutralize(path)} is not a valid native AIBOM file.") from exc


def _refuse_source_overwrite(output: Path | None, source: Path) -> None:
    if output is None:
        return
    try:
        # Path text alone misses a second name for the same file (a hard link, a bind
        # mount or a case variant), so an existing output is also compared by identity.
        same = output.resolve() == source.resolve() or (
            output.exists() and os.path.samefile(output, source)
        )
    except (OSError, RuntimeError) as exc:
        raise output_failure(exc) from exc
    if same:
        raise click.BadParameter("output must not overwrite the source inventory")


def _repository_roots(path: Path) -> list[Path]:
    """Every directory at or above ``path`` that holds a ``.git`` entry."""
    return [candidate for candidate in (path, *path.parents) if os.path.lexists(candidate / ".git")]


def _safe_stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except OSError:
        return None


def _check_launch_policy(policy: Path, project: Path, inventory: Path) -> os.stat_result | None:
    """Refuse a launch policy that the change under review could have written.

    The policy must lie outside the project, outside every repository that encloses
    the project or the inventory, be a single-link regular file owned by the caller or
    root that only its owner can write, in directories owned by you or root that others
    cannot write unless they are sticky, up to the file system root. This catches
    misplacement; it does not authenticate the policy.
    """
    resolved = policy.resolve()
    untrusted = [project.resolve()]
    for start in (project.resolve(), inventory.resolve().parent):
        # A nested checkout (a submodule or vendored repository) has its own .git, but
        # the change under review can still edit the repository around it.
        untrusted.extend(_repository_roots(start))
    if any(resolved.is_relative_to(root) for root in untrusted):
        raise click.UsageError(
            "launch policy must be provisioned outside the untrusted project and outside "
            "the repository that holds the project or the inventory, and any repository "
            "enclosing either"
        )
    if os.name != "posix":
        return None
    try:
        info = resolved.lstat()
        # Whoever can write any directory above the policy can rename the one below it
        # away and put another policy in its place, so every ancestor is checked.
        directories = [path.stat() for path in resolved.parents]
    except OSError as exc:
        raise click.UsageError("launch policy cannot be inspected") from exc
    untrusted_ids = {
        (st.st_dev, st.st_ino) for root in untrusted if (st := _safe_stat(root)) is not None
    }
    if any((entry.st_dev, entry.st_ino) in untrusted_ids for entry in directories):
        raise click.UsageError(
            "launch policy must be provisioned outside the untrusted project and outside "
            "the repository that holds the project or the inventory, and any repository "
            "enclosing either"
        )
    owners = {0, os.geteuid()}
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid not in owners
        or info.st_mode & 0o022
        or any(
            directory.st_uid not in owners
            or (directory.st_mode & 0o022 and not directory.st_mode & stat.S_ISVTX)
            for directory in directories
        )
    ):
        raise click.UsageError(
            "launch policy must be a single-link regular file owned by you or root and "
            "writable only by its owner, in directories owned by you or root that others "
            "cannot write unless they are sticky, up to the file system root"
        )
    return info


def _drift_summary(report: LiveVerifyReport) -> None:
    """Print each drifted server and tool to standard error, one neutralized line each."""
    for result in report.results:
        changes = [
            f"{finding.status} tool {finding.name}"
            for finding in result.tool_findings
            if finding.status != "match"
        ]
        if result.declaration_status in {"changed", "new"}:
            changes.append(f"{result.declaration_status} server declarations")
        if result.identity_status == "changed":
            changes.append("changed server identity or capabilities")
        if changes:
            echo_line("Drift in server ", result.server_ref, ": ", "; ".join(changes), err=True)


# Names only. verify-live starts the launcher with a cleared environment, but the
# parent still holds these, and --no-isolation or a containment failure is not a
# sandbox. The source-binding key is not one of them: drift comparison needs it,
# and it is not a cloud or registry credential.
_HOST_CREDENTIAL_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "PYPI_TOKEN",
    "DOCKER_PASSWORD",
    "KUBECONFIG",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
)


def _host_credential_names() -> list[str]:
    return [name for name in _HOST_CREDENTIAL_ENV if os.environ.get(name)]


def register_supply_chain_commands(main: click.Group) -> None:
    @main.command("verify-live")
    @click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False))
    @click.option(
        "--project",
        type=click.Path(exists=True, file_okay=False),
        required=True,
        help=(
            "Untrusted project root; the launch policy must be outside it and outside "
            "every repository that encloses the project or the inventory."
        ),
    )
    @click.option(
        "--launch-policy",
        required=True,
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Operator-owned JSON outside the project: exact server references to absolute commands and SHA-256 pins.",
    )
    @click.option("--json-output", is_flag=True, help="Output the verification report as JSON.")
    @click.option(
        "--record",
        is_flag=True,
        help=(
            "Print an unsigned candidate BOM with the observed descriptors instead of a "
            "report; exits 1 when served tools, declarations or the server identity "
            "drifted, unless --accept-drift."
        ),
    )
    @click.option(
        "--accept-drift",
        is_flag=True,
        help=(
            "With --record, exit 0 although changed or new tools, declarations or server "
            "identity were recorded."
        ),
    )
    @click.option(
        "--no-isolation",
        is_flag=True,
        help=(
            "Explicitly allow execution without a PID namespace; printed as a warning. On "
            "Linux the launcher runs in its own process group under a wrapper that stays "
            "its parent as a child subreaper and ignores the signals it can, and cleanup "
            "kills the wrapper's whole tree, including a clone(CLONE_PARENT) child that has "
            "called setsid and what a launcher that already exited left behind. A launcher "
            "that kills its wrapper with SIGKILL can escape, except from a cgroup v2 child "
            "where one can be created, which cleanup also kills; the server then fails "
            "with isolation-teardown-failed, unless the launcher runs as root or holds "
            "CAP_SYS_PTRACE or CAP_SYS_ADMIN, which can hide the escape. Never opt out as "
            "root. Elsewhere cleanup is best effort. This is not a namespace or sandbox."
        ),
    )
    @click.option(
        "--allow-host-credentials",
        is_flag=True,
        help=(
            "Run even when host credential environment variables are set. The launcher "
            "is started with a cleared environment, but this process is not a sandbox: "
            "--no-isolation and a containment failure leave those credentials on the host."
        ),
    )
    def verify_live(
        aibom_path: str,
        project: str,
        launch_policy: Path,
        json_output: bool,
        record: bool,
        accept_drift: bool,
        no_isolation: bool,
        allow_host_credentials: bool,
    ) -> None:
        """Live: observe independently pinned stdio launchers; optionally emit an unsigned candidate.

        The operator must provision policy outside the untrusted checkout. Pins
        cover launcher bytes; use an externally isolated worker to restrict its
        host dependencies, filesystem, identity and egress. Project settings do
        not supply launch authority. Descriptor matches do not establish safety.
        Remote MCP servers in the inventory are reported as not verifiable here;
        observe them with discover-mcp --record.
        """
        modes.require_live("verify-live")
        from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict
        from nexus_symbiote.live.pinned_process import isolation_off
        from nexus_symbiote.live.verify import record_candidate, verify_mcp_servers

        if record and json_output:
            raise click.UsageError("choose a candidate BOM or a JSON verification report")
        if accept_drift and not record:
            raise click.UsageError("--accept-drift applies only to --record")
        present = _host_credential_names()
        if present and not allow_host_credentials:
            raise click.UsageError(
                "verify-live refuses to run while host credential environment variables "
                "are set (" + ", ".join(present) + "). Unset them, or pass "
                "--allow-host-credentials. The launcher is started with a cleared "
                "environment; this process is still not a sandbox."
            )
        expected_info = _check_launch_policy(launch_policy, Path(project), Path(aibom_path))
        try:
            with open_regular_file(launch_policy) as stream:
                finfo = os.fstat(stream.fileno())
                if not stat.S_ISREG(finfo.st_mode) or finfo.st_nlink != 1:
                    raise ValueError("launch policy has more than one link")
                if expected_info is not None and (
                    finfo.st_uid not in {0, os.geteuid()}
                    or finfo.st_mode & 0o022
                    or (finfo.st_dev, finfo.st_ino) != (expected_info.st_dev, expected_info.st_ino)
                ):
                    raise ValueError("launch policy changed after inspection")
                policy_bytes = stream.read(4 * 1024 * 1024 + 1)
            policy = parse_json_strict(policy_bytes)
            if not isinstance(policy, dict):
                raise ValueError("launch policy must be an object")
            with open_regular_file(Path(aibom_path)) as stream:
                inventory_bytes = stream.read(16 * 1024 * 1024 + 1)
            document = parse_json_strict(inventory_bytes, max_bytes=16 * 1024 * 1024)
            bom = AIBOM.from_document(document)
        except (OSError, ValueError, TypeError, RecursionError):
            raise click.ClickException("invalid BOM or operator launch policy") from None
        if no_isolation:
            click.echo(
                "warning: --no-isolation: kernel PID containment is disabled. On Linux the "
                "launcher runs in its own process group under a wrapper that stays its parent "
                "as a child subreaper and ignores the signals it can, and cleanup kills the "
                "wrapper's whole tree, including a clone(CLONE_PARENT) child that has called "
                "setsid and what a launcher that already exited left behind. A launcher that "
                "kills its wrapper with SIGKILL can escape, except from a cgroup v2 child where "
                "one can be created, which cleanup also kills; the server then fails with "
                "isolation-teardown-failed, unless the launcher runs as root or holds "
                "CAP_SYS_PTRACE or CAP_SYS_ADMIN, which can hide the escape. Never opt out as "
                "root. Elsewhere cleanup is best effort. This is not a namespace or sandbox.",
                err=True,
            )
            if _running_as_root():
                click.echo(
                    "warning: --no-isolation as root: the pinned launcher runs as root with no "
                    "kernel containment, and can escape cleanup without it being reported.",
                    err=True,
                )
        with isolation_off() if no_isolation else contextlib.nullcontext():
            report = verify_mcp_servers(bom, trusted_launchers=policy)
        report.inputs = {
            "inventory_sha256": hash_bytes(inventory_bytes),
            "launch_policy_sha256": hash_bytes(policy_bytes),
        }
        if record:
            try:
                record_candidate(bom, report)
            except ValueError:
                raise click.ClickException("incomplete inventory; candidate not emitted") from None
            try:
                candidate = bom.to_native_json()
            except NativeFormatError as exc:
                raise click.ClickException(f"Inventory not written. {exc}") from exc
            click.echo(json_text(candidate))
            _drift_summary(report)
            review_notice(
                [
                    finding.name
                    for result in report.results
                    for finding in result.tool_findings
                    if finding.display_differs
                ]
            )
            if report.has_drift and not accept_drift:
                click.echo(
                    "Candidate differs from the inventory; review it, then rerun with "
                    "--accept-drift to record it with exit status 0.",
                    err=True,
                )
                raise click.exceptions.Exit(1)
            return
        if json_output:
            click.echo(json_text(json.dumps(report.to_dict(), indent=2)))
        else:
            echo_line(
                "Live descriptor observation: ",
                f"{report.servers_reachable}/{report.servers_checked} servers; ",
                f"{report.servers_skipped} remote not verifiable here; ",
                f"complete={report.complete}; drift={report.has_drift}",
            )
            for result in report.results:
                if result.reason is not None:
                    echo_line(
                        "Server ", f"{result.server_ref}: {result.reason}: {result.error}", err=True
                    )
        if not report.complete or report.has_drift:
            raise click.exceptions.Exit(1)

    @main.command()
    @click.argument("project_path", type=click.Path(exists=True, file_okay=False), default=".")
    @click.option(
        "-o",
        "--baseline-path",
        type=click.Path(path_type=Path),
        default=".nexus-symbiote-baseline.json",
        help="Where to write the unsigned baseline (default: .nexus-symbiote-baseline.json).",
    )
    @click.option(
        "--no-project-policy",
        is_flag=True,
        help="Use built-in policy without reading configuration from the target, as scan does.",
    )
    @click.option(
        "--accept-project-policy",
        is_flag=True,
        help=(
            "In CI, accept a project policy that weakens the built-in gates explicitly for "
            "collection, as scan does; the staged inventory is still re-gated by the built-in "
            "policy."
        ),
    )
    @click.option(
        "--signature-policy",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Explicit operator signer policy JSON, kept outside the project, as for scan.",
    )
    @click.option(
        "--fail-on-unsigned-discovery",
        is_flag=True,
        help="Refuse to promote unverified ShadowScan discovery evidence into a baseline.",
    )
    @click.option(
        "--allow-unsigned-discovery",
        is_flag=True,
        help="Accept unverified ShadowScan discovery evidence explicitly in CI (still warns).",
    )
    @click.pass_context
    def baseline(
        ctx: click.Context,
        project_path: str,
        baseline_path: Path,
        no_project_policy: bool = False,
        accept_project_policy: bool = False,
        signature_policy: Path | None = None,
        fail_on_unsigned_discovery: bool = False,
        allow_unsigned_discovery: bool = False,
    ) -> None:
        """Stage a static snapshot for review; publish it only after the scan gate passes.

        The file is unsigned. Operators must review and authenticate the baseline
        before using it as an authority for runtime admission. Take the baseline and
        the snapshots compared with it under the same policy: pass --no-project-policy
        here when the candidate scan uses it.
        """
        from nexus_symbiote.policy import PolicyError, default_policy, load_policy_file
        from nexus_symbiote.signature_policy import SignaturePolicyError, load_signature_policies
        from nexus_symbiote.validators.completeness import (
            carries_discovery_evidence,
            discovery_producer_check,
            discovery_signature_required,
        )
        from nexus_symbiote.validators.risk import RiskScorer

        if fail_on_unsigned_discovery and allow_unsigned_discovery:
            raise click.UsageError(
                "--fail-on-unsigned-discovery and --allow-unsigned-discovery contradict each other"
            )

        # Resolve the registered command instead of importing cli, which imports this module.
        root = ctx.find_root()
        scan = (
            root.command.get_command(root, "scan")
            if isinstance(root.command, click.Group)
            else None
        )
        if scan is None:
            raise click.ClickException("scan command is unavailable")

        refuse_dash_output(baseline_path)
        target = baseline_path.absolute()
        try:
            staged = create_staging_file(target, ".nexus-baseline-")
        except (OSError, ValueError) as exc:
            raise output_failure(exc) from exc
        ctx.meta[STAGED_INVENTORY] = True
        try:
            ctx.invoke(
                scan,
                project_path=project_path,
                output=str(staged),
                output_format="json",
                scanners=(),
                report_only=False,
                signature_policy=signature_policy,
                no_project_policy=no_project_policy,
                accept_project_policy=accept_project_policy,
            )
            # A project policy may select report-only mode; it cannot authorize
            # promotion of incomplete evidence into an approved baseline.
            try:
                staged_bom, staged_bytes = AIBOM.load_with_bytes(staged)
            except NativeFormatError as exc:
                raise click.ClickException(f"Baseline was not written. {exc}") from exc
            scorer = RiskScorer()
            passed, report = scorer.passes_gate(staged_bom)
            if not passed:
                from nexus_symbiote.reporting import gate_reason_lines, print_lines

                document = {
                    **report.to_dict(),
                    "fail_on_severity": scorer.fail_on_severity,
                    "score_threshold": scorer.fail_threshold,
                }
                heading = "Built-in scan gate failed; a project policy cannot relax it here:"
                print_lines([(heading, "red"), *gate_reason_lines(document)], err=True)
                raise click.ClickException("Baseline was not written: static scan gate failed")
            resolved_root = Path(project_path).resolve()
            try:
                loaded_policy = None if no_project_policy else load_policy_file(resolved_root)
                active_policy = loaded_policy[0] if loaded_policy is not None else default_policy()
                sig_policies = (
                    load_signature_policies(signature_policy, project_root=resolved_root)
                    if signature_policy is not None
                    else []
                )
            except (PolicyError, SignaturePolicyError) as exc:
                raise click.ClickException(neutralize(exc)) from exc
            producer_verified = False
            if discovery_signature_required(
                active_policy.validation.require_discovery_signature,
                resolved_root,
                sig_policies,
            ):
                status, problems = discovery_producer_check(
                    staged_bom,
                    resolved_root,
                    sig_policies,
                    exclude_paths=active_policy.scan.exclude_paths,
                )
                if status == "failed" or problems:
                    for problem in problems:
                        echo_line("  - ", problem, err=True)
                    raise click.ClickException(
                        "Baseline was not written: unverified imported discovery cannot be promoted"
                    )
                producer_verified = status == "verified"
            if carries_discovery_evidence(staged_bom) and not producer_verified:
                echo_line(
                    "WARNING: ShadowScan discovery evidence is UNVERIFIED; verify with "
                    "--signature-policy before promoting.",
                    err=True,
                )
                in_ci = any(
                    os.environ.get(name) not in (None, "", "0", "false")
                    for name in (
                        "CI",
                        "GITHUB_ACTIONS",
                        "GITLAB_CI",
                        "CIRCLECI",
                        "TF_BUILD",
                        "JENKINS_URL",
                        "BUILDKITE",
                        "DRONE",
                        "TRAVIS",
                    )
                )
                if (
                    active_policy.validation.require_discovery_signature
                    or fail_on_unsigned_discovery
                    or (in_ci and not allow_unsigned_discovery)
                ):
                    raise click.ClickException(
                        "Baseline was not written: unsigned ShadowScan discovery evidence; "
                        "verify with --signature-policy or pass --allow-unsigned-discovery"
                    )
            write_cli_output(target, staged_bytes.decode("utf-8"))
        finally:
            ctx.meta.pop(STAGED_INVENTORY, None)
            # A directory that forbids removal keeps the staged copy; that must not
            # replace the command's result.
            with contextlib.suppress(OSError):
                staged.unlink(missing_ok=True)
        echo_line("Unsigned baseline staged for review: ", target)

    @main.command()
    @click.argument("aibom_path", type=click.Path(exists=True, path_type=Path))
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the VEX document to this file instead of standard output.",
    )
    @click.option(
        "--decisions",
        "decisions_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help=(
            "Operator-owned VEX decisions YAML/JSON outside the scanned project; expired "
            "decisions revert to in_triage with a warning."
        ),
    )
    @click.option(
        "--project-root",
        type=click.Path(exists=True, file_okay=False, path_type=Path),
        help="Scanned project root used to refuse policy and trace files stored inside the checkout.",
    )
    @click.option(
        "--advisories",
        "advisories_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Link matched advisories from a live or offline advisories report JSON bound to this AIBOM.",
    )
    @click.option(
        "--trace-evidence",
        "trace_evidence_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help=(
            "trace-diff or execution-evidence JSON bound to this AIBOM; requires "
            "--trace-attestation with --trusted-key unless --allow-unsigned-trace-evidence is set."
        ),
    )
    @click.option(
        "--trace-attestation",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Ed25519 DSSE attestation envelope authenticating --trace-evidence.",
    )
    @click.option(
        "--trusted-key",
        "trusted_keys",
        multiple=True,
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Trusted Ed25519 public key PEM outside the scanned project (repeatable; used with --trace-attestation).",
    )
    @click.option(
        "--allow-unsigned-trace-evidence",
        is_flag=True,
        help="Explicitly accept unsigned --trace-evidence without --trace-attestation.",
    )
    @click.option("--deployment-id", help="Operator-selected deployment covered by VEX decisions.")
    @click.option(
        "--allow-partial-advisories",
        is_flag=True,
        help="Include an incomplete advisory report with its coverage and counters.",
    )
    def vex(
        allow_partial_advisories: bool,
        aibom_path: Path,
        output: Path | None,
        decisions_path: Path | None,
        project_root: Path | None,
        advisories_path: Path | None,
        trace_evidence_path: Path | None,
        trace_attestation: Path | None,
        trusted_keys: tuple[Path, ...],
        allow_unsigned_trace_evidence: bool,
        deployment_id: str | None,
    ) -> None:
        """Export schema-validated VEX findings with optional decisions, advisories, and trace evidence."""
        from nexus_symbiote.core.hashing import hash_bytes
        from nexus_symbiote.generators.vex import VEXGenerator
        from nexus_symbiote.vex_decisions import (
            load_advisory_report,
            load_execution_evidence,
            load_vex_decisions,
        )

        if (
            trace_attestation is not None or trusted_keys or allow_unsigned_trace_evidence
        ) and trace_evidence_path is None:
            raise click.UsageError(
                "--trace-attestation, --trusted-key, and --allow-unsigned-trace-evidence require --trace-evidence"
            )
        if trace_attestation is not None and allow_unsigned_trace_evidence:
            raise click.UsageError(
                "--trace-attestation and --allow-unsigned-trace-evidence contradict each other"
            )

        _refuse_source_overwrite(output, aibom_path)
        try:
            bom, inv_bytes = AIBOM.load_with_bytes(aibom_path)
        except NativeFormatError as exc:
            raise click.ClickException(
                f"{neutralize(aibom_path)} is not a valid native AIBOM file. {neutralize(exc)}"
            ) from exc
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            raise click.ClickException(
                f"{neutralize(aibom_path)} is not a valid native AIBOM file."
            ) from exc
        inv_sha = hash_bytes(inv_bytes)
        try:
            loaded_decisions = (
                load_vex_decisions(
                    decisions_path, project_root=project_root, inventory_path=aibom_path
                )
                if decisions_path is not None
                else None
            )
            loaded_trace = (
                load_execution_evidence(
                    trace_evidence_path,
                    project_root=project_root,
                    inventory_path=aibom_path,
                    expected_inventory_sha256=inv_sha,
                    attestation_path=trace_attestation,
                    trusted_key_paths=trusted_keys,
                    allow_unsigned=allow_unsigned_trace_evidence,
                )
                if trace_evidence_path is not None
                else None
            )
            loaded_advisories = (
                load_advisory_report(
                    advisories_path,
                    expected_inventory_sha256=inv_sha,
                    allow_partial=allow_partial_advisories,
                )
                if advisories_path is not None
                else None
            )
            text = VEXGenerator(
                decisions=loaded_decisions,
                execution_evidence=loaded_trace,
                advisory_report=loaded_advisories,
                inventory_sha256=inv_sha,
                deployment_id=deployment_id,
            ).generate_json(bom)
        except (OSError, ValueError, RecursionError) as exc:
            raise click.ClickException(neutralize(exc)) from exc
        if output:
            write_cli_output(output, text)
        else:
            click.echo(json_text(text))

    @main.command()
    @click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the advisory report to this file instead of standard output.",
    )
    @click.option(
        "--fail-on-advisory/--no-fail-on-advisory",
        default=True,
        show_default=True,
        help="Exit with status 1 when an advisory is found.",
    )
    @click.option(
        "--exclude",
        multiple=True,
        metavar="NAME",
        help="Never send this package name to OSV; a trailing * matches a prefix (repeatable).",
    )
    @click.option(
        "--exclude-private-origins",
        is_flag=True,
        help=(
            "Send only packages whose lockfile resolution records the public PyPI or npm "
            "registry. A Python package that no uv.lock or poetry.lock resolves has no "
            "recorded origin, so it is withheld; withhold private names with --exclude "
            "instead to keep public ones checked."
        ),
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        help="List the package identities that would be sent, without contacting OSV (works offline).",
    )
    @click.option(
        "--offline-db",
        type=click.Path(exists=True, path_type=Path),
        help=(
            "Match exact pinned PyPI/npm packages offline against an OSV JSON bundle or "
            "directory without contacting api.osv.dev."
        ),
    )
    @click.option(
        "--kev",
        "kev_paths",
        multiple=True,
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help=(
            "Offline CISA/ENISA KEV JSON catalog used with --offline-db to elevate matched "
            "advisories to critical with source provenance (repeatable)."
        ),
    )
    @click.option(
        "--epss",
        "epss_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Offline EPSS CSV/JSON catalog used with --offline-db to attach EPSS scores.",
    )
    @click.option(
        "--max-feed-age-days",
        type=click.IntRange(min=1, max=36_500),
        help=(
            "With --offline-db, the report is incomplete (exit 1) when the bundle's newest "
            "record, a KEV catalog's dateReleased or the EPSS score_date is missing or more "
            "than this many days old (default: 30). The check cannot be turned off."
        ),
    )
    def advisories(
        aibom_path: Path,
        output: Path | None,
        fail_on_advisory: bool,
        exclude: tuple[str, ...],
        exclude_private_origins: bool,
        dry_run: bool,
        offline_db: Path | None,
        kev_paths: tuple[Path, ...],
        epss_path: Path | None,
        max_feed_age_days: int | None,
    ) -> None:
        """Live (or offline with --offline-db): query OSV for exact PyPI/npm package URLs.

        Live mode sends each package's ecosystem, normalized name and exact version to
        api.osv.dev, including packages from private registries unless excluded. With
        --offline-db, matching runs locally against an operator-supplied OSV bundle with
        optional --kev and --epss catalogs and no network I/O; a feed that is undated or older
        than --max-feed-age-days makes the report incomplete. Exits 1 when an advisory is
        found (unless --no-fail-on-advisory) or when not every package in scope was looked
        up, including when none was; with --dry-run (live), only when the report lists an error.
        """
        if (kev_paths or epss_path is not None) and offline_db is None:
            raise click.ClickException("--kev and --epss require --offline-db")
        if max_feed_age_days is not None and offline_db is None:
            raise click.ClickException("--max-feed-age-days requires --offline-db")
        if not dry_run and offline_db is None:
            modes.require_live("advisories")
        from nexus_symbiote.advisories import fetch_advisories
        from nexus_symbiote.core.hashing import hash_bytes

        _refuse_source_overwrite(output, aibom_path)
        try:
            bom, data = AIBOM.load_with_bytes(aibom_path)
        except NativeFormatError as exc:
            raise click.ClickException(
                f"{neutralize(aibom_path)} is not a valid native AIBOM file. {neutralize(exc)}"
            ) from exc
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            raise click.ClickException(
                f"{neutralize(aibom_path)} is not a valid native AIBOM file."
            ) from exc
        try:
            if offline_db is not None:
                from nexus_symbiote.offline_advisories import (
                    DEFAULT_MAX_FEED_AGE_DAYS,
                    match_offline_advisories,
                )

                report, provenance = match_offline_advisories(
                    bom,
                    db_path=offline_db,
                    kev_paths=kev_paths,
                    epss_path=epss_path,
                    exclude=exclude,
                    exclude_private_origins=exclude_private_origins,
                    inventory_sha256=hash_bytes(data),
                    now=datetime.now(UTC),
                    max_feed_age_days=max_feed_age_days or DEFAULT_MAX_FEED_AGE_DAYS,
                )
                payload = report.to_dict()
                payload["sent_to_osv"] = "nothing (offline advisory bundle)"
                payload["provenance"] = provenance
            else:
                report = fetch_advisories(
                    bom,
                    exclude=exclude,
                    exclude_private_origins=exclude_private_origins,
                    dry_run=dry_run,
                    inventory_sha256=hash_bytes(data),
                )
                payload = report.to_dict()
        except (OSError, ValueError) as exc:
            raise click.ClickException(neutralize(exc)) from exc
        text = json.dumps(payload, indent=2, allow_nan=False)
        if output:
            write_cli_output(output, text)
        else:
            click.echo(json_text(text))
        if dry_run and offline_db is None:
            if report.errors:
                raise click.exceptions.Exit(1)
            return
        if not report.complete or (fail_on_advisory and report.advisories):
            raise click.exceptions.Exit(1)

    @main.command()
    @click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the trifecta and toxic-flow report JSON to this file instead of stdout.",
    )
    @click.option(
        "--fail-on-critical/--no-fail-on-critical",
        default=True,
        show_default=True,
        help="Exit with status 1 when a critical lethal-trifecta finding is present.",
    )
    @click.option(
        "--fail-on-finding/--no-fail-on-finding",
        default=False,
        show_default=True,
        help="Exit with status 1 when any trifecta, toxic-flow, or tool-shadowing finding is present.",
    )
    def trifecta(
        aibom_path: Path,
        output: Path | None,
        fail_on_critical: bool,
        fail_on_finding: bool,
    ) -> None:
        """Analyze an inventory offline for lethal trifectas, toxic flows, and tool shadowing."""
        from nexus_symbiote.trifecta import analyze_trifecta

        _refuse_source_overwrite(output, aibom_path)
        bom = _load_inventory(aibom_path)
        report = analyze_trifecta(bom)
        text = json.dumps(report.to_dict(), indent=2)
        if output:
            write_cli_output(output, text)
        else:
            click.echo(json_text(text))
        if (fail_on_finding and report.findings) or (fail_on_critical and report.has_critical):
            raise click.exceptions.Exit(1)
