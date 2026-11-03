"""Run the security acceptance cases against the exact wheel installed by pip."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from importlib.metadata import distribution
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

import nexus_symbiote

TESTS = Path(__file__).resolve().parents[1] / "tests"
CASES = (
    "test_scoped_collection.py::test_default_baseline_with_no_external_report",
    "test_scoped_collection.py::test_complete_producer_report_preserves_partial_projection",
    "test_project_reconciliation.py::test_cli_rejects_omitted_instruction_with_forged_complete_coverage",
    "test_project_reconciliation.py::test_cli_rejects_forged_discovery_projection_in_combined_bom",
    "test_project_reconciliation.py::test_known_package_url_cannot_be_replaced_with_another_package",
    "test_mcp_source_binding.py::test_changed_launcher_rejects_unchanged_baseline",
    "test_mcp_source_binding.py::test_self_consistent_replacement_descriptor_is_not_source_corroboration",
    "test_scanner_error_redaction.py::test_invalid_model_config_retains_artifact_and_safe_failure_location",
    "test_ide_permission_semantics.py::test_cli_does_not_report_unrestricted_shell_declaration_as_clean",
    "test_shadowscan_relationships.py::test_project_reconciliation_binds_imported_dependency_claims",
    "test_diff_profiles.py::test_mcp_endpoint_substitution_after_scan",
    "test_action_artifact_redaction.py::test_staged_artifact_omits_descriptor_credential",
    "test_descriptor_redaction.py",
    "test_mcp_launcher_identity.py",
    "test_local_projection_gates.py",
    "test_shadowscan_bridge_security.py::test_import_ignores_supplier_policy",
    "test_runtime_authorization.py::test_revoked_trust_signer_cannot_reinstate_itself",
    "test_runtime_authorization.py::test_revocation_during_final_authentication_denies_pending_invocation",
    "test_export_conformance.py::test_spdx_aggregation_keeps_revisions_and_references_distinct",
    "test_projection_integrity.py",
)


class RequireExecution:
    """A skipped regression cannot approve a release candidate."""

    def __init__(self) -> None:
        self.skipped: list[str] = []

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.skipped:
            self.skipped.append(report.nodeid)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    wheel = parser.parse_args().wheel
    with wheel.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    installed = distribution("nexus-symbiote")
    direct_url = json.loads(installed.read_text("direct_url.json") or "{}")
    installed_hash = direct_url.get("archive_info", {}).get("hashes", {}).get("sha256")
    origin = Path(nexus_symbiote.__file__).resolve()
    located_init = Path(str(installed.locate_file("nexus_symbiote/__init__.py"))).resolve()
    if not sys.flags.isolated or digest != installed_hash or origin != located_init:
        parser.error("use python -I and pip-install the exact wheel in the test environment")
    print(f"Testing {wheel.name} sha256={digest} from {origin}", flush=True)

    with TemporaryDirectory(prefix="symbiote-wheel-check-") as scratch:
        tests = Path(scratch) / "tests"
        tests.mkdir()
        shutil.copyfile(TESTS / "__init__.py", tests / "__init__.py")
        for filename in {node.split("::", 1)[0] for node in CASES}:
            shutil.copyfile(TESTS / filename, tests / filename)
        shutil.copytree(TESTS / "fixtures", tests / "fixtures")
        scripts = tests.parent / "scripts"
        scripts.mkdir()
        shutil.copyfile(TESTS.parent / "scripts/run_action.py", scripts / "run_action.py")
        previous = Path.cwd()
        try:
            os.chdir(tests)
            os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
            required = RequireExecution()
            status = pytest.main(["-v", "--import-mode=importlib", *CASES], plugins=[required])
            if required.skipped:
                print(f"Required wheel checks skipped: {required.skipped}", file=sys.stderr)
                return 1
            return int(status)
        finally:
            os.chdir(previous)


if __name__ == "__main__":
    raise SystemExit(main())
