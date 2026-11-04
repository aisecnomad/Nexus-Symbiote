"""Settings exported in the developer's shell must not change test outcomes."""

import os
import subprocess
import sys
from pathlib import Path

from nexus_symbiote.core.hashing import SOURCE_BINDING_KEY_ENV

ROOT = Path(__file__).resolve().parents[1]


def test_an_exported_invalid_binding_key_does_not_reach_other_tests():
    # A key accepted by an earlier build, or a short one, makes collection fail.
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("COV_CORE_")
    }
    environment[SOURCE_BINDING_KEY_ENV] = "too-short"
    node = "tests/test_scanners.py::TestMCPScanner::test_scan_mcp_json_config"
    run = subprocess.run(  # noqa: S603 - the test interpreter with fixed arguments
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", node],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert run.returncode == 0, run.stdout[-2000:]
