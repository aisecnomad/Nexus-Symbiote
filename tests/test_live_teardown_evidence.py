"""Only successful cleanup of this launch can confirm teardown in the report."""

import sys

import pytest

from nexus_symbiote.live import verify
from tests.test_verify_live_scope import HELLO, TOOL, inventory, launcher


@pytest.mark.usefixtures("nonisolated_pinned_fixtures")
def test_verified_frozen_launcher_has_no_teardown_receipt(tmp_path, monkeypatch):
    # The ordinary local fixture completes the protocol; this interpreter cannot
    # start the subreaper wrapper when running under a frozen application.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    report = verify.verify_mcp_servers(inventory(), trusted_launchers=launcher(tmp_path))
    assert [(item.status, item.teardown) for item in report.results] == [("verified", None)]
    assert report.results[0].to_dict()["teardown"] is None


def test_protocol_observation_without_cleanup_evidence_has_no_teardown_receipt(monkeypatch):
    monkeypatch.setattr(
        verify, "fetch_observation", lambda _: verify.PinnedObservation(HELLO, [TOOL])
    )
    result = verify.verify_mcp_servers(inventory()).results[0]
    assert (result.status, result.teardown) == ("verified", None)
