"""Supply-chain drift signals from MCP fingerprints and connection declarations."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import TOOL_DEFINITION_HASH_VERSION
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.diff.differ import AIBOMDiffer


def document(digest, version):
    return AIBOM(
        components=[
            ToolComponent(
                bom_ref="tool:t", name="t", definition_hash=digest, definition_hash_version=version
            )
        ]
    )


def test_current_fingerprint_identical_is_not_drift():
    first = document("sha256:" + "a" * 64, TOOL_DEFINITION_HASH_VERSION)
    second = document("sha256:" + "a" * 64, TOOL_DEFINITION_HASH_VERSION)
    assert not AIBOMDiffer().diff(first, second).has_changes


def test_current_fingerprint_mutation_is_critical():
    result = AIBOMDiffer().diff(
        document("sha256:" + "a" * 64, TOOL_DEFINITION_HASH_VERSION),
        document("sha256:" + "b" * 64, TOOL_DEFINITION_HASH_VERSION),
    )
    assert result.security_alerts[0]["severity"] == "critical"
    assert result.components_modified[0].severity == "critical"


def test_legacy_profile_requires_reapproval_even_when_digest_looks_equal():
    for legacy in [None, "rfc8785-jcs-v1"]:
        result = AIBOMDiffer().diff(
            document("sha256:" + "a" * 64, legacy),
            document("sha256:" + "a" * 64, TOOL_DEFINITION_HASH_VERSION),
        )
        assert result.has_changes
        assert result.components_modified[0].severity == "high"
        assert "re-approve" in result.components_modified[0].details[0]


def test_changed_digest_under_one_legacy_profile_is_a_rug_pull():
    # Both digests come from one named serializer, so they are comparable: a change is
    # a changed descriptor, not an incompatible profile.
    result = AIBOMDiffer().diff(
        document("sha256:" + "a" * 64, "rfc8785-jcs-v1"),
        document("sha256:" + "b" * 64, "rfc8785-jcs-v1"),
    )
    assert result.components_modified[0].severity == "critical"
    assert result.components_modified[0].details == [
        "Tool definition hash changed — possible rug-pull attack."
    ]
    for old_version, new_version in ((None, None), (None, "rfc8785-jcs-v1")):
        unnamed = AIBOMDiffer().diff(
            document("sha256:" + "a" * 64, old_version),
            document("sha256:" + "b" * 64, new_version),
        )
        assert unnamed.components_modified[0].severity == "high"
        assert "incompatible" in unnamed.components_modified[0].details[0]


def test_mcp_endpoint_substitution_after_scan(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    runner = CliRunner()
    snapshots = []
    for index, host in enumerate(("trusted.example", "trusted.example", "attacker.example")):
        config = {"mcpServers": {"payments": {"url": f"https://{host}/mcp?token=private-value"}}}
        (project / ".mcp.json").write_text(json.dumps(config))
        path = tmp_path / f"snapshot-{index}.json"
        result = runner.invoke(
            main,
            [
                "scan",
                str(project),
                "--scanner",
                "mcp",
                "--report-only",
                "--no-project-policy",
                "-o",
                str(path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "private-value" not in path.read_text()
        snapshots.append(path)

    def compare(left, right, *flags, expected_exit=0):
        result = runner.invoke(main, ["diff", str(left), str(right), "--json-output", *flags])
        assert result.exit_code == expected_exit, result.output
        return json.loads(result.output)

    identical = compare(snapshots[0], snapshots[1], "--fail-on-alert", expected_exit=1)
    assert identical["has_changes"]
    assert "unbound" in identical["components_modified"][0]["details"][0]
    changed = compare(snapshots[1], snapshots[2], "--no-fail-on-alert")
    assert compare(snapshots[1], snapshots[2], "--fail-on-alert", expected_exit=1) == changed
    assert changed["has_changes"]
    assert changed["total_changes"] == 1
    modified = changed["components_modified"][0]
    assert modified["name"] == "payments"
    assert "endpoint" in modified["details"][0]
    assert changed["security_alerts"][0]["severity"] == "critical"
    assert changed["security_alerts"][0]["component"] == modified["bom_ref"]
    args = ["diff", str(snapshots[1]), str(snapshots[2])]
    report = runner.invoke(main, [*args, "--no-fail-on-alert"])
    gated = runner.invoke(main, args)
    assert report.exit_code == 0 and gated.exit_code == 1
    assert gated.output == report.output
    assert "MCP server endpoint changed" in gated.output


@pytest.mark.parametrize("field", ["endpoint_url", "transport", "command"])
def test_mcp_connection_drift_does_not_echo_untrusted_values(field):
    server = MCPServerComponent(bom_ref="server:payments", name="payments")
    old = server.model_copy(update={field: "private-old-value"})
    new = server.model_copy(update={field: "private-new-value"})
    for replacement in (new, server):
        result = AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[replacement]))
        assert result.security_alerts[0]["severity"] == "critical"
        assert "private-" not in json.dumps(result.to_dict())
