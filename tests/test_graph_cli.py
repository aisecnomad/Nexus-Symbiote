"""The graph command: usage, refusals, confined output, determinism and offline operation."""

from __future__ import annotations

import json
import os
import re
import socket
import stat
from pathlib import Path

import pytest

from nexus_symbiote import modes
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.models import AgentComponent, ToolComponent
from nexus_symbiote.graph_view import SCRIPT, build_view, view_document
from nexus_symbiote.utils.terminal import OUTPUT_REFUSED
from tests.conftest import ISOLATED_NAMES, ISOLATED_PREFIXES

ROOT = Path(__file__).resolve().parents[1]
UNSET = {modes.ENV_VAR: None}


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from click.testing import CliRunner

    output = tmp_path_factory.mktemp("demo") / "demo.aibom.json"
    # A module-scoped fixture runs before the per-test isolation, so it clears the ambient names itself.
    ambient = {
        name: None
        for name in os.environ
        if name.startswith(ISOLATED_PREFIXES) or name in ISOLATED_NAMES
    }
    scanned = CliRunner().invoke(
        main,
        ["scan", str(ROOT / "examples" / "demo-agent"), "-o", str(output)],
        env={**ambient, **UNSET},
    )
    assert scanned.exit_code == 0, scanned.output
    return output


def saved(tmp_path: Path, bom: AIBOM, name: str = "bom.json") -> Path:
    path = tmp_path / name
    bom.save(path)
    return path


def write_inventory(tmp_path: Path, content: bytes) -> Path:
    path = tmp_path / "inventory.json"
    path.write_bytes(content)
    return path


def test_html_is_written_to_a_private_file_with_a_summary_on_stderr(runner, demo, tmp_path):
    output = tmp_path / "graph.html"
    result = runner.invoke(main, ["graph", str(demo), "-o", str(output)], env=UNSET)
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert result.stderr == (
        "Graph view: 11 components, 13 edges, 3 exposure paths; coverage unknown\n"
    )
    text = output.read_text(encoding="utf-8")
    assert text.startswith('<!DOCTYPE html>\n<html lang="en">')
    assert text.count("<script>") == 1 and f"<script>{SCRIPT}</script>" in text
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_html_is_never_printed_to_standard_output(runner, demo):
    result = runner.invoke(main, ["graph", str(demo)], env=UNSET)
    assert result.exit_code == 2
    assert "the HTML view is written to a file: pass -o/--output" in result.output
    assert "<html" not in result.output
    explicit = runner.invoke(main, ["graph", str(demo), "--format", "html"], env=UNSET)
    assert explicit.exit_code == 2


def test_json_goes_to_standard_output_and_matches_the_model(runner, demo):
    result = runner.invoke(main, ["graph", str(demo), "--format", "json"], env=UNSET)
    assert result.exit_code == 0, result.output
    expected = view_document(build_view(AIBOM.load(demo), max_nodes=2_000))
    assert json.loads(result.stdout) == expected
    assert result.stderr == ""


def test_json_can_be_written_to_a_file(runner, demo, tmp_path):
    output = tmp_path / "graph.json"
    result = runner.invoke(main, ["graph", str(demo), "--format", "json", "-o", str(output)])
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert json.loads(output.read_text())["format"] == "nexus-symbiote/graph-view/v1"


def test_output_is_deterministic(runner, demo, tmp_path):
    outputs = []
    for name in ("a.html", "b.html"):
        result = runner.invoke(main, ["graph", str(demo), "-o", str(tmp_path / name)])
        assert result.exit_code == 0, result.output
        outputs.append((tmp_path / name).read_bytes())
    assert outputs[0] == outputs[1]
    documents = [runner.invoke(main, ["graph", str(demo), "--format", "json"]).stdout for _ in "ab"]
    assert documents[0] == documents[1]


@pytest.mark.parametrize("output_format", ["html", "json"])
def test_the_inventory_is_never_overwritten(runner, demo, tmp_path, output_format):
    before = demo.read_bytes()
    alias = tmp_path / "alias.json"
    os.link(demo, alias)
    for target in (demo, alias):
        result = runner.invoke(
            main, ["graph", str(demo), "--format", output_format, "-o", str(target)]
        )
        assert result.exit_code == 2
        assert "output must not overwrite the source inventory" in result.output
    assert demo.read_bytes() == before


def test_output_through_a_symlinked_directory_is_refused(runner, demo, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real, target_is_directory=True)
    result = runner.invoke(main, ["graph", str(demo), "-o", str(tmp_path / "link" / "g.html")])
    assert result.exit_code == 1
    assert OUTPUT_REFUSED in result.output
    assert list(real.iterdir()) == []


def test_output_onto_a_directory_or_a_fifo_is_refused(runner, demo, tmp_path):
    (tmp_path / "dir").mkdir()
    os.mkfifo(tmp_path / "fifo")
    for target in ("dir", "fifo"):
        result = runner.invoke(main, ["graph", str(demo), "-o", str(tmp_path / target)])
        assert result.exit_code == 1, target
        assert OUTPUT_REFUSED in result.output


@pytest.mark.parametrize("value", ["0", "20001", "-1", "many"])
def test_max_nodes_outside_its_range_is_a_usage_error(runner, demo, value):
    result = runner.invoke(main, ["graph", str(demo), "--format", "json", "--max-nodes", value])
    assert result.exit_code == 2


def test_a_graph_over_max_nodes_fails_and_suggests_focus(runner, demo, tmp_path):
    output = tmp_path / "graph.html"
    result = runner.invoke(main, ["graph", str(demo), "-o", str(output), "--max-nodes", "10"])
    assert result.exit_code == 1
    assert (
        "The view would show 11 components, more than --max-nodes 10. Select part of the "
        "graph with --focus REF, or raise --max-nodes (at most 20000)."
    ) in result.output
    assert not output.exists()
    exact = runner.invoke(main, ["graph", str(demo), "--format", "json", "--max-nodes", "11"])
    assert exact.exit_code == 0


def test_focus_restricts_the_view(runner, tmp_path):
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="a1", name="one", tool_refs=["t1"]),
            ToolComponent(bom_ref="t1", name="t1"),
            AgentComponent(bom_ref="a2", name="two", tool_refs=["t2"]),
            ToolComponent(bom_ref="t2", name="t2"),
        ]
    )
    path = saved(tmp_path, bom)
    result = runner.invoke(main, ["graph", str(path), "--format", "json", "--focus", "t2"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["focus"] == "t2"
    assert sorted(node["ref"] for node in document["nodes"]) == ["a2", "t2"]
    limited = runner.invoke(
        main, ["graph", str(path), "--format", "json", "--focus", "t2", "--max-nodes", "2"]
    )
    assert limited.exit_code == 0


def test_an_unknown_focus_fails_naming_only_a_clipped_reference(runner, tmp_path):
    listed_name = "inventory-only-name"
    bom = AIBOM(components=[ToolComponent(bom_ref="t", name=listed_name)])
    path = saved(tmp_path, bom)
    focus = "missing\u202e\x1b[31m::error::" + "y" * 1_000
    result = runner.invoke(main, ["graph", str(path), "--format", "json", "--focus", focus])
    assert result.exit_code == 1
    assert "unknown component: missing\ufffd\ufffd[31m::error::yyy" in result.output
    assert listed_name not in result.output and "\x1b" not in result.output
    assert "\u202e" not in result.output
    assert len(result.output) < 400


def test_an_invalid_graph_fails_like_blast_radius(runner, tmp_path):
    bom = AIBOM(
        components=[AgentComponent(bom_ref="a", name="a")],
        dependencies=[DependencyEdge(source_ref="a", target_ref="gone", relationship="invokes")],
    )
    # Written as another producer could write it: this build refuses to save a dangling edge.
    with pytest.raises(ValueError, match="unknown component"):
        bom.save(tmp_path / "refused.json")
    document = bom.model_dump(mode="json", exclude_none=True)
    path = write_inventory(tmp_path, json.dumps(document).encode())
    result = runner.invoke(main, ["graph", str(path), "--format", "json"])
    assert result.exit_code == 1
    assert "invalid graph: invokes: dangling edge a -> gone" in result.output
    assert result.stdout == ""


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (b'{"components": [], "components": []}', "duplicate keys"),
        (b"[" * 100_000 + b"]" * 100_000, "not strict UTF-8 JSON"),
        (b'{"metadata": {"spec_version": "1.1.0"}, "components": [{"bom_ref": "<b>"}]}', "schema"),
        (b"\xff\xfe not json", "not strict UTF-8 JSON"),
        (b'{"metadata": {"spec_version": "9.0.0"}}', "not supported"),
    ],
)
def test_an_invalid_inventory_is_refused_without_quoting_it(runner, tmp_path, content, reason):
    path = write_inventory(tmp_path, content)
    result = runner.invoke(main, ["graph", str(path), "--format", "json"])
    assert result.exit_code == 1
    assert "is not a valid native AIBOM file" in result.output
    assert reason in result.output
    assert "<b>" not in result.output


def test_an_oversized_inventory_is_refused(runner, tmp_path):
    path = write_inventory(tmp_path, b" " * (16 * 1024 * 1024 + 1))
    result = runner.invoke(main, ["graph", str(path), "--format", "json"])
    assert result.exit_code == 1
    assert "16 MiB" in result.output


def test_an_inventory_behind_a_link_or_a_fifo_is_refused(runner, demo, tmp_path):
    link = tmp_path / "link.json"
    link.symlink_to(demo)
    linked = runner.invoke(main, ["graph", str(link), "--format", "json"])
    assert linked.exit_code == 1
    assert "symbolic link" in linked.output
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    special = runner.invoke(main, ["graph", str(fifo), "--format", "json"])
    assert special.exit_code == 1
    assert "not a regular file" in special.output
    directory = runner.invoke(main, ["graph", str(tmp_path), "--format", "json"])
    assert directory.exit_code == 2


def test_hostile_text_stays_inert_in_files_and_on_standard_output(runner, tmp_path):
    hostile = '</script><script>alert(1)</script>"><img src=x>\u202e##[error]::error::x'
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref=f"a:{hostile}", name=hostile, tool_refs=[f"t:{hostile}"]),
            ToolComponent(bom_ref=f"t:{hostile}", name=hostile, version=hostile),
        ],
        dependencies=[
            DependencyEdge(
                source_ref=f"a:{hostile}",
                target_ref=f"t:{hostile}",
                relationship="configured-with",
                conditions=hostile,
            )
        ],
    )
    path = saved(tmp_path, bom)
    output = tmp_path / "graph.html"
    result = runner.invoke(main, ["graph", str(path), "-o", str(output)])
    assert result.exit_code == 0, result.output
    page = output.read_text(encoding="utf-8")
    assert page.count("<script>") == 1 and "<img" not in page
    assert "\u202e" not in page and "##[" not in page
    assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img src=x&gt;" in page
    printed = runner.invoke(main, ["graph", str(path), "--format", "json"])
    assert printed.exit_code == 0
    assert "\u202e" not in printed.stdout and "##[" not in printed.stdout
    assert "##\\u005b" in printed.stdout
    assert json.loads(printed.stdout)["nodes"][0]["name"] == hostile


def test_the_command_stays_offline_even_in_live_mode(runner, demo, tmp_path, monkeypatch):
    from nexus_symbiote import graph_view

    def resolving(*args: object, **kwargs: object) -> None:
        socket.getaddrinfo("example.com", 443)

    monkeypatch.setattr(graph_view, "render_html", resolving)
    result = runner.invoke(main, ["--live", "graph", str(demo), "-o", str(tmp_path / "g.html")])
    assert result.exit_code == 1
    assert "offline mode blocked" in result.output
    assert not (tmp_path / "g.html").exists()


def test_the_documented_demo_view_matches_a_real_run(runner, demo):
    text = (ROOT / "docs" / "graph-view.md").read_text(encoding="utf-8")
    quoted = re.search(
        r"shows (\d+) components, (\d+) edges \((\d+) recorded dependency edges and (\d+) "
        r"reference fields\) and (\w+) exposure paths".replace(" ", r"\s+"),
        text,
    )
    assert quoted, "docs/graph-view.md no longer states the demo view in the expected sentence"
    result = runner.invoke(main, ["graph", str(demo), "--format", "json"], env=UNSET)
    document = json.loads(result.stdout)
    kinds = [edge["kind"] for edge in document["edges"]]
    words = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
    assert quoted.groups() == (
        str(len(document["nodes"])),
        str(len(kinds)),
        str(kinds.count("dependency")),
        str(kinds.count("reference")),
        words[len(document["exposure"]["paths"])],
    )
    stated = re.search(r"Graph view: [^\n]+", text)
    assert stated is not None
    html = runner.invoke(main, ["graph", str(demo), "-o", str(demo.parent / "g.html")])
    assert html.exit_code == 0, html.output
    assert html.stderr.strip() == stated.group(0)


def test_export_policy_cedar_rego_json_and_crosswalk_evidence_pack(runner, tmp_path):
    import hashlib
    import struct

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from nexus_symbiote.core.enums import AssuranceLevel, SerializationSafety
    from nexus_symbiote.core.models import MCPServerComponent, ModelComponent
    from nexus_symbiote.policy_export import _cedar_str, render_authorization_policy

    assert _cedar_str('a"b\\c\n\r\t\0é##vso[task.setvariable]\u202e') == (
        r'"a\"b\\c\n\r\t\0\u{e9}##vso\u{5b}task.setvariable]\u{202e}"'
    )
    with pytest.raises(ValueError, match="unsupported policy format"):
        render_authorization_policy(AIBOM(), "xml")

    bom = AIBOM(
        components=[
            ToolComponent(
                bom_ref="tool:search##vso[task.setvariable]",
                name="search",
                definition_hash="sha256:" + "11" * 32,
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            ToolComponent(
                bom_ref="tool:declared_only",
                name="declared",
                definition_hash="sha256:" + "22" * 32,
                assurance_level=AssuranceLevel.DECLARED,
            ),
            ToolComponent(
                bom_ref="tool:bad_hash",
                name="bad",
                definition_hash="not-a-sha256",
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            ModelComponent(
                bom_ref="model:modèle-1",
                name="m1",
                hashes={"sha256": "33" * 32},
                signing_status="sigstore-signed",
                serialization_safety=SerializationSafety.SAFE,
            ),
            ModelComponent(
                bom_ref="model:unsafe",
                name="unsafe",
                hashes={"sha256": "44" * 32},
                signing_status="sigstore-signed",
                serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
            ),
            ModelComponent(
                bom_ref="model:no_sha",
                name="no_sha",
                hashes={},
                signing_status="sigstore-signed",
                serialization_safety=SerializationSafety.SAFE,
            ),
            MCPServerComponent(
                bom_ref="mcp:s1",
                name="s1",
                version_pinned=True,
                assurance_level=AssuranceLevel.OBSERVED,
            ),
        ]
    )
    path = saved(tmp_path, bom)

    # A model is permitted only when the caller names it as corroborated; None permits none.
    assert "UseModel" not in render_authorization_policy(bom, "cedar")
    corroborated = frozenset({"model:modèle-1", "model:unsafe"})
    cedar_model = render_authorization_policy(bom, "cedar", corroborated_model_refs=corroborated)
    assert 'NexusSymbiote::Model::"model:mod\\u{e8}le-1"' in cedar_model
    assert "model:unsafe" not in cedar_model
    rego_model = render_authorization_policy(bom, "rego", corroborated_model_refs=corroborated)
    assert '"model:mod\\u00e8le-1": "' + "33" * 32 + '"' in rego_model

    # Usage error gates on export-policy and crosswalk.
    assert runner.invoke(main, ["export-policy", str(path), "--format", "cedar"]).exit_code == 2
    assert (
        runner.invoke(main, ["export-policy", str(path), "--signature-policy", str(path)]).exit_code
        == 2
    )
    assert (
        runner.invoke(main, ["export-policy", str(path), "--trusted-key", str(path)]).exit_code == 2
    )
    assert (
        runner.invoke(
            main, ["export-policy", str(path), "--require-attestation", str(path)]
        ).exit_code
        == 2
    )
    assert (
        runner.invoke(
            main, ["export-policy", str(path), "--include-declared", "-o", str(path)]
        ).exit_code
        == 2
    )
    assert runner.invoke(main, ["crosswalk", str(path), "--project", str(tmp_path)]).exit_code == 2
    markdown_pack = ["crosswalk", str(path), "--include-evidence-pack", "--format", "markdown"]
    assert runner.invoke(main, markdown_pack).exit_code == 2
    assert (
        runner.invoke(main, ["crosswalk", str(path), "--signature-policy", str(path)]).exit_code
        == 2
    )

    bad_file = tmp_path / "not-bom.json"
    bad_file.write_text("not-json", encoding="utf-8")
    assert (
        runner.invoke(main, ["export-policy", str(bad_file), "--include-declared"]).exit_code == 1
    )

    key_dir = tmp_path / "keys"
    key_dir.mkdir(mode=0o700)
    priv = Ed25519PrivateKey.generate()
    priv_path = key_dir / "rev.key"
    priv_path.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    priv_path.chmod(0o600)
    pub_path = key_dir / "rev.pub"
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    pub_path.chmod(0o600)
    att_path = tmp_path / "bom.att.json"
    assert (
        runner.invoke(
            main,
            [
                "attest",
                str(path),
                "--key",
                str(priv_path),
                "--purpose",
                "reviewed",
                "--out",
                str(att_path),
            ],
        ).exit_code
        == 0
    )

    cedar = runner.invoke(
        main,
        [
            "export-policy",
            str(path),
            "--format",
            "cedar",
            "--require-attestation",
            str(att_path),
            "--trusted-key",
            str(pub_path),
        ],
    )
    assert cedar.exit_code == 0, cedar.output
    assert 'NexusSymbiote::Tool::"tool:search##vso\\u{5b}task.setvariable]"' in cedar.stdout
    assert "##vso[" not in cedar.stdout
    assert "tool:declared_only" not in cedar.stdout
    # A reviewed attestation alone never permits a model on its own signing_status.
    assert "UseModel" not in cedar.stdout
    assert "model:unsafe" not in cedar.stdout

    rego = runner.invoke(
        main, ["export-policy", str(path), "--format", "rego", "--include-declared"]
    )
    assert rego.exit_code == 0, rego.output
    assert "package nexus_symbiote.authz" in rego.stdout
    assert "##vso\\u005b" in rego.stdout
    assert "##vso[" not in rego.stdout
    assert '"tool:declared_only"' in rego.stdout

    out_pol = tmp_path / "policy.json"
    json_pol = runner.invoke(
        main,
        [
            "export-policy",
            str(path),
            "--format",
            "json",
            "--require-attestation",
            str(att_path),
            "--trusted-key",
            str(pub_path),
            "-o",
            str(out_pol),
        ],
    )
    assert json_pol.exit_code == 0, json_pol.output
    parsed_pol = json.loads(out_pol.read_text(encoding="utf-8"))
    assert parsed_pol["format"] == "nexus-symbiote/authorization-policy/v1"
    assert [t["bom_ref"] for t in parsed_pol["allowed_tools"]] == [
        "tool:search##vso[task.setvariable]"
    ]
    assert parsed_pol["allowed_models"] == []

    # Wrong attestation key must fail closed.
    wrong_pub = key_dir / "wrong.pub"
    wrong_pub.write_bytes(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    wrong_pub.chmod(0o600)
    assert (
        runner.invoke(
            main,
            [
                "export-policy",
                str(path),
                "--require-attestation",
                str(att_path),
                "--trusted-key",
                str(wrong_pub),
            ],
        ).exit_code
        == 1
    )

    # Without --project, crosswalk --include-evidence-pack keeps verified_models empty.
    cw = runner.invoke(main, ["crosswalk", str(path), "--include-evidence-pack"])
    assert cw.exit_code == 0, cw.output
    pack = json.loads(cw.stdout)["evidence_pack"]
    assert pack["verification_basis"] == "unverified-supplied-bom"
    assert pack["verified_models"] == []
    assert pack["declared_signed_models"][0]["bom_ref"] == "model:modèle-1"
    assert pack["pinned_mcp_servers"][0]["bom_ref"] == "mcp:s1"

    # End-to-end --project corroboration: uncorroborated/tampered inventories fail closed,
    # and unsigned models are never permitted unless verified by --signature-policy.
    proj = tmp_path / "proj"
    (proj / "models").mkdir(parents=True)
    header_json = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    st_bytes = struct.pack("<Q", len(header_json)) + header_json + b"\x00\x00\x80?"
    model_file = proj / "models" / "m.safetensors"
    model_file.write_bytes(st_bytes)
    model_sha = hashlib.sha256(st_bytes).hexdigest()
    (proj / "server.py").write_text(
        'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("demo")\n'
        '@mcp.tool()\ndef greet(name: str) -> str:\n    """Say hi."""\n    return name\n',
        encoding="utf-8",
    )
    env = {"NEXUS_SYMBIOTE_SOURCE_BINDING_KEY": "k" * 32}
    sig_pol = tmp_path / "sig-policy.json"
    sig_pol.write_text(
        json.dumps(
            {
                "version": 2,
                "artifacts": [
                    {
                        "kind": "digest-pin",
                        "artifact_path": "models/m.safetensors",
                        "expected_sha256": f"sha256:{model_sha}",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    unsigned_bom = tmp_path / "unsigned.json"
    assert runner.invoke(main, ["scan", str(proj), "-o", str(unsigned_bom)], env=env).exit_code == 0

    scanned_bom = tmp_path / "scanned.json"
    assert (
        runner.invoke(
            main,
            ["scan", str(proj), "--signature-policy", str(sig_pol), "-o", str(scanned_bom)],
            env=env,
        ).exit_code
        == 0
    )

    # A BOM claiming policy verification fails closed when --signature-policy is omitted.
    assert (
        runner.invoke(
            main,
            ["export-policy", str(scanned_bom), "--format", "json", "--project", str(proj)],
            env=env,
        ).exit_code
        == 1
    )

    # Without --signature-policy on an unsigned scan, neither static-declared tools nor
    # unsigned models are permitted under --verified-only.
    no_pol_json = runner.invoke(
        main,
        ["export-policy", str(unsigned_bom), "--format", "json", "--project", str(proj)],
        env=env,
    )
    assert no_pol_json.exit_code == 0, no_pol_json.output
    no_pol_doc = json.loads(no_pol_json.stdout)
    assert no_pol_doc["allowed_tools"] == []
    assert no_pol_doc["allowed_models"] == []

    # With --signature-policy, the corroborated SafeTensors model is permitted while static
    # unhashed source declarations remain excluded.
    with_pol_json = runner.invoke(
        main,
        [
            "export-policy",
            str(scanned_bom),
            "--format",
            "json",
            "--project",
            str(proj),
            "--signature-policy",
            str(sig_pol),
        ],
        env=env,
    )
    assert with_pol_json.exit_code == 0, with_pol_json.output
    with_pol_doc = json.loads(with_pol_json.stdout)
    assert with_pol_doc["allowed_tools"] == []
    assert len(with_pol_doc["allowed_models"]) == 1

    cw_corroborated = runner.invoke(
        main,
        [
            "crosswalk",
            str(scanned_bom),
            "--include-evidence-pack",
            "--project",
            str(proj),
            "--signature-policy",
            str(sig_pol),
        ],
        env=env,
    )
    assert cw_corroborated.exit_code == 0, cw_corroborated.output
    cw_pack = json.loads(cw_corroborated.stdout)["evidence_pack"]
    assert len(cw_pack["verified_models"]) == 1

    # Injecting an uncorroborated tool or tampering with the model on disk causes export-policy
    # --verified-only --project to exit 1 without emitting any permit!
    assert (
        runner.invoke(main, ["export-policy", str(path), "--project", str(proj)], env=env).exit_code
        == 1
    )
    model_file.write_bytes(st_bytes[:-4] + b"\x00\x00\x00\x00")
    tampered = runner.invoke(
        main,
        [
            "export-policy",
            str(scanned_bom),
            "--project",
            str(proj),
            "--signature-policy",
            str(sig_pol),
        ],
        env=env,
    )
    assert tampered.exit_code == 1
    assert "permit (" not in tampered.stdout


def test_policy_export_boundary_errors_and_graph_guards(
    runner, tmp_path: Path, monkeypatch
) -> None:
    import click
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from nexus_symbiote import policy_export
    from nexus_symbiote.core.aibom import DependencyEdge

    outside = tmp_path / "outside"
    outside.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    escape_link = work / "escape"
    escape_link.symlink_to(outside)
    monkeypatch.chdir(work)
    with pytest.raises(click.BadParameter, match="symbolic link"):
        policy_export.resolve_project_root(Path("escape"), label="--project")
    abs_link = tmp_path / "abs_link"
    abs_link.symlink_to(outside)
    assert policy_export.resolve_project_root(abs_link, label="--project") == outside.resolve()

    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "short")
    with pytest.raises(click.UsageError, match="NEXUS_SYMBIOTE_SOURCE_BINDING_KEY"):
        policy_export.require_binding_key()
    monkeypatch.delenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", raising=False)

    bad_sig = tmp_path / "bad-sig.json"
    bad_sig.write_text("{}", encoding="utf-8")
    with pytest.raises(click.ClickException):
        policy_export.load_signer_policies(bad_sig, outside)

    subject = work / "sub.json"
    subject.write_text("{}", encoding="utf-8")
    env_file = work / "sub.att.json"
    env_file.write_text("{}", encoding="utf-8")
    bad_key = tmp_path / "bad.pub"
    bad_key.write_text("not-pem", encoding="utf-8")
    with pytest.raises(click.ClickException, match="key-invalid"):
        policy_export.verify_file_attestation(
            subject, env_file, trusted_keys=(bad_key,), purpose="reviewed"
        )

    priv = Ed25519PrivateKey.generate()
    pub_path = tmp_path / "good.pub"
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    missing_env = work / "missing.att.json"
    with pytest.raises(click.ClickException, match="input-unreadable"):
        policy_export.verify_file_attestation(
            subject, missing_env, trusted_keys=(pub_path,), purpose="reviewed"
        )

    big_env = work / "big.att.json"
    big_env.write_bytes(b"x" * (policy_export.attestation.MAX_ENVELOPE_BYTES + 1))
    with pytest.raises(click.ClickException, match="input-too-large"):
        policy_export.verify_file_attestation(
            subject, big_env, trusted_keys=(pub_path,), purpose="reviewed"
        )

    with pytest.raises(click.ClickException, match="input-too-large"):
        policy_export.verify_file_attestation(
            subject,
            env_file,
            trusted_keys=(pub_path,),
            purpose="reviewed",
            subject_bytes=b"x" * (policy_export.MAX_SUBJECT_BYTES + 1),
        )

    with pytest.raises(click.ClickException):
        policy_export.verify_file_attestation(
            subject, env_file, trusted_keys=(pub_path,), purpose="reviewed"
        )

    # Invalid dependency graph fails both render_authorization_policy and CLI export-policy.
    bad_graph_bom = AIBOM(
        dependencies=[
            DependencyEdge(
                source_ref="missing:a", target_ref="missing:b", relationship="depends-on"
            )
        ]
    )
    with pytest.raises(ValueError, match="invalid graph"):
        policy_export.render_authorization_policy(bad_graph_bom, "json", verified_only=False)
    bad_graph_path = work / "bad-graph.json"
    bad_graph_path.write_text(
        json.dumps(bad_graph_bom.model_dump(mode="json", exclude_none=True)),
        encoding="utf-8",
    )
    assert (
        runner.invoke(main, ["export-policy", str(bad_graph_path), "--include-declared"]).exit_code
        == 1
    )

    # Integrity failure branch and discovery-producer failure branch in corroborate_against_project.
    from nexus_symbiote.validators.completeness import CompletenessReport
    from nexus_symbiote.validators.integrity import IntegrityIssue, IntegrityReport

    monkeypatch.setattr(
        "nexus_symbiote.validators.completeness.CompletenessValidator.validate_against_project",
        lambda *_a, **_kw: CompletenessReport(is_complete=True, basis="project"),
    )
    monkeypatch.setattr(
        "nexus_symbiote.validators.integrity.IntegrityValidator.validate",
        lambda *_a, **_kw: IntegrityReport(
            issues=[IntegrityIssue(component_ref="x", category="c", detail="d", severity="error")],
            omitted_severities={"error"},
        ),
    )
    with pytest.raises(click.ClickException, match="integrity validation"):
        policy_export.corroborate_against_project(AIBOM(), outside)

    monkeypatch.setattr(
        "nexus_symbiote.validators.integrity.IntegrityValidator.validate",
        lambda *_a, **_kw: IntegrityReport(hashes_verified=1),
    )
    monkeypatch.setattr(
        "nexus_symbiote.validators.completeness.discovery_signature_required",
        lambda *_a, **_kw: True,
    )
    monkeypatch.setattr(
        "nexus_symbiote.validators.completeness.discovery_producer_check",
        lambda *_a, **_kw: ("failed", ["unsigned discovery"]),
    )
    with pytest.raises(click.ClickException, match="discovery producer"):
        policy_export.corroborate_against_project(AIBOM(), outside)
