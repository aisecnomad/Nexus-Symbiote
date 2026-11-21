"""`export-policy --project` and the evidence pack gate under the project's own policy.

The checkout's `.nexus-symbiote.yaml` is read as `validate --project` reads it. It can
only tighten what `--project` corroborates: a malformed policy, or one that weakens a
gate, is refused in every run, and an inventory that `validate --project` rejects in CI
for a reason the policy sets, or for unsigned discovery evidence, gets no allowlist.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from nexus_symbiote.cli import main
from nexus_symbiote.utils.crypto import VerificationResult

FIXTURES = Path(__file__).parent / "fixtures"
SHADOWSCAN_REPORT = FIXTURES / "shadowscan/code-report-0.1.4.json"
ENV = {"NEXUS_SYMBIOTE_SOURCE_BINDING_KEY": "k" * 32}
_HEADER = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
WEIGHTS = struct.pack("<Q", len(_HEADER)) + _HEADER + b"\x00\x00\x80?"
WEIGHTS_SHA = hashlib.sha256(WEIGHTS).hexdigest()
MODEL = "model:models/m.safetensors"
VENDOR_MODEL = "model:vendor/models/v.safetensors"
FASTMCP_SERVER = (
    'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("demo")\n'
    '@mcp.tool()\ndef greet(name: str) -> str:\n    """Say hi."""\n    return name\n'
)
WEAKENING_REFUSAL = "--project refuses a project policy that weakens a gate"
DISCOVERY_REFUSAL = "inventory failed discovery producer verification against --project"
REPORT_SIGNER = {
    "kind": "sigstore-message-signature",
    "artifact_path": ".shadowscan/report.json",
    "bundle_path": ".shadowscan/report.sigstore.json",
    "expected_identity": "https://github.com/acme/discovery/.github/workflows/scan.yml@refs/heads/main",
    "expected_issuer": "https://token.actions.githubusercontent.com",
}


class Project:
    def __init__(self, root: Path, signers: Path, inventory: Path) -> None:
        self.root, self.signers, self.inventory = root, signers, inventory

    def write_policy(self, text: str, name: str = ".nexus-symbiote.yaml") -> None:
        (self.root / name).write_text(text, encoding="utf-8")

    def invoke(self, *args: str) -> Result:
        return CliRunner().invoke(main, list(args), env=ENV)

    def validate(self, *extra: str) -> Result:
        return self.invoke(
            "validate",
            str(self.inventory),
            "--project",
            str(self.root),
            "--signature-policy",
            str(self.signers),
            *extra,
        )

    def export_policy(self) -> Result:
        return self.invoke(
            "export-policy",
            str(self.inventory),
            "--format",
            "json",
            "--project",
            str(self.root),
            "--signature-policy",
            str(self.signers),
        )

    def crosswalk(self) -> Result:
        return self.invoke(
            "crosswalk",
            str(self.inventory),
            "--include-evidence-pack",
            "--project",
            str(self.root),
            "--signature-policy",
            str(self.signers),
        )


def _project(
    tmp_path: Path,
    models: tuple[str, ...] = ("models/m.safetensors",),
    extra: Callable[[Path], None] | None = None,
) -> Project:
    """A project whose model weights the operator pins, scanned without its own policy."""
    root = tmp_path / "proj"
    root.mkdir()
    pins = []
    for relative in models:
        weight = root / relative
        weight.parent.mkdir(parents=True, exist_ok=True)
        weight.write_bytes(WEIGHTS)
        pins.append(
            {
                "kind": "digest-pin",
                "artifact_path": relative,
                "expected_sha256": f"sha256:{WEIGHTS_SHA}",
            }
        )
    if extra is not None:
        extra(root)
    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({"version": 2, "artifacts": pins}), encoding="utf-8")
    inventory = tmp_path / "bom.json"
    scan = CliRunner().invoke(
        main,
        [
            "scan",
            str(root),
            "--no-project-policy",
            "--signature-policy",
            str(signers),
            "-o",
            str(inventory),
        ],
        env=ENV,
    )
    assert inventory.is_file(), scan.output
    return Project(root, signers, inventory)


def _allowed_models(result: Result) -> list[str]:
    assert result.exit_code == 0, result.output
    return [entry["bom_ref"] for entry in json.loads(result.stdout)["allowed_models"]]


def _vendored(root: Path) -> None:
    server = {"command": "npx", "args": ["-y", "@acme/vendored-mcp@1.0.0"]}
    (root / "vendor").mkdir(exist_ok=True)
    (root / "vendor/.mcp.json").write_text(json.dumps({"mcpServers": {"vendored": server}}))


def _shadowscan(root: Path) -> None:
    (root / ".shadowscan").mkdir()
    shutil.copy(SHADOWSCAN_REPORT, root / ".shadowscan/report.json")
    (root / ".shadowscan/report.sigstore.json").write_text("{}", encoding="utf-8")


def _verified_report_signer(project: Project, monkeypatch: pytest.MonkeyPatch) -> None:
    """Name the report in the signer policy and accept its bundle, as a real signer would."""

    def verify(artifact: str, bundle: str, identity: str, issuer: str) -> VerificationResult:
        digest = "sha256:" + hashlib.sha256(Path(artifact).read_bytes()).hexdigest()
        details = {"artifact_digest": digest}
        return VerificationResult(verified=True, identity=identity, issuer=issuer, details=details)

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_bundle", verify)
    document = json.loads(project.signers.read_text(encoding="utf-8"))
    document["artifacts"].append(REPORT_SIGNER)
    project.signers.write_text(json.dumps(document), encoding="utf-8")


def _fastmcp(root: Path) -> None:
    (root / "server.py").write_text(FASTMCP_SERVER, encoding="utf-8")


def _refused(result: Result, reason: str) -> None:
    assert result.exit_code == 1, result.output
    assert reason in result.output
    assert "permit (" not in result.stdout and "allowed_models" not in result.stdout
    assert "evidence_pack" not in result.stdout


def test_a_component_under_an_excluded_path_gets_no_permit(tmp_path):
    project = _project(tmp_path, ("models/m.safetensors", "vendor/models/v.safetensors"), _vendored)
    assert _allowed_models(project.export_policy()) == [MODEL, VENDOR_MODEL]
    project.write_policy('scan: {exclude_paths: ["vendor"]}\n')
    validate = project.validate()
    assert validate.exit_code == 1
    assert f"Supplied component has no matching local evidence: {VENDOR_MODEL}" in validate.output
    _refused(project.export_policy(), WEAKENING_REFUSAL)


def test_the_evidence_pack_corroborates_nothing_under_an_excluded_path(tmp_path):
    project = _project(tmp_path, ("models/m.safetensors", "vendor/models/v.safetensors"), _vendored)
    pack = json.loads(project.crosswalk().stdout)["evidence_pack"]
    assert [entry["bom_ref"] for entry in pack["verified_models"]] == [MODEL, VENDOR_MODEL]
    project.write_policy('scan: {exclude_paths: ["vendor"]}\n')
    _refused(project.crosswalk(), WEAKENING_REFUSAL)


def test_a_required_discovery_signature_is_enforced(tmp_path, monkeypatch):
    project = _project(tmp_path, extra=_shadowscan)
    project.write_policy("validate: {require_discovery_signature: true}\n")
    validate = project.validate("--allow-unsigned-discovery")
    assert validate.exit_code == 1
    assert "No operator signature policy entry names the ShadowScan report" in validate.output
    _refused(project.export_policy(), DISCOVERY_REFUSAL)
    _refused(project.crosswalk(), DISCOVERY_REFUSAL)
    _verified_report_signer(project, monkeypatch)
    assert project.validate().exit_code == 0
    assert _allowed_models(project.export_policy()) == [MODEL]
    pack = json.loads(project.crosswalk().stdout)["evidence_pack"]
    assert [entry["bom_ref"] for entry in pack["verified_models"]] == [MODEL]


def test_unsigned_discovery_evidence_is_refused_in_every_run_as_validate_refuses_it_in_ci(
    tmp_path, monkeypatch
):
    project = _project(tmp_path, extra=_shadowscan)
    assert project.validate().exit_code == 0
    monkeypatch.setenv("CI", "true")
    validate = project.validate()
    assert validate.exit_code == 1
    assert "Unsigned ShadowScan discovery evidence in CI" in validate.output
    _refused(project.export_policy(), DISCOVERY_REFUSAL)
    monkeypatch.delenv("CI")
    _refused(project.export_policy(), DISCOVERY_REFUSAL)
    _refused(project.crosswalk(), DISCOVERY_REFUSAL)
    _verified_report_signer(project, monkeypatch)
    assert _allowed_models(project.export_policy()) == [MODEL]


def test_a_component_of_unknown_integrity_is_left_out_not_refused(tmp_path):
    project = _project(tmp_path, extra=_fastmcp)
    validate = project.validate()
    assert validate.exit_code == 1
    assert "Status: UNKNOWN" in validate.output
    exported = project.export_policy()
    document = json.loads(exported.stdout)
    assert document["allowed_tools"] == [] and document["allowed_mcp_servers"] == []
    assert _allowed_models(exported) == [MODEL]
    assert document["allowed_models"][0]["sha256"] == WEIGHTS_SHA


def test_a_minimum_assurance_level_the_inventory_misses_is_enforced(tmp_path):
    def hosted_alias(root: Path) -> None:
        (root / "CLAUDE.md").write_text("Read-only triage.", encoding="utf-8")
        (root / "agent.yaml").write_text(
            "name: triage\ninstructions: [CLAUDE.md]\n"
            "models: {chat: {provider: example, requested_ref: latest}}\n",
            encoding="utf-8",
        )

    project = _project(tmp_path, extra=hosted_alias)
    assert MODEL in _allowed_models(project.export_policy())
    project.write_policy("validate: {minimum_assurance_level: observed}\n")
    validate = project.validate()
    assert validate.exit_code == 1
    assert "minimum observed assurance not attained" in validate.output
    _refused(project.export_policy(), "inventory failed validate.minimum_assurance_level")
    project.write_policy("validate: {minimum_assurance_level: verified}\n")
    _refused(project.export_policy(), "inventory failed validate.minimum_assurance_level")


@pytest.mark.parametrize(
    "policy",
    [
        "validate: {require_integrity: false}\n",
        "validate: {require_completeness: false}\n",
        "validate: {require_completeness: false, require_integrity: false}\n",
        "scan: {failure_mode: report-only}\n",
        'scan: {scanners: ["mcp", "model"]}\n',
        "risk: {ignore_categories: [signing_status]}\n",
        "risk: {fail_threshold: 90, warn_threshold: 30}\n",
    ],
)
@pytest.mark.parametrize("ci", [False, True])
def test_a_policy_that_weakens_a_gate_never_loosens_export_policy(
    tmp_path, monkeypatch, policy, ci
):
    project = _project(tmp_path)
    project.write_policy(policy)
    if ci:
        monkeypatch.setenv("CI", "true")
        assert project.validate().exit_code == 1
    _refused(project.export_policy(), WEAKENING_REFUSAL)
    _refused(project.crosswalk(), WEAKENING_REFUSAL)


def test_disabled_integrity_does_not_let_a_tampered_model_through(tmp_path):
    project = _project(tmp_path)
    (project.root / "models/m.safetensors").write_bytes(WEIGHTS[:-4] + b"\x00\x00\x00\x00")
    project.write_policy("validate: {require_completeness: false, require_integrity: false}\n")
    assert project.validate().exit_code == 0
    _refused(project.export_policy(), WEAKENING_REFUSAL)
    (project.root / ".nexus-symbiote.yaml").unlink()
    _refused(project.export_policy(), "inventory failed")


@pytest.mark.parametrize(
    "policy",
    [
        "output: {default_format: sarif}\n",
        "risk: {fail_threshold: 10, warn_threshold: 5}\n",
        "validate: {minimum_assurance_level: observed}\n",
        'scan: {exclude_paths: ["node_modules", "venv"]}\n',
        'version: "1.0"\n',
    ],
)
def test_a_policy_that_only_tightens_or_reports_still_corroborates(tmp_path, policy):
    project = _project(tmp_path)
    project.write_policy(policy)
    assert _allowed_models(project.export_policy()) == [MODEL]
    pack = json.loads(project.crosswalk().stdout)["evidence_pack"]
    assert pack["verification_basis"] == "project-reconciled"
    assert [entry["bom_ref"] for entry in pack["verified_models"]] == [MODEL]


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("validate: {bogus: 1}\n", "invalid or unsupported settings: validate.bogus"),
        (
            "validate: {require_integrity: 'sk-ant-secret-looking-value'}\n",
            "invalid or unsupported settings: validate.require_integrity",
        ),
        ("validate: [unterminated\n", "invalid YAML document"),
        ("- a list\n", "configuration must be a YAML mapping"),
        ("version: 1.0\n", "invalid or unsupported settings: version"),
    ],
)
def test_a_malformed_policy_fails_closed_without_quoting_its_values(tmp_path, text, reason):
    project = _project(tmp_path)
    project.write_policy(text)
    validate = project.validate()
    assert validate.exit_code == 1 and reason in validate.output
    for result in (project.export_policy(), project.crosswalk()):
        _refused(result, reason)
        assert "invalid policy" in result.output
        assert "sk-ant" not in result.output and "unterminated" not in result.output


def test_two_policy_files_fail_closed(tmp_path):
    project = _project(tmp_path)
    project.write_policy("validate: {require_discovery_signature: true}\n")
    project.write_policy("validate: {require_discovery_signature: false}\n", ".nexus-symbiote.yml")
    _refused(project.export_policy(), "keep one policy file")
    _refused(project.crosswalk(), "keep one policy file")
