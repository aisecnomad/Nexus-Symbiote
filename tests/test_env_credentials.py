"""`.env` findings name the key and vendor. They do not name or hash the value."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import env_credentials
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.credential_allowlist import bind_credential_allowlist, load_credential_allowlist
from nexus_symbiote.env_credentials import MAX_ENV_LINES, apply_env_credential_findings
from nexus_symbiote.generators.sarif import SARIFGenerator

_SAMPLE = "sk-proj-thisisfake0123456789ab"


def _bom(tmp_path: Path, name: str = "notes.md") -> PromptComponent:
    (tmp_path / name).write_text("notes\n", encoding="utf-8")
    return PromptComponent(bom_ref="prompt:notes", name="notes", source_path=name)


def test_an_env_assignment_names_the_key_and_vendor_not_the_value(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        f'# comment\n\nexport OPENAI_API_KEY="{_SAMPLE}"\nPORT=3000\n',
        encoding="utf-8",
    )
    notes = _bom(tmp_path)
    added = apply_env_credential_findings(AIBOM(components=[notes]), tmp_path)
    assert added == 2
    rendered = " ".join(risk.detail for risk in notes.risks)
    assert ".env:3: OPENAI_API_KEY holds an openai credential." in rendered
    assert ".env:4: PORT holds an unspecified credential." in rendered
    assert _SAMPLE not in rendered
    assert "sha256:" not in rendered


def test_a_template_uses_the_vendor_shape_digest(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(f"OPENAI_API_KEY={_SAMPLE}\n", encoding="utf-8")
    (tmp_path / ".env.sample").write_text("PORT=1\n", encoding="utf-8")
    notes = _bom(tmp_path)
    added = apply_env_credential_findings(AIBOM(components=[notes]), tmp_path)
    assert added == 1
    detail = notes.risks[0].detail
    assert detail.startswith(".env.example:1: a vendor token shape is committed (value unbound).")
    assert _SAMPLE not in detail


def test_a_mark_inside_the_value_still_names_the_vendor(tmp_path: Path) -> None:
    marked = "sk-proj-thisis" + "\u200b" + "fake0123456789ab"
    (tmp_path / "svc" / ".env").parent.mkdir()
    (tmp_path / "svc" / ".env").write_text(f"OPENAI_API_KEY={marked}\n", encoding="utf-8")
    notes = _bom(tmp_path)
    added = apply_env_credential_findings(AIBOM(components=[notes]), tmp_path)
    assert added == 1
    assert notes.risks[0].detail == "svc/.env:1: OPENAI_API_KEY holds an openai credential."
    assert marked not in notes.risks[0].detail
    assert "\u200b" not in notes.risks[0].detail


def test_a_non_utf8_env_and_a_huge_env_fail_closed(tmp_path: Path) -> None:
    (tmp_path / ".env").write_bytes(b"\xff" + _SAMPLE.encode())
    notes = _bom(tmp_path)
    failures: list[str] = []
    assert (
        apply_env_credential_findings(AIBOM(components=[notes]), tmp_path, failures=failures) == 0
    )
    assert notes.risks == []
    assert failures == ["an env file: env credentials were not read (not UTF-8)"]
    assert _SAMPLE not in failures[0]

    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / ".env").write_text("A=1\n" * (MAX_ENV_LINES + 1), encoding="utf-8")
    failures.clear()
    assert (
        apply_env_credential_findings(AIBOM(components=[notes]), tmp_path, failures=failures) == 0
    )
    assert any("line bound" in failure for failure in failures)
    assert _SAMPLE not in " ".join(failures)


def test_keys_are_checked_against_all_assignment_values_before_export(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "SAME_LABEL=SAME_LABEL\nA_SHORT_KEY=one\nPUBLIC_NAME=two\n", encoding="utf-8"
    )
    (tmp_path / ".env.local").write_text(
        'FIRST="SHORT" # inert label\nSECOND=PUBLIC_NAME # another label\n', encoding="utf-8"
    )
    notes = _bom(tmp_path)
    assert apply_env_credential_findings(AIBOM(components=[notes]), tmp_path) == 5
    details = [risk.detail for risk in notes.risks]
    assert all("a key name holds" in line for line in details[:3])
    assert "FIRST holds" in details[3] and "SECOND holds" in details[4]
    assert all(
        name not in notes.model_dump_json() for name in ("SAME_LABEL", "SHORT", "PUBLIC_NAME")
    )


def test_env_aliases_preserve_store_and_template_policies(tmp_path: Path) -> None:
    (tmp_path / ".env.local").write_text("PORT=3000\n", encoding="utf-8")
    (tmp_path / ".env").symlink_to(".env.local")
    (tmp_path / ".env.sample").symlink_to(".env.local")
    notes = _bom(tmp_path)
    failures: list[str] = []
    assert (
        apply_env_credential_findings(AIBOM(components=[notes]), tmp_path, failures=failures) == 2
    )
    assert failures == ["an env file: env symlink crosses the file's credential policy"]
    assert [r.detail for r in notes.risks] == [
        "an env file:1: a key name holds an unspecified credential.",
        "an env file:1: a key name holds an unspecified credential.",
    ]


def test_project_gates_corroborate_env_findings_and_report_collection_failures(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Be helpful.\n", encoding="utf-8")
    env_file = project / ".env"
    env_file.write_text("PORT=3000\n", encoding="utf-8")
    out = tmp_path / "bom.json"
    runner = CliRunner()
    scanned = runner.invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(out)]
    )
    assert scanned.exit_code == 0, scanned.output
    assert any("PORT holds" in r.detail for c in AIBOM.load(out).components for r in c.risks)
    common = ["--no-project-policy", "--project", str(project), str(out)]
    for command in ("validate", "risk"):
        result = runner.invoke(main, [command, "--json-output", *common])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["assessment_basis"] == "project-reconciled"

    env_file.write_bytes(b"\xff")
    for command in ("validate", "risk"):
        result = runner.invoke(main, [command, *common])
        assert result.exit_code == 1, result.output
        assert "env credentials were not read (not UTF-8)" in result.output


def test_a_path_allowlist_suppresses_the_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={_SAMPLE}\n", encoding="utf-8")
    (tmp_path / ".nexus-symbiote-credential-allowlist.yaml").write_text(
        'allow:\n  - path: ".env"\n    reason: "Local fixture."\n',
        encoding="utf-8",
    )
    allowlist, error = load_credential_allowlist(tmp_path)
    assert error is None
    notes = _bom(tmp_path)
    with bind_credential_allowlist(allowlist):
        added = apply_env_credential_findings(AIBOM(components=[notes]), tmp_path)
    assert added == 0
    assert notes.risks == []


def test_env_locations_use_all_values_even_from_later_allowed_files(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "field study").mkdir()
    (project / "field study" / ".env").write_text("ALPHA=blue\nZONE=north\n")
    (project / "z").mkdir()
    (project / "z" / ".env").write_text('LABEL="field study"\n')
    (project / "z" / ".env.example").write_text("EMPTY=\n")
    (project / ".nexus-symbiote-credential-allowlist.yaml").write_text(
        'allow:\n  - path: "z/.env"\n    reason: "Reference configuration."\n'
    )
    allowlist, error = load_credential_allowlist(project)
    assert error is None
    notes = _bom(project)
    inventory = AIBOM(components=[notes])
    with bind_credential_allowlist(allowlist):
        assert apply_env_credential_findings(inventory, project) == 2
    assert all(r.detail.startswith("an env file:") for r in notes.risks)
    assert "ALPHA holds" in notes.risks[0].detail
    assert "field study" not in inventory.to_native_json()
    assert "field study" not in json.dumps(SARIFGenerator().generate(inventory))


def test_env_gaps_and_failures_keep_locations_private(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("REGION=map-west\n")
    skipped = tmp_path / "map-west"
    skipped.mkdir()
    (skipped / "notes").write_text("notes")
    inventory = AIBOM(components=[_bom(tmp_path)])
    failures: list[str] = []
    gaps: list[str] = []
    assert (
        apply_env_credential_findings(
            inventory, tmp_path, failures=failures, exclusions=gaps, exclude_paths=[skipped]
        )
        == 1
    )
    assert not failures
    assert gaps == ["env path excluded during collection"]
    assert ".env:1: REGION holds" in inventory.components[0].risks[0].detail

    (skipped / ".env").write_bytes(b"\xff")
    failures.clear()
    assert apply_env_credential_findings(inventory, tmp_path, failures=failures) == 1
    assert failures == ["an env file: env credentials were not read (not UTF-8)"]
    assert inventory.components[0].risks[-1].detail.startswith("an env file:1: a key name holds")


def test_env_display_budget_withholds_labels_but_preserves_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(env_credentials, "MAX_ENV_LINES", 1)
    (tmp_path / ".env").write_text("ONE=first\n")
    (tmp_path / ".env.local").write_text("TWO=second\n")
    notes = _bom(tmp_path)
    assert apply_env_credential_findings(AIBOM(components=[notes]), tmp_path) == 2
    assert all(r.detail.startswith("an env file:1: a key name holds") for r in notes.risks)


def test_shared_walk_failures_remain_private_and_do_not_hide_new_gaps(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / ".env").write_text("ZONE=north\n")
    notes = _bom(root)
    bom = AIBOM(components=[notes])
    first = root / "ordinary-link"
    first.symlink_to(tmp_path / "outside")
    published = "ordinary-link: symlink target is absolute"
    generic = "env collection could not safely read every path"

    for recorded, expected in (([], [generic]), ([published], [published])):
        assert apply_env_credential_findings(bom, root, failures=recorded) == 1
        assert recorded == expected
        assert notes.risks[-1].detail.startswith("an env file:1: a key name holds")

    # Replay's sink starts empty, and only failures independently observed on the
    # local project can satisfy the diagnostic. An additional gap still fails.
    local: list[str] = []
    assert apply_env_credential_findings(bom, root, failures=local, prior_failures={published}) == 1
    assert local == []
    (root / "north").symlink_to(tmp_path / "another")
    assert apply_env_credential_findings(bom, root, failures=local, prior_failures={published}) == 1
    assert local == [generic]
