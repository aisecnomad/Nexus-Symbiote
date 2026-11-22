"""Exercise the separate scopes for accepting root and nested Git metadata."""

import pytest

from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.utils.confined import ROOT_GIT_METADATA
from scripts import verify_staged_policy
from scripts.run_action import _default_exclusions


@pytest.mark.parametrize(
    ("acceptance", "paths"),
    [(ROOT_GIT_METADATA, [".git"]), (".git", [".git", "library/.git"])],
)
def test_nested_gitfile_requires_explicit_scope(tmp_path, acceptance, paths):
    root_metadata = tmp_path / ".git"
    root_metadata.mkdir()
    (root_metadata / "HEAD").write_text("ref: refs/heads/main\n")
    submodule = tmp_path / "library"
    submodule.mkdir()
    (submodule / ".git").write_text("gitdir: ../.git/modules/library\n")

    scanner = MCPScanner()
    scanner.configure(accept_default_excludes=_default_exclusions(acceptance))
    result = scanner.scan(tmp_path)

    assert result.accepted_default_exclusions == paths
    if acceptance == ROOT_GIT_METADATA:
        assert any("library/.git" in reason for reason in result.surfaces_excluded)
    else:
        assert not result.surfaces_excluded
    assert not result.scan_failures


@pytest.mark.parametrize("kind", ["invalid", "directory", "symlink"])
def test_explicit_gitfile_acceptance_still_checks_the_file_shape(tmp_path, kind):
    nested = tmp_path / "library"
    nested.mkdir()
    git_entry = nested / ".git"
    if kind == "invalid":
        git_entry.write_text("A regular project file.\n")
    elif kind == "directory":
        git_entry.mkdir()
        (git_entry / "HEAD").write_text("ref: refs/heads/main\n")
    else:
        (nested / "marker").write_text("gitdir: metadata\n")
        git_entry.symlink_to("marker")

    scanner = MCPScanner()
    scanner.configure(accept_default_excludes=(".git",))
    result = scanner.scan(tmp_path)

    assert not result.accepted_default_exclusions
    assert any("library/.git" in reason for reason in result.surfaces_excluded)


def test_staged_verifier_keeps_the_root_only_default(tmp_path):
    project = tmp_path / "checkout"
    project.mkdir()
    (project / "AGENTS.md").write_text("Use sentence case for headings.\n")
    (project / ".git").mkdir()
    (project / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    module = project / "library"
    module.mkdir()
    (module / ".git").write_text("gitdir: ../.git/modules/library\n")
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: '1.0'\n")

    code, output = verify_staged_policy.run_staged_gate(project, policy, allow_unsigned=True)
    assert code == 1 and "library/.git" in output
    code, output = verify_staged_policy.run_staged_gate(
        project, policy, allow_unsigned=True, accept_default_excludes=(".git",)
    )
    assert code == 0, output
