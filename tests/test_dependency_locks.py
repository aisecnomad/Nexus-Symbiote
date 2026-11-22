"""scripts/check_locks.py: the locks agree with pyproject.toml, with each other and with the floors."""

from __future__ import annotations

import re
import shutil
import tomllib
from pathlib import Path

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from tests.support import ROOT, load_script

locks = load_script("check_locks")
FILES = ("pyproject.toml", locks.CI_LOCK, locks.ACTION_LOCK, locks.FLOOR_LOCK)


@pytest.fixture
def checkout(tmp_path):
    for name in FILES:
        shutil.copyfile(ROOT / name, tmp_path / name)
    return tmp_path


def edit(path, old, new):
    text = path.read_text()
    assert old in text, old
    path.write_text(text.replace(old, new, 1))


def test_the_committed_locks_agree_with_pyproject_and_each_other():
    assert locks.check(ROOT) == []


def test_a_wildcard_floor_is_reported_as_no_bound_instead_of_crashing(checkout):
    edit(checkout / "pyproject.toml", '"click>=8.2.1,<9"', '"click==8.*"')
    assert "pyproject.toml: click declares no lower bound to test" in locks.check(checkout)


def test_regeneration_options_need_regenerate(capsys):
    with pytest.raises(SystemExit):
        locks.main(["--exclude-newer", "2026-11-03T00:00:00Z"])
    assert "need --regenerate" in capsys.readouterr().err


def test_every_runtime_floor_is_the_version_the_floor_lock_tests():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    floor = locks.read_lock(ROOT, locks.FLOOR_LOCK)
    for requirement in [
        *locks.runtime_requirements(pyproject),
        *locks.build_requirements(pyproject),
    ]:
        name = locks.canonicalize_name(requirement.name)
        assert floor.versions(name) == {locks._lower_bound(requirement)}, name
    # The suite reads CliRunner's separate stderr, which needs click 8.2.
    assert floor.versions("click") == {Version("8.2.1")}


def test_dependabot_never_proposes_a_tree_sitter_past_the_reviewed_range():
    # tree-sitter 0.26 dropped the parse timeout that bounds untrusted TypeScript (#91), so
    # no release from the declared upper bound on may be proposed, whatever it is numbered.
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    declared = next(
        Requirement(entry)
        for entry in pyproject["project"]["dependencies"]
        if Requirement(entry).name == "tree-sitter"
    )
    bound = Version(next(spec.version for spec in declared.specifier if spec.operator == "<"))
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    (pip,) = (update for update in config["updates"] if update["package-ecosystem"] == "pip")
    ignored = [
        SpecifierSet(versions)
        for rule in pip["ignore"]
        if rule["dependency-name"] == "tree-sitter"
        for versions in rule["versions"]
    ]
    later = (f"{bound.major}.{bound.minor}.9", f"{bound.major}.{bound.minor + 1}.0", "99.0.0")
    for candidate in (str(bound), *later):
        assert any(Version(candidate) in versions for versions in ignored), candidate


def test_a_range_change_without_regenerated_locks_fails(checkout):
    edit(checkout / "pyproject.toml", '"click>=8.2.1,<9"', '"click>=8.2.1,<10"')
    errors = locks.check(checkout)
    assert any("dependency declarations changed" in error for error in errors)


def test_a_raised_floor_without_a_regenerated_floor_lock_fails(checkout):
    edit(checkout / "pyproject.toml", '"click>=8.2.1,<9"', '"click>=8.3,<9"')
    errors = locks.check(checkout)
    assert any("click==8.2.1 is outside" in error for error in errors)


def test_a_declared_floor_that_the_resolution_cannot_use_fails(checkout):
    # pydantic 2.10 is what an earlier release declared; the sigstore extra needs 2.12.
    edit(checkout / "pyproject.toml", '"pydantic>=2.12,<3"', '"pydantic>=2.10,<3"')
    errors = locks.check(checkout)
    assert any("pydantic declares 2.10 as its floor" in error for error in errors)


def test_an_action_pin_that_differs_from_the_reviewed_ci_pin_fails(checkout):
    action = checkout / locks.ACTION_LOCK
    text = action.read_text()
    first_hash = re.search(r"--hash=sha256:([0-9a-f]{64})", text)[1]
    action.write_text(text.replace(first_hash, "0" * 64, 1))
    assert any("differs from requirements-ci.lock" in e for e in locks.check(checkout))


def test_a_test_tool_in_the_action_runtime_fails(checkout):
    ci = locks.read_lock(checkout, locks.CI_LOCK)
    pytest_pin = ci.pins["pytest"][0]
    block = f"pytest=={pytest_pin.version} \\\n" + " \\\n".join(
        f"    --hash=sha256:{value}" for value in sorted(pytest_pin.hashes)
    )
    with (checkout / locks.ACTION_LOCK).open("a") as stream:
        stream.write(block + "\n")
    assert any("test tool pytest" in e for e in locks.check(checkout))


def test_a_floor_test_tool_must_match_its_ci_version(checkout):
    floor = checkout / locks.FLOOR_LOCK
    text = floor.read_text()
    version = locks.read_lock(checkout, locks.FLOOR_LOCK).pins["hypothesis"][0].version
    floor.write_text(text.replace(f"hypothesis=={version}", "hypothesis==6.0.0", 1))
    assert any("test tool hypothesis differs" in e for e in locks.check(checkout))


@pytest.mark.parametrize(
    "lock,message",
    [
        ("annotated-types>=0.8.0 \\\n    --hash=sha256:" + "a" * 64 + "\n", "not one exact pin"),
        ("annotated-types==0.8.0\n", "no sha256 hash"),
        ("annotated-types==0.8.0 \\\n    --index-url https://example.invalid\n", "no sha256"),
        (
            "annotated-types==0.8.0 \\\n    --hash=sha256:"
            + "a" * 64
            + " \\\n    --hash=sha512:"
            + "b" * 128
            + "\n",
            "no sha256 hash or an option",
        ),
        (
            "annotated-types==0.8.0 \\\n    --hash=sha256:"
            + "a" * 64
            + " \\\n    --hash=sha384:"
            + "b" * 96
            + "\n",
            "no sha256 hash or an option",
        ),
        (
            "annotated-types==0.8.0 \\\n    --hash=sha256:" + "a" * 64 + " --config-settings=x=y\n",
            "no sha256 hash or an option",
        ),
        (
            "annotated-types @ https://example.invalid/a.whl \\\n    --hash=sha256:"
            + "a" * 64
            + "\n",
            "not one exact pin",
        ),
        ("    --hash=sha256:" + "a" * 64 + "\n", "continuation line"),
        ("", "no pinned requirement"),
    ],
)
def test_a_lock_entry_that_is_not_an_exact_hashed_pin_is_rejected(lock, message):
    with pytest.raises(locks.LockError, match=message):
        locks.parse_lock(lock)


def test_a_package_pinned_twice_under_one_marker_is_rejected():
    entry = "attrs==26.1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"
    with pytest.raises(locks.LockError, match="twice"):
        locks.parse_lock(entry + entry)


def test_locks_without_their_inputs_header_fail(checkout):
    edit(checkout / locks.FLOOR_LOCK, "# lock-inputs:", "# lock inputs removed:")
    assert any("no lock-inputs header" in e for e in locks.check(checkout))


def test_locks_resolved_with_different_cutoffs_fail(checkout):
    floor = checkout / locks.FLOOR_LOCK
    text = floor.read_text()
    floor.write_text(re.sub(r"exclude-newer=\S+", "exclude-newer=2026-01-01T00:00:00Z", text))
    assert any("different upload cut-offs" in e for e in locks.check(checkout))


def test_regeneration_refuses_an_unpinned_uv(monkeypatch):
    monkeypatch.setattr(locks.shutil, "which", lambda name: None)
    with pytest.raises(locks.LockError, match="uv"):
        locks.regenerate(ROOT, None, False)


def test_every_locked_pin_is_listed_for_the_advisory_audit_whatever_its_marker():
    packages = locks.locked_packages(ROOT, [locks.CI_LOCK, locks.ACTION_LOCK])
    names = {package["name"] for package in packages}
    # Pins that the Python 3.12 Linux audit job never installs.
    assert {
        "backports-tarfile",
        "importlib-metadata",
        "zipp",
        "colorama",
        "pywin32-ctypes",
    } <= names
    assert len(packages) == len({(p["name"], p["version"]) for p in packages})


def test_a_failed_resolution_points_at_the_cutoff(monkeypatch, capsys):
    def failing(*_args):
        raise locks.subprocess.CalledProcessError(1, ["uv", "pip", "compile"])

    monkeypatch.setattr(locks, "regenerate", failing)
    assert locks.main(["--regenerate"]) == 1
    assert "--exclude-newer" in capsys.readouterr().err


def _record_cutoff(checkout, cutoff):
    """A cut-off that a fallback to seven days ago can never produce by coincidence."""
    committed = locks.read_lock(checkout, locks.CI_LOCK).inputs["cutoff"]
    edit(checkout / locks.CI_LOCK, f"exclude-newer={committed} ", f"exclude-newer={cutoff} ")
    return cutoff


def fake_uv(monkeypatch, *, fail_on=None):
    """Stand-in for uv pip compile: writes an unstamped lock where uv would, or fails."""
    calls = []

    def run(command, **kwargs):
        output = Path(kwargs["cwd"]) / command[command.index("-o") + 1]
        calls.append((command, output.read_bytes() if output.exists() else None))
        if fail_on is not None and fail_on in command:
            raise locks.subprocess.CalledProcessError(1, command)
        output.write_text(
            "# This file was autogenerated by uv via the following command:\n#    make lock\n"
            "attrs==26.1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"
        )
        return locks.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(locks, "_uv", lambda: "uv")
    monkeypatch.setattr(locks.subprocess, "run", run)
    return calls


def test_a_failed_resolution_leaves_every_lock_and_its_cutoff_as_it_was(checkout, monkeypatch):
    recorded = _record_cutoff(checkout, "2001-02-03T00:00:00Z")
    before = {name: (checkout / name).read_bytes() for name in FILES}
    calls = fake_uv(monkeypatch, fail_on="lowest-direct")
    with pytest.raises(locks.subprocess.CalledProcessError):
        locks.regenerate(checkout, None, False)
    assert len(calls) == 3
    # uv was handed the committed CI lock, so it keeps the reviewed pins.
    assert calls[0][1] == before[locks.CI_LOCK]
    assert "--exclude-newer" in calls[0][0]
    assert calls[0][0][calls[0][0].index("--exclude-newer") + 1] == recorded
    assert {name: (checkout / name).read_bytes() for name in FILES} == before
    assert sorted(path.name for path in checkout.iterdir()) == sorted(FILES)


def test_regeneration_ignores_package_sources_from_the_checkout(checkout, monkeypatch):
    calls = fake_uv(monkeypatch)
    locks.regenerate(checkout, "2001-02-03T00:00:00Z", False)
    assert calls
    for command, _ in calls:
        assert "--no-config" in command
        assert "--no-sources" in command


@pytest.mark.parametrize(
    "table",
    [
        '[tool.uv.sources]\nclick = { index = "mirror" }\n',
        '[[tool.uv.index]]\nname = "mirror"\nurl = "https://mirror.invalid/simple"\nexplicit = true\n',
        '[tool.uv]\nindex-url = "https://mirror.invalid/simple"\n',
    ],
)
def test_uv_settings_in_pyproject_fail_the_lock_check(checkout, table):
    with (checkout / "pyproject.toml").open("a") as handle:
        handle.write("\n" + table)
    assert (
        "pyproject.toml: [tool.uv] is not allowed; the locks resolve from PyPI only"
        in locks.check(checkout)
    )


def test_a_successful_resolution_replaces_all_three_locks_stamped(checkout, monkeypatch):
    recorded = _record_cutoff(checkout, "2001-02-03T00:00:00Z")
    fake_uv(monkeypatch)
    locks.regenerate(checkout, None, False)
    for name in (locks.CI_LOCK, locks.ACTION_LOCK, locks.FLOOR_LOCK):
        lock = locks.read_lock(checkout, name)
        assert lock.inputs["cutoff"] == recorded, name
        assert set(lock.pins) == {"attrs"}, name
    assert sorted(path.name for path in checkout.iterdir()) == sorted(FILES)


def test_a_ci_lock_without_its_cutoff_is_not_silently_moved_to_now(checkout, monkeypatch):
    edit(checkout / locks.CI_LOCK, "# lock-inputs:", "# lock inputs removed:")
    calls = fake_uv(monkeypatch)
    with pytest.raises(locks.LockError, match="no upload cut-off"):
        locks.regenerate(checkout, None, False)
    assert calls == []
    locks.regenerate(checkout, "2026-11-03T00:00:00Z", False)
    assert locks.read_lock(checkout, locks.FLOOR_LOCK).inputs["cutoff"] == "2026-11-03T00:00:00Z"


def _orphan(name="evil-helper", via="nexus-symbiote (pyproject.toml)"):
    block = f"{name}==1.0.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"
    return block + (f"    # via {via}\n" if via is not None else "")


@pytest.mark.parametrize("lock", [locks.CI_LOCK, locks.ACTION_LOCK, locks.FLOOR_LOCK])
@pytest.mark.parametrize(
    "via",
    [
        None,
        "\n    #   -c requirements-ci.lock",
        "\n    #   -c requirements-ci.lock (test tools)",
        "nexus-symbiote (pyproject.toml)",
        "nexus-symbiote (pyproject.toml:dev)",
        "\n    #   -r pyproject.toml (build-system)",
        "not-a-locked-package",
        "evil-helper",
    ],
)
def test_a_pin_that_no_declaration_or_locked_parent_requires_fails(checkout, lock, via):
    # Audit 2026-11-16 S16-02: a pin inserted into a lock, with no declaration behind it,
    # was installed with --require-hashes by CI, the release build and the Action while
    # the check reported that the locks agree with pyproject.toml.
    names = [lock, locks.CI_LOCK] if lock == locks.ACTION_LOCK else [lock]
    for name in names:
        edit(checkout / name, "email-validator==", _orphan(via=via) + "email-validator==")
    errors = locks.check(checkout)
    for name in names:
        message = f"{name}: evil-helper is not required by pyproject.toml or by another pin"
        assert any(error.startswith(message) for error in errors), errors


def test_a_pin_reached_only_through_an_orphan_parent_fails(checkout):
    edit(
        checkout / locks.FLOOR_LOCK,
        "email-validator==",
        _orphan(via="not-a-locked-package")
        + _orphan("evil-child", via="evil-helper")
        + "email-validator==",
    )
    errors = "\n".join(locks.check(checkout))
    assert f"{locks.FLOOR_LOCK}: evil-helper is not required" in errors
    assert f"{locks.FLOOR_LOCK}: evil-child is not required" in errors


def test_a_pin_required_by_a_locked_parent_passes(checkout):
    edit(
        checkout / locks.FLOOR_LOCK,
        "email-validator==",
        _orphan("new-helper", via="pydantic") + "email-validator==",
    )
    assert locks.check(checkout) == []


def test_via_annotations_are_read_in_both_layouts():
    lock = locks.parse_lock(
        _orphan("a", via="b") + _orphan("b", via="\n    #   -c requirements-ci.lock\n    #   Click")
    )
    assert lock.pins["a"][0].via == frozenset({"b"})
    assert lock.pins["b"][0].via == frozenset({"-c requirements-ci.lock", "Click"})
