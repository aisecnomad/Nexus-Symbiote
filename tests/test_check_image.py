"""scripts/check_image.py: one wheel in, an image that is built, run offline and checked."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from tests.support import ROOT, load_script

check_image = load_script("check_image")

VERSION = "0.2.0"
WHEEL = f"nexus_symbiote-{VERSION}-py3-none-any.whl"
LICENSE = "MIT AND Apache-2.0 AND Community-Spec-1.0 AND CC-BY-3.0"
OS_RELEASE = 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n'
DPKG = (
    "glibc\t2.41-12+deb13u4\tlibc6\nglibc\t2.41-12+deb13u4\tlibc-bin\nzlib\t1:1.3.dfsg-1\tzlib1g\n"
)
# What the image the 0.2.0 release published prints: the group id has no name.
UNNAMED_GROUP = "uid=10001(symbiote) gid=10001 groups=10001"

# A docker that records its calls and answers from files, never a daemon or a registry.
DOCKER = """#!/bin/bash
printf '%s\\n' "$*" >> "$STUB/calls"
answer() { cat "$STUB/$1"; exit "$(cat "$STUB/$1.status" 2>/dev/null || echo 0)"; }
case "$*" in
  "buildx build "*) ls -A "${@: -1}" > "$STUB/context"; answer build ;;
  "image inspect "*) answer config ;;
  *"--entrypoint id "*) answer id ;;
  *"--entrypoint cat "*) answer os-release ;;
  *"--entrypoint dpkg-query "*) answer dpkg ;;
  *" scan /work "*) answer scan ;;
  *" --version") answer version ;;
esac
exit 97
"""


def write_wheel(directory: Path, name: str = WHEEL, license_expression: str | None = LICENSE):
    metadata = "Metadata-Version: 2.4\nName: nexus-symbiote\nVersion: 0.2.0\n"
    if license_expression is not None:
        metadata += f"License-Expression: {license_expression}\n"
    with zipfile.ZipFile(directory / name, "w") as archive:
        archive.writestr(f"nexus_symbiote-{VERSION}.dist-info/METADATA", metadata)


@pytest.fixture
def stub(tmp_path, monkeypatch):
    """A stub docker on PATH whose answers describe a correct image; tests change one."""
    directory = tmp_path / "stub"
    (directory / "bin").mkdir(parents=True)
    (directory / "bin" / "docker").write_text(DOCKER)
    (directory / "bin" / "docker").chmod(0o755)
    config = {
        "User": "10001:10001",
        "Entrypoint": ["/opt/nexus-symbiote/bin/nexus-symbiote"],
        "Labels": {check_image.LICENSES: LICENSE, check_image.VERSION: VERSION},
    }
    answers = {
        "build": "",
        "version": f"nexus-symbiote, version {VERSION}\n",
        "config": json.dumps(config),
        "id": check_image.IDENTITY + "\n",
        "scan": json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "demo"}]}),
        "os-release": OS_RELEASE,
        "dpkg": DPKG,
    }
    for name, text in answers.items():
        (directory / name).write_text(text)
    monkeypatch.setenv("STUB", str(directory))
    monkeypatch.setenv("PATH", f"{directory / 'bin'}:/usr/bin:/bin")
    (tmp_path / "dist").mkdir()
    write_wheel(tmp_path / "dist")
    (tmp_path / "dist" / f"nexus_symbiote-{VERSION}.tar.gz").write_text("sdist")
    return directory


def calls(stub: Path) -> list[str]:
    return (stub / "calls").read_text().splitlines() if (stub / "calls").exists() else []


def test_a_correct_image_is_built_from_three_files_and_run_only_without_a_network(
    stub, tmp_path, capsys
):
    # The evidence directory need not exist yet: this is the first step that writes to it
    # when the advisory recheck before it is skipped or moved.
    output, packages = tmp_path / "output", tmp_path / "evidence" / "packages.json"
    status = check_image.main(
        [
            str(tmp_path / "dist"),
            *("--name", "ghcr.io/owner/repo", "--label", "org.opencontainers.image.revision=abc"),
            *("--packages-out", str(packages), "--github-output", str(output)),
        ]
    )
    assert status == 0, capsys.readouterr().out
    tag = f"ghcr.io/owner/repo:{VERSION}"
    made = calls(stub)
    assert made[0].startswith(
        f"buildx build --load --provenance=false --tag {tag}"
        f" --label {check_image.VERSION}={VERSION}"
        " --label org.opencontainers.image.revision=abc "
    )
    assert set((stub / "context").read_text().split()) == {
        "Dockerfile",
        "requirements-action.lock",
        WHEEL,
    }
    runs = [call for call in made if call.startswith("run ")]
    assert len(runs) == 5 and all(call.startswith("run --rm --network none ") for call in runs)
    assert not any(call.split()[0] in {"push", "login"} for call in made)
    # The scan runs exactly as the documentation tells a user to run it.
    [scan] = [call for call in runs if " scan /work " in call]
    demo = ROOT / "examples" / "demo-agent"
    assert (
        " --read-only --cap-drop ALL --security-opt no-new-privileges --user " in scan
        and f" --volume {demo}:/work:ro {tag} scan /work --no-project-policy -f cyclonedx" in scan
    )
    assert output.read_text() == f"name=ghcr.io/owner/repo\nversion={VERSION}\n"
    record = json.loads(packages.read_text())
    assert record["os"] == {"id": "debian", "version_id": "13"}
    assert record["image"] == tag
    assert record["base"] in (ROOT / "Dockerfile").read_text()
    assert record["packages"] == [
        {"source": "glibc", "version": "2.41-12+deb13u4", "binaries": ["libc-bin", "libc6"]},
        {"source": "zlib", "version": "1:1.3.dfsg-1", "binaries": ["zlib1g"]},
    ]
    assert f"Image check passed: {tag}" in capsys.readouterr().out


@pytest.mark.parametrize(
    "answer,text,reported",
    [
        ("version", "nexus-symbiote, version 0.1.0\n", "--version printed"),
        ("id", UNNAMED_GROUP + "\n", f"id printed {UNNAMED_GROUP!r}"),
        ("id", "uid=0(root) gid=0(root) groups=0(root)\n", "id printed"),
        ("scan", "Traceback (most recent call last):\n", "hardened scan"),
        ("scan", '{"bomFormat": "CycloneDX", "components": []}', "hardened scan"),
        ("scan", '{"components": [{"name": "demo"}]}', "hardened scan"),
        ("scan", "[]", "hardened scan"),
    ],
)
def test_an_image_that_does_not_behave_as_documented_fails(
    stub, tmp_path, capsys, answer, text, reported
):
    (stub / answer).write_text(text)
    output = tmp_path / "output"
    assert check_image.main([str(tmp_path / "dist"), "--github-output", str(output)]) == 1
    assert reported in capsys.readouterr().out
    assert not output.exists()


@pytest.mark.parametrize(
    "key,value,reported",
    [
        ("User", "0:0", "the image's user is '0:0'"),
        ("User", "10001", "the image's user is '10001'"),
        ("Entrypoint", ["/bin/sh"], "the image's entry point"),
        (
            "Labels",
            {check_image.LICENSES: "MIT", check_image.VERSION: VERSION},
            "licenses is 'MIT'",
        ),
        ("Labels", {check_image.LICENSES: LICENSE}, "version is None"),
        ("Labels", None, "licenses is None"),
    ],
)
def test_the_image_configuration_must_match_the_wheel_and_the_dockerfile(
    stub, tmp_path, capsys, key, value, reported
):
    config = json.loads((stub / "config").read_text())
    config[key] = value
    (stub / "config").write_text(json.dumps(config))
    assert check_image.main([str(tmp_path / "dist")]) == 1
    assert reported in capsys.readouterr().out


@pytest.mark.parametrize("failing", ["build", "version", "config", "id", "scan", "dpkg"])
def test_a_docker_command_that_fails_stops_the_check_and_writes_no_output(
    stub, tmp_path, capsys, failing
):
    (stub / f"{failing}.status").write_text("1")
    output, packages = tmp_path / "output", tmp_path / "packages.json"
    arguments = ["--github-output", str(output), "--packages-out", str(packages)]
    assert check_image.main([str(tmp_path / "dist"), *arguments]) == 1
    assert "could not finish: CalledProcessError" in capsys.readouterr().out
    assert not output.exists() and not packages.exists()
    if failing == "build":
        assert len(calls(stub)) == 1


@pytest.mark.parametrize(
    "case", ["none", "two", "symlink", "directory", "other-project", "unsafe-version", "hidden"]
)
def test_anything_but_one_regular_wheel_of_this_project_builds_nothing(
    stub, tmp_path, capsys, case
):
    dist = tmp_path / "dist"
    (dist / WHEEL).unlink()
    if case == "two":
        write_wheel(dist)
        write_wheel(dist, "nexus_symbiote-0.1.0-py3-none-any.whl")
    elif case == "symlink":
        write_wheel(tmp_path)
        (dist / WHEEL).symlink_to(tmp_path / WHEEL)
    elif case == "directory":
        (dist / WHEEL).mkdir()
    elif case == "other-project":
        write_wheel(dist, "other-0.2.0-py3-none-any.whl")
    elif case == "unsafe-version":
        write_wheel(dist, "nexus_symbiote-0.2.0+local-py3-none-any.whl")
    elif case == "hidden":
        write_wheel(dist)
        write_wheel(dist, ".extra.whl")
    assert check_image.main([str(dist)]) == 1
    assert "Image check: could not finish: ValueError" in capsys.readouterr().out
    assert calls(stub) == []


def test_a_registry_with_a_port_may_hold_the_image(stub, tmp_path):
    assert check_image.main([str(tmp_path / "dist"), "--name", "localhost:5000/owner/repo"]) == 0
    assert f" --tag localhost:5000/owner/repo:{VERSION} " in calls(stub)[0]


@pytest.mark.parametrize(
    "name", ["Owner/Repo", "ghcr.io/owner/repo:latest", "repo@sha256:" + "a" * 64, "-x", ""]
)
def test_an_image_name_that_is_not_a_plain_lower_case_repository_is_refused(stub, tmp_path, name):
    assert check_image.main([str(tmp_path / "dist"), f"--name={name}"]) == 1
    assert calls(stub) == []


def test_the_license_is_read_from_the_wheel_that_goes_into_the_image(stub, tmp_path, capsys):
    dist = tmp_path / "dist"
    write_wheel(dist, license_expression="MIT")
    assert check_image.main([str(dist)]) == 1
    assert f"licenses is {LICENSE!r}, not 'MIT'" in capsys.readouterr().out
    write_wheel(dist, license_expression=None)
    assert check_image.main([str(dist)]) == 1
    assert "declares no License-Expression" in capsys.readouterr().out
    (dist / WHEEL).write_text("not a zip archive")
    assert check_image.main([str(dist)]) == 1
    assert "BadZipFile" in capsys.readouterr().out
    with zipfile.ZipFile(dist / WHEEL, "w") as archive:
        archive.writestr("README", "no metadata")
    assert check_image.main([str(dist)]) == 1
    assert "exactly one METADATA" in capsys.readouterr().out


@pytest.mark.parametrize(
    "answer,text",
    [
        ("os-release", "NAME=unknown\n"),
        ("os-release", 'ID=debian\nVERSION_ID="13 ::warning::x"\n'),
        ("dpkg", ""),
        ("dpkg", "glibc\t2.41-12\n"),
        ("dpkg", "glibc\t2.41 ::error::x\tlibc6\n"),
        ("dpkg", "GLIBC\t2.41-12\tlibc6\n"),
    ],
)
def test_a_package_inventory_that_cannot_be_read_exactly_is_not_written(
    stub, tmp_path, capsys, answer, text
):
    (stub / answer).write_text(text)
    packages = tmp_path / "packages.json"
    assert check_image.main([str(tmp_path / "dist"), "--packages-out", str(packages)]) == 1
    assert "could not finish: ValueError" in capsys.readouterr().out
    assert not packages.exists()


def test_without_docker_the_check_fails_instead_of_passing(stub, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert check_image.main([str(tmp_path / "dist")]) == 1
    assert "docker is not on PATH" in capsys.readouterr().out


def test_the_checked_identity_is_the_one_the_dockerfile_declares():
    text = (ROOT / "Dockerfile").read_text()
    assert f"\nUSER {check_image.USER}\n" in text
    assert f"\nENTRYPOINT {json.dumps(check_image.ENTRYPOINT)}\n" in text
    uid, gid = check_image.USER.split(":")
    named = f"uid={uid}(symbiote) gid={gid}(symbiote) groups={gid}(symbiote)"
    assert named == check_image.IDENTITY
