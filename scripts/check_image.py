"""Build the container image from one release wheel and check it before it can be pushed.

The build context holds the Dockerfile, ``requirements-action.lock`` and the wheel, nothing
else. The built image must print the wheel's version with the network removed, run as
10001:10001 with both ids named ``symbiote``, carry the wheel's license expression, and write
the demo agent's inventory under the flags docs/container-image.md recommends. CI runs this
on every pull request, each release run before it attests or publishes anything, and the job
that pushes the image before it logs in to the registry. Nothing here pushes or needs a
token. It uses only the standard library, so the pushing job installs nothing, and every
caller runs it with ``-S`` so that it cannot come to depend on an installed package.
"""

from __future__ import annotations

import argparse
import email
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WHEEL = re.compile(r"nexus_symbiote-([0-9][0-9A-Za-z._]*)-py3-none-any\.whl")
# A repository name, after an optional registry host and port; never a tag or a digest.
NAME = re.compile(r"(?:[a-z0-9.-]+:[0-9]{1,5}/)?[a-z0-9][a-z0-9._/-]{0,199}")
USER = "10001:10001"
IDENTITY = "uid=10001(symbiote) gid=10001(symbiote) groups=10001(symbiote)"
ENTRYPOINT = ["/opt/nexus-symbiote/bin/nexus-symbiote"]
LICENSES = "org.opencontainers.image.licenses"
VERSION = "org.opencontainers.image.version"
# What docs/container-image.md tells users to pass besides the mount and their own ids.
HARDENING = ("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges")
# Debian source package names and versions (Policy 5.6.1 and 5.6.12), as they reach a log.
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
PACKAGE_VERSION = re.compile(r"[0-9][0-9A-Za-z.+~:-]{0,127}")
PACKAGE_FIELDS = "${source:Package}\\t${source:Version}\\t${Package}\\n"


def find_wheel(directory: Path) -> tuple[Path, str]:
    """The directory's one wheel, a regular file of this project, and its version."""
    wheels = [path for path in directory.iterdir() if path.name.endswith(".whl")]
    if len(wheels) != 1:
        raise ValueError(f"expected exactly one wheel, found {len(wheels)}")
    named = WHEEL.fullmatch(wheels[0].name)
    if named is None or wheels[0].is_symlink() or not wheels[0].is_file():
        raise ValueError("the wheel is not a regular nexus_symbiote py3-none-any wheel file")
    return wheels[0], named[1]


def wheel_license(wheel: Path) -> str:
    """The License-Expression the wheel's own metadata declares."""
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("the wheel does not hold exactly one METADATA file")
        expression = email.message_from_bytes(archive.read(names[0]))["License-Expression"]
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("the wheel declares no License-Expression")
    return expression.strip()


def docker(*arguments: str, capture: bool = False, timeout: int = 300) -> str:
    """Run docker and fail on a nonzero exit; its output goes to the log unless captured."""
    program = shutil.which("docker")
    if program is None:
        raise OSError("docker is not on PATH")
    result = subprocess.run(  # noqa: S603 - resolved docker, arguments built in this file
        [program, *arguments],
        stdout=subprocess.PIPE if capture else None,
        text=True,
        check=True,
        timeout=timeout,
    )
    return result.stdout if capture else ""


def build(wheel: Path, tag: str, labels: list[str]) -> None:
    with tempfile.TemporaryDirectory(prefix="nexus-symbiote-image-") as context:
        for source in (ROOT / "Dockerfile", ROOT / "requirements-action.lock", wheel):
            shutil.copyfile(source, Path(context) / source.name)
        options = [option for label in labels for option in ("--label", label)]
        docker(
            *("buildx", "build", "--load", "--provenance=false", "--tag", tag),
            *options,
            context,
            timeout=1200,
        )


def run(tag: str, *arguments: str, options: tuple[str, ...] = ()) -> str:
    """Standard output of one container of the image, always without a network."""
    return docker("run", "--rm", "--network", "none", *options, tag, *arguments, capture=True)


def problems(tag: str, version: str, expression: str, demo: Path) -> list[str]:
    """Each way the built image differs from what the documentation promises."""
    found = []
    printed = run(tag, "--version").strip()
    if printed != f"nexus-symbiote, version {version}":
        found.append(f"--version printed {printed!r}, not the wheel's version {version}")
    inspected = docker("image", "inspect", "--format", "{{json .Config}}", tag, capture=True)
    config = json.loads(inspected)
    labels = config.get("Labels") or {}
    for name, actual, expected in (
        ("user", config.get("User"), USER),
        ("entry point", config.get("Entrypoint"), ENTRYPOINT),
        (LICENSES, labels.get(LICENSES), expression),
        (VERSION, labels.get(VERSION), version),
    ):
        if actual != expected:
            found.append(f"the image's {name} is {actual!r}, not {expected!r}")
    identity = run(tag, options=("--entrypoint", "id")).strip()
    if identity != IDENTITY:
        found.append(f"id printed {identity!r}, not {IDENTITY!r}")
    caller = f"{os.getuid()}:{os.getgid()}"
    mount = ("--user", caller, "--volume", f"{demo}:/work:ro")
    scan = run(
        tag, "scan", "/work", "--no-project-policy", "-f", "cyclonedx", options=HARDENING + mount
    )
    try:
        inventory = json.loads(scan)
    except ValueError:
        inventory = None
    if (
        not isinstance(inventory, dict)
        or inventory.get("bomFormat") != "CycloneDX"
        or not inventory.get("components")
    ):
        found.append("the documented hardened scan of the demo agent wrote no inventory")
    return found


def base_packages(tag: str) -> dict[str, Any]:
    """The image's operating system and the Debian source packages installed in it."""
    release = dict(
        line.split("=", 1)
        for line in run(tag, "/etc/os-release", options=("--entrypoint", "cat")).splitlines()
        if "=" in line
    )
    system = {key: release.get(key.upper(), "").strip("\"'") for key in ("id", "version_id")}
    if not all(re.fullmatch(r"[a-z0-9.]{1,32}", value) for value in system.values()):
        raise ValueError("the image's os-release names no operating system and version")
    sources: dict[tuple[str, str], list[str]] = {}
    listing = run(tag, "-W", "-f", PACKAGE_FIELDS, options=("--entrypoint", "dpkg-query"))
    for row in listing.splitlines():
        fields = row.split("\t")
        if (
            len(fields) != 3
            or not all(PACKAGE.fullmatch(name) for name in (fields[0], fields[2]))
            or not PACKAGE_VERSION.fullmatch(fields[1])
        ):
            raise ValueError("dpkg-query printed a row that is not a package and its source")
        sources.setdefault((fields[0], fields[1]), []).append(fields[2])
    if not sources:
        raise ValueError("dpkg-query listed no package")
    bases = re.findall(r"^FROM (\S+)", (ROOT / "Dockerfile").read_text(encoding="utf-8"), re.M)
    return {
        "schema_version": 1,
        "image": tag,
        "base": bases[-1],
        "os": system,
        "packages": [
            {"source": source, "version": version, "binaries": sorted(binaries)}
            for (source, version), binaries in sorted(sources.items())
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", type=Path, help="directory that holds exactly one wheel")
    parser.add_argument("--name", default="nexus-symbiote", help="image name, without a tag")
    parser.add_argument("--label", action="append", default=[], help="extra KEY=VALUE label")
    parser.add_argument("--packages-out", type=Path, help="write the base package inventory")
    parser.add_argument("--github-output", type=Path, help="append name= and version= here")
    args = parser.parse_args(argv)
    try:
        if NAME.fullmatch(args.name) is None:
            raise ValueError("the image name is not a lower-case repository name")
        wheel, version = find_wheel(args.wheels)
        expression = wheel_license(wheel)
        tag = f"{args.name}:{version}"
        build(wheel, tag, [f"{VERSION}={version}", *args.label])
        found = problems(tag, version, expression, ROOT / "examples" / "demo-agent")
        if not found and args.packages_out is not None:
            args.packages_out.parent.mkdir(parents=True, exist_ok=True)
            args.packages_out.write_text(
                json.dumps(base_packages(tag), indent=2) + "\n", encoding="utf-8"
            )
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        found = [f"could not finish: {type(error).__name__}: {error}"]
    for problem in found:
        print(f"Image check: {problem}")
    if found:
        return 1
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"name={args.name}\nversion={version}\n")
    print(f"Image check passed: {tag} ran offline, unprivileged and with the documented flags.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
