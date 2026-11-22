"""Check the hash locks against pyproject.toml offline, or regenerate them with the pinned uv.

requirements-ci.lock      every extra and the dev group, universal for CPython 3.11 and later.
requirements-action.lock  what the Action installs: the core, the sigstore extra and the build
                          backend, resolved inside the CI lock (the same versions and hashes).
requirements-floor.lock   the declared lower bound of every runtime dependency on Python 3.11,
                          with the test tools at their CI-lock versions.

`python scripts/check_locks.py` (`make lock-check`, the CI quality job) needs no network.
`python scripts/check_locks.py --regenerate` (`make lock`) resolves from PyPI with uv and keeps
existing CI pins unless `--upgrade` is given. Only packages uploaded before the cut-off recorded
in the locks are considered; `--upgrade` moves it to seven days ago, so a release has a week
before it can be locked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = "0.11.32"
COOLDOWN_DAYS = 7
FLOOR_PYTHON = "3.11"
FLOOR_PLATFORM = "x86_64-unknown-linux-gnu"
CI_LOCK = "requirements-ci.lock"
ACTION_LOCK = "requirements-action.lock"
FLOOR_LOCK = "requirements-floor.lock"
PROJECT = "nexus-symbiote"
COMPILE_COMMAND = "make lock"
INDEX = "https://pypi.org/simple"
# Settings that would change what is resolved, and from where, behind the script's back.
UV_RESOLUTION_ENV = frozenset(
    {
        "UV_CONFIG_FILE",
        "UV_CONSTRAINT",
        "UV_DEFAULT_INDEX",
        "UV_EXCLUDE",
        "UV_EXCLUDE_NEWER",
        "UV_EXTRA_INDEX_URL",
        "UV_FIND_LINKS",
        "UV_FORK_STRATEGY",
        "UV_INDEX",
        "UV_INDEX_STRATEGY",
        "UV_INDEX_URL",
        "UV_INSECURE_HOST",
        "UV_KEYRING_PROVIDER",
        "UV_NO_BINARY",
        "UV_NO_SOURCES",
        "UV_ONLY_BINARY",
        "UV_OFFLINE",
        "UV_OVERRIDE",
        "UV_PRERELEASE",
        "UV_PROJECT",
        "UV_RESOLUTION",
        "UV_TORCH_BACKEND",
        "UV_WORKING_DIR",
    }
)
INPUTS = re.compile(
    r"^# lock-inputs: uv=(?P<uv>\S+) exclude-newer=(?P<cutoff>\S+) "
    r"python=(?P<python>\S+) pyproject=sha256:(?P<digest>[0-9a-f]{64})$",
    re.M,
)
HASH_LINE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?: \\)?")
PACKAGE_SOURCE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
# The `# via` sources uv writes for a requirement that pyproject.toml declares itself.
DECLARED_SOURCES = frozenset(
    {
        f"{PROJECT} (pyproject.toml)",
        f"{PROJECT} (pyproject.toml:dev)",
        "-r pyproject.toml (build-system)",
    }
)
SCOPES = {
    CI_LOCK: "every extra and the dev group, universal for CPython 3.11 and later.",
    ACTION_LOCK: (
        "the core, the sigstore extra and the build backend that the Action installs,"
        " resolved inside requirements-ci.lock (the same versions and hashes); no test tools."
    ),
    FLOOR_LOCK: (
        "the declared lower bound of every runtime dependency and the build backend on"
        " Python 3.11 (x86-64 Linux), with the test tools at their requirements-ci.lock versions."
    ),
}


class LockError(ValueError):
    """A lock or its declared inputs cannot be checked."""


@dataclass(frozen=True)
class Pin:
    name: str
    version: Version
    marker: str | None
    hashes: frozenset[str]
    via: frozenset[str] = frozenset()


@dataclass
class Lock:
    path: str
    pins: dict[str, list[Pin]] = field(default_factory=dict)
    inputs: dict[str, str] = field(default_factory=dict)

    def versions(self, name: str) -> set[Version]:
        return {pin.version for pin in self.pins.get(name, [])}


def declarations(pyproject: Mapping[str, Any]) -> dict[str, Any]:
    """The pyproject.toml fields a resolution depends on."""
    project = pyproject["project"]
    return {
        "build-system": pyproject["build-system"]["requires"],
        "requires-python": project["requires-python"],
        "dependencies": project["dependencies"],
        "optional-dependencies": project.get("optional-dependencies", {}),
        "dependency-groups": pyproject.get("dependency-groups", {}),
    }


def declarations_digest(pyproject: Mapping[str, Any]) -> str:
    encoded = json.dumps(declarations(pyproject), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def parse_lock(text: str, path: str = "lock") -> Lock:
    """Parse uv's hashed requirements output: one exact pin per block, hashes required."""
    lock = Lock(path)
    match = INPUTS.search(text)
    if match is not None:
        lock.inputs = match.groupdict()
    blocks: list[list[str]] = []
    vias: list[set[str]] = []
    in_via = False
    for line in text.splitlines():
        comment = line.strip()
        if comment.startswith("#") and blocks:
            body = comment.removeprefix("#")
            if body.startswith(" via"):
                in_via = True
                if body[4:].strip():
                    vias[-1].add(body[4:].strip())
            elif in_via and body.startswith("   ") and body.strip():
                vias[-1].add(body.strip())
            else:
                in_via = False
            continue
        in_via = False
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace():
            if not blocks:
                raise LockError(f"{path}: continuation line before any requirement")
            blocks[-1].append(line.strip())
        else:
            blocks.append([line.strip()])
            vias.append(set())
    for block, via in zip(blocks, vias, strict=True):
        head = block[0].removesuffix("\\").strip()
        try:
            requirement = Requirement(head)
        except InvalidRequirement as exc:
            raise LockError(f"{path}: unparseable requirement line") from exc
        clauses = list(requirement.specifier)
        if (
            len(clauses) != 1
            or clauses[0].operator != "=="
            or "*" in clauses[0].version
            or requirement.url
            or requirement.extras
        ):
            raise LockError(f"{path}: {requirement.name} is not one exact pin")
        # pip accepts any hash it knows, so a line with another algorithm or an option
        # would admit a file that the compared sha256 hashes do not name.
        found = [HASH_LINE.fullmatch(line) for line in block[1:]]
        if not found or any(match is None for match in found):
            raise LockError(f"{path}: {requirement.name} has no sha256 hash or an option")
        hashes = frozenset(match[1] for match in found if match is not None)
        try:
            version = Version(clauses[0].version)
        except InvalidVersion as exc:
            raise LockError(f"{path}: {requirement.name} has an invalid version") from exc
        name = canonicalize_name(requirement.name)
        marker = str(requirement.marker) if requirement.marker else None
        entries = lock.pins.setdefault(name, [])
        if any(entry.marker == marker for entry in entries):
            raise LockError(f"{path}: {name} is pinned twice under the same marker")
        entries.append(Pin(name, version, marker, hashes, frozenset(via)))
    if not lock.pins:
        raise LockError(f"{path}: no pinned requirement")
    return lock


def read_lock(root: Path, name: str) -> Lock:
    try:
        text = (root / name).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise LockError(f"{name}: unreadable") from exc
    return parse_lock(text, name)


def locked_packages(root: Path, names: Iterable[str]) -> list[dict[str, str]]:
    """Every exact name and version pinned by the given locks, whatever its marker."""
    found: set[tuple[str, str]] = set()
    for name in names:
        for pins in read_lock(root, name).pins.values():
            found.update((pin.name, str(pin.version)) for pin in pins)
    return [{"name": name, "version": version} for name, version in sorted(found)]


def _requirements(values: Iterable[str]) -> list[Requirement]:
    return [Requirement(value) for value in values]


def runtime_requirements(pyproject: Mapping[str, Any]) -> list[Requirement]:
    """Core dependencies and every extra, without the project's own self-references."""
    project = pyproject["project"]
    values = list(project["dependencies"])
    for extra in project.get("optional-dependencies", {}).values():
        values.extend(extra)
    return [r for r in _requirements(values) if canonicalize_name(r.name) != PROJECT]


def build_requirements(pyproject: Mapping[str, Any]) -> list[Requirement]:
    return _requirements(pyproject["build-system"]["requires"])


def dev_requirements(pyproject: Mapping[str, Any]) -> list[Requirement]:
    groups = pyproject.get("dependency-groups", {})
    return _requirements(value for value in groups.get("dev", []) if isinstance(value, str))


def _lower_bound(requirement: Requirement) -> Version | None:
    # A wildcard such as ==1.* names no single version, so it is no bound to test.
    bounds = [
        Version(c.version)
        for c in requirement.specifier
        if c.operator in {">=", "==", "~="} and not c.version.endswith(".*")
    ]
    return max(bounds) if bounds else None


def _satisfied(lock: Lock, requirement: Requirement, errors: list[str]) -> None:
    name = canonicalize_name(requirement.name)
    versions = lock.versions(name)
    if not versions:
        errors.append(f"{lock.path}: {name} is declared but not locked")
    for version in sorted(versions):
        if not requirement.specifier.contains(version, prereleases=True):
            errors.append(f"{lock.path}: {name}=={version} is outside {requirement.specifier}")


CUTOFF = re.compile(r"\d{4}-\d{2}-\d{2}T00:00:00Z")


def cutoff_issue(cutoff: str | None, now: datetime | None = None) -> str | None:
    """Why an upload cut-off is unacceptable: not the form ``make lock`` writes, or less
    than COOLDOWN_DAYS ago, so that a lock it resolves could take a release that had no
    week of public scrutiny. None when it is acceptable."""
    if cutoff is None or not CUTOFF.fullmatch(cutoff):
        return f"upload cut-off {cutoff!r} is not of the form YYYY-MM-DDT00:00:00Z"
    try:
        moment = datetime.strptime(cutoff, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return f"upload cut-off {cutoff!r} is not a date"
    if moment > (now or datetime.now(UTC)) - timedelta(days=COOLDOWN_DAYS):
        return f"upload cut-off {cutoff} is less than {COOLDOWN_DAYS} days ago"
    return None


def _inputs_issues(lock: Lock, digest: str, python: str) -> list[str]:
    inputs = lock.inputs
    if not inputs:
        return [f"{lock.path}: no lock-inputs header; regenerate it with `make lock`"]
    issues = []
    if inputs["uv"] != UV_VERSION:
        issues.append(f"{lock.path}: generated with uv {inputs['uv']}, not uv {UV_VERSION}")
    if inputs["digest"] != digest:
        issues.append(
            f"{lock.path}: pyproject.toml dependency declarations changed since the lock was"
            " generated; run `make lock`"
        )
    if inputs["python"] != python:
        issues.append(f"{lock.path}: resolved for Python {inputs['python']}, not {python}")
    return issues


def _unreachable(lock: Lock, declared: Collection[str]) -> list[str]:
    """Pins that neither a declaration nor another pin of the same lock requires.

    uv records why each pin is in a lock in its `# via` lines. A pin is reachable when it is
    declared in pyproject.toml and uv says so, or when a reachable pin of this lock is named
    as its parent; a `-c` constraint is no reason to install anything. Reachability is
    evaluated per individual pin so an unreferenced duplicate entry for an already-reachable
    package is still caught; a forged `# via` comment naming another reachable package is
    caught only by regenerating the lockfile.
    """
    pin_entries = [
        (name, idx, pin) for name, pins in lock.pins.items() for idx, pin in enumerate(pins)
    ]
    reached_pins: set[tuple[str, int]] = {
        (name, idx)
        for name, idx, pin in pin_entries
        if name in declared and bool(pin.via & DECLARED_SOURCES)
    }
    reached_names: set[str] = {name for name, _idx in reached_pins}
    pin_parents: dict[tuple[str, int], set[str]] = {
        (name, idx): {
            canonicalize_name(source) for source in pin.via if PACKAGE_SOURCE.fullmatch(source)
        }
        for name, idx, pin in pin_entries
    }
    changed = True
    while changed:
        found = {
            key
            for key, wanted in pin_parents.items()
            if key not in reached_pins and ((wanted - {key[0]}) & reached_names)
        }
        reached_pins |= found
        reached_names |= {name for name, _idx in found}
        changed = bool(found)
    issues: list[str] = []
    for name in sorted(lock.pins):
        pins = lock.pins[name]
        missing = [pin for idx, pin in enumerate(pins) if (name, idx) not in reached_pins]
        if not missing:
            continue
        if len(missing) == len(pins):
            issues.append(
                f"{lock.path}: {name} is not required by pyproject.toml or by another pin of"
                " the lock; remove it or run `make lock`"
            )
        else:
            for pin in missing:
                issues.append(
                    f"{lock.path}: {name}=={pin.version} is not required by pyproject.toml or by"
                    " another pin of the lock; remove it or run `make lock`"
                )
    return issues


def check(root: Path = ROOT) -> list[str]:
    """Every problem that makes a lock disagree with pyproject.toml or with another lock."""
    try:
        pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        digest = declarations_digest(pyproject)
        runtime = runtime_requirements(pyproject)
        build = build_requirements(pyproject)
        dev = dev_requirements(pyproject)
        locks = {name: read_lock(root, name) for name in (CI_LOCK, ACTION_LOCK, FLOOR_LOCK)}
    except (OSError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as exc:
        return [f"locks could not be checked: {exc}"]
    ci, action, floor = locks[CI_LOCK], locks[ACTION_LOCK], locks[FLOOR_LOCK]
    errors = [
        *_inputs_issues(ci, digest, f"{FLOOR_PYTHON}+"),
        *_inputs_issues(action, digest, f"{FLOOR_PYTHON}+"),
        *_inputs_issues(floor, digest, FLOOR_PYTHON),
    ]
    cutoffs = {lock.inputs.get("cutoff") for lock in locks.values()}
    if len(cutoffs) != 1:
        errors.append("the three locks were resolved with different upload cut-offs")
    elif (issue := cutoff_issue(next(iter(cutoffs)))) is not None:
        errors.append(issue)
    for requirement in [*runtime, *build, *dev]:
        _satisfied(ci, requirement, errors)
    every = {canonicalize_name(r.name) for r in [*runtime, *build, *dev]}
    errors.extend(_unreachable(ci, every))

    project = pyproject["project"]
    core = _requirements(project["dependencies"])
    signing = _requirements(project.get("optional-dependencies", {}).get("sigstore", []))
    for requirement in [*core, *signing, *build]:
        _satisfied(action, requirement, errors)
    errors.extend(
        _unreachable(action, {canonicalize_name(r.name) for r in [*core, *signing, *build]})
    )
    build_names = {canonicalize_name(r.name) for r in build}
    test_tools = {canonicalize_name(r.name) for r in dev} - build_names
    for name, pins in action.pins.items():
        if name in test_tools:
            errors.append(f"{ACTION_LOCK}: test tool {name} must not be in the Action runtime")
        reviewed = {(pin.version, pin.hashes) for pin in ci.pins.get(name, [])}
        for pin in pins:
            if (pin.version, pin.hashes) not in reviewed:
                errors.append(
                    f"{ACTION_LOCK}: {name}=={pin.version} differs from {CI_LOCK} in version"
                    " or hashes"
                )

    for requirement in [*runtime, *build, *dev]:
        _satisfied(floor, requirement, errors)
    errors.extend(_unreachable(floor, every))
    for requirement in [*runtime, *build]:
        name = canonicalize_name(requirement.name)
        bound = _lower_bound(requirement)
        if bound is None:
            errors.append(f"pyproject.toml: {name} declares no lower bound to test")
        elif floor.versions(name) and floor.versions(name) != {bound}:
            tested = ", ".join(str(v) for v in sorted(floor.versions(name)))
            errors.append(
                f"{FLOOR_LOCK}: {name} declares {bound} as its floor but the floor"
                f" resolution needs {tested}; raise the declared floor or fix the conflict"
            )
    for name in sorted(test_tools):
        if floor.versions(name) and floor.versions(name) != ci.versions(name):
            errors.append(f"{FLOOR_LOCK}: test tool {name} differs from its {CI_LOCK} version")
    return errors


def _uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        raise LockError(f"uv {UV_VERSION} is required to regenerate the locks")
    reported = subprocess.run(  # noqa: S603 - resolved uv executable, fixed argument
        [uv, "--version"], capture_output=True, text=True, check=True, timeout=30
    ).stdout.split()
    if reported[1:2] != [UV_VERSION]:
        raise LockError(f"uv {UV_VERSION} is required to regenerate the locks")
    return uv


def _pins_file(path: Path, lock: Lock, names: Iterable[str] | None = None) -> None:
    wanted = None if names is None else set(names)
    lines = [
        f"{pin.name}=={pin.version}" + (f" ; {pin.marker}" if pin.marker else "")
        for name, pins in sorted(lock.pins.items())
        if wanted is None or name in wanted
        for pin in pins
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _stamp(path: Path, cutoff: str, python: str, digest: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    lines = [line for line in lines if not line.startswith(("# lock-inputs:", "# Scope:"))]
    header = 2 if len(lines) > 1 and lines[1].strip() == f"#    {COMPILE_COMMAND}" else 0
    stamp = [
        f"# Scope: {SCOPES[path.name]}",
        f"# lock-inputs: uv={UV_VERSION} exclude-newer={cutoff} python={python}"
        f" pyproject=sha256:{digest}",
    ]
    path.write_text("\n".join([*lines[:header], *stamp, *lines[header:]]) + "\n", "utf-8")


def _install(source: Path, target: Path) -> None:
    """Replace target in one step, so that an interrupted copy leaves the old lock whole.

    The staging file is created new, so a symlink a branch committed at a fixed staging
    name cannot redirect the write outside the checkout, and a target that is a symlink
    is refused rather than replaced.
    """
    if target.is_symlink():
        raise LockError(f"{target.name} is a symlink; not replaced")
    try:
        mode = target.stat().st_mode & 0o7777
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask
    descriptor, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    staged = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as out, source.open("rb") as copied:
            # mkstemp creates the file 0600; the lock keeps the mode a plain write gives.
            os.fchmod(out.fileno(), mode)
            shutil.copyfileobj(copied, out)
        os.replace(staged, target)
    finally:
        staged.unlink(missing_ok=True)


def regenerate(root: Path, cutoff: str | None, upgrade: bool) -> None:
    """Resolve the three locks in a scratch directory; replace them only once all succeed.

    A failed resolution leaves every committed lock, and the cut-off it records, as it was.
    """
    uv = _uv()
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    digest = declarations_digest(pyproject)
    existing = root / CI_LOCK
    if cutoff is None and not upgrade and existing.exists():
        cutoff = read_lock(root, CI_LOCK).inputs.get("cutoff")
        if cutoff is None:
            raise LockError(
                f"{CI_LOCK} records no upload cut-off; pass --exclude-newer with the reviewed"
                " cut-off, or --upgrade to move it"
            )
    if cutoff is None:
        moment = datetime.now(UTC) - timedelta(days=COOLDOWN_DAYS)
        cutoff = moment.strftime("%Y-%m-%dT00:00:00Z")
    if (issue := cutoff_issue(cutoff)) is not None:
        raise LockError(issue)
    common = [
        "--default-index",
        INDEX,
        "--generate-hashes",
        "--no-emit-index-url",
        "--only-binary",
        ":all:",
        "--exclude-newer",
        cutoff,
        "--custom-compile-command",
        COMPILE_COMMAND,
        "--quiet",
    ]
    universal = ["--universal", "--python-version", FLOOR_PYTHON]

    environment = {k: v for k, v in os.environ.items() if k not in UV_RESOLUTION_ENV}

    def compile_(arguments: list[str]) -> None:
        subprocess.run(  # noqa: S603 - resolved uv executable and fixed arguments
            [uv, "--no-config", "pip", "compile", *arguments, *common],
            cwd=root,
            env=environment,
            check=True,
            timeout=600,
        )

    with tempfile.TemporaryDirectory(prefix="nexus-symbiote-lock-") as scratch:
        tmp = Path(scratch)
        if existing.exists():
            # uv keeps the pins of the lock it is asked to rewrite unless told to upgrade.
            shutil.copyfile(existing, tmp / CI_LOCK)
        compile_(
            [
                "pyproject.toml",
                "--extra",
                "all",
                "--group",
                "dev",
                *universal,
                *(["--upgrade"] if upgrade else []),
                "-o",
                str(tmp / CI_LOCK),
            ]
        )
        ci = read_lock(tmp, CI_LOCK)
        _pins_file(tmp / "ci-pins.txt", ci)
        (tmp / "build.in").write_text(
            "\n".join(pyproject["build-system"]["requires"]) + "\n", encoding="utf-8"
        )
        compile_(
            [
                "pyproject.toml",
                str(tmp / "build.in"),
                "--extra",
                "sigstore",
                *universal,
                "-c",
                str(tmp / "ci-pins.txt"),
                "-o",
                str(tmp / ACTION_LOCK),
            ]
        )
        build_names = {canonicalize_name(r.name) for r in build_requirements(pyproject)}
        tools = {canonicalize_name(r.name) for r in dev_requirements(pyproject)} - build_names
        _pins_file(tmp / "tools.txt", ci, tools)
        compile_(
            [
                "pyproject.toml",
                "--extra",
                "all",
                "--group",
                "dev",
                "--resolution",
                "lowest-direct",
                "--python-version",
                FLOOR_PYTHON,
                "--python-platform",
                FLOOR_PLATFORM,
                "-c",
                str(tmp / "tools.txt"),
                "-o",
                str(tmp / FLOOR_LOCK),
            ]
        )
        # uv annotates where a pin came from; name the inputs, not this temporary directory.
        labels = {
            str(tmp / "ci-pins.txt"): CI_LOCK,
            str(tmp / "tools.txt"): f"{CI_LOCK} (test tools)",
            str(tmp / "build.in"): "pyproject.toml (build-system)",
        }
        for name in (CI_LOCK, ACTION_LOCK, FLOOR_LOCK):
            text = (tmp / name).read_text(encoding="utf-8")
            for source, label in labels.items():
                text = text.replace(source, label)
            (tmp / name).write_text(text, encoding="utf-8")
        _stamp(tmp / CI_LOCK, cutoff, f"{FLOOR_PYTHON}+", digest)
        _stamp(tmp / ACTION_LOCK, cutoff, f"{FLOOR_PYTHON}+", digest)
        _stamp(tmp / FLOOR_LOCK, cutoff, FLOOR_PYTHON, digest)
        for name in (CI_LOCK, ACTION_LOCK, FLOOR_LOCK):
            _install(tmp / name, root / name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regenerate", action="store_true", help="resolve again with uv")
    parser.add_argument("--upgrade", action="store_true", help="upgrade every CI pin as well")
    parser.add_argument("--exclude-newer", help="upload cut-off, for example 2026-11-03T00:00:00Z")
    args = parser.parse_args(argv)
    if (args.upgrade or args.exclude_newer) and not args.regenerate:
        parser.error("--upgrade and --exclude-newer need --regenerate")
    if args.regenerate:
        try:
            regenerate(ROOT, args.exclude_newer, args.upgrade)
        except (LockError, OSError, subprocess.SubprocessError, ValueError) as exc:
            print(f"Lock regeneration failed: {exc}", file=sys.stderr)
            if isinstance(exc, subprocess.CalledProcessError):
                print(
                    "If a declaration needs a release newer than the recorded cut-off, pass"
                    " --exclude-newer or run `make lock-upgrade`.",
                    file=sys.stderr,
                )
            return 1
    errors = check(ROOT)
    for error in errors:
        print(error)
    if not errors:
        print("Locks agree with pyproject.toml and with each other.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
