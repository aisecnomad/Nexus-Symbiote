"""docs/releasing.md, step 7: the documented commands attach every bundle under its own name."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.support import ROOT

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None or os.name != "posix", reason="needs bash")

VERSION = "0.2.0"
WHEEL = f"nexus_symbiote-{VERSION}-py3-none-any.whl"
SDIST = f"nexus_symbiote-{VERSION}.tar.gz"
BUNDLES = ("distribution", "release-evidence", "inventory-benchmark")
PLACEHOLDERS = {
    "<run id>": "45671527287",
    "<version>": VERSION,
    "<notes>": "notes.md",
    "<release commit SHA>": "a" * 40,
}
# `gh run download` as run 45671527287 answers it: every attestation artifact holds one
# file named attestation.json (actions/attest names it; upload-artifact keeps the name).
# `gh release create` and `gh attestation verify` refuse a file that does not exist, as
# the real CLI does before it contacts GitHub.
GH = """#!/bin/bash
case "$1 $2" in
  "run download")
    shift 3
    while (( $# )); do
      case "$1" in
        --dir) dir="$2" ;;
        --name)
          mkdir -p "$dir/$2"
          case "$2" in
            release-distributions) printf wheel > "$dir/$2/$WHEEL"; printf sdist > "$dir/$2/$SDIST" ;;
            release-evidence) cp "$SUMS" "$dir/$2/SHA256SUMS"; : > "$dir/$2/release-evidence.tar.gz" ;;
            *) printf '%s' "$2" > "$dir/$2/attestation.json"
               [[ "$2" != "$EXTRA_FILE_IN" ]] || : > "$dir/$2/second.json" ;;
          esac ;;
      esac
      shift 2
    done ;;
  "release create")
    shift 2
    for argument in "$@"; do
      [[ "$argument" != release-assets/* || -f "$argument" ]] || { echo "no matches found"; exit 1; }
    done
    printf '%s\\n' "$@" > "$CALLS.release" ;;
  "attestation verify")
    shift 2
    printf '%s\\n' "$@" > "$CALLS.verify"
    while (( $# )); do
      [[ "$1" != --bundle || -f "$2" ]] || exit 1
      shift
    done ;;
  *) exit 64 ;;
esac
"""


def blocks() -> list[str]:
    """The fenced commands of step 7, with the placeholders a maintainer fills in."""
    text = (ROOT / "docs" / "releasing.md").read_text(encoding="utf-8")
    step = text.split("\n7. Publish the GitHub release", 1)[1].split("\n8. ", 1)[0]
    found = [
        re.sub(r"(?m)^   ", "", block) for block in re.findall(r"```bash\n(.*?)```", step, re.S)
    ]
    assert len(found) == 2
    for placeholder, value in PLACEHOLDERS.items():
        found = [block.replace(placeholder, value) for block in found]
    assert not re.search(r"<[a-z][a-z ]*>", "".join(found))
    return found


# The macOS runners have no GNU sha256sum; the test checks the list it is given, and that
# the command was asked to check it strictly, instead.
SHA256SUM = '#!/bin/bash\nprintf "%s\\n" "$*" > "$CALLS.sums-arguments"\ncat > "$CALLS.sums"\n'


def run(tmp_path: Path, script: str, **extra: str) -> subprocess.CompletedProcess[str]:
    stubs = tmp_path / "stubs"
    if not stubs.exists():
        stubs.mkdir()
        for name, body in (("gh", GH), ("sha256sum", SHA256SUM)):
            (stubs / name).write_text(body)
            (stubs / name).chmod(0o755)
        sums = [
            f"{hashlib.sha256(content).hexdigest()}  dist/{name}"
            for name, content in ((WHEEL, b"wheel"), (SDIST, b"sdist"))
        ]
        sums.append(f"{'0' * 64}  evidence/source-revision.json")
        (tmp_path / "SHA256SUMS").write_text("\n".join(sums) + "\n")
        (tmp_path / "work").mkdir()
    environment = {
        "PATH": f"{stubs}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "CALLS": str(tmp_path / "calls"),
        "SUMS": str(tmp_path / "SHA256SUMS"),
        "WHEEL": WHEEL,
        "SDIST": SDIST,
        "EXTRA_FILE_IN": "",
        **extra,
    }
    # The documented commands under a fixed interpreter, with a local stub for gh.
    return subprocess.run(  # noqa: S603
        [BASH or "bash", "-c", script],
        cwd=tmp_path / "work",
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_the_documented_commands_attach_each_bundle_under_its_artifact_name(tmp_path):
    create, verify = blocks()
    result = run(tmp_path, create)
    assert result.returncode == 0, result.stderr
    arguments = (tmp_path / "calls.release").read_text().splitlines()
    assets = [argument for argument in arguments if argument.startswith("release-assets/")]
    assert arguments[: len(arguments) - len(assets)] == [
        f"v{VERSION}",
        "--verify-tag",
        "--notes-file",
        "notes.md",
    ]
    # A release names an asset by its file name alone: every one must differ.
    names = [Path(asset).name for asset in assets]
    assert sorted(names) == sorted(
        [WHEEL, SDIST, "SHA256SUMS", "release-evidence.tar.gz"]
        + [f"{bundle}-attestation.sigstore.json" for bundle in BUNDLES]
    )
    work = tmp_path / "work"
    for bundle in BUNDLES:
        renamed = work / "release-assets" / f"{bundle}-attestation.sigstore.json"
        assert renamed.read_text() == f"{bundle}-attestation"

    # The offline verification that follows reads the files where the commands left them.
    result = run(tmp_path, "set -euo pipefail\n" + verify)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "calls.sums-arguments").read_text() == "--strict -c -\n"
    # The checksum list names both distributions where the download put them, and only them.
    listed = dict(
        line.split("  ")[::-1] for line in (tmp_path / "calls.sums").read_text().splitlines()
    )
    assert sorted(listed) == sorted(
        f"release-assets/release-distributions/{n}" for n in (WHEEL, SDIST)
    )
    for path, digest in listed.items():
        assert hashlib.sha256((work / path).read_bytes()).hexdigest() == digest
    verified = (tmp_path / "calls.verify").read_text().splitlines()
    assert verified[0] == f"release-assets/release-distributions/{WHEEL}"
    bundle = verified[verified.index("--bundle") + 1]
    assert bundle == "release-assets/distribution-attestation.sigstore.json"
    assert (work / bundle).read_text() == "distribution-attestation"
    assert verified[verified.index("--source-digest") + 1] == "a" * 40


def test_the_commands_before_this_fix_named_three_assets_alike(tmp_path):
    create, _ = blocks()
    assert "release-assets/*-attestation/*" not in create
    old = "\n".join(
        line for line in create.splitlines() if not line.startswith(("for ", "  mv ", "done"))
    )
    old = old.split("release-assets/distribution-attestation.sigstore.json")[0]
    result = run(tmp_path, old + "release-assets/*-attestation/*\n")
    assert result.returncode == 0, result.stderr
    assets = (tmp_path / "calls.release").read_text().splitlines()[4:]
    assert [Path(asset).name for asset in assets].count("attestation.json") == 3


@pytest.mark.parametrize("bundle", BUNDLES)
def test_an_artifact_that_holds_more_than_its_bundle_creates_no_release(tmp_path, bundle):
    create, _ = blocks()
    result = run(tmp_path, create, EXTRA_FILE_IN=f"{bundle}-attestation")
    assert result.returncode != 0
    assert not (tmp_path / "calls.release").exists()
