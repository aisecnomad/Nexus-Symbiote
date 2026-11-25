"""The release image: built and checked before anything is uploaded, then built from the
verified wheel, pushed, attested and verified by digest."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.support import ROOT, load_script

check_image = load_script("check_image")
DIGEST = "sha256:" + "ab" * 32
SHA = "c" * 40
WHEEL = "nexus_symbiote-0.2.0-py3-none-any.whl"


def jobs():
    return yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]


def run_step(job: str, name: str | None = None) -> dict:
    steps = [step for step in jobs()[job]["steps"] if "run" in step]
    return steps[0] if name is None else next(step for step in steps if step.get("id") == name)


def ci_jobs():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]


def test_every_release_run_builds_and_runs_the_image_before_anything_is_attested_or_uploaded():
    workflow = jobs()
    steps = workflow["build"]["steps"]
    [checked] = [i for i, step in enumerate(steps) if "check_image.py" in step.get("run", "")]
    step = steps[checked]
    # It runs in every release run, whatever `publish` is, with no token and no registry.
    assert "if" not in step and "env" not in step and "continue-on-error" not in step
    assert step["run"].splitlines() == [
        'sha256sum --strict -c "$RUNNER_TEMP/distributions.sha256"',
        "python -I scripts/check_image.py dist --packages-out evidence/image-packages.json",
        "python scripts/image_base_updates.py evidence/image-packages.json"
        " --out evidence/image-base-updates.json",
    ]
    assert not any(word in step["run"] for word in ("login", "push", "ghcr.io"))
    assert "packages" not in workflow["build"]["permissions"]

    def index(text):
        return next(
            i for i, s in enumerate(steps) if text in (s.get("name", "") + s.get("run", ""))
        )

    # After the distributions are uploaded, so it cannot change them; before the evidence
    # is summed and packed, so the attested bundle holds the image's records.
    assert index("Upload distributions") < checked < index("scripts/release_checksums.py")
    # Nothing is attested, published or pushed unless the build job, and so the image, passed.
    for job in ("attest", "verify", "publish", "image"):
        assert "build" in workflow[job]["needs"]
    assert "attest" in workflow["publish"]["needs"]


def test_ci_builds_and_runs_the_image_from_the_wheel_it_built():
    steps = ci_jobs()["distribution"]["steps"]
    [step] = [step for step in steps if "check_image.py" in step.get("run", "")]
    assert step["run"] == "python -I scripts/check_image.py dist"
    assert "if" not in step and "continue-on-error" not in step
    built = next(i for i, s in enumerate(steps) if s.get("run") == "python -m build --no-isolation")
    assert built < steps.index(step)


def test_only_an_approved_pypi_release_pushes_an_image_and_only_its_attest_job_signs():
    workflow = jobs()
    image, attest, verify = workflow["image"], workflow["image-attest"], workflow["image-verify"]
    assert image["if"] == "inputs.publish == 'pypi' && github.ref == 'refs/heads/main'"
    assert set(image["needs"]) == {"build", "verify", "publish"}
    assert image["environment"]["name"] == "pypi"
    assert image["permissions"] == {"contents": "read", "packages": "write"}
    download = next(s for s in image["steps"] if "download-artifact" in s.get("uses", ""))
    assert download["with"] == {
        "artifact-ids": "${{ needs.build.outputs.distributions_id || 'missing' }}",
        "path": "dist",
        "digest-mismatch": "error",
    }
    # The image is built and checked in a step that holds no token; only the step after it,
    # which runs unless that one failed, logs in and pushes what that step named.
    build, push = image["steps"][-2:]
    assert (build["id"], push["id"]) == ("build", "push")
    assert not {"env", "if", "continue-on-error"} & build.keys()
    assert not {"if", "continue-on-error"} & push.keys()
    assert push["env"] == {
        "REGISTRY_TOKEN": "${{ github.token }}",
        "IMAGE": "${{ steps.build.outputs.name }}",
        "VERSION": "${{ steps.build.outputs.version }}",
    }
    assert "login" not in build["run"] and "push" not in build["run"]
    assert "check_image.py" not in push["run"] and "buildx" not in push["run"]
    # The OIDC job runs no shell, checks nothing out and signs what the image job pushed,
    # with the same pinned action as the distributions.
    assert attest["needs"] == "image"
    assert attest["permissions"] == {"id-token": "write", "attestations": "write"}
    assert all("run" not in step for step in attest["steps"])
    [step] = attest["steps"]
    pinned = {s["uses"] for s in workflow["attest"]["steps"] if "attest-build" in s["uses"]}
    assert {step["uses"]} == pinned
    assert step["with"] == {
        "subject-name": "${{ needs.image.outputs.name }}",
        "subject-digest": "${{ needs.image.outputs.digest }}",
    }
    assert set(verify["needs"]) == {"image", "image-attest"}
    assert verify["permissions"] == {
        "contents": "read",
        "attestations": "read",
        "packages": "read",
    }


def stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o755)


def environment(tmp_path: Path, **values: str) -> dict[str, str]:
    return {
        **os.environ,
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
        "CALLS": str(tmp_path / "calls"),
        "GITHUB_REPOSITORY": "Owner/Repo",
        "GITHUB_SHA": SHA,
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_ACTOR": "maintainer",
        **values,
    }


PYTHON3 = """printf '%s\\n' "$*" >> "$CALLS"
[[ -z "${FAIL_CHECK:-}" ]] || exit 1
while (( $# )); do
  [[ "$1" != --github-output ]] || printf 'name=ghcr.io/owner/repo\\nversion=0.2.0\\n' >> "$2"
  shift
done
"""


@pytest.mark.parametrize("case", ["success", "check-fails"])
def test_the_build_step_runs_the_same_check_on_the_downloaded_wheel(tmp_path, case):
    (tmp_path / "bin").mkdir()
    stub(tmp_path / "bin", "python3", PYTHON3)
    stub(tmp_path / "bin", "docker", 'printf "docker %s\\n" "$*" >> "$CALLS"\n')
    output = tmp_path / "output"
    # Exercise the reviewed workflow shell with local stubs, never a registry.
    process = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", run_step("image", "build")["run"]],
        cwd=tmp_path,
        env=environment(
            tmp_path, GITHUB_OUTPUT=str(output), FAIL_CHECK="yes" if case == "check-fails" else ""
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert (process.returncode == 0) == (case == "success"), process.stderr
    # The step itself runs no docker command: the script builds, runs and checks.
    assert (tmp_path / "calls").read_text().splitlines() == [
        "-I scripts/check_image.py dist --name ghcr.io/owner/repo"
        " --label org.opencontainers.image.source=https://github.com/Owner/Repo"
        f" --label org.opencontainers.image.revision={SHA} --github-output {output}"
    ]
    if case == "success":
        assert output.read_text() == "name=ghcr.io/owner/repo\nversion=0.2.0\n"


DOCKER = """printf '%s\\n' "$*" >> "$CALLS"
case "$1 $2" in
  "login ghcr.io") cat > "$CALLS.token" ;;
  "push "*)
    [[ -z "${PUSH_FAIL:-}" ]] || exit 1
    [[ -z "${EMPTY_RECEIPT:-}" ]] || exit 0
    [[ -z "${DUPLICATE_RECEIPT:-}" ]] || printf '%s: digest: %s size: 1234\\n' "${2##*:}" "$PUSH_DIGEST"
    printf '%s: digest: %s size: 1234\\n' "${2##*:}" "$PUSH_DIGEST" ;;
  "logout ghcr.io") ;;
  *) exit 1 ;;
esac
"""


@pytest.mark.parametrize(
    "case",
    [
        "success",
        "other-image",
        "no-image",
        "unsafe-version",
        "digest",
        "no-receipt",
        "duplicate",
        "push-fails",
    ],
)
def test_the_push_step_pushes_only_the_image_the_build_step_named(tmp_path, case):
    for directory in ("bin", "runner"):
        (tmp_path / directory).mkdir()
    stub(tmp_path / "bin", "docker", DOCKER)
    output, summary = tmp_path / "output", tmp_path / "summary"
    image = {"other-image": "ghcr.io/other/repo", "no-image": ""}.get(case, "ghcr.io/owner/repo")
    # Exercise the reviewed workflow shell with local stubs, never a registry.
    process = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", run_step("image", "push")["run"]],
        cwd=tmp_path,
        env=environment(
            tmp_path,
            RUNNER_TEMP=str(tmp_path / "runner"),
            GITHUB_OUTPUT=str(output),
            GITHUB_STEP_SUMMARY=str(summary),
            REGISTRY_TOKEN="registry-token",  # noqa: S106 - a stub's input, not a credential
            IMAGE=image,
            VERSION="0.2.0;id" if case == "unsafe-version" else "0.2.0",
            PUSH_DIGEST="sha256:" + "ab" * 31 if case == "digest" else DIGEST,
            PUSH_FAIL="yes" if case == "push-fails" else "",
            EMPTY_RECEIPT="yes" if case == "no-receipt" else "",
            DUPLICATE_RECEIPT="yes" if case == "duplicate" else "",
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    calls = (tmp_path / "calls").read_text().splitlines() if (tmp_path / "calls").exists() else []
    assert (process.returncode == 0) == (case == "success"), process.stderr
    if case in {"other-image", "no-image", "unsafe-version"}:
        assert calls == []
    if case != "success":
        assert not output.exists() or output.read_text() == ""
        return
    image = "ghcr.io/owner/repo"
    assert calls == [
        "login ghcr.io -u maintainer --password-stdin",
        f"push {image}:0.2.0",
        "logout ghcr.io",
    ]
    assert (tmp_path / "calls.token").read_text() == "registry-token"
    assert output.read_text() == f"name={image}\ndigest={DIGEST}\n"
    assert summary.read_text() == f"Pushed {image}@{DIGEST}\n"


@pytest.mark.parametrize("case", ["success", "other-image", "bad-digest", "unverified"])
def test_the_image_digest_is_verified_against_the_release_source(tmp_path, case):
    (tmp_path / "bin").mkdir()
    stub(tmp_path / "bin", "docker", 'cat > /dev/null; printf "docker %s\\n" "$*" >> "$CALLS"\n')
    stub(
        tmp_path / "bin",
        "gh",
        'printf "gh %s\\n" "$*" >> "$CALLS"\nexit "$FAIL_VERIFY"\n',
    )
    process = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", run_step("image-verify")["run"]],
        cwd=tmp_path,
        env=environment(
            tmp_path,
            GH_TOKEN="registry-token",  # noqa: S106 - a stub's input, not a credential
            IMAGE="ghcr.io/other/repo" if case == "other-image" else "ghcr.io/owner/repo",
            DIGEST="sha256:" + "AB" * 32 if case == "bad-digest" else DIGEST,
            FAIL_VERIFY=str(int(case == "unverified")),
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert (process.returncode == 0) == (case == "success")
    calls = (tmp_path / "calls").read_text().splitlines() if (tmp_path / "calls").exists() else []
    if case in {"other-image", "bad-digest"}:
        assert calls == []
        return
    assert calls[-1] == (
        f"gh attestation verify oci://ghcr.io/owner/repo@{DIGEST} --repo Owner/Repo"
        " --signer-workflow Owner/Repo/.github/workflows/release.yml"
        f" --source-ref refs/heads/main --source-digest {SHA} --deny-self-hosted-runners"
    )


def test_the_dockerfile_installs_the_hash_locked_runtime_and_runs_unprivileged():
    text = (ROOT / "Dockerfile").read_text()
    bases = re.findall(r"^FROM (\S+)", text, re.M)
    assert len(bases) == 2 and len(set(bases)) == 1
    assert re.fullmatch(r"python:[\w.-]+@sha256:[0-9a-f]{64}", bases[0])
    assert re.findall(r"^COPY (?!--from).*$", text, re.M) == [
        "COPY requirements-action.lock nexus_symbiote-*-py3-none-any.whl /tmp/build/"
    ]
    assert "--require-hashes --only-binary=:all: -r /tmp/build/requirements-action.lock" in text
    assert "--only-binary=:all: --no-index --no-deps /tmp/build/nexus_symbiote-" in text
    assert "pip check" in text
    [user] = re.findall(r"^USER (\S+)$", text, re.M)
    assert user == "10001:10001" == check_image.USER
    # The group exists under the id USER names, and the user is put in it: --user-group
    # gave the 0.2.0 image a group 999 and a process group without a name.
    assert "groupadd --system --gid 10001 symbiote" in text
    assert "useradd --system --uid 10001 --gid 10001 --no-user-group " in text
    instructions = "".join(line for line in text.splitlines(True) if not line.startswith("#"))
    assert "--user-group" not in instructions.replace("--no-user-group", "")
    assert '\nENTRYPOINT ["/opt/nexus-symbiote/bin/nexus-symbiote"]\n' in text
