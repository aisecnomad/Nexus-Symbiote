"""The release image: built from the verified wheel, pushed, attested and verified by digest."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.support import ROOT

DIGEST = "sha256:" + "ab" * 32
SHA = "c" * 40
WHEEL = "nexus_symbiote-0.2.0-py3-none-any.whl"


def jobs():
    return yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]


def run_step(job: str) -> dict:
    return next(step for step in jobs()[job]["steps"] if "run" in step)


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


DOCKER = """printf '%s\\n' "$*" >> "$CALLS"
case "$1 $2" in
  "buildx build") ls -A "${@: -1}" > "$CALLS.context" ;;
  "run --rm") exit "${FAIL_RUN:-0}" ;;
  "image inspect") echo "${IMAGE_USER:-10001:10001}" ;;
  "login ghcr.io") cat > "$CALLS.token" ;;
  "push "*)
    [[ -z "${PUSH_FAIL:-}" ]] || exit 1
    [[ -z "${EMPTY_RECEIPT:-}" ]] || exit 0
    [[ -z "${DUPLICATE_RECEIPT:-}" ]] || printf '%s: digest: %s size: 1234\\n' "${2##*:}" "$PUSH_DIGEST"
    printf '%s: digest: %s size: 1234\\n' "${2##*:}" "$PUSH_DIGEST" ;;
  "buildx imagetools") exit 1 ;;
esac
"""


@pytest.mark.parametrize(
    "case",
    [
        "success",
        "no-wheel",
        "two-wheels",
        "symlinked-wheel",
        "root",
        "run-fails",
        "digest",
        "no-receipt",
        "duplicate",
        "push-fails",
    ],
)
def test_the_image_step_pushes_only_the_one_verified_wheel_that_ran_offline(tmp_path, case):
    for directory in ("bin", "dist", "runner"):
        (tmp_path / directory).mkdir()
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / "requirements-action.lock").write_text("")
    if case == "symlinked-wheel":
        (tmp_path / "elsewhere.whl").write_text("wheel")
        (tmp_path / "dist" / WHEEL).symlink_to(tmp_path / "elsewhere.whl")
    elif case != "no-wheel":
        (tmp_path / "dist" / WHEEL).write_text("wheel")
    if case == "two-wheels":
        (tmp_path / "dist" / "nexus_symbiote-0.1.0-py3-none-any.whl").write_text("old")
    (tmp_path / "dist" / "nexus_symbiote-0.2.0.tar.gz").write_text("sdist")
    stub(tmp_path / "bin", "docker", DOCKER)
    output, summary = tmp_path / "output", tmp_path / "summary"
    # Exercise the reviewed workflow shell with local stubs, never a registry.
    process = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", run_step("image")["run"]],
        cwd=tmp_path,
        env=environment(
            tmp_path,
            RUNNER_TEMP=str(tmp_path / "runner"),
            GITHUB_OUTPUT=str(output),
            GITHUB_STEP_SUMMARY=str(summary),
            REGISTRY_TOKEN="registry-token",  # noqa: S106 - a stub's input, not a credential
            PUSH_DIGEST="sha256:" + "ab" * 31 if case == "digest" else DIGEST,
            PUSH_FAIL="yes" if case == "push-fails" else "",
            EMPTY_RECEIPT="yes" if case == "no-receipt" else "",
            DUPLICATE_RECEIPT="yes" if case == "duplicate" else "",
            IMAGE_USER="0:0" if case == "root" else "10001:10001",
            FAIL_RUN=str(int(case == "run-fails")),
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    calls = (tmp_path / "calls").read_text().splitlines() if (tmp_path / "calls").exists() else []
    assert (process.returncode == 0) == (case == "success"), process.stderr
    pushed = [call for call in calls if call.startswith("push ")]
    if case in {"no-wheel", "two-wheels", "symlinked-wheel"}:
        assert calls == []
    elif case in {"root", "run-fails"}:
        assert pushed == [] and not any(call.startswith("login") for call in calls)
    if case != "success":
        assert not output.exists() or output.read_text() == ""
        return
    image = "ghcr.io/owner/repo"
    assert calls[0].startswith(f"buildx build --load --provenance=false --tag {image}:0.2.0 ")
    assert f"org.opencontainers.image.revision={SHA}" in calls[0]
    assert set((tmp_path / "calls.context").read_text().split()) == {
        "Dockerfile",
        WHEEL,
        "requirements-action.lock",
    }
    assert calls[1] == f"run --rm --network none {image}:0.2.0 --version"
    order = [call.split()[0] for call in calls]
    assert order.index("run") < order.index("login") < order.index("push")
    assert pushed == [f"push {image}:0.2.0"]
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
    assert user == "10001:10001"
    assert f"= {user}\n" in run_step("image")["run"]
    assert '\nENTRYPOINT ["/opt/nexus-symbiote/bin/nexus-symbiote"]\n' in text
