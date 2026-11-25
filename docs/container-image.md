# Container image

Each PyPI release since 0.2.0 also publishes the CLI as a container image,
`ghcr.io/aisecnomad/nexus-symbiote`, tagged with the version. It contains the same
wheel that went to PyPI, installed on the hash-locked runtime the GitHub Action uses,
with its own build-provenance attestation. Use it where the CLI cannot run directly,
such as on Windows ([platforms](../SECURITY.md#platforms)).

## What is in it

The [`Dockerfile`](../Dockerfile) installs into a virtual environment on the Debian
`python:3.12.16-slim-trixie` base, pinned by digest:

- every pin of `requirements-action.lock` with `--require-hashes --only-binary=:all:`,
  followed by `pip check`;
- the release wheel with `--no-index --no-deps`, so nothing else is resolved.

The build context holds only the `Dockerfile`, the lock and the wheel. The image runs as
the unprivileged user and group `symbiote`, both with id 10001, its installed environment
is owned by root, and its entry point is `nexus-symbiote`. The CLI is offline unless
`--live` is given; the image cannot take the network away by itself, so run it with
`--network none`.

The `org.opencontainers.image.licenses` label is the wheel's license expression,
`MIT AND Apache-2.0 AND Community-Spec-1.0 AND CC-BY-3.0`: the wheel bundles the
CycloneDX and SPDX schemas. The Debian base and the locked dependencies keep their own
licenses, which the label does not list.

The 0.2.0 image differs in two details. Its label says `MIT`, and its `symbiote` group
has id 999 while the process runs with group id 10001, so `id` prints that group without a
name. The user id owns the home directory either way, and the CLI behaves the same.

## Verify and run a published image

Take the digest from the release notes, or resolve the version's tag to its digest, and
use only the digest from then on: a tag can be pushed again, a digest cannot change.

```bash
gh auth login
docker buildx imagetools inspect ghcr.io/aisecnomad/nexus-symbiote:<version>
gh attestation verify oci://ghcr.io/aisecnomad/nexus-symbiote@<digest> \
  --repo aisecnomad/Nexus-Symbiote \
  --signer-workflow aisecnomad/Nexus-Symbiote/.github/workflows/release.yml \
  --source-ref refs/heads/main --source-digest <release commit SHA> \
  --deny-self-hosted-runners
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" ghcr.io/aisecnomad/nexus-symbiote@<digest> \
  scan /work --no-project-policy -f cyclonedx > agent.cdx.json
```

The attestation binds the image digest to `release.yml` on `main` at the release commit;
it does not show that the base image or runner was uncompromised. Mount the project
read-only and run as yourself, so the scan reads only what you can read. Use `-o` with
a path on a writable mount to write a file instead of standard output.

`--cap-drop ALL` and `--security-opt no-new-privileges` leave the process no capability
and no way to gain one through the setuid programs of the Debian base (`su`, `mount`,
`passwd` and others), none of which the CLI runs. They also hold root to its file
permissions: run as root, the scan cannot read a tree that only another user may read,
and stops with `Directory '/work' is not readable` instead.

## Build it yourself

From a checkout, in the environment `make install-locked` installed:

```bash
context="$(mktemp -d)"
python -m build --no-isolation --wheel --outdir "$context"
cp Dockerfile requirements-action.lock "$context/"
docker build --tag nexus-symbiote:local "$context"
docker run --rm --network none nexus-symbiote:local --version
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/examples/demo-agent:/work:ro" nexus-symbiote:local \
  scan /work --no-project-policy -f cyclonedx > demo.cdx.json
```

The scan of the demo agent in the image writes the same bytes as
`nexus-symbiote scan examples/demo-agent --no-project-policy -f cyclonedx` on the host.

`make image-smoke` builds the wheel and the image the same way, then checks the image
with `scripts/check_image.py`, as CI and the release workflow do: the version it prints
without a network, its user and group, its entry point, its license label, and that scan
under the flags above.

## Limits

- The image is built for `linux/amd64` only.
- The base image changes only when a reviewed pull request moves its digest; Dependabot
  proposes those. A published image is not rebuilt when its base gets a fix, so take the
  next release's image. From the release after 0.2.0 on, the release evidence records
  which Debian fixes the base was behind when the image was built
  ([`image-base-updates.json`](releasing.md#what-the-pipeline-guarantees)).
- The release pushes the image after the PyPI upload. Every release run has by then built
  and checked the image once, from the same wheel, `Dockerfile` and lock, before it
  attested or uploaded anything. An image job that fails can be run again; it pushes a
  new digest under the same tag, which is why the commands above verify and run a digest.
