# Container image

Each PyPI release from the next one on also publishes the CLI as a container image,
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
the unprivileged user 10001, its installed environment is owned by root, and its entry
point is `nexus-symbiote`. The CLI is offline unless `--live` is given; the image cannot
take the network away by itself, so run it with `--network none`.

## Verify and run a published image

These commands need a published image, so they cannot be run before the first release
that has one. Take the digest from the release notes, or resolve the version's tag to its
digest, and use only the digest from then on: a tag can be pushed again, a digest cannot
change.

```bash
gh auth login
docker buildx imagetools inspect ghcr.io/aisecnomad/nexus-symbiote:<version>
gh attestation verify oci://ghcr.io/aisecnomad/nexus-symbiote@<digest> \
  --repo aisecnomad/Nexus-Symbiote \
  --signer-workflow aisecnomad/Nexus-Symbiote/.github/workflows/release.yml \
  --source-ref refs/heads/main --source-digest <release commit SHA> \
  --deny-self-hosted-runners
docker run --rm --network none --read-only --user "$(id -u):$(id -g)" \
  -v "$PWD:/work:ro" ghcr.io/aisecnomad/nexus-symbiote@<digest> \
  scan /work --no-project-policy -f cyclonedx > agent.cdx.json
```

The attestation binds the image digest to `release.yml` on `main` at the release commit;
it does not show that the base image or runner was uncompromised. Mount the project
read-only and run as yourself, so the scan reads only what you can read. Use `-o` with
a path on a writable mount to write a file instead of standard output.

## Build it yourself

From a checkout, in the environment `make install-locked` installed:

```bash
context="$(mktemp -d)"
python -m build --no-isolation --wheel --outdir "$context"
cp Dockerfile requirements-action.lock "$context/"
docker build --tag nexus-symbiote:local "$context"
docker run --rm --network none nexus-symbiote:local --version
docker run --rm --network none --read-only -v "$PWD/examples/demo-agent:/work:ro" \
  nexus-symbiote:local scan /work --no-project-policy -f cyclonedx > demo.cdx.json
```

The scan of the demo agent in the image writes the same bytes as
`nexus-symbiote scan examples/demo-agent --no-project-policy -f cyclonedx` on the host.

## Limits

- The image is built for `linux/amd64` only.
- The base image changes only when a reviewed pull request moves its digest; Dependabot
  proposes those. A published image is not rebuilt when its base gets a fix, so take the
  next release's image.
- The release pushes the image after the PyPI upload. An image job that is run again
  pushes a new digest under the same tag, which is why the commands above verify and run
  a digest.
