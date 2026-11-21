# The nexus-symbiote CLI on the hash-locked runtime that the GitHub Action installs.
# Build it from a context that holds only this file, requirements-action.lock and one
# release wheel (docs/container-image.md); the release workflow pushes and attests it.
# Both stages use the same base, pinned by digest; Dependabot proposes its updates.
FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS install
COPY requirements-action.lock nexus_symbiote-*-py3-none-any.whl /tmp/build/
RUN python -m venv /opt/nexus-symbiote \
    && /opt/nexus-symbiote/bin/python -m pip install --no-cache-dir --disable-pip-version-check \
        --require-hashes --only-binary=:all: -r /tmp/build/requirements-action.lock \
    && /opt/nexus-symbiote/bin/python -m pip install --no-cache-dir --disable-pip-version-check \
        --only-binary=:all: --no-index --no-deps /tmp/build/nexus_symbiote-*-py3-none-any.whl \
    && /opt/nexus-symbiote/bin/python -m pip check

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.title="nexus-symbiote" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --system --user-group --uid 10001 --home-dir /home/symbiote --create-home \
        --shell /usr/sbin/nologin symbiote
COPY --from=install /opt/nexus-symbiote /opt/nexus-symbiote
ENV PATH=/opt/nexus-symbiote/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1
# The installed environment is root's and read-only to the user that runs the CLI. The
# CLI is offline unless --live is given; run the image with --network none as well.
USER 10001:10001
WORKDIR /home/symbiote
ENTRYPOINT ["/opt/nexus-symbiote/bin/nexus-symbiote"]
CMD ["--help"]
