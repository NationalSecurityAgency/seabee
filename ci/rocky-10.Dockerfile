ARG DOCKER_MIRROR

FROM ${DOCKER_MIRROR}rockylinux/rockylinux:10

LABEL org.opencontainers.image.source=https://github.com/NationalSecurityAgency/seabee

COPY scripts /scripts
COPY pyproject.toml /pyproject.toml

RUN DOCKER=1 /scripts/update_dependencies.sh \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# update the path for rust and poetry installation
ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:/root/.local/bin:$PATH
