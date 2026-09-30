ARG DOCKER_MIRROR

FROM ${DOCKER_MIRROR}ubuntu:resolute

LABEL org.opencontainers.image.source=https://github.com/NationalSecurityAgency/seabee

COPY scripts /scripts
COPY pyproject.toml /pyproject.toml

RUN DOCKER=1 /scripts/update_dependencies.sh \
    && rm -rf /var/lib/apt/lists/*

# update the path for rust and poetry installation
ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:/root/.local/bin:$PATH
