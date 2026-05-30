# Linux dev/test container for RFC 9868 work.
#
# The crate compiles anywhere, but the raw-socket paths (Steps 8, 9, 14-16) and the
# evaluation harness (Step 17) only run on Linux with CAP_NET_RAW. macOS cannot run
# them at all. This image gives macOS contributors a Linux box (Docker Desktop's VM)
# in which `cargo build/fmt/clippy/test` and the root-gated socket lane all work.
FROM ubuntu:24.04

# Toolchain version is kept in sync with rust-toolchain.toml / Cargo.toml rust-version.
ARG RUST_VERSION=1.96

ENV DEBIAN_FRONTEND=noninteractive

# build-essential + pkg-config: build the crate and its native deps.
# iproute2 + tcpdump + libcap2-bin + ethtool: netns/veth, packet capture, capability and
#   offload inspection for the integration lane and the Step 17 harness.
# curl + ca-certificates + git + sudo: rustup install and an interactive dev shell.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        ethtool \
        git \
        iproute2 \
        libcap2-bin \
        pkg-config \
        sudo \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Non-root dev user with passwordless sudo. The container's CAP_NET_RAW/NET_ADMIN/SYS_ADMIN
# (granted in compose.yml) are effective only for root, so the root-gated raw-socket lane runs
# as `sudo -E cargo ...`. secure_path keeps rustup's cargo (under the dev HOME) on sudo's PATH;
# without it sudo resets PATH and `cargo` is not found.
ARG USERNAME=dev
RUN useradd --create-home --shell /bin/bash "${USERNAME}" \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${USERNAME}" \
    && echo "Defaults:${USERNAME} secure_path=\"/home/${USERNAME}/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" >> "/etc/sudoers.d/${USERNAME}" \
    && chmod 0440 "/etc/sudoers.d/${USERNAME}"

# Pre-create the bind/volume mountpoints owned by dev. A fresh named volume inherits the
# ownership of the image directory it mounts over, so this keeps cargo-registry/target-cache
# writable by the non-root dev user.
RUN mkdir -p /workspace && chown "${USERNAME}:${USERNAME}" /workspace

USER ${USERNAME}
ENV HOME=/home/${USERNAME}
ENV PATH=${HOME}/.cargo/bin:${PATH}

# Install rustup and the pinned toolchain with the components the repo lints with.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "${RUST_VERSION}" \
            --component rustfmt --component clippy \
    && rustc --version && cargo --version \
    && mkdir -p "${HOME}/.cargo/registry" /workspace/target

WORKDIR /workspace
