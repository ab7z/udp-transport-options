#!/usr/bin/env bash
# Cross-compile lanes for the achim Linux test host: build on the Mac for
# aarch64-unknown-linux-musl (rust-lld, see .cargo/config.toml) and only *execute* on achim.
# Test binaries travel through the cargo runner scripts/achim-runner.sh; the spike syncs its
# prebuilt example binaries and runs scripts/spike.sh remotely. achim carries no Rust toolchain.

set -euo pipefail

# Repo root: .cargo/config.toml and the relative runner path only resolve from here.
cd "$(dirname "$0")/.."

# Nested checkouts (e.g. git worktrees under .claude/worktrees/) see BOTH this checkout's
# .cargo/config.toml and the parent checkout's; cargo joins array values when merging config
# files, which would invoke the runner with itself as its first argument (it then ships itself
# and fails on achim with "Host key verification failed"). The environment variable takes
# precedence over all config files and keeps the runner single.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="$PWD/scripts/achim-runner.sh"

HOST="${VM_UBUNTU_SERVER_HOST:-achim}"
REMOTE_DIR="${VM_UBUNTU_SERVER_DIR:-udp-transport-options}"
TARGET=aarch64-unknown-linux-musl
# Honor a CARGO_TARGET_DIR override so sync/spike never ship missing or stale binaries.
TARGET_DIR="${CARGO_TARGET_DIR:-target}/$TARGET/debug"

usage() {
    cat <<'EOF'
usage: scripts/vm-ubuntu-server.sh [command]

Commands:
  bootstrap   Install the local musl cross target; check ssh, sudo -n, and rsync on achim
  sync        Cross-build and sync the binaries (bins + examples) and scripts to achim
  build       cargo build --target aarch64-unknown-linux-musl (local)
  test        cargo test --target ... (test binaries execute on achim via the runner)
  fmt         cargo fmt --check (local)
  clippy      cargo clippy --all-targets --target ... -- -D warnings (lints the Linux cfg paths)
  verify      Run build, test, fmt, and clippy (default)
  ignored     Root-gated test lane: test binaries run under sudo on achim (ACHIM_SUDO=1)
  spike       Cross-build the spike examples, sync, and run the Step 0.5 spike on achim
  wire        Cross-build, sync, and run the tcpdump wire-verification lane on achim (root)
  shell       Open a shell in the remote run directory on achim
  run <cmd>   Run an arbitrary command in the remote run directory on achim

Environment:
  VM_UBUNTU_SERVER_HOST  SSH host alias to use (default: achim)
  VM_UBUNTU_SERVER_DIR   Remote run directory, relative to $HOME unless absolute
                         (default: udp-transport-options; no spaces)
EOF
}

remote_dir_q() {
    printf "%q" "$REMOTE_DIR"
}

bootstrap() {
    # The toolchain itself is pinned by rust-toolchain.toml; this only adds the cross target.
    rustup target add "$TARGET"
    ssh "$HOST" 'set -eu
echo "ssh: ok ($(uname -sm))"
command -v rsync >/dev/null || { echo "rsync: MISSING" >&2; exit 1; }
echo "rsync: ok"
sudo -n true || { echo "sudo -n: FAILED (the root-gated lanes need passwordless sudo)" >&2; exit 1; }
echo "sudo -n: ok"
# Informational only: the wire lane re-checks these itself with a hard error.
for tool in tcpdump tshark python3; do
    command -v "$tool" >/dev/null && echo "$tool: ok" || echo "$tool: MISSING (wire lane needs it: sudo apt-get install -y $tool)"
done'
}

sync_bins() {
    cargo build --target "$TARGET" --bins --examples
    ssh "$HOST" "mkdir -p $(remote_dir_q)/bin $(remote_dir_q)/scripts"
    rsync -az \
        "$TARGET_DIR/udpopt-send" "$TARGET_DIR/udpopt-recv" \
        "$TARGET_DIR/examples/spike_server" "$TARGET_DIR/examples/spike_client" \
        "$TARGET_DIR/examples/wire_probe" \
        "$HOST:$REMOTE_DIR/bin/"
    rsync -az scripts/spike.sh scripts/wire-check.sh scripts/wire-check.py "$HOST:$REMOTE_DIR/scripts/"
}

cmd="${1:-verify}"
case "$cmd" in
    bootstrap)
        bootstrap
        ;;
    sync)
        sync_bins
        ;;
    build)
        cargo build --target "$TARGET"
        ;;
    test)
        cargo test --target "$TARGET"
        ;;
    fmt)
        cargo fmt --check
        ;;
    clippy)
        cargo clippy --all-targets --target "$TARGET" -- -D warnings
        ;;
    verify)
        cargo build --target "$TARGET"
        cargo test --target "$TARGET"
        cargo fmt --check
        cargo clippy --all-targets --target "$TARGET" -- -D warnings
        ;;
    ignored)
        ACHIM_SUDO=1 cargo test --target "$TARGET" -- --ignored
        ;;
    spike)
        sync_bins
        ssh "$HOST" "set -euo pipefail; cd $(remote_dir_q); SPIKE_SKIP_BUILD=1 SPIKE_BIN_DIR=bin scripts/spike.sh"
        ;;
    wire)
        sync_bins
        ssh "$HOST" "set -euo pipefail; cd $(remote_dir_q); WIRE_SKIP_BUILD=1 WIRE_BIN_DIR=bin scripts/wire-check.sh"
        ;;
    shell)
        ssh -t "$HOST" "cd $(remote_dir_q) 2>/dev/null || cd; exec \${SHELL:-/bin/bash}"
        ;;
    run)
        shift
        if [ "$#" -eq 0 ]; then
            usage >&2
            exit 64
        fi
        ssh "$HOST" "set -euo pipefail; cd $(remote_dir_q); $*"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 64
        ;;
esac
