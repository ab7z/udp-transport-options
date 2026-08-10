#!/usr/bin/env bash
# Remote command fragments are intentionally expanded and quoted on the client.
# shellcheck disable=SC2029
# Cross-compile lanes for configurable Linux test hosts: build on the Mac for a supported musl
# target (rust-lld, see .cargo/config.toml) and only execute on the matching remote architecture.
# Test binaries travel through the cargo runner scripts/achim-runner.sh; the spike syncs its
# prebuilt example binaries and runs scripts/spike.sh remotely. Remote hosts need no Rust toolchain.

set -euo pipefail

# Repo root: .cargo/config.toml and the relative runner path only resolve from here.
cd "$(dirname "$0")/.."

HOST="${VM_UBUNTU_SERVER_HOST:-achim}"
REMOTE_DIR="${VM_UBUNTU_SERVER_DIR:-udp-transport-options}"
TARGET="${VM_UBUNTU_SERVER_TARGET:-aarch64-unknown-linux-musl}"

# Nested checkouts (e.g. git worktrees under .claude/worktrees/) see BOTH this checkout's
# .cargo/config.toml and the parent checkout's; cargo joins array values when merging config
# files, which would invoke the runner with itself as its first argument. The target-specific
# environment variable takes precedence over all config files and keeps the runner single.
unset CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER
unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER
case "$TARGET" in
    aarch64-unknown-linux-musl)
        EXPECTED_REMOTE_ARCH=aarch64
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="$PWD/scripts/achim-runner.sh"
        ;;
    x86_64-unknown-linux-musl)
        EXPECTED_REMOTE_ARCH=x86_64
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="$PWD/scripts/achim-runner.sh"
        ;;
    *)
        echo "error: unsupported VM_UBUNTU_SERVER_TARGET: $TARGET" >&2
        echo "supported targets: aarch64-unknown-linux-musl, x86_64-unknown-linux-musl" >&2
        exit 64
        ;;
esac

# Honor a CARGO_TARGET_DIR override so sync/spike never ship missing or stale binaries.
TARGET_DIR="${CARGO_TARGET_DIR:-target}/$TARGET/debug"

usage() {
    cat <<'EOF'
usage: scripts/vm-ubuntu-server.sh [command]

Commands:
  bootstrap   Install the selected local musl target; check remote architecture and tools
  sync        Cross-build and sync the binaries (bins + examples) and scripts to the remote host
  build       cargo build --target <selected musl target> (local)
  test        cargo test --target ... (test binaries execute remotely via the runner)
  fmt         cargo fmt --check (local)
  clippy      cargo clippy --all-targets --target ... -- -D warnings (lints the Linux cfg paths)
  verify      Run build, test, fmt, and clippy (default)
  ignored     Root-gated test lane: test binaries run remotely under sudo (ACHIM_SUDO=1)
  spike       Cross-build, sync, and run the Step 0.5 spike on the remote host
  wire        Cross-build, sync, and run the tcpdump wire-verification lane remotely (root)
  eval [topo] Cross-build, sync, and run the Step 17 FF2 eval lane remotely (root)
  shell       Open a shell in the remote run directory
  run <cmd>   Run an arbitrary command in the remote run directory

Environment:
  VM_UBUNTU_SERVER_HOST  SSH host alias to use (default: achim)
  VM_UBUNTU_SERVER_DIR   Remote run directory, relative to $HOME unless absolute
                         (default: udp-transport-options; no spaces)
  VM_UBUNTU_SERVER_TARGET  Rust musl target matching the remote architecture
                           (default: aarch64-unknown-linux-musl; also supports
                           x86_64-unknown-linux-musl)
EOF
}

remote_dir_q() {
    printf "%q" "$REMOTE_DIR"
}

check_remote_arch() {
    local actual_arch
    actual_arch="$(ssh "$HOST" uname -m)"
    if [ "$actual_arch" != "$EXPECTED_REMOTE_ARCH" ]; then
        echo "error: remote architecture mismatch on $HOST for $TARGET:" >&2
        echo "expected $EXPECTED_REMOTE_ARCH, got $actual_arch" >&2
        return 65
    fi
}

bootstrap() {
    check_remote_arch
    # The toolchain itself is pinned by rust-toolchain.toml; this only adds the cross target.
    rustup target add "$TARGET"
    ssh "$HOST" 'set -eu
echo "ssh: ok ($(uname -sm))"
command -v rsync >/dev/null || { echo "rsync: MISSING" >&2; exit 1; }
echo "rsync: ok"
sudo -n true || { echo "sudo -n: FAILED (the root-gated lanes need passwordless sudo)" >&2; exit 1; }
echo "sudo -n: ok"
# Informational only: the privileged lanes re-check required tools themselves with hard errors.
for tool in tcpdump tshark python3 ethtool nft; do
    command -v "$tool" >/dev/null && echo "$tool: ok" || echo "$tool: MISSING (wire lane needs it: sudo apt-get install -y $tool)"
done'
}

sync_bins() {
    check_remote_arch
    cargo build --target "$TARGET" --bins --examples
    ssh "$HOST" "mkdir -p $(remote_dir_q)/bin $(remote_dir_q)/scripts"
    rsync -az \
        "$TARGET_DIR/udpopt-send" "$TARGET_DIR/udpopt-recv" \
        "$TARGET_DIR/examples/spike_server" "$TARGET_DIR/examples/spike_client" \
        "$TARGET_DIR/examples/wire_probe" \
        "$HOST:$REMOTE_DIR/bin/"
    rsync -az \
        scripts/spike.sh scripts/wire-check.sh scripts/wire-check.py \
        scripts/eval-env.sh scripts/eval-run.sh scripts/eval-check.py \
        "$HOST:$REMOTE_DIR/scripts/"
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
        check_remote_arch
        cargo test --target "$TARGET"
        ;;
    fmt)
        cargo fmt --check
        ;;
    clippy)
        cargo clippy --all-targets --target "$TARGET" -- -D warnings
        ;;
    verify)
        check_remote_arch
        cargo build --target "$TARGET"
        cargo test --target "$TARGET"
        cargo fmt --check
        cargo clippy --all-targets --target "$TARGET" -- -D warnings
        ;;
    ignored)
        check_remote_arch
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
    eval)
        topo="${2:-veth}"
        case "$topo" in
            veth|router|nat|filter) ;;
            *)
                echo "usage: scripts/vm-ubuntu-server.sh eval [veth|router|nat|filter]" >&2
                exit 64
                ;;
        esac
        sync_bins
        topo_q="$(printf "%q" "$topo")"
        ssh "$HOST" "set -euo pipefail; cd $(remote_dir_q); EVAL_SKIP_BUILD=1 EVAL_BIN_DIR=bin scripts/eval-run.sh $topo_q"
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
