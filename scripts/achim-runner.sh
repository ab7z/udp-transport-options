#!/usr/bin/env bash
# Cargo runner for the aarch64-unknown-linux-musl target (wired up in .cargo/config.toml):
# ships the cross-built binary to the achim host and executes it there, streaming output and
# propagating the exit code. ACHIM_SUDO=1 runs the binary under sudo (raw sockets need root).
#
# Invoked by cargo as: achim-runner.sh <binary> [args...]

set -euo pipefail

HOST="${VM_UBUNTU_SERVER_HOST:-achim}"
RUN_DIR="${VM_UBUNTU_SERVER_RUN_DIR:-.cache/udpopt-run}"

bin="$1"
shift

name="$(basename "$bin")"
ssh "$HOST" "mkdir -p $(printf "%q" "$RUN_DIR")"
rsync -az "$bin" "$HOST:$RUN_DIR/$name"

# %q-quote the remote command so test-harness args (filters, --ignored, ...) survive the
# remote shell; the achim login shell is bash, which understands %q quoting.
cmd="$(printf "%q " "$RUN_DIR/$name" "$@")"
if [ "${ACHIM_SUDO:-0}" = "1" ]; then
    cmd="sudo env ACHIM_SUDO=1 $cmd"
fi
exec ssh "$HOST" "$cmd"
