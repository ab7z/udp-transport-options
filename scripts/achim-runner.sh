#!/usr/bin/env bash
# Remote command fragments are intentionally expanded and quoted on the client.
# shellcheck disable=SC2029
# Cargo runner for the supported Linux musl targets (wired up in .cargo/config.toml): ships the
# cross-built binary to the configured test host and executes it there, streaming output and
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
# remote shell; the configured login shell must be bash, which understands %q quoting.
cmd="$(printf "%q " "$RUN_DIR/$name" "$@")"
if [ "${ACHIM_SUDO:-0}" = "1" ]; then
    cmd="sudo env ACHIM_SUDO=1 $cmd"
fi
exec ssh "$HOST" "$cmd"
