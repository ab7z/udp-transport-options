#!/usr/bin/env bash
# Step 0.5 spike orchestrator (throwaway). Stages a 1500-MTU veth link across two network
# namespaces, runs the client (default netns) and server (netns spk), prints the per-case report,
# and tears the link down. Prototypes the Step 17 netns/veth harness.
#
#   scripts/vm-ubuntu-server.sh spike       # cross-build on the Mac, sync + run on achim
#   scripts/spike.sh             # full local Linux run (setup -> run -> teardown)
#   scripts/spike.sh up          # just create the link (e.g. tcpdump)
#   scripts/spike.sh down        # remove the link
#
# Needs root + CAP_NET_RAW/CAP_NET_ADMIN/CAP_SYS_ADMIN. If called as a normal user, the script builds
# the examples first (unless SPIKE_SKIP_BUILD=1, e.g. for prebuilt cross-compiled binaries in
# SPIKE_BIN_DIR) and then re-execs itself under sudo for the namespace/raw-socket work.

set -euo pipefail

action="${1:-run}"
case "$action" in
    run|up|down) ;;
    *)
        echo "usage: spike.sh [run|up|down]" >&2
        exit 64
        ;;
esac

BIN_DIR="${SPIKE_BIN_DIR:-target/debug/examples}"
SRV_BIN="$BIN_DIR/spike_server"
CLI_BIN="$BIN_DIR/spike_client"

# Self-elevate: link setup + raw sockets need CAP_NET_RAW/CAP_NET_ADMIN/CAP_SYS_ADMIN. Build before
# sudo so root never runs cargo and does not create files in the Cargo target directory.
if [ "$(id -u)" -ne 0 ]; then
    if [ "$action" = "run" ]; then
        if [ "${SPIKE_SKIP_BUILD:-0}" != "1" ]; then
            echo "building examples..."
            cargo build --examples
        fi
        if [ ! -x "$SRV_BIN" ] || [ ! -x "$CLI_BIN" ]; then
            echo "error: spike binaries not found under $BIN_DIR (set SPIKE_BIN_DIR?)" >&2
            exit 66
        fi
    fi
    exec sudo env \
        "PATH=$PATH" \
        "SPIKE_BIN_DIR=$BIN_DIR" \
        "$0" "$@"
fi

NS=spk
VETH_H=veth-h
VETH_P=veth-p
CLIENT_IP=10.0.0.1
SERVER_IP=10.0.0.2
PREFIX=24
MTU=1500
READY=/tmp/spike-server-ready

link_up() {
    link_down >/dev/null 2>&1 || true
    ip netns add "$NS"
    ip link add "$VETH_H" type veth peer name "$VETH_P"
    ip link set "$VETH_P" netns "$NS"
    ip addr add "$CLIENT_IP/$PREFIX" dev "$VETH_H"
    ip link set "$VETH_H" mtu "$MTU" up
    ip netns exec "$NS" ip addr add "$SERVER_IP/$PREFIX" dev "$VETH_P"
    ip netns exec "$NS" ip link set "$VETH_P" mtu "$MTU" up
    ip netns exec "$NS" ip link set lo up
    echo "link up: $VETH_H($CLIENT_IP) <=> [$NS]$VETH_P($SERVER_IP), mtu $MTU"
}

link_down() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH_H" 2>/dev/null || true
    rm -f "$READY"
}

run_spike() {
    rm -f "$READY"
    # Built (or synced) before the sudo re-exec; root never runs cargo.
    if [ ! -x "$SRV_BIN" ] || [ ! -x "$CLI_BIN" ]; then
        echo "error: spike binaries not found under $BIN_DIR; run via scripts/spike.sh as a normal user" >&2
        return 66
    fi

    # Server in netns spk (background); wait until it has opened its recv socket.
    ip netns exec "$NS" "$SRV_BIN" &
    local srv_pid=$!
    for _ in $(seq 1 50); do
        [ -f "$READY" ] && break
        sleep 0.1
    done
    [ -f "$READY" ] || echo "warning: server readiness file not seen; proceeding anyway" >&2

    # Client in the default netns: gates the send-limit case (Finding B).
    local cli_rc=0 srv_rc=0
    "$CLI_BIN" || cli_rc=$?
    # Server gates delivery; let it finish collecting + reporting.
    wait "$srv_pid" || srv_rc=$?

    echo "spike: client rc=$cli_rc, server rc=$srv_rc"
    [ "$cli_rc" -eq 0 ] && [ "$srv_rc" -eq 0 ]
}

case "$action" in
    up)
        link_up
        ;;
    down)
        link_down
        echo "link down"
        ;;
    run)
        link_up
        trap link_down EXIT
        rc=0
        run_spike || rc=$?
        exit $rc
        ;;
esac
