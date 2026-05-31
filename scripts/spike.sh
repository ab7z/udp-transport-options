#!/usr/bin/env bash
# Step 0.5 spike orchestrator (throwaway). Stages a 1500-MTU veth link across two network
# namespaces, runs the client (default netns) and server (netns spk), prints the per-case report,
# and tears the link down. Prototypes the Step 17 netns/veth harness.
#
#   docker compose run --rm dev sudo -E scripts/spike.sh          # full run (setup -> run -> teardown)
#   docker compose run --rm dev sudo -E scripts/spike.sh --keep   # run, but leave the link up
#   docker compose run --rm dev sudo -E scripts/spike.sh up       # just create the link (e.g. tcpdump)
#   docker compose run --rm dev sudo -E scripts/spike.sh down     # remove the link
#
# Needs root + CAP_NET_ADMIN/CAP_SYS_ADMIN (the dev service holds them; reach them via sudo). `-E`
# keeps the dev HOME so cargo finds its registry cache.
set -euo pipefail

NS=spk
VETH_H=veth-h
VETH_P=veth-p
CLIENT_IP=10.0.0.1
SERVER_IP=10.0.0.2
PREFIX=24
MTU=1500
READY=/tmp/spike-server-ready
SRV_BIN=target/debug/examples/spike_server
CLI_BIN=target/debug/examples/spike_client

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
    echo "building examples..."
    cargo build --examples

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

action="${1:-run}"
case "$action" in
    up)
        link_up
        ;;
    down)
        link_down
        echo "link down"
        ;;
    run | --keep)
        link_up
        if [ "$action" = "--keep" ]; then
            rc=0
            run_spike || rc=$?
            echo "(--keep) link left up; tear down with: scripts/spike.sh down"
            exit $rc
        fi
        trap link_down EXIT
        rc=0
        run_spike || rc=$?
        exit $rc
        ;;
    *)
        echo "usage: spike.sh [run|--keep|up|down]" >&2
        exit 64
        ;;
esac
