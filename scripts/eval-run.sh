#!/usr/bin/env bash
# Run one Step 17 FF2/P2 evaluation topology, capturing at sender and receiver.

set -euo pipefail

TOPOLOGY="${1:-veth}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${EVAL_BIN_DIR:-${CARGO_TARGET_DIR:-target}/debug}"
SEND_BIN="$BIN_DIR/udpopt-send"
RECV_BIN="$BIN_DIR/udpopt-recv"
RUN_DIR="${EVAL_RUN_DIR:-/tmp/uoe-$(date +%s)}"
PORT_BASE=41000
CANARY_PORT=40999
SCENARIOS=5
MDS_SIZE=1472
EVAL_REQUIRE_INTACT="${EVAL_REQUIRE_INTACT:-}"

case "$TOPOLOGY" in
    veth)
        SRC_NS=uoe-l
        DST_NS=uoe-r
        SRC_IP=10.9.1.1
        DST_IP=10.9.1.2
        SRC_IF=uoe-vl
        DST_IF=uoe-vr
        ;;
    router|nat|filter)
        SRC_NS=uoe-l
        DST_NS=uoe-r
        SRC_IP=10.9.1.1
        DST_IP=10.9.2.2
        SRC_IF=uoe-lm-l
        DST_IF=uoe-mr-r
        ;;
    *)
        echo "usage: eval-run.sh [veth|router|nat|filter]" >&2
        exit 64
        ;;
esac
case "$TOPOLOGY" in
    veth|router)
        EVAL_REQUIRE_INTACT="${EVAL_REQUIRE_INTACT:-1}"
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    if [ "${EVAL_SKIP_BUILD:-0}" != "1" ]; then
        cargo build --bins
    fi
    exec sudo env \
        "PATH=$PATH" \
        "EVAL_BIN_DIR=$BIN_DIR" \
        "EVAL_SKIP_BUILD=1" \
        "EVAL_RUN_DIR=$RUN_DIR" \
        "EVAL_REQUIRE_INTACT=$EVAL_REQUIRE_INTACT" \
        "$0" "$@"
fi

for tool in tcpdump python3 ip; do
    command -v "$tool" >/dev/null || {
        echo "error: $tool is missing" >&2
        exit 69
    }
done
[ -x "$SEND_BIN" ] || { echo "error: missing sender binary $SEND_BIN" >&2; exit 66; }
[ -x "$RECV_BIN" ] || { echo "error: missing receiver binary $RECV_BIN" >&2; exit 66; }

mkdir -p "$RUN_DIR"
"$SCRIPT_DIR/eval-env.sh" "$TOPOLOGY" up

TCPDUMP_PIDS=()
cleanup() {
    for pid in "${TCPDUMP_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    "$SCRIPT_DIR/eval-env.sh" "$TOPOLOGY" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

FILTER="udp and dst portrange $CANARY_PORT-$((PORT_BASE + SCENARIOS - 1))"

start_capture() {
    local ns="$1" iface="$2" pcap="$3" log="$4"
    # shellcheck disable=SC2086
    ip netns exec "$ns" tcpdump -i "$iface" -n -p -U --immediate-mode -Z root -w "$pcap" $FILTER 2>"$log" &
    TCPDUMP_PIDS+=("$!")
}

wait_for_pcap_header() {
    local pcap="$1" log="$2"
    for _ in $(seq 1 50); do
        [ "$(stat -c %s "$pcap" 2>/dev/null || echo 0)" -ge 24 ] && return 0
        sleep 0.1
    done
    cat "$log" >&2 || true
    echo "error: tcpdump did not become ready for $pcap" >&2
    return 1
}

send_canary_until_capture_grows() {
    local pcap="$1"
    for _ in $(seq 1 50); do
        ip netns exec "$SRC_NS" python3 - "$SRC_IP" "$DST_IP" "$CANARY_PORT" <<'PY'
import socket
import sys
src, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
s.sendto(b"canary", (dst, port))
PY
        sleep 0.1
        [ "$(stat -c %s "$pcap" 2>/dev/null || echo 0)" -gt 24 ] && return 0
    done
    echo "error: capture never recorded warm-up traffic for $pcap" >&2
    return 1
}

stop_captures() {
    for _ in $(seq 1 20); do
        sleep 0.2
    done
    for pid in "${TCPDUMP_PIDS[@]}"; do
        kill -INT "$pid" 2>/dev/null || true
        wait "$pid" || true
    done
    TCPDUMP_PIDS=()
    for log in "$RUN_DIR"/*.tcpdump.log; do
        grep -Eq '^0 packets dropped by kernel' "$log" || {
            echo "error: tcpdump reported kernel drops in $log" >&2
            cat "$log" >&2
            exit 1
        }
    done
}

start_capture "$SRC_NS" "$SRC_IF" "$RUN_DIR/sender.pcap" "$RUN_DIR/sender.tcpdump.log"
start_capture "$DST_NS" "$DST_IF" "$RUN_DIR/receiver.pcap" "$RUN_DIR/receiver.tcpdump.log"
wait_for_pcap_header "$RUN_DIR/sender.pcap" "$RUN_DIR/sender.tcpdump.log"
wait_for_pcap_header "$RUN_DIR/receiver.pcap" "$RUN_DIR/receiver.tcpdump.log"
send_canary_until_capture_grows "$RUN_DIR/sender.pcap"
send_canary_until_capture_grows "$RUN_DIR/receiver.pcap"

run_scenario() {
    local name="$1" port="$2" count="$3"
    shift 3
    ip netns exec "$DST_NS" "$RECV_BIN" --dst-port "$port" --timeout-ms 3000 --count "$count" \
        --max-segments 8 --json \
        >"$RUN_DIR/recv-$name.jsonl" &
    local recv_pid=$!
    sleep 0.2
    ip netns exec "$SRC_NS" "$SEND_BIN" --src "$SRC_IP" --dst "$DST_IP" --src-port 40000 --dst-port "$port" "$@" \
        --manifest "$RUN_DIR/send-$name.jsonl" >"$RUN_DIR/send-$name.log"
    wait "$recv_pid" || true
}

run_scenario baseline 41000 1 --payload plain
run_scenario typed 41001 1 --payload wire --apc --mds "$MDS_SIZE" --mrds-size 2926 --req deadbeef
run_scenario pad 41002 1 --payload odd --req c0ffee01
run_scenario near-mtu 41003 1 --payload-size 1392 --apc --mds "$MDS_SIZE"
run_scenario frag 41004 8 --payload-size 256 --max-datagram-len 96 --peer-mrds-segments 8

stop_captures
python3 "$SCRIPT_DIR/eval-check.py" \
    --sender-pcap "$RUN_DIR/sender.pcap" \
    --receiver-pcap "$RUN_DIR/receiver.pcap" \
    --port-base "$PORT_BASE" \
    --port-count "$SCENARIOS" \
    ${EVAL_REQUIRE_INTACT:+--require-intact} | tee "$RUN_DIR/verdicts.jsonl"

echo "eval-run: artifacts in $RUN_DIR"
