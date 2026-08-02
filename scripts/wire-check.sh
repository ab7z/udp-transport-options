#!/usr/bin/env bash
# Step 10.5 wire-verification lane: capture the examples/wire_probe.rs scenario set on lo with
# tcpdump and gate the post-kernel bytes through the independent checker scripts/wire-check.py,
# including a tshark L3/L4 field cross-check. See docs/plan/steps/10b-wire-check.md.
#
#   scripts/vm-ubuntu-server.sh wire        # cross-build on the Mac, sync + run on achim
#   scripts/wire-check.sh                   # local Linux run (builds the probe, self-elevates)
#
# Needs root + CAP_NET_RAW for the raw-socket probe and the capture. If called as a normal user,
# the script builds the probe first (unless WIRE_SKIP_BUILD=1, e.g. for prebuilt cross-compiled
# binaries in WIRE_BIN_DIR) and re-execs itself under sudo.
#
# Artifacts (pcap, tshark views, logs) persist under /tmp/udpopt-wire for debugging and for the
# documented mutation check (flip one surplus byte in the pcap -> the checker must fail).

set -euo pipefail

# Honor a CARGO_TARGET_DIR override like vm-ubuntu-server.sh does, so a local build and this
# script always agree on where the probe binary lives.
BIN_DIR="${WIRE_BIN_DIR:-${CARGO_TARGET_DIR:-target}/debug/examples}"
PROBE="$BIN_DIR/wire_probe"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR=/tmp/udpopt-wire
PCAP="$RUN_DIR/wire.pcap"

# Keep in sync with examples/wire_probe.rs and scripts/wire-check.py.
SRC_PORT=39424
PORT_LO=39528
# Ten single-datagram scenarios plus the shared production-split port.
PORT_HI=39538
# Warm-up-only port just below the scenario range; the checker ignores it entirely.
CANARY_PORT=39527

# Self-elevate: build before sudo so root never runs cargo (spike.sh pattern).
if [ "$(id -u)" -ne 0 ]; then
    if [ "${WIRE_SKIP_BUILD:-0}" != "1" ]; then
        echo "building wire_probe..."
        cargo build --example wire_probe
    fi
    if [ ! -x "$PROBE" ]; then
        echo "error: $PROBE not found (set WIRE_BIN_DIR?)" >&2
        exit 66
    fi
    exec sudo env \
        "PATH=$PATH" \
        "WIRE_BIN_DIR=$BIN_DIR" \
        "WIRE_SKIP_BUILD=1" \
        "$0" "$@"
fi

for tool in tcpdump tshark python3; do
    command -v "$tool" >/dev/null || {
        echo "error: $tool is missing (sudo apt-get install -y $tool)" >&2
        exit 69
    }
done

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR"

# No -Q out: loopback copies do not carry the PACKET_OUTGOING type libpcap's direction filter
# expects, so -Q out on lo captures nothing (verified: 20 received by filter, 0 captured). Both
# tap copies of each datagram are recorded instead and the checker asserts they are byte-identical.
# -U flushes the pcap header and every packet immediately, which the readiness loop below relies
# on; -n -p plus the exact filter keep unrelated loopback traffic out. The filter expression is
# intentionally word-split.
FILTER="udp and src host 127.0.0.1 and dst host 127.0.0.1 and src port $SRC_PORT and dst portrange $CANARY_PORT-$PORT_HI"
# -Z root keeps the pcap root-owned: Ubuntu's tcpdump otherwise drops privileges and chowns the
# file to tcpdump:tcpdump, which the owner-based AppArmor tshark profile then refuses to read.
# --immediate-mode disables the kernel-side TPACKET block batching: without it, packets matching
# the filter can sit in a kernel block past our SIGINT and are silently lost (observed: 34
# received by filter, 6 written, 0 dropped). -U additionally flushes each packet to the file.
# shellcheck disable=SC2086
tcpdump -i lo -n -p -U --immediate-mode -Z root -w "$PCAP" $FILTER 2>"$RUN_DIR/tcpdump.log" &
TCPDUMP_PID=$!
trap 'kill "$TCPDUMP_PID" 2>/dev/null || true' EXIT

ready=0
for _ in $(seq 1 50); do
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        echo "error: tcpdump exited early" >&2
        cat "$RUN_DIR/tcpdump.log" >&2
        exit 1
    fi
    if [ "$(stat -c %s "$PCAP" 2>/dev/null || echo 0)" -ge 24 ]; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    echo "error: tcpdump did not become ready within 5s" >&2
    cat "$RUN_DIR/tcpdump.log" >&2
    exit 1
fi

# The pcap header alone does not prove the capture path is live (under load the probe outran the
# filter attach and the file stayed at 24 bytes). Send canary datagrams -- same source port, the
# warm-up dst port -- until one is visibly recorded; only then is the capture provably end-to-end.
ready=0
for _ in $(seq 1 50); do
    python3 -c "import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $SRC_PORT))
s.sendto(b'canary', ('127.0.0.1', $CANARY_PORT))"
    sleep 0.1
    if [ "$(stat -c %s "$PCAP" 2>/dev/null || echo 0)" -gt 24 ]; then
        ready=1
        break
    fi
done
if [ "$ready" -ne 1 ]; then
    echo "error: capture never recorded the warm-up canary within 5s" >&2
    cat "$RUN_DIR/tcpdump.log" >&2
    exit 1
fi

"$PROBE"

# Stop only once the dump file has stopped growing (three quiet 0.2s polls), so late packets are
# on disk before the SIGINT; bounded at 10s.
last_size=-1
quiet=0
for _ in $(seq 1 50); do
    sleep 0.2
    size="$(stat -c %s "$PCAP" 2>/dev/null || echo 0)"
    if [ "$size" -eq "$last_size" ]; then
        quiet=$((quiet + 1))
        [ "$quiet" -ge 3 ] && break
    else
        quiet=0
        last_size="$size"
    fi
done
kill -INT "$TCPDUMP_PID"
wait "$TCPDUMP_PID" || true
trap - EXIT
grep -Eq '^0 packets dropped by kernel' "$RUN_DIR/tcpdump.log" || {
    echo "error: tcpdump reported kernel drops" >&2
    cat "$RUN_DIR/tcpdump.log" >&2
    exit 1
}

# tshark reads the capture offline (no capture privilege involved). The CSV is the hard L3/L4
# cross-check consumed by wire-check.py; the verbose and expert views are informational artifacts
# only (tshark 4.6 carries no RFC 9868 UDP-options dissector; see the step file).
tshark -r "$PCAP" -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE -T fields -E separator=, \
    -e ip.hdr_len -e ip.len -e ip.checksum.status \
    -e udp.srcport -e udp.dstport -e udp.length -e udp.checksum -e udp.checksum.status \
    >"$RUN_DIR/tshark.csv" 2>"$RUN_DIR/tshark.log"
tshark -r "$PCAP" -o udp.check_checksum:TRUE -V >"$RUN_DIR/tshark-verbose.txt" 2>&1 || true
tshark -r "$PCAP" -q -z expert >"$RUN_DIR/tshark-expert.txt" 2>&1 || true

python3 "$SCRIPT_DIR/wire-check.py" "$PCAP" "$RUN_DIR/tshark.csv"
