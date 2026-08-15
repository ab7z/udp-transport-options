#!/usr/bin/env bash
# Remote command fragments are intentionally expanded and quoted on the client.
# shellcheck disable=SC2029
# P0 campaign driver for the real path 1blu <-> mcs (FF1 test plan).
#
#   scripts/p0-campaign.sh <scenario>
#
# Scenarios: s35 (MTU sweep), s31 (twin sandwich series), sopt (single-option positives S-02/S-03/
# S-12/S-15/S-16/S-17-announce), sfrag (FRAG positives S-17/S-18/S-46), s30 (option mix rotation),
# s40 (long interleaved series), s47 (datagram duplicates), s48 (emulated reordering), s53 (legacy
# SOCK_DGRAM receiver), s14 (REQ/RES echo two-step with reflector check), s36 (three-port
# parallel flows sharing one FRAG Identification).
#
# Runs from the workstation and orchestrates both hosts over ssh: sender-side and receiver-side
# tcpdump with a canary warm-up on an allowed port (cloud firewalls drop unknown ports before the
# NIC, so the canary must use one), blocking receivers (--timeout-ms 0) stopped by pidfile, and a
# per-attempt send log so sender errors stay separable from path loss. Artifacts land under
# target/p0-campaign-<stamp>/<scenario>/ and are evaluated by p0-eval.py. Hosts, ports and
# interfaces are the fixed uoe-s00 deployment from S-00.
set -euo pipefail

SCENARIO="${1:?usage: p0-campaign.sh <scenario>}"
STAMP="${P0_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
cd "$(dirname "$0")/.."
RUN_ROOT="target/p0-campaign-$STAMP/$SCENARIO"
mkdir -p "$RUN_ROOT"

# Role A defaults to mcs, role B to 1blu; override from the environment to measure another host
# pair without editing the driver. A_NAME/B_NAME only label directions and artifact directories.
MCS_SSH=${MCS_SSH:-ab@46.225.188.39}
MCS_IP=${MCS_IP:-46.225.188.39}
MCS_IF=${MCS_IF:-eth0}
MCS_DIR=${MCS_DIR:-/home/ab/uoe-s00}
MCS_SUDO=${MCS_SUDO:-sudo}
BLU_SSH=${BLU_SSH:-root@178.254.35.195}
BLU_IP=${BLU_IP:-178.254.35.195}
BLU_IF=${BLU_IF:-venet0}
BLU_DIR=${BLU_DIR:-/root/uoe-s00}
BLU_SUDO=${BLU_SUDO-}
A_NAME=${A_NAME:-mcs}
B_NAME=${B_NAME:-1blu}

DST_PORT=47101
SRC_PORT=47102
CANARY_PORT=47103

# EXPECTED=0 means "stop on a line count stable across three 5s polls" (used when the delivered
# or raw-datagram count is itself the measurement or depends on the fragment split).
RECV_EXTRA=
case "$SCENARIO" in
    s35) EXPECTED=0 ;;
    s31) EXPECTED=1500 ;;
    sopt) EXPECTED=72 ;;
    sfrag)
        EXPECTED=0
        RECV_EXTRA="--max-reassembled-size 6008 --max-segments 4 --reassembly-timeout-ms 5000"
        ;;
    s30) EXPECTED=120 ;;
    s40) EXPECTED=1000 ;;
    s47) EXPECTED=60 ;;
    s48) EXPECTED=0 ;;
    s53) EXPECTED=2000 ;;
    s14 | s36) EXPECTED=0 ;;
    *) echo "unknown scenario: $SCENARIO" >&2; exit 64 ;;
esac

# --- shared helpers ----------------------------------------------------------------------------

# start_capture <ssh> <sudo> <iface> <rundir> <pcap-name> <filter>
start_capture() {
    ssh "$1" "$2 bash -c 'cd $4 || exit 1; nohup tcpdump -i $3 -n -p -U --immediate-mode -w $5 \"$6\" >/dev/null 2>tcpdump-$5.log & echo \$! >tcpdump-$5.pid'"
}

# stop_capture <ssh> <sudo> <rundir> <pcap-name>; verifies zero kernel drops
stop_capture() {
    ssh "$1" "$2 bash -c 'kill -INT \$(cat $3/tcpdump-$4.pid) 2>/dev/null; sleep 1'; true"
    ssh "$1" "grep -q '^0 packets dropped by kernel' $3/tcpdump-$4.log" ||
        { echo "error: kernel drops in capture $4" >&2; exit 1; }
}

# canary_until_ready <sender-ssh> <receiver-ip> <check-ssh:file>... polls the given remote files
canary_until_ready() {
    local s_ssh="$1" r_ip="$2" ready=0 spec size
    shift 2
    for _ in $(seq 1 20); do
        ssh "$s_ssh" "bash -c 'echo -n canary >/dev/udp/$r_ip/$CANARY_PORT'"
        sleep 0.4
        ready=1
        for spec in "$@"; do
            size=$(ssh "${spec%%:*}" "stat -c %s ${spec#*:} 2>/dev/null || echo 0")
            [ "$size" -gt 24 ] || ready=0
        done
        [ "$ready" -eq 1 ] && break
    done
    [ "$ready" -eq 1 ] || { echo "error: captures never recorded the canary" >&2; exit 1; }
}

# poll_lines <ssh> <path-glob> <expected>; EXPECTED=0 falls back to the stability rule
poll_lines() {
    local r_ssh="$1" glob="$2" expected="$3" lines=0 last=-1 stable=0
    for _ in $(seq 1 120); do
        lines=$(ssh "$r_ssh" "cat $glob 2>/dev/null | wc -l")
        if [ "$expected" -gt 0 ] && [ "$lines" -ge "$expected" ]; then break; fi
        if [ "$lines" -eq "$last" ]; then
            stable=$((stable + 1))
            [ "$stable" -ge 3 ] && break
        else
            stable=0
            last="$lines"
        fi
        sleep 5
    done
    echo "   recv lines: $lines (expected: $expected)"
}

snapshot_meta() { # <out> <sender-ssh> <sender-if> <sender-dir> <receiver-ssh> <receiver-if> <receiver-dir>
    ssh "$2" "hostname; uname -r; ip -o link show $3; sha256sum $4/udpopt-send" >"$1/meta-sender.txt"
    ssh "$5" "hostname; uname -r; ip -o link show $6; sha256sum $7/udpopt-recv" >"$1/meta-receiver.txt"
}

# --- per-scenario send sequences ---------------------------------------------------------------

# Emits the per-direction send sequence. Every attempt is logged with its exit code so the
# evaluator can separate sender errors from path loss. seq ranges encode the class per scenario
# (mirrored in p0-eval.py). --no-frag everywhere except the FRAG scenarios.
make_sender_script() { # $1 src_ip, $2 dst_ip
    cat <<EOF
#!/usr/bin/env bash
set -u
cd "\$(dirname "\$0")"
send() {
    local cls="\$1" seq="\$2" pay="\$3" extra="\$4" rc=0
    ../udpopt-send --src $1 --dst $2 --src-port $SRC_PORT --dst-port $DST_PORT \\
        --count 1 --manifest manifest.jsonl --seq-start "\$seq" --payload-size "\$pay" \\
        \$extra >>send.log 2>&1 || rc=\$?
    echo "attempt class=\$cls seq=\$seq payload=\$pay rc=\$rc" >>send.log
    sleep 0.02
}
EOF
    case "$SCENARIO" in
    s35) cat <<'EOF'
# 16 IPv4 total lengths 1460..1520 step 4; per length 3 baseline + 3 APC twins of equal total.
# --max-datagram-len 1600 lifts the CLI ceiling so sizes above 1500 reach the kernel.
for idx in $(seq 0 15); do
    L=$((1460 + 4 * idx))
    for k in 0 1 2; do
        send b $((idx * 10 + k)) $((L - 28)) "--no-frag --max-datagram-len 1600"
        send t $((1000 + idx * 10 + k)) $((L - 38)) "--apc --no-frag --max-datagram-len 1600"
    done
done
EOF
        ;;
    s31) cat <<'EOF'
# 500 sandwich triples on one 5-tuple: baseline, APC twin of equal IPv4 total (102), baseline.
for i in $(seq 0 499); do
    send b $((3 * i)) 74 "--no-frag"
    send t $((3 * i + 1)) 64 "--apc --no-frag"
    send b $((3 * i + 2)) 74 "--no-frag"
done
EOF
        ;;
    sopt) cat <<'EOF'
# Single-option positives, 6 packets per class; seq base encodes the class:
#  100 S-02 even start, minimal REQ deadbeef  | 200 S-03 odd start (pad), REQ c0ffee01
#  300/320/340/360/380 S-12 APC payload 0/1/9/64/1462 (0 and 1 carry no seq: count-only)
#  400 S-15 unsolicited RES cafebabe          | 500 S-16a MDS 1200 announce
#  600 S-16b plain 1400-byte send after the MDS announce (sender must not be limited)
#  700 S-17 MRDS 6000/4 announce             | 900 baseline
for k in 0 1 2 3 4 5; do
    send t $((100 + k)) 64 "--req deadbeef --no-frag"
    send t $((200 + k)) 17 "--req c0ffee01 --no-frag"
    send t $((300 + k)) 0 "--apc --no-frag"
    send t $((320 + k)) 1 "--apc --no-frag"
    send t $((340 + k)) 9 "--apc --no-frag"
    send t $((360 + k)) 64 "--apc --no-frag"
    send t $((380 + k)) 1462 "--apc --no-frag"
    send t $((400 + k)) 64 "--res cafebabe --no-frag"
    send t $((500 + k)) 64 "--mds 1200 --no-frag"
    send t $((600 + k)) 1372 "--no-frag"
    send t $((700 + k)) 64 "--mrds-size 6000 --mrds-segments 4 --no-frag"
    send b $((900 + k)) 74 "--no-frag"
done
EOF
        ;;
    sfrag) cat <<'EOF'
# FRAG positives; receiver runs with --max-reassembled-size 6008 --max-segments 4 and a 5s
# reassembly timeout. Classes by seq base:
#  100 S-17a 2900 bytes, sender default peer limits 2926/2 -> 2 fragments
#  200 S-17b 3100 bytes, default limits -> sender MUST refuse (rc != 0 expected)
#  300 S-17c 5000 bytes with announced peer limits 6008/4 -> up to 4 fragments
#  400 S-18 2000 bytes, distinct Identifications -> 2 fragments each
#  500/520 S-46 Identification reuse across the receiver's 5s reassembly window (7s gap)
for k in 0 1 2 3 4 5; do
    send t $((100 + k)) 2900 ""
    send t $((200 + k)) 3100 ""
    send t $((300 + k)) 5000 "--peer-mrds-size 6008 --peer-mrds-segments 4"
done
for j in 0 1 2 3 4 5 6 7 8 9; do
    send t $((400 + j)) 2000 "--identification $((41377 + j))"
done
for i in 0 1 2 3 4 5; do
    send t $((500 + i)) 1000 "--max-datagram-len 600 --identification 49374"
    sleep 7
    send t $((520 + i)) 1000 "--max-datagram-len 600 --identification 49374"
done
for k in 0 1 2 3 4 5; do
    send b $((900 + k)) 1462 "--no-frag"
done
EOF
        ;;
    s30) cat <<'EOF'
# Option mix on one 5-tuple (statelessness): run 1 seq 0..59 with class = seq % 6, run 2
# seq 100..159 with the rotation shifted by 3. Class 0/5 baseline, 1 APC, 2 APC+REQ,
# 3 MDS+MRDS, 4 RES.
profile() {
    case "$1" in
    0 | 5) echo "b 74 --no-frag" ;;
    1) echo "t 64 --apc --no-frag" ;;
    2) echo "t 64 --apc --req deadbeef --no-frag" ;;
    3) echo "t 64 --mds 1200 --mrds-size 2926 --mrds-segments 2 --no-frag" ;;
    4) echo "t 64 --res feedface --no-frag" ;;
    esac
}
for i in $(seq 0 59); do
    read -r cls pay extra <<<"$(profile $((i % 6)))"
    send "$cls" "$i" "$pay" "$extra"
done
for i in $(seq 0 59); do
    read -r cls pay extra <<<"$(profile $(((i + 3) % 6)))"
    send "$cls" $((100 + i)) "$pay" "$extra"
done
EOF
        ;;
    s40) cat <<'EOF'
# Long interleaved series: 500 baseline/APC pairs of equal IPv4 total (102) on one 5-tuple.
for i in $(seq 0 499); do
    send b $((2 * i)) 74 "--no-frag"
    send t $((2 * i + 1)) 64 "--apc --no-frag"
done
EOF
        ;;
    s47) cat <<'EOF'
# Datagram duplicates: 20 APC packets each sent twice with the same seq (expected: both copies
# delivered, no silent dedup), plus 20 baselines.
for i in $(seq 0 19); do
    send t "$i" 64 "--apc --no-frag"
    send t "$i" 64 "--apc --no-frag"
done
for i in $(seq 100 119); do
    send b "$i" 74 "--no-frag"
done
EOF
        ;;
    s48) cat <<'EOF'
# Emulated reordering: 30 APC packets sent in a fixed shuffled seq order (the evaluator compares
# delivered inversions against this order), then two MRDS announcements in swapped order followed
# by fragmented traffic (receiver reports each announcement statelessly per packet).
for s in 17 3 24 9 0 28 12 21 6 15 1 26 10 19 4 23 8 29 13 2 27 11 20 5 16 7 25 14 22 18; do
    send t "$s" 64 "--apc --no-frag"
done
send t 100 64 "--mrds-size 6000 --mrds-segments 4 --no-frag"
send t 101 64 "--mrds-size 2926 --mrds-segments 2 --no-frag"
for k in 0 1 2; do
    send t $((110 + k)) 2900 "--identification $((51966 + k))"
done
EOF
        ;;
    s53) cat <<'EOF'
# Legacy receiver (plain SOCK_DGRAM, no RFC 9868 support): 1000 baseline/APC pairs of equal
# IPv4 total 102; the legacy receiver must deliver both classes identically and can never see
# the surplus area.
for i in $(seq 0 999); do
    send b $((2 * i)) 74 "--no-frag"
    send t $((2 * i + 1)) 64 "--apc --no-frag"
done
EOF
        ;;
    esac
}

# Three concurrent flows, one per allowed port, deliberately sharing FRAG Identification 0xAAAA:
# the reassembly key is the 4-tuple plus Identification, so flows on different ports must never
# cross-contaminate. seq ranges encode the port (see p0-eval.py).
make_s36_sender_script() { # $1 src_ip, $2 dst_ip
    cat <<EOF
#!/usr/bin/env bash
set -u
cd "\$(dirname "\$0")"
send36() {
    local cls="\$1" seq="\$2" pay="\$3" port="\$4" extra="\$5" rc=0
    ../udpopt-send --src $1 --dst $2 --src-port $SRC_PORT --dst-port "\$port" \\
        --count 1 --manifest "manifest-\$port.jsonl" --seq-start "\$seq" --payload-size "\$pay" \\
        \$extra >>"send-\$port.log" 2>&1 || rc=\$?
    echo "attempt class=\$cls seq=\$seq payload=\$pay port=\$port rc=\$rc" >>send.log
    sleep 0.02
}
flow() {
    local port="\$1" fragbase="\$2" basebase="\$3" j
    for j in 0 1 2 3 4 5 6 7 8 9; do
        send36 t \$((fragbase + j)) 2000 "\$port" "--identification 43690"
        send36 b \$((basebase + j)) 74 "\$port" "--no-frag"
    done
}
flow 47101 0 300 &
flow 47102 100 400 &
flow 47103 200 500 &
wait
EOF
}

# --- generic two-direction scenario ------------------------------------------------------------

run_direction() {
    local name="$1" s_ssh="$2" s_ip="$3" s_if="$4" s_dir="$5" s_sudo="$6" \
        r_ssh="$7" r_ip="$8" r_if="$9" r_dir="${10}" r_sudo="${11}"
    local srun="$s_dir/run-$SCENARIO-$name" rrun="$r_dir/run-$SCENARIO-$name"
    local filter="udp and src host $s_ip and dst host $r_ip and ((src port $SRC_PORT and dst port $DST_PORT) or dst port $CANARY_PORT)"
    local out="$RUN_ROOT/$name"
    mkdir -p "$out"
    echo "== $SCENARIO $name: $s_ip -> $r_ip =="

    ssh "$r_ssh" "$r_sudo rm -rf $rrun && mkdir -p $rrun"
    ssh "$s_ssh" "$s_sudo rm -rf $srun && mkdir -p $srun"

    start_capture "$r_ssh" "$r_sudo" "$r_if" "$rrun" ingress.pcap "$filter"
    start_capture "$s_ssh" "$s_sudo" "$s_if" "$srun" egress.pcap "$filter"
    canary_until_ready "$s_ssh" "$r_ip" "$r_ssh:$rrun/ingress.pcap" "$s_ssh:$srun/egress.pcap"

    local rcount="$EXPECTED"
    [ "$rcount" -eq 0 ] && rcount=100000
    if [ "$SCENARIO" = s53 ]; then
        scp -q scripts/p0-legacy-recv.py "$r_ssh:$rrun/p0-legacy-recv.py"
        ssh "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup python3 p0-legacy-recv.py $DST_PORT $SRC_PORT >recv.jsonl 2>recv.log & echo \$! >recv.pid'"
    else
        ssh "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup ../udpopt-recv --dst-port $DST_PORT --src-port $SRC_PORT --own-src $r_ip --timeout-ms 0 --count $rcount $RECV_EXTRA --json >recv.jsonl 2>recv.log & echo \$! >recv.pid'"
    fi

    make_sender_script "$s_ip" "$r_ip" >"$out/sender.sh"
    scp -q "$out/sender.sh" "$s_ssh:$srun/sender.sh"
    ssh "$s_ssh" "$s_sudo bash $srun/sender.sh"

    poll_lines "$r_ssh" "$rrun/recv.jsonl" "$EXPECTED"

    ssh "$r_ssh" "$r_sudo bash -c 'kill \$(cat $rrun/recv.pid) 2>/dev/null; sleep 1'; true"
    stop_capture "$r_ssh" "$r_sudo" "$rrun" ingress.pcap
    stop_capture "$s_ssh" "$s_sudo" "$srun" egress.pcap
    snapshot_meta "$out" "$s_ssh" "$s_if" "$s_dir" "$r_ssh" "$r_if" "$r_dir"

    ssh "$r_ssh" "$r_sudo chmod -R a+rX $rrun"
    ssh "$s_ssh" "$s_sudo chmod -R a+rX $srun"
    scp -q "$r_ssh:$rrun/recv.jsonl" "$r_ssh:$rrun/recv.log" "$r_ssh:$rrun/ingress.pcap" "$out/"
    scp -q "$r_ssh:$rrun/tcpdump-ingress.pcap.log" "$out/tcpdump-ingress.log"
    scp -q "$s_ssh:$srun/manifest.jsonl" "$s_ssh:$srun/send.log" "$s_ssh:$srun/egress.pcap" "$out/"
    scp -q "$s_ssh:$srun/tcpdump-egress.pcap.log" "$out/tcpdump-egress.log"
    ssh "$r_ssh" "$r_sudo rm -rf $rrun"
    ssh "$s_ssh" "$s_sudo rm -rf $srun"

    python3 scripts/p0-eval.py "$SCENARIO" "$name" "$out" | tee -a "$RUN_ROOT/results.md"
}

# --- s36: three parallel port flows ------------------------------------------------------------

run_s36() {
    local name="$1" s_ssh="$2" s_ip="$3" s_if="$4" s_dir="$5" s_sudo="$6" \
        r_ssh="$7" r_ip="$8" r_if="$9" r_dir="${10}" r_sudo="${11}"
    local srun="$s_dir/run-$SCENARIO-$name" rrun="$r_dir/run-$SCENARIO-$name"
    local filter="udp and src host $s_ip and dst host $r_ip and ((src port $SRC_PORT and dst portrange 47101-47103) or dst port $CANARY_PORT)"
    local out="$RUN_ROOT/$name" port
    mkdir -p "$out"
    echo "== $SCENARIO $name: $s_ip -> $r_ip =="

    ssh "$r_ssh" "$r_sudo rm -rf $rrun && mkdir -p $rrun"
    ssh "$s_ssh" "$s_sudo rm -rf $srun && mkdir -p $srun"
    start_capture "$r_ssh" "$r_sudo" "$r_if" "$rrun" ingress.pcap "$filter"
    start_capture "$s_ssh" "$s_sudo" "$s_if" "$srun" egress.pcap "$filter"
    canary_until_ready "$s_ssh" "$r_ip" "$r_ssh:$rrun/ingress.pcap" "$s_ssh:$srun/egress.pcap"

    for port in 47101 47102 47103; do
        ssh "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup ../udpopt-recv --dst-port $port --src-port $SRC_PORT --own-src $r_ip --timeout-ms 0 --count 30 --json >recv-$port.jsonl 2>recv-$port.log & echo \$! >recv-$port.pid'"
    done

    make_s36_sender_script "$s_ip" "$r_ip" >"$out/sender.sh"
    scp -q "$out/sender.sh" "$s_ssh:$srun/sender.sh"
    ssh "$s_ssh" "$s_sudo bash $srun/sender.sh"

    poll_lines "$r_ssh" "$rrun/recv-*.jsonl" 90

    for port in 47101 47102 47103; do
        ssh "$r_ssh" "$r_sudo bash -c 'kill \$(cat $rrun/recv-$port.pid) 2>/dev/null'; true"
    done
    sleep 1
    stop_capture "$r_ssh" "$r_sudo" "$rrun" ingress.pcap
    stop_capture "$s_ssh" "$s_sudo" "$srun" egress.pcap
    snapshot_meta "$out" "$s_ssh" "$s_if" "$s_dir" "$r_ssh" "$r_if" "$r_dir"

    ssh "$r_ssh" "$r_sudo chmod -R a+rX $rrun"
    ssh "$s_ssh" "$s_sudo chmod -R a+rX $srun"
    scp -q "$r_ssh:$rrun/recv-47101.jsonl" "$r_ssh:$rrun/recv-47102.jsonl" "$r_ssh:$rrun/recv-47103.jsonl" "$r_ssh:$rrun/ingress.pcap" "$out/"
    scp -q "$r_ssh:$rrun/tcpdump-ingress.pcap.log" "$out/tcpdump-ingress.log"
    scp -q "$s_ssh:$srun/send.log" "$s_ssh:$srun/egress.pcap" "$out/"
    scp -q "$s_ssh:$srun/manifest-47101.jsonl" "$s_ssh:$srun/manifest-47102.jsonl" "$s_ssh:$srun/manifest-47103.jsonl" "$out/"
    scp -q "$s_ssh:$srun/tcpdump-egress.pcap.log" "$out/tcpdump-egress.log"
    ssh "$r_ssh" "$r_sudo rm -rf $rrun"
    ssh "$s_ssh" "$s_sudo rm -rf $srun"

    python3 scripts/p0-eval.py "$SCENARIO" "$name" "$out" | tee -a "$RUN_ROOT/results.md"
}

# --- s14: REQ/RES echo two-step ----------------------------------------------------------------

# Phase 1: 6 REQ datagrams; the receiver side must produce NO automatic answer (reflector check
# on its egress). Phase 2: the receiver-side application reads the received token from the JSONL
# and answers with 6 RES datagrams carrying exactly that token.
run_s14() {
    local name="$1" s_ssh="$2" s_ip="$3" s_if="$4" s_dir="$5" s_sudo="$6" \
        r_ssh="$7" r_ip="$8" r_if="$9" r_dir="${10}" r_sudo="${11}"
    local srun="$s_dir/run-$SCENARIO-$name" rrun="$r_dir/run-$SCENARIO-$name"
    local fwd="udp and src host $s_ip and dst host $r_ip and ((src port $SRC_PORT and dst port $DST_PORT) or dst port $CANARY_PORT)"
    local rev="udp and src host $r_ip and dst host $s_ip and ((src port $SRC_PORT and dst port $DST_PORT) or dst port $CANARY_PORT)"
    local reflector="udp and src host $r_ip and dst host $s_ip"
    local out="$RUN_ROOT/$name" tok
    mkdir -p "$out"
    echo "== $SCENARIO $name: REQ $s_ip -> $r_ip, RES zurueck =="

    ssh "$r_ssh" "$r_sudo rm -rf $rrun && mkdir -p $rrun"
    ssh "$s_ssh" "$s_sudo rm -rf $srun && mkdir -p $srun"

    # Phase 1: REQ leg plus reflector capture on the REQ receiver's egress.
    start_capture "$r_ssh" "$r_sudo" "$r_if" "$rrun" p1-ingress.pcap "$fwd"
    start_capture "$r_ssh" "$r_sudo" "$r_if" "$rrun" p1-reflector.pcap "$reflector"
    start_capture "$s_ssh" "$s_sudo" "$s_if" "$srun" p1-egress.pcap "$fwd"
    canary_until_ready "$s_ssh" "$r_ip" "$r_ssh:$rrun/p1-ingress.pcap" "$s_ssh:$srun/p1-egress.pcap"
    ssh "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup ../udpopt-recv --dst-port $DST_PORT --src-port $SRC_PORT --own-src $r_ip --timeout-ms 0 --count 6 --json >p1-recv.jsonl 2>p1-recv.log & echo \$! >p1-recv.pid'"
    ssh "$s_ssh" "$s_sudo bash -c 'cd $srun || exit 1; for k in 0 1 2 3 4 5; do ../udpopt-send --src $s_ip --dst $r_ip --src-port $SRC_PORT --dst-port $DST_PORT --count 1 --manifest p1-manifest.jsonl --seq-start \$k --payload-size 64 --req deadbeef --no-frag >>p1-send.log 2>&1; echo \"attempt class=t seq=\$k payload=64 rc=\$?\" >>p1-send.log; sleep 0.1; done'"
    poll_lines "$r_ssh" "$rrun/p1-recv.jsonl" 6
    sleep 3 # reflector window: any automatic answer would have to appear here
    ssh "$r_ssh" "$r_sudo bash -c 'kill \$(cat $rrun/p1-recv.pid) 2>/dev/null'; true"
    stop_capture "$r_ssh" "$r_sudo" "$rrun" p1-ingress.pcap
    stop_capture "$r_ssh" "$r_sudo" "$rrun" p1-reflector.pcap
    stop_capture "$s_ssh" "$s_sudo" "$srun" p1-egress.pcap
    ssh "$r_ssh" "$r_sudo chmod -R a+rX $rrun"
    ssh "$r_ssh" "tcpdump -nr $rrun/p1-reflector.pcap 2>/dev/null | wc -l" >"$out/p1-reflector-count.txt"

    # The application step: read the received token out of the REQ receiver's JSONL.
    tok=$(ssh "$r_ssh" "python3 -c \"
import json, re, sys
for line in open('$rrun/p1-recv.jsonl'):
    m = re.search(r'REQ:([0-9a-f]{8})', json.loads(line).get('options', ''))
    if m:
        print(m.group(1))
        break
\"")
    [ -n "$tok" ] || { echo "error: no REQ token in phase-1 JSONL" >&2; exit 1; }
    echo "   REQ token received: $tok"

    # Phase 2: RES leg with swapped roles, token taken from phase 1.
    start_capture "$s_ssh" "$s_sudo" "$s_if" "$srun" p2-ingress.pcap "$rev"
    start_capture "$r_ssh" "$r_sudo" "$r_if" "$rrun" p2-egress.pcap "$rev"
    canary_until_ready "$r_ssh" "$s_ip" "$s_ssh:$srun/p2-ingress.pcap" "$r_ssh:$rrun/p2-egress.pcap"
    ssh "$s_ssh" "$s_sudo bash -c 'cd $srun || exit 1; nohup ../udpopt-recv --dst-port $DST_PORT --src-port $SRC_PORT --own-src $s_ip --timeout-ms 0 --count 6 --json >p2-recv.jsonl 2>p2-recv.log & echo \$! >p2-recv.pid'"
    ssh "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; for k in 100 101 102 103 104 105; do ../udpopt-send --src $r_ip --dst $s_ip --src-port $SRC_PORT --dst-port $DST_PORT --count 1 --manifest p2-manifest.jsonl --seq-start \$k --payload-size 64 --res $tok --no-frag >>p2-send.log 2>&1; echo \"attempt class=t seq=\$k payload=64 rc=\$?\" >>p2-send.log; sleep 0.1; done'"
    poll_lines "$s_ssh" "$srun/p2-recv.jsonl" 6
    ssh "$s_ssh" "$s_sudo bash -c 'kill \$(cat $srun/p2-recv.pid) 2>/dev/null'; true"
    stop_capture "$s_ssh" "$s_sudo" "$srun" p2-ingress.pcap
    stop_capture "$r_ssh" "$r_sudo" "$rrun" p2-egress.pcap
    snapshot_meta "$out" "$s_ssh" "$s_if" "$s_dir" "$r_ssh" "$r_if" "$r_dir"

    ssh "$r_ssh" "$r_sudo chmod -R a+rX $rrun"
    ssh "$s_ssh" "$s_sudo chmod -R a+rX $srun"
    scp -q "$r_ssh:$rrun/p1-recv.jsonl" "$r_ssh:$rrun/p1-ingress.pcap" "$r_ssh:$rrun/p1-reflector.pcap" "$out/"
    scp -q "$r_ssh:$rrun/p2-send.log" "$r_ssh:$rrun/p2-egress.pcap" "$out/"
    scp -q "$s_ssh:$srun/p1-send.log" "$s_ssh:$srun/p1-egress.pcap" "$out/"
    scp -q "$s_ssh:$srun/p2-recv.jsonl" "$s_ssh:$srun/p2-ingress.pcap" "$out/"
    echo "$tok" >"$out/token.txt"
    ssh "$r_ssh" "$r_sudo rm -rf $rrun"
    ssh "$s_ssh" "$s_sudo rm -rf $srun"

    python3 scripts/p0-eval.py "$SCENARIO" "$name" "$out" | tee -a "$RUN_ROOT/results.md"
}

# --- dispatch ----------------------------------------------------------------------------------

: >"$RUN_ROOT/results.md"
case "$SCENARIO" in
s36)
    run_s36 "a-$A_NAME-to-$B_NAME" "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO" \
        "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO"
    run_s36 "b-$B_NAME-to-$A_NAME" "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO" \
        "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO"
    ;;
s14)
    run_s14 "a-req-$B_NAME-to-$A_NAME" "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO" \
        "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO"
    run_s14 "b-req-$A_NAME-to-$B_NAME" "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO" \
        "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO"
    ;;
*)
    run_direction "a-$A_NAME-to-$B_NAME" "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO" \
        "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO"
    run_direction "b-$B_NAME-to-$A_NAME" "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO" \
        "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO"
    ;;
esac
echo "done: $RUN_ROOT"
