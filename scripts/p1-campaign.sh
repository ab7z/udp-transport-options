#!/usr/bin/env bash
# Remote command fragments are intentionally expanded and quoted on the client.
# shellcheck disable=SC2029
# P1 campaign driver for the real path 1blu <-> mcs: the negative and disturbance scenarios of the
# FF1 test plan.
#
#   scripts/p1-campaign.sh <scenario>
#
# Scenarios: p1opt (single-datagram option negatives S-04/S-05/S-06/S-08/S-10/S-11/S-13/S-20/S-21),
# p1frag (fragment disturbance S-41/S-42/S-43/S-44), p1coll (Identification collisions S-32/S-33/
# S-52), p1s49 (partial loss across a long fragment series, S-49).
#
# Path constraint measured on 2026-08-15: this path enforces a legacy UDP checksum over the ENTIRE
# IP payload, with the pseudo-header length taken from the IP total length instead of the UDP Length
# field. A datagram only arrives when its UDP checksum field is zero or that sum comes out valid.
# Faults that break the surplus-area fold therefore never reach the receiver, so the option faults
# below either compensate the fold (--ocs-hex) or switch the check off (--udp-cksum-zero). Structural
# TLV faults need neither, because the sender still computes a correct OCS over the broken body.
#
# Everything else follows the P0 driver: captures at both ends with a canary warm-up on an allowed
# port, blocking receivers stopped by pidfile, and a per-attempt send log. Artifacts land under
# target/p1-campaign-<stamp>/<scenario>/ and are evaluated by p1-eval.py.
set -euo pipefail

SCENARIO="${1:?usage: p1-campaign.sh <scenario>}"
STAMP="${P1_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
cd "$(dirname "$0")/.."
RUN_ROOT="target/p1-campaign-$STAMP/$SCENARIO"
mkdir -p "$RUN_ROOT"

MCS_SSH=ab@46.225.188.39
MCS_IP=46.225.188.39
MCS_IF=eth0
MCS_DIR=/home/ab/uoe-s00
MCS_SUDO=sudo
BLU_SSH=root@178.254.35.195
BLU_IP=178.254.35.195
BLU_IF=venet0
BLU_DIR=/root/uoe-s00
BLU_SUDO=

DST_PORT=47101
SRC_PORT=47102
CANARY_PORT=47103

RECV_EXTRA=
case "$SCENARIO" in
    p1opt) EXPECTED=90 ;;
    p1frag | p1coll | p1s49)
        EXPECTED=0
        RECV_EXTRA="--max-reassembled-size 6008 --max-segments 4 --reassembly-timeout-ms 5000"
        ;;
    *) echo "unknown scenario: $SCENARIO" >&2; exit 64 ;;
esac

# --- shared helpers ----------------------------------------------------------------------------

# start_capture <ssh> <sudo> <iface> <rundir> <pcap-name> <filter>
start_capture() {
    ssh -n "$1" "$2 bash -c 'cd $4 || exit 1; nohup tcpdump -i $3 -n -p -U --immediate-mode -w $5 \"$6\" >/dev/null 2>tcpdump-$5.log & echo \$! >tcpdump-$5.pid'"
}

# stop_capture <ssh> <sudo> <rundir> <pcap-name>; verifies zero kernel drops
stop_capture() {
    ssh -n "$1" "$2 bash -c 'kill -INT \$(cat $3/tcpdump-$4.pid) 2>/dev/null; sleep 1'; true"
    ssh -n "$1" "grep -q '^0 packets dropped by kernel' $3/tcpdump-$4.log" ||
        { echo "error: kernel drops in capture $4" >&2; exit 1; }
}

# canary_until_ready <sender-ssh> <receiver-ip> <check-ssh:file>...
canary_until_ready() {
    local s_ssh="$1" r_ip="$2" ready=0 spec size
    shift 2
    for _ in $(seq 1 20); do
        ssh -n "$s_ssh" "bash -c 'echo -n canary >/dev/udp/$r_ip/$CANARY_PORT'"
        sleep 0.4
        ready=1
        for spec in "$@"; do
            size=$(ssh -n "${spec%%:*}" "stat -c %s ${spec#*:} 2>/dev/null || echo 0")
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
        lines=$(ssh -n "$r_ssh" "cat $glob 2>/dev/null | wc -l")
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
    ssh -n "$2" "hostname; uname -r; ip -o link show $3; sha256sum $4/udpopt-send" >"$1/meta-sender.txt"
    ssh -n "$5" "hostname; uname -r; ip -o link show $6; sha256sum $7/udpopt-recv" >"$1/meta-receiver.txt"
}

# --- per-scenario send sequences ----------------------------------------------------------------

# Every attempt is logged with its exit code so the evaluator can separate sender errors from path
# loss. The seq base encodes the class; p1-eval.py holds the matching expectation table.
make_sender_script() { # $1 src_ip, $2 dst_ip
    cat <<EOF
#!/usr/bin/env bash
set -u
cd "\$(dirname "\$0")"
SEND_SRC=$1
SEND_DST=$2
SEND_SPORT=$SRC_PORT
SEND_DPORT=$DST_PORT
send() {
    local cls="\$1" seq="\$2" pay="\$3" extra="\$4" rc=0
    ../udpopt-send --src $1 --dst $2 --src-port $SRC_PORT --dst-port $DST_PORT \\
        --count 1 --manifest manifest.jsonl --seq-start "\$seq" --payload-size "\$pay" \\
        \$extra >>send.log 2>&1 || rc=\$?
    echo "attempt class=\$cls seq=\$seq payload=\$pay rc=\$rc" >>send.log
    sleep 0.05
}
EOF
    case "$SCENARIO" in
    p1opt) cat <<'EOF'
# Single-datagram option negatives, 6 packets per class. The REQ token deadbeef is the marker that
# tells "options processed" from "options discarded". Compensated OCS values keep the datagram
# neutral against the path's legacy checksum; they are constant because the UDP checksum absorbs
# every payload change.
for k in 0 1 2 3 4 5; do
    # controls
    send a $((100 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef0000"
    send b $((150 + k)) 17 "--no-frag --raw-options-hex 0606deadbeef00"
    # S-04 non-zero pad; OCS compensated by the pad value so the path still forwards it
    send c $((200 + k)) 17 "--no-frag --raw-options-hex 0606deadbeef00 --pad-hex ff --ocs-hex 5b53"
    # S-05 invalid OCS; only reachable with the legacy check switched off
    send d $((250 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef0000 --ocs-hex dead --udp-cksum-zero"
    # S-06 matrix: zero OCS with a live UDP checksum (token compensates the fold), zero OCS with a
    # zero UDP checksum, and a valid OCS with a zero UDP checksum
    send e $((300 + k)) 64 "--no-frag --raw-options-hex 06063b00beef0000 --ocs-hex 0000"
    send f $((350 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef0000 --ocs-hex 0000 --udp-cksum-zero"
    send g $((400 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef0000 --udp-cksum-zero"
    # S-08 bytes after EOL
    send h $((450 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef00deadbeefaa"
    # S-10 unknown SAFE option (Kind 20) ahead of a valid REQ
    send i $((500 + k)) 64 "--no-frag --raw-options-hex 1404aabb0606deadbeef0000"
    # S-11a length underrun (Kind 6 with Length 1)
    send j $((550 + k)) 64 "--no-frag --raw-options-hex 0601deadbeef0000"
    # S-11b length overrun behind a valid REQ: the Section 10 / erratum 8834 test
    send k $((600 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef04c800000000"
    # S-13 APC with a wrong checksum
    send l $((650 + k)) 64 "--no-frag --raw-options-hex 0206deadbeef0000"
    # S-20 UNSAFE option (Kind 192) while UDP user data is present
    send m $((700 + k)) 64 "--no-frag --raw-options-hex c004aabb0000"
    # S-21 eight NOPs, one above the DoS threshold, ahead of a valid REQ
    send n $((750 + k)) 64 "--no-frag --raw-options-hex 01010101010101010606deadbeef0000"
    # plain baseline
    send o $((900 + k)) 74 "--no-frag"
done
EOF
        ;;
    p1frag) cat <<'EOF'
# Fragment disturbance through --frag-emit. Every logical send is 2000 bytes, which splits into two
# fragments under the default limits; the receiver runs with a 5s reassembly timeout.
for k in 0 1 2 3 4 5; do
    # control: both fragments, in order
    send a $((100 + k)) 2000 "--identification $((60000 + k))"
    # S-41 fragment loss: terminal fragment withheld
    send b $((200 + k)) 2000 "--identification $((60100 + k)) --frag-emit 0"
    # S-43 fragment duplicate: first fragment sent twice
    send c $((300 + k)) 2000 "--identification $((60200 + k)) --frag-emit 0,0,1"
    # S-44 fragment reordering: terminal fragment first
    send d $((400 + k)) 2000 "--identification $((60300 + k)) --frag-emit 1,0"
done
# S-42 reassembly timeout: first fragment, wait past the 5s window, then the rest. The control uses
# the same split with a 1s gap.
for k in 0 1 2 3 4 5; do
    send e $((500 + k)) 2000 "--identification $((60400 + k)) --frag-emit 0"
    sleep 8
    send e $((500 + k)) 2000 "--identification $((60400 + k)) --frag-emit 1"
done
for k in 0 1 2 3 4 5; do
    send f $((600 + k)) 2000 "--identification $((60500 + k)) --frag-emit 0"
    sleep 1
    send f $((600 + k)) 2000 "--identification $((60500 + k)) --frag-emit 1"
done
EOF
        ;;
    p1coll) cat <<'EOF'
# Identification collisions. Two logical datagrams A and B of equal size share one 4-tuple; their
# fragments are emitted one at a time so they interleave. The payload is derived from the sequence
# number, so repeating a send with the same --seq-start reproduces the same fragment bytes exactly.
#
# S-32 distinct Identifications, interleaved: both sets must reassemble independently.
for k in 0 1 2 3 4 5; do
    send a $((100 + k)) 2000 "--identification $((61000 + k)) --frag-emit 0"
    send a $((150 + k)) 2000 "--identification $((61100 + k)) --frag-emit 0"
    send a $((100 + k)) 2000 "--identification $((61000 + k)) --frag-emit 1"
    send a $((150 + k)) 2000 "--identification $((61100 + k)) --frag-emit 1"
done
# S-33 shared Identification with overlapping offsets: A0 and B0 claim the same offset with
# different content, which must abort the set rather than deliver a mixture.
for k in 0 1 2 3 4 5; do
    send b $((200 + k)) 2000 "--identification $((61200 + k)) --frag-emit 0"
    send b $((250 + k)) 2000 "--identification $((61200 + k)) --frag-emit 0"
    send b $((200 + k)) 2000 "--identification $((61200 + k)) --frag-emit 1"
    send b $((250 + k)) 2000 "--identification $((61200 + k)) --frag-emit 1"
done
# S-52 shared Identification, complementary halves, no overlap: the first fragment of A plus the
# terminal fragment of B form a complete set of a datagram that was never sent. Whatever the
# receiver does here follows the RFC; a delivered mixture is a robustness finding, not a defect.
for k in 0 1 2 3 4 5; do
    send c $((300 + k)) 2000 "--identification $((61300 + k)) --frag-emit 0"
    send c $((350 + k)) 2000 "--identification $((61300 + k)) --frag-emit 1"
done
# S-52 with APC on both originals: the terminal fragment carries B's APC, which cannot match a
# mixed payload. This is the end-to-end check the RFC leaves optional.
for k in 0 1 2 3 4 5; do
    send d $((400 + k)) 2000 "--apc --identification $((61400 + k)) --frag-emit 0"
    send d $((450 + k)) 2000 "--apc --identification $((61400 + k)) --frag-emit 1"
done
# S-52 with payloads that differ in every byte. --payload-size derives the payload from the sequence
# number and only varies its first eight bytes, so the tails of A and B would be identical and a
# mixture would be invisible in the bytes. Filling A with 0xa1 and B with 0xb2 makes the boundary
# readable straight from the delivered payload.
PAY_A=$(printf 'a1%.0s' $(seq 1 2000))
PAY_B=$(printf 'b2%.0s' $(seq 1 2000))
send_hex() {
    local cls="$1" hex="$2" extra="$3" rc=0
    ../udpopt-send --src "$SEND_SRC" --dst "$SEND_DST" --src-port "$SEND_SPORT" --dst-port "$SEND_DPORT" \
        --count 1 --manifest manifest.jsonl --payload-hex "$hex" \
        $extra >>send.log 2>&1 || rc=$?
    echo "attempt class=$cls seq=0 payload=2000 rc=$rc" >>send.log
    sleep 0.05
}
for k in 0 1 2 3 4 5; do
    send_hex f "$PAY_A" "--identification $((61600 + k)) --frag-emit 0"
    send_hex f "$PAY_B" "--identification $((61600 + k)) --frag-emit 1"
done
# Control: complete, undisturbed sends on the same path.
for k in 0 1 2 3 4 5; do
    send e $((500 + k)) 2000 "--identification $((61500 + k))"
done
EOF
        ;;
    p1s49) cat <<'EOF'
# S-49 partial loss across a long fragment series: 300 logical datagrams of 2000 bytes each (two
# fragments under the default limits) in one uninterrupted series. Every tenth send withholds its
# terminal fragment, so the schedule is 270 complete sets (class a) and 30 incomplete ones (class b)
# under unique Identifications. The quota question: delivered must be exactly the 270 complete
# sends, byte-intact, the 30 withheld seqs must expire, and the rate must hold across the series
# while expired sets accumulate and age out underneath it.
for k in $(seq 0 299); do
    if [ $(((k + 1) % 10)) -eq 0 ]; then
        send b $((1000 + k)) 2000 "--identification $((62000 + k)) --frag-emit 0"
    else
        send a $((1000 + k)) 2000 "--identification $((62000 + k))"
    fi
done
EOF
        ;;
    esac
}

# --- generic two-direction scenario --------------------------------------------------------------

run_direction() {
    local name="$1" s_ssh="$2" s_ip="$3" s_if="$4" s_dir="$5" s_sudo="$6" \
        r_ssh="$7" r_ip="$8" r_if="$9" r_dir="${10}" r_sudo="${11}"
    local srun="$s_dir/run-$SCENARIO-$name" rrun="$r_dir/run-$SCENARIO-$name"
    local filter="udp and src host $s_ip and dst host $r_ip and ((src port $SRC_PORT and dst port $DST_PORT) or dst port $CANARY_PORT)"
    local out="$RUN_ROOT/$name"
    mkdir -p "$out"
    echo "== $SCENARIO $name: $s_ip -> $r_ip =="

    ssh -n "$r_ssh" "$r_sudo rm -rf $rrun && mkdir -p $rrun"
    ssh -n "$s_ssh" "$s_sudo rm -rf $srun && mkdir -p $srun"

    start_capture "$r_ssh" "$r_sudo" "$r_if" "$rrun" ingress.pcap "$filter"
    start_capture "$s_ssh" "$s_sudo" "$s_if" "$srun" egress.pcap "$filter"
    canary_until_ready "$s_ssh" "$r_ip" "$r_ssh:$rrun/ingress.pcap" "$s_ssh:$srun/egress.pcap"

    local rcount="$EXPECTED"
    [ "$rcount" -eq 0 ] && rcount=100000
    ssh -n "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup ../udpopt-recv --dst-port $DST_PORT --src-port $SRC_PORT --own-src $r_ip --timeout-ms 0 --count $rcount $RECV_EXTRA --json >recv.jsonl 2>recv.log & echo \$! >recv.pid'"

    make_sender_script "$s_ip" "$r_ip" >"$out/sender.sh"
    scp -q "$out/sender.sh" "$s_ssh:$srun/sender.sh"
    ssh -n "$s_ssh" "$s_sudo bash $srun/sender.sh"

    poll_lines "$r_ssh" "$rrun/recv.jsonl" "$EXPECTED"

    ssh -n "$r_ssh" "$r_sudo bash -c 'kill \$(cat $rrun/recv.pid) 2>/dev/null; sleep 1'; true"
    stop_capture "$r_ssh" "$r_sudo" "$rrun" ingress.pcap
    stop_capture "$s_ssh" "$s_sudo" "$srun" egress.pcap
    snapshot_meta "$out" "$s_ssh" "$s_if" "$s_dir" "$r_ssh" "$r_if" "$r_dir"

    ssh -n "$r_ssh" "$r_sudo chmod -R a+rX $rrun"
    ssh -n "$s_ssh" "$s_sudo chmod -R a+rX $srun"
    scp -q "$r_ssh:$rrun/recv.jsonl" "$r_ssh:$rrun/recv.log" "$r_ssh:$rrun/ingress.pcap" "$out/"
    scp -q "$r_ssh:$rrun/tcpdump-ingress.pcap.log" "$out/tcpdump-ingress.log"
    scp -q "$s_ssh:$srun/manifest.jsonl" "$s_ssh:$srun/send.log" "$s_ssh:$srun/egress.pcap" "$out/"
    scp -q "$s_ssh:$srun/tcpdump-egress.pcap.log" "$out/tcpdump-egress.log"
    ssh -n "$r_ssh" "$r_sudo rm -rf $rrun"
    ssh -n "$s_ssh" "$s_sudo rm -rf $srun"

    python3 scripts/p1-eval.py "$SCENARIO" "$name" "$out" | tee -a "$RUN_ROOT/results.md"
}

# --- dispatch ------------------------------------------------------------------------------------

: >"$RUN_ROOT/results.md"
run_direction a-mcs-to-1blu "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO" \
    "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO"
run_direction b-1blu-to-mcs "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO" \
    "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO"
echo "done: $RUN_ROOT"
