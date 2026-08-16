#!/usr/bin/env bash
# Remote command fragments are intentionally expanded and quoted on the client.
# shellcheck disable=SC2029
# P2 campaign driver for the real path 1blu <-> mcs, following the reviewed plan v2.
#
#   scripts/p2-campaign.sh <scenario>
#
# Scenarios: p2opt (single-datagram classes S-07/S-09/S-22/S-23), p2frag (fragment edge cases
# S-19/S-34/S-45 plus the conditional S-24r follow-up), p2s50 (reassembly-cache capacity S-50),
# p2netem (S-51; refuses to run until the E1 go decision is recorded, see p2-plan.md section 4).
#
# All expectations live in scripts/p2-cellplan.json; this driver only produces evidence. Every
# class computes a correct OCS over its (possibly broken) option body, so no U1/U2 checksum-gate
# workaround is needed anywhere (finding P1-A); p2-eval.py re-checks that per captured packet.
set -euo pipefail

SCENARIO="${1:?usage: p2-campaign.sh <scenario>}"
STAMP="${P2_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
cd "$(dirname "$0")/.."
RUN_ROOT="target/p2-campaign-$STAMP/$SCENARIO"
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
# NAT-split endpoints (e.g. EC2 1:1 NAT): *_IP stays the wire/public address (the peer's --dst
# and what the peer's capture sees); *_LOCAL_IP is the address on the local NIC (raw --src,
# --own-src, and the local capture view). The defaults keep symmetric public-IP hosts unchanged.
MCS_LOCAL_IP=${MCS_LOCAL_IP:-$MCS_IP}
BLU_LOCAL_IP=${BLU_LOCAL_IP:-$BLU_IP}
A_NAME=${A_NAME:-mcs}
B_NAME=${B_NAME:-1blu}

DST_PORT=47101
SRC_PORT=47102
CANARY_PORT=47103

RECV_EXTRA=
case "$SCENARIO" in
    p2opt) EXPECTED=84 ;;
    p2frag)
        EXPECTED=0
        RECV_EXTRA="--max-reassembled-size 6008 --max-segments 4 --reassembly-timeout-ms 5000"
        ;;
    p2s50)
        EXPECTED=0
        RECV_EXTRA="--max-reassembled-size 6008 --max-segments 4 --max-pending-partials 64 --reassembly-timeout-ms 60000"
        ;;
    p2netem)
        echo "S-51 wurde am 2026-08-15 begruendet gestrichen (Entscheidung E1 = No-Go)." >&2
        echo "Begruendung: p2-ergebnisse.md, Abschnitt 'S-51: begruendete Streichung'." >&2
        echo "Kein tc-Eingriff auf mcs; dieses Szenario ist absichtlich nicht implementiert." >&2
        exit 65
        ;;
    *) echo "unknown scenario: $SCENARIO" >&2; exit 64 ;;
esac

# --- shared helpers (P0/P1 pattern) --------------------------------------------------------------

start_capture() { # <ssh> <sudo> <iface> <rundir> <pcap-name> <filter>
    ssh -n "$1" "$2 bash -c 'cd $4 || exit 1; nohup tcpdump -i $3 -n -p -U --immediate-mode -w $5 \"$6\" >/dev/null 2>tcpdump-$5.log & echo \$! >tcpdump-$5.pid'"
}

stop_capture() { # <ssh> <sudo> <rundir> <pcap-name>; verifies zero kernel drops
    ssh -n "$1" "$2 bash -c 'kill -INT \$(cat $3/tcpdump-$4.pid) 2>/dev/null; sleep 1'; true"
    ssh -n "$1" "grep -q '^0 packets dropped by kernel' $3/tcpdump-$4.log" ||
        { echo "error: kernel drops in capture $4" >&2; exit 1; }
}

canary_until_ready() { # <sender-ssh> <receiver-ip> <check-ssh:file>...
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

poll_lines() { # <ssh> <path-glob> <expected>; EXPECTED=0 falls back to the stability rule
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
    git rev-parse HEAD >"$1/meta-runner-commit.txt"
}

# --- per-scenario send sequences -----------------------------------------------------------------

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
send_hex() {
    local cls="\$1" seq="\$2" hex="\$3" extra="\$4" rc=0
    ../udpopt-send --src $1 --dst $2 --src-port $SRC_PORT --dst-port $DST_PORT \\
        --count 1 --manifest manifest.jsonl --payload-hex "\$hex" \\
        \$extra >>send.log 2>&1 || rc=\$?
    echo "attempt class=\$cls seq=\$seq payload=\$((\${#hex} / 2)) rc=\$rc" >>send.log
    sleep 0.05
}
EOF
    case "$SCENARIO" in
    p2opt) cat <<'EOF'
# Single-datagram classes. REQ (must-support) always precedes optional SAFE options, so the
# receiver verdicts stay usable as an RFC oracle (rfc9868 :791-794). Bodies calibrated 2026-08-15.
Z() { printf '00%.0s' $(seq 1 "$1"); }
# S-09d needs one APC value per payload; values read from --apc hexdumps in the calibration run.
APC=(e4e96ae5 9dc01782 f7f21346 8edb6e21 05a0e988 7c8994ef)
for k in 0 1 2 3 4 5; do
    # S-07 EOL fill ladder
    send a $((2000 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef00"
    send b $((2010 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef00$(Z 8)"
    send c $((2020 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef00$(Z 64)"
    send d $((2030 + k)) 64 "--no-frag --raw-options-hex 00$(Z 32)"
    # S-09 NOP ladder, at and below the DoS threshold of 7
    send e $((2100 + k)) 64 "--no-frag --raw-options-hex 010606deadbeef"
    send f $((2110 + k)) 64 "--no-frag --raw-options-hex 0101010606deadbeef00"
    send g $((2120 + k)) 64 "--no-frag --raw-options-hex 010101010101010606deadbeef0000"
    send_hex h $((2130 + k)) "$(printf '%016x' $((2130 + k)))$(Z 56)" \
        "--no-frag --raw-options-hex 0606deadbeef01010206${APC[$k]}"
    # S-22 extended length: valid 300, sender-illegal 254, truncated header
    send i $((2200 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef14ff012c$(Z 296)"
    send j $((2210 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef14ff00fe$(Z 250)"
    send k $((2220 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef14ff01"
    # S-23 TIME: well-formed (TSval 1, TSecr 0) and sub-minimum length 6
    send l $((2300 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef080a0000000100000000"
    send m $((2310 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef080600000001"
    # control, P1 reference
    send o $((2890 + k)) 64 "--no-frag --raw-options-hex 0606deadbeef0000"
done
EOF
        ;;
    p2frag) cat <<'EOF'
Z() { printf '00%.0s' $(seq 1 "$1"); }
# S-19: atomic FRAG, one terminal fragment with reconstructed offset 8 and RDOS 72. Byte form
# fixed from the calibration hexdump: kind 03, len 0c, FragStart 22, Id, FragOffset 8, RDOS,
# then the 64-byte content (leading 8 bytes carry the seq).
for k in 0 1 2 3 4 5; do
    send_hex s19 $((2400 + k)) "" "--raw-options-hex 030c0016$(printf '%08x' $((63000 + k)))00080048$(printf '%016x' $((2400 + k)))$(Z 56)"
done
# S-34: pending set, ten undisturbed sends, then the terminal after 2 s.
for k in 0 1 2 3 4 5; do
    send s34f $((2500 + k)) 2000 "--identification $((63100 + k)) --frag-emit 0"
    for j in 0 1 2 3 4 5 6 7 8 9; do
        send s34c $((2510 + 10 * k + j)) 1200 "--no-frag"
    done
    sleep 2
    send s34t $((2500 + k)) 2000 "--identification $((63100 + k)) --frag-emit 1"
done
# S-45: overlap cells. The 1500 split covers [0,542)+[542,2000), the 1000 split (needs
# --peer-mrds-segments 3) covers [0,960)+[960,1042)+[1042,2000); B0 then the A terminal overlap
# in [542,960). Fill bytes identify the cell in delivered rows; FRAG ids identify it on the wire.
PAY_A0=$(printf 'a0%.0s' $(seq 1 2000))
PAY_A1=$(printf 'a1%.0s' $(seq 1 2000))
PAY_A3=$(printf 'a3%.0s' $(seq 1 2000))
PAY_B2=$(printf 'b2%.0s' $(seq 1 2000))
PAY_A4=$(printf 'a4%.0s' $(seq 1 2000))
for k in 0 1 2 3 4 5; do
    # Z0 exact duplicate: MAY latitude, expected delivered (P1 S-43 behaviour)
    send_hex z0 0 "$PAY_A0" "--identification $((63200 + k)) --max-datagram-len 1500 --frag-emit 0,0,1"
    # Z1 partial overlap, identical bytes: B0 first, then the A terminal
    send_hex z1b 0 "$PAY_A1" "--identification $((63220 + k)) --max-datagram-len 1000 --peer-mrds-segments 3 --frag-emit 0"
    send_hex z1a 0 "$PAY_A1" "--identification $((63220 + k)) --max-datagram-len 1500 --frag-emit 1"
    # Z2 partial overlap, differing bytes
    send_hex z2b 0 "$PAY_B2" "--identification $((63240 + k)) --max-datagram-len 1000 --peer-mrds-segments 3 --frag-emit 0"
    send_hex z2a 0 "$PAY_A3" "--identification $((63240 + k)) --max-datagram-len 1500 --frag-emit 1"
    # Z3 like Z1 with APC in both originals
    send_hex z3b 0 "$PAY_A4" "--identification $((63260 + k)) --max-datagram-len 1000 --peer-mrds-segments 3 --apc --frag-emit 0"
    send_hex z3a 0 "$PAY_A4" "--identification $((63260 + k)) --max-datagram-len 1500 --apc --frag-emit 1"
done
# S-24r (decision gate E3, taken: the S-19 hand-built technique holds): two raw fragments of one
# set where only the FIRST carries a per-fragment MDS option. Unequal per-fragment option sets are
# explicitly allowed (rfc9868 :1169); a reject on inequality would be an implementation finding.
# Fragment 1: OCS + MDS(1472) + FRAG(len 10, FragStart 24, offset 8) + 64 bytes (leading seq).
# Fragment 2: OCS + FRAG(len 12, FragStart 22, offset 72, RDOS 136) + 64 bytes fill.
for k in 0 1 2 3 4 5; do
    send_hex s24a $((2680 + k)) "" "--raw-options-hex 040405c0030a0018$(printf '%08x' $((63400 + k)))0008$(printf '%016x' $((2680 + k)))$(Z 56)"
    send_hex s24b $((2680 + k)) "" "--raw-options-hex 030c0016$(printf '%08x' $((63400 + k)))00480088$(printf 'bb%.0s' $(seq 1 64))"
done
EOF
        ;;
    esac
}

# S-50 phase scripts: run r, phases split so the driver can sample VmRSS between them.
make_s50_script() { # $1 src_ip, $2 dst_ip, $3 global run index r
    local r="$3"
    cat <<EOF
#!/usr/bin/env bash
set -u
cd "\$(dirname "\$0")"
R=$r
SEQ0=\$((5000 + 100 * R))
ID0=\$((64000 + 80 * R))
send() {
    local cls="\$1" seq="\$2" pay="\$3" extra="\$4" rc=0
    ../udpopt-send --src $1 --dst $2 --src-port $SRC_PORT --dst-port $DST_PORT \\
        --count 1 --manifest manifest.jsonl --seq-start "\$seq" --payload-size "\$pay" \\
        \$extra >>send.log 2>&1 || rc=\$?
    echo "attempt class=\$cls seq=\$seq payload=\$pay rc=\$rc" >>send.log
    sleep 0.01
}
case "\$1" in
firsts32)  for k in \$(seq 0 31);  do send s50f \$((SEQ0 + k)) 2000 "--identification \$((ID0 + k)) --frag-emit 0"; done ;;
firsts64)  for k in \$(seq 32 63); do send s50f \$((SEQ0 + k)) 2000 "--identification \$((ID0 + k)) --frag-emit 0"; done ;;
firsts80)
    for k in \$(seq 64 79); do send s50f \$((SEQ0 + k)) 2000 "--identification \$((ID0 + k)) --frag-emit 0"; done
    # atomic probe against the full cache (S-19b): must deliver without taking a slot
    rc=0
    ../udpopt-send --src $1 --dst $2 --src-port $SRC_PORT --dst-port $DST_PORT \\
        --count 1 --manifest manifest.jsonl --payload-hex "" \\
        --raw-options-hex "030c0016\$(printf '%08x' \$((64960 + R)))00080048\$(printf '%016x' \$((6200 + R)))\$(printf '00%.0s' \$(seq 1 56))" \\
        >>send.log 2>&1 || rc=\$?
    echo "attempt class=s50p seq=\$((6200 + R)) payload=64 rc=\$rc" >>send.log
    ;;
controls)  for j in \$(seq 0 19); do send s50c \$((SEQ0 + 80 + j)) 1200 "--no-frag"; done ;;
terminalsV) for k in \$(seq 0 79);  do send s50t \$((SEQ0 + k)) 2000 "--identification \$((ID0 + k)) --frag-emit 1"; done ;;
terminalsR) for k in \$(seq 79 -1 0); do send s50t \$((SEQ0 + k)) 2000 "--identification \$((ID0 + k)) --frag-emit 1"; done ;;
esac
EOF
}

# --- generic two-direction scenario --------------------------------------------------------------

run_direction() {
    local name="$1" s_ssh="$2" s_ip="$3" s_if="$4" s_dir="$5" s_sudo="$6" \
        r_ssh="$7" r_ip="$8" r_if="$9" r_dir="${10}" r_sudo="${11}" \
        s_local="${12:-$3}" r_local="${13:-$8}"
    local srun="$s_dir/run-$SCENARIO-$name" rrun="$r_dir/run-$SCENARIO-$name"
    local egfilter="udp and src host $s_local and dst host $r_ip and ((src port $SRC_PORT and dst port $DST_PORT) or dst port $CANARY_PORT)"
    local infilter="udp and src host $s_ip and dst host $r_local and ((src port $SRC_PORT and dst port $DST_PORT) or dst port $CANARY_PORT)"
    local out="$RUN_ROOT/$name"
    mkdir -p "$out"
    echo "== $SCENARIO $name: $s_ip -> $r_ip =="

    ssh -n "$r_ssh" "$r_sudo rm -rf $rrun && mkdir -p $rrun"
    ssh -n "$s_ssh" "$s_sudo rm -rf $srun && mkdir -p $srun"

    start_capture "$r_ssh" "$r_sudo" "$r_if" "$rrun" ingress.pcap "$infilter"
    start_capture "$s_ssh" "$s_sudo" "$s_if" "$srun" egress.pcap "$egfilter"
    canary_until_ready "$s_ssh" "$r_ip" "$r_ssh:$rrun/ingress.pcap" "$s_ssh:$srun/egress.pcap"

    local rcount="$EXPECTED"
    [ "$rcount" -eq 0 ] && rcount=100000
    ssh -n "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup ../udpopt-recv --dst-port $DST_PORT --src-port $SRC_PORT --own-src $r_local --timeout-ms 0 --count $rcount $RECV_EXTRA --json >recv.jsonl 2>recv.log & echo \$! >recv.pid'"

    make_sender_script "$s_local" "$r_ip" >"$out/sender.sh"
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

    python3 scripts/p2-eval.py "$SCENARIO" "$name" "$out" | tee -a "$RUN_ROOT/results.md"
}

# --- S-50: six runs per direction, fresh receiver and fresh ids per run --------------------------

run_s50_direction() {
    local name="$1" s_ssh="$2" s_ip="$3" s_if="$4" s_dir="$5" s_sudo="$6" \
        r_ssh="$7" r_ip="$8" r_if="$9" r_dir="${10}" r_sudo="${11}" dirbase="${12}" \
        s_local="${13:-$3}" r_local="${14:-$8}"
    local srun="$s_dir/run-$SCENARIO-$name" rrun="$r_dir/run-$SCENARIO-$name"
    local egfilter="udp and src host $s_local and dst host $r_ip and ((src port $SRC_PORT and dst port $DST_PORT) or dst port $CANARY_PORT)"
    local infilter="udp and src host $s_ip and dst host $r_local and ((src port $SRC_PORT and dst port $DST_PORT) or dst port $CANARY_PORT)"
    local out="$RUN_ROOT/$name"
    mkdir -p "$out"
    echo "== $SCENARIO $name: $s_ip -> $r_ip =="

    ssh -n "$r_ssh" "$r_sudo rm -rf $rrun && mkdir -p $rrun"
    ssh -n "$s_ssh" "$s_sudo rm -rf $srun && mkdir -p $srun"
    start_capture "$r_ssh" "$r_sudo" "$r_if" "$rrun" ingress.pcap "$infilter"
    start_capture "$s_ssh" "$s_sudo" "$s_if" "$srun" egress.pcap "$egfilter"
    canary_until_ready "$s_ssh" "$r_ip" "$r_ssh:$rrun/ingress.pcap" "$s_ssh:$srun/egress.pcap"

    rss() { # <run-index g> <tag>
        ssh -n "$r_ssh" "grep VmRSS /proc/\$(cat $rrun/recv-r$1.pid)/status 2>/dev/null || echo 'VmRSS: n/a'" |
            sed "s/^/run=$1 $2 /" >>"$out/vmrss.txt"
    }

    local g r order
    for g in 0 1 2 3 4 5; do
        r=$((dirbase + g))
        order=terminalsV
        [ "$g" -ge 3 ] && order=terminalsR
        echo "-- Lauf $r ($order) --"
        ssh -n "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup ../udpopt-recv --dst-port $DST_PORT --src-port $SRC_PORT --own-src $r_local --timeout-ms 0 --count 100000 $RECV_EXTRA --json >recv-r$g.jsonl 2>recv-r$g.log & echo \$! >recv-r$g.pid'"
        sleep 0.5
        rss "$g" leer
        make_s50_script "$s_local" "$r_ip" "$r" >"$out/s50-run$g.sh"
        scp -q "$out/s50-run$g.sh" "$s_ssh:$srun/s50-run$g.sh"
        ssh -n "$s_ssh" "$s_sudo bash $srun/s50-run$g.sh firsts32"
        rss "$g" nach32
        ssh -n "$s_ssh" "$s_sudo bash $srun/s50-run$g.sh firsts64"
        rss "$g" nach64
        ssh -n "$s_ssh" "$s_sudo bash $srun/s50-run$g.sh firsts80"
        rss "$g" nach80
        ssh -n "$s_ssh" "$s_sudo bash $srun/s50-run$g.sh controls"
        ssh -n "$s_ssh" "$s_sudo bash $srun/s50-run$g.sh $order"
        rss "$g" nachTerminalen
        poll_lines "$r_ssh" "$rrun/recv-r$g.jsonl" 0
        if [ "$g" -eq 5 ]; then
            echo "   warte 65 s auf Timeout-Ablauf plus GC fuer die VmRSS-Reihe"
            sleep 65
            ssh -n "$s_ssh" "bash -c 'echo -n gc >/dev/udp/$r_ip/$CANARY_PORT'" || true
            rss "$g" nachTimeout
        fi
        ssh -n "$r_ssh" "$r_sudo bash -c 'kill \$(cat $rrun/recv-r$g.pid) 2>/dev/null; sleep 1'; true"
    done

    stop_capture "$r_ssh" "$r_sudo" "$rrun" ingress.pcap
    stop_capture "$s_ssh" "$s_sudo" "$srun" egress.pcap
    snapshot_meta "$out" "$s_ssh" "$s_if" "$s_dir" "$r_ssh" "$r_if" "$r_dir"

    ssh -n "$r_ssh" "$r_sudo chmod -R a+rX $rrun"
    ssh -n "$s_ssh" "$s_sudo chmod -R a+rX $srun"
    scp -q "$r_ssh:$rrun/recv-r"*.jsonl "$r_ssh:$rrun/ingress.pcap" "$out/"
    scp -q "$r_ssh:$rrun/tcpdump-ingress.pcap.log" "$out/tcpdump-ingress.log"
    scp -q "$s_ssh:$srun/manifest.jsonl" "$s_ssh:$srun/send.log" "$s_ssh:$srun/egress.pcap" "$out/"
    scp -q "$s_ssh:$srun/tcpdump-egress.pcap.log" "$out/tcpdump-egress.log"
    ssh -n "$r_ssh" "$r_sudo rm -rf $rrun"
    ssh -n "$s_ssh" "$s_sudo rm -rf $srun"

    python3 scripts/p2-eval.py "$SCENARIO" "$name" "$out" | tee -a "$RUN_ROOT/results.md"
}

# --- dispatch ------------------------------------------------------------------------------------

: >"$RUN_ROOT/results.md"
if [ "$SCENARIO" = p2s50 ]; then
    run_s50_direction "a-$A_NAME-to-$B_NAME" "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO" \
        "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO" 0 "$MCS_LOCAL_IP" "$BLU_LOCAL_IP"
    run_s50_direction "b-$B_NAME-to-$A_NAME" "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO" \
        "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO" 6 "$BLU_LOCAL_IP" "$MCS_LOCAL_IP"
else
    run_direction "a-$A_NAME-to-$B_NAME" "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO" \
        "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO" "$MCS_LOCAL_IP" "$BLU_LOCAL_IP"
    run_direction "b-$B_NAME-to-$A_NAME" "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO" \
        "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO" "$BLU_LOCAL_IP" "$MCS_LOCAL_IP"
fi
echo "done: $RUN_ROOT"
