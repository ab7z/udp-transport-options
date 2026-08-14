#!/usr/bin/env bash
# Remote command fragments are intentionally expanded and quoted on the client.
# shellcheck disable=SC2029
# P0 campaign driver for the real path 1blu <-> mcs (FF1 test plan, scenarios S-35 and S-31).
#
#   scripts/p0-campaign.sh s35   # MTU sweep: IPv4 totals 1460..1520, baseline + APC twins
#   scripts/p0-campaign.sh s31   # twin sandwich series: 500 baseline/typed/baseline triples
#
# Runs from the workstation and orchestrates both hosts over ssh: receiver-side and sender-side
# tcpdump with a canary warm-up on an allowed port (cloud firewalls drop unknown ports before the
# NIC, so the canary must use one), a blocking udpopt-recv (--timeout-ms 0) stopped by pidfile,
# and a per-attempt send log so sender errors (EMSGSIZE) stay separable from path loss. Artifacts
# land under target/p0-campaign-<stamp>/<scenario>/<direction>/ and are evaluated by p0-eval.py.
# Hosts, ports and interfaces are the fixed uoe-s00 deployment from the S-00 pre-stage.
set -euo pipefail

SCENARIO="${1:?usage: p0-campaign.sh <s35|s31>}"
STAMP="${P0_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
cd "$(dirname "$0")/.."
RUN_ROOT="target/p0-campaign-$STAMP/$SCENARIO"
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

case "$SCENARIO" in
    s35) EXPECTED=0 ;;      # delivered count is the measurement; stop on a stable line count
    s31) EXPECTED=1500 ;;   # 500 triples, unfragmented
    *) echo "unknown scenario: $SCENARIO (supported: s35, s31)" >&2; exit 64 ;;
esac

# Emits the per-direction send sequence. Every attempt is logged with its exit code so the
# evaluator can separate sender-side errors from path loss; --no-frag keeps oversized sends as
# hard errors instead of silent auto-fragmentation. seq ranges encode the class (see p0-eval.py).
make_sender_script() { # $1 src_ip, $2 dst_ip
    cat <<EOF
#!/usr/bin/env bash
set -u
cd "\$(dirname "\$0")"
send() {
    local cls="\$1" seq="\$2" pay="\$3" extra="\$4" rc=0
    ../udpopt-send --src $1 --dst $2 --src-port $SRC_PORT --dst-port $DST_PORT --no-frag \\
        --count 1 --manifest manifest.jsonl --seq-start "\$seq" --payload-size "\$pay" \\
        \$extra >>send.log 2>&1 || rc=\$?
    echo "attempt class=\$cls seq=\$seq payload=\$pay rc=\$rc" >>send.log
    sleep 0.02
}
EOF
    case "$SCENARIO" in
    s35) cat <<'EOF'
# 16 IPv4 total lengths, 1460..1520 step 4; per length 3 baseline + 3 APC twins of equal total.
# Baseline payload = L - 28 (IP + UDP header); typed payload = L - 38 (10-byte APC surplus).
# --max-datagram-len 1600 lifts the CLI's own ceiling so sizes above 1500 reach the kernel and
# the sweep measures the path (EMSGSIZE or wire behavior), not the tool default.
for idx in $(seq 0 15); do
    L=$((1460 + 4 * idx))
    for k in 0 1 2; do
        send b $((idx * 10 + k)) $((L - 28)) "--max-datagram-len 1600"
        send t $((1000 + idx * 10 + k)) $((L - 38)) "--apc --max-datagram-len 1600"
    done
done
EOF
        ;;
    s31) cat <<'EOF'
# 500 sandwich triples on one 5-tuple: baseline, APC twin of equal IPv4 total (102), baseline.
for i in $(seq 0 499); do
    send b $((3 * i)) 74 ""
    send t $((3 * i + 1)) 64 "--apc"
    send b $((3 * i + 2)) 74 ""
done
EOF
        ;;
    esac
}

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

    local rcount="$EXPECTED"
    [ "$rcount" -eq 0 ] && rcount=100000
    # The starts use ';' before nohup: with '&&', '&' would background the whole 'cd && nohup'
    # list, tcpdump would run in the foreground of that subshell and hold the ssh channel open.
    ssh "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup tcpdump -i $r_if -n -p -U --immediate-mode -w ingress.pcap \"$filter\" >/dev/null 2>tcpdump.log & echo \$! >tcpdump.pid'"
    ssh "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup ../udpopt-recv --dst-port $DST_PORT --src-port $SRC_PORT --own-src $r_ip --timeout-ms 0 --count $rcount --json >recv.jsonl 2>recv.log & echo \$! >recv.pid'"
    ssh "$s_ssh" "$s_sudo bash -c 'cd $srun || exit 1; nohup tcpdump -i $s_if -n -p -U --immediate-mode -w egress.pcap \"$filter\" >/dev/null 2>tcpdump.log & echo \$! >tcpdump.pid'"

    # Canary warm-up on the allowed spare port until both captures provably record traffic.
    local ready=0 ri si
    for _ in $(seq 1 20); do
        ssh "$s_ssh" "bash -c 'echo -n canary >/dev/udp/$r_ip/$CANARY_PORT'"
        sleep 0.4
        ri=$(ssh "$r_ssh" "stat -c %s $rrun/ingress.pcap 2>/dev/null || echo 0")
        si=$(ssh "$s_ssh" "stat -c %s $srun/egress.pcap 2>/dev/null || echo 0")
        if [ "$ri" -gt 24 ] && [ "$si" -gt 24 ]; then
            ready=1
            break
        fi
    done
    [ "$ready" -eq 1 ] || { echo "error: captures never recorded the canary" >&2; exit 1; }

    make_sender_script "$s_ip" "$r_ip" >"$out/sender.sh"
    scp -q "$out/sender.sh" "$s_ssh:$srun/sender.sh"
    ssh "$s_ssh" "$s_sudo bash $srun/sender.sh"

    # Completion: the expected line count, or a line count stable across three 5s polls.
    local lines=0 last=-1 stable=0
    for _ in $(seq 1 120); do
        lines=$(ssh "$r_ssh" "wc -l <$rrun/recv.jsonl 2>/dev/null || echo 0")
        if [ "$EXPECTED" -gt 0 ] && [ "$lines" -ge "$EXPECTED" ]; then break; fi
        if [ "$lines" -eq "$last" ]; then
            stable=$((stable + 1))
            [ "$stable" -ge 3 ] && break
        else
            stable=0
            last="$lines"
        fi
        sleep 5
    done
    echo "   recv lines: $lines (expected: $EXPECTED)"

    ssh "$r_ssh" "$r_sudo bash -c 'kill \$(cat $rrun/recv.pid) 2>/dev/null; sleep 1; kill -INT \$(cat $rrun/tcpdump.pid) 2>/dev/null; sleep 1'; true"
    ssh "$s_ssh" "$s_sudo bash -c 'kill -INT \$(cat $srun/tcpdump.pid) 2>/dev/null; sleep 1'; true"
    ssh "$r_ssh" "grep -q '^0 packets dropped by kernel' $rrun/tcpdump.log" ||
        { echo "error: kernel drops in the receiver capture" >&2; exit 1; }
    ssh "$s_ssh" "grep -q '^0 packets dropped by kernel' $srun/tcpdump.log" ||
        { echo "error: kernel drops in the sender capture" >&2; exit 1; }

    ssh "$s_ssh" "hostname; uname -r; ip -o link show $s_if; sha256sum $s_dir/udpopt-send" >"$out/meta-sender.txt"
    ssh "$r_ssh" "hostname; uname -r; ip -o link show $r_if; sha256sum $r_dir/udpopt-recv" >"$out/meta-receiver.txt"

    ssh "$r_ssh" "$r_sudo chmod -R a+rX $rrun"
    ssh "$s_ssh" "$s_sudo chmod -R a+rX $srun"
    scp -q "$r_ssh:$rrun/recv.jsonl" "$r_ssh:$rrun/recv.log" "$r_ssh:$rrun/ingress.pcap" "$out/"
    scp -q "$r_ssh:$rrun/tcpdump.log" "$out/tcpdump-ingress.log"
    scp -q "$s_ssh:$srun/manifest.jsonl" "$s_ssh:$srun/send.log" "$s_ssh:$srun/egress.pcap" "$out/"
    scp -q "$s_ssh:$srun/tcpdump.log" "$out/tcpdump-egress.log"
    ssh "$r_ssh" "$r_sudo rm -rf $rrun"
    ssh "$s_ssh" "$s_sudo rm -rf $srun"

    python3 scripts/p0-eval.py "$SCENARIO" "$name" "$out" | tee -a "$RUN_ROOT/results.md"
}

: >"$RUN_ROOT/results.md"
run_direction a-mcs-to-1blu "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO" \
    "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO"
run_direction b-1blu-to-mcs "$BLU_SSH" "$BLU_IP" "$BLU_IF" "$BLU_DIR" "$BLU_SUDO" \
    "$MCS_SSH" "$MCS_IP" "$MCS_IF" "$MCS_DIR" "$MCS_SUDO"
echo "done: $RUN_ROOT"
