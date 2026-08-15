#!/usr/bin/env bash
# Remote command fragments are intentionally expanded and quoted on the client.
# shellcheck disable=SC2029
# Checksum-gate cross cell (finding P1-A): decides whether a path enforces the legacy UDP
# checksum over the entire IP payload. Per direction it sends, on the campaign ports:
#
#   cell G (gate victim):  20x REQ deadbeef, pad ff, sender-computed CORRECT OCS (seq 0-19)
#   cell C (compensated):  20x the same body with --ocs-hex 5b53, which passes a legacy gate
#                          and fails at the receiver (constant per P1-A algebra; seq 100-119)
#   cell B (baseline):     10x plain 74-byte datagrams without options (seq 900-909)
#
# A transparent path delivers G and C alike; a checksum-enforcing path kills G and forwards C.
# Cells are counted by their seq ranges from the delivered receiver rows; both ends capture
# (egress/ingress pcap with canary warm-up), so a kill can be localized like in the campaigns.
# Artifacts under target/checksumgate-<stamp>-<pair>/. Pairs and endpoint overrides as in
# pair-campaign.sh. Measured 2026-08-15: the gate exists on 1blu<->mcs AND on mcs<->hel.
#
#   scripts/checksumgate-cell.sh <pair>     # mcs-1blu | mcs-hel | hel-1blu
set -uo pipefail

PAIR="${1:?usage: checksumgate-cell.sh <mcs-1blu|mcs-hel|hel-1blu>}"
cd "$(dirname "$0")/.." || exit 1

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

HEL_SSH=ab@62.238.103.75
HEL_IP=62.238.103.75
HEL_IF=eth0
HEL_DIR=/home/ab/uoe-s00
HEL_SUDO=sudo

case "$PAIR" in
mcs-1blu) ;;
mcs-hel)
    BLU_SSH="$HEL_SSH" BLU_IP="$HEL_IP" BLU_IF="$HEL_IF" BLU_DIR="$HEL_DIR" BLU_SUDO="$HEL_SUDO"
    A_NAME=mcs B_NAME=hel
    ;;
hel-1blu)
    MCS_SSH="$HEL_SSH" MCS_IP="$HEL_IP" MCS_IF="$HEL_IF" MCS_DIR="$HEL_DIR" MCS_SUDO="$HEL_SUDO"
    A_NAME=hel B_NAME=1blu
    ;;
*) echo "unknown pair: $PAIR" >&2; exit 64 ;;
esac

DST_PORT=47101
SRC_PORT=47102
CANARY_PORT=47103
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$PAIR"
RUN_ROOT="target/checksumgate-$STAMP"
mkdir -p "$RUN_ROOT"

start_capture() { # <ssh> <sudo> <iface> <rundir> <pcap-name> <filter>
    ssh -n "$1" "$2 bash -c 'cd $4 || exit 1; nohup tcpdump -i $3 -n -p -U --immediate-mode -w $5 \"$6\" >/dev/null 2>tcpdump-$5.log & echo \$! >tcpdump-$5.pid'"
}

stop_capture() { # <ssh> <sudo> <rundir> <pcap-name>
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

# run_cells <name> <s_ssh> <s_sudo> <s_if> <s_dir> <s_ip> <r_ssh> <r_sudo> <r_if> <r_dir> <r_ip>
run_cells() {
    local name="$1" s_ssh="$2" s_sudo="$3" s_if="$4" s_dir="$5" s_ip="$6" \
        r_ssh="$7" r_sudo="$8" r_if="$9" r_dir="${10}" r_ip="${11}"
    local rrun="$r_dir/run-ckgate-$name" srun="$s_dir/run-ckgate-$name"
    local filter="udp and src host $s_ip and dst host $r_ip and ((src port $SRC_PORT and dst port $DST_PORT) or dst port $CANARY_PORT)"
    local out="$RUN_ROOT/$name" alive
    mkdir -p "$out"
    echo "== checksumgate $name: $s_ip -> $r_ip =="

    ssh -n "$r_ssh" "$r_sudo rm -rf $rrun && mkdir -p $rrun"
    ssh -n "$s_ssh" "$s_sudo rm -rf $srun && mkdir -p $srun"
    start_capture "$r_ssh" "$r_sudo" "$r_if" "$rrun" ingress.pcap "$filter"
    start_capture "$s_ssh" "$s_sudo" "$s_if" "$srun" egress.pcap "$filter"
    canary_until_ready "$s_ssh" "$r_ip" "$r_ssh:$rrun/ingress.pcap" "$s_ssh:$srun/egress.pcap"

    ssh -n "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup ../udpopt-recv --dst-port $DST_PORT --src-port $SRC_PORT --own-src $r_ip --timeout-ms 0 --count 50 --json >recv.jsonl 2>recv.log & echo \$! >recv.pid'"
    sleep 1
    ssh -n "$s_ssh" "$s_sudo bash -c 'cd $srun || exit 1; for k in \$(seq 0 19); do ../udpopt-send --src $s_ip --dst $r_ip --src-port $SRC_PORT --dst-port $DST_PORT --count 1 --manifest manifest.jsonl --seq-start \$k --payload-size 17 --no-frag --raw-options-hex 0606deadbeef00 --pad-hex ff >>send.log 2>&1; echo \"attempt class=g seq=\$k rc=\$?\" >>send.log; sleep 0.05; done; for k in \$(seq 100 119); do ../udpopt-send --src $s_ip --dst $r_ip --src-port $SRC_PORT --dst-port $DST_PORT --count 1 --manifest manifest.jsonl --seq-start \$k --payload-size 17 --no-frag --raw-options-hex 0606deadbeef00 --pad-hex ff --ocs-hex 5b53 >>send.log 2>&1; echo \"attempt class=c seq=\$k rc=\$?\" >>send.log; sleep 0.05; done; for k in \$(seq 900 909); do ../udpopt-send --src $s_ip --dst $r_ip --src-port $SRC_PORT --dst-port $DST_PORT --count 1 --manifest manifest.jsonl --seq-start \$k --payload-size 74 --no-frag >>send.log 2>&1; echo \"attempt class=b seq=\$k rc=\$?\" >>send.log; sleep 0.05; done'"
    for _ in $(seq 1 12); do
        alive=$(ssh -n "$r_ssh" "$r_sudo bash -c 'kill -0 \$(cat $rrun/recv.pid) 2>/dev/null && echo up || echo down'")
        [ "$alive" = "down" ] && break
        sleep 1
    done
    ssh -n "$r_ssh" "$r_sudo bash -c 'kill \$(cat $rrun/recv.pid) 2>/dev/null; sleep 1'; true"
    stop_capture "$r_ssh" "$r_sudo" "$rrun" ingress.pcap
    stop_capture "$s_ssh" "$s_sudo" "$srun" egress.pcap

    ssh -n "$r_ssh" "$r_sudo chmod -R a+rX $rrun"
    ssh -n "$s_ssh" "$s_sudo chmod -R a+rX $srun"
    scp -q "$r_ssh:$rrun/recv.jsonl" "$r_ssh:$rrun/ingress.pcap" "$out/"
    scp -q "$s_ssh:$srun/send.log" "$s_ssh:$srun/manifest.jsonl" "$s_ssh:$srun/egress.pcap" "$out/"
    ssh -n "$r_ssh" "$r_sudo rm -rf $rrun"
    ssh -n "$s_ssh" "$s_sudo rm -rf $srun"

    python3 - "$out" "$name" <<'PYEOF' | tee -a "$RUN_ROOT/summary.txt"
import json, sys
out, name = sys.argv[1], sys.argv[2]
g = c = b = 0
verdicts = {}
for line in open(f"{out}/recv.jsonl"):
    r = json.loads(line)
    seq = int(r["payload_hex"][:16], 16) if r["payload_len"] >= 8 else -1
    verdicts[r["ocs_reports"]] = verdicts.get(r["ocs_reports"], 0) + 1
    if 0 <= seq <= 19:
        g += 1
    elif 100 <= seq <= 119:
        c += 1
    elif 900 <= seq <= 909:
        b += 1
print(f"{name}: cell G (correct OCS, pad ff) {g}/20, cell C (compensated 5b53) {c}/20, "
      f"baseline {b}/10; verdicts {verdicts}")
PYEOF
}

run_cells "a-$A_NAME-to-$B_NAME" "$MCS_SSH" "$MCS_SUDO" "$MCS_IF" "$MCS_DIR" "$MCS_IP" \
    "$BLU_SSH" "$BLU_SUDO" "$BLU_IF" "$BLU_DIR" "$BLU_IP"
run_cells "b-$B_NAME-to-$A_NAME" "$BLU_SSH" "$BLU_SUDO" "$BLU_IF" "$BLU_DIR" "$BLU_IP" \
    "$MCS_SSH" "$MCS_SUDO" "$MCS_IF" "$MCS_DIR" "$MCS_IP"

echo "checksumgate done: pair=$PAIR stamp=$STAMP"
