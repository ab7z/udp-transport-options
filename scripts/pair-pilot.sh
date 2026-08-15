#!/usr/bin/env bash
# Remote command fragments are intentionally expanded and quoted on the client.
# shellcheck disable=SC2029
# Readiness pilot for one host pair: 3 baseline + 6 REQ-typed datagrams per direction on the
# campaign ports, judged on the delivered receiver rows (REQ parsed, OCS valid). This is the cheap
# smoke check before a full pair-campaign.sh run, e.g. after standing up a new endpoint; it needs
# only the canonical uoe-s00 binary deployment on both hosts and takes well under a minute.
#
#   scripts/pair-pilot.sh <pair>     # pairs as in pair-campaign.sh
#
# Endpoints follow the same role-A/role-B environment overrides as the campaign drivers. Artifacts
# (per-direction recv JSONL and send log) land under target/pair-pilot-<stamp>-<pair>/.
set -uo pipefail

PAIR="${1:?usage: pair-pilot.sh <mcs-1blu|mcs-hel|hel-1blu>}"
cd "$(dirname "$0")/.." || exit 1

MCS_SSH=${MCS_SSH:-ab@46.225.188.39}
MCS_IP=${MCS_IP:-46.225.188.39}
MCS_DIR=${MCS_DIR:-/home/ab/uoe-s00}
MCS_SUDO=${MCS_SUDO:-sudo}
BLU_SSH=${BLU_SSH:-root@178.254.35.195}
BLU_IP=${BLU_IP:-178.254.35.195}
BLU_DIR=${BLU_DIR:-/root/uoe-s00}
BLU_SUDO=${BLU_SUDO-}
A_NAME=${A_NAME:-mcs}
B_NAME=${B_NAME:-1blu}

HEL_SSH=ab@62.238.103.75
HEL_IP=62.238.103.75
HEL_DIR=/home/ab/uoe-s00
HEL_SUDO=sudo

case "$PAIR" in
mcs-1blu) ;;
mcs-hel)
    BLU_SSH="$HEL_SSH" BLU_IP="$HEL_IP" BLU_DIR="$HEL_DIR" BLU_SUDO="$HEL_SUDO"
    A_NAME=mcs B_NAME=hel
    ;;
hel-1blu)
    MCS_SSH="$HEL_SSH" MCS_IP="$HEL_IP" MCS_DIR="$HEL_DIR" MCS_SUDO="$HEL_SUDO"
    A_NAME=hel B_NAME=1blu
    ;;
*) echo "unknown pair: $PAIR" >&2; exit 64 ;;
esac

DST_PORT=47101
SRC_PORT=47102
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$PAIR"
RUN_ROOT="target/pair-pilot-$STAMP"
mkdir -p "$RUN_ROOT"
fail=0

# run_pilot <name> <s_ssh> <s_sudo> <s_dir> <s_ip> <r_ssh> <r_sudo> <r_dir> <r_ip>
run_pilot() {
    local name="$1" s_ssh="$2" s_sudo="$3" s_dir="$4" s_ip="$5" \
        r_ssh="$6" r_sudo="$7" r_dir="$8" r_ip="$9"
    local rrun="$r_dir/run-pilot-$name" srun="$s_dir/run-pilot-$name"
    local out="$RUN_ROOT/$name" alive b t
    mkdir -p "$out"
    echo "== pilot $name: $s_ip -> $r_ip =="

    ssh -n "$r_ssh" "$r_sudo rm -rf $rrun && mkdir -p $rrun"
    ssh -n "$s_ssh" "$s_sudo rm -rf $srun && mkdir -p $srun"
    ssh -n "$r_ssh" "$r_sudo bash -c 'cd $rrun || exit 1; nohup ../udpopt-recv --dst-port $DST_PORT --src-port $SRC_PORT --own-src $r_ip --timeout-ms 0 --count 9 --json >recv.jsonl 2>recv.log & echo \$! >recv.pid'"
    sleep 1
    ssh -n "$s_ssh" "$s_sudo bash -c 'cd $srun || exit 1; for k in 0 1 2; do ../udpopt-send --src $s_ip --dst $r_ip --src-port $SRC_PORT --dst-port $DST_PORT --count 1 --seq-start \$k --payload-size 64 --no-frag >>send.log 2>&1; echo \"attempt class=b seq=\$k rc=\$?\" >>send.log; sleep 0.1; done; for k in 1000 1001 1002 1003 1004 1005; do ../udpopt-send --src $s_ip --dst $r_ip --src-port $SRC_PORT --dst-port $DST_PORT --count 1 --seq-start \$k --payload-size 64 --req deadbeef --no-frag >>send.log 2>&1; echo \"attempt class=t seq=\$k rc=\$?\" >>send.log; sleep 0.1; done'"
    for _ in $(seq 1 12); do
        alive=$(ssh -n "$r_ssh" "$r_sudo bash -c 'kill -0 \$(cat $rrun/recv.pid) 2>/dev/null && echo up || echo down'")
        [ "$alive" = "down" ] && break
        sleep 1
    done
    ssh -n "$r_ssh" "$r_sudo bash -c 'kill \$(cat $rrun/recv.pid) 2>/dev/null; chmod -R a+rX $rrun'; true"
    scp -q "$r_ssh:$rrun/recv.jsonl" "$out/recv.jsonl"
    scp -q "$s_ssh:$srun/send.log" "$out/send.log"
    ssh -n "$r_ssh" "$r_sudo rm -rf $rrun"
    ssh -n "$s_ssh" "$s_sudo rm -rf $srun"

    b=$(grep -c '"option_bearing":false' "$out/recv.jsonl" || true)
    t=$(grep -c '"options":"REQ:deadbeef","reports":"REQ:success:datagram","ocs_reports":"valid:datagram"' "$out/recv.jsonl" || true)
    echo "   baseline $b/3, typed(REQ+OCS valid) $t/6"
    if [ "$b" -ne 3 ] || [ "$t" -ne 6 ]; then
        fail=1
        echo "!!!!! pilot $name FAILED"
    fi
}

run_pilot "a-$A_NAME-to-$B_NAME" "$MCS_SSH" "$MCS_SUDO" "$MCS_DIR" "$MCS_IP" \
    "$BLU_SSH" "$BLU_SUDO" "$BLU_DIR" "$BLU_IP"
run_pilot "b-$B_NAME-to-$A_NAME" "$BLU_SSH" "$BLU_SUDO" "$BLU_DIR" "$BLU_IP" \
    "$MCS_SSH" "$MCS_SUDO" "$MCS_DIR" "$MCS_IP"

echo "pilot done: pair=$PAIR fail=$fail stamp=$STAMP"
exit "$fail"
