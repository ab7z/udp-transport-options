#!/usr/bin/env bash
# Full-suite campaign master: runs every P0/P1/P2 scenario for one host pair by exporting the
# role-A/role-B endpoint overrides understood by scripts/p{0,1,2}-campaign.sh.
#
#   scripts/pair-campaign.sh <pair>
#
# Pairs: mcs-1blu (the driver defaults), mcs-hel, hel-1blu, aws-mcs, aws-hel, aws-1blu. The aws
# endpoint sits behind the EC2 1:1 NAT, so it carries a *_LOCAL_IP override (raw sends and the
# local capture use the internal address, peers address the public one). One shared stamp groups
# the artifacts under target/p{0,1,2}-campaign-<stamp>-<pair>/<scenario>/. A scenario failure does
# not stop the suite: the failed scenario is flagged in the log, the run continues, and the final
# summary line carries overall=1 (also the exit code). p2netem is intentionally not scheduled
# (S-51 struck by decision E1, see p2-campaign.sh).
set -uo pipefail

PAIR="${1:?usage: pair-campaign.sh <mcs-1blu|mcs-hel|hel-1blu|aws-mcs|aws-hel|aws-1blu>}"
cd "$(dirname "$0")/.." || exit 1

# The helsinki endpoint (Hetzner HEL1, deployed 2026-08-15 with the uoe-s00 layout).
HEL_SSH=ab@62.238.103.75
HEL_IP=62.238.103.75
HEL_IF=eth0
HEL_DIR=/home/ab/uoe-s00
HEL_SUDO=sudo

# The aws endpoint (EC2 t3.micro us-east-1a, deployed 2026-08-16 with the uoe-s00 layout).
# NAT-split: the public IP is held by the EC2 1:1 NAT, the NIC carries only the internal one.
AWS_SSH=ab@100.48.90.53
AWS_IP=100.48.90.53
AWS_LOCAL_IP=172.31.8.92
AWS_IF=ens5
AWS_DIR=/home/ab/uoe-s00
AWS_SUDO=sudo

export_aws_role_a() {
    export MCS_SSH="$AWS_SSH" MCS_IP="$AWS_IP" MCS_LOCAL_IP="$AWS_LOCAL_IP" \
        MCS_IF="$AWS_IF" MCS_DIR="$AWS_DIR" MCS_SUDO="$AWS_SUDO"
    export A_NAME=aws
}

case "$PAIR" in
mcs-1blu) ;; # driver defaults, no overrides
mcs-hel)
    export BLU_SSH="$HEL_SSH" BLU_IP="$HEL_IP" BLU_IF="$HEL_IF" BLU_DIR="$HEL_DIR" BLU_SUDO="$HEL_SUDO"
    export A_NAME=mcs B_NAME=hel
    ;;
hel-1blu)
    export MCS_SSH="$HEL_SSH" MCS_IP="$HEL_IP" MCS_IF="$HEL_IF" MCS_DIR="$HEL_DIR" MCS_SUDO="$HEL_SUDO"
    export A_NAME=hel B_NAME=1blu
    ;;
aws-mcs)
    export_aws_role_a
    export BLU_SSH=ab@46.225.188.39 BLU_IP=46.225.188.39 BLU_IF=eth0 \
        BLU_DIR=/home/ab/uoe-s00 BLU_SUDO=sudo
    export B_NAME=mcs
    ;;
aws-hel)
    export_aws_role_a
    export BLU_SSH="$HEL_SSH" BLU_IP="$HEL_IP" BLU_IF="$HEL_IF" BLU_DIR="$HEL_DIR" BLU_SUDO="$HEL_SUDO"
    export B_NAME=hel
    ;;
aws-1blu)
    export_aws_role_a
    export B_NAME=1blu
    ;;
*) echo "unknown pair: $PAIR" >&2; exit 64 ;;
esac

STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$PAIR"
echo "campaign stamp: $STAMP"

overall=0
run_scenario() {
    local phase="$1" scen="$2" rc=0
    echo "===== [$(date -u +%H:%M:%SZ)] START $phase $scen ====="
    case "$phase" in
    P0) P0_STAMP="$STAMP" bash scripts/p0-campaign.sh "$scen" || rc=$? ;;
    P1) P1_STAMP="$STAMP" bash scripts/p1-campaign.sh "$scen" || rc=$? ;;
    P2) P2_STAMP="$STAMP" bash scripts/p2-campaign.sh "$scen" || rc=$? ;;
    esac
    if [ "$rc" -ne 0 ]; then
        overall=1
        echo "!!!!! $phase $scen FAILED rc=$rc"
    fi
    echo "===== [$(date -u +%H:%M:%SZ)] END $phase $scen rc=$rc ====="
}

for s in s35 s31 sopt sfrag s30 s40 s47 s48 s53 s14 s36; do run_scenario P0 "$s"; done
for s in p1opt p1frag p1coll p1s49; do run_scenario P1 "$s"; done
for s in p2opt p2frag p2s50; do run_scenario P2 "$s"; done

echo "pair done: pair=$PAIR overall=$overall stamp=$STAMP"
exit "$overall"
