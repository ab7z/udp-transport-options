#!/usr/bin/env bash
# Step 17 evaluation environment setup. Creates reproducible Linux network-namespace paths for
# FF2/P2 surplus-area survival measurements.

set -euo pipefail

topology="${1:-veth}"
action="${2:-up}"

case "$topology" in
    veth|router|nat|filter) ;;
    *)
        echo "usage: eval-env.sh [veth|router|nat|filter] [up|down|status]" >&2
        exit 64
        ;;
esac
case "$action" in
    up|down|status) ;;
    *)
        echo "usage: eval-env.sh [veth|router|nat|filter] [up|down|status]" >&2
        exit 64
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    exec sudo env "PATH=$PATH" "$0" "$@"
fi

NS_L=uoe-l
NS_M=uoe-m
NS_R=uoe-r
VETH_L=uoe-vl
VETH_R=uoe-vr
VETH_LM_L=uoe-lm-l
VETH_LM_M=uoe-lm-m
VETH_MR_M=uoe-mr-m
VETH_MR_R=uoe-mr-r

offload_off() {
    local ns="$1" dev="$2"
    ip netns exec "$ns" ethtool -K "$dev" tx off rx off gso off tso off gro off >/dev/null 2>&1 || true
}

down_all() {
    ip netns del "$NS_L" 2>/dev/null || true
    ip netns del "$NS_M" 2>/dev/null || true
    ip netns del "$NS_R" 2>/dev/null || true
    ip link del "$VETH_L" 2>/dev/null || true
    ip link del "$VETH_R" 2>/dev/null || true
    ip link del "$VETH_LM_L" 2>/dev/null || true
    ip link del "$VETH_LM_M" 2>/dev/null || true
    ip link del "$VETH_MR_M" 2>/dev/null || true
    ip link del "$VETH_MR_R" 2>/dev/null || true
}

up_veth() {
    down_all
    ip netns add "$NS_L"
    ip netns add "$NS_R"
    ip link add "$VETH_L" type veth peer name "$VETH_R"
    ip link set "$VETH_L" netns "$NS_L"
    ip link set "$VETH_R" netns "$NS_R"
    ip netns exec "$NS_L" ip addr add 10.9.1.1/24 dev "$VETH_L"
    ip netns exec "$NS_R" ip addr add 10.9.1.2/24 dev "$VETH_R"
    ip netns exec "$NS_L" ip link set lo up
    ip netns exec "$NS_R" ip link set lo up
    ip netns exec "$NS_L" ip link set "$VETH_L" mtu 1500 up
    ip netns exec "$NS_R" ip link set "$VETH_R" mtu 1500 up
    offload_off "$NS_L" "$VETH_L"
    offload_off "$NS_R" "$VETH_R"
    echo "eval-env: veth up: $NS_L 10.9.1.1 <-> $NS_R 10.9.1.2"
}

up_routed() {
    down_all
    ip netns add "$NS_L"
    ip netns add "$NS_M"
    ip netns add "$NS_R"
    ip link add "$VETH_LM_L" type veth peer name "$VETH_LM_M"
    ip link add "$VETH_MR_M" type veth peer name "$VETH_MR_R"
    ip link set "$VETH_LM_L" netns "$NS_L"
    ip link set "$VETH_LM_M" netns "$NS_M"
    ip link set "$VETH_MR_M" netns "$NS_M"
    ip link set "$VETH_MR_R" netns "$NS_R"

    ip netns exec "$NS_L" ip addr add 10.9.1.1/24 dev "$VETH_LM_L"
    ip netns exec "$NS_M" ip addr add 10.9.1.254/24 dev "$VETH_LM_M"
    ip netns exec "$NS_M" ip addr add 10.9.2.254/24 dev "$VETH_MR_M"
    ip netns exec "$NS_R" ip addr add 10.9.2.2/24 dev "$VETH_MR_R"
    for ns in "$NS_L" "$NS_M" "$NS_R"; do
        ip netns exec "$ns" ip link set lo up
    done
    ip netns exec "$NS_L" ip link set "$VETH_LM_L" mtu 1500 up
    ip netns exec "$NS_M" ip link set "$VETH_LM_M" mtu 1500 up
    ip netns exec "$NS_M" ip link set "$VETH_MR_M" mtu 1500 up
    ip netns exec "$NS_R" ip link set "$VETH_MR_R" mtu 1500 up
    offload_off "$NS_L" "$VETH_LM_L"
    offload_off "$NS_M" "$VETH_LM_M"
    offload_off "$NS_M" "$VETH_MR_M"
    offload_off "$NS_R" "$VETH_MR_R"

    ip netns exec "$NS_L" ip route add default via 10.9.1.254
    ip netns exec "$NS_R" ip route add default via 10.9.2.254
    ip netns exec "$NS_M" sysctl -qw net.ipv4.ip_forward=1

    if [ "$topology" = "nat" ]; then
        ip netns exec "$NS_M" nft add table ip uoe_nat
        ip netns exec "$NS_M" nft add chain ip uoe_nat postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
        ip netns exec "$NS_M" nft add rule ip uoe_nat postrouting oifname "$VETH_MR_M" masquerade
    fi
    if [ "$topology" = "filter" ]; then
        ip netns exec "$NS_M" nft add table ip uoe_filter
        ip netns exec "$NS_M" nft add chain ip uoe_filter forward '{ type filter hook forward priority filter; policy accept; }'
        ip netns exec "$NS_M" nft add rule ip uoe_filter forward udp dport 41000-41015 drop
    fi

    echo "eval-env: $topology up: $NS_L 10.9.1.1 -> $NS_M -> $NS_R 10.9.2.2"
}

status() {
    echo "namespaces:"
    ip netns list | grep -E '(^| )uoe-' || true
    echo "links:"
    ip -o link show | grep -E 'uoe-' || true
}

case "$action" in
    down)
        down_all
        echo "eval-env: down"
        ;;
    status)
        status
        ;;
    up)
        if [ "$topology" = "veth" ]; then
            up_veth
        else
            up_routed
        fi
        ;;
esac
