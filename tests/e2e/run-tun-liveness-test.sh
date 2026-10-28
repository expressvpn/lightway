#!/bin/bash
#
# e2e test of the client TUN liveness check (`--tun-liveness-timeout`).
#
# Runs a download through the tunnel, then breaks the client's TUN path while
# the server keeps sending (TCP retransmits once the client's ACKs stop), and
# checks that the client detects the dead TUN and tears the connection down.
#
# Scenarios:
#   read-stall  - drop everything routed into the TUN device, so nothing is
#                 read from it while downstream data keeps arriving
#   link-down   - take the TUN link down. Linux drops packets written to a
#                 down TUN without an error, so this shows up as a read stall
#   healthy     - no fault; the check must not fire
#   udp-oneway  - no fault, but a one-way UDP download, so the client sends
#                 nothing into the tunnel. A known false positive of the
#                 check: this scenario documents that it fires

set -euo pipefail

scenario="${1:?usage: $0 read-stall|link-down|healthy|udp-oneway}"

TUN="lightway"
# Covers the TCP retransmit backoff plus the check interval for a 5s timeout,
# with margin.
WAIT_SECS="${TUN_LIVENESS_WAIT_SECS:-40}"
DEAD_LOG="TUN device appears dead"

echo "============================================================"
echo "TUN LIVENESS TEST: scenario=${scenario} wait=${WAIT_SECS}s"
echo "============================================================"

docker compose exec -T client ping -W 1 -c 3 nginx

# Rate-limited so the trace log stays manageable.
if [ "$scenario" = "udp-oneway" ]; then
    docker compose exec -T --detach client iperf3 -c iperf -u -R -b 1M -t 120
else
    docker compose exec -T --detach client iperf3 -c iperf -R -b 5M -t 120
fi
sleep 3

case "$scenario" in
    read-stall)
        docker compose exec -T client iptables -A OUTPUT -o "$TUN" -j DROP
        ;;
    link-down)
        docker compose exec -T client ip link set "$TUN" down
        ;;
    healthy|udp-oneway)
        # The container healthcheck pings nginx through the tunnel every
        # second, which would count as TUN reads. Drop it, so only the
        # download's own traffic is left.
        docker compose exec -T client iptables -A OUTPUT -o "$TUN" -p icmp -j DROP
        # Show what, if anything, the client still sends into the tunnel.
        docker compose exec -T client timeout 5 tcpdump -nn -i "$TUN" -Q out -c 5 || true
        ;;
    *)
        echo "Unknown scenario: $scenario"
        exit 1
        ;;
esac

DEADLINE=$(( $(date +%s) + WAIT_SECS ))
detected=""
while (( $(date +%s) < DEADLINE )); do
    detected=$(docker compose logs --no-log-prefix --no-color client 2>/dev/null \
        | grep -m1 "$DEAD_LOG" || true)
    if [ -n "$detected" ]; then
        break
    fi
    sleep 2
done

if [ "$scenario" = "healthy" ]; then
    if [ -n "$detected" ]; then
        echo "TUN LIVENESS TEST: FAIL - check fired on a healthy tunnel:"
        echo "$detected"
        exit 1
    fi
    docker compose exec -T client iptables -D OUTPUT -o "$TUN" -p icmp -j DROP
    docker compose exec -T client ping -W 1 -c 3 nginx
    echo "TUN LIVENESS TEST: PASS - no false positive"
    exit 0
fi

if [ -z "$detected" ]; then
    echo "TUN LIVENESS TEST: FAIL - dead TUN not detected within ${WAIT_SECS}s"
    exit 1
fi

echo "$detected"

# Both faults stop TUN reads while writes still succeed.
if ! grep -q "read stall" <<<"$detected"; then
    echo "TUN LIVENESS TEST: FAIL - expected a read stall"
    exit 1
fi

echo "TUN LIVENESS TEST: PASS - dead TUN detected"
