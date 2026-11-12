#!/bin/bash

set -euo pipefail

# Run with the client's raw TCP coalescing enabled: the usual tests must
# still pass, the capability probe must succeed with no fallback, and
# over UDP a bulk TCP download must reach the TUN as packets larger than
# its MTU. Over TCP transport few decrypt batches hold several segments,
# so the size check would be flaky there and is skipped.

if [ $# -ne 1 ] || { [ "$1" != udp ] && [ "$1" != tcp ]; } ; then
    echo "Usage: $0 udp|tcp"
    exit 1
fi
mode="$1"

./run-simple-test.sh

echo ""
echo "====================================================================="
echo "CHECKING client TCP coalescing"
echo "====================================================================="

stat() {
    docker compose exec -T client cat "/sys/class/net/lightway/statistics/$1"
}

mtu=$(docker compose exec -T client ip --json link show lightway | jq -r '.[0].mtu')
bytes_before=$(stat rx_bytes)
packets_before=$(stat rx_packets)

# Unthrottled, so decrypt batches hold several segments of the flow.
docker compose exec -T client retry --times=3 --delay=1 -- iperf3 -t 5 -c iperf -R

# What the client writes into the TUN, the kernel counts as received.
bytes=$(( $(stat rx_bytes) - bytes_before ))
packets=$(( $(stat rx_packets) - packets_before ))
if [ "$packets" -eq 0 ] ; then
    echo "The download wrote nothing to the TUN"
    exit 1
fi
average=$(( bytes / packets ))
echo "TUN writes during the download: ${packets} packets, ${bytes} bytes, average ${average} (MTU ${mtu})"

logs=$(mktemp)
trap 'rm -f "$logs"' EXIT
docker compose logs --no-color client >"$logs"
if grep -q "IPv4 forwarding is on for the TUN" "$logs" ; then
    echo "The client container forwards IPv4, so coalescing is not allowed (see docker-compose.yml)"
    exit 1
fi
if ! grep -q "oversized TUN write probe succeeded" "$logs" ; then
    echo "The coalescing capability probe did not succeed"
    exit 1
fi
if grep -qE "permanently falling back|re-split segment rebuild failed" "$logs" ; then
    echo "Coalescing fell back or failed to re-split"
    exit 1
fi
if [ "$mode" = udp ] && [ "$average" -le "$mtu" ] ; then
    echo "Average TUN write is not above the MTU: nothing was coalesced"
    exit 1
fi

if [ "$mode" = udp ] ; then
    echo "Coalesced writes reached the TUN"
else
    echo "Probe succeeded with no fallback (size check skipped over TCP)"
fi
