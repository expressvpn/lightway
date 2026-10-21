#!/bin/bash

set -euo pipefail

if [ $# -ne 1 ] ; then
    echo "Usage: $0 <expected_mtu>"
    exit 1
fi
expected_mtu="$1"

echo ""
echo "====================================================================="
echo "CHECKING client TUN MTU"
echo "====================================================================="

mtu=$(docker compose exec client ip --json link show lightway | jq -r '.[0].mtu')
echo "Client TUN MTU is ${mtu}, expected ${expected_mtu}"
if [ "$mtu" != "$expected_mtu" ] ; then
    echo "Client did not apply the server MTU"
    exit 1
fi

echo ""
echo "====================================================================="
echo "STARTING full MTU ping TEST"
echo "====================================================================="

# Don't fragment, so a packet of exactly the TUN MTU has to pass through
# the client receive buffers sized for the new MTU (20 IP + 8 ICMP header)
docker compose exec client ping -M "do" -s $((expected_mtu - 28)) -W 1 -c 3 nginx

./run-simple-test.sh
