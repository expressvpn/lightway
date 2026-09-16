#!/bin/bash

set -euo pipefail

echo ""
echo "====================================================================="
echo "INITIAL CONNECTIVITY CHECK"
echo "====================================================================="

docker compose exec client ping -W 1 -c 3 nginx

echo ""
echo "====================================================================="
echo "VERIFY VPN CONNECTIVITY BEFORE WIFI SWITCH"
echo "====================================================================="

docker compose exec client ping -W 1 -c 3 nginx

tunnel_ip=$(docker compose exec client ip --json addr show lightway | jq -r '.[0].addr_info[0].local')
echo "Tunnel IP: ${tunnel_ip}"

# Identify the physical interface currently used to route to the server
server_ip=$(docker compose exec client getent hosts server | awk '{print $1}' | head -1)
active_iface=$(docker compose exec client ip --json route get "$server_ip" | jq -r '.[0].dev')
active_ip=$(docker compose exec client ip --json addr show "$active_iface" | jq -r '.[0].addr_info[0].local')

echo "Server IP: ${server_ip}"
echo "Active interface: ${active_iface} (${active_ip})"

echo ""
docker compose exec client ip addr show
echo ""
docker compose exec client ip route show

# ---------------------------------------------------------------------

echo ""
echo "====================================================================="
echo "SIMULATING WIFI SWITCH: Deleting ${active_iface} (${active_ip})"
echo "====================================================================="

docker compose exec client ip link delete "${active_iface}"

echo ""
echo "Client interfaces after switch:"
docker compose exec client ip addr show
echo ""
docker compose exec client ip route show

# ---------------------------------------------------------------------

echo ""
echo "====================================================================="
echo "WAITING FOR VPN TO RECONNECT VIA SECONDARY INTERFACE"
echo "====================================================================="

MAX_WAIT=60
INTERVAL=5
elapsed=0
reconnected=false

while [ "$elapsed" -lt "$MAX_WAIT" ]; do
    if docker compose exec client ping -W 1 -c 1 nginx > /dev/null 2>&1; then
        reconnected=true
        echo "VPN reconnected after ${elapsed}s"
        break
    fi
    echo "Waiting for reconnection... (${elapsed}/${MAX_WAIT}s)"
    sleep "$INTERVAL"
    elapsed=$(( elapsed + INTERVAL ))
done

if [ "$reconnected" != "true" ]; then
    echo "VPN failed to reconnect within ${MAX_WAIT}s"
    exit 1
fi

# ---------------------------------------------------------------------

echo ""
echo "====================================================================="
echo "VERIFY VPN CONNECTIVITY AFTER WIFI SWITCH"
echo "====================================================================="

docker compose exec client ping -W 1 -c 3 nginx

REPLY=$(docker compose exec client curl --silent http://nginx)
IP=$(<<< "$REPLY" jq -e -r '.ip // "fail"' || echo "invalid-json")

echo ""
echo "curl replied: $REPLY"
echo "Server saw IP: $IP"
echo ""

case $IP in
    "fail")
        echo "Invalid response from nginx"
        exit 1
        ;;
    "invalid-json")
        echo "JSON response did not contain ip key"
        exit 1
        ;;
    "${tunnel_ip}")
        echo "nginx saw our real tunnel IP!"
        exit 1
        ;;
    "10.0."*)
        echo "nginx saw a backend network IP address -- VPN is masquerading correctly!"
        ;;
    *)
        echo "nginx unexpectedly saw IP ${IP}"
        exit 1
        ;;
esac

new_iface=$(docker compose exec client ip --json route get "$server_ip" | jq -r '.[0].dev')
new_ip=$(docker compose exec client ip --json addr show "$new_iface" | jq -r '.[0].addr_info[0].local')
echo ""
echo "VPN reconnected via: ${new_iface} (${new_ip})"

echo ""
echo "====================================================================="
echo "WIFI SWITCH TEST PASSED"
echo "====================================================================="
