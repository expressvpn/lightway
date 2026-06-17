#!/bin/sh

set -eu

server_ip_pool=10.128.0.0/16

tunname=lightway
tun_local_ip=10.128.0.42

echo ""
echo "====================================================================="
echo "Setup Server TUN device $tunname $tun_local_ip"
echo "====================================================================="

ip tuntap add mode tun dev "${tunname}"
ip link set dev "${tunname}" mtu 1350
# Cap GSO superpacket intake. The default 65536 plus Lightway + TLS/expresslane
# headers per segment can exceed what sendmsg(UDP_SEGMENT) accepts, causing the
# kernel to return EMSGSIZE ("Message too long") on the outside socket.
ip link set dev "${tunname}" gso_max_size 60300
ip link set dev "${tunname}" up
ip addr replace "${tun_local_ip}" dev "${tunname}"

ip route add "${server_ip_pool}" dev "${tunname}"

ip addr show
echo ""
ip route show

# Find our backend network info
backend_ip=$(ip -j route show 10.0.0.0/16 | jq -r .[0].prefsrc)
backend_dev=$(ip -j route show 10.0.0.0/16 | jq -r .[0].dev)

echo ""
echo "====================================================================="
echo "Setup SNAT for ${backend_dev} addresses ${server_ip_pool} using ${backend_ip}"
echo "====================================================================="

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -s "${server_ip_pool}" -o "${backend_dev}" -p all -j SNAT --to "${backend_ip}"

echo "iptables:"
iptables -n -L
echo ""
echo "iptables (nat):"
iptables -n -L -t nat

echo ""
echo "====================================================================="
echo "Start lightway-server: --ip-pool ${server_ip_pool} $*"
echo "====================================================================="

exec ./lightway-server --ip-pool ${server_ip_pool} --tun-ip ${tun_local_ip} "$@"
