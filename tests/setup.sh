#!/usr/bin/env bash

shopt -s nullglob

# Set EXTRA_CLIENTS envvar to a positive integer N to create up to
# `lightway-client#` namespaces [1,N]. Do not set to larger than 16,383.
: "${EXTRA_CLIENTS:=0}"

if [ "$EUID" -ne 0 ]
  then echo "Please run this script with sudo"
  exit
fi

setup_ns() {
    ns=$1
    tunname=$2
    local_ip=$3
    peer_ip=$4
    network=$5

    # Create namespace
    ip netns add "${ns}"
    ip netns exec "${ns}" ip link set lo up
    mkdir /etc/netns/"${ns}" -p

    ip netns exec "${ns}" sysctl -q net.ipv4.conf.all.arp_ignore=0
    ip netns exec "${ns}" sysctl -q net.ipv4.conf.all.arp_announce=0

    # Setup TUN interface
    if [[ -n $tunname ]]; then
        ip netns exec "${ns}" ip tuntap add mode tun dev "${tunname}"
        ip netns exec "${ns}" ip link set dev "${tunname}" mtu 1350
        ip netns exec "${ns}" ip link set dev "${tunname}" up

        if [[ -n $peer_ip ]]; then
            ip netns exec "${ns}" ip addr replace "${local_ip}" peer "${peer_ip}" dev "${tunname}"
        else
            ip netns exec "${ns}" ip addr replace "${local_ip}" dev "${tunname}"
        fi
        if [[ -n $network ]]; then
            if [[ -n $peer_ip ]]; then
                ip netns exec "${ns}" ip route replace "${network}" via "${local_ip}" dev "${tunname}"
            else
                ip netns exec "${ns}" ip route replace "${network}" dev "${tunname}"
            fi
        fi
    fi
}

delete_ns() {
    ns=$1
    rm -rf /etc/netns/"${ns}"
    ip netns del "${ns}"
}

setup_ip_snat() {
    ns=$1
    subnet=$2
    dev=$3
    basenet=$4

    ip netns exec "${ns}" iptables -P INPUT ACCEPT
    ip netns exec "${ns}" iptables -P OUTPUT ACCEPT
    ip netns exec "${ns}" iptables -P FORWARD ACCEPT
    ip netns exec "${ns}" iptables -t nat -A POSTROUTING -s "${subnet}" -o "${dev}" -j SNAT --to "${basenet}"
}

setup_ip_forward() {
    ns=$1
    value=$2

    ip netns exec "${ns}" sysctl -q net.ipv4.ip_forward="$value"
}

setup_bridge_interface() {
    intf_name=$1
    ns1=$2
    ip1=$3
    ns2=$4
    ip2=$5

    ip link add "${intf_name}" netns "${ns1}" type veth peer "${intf_name}" netns "${ns2}"

    ip netns exec "${ns1}" ip addr add "${ip1}" dev "${intf_name}"
    ip netns exec "${ns1}" ip link set "${intf_name}" up
    ip netns exec "${ns2}" ip addr add "${ip2}" dev "${intf_name}"
    ip netns exec "${ns2}" ip link set "${intf_name}" up
}

setup_client() {
    ns=$1
    serverip=$2
    ip netns exec "${ns}" sysctl -q net.ipv4.conf.all.promote_secondaries=1
    touch /etc/netns/"${ns}"/hosts
    echo '127.0.0.1   localhost' | tee -a /etc/netns/"${ns}"/hosts > /dev/null
    echo "$serverip   server" | tee -a /etc/netns/"${ns}"/hosts > /dev/null
    echo '8.8.8.8     google.com' | tee -a /etc/netns/"${ns}"/hosts > /dev/null
}

# Networks used:
#
# Physical Multihop (default `lightway-client` namespace):
#
# remote <--169.254.99.0/24--> 10.125.0.0/16 <--ip pool--> server <--172.16.0.0/12--> middle <--192.168.0.0/24--> client
#
# Physical Single hop (extra `lightway-client${N}` namespaces, with x=${N}/64 and y=4*${N}%64):
#
# remote <--169.254.99.0/24--> 10.125.0.0/16 <--ip pool--> server <----------------192.168.x.y/24---------------> client${N}
#
# Lightway Tunnel:
#
#                                                          server <-----------------100.64.0.5/31---------------> client${N}
create_setup() {
    # Setup lightway-server
    setup_ns lightway-server lightway 10.125.0.1 '' 10.125.0.0/16
    setup_ip_forward lightway-server 1

    # Setup lightway-middle and create bridge interface to server
    setup_ns lightway-middle
    setup_bridge_interface veth-s2m lightway-server 172.16.0.1/12 lightway-middle 172.16.0.2/12
    setup_ip_forward lightway-middle 1
    ip netns exec lightway-server ip route add 192.168.0.0/16 via 172.16.0.2

    # Setup lightway-client and create bridge interface to middle
    setup_ns lightway-client '' 100.64.0.6 100.64.0.5
    setup_bridge_interface veth-c2m lightway-middle 192.168.0.1/30 lightway-client 192.168.0.2/30
    ip netns exec lightway-client ip route add 172.16.0.0/12 via 192.168.0.1
    setup_client lightway-client 172.16.0.1
    setup_ip_forward lightway-client 0

    # Setup additional lightway-client# and create bridge interface to server
    for n in $(seq 1 "${EXTRA_CLIENTS}") ; do
        x=$(( n / 64 ))
        y=$(( n % 64 << 2 )) # + 0 == network address, +1 == server, + 2 == client, + 3 = broadcast address
        server_ip="192.168.${x}.$(( y + 1 ))"
        client_ip="192.168.${x}.$(( y + 2 ))"
        echo "Addl client :${n} ip: ${client_ip} server_ip: ${server_ip}"
        setup_ns "lightway-client${n}" '' 100.64.0.6 100.64.0.5
        setup_bridge_interface "veth${n}" lightway-server "${server_ip}/30" "lightway-client${n}" "${client_ip}/30"
        setup_client "lightway-client${n}" "${server_ip}"
        setup_ip_forward "lightway-client${n}" 0
    done

    # Setup lightway-remote namespace and set 8.8.8.8 to loopback in remote device
    setup_ns lightway-remote
    ip netns exec lightway-remote ip addr add 8.8.8.8/24 dev lo
    setup_ip_forward lightway-remote 0

    # Create bridge eth interface between server and remote
    setup_bridge_interface wan lightway-server 169.254.99.1/24 lightway-remote 169.254.99.2/24

    # Setup forwarding rules in lightway-server
    ip netns exec lightway-server ip route add 8.8.8.8/32 via 169.254.99.1
    setup_ip_snat lightway-server 10.125.0.0/16 wan 169.254.99.1
}

delete_setup() {
    # Delete namespace along with all tun interfaces
    delete_ns lightway-server
    delete_ns lightway-middle
    for ns in /run/netns/lightway-client* ; do
        delete_ns "${ns#/run/netns/}"
    done
    delete_ns lightway-remote
}


COMMAND="${1:-setup}"
case "${COMMAND}" in
    delete)
        echo "Deleting setup..."
        delete_setup
        ;;
    setup)
        echo "Creating setup..."
        create_setup
        ;;
    *)
        echo "Unknown command: $COMMAND"
        echo "Valid commands: setup (default), delete"
        exit 1
        ;;
esac
