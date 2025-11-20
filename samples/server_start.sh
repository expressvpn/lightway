#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat << EOF
Usage: $(basename "$0") [CONFIG_FILE] [OPTIONS...]
Starts Lightway VPN server (default config: server_config.yaml)
Additional OPTIONS are passed directly to lightway-server
EOF
    exit 1
}

check_dependencies() {
    local missing_cmds=()
    local missing_pkgs=()
    local config_file="$1"

    # Map commands to their package names
    declare -A cmd_to_pkg=(
        ["yq"]="yq"
        ["jq"]="jq"
        ["ip"]="iproute2"
        ["iptables"]="iptables"
        ["sysctl"]="procps"
        ["pgrep"]="procps"
    )

    for cmd in yq jq ip iptables sysctl pgrep; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_cmds+=("$cmd")
            missing_pkgs+=("${cmd_to_pkg[$cmd]}")
        fi
    done

    if [[ ! -f "$config_file" ]]; then
        echo "Error: Configuration file '$config_file' not found" >&2
        exit 1
    fi

    if [[ ! -f "./lightway-server" ]]; then
        echo "Error: lightway-server binary not found in current directory" >&2
        exit 1
    fi

    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        # Remove duplicates from package list
        local unique_pkgs=($(printf '%s\n' "${missing_pkgs[@]}" | sort -u))

        echo "Error: Missing commands: ${missing_cmds[*]}" >&2
        echo "Install with: sudo apt-get install ${unique_pkgs[*]} (or yum/dnf on RHEL)" >&2
        echo "Note: yq must be installed from https://github.com/mikefarah/yq" >&2
        exit 1
    fi
}

case "${1:-}" in
    -h|--help)
        usage
        ;;
    "")
        VPN_SERVER_CONFIG="server_config.yaml"
        EXTRA_ARGS=()
        ;;
    *)
        VPN_SERVER_CONFIG="$1"
        shift
        EXTRA_ARGS=("$@")
        ;;
esac

check_dependencies "$VPN_SERVER_CONFIG"

set -x

tun_intf=$(yq -r '.tun_name' "${VPN_SERVER_CONFIG}")
tun_ip=$(yq -r '.tun_ip' "${VPN_SERVER_CONFIG}")
tun_ip_subnet=$(yq -r '.ip_pool' "${VPN_SERVER_CONFIG}")

wandev=$(ip --json route get 8.8.8.8 | jq '.[0].dev' -r)
basenet=$(ip --json add show "${wandev}" | jq '.[0].addr_info[0].local' -r)
gateway=$(ip --json route get 8.8.8.8 | jq '.[0].gateway' -r)

echo "FOUND DEV AND IP ${wandev} ${basenet}"
echo "FOUND GATEWAY: ${gateway}"

function cleanup() {
    echo "Cleaning up tunnel interface"
    iptables -t nat -D POSTROUTING -s "${tun_ip_subnet}" -o "${wandev}" -j SNAT --to "${basenet}"
    ip tuntap del mode tun dev "${tun_intf}"
}
trap cleanup INT TERM

function tunnel_configure() {
  set +x
  sleep 2
  pgrep -fla lightway-server || exit 0
  echo "Assigning IP address after 5 seconds"
  ip link set dev "${tun_intf}" up
  ip addr replace "${tun_ip}" dev "${tun_intf}"
  ip route replace "${tun_ip_subnet}" dev "${tun_intf}"
}

echo "Adding tun interface"
ip tuntap del mode tun dev "${tun_intf}"
ip tuntap add mode tun dev "${tun_intf}"
ip link set dev "${tun_intf}" qlen 10000
ip link set dev "${tun_intf}" mtu 1350

tunnel_configure &

echo "Adding iptable SNAT rule"
sysctl -w net.ipv4.ip_forward=1

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -s "${tun_ip_subnet}" -o "${wandev}" -j SNAT --to "${basenet}"

./lightway-server -c "${VPN_SERVER_CONFIG}" "${EXTRA_ARGS[@]}"

