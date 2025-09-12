#!/bin/bash
set -euo pipefail

# This replaces tests/setup.sh with a Flox-native approach
# Note: Requires sudo/root privileges on Linux

ACTION="${1:-setup}"

setup_namespaces() {
    echo "🌐 Setting up Lightway test network namespaces..."
    
    # Create namespaces
    for ns in lightway-server lightway-middle lightway-client lightway-remote; do
        sudo ip netns add "$ns" 2>/dev/null || echo "Namespace $ns already exists"
        sudo ip netns exec "$ns" ip link set lo up
    done
    
    # Create veth pairs
    # Client <-> Middle
    sudo ip link add veth-c2m type veth peer name veth-m2c 2>/dev/null || true
    sudo ip link set veth-c2m netns lightway-client
    sudo ip link set veth-m2c netns lightway-middle
    
    sudo ip netns exec lightway-client ip addr add 192.168.0.2/24 dev veth-c2m
    sudo ip netns exec lightway-client ip link set veth-c2m up
    sudo ip netns exec lightway-middle ip addr add 192.168.0.1/24 dev veth-m2c
    sudo ip netns exec lightway-middle ip link set veth-m2c up
    
    # Middle <-> Server
    sudo ip link add veth-m2s type veth peer name veth-s2m 2>/dev/null || true
    sudo ip link set veth-m2s netns lightway-middle
    sudo ip link set veth-s2m netns lightway-server
    
    sudo ip netns exec lightway-middle ip addr add 10.0.0.1/24 dev veth-m2s
    sudo ip netns exec lightway-middle ip link set veth-m2s up
    sudo ip netns exec lightway-server ip addr add 10.0.0.2/24 dev veth-s2m
    sudo ip netns exec lightway-server ip link set veth-s2m up
    
    # Enable routing
    sudo ip netns exec lightway-middle sysctl -w net.ipv4.ip_forward=1
    
    echo "✅ Network namespaces ready!"
}

cleanup_namespaces() {
    echo "🧹 Cleaning up namespaces..."
    for ns in lightway-server lightway-middle lightway-client lightway-remote; do
        sudo ip netns del "$ns" 2>/dev/null || true
    done
}

case "$ACTION" in
    setup)
        setup_namespaces
        ;;
    cleanup|delete)
        cleanup_namespaces
        ;;
    *)
        echo "Usage: $0 [setup|cleanup]"
        exit 1
        ;;
esac
