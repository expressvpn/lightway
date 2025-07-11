#!/bin/sh

set -eu

echo "Configuring client container networking"

echo ""
echo "====================================================================="
echo "Ping server"
echo "====================================================================="
ping -W 1 -c 3 server

server=$(dig +short server)

# Add server argument using resolved IP and SERVER_PORT env var
if [ -n "${SERVER_PORT:-}" ]; then
    server_arg="--server=$server:$SERVER_PORT"
    echo "Using server address: $server:$SERVER_PORT"
else
    server_arg=""
    echo "No SERVER_PORT set, using arguments from command line"
fi

echo ""
echo "====================================================================="
echo "Start lightway-client: $* $server_arg"
echo "====================================================================="

exec ./lightway-client "$@" "$server_arg"
