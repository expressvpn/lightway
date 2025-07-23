#!/bin/sh

set -eu

echo "Configuring client container networking"

echo ""
echo "====================================================================="
echo "Ping server"
echo "====================================================================="

config_file=$(echo "$@" | grep -oP '(?<=--config-file )\S+')
echo "Using config file: $config_file"
# Take the first entry of `servers` or the top-level `server` field
server=$(grep -m1 'server: ' "$config_file" | sed -E 's/^[- ]*server: *(.+):.+$/\1/')
echo "Server found: $server"
ping -W 1 -c 3 "$server"

echo ""
echo "====================================================================="
echo "Start lightway-client: $*"
echo "====================================================================="

exec ./lightway-client "$@"
