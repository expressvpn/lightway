#!/bin/sh

set -eu

echo "Configuring client container networking"

echo ""
echo "====================================================================="
echo "Ping server"
echo "====================================================================="
ping -W 1 -c 3 "${SERVER_ADDR}"

echo ""
echo "====================================================================="
echo "Start lightway-client: $*"
echo "====================================================================="

exec ./lightway-client "$@"
