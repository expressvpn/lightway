#!/bin/bash

set -euo pipefail

expected_server_ip=$(dig +short A "$1" | head -1)
connected_server_ip=$(ip --json route | jq -r '.[] | select((.dev == "eth0" and .protocol == "static")) | .dst')

if [ "$connected_server_ip" != "$expected_server_ip" ]; then
    echo "Server IP is incorrect: ${connected_server_ip}, expected: ${expected_server_ip} ($1)"
    exit 1
fi

echo "Server IP is correct: ${connected_server_ip}"
exit 0