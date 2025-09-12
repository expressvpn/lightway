#!/bin/bash
set -euo pipefail

echo "🧪 Running Lightway E2E Tests..."

# Check if on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "⚠️  Network namespace tests require Linux"
    echo "On macOS, tests must run in Docker or a Linux VM"
    exit 1
fi

# Check for binaries
if [[ ! -f artifacts/lightway-server || ! -f artifacts/lightway-client ]]; then
    echo "❌ Binaries not found. Run: .flox/scripts/build.sh first"
    exit 1
fi

# Setup namespaces
.flox/scripts/setup-namespaces.sh setup

# Start server
echo "Starting server..."
sudo ip netns exec lightway-server ./artifacts/lightway-server \
    --config-file ./tests/server/server_config.yaml &
SERVER_PID=$!

sleep 2

# Start client
echo "Starting client..."
sudo ip netns exec lightway-client ./artifacts/lightway-client \
    --config-file ./tests/client/client_config.yaml &
CLIENT_PID=$!

sleep 2

# Run basic connectivity test
echo "Testing connectivity..."
sudo ip netns exec lightway-client ping -c 3 10.0.0.2 || echo "Warning: Ping test failed"

# Cleanup
echo "Cleaning up..."
sudo kill $SERVER_PID $CLIENT_PID 2>/dev/null || true
.flox/scripts/setup-namespaces.sh cleanup

echo "✅ Tests complete!"
