#!/bin/bash
set -euo pipefail

echo "🔨 Building Lightway components..."

# Use nix develop to build
nix develop .#lightway-server --extra-experimental-features 'nix-command flakes' -c bash -c "cargo build --release"

# Create artifacts
mkdir -p artifacts
cp target/release/lightway-server artifacts/
cp target/release/lightway-client artifacts/

echo "✅ Build complete! Binaries in ./artifacts/"
