# Flox Runbook for Lightway

## Prerequisites
- Flox installed
- Nix with flakes enabled (for building)
- Linux system for full testing (network namespaces)

## Quick Start

### 1. Activate Flox Environment
```bash
flox activate
2. Build the Project
# On any platform (uses Nix flake)
./dev.sh build

# Or directly:
nix develop .#lightway-server --extra-experimental-features 'nix-command flakes' -c bash -c "cargo build --release"
mkdir -p artifacts
cp target/release/lightway-{server,client} artifacts/
3. Run Components
# Server
./artifacts/lightway-server --config-file ./tests/server/server_config.yaml

# Client (new terminal)
./artifacts/lightway-client --config-file ./tests/client/client_config.yaml
Platform-Specific Notes
macOS
	•	Building works via Nix flake
	•	Network namespace tests not supported
	•	Binaries built here work on Linux
Linux
	•	Full functionality including network tests
	•	Run E2E tests: sudo ./dev.sh test
	•	Network namespaces: .flox/scripts/setup-namespaces.sh
Key Commands
	•	./dev.sh build - Build all components
	•	./dev.sh test - Run tests (Linux only)
	•	./dev.sh server - Start server
	•	./dev.sh client - Start client
	•	./dev.sh clean - Clean artifacts
Migration from Earthly/Docker
This Flox setup replaces:
	•	Earthly build commands → ./dev.sh build
	•	Docker Compose tests → ./dev.sh test
	•	Container dependencies → Flox manifest
Troubleshooting
	•	Certificate errors in tests: Expected (test certs expired)
	•	Build fails on macOS: Use the Nix develop command shown above
	•	Network tests fail: Requires Linux with sudo access


