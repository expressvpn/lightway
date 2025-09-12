# Lightway Flox Migration

This repository has been migrated from Earthly/Docker to Flox for better reproducibility and simpler workflows.

## Quick Start

### Building
```bash
./dev.sh build
Running Tests (Linux only)
./dev.sh test
Development
# Terminal 1
./dev.sh server

# Terminal 2
./dev.sh client
Migration from Earthly
Old Command
New Command
earthly +build
./dev.sh build
earthly +test
./dev.sh test
docker-compose up
./dev.sh test
Platform Notes
	•	Linux: Full functionality including network namespace tests
	•	macOS: Build only; tests require Linux VM or container
Directory Structure
.flox/
├── scripts/
│   ├── build.sh           # Build script
│   ├── run-tests.sh       # E2E test runner
│   ├── setup-namespaces.sh # Network setup
│   └── dev.sh             # Developer helper
└── manifest.toml          # Flox environment definition
