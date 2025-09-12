#!/bin/bash

case "${1:-help}" in
    build)
        ./.flox/scripts/build.sh
        ;;
    test)
        ./.flox/scripts/run-tests.sh
        ;;
    server)
        ./artifacts/lightway-server --config-file ./tests/server/server_config.yaml
        ;;
    client)
        ./artifacts/lightway-client --config-file ./tests/client/client_config.yaml
        ;;
    clean)
        cargo clean
        rm -rf artifacts/
        ;;
    help)
        cat <<HELP
Lightway Development Commands:
  ./dev.sh build   - Build all components
  ./dev.sh test    - Run E2E tests (Linux only)
  ./dev.sh server  - Start development server
  ./dev.sh client  - Start development client
  ./dev.sh clean   - Clean build artifacts
HELP
        ;;
esac
