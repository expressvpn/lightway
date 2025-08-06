#!/bin/bash

set -euo pipefail


docker compose exec client ./check-server.sh "$1"

docker compose exec client ./run-test-inside.sh
