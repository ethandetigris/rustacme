#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "=== Building rustacme ==="
docker build --build-arg CARGO_CONFIG="${RUSTACME_CARGO_CONFIG:-.cargo/config.toml}" -t rustacme:local .
echo "=== Starting ==="
RUSTACME_IMAGE=rustacme:local docker compose up -d
echo "=== Done. Check logs: docker logs rustacme ==="
