#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "=== Building rustacme ==="
docker build -t rustacme:local .
echo "=== Starting ==="
RUSTACME_IMAGE=rustacme:local docker compose up -d
echo "=== Done. Check logs: docker logs rustacme ==="
