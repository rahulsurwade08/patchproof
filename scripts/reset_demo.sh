#!/usr/bin/env bash
# Reset all demo state between runs.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose -f infra/docker-compose.yml down -v 2>/dev/null || true
rm -f /tmp/patchproof_pwned
rm -f scenarios/*/verdict.json scenarios/*/state.json
rm -rf data/inbox
mkdir -p data/inbox

echo "demo state reset"
