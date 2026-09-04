#!/usr/bin/env bash
# Reset all run state.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -f /tmp/ce_pwned
rm -rf data/inbox
mkdir -p data/inbox
rm -rf data/output

echo "state reset"
