#!/usr/bin/env bash
# Keyless sandbox: run one scenario's PoC against its service inside a single
# disposable Docker container — no cloud accounts, no API keys.
#
# The service and the PoC share the container (satisfying the shared-/tmp
# contract), and the container runs with --network none so the exploit is
# fully isolated: it can only reach the service on 127.0.0.1 inside itself.
#
# Usage: scripts/run_poc_local.sh <scenario-id>
#   e.g. scripts/run_poc_local.sh s01-pyyaml-rce
set -euo pipefail

SCENARIO=${1:?usage: run_poc_local.sh <scenario-id>}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT/scenarios/$SCENARIO/app"
IMAGE="patchproof-$SCENARIO"
# Unique per-invocation container so concurrent runs can't clobber each other.
CONTAINER="patchproof-$SCENARIO-poc-$$"

# Exit codes: 0 exploitable · 1 not affected · 2 usage/setup · 3 service
# failed to start · 4 PoC timed out (>60s). Never let infra failures look
# like NOT_AFFECTED verdicts.

[ -d "$APP_DIR" ] || { echo "unknown scenario: $SCENARIO" >&2; exit 2; }

# Resolve the PoC script from the scenario contract (s05 reuses s01's).
POC_REL=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['poc_contract']['script'])" "$ROOT/scenarios/$SCENARIO/cve-meta.json")
POC_PATH="$ROOT/scenarios/$SCENARIO/$POC_REL"
[ -f "$POC_PATH" ] || { echo "PoC not found: $POC_PATH" >&2; exit 2; }

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker build -q -t "$IMAGE" "$APP_DIR" >/dev/null
docker run --rm -d --name "$CONTAINER" --network none \
  --entrypoint sh "$IMAGE" -c "uvicorn main:app --host 127.0.0.1 --port 8000 & sleep infinity" \
  >/dev/null

echo "waiting for service..."
healthy=0
for _ in $(seq 1 30); do
  if docker exec "$CONTAINER" python3 -c "
import urllib.request, sys
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status == 200 else 1)
" >/dev/null 2>&1; then healthy=1; break; fi
  sleep 1
done
if [ "$healthy" -ne 1 ]; then
  echo "service failed to start — not a verdict (infra failure)" >&2
  docker logs "$CONTAINER" >&2 || true
  exit 3
fi

docker cp "$POC_PATH" "$CONTAINER":/srv/poc.py >/dev/null

echo "running PoC inside isolated container (60s deadline)..."
if timeout 60 docker exec -w /srv "$CONTAINER" python3 poc.py; then
  poc_exit=0
else
  poc_exit=$?
fi
if [ "$poc_exit" -eq 124 ]; then
  echo "PoC exceeded the 60s deadline — not a verdict" >&2
  poc_exit=4
fi

docker cp "$CONTAINER":/srv/verdict.json "$ROOT/scenarios/$SCENARIO/verdict.json" 2>/dev/null || true

echo "--- verdict.json ---"
cat "$ROOT/scenarios/$SCENARIO/verdict.json" 2>/dev/null || echo "(not written)"

echo "PoC exit code: $poc_exit (0 = exploitable, 1 = not affected)"
exit "$poc_exit"
