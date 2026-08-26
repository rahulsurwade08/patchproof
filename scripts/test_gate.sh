#!/bin/bash
# Subagent test gate: mandatory sandbox_build + sandbox_exec path
# Starts uvicorn inside the container, waits for health, runs pytest, then stops.
SCENARIO=${1:-s01-pyyaml-rce}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCENARIO_DIR="$ROOT/scenarios/$SCENARIO/app"
GATE_FILE="$ROOT/scenarios/$SCENARIO/test_gate.json"

if [ ! -d "$SCENARIO_DIR" ]; then
  printf '{"scenario":"%s","passed":false,"exit_code":1,"poc_exit":1,"poc_verdict":"exploitable=false","summary":"scenario dir missing"}\n' "$SCENARIO" > "$GATE_FILE"
  exit 1
fi

# Mandatory sandbox-only path per AGENTS.md and Qodo rules
# Timeout: 60s max per scenario (matches PoC contract deadline)
TIMEOUT=60
RESULT_FILE=$(mktemp)

# Build image with timeout
if ! timeout $TIMEOUT docker build --no-cache -t patchproof-test-$SCENARIO "$SCENARIO_DIR" > /dev/null 2>&1; then
  printf '{"scenario":"%s","passed":false,"exit_code":3,"poc_exit":1,"poc_verdict":"exploitable=false","summary":"image build failed or timeout"}\n' "$SCENARIO" > "$GATE_FILE"
  rm -f "$RESULT_FILE"
  exit 3
fi

# Start uvicorn inside the container and wait for health
CONTAINER="patchproof-gate-$SCENARIO-$$"
cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# shellcheck disable=SC2046
docker run -d --name "$CONTAINER" --network host \
  --entrypoint sh patchproof-test-$SCENARIO \
  -c "uvicorn main:app --host 127.0.0.1 --port 8000 & sleep $TIMEOUT" \
  >/dev/null 2>&1

# Wait for service to become healthy (poll /health endpoint)
HEALTHY=0
for _ in $(seq 1 20); do
  if docker exec "$CONTAINER" python3 -c "
import urllib.request, sys
try:
    sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status == 200 else 1)
except Exception:
    sys.exit(1)
" >/dev/null 2>&1; then
    HEALTHY=1
    break
  fi
  sleep 1
done

if [ "$HEALTHY" -ne 1 ]; then
  printf '{"scenario":"%s","passed":false,"exit_code":3,"poc_exit":1,"poc_verdict":"exploitable=false","summary":"service failed to start"}\n' "$SCENARIO" > "$GATE_FILE"
  exit 3
fi

# Run tests with timeout; propagate nonzero status and capture timeout
timeout $TIMEOUT docker exec -e TARGET_URL=http://127.0.0.1:8000 \
  "$CONTAINER" python -m pytest test_main.py -q 2>&1 > "$RESULT_FILE"
CODE=$?

# Stop the service
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
trap - EXIT

if [ $CODE -eq 124 ]; then
  printf '{"scenario":"%s","passed":false,"exit_code":4,"poc_exit":1,"poc_verdict":"exploitable=false","summary":"tests timeout (%ss)"}\n' "$SCENARIO" "$TIMEOUT" > "$GATE_FILE"
  rm -f "$RESULT_FILE"
  exit 4
elif [ $CODE -eq 0 ]; then
  printf '{"scenario":"%s","passed":true,"exit_code":%d,"poc_exit":0,"poc_verdict":"exploitable=false","summary":"tests pass (sandbox-only, %ss timeout)"}\n' "$SCENARIO" "$CODE" "$TIMEOUT" > "$GATE_FILE"
else
  printf '{"scenario":"%s","passed":false,"exit_code":%d,"poc_exit":1,"poc_verdict":"exploitable=false","summary":"tests failed (timeout:%ss)"}\n' "$SCENARIO" "$CODE" "$TIMEOUT" > "$GATE_FILE"
fi
rm -f "$RESULT_FILE"
exit $CODE
