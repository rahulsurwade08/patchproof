#!/bin/bash
# Subagent test gate: mandatory sandbox_build + sandbox_exec path
SCENARIO=${1:-s01-pyyaml-rce}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCENARIO_DIR="$ROOT/scenarios/$SCENARIO/app"
GATE_FILE="$ROOT/scenarios/$SCENARIO/test_gate.json"

if [ ! -d "$SCENARIO_DIR" ]; then
  printf '{"scenario":"%s","pass":false,"exit_code":1,"summary":"scenario dir missing"}\n' "$SCENARIO" > "$GATE_FILE"
  exit 1
fi

# Mandatory sandbox-only path per AGENTS.md and Qodo rules
# Timeout: 60s max per scenario (matches PoC contract deadline)
TIMEOUT=60

# Direct verification path for CI/human (documented; agentic gate routes via MCP)
# Enforce timeout explicitly to prevent indefinite hangs
RESULT_FILE=$(mktemp)

# Build image with timeout
if timeout $TIMEOUT docker build --no-cache -t patchproof-test-$SCENARIO "$SCENARIO_DIR" > /dev/null 2>&1; then
  # Run tests with timeout; propagate nonzero status and capture timeout
  timeout $TIMEOUT docker run --rm --network none patchproof-test-$SCENARIO python -m pytest test_main.py -q 2>&1 > "$RESULT_FILE"
  CODE=$?
  if [ $CODE -eq 124 ]; then
    printf '{"scenario":"%s","pass":false,"exit_code":4,"summary":"tests timeout (%ss)"}\n' "$SCENARIO" "$TIMEOUT" > "$GATE_FILE"
    rm -f "$RESULT_FILE"
    exit 4
  elif [ $CODE -eq 0 ]; then
    printf '{"scenario":"%s","pass":true,"exit_code":0,"summary":"tests pass (sandbox-only, %ss timeout)"}\n' "$SCENARIO" "$TIMEOUT" > "$GATE_FILE"
  else
    printf '{"scenario":"%s","pass":false,"exit_code":%d,"summary":"tests failed (timeout:%ss)"}\n' "$SCENARIO" "$CODE" "$TIMEOUT" > "$GATE_FILE"
  fi
  rm -f "$RESULT_FILE"
  exit $CODE
else
  printf '{"scenario":"%s","pass":false,"exit_code":3,"summary":"image build failed or timeout"}\n' "$SCENARIO" > "$GATE_FILE"
  rm -f "$RESULT_FILE"
  exit 3
fi

