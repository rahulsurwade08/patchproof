#!/bin/bash
# Subagent test gate: runs pytest for scenario app and writes gate JSON
SCENARIO=${1:-s01-pyyaml-rce}
SCENARIO_DIR="scenarios/$SCENARIO/app"
GATE_FILE="scenarios/$SCENARIO/test_gate.json"

if [ ! -d "$SCENARIO_DIR" ]; then
  echo '{"scenario":"'$SCENARIO'","pass":false,"exit_code":1,"summary":"scenario dir missing"}' > "$GATE_FILE"
  exit 1
fi

# Build scenario image first (as per build-then-run workflow)
echo "Building scenario image..."
docker build --no-cache -t patchproof-test-$SCENARIO $SCENARIO_DIR > /dev/null 2>&1 || {
  echo '{"scenario":"'$SCENARIO'","pass":false,"exit_code":3,"summary":"image build failed"}' > "$GATE_FILE"
  exit 3
}

# Run tests inside the scenario container
RESULT=$(docker run --rm --network none patchproof-test-$SCENARIO python -m pytest test_main.py -q 2>&1)
CODE=$?

if [ $CODE -eq 0 ]; then
  echo '{"scenario":"'$SCENARIO'","pass":true,"exit_code":0,"summary":"tests pass"}' > "$GATE_FILE"
else
  echo '{"scenario":"'$SCENARIO'","pass":false,"exit_code":'$CODE'","summary":"tests failed"}' > "$GATE_FILE"
fi
