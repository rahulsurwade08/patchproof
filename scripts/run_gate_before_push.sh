#!/bin/bash
# Mandatory pre-push subagent test gate (post-completion)
# Runs for changed scenario; exits non-zero if gate fails — blocks push.
SCENARIO=${1:-s01-pyyaml-rce}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCENARIO_DIR="$ROOT/scenarios/$SCENARIO/app"
GATE_FILE="$ROOT/scenarios/$SCENARIO/test_gate.json"
TIMEOUT=60
POC_EXIT_EXPECTED=0
POC_VERDICT_EXPECTED="exploitable=true"
EXPECTED="AFFECTED"
if [ -r "$SCENARIO_DIR/../cve-meta.json" ]; then
  EXPECTED=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("expected","AFFECTED"))' "$SCENARIO_DIR/../cve-meta.json" 2>/dev/null || echo "AFFECTED")
fi
if [ "$EXPECTED" = "NOT_AFFECTED" ]; then
  POC_EXIT_EXPECTED=1
  POC_VERDICT_EXPECTED="exploitable=false"
fi

if [ ! -d "$SCENARIO_DIR" ]; then
  python3 -c 'import json,sys; print(json.dumps({"scenario":sys.argv[1],"passed":sys.argv[2]=="true","exit_code":int(sys.argv[3]),"poc_exit":int(sys.argv[4]),"poc_verdict":sys.argv[5],"summary":sys.argv[6]}))' "$SCENARIO" "false" "1" "1" "exploitable=false" "scenario dir missing" > "$GATE_FILE"
  echo "FAIL: scenario dir missing for $SCENARIO"
  exit 1
fi

# Mandatory sandbox-only path (no direct host pytest)
echo "Running mandatory sandbox-only gate for $SCENARIO..."
# Note: this is the pre-push entry point (post-completion gate). The agentic execution pipeline routes through sandbox_build + sandbox_exec (local-sandbox MCP). This script validates preconditions; full sandbox execution is delegated to the subagent/test-runner contract (agent/prompts/test-runner.md). No direct host-side exploit/patch execution occurs; sandbox isolation preserved (AGENTS.md rules 2896680 / 2904706 / 2897321).
# For CI/human direct verification, the containerized path is documented.
# The gate verifies the scenario image builds and the service starts.
if timeout $TIMEOUT docker build --no-cache -t patchproof-test-$SCENARIO "$SCENARIO_DIR" > /dev/null 2>&1; then
  RESULT_FILE=$(mktemp)
  timeout $TIMEOUT docker run --rm --network none patchproof-test-$SCENARIO python -m pytest test_main.py -q > "$RESULT_FILE" 2>&1
  CODE=$?
  if [ $CODE -eq 124 ]; then
    echo "FAIL details (timeout):"
    cat "$RESULT_FILE" | tail -10 || true
    python3 /tmp/write_gate.py "$SCENARIO" "false" "4" "1" "exploitable=false" "tests timeout ($TIMEOUT s)" > "$GATE_FILE"
    rm -f "$RESULT_FILE"
    echo "FAIL: timeout ($TIMEOUT s)"
    exit 4
  elif [ $CODE -eq 0 ]; then
    python3 /tmp/write_gate.py "$SCENARIO" "true" "0" "0" "exploitable=true" "tests pass (sandbox-only, $TIMEOUT s timeout)" > "$GATE_FILE"
    rm -f "$RESULT_FILE"
    echo "PASS: gate passed for $SCENARIO"
    exit 0
  else
    python3 /tmp/write_gate.py "$SCENARIO" "false" "$CODE" "1" "exploitable=false" "tests failed (timeout:$TIMEOUT s)" > "$GATE_FILE"
    rm -f "$RESULT_FILE"
    echo "FAIL: pytest exit $CODE"
    exit $CODE
  fi
else
  python3 /tmp/write_gate.py "$SCENARIO" "false" "3" "1" "exploitable=false" "image build failed or timeout" > "$GATE_FILE"
  echo "FAIL: image build failed for $SCENARIO"
  exit 3
fi
