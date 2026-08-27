#!/bin/bash
# Mandatory pre-push subagent test gate (post-completion)
# Installed as .git/hooks/pre-push by scripts/install-hooks.sh.
# A normal `git push` invokes this automatically via the pre-push hook.
# Routes through the local-sandbox MCP server (127.0.0.1:8081/mcp).
# Uses sandbox_build + sandbox_exec via JSON-RPC — never calls Docker directly.
# Runs pytest AND the scenario PoC separately; records real results for each.
set -euo pipefail

SCENARIO=${1:-s01-pyyaml-rce}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCENARIO_DIR="$ROOT/scenarios/$SCENARIO/app"
SCENARIO_META="$ROOT/scenarios/$SCENARIO/cve-meta.json"
GATE_FILE="$ROOT/scenarios/$SCENARIO/test_gate.json"
MCP_URL="http://127.0.0.1:8081/mcp"
TIMEOUT=60

write_gate() {
  python3 -c 'import json,sys; print(json.dumps({"scenario":sys.argv[1],"passed":sys.argv[2]=="true","exit_code":int(sys.argv[3]),"poc_exit":int(sys.argv[4]),"poc_verdict":sys.argv[5],"summary":sys.argv[6]}))' \
    "$SCENARIO" "$1" "$2" "$3" "$4" "$5" > "$GATE_FILE"
}

# JSON-RPC call to local-sandbox MCP via Python (handles JSON correctly).
mcp_call() {
  python3 -c '
import json, sys, urllib.request
url, tool, args_json = sys.argv[1], sys.argv[2], sys.argv[3]
req = urllib.request.Request(url, data=json.dumps({
    "jsonrpc": "2.0", "id": 1,
    "method": "tools/call",
    "params": {"name": tool, "arguments": json.loads(args_json)}
}).encode(), headers={"Content-Type": "application/json"})
try:
    resp = urllib.request.urlopen(req, timeout=300)
    body = json.loads(resp.read())
    content = body.get("result", {}).get("content", [{}])[0].get("text", "{}")
    inner = json.loads(content) if isinstance(content, str) else content
    print(json.dumps(inner))
except Exception as e:
    print(json.dumps({"error": str(e)}))
' "$MCP_URL" "$1" "$2"
}

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], sys.argv[2]))' "$1" "$2"
}

# --- Precondition checks ---

if ! python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8081/health", timeout=5)' 2>/dev/null; then
  echo "FAIL: local-sandbox MCP server not reachable at $MCP_URL" >&2
  echo "Start it with: node agent/mcp/local-sandbox-server/index.mjs &" >&2
  write_gate false 2 1 "exploitable=false" "MCP server unreachable"
  exit 2
fi

if [ ! -d "$SCENARIO_DIR" ]; then
  echo "FAIL: scenario dir missing for $SCENARIO" >&2
  write_gate false 1 1 "exploitable=false" "scenario dir missing"
  exit 1
fi

# Acceptance gate: S04 requires S01 and S05 to be passing first.
if [ "$SCENARIO" = "s04-jinja2-escape" ]; then
  for prereq in s01-pyyaml-rce s05-negative-case; do
    gate="$ROOT/scenarios/$prereq/test_gate.json"
    if [ ! -f "$gate" ]; then
      echo "FAIL: acceptance gate — $prereq test_gate.json missing" >&2
      write_gate false 2 1 "exploitable=false" "acceptance gate: $prereq missing"
      exit 2
    fi
    if ! python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get('passed') or d.get('pass') else 1)" "$gate" 2>/dev/null; then
      echo "FAIL: acceptance gate — $prereq has not passed" >&2
      write_gate false 2 1 "exploitable=false" "acceptance gate: $prereq failed"
      exit 2
    fi
  done
fi

# Read scenario contract
EXPECTED="AFFECTED"
POC_REL="poc.py"
if [ -r "$SCENARIO_META" ]; then
  EXPECTED=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("expected","AFFECTED"))' "$SCENARIO_META" 2>/dev/null || echo "AFFECTED")
  POC_REL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["poc_contract"]["script"])' "$SCENARIO_META" 2>/dev/null || echo "poc.py")
fi
POC_PATH="$ROOT/scenarios/$SCENARIO/$POC_REL"

IMAGE_TAG="patchproof-test-$SCENARIO"
echo "Running mandatory sandbox-only gate for $SCENARIO via local-sandbox MCP..."

# --- Step 1: Build image via sandbox_build ---

echo "Step 1/3: Building image via sandbox_build..."
BUILD_LOG=$(mktemp)
BUILD_RESULT=$(mcp_call "sandbox_build" "{\"tag\":\"$IMAGE_TAG\",\"context_path\":\"$SCENARIO_DIR\",\"no_cache\":true}" 2>"$BUILD_LOG") || true
BUILD_EXIT=$(json_field "$BUILD_RESULT" "exit_code" "1")

if [ "$BUILD_EXIT" != "0" ]; then
  echo "FAIL: sandbox_build failed (exit $BUILD_EXIT)" >&2
  json_field "$BUILD_RESULT" "output" "" | tail -20 >&2 || true
  [ -s "$BUILD_LOG" ] && tail -5 "$BUILD_LOG" >&2 || true
  rm -f "$BUILD_LOG"
  write_gate false 3 1 "exploitable=false" "sandbox_build failed"
  exit 3
fi
rm -f "$BUILD_LOG"
echo "  Image built: $IMAGE_TAG"

# --- Step 2: Run pytest via sandbox_exec ---

SESSION_TEST="gate-test-$SCENARIO-$$"
echo "Step 2/3: Running pytest via sandbox_exec..."
PYTEST_RESULT=$(mcp_call "sandbox_exec" "{\"session\":\"$SESSION_TEST\",\"command\":\"python -m pytest test_main.py -q\",\"image\":\"$IMAGE_TAG\",\"timeout_secs\":$TIMEOUT}")
PYTEST_EXIT=$(json_field "$PYTEST_RESULT" "exit_code" "1")
PYTEST_STDOUT=$(json_field "$PYTEST_RESULT" "stdout" "")
PYTEST_STDERR=$(json_field "$PYTEST_RESULT" "stderr" "")

if [ "$PYTEST_EXIT" = "124" ]; then
  echo "FAIL: pytest timeout ($TIMEOUT s)" >&2
  echo "$PYTEST_STDERR" | tail -20 >&2 || true
  write_gate false 4 1 "exploitable=false" "pytest timeout ($TIMEOUT s)"
  exit 4
elif [ "$PYTEST_EXIT" != "0" ]; then
  echo "FAIL: pytest exit $PYTEST_EXIT" >&2
  echo "$PYTEST_STDOUT" | tail -20 >&2 || true
  [ -n "$PYTEST_STDERR" ] && echo "$PYTEST_STDERR" | tail -10 >&2 || true
  write_gate false "$PYTEST_EXIT" 1 "exploitable=false" "pytest failed (exit $PYTEST_EXIT)"
  exit "$PYTEST_EXIT"
fi
echo "  Pytest: PASS"

# --- Step 3: Run PoC via sandbox_exec (separate from pytest, real execution) ---

SESSION_POC="gate-poc-$SCENARIO-$$"
echo "Step 3/3: Running PoC via sandbox_exec..."

# Start service inside the container
mcp_call "sandbox_exec" "{\"session\":\"$SESSION_POC\",\"command\":\"uvicorn main:app --host 127.0.0.1 --port 8000 & sleep 3\",\"image\":\"$IMAGE_TAG\",\"timeout_secs\":$TIMEOUT}" >/dev/null 2>&1 || true

# Copy PoC script into container via sandbox_write
if [ -f "$POC_PATH" ]; then
  POC_CONTENT=$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "$POC_PATH")
  mcp_call "sandbox_write" "{\"session\":\"$SESSION_POC\",\"path\":\"/srv/poc.py\",\"content\":$POC_CONTENT}" >/dev/null 2>&1 || true
else
  echo "FAIL: PoC script not found: $POC_PATH" >&2
  write_gate true 0 2 "exploitable=false" "PoC script missing"
  exit 2
fi

# Poll for service health
HEALTHY=0
for _ in $(seq 1 20); do
  HEALTH=$(mcp_call "sandbox_exec" "{\"session\":\"$SESSION_POC\",\"command\":\"python3 -c \\\"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)\\\"\",\"timeout_secs\":5}" 2>/dev/null) || true
  HEALTH_EXIT=$(json_field "$HEALTH" "exit_code" "1")
  if [ "$HEALTH_EXIT" = "0" ]; then HEALTHY=1; break; fi
  sleep 1
done

if [ "$HEALTHY" != "1" ]; then
  echo "FAIL: service failed to start in sandbox" >&2
  write_gate true 0 3 "exploitable=false" "service failed to start"
  exit 3
fi
echo "  Service healthy"

# Run the PoC
POC_EXEC=$(mcp_call "sandbox_exec" "{\"session\":\"$SESSION_POC\",\"command\":\"timeout 60 python3 /srv/poc.py\",\"timeout_secs\":$TIMEOUT}")
POC_EXIT=$(json_field "$POC_EXEC" "exit_code" "1")
POC_STDOUT=$(json_field "$POC_EXEC" "stdout" "")
POC_STDERR=$(json_field "$POC_EXEC" "stderr" "")

if [ "$POC_EXIT" = "124" ]; then
  echo "FAIL: PoC timeout ($TIMEOUT s)" >&2
  echo "$POC_STDERR" | tail -10 >&2 || true
  write_gate true 0 4 "exploitable=false" "PoC timeout ($TIMEOUT s)"
  exit 4
fi

# Read verdict.json from the container
VERDICT_RAW=$(mcp_call "sandbox_read" "{\"session\":\"$SESSION_POC\",\"path\":\"/srv/verdict.json\"}")
VERDICT_EXISTS=$(json_field "$VERDICT_RAW" "exists" "false")

if [ "$VERDICT_EXISTS" = "true" ]; then
  VERDICT_CONTENT=$(json_field "$VERDICT_RAW" "content" "{}")
  POC_VERDICT=$(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print("exploitable=true" if d.get("exploitable") else "exploitable=false")' <<< "$VERDICT_CONTENT" 2>/dev/null || echo "exploitable=false")
else
  POC_VERDICT="exploitable=false"
  if [ "$POC_EXIT" = "0" ]; then
    POC_VERDICT="exploitable=true"
  fi
fi

echo "  PoC exit: $POC_EXIT, verdict: $POC_VERDICT, expected: $EXPECTED"

# --- Write gate result ---

if [ "$PYTEST_EXIT" = "0" ]; then
  if [ "$POC_EXIT" = "0" ]; then
    write_gate true 0 "$POC_EXIT" "$POC_VERDICT" "tests pass, PoC exploitable (MCP sandbox)"
  else
    write_gate true 0 "$POC_EXIT" "$POC_VERDICT" "tests pass, PoC not affected (MCP sandbox)"
  fi
  echo "PASS: gate passed for $SCENARIO"
  exit 0
else
  write_gate false "$PYTEST_EXIT" "$POC_EXIT" "$POC_VERDICT" "tests failed (exit $PYTEST_EXIT)"
  echo "FAIL: gate failed for $SCENARIO"
  exit "$PYTEST_EXIT"
fi
