#!/bin/bash
# Install the mandatory pre-push test gate hook.
# Run once per clone: scripts/install-hooks.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HOOK_DIR="$ROOT/.git/hooks"
HOOK_FILE="$HOOK_DIR/pre-push"
GATE_SCRIPT="$ROOT/scripts/run_gate_before_push.sh"

mkdir -p "$HOOK_DIR"

cat > "$HOOK_FILE" << 'HOOK'
#!/bin/bash
# Mandatory pre-push sandbox-only gate.
# Blocks push unless run_gate_before_push.sh passes for each changed scenario.
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCENARIOS=$(git diff --name-only HEAD@{1} HEAD -- 'scenarios/' 2>/dev/null | cut -d/ -f1 | sort -u)
[ -z "$SCENARIOS" ] && SCENARIOS="s01-pyyaml-rce"

for S in $SCENARIOS; do
  echo "Pre-push gate: $S"
  bash "$ROOT/scripts/run_gate_before_push.sh" "$S" || exit 1
done
HOOK

chmod +x "$HOOK_FILE"
echo "Installed pre-push hook: $HOOK_FILE"
echo "Gate script: $GATE_SCRIPT"
