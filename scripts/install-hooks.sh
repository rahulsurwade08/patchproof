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
CHANGED=$(mktemp)
trap 'rm -f "$CHANGED"' EXIT
if [ -t 0 ]; then
  git diff --name-only HEAD@{1} HEAD 2>/dev/null > "$CHANGED" || true
else
  while read -r local_ref local_sha remote_ref remote_sha; do
    [ -z "$local_sha" ] && continue
    case "$remote_sha" in
      0000000000000000000000000000000000000000*|"") empty=$(git hash-object -t tree /dev/null); git diff --name-only "$empty" "$local_sha" 2>/dev/null >> "$CHANGED" || true ;;
      *) git diff --name-only "$remote_sha" "$local_sha" 2>/dev/null >> "$CHANGED" || true ;;
    esac
  done
fi
SCENARIOS=$(grep "^scenarios/" "$CHANGED" 2>/dev/null | cut -d/ -f2 | sort -u)
DASH_CHANGED=$(grep -q "^dashboard/" "$CHANGED" 2>/dev/null && echo "1" || true)
[ -z "$SCENARIOS" ] && SCENARIOS="s01-pyyaml-rce"
[ -n "$DASH_CHANGED" ] && SCENARIOS="dashboard $SCENARIOS"

for S in $SCENARIOS; do
  echo "Pre-push gate: $S"
  bash "$ROOT/scripts/run_gate_before_push.sh" "$S" || exit 1
done
HOOK

chmod +x "$HOOK_FILE"
echo "Installed pre-push hook: $HOOK_FILE"
echo "Gate script: $GATE_SCRIPT"
