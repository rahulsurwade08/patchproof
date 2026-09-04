#!/usr/bin/env bash
# Install CheckExploit into opencode.
# Run once after cloning the repo.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Installing CheckExploit skill for opencode..."

# 1. Copy the skill
SKILL_DIR="$HOME/.agents/skills/check-exploit"
mkdir -p "$SKILL_DIR"
cp "$REPO_DIR/SKILL.md" "$SKILL_DIR/SKILL.md"
echo "  skill -> $SKILL_DIR/SKILL.md"

# 2. Merge MCP config into opencode.json (idempotent)
OCCONF="$HOME/.config/opencode/opencode.json"
OCCONF_DIR="$(dirname "$OCCONF")"
mkdir -p "$OCCONF_DIR"

# ponytail: python3 is always available (it's how opencode itself runs).
# Upgrade path: native jq or python-jq if available.
python3 -c "
import json, os, sys

occ = os.path.expanduser('$OCCONF')
if os.path.exists(occ):
    cfg = json.load(open(occ))
else:
    cfg = {'\$schema': 'https://opencode.ai/config.json', 'mcp': {}}

desired = {
    'local-sandbox': {'type': 'remote', 'url': 'http://127.0.0.1:8081/mcp'},
    'cve-feed':       {'type': 'remote', 'url': 'http://127.0.0.1:8091/mcp'},
}
changed = False
for k, v in desired.items():
    if cfg.get('mcp', {}).get(k) != v:
        cfg.setdefault('mcp', {})[k] = v
        changed = True

if changed:
    with open(occ, 'w') as f:
        json.dump(cfg, f, indent=2)
    print('  mcp config -> $OCCONF (updated)')
else:
    print('  mcp config -> $OCCONF (unchanged)')
"
echo ""
echo "CheckExploit installed. To start the sandbox MCP servers:"
echo ""
echo "  python3 $REPO_DIR/agent/mcp/local_sandbox_server.py &"
echo "  python3 $REPO_DIR/agent/mcp/cve_feed_server.py &"
echo ""
echo "Then opencode will use CheckExploit when you say 'scan this repo for CVEs'."
