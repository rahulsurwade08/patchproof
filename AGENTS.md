# AGENTS.md

PatchProof: agent that proves whether a scanner-flagged CVE is actually *reachable*
with attacker-controlled input in your repo (reachability triage), runs real exploits
inside an isolated sandbox to confirm, then patches and verifies fixes.

## Commands

```bash
# Start local-sandbox MCP (required before any agent run)
python3 agent/mcp/local_sandbox_server.py &     # http://127.0.0.1:8081/mcp
python3 agent/mcp/cve_feed_server.py &       # http://127.0.0.1:8091/mcp (Streamable HTTP)

# Run the reachability analyzer directly (dev/CI only)
python3 agent/analyzer/reach.py <repo-path> <cve-or-advisory> [--out <dir>]

# Staging
docker compose -f infra/docker-compose.yml up --build

# Reset state between runs
bash scripts/reset_state.sh
```

## Hard rules

- **All execution goes through the harness (MCP), never on the host.** Direct
  `pytest`, `python`, or `docker run` on the host is forbidden.
- **Prioritize security on every change**: no secrets in code or git history; never
  weaken the sandbox or approval model.
- **Never display secrets**: refer to API keys by name only, never print `.env` or tokens.
- **Exploits never run on the host.** All execution through the `local-sandbox` MCP
  (`agent/mcp/local_sandbox_server.py`, Streamable HTTP at `127.0.0.1:8081/mcp`):
  `sandbox_build` (build-time network allowed), `sandbox_exec`/`sandbox_write`/
  `sandbox_read`/`sandbox_pull`/`sandbox_stop` (offline `--network none` containers).
  `image` is REQUIRED on every `sandbox_exec`/`sandbox_write`/`sandbox_pull` call.
- **`sandbox_pull`** copies `/srv/verdict.json` to a host path so the canonical
  copy survives container teardown.
- **Deploy-to-staging pauses for explicit human approval** (irreversible step).
- **Never commit `.env`.**
- **PoC contract**: exit 0 iff exploitable, exit 1 = not affected; write
  `verdict.json` with `{cve_id, exploitable, evidence}`; deterministic, <60s.
- **LLM-judge annotates, never decides** (`agent/prompts/judge.md`): every verdict
  gets a judge review written to `assessment.json`. The PoC exit code stays ground truth.
- **PRs: small, intermittent, ONE concern each.** A PR touches at most ~5 files
  and ~400 changed lines.
- **No hardcoded CVE data.** CVE.org + OSV.dev are the only source.
- **Sandbox + image cleanup is mandatory** after every execution.
- **Secrets never reach the sandbox.** `.env`, `.git`, credentials, and `data/output/`
  are never mounted or copied into build context or exec containers.

## Lessons learned

- **`image` required on every `sandbox_exec`/`sandbox_write`.** Omitting it silently
  uses `python:3.11-slim`.
- **`curl` is NOT in `python:3.11-slim`.** Health-checks must use
  `python3 -c "import urllib.request; ..."`.
- **`/srv` is the image WORKDIR.** Any injected files must go there.
- **PoC URLs with single-quote injection must be `urllib.parse.urlencode`d.**
- **Service start needs `nohup` + stdio redirects, not `&`.**
- **`sandbox_build` schema: `context_path` (absolute) + `tag`.**
- **`pkill`/`pgrep` can hang this shell** — use `ps -eo pid,args | grep`.
- **ALL execution through harness (MCP), never locally.**

## Layout

- `agent/analyzer/` — reachability triage engine (`reach.py`, `gen_context.py`, `deps.py`)
- `agent/mcp/` — MCP servers (`local_sandbox_server.py`, `cve_feed_server.py`)
- `agent/prompts/` — subagent prompts (orchestrator, analyzer, reproducer, judge, patcher, verifier, test-runner)
- `agent/skills/` — harness skills (SKILL.md per node)
- `data/output/<repo>/` — per-run artifacts: `reachability.json`, `verdict.json`, `assessment.json` (gitignored)

## Environment

- Python is the runtime for all `agent/` code.
- Direct analyzer: `python agent/analyzer/reach.py <repo-path> <cve-or-advisory>` → writes `reachability.json` into `data/output/<repo>/`.
