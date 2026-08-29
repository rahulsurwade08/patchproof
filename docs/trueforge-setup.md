# TrueForge setup (verified against v0.1.4)

TrueForge has **no config file** — models, connectors, skills, and the sandbox
are configured once via **Settings** (UI at `http://localhost:8790` or the HTTP
API), then referenced by name when creating agents. The former
`agent/trueforge.json` draft was removed: its mechanism does not exist.

## 1. Start the server

```bash
npx @truefoundry/trueforge        # serves UI + API on http://localhost:8790
```

## 2. Model provider — OpenRouter

Settings → Models → add a **custom OpenAI-compatible** endpoint:

| Field | Value |
|---|---|
| Base URL | `https://openrouter.ai/api/v1` |
| API key | value of `OPENROUTER_API_KEY` |
| Model IDs | value of `OPENROUTER_MODEL` (e.g. `deepseek/deepseek-chat-v3.1:free`) |

## 3. GitHub connector

Settings → Connectors → **GitHub** from the shipped catalog:

- Preferred: **OAuth** — authorize in the browser; no static token anywhere
- Fallback: header auth — paste a repo-scope PAT (the `GITHUB_TOKEN` from
  `.env`) into the connector's Authorization header here; storing it in `.env`
  alone does not configure the connector

Used by the orchestrator (advisory → repo matching) and the patcher (evidence PRs).

## 4. Sandbox — local Docker MCP server

Code execution runs through our own keyless sandbox MCP server (no cloud
providers, no accounts):

```bash
python3 agent/mcp/local_sandbox_server.py &   # serves http://127.0.0.1:8081/mcp
```

Register it once (remote-URL server, no auth):

```json
{"manifest": {"type": "remote", "name": "local-sandbox",
  "description": "Keyless local Docker sandbox.",
  "url": "http://127.0.0.1:8081/mcp"}}
```

Tools: `sandbox_build` (host-side image build — bake scenario deps in at build
time, since containers run offline), `sandbox_exec`, `sandbox_write`,
`sandbox_read`, `sandbox_stop`. Containers are disposable Docker containers
with `--network none`, one per session label so the service and PoC share
`/tmp` and localhost. Requires only Docker. Leave Settings → Sandbox providers
unconfigured; agents set `sandbox.enabled: true` so TrueForge's built-in
materializes skill repos and backs `sandbox_artifacts` file downloads, but
exploit/PoC execution routes only through the `local-sandbox` MCP (--network
none). Evaluated alternatives are recorded in ADR-008 (`docs/decisions.md`).

Attach the `local-sandbox` server to **every agent that executes code**
(reproducer, patcher, verifier) and give each investigation one session label
(the scenario id) that all subagents share; see `agent/prompts/*`.

## 5. CVE feed MCP server — dual-source legitimacy check

MCP servers in TrueForge are remote-URL only (header auth / OAuth); local stdio
servers are not supported. Our dual-source feed server
(`agent/mcp/cve_feed_server.py` — Python port; the Node `index.mjs` was
retired in PR #26) speaks Streamable HTTP at `http://127.0.0.1:8091/mcp`
(PR #71) and can be registered as a remote URL MCP in TrueForge Settings.
Remote-URL registration is wired in cut-order step 3 (see `docs/custom-harness-build-plan.md`).
Until registered, `data/inbox/*.json` with `demo:true` is the fail-closed fallback.

Tools it exposes:

| Tool | Source | Purpose |
|---|---|---|
| `cve_get_cve` | CVE.org (`cveawg.mitre.org`) | canonical record: exists, state, description |
| `osv_query_package` | OSV.dev | vulns for ecosystem/package[/version] |
| `osv_get_vuln` | OSV.dev | full OSV record |
| `cve_cross_check` | both | one-call legitimacy verdict: CONFIRMED / NOT_IN_SCOPE / UNKNOWN |

Until the wrapper lands, the legitimacy gate **fails closed**: only advisories
explicitly marked `"demo": true` (via `scripts/fake_cve_injector.py`, trusted
local demo) may proceed without a cross-check, recorded as
`legitimacy: "demo-bypass"` in state.json. Once registered, triage runs
`cve_cross_check` on every advisory.

Register cve-feed:

```json
{"manifest": {"type": "remote", "name": "cve-feed",
  "description": "Dual-source CVE legitimacy (CVE.org + OSV.dev)",
  "url": "http://127.0.0.1:8091/mcp"}}
```

## 6. Skills — 7 PatchProof agent skills

Settings → Skills → Add skill (git):

| Skill | Repository | Path | Pin SHA |
|---|---|---|---|
| analyzer | `https://github.com/rahulsurwade08/patchproof` | `agent/skills/analyzer` | current HEAD |
| orchestrator | `...` | `agent/skills/orchestrator` | current HEAD |
| reproducer | `...` | `agent/skills/reproducer` | current HEAD |
| judge | `...` | `agent/skills/judge` | current HEAD |
| patcher | `...` | `agent/skills/patcher` | current HEAD |
| verifier | `...` | `agent/skills/verifier` | current HEAD |
| test-runner | `...` | `agent/skills/test-runner` | current HEAD |

Pin each to the current git HEAD. Run `python3 scripts/harness_setup.py` to
register all skills + 2 MCPs (local-sandbox, cve-feed) + the `patchproof-v2`
agent manifest idempotently (`sandbox.enabled: true`, skills + MCPs attached).
The `github` connector is added separately via the catalog UI per step 3.

## 7. Agent manifest — patchproof-v2

Settings → Agents → `patchproof-v2` → edit manifest:

```json
{
  "mode": "SingleAgent",
  "name": "patchproof-v2",
  "sandbox": {"enabled": true, "file_downloads": true},
  "file_downloads": true,
  "skills": [...7 PatchProof skills registered in step 6...],
  "mcp_servers": [
    {"name": "local-sandbox", "require_approval_for_tools": ["@all"]},
    {"name": "cve-feed",      "require_approval_for_tools": ["@write", "@destructive"]},
    {"name": "github"}
  ]
}
```

`require_approval_for_tools` is per MCP server in the agent manifest (not on the MCP registration). `local-sandbox` uses `["@all"]` because every sandbox tool call (build/exec/write/read/stop) represents an irreversible exploit-execution step — the human must approve each call individually. `cve-feed` uses the default `["@write","@destructive"]` (read-only data lookup). `github` uses the default (PR operations are gated).

`python3 scripts/harness_setup.py` upserts this manifest idempotently — re-running after schema changes or skill pin updates is safe.

For the combined harness wiring + Chat UI work loop (Initial Setup + Chat UI SDK, cut-order, verification via `http://[::1]:8790` / `127.0.0.1:8081/mcp`), see `docs/harness-loop-plan.md` — the single loop the agent follows. The intermediate `docs/harness-patchproof-setup.md` and `docs/harness-chat-ui-plan.md` were merged into that loop and removed.
